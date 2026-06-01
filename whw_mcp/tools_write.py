"""Write tools exposed by the audit MCP.

Each write validates its payload (severity/confidence vocabulary), computes embeddings
server-side via Nomic (or noop fallback), and runs a single MERGE/CREATE Cypher
statement so re-invocations are idempotent or auditable.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from .db import load_cypher, run_one
from .embeddings import EMBED_DIM, embed


def _deterministic_asset_id(name: str, kind: str) -> str:
    """Stable id from (name, kind) so re-extraction hits the same row."""
    h = hashlib.sha256(f"{name}\x00{kind}".encode("utf-8")).hexdigest()
    return f"asset-{h[:24]}"


SEVERITY_VOCAB = {"info", "low", "med", "high", "crit"}
CONFIDENCE_VOCAB = {"certain", "inferred", "uncertain"}
SOURCE_VOCAB = {"llm", "manual", "docstring", "infra-pass"}
MODE_VOCAB = {"live", "eval"}
ASSET_KIND_VOCAB = {"db", "cache", "queue", "secret", "endpoint", "container",
                    "iam", "bucket", "network", "observability", "third_party"}
CRITICALITY_VOCAB = {"low", "med", "high", "crit"}


def register_write_tools(mcp: FastMCP) -> None:
    """Bind write tools to the FastMCP server."""

    @mcp.tool()
    def register_repo_commit(
        repo_id: str,
        commit: str,
        abs_repo_root: Annotated[str, Field(
            description="Absolute path to the source worktree on the host. Used by "
                        "get_snippet to slice files server-side."
        )],
        commit_ts: Annotated[str | None, Field(
            description="ISO-8601 commit timestamp (e.g. from `git show -s --format=%cI`). "
                        "Used by eval-mode anti-leakage."
        )] = None,
    ) -> dict[str, Any]:
        """Register or update the host filesystem pointer + commit timestamp for a
        `(repo_id, commit)` pair. Called by `whw ingest` after parsing.
        """
        row = run_one(
            load_cypher("register_repo_commit"),
            {"repo_id": repo_id, "commit": commit, "abs_repo_root": abs_repo_root,
             "commit_ts": commit_ts},
        )
        return dict(row) if row else {"repo_id": repo_id, "commit": commit, "abs_repo_root": abs_repo_root}

    @mcp.tool()
    def mark_in_scope(
        qualified_names: list[str],
        repo_id: str,
        commit: str,
        entrypoint_kind: str | None = None,
        trust_level: Annotated[str | None, Field(
            description="trailmark vocabulary: 'UNTRUSTED', 'MIXED', or 'TRUSTED'."
        )] = None,
    ) -> dict[str, Any]:
        """Mark each function whose QN is in `qualified_names` as `in_scope=true`.

        Returns `{"marked": <count>}`. Optionally stamps `entrypoint_kind` (e.g.
        'fuzz_harness', 'api_route') and `trust_level` for entrypoints.
        """
        if not qualified_names:
            return {"marked": 0}
        row = run_one(
            load_cypher("mark_in_scope"),
            {"repo_id": repo_id, "commit": commit, "qns": qualified_names,
             "entrypoint_kind": entrypoint_kind, "trust_level": trust_level},
        )
        return {"marked": int(row["marked"]) if row else 0}

    @mcp.tool()
    def record_audit_run(
        id: str,
        repo_id: str,
        commit: str,
        scope_spec: str,
        depth: Annotated[int, Field(ge=1, le=5)],
        tools_image: str,
        mode: Annotated[str, Field(description="'live' or 'eval'.")],
        model: str,
        eval_commit: str | None = None,
        eval_commit_ts: Annotated[str | None, Field(
            description="Resolved ISO-8601 timestamp of eval_commit. Required when mode='eval'."
        )] = None,
        status: str = "running",
        notes: str = "",
    ) -> dict[str, Any]:
        """Upsert an AuditRun node. Subsequent `add_finding` calls reference this `id`.

        In `mode='eval'`, the server uses `eval_commit_ts` as the anti-leakage boundary:
        new Findings get `commit_observed_at = eval_commit_ts`, and read tools filter
        prior findings/FPs whose `commit_observed_at >= eval_commit_ts`.
        """
        if mode not in MODE_VOCAB:
            raise ValueError(f"mode must be one of {sorted(MODE_VOCAB)}")
        if mode == "eval" and not eval_commit_ts:
            raise ValueError("eval_commit_ts is required when mode='eval'")
        row = run_one(load_cypher("record_audit_run"), {
            "id": id, "repo_id": repo_id, "commit": commit,
            "scope_spec": scope_spec, "depth": depth, "tools_image": tools_image,
            "mode": mode, "eval_commit": eval_commit, "eval_commit_ts": eval_commit_ts,
            "model": model, "status": status, "notes": notes,
        })
        return dict(row) if row else {"id": id}

    @mcp.tool()
    def add_finding(
        audit_run_id: str,
        vuln_class: Annotated[str, Field(description="e.g. UNINIT_MEMORY, OOB_READ, NOVEL, INFRA_*.")],
        severity: Annotated[str, Field(description="One of: info, low, med, high, crit.")],
        confidence: Annotated[str, Field(description="One of: certain, inferred, uncertain.")],
        summary: Annotated[str, Field(min_length=1, max_length=400, description="One-line.")],
        rationale: Annotated[str, Field(min_length=1, description="3-10 lines with line refs.")],
        function_qn: str | None = None,
        file_path: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
        source: str = "llm",
        tool_evidence: str = "",
        model_used: str | None = None,
        id: str | None = None,
    ) -> dict[str, Any]:
        """Create a new `:Finding`, link it to the `AuditRun` and (if present) the host
        `Function` via `:LOCATED_IN`. Embedding is computed server-side from
        `summary + rationale` via Nomic (or zero-vector under WHW_EMBEDDING_BACKEND=noop).

        Returns `{"id", "created_at", "commit_observed_at"}`.
        """
        if severity not in SEVERITY_VOCAB:
            raise ValueError(f"severity must be one of {sorted(SEVERITY_VOCAB)}")
        if confidence not in CONFIDENCE_VOCAB:
            raise ValueError(f"confidence must be one of {sorted(CONFIDENCE_VOCAB)}")
        if not vuln_class.strip():
            raise ValueError("vuln_class must be non-empty")
        # source is advisory; warn-don't-fail on novel values.
        if source not in SOURCE_VOCAB:
            source = "llm"

        finding_id = id or str(uuid.uuid4())
        emb = embed(f"{summary}\n\n{rationale}")
        if len(emb) != EMBED_DIM:
            raise RuntimeError(f"embedding dim {len(emb)} != {EMBED_DIM}")

        if line_start is not None and line_end is not None and line_end < line_start:
            line_start, line_end = line_end, line_start

        params = {
            "id": finding_id,
            "audit_run_id": audit_run_id,
            "vuln_class": vuln_class,
            "severity": severity,
            "confidence": confidence,
            "summary": summary,
            "rationale": rationale,
            "function_qn": function_qn,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "embedding": emb,
            "source": source,
            "tool_evidence": tool_evidence,
            "model_used": model_used,
        }
        row = run_one(load_cypher("add_finding"), params)
        if row is None:
            raise RuntimeError(
                f"add_finding failed: AuditRun {audit_run_id!r} not found, or function_qn "
                f"{function_qn!r} not present for the run's (repo_id, commit)."
            )
        return dict(row)

    @mcp.tool()
    def mark_false_positive(
        finding_id: str,
        reason: Annotated[str, Field(min_length=1, description="Why this is a false positive.")],
        marked_by: str | None = None,
    ) -> dict[str, Any]:
        """Flip a Finding's status to 'fp' AND create a sibling :FalsePositive node
        carrying the Finding's embedding so future audits can vector-suppress repeats."""
        if not finding_id.strip():
            raise ValueError("finding_id must be non-empty")
        fp_id = str(uuid.uuid4())
        row = run_one(load_cypher("mark_false_positive"), {
            "finding_id": finding_id, "fp_id": fp_id,
            "reason": reason, "marked_by": marked_by,
        })
        if row is None:
            raise RuntimeError(f"mark_false_positive: Finding {finding_id!r} not found")
        return dict(row)

    @mcp.tool()
    def link_finding_duplicate(
        duplicate_id: Annotated[str, Field(description="The Finding being marked as a duplicate.")],
        canonical_id: Annotated[str, Field(description="The Finding it duplicates of.")],
        cosine: Annotated[float, Field(ge=-1.0, le=1.0)] = 1.0,
    ) -> dict[str, Any]:
        """Create `(duplicate)-[:DUPLICATE_OF]->(canonical)` + a SIMILAR_TO edge carrying
        the measured cosine. Flips the duplicate's status to 'duplicate' so subsequent
        consolidation passes ignore it."""
        if duplicate_id == canonical_id:
            raise ValueError("duplicate_id and canonical_id must differ")
        row = run_one(load_cypher("link_finding_duplicate"), {
            "a_id": duplicate_id, "canonical_id": canonical_id, "cosine": cosine,
        })
        if row is None:
            raise RuntimeError(
                f"link_finding_duplicate: one of {duplicate_id!r}/{canonical_id!r} not found"
            )
        return dict(row)

    @mcp.tool()
    def link_finding_to_asset(
        finding_id: str,
        asset_id: str,
    ) -> dict[str, Any]:
        """Idempotent :AFFECTS_ASSET edge between a Finding and a ProductionAsset."""
        row = run_one(load_cypher("link_finding_to_asset"), {
            "finding_id": finding_id, "asset_id": asset_id,
        })
        if row is None:
            raise RuntimeError(
                f"link_finding_to_asset: Finding {finding_id!r} or Asset {asset_id!r} not found"
            )
        return dict(row)

    @mcp.tool()
    def upsert_production_asset(
        name: Annotated[str, Field(min_length=1, max_length=200)],
        kind: Annotated[str, Field(description=f"One of: {sorted(ASSET_KIND_VOCAB)}")],
        description: Annotated[str, Field(default="", description="One sentence.")] = "",
        criticality: Annotated[str, Field(description="low|med|high|crit")] = "med",
        id: str | None = None,
    ) -> dict[str, Any]:
        """Upsert a :ProductionAsset. Server computes:
          - id (deterministic from sha256(name||kind) if not supplied),
          - embedding (Nomic of `name + ' ' + description`).

        Re-calls with the same name+kind upsert the same node — safe for the infra-pass
        agent to call repeatedly during extraction.
        """
        if kind not in ASSET_KIND_VOCAB:
            raise ValueError(f"kind must be one of {sorted(ASSET_KIND_VOCAB)}")
        if criticality not in CRITICALITY_VOCAB:
            raise ValueError(f"criticality must be one of {sorted(CRITICALITY_VOCAB)}")
        asset_id = id or _deterministic_asset_id(name, kind)
        emb = embed(f"{name} {description}".strip())
        if len(emb) != EMBED_DIM:
            raise RuntimeError(f"embedding dim {len(emb)} != {EMBED_DIM}")
        row = run_one(load_cypher("upsert_production_asset"), {
            "id": asset_id, "name": name, "kind": kind,
            "description": description, "criticality": criticality, "embedding": emb,
        })
        return dict(row) if row else {"id": asset_id, "name": name, "kind": kind}

    @mcp.tool()
    def link_user_doc(
        path: str,
        audit_run_id: str,
        sha256: str,
        content_text: Annotated[str, Field(description="Chunk text; embedded server-side.")],
        mentions: Annotated[list[str] | None, Field(
            description="Asset ids this chunk mentions; each gets a :MENTIONS edge."
        )] = None,
    ) -> dict[str, Any]:
        """Register a chunk of the user-context bundle for this run and link it to
        ProductionAssets it mentions. The :MENTIONS edges let the consolidation infra
        pass tie code-level Findings to operational assets via cosine matching."""
        emb = embed(content_text)
        if len(emb) != EMBED_DIM:
            raise RuntimeError(f"embedding dim {len(emb)} != {EMBED_DIM}")
        row = run_one(load_cypher("link_user_doc"), {
            "path": path, "audit_run_id": audit_run_id, "sha256": sha256,
            "embedding": emb, "mentions": mentions or [],
        })
        return dict(row) if row else {"path": path, "audit_run_id": audit_run_id, "mention_count": 0}
