"""Write tools exposed by the audit MCP.

Each write validates its payload (severity/confidence vocabulary), computes embeddings
server-side via Nomic (or noop fallback), and runs a single MERGE/CREATE Cypher
statement so re-invocations are idempotent or auditable.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from .db import load_cypher, run_one
from .embeddings import EMBED_DIM, embed


SEVERITY_VOCAB = {"info", "low", "med", "high", "crit"}
CONFIDENCE_VOCAB = {"certain", "inferred", "uncertain"}
SOURCE_VOCAB = {"llm", "manual", "docstring", "infra-pass"}
MODE_VOCAB = {"live", "eval"}


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
