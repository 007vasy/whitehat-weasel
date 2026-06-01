"""Read tools exposed by the audit MCP.

Each tool runs one or a few Cypher queries from `whw_mcp/cypher/*.cypher`, validates
inputs, and returns JSON-serializable dicts. Sub-agents see these as `mcp__whw__<name>`.

Filters by eval_commit_ts when requested so prior findings/FPs after the benchmark
commit are hidden — this is how CyberGym held-out samples avoid leakage.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from .db import load_cypher, render_cypher, run_one, run_query
from .embeddings import EMBED_DIM, embed


_VALID_DIRECTIONS = {"inbound", "outbound", "both"}


def _is_zero_vector(v: list[float]) -> bool:
    """A zero vector breaks cosine vector queries; short-circuit instead."""
    return not v or all(x == 0.0 for x in v)


def register_read_tools(mcp: FastMCP) -> None:
    """Bind read tools to the FastMCP server."""

    @mcp.tool()
    def find_in_scope(
        repo_id: Annotated[str, Field(description="Repo slug, e.g. 'arvo-1065'.")],
        commit: Annotated[str, Field(description="Commit SHA the audit is anchored to.")],
    ) -> list[dict]:
        """Return all Function nodes marked `in_scope=true` for (repo_id, commit).

        Each row carries qualified_name, name, file_path, line span, language, signature,
        and (if set) entrypoint_kind / trust_level. Ordered deterministically.
        """
        rows = run_query(load_cypher("find_in_scope"), {"repo_id": repo_id, "commit": commit})
        return [_record_to_dict(r) for r in rows]

    @mcp.tool()
    def get_callgraph_slice(
        qualified_name: Annotated[str, Field(description="QN of the seed function.")],
        repo_id: str,
        commit: str,
        depth: Annotated[int, Field(ge=1, le=5, description="Max CALLS-edge hops (1..5).")] = 3,
        direction: Annotated[str, Field(description="'inbound', 'outbound', or 'both'.")] = "both",
    ) -> dict[str, Any]:
        """Return the seed function plus its callers (inbound) and callees (outbound) up to
        `depth` hops in the CALLS graph. `direction` filters which side is populated.
        """
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(f"direction must be one of {sorted(_VALID_DIRECTIONS)}")

        params = {"qn": qualified_name, "repo_id": repo_id, "commit": commit}
        seed_row = run_one(load_cypher("get_callgraph_seed"), params)
        if seed_row is None:
            return {"seed": None, "callees": [], "callers": []}

        callees: list[dict] = []
        callers: list[dict] = []
        if direction in ("outbound", "both"):
            rows = run_query(render_cypher("get_callgraph_outbound", DEPTH=depth), params)
            callees = [_record_to_dict(r) for r in rows]
        if direction in ("inbound", "both"):
            rows = run_query(render_cypher("get_callgraph_inbound", DEPTH=depth), params)
            callers = [_record_to_dict(r) for r in rows]

        return {
            "seed": _record_to_dict(seed_row),
            "callees": callees,
            "callers": callers,
            "depth": depth,
            "direction": direction,
        }

    @mcp.tool()
    def get_snippet(
        qualified_name: str,
        repo_id: str,
        commit: str,
    ) -> dict[str, Any]:
        """Return the source text + span for a function. The MCP looks up the registered
        worktree root (from `:RepoCommit.abs_repo_root`) and slices the file directly.
        If the root isn't registered or the file is missing, `text` is None and the
        caller should use its own `Read` tool with `<repo_root>/<file_path>`.
        """
        row = run_one(load_cypher("get_snippet"),
                      {"qn": qualified_name, "repo_id": repo_id, "commit": commit})
        if row is None:
            return {"file_path": None, "line_start": None, "line_end": None, "text": None}

        rec = _record_to_dict(row)
        abs_root = rec.get("abs_repo_root")
        rel_path = rec.get("file_path")
        ls = rec.get("line_start")
        le = rec.get("line_end")
        text: str | None = None

        if abs_root and rel_path and ls and le:
            file = Path(abs_root) / rel_path
            if file.is_file():
                try:
                    all_lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
                    # 1-based inclusive line numbers.
                    text = "\n".join(all_lines[max(0, ls - 1): le])
                except OSError:
                    text = None

        return {
            "qualified_name": qualified_name,
            "name": rec.get("name"),
            "language": rec.get("language"),
            "file_path": rel_path,
            "abs_file_path": str(Path(abs_root) / rel_path) if abs_root and rel_path else None,
            "line_start": ls,
            "line_end": le,
            "text": text,
        }

    @mcp.tool()
    def find_similar_findings(
        summary_text: Annotated[str, Field(
            description="The candidate finding's one-line summary. The server embeds it via "
                        "Nomic and runs a cosine vector query against the Finding index."
        )],
        repo_id: str | None = None,
        commit: str | None = None,
        k: Annotated[int, Field(ge=1, le=50)] = 10,
        min_cosine: Annotated[float, Field(ge=-1.0, le=1.0)] = 0.85,
        eval_commit_ts: Annotated[str | None, Field(
            description="ISO-8601; if set, prior findings observed at/after this ts are hidden."
        )] = None,
    ) -> list[dict]:
        """Vector-search Findings semantically similar to `summary_text`. Returns top-`k`
        rows above `min_cosine`. Used by the audit sub-agent to spot prior duplicates
        before filing, and by the consolidation pipeline for dedup grouping.
        """
        v = embed(summary_text)
        if _is_zero_vector(v):
            return []
        rows = run_query(load_cypher("find_similar_findings"), {
            "embedding": v, "k": k, "min_cosine": min_cosine,
            "repo_id": repo_id, "commit": commit, "eval_ts": eval_commit_ts,
        })
        return [_record_to_dict(r) for r in rows]

    @mcp.tool()
    def get_prior_false_positives(
        summary_text: Annotated[str, Field(
            description="One-line summary of the agent's working hypothesis."
        )],
        repo_id: str | None = None,
        commit: str | None = None,
        k: Annotated[int, Field(ge=1, le=50)] = 10,
        min_cosine: Annotated[float, Field(ge=-1.0, le=1.0)] = 0.88,
        eval_commit_ts: str | None = None,
    ) -> list[dict]:
        """Vector-search prior :FalsePositive nodes. If any match at high cosine, the
        agent should DROP the hypothesis. Threshold defaults stricter (0.88) than
        find_similar_findings since FP suppression is high-impact.
        """
        v = embed(summary_text)
        if _is_zero_vector(v):
            return []
        rows = run_query(load_cypher("get_prior_false_positives"), {
            "embedding": v, "k": k, "min_cosine": min_cosine,
            "repo_id": repo_id, "commit": commit, "eval_ts": eval_commit_ts,
        })
        return [_record_to_dict(r) for r in rows]

    @mcp.tool()
    def list_findings(
        repo_id: str,
        commit: str,
        status: str | None = None,
        eval_commit_ts: Annotated[str | None, Field(
            description="ISO-8601 timestamp; only Findings whose commit_observed_at is "
                        "strictly before this are returned (eval-mode anti-leakage)."
        )] = None,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> list[dict]:
        """List findings on (repo_id, commit). Optional status filter and eval-mode time gate."""
        rows = run_query(
            load_cypher("list_findings"),
            {
                "repo_id": repo_id,
                "commit": commit,
                "status": status,
                "eval_ts": eval_commit_ts,
                "limit": limit,
            },
        )
        return [_record_to_dict(r) for r in rows]

    @mcp.tool()
    def find_upstream_entrypoints(
        qualified_name: Annotated[str, Field(description="QN of the target (downstream) function.")],
        repo_id: str,
        commit: str,
        max_depth: Annotated[int, Field(ge=1, le=10, description="Max CALLS-edge hops to walk backward.")] = 5,
    ) -> list[dict]:
        """Walk CALLS backward from `qualified_name` until hitting a function that looks
        like an untrusted entry (entrypoint_kind set, or trust_level='UNTRUSTED', or a
        name matching a handler/route/webhook/fuzzer shape). Returns shortest path per
        entry, ordered by hop count. Empty list means the target is not reachable from
        any flagged entry within `max_depth` hops — that's a meaningful negative
        signal, not an error.
        """
        rows = run_query(
            render_cypher("find_upstream_entrypoints", DEPTH=max_depth),
            {"qn": qualified_name, "repo_id": repo_id, "commit": commit},
        )
        return [_record_to_dict(r) for r in rows]


def _record_to_dict(record) -> dict:
    """neo4j.Record → plain dict (no DateTime objects; they're already toString()'d in Cypher)."""
    return dict(record)
