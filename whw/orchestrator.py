"""WHW audit orchestrator (Phase A: serial fan-out).

Pipeline:

  1. resolve_scope() — convert a high-level scope spec into a concrete set of in-scope
     Function qualified_names. Supports four strategies:
       - "entrypoint": seed QN, optionally CALLS-expanded to depth (with USAGE fallback
         since cbm's C parser often attributes calls at Module rather than Function level)
       - "file_glob":  match by file_path SQL-style LIKE
       - "function":   exact match on Function.name (smoke-test friendly)
       - "all":        every Function in (repo_id, commit)

  2. mark_in_scope_in_neo4j() — flip in_scope=true on the selected Functions.

  3. record_audit_run_in_neo4j() — MERGE the AuditRun anchor.

  4. For each in-scope Function (serial in Phase A): spawn a `claude -p` sub-agent with
     a fresh MCP-config + per-function task message. Wait for completion. Collect the
     Findings the agent wrote (by querying Neo4j for Findings with audit_run_id=$rid).

  5. Write `.whw/run-<id>/{run.json, agents/<qn>.jsonl, findings.json}`.

Bias-to-MCP note: this file is a SCRIPT. Sub-agents are the MCP-driven agentic layer.
The orchestrator's job is process control — spawn, throttle, collect — not domain logic.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from neo4j import Driver, GraphDatabase

from .config import get_settings


# ---------- thread-safe token-bucket rate limiter ----------------------------

class TokenBucket:
    """Thread-safe token bucket. acquire() blocks until a token is available.

    `rate_per_min` is the long-run rate; capacity equals one minute of burst.
    """

    def __init__(self, rate_per_min: int):
        if rate_per_min <= 0:
            raise ValueError("rate_per_min must be > 0")
        self.capacity = float(rate_per_min)
        self.tokens = self.capacity
        self.rate_per_sec = rate_per_min / 60.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, n: float = 1.0) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate_per_sec)
                self._last = now
                if self.tokens >= n:
                    self.tokens -= n
                    return
                wait = (n - self.tokens) / self.rate_per_sec
            # Sleep outside the lock so other threads can refill if their clocks differ.
            time.sleep(min(wait, 1.0))


# --- types ---------------------------------------------------------------------

@dataclass
class ScopeSpec:
    """Declarative description of what to audit. Exactly one strategy field should be set."""
    entrypoint: str | None = None           # QN or "<file_basename>:<symbol>" shorthand
    entrypoint_depth: int = 3
    file_glob: str | None = None            # shell glob, basename-fallback if literal misses
    function: str | None = None             # exact Function.name
    all: bool = False
    qualified_names: list[str] | None = None  # explicit QN list (used by eval suite for
                                              # multi-file patches: gather QNs across all
                                              # patched files, scope as a single set)

    def describe(self) -> str:
        if self.entrypoint:
            return f"entrypoint={self.entrypoint} depth={self.entrypoint_depth}"
        if self.file_glob:
            return f"file_glob={self.file_glob}"
        if self.function:
            return f"function={self.function}"
        if self.qualified_names is not None:
            return f"qualified_names×{len(self.qualified_names)}"
        if self.all:
            return "all"
        return "(empty)"


@dataclass
class SubagentResult:
    function_qn: str
    file_path: str
    line_start: int
    line_end: int
    exit_code: int
    elapsed_s: float
    n_findings_after: int       # Findings linked to this function under this run
    stdout_path: str
    error: str | None = None


@dataclass
class TriageResult:
    """Outcome of one re-triage sub-agent run."""
    finding_id: str
    function_qn: str | None
    exit_code: int
    elapsed_s: float
    final_status: str           # status of the Finding after this triage
    conclusion: str             # 'confirm' (status=verified) | 'refute' (fp) | 'refine' (duplicate) | 'failed'
    stdout_path: str
    error: str | None = None


@dataclass
class InfraResult:
    """Outcome of one infra-context sub-agent run."""
    audit_run_id: str
    exit_code: int
    elapsed_s: float
    n_assets_added: int
    n_findings_added: int
    n_asset_links: int
    stdout_path: str
    error: str | None = None


@dataclass
class AuditResult:
    audit_run_id: str
    repo_id: str
    commit: str
    mode: Literal["live", "eval"]
    eval_commit: str | None
    scope_spec: dict[str, Any]
    n_in_scope: int
    n_agents_run: int
    n_findings_total: int
    elapsed_s: float
    run_dir: str
    agents: list[SubagentResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --- Neo4j helpers (direct; the orchestrator is in-process and doesn't need MCP) ---

def _open_driver() -> Driver:
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    driver.verify_connectivity()
    return driver


def resolve_scope(driver: Driver, repo_id: str, commit: str, spec: ScopeSpec) -> list[dict[str, Any]]:
    """Return a list of in-scope Function dicts (qualified_name, name, file_path, lines)."""
    s = get_settings()

    with driver.session(database=s.neo4j_database) as session:
        if spec.all:
            rows = session.run("""
                MATCH (f:Function {repo_id:$repo_id, commit:$commit})
                RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
                       f.line_start AS ls, f.line_end AS le
                ORDER BY f.file_path, f.line_start
            """, repo_id=repo_id, commit=commit)
            return [dict(r) for r in rows]

        if spec.function:
            rows = session.run("""
                MATCH (f:Function {repo_id:$repo_id, commit:$commit, name:$name})
                RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
                       f.line_start AS ls, f.line_end AS le
                ORDER BY f.file_path, f.line_start
            """, repo_id=repo_id, commit=commit, name=spec.function)
            return [dict(r) for r in rows]

        if spec.file_glob:
            # First try the literal glob.
            rows = list(session.run("""
                MATCH (f:Function {repo_id:$repo_id, commit:$commit})
                WHERE f.file_path =~ $regex
                RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
                       f.line_start AS ls, f.line_end AS le
                ORDER BY f.file_path, f.line_start
            """, repo_id=repo_id, commit=commit, regex=_glob_to_regex(spec.file_glob)))
            if rows:
                return [dict(r) for r in rows]

            # Fallback: basename-based suffix match. CyberGym L3 patch paths are
            # project-relative (e.g. 'src/funcs.c') while ingested file_paths include
            # the src-vul tree prefix (e.g. 'file/src/funcs.c'). The auto-scoping in
            # whw eval suite relies on this fallback.
            tail = Path(spec.file_glob).name
            rows = list(session.run("""
                MATCH (f:Function {repo_id:$repo_id, commit:$commit})
                WHERE f.file_path ENDS WITH $tail
                RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
                       f.line_start AS ls, f.line_end AS le
                ORDER BY f.file_path, f.line_start
            """, repo_id=repo_id, commit=commit, tail="/" + tail))
            return [dict(r) for r in rows]

        if spec.entrypoint:
            return _resolve_entrypoint_scope(session, repo_id, commit, spec)

        if spec.qualified_names is not None:
            if not spec.qualified_names:
                return []
            rows = session.run("""
                MATCH (f:Function {repo_id:$repo_id, commit:$commit})
                WHERE f.qualified_name IN $qns
                RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
                       f.line_start AS ls, f.line_end AS le
                ORDER BY f.file_path, f.line_start
            """, repo_id=repo_id, commit=commit, qns=spec.qualified_names)
            return [dict(r) for r in rows]

    raise ValueError("ScopeSpec is empty — set exactly one of entrypoint/file_glob/function/all/qualified_names.")


def _resolve_entrypoint_scope(session, repo_id: str, commit: str, spec: ScopeSpec) -> list[dict]:
    """Seed = entrypoint QN/symbol; expand by CALLS to depth.

    Fallback (essential for C, where cbm attributes most CALLS to Module nodes): if CALLS
    expansion finds <= 1 callees, also include every Function defined in the same File as
    the entrypoint. This gives the agent a useful in-scope set even when the call graph
    is coarse.
    """
    # Find the seed: accept either a full QN, "file:symbol", or just "symbol".
    seed_qn = _find_seed_qn(session, repo_id, commit, spec.entrypoint)
    if not seed_qn:
        return []

    depth = max(1, min(5, int(spec.entrypoint_depth)))
    rows = list(session.run(f"""
        MATCH (seed:Function {{qualified_name:$qn, repo_id:$repo_id, commit:$commit}})
        OPTIONAL MATCH (seed)-[:CALLS*1..{depth}]->(callee:Function)
        WITH seed, collect(DISTINCT callee.qualified_name) AS callee_qns
        RETURN seed.qualified_name AS seed_qn,
               seed.file_path      AS seed_fp,
               [x IN callee_qns WHERE x IS NOT NULL] AS callee_qns
    """, qn=seed_qn, repo_id=repo_id, commit=commit))

    if not rows:
        return []
    seed_fp = rows[0]["seed_fp"]
    callee_qns = rows[0]["callee_qns"] or []

    scope_qns = {seed_qn, *callee_qns}

    # Fallback for coarse C parsing: include all Functions in the seed's File.
    if len(scope_qns) <= 1 and seed_fp:
        extra = session.run("""
            MATCH (f:Function {repo_id:$repo_id, commit:$commit, file_path:$fp})
            RETURN f.qualified_name AS qn
        """, repo_id=repo_id, commit=commit, fp=seed_fp)
        scope_qns.update(r["qn"] for r in extra)

    # Fetch full rows for the scope QNs.
    rows = session.run("""
        MATCH (f:Function {repo_id:$repo_id, commit:$commit})
        WHERE f.qualified_name IN $qns
        RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
               f.line_start AS ls, f.line_end AS le
        ORDER BY f.file_path, f.line_start
    """, repo_id=repo_id, commit=commit, qns=list(scope_qns))
    return [dict(r) for r in rows]


def _find_seed_qn(session, repo_id: str, commit: str, entrypoint: str) -> str | None:
    """Resolve a flexible entrypoint string to a concrete Function.qualified_name.

    Accepts:
      - Full qualified_name (exact match)
      - "<file>:<symbol>" or "<symbol>" (resolved by name; if multiple, prefer file match)
    """
    # 1. exact QN match
    r = session.run("""
        MATCH (f:Function {qualified_name:$qn, repo_id:$repo_id, commit:$commit})
        RETURN f.qualified_name AS qn LIMIT 1
    """, qn=entrypoint, repo_id=repo_id, commit=commit).single()
    if r:
        return r["qn"]

    # 2. parse "file:symbol" shorthand
    if ":" in entrypoint:
        file_part, _, sym = entrypoint.rpartition(":")
    else:
        file_part, sym = "", entrypoint

    rows = list(session.run("""
        MATCH (f:Function {repo_id:$repo_id, commit:$commit, name:$name})
        RETURN f.qualified_name AS qn, f.file_path AS fp
        ORDER BY f.file_path
    """, name=sym, repo_id=repo_id, commit=commit))
    if not rows:
        return None
    if file_part:
        for row in rows:
            if file_part in (row["fp"] or ""):
                return row["qn"]
    return rows[0]["qn"]


def _glob_to_regex(glob: str) -> str:
    """Translate a shell-style glob (*, ?, **) to a Neo4j regex anchored at both ends."""
    out: list[str] = ["^"]
    i = 0
    while i < len(glob):
        ch = glob[i]
        if ch == "*" and i + 1 < len(glob) and glob[i + 1] == "*":
            out.append(".*"); i += 2
        elif ch == "*":
            out.append("[^/]*"); i += 1
        elif ch == "?":
            out.append("[^/]"); i += 1
        elif ch in ".+()[]{}|^$\\":
            out.append("\\" + ch); i += 1
        else:
            out.append(ch); i += 1
    out.append("$")
    return "".join(out)


def mark_in_scope_in_neo4j(driver: Driver, repo_id: str, commit: str,
                           qns: list[str], *, entrypoint_kind: str | None = None,
                           trust_level: str | None = None) -> int:
    if not qns:
        return 0
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        r = session.run("""
            MATCH (f:Function {repo_id:$repo_id, commit:$commit})
            WHERE f.qualified_name IN $qns
            SET f.in_scope = true,
                f.entrypoint_kind = coalesce($ek, f.entrypoint_kind),
                f.trust_level     = coalesce($tl, f.trust_level)
            RETURN count(f) AS c
        """, repo_id=repo_id, commit=commit, qns=qns,
            ek=entrypoint_kind, tl=trust_level).single()
        return int(r["c"]) if r else 0


def record_audit_run_in_neo4j(
    driver: Driver, *, run_id: str, repo_id: str, commit: str,
    scope_spec: dict, depth: int, tools_image: str, mode: str,
    model: str, eval_commit: str | None, eval_commit_ts: str | None,
    status: str = "running", notes: str = "",
) -> None:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$id})
            ON CREATE SET run.started_at = datetime()
            SET run.repo_id = $repo_id, run.commit = $commit,
                run.scope_spec = $scope_spec, run.depth = $depth,
                run.tools_image = $tools_image, run.mode = $mode,
                run.eval_commit = $eval_commit,
                run.eval_commit_ts = CASE WHEN $eval_commit_ts IS NULL THEN NULL ELSE datetime($eval_commit_ts) END,
                run.model = $model, run.status = $status, run.notes = $notes,
                run.updated_at = datetime()
        """, id=run_id, repo_id=repo_id, commit=commit,
            scope_spec=json.dumps(scope_spec), depth=depth, tools_image=tools_image,
            mode=mode, eval_commit=eval_commit, eval_commit_ts=eval_commit_ts,
            model=model, status=status, notes=notes)


def finalize_audit_run(driver: Driver, run_id: str, status: str, n_findings: int) -> None:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MATCH (run:AuditRun {id:$id})
            SET run.status = $status, run.finished_at = datetime(),
                run.total_findings = $n
        """, id=run_id, status=status, n=n_findings)


def fetch_callgraph_text(driver: Driver, repo_id: str, commit: str,
                         seed_qn: str, depth: int) -> str:
    """Render a tiny human-readable call-graph slice for the sub-agent prompt.

    Contains four sections:
      CALLERS  — direct Function→Function inbound up to `depth` hops
      CALLEES  — direct Function→Function outbound up to `depth` hops
      TRUST PATH — backward walk from the seed to flagged untrusted entry points
                   (entrypoint_kind set, trust_level='UNTRUSTED', or name pattern)
      USAGE/WRITES — sparse cbm-derived edges. Useless for taint walks but cheap
                   to render when present and helps when name-resolution is poor.

    Module-level USAGE/CALLS fallback is appended to CALLERS when no Function-level
    inbound edges exist (cbm's C/TS parsers leave Function→Function edges sparse).
    """
    depth = max(1, min(5, depth))
    s = get_settings()
    lines: list[str] = []
    with driver.session(database=s.neo4j_database) as session:
        callees = list(session.run(f"""
            MATCH (seed:Function {{qualified_name:$qn, repo_id:$repo_id, commit:$commit}})
            OPTIONAL MATCH path = (seed)-[:CALLS*1..{depth}]->(c:Function)
            WITH c, min(length(path)) AS hops
            WHERE c IS NOT NULL
            RETURN c.qualified_name AS qn, c.name AS name, c.file_path AS fp,
                   c.line_start AS ls, hops
            ORDER BY hops, c.name LIMIT 30
        """, qn=seed_qn, repo_id=repo_id, commit=commit))
        callers = list(session.run(f"""
            MATCH (seed:Function {{qualified_name:$qn, repo_id:$repo_id, commit:$commit}})
            OPTIONAL MATCH path = (c:Function)-[:CALLS*1..{depth}]->(seed)
            WITH c, min(length(path)) AS hops
            WHERE c IS NOT NULL
            RETURN c.qualified_name AS qn, c.name AS name, c.file_path AS fp,
                   c.line_start AS ls, hops
            ORDER BY hops, c.name LIMIT 30
        """, qn=seed_qn, repo_id=repo_id, commit=commit))

        # Module-level fallback for coarse-parsed languages.
        module_callers = list(session.run("""
            MATCH (m)-[r:CALLS|USAGE]->(seed:Function {qualified_name:$qn, repo_id:$repo_id, commit:$commit})
            WHERE 'Module' IN labels(m) OR 'File' IN labels(m)
            RETURN labels(m)[0] AS kind, m.qualified_name AS qn, type(r) AS rel
            LIMIT 20
        """, qn=seed_qn, repo_id=repo_id, commit=commit))

        # TRUST PATH: backward walk to untrusted entry points. Uses the same Cypher
        # logic as the find_upstream_entrypoints MCP tool — pre-fetched here so the
        # agent has it in stdin without needing a separate roundtrip.
        trust_entries = list(session.run(f"""
            MATCH (seed:Function {{qualified_name:$qn, repo_id:$repo_id, commit:$commit}})
            MATCH (entry:Function {{repo_id:$repo_id, commit:$commit}})
            WHERE entry.qualified_name <> seed.qualified_name
              AND (
                entry.entrypoint_kind IS NOT NULL
                OR entry.trust_level = 'UNTRUSTED'
                OR entry.name =~ '(?i)(main|llvmfuzzertestoneinput|.*(handler|handle|route|webhook|endpoint|fuzzer|onrequest|onmessage))'
              )
            MATCH path = shortestPath((entry)-[:CALLS*1..{depth}]->(seed))
            WITH entry, path, length(path) AS hops
            RETURN entry.qualified_name AS entry_qn, entry.name AS entry_name,
                   entry.file_path AS entry_file, entry.entrypoint_kind AS entry_kind,
                   entry.trust_level AS trust_level, hops,
                   [n IN nodes(path)[1..-1] | n.qualified_name] AS intermediate_qns,
                   CASE
                     WHEN entry.entrypoint_kind IS NOT NULL THEN 'entrypoint_kind'
                     WHEN entry.trust_level = 'UNTRUSTED' THEN 'trust_level'
                     ELSE 'name_pattern'
                   END AS match_source
            ORDER BY hops ASC, entry.qualified_name ASC
            LIMIT 5
        """, qn=seed_qn, repo_id=repo_id, commit=commit))

        # USAGE / WRITES edges touching the seed. cbm emits these sparsely, but
        # when present they can carry type-reference / field-write signal that
        # the agent shouldn't have to query separately.
        usage_writes = list(session.run("""
            MATCH (a)-[r:USAGE|WRITES]-(seed:Function {qualified_name:$qn, repo_id:$repo_id, commit:$commit})
            WHERE a.qualified_name <> seed.qualified_name
            RETURN type(r) AS rel, labels(a)[0] AS kind, a.qualified_name AS qn,
                   startNode(r).qualified_name = seed.qualified_name AS outbound
            LIMIT 20
        """, qn=seed_qn, repo_id=repo_id, commit=commit))

    lines.append("=== CALLERS (inbound) ===")
    if callers:
        for r in callers:
            lines.append(f"  hop={r['hops']} {r['name']}  @ {r['fp']}:{r['ls']}")
    if module_callers:
        lines.append("  (Module/File-level fallback — cbm couldn't resolve precise callers:)")
        for r in module_callers:
            lines.append(f"    [{r['rel']} from {r['kind']}] {r['qn']}")
    if not callers and not module_callers:
        lines.append("  (none)")

    lines.append("")
    lines.append("=== CALLEES (outbound) ===")
    if callees:
        for r in callees:
            lines.append(f"  hop={r['hops']} {r['name']}  @ {r['fp']}:{r['ls']}")
    else:
        lines.append("  (none — cbm's call graph may be sparse for this language)")

    lines.append("")
    lines.append("=== TRUST PATH (shortest CALLS chain from each untrusted entry to this function) ===")
    if trust_entries:
        for r in trust_entries:
            kind_tag = r["entry_kind"] or r["trust_level"] or r["match_source"]
            chain = " -> ".join(r["intermediate_qns"]) if r["intermediate_qns"] else "(direct)"
            lines.append(
                f"  [{kind_tag}] {r['entry_name']}  @ {r['entry_file']}  "
                f"hops={r['hops']}  via: {chain}"
            )
        lines.append(
            "  (If any of these chains lacks an authn/authz/validation check between "
            "the entry and this function, the function inherits that untrusted reach.)"
        )
    else:
        lines.append(
            "  (no upstream entry reached within depth — function is not transitively "
            "called by any handler/route/webhook/fuzzer-shaped function at this depth)"
        )

    lines.append("")
    lines.append("=== USAGE / WRITES (sparse cbm edges touching this function) ===")
    if usage_writes:
        for r in usage_writes:
            arrow = "->" if r["outbound"] else "<-"
            lines.append(f"  {r['rel']} {arrow} [{r['kind']}] {r['qn']}")
    else:
        lines.append("  (none)")

    return "\n".join(lines)


def fetch_source_slice(abs_repo_root: Path, file_path: str, ls: int, le: int) -> str:
    """Return the source lines for a span (inclusive, 1-based)."""
    try:
        text = (abs_repo_root / file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    s, e = max(0, ls - 1), min(len(lines), le)
    return "\n".join(f"{n:5d}  {line}" for n, line in zip(range(s + 1, e + 1), lines[s:e]))


def write_sentinel_finding(
    driver: Driver, *, audit_run_id: str, function_qn: str | None,
    vuln_class: str, summary: str, rationale: str,
    file_path: str | None = None, line_start: int | None = None, line_end: int | None = None,
    tool_evidence: str = "",
) -> str:
    """Direct-Cypher sentinel writer (no MCP roundtrip). Used by the orchestrator on
    sub-agent failure (AGENT_FAILED) and on partial cbm index (INDEX_PARTIAL).
    Embedding is a zero vector so sentinels never participate in dedup/FP suppression.
    """
    s = get_settings()
    finding_id = str(uuid.uuid4())
    cypher_path = Path(__file__).resolve().parent.parent / "whw_mcp" / "cypher" / "add_sentinel_finding.cypher"
    cypher = cypher_path.read_text(encoding="utf-8")
    with driver.session(database=s.neo4j_database) as session:
        session.run(cypher, {
            "id": finding_id, "audit_run_id": audit_run_id,
            "vuln_class": vuln_class, "summary": summary, "rationale": rationale,
            "function_qn": function_qn,
            "file_path": file_path, "line_start": line_start, "line_end": line_end,
            "tool_evidence": tool_evidence,
            "zero_embedding": [0.0] * 768,
        })
    return finding_id


def count_findings_for_function(driver: Driver, run_id: str, function_qn: str) -> int:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        r = session.run("""
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {function_qn:$qn})
            RETURN count(n) AS c
        """, rid=run_id, qn=function_qn).single()
        return int(r["c"]) if r else 0


def count_findings_for_run(driver: Driver, run_id: str) -> int:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        r = session.run("""
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding)
            RETURN count(n) AS c
        """, rid=run_id).single()
        return int(r["c"]) if r else 0


# --- claude -p sub-agent spawning ---------------------------------------------

def write_mcp_config(target_path: Path, env: dict[str, str]) -> None:
    """Write the MCP config the sub-agent will use. Points at `python -m whw_mcp` over stdio."""
    repo_root = Path(__file__).resolve().parent.parent  # whitehat-weasel/
    cfg = {
        "mcpServers": {
            "whw": {
                "command": "uv",
                "args": ["--directory", str(repo_root), "run", "python", "-m", "whw_mcp"],
                "env": env,
            }
        }
    }
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(cfg, indent=2))


def build_task_message(*, run_id: str, repo_id: str, commit: str, mode: str,
                       eval_commit_ts: str | None, function_qn: str, name: str,
                       file_path: str, line_start: int, line_end: int,
                       callgraph_text: str, source_slice: str,
                       tools_image: str | None,
                       abs_repo_root: str | None,
                       user_context_excerpt: str | None) -> str:
    """Serialize the per-function task into a single string passed as the user message.

    When `tools_image` is supplied, includes a "STATIC ANALYSIS TOOLS" section that
    shows the agent the exact `docker run` invocation pattern (image name + the host
    mount path resolved from RepoCommit.abs_repo_root). Without that block, the
    system prompt's Bash hint is too abstract for the agent to act on.
    """
    parts = [
        f"audit_run_id: {run_id}",
        f"repo_id: {repo_id}",
        f"commit: {commit}",
        f"mode: {mode}",
    ]
    if eval_commit_ts:
        parts.append(f"eval_commit_ts: {eval_commit_ts}")
    parts.append("")
    parts.append(f"TARGET FUNCTION: {name}  (qualified_name: {function_qn})")
    parts.append(f"LOCATION: {file_path}:{line_start}-{line_end}")
    parts.append("")
    parts.append("CALL-GRAPH SLICE:")
    parts.append(callgraph_text)
    parts.append("")
    parts.append("SOURCE (with line numbers):")
    parts.append("```c")
    parts.append(source_slice or "(unavailable)")
    parts.append("```")
    if tools_image and abs_repo_root:
        parts.append("")
        parts.append("STATIC ANALYSIS TOOLS — Docker image is available:")
        parts.append(f"  image:       {tools_image}")
        parts.append(f"  mount path:  {abs_repo_root}  (mount read-only as /src)")
        parts.append("  example invocation (Bash is allowed for `docker run` against this image):")
        parts.append(f"    docker run --rm -v {abs_repo_root}:/src:ro {tools_image} \\")
        parts.append(f"      <tool> /src/{file_path}")
        parts.append("  Run the language's statics (e.g. clang-static-analyzer, cppcheck,")
        parts.append("  semgrep) to corroborate findings. Paste any non-trivial output")
        parts.append("  into the add_finding `tool_evidence` field.")
    elif tools_image and not abs_repo_root:
        parts.append("")
        parts.append(f"tools_image was set ({tools_image}) but the host mount path is unknown — "
                     "skip docker invocations and rely on source-only analysis.")
    if user_context_excerpt:
        parts.append("")
        parts.append("USER CONTEXT (excerpt):")
        parts.append(user_context_excerpt)
    parts.append("")
    parts.append("Per the system prompt: check classic & novel vulnerabilities, "
                 "call mcp__whw__add_finding for each, and end with the finished-JSON line.")
    return "\n".join(parts)


# ---------- shared claude -p plumbing (audit + triage + infra agents) -------

# Phase A tool surface — what the per-function audit sub-agent is allowed to call.
# When the orchestrator is given a `tools_image`, we additionally allow Bash invocations
# whose first tokens are `docker run *<image>*` so the agent can drive the language's
# static analyzers (clang static-analyzer, cppcheck, semgrep, etc.). See `_audit_allowed_tools`.
AUDIT_AGENT_ALLOWED_TOOLS = (
    "mcp__whw__add_finding,"
    "mcp__whw__find_in_scope,"
    "mcp__whw__get_callgraph_slice,"
    "mcp__whw__find_upstream_entrypoints,"
    "mcp__whw__get_snippet,"
    "mcp__whw__list_findings,"
    "mcp__whw__find_similar_findings,"
    "mcp__whw__get_prior_false_positives,"
    "Read"
)


def _audit_allowed_tools(tools_image: str | None) -> str:
    """Audit agent's allowed-tool list, augmented with a Bash pattern that restricts
    shell access to `docker run *<tools_image>*` when an image is supplied. Without
    this extension, the sub-agent prompt mentions a tools image it cannot actually use."""
    if not tools_image:
        return AUDIT_AGENT_ALLOWED_TOOLS
    # claude -p's allowed-tools entries are comma-separated; the Bash pattern itself
    # contains spaces but no commas, so the split is unambiguous.
    return f"{AUDIT_AGENT_ALLOWED_TOOLS},Bash(docker run *{tools_image}*)"

# B3.2 — re-triage sub-agent: read + 3 write tools (refute / refine / dedupe).
TRIAGE_AGENT_ALLOWED_TOOLS = (
    "mcp__whw__get_snippet,"
    "mcp__whw__get_callgraph_slice,"
    "mcp__whw__find_upstream_entrypoints,"
    "mcp__whw__find_similar_findings,"
    "mcp__whw__get_prior_false_positives,"
    "mcp__whw__list_findings,"
    "mcp__whw__mark_false_positive,"
    "mcp__whw__add_finding,"
    "mcp__whw__link_finding_duplicate,"
    "Read"
)

# B3.3 — production-context infra sub-agent: read + extract assets + file infra Findings.
INFRA_AGENT_ALLOWED_TOOLS = (
    "mcp__whw__upsert_production_asset,"
    "mcp__whw__add_finding,"
    "mcp__whw__link_finding_to_asset,"
    "mcp__whw__link_user_doc,"
    "mcp__whw__list_production_assets,"
    "Read"
)


def _build_claude_p_cmd(*, mcp_config_path: Path, system_prompt: str,
                        allowed_tools: str, model: str, max_turns: int) -> list[str]:
    """Common `claude -p` argv assembly. Each agent flavour picks its allowed-tools list."""
    s = get_settings()
    return [
        s.claude_code_bin, "-p",
        "--output-format", "stream-json",
        "--include-partial-messages",
        "--verbose",
        "--model", model,
        "--max-turns", str(max_turns),
        "--mcp-config", str(mcp_config_path),
        "--strict-mcp-config",
        "--allowed-tools", allowed_tools,
        "--append-system-prompt", system_prompt,
        "--setting-sources", "project",
    ]


def _run_claude_p(*, cmd: list[str], task: str, stdout_path: Path,
                  timeout_s: int) -> tuple[int, str | None]:
    """Run claude -p; write stdout to a file, capture stderr, return (rc, err_or_none).

    Recognised exit codes:
      0   — success
      124 — wall-clock timeout (we mapped from subprocess.TimeoutExpired)
      127 — `claude` binary missing
    """
    try:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        with stdout_path.open("w", encoding="utf-8") as out:
            proc = subprocess.run(
                cmd, input=task, stdout=out, stderr=subprocess.PIPE, text=True,
                timeout=timeout_s,
                cwd=str(Path(__file__).resolve().parent.parent),
            )
        return proc.returncode, (proc.stderr if proc.returncode != 0 else None)
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout_s}s"
    except FileNotFoundError as e:
        return 127, f"claude -p not found ({e}); set CLAUDE_CODE_BIN"


# ---------- per-function audit sub-agent -------------------------------------

def _spawn_subagent_attempt(
    *, function: dict, run_id: str, repo_id: str, commit: str, mode: str,
    eval_commit_ts: str | None, depth: int, run_dir: Path, mcp_config_path: Path,
    system_prompt_path: Path, tools_image: str | None, user_context_excerpt: str | None,
    driver: Driver, abs_repo_root: Path, attempt: int = 0,
) -> SubagentResult:
    """One attempt at running one sub-agent. Public callers should use
    `spawn_subagent_with_retries` which wraps this with backoff + sentinel-on-failure."""
    s = get_settings()
    qn = function["qn"]
    safe_qn = re.sub(r"[^A-Za-z0-9._-]+", "_", qn)[:200]
    suffix = f".attempt{attempt}" if attempt > 0 else ""
    stdout_path = run_dir / "agents" / f"{safe_qn}{suffix}.jsonl"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)

    callgraph_text = fetch_callgraph_text(driver, repo_id, commit, qn, depth)
    source_slice = fetch_source_slice(abs_repo_root, function["fp"], function["ls"], function["le"])

    task = build_task_message(
        run_id=run_id, repo_id=repo_id, commit=commit, mode=mode,
        eval_commit_ts=eval_commit_ts, function_qn=qn, name=function["name"] or qn,
        file_path=function["fp"], line_start=function["ls"], line_end=function["le"],
        callgraph_text=callgraph_text, source_slice=source_slice,
        tools_image=tools_image, abs_repo_root=str(abs_repo_root) if abs_repo_root else None,
        user_context_excerpt=user_context_excerpt,
    )

    system_prompt = system_prompt_path.read_text(encoding="utf-8")
    cmd = _build_claude_p_cmd(
        mcp_config_path=mcp_config_path, system_prompt=system_prompt,
        allowed_tools=_audit_allowed_tools(tools_image),
        model="sonnet", max_turns=s.whw_per_agent_max_turns,
    )

    started = time.monotonic()
    rc, err = _run_claude_p(cmd=cmd, task=task, stdout_path=stdout_path,
                            timeout_s=s.whw_per_agent_timeout_s)
    elapsed = round(time.monotonic() - started, 2)
    n_findings = count_findings_for_function(driver, run_id, qn) if rc != 127 else 0
    return SubagentResult(
        function_qn=qn, file_path=function["fp"],
        line_start=function["ls"], line_end=function["le"],
        exit_code=rc, elapsed_s=elapsed,
        n_findings_after=n_findings, stdout_path=str(stdout_path),
        error=err,
    )


def spawn_subagent_with_retries(
    *, function: dict, run_id: str, repo_id: str, commit: str, mode: str,
    eval_commit_ts: str | None, depth: int, run_dir: Path, mcp_config_path: Path,
    system_prompt_path: Path, tools_image: str | None, user_context_excerpt: str | None,
    driver: Driver, abs_repo_root: Path,
    rate_limiter: TokenBucket | None = None,
    max_retries: int = 2, backoff_base_s: float = 5.0,
) -> SubagentResult:
    """Spawn one sub-agent with rate-limit + retry-on-failure + AGENT_FAILED sentinel.

    Retries on:
      - rc != 0 (sub-process crash or non-zero exit)
      - timeout (rc == 124)
    Does NOT retry on `127` (claude binary missing) — bail immediately.

    After `max_retries` retries (so `max_retries + 1` attempts total) still failing, the
    orchestrator writes a sentinel `Finding{vuln_class:'AGENT_FAILED', severity:'info',
    confidence:'uncertain'}` so the function is visibly unaudited (localization treats
    AGENT_FAILED as a miss rather than silently skipping).
    """
    last_result: SubagentResult | None = None
    for attempt in range(max_retries + 1):
        if rate_limiter is not None:
            rate_limiter.acquire()

        result = _spawn_subagent_attempt(
            function=function, run_id=run_id, repo_id=repo_id, commit=commit, mode=mode,
            eval_commit_ts=eval_commit_ts, depth=depth, run_dir=run_dir,
            mcp_config_path=mcp_config_path, system_prompt_path=system_prompt_path,
            tools_image=tools_image, user_context_excerpt=user_context_excerpt,
            driver=driver, abs_repo_root=abs_repo_root, attempt=attempt,
        )
        last_result = result

        if result.exit_code == 0:
            return result
        if result.exit_code == 127:
            # claude binary missing — retrying won't fix it.
            break
        if attempt < max_retries:
            backoff = backoff_base_s * (2 ** attempt)
            print(f"  attempt {attempt + 1}/{max_retries + 1} for {function['name']} "
                  f"failed (rc={result.exit_code}); retrying in {backoff:.0f}s",
                  file=sys.stderr)
            time.sleep(backoff)

    # All attempts failed → write AGENT_FAILED sentinel so the function isn't silently
    # absent from the audit graph.
    assert last_result is not None
    write_sentinel_finding(
        driver,
        audit_run_id=run_id, function_qn=function["qn"],
        vuln_class="AGENT_FAILED",
        summary=f"sub-agent failed after {max_retries + 1} attempts (last rc={last_result.exit_code})",
        rationale=(f"Function {function['name']} ({function['fp']}:{function['ls']}-{function['le']}) "
                   f"was in scope but no sub-agent completed successfully. "
                   f"Last error: {last_result.error or '(no stderr captured)'}\n"
                   f"Treat this function as UNAUDITED. See agent stdout: {last_result.stdout_path}"),
        file_path=function["fp"], line_start=function["ls"], line_end=function["le"],
        tool_evidence=str(last_result.error or ""),
    )
    # Refresh n_findings to include the sentinel we just wrote.
    last_result.n_findings_after = count_findings_for_function(driver, run_id, function["qn"])
    return last_result


# ---------- re-triage sub-agent (B3.2) ---------------------------------------

def _build_triage_task(*, finding: dict, audit_run_id: str, source_slice: str) -> str:
    """Serialize one Finding into the triage agent's user message."""
    parts = [
        f"audit_run_id: {audit_run_id}",
        "",
        "TARGET FINDING:",
        f"  id:           {finding['id']}",
        f"  vuln_class:   {finding.get('vuln_class', '?')}",
        f"  severity:     {finding.get('severity', '?')}",
        f"  confidence:   {finding.get('confidence', '?')}",
        f"  function_qn:  {finding.get('function_qn') or '(none — infra)'}",
        f"  location:     {finding.get('file_path') or '?'}:"
        f"{finding.get('line_start') or '?'}-{finding.get('line_end') or '?'}",
        f"  source:       {finding.get('source', 'llm')}",
        "",
        "SUMMARY:",
        f"  {finding.get('summary', '')}",
        "",
        "RATIONALE:",
        finding.get('rationale', '') or "(none)",
        "",
        "CITED SOURCE:",
        "```",
        source_slice or "(source unavailable — use mcp__whw__get_snippet)",
        "```",
        "",
        "Per the system prompt: conclude exactly one of {confirm, refute, refine} and call "
        "the appropriate tool. End with the finished-JSON line.",
    ]
    return "\n".join(parts)


def _spawn_triage_attempt(
    *, finding: dict, audit_run_id: str, mcp_config_path: Path, system_prompt_path: Path,
    run_dir: Path, driver: Driver, abs_repo_root: Path | None,
    attempt: int = 0,
) -> TriageResult:
    """One triage sub-agent attempt. Caller layers retry/concurrency on top."""
    s = get_settings()
    fid = finding["id"]
    suffix = f".attempt{attempt}" if attempt > 0 else ""
    stdout_path = run_dir / "triage" / f"{fid}{suffix}.jsonl"

    source_slice = ""
    if abs_repo_root and finding.get("file_path") and finding.get("line_start"):
        source_slice = fetch_source_slice(
            abs_repo_root, finding["file_path"],
            int(finding["line_start"]), int(finding["line_end"] or finding["line_start"]),
        )

    task = _build_triage_task(
        finding=finding, audit_run_id=audit_run_id, source_slice=source_slice,
    )
    system_prompt = system_prompt_path.read_text(encoding="utf-8")
    cmd = _build_claude_p_cmd(
        mcp_config_path=mcp_config_path, system_prompt=system_prompt,
        allowed_tools=TRIAGE_AGENT_ALLOWED_TOOLS,
        model="sonnet", max_turns=10,  # triage is bounded; cheaper than initial audit
    )

    started = time.monotonic()
    rc, err = _run_claude_p(cmd=cmd, task=task, stdout_path=stdout_path,
                            timeout_s=max(120, s.whw_per_agent_timeout_s // 3))
    elapsed = round(time.monotonic() - started, 2)

    # Infer conclusion from Neo4j state post-exit.
    final_status, conclusion = _classify_triage_outcome(driver, fid)
    return TriageResult(
        finding_id=fid, function_qn=finding.get("function_qn"),
        exit_code=rc, elapsed_s=elapsed,
        final_status=final_status, conclusion=conclusion,
        stdout_path=str(stdout_path), error=err,
    )


def _classify_triage_outcome(driver: Driver, finding_id: str) -> tuple[str, str]:
    """Look at the Finding's post-triage state to infer the agent's conclusion.

    Mapping:
      status='fp'        → 'refute'
      status='duplicate' → 'refine' (agent filed a new finding + linked old as duplicate)
      status='open'      → 'confirm' (agent did nothing destructive)
      anything else      → 'unknown'
    """
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (n:Finding {id:$id}) RETURN n.status AS s", id=finding_id,
        ).single()
    if row is None:
        return ("missing", "failed")
    st = row["s"]
    return st, {"fp": "refute", "duplicate": "refine", "open": "confirm"}.get(st, "unknown")


def mark_finding_verified(driver: Driver, finding_id: str) -> None:
    """Promote a Finding from 'open' to 'verified' after a successful confirm-triage."""
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        session.run(
            "MATCH (n:Finding {id:$id}) WHERE n.status='open' "
            "SET n.status='verified', n.updated_at=datetime()",
            id=finding_id,
        )


# ---------- infra-context sub-agent (B3.3) -----------------------------------

def chunk_markdown_by_headings(text: str, *, max_chunks: int = 64) -> list[str]:
    """Split a markdown bundle on `## ` headings (level-2). Pre-amble before the first
    `##` becomes the first chunk. Empty chunks are filtered. Capped at `max_chunks`."""
    chunks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            if current:
                chunks.append("\n".join(current).strip())
                current = []
        current.append(line)
    if current:
        chunks.append("\n".join(current).strip())
    chunks = [c for c in chunks if c]
    return chunks[:max_chunks]


def _build_infra_task(*, audit_run_id: str, repo_id: str, commit: str,
                      bundle_path: str, bundle_text: str) -> str:
    """User message for the infra-context sub-agent."""
    parts = [
        f"audit_run_id: {audit_run_id}",
        f"repo_id:      {repo_id}",
        f"commit:       {commit}",
        f"bundle_path:  {bundle_path}",
        "",
        "PRODUCTION CONTEXT BUNDLE:",
        "```markdown",
        bundle_text,
        "```",
        "",
        "Per the system prompt: do two passes — extract every concrete asset via "
        "mcp__whw__upsert_production_asset, then file infra/config Findings via "
        "mcp__whw__add_finding (source='infra-pass', leave function_qn null) and "
        "immediately link each via mcp__whw__link_finding_to_asset. End with the "
        "finished-JSON line.",
    ]
    return "\n".join(parts)


def _spawn_infra_attempt(
    *, audit_run_id: str, repo_id: str, commit: str,
    bundle_path: Path, mcp_config_path: Path, system_prompt_path: Path,
    run_dir: Path, driver: Driver,
) -> InfraResult:
    """Run ONE infra sub-agent over the full user-context bundle."""
    s = get_settings()
    stdout_path = run_dir / "infra" / "main.jsonl"
    bundle_text = bundle_path.read_text(encoding="utf-8", errors="replace")

    # Snapshot pre-counts so we can compute deltas.
    pre_assets, pre_infra_findings = _count_infra_state(driver, audit_run_id)

    task = _build_infra_task(
        audit_run_id=audit_run_id, repo_id=repo_id, commit=commit,
        bundle_path=str(bundle_path), bundle_text=bundle_text,
    )
    system_prompt = system_prompt_path.read_text(encoding="utf-8")
    cmd = _build_claude_p_cmd(
        mcp_config_path=mcp_config_path, system_prompt=system_prompt,
        allowed_tools=INFRA_AGENT_ALLOWED_TOOLS,
        model="sonnet", max_turns=s.whw_per_agent_max_turns,
    )
    started = time.monotonic()
    rc, err = _run_claude_p(cmd=cmd, task=task, stdout_path=stdout_path,
                            timeout_s=s.whw_per_agent_timeout_s)
    elapsed = round(time.monotonic() - started, 2)

    post_assets, post_infra_findings = _count_infra_state(driver, audit_run_id)
    n_links = _count_asset_links(driver, audit_run_id)
    return InfraResult(
        audit_run_id=audit_run_id, exit_code=rc, elapsed_s=elapsed,
        n_assets_added=max(0, post_assets - pre_assets),
        n_findings_added=max(0, post_infra_findings - pre_infra_findings),
        n_asset_links=n_links,
        stdout_path=str(stdout_path), error=err,
    )


def _count_infra_state(driver: Driver, audit_run_id: str) -> tuple[int, int]:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        n_assets = session.run("MATCH (a:ProductionAsset) RETURN count(a) AS c").single()["c"]
        n_infra = session.run(
            "MATCH (:AuditRun {id:$rid})-[:FOUND]->(n:Finding {source:'infra-pass'}) "
            "RETURN count(n) AS c", rid=audit_run_id,
        ).single()["c"]
    return int(n_assets), int(n_infra)


def _count_asset_links(driver: Driver, audit_run_id: str) -> int:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        r = session.run(
            "MATCH (:AuditRun {id:$rid})-[:FOUND]->(:Finding)-[r:AFFECTS_ASSET]->(:ProductionAsset) "
            "RETURN count(r) AS c", rid=audit_run_id,
        ).single()
    return int(r["c"]) if r else 0


# --- top-level audit() ---------------------------------------------------------

def audit(
    *, repo_id: str, commit: str, scope: ScopeSpec,
    eval_commit: str | None = None, eval_commit_ts: str | None = None,
    tools_image: str | None = None, model: str = "sonnet",
    user_context_excerpt: str | None = None,
) -> AuditResult:
    """Top-level Phase A audit loop. Serial sub-agent fan-out.

    Returns an AuditResult and writes `.whw/run-<id>/{run.json, agents/*.jsonl}`.
    """
    s = get_settings()
    run_id = str(uuid.uuid4())
    run_dir = s.whw_run_dir / f"run-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)

    mode: Literal["live", "eval"] = "eval" if eval_commit else "live"
    if mode == "eval" and not eval_commit_ts:
        raise ValueError("eval_commit_ts is required when eval_commit is set")

    started = time.monotonic()
    driver = _open_driver()
    try:
        # Resolve the RepoCommit pointer for source slicing.
        with driver.session(database=s.neo4j_database) as session:
            row = session.run("""
                MATCH (r:RepoCommit {repo_id:$repo_id, commit:$commit})
                RETURN r.abs_repo_root AS p
            """, repo_id=repo_id, commit=commit).single()
        if not row or not row["p"]:
            raise RuntimeError(
                f"RepoCommit not registered for ({repo_id}, {commit}). Run `whw ingest` first."
            )
        abs_repo_root = Path(row["p"])

        # Resolve scope & flip in_scope=true.
        in_scope = resolve_scope(driver, repo_id, commit, scope)
        marked = mark_in_scope_in_neo4j(
            driver, repo_id, commit,
            [f["qn"] for f in in_scope],
            entrypoint_kind="fuzz_harness" if scope.entrypoint else None,
            trust_level="UNTRUSTED" if scope.entrypoint else None,
        )

        # Record the AuditRun.
        record_audit_run_in_neo4j(
            driver, run_id=run_id, repo_id=repo_id, commit=commit,
            scope_spec=asdict(scope), depth=scope.entrypoint_depth,
            tools_image=tools_image or "", mode=mode,
            model=model, eval_commit=eval_commit, eval_commit_ts=eval_commit_ts,
        )

        # Write the MCP config sub-agents will use.
        mcp_config_path = run_dir / "mcp.json"
        write_mcp_config(mcp_config_path, env={
            "NEO4J_URI": s.neo4j_uri,
            "NEO4J_USER": s.neo4j_user,
            "NEO4J_PASSWORD": s.neo4j_password,
            "NEO4J_DATABASE": s.neo4j_database,
            "WHW_EMBEDDING_BACKEND": s.whw_embedding_backend,
            "WHW_NOMIC_MODEL": s.whw_nomic_model,
            "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", s.anthropic_api_key),
        })

        sys_prompt_path = Path(__file__).resolve().parent / "prompts" / "subagent_system.md"
        max_parallel = max(1, int(s.whw_max_parallel))
        rate_limiter = TokenBucket(s.whw_rate_per_min) if s.whw_rate_per_min > 0 else None
        agent_results: list[SubagentResult] = []

        common_kwargs: dict[str, Any] = dict(
            run_id=run_id, repo_id=repo_id, commit=commit, mode=mode,
            eval_commit_ts=eval_commit_ts, depth=scope.entrypoint_depth,
            run_dir=run_dir, mcp_config_path=mcp_config_path,
            system_prompt_path=sys_prompt_path,
            tools_image=tools_image,
            user_context_excerpt=user_context_excerpt,
            driver=driver, abs_repo_root=abs_repo_root,
            rate_limiter=rate_limiter,
        )

        def _log(fn: dict, r: SubagentResult) -> None:
            print(f"  agent {fn['name']} → rc={r.exit_code} "
                  f"({r.elapsed_s}s, {r.n_findings_after} findings)",
                  file=sys.stderr)

        if max_parallel <= 1 or len(in_scope) <= 1:
            for fn in in_scope:
                result = spawn_subagent_with_retries(function=fn, **common_kwargs)
                agent_results.append(result)
                _log(fn, result)
        else:
            print(f"  fan-out: {len(in_scope)} agents × max_parallel={max_parallel}"
                  + (f", rate={s.whw_rate_per_min}/min" if rate_limiter else ""),
                  file=sys.stderr)
            with ThreadPoolExecutor(max_workers=max_parallel) as pool:
                futures = {
                    pool.submit(spawn_subagent_with_retries, function=fn, **common_kwargs): fn
                    for fn in in_scope
                }
                for fut in as_completed(futures):
                    fn = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as e:
                        # Hard failure inside the wrapper itself (shouldn't normally happen
                        # since the wrapper writes a sentinel on sub-agent failure).
                        result = SubagentResult(
                            function_qn=fn["qn"], file_path=fn["fp"],
                            line_start=fn["ls"], line_end=fn["le"],
                            exit_code=-1, elapsed_s=0.0, n_findings_after=0,
                            stdout_path="", error=f"orchestrator exception: {e!r}",
                        )
                    agent_results.append(result)
                    _log(fn, result)

        n_findings = count_findings_for_run(driver, run_id)
        finalize_audit_run(driver, run_id, status="completed", n_findings=n_findings)

        result = AuditResult(
            audit_run_id=run_id, repo_id=repo_id, commit=commit, mode=mode,
            eval_commit=eval_commit, scope_spec=asdict(scope),
            n_in_scope=marked, n_agents_run=len(agent_results),
            n_findings_total=n_findings,
            elapsed_s=round(time.monotonic() - started, 2),
            run_dir=str(run_dir),
            agents=agent_results,
        )
    finally:
        driver.close()

    # Persist the run summary.
    (run_dir / "run.json").write_text(json.dumps(result.to_dict(), indent=2))
    return result


# --- CLI -----------------------------------------------------------------------

def _main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Run an audit (Phase A serial mode).")
    p.add_argument("--repo-id", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--scope-entrypoint")
    p.add_argument("--scope-function")
    p.add_argument("--scope-file-glob")
    p.add_argument("--scope-all", action="store_true")
    p.add_argument("--depth", type=int, default=3)
    p.add_argument("--eval-commit")
    p.add_argument("--eval-commit-ts")
    p.add_argument("--tools-image")
    p.add_argument("--model", default="sonnet")
    args = p.parse_args()

    scope = ScopeSpec(
        entrypoint=args.scope_entrypoint,
        entrypoint_depth=args.depth,
        function=args.scope_function,
        file_glob=args.scope_file_glob,
        all=args.scope_all,
    )
    result = audit(
        repo_id=args.repo_id, commit=args.commit, scope=scope,
        eval_commit=args.eval_commit, eval_commit_ts=args.eval_commit_ts,
        tools_image=args.tools_image, model=args.model,
    )
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    _main()
