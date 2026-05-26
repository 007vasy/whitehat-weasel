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
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from neo4j import Driver, GraphDatabase

from .config import get_settings


# --- types ---------------------------------------------------------------------

@dataclass
class ScopeSpec:
    """Declarative description of what to audit. Exactly one strategy field should be set."""
    entrypoint: str | None = None           # QN or "<file_basename>:<symbol>" shorthand
    entrypoint_depth: int = 3
    file_glob: str | None = None            # SQL LIKE pattern (use % wildcards)
    function: str | None = None             # exact Function.name
    all: bool = False

    def describe(self) -> str:
        if self.entrypoint:
            return f"entrypoint={self.entrypoint} depth={self.entrypoint_depth}"
        if self.file_glob:
            return f"file_glob={self.file_glob}"
        if self.function:
            return f"function={self.function}"
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
            rows = session.run("""
                MATCH (f:Function {repo_id:$repo_id, commit:$commit})
                WHERE f.file_path =~ $regex
                RETURN f.qualified_name AS qn, f.name AS name, f.file_path AS fp,
                       f.line_start AS ls, f.line_end AS le
                ORDER BY f.file_path, f.line_start
            """, repo_id=repo_id, commit=commit, regex=_glob_to_regex(spec.file_glob))
            return [dict(r) for r in rows]

        if spec.entrypoint:
            return _resolve_entrypoint_scope(session, repo_id, commit, spec)

    raise ValueError("ScopeSpec is empty — set exactly one of entrypoint/file_glob/function/all.")


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
    Falls back to Module-level USAGE/CALLS if no Function→Function edges exist."""
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
                       user_context_excerpt: str | None) -> str:
    """Serialize the per-function task into a single string passed as the user message."""
    parts = [
        f"audit_run_id: {run_id}",
        f"repo_id: {repo_id}",
        f"commit: {commit}",
        f"mode: {mode}",
    ]
    if eval_commit_ts:
        parts.append(f"eval_commit_ts: {eval_commit_ts}")
    if tools_image:
        parts.append(f"tools_image: {tools_image}")
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
    if user_context_excerpt:
        parts.append("")
        parts.append("USER CONTEXT (excerpt):")
        parts.append(user_context_excerpt)
    parts.append("")
    parts.append("Per the system prompt: check classic & novel vulnerabilities, "
                 "call mcp__whw__add_finding for each, and end with the finished-JSON line.")
    return "\n".join(parts)


def spawn_subagent(
    *, function: dict, run_id: str, repo_id: str, commit: str, mode: str,
    eval_commit_ts: str | None, depth: int, run_dir: Path, mcp_config_path: Path,
    system_prompt_path: Path, tools_image: str | None, user_context_excerpt: str | None,
    driver: Driver, abs_repo_root: Path,
) -> SubagentResult:
    """Run one `claude -p` sub-agent for one in-scope function. Serial in Phase A."""
    s = get_settings()
    qn = function["qn"]
    safe_qn = re.sub(r"[^A-Za-z0-9._-]+", "_", qn)[:200]
    stdout_path = run_dir / "agents" / f"{safe_qn}.jsonl"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)

    callgraph_text = fetch_callgraph_text(driver, repo_id, commit, qn, depth)
    source_slice = fetch_source_slice(abs_repo_root, function["fp"], function["ls"], function["le"])

    task = build_task_message(
        run_id=run_id, repo_id=repo_id, commit=commit, mode=mode,
        eval_commit_ts=eval_commit_ts, function_qn=qn, name=function["name"] or qn,
        file_path=function["fp"], line_start=function["ls"], line_end=function["le"],
        callgraph_text=callgraph_text, source_slice=source_slice,
        tools_image=tools_image, user_context_excerpt=user_context_excerpt,
    )

    system_prompt = system_prompt_path.read_text(encoding="utf-8")

    cmd = [
        s.claude_code_bin, "-p",
        "--output-format", "stream-json",
        "--include-partial-messages",
        "--verbose",
        "--model", "sonnet",
        "--max-turns", str(s.whw_per_agent_max_turns),
        "--mcp-config", str(mcp_config_path),
        "--strict-mcp-config",
        "--allowed-tools", "mcp__whw__add_finding,mcp__whw__find_in_scope,"
                           "mcp__whw__get_callgraph_slice,mcp__whw__get_snippet,"
                           "mcp__whw__list_findings,Read",
        "--append-system-prompt", system_prompt,
        "--setting-sources", "project",
    ]

    started = time.monotonic()
    try:
        with stdout_path.open("w", encoding="utf-8") as out:
            proc = subprocess.run(
                cmd, input=task, stdout=out, stderr=subprocess.PIPE, text=True,
                timeout=s.whw_per_agent_timeout_s,
                cwd=str(Path(__file__).resolve().parent.parent),
            )
        err = proc.stderr if proc.returncode != 0 else None
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        rc, err = 124, f"timeout after {s.whw_per_agent_timeout_s}s"
    except FileNotFoundError as e:
        rc, err = 127, f"claude -p not found ({e}); set CLAUDE_CODE_BIN"

    elapsed = round(time.monotonic() - started, 2)
    n_findings = count_findings_for_function(driver, run_id, qn) if rc != 127 else 0
    return SubagentResult(
        function_qn=qn, file_path=function["fp"],
        line_start=function["ls"], line_end=function["le"],
        exit_code=rc, elapsed_s=elapsed,
        n_findings_after=n_findings, stdout_path=str(stdout_path),
        error=err,
    )


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
        agent_results: list[SubagentResult] = []
        for fn in in_scope:
            result = spawn_subagent(
                function=fn, run_id=run_id, repo_id=repo_id, commit=commit, mode=mode,
                eval_commit_ts=eval_commit_ts, depth=scope.entrypoint_depth,
                run_dir=run_dir, mcp_config_path=mcp_config_path,
                system_prompt_path=sys_prompt_path,
                tools_image=tools_image,
                user_context_excerpt=user_context_excerpt,
                driver=driver, abs_repo_root=abs_repo_root,
            )
            agent_results.append(result)
            print(f"  agent {fn['name']} → rc={result.exit_code} "
                  f"({result.elapsed_s}s, {result.n_findings_after} findings)",
                  file=sys.stderr)

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
