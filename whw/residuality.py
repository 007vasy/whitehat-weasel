"""Residuality probes — `whw doctor --stress`.

Per the plan's residuality table, the WHW pipeline has 5-8 dominant stressors that can
break the happy path: Neo4j down, MCP server down, sub-agent timeout, claude -p rate
limit, partial cbm index, embedding service failure. Each probe here exercises one
stressor's *detection* path and verifies the system's graceful-degradation residue.

Probes are deterministic (no API spend) and fast (<10s each). They return PASS / FAIL /
SKIP with a short detail message; the harness prints a Rich table summarising results.

Out of scope for Phase B (deferred to PoC stretch / Phase C):
  - sanitizer false-positive grading (only relevant once we actually run `build.sh`)
  - claude -p rate-limit auto-detection (we surface it via TokenBucket but don't probe)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from neo4j import GraphDatabase

from .config import get_settings


PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class ProbeResult:
    name: str
    status: str
    elapsed_s: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StressReport:
    probes: list[ProbeResult]
    n_pass: int = 0
    n_fail: int = 0
    n_skip: int = 0
    elapsed_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "probes": [p.to_dict() for p in self.probes],
            "n_pass": self.n_pass, "n_fail": self.n_fail, "n_skip": self.n_skip,
            "elapsed_s": self.elapsed_s,
        }


# ---------- probe implementations -------------------------------------------

def _timed(fn: Callable[[], tuple[str, str]]) -> tuple[str, str, float]:
    """Run `fn` and return (status, detail, elapsed_s). Exceptions become FAIL."""
    t0 = time.monotonic()
    try:
        st, detail = fn()
    except Exception as e:
        return FAIL, f"{type(e).__name__}: {e}", round(time.monotonic() - t0, 3)
    return st, detail, round(time.monotonic() - t0, 3)


def probe_neo4j_reachable() -> tuple[str, str]:
    """Verify the Neo4j driver can connect on the configured URI."""
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    try:
        driver.verify_connectivity()
        with driver.session(database=s.neo4j_database) as session:
            row = session.run("RETURN 1 AS x").single()
            assert row and row["x"] == 1
        return PASS, f"connected to {s.neo4j_uri}"
    finally:
        driver.close()


def probe_neo4j_schema_present() -> tuple[str, str]:
    """Expected constraints + the 4 vector indexes must be in place."""
    s = get_settings()
    expected_constraints = {
        "function_key", "file_key", "finding_id", "auditrun_id",
        "falsepositive_id", "productionasset_id", "repocommit_key",
    }
    expected_vec_indexes = {
        "function_embedding", "finding_embedding",
        "fp_embedding", "productionasset_embedding",
    }
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    try:
        with driver.session(database=s.neo4j_database) as session:
            cs = {r["name"] for r in session.run("SHOW CONSTRAINTS YIELD name RETURN name")}
            vs = {r["name"] for r in session.run(
                "SHOW INDEXES YIELD name, type WHERE type='VECTOR' RETURN name"
            )}
    finally:
        driver.close()
    missing_c = expected_constraints - cs
    missing_v = expected_vec_indexes - vs
    if missing_c or missing_v:
        return FAIL, (f"missing constraints: {sorted(missing_c) or '∅'} · "
                      f"missing vector indexes: {sorted(missing_v) or '∅'} "
                      f"— run scripts/bootstrap_neo4j.sh")
    return PASS, f"{len(cs)} constraints · {len(vs)} vector indexes"


def probe_mcp_server_builds() -> tuple[str, str]:
    """Audit MCP must be importable and register the full Phase A + B tool surface."""
    from whw_mcp.server import build_server  # late import to keep this module lean

    mcp = build_server()
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    if len(names) < 15:
        return FAIL, f"only {len(names)} tools registered (expected 15): {sorted(names)}"
    return PASS, f"{len(names)} tools registered"


def probe_mcp_server_subprocess_launches() -> tuple[str, str]:
    """`python -m whw_mcp` (or `uv run python -m whw_mcp`) must launch and stay alive.

    The MCP server runs on stdio with no input → it'll sit waiting. We give it 2s; if
    it crashed/exited in that window, it's broken. If it's still alive, terminate.
    """
    repo_root = Path(__file__).resolve().parent.parent
    cmd = ["uv", "--directory", str(repo_root), "run", "python", "-m", "whw_mcp"]
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(repo_root), text=True,
        )
    except FileNotFoundError:
        return SKIP, "uv not on PATH"

    try:
        time.sleep(2.0)
        if proc.poll() is None:
            return PASS, f"alive after 2s (pid {proc.pid})"
        rc = proc.returncode
        err = (proc.stderr.read(2000) if proc.stderr else "")[:500]
        return FAIL, f"exited rc={rc} within 2s; stderr head: {err!r}"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


def probe_embedding_backend() -> tuple[str, str]:
    """The configured backend (noop or nomic) must return a 768-dim list."""
    from whw_mcp.embeddings import EMBED_DIM, embed
    v = embed("residuality probe input")
    if not isinstance(v, list) or len(v) != EMBED_DIM:
        return FAIL, f"expected list[{EMBED_DIM}] float, got {type(v).__name__} of len {len(v) if hasattr(v, '__len__') else '?'}"
    backend = get_settings().whw_embedding_backend
    return PASS, f"backend={backend} · dim={EMBED_DIM}"


def probe_claude_p_available() -> tuple[str, str]:
    """`claude -p` binary must be on PATH for any sub-agent work."""
    bin_name = get_settings().claude_code_bin
    path = shutil.which(bin_name)
    if not path:
        return FAIL, f"`{bin_name}` not on PATH (set CLAUDE_CODE_BIN)"
    return PASS, path


def probe_sentinel_writer_round_trip() -> tuple[str, str]:
    """write_sentinel_finding must round-trip cleanly: create AuditRun, write sentinel,
    verify properties, clean up. Exercises the orchestrator's degradation path."""
    from .orchestrator import write_sentinel_finding

    s = get_settings()
    run_id = f"probe-{uuid.uuid4().hex[:8]}"
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    try:
        with driver.session(database=s.neo4j_database) as session:
            session.run("""
                MERGE (run:AuditRun {id:$rid})
                SET run.repo_id='probe', run.commit='c', run.model='probe',
                    run.status='probe', run.started_at=datetime()
            """, rid=run_id)
        fid = write_sentinel_finding(
            driver, audit_run_id=run_id, function_qn=None,
            vuln_class="AGENT_FAILED",
            summary="residuality probe sentinel",
            rationale="this finding exists for ~milliseconds; cleaned up below.",
        )
        with driver.session(database=s.neo4j_database) as session:
            row = session.run(
                "MATCH (n:Finding {id:$id}) RETURN n.vuln_class AS vc, n.source AS src",
                id=fid,
            ).single()
            # Cleanup.
            session.run(
                "MATCH (run:AuditRun {id:$rid}) "
                "OPTIONAL MATCH (run)-[:FOUND]->(n:Finding) "
                "DETACH DELETE n, run",
                rid=run_id,
            )
        if not row or row["vc"] != "AGENT_FAILED" or row["src"] != "orchestrator":
            return FAIL, f"sentinel round-trip wrong shape: {dict(row) if row else None}"
        return PASS, f"AGENT_FAILED sentinel round-tripped (id={fid[:8]}…)"
    finally:
        driver.close()


def probe_cbm_cli_available() -> tuple[str, str]:
    """codebase-memory-mcp CLI must be on PATH for ingest."""
    path = shutil.which("codebase-memory-mcp")
    if not path:
        return FAIL, "codebase-memory-mcp not on PATH"
    return PASS, path


# Order matters: cheaper probes first so failures surface quickly.
PROBES: list[tuple[str, Callable[[], tuple[str, str]]]] = [
    ("neo4j_reachable",                 probe_neo4j_reachable),
    ("neo4j_schema_present",            probe_neo4j_schema_present),
    ("embedding_backend",               probe_embedding_backend),
    ("cbm_cli_available",               probe_cbm_cli_available),
    ("claude_p_available",              probe_claude_p_available),
    ("mcp_server_builds",               probe_mcp_server_builds),
    ("sentinel_writer_round_trip",      probe_sentinel_writer_round_trip),
    # Subprocess launch is the slowest probe (~2s). Run last so faster failures preempt.
    ("mcp_server_subprocess_launches",  probe_mcp_server_subprocess_launches),
]


def run_all_probes() -> StressReport:
    """Run every probe; aggregate counts and elapsed time."""
    started = time.monotonic()
    results: list[ProbeResult] = []
    for name, fn in PROBES:
        status, detail, elapsed = _timed(fn)
        results.append(ProbeResult(name=name, status=status, elapsed_s=elapsed, detail=detail))
    report = StressReport(probes=results, elapsed_s=round(time.monotonic() - started, 3))
    report.n_pass = sum(1 for p in results if p.status == PASS)
    report.n_fail = sum(1 for p in results if p.status == FAIL)
    report.n_skip = sum(1 for p in results if p.status == SKIP)
    return report
