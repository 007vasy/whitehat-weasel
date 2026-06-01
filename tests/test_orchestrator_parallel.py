"""Tests for Phase B orchestrator: TokenBucket, sentinel writer, retry wrapper.

Three layers:
  - TokenBucket unit (fast, deterministic).
  - write_sentinel_finding integration (live Neo4j; no claude -p).
  - spawn_subagent_with_retries with the inner attempt fn monkey-patched (no claude -p).
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import time
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from whw.config import get_settings
from whw.orchestrator import (
    SubagentResult,
    TokenBucket,
    spawn_subagent_with_retries,
    write_sentinel_finding,
)


# ---------- TokenBucket unit tests (no fixtures) -----------------------------

def test_token_bucket_full_acquire_is_instant():
    tb = TokenBucket(rate_per_min=60)  # capacity = 60
    t0 = time.monotonic()
    for _ in range(10):
        tb.acquire()
    assert time.monotonic() - t0 < 0.2  # 10 tokens consumed instantly from full bucket


def test_token_bucket_blocks_when_empty():
    """At 60/min the refill rate is 1/sec. After draining, the next acquire blocks ~1s."""
    tb = TokenBucket(rate_per_min=60)
    # Drain the bucket.
    for _ in range(60):
        tb.acquire()
    t0 = time.monotonic()
    tb.acquire()  # should block ~1 second waiting for one token to refill
    elapsed = time.monotonic() - t0
    assert 0.5 < elapsed < 2.0, f"expected ~1s wait, got {elapsed:.2f}s"


def test_token_bucket_rejects_invalid_rate():
    with pytest.raises(ValueError):
        TokenBucket(rate_per_min=0)
    with pytest.raises(ValueError):
        TokenBucket(rate_per_min=-5)


# ---------- write_sentinel_finding integration -------------------------------

pytestmark_integration = pytest.mark.integration


@pytest.mark.integration
def test_write_sentinel_finding_creates_agent_failed(
    arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run,
):
    """write_sentinel_finding directly inserts a Finding without going through MCP.
    AGENT_FAILED sentinels must use 'orchestrator' as source and zero embedding so
    they don't poison the dedup/FP vector indexes."""
    s = get_settings()
    run_id = str(uuid.uuid4())
    cleanup_neo4j_run(run_id)

    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$rid})
            SET run.repo_id='arvo-1065', run.commit='vul', run.model='test',
                run.status='running', run.started_at=datetime()
        """, rid=run_id)
        qn = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn"
        ).single()["qn"]

    fid = write_sentinel_finding(
        neo4j_driver,
        audit_run_id=run_id, function_qn=qn,
        vuln_class="AGENT_FAILED",
        summary="sub-agent failed after 3 attempts (last rc=124)",
        rationale="Function file_regexec timed out repeatedly; treat as UNAUDITED.",
        file_path="file/src/funcs.c", line_start=507, line_end=513,
        tool_evidence="timeout after 600s",
    )
    assert fid

    # Pure Cypher (no APOC) — `reduce` sums the zero vector to confirm sentinels don't
    # poison the vector indexes.
    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run("""
            MATCH (n:Finding {id:$fid})
            RETURN n.vuln_class AS vc, n.severity AS sev, n.confidence AS conf,
                   n.source AS src, n.status AS status,
                   n.function_qn AS qn, n.file_path AS fp,
                   size(n.embedding) AS emb_dim,
                   reduce(t = 0.0, x IN n.embedding | t + x) AS emb_sum
        """, fid=fid).single()

    assert row["vc"] == "AGENT_FAILED"
    assert row["sev"] == "info"
    assert row["conf"] == "uncertain"
    assert row["src"] == "orchestrator"
    assert row["status"] == "open"
    assert row["qn"] == qn
    assert row["fp"] == "file/src/funcs.c"
    assert row["emb_dim"] == 768
    assert row["emb_sum"] == pytest.approx(0.0)


# ---------- spawn_subagent_with_retries — retry behavior via patching --------

def _make_attempt_result(rc: int, qn: str) -> SubagentResult:
    return SubagentResult(
        function_qn=qn, file_path="file/src/funcs.c",
        line_start=507, line_end=513, exit_code=rc, elapsed_s=0.01,
        n_findings_after=(1 if rc == 0 else 0),
        stdout_path="/tmp/x.jsonl", error=None if rc == 0 else f"rc={rc}",
    )


@pytest.mark.integration
def test_retry_succeeds_on_second_attempt(arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run):
    """fail-then-succeed pattern: wrapper retries once and returns the success."""
    s = get_settings()
    run_id = str(uuid.uuid4())
    cleanup_neo4j_run(run_id)
    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$rid})
            SET run.repo_id='arvo-1065', run.commit='vul', run.model='test',
                run.status='running', run.started_at=datetime()
        """, rid=run_id)
        qn = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn"
        ).single()["qn"]
    fn = {"qn": qn, "name": "file_regexec", "fp": "file/src/funcs.c", "ls": 507, "le": 513}

    call_count = {"n": 0}

    def fake_attempt(**kwargs):
        call_count["n"] += 1
        rc = 1 if call_count["n"] == 1 else 0
        return _make_attempt_result(rc, qn)

    with patch("whw.orchestrator._spawn_subagent_attempt", side_effect=fake_attempt):
        result = spawn_subagent_with_retries(
            function=fn, run_id=run_id, repo_id="arvo-1065", commit="vul",
            mode="live", eval_commit_ts=None, depth=1,
            run_dir=Path("/tmp/whw-test-rd"), mcp_config_path=Path("/tmp/x.json"),
            system_prompt_path=Path("/tmp/x.md"),
            tools_image=None, user_context_excerpt=None,
            driver=neo4j_driver, abs_repo_root=Path("/tmp"),
            rate_limiter=None,
            max_retries=2, backoff_base_s=0.01,
        )

    assert call_count["n"] == 2
    assert result.exit_code == 0
    # No sentinel written (success).
    with neo4j_driver.session(database=s.neo4j_database) as session:
        n_sent = session.run(
            "MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {vuln_class:'AGENT_FAILED'}) "
            "RETURN count(n) AS c", rid=run_id,
        ).single()["c"]
    assert n_sent == 0


@pytest.mark.integration
def test_all_attempts_fail_writes_sentinel(arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run):
    """All attempts fail → wrapper writes an AGENT_FAILED sentinel and returns the
    last failure result, with n_findings_after refreshed to include the sentinel."""
    s = get_settings()
    run_id = str(uuid.uuid4())
    cleanup_neo4j_run(run_id)
    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$rid})
            SET run.repo_id='arvo-1065', run.commit='vul', run.model='test',
                run.status='running', run.started_at=datetime()
        """, rid=run_id)
        qn = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn"
        ).single()["qn"]
    fn = {"qn": qn, "name": "file_regexec", "fp": "file/src/funcs.c", "ls": 507, "le": 513}

    call_count = {"n": 0}

    def fake_attempt(**kwargs):
        call_count["n"] += 1
        return _make_attempt_result(1, qn)  # always fails

    with patch("whw.orchestrator._spawn_subagent_attempt", side_effect=fake_attempt):
        result = spawn_subagent_with_retries(
            function=fn, run_id=run_id, repo_id="arvo-1065", commit="vul",
            mode="live", eval_commit_ts=None, depth=1,
            run_dir=Path("/tmp/whw-test-rd"), mcp_config_path=Path("/tmp/x.json"),
            system_prompt_path=Path("/tmp/x.md"),
            tools_image=None, user_context_excerpt=None,
            driver=neo4j_driver, abs_repo_root=Path("/tmp"),
            rate_limiter=None,
            max_retries=2, backoff_base_s=0.01,
        )

    assert call_count["n"] == 3  # initial + 2 retries
    assert result.exit_code == 1
    assert result.n_findings_after == 1  # sentinel counts

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {vuln_class:'AGENT_FAILED'}) "
            "RETURN n.summary AS summary, n.source AS source",
            rid=run_id,
        ).single()
    assert row is not None
    assert "3 attempts" in row["summary"]
    assert row["source"] == "orchestrator"


@pytest.mark.integration
def test_rc_127_does_not_retry(arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run):
    """rc=127 means claude binary missing — retrying won't help. Bail immediately
    (still writes a sentinel so the function isn't silently absent)."""
    s = get_settings()
    run_id = str(uuid.uuid4())
    cleanup_neo4j_run(run_id)
    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$rid})
            SET run.repo_id='arvo-1065', run.commit='vul', run.model='test',
                run.status='running', run.started_at=datetime()
        """, rid=run_id)
        qn = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn"
        ).single()["qn"]
    fn = {"qn": qn, "name": "file_regexec", "fp": "file/src/funcs.c", "ls": 507, "le": 513}

    call_count = {"n": 0}

    def fake_attempt(**kwargs):
        call_count["n"] += 1
        return _make_attempt_result(127, qn)

    with patch("whw.orchestrator._spawn_subagent_attempt", side_effect=fake_attempt):
        result = spawn_subagent_with_retries(
            function=fn, run_id=run_id, repo_id="arvo-1065", commit="vul",
            mode="live", eval_commit_ts=None, depth=1,
            run_dir=Path("/tmp/whw-test-rd"), mcp_config_path=Path("/tmp/x.json"),
            system_prompt_path=Path("/tmp/x.md"),
            tools_image=None, user_context_excerpt=None,
            driver=neo4j_driver, abs_repo_root=Path("/tmp"),
            rate_limiter=None,
            max_retries=2, backoff_base_s=0.01,
        )

    assert call_count["n"] == 1  # no retries on 127
    assert result.exit_code == 127
