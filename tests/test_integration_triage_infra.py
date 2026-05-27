"""Integration tests for consolidate_triage and consolidate_infra (Phase B3.2 + B3.3).

Mocks `_spawn_triage_attempt` / `_spawn_infra_attempt` so tests don't spawn billable
`claude -p` sub-agents. The mocks mutate Neo4j to simulate what a real agent would do
(via the audit MCP), then return a constructed Result. This validates the orchestration
layer (fan-out, status promotion, count aggregation) without touching the network.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import uuid
from pathlib import Path
from unittest.mock import patch

import pytest

from whw.config import get_settings
from whw.consolidate import consolidate_infra, consolidate_triage
from whw.orchestrator import InfraResult, TriageResult


pytestmark = pytest.mark.integration


# ---------- helpers ----------------------------------------------------------

def _inject_finding(driver, run_id: str, *, summary: str = "synthetic open finding") -> str:
    """Create a single open :Finding with a non-zero embedding."""
    s = get_settings()
    fid = str(uuid.uuid4())
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MATCH (run:AuditRun {id:$rid})
            CREATE (n:Finding {
                id:$fid, vuln_class:'TEST', severity:'med', confidence:'inferred',
                summary:$summary, rationale:'r', source:'test', tool_evidence:'',
                created_at:datetime(), commit_observed_at:datetime(),
                audit_run_id:$rid, status:'open', model_used:'test',
                repo_id:run.repo_id, commit:run.commit,
                embedding:$emb
            })
            MERGE (run)-[:FOUND]->(n)
        """, rid=run_id, fid=fid, summary=summary, emb=[0.1] * 768)
    return fid


def _ensure_run(driver, run_id: str) -> None:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$rid})
            SET run.repo_id='triage-test', run.commit='c1', run.model='test',
                run.mode='live', run.status='running', run.started_at=datetime()
            MERGE (rc:RepoCommit {repo_id:'triage-test', commit:'c1'})
            SET rc.abs_repo_root='/tmp', rc.updated_at=datetime()
        """, rid=run_id)


def _finding_status(driver, fid: str) -> str:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        row = session.run("MATCH (n:Finding {id:$id}) RETURN n.status AS s", id=fid).single()
    return row["s"] if row else "missing"


# ---------- triage tests -----------------------------------------------------

@pytest.fixture
def triage_run(neo4j_driver, cleanup_neo4j_run):
    rid = str(uuid.uuid4())
    _ensure_run(neo4j_driver, rid)
    cleanup_neo4j_run(rid)
    return rid


def test_triage_confirm_promotes_to_verified(neo4j_driver, triage_run):
    """When the agent does nothing destructive, the Finding stays 'open' → orchestrator
    promotes it to 'verified'."""
    fid = _inject_finding(neo4j_driver, triage_run)

    def fake_attempt(*, finding, **_kwargs):
        # Agent did nothing — Finding remains 'open', orchestrator infers 'confirm'.
        return TriageResult(
            finding_id=finding["id"], function_qn=finding.get("function_qn"),
            exit_code=0, elapsed_s=0.01,
            final_status="open", conclusion="confirm",
            stdout_path="/tmp/x.jsonl", error=None,
        )

    with patch("whw.orchestrator._spawn_triage_attempt", side_effect=fake_attempt):
        res = consolidate_triage(triage_run, max_parallel=1, driver=neo4j_driver)

    assert res.n_open_at_start == 1
    assert res.n_confirm == 1
    assert res.n_refute == 0
    assert res.n_refine == 0
    assert res.n_failed == 0
    assert _finding_status(neo4j_driver, fid) == "verified"


def test_triage_refute_simulates_mark_false_positive(neo4j_driver, triage_run):
    """Simulate the agent calling mark_false_positive (flips status to 'fp')."""
    fid = _inject_finding(neo4j_driver, triage_run)
    s = get_settings()

    def fake_attempt(*, finding, driver, **_kwargs):
        # Simulate the agent calling mcp__whw__mark_false_positive.
        with driver.session(database=s.neo4j_database) as session:
            session.run("MATCH (n:Finding {id:$id}) SET n.status='fp'", id=finding["id"])
        return TriageResult(
            finding_id=finding["id"], function_qn=finding.get("function_qn"),
            exit_code=0, elapsed_s=0.01,
            final_status="fp", conclusion="refute",
            stdout_path="/tmp/x.jsonl", error=None,
        )

    with patch("whw.orchestrator._spawn_triage_attempt", side_effect=fake_attempt):
        res = consolidate_triage(triage_run, max_parallel=1, driver=neo4j_driver)

    assert res.n_refute == 1
    assert res.n_confirm == 0
    assert _finding_status(neo4j_driver, fid) == "fp"


def test_triage_refine_simulates_link_finding_duplicate(neo4j_driver, triage_run):
    """Simulate the agent calling link_finding_duplicate (flips status to 'duplicate')."""
    fid = _inject_finding(neo4j_driver, triage_run)
    s = get_settings()

    def fake_attempt(*, finding, driver, **_kwargs):
        with driver.session(database=s.neo4j_database) as session:
            session.run(
                "MATCH (n:Finding {id:$id}) SET n.status='duplicate', n.dedup_of='other'",
                id=finding["id"],
            )
        return TriageResult(
            finding_id=finding["id"], function_qn=finding.get("function_qn"),
            exit_code=0, elapsed_s=0.01,
            final_status="duplicate", conclusion="refine",
            stdout_path="/tmp/x.jsonl", error=None,
        )

    with patch("whw.orchestrator._spawn_triage_attempt", side_effect=fake_attempt):
        res = consolidate_triage(triage_run, max_parallel=1, driver=neo4j_driver)

    assert res.n_refine == 1
    assert res.n_confirm == 0
    assert _finding_status(neo4j_driver, fid) == "duplicate"


def test_triage_agent_failure_counts_as_failed(neo4j_driver, triage_run):
    fid = _inject_finding(neo4j_driver, triage_run)

    def fake_attempt(*, finding, **_kwargs):
        return TriageResult(
            finding_id=finding["id"], function_qn=finding.get("function_qn"),
            exit_code=1, elapsed_s=0.01,
            final_status="open", conclusion="failed",
            stdout_path="/tmp/x.jsonl", error="rc=1",
        )

    with patch("whw.orchestrator._spawn_triage_attempt", side_effect=fake_attempt):
        res = consolidate_triage(triage_run, max_parallel=1, driver=neo4j_driver)

    assert res.n_failed == 1
    assert res.n_confirm == 0
    # The finding stays 'open' — orchestrator only promotes when conclusion='confirm'.
    assert _finding_status(neo4j_driver, fid) == "open"


def test_triage_empty_run_is_noop(neo4j_driver, triage_run):
    """No open findings → no sub-agents spawned, all counters zero."""
    res = consolidate_triage(triage_run, max_parallel=1, driver=neo4j_driver)
    assert res.n_open_at_start == 0
    assert res.n_confirm == res.n_refute == res.n_refine == res.n_failed == 0
    assert res.agents == []


def test_triage_mixed_outcomes(neo4j_driver, triage_run):
    """Three findings, three different outcomes — counts reflect the mix."""
    fids = [_inject_finding(neo4j_driver, triage_run, summary=f"f{i}") for i in range(3)]
    s = get_settings()
    call_idx = {"n": 0}

    def fake_attempt(*, finding, driver, **_kwargs):
        i = call_idx["n"]
        call_idx["n"] += 1
        idx = fids.index(finding["id"]) if finding["id"] in fids else i
        if idx == 0:
            return TriageResult(
                finding_id=finding["id"], function_qn=None,
                exit_code=0, elapsed_s=0.01,
                final_status="open", conclusion="confirm",
                stdout_path="", error=None,
            )
        if idx == 1:
            with driver.session(database=s.neo4j_database) as session:
                session.run("MATCH (n:Finding {id:$id}) SET n.status='fp'", id=finding["id"])
            return TriageResult(
                finding_id=finding["id"], function_qn=None,
                exit_code=0, elapsed_s=0.01,
                final_status="fp", conclusion="refute",
                stdout_path="", error=None,
            )
        return TriageResult(
            finding_id=finding["id"], function_qn=None,
            exit_code=1, elapsed_s=0.01,
            final_status="open", conclusion="failed",
            stdout_path="", error="rc=1",
        )

    with patch("whw.orchestrator._spawn_triage_attempt", side_effect=fake_attempt):
        res = consolidate_triage(triage_run, max_parallel=1, driver=neo4j_driver)

    assert res.n_open_at_start == 3
    assert res.n_confirm == 1
    assert res.n_refute == 1
    assert res.n_failed == 1


# ---------- infra tests ------------------------------------------------------

def test_consolidate_infra_returns_counts(neo4j_driver, triage_run, tmp_path):
    """consolidate_infra wraps the sub-agent's InfraResult + counts asset links."""
    bundle = tmp_path / "runbook.md"
    bundle.write_text("## prod db\nprimary user DB at db.prod\n")

    def fake_attempt(**kwargs):
        return InfraResult(
            audit_run_id=kwargs["audit_run_id"],
            exit_code=0, elapsed_s=0.5,
            n_assets_added=2, n_findings_added=1, n_asset_links=0,
            stdout_path="/tmp/infra.jsonl", error=None,
        )

    with patch("whw.orchestrator._spawn_infra_attempt", side_effect=fake_attempt):
        res = consolidate_infra(triage_run, user_context_path=bundle,
                                also_link=False, driver=neo4j_driver)

    assert res.audit_run_id == triage_run
    assert res.exit_code == 0
    assert res.n_assets_added == 2
    assert res.n_findings_added == 1
    assert res.bundle_path == str(bundle.resolve())
    assert res.error is None


def test_consolidate_infra_missing_bundle_raises(neo4j_driver, triage_run, tmp_path):
    with pytest.raises(FileNotFoundError):
        consolidate_infra(triage_run, user_context_path=tmp_path / "nope.md",
                          driver=neo4j_driver)


def test_consolidate_infra_failed_agent_propagates(neo4j_driver, triage_run, tmp_path):
    bundle = tmp_path / "x.md"
    bundle.write_text("## bad\n")

    def fake_attempt(**kwargs):
        return InfraResult(
            audit_run_id=kwargs["audit_run_id"],
            exit_code=124, elapsed_s=600.0,
            n_assets_added=0, n_findings_added=0, n_asset_links=0,
            stdout_path="/tmp/infra.jsonl", error="timeout after 600s",
        )

    with patch("whw.orchestrator._spawn_infra_attempt", side_effect=fake_attempt):
        res = consolidate_infra(triage_run, user_context_path=bundle, driver=neo4j_driver)

    assert res.exit_code == 124
    assert res.error and "timeout" in res.error
    assert res.n_assets_added == 0


# ---------- markdown chunking unit -------------------------------------------

def test_chunk_markdown_by_headings_splits_on_h2():
    from whw.orchestrator import chunk_markdown_by_headings
    md = "preamble line\n## first\nbody a\nbody a2\n## second\nbody b\n"
    chunks = chunk_markdown_by_headings(md)
    assert len(chunks) == 3
    assert chunks[0].startswith("preamble")
    assert chunks[1].startswith("## first")
    assert chunks[2].startswith("## second")


def test_chunk_markdown_filters_empties_and_caps():
    from whw.orchestrator import chunk_markdown_by_headings
    md = "\n\n## a\n\n## b\n\n"
    chunks = chunk_markdown_by_headings(md, max_chunks=10)
    # Empty preamble is filtered.
    assert all(c.strip() for c in chunks)
    # Heading-only chunks are still kept (non-empty after strip).
    assert chunks == ["## a", "## b"]


def test_chunk_markdown_empty_input():
    from whw.orchestrator import chunk_markdown_by_headings
    assert chunk_markdown_by_headings("") == []
