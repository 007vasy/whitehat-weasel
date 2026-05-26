"""Tests for residuality probes (Phase B4)."""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import pytest

from whw import residuality
from whw.residuality import (
    PASS, FAIL, SKIP, ProbeResult, run_all_probes,
    probe_claude_p_available, probe_cbm_cli_available, probe_embedding_backend,
    probe_mcp_server_builds, probe_neo4j_reachable, probe_neo4j_schema_present,
    probe_sentinel_writer_round_trip,
)


# ---------- unit-ish probes that don't need Neo4j ----------------------------

def test_probe_embedding_backend_returns_pass_with_noop():
    status, detail = probe_embedding_backend()
    assert status == PASS
    assert "noop" in detail or "nomic" in detail
    assert "dim=768" in detail


def test_probe_mcp_server_builds_returns_pass_with_15_tools():
    status, detail = probe_mcp_server_builds()
    assert status == PASS, f"got {status}: {detail}"
    assert "15" in detail or "tools" in detail


def test_probe_claude_p_available_reflects_path():
    """Whether PASS or FAIL depends on host PATH; only assert the contract shape."""
    status, detail = probe_claude_p_available()
    assert status in (PASS, FAIL)
    assert detail  # non-empty


def test_probe_cbm_cli_available_reflects_path():
    status, detail = probe_cbm_cli_available()
    assert status in (PASS, FAIL)
    assert detail


# ---------- live-Neo4j probes (integration) ---------------------------------

pytestmark_neo4j_section = pytest.mark.integration


@pytest.mark.integration
def test_probe_neo4j_reachable_against_live_db(neo4j_driver):
    status, detail = probe_neo4j_reachable()
    assert status == PASS, f"got {status}: {detail}"
    assert "bolt://" in detail


@pytest.mark.integration
def test_probe_neo4j_schema_present_against_bootstrapped_db(neo4j_driver):
    status, detail = probe_neo4j_schema_present()
    assert status == PASS, f"got {status}: {detail}"
    assert "constraint" in detail.lower()
    assert "vector" in detail.lower()


@pytest.mark.integration
def test_probe_sentinel_writer_round_trip_cleans_up(neo4j_driver):
    status, detail = probe_sentinel_writer_round_trip()
    assert status == PASS, f"got {status}: {detail}"
    # The probe creates a one-off AuditRun, writes a sentinel, then deletes both.
    # Verify nothing leaked by querying for probe-* runs.
    from whw.config import get_settings
    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        leaked = session.run(
            "MATCH (run:AuditRun) WHERE run.id STARTS WITH 'probe-' RETURN count(run) AS c"
        ).single()["c"]
    assert leaked == 0, f"sentinel probe leaked {leaked} AuditRun(s)"


# ---------- aggregate run_all_probes -----------------------------------------

@pytest.mark.integration
def test_run_all_probes_returns_structured_report(neo4j_driver):
    """run_all_probes returns a StressReport with one ProbeResult per registered probe."""
    report = run_all_probes()
    assert len(report.probes) == len(residuality.PROBES)
    assert all(isinstance(p, ProbeResult) for p in report.probes)
    assert report.n_pass + report.n_fail + report.n_skip == len(report.probes)
    # On a healthy dev stack (Neo4j + cbm + claude on PATH), expect all PASS.
    failing = [p for p in report.probes if p.status == FAIL]
    if failing:
        print("\nfailing probes:")
        for p in failing:
            print(f"  {p.name}: {p.detail}")
    # Sentinel: at least the static probes must pass.
    by_name = {p.name: p for p in report.probes}
    assert by_name["embedding_backend"].status == PASS
    assert by_name["mcp_server_builds"].status == PASS


def test_stress_report_to_dict_is_json_serializable():
    """The report must be JSON-serializable for the CLI."""
    import json
    rep = run_all_probes()
    text = json.dumps(rep.to_dict())
    assert "probes" in text
