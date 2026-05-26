"""End-to-end test: full WHW audit pipeline on arvo-1065 with a real `claude -p`.

Spawns ONE billable Claude Code sub-agent against the known-vulnerable `file_regexec`
function (libmagic's missing `memset(pmatch, ...)` per arvo-1065's L3 patch). Asserts:

  - the audit completes without an orchestrator-level error,
  - at least one :Finding is written by the sub-agent for this run,
  - the localization grader reports hit_at_file=True (the sub-agent flagged a span
    inside `file/src/funcs.c`, which IS the patched file).

Skipped unless the user explicitly opts in: `WHW_RUN_E2E=1` and `ANTHROPIC_API_KEY` set.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import json
from pathlib import Path

import pytest

from whw.config import get_settings
from whw.eval.cybergym_loader import find_sample
from whw.eval.localization import FindingLoc, grade
from whw.orchestrator import ScopeSpec, audit

from .conftest import CLAUDE_OK, DATA_ROOT, E2E_OPT_IN, HAVE_ARVO_1065


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not E2E_OPT_IN,
                       reason="set WHW_RUN_E2E=1 to authorize the API-billed sub-agent call"),
    pytest.mark.skipif(not CLAUDE_OK, reason="`claude` CLI not on PATH"),
    pytest.mark.skipif(not HAVE_ARVO_1065, reason="cybergym_data/arvo-1065 not present"),
]


def test_e2e_audit_file_regexec_flags_funcs_c(
    arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run,
):
    # The per-agent subprocess timeout in spawn_subagent is the real wall-clock limiter.
    s = get_settings()

    # Pin eval mode anchored before the 2017-04 libmagic fix, so even if WHW were
    # previously run on patched data those findings stay hidden.
    result = audit(
        repo_id=arvo_1065_ingested["repo_id"],
        commit=arvo_1065_ingested["commit"],
        scope=ScopeSpec(function="file_regexec"),
        eval_commit=arvo_1065_ingested["commit"],
        eval_commit_ts="2017-01-01T00:00:00Z",
        model="sonnet",
    )
    cleanup_neo4j_run(result.audit_run_id)

    print("\nAudit summary:")
    print(json.dumps(result.to_dict(), indent=2))

    assert result.n_in_scope == 1, \
        f"expected exactly one in-scope function (file_regexec); got {result.n_in_scope}"
    assert result.n_agents_run == 1
    agent = result.agents[0]
    assert agent.exit_code == 0, f"sub-agent failed: rc={agent.exit_code} err={agent.error}"
    assert result.n_findings_total >= 1, (
        "expected >=1 Finding for the known UNINIT_MEMORY bug in file_regexec; got 0. "
        "(Prompt or model issue — review .whw/run-<id>/agents/*.jsonl for traces.)"
    )

    # Fetch findings + grade against L3 patch.
    with neo4j_driver.session(database=s.neo4j_database) as session:
        rows = list(session.run(
            """
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding)
            RETURN n.id AS id, n.file_path AS fp, n.line_start AS ls,
                   n.line_end AS le, n.severity AS sev, n.confidence AS conf,
                   n.vuln_class AS vc, n.summary AS summary
            """,
            rid=result.audit_run_id,
        ))
    print(f"\nFindings ({len(rows)}):")
    for r in rows:
        print(f"  [{r['vc']}/{r['sev']}/{r['conf']}] {r['fp']}:{r['ls']}-{r['le']}  {r['summary']}")

    cg = find_sample("arvo-1065", DATA_ROOT)
    assert cg.patch_hunks, "L3 patch.diff should yield >=1 hunk"

    findings = [
        FindingLoc(
            id=r["id"] or "", file_path=r["fp"] or "",
            line_start=int(r["ls"] or 0), line_end=int(r["le"] or 0),
            severity=r["sev"] or "med", confidence=r["conf"] or "inferred",
        )
        for r in rows if r["fp"]
    ]
    g = grade(findings, cg.patch_hunks, sample_id="arvo-1065",
              audit_run_id=result.audit_run_id)
    print("\nLocalization grade:")
    print(json.dumps(g.to_dict(), indent=2))

    assert g.hit_at_file is True, (
        "The audited function `file_regexec` lives in file/src/funcs.c (the file the "
        "L3 patch touches). hit_at_file=False means the agent's Finding cited a path "
        "that didn't resolve to funcs.c — bug in path normalization or in the prompt."
    )
    # hit_at_line is a stretch — the agent may flag a slightly wider/narrower span than
    # the 2-line patch hunk. Leave it as an informative print, not a hard assert.
