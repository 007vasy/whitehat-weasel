"""Integration tests for the whw_mcp Phase A tool set against a LIVE Neo4j.

Skips cleanly if Neo4j is unreachable or arvo-1065 isn't ingested. Each test exercises
one (or a few) MCP tools end-to-end: builds the FastMCP server, looks up the tool by
name, invokes it via `mcp.call_tool()`, and asserts on the returned payload + Neo4j
side-effects.
"""

from __future__ import annotations

import os

# Force noop embeddings (don't download torch in CI).
os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import uuid
from pathlib import Path

import pytest

from whw.config import get_settings
from whw_mcp.server import build_server

pytestmark = pytest.mark.integration


# ----- helpers ---------------------------------------------------------------

async def _call(server, name: str, **args):
    """Call a registered MCP tool by name; unwrap the JSON result.

    FastMCP returns a ToolResult with `.structured_content` (dict) and/or `.content` list.
    We prefer structured_content if present, else parse the first text content item.
    """
    result = await server.call_tool(name, args)
    if hasattr(result, "structured_content") and result.structured_content is not None:
        sc = result.structured_content
        # When a tool returns a list, FastMCP wraps as {"result": [...]} — unwrap.
        if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
            return sc["result"]
        return sc
    if hasattr(result, "content") and result.content:
        import json
        for item in result.content:
            text = getattr(item, "text", None)
            if text:
                try:
                    return json.loads(text)
                except Exception:
                    return text
    return result


# ----- tests ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_register_repo_commit_upsert(arvo_1065_ingested):
    """register_repo_commit should upsert idempotently and return the updated row."""
    server = build_server()
    res = await _call(server, "register_repo_commit",
                      repo_id=arvo_1065_ingested["repo_id"],
                      commit=arvo_1065_ingested["commit"],
                      abs_repo_root=arvo_1065_ingested["abs_repo_root"])
    assert res["repo_id"] == "arvo-1065"
    assert res["commit"] == "vul"
    assert res["abs_repo_root"] == arvo_1065_ingested["abs_repo_root"]


@pytest.mark.asyncio
async def test_find_in_scope_after_mark_in_scope(arvo_1065_ingested, neo4j_driver):
    """mark_in_scope flips in_scope=true on the named QNs; find_in_scope returns them."""
    server = build_server()
    s = get_settings()

    # Reset in_scope flags on a known-stable set so the assertion is deterministic.
    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c}) SET f.in_scope=false",
            rid="arvo-1065", c="vul",
        )

    # Look up file_regexec's QN dynamically (the cbm slug includes the abs path).
    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c, name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn LIMIT 1",
            rid="arvo-1065", c="vul",
        ).single()
    assert row is not None, "expected `file_regexec` Function to exist post-ingest"
    fr_qn = row["qn"]

    marked = await _call(server, "mark_in_scope",
                         qualified_names=[fr_qn], repo_id="arvo-1065", commit="vul")
    assert marked == {"marked": 1}

    in_scope = await _call(server, "find_in_scope", repo_id="arvo-1065", commit="vul")
    assert isinstance(in_scope, list)
    qns = {fn["qualified_name"] for fn in in_scope}
    assert fr_qn in qns
    # Sanity: each row carries the expected shape.
    sample = next(fn for fn in in_scope if fn["qualified_name"] == fr_qn)
    assert sample["name"] == "file_regexec"
    assert sample["file_path"] == "file/src/funcs.c"
    assert sample["line_start"] >= 1 and sample["line_end"] >= sample["line_start"]


@pytest.mark.asyncio
async def test_get_callgraph_slice_returns_seed_and_safe_empty_lists(arvo_1065_ingested, neo4j_driver):
    """get_callgraph_slice on a Function with no Function-level CALLS returns empty
    callee/caller lists but always includes the seed (cbm's C parsing limitation)."""
    server = build_server()
    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c, name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn LIMIT 1",
            rid="arvo-1065", c="vul",
        ).single()
    qn = row["qn"]

    slice_ = await _call(server, "get_callgraph_slice",
                         qualified_name=qn, repo_id="arvo-1065", commit="vul",
                         depth=3, direction="both")
    assert slice_["seed"]["qualified_name"] == qn
    assert slice_["seed"]["file_path"] == "file/src/funcs.c"
    assert slice_["depth"] == 3
    assert isinstance(slice_["callees"], list)
    assert isinstance(slice_["callers"], list)


@pytest.mark.asyncio
async def test_get_snippet_reads_real_source(arvo_1065_ingested, neo4j_driver):
    """get_snippet uses RepoCommit.abs_repo_root to slice the actual file."""
    server = build_server()
    s = get_settings()

    # Ensure RepoCommit is registered (ingest does this but be defensive).
    await _call(server, "register_repo_commit",
                repo_id="arvo-1065", commit="vul",
                abs_repo_root=arvo_1065_ingested["abs_repo_root"])

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c, name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn",
            rid="arvo-1065", c="vul",
        ).single()
    qn = row["qn"]

    snip = await _call(server, "get_snippet",
                       qualified_name=qn, repo_id="arvo-1065", commit="vul")
    assert snip["file_path"] == "file/src/funcs.c"
    assert snip["text"] is not None
    # The function definition contains "file_regexec" and a "regexec(" call.
    assert "file_regexec" in snip["text"]
    assert "regexec(" in snip["text"]


@pytest.mark.asyncio
async def test_record_audit_run_and_add_finding_with_function(
    arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run,
):
    """End-to-end write path: record_audit_run → add_finding → list_findings round-trip."""
    server = build_server()
    s = get_settings()
    run_id = str(uuid.uuid4())
    cleanup_neo4j_run(run_id)

    # Look up file_regexec QN.
    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c, name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn",
            rid="arvo-1065", c="vul",
        ).single()
    qn = row["qn"]

    rec = await _call(server, "record_audit_run",
                      id=run_id, repo_id="arvo-1065", commit="vul",
                      scope_spec="integration-test", depth=3, tools_image="none",
                      mode="live", model="sonnet")
    assert rec["id"] == run_id

    finding = await _call(server, "add_finding",
                          audit_run_id=run_id,
                          vuln_class="UNINIT_MEMORY",
                          severity="high",
                          confidence="certain",
                          summary="pmatch may be uninitialized on glibc regexec=0",
                          rationale="glibc regexec() does not always init pmatch; "
                                    "downstream consumers read uninit memory. "
                                    "Lines 510-513 of file/src/funcs.c.",
                          function_qn=qn,
                          file_path="file/src/funcs.c",
                          line_start=510, line_end=513,
                          source="llm",
                          tool_evidence="msan: use-of-uninitialized-value at funcs.c:510")
    assert finding["id"]
    assert finding["created_at"]

    # list_findings should now show our row.
    listed = await _call(server, "list_findings",
                         repo_id="arvo-1065", commit="vul", limit=10)
    ids = {row["id"] for row in listed}
    assert finding["id"] in ids
    me = next(row for row in listed if row["id"] == finding["id"])
    assert me["vuln_class"] == "UNINIT_MEMORY"
    assert me["severity"] == "high"
    assert me["function_qn"] == qn
    assert me["status"] == "open"


@pytest.mark.asyncio
async def test_add_finding_rejects_bad_vocab(arvo_1065_ingested):
    """Severity and confidence are validated server-side."""
    server = build_server()
    with pytest.raises(Exception) as exc:
        await _call(server, "add_finding",
                    audit_run_id="any", vuln_class="X",
                    severity="extremely-bad-this-is-not-a-vocab-word",
                    confidence="certain",
                    summary="x", rationale="x")
    assert "severity" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_list_findings_filters_eval_commit_ts(
    arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run,
):
    """Findings with commit_observed_at >= eval_commit_ts must be hidden."""
    server = build_server()
    s = get_settings()
    run_id_old = str(uuid.uuid4())
    run_id_new = str(uuid.uuid4())
    cleanup_neo4j_run(run_id_old)
    cleanup_neo4j_run(run_id_new)

    # Pin the "old" run to 2015 and "new" run to 2025 via eval mode (commit_observed_at
    # defaults to AuditRun.eval_commit_ts).
    await _call(server, "record_audit_run",
                id=run_id_old, repo_id="arvo-1065", commit="vul",
                scope_spec="t", depth=1, tools_image="", mode="eval", model="sonnet",
                eval_commit="dummy-old", eval_commit_ts="2015-01-01T00:00:00Z")
    await _call(server, "record_audit_run",
                id=run_id_new, repo_id="arvo-1065", commit="vul",
                scope_spec="t", depth=1, tools_image="", mode="eval", model="sonnet",
                eval_commit="dummy-new", eval_commit_ts="2025-01-01T00:00:00Z")

    with neo4j_driver.session(database=s.neo4j_database) as session:
        qn = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn",
        ).single()["qn"]

    f_old = await _call(server, "add_finding",
                        audit_run_id=run_id_old, vuln_class="UNINIT_MEMORY",
                        severity="high", confidence="certain",
                        summary="older finding", rationale="r", function_qn=qn)
    f_new = await _call(server, "add_finding",
                        audit_run_id=run_id_new, vuln_class="UNINIT_MEMORY",
                        severity="high", confidence="certain",
                        summary="newer finding", rationale="r", function_qn=qn)

    # An eval-mode read anchored at 2020 should see f_old, hide f_new.
    listed = await _call(server, "list_findings",
                         repo_id="arvo-1065", commit="vul", limit=100,
                         eval_commit_ts="2020-01-01T00:00:00Z")
    ids = {r["id"] for r in listed}
    assert f_old["id"] in ids
    assert f_new["id"] not in ids
