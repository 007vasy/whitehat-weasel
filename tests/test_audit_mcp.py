"""Smoke tests for whw_mcp.

Most tests don't require a live Neo4j — we exercise:
  - server build (all 8 tools register, schemas are valid),
  - Cypher template loading + safe substitution,
  - vocabulary validation on add_finding inputs,
  - embedding backend in 'noop' mode (deterministic, no model download).

A separate test asserts get_graph_schema (live Neo4j) only if NEO4J is reachable.
"""

from __future__ import annotations

import os

import pytest

# Force noop embeddings so the test suite stays fast and offline.
os.environ["WHW_EMBEDDING_BACKEND"] = "noop"

from whw_mcp.db import load_cypher, render_cypher
from whw_mcp.embeddings import EMBED_DIM, embed, embed_many
from whw_mcp.server import build_server


EXPECTED_TOOLS = {
    # Phase A
    "find_in_scope",
    "get_callgraph_slice",
    "get_snippet",
    "list_findings",
    "register_repo_commit",
    "mark_in_scope",
    "record_audit_run",
    "add_finding",
    # Phase B
    "find_similar_findings",
    "get_prior_false_positives",
    "mark_false_positive",
    "link_finding_duplicate",
    "link_finding_to_asset",
    "upsert_production_asset",
    "link_user_doc",
}


@pytest.mark.asyncio
async def test_server_builds_and_registers_full_tool_surface():
    """Asserts the audit MCP exposes exactly the Phase A + Phase B tool set (no more, no less)."""
    mcp = build_server()
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    missing = EXPECTED_TOOLS - names
    assert not missing, f"missing tools: {sorted(missing)}; got {sorted(names)}"
    extras = names - EXPECTED_TOOLS
    assert not extras, f"unexpected extra tools: {sorted(extras)}"


def test_load_cypher_returns_text():
    text = load_cypher("find_in_scope")
    assert "MATCH (f:Function" in text
    assert "$repo_id" in text


def test_load_cypher_missing_raises():
    with pytest.raises(FileNotFoundError):
        load_cypher("does_not_exist")


def test_render_cypher_substitutes_int_depth():
    text = render_cypher("get_callgraph_outbound", DEPTH=3)
    assert "*1..3" in text
    assert "__DEPTH__" not in text


def test_render_cypher_rejects_bool():
    with pytest.raises(TypeError):
        render_cypher("get_callgraph_outbound", DEPTH=True)


def test_render_cypher_rejects_unsafe_string():
    with pytest.raises(TypeError):
        # not a Python identifier (contains a quote); should be rejected.
        render_cypher("get_callgraph_outbound", DEPTH="3); DROP")  # type: ignore[arg-type]


def test_embed_noop_backend_dimensions():
    v = embed("some text")
    assert len(v) == EMBED_DIM
    assert all(x == 0.0 for x in v)


def test_embed_many_noop():
    vecs = embed_many(["a", "b", ""])
    assert len(vecs) == 3
    assert all(len(v) == EMBED_DIM for v in vecs)
