"""Integration test: prove `find_upstream_entrypoints` walks CALLS backward and
correctly identifies untrusted entries by three signals (entrypoint_kind set,
trust_level='UNTRUSTED', or name-pattern match).

The fixture builds a synthetic CALLS chain similar to test_callgraph_depth.py:

    httpHandler  ─┐
                  │
    Webhook ──── B ── C ── D ── seed     (CALLS edges, left calls right)
                  │
    markedFn  ───┘   (no entry-shape name, but entrypoint_kind set)
                  │
    untrustedFn  ─┘  (trust_level='UNTRUSTED', no entry-shape name)

We test:
  1. From `seed` with max_depth=4, all four upstream entries appear.
  2. The TRUST PATH rendering in `fetch_callgraph_text` also surfaces them.
  3. `match_source` is reported correctly for each signal type.
  4. With max_depth=2, only B is in range — entries are 3+ hops up, so empty.
  5. A function with neither flag nor entry-name (an ordinary intermediate) is NOT
     returned even though it's on the CALLS path.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import uuid

import pytest

from whw.config import get_settings
from whw.orchestrator import fetch_callgraph_text
from whw_mcp.db import render_cypher, run_query


pytestmark = pytest.mark.integration


@pytest.fixture
def trust_path_chain(neo4j_driver):
    """Synthetic graph:

        httpHandler ──┐
        Webhook ──────┼─→ B ─→ C ─→ D ─→ seed
        markedFn ─────┤
        untrustedFn ──┘
        plainCaller ──→ B   (no entry signal — should never appear in results)

    All under a throwaway repo_id; teardown deletes the subgraph.
    """
    s = get_settings()
    repo_id = f"trust-path-test-{uuid.uuid4().hex[:8]}"
    commit = "c1"

    # (name, entrypoint_kind, trust_level) — the four entry-shaped + one plain.
    entries = [
        ("httpHandler",  None,            None),            # name-pattern match
        ("Webhook",      None,            None),            # name-pattern match
        ("markedFn",     "background_job", None),           # entrypoint_kind match
        ("untrustedFn",  None,            "UNTRUSTED"),     # trust_level match
        ("plainCaller",  None,            None),            # NOTHING — should not appear
    ]
    chain = ["B", "C", "D", "seed"]

    all_names = [e[0] for e in entries] + chain
    qns = {n: f"{repo_id}.{n}" for n in all_names}

    with neo4j_driver.session(database=s.neo4j_database) as session:
        for name, kind, trust in entries:
            session.run("""
                MERGE (f:Function {qualified_name:$qn, repo_id:$rid, commit:$c})
                SET f.name=$name, f.file_path='synth.ts', f.line_start=10, f.line_end=20,
                    f.in_scope=false, f.language='typescript',
                    f.entrypoint_kind=$kind, f.trust_level=$trust
            """, qn=qns[name], rid=repo_id, c=commit, name=name, kind=kind, trust=trust)
        for i, name in enumerate(chain):
            session.run("""
                MERGE (f:Function {qualified_name:$qn, repo_id:$rid, commit:$c})
                SET f.name=$name, f.file_path='synth.ts', f.line_start=$ls, f.line_end=$le,
                    f.in_scope=false, f.language='typescript'
            """, qn=qns[name], rid=repo_id, c=commit, name=name,
                ls=100 + 10 * i, le=100 + 10 * i + 5)

        # Wire entries → B (1 hop into chain), then chain B→C→D→seed.
        for entry_name, _, _ in entries:
            session.run("""
                MATCH (a:Function {qualified_name:$a, repo_id:$rid, commit:$c})
                MATCH (b:Function {qualified_name:$b, repo_id:$rid, commit:$c})
                MERGE (a)-[:CALLS]->(b)
            """, a=qns[entry_name], b=qns["B"], rid=repo_id, c=commit)
        for src, dst in zip(chain, chain[1:]):
            session.run("""
                MATCH (a:Function {qualified_name:$a, repo_id:$rid, commit:$c})
                MATCH (b:Function {qualified_name:$b, repo_id:$rid, commit:$c})
                MERGE (a)-[:CALLS]->(b)
            """, a=qns[src], b=qns[dst], rid=repo_id, c=commit)

    yield {"repo_id": repo_id, "commit": commit, "qns": qns}

    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run("MATCH (f:Function {repo_id:$rid}) DETACH DELETE f", rid=repo_id)


# ---------- Cypher contract -------------------------------------------------

def test_find_upstream_entrypoints_returns_all_four_signals(neo4j_driver, trust_path_chain):
    """seed is 4 hops downstream of each entry. With max_depth=4, all four signal
    types fire; the plain non-entry caller is excluded."""
    seed_qn = trust_path_chain["qns"]["seed"]
    rows = run_query(
        render_cypher("find_upstream_entrypoints", DEPTH=4),
        {"qn": seed_qn,
         "repo_id": trust_path_chain["repo_id"],
         "commit": trust_path_chain["commit"]},
    )
    by_name = {r["entry_name"]: dict(r) for r in rows}
    assert "httpHandler" in by_name, "name-pattern match (handler) missing"
    assert "Webhook" in by_name, "name-pattern match (webhook) missing"
    assert "markedFn" in by_name, "entrypoint_kind match missing"
    assert "untrustedFn" in by_name, "trust_level match missing"
    assert "plainCaller" not in by_name, "plain caller should not be flagged as entry"

    # Each entry is 4 hops to seed (entry → B → C → D → seed).
    for name in ("httpHandler", "Webhook", "markedFn", "untrustedFn"):
        assert by_name[name]["hops"] == 4, f"{name} hops: {by_name[name]['hops']}"

    assert by_name["httpHandler"]["match_source"] == "name_pattern"
    assert by_name["Webhook"]["match_source"] == "name_pattern"
    assert by_name["markedFn"]["match_source"] == "entrypoint_kind"
    assert by_name["untrustedFn"]["match_source"] == "trust_level"

    # intermediate_qns: nodes between entry and seed, in order. For all entries
    # the chain is entry → B → C → D → seed; intermediates are [B, C, D].
    expected_qns = [trust_path_chain["qns"][n] for n in ("B", "C", "D")]
    for name in ("httpHandler", "Webhook", "markedFn", "untrustedFn"):
        assert by_name[name]["intermediate_qns"] == expected_qns, (
            f"{name} intermediate_qns: {by_name[name]['intermediate_qns']}"
        )


def test_find_upstream_entrypoints_depth_limit_blocks_far_entries(neo4j_driver, trust_path_chain):
    """With max_depth=2, no entry is reachable (all are 4 hops). Empty result is
    a meaningful negative signal."""
    seed_qn = trust_path_chain["qns"]["seed"]
    rows = run_query(
        render_cypher("find_upstream_entrypoints", DEPTH=2),
        {"qn": seed_qn,
         "repo_id": trust_path_chain["repo_id"],
         "commit": trust_path_chain["commit"]},
    )
    assert rows == [], f"expected empty result at depth=2, got {len(rows)} rows"


def test_find_upstream_entrypoints_seed_excluded_from_self(neo4j_driver, trust_path_chain):
    """A handler-named function asking about itself should not be reported as its
    own upstream entry (self-loops disallowed via entry.qn <> seed.qn predicate)."""
    handler_qn = trust_path_chain["qns"]["httpHandler"]
    rows = run_query(
        render_cypher("find_upstream_entrypoints", DEPTH=4),
        {"qn": handler_qn,
         "repo_id": trust_path_chain["repo_id"],
         "commit": trust_path_chain["commit"]},
    )
    by_name = {r["entry_name"] for r in rows}
    assert "httpHandler" not in by_name, "self should not be returned as its own entry"


# ---------- Rendered TRUST PATH block ---------------------------------------

def test_fetch_callgraph_text_renders_trust_path_block(neo4j_driver, trust_path_chain):
    """fetch_callgraph_text on `seed` produces a TRUST PATH section that names every
    untrusted entry. This is the pre-fetched view the audit sub-agent sees on stdin."""
    seed_qn = trust_path_chain["qns"]["seed"]
    text = fetch_callgraph_text(
        neo4j_driver, trust_path_chain["repo_id"], trust_path_chain["commit"],
        seed_qn, depth=4,
    )
    # Split out the TRUST PATH section so we can scope assertions to it (plainCaller
    # legitimately appears in CALLERS because it does call B — it just must not appear
    # as a trust-path entry).
    trust_section = text.split("=== TRUST PATH", 1)[1].split("=== ", 1)[0]
    assert "=== TRUST PATH" in text, "TRUST PATH section header missing"
    for name in ("httpHandler", "Webhook", "markedFn", "untrustedFn"):
        assert name in trust_section, f"{name} not surfaced in TRUST PATH section"
    assert "plainCaller" not in trust_section, "plainCaller leaked into TRUST PATH"


def test_fetch_callgraph_text_empty_trust_path_when_no_entries(neo4j_driver, trust_path_chain):
    """Picking a node with no upstream entry-shaped caller (B itself, audited in
    isolation from a different seed direction) should produce an explicit empty-state
    message in TRUST PATH rather than no section at all."""
    # B has 5 upstream callers, but if we point at the one entry that does NOT have
    # an upstream chain — the entry itself with depth=1 looking for its own entry —
    # we get the empty-state. Use markedFn as seed: no caller exists upstream of it.
    marked_qn = trust_path_chain["qns"]["markedFn"]
    text = fetch_callgraph_text(
        neo4j_driver, trust_path_chain["repo_id"], trust_path_chain["commit"],
        marked_qn, depth=5,
    )
    assert "=== TRUST PATH" in text
    assert "no upstream entry reached" in text, (
        "empty-state message missing; rendered text:\n" + text
    )


# ---------- Cypher render template safety -----------------------------------

def test_find_upstream_entrypoints_cypher_renders_with_int_depth():
    """render_cypher substitutes __DEPTH__ with an int. Non-int inputs raise."""
    rendered = render_cypher("find_upstream_entrypoints", DEPTH=3)
    assert "__DEPTH__" not in rendered
    assert "CALLS*1..3" in rendered

    with pytest.raises(TypeError):
        render_cypher("find_upstream_entrypoints", DEPTH=True)
    with pytest.raises(TypeError):
        render_cypher("find_upstream_entrypoints", DEPTH="3; DROP TABLE")
