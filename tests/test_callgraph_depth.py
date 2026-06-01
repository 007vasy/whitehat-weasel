"""Integration test: prove the `--depth` control mechanically affects both the
call-graph slice the agent sees AND the entrypoint-scope expansion radius.

We can't rely on cbm's C parsing to give us deep Function→Function chains (it
attributes most C calls to :Module, leaving Function-CALLS-Function nearly empty —
see the Phase A discovery note). So this test builds a synthetic linear call chain
A → B → C → D → E directly via Cypher under a throwaway repo_id, exercises both
depth-aware paths, and tears down.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import uuid

import pytest

from whw.config import get_settings
from whw.orchestrator import (
    ScopeSpec, _resolve_entrypoint_scope, fetch_callgraph_text, resolve_scope,
)


pytestmark = pytest.mark.integration


@pytest.fixture
def linear_chain(neo4j_driver):
    """Build A→B→C→D→E with CALLS edges, all :Function, under a throwaway repo_id.

    Yields the repo_id; deletes the whole subgraph on teardown.
    """
    s = get_settings()
    repo_id = f"depth-test-{uuid.uuid4().hex[:8]}"
    commit = "c1"
    names = ["A", "B", "C", "D", "E"]
    qns = [f"{repo_id}.{n}" for n in names]

    with neo4j_driver.session(database=s.neo4j_database) as session:
        # Create nodes.
        for i, name in enumerate(names):
            session.run("""
                MERGE (f:Function {qualified_name:$qn, repo_id:$rid, commit:$c})
                SET f.name=$name, f.file_path='synth.c', f.line_start=$ls, f.line_end=$le,
                    f.in_scope=false, f.language='c'
            """, qn=qns[i], rid=repo_id, c=commit, name=name,
                ls=10 * (i + 1), le=10 * (i + 1) + 5)
        # Create A→B→C→D→E linear CALLS chain.
        for src, dst in zip(qns, qns[1:]):
            session.run("""
                MATCH (a:Function {qualified_name:$a, repo_id:$rid, commit:$c})
                MATCH (b:Function {qualified_name:$b, repo_id:$rid, commit:$c})
                MERGE (a)-[:CALLS]->(b)
            """, a=src, b=dst, rid=repo_id, c=commit)

    yield {"repo_id": repo_id, "commit": commit, "qns": qns, "names": names}

    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run(
            "MATCH (f:Function {repo_id:$rid}) DETACH DELETE f", rid=repo_id,
        )


# ---------- per-agent call-graph slice (fetch_callgraph_text) ---------------

def _max_hop(text: str) -> int:
    """Extract the largest 'hop=N' value from the rendered slice text."""
    hops: list[int] = []
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("hop="):
            try:
                hops.append(int(st.split()[0].split("=")[1]))
            except (IndexError, ValueError):
                pass
    return max(hops) if hops else 0


def _count_hop_lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip().startswith("hop="))


def test_callgraph_slice_grows_monotonically_with_depth(neo4j_driver, linear_chain):
    """fetch_callgraph_text on seed A: depth=1 sees only B, depth=4 sees B,C,D,E."""
    seed_qn = linear_chain["qns"][0]  # A
    repo_id, commit = linear_chain["repo_id"], linear_chain["commit"]

    counts: dict[int, int] = {}
    max_hops: dict[int, int] = {}
    for depth in (1, 2, 3, 4):
        text = fetch_callgraph_text(neo4j_driver, repo_id, commit, seed_qn, depth)
        counts[depth] = _count_hop_lines(text)
        max_hops[depth] = _max_hop(text)

    # Each row appears under both Callers and Callees sections — for our linear chain
    # A has 0 callers and (depth) callees, so total hop-lines == depth.
    # (A has no callers; B/C/D/E each appear once as callees at their respective hops.)
    assert counts[1] == 1, f"depth=1 should expose one callee (B); got {counts[1]}"
    assert counts[2] == 2, f"depth=2 should expose B + C; got {counts[2]}"
    assert counts[3] == 3, f"depth=3 should expose B + C + D; got {counts[3]}"
    assert counts[4] == 4, f"depth=4 should expose B + C + D + E; got {counts[4]}"
    assert max_hops[1] == 1
    assert max_hops[2] == 2
    assert max_hops[3] == 3
    assert max_hops[4] == 4


def test_callgraph_slice_depth_5_caps_at_chain_end(neo4j_driver, linear_chain):
    """A→...→E is depth 4. depth=5 should still only return 4 callees (no more nodes
    exist after E). Proves depth is an UPPER bound, not a "must reach" requirement."""
    seed_qn = linear_chain["qns"][0]
    text = fetch_callgraph_text(neo4j_driver, linear_chain["repo_id"],
                                linear_chain["commit"], seed_qn, depth=5)
    assert _count_hop_lines(text) == 4
    assert _max_hop(text) == 4


def test_callgraph_inbound_section_grows_with_depth(neo4j_driver, linear_chain):
    """Seed E sees A,B,C,D as inbound callers across depth=1..4. Proves the
    direction='both' code paths both honor depth."""
    seed_qn = linear_chain["qns"][-1]  # E
    text_d1 = fetch_callgraph_text(neo4j_driver, linear_chain["repo_id"],
                                   linear_chain["commit"], seed_qn, depth=1)
    text_d4 = fetch_callgraph_text(neo4j_driver, linear_chain["repo_id"],
                                   linear_chain["commit"], seed_qn, depth=4)
    # E has 0 callees (end of chain) and `depth` inbound callers.
    assert _count_hop_lines(text_d1) == 1   # just D as caller
    assert _count_hop_lines(text_d4) == 4   # D, C, B, A


# ---------- entrypoint-scope expansion (--scope-entrypoint --depth N) -------

def test_entrypoint_scope_expansion_includes_callees_up_to_depth(
    neo4j_driver, linear_chain,
):
    """--scope-entrypoint A --depth N → in-scope set = {A, B, ..., up to N hops}.

    Uses resolve_scope (the public API), not the private fallback helper, so this
    exercises the same path the CLI runs.
    """
    s = get_settings()
    repo_id, commit = linear_chain["repo_id"], linear_chain["commit"]

    for depth, expected_count in [(1, 2), (2, 3), (3, 4), (4, 5)]:
        # Reset in_scope between iterations to keep the test deterministic.
        with neo4j_driver.session(database=s.neo4j_database) as session:
            session.run(
                "MATCH (f:Function {repo_id:$rid, commit:$c}) SET f.in_scope=false",
                rid=repo_id, c=commit,
            )
        fns = resolve_scope(neo4j_driver, repo_id, commit,
                            ScopeSpec(entrypoint="A", entrypoint_depth=depth))
        names = sorted(f["name"] for f in fns)
        assert len(fns) == expected_count, (
            f"depth={depth}: expected {expected_count} (seed + {depth} callees), got "
            f"{len(fns)}: {names}"
        )
        # First {depth+1} letters of the chain must all be present.
        expected_names = sorted(linear_chain["names"][: depth + 1])
        assert names == expected_names, f"depth={depth} names={names} vs {expected_names}"


def test_entrypoint_scope_caps_at_chain_end_when_depth_exceeds_reachable(
    neo4j_driver, linear_chain,
):
    """--scope-entrypoint A --depth 5 on a 4-edge chain → returns all 5 nodes (not 6)."""
    fns = resolve_scope(neo4j_driver, linear_chain["repo_id"], linear_chain["commit"],
                        ScopeSpec(entrypoint="A", entrypoint_depth=5))
    assert sorted(f["name"] for f in fns) == ["A", "B", "C", "D", "E"]


def test_entrypoint_scope_depth_clamped_to_1_to_5_range(neo4j_driver, linear_chain):
    """`_resolve_entrypoint_scope` enforces depth ∈ [1, 5] — out-of-range values are clamped."""
    fns_lo = resolve_scope(neo4j_driver, linear_chain["repo_id"], linear_chain["commit"],
                           ScopeSpec(entrypoint="A", entrypoint_depth=0))
    # depth=0 clamped to 1 → seed + 1 hop = {A, B}.
    assert sorted(f["name"] for f in fns_lo) == ["A", "B"]

    fns_hi = resolve_scope(neo4j_driver, linear_chain["repo_id"], linear_chain["commit"],
                           ScopeSpec(entrypoint="A", entrypoint_depth=99))
    # depth=99 clamped to 5; chain is depth 4, so we get all 5 nodes.
    assert sorted(f["name"] for f in fns_hi) == ["A", "B", "C", "D", "E"]
