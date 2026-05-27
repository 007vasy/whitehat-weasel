"""Integration tests for the 7 new Phase B audit-MCP tools (live Neo4j).

Tests use WHW_EMBEDDING_BACKEND=noop so zero-vector queries short-circuit cleanly
without requiring the Nomic model to be downloaded. The semantic behavior (cosine
above threshold finds the right neighbor) is exercised separately in the opt-in
Nomic test (B1.2).
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import uuid

import pytest

from whw.config import get_settings
from whw_mcp.server import build_server
from whw_mcp.tools_write import _deterministic_asset_id

from .test_integration_audit_mcp import _call


pytestmark = pytest.mark.integration


# ---------- helpers -----------------------------------------------------------

async def _seed_finding(server, *, audit_run_id, function_qn, summary, severity="med") -> str:
    """Create a Finding and return its id."""
    res = await _call(server, "add_finding",
                      audit_run_id=audit_run_id,
                      vuln_class="UNINIT_MEMORY",
                      severity=severity, confidence="certain",
                      summary=summary, rationale="r",
                      function_qn=function_qn)
    return res["id"]


@pytest.fixture
async def seeded_run(arvo_1065_ingested, neo4j_driver, cleanup_neo4j_run):
    """Create a fresh AuditRun + one in-scope Function + return helpers."""
    server = build_server()
    s = get_settings()
    run_id = str(uuid.uuid4())
    cleanup_neo4j_run(run_id)

    # Resolve file_regexec QN.
    with neo4j_driver.session(database=s.neo4j_database) as session:
        qn = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', name:'file_regexec'}) "
            "RETURN f.qualified_name AS qn"
        ).single()["qn"]

    await _call(server, "record_audit_run",
                id=run_id, repo_id="arvo-1065", commit="vul",
                scope_spec="phase-b-test", depth=1, tools_image="", mode="live",
                model="sonnet")

    return {"server": server, "run_id": run_id, "fn_qn": qn,
            "repo_id": "arvo-1065", "commit": "vul"}


# ---------- find_similar_findings / get_prior_false_positives -----------------

@pytest.mark.asyncio
async def test_find_similar_findings_noop_returns_empty(seeded_run):
    """With WHW_EMBEDDING_BACKEND=noop, summary embeddings are zero vectors and the
    tool short-circuits to []. This proves the safety guard without requiring Nomic."""
    server = seeded_run["server"]
    res = await _call(server, "find_similar_findings",
                      summary_text="some hypothesis", repo_id="arvo-1065", commit="vul")
    assert res == []


@pytest.mark.asyncio
async def test_find_similar_findings_empty_input_returns_empty(seeded_run):
    server = seeded_run["server"]
    res = await _call(server, "find_similar_findings", summary_text="")
    assert res == []


@pytest.mark.asyncio
async def test_get_prior_false_positives_noop_returns_empty(seeded_run):
    server = seeded_run["server"]
    res = await _call(server, "get_prior_false_positives",
                      summary_text="some hypothesis", min_cosine=0.5)
    assert res == []


# ---------- mark_false_positive ----------------------------------------------

@pytest.mark.asyncio
async def test_mark_false_positive_creates_fp_and_flips_status(seeded_run, neo4j_driver):
    server = seeded_run["server"]
    s = get_settings()

    finding_id = await _seed_finding(server,
                                     audit_run_id=seeded_run["run_id"],
                                     function_qn=seeded_run["fn_qn"],
                                     summary="suspicious memcpy without bounds check")

    fp = await _call(server, "mark_false_positive",
                     finding_id=finding_id, reason="overstated — guarded by caller",
                     marked_by="test")
    assert fp["finding_id"] == finding_id
    assert fp["finding_status"] == "fp"
    assert fp["id"]  # the FalsePositive uuid

    with neo4j_driver.session(database=s.neo4j_database) as session:
        rec = session.run(
            "MATCH (f:Finding {id:$fid})<-[:DERIVED_FROM]-(fp:FalsePositive) "
            "RETURN f.status AS status, fp.reason AS reason, fp.marked_by AS marked_by, "
            "       fp.repo_id AS repo_id, fp.commit AS commit",
            fid=finding_id,
        ).single()
    assert rec is not None
    assert rec["status"] == "fp"
    assert rec["reason"] == "overstated — guarded by caller"
    assert rec["marked_by"] == "test"
    assert rec["repo_id"] == "arvo-1065"
    assert rec["commit"] == "vul"


@pytest.mark.asyncio
async def test_mark_false_positive_missing_finding_raises(seeded_run):
    server = seeded_run["server"]
    with pytest.raises(Exception):
        await _call(server, "mark_false_positive",
                    finding_id="does-not-exist", reason="x")


# ---------- link_finding_duplicate -------------------------------------------

@pytest.mark.asyncio
async def test_link_finding_duplicate_creates_edges_and_flips_status(seeded_run, neo4j_driver):
    server = seeded_run["server"]
    s = get_settings()

    canon_id = await _seed_finding(server,
                                   audit_run_id=seeded_run["run_id"],
                                   function_qn=seeded_run["fn_qn"],
                                   summary="canonical: uninit pmatch")
    dup_id = await _seed_finding(server,
                                 audit_run_id=seeded_run["run_id"],
                                 function_qn=seeded_run["fn_qn"],
                                 summary="duplicate phrasing of pmatch issue")

    res = await _call(server, "link_finding_duplicate",
                      duplicate_id=dup_id, canonical_id=canon_id, cosine=0.95)
    assert res["duplicate_id"] == dup_id
    assert res["canonical_id"] == canon_id
    assert abs(res["cosine"] - 0.95) < 1e-6

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (a:Finding {id:$a})-[:DUPLICATE_OF]->(b:Finding {id:$b}) "
            "MATCH (a)-[r:SIMILAR_TO]->(b) "
            "RETURN a.status AS status, a.dedup_of AS dedup_of, r.cosine AS cosine",
            a=dup_id, b=canon_id,
        ).single()
    assert row is not None
    assert row["status"] == "duplicate"
    assert row["dedup_of"] == canon_id
    assert abs(row["cosine"] - 0.95) < 1e-6


@pytest.mark.asyncio
async def test_link_finding_duplicate_rejects_self_link(seeded_run):
    server = seeded_run["server"]
    fid = await _seed_finding(server, audit_run_id=seeded_run["run_id"],
                              function_qn=seeded_run["fn_qn"], summary="s")
    with pytest.raises(Exception):
        await _call(server, "link_finding_duplicate",
                    duplicate_id=fid, canonical_id=fid, cosine=1.0)


# ---------- upsert_production_asset + link_finding_to_asset + link_user_doc --

@pytest.mark.asyncio
async def test_upsert_production_asset_is_idempotent(arvo_1065_ingested, neo4j_driver):
    """Two calls with the same (name, kind) hit the same node id."""
    server = build_server()
    s = get_settings()
    asset_name = f"test-db-{uuid.uuid4().hex[:8]}"
    kind = "db"
    expected_id = _deterministic_asset_id(asset_name, kind)

    a = await _call(server, "upsert_production_asset",
                    name=asset_name, kind=kind,
                    description="Primary user DB", criticality="high")
    b = await _call(server, "upsert_production_asset",
                    name=asset_name, kind=kind,
                    description="Primary user DB (updated)", criticality="crit")
    assert a["id"] == b["id"] == expected_id

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (a:ProductionAsset {id:$id}) RETURN a.criticality AS c, a.description AS d",
            id=expected_id,
        ).single()
        # Cleanup at end of this test (no fixture for it).
        session.run("MATCH (a:ProductionAsset {id:$id}) DETACH DELETE a", id=expected_id)
    assert row["c"] == "crit"
    assert row["d"] == "Primary user DB (updated)"


@pytest.mark.asyncio
async def test_upsert_production_asset_rejects_bad_kind(arvo_1065_ingested):
    server = build_server()
    with pytest.raises(Exception) as exc:
        await _call(server, "upsert_production_asset",
                    name="bad", kind="not-a-real-kind",
                    description="x", criticality="med")
    assert "kind" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_link_finding_to_asset_creates_edge(seeded_run, neo4j_driver):
    server = seeded_run["server"]
    s = get_settings()

    asset = await _call(server, "upsert_production_asset",
                        name=f"q-{uuid.uuid4().hex[:8]}", kind="queue",
                        description="message bus", criticality="med")
    finding_id = await _seed_finding(server,
                                     audit_run_id=seeded_run["run_id"],
                                     function_qn=seeded_run["fn_qn"],
                                     summary="unhandled error path leaks message")

    res = await _call(server, "link_finding_to_asset",
                      finding_id=finding_id, asset_id=asset["id"])
    assert res["finding_id"] == finding_id
    assert res["asset_id"] == asset["id"]

    with neo4j_driver.session(database=s.neo4j_database) as session:
        n_edges = session.run(
            "MATCH (:Finding {id:$f})-[r:AFFECTS_ASSET]->(:ProductionAsset {id:$a}) "
            "RETURN count(r) AS n",
            f=finding_id, a=asset["id"],
        ).single()["n"]
        session.run("MATCH (a:ProductionAsset {id:$id}) DETACH DELETE a", id=asset["id"])
    assert n_edges == 1


@pytest.mark.asyncio
async def test_link_user_doc_with_mentions(seeded_run, neo4j_driver):
    server = seeded_run["server"]
    s = get_settings()

    a1 = await _call(server, "upsert_production_asset",
                     name=f"db-{uuid.uuid4().hex[:6]}", kind="db",
                     description="primary db", criticality="high")
    a2 = await _call(server, "upsert_production_asset",
                     name=f"sec-{uuid.uuid4().hex[:6]}", kind="secret",
                     description="vault path /secret/api/key", criticality="crit")

    res = await _call(server, "link_user_doc",
                      path="prod-runbook.md",
                      audit_run_id=seeded_run["run_id"],
                      sha256="abc123",
                      content_text="The primary DB is reached via the vault secret.",
                      mentions=[a1["id"], a2["id"]])
    assert res["path"] == "prod-runbook.md"
    assert res["mention_count"] == 2

    with neo4j_driver.session(database=s.neo4j_database) as session:
        rows = list(session.run(
            "MATCH (d:UserContextDoc {path:'prod-runbook.md', audit_run_id:$rid})"
            "-[:MENTIONS]->(a:ProductionAsset) RETURN a.id AS id",
            rid=seeded_run["run_id"],
        ))
        # Cleanup
        session.run(
            "MATCH (d:UserContextDoc {audit_run_id:$rid}) DETACH DELETE d",
            rid=seeded_run["run_id"],
        )
        for aid in (a1["id"], a2["id"]):
            session.run("MATCH (a:ProductionAsset {id:$id}) DETACH DELETE a", id=aid)
    assert {r["id"] for r in rows} == {a1["id"], a2["id"]}


@pytest.mark.asyncio
async def test_link_user_doc_no_mentions_still_creates_doc(seeded_run, neo4j_driver):
    server = seeded_run["server"]
    s = get_settings()
    res = await _call(server, "link_user_doc",
                      path="empty-doc.md",
                      audit_run_id=seeded_run["run_id"],
                      sha256="zzz",
                      content_text="just text, no mentions")
    assert res["mention_count"] == 0
    with neo4j_driver.session(database=s.neo4j_database) as session:
        exists = session.run(
            "MATCH (d:UserContextDoc {path:'empty-doc.md', audit_run_id:$rid}) "
            "RETURN d.path AS p",
            rid=seeded_run["run_id"],
        ).single()
        session.run(
            "MATCH (d:UserContextDoc {audit_run_id:$rid}) DETACH DELETE d",
            rid=seeded_run["run_id"],
        )
    assert exists and exists["p"] == "empty-doc.md"


# ---------- helper sanity ----------------------------------------------------

def test_deterministic_asset_id_stable():
    a = _deterministic_asset_id("primary-db", "db")
    b = _deterministic_asset_id("primary-db", "db")
    c = _deterministic_asset_id("primary-db", "cache")
    assert a == b
    assert a != c
    assert a.startswith("asset-")
