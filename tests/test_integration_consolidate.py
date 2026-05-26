"""Integration tests for whw.consolidate (Phase B passes 1, 3, 4-link).

Strategy: inject Findings + FalsePositives + ProductionAssets directly via Cypher
with deterministic synthetic embeddings (so we don't need Nomic to be installed and
the cosines are known a priori). This isolates the consolidation logic from the
embedding backend (which has its own coverage in test_embeddings_nomic.py).
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import math
import uuid
from typing import Iterable

import numpy as np
import pytest

from whw.config import get_settings
from whw.consolidate import consolidate


pytestmark = pytest.mark.integration


# ---------- synthetic embedding helpers --------------------------------------

EMBED_DIM = 768


def _unit_vec(seed: int) -> list[float]:
    """Deterministic unit-norm vector from a seed."""
    rng = np.random.default_rng(seed)
    v = rng.standard_normal(EMBED_DIM)
    v /= np.linalg.norm(v)
    return v.astype(np.float32).tolist()


def _near_unit_vec(seed: int, base: list[float], target_cosine: float) -> list[float]:
    """Return a unit vector whose cosine with `base` is ~target_cosine.

    Uses Gram-Schmidt: pick a random orthogonal direction, then build
       v = target_cosine * base + sqrt(1 - target_cosine^2) * orth.
    Cosine of v with base = target_cosine (since both are unit-norm and orth ⊥ base).
    """
    rng = np.random.default_rng(seed)
    base_np = np.asarray(base, dtype=np.float32)
    noise = rng.standard_normal(EMBED_DIM).astype(np.float32)
    orth = noise - noise.dot(base_np) * base_np
    orth /= np.linalg.norm(orth)
    v = target_cosine * base_np + math.sqrt(1.0 - target_cosine * target_cosine) * orth
    v /= np.linalg.norm(v)  # numerical clean-up
    return v.tolist()


# ---------- direct-Cypher injection helpers (bypass MCP) ---------------------

def _ensure_audit_run(driver, run_id: str, eval_ts: str | None = None) -> None:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (run:AuditRun {id:$rid})
            SET run.repo_id='consolidate-test', run.commit='c1', run.model='test',
                run.mode = CASE WHEN $eval_ts IS NULL THEN 'live' ELSE 'eval' END,
                run.eval_commit_ts = CASE WHEN $eval_ts IS NULL THEN NULL ELSE datetime($eval_ts) END,
                run.status='running', run.started_at=datetime()
        """, rid=run_id, eval_ts=eval_ts)


def _inject_finding(driver, run_id: str, embedding: list[float], *,
                    summary: str = "synthetic finding", status: str = "open",
                    observed_at: str | None = None) -> str:
    s = get_settings()
    fid = str(uuid.uuid4())
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MATCH (run:AuditRun {id:$rid})
            CREATE (n:Finding {
                id: $id, vuln_class: 'TEST', severity: 'med', confidence: 'inferred',
                summary: $summary, rationale: 'r', source: 'test',
                tool_evidence: '', created_at: datetime(),
                commit_observed_at: CASE WHEN $obs IS NULL THEN datetime() ELSE datetime($obs) END,
                audit_run_id: $rid, status: $status, model_used: 'test',
                repo_id: run.repo_id, commit: run.commit,
                embedding: $emb
            })
            MERGE (run)-[:FOUND]->(n)
        """, rid=run_id, id=fid, summary=summary, status=status, obs=observed_at, emb=embedding)
    return fid


def _inject_false_positive(driver, embedding: list[float], *,
                           original_finding_id: str = "",
                           reason: str = "synthetic FP",
                           observed_at: str | None = None) -> str:
    s = get_settings()
    fp_id = str(uuid.uuid4())
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            CREATE (fp:FalsePositive {
                id: $id, finding_id: $fid, reason: $reason, marked_by: 'test',
                embedding: $emb, created_at: datetime(),
                commit_observed_at: CASE WHEN $obs IS NULL THEN datetime() ELSE datetime($obs) END,
                repo_id: 'consolidate-test', commit: 'c1'
            })
        """, id=fp_id, fid=original_finding_id, reason=reason, emb=embedding, obs=observed_at)
    return fp_id


def _inject_asset(driver, embedding: list[float], *,
                  name: str | None = None, kind: str = "db") -> str:
    s = get_settings()
    aid = f"asset-test-{uuid.uuid4().hex[:12]}"
    with driver.session(database=s.neo4j_database) as session:
        session.run("""
            MERGE (a:ProductionAsset {id:$id})
            ON CREATE SET a.created_at = datetime()
            SET a.name = $name, a.kind = $kind, a.description = 'synthetic',
                a.criticality = 'med', a.embedding = $emb, a.updated_at = datetime()
        """, id=aid, name=name or aid, kind=kind, emb=embedding)
    return aid


# ---------- fixtures ---------------------------------------------------------

@pytest.fixture
def fresh_run(neo4j_driver, cleanup_neo4j_run):
    """Yield a (run_id, cleanup-helper) for one consolidation test. Cleans up Findings,
    FalsePositives, and ProductionAssets created by injection helpers."""
    run_id = str(uuid.uuid4())
    _ensure_audit_run(neo4j_driver, run_id)
    cleanup_neo4j_run(run_id)
    created_fps: list[str] = []
    created_assets: list[str] = []

    def _track_fp(fp_id: str) -> str:
        created_fps.append(fp_id)
        return fp_id

    def _track_asset(asset_id: str) -> str:
        created_assets.append(asset_id)
        return asset_id

    yield {"run_id": run_id, "track_fp": _track_fp, "track_asset": _track_asset}

    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        for fid in created_fps:
            session.run("MATCH (fp:FalsePositive {id:$id}) DETACH DELETE fp", id=fid)
        for aid in created_assets:
            session.run("MATCH (a:ProductionAsset {id:$id}) DETACH DELETE a", id=aid)


# ---------- pass 1: FP suppression ------------------------------------------

def test_fp_suppress_marks_status_suppressed(neo4j_driver, fresh_run):
    """A Finding whose embedding cosine-matches a prior FP (>= 0.88) flips to 'suppressed'."""
    s = get_settings()
    base = _unit_vec(1)
    fp_id = fresh_run["track_fp"](_inject_false_positive(neo4j_driver, base, reason="prior FP"))
    finding_id = _inject_finding(neo4j_driver, fresh_run["run_id"], base, summary="dup of fp")

    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_dedup=True, skip_asset_link=True)
    assert result.n_suppressed == 1

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (fp:FalsePositive {id:$fp})-[r:SUPPRESSES]->(n:Finding {id:$fid}) "
            "RETURN n.status AS status, r.cosine AS cosine",
            fp=fp_id, fid=finding_id,
        ).single()
    assert row is not None
    assert row["status"] == "suppressed"
    assert row["cosine"] >= 0.88


def test_fp_suppress_below_threshold_keeps_open(neo4j_driver, fresh_run):
    """A Finding whose best FP cosine is < 0.88 stays open."""
    s = get_settings()
    fp_vec = _unit_vec(2)
    finding_vec = _near_unit_vec(seed=3, base=fp_vec, target_cosine=0.5)
    fresh_run["track_fp"](_inject_false_positive(neo4j_driver, fp_vec))
    finding_id = _inject_finding(neo4j_driver, fresh_run["run_id"], finding_vec)

    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_dedup=True, skip_asset_link=True)
    assert result.n_suppressed == 0

    with neo4j_driver.session(database=s.neo4j_database) as session:
        st = session.run("MATCH (n:Finding {id:$id}) RETURN n.status AS s",
                         id=finding_id).single()["s"]
    assert st == "open"


def test_fp_suppress_skip_flag_is_respected(neo4j_driver, fresh_run):
    base = _unit_vec(4)
    fresh_run["track_fp"](_inject_false_positive(neo4j_driver, base))
    finding_id = _inject_finding(neo4j_driver, fresh_run["run_id"], base)

    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_fp_suppress=True, skip_dedup=True, skip_asset_link=True)
    assert result.n_suppressed == 0
    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        st = session.run("MATCH (n:Finding {id:$id}) RETURN n.status AS s",
                         id=finding_id).single()["s"]
    assert st == "open"


# ---------- pass 3: dedup ----------------------------------------------------

def test_dedup_marks_newer_as_duplicate_of_older(neo4j_driver, fresh_run):
    """Two near-identical Findings → the OLDER stays canonical, the newer becomes duplicate."""
    s = get_settings()
    base = _unit_vec(5)
    canonical_id = _inject_finding(neo4j_driver, fresh_run["run_id"], base,
                                   summary="first wording",
                                   observed_at="2024-01-01T00:00:00Z")
    duplicate_id = _inject_finding(neo4j_driver, fresh_run["run_id"], base,
                                   summary="second wording",
                                   observed_at="2024-06-01T00:00:00Z")

    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_fp_suppress=True, skip_asset_link=True)
    assert result.n_duplicates == 1

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run("""
            MATCH (a:Finding {id:$dup})-[:DUPLICATE_OF]->(b:Finding {id:$can})
            MATCH (a)-[r:SIMILAR_TO]->(b)
            RETURN a.status AS dup_status, a.dedup_of AS dedup_of, r.cosine AS cosine,
                   b.status AS can_status
        """, dup=duplicate_id, can=canonical_id).single()
    assert row is not None
    assert row["dup_status"] == "duplicate"
    assert row["dedup_of"] == canonical_id
    assert row["can_status"] == "open"
    assert row["cosine"] >= 0.92


def test_dedup_below_threshold_keeps_both_open(neo4j_driver, fresh_run):
    s = get_settings()
    base = _unit_vec(6)
    far = _near_unit_vec(seed=7, base=base, target_cosine=0.5)
    a_id = _inject_finding(neo4j_driver, fresh_run["run_id"], base)
    b_id = _inject_finding(neo4j_driver, fresh_run["run_id"], far)
    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_fp_suppress=True, skip_asset_link=True)
    assert result.n_duplicates == 0
    with neo4j_driver.session(database=s.neo4j_database) as session:
        statuses = sorted([
            session.run("MATCH (n:Finding {id:$id}) RETURN n.status AS s",
                        id=fid).single()["s"]
            for fid in (a_id, b_id)
        ])
    assert statuses == ["open", "open"]


# ---------- pass 4 (link): finding ↔ asset ----------------------------------

def test_asset_link_creates_edge_above_threshold(neo4j_driver, fresh_run):
    s = get_settings()
    base = _unit_vec(8)
    asset_id = fresh_run["track_asset"](_inject_asset(neo4j_driver, base, kind="db"))
    finding_id = _inject_finding(neo4j_driver, fresh_run["run_id"], base,
                                 summary="touches the db")

    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_fp_suppress=True, skip_dedup=True)
    assert result.n_asset_links == 1

    with neo4j_driver.session(database=s.neo4j_database) as session:
        n = session.run(
            "MATCH (:Finding {id:$f})-[:AFFECTS_ASSET]->(:ProductionAsset {id:$a}) "
            "RETURN count(*) AS n", f=finding_id, a=asset_id,
        ).single()["n"]
    assert n == 1


def test_asset_link_no_assets_is_noop(neo4j_driver, fresh_run):
    """When no ProductionAsset exists at all, the asset-link pass short-circuits."""
    _inject_finding(neo4j_driver, fresh_run["run_id"], _unit_vec(9))
    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_fp_suppress=True, skip_dedup=True)
    assert result.n_asset_links == 0


# ---------- end-to-end consolidate counts ------------------------------------

def test_consolidate_returns_open_counts_and_elapsed(neo4j_driver, fresh_run):
    """ConsolidateResult tracks before/after open counts and elapsed_s."""
    base = _unit_vec(10)
    _inject_finding(neo4j_driver, fresh_run["run_id"], base, summary="a")
    _inject_finding(neo4j_driver, fresh_run["run_id"], base, summary="b")
    _inject_finding(neo4j_driver, fresh_run["run_id"], _unit_vec(11), summary="c")

    result = consolidate(fresh_run["run_id"], driver=neo4j_driver,
                         skip_fp_suppress=True, skip_asset_link=True)
    assert result.n_open_at_start == 3
    assert result.n_duplicates == 1
    assert result.n_open_at_end == 2  # one of the (a,b) pair becomes 'duplicate'
    assert result.elapsed_s >= 0.0


def test_consolidate_empty_run_is_noop(neo4j_driver, fresh_run):
    result = consolidate(fresh_run["run_id"], driver=neo4j_driver)
    assert result.n_open_at_start == 0
    assert result.n_suppressed == 0
    assert result.n_duplicates == 0
    assert result.n_asset_links == 0
