"""Shared pytest fixtures for unit / integration / e2e tests.

Environment overrides set BEFORE importing any whw.* code so pydantic-settings
picks them up:
  - WHW_EMBEDDING_BACKEND=noop (never download the Nomic model in CI/tests)
"""

from __future__ import annotations

import os
import shutil
import subprocess

# Must precede any `from whw...` import below.
os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

from pathlib import Path

import pytest
from neo4j import GraphDatabase

from whw.config import get_settings


def _neo4j_reachable() -> bool:
    try:
        s = get_settings()
        driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
        driver.verify_connectivity()
        driver.close()
        return True
    except Exception:
        return False


NEO4J_OK = _neo4j_reachable()
CBM_OK = shutil.which("codebase-memory-mcp") is not None
CLAUDE_OK = shutil.which(get_settings().claude_code_bin) is not None
HAVE_API_KEY = bool(os.environ.get("ANTHROPIC_API_KEY"))
E2E_OPT_IN = os.environ.get("WHW_RUN_E2E") == "1"

DATA_ROOT = Path(__file__).resolve().parent.parent / "cybergym_data"
HAVE_ARVO_1065 = (DATA_ROOT / "arvo-1065" / "src-vul").is_dir()


# ---------- shared driver fixture --------------------------------------------

@pytest.fixture(scope="session")
def neo4j_driver():
    """Session-scoped Neo4j driver; skips entire test if Neo4j is unreachable."""
    if not NEO4J_OK:
        pytest.skip("Neo4j not reachable at the configured URI; see `whw doctor`.")
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    yield driver
    driver.close()


# ---------- arvo-1065 ingest (session-scoped, idempotent) --------------------

ARVO_1065_REPO_ID = "arvo-1065"
ARVO_1065_COMMIT = "vul"


@pytest.fixture(scope="session")
def arvo_1065_ingested(neo4j_driver):
    """Ensure arvo-1065 is ingested. Re-ingests only if Neo4j has < 100 Functions for it.

    Returns {"repo_id", "commit", "abs_repo_root"} so tests can use the same anchors.
    """
    if not HAVE_ARVO_1065:
        pytest.skip("cybergym_data/arvo-1065/src-vul is not present locally")
    if not CBM_OK:
        pytest.skip("codebase-memory-mcp not on PATH (needed to (re)index arvo-1065)")

    s = get_settings()
    abs_repo_root = (DATA_ROOT / "arvo-1065" / "src-vul").resolve()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c}) RETURN count(f) AS n",
            rid=ARVO_1065_REPO_ID, c=ARVO_1065_COMMIT,
        ).single()
    n_existing = int(row["n"]) if row else 0

    if n_existing < 100:
        from whw.ingest import ingest
        ingest(str(abs_repo_root), ARVO_1065_COMMIT, ARVO_1065_REPO_ID, mode="full")

    return {
        "repo_id": ARVO_1065_REPO_ID,
        "commit": ARVO_1065_COMMIT,
        "abs_repo_root": str(abs_repo_root),
    }


# ---------- helpers for write-test cleanup -----------------------------------

@pytest.fixture
def cleanup_neo4j_run(neo4j_driver):
    """Returns a callable that deletes an AuditRun and all its Findings cleanly.

    Usage:
        def test_x(neo4j_driver, cleanup_neo4j_run):
            run_id = "..."
            # ... do stuff ...
            cleanup_neo4j_run(run_id)
    """
    created: list[str] = []
    s = get_settings()

    def _register(run_id: str):
        created.append(run_id)

    yield _register

    with neo4j_driver.session(database=s.neo4j_database) as session:
        for rid in created:
            session.run(
                "MATCH (run:AuditRun {id:$rid}) "
                "OPTIONAL MATCH (run)-[:FOUND]->(n:Finding) "
                "DETACH DELETE n, run",
                rid=rid,
            )


# ---------- synthetic ingest helper (cbm + Neo4j) -----------------------------

@pytest.fixture
def cleanup_synthetic(neo4j_driver):
    """Tracks (repo_id, cbm_slug) pairs created during a test; removes both at end."""
    created: list[tuple[str, str]] = []
    s = get_settings()

    def _register(repo_id: str, cbm_slug: str):
        created.append((repo_id, cbm_slug))

    yield _register

    # Neo4j cleanup
    with neo4j_driver.session(database=s.neo4j_database) as session:
        for repo_id, _slug in created:
            session.run(
                "MATCH (n {repo_id:$rid}) DETACH DELETE n",
                rid=repo_id,
            )
    # cbm cleanup
    for _repo_id, slug in created:
        try:
            subprocess.run(
                ["codebase-memory-mcp", "cli", "delete_project",
                 f'{{"project":"{slug}"}}'],
                capture_output=True, timeout=30,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
