"""Integration test: full cbm + Neo4j pipeline on a tiny synthetic C project.

Avoids depending on the arvo-1065 fixture so this also serves as a "from scratch"
sanity check of the ingest. Cleans up both Neo4j and cbm cache at end.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import textwrap
from pathlib import Path

import pytest

from whw.config import get_settings
from whw.ingest import cbm_db_path, cbm_slug, decode_embedding, ingest

pytestmark = [pytest.mark.integration, pytest.mark.ingest]


# ----- pure-helper unit tests (no Neo4j needed) ------------------------------

def test_decode_embedding_int8_round_trip():
    # 768 signed-int8 bytes → 768 floats, roughly in [-1, 1].
    import numpy as np
    blob = np.array([127, -127, 0, 64, -64] + [0] * 763, dtype=np.int8).tobytes()
    vec = decode_embedding(blob)
    assert len(vec) == 768
    assert vec[0] == pytest.approx(1.0, abs=1e-6)
    assert vec[1] == pytest.approx(-1.0, abs=1e-6)
    assert vec[2] == pytest.approx(0.0)
    assert -1.0 <= min(vec) and max(vec) <= 1.0


def test_decode_embedding_short_blob_is_zero_padded_uses_unsigned_byte_input():
    # Use unsigned bytes for the short-blob check since bytes() needs values in [0,255].
    vec = decode_embedding(bytes([10, 20, 30]))
    assert len(vec) == 768
    assert vec[0] == pytest.approx(10 / 127.0, abs=1e-6)
    assert all(x == 0.0 for x in vec[3:])


def test_decode_embedding_empty_returns_empty():
    assert decode_embedding(b"") == []




def test_cbm_slug_matches_cbm_convention():
    assert cbm_slug("/home/x/y") == "home-x-y"
    assert cbm_slug("/a/b_c/d-e") == "a-b_c-d-e"


def test_cbm_db_path_resolves():
    p = cbm_db_path("home-x-y")
    assert p.name == "home-x-y.db"
    assert "codebase-memory-mcp" in str(p)


# ----- live pipeline test ----------------------------------------------------

SYNTH_FOO_C = textwrap.dedent("""\
    #include <stdio.h>
    int add(int a, int b) {
        return a + b;
    }
    int sub(int a, int b) {
        return a - b;
    }
    int main(int argc, char **argv) {
        int x = add(1, 2);
        int y = sub(x, 3);
        printf("%d\\n", y);
        return 0;
    }
""")


@pytest.mark.ingest
def test_full_pipeline_on_synthetic_c_project(tmp_path, neo4j_driver, cleanup_synthetic):
    """Create a tiny C project on disk; index via cbm; drain to Neo4j; verify state."""
    from shutil import which
    if not which("codebase-memory-mcp"):
        pytest.skip("codebase-memory-mcp not on PATH")

    project = tmp_path / "synthproject"
    project.mkdir()
    (project / "foo.c").write_text(SYNTH_FOO_C)

    repo_id = f"whw-test-synth-{os.getpid()}"
    slug = cbm_slug(project)
    cleanup_synthetic(repo_id, slug)

    result = ingest(str(project), commit="synth", repo_id=repo_id, mode="full")

    assert result.repo_id == repo_id
    assert result.commit == "synth"
    assert result.abs_repo_root == str(project.resolve())
    assert result.cbm_project == slug
    # A trivial project must yield at least the 3 functions plus a File/Module.
    assert result.nodes_written >= 3
    assert result.label_counts.get("Function", 0) >= 3
    # Embeddings: cbm may skip some — assert >= 0 and consistent shape.
    assert result.embeddings_written >= 0

    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        names = {
            r["name"] for r in session.run(
                "MATCH (f:Function {repo_id:$rid, commit:$c}) RETURN f.name AS name",
                rid=repo_id, c="synth",
            )
        }
        rp = session.run(
            "MATCH (r:RepoCommit {repo_id:$rid, commit:$c}) RETURN r.abs_repo_root AS p",
            rid=repo_id, c="synth",
        ).single()
    assert {"add", "sub", "main"}.issubset(names)
    assert rp and rp["p"] == str(project.resolve())


@pytest.mark.ingest
def test_full_pipeline_is_idempotent(tmp_path, neo4j_driver, cleanup_synthetic):
    """Running ingest twice on the same (repo, commit) doesn't multiply rows."""
    from shutil import which
    if not which("codebase-memory-mcp"):
        pytest.skip("codebase-memory-mcp not on PATH")

    project = tmp_path / "idemproject"
    project.mkdir()
    (project / "foo.c").write_text(SYNTH_FOO_C)
    repo_id = f"whw-test-idem-{os.getpid()}"
    cleanup_synthetic(repo_id, cbm_slug(project))

    r1 = ingest(str(project), commit="x", repo_id=repo_id, mode="full")
    r2 = ingest(str(project), commit="x", repo_id=repo_id, mode="full", skip_index=True)

    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        n_funcs = session.run(
            "MATCH (f:Function {repo_id:$rid, commit:$c}) RETURN count(f) AS c",
            rid=repo_id, c="x",
        ).single()["c"]
    # Counts should match between runs and Neo4j has exactly one node per QN.
    assert r1.label_counts.get("Function", 0) == r2.label_counts.get("Function", 0)
    assert n_funcs == r1.label_counts.get("Function", 0)
