"""Integration tests for whw.orchestrator scope resolution + Neo4j writes.

Verifies all four ScopeSpec strategies and the in-scope flipping helper produce the
expected Neo4j state on live arvo-1065 data.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

import pytest

from whw.config import get_settings
from whw.orchestrator import (
    ScopeSpec,
    _glob_to_regex,
    mark_in_scope_in_neo4j,
    resolve_scope,
)

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _reset_in_scope(arvo_1065_ingested, neo4j_driver):
    """Before each test, reset in_scope on all arvo-1065 functions to avoid bleed-over."""
    s = get_settings()
    with neo4j_driver.session(database=s.neo4j_database) as session:
        session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul'}) SET f.in_scope=false",
        )


def test_glob_to_regex_basic_patterns():
    assert _glob_to_regex("foo.c") == r"^foo\.c$"
    assert _glob_to_regex("*.c") == r"^[^/]*\.c$"
    assert _glob_to_regex("src/*.c") == r"^src/[^/]*\.c$"
    assert _glob_to_regex("src/**/*.c") == r"^src/.*/[^/]*\.c$"
    # Question mark = single non-slash char.
    assert _glob_to_regex("a?b") == r"^a[^/]b$"
    # Escape regex metacharacters that aren't glob ops.
    assert _glob_to_regex("path+(x)") == r"^path\+\(x\)$"


def test_resolve_scope_function_exact(arvo_1065_ingested, neo4j_driver):
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(function="file_regexec"))
    assert len(fns) == 1
    assert fns[0]["name"] == "file_regexec"
    assert fns[0]["fp"] == "file/src/funcs.c"
    assert 500 <= fns[0]["ls"] <= 520


def test_resolve_scope_function_unknown_returns_empty(arvo_1065_ingested, neo4j_driver):
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(function="totally_imaginary_symbol_xyz"))
    assert fns == []


def test_resolve_scope_file_glob_matches_all_in_funcs_c(arvo_1065_ingested, neo4j_driver):
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(file_glob="file/src/funcs.c"))
    # arvo-1065's funcs.c has on the order of 20+ functions; assert a lower bound + that
    # file_regexec is among them.
    assert len(fns) >= 15
    names = {f["name"] for f in fns}
    assert "file_regexec" in names
    assert {f["fp"] for f in fns} == {"file/src/funcs.c"}


def test_resolve_scope_file_glob_wildcard_matches_all_c_files(arvo_1065_ingested, neo4j_driver):
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(file_glob="file/src/**.c"))
    # Should pick up multiple files (funcs.c, softmagic.c, magic.c, ...).
    files = {f["fp"] for f in fns}
    assert any(fp.endswith("funcs.c") for fp in files)
    assert any(fp.endswith("softmagic.c") for fp in files)
    assert len(files) >= 3


def test_resolve_scope_entrypoint_with_same_file_fallback(arvo_1065_ingested, neo4j_driver):
    """For C, cbm doesn't attribute Function-CALLS — the orchestrator's same-file fallback
    must kick in and return at least the seed + sibling functions in the entrypoint's file."""
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(entrypoint="magic_fuzzer.cc:LLVMFuzzerTestOneInput",
                                  entrypoint_depth=3))
    assert len(fns) >= 1
    names = {f["name"] for f in fns}
    assert "LLVMFuzzerTestOneInput" in names
    # Same-file fallback brings in siblings if there are any.
    files = {f["fp"] for f in fns}
    assert "magic_fuzzer.cc" in files


def test_resolve_scope_all_returns_every_function(arvo_1065_ingested, neo4j_driver):
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul", ScopeSpec(all=True))
    # arvo-1065 ingested ~324 functions earlier; allow generous lower bound.
    assert len(fns) >= 200


def test_resolve_scope_file_glob_basename_fallback_for_cybergym_paths(
    arvo_1065_ingested, neo4j_driver,
):
    """CyberGym L3 patch paths are project-relative (e.g. 'src/funcs.c') while ingested
    file_paths include the src-vul prefix ('file/src/funcs.c'). The exact glob misses,
    but the basename fallback in resolve_scope still finds the file. Used by
    `whw eval suite` to auto-scope from the patch path."""
    # Literal 'src/funcs.c' would regex-anchor to '^src/funcs\\.c$' and match nothing.
    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(file_glob="src/funcs.c"))
    # Fallback by trailing '/funcs.c' matches the file/src/funcs.c functions.
    assert len(fns) >= 15
    names = {f["name"] for f in fns}
    assert "file_regexec" in names
    assert {f["fp"] for f in fns} == {"file/src/funcs.c"}


def test_resolve_scope_empty_raises(arvo_1065_ingested, neo4j_driver):
    with pytest.raises(ValueError):
        resolve_scope(neo4j_driver, "arvo-1065", "vul", ScopeSpec())


def test_mark_in_scope_flips_only_the_named_qns(arvo_1065_ingested, neo4j_driver):
    s = get_settings()
    # Sanity: nothing in scope to start (autouse fixture reset).
    with neo4j_driver.session(database=s.neo4j_database) as session:
        c0 = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', in_scope:true}) "
            "RETURN count(f) AS c",
        ).single()["c"]
    assert c0 == 0

    fns = resolve_scope(neo4j_driver, "arvo-1065", "vul",
                        ScopeSpec(function="file_regexec"))
    marked = mark_in_scope_in_neo4j(neo4j_driver, "arvo-1065", "vul",
                                    [f["qn"] for f in fns],
                                    entrypoint_kind="manual", trust_level="MIXED")
    assert marked == 1

    with neo4j_driver.session(database=s.neo4j_database) as session:
        row = session.run(
            "MATCH (f:Function {repo_id:'arvo-1065', commit:'vul', in_scope:true}) "
            "RETURN f.name AS name, f.entrypoint_kind AS ek, f.trust_level AS tl",
        ).single()
    assert row["name"] == "file_regexec"
    assert row["ek"] == "manual"
    assert row["tl"] == "MIXED"


def test_mark_in_scope_empty_list_is_noop(arvo_1065_ingested, neo4j_driver):
    assert mark_in_scope_in_neo4j(neo4j_driver, "arvo-1065", "vul", []) == 0
