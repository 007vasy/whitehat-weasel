"""Tests for whw.eval.cybergym_loader.

Uses the real arvo-1065 sample dir under cybergym_data/ (gitignored locally) when
present; falls back to synthetic-text tests for parse_patch_hunks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from whw.eval.cybergym_loader import (
    PatchHunk,
    find_sample,
    list_local_samples,
    parse_patch_hunks,
)


DATA_ROOT = Path(__file__).resolve().parent.parent / "cybergym_data"
HAVE_LOCAL = DATA_ROOT.is_dir()


SYNTHETIC_DIFF = """\
diff --git a/src/foo.c b/src/foo.c
--- a/src/foo.c
+++ b/src/foo.c
@@ -10,3 +10,4 @@
 ctx_a
-old
+new1
+new2
 ctx_b
diff --git a/src/del.c b/src/del.c
--- a/src/del.c
+++ b/src/del.c
@@ -5,3 +4,2 @@
 ctx_a
-deleted_line
 ctx_b
"""


def test_parse_patch_hunks_synthetic_added_and_removed():
    hunks = parse_patch_hunks(SYNTHETIC_DIFF)
    # foo.c has added lines (post-image numbering); del.c is pure deletion (source-side).
    by_path = {h.file_path: h for h in hunks}
    assert "src/foo.c" in by_path
    assert "src/del.c" in by_path
    foo = by_path["src/foo.c"]
    assert foo.source_side is False
    # Hunk header +10,4 means post-image lines 10..13. Added lines are new1 (line 11) and
    # new2 (line 12), so the recorded span covers those.
    assert foo.line_start == 11
    assert foo.line_end == 12
    delh = by_path["src/del.c"]
    assert delh.source_side is True
    # Hunk header -5,3 means source lines 5..7. The removed line is source line 6.
    assert delh.line_start == 6
    assert delh.line_end == 6


def test_parse_patch_hunks_empty():
    assert parse_patch_hunks("") == []


def test_patchhunk_immutable():
    h = PatchHunk(file_path="x.c", line_start=1, line_end=2)
    with pytest.raises(Exception):
        h.line_start = 99  # frozen dataclass


@pytest.mark.skipif(not HAVE_LOCAL, reason="cybergym_data/ not present locally")
def test_list_local_samples_dedupes_levels():
    samples = list_local_samples(DATA_ROOT)
    assert "arvo-1065" in samples
    for s in samples:
        assert not s.endswith("-l2")
        assert not s.endswith("-l3")


@pytest.mark.skipif(not HAVE_LOCAL, reason="cybergym_data/ not present locally")
def test_find_sample_arvo_1065_loads_description_and_patch():
    sample = find_sample("arvo-1065", DATA_ROOT)
    assert sample.sample_id == "arvo-1065"
    assert sample.base_dir.is_dir()
    assert sample.description  # non-empty
    assert sample.src_vul_dir is not None
    assert sample.l2_dir is not None
    assert sample.l3_dir is not None
    # MSan emits "WARNING:" not "ERROR:" — accept either, plus the generic sanitizer marker.
    assert sample.error_text and ("SANITIZER" in sample.error_text.upper()
                                  or "ERROR:" in sample.error_text.upper())
    assert sample.patch_diff_text and "diff --git" in sample.patch_diff_text
    assert sample.patch_hunks, "expected at least one hunk parsed from arvo-1065-l3/patch.diff"
    # Language detection: arvo-1065 has magic_fuzzer.cc → cpp.
    assert sample.language in ("c", "cpp")


@pytest.mark.skipif(not HAVE_LOCAL, reason="cybergym_data/ not present locally")
def test_find_sample_missing_raises():
    with pytest.raises(FileNotFoundError):
        find_sample("does-not-exist-xyz", DATA_ROOT)
