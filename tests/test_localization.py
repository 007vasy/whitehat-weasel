"""Tests for whw.eval.localization.grade()."""

from __future__ import annotations

from whw.eval.cybergym_loader import PatchHunk
from whw.eval.localization import FindingLoc, grade


def _f(path: str, ls: int, le: int, sev: str = "high", conf: str = "certain", id: str = "") -> FindingLoc:
    return FindingLoc(file_path=path, line_start=ls, line_end=le, severity=sev, confidence=conf, id=id)


def _h(path: str, ls: int, le: int) -> PatchHunk:
    return PatchHunk(file_path=path, line_start=ls, line_end=le, source_side=False)


def test_grade_empty_inputs():
    g = grade([], [])
    assert g.n_findings == 0
    assert g.n_hunks == 0
    assert g.hit_at_file is False
    assert g.hit_at_line is False
    assert g.iou_line == 0.0
    assert all(v is False for v in g.hit_at_k.values())


def test_grade_perfect_line_hit():
    findings = [_f("src/foo.c", 10, 20, id="F1")]
    hunks = [_h("src/foo.c", 12, 18)]
    g = grade(findings, hunks)
    assert g.hit_at_file is True
    assert g.hit_at_line is True
    # finding lines 10..20 = 11 lines; hunk 12..18 = 7 lines; intersection 7, union 11.
    assert abs(g.iou_line - (7 / 11)) < 1e-6
    assert g.hit_at_k[1] is True
    assert "F1" in g.matched_finding_ids


def test_grade_file_match_but_no_line_overlap():
    findings = [_f("src/foo.c", 100, 110)]
    hunks = [_h("src/foo.c", 12, 18)]
    g = grade(findings, hunks)
    assert g.hit_at_file is True
    assert g.hit_at_line is False
    assert g.iou_line == 0.0
    assert all(v is False for v in g.hit_at_k.values())


def test_grade_basename_fallback_path_match():
    # WHW finding stores absolute-ish path; patch path is short. Basename fallback should match.
    findings = [_f("/abs/path/to/funcs.c", 500, 520)]
    hunks = [_h("src/funcs.c", 508, 514)]
    g = grade(findings, hunks)
    assert g.hit_at_file is True
    assert g.hit_at_line is True
    assert g.iou_line > 0


def test_grade_hit_at_k_ranks_by_severity_confidence():
    # Three findings; the line-overlapping one is RANKED LAST by severity.
    findings = [
        _f("src/foo.c", 1, 5, sev="crit", conf="certain", id="noise-1"),       # rank 1, no overlap
        _f("src/foo.c", 50, 60, sev="crit", conf="certain", id="noise-2"),     # rank 2, no overlap
        _f("src/foo.c", 12, 18, sev="low",  conf="uncertain", id="hitter"),    # rank last, overlaps
    ]
    hunks = [_h("src/foo.c", 12, 18)]
    g = grade(findings, hunks)
    assert g.hit_at_line is True
    # k=1,2 should miss (top-1/3 are noise); k=3 should hit (includes the hitter).
    assert g.hit_at_k[1] is False
    assert g.hit_at_k[3] is True
    assert g.hit_at_k[5] is True
    assert g.hit_at_k[10] is True


def test_grade_iou_with_multiple_patched_files_macro_average():
    findings = [
        _f("a.c", 10, 12),   # exact match on a.c hunk
    ]
    hunks = [
        _h("a.c", 10, 12),   # union=3 inter=3 → 1.0
        _h("b.c", 50, 60),   # union=11 inter=0 → 0.0 (missing coverage)
    ]
    g = grade(findings, hunks)
    # Macro average over two files: (1.0 + 0.0) / 2 = 0.5
    assert abs(g.iou_line - 0.5) < 1e-6
    assert g.hit_at_file is True
    assert g.hit_at_line is True


def test_grade_to_dict_serializable():
    findings = [_f("src/foo.c", 12, 18, id="F1")]
    hunks = [_h("src/foo.c", 12, 18)]
    g = grade(findings, hunks, sample_id="arvo-1065", audit_run_id="run-xyz")
    d = g.to_dict()
    assert d["sample"] == "arvo-1065"
    assert d["audit_run_id"] == "run-xyz"
    assert d["hit_at_k"] == {"1": True, "3": True, "5": True, "10": True}
    assert d["matched_finding_ids"] == ["F1"]
