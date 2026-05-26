"""Tests for the multi-sample suite aggregator.

Skips the per-sample pipeline (which would spawn `claude -p`); instead synthesizes
SampleGrade objects and asserts the aggregator math.
"""

from __future__ import annotations

import os

os.environ.setdefault("WHW_EMBEDDING_BACKEND", "noop")

from whw.eval.suite import SampleGrade, _aggregate


def _grade(*, hit_file: bool = True, hit_line: bool = True, iou: float = 0.5,
           h1: bool = False, h3: bool = True, h5: bool = True, h10: bool = True) -> dict:
    return {
        "hit_at_file": hit_file, "hit_at_line": hit_line, "iou_line": iou,
        "hit_at_k": {"1": h1, "3": h3, "5": h5, "10": h10},
    }


def test_aggregate_empty():
    agg = _aggregate([])
    assert agg.n_samples == 0
    assert agg.n_succeeded == 0
    assert agg.n_failed == 0
    assert agg.micro_hit_at_file == 0.0
    assert agg.macro_iou_line == 0.0
    assert agg.micro_hit_at_k == {"1": 0.0, "3": 0.0, "5": 0.0, "10": 0.0}


def test_aggregate_all_succeed_all_hit():
    samples = [
        SampleGrade(sample="a", audit_run_id="x", grade=_grade(iou=0.5, h1=True)),
        SampleGrade(sample="b", audit_run_id="y", grade=_grade(iou=0.3, h1=True)),
    ]
    agg = _aggregate(samples)
    assert agg.n_samples == 2
    assert agg.n_succeeded == 2
    assert agg.n_failed == 0
    assert agg.micro_hit_at_file == 1.0
    assert agg.micro_hit_at_line == 1.0
    assert agg.macro_iou_line == 0.4  # (0.5 + 0.3) / 2
    assert agg.micro_hit_at_k["1"] == 1.0
    assert agg.micro_hit_at_k["3"] == 1.0


def test_aggregate_partial_hit_partial_miss():
    samples = [
        SampleGrade(sample="a", audit_run_id="x", grade=_grade(hit_file=True, hit_line=True,
                                                                iou=0.6, h1=True, h3=True)),
        SampleGrade(sample="b", audit_run_id="y", grade=_grade(hit_file=True, hit_line=False,
                                                                iou=0.0, h1=False, h3=False)),
        SampleGrade(sample="c", audit_run_id="z", grade=_grade(hit_file=False, hit_line=False,
                                                                iou=0.0, h1=False, h3=False)),
    ]
    agg = _aggregate(samples)
    assert agg.n_samples == 3
    assert agg.n_succeeded == 3
    assert agg.micro_hit_at_file == round(2 / 3, 4)
    assert agg.micro_hit_at_line == round(1 / 3, 4)
    assert agg.macro_iou_line == 0.2  # (0.6 + 0.0 + 0.0) / 3
    assert agg.micro_hit_at_k["1"] == round(1 / 3, 4)
    assert agg.micro_hit_at_k["3"] == round(1 / 3, 4)


def test_aggregate_skips_errored_samples():
    """Samples with `error` set don't contribute to numerator OR denominator."""
    samples = [
        SampleGrade(sample="ok", audit_run_id="x", grade=_grade(hit_file=True, iou=1.0,
                                                                 h1=True, h3=True, h5=True, h10=True)),
        SampleGrade(sample="bad1", error="cbm index failed"),
        SampleGrade(sample="bad2", error="audit timed out"),
    ]
    agg = _aggregate(samples)
    assert agg.n_samples == 3
    assert agg.n_succeeded == 1
    assert agg.n_failed == 2
    assert agg.micro_hit_at_file == 1.0  # 1 of 1 succeeded
    assert agg.macro_iou_line == 1.0


def test_aggregate_all_errors_yields_zeros():
    samples = [SampleGrade(sample=f"bad{i}", error="x") for i in range(4)]
    agg = _aggregate(samples)
    assert agg.n_samples == 4
    assert agg.n_succeeded == 0
    assert agg.micro_hit_at_file == 0.0
    assert agg.macro_iou_line == 0.0


def test_fetch_findings_filters_sentinel_rows(monkeypatch):
    """`_fetch_findings` must exclude AGENT_FAILED / INDEX_PARTIAL / source='orchestrator'
    sentinels — they inherit the host Function's span so they'd spuriously hit the
    patch hunks under line-overlap grading."""
    from whw.eval.suite import _fetch_findings, GRADING_SENTINEL_VULN_CLASSES

    # The function builds a Cypher session and runs one query. We replace the driver
    # with a minimal stub that captures the query parameters; the actual filter has
    # to be in the Cypher.
    captured: dict = {}

    class _Session:
        def __init__(self):
            pass
        def __enter__(self): return self
        def __exit__(self, *exc): return False
        def run(self, query, **params):
            captured["query"] = query
            captured["params"] = params
            return iter([])

    class _Driver:
        def session(self, **kw): return _Session()

    findings = _fetch_findings(_Driver(), "run-x")
    assert findings == []
    q = captured["query"]
    assert "WHERE n.status IN ['open', 'verified']" in q
    # The Cypher MUST reference both the sentinel-class filter AND the source filter.
    assert "NOT n.vuln_class IN $sentinels" in q
    assert "NOT n.source = 'orchestrator'" in q
    assert set(captured["params"]["sentinels"]) == set(GRADING_SENTINEL_VULN_CLASSES)


def test_scope_for_all_patched_files_unions_qns_across_files(monkeypatch):
    """_scope_for_all_patched_files calls resolve_scope per distinct patched file and
    unions the QNs. Test the union math without touching Neo4j by stubbing resolve_scope."""
    from unittest.mock import MagicMock

    from whw.eval.cybergym_loader import CyberGymSample, PatchHunk
    from whw.eval.suite import _scope_for_all_patched_files
    import whw.eval.suite as suite_mod

    # Three hunks across two distinct files.
    cg = CyberGymSample(
        sample_id="x", base_dir=None, l2_dir=None, l3_dir=None,
        description="", src_vul_dir=None,
        patch_hunks=[
            PatchHunk(file_path="src/a.c", line_start=10, line_end=12),
            PatchHunk(file_path="src/a.c", line_start=50, line_end=51),
            PatchHunk(file_path="src/b.c", line_start=1, line_end=1),
        ],
    )

    calls: list[str] = []

    def fake_resolve_scope(driver, repo_id, commit, scope):
        calls.append(scope.file_glob)
        if scope.file_glob == "src/a.c":
            return [{"qn": "a.foo"}, {"qn": "a.bar"}]
        if scope.file_glob == "src/b.c":
            return [{"qn": "b.baz"}]
        return []

    monkeypatch.setattr(suite_mod, "resolve_scope", fake_resolve_scope)

    spec = _scope_for_all_patched_files(MagicMock(), "x", "vul", cg)
    # One resolve_scope call per distinct file (a.c appears twice → still 1 call).
    assert sorted(calls) == ["src/a.c", "src/b.c"]
    assert spec.qualified_names == ["a.bar", "a.foo", "b.baz"]


def test_suite_report_to_dict_serializable():
    """End-to-end: SuiteReport.to_dict round-trips through JSON without errors."""
    import json
    from whw.eval.suite import SuiteAggregate, SuiteReport
    rep = SuiteReport(
        samples=[SampleGrade(sample="a", audit_run_id="r", grade=_grade())],
        aggregate=SuiteAggregate(
            n_samples=1, n_succeeded=1, n_failed=0,
            micro_hit_at_file=1.0, micro_hit_at_line=1.0,
            macro_iou_line=0.5,
            micro_hit_at_k={"1": 0.0, "3": 1.0, "5": 1.0, "10": 1.0},
        ),
        elapsed_s=1.23,
    )
    text = json.dumps(rep.to_dict())
    parsed = json.loads(text)
    assert parsed["aggregate"]["n_succeeded"] == 1
    assert parsed["samples"][0]["sample"] == "a"
