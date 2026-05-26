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
