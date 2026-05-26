"""Multi-sample benchmark runner — `whw eval suite`.

For each CyberGym sample id, runs:

  1. ingest:       cbm + Neo4j drain (skipped if data already present and --no-ingest).
  2. audit:        scope = the file(s) the L3 patch.diff touches, depth 3.
                   Spawns BILLABLE claude -p sub-agents.
  3. consolidate:  FP suppression + dedup + asset link (Cypher only — no triage/infra).
  4. localize:     hit@file, hit@line, IoU, hit@k against patch.diff hunks.

Aggregates per-sample grades into micro/macro metrics. Per-sample failures are captured
so one bad sample doesn't kill the suite.

Cost guardrail: requires explicit `--samples` list (no auto-discovery default). The
caller's CLI verb is responsible for confirming any cost-spending behaviour with the
user before invoking this.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase

from ..config import get_settings
from ..consolidate import consolidate as run_consolidate
from ..ingest import ingest as run_ingest
from ..orchestrator import ScopeSpec, audit as run_audit, resolve_scope
from .cybergym_loader import CyberGymSample, find_sample
from .localization import FindingLoc, LocalizationGrade, grade


@dataclass
class SampleGrade:
    sample: str
    audit_run_id: str | None = None
    grade: dict[str, Any] = field(default_factory=dict)
    n_findings_total: int = 0
    n_in_scope: int = 0
    elapsed_s: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SuiteAggregate:
    n_samples: int
    n_succeeded: int
    n_failed: int
    micro_hit_at_file: float
    micro_hit_at_line: float
    macro_iou_line: float
    micro_hit_at_k: dict[str, float]  # {"1": .., "3": .., "5": .., "10": ..}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SuiteReport:
    samples: list[SampleGrade]
    aggregate: SuiteAggregate
    elapsed_s: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": [s.to_dict() for s in self.samples],
            "aggregate": self.aggregate.to_dict(),
            "elapsed_s": self.elapsed_s,
        }


def run_suite(
    samples: list[str],
    *,
    data_root: Path,
    skip_ingest: bool = False,
    skip_consolidate: bool = False,
    depth: int = 3,
    model: str = "sonnet",
    tools_image: str | None = None,
) -> SuiteReport:
    """Run the full ingest+audit+consolidate+localize pipeline per sample, aggregate."""
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    started = time.monotonic()
    per_sample: list[SampleGrade] = []
    try:
        for sample_id in samples:
            per_sample.append(_run_one(
                sample_id, data_root=data_root, driver=driver,
                skip_ingest=skip_ingest, skip_consolidate=skip_consolidate,
                depth=depth, model=model, tools_image=tools_image,
            ))
    finally:
        driver.close()

    return SuiteReport(
        samples=per_sample,
        aggregate=_aggregate(per_sample),
        elapsed_s=round(time.monotonic() - started, 2),
    )


def _run_one(
    sample_id: str, *, data_root: Path, driver,
    skip_ingest: bool, skip_consolidate: bool,
    depth: int, model: str, tools_image: str | None,
) -> SampleGrade:
    t0 = time.monotonic()
    g = SampleGrade(sample=sample_id)
    try:
        cg = find_sample(sample_id, data_root)
        if not cg.patch_hunks:
            raise RuntimeError(f"sample has no L3 patch.diff hunks — cannot grade")
        if not cg.src_vul_dir:
            raise RuntimeError("sample src-vul/ missing on disk")

        if not skip_ingest:
            run_ingest(str(cg.src_vul_dir), "vul", sample_id, mode="full")

        # Scope = the UNION of functions across every file the L3 patch touches. This
        # handles multi-file patches correctly and uses the file_glob basename fallback
        # in resolve_scope (CyberGym patch paths are project-relative; ingested
        # file_paths include the src-vul prefix).
        scope = _scope_for_all_patched_files(driver, sample_id, "vul", cg)

        audit_res = run_audit(
            repo_id=sample_id, commit="vul",
            scope=scope,
            eval_commit="vul",
            eval_commit_ts="2017-01-01T00:00:00Z",
            tools_image=tools_image, model=model,
        )
        g.audit_run_id = audit_res.audit_run_id
        g.n_in_scope = audit_res.n_in_scope
        g.n_findings_total = audit_res.n_findings_total

        if not skip_consolidate:
            run_consolidate(audit_res.audit_run_id)

        findings = _fetch_findings(driver, audit_res.audit_run_id)
        grade_obj = grade(findings, cg.patch_hunks,
                          sample_id=sample_id, audit_run_id=audit_res.audit_run_id)
        g.grade = grade_obj.to_dict()
    except Exception as e:
        g.error = f"{type(e).__name__}: {e}"
    g.elapsed_s = round(time.monotonic() - t0, 2)
    return g


def _scope_for_all_patched_files(driver, repo_id: str, commit: str,
                                  cg: CyberGymSample) -> ScopeSpec:
    """Resolve in-scope Functions for every distinct file the L3 patch.diff touches,
    union the QNs, and return a ScopeSpec(qualified_names=[...]). Empty if nothing
    matched — the caller will see n_in_scope=0 and skip the audit."""
    qns: set[str] = set()
    for path in sorted({h.file_path for h in cg.patch_hunks}):
        fns = resolve_scope(driver, repo_id, commit, ScopeSpec(file_glob=path))
        qns.update(f["qn"] for f in fns)
    return ScopeSpec(qualified_names=sorted(qns))


def _fetch_findings(driver, audit_run_id: str) -> list[FindingLoc]:
    """Return the current open/verified Findings for the run, projected to FindingLoc."""
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        rows = list(session.run("""
            MATCH (:AuditRun {id:$rid})-[:FOUND]->(n:Finding)
            WHERE n.status IN ['open', 'verified']
            RETURN n.id AS id, n.file_path AS fp, n.line_start AS ls,
                   n.line_end AS le, n.severity AS sev, n.confidence AS conf
        """, rid=audit_run_id))
    return [
        FindingLoc(
            id=r["id"] or "", file_path=r["fp"] or "",
            line_start=int(r["ls"] or 0), line_end=int(r["le"] or 0),
            severity=r["sev"] or "med", confidence=r["conf"] or "inferred",
        )
        for r in rows if r["fp"]
    ]


def _aggregate(samples: list[SampleGrade]) -> SuiteAggregate:
    """Micro hit_at_file/line (rate over succeeded samples) + macro IoU + micro hit@k."""
    succeeded = [s for s in samples if s.error is None and s.grade]
    n_total = len(samples)
    n_ok = len(succeeded)

    def _bool_rate(key: str) -> float:
        if not succeeded:
            return 0.0
        return sum(1 for s in succeeded if s.grade.get(key)) / n_ok

    def _macro_iou() -> float:
        if not succeeded:
            return 0.0
        return sum(float(s.grade.get("iou_line", 0.0)) for s in succeeded) / n_ok

    def _hat_k() -> dict[str, float]:
        out: dict[str, float] = {}
        for k in ("1", "3", "5", "10"):
            if not succeeded:
                out[k] = 0.0
                continue
            hk = sum(1 for s in succeeded if s.grade.get("hit_at_k", {}).get(k)) / n_ok
            out[k] = round(hk, 4)
        return out

    return SuiteAggregate(
        n_samples=n_total,
        n_succeeded=n_ok,
        n_failed=n_total - n_ok,
        micro_hit_at_file=round(_bool_rate("hit_at_file"), 4),
        micro_hit_at_line=round(_bool_rate("hit_at_line"), 4),
        macro_iou_line=round(_macro_iou(), 4),
        micro_hit_at_k=_hat_k(),
    )
