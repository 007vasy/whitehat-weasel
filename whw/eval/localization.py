"""Localization metrics: how well did WHW's Findings overlap with the L3 patch hunks?

Given a list of Findings (each with file_path, line_start, line_end, severity,
confidence) and a list of patch hunks (each with file_path, line_start, line_end),
compute:

    hit_at_file: any finding's file matches any hunk's file
    hit_at_line: any finding's line range intersects any hunk's line range (same file)
    iou_line:    per-file (intersection / union) over line sets, averaged across patched files
    hit_at_k:    for k in {1,3,5,10}, does the top-k (ranked by severity*confidence weight)
                 contain a line-hit?

All scores are floats in [0,1] except hit_* which are bools.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Sequence

from .cybergym_loader import PatchHunk


SEVERITY_WEIGHT = {"crit": 4.0, "high": 3.0, "med": 2.0, "low": 1.0, "info": 0.0}
CONFIDENCE_WEIGHT = {"certain": 1.0, "inferred": 0.7, "uncertain": 0.4}


@dataclass(frozen=True)
class FindingLoc:
    """The localization-relevant projection of a Finding."""
    file_path: str
    line_start: int
    line_end: int
    severity: str = "med"
    confidence: str = "inferred"
    # Free-form id for tie-breaking and reporting; not used in scoring.
    id: str = ""


@dataclass
class LocalizationGrade:
    sample_id: str | None = None
    audit_run_id: str | None = None
    n_findings: int = 0
    n_hunks: int = 0
    hit_at_file: bool = False
    hit_at_line: bool = False
    iou_line: float = 0.0
    hit_at_k: dict[int, bool] = field(default_factory=lambda: {1: False, 3: False, 5: False, 10: False})
    patched_files: list[str] = field(default_factory=list)
    matched_finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sample": self.sample_id,
            "audit_run_id": self.audit_run_id,
            "n_findings": self.n_findings,
            "n_hunks": self.n_hunks,
            "patched_files": self.patched_files,
            "hit_at_file": self.hit_at_file,
            "hit_at_line": self.hit_at_line,
            "iou_line": round(self.iou_line, 4),
            "hit_at_k": {str(k): v for k, v in sorted(self.hit_at_k.items())},
            "matched_finding_ids": self.matched_finding_ids,
        }


def _normalize_path(path: str) -> str:
    """Compare paths leniently: drop leading './', normalize separators, lowercase nothing.

    We intentionally do NOT lowercase — POSIX file systems are case-sensitive.
    """
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _finding_overlaps_hunk(f: FindingLoc, h: PatchHunk) -> bool:
    if _normalize_path(f.file_path) != _normalize_path(h.file_path):
        # Tolerate trailing-suffix match on either side (e.g. finding=src/foo.c, hunk=foo.c).
        fp, hp = _normalize_path(f.file_path), _normalize_path(h.file_path)
        if not (fp.endswith("/" + hp) or hp.endswith("/" + fp) or os.path.basename(fp) == os.path.basename(hp)):
            return False
    return f.line_start <= h.line_end and h.line_start <= f.line_end


def _finding_file_matches_any_hunk(f: FindingLoc, hunks: Sequence[PatchHunk]) -> bool:
    f_norm = _normalize_path(f.file_path)
    f_base = os.path.basename(f_norm)
    for h in hunks:
        h_norm = _normalize_path(h.file_path)
        if f_norm == h_norm:
            return True
        if f_norm.endswith("/" + h_norm) or h_norm.endswith("/" + f_norm):
            return True
        if os.path.basename(h_norm) == f_base:
            return True
    return False


def _rank_findings(findings: Sequence[FindingLoc]) -> list[FindingLoc]:
    """Sort by severity_weight × confidence_weight descending; stable by input order."""
    def key(f: FindingLoc) -> float:
        sw = SEVERITY_WEIGHT.get(f.severity, 1.0)
        cw = CONFIDENCE_WEIGHT.get(f.confidence, 0.5)
        return -(sw * cw)
    return sorted(findings, key=key)


def grade(
    findings: Sequence[FindingLoc],
    hunks: Sequence[PatchHunk],
    *,
    sample_id: str | None = None,
    audit_run_id: str | None = None,
) -> LocalizationGrade:
    """Compute the full grade."""
    g = LocalizationGrade(
        sample_id=sample_id,
        audit_run_id=audit_run_id,
        n_findings=len(findings),
        n_hunks=len(hunks),
        patched_files=sorted({_normalize_path(h.file_path) for h in hunks}),
    )

    if not findings or not hunks:
        return g

    # hit_at_file
    g.hit_at_file = any(_finding_file_matches_any_hunk(f, hunks) for f in findings)

    # hit_at_line + matched ids
    matched_ids: list[str] = []
    for f in findings:
        for h in hunks:
            if _finding_overlaps_hunk(f, h):
                if f.id and f.id not in matched_ids:
                    matched_ids.append(f.id)
                g.hit_at_line = True
                break
    g.matched_finding_ids = matched_ids

    # iou_line per file
    g.iou_line = _iou_line(findings, hunks)

    # hit@k
    ranked = _rank_findings(findings)
    for k in (1, 3, 5, 10):
        top_k = ranked[:k]
        g.hit_at_k[k] = any(
            _finding_overlaps_hunk(f, h)
            for f in top_k
            for h in hunks
        )

    return g


def _iou_line(findings: Sequence[FindingLoc], hunks: Sequence[PatchHunk]) -> float:
    """Per-patched-file line-set IoU, then macro-average across patched files.

    Lines are counted as the set of integer line numbers covered by each span.
    Files that have hunks but no findings count as IoU 0 for that file
    (penalty for missing coverage). Files with findings but no hunks are ignored.
    """
    # Bucket by file (normalized).
    hunk_lines: dict[str, set[int]] = {}
    for h in hunks:
        hunk_lines.setdefault(_normalize_path(h.file_path), set()).update(
            range(h.line_start, h.line_end + 1)
        )

    finding_lines_by_file: dict[str, set[int]] = {}
    for f in findings:
        f_norm = _normalize_path(f.file_path)
        # Map to a patched-file bucket if any matches (incl. basename fallback).
        bucket = None
        for hf in hunk_lines:
            if f_norm == hf or f_norm.endswith("/" + hf) or hf.endswith("/" + f_norm) \
               or os.path.basename(f_norm) == os.path.basename(hf):
                bucket = hf
                break
        if bucket is None:
            continue
        finding_lines_by_file.setdefault(bucket, set()).update(
            range(f.line_start, f.line_end + 1)
        )

    per_file_iou: list[float] = []
    for hf, hlines in hunk_lines.items():
        flines = finding_lines_by_file.get(hf, set())
        union = hlines | flines
        inter = hlines & flines
        per_file_iou.append(len(inter) / len(union) if union else 0.0)

    return sum(per_file_iou) / len(per_file_iou) if per_file_iou else 0.0
