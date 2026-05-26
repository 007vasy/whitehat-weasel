"""Parse CyberGym local sample directories.

Layout (per the explored data):

    cybergym_data/<sample>/         # base (level 1): description + repo
        description.txt
        repo-vul.tar.gz
        src-vul/                    # extracted; contains build.sh + libFuzzer harness
    cybergym_data/<sample>-l2/      # + sanitizer crash stack
        error.txt
    cybergym_data/<sample>-l3/      # + ground-truth patch + fixed repo
        patch.diff
        repo-fix.tar.gz
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from unidiff import PatchSet


@dataclass(frozen=True)
class PatchHunk:
    """A single hunk of a patch: lines on the post-image we treat as ground-truth vulnerable.

    `line_start`/`line_end` are inclusive 1-based line numbers in the *post-patch* file
    (i.e. the lines added or modified by the fix; these are the lines the bug "was at").
    For pure deletions we fall back to the source-side line range.
    """

    file_path: str
    line_start: int
    line_end: int
    source_side: bool = False  # True if we used source-side numbering (pure deletion)


@dataclass(frozen=True)
class CyberGymSample:
    sample_id: str               # e.g. "arvo-1065"
    base_dir: Path               # cybergym_data/<sample>/
    l2_dir: Path | None          # cybergym_data/<sample>-l2/  (None if missing)
    l3_dir: Path | None          # cybergym_data/<sample>-l3/  (None if missing)
    description: str             # contents of description.txt
    src_vul_dir: Path | None     # cybergym_data/<sample>/src-vul/ (None if not extracted)
    error_text: str | None = None      # sanitizer stack from -l2/error.txt
    patch_diff_text: str | None = None # raw patch.diff text from -l3/
    patch_hunks: list[PatchHunk] = field(default_factory=list)

    @property
    def language(self) -> str:
        # All current samples are C/C++. Detect by extension if any C++ source files exist.
        if self.src_vul_dir is None:
            return "c"
        for ext in ("*.cc", "*.cpp", "*.cxx", "*.C", "*.hpp"):
            if any(self.src_vul_dir.rglob(ext)):
                return "cpp"
        return "c"


def find_sample(sample_id: str, data_root: Path) -> CyberGymSample:
    """Locate and load metadata for one CyberGym sample.

    Raises FileNotFoundError if the base directory is missing.
    """
    base_dir = data_root / sample_id
    if not base_dir.is_dir():
        raise FileNotFoundError(f"cybergym sample not found: {base_dir}")

    l2_dir = data_root / f"{sample_id}-l2"
    l3_dir = data_root / f"{sample_id}-l3"

    description_path = base_dir / "description.txt"
    description = description_path.read_text(encoding="utf-8", errors="replace").strip() \
        if description_path.is_file() else ""

    src_vul_dir = base_dir / "src-vul"
    src_vul_dir = src_vul_dir if src_vul_dir.is_dir() else None

    error_text: str | None = None
    if l2_dir.is_dir():
        err_path = l2_dir / "error.txt"
        if err_path.is_file():
            error_text = err_path.read_text(encoding="utf-8", errors="replace")

    patch_diff_text: str | None = None
    patch_hunks: list[PatchHunk] = []
    if l3_dir is not None and l3_dir.is_dir():
        patch_path = l3_dir / "patch.diff"
        if patch_path.is_file():
            patch_diff_text = patch_path.read_text(encoding="utf-8", errors="replace")
            patch_hunks = parse_patch_hunks(patch_diff_text)

    return CyberGymSample(
        sample_id=sample_id,
        base_dir=base_dir,
        l2_dir=l2_dir if l2_dir.is_dir() else None,
        l3_dir=l3_dir if l3_dir.is_dir() else None,
        description=description,
        src_vul_dir=src_vul_dir,
        error_text=error_text,
        patch_diff_text=patch_diff_text,
        patch_hunks=patch_hunks,
    )


def parse_patch_hunks(diff_text: str) -> list[PatchHunk]:
    """Convert a unified-diff string into a list of PatchHunks anchored on the post-image.

    We collect, per hunk, the smallest contiguous range of post-image line numbers that
    covers every added or modified line. For pure-deletion hunks (no added/modified
    post-image lines), we fall back to the pre-image span (`source_side=True`) so the
    location is still recorded.
    """
    hunks: list[PatchHunk] = []
    patch = PatchSet.from_string(diff_text)
    for pf in patch:
        # unidiff exposes path on pf.target_file / pf.source_file with "a/" / "b/" prefixes.
        target = _strip_diff_prefix(pf.target_file)
        source = _strip_diff_prefix(pf.source_file)
        path = target if target and target != "/dev/null" else source
        if path is None or path == "/dev/null":
            continue

        for hunk in pf:
            added_lines = [ln.target_line_no for ln in hunk if ln.is_added and ln.target_line_no]
            if added_lines:
                hunks.append(PatchHunk(
                    file_path=path,
                    line_start=min(added_lines),
                    line_end=max(added_lines),
                    source_side=False,
                ))
                continue
            removed_lines = [ln.source_line_no for ln in hunk if ln.is_removed and ln.source_line_no]
            if removed_lines:
                hunks.append(PatchHunk(
                    file_path=path,
                    line_start=min(removed_lines),
                    line_end=max(removed_lines),
                    source_side=True,
                ))
    return hunks


def _strip_diff_prefix(path: str | None) -> str | None:
    """Strip `a/` or `b/` from a unified-diff path. Returns None for /dev/null."""
    if path is None:
        return None
    if path in ("/dev/null", "dev/null"):
        return path
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def list_local_samples(data_root: Path) -> list[str]:
    """Return base sample ids (no -l2/-l3 variants), sorted."""
    ids: set[str] = set()
    for child in sorted(data_root.iterdir()):
        if not child.is_dir():
            continue
        name = child.name
        if name.endswith("-l2") or name.endswith("-l3"):
            continue
        ids.add(name)
    return sorted(ids)
