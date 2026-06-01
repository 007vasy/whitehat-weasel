"""cbm SQLite → Neo4j ingestion bridge.

Pipeline:

    1. (Re)index target repo via `codebase-memory-mcp cli index_repository`.
       cbm writes its per-project SQLite to ~/.cache/codebase-memory-mcp/<slug>.db
       where slug = <abs_path>.lstrip('/').replace('/', '-').

    2. Open the SQLite directly. Iterate nodes (with their int8 Nomic embeddings) and
       edges (with their cbm source/target SQLite ids).

    3. Stream into Neo4j with batched MERGEs. Every node/edge is stamped with
       (repo_id, commit) so multiple commits of the same repo can coexist.

Idempotent: re-running with the same (repo, commit) re-MERGEs the same nodes and edges.

Bias-to-MCP note: this is a SCRIPT, not an MCP tool. It runs once per (repo, commit)
with zero per-call variance, so wrapping it in MCP roundtrips would be pure overhead.
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from neo4j import Driver, GraphDatabase

from .config import get_settings


# --- constants -----------------------------------------------------------------

NODE_BATCH = 1000
EDGE_BATCH = 1000
EMBED_DIM = 768
SAFE_LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SAFE_EDGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Properties from cbm's JSON column that we lift into top-level Neo4j props.
NODE_PROP_KEYS = ("signature", "complexity", "is_entry_point", "is_test",
                  "is_exported", "docstring", "return_type", "language")


# --- helpers -------------------------------------------------------------------

def cbm_slug(abs_path: str | Path) -> str:
    """Slugify an absolute path the way cbm does: drop leading '/', '/' → '-'."""
    return str(Path(abs_path).resolve()).lstrip("/").replace("/", "-")


def cbm_db_path(slug: str) -> Path:
    return Path.home() / ".cache" / "codebase-memory-mcp" / f"{slug}.db"


def decode_embedding(blob: bytes) -> list[float]:
    """768 signed int8 bytes → 768 floats in roughly [-1, 1] (Nomic int8 → float)."""
    if not blob:
        return []
    arr = np.frombuffer(blob, dtype=np.int8)
    if arr.size < EMBED_DIM:
        arr = np.concatenate([arr, np.zeros(EMBED_DIM - arr.size, dtype=np.int8)])
    elif arr.size > EMBED_DIM:
        arr = arr[:EMBED_DIM]
    return (arr.astype(np.float32) / 127.0).tolist()


def _git_head(repo: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True, stderr=subprocess.DEVNULL,
        )
        return out.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _git_commit_ts(repo: Path, commit: str) -> str | None:
    """ISO-8601 commit timestamp via `git show -s --format=%cI`."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "show", "-s", "--format=%cI", commit],
            text=True, stderr=subprocess.DEVNULL,
        )
        return out.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _guess_language(file_path: str | None) -> str:
    if not file_path:
        return ""
    ext = Path(file_path).suffix.lower()
    return {
        ".c": "c", ".h": "c",
        ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
        ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp", ".C": "cpp",
        ".py": "python",
        ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".rs": "rust",
        ".go": "go",
        ".java": "java",
        ".sol": "solidity",
    }.get(ext, "")


# --- cbm CLI invocation --------------------------------------------------------

def invoke_cbm_index(repo_path: Path, mode: str = "full", *, timeout: int = 1800) -> dict[str, Any]:
    """Run `codebase-memory-mcp cli index_repository` synchronously.

    Returns the parsed MCP response (or a {"raw_stdout": ...} fallback). Raises
    RuntimeError on non-zero exit code.
    """
    payload = json.dumps({"repo_path": str(repo_path), "mode": mode})
    cmd = ["codebase-memory-mcp", "cli", "index_repository", payload]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"cbm index_repository failed (exit {proc.returncode}):\n"
            f"--- stdout ---\n{proc.stdout[:4000]}\n"
            f"--- stderr ---\n{proc.stderr[:4000]}"
        )
    # The JSON response is on stdout; informational lines go to stderr.
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        # Fall back to line-wise: take the last parseable JSON line.
        last: dict[str, Any] | None = None
        for line in proc.stdout.splitlines():
            if not line.strip().startswith("{"):
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
        return last or {"raw_stdout": proc.stdout[:2000]}


# --- main ----------------------------------------------------------------------

@dataclass
class IngestResult:
    repo_id: str
    commit: str
    commit_ts: str | None
    abs_repo_root: str
    cbm_project: str
    cbm_db: str
    nodes_written: int
    edges_written: int
    embeddings_written: int
    label_counts: dict[str, int]
    edge_type_counts: dict[str, int]
    elapsed_s: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ingest(
    repo_path: str | Path,
    commit: str,
    repo_id: str,
    *,
    mode: str = "full",
    skip_index: bool = False,
    driver: Driver | None = None,
) -> IngestResult:
    """End-to-end ingest of (repo_path, commit) into Neo4j as `repo_id`.

    Args:
      repo_path: absolute or relative path to the source repository worktree (which
                 must already be checked out at `commit` — Phase A requires this).
      commit:    the commit SHA. Stamped on every Function/File/edge for keying.
      repo_id:   short slug used in Neo4j (e.g. 'arvo-1065'); independent of cbm's slug.
      mode:      passed to cbm's index_repository ('full' | 'moderate' | 'fast').
      skip_index: if True, assume cbm is already up to date; skip the (re)index step.
      driver:    optional pre-built Neo4j driver (for tests). If None, one is built
                 from get_settings() and closed at end.
    """
    settings = get_settings()
    repo_root = Path(repo_path).resolve()
    if not repo_root.is_dir():
        raise FileNotFoundError(f"repo_path does not exist or is not a directory: {repo_root}")

    # CyberGym samples (and other tarball-extracted trees) have no .git of their own;
    # `git rev-parse HEAD` then walks up to a parent repo, which is misleading. We treat
    # the supplied `commit` as a label and only WARN if a real local git points elsewhere.
    own_git = (repo_root / ".git").exists()
    head = _git_head(repo_root) if own_git else None
    if head and head != commit:
        import sys
        print(
            f"warning: working tree HEAD={head[:12]} differs from requested "
            f"commit={commit[:12]} — proceeding (commit is used only as a label).",
            file=sys.stderr,
        )

    start = time.monotonic()
    if not skip_index:
        invoke_cbm_index(repo_root, mode=mode)

    slug = cbm_slug(repo_root)
    db = cbm_db_path(slug)
    if not db.is_file():
        raise FileNotFoundError(
            f"cbm SQLite not found after index: {db}. "
            f"(Check `codebase-memory-mcp cli list_projects` for the actual slug.)"
        )

    commit_ts = _git_commit_ts(repo_root, commit) if own_git else None

    own_driver = driver is None
    if driver is None:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=settings.neo4j_auth)
    try:
        with driver.session(database=settings.neo4j_database) as session:
            # 1. RepoCommit pointer (lets the audit MCP slice files server-side later).
            session.run(
                """
                MERGE (r:RepoCommit {repo_id: $repo_id, commit: $commit})
                SET r.abs_repo_root = $abs_repo_root,
                    r.cbm_project   = $cbm_project,
                    r.commit_ts = CASE WHEN $commit_ts IS NULL THEN NULL ELSE datetime($commit_ts) END,
                    r.updated_at = datetime()
                """,
                repo_id=repo_id, commit=commit,
                abs_repo_root=str(repo_root), cbm_project=slug, commit_ts=commit_ts,
            )

            # 2. Stream nodes + edges from cbm.
            nodes_written, embeddings_written, label_counts = _stream_nodes(
                session, db, slug, repo_id, commit,
            )
            edges_written, edge_type_counts = _stream_edges(
                session, db, slug, repo_id, commit,
            )
    finally:
        if own_driver:
            driver.close()

    return IngestResult(
        repo_id=repo_id, commit=commit, commit_ts=commit_ts,
        abs_repo_root=str(repo_root),
        cbm_project=slug, cbm_db=str(db),
        nodes_written=nodes_written,
        edges_written=edges_written,
        embeddings_written=embeddings_written,
        label_counts=label_counts,
        edge_type_counts=edge_type_counts,
        elapsed_s=round(time.monotonic() - start, 2),
    )


# --- streaming helpers ---------------------------------------------------------

def _stream_nodes(
    session, db_path: Path, cbm_project: str, repo_id: str, commit: str,
) -> tuple[int, int, dict[str, int]]:
    """Iterate cbm nodes; flush per-label batches into Neo4j."""
    con = sqlite3.connect(str(db_path))
    # cbm SQLite may contain non-UTF-8 bytes in `properties` JSON for code with
    # exotic source-byte sequences (e.g. minified third-party JS). Replace bad
    # bytes instead of crashing the whole ingest.
    con.text_factory = lambda b: b.decode("utf-8", errors="replace")
    try:
        per_label: dict[str, list[dict]] = defaultdict(list)
        nodes_written = 0
        embeddings_written = 0
        label_counts: dict[str, int] = defaultdict(int)

        rows = con.execute("""
            SELECT n.id, n.label, n.name, n.qualified_name, n.file_path,
                   n.start_line, n.end_line, n.properties, v.vector
            FROM nodes n
            LEFT JOIN node_vectors v ON v.node_id = n.id
            WHERE n.project = ?
            ORDER BY n.id
        """, (cbm_project,))

        for nid, label, name, qn, fp, sl, el, props_json, blob in rows:
            if not SAFE_LABEL_RE.match(label or ""):
                continue  # skip unknown/unsafe labels
            try:
                props = json.loads(props_json) if props_json else {}
            except json.JSONDecodeError:
                props = {}

            emb = decode_embedding(blob) if blob else None
            if emb:
                embeddings_written += 1
            item = {
                "qualified_name": qn,
                "name": name or "",
                "file_path": fp or "",
                "line_start": int(sl or 0),
                "line_end": int(el or 0),
                "signature":     props.get("signature", ""),
                "complexity":    props.get("complexity"),
                "is_entry_point": bool(props.get("is_entry_point", False)),
                "is_test":       bool(props.get("is_test", False)),
                "is_exported":   bool(props.get("is_exported", False)),
                "docstring":     props.get("docstring", "") or "",
                "return_type":   props.get("return_type", "") or "",
                "language":      props.get("language") or _guess_language(fp),
                "embedding":     emb,
            }
            per_label[label].append(item)
            label_counts[label] += 1

            if len(per_label[label]) >= NODE_BATCH:
                nodes_written += _flush_node_batch(session, label, per_label[label], repo_id, commit)
                per_label[label] = []

        for label, items in per_label.items():
            if items:
                nodes_written += _flush_node_batch(session, label, items, repo_id, commit)
    finally:
        con.close()

    return nodes_written, embeddings_written, dict(label_counts)


def _flush_node_batch(session, label: str, items: list[dict], repo_id: str, commit: str) -> int:
    # label is validated by SAFE_LABEL_RE upstream — safe to interpolate.
    cypher = f"""
    UNWIND $batch AS row
    MERGE (n:`{label}` {{qualified_name: row.qualified_name, repo_id: $repo_id, commit: $commit}})
    SET n.name        = row.name,
        n.file_path   = row.file_path,
        n.line_start  = row.line_start,
        n.line_end    = row.line_end,
        n.signature   = row.signature,
        n.language    = row.language,
        n.complexity  = row.complexity,
        n.is_entry_point = row.is_entry_point,
        n.is_test     = row.is_test,
        n.is_exported = row.is_exported,
        n.docstring   = row.docstring,
        n.return_type = row.return_type,
        n.embedding   = row.embedding,
        n.in_scope    = coalesce(n.in_scope, false),
        n.updated_at  = datetime()
    """
    session.run(cypher, batch=items, repo_id=repo_id, commit=commit)
    return len(items)


def _stream_edges(
    session, db_path: Path, cbm_project: str, repo_id: str, commit: str,
) -> tuple[int, dict[str, int]]:
    """Iterate cbm edges; flush batches bucketed by `(src_label, tgt_label, type)`.

    Bucketing lets us include labels in the MATCH so we hit the per-label uniqueness
    constraint's index instead of full-graph scans.
    """
    con = sqlite3.connect(str(db_path))
    # cbm SQLite may contain non-UTF-8 bytes in `properties` JSON for code with
    # exotic source-byte sequences (e.g. minified third-party JS). Replace bad
    # bytes instead of crashing the whole ingest.
    con.text_factory = lambda b: b.decode("utf-8", errors="replace")
    try:
        # (src_label, tgt_label, type) → list of {src, tgt, confidence, source}
        buckets: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
        edge_type_counts: dict[str, int] = defaultdict(int)
        edges_written = 0

        rows = con.execute("""
            SELECT e.id, e.type, e.properties,
                   ns.label, ns.qualified_name,
                   nt.label, nt.qualified_name
            FROM edges e
            JOIN nodes ns ON ns.id = e.source_id
            JOIN nodes nt ON nt.id = e.target_id
            WHERE e.project = ?
            ORDER BY e.id
        """, (cbm_project,))

        for _eid, etype, eprops_json, src_label, src_qn, tgt_label, tgt_qn in rows:
            if not (SAFE_EDGE_RE.match(etype or "")
                    and SAFE_LABEL_RE.match(src_label or "")
                    and SAFE_LABEL_RE.match(tgt_label or "")):
                continue
            try:
                eprops = json.loads(eprops_json) if eprops_json else {}
            except json.JSONDecodeError:
                eprops = {}
            buckets[(src_label, tgt_label, etype)].append({
                "src": src_qn,
                "tgt": tgt_qn,
                "confidence": eprops.get("confidence", "inferred"),
                "source":     eprops.get("source",     "tree-sitter"),
            })
            edge_type_counts[etype] += 1

        for (src_label, tgt_label, etype), batch in buckets.items():
            for chunk in _chunks(batch, EDGE_BATCH):
                edges_written += _flush_edge_chunk(
                    session, src_label, tgt_label, etype, chunk, repo_id, commit,
                )
    finally:
        con.close()

    return edges_written, dict(edge_type_counts)


def _flush_edge_chunk(
    session, src_label: str, tgt_label: str, etype: str, chunk: list[dict],
    repo_id: str, commit: str,
) -> int:
    cypher = f"""
    UNWIND $batch AS row
    MATCH (s:`{src_label}` {{qualified_name: row.src, repo_id: $repo_id, commit: $commit}})
    MATCH (t:`{tgt_label}` {{qualified_name: row.tgt, repo_id: $repo_id, commit: $commit}})
    MERGE (s)-[r:`{etype}`]->(t)
    SET r.confidence = coalesce(r.confidence, row.confidence),
        r.source     = coalesce(r.source,     row.source)
    """
    session.run(cypher, batch=chunk, repo_id=repo_id, commit=commit)
    return len(chunk)


def _chunks(items: list[dict], size: int) -> Iterable[list[dict]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


# --- CLI entrypoint (the proper `whw ingest` verb wraps this) ------------------

def _main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="Drain a cbm-indexed repo into Neo4j.")
    p.add_argument("--repo", required=True, help="Path to source repo (worktree).")
    p.add_argument("--commit", required=True, help="Commit SHA to anchor on.")
    p.add_argument("--repo-id", required=True, help="Short slug used in Neo4j.")
    p.add_argument("--mode", default="full", choices=["full", "moderate", "fast"])
    p.add_argument("--skip-index", action="store_true",
                   help="Assume cbm has already indexed; skip the re-index step.")
    args = p.parse_args()
    result = ingest(args.repo, args.commit, args.repo_id,
                    mode=args.mode, skip_index=args.skip_index)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    _main()
