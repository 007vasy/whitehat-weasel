"""4-pass consolidation pipeline (Phase B).

Pass 1 — FP suppression (Cypher)
   For each open Finding in the run, vector-query the FalsePositive embedding index.
   If the best match has cosine >= 0.88, flip the Finding to status='suppressed' and
   add (FalsePositive)-[:SUPPRESSES]->(Finding). Eval-mode-aware: FPs observed at or
   after the run's eval_commit_ts are hidden so held-out benchmarks stay sealed.

Pass 2 — Re-triage (MCP/agent)
   Implemented in `consolidate_triage()` (one `claude -p` per remaining open Finding,
   concurrency-capped at 2). Returns confirm | refute | refine outcomes. Reuses the
   orchestrator's spawn machinery via a triage-prompt variant.

Pass 3 — Dedup (Cypher)
   For each remaining open Finding, vector-query the Finding embedding index for
   semantic near-duplicates already in the audit graph. If best other match has
   cosine >= 0.92, mark this Finding duplicate-of the older canonical.

Pass 4 — Infra link (Cypher)
   For each ProductionAsset registered for this run, vector-match open Findings
   above cosine 0.80; create :AFFECTS_ASSET edges. (Pass 4's per-bundle extraction
   of new assets/infra-findings is in `consolidate_infra()` and uses a sub-agent.)

The Python loops are thin drivers; the per-pass logic is one or two MATCH/CALL
Cypher statements. Counts are returned so callers can chain results into reports.
"""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from neo4j import Driver, GraphDatabase

from .config import get_settings


@dataclass
class ConsolidateResult:
    audit_run_id: str
    # Pass 1
    n_suppressed: int = 0
    # Pass 3
    n_duplicates: int = 0
    # Pass 4 (linking only — extraction is consolidate_infra())
    n_asset_links: int = 0
    # Bookkeeping
    n_open_at_start: int = 0
    n_open_at_end: int = 0
    elapsed_s: float = 0.0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def consolidate(
    audit_run_id: str,
    *,
    skip_fp_suppress: bool = False,
    skip_dedup: bool = False,
    skip_asset_link: bool = False,
    fp_threshold: float = 0.88,
    dedup_threshold: float = 0.92,
    asset_link_threshold: float = 0.80,
    driver: Driver | None = None,
) -> ConsolidateResult:
    """Run the Cypher-only consolidation passes (1, 3, and the 4-link sub-pass).

    Re-triage (pass 2) and infra-extraction (pass 4 first half) spawn sub-agents and
    live in `consolidate_triage()` / `consolidate_infra()`.
    """
    s = get_settings()
    own_driver = driver is None
    if driver is None:
        driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)

    result = ConsolidateResult(audit_run_id=audit_run_id)
    started = time.monotonic()
    try:
        result.n_open_at_start = _count_open(driver, audit_run_id)
        if not skip_fp_suppress:
            result.n_suppressed = _pass_fp_suppress(driver, audit_run_id, fp_threshold)
        if not skip_dedup:
            result.n_duplicates = _pass_dedup(driver, audit_run_id, dedup_threshold)
        if not skip_asset_link:
            result.n_asset_links = _pass_link_findings_to_assets(
                driver, audit_run_id, asset_link_threshold,
            )
        result.n_open_at_end = _count_open(driver, audit_run_id)
    finally:
        if own_driver:
            driver.close()

    result.elapsed_s = round(time.monotonic() - started, 2)
    return result


# ---------- pass 1: FP suppression -------------------------------------------

def _pass_fp_suppress(driver: Driver, audit_run_id: str, threshold: float) -> int:
    """Suppress open Findings whose embedding cosine-matches a prior FalsePositive.

    Implemented as one read (find suppressable candidates with their best FP match)
    plus one write per suppression. Avoids APOC; works on stock Neo4j 5.
    """
    s = get_settings()
    n_suppressed = 0
    with driver.session(database=s.neo4j_database) as session:
        candidates = list(session.run("""
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {status:'open'})
            WHERE n.embedding IS NOT NULL
              AND any(x IN n.embedding WHERE x <> 0.0)
            RETURN n.id AS id, n.embedding AS emb,
                   toString(run.eval_commit_ts) AS eval_ts
        """, rid=audit_run_id))

        for row in candidates:
            best = session.run("""
                CALL db.index.vector.queryNodes('fp_embedding', 5, $emb) YIELD node AS fp, score
                WHERE score >= $threshold
                  AND ($eval_ts IS NULL OR fp.commit_observed_at < datetime($eval_ts))
                WITH fp, score ORDER BY score DESC LIMIT 1
                RETURN fp.id AS fp_id, score AS cosine
            """, emb=row["emb"], threshold=threshold, eval_ts=row["eval_ts"]).single()
            if not best:
                continue
            session.run("""
                MATCH (n:Finding {id:$nid})
                MATCH (fp:FalsePositive {id:$fid})
                MERGE (fp)-[r:SUPPRESSES]->(n)
                SET r.cosine     = $cosine,
                    n.status     = 'suppressed',
                    n.updated_at = datetime()
            """, nid=row["id"], fid=best["fp_id"], cosine=best["cosine"])
            n_suppressed += 1
    return n_suppressed


# ---------- pass 3: dedup via vector index -----------------------------------

def _pass_dedup(driver: Driver, audit_run_id: str, threshold: float) -> int:
    """Mark open Findings as :DUPLICATE_OF an older canonical when cosine >= threshold.

    Iterates NEWEST-first. Each newer Finding looks for an older open canonical and
    marks itself the duplicate. By the time the loop reaches older Findings, their
    newer near-duplicates already have status='duplicate' and the inner query filters
    them out — so older Findings stay 'open' and remain canonical for their cluster.
    """
    s = get_settings()
    n_duplicates = 0
    with driver.session(database=s.neo4j_database) as session:
        candidates = list(session.run("""
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {status:'open'})
            WHERE n.embedding IS NOT NULL
              AND any(x IN n.embedding WHERE x <> 0.0)
            RETURN n.id AS id, n.embedding AS emb, n.created_at AS created_at
            ORDER BY n.created_at DESC, n.id DESC
        """, rid=audit_run_id))

        for row in candidates:
            best = session.run("""
                CALL db.index.vector.queryNodes('finding_embedding', 6, $emb) YIELD node AS m, score
                WHERE m.id <> $nid
                  AND score >= $threshold
                  AND m.status IN ['open', 'verified']
                WITH m, score ORDER BY score DESC, m.created_at ASC LIMIT 1
                RETURN m.id AS canonical_id, score AS cosine
            """, emb=row["emb"], nid=row["id"], threshold=threshold).single()
            if not best:
                continue
            session.run("""
                MATCH (a:Finding {id:$a})
                MATCH (b:Finding {id:$b})
                WHERE a.id <> b.id
                MERGE (a)-[:DUPLICATE_OF]->(b)
                MERGE (a)-[r:SIMILAR_TO]->(b)
                SET r.cosine     = $cos,
                    a.status     = 'duplicate',
                    a.dedup_of   = $b,
                    a.updated_at = datetime()
            """, a=row["id"], b=best["canonical_id"], cos=best["cosine"])
            n_duplicates += 1
    return n_duplicates


# ---------- pass 4 (Cypher half): link findings to production assets ---------

def _pass_link_findings_to_assets(driver: Driver, audit_run_id: str, threshold: float) -> int:
    """For each open Finding, vector-query ProductionAsset embeddings and create
    :AFFECTS_ASSET edges to those above `threshold` cosine. Idempotent via MERGE.
    """
    s = get_settings()
    n_links = 0
    with driver.session(database=s.neo4j_database) as session:
        # Bail if there are no assets at all — saves one vector query per finding.
        n_assets = session.run("MATCH (a:ProductionAsset) RETURN count(a) AS c").single()["c"]
        if n_assets == 0:
            return 0

        candidates = list(session.run("""
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {status:'open'})
            WHERE n.embedding IS NOT NULL
              AND any(x IN n.embedding WHERE x <> 0.0)
            RETURN n.id AS id, n.embedding AS emb
        """, rid=audit_run_id))

        for row in candidates:
            matches = session.run("""
                CALL db.index.vector.queryNodes('productionasset_embedding', 5, $emb)
                YIELD node AS a, score
                WHERE score >= $threshold
                RETURN a.id AS asset_id, score AS cosine
            """, emb=row["emb"], threshold=threshold)
            for m in matches:
                session.run("""
                    MATCH (n:Finding {id:$nid})
                    MATCH (a:ProductionAsset {id:$aid})
                    MERGE (n)-[r:AFFECTS_ASSET]->(a)
                    SET r.cosine = coalesce(r.cosine, $cos)
                """, nid=row["id"], aid=m["asset_id"], cos=m["cosine"])
                n_links += 1
    return n_links


# ---------- pass 2: re-triage (sub-agents) -----------------------------------

@dataclass
class TriageBatchResult:
    audit_run_id: str
    n_open_at_start: int = 0
    n_confirm: int = 0
    n_refute: int = 0
    n_refine: int = 0
    n_failed: int = 0
    elapsed_s: float = 0.0
    agents: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def consolidate_triage(
    audit_run_id: str,
    *,
    max_parallel: int | None = None,
    max_findings: int | None = None,
    driver: Driver | None = None,
) -> TriageBatchResult:
    """Spawn one `claude -p` per remaining open Finding using prompts/triage_system.md.

    The agent concludes confirm | refute | refine and calls the appropriate write tool.
    After it exits, Findings still in status='open' are promoted to 'verified'
    (interpreted as "the triage agent looked, found nothing to refute or refine").

    Concurrency capped at `max_parallel` (default 2 — triage is lighter than audit and
    we want to keep `claude -p` rate-limit headroom for any concurrent audit work).
    """
    # Local import keeps consolidate.py importable without orchestrator's heavier deps.
    from .orchestrator import (
        TokenBucket, _spawn_triage_attempt, mark_finding_verified, write_mcp_config,
    )

    s = get_settings()
    parallel = max_parallel if max_parallel is not None else max(1, min(2, s.whw_max_parallel))
    own_driver = driver is None
    if driver is None:
        driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)

    started = time.monotonic()
    result = TriageBatchResult(audit_run_id=audit_run_id)
    try:
        # 1. Locate the run + its repo worktree so we can pre-slice source snippets.
        with driver.session(database=s.neo4j_database) as session:
            run_row = session.run("""
                MATCH (run:AuditRun {id:$rid})
                OPTIONAL MATCH (rc:RepoCommit {repo_id: run.repo_id, commit: run.commit})
                RETURN run.repo_id AS repo_id, run.commit AS commit,
                       rc.abs_repo_root AS abs_repo_root
            """, rid=audit_run_id).single()
        if run_row is None:
            raise RuntimeError(f"AuditRun {audit_run_id!r} not found")
        abs_repo_root = Path(run_row["abs_repo_root"]) if run_row["abs_repo_root"] else None

        # 2. Collect open findings to triage.
        with driver.session(database=s.neo4j_database) as session:
            rows = list(session.run("""
                MATCH (:AuditRun {id:$rid})-[:FOUND]->(n:Finding {status:'open'})
                RETURN n.id AS id, n.vuln_class AS vuln_class, n.severity AS severity,
                       n.confidence AS confidence, n.summary AS summary,
                       n.rationale AS rationale, n.function_qn AS function_qn,
                       n.file_path AS file_path, n.line_start AS line_start,
                       n.line_end AS line_end, n.source AS source
                ORDER BY n.created_at ASC
            """, rid=audit_run_id))
        findings = [dict(r) for r in rows]
        if max_findings is not None:
            findings = findings[:max_findings]
        result.n_open_at_start = len(findings)
        if not findings:
            return result

        # 3. Per-run MCP config + prompt path.
        run_dir = s.whw_run_dir / f"run-{audit_run_id}"
        mcp_config_path = run_dir / "mcp.json"
        if not mcp_config_path.exists():
            write_mcp_config(mcp_config_path, env={
                "NEO4J_URI": s.neo4j_uri,
                "NEO4J_USER": s.neo4j_user,
                "NEO4J_PASSWORD": s.neo4j_password,
                "NEO4J_DATABASE": s.neo4j_database,
                "WHW_EMBEDDING_BACKEND": s.whw_embedding_backend,
                "WHW_NOMIC_MODEL": s.whw_nomic_model,
                "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", s.anthropic_api_key),
            })
        sys_prompt_path = Path(__file__).resolve().parent / "prompts" / "triage_system.md"
        rate_limiter = TokenBucket(s.whw_rate_per_min) if s.whw_rate_per_min > 0 else None

        def _run(finding: dict):
            if rate_limiter is not None:
                rate_limiter.acquire()
            return _spawn_triage_attempt(
                finding=finding, audit_run_id=audit_run_id,
                mcp_config_path=mcp_config_path, system_prompt_path=sys_prompt_path,
                run_dir=run_dir, driver=driver, abs_repo_root=abs_repo_root,
            )

        # 4. Fan out (capped) and tally.
        if parallel <= 1 or len(findings) <= 1:
            triage_results = [_run(f) for f in findings]
        else:
            with ThreadPoolExecutor(max_workers=parallel) as pool:
                futs = {pool.submit(_run, f): f for f in findings}
                triage_results = [fut.result() for fut in as_completed(futs)]

        for tr in triage_results:
            result.agents.append(asdict(tr))
            if tr.exit_code != 0 or tr.conclusion == "failed":
                result.n_failed += 1
                continue
            if tr.conclusion == "refute":
                result.n_refute += 1
            elif tr.conclusion == "refine":
                result.n_refine += 1
            elif tr.conclusion == "confirm":
                mark_finding_verified(driver, tr.finding_id)
                result.n_confirm += 1
            else:
                result.warnings.append(
                    f"finding {tr.finding_id}: unknown conclusion {tr.conclusion!r} "
                    f"(final_status={tr.final_status!r})"
                )
    finally:
        if own_driver:
            driver.close()

    result.elapsed_s = round(time.monotonic() - started, 2)
    return result


# ---------- pass 4 (sub-agent half): infra-context extraction ----------------

@dataclass
class InfraConsolidateResult:
    audit_run_id: str
    bundle_path: str
    exit_code: int = 0
    elapsed_s: float = 0.0
    n_assets_added: int = 0
    n_findings_added: int = 0
    n_asset_links: int = 0
    stdout_path: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def consolidate_infra(
    audit_run_id: str,
    user_context_path: str | Path,
    *,
    driver: Driver | None = None,
    also_link: bool = True,
    asset_link_threshold: float = 0.80,
) -> InfraConsolidateResult:
    """Spawn ONE `claude -p` infra-context sub-agent over `user_context_path`.

    The agent reads the markdown bundle, upserts ProductionAssets, files INFRA_* Findings,
    and links Findings to assets. After it exits we optionally run the Cypher-only
    asset-link pass (`_pass_link_findings_to_assets`) to catch code-level Findings that
    the agent itself didn't link.
    """
    from .orchestrator import _spawn_infra_attempt, write_mcp_config

    s = get_settings()
    bundle_path = Path(user_context_path).resolve()
    if not bundle_path.is_file():
        raise FileNotFoundError(f"user-context bundle not found: {bundle_path}")

    own_driver = driver is None
    if driver is None:
        driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)

    try:
        with driver.session(database=s.neo4j_database) as session:
            run_row = session.run(
                "MATCH (run:AuditRun {id:$rid}) RETURN run.repo_id AS r, run.commit AS c",
                rid=audit_run_id,
            ).single()
        if run_row is None:
            raise RuntimeError(f"AuditRun {audit_run_id!r} not found")
        repo_id, commit = run_row["r"], run_row["c"]

        run_dir = s.whw_run_dir / f"run-{audit_run_id}"
        mcp_config_path = run_dir / "mcp.json"
        if not mcp_config_path.exists():
            write_mcp_config(mcp_config_path, env={
                "NEO4J_URI": s.neo4j_uri,
                "NEO4J_USER": s.neo4j_user,
                "NEO4J_PASSWORD": s.neo4j_password,
                "NEO4J_DATABASE": s.neo4j_database,
                "WHW_EMBEDDING_BACKEND": s.whw_embedding_backend,
                "WHW_NOMIC_MODEL": s.whw_nomic_model,
                "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", s.anthropic_api_key),
            })
        sys_prompt_path = Path(__file__).resolve().parent / "prompts" / "infra_vuln_system.md"

        infra = _spawn_infra_attempt(
            audit_run_id=audit_run_id, repo_id=repo_id, commit=commit,
            bundle_path=bundle_path,
            mcp_config_path=mcp_config_path, system_prompt_path=sys_prompt_path,
            run_dir=run_dir, driver=driver,
        )

        n_link_added = 0
        if also_link and infra.exit_code == 0:
            n_link_added = _pass_link_findings_to_assets(
                driver, audit_run_id, asset_link_threshold,
            )

        return InfraConsolidateResult(
            audit_run_id=audit_run_id, bundle_path=str(bundle_path),
            exit_code=infra.exit_code, elapsed_s=infra.elapsed_s,
            n_assets_added=infra.n_assets_added,
            n_findings_added=infra.n_findings_added,
            n_asset_links=infra.n_asset_links + n_link_added,
            stdout_path=infra.stdout_path, error=infra.error,
        )
    finally:
        if own_driver:
            driver.close()


# ---------- helpers ----------------------------------------------------------

def _count_open(driver: Driver, audit_run_id: str) -> int:
    s = get_settings()
    with driver.session(database=s.neo4j_database) as session:
        r = session.run("""
            MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding {status:'open'})
            RETURN count(n) AS c
        """, rid=audit_run_id).single()
    return int(r["c"]) if r else 0
