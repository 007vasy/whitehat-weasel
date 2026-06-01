"""Unified `whw` CLI. Wires together ingest, orchestrator, eval, and doctor.

Verbs:

    whw doctor                                  — health-check stack
    whw ingest --repo --commit --repo-id        — cbm + Neo4j ingest
    whw audit  --repo-id --commit --scope-* ... — run an audit
    whw eval localize --sample --audit-run      — grade findings vs L3 patch.diff
    whw eval poc      (stretch, not in Phase A)
    whw verify                                  — end-to-end smoke on arvo-1065
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import click
from neo4j import GraphDatabase
from rich.console import Console
from rich.table import Table

from .config import get_settings
from .consolidate import (
    consolidate as run_consolidate,
    consolidate_infra as run_consolidate_infra,
    consolidate_triage as run_consolidate_triage,
)
from .eval.cybergym_loader import find_sample
from .eval.localization import FindingLoc, LocalizationGrade, grade
from .ingest import ingest as run_ingest
from .orchestrator import ScopeSpec, audit as run_audit, _open_driver


console = Console()


@click.group(help="White-Hat Weasel — autonomous AI security-audit harness.")
def cli() -> None:
    pass


# --- doctor -------------------------------------------------------------------

@cli.command()
@click.option("--stress", is_flag=True, help="Also run residuality stressor probes (Phase B).")
def doctor(stress: bool) -> None:
    """Health-check Neo4j, codebase-memory-mcp, claude -p, and Docker."""
    s = get_settings()
    t = Table(title="WHW doctor")
    t.add_column("check"); t.add_column("status"); t.add_column("details")

    # Neo4j connectivity + schema sanity
    try:
        driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
        driver.verify_connectivity()
        with driver.session(database=s.neo4j_database) as session:
            n_constraints = session.run("SHOW CONSTRAINTS YIELD name RETURN count(*) AS c").single()["c"]
            n_vec_indexes = session.run(
                "SHOW INDEXES YIELD type RETURN sum(CASE WHEN type='VECTOR' THEN 1 ELSE 0 END) AS c"
            ).single()["c"]
        driver.close()
        t.add_row("neo4j", "[green]ok[/]", f"{s.neo4j_uri} • {n_constraints} constraints • {n_vec_indexes} vector indexes")
    except Exception as e:
        t.add_row("neo4j", "[red]FAIL[/]", f"{s.neo4j_uri} • {type(e).__name__}: {e}")

    # cbm CLI
    cbm = shutil.which("codebase-memory-mcp")
    if cbm:
        try:
            ver = subprocess.run([cbm, "--version"], capture_output=True, text=True, timeout=10)
            t.add_row("cbm", "[green]ok[/]", f"{cbm} • {ver.stdout.strip() or '(no version)'}")
        except Exception as e:
            t.add_row("cbm", "[yellow]warn[/]", f"{cbm} • probe failed: {e}")
    else:
        t.add_row("cbm", "[red]FAIL[/]", "codebase-memory-mcp not on PATH")

    # claude -p
    cc = shutil.which(s.claude_code_bin)
    if cc:
        t.add_row("claude -p", "[green]ok[/]", cc)
    else:
        t.add_row("claude -p", "[red]FAIL[/]", f"`{s.claude_code_bin}` not on PATH (CLAUDE_CODE_BIN)")

    # Docker
    docker = shutil.which("docker")
    if docker:
        try:
            r = subprocess.run([docker, "info"], capture_output=True, text=True, timeout=10)
            ok = r.returncode == 0
            t.add_row("docker", "[green]ok[/]" if ok else "[yellow]warn[/]",
                      "daemon up" if ok else "daemon not running")
        except Exception as e:
            t.add_row("docker", "[yellow]warn[/]", str(e))
    else:
        t.add_row("docker", "[red]FAIL[/]", "docker not on PATH")

    # WHW dirs
    t.add_row("run_dir", "[green]ok[/]" if s.whw_run_dir.parent.exists() else "[yellow]warn[/]",
              str(s.whw_run_dir.resolve()))

    console.print(t)
    if stress:
        from .residuality import run_all_probes
        console.rule("[bold]residuality probes[/]")
        report = run_all_probes()
        rt = Table()
        rt.add_column("probe"); rt.add_column("status"); rt.add_column("ms",
                                                                       justify="right")
        rt.add_column("detail")
        for p in report.probes:
            color = {"PASS": "green", "FAIL": "red", "SKIP": "yellow"}.get(p.status, "white")
            rt.add_row(p.name, f"[{color}]{p.status}[/]",
                       f"{int(p.elapsed_s * 1000)}", p.detail)
        console.print(rt)
        console.print(
            f"[bold]{report.n_pass} pass · {report.n_fail} fail · {report.n_skip} skip "
            f"({report.elapsed_s}s)[/]"
        )
        if report.n_fail:
            raise SystemExit(1)


# --- ingest -------------------------------------------------------------------

@cli.command()
@click.option("--repo", required=True, type=click.Path(exists=True, file_okay=False, resolve_path=True))
@click.option("--commit", required=True, help="Commit SHA or arbitrary label (for non-git samples).")
@click.option("--repo-id", required=True, help="Short slug used in Neo4j (e.g. arvo-1065).")
@click.option("--mode", type=click.Choice(["full", "moderate", "fast"]), default="full")
@click.option("--skip-index", is_flag=True, help="Assume cbm has already indexed; skip re-index.")
def ingest(repo: str, commit: str, repo_id: str, mode: str, skip_index: bool) -> None:
    """Parse `repo` at `commit` via codebase-memory-mcp; drain everything into Neo4j."""
    result = run_ingest(repo, commit, repo_id, mode=mode, skip_index=skip_index)
    click.echo(json.dumps(result.to_dict(), indent=2))


# --- audit --------------------------------------------------------------------

@cli.command()
@click.option("--repo-id", required=True)
@click.option("--commit", required=True)
@click.option("--scope-entrypoint", help="QN or '<file>:<symbol>' to expand by CALLS depth.")
@click.option("--scope-function", help="Mark exactly one Function by .name.")
@click.option("--scope-file-glob", help="Glob over Function.file_path (e.g. 'src/**/*.c').")
@click.option("--scope-all", is_flag=True, help="Audit every Function in (repo_id, commit).")
@click.option("--depth", type=click.IntRange(1, 5), default=3)
@click.option("--eval-commit", help="Anchor for anti-leakage time filter.")
@click.option("--eval-commit-ts", help="ISO-8601 timestamp; required when --eval-commit is set "
                                       "for non-git samples (cybergym).")
@click.option("--tools-image", help="Docker image with statics for the language.")
@click.option("--model", default="sonnet")
@click.option("--out", type=click.Path(), help="Write run.json summary here in addition to .whw/")
@click.option("--consolidate", "with_consolidate", is_flag=True,
              help="After the audit completes, chain `whw consolidate` (FP suppress + "
                   "dedup + asset link). Matches the original spec's 'Then run "
                   "consolidation' step. Triage + infra remain separate verbs.")
def audit(repo_id: str, commit: str, scope_entrypoint: str | None,
          scope_function: str | None, scope_file_glob: str | None,
          scope_all: bool, depth: int,
          eval_commit: str | None, eval_commit_ts: str | None,
          tools_image: str | None, model: str, out: str | None,
          with_consolidate: bool) -> None:
    """Resolve scope, fan out claude -p sub-agents (parallel + retries + sentinels in
    Phase B), write Findings, and optionally run the Cypher consolidation passes."""
    chosen = sum(bool(x) for x in [scope_entrypoint, scope_function, scope_file_glob, scope_all])
    if chosen != 1:
        raise click.UsageError(
            "Pick exactly one of --scope-entrypoint / --scope-function / "
            "--scope-file-glob / --scope-all."
        )
    if eval_commit and not eval_commit_ts:
        raise click.UsageError(
            "--eval-commit-ts (ISO-8601) is required with --eval-commit for non-git samples."
        )

    scope = ScopeSpec(
        entrypoint=scope_entrypoint, entrypoint_depth=depth,
        function=scope_function, file_glob=scope_file_glob, all=scope_all,
    )
    result = run_audit(
        repo_id=repo_id, commit=commit, scope=scope,
        eval_commit=eval_commit, eval_commit_ts=eval_commit_ts,
        tools_image=tools_image, model=model,
    )
    payload = {"audit": result.to_dict()}
    if with_consolidate:
        cons = run_consolidate(result.audit_run_id)
        payload["consolidate"] = cons.to_dict()
    text = json.dumps(payload, indent=2)
    click.echo(text)
    if out:
        Path(out).write_text(text)


# --- consolidate -------------------------------------------------------------

@cli.command()
@click.option("--audit-run", "audit_run", required=True, help="AuditRun.id to consolidate.")
@click.option("--skip-fp-suppress", is_flag=True, help="Don't run the FP-suppression pass.")
@click.option("--skip-dedup",       is_flag=True, help="Don't run the embedding-dedup pass.")
@click.option("--skip-asset-link",  is_flag=True, help="Don't link findings to production assets.")
@click.option("--fp-threshold",     type=click.FloatRange(-1.0, 1.0), default=0.88,
              show_default=True, help="Cosine threshold for FP suppression.")
@click.option("--dedup-threshold",  type=click.FloatRange(-1.0, 1.0), default=0.92,
              show_default=True, help="Cosine threshold for marking duplicates.")
@click.option("--asset-link-threshold", type=click.FloatRange(-1.0, 1.0), default=0.80,
              show_default=True, help="Cosine threshold for Finding↔Asset linking.")
def consolidate(audit_run: str, skip_fp_suppress: bool, skip_dedup: bool,
                skip_asset_link: bool, fp_threshold: float, dedup_threshold: float,
                asset_link_threshold: float) -> None:
    """Run the Cypher consolidation passes: FP suppression → dedup → asset linking.

    Sub-agent passes (re-triage, infra-extraction) are separate verbs: `whw triage`
    and `whw infra`. They spawn billable `claude -p` runs and are opt-in.
    """
    result = run_consolidate(
        audit_run,
        skip_fp_suppress=skip_fp_suppress,
        skip_dedup=skip_dedup,
        skip_asset_link=skip_asset_link,
        fp_threshold=fp_threshold,
        dedup_threshold=dedup_threshold,
        asset_link_threshold=asset_link_threshold,
    )
    click.echo(json.dumps(result.to_dict(), indent=2))


@cli.command()
@click.option("--audit-run", "audit_run", required=True)
@click.option("--max-parallel", type=click.IntRange(1, 16), default=None,
              help="Override the per-run triage concurrency cap (default 2).")
@click.option("--max-findings", type=click.IntRange(1, 10_000), default=None,
              help="Stop after this many findings (cost guard).")
def triage(audit_run: str, max_parallel: int | None, max_findings: int | None) -> None:
    """Re-triage every open Finding via a `claude -p` agent.

    Spawns BILLABLE sub-agents. Each agent concludes confirm | refute | refine; the
    orchestrator promotes 'confirm' Findings to status='verified' after the agent exits.
    """
    res = run_consolidate_triage(
        audit_run, max_parallel=max_parallel, max_findings=max_findings,
    )
    click.echo(json.dumps(res.to_dict(), indent=2))


@cli.command()
@click.option("--audit-run", "audit_run", required=True)
@click.option("--user-context", "user_context", required=True,
              type=click.Path(exists=True, dir_okay=False, resolve_path=True),
              help="Path to the production-context markdown bundle.")
@click.option("--no-link-pass", is_flag=True,
              help="Skip the Cypher pass that links open code Findings to assets.")
@click.option("--asset-link-threshold", type=click.FloatRange(-1.0, 1.0), default=0.80,
              show_default=True)
def infra(audit_run: str, user_context: str, no_link_pass: bool,
          asset_link_threshold: float) -> None:
    """Extract production assets + infra/config Findings from a context bundle.

    Spawns ONE billable `claude -p`. After it exits, the orchestrator optionally runs
    the Cypher pass that links open code-level Findings to extracted assets by cosine.
    """
    res = run_consolidate_infra(
        audit_run, user_context_path=user_context,
        also_link=not no_link_pass, asset_link_threshold=asset_link_threshold,
    )
    click.echo(json.dumps(res.to_dict(), indent=2))


# --- eval ---------------------------------------------------------------------

@cli.group()
def eval() -> None:
    """Benchmark verbs."""
    pass


@eval.command("localize")
@click.option("--sample", required=True, help="CyberGym sample id (e.g. arvo-1065).")
@click.option("--audit-run", "audit_run", required=True, help="AuditRun.id to grade.")
@click.option("--data-root", type=click.Path(exists=True, file_okay=False, resolve_path=True),
              default="cybergym_data", show_default=True)
@click.option("--out", type=click.Path(), help="Write grade JSON to this path.")
def eval_localize(sample: str, audit_run: str, data_root: str, out: str | None) -> None:
    """Score a run's Findings against the L3 patch.diff for `sample`."""
    cg = find_sample(sample, Path(data_root))
    if not cg.patch_hunks:
        raise click.ClickException(f"sample {sample!r} has no L3 patch.diff hunks — cannot grade.")

    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    try:
        with driver.session(database=s.neo4j_database) as session:
            # Match the suite grader exactly: open/verified only (skip duplicates,
            # suppressed, FPs) and skip orchestrator-written sentinels. This makes
            # `whw eval localize` consistent with `whw eval suite`.
            rows = list(session.run("""
                MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding)
                WHERE n.status IN ['open', 'verified']
                  AND NOT n.vuln_class IN ['AGENT_FAILED', 'INDEX_PARTIAL']
                  AND NOT n.source = 'orchestrator'
                RETURN n.id AS id, n.file_path AS fp, n.line_start AS ls,
                       n.line_end AS le, n.severity AS sev, n.confidence AS conf
            """, rid=audit_run))
    finally:
        driver.close()

    findings = [
        FindingLoc(
            id=r["id"] or "",
            file_path=r["fp"] or "",
            line_start=int(r["ls"] or 0),
            line_end=int(r["le"] or 0),
            severity=r["sev"] or "med",
            confidence=r["conf"] or "inferred",
        )
        for r in rows
        if r["fp"]
    ]
    g: LocalizationGrade = grade(findings, cg.patch_hunks, sample_id=sample, audit_run_id=audit_run)
    text = json.dumps(g.to_dict(), indent=2)
    click.echo(text)
    if out:
        Path(out).write_text(text)


@eval.command("poc")
def eval_poc() -> None:
    """(Stretch) Drive the upstream sunblaze-ucb/cybergym PoC grader. Phase C."""
    raise click.ClickException("PoC grading is Phase C — not yet implemented.")


@eval.command("suite")
@click.option("--samples", required=True,
              help="Comma-separated CyberGym sample ids, e.g. arvo-1065,arvo-368,arvo-3938.")
@click.option("--data-root", type=click.Path(exists=True, file_okay=False, resolve_path=True),
              default="cybergym_data", show_default=True)
@click.option("--out", type=click.Path(), help="Write the suite report JSON here.")
@click.option("--skip-ingest", is_flag=True, help="Assume samples are already ingested.")
@click.option("--skip-consolidate", is_flag=True, help="Run audit + grade only.")
@click.option("--depth", type=click.IntRange(1, 5), default=3, show_default=True)
@click.option("--model", default="sonnet", show_default=True)
@click.option("--tools-image")
@click.option("--yes", is_flag=True,
              help="Skip the API-cost confirmation prompt (for unattended runs).")
def eval_suite(samples: str, data_root: str, out: str | None,
               skip_ingest: bool, skip_consolidate: bool,
               depth: int, model: str, tools_image: str | None, yes: bool) -> None:
    """Run ingest+audit+consolidate+localize per sample and aggregate the grades.

    BILLABLE: each sample spawns one or more `claude -p` sub-agents (~$0.20-1.00 each
    depending on the patched-file size). Confirm before running unattended.
    """
    from .eval.suite import run_suite

    sample_list = [s.strip() for s in samples.split(",") if s.strip()]
    if not sample_list:
        raise click.UsageError("--samples must contain at least one id")

    if not yes:
        click.echo(f"about to run {len(sample_list)} samples × claude -p — confirm to proceed.")
        click.confirm(f"Run suite on {sample_list}?", abort=True)

    report = run_suite(
        sample_list, data_root=Path(data_root),
        skip_ingest=skip_ingest, skip_consolidate=skip_consolidate,
        depth=depth, model=model, tools_image=tools_image,
    )
    payload = json.dumps(report.to_dict(), indent=2)
    click.echo(payload)
    if out:
        Path(out).write_text(payload)


# --- verify -------------------------------------------------------------------

@cli.command()
@click.option("--sample", default="arvo-1065", show_default=True)
@click.option("--scope-function", default="file_regexec", show_default=True,
              help="Narrow scope used for the smoke test.")
@click.option("--commit-label", default="vul", show_default=True)
@click.option("--data-root", type=click.Path(exists=True, file_okay=False, resolve_path=True),
              default="cybergym_data", show_default=True)
def verify(sample: str, scope_function: str, commit_label: str, data_root: str) -> None:
    """End-to-end Phase A smoke: ingest a CyberGym sample, audit one function, grade.

    Spawns one real `claude -p` sub-agent. Costs a small number of tokens.
    """
    data_root_p = Path(data_root)
    sample_dir = data_root_p / sample / "src-vul"
    if not sample_dir.is_dir():
        raise click.ClickException(f"Sample tree not found at {sample_dir}")

    console.rule(f"[bold]whw verify[/] · {sample} · {scope_function}")
    console.print(f"[dim]Step 1/3 — ingest {sample_dir}[/]")
    ingest_res = run_ingest(str(sample_dir), commit_label, sample, skip_index=False)
    console.print(json.dumps(ingest_res.to_dict(), indent=2))

    console.print(f"\n[dim]Step 2/3 — audit (scope: function='{scope_function}')[/]")
    audit_res = run_audit(
        repo_id=sample, commit=commit_label,
        scope=ScopeSpec(function=scope_function),
        eval_commit=commit_label,
        eval_commit_ts="2017-01-01T00:00:00Z",   # arvo-1065 fix landed 2017-04; this hides L3 leakage
        model="sonnet",
    )
    console.print(json.dumps(audit_res.to_dict(), indent=2))

    console.print("\n[dim]Step 3/3 — localization grade[/]")
    cg = find_sample(sample, data_root_p)
    driver = _open_driver()
    try:
        with driver.session(database=get_settings().neo4j_database) as session:
            rows = list(session.run("""
                MATCH (run:AuditRun {id:$rid})-[:FOUND]->(n:Finding)
                RETURN n.id AS id, n.file_path AS fp, n.line_start AS ls,
                       n.line_end AS le, n.severity AS sev, n.confidence AS conf
            """, rid=audit_res.audit_run_id))
    finally:
        driver.close()

    findings = [
        FindingLoc(
            id=r["id"] or "", file_path=r["fp"] or "",
            line_start=int(r["ls"] or 0), line_end=int(r["le"] or 0),
            severity=r["sev"] or "med", confidence=r["conf"] or "inferred",
        )
        for r in rows if r["fp"]
    ]
    g = grade(findings, cg.patch_hunks, sample_id=sample, audit_run_id=audit_res.audit_run_id)
    console.print(json.dumps(g.to_dict(), indent=2))

    console.rule("[bold]done[/]")
    status = "[green]PASS[/]" if (g.hit_at_line or g.hit_at_file) else "[red]MISS[/]"
    console.print(f"{status} — hit@file={g.hit_at_file} hit@line={g.hit_at_line} "
                  f"iou_line={g.iou_line:.3f} top-5_hit={g.hit_at_k.get(5)}")


# --- entry --------------------------------------------------------------------

if __name__ == "__main__":
    cli()
