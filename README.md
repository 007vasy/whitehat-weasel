# White-Hat Weasel (`whw`)

Autonomous AI security-audit harness over a Neo4j code graph.

Given a target repository, commit, scope, call-graph depth, a Docker image with the
language's static analyzers, and a markdown bundle describing the production setup, WHW:

1. **Parses** the code with [`codebase-memory-mcp`][cbm] (155 langs via tree-sitter) and
   pushes the entire graph — nodes, edges, and Nomic 768-dim embeddings — into a
   dedicated **Neo4j** database with native cosine vector indexes.
2. **Marks** the in-scope functions per the scope spec.
3. **Fans out** parallel `claude -p` sub-agents (one per in-scope function, capped
   concurrency + rate limit + retries + an `AGENT_FAILED` sentinel on giveup). Each
   sub-agent gets the function's source slice + a depth-N call-graph context, and
   writes its `:Finding`s through a thin custom MCP server (`whw-mcp`, 15 tools).
4. **Consolidates** the run: suppresses findings that semantically match prior
   false positives (cosine ≥ 0.88), re-triages the rest with a second-pass agent,
   dedupes via embedding cosine (≥ 0.92), and (optionally) extracts production-config
   vulnerabilities from a user-context bundle.
5. **Grades** against held-out [CyberGym][cybergym] samples — localization (hit@file,
   hit@line, IoU, hit@k vs the L3 `patch.diff`) and, as a stretch, PoC crash-reproduction.

References worth reading: [trailofbits/trailmark][trailmark] (scope/annotation model),
[codebase-memory-mcp][cbm] (parser + embeddings), [CyberGym][cybergym] (benchmark).

---

## The happy path

This is the canonical end-to-end workflow. Inputs map 1:1 to the original spec.

```bash
# ─── 0. Bootstrap (one-time) ─────────────────────────────────────────────────
cp .env.example .env                     # edit ANTHROPIC_API_KEY if needed
docker compose up -d whw-neo4j           # Neo4j 5.21 on bolt :7691
uv sync --extra dev                      # Python deps incl. test extras
./scripts/bootstrap_neo4j.sh             # apply schema (10 constraints + 4 vector indexes)

uv run whw doctor --stress               # 8 residuality probes; non-zero exit on FAIL

# ─── 1. Ingest: parse repo + drain into Neo4j ────────────────────────────────
uv run whw ingest \
    --repo cybergym_data/arvo-1065/src-vul \
    --commit vul \
    --repo-id arvo-1065

# ─── 2. Audit: scope + per-function claude -p fan-out + consolidate ──────────
uv run whw audit \
    --repo-id arvo-1065 \
    --commit  vul \
    --scope-file-glob 'file/src/funcs.c' \
    --depth   3 \
    --tools-image whw/c-cpp-statics:latest \
    --eval-commit vul \
    --eval-commit-ts 2017-01-01T00:00:00Z \
    --consolidate                        \
    --out .whw/run.json
# `--consolidate` chains the Cypher passes (FP-suppress → dedup → asset-link) after
# the audit. Re-triage and infra-extraction stay separate (they spawn more agents):

# ─── 3a. Re-triage (optional, billable) ──────────────────────────────────────
uv run whw triage --audit-run $(jq -r .audit.audit_run_id .whw/run.json)

# ─── 3b. Infra pass over a production-setup bundle (optional, billable) ──────
uv run whw infra --audit-run $(jq -r .audit.audit_run_id .whw/run.json) \
                 --user-context docs/prod-runbook.md

# ─── 4. Localization grade vs the CyberGym L3 patch ──────────────────────────
uv run whw eval localize \
    --sample    arvo-1065 \
    --audit-run $(jq -r .audit.audit_run_id .whw/run.json) \
    --out .whw/grade.json

# ─── 5. Multi-sample suite (chains ingest + audit + consolidate + grade) ─────
uv run whw eval suite --samples arvo-1065,arvo-3938 --yes --out .whw/suite.json
```

What that produces, end to end:
- `arvo-1065` Function/File/Module nodes in Neo4j with Nomic embeddings on every Function.
- An `:AuditRun` node + per-Function `:Finding`s for the in-scope set (`file/src/funcs.c` →
  ~22 functions; the known `file_regexec` MSan uninit-pmatch bug is one of them).
- `:Finding-[:DUPLICATE_OF]->:Finding` edges for near-duplicates; `:FalsePositive-[:SUPPRESSES]->:Finding`
  for hits against the prior-FP vector index.
- A grade JSON: `hit_at_file`, `hit_at_line`, `iou_line`, `hit_at_k` for `k ∈ {1,3,5,10}`,
  with the matched Finding ids listed.

The verified-end-to-end smoke (Phase A) is `whw verify`, which targets `arvo-1065`'s
`file_regexec` directly (~$0.20–0.50, ~2.5 min wall clock).

---

## Inputs (mapped to the original spec)

| Spec input | Where it lands | Example |
|---|---|---|
| **Repository** | `whw ingest --repo`, `whw audit --repo-id` | `cybergym_data/arvo-1065/src-vul` + `arvo-1065` |
| **Commit** | `--commit` (any string label; for non-git trees it's just an anchor) | `vul`, `91d5ecb…`, `main@2024-01-15` |
| **Scope** | `whw audit --scope-{entrypoint,function,file-glob,all}` | `--scope-file-glob 'src/**/*.c'` |
| **Call-graph depth** | `--depth 1..5` (clamped) | `--depth 3` |
| **Tools Docker image** | `--tools-image` — sub-agent gets `Bash(docker run *<image>*)` access + an explicit example invocation in the task message | `--tools-image whw/c-cpp-statics:latest` |
| **User context (docs + prod setup)** | `whw infra --user-context PATH` (markdown chunked by `## ` headings) | `--user-context docs/prod.md` |

---

## CLI reference

```
whw doctor [--stress]                                health checks (+ 8 residuality probes)
whw ingest --repo --commit --repo-id                 cbm → Neo4j drain
whw audit --repo-id --commit --scope-* [--consolidate] per-fn claude -p fan-out (+ Cypher consolidate)
whw consolidate --audit-run                          FP-suppress → dedup → asset link (Cypher)
whw triage --audit-run                               one claude -p per open Finding (re-verify)
whw infra --audit-run --user-context PATH            extract production assets + INFRA_* Findings
whw eval localize --sample --audit-run               score vs L3 patch.diff
whw eval suite --samples a,b,c [--yes]               multi-sample ingest+audit+consolidate+grade
whw eval poc                                         (Phase C, not yet implemented)
whw verify                                           end-to-end smoke on arvo-1065
```

### `whw audit` — scope strategies

```bash
# entrypoint, expand by CALLS depth (with same-file fallback for sparse C call graphs)
whw audit --scope-entrypoint 'magic_fuzzer.cc:LLVMFuzzerTestOneInput' --depth 3 ...

# all functions in a path (glob; basename fallback when literal misses)
whw audit --scope-file-glob 'src/**/*.c' ...
whw audit --scope-file-glob 'src/funcs.c' ...        # picked up by basename even if
                                                     # ingested path is file/src/funcs.c

# one exact function (smoke test / surgical audit)
whw audit --scope-function file_regexec ...

# every Function in (repo_id, commit) — be deliberate, this is the whole graph
whw audit --scope-all ...
```

### `whw audit` — eval mode (anti-leakage)

```bash
whw audit --eval-commit <ref> --eval-commit-ts 2017-01-01T00:00:00Z ...
```

Stamps `:AuditRun {mode:'eval', eval_commit_ts: ...}`. Every read tool exposed to
sub-agents filters prior `:Finding`/`:FalsePositive` nodes by
`commit_observed_at < eval_commit_ts`. New findings get
`commit_observed_at = eval_commit_ts` so they don't leak into other runs either.
For non-git CyberGym samples, pass `--eval-commit-ts` explicitly (no `git show -s`
available); pick a date earlier than the sample's fix commit.

### Tools-image contract

When `--tools-image <image>` is supplied:
- The sub-agent's `--allowed-tools` adds `Bash(docker run *<image>*)`.
- Its task message gets a `STATIC ANALYSIS TOOLS` section with:
  - The image name.
  - The host mount path (`abs_repo_root` resolved from `:RepoCommit`).
  - An explicit example invocation: `docker run --rm -v <abs_root>:/src:ro <image> <tool> /src/<file>`.
- The system prompt (`prompts/subagent_system.md`) tells the agent to run the
  relevant statics and paste output into the Finding's `tool_evidence` field.

If `--tools-image` is omitted, the agent stays source-only (Bash is not in its
allowed-tools list and the system prompt instructs it to skip the tool step).

---

## Architecture

```
                                          ┌────────────┐
                                          │  whw-mcp   │
                                          │ (FastMCP   │
                                          │  audit MCP,│   ◀── claude -p sub-agents (N parallel)
                                          │  15 tools) │       per in-scope function
                                          └─────▲──────┘
                                                │
┌─────────┐    ┌──────────┐    ┌──────────────────────┐
│  repo   │──▶ │   cbm    │──▶ │       Neo4j          │
│ + commit│    │ tree-    │    │ code graph + Nomic   │
└─────────┘    │ sitter + │    │ vector indexes       │
               │ Nomic    │    │ (Function/Finding/   │
               │ embeds   │    │  FalsePositive/      │
               └──────────┘    │  ProductionAsset)    │
                               └──────────▲───────────┘
                                          │
                                ┌─────────┴──────────┐
                                │ whw/orchestrator   │  ── direct Cypher for control-plane
                                │ whw/ingest         │     ops (mark in-scope, AuditRun,
                                │ whw/consolidate    │     sentinels, consolidation passes)
                                │ whw/eval           │
                                │ whw/residuality    │
                                └────────────────────┘
```

| Module | Responsibility |
|---|---|
| `whw/ingest.py` | Invoke cbm CLI, open its per-project SQLite, stream nodes + edges + int8→float embeddings into Neo4j with batched MERGE. Idempotent. |
| `whw/orchestrator.py` | Scope resolution, `claude -p` spawn with retry + sentinel, TokenBucket rate limit + ThreadPoolExecutor fan-out, task-message + MCP-config assembly. |
| `whw/consolidate.py` | FP suppression (cosine ≥ 0.88), embedding dedup (≥ 0.92), asset linking (≥ 0.80) via Cypher; re-triage + infra orchestration spawn more sub-agents. |
| `whw/eval/` | CyberGym sample loader, localization grader, multi-sample suite runner. |
| `whw/residuality.py` | 8 probes for `whw doctor --stress`. |
| `whw_mcp/` | Thin FastMCP stdio server; one tool per audit operation, each backed by a single Cypher template under `whw_mcp/cypher/`. Sub-agents see only `mcp__whw__*`. |

Audit MCP tool surface (15):

| Read | Write |
|---|---|
| `find_in_scope` | `register_repo_commit` |
| `get_callgraph_slice` (depth 1–5, inbound/outbound/both) | `mark_in_scope` |
| `get_snippet` (slices source via `:RepoCommit.abs_repo_root`) | `record_audit_run` |
| `list_findings` | `add_finding` (server-embeds summary+rationale via Nomic) |
| `find_similar_findings` (vector search :Finding) | `mark_false_positive` (copies embedding to :FalsePositive) |
| `get_prior_false_positives` (vector search :FalsePositive) | `link_finding_duplicate` (cosine on edge) |
| | `link_finding_to_asset` |
| | `upsert_production_asset` (id = sha256(name‖kind)) |
| | `link_user_doc` (mentions[]) |

---

## Configuration

`.env` (see `.env.example`):

| Var | Default | Notes |
|---|---|---|
| `NEO4J_URI` | `bolt://localhost:7691` | Bolt port. `7687`–`7690` are commonly in use by other Neo4j instances. |
| `NEO4J_USER` / `NEO4J_PASSWORD` | `neo4j` / `whw-dev-password` | Matches `docker-compose.yml`. |
| `ANTHROPIC_API_KEY` | — | Only needed if your `claude` CLI doesn't use subscription auth. |
| `CLAUDE_CODE_BIN` | `claude` | Override if not on PATH. |
| `WHW_EMBEDDING_BACKEND` | `nomic` | `nomic` (≈ 250 MB first-run download) or `noop` (zero vector; vector queries short-circuit; CI default). |
| `WHW_NOMIC_MODEL` | `nomic-ai/nomic-embed-text-v1.5` | Any sentence-transformers model that returns 768-dim. |
| `WHW_MAX_PARALLEL` | `4` | ThreadPoolExecutor cap for audit fan-out. |
| `WHW_PER_AGENT_BUDGET_USD` | `0.50` | (Reserved; not currently enforced.) |
| `WHW_PER_AGENT_TIMEOUT_S` | `600` | Per-sub-agent wall clock (subprocess timeout). |
| `WHW_PER_AGENT_MAX_TURNS` | `25` | `claude -p --max-turns`. |
| `WHW_RATE_PER_MIN` | `8` | Token-bucket rate cap for `claude -p` spawns. |
| `WHW_RUN_DIR` | `.whw` | Where per-run artefacts (mcp.json, agent transcripts, summaries) land. |
| `WHW_WORKTREE_DIR` | `/tmp/whw-worktrees` | (Reserved for future git-worktree-based ingest.) |
| `WHW_CACHE_DIR` | `~/.cache/whw` | (Reserved for upstream cybergym clone in PoC stretch.) |

---

## Tests (3 tiers)

```bash
# Tier 1 — default: unit + integration (live Neo4j on $NEO4J_URI). Fast, no API spend.
uv run pytest -m 'not e2e'

# Tier 2 — opt-in: real Nomic embeddings (downloads ~250 MB model first run).
WHW_RUN_NOMIC=1 uv run pytest tests/test_embeddings_nomic.py

# Tier 3 — opt-in: real claude -p sub-agent on arvo-1065. Billable (~$0.20–0.50).
WHW_RUN_E2E=1 uv run pytest -m e2e
```

Current scoreboard: **116 default-pass** (unit + integration), 3 Nomic opt-in pass, 1
e2e opt-in passes (file_regexec → `UNINIT_MEMORY` + `NOVEL` findings, both intersect
the L3 patch hunks).

---

## Known limitations

- **cbm's C-call resolution is sparse.** On C samples ~96% of `:CALLS` edges originate
  from `:Module` nodes rather than `:Function`. A literal `Function-CALLS-Function`
  traversal from a libFuzzer entrypoint usually returns nothing, so:
  - `--scope-entrypoint` falls back to "all functions in the same file as the seed"
    when expansion finds ≤ 1 callee.
  - `--depth` still mechanically works (proven by `tests/test_callgraph_depth.py` on a
    synthetic A→B→C→D→E chain) but produces sparse slices on real C.
  - Practical alternatives for C: `--scope-file-glob '<patched-file>'` or `--scope-all`.
- **CyberGym L3 patch paths are project-relative** (`src/funcs.c`) while ingested
  `file_path` values include the `src-vul` prefix (`file/src/funcs.c`). The localization
  grader has a basename fallback; `resolve_scope`'s `file_glob` branch does too.
- **No automatic CyberGym dataset download.** Users place samples under `cybergym_data/`
  manually (or download from the HuggingFace `sunblaze-ucb/cybergym` dataset, ~236 GB
  for full mode).
- **Phase C deferred.** PoC generation per Finding + crash-grading via the upstream
  `sunblaze-ucb/cybergym` Docker harness is on the roadmap but not in this PR.

---

## Ports

- `whw-neo4j` bolt: **7691** (HTTP browser intentionally not exposed; bind a free port
  in `docker-compose.yml` if needed).

## Plan + PRs

- Design plan: `~/.claude/plans/create-a-harness-for-shimmering-dijkstra.md` (local).
- Phase A PR: `phase-a-whw-harness` → `main`.
- Phase B PR: `phase-b-consolidation-residuality` → `phase-a-whw-harness`.

[cbm]: https://github.com/007vasy/codebase-memory-mcp
[trailmark]: https://github.com/trailofbits/trailmark
[cybergym]: https://www.cybergym.io/
