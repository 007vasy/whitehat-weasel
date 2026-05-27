# White-Hat Weasel (`whw`)

Autonomous AI security-audit harness. Given a repository, commit, scope, call-graph depth,
a Docker image with the language's static tools, and a user-context bundle, WHW parses the
code (via [codebase-memory-mcp][cbm]), pushes the graph + Nomic embeddings into Neo4j,
marks in-scope functions, fans out parallel `claude -p` sub-agents that hunt for known +
novel vulnerabilities, consolidates findings against prior false positives via semantic
similarity, and benchmarks itself against held-out [CyberGym][cybergym] samples.

References: [trailofbits/trailmark][trailmark] (scope/annotation model), [codebase-memory-mcp][cbm]
(parsing + embeddings), [CyberGym][cybergym] (benchmark).

## Quickstart

```bash
# 0. Bootstrap
cp .env.example .env                                        # edit ANTHROPIC_API_KEY
docker compose up -d whw-neo4j                              # bolt :7691
uv sync
scripts/bootstrap_neo4j.sh                                  # applies whw/neo4j_schema.cypher
uv run whw doctor                                           # confirms neo4j / cbm / claude -p / docker

# 1. Ingest a target repo at a commit (parses via cbm, drains into Neo4j)
uv run whw ingest --repo <path> --commit <ref> --repo-id <slug>

# 2. Audit. Scope = entrypoint(s), depth = call-graph radius the sub-agent sees.
uv run whw audit \
    --repo-id <slug> --commit <ref> \
    --scope-entrypoint '<file>:<symbol>' \
    --depth 3 \
    --tools-image whw/c-cpp-statics:latest \
    --user-context-bundle path/to/prod.md \
    --out .whw/run.json

# 3. Consolidate (FP-suppress → triage → dedupe → infra-pass)
uv run whw consolidate --audit-run <run_id>

# 4. Localization grade against a CyberGym L3 patch
uv run whw eval localize \
    --sample arvo-1065 --audit-run <run_id> \
    --patch cybergym_data/arvo-1065-l3/patch.diff
```

## CLI verbs

| Verb | Purpose |
|---|---|
| `whw ingest` | Parse a `(repo, commit)` with cbm and drain everything (nodes, edges, embeddings) into Neo4j. |
| `whw audit` | Mark in-scope functions, fan out per-function `claude -p` sub-agents, write Findings via the audit MCP. |
| `whw consolidate` | FP-suppress → re-triage → embedding-dedup → production-context infra pass. |
| `whw eval localize` | Score Findings against a CyberGym L3 `patch.diff` (hit@file/line, IoU, hit@k). |
| `whw eval poc` | (Stretch) Drive the upstream `sunblaze-ucb/cybergym` PoC grader. |
| `whw doctor` | Health-check Neo4j / cbm / `claude -p` / Docker. `--stress` runs residuality probes. |
| `whw verify` | End-to-end sanity run on `arvo-1065`. |

## Eval mode (anti-leakage)

`whw audit --eval-commit <ref>` stamps the run with `mode='eval'` and a resolved timestamp.
Every read tool exposed to sub-agents filters prior `Finding`/`FalsePositive` nodes by
`commit_observed_at < eval_commit_ts`. New findings get `commit_observed_at = eval_commit_ts`
so they don't leak into other runs' prior pools. This is how CyberGym held-out samples stay
sealed even if WHW was previously run on the patched tree.

## Architecture (short)

```
┌─────────┐    ┌──────────┐    ┌──────────┐    ┌────────────┐
│  repo   │──▶ │   cbm    │──▶ │  Neo4j   │◀──▶│  whw_mcp   │◀── claude -p sub-agents (N parallel)
│ + commit│    │ (parser  │    │ (audit   │    │ (FastMCP   │
└─────────┘    │  + Nomic │    │  graph + │    │  audit     │
               │  embeds) │    │  vector  │    │  tools)    │
               └──────────┘    │  index)  │    └────────────┘
                               └──────────┘
```

- `whw/` — Python orchestration package (CLI, ingest, orchestrator, consolidate, eval, residuality).
- `whw_mcp/` — thin FastMCP stdio server wrapping Neo4j; sub-agents see only `mcp__whw__*`.
- `cybergym_data/` — local benchmark samples (read-only; .gitignored).
- Plan: `~/.claude/plans/create-a-harness-for-shimmering-dijkstra.md`

## Ports

- `whw-neo4j` bolt: **7691** (HTTP browser: 7475). `7687`/`7688` are intentionally avoided
  (codegarden / autoresearch run there locally).

[cbm]: https://github.com/007vasy/codebase-memory-mcp
[trailmark]: https://github.com/trailofbits/trailmark
[cybergym]: https://www.cybergym.io/
