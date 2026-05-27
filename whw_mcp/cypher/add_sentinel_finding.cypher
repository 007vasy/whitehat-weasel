// Orchestrator-written sentinel Finding (AGENT_FAILED or INDEX_PARTIAL). Created
// without calling the MCP because the MCP server is not in this process. Embedding
// is a zero vector so it doesn't pollute the dedup/FP vector indexes.
MATCH (run:AuditRun {id: $audit_run_id})
WITH run, coalesce(run.eval_commit_ts, datetime()) AS observed_at
OPTIONAL MATCH (f:Function {qualified_name: $function_qn, repo_id: run.repo_id, commit: run.commit})
CREATE (n:Finding {
  id:                 $id,
  vuln_class:         $vuln_class,
  severity:           'info',
  confidence:         'uncertain',
  summary:            $summary,
  rationale:          $rationale,
  file_path:          coalesce($file_path,  f.file_path),
  line_start:         coalesce($line_start, f.line_start),
  line_end:           coalesce($line_end,   f.line_end),
  function_qn:        $function_qn,
  embedding:          $zero_embedding,
  source:             'orchestrator',
  tool_evidence:      $tool_evidence,
  created_at:         datetime(),
  commit_observed_at: observed_at,
  audit_run_id:       $audit_run_id,
  status:             'open',
  model_used:         run.model,
  repo_id:            run.repo_id,
  commit:             run.commit
})
MERGE (run)-[:FOUND]->(n)
FOREACH (_ IN CASE WHEN f IS NULL THEN [] ELSE [1] END |
  MERGE (n)-[:LOCATED_IN]->(f)
)
RETURN n.id AS id
