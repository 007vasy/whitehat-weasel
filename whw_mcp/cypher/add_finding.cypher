// Create a Finding, link it to its AuditRun and (optionally) the host Function.
// commit_observed_at defaults to the run's eval_commit_ts (eval mode) or NOW (live mode).
MATCH (run:AuditRun {id: $audit_run_id})
WITH run, coalesce(run.eval_commit_ts, datetime()) AS observed_at
OPTIONAL MATCH (f:Function {qualified_name: $function_qn, repo_id: run.repo_id, commit: run.commit})
WHERE $function_qn IS NULL OR f IS NOT NULL
CREATE (n:Finding {
  id:                 $id,
  vuln_class:         $vuln_class,
  severity:           $severity,
  confidence:         $confidence,
  summary:            $summary,
  rationale:          $rationale,
  file_path:          coalesce($file_path,  f.file_path),
  line_start:         coalesce($line_start, f.line_start),
  line_end:           coalesce($line_end,   f.line_end),
  function_qn:        $function_qn,
  embedding:          $embedding,
  source:             coalesce($source, 'llm'),
  tool_evidence:      coalesce($tool_evidence, ''),
  created_at:         datetime(),
  commit_observed_at: observed_at,
  audit_run_id:       $audit_run_id,
  status:             'open',
  model_used:         coalesce($model_used, run.model),
  repo_id:            run.repo_id,
  commit:             run.commit
})
MERGE (run)-[:FOUND]->(n)
FOREACH (_ IN CASE WHEN f IS NULL THEN [] ELSE [1] END |
  MERGE (n)-[:LOCATED_IN]->(f)
)
RETURN n.id AS id, toString(n.created_at) AS created_at, toString(n.commit_observed_at) AS commit_observed_at
