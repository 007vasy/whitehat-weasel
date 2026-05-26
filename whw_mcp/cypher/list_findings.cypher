// List findings for (repo_id, commit), optionally filtered by status, with eval-mode time gating.
MATCH (n:Finding {repo_id: $repo_id, commit: $commit})
WHERE ($status     IS NULL OR n.status = $status)
  AND ($eval_ts    IS NULL OR n.commit_observed_at < datetime($eval_ts))
RETURN n.id                AS id,
       n.vuln_class        AS vuln_class,
       n.severity          AS severity,
       n.confidence        AS confidence,
       n.summary           AS summary,
       n.rationale         AS rationale,
       n.file_path         AS file_path,
       n.line_start        AS line_start,
       n.line_end          AS line_end,
       n.function_qn       AS function_qn,
       n.source            AS source,
       n.status            AS status,
       n.audit_run_id      AS audit_run_id,
       toString(n.commit_observed_at) AS commit_observed_at,
       toString(n.created_at)         AS created_at
ORDER BY n.created_at DESC
LIMIT $limit
