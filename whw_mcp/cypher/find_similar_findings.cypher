// Vector search the Finding embedding index. Server embeds the caller's summary_text
// before binding $embedding. Optional time-gate hides Findings observed after $eval_ts.
CALL db.index.vector.queryNodes('finding_embedding', $k, $embedding) YIELD node, score
WHERE score >= $min_cosine
  AND ($repo_id  IS NULL OR node.repo_id = $repo_id)
  AND ($commit   IS NULL OR node.commit  = $commit)
  AND ($eval_ts  IS NULL OR node.commit_observed_at < datetime($eval_ts))
RETURN node.id            AS id,
       node.vuln_class    AS vuln_class,
       node.severity      AS severity,
       node.confidence    AS confidence,
       node.summary       AS summary,
       node.file_path     AS file_path,
       node.line_start    AS line_start,
       node.line_end      AS line_end,
       node.function_qn   AS function_qn,
       node.status        AS status,
       node.audit_run_id  AS audit_run_id,
       toString(node.commit_observed_at) AS commit_observed_at,
       score              AS cosine
ORDER BY score DESC
