// Vector search the FalsePositive embedding index. Same semantics as find_similar_findings
// but against :FalsePositive nodes — agents use this to drop hypotheses that match
// previously-judged FPs at cosine >= ~0.88.
CALL db.index.vector.queryNodes('fp_embedding', $k, $embedding) YIELD node, score
WHERE score >= $min_cosine
  AND ($repo_id  IS NULL OR node.repo_id = $repo_id)
  AND ($commit   IS NULL OR node.commit  = $commit)
  AND ($eval_ts  IS NULL OR node.commit_observed_at < datetime($eval_ts))
RETURN node.id          AS id,
       node.finding_id  AS original_finding_id,
       node.reason      AS reason,
       node.marked_by   AS marked_by,
       toString(node.created_at)         AS created_at,
       toString(node.commit_observed_at) AS commit_observed_at,
       score            AS cosine
ORDER BY score DESC
