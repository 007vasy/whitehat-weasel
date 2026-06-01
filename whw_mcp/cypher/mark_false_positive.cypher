// Flip a Finding to status='fp' and CREATE a sibling :FalsePositive node that copies
// the Finding's embedding + provenance. Future audits can vector-query the :FP index
// to suppress repeats.
MATCH (n:Finding {id: $finding_id})
SET n.status = 'fp', n.updated_at = datetime()
CREATE (fp:FalsePositive {
  id:                 $fp_id,
  finding_id:         $finding_id,
  reason:             $reason,
  marked_by:          coalesce($marked_by, 'manual'),
  embedding:          n.embedding,
  created_at:         datetime(),
  commit_observed_at: n.commit_observed_at,
  repo_id:            n.repo_id,
  commit:             n.commit
})
MERGE (fp)-[:DERIVED_FROM]->(n)
RETURN fp.id AS id, n.id AS finding_id, n.status AS finding_status
