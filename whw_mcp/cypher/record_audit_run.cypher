// Upsert an AuditRun node. eval_commit_ts is the boundary used by eval-mode read filters.
MERGE (run:AuditRun {id: $id})
ON CREATE SET run.started_at = datetime()
SET run.repo_id        = $repo_id,
    run.commit         = $commit,
    run.scope_spec     = $scope_spec,
    run.depth          = $depth,
    run.tools_image    = $tools_image,
    run.mode           = $mode,
    run.eval_commit    = $eval_commit,
    run.eval_commit_ts = CASE WHEN $eval_commit_ts IS NULL THEN NULL ELSE datetime($eval_commit_ts) END,
    run.model          = $model,
    run.status         = coalesce($status, 'running'),
    run.notes          = coalesce($notes, ''),
    run.updated_at     = datetime()
RETURN run.id AS id,
       toString(run.started_at)    AS started_at,
       toString(run.eval_commit_ts) AS eval_commit_ts
