// Upsert a RepoCommit pointer so get_snippet can read source server-side.
MERGE (r:RepoCommit {repo_id: $repo_id, commit: $commit})
SET r.abs_repo_root  = $abs_repo_root,
    r.commit_ts      = CASE WHEN $commit_ts IS NULL THEN r.commit_ts ELSE datetime($commit_ts) END,
    r.updated_at     = datetime()
RETURN r.repo_id AS repo_id, r.commit AS commit, r.abs_repo_root AS abs_repo_root
