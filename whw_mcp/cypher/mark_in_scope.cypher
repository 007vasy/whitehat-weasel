// Flip in_scope=true for every Function in (repo_id, commit) whose QN is in $qns.
MATCH (f:Function {repo_id: $repo_id, commit: $commit})
WHERE f.qualified_name IN $qns
SET f.in_scope = true,
    f.entrypoint_kind = coalesce($entrypoint_kind, f.entrypoint_kind),
    f.trust_level     = coalesce($trust_level,     f.trust_level)
RETURN count(f) AS marked
