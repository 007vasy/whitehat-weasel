// Resolve a function's source span and the abs repo root (if registered).
MATCH (f:Function {qualified_name: $qn, repo_id: $repo_id, commit: $commit})
OPTIONAL MATCH (r:RepoCommit {repo_id: $repo_id, commit: $commit})
RETURN f.file_path        AS file_path,
       f.line_start       AS line_start,
       f.line_end         AS line_end,
       f.language         AS language,
       f.name             AS name,
       r.abs_repo_root    AS abs_repo_root
