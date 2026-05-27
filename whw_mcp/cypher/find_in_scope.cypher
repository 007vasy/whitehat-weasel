// Return all in-scope Function nodes for (repo_id, commit), ordered for deterministic fan-out.
MATCH (f:Function {repo_id: $repo_id, commit: $commit, in_scope: true})
RETURN f.qualified_name        AS qualified_name,
       f.name                  AS name,
       f.file_path             AS file_path,
       f.line_start            AS line_start,
       f.line_end              AS line_end,
       f.language              AS language,
       f.signature             AS signature,
       f.entrypoint_kind       AS entrypoint_kind,
       f.trust_level           AS trust_level
ORDER BY f.file_path ASC, f.line_start ASC, f.qualified_name ASC
