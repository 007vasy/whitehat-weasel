// Fetch the seed Function (the one being audited). Used by get_callgraph_slice.
MATCH (seed:Function {qualified_name: $qn, repo_id: $repo_id, commit: $commit})
RETURN seed.qualified_name      AS qualified_name,
       seed.name                AS name,
       seed.file_path           AS file_path,
       seed.line_start          AS line_start,
       seed.line_end            AS line_end,
       seed.language            AS language,
       seed.signature           AS signature,
       seed.entrypoint_kind     AS entrypoint_kind,
       seed.trust_level         AS trust_level
