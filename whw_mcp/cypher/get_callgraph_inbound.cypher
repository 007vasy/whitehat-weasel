// Inbound callers of $qn, up to __DEPTH__ hops.
MATCH (seed:Function {qualified_name: $qn, repo_id: $repo_id, commit: $commit})
OPTIONAL MATCH path = (caller:Function)-[:CALLS*1..__DEPTH__]->(seed)
WITH caller, min(length(path)) AS hops
WHERE caller IS NOT NULL
RETURN caller.qualified_name AS qualified_name,
       caller.name           AS name,
       caller.file_path      AS file_path,
       caller.line_start     AS line_start,
       caller.line_end       AS line_end,
       hops                  AS hops
ORDER BY hops ASC, caller.qualified_name ASC
