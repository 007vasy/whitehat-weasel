// Outbound callees of $qn, up to __DEPTH__ hops. __DEPTH__ is substituted in Python
// (validated to be in 1..5) — Cypher's variable-length bounds must be literals.
MATCH (seed:Function {qualified_name: $qn, repo_id: $repo_id, commit: $commit})
OPTIONAL MATCH path = (seed)-[:CALLS*1..__DEPTH__]->(callee:Function)
WITH callee, min(length(path)) AS hops
WHERE callee IS NOT NULL
RETURN callee.qualified_name AS qualified_name,
       callee.name           AS name,
       callee.file_path      AS file_path,
       callee.line_start     AS line_start,
       callee.line_end       AS line_end,
       hops                  AS hops
ORDER BY hops ASC, callee.qualified_name ASC
