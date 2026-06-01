// Walk the CALLS graph backward from $qn until we hit a function that looks like
// an untrusted entry point. "Entry" = function with entrypoint_kind set, or
// trust_level='UNTRUSTED', or a name that matches a handler/route/webhook/fuzzer
// shape. Returns shortest path per entry, up to __DEPTH__ CALLS hops.
//
// Intended use: pre-fetched into the audit sub-agent's slice so the agent can
// reason about whether the target function inherits an unguarded reach from an
// untrusted entry, without having to walk the CALLS graph itself.
MATCH (seed:Function {qualified_name: $qn, repo_id: $repo_id, commit: $commit})
MATCH (entry:Function {repo_id: $repo_id, commit: $commit})
WHERE entry.qualified_name <> seed.qualified_name
  AND (
    entry.entrypoint_kind IS NOT NULL
    OR entry.trust_level = 'UNTRUSTED'
    OR entry.name =~ '(?i)(main|llvmfuzzertestoneinput|.*(handler|handle|route|webhook|endpoint|fuzzer|onrequest|onmessage))'
  )
MATCH path = shortestPath((entry)-[:CALLS*1..__DEPTH__]->(seed))
WITH entry, path, length(path) AS hops
RETURN entry.qualified_name        AS entry_qn,
       entry.name                  AS entry_name,
       entry.file_path             AS entry_file,
       entry.line_start            AS entry_line_start,
       entry.entrypoint_kind       AS entry_kind,
       entry.trust_level           AS trust_level,
       hops                        AS hops,
       [n IN nodes(path)[1..-1] | n.qualified_name] AS intermediate_qns,
       CASE
         WHEN entry.entrypoint_kind IS NOT NULL THEN 'entrypoint_kind'
         WHEN entry.trust_level = 'UNTRUSTED' THEN 'trust_level'
         ELSE 'name_pattern'
       END                         AS match_source
ORDER BY hops ASC, entry.qualified_name ASC
LIMIT 10
