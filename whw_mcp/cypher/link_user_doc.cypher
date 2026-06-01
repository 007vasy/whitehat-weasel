// Register a chunk of the user-context bundle and link it to the assets it MENTIONS.
// embedding is computed server-side from the chunk text.
MERGE (d:UserContextDoc {path: $path, audit_run_id: $audit_run_id})
ON CREATE SET d.created_at = datetime()
SET d.sha256     = $sha256,
    d.embedding  = $embedding,
    d.updated_at = datetime()
WITH d
UNWIND $mentions AS asset_id
MATCH (a:ProductionAsset {id: asset_id})
MERGE (d)-[:MENTIONS]->(a)
RETURN d.path AS path, d.audit_run_id AS audit_run_id, count(a) AS mention_count
