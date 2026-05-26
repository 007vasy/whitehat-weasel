// Upsert a ProductionAsset. id is deterministic when not supplied (derived in Python
// from sha256(name + ':' + kind)) so re-extraction from the same context bundle hits
// the same row.
MERGE (a:ProductionAsset {id: $id})
ON CREATE SET a.created_at = datetime()
SET a.name        = $name,
    a.kind        = $kind,
    a.description = $description,
    a.criticality = coalesce($criticality, 'med'),
    a.embedding   = $embedding,
    a.updated_at  = datetime()
RETURN a.id AS id, a.name AS name, a.kind AS kind, a.criticality AS criticality
