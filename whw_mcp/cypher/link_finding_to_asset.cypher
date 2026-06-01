// Idempotent AFFECTS_ASSET edge between a Finding and a ProductionAsset.
MATCH (f:Finding {id: $finding_id})
MATCH (a:ProductionAsset {id: $asset_id})
MERGE (f)-[:AFFECTS_ASSET]->(a)
RETURN f.id AS finding_id, a.id AS asset_id
