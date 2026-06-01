// Mark $a_id as a duplicate of $canonical_id with the measured cosine.
// Sets a.status='duplicate' so consolidation passes ignore it.
MATCH (a:Finding {id: $a_id})
MATCH (b:Finding {id: $canonical_id})
WHERE a.id <> b.id
MERGE (a)-[:DUPLICATE_OF]->(b)
MERGE (a)-[r:SIMILAR_TO]->(b)
SET r.cosine     = $cosine,
    a.status     = 'duplicate',
    a.dedup_of   = $canonical_id,
    a.updated_at = datetime()
RETURN a.id AS duplicate_id, b.id AS canonical_id, $cosine AS cosine
