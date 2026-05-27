#!/usr/bin/env bash
# Apply whw/neo4j_schema.cypher to the running whw-neo4j container.
# Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

URI="${NEO4J_URI:-bolt://localhost:7691}"
USER="${NEO4J_USER:-neo4j}"
PASS="${NEO4J_PASSWORD:-whw-dev-password}"

# Wait for Neo4j to accept connections (up to 60s).
echo "Waiting for Neo4j at $URI ..."
for _ in $(seq 1 30); do
  if docker exec whw-neo4j cypher-shell -u "$USER" -p "$PASS" 'RETURN 1' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "Applying schema: whw/neo4j_schema.cypher"
docker exec -i whw-neo4j cypher-shell -u "$USER" -p "$PASS" < "$REPO_ROOT/whw/neo4j_schema.cypher"

echo "Verifying constraints + indexes:"
docker exec whw-neo4j cypher-shell -u "$USER" -p "$PASS" 'SHOW CONSTRAINTS YIELD name, type RETURN name, type ORDER BY name'
docker exec whw-neo4j cypher-shell -u "$USER" -p "$PASS" 'SHOW INDEXES YIELD name, type, entityType RETURN name, type, entityType ORDER BY name'

echo "✓ schema applied"
