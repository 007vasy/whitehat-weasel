// White-Hat Weasel — Neo4j schema (constraints + indexes + vector indexes).
// Idempotent. Apply with:
//   cypher-shell -a bolt://localhost:7690 -u neo4j -p whw-dev-password -f whw/neo4j_schema.cypher
// Requires Neo4j >= 5.13 for native vector indexes.

// =================== Uniqueness constraints ===================

CREATE CONSTRAINT repocommit_key IF NOT EXISTS
  FOR (r:RepoCommit) REQUIRE (r.repo_id, r.commit) IS UNIQUE;

CREATE CONSTRAINT function_key IF NOT EXISTS
  FOR (f:Function) REQUIRE (f.qualified_name, f.repo_id, f.commit) IS UNIQUE;

CREATE CONSTRAINT file_key IF NOT EXISTS
  FOR (n:File) REQUIRE (n.path, n.repo_id, n.commit) IS UNIQUE;

CREATE CONSTRAINT class_key IF NOT EXISTS
  FOR (n:Class) REQUIRE (n.qualified_name, n.repo_id, n.commit) IS UNIQUE;

CREATE CONSTRAINT module_key IF NOT EXISTS
  FOR (n:Module) REQUIRE (n.qualified_name, n.repo_id, n.commit) IS UNIQUE;

CREATE CONSTRAINT auditrun_id IF NOT EXISTS
  FOR (n:AuditRun) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT finding_id IF NOT EXISTS
  FOR (n:Finding) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT falsepositive_id IF NOT EXISTS
  FOR (n:FalsePositive) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT productionasset_id IF NOT EXISTS
  FOR (n:ProductionAsset) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT usercontextdoc_path IF NOT EXISTS
  FOR (n:UserContextDoc) REQUIRE (n.path, n.audit_run_id) IS UNIQUE;

// =================== Lookup indexes ===================

CREATE INDEX function_in_scope IF NOT EXISTS
  FOR (f:Function) ON (f.in_scope, f.repo_id, f.commit);

CREATE INDEX function_file IF NOT EXISTS
  FOR (f:Function) ON (f.file_path, f.repo_id, f.commit);

CREATE INDEX finding_run IF NOT EXISTS
  FOR (n:Finding) ON (n.audit_run_id);

CREATE INDEX finding_status IF NOT EXISTS
  FOR (n:Finding) ON (n.status);

CREATE INDEX finding_commit_observed IF NOT EXISTS
  FOR (n:Finding) ON (n.commit_observed_at);

CREATE INDEX fp_commit_observed IF NOT EXISTS
  FOR (n:FalsePositive) ON (n.commit_observed_at);

// =================== Vector indexes (Nomic, 768-dim, cosine) ===================

CREATE VECTOR INDEX function_embedding IF NOT EXISTS
  FOR (f:Function) ON f.embedding
  OPTIONS {indexConfig: {
    `vector.dimensions`: 768,
    `vector.similarity_function`: 'cosine'
  }};

CREATE VECTOR INDEX finding_embedding IF NOT EXISTS
  FOR (n:Finding) ON n.embedding
  OPTIONS {indexConfig: {
    `vector.dimensions`: 768,
    `vector.similarity_function`: 'cosine'
  }};

CREATE VECTOR INDEX fp_embedding IF NOT EXISTS
  FOR (n:FalsePositive) ON n.embedding
  OPTIONS {indexConfig: {
    `vector.dimensions`: 768,
    `vector.similarity_function`: 'cosine'
  }};

CREATE VECTOR INDEX productionasset_embedding IF NOT EXISTS
  FOR (n:ProductionAsset) ON n.embedding
  OPTIONS {indexConfig: {
    `vector.dimensions`: 768,
    `vector.similarity_function`: 'cosine'
  }};
