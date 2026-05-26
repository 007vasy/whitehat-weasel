"""Shared configuration (env + defaults). Used by `whw/*` and `whw_mcp/*`.

Loads .env if present. Pydantic-settings validates types and gives nice errors.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Single source of runtime configuration.

    Field names map 1:1 to env vars (case-insensitive). See .env.example for the full list.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Neo4j ---
    neo4j_uri: str = "bolt://localhost:7691"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "whw-dev-password"
    neo4j_database: str = "neo4j"

    # --- Anthropic / Claude Code ---
    anthropic_api_key: str = ""
    claude_code_bin: str = "claude"

    # --- Audit MCP (whw_mcp) ---
    whw_embedding_backend: str = Field("nomic", description="'nomic' or 'noop'")
    whw_nomic_model: str = "nomic-ai/nomic-embed-text-v1.5"

    # --- Orchestration defaults (overridable by CLI flags) ---
    whw_max_parallel: int = 4
    whw_per_agent_budget_usd: float = 0.50
    whw_per_agent_timeout_s: int = 600
    whw_per_agent_max_turns: int = 25
    whw_rate_per_min: int = 8

    # --- Paths ---
    whw_run_dir: Path = Path(".whw")
    whw_worktree_dir: Path = Path("/tmp/whw-worktrees")
    whw_cache_dir: Path = Path.home() / ".cache" / "whw"

    @property
    def neo4j_auth(self) -> tuple[str, str]:
        return (self.neo4j_user, self.neo4j_password)


_singleton: Settings | None = None


def get_settings() -> Settings:
    """Return a process-wide Settings singleton."""
    global _singleton
    if _singleton is None:
        _singleton = Settings()
    return _singleton
