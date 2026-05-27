"""Neo4j driver helpers for the audit MCP.

We use the sync driver — per-tool Cypher is fast (<10ms typical) and a synchronous
FastMCP tool is simpler than fighting asyncio integration. The driver is created lazily
on first use and reused for the process lifetime.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from neo4j import Driver, GraphDatabase, Record

from whw.config import get_settings


@lru_cache(maxsize=1)
def get_driver() -> Driver:
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=s.neo4j_auth)
    # Eagerly verify connectivity so config errors fail loudly at startup.
    driver.verify_connectivity()
    return driver


_CYPHER_DIR = Path(__file__).parent / "cypher"


def load_cypher(name: str) -> str:
    """Load a Cypher template by stem (without .cypher extension)."""
    path = _CYPHER_DIR / f"{name}.cypher"
    if not path.is_file():
        raise FileNotFoundError(f"Cypher file not found: {path}")
    return path.read_text(encoding="utf-8")


def render_cypher(name: str, **substitutions: Any) -> str:
    """Load Cypher and substitute `__KEY__` placeholders. Substitutions are validated:
    only int and a small whitelist of identifier strings are allowed (no general string
    interpolation — that would be a Cypher-injection vector).
    """
    text = load_cypher(name)
    for k, v in substitutions.items():
        marker = f"__{k.upper()}__"
        if marker not in text:
            continue
        if isinstance(v, bool):
            raise TypeError(f"bool substitution not allowed for {k!r}")
        if isinstance(v, int):
            if not (-2**31 <= v <= 2**31 - 1):
                raise ValueError(f"int {v!r} out of safe range for substitution")
            text = text.replace(marker, str(v))
        elif isinstance(v, str) and v.isidentifier():
            text = text.replace(marker, v)
        else:
            raise TypeError(f"unsupported substitution {k}={v!r}")
    return text


def run_query(
    cypher: str,
    params: dict[str, Any] | None = None,
    *,
    database: str | None = None,
) -> list[Record]:
    """Run a Cypher statement and return all records."""
    s = get_settings()
    driver = get_driver()
    with driver.session(database=database or s.neo4j_database) as session:
        result = session.run(cypher, params or {})
        return list(result)


def run_one(
    cypher: str,
    params: dict[str, Any] | None = None,
    *,
    database: str | None = None,
) -> Record | None:
    rows = run_query(cypher, params, database=database)
    return rows[0] if rows else None
