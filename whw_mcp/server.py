"""whw-mcp: FastMCP stdio server wrapping the Neo4j audit graph.

Tools exposed as `mcp__whw__*` to sub-agents.

Run it manually for debugging:

    uv run python -m whw_mcp

Or from a sub-agent via its MCP config (the orchestrator writes a JSON file like):

    {
      "mcpServers": {
        "whw": {
          "command": "uv",
          "args": ["run", "python", "-m", "whw_mcp"],
          "env": { "NEO4J_URI": "...", "NEO4J_PASSWORD": "..." }
        }
      }
    }
"""

from __future__ import annotations

from fastmcp import FastMCP

from .tools_read import register_read_tools
from .tools_write import register_write_tools


def build_server() -> FastMCP:
    """Construct and configure the FastMCP server. Pulled out for testing."""
    mcp = FastMCP("whw")
    register_read_tools(mcp)
    register_write_tools(mcp)
    return mcp


_app = build_server()


def main() -> None:
    """Entry point for `python -m whw_mcp`."""
    _app.run()


if __name__ == "__main__":
    main()
