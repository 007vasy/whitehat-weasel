"""Allow `python -m whw_mcp` to start the audit MCP server over stdio."""

from .server import main

if __name__ == "__main__":
    main()
