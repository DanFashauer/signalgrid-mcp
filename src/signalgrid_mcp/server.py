"""SignalGrid MCP server entry point.

Run locally over stdio (the right transport for a per-device agent — the
server must execute on the Mac being assessed, as a subprocess of the client):

    signalgrid-mcp          # via the installed console script
    python -m signalgrid_mcp.server
"""

from __future__ import annotations

from signalgrid_mcp import tools  # noqa: F401  (importing registers every tool)
from signalgrid_mcp.app import mcp


def main() -> None:
    mcp.run()  # stdio transport


if __name__ == "__main__":
    main()
