"""The shared FastMCP application instance and common tool annotations."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP(
    "signalgrid_mcp",
    instructions=(
        "SignalGrid exposes macOS-native device trust signals: hardware identity, "
        "OS and security posture, MDM enrollment, software/patch state, network "
        "exposure, persistence mechanisms, and code-signature inspection. "
        "Every tool is strictly read-only. For a one-call snapshot use "
        "signalgrid_posture_report; use the focused tools to drill into a signal. "
        "A value of null/unknown always means 'could not be determined', never 'off'."
    ),
)

# Every SignalGrid tool is read-only, non-destructive, idempotent, and local.
READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
