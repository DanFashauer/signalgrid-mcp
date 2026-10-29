#!/usr/bin/env python3
"""Node-free MCP inspector for the SignalGrid server.

Connects over stdio exactly as an MCP client would, initializes the session,
lists every tool, and calls each with bounded probe arguments — then reports, per
tool: its read-only annotation, whether its input schema is well-formed, and
its text-marker classification. A "value" label is a heuristic, not verification
of signal data. It exits non-zero on a crash, a missing expected tool, an MCP
tool error, or a missing read-only annotation. Honest unknown results remain
protocol-health successes; they are not live-signal evidence.

This is the scriptable equivalent of `npx @modelcontextprotocol/inspector` — it
needs no Node, so `verify.sh` can run it anywhere. Live-signal claims require
successful signal-specific returned data or a corresponding assertion on a real
Mac. This script alone does not establish that proof on any platform.

    python3 tools/inspect_stdio.py           # human-readable report
    python3 tools/inspect_stdio.py --json     # machine-readable summary
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

# Make `src/` importable when run from the repo root, without an install.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "signalgrid_device_identity",
    "signalgrid_os_info",
    "signalgrid_security_posture",
    "signalgrid_sharing_services",
    "signalgrid_mdm_status",
    "signalgrid_software_updates",
    "signalgrid_xprotect_status",
    "signalgrid_install_history",
    "signalgrid_network_posture",
    "signalgrid_listening_services",
    "signalgrid_launch_items",
    "signalgrid_kernel_extensions",
    "signalgrid_local_users",
    "signalgrid_installed_apps",
    "signalgrid_process_snapshot",
    "signalgrid_codesign_inspect",
    "signalgrid_time_machine",
    "signalgrid_posture_report",
    "signalgrid_removable_media",
    "signalgrid_screen_lock",
    "signalgrid_system_extensions",
    "signalgrid_trust_verdict",
}

UNKNOWN_MARKERS = ("not macos", "not found", '"unknown"', "could not", "unavailable", ": null")

# This existing tool requires a path. Inspect a bounded system binary rather
# than calling it with invalid empty arguments or requesting elevation.
PROBE_ARGUMENTS = {"signalgrid_codesign_inspect": {"path": "/bin/ls"}}


def _text(result) -> str:
    out = ""
    for c in result.content:
        if getattr(c, "type", None) == "text":
            out += c.text
    return out


async def run() -> int:
    params = StdioServerParameters(command=sys.executable, args=["-m", "signalgrid_mcp.server"], env=None)
    rows: list[dict] = []
    crashes: list[tuple[str, str]] = []

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            server_name = init.serverInfo.name
            server_version = init.serverInfo.version
            listed = await session.list_tools()
            tools = listed.tools
            names = {t.name for t in tools}

            for t in sorted(tools, key=lambda x: x.name):
                ann = t.annotations
                read_only = getattr(ann, "readOnlyHint", None) if ann else None
                destructive = getattr(ann, "destructiveHint", None) if ann else None
                schema_ok = isinstance(t.inputSchema, dict)
                try:
                    res = await session.call_tool(t.name, dict(PROBE_ARGUMENTS.get(t.name, {})))
                except Exception as exc:  # protocol/tool crash — never acceptable
                    crashes.append((t.name, f"{type(exc).__name__}: {exc}"))
                    rows.append({"tool": t.name, "status": "CRASH", "read_only": read_only})
                    continue
                body = _text(res)
                low = body.lower()
                is_error = bool(getattr(res, "isError", False))
                resolved_unknown = any(m in low for m in UNKNOWN_MARKERS)
                rows.append({
                    "tool": t.name,
                    "read_only": read_only,
                    "destructive": destructive,
                    "schema_ok": schema_ok,
                    "is_error": is_error,
                    "resolved": "error" if is_error else "unknown" if resolved_unknown else "value",
                    "classification_basis": "text_marker_heuristic",
                    "live_verified": False,
                    "bytes": len(body),
                })

            missing = sorted(EXPECTED_TOOLS - names)
            not_read_only = [r["tool"] for r in rows if r.get("read_only") is not True]
            tool_errors = [r["tool"] for r in rows if r.get("is_error") is True]

            summary = {
                "server": {"name": server_name, "version": server_version},
                "tools_registered": len(tools),
                "expected_present": not missing,
                "missing_tools": missing,
                "all_read_only": not not_read_only,
                "non_read_only_tools": not_read_only,
                "crashes": [c[0] for c in crashes],
                "tool_errors": tool_errors,
                "resolved_values": sum(1 for r in rows if r.get("resolved") == "value"),
                "resolved_unknown": sum(1 for r in rows if r.get("resolved") == "unknown"),
            }

    if "--json" in sys.argv:
        print(json.dumps({"summary": summary, "tools": rows}, indent=2))
    else:
        print(f"MCP inspect — {summary['server']['name']} v{summary['server']['version']}")
        print(f"tools registered: {summary['tools_registered']}  "
              f"(expected {len(EXPECTED_TOOLS)}; missing={summary['missing_tools'] or 'none'})\n")
        for r in rows:
            if r["status"] if "status" in r else False:
                print(f"  {r['tool']:34} CRASH")
                continue
            print(f"  {r['tool']:34} readOnly={r['read_only']!s:5} "
                  f"schema={'ok' if r['schema_ok'] else 'BAD'} "
                  f"-> {r['resolved']:7} ({r['bytes']}b)")
        print(f"\nresolved: {summary['resolved_values']} value / {summary['resolved_unknown']} unknown")
        print("(text-marker classifications are heuristic; a value label is not "
              "verified live-signal evidence. Honest unknowns may reflect an absent "
              "binary, timeout or unavailable permission; do not infer a value.)")

    # Fail only on a genuine protocol/contract violation.
    ok = not crashes and not missing and not not_read_only and not tool_errors
    if not ok:
        print("\nFAIL:", file=sys.stderr)
        if crashes:
            print(f"  crashes: {crashes}", file=sys.stderr)
        if missing:
            print(f"  missing tools: {missing}", file=sys.stderr)
        if not_read_only:
            print(f"  tools not marked read-only: {not_read_only}", file=sys.stderr)
        if tool_errors:
            print(f"  MCP tool errors: {tool_errors}", file=sys.stderr)
        return 1
    print("\nOK — protocol healthy, all expected tools present, every tool read-only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
