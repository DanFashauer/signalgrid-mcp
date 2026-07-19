"""Persistence: launch daemons/agents and loaded kernel extensions."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import run, text

# Third-party persistence locations. /System/Library is Apple-only and sealed,
# so it is deliberately excluded — everything here is admin- or user-writable.
LAUNCH_DIRS: dict[str, str] = {
    "/Library/LaunchDaemons": "system_daemon",
    "/Library/LaunchAgents": "system_agent",
    "~/Library/LaunchAgents": "user_agent",
    "~/Library/LaunchDaemons": "user_daemon_nonstandard",
}


def _installed_launch_items() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for d, scope in LAUNCH_DIRS.items():
        path = Path(os.path.expanduser(d))
        if not path.is_dir():
            continue
        try:
            for f in sorted(path.iterdir()):
                if f.suffix != ".plist":
                    continue
                st = f.stat()
                items.append(
                    {
                        "label": f.stem,
                        "scope": scope,
                        "path": str(f),
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(
                            timespec="seconds"
                        ),
                    }
                )
        except PermissionError:
            items.append(
                {"label": f"(permission denied reading {path})", "scope": scope, "path": str(path), "modified": None}
            )
    return items


def collect_persistence_summary() -> dict[str, Any]:
    installed = _installed_launch_items()
    return {
        "third_party_launch_item_count": len(installed),
        "by_scope": {
            scope: sum(1 for i in installed if i["scope"] == scope)
            for scope in set(i["scope"] for i in installed)
        },
    }


@mcp.tool(name="signalgrid_launch_items", annotations=READ_ONLY)
def signalgrid_launch_items(
    name_contains: Annotated[
        str | None,
        Field(description="Case-insensitive substring filter on the launchd label, e.g. 'docker'"),
    ] = None,
    limit: Annotated[int, Field(description="Maximum results to return", ge=1, le=200)] = 50,
    offset: Annotated[int, Field(description="Results to skip for pagination", ge=0)] = 0,
    response_format: Annotated[
        ResponseFormat,
        Field(description="'markdown' for a human-readable table, 'json' for machine-readable data"),
    ] = ResponseFormat.MARKDOWN,
) -> str:
    """Third-party launchd persistence: plists installed in /Library/LaunchDaemons,
    /Library/LaunchAgents, and ~/Library/LaunchAgents.

    These are the standard macOS persistence mechanisms -- anything here runs
    automatically at boot or login. Apple's own sealed /System items are
    excluded, so every row is software someone installed. A recently-modified,
    oddly-named plist is a prime malware-persistence signal.

    Args:
        name_contains: substring filter on the launchd label (filename).
        limit/offset: pagination (default 50 per page).
        response_format: markdown table (default) or JSON envelope; items have
            label, scope (system_daemon | system_agent | user_agent |
            user_daemon_nonstandard), path, modified (ISO timestamp).

    Returns:
        str: rendered table or JSON string.
    """
    items = name_filter(_installed_launch_items(), name_contains, "label")
    page = paginate(items, limit, offset)
    return render_page(
        page,
        response_format,
        "Third-party launch items",
        [("label", "Label"), ("scope", "Scope"), ("modified", "Modified"), ("path", "Path")],
        note="user_daemon_nonstandard entries (~/Library/LaunchDaemons) are unusual and worth a close look.",
    )


@mcp.tool(name="signalgrid_kernel_extensions", annotations=READ_ONLY)
def signalgrid_kernel_extensions() -> dict[str, Any]:
    """Loaded kernel extensions, with third-party (non-Apple) kexts singled out.

    Modern macOS strongly discourages kexts; any third-party kext is a
    significant trust signal (legacy security tools, virtualization, or
    something worse). Tries `kmutil showloaded` first, falls back to `kextstat`.

    Returns:
        dict with keys: third_party (list[str] of loaded non-Apple kext lines,
        ideally empty), raw (full loader output), source ('kmutil' or
        'kextstat'), or {"error": str} if neither tool ran.
    """
    r = run(["kmutil", "showloaded", "--list-only"], timeout=30)
    source = "kmutil"
    if "error" in r or (not r.get("stdout") and not r.get("ok")):
        raw = text(["kextstat", "-l"], timeout=30)
        source = "kextstat"
    else:
        raw = r.get("stdout") or r.get("stderr") or ""
    if raw.startswith("not found:") or raw == "unavailable":
        return {"error": raw}
    third_party = [
        line.strip()
        for line in raw.splitlines()
        if line.strip()
        and "com.apple." not in line
        and "Executing:" not in line
        and not line.lstrip().lower().startswith(("index ", "no variant specified"))
    ]
    return {"third_party": third_party, "source": source, "raw": raw}
