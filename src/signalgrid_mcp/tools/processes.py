"""Running process snapshot."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import run


class ProcessSort(str, Enum):
    CPU = "cpu"
    MEMORY = "memory"
    PID = "pid"


def _parse_ps(out: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        pid, ppid, user, cpu, mem, comm = parts
        try:
            items.append(
                {
                    "pid": int(pid),
                    "ppid": int(ppid),
                    "user": user,
                    "cpu_pct": float(cpu),
                    "mem_pct": float(mem),
                    "command": comm.strip(),
                }
            )
        except ValueError:
            continue
    return items


@mcp.tool(name="signalgrid_process_snapshot", annotations=READ_ONLY)
def signalgrid_process_snapshot(
    name_contains: Annotated[
        str | None,
        Field(description="Case-insensitive substring filter on the command path, e.g. 'python'"),
    ] = None,
    sort_by: Annotated[
        ProcessSort,
        Field(description="Sort order: 'cpu' (default), 'memory', or 'pid'"),
    ] = ProcessSort.CPU,
    limit: Annotated[int, Field(description="Maximum results to return", ge=1, le=200)] = 25,
    offset: Annotated[int, Field(description="Results to skip for pagination", ge=0)] = 0,
    response_format: Annotated[
        ResponseFormat,
        Field(description="'markdown' for a human-readable table, 'json' for machine-readable data"),
    ] = ResponseFormat.MARKDOWN,
) -> str:
    """Point-in-time snapshot of running processes (pid, parent, user, %CPU,
    %MEM, command path).

    Use to confirm an agent/daemon is actually running (filter by name) or to
    spot suspicious processes. Full executable paths are included -- feed a
    suspicious one to signalgrid_codesign_inspect.

    Args:
        name_contains: substring filter on the command path.
        sort_by: cpu (default) | memory | pid.
        limit/offset: pagination (default 25 per page).
        response_format: markdown table (default) or JSON envelope; items have
            pid, ppid, user, cpu_pct, mem_pct, command.

    Returns:
        str: rendered table or JSON string; "Error: ..." if ps failed.
    """
    r = run(["ps", "axo", "pid,ppid,user,%cpu,%mem,comm"])
    if not r.get("ok"):
        return f"Error: {r.get('error') or r.get('stderr') or 'ps failed'}"
    items = name_filter(_parse_ps(r["stdout"]), name_contains, "command")
    key = {"cpu": "cpu_pct", "memory": "mem_pct", "pid": "pid"}[sort_by.value]
    items.sort(key=lambda x: x[key], reverse=sort_by != ProcessSort.PID)
    page = paginate(items, limit, offset)
    return render_page(
        page,
        response_format,
        "Process snapshot"
        + (f" matching '{name_contains}'" if name_contains else "")
        + f" (by {sort_by.value})",
        [
            ("pid", "PID"),
            ("user", "User"),
            ("cpu_pct", "%CPU"),
            ("mem_pct", "%MEM"),
            ("command", "Command"),
        ],
    )
