"""Network posture and listening-service exposure."""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import run, text


def collect_network() -> dict[str, Any]:
    dns_raw = text(["scutil", "--dns"])
    nameservers = sorted(set(re.findall(r"nameserver\[\d+\] : (\S+)", dns_raw)))
    return {
        "hardware_ports": text(["networksetup", "-listallhardwareports"]),
        "active_state": text(["scutil", "--nwi"]),
        "dns_nameservers": nameservers,
        "proxies": text(["scutil", "--proxy"]),
        "vpn_configurations": text(["scutil", "--nc", "list"]),
        "_note": (
            "vpn_configurations lists configured VPN services and whether each "
            "is Connected/Disconnected. Unexpected DNS nameservers or proxies "
            "are exfiltration/MITM signals worth investigating."
        ),
    }


def _parse_lsof_listeners(out: str) -> list[dict[str, Any]]:
    """Parse `lsof -F pcLn` field output (one tagged field per line).

    Field output is used instead of the columnar default because process
    names containing spaces (e.g. 'Google Chrome Helper') break naive
    whitespace splitting. Tags: p=pid, c=command, L=login name, n=address.
    """
    items: list[dict[str, Any]] = []
    pid: str | None = None
    command: str | None = None
    user: str | None = None
    for line in out.splitlines():
        if not line:
            continue
        tag, value = line[0], line[1:]
        if tag == "p":
            pid, command, user = value, None, None
        elif tag == "c":
            command = value
        elif tag == "L":
            user = value
        elif tag == "n" and pid is not None:
            items.append(
                {"command": command, "pid": pid, "user": user, "address": value}
            )
    return items


@mcp.tool(name="signalgrid_network_posture", annotations=READ_ONLY)
def signalgrid_network_posture() -> dict[str, Any]:
    """Network configuration snapshot: hardware ports, active interface state,
    DNS nameservers, proxy settings, and configured VPNs.

    Use to spot rogue DNS, unexpected proxies, or missing corporate VPN --
    all classic device-trust red flags.

    Returns:
        dict with keys: hardware_ports (str), active_state (str, from
        `scutil --nwi`), dns_nameservers (list[str]), proxies (str),
        vpn_configurations (str), _note.
    """
    return collect_network()


@mcp.tool(name="signalgrid_listening_services", annotations=READ_ONLY)
def signalgrid_listening_services(
    name_contains: Annotated[
        str | None,
        Field(description="Case-insensitive substring filter on process command name, e.g. 'ssh'"),
    ] = None,
    limit: Annotated[int, Field(description="Maximum results to return", ge=1, le=200)] = 50,
    offset: Annotated[int, Field(description="Results to skip for pagination", ge=0)] = 0,
    response_format: Annotated[
        ResponseFormat,
        Field(description="'markdown' for a human-readable table, 'json' for machine-readable data"),
    ] = ResponseFormat.MARKDOWN,
) -> str:
    """Processes listening on TCP ports (via `lsof -iTCP -sTCP:LISTEN`).

    The live map of this Mac's inbound network exposure. Note: without
    elevation, lsof only sees processes owned by the current user; system
    daemons may be missing from the list -- absence of a listener here is
    weaker evidence than presence.

    Args:
        name_contains: substring filter on the listening process's command.
        limit/offset: pagination (default 50 per page).
        response_format: markdown table (default) or JSON envelope; items have
            command, pid, user, address (e.g. '*:22', '127.0.0.1:8021').

    Returns:
        str: rendered table or JSON string; "Error: ..." if lsof could not run.
    """
    r = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcLn"])
    if "error" in r:
        return f"Error: {r['error']}"
    # lsof exits 1 when it finds nothing; treat empty output as an empty list.
    items = _parse_lsof_listeners(r.get("stdout") or "")
    items = name_filter(items, name_contains, "command")
    page = paginate(items, limit, offset)
    return render_page(
        page,
        response_format,
        "Listening TCP services",
        [("command", "Command"), ("pid", "PID"), ("user", "User"), ("address", "Address")],
        note="Unelevated lsof may miss system daemons owned by other users.",
    )
