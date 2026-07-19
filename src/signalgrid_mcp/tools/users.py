"""Local accounts and admin membership."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import run, text


def _parse_users(out: str) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("-").isdigit():
            users.append({"username": parts[0], "uid": int(parts[-1])})
    return users


def collect_users(include_system: bool = False) -> dict[str, Any]:
    r = run(["dscl", ".", "-list", "/Users", "UniqueID"])
    if "error" in r:
        return {"error": r["error"]}
    users = _parse_users(r.get("stdout") or "")
    if not include_system:
        users = [u for u in users if u["uid"] >= 500]
    admin_raw = text(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
    admins = admin_raw.replace("GroupMembership:", "").split() if "GroupMembership:" in admin_raw else []
    for u in users:
        u["is_admin"] = u["username"] in admins
    return {
        "users": sorted(users, key=lambda u: u["uid"]),
        "admin_group": admins,
        "console_user": text(["stat", "-f", "%Su", "/dev/console"]),
        "_note": "uid >= 500 are real login accounts; pass include_system=true for daemon accounts.",
    }


@mcp.tool(name="signalgrid_local_users", annotations=READ_ONLY)
def signalgrid_local_users(
    include_system: Annotated[
        bool,
        Field(description="Include system/daemon accounts (uid < 500). Default false: real login accounts only."),
    ] = False,
) -> dict[str, Any]:
    """Local user accounts, admin-group membership, and the current console user.

    Unexpected accounts -- especially unexpected admins -- are a core device
    trust signal. Cross-check admin_group against your expected owner list.

    Args:
        include_system: include uid < 500 daemon accounts (default false).

    Returns:
        dict with keys: users (list of {username, uid, is_admin}), admin_group
        (list[str] of admin usernames), console_user (str), _note — or
        {"error": str} if directory services could not be queried.
    """
    return collect_users(include_system)
