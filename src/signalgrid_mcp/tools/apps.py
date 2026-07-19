"""Installed application inventory."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import run_json


@mcp.tool(name="signalgrid_installed_apps", annotations=READ_ONLY)
def signalgrid_installed_apps(
    name_contains: Annotated[
        str | None,
        Field(description="Case-insensitive substring filter on app name, e.g. 'chrome'"),
    ] = None,
    unsigned_only: Annotated[
        bool,
        Field(description="If true, return only apps with no valid signing info -- the high-risk shortlist."),
    ] = False,
    limit: Annotated[int, Field(description="Maximum results to return", ge=1, le=200)] = 30,
    offset: Annotated[int, Field(description="Results to skip for pagination", ge=0)] = 0,
    response_format: Annotated[
        ResponseFormat,
        Field(description="'markdown' for a human-readable table, 'json' for machine-readable data"),
    ] = ResponseFormat.MARKDOWN,
) -> str:
    """Inventory of installed applications with version, source, and signer
    (via `system_profiler SPApplicationsDataType`; first call can take ~30s).

    Use for software-inventory questions and to shortlist risky installs:
    obtained_from='Unknown' plus no signer is the classic sideloaded-app
    signal. For a deep verdict on one app, follow up with
    signalgrid_codesign_inspect on its path.

    Args:
        name_contains: substring filter on the application name.
        unsigned_only: only apps lacking signing info.
        limit/offset: pagination (default 30 per page; inventories often
            have hundreds of entries).
        response_format: markdown table (default) or JSON envelope; items have
            name, version, obtained_from, signed_by (first authority),
            last_modified, path.

    Returns:
        str: rendered table or JSON string; "Error: ..." if system_profiler
        failed.
    """
    r = run_json(["system_profiler", "SPApplicationsDataType", "-json"], timeout=120)
    if not r["ok"]:
        return f"Error: {r['error']}"
    raw = r["data"].get("SPApplicationsDataType", [])
    items = []
    for it in raw:
        signed = it.get("signed_by")
        if isinstance(signed, list):
            signed = signed[0] if signed else None
        items.append(
            {
                "name": it.get("_name"),
                "version": it.get("version"),
                "obtained_from": it.get("obtained_from"),
                "signed_by": signed,
                "last_modified": it.get("lastModified"),
                "path": it.get("path"),
            }
        )
    items = name_filter(items, name_contains, "name")
    if unsigned_only:
        items = [i for i in items if not i["signed_by"]]
    items.sort(key=lambda x: str(x.get("name") or "").lower())
    page = paginate(items, limit, offset)
    return render_page(
        page,
        response_format,
        "Installed applications"
        + (f" matching '{name_contains}'" if name_contains else "")
        + (" (unsigned only)" if unsigned_only else ""),
        [
            ("name", "Name"),
            ("version", "Version"),
            ("obtained_from", "Source"),
            ("signed_by", "Signed by"),
            ("path", "Path"),
        ],
    )
