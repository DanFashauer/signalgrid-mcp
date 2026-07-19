"""Patch state: software updates, XProtect/MRT versions, install history."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import defaults_read, run_json, text

SU_DOMAIN = "/Library/Preferences/com.apple.SoftwareUpdate"
XPROTECT_PLISTS = {
    "xprotect_definitions": (
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        "Version",
    ),
    "xprotect_remediator": (
        "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist",
        "CFBundleShortVersionString",
    ),
    "mrt": (
        "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist",
        "CFBundleShortVersionString",
    ),
}


def collect_update_settings() -> dict[str, Any]:
    keys = [
        "AutomaticCheckEnabled",
        "AutomaticDownload",
        "AutomaticallyInstallMacOSUpdates",
        "ConfigDataInstall",
        "CriticalUpdateInstall",
        "LastSuccessfulDate",
        "LastUpdatesAvailable",
    ]
    out: dict[str, Any] = {}
    for k in keys:
        p = defaults_read(SU_DOMAIN, k)
        out[k] = p["raw"] if p["ok"] else None
    app_store = defaults_read("/Library/Preferences/com.apple.commerce", "AutoUpdate")
    out["AppStoreAutoUpdate"] = app_store["raw"] if app_store["ok"] else None
    return out


def collect_xprotect() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, (plist, key) in XPROTECT_PLISTS.items():
        # `defaults read` accepts a plist path without the .plist extension.
        p = defaults_read(plist.removesuffix(".plist"), key)
        out[name] = p["raw"] if p["ok"] else f"unavailable: {p['raw']}"
    return out


@mcp.tool(name="signalgrid_software_updates", annotations=READ_ONLY)
def signalgrid_software_updates(
    check_online: Annotated[
        bool,
        Field(
            description=(
                "If true, also query Apple's update servers live via "
                "`softwareupdate -l` (slow: 30-120s). If false (default), "
                "report only cached preference state, which is instant."
            ),
        ),
    ] = False,
) -> dict[str, Any]:
    """Software update posture: auto-update settings, last successful check,
    cached count of available updates, and optionally a live check.

    LastUpdatesAvailable > 0 or a stale LastSuccessfulDate is a patch-hygiene
    red flag. Values are null when a preference is unset or unreadable.

    Args:
        check_online: run a live `softwareupdate -l` (slow) in addition to the
            cached state.

    Returns:
        dict with keys: settings (dict of SoftwareUpdate preferences incl.
        AutomaticCheckEnabled, AutomaticallyInstallMacOSUpdates,
        CriticalUpdateInstall, LastSuccessfulDate, LastUpdatesAvailable,
        AppStoreAutoUpdate), and live_check (str, only when check_online=true).
    """
    out: dict[str, Any] = {"settings": collect_update_settings()}
    if check_online:
        out["live_check"] = text(["softwareupdate", "-l"], timeout=150)
    return out


@mcp.tool(name="signalgrid_xprotect_status", annotations=READ_ONLY)
def signalgrid_xprotect_status() -> dict[str, Any]:
    """Versions of Apple's built-in anti-malware: XProtect definitions,
    XProtect Remediator, and MRT (Malware Removal Tool).

    Stale definitions indicate the Mac is not receiving Apple security
    content updates (often caused by ConfigDataInstall being disabled).

    Returns:
        dict with keys: xprotect_definitions, xprotect_remediator, mrt.
        Each is a version string, or "unavailable: <reason>" text.
    """
    return collect_xprotect()


@mcp.tool(name="signalgrid_install_history", annotations=READ_ONLY)
def signalgrid_install_history(
    name_contains: Annotated[
        str | None,
        Field(description="Case-insensitive substring filter on package name, e.g. 'XProtect' or 'macOS'"),
    ] = None,
    limit: Annotated[int, Field(description="Maximum results to return", ge=1, le=200)] = 25,
    offset: Annotated[int, Field(description="Results to skip for pagination", ge=0)] = 0,
    response_format: Annotated[
        ResponseFormat,
        Field(description="'markdown' for a human-readable table, 'json' for machine-readable data"),
    ] = ResponseFormat.MARKDOWN,
) -> str:
    """Software install history (OS updates, security content, packages),
    newest first — the audit trail of what changed on this Mac and when.

    Use to verify security updates actually landed (e.g. filter
    name_contains='XProtect') or to spot unexpected installs.

    Args:
        name_contains: substring filter on the package name.
        limit/offset: pagination (default 25 per page).
        response_format: markdown table (default) or JSON envelope
            {total, count, offset, items, has_more, next_offset}; items have
            name, version, source, install_date.

    Returns:
        str: rendered table or JSON string; "Error: ..." if the underlying
        system_profiler query failed.
    """
    r = run_json(["system_profiler", "SPInstallHistoryDataType", "-json"], timeout=90)
    if not r["ok"]:
        return f"Error: {r['error']}"
    raw = r["data"].get("SPInstallHistoryDataType", [])
    items = [
        {
            "name": it.get("_name"),
            "version": it.get("install_version"),
            "source": it.get("package_source"),
            "install_date": it.get("install_date"),
        }
        for it in raw
    ]
    items = name_filter(items, name_contains, "name")
    items.sort(key=lambda x: str(x.get("install_date") or ""), reverse=True)
    page = paginate(items, limit, offset)
    return render_page(
        page,
        response_format,
        "Install history" + (f" matching '{name_contains}'" if name_contains else ""),
        [("install_date", "Date"), ("name", "Name"), ("version", "Version"), ("source", "Source")],
    )
