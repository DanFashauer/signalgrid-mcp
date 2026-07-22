"""System extensions — installed endpoint-security / network extensions and
whether any is stranded (still registered after its app is gone).

Read-only. `systemextensionsctl list` needs no root. The security angle: a
security agent that was deleted-but-not-deactivated leaves a system extension
behind — its state reads `activated enabled (removed)` or `terminated waiting to
uninstall` — it still occupies the slot and can block a reinstall. Two enabled
endpoint-security extensions is a conflict. This tool reports the facts; the
decision fabric interprets them.

Fail-safe throughout: a state that could NOT be read is never "clean". If the
command fails, `available` is False (NOT "none installed"); if the parsed count
disagrees with the header's declared count, or any row can't be parsed,
`reliable` is False so a caller raises the assurance bar rather than trusting a
possibly-incomplete list; an unrecognized state is `unknown`, never `active`.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat, name_filter, paginate, render_page
from signalgrid_mcp.runner import run

# The tool always prints "N extension(s)" as a real header line. Anchor on it
# (not a loose substring) so error text that merely mentions "extension(s)" can't
# masquerade as a successful listing.
_HEADER_RE = re.compile(r"^\s*(\d+)\s+extension\(s\)", re.IGNORECASE)


def _classify(state: str) -> str:
    """Normalize the bracketed state into a coarse status. Fail-safe: residual
    wins over active, and anything unrecognized is 'unknown', never 'active'."""
    s = state.lower()
    # Stranded: the sponsoring app is gone but the extension is STILL registered.
    # Covers "terminated"/"terminating", "waiting to uninstall", and the common
    # deleted-app marker "activated enabled (removed)".
    if "terminat" in s or "uninstall" in s or "removed" in s:
        return "residual"
    if "waiting for user" in s or "pending" in s or "approval" in s:
        return "pending"
    if "activated" in s:
        return "active"
    return "unknown"


def _empty(available: bool, note: str) -> dict[str, Any]:
    return {
        "available": available,
        "reliable": False,
        "count": None if not available else 0,
        "declared_count": None,
        "extensions": [],
        "residual_count": 0,
        "active_count": 0,
        "unparsed_rows": 0,
        "_note": note,
    }


def parse_system_extensions(raw: str) -> dict[str, Any]:
    """Parse `systemextensionsctl list`. Fail-safe (see module docstring).

    Row format (tab-separated):
        enabled  active  teamID  bundleID (version)  name  [state]
    where enabled/active are "*" or empty. The header row's 3rd column is the
    literal "teamID" — used to skip it exactly (a data row's 3rd column is a real
    team identifier, never "teamID")."""
    if not isinstance(raw, str) or not raw.strip():
        return _empty(False, "no output")

    declared: int | None = None
    for line in raw.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            declared = int(m.group(1))
            break
    if declared is None:
        return _empty(False, "unrecognized output — could not read system extensions (no 'N extension(s)' header)")

    category = None
    exts: list[dict[str, Any]] = []
    unparsed = 0
    for line in raw.splitlines():
        if _HEADER_RE.match(line):
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("---"):
            category = stripped.lstrip("-").strip() or None
            continue
        if "\t" not in line:
            continue
        cols = line.split("\t")
        # Exact header-row detection: 3rd column literally "teamID".
        if len(cols) >= 3 and cols[2].strip().lower() == "teamid":
            continue
        if len(cols) < 6:
            unparsed += 1  # looked like a data row but didn't parse — never silent
            continue
        try:
            bundle_ver = cols[3].strip()
            if " (" in bundle_ver and bundle_ver.endswith(")"):
                idx = bundle_ver.rindex(" (")
                bundle, version = bundle_ver[:idx].strip(), bundle_ver[idx + 2 : -1].strip()
            else:
                bundle, version = bundle_ver, None
            state = cols[5].strip().strip("[]").strip()
            exts.append({
                "category": category,
                "teamID": cols[2].strip() or None,
                "bundleID": bundle or None,
                "version": version,
                "name": cols[4].strip() or None,
                "enabled": cols[0].strip() == "*",
                "active": cols[1].strip() == "*",
                "state": state,
                "status": _classify(state),
            })
        except Exception:  # noqa: BLE001 — a bad row is counted, never crashes the read
            unparsed += 1

    residual = sum(1 for e in exts if e["status"] == "residual")
    active = sum(1 for e in exts if e["status"] == "active")
    # Reliable only when every declared extension was parsed and nothing was left
    # unparsed. Otherwise a residual one may be missing → treat as raise-assurance.
    reliable = unparsed == 0 and declared == len(exts)
    note = (
        "status 'residual' = terminated/removed/waiting-to-uninstall but STILL "
        "registered (a stranded extension that can block reinstall); 'unknown' = "
        "state not recognized (never assume active/clean)."
    )
    if not reliable:
        note = (
            f"UNRELIABLE: header declares {declared} extension(s) but parsed {len(exts)} "
            f"+ {unparsed} unparsed. The list may be incomplete — a residual one could "
            f"be missing; treat as raise-assurance. " + note
        )
    return {
        "available": True,
        "reliable": reliable,
        "count": len(exts),
        "declared_count": declared,
        "extensions": exts,
        "residual_count": residual,
        "active_count": active,
        "unparsed_rows": unparsed,
        "_note": note,
    }


def collect_system_extensions() -> dict[str, Any]:
    # `run` reports ok=False on a nonzero exit (permission/error), so an errored
    # command never reaches the parser and is never read as a clean listing.
    r = run(["systemextensionsctl", "list"])
    if not r.get("ok"):
        return _empty(False, r.get("error") or r.get("stderr") or "command failed")
    return parse_system_extensions(r.get("stdout") or "")


@mcp.tool(name="signalgrid_system_extensions", annotations=READ_ONLY)
def signalgrid_system_extensions(
    name_contains: Annotated[str | None, Field(description="Case-insensitive filter on extension name/bundleID.")] = None,
    limit: Annotated[int, Field(ge=1, le=500, description="Max extensions to return.")] = 100,
    offset: Annotated[int, Field(ge=0, description="Pagination offset.")] = 0,
    response_format: ResponseFormat = ResponseFormat.MARKDOWN,
) -> Any:
    """Installed system extensions (endpoint-security / network) and whether any
    is STRANDED — still registered after its app is gone (state `activated
    enabled (removed)` or `terminated waiting to uninstall`), which blocks its own
    reinstall. Read-only; needs no elevation.

    Fail-safe: `available: false` means the state could not be read (never "none
    installed"); `reliable: false` means the parsed list may be incomplete (a
    residual one could be missing — raise the assurance bar); an unrecognized
    state is `unknown`, never `active`.

    Returns:
        dict with available (bool), reliable (bool), count, declared_count,
        residual_count, active_count, unparsed_rows, and extensions[] each with
        teamID, bundleID, version, name, enabled, active, state, status
        (active | pending | residual | unknown).
    """
    data = collect_system_extensions()
    exts = data.get("extensions") or []
    exts = name_filter(exts, name_contains, "name", "bundleID")
    page = paginate(exts, limit, offset)
    if response_format == ResponseFormat.JSON:
        return {
            "available": data.get("available"),
            "reliable": data.get("reliable"),
            "count": data.get("count"),
            "declared_count": data.get("declared_count"),
            "residual_count": data.get("residual_count"),
            "active_count": data.get("active_count"),
            "unparsed_rows": data.get("unparsed_rows"),
            "extensions": page["items"],
            "total": page["total"],
            "has_more": page["has_more"],
            "next_offset": page["next_offset"],
            "_note": data.get("_note"),
        }
    unparsed = data.get("unparsed_rows") or 0
    title = (
        f"System extensions (available={data.get('available')}, "
        f"reliable={data.get('reliable')}, {data.get('count')} total, "
        f"{data.get('residual_count')} residual, {data.get('active_count')} active"
        + (f", {unparsed} unparsed" if unparsed else "") + ")"
    )
    return render_page(page, response_format, title,
                       [("name", "Name"), ("bundleID", "Bundle"), ("teamID", "Team"), ("status", "Status"), ("state", "State")],
                       note=data.get("_note"))
