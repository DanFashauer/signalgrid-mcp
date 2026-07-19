"""Core security posture and sharing-service exposure."""

from __future__ import annotations

from typing import Any

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import probe

UNKNOWN_NOTE = (
    "enabled=null means the check could not run (missing binary, timeout, or "
    "needs elevation) -- it does NOT mean the control is off. Anything in "
    "_unknown is an unresolved signal, not a failure."
)

# name -> (argv, enabled needle, disabled needle). Matched lowercased; when
# neither matches, the state is unknown (None) rather than a guess.
POSTURE_CHECKS: dict[str, tuple[list[str], str, str]] = {
    "sip": (["csrutil", "status"], "enabled", "disabled"),
    "filevault": (["fdesetup", "status"], "is on", "is off"),
    "gatekeeper": (["spctl", "--status"], "enabled", "disabled"),
    "firewall": (
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        "enabled",
        "disabled",
    ),
    "firewall_stealth": (
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
        "enabled",
        "disabled",
    ),
    "firewall_block_all": (
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
        "enabled",
        "disabled",
    ),
}

# Sharing/remote-access services: name -> (argv, enabled needle, disabled needle)
# Both needles are matched against lowercased output; when NEITHER matches
# (permission error, unexpected text) the state is unknown, never a guess.
SHARING_CHECKS: dict[str, tuple[list[str], str, str]] = {
    "remote_login_ssh": (["systemsetup", "-getremotelogin"], ": on", ": off"),
    "remote_apple_events": (["systemsetup", "-getremoteappleevents"], ": on", ": off"),
    "screen_sharing": (
        ["launchctl", "print", "system/com.apple.screensharing"],
        "state = running",
        "could not find service",
    ),
    "smb_file_sharing": (
        ["launchctl", "print", "system/com.apple.smbd"],
        "state = running",
        "could not find service",
    ),
    "remote_management_ard": (
        ["launchctl", "print", "system/com.apple.RemoteDesktop.agent"],
        "state = running",
        "could not find service",
    ),
}


def classify(raw: str, ok: bool, enabled_needle: str, disabled_needle: str) -> bool | None:
    """Three-way classification: True / False / None(unknown).

    An explicit needle must match for a True or False verdict; anything else
    (permission errors, 'You need administrator access', garbage) is unknown.
    """
    if not ok:
        return None
    lower = raw.lower()
    if enabled_needle in lower:
        return True
    if disabled_needle in lower:
        return False
    return None


def _evaluate_three_way(checks: dict[str, tuple[list[str], str, str]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    unknown: list[str] = []
    for name, (cmd, on_needle, off_needle) in checks.items():
        p = probe(cmd)
        enabled = classify(p["raw"], p["ok"], on_needle, off_needle)
        if enabled is None:
            unknown.append(name)
        out[name] = {"raw": p["raw"], "enabled": enabled}
    out["_unknown"] = unknown
    out["_note"] = UNKNOWN_NOTE
    return out


def collect_security() -> dict[str, Any]:
    return _evaluate_three_way(POSTURE_CHECKS)


def collect_sharing() -> dict[str, Any]:
    return _evaluate_three_way(SHARING_CHECKS)


@mcp.tool(name="signalgrid_security_posture", annotations=READ_ONLY)
def signalgrid_security_posture() -> dict[str, Any]:
    """Core security posture: SIP, FileVault, Gatekeeper, and application firewall
    (global state, stealth mode, block-all).

    Each control reports {raw, enabled}. `enabled` is null when the check could
    not be completed -- null means UNKNOWN, never "off". Treat null as a signal
    to investigate (often the check needs elevation), not as a grade.

    Returns:
        dict mapping control name -> {"raw": str, "enabled": bool | None},
        plus "_unknown" (list of controls that could not be evaluated) and
        "_note" explaining the null semantics.
    """
    return collect_security()


@mcp.tool(name="signalgrid_sharing_services", annotations=READ_ONLY)
def signalgrid_sharing_services() -> dict[str, Any]:
    """Remote-access exposure: SSH remote login, remote Apple events, Screen
    Sharing, SMB file sharing, and Apple Remote Desktop.

    An enabled sharing service widens the device's attack surface; on a
    managed endpoint most of these should be off. Same null-means-unknown
    semantics as signalgrid_security_posture (systemsetup checks in
    particular often need elevation and will report null without it).

    Returns:
        dict mapping service name -> {"raw": str, "enabled": bool | None},
        plus "_unknown" and "_note".
    """
    return collect_sharing()
