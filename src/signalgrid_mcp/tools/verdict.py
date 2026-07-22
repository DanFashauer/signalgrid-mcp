"""On-device trust verdict — the app function, not just the raw facts.

The other tools report what a Mac's posture IS. This one makes the SignalGrid
decision about it locally: it composes the posture into one fail-safe verdict —
`allow` / `step_up` / `restrict` / `deny` — with the reasons behind it. Read-only:
it reads posture and computes, it changes nothing.

Fail-safe by construction (the same discipline the SignalGrid fabric uses):
- a disabled hardening control (SIP / FileVault / Gatekeeper / firewall) or a
  stranded security extension is a CRITICAL failure → one critical restricts, two
  or more deny;
- a control whose state could NOT be read, an unmanaged device, a stale malware
  definition, or auto-update off RAISES the bar to `step_up` — never `allow`;
- `allow` is returned ONLY when every checked control reads healthy. Unknown is
  never allowed.
"""

from __future__ import annotations

import json
import re
from typing import Any

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.tools.report import ReportSection, build_report

# The sections a verdict needs (a focused, opt-in-inclusive report).
_VERDICT_SECTIONS = [
    ReportSection.SECURITY,
    ReportSection.MDM,
    ReportSection.UPDATES,
    ReportSection.XPROTECT,
    ReportSection.SYSTEM_EXTENSIONS,
]

Verdict = str  # "allow" | "step_up" | "restrict" | "deny"


def _control(security: dict[str, Any], key: str) -> str:
    """'on' / 'off' / 'unknown' for a security control. Fail-safe: anything that
    isn't an explicit boolean is 'unknown' (never assumed on OR off)."""
    entry = security.get(key)
    enabled = entry.get("enabled") if isinstance(entry, dict) else None
    if enabled is True:
        return "on"
    if enabled is False:
        return "off"
    return "unknown"


def _xprotect_readable(xprotect: dict[str, Any]) -> bool:
    """Readable ONLY when the definition looks like a real version (digits/dots).
    A blocklist over free-form `defaults` stderr can never be complete — a missing
    key prints "The domain/default pair … does not exist", an unsubstituted format
    prints "%Su", etc. — so allowlist a plausible version and fail every other
    string closed to unknown."""
    defs = xprotect.get("xprotect_definitions")
    if not isinstance(defs, str):
        return False
    return re.fullmatch(r"[0-9][0-9.]*", defs.strip()) is not None


def compute_verdict(report: dict[str, Any]) -> dict[str, Any]:
    """Pure, deterministic. Fold a posture report into one fail-safe verdict."""
    security = report.get("security")
    security = security if isinstance(security, dict) else {}
    controls = {k: _control(security, k) for k in ("sip", "filevault", "gatekeeper", "firewall")}

    criticals: list[str] = [f"{k}_off" for k, v in controls.items() if v == "off"]
    unknowns: list[str] = [k for k, v in controls.items() if v == "unknown"]

    mdm = report.get("mdm")
    mdm = mdm if isinstance(mdm, dict) else {}
    mdm_enrolled = mdm.get("mdm_enrolled")
    # Only an explicit boolean is trusted; anything else (None, "false", 0) is
    # unreadable → raise the bar. Never treat a non-True value as enrolled.
    if mdm_enrolled is not True and mdm_enrolled is not False:
        unknowns.append("mdm")

    updates = report.get("updates")
    updates = updates if isinstance(updates, dict) else {}
    auto_check = updates.get("AutomaticCheckEnabled")
    # An unreadable update state (None / errored / absent section) must NOT pass as
    # healthy — fold it into the unknowns like every other control. Only an explicit
    # `True` is allowed to pass.
    if auto_check is not True and auto_check is not False:
        unknowns.append("updates")

    xprotect = report.get("xprotect")
    xprotect = xprotect if isinstance(xprotect, dict) else {}
    if not _xprotect_readable(xprotect):
        unknowns.append("xprotect")

    # Optional: stranded system extension (from the system_extensions section).
    sx = report.get("system_extensions")
    if isinstance(sx, dict):
        if sx.get("available") is True and sx.get("reliable") is True and isinstance(sx.get("residual_count"), int):
            if sx["residual_count"] > 0:
                criticals.append("stranded_extension")
        else:
            # Present but not trustworthy → raise the bar (never a silent pass).
            unknowns.append("system_extensions")

    reasons: list[str] = []
    reasons += [f"critical: {c}" for c in criticals]
    if mdm_enrolled is False:
        reasons.append("device is not MDM-enrolled (unmanaged)")
    if auto_check is False:
        reasons.append("automatic update checks are disabled")
    reasons += [f"could not read: {u}" for u in unknowns]

    # The ladder — worst wins, fail-safe.
    if len(criticals) >= 2:
        verdict = "deny"
    elif len(criticals) == 1:
        verdict = "restrict"
    elif mdm_enrolled is False or auto_check is False or unknowns:
        verdict = "step_up"
    else:
        verdict = "allow"
        reasons.append("all checked controls read healthy")

    return {
        "verdict": verdict,
        "reasons": reasons,
        "criticals": criticals,
        "unknowns": unknowns,
        "controls": controls,
        "mdm_enrolled": mdm_enrolled,
        "_note": (
            "Fail-safe: unknown is never 'allow'. One critical restricts; two or "
            "more deny. This is a local, single-device verdict; the SignalGrid "
            "fabric fuses it with identity, custody, and other signals for the "
            "final decision."
        ),
    }


@mcp.tool(name="signalgrid_trust_verdict", annotations=READ_ONLY)
def signalgrid_trust_verdict() -> dict[str, Any]:
    """The SignalGrid decision for THIS Mac, computed on-device: one fail-safe
    verdict — allow / step_up / restrict / deny — plus the reasons.

    Read-only. Composes security posture, MDM enrollment, update settings,
    XProtect currency, and stranded system extensions. Unknown is never 'allow':
    a control that could not be read raises the bar to step_up; a disabled
    hardening control or a stranded security extension restricts (two or more
    deny).

    Returns:
        dict with verdict (str), reasons (list), criticals, unknowns, controls,
        mdm_enrolled, and a _note. This is a single-device verdict; the fabric
        fuses it with other signals for the final decision.
    """
    return compute_verdict(build_report(_VERDICT_SECTIONS))


@mcp.resource("signalgrid://verdict")
def verdict_resource() -> str:
    """The on-device trust verdict as a JSON resource, so a connecting fabric can
    pull one decision (read-only, computed from live posture)."""
    return json.dumps(compute_verdict(build_report(_VERDICT_SECTIONS)), indent=2, default=str)
