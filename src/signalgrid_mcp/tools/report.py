"""The one-call aggregate posture report, plus a resource alias."""

from __future__ import annotations

import json
from enum import Enum
from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.tools.backup import collect_time_machine
from signalgrid_mcp.tools.identity import collect_identity, collect_os
from signalgrid_mcp.tools.launchd import collect_persistence_summary
from signalgrid_mcp.tools.mdm import collect_mdm
from signalgrid_mcp.tools.network import collect_network
from signalgrid_mcp.tools.screen_lock import collect_screen_lock
from signalgrid_mcp.tools.security import collect_security, collect_sharing
from signalgrid_mcp.tools.software import collect_update_settings, collect_xprotect
from signalgrid_mcp.tools.sysext import collect_system_extensions


class ReportSection(str, Enum):
    IDENTITY = "identity"
    OS = "os"
    SECURITY = "security"
    SHARING = "sharing"
    MDM = "mdm"
    UPDATES = "updates"
    XPROTECT = "xprotect"
    NETWORK = "network"
    PERSISTENCE = "persistence"
    TIME_MACHINE = "time_machine"
    SYSTEM_EXTENSIONS = "system_extensions"
    SCREEN_LOCK = "screen_lock"


_COLLECTORS = {
    ReportSection.IDENTITY: collect_identity,
    ReportSection.OS: collect_os,
    ReportSection.SECURITY: collect_security,
    ReportSection.SHARING: collect_sharing,
    ReportSection.MDM: collect_mdm,
    ReportSection.UPDATES: collect_update_settings,
    ReportSection.XPROTECT: collect_xprotect,
    ReportSection.NETWORK: collect_network,
    ReportSection.PERSISTENCE: collect_persistence_summary,
    ReportSection.TIME_MACHINE: collect_time_machine,
    ReportSection.SYSTEM_EXTENSIONS: collect_system_extensions,
    ReportSection.SCREEN_LOCK: collect_screen_lock,
}

# Fast, high-signal default. network/persistence add noise; sharing's
# systemsetup probes can be slow -- opt in via `sections` when needed.
_DEFAULT_SECTIONS = [
    ReportSection.IDENTITY,
    ReportSection.OS,
    ReportSection.SECURITY,
    ReportSection.MDM,
    ReportSection.UPDATES,
    ReportSection.XPROTECT,
]


def build_report(sections: list[ReportSection]) -> dict[str, Any]:
    report: dict[str, Any] = {}
    for section in sections:
        try:
            report[section.value] = _COLLECTORS[section]()
        except Exception as e:  # noqa: BLE001 — one bad section must not sink the report
            report[section.value] = {"error": f"{type(e).__name__}: {e}"}
    return report


@mcp.tool(name="signalgrid_posture_report", annotations=READ_ONLY)
def signalgrid_posture_report(
    sections: Annotated[
        list[ReportSection] | None,
        Field(
            description=(
                "Which sections to include. Default: identity, os, security, "
                "mdm, updates, xprotect. Also available: sharing, network, "
                "persistence, time_machine, system_extensions, screen_lock. Pass "
                "an explicit list to customize."
            ),
        ),
    ] = None,
    include_verdict: Annotated[
        bool,
        Field(
            description=(
                "Also fold the posture into the fail-safe SignalGrid verdict "
                "(allow / step_up / restrict / deny) under a 'verdict' key. "
                "Default False (the report stays purely factual). When True, the "
                "sections the verdict needs (security, mdm, updates, xprotect, "
                "system_extensions) are collected even if not in `sections`."
            ),
        ),
    ] = False,
) -> dict[str, Any]:
    """Full device trust snapshot in a single round-trip: identity + OS +
    security + MDM + patch state by default, with optional extra sections.

    Use this first. One call instead of six, which matters when every tool
    call is a network round-trip. Drill into the focused tools afterward for
    anything that looks off. A failed section reports {"error": ...} instead
    of sinking the whole snapshot.

    Set include_verdict=True to also get the on-device SignalGrid decision as a
    'verdict' summary alongside the raw facts — the same fail-safe fold as
    signalgrid_trust_verdict (unknown is never 'allow'). The verdict is a derived
    summary, never a collected signal, so it is absent unless explicitly asked for.

    Args:
        sections: optional list from {identity, os, security, sharing, mdm,
            updates, xprotect, network, persistence, time_machine,
            system_extensions, screen_lock}.
        include_verdict: attach the folded allow/step_up/restrict/deny verdict.

    Returns:
        dict keyed by section name; each value is that section's collector
        output (same shapes as the corresponding focused tools). With
        include_verdict, an extra 'verdict' key holds the folded decision.
    """
    selected = list(sections or _DEFAULT_SECTIONS)
    if not include_verdict:
        return build_report(selected)
    # Function-local import breaks the module cycle (verdict.py imports this module
    # at top). The verdict is only honest over the sections it grades — pull them
    # in (deduped) even if the caller narrowed `sections`, so the fold sees real
    # data instead of fail-safing everything to unknown.
    from signalgrid_mcp.tools.verdict import _VERDICT_SECTIONS, compute_verdict

    for s in _VERDICT_SECTIONS:
        if s not in selected:
            selected.append(s)
    report = build_report(selected)
    report["verdict"] = compute_verdict(report)
    return report


@mcp.resource("signalgrid://posture")
def posture_resource() -> str:
    """The default posture report as a JSON resource."""
    return json.dumps(build_report(_DEFAULT_SECTIONS), indent=2, default=str)


@mcp.resource("signalgrid://sourcing")
def sourcing_resource() -> str:
    """How this server's macOS signals reach the SignalGrid fabric — the
    grid_collected sourcing manifest (device-independent, safe to read anywhere).
    Lets a connecting fabric discover each signal's provenance and fidelity."""
    from signalgrid_mcp.sourcing import sourcing_json

    return sourcing_json()
