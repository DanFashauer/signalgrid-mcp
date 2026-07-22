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
from signalgrid_mcp.tools.security import collect_security, collect_sharing
from signalgrid_mcp.tools.software import collect_update_settings, collect_xprotect


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
                "persistence, time_machine. Pass an explicit list to customize."
            ),
        ),
    ] = None,
) -> dict[str, Any]:
    """Full device trust snapshot in a single round-trip: identity + OS +
    security + MDM + patch state by default, with optional extra sections.

    Use this first. One call instead of six, which matters when every tool
    call is a network round-trip. Drill into the focused tools afterward for
    anything that looks off. A failed section reports {"error": ...} instead
    of sinking the whole snapshot.

    Args:
        sections: optional list from {identity, os, security, sharing, mdm,
            updates, xprotect, network, persistence, time_machine}.

    Returns:
        dict keyed by section name; each value is that section's collector
        output (same shapes as the corresponding focused tools).
    """
    return build_report(sections or _DEFAULT_SECTIONS)


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
