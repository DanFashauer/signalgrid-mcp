"""How SignalGrid's macOS signals reach the Grid — the sourcing manifest.

SignalGrid's decision fabric classifies every signal by *how* it is obtained,
because a verdict is only ever as trustworthy as its inputs' provenance:

  • api            — the source system exposes a read API the Grid polls.
  • native         — a first-party/partner integration feeds it (webhook, SCIM…).
  • grid_collected — no usable API/native hook exists, so SignalGrid DOES THE
                     LIFTING itself with an on-device collector. Delivered — at a
                     lower confidence and higher setup cost than a vendor API.
  • unavailable    — no path at all. A real gap, surfaced, never faked healthy.

**This MCP server IS the `grid_collected` path for macOS device trust.** SIP,
FileVault, Gatekeeper, MDM enrollment, XProtect currency and the rest are facts
about a Mac that no cloud API hands you faithfully in real time — you have to
read them on the device. That is exactly what a grid-collected source is.

So every signal this server produces is classified `grid_collected` with
`medium` fidelity — deliberately *not* `high`. The reads are authoritative
(they come straight from the OS), but the fabric never over-trusts a signal it
had to collect itself, and several probes degrade to `unknown` without elevation
(see the README's permissions note). Medium is the honest, fail-safe label.

The manifest below maps each posture-report section to the fabric signal it
feeds. It is exposed over MCP as the resource ``signalgrid://sourcing`` so a
connecting fabric (or agent) can *discover* how these signals plug in, and
``tests/test_sourcing.py`` pins it as a bijection with the report *sections* so
no section can go un-sourced and no stale entry can linger. (The per-signal
names/`feeds` text are descriptive prose, not machine-checked against collector
output.)

No device access: importing this module runs no subprocess and reads nothing off
the machine — it is safe to import from tests or tooling. It is not dependency-
free, though: it imports ``ReportSection`` from ``tools.report``, which pulls in
the tool graph transitively.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Literal

from signalgrid_mcp.tools.report import ReportSection

# The fabric's four acquisition paths. Kept as a plain tuple (not an enum) so the
# manifest reads as data and the values match the TypeScript fabric verbatim.
AcquisitionMethod = Literal["api", "native", "grid_collected", "unavailable"]
Fidelity = Literal["high", "medium", "low", "none"]

_VALID_METHODS: frozenset[str] = frozenset(
    {"api", "native", "grid_collected", "unavailable"}
)


def fidelity_for(method: AcquisitionMethod, degraded: bool = False) -> Fidelity:
    """Fidelity a source earns from its acquisition path — mirrors the fabric's
    ``fidelityOf`` exactly so the two never disagree.

    api/native → high; grid_collected → medium (low if a coarse/degraded proxy);
    unavailable → none. An unknown method fails closed to ``none`` — a signal of
    unrecognized provenance is never handed a confidence it did not earn.
    """
    if method == "api" or method == "native":
        return "high"
    if method == "grid_collected":
        return "low" if degraded else "medium"
    return "none"


@dataclass(frozen=True)
class SignalSource:
    """One macOS posture section and how it reaches the SignalGrid fabric."""

    # The report section this describes (ReportSection value, e.g. "security").
    section: str
    # Stable fabric signal id (matches Flow.requiredSignals / SignalState.id).
    signal_id: str
    # Human-readable signal name.
    name: str
    # The system the signal comes from — always macOS for this collector.
    system: str
    # How the Grid obtains it. Always grid_collected here (on-device collection).
    method: AcquisitionMethod
    # Confidence given the acquisition path. Derived, never hand-set — see __post_init__.
    fidelity: Fidelity
    # The fabric decision dimension this signal informs.
    feeds: str
    # A grid_collected signal that is an especially coarse/derived proxy — pins
    # fidelity to "low" instead of "medium" (mirrors the fabric's `degraded`).
    degraded: bool = False

    def __post_init__(self) -> None:
        # Reject an unrecognized acquisition path outright — never let a signal of
        # unknown provenance into the manifest on the strength of failing closed.
        if self.method not in _VALID_METHODS:
            raise ValueError(
                f"{self.signal_id}: unknown acquisition method {self.method!r}; "
                f"expected one of {sorted(_VALID_METHODS)}"
            )
        # Fidelity is a function of (method, degraded), not a free field — pin it
        # so a hand edit can't quietly claim a confidence the path didn't earn.
        derived = fidelity_for(self.method, self.degraded)  # type: ignore[arg-type]
        if self.fidelity != derived:
            raise ValueError(
                f"{self.signal_id}: fidelity {self.fidelity!r} disagrees with "
                f"method {self.method!r} (degraded={self.degraded}, expected {derived!r})"
            )


def _src(
    section: ReportSection,
    signal_id: str,
    name: str,
    method: AcquisitionMethod,
    feeds: str,
    degraded: bool = False,
) -> SignalSource:
    return SignalSource(
        section=section.value,
        signal_id=signal_id,
        name=name,
        system="macOS",
        method=method,
        fidelity=fidelity_for(method, degraded),
        feeds=feeds,
        degraded=degraded,
    )


# One entry per ReportSection. test_sourcing.py asserts this is a bijection with
# ReportSection — no section can go un-sourced, no stale entry can linger.
SOURCING_MANIFEST: tuple[SignalSource, ...] = (
    _src(
        ReportSection.IDENTITY,
        "macos.device_identity",
        "Device identity (serial / UUID / chip / activation lock)",
        "grid_collected",
        "Device inventory & custody binding — which physical Mac this verdict is about.",
    ),
    _src(
        ReportSection.OS,
        "macos.os_build",
        "OS name / version / build",
        "grid_collected",
        "Vulnerability & update-enforcement currency — is this build still supported and patched.",
    ),
    _src(
        ReportSection.SECURITY,
        "macos.security_posture",
        "SIP / FileVault / Gatekeeper / firewall",
        "grid_collected",
        "Security-baseline posture — the core hardening controls that gate an allow verdict.",
    ),
    _src(
        ReportSection.SHARING,
        "macos.remote_access",
        "Remote access exposure (SSH / Screen Sharing / SMB / ARD)",
        "grid_collected",
        "Attack-surface / network posture — remotely reachable services widen blast radius.",
    ),
    _src(
        ReportSection.MDM,
        "macos.mdm_enrollment",
        "MDM / DEP enrollment & installed profiles",
        "grid_collected",
        "Management & enforcement — is this device actually under managed control.",
    ),
    _src(
        ReportSection.UPDATES,
        "macos.update_state",
        "Software update / auto-update settings",
        "grid_collected",
        "Update-enforcement currency — the silent-no-op guard (is patching actually happening).",
    ),
    _src(
        ReportSection.XPROTECT,
        "macos.malware_defs",
        "XProtect / MRT malware-definition currency",
        "grid_collected",
        "Threat-defense freshness — stale definitions raise the assurance bar.",
    ),
    _src(
        ReportSection.NETWORK,
        "macos.network_posture",
        "DNS / proxies / VPNs / interfaces",
        "grid_collected",
        "Network / NAC posture — where this device sits and how its traffic is routed.",
    ),
    _src(
        ReportSection.PERSISTENCE,
        "macos.persistence",
        "launchd items that persist across reboot",
        "grid_collected",
        "Device / threat posture — unexpected persistence is a tamper/compromise signal.",
    ),
    _src(
        ReportSection.TIME_MACHINE,
        "macos.backup_state",
        "Time Machine backup configuration & recency",
        "grid_collected",
        "Resilience / recovery posture — can this device be restored after loss or compromise.",
    ),
    _src(
        ReportSection.SYSTEM_EXTENSIONS,
        "macos.system_extensions",
        "System extensions — stranded / conflicting security agents",
        "grid_collected",
        "Endpoint-hardening integrity — a security agent still registered after removal (blocks reinstall) or two conflicting agents.",
    ),
)


def sourcing_manifest() -> list[dict[str, object]]:
    """The manifest as plain dicts (JSON-ready)."""
    return [asdict(s) for s in SOURCING_MANIFEST]


def sourcing_summary() -> dict[str, int]:
    """Roll up how this server's signals are sourced — mirrors the fabric's
    ``summarizeSourcing``. Every signal here is grid_collected, so ``wireable``
    equals the total and ``vendor_integrated`` is zero: SignalGrid does all of
    this lifting itself on the device."""
    api = sum(1 for s in SOURCING_MANIFEST if s.method == "api")
    native = sum(1 for s in SOURCING_MANIFEST if s.method == "native")
    grid_collected = sum(1 for s in SOURCING_MANIFEST if s.method == "grid_collected")
    unavailable = sum(1 for s in SOURCING_MANIFEST if s.method == "unavailable")
    return {
        "total": len(SOURCING_MANIFEST),
        "api": api,
        "native": native,
        "grid_collected": grid_collected,
        "unavailable": unavailable,
        "wireable": api + native + grid_collected,
        "vendor_integrated": api + native,
    }


def sourcing_document() -> dict[str, object]:
    """The full resource payload: what this is, the signals, and the summary."""
    return {
        "server": "signalgrid-mcp",
        "system": "macOS",
        "acquisition_method": "grid_collected",
        "explanation": (
            "This MCP server is SignalGrid's grid_collected acquisition path for "
            "macOS device trust: it reads authoritative on-device state that no "
            "cloud API exposes faithfully in real time. Signals are classified "
            "medium fidelity — authoritative but self-collected, and the fabric "
            "never over-trusts a signal it had to collect itself."
        ),
        "signals": sourcing_manifest(),
        "summary": sourcing_summary(),
    }


def sourcing_json() -> str:
    """The sourcing document as pretty JSON (used by the MCP resource)."""
    return json.dumps(sourcing_document(), indent=2)
