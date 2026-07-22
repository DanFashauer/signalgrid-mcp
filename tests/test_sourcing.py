"""The sourcing manifest must stay honest and in sync with the report.

These run on any OS — the manifest is pure data, no device access.
"""

from __future__ import annotations

import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from signalgrid_mcp import tools  # noqa: F401  (registers the resource)
from signalgrid_mcp.app import mcp
import pytest as _pytest

from signalgrid_mcp.sourcing import (
    SOURCING_MANIFEST,
    SignalSource,
    fidelity_for,
    sourcing_document,
    sourcing_summary,
)
from signalgrid_mcp.tools.report import ReportSection


def test_manifest_is_a_bijection_with_report_sections():
    """Every report section is sourced exactly once, and no manifest entry
    describes a section that no longer exists. This is the anti-drift gate: add
    a ReportSection without a manifest entry (or vice versa) and this fails."""
    manifest_sections = [s.section for s in SOURCING_MANIFEST]
    report_sections = [s.value for s in ReportSection]

    assert sorted(manifest_sections) == sorted(report_sections), (
        "manifest sections and ReportSection have diverged: "
        f"only-in-manifest={set(manifest_sections) - set(report_sections)}, "
        f"only-in-report={set(report_sections) - set(manifest_sections)}"
    )
    # Exactly once each — no section double-sourced.
    assert len(manifest_sections) == len(set(manifest_sections))


def test_signal_ids_are_unique():
    ids = [s.signal_id for s in SOURCING_MANIFEST]
    assert len(ids) == len(set(ids)), "duplicate signal_id in the manifest"


def test_every_signal_is_grid_collected():
    """This server is the on-device collector: every signal it produces is, by
    definition, grid_collected. If a future entry claims api/native, that's a
    category error to catch here — those come from a vendor's own surface, not
    from reading the device."""
    for s in SOURCING_MANIFEST:
        assert s.method == "grid_collected", (
            f"{s.signal_id} is {s.method!r}; an on-device read is grid_collected"
        )


def test_fidelity_matches_method_and_is_never_overstated():
    """Fidelity is derived from method, never hand-set. grid_collected is medium
    (or low) — never high. The fabric must not over-trust a self-collected
    signal, so 'high' (reserved for vendor api/native) must never appear here."""
    for s in SOURCING_MANIFEST:
        assert s.fidelity == fidelity_for(s.method), (
            f"{s.signal_id}: fidelity {s.fidelity!r} != derived for {s.method!r}"
        )
        assert s.fidelity != "high", (
            f"{s.signal_id}: grid_collected must never read as high fidelity"
        )
        assert s.fidelity in {"medium", "low"}


def test_every_entry_names_what_it_feeds():
    for s in SOURCING_MANIFEST:
        assert s.name.strip(), f"{s.section} has no name"
        assert s.feeds.strip(), f"{s.signal_id} does not say what it feeds"
        assert s.system == "macOS"


def test_summary_is_internally_consistent():
    summary = sourcing_summary()
    assert summary["total"] == len(SOURCING_MANIFEST)
    assert summary["grid_collected"] == summary["total"]
    assert summary["vendor_integrated"] == 0
    assert summary["wireable"] == summary["total"]
    assert summary["api"] == 0 and summary["native"] == 0 and summary["unavailable"] == 0


def test_document_is_json_serializable_and_shaped():
    doc = sourcing_document()
    round_tripped = json.loads(json.dumps(doc))
    assert round_tripped["server"] == "signalgrid-mcp"
    assert round_tripped["acquisition_method"] == "grid_collected"
    assert len(round_tripped["signals"]) == len(SOURCING_MANIFEST)


def test_fidelity_for_covers_every_method():
    assert fidelity_for("api") == "high"
    assert fidelity_for("native") == "high"
    assert fidelity_for("grid_collected") == "medium"
    assert fidelity_for("grid_collected", degraded=True) == "low"
    assert fidelity_for("unavailable") == "none"
    # Unknown provenance fails closed — never inherits a confidence it didn't earn.
    assert fidelity_for("mystery") == "none"  # type: ignore[arg-type]


def test_degraded_grid_collected_source_is_constructible_at_low():
    """The degraded→low path is real, not just advertised: a coarse grid-collected
    proxy constructs with fidelity 'low' and is rejected at any other fidelity."""
    s = SignalSource(
        section="security",
        signal_id="macos.example_proxy",
        name="coarse derived proxy",
        system="macOS",
        method="grid_collected",
        fidelity="low",
        feeds="example",
        degraded=True,
    )
    assert s.fidelity == "low"
    with _pytest.raises(ValueError):
        SignalSource(
            section="security",
            signal_id="macos.example_proxy",
            name="coarse derived proxy",
            system="macOS",
            method="grid_collected",
            fidelity="medium",  # wrong for degraded=True
            feeds="example",
            degraded=True,
        )


def test_unknown_method_is_rejected():
    with _pytest.raises(ValueError):
        SignalSource(
            section="security",
            signal_id="macos.bogus",
            name="bogus",
            system="macOS",
            method="carrier_pigeon",  # type: ignore[arg-type]
            fidelity="none",
            feeds="example",
        )


@pytest.mark.anyio
async def test_sourcing_resource_is_registered_and_valid():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        listed = await client.list_resources()
        uris = {str(r.uri) for r in listed.resources}
        assert "signalgrid://sourcing" in uris, f"resource not registered; have {uris}"

        read = await client.read_resource("signalgrid://sourcing")
        payload = json.loads(read.contents[0].text)
        assert payload["acquisition_method"] == "grid_collected"
        assert len(payload["signals"]) == len(SOURCING_MANIFEST)
