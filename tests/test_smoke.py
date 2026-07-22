"""Smoke tests: server registration, schemas, and graceful degradation.

These tests run anywhere (including Linux CI). On non-macOS hosts every
macOS binary is missing, which is exactly the degradation path we want to
prove never crashes a tool.
"""

from __future__ import annotations

import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from signalgrid_mcp import tools  # noqa: F401
from signalgrid_mcp.app import mcp
from signalgrid_mcp.formatting import name_filter, paginate

EXPECTED_TOOLS = {
    "signalgrid_device_identity",
    "signalgrid_os_info",
    "signalgrid_security_posture",
    "signalgrid_sharing_services",
    "signalgrid_mdm_status",
    "signalgrid_codesign_inspect",
    "signalgrid_software_updates",
    "signalgrid_xprotect_status",
    "signalgrid_install_history",
    "signalgrid_network_posture",
    "signalgrid_listening_services",
    "signalgrid_launch_items",
    "signalgrid_kernel_extensions",
    "signalgrid_system_extensions",
    "signalgrid_local_users",
    "signalgrid_installed_apps",
    "signalgrid_process_snapshot",
    "signalgrid_removable_media",
    "signalgrid_posture_report",
    "signalgrid_trust_verdict",
}


@pytest.mark.anyio
async def test_all_tools_registered_and_read_only():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.list_tools()
        names = {t.name for t in result.tools}
        assert EXPECTED_TOOLS <= names, f"missing: {EXPECTED_TOOLS - names}"
        for t in result.tools:
            assert t.annotations is not None, f"{t.name} has no annotations"
            assert t.annotations.readOnlyHint is True
            assert t.annotations.destructiveHint is False
            assert t.description, f"{t.name} has no description"


@pytest.mark.anyio
async def test_posture_report_degrades_gracefully():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool("signalgrid_posture_report", {})
        assert not result.isError
        report = result.structuredContent
        assert report is not None
        # dict-returning tools are wrapped under 'result' by FastMCP
        body = report.get("result", report)
        for section in ("identity", "os", "security", "mdm", "updates", "xprotect"):
            assert section in body
        # system_extensions is opt-in (security-relevant but slower) — it must NOT
        # be in the fast default report, only available on request.
        assert "system_extensions" not in body


def test_system_extensions_is_optin_not_default():
    import sys

    from signalgrid_mcp.tools.report import _DEFAULT_SECTIONS, ReportSection, build_report

    assert ReportSection.SYSTEM_EXTENSIONS not in _DEFAULT_SECTIONS
    # …but requestable. The behaviour is host-dependent, so assert per platform:
    section = build_report([ReportSection.SYSTEM_EXTENSIONS])["system_extensions"]
    if sys.platform == "darwin":
        # On macOS the probe genuinely runs (systemextensionsctl needs no root), so
        # it reports available with a REAL integer count — never a fabricated None.
        assert section.get("available") is True
        assert isinstance(section.get("count"), int)
    else:
        # Off-macOS it degrades fail-safe — available False, never "none installed".
        assert section.get("available") is False


@pytest.mark.anyio
async def test_security_posture_null_semantics_off_macos():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool("signalgrid_security_posture", {})
        assert not result.isError
        body = result.structuredContent.get("result", result.structuredContent)
        assert "_note" in body
        for name, val in body.items():
            if name.startswith("_"):
                continue
            assert set(val) == {"raw", "enabled"}


@pytest.mark.anyio
async def test_codesign_rejects_relative_path():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool(
            "signalgrid_codesign_inspect", {"path": "../etc/passwd"}
        )
        assert result.isError  # pattern requires an absolute path


@pytest.mark.anyio
async def test_process_snapshot_pagination_json():
    async with create_connected_server_and_client_session(mcp._mcp_server) as client:
        result = await client.call_tool(
            "signalgrid_process_snapshot",
            {"limit": 3, "offset": 0, "response_format": "json"},
        )
        assert not result.isError
        payload = json.loads(result.content[0].text)
        assert {"total", "count", "offset", "items", "has_more", "next_offset"} <= set(payload)
        assert payload["count"] <= 3


def test_paginate_envelope():
    page = paginate(list(range(10)), limit=4, offset=8)
    assert page["total"] == 10
    assert page["count"] == 2
    assert page["has_more"] is False
    assert page["next_offset"] is None
    mid = paginate(list(range(10)), limit=4, offset=4)
    assert mid["has_more"] is True and mid["next_offset"] == 8


def test_name_filter():
    items = [{"name": "Google Chrome"}, {"name": "Safari"}]
    assert name_filter(items, "chrome", "name") == [{"name": "Google Chrome"}]
    assert name_filter(items, None, "name") == items
