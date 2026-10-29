"""Inspector protocol health never promotes an MCP error into live evidence."""
import asyncio
from contextlib import asynccontextmanager
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace as NS
import uuid
import pytest


def exercise(monkeypatch, capsys, *, is_error=False, body='{"value": 7}', read_only=True):
    source = Path(os.environ.get("SIGNALGRID_INSPECTOR_UNDER_TEST", Path(__file__).parents[1] / "tools/inspect_stdio.py"))
    spec = importlib.util.spec_from_file_location("inspector_case_" + uuid.uuid4().hex, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    target = "signalgrid_device_identity"

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def initialize(self):
            return NS(serverInfo=NS(name="frozen-inspector-fixture", version="1"))

        async def list_tools(self):
            return NS(tools=[NS(name=name,
                               annotations=NS(readOnlyHint=read_only, destructiveHint=False),
                               inputSchema={"type": "object"})
                             for name in sorted(module.EXPECTED_TOOLS)])

        async def call_tool(self, name, args):
            calls.append((name, args))
            text, error = (body, is_error) if name == target else ('{"unknown": null}', False)
            return NS(content=[NS(type="text", text=text)], isError=error)

    @asynccontextmanager
    async def stdio(_params):
        yield object(), object()

    monkeypatch.setattr(module, "stdio_client", stdio)
    monkeypatch.setattr(module, "ClientSession", lambda *_args: Session())
    monkeypatch.setattr(sys, "argv", ["inspect_stdio.py", "--json"])
    status = asyncio.run(module.run())
    output = capsys.readouterr()
    data, _end = json.JSONDecoder().raw_decode(output.out)
    row = next(row for row in data["tools"] if row["tool"] == target)
    return status, data, row, calls


@pytest.mark.parametrize("body", [
    "Error: permission denied",
    "Error: unknown operation",
    "Error: temporarily unavailable",
])
def test_mcp_errors_are_never_values_or_healthy_protocol_success(monkeypatch, capsys, body):
    status, data, row, _calls = exercise(monkeypatch, capsys, is_error=True, body=body)
    assert status == 1
    assert row["resolved"] == "error"
    assert row["live_verified"] is False
    assert data["summary"]["tool_errors"] == ["signalgrid_device_identity"]


def test_codesign_probe_supplies_the_required_bounded_path(monkeypatch, capsys):
    _status, _data, _row, calls = exercise(monkeypatch, capsys)
    assert [args for name, args in calls if name == "signalgrid_codesign_inspect"] == [{"path": "/bin/ls"}]


def test_honest_unknown_is_protocol_healthy_without_live_claim(monkeypatch, capsys):
    status, data, row, _calls = exercise(monkeypatch, capsys, body='{"unknown": null}')
    assert status == 0
    assert row["resolved"] == "unknown"
    assert data["summary"]["resolved_unknown"] == len(data["tools"])


def test_successful_text_classification_is_still_only_a_heuristic(monkeypatch, capsys):
    status, _data, row, _calls = exercise(monkeypatch, capsys)
    assert status == 0
    assert row["resolved"] == "value"
    assert row["live_verified"] is False
    assert row["classification_basis"] == "text_marker_heuristic"


def test_existing_read_only_requirement_remains_a_health_gate(monkeypatch, capsys):
    status, data, _row, _calls = exercise(monkeypatch, capsys, read_only=False)
    assert status == 1
    assert data["summary"]["all_read_only"] is False

