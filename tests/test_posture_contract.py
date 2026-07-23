"""Cross-repo posture-report CONTRACT (producer side).

Proves ``signalgrid_posture_report()`` still EMITS the shape the SignalGrid
Review-Hub ``macos-posture`` connector consumes: every required top-level section,
and every required security control under ``security``. The connector (Review-Hub)
proves it CONSUMES that shape; this proves the server keeps PRODUCING it.

Review-Hub's ``pnpm run verify:all`` points ``SIGNALGRID_CONTRACT_PATH`` at the one
canonical contract file so both repos check the SAME contract (single source of
truth). Run standalone (no env var), a built-in default of the same core sections/
controls still guards it — so this test is meaningful in this repo's own CI too.

It asserts SHAPE only (which keys are present), never values: off-macOS every
control reads unknown, and that is exactly the degradation path — the contract is
about the report's structure, which must stay stable for the connector.
"""

from __future__ import annotations

import json
import os

from signalgrid_mcp.tools.report import signalgrid_posture_report

# The contract's core shape. When Review-Hub's verify:all provides the canonical
# file via SIGNALGRID_CONTRACT_PATH these are overridden from it (single source of
# truth); otherwise this built-in default guards the same core sections/controls.
_DEFAULT_REQUIRED_SECTIONS = ["os", "security", "mdm", "updates", "xprotect"]
_DEFAULT_REQUIRED_SECURITY_CONTROLS = ["sip", "filevault", "gatekeeper", "firewall"]


def _load_contract() -> tuple[list[str], list[str]]:
    path = os.environ.get("SIGNALGRID_CONTRACT_PATH")
    if not path:
        return _DEFAULT_REQUIRED_SECTIONS, _DEFAULT_REQUIRED_SECURITY_CONTROLS
    with open(path, encoding="utf-8") as f:
        contract = json.load(f)
    return contract["requiredSections"], contract["requiredSecurityControls"]


def test_posture_report_emits_the_contract_shape():
    required_sections, required_controls = _load_contract()
    report = signalgrid_posture_report()
    # Called directly the tool returns the raw dict; via a FastMCP client it is
    # wrapped under 'result'. Handle both so the test is transport-agnostic.
    body = report.get("result", report) if isinstance(report, dict) else report
    assert isinstance(body, dict), "posture_report must return a dict"
    for section in required_sections:
        assert section in body, f"posture_report is missing contract section '{section}'"
    security = body.get("security")
    assert isinstance(security, dict), "the 'security' section must be a dict"
    for control in required_controls:
        assert control in security, f"the 'security' section is missing contract control '{control}'"
