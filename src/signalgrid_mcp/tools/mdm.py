"""MDM enrollment and configuration profiles."""

from __future__ import annotations

from typing import Any

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import text


def parse_enrollment(raw: str) -> dict[str, bool | None]:
    """Parse `profiles status -type enrollment` output.

    Typical output:
        Enrolled via DEP: Yes
        MDM enrollment: Yes (User Approved)

    Returns booleans that are None when the state cannot be determined
    (command missing, permission error, unrecognized output).
    """
    lower = raw.lower()
    if "enrollment" not in lower:
        # Command failed or produced something we don't recognize.
        return {"mdm_enrolled": None, "dep_enrolled": None}

    def flag(prefix: str) -> bool | None:
        for line in lower.splitlines():
            line = line.strip()
            if line.startswith(prefix):
                value = line[len(prefix):].strip()
                if value.startswith("yes"):
                    return True
                if value.startswith("no"):
                    return False
                return None
        return None

    return {
        "mdm_enrolled": flag("mdm enrollment:"),
        "dep_enrolled": flag("enrolled via dep:"),
    }


def collect_mdm() -> dict[str, Any]:
    enrollment = text(["profiles", "status", "-type", "enrollment"])
    parsed = parse_enrollment(enrollment)
    return {
        "enrollment_raw": enrollment,
        "mdm_enrolled": parsed["mdm_enrolled"],
        "dep_enrolled": parsed["dep_enrolled"],
        "profiles_raw": text(["profiles", "list"]),
        "_note": (
            "'profiles list' often needs sudo; empty or permission output is "
            "expected without it. mdm_enrolled/dep_enrolled are parsed from "
            "enrollment_raw; null means the state could not be determined -- "
            "trust the raw text over the booleans if they disagree."
        ),
    }


@mcp.tool(name="signalgrid_mdm_status", annotations=READ_ONLY)
def signalgrid_mdm_status() -> dict[str, Any]:
    """MDM enrollment state (including DEP/Automated Device Enrollment) and
    installed configuration profiles.

    Key managed-device signal: an unenrolled corporate Mac is a trust gap.
    Profile listing may require elevation; the raw output is returned either way.

    Returns:
        dict with keys: enrollment_raw (str), mdm_enrolled (bool | None),
        dep_enrolled (bool | None), profiles_raw (str), _note.
        null booleans mean the state could not be determined.
    """
    return collect_mdm()
