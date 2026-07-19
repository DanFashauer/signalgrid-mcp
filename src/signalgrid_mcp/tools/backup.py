"""Time Machine backup posture."""

from __future__ import annotations

from typing import Any

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.runner import defaults_read, text


def collect_time_machine() -> dict[str, Any]:
    auto = defaults_read("/Library/Preferences/com.apple.TimeMachine", "AutoBackup")
    return {
        "auto_backup": (
            None if not auto["ok"] else auto["raw"].strip() == "1"
        ),
        "destinations": text(["tmutil", "destinationinfo"]),
        "latest_backup": text(["tmutil", "latestbackup"]),
        "_note": (
            "auto_backup=null means the preference could not be read (often "
            "requires Full Disk Access), not that backups are off. "
            "tmutil latestbackup may also need Full Disk Access."
        ),
    }


@mcp.tool(name="signalgrid_time_machine", annotations=READ_ONLY)
def signalgrid_time_machine() -> dict[str, Any]:
    """Time Machine posture: automatic backups on/off, configured destinations,
    and the most recent completed backup.

    A device with no recent backup carries higher data-loss risk; a stale
    latest_backup date on a machine that should back up daily is a drift signal.

    Returns:
        dict with keys: auto_backup (bool | None; null = could not read),
        destinations (str), latest_backup (str; a snapshot path on success or
        error text), _note.
    """
    return collect_time_machine()
