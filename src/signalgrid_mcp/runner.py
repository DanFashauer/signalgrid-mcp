"""Subprocess plumbing shared by every SignalGrid tool.

Design rules:
- Never raise out of these helpers; always return a structured result.
- Never invoke a shell. Commands are argv lists, so there is no injection
  surface no matter what an input string contains.
- Distinguish "the check ran and said X" from "the check could not run".
  Those are different facts and must never collapse into each other.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
from typing import Any

DEFAULT_TIMEOUT = 20
IS_MACOS = platform.system() == "Darwin"

NOT_MACOS_HINT = (
    "This host is not macOS, so macOS-native binaries are unavailable. "
    "SignalGrid must run on the Mac being assessed."
)


def run(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a command, never raise. Returns a structured result.

    Keys on success: ok, exit_code, stdout, stderr.
    Keys on failure to execute at all: ok=False, error.
    """
    if not shutil.which(cmd[0]) and not cmd[0].startswith("/"):
        msg = f"not found: {cmd[0]}"
        if not IS_MACOS:
            msg += f" ({NOT_MACOS_HINT})"
        return {"ok": False, "error": msg}
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return {
            "ok": p.returncode == 0,
            "exit_code": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {timeout}s"}
    except Exception as e:  # noqa: BLE001 — deliberately total: tools must not crash
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def text(cmd: list[str], fallback: str = "unavailable", timeout: int = DEFAULT_TIMEOUT) -> str:
    """Best-effort single string from a command (some tools print to stderr)."""
    r = run(cmd, timeout=timeout)
    if r.get("ok") and r.get("stdout"):
        return r["stdout"]
    if r.get("stderr"):
        return r["stderr"]
    if r.get("stdout"):
        return r["stdout"]
    return r.get("error", fallback)


def probe(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a posture check, distinguishing TWO different kinds of failure.

    ok=True  -> the check ran; 'raw' is its real answer (even on nonzero exit)
    ok=False -> the check itself could not run (missing binary, timeout,
                permission). 'raw' explains why.

    "FileVault is off" and "I could not read FileVault" are different facts.
    """
    r = run(cmd, timeout=timeout)
    if "error" in r:
        return {"ok": False, "raw": r["error"]}
    out = (r.get("stdout") or r.get("stderr") or "").strip()
    return {"ok": True, "raw": out or f"(no output, exit {r.get('exit_code')})"}


def run_json(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a command whose stdout is JSON (e.g. system_profiler -json).

    Returns {"ok": True, "data": <parsed>} or {"ok": False, "error": ...}.
    """
    r = run(cmd, timeout=timeout)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("stderr") or "command failed"}
    try:
        return {"ok": True, "data": json.loads(r["stdout"])}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": f"JSON parse failed: {e}"}


def defaults_read(domain: str, key: str | None = None) -> dict[str, Any]:
    """Read a macOS preference via `defaults read`. Best-effort, structured."""
    cmd = ["defaults", "read", domain] + ([key] if key else [])
    return probe(cmd)
