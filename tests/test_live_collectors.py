"""LIVE collector tests — run against the REAL macOS this executes on.

The monkeypatched tests in test_parsers.py prove the parsers in isolation and pass on
any OS, which is exactly why three modern-macOS breaks (XProtect defs, update settings,
screen lock) reached production: nothing ran the collectors against a real Mac. These
do. They are skipped off macOS (CI's Linux job keeps the smoke/parser invariants), and
they FAIL on the specific regressions that were shipped — a plist key Apple moved that
leaves a signal permanently "unknown", or a `defaults` error string handed back as a
value.

Each asserts only what is guaranteed on any HEALTHY macOS, so it is a gate, not a
flake: XProtect.bundle always carries a version; update settings are null-or-value,
never an error string; and `sysadminctl -screenLock status` always parses to a known
lock state. Run automatically by the `live-macos` CI job (see .github/workflows/ci.yml)
and by anyone running `pytest` on a Mac.
"""

from __future__ import annotations

import platform
import re

import pytest

pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin", reason="live collectors read real macOS state"
)


def test_xprotect_definitions_reads_a_real_version():
    # Regression: reading the `Version` key (gone on macOS 11+) left this "unavailable"
    # on every modern Mac. A healthy Mac always has a numeric XProtect version.
    from signalgrid_mcp.tools.software import collect_xprotect

    defs = collect_xprotect()["xprotect_definitions"]
    assert re.fullmatch(r"[0-9][0-9.]*", defs), (
        f"XProtect definitions did not read as a version: {defs!r} "
        f"(a moved/renamed plist key, or an unreadable bundle)"
    )


def test_update_settings_are_null_or_value_never_an_error_string():
    # Regression: absent keys (AutomaticCheckEnabled, LastUpdatesAvailable are gone on
    # macOS 26/27) were stored as the `defaults` error text instead of None.
    from signalgrid_mcp.tools.software import collect_update_settings

    for key, value in collect_update_settings().items():
        assert value is None or (
            isinstance(value, str)
            and not re.search(r"error|could not find|does not exist|unavailable", value, re.I)
        ), f"update setting {key} leaked an error string: {value!r}"


def test_screen_lock_status_parses_when_sysadminctl_reports():
    # Regression: reading com.apple.screensaver askForPassword/Delay (gone on macOS 11+)
    # left password_on_wake permanently unknown. sysadminctl carries the real state.
    #
    # A headless CI runner has no GUI login session, so sysadminctl may decline to report
    # a lock state at all — which is NOT the regression this guards. Skip that case (the
    # raw carries no "screenLock" line) and assert only when sysadminctl actually reports:
    # then a parse of None means the wording changed or the source broke — the real defect.
    from signalgrid_mcp.runner import probe
    from signalgrid_mcp.tools.screen_lock import parse_screenlock_status

    sl = probe(["sysadminctl", "-screenLock", "status"])
    if "screenlock" not in sl["raw"].lower():
        pytest.skip(f"sysadminctl reported no screenLock status (headless session?): {sl['raw']!r}")
    password_on_wake, _delay = parse_screenlock_status(sl["raw"], sl["ok"])
    assert password_on_wake is not None, (
        f"sysadminctl reported a screenLock status but it did not parse: {sl['raw']!r}"
    )
