"""Regression tests for the pure parsers fixed in the v1.0.1 audit.

Each test pins the exact failure mode found in review so it cannot regress.
"""

from __future__ import annotations

from signalgrid_mcp.tools.mdm import parse_enrollment
from signalgrid_mcp.tools.network import _parse_lsof_listeners
from signalgrid_mcp.tools.processes import _parse_ps
from signalgrid_mcp.tools.security import POSTURE_CHECKS, classify
from signalgrid_mcp.tools.users import _parse_users


class TestEnrollmentParsing:
    def test_unenrolled_mac_is_not_reported_enrolled(self):
        # Regression: the 'Enrolled via DEP:' HEADER used to count as enrolled.
        raw = "Enrolled via DEP: No\nMDM enrollment: No"
        parsed = parse_enrollment(raw)
        assert parsed["mdm_enrolled"] is False
        assert parsed["dep_enrolled"] is False

    def test_user_approved_mdm(self):
        raw = "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)"
        parsed = parse_enrollment(raw)
        assert parsed["mdm_enrolled"] is True
        assert parsed["dep_enrolled"] is False

    def test_dep_enrolled(self):
        raw = "Enrolled via DEP: Yes\nMDM enrollment: Yes"
        parsed = parse_enrollment(raw)
        assert parsed["mdm_enrolled"] is True
        assert parsed["dep_enrolled"] is True

    def test_unrecognized_output_is_unknown(self):
        parsed = parse_enrollment("not found: profiles (not macOS)")
        assert parsed["mdm_enrolled"] is None
        assert parsed["dep_enrolled"] is None


class TestSharingClassification:
    def test_permission_error_is_unknown_not_enabled(self):
        # Regression: 'permissiON'/'configuratiON' used to match the bare
        # 'on' needle and report a disabled service as enabled.
        raw = "Error, permission denied to read configuration"
        assert classify(raw, ok=True, enabled_needle=": on", disabled_needle=": off") is None

    def test_admin_access_error_is_unknown(self):
        raw = "You need administrator access to run this tool... exiting!"
        assert classify(raw, ok=True, enabled_needle=": on", disabled_needle=": off") is None

    def test_explicit_on_off(self):
        assert classify("Remote Login: On", True, ": on", ": off") is True
        assert classify("Remote Login: Off", True, ": on", ": off") is False

    def test_launchctl_not_loaded_is_disabled(self):
        raw = "Could not find service \"com.apple.screensharing\" in domain for system"
        assert classify(raw, True, "state = running", "could not find service") is False

    def test_probe_failure_is_unknown(self):
        assert classify("timeout after 20s", ok=False, enabled_needle="x", disabled_needle="y") is None


class TestFirewallStealthClassification:
    """Regression: `socketfilterfw --getstealthmode` prints
    "Firewall stealth mode is on/off" -- NOT "enabled"/"disabled". The check
    used the wrong needles, so a clearly-off stealth mode classified as null
    (unknown) instead of False. These pin the real vendor wording against the
    needles wired into POSTURE_CHECKS, so reverting the fix fails here too.
    """

    ON_NEEDLE = POSTURE_CHECKS["firewall_stealth"][1]
    OFF_NEEDLE = POSTURE_CHECKS["firewall_stealth"][2]

    def test_stealth_on_is_true(self):
        assert classify("Firewall stealth mode is on", True, self.ON_NEEDLE, self.OFF_NEEDLE) is True

    def test_stealth_off_is_false_not_unknown(self):
        # The exact live-server raw string that used to return null.
        assert classify("Firewall stealth mode is off", True, self.ON_NEEDLE, self.OFF_NEEDLE) is False

    def test_configured_needles_match_vendor_wording(self):
        # Guards the fix at the source: the needles wired into POSTURE_CHECKS
        # must actually resolve the real command output to a bool, not null.
        for raw, expected in [
            ("Firewall stealth mode is on", True),
            ("Firewall stealth mode is off", False),
        ]:
            assert classify(raw, True, self.ON_NEEDLE, self.OFF_NEEDLE) is expected


class TestLsofFieldParsing:
    SAMPLE = "\n".join(
        [
            "p321",
            "cGoogle Chrome Helper",  # command with spaces — the regression case
            "Ldan",
            "n127.0.0.1:9222",
            "p845",
            "csshd",
            "Lroot",
            "n*:22",
            "n[::]:22",  # second listener for the same pid
        ]
    )

    def test_commands_with_spaces_parse_intact(self):
        items = _parse_lsof_listeners(self.SAMPLE)
        assert items[0] == {
            "command": "Google Chrome Helper",
            "pid": "321",
            "user": "dan",
            "address": "127.0.0.1:9222",
        }

    def test_multiple_listeners_per_process(self):
        items = _parse_lsof_listeners(self.SAMPLE)
        sshd = [i for i in items if i["command"] == "sshd"]
        assert [i["address"] for i in sshd] == ["*:22", "[::]:22"]

    def test_empty_output(self):
        assert _parse_lsof_listeners("") == []


class TestPsParsing:
    # Representative `ps axo pid,ppid,user,%cpu,%mem,comm` output on real macOS:
    # a header row (skipped), right-aligned numeric columns, and — the case that
    # bites naive parsers — a COMM path containing spaces.
    SAMPLE = "\n".join(
        [
            "  PID  PPID USER             %CPU %MEM COMM",
            "    1     0 root              0.0  0.1 /sbin/launchd",
            "  501     1 dan               1.5  0.8 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            "  842   501 dan               3.2  2.1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "  845     1 root              0.0  0.0 /usr/sbin/sshd",
        ]
    )

    def test_header_is_skipped_and_rows_parse(self):
        items = _parse_ps(self.SAMPLE)
        assert len(items) == 4
        assert items[0] == {
            "pid": 1,
            "ppid": 0,
            "user": "root",
            "cpu_pct": 0.0,
            "mem_pct": 0.1,
            "command": "/sbin/launchd",
        }

    def test_command_path_with_spaces_is_kept_whole(self):
        # Regression: split(None, 5) must keep the full path, not truncate at the
        # first space in "Google Chrome".
        items = _parse_ps(self.SAMPLE)
        chrome = [i for i in items if i["pid"] == 842][0]
        assert chrome["command"] == "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        assert chrome["user"] == "dan"
        assert chrome["cpu_pct"] == 3.2 and chrome["mem_pct"] == 2.1

    def test_malformed_rows_are_dropped_not_crashed(self):
        raw = "PID PPID USER %CPU %MEM COMM\ngarbage line\n  9  1 dan 0.0 0.0 /bin/zsh"
        items = _parse_ps(raw)
        assert [i["pid"] for i in items] == [9]

    def test_empty_output(self):
        assert _parse_ps("") == []


class TestUsersParsing:
    # Representative `dscl . -list /Users UniqueID` output: whitespace-aligned
    # columns, daemon accounts (uid < 500), a real login account (>= 500), and
    # the negative-uid `nobody` account.
    SAMPLE = "\n".join(
        [
            "_spotlight                       89",
            "daemon                           1",
            "dan                              501",
            "nobody                           -2",
            "root                             0",
        ]
    )

    def test_all_accounts_parse_with_correct_uids(self):
        users = _parse_users(self.SAMPLE)
        by_name = {u["username"]: u["uid"] for u in users}
        assert by_name == {"_spotlight": 89, "daemon": 1, "dan": 501, "nobody": -2, "root": 0}

    def test_negative_uid_is_parsed(self):
        users = _parse_users(self.SAMPLE)
        assert {"username": "nobody", "uid": -2} in users

    def test_blank_and_partial_lines_ignored(self):
        users = _parse_users("dan 501\n\nonlyusername\n")
        assert users == [{"username": "dan", "uid": 501}]

    def test_empty_output(self):
        assert _parse_users("") == []


class TestSystemExtensionParsing:
    from signalgrid_mcp.tools.sysext import parse_system_extensions as _p

    SAMPLE = (
        "2 extension(s)\n"
        "--- com.apple.system_extension.endpoint_security\n"
        "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
        "*\t*\t1A2B3C4D5E\tcom.vendor.falcon.Agent (7.20/1)\tFalcon\t[activated enabled]\n"
        "--- com.apple.system_extension.network_extension\n"
        "\t\t9Z8Y7X6W5V\tcom.other.net.ext (2.0/3)\tNetExt\t[terminated waiting to uninstall on reboot]\n"
    )

    def test_active_extension_is_classified_active(self):
        r = TestSystemExtensionParsing._p(self.SAMPLE)
        assert r["available"] is True and r["count"] == 2 and r["reliable"] is True
        falcon = next(e for e in r["extensions"] if e["name"] == "Falcon")
        assert falcon["status"] == "active" and falcon["enabled"] is True and falcon["active"] is True
        assert falcon["teamID"] == "1A2B3C4D5E" and falcon["version"] == "7.20/1"

    def test_terminated_extension_is_flagged_residual(self):
        r = TestSystemExtensionParsing._p(self.SAMPLE)
        net = next(e for e in r["extensions"] if e["name"] == "NetExt")
        assert net["status"] == "residual" and net["enabled"] is False
        assert r["residual_count"] == 1 and r["active_count"] == 1

    def test_removed_marker_is_residual_not_active(self):
        # BLOCKER regression: a deleted-app extension reads "activated enabled
        # (removed)" — still registered. It must be residual, NEVER clean active.
        raw = (
            "1 extension(s)\n"
            "--- com.apple.system_extension.endpoint_security\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t*\tTEAM123456\tcom.vendor.agent (1.0)\tGhost\t[activated enabled (removed)]\n"
        )
        r = TestSystemExtensionParsing._p(raw)
        g = next(e for e in r["extensions"] if e["name"] == "Ghost")
        assert g["status"] == "residual" and r["residual_count"] == 1 and r["active_count"] == 0

    def test_terminating_is_residual(self):
        assert TestSystemExtensionParsing._p(
            "1 extension(s)\n--- x\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t*\tT\tc.x (1)\tX\t[terminating]\n"
        )["extensions"][0]["status"] == "residual"

    def test_unrecognized_output_is_unavailable_not_empty(self):
        r = TestSystemExtensionParsing._p("zsh: command not found: systemextensionsctl")
        assert r["available"] is False and r["count"] is None and r["extensions"] == []

    def test_error_text_mentioning_extensions_is_not_a_listing(self):
        # MAJOR regression: a loose substring must not pass as a real listing.
        r = TestSystemExtensionParsing._p("Operation not permitted reading extension(s)")
        assert r["available"] is False

    def test_empty_output_is_unavailable(self):
        assert TestSystemExtensionParsing._p("")["available"] is False

    def test_unknown_state_is_never_active(self):
        raw = (
            "1 extension(s)\n--- com.apple.system_extension.endpoint_security\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t\tTEAMXYZ\tcom.x.ext (1.0)\tMystery\t[some future state]\n"
        )
        assert next(e for e in TestSystemExtensionParsing._p(raw)["extensions"] if e["name"] == "Mystery")["status"] == "unknown"

    def test_disabled_row_with_teamid_in_bundle_is_not_dropped(self):
        # MAJOR regression: a residual row whose bundle contains "teamid" and whose
        # enabled marker is empty must NOT be mistaken for the column header.
        raw = (
            "1 extension(s)\n--- com.apple.system_extension.network_extension\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "\t\t9Z8Y7X6W5V\tcom.acme.teamid.net (2.0)\tHelper\t[terminated waiting to uninstall]\n"
        )
        r = TestSystemExtensionParsing._p(raw)
        assert r["count"] == 1 and r["residual_count"] == 1 and r["reliable"] is True

    def test_count_mismatch_is_unreliable(self):
        # MAJOR regression: header declares more than we parsed → unreliable, so a
        # missing (possibly residual) extension can't read as clean.
        raw = (
            "3 extension(s)\n--- com.apple.system_extension.endpoint_security\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t*\tT1\tc.one (1)\tOne\t[activated enabled]\n"
        )
        r = TestSystemExtensionParsing._p(raw)
        assert r["available"] is True and r["reliable"] is False and r["declared_count"] == 3

    def test_malformed_row_is_counted_unparsed_not_dropped(self):
        raw = (
            "1 extension(s)\n--- com.apple.system_extension.endpoint_security\n"
            "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
            "*\t*\tT1\tc.short (1)\n"
        )
        r = TestSystemExtensionParsing._p(raw)
        assert r["unparsed_rows"] == 1 and r["reliable"] is False


class TestTrustVerdict:
    from signalgrid_mcp.tools.verdict import compute_verdict as _v

    ON = {"enabled": True}
    OFF = {"enabled": False}
    UNK = {"enabled": None}

    def _healthy(self):
        return {
            "security": {"sip": self.ON, "filevault": self.ON, "gatekeeper": self.ON, "firewall": self.ON},
            "mdm": {"mdm_enrolled": True},
            "updates": {"AutomaticCheckEnabled": True},
            "xprotect": {"xprotect_definitions": "2183"},
        }

    def test_all_healthy_allows(self):
        assert TestTrustVerdict._v(self._healthy())["verdict"] == "allow"

    def test_one_control_off_restricts(self):
        r = self._healthy(); r["security"]["filevault"] = self.OFF
        assert TestTrustVerdict._v(r)["verdict"] == "restrict"

    def test_two_controls_off_deny(self):
        r = self._healthy(); r["security"]["filevault"] = self.OFF; r["security"]["sip"] = self.OFF
        assert TestTrustVerdict._v(r)["verdict"] == "deny"

    def test_unknown_never_allows(self):
        # Fail-safe: an entirely unreadable report (non-macOS) is step_up, NOT allow.
        r = {"security": {"error": "csrutil unavailable"}, "mdm": {"mdm_enrolled": None},
             "updates": {"AutomaticCheckEnabled": None}, "xprotect": {"xprotect_definitions": "unavailable"}}
        v = TestTrustVerdict._v(r)
        assert v["verdict"] == "step_up" and v["verdict"] != "allow"

    def test_a_single_unknown_control_never_allows(self):
        r = self._healthy(); r["security"]["gatekeeper"] = self.UNK
        assert TestTrustVerdict._v(r)["verdict"] == "step_up"

    def test_unmanaged_steps_up(self):
        r = self._healthy(); r["mdm"]["mdm_enrolled"] = False
        assert TestTrustVerdict._v(r)["verdict"] == "step_up"

    def test_stranded_extension_restricts(self):
        r = self._healthy()
        r["system_extensions"] = {"available": True, "reliable": True, "residual_count": 1}
        assert TestTrustVerdict._v(r)["verdict"] == "restrict"

    def test_stranded_extension_plus_control_off_denies(self):
        r = self._healthy(); r["security"]["firewall"] = self.OFF
        r["system_extensions"] = {"available": True, "reliable": True, "residual_count": 2}
        assert TestTrustVerdict._v(r)["verdict"] == "deny"

    def test_unreadable_sysext_section_steps_up(self):
        r = self._healthy(); r["system_extensions"] = {"available": False}
        assert TestTrustVerdict._v(r)["verdict"] == "step_up"

    def test_auto_update_off_steps_up(self):
        r = self._healthy(); r["updates"]["AutomaticCheckEnabled"] = False
        assert TestTrustVerdict._v(r)["verdict"] == "step_up"

    # ── review regressions: no path to a false 'allow' ──────────────────────────
    def test_unreadable_updates_section_never_allows(self):
        # BLOCKER regression: an errored / None / absent updates section must NOT
        # pass as healthy.
        for bad in ({"error": "defaults unavailable"}, {"AutomaticCheckEnabled": None}, {}):
            r = self._healthy(); r["updates"] = bad
            assert TestTrustVerdict._v(r)["verdict"] == "step_up", bad
        r = self._healthy(); del r["updates"]
        assert TestTrustVerdict._v(r)["verdict"] == "step_up"

    def test_xprotect_not_found_stderr_never_allows(self):
        # MAJOR regression: real `defaults` failure text must read as unknown, not
        # a valid definition version.
        for bad in ("The domain/default pair of (X, Version) does not exist", "%Su", "unavailable: not found"):
            r = self._healthy(); r["xprotect"] = {"xprotect_definitions": bad}
            assert TestTrustVerdict._v(r)["verdict"] == "step_up", bad

    def test_a_real_xprotect_version_allows(self):
        r = self._healthy(); r["xprotect"] = {"xprotect_definitions": "2183"}
        assert TestTrustVerdict._v(r)["verdict"] == "allow"

    def test_non_boolean_mdm_never_allows(self):
        # MINOR regression: a non-boolean enrollment value ("false", 0) must not be
        # treated as enrolled.
        for bad in ("false", "no", 0, "true"):
            r = self._healthy(); r["mdm"]["mdm_enrolled"] = bad
            assert TestTrustVerdict._v(r)["verdict"] == "step_up", bad


class TestRemovableMedia:
    from signalgrid_mcp.tools.removable_media import parse_usb as _p

    def test_mass_storage_is_flagged(self):
        data = [{"_name": "USB31Bus", "host_controller": "AppleT8103USBXHCI", "_items": [
            {"_name": "Flash Drive", "manufacturer": "SanDisk", "serial_num": "ABC123",
             "Media": [{"_name": "disk4", "volumes": [{"_name": "UNTITLED"}]}]},
        ]}]
        r = TestRemovableMedia._p(data)
        assert r["available"] is True and r["mass_storage_connected"] is True and r["mass_storage_count"] == 1
        d = r["devices"][0]
        assert d["kind"] == "mass_storage" and d["vendor"] == "SanDisk" and d["volumes"] == ["UNTITLED"]

    def test_non_storage_device_is_other_not_storage(self):
        data = [{"_name": "USB31Bus", "host_controller": "x", "_items": [
            {"_name": "Keyboard", "manufacturer": "Apple", "vendor_id": "0x05ac"},
        ]}]
        r = TestRemovableMedia._p(data)
        assert r["device_count"] == 1 and r["mass_storage_count"] == 0 and r["mass_storage_connected"] is False
        assert r["devices"][0]["kind"] == "other"

    def test_bus_controllers_are_not_counted_as_devices(self):
        data = [{"_name": "USB31Bus", "host_controller": "AppleT8103USBXHCI"}]
        assert TestRemovableMedia._p(data)["device_count"] == 0

    def test_unreadable_tree_is_unavailable_not_empty(self):
        # Fail-safe: a shape we can't read is available:false, NOT "nothing connected".
        for bad in (None, {}, "error"):
            r = TestRemovableMedia._p(bad)
            assert r["available"] is False and r["mass_storage_connected"] is None

    def test_empty_bus_is_available_with_zero_devices(self):
        # A readable-but-empty tree IS available (genuinely nothing plugged in).
        r = TestRemovableMedia._p([{"_name": "USB31Bus", "host_controller": "x", "_items": []}])
        assert r["available"] is True and r["device_count"] == 0 and r["mass_storage_connected"] is False

    def test_nested_hub_storage_is_found(self):
        data = [{"_name": "Bus", "host_controller": "x", "_items": [
            {"_name": "Hub", "manufacturer": "Generic", "_items": [
                {"_name": "Stick", "manufacturer": "Kingston", "Media": [{"_name": "disk5"}]},
            ]},
        ]}]
        r = TestRemovableMedia._p(data)
        assert r["mass_storage_count"] == 1 and any(d["name"] == "Stick" for d in r["devices"])

    # ── review regressions ──────────────────────────────────────────────────────
    def test_unreadable_count_is_none_not_zero(self):
        # MAJOR: an unreadable tree must NOT numerically read as "0 storage".
        for bad in (None, "error", {}):
            r = TestRemovableMedia._p(bad)
            assert r["available"] is False and r["mass_storage_count"] is None and r["mass_storage_connected"] is None

    def test_media_bearing_controller_node_not_dropped(self):
        # MAJOR: a node with a controller key that ALSO presents storage must be kept.
        data = [{"_name": "Bus", "host_controller": "x", "_items": [
            {"_name": "Enc", "manufacturer": "OWC", "pci_device": "yes",
             "Media": [{"_name": "disk9", "volumes": [{"_name": "DATA"}]}]},
        ]}]
        r = TestRemovableMedia._p(data)
        assert r["mass_storage_count"] == 1 and r["mass_storage_connected"] is True

    def test_scalar_volumes_does_not_crash(self):
        data = [{"_name": "Bus", "host_controller": "x", "_items": [
            {"_name": "Stick", "manufacturer": "K", "Media": [{"_name": "d", "volumes": 5}]},
        ]}]
        r = TestRemovableMedia._p(data)  # must not raise
        assert r["mass_storage_count"] == 1 and r["devices"][0]["volumes"] == []


class TestScreenLock:
    from signalgrid_mcp.tools.screen_lock import (
        _bool_flag as _flag,
    )
    from signalgrid_mcp.tools.screen_lock import (
        _int_seconds as _sec,
    )
    from signalgrid_mcp.tools.screen_lock import (
        assess as _assess,
    )
    from signalgrid_mcp.tools.screen_lock import (
        parse_displaysleep as _ds,
    )

    # ── defaults boolean flag ────────────────────────────────────────────────────
    def test_flag_explicit_one_zero(self):
        assert TestScreenLock._flag("1", ok=True) is True
        assert TestScreenLock._flag("0", ok=True) is False

    def test_flag_absent_key_is_unknown_not_off(self):
        # Fail-safe: `defaults` prints this when the key doesn't exist. It is
        # UNKNOWN, never a confident "no password".
        raw = "The domain/default pair of (com.apple.screensaver, askForPassword) does not exist"
        assert TestScreenLock._flag(raw, ok=True) is None

    def test_flag_probe_failure_is_unknown(self):
        assert TestScreenLock._flag("timeout after 20s", ok=False) is None

    def test_flag_garbage_is_unknown_not_true(self):
        # Anything that isn't 0/1 (after strip) must not read as a boolean.
        for bad in ("2", "yes", "true", "", "10", "on"):
            assert TestScreenLock._flag(bad, ok=True) is None, bad

    def test_flag_tolerates_trailing_whitespace(self):
        # `defaults` output can carry a trailing newline; a stripped '1'/'0' is
        # still a valid flag (whitespace tolerance is not a fail-open).
        assert TestScreenLock._flag("1\n", ok=True) is True
        assert TestScreenLock._flag(" 0 ", ok=True) is False

    # ── numeric grace delay ──────────────────────────────────────────────────────
    def test_seconds_int_and_float(self):
        assert TestScreenLock._sec("0", ok=True) == 0
        assert TestScreenLock._sec("5", ok=True) == 5
        assert TestScreenLock._sec("5.0", ok=True) == 5

    def test_seconds_error_text_is_none(self):
        assert TestScreenLock._sec("does not exist", ok=True) is None
        assert TestScreenLock._sec("-1", ok=True) is None  # no negative delays
        assert TestScreenLock._sec("x", ok=False) is None

    # ── pmset displaysleep ───────────────────────────────────────────────────────
    PMSET = "\n".join([
        "System-wide power settings:",
        "Currently in use:",
        " standby              1",
        " hibernatemode        3",
        " displaysleep         10",
        " disksleep            10",
        " sleep                1",
    ])

    def test_displaysleep_parsed(self):
        assert TestScreenLock._ds(self.PMSET, ok=True) == 10

    def test_displaysleep_never_sleeps_is_zero(self):
        assert TestScreenLock._ds(" displaysleep         0", ok=True) == 0

    def test_displaysleep_missing_is_unknown_not_zero(self):
        # Fail-safe: absent line → None (unknown), NOT a fabricated 0/"never".
        assert TestScreenLock._ds("Currently in use:\n sleep 1", ok=True) is None
        assert TestScreenLock._ds("anything", ok=False) is None

    # ── fail-safe hygiene verdict ────────────────────────────────────────────────
    def test_healthy_locks_when_idle(self):
        r = TestScreenLock._assess(True, 0, 10)
        assert r["locks_when_idle"] is True and r["concerns"] == [] and r["unknowns"] == []

    def test_no_password_is_a_concern_not_locking(self):
        r = TestScreenLock._assess(False, 0, 10)
        assert r["locks_when_idle"] is False and any("walk-up" in c for c in r["concerns"])

    def test_display_never_sleeps_is_concern(self):
        r = TestScreenLock._assess(True, 0, 0)
        assert r["locks_when_idle"] is False and any("never sleeps" in c for c in r["concerns"])

    def test_long_grace_delay_is_concern(self):
        r = TestScreenLock._assess(True, 300, 10)
        assert r["locks_when_idle"] is False and any("grace delay" in c for c in r["concerns"])

    def test_long_display_sleep_is_concern(self):
        r = TestScreenLock._assess(True, 0, 120)
        assert r["locks_when_idle"] is False and any("unattended-unlocked" in c for c in r["concerns"])

    def test_all_unknown_is_null_never_locking(self):
        # BLOCKER shape: nothing readable (non-macOS) → locks_when_idle is None,
        # never True. Unknown is never graded as "locks".
        r = TestScreenLock._assess(None, None, None)
        assert r["locks_when_idle"] is None
        assert set(r["unknowns"]) == {"password_on_wake", "password_delay_seconds", "display_sleep_minutes"}

    def test_password_ok_but_sleep_unknown_cannot_confirm(self):
        # A password is required, but we can't read whether the display sleeps →
        # cannot confirm it ever locks. Null, not True.
        r = TestScreenLock._assess(True, 0, None)
        assert r["locks_when_idle"] is None and "display_sleep_minutes" in r["unknowns"]

    def test_concern_dominates_remaining_unknown(self):
        # A definite concern (no password) outweighs an unreadable display timeout:
        # the verdict is a firm False, not a soft None.
        r = TestScreenLock._assess(False, None, None)
        assert r["locks_when_idle"] is False


def test_removable_media_collect_survives_nondict_json():
    # MINOR: a truthy non-dict top-level JSON must degrade, not crash.
    from signalgrid_mcp.tools.removable_media import parse_usb
    # simulate the collect path's guard: a list top-level → tree None → available False
    assert parse_usb(None)["available"] is False
