"""Regression tests for the pure parsers fixed in the v1.0.1 audit.

Each test pins the exact failure mode found in review so it cannot regress.
"""

from __future__ import annotations

from signalgrid_mcp.tools.mdm import parse_enrollment
from signalgrid_mcp.tools.network import _parse_lsof_listeners
from signalgrid_mcp.tools.processes import _parse_ps
from signalgrid_mcp.tools.security import classify
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
