"""Screen-lock / auto-lock hygiene — the walk-up risk on a shared endpoint.

A shared or plant-floor Mac that never locks itself, or that lets someone wake it
without a password, is a walk-up-and-use risk: the previous user's session is
handed to whoever touches the device next. This read-only tool reports three
facts that together decide whether the device actually auto-locks when left idle:

  • is a password required on wake from the screensaver / display sleep, and
  • how long the grace delay is before that password is demanded, and
  • whether the display ever sleeps (the event that engages the lock).

It reads the lock state (`sysadminctl -screenLock status`, with the legacy
`defaults -currentHost read com.apple.screensaver` keys as a fallback for older
macOS) and the active power profile (`pmset -g`); it changes nothing and enforces
nothing.

Fail-safe: a value that could not be read is `null` (UNKNOWN), never assumed
healthy. `locks_when_idle` is `true` ONLY when a password is required, the grace
delay is short, and the display sleeps within a sane idle window — every other
combination is `false` (a real concern) or `null` (couldn't confirm). Unknown is
never graded as "locks".
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import Field

from signalgrid_mcp.app import READ_ONLY, mcp
from signalgrid_mcp.formatting import ResponseFormat
from signalgrid_mcp.runner import probe

# Above these thresholds the device is unattended-and-unlocked for too long to
# call it "locking". Conservative defaults; the concern text always states them.
GRACE_THRESHOLD_SECONDS = 60
IDLE_THRESHOLD_MINUTES = 20


def _bool_flag(raw: str, ok: bool) -> bool | None:
    """A `defaults` boolean flag: exactly '1' → True, '0' → False, anything else
    (key absent → 'does not exist', permission text, garbage) → None (unknown).
    Fail-safe: only an explicit 0/1 is trusted."""
    if not ok:
        return None
    s = raw.strip()
    if s == "1":
        return True
    if s == "0":
        return False
    return None


def _int_seconds(raw: str, ok: bool) -> int | None:
    """A non-negative numeric `defaults` value (askForPasswordDelay is seconds and
    may be written as a float like '5' or '5.0'). Allowlist digits/one dot; every
    other string (error text, absent key) → None. Fail-safe: never guess a delay."""
    if not ok:
        return None
    s = raw.strip()
    if re.fullmatch(r"\d+(\.\d+)?", s) is None:
        return None
    return int(float(s))


def parse_displaysleep(raw: str, ok: bool) -> int | None:
    """Minutes before the display sleeps, from `pmset -g` (0 = never sleeps). The
    active profile prints a line like ` displaysleep         10`. Not found /
    unreadable → None (unknown), never a fabricated timeout."""
    if not ok:
        return None
    m = re.search(r"^\s*displaysleep\s+(\d+)", raw, re.MULTILINE)
    if m is None:
        return None
    return int(m.group(1))


def parse_screenlock_status(raw: str, ok: bool) -> tuple[bool | None, int | None]:
    """Modern source for (password_on_wake, delay_seconds) from
    `sysadminctl -screenLock status` — the `com.apple.screensaver`
    `askForPassword`/`askForPasswordDelay` keys are GONE on macOS 11+ (measured
    absent on macOS 26/27), so the legacy `defaults` reads always returned unknown
    and this safety-critical signal was dead on every modern Mac.

    `sysadminctl` (no elevation) prints one of, to stderr with a process-log prefix:
      'screenLock is off'             -> (False, None)  no password on wake
      'screenLock delay is immediate' -> (True, 0)      password demanded at once
      'screenLock delay is N seconds' -> (True, N)      password after N s grace
    Anything else / not ok -> (None, None), fail-safe (unknown, never assumed on)."""
    if not ok:
        return (None, None)
    s = raw.lower()
    if "screenlock is off" in s:
        return (False, None)
    if "screenlock delay is immediate" in s:
        return (True, 0)
    m = re.search(r"screenlock delay is (\d+)\s*second", s)
    if m:
        return (True, int(m.group(1)))
    return (None, None)


def assess(
    password_on_wake: bool | None,
    delay_seconds: int | None,
    display_sleep_minutes: int | None,
) -> dict[str, Any]:
    """Fold the three facts into a fail-safe hygiene verdict. `locks_when_idle`
    is True ONLY when every condition is affirmatively healthy; a concern makes it
    False; unknowns-only make it None (couldn't confirm — never a silent pass)."""
    concerns: list[str] = []
    unknowns: list[str] = []

    if password_on_wake is True:
        pass
    elif password_on_wake is False:
        concerns.append("no password required on wake (walk-up unlocked)")
    else:
        unknowns.append("password_on_wake")

    if isinstance(delay_seconds, int):
        if delay_seconds > GRACE_THRESHOLD_SECONDS:
            concerns.append(
                f"password grace delay is {delay_seconds}s "
                f"(> {GRACE_THRESHOLD_SECONDS}s unlocked after sleep)"
            )
    else:
        unknowns.append("password_delay_seconds")

    if isinstance(display_sleep_minutes, int):
        if display_sleep_minutes == 0:
            concerns.append("display never sleeps (the lock never auto-engages)")
        elif display_sleep_minutes > IDLE_THRESHOLD_MINUTES:
            concerns.append(
                f"display sleeps after {display_sleep_minutes} min "
                f"(> {IDLE_THRESHOLD_MINUTES} min unattended-unlocked window)"
            )
    else:
        unknowns.append("display_sleep_minutes")

    healthy = (
        password_on_wake is True
        and isinstance(delay_seconds, int)
        and delay_seconds <= GRACE_THRESHOLD_SECONDS
        and isinstance(display_sleep_minutes, int)
        and 0 < display_sleep_minutes <= IDLE_THRESHOLD_MINUTES
    )
    if healthy:
        locks_when_idle: bool | None = True
    elif concerns:
        locks_when_idle = False
    else:
        # Only unknowns, no affirmative concern — cannot confirm it locks.
        locks_when_idle = None

    return {
        "locks_when_idle": locks_when_idle,
        "password_on_wake": password_on_wake,
        "password_delay_seconds": delay_seconds,
        "display_sleep_minutes": display_sleep_minutes,
        "concerns": concerns,
        "unknowns": unknowns,
        "_note": (
            "locks_when_idle=true only when a password is required, the grace "
            "delay is short, and the display sleeps within a sane window. false "
            "means a real walk-up gap; null means it could not be confirmed "
            "(unknown is never graded as locking). password_delay_seconds=0 means "
            "a password is demanded immediately; display_sleep_minutes=0 means the "
            "display never sleeps."
        ),
    }


def collect_screen_lock() -> dict[str, Any]:
    """Read the live screen-lock posture. Each probe degrades independently to
    unknown, so one unreadable value never sinks the others."""
    # Modern source first (macOS 11+): the screensaver askForPassword/Delay keys are
    # gone, so read the authoritative lock state from `sysadminctl -screenLock status`.
    sl = probe(["sysadminctl", "-screenLock", "status"])
    password_on_wake, delay_seconds = parse_screenlock_status(sl["raw"], sl["ok"])
    # Fall back to the legacy user-domain defaults where sysadminctl gave nothing
    # (older macOS, or an unrecognized form). Fail-safe: still None if both fail.
    if password_on_wake is None:
        ask = probe(["defaults", "-currentHost", "read", "com.apple.screensaver", "askForPassword"])
        password_on_wake = _bool_flag(ask["raw"], ask["ok"])
    if delay_seconds is None:
        d = probe(["defaults", "-currentHost", "read", "com.apple.screensaver", "askForPasswordDelay"])
        delay_seconds = _int_seconds(d["raw"], d["ok"])
    pm = probe(["pmset", "-g"])
    return assess(
        password_on_wake,
        delay_seconds,
        parse_displaysleep(pm["raw"], pm["ok"]),
    )


@mcp.tool(name="signalgrid_screen_lock", annotations=READ_ONLY)
def signalgrid_screen_lock(
    response_format: ResponseFormat = ResponseFormat.MARKDOWN,
) -> Any:
    """Screen-lock / auto-lock hygiene: does this Mac lock itself when left idle?
    The walk-up risk on a shared or plant-floor device. Read-only; no elevation.

    Composes three facts — password required on wake, the grace delay before it,
    and whether the display ever sleeps — into a fail-safe `locks_when_idle`
    verdict. `true` only when all three read healthy; `false` on a real gap;
    `null` when it could not be confirmed (unknown is never graded as locking).

    Returns:
        dict with locks_when_idle (bool | None), password_on_wake (bool | None),
        password_delay_seconds (int | None), display_sleep_minutes (int | None),
        concerns (list), unknowns (list), and a _note.
    """
    data = collect_screen_lock()
    if response_format == ResponseFormat.JSON:
        return data
    lines = [
        f"# Screen-lock hygiene (locks_when_idle={data['locks_when_idle']})",
        "",
        f"- password on wake: {data['password_on_wake']}",
        f"- grace delay (s): {data['password_delay_seconds']}",
        f"- display sleep (min): {data['display_sleep_minutes']}",
    ]
    if data["concerns"]:
        lines += ["", "**Concerns:**"] + [f"- {c}" for c in data["concerns"]]
    if data["unknowns"]:
        lines += ["", f"_Could not read: {', '.join(data['unknowns'])}_"]
    lines += ["", data["_note"]]
    return "\n".join(lines)
