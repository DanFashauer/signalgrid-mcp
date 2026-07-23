# Changelog

All notable changes to SignalGrid MCP are documented here. This project follows
semantic versioning. Every tool is read-only and fails safe by design.

## v1.0.2

Patch release. No tool behavior changes; every tool remains read-only.

### Added
- **Cross-repo posture-report contract test** (`tests/test_posture_contract.py`) —
  proves `signalgrid_posture_report` still emits the shape the SignalGrid
  Review-Hub `macos-posture` connector consumes (required sections + security
  controls). Reads the canonical contract via `SIGNALGRID_CONTRACT_PATH` when the
  Review-Hub `pnpm run verify:all` provides it (single source of truth), and falls
  back to a built-in core-shape default so it also guards this repo's own CI.

### Fixed
- **firewall_stealth parser** — `socketfilterfw --getstealthmode` prints
  "Firewall stealth mode is on/off", not "enabled/disabled"; the check matched the
  wrong needles and returned `null` for a clearly-off stealth mode. Aligned the
  needles with the real vendor wording and pinned it with a regression test.
- **verify.sh turnkey on a stock Mac** — auto-selects a Python >= 3.10 (probing
  common interpreter names, then a uv-managed interpreter; explicit `PYTHON=`
  still wins), so `./verify.sh` no longer fails on macOS's stock 3.9 without a
  manual override.

## v1.0.1

Initial release. 18 read-only tools exposing macOS-native device-trust signals
over MCP (hardware identity, OS/security posture, MDM enrollment, software/patch
state, network exposure, persistence, code-signature inspection). Every tool is
read-only and fails safe: a value is null/unknown when a check could not run —
never a false "off". Runs locally over stdio (must execute on the Mac being
assessed). `pytest` 27 passing; an Inspector-equivalent stdio drive of all 18
tools (valid schemas, read-only annotations, zero crashes).
