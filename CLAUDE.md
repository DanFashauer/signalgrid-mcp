# CLAUDE.md — signalgrid-mcp

Guidance for Claude Code (and humans) working in this repository. Read it before
your first change. These rules override default behaviour.

## What this is

An MCP server that exposes **macOS-native device trust signals** — the facts
about a Mac that no Linux container or cloud runner can gather. It is one
source feeding SignalGrid's decision core; the core and the canonical posture
contract live in the SignalGrid-Review-Hub repository. `README.md` must list
every registered tool; `RUNBOOK.md` says how it is run and verified.

Role: **read the device and report honestly.** Almost every tool only reports
posture. One piece here does decide: `src/signalgrid_mcp/tools/verdict.py` folds
a posture report into a single-device verdict (two or more criticals deny, one
restricts, unmanaged / auto-update off / any unknown steps up, else allow). It
ships as the tool `signalgrid_trust_verdict`, the resource `signalgrid://verdict`
and the posture report's `include_verdict`. Its own `_note` says it is a local,
single-device verdict that the SignalGrid fabric fuses with identity, custody and
other signals for the final decision. The golden rules below bind it.

Both SignalGrid lanes (Mac and cloud) have opened pull requests here. Under
proposed DR-063 rule 2 a lane writes here only on the owner's go-ahead. There is
no backlog file, so work arrives as a pull request with its reason in the body.

## Golden rules — do not break these

1. **Strictly read-only.** No tool mutates the device, ever: no writes to
   files, settings, profiles, users, services or the network. Every tool
   carries the read-only annotation; a tool without it does not ship. A new
   tool that needs a write is a different product and needs a decision record
   in the Review-Hub first.
2. **Unknown is unknown, and never loosens an answer.** A value this server
   could not determine is reported as null/unknown, never as "off", "disabled"
   or "safe". Downstream, unknown raises the bar; a collector that guesses
   lowers it, which is the one failure SignalGrid refuses. This binds
   `verdict.py` too: `compute_verdict` stays pure and deterministic (no clock,
   randomness or I/O), and a control it cannot read raises the answer to at least
   `step_up`, never `allow`. Some probes legitimately read unknown without
   elevation or Full Disk Access (`profiles list`, `systemsetup`,
   `tmutil latestbackup`; README "Permissions & elevation", RUNBOOK step 3 item
   2), by design. An unknown on a real Mac is a discrepancy to chase, neither a
   fact nor automatically a bug: if the raw command shows a value, the parser is
   wrong (PR #14 fixed three such reads: XProtect version, update settings,
   screen lock). Never "fix" an unknown by running elevated or by inferring a
   value.
3. **The contract is owned elsewhere.** The canonical posture contract is
   `lib/integrations/src/integrations/macos-posture/contract/posture-report.contract.json`
   in the Review-Hub. `tests/test_posture_contract.py` reads it through
   `SIGNALGRID_CONTRACT_PATH` only when that variable is set, which the
   Review-Hub's `pnpm run verify:all` does. Without it (this repository's CI)
   the test checks a copy of the core shape built into the test file. Keep that
   copy equal to the contract, never ahead of it: a shape change is a
   Review-Hub change first, proven with `verify:all`, then this repository
   follows.
4. **Truthful on CI.** Ubuntu CI proves the code, not the signals. `verify.sh`
   installs, runs `pytest -q` (on a Mac that includes the live collector tests),
   then `tools/inspect_stdio.py`, which fails only on a crash, a missing tool or
   a missing read-only marker and exits 0 while tools read unknown; whether a
   signal is live is the `value`/`unknown` column it prints. The `test-macos` CI
   job runs `pytest -q` on GitHub's macOS runner, where
   `tests/test_live_collectors.py` asserts only that XProtect definitions read as
   a version, update settings are never an error string, screen lock parses when
   `sysadminctl` reports, SIP / FileVault / Gatekeeper read as booleans, and
   identity and OS version read. Nothing else is proven live by CI. A green
   ubuntu run is never evidence that a collector works.
5. **Nothing ships by assertion.** `README.md` must list and describe every
   registered tool (`git grep 'name="signalgrid_' src/` is the list;
   `EXPECTED_TOOLS` in `tests/test_smoke.py` must match it). `CHANGELOG.md` is
   meant to describe what shipped but trails the code (last entry v1.0.2; its
   only tool count is v1.0.1's 18), so do not use it as the tool list. A
   capability is claimed only after it reads a value on a real Mac (the
   `verify.sh` inspector column or a live-collector test); being registered, or
   green on ubuntu, is not that.

## Before you push

```bash
pip install -e ".[dev]"       # once per venv; CI does this first, on ubuntu and macOS
pytest -q                     # the whole suite; CI runs it on ubuntu-latest and macos-latest
./verify.sh                   # on a Mac: venv + install + pytest + stdio inspection of every tool
```

Add a test for every collector or verdict change — the test that fails on the
old behaviour and passes on the new — and name the macOS version you verified on.

## How the AI lanes work here (SignalGrid DR-047, DR-054, DR-063)

DR-063 is proposed (PR #1357 in the Review-Hub), not yet in force.

- Reviews run two ways; the owner chose both on 2026-10-01 (DR-063 rule 5). The
  owner's Mac keeps the checks that need real hardware: `verify.sh` and live runs
  of the tools. The `@claude` workflow (`.github/workflows/claude.yml`, PR #17;
  present only once that PR has merged) answers and reviews on GitHub's runner
  when the owner writes `@claude`: owner-only trigger, authenticated by the
  repository secret `CLAUDE_CODE_OAUTH_TOKEN`, which only the owner mints (no
  lane creates, reads or moves it), and it never merges.
- Every model-run stage names its tier on the spawn itself and never inherits the
  coordinator's model (DR-047). Haiku for bulk mechanical work (log scanning,
  mapping reads, doc regeneration); Sonnet for building, verification and reads
  that feed a decision; Opus for judgment and review (DR-047, DR-063 rule 6). An
  unavailable tier resolves up to Opus. Fable and Mythos never run an engineering
  or review stage.
- Pull requests are opened by lanes and merged by a person. A lane never merges
  its own work here and never force-pushes.
- Raise your hand when stuck (DR-054): say what you were doing, what blocked you,
  what you need and who can unblock it, instead of returning a partial result as
  done. From a Review-Hub checkout run `pnpm run hand:raise -- --doing "…"
  --blocked "…" --need "…" --who owner|"mac lane"|"cloud lane"`; without one
  (for example in the `@claude` workflow) open an issue on this repository.

## Owner

Dan Fashauer. He decides; Claude executes. Be concise — he reads on a phone.
