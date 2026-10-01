# CLAUDE.md — signalgrid-mcp

Guidance for Claude Code (and humans) working in this repository. Read it before
your first change. These rules override default behaviour.

## What this is

An MCP server that exposes **macOS-native device trust signals** — the facts
about a Mac that no Linux container or cloud runner can gather. It is one
source feeding SignalGrid's decision core; the core itself, the shared posture
contract and every decision rule live in the SignalGrid-Review-Hub repository.
`README.md` lists every tool; `RUNBOOK.md` says how it is run and verified.

Role: **read the device, report honestly, decide nothing new.** This repository
is maintained by SignalGrid's Mac lane; it has no backlog file, so work arrives
as a pull request with its reason in the body.

## Golden rules — do not break these

1. **Strictly read-only.** No tool mutates the device, ever: no writes to
   files, settings, profiles, users, services or the network. Every tool
   carries the read-only annotation; a tool without it does not ship. A new
   tool that needs a write is a different product and needs a decision record
   in the Review-Hub first.
2. **Unknown is unknown.** A value this server could not determine is reported
   as null/unknown, never as "off", "disabled" or "safe". Downstream, unknown
   raises the bar; a collector that guesses lowers it, which is the one failure
   SignalGrid refuses. Modern-macOS reads that come back unknown on a real Mac
   are bugs here, not facts about the Mac (PR #14 fixed two).
3. **The contract is owned elsewhere.** `tests/test_posture_contract.py` reads
   the canonical posture contract from the Review-Hub through
   `SIGNALGRID_CONTRACT_PATH`. Never copy or fork it here; a shape change is a
   Review-Hub change first, then this repository follows it.
4. **Truthful on CI.** Ubuntu CI cannot see a Mac: it proves the code, not the
   signals. Only the macOS job and `verify.sh` on a real Mac prove that a
   signal is live. A green ubuntu run is never evidence that a collector works.
5. **Nothing ships by assertion.** `README.md` and `CHANGELOG.md` describe what
   the code does today; a capability is claimed only after `verify.sh` has
   shown it on a real Mac.

## Before you push

```bash
python3 -m pytest -q          # the whole suite (ubuntu CI runs exactly this)
./verify.sh                   # on a Mac: every tool live, over stdio
```

Add a test for every collector change — the test that fails on the old read
and passes on the new one — and name the macOS version you verified on.

## How the AI lanes work here (SignalGrid DR-047, DR-060, DR-063)

- Reviews run on the owner's Mac, never through an API key stored in GitHub
  (owner decision, 2026-10-01). Anything that needs a real Mac is the Mac lane's.
- Every model-run stage names its tier: Sonnet for reads, verification and
  building; Opus for judgment and review; Haiku only for mechanical reruns.
- Pull requests are opened by lanes and merged by a person. A lane never merges
  its own work here and never force-pushes.
- Raise your hand when stuck: say what you were doing, what blocked you, what
  you need and who can unblock it, instead of returning a partial result as done.

## Owner

Dan Fashauer. He decides; Claude executes. Be concise — he reads on a phone.
