# CLAUDE.md — signalgrid-mcp

Guidance for owner-authorized agents and humans working in this repository.
Read it before your first change. These rules override default behaviour.

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

Both SignalGrid lanes (Mac and cloud) have opened pull requests here. Work
arrives as an explicitly selected pull request with its reason in the body.

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
   wrong. Never "fix" an unknown by running elevated or by inferring a value.
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
   then `tools/inspect_stdio.py`, which rejects crashes, missing tools, MCP tool
   errors and missing read-only markers. Honest unknown results can still pass
   protocol health. Its `value`/`unknown` column uses text-marker heuristics and
   is not proof that a signal is live. The `test-macos` CI
   job runs `pytest -q` on GitHub's macOS runner. Live assertions are in
   `tests/test_live_collectors.py` and Darwin-only checks in `tests/test_smoke.py`;
   these do not prove every collector reads a value. A green ubuntu run is never
   evidence that a collector works.
5. **Nothing ships by assertion.** `README.md` must list and describe every
   registered tool (`git grep 'name="signalgrid_' src/` is the list;
   `EXPECTED_TOOLS` in `tests/test_smoke.py` must match it). `CHANGELOG.md` is
   meant to describe what shipped, so do not use it as the tool list. A
   capability is claimed only after successful, signal-specific returned data
   or a corresponding live-collector assertion establishes it on a real Mac.
   An inspector label, registration or green ubuntu run is not that proof.

## Before you push

```bash
pip install -e ".[dev]"       # once per venv; CI does this first, on ubuntu and macOS
pytest -q                     # the whole suite; CI runs it on ubuntu-latest and macos-latest
./verify.sh                   # on a Mac: venv + install + pytest + stdio inspection of every tool
```

Add a test for every collector or verdict change — the test that fails on the
old behaviour and passes on the new — and name the macOS version you verified on.

## How the AI lanes work here (owner directions; SignalGrid DR-047, DR-054)
- Record the actual provider/model and any required native review tier for every
  model-run stage (DR-047). Local Ollama is primary for bounded ordinary work.
  Claude/Codex supply necessary escalation or genuine independent source review
  within the current owner-approved limits and model tiers. An already authorized
  escalation may run within those limits; a missing capability never authorizes a
  new provider, paid plan, credential, budget reset or cap increase.
- The owner-authorized repository steward selects bounded work only after fresh
  source, comments, findings and ownership checks, with an exclusive visible claim
  and an explicit ready label. A label or generated proposal does not expand a
  source grant, waive a check or authorize an owner-reserved decision.
- Qualified automated landing requires all four independent source-review lenses
  in each own Codex and Claude system on the same final head, the full applicable
  local validation, ordinary hooks and
  publication, successful required CI on that exact head, findings disposition,
  and the current owner-authorized DR-037 delivery conditions. Land serially using
  a freshly reread full 40-character expected head. Record genuine source-review
  evidence as a GitHub COMMENT review; no separate reviewer account/App or mandatory
  approving vote is required. Never force-push, bypass protection, fabricate
  evidence or decide owner-reserved matters. Retire an exact topic branch only
  within current owner scope, after its contents are preserved and its completion,
  supersession or removal disposition is verified.
- Raise your hand when stuck (DR-054): say what you were doing, what blocked you,
  what you need and who can unblock it, instead of returning a partial result as
  done. From a Review-Hub checkout run `pnpm run hand:raise -- --doing "…"
  --blocked "…" --need "…" --who owner|"mac lane"|"cloud lane"`; without one
  (for example in the proposed `@claude` workflow) open an issue on this repository.

## Owner

Dan Fashauer owns scope and reserved decisions. Authorized local workers and the
repository steward carry routine work within the existing limits. Be concise — he
reads on a phone.
