# SignalGrid MCP — Mac verification runbook

This server reads **macOS-native trust signals** that a Linux container or cloud
runner simply cannot produce. CI proves the protocol, tool registration,
read-only annotations, and graceful-degradation paths on Linux — but the *real
signal values* only appear on the Mac being assessed. This runbook is the
turnkey way to verify it there.

Everything here is **read-only**: no tool changes anything on the machine.

## TL;DR — one command

```bash
git clone https://github.com/DanFashauer/signalgrid-mcp.git
cd signalgrid-mcp
./verify.sh
```

`verify.sh` creates a venv, installs, runs `pytest`, then inspects the live
server over MCP stdio (listing and calling every tool). Expected result:

- `pytest` → all tests pass.
- inspector → `OK — protocol healthy, all expected tools present, every tool read-only.`
- on a Mac, the macOS-only probes report **values**, not `unknown`.

## Step by step

### 1. Install + test

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

### 2. Inspect the running server

Two equivalent ways — use either or both:

**Node-free (bundled, authoritative for the contract):**

```bash
python tools/inspect_stdio.py         # human-readable
python tools/inspect_stdio.py --json  # machine-readable summary
```

**Official MCP Inspector** (needs Node):

```bash
# headless CLI — list tools, then call one:
npx @modelcontextprotocol/inspector --cli python3 server.py --method tools/list
npx @modelcontextprotocol/inspector --cli python3 server.py \
  --method tools/call --tool-name signalgrid_security_posture

# or the interactive browser UI:
npx @modelcontextprotocol/inspector python3 server.py
```

### 3. Chase down discrepancies

On a real Mac, every macOS-only signal should resolve to a value. When the
inspector prints `unknown` for one, that is a **discrepancy to investigate**, in
this order:

1. **Run the underlying command by hand** to see what the Mac actually returns —
   e.g. `system_profiler SPHardwareDataType`, `csrutil status`,
   `fdesetup status`, `spctl --status`, `profiles status -type enrollment`,
   `softwareupdate --history`, `launchctl print-disabled system`.
2. **Elevation / Full Disk Access** — some probes legitimately return `unknown`
   unelevated (`profiles list`, `systemsetup`, `tmutil latestbackup`, system
   `launchctl` targets). That is *by design*: an unattended trust agent should
   not hold root. Confirm the tool says *unknown*, never a false "off".
3. **Parser mismatch** — if the raw command shows a value but the tool still says
   `unknown`, the parser needs to match this macOS version's output. The parsers
   live in `src/signalgrid_mcp/tools/`; `tests/test_parsers.py` pins them against
   captured fixtures. Add the real output as a fixture and adjust the parser.

The honesty contract is the point: **`unknown` must always mean "the check could
not run"**, never a security control silently reported as disabled.

### 4. Register with Claude Code / Claude Desktop

```json
{
  "mcpServers": {
    "signalgrid": {
      "command": "python3",
      "args": ["/Users/<you>/signalgrid-mcp/server.py"]
    }
  }
}
```

Then ask: *"Use signalgrid to report this Mac's security posture."* The
`signalgrid_posture_report` tool answers the whole picture in one call.

## What "green" means

| Check | Green |
|---|---|
| `pytest` | all tests pass on this Mac |
| `tools/inspect_stdio.py` | protocol OK, all expected tools present, every tool `readOnly=True` |
| macOS signals | SIP / FileVault / Gatekeeper / firewall / MDM / updates read **values**, not `unknown` |
| honesty | no control ever reported "off" when the probe could not actually run |
