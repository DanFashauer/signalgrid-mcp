# SignalGrid MCP

An MCP (Model Context Protocol) server that exposes **macOS-native device trust
signals** — the facts about a Mac that cannot be gathered from a Linux container
or a cloud runner. Every tool is **strictly read-only**: nothing on the device is
ever mutated.

## What it answers

| Signal | Tool |
|---|---|
| Who is this machine? (serial, UUID, chip, activation lock) | `signalgrid_device_identity` |
| What OS build is it on? | `signalgrid_os_info` |
| Are SIP / FileVault / Gatekeeper / firewall on? | `signalgrid_security_posture` |
| What remote access is exposed? (SSH, Screen Sharing, SMB, ARD) | `signalgrid_sharing_services` |
| Is it MDM/DEP enrolled? What profiles are installed? | `signalgrid_mdm_status` |
| Is it patched? Are auto-updates on? | `signalgrid_software_updates` |
| Are XProtect / MRT malware definitions current? | `signalgrid_xprotect_status` |
| What got installed, and when? | `signalgrid_install_history` |
| DNS, proxies, VPNs, interfaces | `signalgrid_network_posture` |
| What's listening on the network? | `signalgrid_listening_services` |
| What persists across reboots? (launchd items) | `signalgrid_launch_items` |
| Any third-party kernel extensions? | `signalgrid_kernel_extensions` |
| Who has accounts? Who is admin? | `signalgrid_local_users` |
| What apps are installed, and who signed them? | `signalgrid_installed_apps` |
| What's running right now? | `signalgrid_process_snapshot` |
| Is this app properly signed & notarized? | `signalgrid_codesign_inspect` |
| **Everything above the fold, in one call** | `signalgrid_posture_report` |

The aggregate report is also exposed as an MCP resource at `signalgrid://posture`.

## Design principles

- **Read-only, always.** Every tool carries `readOnlyHint: true`,
  `destructiveHint: false`. No command mutates state.
- **Unknown ≠ off.** Posture checks distinguish "the check ran and said X"
  from "the check could not run" (missing binary, timeout, needs elevation).
  `enabled: null` always means *unknown* — investigate, don't grade.
- **No shell, no injection.** Every command is an argv list executed without a
  shell; user input is never interpolated into a command line.
- **Context-efficient.** Large inventories (apps, processes, launch items,
  install history, listeners) are paginated (`limit`/`offset`, standard
  `total/has_more/next_offset` envelope), filterable (`name_contains`), and
  render as a compact markdown table by default or JSON on request.
- **Degrades gracefully.** On a non-macOS host, or when a probe needs
  elevation, tools return structured error/unknown text — they never crash.

## Install

Requires Python ≥ 3.10 on the Mac being assessed.

```bash
cd signalgrid-mcp
pip install -e .          # or: uv pip install -e .
```

## Run

stdio transport (the server must run **on the Mac it is assessing**, as a
subprocess of the MCP client):

```bash
signalgrid-mcp            # console script
# or
python -m signalgrid_mcp.server
# or (back-compat)
python server.py
```

### Claude Desktop / Claude Code config

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

### Inspect interactively

```bash
npx @modelcontextprotocol/inspector python3 server.py
```

## Permissions & elevation

The server intentionally runs unelevated. Some probes therefore report
`null`/unknown rather than an answer:

- `profiles list`, `systemsetup`, and some `launchctl print system/...` targets
  want root.
- `tmutil latestbackup` and the Time Machine preference need Full Disk Access.
- Unelevated `lsof` only sees the current user's listeners.

This is by design: an unattended trust agent should not hold root. Treat
`null` as "unresolved signal" and escalate out-of-band if it matters.

## Verify (turnkey, on the Mac)

One command sets up, tests, and inspects the live server end to end:

```bash
./verify.sh
```

It creates a venv, installs, runs `pytest`, then inspects the server over MCP
stdio — listing and calling every tool. See **[RUNBOOK.md](RUNBOOK.md)** for the
step-by-step Mac verification, including how to chase down any signal that reads
`unknown` against real macOS output.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The smoke tests run on any OS (they exercise the graceful-degradation paths on
Linux CI); the meaningful signal values obviously require macOS. For a Node-free
protocol inspection (no browser, no `npx`):

```bash
python tools/inspect_stdio.py          # human-readable
python tools/inspect_stdio.py --json   # machine-readable summary
```

## Layout

```
signalgrid-mcp/
├── server.py                  # back-compat stdio entry point
├── verify.sh                  # one-command turnkey verify (install + test + inspect)
├── RUNBOOK.md                 # step-by-step Mac verification runbook
├── src/signalgrid_mcp/
│   ├── app.py                 # FastMCP instance + shared annotations
│   ├── runner.py              # subprocess plumbing (run/text/probe/run_json)
│   ├── formatting.py          # pagination, filtering, markdown/JSON rendering
│   ├── server.py              # entry point (main)
│   └── tools/                 # one module per signal domain
├── tools/inspect_stdio.py     # Node-free MCP inspector (protocol/read-only/honesty)
├── tests/test_smoke.py
├── tests/test_parsers.py      # parser fixtures pinned against captured output
└── evaluation.xml             # MCP eval suite (read-only Q&A pairs)
```
