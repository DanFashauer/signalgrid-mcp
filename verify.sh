#!/usr/bin/env bash
# One-command turnkey verification for the SignalGrid MCP server.
#
# Run this ON THE MAC you want to assess. It:
#   1. creates a local virtualenv and installs the server (+ dev extras),
#   2. runs the test suite (pytest),
#   3. inspects the live server over MCP stdio — listing every tool and calling
#      each one — using the official MCP Inspector CLI when Node is available,
#      and always with the bundled Node-free Python inspector as the source of
#      truth for the protocol/read-only/honesty contract.
#
#   ./verify.sh
#
# Every tool is read-only, so this never changes anything on the machine.
set -euo pipefail
cd "$(dirname "$0")"

VENV="${VENV:-.venv}"
PY="${PYTHON:-python3}"

echo "== SignalGrid MCP verify =="
echo "-- host: $(uname -s) $(uname -m); python: $("$PY" --version 2>&1)"

echo
echo "== 1/3  install (venv: $VENV) =="
"$PY" -m venv "$VENV"
# shellcheck disable=SC1090
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -e ".[dev]"

echo
echo "== 2/3  pytest =="
"$VENV/bin/pytest" -q

echo
echo "== 3/3  inspect the live MCP server =="
echo "-- Node-free stdio inspector (protocol + read-only + honesty contract):"
"$VENV/bin/python" tools/inspect_stdio.py

if command -v npx >/dev/null 2>&1; then
  echo
  echo "-- official MCP Inspector CLI (tools/list):"
  # Point the Inspector at THIS venv's python so it imports the installed server.
  npx --yes @modelcontextprotocol/inspector --cli "$VENV/bin/python" server.py --method tools/list \
    || echo "   (inspector CLI unavailable or offline — the Python inspector above is authoritative)"
else
  echo
  echo "-- 'npx' not found: skipping the official Inspector CLI."
  echo "   The Node-free Python inspector above already verified the full contract."
  echo "   To also drive the browser UI:  npx @modelcontextprotocol/inspector server.py"
fi

echo
echo "== verify complete =="
echo "On a real Mac every macOS-only signal should read a value; any 'unknown' is a"
echo "discrepancy to chase down (missing tool, timeout, or a probe needing elevation)."
