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

# Pick a Python >= 3.10 (the project's requires-python). An explicit PYTHON=
# override always wins; otherwise probe the common interpreter names and, as a
# last resort, a uv-managed interpreter. This keeps ./verify.sh turnkey on a
# stock Mac whose /usr/bin/python3 is still 3.9.
py_ok() { "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)' >/dev/null 2>&1; }
select_python() {
  if [ -n "${PYTHON:-}" ]; then printf '%s\n' "$PYTHON"; return 0; fi
  for cand in python3.13 python3.12 python3.11 python3.10 python3 python; do
    if command -v "$cand" >/dev/null 2>&1 && py_ok "$cand"; then command -v "$cand"; return 0; fi
  done
  if command -v uv >/dev/null 2>&1; then
    for v in 3.12 3.11 3.13 3.10; do
      p="$(uv python find "$v" 2>/dev/null)" || true
      if [ -n "$p" ] && py_ok "$p"; then printf '%s\n' "$p"; return 0; fi
    done
  fi
  return 1
}
if ! PY="$(select_python)"; then
  echo "ERROR: no Python >= 3.10 found (this project's requires-python)." >&2
  echo "       Install one, e.g.:  xcode-select --install   or   uv python install 3.12" >&2
  echo "       or point at your own:  PYTHON=/path/to/python3.10+ ./verify.sh" >&2
  exit 1
fi

echo "== SignalGrid MCP verify =="
echo "-- host: $(uname -s) $(uname -m); python: $("$PY" --version 2>&1) ($PY)"

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
