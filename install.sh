#!/usr/bin/env bash
# Install the `probe` command into an isolated venv and symlink it onto PATH.
# Zero runtime deps; just needs python3. Usage:  ./install.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PROBE_VENV:-$HOME/.probe-venv}"
BIN="${PROBE_BIN:-$HOME/.local/bin}"

echo "==> creating venv at $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip >/dev/null
echo "==> installing probe (stdlib only, no deps)"
"$VENV/bin/pip" install -q "$HERE"

mkdir -p "$BIN"
ln -sf "$VENV/bin/probe" "$BIN/probe"
echo "==> linked $BIN/probe"

# Optional Rust accelerator (~4x). Built only if cargo is present; probe auto-detects it.
if command -v cargo >/dev/null 2>&1; then
  echo "==> cargo found — building the Rust accelerator (~4x faster)"
  if (cd "$HERE/rs" && CARGO_TARGET_DIR="$HERE/rs/target" cargo build --release -q 2>/dev/null); then
    ln -sf "$HERE/rs/target/release/probe-rs" "$BIN/probe-rs"
    echo "==> linked $BIN/probe-rs — probe will auto-use it"
  else
    echo "==> Rust build failed; continuing with the pure-Python engine"
  fi
else
  echo "==> cargo not found — pure-Python engine (install Rust + re-run for ~4x)"
fi

if ! printf '%s' ":$PATH:" | grep -q ":$BIN:"; then
  echo "NOTE: add this to your shell profile:"
  echo "    export PATH=\"$BIN:\$PATH\""
fi

echo
echo "Done. Try:"
echo "    probe selftest"
echo "    probe wrap -- kubectl logs api -n prod --tail=200000"
echo "    # Claude Code MCP: add to .mcp.json ->"
echo "    #   {\"mcpServers\":{\"probe\":{\"command\":\"$BIN/probe\",\"args\":[\"mcp\"]}}}"
