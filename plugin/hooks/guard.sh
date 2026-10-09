#!/bin/sh
# Run `sealkeep guard` on the tool call that Claude Code sends on stdin.
#
# The hook runs before every Bash, Read and Grep call, so it uses a binary that is
# already on the machine: $SEALKEEP_BIN, then `sealkeep` on PATH, then the newest
# binary that the npm package cached (the MCP server of this plugin downloads it on
# its first start). With none of them, the hook lets the call through: it cannot
# check it, and a hook that refuses every call would stop the session.
set -u
bin="${SEALKEEP_BIN:-}"
if [ -z "$bin" ] || [ ! -x "$bin" ]; then
  bin="$(command -v sealkeep 2>/dev/null || true)"
fi
if [ -z "$bin" ]; then
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/sealkeep/bin"
  bin="$(ls -1t "$cache"/sealkeep-* 2>/dev/null | grep -v '\.tmp-' | head -n 1)"
fi
if [ -z "$bin" ] || [ ! -x "$bin" ]; then
  exit 0
fi
exec "$bin" guard --client claude
