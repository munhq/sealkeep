#!/usr/bin/env node
// The entry point of `npx -y @munhq/sealkeep`: resolve the binary, then become it.
//
// With no arguments it starts the MCP server (`sealkeep mcp`), because an MCP
// client starts the package with no arguments. With arguments it is the CLI:
// `npx @munhq/sealkeep list`.
'use strict';

const { spawnSync } = require('child_process');
const { resolveBinary, log } = require('./resolve.js');

(async () => {
  let bin;
  try {
    bin = await resolveBinary();
  } catch (err) {
    log(`could not start: ${err.message}`);
    process.exit(1);
  }

  const args = process.argv.slice(2);
  if (args.length === 0) {
    args.push('mcp');
    if (process.stdin.isTTY) {
      log('no arguments: starting the MCP server on stdio. Run `sealkeep --help` for the CLI.');
    }
  }

  // Replace this process with the binary (POSIX, Node 22.15 and later), so no
  // Node process stays resident for the MCP session.
  if (typeof process.execve === 'function') {
    try {
      process.execve(bin, [bin, ...args], process.env);
    } catch (err) {
      log(`could not exec ${bin} (${err.message}); supervising it instead`);
    }
  }

  const res = spawnSync(bin, args, { stdio: 'inherit' });
  if (res.error) {
    log(`failed to exec ${bin}: ${res.error.message}`);
    process.exit(1);
  }
  // A death by signal must not look like exit 0.
  if (res.signal) process.kill(process.pid, res.signal);
  process.exit(res.status === null ? 1 : res.status);
})();
