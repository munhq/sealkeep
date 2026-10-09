#!/usr/bin/env node
// Build the .mcpb bundle: the artefact Smithery requires for a stdio release,
// and the one Claude Desktop installs with a double click.
//
// `PUT /servers/{namespace}%2F{server}/releases` refuses a stdio release without
// a `bundle` part — it answers `Missing required part: bundle`. The first listing
// was built by hand at a terminal, which is exactly the thing that rots: the next
// version ships and the listing still describes the old one. So it is a script,
// and it reads its facts from the same files the npm package and server.json do.
//
// The bundle carries the launcher of the npm package, not a binary, and the
// launcher fetches the one release asset that the host needs.
//
// Usage: node npm/build-mcpb.mjs [--card <tools.json>] [--out <file.mcpb>]
//   --card  a `tools/list` result captured from the real server, so the declared
//           tool list cannot drift from the code. Optional: without it the
//           bundle simply declares no tools.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(path.join(here, 'package.json'), 'utf8'));

const argv = process.argv.slice(2);
const argOf = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? null : argv[i + 1];
};
// Resolved, because zip runs with cwd set to the staging directory.
const out = path.resolve(argOf('--out') || path.join(here, '..', `sealkeep-${pkg.version}.mcpb`));
const cardPath = argOf('--card');

let tools = [];
if (cardPath) {
  const card = JSON.parse(readFileSync(cardPath, 'utf8'));
  const list = card.tools || card.result?.tools || [];
  tools = list.map((t) => ({ name: t.name, description: t.description || '' }));
}

const stage = mkdtempSync(path.join(tmpdir(), 'sealkeep-mcpb-'));
try {
  mkdirSync(path.join(stage, 'server'));
  for (const f of ['sealkeep.js', 'resolve.js']) {
    copyFileSync(path.join(here, 'bin', f), path.join(stage, 'server', f));
  }
  // resolve.js reads ../package.json for the version of the release it downloads.
  writeFileSync(
    path.join(stage, 'package.json'),
    JSON.stringify({ name: pkg.name, version: pkg.version, private: true }, null, 2) + '\n'
  );

  const manifest = {
    manifest_version: '0.3',
    name: 'sealkeep',
    display_name: 'sealkeep',
    version: pkg.version,
    description: 'Let AI agents use secrets without seeing them: inject into a command, redact the output.',
    long_description:
      'The agent asks for a secret by name; sealkeep puts the value into the environment of one command and replaces it with [sealkeep:NAME] in all output. Secrets live in the OS keyring, Vault or OpenBao, AWS, Google, Azure, 1Password or Bitwarden. No tool returns a value.',
    author: { name: 'munhq', url: 'https://github.com/munhq' },
    homepage: 'https://github.com/munhq/sealkeep',
    repository: { type: 'git', url: 'https://github.com/munhq/sealkeep' },
    license: 'MIT',
    keywords: ['mcp', 'secrets', 'keyring', 'vault', 'security'],
    icons: [
      { src: 'https://raw.githubusercontent.com/munhq/sealkeep/main/docs/brand/icon-128.png', size: '128x128' },
      { src: 'https://raw.githubusercontent.com/munhq/sealkeep/main/docs/brand/icon-512.png', size: '512x512' },
    ],
    server: {
      type: 'node',
      entry_point: 'server/sealkeep.js',
      mcp_config: { command: 'node', args: ['${__dirname}/server/sealkeep.js', 'mcp'] },
    },
    tools,
    tools_generated: false,
    compatibility: { platforms: ['darwin', 'win32', 'linux'], runtimes: { node: '>=18.0.0' } },
  };
  writeFileSync(path.join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  rmSync(out, { force: true });
  execFileSync('zip', ['-qr', out, '.'], { cwd: stage });
} finally {
  rmSync(stage, { recursive: true, force: true });
}

const bytes = readFileSync(out);
process.stdout.write(
  `${path.basename(out)}  ${statSync(out).size} bytes  sha256=${createHash('sha256').update(bytes).digest('hex')}\n` +
    `  version ${pkg.version}, ${tools.length} tool(s) declared\n`
);
