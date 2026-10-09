#!/usr/bin/env node
// Check that every platform this package supports maps to an asset of the release.
'use strict';

const assert = require('assert');
const { assetFor } = require('./resolve.js');

const want = {
  'linux/x64': 'sealkeep-linux-x86_64',
  'linux/arm64': 'sealkeep-linux-aarch64',
  'darwin/x64': 'sealkeep-darwin-x86_64',
  'darwin/arm64': 'sealkeep-darwin-arm64',
  'win32/x64': 'sealkeep-windows-x86_64.exe',
  'win32/arm64': null,
  'freebsd/x64': null,
};
for (const [k, v] of Object.entries(want)) {
  const [platform, arch] = k.split('/');
  assert.strictEqual(assetFor(platform, arch), v, k);
}
// The release workflow must build each of these assets.
const fs = require('fs');
const path = require('path');
const release = fs.readFileSync(path.join(__dirname, '..', '..', '.github', 'workflows', 'release.yml'), 'utf8');
for (const v of Object.values(want).filter(Boolean)) {
  assert.ok(release.includes(`asset: ${v}`), `release.yml does not build ${v}`);
}
console.error('selftest ok');
