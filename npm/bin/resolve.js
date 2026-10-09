// Resolve a sealkeep binary for this platform, downloading the pinned release
// asset when the cache does not already hold it.
//
// Every MCP directory installs servers the way npm installs them: the official
// registry validates an npm version, Smithery runs `npx`, and mcp.so lists the
// same command. This package is the small shim that makes `npx -y @munhq/sealkeep`
// work: it fetches the binary that the GitHub release publishes, checks it
// against SHA256SUMS, and runs it.
//
// Write NOTHING to stdout. Stdout is the MCP JSON-RPC channel; one stray line
// there makes the server look broken with no error that explains why. Every
// diagnostic goes to stderr, which the client logs.
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { Transform, pipeline } = require('stream');

const REPO = 'munhq/sealkeep';
const { version: VERSION } = require('../package.json');

const log = (msg) => process.stderr.write(`sealkeep: ${msg}\n`);

// Map Node's platform/arch onto the asset names of the release
// (.github/workflows/release.yml): sealkeep-linux-x86_64, sealkeep-linux-aarch64,
// sealkeep-darwin-x86_64, sealkeep-darwin-arm64, sealkeep-windows-x86_64.exe.
// Pure, so selftest.js can check every platform this package claims.
function assetFor(platform, arch) {
  if (platform === 'linux') {
    const a = { x64: 'x86_64', arm64: 'aarch64' }[arch];
    return a ? `sealkeep-linux-${a}` : null;
  }
  if (platform === 'darwin') {
    const a = { x64: 'x86_64', arm64: 'arm64' }[arch];
    return a ? `sealkeep-darwin-${a}` : null;
  }
  if (platform === 'win32' && arch === 'x64') return 'sealkeep-windows-x86_64.exe';
  return null;
}

function assetName() {
  return assetFor(process.platform, process.arch);
}

function cacheDir() {
  const base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  return path.join(base, 'sealkeep', 'bin');
}

// The cached file carries the version, so an upgrade of this package is a cache
// miss and never runs an older binary.
function cachedBinary() {
  const exe = process.platform === 'win32' ? '.exe' : '';
  return path.join(cacheDir(), `sealkeep-${VERSION}${exe}`);
}

function get(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error(`too many redirects for ${url}`));
    https
      .get(url, { headers: { 'user-agent': `sealkeep-npm/${VERSION}` } }, (res) => {
        // GitHub serves release assets as a redirect to object storage.
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(get(res.headers.location, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

// Stream an asset to `dest`, hashing the bytes as they go past. Resolves to the
// hex digest. The hash is incremental and the write is a pipe, so the binary is
// never held in memory.
function download(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error(`too many redirects for ${url}`));
    https
      .get(url, { headers: { 'user-agent': `sealkeep-npm/${VERSION}` } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return resolve(download(res.headers.location, dest, redirects + 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`GET ${url} -> HTTP ${res.statusCode}`));
        }
        const hash = crypto.createHash('sha256');
        // The hash is a pass-through in the pipeline, so `pipeline` keeps the
        // source paused whenever the disk is behind.
        const tap = new Transform({
          transform(chunk, _enc, cb) {
            hash.update(chunk);
            cb(null, chunk);
          },
        });
        pipeline(res, tap, fs.createWriteStream(dest, { mode: 0o755 }), (err) =>
          err ? reject(err) : resolve(hash.digest('hex'))
        );
      })
      .on('error', reject);
  });
}

// The checksum published beside the binary is not proof on its own — whoever can
// replace one can replace the other. It is here to catch a truncated download
// and a mismatched tag, which are the failures that actually happen, and to make
// the pin auditable: both files come from the tag this package version names.
async function verifiedDownload(asset) {
  const base = `https://github.com/${REPO}/releases/download/v${VERSION}`;
  log(`fetching ${asset} for v${VERSION} (once per version)`);

  const sums = (await get(`${base}/SHA256SUMS`)).toString('utf8');
  const line = sums.split('\n').find((l) => l.trim().endsWith(` ${asset}`));
  if (!line) throw new Error(`SHA256SUMS for v${VERSION} does not list ${asset}`);
  const want = line.trim().split(/\s+/)[0];

  const dest = cachedBinary();
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  // Download to a temp name and rename, so a killed download never leaves a
  // half file that the next run treats as installed. The name carries this
  // process's pid because several sessions can start at once on a cold cache,
  // and one shared temp name would let them write over each other.
  const tmp = `${dest}.tmp-${process.pid}`;
  const discard = () => {
    try {
      fs.unlinkSync(tmp);
    } catch {}
  };

  let got;
  try {
    got = await download(`${base}/${asset}`, tmp);
  } catch (err) {
    discard();
    throw err;
  }
  if (got !== want) {
    discard();
    throw new Error(`checksum mismatch for ${asset}: want ${want}, got ${got}`);
  }
  // A umask can clear the mode the stream was created with, and a binary that
  // is not executable fails later with a message about the wrong thing.
  fs.chmodSync(tmp, 0o755);
  fs.renameSync(tmp, dest);
  log(`installed ${dest}`);
  return dest;
}

// An explicit override wins, for a local build. The binary on PATH is not used:
// this package declares one version to the registry, and it runs that version.
async function resolveBinary() {
  const override = process.env.SEALKEEP_BIN;
  if (override && fs.existsSync(override)) return override;

  const cached = cachedBinary();
  if (fs.existsSync(cached)) return cached;

  const asset = assetName();
  if (!asset) {
    throw new Error(
      `no release build for ${process.platform}/${process.arch}. ` +
        `Build from source: cargo install --git https://github.com/${REPO}`
    );
  }
  return verifiedDownload(asset);
}

module.exports = { resolveBinary, cachedBinary, assetName, assetFor, VERSION, log };
