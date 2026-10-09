#!/bin/sh
# Install sealkeep from the newest GitHub release: download the binary for this machine,
# check it against SHA256SUMS, copy it to ~/.local/bin (or $SEALKEEP_BIN_DIR), then run
# `sealkeep install` to add the skill, the MCP server and the guard hook to each AI client.
#
#   curl -fsSL https://raw.githubusercontent.com/munhq/sealkeep/main/install.sh | sh
#
# Arguments go to `sealkeep install`, for example: sh install.sh --client claude --dry-run
set -eu

repo="munhq/sealkeep"
bin_dir="${SEALKEEP_BIN_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "sealkeep: this script supports Linux and macOS. On Windows, download sealkeep-windows-x86_64.exe from https://github.com/$repo/releases." >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  aarch64) arch=aarch64 ;;
  arm64) if [ "$os" = darwin ]; then arch=arm64; else arch=aarch64; fi ;;
  *) echo "sealkeep: no release binary for $(uname -m). Build it: cargo install --git https://github.com/$repo" >&2; exit 1 ;;
esac
asset="sealkeep-$os-$arch"
base="https://github.com/$repo/releases/latest/download"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
(
  cd "$tmp"
  if command -v sha256sum >/dev/null 2>&1; then
    grep " $asset\$" SHA256SUMS | sha256sum -c -
  else
    grep " $asset\$" SHA256SUMS | shasum -a 256 -c -
  fi
)

mkdir -p "$bin_dir"
install -m 0755 "$tmp/$asset" "$bin_dir/sealkeep"
echo "Installed $bin_dir/sealkeep"
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) echo "$bin_dir is not on PATH. Add this line to your shell profile: export PATH=\"$bin_dir:\$PATH\"" >&2 ;;
esac
"$bin_dir/sealkeep" install "$@"
