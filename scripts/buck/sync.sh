#!/bin/sh
# Copy the shared Buck2 files of desk (buck/rust/ of munhq/desk, #97) into this repository, and write their hashes.
#
#   sh <folder of munhq/desk>/buck/rust/sync.sh <folder of munhq/desk>   the first copy
#   sh scripts/buck/sync.sh <folder of munhq/desk>                         copy the files and write scripts/buck/SHARED
#   sh scripts/buck/sync.sh --check                                        fail when a copy differs from SHARED
#
# Run it from the root of the repository.
#
# The folder is any copy of munhq/desk: a desk work folder (desk checkout) or the GitHub copy. A repository keeps the
# copies in its own tree, so a build reads no other repository; SHARED names the files, their hashes and the change
# of desk they came from. Change a shared file in desk, then sync each repository.
set -eu
# The repository is the current folder: the copy in scripts/buck/ and the copy of desk both run from its root.
[ -f Cargo.toml ] && [ -d .desk ] || { echo "run sync.sh from the root of the Rust repository" >&2; exit 1; }
FILES="scripts/buck/gen_buck.py scripts/buck/run_tests.py scripts/buck/test_run.py scripts/buck/buckify.sh scripts/buck/sync.sh toolchains/BUCK platforms/BUCK platforms/defs.bzl platforms/test_run.bzl reindeer.toml"

if [ "${1:-}" = "--check" ]; then
  [ -f scripts/buck/SHARED ] || { echo "scripts/buck/SHARED is missing: run sh scripts/buck/sync.sh <folder of munhq/desk>" >&2; exit 1; }
  grep -v '^#' scripts/buck/SHARED | sha256sum --quiet -c - \
    || { echo "a shared Buck2 file differs from scripts/buck/SHARED: change it in buck/rust/ of munhq/desk, then sync" >&2; exit 1; }
  exit 0
fi

src="${1:?usage: sh scripts/buck/sync.sh <folder of munhq/desk> | --check}"
[ -f "$src/buck/rust/gen_buck.py" ] || { echo "$src has no buck/rust/gen_buck.py" >&2; exit 1; }
mkdir -p scripts/buck toolchains platforms
for f in $FILES; do
  # desk keeps no file named BUCK under buck/rust/, so that folder is no package of its own build.
  case "$f" in
    scripts/buck/*) from="$src/buck/rust/${f#scripts/buck/}" ;;
    toolchains/BUCK) from="$src/buck/rust/toolchains.BUCK" ;;
    platforms/BUCK) from="$src/buck/rust/platforms.BUCK" ;;
    platforms/defs.bzl) from="$src/buck/rust/platforms.defs.bzl" ;;
    platforms/test_run.bzl) from="$src/buck/rust/test_run.bzl" ;;
    *) from="$src/buck/rust/$f" ;;
  esac
  cp "$from" "$f"
done
chmod +x scripts/buck/buckify.sh scripts/buck/sync.sh
{
  printf '# The shared Buck2 files of buck/rust/ of munhq/desk. Written by scripts/buck/sync.sh; do not edit.\n'
  # The change of desk: the base of a desk work folder, or the commit of a git copy.
  if [ -f "$src/.desk-work/work.json" ]; then
    source="change $(sed -n 's/.*"base": *"\([0-9a-f]*\)".*/\1/p' "$src/.desk-work/work.json")"
  else
    source="commit $(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)"
  fi
  printf '# Source: munhq/desk %s\n' "$source"
  for f in $FILES; do sha256sum "$f"; done
} > scripts/buck/SHARED
echo "copied $(echo $FILES | wc -w) files from $src"
