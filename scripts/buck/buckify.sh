#!/bin/sh
# Write //third-party from third-party/Cargo.toml (buck/rust/ of munhq/desk, #113, #116). reindeer gives each build
# script the cargo variables of a debug build (OPT_LEVEL 0, PROFILE debug); cc-rs compiles the C code of ring, aws-lc and
# the others with them. A release build (scripts/release.sh, -c desk.profile=release) needs the values of
# [profile.release], so the two values are read from the config, with the debug values as default.
set -eu
cd "$(dirname "$0")/../.."
reindeer buckify
sed -i \
  -e 's/"OPT_LEVEL": "0",/"OPT_LEVEL": read_root_config("desk", "build_script_opt_level", "0"),/' \
  -e 's/"PROFILE": "debug",/"PROFILE": read_root_config("desk", "build_script_profile", "debug"),/' \
  third-party/BUCK
grep -c 'build_script_opt_level' third-party/BUCK
