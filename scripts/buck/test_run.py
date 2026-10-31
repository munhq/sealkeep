#!/usr/bin/env python3
"""Run one test binary inside a Buck2 action (buck/rust/ of munhq/desk, #97; the rule is platforms/test_run.bzl).

  python3 test_run.py --out <log> --tree <data folder> --dir <package folder> [--one-at-a-time] -- <binary> [args]

The binary runs in <tree>/<dir> with CARGO_MANIFEST_DIR set to that folder, as cargo runs it. The environment holds
only PATH, HOME, TMPDIR and the Rust settings, so the result depends on the inputs of the action alone. The output
goes to <log>; on a failure its end is printed, and the exit code of the binary is the exit code of the action.
"""

import os
import subprocess
import sys
import tempfile


def main():
    args = sys.argv[1:]
    if "--" not in args:
        sys.exit("usage: test_run.py --out <log> --tree <dir> --dir <package> [--one-at-a-time] -- <binary> [args]")
    split = args.index("--")
    opts, command = args[:split], args[split + 1:]
    out = opts[opts.index("--out") + 1]
    tree = os.path.abspath(opts[opts.index("--tree") + 1])
    package = os.path.join(tree, opts[opts.index("--dir") + 1])
    if "--one-at-a-time" in opts:
        command.append("--test-threads=1")
    # The paths of the action are relative to the root of the project; the binary runs in its package folder.
    command[0] = os.path.abspath(command[0])
    with tempfile.TemporaryDirectory(prefix="test-run-") as scratch:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": scratch,
            "TMPDIR": scratch,
            "CARGO_MANIFEST_DIR": package,
            "RUST_BACKTRACE": "1",
        }
        with open(out, "wb") as log:
            code = subprocess.run(command, cwd=package, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    if code != 0:
        with open(out, "rb") as f:
            sys.stderr.write(f.read().decode("utf-8", "replace")[-6000:])
        sys.stderr.write(f"\nthe test binary {os.path.basename(command[0])} exited with {code}\n")
    sys.exit(code)


if __name__ == "__main__":
    main()
