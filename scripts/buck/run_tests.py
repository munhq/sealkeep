#!/usr/bin/env python3
"""Run the test binaries that Buck2 built (buck/rust/ of munhq/desk, #97).

  python3 -I scripts/buck/run_tests.py <outputs.json>

<outputs.json> is the output of `buck2 build --show-full-json-output`: the path of each target. A test target is
`<crate>-unittest` (the unit tests of a library) or `test-<name>` (tests/<name>.rs). Each binary runs in the folder of
its package with CARGO_MANIFEST_DIR set to that folder, as cargo runs it, and with the environment of this script.

The rules of .config/nextest.toml apply when the repository has that file:
  - a binary whose tests take every test slot (`threads-required = "num-test-threads"`) runs alone, after the others,
    one test at a time;
  - the binaries of a test group with `max-threads = 1` run one after the other, one test at a time, in one lane for
    each group, beside the rest;
  - every other binary runs in parallel with the others, AXON_TEST_JOBS at a time (default: the number of cores).
The output of each binary goes to a file; the output of a failed binary is printed. The exit code is 1 when a binary
fails.
"""

import json
import os
import re
import subprocess
import sys
import threading
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BINARY = re.compile(r"binary\(([A-Za-z0-9_-]+)\)")


def nextest_rules():
    """The binaries that run alone, and the binaries of each serial test group, from .config/nextest.toml.

    A binary that runs alone is in no group: it already runs with nothing beside it."""
    path = os.path.join(ROOT, ".config", "nextest.toml")
    if not os.path.exists(path):
        return set(), {}
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    serial_groups = {name for name, g in cfg.get("test-groups", {}).items() if g.get("max-threads") == 1}
    alone, groups = set(), {}
    for o in cfg.get("profile", {}).get("default", {}).get("overrides", []):
        names = set(BINARY.findall(o.get("filter", "")))
        if o.get("threads-required") == "num-test-threads":
            alone |= names
        if o.get("test-group") in serial_groups:
            groups.setdefault(o["test-group"], set()).update(names)
    return alone, {g: names - alone for g, names in groups.items()}


def test_name(label):
    """The nextest binary name of a test target: `core` for root//:core-unittest, `e2e` for root//:test-e2e."""
    name = label.split(":")[-1]
    if name.endswith("-unittest"):
        return name.removesuffix("-unittest")
    if name.startswith("test-"):
        return name.removeprefix("test-")
    return None


def package_dir(label):
    """The folder of the package of a target: the repository root for root//:x, crates/a for root//crates/a:x."""
    return os.path.normpath(os.path.join(ROOT, label.split("//", 1)[1].split(":", 1)[0]))


LOG_DIR = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"buck-tests-{os.getpid()}")
print_lock = threading.Lock()


def run(label, path, one_at_a_time):
    name = test_name(label)
    log = os.path.join(LOG_DIR, name + ".log")
    args = [path] + (["--test-threads=1"] if one_at_a_time else [])
    start = time.monotonic()
    with open(log, "wb") as out:
        env = dict(os.environ, CARGO_MANIFEST_DIR=package_dir(label))
        code = subprocess.run(args, cwd=package_dir(label), env=env, stdout=out, stderr=subprocess.STDOUT).returncode
    took = time.monotonic() - start
    with print_lock:
        if code == 0:
            if took >= 30:
                print(f"  SLOW {took:6.1f}s {name}", flush=True)
        else:
            print(f"  FAIL {took:6.1f}s {name} (exit {code}), output in {log}:", flush=True)
            with open(log, "rb") as f:
                sys.stdout.write(f.read().decode("utf-8", "replace")[-6000:])
            sys.stdout.flush()
    return name, code, took


def main():
    with open(sys.argv[1]) as f:
        outputs = json.load(f)
    tests = {label: path for label, path in outputs.items() if test_name(label)}
    alone, groups = nextest_rules()
    serial = set().union(*groups.values()) if groups else set()
    for name in alone | serial:
        if not any(test_name(label) == name for label in tests):
            sys.exit(f".config/nextest.toml names the binary {name}, and the build has no test binary of that name")
    os.makedirs(LOG_DIR, exist_ok=True)
    jobs = int(os.environ.get("AXON_TEST_JOBS", os.cpu_count() or 4))
    start = time.monotonic()
    results = []

    def serial_lane(names):
        return [run(label, path, True) for label, path in sorted(tests.items()) if test_name(label) in names]

    with ThreadPoolExecutor(max_workers=jobs + len(groups)) as pool:
        lanes = [pool.submit(serial_lane, names) for _, names in sorted(groups.items())]
        rest = [
            pool.submit(run, label, path, False)
            for label, path in sorted(tests.items())
            if test_name(label) not in alone | serial
        ]
        results += [f.result() for f in rest]
        for lane in lanes:
            results += lane.result()
    for label, path in sorted(tests.items()):
        if test_name(label) in alone:
            results.append(run(label, path, True))
    failed = sorted(name for name, code, _ in results if code != 0)
    print(f"{len(results)} test binaries in {time.monotonic() - start:.1f}s, {len(failed)} failed{': ' + ', '.join(failed) if failed else ''}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
