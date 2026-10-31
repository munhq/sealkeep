#!/usr/bin/env python3
"""Write the Buck2 rules of a Rust workspace from `cargo metadata` (munhq/desk#97, #113).

The shared copy of desk (buck/rust/), for every Rust repository that desk builds. A repository runs the copy that
scripts/buck/sync.sh put into its scripts/buck/, and describes what differs in .desk/buck-rust.json:
  name             the section of the Buck2 config for the commit stamp (-c <name>.build_sha=<id>) and the release
  build_sha_env    the variable of the commit stamp; a target gets it when its own sources read it
  release          optional: {"features": "a,b", "bins": ["x"]}, the features and the binaries of the images
                   (`-release` targets, `//:release`)
  check_filegroup  optional, false by default: write //:check, a filegroup of every binary and test binary
  test_data        optional: the globs of the files that the tests read at run time, from the root of their Buck2
                   package (default: every file but the Rust sources, the files of the build and the build folders)
  issue            the issue that the generated files name

Cargo resolves the features and the dependencies; this script copies that resolution, so Buck2 builds the same graph
as `cargo test --no-run --workspace`. It writes:
  third-party/Cargo.toml   each external dependency of the workspace, pinned, with the features cargo resolved; reindeer
                           makes //third-party from it (third-party/BUCK)
  BUCK, crates/*/BUCK      the rules of the workspace packages; each test gets a `-run` target (platforms/test_run.bzl)
                           that runs it as a cached action, and //:test-runs builds them all
After a change of a Cargo.toml: python3 -I scripts/buck/gen_buck.py && sh scripts/buck/buckify.sh
With --check, it writes nothing and fails when one of these files is out of date.
With --check-inputs, it reads no cargo metadata: it fails when the hash of the inputs (every Cargo.toml, Cargo.lock,
.desk/buck-rust.json and this script) differs from the one that the last run wrote into BUCK. A runner of desk has no
copy of the crates, so `cargo metadata --offline` fails there, and this check needs none.
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKSPACE = ROOT
TARGET = "x86_64-unknown-linux-gnu"
LIB_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}

with open(os.path.join(ROOT, ".desk", "buck-rust.json")) as _f:
    CONFIG = json.load(_f)
NAME = CONFIG["name"]
SHA_ENV = CONFIG["build_sha_env"]
ISSUE = CONFIG["issue"]
RELEASE = CONFIG.get("release")
CHECK_FILEGROUP = CONFIG.get("check_filegroup", False)
TEST_DATA = CONFIG.get("test_data")

# With --check, the script writes nothing and fails when a file it writes differs from the one in the repository.
CHECK = "--check" in sys.argv[1:]
CHECK_INPUTS = "--check-inputs" in sys.argv[1:]
INPUTS_LINE = "# Inputs: sha256 "
SKIP_INPUT_DIRS = {"target", "buck-out", "node_modules", ".git", "third-party", ".desk-work"}


def inputs_hash():
    """The sha256 of the files that decide the rules: every Cargo.toml of the repository, Cargo.lock, the config of
    .desk/buck-rust.json and this script, each with its path."""
    paths = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_INPUT_DIRS)
        paths += [os.path.join(base, f) for f in files if f == "Cargo.toml"]
    paths += [os.path.join(ROOT, "Cargo.lock"), os.path.join(ROOT, ".desk", "buck-rust.json"), os.path.abspath(__file__)]
    h = hashlib.sha256()
    for p in sorted(set(paths)):
        h.update(rel(p).encode() + b"\0")
        with open(p, "rb") as f:
            h.update(f.read())
        h.update(b"\0")
    return h.hexdigest()
stale_files = []


def emit(path, text):
    if CHECK:
        try:
            current = open(path, encoding="utf-8").read()
        except FileNotFoundError:
            current = None
        if current != text:
            stale_files.append(rel(path))
        return
    with open(path, "w") as f:
        f.write(text)


def say(*args):
    if not CHECK:
        print(*args)

# Files read at compile time: include_str!/include_bytes! name a file next to the source, sqlx::migrate! a folder
# under CARGO_MANIFEST_DIR.
INCLUDE = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)')
MIGRATE = re.compile(r'sqlx::migrate!\(\s*"([^"]+)"\s*\)')


def metadata(features=None):
    extra = ["--features", features] if features else []
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--offline", "--filter-platform", TARGET] + extra,
        cwd=WORKSPACE, check=True, capture_output=True, text=True,
    ).stdout
    return json.loads(out)


def rel(path):
    return os.path.relpath(path, ROOT)


SKIP_DIRS = ("target", "node_modules", ".git", "buck-out")


def compile_inputs(pkg_dir):
    """The files that a source of the package reads at compile time, outside its src/, as absolute paths.

    The walk skips the folders of nested packages: their sources belong to their own rules."""
    found = set()
    for base, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.exists(os.path.join(base, d, "Cargo.toml"))]
        for f in files:
            if not f.endswith(".rs"):
                continue
            path = os.path.join(base, f)
            text = open(path, encoding="utf-8", errors="replace").read()
            for m in INCLUDE.finditer(text):
                found.add(os.path.normpath(os.path.join(base, m.group(1))))
            for m in MIGRATE.finditer(text):
                found.add(os.path.normpath(os.path.join(pkg_dir, m.group(1))))
    src = os.path.join(pkg_dir, "src") + os.sep
    return sorted(p for p in found if not p.startswith(src))


def input_globs(inputs, home):
    """The inputs as globs relative to the Buck2 package at `home`."""
    globs = set()
    for p in inputs:
        r = os.path.relpath(p, home)
        if r.startswith(".."):
            sys.exit(f"{p}: a compile-time input outside the repository is not supported")
        globs.add(r + "/**" if os.path.isdir(p) else r)
    return sorted(globs)


MOD_DECL = re.compile(r"^\s*(?:pub\s+)?mod\s+([a-z_][a-z0-9_]*)\s*;", re.M)


def test_modules(test_root):
    """The files of the modules that the root file of an integration test declares (`mod common;`), as absolute
    paths: tests/common.rs, or the folder tests/common/."""
    base = os.path.dirname(test_root)
    found = []
    for name in MOD_DECL.findall(open(test_root, encoding="utf-8").read()):
        for cand in (os.path.join(base, name + ".rs"), os.path.join(base, name)):
            if os.path.exists(cand):
                found.append(cand)
    return found


def reads_env(path):
    """Whether a source file reads SHA_ENV at compile time: env!("...") or option_env!("...")."""
    return re.search(r'\b(?:option_)?env!\(\s*"' + re.escape(SHA_ENV) + '"', open(path, encoding="utf-8").read()) is not None


def reads_sha(target, bin_roots):
    """Whether the sources of a target read the commit that the build script stamps (SHA_ENV).

    A binary reads it in its main file. A library reads it in any file of its folder that is not the main file of a
    binary. Only such a target gets the stamp, so a new commit compiles no other target."""
    if LIB_KINDS & set(target["kind"]):
        src = os.path.dirname(target["src_path"])
        for base, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d != "bin"]
            for f in files:
                path = os.path.join(base, f)
                if f.endswith(".rs") and path not in bin_roots and reads_env(path):
                    return True
        return False
    return reads_env(target["src_path"])


def home_of(pkg_dir, pkg_dirs):
    """The folder of the BUCK file that holds the rules of the package.

    A Buck2 rule reads files of its own package only. So a package that reads a file outside its folder at compile
    time (the migrations, the templates, the test fixtures), and a package with a file that another package reads at
    compile time, has its rules in the root BUCK."""
    if any(not p.startswith(pkg_dir + os.sep) for p in compile_inputs(pkg_dir)):
        return ROOT
    for other in pkg_dirs:
        if other != pkg_dir and any(p.startswith(pkg_dir + os.sep) for p in compile_inputs(other)):
            return ROOT
    return pkg_dir


def cargo_env(pkg, crate, extra, manifest_dir):
    v = pkg["version"].split("-")[0].split(".")
    env = {
        "CARGO_CRATE_NAME": crate,
        # rustc runs in the source tree of the rule, and that tree starts at the folder of the BUCK file.
        "CARGO_MANIFEST_DIR": manifest_dir,
        "CARGO_PKG_NAME": pkg["name"],
        "CARGO_PKG_VERSION": pkg["version"],
        "CARGO_PKG_VERSION_MAJOR": v[0],
        "CARGO_PKG_VERSION_MINOR": v[1],
        "CARGO_PKG_VERSION_PATCH": v[2],
        "CARGO_PKG_VERSION_PRE": "",
        "CARGO_PKG_AUTHORS": ":".join(pkg.get("authors") or []),
        "CARGO_PKG_DESCRIPTION": pkg.get("description") or "",
        "CARGO_PKG_LICENSE": pkg.get("license") or "",
        "CARGO_PKG_LICENSE_FILE": pkg.get("license_file") or "",
        "CARGO_PKG_HOMEPAGE": pkg.get("homepage") or "",
        "CARGO_PKG_REPOSITORY": pkg.get("repository") or "",
        "CARGO_PKG_RUST_VERSION": pkg.get("rust_version") or "",
    }
    env.update(extra)
    return env


def starlark(value, indent=1):
    pad = "    " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = "".join(f'{pad}    {json.dumps(k)}: {starlark(v, indent + 1)},\n' for k, v in sorted(value.items()))
        return "{\n" + items + pad + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        items = "".join(f"{pad}    {starlark(v, indent + 1)},\n" for v in value)
        return "[\n" + items + pad + "]"
    if isinstance(value, bool):
        return "True" if value else "False"
    return json.dumps(value)


def rule(kind, attrs):
    body = "".join(f"    {k} = {starlark(v)},\n" for k, v in attrs.items() if v not in (None, [], {}))
    return f"{kind}(\n{body})\n"


GIT_SOURCE = re.compile(r"^git\+(?P<url>[^?#]+)\?tag=(?P<tag>[^#]+)#")


def nextest_lane():
    """The test binaries that run one at a time on the runner, in the order of their lane (.config/nextest.toml): the
    binaries of the serial test groups, then the ones that take every test slot. Each runs after the one before it."""
    import tomllib

    path = os.path.join(ROOT, ".config", "nextest.toml")
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    serial_groups = {name for name, g in cfg.get("test-groups", {}).items() if g.get("max-threads") == 1}
    alone, serial = set(), set()
    for o in cfg.get("profile", {}).get("default", {}).get("overrides", []):
        names = set(re.findall(r"binary\(([A-Za-z0-9_-]+)\)", o.get("filter", "")))
        if o.get("threads-required") == "num-test-threads":
            alone |= names
        if o.get("test-group") in serial_groups:
            serial |= names
    return sorted(serial - alone) + sorted(alone)


def test_data_globs():
    """The files that the tests read at run time, from the root of a Buck2 package."""
    if TEST_DATA is not None:
        return {"include": TEST_DATA, "exclude": []}
    # The files of the build itself are no data of a test, so a change of them runs no test again.
    build = ["**/BUCK", ".buckconfig", ".buckconfig.local", ".buckroot", "platforms/**", "toolchains/**", "scripts/buck/**"]
    # A glob of Buck2 leaves out the files whose name starts with a dot, unless a pattern names them: munbot's tests read
    # .dockerignore.
    return {"include": ["**", "**/.*"], "exclude": ["**/*.rs"] + build + [d + "/**" for d in sorted(SKIP_INPUT_DIRS)]}


def third_party_manifest(packages, nodes, local, release_nodes):
    """third-party/Cargo.toml: the normal and dev dependencies of the workspace that are not in it, as resolved for the
    check and for the images. A crate has one rule in //third-party, so it gets the features of both resolutions."""
    wanted = {}
    for graph in (nodes, release_nodes):
        for pid in local:
            for d in graph[pid]["deps"]:
                kinds = {k["kind"] or "normal" for k in d["dep_kinds"]}
                if d["pkg"] in local or not kinds & {"normal", "dev"}:
                    continue
                wanted[d["pkg"]] = packages[d["pkg"]]
    names = {}
    for pid, p in wanted.items():
        names.setdefault(p["name"], []).append(pid)
    lines = []
    for pid, p in sorted(wanted.items(), key=lambda x: (x[1]["name"], x[1]["version"])):
        key = p["name"] if len(names[p["name"]]) == 1 else f'{p["name"]}-{p["version"].split(".")[0]}'
        spec = {} if key == p["name"] else {"package": p["name"]}
        git = GIT_SOURCE.match(p["source"] or "")
        if git:
            spec.update({"git": git.group("url"), "tag": git.group("tag")})
        elif (p["source"] or "").startswith("registry+"):
            spec["version"] = "=" + p["version"]
        else:
            sys.exit(f'{p["name"]}: the source {p["source"]} is not a registry or a git tag')
        spec["default-features"] = False
        spec["features"] = sorted(set(nodes.get(pid, {}).get("features", [])) | set(release_nodes.get(pid, {}).get("features", [])))
        body = ", ".join(f"{k.replace('_', '-') if k == 'default_features' else k} = {json.dumps(v)}" for k, v in spec.items())
        lines.append(f"{json.dumps(key) if '.' in key else key} = {{ {body} }}")
    text = (
        f"# @generated by scripts/buck/gen_buck.py from `cargo metadata` ({ISSUE}). Do not edit.\n"
        f"# The external dependencies of {NAME}, pinned and with the features that cargo resolved; reindeer makes BUCK.\n"
        "[workspace]\n\n[package]\nname = \"rust-third-party\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n"
        "[lib]\npath = \"top.rs\"\n\n[dependencies]\n" + "\n".join(lines) + "\n"
    )
    if not CHECK:
        os.makedirs(os.path.join(ROOT, "third-party"), exist_ok=True)
    emit(os.path.join(ROOT, "third-party", "Cargo.toml"), text)
    top = os.path.join(ROOT, "third-party", "top.rs")
    if not os.path.exists(top) and not CHECK:
        open(top, "w").close()
    say("wrote third-party/Cargo.toml with", len(lines), "dependencies")


def main():
    meta = metadata()
    # Without a release in the config, the release resolution is the one of the check, and no -release target is
    # written.
    release_meta = metadata(RELEASE["features"]) if RELEASE else meta
    packages = {p["id"]: p for p in meta["packages"]}
    packages.update({p["id"]: p for p in release_meta["packages"] if p["id"] not in packages})
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    release_nodes = {n["id"]: n for n in release_meta["resolve"]["nodes"]}
    local = {pid for pid, p in packages.items() if p["source"] is None}
    third_party_manifest(packages, nodes, local, release_nodes)
    check = []
    release = []
    pkg_dirs = [os.path.dirname(packages[pid]["manifest_path"]) for pid in local]
    home = {pid: home_of(os.path.dirname(packages[pid]["manifest_path"]), pkg_dirs) for pid in local}
    buck_files = {}
    # The run of each test: (Buck2 package, test target, nextest name, package folder from the root).
    test_runs = []

    def label(pid, suffix=""):
        p = packages[pid]
        if pid in local:
            return "//" + ("" if home[pid] == ROOT else rel(home[pid])) + ":" + lib_name(p) + suffix
        return "//third-party:" + p["name"]

    def lib_name(p):
        return next(t["name"] for t in p["targets"] if LIB_KINDS & set(t["kind"]))

    def resolve(node, suffix):
        """The deps and the renamed deps of a package in one resolution; a local dep gets the targets of `suffix`."""
        deps = {"normal": [], "dev": []}
        named = {"normal": {}, "dev": {}}
        for d in node["deps"]:
            dep_pkg = packages[d["pkg"]]
            kinds = {k["kind"] or "normal" for k in d["dep_kinds"]}
            plain = dep_pkg["name"].replace("-", "_")
            lib = lib_name(dep_pkg).replace("-", "_")
            for kind in ("normal", "dev"):
                if kind not in kinds:
                    continue
                if d["name"] in (plain, lib):
                    deps[kind].append(label(d["pkg"], suffix))
                else:
                    named[kind][d["name"]] = label(d["pkg"], suffix)
        return deps, named

    for pid in sorted(local, key=lambda i: packages[i]["name"]):
        pkg = packages[pid]
        node = nodes[pid]
        pkg_dir = os.path.dirname(pkg["manifest_path"])
        deps, named = resolve(node, "")
        here = home[pid]
        src_dir = os.path.relpath(os.path.join(pkg_dir, "src"), here)
        inputs = input_globs(compile_inputs(pkg_dir), here)
        srcs = [src_dir + "/**"] + inputs
        srcs_expr = "glob(" + starlark(srcs, 1) + ")"
        manifest_dir = os.path.relpath(pkg_dir, here)
        # A test runs from the project root, so at runtime the package folder is its path from the root; cargo gives
        # each test process the same variable.
        test_manifest_dir = os.path.relpath(pkg_dir, ROOT)
        out = []
        where = "//" + ("" if here == ROOT else rel(here))
        features = sorted(node["features"])
        lib_target = next((t for t in pkg["targets"] if LIB_KINDS & set(t["kind"])), None)
        lib_crate = lib_target["name"].replace("-", "_") if lib_target else None
        own = f":{lib_target['name']}" if lib_target else None
        bin_roots = {t["src_path"] for t in pkg["targets"] if "bin" in t["kind"]}
        lib_sha = {SHA_ENV: "@@SHA@@"} if lib_target and reads_sha(lib_target, bin_roots) else None

        # The binaries and the tests link on a worker: system_cxx_toolchain of the prelude links every binary on the
        # machine of the build, and `is_core_tool` is the label that the prelude reads to link one on RE
        # (local_only.bzl). A one-file change of axon brought 1.3 GiB of libraries to the runner to link one test
        # (desk run 374), and the image of axon 1.3 GiB to link its binary (run 413).
        CHECK_LABELS = ["is_core_tool"]

        def common(crate, root, kind_deps, with_lib, extra=None, deps=deps, named=named, features=features, own=own):
            d = sorted(set(deps["normal"] + (deps["dev"] if kind_deps == "dev" else [])))
            n = dict(named["normal"])
            if kind_deps == "dev":
                n.update(named["dev"])
            if with_lib and own:
                d = [own] + d
            return {
                "crate": crate,
                "crate_root": os.path.relpath(root, here),
                "edition": pkg["edition"],
                "env": cargo_env(pkg, crate, extra or {}, manifest_dir),
                "features": features,
                "deps": d,
                "named_deps": n,
            }

        for t in pkg["targets"]:
            kinds = set(t["kind"])
            if t.get("required-features") and not set(t["required-features"]) <= set(features):
                continue
            crate = t["name"].replace("-", "_")
            if LIB_KINDS & kinds:
                attrs = {"name": t["name"], "srcs": "@@SRCS@@"}
                attrs.update(common(crate, t["src_path"], "normal", False, lib_sha))
                attrs["visibility"] = ["PUBLIC"]
                out.append(rule("rust_library", attrs))
                attrs = {"name": t["name"] + "-unittest", "srcs": "@@SRCS@@"}
                attrs.update(common(crate, t["src_path"], "dev", False, lib_sha))
                attrs["run_env"] = {"CARGO_MANIFEST_DIR": test_manifest_dir}
                attrs["labels"] = CHECK_LABELS
                attrs["visibility"] = ["PUBLIC"]
                out.append(rule("rust_test", attrs))
                check.append(f"{where}:{t['name']}-unittest")
                test_runs.append((here, t["name"] + "-unittest", t["name"], test_manifest_dir))
            elif "bin" in kinds:
                attrs = {"name": t["name"] + "-bin" if t["name"] == lib_crate else t["name"], "srcs": "@@SRCS@@"}
                # The build script stamps the commit; a Buck2 build gives it to each target whose sources read it, from
                # -c <name>.build_sha=<id>, so a new commit compiles no other target.
                extra = {SHA_ENV: "@@SHA@@"} if reads_sha(t, bin_roots) else None
                attrs.update(common(crate, t["src_path"], "normal", True, extra))
                attrs["labels"] = CHECK_LABELS
                attrs["visibility"] = ["PUBLIC"]
                out.append(rule("rust_binary", attrs))
                check.append(f"{where}:{attrs['name']}")
            elif "test" in kinds:
                attrs = {"name": "test-" + t["name"], "srcs": "@@SRCS@@"}
                attrs.update(common(crate, t["src_path"], "dev", True))
                attrs["run_env"] = {"CARGO_MANIFEST_DIR": test_manifest_dir}
                test_srcs = [src_dir + "/**", os.path.relpath(t["src_path"], here)] + inputs
                # The modules that the test declares (`mod common;`) are sources of the test.
                test_srcs += input_globs(test_modules(t["src_path"]), here)
                attrs["srcs"] = "@@TESTSRCS:" + json.dumps(sorted(set(test_srcs))) + "@@"
                attrs["labels"] = CHECK_LABELS
                attrs["visibility"] = ["PUBLIC"]
                out.append(rule("rust_test", attrs))
                check.append(f"{where}:test-{t['name']}")
                test_runs.append((here, "test-" + t["name"], t["name"], test_manifest_dir))
        # The targets of the images: each library and the binaries of the images, with the features of the images.
        if RELEASE and pid in release_nodes:
            r_deps, r_named = resolve(release_nodes[pid], "-release")
            r = dict(deps=r_deps, named=r_named, features=sorted(release_nodes[pid]["features"]), own=f":{lib_target['name']}-release" if lib_target else None)
            for t in pkg["targets"]:
                kinds = set(t["kind"])
                crate = t["name"].replace("-", "_")
                if LIB_KINDS & kinds:
                    attrs = {"name": t["name"] + "-release", "srcs": "@@SRCS@@"}
                    attrs.update(common(crate, t["src_path"], "normal", False, **r))
                    attrs["labels"] = CHECK_LABELS
                    attrs["visibility"] = ["PUBLIC"]
                    out.append(rule("rust_library", attrs))
                elif "bin" in kinds and t["name"] in RELEASE["bins"]:
                    attrs = {"name": (t["name"] + "-bin" if t["name"] == lib_crate else t["name"]) + "-release", "srcs": "@@SRCS@@"}
                    extra = {SHA_ENV: "@@SHA@@"} if reads_sha(t, bin_roots) else None
                    attrs.update(common(crate, t["src_path"], "normal", True, extra, **r))
                    attrs["labels"] = CHECK_LABELS
                    attrs["visibility"] = ["PUBLIC"]
                    out.append(rule("rust_binary", attrs))
                    release.append(f"{where}:{attrs['name']}")
        text = "".join(out)
        text = text.replace('"@@SRCS@@"', srcs_expr)
        text = re.sub(r'"@@TESTSRCS:(.*?)@@"', lambda m: "glob(" + starlark(json.loads(m.group(1).replace('\\"', '"')), 1) + ")", text)
        text = text.replace('"@@SHA@@"', f'read_config("{NAME}", "build_sha", "unknown")')
        buck_files.setdefault(here, []).append(text)
    header = f"# @generated by scripts/buck/gen_buck.py from `cargo metadata` ({ISSUE}). Do not edit.\n\n"
    # The runs of the tests, in the package of each test. The tests of the lane of .config/nextest.toml run one test at a
    # time, each after the one before it, so no two of them share their services at once; every other test runs beside
    # the rest. Each runs on any worker, so no binary comes down to the runner.
    lane = nextest_lane()
    names = {name for _, _, name, _ in test_runs}
    for name in lane:
        if name not in names:
            sys.exit(f".config/nextest.toml names the binary {name}, and the workspace has no test of that name")
    order = {name: i for i, name in enumerate(lane)}
    # The data of every package of the workspace: a test reads files of other packages by their path from its own.
    homes = sorted(set(buck_files) | {ROOT})
    data_targets = ["//" + ("" if h == ROOT else rel(h)) + ":test-data" for h in homes]
    for h in homes:
        buck_files.setdefault(h, []).append(rule("rust_test_data", {"name": "test-data", "srcs": "@@TESTDATA@@", "visibility": ["PUBLIC"]}).replace('"@@TESTDATA@@"', "TEST_DATA"))
    previous = None
    runs = []
    for here, target, name, manifest_dir in sorted(test_runs, key=lambda r: (order.get(r[2], -1), r[0], r[1])):
        where = "//" + ("" if here == ROOT else rel(here))
        attrs = {"name": target + "-run", "test": ":" + target, "data": data_targets, "runner": "//:test_run.py", "manifest_dir": manifest_dir}
        if name in order:
            attrs["one_at_a_time"] = True
            if previous:
                attrs["after"] = [previous]
            previous = f"{where}:{target}-run"
        attrs["visibility"] = ["PUBLIC"]
        buck_files.setdefault(here, []).append(rule("rust_test_run", attrs))
        runs.append(f"{where}:{target}-run")
    test_load = 'load("//platforms:test_run.bzl", "rust_test_data", "rust_test_run")\n\n'
    data = test_data_globs()
    test_data = "# The files that the tests read at run time (.desk/buck-rust.json test_data).\nTEST_DATA = glob(" + starlark(data["include"], 0) + (", exclude = " + starlark(data["exclude"], 0) if data["exclude"] else "") + ")\n\n"
    # A package whose rules moved to the root BUCK loses the BUCK file that this script wrote for it before: while
    # that file exists, its folder is a Buck2 package, and a rule of the root package cannot read its files.
    for pid in local:
        pkg_dir = os.path.dirname(packages[pid]["manifest_path"])
        stale = os.path.join(pkg_dir, "BUCK")
        if home[pid] == ROOT and pkg_dir != ROOT and os.path.exists(stale):
            with open(stale) as f:
                generated = f.read().startswith("# @generated by scripts/buck/gen_buck.py")
            if not generated:
                sys.exit(f"{rel(stale)}: the rules of the package moved to the root BUCK, and this BUCK was not written by gen_buck.py")
            if CHECK:
                stale_files.append(rel(stale))
            else:
                os.remove(stale)
                say("removed", rel(stale))
    for here, texts in sorted(buck_files.items()):
        if here == ROOT:
            continue
        emit(os.path.join(here, "BUCK"), header + (test_load + test_data if test_runs else "") + "\n".join(texts))
        say("wrote", rel(os.path.join(here, "BUCK")))
    text = header + (test_load + test_data if test_runs else "") + "\n".join(buck_files.get(ROOT, []))
    # The runner of the test runs, and //:test-runs: the check builds it with no output on the runner (scripts/check.sh).
    text += "\n# The script that runs one test binary in its action (platforms/test_run.bzl).\n" + rule("export_file", {"name": "test_run.py", "src": "scripts/buck/test_run.py", "visibility": ["PUBLIC"]})
    text += "\n# Every test run of the workspace: an unchanged test is a hit of the action cache.\n" + rule("filegroup", {"name": "test-runs", "srcs": {t.lstrip("/").replace(":", "/").lstrip("/"): t for t in sorted(runs)}, "visibility": ["PUBLIC"]})
    # //:check builds every binary and test binary of the workspace: the same set as cargo test --no-run --workspace.
    # A filegroup copies each output into its folder, so a repository without it builds `//: //crates/...` and reads
    # the path of each output from the JSON of the build.
    if CHECK_FILEGROUP:
        text += f"\n# The check of {NAME} (scripts/check.sh): every binary and test binary of the workspace.\n" + rule("filegroup", {"name": "check", "srcs": {t.lstrip("/").replace(":", "/").lstrip("/"): t for t in sorted(check)}, "visibility": ["PUBLIC"]})
    if RELEASE:
        text += f"\n# The binaries of the images (scripts/release.sh, with -c {NAME}.profile=release).\n" + rule("filegroup", {"name": "release", "srcs": {t.split(":")[1].removesuffix("-release").removesuffix("-bin"): t for t in sorted(release)}, "visibility": ["PUBLIC"]})
    # The hash of the inputs, which --check-inputs compares with no cargo metadata.
    emit(os.path.join(ROOT, "BUCK"), text.replace(header, header.rstrip("\n") + "\n" + INPUTS_LINE + inputs_hash() + "\n\n", 1))
    say("wrote BUCK with", len(check), "binaries and test binaries and", len(release), "release binaries")


def check_inputs():
    try:
        first = open(os.path.join(ROOT, "BUCK"), encoding="utf-8").read().split("\n", 3)[:3]
    except FileNotFoundError:
        sys.exit("BUCK is missing. Run: python3 -I scripts/buck/gen_buck.py && sh scripts/buck/buckify.sh")
    stamped = next((l[len(INPUTS_LINE):] for l in first if l.startswith(INPUTS_LINE)), None)
    if stamped != inputs_hash():
        sys.exit("the Cargo manifests changed after the last run of gen_buck.py. "
                 "Run: python3 -I scripts/buck/gen_buck.py && sh scripts/buck/buckify.sh")


if __name__ == "__main__":
    if CHECK_INPUTS:
        check_inputs()
        sys.exit(0)
    main()
    if stale_files:
        sys.exit("out of date: " + ", ".join(stale_files) + ". Run: python3 -I scripts/buck/gen_buck.py && sh scripts/buck/buckify.sh")
