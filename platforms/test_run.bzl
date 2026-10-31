load("@prelude//:paths.bzl", "paths")

# One run of a test binary as a Buck2 action (munhq/desk#97): its inputs are the binary and the data files of the
# repository, so a test whose binary and data did not change is a hit of the action cache and does not run, and a
# test that changed runs on a NativeLink worker. The binary stays on the worker: the check asks for no output.
#
# The check of a repository without test services builds //:test-runs (scripts/check.sh). A test that needs a service
# reads its address from the environment, and the action has a clean environment, so such a test skips in the same
# way on every run, and its cached result stays true.

# The data files of one Buck2 package, by their path from the root of the repository.
TestDataInfo = provider(fields = {"files": provider_field(dict[str, Artifact])})

def _rust_test_data_impl(ctx: AnalysisContext) -> list[Provider]:
    # The path of a source file is relative to its package.
    prefix = ctx.label.package + "/" if ctx.label.package else ""
    return [DefaultInfo(), TestDataInfo(files = {prefix + f.short_path: f for f in ctx.attrs.srcs})]

rust_test_data = rule(impl = _rust_test_data_impl, attrs = {"srcs": attrs.list(attrs.source(), default = [])})

def _rust_test_run_impl(ctx: AnalysisContext) -> list[Provider]:
    out = ctx.actions.declare_output(ctx.label.name + ".log")
    # The data files of every package at their paths in the repository, so a test that reads ../../skills from its
    # package finds them (munbot run 401).
    files = {}
    for d in ctx.attrs.data:
        files.update(d[TestDataInfo].files)
    # The folder of the package is the working folder of the test, also when no data file is in it (a repository with
    # a narrow test_data, 2026-10-25).
    marker = ctx.actions.write(".desk-test-cwd", "")
    files[paths.normalize(ctx.attrs.manifest_dir + "/.desk-test-cwd")] = marker
    tree = ctx.actions.symlinked_dir("tree", files)
    cmd = cmd_args(
        "python3",
        ctx.attrs.runner,
        "--out",
        out.as_output(),
        "--tree",
        tree,
        "--dir",
        ctx.attrs.manifest_dir,
        "--one-at-a-time" if ctx.attrs.one_at_a_time else [],
        "--",
        # The test binary itself: the RunInfo of a Rust test is a wrapper that sets run_env, and the runner sets
        # CARGO_MANIFEST_DIR.
        ctx.attrs.test[DefaultInfo].default_outputs[0],
        # A test of a serial lane starts after the test before it: the lane is a chain of actions.
        hidden = [a[DefaultInfo].default_outputs for a in ctx.attrs.after],
    )
    ctx.actions.run(cmd, category = "rust_test_run", local_only = ctx.attrs.local_only)
    return [DefaultInfo(default_output = out)]

rust_test_run = rule(
    impl = _rust_test_run_impl,
    attrs = {
        "test": attrs.dep(providers = [DefaultInfo]),
        "data": attrs.list(attrs.dep(providers = [TestDataInfo]), default = []),
        "runner": attrs.source(),
        # The folder of the package from the root of the repository: the working folder and CARGO_MANIFEST_DIR.
        "manifest_dir": attrs.string(),
        # A test of a serial group or one that takes every test slot (.config/nextest.toml) runs one test at a time,
        # after the run before it in `after`. `local_only` keeps a run on the machine of the build.
        "one_at_a_time": attrs.bool(default = False),
        "local_only": attrs.bool(default = False),
        "after": attrs.list(attrs.dep(), default = []),
    },
)
