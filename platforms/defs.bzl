# The one execution platform of desk: every action runs on the machine of the build (the runner). With
# -c desk.remote_cache=true, Buck2 reads each action result from NativeLink first and writes the new ones to it.
# -c desk.cache_uploads=false keeps the reads and writes nothing: a machine on the mesh reads the results of the runners
# from the read listener of NativeLink, where the action cache is read-only.

def _platforms(ctx):
    remote_cache = read_root_config("desk", "remote_cache", "false") == "true"
    uploads = remote_cache and read_root_config("desk", "cache_uploads", "true") == "true"
    # -c desk.remote_exec=true sends every action to the workers of NativeLink on all the nodes (munhq/desk#97): a
    # worker with the properties below runs it, and its result goes to the cache.
    remote_exec = read_root_config("desk", "remote_exec", "false") == "true"
    # The OS and the CPU of the machine, so a rule that selects on them (the Rust toolchain picks its target triple
    # by OS) resolves for the actions that run on this platform, such as build scripts.
    constraints = {}
    constraints.update(ctx.attrs.cpu_configuration[ConfigurationInfo].constraints)
    constraints.update(ctx.attrs.os_configuration[ConfigurationInfo].constraints)
    configuration = ConfigurationInfo(constraints = constraints, values = {})
    platform = ExecutionPlatformInfo(
        label = ctx.label.raw_target(),
        configuration = configuration,
        executor_config = CommandExecutorConfig(
            # Under remote execution the limited hybrid executor sends every action to the workers and runs on the
            # runner only an action marked local_only, such as the git_fetch of a git dependency, which needs the
            # network (munbot check run 310, 2026-10-25).
            local_enabled = True,
            remote_enabled = remote_exec,
            remote_cache_enabled = remote_cache or remote_exec,
            allow_cache_uploads = uploads,
            use_limited_hybrid = remote_exec,
            remote_execution_properties = {"OSFamily": "linux", "container-image": "desk-runner"} if remote_exec else {},
            remote_execution_use_case = "buck2-default",
            remote_output_paths = "output_paths",
        ),
    )
    return [DefaultInfo(), ExecutionPlatformRegistrationInfo(platforms = [platform])]

platforms = rule(
    attrs = {
        "cpu_configuration": attrs.dep(providers = [ConfigurationInfo]),
        "os_configuration": attrs.dep(providers = [ConfigurationInfo]),
    },
    impl = _platforms,
)
