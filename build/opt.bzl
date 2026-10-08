"""Built optimised, as Cargo's `--release` builds: for a test that runs relays in real time, whose
debug build cannot keep up with the clock it is tested against (`crates/relay/BUILD.bazel`,
`mlat_host`), and for the binaries a deployed relay runs, which must keep up with the same clock.

`opt_test` runs `test`, and `opt_files` gives `srcs`' outputs, each built with `compilation_mode=opt`
(rustc `-Copt-level=3`, its dependencies too). Everything else in the build stays on the command
line's mode.
"""

def _opt_impl(_settings, _attr):
    return {"//command_line_option:compilation_mode": "opt"}

_opt = transition(
    implementation = _opt_impl,
    inputs = [],
    outputs = ["//command_line_option:compilation_mode"],
)

def _opt_test_impl(ctx):
    test = ctx.attr.test[0][DefaultInfo]
    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(
        output = executable,
        target_file = test.files_to_run.executable,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [executable]).merge(test.default_runfiles)
    return [DefaultInfo(executable = executable, runfiles = runfiles)]

opt_test = rule(
    implementation = _opt_test_impl,
    doc = "`test`, built optimised (compilation_mode=opt), run as this test.",
    test = True,
    attrs = {
        "test": attr.label(
            mandatory = True,
            executable = True,
            cfg = _opt,
            doc = "The test binary to build optimised (tag it manual: it runs only through here).",
        ),
    },
)

def _opt_files_impl(ctx):
    # The target's own outputs, as the optimised build made them: no copy and no symlink, so whatever
    # packs them (a tar layer) reads the file itself.
    return [DefaultInfo(files = depset(transitive = [target[DefaultInfo].files for target in ctx.attr.srcs]))]

opt_files = rule(
    implementation = _opt_files_impl,
    doc = "`srcs`' outputs, built optimised (compilation_mode=opt), as Cargo's `--release` builds what it ships: what a deployed image carries, whatever mode the command line builds in.",
    attrs = {
        "srcs": attr.label_list(
            mandatory = True,
            cfg = _opt,
            doc = "The binaries to build optimised.",
        ),
    },
)
