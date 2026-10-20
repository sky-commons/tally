"""One test binary run as several tests: `run_test` runs `test` as this test, so a binary built once
can be run by many targets, each with its own `args` and `size` (`crates/relay/BUILD.bazel`, its
unit tests, one target per module of the crate). `run_test_impl` is the same for a rule that
builds `test` in a configuration of its own (`//build:opt.bzl`, `opt_test`).
"""

def run_test_impl(ctx):
    """`ctx.attr.test`'s executable and runfiles, as this test's.

    Args:
      ctx: the rule's context; its `test` attribute is the binary to run.

    Returns:
      The test's `DefaultInfo`.
    """
    test = ctx.attr.test
    if type(test) == "list":
        # Built through a transition, the label is a list of its one configured target.
        test = test[0]
    test = test[DefaultInfo]
    executable = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.symlink(
        output = executable,
        target_file = test.files_to_run.executable,
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [executable]).merge(test.default_runfiles)
    return [DefaultInfo(executable = executable, runfiles = runfiles)]

run_test = rule(
    implementation = run_test_impl,
    doc = "`test`, built in the command line's mode, run as this test.",
    test = True,
    attrs = {
        "test": attr.label(
            mandatory = True,
            executable = True,
            cfg = "target",
            doc = "The test binary (tag it manual: it runs only through here).",
        ),
    },
)
