"""What a test needs from the machine that runs it, declared once for both of Bazel's schedulers.

A test's size is two numbers, cores and MiB, measured and written beside the test. Bazel's local
scheduler reads them as `resources:` tags (Bazel's own test tags, `resources:cpu:N` and
`resources:memory:N`); a remote-execution service reads them as exec properties of the test's
runner action (Bazel's `test` exec group, so the target's compiles are not also sized), under the
Remote Execution API's common platform properties `cpu_count` and `memory_mb`. Both come from one
call here, so the two cannot drift. Tally's own build helper: it names nothing outside `tally/`.
"""

def test_size(cpu, memory_mb):
    """The `tags` and `exec_properties` of a test that needs `cpu` cores and `memory_mb` MiB.

    Args:
      cpu: cores, a positive integer.
      memory_mb: resident memory in MiB, a positive integer.

    Returns:
      A struct whose `exec_properties` and `tags` a test rule takes as its own.
    """
    if type(cpu) != "int" or cpu <= 0:
        fail("cpu must be a positive integer")
    if type(memory_mb) != "int" or memory_mb <= 0:
        fail("memory_mb must be a positive integer")
    return struct(
        exec_properties = {
            "test.cpu_count": str(cpu),
            "test.memory_mb": str(memory_mb),
        },
        tags = [
            "resources:cpu:" + str(cpu),
            "resources:memory:" + str(memory_mb),
        ],
    )
