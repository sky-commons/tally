//! The relay's one panic mechanism (`tally_relay::abort_on_any_panic`, which `main` sets first):
//! a panic on any thread ends the process, a tokio task's (which the runtime would otherwise catch
//! and run on without) and a plain thread's (a stage's) alike. Each case runs this binary again as
//! the process that panics, so what is asserted is how that process ends.

use std::process::Command;
use std::time::Duration;

type Result<T = ()> = std::result::Result<T, String>;

/// Set in the process this test starts: which part of it panics.
const CHILD: &str = "TALLY_RELAY_PANIC_CHILD";
/// What the child prints if it outlived the panic.
const SURVIVED: &str = "survived the panic";

/// The child: the relay's hook set, then a panic where `part` says, then a wait long enough that
/// a process still running after it would print `SURVIVED`.
fn child(part: &str) -> Result {
    tally_relay::abort_on_any_panic();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        match part {
            "task" => {
                // Tokio catches this panic and reports it to the task's handle, which nobody
                // awaits: without the hook the runtime runs on.
                drop(tokio::spawn(async {
                    panic!("a connection's task panicked")
                }));
            }
            _ => {
                // A stage's thread: without the hook it unwinds and ends alone.
                drop(std::thread::spawn(|| panic!("a stage's thread panicked")));
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        println!("{SURVIVED}");
    });
    Ok(())
}

/// Runs this binary as the child panicking in `part`, and says how it ended.
fn panicking(part: &str, test: &str) -> Result<std::process::Output> {
    let me = std::env::current_exe().map_err(|error| error.to_string())?;
    Command::new(me)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, part)
        .output()
        .map_err(|error| error.to_string())
}

fn assert_aborted(output: &std::process::Output) -> Result {
    use std::os::unix::process::ExitStatusExt as _;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains(SURVIVED),
        "the process ran on after the panic: {stdout}"
    );
    assert_eq!(
        output.status.signal(),
        Some(SIGABRT),
        "the process did not abort: {:?}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("ending the relay rather than running without it"),
        "{stderr}"
    );
    Ok(())
}

/// What `std::process::abort` raises: SIGABRT, 6 on Linux and macOS.
const SIGABRT: i32 = 6;

#[test]
fn a_panicking_tokio_task_ends_the_process() -> Result {
    if let Ok(part) = std::env::var(CHILD) {
        return child(&part);
    }
    assert_aborted(&panicking(
        "task",
        "a_panicking_tokio_task_ends_the_process",
    )?)
}

#[test]
fn a_panicking_thread_ends_the_process() -> Result {
    if let Ok(part) = std::env::var(CHILD) {
        return child(&part);
    }
    assert_aborted(&panicking("thread", "a_panicking_thread_ends_the_process")?)
}
