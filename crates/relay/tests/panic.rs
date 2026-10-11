//! The relay's one panic mechanism (`tally_relay::abort_on_any_panic`, which `main` sets first):
//! a panic on any thread ends the process, a tokio task's (which the runtime would otherwise catch
//! and run on without) and a plain thread's (a stage's) alike. Each case runs this binary again as
//! the process that panics, so what is asserted is how that process ends. And the relay's own
//! program sets it: the built `tally-relay` (named by the build, `TALLY_RELAY_BIN`; `cargo test`
//! finds it itself) is made to panic as it reads its arguments, and ends as the hook ends it.

use std::path::PathBuf;
use std::process::Command;

type Result<T = ()> = std::result::Result<T, String>;

/// Set in the process this test starts: which part of it panics.
const CHILD: &str = "TALLY_RELAY_PANIC_CHILD";
/// What the child prints if it outlived the panic.
const SURVIVED: &str = "survived the panic";

/// The child: the relay's hook set, then a panic where `part` says, then, once the panic is
/// over (the task or thread that panicked has ended), `SURVIVED` printed: a process the hook
/// ended never gets there, and one it did not prints it however long the panic took on a loaded
/// machine (before, a wait of five seconds stood for "the panic is over").
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
                // Tokio catches this panic and reports it to the task's handle, which the relay
                // never awaits: without the hook the runtime runs on. Awaited here only to know
                // the panic is over.
                let _ = tokio::spawn(async { panic!("a connection's task panicked") }).await;
            }
            _ => {
                // A stage's thread: without the hook it unwinds and ends alone. Joined here only
                // to know the panic is over.
                let _ = std::thread::spawn(|| panic!("a stage's thread panicked")).join();
            }
        }
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

/// The built relay program.
fn relay_binary() -> Result<PathBuf> {
    std::env::var_os("TALLY_RELAY_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_tally-relay").map(PathBuf::from))
        .ok_or_else(|| "TALLY_RELAY_BIN names the relay (set by the build)".to_owned())
}

/// `tally-relay`'s `main` sets the hook before anything else: an argument that is not Unicode
/// makes the program panic as it reads its arguments (`std::env::args`), on its main thread inside
/// the runtime, and the process aborts with the hook's word. A program that did not set it would
/// unwind and exit with 101, the hook's word never said, so this fails if `main` stops setting it
/// or sets it after reading its arguments.
#[test]
fn the_relay_program_sets_the_hook_before_anything_runs() -> Result {
    use std::os::unix::ffi::OsStrExt as _;
    let not_unicode = std::ffi::OsStr::from_bytes(b"--memory\xff");
    let output = Command::new(relay_binary()?)
        .arg(not_unicode)
        .output()
        .map_err(|error| error.to_string())?;
    assert_aborted(&output)
}
