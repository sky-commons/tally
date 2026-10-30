//! The harness's calls into libc, and so its one module allowed `unsafe` (the crate denies it
//! elsewhere, `lib.rs`): it reaches no key. The open-file limit is the relay's own call
//! (`tally_relay::os`).

use std::os::unix::process::CommandExt;
use std::process::Command;

/// Sets thread `tid`'s nice value to `nice` (`setpriority`). Failing, it leaves the thread as it
/// is.
pub fn set_thread_nice(tid: libc::id_t, nice: libc::c_int) {
    // SAFETY: `setpriority` takes and touches no memory of ours.
    unsafe {
        let _ = libc::setpriority(libc::PRIO_PROCESS, tid, nice);
    }
}

/// Makes the child `command` starts die with this process however it ends
/// (`PR_SET_PDEATHSIG`, `SIGKILL`).
pub fn die_with_parent(command: &mut Command) {
    // SAFETY: between fork and exec only `prctl` runs, which is async-signal-safe and touches no
    // memory of the parent's.
    unsafe {
        command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The CPU set of the cores in `cores` (`sched_setaffinity`'s mask).
fn cpu_set(cores: &std::ops::Range<usize>) -> libc::cpu_set_t {
    // SAFETY: a `cpu_set_t` is plain bits, all zero an empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for core in cores.clone() {
        // SAFETY: `CPU_SET` writes a bit of `set`, ours, and ignores a core past its size.
        unsafe { libc::CPU_SET(core, &mut set) };
    }
    set
}

/// Makes the child `command` starts run on `cores` alone (`sched_setaffinity`), which is what it
/// then finds it has (`std::thread::available_parallelism`), as a relay in a unit or container of
/// that many cores does.
pub fn run_on(command: &mut Command, cores: std::ops::Range<usize>) {
    let set = cpu_set(&cores);
    // SAFETY: between fork and exec only `sched_setaffinity` runs, which is async-signal-safe and
    // reads only `set`, copied into the closure.
    unsafe {
        command.pre_exec(move || {
            if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Moves every thread of this process onto `cores` (`sched_setaffinity` of each task in
/// `/proc/self/task`); a thread started later inherits its starter's. Failing, a thread stays
/// where it was, and the error is said.
pub fn keep_to(cores: std::ops::Range<usize>) -> Result<(), String> {
    let set = cpu_set(&cores);
    let tasks = std::fs::read_dir("/proc/self/task").map_err(|error| error.to_string())?;
    for task in tasks.flatten() {
        let Some(tid) = task.file_name().to_str().and_then(|tid| tid.parse().ok()) else {
            continue;
        };
        // SAFETY: `sched_setaffinity` reads only `set`, ours.
        if unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set) }
            != 0
        {
            return Err(format!(
                "thread {tid} onto cores {cores:?}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}
