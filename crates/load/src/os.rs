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
