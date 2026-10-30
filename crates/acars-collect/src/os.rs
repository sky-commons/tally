//! The collector's calls into libc, the one module of the crate allowed `unsafe` (the crate
//! denies it everywhere else): catching the stop signals, and a socket's keepalive.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set by SIGTERM and SIGINT once [`catch_stop`] has run.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// The stop signals' handler: a store to an atomic, all a signal handler may do here.
extern "C" fn on_stop(_: libc::c_int) {
    STOPPING.store(true, Ordering::SeqCst);
}

/// Whether a stop signal came since [`catch_stop`].
pub fn stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

/// SIGTERM and SIGINT set [`stopping`], without `SA_RESTART`, so a read waiting on the relay
/// returns at once. The one handler this crate installs is this module's own, so no caller
/// chooses what runs in a signal handler.
pub fn catch_stop() -> io::Result<()> {
    // SAFETY: `on_stop` only stores to an atomic, which a signal handler may do.
    unsafe { catch(&[libc::SIGTERM, libc::SIGINT], on_stop) }
}

/// Each of `signals` calls `handler`, without `SA_RESTART`, so a read waiting on the relay
/// returns at once.
///
/// # Safety
///
/// `handler` runs in a signal handler: it must do only what one may (async-signal-safe calls,
/// stores to atomics), or the process's behaviour is undefined.
unsafe fn catch(signals: &[libc::c_int], handler: extern "C" fn(libc::c_int)) -> io::Result<()> {
    for &signal in signals {
        // SAFETY: a zeroed `sigaction` is a valid one with no flags, its mask emptied before use,
        // and `handler` does only what a signal handler may (this function's contract).
        let done = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if done != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Sets the int option `name` at `level` of `socket` to `value`.
pub fn set_int(
    socket: &impl AsRawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    // SAFETY: `fd` is this socket's open descriptor, and `value` an int that lives for the call.
    let done = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if done == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
