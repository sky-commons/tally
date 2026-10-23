//! The C library calls Tally makes beyond POSIX, each made so the binary runs on the oldest glibc a
//! release supports: the release links against Chromium's Debian bullseye sysroot (`MODULE.bazel`),
//! which offers no symbol newer than that, so a call to one fails the release's link while a build
//! against a newer host's glibc passes. Every such call lives here and nowhere else.

/// The calling thread's kernel id, for `setpriority` and `getpriority` on one thread: on Linux a
/// thread is addressed by its id as a process. The raw system call, since the `gettid` wrapper is
/// not in the release's sysroot.
#[cfg(target_os = "linux")]
pub fn thread_id() -> libc::id_t {
    // SAFETY: `SYS_gettid` takes no arguments and touches no memory.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    libc::id_t::try_from(tid).unwrap_or(0)
}

/// What every arena of glibc's allocator holds now, in bytes: in use (`uordblks`), freed and kept
/// (`fordblks`), mapped apart (`hblkhd`) and taken from the kernel (`arena`). `mallinfo2` where the
/// running glibc has it (2.33 and later), found at run time since the release's sysroot does not;
/// else `mallinfo`, whose fields are C ints and so wrap past 2 GiB, read as unsigned.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn allocator_holdings() -> [u64; 4] {
    type Mallinfo2 = unsafe extern "C" fn() -> libc::mallinfo2;
    static MALLINFO2: std::sync::OnceLock<Option<Mallinfo2>> = std::sync::OnceLock::new();
    let mallinfo2 = MALLINFO2.get_or_init(|| {
        // SAFETY: `dlsym` with `RTLD_DEFAULT` looks a name up in what is already loaded; the name
        // is a NUL-terminated literal, and a symbol found is glibc's `mallinfo2`, of this type.
        let found = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mallinfo2".as_ptr()) };
        (!found.is_null())
            .then(|| unsafe { std::mem::transmute::<*mut libc::c_void, Mallinfo2>(found) })
    });
    match mallinfo2 {
        Some(mallinfo2) => {
            // SAFETY: `mallinfo2` only reads the allocator's counters.
            let info = unsafe { mallinfo2() };
            [info.uordblks, info.fordblks, info.hblkhd, info.arena].map(|bytes| bytes as u64)
        }
        None => {
            // SAFETY: `mallinfo` only reads the allocator's counters.
            #[allow(deprecated)]
            let info = unsafe { libc::mallinfo() };
            [info.uordblks, info.fordblks, info.hblkhd, info.arena]
                .map(|bytes| u64::from(bytes as u32))
        }
    }
}

/// The kernel's word on the host's clock, as its NTP daemon keeps it (`adjtimex(2)` with no
/// modes: a read, which needs no capability): whether it says the clock is synchronised (not
/// `STA_UNSYNC`, nor the call's `TIME_ERROR`), and its error bound `maxerror` in microseconds,
/// which the kernel grows by 500 ppm a second while nothing disciplines the clock. `None` when
/// the kernel cannot be asked (a sandbox that filters the call: systemd's `ProtectClock=` does,
/// so the relay's unit leaves it off, and a start refuses to run without it).
pub fn clock_error_us() -> Option<(bool, u64)> {
    asked_clock().ok()
}

/// As [`clock_error_us`], the kernel's refusal when it will not answer (the errno a seccomp
/// filter or `ProtectClock=` returns): what a start reports before it refuses to run. The read
/// is the one both ends make (`tally_wire::kernel_clock`).
pub fn asked_clock() -> std::io::Result<(bool, u64)> {
    tally_wire::kernel_clock::asked()
}

/// Sets an `int` option `name` at `level` on the socket `fd`, as `setsockopt` takes one; false
/// when the kernel refused it.
#[cfg(unix)]
pub fn set_socket_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> bool {
    // SAFETY: `setsockopt` reads one `c_int` from a live local for the length given, and changes
    // only the socket's own options.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
    }
}

/// Reads the `int` option `name` at `level` of the socket `fd`, or none when the kernel refused.
#[cfg(unix)]
pub fn socket_int(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes one `c_int` and its length into live locals.
    let read = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            std::ptr::from_mut(&mut value).cast(),
            &mut length,
        )
    };
    (read == 0).then_some(value)
}

/// The open-file limit, soft and hard (`getrlimit(RLIMIT_NOFILE)`).
pub fn open_files_limit() -> std::io::Result<(u64, u64)> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for the call to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((limit.rlim_cur, limit.rlim_max))
}

/// Sets the open-file limit's soft limit to `soft` under its hard `hard` (`setrlimit`).
pub fn set_open_files_limit(soft: u64, hard: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `limit` is a valid rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Sets glibc's allocator parameters: its arenas at most `arenas`, and its mmap and trim
/// thresholds. Called before any thread starts. Elsewhere than glibc, nothing.
pub fn set_allocator(
    arenas: libc::c_int,
    mmap_threshold: libc::c_int,
    trim_threshold: libc::c_int,
) {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `mallopt` only sets a parameter of the allocator.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, arenas);
        libc::mallopt(libc::M_MMAP_THRESHOLD, mmap_threshold);
        libc::mallopt(libc::M_TRIM_THRESHOLD, trim_threshold);
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let _ = (arenas, mmap_threshold, trim_threshold);
}

/// Returns every glibc arena's free pages to the kernel (`malloc_trim(0)`). Elsewhere, nothing.
pub fn trim_allocator() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: `malloc_trim` only returns free pages of the allocator's own arenas.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// Sets the calling thread to the lowest priority, nice [`LOWEST_NICE`]; false when it could not.
pub fn run_at_lowest() -> bool {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `setpriority` on this thread's own id touches no memory of ours.
        unsafe { libc::setpriority(libc::PRIO_PROCESS, thread_id(), LOWEST_NICE) == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    true
}

/// glibc's `malloc_info` written to the file at `path`: its arenas as XML. A test's.
#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
pub fn write_malloc_info(path: &std::path::Path) -> Result<(), String> {
    let name =
        std::ffi::CString::new(path.display().to_string()).map_err(|error| error.to_string())?;
    // SAFETY: a file opened for writing, handed to glibc's `malloc_info` and closed.
    unsafe {
        let file = libc::fopen(name.as_ptr(), c"w".as_ptr());
        if file.is_null() {
            return Err("fopen".to_owned());
        }
        libc::malloc_info(0, file);
        libc::fclose(file);
    }
    Ok(())
}

/// The lowest priority Linux has: nice 19.
pub const LOWEST_NICE: libc::c_int = 19;

/// The calling thread's nice value, or none when it cannot be read.
pub fn own_nice() -> Option<libc::c_int> {
    #[cfg(target_os = "linux")]
    {
        let tid = thread_id();
        // SAFETY: `getpriority` and `__errno_location` read and write no memory of this process
        // but this thread's errno; on Linux a thread is addressed by its id as a process.
        unsafe {
            // `getpriority` may return -1 as a value: errno, cleared first, tells a failure.
            *libc::__errno_location() = 0;
            let own = libc::getpriority(libc::PRIO_PROCESS, tid);
            (own != -1 || *libc::__errno_location() == 0).then_some(own)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Some(0)
    }
}

/// Lowers the calling thread's priority `below` nice steps under its own, at most to
/// [`LOWEST_NICE`]; false when it could not be lowered all of them. A thread may always lower its
/// own.
pub fn lower_own_nice(below: libc::c_int) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Some(own) = own_nice() else {
            return false;
        };
        let target = own.saturating_add(below).min(LOWEST_NICE);
        // SAFETY: `setpriority` reads no memory of this process; on Linux a thread is addressed by
        // its id as a process, so this changes this thread's nice value alone.
        let set = unsafe { libc::setpriority(libc::PRIO_PROCESS, thread_id(), target) };
        set == 0 && target - own == below
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = below;
        true
    }
}

#[cfg(all(test, target_os = "linux", target_env = "gnu"))]
mod tests {
    use super::*;

    #[test]
    fn a_thread_has_its_own_id_and_the_main_thread_is_the_process() {
        let here = thread_id();
        let there = std::thread::spawn(thread_id).join().unwrap_or(here);
        assert_ne!(here, 0);
        assert_ne!(here, there);
        // SAFETY: `getpid` touches no memory.
        let pid = unsafe { libc::getpid() };
        assert!(libc::id_t::try_from(pid).is_ok());
    }

    #[test]
    fn the_allocator_counts_what_is_held() {
        let held: Vec<u8> = vec![1; 1 << 16];
        let [in_use, _, _, arenas] = allocator_holdings();
        assert!(in_use >= held.len() as u64 || arenas > 0);
        drop(held);
    }
}

/// The signals that stop the relay gracefully: SIGTERM (systemd's and Kubernetes' stop) and
/// SIGINT.
#[cfg(target_os = "linux")]
fn termination_set() -> libc::sigset_t {
    // SAFETY: `sigemptyset` and `sigaddset` write only the set they are given, which lives here.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        set
    }
}

/// Blocks the stopping signals in the calling thread, and so in every thread it starts after:
/// what the relay's program does first, before any thread runs, so that only
/// [`wait_termination`] takes them (sigwait(3), the standard way a multithreaded program takes a
/// signal). Whether they were blocked.
#[cfg(target_os = "linux")]
pub fn block_termination() -> bool {
    let set = termination_set();
    // SAFETY: the set is initialized above; the old mask is not asked for.
    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) == 0 }
}

/// Waits, on the calling thread, until a stopping signal is sent (blocked first,
/// [`block_termination`]); the signal, or `None` when it cannot be waited for.
#[cfg(target_os = "linux")]
pub fn wait_termination() -> Option<i32> {
    let set = termination_set();
    let mut signal = 0;
    // SAFETY: the set is initialized above and `signal` is a valid place for the answer.
    let waited = unsafe { libc::sigwait(&set, &mut signal) };
    (waited == 0).then_some(signal)
}
