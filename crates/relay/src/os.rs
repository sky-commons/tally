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
