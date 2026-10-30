//! Running as an unprivileged user in a container whose volume root owns. The image starts the
//! feeder as root with `TALLY_RUN_AS=UID:GID` (packaging/container/Dockerfile): before it reads
//! or writes anything, the feeder makes its state directory that user's (creating it if need be),
//! and becomes that user for good. So a bind-mounted directory Docker created as root
//! (`/opt/adsb/tally-feed:/var/lib/tally-feed`) works as a named volume does, with no `chown` by
//! hand, and the feeder never runs as root. A feeder started as any other user (a host's systemd
//! unit, a compose file's `user:`) changes nothing. Its sockets' keepalive is set here too: this
//! is the feeder's one module of system calls, the one that allows `unsafe`, and it reaches no
//! key.

use std::path::Path;

/// The variable that names the user to become, as `UID:GID`.
pub const RUN_AS: &str = "TALLY_RUN_AS";

/// `UID:GID`, as the variable holds it.
pub fn parse(text: &str) -> Result<(u32, u32), String> {
    let (uid, gid) = text
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("{RUN_AS}: {text} is not UID:GID"))?;
    let number = |part: &str| {
        part.parse::<u32>()
            .map_err(|_| format!("{RUN_AS}: {text} is not UID:GID"))
    };
    Ok((number(uid)?, number(gid)?))
}

/// If this process is root and `run_as` names a user, makes `state_dir` and what is directly in
/// it that user's, and becomes that user. Does nothing otherwise.
#[cfg(unix)]
pub fn become_user(run_as: Option<&str>, state_dir: &Path) -> Result<(), String> {
    let Some(text) = run_as.filter(|text| !text.trim().is_empty()) else {
        return Ok(());
    };
    let (uid, gid) = parse(text)?;
    // SAFETY: `geteuid` touches no memory.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let at = |error: std::io::Error, path: &Path| format!("{}: {error}", path.display());
    std::fs::create_dir_all(state_dir).map_err(|error| at(error, state_dir))?;
    std::os::unix::fs::chown(state_dir, Some(uid), Some(gid))
        .map_err(|error| at(error, state_dir))?;
    // The feeder keeps a flat directory: its files, never a tree.
    for entry in std::fs::read_dir(state_dir).map_err(|error| at(error, state_dir))? {
        let path = entry.map_err(|error| at(error, state_dir))?.path();
        std::os::unix::fs::lchown(&path, Some(uid), Some(gid)).map_err(|error| at(error, &path))?;
    }
    // SAFETY: each call takes plain integers (and a null list of no groups) and touches no memory
    // of ours. The groups go first, then the group, then the user, as only root may change them.
    let dropped = unsafe {
        libc::setgroups(0, std::ptr::null()) == 0
            && libc::setgid(gid) == 0
            && libc::setuid(uid) == 0
    };
    if !dropped {
        return Err(format!(
            "{RUN_AS}: becoming {uid}:{gid}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn become_user(_run_as: Option<&str>, _state_dir: &Path) -> Result<(), String> {
    Ok(())
}

/// Probes `stream` after a minute idle, every 10 s, 6 times (`SO_KEEPALIVE`, and on Linux its
/// times): the feeder's one other system call, kept here beside the others so this is the one
/// module of the feeder that holds `unsafe`, and it reaches no key.
pub fn keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let set = |level, name, value: libc::c_int| {
        // SAFETY: `fd` is this stream's open socket, and `value` an int that lives for the call.
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
            Err(std::io::Error::last_os_error())
        }
    };
    set(libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    #[cfg(target_os = "linux")]
    {
        set(libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 60)?;
        set(libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10)?;
        set(libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 6)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_as_is_uid_colon_gid() {
        assert_eq!(parse("65532:65532"), Ok((65532, 65532)));
        assert_eq!(parse(" 0:10 "), Ok((0, 10)));
        for bad in ["65532", "a:b", ":1", "1:", "-1:2"] {
            assert!(parse(bad).is_err(), "{bad} was taken");
        }
    }

    #[test]
    fn nothing_is_done_without_a_user_or_without_root() {
        assert!(become_user(None, Path::new("/nonexistent/tally")).is_ok());
        assert!(become_user(Some(""), Path::new("/nonexistent/tally")).is_ok());
        // SAFETY: `geteuid` touches no memory.
        if unsafe { libc::geteuid() } != 0 {
            assert!(become_user(Some("65532:65532"), Path::new("/nonexistent/tally")).is_ok());
        }
    }
}
