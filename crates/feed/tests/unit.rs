//! The packaged feeder unit (`tally/packaging/systemd/tally-feed.service`) lets through every
//! system call the feeder's read of its host clock's error bound may make
//! (`tally_wire::kernel_clock::SYSCALLS`), so a synced host is a clock source of its own bound
//! (RFC-0171 §3.6; refused, the host would read as unsynced, which is no source at all), and a
//! call it does refuse fails with EPERM rather than SIGSYS; and it is ordered after the time
//! daemon's waits (chrony's, and `time-sync.target` for ntpd's when one is enabled).

use std::path::PathBuf;

fn packaged_unit() -> PathBuf {
    std::env::var_os("TALLY_FEED_UNIT").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../packaging/systemd/tally-feed.service")
        },
        PathBuf::from,
    )
}

#[test]
fn the_packaged_unit_lets_the_feeder_read_its_clock() -> Result<(), String> {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let refused = tally_wire::kernel_clock::refused_by(&text);
    assert!(refused.is_empty(), "{} refuses {refused:?}", path.display());
    let errno = text
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("SystemCallErrorNumber="));
    assert_eq!(errno, Some("EPERM"), "{}", path.display());
    Ok(())
}

/// The packaged unit is ordered after the waits of the daemons that keep the bound the feeder
/// judges by: after chrony's wait, which it pulls in, and after `time-sync.target`, which it never
/// pulls in and which holds the start back only while a wait service is enabled (systemd.special(7);
/// `tally_wire::kernel_clock::TIME_WAITS`; RFC-0171 §3.6, chrony or ntpd, never
/// systemd-timesyncd).
#[test]
fn the_packaged_unit_waits_for_a_bounded_clock() -> Result<(), String> {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let unwaited = tally_wire::kernel_clock::unwaited(&text);
    assert!(
        unwaited.is_empty(),
        "{} holds its clock waits wrongly: {unwaited:?}",
        path.display()
    );
    Ok(())
}
