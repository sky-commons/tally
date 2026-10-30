//! The packaged feeder unit (`tally/packaging/systemd/tally-feed.service`) reads its host clock's
//! bound as ClockBound publishes it (`tally_wire::clock_bound::unit_faults`): ordered after
//! `clockbound.service` and never pulling it in, since the feeder never needs it (without it the
//! host is no reference and its configured relays are its sources, RFC-0171 §3.6), and letting
//! ClockBound's client read VMClock; it filters every call that would set the clock
//! (`ProtectClock=yes`), since nothing reads `adjtimex` any more; and a call it refuses fails with
//! EPERM rather than SIGSYS. Its `MemoryMax=` is the memory the feeder sizes its hold for an
//! anchor by (`tally_feed::source::MEMORY_MAX`), and its `/dev/shm` is its own.

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

/// The last value `key` is given in `text`.
fn last<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(key))
        .map(str::trim)
}

#[test]
fn the_packaged_unit_reads_clockbound_and_needs_none() -> Result<(), String> {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let faults = tally_wire::clock_bound::unit_faults(&text);
    assert!(faults.is_empty(), "{}: {faults:?}", path.display());
    assert_eq!(
        last(&text, "ProtectClock="),
        Some("yes"),
        "{}",
        path.display()
    );
    assert_eq!(
        last(&text, "SystemCallErrorNumber="),
        Some("EPERM"),
        "{}",
        path.display()
    );
    Ok(())
}

/// A systemd size (`64M`, `1G`, plain bytes): its suffixes are powers of 1024.
fn unit_size(value: &str) -> Option<u64> {
    let (number, scale) = match value.as_bytes().last()? {
        b'K' => (&value[..value.len() - 1], 1 << 10),
        b'M' => (&value[..value.len() - 1], 1 << 20),
        b'G' => (&value[..value.len() - 1], 1 << 30),
        _ => (value, 1),
    };
    number.parse::<u64>().ok()?.checked_mul(scale)
}

/// The unit's `MemoryMax=` is the memory the feeder refuses a `--ceiling` by
/// (`tally_feed::source::MEMORY_MAX`): a ceiling whose hold for an anchor would not fit is
/// refused, so the kernel never kills a feeder for its backlog. One changed without the other
/// fails here. Its `/dev/shm` is its own, as `PrivateDevices=` made it before it was dropped.
#[test]
fn the_packaged_unit_runs_in_the_memory_the_feeder_sizes_its_hold_by() -> Result<(), String> {
    let path = packaged_unit();
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let max =
        last(&text, "MemoryMax=").ok_or_else(|| format!("{}: no MemoryMax", path.display()))?;
    assert_eq!(
        unit_size(max),
        Some(tally_feed::source::MEMORY_MAX),
        "{}: MemoryMax={max}",
        path.display()
    );
    assert!(
        last(&text, "MemoryHigh=").is_none(),
        "{}: a MemoryHigh= below MemoryMax= would throttle the hold",
        path.display()
    );
    assert!(
        last(&text, "TemporaryFileSystem=").is_some_and(|value| value.starts_with("/dev/shm:")),
        "{}: the host's /dev/shm is shared",
        path.display()
    );
    Ok(())
}
