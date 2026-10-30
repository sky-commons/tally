//! The host's raw monotonic clock (`CLOCK_MONOTONIC_RAW`), the oscillator's own count: the one
//! read of it, which a relay's clock (`tally_relay::clock`) and a feeder's
//! (`tally_feed::source::HostClock`) both make. The host's wall clock's error bound is not the
//! kernel's word (`adjtimex`'s `maxerror`, which the kernel cannot vouch for) but ClockBound's,
//! read in `clock_bound`.

/// The host's raw monotonic clock in milliseconds (`CLOCK_MONOTONIC_RAW`): the oscillator's own
/// rate, which no time daemon slews and nothing steps, so a span measured by it is off true time
/// only by that rate's own error (`budget::DRIFT_PPM`). What a relay measures its own anchors'
/// ages by (`budget::OWN_ANCHOR_OLDEST`); `CLOCK_MONOTONIC` is slewed with the wall clock.
///
/// A read the kernel refuses (a seccomp filter, a kernel before 2.6.28) is never a reading: a
/// start asks [`raw_monotonic`] first and refuses to run, and a refusal after it panics, since an
/// age measured from a made-up reading would blame or clear an origin for nothing.
pub fn raw_monotonic_ms() -> u64 {
    match raw_monotonic() {
        Ok(ms) => ms,
        Err(error) => panic!(
            "the kernel refused a read of CLOCK_MONOTONIC_RAW ({error}) after it answered at start"
        ),
    }
}

/// As [`raw_monotonic_ms`], the kernel's refusal when it will not answer: what a start asks before
/// it runs.
#[cfg(target_os = "linux")]
#[allow(
    clippy::disallowed_methods,
    reason = "the one read of the raw monotonic clock, which no daemon adjusts"
)]
pub fn raw_monotonic() -> std::io::Result<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable `timespec`, and `CLOCK_MONOTONIC_RAW` a clock every Linux
    // since 2.6.28 has.
    let read = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut now) };
    millis(read, &now).ok_or_else(std::io::Error::last_os_error)
}

/// The milliseconds a `clock_gettime` that returned `read` filled `now` with, none when it failed.
#[cfg(target_os = "linux")]
fn millis(read: libc::c_int, now: &libc::timespec) -> Option<u64> {
    if read != 0 {
        return None;
    }
    Some(
        u64::try_from(now.tv_sec)
            .unwrap_or(0)
            .saturating_mul(1_000)
            .saturating_add(u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000_000),
    )
}

/// As the Linux one, by `std`'s monotonic clock where there is no raw one.
#[cfg(not(target_os = "linux"))]
pub fn raw_monotonic() -> std::io::Result<u64> {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    Ok(u64::try_from(
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis(),
    )
    .unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read the kernel refused is no reading: before, it was 0 ms, which aged an anchor signed
    /// at any raw time as from the clock's start.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_refused_raw_read_is_no_reading() {
        let now = libc::timespec {
            tv_sec: 12,
            tv_nsec: 345_000_000,
        };
        assert_eq!(millis(0, &now), Some(12_345));
        assert_eq!(millis(-1, &now), None);
        assert!(raw_monotonic().is_ok());
    }
}
