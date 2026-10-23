//! The kernel's word on the host's wall clock, as its NTP daemon keeps it: the one read of it,
//! which a relay's clock (`tally_relay::clock`) and a feeder's (`tally_feed::source::HostClock`)
//! both make, and the one list of the system calls that read is made of, which each packaged
//! unit's seccomp filter is held to (`SYSCALLS`).

/// Every system call [`asked`] may make, by the name systemd's `SystemCallFilter=` takes: glibc's
/// `adjtimex(3)` is `clock_adjtime(CLOCK_REALTIME)` since 2.31 (`clock_adjtime64` where `time_t`
/// was 32 bits), and `adjtimex` itself on older libraries and other libcs. Each packaged unit
/// allows all three after its `~@privileged` (which holds `@clock`), and a test holds each unit to
/// this list (`//crates/relay:check`, `//crates/feed:unit`).
pub const SYSCALLS: [&str; 3] = ["adjtimex", "clock_adjtime", "clock_adjtime64"];

/// The kernel's word on the host's clock (`adjtimex(2)` with no modes: a read, which needs no
/// capability): whether it says the clock is synchronised (not `STA_UNSYNC`, nor the call's
/// `TIME_ERROR`), and its error bound `maxerror` in microseconds, which the kernel grows by 500
/// ppm a second while nothing disciplines the clock. The kernel's refusal when it will not answer
/// (the `EPERM` a seccomp filter or systemd's `ProtectClock=` returns).
#[cfg(target_os = "linux")]
#[allow(
    clippy::disallowed_methods,
    reason = "the one read of the kernel's word on the host's wall clock"
)]
pub fn asked() -> std::io::Result<(bool, u64)> {
    // SAFETY: an all-zero `timex` is a valid one with no modes set, which asks the kernel to
    // change nothing and only fill it in.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `timex` is a valid, writable `timex` for the call's length.
    let state = unsafe { libc::adjtimex(&mut timex) };
    if state < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let synced = state != libc::TIME_ERROR && timex.status & libc::STA_UNSYNC == 0;
    Ok((synced, u64::try_from(timex.maxerror).unwrap_or(u64::MAX)))
}

/// The error bound, in whole milliseconds rounded up, by which the kernel's word `answer`
/// ([`asked`]: synchronised, and `maxerror` in microseconds) holds the host's clock to true time,
/// when it holds it within `budget::E`: none past `E`, and none unless the kernel says the clock is
/// synchronised now or `synced_before` (it said so earlier, and a clock that lost its sources is
/// judged on the bound the kernel grows by 500 ppm a second from its last sync, as NTP's own error
/// budget does, RFC 5905 §11.3). The one reading of the kernel's word: a relay's judging clock
/// (`tally_relay::clock`, `synced_before` once it has seen a sync since it started), a feeder's
/// host source (`tally_feed::source::host_error_ms`, synchronised now) and the API's judging clock
/// (`tally_api::mlat::Clock`, synchronised now) each take its answer, and none reads the word
/// another way.
///
/// The bound is the time daemon's, and only chrony and ntpd keep one that bounds the clock against
/// true time (each sets `maxerror` from its sources' root distance). systemd-timesyncd sets it to
/// 0 at each sync, and the kernel then grows it by 500 µs a second, so under timesyncd the bound
/// leaves out the server's own error and the measurement's and understates the clock's error; a
/// bound of 0 is one millisecond's worth of nothing, not a mark of timesyncd, and no reading of
/// it tells the two apart. So no host is told from another at run time: the daemon must be chrony
/// or ntpd, which the packaged units wait for (`TIME_WAITS`) and the installer installs, and that
/// requirement is stated rather than detected (RFC-0171 §3.6). Under timesyncd anyway, this bound
/// understates the error and nothing here can tell.
pub const fn bound_ms(answer: (bool, u64), synced_before: bool) -> Option<u64> {
    let (synced, maxerror_us) = answer;
    let ms = maxerror_us.div_ceil(1_000);
    if (synced || synced_before) && crate::budget::E.covers(ms) {
        Some(ms)
    } else {
        None
    }
}

/// As the Linux one; no other host is asked.
#[cfg(not(target_os = "linux"))]
pub fn asked() -> std::io::Result<(bool, u64)> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

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

/// The calls of [`SYSCALLS`] a systemd unit's `[Service]` would refuse the process, as systemd
/// reads its seccomp settings: `SystemCallFilter=` lines in order, a `~` line denying what it
/// names and any other allowing it, the first line's kind setting what is unnamed (an allow list
/// refuses everything it does not name), a group (`@clock`, and `@privileged`, which holds it)
/// naming each of these; and `ProtectClock=yes`, which filters `@clock` whatever the lines say.
/// Empty when the unit lets the read through. What each packaged unit is held to.
#[must_use]
pub fn refused_by(unit: &str) -> Vec<&'static str> {
    let mut allowed: Option<[bool; SYSCALLS.len()]> = None;
    let mut protected = false;
    for line in unit.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("ProtectClock=") {
            protected = matches!(value.trim(), "yes" | "true" | "on" | "1");
            continue;
        }
        let Some(value) = line.strip_prefix("SystemCallFilter=") else {
            continue;
        };
        let (deny, names) = match value.trim().strip_prefix('~') {
            Some(names) => (true, names),
            None => (false, value),
        };
        let state = allowed.get_or_insert([deny; SYSCALLS.len()]);
        let names: Vec<&str> = names.split_whitespace().collect();
        for (call, allow) in SYSCALLS.iter().zip(state.iter_mut()) {
            if names
                .iter()
                .any(|name| name == call || matches!(*name, "@clock" | "@privileged"))
            {
                *allow = !deny;
            }
        }
    }
    let allowed = allowed.unwrap_or([true; SYSCALLS.len()]);
    SYSCALLS
        .iter()
        .zip(allowed)
        .filter(|(_, allow)| protected || !allow)
        .map(|(call, _)| *call)
        .collect()
}

/// What a packaged unit starts after, so that where the host's time daemon offers a wait for a
/// synchronised clock the process starts after it (RFC-0171 §3.6: the daemon must be chrony or
/// ntpd, whose bound [`bound_ms`] reads), each with whether the unit also pulls it in:
///
/// - `chrony-wait.service`, chrony's own wait for a synchronised clock: a service no target
///   starts by itself, so the unit pulls it in (`Wants=`) as well as ordering after it. Under
///   chrony the process starts once the clock is synchronised, or once the wait gives up.
/// - `time-sync.target`, a passive target, which systemd.special(7) says units that need the time
///   "should be ordered after", "but not pull it in": only a wait service pulls it in. Under ntpd
///   it holds back nothing unless such a service is enabled (ntpsec's `ntpsec-wait.service`, or
///   `systemd-time-wait-sync.service`, which waits for the kernel to say synchronised), and
///   neither is by default, so the unit
///   may start before ntpd has synchronised the clock. What holds then is the kernel's word,
///   read at each judgement: a relay judges nothing until the kernel has said synchronised, and a
///   feeder's host is no clock source until it does. So the unit orders after it and never
///   wants it.
pub const TIME_WAITS: [(&str, bool); 2] =
    [("chrony-wait.service", true), ("time-sync.target", false)];

/// The waits of [`TIME_WAITS`] a systemd unit's `[Unit]` holds wrongly: one it is not ordered
/// after (`After=`), one it must pull in and does not (`Wants=`), or one it pulls in and must
/// not. Empty when it waits for the clock as both packaged units must.
#[must_use]
pub fn unwaited(unit: &str) -> Vec<&'static str> {
    let named = |key: &str| -> Vec<&str> {
        unit.lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(key))
            .flat_map(str::split_whitespace)
            .collect()
    };
    let (after, wants) = (named("After="), named("Wants="));
    TIME_WAITS
        .into_iter()
        .filter(|(wait, pulled)| !after.contains(wait) || wants.contains(wait) != *pulled)
        .map(|(wait, _)| wait)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's word is a bound only within `E`, and only synchronised now or before: a bound
    /// of 0 is a bound of 0 ms like any other (the daemon's word, never a mark of one daemon),
    /// one past `E` by a microsecond is none, and an unsynchronised clock never synced is none
    /// however small its bound, while one that lost its sync is judged on the bound it grows.
    /// Before, a bound of exactly 0 was taken for systemd-timesyncd's and none, which it is for
    /// under a second after each of its syncs: the kernel grows it 500 µs a second after.
    #[test]
    fn the_kernels_word_is_its_bound_within_e_once_synced() {
        let e_us = crate::budget::E.duration().as_micros() as u64;
        let e_ms = crate::budget::E_MS;
        assert_eq!(bound_ms((true, 0), false), Some(0));
        assert_eq!(bound_ms((true, 1), false), Some(1));
        assert_eq!(bound_ms((true, 2_500), false), Some(3));
        assert_eq!(bound_ms((true, e_us), false), Some(e_ms));
        assert_eq!(bound_ms((true, e_us + 1), false), None);
        assert_eq!(bound_ms((false, 1), false), None);
        assert_eq!(bound_ms((false, 3_000_000), true), Some(3_000));
        assert_eq!(bound_ms((false, e_us + 1), true), None);
    }

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

    /// A unit orders itself after both waits, pulls in chrony's wait and never `time-sync.target`
    /// (systemd.special(7)). Before, it was held to pull in both.
    #[test]
    fn a_unit_waits_for_the_clock_after_both_and_wanting_only_chronys() {
        let right = "After=network-online.target chrony-wait.service time-sync.target\nWants=network-online.target chrony-wait.service\n";
        assert!(unwaited(right).is_empty());
        let wants_the_target = "After=chrony-wait.service time-sync.target\nWants=chrony-wait.service\nWants=time-sync.target\n";
        assert_eq!(unwaited(wants_the_target), ["time-sync.target"]);
        assert_eq!(
            unwaited("After=chrony-wait.service time-sync.target\n"),
            ["chrony-wait.service"]
        );
        assert_eq!(
            unwaited("Wants=chrony-wait.service\n"),
            ["chrony-wait.service", "time-sync.target"]
        );
    }

    #[test]
    fn a_unit_refuses_what_its_filter_last_denies() {
        let stock = "SystemCallFilter=@system-service\nSystemCallFilter=~@privileged\n";
        assert_eq!(refused_by(stock), SYSCALLS);
        assert_eq!(
            refused_by(&format!("{stock}SystemCallFilter=adjtimex\n")),
            ["clock_adjtime", "clock_adjtime64"]
        );
        let allowed = format!("{stock}SystemCallFilter=adjtimex clock_adjtime clock_adjtime64\n");
        assert!(refused_by(&allowed).is_empty());
        assert_eq!(
            refused_by(&format!("{allowed}ProtectClock=yes\n")),
            SYSCALLS
        );
        assert_eq!(refused_by("SystemCallFilter=read write\n"), SYSCALLS);
        assert!(refused_by("SystemCallFilter=~@mount\n").is_empty());
        assert!(refused_by("Restart=always\n").is_empty());
    }
}
