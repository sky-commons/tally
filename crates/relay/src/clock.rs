//! The relay's clocks (RFC-0171 §3.6), as a host keeps them: TrueTime's interval on stock Linux.
//! Two it judges and steps by, and a third it ages its own anchors by.
//!
//! - **The judging clock, `J`** ([`RelayClock::now_ms`]): `CLOCK_REALTIME` as the host's NTP
//!   daemon (chrony) keeps it, and its error bound as the host's ClockBound daemon publishes it
//!   (`tally_wire::clock_bound`, read at every judgement: [`RelayClock::error_ms`]). It judges
//!   everything compared across machines: a record's signed time against the windows of
//!   `strikes`, a feeder's clock, the directory's offers, the groups' manifests and receipts; and
//!   it is what the relay signs and states. The relay moves it in no way: the daemon slews it
//!   (chrony at up to 83,333 ppm) and steps it only as it is told to (`makestep`), and a second
//!   slewer in the relay would only trail real time.
//! - **The monotonic clock, `M`** ([`RelayClock::mono_ms`]): `CLOCK_MONOTONIC`, read in
//!   milliseconds from `J` at the relay's start, so the two read alike until the host's clock
//!   steps. It drives the epochs, the ticks, the hosted MLAT's steps, the paces and every
//!   duration, and never goes back or jumps: a step of `J` neither bursts an epoch forward nor
//!   holds one open. A stamp carries both (`ingest::Stamp`), and what a stage signs is `J` at the
//!   epoch's end (`Stamp::judging`).
//! - **The raw clock, `Raw`** ([`RelayClock::raw`]): `CLOCK_MONOTONIC_RAW`, the oscillator's own
//!   count, which no daemon slews or steps. A stamp carries it beside the other two, and it is
//!   what the age of an anchor this relay issued is measured on (`anchors::Anchors::issued_by`),
//!   so neither a slew of `M` nor a step of `J` makes a fresh anchor look old.
//!
//! **Steps, exactly.** `J - M` changes only when the host's clock steps (`settimeofday`,
//! `ADJ_SETOFFSET`, a leap second, a resume): a slew moves both alike. So every read compares the
//! two, and a change past [`STEP_SEEN_MS`] is a step, counted ([`RelayClock::steps`]). A step ends
//! nothing: it is stated again to every feeder session at its next heartbeat (`link`), and the
//! strike tables keep their own safety whatever the clock does (`strikes`).
//!
//! **Unsynced.** The relay judges by the clock only while ClockBound says it is `Synchronized`
//! and the half-width of its interval is within `tally_wire::budget::E` (`E`), read at every
//! judgement (a memory read of its shared segment). Anything else (no ClockBound on the host, a
//! segment its client cannot read, `Unknown`, `FreeRunning`, `Disrupted`, or a bound past `E`)
//! states the relay's error as unbounded: it judges and uses nothing (`strikes::feeder_clock`,
//! `strikes::Now`) and signs nothing (`signer::Signer`), each such read counted by why and the
//! last stated (`hub::MemoryReport::clock_bound`). Synced or not, it refuses no one for a clock: a
//! clock decides usability alone (RFC-0171 §3.6). A host without ClockBound runs a relay that
//! never judges; what ClockBound says when chronyd dies, and the gaps that stay, are
//! `tally_wire::clock_bound`'s.
//!
//! The host's wall clock is read in this module alone, and its bound in one place every end
//! shares (`tally_wire::clock_bound`): Clippy's `disallowed-methods` refuses `SystemTime::now`,
//! `SystemTime::elapsed`, `UNIX_EPOCH.elapsed`, `clock_gettime`, `gettimeofday` and `time`
//! anywhere else, and `adjtimex` and `clock_adjtime` everywhere (`clippy.toml`), so
//! nothing in the relay can judge or sign by another clock. `M` is read here for what is stamped
//! and ticked by it; a duration timed elsewhere (a deadline, a timeout, a measure of how long
//! something took) reads std's `Instant`, the same `CLOCK_MONOTONIC`, where it is timed: it is
//! never compared across machines and never signed, so it needs no single owner.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use tally_wire::clocks::{Judged, JudgedReader, Moment, Mono, MonoReader, Raw, RawReader};

use crate::ingest::Stamp;

/// A test's or a replay's stand-in for one of the host's clocks, in milliseconds: what a scripted
/// clock reads ([`RelayClock::scripted`]). A script, not a reader: its readings are made here, by
/// the relay's clock, like the host's.
pub type Script = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A change of `J - M` past this between two reads is a step of the host's clock: past what the
/// two reads' own gap can make (they are taken back to back, and a pair further apart than a
/// millisecond is read again).
pub const STEP_SEEN_MS: i64 = 5;

/// What [`RelayClock::error_ms`] holds for an error past bounds.
const UNBOUNDED: u64 = u64::MAX;

/// The relay's two clocks ([`RelayClock::now_ms`], [`RelayClock::mono_ms`]); a test's or a
/// replay's may be scripts of its own ([`RelayClock::scripted`], [`RelayClock::scripted_apart`]).
#[derive(Clone)]
pub struct RelayClock(Arc<Reading>);

enum Reading {
    /// A host's.
    Host {
        started: Instant,
        /// `J` at start: where `M` reads from.
        start_ms: u64,
        offset: Offset,
        /// The host's ClockBound, read at every judgement.
        bound: &'static tally_wire::clock_bound::Reader,
    },
    /// Exactly what scripts read: a test's or a replay's times of its own choosing, and the
    /// error it says.
    Scripted {
        judging: Script,
        monotonic: Script,
        raw: Script,
        offset: Offset,
        error: AtomicU64,
    },
}

/// `J - M` as last read, and the steps seen.
struct Offset {
    last: AtomicI64,
    steps: AtomicU64,
}

impl Offset {
    fn new(offset: i64) -> Self {
        Self {
            last: AtomicI64::new(offset),
            steps: AtomicU64::new(0),
        }
    }

    /// `offset` read now: a step counted, and the offset taken, when it moved past
    /// [`STEP_SEEN_MS`]; a smaller change (the reads' own rounding) is no step and moves nothing,
    /// so none adds up to one.
    fn seen(&self, offset: i64) {
        let last = self.last.load(Ordering::Acquire);
        if offset.abs_diff(last) > STEP_SEEN_MS.unsigned_abs()
            && self
                .last
                .compare_exchange(last, offset, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.steps.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// The host's wall clock in milliseconds since the Unix epoch: read here and nowhere else in the
/// relay.
#[allow(
    clippy::disallowed_methods,
    reason = "the one read of the host's wall clock, the relay's judging clock"
)]
fn host_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Whether the kernel reads the raw monotonic clock the relay ages its own anchors by: a relay
/// that cannot read it refuses to start, naming the cause. (The judging clock's bound is
/// ClockBound's, and a host without it starts a relay that judges nothing.)
pub fn kernel_answers() -> Result<(), String> {
    tally_wire::kernel_clock::raw_monotonic()
        .map(drop)
        .map_err(|error| {
            format!(
                "the kernel will not read the raw monotonic clock (CLOCK_MONOTONIC_RAW: {error}), \
                 which the relay ages its own anchors by: a seccomp filter blocks clock_gettime \
                 or the kernel is older than 2.6.28"
            )
        })
}

impl RelayClock {
    /// A relay's: the host's clocks, its judging clock bounded by the host's ClockBound.
    pub fn system() -> Self {
        Self::bounded_by(tally_wire::clock_bound::Reader::host())
    }

    /// The host's clocks, the judging clock bounded by the ClockBound segment `bound` reads: a
    /// relay's `--clock-bound`.
    pub fn bounded_by(bound: &'static tally_wire::clock_bound::Reader) -> Self {
        let started = Instant::now();
        let start_ms = host_ms();
        Self(Arc::new(Reading::Host {
            started,
            start_ms,
            offset: Offset::new(0),
            bound,
        }))
    }

    /// A test's: the host's three clocks as they read, as a script ([`RelayClock::scripted_raw`]),
    /// its error stated at 0 ms ([`RelayClock::set_error`] changes it), since no test host runs
    /// ClockBound: what a test that wants real time and a judging clock builds (`Hub::new`). A
    /// relay's is [`RelayClock::system`]. Clippy refuses it outside a test (`clippy.toml`).
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's clock, made on the scripted clocks it is"
    )]
    pub fn host_stated() -> Self {
        let started = Instant::now();
        let start_ms = host_ms();
        Self::scripted_raw(
            Arc::new(host_ms),
            Arc::new(move || {
                start_ms.saturating_add(
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                )
            }),
            Arc::new(tally_wire::kernel_clock::raw_monotonic_ms),
        )
    }

    /// Exactly the times `clock` reads, for both clocks, its error none: a test's or a replay's,
    /// which chooses its times itself. Clippy refuses it outside a test (`clippy.toml`).
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's clock, made on the scripted clocks it is"
    )]
    pub fn scripted(clock: Script) -> Self {
        Self::scripted_apart(Arc::clone(&clock), clock)
    }

    /// `judging` and `monotonic` as a test's stand-ins for the host's two clocks: a step of the
    /// one is a step only when the other does not move with it. Clippy refuses it outside a test
    /// (`clippy.toml`).
    #[allow(
        clippy::disallowed_methods,
        reason = "a test's clock, made on the scripted clocks it is"
    )]
    pub fn scripted_apart(judging: Script, monotonic: Script) -> Self {
        Self::scripted_raw(judging, Arc::clone(&monotonic), monotonic)
    }

    /// As [`RelayClock::scripted_apart`], with `raw` the stand-in for the host's raw monotonic
    /// clock ([`RelayClock::raw`]): a test's true time, while the other two slew and step.
    /// Clippy refuses it outside a test (`clippy.toml`).
    pub fn scripted_raw(judging: Script, monotonic: Script, raw: Script) -> Self {
        let offset = i64_of(judging()) - i64_of(monotonic());
        Self(Arc::new(Reading::Scripted {
            judging,
            monotonic,
            raw,
            offset: Offset::new(offset),
            error: AtomicU64::new(0),
        }))
    }

    /// A scripted clock's error set (`None`: unbounded, unsynced): a test's. A host's is
    /// ClockBound's alone. Clippy refuses it outside a test (`clippy.toml`).
    pub fn set_error(&self, error_ms: Option<u64>) {
        if let Reading::Scripted { error, .. } = &*self.0 {
            error.store(error_ms.unwrap_or(UNBOUNDED), Ordering::Release);
        }
    }

    /// The judging clock now, `J`, in milliseconds since the Unix epoch.
    pub fn judged(&self) -> Judged {
        self.read().judged()
    }

    /// The monotonic clock now, `M`, in milliseconds from `J` at start: what the pipeline runs on.
    pub fn mono(&self) -> Mono {
        self.read().mono()
    }

    /// The raw monotonic clock now, in milliseconds from an origin of its own
    /// (`CLOCK_MONOTONIC_RAW`, `tally_wire::kernel_clock::raw_monotonic_ms`): the oscillator's
    /// rate, which no time daemon slews and nothing steps, unlike `M` (`CLOCK_MONOTONIC`, slewed
    /// with `J`). For one thing only: the age of this relay's own anchors
    /// (`tally_wire::budget::OWN_ANCHOR_OLDEST`), a span that must be true whatever the daemon does
    /// to `J` meanwhile. Never compared across machines, and never signed.
    pub fn raw(&self) -> Raw {
        made::raw(match &*self.0 {
            Reading::Host { .. } => tally_wire::kernel_clock::raw_monotonic_ms(),
            Reading::Scripted { raw, .. } => raw(),
        })
    }

    /// Both clocks, read together: one instant on `J` and `M`. A step between this read and the
    /// last is counted.
    pub fn read(&self) -> Moment {
        let (judged, mono) = self.read_ms();
        made::moment(mono, judged)
    }

    /// What a batch, a record or a tick is stamped with (`ingest::Stamp`): both clocks read as a
    /// pair, the raw clock beside them, and whether the judging clock judges, all at one instant,
    /// so whatever the stamp is used for later is decided by what was true as it was taken.
    pub fn stamp(&self, ingest_seq: u64) -> Stamp {
        let moment = self.read();
        Stamp::read(moment, ingest_seq, self.raw(), self.judging())
    }

    fn read_ms(&self) -> (u64, u64) {
        match &*self.0 {
            Reading::Host {
                started,
                start_ms,
                offset,
                ..
            } => read_pair(offset, host_ms, || {
                start_ms.saturating_add(
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                )
            }),
            Reading::Scripted {
                judging,
                monotonic,
                offset,
                ..
            } => read_pair(offset, || judging(), || monotonic()),
        }
    }

    /// The steps of `J` seen so far ([`STEP_SEEN_MS`]), at reads of the clock.
    pub fn steps(&self) -> u64 {
        match &*self.0 {
            Reading::Host { offset, .. } | Reading::Scripted { offset, .. } => {
                offset.steps.load(Ordering::Acquire)
            }
        }
    }

    /// The judging clock's error bound now, in milliseconds: ClockBound's, read now
    /// (`tally_wire::clock_bound::Reader::read`); `None` while it is unbounded (ClockBound absent,
    /// unreadable or not `Synchronized`, or its bound past `E`), when the relay judges nothing by
    /// it.
    pub fn error_ms(&self) -> Option<u64> {
        match &*self.0 {
            Reading::Host { bound, .. } => bound.read().ok(),
            Reading::Scripted { error, .. } => {
                Some(error.load(Ordering::Acquire)).filter(|error| *error != UNBOUNDED)
            }
        }
    }

    /// What the reads of the judging clock's bound said: the last verdict and the refusals by
    /// why (`tally_wire::clock_bound::Health`). A scripted clock's reads none.
    pub fn bound_health(&self) -> tally_wire::clock_bound::Health {
        match &*self.0 {
            Reading::Host { bound, .. } => bound.health(),
            Reading::Scripted { .. } => tally_wire::clock_bound::Health::default(),
        }
    }

    /// Whether the judging clock is bounded now: what lets the relay judge a record usable.
    pub fn judging(&self) -> bool {
        self.error_ms().is_some()
    }

    /// The judging clock as a reader.
    pub fn reader(&self) -> JudgedReader {
        let clock = self.clone();
        JudgedReader::of(move || clock.judged())
    }

    /// The monotonic clock as a reader.
    pub fn mono_reader(&self) -> MonoReader {
        let clock = self.clone();
        MonoReader::of(move || clock.mono())
    }

    /// The raw monotonic clock as a reader.
    pub fn raw_reader(&self) -> RawReader {
        let clock = self.clone();
        RawReader::of(move || clock.raw())
    }
}

/// Where the relay's readings are made: its clock is the relay's one reader of the host's clocks
/// (or a test's scripts of them), so it makes them from what it read.
#[allow(
    clippy::disallowed_methods,
    reason = "the relay's clock readers: a reading is made where the clock is read"
)]
mod made {
    use tally_wire::clocks::{Moment, Raw, recorded};

    pub(super) fn moment(mono: u64, judged: u64) -> Moment {
        recorded::moment(mono, judged)
    }

    pub(super) fn raw(ms: u64) -> Raw {
        recorded::raw(ms)
    }
}

fn i64_of(ms: u64) -> i64 {
    i64::try_from(ms).unwrap_or(i64::MAX)
}

/// Both clocks read as a pair, the same way for a host's and a script's: the monotonic clock,
/// the judging one, the monotonic one again, read again while the monotonic reads are further
/// apart than a millisecond (the thread was preempted between them), so a gap of the reads is
/// never a step. A pair still apart once the tries ran out is used, but never watched for a step.
fn read_pair(offset: &Offset, judging: impl Fn() -> u64, mono: impl Fn() -> u64) -> (u64, u64) {
    let mut tries = 0;
    loop {
        let before = mono();
        let read = judging();
        let after = mono();
        tries += 1;
        let pair = paired(after.saturating_sub(before), tries);
        if pair != Pair::Again {
            if pair == Pair::Close {
                offset.seen(i64_of(read) - i64_of(after));
            }
            return (read, after);
        }
    }
}

/// The reads of the host's clocks a read of them may take ([`RelayClock::read`]).
const READ_TRIES: u32 = 4;

/// What a read of the host's two clocks is, its reads `gap` apart on try `tries`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pair {
    /// Within a millisecond: used, and watched for a step.
    Close,
    /// Further apart (the thread was preempted between them): read again.
    Again,
    /// Still further apart once the tries ran out: used, but never watched for a step.
    Apart,
}

fn paired(gap_ms: u64, tries: u32) -> Pair {
    if gap_ms <= 1 {
        Pair::Close
    } else if tries < READ_TRIES {
        Pair::Again
    } else {
        Pair::Apart
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// The same paired read serves a script as a host (`read_pair`): a script whose monotonic
    /// clock moves between its two reads (a test's thread preempted) is read again, and no step is
    /// seen. Before, a script was read once, judging then monotonic, and a preemption between them
    /// counted a step.
    #[test]
    fn a_scripts_clocks_are_read_as_a_pair_like_the_hosts() {
        use std::sync::Mutex;
        let script = |values: Vec<u64>| {
            let values = Mutex::new(values.into_iter());
            Arc::new(move || {
                values
                    .lock()
                    .ok()
                    .and_then(|mut values| values.next())
                    .unwrap_or(20)
            }) as Script
        };
        // At construction both read 0; then the first pair's monotonic reads 0 and 20 around a
        // judging read of 10 (preempted), and the second pair reads 20, 20, 20.
        let clock = RelayClock::scripted_apart(script(vec![0, 10, 20]), script(vec![0, 0, 20]));
        assert_eq!(clock.read(), tally_wire::clocks::recorded::moment(20, 20));
        assert_eq!(clock.steps(), 0);
    }

    /// A pair of reads too far apart is read again, and once the tries run out it is used but
    /// never watched for a step: the gap between its reads is no step of the clock. Before, the
    /// last try's pair was watched like any, so a preempted read counted a step and restated the
    /// clock to every feeder.
    #[test]
    fn a_pair_read_too_far_apart_is_never_taken_for_a_step() {
        assert_eq!(paired(0, 1), Pair::Close);
        assert_eq!(paired(1, READ_TRIES), Pair::Close);
        assert_eq!(paired(5, 1), Pair::Again);
        assert_eq!(paired(5, READ_TRIES - 1), Pair::Again);
        assert_eq!(paired(5, READ_TRIES), Pair::Apart);
    }

    /// The host's two clocks read alike at start and go on together: `M` never goes back, and no
    /// step is seen on a host whose clock is not stepped.
    #[test]
    fn the_hosts_clocks_read_alike_and_the_monotonic_one_never_goes_back() {
        let clock = RelayClock::system();
        let read = clock.read();
        let (judging, mono) = (read.judged().ms(), read.mono().ms());
        assert!(judging.abs_diff(mono) < 1_000, "{judging} beside {mono}");
        let mut last = mono;
        for _ in 0..1_000 {
            let mono = clock.mono().ms();
            assert!(mono >= last);
            last = mono;
        }
        assert_eq!(clock.steps(), 0);
    }

    /// A step of `J` either way, `M` going on, is seen exactly, once, at the next read, and `M`
    /// carries on as if nothing happened; a slew (both moving alike) is no step.
    #[test]
    fn a_step_either_way_is_seen_once_and_the_monotonic_clock_goes_on() {
        let judging = Arc::new(AtomicU64::new(10_000_000));
        let monotonic = Arc::new(AtomicU64::new(10_000_000));
        let clock = {
            let (j, m) = (Arc::clone(&judging), Arc::clone(&monotonic));
            RelayClock::scripted_apart(
                Arc::new(move || j.load(Ordering::Relaxed)),
                Arc::new(move || m.load(Ordering::Relaxed)),
            )
        };
        // Both on together: no step.
        for _ in 0..10 {
            judging.fetch_add(1_000, Ordering::Relaxed);
            monotonic.fetch_add(1_000, Ordering::Relaxed);
            let _ = clock.read();
        }
        assert_eq!(clock.steps(), 0);
        // Back an hour.
        judging.fetch_sub(3_600_000, Ordering::Relaxed);
        let read = clock.read();
        let (j, m) = (read.judged().ms(), read.mono().ms());
        assert_eq!((clock.steps(), m), (1, 10_010_000));
        assert_eq!(j + 3_600_000, 10_010_000);
        let _ = clock.read();
        assert_eq!(clock.steps(), 1);
        // Forward two hours.
        judging.fetch_add(7_200_000, Ordering::Relaxed);
        let _ = clock.read();
        assert_eq!(clock.steps(), 2);
    }

    /// A host's judging clock is bounded by its ClockBound alone, read at each judgement: with
    /// none on the host, it judges nothing, and says why. Before, it was bounded by the kernel's
    /// `maxerror`, which no daemon vouches for.
    #[test]
    fn a_host_without_clockbound_judges_nothing_and_says_why() {
        let missing = std::env::temp_dir().join(format!("no_clockbound_{}", std::process::id()));
        let bound: &'static tally_wire::clock_bound::Reader =
            Box::leak(Box::new(tally_wire::clock_bound::Reader::at(
                &missing.join("shm0").to_string_lossy(),
                &missing.join("vmclock0").to_string_lossy(),
            )));
        let clock = RelayClock::bounded_by(bound);
        assert_eq!((clock.error_ms(), clock.judging()), (None, false));
        let health = clock.bound_health();
        assert_eq!(
            health.refusing,
            Some(tally_wire::clock_bound::Refusal::Missing)
        );
        assert!(health.missing >= 2, "{health:?}");
        assert_eq!(health.bound_ms, None);
    }

    /// A clock's error: unbounded is no judging clock.
    #[test]
    fn an_unbounded_error_judges_no_clock() {
        let clock = RelayClock::scripted(Arc::new(|| 5));
        assert_eq!((clock.error_ms(), clock.judging()), (Some(0), true));
        clock.set_error(None);
        assert_eq!((clock.error_ms(), clock.judging()), (None, false));
        clock.set_error(Some(20));
        assert_eq!(clock.error_ms(), Some(20));
    }
}
