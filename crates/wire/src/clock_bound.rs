//! The host clock's error bound as the host's own ClockBound daemon publishes it (RFC-0171 §3.6):
//! the one reader of it, which a relay's judging clock (`tally_relay::clock`), the API's
//! (`tally_api::mlat::Clock`) and a feeder's host source (`tally_feed::source::host_error_ms`) each
//! read at every judgement, and the one judgement of what it says ([`judged`]).
//!
//! The bound is a per-host daemon's, as Google's TrueTime and AWS ClockBound keep one: ClockBound
//! 2.x (`clockbound`) polls chronyd ten times a second, takes its root delay over two, its root
//! dispersion and its outstanding correction, and publishes that bound with the time it took it, a
//! drift rate (`--max-drift-rate`) and a status in a shared memory segment
//! (`/var/run/clockbound/shm0`). Its client ([`clock_bound_client`], 2.0.3, the vendor's own
//! crate) reads the segment, a memory read with no system call but the clock's vDSO reads, and
//! grows the bound by the drift rate since it was taken. The kernel's own word (`adjtimex`'s
//! `maxerror`) is no bound by itself: the kernel cannot tell which daemon wrote it
//! (systemd-timesyncd writes 0), a chronyd killed mid-slew leaves the tick biased by up to 83,333
//! ppm while `maxerror` grows at 500 ppm, and a suspend or a VM's restore is not aged at all. So
//! nothing reads it any more, and Clippy refuses `adjtimex` everywhere (`clippy.toml`).
//!
//! What ClockBound says, from its source (clock-bound-d and clock-bound-shm 2.0.3):
//!
//! - **chronyd stops answering** (killed, or hung): the daemon's next poll of chronyd fails (at
//!   once when it is gone, after the 1 s query timeout when it hangs), and it writes `FreeRunning`
//!   while the last synchronised sample is under 5 s old, `Unknown` after
//!   (`CHRONY_RESTART_GRACE_PERIOD`). It keeps the last synchronised bound and its time, so the
//!   bound a client reads grows from there by `--max-drift-rate`. So the status leaves
//!   `Synchronized` within about 0.1 s of chronyd's death, or about 1.1 s while it hangs.
//! - **chronyd alive, its sources lost**: chrony goes on saying synchronised, and ClockBound
//!   writes `FreeRunning` once chrony's last clock update is older than eight of its polling
//!   intervals (its register empty); until then the bound is chrony's root dispersion, which
//!   chrony grows by `maxclockerror` (hence 50 ppm, not chrony's optimistic 1 ppm).
//! - **ClockBound itself stops**: the segment stays as last written, and the client reads it
//!   `Synchronized` for 5 s after its last sample, `FreeRunning` until 1,000 s, `Unknown` after,
//!   the bound growing by the drift rate throughout.
//! - **A VM's clock disrupted** (VMClock's disruption marker moved): `Disrupted`, or `Unknown`
//!   to a client whose marker differs, until chronyd has been reset and resynchronised.
//!
//! A relay and the API judge only while it says `Synchronized` and the bound's half-width is
//! within `budget::E` less `budget::CLOCK_BOUND_MARGIN` (what the gaps below may leave unsaid,
//! 418 ms, so a judging clock is within `E` even across them): anything else (the segment missing or unreadable, `Unknown`,
//! `FreeRunning`, `Disrupted`, or a bound too wide) judges nothing, each counted by its reason and
//! the last stated ([`Health`]). A feeder's host is a trusted reference by the same verdict, and
//! never needs it: without it the feeder signs by its relays alone.
//!
//! The residual gaps, stated rather than closed (RFC-0171 §3.6):
//!
//! - The bound is only as honest as the daemons: chrony's root distance (its sources' word, and
//!   `maxclockerror` covering the oscillator) and ClockBound's `--max-drift-rate`.
//! - Between chronyd's death mid-slew and ClockBound's next poll the status still says
//!   `Synchronized` while the tick's bias runs at up to 83,333 ppm against a bound growing at 50:
//!   about 8 ms unaccounted when chronyd exits (one 0.1 s poll), up to about 92 ms while it hangs
//!   (the 1.1 s query timeout), and up to about 417 ms when ClockBound stops with it (its segment
//!   read `Synchronized` for 5 s after its last sample). `budget::CLOCK_BOUND_MARGIN` covers the
//!   worst of them and `J`'s truncation to the millisecond, so these cost judging time, not truth.
//! - ClockBound's daemon, restarted, wipes its segment in place (`ShmWriter::wipe` truncates the
//!   file with `File::create`), so a reader holding the old mapping takes `SIGBUS` if it reads
//!   between the truncation and the rewrite. The process dies and `Restart=always` brings it back
//!   (RFC-0171 §3.6, a known upstream defect; the fix proposed upstream is to write a new file and
//!   rename it over the old).
//! - The vendor's reader prints to stderr each time it opens a segment of a version it does not
//!   support, so a reader opens such a segment again only once the file changes ([`Reader`]).
//! - A leap smear (a smearing server, or chrony's own `leapsecmode slew`) moves the clock off UTC
//!   by up to half a second with no bound that says so.
//! - A suspend or a VM's restore without VMClock is seen only once chronyd's next measurement
//!   is: until then the bound read is the one before it.
//! - A host without ClockBound never judges as a relay or the API: it is no host to run one on.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use clock_bound_client::{ClockBoundClient, ClockStatus};

/// Where ClockBound's daemon publishes its segment by default.
pub const SHM: &str = clock_bound_client::CLOCKBOUND_SHM_DEFAULT_PATH;

/// Where the kernel's VMClock is, which ClockBound's client reads beside the segment when the
/// daemon runs with clock disruption support (the hypervisor offering it).
pub const VMCLOCK: &str = clock_bound_client::VMCLOCK_SHM_DEFAULT_PATH;

/// ClockBound's systemd unit, as its package installs it: a packaged unit of ours is ordered after
/// it and never pulls it in ([`unit_faults`]).
pub const UNIT: &str = "clockbound.service";

/// How long a reader that found no usable segment waits before it opens it again: a second, so a
/// host without ClockBound pays one `stat` a second per thread, not one per judgement.
const REOPEN_MS: u64 = 1_000;

/// Why a read of the bound judges nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// No segment: ClockBound is not running on this host, or never has.
    Missing,
    /// A segment its client cannot read (malformed, of another version, uninitialised, or a
    /// VMClock it names and the process cannot open).
    Unreadable,
    /// ClockBound does not know the clock's state (chronyd silent past its grace, or a segment
    /// stale past its life).
    Unknown,
    /// The clock is free running: chronyd silent within its grace, its sources lost, or
    /// ClockBound itself stopped.
    FreeRunning,
    /// VMClock says the clock was disrupted, and it is not yet resynchronised.
    Disrupted,
    /// Synchronised, but its half-width is past `budget::E` less `budget::CLOCK_BOUND_MARGIN`.
    TooWide,
}

impl Refusal {
    const ALL: [Self; 6] = [
        Self::Missing,
        Self::Unreadable,
        Self::Unknown,
        Self::FreeRunning,
        Self::Disrupted,
        Self::TooWide,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Missing => 0,
            Self::Unreadable => 1,
            Self::Unknown => 2,
            Self::FreeRunning => 3,
            Self::Disrupted => 4,
            Self::TooWide => 5,
        }
    }
}

/// What ClockBound says of the clock, as its client reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Unknown,
    Synchronized,
    FreeRunning,
    Disrupted,
}

impl From<ClockStatus> for Status {
    fn from(status: ClockStatus) -> Self {
        match status {
            ClockStatus::Synchronized => Self::Synchronized,
            ClockStatus::FreeRunning => Self::FreeRunning,
            ClockStatus::Disrupted => Self::Disrupted,
            ClockStatus::Unknown => Self::Unknown,
        }
    }
}

/// The bound, in whole milliseconds rounded up, by which ClockBound's word (`status`, and its
/// interval's half-width in nanoseconds) holds the host's clock to true time: only while it says
/// `Synchronized` and the half-width leaves the clock within `budget::E` past what ClockBound may
/// leave unsaid (`budget::judging_bound`). The one judgement of its word.
pub const fn judged(status: Status, half_width_ns: u64) -> Result<u64, Refusal> {
    match status {
        Status::Synchronized => {
            let ms = half_width_ns.div_ceil(1_000_000);
            if crate::budget::judging_bound(ms) {
                Ok(ms)
            } else {
                Err(Refusal::TooWide)
            }
        }
        Status::FreeRunning => Err(Refusal::FreeRunning),
        Status::Disrupted => Err(Refusal::Disrupted),
        Status::Unknown => Err(Refusal::Unknown),
    }
}

/// The half-width of ClockBound's interval `[earliest, latest]` in nanoseconds, or
/// [`Refusal::Unreadable`] for an interval whose end is before its start: no bound at all, never
/// one of none. Before, an inverted interval read as a half-width of 0, the narrowest bound.
fn half_width_ns(earliest: (i64, i64), latest: (i64, i64)) -> Result<u64, Refusal> {
    let ns = |(sec, nsec): (i64, i64)| i128::from(sec) * 1_000_000_000 + i128::from(nsec);
    let width = u128::try_from(ns(latest) - ns(earliest)).map_err(|_| Refusal::Unreadable)?;
    Ok(u64::try_from(width.div_ceil(2)).unwrap_or(u64::MAX))
}

/// What names a segment's file as it is: its device and inode, its length, and when its contents
/// and its inode last changed. A file ClockBound made again, wiped or rewrote differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileId {
    fn of(path: &str) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).ok()?;
        Some(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: (meta.mtime(), meta.mtime_nsec()),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

/// A `timespec`'s seconds and nanoseconds as they are on every target.
#[allow(
    clippy::useless_conversion,
    reason = "`time_t` and `c_long` are 32 bits on a 32-bit ARM feeder, 64 elsewhere"
)]
fn parts(sec: libc::time_t, nsec: libc::c_long) -> (i64, i64) {
    (i64::from(sec), i64::from(nsec))
}

/// The reads of the bound, by their verdicts: what a relay states (`MemoryReport::clock_bound`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Health {
    /// The last read's bound in milliseconds, when it judged.
    pub bound_ms: Option<u64>,
    /// Why the last read judged nothing, when it did not.
    pub refusing: Option<Refusal>,
    /// The reads that judged nothing, by why.
    pub missing: u64,
    pub unreadable: u64,
    pub unknown: u64,
    pub free_running: u64,
    pub disrupted: u64,
    pub too_wide: u64,
}

/// What [`Reader`] keeps of its last read: a bound in milliseconds (within `E`, far below these),
/// or a refusal at `REFUSED - index`, or none yet.
const NONE_YET: u64 = u64::MAX;
const REFUSED: u64 = u64::MAX - 1;

/// A reader of one ClockBound segment: the host's ([`Reader::host`]), or a test's at its own
/// paths ([`Reader::at`]). Its client is the vendor's, which is neither `Send` nor `Sync` (it
/// keeps its last snapshot), so each thread holds its own, opened at its first read, let go after
/// any read that judged nothing, and opened again a second later (until then the refusal holds).
/// A segment of a version the vendor's reader does not support is opened again only once its file
/// changes: each open of one prints a line to stderr, so a host running a newer ClockBound logs it
/// once, not once a second per thread.
pub struct Reader {
    id: u64,
    shm: String,
    vmclock: String,
    reopen_ms: u64,
    refused: [AtomicU64; Refusal::ALL.len()],
    last: AtomicU64,
    /// The clients opened, for a test of how often it opens.
    opens: AtomicU64,
}

/// A thread's client of one reader's segment, or when it found none usable and why.
enum Held {
    /// Boxed: the client holds its last snapshot and both segments' mappings. Beside it, the
    /// segment's file as it was when it was opened.
    Open(Box<ClockBoundClient>, Option<FileId>),
    Shut {
        at: std::time::Instant,
        why: Refusal,
        /// The file a segment of a version the vendor's reader does not support was read from:
        /// not opened again until the file changes, since each open of it prints to stderr.
        quiet: Option<FileId>,
    },
}

thread_local! {
    static HELD: RefCell<Vec<(u64, Held)>> = const { RefCell::new(Vec::new()) };
}

impl Reader {
    /// The host's: ClockBound's segment and VMClock at their default paths, one for the process.
    pub fn host() -> &'static Self {
        static HOST: OnceLock<Reader> = OnceLock::new();
        HOST.get_or_init(|| Self::at(SHM, VMCLOCK))
    }

    /// A reader of the segment at `shm`, VMClock at `vmclock`.
    pub fn at(shm: &str, vmclock: &str) -> Self {
        static IDS: AtomicU64 = AtomicU64::new(0);
        Self {
            id: IDS.fetch_add(1, Ordering::Relaxed),
            shm: shm.to_owned(),
            vmclock: vmclock.to_owned(),
            reopen_ms: REOPEN_MS,
            refused: [const { AtomicU64::new(0) }; Refusal::ALL.len()],
            last: AtomicU64::new(NONE_YET),
            opens: AtomicU64::new(0),
        }
    }

    /// The bound now ([`judged`]), counted by its verdict.
    pub fn read(&self) -> Result<u64, Refusal> {
        let verdict = self.asked();
        match verdict {
            Ok(ms) => self.last.store(ms, Ordering::Relaxed),
            Err(why) => {
                self.refused[why.index()].fetch_add(1, Ordering::Relaxed);
                self.last
                    .store(REFUSED - why.index() as u64, Ordering::Relaxed);
            }
        }
        verdict
    }

    /// What the reads said: the last one's verdict, and the refusals by why.
    pub fn health(&self) -> Health {
        let last = self.last.load(Ordering::Relaxed);
        let refusing = Refusal::ALL
            .into_iter()
            .find(|why| last == REFUSED - why.index() as u64);
        let count = |why: Refusal| self.refused[why.index()].load(Ordering::Relaxed);
        Health {
            bound_ms: (last < REFUSED - Refusal::ALL.len() as u64).then_some(last),
            refusing,
            missing: count(Refusal::Missing),
            unreadable: count(Refusal::Unreadable),
            unknown: count(Refusal::Unknown),
            free_running: count(Refusal::FreeRunning),
            disrupted: count(Refusal::Disrupted),
            too_wide: count(Refusal::TooWide),
        }
    }

    /// The bound now, by this thread's client of the segment: opened when there is none, or when
    /// the last read found none usable a second ago; and let go after any read that does not
    /// judge, so a segment ClockBound made again is the one read next.
    fn asked(&self) -> Result<u64, Refusal> {
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            let index = match held.iter().position(|(id, _)| *id == self.id) {
                Some(index) => index,
                None => {
                    held.push((self.id, self.opened()));
                    held.len() - 1
                }
            };
            let slot = &mut held[index].1;
            if let Held::Shut { at, why, quiet } = *slot {
                if at.elapsed() < std::time::Duration::from_millis(self.reopen_ms) {
                    return Err(why);
                }
                if quiet.is_some() && quiet == FileId::of(&self.shm) {
                    *slot = Held::Shut {
                        at: std::time::Instant::now(),
                        why,
                        quiet,
                    };
                    return Err(why);
                }
                *slot = self.opened();
            }
            let mut quiet = None;
            let verdict = match slot {
                Held::Open(client, file) => match client.now() {
                    Ok(now) => half_width_ns(
                        parts(now.earliest.tv_sec(), now.earliest.tv_nsec()),
                        parts(now.latest.tv_sec(), now.latest.tv_nsec()),
                    )
                    .and_then(|half_width| judged(now.clock_status.into(), half_width)),
                    Err(error) => {
                        quiet = unsupported(&error, *file);
                        Err(Refusal::Unreadable)
                    }
                },
                Held::Shut { why, .. } => Err(*why),
            };
            if let Err(why) = verdict
                && matches!(slot, Held::Open(..))
            {
                *slot = Self::shut(why, quiet);
            }
            verdict
        })
    }

    /// A client of the segment, or why there is none.
    fn opened(&self) -> Held {
        if !std::path::Path::new(&self.shm).exists() {
            return Self::shut(Refusal::Missing, None);
        }
        self.opens.fetch_add(1, Ordering::Relaxed);
        // The file as it was before it was opened, so a change made while it opens is seen.
        let file = FileId::of(&self.shm);
        ClockBoundClient::new_with_paths(&self.shm, &self.vmclock).map_or_else(
            |error| Self::shut(Refusal::Unreadable, unsupported(&error, file)),
            |client| Held::Open(Box::new(client), file),
        )
    }

    fn shut(why: Refusal, quiet: Option<FileId>) -> Held {
        Held::Shut {
            at: std::time::Instant::now(),
            why,
            quiet,
        }
    }
}

/// `file`, the segment's file as it was opened, when `error` is the vendor's refusal of its
/// version: what a reader waits to see change before it opens the segment again.
fn unsupported(
    error: &clock_bound_client::ClockBoundError,
    file: Option<FileId>,
) -> Option<FileId> {
    if matches!(
        error.kind,
        clock_bound_client::ClockBoundErrorKind::SegmentVersionNotSupported
    ) {
        file
    } else {
        None
    }
}

/// What a packaged systemd unit holds wrongly about ClockBound: not ordered after [`UNIT`]
/// (`After=`), so on a host that has it the process may judge before it is up; pulling it in
/// (`Wants=`, `Requires=`, `BindsTo=`), which a host without it must not need; no read of VMClock
/// (`DeviceAllow=/dev/vmclock0 r`), which ClockBound's client opens beside the segment where the
/// hypervisor offers one; `PrivateDevices=yes`, which hides it whatever `DeviceAllow=` says; or
/// the host's `/dev/shm` shared with the process (no `TemporaryFileSystem=/dev/shm`), which
/// `PrivateDevices=` would have made private and a unit without it must make private itself.
/// Empty when the unit reads the bound as both packaged units must.
#[must_use]
pub fn unit_faults(unit: &str) -> Vec<&'static str> {
    let named = |key: &str| -> Vec<&str> {
        unit.lines()
            .map(str::trim)
            .filter_map(|line| line.strip_prefix(key))
            .flat_map(str::split_whitespace)
            .collect()
    };
    let mut faults = Vec::new();
    if !named("After=").contains(&UNIT) {
        faults.push("not ordered after clockbound.service");
    }
    if ["Wants=", "Requires=", "BindsTo=", "Requisite="]
        .into_iter()
        .any(|key| named(key).contains(&UNIT))
    {
        faults.push("pulls in clockbound.service");
    }
    let devices = unit
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("DeviceAllow="))
        .any(|value| {
            let mut words = value.split_whitespace();
            words.next() == Some(VMCLOCK) && words.next().is_some_and(|mode| mode.contains('r'))
        });
    if !devices {
        faults.push("does not allow reading /dev/vmclock0");
    }
    let private = unit
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("PrivateDevices="))
        .next_back()
        .is_some_and(|value| matches!(value.trim(), "yes" | "true" | "on" | "1"));
    if private {
        faults.push("PrivateDevices= hides /dev/vmclock0");
    }
    if !named("TemporaryFileSystem=")
        .into_iter()
        .any(|entry| entry.split(':').next() == Some("/dev/shm"))
    {
        faults.push("shares the host's /dev/shm");
    }
    faults
}

#[cfg(test)]
mod tests {
    use super::*;
    use clock_bound_shm::{ClockErrorBound, ShmWrite, ShmWriter};
    use nix::sys::time::TimeSpec;

    /// A test's scratch directory, its own per test.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::var_os("TEST_TMPDIR")
            .map_or_else(std::env::temp_dir, std::path::PathBuf::from)
            .join(format!("clock_bound_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
        dir
    }

    /// A segment written as ClockBound's daemon writes one, its sample taken now on
    /// `CLOCK_MONOTONIC_COARSE` (the client's clock), with `bound_ns` and `status`, and no clock
    /// disruption support (so no VMClock is read).
    fn segment(dir: &std::path::Path, bound_ns: i64, status: ClockStatus) -> String {
        let path = dir.join("shm0");
        let now =
            clock_bound_shm::common::clock_gettime_safe(clock_bound_shm::common::CLOCK_MONOTONIC)
                .unwrap_or_else(|error| panic!("{error:?}"));
        let ceb = ClockErrorBound::new(
            now,
            now + TimeSpec::new(1_000, 0),
            bound_ns,
            0,
            50_000,
            status,
            false,
        );
        let mut writer = ShmWriter::new(&path).unwrap_or_else(|error| panic!("{error}"));
        writer.write(&ceb);
        path.to_string_lossy().into_owned()
    }

    fn reader_of(shm: &str, dir: &std::path::Path) -> Reader {
        Reader {
            reopen_ms: 0,
            ..Reader::at(shm, &dir.join("vmclock0").to_string_lossy())
        }
    }

    /// The one judgement: synchronised within `E` is its half-width rounded up to the
    /// millisecond; one nanosecond past `E` is too wide; every other status is no bound however
    /// narrow. Each guard's mutation fails here: `<=` for `<`, a free-running or unknown clock
    /// taken as synchronised, rounding down.
    #[test]
    fn only_a_synchronised_bound_within_e_judges() {
        // `E` less `budget::CLOCK_BOUND_MARGIN`, 418 ms (asserted there).
        let limit_ms = crate::budget::E_MS - 418;
        let limit_ns = limit_ms * 1_000_000;
        assert_eq!(judged(Status::Synchronized, 0), Ok(0));
        assert_eq!(judged(Status::Synchronized, 1), Ok(1));
        assert_eq!(judged(Status::Synchronized, 2_500_000), Ok(3));
        assert_eq!(judged(Status::Synchronized, limit_ns), Ok(limit_ms));
        assert_eq!(
            judged(Status::Synchronized, limit_ns + 1),
            Err(Refusal::TooWide)
        );
        // A bound within `E` but not past ClockBound's gaps judges nothing: before, it did.
        assert_eq!(
            judged(Status::Synchronized, crate::budget::E_MS * 1_000_000),
            Err(Refusal::TooWide)
        );
        assert_eq!(judged(Status::FreeRunning, 0), Err(Refusal::FreeRunning));
        assert_eq!(judged(Status::Unknown, 0), Err(Refusal::Unknown));
        assert_eq!(judged(Status::Disrupted, 0), Err(Refusal::Disrupted));
        assert_eq!(half_width_ns((10, 0), (10, 4)), Ok(2));
        assert_eq!(half_width_ns((9, 999_999_999), (10, 2)), Ok(2));
        assert_eq!(half_width_ns((10, 0), (10, 0)), Ok(0));
        // An interval whose end is before its start is no bound, never the narrowest one.
        assert_eq!(half_width_ns((10, 5), (10, 0)), Err(Refusal::Unreadable));
    }

    /// Read through ClockBound's own client from a segment its own writer wrote: synchronised
    /// and narrow judges by its bound (grown by the drift rate since it was taken, so at least
    /// the bound written); missing, unreadable, free running, unknown and too wide judge
    /// nothing, each counted by why, and the last stated.
    #[test]
    fn a_segment_judges_only_synchronised_and_narrow() {
        let dir = scratch("verdicts");
        let synced = reader_of(
            &segment(&dir.join("synced"), 2_000_000, ClockStatus::Synchronized),
            &dir,
        );
        let bound = synced.read();
        assert!(
            matches!(bound, Ok(ms) if (2..=3).contains(&ms)),
            "{bound:?}"
        );
        assert_eq!(synced.health().bound_ms, bound.ok());
        assert_eq!(synced.health().refusing, None);

        let missing = reader_of(&dir.join("none").to_string_lossy(), &dir);
        assert_eq!(missing.read(), Err(Refusal::Missing));
        assert_eq!(missing.health().missing, 1);
        assert_eq!(missing.health().refusing, Some(Refusal::Missing));

        let junk = dir.join("junk");
        std::fs::write(&junk, [7_u8; 64]).unwrap_or_else(|error| panic!("{error}"));
        let unreadable = reader_of(&junk.to_string_lossy(), &dir);
        assert_eq!(unreadable.read(), Err(Refusal::Unreadable));
        assert_eq!(unreadable.health().unreadable, 1);

        for (name, status, why) in [
            ("free", ClockStatus::FreeRunning, Refusal::FreeRunning),
            ("unknown", ClockStatus::Unknown, Refusal::Unknown),
            ("disrupted", ClockStatus::Disrupted, Refusal::Disrupted),
        ] {
            let reader = reader_of(&segment(&dir.join(name), 1_000, status), &dir);
            assert_eq!(reader.read(), Err(why), "{name}");
            assert_eq!(reader.health().refusing, Some(why), "{name}");
        }

        let e_ns = i64::try_from(crate::budget::E_MS * 1_000_000).unwrap_or(i64::MAX);
        let wide = reader_of(
            &segment(&dir.join("wide"), e_ns + 1, ClockStatus::Synchronized),
            &dir,
        );
        assert_eq!(wide.read(), Err(Refusal::TooWide));
        assert_eq!(wide.health().too_wide, 1);
        assert_eq!(wide.health().bound_ms, None);
    }

    /// A segment that turns up later is read once the reader opens it again (at once here, a
    /// second on a host), and one that stops judging is let go and read afresh, so a segment
    /// ClockBound made again is the one read. Each guard's mutation fails here.
    #[test]
    fn a_segment_that_turns_up_later_is_read() {
        let dir = scratch("later");
        let path = dir.join("later").join("shm0");
        let reader = reader_of(&path.to_string_lossy(), &dir);
        assert_eq!(reader.read(), Err(Refusal::Missing));
        segment(&dir.join("later"), 1_000_000, ClockStatus::FreeRunning);
        assert_eq!(reader.read(), Err(Refusal::FreeRunning));
        // ClockBound made again, a new file where the old was: the old mapping still says free
        // running, so only a reader that let it go reads the new one.
        std::fs::remove_file(&path).unwrap_or_else(|error| panic!("{error}"));
        segment(&dir.join("later"), 1_000_000, ClockStatus::Synchronized);
        assert!(reader.read().is_ok());
        assert_eq!(reader.health().missing, 1);
        assert_eq!(reader.health().free_running, 1);
    }

    /// A reader that found no usable segment does not open it again for a second, so a host
    /// without ClockBound pays a `stat` a second per thread, not one per judgement: a segment that
    /// turns up within the second is not read yet. Removing the throttle fails here.
    #[test]
    fn a_reader_opens_a_segment_again_only_a_second_later() {
        let dir = scratch("throttled");
        let path = dir.join("throttled").join("shm0");
        let reader = Reader::at(
            &path.to_string_lossy(),
            &dir.join("vmclock0").to_string_lossy(),
        );
        assert_eq!(reader.read(), Err(Refusal::Missing));
        segment(&dir.join("throttled"), 1_000_000, ClockStatus::Synchronized);
        assert_eq!(reader.read(), Err(Refusal::Missing));
        assert_eq!(reader.health().missing, 2);
    }

    /// A segment of a version the vendor's reader does not support (whose every open prints to
    /// stderr) is opened once, and again only once its file changes. Before, it was opened again
    /// every second, a line each time. Removing the check fails here.
    #[test]
    fn a_segment_of_an_unsupported_version_is_opened_again_only_once_it_changes() {
        use std::io::{Seek, Write};
        let dir = scratch("version");
        let path = segment(&dir.join("version"), 1_000_000, ClockStatus::Synchronized);
        // The layout version, after the two magic words and the size.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap_or_else(|error| panic!("{error}"));
        file.seek(std::io::SeekFrom::Start(12))
            .and_then(|_| file.write_all(&99_u16.to_ne_bytes()))
            .unwrap_or_else(|error| panic!("{error}"));
        drop(file);
        let reader = reader_of(&path, &dir);
        for _ in 0..3 {
            assert_eq!(reader.read(), Err(Refusal::Unreadable));
        }
        assert_eq!(reader.opens.load(Ordering::Relaxed), 1);
        // ClockBound wipes and rewrites it: a changed file, opened again and read.
        segment(&dir.join("version"), 1_000_000, ClockStatus::Synchronized);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| {
                file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            })
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(reader.read().is_ok());
        assert_eq!(reader.opens.load(Ordering::Relaxed), 2);
    }

    /// A packaged unit is ordered after ClockBound and never pulls it in, and lets its client read
    /// VMClock. Each fault is named.
    #[test]
    fn a_unit_orders_after_clockbound_and_reads_vmclock() {
        let right = "After=network-online.target clockbound.service\nDeviceAllow=/dev/vmclock0 r\nDevicePolicy=closed\nTemporaryFileSystem=/dev/shm:mode=1777,nosuid,nodev,noexec\n";
        assert!(unit_faults(right).is_empty(), "{:?}", unit_faults(right));
        let shm = "TemporaryFileSystem=/dev/shm\n";
        assert_eq!(
            unit_faults(&format!("DeviceAllow=/dev/vmclock0 r\n{shm}")),
            ["not ordered after clockbound.service"]
        );
        assert_eq!(
            unit_faults(&format!("{right}Wants=clockbound.service\n")),
            ["pulls in clockbound.service"]
        );
        assert_eq!(
            unit_faults(&format!("After=clockbound.service\n{shm}")),
            ["does not allow reading /dev/vmclock0"]
        );
        // VMClock allowed for writing only is not allowed for reading.
        assert_eq!(
            unit_faults(&format!(
                "After=clockbound.service\nDeviceAllow=/dev/vmclock0 w\n{shm}"
            )),
            ["does not allow reading /dev/vmclock0"]
        );
        // With no PrivateDevices=, the host's /dev/shm is the process's unless made private.
        assert_eq!(
            unit_faults("After=clockbound.service\nDeviceAllow=/dev/vmclock0 r\n"),
            ["shares the host's /dev/shm"]
        );
        assert_eq!(
            unit_faults(
                "After=clockbound.service\nDeviceAllow=/dev/vmclock0 r\nTemporaryFileSystem=/var/cache /dev/shmem\n"
            ),
            ["shares the host's /dev/shm"]
        );
        assert_eq!(
            unit_faults(&format!("{right}PrivateDevices=yes\n")),
            ["PrivateDevices= hides /dev/vmclock0"]
        );
        assert!(unit_faults(&format!("{right}PrivateDevices=yes\nPrivateDevices=no\n")).is_empty());
    }
}
