//! The map image's ACARS collector (RFC-0187 §3, packaging/map/README.md): reads a relay's
//! `--acars-out`, merges the copies of each message its receivers published, and files each
//! message into the UTC day of its own time, for the archiver to pack with that day's globe
//! history.
//!
//! - **Copies are merged.** Every receiver that heard a message publishes its own copy, and a
//!   receiver's copies, told apart by their times, would say where it is, set against the
//!   positions the messages name. The wire's one flat schema (`tally_wire::acars`) makes every
//!   copy of a message the same line but for its time, so copies are found by equality
//!   (`acars::copy_key`). A message is held [`MERGE_WINDOW`] seconds from its first copy's
//!   arrival, every copy that comes meanwhile is counted into it, and it is written once, timed at
//!   the median of its copies' seconds (with an even count, the floor of the mean of the middle
//!   two): one receiver's clock, fast or slow, cannot move it while most copies agree, where the
//!   earliest second would always be the slowest clock's. A message only one receiver heard keeps
//!   that receiver's second. A copy that comes after its message was written, within
//!   [`MAX_SKEW`], is dropped and counted ([`WRITTEN_KEYS`] are remembered), never written as a
//!   second line. While [`PENDING_BYTES`] of messages are held, a new one is dropped and the
//!   day's `full` gap opened, rather than a held one written before its copies are in.
//! - **One file a day,** `HISTORY/YYYY/MM/DD/acars.jsonl`, the day of each message's own time, each
//!   line as `tally_wire::acars::line` takes it (the relay's lines are held to the rule again
//!   here, never taken on its word). A message whose time is more than [`MAX_SKEW`] from its
//!   arrival is dropped, so a day takes only what can arrive before it is packed. A day's file is
//!   held to a number of bytes, counted to the byte, newlines included; past it the rest of the
//!   day's lines are dropped. A day is never written once its packing may have begun (01:10 UTC
//!   the next day; the archiver starts at 01:15) or once it is packed (`archive/.packed`): a line
//!   for it is dropped and counted. A line cut short by a crash is cut off when the file is next
//!   opened.
//! - **What a day misses is written down,** in `HISTORY/YYYY/MM/DD/acars.gaps`, one line a gap,
//!   `FROM TO WHY` in Unix seconds: the collector was not reading the relay (`down`: from the last
//!   time it read, which it keeps on the volume in `archive/.acars-read`, written about once a
//!   minute and as it stops, until it is connected again), lines could not be written (`write`:
//!   from the first that failed until the next that did not), messages were dropped for want of
//!   room to hold them (`full`: from the first to the next one held), messages came timed more
//!   than [`MAX_SKEW`] from their arrival (`skew`: from the first to the next one that was not),
//!   or the day reached its cap (`cap`). A `down` or `skew` gap is in every day a message
//!   arriving in it may be filed in: from [`MAX_SKEW`] before it to [`MAX_SKEW`] after.
//!   A gap is written as it opens, `TO` `-`, and again once it closes with its `TO`; one never
//!   closed ran to the day's end. A day with gaps is packed as partial (entrypoint.sh), the file
//!   with it.
//! - **At pack time the day is sorted** by each message's own time ([`sort_day`]), so the order
//!   says nothing of who sent what together. The sort is an external merge in bounded memory
//!   ([`SORT_MEMORY`]), its runs on the volume under `archive/.sorting`, which nothing serves.

#![deny(unsafe_code)]

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, RandomState};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tally_wire::acars;
use tally_wire::backoff::Backoff;

// The one module allowed `unsafe`: its calls into libc.
#[allow(unsafe_code)]
mod os;

/// A day's ACARS file in its history directory.
pub const DAY_FILE: &str = "acars.jsonl";
/// What a day missed, beside it.
pub const GAPS_FILE: &str = "acars.gaps";
/// Where the archiver records each day it packed, `YYYY-MM-DD`, under the history directory
/// (entrypoint.sh's `PACKED`).
pub const PACKED_DIR: &str = "archive/.packed";
/// The last time the collector read the relay, in Unix seconds, under the history directory.
pub const READ_FILE: &str = "archive/.acars-read";
/// A day's file is held to this unless `--day-max` says otherwise: while it is packed, it, the
/// sort's runs and the run they merge into are on the volume at once.
pub const DEFAULT_DAY_MAX: u64 = 256 * 1024 * 1024;
/// How long a message is held for its copies, from its first copy's arrival: a feeder seals a
/// batch every second and a relay forwards it at once, so every copy is in within seconds.
pub const MERGE_WINDOW: u64 = 30;
/// The most a message's own time may be from its arrival, in seconds.
pub const MAX_SKEW: u64 = tally_wire::budget::ACARS_MESSAGE_SKEW.duration().as_secs();
/// The most the held messages take (their lines, keys, copies' seconds and bookkeeping): past it
/// a new message is dropped, and its day's `full` gap opened.
pub const PENDING_BYTES: usize = 8 * 1024 * 1024;
/// A held message's bookkeeping beside its line, key (twice: the map's and the queue's) and
/// seconds: the map's and the queue's slots and the allocator's rounding of four allocations.
/// Measured with glibc's allocator at its worst, a map just past its growth: 300 bytes.
const PENDING_OVERHEAD: usize = 304;
/// The most copies' seconds kept for one message's median.
const MAX_COPIES: usize = 64;
/// The most messages written whose keys are remembered, for [`MAX_SKEW`] after, so a late copy is
/// dropped; past it the oldest is forgotten early.
pub const WRITTEN_KEYS: usize = 65_536;
/// What remembering one written key takes: its hash and time in the map and the queue, and the
/// map's room to grow. Measured as `PENDING_OVERHEAD` is: 66 bytes at worst.
const WRITTEN_OVERHEAD: usize = 72;
/// Seconds after a day's end from which the archiver packs it (01:15): entrypoint.sh's
/// `archive_pass`, held to it by packaging/tests/map_archive.rs.
pub const PACKED_FROM: u64 = 4_500;
/// Seconds after a day's end from which it is not written (01:10): five minutes before it may be
/// packed, so no line is on its way into it as the pack begins.
const WRITABLE_FOR: u64 = PACKED_FROM - 300;
/// How often the last read time is written to the volume, at most.
const PERSIST_EVERY: u64 = 60;
/// What the collector holds while it collects, at most: the held messages, the line being read
/// and the socket's read buffer.
pub const COLLECT_MEMORY: usize =
    PENDING_BYTES + WRITTEN_KEYS * WRITTEN_OVERHEAD + 2 * acars::MAX_LINE + 8 * 1024;

/// The most one run of the sort holds before it is written out: its lines' bytes, and
/// [`LINE_OVERHEAD`] for each.
const RUN_BYTES: usize = 12 * 1024 * 1024;
/// What holding one line costs beside its bytes: its time and its `Vec` in the run (32 bytes,
/// counted twice for the run's room to grow), and the allocator's rounding.
const LINE_OVERHEAD: usize = 80;
/// The most runs merged at once; more are merged in passes.
const MERGE_WAYS: usize = 64;
/// Each run's read buffer, and the output's write buffer.
const MERGE_BUFFER: usize = 64 * 1024;
/// The most [`sort_day`] holds, whatever the day's size: while it makes runs, one run, the line
/// being read, its key's copy, and the read and write buffers; while it merges, [`MERGE_WAYS`]
/// runs' read buffers, line buffers and lines in the heap, and the write buffer; and either way
/// the keys of the messages written in the last [`MAX_SKEW`] (at most [`WRITTEN_KEYS`], as the
/// collector keeps them) and a line read for its copy key, so none is written twice.
pub const SORT_MEMORY: usize = {
    let written = WRITTEN_KEYS * WRITTEN_OVERHEAD + 2 * acars::MAX_LINE;
    let run = RUN_BYTES + 3 * acars::MAX_LINE + 2 * MERGE_BUFFER;
    let merge = MERGE_WAYS * (MERGE_BUFFER + 2 * acars::MAX_LINE + LINE_OVERHEAD) + MERGE_BUFFER;
    written + if merge > run { merge } else { run }
};

// The bounds packaging/map/README.md states ("What ACARS costs"), held by the compiler.
const _: () = assert!(SORT_MEMORY < 17 * 1024 * 1024);
const _: () = assert!(COLLECT_MEMORY < 13 * 1024 * 1024);

const DAY_SECS: u64 = 86_400;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// A read waits at most this, so held messages are written and a stop is seen while the relay
/// is quiet.
const READ_TICK: Duration = Duration::from_secs(1);

/// The Unix seconds now.
#[allow(
    clippy::disallowed_methods,
    reason = "the collector's own host clock, which names its files' days"
)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The UTC day holding `seconds`, as its history directory names it: `YYYY/MM/DD`.
pub fn day_path(seconds: u64) -> String {
    // Howard Hinnant's days-to-civil, for days since 1970-01-01.
    let days = i64::try_from(seconds / DAY_SECS).unwrap_or(i64::MAX) + 719_468;
    let era = days.div_euclid(146_097);
    let of_era = days.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}/{month:02}/{day:02}")
}

fn day_start(seconds: u64) -> u64 {
    seconds - seconds % DAY_SECS
}

/// The starts of the days a message that arrived from `from` to `to` may be filed in: a message
/// is filed by its own time, up to [`MAX_SKEW`] from its arrival.
fn days_arrived(from: u64, to: u64) -> impl Iterator<Item = u64> {
    let last = day_start(to.saturating_add(MAX_SKEW));
    (day_start(from.saturating_sub(MAX_SKEW))..=last).step_by(DAY_SECS as usize)
}

/// What became of one line.
#[derive(Debug, PartialEq, Eq)]
pub enum Filed {
    /// Held for its copies.
    Held,
    /// A copy of a message held, counted into it.
    Merged,
    /// A copy of a message already written: dropped.
    Late,
    /// No room to hold it: dropped, and a `full` gap opened.
    Full,
    /// Not one published message (`acars::line`): skipped.
    Invalid,
    /// Its time is more than [`MAX_SKEW`] from its arrival.
    Skewed,
    Written,
    /// The day reached its cap.
    Capped,
    /// Its day's file could not be opened or written.
    Failed,
    /// Its day is packed, or its packing may have begun.
    Closed,
}

/// A day written to.
struct Day {
    /// Open, or `None` after it could not be opened or written: every line retries it.
    file: Option<File>,
    written: u64,
    capped: bool,
    /// When writing it began to fail, while it still does: its `write` gap, open.
    failing_since: Option<u64>,
}

/// A message held for its copies.
struct Held {
    line: String,
    seconds: Vec<u64>,
}

/// A gap line not yet written: its day's start, the line, and whether it may make the day's
/// directory.
struct Mark {
    day: u64,
    line: String,
    create: bool,
}

pub struct Collector {
    history: PathBuf,
    day_max: u64,
    days: BTreeMap<u64, Day>,
    held: HashMap<String, Held>,
    /// The held messages' keys by first arrival.
    arrivals: VecDeque<(u64, String)>,
    held_bytes: usize,
    /// The hashes of the keys written in the last [`MAX_SKEW`], with when, oldest first.
    written: HashMap<u64, u64>,
    written_order: VecDeque<(u64, u64)>,
    hasher: RandomState,
    /// The `full` and `skew` gaps open: since when, and the days each has marked.
    open: BTreeMap<&'static str, (u64, BTreeSet<u64>)>,
    /// Lines dropped for a day packed or being packed, by the day's start.
    closed_drops: BTreeMap<u64, u64>,
    late: u64,
    /// Whether the relay is connected now: while it is, every tick is a read of it.
    connected: bool,
    /// Gap lines not yet written: each mark and each line retries them, so a day that could not
    /// hold its gaps file when it lost a line still packs as partial.
    unwritten: Vec<Mark>,
    /// The last time the relay was read: connected, or a line from it.
    last_read: Option<u64>,
    persisted: Option<(u64, u64)>,
    /// A `down` gap open: since when, and the start of the last day marked with it.
    down: Option<(u64, u64)>,
    /// While it starts, before the archiver runs, a day past `WRITABLE_FOR` but not packed is
    /// still marked.
    starting: bool,
    skewed: u64,
    /// Messages dropped for want of room to hold them, since it started.
    crowded: u64,
}

impl Collector {
    /// Files into `history` (`/var/globe_history`), at most `day_max` bytes a day.
    pub fn new(history: impl Into<PathBuf>, day_max: u64) -> Self {
        Self {
            history: history.into(),
            day_max,
            days: BTreeMap::new(),
            held: HashMap::new(),
            arrivals: VecDeque::new(),
            held_bytes: 0,
            written: HashMap::new(),
            written_order: VecDeque::new(),
            hasher: RandomState::new(),
            open: BTreeMap::new(),
            closed_drops: BTreeMap::new(),
            late: 0,
            connected: false,
            unwritten: Vec::new(),
            last_read: None,
            persisted: None,
            down: None,
            starting: false,
            skewed: 0,
            crowded: 0,
        }
    }

    /// Takes `line` (without its newline), received at `now`: held for its copies, or counted
    /// into the message held; what is held past its window is written.
    pub fn line(&mut self, now: u64, line: &[u8]) -> Filed {
        let filed = self.take(now, line);
        self.flush_due(now);
        filed
    }

    fn take(&mut self, now: u64, line: &[u8]) -> Filed {
        let Some(line) = acars::line(line) else {
            return Filed::Invalid;
        };
        let (Some(second), Some(key)) = (
            acars::time_us(line).map(|micros| micros / 1_000_000),
            acars::copy_key(line),
        ) else {
            return Filed::Invalid;
        };
        if tally_wire::budget::acars_skewed(second, now) {
            if self.skewed == 0 {
                eprintln!(
                    "tally-acars-collect: a message timed {second} came at {now}, more than \
                     {MAX_SKEW} s away; such messages are dropped, each time a gap (a clock is \
                     wrong: a receiver's, or this host's)"
                );
            }
            self.skewed += 1;
            self.open_gap("skew", days_arrived(now, now), now);
            return Filed::Skewed;
        }
        self.close_gap("skew", now);
        if let Some(held) = self.held.get_mut(&key) {
            // A copy with no room for its second is still this message's: only the median misses it.
            if held.seconds.len() < MAX_COPIES
                && self.held_bytes + std::mem::size_of::<u64>() <= PENDING_BYTES
            {
                held.seconds.push(second);
                self.held_bytes += std::mem::size_of::<u64>();
            }
            return Filed::Merged;
        }
        self.forget_written(now);
        if self.written.contains_key(&self.hash(&key)) {
            if self.late == 0 {
                eprintln!(
                    "tally-acars-collect: a copy came after its message was written; such copies \
                     are dropped"
                );
            }
            self.late += 1;
            return Filed::Late;
        }
        let cost = held_cost(line, &key) + std::mem::size_of::<u64>();
        if self.held_bytes + cost > PENDING_BYTES {
            let start = day_start(second);
            if self.crowded == 0 {
                eprintln!(
                    "tally-acars-collect: {PENDING_BYTES} bytes of messages are held; new ones \
                     are dropped while there is no room, each time a gap"
                );
            }
            self.crowded += 1;
            self.open_gap("full", std::iter::once(start), now);
            return Filed::Full;
        }
        self.close_gap("full", now);
        self.held_bytes += cost;
        self.arrivals.push_back((now, key.clone()));
        self.held.insert(
            key,
            Held {
                line: line.to_owned(),
                seconds: vec![second],
            },
        );
        Filed::Held
    }

    /// Opens the gap `why` at `now`, unless it is open, and marks each of `days` it has not.
    fn open_gap(&mut self, why: &'static str, days: impl Iterator<Item = u64>, now: u64) {
        let (from, marked) = self
            .open
            .entry(why)
            .or_insert_with(|| (now, BTreeSet::new()));
        let from = *from;
        let new: Vec<u64> = days.filter(|day| marked.insert(*day)).collect();
        for day in new {
            self.mark(day, from, None, why, true, now);
        }
    }

    /// Closes the gap `why`, if it is open, at `now`, in every day it marked.
    fn close_gap(&mut self, why: &'static str, now: u64) {
        if let Some((from, days)) = self.open.remove(why) {
            for day in days {
                self.mark(day, from, Some(now), why, true, now);
            }
        }
    }

    fn hash(&self, key: &str) -> u64 {
        self.hasher.hash_one(key)
    }

    /// Forgets the keys written more than [`MAX_SKEW`] before `now`: no copy of theirs is taken
    /// after that.
    fn forget_written(&mut self, now: u64) {
        while let Some((at, hash)) = self.written_order.front().copied() {
            if at + MAX_SKEW > now && self.written_order.len() <= WRITTEN_KEYS {
                break;
            }
            self.written_order.pop_front();
            if self.written.get(&hash) == Some(&at) {
                self.written.remove(&hash);
            }
        }
    }

    /// Writes every held message whose window has passed at `now`.
    fn flush_due(&mut self, now: u64) -> Vec<Filed> {
        let mut filed = Vec::new();
        while let Some((arrived, _)) = self.arrivals.front() {
            if *arrived + MERGE_WINDOW > now {
                break;
            }
            filed.extend(self.write_oldest(now));
        }
        filed
    }

    /// Writes every message held, whatever its window (as it stops, or for a test).
    pub fn flush(&mut self, now: u64) -> Vec<Filed> {
        let mut filed = Vec::new();
        while !self.arrivals.is_empty() {
            filed.extend(self.write_oldest(now));
        }
        filed
    }

    fn write_oldest(&mut self, now: u64) -> Option<Filed> {
        let (_, key) = self.arrivals.pop_front()?;
        let held = self.held.remove(&key)?;
        self.held_bytes = self.held_bytes.saturating_sub(
            held_cost(&held.line, &key) + held.seconds.len() * std::mem::size_of::<u64>(),
        );
        let hash = self.hash(&key);
        self.written.insert(hash, now);
        self.written_order.push_back((now, hash));
        self.forget_written(now);
        let second = median(held.seconds);
        let line = acars::at_second(&held.line, second)
            .filter(|line| acars::line(line.as_bytes()).is_some());
        Some(match line {
            Some(line) => self.write(now, second, line.as_bytes()),
            None => Filed::Invalid,
        })
    }

    /// Writes one merged line into the day of `second`.
    fn write(&mut self, now: u64, second: u64, line: &[u8]) -> Filed {
        self.write_marks(now);
        let start = day_start(second);
        let path = day_path(start);
        if self.closed(start, now) {
            let dropped = self.closed_drops.entry(start).or_insert(0);
            if *dropped == 0 {
                eprintln!(
                    "tally-acars-collect: {path} is packed or being packed; its lines are dropped"
                );
            }
            *dropped += 1;
            self.sweep(now);
            return Filed::Closed;
        }
        let dir = self.history.join(&path);
        let day_max = self.day_max;
        let day = self.days.entry(start).or_insert(Day {
            file: None,
            written: 0,
            capped: false,
            failing_since: None,
        });
        if day.capped {
            return Filed::Capped;
        }
        let size = line.len() as u64 + 1;
        let written = match day.file.as_mut() {
            Some(file) => Ok(file),
            None => open(&dir).map(|(file, length)| {
                day.written = length;
                day.file.insert(file)
            }),
        }
        .and_then(|file| {
            if day.written.saturating_add(size) > day_max {
                return Ok(false);
            }
            let mut bytes = Vec::with_capacity(line.len() + 1);
            bytes.extend_from_slice(line);
            bytes.push(b'\n');
            file.write_all(&bytes).map(|()| true)
        });
        let filed = match written {
            Ok(true) => {
                day.written += size;
                if let Some(from) = day.failing_since.take() {
                    eprintln!("tally-acars-collect: {path}/{DAY_FILE} is written again");
                    self.mark(start, from, Some(now), "write", true, now);
                }
                Filed::Written
            }
            Ok(false) => {
                day.capped = true;
                eprintln!(
                    "tally-acars-collect: {path} reached its cap of {day_max} bytes; the rest of \
                     the day's lines are dropped"
                );
                self.mark(start, now, None, "cap", true, now);
                Filed::Capped
            }
            Err(error) => {
                // Reopened, and its length read again, at the next line.
                day.file = None;
                if day.failing_since.is_none() {
                    day.failing_since = Some(now);
                    eprintln!(
                        "tally-acars-collect: {path}/{DAY_FILE}: {error}; lines are dropped until \
                         it is written again"
                    );
                    self.mark(start, now, None, "write", true, now);
                }
                Filed::Failed
            }
        };
        self.sweep(now);
        filed
    }

    /// Lets go of each day whose packing may have begun, its file synced and closed, and says
    /// once the count of what a day long closed lost.
    fn sweep(&mut self, now: u64) {
        let closing: Vec<u64> = self
            .days
            .keys()
            .copied()
            .filter(|start| self.closed(*start, now))
            .collect();
        for start in closing {
            if let Some(Day {
                file: Some(file), ..
            }) = self.days.remove(&start)
                && let Err(error) = file.sync_data()
            {
                eprintln!(
                    "tally-acars-collect: {}/{DAY_FILE}: {error}",
                    day_path(start)
                );
            }
        }
        let past = day_start(now).saturating_sub(2 * DAY_SECS);
        let kept = self.closed_drops.split_off(&past);
        for (start, dropped) in std::mem::replace(&mut self.closed_drops, kept) {
            eprintln!(
                "tally-acars-collect: {dropped} lines for {}, packed or being packed, were dropped",
                day_path(start)
            );
        }
    }

    /// Whether every gap marked is written: until then, a day may yet be packed without one.
    pub fn marks_written(&self) -> bool {
        self.unwritten.is_empty()
    }

    /// Whether the day starting `start` is written no more at `now`: packed, or (but while the
    /// collector starts) past `WRITABLE_FOR`.
    fn closed(&self, start: u64, now: u64) -> bool {
        (!self.starting && now >= start + DAY_SECS + WRITABLE_FOR)
            || self
                .history
                .join(PACKED_DIR)
                .join(day_path(start).replace('/', "-"))
                .exists()
    }

    /// Starts at `now`: the relay was last read when `archive/.acars-read` says, or, if it says
    /// nothing, at the start of today, so a down gap is open from then over every day not
    /// packed. Run before the archiver, so a day it is about to pack learns what it missed.
    pub fn start(&mut self, now: u64) {
        let from = std::fs::read_to_string(self.history.join(READ_FILE))
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .unwrap_or(day_start(now))
            .min(now);
        self.starting = true;
        self.last_read = Some(from);
        self.persisted = Some((from, now));
        self.down_since(from, now);
        self.starting = false;
    }

    /// Connected to the relay at `now`: an open `down` gap closes.
    pub fn connected(&mut self, now: u64) {
        self.connected = true;
        self.read_at(now);
    }

    /// A line came at `now` (filed or not).
    pub fn received(&mut self, now: u64) {
        self.read_at(now);
    }

    fn read_at(&mut self, now: u64) {
        self.last_read = Some(now);
        // Every day it touched knows of it, open, before it is closed.
        self.still_down(now);
        if let Some((from, _)) = self.down.take() {
            for day in days_arrived(from, now) {
                self.mark(day, from, Some(now), "down", false, now);
            }
        }
    }

    /// The relay has not been read since `from` (unless a gap is open already), as at `now`:
    /// every day a message arriving since may be filed in is marked, open.
    pub fn down_since(&mut self, from: u64, now: u64) {
        if self.down.is_none() {
            let first = day_start(from.saturating_sub(MAX_SKEW));
            self.down = Some((from, first));
            self.mark(first, from, None, "down", false, now);
        }
        self.still_down(now);
    }

    /// The connection ended at `now`: the relay was last read at the last line it gave, or when
    /// it connected.
    pub fn disconnected(&mut self, now: u64) {
        self.connected = false;
        self.down_since(self.last_read.unwrap_or(now).min(now), now);
    }

    /// Still down at `now`: a day begun since it was last marked is marked, open.
    fn still_down(&mut self, now: u64) {
        let Some((from, marked)) = self.down.as_mut() else {
            return;
        };
        let from = *from;
        let mut days = Vec::new();
        while *marked + DAY_SECS <= now.saturating_add(MAX_SKEW) {
            *marked += DAY_SECS;
            days.push(*marked);
        }
        for day in days {
            self.mark(day, from, None, "down", false, now);
        }
    }

    /// What happens about once a second: held messages past their window are written, a day
    /// begun while down is marked, and the last read time (or the oldest held message's arrival,
    /// if earlier) is kept on the volume once a minute.
    pub fn tick(&mut self, now: u64) -> Vec<Filed> {
        if self.connected {
            self.last_read = Some(now);
        }
        let filed = self.flush_due(now);
        self.still_down(now);
        self.write_marks(now);
        self.sweep(now);
        // A message held is lost if the collector dies before it is written, so the time kept is
        // never past the oldest held one's arrival: a restart's gap covers it.
        let oldest = self.arrivals.front().map(|(arrived, _)| *arrived);
        let kept = self
            .last_read
            .map(|last| oldest.map_or(last, |oldest| oldest.min(last)));
        if let Some(last) = kept
            && self
                .persisted
                .is_none_or(|(kept, at)| kept != last && now.saturating_sub(at) >= PERSIST_EVERY)
        {
            self.persist(last, now);
        }
        filed
    }

    /// Stopping at `now`: what is held is written, the relay counts as read until now if it was
    /// connected, that time is kept, and the down gap from it is written, open.
    pub fn stop(&mut self, now: u64, connected: bool) {
        self.flush(now);
        self.close_gap("full", now);
        self.close_gap("skew", now);
        if connected {
            self.read_at(now);
        }
        let last = self.last_read.unwrap_or(now).min(now);
        self.persist(last, now);
        self.down_since(last, now);
        self.write_marks(now);
        for (start, day) in &self.days {
            if let Some(file) = &day.file
                && let Err(error) = file.sync_data()
            {
                eprintln!(
                    "tally-acars-collect: {}/{DAY_FILE}: {error}",
                    day_path(*start)
                );
            }
        }
    }

    /// Keeps `last` on the volume: written whole under another name, synced, renamed over the
    /// last, and the rename synced.
    fn persist(&mut self, last: u64, now: u64) {
        let path = self.history.join(READ_FILE);
        let temporary = path.with_extension("tmp");
        let dir = path.parent().unwrap_or(&self.history);
        let written = std::fs::create_dir_all(dir)
            .and_then(|()| {
                let mut file = File::create(&temporary)?;
                file.write_all(format!("{last}\n").as_bytes())?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&temporary, &path))
            .and_then(|()| File::open(dir)?.sync_all());
        match written {
            Ok(()) => self.persisted = Some((last, now)),
            Err(error) => eprintln!("tally-acars-collect: {READ_FILE}: {error}"),
        }
    }

    /// Marks the day starting `day` with a gap. A `down` gap makes no past day's directory: a day
    /// gone from the volume (archived and deleted) is not made again for it.
    fn mark(&mut self, day: u64, from: u64, to: Option<u64>, why: &str, create: bool, now: u64) {
        let to = to.map_or_else(|| "-".to_owned(), |to| to.to_string());
        self.unwritten.push(Mark {
            day,
            line: format!("{from} {to} {why}\n"),
            create: create || day >= day_start(now),
        });
        self.write_marks(now);
    }

    fn write_marks(&mut self, now: u64) {
        let unwritten = std::mem::take(&mut self.unwritten);
        for mark in unwritten {
            // A day packed, or being packed, takes nothing more.
            if self.closed(mark.day, now) {
                continue;
            }
            let dir = self.history.join(day_path(mark.day));
            if !mark.create && !dir.is_dir() {
                continue;
            }
            let gaps = dir.join(GAPS_FILE);
            // A gap opened again (a restart, from the time the last run kept) is there once.
            if mark.line.contains(" - ")
                && std::fs::read_to_string(&gaps).is_ok_and(|text| text.contains(&mark.line))
            {
                continue;
            }
            // A mark is rare, and the one record of what the day lost: it is synced.
            let written = std::fs::create_dir_all(&dir).and_then(|()| {
                let mut file = OpenOptions::new().create(true).append(true).open(&gaps)?;
                file.write_all(mark.line.as_bytes())?;
                file.sync_data()
            });
            if let Err(error) = written {
                eprintln!(
                    "tally-acars-collect: {}/{GAPS_FILE}: {error}; retried",
                    day_path(mark.day)
                );
                self.unwritten.push(mark);
            }
        }
    }

    /// Takes every line `reader` gives until it ends or `stop` says so, each at the time `now`
    /// reads when it arrives, ticking after each, and on a read that waits ([`READ_TICK`]). A line
    /// longer than the wire's cap is skipped whole. Returns how many lines came.
    pub fn session(
        &mut self,
        reader: impl BufRead,
        now: &dyn Fn() -> u64,
        stop: &dyn Fn() -> bool,
    ) -> io::Result<u64> {
        let mut lines = BoundedLines::new(reader, acars::MAX_LINE);
        let mut count = 0;
        loop {
            match lines.next_line() {
                Ok(Some(line)) => {
                    count += 1;
                    let at = now();
                    self.received(at);
                    if let Some(line) = line {
                        self.take(at, line);
                    }
                    // A relay that never pauses still has its held lines written and its read
                    // time kept.
                    self.tick(at);
                }
                Ok(None) => return Ok(count),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    self.tick(now());
                }
                Err(error) => return Err(error),
            }
            if stop() {
                return Ok(count);
            }
        }
    }
}

/// What holding one message takes beside its copies' seconds.
fn held_cost(line: &str, key: &str) -> usize {
    line.len() + 2 * key.len() + PENDING_OVERHEAD
}

/// The median of `seconds` (at least one): the middle one, or with an even count the floor of the
/// mean of the middle two.
fn median(mut seconds: Vec<u64>) -> u64 {
    seconds.sort_unstable();
    let middle = seconds.len() / 2;
    if seconds.len() % 2 == 1 {
        seconds[middle]
    } else {
        let (low, high) = (seconds[middle - 1], seconds[middle]);
        low + (high - low) / 2
    }
}

/// `dir`'s day file, made with its directory if missing, open to append, and its length: a last
/// line with no newline (a write cut short) is cut off first.
fn open(dir: &Path) -> io::Result<(File, u64)> {
    std::fs::create_dir_all(dir)?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(dir.join(DAY_FILE))?;
    let length = file.metadata()?.len();
    let whole = whole_lines(&mut file, length)?;
    if whole < length {
        eprintln!(
            "tally-acars-collect: {}/{DAY_FILE} ended in {} bytes of a line cut short; cut off",
            dir.display(),
            length - whole
        );
        file.set_len(whole)?;
    }
    Ok((file, whole))
}

/// Where `file`'s last newline ends: the length of its whole lines.
fn whole_lines(file: &mut File, length: u64) -> io::Result<u64> {
    let mut buffer = [0u8; 4096];
    let mut end = length;
    while end > 0 {
        let start = end.saturating_sub(buffer.len() as u64);
        let count = usize::try_from(end - start).unwrap_or(buffer.len());
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut buffer[..count])?;
        if let Some(at) = buffer[..count].iter().rposition(|byte| *byte == b'\n') {
            return Ok(start + at as u64 + 1);
        }
        end = start;
    }
    Ok(0)
}

/// Lines of at most `max` bytes from a buffered reader, holding no more than that of one: a line
/// past it is read through to its newline and given as `None`. A read that fails (a timeout)
/// keeps what it has of the line, so the next read goes on with it.
struct BoundedLines<R> {
    reader: R,
    max: usize,
    line: Vec<u8>,
    overlong: bool,
    ended: bool,
}

impl<R: BufRead> BoundedLines<R> {
    fn new(reader: R, max: usize) -> Self {
        Self {
            reader,
            max,
            line: Vec::new(),
            overlong: false,
            ended: false,
        }
    }

    /// The next line (`Some(None)` if it was too long), or `None` at the end. A last line with no
    /// newline is cut off, not a line.
    fn next_line(&mut self) -> io::Result<Option<Option<&[u8]>>> {
        if self.ended {
            self.line.clear();
            self.overlong = false;
            self.ended = false;
        }
        loop {
            let buffer = self.reader.fill_buf()?;
            if buffer.is_empty() {
                return Ok(None);
            }
            let (part, ended) = match buffer.iter().position(|byte| *byte == b'\n') {
                Some(at) => (&buffer[..at], at + 1),
                None => (buffer, 0),
            };
            if !self.overlong && self.line.len() + part.len() <= self.max {
                self.line.extend_from_slice(part);
            } else {
                self.overlong = true;
                self.line.clear();
            }
            let consumed = if ended > 0 { ended } else { part.len() };
            self.reader.consume(consumed);
            if ended > 0 {
                self.ended = true;
                return Ok(Some((!self.overlong).then_some(self.line.as_slice())));
            }
        }
    }
}

/// Whether SIGTERM or SIGINT came (`os::catch_stop`).
fn stopping() -> bool {
    os::stopping()
}

/// SIGTERM and SIGINT mark the collector stopping, without `SA_RESTART`, so a read waiting on
/// the relay returns at once.
fn catch_stop() -> io::Result<()> {
    os::catch_stop()
}

/// Reads `from` (the relay's `--acars-out`) into `collector` until SIGTERM, redialling while it is
/// down and marking what each day missed. Before anything, it marks what was missed since the
/// last run ([`Collector::start`]) and then creates `ready`, which the entrypoint waits for before
/// it starts the archiver.
pub fn run(from: &str, collector: &mut Collector, ready: Option<&Path>) -> io::Result<()> {
    catch_stop()?;
    collector.start(now());
    // Ready once what it missed is written down, so the archiver packs no day without it.
    let mut said = false;
    while !collector.marks_written() && !stopping() {
        if !said {
            eprintln!("tally-acars-collect: the gaps missed while stopped are not written yet");
            said = true;
        }
        std::thread::sleep(Duration::from_secs(1));
        collector.tick(now());
    }
    if let Some(ready) = ready {
        File::create(ready)?;
    }
    let mut backoff = Backoff::new();
    while !stopping() {
        match connect(from) {
            Ok(stream) => {
                stream.set_read_timeout(Some(READ_TICK))?;
                collector.connected(now());
                eprintln!("tally-acars-collect: reading {from}");
                let read = collector.session(BufReader::new(stream), &now, &stopping);
                if stopping() {
                    collector.stop(now(), true);
                    return Ok(());
                }
                collector.disconnected(now());
                match read {
                    // Only a connection that gave lines worked: one that accepts and closes keeps
                    // backing off.
                    Ok(lines) if lines > 0 => {
                        backoff.reset();
                        eprintln!("tally-acars-collect: {from} closed after {lines} lines");
                    }
                    Ok(_) => eprintln!("tally-acars-collect: {from} closed"),
                    Err(error) => eprintln!("tally-acars-collect: {from}: {error}"),
                }
            }
            Err(error) => eprintln!("tally-acars-collect: {from}: {error}"),
        }
        let until = Instant::now() + backoff.wait();
        while Instant::now() < until && !stopping() {
            std::thread::sleep(Duration::from_millis(100));
            collector.tick(now());
        }
    }
    collector.stop(now(), false);
    Ok(())
}

/// Whether `from` is `HOST:PORT` or `[IPV6]:PORT`, its port 1 to 65535: refused as the collector
/// starts, not found wrong at every connection.
pub fn check_address(from: &str) -> Result<(), String> {
    let refused = || format!("--from {from} is not HOST:PORT");
    let (host, port) = from.rsplit_once(':').ok_or_else(refused)?;
    // An IPv6 address is bracketed, so its colons are not the port's.
    let host = match host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        Some(address) => address,
        None if host.contains(':') => return Err(refused()),
        None => host,
    };
    let port = port.parse::<u16>().map_err(|_| refused())?;
    if host.is_empty() || host.contains(['[', ']']) || port == 0 {
        return Err(refused());
    }
    Ok(())
}

/// `from`'s addresses, looked up within [`CONNECT_TIMEOUT`]: the system's resolver takes no
/// deadline, so it is asked on a thread of its own, which ends when the resolver gives up.
fn resolve(from: &str) -> io::Result<Vec<SocketAddr>> {
    let (send, answer) = std::sync::mpsc::channel();
    let name = from.to_owned();
    std::thread::spawn(move || {
        let _ = send.send(name.to_socket_addrs().map(Iterator::collect));
    });
    answer.recv_timeout(CONNECT_TIMEOUT).map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "looking up {from} took over {} s",
                CONNECT_TIMEOUT.as_secs()
            ),
        )
    })?
}

fn connect(from: &str) -> io::Result<TcpStream> {
    let mut last = io::Error::other(format!("{from} names no address"));
    for address in resolve(from)? {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                keepalive(&stream)?;
                return Ok(stream);
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// Probes after a minute idle, every 10 s, 6 times: a relay gone is noticed within two minutes,
/// though a quiet one sends nothing for hours.
fn keepalive(stream: &TcpStream) -> io::Result<()> {
    os::set_int(stream, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    #[cfg(target_os = "linux")]
    {
        os::set_int(stream, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 60)?;
        os::set_int(stream, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 10)?;
        os::set_int(stream, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 6)?;
    }
    Ok(())
}

/// What a sort dropped: lines the wire does not take, and copies of a message written in the
/// [`MAX_SKEW`] before them (a message written twice, as a restart can: what the collector wrote
/// before is gone with it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sorted {
    pub dropped: u64,
    pub repeated: u64,
}

/// Sorts a day's file in place by each message's own time (`acars::time_us`), then by its bytes,
/// so the order says nothing of which receiver sent what together. Only lines the wire takes
/// (`acars::line`) are kept, each message once in any [`MAX_SKEW`] (its earliest line, as the
/// collector drops a late copy); what else is dropped is counted ([`Sorted`]). An external
/// merge:
/// runs of at most [`RUN_BYTES`] sorted and written to `scratch` (on the same volume, and served
/// by nothing), merged [`MERGE_WAYS`] at a time, and the result renamed over the day's file and
/// its directory synced, so the file is whole whatever happens and the sort holds at most
/// [`SORT_MEMORY`]. `scratch` is emptied first and removed after.
pub fn sort_day(path: &Path, scratch: &Path) -> io::Result<Sorted> {
    sort_with(path, scratch, RUN_BYTES, MERGE_WAYS)
}

type Keyed = (u64, Vec<u8>);

fn keyed(line: &[u8]) -> Keyed {
    let time = std::str::from_utf8(line)
        .ok()
        .and_then(acars::time_us)
        .unwrap_or(u64::MAX);
    (time, line.to_vec())
}

fn sort_with(path: &Path, scratch: &Path, run_bytes: usize, ways: usize) -> io::Result<Sorted> {
    match std::fs::remove_dir_all(scratch) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    std::fs::create_dir_all(scratch)?;
    let mut made = 0usize;
    let mut next_run = |scratch: &Path| {
        made += 1;
        scratch.join(format!("run-{made}"))
    };
    let mut runs = Vec::new();
    let mut lines = BoundedLines::new(
        BufReader::with_capacity(MERGE_BUFFER, File::open(path)?),
        acars::MAX_LINE,
    );
    let mut run: Vec<Keyed> = Vec::new();
    let mut held = 0;
    let mut sorted = Sorted::default();
    loop {
        let line = lines.next_line()?;
        let ended = line.is_none();
        match line {
            Some(Some(line)) if acars::line(line).is_some() => {
                held += line.len() + LINE_OVERHEAD;
                run.push(keyed(line));
            }
            Some(Some([])) | None => {}
            Some(_) => sorted.dropped += 1,
        }
        if (ended && !run.is_empty()) || held >= run_bytes {
            run.sort_unstable();
            let name = next_run(scratch);
            sorted.repeated += write_lines(&name, run.drain(..).map(|(_, line)| line))?;
            runs.push(name);
            held = 0;
        }
        if ended {
            break;
        }
    }
    if runs.is_empty() {
        let name = next_run(scratch);
        write_lines(&name, std::iter::empty())?;
        runs.push(name);
    }
    while runs.len() > 1 {
        let mut merged = Vec::new();
        for group in runs.chunks(ways.max(2)) {
            let name = next_run(scratch);
            sorted.repeated += merge(group, &name)?;
            for done in group {
                std::fs::remove_file(done)?;
            }
            merged.push(name);
        }
        runs = merged;
    }
    std::fs::rename(&runs[0], path)?;
    // A bare file name's directory is the working one.
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()?;
    std::fs::remove_dir_all(scratch)?;
    Ok(sorted)
}

/// Writes sorted `lines` to `name`, each message once: how many were copies.
fn write_lines(name: &Path, lines: impl Iterator<Item = Vec<u8>>) -> io::Result<u64> {
    let mut out = Unrepeated::new(name)?;
    for line in lines {
        out.write(&line)?;
    }
    out.done()
}

/// A sorted file being written, each message once: a line whose copy key (`acars::copy_key`) was
/// written in the [`MAX_SKEW`] of message time before it is dropped, the rule the collector keeps
/// with as many keys.
struct Unrepeated {
    out: BufWriter<File>,
    hasher: RandomState,
    /// The hashes of the keys written in the last [`MAX_SKEW`], with their second, oldest first.
    written: HashMap<u64, u64>,
    written_order: VecDeque<(u64, u64)>,
    repeated: u64,
}

impl Unrepeated {
    fn new(name: &Path) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::with_capacity(MERGE_BUFFER, File::create(name)?),
            hasher: RandomState::new(),
            written: HashMap::new(),
            written_order: VecDeque::new(),
            repeated: 0,
        })
    }

    /// Writes `line`, given in order of message time, unless its message was written in the
    /// [`MAX_SKEW`] before.
    fn write(&mut self, line: &[u8]) -> io::Result<()> {
        let text = std::str::from_utf8(line).ok();
        if let (Some(key), Some(second)) =
            (text.and_then(acars::copy_key), text.and_then(acars::second))
        {
            while let Some((at, hash)) = self.written_order.front().copied() {
                if at + MAX_SKEW >= second && self.written_order.len() < WRITTEN_KEYS {
                    break;
                }
                self.written_order.pop_front();
                if self.written.get(&hash) == Some(&at) {
                    self.written.remove(&hash);
                }
            }
            let hash = self.hasher.hash_one(&key);
            if self.written.contains_key(&hash) {
                self.repeated += 1;
                return Ok(());
            }
            self.written.insert(hash, second);
            self.written_order.push_back((second, hash));
        }
        self.out.write_all(line)?;
        self.out.write_all(b"\n")?;
        Ok(())
    }

    fn done(self) -> io::Result<u64> {
        self.out
            .into_inner()
            .map_err(|error| error.into_error())?
            .sync_all()?;
        Ok(self.repeated)
    }
}

/// Merges sorted runs into `name`, sorted, each message once: how many were copies.
fn merge(runs: &[PathBuf], name: &Path) -> io::Result<u64> {
    let mut readers = runs
        .iter()
        .map(|run| {
            Ok(BoundedLines::new(
                BufReader::with_capacity(MERGE_BUFFER, File::open(run)?),
                acars::MAX_LINE,
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut heap = BinaryHeap::new();
    for (at, reader) in readers.iter_mut().enumerate() {
        if let Some(line) = reader.next_line()?.flatten() {
            heap.push(Reverse((keyed(line), at)));
        }
    }
    let mut out = Unrepeated::new(name)?;
    while let Some(Reverse(((_, line), at))) = heap.pop() {
        out.write(&line)?;
        if let Some(line) = readers[at].next_line()?.flatten() {
            heap.push(Reverse((keyed(line), at)));
        }
    }
    out.done()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A history directory of the test's own.
    fn history(name: &str) -> Result<PathBuf, String> {
        let base = std::env::var_os("TEST_TMPDIR")
            .map_or_else(std::env::temp_dir, PathBuf::from)
            .join(format!("tally-acars-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).map_err(|error| error.to_string())?;
        Ok(base)
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    /// 2026-10-21 00:00:00 UTC.
    const DAY: u64 = 1_792_540_800;

    /// A message of its own `n`, timed `second`.
    fn message(n: u64, second: u64) -> String {
        format!(r#"{{"kind":"acars","label":"H1","t":{second},"text":"{n}"}}"#)
    }

    #[test]
    fn a_day_is_named_by_its_utc_date() {
        assert_eq!(day_path(0), "1970/01/01");
        assert_eq!(day_path(DAY), "2026/10/21");
        assert_eq!(day_path(DAY - 1), "2026/10/20");
        assert_eq!(day_path(951_782_400), "2000/02/29");
        assert_eq!(day_path(4_107_542_399), "2100/02/28");
    }

    #[test]
    fn a_days_cap_is_counted_to_the_byte() -> Result<(), String> {
        let dir = history("cap")?;
        let size = message(0, DAY + 5).len() as u64 + 1;
        let mut collector = Collector::new(&dir, 3 * size);
        for n in 0..5 {
            assert_eq!(
                collector.line(DAY + 5, message(n, DAY + 5).as_bytes()),
                Filed::Held
            );
        }
        // Exactly full: the next is over, and so is the rest of the day, however small.
        assert_eq!(
            collector.flush(DAY + 6),
            [
                Filed::Written,
                Filed::Written,
                Filed::Written,
                Filed::Capped,
                Filed::Capped
            ]
        );
        let today = dir.join("2026/10/21");
        assert_eq!(read(&today.join(DAY_FILE)).len() as u64, 3 * size);
        assert_eq!(read(&today.join(GAPS_FILE)), format!("{} - cap\n", DAY + 6));
        // A restart counts what the day's file already holds.
        let mut again = Collector::new(&dir, 3 * size);
        again.line(DAY + 9, message(9, DAY + 9).as_bytes());
        assert_eq!(again.flush(DAY + 9), [Filed::Capped]);
        // What is not one published message is never taken.
        for invalid in [
            br#"{"kind":"acars","label":"H1","t":1}{"kind":"acars","label":"H1","t":1}"#.as_slice(),
            b"[1]",
            br#"{"kind":"acars","label":"H1","level":-20,"t":1}"#,
            br#"{"kind":"acars","label":"H1","t":1.5}"#,
        ] {
            assert_eq!(again.line(DAY + DAY_SECS, invalid), Filed::Invalid);
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Copies of one message from several receivers, within the window, are one line timed at the
    /// median of their seconds; a copy after it is written is dropped, for as long as a copy can
    /// come; another message is a line of its own.
    #[test]
    fn copies_are_merged_and_timed_at_their_median() -> Result<(), String> {
        let dir = history("merge-copies")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let copy = |second: u64| {
            format!(r#"{{"icao":"A1B2C3","kind":"vdl2","label":"H1","t":{second},"text":"HI"}}"#)
        };
        let at = DAY + 1_000;
        assert_eq!(collector.line(at, copy(at).as_bytes()), Filed::Held);
        // A slow clock and two fast ones.
        for (arrived, second) in [(at + 2, at - 40), (at + 3, at + 3), (at + 4, at + 9)] {
            assert_eq!(
                collector.line(arrived, copy(second).as_bytes()),
                Filed::Merged
            );
        }
        assert_eq!(
            collector.line(at + 5, message(1, at).as_bytes()),
            Filed::Held
        );
        // Nothing is written inside the window.
        assert!(collector.tick(at + MERGE_WINDOW - 1).is_empty());
        assert_eq!(collector.tick(at + MERGE_WINDOW), [Filed::Written]);
        // A copy after it: dropped, while a copy of it could still come.
        assert_eq!(
            collector.line(at + MERGE_WINDOW + 1, copy(at).as_bytes()),
            Filed::Late
        );
        assert_eq!(
            collector.line(at + 200, copy(at + 100).as_bytes()),
            Filed::Late
        );
        collector.flush(at + 200);
        // Long after, the same text is another message.
        let later = at + MERGE_WINDOW + MAX_SKEW + 10;
        assert_eq!(collector.line(later, copy(later).as_bytes()), Filed::Held);
        collector.flush(later);
        // Of at - 40, at, at + 3 and at + 9: the floor of the mean of at and at + 3, neither the
        // first copy's second nor the earliest.
        let median = at + 1;
        assert_eq!(
            read(&dir.join("2026/10/21").join(DAY_FILE)),
            format!("{}\n{}\n{}\n", copy(median), message(1, at), copy(later))
        );
        assert_eq!(super::median(vec![5, 1, 3]), 3);
        assert_eq!(super::median(vec![4, 1]), 2);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// While the held messages fill their room, a new one is dropped and its day's `full` gap
    /// opened, never a held one written before its copies are in; the gap closes at the next one
    /// held.
    #[test]
    fn a_message_with_no_room_to_be_held_is_dropped_as_a_gap() -> Result<(), String> {
        let dir = history("full")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let big = |n: u64| {
            format!(
                r#"{{"kind":"acars","label":"H1","t":{},"text":"{n}{}"}}"#,
                DAY + 10,
                "x".repeat(16_000)
            )
        };
        let mut held = 0;
        let full_at = loop {
            match collector.line(DAY + 10, big(held).as_bytes()) {
                Filed::Held => held += 1,
                Filed::Full => break DAY + 10,
                other => return Err(format!("{other:?}")),
            }
        };
        assert!(held > 100, "{held}");
        assert!(collector.held_bytes <= PENDING_BYTES);
        assert_eq!(
            collector.line(DAY + 11, big(held + 1).as_bytes()),
            Filed::Full
        );
        let gaps = dir.join("2026/10/21").join(GAPS_FILE);
        assert_eq!(read(&gaps), format!("{full_at} - full\n"));
        // Nothing held was written early.
        assert!(!dir.join("2026/10/21").join(DAY_FILE).exists());
        let written = collector.tick(DAY + 10 + MERGE_WINDOW);
        assert_eq!(written.len(), held as usize);
        let back = DAY + 10 + MERGE_WINDOW;
        assert_eq!(
            collector.line(back, message(1, back).as_bytes()),
            Filed::Held
        );
        assert_eq!(
            read(&gaps),
            format!("{full_at} - full\n{full_at} {back} full\n")
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A message goes to the day of its own time, not of its arrival; one whose time is too far
    /// from its arrival is dropped, as a `skew` gap in every day such a message may be filed in,
    /// closed at the next that is not.
    #[test]
    fn a_message_is_filed_by_its_own_time() -> Result<(), String> {
        let dir = history("by-time")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let arrival = DAY + DAY_SECS + 10;
        collector.line(arrival, message(1, DAY + DAY_SECS - 5).as_bytes());
        collector.line(arrival, message(2, DAY + DAY_SECS + 3).as_bytes());
        assert_eq!(
            collector.line(arrival, message(3, arrival - MAX_SKEW - 1).as_bytes()),
            Filed::Skewed
        );
        assert_eq!(
            collector.line(arrival, message(4, arrival + MAX_SKEW + 1).as_bytes()),
            Filed::Skewed
        );
        let back = arrival + 1;
        collector.line(back, message(5, back).as_bytes());
        collector.flush(back);
        assert_eq!(
            read(&dir.join("2026/10/21").join(DAY_FILE)),
            message(1, DAY + DAY_SECS - 5) + "\n"
        );
        assert_eq!(
            read(&dir.join("2026/10/22").join(DAY_FILE)),
            message(2, DAY + DAY_SECS + 3) + "\n" + &message(5, back) + "\n"
        );
        for day in ["2026/10/21", "2026/10/22"] {
            assert_eq!(
                read(&dir.join(day).join(GAPS_FILE)),
                format!("{arrival} - skew\n{arrival} {back} skew\n"),
                "{day}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A day whose file cannot be made drops its lines until it can, as one `write` gap, opened at
    /// the first failure and closed at the next line written; the day is checked on every line,
    /// never assumed.
    #[test]
    fn a_day_that_cannot_be_written_drops_lines_as_one_gap() -> Result<(), String> {
        let dir = history("fail")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        // Tomorrow's directory is a file: nothing can be opened under it.
        std::fs::create_dir_all(dir.join("2026/10")).map_err(text)?;
        std::fs::write(dir.join("2026/10/22"), b"").map_err(text)?;
        let first = DAY + DAY_SECS + 1;
        for n in 0..5 {
            collector.line(first + n, message(n, first + n).as_bytes());
            assert_eq!(collector.flush(first + n), [Filed::Failed]);
        }
        std::fs::remove_file(dir.join("2026/10/22")).map_err(text)?;
        for n in 10..12 {
            collector.line(first + n, message(n, first + n).as_bytes());
            assert_eq!(collector.flush(first + n), [Filed::Written]);
        }
        let tomorrow = dir.join("2026/10/22");
        assert_eq!(read(&tomorrow.join(DAY_FILE)).lines().count(), 2);
        // The open mark had nowhere to go until the day could hold it.
        assert_eq!(
            read(&tomorrow.join(GAPS_FILE)),
            format!("{first} - write\n{first} {} write\n", first + 10)
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A line a crash cut short is cut off when the day is next opened; the lines before it stay.
    #[test]
    fn a_line_cut_short_is_cut_off() -> Result<(), String> {
        let dir = history("torn")?;
        let today = dir.join("2026/10/21");
        std::fs::create_dir_all(&today).map_err(text)?;
        let whole = message(1, DAY + 1) + "\n";
        std::fs::write(today.join(DAY_FILE), whole.clone() + r#"{"text":"2","time"#)
            .map_err(text)?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        collector.line(DAY + 3, message(3, DAY + 3).as_bytes());
        assert_eq!(collector.flush(DAY + 3), [Filed::Written]);
        assert_eq!(
            read(&today.join(DAY_FILE)),
            whole + &message(3, DAY + 3) + "\n"
        );
        // A file with no whole line at all is emptied.
        let tomorrow = dir.join("2026/10/22");
        std::fs::create_dir_all(&tomorrow).map_err(text)?;
        std::fs::write(tomorrow.join(DAY_FILE), "x".repeat(10_000)).map_err(text)?;
        collector.line(DAY + DAY_SECS, message(4, DAY + DAY_SECS).as_bytes());
        collector.flush(DAY + DAY_SECS);
        assert_eq!(
            read(&tomorrow.join(DAY_FILE)),
            message(4, DAY + DAY_SECS) + "\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A `down` gap runs from the last time the relay was read to the next connection, and is
    /// written to every day it touches: open as each begins, closed once it ends.
    #[test]
    fn a_down_gap_runs_from_the_last_read_to_the_next_connection() -> Result<(), String> {
        let dir = history("gap")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let last = DAY + 100;
        collector.connected(DAY + 50);
        collector.received(last);
        // The connection is seen to end later; the gap is from its last line.
        collector.disconnected(last + 60);
        collector.tick(DAY + DAY_SECS + 5);
        collector.tick(DAY + DAY_SECS + 9);
        // Back before 10/21 may be packed (01:10 the next day): both days learn the gap's end.
        let back = DAY + DAY_SECS + 3_000;
        collector.connected(back);
        for day in ["2026/10/21", "2026/10/22"] {
            assert_eq!(
                read(&dir.join(day).join(GAPS_FILE)),
                format!("{last} - down\n{last} {back} down\n"),
                "{day}"
            );
        }
        assert!(!dir.join("2026/10/23").exists());
        // A connection that gave nothing: the gap is from when it connected.
        collector.disconnected(back + 30);
        collector.connected(back + 100);
        assert!(
            read(&dir.join("2026/10/22").join(GAPS_FILE))
                .ends_with(&format!("{back} - down\n{back} {} down\n", back + 100))
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Just past midnight, a gap is the day before's too: a message arriving in it may be timed
    /// before midnight. The relay down 00:01 to 00:20, and a collector that died at 00:00:39
    /// holding a message timed 23:59:55, each mark both days.
    #[test]
    fn a_gap_past_midnight_is_the_day_befores_too() -> Result<(), String> {
        let dir = history("midnight")?;
        // The day before is on the volume, as readsb's history makes it.
        let before = dir.join("2026/10/20");
        std::fs::create_dir_all(&before).map_err(text)?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        collector.connected(DAY - 200);
        collector.tick(DAY - 130);
        collector.line(DAY + 10, message(1, DAY - 5).as_bytes());
        collector.tick(DAY + 39);
        assert_eq!(read(&dir.join(READ_FILE)), format!("{}\n", DAY + 10));
        // It dies at 00:00:39, the message unwritten; the next run is back at 00:01:00.
        drop(collector);
        let back = DAY + 60;
        let mut next = Collector::new(&dir, DEFAULT_DAY_MAX);
        next.start(back);
        next.connected(back);
        let crash = format!("{0} - down\n{0} {back} down\n", DAY + 10);
        for day in [&before, &dir.join("2026/10/21")] {
            assert_eq!(read(&day.join(GAPS_FILE)), crash, "{}", day.display());
        }
        // The relay is down from 00:01 to 00:20.
        next.disconnected(back);
        let up = DAY + 1_200;
        next.tick(up - 1);
        next.connected(up);
        let down = format!("{back} - down\n{back} {up} down\n");
        for day in [&before, &dir.join("2026/10/21")] {
            assert_eq!(
                read(&day.join(GAPS_FILE)),
                crash.clone() + &down,
                "{}",
                day.display()
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// The last read time outlives the collector: kept about once a minute and as it stops, and
    /// a start opens the gap from it over every day still on the volume and not packed, closed
    /// on connecting.
    #[test]
    fn a_restart_marks_what_was_missed_since_the_last_read() -> Result<(), String> {
        let dir = history("restart")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let start = DAY - 2 * DAY_SECS + 7_000;
        collector.start(start);
        collector.connected(start + 5);
        collector.received(start + 20);
        collector.tick(start + 30);
        // Not yet a minute since it started.
        assert!(!dir.join(READ_FILE).exists());
        // Connected, every tick is a read of the relay, though no line came; but a message held
        // and not yet written would be lost with the collector, so the time kept is its arrival.
        collector.line(start + 70, message(1, start + 70).as_bytes());
        collector.tick(start + 80);
        assert_eq!(read(&dir.join(READ_FILE)), format!("{}\n", start + 70));
        collector.tick(start + 140);
        assert_eq!(read(&dir.join(READ_FILE)), format!("{}\n", start + 140));
        // Stopped later: read until then, kept, and its gap written open.
        let stopped = DAY - DAY_SECS + 3_000;
        collector.stop(stopped, true);
        assert_eq!(read(&dir.join(READ_FILE)), format!("{stopped}\n"));
        assert!(
            read(&dir.join("2026/10/20").join(GAPS_FILE)).ends_with(&format!("{stopped} - down\n"))
        );

        // The next run starts a day later. 10/20 is still on the volume, past its time to be
        // written but not packed: it learns the rest of its gap. 10/19 is packed: nothing.
        std::fs::create_dir_all(dir.join(PACKED_DIR)).map_err(text)?;
        std::fs::write(dir.join(PACKED_DIR).join("2026-10-19"), b"").map_err(text)?;
        let gaps_19 = read(&dir.join("2026/10/19").join(GAPS_FILE));
        let mut next = Collector::new(&dir, DEFAULT_DAY_MAX);
        let restart = DAY + 9_000;
        next.start(restart);
        next.connected(restart + 2);
        assert_eq!(
            read(&dir.join("2026/10/20").join(GAPS_FILE))
                .matches(&format!("{stopped} - down\n"))
                .count(),
            1
        );
        // Once started, a day past its time is closed again: the gap's end is not written there.
        assert!(
            !read(&dir.join("2026/10/20").join(GAPS_FILE))
                .contains(&format!("{stopped} {} down", restart + 2))
        );
        assert_eq!(
            read(&dir.join("2026/10/21").join(GAPS_FILE)),
            format!("{stopped} - down\n{stopped} {} down\n", restart + 2)
        );
        assert_eq!(read(&dir.join("2026/10/19").join(GAPS_FILE)), gaps_19);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// A day the archiver packed, or may be packing, is never written again: its lines are
    /// dropped and counted, and a gap closing over a day gone from the volume makes nothing.
    #[test]
    fn a_closed_day_is_never_reopened() -> Result<(), String> {
        let dir = history("packed")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        collector.down_since(DAY - 2 * DAY_SECS, DAY - 2 * DAY_SECS + 5);
        std::fs::create_dir_all(dir.join(PACKED_DIR)).map_err(text)?;
        std::fs::write(dir.join(PACKED_DIR).join("2026-10-20"), b"").map_err(text)?;
        let packed = dir.join("2026/10/20");
        std::fs::create_dir_all(&packed).map_err(text)?;
        let gone = dir.join("2026/10/19");
        std::fs::remove_dir_all(&gone).map_err(text)?;
        collector.connected(DAY + 10);
        collector.line(DAY + 10, message(1, DAY - 10).as_bytes());
        assert_eq!(collector.flush(DAY + 10), [Filed::Closed]);
        assert!(!packed.join(DAY_FILE).exists());
        assert!(!packed.join(GAPS_FILE).exists());
        assert!(!gone.exists());
        // Not packed, but past 01:10 the next day: closed all the same.
        let late = DAY + DAY_SECS + WRITABLE_FOR;
        let arrived = DAY + DAY_SECS + 100;
        collector.line(arrived, message(2, DAY + DAY_SECS - 100).as_bytes());
        assert_eq!(collector.tick(late), [Filed::Closed]);
        collector.line(late, message(3, late).as_bytes());
        assert_eq!(collector.flush(late), [Filed::Written]);
        assert!(!dir.join("2026/10/21").join(DAY_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Lines split across reads are whole, an overlong one is skipped whole.
    #[test]
    fn a_session_takes_each_line_and_skips_an_overlong_one() -> Result<(), String> {
        let dir = history("session")?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let long = format!(
            r#"{{"kind":"acars","label":"H1","t":1,"text":"{}"}}"#,
            "x".repeat(acars::MAX_LINE)
        );
        let stream = format!(
            "{}\n{long}\n{}\n{{\"cut\":",
            message(1, DAY + 1),
            message(2, DAY + 2)
        );
        // A reader that hands over a few bytes at a time.
        let reader = BufReader::with_capacity(7, stream.as_bytes());
        let clock = Cell::new(DAY + 1);
        let tick = || {
            let now = clock.get();
            clock.set(now + 1);
            now
        };
        let lines = collector.session(reader, &tick, &|| false).map_err(text)?;
        assert_eq!(lines, 3);
        collector.flush(DAY + 10);
        assert_eq!(
            read(&dir.join("2026/10/21").join(DAY_FILE)),
            format!("{}\n{}\n", message(1, DAY + 1), message(2, DAY + 2))
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Over a socket, as from a relay that pauses mid-line past a read's wait: the line is whole.
    #[test]
    fn a_session_reads_a_relays_acars_out_across_its_pauses() -> Result<(), String> {
        use std::net::TcpListener;
        let dir = history("socket")?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(text)?;
        let address = listener.local_addr().map_err(text)?;
        let (one, two) = (message(1, DAY + 2), message(2, DAY + 1));
        let sent = format!("{one}\n{two}\n");
        let relay = std::thread::spawn(move || -> io::Result<()> {
            let (mut stream, _) = listener.accept()?;
            let (first, rest) = sent.split_at(one.len() + 8);
            stream.write_all(first.as_bytes())?;
            std::thread::sleep(Duration::from_millis(300));
            stream.write_all(rest.as_bytes())?;
            Ok(())
        });
        let stream = connect(&address.to_string()).map_err(text)?;
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(text)?;
        let mut collector = Collector::new(&dir, DEFAULT_DAY_MAX);
        let lines = collector
            .session(BufReader::new(stream), &|| DAY + 5, &|| false)
            .map_err(text)?;
        relay
            .join()
            .map_err(|_| "the relay panicked".to_owned())?
            .map_err(text)?;
        assert_eq!(lines, 2);
        collector.flush(DAY + 5);
        let file = dir.join("2026/10/21").join(DAY_FILE);
        assert_eq!(read(&file).lines().count(), 2);
        // Packed, the day is in its messages' order, whoever sent them.
        let scratch = dir.join(".sorting");
        assert_eq!(sort_day(&file, &scratch).map_err(text)?, Sorted::default());
        assert_eq!(
            read(&file),
            format!("{}\n{}\n", message(2, DAY + 1), message(1, DAY + 2))
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// `--from` is a host or an address and a port, or nothing starts.
    #[test]
    fn an_address_without_a_port_is_refused_at_start() {
        for good in ["127.0.0.1:30106", "relay:30106", "[::1]:30106"] {
            assert_eq!(check_address(good), Ok(()), "{good}");
        }
        for bad in [
            "127.0.0.1",
            "relay:",
            ":30106",
            "relay:0",
            "relay:65536",
            "relay:http",
            "[::1]",
            "::1:30106",
        ] {
            assert!(check_address(bad).is_err(), "{bad}");
        }
    }

    /// A day is sorted by message time, then bytes, keeping only published lines, and a message
    /// once in any [`MAX_SKEW`].
    #[test]
    fn a_day_is_sorted_by_message_time_then_bytes_and_keeps_only_published_lines()
    -> Result<(), String> {
        let dir = history("sort")?;
        let file = dir.join(DAY_FILE);
        let lines = [
            r#"{"kind":"vdl2","label":"H1","t":3,"text":"b"}"#,
            r#"{"kind":"vdl2","label":"H1","t":3,"text":"a"}"#,
            r#"{"kind":"acars","label":"H1","text":"no time"}"#,
            r#"{"kind":"acars","label":"H1","t":1,"text":"first"}"#,
            r#"{"kind":"hfdl","label":"_d","t":2}"#,
            r#"{"kind":"acars","label":"H1","level":-3,"t":1}"#,
            // Written again, as a restart can: at its second, and at another its later copies'
            // median gave; the earliest is kept. Past the window, the same text is another message.
            r#"{"kind":"vdl2","label":"H1","t":3,"text":"b"}"#,
            r#"{"kind":"vdl2","label":"H1","t":5,"text":"b"}"#,
            r#"{"kind":"vdl2","label":"H1","t":304,"text":"b"}"#,
        ];
        std::fs::write(&file, lines.join("\n") + "\n").map_err(text)?;
        let scratch = dir.join(".sorting");
        assert_eq!(
            sort_day(&file, &scratch).map_err(text)?,
            Sorted {
                dropped: 2,
                repeated: 2
            }
        );
        let sorted = [lines[3], lines[4], lines[1], lines[0], lines[8]];
        assert_eq!(read(&file), sorted.join("\n") + "\n");
        assert!(!scratch.exists());
        // An empty day stays an empty file.
        std::fs::write(&file, b"").map_err(text)?;
        sort_day(&file, &scratch).map_err(text)?;
        assert_eq!(read(&file), "");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Past one run, the day is sorted in runs and merged, in passes when there are more runs
    /// than one merge takes, to the same order as one sort in memory.
    #[test]
    fn a_day_past_one_run_is_merged_to_the_same_order() -> Result<(), String> {
        let dir = history("merge")?;
        let file = dir.join(DAY_FILE);
        let lines: Vec<String> = (0..500u64).map(|n| message(n, (n * 7_919) % 211)).collect();
        // Each line twice, in other runs: one of each is kept.
        let twice = [&lines[..], &lines[..]].concat();
        std::fs::write(&file, twice.join("\n") + "\n").map_err(text)?;
        let mut expected: Vec<Keyed> = lines.iter().map(|line| keyed(line.as_bytes())).collect();
        expected.sort_unstable();
        let expected: Vec<String> = expected
            .into_iter()
            .map(|(_, line)| String::from_utf8_lossy(&line).into_owned())
            .collect();
        // About 30 runs of 17 lines, merged 3 at a time: four passes.
        let scratch = dir.join(".sorting");
        std::fs::create_dir_all(scratch.join("left-over")).map_err(text)?;
        let sorted = sort_with(&file, &scratch, 17 * (30 + LINE_OVERHEAD), 3).map_err(text)?;
        assert_eq!(sorted.repeated, 500);
        assert_eq!(read(&file), expected.join("\n") + "\n");
        assert!(!scratch.exists());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
