//! Reading the receiver's own decoders and turning what they heard into signed batches (RFC-0171
//! §3.1, §3.5). Each decoder's port is read as one more client; nothing about readsb, dump978 or
//! the ACARS-family decoders is changed. Each source has its own reader, and every reader feeds
//! the one batcher that owns the chain.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tally_wire::backoff::Backoff;
use tally_wire::batch::Hash;
use tally_wire::beast::Decoder;
use tally_wire::noise;
use tally_wire::{
    Batch, BatchContent, Clock, Codec, EncodedBatch, Frame, Identity, Observation, Record,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};

use crate::health::Health;
use crate::lines::{self, Line, Lines};
use crate::{acars, uat};

/// How often a batch is sealed, at most (`tally_wire::budget::SEAL_PERIOD`).
const SEAL_EVERY: Duration = tally_wire::budget::SEAL_PERIOD.duration();
/// A batch is sealed early once its receptions reach this, well inside one Noise message.
const MAX_BATCH_BYTES: usize = 48 * 1024;
/// A signed batch as a record: the record's header (kind and length), the batch's fixed fields
/// (format, key, boot id, sequence, epoch, wall clock, dropped, previous hash, count), its anchors
/// at the most it carries (`tally_wire::batch::ANCHORS_MAX_LEN`) and its signature.
/// `a_batch_record_costs_its_overhead` checks it against the wire's own encoding.
pub const BATCH_OVERHEAD: usize =
    3 + (1 + 32 + 8 + 8 + 4 + 8 + 4 + 32 + 4) + tally_wire::batch::ANCHORS_MAX_LEN + 64;
/// The most one batch's receptions may come to: what makes the signed batch, as a record, exactly
/// one Noise message. The batcher never seals more, so no batch is ever too big to send.
const MAX_OBSERVATION_BYTES: usize = noise::MAX_PLAINTEXT - BATCH_OVERHEAD;
/// A free-running counter that runs backwards by more than a second of 12 MHz ticks means the
/// receiver's clock restarted, so later counters must not be compared with earlier ones.
const COUNTER_RESTART: u64 = 12_000_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Receptions waiting for the batcher. It only falls this far behind if the box is starved, and
/// then what does not fit is dropped and counted like anything over the ceiling.
const INPUT_BACKLOG: usize = 4096;

/// The kinds of batch a seal signs: the receptions (and what was dropped), and the ACARS-family
/// messages in a batch of their own (`Batcher::seal`).
pub const SEAL_KINDS: usize = 2;

/// The fewest receptions' bytes a batch sealed because it filled carries: one sealed as it
/// reached `MAX_BATCH_BYTES` (`Batcher::is_full`), or because the next reception, at most the
/// longest there is, would take it past `MAX_OBSERVATION_BYTES` (`push_paying`).
const FILLED_AT_LEAST: usize = if MAX_BATCH_BYTES < MAX_OBSERVATION_BYTES - LONGEST_ACARS {
    MAX_BATCH_BYTES
} else {
    MAX_OBSERVATION_BYTES - LONGEST_ACARS
};
const _: () = assert!(
    LONGEST_ACARS < MAX_OBSERVATION_BYTES && FILLED_AT_LEAST > 0,
    "a filled batch carries some bytes, so the ceiling bounds how many fill"
);

/// The most batches a batcher with upload ceiling `ceiling` (bytes a second) holds for an anchor
/// at once (`Batcher::pending`): one of each kind every seal (`SEAL_EVERY`) through the longest
/// it holds any (`tally_wire::budget::ANCHOR_WAIT`, and the seal that releases it), and one more
/// each time what it gathered filled a batch, which the ceiling bounds (its bucket holds a second
/// more at once). Past it the oldest is signed with no anchor, counted, never dropped
/// (`Batcher::signed_or_held`); a source that restarts its counter faster than it seals is the
/// one way to reach it.
pub const fn batches_held(ceiling: u32) -> usize {
    let held_ms = tally_wire::budget::ANCHOR_WAIT
        .span::<tally_wire::clocks::Judged>()
        .ms();
    let seal_ms = SEAL_EVERY.as_millis() as u64;
    let seals = held_ms.div_ceil(seal_ms) + 1;
    let filled = held_gathered(ceiling).div_ceil(FILLED_AT_LEAST as u64);
    (seals * SEAL_KINDS as u64 + filled) as usize
}

/// The most receptions' bytes a batcher with upload ceiling `ceiling` gathers into the batches it
/// holds for an anchor at once: what its ceiling lets through over `B`
/// (`tally_wire::budget::Tolerance::gathered`), the longest it holds any (`ANCHOR_WAIT`), the seal
/// that releases them and its bucket's second more.
const fn held_gathered(ceiling: u32) -> u64 {
    tally_wire::budget::B.gathered(ceiling as u64)
}

/// What one batch held for an anchor allocates beside its receptions' bytes (`Pending`, its
/// receptions encoded as the wire carries them, `tally_wire::EncodedBatch`): its place in the
/// queue, twice over since a `VecDeque` grows by doubling, the encoding's count and DEFLATE length
/// fields, and the allocator's own header and rounding (16 bytes each, as
/// `tally_counting::Counting` measures against).
const HELD_BATCH_BYTES: u64 = 2 * std::mem::size_of::<Pending>() as u64 + 4 + 4 + 16;

/// What one batch in the channel to the sessions allocates at most (`batch_backlog`): a signed
/// batch's bytes, at most one Noise message (`MAX_OBSERVATION_BYTES` and `BATCH_OVERHEAD`), its
/// kept key and hash, and the record that carries it, each with the allocator's own 16 bytes.
const CHANNEL_BATCH_BYTES: u64 = (noise::MAX_PLAINTEXT
    + tally_wire::batch::KEPT_BYTES
    + tally_wire::footprint::arc::<Record>()
    + 3 * 16) as u64;

/// The most memory a batcher with upload ceiling `ceiling` and the channel to its sessions keep at
/// once, in bytes: the batches it holds for an anchor, each as its receptions' wire bytes
/// (compressed where that is smaller, never larger: `held_gathered` of them) and its own
/// (`HELD_BATCH_BYTES`, `batches_held` of them); and every batch the channel holds
/// (`batch_backlog`) at the most one signed batch allocates, since a session that reads nothing
/// keeps it full while the hold fills. An anchor's return moves the hold into the channel batch
/// by batch, each signed from its compact form and that form freed, so the drain never holds the
/// backlog twice.
pub const fn held_bytes(ceiling: u32) -> u64 {
    held_gathered(ceiling)
        + batches_held(ceiling) as u64 * HELD_BATCH_BYTES
        + batch_backlog(ceiling) as u64 * CHANNEL_BATCH_BYTES
}

/// The memory the packaged unit runs the feeder in (`packaging/systemd/tally-feed.service`'s
/// `MemoryMax=64M`; `tests/unit.rs` reads it there), past which the kernel kills it and the
/// backlog it held is lost.
pub const MEMORY_MAX: u64 = 64 << 20;

/// What the feeder needs of `MEMORY_MAX` beside what it holds for an anchor (`held_bytes`): the
/// binary's pages, the runtime's threads and their stacks, its sessions' Noise buffers, the
/// batch it is gathering of each kind as owned receptions, the readers' queue (`INPUT_BACKLOG`),
/// and the delivery check's audited batches. An allowance: an idle feeder publishing to a relay
/// was measured at 10.3 MB resident (33 threads, on a 32-core host).
pub const RUNTIME_BYTES: u64 = 24 << 20;

/// The highest `--ceiling` whose hold for an anchor (`held_bytes`) and runtime (`RUNTIME_BYTES`)
/// fit `MEMORY_MAX`: `config` refuses a higher one, which the kernel would kill as its backlog
/// grew.
pub const CEILING_MOST: u32 = {
    let (mut fits, mut over) = (0u32, u32::MAX);
    while over - fits > 1 {
        let mid = fits + (over - fits) / 2;
        if held_bytes(mid) + RUNTIME_BYTES <= MEMORY_MAX {
            fits = mid;
        } else {
            over = mid;
        }
    }
    fits
};

/// The most bytes a second a batcher with upload ceiling `ceiling` signs, as its sessions send
/// them: the ceiling's receptions, and each batch's own bytes (`BATCH_OVERHEAD`, and a stored
/// DEFLATE stream's framing where its content does not compress) for every batch it may seal in a
/// second, one of each kind a seal and one each time the ceiling's second fills one, rounded up.
/// What a session paces its sends at when its relay asks no less (`relays::Pace`), so a backlog
/// released at once goes out at the ceiling, and a session sends at least as fast as the batcher
/// signs, so the backlog drains (`tally_wire::budget::BACKLOG_DRAIN`).
pub const fn signed_most(ceiling: u32) -> u32 {
    let per_second = SEAL_KINDS as u64 + (ceiling as u64).div_ceil(FILLED_AT_LEAST as u64) + 1;
    let own = (BATCH_OVERHEAD + DEFLATE_STORED_FRAMING) as u64 * per_second;
    let most = ceiling as u64 + own;
    if most > u32::MAX as u64 {
        u32::MAX
    } else {
        most as u32
    }
}

/// What a DEFLATE stream of stored blocks adds to its content at most, for a batch no larger than
/// one Noise message: its length field (4) and two blocks' headers (5 each, 64 KiB a block).
const DEFLATE_STORED_FRAMING: usize = 4 + 2 * 5;

/// The batches the channel to the relay sessions holds (`tally_feed::publish`) for a batcher with
/// upload ceiling `ceiling`: every batch it may sign at once as an anchor returns after it held
/// them the longest it does (`batches_held`, and what had gathered since its last seal), and a
/// seal's more, so a session that read nothing meanwhile is lagged by none of them. A broadcast
/// channel's receiver past its capacity loses the oldest (`RecvError::Lagged`), and its sending
/// never waits, so its capacity is sized to the largest burst it is sent, as tokio's own
/// documentation of it says.
pub const fn batch_backlog(ceiling: u32) -> usize {
    let a_second = (2 * ceiling as u64).div_ceil(FILLED_AT_LEAST as u64) as usize;
    batches_held(ceiling) + 2 * SEAL_KINDS + a_second
}

/// The most ACARS-family messages take of the upload ceiling a second unless `--acars-ceiling`
/// says otherwise: a busy VDL2 station near a hub, about ten messages a second of a few hundred
/// bytes each, fits, and ADS-B keeps the rest of the default ceiling (64000).
pub const DEFAULT_ACARS_CEILING: u32 = 8_000;

/// The most ACARS-family messages waiting for the batcher at once, of the queue's
/// `INPUT_BACKLOG`: however small they are, they never take more of the places BEAST's frames
/// wait in.
const ACARS_BACKLOG: u32 = 256;

/// What a reception costs of the upload ceiling: its bytes in a batch (format, counter, signal,
/// length, data).
fn reception_cost(observation: &Observation) -> usize {
    RECEPTION_OVERHEAD + observation.data.len()
}

const RECEPTION_OVERHEAD: usize = 1 + 6 + 1 + 2;

/// What the longest ACARS-family message costs of the upload ceiling (`reception_cost`): a
/// `--ceiling` below it could never send one (`config`).
pub const LONGEST_ACARS: usize = RECEPTION_OVERHEAD + tally_wire::acars::MAX_LINE;

/// The owner's upload ceiling (`--ceiling`) and the ACARS-family share of it (`--acars-ceiling`),
/// one of each for the feeder: the batcher takes every reception's bytes from the ceiling, and
/// each ACARS reader takes a message's from the share before it queues it
/// ([`Inputs::offer_acars`]), so however many `--acars` ports there are and however busy, they
/// take no more than the share between them, and never a place in the queue BEAST's frames wait
/// in beyond it.
pub struct Ceilings {
    ceiling: u32,
    upload: Mutex<TokenBucket>,
    acars: Mutex<TokenBucket>,
}

impl Ceilings {
    /// The share holds a second of itself at once, never more: a burst of messages takes no
    /// more of the ceiling's second than the share does.
    pub fn new(ceiling: u32, acars: u32) -> Arc<Self> {
        Arc::new(Self {
            ceiling,
            upload: Mutex::new(TokenBucket::new(ceiling)),
            acars: Mutex::new(TokenBucket::new(acars)),
        })
    }

    /// Whether `cost` bytes fit the upload ceiling at `now`, and takes them.
    fn take_upload(&self, cost: usize, now: Instant) -> bool {
        self.upload
            .lock()
            .is_ok_and(|mut bucket| bucket.take_at(cost, now))
    }

    /// Whether an ACARS-family message of `cost` bytes may be queued at `now`, and if so takes
    /// its bytes from the upload ceiling and the share at once, under both locks, so nothing
    /// takes the ceiling's room between the two (the batcher then takes nothing more for it:
    /// `Batcher::push_admitted_at`). A message the ceiling has no room for never spends the share.
    /// A message longer than the share goes once the share is full, and the share owes it
    /// (`take_owing_at`), so the share holds on average and a long message is still sent.
    pub fn admit_acars(&self, cost: usize, now: Instant) -> bool {
        let (Ok(mut upload), Ok(mut acars)) = (self.upload.lock(), self.acars.lock()) else {
            return false;
        };
        if !upload.fits_at(cost, now) || !acars.take_owing_at(cost, now) {
            return false;
        }
        upload.take_at(cost, now)
    }

    /// Gives back what [`Self::admit_acars`] took for a message that was then not queued, so a
    /// message dropped never spends the share or the ceiling.
    fn refund_acars(&self, cost: usize) {
        for bucket in [&self.upload, &self.acars] {
            if let Ok(mut bucket) = bucket.lock() {
                bucket.give_back(cost);
            }
        }
    }
}

/// The milliseconds from `since` to `now` on the feeder's own clock, none when `now` is before
/// it: a span to hold against a tolerance of `tally_wire::budget`.
fn elapsed(since: i128, now: i128) -> u64 {
    u64::try_from(now.saturating_sub(since).max(0)).unwrap_or(u64::MAX)
}

/// A token bucket that drops what is over budget and never buffers (§3.5). It starts full.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    filled: Instant,
}

impl TokenBucket {
    /// The owner's upload ceiling: one second of budget is the most it lets through at once.
    pub fn new(bytes_per_sec: u32) -> Self {
        Self::with_burst(bytes_per_sec, bytes_per_sec)
    }

    /// `bytes_per_sec`, and at most `burst` bytes at once.
    pub fn with_burst(bytes_per_sec: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(bytes_per_sec),
            burst: f64::from(burst),
            tokens: f64::from(burst),
            filled: Instant::now(),
        }
    }

    /// True if `cost` bytes fit, and takes them.
    pub fn take(&mut self, cost: usize) -> bool {
        self.take_at(cost, Instant::now())
    }

    /// As `take`, at `now` (which never runs backwards for one bucket).
    pub fn take_at(&mut self, cost: usize, now: Instant) -> bool {
        if !self.fits_at(cost, now) {
            return false;
        }
        self.tokens -= cost as f64;
        true
    }

    /// As `take_at`, but a `cost` past the burst is taken once the bucket is full, leaving it
    /// owing: what it lets through still averages its rate.
    pub fn take_owing_at(&mut self, cost: usize, now: Instant) -> bool {
        if !self.fits_at((cost as f64).min(self.burst) as usize, now) {
            return false;
        }
        self.tokens -= cost as f64;
        true
    }

    /// How long from `now` until `cost` bytes fit: none when they fit now, and then they are
    /// taken. What a paced sender waits before it asks again (`relays::Pace`), never dropping.
    pub fn wait_at(&mut self, cost: usize, now: Instant) -> Duration {
        if self.take_at(cost, now) {
            return Duration::ZERO;
        }
        let short = cost as f64 - self.tokens;
        // At least a millisecond, so a wait rounded to nothing is never asked again at once.
        Duration::from_secs_f64((short / self.rate.max(1.0)).max(0.001))
    }

    /// Returns `cost` bytes taken for what was not sent, never past the burst.
    fn give_back(&mut self, cost: usize) {
        self.tokens = (self.tokens + cost as f64).min(self.burst);
    }

    /// Whether `cost` bytes fit at `now`, taking nothing.
    pub fn fits_at(&mut self, cost: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.filled).as_secs_f64();
        self.filled = self.filled.max(now);
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        cost as f64 <= self.tokens
    }
}

/// The wanted receptions a second (`tally_wire::modes::wanted_reception`) the relays this feeder
/// publishes to take from it: each relay states its own in its `RateLimit` (`wanted_per_sec`), and
/// the batcher sheds to the least any live session stated, before it signs, so every batch it
/// seals is one every relay it goes to takes whole. A relay that states none (one that predates the
/// field) holds the feeder to nothing here; a session's statement goes with it ([`Stating`]).
#[derive(Default)]
pub struct WantedCeilings {
    stated: std::sync::Mutex<std::collections::HashMap<u64, u32>>,
    sessions: std::sync::atomic::AtomicU64,
    /// The least stated, or 0 for none.
    least: AtomicU32,
}

/// One relay session's place in [`WantedCeilings`]: what it stated, until it is dropped with the
/// session (however the session ends, its task aborted included).
pub struct Stating {
    ceilings: Arc<WantedCeilings>,
    session: u64,
}

impl Stating {
    /// The session's relay stated `wanted_per_sec` (or none) in its latest `RateLimit`.
    pub fn state(&self, wanted_per_sec: Option<u32>) {
        self.ceilings.change(|stated| match wanted_per_sec {
            Some(wanted) => {
                stated.insert(self.session, wanted);
            }
            None => {
                stated.remove(&self.session);
            }
        });
    }
}

impl Drop for Stating {
    fn drop(&mut self) {
        self.ceilings.change(|stated| {
            stated.remove(&self.session);
        });
    }
}

impl WantedCeilings {
    /// A new session's place, stating nothing yet.
    pub fn session(self: &Arc<Self>) -> Stating {
        Stating {
            ceilings: Arc::clone(self),
            session: self.sessions.fetch_add(1, Ordering::Relaxed),
        }
    }

    fn change(&self, change: impl FnOnce(&mut std::collections::HashMap<u64, u32>)) {
        if let Ok(mut stated) = self.stated.lock() {
            change(&mut stated);
            let least = stated.values().copied().min().unwrap_or(0);
            self.least.store(least, Ordering::Relaxed);
        }
    }

    /// The least wanted receptions a second a live session stated, if any did.
    pub fn least(&self) -> Option<u32> {
        Some(self.least.load(Ordering::Relaxed)).filter(|least| *least > 0)
    }
}

/// This host's clocks: its wall clock (milliseconds since the epoch, which NTP or its owner may
/// step either way), a monotonic one (time since some instant of its own, which never steps), and
/// what the host's ClockBound says of the wall clock (`synced`: its error bound in milliseconds
/// while it reports it synchronised within `E`, none otherwise or without ClockBound). The
/// system's, or a test's.
#[derive(Clone)]
pub struct HostClock {
    pub wall: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub monotonic: Arc<dyn Fn() -> Duration + Send + Sync>,
    pub synced: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
}

impl HostClock {
    /// The system's: `SystemTime`, the raw monotonic clock (`CLOCK_MONOTONIC_RAW`,
    /// `tally_wire::kernel_clock::raw_monotonic_ms`) and the host's ClockBound
    /// (`tally_wire::clock_bound::Reader::host`). The monotonic clock is the raw one, the
    /// oscillator's own rate, because it ages every sample's uncertainty at
    /// `tally_wire::budget::DRIFT_PPM` and anchors every sample's offset: `Instant`
    /// (`CLOCK_MONOTONIC`) is slewed with the wall clock, by chrony at up to 83,333 ppm, so a
    /// sample 30 s old could be off by 2.5 s while its interval widened by 15 ms. A start asks
    /// [`raw_clock_answers`] first.
    pub fn system() -> Self {
        Self::bounded_by(tally_wire::clock_bound::Reader::host())
    }

    /// As [`HostClock::system`], its wall clock bounded by the ClockBound segment `bound` reads.
    pub fn bounded_by(bound: &'static tally_wire::clock_bound::Reader) -> Self {
        let started = tally_wire::kernel_clock::raw_monotonic_ms();
        Self {
            wall: Arc::new(wall_ms),
            monotonic: Arc::new(move || {
                Duration::from_millis(
                    tally_wire::kernel_clock::raw_monotonic_ms().saturating_sub(started),
                )
            }),
            synced: Arc::new(move || host_error_ms(bound)),
        }
    }
}

/// Whether the kernel reads the raw monotonic clock the feeder measures its relays' clocks by
/// ([`HostClock::system`]): a feeder that cannot read it refuses to start, naming why, since a
/// sample aged by a made-up reading would sign by a clock nobody measured.
pub fn raw_clock_answers() -> Result<(), String> {
    tally_wire::kernel_clock::raw_monotonic()
        .map(drop)
        .map_err(|error| {
            format!(
                "the kernel will not read the raw monotonic clock (CLOCK_MONOTONIC_RAW: {error}), \
                 which the feeder measures its relays' clocks by: a seccomp filter blocks \
                 clock_gettime or the kernel is older than 2.6.28"
            )
        })
}

impl HostClock {
    /// A host whose wall clock reads `wall` and monotonic clock `monotonic` (milliseconds), each
    /// as a test sets them, and which has no ClockBound to bound it.
    pub fn set_by(
        wall: &Arc<std::sync::atomic::AtomicU64>,
        monotonic: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        let (wall, monotonic) = (Arc::clone(wall), Arc::clone(monotonic));
        Self {
            wall: Arc::new(move || wall.load(Ordering::Relaxed)),
            monotonic: Arc::new(move || Duration::from_millis(monotonic.load(Ordering::Relaxed))),
            synced: Arc::new(|| None),
        }
    }
}

impl Default for HostClock {
    fn default() -> Self {
        Self::system()
    }
}

/// The wall clock's error bound in milliseconds while the host's ClockBound, as `bound` reads it,
/// says it is synchronised within `E` (`tally_wire::clock_bound`, the one reader and the one
/// judgement of its word every end shares); none while it is missing, unreadable, not
/// synchronised or too wide. A feeder never needs ClockBound: without it the host is no reference,
/// and the feeder signs by its configured relays.
pub fn host_error_ms(bound: &tally_wire::clock_bound::Reader) -> Option<u64> {
    bound.read().ok()
}

/// `E` in milliseconds: the error a relay that states none is taken to have, as a relay that
/// judges states at most this.
const E_MS: u64 = tally_wire::budget::E_MS;

/// The sources a feeder gathers before it stops probing for more (RFC-0171 §3.6): fewer, and one
/// wrong source cannot be outvoted. A majority of fewer is still selected, as NTP selects (RFC 5905
/// §11.2.1, whose intersection needs no least number; ntpd's `minsane` and chrony's `minsources`
/// are 1 by default); the feeder probes meanwhile.
const SELECT_AT_LEAST: usize = 3;

/// Where a clock sample came from: a session publishing to its relay, or a probe of a configured
/// relay. What is selected over is the relay, not where it was heard: each sample is held with its
/// relay's key, and a relay heard through both a session and a probe (or two sessions) is one
/// source, its tighter interval ([`RelayClocks::offset_now`]), so one relay never counts twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Source {
    Session(u64),
    Probed(tally_wire::PublicKey),
}

/// The selection's cases (`selected`): one source is its interval; three that all meet are the
/// span a majority (two) covers, wider than their common part; two of three that meet, with one
/// apart, are the two's; two that do not meet select nothing (no point has both); intervals that
/// touch meet at that point, and honest relays at `-E` and `E` select where they touch; an exact
/// source is its point; and majority regions apart are one span, the two covered by a source in
/// common.
#[cfg(test)]
#[test]
fn selection_is_the_span_a_majority_covers() {
    assert_eq!(selected(&[(0, 10)]), Some((0, 10)));
    assert_eq!(selected(&[(0, 10), (2, 12), (4, 14)]), Some((2, 12)));
    assert_eq!(selected(&[(0, 10), (2, 12), (100, 110)]), Some((2, 10)));
    assert_eq!(selected(&[(0, 10), (20, 30)]), None);
    assert_eq!(selected(&[(0, 10), (10, 20)]), Some((10, 10)));
    assert_eq!(selected(&[(5, 5)]), Some((5, 5)));
    // Two honest relays at -E and E, each stating E, meet at 0.
    assert_eq!(selected(&[(-15, 0), (0, 15)]), Some((0, 0)));
    assert_eq!(selected(&[]), None);
    // Three of five over each of two regions apart: the span over both, which (0, 42) covers.
    assert_eq!(
        selected(&[(0, 10), (2, 12), (30, 40), (32, 42), (0, 42)]),
        Some((2, 40))
    );
}

/// Two liars of five, agreeing, never sign ahead of true time (0): honest (-8500, 8500) twice and
/// (-1000, 1000), liars (6000, 22000) twice. The most intervals (four) meet at (6000, 8500), which
/// the sweep for the deepest region selected, signing 6 s ahead; the span three cover is
/// (-1000, 8500), which RFC 5905's intersection also finds (at `f = 2`, its midpoint rule
/// passing), and its low end is behind true time.
#[cfg(test)]
#[test]
fn two_agreeing_liars_of_five_never_sign_ahead_of_true_time() {
    let honest = [(-8_500, 8_500), (-8_500, 8_500), (-1_000, 1_000)];
    let liars = [(6_000, 22_000), (6_000, 22_000)];
    let all: Vec<(i64, i64)> = honest.iter().chain(&liars).copied().collect();
    let selection = selected(&all);
    assert!(
        selection.is_some_and(|(low, high)| low <= 0 && 0 <= high),
        "{selection:?} does not hold true time"
    );
    assert_eq!(selection, Some((-1_000, 8_500)));
}

/// One liar of four cannot stop a selection: honest (-10, 10) twice and (-2, 2), liar (5, 20).
/// Three cover (-2, 2) and three (5, 10), two regions apart; the sweep that refused a tie between
/// them selected nothing, and a feeder then signed by its own host's clock as read. They are one
/// span, (-2, 10), which holds true time (0).
#[cfg(test)]
#[test]
fn one_liar_of_four_cannot_stop_a_selection() {
    let selected = selected(&[(-10, 10), (-10, 10), (-2, 2), (5, 20)]);
    assert_eq!(selected, Some((-2, 10)));
}

/// One measurement of a relay's clock (RFC 5905 §8): its offset `θ` from this host's anchored
/// monotonic clock, half the round trip it was measured over, when it was measured on the
/// anchored clock, and the relay's own error bound (`ε_r`). Measured by an echo (NTP's four
/// timestamps), or read off a statement (a `RateLimit`, whose one-way time is unknown: its whole
/// handshake is taken for it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sample {
    offset_ms: i64,
    half_rtt_ms: u64,
    at_ms: i128,
    error_ms: u64,
}

impl Sample {
    /// How uncertain it is at `now_ms` on the anchored clock: half its round trip, and `ρ` of its
    /// age (`u = RTT/2 + ρ·age`).
    fn uncertainty_ms(&self, now_ms: i128) -> u64 {
        let age = u64::try_from((now_ms - self.at_ms).max(0)).unwrap_or(u64::MAX);
        self.half_rtt_ms
            .saturating_add(age.saturating_mul(tally_wire::budget::DRIFT_PPM) / 1_000_000)
    }

    /// Its interval of the relay's clock at `now_ms` (offsets from the anchored clock), when it
    /// may be selected by: measured within `U_m`, and from a relay whose error is within `E`.
    fn interval(&self, now_ms: i128) -> Option<(i64, i64)> {
        let u = self.uncertainty_ms(now_ms);
        if !tally_wire::budget::U_M.covers(u) || !tally_wire::budget::E.covers(self.error_ms) {
            return None;
        }
        let half = i64::try_from(u + self.error_ms).unwrap_or(i64::MAX);
        Some((
            self.offset_ms.saturating_sub(half),
            self.offset_ms.saturating_add(half),
        ))
    }
}

/// The clock a feeder signs its batches by, selected from the clocks of the relays it reaches
/// as NTP selects (RFC 5905 §11.2.1, Marzullo's algorithm; RFC-0171 §3.6). Each relay's clock is
/// measured (`Sample`): by the four timestamps of a timed heartbeat's echo where the relay
/// answers one, else by the clock its `RateLimit` stated, its handshake's whole time taken for
/// the uncertainty. A sample is held as an offset from this host's monotonic clock (anchored to
/// its wall clock as it read when the feeder started), so it runs on from when it was measured
/// and never moves with a step of this host's wall clock.
///
/// The sources are configured, never discovered, as NTP's are only the servers it was configured
/// with: the relays its owner configured or its binary seeds (`--relay`, the seeds:
/// [`RelayClocks::configured`]), measured by a session to one or a probe of one, and this host's
/// own clock while its ClockBound reports it synchronised within `E`. Nothing else is a source: not a probe
/// answer from a relay a hint named, and not a session to one either, so no number of hinted
/// relays changes what is selected. One relay is one source however it was heard, and a session
/// that ends takes its sample with it. An unsynced host is no source, as NTP never votes its
/// undisciplined local clock (it is read as it is only when nothing is selected). Each relay is an
/// interval: its offset, widened by its uncertainty (`u = RTT/2 + ρ·age`, a sample past `U_m`
/// dropped) and its relay's stated error (`ε_r`, a relay that states none taken at `E`, one past
/// `E` ignored). What is selected is the span of the points more than half the intervals cover,
/// and the batches are signed at its low end: while honest sources are a majority, true time lies
/// in that span, so no batch is signed ahead of it. No point covered by a strict majority selects
/// nothing; nor does a selection with no configured relay heard (a synced host alone selects
/// nothing). How this relates to RFC 5905's `clock_select`, `selected` says. With fewer than three
/// sources a majority is still selected, and it asks for probes of its configured relays not yet
/// heard (`RelayClocks::probing`). Without a selection (as in NTP, no system peer: the clock is
/// not steered by a minority) it asks for them too, and meanwhile signs at the low end of this
/// host's clock's bound while its ClockBound reports it synchronised (its own trusted reference, so again
/// never ahead of true time), else by the offset a selection of its configured relays last made
/// (NTP's holdover, widened by the raw clock's drift as it ages and dropped once wider than
/// `tally_wire::budget::SELECTION_LAG`), else by this host's clock as read. What it selects is an interval holding
/// true time (`RelayClocks::reference`), at most `tally_wire::budget::SELECTION_LAG` wide, so a
/// batch's signed time lags true time by at most that: the lag every window of time allows for.
///
/// What is selected decides only the time a batch is signed at. No clock decides what is sent:
/// every batch goes to every session it is routed to, and each relay alone judges whether it can
/// use it (RFC-0171 §3.6: possession never depends on a clock). A session's measure of its relay's
/// clock says only how far this feeder's clock is from that relay's, which its health reports
/// ([`RelayClocks::disagreements`]): never whether a batch goes, and never the relay's fate.
pub struct RelayClocks {
    /// Every sample kept, by where it was heard (`change`, the one place that decides which are
    /// kept and which are sources).
    samples: std::sync::Mutex<std::collections::HashMap<Source, Kept>>,
    /// The relays that are sources: the owner's and the binary's seeds.
    configured: std::collections::HashSet<tally_wire::PublicKey>,
    sessions: std::sync::atomic::AtomicU64,
    host: HostClock,
    /// This host's wall clock when its monotonic clock read zero, as near as it was read: the
    /// anchor the monotonic clock is read in milliseconds since the epoch from.
    anchor_ms: i128,
    /// The interval last selected (offsets from the anchored clock) and when (the anchored
    /// clock), held when every source is gone, so a feeder keeps signing by the corrected clock
    /// across its reconnects: widened by the raw clock's drift as it ages, and dropped once wider
    /// than any reference a feeder signs by (`tally_wire::budget::held_over`).
    held_ms: std::sync::Mutex<Option<((i64, i64), i128)>>,
    /// Told when the sources make no majority: the publisher probes until they do.
    probing: tokio::sync::Notify,
    /// Each live session's freshness anchor from its relay heard last (RFC-0171 §3.6): what the
    /// batcher signs into each batch ([`RelayClocks::anchors`]). A session's goes with it.
    anchors: std::sync::Mutex<std::collections::HashMap<u64, Heard>>,
    /// Batches signed with no anchor since it started (a backlog that waited `ANCHOR_WAIT` for
    /// one, or one its source's end left): passed on and held by every relay, used by none. What
    /// the health reports.
    unanchored: AtomicU64,
}

/// A session's freshness anchor as it was first heard.
#[derive(Clone, Copy, Debug)]
struct Heard {
    anchor: tally_wire::Anchor,
    /// When it was first heard, by the anchored (monotonic) clock: its age counts from then.
    at: i128,
}

impl Default for RelayClocks {
    fn default() -> Self {
        Self::on(HostClock::system())
    }
}

/// One relay session's place in [`RelayClocks`]: its relay's clock as this session measured it,
/// until it is dropped with the session.
pub struct Telling {
    clocks: Arc<RelayClocks>,
    session: u64,
    /// The relay this session publishes to: the source its samples count as.
    relay: tally_wire::PublicKey,
    /// How long the session took from its Hello to its relay's first statement: the uncertainty
    /// of a statement, whose one-way time is unknown.
    handshake_ms: std::sync::atomic::AtomicU64,
}

impl Telling {
    /// The session's relay stated its clock `clock_ms` with its error `error_ms` (either none) in
    /// a `RateLimit`, heard now, the session's Hello sent at `hello_ms` (the anchored clock,
    /// [`RelayClocks::stamp_ms`]: the raw monotonic clock, never `Instant`, which a daemon slews
    /// with the wall clock by up to 83,333 ppm). Its greeting, the first
    /// statement, answers the Hello, so its one-way time is within that round trip: a sample
    /// whose uncertainty is the whole of it (the session's handshake time). A restatement, any
    /// after it, comes on the relay's own account (its clock stepped, or this feeder's batches
    /// drifted), not in answer to anything, so its one-way time is unbounded and it is no sample:
    /// the session's sample goes (the relay's clock stepped, so it is wrong now), and true is
    /// returned so the session asks for an echo at once, which measures the relay by its own
    /// round trip (`Telling::echoed`). Before, a restatement was a sample within the handshake's
    /// time, however long it had queued.
    pub fn stated(&self, clock_ms: Option<u64>, error_ms: Option<u64>, hello_ms: u64) -> bool {
        if self.handshake_ms.load(Ordering::Relaxed) != 0 {
            self.clocks
                .change(Source::Session(self.session), self.relay, None);
            return true;
        }
        let now = self.clocks.anchored_ms();
        let handshake = u64::try_from(now - i128::from(hello_ms))
            .unwrap_or(0)
            .max(1);
        self.handshake_ms.store(handshake, Ordering::Relaxed);
        let sample = clock_ms.map(|clock| Sample {
            offset_ms: saturated(i128::from(clock) - now),
            half_rtt_ms: handshake,
            at_ms: now,
            error_ms: error_ms.unwrap_or(E_MS),
        });
        self.clocks
            .change(Source::Session(self.session), self.relay, sample);
        false
    }

    /// The relay answered a timed heartbeat (NTP's on-wire exchange): `asked_ms` (`T1`, the
    /// anchored clock this session sent it by, `Telling::asking_ms`), `took_ms` and `sent_ms`
    /// (`T2`, `T3`, the relay's clock), heard now (`T4`), with its error bound.
    ///
    /// `T1` is taken as the relay echoes it, with no nonce as a probe's echo carries: the session
    /// is the relay's own, authenticated end to end by Noise, so only the relay measured can answer,
    /// and every number in the answer but `T4` is already its word. An echoed `T1` later than the
    /// one sent only narrows that relay's own interval, by at most the true round trip, while its
    /// `T2` and `T3` place the interval anywhere: what makes one relay's lie harmless is the
    /// selection, a majority of sources outvoting it (`selected`), never the width it claims. One
    /// later than now (`T4`), or a round trip below none, is no sample (`echo_sample`).
    pub fn echoed(&self, asked_ms: u64, took_ms: u64, sent_ms: u64, error_ms: Option<u64>) {
        let now = self.clocks.anchored_ms();
        if let Some(sample) = echo_sample(asked_ms, took_ms, sent_ms, now, error_ms) {
            self.clocks
                .change(Source::Session(self.session), self.relay, Some(sample));
        }
    }

    /// The session's relay stated its freshness anchor (`Record::Anchor`, RFC-0171 §3.6): kept as
    /// this session's, the one heard last, when it is that relay's and its signature verifies, so
    /// a batch never carries an anchor its relay did not sign. The same anchor stated again is
    /// not heard anew: its age counts from when it was first heard. False when it is not kept.
    pub fn anchored(&self, anchor: tally_wire::Anchor) -> bool {
        if anchor.relay != self.relay || anchor.verify().is_err() {
            return false;
        }
        let at = self.clocks.anchored_ms();
        let Ok(mut anchors) = self.clocks.anchors.lock() else {
            return false;
        };
        if anchors
            .get(&self.session)
            .is_some_and(|held| held.anchor == anchor)
        {
            return false;
        }
        anchors.insert(self.session, Heard { anchor, at });
        true
    }

    /// The time a timed heartbeat this session sends now carries (`T1`): the anchored clock.
    pub fn asking_ms(&self) -> u64 {
        self.clocks.stamp_ms()
    }

    /// This session's sample of its relay's clock, when it is one to judge by now: measured
    /// within `U_m` (by its echo, or by the clock its greeting stated) from a relay whose stated
    /// error is within `E` (an unsynced relay, stating its error unbounded, is ignored).
    fn sample(&self, now: i128) -> Option<Sample> {
        self.clocks
            .samples
            .lock()
            .ok()
            .and_then(|samples| {
                samples
                    .get(&Source::Session(self.session))
                    .map(|kept| kept.sample)
            })
            .filter(|sample| sample.interval(now).is_some())
    }

    /// How far the clock batches are signed by now is outside this relay's clock as this session
    /// measured it (its interval, `θ ± (u + ε_r)`): positive ahead of it, negative behind it, none
    /// while inside it or not measured. What the feeder's health reports, never what decides a
    /// send.
    pub fn disagreement_ms(&self) -> Option<i64> {
        let signing = i128::from(self.clocks.now_ms());
        let now = self.clocks.anchored_ms();
        let sample = self.sample(now)?;
        outside(signing, now, &sample)
    }
}

/// How far `signing` is outside `sample`'s interval at `now` (anchored milliseconds): positive
/// past its high end, negative below its low end, none within it.
fn outside(signing: i128, now: i128, sample: &Sample) -> Option<i64> {
    let (lo, hi) = sample.interval(now)?;
    let (lo, hi) = (now + i128::from(lo), now + i128::from(hi));
    if signing > hi {
        Some(saturated(signing - hi))
    } else if signing < lo {
        Some(saturated(signing - lo))
    } else {
        None
    }
}

/// A sample from a timed heartbeat's echo: `T1` (`asked_ms`) and `T4` (`now_ms`) on the anchored
/// clock, `T2` and `T3` on the relay's. `θ = ((T2 - T1) + (T3 - T4)) / 2`, within half the round
/// trip `(T4 - T1) - (T3 - T2)`. None for an echo of nothing this clock sent (a round trip below
/// zero).
fn echo_sample(
    asked_ms: u64,
    took_ms: u64,
    sent_ms: u64,
    now_ms: i128,
    error_ms: Option<u64>,
) -> Option<Sample> {
    let (t1, t2, t3, t4) = (
        i128::from(asked_ms),
        i128::from(took_ms),
        i128::from(sent_ms),
        now_ms,
    );
    let rtt = (t4 - t1) - (t3 - t2).max(0);
    if rtt < 0 || t4 < t1 {
        return None;
    }
    Some(Sample {
        offset_ms: saturated(((t2 - t1) + (t3 - t4)) / 2),
        half_rtt_ms: u64::try_from(rtt).unwrap_or(u64::MAX).div_ceil(2),
        at_ms: now_ms,
        error_ms: error_ms.unwrap_or(E_MS),
    })
}

impl Drop for Telling {
    fn drop(&mut self) {
        if let Ok(mut anchors) = self.clocks.anchors.lock() {
            anchors.remove(&self.session);
        }
        self.clocks
            .change(Source::Session(self.session), self.relay, None);
    }
}

/// A sample as [`RelayClocks::change`] keeps it: its relay, and whether that relay is a clock
/// source (configured, [`RelayClocks::configured`]), decided once as it is kept. A session's sample
/// of a relay a hint named is kept for its health (`Telling::disagreement_ms`,
/// [`RelayClocks::disagreements`]) and is no source; a probe's of one is not kept at all.
#[derive(Clone, Copy, Debug)]
struct Kept {
    relay: tally_wire::PublicKey,
    sample: Sample,
    source: bool,
}

/// An `i128` of milliseconds held to an `i64`.
fn saturated(value: i128) -> i64 {
    i64::try_from(value).unwrap_or(if value < 0 { i64::MIN } else { i64::MAX })
}

/// What the sources' `intervals` select: the span of the points more than half of them cover,
/// its low and high ends; none when no point is covered by a strict majority.
///
/// Why it holds true time. While honest sources are a strict majority, each honest interval holds
/// true time, so true time is covered by more than half and lies in the span: its low end, which
/// a feeder signs at, is never ahead of true time. Any two points in the span are each covered by
/// more than half the intervals, so some one interval covers both: the span is never wider than
/// the widest interval (`tally_wire::budget::SELECTION_LAG`), and its low end is never further
/// behind true time than that. Majority points apart (two regions, as when one source's interval
/// reaches across both) are one span for the same reason, never a tie.
///
/// How it relates to RFC 5905's intersection (§11.2.1, Appendix A.5.5.1 `clock_select`). The RFC
/// tries `f = 0, 1, ...` falsetickers while `f < n / 2`, takes the span of the points `n - f`
/// intervals cover, and accepts the first `f` whose span is not empty and whose midpoint rule
/// passes (no more than `f` midpoints outside it). This is that span at the largest `f` the RFC
/// allows, `f = ceil(n / 2) - 1` (points covered by more than half), with no midpoint rule. So it
/// is never narrower than the RFC's selection when the RFC selects, and contains it. Where the RFC
/// would stop at a smaller `f` its span is the region the most intervals cover, and two agreeing
/// liars can make that region lie ahead of true time (as in
/// `two_agreeing_liars_of_five_never_sign_ahead_of_true_time`, where the RFC's own midpoint rule
/// rejects the smaller `f`). The midpoint rule is not taken: it
/// assumes intervals as wide as a root distance against the offsets, while here two honest relays
/// at `-E` and `E`, each stating `E`, meet only at their edges, their midpoints outside, and the
/// rule would select nothing from the honest pair (the clocks' error budget end to end,
/// `tally_relay`'s `hub::honest_end_to_end`, fails then). The price is a wider span when sources
/// agree: signing at its low end lags true time by up to `SELECTION_LAG`, which every window
/// allows for.
fn selected(intervals: &[(i64, i64)]) -> Option<(i64, i64)> {
    // A sweep of the edges: each interval opens at its low end and closes past its high end, an
    // opening before a closing at the same point, so intervals that touch meet. The first point
    // more than half are open over is the low end, and the last closing among more than half the
    // high end.
    let majority = intervals.len() / 2 + 1;
    let mut edges: Vec<(i64, i32)> = intervals
        .iter()
        .flat_map(|&(lo, hi)| [(lo, -1), (hi, 1)])
        .collect();
    edges.sort_unstable();
    let (mut open, mut low, mut high) = (0usize, None, None);
    for (point, edge) in edges {
        if edge < 0 {
            open += 1;
            if open >= majority && low.is_none() {
                low = Some(point);
            }
        } else {
            if open >= majority {
                high = Some(point);
            }
            open -= 1;
        }
    }
    Some((low?, high?))
}

impl RelayClocks {
    /// Clocks read by `host`, none measured yet.
    pub fn on(host: HostClock) -> Self {
        let anchor_ms = i128::from((host.wall)()) - (host.monotonic)().as_millis().cast_signed();
        Self {
            samples: std::sync::Mutex::default(),
            configured: std::collections::HashSet::new(),
            sessions: std::sync::atomic::AtomicU64::new(0),
            host,
            anchor_ms,
            held_ms: std::sync::Mutex::new(None),
            probing: tokio::sync::Notify::new(),
            anchors: std::sync::Mutex::default(),
            unanchored: AtomicU64::new(0),
        }
    }

    /// A test's anchor, as if a session that never ends had heard it and it never aged: what a
    /// test that is not about anchors signs its batches with.
    #[cfg(test)]
    pub(crate) fn always_anchored(&self, anchor: tally_wire::Anchor) {
        if let Ok(mut anchors) = self.anchors.lock() {
            let session = u64::MAX - anchors.len() as u64;
            anchors.insert(
                session,
                Heard {
                    anchor,
                    at: i128::MAX,
                },
            );
        }
    }

    /// The sessions' anchors heard within `tally_wire::budget::ANCHOR_HELD`, one a relay (the
    /// one heard last), the last heard first.
    fn live_anchors(&self) -> Vec<Heard> {
        let now = self.anchored_ms();
        let Ok(anchors) = self.anchors.lock() else {
            return Vec::new();
        };
        let mut live: Vec<Heard> = anchors
            .values()
            .filter(|heard| {
                heard.at == i128::MAX
                    || tally_wire::budget::ANCHOR_HELD.covers(elapsed(heard.at, now))
            })
            .copied()
            .collect();
        drop(anchors);
        live.sort_by_key(|heard| std::cmp::Reverse(heard.at));
        let mut relays = std::collections::HashSet::new();
        live.retain(|heard| relays.insert(heard.anchor.relay));
        live
    }

    /// The trusted reference now, when there is one its operator trusts, as the interval of
    /// wall-clock milliseconds it holds true time in: where its configured relays' selection
    /// meets (`Selection::Majority` or `Selection::Few`), or this host's clock within its
    /// ClockBound's bound while it reports it synchronised within `E` (its NTP daemon's
    /// configured servers). Batches are signed at its low end (`now_ms`). None otherwise: the host's clock as
    /// read, or held over, is no reference to judge a relay's anchor by.
    fn reference(&self) -> Option<(i128, i128)> {
        let now = self.anchored_ms();
        match self.offset_now().0 {
            Selection::Majority((lo, hi)) | Selection::Few((lo, hi)) => {
                Some((now + i128::from(lo), now + i128::from(hi)))
            }
            Selection::NoMajority => self.host_bound().map(|error| {
                let wall = i128::from((self.host.wall)());
                (wall - i128::from(error), wall + i128::from(error))
            }),
        }
    }

    /// The live anchors that a trusted reference rejects, each with how far outside the
    /// reference's whole interval it was as it was heard (`tally_wire::budget::anchor_outside`:
    /// positive below it, negative above it); and those it keeps. With no reference, it rejects
    /// none.
    fn judged_anchors(&self) -> (Vec<Heard>, Vec<(tally_wire::PublicKey, i64)>) {
        let live = self.live_anchors();
        let Some((lo, hi)) = self.reference() else {
            return (live, Vec::new());
        };
        let now = self.anchored_ms();
        let mut kept = Vec::new();
        let mut rejected = Vec::new();
        for heard in live {
            // A test's anchor that never ages (`always_anchored`) is never judged.
            if heard.at == i128::MAX {
                kept.push(heard);
                continue;
            }
            let ago = now - heard.at;
            match tally_wire::budget::anchor_outside(lo - ago, hi - ago, heard.anchor.j_ms) {
                Some(off) => rejected.push((heard.anchor.relay, off)),
                None => kept.push(heard),
            }
        }
        (kept, rejected)
    }

    /// A batch was signed with no anchor (`Batcher`).
    fn signed_unanchored(&self) {
        self.unanchored.fetch_add(1, Ordering::Relaxed);
    }

    /// The batches signed with no anchor since it started.
    pub fn unanchored(&self) -> u64 {
        self.unanchored.load(Ordering::Relaxed)
    }

    /// The anchors a batch signed now carries (RFC-0171 §3.6), from the sessions' anchors heard
    /// within `tally_wire::budget::ANCHOR_HELD`, one a relay (the one heard last).
    ///
    /// With a trusted reference (`reference_ms`: a selection of its configured relays, or its
    /// host synced), only those that agree with it as an honest relay's must
    /// against the reference's whole interval (`tally_wire::budget::anchor_outside`); the rest are
    /// left out and its health reports them ([`RelayClocks::anchor_disagreements`]), so a lying
    /// relay its operator did not configure can neither make its batches unusable nor make stale
    /// ones look fresh. With none, it has nothing to judge an anchor by (anchors matter exactly
    /// when its own clock is wrong, and a lie matching that clock is what a filter by it would
    /// keep), so it carries them all and the hop takes the oldest it knows: a lying relay can then
    /// make its batches unusable, and makes a stale one usable only at a hop that knows no honest
    /// anchor it carries (while one honest known anchor is there, the oldest decides).
    ///
    /// When there are more than `tally_wire::batch::MAX_ANCHORS`, the oldest reading always goes
    /// in, then the last heard. None while no session has one: the batcher then holds its
    /// batches unsigned (`Batcher::seal`).
    pub fn anchors(&self) -> Vec<tally_wire::Anchor> {
        let (kept, _) = self.judged_anchors();
        let mut anchors: Vec<tally_wire::Anchor> = kept.iter().map(|heard| heard.anchor).collect();
        if anchors.len() > tally_wire::batch::MAX_ANCHORS
            && let Some(oldest) = anchors
                .iter()
                .enumerate()
                .min_by_key(|(_, anchor)| anchor.j_ms)
                .map(|(at, _)| at)
        {
            let oldest = anchors.remove(oldest);
            anchors.truncate(tally_wire::batch::MAX_ANCHORS - 1);
            anchors.insert(0, oldest);
        }
        anchors
    }

    /// Every relay whose anchor, heard within `tally_wire::budget::ANCHOR_HELD`, the trusted
    /// reference rejects (see [`RelayClocks::anchors`]): by how far that reference was ahead of
    /// its reading (negative: behind). What the feeder's health reports ("relay X's anchor
    /// disagrees by N s"). None while there is no trusted reference.
    pub fn anchor_disagreements(&self) -> Vec<(tally_wire::PublicKey, i64)> {
        let (_, mut rejected) = self.judged_anchors();
        rejected.sort_unstable_by_key(|(relay, _)| *relay);
        rejected
    }

    /// This host's monotonic clock in milliseconds since the epoch, anchored to its wall clock as
    /// it read when these clocks were made: it runs on at the monotonic pace and never steps.
    pub(crate) fn anchored_ms(&self) -> i128 {
        self.anchor_ms + (self.host.monotonic)().as_millis().cast_signed()
    }

    /// A new session's place, to the relay `relay`, measuring nothing yet.
    pub fn session(self: &Arc<Self>, relay: tally_wire::PublicKey) -> Telling {
        Telling {
            clocks: Arc::clone(self),
            relay,
            session: self.sessions.fetch_add(1, Ordering::Relaxed),
            handshake_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// As these clocks, whose probe answers from `relays` (the owner's `--relay` and the binary's
    /// seeds) are sources. No other probe answer is.
    #[must_use]
    pub fn configured(mut self, relays: impl IntoIterator<Item = tally_wire::PublicKey>) -> Self {
        self.configured.extend(relays);
        self
    }

    /// A relay this feeder probed (`probe`) answered a timed heartbeat: `asked_ms` and `took_ms`,
    /// `sent_ms` as `Telling::echoed` takes them, its answer heard at `heard_ms`, both stamps on
    /// the anchored clock ([`RelayClocks::stamp_ms`]). It is kept only when the relay is configured
    /// ([`RelayClocks::configured`]), which the store alone decides (`change`): a relay a hint
    /// named is probed for its rate and its room, never for the time, and its answer is not kept.
    pub fn probed(
        &self,
        relay: tally_wire::PublicKey,
        (asked_ms, took_ms, sent_ms): (u64, u64, u64),
        error_ms: Option<u64>,
        heard_ms: u64,
    ) {
        let heard = i128::from(heard_ms);
        if let Some(sample) = echo_sample(asked_ms, took_ms, sent_ms, heard, error_ms) {
            self.change(Source::Probed(relay), relay, Some(sample));
        }
    }

    /// The anchored clock now, in whole milliseconds: what a timed heartbeat's question (`T1`)
    /// and its answer (`T4`) and a session's Hello are stamped by, a probe's as a session's. It
    /// runs on the raw monotonic clock ([`HostClock::system`]), so a daemon's slew of the wall
    /// clock, which `Instant` follows, moves no stamp.
    pub fn stamp_ms(&self) -> u64 {
        u64::try_from(self.anchored_ms().max(0)).unwrap_or(u64::MAX)
    }

    /// Keeps `sample` as `source`'s, or forgets `source`'s (none). The one owner of which relays
    /// are clock sources: a configured relay's sample is one, however it was heard; a session's
    /// sample of any other is kept for its health and is none; a probe of any other is kept not
    /// at all, since nothing reads it (a probe's sample is a source's or nothing).
    fn change(&self, source: Source, relay: tally_wire::PublicKey, sample: Option<Sample>) {
        let configured = self.configured.contains(&relay);
        if let Ok(mut samples) = self.samples.lock() {
            match sample {
                Some(sample) if configured || matches!(source, Source::Session(_)) => {
                    samples.insert(
                        source,
                        Kept {
                            relay,
                            sample,
                            source: configured,
                        },
                    );
                }
                Some(_) => {}
                None => {
                    samples.remove(&source);
                }
            }
        }
    }

    /// The offset the batches are signed by now, from the anchored clock, when a majority of the
    /// sources selected one (`Selection::Majority`, `Selection::Few` of fewer than three); else
    /// none (`Selection::NoMajority`). With it, how many relays were sources beside this host, and
    /// whether a configured relay is not among them (a probe could add it).
    fn offset_now(&self) -> (Selection, usize, bool) {
        let now = self.anchored_ms();
        // One source a relay, however many ways it was heard: its tightest interval.
        let mut by_relay: std::collections::HashMap<tally_wire::PublicKey, (i64, i64)> =
            std::collections::HashMap::new();
        if let Ok(samples) = self.samples.lock() {
            // Only a source's sample, as the store kept it (`change`).
            for Kept { relay, sample, .. } in samples.values().filter(|kept| kept.source) {
                let Some(interval) = sample.interval(now) else {
                    continue;
                };
                let width = |(lo, hi): (i64, i64)| hi.saturating_sub(lo);
                by_relay
                    .entry(*relay)
                    .and_modify(|held| {
                        if width(interval) < width(*held) {
                            *held = interval;
                        }
                    })
                    .or_insert(interval);
            }
        }
        let unheard = self
            .configured
            .iter()
            .any(|relay| !by_relay.contains_key(relay));
        let mut intervals: Vec<(i64, i64)> = by_relay.into_values().collect();
        let relays = intervals.len();
        // This host's own clock is a source only while its ClockBound reports it synced within `E`,
        // within that bound: an undisciplined clock never votes, as NTP never votes its local
        // clock (it is read as it is only when nothing is selected, `now_ms`). Before, an
        // unsynced host was a source within `E`, so a Pi an hour off beside one seed made two
        // sources that did not meet, no majority, and signed by its own wrong clock.
        if let Some(error) =
            (self.host.synced)().filter(|error| tally_wire::budget::E.covers(*error))
        {
            let offset = saturated(i128::from((self.host.wall)()) - now);
            let half = i64::try_from(error).unwrap_or(i64::MAX);
            intervals.push((offset.saturating_sub(half), offset.saturating_add(half)));
        }
        // With no configured relay heard, this host alone selects nothing: it is read as it is.
        let selection = match selected(&intervals).filter(|_| relays > 0) {
            Some(offset) if intervals.len() < SELECT_AT_LEAST => Selection::Few(offset),
            Some(offset) => Selection::Majority(offset),
            None => Selection::NoMajority,
        };
        (selection, relays, unheard)
    }

    /// Every relay a session measures now (a live sample within `U_m` from a relay whose error is
    /// within `E`) whose clock the one batches are signed by is outside: by how far (positive
    /// ahead of it, negative behind it). What the feeder's health reports ("your clock disagrees
    /// with relay X by N s"), so an owner sees a wrong clock (theirs or a relay's); it decides no
    /// send.
    pub fn disagreements(&self) -> Vec<(tally_wire::PublicKey, i64)> {
        let signing = i128::from(self.now_ms());
        let now = self.anchored_ms();
        let Ok(samples) = self.samples.lock() else {
            return Vec::new();
        };
        let mut by_relay: std::collections::HashMap<tally_wire::PublicKey, i64> =
            std::collections::HashMap::new();
        for (source, Kept { relay, sample, .. }) in samples.iter() {
            if !matches!(source, Source::Session(_)) {
                continue;
            }
            if let Some(off) = outside(signing, now, sample) {
                // The least of two sessions' measures of one relay.
                by_relay
                    .entry(*relay)
                    .and_modify(|held| {
                        if off.unsigned_abs() < held.unsigned_abs() {
                            *held = off;
                        }
                    })
                    .or_insert(off);
            }
        }
        let mut out: Vec<(tally_wire::PublicKey, i64)> = by_relay.into_iter().collect();
        out.sort_unstable_by_key(|(relay, _)| *relay);
        out
    }

    /// The relays with a live sample now (one whose interval still holds, `Sample::interval`):
    /// a configured relay not among them is probed every round, whatever else the round holds
    /// (`relays::Directory::probe_set`).
    pub fn heard(&self) -> Vec<tally_wire::PublicKey> {
        let now = self.anchored_ms();
        let Ok(samples) = self.samples.lock() else {
            return Vec::new();
        };
        let heard: std::collections::HashSet<tally_wire::PublicKey> = samples
            .values()
            .filter(|kept| kept.sample.interval(now).is_some())
            .map(|kept| kept.relay)
            .collect();
        heard.into_iter().collect()
    }

    /// Whether the batcher has a clock source but its own unsynced host: a configured relay
    /// heard, or this host's clock synced. What the feeder's health reports (`health`).
    pub fn sourced(&self) -> bool {
        self.host_synced() || self.offset_now().1 > 0
    }

    /// This host's ClockBound reports its clock synchronised within `E`.
    fn host_synced(&self) -> bool {
        self.host_bound().is_some()
    }

    /// The bound this host's ClockBound reports its clock synchronised within, while within `E`.
    fn host_bound(&self) -> Option<u64> {
        (self.host.synced)().filter(|error| tally_wire::budget::E.covers(*error))
    }

    /// The clock batches are signed by now (see the type): the low end of its trusted reference
    /// (`reference`), the anchored clock moved by the low end of what its configured sources
    /// selected, or this host's clock less its ClockBound's bound while it reports it synced, so a
    /// batch is never signed ahead of true time. With no selection (RFC 5905: nothing selected),
    /// the publisher is asked to probe (`probing`); with no reference either, it is the low end of
    /// what its configured relays last selected (NTP's holdover), widened by the raw clock's drift
    /// since and dropped once wider than `tally_wire::budget::SELECTION_LAG`
    /// (`tally_wire::budget::held_over`), so a held offset is never ahead of true time nor further
    /// behind than a live selection may be; else this host's clock as read. So a Pi
    /// an hour off between sessions signs by the time its configured relays last agreed, not its
    /// own, and nothing a hinted relay said is ever held.
    pub fn now_ms(&self) -> u64 {
        let held = || {
            let ((lo, hi), at) = self.held_ms.lock().ok().and_then(|held| *held)?;
            let age = u64::try_from(self.anchored_ms() - at).unwrap_or(0);
            tally_wire::budget::held_over(lo, hi, age).map(|(lo, _)| lo)
        };
        let (selection, _, unheard) = self.offset_now();
        // Probes help only while a configured relay is unheard: no other relay's answer is a
        // source. Before, every round under three sources was hastened, forever.
        if unheard && !matches!(selection, Selection::Majority(_)) {
            self.probing.notify_one();
        }
        let chosen = match selection {
            Selection::Majority(interval) | Selection::Few(interval) => Some(interval),
            Selection::NoMajority => None,
        };
        // Every selection holds a heard relay (`offset_now` selects nothing without one), so only
        // such a one is held.
        let offset = match chosen {
            Some((lo, hi)) => {
                if let Ok(mut held) = self.held_ms.lock() {
                    *held = Some(((lo, hi), self.anchored_ms()));
                }
                Some(lo)
            }
            None => {
                if let Some(error) = self.host_bound() {
                    return (self.host.wall)().saturating_sub(error);
                }
                held()
            }
        };
        match offset {
            Some(offset) => {
                u64::try_from((self.anchored_ms() + i128::from(offset)).max(0)).unwrap_or(u64::MAX)
            }
            None => (self.host.wall)(),
        }
    }

    /// Resolves when the sources last read made no majority of three or more while a configured
    /// relay was unheard: the publisher probes sooner then (`relays`), as NTP polls a configured
    /// server until it can select. No other relay's answer is a source, so nothing else hastens
    /// a round.
    pub async fn probing(&self) {
        self.probing.notified().await;
    }
}

/// What the sources select now ([`RelayClocks::offset_now`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selection {
    /// A majority meet, where they do (the low and high ends, offsets from the anchored clock):
    /// the batches are signed at the low end.
    Majority((i64, i64)),
    /// As `Majority`, of fewer than [`SELECT_AT_LEAST`] sources: the feeder probes for more.
    Few((i64, i64)),
    /// No point is covered by a strict majority of the sources: nothing is selected.
    NoMajority,
}

/// Builds one boot's chain of signed batches.
pub struct Batcher {
    identity: Arc<Identity>,
    clock: Clock,
    boot_id: u64,
    sequence: u64,
    counter_epoch: u32,
    previous: Hash,
    observations: Vec<Observation>,
    bytes: usize,
    /// ACARS-family messages, gathered apart: they travel in a batch of their own format
    /// (`tally_wire::batch::BATCH_FORMAT_ACARS`), which no relay that predates them reads.
    acars: Vec<Observation>,
    acars_bytes: usize,
    dropped: u32,
    last_counter: Option<u64>,
    /// The upload ceiling, shared with the ACARS readers (`Ceilings`).
    ceilings: Arc<Ceilings>,
    /// The relays' wanted ceilings this batcher sheds to, and its bucket at the one it last read.
    wanted: Arc<WantedCeilings>,
    wanted_bucket: Option<(u32, TokenBucket)>,
    /// The relays' stated clocks, which it signs its batches' clock by, and their anchors, which
    /// it signs into its batches.
    clocks: Arc<RelayClocks>,
    codec: Codec,
    /// Batches gathered while no session had a fresh anchor (RFC-0171 §3.6), oldest first: each
    /// signed once one does, or unanchored once it has waited `tally_wire::budget::ANCHOR_WAIT`
    /// (what is left of `B` once the backlog's way out is paid for), in order, so the chain runs
    /// as it was made.
    /// Never dropped.
    pending: std::collections::VecDeque<Pending>,
}

/// A batch gathered and not yet signed ([`Batcher::pending`]): its receptions encoded as the wire
/// carries them, compressed (`tally_wire::EncodedBatch`), so the hold costs about its wire bytes
/// and not the owned receptions' several times that; its chain link, which is taken as it is
/// signed; and when it was gathered (the anchored clock).
#[derive(Debug)]
struct Pending {
    batch: EncodedBatch,
    gathered_ms: i128,
}

impl Batcher {
    /// `clock` is the receiver's, which says whether a counter that runs backwards restarted.
    /// `identity` is the feeder's key, which its sessions share (`Arc`).
    pub fn new(identity: impl Into<Arc<Identity>>, ceiling: u32, clock: Clock) -> Self {
        let mut boot = [0; 8];
        // A boot id only has to differ from this receiver's other boots; failing that, the
        // clock does.
        if getrandom::getrandom(&mut boot).is_err() {
            boot = wall_ms().to_be_bytes();
        }
        Self {
            identity: identity.into(),
            clock,
            boot_id: u64::from_be_bytes(boot),
            sequence: 0,
            counter_epoch: 0,
            previous: [0; 32],
            observations: Vec::new(),
            bytes: 0,
            acars: Vec::new(),
            acars_bytes: 0,
            dropped: 0,
            last_counter: None,
            ceilings: Ceilings::new(ceiling, DEFAULT_ACARS_CEILING),
            wanted: Arc::default(),
            wanted_bucket: None,
            clocks: Arc::default(),
            codec: Codec::Deflate,
            pending: std::collections::VecDeque::new(),
        }
    }

    /// As this batcher, its clocks given an anchor that never ages (`RelayClocks::
    /// always_anchored`): a test's that is not about anchors.
    #[cfg(test)]
    pub(crate) fn always_anchored(self) -> Self {
        self.clocks.always_anchored(tally_wire::Anchor::sign(
            &Identity::from_seed([0xa7; 32]),
            wall_ms(),
        ));
        self
    }

    /// The batches it signed with no anchor (`pending`).
    pub fn unanchored(&self) -> u64 {
        self.clocks.unanchored()
    }

    /// The batches gathered and held for an anchor now.
    pub fn held_for_anchor(&self) -> usize {
        self.pending.len()
    }

    /// Holds ACARS-family messages to `bytes_per_sec` of the upload ceiling (`--acars-ceiling`),
    /// dropped and counted past it like anything over the ceiling. Before `ceilings` is shared.
    pub fn holding_acars_to(mut self, bytes_per_sec: u32) -> Self {
        self.ceilings = Ceilings::new(self.ceilings.ceiling, bytes_per_sec);
        self
    }

    /// The ceilings, for the channel its readers offer to (`channel`).
    pub fn ceilings(&self) -> Arc<Ceilings> {
        Arc::clone(&self.ceilings)
    }

    /// Compresses at DEFLATE level `level` instead of the wire's own (`Codec::DeflateAt`).
    pub fn compressing_at(mut self, level: Option<u8>) -> Self {
        if let Some(level) = level {
            self.codec = Codec::DeflateAt(level);
        }
        self
    }

    /// Signs its batches' clock by `clocks` (what the relays it publishes to stated).
    pub fn signing_by(mut self, clocks: Arc<RelayClocks>) -> Self {
        self.clocks = clocks;
        self
    }

    /// Sheds wanted receptions to `ceilings` (what the relays it publishes to stated), counted as
    /// dropped like anything over the owner's ceiling.
    pub fn shedding_to(mut self, ceilings: Arc<WantedCeilings>) -> Self {
        self.wanted = ceilings;
        self
    }

    /// Whether a wanted reception fits under the least ceiling the relays stated now, and takes it.
    /// A second's worth at once, as a relay holds it (`tally_relay::ingest::FEEDER_RECEPTIONS_BURST_SECS`
    /// allows a second more for the batches' arrival). The bucket follows the ceiling as it
    /// changes, keeping what it held.
    fn wanted_fits(&mut self, now: Instant) -> bool {
        let Some(ceiling) = self.wanted.least() else {
            self.wanted_bucket = None;
            return true;
        };
        let bucket = match &mut self.wanted_bucket {
            Some((at, bucket)) if *at == ceiling => bucket,
            held => {
                let mut bucket = TokenBucket::new(ceiling);
                if let Some((_, before)) = held.take() {
                    bucket.tokens = before.tokens.min(bucket.burst);
                    bucket.filled = before.filled;
                }
                &mut held.insert((ceiling, bucket)).1
            }
        };
        bucket.take_at(1, now)
    }

    /// Takes what a reader sent. A batch is returned when the input had to seal one first.
    pub fn take(&mut self, input: Input) -> Result<Option<Batch>, String> {
        match input {
            Input::Frame(frame) => self.observe(&frame),
            Input::Observation(observation) => self.push(observation),
            Input::CounterRestarted => self.counter_restarted(),
        }
    }

    /// The frames one read of a decoder's port gave, as `observe` takes each: every batch that
    /// sealed on the way (a full one) is appended to `sealed`.
    pub fn take_frames(&mut self, frames: &[Frame], sealed: &mut Vec<Batch>) -> Result<(), String> {
        let now = Instant::now();
        for frame in frames {
            sealed.extend(self.observe_at(frame, now)?);
        }
        Ok(())
    }

    /// A 1090 MHz frame. A free-running counter that ran backwards seals what came before it, so
    /// a batch never holds counters from two epochs. A Radarcape's GPS counter is time of day and
    /// runs back every UTC midnight by design, so for it only a reconnect starts an epoch. A frame
    /// with no timestamp (0) says nothing about the counter.
    pub fn observe(&mut self, frame: &Frame) -> Result<Option<Batch>, String> {
        self.observe_at(frame, Instant::now())
    }

    /// As `observe`, with the upload ceiling and the relays' wanted ceiling refilled to `now`: a
    /// reader that hands over what one read decoded reads the clock once for all of it.
    pub fn observe_at(&mut self, frame: &Frame, now: Instant) -> Result<Option<Batch>, String> {
        let counter = frame.timestamp();
        let mut sealed = None;
        if counter != 0 {
            if free_running(self.clock)
                && self
                    .last_counter
                    .is_some_and(|last| last > counter && last - counter > COUNTER_RESTART)
            {
                sealed = self.counter_restarted()?;
            }
            self.last_counter = Some(counter);
        }
        // After a restart the batch is empty, so this reception cannot seal a second one.
        let pushed = self.push_at(Observation::from_beast(frame), now)?;
        Ok(sealed.or(pushed))
    }

    /// A reception of any format, under the ceiling or dropped and counted. If it would take the
    /// batch past what one message carries, what gathered before it is sealed first and returned.
    pub fn push(&mut self, observation: Observation) -> Result<Option<Batch>, String> {
        self.push_at(observation, Instant::now())
    }

    /// As `push`, at `now` (`observe_at`).
    pub fn push_at(
        &mut self,
        observation: Observation,
        now: Instant,
    ) -> Result<Option<Batch>, String> {
        self.push_paying(observation, now, true)
    }

    /// An ACARS-family message `Ceilings::admit_acars` admitted, its bytes already taken from
    /// the ceiling.
    pub fn push_admitted_at(
        &mut self,
        observation: Observation,
        now: Instant,
    ) -> Result<Option<Batch>, String> {
        self.push_paying(observation, now, false)
    }

    fn push_paying(
        &mut self,
        observation: Observation,
        now: Instant,
        pay: bool,
    ) -> Result<Option<Batch>, String> {
        let cost = reception_cost(&observation);
        // A wanted reception past the relays' ceiling is shed here, before it is signed: the
        // relay would drop the batch it took past it.
        let shed = tally_wire::modes::wanted_reception(observation.format, &observation.data)
            && !self.wanted_fits(now);
        if shed || cost > MAX_OBSERVATION_BYTES || (pay && !self.ceilings.take_upload(cost, now)) {
            self.dropped = self.dropped.saturating_add(1);
            return Ok(None);
        }
        let acars = observation.format == tally_wire::batch::format::ACARS_JSON;
        let held = if acars { self.acars_bytes } else { self.bytes };
        let sealed = if held + cost > MAX_OBSERVATION_BYTES {
            self.seal_of(acars)?
        } else {
            None
        };
        if acars {
            self.acars_bytes += cost;
            self.acars.push(observation);
        } else {
            self.bytes += cost;
            self.observations.push(observation);
        }
        Ok(sealed)
    }

    /// Receptions dropped before they reached the batcher, counted with the ceiling's own.
    pub fn add_dropped(&mut self, count: u32) {
        self.dropped = self.dropped.saturating_add(count);
    }

    /// The BEAST source went away or its counter jumped: counters after this are a new epoch.
    /// What gathered under the old epoch is sealed first and returned.
    pub fn counter_restarted(&mut self) -> Result<Option<Batch>, String> {
        let sealed = self.seal_of(false)?;
        self.counter_epoch = self.counter_epoch.wrapping_add(1);
        self.last_counter = None;
        Ok(sealed)
    }

    pub fn is_full(&self) -> bool {
        self.bytes >= MAX_BATCH_BYTES
    }

    /// Signs what has gathered, if anything has: what waited for an anchor first, then the
    /// receptions (and what was dropped), the ACARS-family messages in a batch of their own once
    /// none are left. Called until it signs nothing, it signs everything that has an anchor to
    /// carry, or has waited `ANCHOR_WAIT` for one; the rest waits, in order, for the next call.
    pub fn seal(&mut self) -> Result<Option<Batch>, String> {
        loop {
            if let Some(batch) = self.release()? {
                return Ok(Some(batch));
            }
            let acars = self.observations.is_empty() && !self.acars.is_empty();
            let Some(content) = self.gather(acars) else {
                return Ok(None);
            };
            if let Some(batch) = self.signed_or_held(content)? {
                return Ok(Some(batch));
            }
        }
    }

    /// Signs the ACARS-family messages gathered, or the receptions and what was dropped, or holds
    /// them for an anchor (`signed_or_held`).
    fn seal_of(&mut self, acars: bool) -> Result<Option<Batch>, String> {
        match self.gather(acars) {
            Some(content) => self.signed_or_held(content),
            None => Ok(None),
        }
    }

    /// `content` signed now with the sessions' anchors, when they have one and nothing waits
    /// before it; else held behind what waits, and the oldest of those signed if it may be. At
    /// most [`batches_held`] wait: past it the oldest is signed with what anchors there are (none,
    /// counted), never dropped, so what an anchor's return releases at once is what the sessions'
    /// channel holds (`batch_backlog`).
    fn signed_or_held(&mut self, content: BatchContent) -> Result<Option<Batch>, String> {
        // Encoded once, as it is gathered: what it is held as, and what it is signed from.
        let batch =
            EncodedBatch::encode(&content, self.codec).map_err(|error| error.to_string())?;
        drop(content);
        let anchors = self.clocks.anchors();
        if self.pending.is_empty() && !anchors.is_empty() {
            return self.sign(&batch, &anchors).map(Some);
        }
        let full = self.pending.len() >= batches_held(self.ceilings.ceiling);
        let oldest = if full { self.pending.pop_front() } else { None };
        self.pending.push_back(Pending {
            batch,
            gathered_ms: self.clocks.anchored_ms(),
        });
        match oldest {
            Some(Pending { batch, .. }) => {
                if anchors.is_empty() {
                    self.clocks.signed_unanchored();
                }
                self.sign(&batch, &anchors).map(Some)
            }
            None => self.release(),
        }
    }

    /// The oldest batch waiting for an anchor, signed now whatever it has: what its source's end
    /// leaves (`batch`), so nothing gathered is dropped. None once none waits.
    pub fn finish(&mut self) -> Option<Result<Batch, String>> {
        let Pending { batch, .. } = self.pending.pop_front()?;
        let anchors = self.clocks.anchors();
        if anchors.is_empty() {
            self.clocks.signed_unanchored();
        }
        Some(self.sign(&batch, &anchors))
    }

    /// The oldest batch waiting for an anchor, signed: with the sessions' anchors once they have
    /// one, or with none once it has waited `ANCHOR_WAIT` (a relay holds it, passes it on and uses
    /// it nowhere; counted, `unanchored`). None while it may wait on.
    fn release(&mut self) -> Result<Option<Batch>, String> {
        let Some(oldest) = self.pending.front() else {
            return Ok(None);
        };
        let anchors = self.clocks.anchors();
        let waited = elapsed(oldest.gathered_ms, self.clocks.anchored_ms());
        if anchors.is_empty() && tally_wire::budget::ANCHOR_WAIT.covers(waited) {
            return Ok(None);
        }
        let Some(Pending { batch, .. }) = self.pending.pop_front() else {
            return Ok(None);
        };
        if anchors.is_empty() {
            self.clocks.signed_unanchored();
        }
        self.sign(&batch, &anchors).map(Some)
    }

    /// `batch`, its chain linked to the batch signed before it, signed with `anchors`.
    fn sign(
        &mut self,
        batch: &EncodedBatch,
        anchors: &[tally_wire::Anchor],
    ) -> Result<Batch, String> {
        let batch = Batch::sign_encoded(&self.identity, batch, self.previous, anchors)
            .map_err(|error| error.to_string())?;
        self.previous = batch.hash();
        Ok(batch)
    }

    /// What has gathered, as a batch's content with its sequence taken (its chain link is taken
    /// as it is signed, `sign`): the ACARS-family messages, or the receptions and what was
    /// dropped. None when nothing has.
    fn gather(&mut self, acars: bool) -> Option<BatchContent> {
        let observations = if acars {
            self.acars_bytes = 0;
            std::mem::take(&mut self.acars)
        } else {
            self.bytes = 0;
            std::mem::take(&mut self.observations)
        };
        if observations.is_empty() && (acars || self.dropped == 0) {
            return None;
        }
        // The count dropped rides a batch of receptions alone: a relay that predates the ACARS
        // format reads none of its batches, so would never count it.
        let dropped = if acars {
            0
        } else {
            std::mem::take(&mut self.dropped)
        };
        let content = BatchContent {
            boot_id: self.boot_id,
            sequence: self.sequence,
            counter_epoch: self.counter_epoch,
            // By the clock its relays state, which they judge it by: when it was made.
            wall_ms: self.clocks.now_ms(),
            dropped,
            // Linked as it is signed (`sign`).
            previous: [0; 32],
            observations,
        };
        self.sequence += 1;
        Some(content)
    }
}

/// Whether the counter runs freely from power-on, so that one running backwards means it restarted.
fn free_running(clock: Clock) -> bool {
    matches!(
        clock,
        Clock::Dump1090 | Clock::Beast | Clock::Radarcape12Mhz | Clock::Unknown
    )
}

#[allow(
    clippy::disallowed_methods,
    reason = "the feeder's own host clock (`HostClock::system`), which it signs by until a relay states its own"
)]
pub fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// What a source reader hands the batcher. Every source feeds one batcher, so a receiver's 1090
/// and 978 MHz receptions are one chain: one boot id, one sequence, one upload ceiling.
#[derive(Debug)]
pub enum Input {
    /// A 1090 MHz frame from the BEAST source.
    Frame(Frame),
    /// A reception from a source with no receiver counter (978 MHz UAT, an ACARS-family message;
    /// wall-clock timestamped).
    Observation(Observation),
    /// The BEAST source went away, so its counter may restart: later counters are a new epoch.
    CounterRestarted,
}

/// What crosses the channel: one input, or the frames one read of a decoder's port decoded (one
/// message for all of them, not one each).
enum Message {
    One(Input),
    /// An ACARS-family message (`Inputs::offer_acars`), counted apart (`ACARS_BACKLOG`).
    Acars(Observation),
    Frames(Vec<Frame>),
}

/// A source reader's end of the channel to the batcher.
#[derive(Clone)]
pub struct Inputs {
    sender: mpsc::Sender<Message>,
    overflow: Arc<AtomicU32>,
    /// Receptions sent and not yet taken: the backlog is counted in receptions, whether they
    /// crossed one at a time or a read's worth at once.
    queued: Arc<AtomicU32>,
    /// The batcher's ceilings, which an ACARS message is held to before it is queued.
    ceilings: Arc<Ceilings>,
    /// ACARS-family messages queued and not yet taken (`ACARS_BACKLOG`).
    acars_queued: Arc<AtomicU32>,
}

/// The batcher's end.
pub struct Intake {
    receiver: mpsc::Receiver<Message>,
    overflow: Arc<AtomicU32>,
    queued: Arc<AtomicU32>,
    acars_queued: Arc<AtomicU32>,
}

/// The channel to the batcher that holds `ceilings` (`Batcher::ceilings`).
pub fn channel(ceilings: Arc<Ceilings>) -> (Inputs, Intake) {
    let (sender, receiver) = mpsc::channel(INPUT_BACKLOG);
    let overflow = Arc::new(AtomicU32::new(0));
    let queued = Arc::new(AtomicU32::new(0));
    let acars_queued = Arc::new(AtomicU32::new(0));
    (
        Inputs {
            sender,
            overflow: Arc::clone(&overflow),
            queued: Arc::clone(&queued),
            ceilings,
            acars_queued: Arc::clone(&acars_queued),
        },
        Intake {
            receiver,
            overflow,
            queued,
            acars_queued,
        },
    )
}

impl Inputs {
    /// A reception. If the batcher is behind it is dropped and counted, never waited for: a
    /// reader that waited would buffer in the socket instead, which the ceiling forbids. Public
    /// for a source that is not a decoder's port: the load harness (`tally-load`) offers a
    /// simulated receiver's receptions here, so its batches are this batcher's own.
    pub fn offer(&self, input: Input) {
        self.send(Message::One(input), 1);
    }

    /// An ACARS-family message, held here, before it is queued, to `ACARS_BACKLOG` places in
    /// the queue and to its share of the ceiling (`Ceilings::admit_acars`): past either, it is
    /// dropped and counted as the ceiling's own drops, and a message refused a place spends none
    /// of the share.
    pub fn offer_acars(&self, observation: Observation) {
        let cost = reception_cost(&observation);
        if self.acars_queued.fetch_add(1, Ordering::Relaxed) >= ACARS_BACKLOG
            || !self.ceilings.admit_acars(cost, Instant::now())
        {
            self.acars_queued.fetch_sub(1, Ordering::Relaxed);
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.send(Message::Acars(observation), 1) {
            self.acars_queued.fetch_sub(1, Ordering::Relaxed);
            self.ceilings.refund_acars(cost);
        }
    }

    /// Sends `message` of `count` receptions unless that would put more than `INPUT_BACKLOG`
    /// receptions in the channel: then it is dropped, counted, and this is false.
    fn send(&self, message: Message, count: u32) -> bool {
        let before = self.queued.fetch_add(count, Ordering::Relaxed);
        if before.saturating_add(count) > INPUT_BACKLOG as u32
            || self.sender.try_send(message).is_err()
        {
            self.queued.fetch_sub(count, Ordering::Relaxed);
            self.overflow.fetch_add(count, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// The frames one read decoded, as `offer` takes one: if the batcher is behind, all of them
    /// are dropped and counted.
    pub fn offer_frames(&self, frames: Vec<Frame>) {
        let count = u32::try_from(frames.len()).unwrap_or(u32::MAX);
        if count > 0 {
            self.send(Message::Frames(frames), count);
        }
    }

    /// An epoch change is not a reception and is never dropped.
    async fn counter_restarted(&self) {
        let _ = self
            .sender
            .send(Message::One(Input::CounterRestarted))
            .await;
    }
}

/// Owns the batch chain for as long as the feeder runs: seals once a second or when full, and
/// publishes each sealed batch to `out`.
pub async fn batch(mut batcher: Batcher, mut intake: Intake, out: broadcast::Sender<Arc<Record>>) {
    let mut seal = tokio::time::interval(SEAL_EVERY);
    loop {
        tokio::select! {
            input = intake.receiver.recv() => {
                let Some(input) = input else {
                    flush(&mut batcher, &intake.overflow, &out);
                    // Nothing more comes: what waits for an anchor is signed now, never dropped.
                    while let Some(batch) = batcher.finish() {
                        match batch {
                            Ok(batch) => publish(&out, batch),
                            Err(error) => eprintln!("tally-feed: signing a batch: {error}"),
                        }
                    }
                    return;
                };
                let taken = match &input {
                    Message::One(_) => 1,
                    Message::Acars(_) => {
                        intake.acars_queued.fetch_sub(1, Ordering::Relaxed);
                        1
                    }
                    Message::Frames(frames) => u32::try_from(frames.len()).unwrap_or(u32::MAX),
                };
                intake.queued.fetch_sub(taken, Ordering::Relaxed);
                let one = match input {
                    Message::One(input) => Some(input),
                    Message::Acars(observation) => {
                        match batcher.push_admitted_at(observation, Instant::now()) {
                            Ok(Some(batch)) => publish(&out, batch),
                            Ok(None) => {}
                            Err(error) => eprintln!("tally-feed: signing a batch: {error}"),
                        }
                        None
                    }
                    Message::Frames(frames) => {
                        let mut sealed = Vec::new();
                        if let Err(error) = batcher.take_frames(&frames, &mut sealed) {
                            eprintln!("tally-feed: signing a batch: {error}");
                        }
                        for batch in sealed {
                            publish(&out, batch);
                        }
                        None
                    }
                };
                if let Some(input) = one {
                    match batcher.take(input) {
                        Ok(Some(batch)) => publish(&out, batch),
                        Ok(None) => {}
                        Err(error) => eprintln!("tally-feed: signing a batch: {error}"),
                    }
                }
                if batcher.is_full() {
                    flush(&mut batcher, &intake.overflow, &out);
                }
            }
            _ = seal.tick() => flush(&mut batcher, &intake.overflow, &out),
        }
    }
}

/// Reads readsb's BEAST output for as long as the feeder runs, telling `health` each time it
/// sends bytes.
pub async fn read_beast(address: String, inputs: Inputs, health: Arc<Health>) {
    let mut backoff = Backoff::new();
    let mut refusing = false;
    loop {
        let reading = read_beast_once(&address, &inputs, &health, &mut backoff, &mut refusing);
        if let Err(error) = reading.await {
            eprintln!("tally-feed: source {address}: {error}");
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn read_beast_once(
    address: &str,
    inputs: &Inputs,
    health: &Health,
    backoff: &mut Backoff,
    refusing: &mut bool,
) -> Result<(), String> {
    let stream = connect(address).await?;
    eprintln!("tally-feed: reading {address}");
    let result = read_beast_stream(stream, address, inputs, health, backoff, refusing).await;
    // The counter may restart with the next connection (readsb restarted, or a different one).
    inputs.counter_restarted().await;
    result
}

async fn read_beast_stream(
    mut stream: TcpStream,
    address: &str,
    inputs: &Inputs,
    health: &Health,
    backoff: &mut Backoff,
    refusing: &mut bool,
) -> Result<(), String> {
    let mut decoder = Decoder::new();
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let length = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if length == 0 {
            return Err("closed".to_owned());
        }
        // Only a source that sends anything is a source that works: one that accepts and closes
        // keeps backing off.
        backoff.reset();
        health.source_heard();
        let mut frames = Vec::new();
        decoder.push(&buffer[..length], |frame| {
            if !*refusing {
                frames.push(frame);
            }
        });
        inputs.offer_frames(frames);
        if decoder.is_merged() && !*refusing {
            *refusing = true;
            eprintln!(
                "tally-feed: {address} carries more than one receiver; a feeder publishes one \
                 antenna, so nothing more is published until restart"
            );
        }
    }
}

/// A decoder that writes one reception a line of text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineSource {
    /// dump978-fa's raw output (`--uat`, `uat`).
    Uat,
    /// An ACARS-family decoder's JSON (`--acars`, `acars`).
    Acars,
}

impl LineSource {
    fn name(self) -> &'static str {
        match self {
            Self::Uat => "uat",
            Self::Acars => "acars",
        }
    }

    /// What its lines carry, as a log line names it.
    fn carries(self) -> &'static str {
        match self {
            Self::Uat => "UAT reception",
            Self::Acars => "ACARS, VDL2 or HFDL message",
        }
    }

    fn max_line(self) -> usize {
        match self {
            Self::Uat => uat::MAX_LINE,
            Self::Acars => acars::MAX_LINE,
        }
    }

    fn parse(self, line: &str, now_us: u64) -> Line {
        match self {
            Self::Uat => uat::parse_line(line, now_us),
            Self::Acars => acars::parse_line(line),
        }
    }
}

/// Reads a line-shaped decoder's output for as long as the feeder runs. Its timestamps are wall
/// clock, so a reconnect starts no new counter epoch.
pub async fn read_lines(address: String, inputs: Inputs, source: LineSource) {
    let mut backoff = Backoff::new();
    loop {
        if let Err(error) = read_lines_once(&address, &inputs, source, &mut backoff).await {
            eprintln!("tally-feed: {} source {address}: {error}", source.name());
        }
        tokio::time::sleep(backoff.wait()).await;
    }
}

async fn read_lines_once(
    address: &str,
    inputs: &Inputs,
    source: LineSource,
    backoff: &mut Backoff,
) -> Result<(), String> {
    let mut stream = connect(address).await?;
    eprintln!("tally-feed: reading {address}");
    let mut lines = Lines::new(source.max_line());
    let mut skipped = 0u64;
    let mut not_published = 0u64;
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let length = stream
            .read(&mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if length == 0 {
            return Err(format!(
                "closed ({skipped} unreadable lines skipped, {not_published} frames with no \
                 whole, undamaged message not published)"
            ));
        }
        // As `read_beast_stream`: only a source that sends anything resets the backoff.
        backoff.reset();
        let (mut bad, mut quiet) = (0, 0);
        let unreadable = lines.push(&buffer[..length], |line| {
            match source.parse(line, lines::now_us()) {
                Line::Reception(observation) if source == LineSource::Acars => {
                    inputs.offer_acars(observation);
                }
                Line::Reception(observation) => inputs.offer(Input::Observation(observation)),
                Line::Ignored => {}
                Line::Bad => bad += 1,
                Line::NotPublished => quiet += 1,
            }
        });
        if not_published == 0 && quiet > 0 {
            eprintln!(
                "tally-feed: {address} sent a frame that carries no whole, undamaged {}; such \
                 frames are counted and not published",
                source.carries()
            );
        }
        not_published += quiet;
        if skipped == 0 && bad + unreadable > 0 {
            eprintln!(
                "tally-feed: {address} sent a line that is not a {}; such lines are skipped",
                source.carries()
            );
        }
        skipped += bad + unreadable;
    }
}

/// A decoder's port, with TCP keepalive on: a source that goes quiet (no traffic overhead, a
/// quiet ACARS channel) is told from one whose host went away, which no read would otherwise
/// notice.
async fn connect(address: &str) -> Result<TcpStream, String> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| "connect timed out".to_owned())?
        .map_err(|error| error.to_string())?;
    keepalive(&stream).map_err(|error| format!("keepalive: {error}"))?;
    Ok(stream)
}

/// Probes after a minute idle, every 10 s, 6 times: a peer gone is noticed within two minutes.
/// The system calls are `privilege`'s, the one module here that holds `unsafe` and no key.
fn keepalive(stream: &TcpStream) -> std::io::Result<()> {
    crate::privilege::keepalive(stream)
}

fn flush(batcher: &mut Batcher, overflow: &AtomicU32, out: &broadcast::Sender<Arc<Record>>) {
    batcher.add_dropped(overflow.swap(0, Ordering::Relaxed));
    loop {
        match batcher.seal() {
            Ok(Some(batch)) => publish(out, batch),
            Ok(None) => return,
            Err(error) => return eprintln!("tally-feed: signing a batch: {error}"),
        }
    }
}

fn publish(out: &broadcast::Sender<Arc<Record>>, batch: Batch) {
    // An error only means no relay session is listening right now; the batch is gone, and its
    // sequence number tells everyone downstream so.
    let _ = out.send(Arc::new(Record::Batch(batch)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::FrameKind;

    /// A segment written as ClockBound's daemon writes one at `dir`, its sample taken now, its
    /// bound `bound_ns` and its status `status`, with no VMClock to read beside it.
    fn clock_bound_segment(
        dir: &std::path::Path,
        bound_ns: i64,
        status: clock_bound_shm::ClockStatus,
    ) -> String {
        use clock_bound_shm::{ClockErrorBound, ShmWrite, ShmWriter};
        let path = dir.join("shm0");
        let now =
            clock_bound_shm::common::clock_gettime_safe(clock_bound_shm::common::CLOCK_MONOTONIC)
                .unwrap_or_else(|error| panic!("{error:?}"));
        let later = now + nix::sys::time::TimeSpec::new(1_000, 0);
        let ceb = ClockErrorBound::new(now, later, bound_ns, 0, 50_000, status, false);
        ShmWriter::new(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
            .write(&ceb);
        path.to_string_lossy().into_owned()
    }

    /// A host is a reference only by its ClockBound: synchronised within `E`, it is a source
    /// within its bound and batches are signed at the low end of it; without ClockBound, or with
    /// it free running or too wide, the host is no reference, and with no relay heard the feeder
    /// signs by its own clock as read. Before, the host was a reference by the kernel's
    /// `maxerror`, which no daemon vouches for.
    #[test]
    fn a_host_is_a_reference_only_by_its_clockbound() {
        let dir = std::env::var_os("TEST_TMPDIR")
            .map_or_else(std::env::temp_dir, std::path::PathBuf::from)
            .join(format!("feed_clock_bound_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let vmclock = dir.join("vmclock0").to_string_lossy().into_owned();
        let host = |shm: &str| {
            let reader: &'static tally_wire::clock_bound::Reader =
                Box::leak(Box::new(tally_wire::clock_bound::Reader::at(shm, &vmclock)));
            HostClock::bounded_by(reader)
        };
        let synced = clock_bound_segment(
            &dir.join("synced"),
            4_000_000,
            clock_bound_shm::ClockStatus::Synchronized,
        );
        let free = clock_bound_segment(
            &dir.join("free"),
            4_000_000,
            clock_bound_shm::ClockStatus::FreeRunning,
        );
        let e_ns = i64::try_from(tally_wire::budget::E_MS * 1_000_000).unwrap_or(i64::MAX);
        let wide = clock_bound_segment(
            &dir.join("wide"),
            e_ns + 1,
            clock_bound_shm::ClockStatus::Synchronized,
        );
        let missing = dir.join("none").to_string_lossy().into_owned();

        let bounded = host(&synced);
        let bound = (bounded.synced)();
        assert!(matches!(bound, Some(4..=5)), "{bound:?}");
        let clocks = RelayClocks::on(bounded.clone());
        assert!(clocks.reference().is_some(), "a synced host is a reference");
        let before = (bounded.wall)();
        let signed = clocks.now_ms();
        let after = (bounded.wall)();
        assert!(
            signed + 4 <= after && signed + 6 >= before,
            "signed at {signed}, the wall clock read {before} and {after}"
        );
        for (name, shm) in [("missing", &missing), ("free", &free), ("wide", &wide)] {
            let unbounded = host(shm);
            assert_eq!((unbounded.synced)(), None, "{name}");
            let clocks = RelayClocks::on(unbounded);
            assert!(clocks.reference().is_none(), "{name} is no reference");
            assert!(!clocks.host_synced(), "{name}");
        }
    }

    /// A frame of `counter` whose bytes are a hash of it: what no DEFLATE stream shrinks, so a
    /// batch of them is as large as the ceiling's bytes, as a busy receiver's real traffic nearly
    /// is.
    fn noisy_frame(counter: u64) -> Result<Frame, String> {
        let mut data = [0; 14];
        let mut state = counter.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state.to_le_bytes()[0];
        }
        Frame::new(FrameKind::ModeSLong, counter, 9, &data).map_err(|error| error.to_string())
    }

    fn frame(counter: u64) -> Result<Frame, String> {
        Frame::new(FrameKind::ModeSLong, counter, 9, &[0x8d; 14]).map_err(|error| error.to_string())
    }

    fn batcher(ceiling: u32) -> Result<Batcher, String> {
        clocked(ceiling, Clock::Dump1090)
    }

    fn clocked(ceiling: u32, clock: Clock) -> Result<Batcher, String> {
        Ok(Batcher::new(
            Identity::generate().map_err(|error| error.to_string())?,
            ceiling,
            clock,
        )
        .always_anchored())
    }

    fn content(batch: &Batch) -> Result<BatchContent, String> {
        batch.content().map_err(|error| error.to_string())
    }

    /// A relay key no other in the test has.
    fn fresh_relay() -> tally_wire::PublicKey {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut seed = [7u8; 32];
        seed[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        tally_wire::Identity::from_seed(seed).public()
    }

    /// A relay's greeting answers the session's Hello, so it is a sample within the handshake's
    /// time; a restatement after it comes on the relay's own account, its one-way time unbounded,
    /// so it is no sample: the session's sample goes (the relay's clock stepped) and the session
    /// is told to ask an echo, which then measures the relay by its own round trip. Before, a
    /// restatement was a sample within the handshake's time, however long it had queued.
    #[test]
    fn a_restatement_is_no_sample_and_asks_for_an_echo() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [relay] = seeds();
        let clocks =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([relay]));
        let session = clocks.session(relay);
        // Its Hello went 40 ms ago by the anchored clock.
        let hello = clocks.stamp_ms() - 40;
        assert!(!session.stated(Some(LOCAL + 1_000), Some(0), hello));
        assert_eq!(session.sample(0).map(|sample| sample.half_rtt_ms), Some(40));
        assert_eq!(clocks.now_ms(), LOCAL + 1_000 - 40);
        // The relay steps a second later and restates: no sample, an echo asked.
        monotonic.store(1_000, Ordering::Relaxed);
        assert!(session.stated(Some(LOCAL + 61_000), Some(0), hello));
        assert_eq!(session.sample(1_000), None);
        // The echo measures it.
        let asked = session.asking_ms();
        session.echoed(asked, LOCAL + 61_000, LOCAL + 61_000, Some(0));
        assert_eq!(
            session.sample(1_000).map(|sample| sample.half_rtt_ms),
            Some(0)
        );
        assert_eq!(clocks.now_ms(), LOCAL + 61_000);
    }

    /// One relay is one source, however it is heard: a lying relay this feeder publishes to and
    /// also probes, beside this host's synced clock, is one of two that disagree, no majority, and
    /// the feeder signs by its host, never the liar. Before, its session and its probe were two
    /// sources, and the liar won two of three.
    #[test]
    fn a_relay_heard_through_a_session_and_a_probe_is_one_source() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let liar = fresh_relay();
        // Configured, so its probe answers are a source: still one source with its session.
        let clocks = Arc::new(
            RelayClocks::on(HostClock {
                synced: Arc::new(|| Some(5)),
                ..HostClock::set_by(&wall, &monotonic)
            })
            .configured([liar]),
        );
        let lie = LOCAL + 60_000;
        let session = clocks.session(liar);
        let asked = session.asking_ms();
        session.echoed(asked, lie, lie, Some(0));
        clocks.probed(liar, (asked, lie, lie), Some(0), clocks.stamp_ms());
        // Signed at the low end of its host's bound.
        assert_eq!(clocks.now_ms(), LOCAL - 5, "the liar was followed");
        drop(session);
    }

    /// A relay heard two ways (a session and a probe) is one source at the tighter of its two
    /// intervals, whichever was heard first: here the probe's, narrow and a second ahead of the
    /// session's wide one, so the batches are signed at its low end.
    #[test]
    fn a_relay_heard_two_ways_is_its_tightest_interval() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seed = fresh_relay();
        let clocks =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([seed]));
        let session = clocks.session(seed);
        let asked = session.asking_ms();
        session.echoed(asked, LOCAL, LOCAL, Some(4_000));
        let ahead = LOCAL + 1_000;
        clocks.probed(seed, (asked, ahead, ahead), Some(100), clocks.stamp_ms());
        assert_eq!(clocks.offset_now().1, 1, "one relay, one source");
        assert_eq!(clocks.now_ms(), ahead - 100, "the wider interval was taken");
        drop(session);
    }

    /// A relay session measured by an echo of its clock at `relay_ms` now, with error `error_ms`:
    /// a round trip of nothing (the test's clocks stand still), so its interval is its error.
    /// It is a relay no one configured, one a hint named: no clock source.
    fn measured(clocks: &Arc<RelayClocks>, relay_ms: u64, error_ms: Option<u64>) -> Telling {
        measured_as(clocks, fresh_relay(), relay_ms, error_ms)
    }

    /// As [`measured`], the relay `relay`: a configured one is a clock source.
    fn measured_as(
        clocks: &Arc<RelayClocks>,
        relay: tally_wire::PublicKey,
        relay_ms: u64,
        error_ms: Option<u64>,
    ) -> Telling {
        let session = clocks.session(relay);
        let asked = session.asking_ms();
        session.echoed(asked, relay_ms, relay_ms, error_ms);
        session
    }

    /// `N` relay keys no other in the test has, to configure as seeds.
    fn seeds<const N: usize>() -> [tally_wire::PublicKey; N] {
        std::array::from_fn(|_| fresh_relay())
    }

    /// RFC-0171 §3.6, RFC 5905 §11.2.1: the batcher signs its batches at the low end of where a
    /// majority of its sources' intervals meet (each relay's measured clock, widened by its
    /// uncertainty and its stated error), so no honest relay among them finds a batch ahead of
    /// its clock; a relay off on its own is outvoted; with fewer than three sources a majority is
    /// still selected, and it asks for probes of its unheard configured relays; with no majority
    /// nothing is selected (RFC 5905) and it asks for them too, signing meanwhile by this
    /// host's clock when its ClockBound reports it synced, else by the offset a majority last
    /// selected; this host's clock is a source only while its ClockBound reports it synced; with
    /// every source gone, the offset last taken holds; and with none ever, it signs by its own
    /// clock. Before, no majority signed at the lowest end any source allowed, so one relay far
    /// behind dragged every batch back with it.
    ///
    /// This host's clock is unsynced here until the last part, so it is no source: the relays
    /// alone vote.
    #[test]
    fn a_batch_is_signed_where_a_majority_of_its_sources_meet() -> Result<(), String> {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        // A configured seed never heard: probes are asked for while too few sources meet.
        let unheard = fresh_relay();
        // The relays this feeder publishes to, configured (`--relay`): its clock sources.
        let [ka, kb, kc, kfar] = seeds();
        let clocks = Arc::new(
            RelayClocks::on(HostClock::set_by(&wall, &monotonic))
                .configured([unheard, ka, kb, kc, kfar]),
        );
        let mut batcher = batcher(10_000_000)?
            .signing_by(Arc::clone(&clocks))
            .always_anchored();
        let reception = Observation {
            format: tally_wire::batch::format::MODE_S_LONG,
            timestamp: 1,
            signal: 9,
            data: vec![0x8d; 14],
        };
        let signed = |batcher: &mut Batcher| -> Result<u64, String> {
            batcher.push(reception.clone())?;
            Ok(content(&batcher.seal()?.ok_or("no batch")?)?.wall_ms)
        };
        let e = tally_wire::budget::E
            .span::<tally_wire::clocks::Judged>()
            .ms();
        // This host alone, unsynced: no configured relay heard, so nothing is selected and it
        // signs by its own clock as read (RFC 5905: no system peer).
        assert_eq!(signed(&mut batcher)?, LOCAL, "its own clock");
        // Three relays within their errors of each other (none stated: `E` each): signed at the
        // low end of the span two of three cover, the second of their low ends.
        let a = measured_as(&clocks, ka, LOCAL + 3_000, None);
        let b = measured_as(&clocks, kb, LOCAL - 2_000, None);
        let c = measured_as(&clocks, kc, LOCAL + 1_000, None);
        assert_eq!(signed(&mut batcher)?, LOCAL + 1_000 - e);
        // A relay an hour off that is no configured source moves nothing.
        let astray = measured(&clocks, LOCAL + 3_600_000, None);
        assert_eq!(signed(&mut batcher)?, LOCAL + 1_000 - e);
        // A relay whose error is past `E` is selected by no one.
        let unbounded = measured(&clocks, LOCAL - 100_000, Some(u64::MAX));
        assert_eq!(signed(&mut batcher)?, LOCAL + 1_000 - e);
        drop((astray, unbounded, c, b));
        // One relay alone: a majority of one, selected, and probes asked for, since one wrong
        // source could not be outvoted.
        let probing = clocks.probing();
        tokio::pin!(probing);
        assert_eq!(signed(&mut batcher)?, LOCAL + 3_000 - e);
        assert!(
            futures_ready(probing.as_mut()),
            "no probe was asked for with two sources"
        );
        // A second relay far from the first: two that do not meet, no majority, nothing selected.
        // Signed by the offset the relays last selected (this host's clock is not synced), never
        // by the lower of the two.
        let probing = clocks.probing();
        tokio::pin!(probing);
        let far = measured_as(&clocks, kfar, LOCAL - 100_000, None);
        assert_eq!(signed(&mut batcher)?, LOCAL + 3_000 - e);
        assert!(
            futures_ready(probing.as_mut()),
            "no probe was asked for without a majority"
        );
        // Every relay gone: this host alone, unsynced, is held over by the offset the relays
        // last selected, never its own clock.
        drop((a, far));
        assert_eq!(signed(&mut batcher)?, LOCAL + 3_000 - e);
        // Five sources, two of which meet far from this host and two far apart on their own:
        // the largest set that meets is two of five, no majority. Nothing ever selected: signed
        // by this host's clock, never by the lowest any allows nor where the pair meet, and
        // probes asked for.
        let split =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([unheard]));
        let split_probing = split.probing();
        tokio::pin!(split_probing);
        let pair = (
            measured(&split, LOCAL + 50_000, None),
            measured(&split, LOCAL + 51_000, None),
            measured(&split, LOCAL + 100_000, None),
            measured(&split, LOCAL - 100_000, None),
        );
        assert_eq!(split.now_ms(), LOCAL, "a minority was signed by");
        assert!(
            futures_ready(split_probing.as_mut()),
            "no probe was asked for without a majority"
        );
        drop(pair);
        // This host's clock, synced, is a source within its ClockBound's bound.
        let [k1, k2, k3, kx, ky] = seeds();
        let synced = Arc::new(
            RelayClocks::on(HostClock {
                synced: Arc::new(|| Some(5)),
                ..HostClock::set_by(&wall, &monotonic)
            })
            .configured([k1, k2, k3, kx, ky]),
        );
        let (x, y) = (
            measured_as(&synced, kx, LOCAL + 1_000, Some(10)),
            measured_as(&synced, ky, LOCAL - 1_000, Some(1_000)),
        );
        assert_eq!(synced.now_ms(), LOCAL - 5, "a synced host is a source");
        drop((x, y));
        // A majority selected far from this host, then lost: with this host synced, it signs by
        // this host's clock, not the offset held.
        let distant = (
            measured_as(&synced, k1, LOCAL + 50_000, None),
            measured_as(&synced, k2, LOCAL + 50_000, None),
            measured_as(&synced, k3, LOCAL + 50_000, None),
        );
        assert_eq!(synced.now_ms(), LOCAL + 50_000 - e);
        let lone = measured(&synced, LOCAL - 100_000, None);
        drop((distant.1, distant.2));
        assert_eq!(
            synced.now_ms(),
            LOCAL - 5,
            "no majority, a synced host's low end"
        );
        drop((distant.0, lone));
        Ok(())
    }

    /// A majority that covers two regions apart selects the span over both, never nothing: here
    /// this host's interval (synced, within `E`) meets each of two relays that do not meet each
    /// other, two regions of two of three, and the host's interval covers both. The batches are
    /// signed at the span's low end, the low relay's. Before, the two were a tie, nothing was
    /// selected, and the feeder signed at its host's low end.
    #[test]
    fn majority_regions_apart_select_the_span_over_both() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [kl, kh] = seeds();
        let clocks = Arc::new(
            RelayClocks::on(HostClock {
                synced: Arc::new(|| {
                    Some(
                        tally_wire::budget::E
                            .span::<tally_wire::clocks::Judged>()
                            .ms(),
                    )
                }),
                ..HostClock::set_by(&wall, &monotonic)
            })
            .configured([kl, kh]),
        );
        let low = measured_as(&clocks, kl, LOCAL - 6_000, Some(1_000));
        let high = measured_as(&clocks, kh, LOCAL + 6_000, Some(1_000));
        let Selection::Majority((lo, hi)) = clocks.offset_now().0 else {
            panic!("nothing selected");
        };
        // Each relay's interval is its offset within its error (an echo of no round trip).
        assert_eq!((lo, hi), (-7_000, 7_000));
        assert_eq!(clocks.now_ms(), LOCAL - 7_000);
        drop((low, high));
    }

    /// RFC-0171 §3.6: a feeder's clock sources are configured, never discovered. A probe answer
    /// from a relay a hint named is no source, however many keys answer alike: a flood of fresh
    /// keys an hour ahead moves nothing it signs by. A configured relay's probe answer is one.
    /// Before, every probe answer with a clock was a source, and a hint naming enough fresh keys
    /// outvoted the feeder's relays.
    #[test]
    fn fresh_hinted_keys_cannot_move_the_clock() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seed = fresh_relay();
        let clocks = Arc::new(
            RelayClocks::on(HostClock {
                synced: Arc::new(|| Some(5)),
                ..HostClock::set_by(&wall, &monotonic)
            })
            .configured([seed]),
        );
        let ahead = LOCAL + 3_600_000;
        for _ in 0..64 {
            clocks.probed(
                fresh_relay(),
                (LOCAL, ahead, ahead),
                Some(0),
                clocks.stamp_ms(),
            );
        }
        assert_eq!(clocks.now_ms(), LOCAL - 5, "a hinted key moved the clock");
        // Nor are they kept: nothing reads a hinted relay's probe answer, so it would only grow.
        assert_eq!(
            clocks.samples.lock().map(|samples| samples.len()).ok(),
            Some(0),
            "a hinted key's probe answer was kept"
        );
        // Two sources at most while the seed is unheard: a probe is asked for, to hear it.
        let probing = clocks.probing();
        tokio::pin!(probing);
        let _ = clocks.now_ms();
        assert!(futures_ready(probing.as_mut()), "the seed was never asked");
        // A configured relay's answer is a source: it and this host meet.
        clocks.probed(
            seed,
            (LOCAL, LOCAL + 2, LOCAL + 2),
            Some(0),
            clocks.stamp_ms(),
        );
        assert_eq!(clocks.now_ms(), LOCAL + 2, "a configured relay is a source");
        // Every configured relay heard: no probe can add a source, so none is hastened, however
        // few the sources. Before, a round came every 30 s forever under three.
        let probing = clocks.probing();
        tokio::pin!(probing);
        let _ = clocks.now_ms();
        assert!(
            !futures_ready(probing.as_mut()),
            "a probe was hastened that no answer could serve"
        );
    }

    /// An unsynced host is no source (RFC 5905: an undisciplined local clock never votes), so one
    /// configured relay this feeder holds a session with is its one source and is followed, as
    /// NTP follows its one configured server. Its sample goes with its session: once it ends,
    /// the relay is no source, and its selection is held over.
    #[test]
    fn one_configured_relay_beside_an_unsynced_host_is_followed_and_leaves_with_its_session() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [held] = seeds();
        let clocks =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([held]));
        let relay = measured_as(&clocks, held, LOCAL + 600_000, Some(0));
        assert_eq!(clocks.now_ms(), LOCAL + 600_000);
        assert_eq!(clocks.offset_now().1, 1);
        drop(relay);
        assert_eq!(clocks.offset_now().1, 0, "a session's sample outlived it");
        assert_eq!(
            clocks.now_ms(),
            LOCAL + 600_000,
            "its selection was not held"
        );
    }

    /// The round 14 sweep's case: a Pi whose clock is an hour behind, unsynced, with one seed. It
    /// signs by the seed, its one source. Before, the unsynced host was a source within `E`: it
    /// and the seed did not meet, no majority, and the Pi signed by its own clock an hour behind
    /// (and its sessions then withheld every batch as too old).
    #[test]
    fn a_pi_an_hour_behind_with_one_seed_signs_by_the_seed() {
        const REAL: u64 = 1_800_000_000_000;
        const HOUR: u64 = 3_600_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(REAL - HOUR));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [seed] = seeds();
        let clocks =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([seed]));
        assert_eq!(
            clocks.now_ms(),
            REAL - HOUR,
            "nothing heard: its own clock as read"
        );
        let heard = measured_as(&clocks, seed, REAL, Some(0));
        assert_eq!(clocks.now_ms(), REAL, "the seed was not followed");
        drop(heard);
    }

    /// While no session has an anchor, what the batcher holds for one costs about its batches'
    /// wire bytes (`tally_wire::EncodedBatch`), within `held_bytes`, and an anchor's return moves
    /// the hold into the channel to the sessions without holding it twice, even with a session
    /// that reads nothing keeping every batch there. Before, a held batch was its owned
    /// receptions, some 3.4 times its wire bytes, so at 256 kB/s a minute's hold took the feeder
    /// 46 MB past its start, past the unit's `MemoryMax`, and the kernel killed it.
    #[test]
    fn a_hold_for_an_anchor_costs_its_wire_bytes() -> Result<(), String> {
        const CEILING: u32 = 64_000;
        const AT: u64 = 1_800_000_000_000;
        let error = |error: tally_wire::WireError| error.to_string();
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let mut batcher = Batcher::new(
            Identity::generate().map_err(error)?,
            CEILING,
            Clock::Dump1090,
        )
        .signing_by(Arc::clone(&clocks));
        // A session that reads nothing: the channel keeps every batch it is sent.
        let (out, _unread) = crate::batch_channel(CEILING);
        let overflow = AtomicU32::new(0);
        let start = Instant::now();
        let cost = reception_cost(&Observation::from_beast(&frame(1)?));
        // The ceiling's second in tenths, every reception unlike the last, so nothing compresses.
        let per_tick = CEILING as usize / cost / 10;
        let relay = Identity::from_seed([33; 32]);
        let heard = clocks.session(relay.public());
        let base = tally_counting::Counting::peak_base();
        let mut counter = 1;
        let mut held_most = 0;
        for tick in 0..66 * 10u64 {
            let ms = tick * 100;
            wall.store(AT + ms, Ordering::Relaxed);
            monotonic.store(ms, Ordering::Relaxed);
            // The anchor comes back at the end of the longest hold.
            if ms == 62_000 {
                held_most = tally_counting::Counting::since(base);
                assert!(batcher.held_for_anchor() > 60, "nothing was held");
                assert!(heard.anchored(tally_wire::Anchor::sign(&relay, AT + ms)));
            }
            let now = start + Duration::from_millis(ms);
            for _ in 0..per_tick {
                counter += 1;
                if let Some(batch) = batcher.observe_at(&noisy_frame(counter)?, now)? {
                    publish(&out, batch);
                }
                if batcher.is_full() {
                    flush(&mut batcher, &overflow, &out);
                }
            }
            if ms % 1_000 == 0 {
                flush(&mut batcher, &overflow, &out);
            }
            if ms == 62_000 {
                assert_eq!(batcher.held_for_anchor(), 0, "the anchor released the hold");
            }
        }
        let peak = tally_counting::Counting::peak_since(base);
        assert_eq!(batcher.unanchored(), 0, "a batch was signed with no anchor");
        // 62 s of the ceiling's receptions held, as their wire bytes and a little more.
        let wire = |seconds: isize| seconds * CEILING as isize;
        assert!(
            held_most >= wire(62) / 2 && held_most <= wire(62) * 5 / 4,
            "held {held_most} bytes for {} of wire bytes",
            wire(62)
        );
        // The drain moved the hold into the channel: what it holds at the end is all 66 s, once.
        assert!(
            peak <= wire(66) * 5 / 4,
            "held at most {peak} bytes for {} of wire bytes",
            wire(66)
        );
        assert!(peak as u64 <= held_bytes(CEILING), "{peak} past held_bytes");
        Ok(())
    }

    /// A batcher on its own clocks, set by `wall` and `monotonic`, with no anchor yet.
    fn unanchored_batcher(
        wall: &Arc<std::sync::atomic::AtomicU64>,
        monotonic: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<(Batcher, Arc<RelayClocks>), String> {
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(wall, monotonic)));
        let batcher = Batcher::new(
            Identity::generate().map_err(|error| error.to_string())?,
            1_000_000,
            Clock::Dump1090,
        )
        .signing_by(Arc::clone(&clocks));
        Ok((batcher, clocks))
    }

    /// RFC-0171 §3.6: before its first anchor a feeder holds what it gathers, unsigned, and drops
    /// none of it. Once a session hears its relay's anchor, everything held is signed in the order
    /// it was gathered, each carrying that anchor and its own gathered time, the chain unbroken;
    /// what comes after is signed at once.
    #[test]
    fn a_feeder_holds_its_batches_until_its_first_anchor_and_drops_none() -> Result<(), String> {
        const AT: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (mut batcher, clocks) = unanchored_batcher(&wall, &monotonic)?;
        for second in 0..5u64 {
            wall.store(AT + second * 1_000, Ordering::Relaxed);
            monotonic.store(second * 1_000, Ordering::Relaxed);
            batcher.observe(&frame(1_000 + second)?)?;
            assert!(batcher.seal()?.is_none(), "signed with no anchor");
        }
        assert_eq!(batcher.held_for_anchor(), 5);
        let relay = Identity::from_seed([31; 32]);
        let session = clocks.session(relay.public());
        let anchor = tally_wire::Anchor::sign(&relay, AT + 4_500);
        assert!(session.anchored(anchor));
        let mut signed = Vec::new();
        while let Some(batch) = batcher.seal()? {
            signed.push(batch);
        }
        assert_eq!(signed.len(), 5);
        let mut previous = [0; 32];
        for (sequence, batch) in signed.iter().enumerate() {
            batch.verify().map_err(|error| error.to_string())?;
            assert_eq!(
                batch.anchors().map_err(|error| error.to_string())?,
                [anchor]
            );
            let content = content(batch)?;
            assert_eq!(content.sequence, sequence as u64);
            assert_eq!(content.wall_ms, AT + sequence as u64 * 1_000);
            assert_eq!(content.previous, previous);
            previous = batch.hash();
        }
        batcher.observe(&frame(9_000)?)?;
        let next = batcher.seal()?.ok_or("not signed at once")?;
        assert_eq!(content(&next)?.previous, previous);
        assert_eq!(batcher.unanchored(), 0);
        drop(session);
        Ok(())
    }

    /// RFC-0171 §3.6: a batcher at its ceiling with no anchor holds what it gathers, and once the
    /// oldest has waited the longest it holds any (`ANCHOR_WAIT`) an anchor returns and everything
    /// held goes into the sessions' channel at once, the very channel `publish` builds
    /// (`crate::batch_channel`), sized for that burst. A session that relay asked nothing of
    /// drains it at its pace, the ceiling as the batcher signs at it (`relays::Pace`), while the
    /// receiver goes on hearing at the ceiling. Every batch reaches the relay, in order, lagged by
    /// none, at most `B` after it was gathered, so within `FEEDER_BEHIND` where it publishes; and
    /// no second sends more than the pace and its burst. Before, the channel held 64 and lagged
    /// the session past most of the backlog; the hold was all of `B`, so the backlog's way out
    /// took the oldest past it; and the release went out at once, over the ceiling.
    #[test]
    fn a_backlog_an_anchor_releases_drains_at_the_ceiling_within_b() -> Result<(), String> {
        const AT: u64 = 1_800_000_000_000;
        const CEILING: u32 = 64_000;
        const TICK_MS: u64 = 100;
        let ms = |tolerance: tally_wire::budget::Tolerance| {
            tolerance.span::<tally_wire::clocks::Judged>().ms()
        };
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let mut batcher = Batcher::new(
            Identity::generate().map_err(|error| error.to_string())?,
            CEILING,
            Clock::Dump1090,
        )
        .signing_by(Arc::clone(&clocks));
        let (out, mut channel) = crate::batch_channel(CEILING);
        let mut pace =
            crate::relays::Pace::new(CEILING, Arc::new(WantedCeilings::default()).session());
        let overflow = AtomicU32::new(0);
        let start = Instant::now();
        let per_tick = CEILING as usize / reception_cost(&Observation::from_beast(&frame(1)?))
            * TICK_MS as usize
            / 1_000;
        let relay = Identity::from_seed([33; 32]);
        let heard = clocks.session(relay.public());
        // The anchor returns as the oldest held has waited the longest it may.
        let returns_ms = ms(tally_wire::budget::ANCHOR_WAIT);
        let hearing_until_ms = returns_ms + 40_000;
        let (mut counter, mut most_held) = (1, 0);
        // The session: the batch in hand and when it goes, when the one before it went, every
        // batch's age as it went and its sequence, and the bytes sent each second.
        let mut in_hand: Option<(Arc<Record>, Instant)> = None;
        let mut free = start;
        let mut landed: Vec<(u64, u64)> = Vec::new();
        let mut per_second: std::collections::BTreeMap<u64, usize> = Default::default();
        let mut tick_ms = 0;
        while tick_ms <= hearing_until_ms + 120_000
            && (tick_ms <= hearing_until_ms || in_hand.is_some() || !channel.is_empty())
        {
            wall.store(AT + tick_ms, Ordering::Relaxed);
            monotonic.store(tick_ms, Ordering::Relaxed);
            let now = start + Duration::from_millis(tick_ms);
            if tick_ms >= returns_ms && tick_ms % 1_000 == 0 {
                // A relay states a fresh anchor every second once it is back.
                heard.anchored(tally_wire::Anchor::sign(&relay, AT + tick_ms));
            }
            if tick_ms <= hearing_until_ms {
                for _ in 0..per_tick {
                    counter += 1;
                    if let Some(batch) = batcher.observe_at(&noisy_frame(counter)?, now)? {
                        publish(&out, batch);
                    }
                    if batcher.is_full() {
                        flush(&mut batcher, &overflow, &out);
                    }
                }
                if tick_ms % 1_000 == 0 {
                    flush(&mut batcher, &overflow, &out);
                }
            }
            most_held = most_held.max(batcher.held_for_anchor());
            // The session sends what its pace lets go by now, in order.
            loop {
                let (record, goes) = match in_hand.take() {
                    Some(held) => held,
                    None => match channel.try_recv() {
                        Ok(record) => {
                            let Record::Batch(batch) = &*record else {
                                return Err("not a batch".into());
                            };
                            let bytes = batch.as_bytes().len();
                            let mut goes = free.max(now);
                            loop {
                                let wait = pace.wait(bytes, goes);
                                if wait.is_zero() {
                                    break;
                                }
                                goes += wait;
                            }
                            (record, goes)
                        }
                        Err(broadcast::error::TryRecvError::Empty) => break,
                        Err(error) => {
                            return Err(format!("{error} after {} batches", landed.len()));
                        }
                    },
                };
                if goes > now {
                    in_hand = Some((record, goes));
                    break;
                }
                let Record::Batch(batch) = &*record else {
                    return Err("not a batch".into());
                };
                free = goes;
                let went_ms =
                    AT + u64::try_from(goes.duration_since(start).as_millis()).unwrap_or(u64::MAX);
                let content = content(batch)?;
                landed.push((content.sequence, went_ms.saturating_sub(content.wall_ms)));
                *per_second.entry((went_ms - AT) / 1_000).or_default() += batch.as_bytes().len();
            }
            tick_ms += TICK_MS;
        }
        assert!(most_held > 64, "only {most_held} held: no burst");
        assert!(most_held <= batches_held(CEILING));
        assert!(
            in_hand.is_none() && channel.is_empty(),
            "the backlog never drained"
        );
        // Every batch, in order, none lost.
        assert!(landed.len() > most_held);
        assert!(
            landed
                .iter()
                .enumerate()
                .all(|(at, (sequence, _))| *sequence == at as u64)
        );
        // Each within `B` of its gathering, the oldest held among them.
        let oldest = landed.iter().map(|(_, age)| *age).max().unwrap_or_default();
        assert!(
            oldest >= returns_ms - 1_000,
            "nothing was held: {oldest} ms"
        );
        assert!(
            oldest <= ms(tally_wire::budget::B),
            "a batch went {oldest} ms after it was gathered"
        );
        // And no second over the pace: what the batcher signs a second at the ceiling, and the
        // second's burst the pace starts with.
        let most = u64::from(signed_most(CEILING)) as usize;
        assert!(
            per_second.values().all(|bytes| *bytes <= 2 * most),
            "{per_second:?}"
        );
        assert_eq!(batcher.unanchored(), 0);
        drop(heard);
        Ok(())
    }

    /// A batcher holds at most `batches_held` for an anchor: one gathered past it (a source that
    /// restarts its counter faster than the batcher seals) has the oldest signed with no anchor,
    /// counted, in order, never dropped, so an anchor's return never releases more than the
    /// sessions' channel holds (`batch_backlog`).
    #[test]
    fn a_batcher_holds_no_more_for_an_anchor_than_its_sessions_channel_holds() -> Result<(), String>
    {
        const CEILING: u32 = 1_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(1_800_000_000_000));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let mut batcher = Batcher::new(
            Identity::generate().map_err(|error| error.to_string())?,
            CEILING,
            Clock::Dump1090,
        )
        .signing_by(clocks);
        let most = batches_held(CEILING);
        assert!(most + SEAL_KINDS <= batch_backlog(CEILING));
        let start = Instant::now();
        let mut signed = Vec::new();
        for n in 0..most as u64 + 3 {
            batcher.observe_at(&frame(n + 1)?, start + Duration::from_secs(n))?;
            if let Some(batch) = batcher.counter_restarted()? {
                signed.push(batch);
            }
            assert!(batcher.held_for_anchor() <= most);
        }
        assert_eq!(batcher.held_for_anchor(), most);
        assert_eq!(signed.len(), 3);
        for (sequence, batch) in signed.iter().enumerate() {
            assert_eq!(content(batch)?.sequence, sequence as u64);
            assert!(
                batch
                    .anchors()
                    .map_err(|error| error.to_string())?
                    .is_empty()
            );
        }
        assert_eq!(batcher.unanchored(), 3);
        Ok(())
    }

    /// RFC-0171 §3.6: a batch that has waited `ANCHOR_WAIT` for an anchor is signed with none,
    /// never dropped, and counted (a relay holds it and passes it on, and no hop uses it); so is what is held when
    /// the feeder's source ends. A session's anchor goes with it, and one heard longer ago than a
    /// feeder signs by (`ANCHOR_HELD_MS`) is not put in a batch.
    #[test]
    fn a_batch_that_waited_its_backlog_is_signed_unanchored_and_counted() -> Result<(), String> {
        const AT: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (mut batcher, clocks) = unanchored_batcher(&wall, &monotonic)?;
        batcher.observe(&frame(1_000)?)?;
        assert!(batcher.seal()?.is_none());
        monotonic.store(
            tally_wire::budget::ANCHOR_WAIT
                .span::<tally_wire::clocks::Judged>()
                .ms(),
            Ordering::Relaxed,
        );
        assert!(
            batcher.seal()?.is_none(),
            "signed before it waited ANCHOR_WAIT"
        );
        monotonic.store(
            tally_wire::budget::ANCHOR_WAIT
                .span::<tally_wire::clocks::Judged>()
                .ms()
                + 1,
            Ordering::Relaxed,
        );
        let waited = batcher.seal()?.ok_or("held past ANCHOR_WAIT")?;
        assert!(waited.is_anchored());
        assert!(
            waited
                .anchors()
                .map_err(|error| error.to_string())?
                .is_empty()
        );
        assert_eq!(batcher.unanchored(), 1);
        // An anchor heard, then its session gone: not used.
        let relay = Identity::from_seed([32; 32]);
        let session = clocks.session(relay.public());
        assert!(session.anchored(tally_wire::Anchor::sign(&relay, AT)));
        assert_eq!(clocks.anchors().len(), 1);
        drop(session);
        assert!(clocks.anchors().is_empty());
        // An anchor heard longer ago than a feeder signs by: not used.
        let session = clocks.session(relay.public());
        assert!(session.anchored(tally_wire::Anchor::sign(&relay, AT + 1)));
        let heard = tally_wire::budget::ANCHOR_WAIT
            .span::<tally_wire::clocks::Judged>()
            .ms()
            + 1;
        monotonic.store(
            heard
                + tally_wire::budget::ANCHOR_HELD
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            Ordering::Relaxed,
        );
        assert_eq!(clocks.anchors().len(), 1);
        monotonic.store(
            heard
                + tally_wire::budget::ANCHOR_HELD
                    .span::<tally_wire::clocks::Judged>()
                    .ms()
                + 1,
            Ordering::Relaxed,
        );
        assert!(clocks.anchors().is_empty());
        // What is held when the source ends is signed, whatever it has.
        batcher.observe(&frame(2_000)?)?;
        assert!(batcher.seal()?.is_none());
        let last = batcher.finish().ok_or("nothing held")??;
        assert_eq!(content(&last)?.previous, waited.hash());
        assert!(batcher.finish().is_none());
        assert_eq!(batcher.unanchored(), 2);
        drop(session);
        Ok(())
    }

    /// RFC-0171 §3.6: a session keeps only its own relay's anchors whose signature verifies, the
    /// one heard last (not the highest reading: a relay stepped back states a lower one); a batch
    /// carries one a relay, the last two heard.
    #[test]
    fn a_session_keeps_only_its_relays_signed_anchors() {
        const AT: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let relays: Vec<Identity> = (40..43)
            .map(|seed| Identity::from_seed([seed; 32]))
            .collect();
        let sessions: Vec<Telling> = relays
            .iter()
            .map(|relay| clocks.session(relay.public()))
            .collect();
        // Another relay's anchor, and a forged one: refused.
        assert!(!sessions[0].anchored(tally_wire::Anchor::sign(&relays[1], AT)));
        let mut forged = tally_wire::Anchor::sign(&relays[0], AT);
        forged.j_ms += 1;
        assert!(!sessions[0].anchored(forged));
        // Its own, then a lower reading heard after it: the one heard last kept.
        assert!(sessions[0].anchored(tally_wire::Anchor::sign(&relays[0], AT - 2_000)));
        monotonic.store(1, Ordering::Relaxed);
        assert!(sessions[0].anchored(tally_wire::Anchor::sign(&relays[0], AT - 3_000)));
        monotonic.store(2, Ordering::Relaxed);
        assert!(sessions[1].anchored(tally_wire::Anchor::sign(&relays[1], AT - 1_000)));
        monotonic.store(3, Ordering::Relaxed);
        assert!(sessions[2].anchored(tally_wire::Anchor::sign(&relays[2], AT - 4_000)));
        // A second session to the first relay: still one of its anchors.
        monotonic.store(4, Ordering::Relaxed);
        let again = clocks.session(relays[0].public());
        assert!(again.anchored(tally_wire::Anchor::sign(&relays[0], AT - 5_000)));
        let carried: Vec<u64> = clocks.anchors().iter().map(|anchor| anchor.j_ms).collect();
        assert_eq!(carried, [AT - 5_000, AT - 4_000]);
        drop((sessions, again));
        assert!(clocks.anchors().is_empty());
    }

    /// RFC-0171 §3.6: the same anchor stated again (a relay greets each session with its newest)
    /// is not heard anew: its age counts from when it was first heard, so it leaves the batches
    /// `ANCHOR_HELD_MS` after that however often it is stated. Before, each statement made it new
    /// again, so an anchor stated a period late was older than `W_a` allowed.
    #[test]
    fn an_anchor_stated_again_is_not_heard_anew() {
        const AT: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let relay = Identity::from_seed([44; 32]);
        let session = clocks.session(relay.public());
        let anchor = tally_wire::Anchor::sign(&relay, AT);
        assert!(session.anchored(anchor));
        monotonic.store(
            tally_wire::budget::ANCHOR_HELD
                .span::<tally_wire::clocks::Judged>()
                .ms(),
            Ordering::Relaxed,
        );
        assert!(!session.anchored(anchor), "the same anchor heard anew");
        assert_eq!(clocks.anchors(), [anchor]);
        monotonic.store(
            tally_wire::budget::ANCHOR_HELD
                .span::<tally_wire::clocks::Judged>()
                .ms()
                + 1,
            Ordering::Relaxed,
        );
        assert!(clocks.anchors().is_empty());
    }

    /// RFC-0171 §3.6: with a trusted reference (here its host, synced within 5 ms), the feeder
    /// carries only the anchors that agree with the reference's whole interval. One relay states
    /// an anchor 94 s old: left out, and its health says by how far it is below the interval; the
    /// honest relay's is carried. An anchor at the edges of what an honest relay's can be
    /// (`E` above the interval's high end, `E + P + δ` below its low end) is carried, a
    /// millisecond past either is not. When none agrees, none is carried: there is no fallback
    /// to the nearest.
    #[test]
    fn with_a_trusted_clock_a_feeder_leaves_out_an_anchor_that_disagrees() {
        const AT: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock {
            synced: Arc::new(|| Some(5)),
            ..HostClock::set_by(&wall, &monotonic)
        }));
        let (honest, liar) = (Identity::from_seed([45; 32]), Identity::from_seed([46; 32]));
        let (to_honest, to_liar) = (
            clocks.session(honest.public()),
            clocks.session(liar.public()),
        );
        let fresh = tally_wire::Anchor::sign(&honest, AT);
        let stale = tally_wire::Anchor::sign(&liar, AT - 94_000);
        assert!(to_honest.anchored(fresh));
        assert!(to_liar.anchored(stale));
        assert_eq!(clocks.anchors(), [fresh]);
        let below = tally_wire::budget::ANCHOR_BELOW_REFERENCE
            .duration()
            .as_millis() as u64;
        let above = tally_wire::budget::ANCHOR_ABOVE_REFERENCE
            .duration()
            .as_millis() as u64;
        assert_eq!(
            clocks.anchor_disagreements(),
            [(liar.public(), (94_000 - 5 - below).cast_signed())]
        );
        // The edges of the band: carried, both.
        let ahead = tally_wire::Anchor::sign(&liar, AT + 5 + above);
        assert!(to_liar.anchored(ahead));
        assert_eq!(clocks.anchors().len(), 2);
        let behind = tally_wire::Anchor::sign(&liar, AT - 5 - below);
        assert!(to_liar.anchored(behind));
        assert_eq!(clocks.anchors().len(), 2);
        assert!(clocks.anchor_disagreements().is_empty());
        // A millisecond past either: left out.
        let past = tally_wire::Anchor::sign(&liar, AT + 5 + above + 1);
        assert!(to_liar.anchored(past));
        assert_eq!(clocks.anchors(), [fresh]);
        // Neither agrees: none is carried, and both are said.
        let far = tally_wire::Anchor::sign(&honest, AT + 3_600_000);
        assert!(to_honest.anchored(far));
        assert!(clocks.anchors().is_empty());
        assert_eq!(clocks.anchor_disagreements().len(), 2);
    }

    /// RFC-0171 §3.6: with no trusted reference (its host unsynced, an hour ahead, and no
    /// configured relay heard), the feeder judges no anchor by its own clock, since that is the
    /// clock anchors are there to catch: a lying relay signing at the feeder's wrong clock would
    /// be kept and the honest one dropped. It carries both, and the hop takes the oldest, the
    /// honest one, so its batches are never whitewashed; nothing is said on its health, having
    /// nothing to judge by. Before, it filtered by its own clock and carried the liar's alone.
    #[test]
    fn with_no_trusted_clock_a_feeder_carries_every_anchor() {
        const AT: u64 = 1_800_000_000_000;
        let hour = 3_600_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT + hour));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let (honest, liar) = (Identity::from_seed([45; 32]), Identity::from_seed([46; 32]));
        let (to_honest, to_liar) = (
            clocks.session(honest.public()),
            clocks.session(liar.public()),
        );
        let true_anchor = tally_wire::Anchor::sign(&honest, AT);
        let lie = tally_wire::Anchor::sign(&liar, AT + hour);
        assert!(to_honest.anchored(true_anchor));
        monotonic.store(1, Ordering::Relaxed);
        assert!(to_liar.anchored(lie));
        let mut carried = clocks.anchors();
        carried.sort_by_key(|anchor| anchor.j_ms);
        assert_eq!(carried, [true_anchor, lie]);
        assert!(clocks.anchor_disagreements().is_empty());
        // Just past the band of the wrong clock: still carried, no nearest-anchor choice.
        let further = tally_wire::Anchor::sign(&liar, AT + hour + 20_000);
        assert!(to_liar.anchored(further));
        assert_eq!(clocks.anchors().len(), 2);
    }

    /// RFC-0171 §3.6: with more relays' anchors than a batch has slots, the oldest reading is
    /// always carried (the hop judges by the oldest it knows, so leaving it out could only make
    /// a batch look fresher), then the last heard.
    #[test]
    fn the_oldest_anchor_always_has_a_slot() {
        const AT: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(AT));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let relays: Vec<Identity> = (50..53)
            .map(|seed| Identity::from_seed([seed; 32]))
            .collect();
        let sessions: Vec<Telling> = relays
            .iter()
            .map(|relay| clocks.session(relay.public()))
            .collect();
        // The oldest reading heard first, so last-heard order alone would drop it.
        for (n, (session, relay)) in sessions.iter().zip(&relays).enumerate() {
            monotonic.store(n as u64, Ordering::Relaxed);
            assert!(session.anchored(tally_wire::Anchor::sign(relay, AT + n as u64 * 100)));
        }
        let carried: Vec<u64> = clocks.anchors().iter().map(|anchor| anchor.j_ms).collect();
        assert_eq!(carried, [AT, AT + 200]);
    }

    /// RFC-0171 §3.6: a session to a relay a hint named is no clock source. An attacker holding
    /// both of a feeder's session slots (two /24s, two keys of its own, both an hour ahead) beside
    /// a synced host moves nothing: the feeder signs by its host, at the low end of its ClockBound's
    /// bound. Before, the two outvoted
    /// the host, two of three.
    #[test]
    fn two_lying_hinted_sessions_do_not_outvote_a_synced_host() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock {
            synced: Arc::new(|| Some(5)),
            ..HostClock::set_by(&wall, &monotonic)
        }));
        let lie = LOCAL + 3_600_000;
        let liars = (
            measured(&clocks, lie, Some(0)),
            measured(&clocks, lie, Some(0)),
        );
        assert!(matches!(clocks.offset_now().0, Selection::NoMajority));
        assert_eq!(
            clocks.now_ms(),
            LOCAL - 5,
            "two hinted relays outvoted a synced host"
        );
        drop(liars);
    }

    /// The same two liars beside a configured seed not yet heard and an unsynced host: no source
    /// but the host, so nothing is selected, and nothing they said is held once their sessions
    /// end.
    #[test]
    fn two_lying_hinted_sessions_beside_an_unheard_seed_steer_nothing_and_leave_nothing_held() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(
            RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured(seeds::<1>()),
        );
        let lie = LOCAL + 3_600_000;
        let liars = (
            measured(&clocks, lie, Some(0)),
            measured(&clocks, lie, Some(0)),
        );
        assert_eq!(clocks.now_ms(), LOCAL, "two hinted relays steered");
        drop(liars);
        assert_eq!(clocks.now_ms(), LOCAL, "a hinted selection was held");
        assert_eq!(clocks.held_ms.lock().ok().and_then(|held| *held), None);
    }

    /// Within an unsynced host's own `E`: two hinted relays at its interval's top edge once met
    /// it, three of three, and steered the feeder by up to `E` (it signed at `LOCAL + E`). They
    /// are no source: it signs by its own clock as read.
    #[test]
    fn hinted_relays_cannot_steer_within_an_unsynced_hosts_error() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)));
        let edge = LOCAL
            + tally_wire::budget::E
                .span::<tally_wire::clocks::Judged>()
                .ms();
        let liars = (
            measured(&clocks, edge, Some(0)),
            measured(&clocks, edge, Some(0)),
        );
        assert_eq!(clocks.now_ms(), LOCAL, "steered within E");
        drop(liars);
    }

    /// Only a selection of configured relays is held: once two seeds agree an hour ahead of an
    /// unsynced host, their offset is held over when their sessions end; hinted relays alike
    /// leave nothing held.
    #[test]
    fn only_a_configured_selection_is_held() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [a, b] = seeds();
        let clocks =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([a, b]));
        let ahead = LOCAL + 3_600_000;
        let hinted = (
            measured(&clocks, ahead, Some(0)),
            measured(&clocks, ahead, Some(0)),
        );
        let _ = clocks.now_ms();
        drop(hinted);
        assert_eq!(clocks.held_ms.lock().ok().and_then(|held| *held), None);
        let configured = (
            measured_as(&clocks, a, ahead, Some(0)),
            measured_as(&clocks, b, ahead, Some(0)),
        );
        assert_eq!(clocks.now_ms(), ahead);
        drop(configured);
        assert_eq!(
            clocks.now_ms(),
            ahead,
            "a configured selection was not held"
        );
    }

    /// The round 12 sweep's case: one lying configured relay and an honest one beside a synced
    /// host select the host's time, and two hinted sessions agreeing with the liar change
    /// nothing. Before, the hinted pair counted, and the liar won three of five.
    #[test]
    fn one_lying_configured_relay_and_hinted_sessions_do_not_outvote_a_synced_host_and_a_seed() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [liar, honest] = seeds();
        let clocks = Arc::new(
            RelayClocks::on(HostClock {
                synced: Arc::new(|| Some(5)),
                ..HostClock::set_by(&wall, &monotonic)
            })
            .configured([liar, honest]),
        );
        let lie = LOCAL + 3_600_000;
        let l = measured_as(&clocks, liar, lie, Some(0));
        let h = measured_as(&clocks, honest, LOCAL, Some(0));
        assert_eq!(
            clocks.now_ms(),
            LOCAL,
            "without hints: the host and the honest seed"
        );
        let hinted = (
            measured(&clocks, lie, Some(0)),
            measured(&clocks, lie, Some(0)),
        );
        assert_eq!(
            clocks.now_ms(),
            LOCAL,
            "one lying configured relay and two hinted sessions steered"
        );
        drop((l, h, hinted));
    }

    /// No number of hinted relays changes what is selected: over every count from none to many,
    /// each liar's clock anywhere from far behind to far ahead, synced host or not, the selection
    /// and the clock signed by are what the configured sources alone make.
    #[test]
    fn no_number_of_hinted_relays_changes_the_selection() {
        const LOCAL: u64 = 1_800_000_000_000;
        let e = tally_wire::budget::E
            .span::<tally_wire::clocks::Judged>()
            .ms();
        let lies = [
            LOCAL - 3_600_000,
            LOCAL - e,
            LOCAL,
            LOCAL + e,
            LOCAL + 2 * e,
            LOCAL + 3_600_000,
        ];
        for synced in [None, Some(5)] {
            for configured_at in [None, Some(LOCAL + 2_000), Some(LOCAL + 600_000)] {
                let wall = Arc::new(std::sync::atomic::AtomicU64::new(LOCAL));
                let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let [seed] = seeds();
                let clocks = Arc::new(
                    RelayClocks::on(HostClock {
                        synced: Arc::new(move || synced),
                        ..HostClock::set_by(&wall, &monotonic)
                    })
                    .configured([seed]),
                );
                let _seed = configured_at.map(|at| measured_as(&clocks, seed, at, Some(0)));
                let alone = (clocks.offset_now().0, clocks.now_ms());
                let mut hinted = Vec::new();
                for count in 1..=24 {
                    let lie = lies[count % lies.len()];
                    hinted.push(measured(&clocks, lie, Some(0)));
                    assert_eq!(
                        (clocks.offset_now().0, clocks.now_ms()),
                        alone,
                        "{count} hinted relays (synced {synced:?}, seed {configured_at:?})"
                    );
                }
            }
        }
    }

    /// Whether a future is ready at once, polled once.
    fn futures_ready<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> bool {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        future.poll(&mut context).is_ready()
    }

    /// NTP's on-wire exchange (RFC 5905 §8): `θ = ((T2 - T1) + (T3 - T4)) / 2`, within half the
    /// round trip `(T4 - T1) - (T3 - T2)`, whatever the way there and back take; an answer to
    /// nothing this clock sent (heard before it was asked) is no sample.
    #[test]
    fn an_echo_measures_the_offset_within_half_its_round_trip() {
        // The relay 5 s ahead; 30 ms there, 10 ms back, 4 ms in the relay.
        let sample = echo_sample(1_000, 6_030, 6_034, 1_044, Some(12)).unwrap_or(Sample {
            offset_ms: 0,
            half_rtt_ms: 0,
            at_ms: 0,
            error_ms: 0,
        });
        assert_eq!(sample.offset_ms, 5_010);
        assert_eq!(sample.half_rtt_ms, 20);
        assert!(sample.offset_ms.abs_diff(5_000) <= sample.half_rtt_ms);
        assert_eq!(sample.error_ms, 12);
        assert!(echo_sample(1_000, 6_030, 6_034, 999, None).is_none());
        // It ages at `ρ`: 500 ppm of an hour is 1.8 s, past `U_m`, and it is no longer selected.
        assert_eq!(sample.uncertainty_ms(1_044 + 3_600_000), 20 + 1_800);
        assert!(sample.interval(1_044 + 3_600_000).is_none());
    }

    /// The health's word on each relay's clock as its session measured it (by its echo, or by
    /// the clock its greeting stated): how far the clock batches are signed by is outside it,
    /// and nothing while inside it, unmeasured (a statement slower than `U_m`, or none yet) or
    /// unsynced (its error past `E`). It decides no send and no relay's fate.
    #[test]
    fn a_relays_measured_clock_is_what_the_health_reports_against() {
        const NOW: u64 = 1_800_000_000_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [configured] = seeds();
        let clocks = Arc::new(
            RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([configured]),
        );
        // A configured relay 4 s behind this host, measured exactly: the clock signed by.
        let relay = measured_as(&clocks, configured, NOW - 4_000, Some(3));
        // A relay a hint named, 100 s behind, and two it cannot measure.
        let behind = clocks.session(fresh_relay());
        // Their Hellos went 40 ms and 2 s before now by the anchored clock.
        let (soon, late) = (clocks.stamp_ms() - 40, clocks.stamp_ms() - 2_000);
        behind.stated(Some(NOW - 100_000), Some(0), soon);
        let slow = clocks.session(fresh_relay());
        slow.stated(Some(NOW), None, late);
        let unsynced = clocks.session(fresh_relay());
        unsynced.stated(Some(NOW), Some(u64::MAX), soon);
        assert_eq!(
            (slow.disagreement_ms(), unsynced.disagreement_ms()),
            (None, None)
        );
        drop((slow, unsynced));
        // Signed by the configured relay (inside its own interval), so this feeder's clock
        // disagrees with the one 100 s behind, ahead of it, and no other.
        assert_eq!(clocks.now_ms(), NOW - 4_000 - 3);
        assert_eq!(relay.disagreement_ms(), None);
        let off = behind.disagreement_ms().unwrap_or(0);
        assert!((95_000..=96_000).contains(&off), "{off}");
        let all = clocks.disagreements();
        assert_eq!(all.len(), 1, "{all:?}");
        assert_eq!(all[0].1, off);
        drop((relay, behind));
    }

    /// A measured clock runs on from when it was measured by this host's monotonic clock, so a
    /// step of this host's wall clock, either way, moves nothing it signs by: a Pi that started
    /// before NTP, an hour behind, signs by its relays' clocks, and when NTP steps its own an
    /// hour forward it signs by the same clock still. Before any source, it follows this host's
    /// wall clock, step and all.
    #[test]
    fn a_measured_clock_runs_on_through_a_step_of_this_hosts_clock() {
        const REAL: u64 = 1_800_000_000_000;
        const HOUR: u64 = 3_600_000;
        let wall = Arc::new(std::sync::atomic::AtomicU64::new(REAL - HOUR));
        let monotonic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let [k1, k2, k3] = seeds();
        let clocks = Arc::new(
            RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([k1, k2, k3]),
        );
        // None measured: this host's clock, unsynced, selects nothing on its own.
        assert_eq!(clocks.now_ms(), REAL - HOUR);
        let relays = [
            measured_as(&clocks, k1, REAL, Some(0)),
            measured_as(&clocks, k2, REAL, Some(0)),
            measured_as(&clocks, k3, REAL, Some(0)),
        ];
        assert_eq!(clocks.now_ms(), REAL);
        // Ten seconds on, and NTP steps this host's clock to the real time: still the real time
        // (the samples' age widens them by `ρ`, 5 ms, and the low end is signed at).
        monotonic.store(10_000, Ordering::Relaxed);
        wall.store(REAL + 10_000, Ordering::Relaxed);
        assert_eq!(clocks.now_ms(), REAL + 10_000 - 5);
        // Stepped back an hour by hand: still the real time.
        monotonic.store(20_000, Ordering::Relaxed);
        wall.store(REAL + 20_000 - HOUR, Ordering::Relaxed);
        assert_eq!(clocks.now_ms(), REAL + 20_000 - 10);
        drop(relays);
        // With none ever measured, a step of the host's clock is followed.
        let quiet = RelayClocks::on(HostClock::set_by(&wall, &monotonic));
        wall.store(REAL + 20_000, Ordering::Relaxed);
        assert_eq!(quiet.now_ms(), REAL + 20_000);
    }

    /// The batcher sheds wanted receptions past the least ceiling a relay stated,
    /// before it signs, counted in the batch's `dropped`; receptions MLAT never uses are held to
    /// the owner's bytes alone; and with no relay stating one, nothing is shed.
    #[test]
    fn wanted_receptions_past_the_relays_ceiling_are_shed_before_signing() -> Result<(), String> {
        let wanted = tally_wire::modes::with_parity(&[0x20, 0, 0x12, 0x34], 0x00ab_cdef);
        let unwanted = [0x8d; 14];
        let ceilings = Arc::new(WantedCeilings::default());
        let stating = ceilings.session();
        let mut batcher = batcher(10_000_000)?.shedding_to(Arc::clone(&ceilings));
        let reception = |data: &[u8], format| Observation {
            format,
            timestamp: 1,
            signal: 9,
            data: data.to_vec(),
        };
        // Unstated: every reception is taken.
        for _ in 0..500 {
            batcher.push(reception(&wanted, tally_wire::batch::format::MODE_S_SHORT))?;
        }
        let all = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((all.observations.len(), all.dropped), (500, 0));
        stating.state(Some(100));
        for _ in 0..500 {
            batcher.push(reception(&wanted, tally_wire::batch::format::MODE_S_SHORT))?;
            batcher.push(reception(&unwanted, tally_wire::batch::format::MODE_S_LONG))?;
        }
        let shed = content(&batcher.seal()?.ok_or("no batch")?)?;
        let kept_wanted = shed
            .observations
            .iter()
            .filter(|observation| {
                tally_wire::modes::wanted_reception(observation.format, &observation.data)
            })
            .count();
        // A second's worth of the ceiling at once, the rest shed and counted; none unwanted shed.
        assert!((100..=101).contains(&kept_wanted), "{kept_wanted} kept");
        assert_eq!(shed.observations.len() - kept_wanted, 500);
        assert_eq!(shed.dropped as usize, 500 - kept_wanted);
        // The session ends: its ceiling goes with it.
        drop(stating);
        for _ in 0..500 {
            batcher.push(reception(&wanted, tally_wire::batch::format::MODE_S_SHORT))?;
        }
        assert_eq!(content(&batcher.seal()?.ok_or("no batch")?)?.dropped, 0);
        Ok(())
    }

    /// The frames one read decoded take as each would one at a time: the same batches, in the
    /// same order, a full one sealed on the way, and what the channel holds is counted in
    /// receptions however they crossed it.
    #[test]
    fn a_reads_frames_batch_as_they_would_one_at_a_time() -> Result<(), String> {
        let frames = (1..=4_000u64).map(frame).collect::<Result<Vec<_>, _>>()?;
        let mut together = batcher(100_000_000)?;
        let mut sealed = Vec::new();
        together.take_frames(&frames, &mut sealed)?;
        sealed.extend(together.seal()?);
        assert!(sealed.len() >= 2, "a full batch seals on the way");
        let counters = |batches: &[Batch]| -> Result<Vec<u64>, String> {
            let mut all = Vec::new();
            for batch in batches {
                all.extend(
                    content(batch)?
                        .observations
                        .iter()
                        .map(|each| each.timestamp),
                );
            }
            Ok(all)
        };
        assert_eq!(counters(&sealed)?, (1..=4_000).collect::<Vec<u64>>());
        for pair in sealed.windows(2) {
            assert_eq!(content(&pair[1])?.previous, pair[0].hash());
        }
        let (inputs, mut intake) = channel(Ceilings::new(u32::MAX, DEFAULT_ACARS_CEILING));
        inputs.offer_frames(frames[..3_000].to_vec());
        inputs.offer_frames(frames[..3_000].to_vec());
        // 3,000 and 3,000 receptions against a backlog of 4,096: the second is dropped, counted.
        assert_eq!(intake.overflow.load(Ordering::Relaxed), 3_000);
        assert!(matches!(
            intake.receiver.try_recv(),
            Ok(Message::Frames(taken)) if taken.len() == 3_000
        ));
        assert!(intake.receiver.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn batches_chain_and_number_within_a_boot() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.observe(&frame(1)?)?;
        let first = batcher.seal()?.ok_or("no first batch")?;
        batcher.observe(&frame(2)?)?;
        let second = batcher.seal()?.ok_or("no second batch")?;
        assert!(batcher.seal()?.is_none());
        assert_eq!((first.sequence(), second.sequence()), (0, 1));
        assert_eq!(first.boot_id(), second.boot_id());
        let content = second.content().map_err(|error| error.to_string())?;
        assert_eq!(content.previous, first.hash());
        second.verify().map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn a_counter_that_runs_backwards_starts_a_new_epoch() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        assert!(batcher.observe(&frame(500_000_000)?)?.is_none());
        assert!(batcher.observe(&frame(499_999_000)?)?.is_none());
        let before = batcher
            .observe(&frame(1_000)?)?
            .ok_or("the old epoch was not sealed first")?
            .content()
            .map_err(|error| error.to_string())?;
        let after = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!((before.counter_epoch, before.observations.len()), (0, 2));
        assert_eq!((after.counter_epoch, after.observations.len()), (1, 1));
        Ok(())
    }

    /// ACARS-family messages gathered among receptions are signed in a batch of their own
    /// format, after the receptions' and in one chain with them, so no relay that predates the
    /// format reads one; what was dropped is counted in a batch of receptions alone.
    #[test]
    fn acars_messages_are_signed_apart_from_receptions() -> Result<(), String> {
        let mut batcher = batcher(u32::MAX)?;
        let message = Observation {
            format: tally_wire::batch::format::ACARS_JSON,
            timestamp: 1,
            signal: 0,
            data: br#"{"kind":"acars","label":"H1","t":1}"#.to_vec(),
        };
        for at in 1..=3 {
            batcher.push(message.clone())?;
            batcher.observe(&frame(at * 1_000)?)?;
        }
        let receptions = batcher.seal()?.ok_or("no batch")?;
        let acars = batcher.seal()?.ok_or("no ACARS batch")?;
        assert!(batcher.seal()?.is_none());
        assert_ne!(
            receptions.format(),
            tally_wire::batch::BATCH_FORMAT_ANCHORED_ACARS
        );
        assert_eq!(
            acars.format(),
            tally_wire::batch::BATCH_FORMAT_ANCHORED_ACARS
        );
        let (receptions, acars) = (content(&receptions)?, content(&acars)?);
        assert!(
            receptions
                .observations
                .iter()
                .all(|o| o.format != message.format)
        );
        assert_eq!(acars.observations, vec![message.clone(); 3]);
        assert_eq!((receptions.sequence, acars.sequence), (0, 1));
        // What was dropped rides a batch of receptions, never the ACARS batch: one is signed for
        // it alone if it must be.
        batcher.add_dropped(2);
        batcher.push(message)?;
        let acars = content(&batcher.seal()?.ok_or("no ACARS batch")?)?;
        let receptions = content(&batcher.seal()?.ok_or("no batch for the dropped")?)?;
        assert!(batcher.seal()?.is_none());
        assert_eq!((acars.dropped, acars.observations.len()), (0, 1));
        assert_eq!((receptions.dropped, receptions.observations.len()), (2, 0));
        Ok(())
    }

    /// ACARS-family messages past their share are dropped and counted before they are queued,
    /// however many readers offer them, so the queue keeps its room for BEAST's frames; and a
    /// message the upload ceiling has no room for never spends the share.
    #[test]
    fn a_chatty_acars_decoder_never_takes_adsbs_share() -> Result<(), String> {
        let ceilings = Ceilings::new(64_000, 2_000);
        let (inputs, mut intake) = channel(Arc::clone(&ceilings));
        let line = format!(r#"{{"timestamp":1.5,"text":"{}"}}"#, "x".repeat(470));
        let message = Observation {
            format: tally_wire::batch::format::ACARS_JSON,
            timestamp: 1,
            signal: 0,
            data: line.into_bytes(),
        };
        let cost = reception_cost(&message);
        // Two readers, one share.
        let other = inputs.clone();
        for at in 0..200 {
            if at % 2 == 0 {
                inputs.offer_acars(message.clone());
            } else {
                other.offer_acars(message.clone());
            }
        }
        // The share holds a second of itself, so at most that many bytes of messages at once.
        let fit = 2_000 / cost;
        assert!(fit > 0);
        assert_eq!(intake.queued.load(Ordering::Relaxed) as usize, fit);
        assert_eq!(intake.overflow.load(Ordering::Relaxed) as usize, 200 - fit);
        // The rest of the queue is BEAST's.
        let frames = (1..=(INPUT_BACKLOG - fit) as u64)
            .map(frame)
            .collect::<Result<Vec<_>, _>>()?;
        inputs.offer_frames(frames);
        assert_eq!(intake.overflow.load(Ordering::Relaxed) as usize, 200 - fit);
        while intake.receiver.try_recv().is_ok() {}

        // An upload ceiling with no room: refused, and the share untouched.
        let tight = Ceilings::new(100, 2_000);
        let now = Instant::now();
        let before = tight
            .acars
            .lock()
            .map_err(|error| error.to_string())?
            .tokens;
        assert!(!tight.admit_acars(cost, now));
        let after = tight
            .acars
            .lock()
            .map_err(|error| error.to_string())?
            .tokens;
        assert_eq!(before, after);
        // With room, admitted, its bytes taken from the ceiling then and there.
        let roomy = Ceilings::new(64_000, 2_000);
        assert!(roomy.admit_acars(cost, now));
        assert!(roomy.take_upload(64_000 - cost, now));
        assert!(!roomy.take_upload(cost, now));

        // The longest message, eight times the share: sent once the share is full, which then
        // owes it, so nothing more goes until it is paid.
        let owing = Ceilings::new(64_000, 2_000);
        assert!(owing.admit_acars(LONGEST_ACARS, now));
        assert!(!owing.admit_acars(cost, now));
        Ok(())
    }

    /// However small and however many, ACARS-family messages never hold more than
    /// `ACARS_BACKLOG` places in the queue: the rest are BEAST's.
    #[test]
    fn acars_messages_hold_a_bounded_part_of_the_queue() -> Result<(), String> {
        let ceilings = Ceilings::new(u32::MAX, u32::MAX / 2);
        let (inputs, intake) = channel(ceilings);
        let message = Observation {
            format: tally_wire::batch::format::ACARS_JSON,
            timestamp: 1,
            signal: 0,
            data: br#"{"kind":"acars","label":"H1","t":1}"#.to_vec(),
        };
        for _ in 0..1_000 {
            inputs.offer_acars(message.clone());
        }
        assert_eq!(intake.queued.load(Ordering::Relaxed), ACARS_BACKLOG);
        assert_eq!(
            intake.overflow.load(Ordering::Relaxed),
            1_000 - ACARS_BACKLOG
        );
        let frames = (1..=(INPUT_BACKLOG as u32 - ACARS_BACKLOG) as u64)
            .map(frame)
            .collect::<Result<Vec<_>, _>>()?;
        inputs.offer_frames(frames);
        assert_eq!(
            intake.overflow.load(Ordering::Relaxed),
            1_000 - ACARS_BACKLOG
        );
        drop(inputs);
        Ok(())
    }

    /// A message admitted but then dropped (the queue full of frames) gives its bytes back: it
    /// spends neither the share nor the ceiling.
    #[test]
    fn an_acars_message_not_queued_spends_no_share() -> Result<(), String> {
        let message = Observation {
            format: tally_wire::batch::format::ACARS_JSON,
            timestamp: 1,
            signal: 0,
            data: br#"{"kind":"acars","label":"H1","t":1}"#.to_vec(),
        };
        let cost = reception_cost(&message);
        let ceilings = Ceilings::new(u32::MAX, cost as u32);
        let (inputs, intake) = channel(Arc::clone(&ceilings));
        let frames = (1..=INPUT_BACKLOG as u64)
            .map(frame)
            .collect::<Result<Vec<_>, _>>()?;
        inputs.offer_frames(frames);
        inputs.offer_acars(message);
        assert_eq!(intake.overflow.load(Ordering::Relaxed), 1);
        assert_eq!(intake.acars_queued.load(Ordering::Relaxed), 0);
        assert!(ceilings.admit_acars(cost, Instant::now()));
        drop(inputs);
        Ok(())
    }

    #[test]
    fn uat_and_1090_share_one_chain_and_only_beast_moves_the_epoch() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        let uat = Observation {
            format: tally_wire::batch::format::UAT_DOWNLINK,
            timestamp: 5,
            signal: 0,
            data: vec![0; 18],
        };
        batcher.take(Input::Frame(frame(1)?))?;
        batcher.take(Input::Observation(uat.clone()))?;
        let first = batcher.seal()?.ok_or("no first batch")?;
        batcher.take(Input::Observation(uat.clone()))?;
        let restarted = batcher
            .take(Input::CounterRestarted)?
            .ok_or("the restart did not seal")?;
        batcher.take(Input::Observation(uat))?;
        let last = batcher.seal()?.ok_or("no last batch")?;
        let content = |batch: &Batch| batch.content().map_err(|error| error.to_string());
        let (first_content, restarted_content, last_content) =
            (content(&first)?, content(&restarted)?, content(&last)?);
        assert_eq!(first_content.observations.len(), 2);
        assert_eq!(
            [first.sequence(), restarted.sequence(), last.sequence()],
            [0, 1, 2]
        );
        assert_eq!(first.boot_id(), last.boot_id());
        assert_eq!(restarted_content.previous, first.hash());
        let epochs =
            [&first_content, &restarted_content, &last_content].map(|each| each.counter_epoch);
        assert_eq!(epochs, [0, 0, 1]);
        Ok(())
    }

    #[test]
    fn what_never_reached_the_batcher_is_counted() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.add_dropped(3);
        let content = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!((content.dropped, content.observations.len()), (3, 0));
        Ok(())
    }

    #[test]
    fn over_the_ceiling_is_dropped_and_counted_never_buffered() -> Result<(), String> {
        let mut batcher = batcher(100)?;
        for counter in 0..20 {
            batcher.observe(&frame(counter)?)?;
        }
        let content = batcher
            .seal()?
            .ok_or("no batch")?
            .content()
            .map_err(|error| error.to_string())?;
        assert_eq!(content.observations.len(), 4);
        assert_eq!(content.dropped, 16);
        Ok(())
    }

    #[test]
    fn a_gps_counter_falling_back_at_midnight_starts_no_epoch() -> Result<(), String> {
        let gps = |seconds: u64, nanos: u64| (seconds << 30) | nanos;
        let mut batcher = clocked(1_000_000, Clock::RadarcapeGps)?;
        assert!(
            batcher
                .observe(&frame(gps(86_399, 999_000_000))?)?
                .is_none()
        );
        assert!(batcher.observe(&frame(gps(0, 1_000))?)?.is_none());
        let only = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((only.counter_epoch, only.observations.len()), (0, 2));
        // A reconnect is still a new epoch.
        batcher.observe(&frame(gps(5, 0))?)?;
        let before = batcher.counter_restarted()?.ok_or("no batch")?;
        batcher.observe(&frame(gps(6, 0))?)?;
        let after = batcher.seal()?.ok_or("no batch")?;
        assert_eq!(
            (
                content(&before)?.counter_epoch,
                content(&after)?.counter_epoch
            ),
            (0, 1)
        );
        Ok(())
    }

    #[test]
    fn every_free_running_clock_restarts_when_its_counter_runs_back() -> Result<(), String> {
        for clock in [
            Clock::Dump1090,
            Clock::Beast,
            Clock::Radarcape12Mhz,
            Clock::Unknown,
        ] {
            let mut batcher = clocked(1_000_000, clock)?;
            batcher.observe(&frame(500_000_000)?)?;
            assert!(batcher.observe(&frame(1_000)?)?.is_some(), "{clock:?}");
        }
        Ok(())
    }

    #[test]
    fn a_frame_without_a_timestamp_neither_moves_nor_restarts_the_counter() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        batcher.observe(&frame(500_000_000)?)?;
        assert!(batcher.observe(&frame(0)?)?.is_none(), "0 started an epoch");
        // Had 0 become the last counter, this would read as a jump forward and the next one as a
        // fall of more than a second; it is neither.
        assert!(batcher.observe(&frame(499_999_000)?)?.is_none());
        let only = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((only.counter_epoch, only.observations.len()), (0, 3));
        Ok(())
    }

    #[test]
    fn a_batch_record_costs_its_overhead() -> Result<(), String> {
        let mut batcher = batcher(1_000_000)?;
        // Its anchors at the most a batch carries: one from each of two relays.
        batcher.clocks.always_anchored(tally_wire::Anchor::sign(
            &Identity::from_seed([0xa8; 32]),
            wall_ms(),
        ));
        batcher.add_dropped(1);
        let empty = batcher.seal()?.ok_or("no batch")?;
        let mut encoded = Vec::new();
        Record::Batch(empty)
            .encode(&mut encoded)
            .map_err(|error| error.to_string())?;
        assert_eq!(encoded.len(), BATCH_OVERHEAD);
        Ok(())
    }

    #[test]
    fn no_sealed_batch_is_too_big_for_one_message() -> Result<(), String> {
        let mut batcher = batcher(u32::MAX)?;
        let big = |size: usize| Observation {
            format: tally_wire::batch::format::UAT_UPLINK,
            timestamp: 1,
            signal: 0,
            data: vec![0; size],
        };
        let mut sealed = Vec::new();
        // Receptions the early seal never sees, since none is offered between them.
        for _ in 0..12 {
            sealed.extend(batcher.push(big(20_000))?);
        }
        assert!(batcher.push(big(noise::MAX_PLAINTEXT))?.is_none());
        sealed.extend(batcher.seal()?);
        assert!(sealed.len() >= 4);
        let (mut total, mut dropped) = (0, 0);
        for batch in &sealed {
            let mut encoded = Vec::new();
            Record::Batch(batch.clone())
                .encode(&mut encoded)
                .map_err(|error| error.to_string())?;
            assert!(encoded.len() <= noise::MAX_PLAINTEXT, "{}", encoded.len());
            let content = content(batch)?;
            total += content.observations.len();
            dropped += content.dropped;
        }
        // The one reception bigger than a message is dropped and counted, never sent.
        assert_eq!((total, dropped), (12, 1));
        Ok(())
    }

    #[test]
    fn a_reception_too_big_for_any_batch_is_dropped_and_counted() -> Result<(), String> {
        let mut batcher = batcher(u32::MAX)?;
        batcher.push(Observation {
            format: tally_wire::batch::format::UAT_UPLINK,
            timestamp: 1,
            signal: 0,
            data: vec![0; MAX_OBSERVATION_BYTES],
        })?;
        let content = content(&batcher.seal()?.ok_or("no batch")?)?;
        assert_eq!((content.dropped, content.observations.len()), (1, 0));
        Ok(())
    }

    #[test]
    fn a_relay_bucket_lets_through_its_burst_then_its_rate() {
        let mut bucket = TokenBucket::with_burst(1_000, 10_000);
        let start = Instant::now();
        assert!(bucket.take_at(10_000, start));
        assert!(!bucket.take_at(1, start));
        assert!(!bucket.take_at(5_000, start + Duration::from_secs(4)));
        assert!(bucket.take_at(5_000, start + Duration::from_secs(5)));
    }

    /// RFC-0171 §3.6, the round-20 sweep's probe: a feeder whose host is an hour off and unsynced,
    /// its one configured relay 7 s behind true time stating a 7.4 s error, beside two honest
    /// hinted relays 7 s ahead. It signs at its reference's low end, 14.4 s below true time, and
    /// carries both honest anchors: they are inside the reference's whole interval as an honest
    /// relay's must be, though far ahead of the point it signs at. Before, the filter judged an
    /// anchor against that point and left both out, so the feeder's data went unanchored.
    #[test]
    fn honest_anchors_inside_a_wide_configured_reference_are_carried() {
        let truth: u64 = 1_800_000_000_000;
        let configured = Identity::from_seed([1; 32]);
        let hinted = [Identity::from_seed([2; 32]), Identity::from_seed([3; 32])];
        let wall = Arc::new(AtomicU64::new(truth + 3_600_000));
        let monotonic = Arc::new(AtomicU64::new(10_000));
        let clocks = Arc::new(
            RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([configured.public()]),
        );
        let asked = clocks.stamp_ms() - 2;
        let reading = truth - 7_000;
        clocks.probed(
            configured.public(),
            (asked, reading, reading),
            Some(7_400),
            clocks.stamp_ms(),
        );
        let sessions: Vec<_> = hinted
            .iter()
            .map(|relay| clocks.session(relay.public()))
            .collect();
        for (relay, session) in hinted.iter().zip(&sessions) {
            assert!(session.anchored(tally_wire::Anchor::sign(relay, truth + 7_000)));
        }
        let signs = i128::from(clocks.now_ms()) - i128::from(truth);
        assert!(
            (-14_500..=-14_400).contains(&signs),
            "signs {signs} ms from true time"
        );
        assert_eq!(clocks.anchors().len(), 2);
        assert!(clocks.anchor_disagreements().is_empty());
    }

    /// The reference an anchor is judged by is the one it held as the anchor was heard: its
    /// interval now, moved back by the anchor's age. A synced host (bound 1 s) hears two anchors,
    /// and 2 s later judges them: one exactly `ANCHOR_BELOW_REFERENCE` below the low end as heard
    /// is kept, and one a millisecond past `ANCHOR_ABOVE_REFERENCE` above the high end as heard is
    /// left out. Judged against the reference now, unmoved, the first was 2 s past the low edge
    /// and left out, and the second 2 s inside the high edge and kept.
    #[test]
    fn an_anchor_is_judged_by_the_reference_as_it_was_heard() {
        const HEARD: u64 = 1_800_000_000_000;
        let ms = |tolerance: tally_wire::budget::Tolerance| {
            u64::try_from(tolerance.duration().as_millis()).unwrap_or(u64::MAX)
        };
        let wall = Arc::new(AtomicU64::new(HEARD));
        let monotonic = Arc::new(AtomicU64::new(0));
        let clocks = Arc::new(RelayClocks::on(HostClock {
            synced: Arc::new(|| Some(1_000)),
            ..HostClock::set_by(&wall, &monotonic)
        }));
        let (low, high) = (Identity::from_seed([4; 32]), Identity::from_seed([5; 32]));
        let sessions = [clocks.session(low.public()), clocks.session(high.public())];
        let at_low_edge = tally_wire::Anchor::sign(
            &low,
            HEARD - 1_000 - ms(tally_wire::budget::ANCHOR_BELOW_REFERENCE),
        );
        let past_high_edge = tally_wire::Anchor::sign(
            &high,
            HEARD + 1_000 + ms(tally_wire::budget::ANCHOR_ABOVE_REFERENCE) + 1,
        );
        assert!(sessions[0].anchored(at_low_edge));
        assert!(sessions[1].anchored(past_high_edge));
        let held = ms(tally_wire::budget::ANCHOR_HELD);
        monotonic.store(held, Ordering::Relaxed);
        wall.store(HEARD + held, Ordering::Relaxed);
        assert_eq!(clocks.anchors(), [at_low_edge]);
        assert_eq!(clocks.anchor_disagreements(), [(high.public(), -1)]);
        drop(sessions);
    }

    /// A held selection widens by the raw clock's drift as it ages, so it signs further below
    /// where it was selected the longer it is held, and is dropped once wider than
    /// `SELECTION_LAG`: then this host's clock is read as it is. Before, the offset was held as
    /// selected for ever, ahead of true time once the raw clock had drifted under it.
    #[test]
    fn a_held_selection_widens_with_age_and_is_dropped_past_the_selection_lag() {
        const LOCAL: u64 = 1_800_000_000_000;
        let wall = Arc::new(AtomicU64::new(LOCAL));
        let monotonic = Arc::new(AtomicU64::new(0));
        let [seed] = seeds();
        let clocks =
            Arc::new(RelayClocks::on(HostClock::set_by(&wall, &monotonic)).configured([seed]));
        let relay = measured_as(&clocks, seed, LOCAL + 600_000, Some(0));
        assert_eq!(clocks.now_ms(), LOCAL + 600_000);
        drop(relay);
        let at = |raw: u64| {
            monotonic.store(raw, Ordering::Relaxed);
            wall.store(LOCAL + raw, Ordering::Relaxed);
            clocks.now_ms()
        };
        // 10,000 s on: 5 s of drift at 500 ppm, below where it was selected.
        assert_eq!(at(10_000_000), LOCAL + 600_000 + 10_000_000 - 5_000);
        // 17,000 s on, 8.5 s either side: 17 s wide, still held. A millisecond on, dropped.
        assert_eq!(at(17_000_000), LOCAL + 600_000 + 17_000_000 - 8_500);
        assert_eq!(at(17_000_001), LOCAL + 17_000_001);
    }

    /// A relay whose clock steps back between taking a question and sending its answer (`T3`
    /// before `T2`) is taken to have held it no time: the round trip is the asker's whole wait,
    /// never more. Without the guard, the step back counted as a second of round trip.
    #[test]
    fn a_relay_clock_stepping_back_mid_answer_holds_the_question_no_time() {
        let sample = echo_sample(1_000, 5_000, 4_000, 1_100, Some(0));
        assert_eq!(
            sample.map(|sample| (sample.offset_ms, sample.half_rtt_ms)),
            Some((3_450, 50))
        );
    }
}
