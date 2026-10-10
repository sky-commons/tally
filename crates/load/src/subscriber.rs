//! The one client: a subscriber of the relay, as any client reads it (a Noise session, a
//! `Subscribe`, signatures checked), measuring what arrives. It reads on one task and never waits on
//! its own decoding, so a relay that drops it dropped it for the relay's reasons: decoding runs on
//! threads of its own, and what they cannot keep up with is counted as skipped by the client, not
//! held in the relay's fan-out.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tally_feed::source::wall_ms;
use tally_wire::noise;
use tally_wire::{Batch, Identity, PublicKey, Record, RelayAddress, Role, Streams};
use tokio::net::TcpStream;

use crate::histogram::Histogram;

/// Batches waiting for a decoding thread, each.
const WAITING: usize = 4_096;
/// How often the client says it is still there, as a feeder does.
const HEARTBEAT: Duration = Duration::from_secs(30);

macro_rules! counts {
    ($($name:ident),* $(,)?) => {
        /// Counted since the client started; a window is the difference of two snapshots.
        #[derive(Default)]
        pub struct Counts { $(pub $name: AtomicU64,)* }

        #[derive(Clone, Copy, Debug, Default)]
        pub struct Snapshot { $(pub $name: u64,)* }

        impl Counts {
            pub fn snapshot(&self) -> Snapshot {
                Snapshot { $($name: self.$name.load(Ordering::Relaxed),)* }
            }
        }

        impl std::ops::Sub for Snapshot {
            type Output = Snapshot;
            fn sub(self, before: Snapshot) -> Snapshot {
                Snapshot { $($name: self.$name.saturating_sub(before.$name),)* }
            }
        }
    };
}

counts!(
    raw_batches,
    raw_bytes,
    raw_receptions,
    dedup_batches,
    dedup_bytes,
    dedup_receptions,
    descriptions,
    // Provisional MLAT solutions read (`--streams provisional`).
    provisional,
    // Of them, those dated after the stamp of the step that solved them (`Client::provisional`).
    provisional_after_stamp,
    // Batches missing from a receiver's stream (its sequence jumped), and ones that came again or
    // out of order.
    gaps,
    repeats,
    // Receptions the feeders say they dropped (their ceiling, their batcher behind).
    feeder_dropped,
    sessions,
    disconnects,
    skipped,
    bad_signatures,
    undecodable,
);

/// Each distinct message (by its format and bytes) the client read this window, in the raw stream
/// and in the deduplicated one, each with when (Unix ms, the client's clock) it was first read.
///
/// The relay keeps every message at least once every `DEDUP_GENERATIONS` seconds, so a message
/// read raw and never in the deduplicated stream is one the relay lost, but only a message the
/// stream has had the time to carry can be judged. The deduplicated stream is behind the raw one by
/// an epoch and its latency, and a client that has fallen behind reads raw batches long after the
/// relay stamped them. So a message is judged by its own arrival, never by the window's end
/// (`Heard::coverage`): one read raw in the last `EPOCH_MS` plus the deduplicated stream's longest
/// latency before a session's end (or the moment of asking), or soon after a session began (the
/// copy kept may have been sent before it), is not yet a loss and is counted apart as `unjudged`.
/// The deduplicated ids are kept `LOOKBACK_MS` before the window, since a copy of a message that a
/// slow raw reader reads late was kept, and sent, earlier.
#[derive(Default)]
pub struct Heard {
    /// When the window began (Unix ms): raw read before it is let go.
    pub since_ms: AtomicU64,
    pub raw: Mutex<Ids>,
    pub dedup: Mutex<Ids>,
    /// Each session of the window: when it began and, once it has, when it ended.
    pub sessions: Mutex<Vec<(u64, Option<u64>)>>,
}

/// Message identities, which are hashes already, with when each was first read: kept as they are,
/// not hashed again.
pub type Ids = HashMap<u64, u64, std::hash::BuildHasherDefault<Passthrough>>;

/// How long before a window the deduplicated stream's messages are kept.
const LOOKBACK_MS: u64 = 120_000;

/// The window's coverage of the raw stream by the deduplicated one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Messages read raw this window that the deduplicated stream had the time to carry.
    pub judged: usize,
    /// Of them, those never in the deduplicated stream: what the relay lost.
    pub missing: usize,
    /// Messages read raw this window that cannot be judged yet (see `Heard`).
    pub unjudged: usize,
}

/// A hasher for keys that are already hashes (`message_id`).
#[derive(Default)]
pub struct Passthrough(u64);

impl std::hash::Hasher for Passthrough {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

/// Folds `from` into `into`, keeping each message's first reading.
fn absorb(into: &mut Ids, from: &mut Ids) {
    for (id, at) in from.drain() {
        into.entry(id)
            .and_modify(|first| *first = (*first).min(at))
            .or_insert(at);
    }
}

impl Heard {
    /// Begins a window at `now` (Unix ms).
    pub fn begin(&self, now: u64) {
        self.since_ms.store(now, Ordering::SeqCst);
        if let Ok(mut raw) = self.raw.lock() {
            raw.clear();
        }
        if let Ok(mut dedup) = self.dedup.lock() {
            dedup.retain(|_, at| *at + LOOKBACK_MS >= now);
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|(_, end)| end.is_none());
        }
    }

    /// A session began at `now`.
    pub fn connected(&self, now: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.push((now, None));
        }
    }

    /// The session that was open ended at `now`.
    pub fn disconnected(&self, now: u64) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(open) = sessions.iter_mut().rev().find(|(_, end)| end.is_none())
        {
            open.1 = Some(now);
        }
    }

    /// Hands over what a decoder heard: raw read before the window is let go.
    fn hand_over(&self, raw: &mut Ids, dedup: &mut Ids) {
        let since = self.since_ms.load(Ordering::SeqCst);
        raw.retain(|_, at| *at >= since);
        if let Ok(mut held) = self.raw.lock() {
            absorb(&mut held, raw);
        }
        if let Ok(mut held) = self.dedup.lock() {
            absorb(&mut held, dedup);
        }
        raw.clear();
        dedup.clear();
    }

    /// The window's coverage at `now` (Unix ms). `latency_ms` is the longest the deduplicated
    /// stream took this window (an epoch's end to its reading).
    pub fn coverage(&self, now: u64, latency_ms: u64) -> Coverage {
        let (Ok(raw), Ok(dedup), Ok(sessions)) =
            (self.raw.lock(), self.dedup.lock(), self.sessions.lock())
        else {
            return Coverage::default();
        };
        // A message is kept by the epoch of its first copy, up to the dedup window before the copy
        // read raw, so one read this soon after a session began may have been kept, and sent,
        // before the session was.
        let begins = tally_relay::exchange::DEDUP_WINDOW_MS + tally_relay::seal::EPOCH_MS;
        let settle = tally_relay::seal::EPOCH_MS + latency_ms;
        let mut coverage = Coverage::default();
        for (id, at) in raw.iter() {
            let judged = sessions.iter().any(|(began, ended)| {
                *at >= *began + begins && *at + settle <= ended.unwrap_or(now)
            });
            if judged {
                coverage.judged += 1;
                coverage.missing += usize::from(!dedup.contains_key(id));
            } else {
                coverage.unjudged += 1;
            }
        }
        coverage
    }
}

/// A message's identity for `Heard`: its format and bytes, hashed.
///
/// Twelve million of these a second are made at the run's full rate, so it is a multiply and a
/// fold a word, not SipHash.
fn message_id(format: u8, data: &[u8]) -> u64 {
    let mut hash = 0x9e37_79b9_7f4a_7c15 ^ u64::from(format) ^ ((data.len() as u64) << 8);
    for chunk in data.chunks(8) {
        let mut word = [0u8; 8];
        word[..chunk.len()].copy_from_slice(chunk);
        hash = (hash ^ u64::from_le_bytes(word)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        hash ^= hash >> 31;
    }
    hash = (hash ^ (hash >> 30)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 27)
}

/// How many batches a decoder reads before it hands its messages to `Heard`.
const HEARD_EVERY: usize = 256;

/// What the client measured.
#[derive(Default)]
pub struct Client {
    pub heard: Heard,
    pub counts: Counts,
    pub raw_latency: Mutex<Histogram>,
    /// The most a raw batch took since the progress line last read it (`lib::progress`): when in
    /// the run raw was slow, which the window's histogram does not say.
    pub raw_max_since_ms: AtomicU64,
    pub dedup_latency: Mutex<Histogram>,
    /// Each provisional solution's transmission to its reading: RFC-0174 §2.4's fast MLAT.
    pub provisional_latency: Mutex<Histogram>,
    /// The same in its two halves (`Client::provisional`): its transmission to the stamp of the
    /// relay's step that solved it (the record's `issued_ms`), what the relay's own lateness
    /// budget does not see (the feeder's batching, the ingest and the watermark), and that stamp
    /// to its reading, what the budget does (the step, its publishing and the fan-out).
    pub provisional_to_stamp: Mutex<Histogram>,
    pub provisional_from_stamp: Mutex<Histogram>,
    /// Receivers whose batches arrived this window.
    pub receivers: Mutex<HashSet<PublicKey>>,
    /// Why each session ended, and how often.
    pub endings: Mutex<HashMap<String, u64>>,
    pub connected: AtomicBool,
}

impl Client {
    /// A provisional record read at `now` (Unix ms): each solution's transmission to its reading,
    /// and that split at the stamp of the relay's step that solved it (`issued_ms`, the step's
    /// stamp on the relay's ingest clock, `mlat_host`). A solution dated after that stamp is
    /// counted (`provisional_after_stamp`) and its first half taken as none: a free-running
    /// gauge's model dates its transmissions by the seal of the batch that anchored it
    /// (`tally_mlat_solver::sync`), up to a second late.
    pub fn provisional(&self, content: &tally_wire::SolutionsContent, now: u64) {
        let stamp = content.issued_ms;
        let (Ok(mut whole), Ok(mut to_stamp), Ok(mut from_stamp)) = (
            self.provisional_latency.lock(),
            self.provisional_to_stamp.lock(),
            self.provisional_from_stamp.lock(),
        ) else {
            return;
        };
        let mut after = 0;
        for solution in &content.solutions {
            let transmitted = solution.transmitted.unix_ms;
            whole.record(now.saturating_sub(transmitted));
            to_stamp.record(stamp.saturating_sub(transmitted));
            from_stamp.record(now.saturating_sub(stamp));
            after += u64::from(transmitted > stamp);
        }
        self.counts
            .provisional
            .fetch_add(content.solutions.len() as u64, Ordering::Relaxed);
        self.counts
            .provisional_after_stamp
            .fetch_add(after, Ordering::Relaxed);
    }

    /// Begins a window: latencies and receivers seen from now.
    pub fn reset_window(&self) {
        if let Ok(mut latency) = self.raw_latency.lock() {
            *latency = Histogram::default();
        }
        if let Ok(mut latency) = self.dedup_latency.lock() {
            *latency = Histogram::default();
        }
        for latency in [
            &self.provisional_latency,
            &self.provisional_to_stamp,
            &self.provisional_from_stamp,
        ] {
            if let Ok(mut latency) = latency.lock() {
                *latency = Histogram::default();
            }
        }
        if let Ok(mut receivers) = self.receivers.lock() {
            receivers.clear();
        }
        self.heard.begin(wall_ms());
    }

    fn ended(&self, why: String) {
        self.connected.store(false, Ordering::Relaxed);
        self.heard.disconnected(wall_ms());
        self.counts.disconnects.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut endings) = self.endings.lock() {
            *endings.entry(why).or_default() += 1;
        }
    }
}

enum Work {
    Raw(Batch, u64),
    Dedup(Batch, u64),
}

/// Starts the client on a thread and runtime of its own: its session is one task that has to read
/// a socket carrying the whole run's raw stream, and on the feeders' runtime, saturated by
/// thousands of tasks, it waits its turn behind them and the relay drops it as too slow
/// (`goodbye FellBehind`). A thread of its own gets the share of a core the scheduler gives any.
pub fn start(
    relay: RelayAddress,
    streams: Streams,
    verify: bool,
    threads: usize,
    sample: u32,
    client: Arc<Client>,
) {
    let spawned = std::thread::Builder::new()
        .name("tally-load-client".to_owned())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    runtime.block_on(run(relay, streams, verify, threads, sample, client));
                }
                Err(error) => eprintln!("tally-load: client runtime: {error}"),
            }
        });
    if let Err(error) = spawned {
        eprintln!("tally-load: client thread: {error}");
    }
}

/// Reads `relay` for as long as the harness runs, reconnecting a second after a session ends.
async fn run(
    relay: RelayAddress,
    streams: Streams,
    verify: bool,
    threads: usize,
    sample: u32,
    client: Arc<Client>,
) {
    let workers: Vec<SyncSender<Work>> = (0..threads.max(1))
        .map(|_| {
            let (send, receive) = sync_channel(WAITING);
            let client = Arc::clone(&client);
            let _ = std::thread::Builder::new()
                .name("tally-load-decode".to_owned())
                .spawn(move || decode(&receive, verify, &client));
            send
        })
        .collect();
    let identity = match Identity::generate() {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("tally-load: subscriber key: {error}");
            return;
        }
    };
    let mut reading = Reading {
        workers,
        next: 0,
        newest: HashMap::new(),
        sample: u64::from(sample.max(1)),
        seen: 0,
    };
    loop {
        let why = session(&relay, &identity, streams, &client, &mut reading).await;
        client.ended(why);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

struct Reading {
    workers: Vec<SyncSender<Work>>,
    next: usize,
    /// Each receiver stream's newest sequence (receiver, boot).
    newest: HashMap<(PublicKey, u64), u64>,
    /// One raw batch in this many is decoded (`--client-sample`); the rest are counted and
    /// followed by sequence.
    sample: u64,
    seen: u64,
}

impl Reading {
    /// Whether the next raw batch is one to decode.
    fn sampled(&mut self) -> bool {
        self.seen += 1;
        self.seen.is_multiple_of(self.sample)
    }

    fn hand(&mut self, work: Work, client: &Client) {
        self.next = (self.next + 1) % self.workers.len();
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.workers[self.next].try_send(work)
        {
            client.counts.skipped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn sequence(&mut self, batch: &Batch, receiver: PublicKey, client: &Client) {
        let sequence = batch.sequence();
        match self.newest.get_mut(&(receiver, batch.boot_id())) {
            Some(newest) if sequence > *newest => {
                client
                    .counts
                    .gaps
                    .fetch_add(sequence - *newest - 1, Ordering::Relaxed);
                *newest = sequence;
            }
            Some(_) => {
                client.counts.repeats.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                self.newest.insert((receiver, batch.boot_id()), sequence);
            }
        }
    }
}

/// One session: why it ended.
async fn session(
    relay: &RelayAddress,
    identity: &Identity,
    streams: Streams,
    client: &Client,
    reading: &mut Reading,
) -> String {
    let stream = match TcpStream::connect(&relay.address).await {
        Ok(stream) => stream,
        Err(error) => return format!("connect: {error}"),
    };
    let session = match noise::connect(stream, identity, &relay.key, Role::Subscriber).await {
        Ok(session) => session,
        Err(error) => return format!("handshake: {error}"),
    };
    let (mut reader, mut writer) = (session.reader, session.writer);
    let subscribe = Record::Subscribe {
        streams,
        regions: Vec::new(),
    };
    if let Err(error) = writer.send(&[subscribe]).await {
        return format!("subscribe: {error}");
    }
    let heartbeat = tokio::spawn(async move {
        let mut every = tokio::time::interval(HEARTBEAT);
        loop {
            every.tick().await;
            if writer.send(&[Record::Heartbeat]).await.is_err() {
                return;
            }
        }
    });
    client.connected.store(true, Ordering::Relaxed);
    client.heard.connected(wall_ms());
    client.counts.sessions.fetch_add(1, Ordering::Relaxed);
    let mut got = Vec::new();
    let why = loop {
        got.clear();
        if let Err(error) = reader.recv(&mut got).await {
            break format!("read: {error}");
        }
        let now = wall_ms();
        let mut ended = None;
        for record in got.drain(..) {
            match record {
                Record::Batch(batch) => {
                    let counts = &client.counts;
                    counts.raw_batches.fetch_add(1, Ordering::Relaxed);
                    counts
                        .raw_bytes
                        .fetch_add(batch.as_bytes().len() as u64, Ordering::Relaxed);
                    if let Ok(receiver) = batch.receiver() {
                        reading.sequence(&batch, receiver, client);
                        if let Ok(mut receivers) = client.receivers.lock() {
                            receivers.insert(receiver);
                        }
                    }
                    if reading.sampled() {
                        reading.hand(Work::Raw(batch, now), client);
                    } else if let Ok(receptions) = batch.receptions() {
                        // Not decoded: counted from the batch's own count, and no more.
                        counts
                            .raw_receptions
                            .fetch_add(receptions as u64, Ordering::Relaxed);
                    }
                }
                Record::RelayBatch(batch) => {
                    let counts = &client.counts;
                    counts.dedup_batches.fetch_add(1, Ordering::Relaxed);
                    counts
                        .dedup_bytes
                        .fetch_add(batch.as_bytes().len() as u64, Ordering::Relaxed);
                    reading.hand(Work::Dedup(batch, now), client);
                }
                Record::ReceiverInfo(_) => {
                    client.counts.descriptions.fetch_add(1, Ordering::Relaxed);
                }
                Record::Provisional(positions) => {
                    if let Ok(content) = positions.solutions() {
                        client.provisional(&content, now);
                    }
                }
                Record::Goodbye {
                    reason,
                    retry_after_secs,
                } => {
                    ended = Some(format!(
                        "goodbye {reason:?}, retry after {retry_after_secs} s"
                    ))
                }
                Record::Redirect {
                    retry_after_secs, ..
                } => ended = Some(format!("redirect, retry after {retry_after_secs} s")),
                _ => {}
            }
        }
        if let Some(why) = ended {
            break why;
        }
    };
    heartbeat.abort();
    why
}

fn decode(work: &std::sync::mpsc::Receiver<Work>, verify: bool, client: &Client) {
    let counts = &client.counts;
    let (mut raw_heard, mut dedup_heard) = (Ids::default(), Ids::default());
    let mut since = 0;
    loop {
        let work = match work.recv_timeout(Duration::from_millis(500)) {
            Ok(work) => work,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                client.heard.hand_over(&mut raw_heard, &mut dedup_heard);
                since = 0;
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        since += 1;
        if since >= HEARD_EVERY {
            client.heard.hand_over(&mut raw_heard, &mut dedup_heard);
            since = 0;
        }
        let (batch, received, raw) = match work {
            Work::Raw(batch, received) => (batch, received, true),
            Work::Dedup(batch, received) => (batch, received, false),
        };
        if verify {
            let verified = if raw {
                batch.verify()
            } else {
                batch.verify_as_relay()
            };
            if verified.is_err() {
                counts.bad_signatures.fetch_add(1, Ordering::Relaxed);
            }
        }
        let Ok(content) = batch.content() else {
            counts.undecodable.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let receptions = content.observations.len() as u64;
        let heard = if raw {
            &mut raw_heard
        } else {
            &mut dedup_heard
        };
        for observation in &content.observations {
            heard
                .entry(message_id(observation.format, &observation.data))
                .or_insert(received);
        }
        let latency = received.saturating_sub(content.wall_ms);
        if raw {
            counts
                .raw_receptions
                .fetch_add(receptions, Ordering::Relaxed);
            counts
                .feeder_dropped
                .fetch_add(u64::from(content.dropped), Ordering::Relaxed);
            if let Ok(mut histogram) = client.raw_latency.lock() {
                histogram.record(latency);
            }
            client
                .raw_max_since_ms
                .fetch_max(latency, Ordering::Relaxed);
        } else {
            counts
                .dedup_receptions
                .fetch_add(receptions, Ordering::Relaxed);
            if let Ok(mut histogram) = client.dedup_latency.lock() {
                histogram.record(latency);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::{
        AddressedCitation, EnuCovariance, ObservationSet, Reception, Solution, SolutionsContent,
        TransmitTime,
    };

    fn solution(transmitted_ms: u64) -> Result<Solution, String> {
        let receiver = Identity::from_seed([3; 32]).public();
        Ok(Solution {
            address: 0x48_0001,
            transmitted: TransmitTime::new(transmitted_ms, 0).map_err(|error| error.to_string())?,
            lat_e7: 520_000_000,
            lon_e7: 50_000_000,
            alt_hae_mm: None,
            covariance: EnuCovariance {
                xx: 1.0,
                xy: 0.0,
                xz: 0.0,
                yy: 1.0,
                yz: 0.0,
                zz: 1.0,
            },
            clock_model: [0; 32],
            addressed: AddressedCitation::default(),
            observations: ObservationSet::new(
                vec![0x8d; 14],
                vec![Reception {
                    receiver,
                    epoch: 1,
                    counter: 7,
                }],
            )
            .map_err(|error| error.to_string())?,
        })
    }

    fn ids(entries: &[(u64, u64)]) -> Ids {
        entries.iter().copied().collect()
    }

    /// A message read raw in the last moments of the window has not had the time to come back in
    /// the deduplicated stream, and is not a loss; one read raw earlier and never deduplicated is.
    /// Before, every message read raw was judged at the window's end, so the epoch the stream is
    /// always behind by showed as 1.7 to 8 percent of the messages lost with nothing lost.
    #[test]
    fn coverage_judges_only_what_the_stream_had_time_to_carry() {
        let heard = Heard::default();
        heard.begin(0);
        heard.connected(0);
        // Read raw at 10 s, 20 s and 59.5 s; the first two were kept, only the first came back.
        let mut raw = ids(&[(1, 10_000), (2, 20_000), (3, 59_500)]);
        let mut dedup = ids(&[(1, 11_000)]);
        heard.hand_over(&mut raw, &mut dedup);
        let coverage = heard.coverage(60_000, 1_000);
        assert_eq!(
            coverage,
            Coverage {
                judged: 2,
                missing: 1,
                unjudged: 1
            }
        );
    }

    /// A message read before a session's deduplicated stream could carry it, or just before the
    /// session ended, is not judged; the raw stream a client reads late is judged by its arrival,
    /// against deduplicated messages read before the window.
    #[test]
    fn coverage_leaves_out_a_sessions_edges_and_counts_late_raw_against_early_dedup() {
        let heard = Heard::default();
        heard.connected(0);
        heard.begin(100_000);
        heard.disconnected(120_000);
        heard.connected(130_000);
        let mut raw = ids(&[
            (1, 105_000),
            (2, 119_500),
            (3, 130_500),
            (4, 140_000),
            (5, 50_000),
        ]);
        // Message 1 was kept before the window began (a slow raw reader), 4 never was, 5 is raw of
        // before the window.
        let mut dedup = ids(&[(1, 99_000)]);
        heard.hand_over(&mut raw, &mut dedup);
        let coverage = heard.coverage(150_000, 1_000);
        assert_eq!(
            coverage,
            Coverage {
                judged: 2,
                missing: 1,
                unjudged: 2
            }
        );
    }

    /// A provisional solution's latency is reported in its two halves, split at the stamp of
    /// the relay's step that solved it, beside the whole; one dated after that stamp is counted.
    #[test]
    fn a_provisional_solution_is_timed_to_its_steps_stamp_and_from_it() -> Result<(), String> {
        let client = Client::default();
        let content = SolutionsContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 10_000,
            spec_version: 3,
            solutions: vec![solution(8_700)?, solution(10_400)?],
        };
        client.provisional(&content, 10_900);
        let quantiles = |histogram: &Mutex<Histogram>| -> Result<(u64, u64, u64), String> {
            let histogram = histogram.lock().map_err(|error| error.to_string())?;
            Ok((
                histogram.total(),
                histogram.quantile(0.0).unwrap_or(u64::MAX),
                histogram.max(),
            ))
        };
        assert_eq!(quantiles(&client.provisional_latency)?, (2, 500, 2_200));
        // Transmission to stamp: 1,300 ms, and none for the one dated after it.
        assert_eq!(quantiles(&client.provisional_to_stamp)?, (2, 0, 1_300));
        // Stamp to read: 900 ms for both.
        assert_eq!(quantiles(&client.provisional_from_stamp)?, (2, 900, 900));
        let counts = client.counts.snapshot();
        assert_eq!((counts.provisional, counts.provisional_after_stamp), (2, 1));
        Ok(())
    }
}
