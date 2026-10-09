//! The one client: a subscriber of the relay, as any client reads it (a Noise session, a
//! `Subscribe`, signatures checked), measuring what arrives. It reads on one task and never waits on
//! its own decoding, so a relay that drops it dropped it for the relay's reasons: decoding runs on
//! threads of its own, and what they cannot keep up with is counted as skipped by the client, not
//! held in the relay's fan-out.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash as _, Hasher as _};
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
/// and in the deduplicated one: every message heard raw is in the deduplicated stream at least once
/// a few seconds when the relay loses nothing (its rule keeps a message at least once every
/// `DEDUP_GENERATIONS` seconds), so one heard raw and never deduplicated is a message the relay lost.
#[derive(Default)]
pub struct Heard {
    /// Bumped when a window begins: a decoder's own messages of an older window are let go.
    pub window: AtomicU64,
    pub raw: Mutex<HashSet<u64>>,
    pub dedup: Mutex<HashSet<u64>>,
}

impl Heard {
    /// (Messages heard raw this window, of them never in the deduplicated stream.)
    pub fn coverage(&self) -> (usize, usize) {
        let (Ok(raw), Ok(dedup)) = (self.raw.lock(), self.dedup.lock()) else {
            return (0, 0);
        };
        (raw.len(), raw.difference(&dedup).count())
    }
}

/// A message's identity for `Heard`: its format and bytes, hashed.
fn message_id(format: u8, data: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format.hash(&mut hasher);
    data.hash(&mut hasher);
    hasher.finish()
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
        self.heard.window.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut raw) = self.heard.raw.lock() {
            raw.clear();
        }
        if let Ok(mut dedup) = self.heard.dedup.lock() {
            dedup.clear();
        }
    }

    fn ended(&self, why: String) {
        self.connected.store(false, Ordering::Relaxed);
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

/// Reads `relay` for as long as the harness runs, reconnecting a second after a session ends.
pub async fn run(
    relay: RelayAddress,
    streams: Streams,
    verify: bool,
    threads: usize,
    client: Arc<Client>,
) {
    let workers: Vec<SyncSender<Work>> = (0..threads.max(1))
        .map(|_| {
            let (send, receive) = sync_channel(WAITING);
            let client = Arc::clone(&client);
            std::thread::spawn(move || decode(&receive, verify, &client));
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
}

impl Reading {
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
                    reading.hand(Work::Raw(batch, now), client);
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
    let (mut raw_heard, mut dedup_heard) = (HashSet::new(), HashSet::new());
    let mut window = client.heard.window.load(Ordering::SeqCst);
    let mut since = 0;
    let hand_over =
        |raw_heard: &mut HashSet<u64>, dedup_heard: &mut HashSet<u64>, window: &mut u64| {
            let now = client.heard.window.load(Ordering::SeqCst);
            if now == *window {
                if let Ok(mut raw) = client.heard.raw.lock() {
                    raw.extend(raw_heard.drain());
                }
                if let Ok(mut dedup) = client.heard.dedup.lock() {
                    dedup.extend(dedup_heard.drain());
                }
            }
            raw_heard.clear();
            dedup_heard.clear();
            *window = now;
        };
    loop {
        let work = match work.recv_timeout(Duration::from_millis(500)) {
            Ok(work) => work,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                hand_over(&mut raw_heard, &mut dedup_heard, &mut window);
                since = 0;
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        since += 1;
        if since >= HEARD_EVERY {
            hand_over(&mut raw_heard, &mut dedup_heard, &mut window);
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
            heard.insert(message_id(observation.format, &observation.data));
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

    /// H-d: a provisional solution's latency is reported in its two halves, split at the stamp of
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
