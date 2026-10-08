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

/// What the client measured.
#[derive(Default)]
pub struct Client {
    pub counts: Counts,
    pub raw_latency: Mutex<Histogram>,
    pub dedup_latency: Mutex<Histogram>,
    /// Receivers whose batches arrived this window.
    pub receivers: Mutex<HashSet<PublicKey>>,
    /// Why each session ended, and how often.
    pub endings: Mutex<HashMap<String, u64>>,
    pub connected: AtomicBool,
}

impl Client {
    /// Begins a window: latencies and receivers seen from now.
    pub fn reset_window(&self) {
        if let Ok(mut latency) = self.raw_latency.lock() {
            *latency = Histogram::default();
        }
        if let Ok(mut latency) = self.dedup_latency.lock() {
            *latency = Histogram::default();
        }
        if let Ok(mut receivers) = self.receivers.lock() {
            receivers.clear();
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
    while let Ok(work) = work.recv() {
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
