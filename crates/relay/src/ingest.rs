//! The ingest stage (RFC-0177 §2): where a batch becomes one immutable [`Decoded`], once, before
//! any other stage reads it. A connection task does I/O only and holds at most [`CREDIT`] batches
//! in flight ([`Credit`]); out of credit it stops reading its socket, so TCP pushes back on the
//! feeder (whose signed `dropped` records its own loss) and nothing queues unbounded. The work
//! (verify, hash, admit, inflate, decode, route) runs on a [`Pool`] of dedicated OS threads sized
//! from the host's cores ([`Threads`]), never on the async runtime's workers, so a burst of
//! verification never stalls a heartbeat or an egress write.
//!
//! A batch runs on the worker that owns its receiver's raw shard (`exchange::raw_shard`, fixed
//! logical shards mapped onto the workers), so one receiver's batches are admitted, and reach every
//! subscriber, in the order its connection read them, and its admission state (sequence windows,
//! hashes) and station counters are touched by that worker alone.
//!
//! Every batch is stamped here ([`Stamp`]): the ingest clock's reading and the batch's place in the
//! ingest order, never going back on one worker. Every later decision (which epoch a reception is
//! in, when a shard may seal) reads the stamp and never a clock of its own, so the same stamped
//! trace gives the same output on any number of threads (RFC-0177, invariants 1 and 2). Each worker
//! ticks the message exchange (`exchange::Envelope::Tick`) as its stamps advance and when idle, so
//! epochs close whether or not batches flow.
//!
//! Ed25519 batch verification is not used: it accepts some signatures strict verification refuses
//! (a torsion component in `R` passes a batch equation one time in eight), and every reader of a
//! relay's stream verifies strictly, so a relay that batched could be made to forward what its
//! readers reject. Each batch's key is decompressed once instead (`Batch` keeps it).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tally_wire::{Batch, Decoded, Undecodable};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::exchange::{Gauges, MessageExchange, Sink};

/// Batches one feeder's connection may have in the ingest stage at once. Two: one being worked on,
/// one read and waiting, so a connection's socket is read while its previous batch is decoded.
pub const CREDIT: usize = 2;

/// Batches a relay's connection (a sharing member's, a one-hop raw link's) may have in the stage
/// at once: it carries many receivers' batches, each a feeder's worth, so its credit is many
/// feeders' (about a second of a thousand of them), bounded all the same.
pub const RELAY_CREDIT: usize = 1_024;

/// How often an idle worker ticks the message exchange, and the least advance of its stamps that
/// makes a busy one tick: a shard's watermark is at most this behind the ingest clock.
pub const TICK_MS: u64 = 10;

/// When a batch was taken, by the ingest clock, and its place in the ingest order. Ordered by
/// `(stamp_ms, ingest_seq)`: a watermark (`exchange::Envelope::Tick`) is a stamp.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Stamp {
    pub stamp_ms: u64,
    pub ingest_seq: u64,
}

/// What reads the ingest clock: the system's wall clock in a relay, a script in a test.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// How many threads each stage runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threads {
    /// Ingest workers: verify, hash, admit, inflate, decode, route.
    pub ingest: usize,
    /// Message exchange threads: the one deduplication.
    pub message: usize,
}

impl Threads {
    /// From the host's cores: a quarter for ingest, an eighth for the message exchange, at least
    /// one each. The rest are the async runtime's, the sealer's and the hosted MLAT's.
    pub fn from_cores() -> Self {
        let cores = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
        Self {
            ingest: (cores / 4).max(1),
            message: (cores / 8).max(1),
        }
    }
}

/// One connection's credit (`CREDIT` batches in the ingest stage). The connection task takes a
/// permit before it hands a batch over and the stage drops it when the batch is decoded and
/// routed; with none left the task does not read its socket.
#[derive(Clone)]
pub struct Credit {
    permits: Arc<Semaphore>,
}

impl Default for Credit {
    fn default() -> Self {
        Self::new(CREDIT)
    }
}

impl Credit {
    pub fn new(batches: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(batches)),
        }
    }

    /// A permit for one batch, waiting while the connection has `CREDIT` in flight.
    pub async fn acquire(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).acquire_owned().await.ok()
    }

    /// Permits free now.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// One batch's place in the ingest stage: its connection's credit, and its bytes charged to the
/// relay's budget (`budget::Store::Ingest`), both released when the batch is decoded and routed.
/// A connection takes both before it hands a batch over, and waits for them (its socket unread)
/// while either is spent: the back-pressure raw meets (RFC-0177 §10).
pub struct InFlight {
    pub permit: OwnedSemaphorePermit,
    pub charge: crate::budget::Charge,
}

/// A connection's verdict from the ingest stage: a batch it sent failed its signature, so the
/// connection ends, as it did when the check ran inline.
#[derive(Default)]
pub struct Refusal {
    why: Mutex<Option<String>>,
    notify: Notify,
}

impl Refusal {
    pub fn refuse(&self, why: String) {
        if let Ok(mut held) = self.why.lock() {
            held.get_or_insert(why);
        }
        self.notify.notify_one();
    }

    /// Why, if a batch was refused.
    pub fn now(&self) -> Option<String> {
        self.why.lock().ok().and_then(|held| held.clone())
    }

    /// Resolves with why, once a batch was refused.
    pub async fn refused(&self) -> String {
        loop {
            if let Some(why) = self.why.lock().ok().and_then(|held| held.clone()) {
                return why;
            }
            self.notify.notified().await;
        }
    }
}

/// Work for one worker, given its producer number.
pub type Work = Box<dyn FnOnce(usize) + Send>;

/// The threads the ingest work runs on, each a producer of the message exchange.
enum Pool {
    /// Run by the caller, one at a time: producer 0. For tests, and nothing else.
    Inline(Mutex<()>),
    Threads {
        senders: Vec<Sender<Work>>,
        handles: Vec<JoinHandle<()>>,
    },
}

/// The ingest clock, every worker's stamps, and the message exchange the workers feed.
struct Core {
    clock: Clock,
    next: AtomicU64,
    /// Per producer: the newest stamp it took or ticked.
    last: Box<[AtomicU64]>,
    /// Per producer: when it last ticked.
    ticked: Box<[AtomicU64]>,
    message: MessageExchange,
}

impl Core {
    fn now(&self, producer: usize) -> u64 {
        let last = self.last[producer].load(Ordering::Relaxed);
        (self.clock)().max(last)
    }

    fn stamp(&self, producer: usize) -> Stamp {
        let stamp_ms = self.now(producer);
        self.last[producer].store(stamp_ms, Ordering::Relaxed);
        Stamp {
            stamp_ms,
            ingest_seq: self.next.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// A stamp the trace gave: kept, and the producer's stamps go on from it.
    fn stamped(&self, producer: usize, stamp: Stamp) -> Stamp {
        self.last[producer].fetch_max(stamp.stamp_ms, Ordering::Relaxed);
        stamp
    }

    /// Ticks `producer` at its stamps' newest when `TICK_MS` has passed since its last tick, or
    /// always when `force`.
    fn tick(&self, producer: usize, force: bool) {
        let now = self.now(producer);
        let ticked = self.ticked[producer].load(Ordering::Relaxed);
        if force || now >= ticked + TICK_MS {
            self.last[producer].store(now, Ordering::Relaxed);
            self.ticked[producer].store(now, Ordering::Relaxed);
            self.message.tick(
                producer,
                Stamp {
                    stamp_ms: now,
                    ingest_seq: 0,
                },
            );
        }
    }

    /// Ticks `producer` at `stamp_ms`, moving its stamps on to it.
    fn tick_at(&self, producer: usize, stamp_ms: u64) {
        self.last[producer].fetch_max(stamp_ms, Ordering::Relaxed);
        self.tick(producer, true);
    }
}

/// The staged relay's ingest side: the workers and the message exchange they feed.
pub struct Stages {
    core: Arc<Core>,
    pool: Pool,
}

impl Stages {
    /// Every stage run by the caller (one producer, one message thread): for tests.
    pub fn inline(clock: Clock, sink: Sink, gauges: Gauges) -> Self {
        Self {
            core: Arc::new(Core {
                clock,
                next: AtomicU64::new(0),
                last: vec![AtomicU64::new(0)].into_boxed_slice(),
                ticked: vec![AtomicU64::new(0)].into_boxed_slice(),
                message: MessageExchange::inline(sink, gauges),
            }),
            pool: Pool::Inline(Mutex::new(())),
        }
    }

    /// The stages on `threads`, closed epochs going to `sink`.
    pub fn threaded(clock: Clock, threads: Threads, sink: &Sink, gauges: &Gauges) -> Self {
        let workers = threads.ingest.max(1);
        let core = Arc::new(Core {
            clock,
            next: AtomicU64::new(0),
            last: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            ticked: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            message: MessageExchange::threads(threads.message, workers, sink, gauges),
        });
        let mut senders = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);
        for producer in 0..workers {
            let (sender, receiver) = channel::<Work>();
            let core = Arc::clone(&core);
            let spawned = std::thread::Builder::new()
                .name(format!("tally-ingest-{producer}"))
                .spawn(move || {
                    loop {
                        match receiver.recv_timeout(Duration::from_millis(TICK_MS)) {
                            Ok(work) => {
                                work(producer);
                                core.tick(producer, false);
                            }
                            Err(RecvTimeoutError::Timeout) => core.tick(producer, true),
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                });
            match spawned {
                Ok(handle) => {
                    senders.push(sender);
                    handles.push(handle);
                }
                Err(error) => {
                    eprintln!("tally-relay: ingest thread {producer}: {error}");
                    break;
                }
            }
        }
        Self {
            core,
            pool: Pool::Threads { senders, handles },
        }
    }

    /// Whether the work runs on the caller.
    pub fn is_inline(&self) -> bool {
        matches!(self.pool, Pool::Inline(_))
    }

    /// Workers: the producers of the message exchange.
    pub fn width(&self) -> usize {
        match &self.pool {
            Pool::Inline(_) => 1,
            Pool::Threads { senders, .. } => senders.len().max(1),
        }
    }

    /// The worker that owns raw shard `shard`.
    pub fn worker_of(&self, shard: crate::exchange::ShardId) -> usize {
        crate::exchange::thread_of(shard, self.width())
    }

    /// Runs `work` on worker `worker` (inline: now, on the caller, then ticks).
    pub fn run_on(&self, worker: usize, work: Work) {
        match &self.pool {
            Pool::Inline(lock) => {
                let _held = lock.lock();
                work(0);
                self.core.tick(0, true);
            }
            Pool::Threads { senders, .. } => {
                if let Some(sender) = senders.get(worker % senders.len().max(1)) {
                    let _ = sender.send(work);
                }
            }
        }
    }

    /// The next stamp of `producer`: now by the ingest clock, never before its last.
    pub fn stamp(&self, producer: usize) -> Stamp {
        self.core.stamp(producer)
    }

    /// A stamp a trace gave, for `producer`.
    pub fn stamped(&self, producer: usize, stamp: Stamp) -> Stamp {
        self.core.stamped(producer, stamp)
    }

    /// The ingest clock.
    pub fn clock(&self) -> Clock {
        Arc::clone(&self.core.clock)
    }

    /// The ingest clock now: the stamp of a record that is not a batch (a description, positions)
    /// for a subscriber queue's age.
    pub fn now_ms(&self) -> u64 {
        (self.core.clock)()
    }

    /// Decodes `batch`, verified, stamped `stamp`: the one decode every later stage shares. A
    /// batch of a format this build cannot read comes back whole, to be forwarded raw and read by
    /// nothing else.
    pub fn decode(batch: Batch, stamp: Stamp) -> Result<Arc<Decoded>, Box<Undecodable>> {
        Decoded::from_verified(batch, stamp.stamp_ms, stamp.ingest_seq)
    }

    pub fn message(&self) -> &MessageExchange {
        &self.core.message
    }

    /// Every worker ticks at `stamp_ms`: everything before it has been handed in. For a trace's
    /// end, and a test's.
    pub fn advance(&self, stamp_ms: u64) {
        match &self.pool {
            Pool::Inline(lock) => {
                let _held = lock.lock();
                self.core.tick_at(0, stamp_ms);
            }
            Pool::Threads { senders, .. } => {
                for sender in senders {
                    let core = Arc::clone(&self.core);
                    let _ = sender.send(Box::new(move |producer| {
                        core.tick_at(producer, stamp_ms);
                    }));
                }
            }
        }
    }
}

impl Stages {
    /// Waits until every worker has done everything handed to it before this call (each worker
    /// takes its work in order). For a trace's end, and a test's.
    pub fn flush(&self) {
        if let Pool::Threads { senders, .. } = &self.pool {
            let (done, finished) = channel::<()>();
            let mut waiting = 0;
            for sender in senders {
                let done = done.clone();
                if sender
                    .send(Box::new(move |_| {
                        let _ = done.send(());
                    }))
                    .is_ok()
                {
                    waiting += 1;
                }
            }
            drop(done);
            for _ in 0..waiting {
                if finished.recv().is_err() {
                    break;
                }
            }
        }
    }
}

impl Drop for Stages {
    fn drop(&mut self) {
        if let Pool::Threads { senders, handles } = &mut self.pool {
            senders.clear();
            let here = std::thread::current().id();
            for handle in handles.drain(..) {
                // Dropped by work on one of its own workers: that one ends when its work does.
                if handle.thread().id() != here {
                    let _ = handle.join();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_read_the_ingest_clock_never_go_back_and_count_up() {
        let sink: Sink = Arc::new(|_| true);
        let stages = Stages::inline(Arc::new(|| 42), sink, Gauges::unlimited());
        let first = stages.stamp(0);
        let second = stages.stamp(0);
        assert_eq!((first.stamp_ms, first.ingest_seq), (42, 0));
        assert_eq!((second.stamp_ms, second.ingest_seq), (42, 1));
        assert!(first < second);
        stages.stamped(
            0,
            Stamp {
                stamp_ms: 100,
                ingest_seq: 9,
            },
        );
        assert_eq!(stages.stamp(0).stamp_ms, 100);
    }

    #[tokio::test]
    async fn a_connection_holds_at_most_its_credit() {
        let credit = Credit::default();
        let first = credit.acquire().await;
        let second = credit.acquire().await;
        assert!(first.is_some() && second.is_some());
        assert_eq!(credit.available(), 0);
        drop(first);
        assert_eq!(credit.available(), 1);
    }

    /// The 99th percentile of a batch's time from being handed in to being routed, with a
    /// sealer that takes `seal` over each closed epoch.
    fn ingest_p99(seal: Duration) -> Result<Duration, String> {
        use std::sync::mpsc::sync_channel;
        let (to_sealer, sealing) = sync_channel::<crate::exchange::Frozen>(4);
        let sealer = std::thread::spawn(move || {
            while sealing.recv().is_ok() {
                std::thread::sleep(seal);
            }
        });
        let sink: Sink = Arc::new(move |frozen| crate::exchange::offer(&to_sealer, frozen));
        let stages = Arc::new(Stages::threaded(
            Arc::new(crate::network::wall_ms),
            Threads {
                ingest: 2,
                message: 2,
            },
            &sink,
            &Gauges::unlimited(),
        ));
        drop(sink);
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let (done, finished) = channel::<Duration>();
        const BATCHES: u64 = 1_500;
        for sequence in 0..BATCHES {
            let batch = Batch::sign(
                &identity,
                &tally_wire::BatchContent {
                    boot_id: 1,
                    sequence,
                    counter_epoch: 0,
                    wall_ms: 0,
                    dropped: 0,
                    previous: [0; 32],
                    observations: (0..200u32)
                        .map(|n| tally_wire::Observation {
                            format: b'3',
                            timestamp: u64::from(n),
                            signal: 0,
                            data: (n ^ (sequence as u32) << 8).to_be_bytes().repeat(3)[..12]
                                .iter()
                                .chain(&[0, 0])
                                .copied()
                                .collect(),
                        })
                        .collect(),
                },
            )
            .map_err(|error| error.to_string())?;
            let handed = std::time::Instant::now();
            let done = done.clone();
            let working = Arc::clone(&stages);
            stages.run_on(
                sequence as usize,
                Box::new(move |producer| {
                    if batch.verify().is_ok() {
                        let stamp = working.stamp(producer);
                        if let Ok(decoded) = Stages::decode(batch, stamp) {
                            working.message().route(producer, &decoded, None);
                        }
                    }
                    let _ = done.send(handed.elapsed());
                }),
            );
            // About 2,000 batches a second, for three quarters of a second: several epochs close.
            std::thread::sleep(Duration::from_micros(500));
        }
        drop(done);
        let mut took: Vec<Duration> = finished.iter().collect();
        if took.len() != BATCHES as usize {
            return Err(format!("{} of {BATCHES} routed", took.len()));
        }
        took.sort_unstable();
        drop(stages);
        let _ = sealer.join();
        Ok(took[took.len() * 99 / 100])
    }

    /// RFC-0177 invariant 9: no lock is held across a seal, so a sealer slowed to a second an
    /// epoch leaves ingest as fast as one that takes no time (it refuses the epochs it cannot
    /// take, whole; it never holds a shard back).
    #[test]
    fn ingest_stays_fast_with_the_sealer_slowed_to_a_second() -> Result<(), String> {
        let fast = ingest_p99(Duration::ZERO)?;
        let slow = ingest_p99(Duration::from_secs(1))?;
        assert!(
            slow <= fast * 3 + Duration::from_millis(20),
            "p99 {slow:?} with a slow sealer, {fast:?} with a fast one"
        );
        Ok(())
    }

    #[test]
    fn the_threads_come_from_the_cores_and_never_none() {
        let threads = Threads::from_cores();
        assert!(threads.ingest >= 1 && threads.message >= 1);
    }
}
