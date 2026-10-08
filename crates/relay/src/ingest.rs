//! The ingest stage (RFC-0181 §2): where a batch becomes one immutable [`Decoded`], once, before
//! any other stage reads it. A connection task does I/O only and holds at most its [`Allowance`]
//! of batches in flight, counted in bytes as each batch is charged ([`charge_of`]: its signed
//! bytes, what it inflates to and its receptions' references, from the batch alone before it is
//! decoded), carved from the relay's `Store::Ingest` when the connection is admitted; out of
//! allowance it stops reading its socket, so TCP pushes back on the feeder (whose signed `dropped`
//! records its own loss), no connection can take another's room, and nothing queues unbounded.
//! A batch's charge ([`InFlight`]) travels with it to the message exchange and is let go only once
//! the epochs hold its bytes (`exchange`). The work
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
//! in, when a shard may seal, which copy of a message is kept) reads the stamp's time and the batch
//! itself (`seal::canonical`), never a clock of its own and never the ingest order the workers
//! raced to, so the same stamped batches give the same output on any number of threads and whatever
//! a stage's delays (RFC-0181, invariants 1 and 2). A stage is held up only by a test's [`Pause`],
//! at the points [`Stage`] names. Each worker
//! ticks the message exchange (`exchange::Envelope::Tick`) as its stamps advance and when idle, so
//! epochs close whether or not batches flow.
//!
//! A worker or message thread that panics ends the relay (`crate::abort_on_any_panic`, which the
//! program sets for every thread): a stage that stopped would hold every epoch open for ever, and a
//! lock it left poisoned would refuse every batch of its shard, both silently.
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

use tally_wire::{Batch, Decoded, ObsRef, Undecodable};
use tokio::sync::Notify;

use crate::budget::{Charge, Gauge, PLANNED_BYTES_PER_SEC, PLANNED_RECEPTIONS_PER_SEC, Store};
use crate::exchange::{Gauges, MessageExchange, Sink};

/// Batches at the planned rate one feeder's connection may have in the ingest stage at once. Two:
/// one being worked on, one read and waiting, so a connection's socket is read while its previous
/// batch is decoded. What it holds is counted in bytes ([`FEEDER_ALLOWANCE`]), never in batches,
/// so a peer sending large batches holds no more than one sending small ones.
pub const CREDIT: usize = 2;

/// What a batch costs in the stages before the epochs hold it, from what the batch states: the
/// decode's struct, its signed bytes (`wire`), its observations inflated (`inflated`) and a
/// reference for each reception it can hold (`receptions`). At least `Decoded::footprint` of its
/// decode, so a charge taken before the decode covers it.
pub const fn charge_for(wire: usize, inflated: usize, receptions: usize) -> usize {
    std::mem::size_of::<Decoded>() + wire + inflated + receptions * std::mem::size_of::<ObsRef>()
}

/// What `batch` is charged before it is decoded: as [`charge_for`], its inflated length and the
/// most receptions it can hold read from its stated length (`Batch::inflated_len`, held to the
/// wire's inflation rule; `Batch::receptions_at_most`), never its wire bytes alone. A batch of a
/// format this build cannot read is never inflated or decoded, and costs its signed bytes.
pub fn charge_of(batch: &Batch) -> usize {
    let wire = batch.as_bytes().len();
    match (batch.inflated_len(), batch.receptions_at_most()) {
        (Ok(inflated), Ok(receptions)) => charge_for(wire, inflated, receptions),
        _ => charge_for(wire, 0, 0),
    }
}

/// A batch at the planned rate (RFC-0181, "Requirement": a second of a feeder's batches, its
/// receptions each a 14-byte Mode S message), as [`charge_of`] charges it.
pub const PLANNED_BATCH_CHARGE: usize = {
    let inflated = 4 + PLANNED_RECEPTIONS_PER_SEC * (tally_wire::decoded::OBSERVATION_FIXED + 14);
    charge_for(
        PLANNED_BYTES_PER_SEC,
        inflated,
        (inflated - 4) / tally_wire::decoded::OBSERVATION_FIXED,
    )
};

/// One feeder connection's allowance: [`CREDIT`] planned batches, in bytes. What a feeder reserves
/// of `Store::Ingest` (`budget::PerFeeder::planned`), and carves when its connection is admitted.
pub const FEEDER_ALLOWANCE: usize = CREDIT * PLANNED_BATCH_CHARGE;

/// What a connection holds of Noise buffers at most while it reads: the frame being read, the
/// plaintext it is decrypted into, and then the records decoded from it, each at most a whole
/// message, until every one is handed on. Carved when a connection is admitted, so a peer that
/// sends a whole message and trickles the next holds what was planned for it and no more.
pub const BUFFERS_PER_CONNECTION: usize = 2 * tally_wire::noise::MAX_MESSAGE;

/// What batches larger than their connection's whole allowance may hold past it, all
/// connections together: such a batch takes its connection's whole allowance (it waits until
/// nothing else of that connection is in flight) and the rest from here, waiting for room. Planned
/// in the budget on its own line, beside the base (`budget::Plan::oversize`), and its gauge is the
/// budget's (`budget::Budget::oversize`).
pub const OVERSIZE_BYTES: usize = 64 << 20;

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

/// A stage that a [`Pause`] holds up, at the point where it holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// An ingest worker, after a batch is stamped and before it is admitted and routed.
    Ingest,
    /// A message thread, before each envelope it takes.
    Message,
    /// The sealer, before each command it takes, and its pool, before each job.
    Sealer,
}

/// What holds a stage up, inside it: a test's injected delay or stall (RFC-0181 invariant 2, "no
/// consumer reads a clock": what a stage is given, not when, decides its output). A relay runs with
/// none.
pub type Pause = Arc<dyn Fn(Stage) + Send + Sync>;

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

/// One connection's allowance of bytes in the ingest stage (RFC-0181 §2, §10), carved from the
/// relay's `Store::Ingest` when the connection is admitted and held for as long as it is: what a
/// feeder reserved ([`FEEDER_ALLOWANCE`]), or a sharing member its feeders' worth. Each batch takes
/// its charge ([`charge_of`]) from it before it is handed over, waiting while the connection holds
/// its allowance (its socket unread), so no peer can hold the room another connection was given.
pub struct Allowance {
    own: Arc<Gauge>,
    oversize: Arc<Gauge>,
    _carved: Charge,
}

impl Allowance {
    /// `bytes` carved from `ingest` (the relay's `Store::Ingest`), batches larger than all of them
    /// taking the rest from `oversize`; `None` when `ingest` has no room for them.
    pub fn carve(ingest: &Arc<Gauge>, oversize: &Arc<Gauge>, bytes: usize) -> Option<Self> {
        let carved = ingest.try_charge(bytes)?;
        Some(Self {
            own: Gauge::new(Store::Ingest, bytes),
            oversize: Arc::clone(oversize),
            _carved: carved,
        })
    }

    /// One batch's charge of `bytes`, waiting while the connection holds its allowance. A batch
    /// larger than the whole allowance waits until the connection holds nothing, and takes the rest
    /// from the oversize room ([`OVERSIZE_BYTES`]).
    pub async fn acquire(&self, bytes: usize) -> InFlight {
        let own = bytes.min(self.own.limit());
        let charge = self.own.charge(own).await;
        let over = if bytes > own {
            self.oversize.charge(bytes - own).await
        } else {
            Charge::none()
        };
        InFlight { charge, over }
    }

    /// Bytes of the allowance free now.
    pub fn available(&self) -> usize {
        self.own.limit().saturating_sub(self.own.held())
    }
}

/// One batch's charge in the ingest stage ([`charge_of`]), from its connection's [`Allowance`]
/// or, for a batch the relay itself hands in, from `Store::Ingest` directly
/// ([`InFlight::trusted`]). Every batch handed to the stage carries one (`hub::Inbound`): it is
/// shrunk to the decode's footprint once decoded, split with the batch's slices to the message
/// exchange, and let go when the epochs hold the bytes (or the batch is let go), so the bytes
/// between a socket and the epochs are charged all the way.
#[derive(Debug)]
pub struct InFlight {
    charge: Charge,
    over: Charge,
}

impl InFlight {
    /// `bytes` charged to `gauge` (the relay's `Store::Ingest`), the caller waiting for room: for
    /// a batch handed in by the relay itself (a test's trace, a replay), on a thread that may
    /// wait. A charge larger than the whole limit waits until nothing else is held.
    pub fn trusted(gauge: &Arc<Gauge>, bytes: usize) -> Self {
        Self {
            charge: block_on(gauge.charge(bytes)),
            over: Charge::none(),
        }
    }

    /// Nothing charged: for a test that hands a stage its parts by hand.
    #[cfg(test)]
    pub fn free() -> Self {
        Self {
            charge: Charge::none(),
            over: Charge::none(),
        }
    }

    pub fn bytes(&self) -> usize {
        self.charge.bytes() + self.over.bytes()
    }

    /// Releases all but `bytes` (the oversize room's first): the decode is no larger.
    pub fn shrink_to(&mut self, bytes: usize) {
        let own = self.charge.bytes();
        if bytes < own {
            self.over.shrink_to(0);
            self.charge.shrink_to(bytes);
        } else {
            self.over.shrink_to(bytes - own);
        }
    }

    /// `bytes` of this charge (all of it, if it holds less) moved into a charge of their own,
    /// nothing taken or released: a slice's share, handed on with it.
    pub fn split(&mut self, bytes: usize) -> InFlight {
        let over = self.over.split(bytes);
        let charge = self.charge.split(bytes - over.bytes());
        InFlight { charge, over }
    }
}

/// Runs `future` to its end on the calling thread, parked between polls.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl std::task::Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::park();
    }
}

/// The ingest clock of a relay: the wall clock read once, at the start, and a monotonic clock
/// after it, so a stamp never jumps with the wall clock (a step forward would hold every producer
/// in the future, its epochs open and charged; a step back would hold them still) and stamps stay
/// near the wall time feeders and peers read.
pub fn anchored_wall_clock() -> Clock {
    let started = std::time::Instant::now();
    let wall_ms = crate::network::wall_ms();
    Arc::new(move || {
        wall_ms.saturating_add(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
    })
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

/// Work for one worker, given its producer number. The relay hands a worker a batch only with its
/// charge ([`Stages::run_charged`]), so what waits for the workers is bounded by `Store::Ingest`;
/// anything else a worker is given (a tick, a flush) is the stage's own.
type Work = Box<dyn FnOnce(usize) + Send>;

/// A batch's work for one worker: given its producer number and the batch's charge.
pub type ChargedWork = Box<dyn FnOnce(usize, InFlight) + Send>;

/// A record's work for one worker, stamped there (`Stages::run_stamped`): given its stamp and its
/// charge.
pub type StampedWork = Box<dyn FnOnce(Stamp, InFlight) + Send>;

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
    pause: Option<Pause>,
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
                pause: None,
            }),
            pool: Pool::Inline(Mutex::new(())),
        }
    }

    /// The stages on `threads`, closed epochs going to `sink`, each stage held up by `pause` (a
    /// test's; none in a relay). Every thread is running or the stages are not made: a worker
    /// that cannot be started fails the relay at its start, since every message thread waits for
    /// every worker's tick and one missing would close no epoch ever.
    pub fn threaded(
        clock: Clock,
        threads: Threads,
        sink: &Sink,
        gauges: &Gauges,
        pause: Option<Pause>,
    ) -> Result<Self, String> {
        let workers = threads.ingest.max(1);
        let core = Arc::new(Core {
            clock,
            next: AtomicU64::new(0),
            last: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            ticked: (0..workers).map(|_| AtomicU64::new(0)).collect(),
            message: MessageExchange::threads(
                threads.message,
                workers,
                sink,
                gauges,
                pause.as_ref(),
            )?,
            pause,
        });
        // Dropping `stages` on a failure stops and joins the workers already started.
        let mut stages = Self {
            core: Arc::clone(&core),
            pool: Pool::Threads {
                senders: Vec::with_capacity(workers),
                handles: Vec::with_capacity(workers),
            },
        };
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
            let handle = spawned
                .map_err(|error| format!("ingest thread {producer} of {workers}: {error}"))?;
            if let Pool::Threads { senders, handles } = &mut stages.pool {
                senders.push(sender);
                handles.push(handle);
            }
        }
        Ok(stages)
    }

    /// Holds the calling stage up as the test's [`Pause`] says; nothing in a relay.
    pub fn pause(&self, stage: Stage) {
        if let Some(pause) = &self.core.pause {
            pause(stage);
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

    /// Runs a batch's `work` on worker `worker`, with its charge: the one way a batch reaches a
    /// worker, so the batches waiting for the workers are charged.
    pub fn run_charged(&self, worker: usize, in_flight: InFlight, work: ChargedWork) {
        self.run_on(worker, Box::new(move |producer| work(producer, in_flight)));
    }

    /// Runs `work` on worker `worker` with its charge, stamped there as a batch is: by `given`, a
    /// trace's stamp, else the worker's next stamp by the ingest clock. A record that is not a
    /// batch but must fall among a receiver's batches in the trace's order (its description) goes
    /// this way, on the worker that owns the receiver.
    pub fn run_stamped(
        &self,
        worker: usize,
        in_flight: InFlight,
        given: Option<Stamp>,
        work: StampedWork,
    ) {
        let core = Arc::clone(&self.core);
        self.run_on(
            worker,
            Box::new(move |producer| {
                let stamp = given.map_or_else(
                    || core.stamp(producer),
                    |stamp| core.stamped(producer, stamp),
                );
                work(stamp, in_flight);
            }),
        );
    }

    /// Runs `work` on worker `worker` (inline: now, on the caller, then ticks).
    fn run_on(&self, worker: usize, work: Work) {
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
        let sink: Sink = Arc::new(|_| Ok(()));
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

    /// RFC-0181 §2: a connection's allowance is bytes carved from `Store::Ingest` when it is
    /// admitted, so a peer sending large batches holds its own allowance and never another's. One
    /// batch past the whole allowance waits until its connection holds nothing, and takes the
    /// rest from the oversize room.
    #[tokio::test]
    async fn a_connection_holds_at_most_its_allowance_in_bytes() -> Result<(), String> {
        let ingest = Gauge::new(Store::Ingest, 300);
        let oversize = Gauge::new(Store::Ingest, 1_000);
        let greedy = Allowance::carve(&ingest, &oversize, 100);
        let honest = Allowance::carve(&ingest, &oversize, 100);
        let (Some(greedy), Some(honest)) = (greedy, honest) else {
            return Err("two allowances fit the store".to_owned());
        };
        assert_eq!(ingest.held(), 200);
        // The greedy connection holds all of its own, and a third would not be carved past the
        // store.
        let first = greedy.acquire(60).await;
        let second = greedy.acquire(40).await;
        assert_eq!(
            (greedy.available(), first.bytes() + second.bytes()),
            (0, 100)
        );
        assert!(Allowance::carve(&ingest, &oversize, 101).is_none());
        // The honest one is never held up by it.
        let mine = honest.acquire(100).await;
        assert_eq!(mine.bytes(), 100);
        drop(mine);
        // A batch larger than the allowance waits for its connection to hold nothing.
        let waiting = tokio::spawn(async move { greedy.acquire(250).await.bytes() });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop((first, second));
        assert_eq!(waiting.await.ok(), Some(250));
        // Its batch let go, and the connection gone with it: only the honest one's carve is held.
        assert_eq!((oversize.held(), ingest.held()), (0, 100));
        drop(honest);
        assert_eq!(ingest.held(), 0);
        Ok(())
    }

    /// A charge shrinks to its decode and splits with its slices, nothing taken or released, and
    /// what a batch charges before it is decoded covers the decode.
    #[test]
    fn a_batch_charge_covers_its_decode_and_splits_with_its_slices() -> Result<(), String> {
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let batch = Batch::sign(
            &identity,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: (0..40u8)
                    .map(|n| tally_wire::Observation {
                        format: b'3',
                        timestamp: u64::from(n),
                        signal: 0,
                        data: vec![n; 14],
                    })
                    .collect(),
            },
        )
        .map_err(|error| error.to_string())?;
        let charge = charge_of(&batch);
        let decoded = Stages::decode(batch, Stamp::default())
            .map_err(|undecodable| undecodable.error.to_string())?;
        assert!(charge >= decoded.footprint());
        let gauge = Gauge::new(Store::Ingest, charge);
        let mut in_flight = InFlight::trusted(&gauge, charge);
        in_flight.shrink_to(decoded.footprint());
        assert_eq!(gauge.held(), decoded.footprint());
        let slice = in_flight.split(100);
        assert_eq!(
            (slice.bytes(), in_flight.bytes(), gauge.held()),
            (100, decoded.footprint() - 100, decoded.footprint())
        );
        drop(slice);
        drop(in_flight);
        assert_eq!(gauge.held(), 0);
        Ok(())
    }

    /// RFC-0181 invariant 2: the ingest clock is monotonic, read from the wall once.
    #[test]
    fn the_relays_clock_follows_the_wall_once_and_never_goes_back() {
        let clock = anchored_wall_clock();
        let wall = crate::network::wall_ms();
        let first = clock();
        assert!(first.abs_diff(wall) < 60_000);
        for _ in 0..1_000 {
            assert!(clock() >= first);
        }
    }

    /// Opens a stalled stage's gate when dropped, so a test that fails never leaves a thread
    /// waiting at it.
    struct Gate(Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Gate {
        fn closed() -> Self {
            Self(Arc::new((Mutex::new(false), std::sync::Condvar::new())))
        }

        /// A pause that holds `stage` until the gate opens.
        fn holding(&self, stage: Stage) -> Pause {
            let gate = Arc::clone(&self.0);
            Arc::new(move |at| {
                if at != stage {
                    return;
                }
                let (open, opened) = &*gate;
                let Ok(mut held) = open.lock() else {
                    return;
                };
                while !*held {
                    match opened.wait(held) {
                        Ok(again) => held = again,
                        Err(_) => return,
                    }
                }
            })
        }

        fn open(&self) {
            let (open, opened) = &*self.0;
            if let Ok(mut held) = open.lock() {
                *held = true;
            }
            opened.notify_all();
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            self.open();
        }
    }

    /// RFC-0181 invariant 9: no lock is held across a seal and nothing on the ingest path waits for
    /// the sealer. The real sealer is stalled outright (held at its first command until the test
    /// lets it go) while twenty epochs of batches are handed in by a scripted ingest clock: every
    /// one is decoded and routed all the same, and once the sealer runs again it catches up to the
    /// last epoch. Decided by what completes while the sealer stands still, never by timing: had
    /// any batch waited on the sealer, its routing could not finish (the deadline below only turns
    /// that hang into a failure).
    #[test]
    fn ingest_never_waits_for_a_stalled_sealer() -> Result<(), String> {
        let gate = Gate::closed();
        let pause = gate.holding(Stage::Sealer);
        let products = Arc::new(crate::products::Products::with_boot(1, 1));
        let threads = Threads {
            ingest: 2,
            message: 2,
        };
        products.on_thread(threads.message, Some(&pause))?;
        let sink = products.sink();
        let clock = Arc::new(AtomicU64::new(0));
        let reading = Arc::clone(&clock);
        let stages = Arc::new(Stages::threaded(
            Arc::new(move || reading.load(Ordering::Relaxed)),
            threads,
            &sink,
            &Gauges::unlimited(),
            Some(pause),
        )?);
        drop(sink);
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let (done, finished) = channel::<()>();
        const BATCHES: u64 = 2_000;
        const MS_APART: u64 = 10;
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
                    observations: (0..50u32)
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
            // The ingest clock moves on as the batches come: twenty epochs of them.
            clock.store(sequence * MS_APART, Ordering::Relaxed);
            let done = done.clone();
            let working = Arc::clone(&stages);
            stages.run_on(
                sequence as usize,
                Box::new(move |producer| {
                    let stamp = working.stamp(producer);
                    if let Ok(decoded) = Stages::decode(batch, stamp) {
                        working
                            .message()
                            .route(producer, &decoded, None, InFlight::free());
                    }
                    let _ = done.send(());
                }),
            );
        }
        drop(done);
        for routed in 0..BATCHES {
            match finished.recv_timeout(Duration::from_secs(120)) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "{routed} of {BATCHES} routed: ingest waits for the stalled sealer"
                    ));
                }
            }
        }
        // Everything is routed and the sealer has sealed nothing: it still stands at its gate.
        assert_eq!(products.watermark_ms(), 0);
        let end_ms = BATCHES * MS_APART + crate::seal::EPOCH_MS;
        stages.advance(end_ms);
        stages.flush();
        gate.open();
        // Let go, it takes everything the shards closed while it stood: up to the last epoch.
        let due = (end_ms / crate::seal::EPOCH_MS) * crate::seal::EPOCH_MS;
        let mut waited = 0;
        while products.watermark_ms() < due {
            waited += 1;
            if waited > 24_000 {
                return Err(format!(
                    "the sealer reached {} of {due} once let go",
                    products.watermark_ms()
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(stages);
        Ok(())
    }

    #[test]
    fn the_threads_come_from_the_cores_and_never_none() {
        let threads = Threads::from_cores();
        assert!(threads.ingest >= 1 && threads.message >= 1);
    }
}
