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
//! from the load the relay is planned to admit ([`Threads`], `cores::threads_for`), never on the
//! async runtime's workers, so a burst of verification never stalls a heartbeat or an egress
//! write.
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
#[cfg(test)]
use std::sync::mpsc::{RecvTimeoutError, channel};
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
/// wire's inflation rule; `Batch::receptions_at_most`), never its wire bytes alone, and never less
/// than [`CHARGE_FLOOR`]. A batch of a format this build cannot read is never inflated or decoded,
/// and costs its signed bytes.
pub fn charge_of(batch: &Batch) -> usize {
    let wire = batch.as_bytes().len();
    floored(match (batch.inflated_len(), batch.receptions_at_most()) {
        (Ok(inflated), Ok(receptions)) => charge_for(wire, inflated, receptions),
        _ => charge_for(wire, 0, 0),
    })
}

/// The least a record handed to the ingest workers is charged (a batch's [`charge_of`], a
/// description's bytes): its bytes, or [`CHARGE_FLOOR`] if more.
pub const fn floored(bytes: usize) -> usize {
    if bytes < CHARGE_FLOOR {
        CHARGE_FLOOR
    } else {
        bytes
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

/// The most records one connection's allowance holds in the ingest stage at once, however small
/// they are. Each costs an ingest worker a strict Ed25519 verification whatever its bytes, so a
/// charge by bytes alone let a feeder sending 300-byte batches hold some 500 in the workers'
/// queues at once, each a verification ahead of every honest batch behind it: some 25 such feeders
/// kept the workers busy. Eight is four times what a planned feeder holds ([`CREDIT`]), so a member
/// session forwarding many feeders' small batches still has room while each is verified.
pub const RECORDS_IN_FLIGHT: usize = 8;

/// The least one record is charged in the ingest stage until it is decoded ([`floored`]): a
/// feeder's allowance over [`RECORDS_IN_FLIGHT`]. Once decoded, its charge shrinks to the
/// decode's footprint: the verification is done.
pub const CHARGE_FLOOR: usize = FEEDER_ALLOWANCE / RECORDS_IN_FLIGHT;
// A batch at the planned rate is charged its bytes, never the floor, so the allowance holds the
// batches it was sized for (`budget::PerFeeder::planned`'s ingest line).
const _: () = assert!(PLANNED_BATCH_CHARGE >= CHARGE_FLOOR);

/// The bytes of its byte ceiling each record a connection sends is paced as, at least
/// ([`records_per_sec`]): whatever its bytes, a record costs the relay a fixed amount (a signature
/// verified on an ingest worker, or one checked or signed for an answer on the async runtime, and
/// its decode), so a connection's records a second are held to its byte ceiling over this. A feeder
/// seals a batch once a second and early only at 48 KiB (`tally_feed`), so one keeping to its
/// ceiling sends fewer: at the default 256 KiB/s, eight a second, where it sends five at most.
pub const RECORD_BYTES: u64 = 32 << 10;

/// The records a second a connection held to `bytes_per_sec` may send (R-N12), at least one: its
/// ceiling over [`RECORD_BYTES`]. The ingest cores plan each feeder's worth of these
/// ([`INGEST_NANOS_PER_RECORD`] each, `cores`). Before, a feeder sending tiny batches within its
/// 256 KiB/s was some 870 signature checks a second, and a few dozen such feeders took every
/// ingest worker: [`CHARGE_FLOOR`] bounded how many it had waiting at once, never how many a
/// second.
pub const fn records_per_sec(bytes_per_sec: u64) -> u64 {
    let records = bytes_per_sec.div_ceil(RECORD_BYTES);
    if records == 0 { 1 } else { records }
}

/// The records a second the members' shared rate may bring, all member sessions together, for
/// `member_feeders` planned feeders' worth (`budget::Plan::member_feeders`): [`MEMBER_RECORDS_PER_FEEDER`]
/// each. What a member forwards is feeders' batches at the planned rate (one a second each) and
/// their descriptions.
pub const fn member_records_per_sec(member_feeders: usize) -> u64 {
    let feeders = member_feeders as u64;
    let records = feeders.saturating_mul(MEMBER_RECORDS_PER_FEEDER);
    if records == 0 { 1 } else { records }
}

/// The records a second one planned feeder's worth of the members' rate may bring: four times the
/// planned batch a second, the headroom the notes plan for feeders above their rate
/// (`mlat_host::NOTES_HEADROOM`).
pub const MEMBER_RECORDS_PER_FEEDER: u64 = 4;

/// Nanoseconds of an ingest worker one record costs whatever its receptions: its strict Ed25519
/// verification, its hash, admission and decode. Measured (2026-10-09, `-c opt`-equivalent release
/// build, one core of the 32-core build host): an empty batch and a batch of one reception, read as
/// the connection task reads them (the key decompressed there), cost 24.3 to 25.1 us each to verify,
/// hash and decode, the verification nearly all of it; admission, routing and the fan-out's offer
/// add a few more, so 30 us is planned. A planned batch costs some 151 us
/// (`cores::INGEST_RECEPTIONS_PER_THREAD`), so a feeder at [`records_per_sec`] of the default
/// ceiling (eight tiny records a second, 240 us) costs the workers some 1.8 times a planned one.
pub const INGEST_NANOS_PER_RECORD: usize = 30_000;

/// The receptions a second one feeder's connection may send, at most (RFC-0181 §10, "The cores",
/// decided 2026-10-09): the one ceiling a receiver is held to, the same constant MLAT's raw holder
/// sizes a receiver's open bins by (`tally_mlat_solver::held::Rates::MEASURED`, `ceiling_per_s`),
/// three times the 600 a planned feeder sends (`budget::PLANNED_RECEPTIONS_PER_SEC`), which is what
/// the cores are planned at. Past it the read loop waits before it takes the next batch, its socket
/// unread, as it does for records ([`RecordPace`]): a feeder is slowed, never refused. Before, a
/// feeder's receptions were bounded only by its bytes (256 KiB/s, some 15,000 receptions a second
/// at 17 bytes each), so one feeder within its byte ceiling cost the stages 25 planned feeders'.
pub const FEEDER_RECEPTIONS_PER_SEC: u64 =
    tally_mlat_solver::held::Rates::MEASURED.ceiling_per_s as u64;

/// How fast, and how far ahead, one session of a role may send records: `per_minute` a minute,
/// and `burst` at once from rest. What the cores plan for a session is its `per_minute`
/// (`cores::Sessions`); its `burst` is what its role legitimately sends at once (with its Hello,
/// or a credential and its evidence), taken once and refilled at `per_minute`. By the minute, since
/// what most roles need is a heartbeat every 30 s and a few records when something changes, far
/// under one a second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RolePace {
    pub per_minute: u64,
    pub burst: u64,
}

impl RolePace {
    /// A pace of this role's, for one session (or, the directory's, shared by every link).
    pub fn pace(self) -> RecordPace {
        RecordPace::per_minute(self.per_minute, self.burst)
    }
}

/// The most signatures one evidence bundle carries inside it: `MAX_EVIDENCE` feeders'
/// descriptions and as many receipts, each a token of its asker's pace (`credit::check`).
pub const EVIDENCE_SIGNATURES: u64 = 2 * tally_wire::credit::MAX_EVIDENCE as u64;

/// A subscriber's session (R4 of sweep 5): a heartbeat every 30 s, a `Subscribe` when the regions
/// it reads change, a firehose credential with its relay's evidence when it starts and each time
/// the credential is renewed (at most hourly, `MAX_CREDENTIAL_LIFETIME_MS`), and a provider query
/// or an echo now and then: twelve a minute, one every five seconds, holds them with room. Its
/// burst is what it sends with its Hello at most: the credential, the evidence and every signature
/// inside it ([`EVIDENCE_SIGNATURES`], each a token, `credit::check`), and a few more.
pub const SUBSCRIBER_RECORDS: RolePace = RolePace {
    per_minute: 12,
    burst: EVIDENCE_SIGNATURES + 8,
};

/// Another relay's hosted MLAT taking raw one hop (`Role::Engine`): a heartbeat every 30 s and a
/// `Subscribe` when the band it solves changes; it publishes nothing here. Six a minute, and a
/// burst of a few for what comes with its Hello.
pub const ENGINE_RECORDS: RolePace = RolePace {
    per_minute: 6,
    burst: 8,
};

/// A measurement session (`Role::Probe`): a feeder's round of echoes (five, `tally_feed::probe`,
/// each sent once the one before is answered) or one delivery query, then it hangs up, and the
/// feeder probes again minutes later. Its burst holds a round; past it, one every ten seconds.
pub const PROBE_RECORDS: RolePace = RolePace {
    per_minute: 6,
    burst: 8,
};

/// The most records a minute of every session under the connection cap that is not a directory
/// link (not yet identified, probes, engines): what the cores plan each of them at.
pub const GENERAL_RECORDS_PER_MINUTE: u64 = if PROBE_RECORDS.per_minute > ENGINE_RECORDS.per_minute
{
    PROBE_RECORDS.per_minute
} else {
    ENGINE_RECORDS.per_minute
};

/// Every directory link together (a relay that dialled in and is not a member: offers, queries,
/// evidence, echoes, heartbeats, `subscription::on_directory_link`), one pace they share, as the
/// members share theirs: the gossip a relay must take does not grow with the links it comes over
/// (each offer is the same offer on every link), so a relay with many links is planned no more,
/// and one link sending as fast as it may takes at most its turn (each link waits for its own
/// token in order, so of `k` links sending at once each is let in once in `k`). Twice what the
/// directory holds at its bound (`directory::OFFERS_HELD`), each offer re-signed once a minute
/// (`OWN_RESIGN_EVERY_MS`), some 546 a second: half for the offers, half for the queries, echoes
/// and the evidence and its signatures (each a token, `credit::check`). Gossip past it waits: an
/// offer lives three re-signings and evidence a half-life of 30 minutes, so waiting seconds loses
/// nothing.
pub const DIRECTORY_RECORDS: RolePace = RolePace {
    per_minute: 2 * crate::directory::OFFERS_HELD as u64 * 60_000
        / crate::directory::OWN_RESIGN_EVERY_MS,
    burst: 2 * crate::directory::OFFERS_HELD as u64 * 60_000
        / crate::directory::OWN_RESIGN_EVERY_MS,
};

/// A count a second, waited for: a connection's (or the member sessions', or the directory links')
/// records a second ([`records_per_sec`], [`RolePace`]), or a feeder's receptions a second
/// ([`FEEDER_RECEPTIONS_PER_SEC`]). A token bucket of `rate` a second and `burst` at once from
/// rest. Past it the read loop waits before it takes the next record, its socket unread, so TCP
/// holds the sender back as the ingest allowance does. Work a record brings beyond its one token
/// (each signature inside an evidence bundle, `credit::check`) is owed ([`RecordPace::owe`]) and
/// paid before the connection's next record is read. Read off tokio's clock, so a test that pauses
/// time paces with it.
pub struct RecordPace {
    /// Tokens a second.
    rate: f64,
    burst: u64,
    /// Tokens still allowed (negative: owed), as of when.
    state: Mutex<(f64, tokio::time::Instant)>,
}

impl RecordPace {
    /// `rate` a second, a second's worth at once.
    pub fn new(rate: u64) -> Self {
        Self::with_burst(rate, rate)
    }

    /// `rate` a second, `burst` at once.
    pub fn with_burst(rate: u64, burst: u64) -> Self {
        Self::per_minute(rate.saturating_mul(60), burst)
    }

    /// `per_minute` a minute, `burst` at once.
    pub fn per_minute(per_minute: u64, burst: u64) -> Self {
        let burst = burst.max(1);
        Self {
            rate: per_minute.max(1) as f64 / 60.0,
            burst,
            state: Mutex::new((burst as f64, tokio::time::Instant::now())),
        }
    }

    /// Tokens a minute.
    pub fn per_minute_rate(&self) -> u64 {
        (self.rate * 60.0).round() as u64
    }

    /// Takes `count` tokens now, refilled to the moment: how long the pace then owes, if it does.
    fn spend(&self, count: u64) -> Option<Duration> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };
        let now = tokio::time::Instant::now();
        let elapsed = now.saturating_duration_since(state.1).as_secs_f64();
        let allowed = (state.0 + elapsed * self.rate).min(self.burst as f64) - count as f64;
        *state = (allowed, now);
        (allowed < 0.0).then(|| Duration::from_secs_f64(-allowed / self.rate))
    }

    /// One record, waiting while the pace owes more than it has refilled.
    pub async fn take(&self) {
        self.take_many(1).await;
    }

    /// `count` at once (a batch's receptions), waiting until the pace has refilled them.
    pub async fn take_many(&self, count: u64) {
        if let Some(wait) = self.spend(count) {
            tokio::time::sleep(wait).await;
        }
    }

    /// `count` owed without waiting: work done for a record already taken, paid for by the wait
    /// before the next.
    pub fn owe(&self, count: u64) {
        let _ = self.spend(count);
    }
}

/// What a connection holds of Noise buffers at most, both directions together
/// (`tally_wire::noise::READER_BUFFERS`, `tally_wire::noise::WRITER_BUFFERS`, each a whole
/// message): the reader's frame and its plaintext, then the plaintext and the records decoded
/// from it, until every one is handed on; and the writer's plaintext and ciphertext for as long as
/// a send waits on the peer (up to `noise::WRITE_TIMEOUT`). Carved when a connection is admitted
/// and held for the session, so a peer that trickles a message, or reads slowly what it is sent,
/// holds what was planned for it and no more. Before, only the reader's two were carved, while
/// a send held two more for up to 30 s and the reader held a third while it decoded: some 2 GB
/// outside every gauge at 20,000 slow subscribers. With them, the network duties' replies waiting
/// for the write side ([`REPLIES_BYTES`]).
pub const BUFFERS_PER_CONNECTION: usize = (tally_wire::noise::READER_BUFFERS
    + tally_wire::noise::WRITER_BUFFERS)
    * tally_wire::noise::MAX_MESSAGE
    + REPLIES_BYTES;

/// What one connection's replies from the network duties (echo replies, delivery answers, offers
/// for a provider query) hold at most while they wait for its write side, by their encoded bytes:
/// a message's worth, carved with its buffers ([`BUFFERS_PER_CONNECTION`]). A reply past it is
/// dropped (`link::ReplyRoom`): a peer that asks faster than it reads gets fewer answers, never
/// more of the relay's memory. Before (N4), the answers to a whole message were gathered,
/// uncharged, while its records were paced at eight a second, and up to 64 such lists waited for
/// the write side: one 64 KiB message of `ProviderQuery`s, each answered with up to 32 offers,
/// held some 25 MB a connection for minutes.
pub const REPLIES_BYTES: usize = tally_wire::noise::MAX_MESSAGE;

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

/// How many threads each stage runs on. A relay's follow the load it is planned to admit
/// (`Budget::threads`, from `cores::threads_for`); a test names its own, and the output bytes are
/// the same on any of them (RFC-0181, invariant 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Threads {
    /// Ingest workers: verify, hash, admit, inflate, decode, route.
    pub ingest: usize,
    /// Message exchange threads: the one deduplication.
    pub message: usize,
    /// Sealer threads: the sealer and its pool's helpers beside it (`products::Products::on_thread`).
    pub seal: usize,
}

/// One connection's allowance of bytes in the ingest stage (RFC-0181 §2, §10), carved from the
/// relay's `Store::Ingest` when the connection is admitted and held for as long as the connection
/// is: what a feeder reserved ([`FEEDER_ALLOWANCE`]), or a sharing member its feeders' worth. Each
/// batch takes its charge ([`charge_of`]) from it before it is handed over, waiting while the
/// connection holds its allowance (its socket unread), so no peer can hold the room another
/// connection was given.
///
/// A charge is lent its own bytes of the carve ([`Lent`]), and nothing more: while the connection
/// is open they go back to the carve when the charge is let go, and once it has ended they go back
/// to `Store::Ingest` then; the rest of the carve goes back the moment the connection ends. So a
/// batch the connection read holds what it is charged, whoever holds it and for however long, and
/// a connection that ends with batches still queued for the workers holds the store for those
/// batches alone. Before, every charge held the whole carve (some 68 KB for a feeder) until the
/// last of them was let go, and a decode held on (orphans for 3 s, subscriber queues, the notes,
/// the exchange's held parts) kept it: after a network blip at the ceiling, every reconnect was
/// turned away for want of room for its allowance until the old carves drained, and a churner
/// could force it. And before that, the carve went back when the read loop ended while the batches
/// it had read were charged only to the connection's own gauge: a peer that connected, sent a
/// Hello and ~140 KB of batches, and hung up, again and again, queued work no store counted.
pub struct Allowance {
    own: Arc<Gauge>,
    oversize: Arc<Gauge>,
    carve: Arc<Carve>,
}

/// What of a connection's carve no charge has been lent: given back to `Store::Ingest` when the
/// connection's [`Allowance`] is dropped, with it.
struct Carve(Mutex<Charge>);

impl Carve {
    /// `bytes` of the carve lent to a charge (all of it, if less is left: never, while the
    /// connection's own gauge holds its charges to the allowance).
    fn lend(self: &Arc<Self>, bytes: usize) -> Lent {
        let charge = self
            .0
            .lock()
            .map(|mut carve| carve.split(bytes))
            .unwrap_or_default();
        Lent {
            charge,
            home: Arc::downgrade(self),
        }
    }

    /// `charge` back in the carve.
    fn repay(&self, mut charge: Charge) {
        // The carve holds no decode: what the charge was lent for is not covered by it.
        charge.uncover();
        if let Ok(mut carve) = self.0.lock() {
            // Lent from this carve, so on its gauge: absorbed whole.
            let _ = carve.absorb(charge);
        }
    }
}

/// Bytes of `Store::Ingest` one charge holds: lent from its connection's [`Carve`], to which they go
/// back when let go while the connection is open (else to the store, as the charge drops), or
/// charged to the store directly (`InFlight::trusted`), with no carve to go back to.
#[derive(Debug, Default)]
struct Lent {
    charge: Charge,
    home: std::sync::Weak<Carve>,
}

impl Lent {
    fn bytes(&self) -> usize {
        self.charge.bytes()
    }

    /// All but `bytes` let go.
    fn shrink_to(&mut self, bytes: usize) {
        let excess = self.charge.bytes().saturating_sub(bytes);
        let back = self.charge.split(excess);
        self.give_back(back);
    }

    /// `bytes` of it (all, if it holds less) moved into a charge of their own, lent from the same
    /// carve, covering `decoded` (`budget::Charge::split_covering`).
    fn split_covering(&mut self, bytes: usize, decoded: &Arc<tally_wire::Decoded>) -> Self {
        Self {
            charge: self.charge.split_covering(bytes, decoded),
            home: self.home.clone(),
        }
    }

    fn give_back(&self, charge: Charge) {
        match self.home.upgrade() {
            Some(carve) => carve.repay(charge),
            None => drop(charge),
        }
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        let charge = std::mem::take(&mut self.charge);
        self.give_back(charge);
    }
}

impl std::fmt::Debug for Carve {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Carve")
    }
}

impl Allowance {
    /// `bytes` carved from `ingest` (the relay's `Store::Ingest`), batches larger than all of them
    /// taking the rest from `oversize`; `None` when `ingest` has no room for them.
    pub fn carve(ingest: &Arc<Gauge>, oversize: &Arc<Gauge>, bytes: usize) -> Option<Self> {
        let carved = ingest.try_charge(bytes)?;
        Some(Self {
            own: Gauge::new(Store::Ingest, bytes),
            oversize: Arc::clone(oversize),
            carve: Arc::new(Carve(Mutex::new(carved))),
        })
    }

    /// One batch's charge of `bytes`, waiting while the connection holds its allowance. A batch
    /// larger than the whole allowance waits until the connection holds nothing, and takes the rest
    /// from the oversize room ([`OVERSIZE_BYTES`]). The charge is lent its bytes of the carve.
    pub async fn acquire(&self, bytes: usize) -> InFlight {
        let own = bytes.min(self.own.limit());
        let charge = self.own.charge(own).await;
        let over = if bytes > own {
            self.oversize.charge(bytes - own).await
        } else {
            Charge::none()
        };
        InFlight {
            store: self.carve.lend(own),
            own: charge,
            over,
        }
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
/// between a socket and the epochs are charged all the way. What it holds of `Store::Ingest` is its
/// own bytes and no more ([`Lent`]), however long something holds it.
#[derive(Debug)]
pub struct InFlight {
    /// Against its connection's allowance (none for a trusted batch): what bounds the connection.
    own: Charge,
    /// Its bytes of `Store::Ingest`, the same as `own` for a connection's batch.
    store: Lent,
    /// What a batch past its connection's whole allowance takes from the oversize room.
    over: Charge,
}

impl InFlight {
    /// `bytes` charged to `gauge` (the relay's `Store::Ingest`), the caller waiting for room: for
    /// a batch handed in by the relay itself (a test's trace, a replay), on a thread that may
    /// wait. A charge larger than the whole limit waits until nothing else is held.
    pub fn trusted(gauge: &Arc<Gauge>, bytes: usize) -> Self {
        Self {
            own: Charge::none(),
            store: Lent {
                charge: block_on(gauge.charge(bytes)),
                home: std::sync::Weak::new(),
            },
            over: Charge::none(),
        }
    }

    /// Nothing charged: for a test that hands a stage its parts by hand.
    #[cfg(test)]
    pub fn free() -> Self {
        Self {
            own: Charge::none(),
            store: Lent::default(),
            over: Charge::none(),
        }
    }

    pub fn bytes(&self) -> usize {
        self.store.bytes() + self.over.bytes()
    }

    /// This charge is for holding `decoded` (`budget::Charge::cover`), and so is every part split
    /// from it with it ([`InFlight::split`]). Covered once it is shrunk to the decode (`shrink_to`), so what goes back to the
    /// carve covers nothing.
    pub fn cover(&mut self, decoded: &Arc<tally_wire::Decoded>) {
        self.store.charge.cover(decoded);
        self.over.cover(decoded);
    }

    /// Releases all but `bytes` (the oversize room's first): the decode is no larger.
    pub fn shrink_to(&mut self, bytes: usize) {
        let base = self.store.bytes();
        if bytes < base {
            self.over.shrink_to(0);
            self.store.shrink_to(bytes);
            self.own.shrink_to(bytes);
        } else {
            self.over.shrink_to(bytes - base);
        }
    }

    /// `bytes` of this charge (all of it, if it holds less) moved into a charge of their own,
    /// nothing taken or released: a slice's share, handed on with it, covering its decode
    /// `decoded` and no other (`budget::Charge::split_covering`).
    pub fn split(&mut self, bytes: usize, decoded: &Arc<tally_wire::Decoded>) -> InFlight {
        let over = self.over.split_covering(bytes, decoded);
        let rest = bytes - over.bytes();
        InFlight {
            own: self.own.split(rest),
            store: self.store.split_covering(rest, decoded),
            over,
        }
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

/// The ingest clock of a relay: the wall clock, followed without ever going back and without
/// ever jumping ([`Slewed`]). Stamps advance with a monotonic clock, between [`SLOWEST`] and
/// [`FASTEST`] times its pace, closing on the wall clock whenever they are apart: a stamp never
/// steps with the wall clock (a step forward would close every open epoch at once and shed the
/// hosted MLAT's steps; a step back would hold every epoch open, charged), and stamps stay near
/// the wall time feeders and peers read.
///
/// Before, the wall clock was read once, at the start, and only the monotonic clock after it: a
/// relay started before the host's clock was synchronised (the unit now starts after
/// `time-sync.target`), or a virtual machine suspended and resumed (the monotonic clock stops
/// while it sleeps), stayed seconds behind the wall clock for as long as it ran, so every
/// feeder's raw was refused as ahead of its stamp (`held::AHEAD_MS`, 1 s) and MLAT stopped,
/// silently.
pub fn anchored_wall_clock() -> Clock {
    let started = std::time::Instant::now();
    let slewed = Slewed::new(crate::network::wall_ms());
    Arc::new(move || slewed.read(started.elapsed(), crate::network::wall_ms()))
}

/// The most the ingest clock runs ahead of a monotonic clock's pace while it catches up with a
/// wall clock ahead of it: a gap of `g` closes in `g` (a stamp runs two seconds a second). Twice,
/// so the deduplication's window (`exchange::DEDUP_WINDOW_MS`) never spans less than a second of
/// arrivals while it closes, and an epoch never less than half a second.
pub const FASTEST: f64 = 2.0;

/// The least it runs while a wall clock behind it catches up: half the monotonic pace, so epochs
/// still close while a gap of `g` closes in `2g`.
pub const SLOWEST: f64 = 0.5;

/// A clock that follows a wall clock it is read beside, never going back, its pace held between
/// [`SLOWEST`] and [`FASTEST`] times a monotonic clock's: what [`anchored_wall_clock`] reads.
/// Kept to fractions of a millisecond, so a clock read every microsecond still advances.
pub struct Slewed {
    /// The stamp last read, in milliseconds, and the monotonic time it was read at.
    state: Mutex<(f64, Duration)>,
}

impl Slewed {
    /// Starting at `wall_ms`, at monotonic time zero.
    pub fn new(wall_ms: u64) -> Self {
        Self {
            state: Mutex::new((wall_ms as f64, Duration::ZERO)),
        }
    }

    /// The stamp at monotonic time `monotonic`, the wall clock reading `wall_ms`: as far toward
    /// the wall clock as the pace allows since the last read, never before it.
    pub fn read(&self, monotonic: Duration, wall_ms: u64) -> u64 {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (stamp, at) = *state;
        let elapsed = monotonic.saturating_sub(at).as_secs_f64() * 1_000.0;
        let wall = wall_ms as f64;
        let next = if wall > stamp + elapsed {
            wall.min(stamp + elapsed * FASTEST)
        } else {
            wall.max(stamp + elapsed * SLOWEST)
        }
        .max(stamp);
        *state = (next, monotonic.max(at));
        next as u64
    }
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

/// Work for one worker, given its producer number. The relay hands a worker a record only with its
/// charge ([`Stages::run_charged`], [`Stages::run_stamped`]), each at least [`CHARGE_FLOOR`] of
/// `Store::Ingest` and the oversize room, so the records the charges admit are at most their bytes
/// over [`CHARGE_FLOOR`] ([`Room::records`]), however many connections came and went; and the
/// workers' queues take no more than that, whatever the charges say ([`lanes::Lanes`]). Anything else a
/// worker is given is a trace's or a test's (`advance`, `flush`), at most [`CONTROL_QUEUED`] at
/// once, its sender waiting for room; a worker ticks itself.
type Work = Box<dyn FnOnce(usize) + Send>;

/// The rooms a record handed to the ingest workers is charged to: `Store::Ingest` and the
/// oversize room (`Budget::oversize`). What bounds the workers' queues ([`Room::records`]).
#[derive(Clone)]
pub struct Room {
    pub ingest: Arc<Gauge>,
    pub oversize: Arc<Gauge>,
}

impl Room {
    /// The rooms of a relay's budget.
    pub fn of(budget: &crate::budget::Budget) -> Self {
        Self {
            ingest: budget.gauge(Store::Ingest),
            oversize: budget.oversize(),
        }
    }

    /// The most records the two rooms admit at once, each charged at least [`CHARGE_FLOOR`] (and
    /// one, however large, while nothing else is held): read from their limits now, so a budget
    /// resized is followed.
    pub fn records(&self) -> usize {
        self.ingest
            .limit()
            .saturating_add(self.oversize.limit())
            .checked_div(CHARGE_FLOOR)
            .unwrap_or(usize::MAX)
            .max(1)
    }
}

/// The most control work (`Stages::advance`, `Stages::flush`: a trace's and a test's) waiting for
/// the workers at once; a sender past it waits for room.
pub const CONTROL_QUEUED: usize = 64;

/// The workers' queues (R-P9, R1): one a worker, each pushed only through [`lanes::Lanes`], whose
/// two ways in count what they push. A charged record is counted against [`Room::records`], every
/// worker together, and one past it is refused and counted, never queued; control work waits while
/// [`CONTROL_QUEUED`] wait. A queue is a `VecDeque` behind its lane's lock with no way to push but
/// those two, so no path can hand a worker anything uncounted.
///
/// Before, each queue was an `mpsc::channel`, unbounded, with the count kept beside it: bounded
/// only while every path that sent on it counted first, and the refusals it counted were read by
/// no report (`Hub::memory_report` serves them now, `ingest_refused`).
mod lanes {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use super::{CONTROL_QUEUED, Room, Work};

    enum Item {
        Record(Work),
        Control(Work),
    }

    #[derive(Default)]
    struct State {
        items: VecDeque<Item>,
        closed: bool,
    }

    #[derive(Default)]
    struct Lane {
        state: Mutex<State>,
        ready: Condvar,
    }

    impl Lane {
        fn lock(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }

    /// What a worker is given next.
    pub(super) enum Next {
        Work(Work),
        /// Nothing came within the wait: the worker ticks.
        Idle,
        /// Its stages are dropped and its queue is empty: the worker ends.
        Closed,
    }

    pub(super) struct Lanes {
        lanes: Box<[Lane]>,
        room: Room,
        records: AtomicUsize,
        refused: AtomicU64,
        control: Mutex<usize>,
        control_taken: Condvar,
    }

    impl Lanes {
        pub(super) fn new(workers: usize, room: Room) -> Self {
            Self {
                lanes: (0..workers.max(1)).map(|_| Lane::default()).collect(),
                room,
                records: AtomicUsize::new(0),
                refused: AtomicU64::new(0),
                control: Mutex::new(0),
                control_taken: Condvar::new(),
            }
        }

        pub(super) fn width(&self) -> usize {
            self.lanes.len()
        }

        fn lane(&self, worker: usize) -> &Lane {
            &self.lanes[worker % self.lanes.len()]
        }

        /// A charged record onto worker `worker`'s queue, counted: false, counted refused, when
        /// the queues hold all the records the rooms admit ([`Room::records`]). One handed to a
        /// worker that is gone (the stages being dropped) is dropped unrun.
        pub(super) fn push_record(&self, worker: usize, work: Work) -> bool {
            let bound = self.room.records();
            let admitted = self
                .records
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                    (queued < bound).then_some(queued + 1)
                })
                .is_ok();
            if !admitted {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if !self.push(worker, Item::Record(work)) {
                self.records.fetch_sub(1, Ordering::AcqRel);
            }
            true
        }

        /// Control work onto worker `worker`'s queue, waiting while [`CONTROL_QUEUED`] wait.
        pub(super) fn push_control(&self, worker: usize, work: Work) {
            {
                let mut waiting = self.control.lock().unwrap_or_else(PoisonError::into_inner);
                while *waiting >= CONTROL_QUEUED {
                    waiting = self
                        .control_taken
                        .wait(waiting)
                        .unwrap_or_else(PoisonError::into_inner);
                }
                *waiting += 1;
            }
            if !self.push(worker, Item::Control(work)) {
                self.control_done();
            }
        }

        fn push(&self, worker: usize, item: Item) -> bool {
            let lane = self.lane(worker);
            let mut state = lane.lock();
            if state.closed {
                return false;
            }
            state.items.push_back(item);
            drop(state);
            lane.ready.notify_one();
            true
        }

        fn control_done(&self) {
            {
                let mut waiting = self.control.lock().unwrap_or_else(PoisonError::into_inner);
                *waiting = waiting.saturating_sub(1);
            }
            self.control_taken.notify_all();
        }

        /// Worker `worker`'s next work, waiting up to `wait` for it; uncounted as it is taken.
        pub(super) fn next(&self, worker: usize, wait: Duration) -> Next {
            let lane = self.lane(worker);
            let mut state = lane.lock();
            loop {
                match state.items.pop_front() {
                    Some(Item::Record(work)) => {
                        self.records.fetch_sub(1, Ordering::AcqRel);
                        return Next::Work(work);
                    }
                    Some(Item::Control(work)) => {
                        drop(state);
                        self.control_done();
                        return Next::Work(work);
                    }
                    None if state.closed => return Next::Closed,
                    None => {
                        let (again, waited) = lane
                            .ready
                            .wait_timeout(state, wait)
                            .unwrap_or_else(PoisonError::into_inner);
                        state = again;
                        if waited.timed_out() && state.items.is_empty() && !state.closed {
                            return Next::Idle;
                        }
                    }
                }
            }
        }

        /// No more work is taken: each worker runs what its queue holds, then ends.
        pub(super) fn close(&self) {
            for lane in &*self.lanes {
                lane.lock().closed = true;
                lane.ready.notify_all();
            }
        }

        /// Records refused because the queues held their bound.
        pub(super) fn refused(&self) -> u64 {
            self.refused.load(Ordering::Relaxed)
        }

        /// Records waiting for the workers now.
        pub(super) fn queued(&self) -> usize {
            self.records.load(Ordering::Acquire)
        }
    }
}

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
        lanes: Arc<lanes::Lanes>,
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
    /// test's; none in a relay), the records waiting for the workers at most what `room` admits
    /// ([`Room::records`]). Every thread is running or the stages are not made: a worker that
    /// cannot be started fails the relay at its start, since every message thread waits for every
    /// worker's tick and one missing would close no epoch ever.
    pub fn threaded(
        clock: Clock,
        threads: Threads,
        (sink, gauges, room): (&Sink, &Gauges, Room),
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
        let lanes = Arc::new(lanes::Lanes::new(workers, room));
        // Dropping `stages` on a failure stops and joins the workers already started.
        let mut stages = Self {
            core: Arc::clone(&core),
            pool: Pool::Threads {
                lanes: Arc::clone(&lanes),
                handles: Vec::with_capacity(workers),
            },
        };
        for producer in 0..workers {
            let core = Arc::clone(&core);
            let lanes = Arc::clone(&lanes);
            let spawned = std::thread::Builder::new()
                .name(format!("tally-ingest-{producer}"))
                .spawn(move || {
                    loop {
                        match lanes.next(producer, Duration::from_millis(TICK_MS)) {
                            lanes::Next::Work(work) => {
                                work(producer);
                                core.tick(producer, false);
                            }
                            lanes::Next::Idle => core.tick(producer, true),
                            lanes::Next::Closed => break,
                        }
                    }
                });
            let handle = spawned
                .map_err(|error| format!("ingest thread {producer} of {workers}: {error}"))?;
            if let Pool::Threads { handles, .. } = &mut stages.pool {
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
            Pool::Threads { lanes, .. } => lanes.width(),
        }
    }

    /// The worker that owns raw shard `shard`.
    pub fn worker_of(&self, shard: crate::exchange::ShardId) -> usize {
        crate::exchange::thread_of(shard, self.width())
    }

    /// Runs a batch's `work` on worker `worker`, with its charge: the one way a batch reaches a
    /// worker, so the batches waiting for the workers are charged. False, counted
    /// ([`Stages::refused`]), when the workers' queues hold all the records the rooms admit
    /// ([`Room::records`]): the record is let go with its charge, never queued past the bound.
    pub fn run_charged(&self, worker: usize, in_flight: InFlight, work: ChargedWork) -> bool {
        self.run_record(worker, Box::new(move |producer| work(producer, in_flight)))
    }

    /// Records refused because the workers' queues held their bound: none while every record is
    /// charged as it should be. Served on `GET /memory` (`hub::MemoryReport::ingest_refused`).
    pub fn refused(&self) -> u64 {
        match &self.pool {
            Pool::Inline(_) => 0,
            Pool::Threads { lanes, .. } => lanes.refused(),
        }
    }

    /// Records waiting for the workers now.
    pub fn queued(&self) -> usize {
        match &self.pool {
            Pool::Inline(_) => 0,
            Pool::Threads { lanes, .. } => lanes.queued(),
        }
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
    ) -> bool {
        let core = Arc::clone(&self.core);
        self.run_record(
            worker,
            Box::new(move |producer| {
                let stamp = given.map_or_else(
                    || core.stamp(producer),
                    |stamp| core.stamped(producer, stamp),
                );
                work(stamp, in_flight);
            }),
        )
    }

    /// Runs a charged record's `work` on worker `worker`, counted in the workers' queues until a
    /// worker takes it; false, counted, when they hold their bound.
    fn run_record(&self, worker: usize, work: Work) -> bool {
        match &self.pool {
            Pool::Inline(lock) => {
                self.run_inline(lock, work);
                true
            }
            Pool::Threads { lanes, .. } => lanes.push_record(worker, work),
        }
    }

    /// Runs control work (a trace's or a test's) on worker `worker`, waiting while
    /// [`CONTROL_QUEUED`] wait.
    fn run_control(&self, worker: usize, work: Work) {
        match &self.pool {
            Pool::Inline(lock) => self.run_inline(lock, work),
            Pool::Threads { lanes, .. } => lanes.push_control(worker, work),
        }
    }

    /// Runs `work` now, on the caller, then ticks.
    fn run_inline(&self, lock: &Mutex<()>, work: Work) {
        let _held = lock.lock();
        work(0);
        self.core.tick(0, true);
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

    /// As `decode`, covered by `in_flight` before it is counted alive
    /// (`Decoded::from_verified_held`): never a decode alive no charge covers, even for an instant.
    pub fn decode_covered(
        batch: Batch,
        stamp: Stamp,
        in_flight: &mut InFlight,
    ) -> Result<Arc<Decoded>, Box<Undecodable>> {
        Decoded::from_verified_held(batch, stamp.stamp_ms, stamp.ingest_seq, |decoded| {
            in_flight.cover(decoded);
        })
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
            Pool::Threads { lanes, .. } => {
                for worker in 0..lanes.width() {
                    let core = Arc::clone(&self.core);
                    self.run_control(
                        worker,
                        Box::new(move |producer| {
                            core.tick_at(producer, stamp_ms);
                        }),
                    );
                }
            }
        }
    }
}

impl Stages {
    /// Waits until every worker has done everything handed to it before this call (each worker
    /// takes its work in order). For a trace's end, and a test's.
    pub fn flush(&self) {
        if let Pool::Threads { lanes, .. } = &self.pool {
            let (done, finished) = std::sync::mpsc::channel::<()>();
            let waiting = lanes.width();
            for worker in 0..waiting {
                let done = done.clone();
                self.run_control(
                    worker,
                    Box::new(move |_| {
                        let _ = done.send(());
                    }),
                );
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
        if let Pool::Threads { lanes, handles } = &mut self.pool {
            lanes.close();
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
        let slice = in_flight.split(100, &decoded);
        assert_eq!(
            (slice.bytes(), in_flight.bytes(), gauge.held()),
            (100, decoded.footprint() - 100, decoded.footprint())
        );
        drop(slice);
        drop(in_flight);
        assert_eq!(gauge.held(), 0);
        Ok(())
    }

    /// RFC-0181 invariant 2: the relay's ingest clock is the wall clock now, never going back.
    #[test]
    fn the_relays_clock_follows_the_wall_and_never_goes_back() {
        let clock = anchored_wall_clock();
        let wall = crate::network::wall_ms();
        let first = clock();
        assert!(first.abs_diff(wall) < 60_000);
        let mut last = first;
        for _ in 0..1_000 {
            let now = clock();
            assert!(now >= last);
            last = now;
        }
    }

    /// A relay started behind the wall clock (before the host's clock was synchronised), or
    /// resumed after a suspend (its monotonic clock stood still while it slept), catches up: its
    /// stamps run at most twice the monotonic pace, never jump, and meet the wall clock in as long
    /// as they were behind; then they follow it. Read every microsecond, they still advance. The
    /// clock read once from the wall stayed the five seconds behind for ever.
    #[test]
    fn a_clock_behind_the_wall_catches_up_at_a_bounded_pace() {
        let clock = Slewed::new(10_000);
        let mut last = clock.read(Duration::ZERO, 15_000);
        assert_eq!(last, 10_000);
        let mut met = None;
        for tenth in 1..=100u64 {
            let monotonic = Duration::from_millis(100 * tenth);
            let wall = 15_000 + 100 * tenth;
            let stamp = clock.read(monotonic, wall);
            assert!(stamp >= last && stamp - last <= 200, "{last} then {stamp}");
            assert!(stamp <= wall);
            if stamp == wall && met.is_none() {
                met = Some(tenth);
            }
            last = stamp;
        }
        // Five seconds behind, two seconds a second: met after five seconds, and kept.
        assert_eq!(met, Some(50));
        assert_eq!(last, 25_000);
        let fine = Slewed::new(0);
        let mut stamp = 0;
        for micro in 1..=5_000u64 {
            stamp = fine.read(Duration::from_micros(micro), 1_000_000);
        }
        assert_eq!(stamp, 10);
    }

    /// A wall clock stepped back is never followed back: the stamps slow to half the monotonic
    /// pace, so epochs still close, until the wall clock catches them up.
    #[test]
    fn a_clock_ahead_of_the_wall_slows_and_never_goes_back() {
        let clock = Slewed::new(20_000);
        let mut last = clock.read(Duration::ZERO, 20_000);
        for tenth in 1..=100u64 {
            let monotonic = Duration::from_millis(100 * tenth);
            // The wall clock stepped back three seconds.
            let wall = 17_000 + 100 * tenth;
            let stamp = clock.read(monotonic, wall);
            assert!(
                stamp >= last + 50 && stamp - last <= 100,
                "{last} then {stamp}"
            );
            last = stamp;
        }
        // Three seconds ahead, losing half a second a second: met after six seconds.
        assert_eq!(last, 27_000);
    }

    /// RFC-0181 §2: a batch a connection read holds the store for its own bytes for as long as
    /// anything holds it, whenever the connection ended. A peer that connects, sends a batch the
    /// workers have not taken, and hangs up, again and again, holds `Store::Ingest` for every batch
    /// it left queued, so the next connection is turned away once the store is full and nothing
    /// queues uncounted. Before, the carve went back with the read loop, and the store said 0
    /// while the batches waited.
    #[tokio::test]
    async fn a_batch_a_connection_left_holds_the_store_for_its_own_bytes() -> Result<(), String> {
        let decoded = a_decode()?;
        let ingest = Gauge::new(Store::Ingest, 300);
        let oversize = Gauge::new(Store::Ingest, 1_000);
        let mut queued = Vec::new();
        let mut connected = 0;
        while let Some(allowance) = Allowance::carve(&ingest, &oversize, 100) {
            connected += 1;
            // A batch handed to the workers, then the connection ends.
            queued.push(allowance.acquire(40).await);
            drop(allowance);
            assert_eq!(ingest.held(), 40 * connected);
            assert!(connected <= 6, "connected past the store");
        }
        // Five batches left behind, and room for one more allowance beside them.
        assert_eq!(connected, 6);
        // A slice of a queued batch still holds its share after the rest goes.
        let mut first = queued.remove(0);
        let slice = first.split(10, &decoded);
        drop(first);
        assert_eq!(ingest.held(), 210);
        drop(slice);
        assert_eq!(ingest.held(), 200);
        drop(queued);
        assert_eq!(ingest.held(), 0);
        Ok(())
    }

    /// A signed batch of forty receptions, decoded.
    fn a_decode() -> Result<Arc<Decoded>, String> {
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
        Stages::decode(batch, Stamp::default()).map_err(|undecodable| undecodable.error.to_string())
    }

    /// RFC-0181 §2: what a batch holds of `Store::Ingest` is its own bytes, never its connection's
    /// whole carve. A connection ends while a batch it read is still held (its decode in the
    /// orphans, a subscriber's queue, the exchange's held parts), and its peer reconnects at once:
    /// the new connection's allowance fits beside that batch's bytes. Before, every charge held
    /// the whole carve until the last of them was let go, so after a network blip at the ceiling
    /// every reconnect was turned away ("no room for its ingest allowance") until the old decodes
    /// were gone, and a churner could keep it so. While a connection is open, what its charges let
    /// go goes back to its own carve, never to the store, so it keeps its whole allowance.
    #[tokio::test]
    async fn a_batch_holds_its_own_bytes_of_the_carve_and_no_more() -> Result<(), String> {
        let ingest = Gauge::new(Store::Ingest, 300);
        let oversize = Gauge::new(Store::Ingest, 1_000);
        let first = Allowance::carve(&ingest, &oversize, 100).ok_or("the first carve fits")?;
        let mut held = first.acquire(40).await;
        // Decoded smaller: what it let go is the open connection's again, not the store's.
        held.shrink_to(30);
        assert_eq!((ingest.held(), first.available()), (100, 70));
        // The connection ends, its batch still held: the store holds the batch's bytes alone.
        drop(first);
        assert_eq!(ingest.held(), 30);
        // Its peer reconnects, and another beside it: both fit beside the batch, a third not.
        let second = Allowance::carve(&ingest, &oversize, 100).ok_or("a reconnect fits")?;
        let third = Allowance::carve(&ingest, &oversize, 100).ok_or("a second one fits")?;
        assert_eq!(ingest.held(), 230);
        assert!(Allowance::carve(&ingest, &oversize, 100).is_none());
        // A slice of the old batch holds its share, the rest its own.
        let slice = held.split(10, &a_decode()?);
        drop(held);
        assert_eq!(ingest.held(), 210);
        drop(slice);
        assert_eq!(ingest.held(), 200);
        // An open connection's charges come from its carve and go back to it: the store holds the
        // two carves whatever they lend.
        let lent = second.acquire(100).await;
        assert_eq!((ingest.held(), second.available()), (200, 0));
        drop(lent);
        assert_eq!((ingest.held(), second.available()), (200, 100));
        drop((second, third));
        assert_eq!(ingest.held(), 0);
        Ok(())
    }

    /// RFC-0181 §2: however small its records, a connection has at most `RECORDS_IN_FLIGHT` of
    /// them waiting for, or in, the workers: each is charged at least `CHARGE_FLOOR`, the cost of
    /// its verification. By bytes alone a 300-byte batch took some 500 places.
    #[tokio::test]
    async fn a_connection_holds_at_most_its_records_in_flight_however_small() -> Result<(), String>
    {
        let identity = tally_wire::Identity::generate().map_err(|error| error.to_string())?;
        let tiny = Batch::sign(
            &identity,
            &tally_wire::BatchContent {
                boot_id: 1,
                sequence: 0,
                counter_epoch: 0,
                wall_ms: 0,
                dropped: 0,
                previous: [0; 32],
                observations: Vec::new(),
            },
        )
        .map_err(|error| error.to_string())?;
        assert!(tiny.as_bytes().len() < 400);
        assert_eq!(charge_of(&tiny), CHARGE_FLOOR);
        let ingest = Gauge::unlimited(Store::Ingest);
        let oversize = Gauge::new(Store::Ingest, OVERSIZE_BYTES);
        let allowance = Allowance::carve(&ingest, &oversize, FEEDER_ALLOWANCE)
            .ok_or("an allowance fits an unlimited store")?;
        let mut held = Vec::new();
        while let Ok(in_flight) =
            tokio::time::timeout(Duration::ZERO, allowance.acquire(charge_of(&tiny))).await
        {
            held.push(in_flight);
            if held.len() > 10 * RECORDS_IN_FLIGHT {
                break;
            }
        }
        assert_eq!(held.len(), RECORDS_IN_FLIGHT);
        Ok(())
    }

    /// Rooms that bound nothing: a test's stages.
    fn unlimited_room() -> Room {
        Room {
            ingest: Gauge::unlimited(Store::Ingest),
            oversize: Gauge::unlimited(Store::Ingest),
        }
    }

    /// R-P9: the workers' queues are bounded by construction, not only by what the charges admit.
    /// The one worker is held at a gate while records are handed in: the queues take as many as
    /// the rooms admit (`Room::records`, here two) and refuse, counted, the next, letting its charge
    /// go at once; the worker let go runs the two it holds. Before, each worker's queue was an
    /// unbounded channel: a record handed in past what the charges allow (a path that charged
    /// short, or not at all) was queued all the same, and the queue grew without limit.
    #[test]
    fn the_workers_queues_hold_no_more_than_the_rooms_admit() -> Result<(), String> {
        let room = Room {
            ingest: Gauge::new(Store::Ingest, 2 * CHARGE_FLOOR),
            oversize: Gauge::new(Store::Ingest, 0),
        };
        assert_eq!(room.records(), 2);
        let sink: Sink = Arc::new(|_| Ok(()));
        let threads = Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        };
        let stages = Stages::threaded(
            Arc::new(|| 0),
            threads,
            (&sink, &Gauges::unlimited(), room),
            None,
        )?;
        // The worker takes the first and waits at the gate inside it.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let (started, running) = channel::<()>();
        let held = Arc::clone(&gate);
        assert!(stages.run_charged(
            0,
            InFlight::free(),
            Box::new(move |_, _| {
                let _ = started.send(());
                let (open, opened) = &*held;
                if let Ok(mut open) = open.lock() {
                    while !*open {
                        match opened.wait(open) {
                            Ok(again) => open = again,
                            Err(_) => return,
                        }
                    }
                }
            }),
        ));
        running
            .recv_timeout(Duration::from_secs(60))
            .map_err(|_| "the worker never took the first record".to_owned())?;
        // Two wait for it, each charged; the third is refused and its charge let go.
        let charges = Gauge::unlimited(Store::Ingest);
        let (ran, done) = channel::<()>();
        let mut handed = Vec::new();
        for _ in 0..3 {
            let ran = ran.clone();
            handed.push(stages.run_charged(
                0,
                InFlight::trusted(&charges, CHARGE_FLOOR),
                Box::new(move |_, in_flight| {
                    drop(in_flight);
                    let _ = ran.send(());
                }),
            ));
        }
        drop(ran);
        assert_eq!(handed, [true, true, false]);
        assert_eq!((stages.queued(), stages.refused()), (2, 1));
        assert_eq!(charges.held(), 2 * CHARGE_FLOOR);
        // Let go, the worker runs the two it holds, and the queues are empty again.
        let (open, opened) = &*gate;
        if let Ok(mut open) = open.lock() {
            *open = true;
        }
        opened.notify_all();
        for _ in 0..2 {
            done.recv_timeout(Duration::from_secs(60))
                .map_err(|_| "a queued record never ran".to_owned())?;
        }
        stages.flush();
        assert_eq!((stages.queued(), charges.held()), (0, 0));
        Ok(())
    }

    /// R-N12: a connection's records a second are held to its byte ceiling over `RECORD_BYTES`,
    /// whatever their bytes: at the default feeder ceiling, eight a second after a second's burst,
    /// so tiny batches sent as fast as the socket takes them are some eight signature checks a
    /// second, not the 870 they were. Paused time: each wait is the pace's exactly.
    #[tokio::test(start_paused = true)]
    async fn a_connections_records_a_second_are_held_to_its_ceiling() {
        assert_eq!(records_per_sec(256 * 1024), 8);
        assert_eq!(records_per_sec(0), 1);
        let pace = RecordPace::new(records_per_sec(256 * 1024));
        let start = tokio::time::Instant::now();
        // The burst at once.
        for _ in 0..8 {
            pace.take().await;
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
        // Then eight a second: forty more take five seconds.
        for _ in 0..40 {
            pace.take().await;
        }
        assert_eq!(start.elapsed(), Duration::from_secs(5));
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
            seal: 2,
        };
        products.on_thread(threads, Some(&pause))?;
        let sink = products.sink();
        let clock = Arc::new(AtomicU64::new(0));
        let reading = Arc::clone(&clock);
        let stages = Arc::new(Stages::threaded(
            Arc::new(move || reading.load(Ordering::Relaxed)),
            threads,
            (&sink, &Gauges::unlimited(), unlimited_room()),
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
            stages.run_record(
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
}
