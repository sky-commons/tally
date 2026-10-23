//! One relay's part in its sharing groups (RFC-0174 §2.5), as a state machine with no I/O and no
//! clock of its own: records and messages go in with the time, and what to send to whom comes
//! out. `Sharing` (the network seam) drives it from links and the tick; the tests drive many of
//! them over a virtual clock.
//!
//! The duty, per group (an area cell and one product):
//!
//! - **Seed.** An origin (a relay that took a record in from its feeder, or solved it) sends each
//!   record once into the group, to its stripe's seed (`seeds`), and down its own subtree of the
//!   stripe, which the seed's copy would not reach: it stops at the origin, which holds it.
//! - **Push (eager).** A member that receives a record it did not hold forwards it at once to its
//!   children in the record's stripe (cut-through: the next hop waits for nothing).
//! - **Manifest.** After each second an origin signs the hashes it originated
//!   (`PieceManifest`) and floods it over every tree edge, with the parity of those records down
//!   the parity stripe. A record no manifest lists is held and forwarded but never credited.
//! - **Rebuild.** A member missing records of one data stripe of a manifest rebuilds them from the
//!   others and the parity, and hands them to its relay, which judges each as it judges a piece a
//!   member sent and only then has it forwarded on as if it had arrived (`Member::pass_on`), so
//!   losing a parent costs one stripe only until the parity comes, and a record that fails its
//!   relay's judgment travels no further.
//! - **Repair (lazy).** A member still missing records asks a rotating member with its
//!   `HaveSummary` (which seconds it holds whole); the answer is the manifests and records of the
//!   seconds it lacks, paged. Repaired records are pushed on too (Plumtree's graft). It never asks
//!   a member that cannot answer it: one it routes around as full (the ask would go nowhere), or
//!   one it turned away as full while that one may still route around it, its wait and slack
//!   (which sends it nothing, its answer included). Before, it asked them in turn with the rest,
//!   and a full member repaired at half the pace its one admitted link could carry.
//! - **Receipts.** After each window a child signs, for each stripe, a `StripeReceipt` for what
//!   its parent (or, for a seed, each origin) delivered of what the manifests list, and sends it to
//!   the deliverer: the evidence of the deliverer's credit. One short of what was owed is also a
//!   report: it floods to the group.
//! - **Full members.** A member that turned this relay's link away because it holds every member
//!   session its plan admits (`Reason::Full`, `peers`) is routed around while it is full: what
//!   this relay would send it down a stripe goes instead to the next members of that stripe's tree
//!   beneath it (its children, and theirs where they are full too), a manifest to them in every
//!   stripe, and what was for it alone (a receipt, a have-summary, an ask) nowhere. The trees are
//!   not changed: every relay still lays out the same ones, and the full member's children are fed
//!   past it by whoever would have fed it. Routing around is never taken for a fault, on either
//!   side of it. The full member files no shortfall against a relay it turned away for the windows
//!   that relay was routing around it: it keeps the same wait for it (`full::Wait`, the one rule
//!   both ends apply to the same refusals), so it knows them exactly. And a child whose records
//!   reached it past its parent, from above the parent in the stripe's tree (or from their origin)
//!   before they could have been repaired, was not starved: the parent was being routed around, so
//!   it files no shortfall against the parent and signs its receipt to whoever delivered instead.
//! - **Demotion.** When most of a member's children in a stripe report it short for the same
//!   window, and it did not itself report being starved then, every member drops it from the
//!   trees for `groups::DEMOTION_MS`. Windows in which the trees changed (membership, or a seed
//!   rotation at their end) are not judged, so a move is never mistaken for a fault.
//!
//! **Work follows activity.** A group is held only while it is something more than this relay
//! alone with nothing: another member, or records, manifests, receipts or demotions within the
//! horizon. One that is neither is let go (its trees are this relay alone, which any reader can
//! compute: `Sharing::layout`), so a relay that takes every area of the world holds no group until
//! one carries something. And the tick visits only the groups with something due: each held group
//! is scheduled for when its next duty falls (now, while it holds records; else the next seed
//! rotation or anti-entropy ask while it has other members, and the end of a demotion), so a tick
//! with nothing due does no work whatever the groups held.
//!
//! **Deadlines are given, not read.** A verdict on a deliverer (a receipt short of what it owed, a
//! shortfall, a demotion) is a comparison of when things arrived against a deadline: what came
//! after the receipt grace is not counted to whoever delivered it. The deadlines are a value the
//! member is built with (`Deadlines`), never a constant inside the logic: a relay passes
//! `Deadlines::RELAY`, and a test that judges a delivery over real links declares its own, past
//! anything the machine running it can delay, so its verdict follows what was delivered and not
//! the machine's load. Everything that follows from them (the horizon what is held for, the
//! windows a refusal covers) is read from the same value.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tally_wire::Signs;
use tally_wire::batch::Hash;
use tally_wire::clocks::{Judged, Mono, Span};
use tally_wire::record::{KIND_BATCH, KIND_RELAY_BATCH};
use tally_wire::sharing::{MAX_HAVE_SECONDS, MAX_PIECES, receipt_digest};
use tally_wire::{
    Batch, Bytes, Check, HaveSummary, ParityChunk, PieceManifest, PieceManifestContent, PublicKey,
    Record, StripeAssignment, StripeReceipt, StripeReceiptContent,
};

use crate::budget::{Charge, Gauge};
use crate::footprint::{self, Tree};

use super::full::Wait;
use super::groups::{DEMOTION_MS, GroupKey};
use super::parity::{Parity, id_of};
use super::seeds::{SEED_ROTATION_SECONDS, epoch_of};
use super::stripes::{DATA_STRIPES, Layout, PARITY_STRIPE, STRIPES, data_stripe, score};

/// After a second ends, how long an origin waits before signing its manifest and parity.
pub const MANIFEST_DELAY_MS: u64 = 200;
/// After a second ends, when a member first tries to rebuild a stripe it lacks from parity.
pub const REBUILD_AFTER_MS: u64 = 700;
/// The least time between two asks for repair in one group.
pub const REPAIR_INTERVAL_MS: u64 = 500;
/// How often a member compares holdings with another even with nothing known missing, so a
/// manifest that never arrived is found.
pub const ANTI_ENTROPY_MS: u64 = 5_000;
/// The seconds one receipt covers. Divides `SEED_ROTATION_SECONDS`, so rotations fall between
/// windows.
pub const RECEIPT_WINDOW_SECONDS: u64 = 5;

/// The deadlines a member judges its deliverers by: what arrives after one is not counted to who
/// delivered it, so a member that delivered late is reported short (a shortfall) and, judged,
/// demoted. They are a value the member is built with (`Member::new`, through `Sharing::new` and
/// the hub), never read inside its logic, so no caller gets them by default: a relay's are
/// [`Deadlines::RELAY`], and a test that judges deliveries over real links and the machine's clock
/// declares its own, past anything the machine running it can delay, so the verdict it asserts
/// follows what was delivered and not how loaded the machine is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadlines {
    /// After a second ends, when it is settled: a member first asks another for what it still
    /// lacks of it, and what reached it before then from above its parent in the stripe's tree (or
    /// from the record's origin) was pushed past the parent, which was being routed around, and not
    /// a repair (`routed_past`).
    pub repair_after: Span<Judged>,
    /// After a window ends, how long a child waits (for rebuilds and repairs to arrive from its
    /// parent) before signing its receipts. What its deliverer delivered later is not on them.
    pub receipt_grace: Span<Judged>,
    /// After the receipts of a window, how long before the group judges it. A report (a
    /// shortfall, or a deliverer's own starvation, which excuses it) that arrives later is not
    /// weighed.
    pub judge_after: Span<Judged>,
    /// How long past a refusal's wait the relay refused may still be routing around this one: its
    /// wait starts when the `Goodbye` reaches it, a link's latency after this relay sent it.
    pub route_slack: Span<Judged>,
}

impl Deadlines {
    /// A relay's.
    pub const RELAY: Self = Self {
        repair_after: tally_wire::budget::policy::<_, 1_500>(),
        receipt_grace: tally_wire::budget::policy::<_, 4_000>(),
        judge_after: tally_wire::budget::policy::<_, 2_000>(),
        route_slack: tally_wire::budget::policy::<_, 1_000>(),
    };

    /// How far back a member holds records and manifests: as long as its own duties need them, and
    /// no longer. A record of a window's first second is owed in that window's receipts, signed
    /// `receipt_grace` after the window ends, judged `judge_after` after that, and a member
    /// short of it asks for repair from `repair_after` on; so the horizon is the window, the
    /// grace, the judgment and the repair delay (a relay's, 12.5 s). A relay's is the one batch
    /// byte store's window (RFC-0181 §6): what it holds of a batch's bytes after it is passed on.
    pub const fn horizon_ms(self) -> u64 {
        RECEIPT_WINDOW_SECONDS * 1000
            + self.receipt_grace.ms()
            + self.judge_after.ms()
            + self.repair_after.ms()
    }

    /// The horizon rounded up to whole seconds: what is held is kept by its second.
    pub const fn horizon_seconds(self) -> u64 {
        self.horizon_ms().div_ceil(1000)
    }

    /// [`Deadlines::horizon_seconds`] as a span of the judging clock: what the sharing windows
    /// hold a signed second for (`tally_wire::budget::Window::sharing`).
    pub const fn horizon(self) -> Span<Judged> {
        tally_wire::budget::policy::<_, { RECEIPT_WINDOW_SECONDS * 1000 }>()
            .plus(self.receipt_grace)
            .plus(self.judge_after)
            .plus(self.repair_after)
            .whole_seconds()
    }
}

/// The most bytes one answer to a `HaveSummary` carries. It travels as one send over this relay's
/// member link to the asker, so it is half what may wait for one link
/// (`peers::WAITING_PER_LINK_BYTES` is twice it): a whole page and its records' overhead fit beside
/// the stripes' own sends of the tick, never refused whole for being a page.
pub const REPAIR_PAGE_BYTES: usize = 128 * 1024;
/// The least time between two answers to one member's `HaveSummary`s.
pub const ANSWER_INTERVAL_MS: u64 = REPAIR_INTERVAL_MS / 2;
/// The most manifests held from one origin for one second of one group: `MAX_PIECES` records
/// each, so 14,400 records a second from one origin in one area, far past any feeder count. The
/// cap is per origin, so a member flooding manifests fills only its own share, never another's.
pub const MAX_MANIFESTS_PER_ORIGIN_SECOND: usize = 8;
const REPAIR: &[u8] = b"tally sharing repair";

/// Something to send.
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub to: PublicKey,
    pub message: Message,
}

/// A record as a group holds and passes it: a batch as the batch itself (its bytes are the one
/// shared allocation every stage of the relay holds a handle to, so the group copies nothing), any
/// other record as its encoding, shared. Its length is its encoded length, which is what parity
/// covers and what is counted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    /// Shared: a piece goes to several members, and a batch carries its decompressed key.
    Batch(Arc<Batch>),
    RelayBatch(Arc<Batch>),
    Encoded(Bytes),
}

/// A record's header: kind, then its body's length.
const HEADER_LEN: usize = 3;

/// The senders a record or parity is planned to be noted from: its parent in its stripe's tree,
/// and one more, the member a route-around repair brings it from. Noting more is
/// charged what it allocates as ever (`note_growth`), so a record with more is refused room
/// sooner, never held past its charge.
pub const PLANNED_SENDERS: usize = 2;

/// What a list of [`PLANNED_SENDERS`] allocates, grown as [`note`] grows it.
const PLANNED_SENDERS_BYTES: usize = footprint::vec::<Sender>(grown(grown(0)));

/// What a group is planned at for one record beside its signed bytes, held or credited, whichever
/// allocates more (a record is one or the other: a credit's place is let go when the record is
/// held, `Member::piece`): held, its entry in the group's tree of records at the most a tree costs
/// an entry (`footprint::btree_planned`), the shared batch it names ([`Piece::held_len`]) and its
/// senders; credited, its entry in the tree of credits and its senders.
pub const PIECE_ENTRY_BYTES: usize = {
    let held =
        Tree::<Hash, Held>::bytes_per_entry() + footprint::arc::<Batch>() + PLANNED_SENDERS_BYTES;
    let credited = Tree::<Hash, Credited>::bytes_per_entry() + PLANNED_SENDERS_BYTES;
    if held > credited { held } else { credited }
};

/// What a group is planned at for one parity beside its XOR: its entry in the group's tree of
/// parities, the parity's own allocation and its senders.
pub const PARITY_ENTRY_BYTES: usize = Tree::<Hash, HeldParity>::bytes_per_entry()
    + footprint::arc::<Parity>()
    + PLANNED_SENDERS_BYTES;

const _: () = assert!(grown(grown(0)) >= PLANNED_SENDERS);

/// What a group's trees of records, rebuilt records, credited records and parities cost before any
/// entry, at the most (`footprint::btree_planned` of none): what a plan takes for each group.
pub const GROUP_TREES_BYTES: usize = Tree::<Hash, Held>::bytes_planned(0)
    + Tree::<Hash, Judging>::bytes_planned(0)
    + Tree::<Hash, Credited>::bytes_planned(0)
    + Tree::<Hash, HeldParity>::bytes_planned(0);

impl Piece {
    /// The piece of a record, without copying a batch's bytes. `None` for a record that does not
    /// encode.
    pub fn of(record: &Record) -> Option<Self> {
        match record {
            Record::Batch(batch) => Some(Self::Batch(Arc::new(batch.clone()))),
            Record::RelayBatch(batch) => Some(Self::RelayBatch(Arc::new(batch.clone()))),
            other => {
                let mut bytes = Vec::new();
                other.encode(&mut bytes).ok()?;
                Some(Self::Encoded(Bytes::from(footprint::exact(bytes))))
            }
        }
    }

    /// The piece of one encoded record (what parity rebuilds), a batch's body kept in place: a
    /// slice of the record's allocation, which the batch is charged for whole (its header too,
    /// `Batch::from_shared`). `None` for bytes that are not one record.
    pub fn from_encoded(bytes: Vec<u8>) -> Option<Self> {
        let (_, used) = Record::decode(&bytes).ok()?;
        if used != bytes.len() || bytes.len() < HEADER_LEN {
            return None;
        }
        let kind = bytes[0];
        let bytes = Bytes::from(footprint::exact(bytes));
        let backing = bytes.len();
        match kind {
            KIND_BATCH => Batch::from_shared(bytes.slice(HEADER_LEN..), backing)
                .ok()
                .map(|batch| Self::Batch(Arc::new(batch))),
            KIND_RELAY_BATCH => Batch::from_shared(bytes.slice(HEADER_LEN..), backing)
                .ok()
                .map(|batch| Self::RelayBatch(Arc::new(batch))),
            _ => Some(Self::Encoded(bytes)),
        }
    }

    /// The record it is.
    pub fn record(&self) -> Option<Record> {
        match self {
            Self::Batch(batch) => Some(Record::Batch(Batch::clone(batch))),
            Self::RelayBatch(batch) => Some(Record::RelayBatch(Batch::clone(batch))),
            Self::Encoded(bytes) => Record::decode(bytes).ok()?.0,
        }
    }

    /// What a manifest lists it by.
    pub fn hash(&self) -> Option<Hash> {
        match self {
            Self::Batch(batch) | Self::RelayBatch(batch) => Some(batch.hash()),
            Self::Encoded(bytes) => piece_hash(bytes),
        }
    }

    /// What holding it allocates, beside its entry in its group's tree, as the groups are charged
    /// for it (`budget::Store::Batches`, `footprint`): a batch kept at ingest, whose signed bytes
    /// carry their own charge for their life (`Batch::owned_by`, `budget::Store::Decoded`), only
    /// its shared batch; any other batch that, its bytes and its kept key (`Batch::allocated`);
    /// any other piece its encoded bytes,
    /// which are its own (made exact, [`Piece::of`]). Before, every batch was charged its bytes
    /// here and again in its decode, in the epochs and in each subscriber's queue.
    pub fn held_len(&self) -> usize {
        match self {
            Self::Batch(batch) | Self::RelayBatch(batch) => {
                footprint::arc::<Batch>() + batch.allocated()
            }
            Self::Encoded(bytes) => footprint::shared_bytes(bytes.len()),
        }
    }

    /// Its encoded length: header and body.
    pub fn len(&self) -> usize {
        match self {
            Self::Batch(batch) | Self::RelayBatch(batch) => HEADER_LEN + batch.as_bytes().len(),
            Self::Encoded(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Appends its encoding to `out`: what a parity slice is made of.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Batch(batch) | Self::RelayBatch(batch) => {
                let kind = if matches!(self, Self::Batch(_)) {
                    KIND_BATCH
                } else {
                    KIND_RELAY_BATCH
                };
                let body = batch.as_bytes();
                out.push(kind);
                // A batch fits a record's body: it was read from or signed as one.
                out.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
                out.extend_from_slice(body);
            }
            Self::Encoded(bytes) => out.extend_from_slice(bytes),
        }
    }
}

/// What members send each other.
#[derive(Clone, Debug)]
pub enum Message {
    /// A record of a group's product, by its hash: held, pushed on, receipted and credited by
    /// every member whatever its signed time, since possession never reads a clock; whether a
    /// member's relay uses it is that relay's own judgment (`strikes`).
    Piece {
        group: GroupKey,
        hash: Hash,
        piece: Piece,
    },
    Manifest(PieceManifest),
    Parity(Arc<Parity>),
    Receipt(StripeReceipt),
    Have(HaveSummary),
    Assign(StripeAssignment),
}

impl Message {
    /// Bytes on the wire, near enough, for accounting.
    pub fn len(&self) -> usize {
        match self {
            Self::Piece { piece, .. } => piece.len(),
            Self::Manifest(manifest) => manifest.as_bytes().len(),
            Self::Parity(parity) => parity.len(),
            Self::Receipt(receipt) => receipt.as_bytes().len(),
            Self::Have(have) => 17 + have.seconds.len(),
            Self::Assign(_) => 14,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The group it is about, when it names one.
    pub fn group(&self) -> Option<GroupKey> {
        match self {
            Self::Piece { group, .. } => Some(*group),
            Self::Manifest(manifest) => manifest
                .content()
                .ok()
                .map(|content| GroupKey::new(content.cell, content.product)),
            Self::Parity(parity) => Some(GroupKey::new(parity.cell, parity.product)),
            Self::Receipt(receipt) => receipt
                .content()
                .ok()
                .map(|content| GroupKey::new(content.cell, content.product)),
            Self::Have(have) => Some(GroupKey::new(have.cell, have.product)),
            Self::Assign(_) => None,
        }
    }
}

/// The identity of a record a group carries: what its manifests list. `None` for a kind no group
/// carries or bytes that are not one record.
pub fn piece_hash(bytes: &[u8]) -> Option<Hash> {
    let (record, used) = Record::decode(bytes).ok()?;
    if used != bytes.len() {
        return None;
    }
    record_hash(&record?)
}

/// The hash a manifest lists a record by.
pub fn record_hash(record: &Record) -> Option<Hash> {
    match record {
        Record::Batch(batch) | Record::RelayBatch(batch) => Some(batch.hash()),
        Record::Positions(positions) | Record::Provisional(positions) => Some(positions.hash()),
        Record::ClockModel(model) => Some(model.id()),
        Record::ClockModelPart(part) => Some(part.hash()),
        Record::RegionalBatch(regional) => Some(regional.hash()),
        Record::ClientRegionalBatch(regional) => Some(regional.hash()),
        Record::ClientClockModel(model) => Some(model.hash()),
        Record::WorldPositions(world) => Some(world.hash()),
        _ => None,
    }
}

/// How a record came to be held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// This relay originated it.
    Originated,
    /// A member sent it.
    Received(PublicKey),
    /// Rebuilt from parity: new to the relay, and to its fan-out.
    Rebuilt,
}

/// A record newly held.
#[derive(Clone, Debug)]
pub struct Delivered {
    pub group: GroupKey,
    pub hash: Hash,
    pub piece: Piece,
    pub arrival: Arrival,
}

/// What a member has done, for tests and the relay's report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Rebuilds from parity: each record rebuilt and handed to its relay for judgment. A record
    /// its relay let go for want of room (`Member::let_go`) and rebuilt again is counted again, so
    /// this counts rebuilds, not distinct records.
    pub rebuilt: u64,
    /// Asks for repair sent.
    pub repairs_asked: u64,
    /// Records that arrived from a member other than the stripe's parent (repair).
    pub repaired: u64,
    /// Copies of a record already held.
    pub duplicates: u64,
    /// Records and parities refused whole because holding them would pass the store's share of
    /// the budget (its gauge, `budget::Store::Batches`).
    pub refused: u64,
    /// Receipts signed, and those that reported a shortfall.
    pub receipts: u64,
    pub shortfalls: u64,
    /// Receipt windows the judge weighed (`judge`): those steady enough to be judged (no seed
    /// rotation or change of the members about them), the only windows whose shortfalls can
    /// demote. What says "no member was demoted" is a verdict and not a judge that never sat.
    pub judged: u64,
    /// Refusals of a relay as full not noted for want of the store's room
    /// (`Member::turned_away`): a shortfall of it is judged as any other's.
    pub turned_away_unheld: u64,
}

/// The relay's two clocks at one moment (`clock::RelayClock::read`, an `ingest::Stamp`):
/// `judged` (`J`) for every signed second and everything compared with one (windows, epochs,
/// receipts, when a sender delivered), `mono` (`M`) for how long anything is kept and when the
/// tick next visits a group, and whether `J` judged as they were read. A step of `J` moves no
/// retention: what a group holds is let go on `M`, so a relay whose clock stepped back holds no
/// more than its plan (RFC-0171 §3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    judged: Judged,
    mono: Mono,
    judging: bool,
}

/// A moment on the relay's monotonic clock (`M`) by which something the relay keeps lapses: an
/// ask's membership, a demotion, a full member's route-around, an idle link. Made only from a
/// [`Now`]'s monotonic side ([`Now::after`]), so no deadline can be put on the judging clock and
/// a step of `J` either way moves none of them (RFC-0171 §3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoDeadline(u64);

impl MonoDeadline {
    /// A deadline that never passes.
    pub const NEVER: Self = Self(u64::MAX);

    /// Whether it has passed at `now`.
    pub const fn passed(self, now: Now) -> bool {
        now.mono.ms() >= self.0
    }

    /// How long from `now` until it passes (none, once it has).
    pub const fn left_ms(self, now: Now) -> u64 {
        self.0.saturating_sub(now.mono.ms())
    }

    /// The deadline as a reading of `M`, for a wake computed on `M`.
    pub const fn mono_ms(self) -> u64 {
        self.0
    }
}

impl Now {
    /// `ms` from now by `M`: the one way a [`MonoDeadline`] is made.
    pub const fn after(self, ms: u64) -> MonoDeadline {
        MonoDeadline(self.mono.ms().saturating_add(ms))
    }

    /// The judging reading.
    pub const fn judged(self) -> Judged {
        self.judged
    }

    /// The monotonic reading.
    pub const fn mono(self) -> Mono {
        self.mono
    }

    /// The monotonic reading's milliseconds.
    pub const fn mono_ms(self) -> u64 {
        self.mono.ms()
    }

    /// Whether `J` judged as the two were read: nothing is judged or signed by a moment that did
    /// not (RFC-0171 §3.6).
    pub const fn judging(self) -> bool {
        self.judging
    }

    /// When `M` reaches the moment `J` reads `judge_ms`, as the two read now: a deadline in
    /// signed time put on the clock the tick runs on (now, for one already past).
    const fn mono_at(self, judge_ms: u64) -> u64 {
        self.mono
            .ms()
            .saturating_add(judge_ms.saturating_sub(self.judged.ms()))
    }
}

impl From<crate::ingest::Stamp> for Now {
    fn from(stamp: crate::ingest::Stamp) -> Self {
        Self {
            judged: stamp.judged(),
            mono: stamp.mono(),
            judging: stamp.judging(),
        }
    }
}

/// A test's moment, its two clocks alike and judging. Only a test may name one clock for both:
/// the relay's own code hands its stamp (`ingest::Stamp`) or both clocks read together.
#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
impl From<u64> for Now {
    fn from(ms: u64) -> Self {
        crate::ingest::Stamp::at(ms, 0).into()
    }
}

struct Held {
    piece: Piece,
    /// When it was taken in, by `M` (`Now::mono_ms`): what it is let go by.
    at_ms: u64,
    /// Who sent it, and when, in order; empty for one this relay originated or rebuilt.
    from: Vec<Sender>,
}

/// A relay that delivered a record or a parity, and when.
type Sender = (PublicKey, u64);

/// What a list of senders allocates.
fn senders_bytes(from: &[Sender], capacity: usize) -> usize {
    debug_assert!(capacity >= from.len());
    footprint::vec::<Sender>(capacity)
}

/// What noting `who` among `from` allocates more: nothing if it is there or there is room, else
/// the list doubled (from one).
fn note_growth(from: &Vec<Sender>, who: &PublicKey) -> usize {
    if from.len() < from.capacity() || from.iter().any(|(sender, _)| sender == who) {
        return 0;
    }
    footprint::vec::<Sender>(grown(from.capacity())) - footprint::vec::<Sender>(from.capacity())
}

/// The capacity a full list of senders of `capacity` grows to: doubled, from one.
const fn grown(capacity: usize) -> usize {
    if capacity == 0 { 1 } else { capacity * 2 }
}

/// Notes `sender` among `from` once, grown as [`note_growth`] reckons.
fn note(from: &mut Vec<Sender>, sender: Sender) {
    if from.iter().any(|(who, _)| *who == sender.0) {
        return;
    }
    if from.len() == from.capacity() {
        from.reserve_exact(grown(from.capacity()) - from.len());
    }
    from.push(sender);
}

impl Held {
    /// What it allocates beside its entry in its tree.
    fn bytes(&self) -> usize {
        self.piece.held_len() + senders_bytes(&self.from, self.from.capacity())
    }
}

/// A record rebuilt from parity awaiting its relay's judgment (`Group::judging`): whichever
/// verdict lets it go releases what it allocated, and what it is held as once passed
/// (`Member::pass_on`, the record as its relay took it in) is charged afresh.
struct Judging {
    held: Held,
}

struct Listed {
    manifest: PieceManifest,
    origin: PublicKey,
    hashes: Vec<Hash>,
    whole: bool,
}

/// One thing a window's tree owes its members (a record, or a manifest's parity): who originated
/// it, and the second it is listed in.
struct Owed {
    origins: BTreeSet<PublicKey>,
    second: u64,
}

/// A relay this one turned away as full (`Reason::Full`, `link`): the wait the refusals gave it,
/// by the rule the relay refused applies to them (`full::Wait`), and the spans it routed around
/// this one, (start, end): in order and apart (each starts past the last's end and its slack), a
/// refusal within one merged into it, so a relay turned away again and again while it waits holds
/// one span, and a receipt check finds the span it asks about by search.
#[derive(Clone, Debug, Default)]
struct TurnedAway {
    last: Option<Wait>,
    spans: Vec<(u64, u64)>,
}

impl TurnedAway {
    /// It routed around this relay from `start_ms` to `end_ms`: put in its place by start, and
    /// merged with every span it touches, counting the slack (`Deadlines::route_slack`), which
    /// covers the same moments. A refusal comes after the last as a rule, so this is a merge into
    /// the last span or a push.
    fn add(&mut self, start_ms: u64, end_ms: u64, slack_ms: u64) {
        let at = self.spans.partition_point(|(start, _)| *start <= start_ms);
        self.spans.insert(at, (start_ms, end_ms));
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.spans.len());
        for (start, end) in self.spans.drain(..) {
            match merged.last_mut() {
                Some((_, last)) if start <= last.saturating_add(slack_ms) => {
                    *last = (*last).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        self.spans = merged;
    }

    /// Whether it was routing around this relay at any time from `from_ms` to `to_ms`, each span
    /// counted with its slack.
    fn during(&self, from_ms: u64, to_ms: u64, slack_ms: u64) -> bool {
        // The spans are apart and in order, so their ends are too: the first that reaches
        // `from_ms` is the only one that may.
        let first = self
            .spans
            .partition_point(|(_, end)| end.saturating_add(slack_ms) < from_ms);
        self.spans
            .get(first)
            .is_some_and(|(start, _)| *start <= to_ms)
    }
}

/// The relays a member holds as turned away at most (`Member::turned_away`): as many as the
/// directory holds offers (`directory::OFFERS_HELD`), every relay that can share a group with this
/// one and so be owed a window by it.
pub const TURNED_AWAY_HELD: usize = crate::directory::OFFERS_HELD;

/// The longest record a group carries, encoded: what one record adds to a parity slice at most.
const MAX_PIECE_LEN: usize = HEADER_LEN + tally_wire::record::MAX_BODY;

/// A record its deliverers sent that this relay had no room to take in (`Member::credit`): its
/// senders, for the receipts (`Group::senders`), and when it was first credited. Not held, not
/// counted as had and never pushed on: the group still lacks it and repair asks for it.
struct Credited {
    /// When it was first credited, by `M`.
    at_ms: u64,
    from: Vec<Sender>,
}

struct HeldParity {
    parity: Arc<Parity>,
    /// When it was taken in, by `M`.
    at_ms: u64,
    from: Vec<Sender>,
}

impl HeldParity {
    /// What it allocates beside its entry in its tree: the parity and its XOR, and its senders.
    fn bytes(&self) -> usize {
        footprint::arc::<Parity>()
            + footprint::vec::<u8>(self.parity.xor.capacity())
            + senders_bytes(&self.from, self.from.capacity())
    }
}

struct Group {
    key: GroupKey,
    /// The member's deadlines (`Member::new`): every timed verdict of the group reads them.
    deadlines: Deadlines,
    /// When the tick next visits it (`Member::settle`), by `M`, if ever.
    due_ms: Option<u64>,
    members: Vec<PublicKey>,
    leaves_only: Vec<PublicKey>,
    demoted: BTreeMap<PublicKey, MonoDeadline>,
    layout: Layout,
    /// When the trees last changed, newest last.
    changed_ms: Vec<u64>,
    pieces: Tree<Hash, Held>,
    /// Records rebuilt from parity that this relay has not yet judged (`rebuild`): held apart
    /// from `pieces`, charged and counted in `bytes`, so none is answered to a repair, used to
    /// rebuild another, or pushed on before its relay takes it in (`Member::pass_on`), refuses it
    /// (`Member::refuse`) or lets it go (`Member::let_go`). Counted as had, so no repair asks for
    /// one while it waits.
    judging: Tree<Hash, Judging>,
    /// Records this relay refused (`Member::refuse`), with when by `M`: never held or pushed on, and
    /// counted as had, so a manifest that lists one is whole and no repair asks for it.
    refused: BTreeMap<Hash, u64>,
    /// Records its members sent that this relay had no room to take in (`Member::credit`): their
    /// senders credited for the receipts, nothing held, nothing counted as had.
    credited: Tree<Hash, Credited>,
    /// What the entries of `pieces`, `judging`, `credited` and `parity` allocate beside their
    /// places in the trees (`Held::bytes`, `HeldParity::bytes`, their senders), kept as they
    /// change. With the trees' own ([`Group::bytes`]), what the member's gauge is charged for the
    /// group, each change charged before it is made.
    entries_bytes: usize,
    /// By second, then by the manifest's hash.
    manifests: BTreeMap<u64, BTreeMap<Hash, Listed>>,
    parity: Tree<Hash, HeldParity>,
    /// What this relay originated, by second, not yet in a manifest.
    own: BTreeMap<u64, BTreeSet<Hash>>,
    /// Manifests and receipts already taken in, by hash, with when by `M`.
    seen: BTreeMap<Hash, u64>,
    receipted: BTreeSet<u64>,
    judged: BTreeSet<u64>,
    /// (window, stripe, deliverer): the members that reported it short.
    shortfalls: BTreeMap<(u64, u8, PublicKey), BTreeSet<PublicKey>>,
    /// (window, stripe, member): the member reported its own deliverer short.
    starved: BTreeSet<(u64, u8, PublicKey)>,
    repair_at_ms: u64,
    repair_attempt: u64,
    anti_entropy_at_ms: u64,
    /// When each member's `HaveSummary` was last answered, by `M`.
    answered: BTreeMap<PublicKey, u64>,
    /// The stripes asked of each parent, as last sent.
    assigned: BTreeMap<PublicKey, u32>,
    assigned_epoch: Option<u64>,
}

impl Group {
    fn new(key: GroupKey, me: PublicKey, deadlines: Deadlines) -> Self {
        Self {
            key,
            deadlines,
            due_ms: None,
            members: vec![me],
            leaves_only: Vec::new(),
            demoted: BTreeMap::new(),
            layout: Layout::new(key.cell, key.product, &[me], &[]),
            changed_ms: Vec::new(),
            pieces: Tree::new(),
            judging: Tree::new(),
            refused: BTreeMap::new(),
            credited: Tree::new(),
            entries_bytes: 0,
            manifests: BTreeMap::new(),
            parity: Tree::new(),
            own: BTreeMap::new(),
            seen: BTreeMap::new(),
            receipted: BTreeSet::new(),
            judged: BTreeSet::new(),
            shortfalls: BTreeMap::new(),
            starved: BTreeSet::new(),
            repair_at_ms: 0,
            repair_attempt: 0,
            anti_entropy_at_ms: 0,
            answered: BTreeMap::new(),
            assigned: BTreeMap::new(),
            assigned_epoch: None,
        }
    }

    fn relayout(&mut self, now_ms: u64) {
        let members: Vec<PublicKey> = self
            .members
            .iter()
            .filter(|key| !self.demoted.contains_key(key))
            .copied()
            .collect();
        let layout = Layout::new(self.key.cell, self.key.product, &members, &self.leaves_only);
        if layout != self.layout {
            self.layout = layout;
            self.changed_ms.push(now_ms);
        }
    }

    fn children(&self, stripe: u8, now_ms: u64, me: &PublicKey) -> Vec<PublicKey> {
        self.layout
            .place(stripe, epoch_of(now_ms / 1000), me)
            .map(|place| place.children)
            .unwrap_or_default()
    }

    /// The members beneath `key` in `stripe`'s tree that take its place for what this relay sends
    /// while it is full: its children, and in place of each that is full too, that one's, never
    /// this relay itself.
    fn beneath(
        &self,
        stripe: u8,
        key: &PublicKey,
        (full, me): (&BTreeSet<PublicKey>, &PublicKey),
        now_ms: u64,
        out: &mut BTreeSet<PublicKey>,
    ) {
        let epoch = epoch_of(now_ms / 1000);
        let mut next = vec![*key];
        while let Some(at) = next.pop() {
            let Some(place) = self.layout.place(stripe, epoch, &at) else {
                continue;
            };
            for child in place.children {
                if child == *me || out.contains(&child) {
                    continue;
                }
                if full.contains(&child) {
                    next.push(child);
                } else {
                    out.insert(child);
                }
            }
        }
    }

    /// Every member this one shares a tree edge with, in any stripe.
    fn neighbours(&self, now_ms: u64, me: &PublicKey) -> Vec<PublicKey> {
        let epoch = epoch_of(now_ms / 1000);
        let mut out = BTreeSet::new();
        for stripe in 0..STRIPES {
            if let Some(place) = self.layout.place(stripe, epoch, me) {
                out.extend(place.parent);
                out.extend(place.children);
            }
        }
        out.remove(me);
        out.into_iter().collect()
    }

    /// Whether the trees stood still over a window and its grace, so its receipts can be judged.
    fn steady(&self, window: u64) -> bool {
        let first = window * RECEIPT_WINDOW_SECONDS;
        let end = first + RECEIPT_WINDOW_SECONDS;
        if end.is_multiple_of(SEED_ROTATION_SECONDS) {
            return false;
        }
        let from = (first * 1000).saturating_sub(1000);
        let to = end * 1000 + self.deadlines.receipt_grace.ms();
        !self
            .changed_ms
            .iter()
            .any(|changed| (from..=to).contains(changed))
    }

    /// What every member of the window's tree in `stripe` is owed: every listed record of the
    /// stripe (or, for the parity stripe, every listed manifest's parity), with its origins and the
    /// second it is listed in.
    fn owed(&self, window: u64, stripe: u8) -> BTreeMap<Hash, Owed> {
        let first = window * RECEIPT_WINDOW_SECONDS;
        let mut owed: BTreeMap<Hash, Owed> = BTreeMap::new();
        for (second, listed) in self
            .manifests
            .range(first..first + RECEIPT_WINDOW_SECONDS)
            .flat_map(|(second, by_hash)| by_hash.values().map(move |listed| (*second, listed)))
        {
            let mut owe = |hash: Hash| {
                let entry = owed.entry(hash).or_insert_with(|| Owed {
                    origins: BTreeSet::new(),
                    second,
                });
                entry.origins.insert(listed.origin);
                entry.second = entry.second.min(second);
            };
            if stripe == PARITY_STRIPE {
                if !listed.hashes.is_empty() {
                    owe(id_of(&listed.manifest.hash()));
                }
                continue;
            }
            for hash in listed
                .hashes
                .iter()
                .filter(|hash| data_stripe(hash) == stripe)
            {
                owe(*hash);
            }
        }
        owed
    }

    /// The members above `member` in `stripe`'s tree at `epoch`: its parent, the parent's, and so
    /// on to the stripe's seed. Those are who send it a record past a full parent (`beneath`).
    fn above(&self, stripe: u8, epoch: u64, member: &PublicKey) -> BTreeSet<PublicKey> {
        let mut above = BTreeSet::new();
        let mut at = *member;
        while let Some(parent) = self
            .layout
            .place(stripe, epoch, &at)
            .and_then(|place| place.parent)
        {
            if !above.insert(parent) {
                break;
            }
            at = parent;
        }
        above
    }

    /// Who delivered `hash` (a record or a parity id), in order: whether this relay holds it or
    /// only credited its senders for want of room (`credited`).
    fn senders(&self, hash: &Hash) -> &[Sender] {
        self.pieces
            .get(hash)
            .map(|held| held.from.as_slice())
            .or_else(|| self.parity.get(hash).map(|held| held.from.as_slice()))
            .or_else(|| {
                self.credited
                    .get(hash)
                    .map(|credited| credited.from.as_slice())
            })
            .unwrap_or(&[])
    }

    fn bytes_of(&self, hash: &Hash) -> u64 {
        self.pieces
            .get(hash)
            .map(|held| held.piece.len())
            .or_else(|| self.parity.get(hash).map(|held| held.parity.len()))
            .map_or(0, |len| u64::try_from(len).unwrap_or(u64::MAX))
    }

    fn whole(&self, second: u64) -> bool {
        self.manifests.get(&second).is_some_and(|by_hash| {
            by_hash
                .values()
                .all(|listed| listed.whole || listed.hashes.iter().all(|h| self.has(h)))
        })
    }

    /// Whether it holds `hash`, has it rebuilt and awaiting judgment, or refused it: either way,
    /// nothing to ask for.
    fn has(&self, hash: &Hash) -> bool {
        self.pieces.contains_key(hash)
            || self.judging.contains_key(hash)
            || self.refused.contains_key(hash)
    }

    /// What it allocates for what it holds, as its member's gauge is charged for it: its trees of
    /// records, rebuilt records, credited records and parities (`footprint::Tree`, at most) and
    /// their entries' own.
    fn bytes(&self) -> usize {
        self.pieces.bytes()
            + self.judging.bytes()
            + self.credited.bytes()
            + self.parity.bytes()
            + self.entries_bytes
    }

    /// Lets go of a rebuilt record awaiting judgment, if it is one. The bytes it let go.
    fn drop_judging(&mut self, hash: &Hash) -> usize {
        let before = self.bytes();
        if let Some(judging) = self.judging.remove(hash) {
            self.entries_bytes -= judging.held.bytes();
        }
        before - self.bytes()
    }

    /// What holding a record with `piece` and senders of `capacity` allocates more.
    fn hold_growth(&self, piece: &Piece, capacity: usize) -> usize {
        self.pieces.growth() + piece.held_len() + footprint::vec::<Sender>(capacity)
    }

    /// Holds a piece, counting what it allocates, which its caller has charged
    /// ([`Group::hold_growth`]).
    fn hold(&mut self, hash: Hash, piece: Piece, at_ms: u64, from: Vec<Sender>) {
        let held = Held { piece, at_ms, from };
        self.entries_bytes += held.bytes();
        self.pieces.insert(hash, held);
    }

    /// What holding `held` allocates more.
    fn parity_growth(&self, held: &HeldParity) -> usize {
        self.parity.growth() + held.bytes()
    }

    /// Holds a parity, counting what it allocates, which its caller has charged
    /// ([`Group::parity_growth`]).
    fn hold_parity(&mut self, held: HeldParity) {
        self.entries_bytes += held.bytes();
        self.parity.insert(held.parity.id(), held);
    }

    /// Lets a parity go. The bytes it let go.
    fn drop_parity(&mut self, id: &Hash) -> usize {
        let before = self.bytes();
        if let Some(held) = self.parity.remove(id) {
            self.entries_bytes -= held.bytes();
        }
        before - self.bytes()
    }

    /// What noting `from` as a sender of the record or parity `hash` it holds or credits
    /// allocates more, and then notes it.
    fn note_growth(&self, hash: &Hash, from: &PublicKey) -> usize {
        if let Some(held) = self.pieces.get(hash) {
            note_growth(&held.from, from)
        } else if let Some(held) = self.parity.get(hash) {
            note_growth(&held.from, from)
        } else if let Some(credited) = self.credited.get(hash) {
            note_growth(&credited.from, from)
        } else {
            self.credited.growth() + footprint::vec::<Sender>(1)
        }
    }

    /// Notes `sender` as a sender of the record or parity `hash`, crediting it if it holds
    /// neither, at `kept_ms` by `M`; charged first by [`Group::note_growth`].
    fn note(&mut self, hash: Hash, sender: Sender, kept_ms: u64) {
        let from = if let Some(held) = self.pieces.get_mut(&hash) {
            &mut held.from
        } else if let Some(held) = self.parity.get_mut(&hash) {
            &mut held.from
        } else {
            &mut self
                .credited
                .entry(hash)
                .or_insert(Credited {
                    at_ms: kept_ms,
                    from: Vec::new(),
                })
                .from
        };
        let before = from.capacity();
        note(from, sender);
        self.entries_bytes +=
            footprint::vec::<Sender>(from.capacity()) - footprint::vec::<Sender>(before);
    }

    /// Whether it holds anything within the horizon: then every tick has duties for it
    /// (manifests, rebuilds, receipts, judgment, repair, forgetting).
    fn busy(&self) -> bool {
        !(self.pieces.is_empty()
            && self.judging.is_empty()
            && self.manifests.is_empty()
            && self.parity.is_empty()
            && self.own.is_empty()
            && self.seen.is_empty()
            && self.receipted.is_empty()
            && self.judged.is_empty()
            && self.shortfalls.is_empty()
            && self.starved.is_empty())
    }

    /// Whether this relay is alone in it with nothing: what it would be if it were not held at
    /// all, so it is let go.
    fn idle(&self, me: &PublicKey) -> bool {
        self.members.iter().all(|member| member == me)
            && self.leaves_only.iter().all(|member| member == me)
            && !self.busy()
            && self.demoted.is_empty()
            && self.assigned.is_empty()
            && self.changed_ms.is_empty()
            && self.answered.is_empty()
    }

    /// When the tick must next visit it: at once while it holds anything; else at the soonest of
    /// its timed duties (the next seed rotation and anti-entropy ask while it has another member,
    /// a demotion's end, forgetting what it remembers of the trees); never when it has none. By
    /// `M`, the clock the tick runs on: a duty set by a signed second (a seed rotation, a
    /// demotion's end, a change of the trees) is put on it as the two clocks read now
    /// (`Now::mono_at`), so a step of `J` never stalls a group's tick, and with it the forgetting.
    fn wake_ms(&self, me: &PublicKey, now: Now) -> Option<u64> {
        if self.busy() {
            return Some(now.mono_ms());
        }
        let mut wake = u64::MAX;
        let others = self.layout.members().iter().any(|member| member != me);
        if others || !self.assigned.is_empty() {
            let epoch = epoch_of(now.judged().ms() / 1000);
            wake = wake.min(now.mono_at((epoch + 1) * SEED_ROTATION_SECONDS * 1000));
        }
        if others {
            wake = wake.min(self.repair_at_ms.max(self.anti_entropy_at_ms));
        }
        if let Some(until) = self.demoted.values().min() {
            wake = wake.min(until.mono_ms());
        }
        if let Some(changed) = self.changed_ms.iter().min() {
            wake = wake.min(now.mono_at(changed + 2 * self.deadlines.horizon_seconds() * 1000 + 1));
        }
        if let Some(at) = self.answered.values().min() {
            wake = wake.min(at + ANSWER_INTERVAL_MS);
        }
        (wake != u64::MAX).then_some(wake.max(now.mono_ms()))
    }
}

/// This relay's part in all of its groups.
pub struct Member {
    /// Its key, signing only while the relay's clock is synced (`signer::Signer`).
    signer: crate::signer::Signer,
    me: PublicKey,
    /// What it judges its deliverers by (`Deadlines`), as it was built: each group it holds keeps
    /// a copy.
    deadlines: Deadlines,
    groups: BTreeMap<GroupKey, Group>,
    /// The held groups by when the tick next visits them.
    due: BTreeSet<(u64, GroupKey)>,
    /// What the groups hold together (their records and parities), charged to the one batch byte
    /// store's gauge (`budget::Store::Batches`) before it is held and released as it is let go: the
    /// store's only bound. A record or parity the gauge cannot take is refused whole, counted
    /// (`Stats::refused`).
    held: Charge,
    gauge: Arc<Gauge>,
    /// The members that turned this relay's link away as full, while they are (`set_full`): what
    /// it sends is routed around them (`route`).
    full: BTreeSet<PublicKey>,
    /// The relays this one turned away as full, and when each was routing around it
    /// (`turned_away`): no shortfall is filed against one for those windows. At most
    /// [`TURNED_AWAY_HELD`], charged what they allocate (`turned_away_charge`).
    turned_away: Tree<PublicKey, TurnedAway>,
    /// What `turned_away` allocates, charged to the same store as the groups (`gauge`) before it
    /// grows.
    turned_away_charge: Charge,
    /// Groups the tick has visited since start: the work it did, which follows what the groups
    /// hold and never how many areas the relay takes.
    visits: u64,
    delivered: Vec<Delivered>,
    demotions: Vec<(GroupKey, PublicKey, MonoDeadline)>,
    stats: Stats,
}

impl Member {
    /// A member whose groups hold what `gauge` (the budget's `Store::Batches`) takes, judging its
    /// deliverers by `deadlines` (a relay's `Deadlines::RELAY`).
    pub fn new(signer: crate::signer::Signer, gauge: Arc<Gauge>, deadlines: Deadlines) -> Self {
        let me = signer.public();
        Self {
            signer,
            me,
            deadlines,
            groups: BTreeMap::new(),
            due: BTreeSet::new(),
            held: gauge.empty(),
            turned_away_charge: gauge.empty(),
            gauge,
            full: BTreeSet::new(),
            turned_away: Tree::new(),
            visits: 0,
            delivered: Vec::new(),
            demotions: Vec::new(),
            stats: Stats::default(),
        }
    }

    /// What it holds is charged to `gauge` from now on: what it holds now moved there, or let go
    /// whole if that gauge cannot take it.
    pub fn charge_to(&mut self, gauge: Arc<Gauge>) {
        if Arc::ptr_eq(&self.gauge, &gauge) {
            return;
        }
        let mut moved = gauge.empty();
        if !moved.try_grow(self.held.bytes()) {
            self.groups.clear();
            self.due.clear();
        }
        let mut turned_away = gauge.empty();
        if !turned_away.try_grow(self.turned_away_charge.bytes()) {
            self.turned_away.clear();
        }
        self.held = moved;
        self.turned_away_charge = turned_away;
        self.gauge = gauge;
    }

    /// The members full now (`peers::Peers::full`): routed around from now on, until the next
    /// call says otherwise.
    pub fn set_full(&mut self, full: BTreeSet<PublicKey>) {
        self.full = full;
    }

    /// This relay turned `key`'s member link away as full at `now_ms`, asking it to stay away
    /// `asked` (`link`, `Reason::Full`). It takes that as "this provider is full" and routes its
    /// slice past this relay for the wait the one rule gives (`full::Wait`, which `peers` applies
    /// to the same refusal), so for every window that wait covers it owes this relay nothing.
    ///
    /// At most [`TURNED_AWAY_HELD`] relays are held: one more lets go the one whose last span
    /// ended first. What they allocate is charged before it is held; past the store's room the
    /// refusal is not noted, counted (`Stats::turned_away_unheld`), and a shortfall of that relay
    /// is judged as any other's.
    pub fn turned_away(&mut self, key: PublicKey, asked: std::time::Duration, now_ms: u64) {
        if self.turned_away.get(&key).is_none() && self.turned_away.len() >= TURNED_AWAY_HELD {
            let oldest = self
                .turned_away
                .iter()
                .min_by_key(|(_, held)| held.spans.last().map_or(0, |(_, end)| *end))
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.turned_away.remove(&oldest);
            }
        }
        let before = self.turned_away.get(&key).cloned();
        let held = self.turned_away.entry(key).or_default();
        let wait = Wait::after(held.last, asked, now_ms);
        held.last = Some(wait);
        held.add(now_ms, wait.until_ms, self.deadlines.route_slack.ms());
        if !self.settle_turned_away() {
            match before {
                Some(before) => {
                    self.turned_away.insert(key, before);
                }
                None => {
                    self.turned_away.remove(&key);
                }
            }
            self.settle_turned_away();
            self.stats.turned_away_unheld += 1;
        }
    }

    /// What the relays turned away allocate: their tree and each one's spans.
    fn turned_away_bytes(&self) -> usize {
        self.turned_away.bytes()
            + self
                .turned_away
                .values()
                .map(|held| footprint::vec::<(u64, u64)>(held.spans.capacity()))
                .sum::<usize>()
    }

    /// Brings their charge to what they allocate: false when it would grow past the store's room.
    fn settle_turned_away(&mut self) -> bool {
        let bytes = self.turned_away_bytes();
        let charged = self.turned_away_charge.bytes();
        if bytes > charged {
            self.turned_away_charge.try_grow(bytes - charged)
        } else {
            self.turned_away_charge.shrink_to(bytes);
            true
        }
    }

    /// The relays it holds as turned away, and what they are charged.
    #[cfg(test)]
    pub fn turned_away_held(&self) -> (usize, usize) {
        (self.turned_away.len(), self.turned_away_charge.bytes())
    }

    /// The spans this relay holds of `key` routing around it (`turned_away`).
    #[cfg(test)]
    pub fn turned_away_spans(&self, key: &PublicKey) -> usize {
        self.turned_away.get(key).map_or(0, |held| held.spans.len())
    }

    /// Whether this relay turned `key` away and it was routing around this relay at any time from
    /// `from_ms` to `to_ms`.
    pub fn routed_around_by(&self, key: &PublicKey, from_ms: u64, to_ms: u64) -> bool {
        let slack_ms = self.deadlines.route_slack.ms();
        self.turned_away
            .get(key)
            .is_some_and(|held| held.during(from_ms, to_ms, slack_ms))
    }

    /// Forgets the refusals no window still to be receipted can overlap, and the waits that no
    /// longer double the next.
    fn forget_turned_away(&mut self, now_ms: u64) {
        let horizon_ms = now_ms.saturating_sub(2 * self.deadlines.horizon_ms());
        let slack_ms = self.deadlines.route_slack.ms();
        self.turned_away.retain(|_, held| {
            held.spans
                .retain(|(_, end)| end.saturating_add(slack_ms) >= horizon_ms);
            held.spans.shrink_to_fit();
            !held.spans.is_empty() || held.last.is_some_and(|wait| wait.remembered(now_ms))
        });
        self.settle_turned_away();
    }

    /// Whether a parity chunk `from` sent may start reassembling here, and the most bytes its
    /// whole may be: only for an origin manifest this relay holds, from a relay its group knows,
    /// whose parity it does not hold yet, and with slice lengths its records can have (a stripe
    /// with no record of the manifest has an empty slice, one with records at most their count of
    /// the longest record), the whole as long as the longest slice. `None` otherwise: nothing is
    /// held for it.
    pub fn parity_room(&self, from: &PublicKey, chunk: &ParityChunk) -> Option<usize> {
        let group = self.groups.get(&GroupKey::new(chunk.cell, chunk.product))?;
        if *from == self.me
            || !(group.members.contains(from) || group.leaves_only.contains(from))
            || group.parity.contains_key(&id_of(&chunk.manifest))
            || chunk.lens.len() != usize::from(DATA_STRIPES)
        {
            return None;
        }
        let listed = group.manifests.get(&chunk.second)?.get(&chunk.manifest)?;
        let mut longest = 0usize;
        for (stripe, len) in (0..DATA_STRIPES).zip(&chunk.lens) {
            let records = listed
                .hashes
                .iter()
                .filter(|hash| data_stripe(hash) == stripe)
                .count();
            let len = usize::try_from(*len).ok()?;
            if (records == 0) != (len == 0) || len > records.saturating_mul(MAX_PIECE_LEN) {
                return None;
            }
            longest = longest.max(len);
        }
        (usize::try_from(chunk.total).ok()? == longest).then_some(longest)
    }

    /// What this relay sends, routed around the members that are full: what one would have been
    /// sent down a stripe goes to the members beneath it there (`Group::beneath`), a manifest to
    /// those beneath it in every stripe, and anything else addressed to it alone is not sent. An
    /// answer to `asker` (a repair page) is for it alone and is never routed past it: it goes to
    /// it over this relay's member link, which sends nothing to a member full now (`peers`).
    fn route(&self, out: Vec<Outgoing>, asker: Option<&PublicKey>, now_ms: u64) -> Vec<Outgoing> {
        if self.full.is_empty() {
            return out;
        }
        let mut routed = Vec::with_capacity(out.len());
        for outgoing in out {
            if !self.full.contains(&outgoing.to) || Some(&outgoing.to) == asker {
                routed.push(outgoing);
                continue;
            }
            let stripes: Vec<u8> = match &outgoing.message {
                Message::Piece { hash, .. } => vec![data_stripe(hash)],
                Message::Parity(_) => vec![PARITY_STRIPE],
                Message::Manifest(_) => (0..STRIPES).collect(),
                Message::Receipt(_) | Message::Have(_) | Message::Assign(_) => Vec::new(),
            };
            let Some(group) = outgoing
                .message
                .group()
                .and_then(|key| self.groups.get(&key))
            else {
                continue;
            };
            let mut beneath = BTreeSet::new();
            for stripe in stripes {
                group.beneath(
                    stripe,
                    &outgoing.to,
                    (&self.full, &self.me),
                    now_ms,
                    &mut beneath,
                );
            }
            routed.extend(beneath.into_iter().map(|to| Outgoing {
                to,
                message: outgoing.message.clone(),
            }));
        }
        routed
    }

    /// Bytes held now across its groups (records and parities): what its gauge is charged.
    pub fn held_bytes(&self) -> usize {
        self.held.bytes()
    }

    /// What its groups allocate, by each group's own count (kept apart from the charge, as
    /// records and parities come and go): what its gauge reads.
    pub fn group_bytes(&self) -> usize {
        self.groups.values().map(Group::bytes).sum()
    }

    /// What its groups allocate, counted afresh from every tree and every entry in them: what its
    /// gauge must read.
    #[cfg(test)]
    pub fn counted_bytes(&self) -> usize {
        self.groups
            .values()
            .map(|group| {
                Tree::<Hash, Held>::bytes_at(group.pieces.len())
                    + Tree::<Hash, Judging>::bytes_at(group.judging.len())
                    + Tree::<Hash, Credited>::bytes_at(group.credited.len())
                    + Tree::<Hash, HeldParity>::bytes_at(group.parity.len())
                    + group.pieces.values().map(Held::bytes).sum::<usize>()
                    + group
                        .judging
                        .values()
                        .map(|judging| judging.held.bytes())
                        .sum::<usize>()
                    + group
                        .credited
                        .values()
                        .map(|credited| senders_bytes(&credited.from, credited.from.capacity()))
                        .sum::<usize>()
                    + group.parity.values().map(HeldParity::bytes).sum::<usize>()
            })
            .sum()
    }

    /// Groups the tick has visited since start.
    pub fn visits(&self) -> u64 {
        self.visits
    }

    /// `len` more bytes charged to the gauge, or false, counted as refused, when it is full.
    fn charge(&mut self, len: usize) -> bool {
        charge(&mut self.held, &mut self.stats, len)
    }

    pub fn key(&self) -> PublicKey {
        self.me
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The group's trees as this member sees them.
    pub fn layout(&self, group: GroupKey) -> Option<&Layout> {
        self.groups.get(&group).map(|group| &group.layout)
    }

    pub fn groups(&self) -> Vec<GroupKey> {
        self.groups.keys().copied().collect()
    }

    /// Whether `group` is held (it is more than this relay alone with nothing).
    pub fn holds_group(&self, group: GroupKey) -> bool {
        self.groups.contains_key(&group)
    }

    /// Holds `group` for a message about to be handed in (`receive`), which lets it go again if
    /// the message leaves it with nothing.
    pub fn join(&mut self, group: GroupKey) {
        let (me, deadlines) = (self.me, self.deadlines);
        self.groups
            .entry(group)
            .or_insert_with(|| Group::new(group, me, deadlines));
    }

    /// The origin manifests held of `second`, by group: what the bundle indexes over it digest.
    pub fn manifests_of(&self, second: u64) -> Vec<(GroupKey, Vec<PieceManifest>)> {
        self.groups
            .iter()
            .filter_map(|(key, group)| {
                let by_hash = group.manifests.get(&second)?;
                let manifests: Vec<PieceManifest> = by_hash
                    .values()
                    .map(|listed| listed.manifest.clone())
                    .collect();
                Some((*key, manifests))
            })
            .collect()
    }

    /// The origin manifests held for `group`'s `second`: what a bundle index over it digests.
    pub fn manifests(&self, group: GroupKey, second: u64) -> Vec<PieceManifest> {
        self.groups
            .get(&group)
            .and_then(|group| group.manifests.get(&second))
            .map(|by_hash| {
                by_hash
                    .values()
                    .map(|listed| listed.manifest.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A record of `group` this relay refused (a batch of a format it reads that does not decode):
    /// never held or pushed on, and counted as had until the horizon, so no repair asks for it.
    pub fn refuse(&mut self, group: GroupKey, hash: Hash, now: impl Into<Now>) {
        let now = now.into();
        if let Some(group) = self.groups.get_mut(&group) {
            group.refused.insert(hash, now.mono_ms());
            // One rebuilt from parity awaits its relay's judgment apart (`rebuild`): refused, it
            // is let go, never answered to a repair nor passed on.
            release(&mut self.held, group.drop_judging(&hash));
        }
    }

    /// A record of `group` that `from` delivered and this relay had no room to take in
    /// (`strikes::Verdict::Full`): `from` is credited as its deliverer, as any copy's is, so a
    /// receipt never reports an honest member short for this relay's want of room (RFC-0174 §2.5).
    /// Unlike a copy held it is not counted as had or pushed on: this relay never took it, so
    /// its group still lacks it and asks for it again. Each record credited is charged what its
    /// entry allocates until the horizon (its place in the tree of credits and its senders), and
    /// one there is no room to credit is not.
    pub fn credit(&mut self, from: PublicKey, group: GroupKey, hash: Hash, now: impl Into<Now>) {
        let now = now.into();
        let Some(held) = self.groups.get_mut(&group) else {
            return;
        };
        if held.refused.contains_key(&hash) {
            return;
        }
        let growth = held.note_growth(&hash, &from);
        if !charge(&mut self.held, &mut self.stats, growth) {
            return;
        }
        let before = held.bytes();
        held.note(hash, (from, now.judged().ms()), now.mono_ms());
        settle(&mut self.held, before + growth, held.bytes());
    }

    /// Whether `group` holds `hash` or counts it as had.
    #[cfg(test)]
    pub fn counts_had(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups.get(&group).is_some_and(|group| group.has(hash))
    }

    /// Whether `group` noted `from` as a deliverer of `hash`: the evidence its receipts credit
    /// `from` by (`delivered_by`).
    #[cfg(test)]
    pub fn delivered(&self, group: GroupKey, hash: &Hash, from: &PublicKey) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.senders(hash).iter().any(|(sender, _)| sender == from))
    }

    /// A record rebuilt from parity (`rebuild`) that its relay could not take in for want of room
    /// (`Hub::take_rebuilt`): let go, not refused, so the group lacks it again and repair asks a
    /// member for it, or the parity rebuilds it again.
    pub fn let_go(&mut self, group: GroupKey, hash: Hash) {
        if let Some(group) = self.groups.get_mut(&group) {
            release(&mut self.held, group.drop_judging(&hash));
        }
    }

    /// A record rebuilt from parity (`rebuild`) that its relay judged and took in, as a member's
    /// piece is judged before it is received (`Hub::take_rebuilt`): pushed on down its stripe now.
    /// A piece is pushed on only once its relay took it in, however it came: a rebuilt one is
    /// never passed on before, so a record its relay refuses (a false fault proof, positions that
    /// do not verify) travels no further than the relay that rebuilt it (`refuse`).
    /// One a member sent meanwhile was held and pushed on as it came (`piece`), so this one is let
    /// go and nothing is pushed twice.
    ///
    /// What is held is `taken`, the record as its relay took it in, as a member's piece is held
    /// (`Sharing::received`): a batch the relay admitted carries its own charge
    /// (`Batch::owned_by`, `budget::Store::Decoded`), so the group charges it only its place
    /// (`Piece::held_len`, [`PIECE_ENTRY_BYTES`]), not its bytes a second time. The rebuilt copy
    /// and its whole charge are let go. One whose hash is not the rebuilt record's is no copy of
    /// it, and the rebuilt copy is held instead.
    pub fn pass_on(
        &mut self,
        key: GroupKey,
        hash: Hash,
        taken: Piece,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        let me = self.me;
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        let before = group.bytes();
        let Some(Judging { held: rebuilt }) = group.judging.remove(&hash) else {
            return Vec::new();
        };
        group.entries_bytes -= rebuilt.bytes();
        release(&mut self.held, before - group.bytes());
        if group.pieces.contains_key(&hash) || group.refused.contains_key(&hash) {
            return Vec::new();
        }
        let piece = if taken.hash() == Some(hash) {
            taken
        } else {
            rebuilt.piece
        };
        // Its senders: those credited while there was no room to take it (`credit`), who
        // delivered it before parity rebuilt it, as a member's piece takes them (`piece`). Their
        // list moves from the credit to the record, which lets the credit's place go; the rebuilt
        // copy itself noted none (a member's copy arriving while it was judged takes its place).
        debug_assert!(rebuilt.from.is_empty(), "a rebuilt copy noted a sender");
        let senders_growth = if group.credited.contains_key(&hash) {
            0
        } else {
            footprint::vec::<Sender>(rebuilt.from.capacity())
        };
        let growth = group.pieces.growth() + piece.held_len() + senders_growth;
        if !charge(&mut self.held, &mut self.stats, growth) {
            // No room to hold it: let go, as any record refused for room; whoever delivered it
            // before stays credited.
            return Vec::new();
        }
        let before = group.bytes();
        let senders = match group.credited.remove(&hash) {
            Some(credited) => {
                group.entries_bytes -= senders_bytes(&credited.from, credited.from.capacity());
                credited.from
            }
            None => rebuilt.from,
        };
        group.hold(hash, piece.clone(), rebuilt.at_ms, senders);
        settle(&mut self.held, before + growth, group.bytes());
        let out = push(group, &me, &me, data_stripe(&hash), now_ms, || {
            Message::Piece {
                group: key,
                hash,
                piece: piece.clone(),
            }
        });
        self.route(out, None, now_ms)
    }

    /// What `group` charges for holding `hash` (`Piece::held_len`), if it holds it.
    #[cfg(test)]
    pub fn held_len_of(&self, group: GroupKey, hash: &Hash) -> Option<usize> {
        self.groups
            .get(&group)
            .and_then(|group| group.pieces.get(hash))
            .map(|held| held.piece.held_len())
    }

    /// Whether this relay originated `hash` in `group` (`Member::originate`): seeded as its own.
    #[cfg(test)]
    pub fn originated(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.own.values().any(|own| own.contains(hash)))
    }

    /// Whether `group` counts `hash` refused (`Member::refuse`).
    #[cfg(test)]
    pub fn has_refused(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.refused.contains_key(hash))
    }

    /// Whether `group` holds `hash` rebuilt from parity and awaiting its relay's judgment.
    #[cfg(test)]
    pub fn judging(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.judging.contains_key(hash))
    }

    pub fn holds(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.pieces.contains_key(hash))
    }

    /// Whether `group` holds the parity of the manifest `manifest` (its hash).
    #[cfg(test)]
    pub fn holds_parity(&self, group: GroupKey, manifest: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.parity.contains_key(&id_of(manifest)))
    }

    pub fn is_demoted(&self, group: GroupKey, member: &PublicKey) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.demoted.contains_key(member))
    }

    /// The records newly held since the last call, each once: what the relay's own fan-out
    /// takes from its groups.
    pub fn take_delivered(&mut self) -> Vec<Delivered> {
        std::mem::take(&mut self.delivered)
    }

    /// The members this one demoted since the last call: (group, member, until).
    pub fn take_demotions(&mut self) -> Vec<(GroupKey, PublicKey, MonoDeadline)> {
        std::mem::take(&mut self.demotions)
    }

    /// The group's members as `groups` holds them (this relay is always one).
    pub fn set_members(
        &mut self,
        key: GroupKey,
        members: &[PublicKey],
        leaves_only: &[PublicKey],
        now: impl Into<Now>,
    ) -> Vec<Outgoing> {
        let now = now.into();
        let now_ms = now.judged().ms();
        let (me, deadlines) = (self.me, self.deadlines);
        let group = self
            .groups
            .entry(key)
            .or_insert_with(|| Group::new(key, me, deadlines));
        let mut members = members.to_vec();
        members.push(me);
        members.sort();
        members.dedup();
        group.members = members;
        group.leaves_only = leaves_only.to_vec();
        group.relayout(now_ms);
        let out = assign(group, &me, now_ms);
        self.settle(key, now);
        self.route(out, None, now_ms)
    }

    /// Leaves a group (the relay no longer takes its cell).
    pub fn leave(&mut self, key: GroupKey) {
        if let Some(group) = self.groups.remove(&key) {
            release(&mut self.held, group.bytes());
            if let Some(at) = group.due_ms {
                self.due.remove(&(at, key));
            }
        }
    }

    /// Schedules `key` for when the tick next has something to do for it, or lets it go when it
    /// is this relay alone with nothing.
    fn settle(&mut self, key: GroupKey, now: Now) {
        let me = self.me;
        let Some(group) = self.groups.get_mut(&key) else {
            return;
        };
        if let Some(at) = group.due_ms.take() {
            self.due.remove(&(at, key));
        }
        if group.idle(&me) {
            self.leave(key);
            return;
        }
        if let Some(at) = group.wake_ms(&me, now) {
            group.due_ms = Some(at);
            self.due.insert((at, key));
        }
    }

    /// A record this relay originated for a group: held, and sent once to its stripe's seed.
    pub fn originate(
        &mut self,
        key: GroupKey,
        hash: Hash,
        piece: Piece,
        now: impl Into<Now>,
    ) -> Vec<Outgoing> {
        self.seed(key, hash, piece, now.into())
    }

    fn seed(&mut self, key: GroupKey, hash: Hash, piece: Piece, now: Now) -> Vec<Outgoing> {
        let now_ms = now.judged().ms();
        let (me, deadlines) = (self.me, self.deadlines);
        let held = self
            .groups
            .get(&key)
            .is_some_and(|group| group.pieces.contains_key(&hash));
        let growth = self.groups.get(&key).map_or_else(
            || Tree::<Hash, Held>::bytes_at(1) + piece.held_len(),
            |group| group.hold_growth(&piece, 0),
        );
        if !held && !self.charge(growth) {
            return Vec::new();
        }
        let group = self
            .groups
            .entry(key)
            .or_insert_with(|| Group::new(key, me, deadlines));
        group.own.entry(now_ms / 1000).or_default().insert(hash);
        if held {
            self.settle(key, now);
            return Vec::new();
        }
        let before = group.bytes();
        group.hold(hash, piece.clone(), now.mono_ms(), Vec::new());
        settle(&mut self.held, before + growth, group.bytes());
        self.delivered.push(Delivered {
            group: key,
            hash,
            piece: piece.clone(),
            arrival: Arrival::Originated,
        });
        let stripe = data_stripe(&hash);
        let message = Message::Piece {
            group: key,
            hash,
            piece,
        };
        let out = inject(group, &me, stripe, message, now_ms);
        self.settle(key, now);
        self.route(out, None, now_ms)
    }

    /// A message from another relay.
    pub fn receive(
        &mut self,
        from: PublicKey,
        message: Message,
        now: impl Into<Now>,
    ) -> Vec<Outgoing> {
        let now = now.into();
        let key = message.group();
        let out = match message {
            Message::Piece { group, hash, piece } => self.piece(from, group, hash, piece, now),
            Message::Manifest(manifest) => self.manifest(from, manifest, now),
            Message::Parity(parity) => self.parity(from, parity, now),
            Message::Receipt(receipt) => self.receipt(from, receipt, now),
            Message::Have(have) => self.have(from, &have, now),
            Message::Assign(_) => Vec::new(),
        };
        if let Some(key) = key {
            self.settle(key, now);
        }
        self.route(out, Some(&from), now.judged().ms())
    }

    fn piece(
        &mut self,
        from: PublicKey,
        key: GroupKey,
        hash: Hash,
        piece: Piece,
        now: Now,
    ) -> Vec<Outgoing> {
        let now_ms = now.judged().ms();
        let me = self.me;
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        if group.refused.contains_key(&hash) {
            return Vec::new();
        }
        if group.pieces.contains_key(&hash) {
            // Its sender noted, if there is room to note it.
            let growth = group.note_growth(&hash, &from);
            if charge(&mut self.held, &mut self.stats, growth) {
                let before = group.bytes();
                group.note(hash, (from, now_ms), now.mono_ms());
                settle(&mut self.held, before + growth, group.bytes());
            }
            self.stats.duplicates += 1;
            return Vec::new();
        }
        if piece.hash() != Some(hash) {
            return Vec::new();
        }
        // What holding it allocates more: its place and piece, and its senders, those credited
        // while there was no room to take it (`credit`), who delivered it first, with `from`. Their
        // list moves from the credit to the record, which lets the credit's place go.
        let credited = group.credited.get(&hash);
        let senders_growth = credited.map_or(footprint::vec::<Sender>(1), |credited| {
            note_growth(&credited.from, &from)
        });
        let growth = group.pieces.growth() + piece.held_len() + senders_growth;
        if !charge(&mut self.held, &mut self.stats, growth) {
            // No room to hold it: `from` delivered it all the same, and is credited as a link
            // refused for want of room credits it (`credit`), so its receipt counts it had and
            // the parent that sent it is never reported short.
            self.credit(from, key, hash, now);
            return Vec::new();
        }
        // A member's copy of one rebuilt and awaiting judgment: the member's, judged by its relay
        // before it came here, is held and pushed on; the rebuilt one is let go (`pass_on`).
        release(&mut self.held, group.drop_judging(&hash));
        let before = group.bytes();
        let mut senders = group
            .credited
            .remove(&hash)
            .map_or_else(Vec::new, |credited| {
                group.entries_bytes -= senders_bytes(&credited.from, credited.from.capacity());
                credited.from
            });
        let charged = before + growth;
        note(&mut senders, (from, now_ms));
        let parent = group
            .layout
            .place(data_stripe(&hash), epoch_of(now_ms / 1000), &me)
            .and_then(|place| place.parent);
        if parent.is_some_and(|parent| parent != from) {
            self.stats.repaired += 1;
        }
        group.hold(hash, piece.clone(), now.mono_ms(), senders);
        settle(&mut self.held, charged, group.bytes());
        self.delivered.push(Delivered {
            group: key,
            hash,
            piece: piece.clone(),
            arrival: Arrival::Received(from),
        });
        push(group, &me, &from, data_stripe(&hash), now_ms, || {
            Message::Piece {
                group: key,
                hash,
                piece: piece.clone(),
            }
        })
    }

    fn manifest(&mut self, from: PublicKey, manifest: PieceManifest, now: Now) -> Vec<Outgoing> {
        let now_ms = now.judged().ms();
        let me = self.me;
        let hash = manifest.hash();
        let Ok(content) = manifest.content() else {
            return Vec::new();
        };
        let key = GroupKey::new(content.cell, content.product);
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        let Ok(origin) = manifest.signer() else {
            return Vec::new();
        };
        // Only a member originates into the group (a demoted one too: it is out of the trees, not
        // the group, and still holds its feeders); each origin has its own share of a second.
        if group.seen.contains_key(&hash)
            || !in_window(content.second, now.judged(), group.deadlines)
            || !(group.members.contains(&origin) || group.demoted.contains_key(&origin))
            || group.manifests.get(&content.second).is_some_and(|by_hash| {
                by_hash
                    .values()
                    .filter(|listed| listed.origin == origin)
                    .count()
                    >= MAX_MANIFESTS_PER_ORIGIN_SECOND
            })
            || manifest.verify().is_err()
        {
            return Vec::new();
        }
        group.seen.insert(hash, now.mono_ms());
        group.manifests.entry(content.second).or_default().insert(
            hash,
            Listed {
                manifest: manifest.clone(),
                origin,
                hashes: content.hashes,
                whole: false,
            },
        );
        flood(group, &me, Some(&from), now_ms, Message::Manifest(manifest))
    }

    fn parity(&mut self, from: PublicKey, parity: Arc<Parity>, now: Now) -> Vec<Outgoing> {
        let now_ms = now.judged().ms();
        let me = self.me;
        let key = GroupKey::new(parity.cell, parity.product);
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        let id = parity.id();
        if group.parity.contains_key(&id) {
            let growth = group.note_growth(&id, &from);
            if charge(&mut self.held, &mut self.stats, growth) {
                let before = group.bytes();
                group.note(id, (from, now_ms), now.mono_ms());
                settle(&mut self.held, before + growth, group.bytes());
            }
            return Vec::new();
        }
        // Only the parity of an origin manifest held: every edge carries a manifest before its
        // parity (the origin sends the parity's seed the manifest first, a member floods one on
        // taking it and takes a parity only after, a repair page leads with it), so a parity of
        // nothing held is one nobody owes, and is not kept.
        let listed = group
            .manifests
            .get(&parity.second)
            .is_some_and(|by_hash| by_hash.contains_key(&parity.manifest));
        let held = HeldParity {
            parity: Arc::clone(&parity),
            at_ms: now.mono_ms(),
            from: vec![(from, now_ms)],
        };
        let growth = group.parity_growth(&held);
        if !listed || !in_window(parity.second, now.judged(), group.deadlines) {
            return Vec::new();
        }
        if !charge(&mut self.held, &mut self.stats, growth) {
            // No room to hold it: `from` delivered it all the same, and is credited as a record
            // refused for room credits its sender (`piece`).
            self.credit(from, key, id, now);
            return Vec::new();
        }
        let before = group.bytes();
        group.hold_parity(held);
        settle(&mut self.held, before + growth, group.bytes());
        push(group, &me, &from, PARITY_STRIPE, now_ms, || {
            Message::Parity(Arc::clone(&parity))
        })
    }

    fn receipt(&mut self, from: PublicKey, receipt: StripeReceipt, now: Now) -> Vec<Outgoing> {
        let now_ms = now.judged().ms();
        let me = self.me;
        let hash = receipt.hash();
        let Ok(content) = receipt.content() else {
            return Vec::new();
        };
        let key = GroupKey::new(content.cell, content.product);
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        if group.seen.contains_key(&hash)
            || !in_window(content.first_second, now.judged(), group.deadlines)
            || receipt.verify().is_err()
        {
            return Vec::new();
        }
        let Ok(child) = receipt.signer() else {
            return Vec::new();
        };
        group.seen.insert(hash, now.mono_ms());
        if note_shortfall(group, &child, &content) {
            flood(group, &me, Some(&from), now_ms, Message::Receipt(receipt))
        } else {
            Vec::new()
        }
    }

    /// Answers a member's `HaveSummary`: the manifests, parity and records of the seconds it
    /// does not hold whole that this one holds, oldest first, at most `REPAIR_PAGE_BYTES`. Only a
    /// member of the group's trees that is not demoted is answered: a page is up to
    /// `REPAIR_PAGE_BYTES` of this relay's upload, and an asker the group does not hold is owed
    /// none of it.
    fn have(&mut self, from: PublicKey, have: &HaveSummary, now: Now) -> Vec<Outgoing> {
        let key = GroupKey::new(have.cell, have.product);
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        if have.check().is_err()
            || from == self.me
            || !group.members.contains(&from)
            || group.demoted.contains_key(&from)
            || group
                .answered
                .get(&from)
                .is_some_and(|at| at + ANSWER_INTERVAL_MS > now.mono_ms())
        {
            return Vec::new();
        }
        group.answered.insert(from, now.mono_ms());
        let group = &*group;
        let mut out = Vec::new();
        let mut budget = REPAIR_PAGE_BYTES;
        // `end_second` saturates, so the range is never backwards.
        let (first, end) = (have.first_second, have.end_second());
        if first >= end {
            return out;
        }
        for (second, by_hash) in group.manifests.range(first..end) {
            let bit = second - have.first_second;
            let byte = have
                .seconds
                .get(usize::try_from(bit / 8).unwrap_or(usize::MAX));
            if byte.is_some_and(|byte| byte & (0x80 >> (bit % 8)) != 0) {
                continue;
            }
            for listed in by_hash.values() {
                let mut messages = vec![Message::Manifest(listed.manifest.clone())];
                if let Some(held) = group.parity.get(&id_of(&listed.manifest.hash())) {
                    messages.push(Message::Parity(Arc::clone(&held.parity)));
                }
                messages.extend(listed.hashes.iter().filter_map(|hash| {
                    group.pieces.get(hash).map(|held| Message::Piece {
                        group: key,
                        hash: *hash,
                        piece: held.piece.clone(),
                    })
                }));
                for message in messages {
                    let len = message.len();
                    if len > budget {
                        return out;
                    }
                    budget -= len;
                    out.push(Outgoing { to: from, message });
                }
            }
        }
        out
    }

    /// The timed duties: manifests and parity, rebuilds, receipts, judgments, repair, and
    /// forgetting what is past the horizon.
    ///
    /// Only the groups with something due are visited (`settle`), in key order, and each is
    /// scheduled again after: a group with nothing due at `now_ms` would have done nothing.
    pub fn tick(&mut self, now: impl Into<Now>) -> Vec<Outgoing> {
        let now = now.into();
        let now_ms = now.judged().ms();
        let me = self.me;
        let mut out = Vec::new();
        // Who would not answer an ask: the members this relay routes around as full, and those
        // it turned away while they may still route around it (their wait, and its slack:
        // `Deadlines::route_slack`).
        let silent: BTreeSet<PublicKey> = self
            .full
            .iter()
            .copied()
            .chain(
                self.turned_away
                    .iter()
                    .filter(|(_, held)| {
                        held.last.is_some_and(|wait| {
                            now_ms
                                < wait
                                    .until_ms
                                    .saturating_add(self.deadlines.route_slack.ms())
                        })
                    })
                    .map(|(key, _)| *key),
            )
            .collect();
        let mut keys: Vec<GroupKey> = self
            .due
            .iter()
            .take_while(|(at, _)| *at <= now.mono_ms())
            .map(|(_, key)| *key)
            .collect();
        keys.sort();
        // Manifests and receipts are signed only while the relay's clock is synced
        // (`signer::Signer::with`): until then they wait, and are made at the first tick after.
        let signer = self.signer.clone();
        crate::signer::with(&signer, now, |signing| {
            for key in keys {
                let Some(group) = self.groups.get_mut(&key) else {
                    continue;
                };
                self.visits += 1;
                if let Some(identity) = signing {
                    out.extend(originate_manifests(
                        group,
                        identity,
                        now,
                        (&mut self.held, &mut self.stats),
                    ));
                }
                rebuild(
                    group,
                    now,
                    &mut self.held,
                    &mut self.delivered,
                    &mut self.stats,
                );
                if let Some(identity) = signing {
                    out.extend(receipts(
                        group,
                        identity,
                        &self.turned_away,
                        now,
                        &mut self.stats,
                    ));
                }
                judge(group, now, &mut self.demotions, &mut self.stats);
                expire_demotions(group, now);
                out.extend(assign(group, &me, now_ms));
                out.extend(repair(group, (&me, &silent), now, &mut self.stats));
                release(&mut self.held, forget(group, now));
                self.settle(key, now);
            }
        });
        self.forget_turned_away(now_ms);
        self.route(out, None, now_ms)
    }
}

/// Sends a message of `stripe` into the group as its origin: to the stripe's seed, and down this
/// relay's own subtree of the stripe (when it is the seed, that is the whole tree). Its subtree
/// cannot wait for the seed's copy: that copy reaches this relay as one it already holds, and a
/// record already held is never pushed again.
fn inject(
    group: &Group,
    me: &PublicKey,
    stripe: u8,
    message: Message,
    now_ms: u64,
) -> Vec<Outgoing> {
    let seed = group
        .layout
        .seed(stripe, epoch_of(now_ms / 1000))
        .filter(|seed| seed != me);
    seed.into_iter()
        .chain(group.children(stripe, now_ms, me))
        .map(|to| Outgoing {
            to,
            message: message.clone(),
        })
        .collect()
}

/// Pushes something new on down `stripe` (never back to who sent it).
fn push(
    group: &Group,
    me: &PublicKey,
    from: &PublicKey,
    stripe: u8,
    now_ms: u64,
    message: impl Fn() -> Message,
) -> Vec<Outgoing> {
    group
        .children(stripe, now_ms, me)
        .into_iter()
        .filter(|child| child != from)
        .map(|to| Outgoing {
            to,
            message: message(),
        })
        .collect()
}

/// Sends a group-wide message over every tree edge (never back to who sent it).
fn flood(
    group: &Group,
    me: &PublicKey,
    from: Option<&PublicKey>,
    now_ms: u64,
    message: Message,
) -> Vec<Outgoing> {
    group
        .neighbours(now_ms, me)
        .into_iter()
        .filter(|to| Some(to) != from)
        .map(|to| Outgoing {
            to,
            message: message.clone(),
        })
        .collect()
}

/// Notes a receipt that reports its deliverer short of what the window owed, in a steady
/// window. True when it did (and so travels to the group).
fn note_shortfall(group: &mut Group, child: &PublicKey, content: &StripeReceiptContent) -> bool {
    if content.stripes_of != STRIPES
        || !content.first_second.is_multiple_of(RECEIPT_WINDOW_SECONDS)
        || content.last_second != content.first_second + RECEIPT_WINDOW_SECONDS - 1
    {
        return false;
    }
    let window = content.first_second / RECEIPT_WINDOW_SECONDS;
    if !group.steady(window) || !group.layout.contains(child) {
        return false;
    }
    let owed = owed_by(group, window, content.stripe, child, &content.parent);
    if u64::from(content.records) >= owed.len() as u64 {
        return false;
    }
    group
        .shortfalls
        .entry((window, content.stripe, content.parent))
        .or_default()
        .insert(*child);
    group.starved.insert((window, content.stripe, *child));
    true
}

/// What `deliverer` owed `child` in a window's stripe: everything listed, from its parent; from
/// an origin, to the stripe's seed, what that origin listed. Never what the child itself
/// originated: it holds that already, and the seed never sends a record back where it came from.
fn owed_by(
    group: &Group,
    window: u64,
    stripe: u8,
    child: &PublicKey,
    deliverer: &PublicKey,
) -> Vec<Hash> {
    let epoch = epoch_of(window * RECEIPT_WINDOW_SECONDS);
    let parent = group
        .layout
        .place(stripe, epoch, child)
        .and_then(|place| place.parent);
    group
        .owed(window, stripe)
        .into_iter()
        .filter(|(_, owed)| !owed.origins.contains(child))
        .filter(|(_, owed)| match parent {
            Some(parent) => parent == *deliverer,
            None => owed.origins.contains(deliverer),
        })
        .map(|(hash, _)| hash)
        .collect()
}

/// An origin's duty after each second: sign the manifest of what it originated, flood it, and
/// send its parity down the parity stripe.
fn originate_manifests(
    group: &mut Group,
    identity: &impl Signs,
    now: Now,
    (held, stats): (&mut Charge, &mut Stats),
) -> Vec<Outgoing> {
    let now_ms = now.judged().ms();
    let me = identity.public();
    let due: Vec<u64> = group
        .own
        .keys()
        .copied()
        .filter(|second| (second + 1) * 1000 + MANIFEST_DELAY_MS <= now_ms)
        .collect();
    let mut out = Vec::new();
    for second in due {
        let Some(hashes) = group.own.remove(&second) else {
            continue;
        };
        let hashes: Vec<Hash> = hashes.into_iter().collect();
        for chunk in hashes.chunks(MAX_PIECES) {
            let content = PieceManifestContent {
                cell: group.key.cell,
                product: group.key.product,
                second,
                hashes: chunk.to_vec(),
            };
            let Ok(manifest) = PieceManifest::sign(identity, &content) else {
                continue;
            };
            let hash = manifest.hash();
            group.seen.insert(hash, now.mono_ms());
            let pieces: Option<Vec<(Hash, &Piece)>> = chunk
                .iter()
                .map(|hash| group.pieces.get(hash).map(|held| (*hash, &held.piece)))
                .collect();
            let parity = pieces.map(|pieces| {
                Arc::new(Parity::build(
                    hash,
                    group.key.cell,
                    group.key.product,
                    second,
                    &pieces,
                ))
            });
            group.manifests.entry(second).or_default().insert(
                hash,
                Listed {
                    manifest: manifest.clone(),
                    origin: me,
                    hashes: content.hashes,
                    whole: false,
                },
            );
            let flooded = flood(
                group,
                &me,
                None,
                now_ms,
                Message::Manifest(manifest.clone()),
            );
            let neighbours: BTreeSet<PublicKey> = flooded.iter().map(|sent| sent.to).collect();
            out.extend(flooded);
            if let Some(parity) = parity {
                // Held for repair only if the store has room; sent down the parity stripe either
                // way, as what this relay sends is never the store's.
                let kept = HeldParity {
                    parity: Arc::clone(&parity),
                    at_ms: now.mono_ms(),
                    from: Vec::new(),
                };
                let growth = group.parity_growth(&kept);
                if charge(held, stats, growth) {
                    let before = group.bytes();
                    group.hold_parity(kept);
                    settle(held, before + growth, group.bytes());
                }
                let sends = inject(group, &me, PARITY_STRIPE, Message::Parity(parity), now_ms);
                // A member takes a parity only for a manifest it holds (`Member::parity`), so the
                // parity's seed, which may share no tree edge with this relay, is sent the
                // manifest first, down the same link.
                for to in sends.iter().map(|sent| sent.to) {
                    if !neighbours.contains(&to) {
                        out.push(Outgoing {
                            to,
                            message: Message::Manifest(manifest.clone()),
                        });
                    }
                }
                out.extend(sends);
            }
        }
    }
    out
}

/// Rebuilds, from parity, a manifest's records when all it lacks are in one data stripe, and holds
/// them apart (`Group::judging`), handed to the relay (`Arrival::Rebuilt`), which judges each as a
/// member's piece is and only then has it held and pushed on down its stripe (`Member::pass_on`),
/// refuses it (`Member::refuse`) or lets it go (`Member::let_go`).
/// Parity is unsigned, so it is checked here against the
/// manifest's own hashes: with every other stripe held, a true parity rebuilds exactly the records
/// missing, so one that rebuilds anything else (or nothing) is false and is dropped, and the next
/// parity for the manifest that arrives is taken in its place. What it rebuilt that matches the
/// manifest is kept either way: a record is checked by its own hash.
fn rebuild(
    group: &mut Group,
    now: Now,
    held: &mut Charge,
    delivered: &mut Vec<Delivered>,
    stats: &mut Stats,
) {
    let now_ms = now.judged().ms();
    let mut found: Vec<(Hash, Piece)> = Vec::new();
    let mut false_parity: Vec<Hash> = Vec::new();
    for (second, by_hash) in &mut group.manifests {
        if (second + 1) * 1000 + REBUILD_AFTER_MS > now_ms {
            break;
        }
        for (manifest, listed) in by_hash.iter_mut() {
            if listed.whole {
                continue;
            }
            let missing: Vec<Hash> = listed
                .hashes
                .iter()
                .filter(|hash| {
                    !group.pieces.contains_key(*hash)
                        && !group.judging.contains_key(*hash)
                        && !group.refused.contains_key(*hash)
                })
                .copied()
                .collect();
            let Some(first) = missing.first() else {
                listed.whole = true;
                continue;
            };
            let stripe = data_stripe(first);
            if missing.iter().any(|hash| data_stripe(hash) != stripe) {
                continue;
            }
            let id = id_of(manifest);
            let Some(held) = group.parity.get(&id) else {
                continue;
            };
            let others: Vec<(Hash, &Piece)> = listed
                .hashes
                .iter()
                .filter(|hash| data_stripe(hash) != stripe)
                .filter_map(|hash| group.pieces.get(hash).map(|held| (*hash, &held.piece)))
                .collect();
            // The parity rebuilds the stripe's whole slice: every record the manifest lists in
            // it, those already held beside those missing. A true parity rebuilds exactly those,
            // each once; one held is matched and not taken again. Only a slice that is not the
            // listed records is a false parity: one holding part of the stripe when its parity
            // came is no reason to let a true parity go (and, its parity let go, to report the
            // parent that delivered it short).
            let in_stripe: BTreeSet<Hash> = listed
                .hashes
                .iter()
                .filter(|hash| data_stripe(hash) == stripe)
                .copied()
                .collect();
            let mut matched = BTreeSet::new();
            let mut extra = false;
            for bytes in held.parity.rebuild(stripe, &others).unwrap_or_default() {
                let piece = Piece::from_encoded(bytes);
                match piece.as_ref().and_then(Piece::hash) {
                    Some(hash) if in_stripe.contains(&hash) && matched.insert(hash) => {
                        if let Some(piece) = piece
                            && missing.contains(&hash)
                        {
                            found.push((hash, piece));
                        }
                    }
                    _ => extra = true,
                }
            }
            if extra || matched != in_stripe {
                false_parity.push(id);
            }
        }
    }
    for id in false_parity {
        release(held, group.drop_parity(&id));
    }
    for (hash, piece) in found {
        if group.has(&hash) {
            continue;
        }
        let judging = Judging {
            held: Held {
                piece: piece.clone(),
                at_ms: now.mono_ms(),
                from: Vec::new(),
            },
        };
        let growth = group.judging.growth() + judging.held.bytes();
        if !charge(held, stats, growth) {
            continue;
        }
        let before = group.bytes();
        group.entries_bytes += judging.held.bytes();
        group.judging.insert(hash, judging);
        settle(held, before + growth, group.bytes());
        stats.rebuilt += 1;
        delivered.push(Delivered {
            group: group.key,
            hash,
            piece,
            arrival: Arrival::Rebuilt,
        });
    }
}

/// After each window and its grace: a receipt per stripe for each deliverer that owed this
/// relay something, sent to the deliverer, and to the group when it was short.
///
/// Routing around (RFC-0174 §2.5, "A relay's members are bounded") is no shortfall on either side:
/// a deliverer this relay turned away as full while it owed the window (`turned_away`) is owed
/// nothing and gets no receipt, since it was sending its slice past this relay by the wait both
/// keep; and when what the parent owed came first from above it in the stripe's tree (or from its
/// origin) before it could have been a repair, the parent was being routed around: each who
/// delivered past it is signed a receipt for what it delivered, which no member reads as short (it
/// is not this relay's parent, so it owed this relay nothing), and no shortfall is filed against
/// the parent, which is signed its receipt only if it delivered the rest itself.
fn receipts(
    group: &mut Group,
    identity: &impl Signs,
    turned_away: &Tree<PublicKey, TurnedAway>,
    now: Now,
    stats: &mut Stats,
) -> Vec<Outgoing> {
    let now_ms = now.judged().ms();
    let me = identity.public();
    let deadlines = group.deadlines;
    let windows: BTreeSet<u64> = group
        .manifests
        .keys()
        .map(|second| second / RECEIPT_WINDOW_SECONDS)
        .filter(|window| {
            (window + 1) * RECEIPT_WINDOW_SECONDS * 1000 + deadlines.receipt_grace.ms() <= now_ms
                && !group.receipted.contains(window)
        })
        .collect();
    let mut out = Vec::new();
    for window in windows {
        group.receipted.insert(window);
        let first = window * RECEIPT_WINDOW_SECONDS;
        let end = first + RECEIPT_WINDOW_SECONDS;
        let epoch = epoch_of(first);
        for stripe in 0..STRIPES {
            let Some(place) = group.layout.place(stripe, epoch, &me) else {
                continue;
            };
            let owed_all = group.owed(window, stripe);
            let deliverers: BTreeSet<PublicKey> = match place.parent {
                Some(parent) => [parent].into(),
                None => owed_all
                    .values()
                    .flat_map(|owed| owed.origins.iter())
                    .copied()
                    .collect(),
            };
            for deliverer in deliverers.into_iter().filter(|key| *key != me) {
                if turned_away.get(&deliverer).is_some_and(|held| {
                    held.during(
                        first * 1000,
                        end * 1000 + deadlines.receipt_grace.ms(),
                        deadlines.route_slack.ms(),
                    )
                }) {
                    continue;
                }
                let owed = owed_by(group, window, stripe, &me, &deliverer);
                if owed.is_empty() {
                    continue;
                }
                let got = delivered_by(group, &owed, &deliverer);
                let past = if place.parent == Some(deliverer) {
                    routed_past(group, (stripe, epoch), &me, &deliverer, &owed, &owed_all)
                } else {
                    BTreeMap::new()
                };
                let routed_around = !past.is_empty();
                for (router, got) in past {
                    let Some((receipt, _)) =
                        sign_receipt(group, identity, (router, stripe, first), &got, now)
                    else {
                        continue;
                    };
                    stats.receipts += 1;
                    out.push(Outgoing {
                        to: router,
                        message: Message::Receipt(receipt),
                    });
                }
                // A parent routed around that did not deliver the rest itself is signed nothing:
                // it was full, and a receipt short of what it owed would report it.
                if routed_around && got.len() < owed.len() {
                    continue;
                }
                let Some((receipt, content)) =
                    sign_receipt(group, identity, (deliverer, stripe, first), &got, now)
                else {
                    continue;
                };
                stats.receipts += 1;
                out.push(Outgoing {
                    to: deliverer,
                    message: Message::Receipt(receipt.clone()),
                });
                if note_shortfall(group, &me, &content) {
                    stats.shortfalls += 1;
                    out.extend(flood(
                        group,
                        &me,
                        Some(&deliverer),
                        now_ms,
                        Message::Receipt(receipt),
                    ));
                }
            }
        }
    }
    out
}

/// What of `owed` `deliverer` delivered, in the order it came.
fn delivered_by(group: &Group, owed: &[Hash], deliverer: &PublicKey) -> Vec<Hash> {
    let mut got: Vec<(u64, Hash)> = owed
        .iter()
        .filter_map(|hash| {
            group
                .senders(hash)
                .iter()
                .find(|(sender, _)| sender == deliverer)
                .map(|(_, at)| (*at, *hash))
        })
        .collect();
    got.sort();
    got.into_iter().map(|(_, hash)| hash).collect()
}

/// What `parent` owed this relay in a window's stripe that reached it past the parent first, by
/// who delivered it, each in the order it came: from a member above the parent in the stripe's
/// tree, or from the record's origin, before its second settled (`Deadlines::repair_after`
/// after it ended: no repair is asked for a second before then, so what came sooner was pushed
/// down the tree, past a parent that was full to the one that pushed it), and before the parent's
/// own copy if it sent one.
fn routed_past(
    group: &Group,
    (stripe, epoch): (u8, u64),
    me: &PublicKey,
    parent: &PublicKey,
    owed: &[Hash],
    owed_all: &BTreeMap<Hash, Owed>,
) -> BTreeMap<PublicKey, Vec<Hash>> {
    let above = group.above(stripe, epoch, parent);
    let mut past: BTreeMap<PublicKey, Vec<(u64, Hash)>> = BTreeMap::new();
    for hash in owed {
        let Some(listed) = owed_all.get(hash) else {
            continue;
        };
        let senders = group.senders(hash);
        let parent_at = senders
            .iter()
            .find(|(sender, _)| sender == parent)
            .map_or(u64::MAX, |(_, at)| *at);
        let before_ms =
            parent_at.min((listed.second + 1) * 1000 + group.deadlines.repair_after.ms());
        if let Some((router, at)) = senders.iter().find(|(sender, at)| {
            sender != me
                && sender != parent
                && *at < before_ms
                && (above.contains(sender) || listed.origins.contains(sender))
        }) {
            past.entry(*router).or_default().push((*at, *hash));
        }
    }
    past.into_iter()
        .map(|(router, mut got)| {
            got.sort();
            (router, got.into_iter().map(|(_, hash)| hash).collect())
        })
        .collect()
}

/// This relay's signed receipt to `deliverer` for `hashes` (what it delivered) of a window's
/// stripe, and what it says.
fn sign_receipt(
    group: &mut Group,
    identity: &impl Signs,
    (deliverer, stripe, first): (PublicKey, u8, u64),
    hashes: &[Hash],
    now: Now,
) -> Option<(StripeReceipt, StripeReceiptContent)> {
    let content = StripeReceiptContent {
        parent: deliverer,
        cell: group.key.cell,
        product: group.key.product,
        stripe,
        stripes_of: STRIPES,
        first_second: first,
        last_second: first + RECEIPT_WINDOW_SECONDS - 1,
        records: u32::try_from(hashes.len()).unwrap_or(u32::MAX),
        bytes: hashes.iter().map(|hash| group.bytes_of(hash)).sum(),
        digest: receipt_digest(hashes),
        issued_ms: now.judged().ms(),
    };
    let receipt = StripeReceipt::sign(identity, &content).ok()?;
    group.seen.insert(receipt.hash(), now.mono_ms());
    Some((receipt, content))
}

/// Demotes a member most of whose children in a stripe reported it short for a window it was not
/// itself starved in.
fn judge(
    group: &mut Group,
    now: Now,
    demotions: &mut Vec<(GroupKey, PublicKey, MonoDeadline)>,
    stats: &mut Stats,
) {
    let now_ms = now.judged().ms();
    let deadlines = group.deadlines;
    let due: Vec<u64> = group
        .receipted
        .iter()
        .copied()
        .filter(|window| {
            (window + 1) * RECEIPT_WINDOW_SECONDS * 1000
                + deadlines.receipt_grace.ms()
                + deadlines.judge_after.ms()
                <= now_ms
                && !group.judged.contains(window)
        })
        .collect();
    for window in due {
        group.judged.insert(window);
        if !group.steady(window) {
            continue;
        }
        stats.judged += 1;
        let epoch = epoch_of(window * RECEIPT_WINDOW_SECONDS);
        let accused: Vec<(u8, PublicKey, BTreeSet<PublicKey>)> = group
            .shortfalls
            .iter()
            .filter(|((w, _, _), _)| *w == window)
            .map(|((_, stripe, deliverer), children)| (*stripe, *deliverer, children.clone()))
            .collect();
        for (stripe, deliverer, reporters) in accused {
            if group.demoted.contains_key(&deliverer)
                || group.starved.contains(&(window, stripe, deliverer))
            {
                continue;
            }
            let Some(place) = group.layout.place(stripe, epoch, &deliverer) else {
                continue;
            };
            let reporting = place
                .children
                .iter()
                .filter(|child| reporters.contains(child))
                .count();
            if place.children.is_empty() || reporting * 2 <= place.children.len() {
                continue;
            }
            // Out of the trees for `DEMOTION_MS` by `M`: a step of `J` stretches no demotion.
            let until = now.after(DEMOTION_MS);
            group.demoted.insert(deliverer, until);
            demotions.push((group.key, deliverer, until));
        }
        group.relayout(now_ms);
    }
}

fn expire_demotions(group: &mut Group, now: Now) {
    let before = group.demoted.len();
    group.demoted.retain(|_, until| !until.passed(now));
    if group.demoted.len() != before {
        group.relayout(now.judged().ms());
    }
}

/// Tells each parent which stripes this relay takes from it, when that changes (membership, or a
/// seed rotation); an empty set withdraws from a former parent.
fn assign(group: &mut Group, me: &PublicKey, now_ms: u64) -> Vec<Outgoing> {
    let epoch = epoch_of(now_ms / 1000);
    let mut wanted: BTreeMap<PublicKey, u32> = BTreeMap::new();
    for stripe in 0..STRIPES {
        if let Some(parent) = group
            .layout
            .place(stripe, epoch, me)
            .and_then(|place| place.parent)
        {
            *wanted.entry(parent).or_default() |= 1 << stripe;
        }
    }
    if group.assigned_epoch == Some(epoch) && wanted == group.assigned {
        return Vec::new();
    }
    group.assigned_epoch = Some(epoch);
    let mut out = Vec::new();
    let parents: BTreeSet<PublicKey> = wanted
        .keys()
        .chain(group.assigned.keys())
        .copied()
        .collect();
    for parent in parents {
        let stripes = wanted.get(&parent).copied().unwrap_or(0);
        if group.assigned.get(&parent).copied().unwrap_or(0) == stripes {
            continue;
        }
        out.push(Outgoing {
            to: parent,
            message: Message::Assign(StripeAssignment {
                cell: group.key.cell,
                product: group.key.product,
                stripes_of: STRIPES,
                stripes,
            }),
        });
    }
    group.assigned = wanted;
    out
}

/// Asks a rotating member for the seconds this one lacks (or, now and then, for none in
/// particular, so a lost manifest is found), never one of the `silent`, which would not answer.
fn repair(
    group: &mut Group,
    (me, silent): (&PublicKey, &BTreeSet<PublicKey>),
    now: Now,
    stats: &mut Stats,
) -> Vec<Outgoing> {
    let now_ms = now.judged().ms();
    // Its pace is a duration's, by `M`; the seconds it asks of, by `J`.
    if now.mono_ms() < group.repair_at_ms {
        return Vec::new();
    }
    let now_second = now_ms / 1000;
    let deadlines = group.deadlines;
    let first = now_second.saturating_sub(deadlines.horizon_seconds());
    let lacking = group
        .manifests
        .range(first..)
        .take_while(|(second, _)| (*second + 1) * 1000 + deadlines.repair_after.ms() <= now_ms)
        .any(|(second, _)| !group.whole(*second));
    let anti_entropy = now.mono_ms() >= group.anti_entropy_at_ms;
    if !lacking && !anti_entropy {
        return Vec::new();
    }
    let attempt = group.repair_attempt;
    let peer = group
        .layout
        .members()
        .into_iter()
        .filter(|key| key != me && !silent.contains(key))
        .max_by_key(|key| {
            score(
                REPAIR,
                group.key.cell,
                group.key.product,
                0,
                attempt,
                &[me, key],
            )
        });
    let Some(peer) = peer else {
        return Vec::new();
    };
    group.repair_attempt += 1;
    group.repair_at_ms = now.mono_ms() + REPAIR_INTERVAL_MS;
    group.anti_entropy_at_ms = now.mono_ms() + ANTI_ENTROPY_MS;
    let span = (now_second + 1 - first).min(MAX_HAVE_SECONDS as u64);
    let mut seconds = vec![0u8; usize::try_from(span.div_ceil(8)).unwrap_or(0)];
    for offset in 0..span {
        let second = first + offset;
        // A second still arriving is not asked for; one with no manifest is, so a manifest that
        // never came is found.
        let settled = (second + 1) * 1000 + deadlines.repair_after.ms() <= now_ms;
        if (!settled || group.whole(second))
            && let Some(byte) = seconds.get_mut(usize::try_from(offset / 8).unwrap_or(0))
        {
            *byte |= 0x80 >> (offset % 8);
        }
    }
    stats.repairs_asked += u64::from(lacking);
    vec![Outgoing {
        to: peer,
        message: Message::Have(HaveSummary {
            cell: group.key.cell,
            product: group.key.product,
            first_second: first,
            seconds,
        }),
    }]
}

/// Forgets what is past the horizon. The bytes it let go (records, parities and credits).
///
/// What the group holds (records, records awaiting judgment, parities, credits) and the hashes it
/// took in or refused are let go by `M`, a horizon after they came: how long the relay keeps a
/// possessed thing is a duration, and its store is planned on it (`budget::Store::Batches`), so
/// a step of `J` either way keeps nothing past its plan. What is indexed by signed second (the
/// manifests, the relay's own records not yet in one, the windows receipted and judged, the
/// shortfalls) is let go by `J`: no copy enters it outside the seconds `J` admits
/// (`in_window`), so a step holds at most one horizon's seconds beside the new.
fn forget(group: &mut Group, now: Now) -> usize {
    let now_ms = now.judged().ms();
    let horizon_seconds = group.deadlines.horizon_seconds();
    let horizon_ms = now_ms.saturating_sub(horizon_seconds * 1000);
    let kept_from_ms = now.mono_ms().saturating_sub(horizon_seconds * 1000);
    let horizon_second = horizon_ms / 1000;
    let horizon_window = horizon_second / RECEIPT_WINDOW_SECONDS;
    let before = group.bytes();
    let mut freed = 0;
    group.pieces.retain(|_, held| {
        let keep = held.at_ms >= kept_from_ms;
        if !keep {
            freed += held.bytes();
        }
        keep
    });
    group.judging.retain(|_, judging| {
        let keep = judging.held.at_ms >= kept_from_ms;
        if !keep {
            freed += judging.held.bytes();
        }
        keep
    });
    group.parity.retain(|_, held| {
        let keep = held.at_ms >= kept_from_ms;
        if !keep {
            freed += held.bytes();
        }
        keep
    });
    group.credited.retain(|_, credited| {
        let keep = credited.at_ms >= kept_from_ms;
        if !keep {
            freed += senders_bytes(&credited.from, credited.from.capacity());
        }
        keep
    });
    group.entries_bytes -= freed;
    let freed = before - group.bytes();
    group.manifests = group.manifests.split_off(&horizon_second);
    group.own = group.own.split_off(&horizon_second);
    group.seen.retain(|_, at| *at >= kept_from_ms);
    group.refused.retain(|_, at| *at >= kept_from_ms);
    group
        .answered
        .retain(|_, at| *at + ANSWER_INTERVAL_MS > now.mono_ms());
    group.receipted = group.receipted.split_off(&horizon_window);
    group.judged = group.judged.split_off(&horizon_window);
    group
        .shortfalls
        .retain(|(window, _, _), _| *window >= horizon_window);
    group
        .starved
        .retain(|(window, _, _)| *window >= horizon_window);
    group
        .changed_ms
        .retain(|changed| *changed + 2 * horizon_seconds * 1000 >= now_ms);
    freed
}

/// `len` more bytes on the store's charge, or false, counted as refused, when its gauge is full.
fn charge(held: &mut Charge, stats: &mut Stats, len: usize) -> bool {
    let charged = held.try_grow(len);
    if !charged {
        stats.refused += 1;
    }
    charged
}

/// `freed` bytes the store let go, released from its charge.
fn release(held: &mut Charge, freed: usize) {
    let left = held.bytes().saturating_sub(freed);
    held.shrink_to(left);
}

/// A change charged `charged` (what the group allocated before it and its growth) that leaves the
/// group allocating `now`: what it did not grow by given back, so the charge is what the groups
/// allocate. A change never grows by more than its growth reckons.
fn settle(held: &mut Charge, charged: usize, now: usize) {
    debug_assert!(now <= charged, "a group grew past what it was charged");
    release(held, charged.saturating_sub(now));
}

/// Whether a signed `second` is one this relay holds things for: within the horizon behind its
/// judging clock, and no further ahead than two relays' clocks may differ
/// (`tally_wire::budget::Window::sharing`), so what is held is bounded and `forget` bounds memory.
fn in_window(second: u64, now: Judged, deadlines: Deadlines) -> bool {
    tally_wire::budget::Window::sharing(deadlines.horizon()).holds_second(second, now)
}
