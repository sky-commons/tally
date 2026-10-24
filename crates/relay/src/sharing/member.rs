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

/// What a group is planned at for one record beside its signed bytes: held, its entry in the
/// group's tree of records at the most a tree costs an entry (`footprint::btree_planned`) and the
/// shared batch it names ([`Piece::held_len`]); and what the group reckons by for it
/// ([`RECKONING_PER_RECORD`]), whether it is held or not.
pub const PIECE_ENTRY_BYTES: usize =
    Tree::<Hash, Held>::bytes_per_entry() + footprint::arc::<Batch>() + RECKONING_PER_RECORD;

/// What a group reckons by for one record ([`Reckoning`]): its entry in the ledger of deliveries
/// ([`LEDGER_ENTRY_BYTES`]), and in its books its hash in the manifest that lists it, as signed and
/// as listed, and its place among what this relay originated before the manifest was signed.
pub const RECKONING_PER_RECORD: usize =
    LEDGER_ENTRY_BYTES + 2 * std::mem::size_of::<Hash>() + Tree::<Hash, ()>::bytes_per_entry();

/// What one record's or parity's place in a group's ledger of deliveries is planned at: its entry
/// in the ledger and the list of its [`PLANNED_SENDERS`].
pub const LEDGER_ENTRY_BYTES: usize =
    Tree::<Hash, Noted>::bytes_per_entry() + PLANNED_SENDERS_BYTES;

/// What a group is planned at for one parity beside its XOR: its entry in the group's tree of
/// parities and the parity's own allocation, and what the group reckons by for it
/// ([`RECKONING_PER_PARITY`]).
pub const PARITY_ENTRY_BYTES: usize =
    Tree::<Hash, HeldParity>::bytes_per_entry() + footprint::arc::<Parity>() + RECKONING_PER_PARITY;

/// What a group reckons by for one parity, and the manifest it is the parity of, one an origin's
/// second ([`Reckoning`]): the parity's place in the ledger, and the manifest's books: its entry
/// by second and by hash, what it allocates beside its hashes (`MANIFEST_FIXED_BYTES`), and its
/// hash among those seen.
pub const RECKONING_PER_PARITY: usize = LEDGER_ENTRY_BYTES
    + Tree::<u64, Tree<Hash, Listed>>::bytes_per_entry()
    + Tree::<Hash, Listed>::bytes_per_entry()
    + MANIFEST_FIXED_BYTES
    + Tree::<Hash, u64>::bytes_per_entry();

/// What a held manifest allocates beside the hashes it lists (each counted with its record,
/// [`PIECE_ENTRY_BYTES`]): its signed fields, signature and key at the most a manifest's are.
const MANIFEST_FIXED_BYTES: usize = 256;

const _: () = assert!(grown(grown(0)) >= PLANNED_SENDERS);

/// What a group's trees of records, rebuilt records, deliveries and parities, and its books cost
/// before any entry, at the most (`footprint::btree_planned` of none): what a plan takes for each
/// group.
pub const GROUP_TREES_BYTES: usize = Tree::<Hash, Held>::bytes_planned(0)
    + Tree::<Hash, Judging>::bytes_planned(0)
    + Tree::<Hash, Noted>::bytes_planned(0)
    + Tree::<Hash, HeldParity>::bytes_planned(0)
    + Books::PLANNED_BYTES;

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
    /// Deliveries not noted in the ledger for want of its room, its floor and the store's
    /// (`Reckoning`): what a receipt may then count short.
    pub unnoted: u64,
    /// Entries of a group's books not made for want of the store's room (`book`): a manifest not
    /// listed, a shortfall not noted, an answer or a window not kept.
    pub unbooked: u64,
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
}

/// A relay that delivered a record or a parity, and when by `J`: what a receipt orders what it
/// delivered by, and what says whether it came before its second settled (`routed_past`).
type Sender = (PublicKey, u64);

/// What a list of senders allocates.
fn senders_bytes(capacity: usize) -> usize {
    footprint::vec::<Sender>(capacity)
}

/// What noting `who` among `from` allocates more: nothing if it is there or there is room, else
/// the list doubled (from one).
fn note_growth(from: &Vec<Sender>, who: &PublicKey) -> usize {
    if from.len() < from.capacity() || from.iter().any(|(sender, _)| sender == who) {
        return 0;
    }
    senders_bytes(grown(from.capacity())) - senders_bytes(from.capacity())
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
        self.piece.held_len()
    }
}

/// Who delivered a record or a parity, and how long it is: the evidence a group's receipts are
/// signed from (`receipts`), its ledger (`Group::ledger`), kept apart from whether the group holds
/// the thing. A record held, rebuilt, let go for the store's room or never taken in for want of
/// it (`Member::credit`) is noted alike, so a receipt credits whoever delivered it whatever this
/// relay could hold, with its length (`StripeReceiptContent::bytes`).
///
/// It is kept a horizon after it was first noted, and past that until every window that lists it
/// has been judged (`Group::keep_for`): a receipt is signed when the judging clock has passed its
/// window and its grace (`Due`), which an origin's clock ahead of this one, or this one's stepped
/// back, puts later on `M` than a horizon after the record came. Before, a record's senders were
/// let go with its bytes by `M`, so such a receipt found none and reported an honest deliverer
/// short.
struct Noted {
    /// Its encoded length (`Piece::len`, `Parity::len`): what a receipt counts it as.
    len: u64,
    /// Until when it is kept, by `M`.
    kept_until: MonoDeadline,
    from: Vec<Sender>,
}

impl Noted {
    /// Kept until `until` as well: [`MonoDeadline::NEVER`] while a window that lists it has not
    /// been scheduled, then that window's judgment, in place of the wait (`Reckoning::keep`).
    fn keep(&mut self, until: MonoDeadline) {
        self.kept_until = if until == MonoDeadline::NEVER || self.kept_until != MonoDeadline::NEVER
        {
            self.kept_until.max(until)
        } else {
            until
        };
    }
}

/// A record this relay refused that a member delivered before any manifest it holds listed it
/// (`Member::refused`), kept to be pushed on once one does (`Member::manifest`): only then are
/// its children owed it. Let go a horizon after it came, by `M` (`forget`), as a held record is.
struct Parked {
    held: Held,
    /// Who delivered it: whom the push skips.
    from: PublicKey,
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
    /// Until when it is kept, by `M` (`Listed::kept_until`): let go then, or once `J` puts its
    /// second past the horizon, whichever is first.
    kept_until: MonoDeadline,
}

/// What this relay originated in one second, not yet in a manifest of its own, and when the first
/// of it came by `M`: signed once `J` has passed the second and the manifest's delay, or as long by
/// `M` since the first came, whichever is first, so a step of `J` back holds none of it.
struct Own {
    at_ms: u64,
    hashes: Tree<Hash, ()>,
}

impl Listed {
    /// What it allocates beside its entry in its tree: the manifest's bytes and its hashes.
    fn bytes(&self) -> usize {
        self.manifest.allocated() + footprint::vec::<Hash>(self.hashes.capacity())
    }

    /// How long a manifest listed at `now` is kept, by `M`: a horizon, as what it lists is
    /// (`forget`), and to its window's judgment once that is scheduled (`Group::keep_listed`). On
    /// `M`, so a step of `J` back after it came holds it no longer. A manifest whose window `J`
    /// does not end within that horizon (an origin's clock ahead of this one by more than the
    /// horizon less the window, or this one's stepped back) is let go before its window is
    /// scheduled: its window then signs no receipt and reports nobody short, never one that
    /// finds what it listed forgotten.
    fn kept_until(now: Now, deadlines: Deadlines) -> MonoDeadline {
        now.after(deadlines.horizon_ms())
    }
}

/// One thing a window's tree owes its members (a record, or a manifest's parity): who originated
/// it, and the second it is listed in.
struct Owed {
    origins: BTreeSet<PublicKey>,
    second: u64,
}

/// A receipt window as the relay keeps its own time for it (RFC-0171 §3.6): when its judging
/// clock was first read past the window's end, and the deadlines that follow on `M`. A window is
/// a span of signed seconds, so only `J` says when it has ended; from then on, its receipts and
/// its judgment are this relay's own schedule, put on the clock that neither steps nor slews by
/// the policy's spans (`Deadlines::receipt_grace`, `Deadlines::judge_after`), so a step of `J`
/// forward lets no window fall due before its grace, and one back holds none past it. Before, both
/// were readings of `J`: a step forward made every window it passed due at once, before what was
/// still arriving for them had come.
#[derive(Clone, Copy, Debug)]
struct Due {
    /// When `J` was first read past its end, by `M`.
    ended: MonoDeadline,
    /// When its receipts are signed, by `M`.
    receipt: MonoDeadline,
    /// When the group judges it, by `M`.
    judge: MonoDeadline,
    receipted: bool,
    judged: bool,
}

impl Due {
    /// The span the window and its grace cover on `M`, (start, end): its receipts' deadline and
    /// the window's length before its end. What a relay turned away as full is asked about
    /// (`TurnedAway::during`), as its wait was kept on `M`.
    fn on_mono(&self) -> (u64, u64) {
        (
            self.ended
                .mono_ms()
                .saturating_sub(RECEIPT_WINDOW_SECONDS * 1000),
            self.receipt.mono_ms(),
        )
    }
}

/// What a group keeps of its own reckoning beside what it holds and its ledger: the manifests, the
/// relay's own records not yet in one, the hashes taken in or refused, the receipt windows, the
/// shortfalls and starvations reported, when members' asks were answered, and when its trees
/// changed. Every entry is charged to the store before it is made (`Member::book`), what it
/// allocates read from [`Books::bytes`]; and every one is bounded: a manifest only from a member
/// and within the window of seconds held (`in_window`), at most
/// [`MAX_MANIFESTS_PER_ORIGIN_SECOND`] an origin's second; a shortfall only from a member of the
/// trees, once; a window only of a second a manifest lists. Before, these were held outside what
/// the group was charged.
#[derive(Default)]
struct Books {
    /// By second, then by the manifest's hash.
    manifests: Tree<u64, Tree<Hash, Listed>>,
    /// What the listed manifests allocate beside their entries (`Listed::bytes`).
    listed_bytes: usize,
    /// What this relay originated, by second, not yet in a manifest.
    own: Tree<u64, Own>,
    /// Manifests and receipts already taken in, by hash, with when by `M`.
    seen: Tree<Hash, u64>,
    /// Records this relay refused (`Member::refuse`), with when by `M`: never held or pushed on,
    /// and counted as had, so a manifest that lists one is whole and no repair asks for it; and
    /// owed by nobody, so no deliverer is reported short of one this relay judged bad.
    refused: Tree<Hash, u64>,
    /// The receipt windows `J` has passed the end of, with their schedule on `M` (`Due`).
    windows: Tree<u64, Due>,
    /// (window, stripe, deliverer): the members that reported it short.
    shortfalls: Tree<(u64, u8, PublicKey), Tree<PublicKey, ()>>,
    /// (window, stripe, member): the member reported its own deliverer short.
    starved: Tree<(u64, u8, PublicKey), ()>,
    /// When each member's `HaveSummary` was last answered, by `M`.
    answered: Tree<PublicKey, u64>,
    /// When the trees last changed, (by `J`, by `M`), newest last: judged against the windows'
    /// signed seconds by `J` (`Group::steady`), let go by `M`.
    changed: Vec<(u64, u64)>,
    /// What all of it allocates, as last counted (`Books::count`).
    bytes: usize,
}

impl Books {
    /// What a group's books are planned at before any record (each record's and manifest's share
    /// is in [`PIECE_ENTRY_BYTES`] and [`PARITY_ENTRY_BYTES`]): their trees' roots, the windows of
    /// two horizons (what `forget` keeps of them) with a shortfall reported in every stripe of
    /// each and its reporter, the members' answers and the trees' changes of a horizon, a
    /// change a second.
    pub const PLANNED_BYTES: usize = {
        let windows =
            (2 * Deadlines::RELAY.horizon_seconds()).div_ceil(RECEIPT_WINDOW_SECONDS) as usize + 1;
        let shortfalls = windows * STRIPES as usize;
        Tree::<u64, Tree<Hash, Listed>>::bytes_planned(0)
            + Tree::<u64, Own>::bytes_planned(0)
            + Tree::<Hash, u64>::bytes_planned(0) * 3
            + Tree::<u64, Due>::bytes_planned(windows)
            + Tree::<(u64, u8, PublicKey), Tree<PublicKey, ()>>::bytes_planned(shortfalls)
            + shortfalls * Tree::<PublicKey, ()>::bytes_planned(1)
            + Tree::<(u64, u8, PublicKey), ()>::bytes_planned(shortfalls)
            + footprint::vec::<(u64, u64)>(2 * Deadlines::RELAY.horizon_seconds() as usize)
    };

    /// Counts what it allocates afresh: its trees, at most (`footprint::Tree`), the trees inside
    /// them, the manifests' own and the changes' list. A visit of its seconds and windows, never
    /// of the records they list.
    fn count(&mut self) {
        self.bytes = self.manifests.bytes()
            + self.manifests.values().map(Tree::bytes).sum::<usize>()
            + self.listed_bytes
            + self.own.bytes()
            + self
                .own
                .values()
                .map(|own| own.hashes.bytes())
                .sum::<usize>()
            + self.seen.bytes()
            + self.refused.bytes()
            + self.windows.bytes()
            + self.shortfalls.bytes()
            + self.shortfalls.values().map(Tree::bytes).sum::<usize>()
            + self.starved.bytes()
            + self.answered.bytes()
            + footprint::vec::<(u64, u64)>(self.changed.capacity());
    }

    fn is_empty(&self) -> bool {
        self.manifests.is_empty()
            && self.own.is_empty()
            && self.seen.is_empty()
            && self.windows.is_empty()
            && self.shortfalls.is_empty()
            && self.starved.is_empty()
    }
}

/// What a relay this one turned away as full (`Reason::Full`, `link`) is held as: the wait the
/// refusals gave it, by the rule the relay refused applies to them (`full::Wait`, on `M`), and the
/// spans it routed around this one, (start, end) by `M`: in order and apart (each starts past the
/// last's end and its slack), a refusal within one merged into it, so a relay turned away again
/// and again while it waits holds one span, and a receipt check finds the span it asks about by
/// search.
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

    /// Whether it was routing around this relay at any time from `from_ms` to `to_ms`, by `M`,
    /// each span counted with its slack.
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

struct HeldParity {
    parity: Arc<Parity>,
    /// When it was taken in, by `M`.
    at_ms: u64,
}

impl HeldParity {
    /// What it allocates beside its entry in its tree: the parity and its XOR.
    fn bytes(&self) -> usize {
        footprint::arc::<Parity>() + footprint::vec::<u8>(self.parity.xor.capacity())
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
    pieces: Tree<Hash, Held>,
    /// Records rebuilt from parity that this relay has not yet judged (`rebuild`): held apart
    /// from `pieces`, charged and counted in `bytes`, so none is answered to a repair, used to
    /// rebuild another, or pushed on before its relay takes it in (`Member::pass_on`), refuses it
    /// (`Member::refuse`) or lets it go (`Member::let_go`). Counted as had, so no repair asks for
    /// one while it waits.
    judging: Tree<Hash, Judging>,
    /// Records this relay refused before a manifest it holds listed them (`Parked`): charged and
    /// counted in `bytes` as `judging` is, never answered to a repair, and pushed on only once a
    /// manifest lists them, so a refused record nobody lists (one whose signature fails) is
    /// never carried down the tree.
    parked: Tree<Hash, Parked>,
    /// What the entries of `pieces`, `judging`, `parked` and `parity` allocate beside their places in the
    /// trees (`Held::bytes`, `HeldParity::bytes`), kept as they change. With the trees' own and the
    /// books' ([`Group::bytes`]), what the member's store charge holds for the group, each change
    /// charged before it is made.
    entries_bytes: usize,
    parity: Tree<Hash, HeldParity>,
    /// Who delivered each record and parity (`Noted`), held or not: charged to the member's
    /// ledger (`Member::ledger`), apart from what the group holds.
    ledger: Tree<Hash, Noted>,
    /// What the ledger's senders allocate beside its entries.
    ledger_entries: usize,
    books: Books,
    repair_at_ms: u64,
    repair_attempt: u64,
    anti_entropy_at_ms: u64,
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
            pieces: Tree::new(),
            judging: Tree::new(),
            parked: Tree::new(),
            entries_bytes: 0,
            parity: Tree::new(),
            ledger: Tree::new(),
            ledger_entries: 0,
            books: Books::default(),
            repair_at_ms: 0,
            repair_attempt: 0,
            anti_entropy_at_ms: 0,
            assigned: BTreeMap::new(),
            assigned_epoch: None,
        }
    }

    /// Lays the trees out again over the members not demoted, noting when they changed (one more
    /// entry in the books' list, which its caller charged, `Member::book`).
    fn relayout(&mut self, now: Now) {
        let members: Vec<PublicKey> = self
            .members
            .iter()
            .filter(|key| !self.demoted.contains_key(key))
            .copied()
            .collect();
        let layout = Layout::new(self.key.cell, self.key.product, &members, &self.leaves_only);
        if layout != self.layout {
            self.layout = layout;
            self.books.changed.push((now.judged().ms(), now.mono_ms()));
            self.books.count();
        }
    }

    /// What a relayout may add to the books at most: one change more.
    fn relayout_growth(&self) -> usize {
        let changed = &self.books.changed;
        if changed.len() < changed.capacity() {
            0
        } else {
            footprint::vec::<(u64, u64)>(grown(changed.capacity()).max(4))
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

    /// Whether the trees stood still over a window and its grace, so its receipts can be judged:
    /// the window's signed seconds against when, by `J`, the trees changed.
    fn steady(&self, window: u64) -> bool {
        let first = window * RECEIPT_WINDOW_SECONDS;
        let end = first + RECEIPT_WINDOW_SECONDS;
        if end.is_multiple_of(SEED_ROTATION_SECONDS) {
            return false;
        }
        let from = (first * 1000).saturating_sub(1000);
        let to = end * 1000 + self.deadlines.receipt_grace.ms();
        !self
            .books
            .changed
            .iter()
            .any(|(changed, _)| (from..=to).contains(changed))
    }

    /// What every member of the window's tree in `stripe` is owed: every listed record of the
    /// stripe (or, for the parity stripe, every listed manifest's parity), with its origins and the
    /// second it is listed in. Never a record this relay refused (`Member::refuse`): it judged it
    /// bad, so it holds nobody short of it, and its parent, which refused it too and so pushed it
    /// no further, is not reported for an origin's bad record.
    fn owed(&self, window: u64, stripe: u8) -> BTreeMap<Hash, Owed> {
        let first = window * RECEIPT_WINDOW_SECONDS;
        let mut owed: BTreeMap<Hash, Owed> = BTreeMap::new();
        for (second, listed) in self
            .books
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
            for hash in listed.hashes.iter().filter(|hash| {
                data_stripe(hash) == stripe && !self.books.refused.contains_key(*hash)
            }) {
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

    /// Who delivered `hash` (a record or a parity id), in order, as its ledger noted them: whether
    /// this relay holds it, held and let it go, or never had room to take it in.
    fn senders(&self, hash: &Hash) -> &[Sender] {
        self.ledger
            .get(hash)
            .map_or(&[], |noted| noted.from.as_slice())
    }

    /// The length of `hash` as its ledger noted it: what a receipt counts it as, held or not.
    fn bytes_of(&self, hash: &Hash) -> u64 {
        self.ledger.get(hash).map_or(0, |noted| noted.len)
    }

    fn whole(&self, second: u64) -> bool {
        self.books.manifests.get(&second).is_some_and(|by_hash| {
            by_hash
                .values()
                .all(|listed| listed.whole || listed.hashes.iter().all(|h| self.has(h)))
        })
    }

    /// Whether a manifest it holds lists `hash`: a record some member is owed.
    fn lists(&self, hash: &Hash) -> bool {
        self.books
            .manifests
            .values()
            .flat_map(|by_hash| by_hash.values())
            .any(|listed| listed.hashes.contains(hash))
    }

    /// Whether it holds `hash`, has it rebuilt and awaiting judgment, or refused it: either way,
    /// nothing to ask for.
    fn has(&self, hash: &Hash) -> bool {
        self.pieces.contains_key(hash)
            || self.judging.contains_key(hash)
            || self.books.refused.contains_key(hash)
    }

    /// What it allocates for what it holds, as its member's store charge holds it: its trees of
    /// records, rebuilt records and parities (`footprint::Tree`, at most) and their entries' own.
    /// What it reckons is apart ([`Group::reckoning_bytes`]).
    fn bytes(&self) -> usize {
        self.pieces.bytes()
            + self.judging.bytes()
            + self.parked.bytes()
            + self.parity.bytes()
            + self.entries_bytes
    }

    /// What its reckoning allocates: its ledger (its tree and the senders in it) and its books.
    fn reckoning_bytes(&self) -> usize {
        self.ledger.bytes() + self.ledger_entries + self.books.bytes
    }

    /// Lets go of a rebuilt record awaiting judgment, if it is one. The bytes it let go.
    fn drop_judging(&mut self, hash: &Hash) -> usize {
        let before = self.bytes();
        if let Some(judging) = self.judging.remove(hash) {
            self.entries_bytes -= judging.held.bytes();
        }
        before - self.bytes()
    }

    /// What parking a refused record with `piece` allocates more.
    fn park_growth(&self, piece: &Piece) -> usize {
        self.parked.growth() + piece.held_len()
    }

    /// Parks a refused record `from` delivered (`Parked`), counting what it allocates, which its
    /// caller has charged ([`Group::park_growth`]).
    fn park(&mut self, hash: Hash, piece: Piece, from: PublicKey, at_ms: u64) {
        let held = Held { piece, at_ms };
        self.entries_bytes += held.bytes();
        self.parked.insert(hash, Parked { held, from });
    }

    /// Takes the parked records `hashes` lists out, to be pushed on: (hash, piece, who delivered
    /// it). The bytes it let go beside them.
    fn unpark(&mut self, hashes: &[Hash]) -> (Vec<(Hash, Piece, PublicKey)>, usize) {
        let before = self.bytes();
        let mut out = Vec::new();
        for hash in hashes {
            if let Some(Parked { held, from }) = self.parked.remove(hash) {
                self.entries_bytes -= held.bytes();
                out.push((*hash, held.piece, from));
            }
        }
        (out, before - self.bytes())
    }

    /// What holding a record with `piece` allocates more.
    fn hold_growth(&self, piece: &Piece) -> usize {
        self.pieces.growth() + piece.held_len()
    }

    /// Holds a piece, counting what it allocates, which its caller has charged
    /// ([`Group::hold_growth`]).
    fn hold(&mut self, hash: Hash, piece: Piece, at_ms: u64) {
        let held = Held { piece, at_ms };
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

    /// What noting `from` as a sender of the record or parity `hash` allocates more in the
    /// ledger, at most.
    fn note_growth(&self, hash: &Hash, from: &PublicKey) -> usize {
        match self.ledger.get(hash) {
            Some(noted) => note_growth(&noted.from, from),
            None => self.ledger.growth() + senders_bytes(1),
        }
    }

    /// Notes `sender` as a sender of the record or parity `hash` of `len` bytes, kept at least
    /// until `kept_until`, a horizon on by `M`: past the judgment of any window whose schedule is
    /// made by then (its judgment is at most `receipt_grace` and `judge_after` on), and a window
    /// scheduled later keeps what it lists to its own ([`Group::keep_listed`]). Charged first, by
    /// [`Group::note_growth`], to the ledger. The bytes it grew by.
    fn note(&mut self, hash: Hash, sender: Sender, len: usize, kept_until: MonoDeadline) -> usize {
        let before = self.reckoning_bytes();
        let noted = self.ledger.entry(hash).or_insert(Noted {
            len: u64::try_from(len).unwrap_or(u64::MAX),
            kept_until,
            from: Vec::new(),
        });
        noted.kept_until = noted.kept_until.max(kept_until);
        if noted.len == 0 {
            // Kept for a window before it came (`Reckoning::keep`): its length is now known.
            noted.len = u64::try_from(len).unwrap_or(u64::MAX);
        }
        let capacity = noted.from.capacity();
        note(&mut noted.from, sender);
        let grown = senders_bytes(noted.from.capacity()) - senders_bytes(capacity);
        self.ledger_entries += grown;
        self.reckoning_bytes() - before
    }

    /// Keeps `window`'s manifests, and who delivered what they list (records and parities), until
    /// `until`, its judgment by `M`: a window is judged by `J`, which an origin's clock ahead of this one, or
    /// this one stepped back, puts later than a horizon after the records came.
    fn keep_listed(&mut self, window: u64, until: MonoDeadline) {
        let first = window * RECEIPT_WINDOW_SECONDS;
        let listed: Vec<Hash> = self
            .books
            .manifests
            .range(first..first + RECEIPT_WINDOW_SECONDS)
            .flat_map(|(_, by_hash)| by_hash.iter())
            .flat_map(|(manifest, listed)| {
                std::iter::once(id_of(manifest)).chain(listed.hashes.iter().copied())
            })
            .collect();
        for hash in listed {
            if let Some(noted) = self.ledger.get_mut(&hash) {
                noted.keep(until);
            }
        }
        let seconds: Vec<u64> = self
            .books
            .manifests
            .range(first..first + RECEIPT_WINDOW_SECONDS)
            .map(|(second, _)| *second)
            .collect();
        for second in seconds {
            if let Some(by_hash) = self.books.manifests.get_mut(&second) {
                for listed in by_hash.values_mut() {
                    listed.kept_until = listed.kept_until.max(until);
                }
            }
        }
    }

    /// Whether it holds anything within the horizon: then every tick has duties for it
    /// (manifests, rebuilds, receipts, judgment, repair, forgetting).
    fn busy(&self) -> bool {
        !(self.pieces.is_empty()
            && self.judging.is_empty()
            && self.parked.is_empty()
            && self.parity.is_empty()
            && self.ledger.is_empty()
            && self.books.is_empty())
    }

    /// Whether this relay is alone in it with nothing: what it would be if it were not held at
    /// all, so it is let go.
    fn idle(&self, me: &PublicKey) -> bool {
        self.members.iter().all(|member| member == me)
            && self.leaves_only.iter().all(|member| member == me)
            && !self.busy()
            && self.demoted.is_empty()
            && self.assigned.is_empty()
            && self.books.changed.is_empty()
            && self.books.answered.is_empty()
            && self.books.refused.is_empty()
    }

    /// When the tick must next visit it: at once while it holds anything; else at the soonest of
    /// its timed duties (the next seed rotation and anti-entropy ask while it has another member,
    /// a demotion's end, forgetting what it remembers of the trees and of what it refused); never
    /// when it has none. By `M`, the clock the tick runs on: a seed rotation, set by a signed
    /// second, is put on it as the two clocks read now (`Now::mono_at`), so a step of `J` never
    /// stalls a group's tick, and with it the forgetting.
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
        let horizon_ms = self.deadlines.horizon_seconds() * 1000;
        if let Some((_, changed)) = self.books.changed.iter().min_by_key(|(_, mono)| *mono) {
            wake = wake.min(changed + 2 * horizon_ms + 1);
        }
        if let Some(at) = self.books.answered.values().min() {
            wake = wake.min(at + ANSWER_INTERVAL_MS);
        }
        if let Some(at) = self.books.refused.values().min() {
            wake = wake.min(at + horizon_ms);
        }
        (wake != u64::MAX).then_some(wake.max(now.mono_ms()))
    }
}

/// What every group a member holds reckons by, beside what it holds: its ledger of who delivered
/// what (`Group::ledger`) and its books (`Books`: the manifests, the receipt windows, the
/// shortfalls). Charged together to the one batch byte store (`budget::Store::Batches`), apart
/// from what the groups hold, with a floor reserved for it ([`reckoning_floor`]): records and
/// parities never take the floor, so a store full of what the groups hold still lists what a
/// window owes and notes who delivered what this relay had no room to take in, and its receipts
/// never report an honest deliverer short for this relay's want of room. Before, a sender was
/// noted only when the store had room for its note, which a full store did not, while its
/// manifests were held uncharged.
struct Reckoning {
    /// At least the floor, and at least what the groups reckon by.
    charge: Charge,
    /// What the groups reckon by, each group's `Group::reckoning_bytes` together.
    bytes: usize,
}

impl Reckoning {
    /// Notes `sender` of `hash` (`len` bytes) in `group`'s ledger, kept a horizon on, its growth
    /// charged first: from the floor while it lasts, then from the store. False, counted, when
    /// neither has room.
    fn note(
        &mut self,
        group: &mut Group,
        (hash, len): (Hash, usize),
        sender: Sender,
        now: Now,
        stats: &mut Stats,
    ) -> bool {
        let growth = group.note_growth(&hash, &sender.0);
        if !self.grow(growth) {
            stats.unnoted += 1;
            return false;
        }
        let kept_until = now.after(group.deadlines.horizon_ms());
        self.bytes += group.note(hash, sender, len, kept_until);
        true
    }

    /// Keeps who delivers each of `listed` (what one window's manifest lists, its records and its
    /// parity) in `group`'s ledger until `until`: the window's judgment by `M` once `J` has passed
    /// its end, [`MonoDeadline::NEVER`] before (`Noted::keep`). An entry is made now for each not
    /// delivered yet, so one delivered later is kept to the window's judgment too. Charged as a
    /// note is; one past the room is not kept, counted (`Stats::unnoted`).
    fn keep(&mut self, group: &mut Group, listed: &[Hash], until: MonoDeadline, stats: &mut Stats) {
        for hash in listed {
            if let Some(noted) = group.ledger.get_mut(hash) {
                noted.keep(until);
                continue;
            }
            if !self.grow(group.ledger.growth()) {
                stats.unnoted += 1;
                continue;
            }
            let before = group.reckoning_bytes();
            group.ledger.insert(
                *hash,
                Noted {
                    len: 0,
                    kept_until: until,
                    from: Vec::new(),
                },
            );
            self.bytes += group.reckoning_bytes() - before;
        }
    }

    /// Room for `growth` more: from the charge held (the floor, while the reckoning is under it),
    /// else from the store. False when neither has it.
    fn grow(&mut self, growth: usize) -> bool {
        let need = self.bytes.saturating_add(growth);
        let charged = self.charge.bytes();
        need <= charged || self.charge.try_grow(need - charged)
    }

    /// `freed` bytes the reckoning let go, the charge brought down to what it allocates or the
    /// floor of `gauge`, whichever is more; and the floor taken again where it was short and the
    /// store has room.
    fn settle(&mut self, freed: usize, gauge: &Gauge) {
        self.bytes -= freed;
        let want = self.bytes.max(reckoning_floor(gauge.limit()));
        let charged = self.charge.bytes();
        if charged > want {
            self.charge.shrink_to(want);
        } else if charged < want && self.charge.fits(want - charged) {
            let _ = self.charge.try_grow(want - charged);
        }
    }
}

/// The floor of a store of `limit` bytes reserved for what the groups reckon by ([`Reckoning`]):
/// its share of what the store is planned at for a feeder (`budget::PerFeeder::planned_for`, whose
/// groups' part is [`PIECE_ENTRY_BYTES`] a record and [`PARITY_ENTRY_BYTES`] a second, of them
/// [`RECKONING_PER_RECORD`] and [`RECKONING_PER_PARITY`] the reckoning's). None for a store that
/// is never full (a test's unlimited gauge).
pub fn reckoning_floor(limit: usize) -> usize {
    if limit == usize::MAX {
        return 0;
    }
    let planned = crate::budget::PerFeeder::planned_for(false, true, 0, None)
        .of(crate::budget::Store::Batches);
    if planned == 0 {
        return 0;
    }
    let records = crate::cores::RECORDS_PER_PLANNED_FEEDER as usize;
    let reckoning = (records * RECKONING_PER_RECORD + RECKONING_PER_PARITY)
        * Deadlines::RELAY.horizon_ms() as usize
        / 1000;
    usize::try_from(limit as u128 * reckoning as u128 / planned as u128).unwrap_or(usize::MAX)
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
    /// store's gauge (`budget::Store::Batches`) before it is held and released as it is let go:
    /// the store's only bound. A record or parity the gauge cannot take is refused whole, counted
    /// (`Stats::refused`).
    held: Charge,
    /// What the groups reckon by (ledgers and books), charged to the same store with a floor of
    /// its own ([`Reckoning`]): an entry past its room is not made, counted (`Stats::unnoted`,
    /// `Stats::unbooked`).
    reckoning: Reckoning,
    gauge: Arc<Gauge>,
    /// The members that turned this relay's link away as full, while they are (`set_full`): what
    /// it sends is routed around them (`route`).
    full: BTreeSet<PublicKey>,
    /// The relays this one turned away as full, and when each was routing around it by `M`
    /// (`turned_away`): no shortfall is filed against one for those windows. At most
    /// [`TURNED_AWAY_HELD`], charged what they allocate (`turned_away_charge`).
    turned_away: Tree<PublicKey, TurnedAway>,
    /// What `turned_away` allocates, charged to the same store as the groups (`gauge`) before it
    /// grows.
    turned_away_charge: Charge,
    /// The judging clock as this member first read it judging (`note_started`): a window that
    /// began before is one whose deliveries it may not have seen (the relay restarted within it),
    /// so it signs no receipt for it and reports nobody short of it. A reading taken while `J` did
    /// not judge says nothing of when this member began: a clock behind at boot would put it
    /// before a window the restart cut, and one ahead would skip windows it saw whole.
    started: Option<Judged>,
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
        let mut reckoning = Reckoning {
            charge: gauge.empty(),
            bytes: 0,
        };
        reckoning.settle(0, &gauge);
        Self {
            signer,
            me,
            deadlines,
            groups: BTreeMap::new(),
            due: BTreeSet::new(),
            held: gauge.empty(),
            reckoning,
            turned_away_charge: gauge.empty(),
            gauge,
            full: BTreeSet::new(),
            turned_away: Tree::new(),
            started: None,
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
        let mut reckoning = gauge.empty();
        if !moved.try_grow(self.held.bytes()) || !reckoning.try_grow(self.reckoning.bytes) {
            moved = gauge.empty();
            reckoning = gauge.empty();
            self.groups.clear();
            self.due.clear();
            self.reckoning.bytes = 0;
        }
        let mut turned_away = gauge.empty();
        if !turned_away.try_grow(self.turned_away_charge.bytes()) {
            self.turned_away.clear();
        }
        self.held = moved;
        self.reckoning.charge = reckoning;
        self.turned_away_charge = turned_away;
        self.reckoning.settle(0, &gauge);
        self.gauge = gauge;
    }

    /// The members full now (`peers::Peers::full`): routed around from now on, until the next
    /// call says otherwise.
    pub fn set_full(&mut self, full: BTreeSet<PublicKey>) {
        self.full = full;
    }

    /// This relay turned `key`'s member link away as full at `now`, asking it to stay away `asked`
    /// (`link`, `Reason::Full`). It takes that as "this provider is full" and routes its slice past
    /// this relay for the wait the one rule gives (`full::Wait`, which `peers` applies to the same
    /// refusal, both on `M`), so for every window that wait covers it owes this relay nothing.
    ///
    /// At most [`TURNED_AWAY_HELD`] relays are held: one more lets go the one whose last span
    /// ended first. What they allocate is charged before it is held; past the store's room the
    /// refusal is not noted, counted (`Stats::turned_away_unheld`), and a shortfall of that relay
    /// is judged as any other's.
    pub fn turned_away(&mut self, key: PublicKey, asked: std::time::Duration, now: impl Into<Now>) {
        let now = now.into();
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
        let wait = Wait::after(held.last, asked, now);
        held.last = Some(wait);
        held.add(
            now.mono_ms(),
            wait.until.mono_ms(),
            self.deadlines.route_slack.ms(),
        );
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
    /// `from_ms` to `to_ms`, by `M`.
    #[cfg(test)]
    pub fn routed_around_by(&self, key: &PublicKey, from_ms: u64, to_ms: u64) -> bool {
        let slack_ms = self.deadlines.route_slack.ms();
        self.turned_away
            .get(key)
            .is_some_and(|held| held.during(from_ms, to_ms, slack_ms))
    }

    /// Forgets the refusals no window still to be receipted can overlap, and the waits that no
    /// longer double the next, by `M`.
    fn forget_turned_away(&mut self, now: Now) {
        let horizon_ms = now
            .mono_ms()
            .saturating_sub(2 * self.deadlines.horizon_ms());
        let slack_ms = self.deadlines.route_slack.ms();
        self.turned_away.retain(|_, held| {
            held.spans
                .retain(|(_, end)| end.saturating_add(slack_ms) >= horizon_ms);
            held.spans.shrink_to_fit();
            !held.spans.is_empty() || held.last.is_some_and(|wait| wait.remembered(now))
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
        let listed = group
            .books
            .manifests
            .get(&chunk.second)?
            .get(&chunk.manifest)?;
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

    /// Bytes held now across its groups (records and parities): what its store charge
    /// holds. What they reckon by is charged apart ([`Member::reckoning_bytes`]).
    pub fn held_bytes(&self) -> usize {
        self.held.bytes()
    }

    /// What its groups reckon by (ledgers and books), and what that is charged (it, or its floor
    /// if that is more).
    pub fn reckoning_bytes(&self) -> (usize, usize) {
        (self.reckoning.bytes, self.reckoning.charge.bytes())
    }

    /// What its groups allocate, by each group's own count (kept apart from the charge, as
    /// records and parities come and go): what its store charge reads.
    pub fn group_bytes(&self) -> usize {
        self.groups.values().map(Group::bytes).sum()
    }

    /// Everything it has charged to its gauge: what its groups hold, what they reckon by (at least
    /// its floor) and the relays it turned away.
    #[cfg(test)]
    pub fn charged_bytes(&self) -> usize {
        self.held.bytes() + self.reckoning.charge.bytes() + self.turned_away_charge.bytes()
    }

    /// What its groups hold, counted afresh from every tree and every entry in them: what its
    /// store charge must read.
    #[cfg(test)]
    pub fn counted_bytes(&self) -> usize {
        self.groups
            .values()
            .map(|group| {
                Tree::<Hash, Held>::bytes_at(group.pieces.len())
                    + Tree::<Hash, Judging>::bytes_at(group.judging.len())
                    + Tree::<Hash, Parked>::bytes_at(group.parked.len())
                    + Tree::<Hash, HeldParity>::bytes_at(group.parity.len())
                    + group.pieces.values().map(Held::bytes).sum::<usize>()
                    + group
                        .judging
                        .values()
                        .map(|judging| judging.held.bytes())
                        .sum::<usize>()
                    + group
                        .parked
                        .values()
                        .map(|parked| parked.held.bytes())
                        .sum::<usize>()
                    + group.parity.values().map(HeldParity::bytes).sum::<usize>()
            })
            .sum()
    }

    /// What its groups reckon by, counted afresh from every entry of their ledgers and books:
    /// what [`Member::reckoning_bytes`] must read.
    #[cfg(test)]
    pub fn counted_reckoning_bytes(&self) -> usize {
        self.groups
            .values()
            .map(|group| {
                let books = &group.books;
                let ledger = Tree::<Hash, Noted>::bytes_at(group.ledger.len())
                    + group
                        .ledger
                        .values()
                        .map(|noted| senders_bytes(noted.from.capacity()))
                        .sum::<usize>();
                let listed = books
                    .manifests
                    .values()
                    .flat_map(|by_hash| by_hash.values());
                ledger
                    + Tree::<u64, Tree<Hash, Listed>>::bytes_at(books.manifests.len())
                    + books
                        .manifests
                        .values()
                        .map(|by_hash| Tree::<Hash, Listed>::bytes_at(by_hash.len()))
                        .sum::<usize>()
                    + listed.map(Listed::bytes).sum::<usize>()
                    + Tree::<u64, Own>::bytes_at(books.own.len())
                    + books
                        .own
                        .values()
                        .map(|own| Tree::<Hash, ()>::bytes_at(own.hashes.len()))
                        .sum::<usize>()
                    + Tree::<Hash, u64>::bytes_at(books.seen.len())
                    + Tree::<Hash, u64>::bytes_at(books.refused.len())
                    + Tree::<u64, Due>::bytes_at(books.windows.len())
                    + Tree::<(u64, u8, PublicKey), Tree<PublicKey, ()>>::bytes_at(
                        books.shortfalls.len(),
                    )
                    + books
                        .shortfalls
                        .values()
                        .map(|children| Tree::<PublicKey, ()>::bytes_at(children.len()))
                        .sum::<usize>()
                    + Tree::<(u64, u8, PublicKey), ()>::bytes_at(books.starved.len())
                    + Tree::<PublicKey, u64>::bytes_at(books.answered.len())
                    + footprint::vec::<(u64, u64)>(books.changed.capacity())
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
                let by_hash = group.books.manifests.get(&second)?;
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
            .and_then(|group| group.books.manifests.get(&second))
            .map(|by_hash| {
                by_hash
                    .values()
                    .map(|listed| listed.manifest.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A record of `group` this relay refused (a batch of a format it reads that does not decode):
    /// never held or pushed on, counted as had until the horizon, so no repair asks for it, and
    /// owed by nobody (`Group::owed`), so no deliverer is reported short of it. Its entry is
    /// charged to the store's books; past their room it is not noted, counted.
    pub fn refuse(&mut self, group: GroupKey, hash: Hash, now: impl Into<Now>) {
        let now = now.into();
        let Some(held) = self.groups.get_mut(&group) else {
            return;
        };
        // One rebuilt from parity awaits its relay's judgment apart (`rebuild`): refused, it is
        // let go, never answered to a repair nor passed on.
        release(&mut self.held, held.drop_judging(&hash));
        let bound = held.books.refused.growth();
        book(&mut self.reckoning, &mut self.stats, held, bound, |held| {
            held.books.refused.insert(hash, now.mono_ms());
        });
        self.settle(group, now);
    }

    /// A record of `group` that member `from` delivered and this relay refused (it reads its format
    /// and it does not decode, or does not verify): counted refused here ([`Member::refuse`]), so
    /// it is owed nobody by this relay's reckoning; `from` noted as its deliverer, so this relay's
    /// receipt credits it; and pushed on down its stripe, not held, as possession carries what it
    /// is handed whether or not it is usable here. Its children are owed it by the manifest that
    /// lists it, and each judges it itself: one that cannot read it holds it, one that refuses it
    /// does as this relay does. Before, it was pushed no further, so every child reported this
    /// relay short for an origin's malformed record, and this relay its own honest parent.
    pub fn refused(
        &mut self,
        from: PublicKey,
        key: GroupKey,
        (hash, piece): (Hash, Piece),
        now: impl Into<Now>,
    ) -> Vec<Outgoing> {
        let now = now.into();
        let now_ms = now.judged().ms();
        let me = self.me;
        let fresh = self.groups.get(&key).is_some_and(|group| {
            !group.books.refused.contains_key(&hash) && !group.pieces.contains_key(&hash)
        });
        if let Some(group) = self.groups.get_mut(&key) {
            self.reckoning.note(
                group,
                (hash, piece.len()),
                (from, now_ms),
                now,
                &mut self.stats,
            );
        }
        self.refuse(key, hash, now);
        let Some(group) = self.groups.get(&key) else {
            return Vec::new();
        };
        if !fresh || !group.books.refused.contains_key(&hash) {
            return Vec::new();
        }
        // Pushed on once a manifest held lists it: only then are its children owed it. Until one
        // does it is parked (`Parked`, pushed on by `manifest`), so a refused record no manifest
        // lists (one whose signature fails) is never carried down the tree; past the store's
        // room it is not parked, and goes no further.
        if !group.lists(&hash) {
            let growth = group.park_growth(&piece);
            if self.charge(growth)
                && let Some(group) = self.groups.get_mut(&key)
            {
                let before = group.bytes();
                group.park(hash, piece, from, now.mono_ms());
                settle(&mut self.held, before + growth, group.bytes());
            }
            return Vec::new();
        }
        let out = push(group, &me, &from, data_stripe(&hash), now_ms, || {
            Message::Piece {
                group: key,
                hash,
                piece: piece.clone(),
            }
        });
        self.route(out, Some(&from), now_ms)
    }

    /// A record of `group`, `len` bytes encoded, that `from` delivered and this relay had no room
    /// to take in (`strikes::Verdict::Full`): `from` is noted as its deliverer in the group's
    /// ledger, as any copy's is, so a receipt never reports an honest member short for this
    /// relay's want of room (RFC-0174 §2.5). Unlike a copy held it is not counted as had or pushed
    /// on: this relay never took it, so its group still lacks it and asks for it again. The note
    /// is charged to the ledgers ([`Reckoning`], whose floor the records never take).
    pub fn credit(
        &mut self,
        from: PublicKey,
        group: GroupKey,
        (hash, len): (Hash, usize),
        now: impl Into<Now>,
    ) {
        let now = now.into();
        let Some(held) = self.groups.get_mut(&group) else {
            return;
        };
        if held.books.refused.contains_key(&hash) {
            return;
        }
        self.reckoning.note(
            held,
            (hash, len),
            (from, now.judged().ms()),
            now,
            &mut self.stats,
        );
        self.settle(group, now);
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
    /// it, and the rebuilt copy is held instead. Whoever delivered it before parity rebuilt it
    /// (`credit`) stays in the ledger, apart from what is held.
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
        if group.pieces.contains_key(&hash) || group.books.refused.contains_key(&hash) {
            return Vec::new();
        }
        let piece = if taken.hash() == Some(hash) {
            taken
        } else {
            rebuilt.piece
        };
        let growth = group.hold_growth(&piece);
        if !charge(&mut self.held, &mut self.stats, growth) {
            // No room to hold it: let go, as any record refused for room; whoever delivered it
            // before stays noted.
            return Vec::new();
        }
        let before = group.bytes();
        group.hold(hash, piece.clone(), rebuilt.at_ms);
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
        self.groups.get(&group).is_some_and(|group| {
            group
                .books
                .own
                .values()
                .any(|own| own.hashes.contains_key(hash))
        })
    }

    /// Whether `group` counts `hash` refused (`Member::refuse`).
    #[cfg(test)]
    pub fn has_refused(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.books.refused.contains_key(hash))
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

    /// When this member began, by `J` (`started`): its first judging reading, taken from `now`
    /// when it is the first. None until `J` judges.
    fn note_started(&mut self, now: Now) -> Option<Judged> {
        if now.judging() {
            self.started.get_or_insert(now.judged());
        }
        self.started
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
        self.note_started(now);
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
        relayout(group, now, (&mut self.reckoning, &mut self.stats));
        let out = assign(group, &me, now_ms);
        self.settle(key, now);
        self.route(out, None, now_ms)
    }

    /// Leaves a group (the relay no longer takes its cell).
    pub fn leave(&mut self, key: GroupKey) {
        if let Some(group) = self.groups.remove(&key) {
            release(&mut self.held, group.bytes());
            self.reckoning.settle(group.reckoning_bytes(), &self.gauge);
            if let Some(at) = group.due_ms {
                self.due.remove(&(at, key));
            }
        }
    }

    /// Schedules `key` for when the tick next has something to do for it, or lets it go when it
    /// is this relay alone with nothing.
    fn settle(&mut self, key: GroupKey, now: Now) {
        self.reckoning.settle(0, &self.gauge);
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
        self.note_started(now);
        let now_ms = now.judged().ms();
        let second = now_ms / 1000;
        let (me, deadlines) = (self.me, self.deadlines);
        let held = self
            .groups
            .get(&key)
            .is_some_and(|group| group.pieces.contains_key(&hash));
        let growth = self.groups.get(&key).map_or_else(
            || Tree::<Hash, Held>::bytes_at(1) + piece.held_len(),
            |group| group.hold_growth(&piece),
        );
        if !held && !self.charge(growth) {
            return Vec::new();
        }
        let group = self
            .groups
            .entry(key)
            .or_insert_with(|| Group::new(key, me, deadlines));
        let own_growth = group.books.own.get(&second).map_or_else(
            || group.books.own.growth() + Tree::<Hash, ()>::bytes_at(1),
            |own| own.hashes.growth(),
        );
        let booked = book(
            &mut self.reckoning,
            &mut self.stats,
            group,
            own_growth,
            |group| {
                group
                    .books
                    .own
                    .entry(second)
                    .or_insert_with(|| Own {
                        at_ms: now.mono_ms(),
                        hashes: Tree::new(),
                    })
                    .hashes
                    .insert(hash, ());
            },
        );
        if held || booked.is_none() {
            // Held already, or not to be listed in a manifest of its own for want of the books'
            // room: not seeded (the charge for holding it given back).
            if !held {
                release(&mut self.held, growth);
            }
            self.settle(key, now);
            return Vec::new();
        }
        let before = group.bytes();
        group.hold(hash, piece.clone(), now.mono_ms());
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
        self.note_started(now);
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

    /// A record a member delivered: its sender noted in the ledger whatever comes of it (held
    /// already, held now, or no room to hold it), then held and pushed on if it is new and the
    /// store has room.
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
        if group.books.refused.contains_key(&hash) {
            return Vec::new();
        }
        if group.pieces.contains_key(&hash) {
            self.reckoning.note(
                group,
                (hash, piece.len()),
                (from, now_ms),
                now,
                &mut self.stats,
            );
            self.stats.duplicates += 1;
            return Vec::new();
        }
        if piece.hash() != Some(hash) {
            return Vec::new();
        }
        // Delivered, whether or not there is room to hold it: a receipt credits `from` for it
        // either way, and the parent that sent it is never reported short for this relay's want
        // of room.
        let first = group.senders(&hash).is_empty();
        self.reckoning.note(
            group,
            (hash, piece.len()),
            (from, now_ms),
            now,
            &mut self.stats,
        );
        let growth = group.hold_growth(&piece);
        if !charge(&mut self.held, &mut self.stats, growth) {
            // No room to hold it: pushed on all the same the first time it comes, as it is in
            // hand, so the members beneath this one are owed nothing it could not keep.
            if !first {
                return Vec::new();
            }
            return push(group, &me, &from, data_stripe(&hash), now_ms, || {
                Message::Piece {
                    group: key,
                    hash,
                    piece: piece.clone(),
                }
            });
        }
        // A member's copy of one rebuilt and awaiting judgment: the member's, judged by its relay
        // before it came here, is held and pushed on; the rebuilt one is let go (`pass_on`).
        release(&mut self.held, group.drop_judging(&hash));
        let before = group.bytes();
        let parent = group
            .layout
            .place(data_stripe(&hash), epoch_of(now_ms / 1000), &me)
            .and_then(|place| place.parent);
        if parent.is_some_and(|parent| parent != from) {
            self.stats.repaired += 1;
        }
        group.hold(hash, piece.clone(), now.mono_ms());
        settle(&mut self.held, before + growth, group.bytes());
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
        if group.books.seen.contains_key(&hash)
            || !in_window(content.second, now.judged(), group.deadlines)
            || !(group.members.contains(&origin) || group.demoted.contains_key(&origin))
            || group
                .books
                .manifests
                .get(&content.second)
                .is_some_and(|by_hash| {
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
        let mut owed = content.hashes.clone();
        owed.push(id_of(&hash));
        let listed = Listed {
            manifest: manifest.clone(),
            origin,
            hashes: content.hashes,
            whole: false,
            kept_until: Listed::kept_until(now, group.deadlines),
        };
        if !list(
            &mut self.reckoning,
            &mut self.stats,
            group,
            (content.second, hash),
            listed,
            now,
        ) {
            return Vec::new();
        }
        // Who delivers what it lists is kept to its window's judgment, however late `J` reaches
        // it (an origin ahead of this relay, this relay's clock stepped back): never let go on a
        // clock before the receipts that credit it are signed.
        let window = content.second / RECEIPT_WINDOW_SECONDS;
        let until = match group.books.windows.get(&window) {
            Some(due) if due.judged => None,
            Some(due) => Some(due.judge),
            None => Some(MonoDeadline::NEVER),
        };
        if let Some(until) = until {
            self.reckoning.keep(group, &owed, until, &mut self.stats);
        }
        // The refused records it lists that were parked for want of one: owed now, pushed on.
        let (listed, freed) = group.unpark(&owed);
        release(&mut self.held, freed);
        let mut out = flood(group, &me, Some(&from), now_ms, Message::Manifest(manifest));
        for (hash, piece, by) in listed {
            out.extend(push(group, &me, &by, data_stripe(&hash), now_ms, || {
                Message::Piece {
                    group: key,
                    hash,
                    piece: piece.clone(),
                }
            }));
        }
        out
    }

    /// A parity a member delivered (reassembled from its chunks): its sender noted in the ledger,
    /// and held and pushed on if it is new, of a manifest held, and the store has room.
    fn parity(&mut self, from: PublicKey, parity: Arc<Parity>, now: Now) -> Vec<Outgoing> {
        let now_ms = now.judged().ms();
        let me = self.me;
        let key = GroupKey::new(parity.cell, parity.product);
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        let id = parity.id();
        if group.parity.contains_key(&id) {
            self.reckoning.note(
                group,
                (id, parity.len()),
                (from, now_ms),
                now,
                &mut self.stats,
            );
            return Vec::new();
        }
        // Only the parity of an origin manifest held: every edge carries a manifest before its
        // parity (the origin sends the parity's seed the manifest first, a member floods one on
        // taking it and takes a parity only after, a repair page leads with it), so a parity of
        // nothing held is one nobody owes, and is not kept.
        let listed = group
            .books
            .manifests
            .get(&parity.second)
            .is_some_and(|by_hash| by_hash.contains_key(&parity.manifest));
        if !listed || !in_window(parity.second, now.judged(), group.deadlines) {
            return Vec::new();
        }
        let first = group.senders(&id).is_empty();
        self.reckoning.note(
            group,
            (id, parity.len()),
            (from, now_ms),
            now,
            &mut self.stats,
        );
        let held = HeldParity {
            parity: Arc::clone(&parity),
            at_ms: now.mono_ms(),
        };
        let growth = group.parity_growth(&held);
        if !charge(&mut self.held, &mut self.stats, growth) {
            // No room to hold it: `from` delivered it all the same, and is noted as a record
            // refused for room notes its sender, and it is pushed on unheld the first time it
            // comes (`piece`).
            if !first {
                return Vec::new();
            }
            return push(group, &me, &from, PARITY_STRIPE, now_ms, || {
                Message::Parity(Arc::clone(&parity))
            });
        }
        let before = group.bytes();
        group.hold_parity(held);
        settle(&mut self.held, before + growth, group.bytes());
        push(group, &me, &from, PARITY_STRIPE, now_ms, || {
            Message::Parity(Arc::clone(&parity))
        })
    }

    /// A member's receipt: kept (and flooded on) only when it reports its deliverer short of what
    /// a steady window owed, the first time it says so. Only a member of the trees' report is
    /// weighed, before its signature is checked, so a stranger's keys add nothing to the books.
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
        let Ok(child) = receipt.signer() else {
            return Vec::new();
        };
        if group.books.seen.contains_key(&hash)
            || !group.layout.contains(&child)
            || !in_window(content.first_second, now.judged(), group.deadlines)
            || receipt.verify().is_err()
        {
            return Vec::new();
        }
        if note_shortfall(
            (&mut self.reckoning, &mut self.stats),
            group,
            &child,
            &content,
            Some((hash, now)),
        ) {
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
                .books
                .answered
                .get(&from)
                .is_some_and(|at| at + ANSWER_INTERVAL_MS > now.mono_ms())
        {
            return Vec::new();
        }
        let bound = group.books.answered.growth();
        let answered = book(
            &mut self.reckoning,
            &mut self.stats,
            group,
            bound,
            |group| {
                group.books.answered.insert(from, now.mono_ms());
            },
        );
        if answered.is_none() {
            return Vec::new();
        }
        let group = &*group;
        let mut out = Vec::new();
        let mut budget = REPAIR_PAGE_BYTES;
        // `end_second` saturates, so the range is never backwards.
        let (first, end) = (have.first_second, have.end_second());
        if first >= end {
            return out;
        }
        for (second, by_hash) in group.books.manifests.range(first..end) {
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

    /// The timed duties: manifests and parity, rebuilds, receipt windows, receipts, judgments,
    /// repair, and forgetting what is past the horizon.
    ///
    /// Only the groups with something due are visited (`settle`), in key order, and each is
    /// scheduled again after: a group with nothing due at `now` would have done nothing.
    pub fn tick(&mut self, now: impl Into<Now>) -> Vec<Outgoing> {
        let now = now.into();
        let now_ms = now.judged().ms();
        let started = self.note_started(now);
        let me = self.me;
        let mut out = Vec::new();
        // Who would not answer an ask: the members this relay routes around as full, and those
        // it turned away while they may still route around it (their wait, and its slack:
        // `Deadlines::route_slack`), by `M`.
        let slack_ms = self.deadlines.route_slack.ms();
        let silent: BTreeSet<PublicKey> = self
            .full
            .iter()
            .copied()
            .chain(
                self.turned_away
                    .iter()
                    .filter(|(_, held)| {
                        held.last.is_some_and(|wait| {
                            now.mono_ms() < wait.until.mono_ms().saturating_add(slack_ms)
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
                        (&mut self.held, &mut self.reckoning, &mut self.stats),
                    ));
                }
                rebuild(
                    group,
                    now,
                    &mut self.held,
                    &mut self.delivered,
                    &mut self.stats,
                );
                if now.judging()
                    && let Some(started) = started
                {
                    schedule(group, now, started, (&mut self.reckoning, &mut self.stats));
                }
                if let Some(identity) = signing {
                    out.extend(receipts(
                        group,
                        identity,
                        &self.turned_away,
                        now,
                        (&mut self.reckoning, &mut self.stats),
                    ));
                }
                judge(
                    group,
                    now,
                    &mut self.demotions,
                    (&mut self.reckoning, &mut self.stats),
                );
                expire_demotions(group, now, (&mut self.reckoning, &mut self.stats));
                out.extend(assign(group, &me, now_ms));
                out.extend(repair(group, (&me, &silent), now, &mut self.stats));
                let (freed, freed_ledger) = forget(group, now);
                release(&mut self.held, freed);
                self.reckoning.settle(freed_ledger, &self.gauge);
                self.settle(key, now);
            }
        });
        self.reckoning.settle(0, &self.gauge);
        self.forget_turned_away(now);
        self.route(out, None, now_ms)
    }
}

/// `act` on `group`'s books, `bound` (the most it may add) charged to the reckoning first
/// ([`Reckoning`]) and what it did not add left to its next settling: `None`, nothing done and
/// counted (`Stats::unbooked`), when neither its floor nor the store has room for it.
fn book<T>(
    reckoning: &mut Reckoning,
    stats: &mut Stats,
    group: &mut Group,
    bound: usize,
    act: impl FnOnce(&mut Group) -> T,
) -> Option<T> {
    if !reckoning.grow(bound) {
        stats.unbooked += 1;
        return None;
    }
    let before = group.reckoning_bytes();
    let out = act(group);
    group.books.count();
    let after = group.reckoning_bytes();
    debug_assert!(
        after <= before + bound,
        "a group's books grew past their bound"
    );
    reckoning.bytes = (reckoning.bytes + after).saturating_sub(before);
    Some(out)
}

/// Lists an origin's manifest `hash` of `second` in `group`, and notes it seen, charged as a book
/// is ([`book`]): false when the store has no room.
fn list(
    reckoning: &mut Reckoning,
    stats: &mut Stats,
    group: &mut Group,
    (second, hash): (u64, Hash),
    listed: Listed,
    now: Now,
) -> bool {
    let manifests = &group.books.manifests;
    let bound = manifests.get(&second).map_or_else(
        || manifests.growth() + Tree::<Hash, Listed>::bytes_at(1),
        Tree::growth,
    ) + listed.bytes()
        + group.books.seen.growth();
    let listed_bytes = listed.bytes();
    let booked = book(reckoning, stats, group, bound, |group| {
        group.books.seen.insert(hash, now.mono_ms());
        group
            .books
            .manifests
            .entry(second)
            .or_default()
            .insert(hash, listed);
        group.books.listed_bytes += listed_bytes;
    });
    booked.is_some()
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

/// Notes a receipt from `child` that reports its deliverer short of what the window owed, in a
/// steady window, the first time it says so, charged to the books ([`book`]). True when it did
/// (and so travels to the group). `seen`: the receipt's hash, noted with it so a copy flooded back
/// is not weighed again.
fn note_shortfall(
    (reckoning, stats): (&mut Reckoning, &mut Stats),
    group: &mut Group,
    child: &PublicKey,
    content: &StripeReceiptContent,
    seen: Option<(Hash, Now)>,
) -> bool {
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
    let accused = (window, content.stripe, content.parent);
    if group
        .books
        .shortfalls
        .get(&accused)
        .is_some_and(|children| children.contains_key(child))
    {
        return false;
    }
    let books = &group.books;
    let bound = books.shortfalls.get(&accused).map_or_else(
        || books.shortfalls.growth() + Tree::<PublicKey, ()>::bytes_at(1),
        Tree::growth,
    ) + books.starved.growth()
        + books.seen.growth();
    book(reckoning, stats, group, bound, |group| {
        group
            .books
            .shortfalls
            .entry(accused)
            .or_default()
            .insert(*child, ());
        group
            .books
            .starved
            .insert((window, content.stripe, *child), ());
        if let Some((hash, now)) = seen {
            group.books.seen.insert(hash, now.mono_ms());
        }
    })
    .is_some()
}

/// An origin's duty after each second: sign the manifest of what it originated, flood it, and
/// send its parity down the parity stripe.
fn originate_manifests(
    group: &mut Group,
    identity: &impl Signs,
    now: Now,
    (held, reckoning, stats): (&mut Charge, &mut Reckoning, &mut Stats),
) -> Vec<Outgoing> {
    let now_ms = now.judged().ms();
    let me = identity.public();
    let due: Vec<u64> = group
        .books
        .own
        .iter()
        .filter(|(second, own)| {
            (*second + 1) * 1000 + MANIFEST_DELAY_MS <= now_ms
                || own.at_ms + 1000 + MANIFEST_DELAY_MS <= now.mono_ms()
        })
        .map(|(second, _)| *second)
        .collect();
    let mut out = Vec::new();
    for second in due {
        let before = group.reckoning_bytes();
        let Some(own) = group.books.own.remove(&second) else {
            continue;
        };
        group.books.count();
        reckoning.bytes -= before - group.reckoning_bytes();
        let hashes: Vec<Hash> = own.hashes.keys().copied().collect();
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
            // Listed here for repair and the receipts' reckoning only if the books have room; sent
            // either way, as what this relay sends is never the store's.
            let listed = Listed {
                manifest: manifest.clone(),
                origin: me,
                hashes: content.hashes,
                whole: false,
                kept_until: Listed::kept_until(now, group.deadlines),
            };
            list(reckoning, stats, group, (second, hash), listed, now);
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
                // way.
                let kept = HeldParity {
                    parity: Arc::clone(&parity),
                    at_ms: now.mono_ms(),
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
    let mut whole: Vec<(u64, Hash)> = Vec::new();
    for (second, by_hash) in group.books.manifests.iter() {
        if (second + 1) * 1000 + REBUILD_AFTER_MS > now_ms {
            break;
        }
        for (manifest, listed) in by_hash.iter() {
            if listed.whole {
                continue;
            }
            let missing: Vec<Hash> = listed
                .hashes
                .iter()
                .filter(|hash| !group.has(hash))
                .copied()
                .collect();
            let Some(first) = missing.first() else {
                whole.push((*second, *manifest));
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
    for (second, manifest) in whole {
        if let Some(listed) = group
            .books
            .manifests
            .get_mut(&second)
            .and_then(|by_hash| by_hash.get_mut(&manifest))
        {
            listed.whole = true;
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

/// Puts each receipt window `J` has newly passed the end of on this relay's own schedule
/// (`Due`): its receipts `receipt_grace` on by `M`, its judgment `judge_after` after those, and
/// who delivered what it lists kept until then (`Group::keep_listed`). Only a window a manifest
/// lists, and only while `J` judges (its caller's check), so a window is scheduled by a reading
/// of `J` the relay trusts. A window that began before this member first read its clock
/// (`started`: the relay restarted within it) is scheduled receipted: what was delivered before
/// the restart was never seen here, so a receipt for it would report its deliverer short.
fn schedule(
    group: &mut Group,
    now: Now,
    started: Judged,
    (reckoning, stats): (&mut Reckoning, &mut Stats),
) {
    let now_ms = now.judged().ms();
    let ended: Vec<u64> = group
        .books
        .manifests
        .keys()
        .map(|second| second / RECEIPT_WINDOW_SECONDS)
        .filter(|window| {
            (window + 1) * RECEIPT_WINDOW_SECONDS * 1000 <= now_ms
                && !group.books.windows.contains_key(window)
        })
        .collect::<BTreeSet<u64>>()
        .into_iter()
        .collect();
    let deadlines = group.deadlines;
    for window in ended {
        let receipt = now.after(deadlines.receipt_grace.ms());
        let due = Due {
            ended: now.after(0),
            receipt,
            judge: now.after(deadlines.receipt_grace.ms() + deadlines.judge_after.ms()),
            receipted: window * RECEIPT_WINDOW_SECONDS * 1000 < started.ms(),
            judged: false,
        };
        let bound = group.books.windows.growth();
        if book(reckoning, stats, group, bound, |group| {
            group.books.windows.insert(window, due);
        })
        .is_some()
        {
            group.keep_listed(window, due.judge);
        }
    }
}

/// When each window's receipt deadline passes on `M` (`Due::receipt`): a receipt per stripe for
/// each deliverer that owed this relay something, sent to the deliverer, and to the group when it
/// was short.
///
/// Routing around (RFC-0174 §2.5, "A relay's members are bounded") is no shortfall on either side:
/// a deliverer this relay turned away as full while it owed the window (`turned_away`, the window
/// and its grace as they fell on `M`, `Due::on_mono`) is owed nothing and gets no receipt, since
/// it was sending its slice past this relay by the wait both keep; and when what the parent owed
/// came first from above it in the stripe's tree (or from its origin) before it could have been a
/// repair, the parent was being routed around: each who delivered past it is signed a receipt for
/// what it delivered, which no member reads as short (it is not this relay's parent, so it owed
/// this relay nothing), and no shortfall is filed against the parent, which is signed its receipt
/// only if it delivered the rest itself.
fn receipts(
    group: &mut Group,
    identity: &impl Signs,
    turned_away: &Tree<PublicKey, TurnedAway>,
    now: Now,
    (reckoning, stats): (&mut Reckoning, &mut Stats),
) -> Vec<Outgoing> {
    let now_ms = now.judged().ms();
    let me = identity.public();
    let deadlines = group.deadlines;
    let windows: Vec<(u64, Due)> = group
        .books
        .windows
        .iter()
        .filter(|(_, due)| !due.receipted && due.receipt.passed(now))
        .map(|(window, due)| (*window, *due))
        .collect();
    let mut out = Vec::new();
    for (window, due) in windows {
        if let Some(due) = group.books.windows.get_mut(&window) {
            due.receipted = true;
        }
        let first = window * RECEIPT_WINDOW_SECONDS;
        let epoch = epoch_of(first);
        let (from_ms, to_ms) = due.on_mono();
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
                if turned_away
                    .get(&deliverer)
                    .is_some_and(|turned| turned.during(from_ms, to_ms, deadlines.route_slack.ms()))
                {
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
                if note_shortfall(
                    (&mut *reckoning, &mut *stats),
                    group,
                    &me,
                    &content,
                    Some((receipt.hash(), now)),
                ) {
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
/// This relay's signed receipt to `deliverer` for `hashes` (what it delivered) of a window's
/// stripe, and what it says: their bytes as the ledger noted them, held here or not.
fn sign_receipt(
    group: &Group,
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
    Some((receipt, content))
}

/// When each receipted window's judgment falls due on `M` (`Due::judge`): demotes a member most of
/// whose children in a stripe reported it short for a window it was not itself starved in.
fn judge(
    group: &mut Group,
    now: Now,
    demotions: &mut Vec<(GroupKey, PublicKey, MonoDeadline)>,
    (reckoning, stats): (&mut Reckoning, &mut Stats),
) {
    let due: Vec<u64> = group
        .books
        .windows
        .iter()
        .filter(|(_, due)| due.receipted && !due.judged && due.judge.passed(now))
        .map(|(window, _)| *window)
        .collect();
    for window in due {
        if let Some(due) = group.books.windows.get_mut(&window) {
            due.judged = true;
        }
        if !group.steady(window) {
            continue;
        }
        stats.judged += 1;
        let epoch = epoch_of(window * RECEIPT_WINDOW_SECONDS);
        let accused: Vec<(u8, PublicKey, BTreeSet<PublicKey>)> = group
            .books
            .shortfalls
            .iter()
            .filter(|((w, _, _), _)| *w == window)
            .map(|((_, stripe, deliverer), children)| {
                (*stripe, *deliverer, children.keys().copied().collect())
            })
            .collect();
        let mut demoted = false;
        for (stripe, deliverer, reporters) in accused {
            if group.demoted.contains_key(&deliverer)
                || group
                    .books
                    .starved
                    .contains_key(&(window, stripe, deliverer))
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
            demoted = true;
        }
        if demoted {
            relayout(group, now, (&mut *reckoning, &mut *stats));
        }
    }
}

/// Lays `group`'s trees out again, the change it notes charged to the books ([`book`]): past their
/// room the trees are laid out all the same, and the change goes unnoted, counted, so a window
/// over it may be judged as steady.
fn relayout(group: &mut Group, now: Now, (reckoning, stats): (&mut Reckoning, &mut Stats)) {
    let bound = group.relayout_growth();
    if book(reckoning, stats, group, bound, |group| group.relayout(now)).is_none() {
        let changed = std::mem::take(&mut group.books.changed);
        group.relayout(now);
        group.books.changed = changed;
        group.books.count();
    }
}

fn expire_demotions(group: &mut Group, now: Now, (reckoning, stats): (&mut Reckoning, &mut Stats)) {
    let before = group.demoted.len();
    group.demoted.retain(|_, until| !until.passed(now));
    if group.demoted.len() != before {
        relayout(group, now, (reckoning, stats));
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
        .books
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

/// Forgets what is past the horizon. The bytes it let go: from the store (records, parities and
/// books) and from the ledger.
///
/// What the group holds (records, records awaiting judgment, parities) and the hashes it took in
/// or refused are let go by `M`, a horizon after they came: how long the relay keeps a possessed
/// thing is a duration, and its store is planned on it (`budget::Store::Batches`), so a step of
/// `J` either way keeps nothing past its plan. Who delivered what is let go when its window has
/// been judged (`Noted::kept_until`, put on `M` when `J` passed the window's end), or a horizon
/// after it came when no manifest lists it. What is indexed by signed second (the manifests, the
/// relay's own records not yet in one, the receipt windows, the shortfalls) is let go by `J`: no
/// copy enters it outside the seconds `J` admits (`in_window`), so a step holds at most one
/// horizon's seconds beside the new; a manifest let go before its window was scheduled releases
/// what the ledger kept for it.
fn forget(group: &mut Group, now: Now) -> (usize, usize) {
    let horizon_seconds = group.deadlines.horizon_seconds();
    let horizon_ms = horizon_seconds * 1000;
    let horizon_second = now.judged().ms().saturating_sub(horizon_ms) / 1000;
    let horizon_window = horizon_second / RECEIPT_WINDOW_SECONDS;
    let kept_from_ms = now.mono_ms().saturating_sub(horizon_ms);
    let before = group.bytes();
    let reckoned = group.reckoning_bytes();
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
    group.parked.retain(|_, parked| {
        let keep = parked.held.at_ms >= kept_from_ms;
        if !keep {
            freed += parked.held.bytes();
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
    group.entries_bytes -= freed;
    let mut gone: Vec<Listed> = Vec::new();
    let mut kept = group.books.manifests.split_off(&horizon_second);
    gone.extend(
        group
            .books
            .manifests
            .take()
            .into_values()
            .flat_map(|mut by_hash| by_hash.take().into_values()),
    );
    let lapsed: Vec<(u64, Hash)> = kept
        .iter()
        .flat_map(|(second, by_hash)| {
            by_hash
                .iter()
                .filter(|(_, listed)| listed.kept_until.passed(now))
                .map(|(hash, _)| (*second, *hash))
        })
        .collect();
    for (second, hash) in lapsed {
        if let Some(by_hash) = kept.get_mut(&second) {
            gone.extend(by_hash.remove(&hash));
            if by_hash.is_empty() {
                kept.remove(&second);
            }
        }
    }
    group.books.manifests = kept;
    let now_due = now.after(0);
    for listed in &gone {
        group.books.listed_bytes -= listed.bytes();
        for hash in
            std::iter::once(id_of(&listed.manifest.hash())).chain(listed.hashes.iter().copied())
        {
            if let Some(noted) = group.ledger.get_mut(&hash)
                && noted.kept_until == MonoDeadline::NEVER
            {
                noted.kept_until = now_due;
            }
        }
    }
    drop(gone);
    group.books.own = group.books.own.split_off(&horizon_second);
    group.books.seen.retain(|_, at| *at >= kept_from_ms);
    group.books.refused.retain(|_, at| *at >= kept_from_ms);
    group
        .books
        .answered
        .retain(|_, at| *at + ANSWER_INTERVAL_MS > now.mono_ms());
    // A window is kept while a manifest lists it or its judgment is still to come (by `M`, `Due`),
    // and
    // what was reported of it as long as the window or its manifests are.
    let listed: BTreeSet<u64> = group
        .books
        .manifests
        .keys()
        .map(|second| second / RECEIPT_WINDOW_SECONDS)
        .collect();
    group.books.windows = group.books.windows.split_off(&horizon_window);
    group
        .books
        .windows
        .retain(|window, due| listed.contains(window) || !(due.judged || due.judge.passed(now)));
    let windows = &group.books.windows;
    let reported = |window: &u64| listed.contains(window) || windows.contains_key(window);
    group
        .books
        .shortfalls
        .retain(|(window, _, _), _| *window >= horizon_window && reported(window));
    group
        .books
        .starved
        .retain(|(window, _, _), ()| *window >= horizon_window && reported(window));
    group
        .books
        .changed
        .retain(|(_, mono)| *mono + 2 * horizon_ms >= now.mono_ms());
    if group.books.changed.is_empty() {
        group.books.changed = Vec::new();
    }
    group.books.count();
    let freed = before - group.bytes();
    let mut ledger_freed = 0;
    group.ledger.retain(|_, noted| {
        let keep = !noted.kept_until.passed(now);
        if !keep {
            ledger_freed += senders_bytes(noted.from.capacity());
        }
        keep
    });
    group.ledger_entries -= ledger_freed;
    (freed, reckoned - group.reckoning_bytes())
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
