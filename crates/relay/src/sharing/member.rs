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
//!   others and the parity, and forwards them on as if they had arrived, so losing a parent costs
//!   one stripe only until the parity comes.
//! - **Repair (lazy).** A member still missing records asks a rotating member with its
//!   `HaveSummary` (which seconds it holds whole); the answer is the manifests and records of the
//!   seconds it lacks, paged. Repaired records are pushed on too (Plumtree's graft).
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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tally_wire::batch::Hash;
use tally_wire::record::{KIND_BATCH, KIND_RELAY_BATCH};
use tally_wire::sharing::{MAX_HAVE_SECONDS, MAX_PIECES, receipt_digest};
use tally_wire::{
    Batch, Bytes, Check, HaveSummary, Identity, ParityChunk, PieceManifest, PieceManifestContent,
    PublicKey, Record, StripeAssignment, StripeReceipt, StripeReceiptContent,
};

use crate::budget::{Charge, Gauge};
use crate::directory::CLOCK_SKEW_MS;

use super::full::Wait;
use super::groups::{DEMOTION_MS, GroupKey};
use super::parity::{Parity, id_of};
use super::seeds::{SEED_ROTATION_SECONDS, epoch_of};
use super::stripes::{DATA_STRIPES, Layout, PARITY_STRIPE, STRIPES, data_stripe, score};

/// After a second ends, how long an origin waits before signing its manifest and parity.
pub const MANIFEST_DELAY_MS: u64 = 200;
/// After a second ends, when a member first tries to rebuild a stripe it lacks from parity.
pub const REBUILD_AFTER_MS: u64 = 700;
/// After a second ends, when a member first asks another for what it still lacks.
pub const REPAIR_AFTER_MS: u64 = 1_500;
/// The least time between two asks for repair in one group.
pub const REPAIR_INTERVAL_MS: u64 = 500;
/// How often a member compares holdings with another even with nothing known missing, so a
/// manifest that never arrived is found.
pub const ANTI_ENTROPY_MS: u64 = 5_000;
/// The seconds one receipt covers. Divides `SEED_ROTATION_SECONDS`, so rotations fall between
/// windows.
pub const RECEIPT_WINDOW_SECONDS: u64 = 5;
/// After a window ends, how long a child waits (for rebuilds and repairs to arrive from its
/// parent) before signing its receipts.
pub const RECEIPT_GRACE_MS: u64 = 4_000;
/// After the receipts of a window, how long before the group judges it.
pub const JUDGE_AFTER_MS: u64 = 2_000;
/// How far back a member holds records and manifests: as long as its own duties need them, and no
/// longer. A record of a window's first second is owed in that window's receipts, signed
/// `RECEIPT_GRACE_MS` after the window ends, judged `JUDGE_AFTER_MS` after that, and a member short
/// of it asks for repair from `REPAIR_AFTER_MS` on; so the horizon is the window, the grace, the
/// judgment and the repair delay, 12.5 s, rounded up to whole seconds. It is the one batch byte
/// store's window (RFC-0181 §6): what a relay holds of a batch's bytes after it is passed on.
pub const HORIZON_MS: u64 =
    RECEIPT_WINDOW_SECONDS * 1000 + RECEIPT_GRACE_MS + JUDGE_AFTER_MS + REPAIR_AFTER_MS;
pub const HORIZON_SECONDS: u64 = HORIZON_MS.div_ceil(1000);
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
/// How far past this relay's clock a signed second may be (a manifest's, a parity's, a receipt's
/// window): the directory's allowance for clocks that differ. Anything later is refused, so what
/// is held is bounded by the horizon behind and this ahead, and `forget` bounds memory.
pub const SKEW_SECONDS: u64 = CLOCK_SKEW_MS / 1000;

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

/// What a group holds for one record beside its signed bytes: its entry by hash and the shared
/// batch it names ([`Piece::held_len`]).
pub const PIECE_ENTRY_BYTES: usize = std::mem::size_of::<(Hash, Held)>()
    + tally_wire::decoded::ARC_HEADER
    + std::mem::size_of::<Batch>();

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
                Some(Self::Encoded(Bytes::from(bytes)))
            }
        }
    }

    /// The piece of one encoded record (what parity rebuilds), a batch's body kept in place.
    /// `None` for bytes that are not one record.
    pub fn from_encoded(bytes: Vec<u8>) -> Option<Self> {
        let (_, used) = Record::decode(&bytes).ok()?;
        if used != bytes.len() || bytes.len() < HEADER_LEN {
            return None;
        }
        let kind = bytes[0];
        let bytes = Bytes::from(bytes);
        match kind {
            KIND_BATCH => Batch::from_bytes(bytes.slice(HEADER_LEN..))
                .ok()
                .map(|batch| Self::Batch(Arc::new(batch))),
            KIND_RELAY_BATCH => Batch::from_bytes(bytes.slice(HEADER_LEN..))
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

    /// What holding it allocates, as the groups are charged for it (`budget::Store::Batches`):
    /// a batch kept at ingest, whose signed bytes carry their own charge for their life
    /// (`Batch::owned_by`, `budget::Store::Decoded`), only its place ([`PIECE_ENTRY_BYTES`]); any
    /// other piece its encoded bytes, which are its own. Before, every batch was charged its bytes
    /// here and again in its decode, in the epochs and in each subscriber's queue.
    pub fn held_len(&self) -> usize {
        match self {
            Self::Batch(batch) | Self::RelayBatch(batch) if batch.is_owned() => PIECE_ENTRY_BYTES,
            _ => self.len(),
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
    /// A record of a group's product, by its hash.
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
    /// Records rebuilt from parity.
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
}

struct Held {
    piece: Piece,
    at_ms: u64,
    /// Who sent it, and when, in order; empty for one this relay originated or rebuilt.
    from: Vec<(PublicKey, u64)>,
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
    /// merged with every span it touches, counting the slack, which covers the same moments. A
    /// refusal comes after the last as a rule, so this is a merge into the last span or a push.
    fn add(&mut self, start_ms: u64, end_ms: u64) {
        let at = self.spans.partition_point(|(start, _)| *start <= start_ms);
        self.spans.insert(at, (start_ms, end_ms));
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.spans.len());
        for (start, end) in self.spans.drain(..) {
            match merged.last_mut() {
                Some((_, last)) if start <= last.saturating_add(ROUTE_SLACK_MS) => {
                    *last = (*last).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        self.spans = merged;
    }

    /// Whether it was routing around this relay at any time from `from_ms` to `to_ms`.
    fn during(&self, from_ms: u64, to_ms: u64) -> bool {
        // The spans are apart and in order, so their ends are too: the first that reaches
        // `from_ms` is the only one that may.
        let first = self
            .spans
            .partition_point(|(_, end)| end.saturating_add(ROUTE_SLACK_MS) < from_ms);
        self.spans
            .get(first)
            .is_some_and(|(start, _)| *start <= to_ms)
    }
}

/// How long past a refusal's wait the relay refused may still be routing around this one: its
/// wait starts when the `Goodbye` reaches it, a link's latency after this relay sent it.
const ROUTE_SLACK_MS: u64 = 1_000;
/// The longest record a group carries, encoded: what one record adds to a parity slice at most.
const MAX_PIECE_LEN: usize = HEADER_LEN + tally_wire::record::MAX_BODY;

struct HeldParity {
    parity: Arc<Parity>,
    at_ms: u64,
    from: Vec<(PublicKey, u64)>,
}

struct Group {
    key: GroupKey,
    /// When the tick next visits it (`Member::settle`), if ever.
    due_ms: Option<u64>,
    members: Vec<PublicKey>,
    leaves_only: Vec<PublicKey>,
    demoted: BTreeMap<PublicKey, u64>,
    layout: Layout,
    /// When the trees last changed, newest last.
    changed_ms: Vec<u64>,
    pieces: BTreeMap<Hash, Held>,
    /// The bytes it holds, kept as they change: the encoded bytes of `pieces` and the bytes of
    /// `parity` (`Parity::len`), each charged to the member's gauge before it is held.
    bytes: usize,
    /// By second, then by the manifest's hash.
    manifests: BTreeMap<u64, BTreeMap<Hash, Listed>>,
    parity: BTreeMap<Hash, HeldParity>,
    /// What this relay originated, by second, not yet in a manifest.
    own: BTreeMap<u64, BTreeSet<Hash>>,
    /// Manifests and receipts already taken in, by hash, with when.
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
    /// When each member's `HaveSummary` was last answered.
    answered: BTreeMap<PublicKey, u64>,
    /// The stripes asked of each parent, as last sent.
    assigned: BTreeMap<PublicKey, u32>,
    assigned_epoch: Option<u64>,
}

impl Group {
    fn new(key: GroupKey, me: PublicKey) -> Self {
        Self {
            key,
            due_ms: None,
            members: vec![me],
            leaves_only: Vec::new(),
            demoted: BTreeMap::new(),
            layout: Layout::new(key.cell, key.product, &[me], &[]),
            changed_ms: Vec::new(),
            pieces: BTreeMap::new(),
            bytes: 0,
            manifests: BTreeMap::new(),
            parity: BTreeMap::new(),
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
        let to = end * 1000 + RECEIPT_GRACE_MS;
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

    /// Who delivered `hash` (a record or a parity id), in order.
    fn senders(&self, hash: &Hash) -> &[(PublicKey, u64)] {
        self.pieces
            .get(hash)
            .map(|held| held.from.as_slice())
            .or_else(|| self.parity.get(hash).map(|held| held.from.as_slice()))
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
            by_hash.values().all(|listed| {
                listed.whole || listed.hashes.iter().all(|h| self.pieces.contains_key(h))
            })
        })
    }

    /// Holds a piece, counting its bytes, which its caller has charged (`Member::charge`).
    fn hold(&mut self, hash: Hash, piece: Piece, at_ms: u64, from: Vec<(PublicKey, u64)>) {
        self.bytes += piece.held_len();
        self.pieces.insert(hash, Held { piece, at_ms, from });
    }

    /// Holds a parity, counting its bytes, which its caller has charged.
    fn hold_parity(&mut self, held: HeldParity) {
        self.bytes += held.parity.len();
        self.parity.insert(held.parity.id(), held);
    }

    /// Lets a parity go. The bytes it let go.
    fn drop_parity(&mut self, id: &Hash) -> usize {
        let freed = self.parity.remove(id).map_or(0, |held| held.parity.len());
        self.bytes -= freed;
        freed
    }

    /// Whether it holds anything within the horizon: then every tick has duties for it
    /// (manifests, rebuilds, receipts, judgment, repair, forgetting).
    fn busy(&self) -> bool {
        !(self.pieces.is_empty()
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
    /// a demotion's end, forgetting what it remembers of the trees); never when it has none.
    fn wake_ms(&self, me: &PublicKey, now_ms: u64) -> Option<u64> {
        if self.busy() {
            return Some(now_ms);
        }
        let mut wake = u64::MAX;
        let others = self.layout.members().iter().any(|member| member != me);
        if others || !self.assigned.is_empty() {
            let epoch = epoch_of(now_ms / 1000);
            wake = wake.min((epoch + 1) * SEED_ROTATION_SECONDS * 1000);
        }
        if others {
            wake = wake.min(self.repair_at_ms.max(self.anti_entropy_at_ms));
        }
        if let Some(until) = self.demoted.values().min() {
            wake = wake.min(*until);
        }
        if let Some(changed) = self.changed_ms.iter().min() {
            wake = wake.min(changed + 2 * HORIZON_SECONDS * 1000 + 1);
        }
        if let Some(at) = self.answered.values().min() {
            wake = wake.min(at + ANSWER_INTERVAL_MS);
        }
        (wake != u64::MAX).then_some(wake.max(now_ms))
    }
}

/// This relay's part in all of its groups.
pub struct Member {
    identity: Identity,
    me: PublicKey,
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
    /// (`turned_away`): no shortfall is filed against one for those windows.
    turned_away: BTreeMap<PublicKey, TurnedAway>,
    /// Groups the tick has visited since start: the work it did, which follows what the groups
    /// hold and never how many areas the relay takes.
    visits: u64,
    delivered: Vec<Delivered>,
    demotions: Vec<(GroupKey, PublicKey, u64)>,
    stats: Stats,
}

impl Member {
    /// A member whose groups hold what `gauge` (the budget's `Store::Batches`) takes.
    pub fn new(identity: Identity, gauge: Arc<Gauge>) -> Self {
        let me = identity.public();
        Self {
            identity,
            me,
            groups: BTreeMap::new(),
            due: BTreeSet::new(),
            held: gauge.empty(),
            gauge,
            full: BTreeSet::new(),
            turned_away: BTreeMap::new(),
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
        self.held = moved;
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
    pub fn turned_away(&mut self, key: PublicKey, asked: std::time::Duration, now_ms: u64) {
        let held = self.turned_away.entry(key).or_default();
        let wait = Wait::after(held.last, asked, now_ms);
        held.last = Some(wait);
        held.add(now_ms, wait.until_ms);
    }

    /// The spans this relay holds of `key` routing around it (`turned_away`).
    #[cfg(test)]
    pub fn turned_away_spans(&self, key: &PublicKey) -> usize {
        self.turned_away.get(key).map_or(0, |held| held.spans.len())
    }

    /// Whether this relay turned `key` away and it was routing around this relay at any time from
    /// `from_ms` to `to_ms`.
    pub fn routed_around_by(&self, key: &PublicKey, from_ms: u64, to_ms: u64) -> bool {
        self.turned_away
            .get(key)
            .is_some_and(|held| held.during(from_ms, to_ms))
    }

    /// Forgets the refusals no window still to be receipted can overlap, and the waits that no
    /// longer double the next.
    fn forget_turned_away(&mut self, now_ms: u64) {
        let horizon_ms = now_ms.saturating_sub(2 * HORIZON_MS);
        self.turned_away.retain(|_, held| {
            held.spans
                .retain(|(_, end)| end.saturating_add(ROUTE_SLACK_MS) >= horizon_ms);
            !held.spans.is_empty() || held.last.is_some_and(|wait| wait.remembered(now_ms))
        });
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

    /// The bytes its groups hold, by each group's own count (kept apart from the charge, as
    /// records and parities come and go): what its gauge reads.
    pub fn group_bytes(&self) -> usize {
        self.groups.values().map(|group| group.bytes).sum()
    }

    /// The bytes its groups hold, counted afresh from every record and parity in them: what its
    /// gauge must read.
    #[cfg(test)]
    pub fn counted_bytes(&self) -> usize {
        self.groups
            .values()
            .map(|group| {
                group
                    .pieces
                    .values()
                    .map(|held| held.piece.held_len())
                    .sum::<usize>()
                    + group
                        .parity
                        .values()
                        .map(|held| held.parity.len())
                        .sum::<usize>()
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
        let me = self.me;
        self.groups
            .entry(group)
            .or_insert_with(|| Group::new(group, me));
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

    pub fn holds(&self, group: GroupKey, hash: &Hash) -> bool {
        self.groups
            .get(&group)
            .is_some_and(|group| group.pieces.contains_key(hash))
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
    pub fn take_demotions(&mut self) -> Vec<(GroupKey, PublicKey, u64)> {
        std::mem::take(&mut self.demotions)
    }

    /// The group's members as `groups` holds them (this relay is always one).
    pub fn set_members(
        &mut self,
        key: GroupKey,
        members: &[PublicKey],
        leaves_only: &[PublicKey],
        now_ms: u64,
    ) -> Vec<Outgoing> {
        let me = self.me;
        let group = self
            .groups
            .entry(key)
            .or_insert_with(|| Group::new(key, me));
        let mut members = members.to_vec();
        members.push(me);
        members.sort();
        members.dedup();
        group.members = members;
        group.leaves_only = leaves_only.to_vec();
        group.relayout(now_ms);
        let out = assign(group, &me, now_ms);
        self.settle(key, now_ms);
        self.route(out, None, now_ms)
    }

    /// Leaves a group (the relay no longer takes its cell).
    pub fn leave(&mut self, key: GroupKey) {
        if let Some(group) = self.groups.remove(&key) {
            release(&mut self.held, group.bytes);
            if let Some(at) = group.due_ms {
                self.due.remove(&(at, key));
            }
        }
    }

    /// Schedules `key` for when the tick next has something to do for it, or lets it go when it
    /// is this relay alone with nothing.
    fn settle(&mut self, key: GroupKey, now_ms: u64) {
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
        if let Some(at) = group.wake_ms(&me, now_ms) {
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
        now_ms: u64,
    ) -> Vec<Outgoing> {
        let me = self.me;
        let held = self
            .groups
            .get(&key)
            .is_some_and(|group| group.pieces.contains_key(&hash));
        if !held && !self.charge(piece.held_len()) {
            return Vec::new();
        }
        let group = self
            .groups
            .entry(key)
            .or_insert_with(|| Group::new(key, me));
        group.own.entry(now_ms / 1000).or_default().insert(hash);
        if held {
            self.settle(key, now_ms);
            return Vec::new();
        }
        group.hold(hash, piece.clone(), now_ms, Vec::new());
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
        self.settle(key, now_ms);
        self.route(out, None, now_ms)
    }

    /// A message from another relay.
    pub fn receive(&mut self, from: PublicKey, message: Message, now_ms: u64) -> Vec<Outgoing> {
        let key = message.group();
        let out = match message {
            Message::Piece { group, hash, piece } => self.piece(from, group, hash, piece, now_ms),
            Message::Manifest(manifest) => self.manifest(from, manifest, now_ms),
            Message::Parity(parity) => self.parity(from, parity, now_ms),
            Message::Receipt(receipt) => self.receipt(from, receipt, now_ms),
            Message::Have(have) => self.have(from, &have, now_ms),
            Message::Assign(_) => Vec::new(),
        };
        if let Some(key) = key {
            self.settle(key, now_ms);
        }
        self.route(out, Some(&from), now_ms)
    }

    fn piece(
        &mut self,
        from: PublicKey,
        key: GroupKey,
        hash: Hash,
        piece: Piece,
        now_ms: u64,
    ) -> Vec<Outgoing> {
        let me = self.me;
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        if let Some(held) = group.pieces.get_mut(&hash) {
            if !held.from.iter().any(|(sender, _)| *sender == from) {
                held.from.push((from, now_ms));
            }
            self.stats.duplicates += 1;
            return Vec::new();
        }
        if piece.hash() != Some(hash) || !self.charge(piece.held_len()) {
            return Vec::new();
        }
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        let parent = group
            .layout
            .place(data_stripe(&hash), epoch_of(now_ms / 1000), &me)
            .and_then(|place| place.parent);
        if parent.is_some_and(|parent| parent != from) {
            self.stats.repaired += 1;
        }
        group.hold(hash, piece.clone(), now_ms, vec![(from, now_ms)]);
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

    fn manifest(&mut self, from: PublicKey, manifest: PieceManifest, now_ms: u64) -> Vec<Outgoing> {
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
            || !in_window(content.second, now_ms)
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
        group.seen.insert(hash, now_ms);
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

    fn parity(&mut self, from: PublicKey, parity: Arc<Parity>, now_ms: u64) -> Vec<Outgoing> {
        let me = self.me;
        let key = GroupKey::new(parity.cell, parity.product);
        let Some(group) = self.groups.get_mut(&key) else {
            return Vec::new();
        };
        let id = parity.id();
        if let Some(held) = group.parity.get_mut(&id) {
            if !held.from.iter().any(|(sender, _)| *sender == from) {
                held.from.push((from, now_ms));
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
        if !listed
            || !in_window(parity.second, now_ms)
            || !charge(&mut self.held, &mut self.stats, parity.len())
        {
            return Vec::new();
        }
        group.hold_parity(HeldParity {
            parity: Arc::clone(&parity),
            at_ms: now_ms,
            from: vec![(from, now_ms)],
        });
        push(group, &me, &from, PARITY_STRIPE, now_ms, || {
            Message::Parity(Arc::clone(&parity))
        })
    }

    fn receipt(&mut self, from: PublicKey, receipt: StripeReceipt, now_ms: u64) -> Vec<Outgoing> {
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
            || !in_window(content.first_second, now_ms)
            || receipt.verify().is_err()
        {
            return Vec::new();
        }
        let Ok(child) = receipt.signer() else {
            return Vec::new();
        };
        group.seen.insert(hash, now_ms);
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
    fn have(&mut self, from: PublicKey, have: &HaveSummary, now_ms: u64) -> Vec<Outgoing> {
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
                .is_some_and(|at| at + ANSWER_INTERVAL_MS > now_ms)
        {
            return Vec::new();
        }
        group.answered.insert(from, now_ms);
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
    pub fn tick(&mut self, now_ms: u64) -> Vec<Outgoing> {
        let me = self.me;
        let mut out = Vec::new();
        let mut keys: Vec<GroupKey> = self
            .due
            .iter()
            .take_while(|(at, _)| *at <= now_ms)
            .map(|(_, key)| *key)
            .collect();
        keys.sort();
        for key in keys {
            let Some(group) = self.groups.get_mut(&key) else {
                continue;
            };
            self.visits += 1;
            out.extend(originate_manifests(
                group,
                &self.identity,
                now_ms,
                (&mut self.held, &mut self.stats),
            ));
            out.extend(rebuild(
                group,
                &me,
                now_ms,
                &mut self.held,
                &mut self.delivered,
                &mut self.stats,
            ));
            out.extend(receipts(
                group,
                &self.identity,
                &self.turned_away,
                now_ms,
                &mut self.stats,
            ));
            judge(group, now_ms, &mut self.demotions, &mut self.stats);
            expire_demotions(group, now_ms);
            out.extend(assign(group, &me, now_ms));
            out.extend(repair(group, &me, now_ms, &mut self.stats));
            release(&mut self.held, forget(group, now_ms));
            self.settle(key, now_ms);
        }
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
    identity: &Identity,
    now_ms: u64,
    (held, stats): (&mut Charge, &mut Stats),
) -> Vec<Outgoing> {
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
            group.seen.insert(hash, now_ms);
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
                if charge(held, stats, parity.len()) {
                    group.hold_parity(HeldParity {
                        parity: Arc::clone(&parity),
                        at_ms: now_ms,
                        from: Vec::new(),
                    });
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

/// Rebuilds, from parity, a manifest's records when all it lacks are in one data stripe, and
/// pushes them on down that stripe. Parity is unsigned, so it is checked here against the
/// manifest's own hashes: with every other stripe held, a true parity rebuilds exactly the records
/// missing, so one that rebuilds anything else (or nothing) is false and is dropped, and the next
/// parity for the manifest that arrives is taken in its place. What it rebuilt that matches the
/// manifest is kept either way: a record is checked by its own hash.
fn rebuild(
    group: &mut Group,
    me: &PublicKey,
    now_ms: u64,
    held: &mut Charge,
    delivered: &mut Vec<Delivered>,
    stats: &mut Stats,
) -> Vec<Outgoing> {
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
                .filter(|hash| !group.pieces.contains_key(*hash))
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
            let mut matched = BTreeSet::new();
            let mut extra = false;
            for bytes in held.parity.rebuild(stripe, &others).unwrap_or_default() {
                let piece = Piece::from_encoded(bytes);
                match piece.as_ref().and_then(Piece::hash) {
                    Some(hash) if missing.contains(&hash) && matched.insert(hash) => {
                        if let Some(piece) = piece {
                            found.push((hash, piece));
                        }
                    }
                    _ => extra = true,
                }
            }
            if extra || matched.len() != missing.len() {
                false_parity.push(id);
            }
        }
    }
    for id in false_parity {
        release(held, group.drop_parity(&id));
    }
    let mut out = Vec::new();
    for (hash, piece) in found {
        if group.pieces.contains_key(&hash) {
            continue;
        }
        if !charge(held, stats, piece.held_len()) {
            continue;
        }
        group.hold(hash, piece.clone(), now_ms, Vec::new());
        stats.rebuilt += 1;
        delivered.push(Delivered {
            group: group.key,
            hash,
            piece: piece.clone(),
            arrival: Arrival::Rebuilt,
        });
        let key = group.key;
        out.extend(push(group, me, me, data_stripe(&hash), now_ms, || {
            Message::Piece {
                group: key,
                hash,
                piece: piece.clone(),
            }
        }));
    }
    out
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
    identity: &Identity,
    turned_away: &BTreeMap<PublicKey, TurnedAway>,
    now_ms: u64,
    stats: &mut Stats,
) -> Vec<Outgoing> {
    let me = identity.public();
    let windows: BTreeSet<u64> = group
        .manifests
        .keys()
        .map(|second| second / RECEIPT_WINDOW_SECONDS)
        .filter(|window| {
            (window + 1) * RECEIPT_WINDOW_SECONDS * 1000 + RECEIPT_GRACE_MS <= now_ms
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
                if turned_away
                    .get(&deliverer)
                    .is_some_and(|held| held.during(first * 1000, end * 1000 + RECEIPT_GRACE_MS))
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
                        sign_receipt(group, identity, (router, stripe, first), &got, now_ms)
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
                    sign_receipt(group, identity, (deliverer, stripe, first), &got, now_ms)
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
/// tree, or from the record's origin, before its second settled (`REPAIR_AFTER_MS` after it
/// ended: no repair is asked for a second before then, so what came sooner was pushed down the
/// tree, past a parent that was full to the one that pushed it), and before the parent's own copy
/// if it sent one.
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
        let before_ms = parent_at.min((listed.second + 1) * 1000 + REPAIR_AFTER_MS);
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
    identity: &Identity,
    (deliverer, stripe, first): (PublicKey, u8, u64),
    hashes: &[Hash],
    now_ms: u64,
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
        issued_ms: now_ms,
    };
    let receipt = StripeReceipt::sign(identity, &content).ok()?;
    group.seen.insert(receipt.hash(), now_ms);
    Some((receipt, content))
}

/// Demotes a member most of whose children in a stripe reported it short for a window it was not
/// itself starved in.
fn judge(
    group: &mut Group,
    now_ms: u64,
    demotions: &mut Vec<(GroupKey, PublicKey, u64)>,
    stats: &mut Stats,
) {
    let due: Vec<u64> = group
        .receipted
        .iter()
        .copied()
        .filter(|window| {
            (window + 1) * RECEIPT_WINDOW_SECONDS * 1000 + RECEIPT_GRACE_MS + JUDGE_AFTER_MS
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
            let until = now_ms + DEMOTION_MS;
            group.demoted.insert(deliverer, until);
            demotions.push((group.key, deliverer, until));
        }
        group.relayout(now_ms);
    }
}

fn expire_demotions(group: &mut Group, now_ms: u64) {
    let before = group.demoted.len();
    group.demoted.retain(|_, until| *until > now_ms);
    if group.demoted.len() != before {
        group.relayout(now_ms);
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
/// particular, so a lost manifest is found).
fn repair(group: &mut Group, me: &PublicKey, now_ms: u64, stats: &mut Stats) -> Vec<Outgoing> {
    if now_ms < group.repair_at_ms {
        return Vec::new();
    }
    let now_second = now_ms / 1000;
    let first = now_second.saturating_sub(HORIZON_SECONDS);
    let lacking = group
        .manifests
        .range(first..)
        .take_while(|(second, _)| (*second + 1) * 1000 + REPAIR_AFTER_MS <= now_ms)
        .any(|(second, _)| !group.whole(*second));
    let anti_entropy = now_ms >= group.anti_entropy_at_ms;
    if !lacking && !anti_entropy {
        return Vec::new();
    }
    let attempt = group.repair_attempt;
    let peer = group
        .layout
        .members()
        .into_iter()
        .filter(|key| key != me)
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
    group.repair_at_ms = now_ms + REPAIR_INTERVAL_MS;
    group.anti_entropy_at_ms = now_ms + ANTI_ENTROPY_MS;
    let span = (now_second + 1 - first).min(MAX_HAVE_SECONDS as u64);
    let mut seconds = vec![0u8; usize::try_from(span.div_ceil(8)).unwrap_or(0)];
    for offset in 0..span {
        let second = first + offset;
        // A second still arriving is not asked for; one with no manifest is, so a manifest that
        // never came is found.
        let settled = (second + 1) * 1000 + REPAIR_AFTER_MS <= now_ms;
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

/// Forgets what is past the horizon. The bytes it let go (records and parities).
fn forget(group: &mut Group, now_ms: u64) -> usize {
    let horizon_ms = now_ms.saturating_sub(HORIZON_SECONDS * 1000);
    let horizon_second = horizon_ms / 1000;
    let horizon_window = horizon_second / RECEIPT_WINDOW_SECONDS;
    let mut freed = 0;
    group.pieces.retain(|_, held| {
        let keep = held.at_ms >= horizon_ms;
        if !keep {
            freed += held.piece.held_len();
        }
        keep
    });
    group.parity.retain(|_, held| {
        let keep = held.at_ms >= horizon_ms;
        if !keep {
            freed += held.parity.len();
        }
        keep
    });
    group.bytes -= freed;
    group.manifests = group.manifests.split_off(&horizon_second);
    group.own = group.own.split_off(&horizon_second);
    group.seen.retain(|_, at| *at >= horizon_ms);
    group
        .answered
        .retain(|_, at| *at + ANSWER_INTERVAL_MS > now_ms);
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
        .retain(|changed| *changed + 2 * HORIZON_SECONDS * 1000 >= now_ms);
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

/// Whether a signed `second` is one this relay holds things for: within the horizon behind its
/// clock, and no further ahead than `SKEW_SECONDS`. Overflow-free for any `second`.
fn in_window(second: u64, now_ms: u64) -> bool {
    let now = now_ms / 1000;
    second.saturating_add(HORIZON_SECONDS) >= now && second <= now.saturating_add(SKEW_SECONDS)
}
