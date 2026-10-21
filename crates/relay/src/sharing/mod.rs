//! Sharing groups (RFC-0174 §2.5): per area and product, the relays that take the area, and the
//! duty that taking it is: forwarding one's slice of the area's striped trees.
//!
//! - `groups`: who is in each (cell, product) group, from the directory's offers and who asks.
//! - `stripes`: the trees, one per stripe (data stripes and a parity stripe), by rendezvous over
//!   (area, stripe, relay): each member's parent and children, each member interior in one.
//! - `seeds`: fixed seeding, one seed per stripe (the root), rotated by a rule anyone can check.
//! - `parity`: the parity stripe, which rebuilds any one lost stripe without a round trip.
//! - `member`: this relay's part, as a state machine: push, manifests, rebuild, repair,
//!   receipts and demotion.
//! - `bundles`: parent cells offered as bundles of their children (§2.6), records unchanged, with
//!   an index that makes omission detectable.
//! - `withdrawal`: the regions this relay stops forwarding in while its upload cap sheds the peers
//!   it forwards to (§2.5, "The cap stays the ceiling").
//! - `locks`: the one way every lock here is taken, so a panic never ends sharing.
//! - `full`: how long a member that said it is full is routed around, the one rule both ends of
//!   the refusal keep.
//!
//! [`Sharing`] is the network seam's face of it: the records links hand in, what this relay
//! originates ([`Sharing::originate`]) and members send it ([`Sharing::received`]), parity chunks
//! reassembled ([`Sharing::parity_chunk`]), what the tick publishes (records rebuilt, bundle
//! indexes), and what it addresses to members ([`Sharing::take_outbox`]), which `network` carries
//! down a session to each (`peers`). [`group_of`] is the one rule for which group a record is in.
//!
//! **Idle costs nothing.** A relay takes every area under its regions (the whole world is 41,162),
//! but holds and visits only what carries something: a group only this relay is in, with nothing
//! in it, has no book (`groups`) and is not held (`member`), and its trees are computed when asked
//! ([`Sharing::layout`]). The tick lays out again only the trees of the areas whose offers changed
//! (`Directory::take_changed_cells`), whose demotions began or ended, or all held ones when what
//! the relay takes or has withdrawn from changes; and the member visits only the groups with a duty
//! due. So a tick with no traffic and no change does no work, however many areas are taken
//! ([`Sharing::work`] counts it).
//!
//! Nothing goes back down the link a message came in on. What answers it (a repair page:
//! manifests, parity and records) is addressed to the asker and waits in the outbox like any other
//! send, so it travels over this relay's own member link to the asker (`peers`), the one way data
//! enters a relay (a link a relay dials takes none in, `link::member`), paced and capped as data
//! (`egress`), never drawing the control reserve; and an asker that is full now is sent none.

pub mod bundles;
pub mod full;
pub mod groups;
pub mod locks;
pub mod member;
pub mod parity;
pub mod seeds;
pub mod stripes;
pub mod withdrawal;

/// What a send waiting in the outbox allocates, as it is charged: a batch kept at ingest, whose
/// signed bytes carry their own charge for their life (`Batch::owned_by`), only its place; any
/// other record its encoded bytes, which are its own.
fn addressed_len(record: &Record) -> usize {
    match record {
        Record::Batch(batch) | Record::RelayBatch(batch) if batch.is_owned() => {
            std::mem::size_of::<Addressed>()
        }
        record => record.encoded_len(),
    }
}

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tally_wire::rendezvous::{AREA_RESOLUTION, areas_of};
use tally_wire::{
    BundleIndex, BundleIndexContent, HaveSummary, Identity, ParityChunk, PieceManifest, PublicKey,
    Record, Region, Streams, StripeAssignment, StripeReceipt,
};

use crate::budget::{Charge, Gauge, Store};
use crate::egress::{Class, EgressReport};
use crate::hub::Hub;
use crate::network::{Asker, AskerRole};
use crate::selection::Taken;

use self::groups::{ASK_LIFETIME_MS, GroupKey};
use self::locks::lock;
use self::member::{Arrival, Member, Message, Outgoing, Piece, record_hash};
use self::withdrawal::Withdrawal;

pub use self::member::Deadlines;
pub use self::seeds::{SEED_COPIES, seeded_bytes};

/// The products an area's group shares (§2.5: raw, positions, provisional positions, clock
/// models, and the regional product's deduplicated batches): every record of data one relay passes
/// another travels in one of these groups.
pub const SHARED_PRODUCTS: [Streams; 5] = [
    Streams::RAW,
    Streams::POSITIONS,
    Streams::PROVISIONAL,
    Streams::CLOCK_MODELS,
    Streams::REGIONAL,
];

/// What parities of `len` bytes in all being reassembled are charged at most, their chunks cut as
/// their origins cut them (`ParityChunk::chunks`, the only cut taken, [`Sharing::parity_chunk`]):
/// their bytes, each piece's own cost, and each parity's own. A parity held unfinished holds a
/// whole first chunk at least (a short one is its last, so whole at once), so there are no more of
/// them than whole chunks in `len`.
pub const fn assembling_cost(len: usize) -> usize {
    len + len.div_ceil(tally_wire::sharing::MAX_PARITY_CHUNK)
        * (PIECE_OVERHEAD + std::mem::size_of::<Assembling>())
}

/// The room parities are reassembled in (`budget::Plan::parity_assembly`), apart from the batch
/// store: every chunk the members' shared rate (`--max-member-bytes-per-sec`, at most
/// `member_bytes_per_sec` and its burst, `ceiling::Pace`) can bring in while a parity may wait
/// to be whole ([`PARITY_ASSEMBLY_MS`]). Everything the members send this relay comes through
/// that one pace, and a parity is let go once its wait is over, so what is reassembling is never
/// more than this, however its senders behave: the room is never full for an honest sender.
pub const fn assembly_room(member_bytes_per_sec: usize) -> usize {
    let burst = crate::ceiling::MIN_BURST as usize;
    let burst = if member_bytes_per_sec > burst {
        member_bytes_per_sec
    } else {
        burst
    };
    assembling_cost(
        member_bytes_per_sec
            .saturating_mul((PARITY_ASSEMBLY_MS / 1000) as usize)
            .saturating_add(burst),
    )
}

/// The part of the room one sender's parities may hold ([`assembly_room`]): two seconds of the
/// members' whole rate, of the ten a parity may wait. A sender's chunks of a second are sent
/// together, and a member's parities of a second are no more than what it sends in one, so an
/// honest sender's parities finish within its part; one that never finishes fills its own part only, and
/// the rest of the room is every other sender's.
pub fn sender_part(room: usize) -> usize {
    room / (PARITY_ASSEMBLY_MS / 1000 / SENDER_SECONDS) as usize
}
/// The seconds of the members' whole rate one sender's parities may hold ([`sender_part`]).
const SENDER_SECONDS: u64 = 2;
/// How long a parity may take to arrive whole from its first chunk: its chunks are sent together,
/// so one still missing a piece after this never will be.
pub const PARITY_ASSEMBLY_MS: u64 = 10 * 1000;
/// How long after a second ends a bundle index over it is signed: its manifests are in by then.
pub const BUNDLE_INDEX_AFTER_SECONDS: u64 = 3;

pub struct Sharing {
    /// What the member judges its deliverers by, as the relay was built (`Member::new`).
    deadlines: Deadlines,
    pub groups: groups::Groups,
    pub bundles: bundles::Bundles,
    member: Mutex<Option<Member>>,
    /// The addressed sends waiting for their links, each charged to the store's gauge from when it
    /// is queued until it is handed on ([`Addressed`]); a send the gauge cannot take is refused,
    /// counted (`outbox_refused`), never one already queued dropped.
    outbox: Mutex<Vec<Addressed>>,
    outbox_refused: AtomicU64,
    /// Parity chunks by sender, then manifest, until the parity is whole: each sender's part of
    /// the room its own gauge ([`Sender`]), so what one holds is read, never summed.
    assembling: Mutex<HashMap<PublicKey, Sender>>,
    /// The room parities are reassembled in, apart from the batch store
    /// (`budget::Budget::parity_assembly`): every parity being reassembled is charged to it and to
    /// its sender's part of it. Unlimited until the relay plans it (`assemble_in`).
    room: Mutex<Arc<Gauge>>,
    /// The last second bundle indexes were signed for.
    indexed_through: Mutex<Option<u64>>,
    /// The regions this relay has withdrawn from forwarding in.
    withdrawal: Mutex<Withdrawal>,
    /// The one batch byte store's gauge (`budget::Store::Batches`): what the member's groups hold
    /// (records and parities) and the parities being reassembled are charged to it, and it is
    /// their only bound. Unlimited until the relay charges sharing to its budget (`charge_to`).
    gauge: Mutex<Arc<Gauge>>,
    /// What the trees were last laid out from: the regions taken, the regions withdrawn, the key.
    view: Mutex<View>,
    /// Areas to lay out again at the next tick (a demotion the trees now leave out).
    relayout: Mutex<BTreeSet<u64>>,
    /// Group trees laid out since start: one per (area, product) whose offers, demotions or
    /// withdrawal changed, never one per area taken.
    laid_out: AtomicU64,
}

#[derive(Default)]
struct View {
    taken: Arc<Taken>,
    withdrawn: Vec<Region>,
    me: Option<PublicKey>,
}

/// What sharing has done and holds: the work a tick costs follows these, and none of them follows
/// the number of areas taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Group trees laid out since start.
    pub laid_out: u64,
    /// Groups the member's tick visited since start.
    pub visited: u64,
    /// Groups held now (each more than this relay alone with nothing).
    pub held_groups: usize,
    /// Groups another relay is in (offered or asked), held as books now.
    pub books: usize,
}

/// A send addressed to a member, waiting for the link to it: charged to the one batch byte store's
/// gauge (`budget::Store::Batches`, the store of what sharing holds) for its encoded bytes while it
/// waits, the charge handed on with it so whoever holds it next holds it charged. A piece shares
/// its bytes with the record its group holds, so this counts them again while the send waits:
/// never less than what is held.
#[derive(Debug)]
pub struct Addressed {
    pub to: PublicKey,
    pub record: Record,
    pub charge: Charge,
}

/// One sender's parities being reassembled, and its part of the room ([`sender_part`]).
struct Sender {
    part: Arc<Gauge>,
    parities: HashMap<tally_wire::batch::Hash, Assembling>,
}

impl Sender {
    /// `chunk`, ending at `end`, taken into its parity (begun again at a start, whose whole
    /// `room` gave): the parity once it is whole. Past the room or this sender's part, or out of
    /// its place, the parity is let go whole.
    fn take(
        &mut self,
        gauge: &Arc<Gauge>,
        chunk: ParityChunk,
        room: Option<usize>,
        end: usize,
        now_ms: u64,
    ) -> Option<Assembling> {
        let manifest = chunk.manifest;
        // A start begins the parity again; a parity past its wait is let go.
        if room.is_some()
            || self
                .parities
                .get(&manifest)
                .is_some_and(|held| held.started_ms + PARITY_ASSEMBLY_MS <= now_ms)
        {
            self.parities.remove(&manifest);
        }
        let held = match (self.parities.entry(manifest), room) {
            (std::collections::hash_map::Entry::Occupied(held), _) => held.into_mut(),
            (std::collections::hash_map::Entry::Vacant(vacant), Some(total)) => {
                let mut started = Assembling {
                    first: ParityChunk {
                        bytes: Vec::new(),
                        ..chunk.clone()
                    },
                    total,
                    pieces: Vec::new(),
                    filled: 0,
                    charge: gauge.empty(),
                    part: self.part.empty(),
                    started_ms: now_ms,
                };
                if !started.grow(std::mem::size_of::<Assembling>()) {
                    return None;
                }
                vacant.insert(started)
            }
            // No parity begun: a stray chunk.
            (std::collections::hash_map::Entry::Vacant(_), None) => return None,
        };
        let next = usize::try_from(chunk.offset).is_ok_and(|offset| offset == held.filled)
            && held.agrees(&chunk)
            && held.grow(chunk.bytes.len() + PIECE_OVERHEAD);
        if !next {
            self.parities.remove(&manifest);
            return None;
        }
        held.filled = end;
        held.pieces.push(chunk.bytes);
        if held.filled < held.total {
            return None;
        }
        self.parities.remove(&manifest)
    }

    /// The parities past their wait let go.
    fn expire(&mut self, now_ms: u64) {
        self.parities
            .retain(|_, held| held.started_ms + PARITY_ASSEMBLY_MS > now_ms);
    }
}

/// A parity being reassembled: only the bytes received, charged as each chunk arrives, never its
/// declared whole before it has come.
struct Assembling {
    /// The first chunk, without its bytes: what every later chunk must agree with.
    first: ParityChunk,
    /// The whole's length, as the first chunk declared it and its manifest allows
    /// (`Member::parity_room`).
    total: usize,
    /// The chunks received, in order, each where the last ended.
    pieces: Vec<Vec<u8>>,
    /// The bytes `pieces` hold: where the next chunk starts.
    filled: usize,
    /// What it holds (its pieces, each with its own size, and its own), charged to the room and
    /// to its sender's part as it comes.
    charge: Charge,
    part: Charge,
    started_ms: u64,
}

/// What one piece of a parity being reassembled costs beside its bytes.
const PIECE_OVERHEAD: usize = std::mem::size_of::<(usize, Vec<u8>)>() + 32;

impl Assembling {
    /// Whether `chunk` is a piece of the same parity as the first.
    fn agrees(&self, chunk: &ParityChunk) -> bool {
        chunk.total == self.first.total
            && chunk.cell == self.first.cell
            && chunk.product == self.first.product
            && chunk.second == self.first.second
            && chunk.lens == self.first.lens
    }

    /// `bytes` more charged to the room and the sender's part, both or neither.
    fn grow(&mut self, bytes: usize) -> bool {
        if !self.part.try_grow(bytes) {
            return false;
        }
        if self.charge.try_grow(bytes) {
            return true;
        }
        let back = self.part.bytes() - bytes;
        self.part.shrink_to(back);
        false
    }

    /// Every byte held, in order: the parity whole.
    fn whole(self) -> Option<(ParityChunk, Vec<u8>)> {
        if self.filled != self.total {
            return None;
        }
        let mut xor = Vec::with_capacity(self.total);
        for piece in self.pieces {
            xor.extend_from_slice(&piece);
        }
        Some((self.first, xor))
    }
}

/// The forwarding peers the egress has shed since the relay started: every class but control
/// (never shed) and plain takers (shed first, and no sign the slice cannot be carried).
pub fn forwarders_shed(report: &EgressReport) -> u64 {
    report
        .classes
        .iter()
        .filter(|class| !matches!(class.class, Class::Control | Class::Taker))
        .map(|class| class.shed)
        .sum()
}

impl Sharing {
    /// Sharing whose member judges its deliverers by `deadlines` (a relay's `Deadlines::RELAY`;
    /// `member::Deadlines`). There is no default: a caller names the deadlines its verdicts follow.
    pub fn new(deadlines: Deadlines) -> Self {
        Self {
            deadlines,
            groups: groups::Groups::default(),
            bundles: bundles::Bundles::default(),
            member: Mutex::default(),
            outbox: Mutex::default(),
            outbox_refused: AtomicU64::new(0),
            assembling: Mutex::default(),
            room: Mutex::new(Gauge::unlimited(Store::Batches)),
            indexed_through: Mutex::default(),
            withdrawal: Mutex::default(),
            gauge: Mutex::new(Gauge::unlimited(Store::Batches)),
            view: Mutex::default(),
            relayout: Mutex::default(),
            laid_out: AtomicU64::new(0),
        }
    }

    /// A member asking this relay for stripes: it is a member of the group for a while, as its
    /// offer would make it.
    pub fn assigned(&self, asker: &Asker, assignment: StripeAssignment, now_ms: u64) {
        if asker.role != AskerRole::Relay {
            return;
        }
        let group = GroupKey::new(assignment.cell, assignment.product);
        self.groups
            .admit(group, asker.key, now_ms + ASK_LIFETIME_MS, false);
        self.drive(asker, Message::Assign(assignment), now_ms)
    }

    /// An origin's manifest of one second, passed on to the group.
    pub fn manifest(&self, asker: &Asker, manifest: PieceManifest, now_ms: u64) {
        if asker.role != AskerRole::Relay {
            return;
        }
        self.drive(asker, Message::Manifest(manifest), now_ms)
    }

    /// A member's have-summary: answered with what it lacks, paged, as data, over this relay's
    /// own member link to it (the outbox). Only a member the group's trees hold (by its verified
    /// offer), and not demoted, is answered.
    pub fn have(&self, asker: &Asker, have: HaveSummary, now_ms: u64) {
        if asker.role != AskerRole::Relay {
            return;
        }
        self.drive(asker, Message::Have(have), now_ms)
    }

    /// A child's receipt (this relay's evidence, which `credit` keeps), or a member's report of
    /// a shortfall, which may demote the member it names.
    pub fn receipt(&self, asker: &Asker, receipt: StripeReceipt, now_ms: u64) {
        if asker.role != AskerRole::Relay {
            return;
        }
        self.drive(asker, Message::Receipt(receipt), now_ms)
    }

    /// A record this relay originated for an area's product (a feeder's batch, its own
    /// positions): held, and seeded into the group. Only in an area it takes: a group of any
    /// other has no tree this relay is in.
    pub fn originate(&self, record: &Record, cell: Region, product: Streams, now_ms: u64) {
        if !self.takes_area(cell) {
            return;
        }
        let Some((hash, piece)) = encoded(record) else {
            return;
        };
        let out = self.with_member(|member| {
            member.originate(GroupKey::new(cell, product), hash, piece, now_ms)
        });
        self.queue(out.unwrap_or_default());
    }

    /// A group record a member sent this relay: held and pushed on down its stripe.
    pub fn received(
        &self,
        from: &PublicKey,
        record: &Record,
        cell: Region,
        product: Streams,
        now_ms: u64,
    ) {
        let Some((hash, piece)) = encoded(record) else {
            return;
        };
        let group = GroupKey::new(cell, product);
        let message = Message::Piece { group, hash, piece };
        let joins = self.takes_area(cell);
        let out = self.with_member(|member| {
            if joins {
                member.join(group);
            }
            member.receive(*from, message, now_ms)
        });
        self.queue(out.unwrap_or_default());
    }

    /// A group record a member sent that this relay refused (`Member::refuse`).
    pub fn refused(&self, record: &Record, cell: Region, product: Streams, now_ms: u64) {
        let Some(hash) = member::record_hash(record) else {
            return;
        };
        self.with_member(|member| member.refuse(GroupKey::new(cell, product), hash, now_ms));
    }

    /// A chunk of a parity a member sent: held until the parity is whole, then taken in as the
    /// member's parity.
    ///
    /// Reassembled only for an origin manifest this relay holds, from a relay its group knows, and
    /// only as long as that manifest's records allow (`Member::parity_room`), and only as its
    /// origin cuts it (`ParityChunk::chunks`): in order from the start, each chunk but the last a
    /// whole `MAX_PARITY_CHUNK`. A chunk at the start begins the parity again; any other is taken
    /// only where the last ended, and one that is not lets the parity go (it can no longer be
    /// whole). Each chunk is charged as it comes, never the declared whole ahead of it, to the
    /// room parities are reassembled in ([`assembly_room`], apart from the batch store) and to its
    /// sender's part of it ([`sender_part`]). So a chunk for a manifest nobody signed, or one
    /// declaring more than its records could be, holds nothing; a parity held unfinished holds a
    /// whole chunk at least, so a sender holds no more than it sent; and one that never finishes
    /// holds what it sent, for `PARITY_ASSEMBLY_MS`, from its own part.
    pub fn parity_chunk(&self, asker: &Asker, chunk: ParityChunk, now_ms: u64) {
        use tally_wire::sharing::MAX_PARITY_CHUNK;
        if asker.role != AskerRole::Relay {
            return;
        }
        let (Ok(offset), Ok(total)) = (usize::try_from(chunk.offset), usize::try_from(chunk.total))
        else {
            return;
        };
        let end = offset.saturating_add(chunk.bytes.len());
        // The origin's cut: whole chunks from the start, the last ending the parity.
        if offset % MAX_PARITY_CHUNK != 0
            || end > total
            || (chunk.bytes.len() != MAX_PARITY_CHUNK && end != total)
        {
            return;
        }
        // A start is asked of the member before the assembly is touched: the two locks are never
        // held together.
        let room = if offset == 0 {
            match self.with_member(|member| member.parity_room(&asker.key, &chunk)) {
                Some(Some(total)) => Some(total),
                _ => return,
            }
        } else {
            None
        };
        let whole = {
            let mut assembling = lock(&self.assembling);
            let gauge = Arc::clone(&lock(&self.room));
            let sender = assembling.entry(asker.key).or_insert_with(|| Sender {
                part: gauge.share(sender_part),
                parities: HashMap::new(),
            });
            let whole = sender.take(&gauge, chunk, room, end, now_ms);
            if sender.parities.is_empty() {
                assembling.remove(&asker.key);
            }
            whole
        };
        let Some(assembled) = whole else {
            return;
        };
        // Its charge is held while the whole is put together, and ends once it is
        // (`Assembling::whole`): the parity is charged again where it is held (`Member::parity`).
        let Some((first, xor)) = assembled.whole() else {
            return;
        };
        let mut lens = [0u32; stripes::DATA_STRIPES as usize];
        if first.lens.len() != lens.len() {
            return;
        }
        lens.copy_from_slice(&first.lens);
        let parity = parity::Parity {
            manifest: first.manifest,
            cell: first.cell,
            product: first.product,
            second: first.second,
            lens,
            xor,
        };
        self.drive(asker, Message::Parity(Arc::new(parity)), now_ms)
    }

    /// This relay turned `key`'s member link away as full at `now_ms`, asking it to stay away
    /// `asked` (`link`, every `Goodbye` of reason `Full` it sends a relay): that relay routes its
    /// slice past this one for the wait the one rule gives (`full::Wait`), so no shortfall is filed
    /// against it for those windows (`Member::turned_away`).
    pub fn turned_away(&self, key: PublicKey, asked: std::time::Duration, now_ms: u64) {
        self.with_member(|member| member.turned_away(key, asked, now_ms));
    }

    /// What the member has done since start (records rebuilt, repairs, receipts and shortfalls),
    /// and the sends refused for room before their links took them.
    pub fn stats(&self) -> (member::Stats, u64) {
        let stats = lock(&self.member)
            .as_ref()
            .map(Member::stats)
            .unwrap_or_default();
        (stats, self.outbox_refused.load(Ordering::Relaxed))
    }

    /// What this relay's groups hold (records and parities) and what it addresses its members
    /// are charged to `gauge` (the budget's `Store::Batches`) from now on: its limit, the store's
    /// share of the budget, is the store's only bound. A record or parity past it is refused whole
    /// and counted (`member::Stats::refused`, and the gauge's own count).
    pub fn charge_to(&self, gauge: Arc<Gauge>) {
        *lock(&self.gauge) = Arc::clone(&gauge);
        if let Some(member) = lock(&self.member).as_mut() {
            member.charge_to(gauge);
        }
    }

    /// The parities being reassembled are charged to `room` from now on
    /// (`budget::Budget::parity_assembly`, sized by [`assembly_room`]), each sender's to its part
    /// of it too ([`sender_part`]): a room apart from the batch store, so no sender's chunks take
    /// the room of what the groups hold. A sender already reassembling keeps its part until it
    /// holds nothing.
    pub fn assemble_in(&self, room: Arc<Gauge>) {
        *lock(&self.room) = room;
    }

    /// Bytes the groups hold now (records and parities, what the gauge is charged for them), and
    /// what they refused for room since start. The parities being reassembled are their room's
    /// (`assemble_in`), which counts them itself.
    pub fn held(&self) -> (usize, u64) {
        lock(&self.member).as_ref().map_or((0, 0), |member| {
            (member.group_bytes(), member.stats().refused)
        })
    }

    /// Addresses `record` to the relay `to` down the member link `carry` keeps, charged as every
    /// send is: a record no group holds (an overload cut, `mlat_host::Cut`) that only the relay it
    /// is for reads. False when the store's share is full.
    pub fn address(&self, to: PublicKey, record: Record) -> bool {
        let gauge = Arc::clone(&lock(&self.gauge));
        match gauge.try_charge(addressed_len(&record)) {
            Some(charge) => {
                lock(&self.outbox).push(Addressed { to, record, charge });
                true
            }
            None => {
                self.outbox_refused.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// The addressed sends waiting for their links, each with its charge, which whoever carries it
    /// holds until it is written ([`Addressed`]).
    pub fn take_outbox(&self) -> Vec<Addressed> {
        std::mem::take(&mut *lock(&self.outbox))
    }

    /// The cells this relay may offer as bundles now (§2.6).
    pub fn bundle_offers(&self) -> Vec<Region> {
        self.bundles.offerable()
    }

    /// The group trees as this relay sees them (none before it serves): a held group's, or, for
    /// an area it takes that no other relay is in, this relay alone.
    pub fn layout(&self, cell: Region, product: Streams) -> Option<stripes::Layout> {
        let member = lock(&self.member);
        let member = member.as_ref()?;
        if let Some(layout) = member.layout(GroupKey::new(cell, product)) {
            return Some(layout.clone());
        }
        let me = member.key();
        let taken = Arc::clone(&lock(&self.view).taken);
        if !taken.takes_area(cell) {
            return None;
        }
        let withdrawal = lock(&self.withdrawal).clone();
        let leaves = if self.own_leaf(cell, &taken, &withdrawal) {
            vec![me]
        } else {
            Vec::new()
        };
        Some(stripes::Layout::new(cell, product, &[me], &leaves))
    }

    /// The stripes `key` is an interior candidate in, in the group's trees as this relay sees them;
    /// `None` when there are none or it is not in them. For an area no other relay is in, without
    /// laying the trees out: this relay alone forwards every stripe.
    pub fn homes(&self, cell: Region, product: Streams, key: &PublicKey) -> Option<Vec<u8>> {
        let member = lock(&self.member);
        let member = member.as_ref()?;
        if let Some(layout) = member.layout(GroupKey::new(cell, product)) {
            return layout.contains(key).then(|| layout.homes(key));
        }
        (member.key() == *key && self.takes_area(cell)).then(|| (0..stripes::STRIPES).collect())
    }

    /// What sharing has done and holds.
    pub fn work(&self) -> Work {
        let (visited, held_groups) = lock(&self.member)
            .as_ref()
            .map_or((0, 0), |member| (member.visits(), member.groups().len()));
        Work {
            laid_out: self.laid_out.load(Ordering::Relaxed),
            visited,
            held_groups,
            books: self.groups.keys().len(),
        }
    }

    /// Whether `area` is one this relay takes, as of the last tick.
    fn takes_area(&self, area: Region) -> bool {
        lock(&self.view).taken.takes_area(area)
    }

    /// Whether this relay is a leaf in `area`'s trees: some cell it offers that holds the area (a
    /// region it takes or a bundle) overlaps a region it withdrew from. Its offers for that cell
    /// say 0 stripes, and it reads itself as every other relay reads those offers.
    fn own_leaf(&self, area: Region, taken: &Taken, withdrawal: &Withdrawal) -> bool {
        !withdrawal.withdrawn().is_empty()
            && (0..=area.resolution())
                .filter_map(|resolution| area.ancestor(resolution))
                .any(|cell| {
                    (taken.names(cell) || self.bundles.is_offerable(cell))
                        && withdrawal.covers(cell)
                })
    }

    /// Whether this relay forwards nothing in `cell` now: the cell overlaps a region it withdrew
    /// from while its upload cap shed the peers it forwards to. Its offer for the cell says
    /// `stripes` 0 (`directory`).
    pub fn withdrawn(&self, cell: Region) -> bool {
        lock(&self.withdrawal).covers(cell)
    }

    /// What to publish now: records rebuilt from parity (new to this relay). Manifests,
    /// receipts, assignments and repairs are addressed, and wait in the outbox. Membership is
    /// refreshed first, from the areas this relay takes and the live offers for them, and the
    /// regions it forwards in from what its egress has shed.
    pub fn tick(&self, hub: &Hub, identity: Option<&Identity>, now_ms: u64) -> Vec<Record> {
        let shed = forwarders_shed(&hub.egress().report());
        self.tick_shed(hub, identity, shed, now_ms)
    }

    /// [`Sharing::tick`], with the egress's count of forwarding peers shed given.
    ///
    /// Lays out again only the trees that may have changed: the areas under the cells whose offers
    /// changed (where another relay offers, or a group is held or booked), the areas whose
    /// demotions began or ended, and every held or booked group when the regions taken, the regions
    /// withdrawn or the key change. Then the member's duties that are due.
    pub(crate) fn tick_shed(
        &self,
        hub: &Hub,
        identity: Option<&Identity>,
        shed: u64,
        now_ms: u64,
    ) -> Vec<Record> {
        let Some(identity) = identity else {
            return Vec::new();
        };
        let me = identity.public();
        let network = hub.network();
        let taken = network.selection.taken_index();
        let withdrawal = {
            let mut withdrawal = lock(&self.withdrawal);
            withdrawal.observe(shed, taken.regions(), &me, now_ms);
            withdrawal.clone()
        };
        let (taken_moved, withdrawn_moved) = {
            let mut view = lock(&self.view);
            let taken_moved = view.taken.version() != taken.version() || view.me != Some(me);
            let withdrawn_moved = view.withdrawn != withdrawal.withdrawn();
            view.taken = Arc::clone(&taken);
            view.withdrawn = withdrawal.withdrawn().to_vec();
            view.me = Some(me);
            (taken_moved, withdrawn_moved)
        };
        if taken_moved {
            self.bundles.set_taken(Arc::clone(&taken));
        }
        lock(&self.assembling).retain(|_, sender| {
            sender.expire(now_ms);
            !sender.parities.is_empty()
        });
        let mut guard = lock(&self.member);
        let gauge = Arc::clone(&lock(&self.gauge));
        let fresh =
            |identity: &Identity| Member::new(identity.clone(), Arc::clone(&gauge), self.deadlines);
        let member = guard.get_or_insert_with(|| fresh(identity));
        if member.key() != me {
            *member = fresh(identity);
        }
        // The members that turned this relay's links away as full, while they are: routed around
        // (`Member::route`) until their wait ends.
        member.set_full(network.peers.full(now_ms));
        // The areas whose trees may have changed.
        let directory = &network.directory;
        let changed = directory.take_changed_cells(now_ms);
        let mut areas: BTreeSet<u64> = std::mem::take(&mut *lock(&self.relayout));
        for key in self.groups.expire(now_ms) {
            areas.insert(key.cell.as_u64());
        }
        let known = |areas: &mut BTreeSet<u64>, member: &Member, under: Option<Region>| {
            let held = member.groups().into_iter().chain(self.groups.keys());
            areas.extend(
                held.map(|key| key.cell)
                    .filter(|cell| under.is_none_or(|under| under.contains(*cell)))
                    .map(Region::as_u64),
            );
        };
        if taken_moved || withdrawn_moved {
            known(&mut areas, member, None);
        }
        let cells = if taken_moved {
            directory.cells_held_by_others(&me)
        } else {
            changed
        };
        for cell in cells {
            if cell.resolution() > AREA_RESOLUTION || !taken.touches(cell) {
                continue;
            }
            if directory.others_hold(cell, &me) {
                let under = if cell.resolution() == AREA_RESOLUTION {
                    vec![cell]
                } else {
                    areas_of(cell).unwrap_or_default()
                };
                areas.extend(
                    under
                        .into_iter()
                        .filter(|area| taken.takes_area(*area))
                        .map(Region::as_u64),
                );
            } else {
                // Only this relay offers here now: what changed is another's leaving, and only
                // the groups held or booked under the cell had it.
                known(&mut areas, member, Some(cell));
            }
        }
        let mut out = Vec::new();
        let mut laid_out = 0;
        for area in areas
            .into_iter()
            .filter_map(|area| Region::from_u64(area).ok())
        {
            if !taken.takes_area(area) {
                for product in SHARED_PRODUCTS {
                    let key = GroupKey::new(area, product);
                    self.groups.set_offers(key, &BTreeMap::new());
                    member.leave(key);
                }
                continue;
            }
            // Every live offer covering the area, but this relay's own: checked by the
            // directory when it came (`directory::Checked`), never again here.
            let offers: Vec<crate::directory::Checked> = directory
                .offers_for(area, now_ms)
                .into_iter()
                .filter(|offer| offer.signer() != me)
                .collect();
            let leaf = self.own_leaf(area, &taken, &withdrawal);
            for product in SHARED_PRODUCTS {
                let key = GroupKey::new(area, product);
                // Per signer, a leaf when any of its offers here forwards nothing.
                let mut signers: BTreeMap<PublicKey, bool> = BTreeMap::new();
                for offer in &offers {
                    let content = offer.content();
                    if content.products.contains(product) {
                        *signers.entry(offer.signer()).or_insert(false) |= content.stripes == 0;
                    }
                }
                self.groups.set_offers(key, &signers);
                let (members, mut leaves) = self.groups.tree(key);
                if members.is_empty() && !member.holds_group(key) {
                    // This relay alone, with nothing: not held (`Sharing::layout`).
                    continue;
                }
                if leaf {
                    leaves.push(me);
                    leaves.sort();
                }
                laid_out += 1;
                out.extend(member.set_members(key, &members, &leaves, now_ms));
            }
        }
        self.laid_out.fetch_add(laid_out, Ordering::Relaxed);
        out.extend(member.tick(now_ms));
        let demotions = member.take_demotions();
        if !demotions.is_empty() {
            let mut relayout = lock(&self.relayout);
            for (group, demoted, until) in demotions {
                self.groups.demote(group, demoted, until);
                relayout.insert(group.cell.as_u64());
            }
        }
        let indexes = self.bundle_indexes(member, identity, now_ms);
        let rebuilt: Vec<Record> = member
            .take_delivered()
            .into_iter()
            .filter(|delivered| delivered.arrival == Arrival::Rebuilt)
            .filter_map(|delivered| delivered.piece.record())
            .collect();
        drop(guard);
        self.queue(out);
        let mut published = rebuilt;
        published.extend(indexes.into_iter().map(Record::BundleIndex));
        published
    }

    /// The bundle indexes due (§2.6): once a second, `BUNDLE_INDEX_AFTER_SECONDS` after it ends,
    /// for each parent this relay may offer as a bundle and each shared product under which it
    /// holds an origin manifest of that second, every child with the digest of the manifests held
    /// under it. A parent with nothing under it that second has no index: there is nothing to
    /// omit, and a reader who saw a manifest under a parent for a second with no index from its
    /// bundler holds the omission itself. So the indexes cost what was originated, never the
    /// number of parents offered.
    fn bundle_indexes(
        &self,
        member: &Member,
        identity: &Identity,
        now_ms: u64,
    ) -> Vec<BundleIndex> {
        let Some(second) = (now_ms / 1000).checked_sub(BUNDLE_INDEX_AFTER_SECONDS) else {
            return Vec::new();
        };
        let mut through = lock(&self.indexed_through);
        if through.is_some_and(|done| done >= second) {
            return Vec::new();
        }
        *through = Some(second);
        drop(through);
        // By parent, then product (in `SHARED_PRODUCTS` order), the manifests under it.
        let mut under: BTreeMap<u64, BTreeMap<usize, Vec<PieceManifest>>> = BTreeMap::new();
        for (group, manifests) in member.manifests_of(second) {
            let Some(product) = SHARED_PRODUCTS
                .iter()
                .position(|product| *product == group.product)
            else {
                continue;
            };
            for resolution in 0..AREA_RESOLUTION {
                if let Some(parent) = group.cell.ancestor(resolution)
                    && self.bundles.is_offerable(parent)
                {
                    under
                        .entry(parent.as_u64())
                        .or_default()
                        .entry(product)
                        .or_default()
                        .extend(manifests.iter().cloned());
                }
            }
        }
        let mut out = Vec::new();
        for (parent, products) in under {
            let Ok(parent) = Region::from_u64(parent) else {
                continue;
            };
            for (product, manifests) in products {
                let index = bundles::BundleIndex::build(
                    parent,
                    SHARED_PRODUCTS[product],
                    second,
                    &manifests,
                );
                let content = BundleIndexContent {
                    parent: index.parent,
                    product: index.product,
                    second: index.second,
                    children: index.children,
                };
                if let Ok(signed) = BundleIndex::sign(identity, &content) {
                    out.push(signed);
                }
            }
        }
        out
    }

    /// Hands a message to the member; what it sends, to the asker too, waits in the outbox.
    fn drive(&self, asker: &Asker, message: Message, now_ms: u64) {
        // A message about a group of an area this relay takes is the group's, held or not.
        let joins = message.group().filter(|group| self.takes_area(group.cell));
        let out = self
            .with_member(|member| {
                if let Some(group) = joins {
                    member.join(group);
                }
                member.receive(asker.key, message, now_ms)
            })
            .unwrap_or_default();
        self.queue(out);
    }

    fn with_member<T>(&self, act: impl FnOnce(&mut Member) -> T) -> Option<T> {
        lock(&self.member).as_mut().map(act)
    }

    fn queue(&self, out: Vec<Outgoing>) {
        if out.is_empty() {
            return;
        }
        let gauge = Arc::clone(&lock(&self.gauge));
        let mut refused = 0;
        let mut outbox = lock(&self.outbox);
        for outgoing in out {
            let to = outgoing.to;
            for record in to_records(outgoing.message) {
                // Charged before it is queued: past the store's share the send is refused, and
                // the member it was for repairs what it lacks.
                match gauge.try_charge(addressed_len(&record)) {
                    Some(charge) => outbox.push(Addressed { to, record, charge }),
                    None => refused += 1,
                }
            }
        }
        drop(outbox);
        if refused > 0 {
            self.outbox_refused.fetch_add(refused, Ordering::Relaxed);
        }
    }
}

/// The group a record belongs to (RFC-0174 §2.5): one rule, the same for its origin and every
/// member, so a record is shared in exactly one group.
///
/// - A receiver's batch: the area of the receiver's public cell (`point`, its description's;
///   `rendezvous::area_of_public`, the cell's parent at `AREA_RESOLUTION`), product `RAW`. Never
///   the area its site lies in, which can differ and so says more than the public cell. No
///   public cell, no group.
/// - Final or provisional positions: the area of the record's first solution, product
///   `POSITIONS` or `PROVISIONAL` (an engine packs a record's solutions in tile order, so a record
///   is nearly always one area's).
/// - A clock model manifest: the area of its tile's centre (`point`, from its inline bytes or its
///   first part), product `CLOCK_MODELS`. Its parts are in no group: every member link carries a
///   model's parts just before its manifest (`link`'s `Told`).
/// - A regional batch: its cell's area, product `REGIONAL`; its client form (counters stripped)
///   likewise, beside it. A client clock model goes with its full model, positions tagged for
///   clients with their raw twins (each placed by its own first solution, which is the same).
/// - A fault proof: the group of the first solutions record it holds, or of its models.
pub fn group_of(record: &Record, point: Option<Region>) -> Option<(Region, Streams)> {
    let area_at = tally_wire::rendezvous::area_of_cell;
    match record {
        Record::Batch(_) => Some((
            tally_wire::rendezvous::area_of_public(point?)?,
            Streams::RAW,
        )),
        Record::Positions(_) | Record::Provisional(_) => {
            let solved = match record {
                Record::Positions(positions) | Record::Provisional(positions) => {
                    crate::network::solved(positions)?
                }
                _ => return None,
            };
            let first = solved.first()?;
            let point = Region::point(&tally_wire::Location {
                lat_e7: first.lat_e7,
                lon_e7: first.lon_e7,
                alt_m: 0,
                precision_m: 0,
            })
            .ok()?;
            let product = if matches!(record, Record::Provisional(_)) {
                Streams::PROVISIONAL
            } else {
                Streams::POSITIONS
            };
            Some((area_at(point)?, product))
        }
        // A client clock model with its full model: placed by the full model's tile (`point`).
        Record::ClockModel(_) | Record::ClientClockModel(_) => {
            Some((area_at(point?)?, Streams::CLOCK_MODELS))
        }
        Record::RegionalBatch(regional) => {
            Some((area_at(regional.content().ok()?.cell)?, Streams::REGIONAL))
        }
        Record::ClientRegionalBatch(regional) => {
            Some((area_at(regional.content().ok()?.cell)?, Streams::REGIONAL))
        }
        // A fault proof travels with what it is about: the first of its two solutions' records,
        // or its two models (placed by `point`).
        Record::FaultProof(proof) => match proof.parts() {
            Ok([(positions, _), _]) => group_of(&Record::Positions(positions), None)
                .map(|(cell, _)| (cell, Streams::POSITIONS)),
            Err(_) => Some((area_at(point?)?, Streams::CLOCK_MODELS)),
        },
        _ => None,
    }
}

/// A record as a group carries it: its hash and its piece (a batch's own bytes, shared).
fn encoded(record: &Record) -> Option<(tally_wire::batch::Hash, Piece)> {
    Some((record_hash(record)?, Piece::of(record)?))
}

/// The wire records of a message: one, or a parity's chunks.
fn to_records(message: Message) -> Vec<Record> {
    match message {
        Message::Piece { piece, .. } => piece.record().into_iter().collect(),
        Message::Manifest(manifest) => vec![Record::PieceManifest(manifest)],
        Message::Receipt(receipt) => vec![Record::StripeReceipt(receipt)],
        Message::Have(have) => vec![Record::HaveSummary(have)],
        Message::Assign(assignment) => vec![Record::StripeAssignment(assignment)],
        Message::Parity(parity) => ParityChunk::chunks(
            parity.manifest,
            parity.cell,
            parity.product,
            parity.second,
            parity.lens.to_vec(),
            &parity.xor,
        )
        .map(|chunks| chunks.into_iter().map(Record::Parity).collect())
        .unwrap_or_default(),
    }
}
