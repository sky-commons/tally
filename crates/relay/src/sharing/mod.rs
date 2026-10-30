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

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tally_wire::Signs;
use tally_wire::rendezvous::{AREA_RESOLUTION, areas_of};
use tally_wire::{
    BundleIndex, BundleIndexContent, HaveSummary, ParityChunk, PieceManifest, PublicKey, Record,
    Region, Streams, StripeAssignment, StripeReceipt,
};

use crate::budget::{Charge, Gauge, Store};
use crate::egress::{Class, EgressReport};
use crate::footprint::{self, Deque, Tree};
use crate::hub::Hub;
use crate::network::{Asker, AskerRole};
use crate::selection::Taken;
use crate::signer::Signer;

use self::groups::{ASK_LIFETIME_MS, GroupKey};
use self::locks::lock;
use self::member::{Arrival, Member, Message, Outgoing, Piece, record_hash};
use self::withdrawal::Withdrawal;

pub use self::member::{Deadlines, MonoDeadline, Now};
pub use self::seeds::{SEED_COPIES, seeded_bytes};

/// A record a sharing group rebuilt from parity and holds apart until this relay judges it: the
/// exact group and hash it was rebuilt under, as the member holds it. Made only here, by the tick
/// that rebuilt it ([`Sharing::tick`]), and handed back with the verdict ([`Sharing::passed_on`],
/// [`Sharing::refused_rebuilt`], [`Sharing::let_go`]), so the verdict reaches the group that holds
/// the record and is never reckoned again from the record (a clock model's area, a receiver's
/// described cell), which can say no group, or another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rebuilt {
    group: GroupKey,
    hash: tally_wire::batch::Hash,
}

impl Rebuilt {
    /// A handle for a record a test's group holds rebuilt (`Member::tick`'s `Arrival::Rebuilt`).
    #[cfg(test)]
    pub(crate) fn of(group: GroupKey, hash: tally_wire::batch::Hash) -> Self {
        Self { group, hash }
    }

    /// The group that rebuilt it, for a test.
    #[cfg(test)]
    pub(crate) fn group(&self) -> GroupKey {
        self.group
    }

    /// Its hash, for a test.
    #[cfg(test)]
    pub(crate) fn hash(&self) -> tally_wire::batch::Hash {
        self.hash
    }
}

/// What a sharing tick hands on ([`Sharing::tick`]).
#[derive(Debug, Default)]
pub struct Ticked {
    /// Records rebuilt from parity, new to this relay, each with the group that holds it: each is
    /// taken in through the intake its kind has (`Hub::take_rebuilt`), as a member's piece of the
    /// group is, never published straight into the fan-out, which would skip a batch's admission
    /// (its dedup, its station, its decode for the hosted MLAT, its cell for regional
    /// subscribers).
    pub rebuilt: Vec<(Rebuilt, Record)>,
    /// Records rebuilt from parity whose bytes are no record: no intake can judge one, so its
    /// relay refuses it in its group, counted (`Hub::refuse_rebuilt`).
    pub unreadable: Vec<Rebuilt>,
    /// Records this relay signed of its own (bundle indexes), published as its own.
    pub published: Vec<Record>,
}

/// The products an area's group shares (§2.5: raw, positions, clock models, and the regional
/// product's deduplicated batches): every record of data one relay passes another travels in one
/// of these groups.
pub const SHARED_PRODUCTS: [Streams; 4] = [
    Streams::RAW,
    Streams::POSITIONS,
    Streams::CLOCK_MODELS,
    Streams::REGIONAL,
];

/// What parities of `len` bytes in all being reassembled are charged at most, their chunks cut as
/// their origins cut them (`ParityChunk::chunks`, the only cut taken, [`Sharing::parity_chunk`]):
/// their bytes, and for each whole chunk what the most a chunk costs beside them
/// ([`ASSEMBLING_PER_CHUNK_BYTES`]), with the senders' tree's root. A parity held unfinished holds
/// a whole first chunk at least (a short one is its last, so whole at once), and each sender one
/// parity at least, so there are no more of either than whole chunks in `len`.
pub const fn assembling_cost(len: usize) -> usize {
    len + len.div_ceil(tally_wire::sharing::MAX_PARITY_CHUNK) * ASSEMBLING_PER_CHUNK_BYTES
        + Tree::<PublicKey, Sender>::bytes_planned(0)
}

/// What one chunk being reassembled costs at most beside its bytes, as the assembly allocates it
/// (`footprint`): a sender's place in the senders' tree, its parity's place in that sender's tree
/// with the tree's root (each sender may hold one parity), the first chunk's lengths, and its
/// piece's slot in its parity's deque, which keeps a quarter again what it holds and
/// `Deque::LEAST` more (`Deque::bytes_at_most`, the more for a parity of one piece).
pub const ASSEMBLING_PER_CHUNK_BYTES: usize = Tree::<PublicKey, Sender>::bytes_per_entry()
    + Tree::<tally_wire::batch::Hash, Assembling>::bytes_planned(1)
    + footprint::vec::<u32>(stripes::DATA_STRIPES as usize)
    + (footprint::vec::<Vec<u8>>(1) * 5).div_ceil(4)
    + footprint::vec::<Vec<u8>>(Deque::<Vec<u8>>::LEAST);

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
    outbox: Mutex<Outbox>,
    outbox_refused: AtomicU64,
    /// Sends drained for a member with no address held: queued again while the clock does not
    /// judge (the member's offer may be live), each counted once however often it is queued again;
    /// let go once it judges, or once a send has waited a horizon on `M`, each counted
    /// ([`Sharing::unaddressed`]).
    requeued: AtomicU64,
    unaddressed: AtomicU64,
    /// Parity chunks by sender, then manifest, until the parity is whole, each allocation charged
    /// to the room before it is made ([`Assembly`]); what one sender holds is read from its own
    /// charges and held to its part of the room ([`Sender`]).
    assembling: Mutex<Assembly>,
    /// The room parities are reassembled in, apart from the batch store
    /// (`budget::Budget::parity_assembly`): every parity being reassembled is charged to it, within
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
/// gauge (`budget::Store::Batches`, the store of what sharing holds) for what its record allocates
/// (`Record::allocated`) while it waits, the charge handed on with it so whoever holds it next
/// holds it charged; its slot in the outbox is the outbox's ([`Outbox`]). A piece shares its bytes
/// with the record its group holds, so this counts them again while the send waits: never less
/// than what is held.
#[derive(Debug)]
pub struct Addressed {
    pub to: PublicKey,
    pub record: Record,
    pub charge: Charge,
    /// Once it was first queued again for want of its member's address (`Sharing::unaddressed`),
    /// when it is let go, by `M`: a horizon after, past which its member keeps nothing of what it
    /// carries. None while it was never queued again.
    pub unaddressed_until: Option<MonoDeadline>,
}

/// What a parity of `len` bytes costs the outbox at most while its chunks wait there
/// (`budget::Plan`): its bytes, and for each chunk (`ParityChunk::chunks`, one for an empty
/// parity) its stripes' lengths and its slot, the outbox's deque keeping a quarter again what it
/// holds ([`Outbox`], beside the [`OUTBOX_FIXED_BYTES`] it may keep more).
pub const fn outbox_parity_bytes(len: usize) -> usize {
    let chunks = if len == 0 {
        1
    } else {
        len.div_ceil(tally_wire::sharing::MAX_PARITY_CHUNK)
    };
    len + chunks
        * (footprint::vec::<u32>(stripes::DATA_STRIPES as usize)
            + (footprint::vec::<Addressed>(1) * 5).div_ceil(4))
}

/// What the outbox's deque may keep beyond a quarter again what it holds (`Deque::LEAST`
/// slots), whatever it holds.
pub const OUTBOX_FIXED_BYTES: usize = footprint::vec::<Addressed>(Deque::<Addressed>::LEAST);

/// The addressed sends waiting for their links ([`Sharing::take_outbox`]), oldest first: each
/// send's record charged what it allocates (`Record::allocated`, the charge handed on with it,
/// [`Addressed`]), and the queue's slots what they allocate (`footprint::Deque`, which gives back
/// what a drained queue no longer needs), both to the one batch byte store's gauge before they
/// grow. Before, a send was charged its encoded length (which its record's allocations may pass,
/// and which for a batch was only its place) and the queue's slots, grown by doubling, nothing.
#[derive(Default)]
struct Outbox {
    queued: Deque<Addressed>,
    slots: Charge,
}

impl Outbox {
    /// Queues `record` for `to`, its slot and then its record charged to `gauge` first: false,
    /// and nothing queued or charged, when the store's share has no room for either.
    fn push(&mut self, gauge: &Arc<Gauge>, to: PublicKey, record: Record) -> bool {
        if self.queued.is_empty() && self.slots.bytes() == 0 {
            // Charged to the store's gauge as it is now (`Sharing::charge_to`).
            self.slots = gauge.empty();
        }
        if !self.slots.try_grow(self.queued.growth()) {
            return false;
        }
        let Some(charge) = gauge.try_charge(record.allocated()) else {
            self.settle();
            return false;
        };
        self.queued.push_back(Addressed {
            to,
            record,
            charge,
            unaddressed_until: None,
        });
        self.settle();
        true
    }

    /// Queues `message` for `to`, charged before it is queued: past the store's share a send is
    /// refused, and the member it was for repairs what it lacks. A parity's chunks each go alone,
    /// as each is a record a member reassembles. The sends refused.
    fn push_message(&mut self, gauge: &Arc<Gauge>, to: PublicKey, message: Message) -> u64 {
        let mut refused = 0;
        for record in to_records(message) {
            if !self.push(gauge, to, record) {
                refused += 1;
            }
        }
        refused
    }

    /// Sends taken and not carried, queued again with the charges they hold, each slot charged as
    /// a push's is: the number refused for want of a slot.
    fn requeue(&mut self, gauge: &Arc<Gauge>, sent: Vec<Addressed>) -> u64 {
        let mut refused = 0;
        for addressed in sent {
            if self.queued.is_empty() && self.slots.bytes() == 0 {
                self.slots = gauge.empty();
            }
            if self.slots.try_grow(self.queued.growth()) {
                self.queued.push_back(addressed);
            } else {
                refused += 1;
            }
        }
        self.settle();
        refused
    }

    /// Every send queued, taken in order; the queue allocates nothing after.
    fn take(&mut self) -> Vec<Addressed> {
        let taken = Vec::from(self.queued.take());
        self.settle();
        taken
    }

    /// The slots' charge brought down to what they allocate.
    fn settle(&mut self) {
        self.slots.shrink_to(self.queued.bytes());
        debug_assert_eq!(self.slots.bytes(), self.queued.bytes());
    }

    /// What it allocates now, its slots and each send's record: for a test, to hold its charges
    /// to it.
    #[cfg(test)]
    fn allocated(&self) -> usize {
        self.queued.bytes()
            + self
                .queued
                .iter()
                .map(|addressed| addressed.record.allocated())
                .sum::<usize>()
    }
}

/// The parities being reassembled, by sender ([`Sharing::parity_chunk`]): the senders' tree, its
/// allocation charged to the room before it grows, and each sender's own.
#[derive(Default)]
struct Assembly {
    senders: Tree<PublicKey, Sender>,
    tree: Charge,
}

impl Assembly {
    /// `chunk` from `key`, ending at `end`, taken into its parity (begun again at a start, whose
    /// whole `room` gave), each allocation charged to `gauge` (the room) and the sender's part
    /// before it is made: the parity once it is whole. A sender holding nothing is let go.
    fn take(
        &mut self,
        gauge: &Arc<Gauge>,
        key: PublicKey,
        chunk: ParityChunk,
        room: Option<usize>,
        end: usize,
        now_ms: u64,
    ) -> Option<Assembling> {
        if !self.senders.contains_key(&key) {
            // Only a start begins a sender: a stray chunk holds nothing.
            room?;
            if self.senders.is_empty() && self.tree.bytes() == 0 {
                self.tree = gauge.empty();
            }
            if !self.tree.try_grow(self.senders.growth()) {
                return None;
            }
            self.senders.insert(
                key,
                Sender {
                    parities: Tree::new(),
                    tree: gauge.empty(),
                },
            );
        }
        let whole = self
            .senders
            .get_mut(&key)
            .and_then(|sender| sender.take(gauge, chunk, room, end, now_ms));
        if self
            .senders
            .get(&key)
            .is_some_and(|sender| sender.parities.is_empty())
        {
            self.senders.remove(&key);
        }
        self.settle();
        whole
    }

    /// The parities past their wait let go, and the senders left holding nothing.
    fn expire(&mut self, now_ms: u64) {
        self.senders.retain(|_, sender| {
            sender.expire(now_ms);
            !sender.parities.is_empty()
        });
        self.settle();
    }

    /// The tree's charge brought down to what it allocates.
    fn settle(&mut self) {
        self.tree.shrink_to(self.senders.bytes());
    }

    /// What it allocates now, read from every sender and parity: for a test, to hold the room's
    /// charge to it.
    #[cfg(test)]
    fn allocated(&self) -> usize {
        self.senders.bytes()
            + self
                .senders
                .values()
                .map(|sender| {
                    sender.parities.bytes()
                        + sender
                            .parities
                            .values()
                            .map(Assembling::allocated)
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
}

/// One sender's parities being reassembled, held to its part of the room ([`sender_part`] of the
/// room's limit as it is now, so a resized room resizes every part): its parities' tree charged
/// to the room before it grows, as each parity is, and what it holds read from those charges.
struct Sender {
    parities: Tree<tally_wire::batch::Hash, Assembling>,
    tree: Charge,
}

impl Sender {
    /// What it holds of the room: its tree and its parities, as charged.
    fn held(&self) -> usize {
        self.tree.bytes()
            + self
                .parities
                .values()
                .map(|held| held.charge.bytes())
                .sum::<usize>()
    }

    /// Whether `bytes` more stay within its part of `gauge`.
    fn fits(&self, gauge: &Gauge, bytes: usize) -> bool {
        self.held().saturating_add(bytes) <= sender_part(gauge.limit())
    }

    /// `chunk`, ending at `end`, taken into its parity (begun again at a start, whose whole
    /// `room` gave): the parity once it is whole. Past the room or this sender's part, or out of
    /// its place, the parity is let go whole.
    fn take(
        &mut self,
        gauge: &Arc<Gauge>,
        mut chunk: ParityChunk,
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
            self.settle();
        }
        if !self.parities.contains_key(&manifest) {
            // No parity begun: a stray chunk.
            let total = room?;
            let mut started = Assembling {
                first: ParityChunk {
                    bytes: Vec::new(),
                    lens: chunk.lens.clone(),
                    ..chunk
                },
                total,
                pieces: Deque::new(),
                filled: 0,
                charge: gauge.empty(),
                started_ms: now_ms,
            };
            let place = self.parities.growth();
            let own = started.allocated();
            if !self.fits(gauge, place + own) || !self.tree.try_grow(place) {
                return None;
            }
            if !started.charge.try_grow(own) {
                self.settle();
                return None;
            }
            self.parities.insert(manifest, started);
        }
        let bytes = footprint::exact(std::mem::take(&mut chunk.bytes));
        let growth = self
            .parities
            .get(&manifest)
            .map_or(0, |held| held.pieces.growth())
            + footprint::vec::<u8>(bytes.capacity());
        let fits = self.fits(gauge, growth);
        let held = self.parities.get_mut(&manifest)?;
        let next = usize::try_from(chunk.offset).is_ok_and(|offset| offset == held.filled)
            && held.agrees(&chunk)
            && fits
            && held.charge.try_grow(growth);
        if !next {
            self.parities.remove(&manifest);
            self.settle();
            return None;
        }
        held.filled = end;
        held.pieces.push_back(bytes);
        if held.filled < held.total {
            return None;
        }
        let whole = self.parities.remove(&manifest);
        self.settle();
        whole
    }

    /// The parities past their wait let go.
    fn expire(&mut self, now_ms: u64) {
        self.parities
            .retain(|_, held| held.started_ms + PARITY_ASSEMBLY_MS > now_ms);
        self.settle();
    }

    /// The tree's charge brought down to what it allocates.
    fn settle(&mut self) {
        self.tree.shrink_to(self.parities.bytes());
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
    /// The chunks received, in order, each where the last ended, each made exactly as long.
    pieces: Deque<Vec<u8>>,
    /// The bytes `pieces` hold: where the next chunk starts.
    filled: usize,
    /// What it allocates ([`Assembling::allocated`]), charged to the room before it grows, within
    /// its sender's part.
    charge: Charge,
    /// When its first chunk came, by `M`: what it is let go by.
    started_ms: u64,
}

impl Assembling {
    /// Whether `chunk` is a piece of the same parity as the first.
    fn agrees(&self, chunk: &ParityChunk) -> bool {
        chunk.total == self.first.total
            && chunk.cell == self.first.cell
            && chunk.product == self.first.product
            && chunk.second == self.first.second
            && chunk.lens == self.first.lens
    }

    /// What it allocates of its own (its place in its sender's tree is the tree's): the first
    /// chunk's lengths, its pieces' slots and each piece's bytes.
    fn allocated(&self) -> usize {
        footprint::vec::<u32>(self.first.lens.capacity())
            + self.pieces.bytes()
            + self
                .pieces
                .iter()
                .map(|piece| footprint::vec::<u8>(piece.capacity()))
                .sum::<usize>()
    }

    /// Every byte held, in order: the parity whole.
    fn whole(self) -> Option<(ParityChunk, Vec<u8>)> {
        if self.filled != self.total {
            return None;
        }
        let mut xor = Vec::with_capacity(self.total);
        for piece in self.pieces.iter() {
            xor.extend_from_slice(piece);
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
            requeued: AtomicU64::new(0),
            unaddressed: AtomicU64::new(0),
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
    /// offer would make it. Only for a group this relay holds (an area it takes, one of the
    /// products it shares), and only while the store has room for the ask (`Groups::admit`):
    /// before, any cell an asker named was booked, uncharged.
    pub fn assigned(&self, asker: &Asker, assignment: StripeAssignment, now: impl Into<Now>) {
        if asker.role != AskerRole::Relay
            || assignment.cell.resolution() != AREA_RESOLUTION
            || !SHARED_PRODUCTS.contains(&assignment.product)
            || !self.takes_area(assignment.cell)
        {
            return;
        }
        let now = now.into();
        let group = GroupKey::new(assignment.cell, assignment.product);
        if !self
            .groups
            .admit(group, asker.key, now.after(ASK_LIFETIME_MS), false)
        {
            return;
        }
        self.drive(asker, Message::Assign(assignment), now)
    }

    /// An origin's manifest of one second, passed on to the group.
    pub fn manifest(&self, asker: &Asker, manifest: PieceManifest, now: impl Into<Now>) {
        if asker.role != AskerRole::Relay {
            return;
        }
        self.drive(asker, Message::Manifest(manifest), now.into())
    }

    /// A member's have-summary: answered with what it lacks, paged, as data, over this relay's
    /// own member link to it (the outbox). Only a member the group's trees hold (by its verified
    /// offer), and not demoted, is answered.
    pub fn have(&self, asker: &Asker, have: HaveSummary, now: impl Into<Now>) {
        if asker.role != AskerRole::Relay {
            return;
        }
        self.drive(asker, Message::Have(have), now.into())
    }

    /// A child's receipt (this relay's evidence, which `credit` keeps), or a member's report of
    /// a shortfall, which may demote the member it names.
    pub fn receipt(&self, asker: &Asker, receipt: StripeReceipt, now: impl Into<Now>) {
        if asker.role != AskerRole::Relay {
            return;
        }
        self.drive(asker, Message::Receipt(receipt), now.into())
    }

    /// A record this relay originated for an area's product (a feeder's batch, its own
    /// positions): held, and seeded into the group. Only in an area it takes: a group of any
    /// other has no tree this relay is in. Whether it is usable here (`strikes`) is no question
    /// of the group's: possession never reads a clock.
    pub fn originate(&self, record: &Record, cell: Region, product: Streams, now: impl Into<Now>) {
        if !self.takes_area(cell) {
            return;
        }
        let Some((hash, piece)) = encoded(record) else {
            return;
        };
        let group = GroupKey::new(cell, product);
        let now = now.into();
        let out = self.with_member(|member| member.originate(group, hash, piece, now));
        self.queue(out.unwrap_or_default());
    }

    /// A group record a member sent this relay: held and pushed on down its stripe, whether or
    /// not it is usable here (possession never reads a clock).
    pub fn received(
        &self,
        from: &PublicKey,
        record: &Record,
        cell: Region,
        product: Streams,
        now: impl Into<Now>,
    ) {
        let now = now.into();
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
            member.receive(*from, message, now)
        });
        self.queue(out.unwrap_or_default());
    }

    /// A record its group rebuilt from parity, which this relay judged and took in
    /// (`Hub::take_rebuilt`) as `record`: held as taken in, as a member's piece is (an admitted
    /// batch charged only its place), and pushed on down its stripe now (`Member::pass_on`).
    pub fn passed_on(&self, rebuilt: Rebuilt, record: &Record, now_ms: u64) {
        let Some(piece) = Piece::of(record) else {
            return self.let_go(rebuilt);
        };
        let out =
            self.with_member(|member| member.pass_on(rebuilt.group, rebuilt.hash, piece, now_ms));
        self.queue(out.unwrap_or_default());
    }

    /// A record its group rebuilt from parity that this relay could not take in (no room): let
    /// go, so the group asks for it again (`Member::let_go`).
    pub fn let_go(&self, rebuilt: Rebuilt) {
        self.with_member(|member| member.let_go(rebuilt.group, rebuilt.hash));
    }

    /// A record its group rebuilt from parity that this relay judged and refused: let go and
    /// counted as had, never passed on (`Member::refuse`).
    pub fn refused_rebuilt(&self, rebuilt: Rebuilt, now: impl Into<Now>) {
        let now = now.into();
        self.with_member(|member| member.refuse(rebuilt.group, rebuilt.hash, now));
    }

    /// A group record member `from` sent that this relay refused: counted refused, `from` noted
    /// as its deliverer, and pushed on down its stripe unheld (`Member::refused`), so neither
    /// `from` nor this relay is reported short for an origin's malformed record.
    pub fn refused(
        &self,
        from: PublicKey,
        record: &Record,
        cell: Region,
        product: Streams,
        now: impl Into<Now>,
    ) {
        let now = now.into();
        let Some((hash, piece)) = encoded(record) else {
            return;
        };
        let group = GroupKey::new(cell, product);
        let out = self.with_member(|member| member.refused(from, group, (hash, piece), now));
        self.queue(out.unwrap_or_default());
    }

    /// A record of `cell`'s `product` group that member `from` delivered and this relay had no
    /// room to take in (`strikes::Verdict::Full`): `from` credited for it, nothing held
    /// (`Member::credit`).
    pub fn credit(
        &self,
        from: PublicKey,
        record: &Record,
        cell: Region,
        product: Streams,
        now: impl Into<Now>,
    ) {
        let now = now.into();
        let Some((hash, piece)) = encoded(record) else {
            return;
        };
        self.with_member(|member| {
            member.credit(from, GroupKey::new(cell, product), (hash, piece.len()), now);
        });
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
    pub fn parity_chunk(&self, asker: &Asker, chunk: ParityChunk, now: impl Into<Now>) {
        use tally_wire::sharing::MAX_PARITY_CHUNK;
        let now = now.into();
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
            // Held for its wait by `M`, as everything the relay holds is (`member::Now`).
            assembling.take(&gauge, asker.key, chunk, room, end, now.mono_ms())
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
        self.drive(asker, Message::Parity(Arc::new(parity)), now)
    }

    /// This relay turned `key`'s member link away as full at `now` (its wait kept on `M`), asking it to stay away
    /// `asked` (`link`, every `Goodbye` of reason `Full` it sends a relay): that relay routes its
    /// slice past this one for the wait the one rule gives (`full::Wait`), so no shortfall is filed
    /// against it for those windows (`Member::turned_away`).
    pub fn turned_away(&self, key: PublicKey, asked: std::time::Duration, now: impl Into<Now>) {
        let now = now.into();
        self.with_member(|member| member.turned_away(key, asked, now));
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
        self.groups.charge_to(&gauge);
        if let Some(member) = lock(&self.member).as_mut() {
            member.charge_to(gauge);
        }
    }

    /// The parities being reassembled are charged to `room` from now on
    /// (`budget::Budget::parity_assembly`, sized by [`assembly_room`]), each sender's held to its
    /// part of it ([`sender_part`] of its limit as it is then): a room apart from the batch store,
    /// so no sender's chunks take the room of what the groups hold. What is already reassembling
    /// stays charged to the room it was charged to until it is let go.
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
        let queued = lock(&self.outbox).push(&gauge, to, record);
        if !queued {
            self.outbox_refused.fetch_add(1, Ordering::Relaxed);
        }
        queued
    }

    /// The addressed sends waiting for their links, each with its charge, which whoever carries it
    /// holds until it is written ([`Addressed`]).
    pub fn take_outbox(&self) -> Vec<Addressed> {
        lock(&self.outbox).take()
    }

    /// Sends taken from the outbox for a member no address is held for (`network::Network::carry`):
    /// while the clock does not judge (`now` not judging), queued again with the charges they
    /// hold, to be carried once its offer can be read, each for at most the group's horizon on `M`
    /// from when it was first queued again (`Deadlines::horizon_ms`: past it, its member keeps
    /// nothing of what it carries); once the clock judges, or past that, let go. Each counted once
    /// as queued again however often it is, and once let go; one the outbox's slots have no room
    /// for is refused as any send is.
    pub fn unaddressed(&self, sent: Vec<Addressed>, now: Now) {
        let mut waiting = Vec::with_capacity(sent.len());
        let (mut first, mut let_go) = (0, 0);
        for mut addressed in sent {
            match addressed.unaddressed_until {
                _ if now.judging() => let_go += 1,
                Some(until) if until.passed(now) => let_go += 1,
                Some(_) => waiting.push(addressed),
                None => {
                    addressed.unaddressed_until = Some(now.after(self.deadlines.horizon_ms()));
                    first += 1;
                    waiting.push(addressed);
                }
            }
        }
        self.unaddressed.fetch_add(let_go, Ordering::Relaxed);
        self.requeued.fetch_add(first, Ordering::Relaxed);
        if waiting.is_empty() {
            return;
        }
        let gauge = Arc::clone(&lock(&self.gauge));
        let refused = lock(&self.outbox).requeue(&gauge, waiting);
        self.outbox_refused.fetch_add(refused, Ordering::Relaxed);
    }

    /// The sends queued again for want of an address while the clock did not judge (each once),
    /// and those let go for it (the clock judging, or a horizon waited), since start
    /// ([`Sharing::unaddressed`]).
    pub fn unaddressed_counts(&self) -> (u64, u64) {
        (
            self.requeued.load(Ordering::Relaxed),
            self.unaddressed.load(Ordering::Relaxed),
        )
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

    /// What the tick hands on now: records rebuilt from parity (new to this relay), and the bundle
    /// indexes due ([`Ticked`]). Manifests, receipts, assignments and repairs are addressed, and
    /// wait in the outbox. Membership is refreshed first, from the areas this relay takes and the
    /// live offers for them, and the regions it forwards in from what its egress has shed.
    pub fn tick(&self, hub: &Hub, signer: Option<&Signer>, now: impl Into<Now>) -> Ticked {
        let shed = forwarders_shed(&hub.egress().report());
        self.tick_shed(hub, signer, shed, now)
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
        signer: Option<&Signer>,
        shed: u64,
        now: impl Into<Now>,
    ) -> Ticked {
        let now = now.into();
        let now_ms = now.judged().ms();
        let Some(signer) = signer else {
            return Ticked::default();
        };
        let me = signer.public();
        let network = hub.network();
        let taken = network.selection.taken_index();
        let withdrawal = {
            let mut withdrawal = lock(&self.withdrawal);
            withdrawal.observe(shed, taken.regions(), &me, now);
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
        lock(&self.assembling).expire(now.mono_ms());
        let mut guard = lock(&self.member);
        let gauge = Arc::clone(&lock(&self.gauge));
        let fresh = || Member::new(signer.clone(), Arc::clone(&gauge), self.deadlines);
        let member = guard.get_or_insert_with(fresh);
        if member.key() != me {
            *member = fresh();
        }
        // The members that turned this relay's links away as full, while they are: routed around
        // (`Member::route`) until their wait ends.
        member.set_full(network.peers.full(now));
        // The areas whose trees may have changed.
        let directory = &network.directory;
        // More cells changed than the directory remembers between two looks: every one is taken
        // as changed, as when what the relay takes moves.
        let (changed, all_changed) = match directory.take_changed(now.judged()) {
            crate::directory::Changed::Cells(cells) => (cells, false),
            crate::directory::Changed::All => (Vec::new(), true),
        };
        let mut areas: BTreeSet<u64> = std::mem::take(&mut *lock(&self.relayout));
        for key in self.groups.expire(now) {
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
        if taken_moved || withdrawn_moved || all_changed {
            known(&mut areas, member, None);
        }
        let cells = if taken_moved || all_changed {
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
                .offers_for(area, now.judged())
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
                out.extend(member.set_members(key, &members, &leaves, now));
            }
        }
        self.laid_out.fetch_add(laid_out, Ordering::Relaxed);
        out.extend(member.tick(now));
        let demotions = member.take_demotions();
        if !demotions.is_empty() {
            let mut relayout = lock(&self.relayout);
            for (group, demoted, until) in demotions {
                self.groups.demote(group, demoted, until);
                relayout.insert(group.cell.as_u64());
            }
        }
        // Signed only while the relay's clock is synced; the seconds wait until it is.
        let indexes = crate::signer::with(signer, now, |signing| {
            signing
                .map(|identity| self.bundle_indexes(member, identity, now_ms))
                .unwrap_or_default()
        });
        let (rebuilt, unreadable) = rebuilt_of(member);
        drop(guard);
        self.queue(out);
        Ticked {
            rebuilt,
            unreadable,
            published: indexes.into_iter().map(Record::BundleIndex).collect(),
        }
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
        identity: &impl Signs,
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
    fn drive(&self, asker: &Asker, message: Message, now: Now) {
        // A message about a group of an area this relay takes is the group's, held or not.
        let joins = message.group().filter(|group| self.takes_area(group.cell));
        let out = self
            .with_member(|member| {
                if let Some(group) = joins {
                    member.join(group);
                }
                member.receive(asker.key, message, now)
            })
            .unwrap_or_default();
        self.queue(out);
    }

    fn with_member<T>(&self, act: impl FnOnce(&mut Member) -> T) -> Option<T> {
        lock(&self.member).as_mut().map(act)
    }

    /// A test's areas taken, as a tick would read them from the selection (`tick_shed`).
    #[cfg(test)]
    pub(crate) fn take_areas_for_test(&self, areas: Vec<Region>) {
        lock(&self.view).taken = Arc::new(Taken::of(areas));
    }

    /// A test's hand on this relay's member (made by a tick, `tick_shed`).
    #[cfg(test)]
    pub(crate) fn member_for_test<T>(&self, act: impl FnOnce(&mut Member) -> T) -> Option<T> {
        self.with_member(act)
    }

    /// A test's group set up to rebuild `records[0]`'s data stripe: `members` (this relay among
    /// them), a manifest of every record signed and sent by `signer` (a member), every record
    /// outside that stripe sent by `signer`, and the parity of them all sent by `parity_from`, all
    /// of `second`. The stripe it lacks, rebuilt by the member's next tick past `second`'s
    /// rebuild wait.
    #[cfg(test)]
    pub(crate) fn fill_for_rebuild(
        &self,
        group: GroupKey,
        members: &[PublicKey],
        (signer, parity_from): (&tally_wire::Identity, PublicKey),
        records: &[Record],
        second: u64,
        now_ms: u64,
    ) -> Result<u8, String> {
        let pieces: Vec<(tally_wire::batch::Hash, Piece)> = records
            .iter()
            .map(|record| encoded(record).ok_or("no piece"))
            .collect::<Result<_, _>>()?;
        let lost = stripes::data_stripe(&pieces.first().ok_or("no records")?.0);
        let mut hashes: Vec<_> = pieces.iter().map(|(hash, _)| *hash).collect();
        hashes.sort();
        let manifest = PieceManifest::sign(
            signer,
            &tally_wire::PieceManifestContent {
                cell: group.cell,
                product: group.product,
                second,
                hashes,
            },
        )
        .map_err(|error| error.to_string())?;
        let views: Vec<_> = pieces.iter().map(|(hash, piece)| (*hash, piece)).collect();
        let parity =
            parity::Parity::build(manifest.hash(), group.cell, group.product, second, &views);
        let from = signer.public();
        self.with_member(|member| {
            let _ = member.set_members(group, members, &[], now_ms);
            let _ = member.receive(from, Message::Manifest(manifest), now_ms);
            for (hash, piece) in &pieces {
                if stripes::data_stripe(hash) != lost {
                    let message = Message::Piece {
                        group,
                        hash: *hash,
                        piece: piece.clone(),
                    };
                    let _ = member.receive(from, message, now_ms);
                }
            }
            let _ = member.receive(parity_from, Message::Parity(Arc::new(parity)), now_ms);
        })
        .ok_or("no member")?;
        Ok(lost)
    }

    /// A test's tick of the member alone, its membership as the test set it (the whole tick
    /// lays the groups out again from the directory): what it addresses is queued, and what it
    /// rebuilt is handed on as the tick hands it ([`Ticked::rebuilt`]).
    #[cfg(test)]
    pub(crate) fn tick_member_for_test(&self, now_ms: u64) -> Vec<(Rebuilt, Record)> {
        let mut guard = lock(&self.member);
        let Some(member) = guard.as_mut() else {
            return Vec::new();
        };
        let out = member.tick(now_ms);
        let (rebuilt, _) = rebuilt_of(member);
        drop(guard);
        self.queue(out);
        rebuilt
    }

    fn queue(&self, out: Vec<Outgoing>) {
        if out.is_empty() {
            return;
        }
        let gauge = Arc::clone(&lock(&self.gauge));
        let mut refused = 0;
        let mut outbox = lock(&self.outbox);
        for outgoing in out {
            refused += outbox.push_message(&gauge, outgoing.to, outgoing.message);
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
/// - Positions: the area of the record's first fix, product `POSITIONS` (an engine's fixes are
///   of the transmissions its own areas' hearers heard most, so a record is nearly always one
///   area's).
/// - A clock model manifest: the area its model names (`point`, from its inline bytes or its
///   first part, `publish::area_of`), product `CLOCK_MODELS`. Its parts are in no group: every member link carries a
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
        Record::Positions(positions) => {
            let solved = crate::network::solved(positions)?;
            let first = solved.first()?;
            let point = Region::point(&tally_wire::Location {
                lat_e7: first.lat_e7,
                lon_e7: first.lon_e7,
                alt_m: 0,
                precision_m: 0,
            })
            .ok()?;
            Some((area_at(point)?, Streams::POSITIONS))
        }
        // A client clock model with its full model: placed by the full model's area (`point`).
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

/// What `member` rebuilt from parity since it was last asked, each with the group that holds it
/// ([`Rebuilt`]), for its relay to judge ([`Ticked::rebuilt`]); apart, those whose bytes are no
/// record, which no intake can judge and its relay refuses ([`Ticked::unreadable`]).
fn rebuilt_of(member: &mut Member) -> (Vec<(Rebuilt, Record)>, Vec<Rebuilt>) {
    let (mut rebuilt, mut unreadable) = (Vec::new(), Vec::new());
    for delivered in member.take_delivered() {
        if delivered.arrival != Arrival::Rebuilt {
            continue;
        }
        let handle = Rebuilt {
            group: delivered.group,
            hash: delivered.hash,
        };
        match delivered.piece.record() {
            Some(record) => rebuilt.push((handle, record)),
            None => unreadable.push(handle),
        }
    }
    (rebuilt, unreadable)
}
