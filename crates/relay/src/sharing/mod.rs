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
//!
//! [`Sharing`] is the network seam's face of it: the records links hand in, what this relay
//! originates ([`Sharing::originate`]) and members send it ([`Sharing::received`]), parity chunks
//! reassembled ([`Sharing::parity_chunk`]), what the tick publishes (records rebuilt, bundle
//! indexes), and what it addresses to members ([`Sharing::take_outbox`]), which `network` carries
//! down a session to each (`peers`). [`group_of`] is the one rule for which group a record is in.
//!
//! What the seam hands back to an asker ([`DataReplies`]) is data, never control: a repair page is
//! manifests, parity and records, and the link sends it as data, paced and capped like any other
//! record of its class (`egress`), so an asker cannot draw the control reserve by asking.

pub mod bundles;
pub mod groups;
pub mod locks;
pub mod member;
pub mod parity;
pub mod seeds;
pub mod stripes;
pub mod withdrawal;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tally_wire::{
    BundleIndex, BundleIndexContent, HaveSummary, Identity, ParityChunk, PieceManifest, PublicKey,
    Record, Region, Streams, StripeAssignment, StripeReceipt,
};

use crate::egress::{Class, EgressReport};
use crate::hub::Hub;
use crate::network::{Asker, AskerRole};

use self::groups::{ASK_LIFETIME_MS, GroupKey};
use self::locks::lock;
use self::member::{Arrival, HORIZON_SECONDS, Member, Message, Outgoing, record_hash};
use self::withdrawal::Withdrawal;

pub use self::seeds::{SEED_COPIES, seeded_bytes};

/// Records of data the seam sends back down the asker's link: a repair page (manifests, parity
/// chunks and records). The link sends them as data, each in its own egress class under the
/// cap, never as control.
pub type DataReplies = Vec<Record>;

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

/// The most addressed sends held for the links before the oldest are dropped.
pub const OUTBOX_MAX: usize = 65_536;
/// Parities being reassembled from their chunks at once, at most, and bytes in all.
pub const PARITIES_ASSEMBLING: usize = 256;
pub const PARITY_BYTES_ASSEMBLING: usize = 64 << 20;
/// How long a parity may take to arrive whole from its first chunk: its chunks are sent together,
/// so one still missing a piece after this never will be.
pub const PARITY_ASSEMBLY_MS: u64 = 10 * 1000;
/// How long after a second ends a bundle index over it is signed: its manifests are in by then.
pub const BUNDLE_INDEX_AFTER_SECONDS: u64 = 3;

#[derive(Default)]
pub struct Sharing {
    pub groups: groups::Groups,
    pub bundles: bundles::Bundles,
    member: Mutex<Option<Member>>,
    outbox: Mutex<Vec<(PublicKey, Record)>>,
    /// Parity chunks by (sender, manifest), until the parity is whole.
    assembling: Mutex<HashMap<(PublicKey, tally_wire::batch::Hash), Assembling>>,
    /// The last second bundle indexes were signed for.
    indexed_through: Mutex<Option<u64>>,
    /// The regions this relay has withdrawn from forwarding in.
    withdrawal: Mutex<Withdrawal>,
}

struct Assembling {
    /// The first chunk, without its bytes: what every later chunk must agree with.
    first: ParityChunk,
    bytes: Vec<u8>,
    /// The byte ranges written, disjoint and merged (start to end), and how many bytes they cover.
    covered: BTreeMap<usize, usize>,
    filled: usize,
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

    /// Writes `bytes` at `start`; how many bytes it covered that no earlier chunk had. `None` past
    /// the end.
    fn write(&mut self, start: usize, bytes: &[u8]) -> Option<usize> {
        let end = start.checked_add(bytes.len())?;
        self.bytes.get_mut(start..end)?.copy_from_slice(bytes);
        let fresh = cover(&mut self.covered, start, end);
        self.filled += fresh;
        Some(fresh)
    }
}

/// Adds `start..end` to `covered` (disjoint ranges, start to end), merging what it touches; the
/// bytes of it not covered before.
fn cover(covered: &mut BTreeMap<usize, usize>, start: usize, end: usize) -> usize {
    if start >= end {
        return 0;
    }
    let touching: Vec<(usize, usize)> = covered
        .range(..=end)
        .filter(|(_, until)| **until >= start)
        .map(|(from, until)| (*from, *until))
        .collect();
    let mut merged = (start, end);
    let mut before = 0;
    for (from, until) in touching {
        covered.remove(&from);
        before += until.min(end).saturating_sub(from.max(start));
        merged = (merged.0.min(from), merged.1.max(until));
    }
    covered.insert(merged.0, merged.1);
    (end - start) - before
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
    pub fn new() -> Self {
        Self::default()
    }

    /// A member asking this relay for stripes: it is a member of the group for a while, as its
    /// offer would make it.
    pub fn assigned(
        &self,
        asker: &Asker,
        assignment: StripeAssignment,
        now_ms: u64,
    ) -> DataReplies {
        if asker.role != AskerRole::Relay {
            return Vec::new();
        }
        let group = GroupKey::new(assignment.cell, assignment.product);
        self.groups
            .admit(group, asker.key, now_ms + ASK_LIFETIME_MS, false);
        self.drive(asker, Message::Assign(assignment), now_ms)
    }

    /// An origin's manifest of one second, passed on to the group.
    pub fn manifest(&self, asker: &Asker, manifest: PieceManifest, now_ms: u64) -> DataReplies {
        if asker.role != AskerRole::Relay {
            return Vec::new();
        }
        self.drive(asker, Message::Manifest(manifest), now_ms)
    }

    /// A member's have-summary: answered down its link with what it lacks, paged, as data. Only a
    /// member the group's trees hold (by its verified offer), and not demoted, is answered.
    pub fn have(&self, asker: &Asker, have: HaveSummary, now_ms: u64) -> DataReplies {
        if asker.role != AskerRole::Relay {
            return Vec::new();
        }
        self.drive(asker, Message::Have(have), now_ms)
    }

    /// A child's receipt (this relay's evidence, which `credit` keeps), or a member's report of
    /// a shortfall, which may demote the member it names.
    pub fn receipt(&self, asker: &Asker, receipt: StripeReceipt, now_ms: u64) -> DataReplies {
        if asker.role != AskerRole::Relay {
            return Vec::new();
        }
        self.drive(asker, Message::Receipt(receipt), now_ms)
    }

    /// A record this relay originated for an area's product (a feeder's batch, its own
    /// positions): held, and seeded into the group.
    pub fn originate(&self, record: &Record, cell: Region, product: Streams, now_ms: u64) {
        let Some((hash, bytes)) = encoded(record) else {
            return;
        };
        let out = self.with_member(|member| {
            member.originate(GroupKey::new(cell, product), hash, bytes, now_ms)
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
        let Some((hash, bytes)) = encoded(record) else {
            return;
        };
        let message = Message::Piece {
            group: GroupKey::new(cell, product),
            hash,
            bytes,
        };
        let out = self.with_member(|member| member.receive(*from, message, now_ms));
        self.queue(out.unwrap_or_default());
    }

    /// A chunk of a parity a member sent: held until the parity is whole, then taken in as the
    /// member's parity.
    pub fn parity_chunk(&self, asker: &Asker, chunk: ParityChunk, now_ms: u64) -> DataReplies {
        if asker.role != AskerRole::Relay {
            return Vec::new();
        }
        let whole = {
            let mut assembling = lock(&self.assembling);
            assembling.retain(|_, held| held.started_ms + PARITY_ASSEMBLY_MS > now_ms);
            let key = (asker.key, chunk.manifest);
            let Ok(total) = usize::try_from(chunk.total) else {
                return Vec::new();
            };
            let held_bytes: usize = assembling.values().map(|held| held.bytes.len()).sum();
            if !assembling.contains_key(&key)
                && (assembling.len() >= PARITIES_ASSEMBLING
                    || held_bytes.saturating_add(total) > PARITY_BYTES_ASSEMBLING
                    || chunk.second.saturating_add(HORIZON_SECONDS) < now_ms / 1000)
            {
                return Vec::new();
            }
            let held = assembling.entry(key).or_insert_with(|| Assembling {
                bytes: vec![0; total],
                covered: BTreeMap::new(),
                filled: 0,
                started_ms: now_ms,
                first: ParityChunk {
                    bytes: Vec::new(),
                    ..chunk.clone()
                },
            });
            let Ok(start) = usize::try_from(chunk.offset) else {
                return Vec::new();
            };
            if !held.agrees(&chunk) || held.write(start, &chunk.bytes).is_none() {
                return Vec::new();
            }
            if held.filled < held.bytes.len() {
                return Vec::new();
            }
            assembling.remove(&key)
        };
        let Some(whole) = whole else {
            return Vec::new();
        };
        let mut lens = [0u32; stripes::DATA_STRIPES as usize];
        if whole.first.lens.len() != lens.len() {
            return Vec::new();
        }
        lens.copy_from_slice(&whole.first.lens);
        let parity = parity::Parity {
            manifest: whole.first.manifest,
            cell: whole.first.cell,
            product: whole.first.product,
            second: whole.first.second,
            lens,
            xor: whole.bytes,
        };
        self.drive(asker, Message::Parity(Arc::new(parity)), now_ms)
    }

    /// The addressed sends waiting for their links: (member, record).
    pub fn take_outbox(&self) -> Vec<(PublicKey, Record)> {
        std::mem::take(&mut *lock(&self.outbox))
    }

    /// The cells this relay may offer as bundles now (§2.6).
    pub fn bundle_offers(&self) -> Vec<Region> {
        self.bundles.offerable()
    }

    /// The group trees as this relay sees them (none before it serves).
    pub fn layout(&self, cell: Region, product: Streams) -> Option<stripes::Layout> {
        lock(&self.member)
            .as_ref()?
            .layout(GroupKey::new(cell, product))
            .cloned()
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
        let regions = network.selection.taken();
        // Groups are per area (`group_of` routes every record to its area's), whatever the
        // operator named: a region coarser than an area is every area under it.
        let areas = network.selection.taken_areas();
        let withdrawal = {
            let mut withdrawal = lock(&self.withdrawal);
            withdrawal.observe(shed, &regions, &me, now_ms);
            withdrawal.clone()
        };
        let mut offered_cells = regions.clone();
        offered_cells.extend(self.bundles.offerable());
        self.groups.expire(now_ms);
        let mut keys = Vec::new();
        for area in &areas {
            let offers = network.directory.offers_for(*area, now_ms);
            // This relay's offers covering the area say 0 stripes when any overlaps a withdrawn
            // region; it reads itself as every other relay reads those offers.
            let leaf = offered_cells
                .iter()
                .any(|cell| cell.contains(*area) && withdrawal.covers(*cell));
            for product in SHARED_PRODUCTS {
                let key = GroupKey::new(*area, product);
                self.groups.own(key, me, now_ms + ASK_LIFETIME_MS, leaf);
                // Every live, verified offer covering the area for the product, per signer: until
                // the latest expires, and a leaf when any of them forwards nothing here.
                let mut signers: BTreeMap<PublicKey, (u64, bool)> = BTreeMap::new();
                for offer in &offers {
                    let (Ok(content), Ok(signer)) = (offer.content(), offer.signer()) else {
                        continue;
                    };
                    if signer == me
                        || !content.products.contains(product)
                        || crate::directory::expiry(&content) <= now_ms
                        || offer.verify().is_err()
                    {
                        continue;
                    }
                    let held = signers.entry(signer).or_insert((0, false));
                    held.0 = held.0.max(crate::directory::expiry(&content));
                    held.1 |= content.stripes == 0;
                }
                for (signer, (until, leaf)) in signers {
                    self.groups.offered(key, signer, until, leaf);
                }
                keys.push(key);
            }
        }
        self.bundles.set_gathered(&areas);
        lock(&self.assembling).retain(|_, held| held.started_ms + PARITY_ASSEMBLY_MS > now_ms);
        let mut guard = lock(&self.member);
        let member = guard.get_or_insert_with(|| Member::new(identity.clone()));
        if member.key() != me {
            *member = Member::new(identity.clone());
        }
        let mut out = Vec::new();
        for key in member.groups() {
            if !keys.contains(&key) {
                member.leave(key);
            }
        }
        for key in &keys {
            let (members, leaves) = self.groups.tree(*key, now_ms);
            out.extend(member.set_members(*key, &members, &leaves, now_ms));
        }
        out.extend(member.tick(now_ms));
        for (group, demoted, until) in member.take_demotions() {
            self.groups.demote(group, demoted, until);
        }
        let indexes = self.bundle_indexes(member, identity, now_ms);
        let rebuilt: Vec<Record> = member
            .take_delivered()
            .into_iter()
            .filter(|delivered| delivered.arrival == Arrival::Rebuilt)
            .filter_map(|delivered| decoded(&delivered.bytes))
            .collect();
        drop(guard);
        self.queue(out);
        let mut published = rebuilt;
        published.extend(indexes.into_iter().map(Record::BundleIndex));
        published
    }

    /// The bundle indexes due (§2.6): for each parent this relay offers as a bundle and each
    /// shared product, once a second, `BUNDLE_INDEX_AFTER_SECONDS` after it ends, every child with
    /// the digest of the origin manifests held under it.
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
        let parents = self.bundles.offerable();
        let mut out = Vec::new();
        for parent in parents {
            for product in SHARED_PRODUCTS {
                let manifests: Vec<PieceManifest> = member
                    .groups()
                    .into_iter()
                    .filter(|group| group.product == product && parent.contains(group.cell))
                    .flat_map(|group| member.manifests(group, second))
                    .collect();
                let index = bundles::BundleIndex::build(parent, product, second, &manifests);
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

    /// Hands a message to the member; what goes back to the asker is the reply, the rest waits in
    /// the outbox.
    fn drive(&self, asker: &Asker, message: Message, now_ms: u64) -> DataReplies {
        let out = self
            .with_member(|member| member.receive(asker.key, message, now_ms))
            .unwrap_or_default();
        let (reply, rest): (Vec<Outgoing>, Vec<Outgoing>) = out
            .into_iter()
            .partition(|outgoing| outgoing.to == asker.key);
        self.queue(rest);
        reply
            .into_iter()
            .flat_map(|outgoing| to_records(outgoing.message))
            .collect()
    }

    fn with_member<T>(&self, act: impl FnOnce(&mut Member) -> T) -> Option<T> {
        lock(&self.member).as_mut().map(act)
    }

    fn queue(&self, out: Vec<Outgoing>) {
        if out.is_empty() {
            return;
        }
        let mut outbox = lock(&self.outbox);
        outbox.extend(out.into_iter().flat_map(|outgoing| {
            let to = outgoing.to;
            to_records(outgoing.message)
                .into_iter()
                .map(move |record| (to, record))
        }));
        let excess = outbox.len().saturating_sub(OUTBOX_MAX);
        outbox.drain(..excess);
    }
}

/// The group a record belongs to (RFC-0174 §2.5): one rule, the same for its origin and every
/// member, so a record is shared in exactly one group.
///
/// - A receiver's batch: the area (`rendezvous::AREA_RESOLUTION`) of the receiver's signed
///   location (`point`, as the hub projects it), product `RAW`. No located description, no group.
/// - Final or provisional positions: the area of the record's first solution, product
///   `POSITIONS` or `PROVISIONAL` (an engine packs a record's solutions in tile order, so a record
///   is nearly always one area's).
/// - A clock model manifest: the area of its tile's centre (`point`, from its inline bytes or its
///   first part), product `CLOCK_MODELS`. Its parts are in no group: every member link carries a
///   model's parts just before its manifest (`link`'s `Told`).
/// - A regional batch: its cell's area, product `REGIONAL`.
/// - A fault proof: the group of the first solutions record it holds, or of its models.
pub fn group_of(record: &Record, point: Option<Region>) -> Option<(Region, Streams)> {
    let area_at = tally_wire::rendezvous::area_of_cell;
    match record {
        Record::Batch(_) => Some((area_at(point?)?, Streams::RAW)),
        Record::Positions(_) | Record::Provisional(_) => {
            let content = match record {
                Record::Positions(positions) | Record::Provisional(positions) => {
                    positions.solutions().ok()?
                }
                _ => return None,
            };
            let first = content.solutions.first()?;
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
        Record::ClockModel(_) => Some((area_at(point?)?, Streams::CLOCK_MODELS)),
        Record::RegionalBatch(regional) => {
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

/// A record as a group carries it: its hash and its encoding.
fn encoded(record: &Record) -> Option<(tally_wire::batch::Hash, Arc<Vec<u8>>)> {
    let hash = record_hash(record)?;
    let mut bytes = Vec::new();
    record.encode(&mut bytes).ok()?;
    Some((hash, Arc::new(bytes)))
}

fn decoded(bytes: &[u8]) -> Option<Record> {
    Record::decode(bytes).ok()?.0
}

/// The wire records of a message: one, or a parity's chunks.
fn to_records(message: Message) -> Vec<Record> {
    match message {
        Message::Piece { bytes, .. } => decoded(&bytes).into_iter().collect(),
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
