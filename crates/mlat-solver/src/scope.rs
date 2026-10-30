//! Trailing windows and members (crate docs, § The trailing window, § Areas): which raw an area's
//! pair model at one trailing edge is a function of. An area's members follow its receivers'
//! signed site records alone, never which receivers' raw arrived; its inputs are the sync raw of
//! those members that had arrived when it was fitted, cited by each member's frontier
//! (`arrived::Arrived::area_inputs`), so a holder of more raw builds a superset of what a holder of
//! less builds, and a verifier holding the cited batches rebuilds it exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use blake2::{Blake2s256, Digest};
use tally_wire::budget::{FIT_LAG_MS, REFIT_EVERY_MS, TRAILING_WINDOW_MS};
use tally_wire::{PublicKey, Region};

use crate::obs::{ObservationId, Reception, Site};
use crate::pair::Network;

/// What the input citation is hashed under.
const CITATION_DOMAIN: &[u8] = b"tally clock model inputs";
/// What a cited part's digest is hashed under.
const PART_DOMAIN: &[u8] = b"tally sync part";

/// A set of observations cited by hash and count: the count of the inputs' sync receptions, and a
/// hash of the held batches they are a function of (crate docs, § Thinning, the citation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Citation {
    /// BLAKE2s-256 over `"tally clock model inputs" 0x00`, then each cited part (a batch's kept
    /// sync and status receptions of one slice, [`Part`]) in order as receiver key (32), boot (8),
    /// sequence (8), slice (8) and its digest (32), all big-endian.
    pub hash: [u8; 32],
    pub count: u32,
}

/// One part a citation cites: a batch's kept sync and status receptions of one slice of signed
/// wall clock, by its receiver, boot, sequence and slice, and its digest ([`Part::digest`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Part {
    pub receiver: PublicKey,
    pub boot_id: u64,
    pub sequence: u64,
    pub slice: u64,
    pub digest: [u8; 32],
}

impl Part {
    /// A part's digest: BLAKE2s-256 over `"tally sync part" 0x00`, then each of its receptions as
    /// epoch (4), counter (the low six bytes of eight), message hash (32) and milliseconds into the
    /// slice (2), all big-endian, ascending by those bytes: a function of the receptions as a set
    /// (with their repeats), so of a batch's in whatever order it carries them.
    pub fn digest(entries: impl IntoIterator<Item = (u32, u64, [u8; 32], u16)>) -> [u8; 32] {
        let mut encoded: Vec<[u8; 44]> = entries
            .into_iter()
            .map(|(epoch, counter, message, into_ms)| {
                let mut entry = [0u8; 44];
                entry[..4].copy_from_slice(&epoch.to_be_bytes());
                entry[4..10].copy_from_slice(&counter.to_be_bytes()[2..]);
                entry[10..42].copy_from_slice(&message);
                entry[42..].copy_from_slice(&into_ms.to_be_bytes());
                entry
            })
            .collect();
        encoded.sort_unstable();
        let mut hasher = Blake2s256::new();
        hasher.update(PART_DOMAIN);
        hasher.update([0]);
        for entry in &encoded {
            hasher.update(entry);
        }
        hasher.finalize().into()
    }
}

impl Citation {
    /// The citation of `count` receptions, a function of `parts`, in their order: each member's
    /// in the frontier's order, and a member's by sequence, then slice.
    pub fn of_parts<'a>(parts: impl IntoIterator<Item = &'a Part>, count: usize) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(CITATION_DOMAIN);
        hasher.update([0]);
        for part in parts {
            let mut entry = [0u8; 88];
            entry[..32].copy_from_slice(part.receiver.as_bytes());
            entry[32..40].copy_from_slice(&part.boot_id.to_be_bytes());
            entry[40..48].copy_from_slice(&part.sequence.to_be_bytes());
            entry[48..56].copy_from_slice(&part.slice.to_be_bytes());
            entry[56..].copy_from_slice(&part.digest);
            hasher.update(entry);
        }
        Self {
            hash: hasher.finalize().into(),
            count: u32::try_from(count).unwrap_or(u32::MAX),
        }
    }
}

/// The span of signed wall clock an area's model is fitted over: `[edge - span, edge)`, its first
/// millisecond in and its edge out, so its seconds tile it (crate docs, § The pairwise path,
/// blocks), solved at its trailing edge. Its span is `tally_wire::budget::TRAILING_WINDOW_MS`
/// (`W`), which every party states the same. Its inputs reach `pair::READ_BACK_MS` further back
/// ([`Trailing::read_from_ms`]): what its first blocks read before the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Trailing {
    pub edge_ms: u64,
    pub span_ms: u32,
}

const _: () = assert!(TRAILING_WINDOW_MS <= u32::MAX as u64);
const _: () =
    assert!(TRAILING_WINDOW_MS.is_multiple_of(1000) && REFIT_EVERY_MS.is_multiple_of(1000));

impl Trailing {
    /// The specification's trailing window ending at `edge_ms`.
    pub fn at(edge_ms: u64) -> Self {
        Self {
            edge_ms,
            span_ms: TRAILING_WINDOW_MS as u32,
        }
    }

    /// The specification's trailing window of a refit run at `judged_ms` (the engine's clock):
    /// its edge the newest multiple of `tally_wire::budget::REFIT_EVERY` at least
    /// `tally_wire::budget::FIT_LAG` below, where every honest receiver's raw has arrived, so the
    /// inputs are a function of the edge and of the raw, never of when a batch arrived
    /// (`arrived::Arrived::area_inputs`). On one grid for every relay, whatever the phase its
    /// steps run at, so the models of neighbouring areas, fitted by other relays, share the edges a
    /// fix citing several of them needs (crate docs, § Areas).
    pub fn fitted_at(judged_ms: u64) -> Self {
        let lagged = judged_ms.saturating_sub(FIT_LAG_MS);
        Self::at(lagged - lagged % REFIT_EVERY_MS)
    }

    /// The oldest wall clock the window holds.
    pub fn first_ms(&self) -> u64 {
        self.edge_ms.saturating_sub(u64::from(self.span_ms))
    }

    /// The oldest wall clock its inputs hold: `pair::READ_BACK_MS` before its first.
    pub fn read_from_ms(&self) -> u64 {
        self.first_ms().saturating_sub(crate::pair::READ_BACK_MS)
    }

    /// Whether `wall_ms` lies in `[first_ms, edge_ms)`.
    pub fn holds(&self, wall_ms: u64) -> bool {
        wall_ms >= self.first_ms() && wall_ms < self.edge_ms
    }

    /// Whether its inputs hold `wall_ms`: `[read_from_ms, edge_ms)`.
    pub fn reads(&self, wall_ms: u64) -> bool {
        wall_ms >= self.read_from_ms() && wall_ms < self.edge_ms
    }
}

/// How far one member's raw a model cites reaches: every batch of the member's boot `boot_id`
/// with a sequence at or below `through_sequence` (a contiguous run, as the engine cites only
/// one). A verifier missing a batch at or below it cannot judge the model, and says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Frontier {
    pub receiver: PublicKey,
    pub boot_id: u64,
    pub through_sequence: u64,
}

/// What one area's pair model at one trailing edge is a function of: the sync receptions of its
/// members with a wall clock its inputs hold (`Trailing::reads`), from the batches at or below each member's frontier at
/// the edge (`arrived::Arrived::area_inputs`).
#[derive(Clone, Debug, PartialEq)]
pub struct Inputs {
    pub area: Region,
    pub trailing: Trailing,
    /// The area's members (`Sites::members`), by their signed site records alone, sorted by key.
    pub scope: Vec<Site>,
    /// The frontier of each member whose raw arrived whole over the window, sorted by key: one
    /// with none, or whose first batch held arrived inside the window (what came before it may be
    /// in the window too), cites nothing and has no frontier.
    pub frontier: Vec<Frontier>,
    /// The sync material: the members' receptions of the sync events kept (§ Thinning), and
    /// their receptions of each operational status of a kept event's aircraft. Sorted by
    /// identity ([`Inputs::id`]), each identity once.
    pub sync: Vec<SyncReception>,
    /// The messages the sync material carries, each once, in the order the sync material first
    /// carries them.
    pub messages: Vec<SyncMessage>,
    pub citation: Citation,
}

/// One reception of an area's sync material ([`Inputs::sync`]): its message by its place in
/// [`Inputs::messages`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncReception {
    pub receiver: PublicKey,
    pub epoch: u32,
    pub timestamp: u64,
    pub wall_ms: u64,
    pub message: u32,
}

/// A message of an area's sync material: its bytes and their hash (`obs::message_hash`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncMessage {
    pub hash: [u8; 32],
    pub data: Box<[u8]>,
}

impl Inputs {
    /// A reception's identity.
    pub fn id(&self, reception: &SyncReception) -> ObservationId {
        ObservationId {
            receiver: reception.receiver,
            epoch: reception.epoch,
            timestamp: reception.timestamp,
            message: self.messages[reception.message as usize].hash,
        }
    }

    /// A reception as the wire carries it: `None` for bytes no Mode S message holds.
    pub fn reception(&self, reception: &SyncReception) -> Option<Reception> {
        Reception::mode_s(
            reception.receiver,
            reception.epoch,
            reception.timestamp,
            reception.wall_ms,
            &self.messages[reception.message as usize].data,
        )
    }

    /// The members' keys, sorted.
    pub fn keys(&self) -> Vec<PublicKey> {
        self.scope.iter().map(|site| site.receiver).collect()
    }
}

/// The receivers that may take part, each with its millimetre site: one per receiver, usable
/// (a receiver described twice, or unusable, takes no part). Indexed by area, with every
/// receiver's kept pairs (`pair::Network`, found once) and each area's members once found
/// ([`Sites::members`]): a function of the sites alone, asked for every refit's inputs, every
/// model's verification and every fix's cited models.
#[derive(Debug, Default)]
pub struct Sites {
    by_key: BTreeMap<PublicKey, (Site, [i64; 3])>,
    area_of: BTreeMap<PublicKey, Region>,
    by_area: BTreeMap<Region, Vec<PublicKey>>,
    network: OnceLock<Network>,
    members: std::sync::RwLock<BTreeMap<Region, Arc<[Site]>>>,
}

impl Clone for Sites {
    fn clone(&self) -> Self {
        Self {
            by_key: self.by_key.clone(),
            area_of: self.area_of.clone(),
            by_area: self.by_area.clone(),
            network: self.network.clone(),
            members: std::sync::RwLock::new(read(&self.members).clone()),
        }
    }
}

impl PartialEq for Sites {
    /// The same sites: what they remember is theirs alike.
    fn eq(&self, other: &Self) -> bool {
        self.by_key == other.by_key
    }
}

/// A read of a lock whose writers only insert a finished value: a panic in one leaves nothing
/// half-written, so a poisoned lock is read as it is.
fn read<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Sites {
    pub fn new(sites: &[Site]) -> Self {
        let mut count: BTreeMap<PublicKey, usize> = BTreeMap::new();
        for site in sites {
            *count.entry(site.receiver).or_default() += 1;
        }
        let by_key: BTreeMap<PublicKey, (Site, [i64; 3])> = sites
            .iter()
            .filter(|site| count.get(&site.receiver) == Some(&1) && site.usable())
            .map(|site| (site.receiver, (*site, site.mm())))
            .collect();
        let mut area_of = BTreeMap::new();
        let mut by_area: BTreeMap<Region, Vec<PublicKey>> = BTreeMap::new();
        for (key, (site, _)) in &by_key {
            if let Some(area) = crate::area::of(site) {
                area_of.insert(*key, area);
                by_area.entry(area).or_default().push(*key);
            }
        }
        Self {
            by_key,
            area_of,
            by_area,
            network: OnceLock::new(),
            members: std::sync::RwLock::default(),
        }
    }

    pub fn get(&self, key: &PublicKey) -> Option<&(Site, [i64; 3])> {
        self.by_key.get(key)
    }

    /// The area a receiver is in (`area::of`), when it is a usable receiver.
    pub fn area(&self, key: &PublicKey) -> Option<Region> {
        self.area_of.get(key).copied()
    }

    /// Every area with a receiver in it, ascending, with its receivers' keys, ascending.
    pub fn areas(&self) -> impl Iterator<Item = (&Region, &[PublicKey])> {
        self.by_area
            .iter()
            .map(|(area, keys)| (area, keys.as_slice()))
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Bytes it holds, as allocated: its index of sites and areas, the network and the members it
    /// remembers.
    pub fn bytes(&self) -> usize {
        use tally_wire::footprint::{btree, vec};
        let members = read(&self.members);
        let kept = self.network.get().map_or(0, |network| {
            network.len() * 2 * std::mem::size_of::<PublicKey>()
                + btree::<PublicKey, Vec<PublicKey>>(self.by_key.len()) * 2
        });
        btree::<PublicKey, (Site, [i64; 3])>(self.by_key.len())
            + btree::<PublicKey, Region>(self.area_of.len())
            + btree::<Region, Vec<PublicKey>>(self.by_area.len())
            + self
                .by_area
                .values()
                .map(|keys| vec::<PublicKey>(keys.capacity()))
                .sum::<usize>()
            + kept
            + btree::<Region, Arc<[Site]>>(members.len())
            + members
                .values()
                .map(|sites| tally_wire::decoded::ARC_HEADER + vec::<Site>(sites.len()))
                .sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &(Site, [i64; 3]))> {
        self.by_key.iter()
    }

    /// Every receiver's kept pairs (`pair::Network::of` over every site), found once.
    pub fn network(&self) -> &Network {
        self.network.get_or_init(|| {
            let sites: Vec<Site> = self.by_key.values().map(|(site, _)| *site).collect();
            Network::of(&sites)
        })
    }

    /// The members of `area` (crate docs, § Areas): its receivers and every receiver one of them
    /// keeps, by their signed sites, sorted by key. Never a function of whose raw arrived, so
    /// every holder of the same site records names the same members. Found once an area and
    /// remembered.
    pub fn members(&self, area: Region) -> Arc<[Site]> {
        if let Some(members) = read(&self.members).get(&area) {
            return Arc::clone(members);
        }
        let network = self.network();
        let mut keys: BTreeSet<PublicKey> = BTreeSet::new();
        for key in self.by_area.get(&area).map_or(&[][..], Vec::as_slice) {
            keys.insert(*key);
            keys.extend(network.kept(key).iter().copied());
        }
        let members: Arc<[Site]> = keys
            .iter()
            .filter_map(|key| self.by_key.get(key).map(|(site, _)| *site))
            .collect();
        self.members
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(area)
            .or_insert_with(|| Arc::clone(&members));
        members
    }

    /// The areas `receivers` are in, ascending and without repeats, each a usable receiver here:
    /// the areas whose models a considered set of their receptions is grouped and solved by
    /// (crate docs, § Areas, the models a fix cites).
    pub fn areas_of(&self, receivers: impl IntoIterator<Item = PublicKey>) -> Vec<Region> {
        let areas: std::collections::BTreeSet<Region> = receivers
            .into_iter()
            .filter_map(|key| self.area(&key))
            .collect();
        areas.into_iter().collect()
    }
}
