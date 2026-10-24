//! Firehose credit (RFC-0174 §2.1): the credentials this relay signs for the clients it vouches
//! for, the evidence it keeps (receipts its children signed, feeders' descriptions naming it) and
//! bundles for them, the credentials and bundles clients present to it, and what each client may
//! read: the free small tier with nothing, more in proportion to what the evidence of the relay
//! vouching for it shows.
//!
//! The rules, each a decision of this file:
//!
//! - **Only clients are shaped here.** What every other role may receive is the link's to decide
//!   (`link`'s `Peer::grant`), never this file's; [`Credit::admit`] grants a non-client nothing.
//!   A relay told no upload cap ([`Credit::set_upload_cap`]) sends nothing billed, so it has
//!   nothing to ration and serves its clients as they ask.
//! - **The free tier** ([`Allowance::FREE`]) is final and provisional positions for one area (one
//!   cell at [`AREA_RESOLUTION`] or finer), at what the busiest area's positions cost. All the
//!   clients on the free tier together get at most [`FREE_SHARE_OF_CAP`] of the upload cap; past
//!   it a new one is served nothing until one leaves.
//! - **A relay vouches for the clients its operator names** ([`Credit::vouch_for`]): on each of
//!   their sessions it signs a credential and its newest evidence bundle ([`Credit::vouch`]),
//!   again before the credential lapses, and the client presents both to every relay it reads.
//! - **A credential** is the relay's signature over the client's key, short-lived. It is honoured
//!   only on a session whose Noise handshake proved that key, and only before it expires, so a
//!   copied credential is worth nothing and a leaked one soon lapses.
//! - **Evidence is what a third party signed.** A feeder's description naming the relay, and a
//!   child's receipt for a slice the relay delivered: records anyone can check by their own
//!   signatures, with no history of their own. A delivery answer is the relay's own word about
//!   itself (a holder's proof, checkable only by someone holding the same batch), so it is never
//!   evidence: a relay with no feeders and no children earns nothing, whatever it says it holds.
//! - **Evidence is portable and judged item by item.** A bundle's own signature and time must
//!   hold; within it, an item that does not verify, is dated ahead of this relay's clock, or says
//!   nothing of the relay is skipped and the rest counts. This relay then scores what it
//!   corroborates itself: a feeder's description earns only for a receiver this relay
//!   corroborated ([`Credit::corroborate_receiver`]); a stripe receipt earns only when its signer
//!   is a relay this relay corroborated ([`Credit::corroborate_relay`]). Fake feeder keys and
//!   colluding children earn nothing at a relay that never met them. There is no central score:
//!   each relay computes its own.
//! - **Credit is a rate, earned 1:1.** A relay earns back what its evidence shows it gives the
//!   network: [`FEEDER_CREDIT`] per feeder it hosts, and each receipt's delivered bytes a second.
//!   Each item decays with the age of its own signature (halving every [`HALF_LIFE_MS`], nothing
//!   past `tally_wire::budget::EVIDENCE_AGE`).
//! - **Credit is split** across every session linked to the relay here: a hundred clients, or one
//!   credential shared by a hundred processes, divide it a hundred ways.
//! - **A relay's own clients** (a credential signed by this relay's own key) are served as they
//!   ask, within the credential's products: the operator spends its own cap.

use std::collections::HashMap;
use std::hash::Hash as StdHash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tally_wire::Signs;
use tally_wire::batch::Hash;
use tally_wire::budget::RECEIPT_AHEAD;
use tally_wire::clocks::Judged;

use crate::sharing::{MonoDeadline, Now};
use tally_wire::record::MAX_REGIONS;
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{
    Evidence, EvidenceBundle, FeederReference, FirehoseCredential, FirehoseCredentialContent,
    PublicKey, ReceiverInfo, ReferencedEvidenceContent, Region, Streams, StripeReceipt, WireError,
};

use crate::budget::{Charge, Gauge, Store};
use crate::footprint;
use crate::ingest::RecordPace;
use crate::network::{Asker, AskerRole};
use crate::sharing::seeded_bytes;
use crate::subscription::Subscription;

/// How long a credential this relay signs lives: a client re-asks every quarter hour, so a leaked
/// credential is worth a quarter hour at most.
pub const CREDENTIAL_LIFETIME_MS: u64 = 15 * 60 * 1000;
/// How fast evidence fades: a relay that stops contributing loses half its credit each half hour.
pub const HALF_LIFE_MS: u64 = 30 * 60 * 1000;
/// How long a first-hand corroboration (a receiver whose receptions agreed, a relay this one dealt
/// with) stands without being renewed.
pub const CORROBORATION_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
/// The share of the upload cap all free-tier clients together may take: an eighth, so the duties
/// (the forwarded slice, raw to the MLAT relays, seeding) always keep seven eighths.
pub const FREE_SHARE_OF_CAP: (u64, u64) = (1, 8);

/// What one feeder uploads (RFC-0174 §1: box-01, 7.9 KB/s measured 2026-10-06).
pub const FEEDER_BYTES_PER_SEC: u64 = 8 * 1024;
/// What hosting a feeder gives the network: its raw as seeded into its area's group (§2.5), by the
/// one rule sharing seeds by (`sharing::seeded_bytes`: its copies and the parity beside them).
pub const FEEDER_CREDIT: u64 = seeded_bytes(FEEDER_BYTES_PER_SEC);
/// How long before a vouched client's credential lapses this relay signs it a fresh one: a third
/// of its life, so a client that misses one renewal still holds a valid credential.
pub const RENEW_BEFORE_MS: u64 = CREDENTIAL_LIFETIME_MS / 3;

/// One final or provisional fix, as published (RFC-0174 §2.4: about 370 bytes a solution).
const FIX_BYTES: u64 = 370;
/// Aircraft over the busiest area cell at once (an estimate: a cell of about 12,400 km² over a
/// metropolitan basin).
const AREA_AIRCRAFT: u64 = 100;
/// Aircraft the whole world's MLAT tracks in a window (RFC-0174 §2.3: about 5,400 targets).
const WORLD_AIRCRAFT: u64 = 5_400;
/// A world product fix on the wire (measured, `products` tests: 87.5 bytes), and the aircraft
/// the world product carries a second (the measurement's 12,000 ADS-B and 5,400 MLAT aircraft).
const WORLD_FIX_BYTES: u64 = 88;
const WORLD_PRODUCT_AIRCRAFT: u64 = 17_400;
/// Feeders in the busiest area cell (an estimate), and in the world (RFC-0174 §2.3: 20,000).
const AREA_FEEDERS: u64 = 200;
const WORLD_FEEDERS: u64 = 20_000;
/// Receivers hearing one message (the RFC-0174 §1 Monte Carlo's ten), which deduplication folds to
/// one copy.
const RECEIVERS_PER_MESSAGE: u64 = 10;

/// What a client may read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allowance {
    pub products: Streams,
    /// Regions it may name at once.
    pub regions: usize,
    /// The coarsest resolution a region it names may have.
    pub min_resolution: u8,
    /// Whether it may ask for the whole world (no region).
    pub world: bool,
    /// What its subscription may cost, by [`cost`]'s estimate.
    pub bytes_per_sec: u64,
}

impl Allowance {
    /// The free small tier: positions for an area, with nothing but a connection. Final and
    /// provisional positions (cockpit traffic is what the provisional ones are for, §2.4), one
    /// area cell or finer, at what the busiest area's positions cost.
    pub const FREE: Self = Self {
        products: Streams(Streams::POSITIONS.0 | Streams::PROVISIONAL.0),
        regions: 1,
        min_resolution: AREA_RESOLUTION,
        world: false,
        bytes_per_sec: 2 * AREA_AIRCRAFT * FIX_BYTES,
    };

    /// A relay's own client: what its credential names, anywhere.
    fn vouched(products: Streams) -> Self {
        Self {
            products,
            regions: MAX_REGIONS,
            min_resolution: 0,
            world: true,
            bytes_per_sec: u64::MAX,
        }
    }

    /// A linked client with `share` of its relay's credit.
    fn linked(products: Streams, share: u64) -> Self {
        Self {
            products,
            regions: MAX_REGIONS,
            min_resolution: 0,
            world: true,
            bytes_per_sec: share,
        }
    }
}

/// The estimated rate of each product: (one busiest area cell, the whole world), and whether a
/// subscription's regions cut it. Positions are routed by area as the free tier needs.
const PRODUCTS: [(Streams, u64, u64, bool); 8] = [
    (
        Streams::RAW,
        AREA_FEEDERS * FEEDER_BYTES_PER_SEC,
        WORLD_FEEDERS * FEEDER_BYTES_PER_SEC,
        true,
    ),
    (
        Streams::DEDUPLICATED,
        AREA_FEEDERS * FEEDER_BYTES_PER_SEC / RECEIVERS_PER_MESSAGE,
        WORLD_FEEDERS * FEEDER_BYTES_PER_SEC / RECEIVERS_PER_MESSAGE,
        false,
    ),
    (
        Streams::POSITIONS,
        AREA_AIRCRAFT * FIX_BYTES,
        WORLD_AIRCRAFT * FIX_BYTES,
        true,
    ),
    // An estimate: a tile's model is a few receivers' clocks, re-fit once a stride.
    (Streams::CLOCK_MODELS, 4 * 1024, 256 * 1024, true),
    (
        Streams::PROVISIONAL,
        AREA_AIRCRAFT * FIX_BYTES,
        WORLD_AIRCRAFT * FIX_BYTES,
        true,
    ),
    (
        Streams::REGIONAL,
        AREA_FEEDERS * FEEDER_BYTES_PER_SEC / RECEIVERS_PER_MESSAGE,
        WORLD_FEEDERS * FEEDER_BYTES_PER_SEC / RECEIVERS_PER_MESSAGE,
        true,
    ),
    // The live and the precise world products, each one fix an aircraft a second: costed apart.
    (
        Streams::WORLD,
        WORLD_PRODUCT_AIRCRAFT * WORLD_FIX_BYTES,
        WORLD_PRODUCT_AIRCRAFT * WORLD_FIX_BYTES,
        false,
    ),
    (
        Streams::WORLD_PRECISE,
        WORLD_PRODUCT_AIRCRAFT * WORLD_FIX_BYTES,
        WORLD_PRODUCT_AIRCRAFT * WORLD_FIX_BYTES,
        false,
    ),
];

/// Every product a client may be granted.
const KNOWN_PRODUCTS: Streams = Streams(
    Streams::RAW.0
        | Streams::DEDUPLICATED.0
        | Streams::POSITIONS.0
        | Streams::CLOCK_MODELS.0
        | Streams::PROVISIONAL.0
        | Streams::REGIONAL.0
        | Streams::WORLD.0
        | Streams::WORLD_PRECISE.0,
);

/// What a subscription to `streams` over `regions` (none: the world) is estimated to cost a
/// second.
pub fn cost(streams: Streams, regions: &[Region]) -> u64 {
    PRODUCTS
        .iter()
        .filter(|(product, ..)| streams.contains(*product))
        .map(|&(_, area, world, by_area)| {
            if regions.is_empty() || !by_area {
                return world;
            }
            let areas = regions
                .iter()
                .map(|region| {
                    let coarser = AREA_RESOLUTION.saturating_sub(region.resolution());
                    7u64.saturating_pow(u32::from(coarser))
                })
                .fold(0u64, u64::saturating_add);
            area.saturating_mul(areas).min(world)
        })
        .fold(0, u64::saturating_add)
}

/// `asked`, held to `allowance`: its products, its regions, then its cost, the costliest product
/// dropped first. Never widened: a subscription whose every region is refused is served nothing,
/// not the world.
pub fn narrow(asked: &Subscription, allowance: &Allowance) -> Subscription {
    let nothing = Subscription {
        streams: Streams(0),
        regions: Vec::new(),
    };
    let mut streams = Streams(asked.streams.0 & allowance.products.0 & KNOWN_PRODUCTS.0);
    let regions: Vec<Region> = asked
        .regions
        .iter()
        .filter(|region| region.resolution() >= allowance.min_resolution)
        .take(allowance.regions)
        .copied()
        .collect();
    if asked.regions.is_empty() && !allowance.world {
        return nothing;
    }
    if !asked.regions.is_empty() && regions.is_empty() {
        return nothing;
    }
    while streams.0 != 0 && cost(streams, &regions) > allowance.bytes_per_sec {
        let costliest = PRODUCTS
            .iter()
            .filter(|(product, ..)| streams.contains(*product))
            .max_by_key(|(product, ..)| (cost(*product, &regions), product.0))
            .map_or(Streams(0), |(product, ..)| *product);
        streams = Streams(streams.0 & !costliest.0);
    }
    if streams.0 == 0 {
        return nothing;
    }
    Subscription { streams, regions }
}

/// `value` signed at `signed_ms` as it stands by the judging clock `now`: halved each
/// [`HALF_LIFE_MS`] of its age (straight between halvings), nothing once older than the budget's
/// `EVIDENCE_AGE`.
pub fn decayed(value: u64, signed_ms: u64, now: Judged) -> u64 {
    if tally_wire::budget::EVIDENCE_AGE.older(signed_ms, now) {
        return 0;
    }
    let age_ms = now.ms().saturating_sub(signed_ms);
    let halvings = age_ms / HALF_LIFE_MS;
    let into = age_ms % HALF_LIFE_MS;
    let whole = value
        .checked_shr(u32::try_from(halvings).unwrap_or(u32::MAX))
        .unwrap_or(0);
    let lost = u128::from(whole) * u128::from(into) / (2 * u128::from(HALF_LIFE_MS));
    whole - u64::try_from(lost).unwrap_or(whole)
}

/// Why a credential or a bundle is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Only a client links to a relay by credential.
    NotAClient,
    /// A bad signature or body.
    Unreadable(String),
    /// Bound to another key than the one the session's handshake proved: a copy.
    OtherKey,
    Expired,
    /// Signed further ahead than any clock skew.
    Future,
    /// A bundle older than any evidence counts.
    Stale,
    /// Too many sessions linked at once.
    Full,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAClient => write!(f, "not presented by a client"),
            Self::Unreadable(why) => write!(f, "bad signature or body: {why}"),
            Self::OtherKey => write!(f, "bound to another key than the session's"),
            Self::Expired => write!(f, "expired"),
            Self::Future => write!(f, "signed in the future"),
            Self::Stale => write!(f, "too old"),
            Self::Full => write!(f, "too many sessions linked"),
        }
    }
}

impl std::error::Error for Refused {}

fn unreadable(error: WireError) -> Refused {
    Refused::Unreadable(error.to_string())
}

/// A session linked to a relay by a credential it presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Linked {
    client: PublicKey,
    relay: PublicKey,
    products: Streams,
    expires_ms: u64,
}

/// One stripe slice a receipt shows, as this relay will score it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slice {
    child: PublicKey,
    /// Delivered bytes a second, at most an area's raw.
    rate: u64,
    issued_ms: u64,
}

/// What a relay's newest checked bundle shows, before anyone's corroboration ([`check`]): what
/// the directory ranks a relay's offers by (`directory`), and what this relay's clients are
/// credited by, each weighed by [`worth`] under its own [`Corroboration`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shown {
    issued_ms: u64,
    /// Feeders naming the relay, by key, with their descriptions' times.
    feeders: Vec<ShownFeeder>,
    slices: Vec<Slice>,
}

/// A feeder a bundle shows naming its relay ([`check`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShownFeeder {
    pub feeder: PublicKey,
    pub issued_ms: u64,
    /// For a bundle that names its feeders by reference (format 2, which carries no site): the
    /// hash of the description it names, which only a judge holding the same description can
    /// resolve ([`Credit::described`]). `None` for one carried whole, already checked.
    pub description: Option<Hash>,
}

/// What a relay holds of a feeder's newest description, whoever it names: what a bundle's
/// reference to it is resolved against ([`resolves`]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct HeldCopy {
    issued_ms: u64,
    description: Hash,
    relays: Vec<PublicKey>,
}

impl Shown {
    /// When the bundle it was read from was signed.
    pub fn issued_ms(&self) -> u64 {
        self.issued_ms
    }

    /// What it allocates beside itself: its feeders' and slices' lists.
    pub fn allocated(&self) -> usize {
        footprint::vec::<ShownFeeder>(self.feeders.capacity())
            + footprint::vec::<Slice>(self.slices.capacity())
    }
}

/// The receivers a credit not yet told its figure holds (`Credit::set_receivers`): a test's that
/// builds one alone. A relay's is told its figure before it starts.
const UNSIZED_RECEIVERS: usize = 65_536;

/// The most of each kind this relay keeps of its own evidence: a few bundles' worth.
const OWN_EVIDENCE: usize = 16 * tally_wire::credit::MAX_EVIDENCE;
/// The most relays whose evidence it holds, sessions it links, and corroborations it keeps.
const MAX_RELAYS_SHOWN: usize = 4_096;
const MAX_LINKED: usize = 8_192;
const MAX_CORROBORATED_RELAYS: usize = 8_192;
// The receivers corroborated, and the feeders' descriptions held to resolve references by (one
// each), are as many as the receiver figure (`budget::Plan::receivers`, `Credit::set_receivers`):
// the receivers the records a second the relay admits may be.
/// The most clients this relay vouches for (its operator's list, `--vouch`): past it the rest are
/// not taken.
const MAX_VOUCHED: usize = 1_024;
/// What client sessions asked for, at most, and the most served on the free tier: one per client
/// session, which ends with it (`Credit::left`), as many as may be linked.
const ASKED_REMEMBERED: usize = MAX_LINKED;
/// The most a held description's signed bytes take: its fixed fields, its signature and key, a
/// software name of 255 bytes and the most relays a held description names
/// (`tally_wire::credit::MAX_DESCRIBED_RELAYS`); a test holds the largest one to it.
pub(crate) const DESCRIPTION_MOST: usize = 1_024;
/// The most a receipt's signed bytes take; a test holds one to it.
const RECEIPT_MOST: usize = 256;
/// The most receipts held from one signer: a bundle's worth. A signer is anyone with a key, so one
/// signer's receipts (a fresh key's, dated ahead) take no more of the evidence than this.
const RECEIPTS_PER_SIGNER: usize = tally_wire::credit::MAX_EVIDENCE;

/// What every table here allocates at most at its caps ([`Credit`], charged to the budget's
/// `Store::Credit`, a part of what the relay holds before any feeder): each table at its cap and
/// one more (a table is trimmed once past its cap, `Gauged::trim`), never shrunk, so its buckets
/// are those [`footprint::table_planned`] plans; and what each entry holds beside its table, at
/// the most it may hold (a description, a receipt, a copy's relays, a bundle's feeders and slices,
/// a session's two subscriptions).
pub const fn planned_bytes(receivers: usize) -> usize {
    use tally_wire::footprint::{table_planned, vec};
    let copies = table_planned::<PublicKey, HeldCopy>(receivers + 1)
        + (receivers + 1) * vec::<PublicKey>(tally_wire::credit::MAX_DESCRIBED_RELAYS);
    let corroborated = table_planned::<PublicKey, MonoDeadline>(receivers + 1);
    FIXED_TABLES_BYTES + copies + corroborated
}

/// What [`planned_bytes`] takes for each receiver at most, linear with [`FIXED_BYTES`]: a copy's
/// share of its table (`footprint::table_planned_per_entry`) and the relays it names, and a
/// corroboration's share of its.
pub const BYTES_PER_RECEIVER: usize = {
    use tally_wire::footprint::{table_planned_per_entry, vec};
    table_planned_per_entry::<PublicKey, HeldCopy>()
        + vec::<PublicKey>(tally_wire::credit::MAX_DESCRIBED_RELAYS)
        + table_planned_per_entry::<PublicKey, MonoDeadline>()
};

/// What [`planned_bytes`] takes beside [`BYTES_PER_RECEIVER`] for each receiver: every table held
/// at its own caps ([`FIXED_TABLES_BYTES`]), and the receivers' two tables' fixed parts and the one
/// entry each holds past its figure.
pub const FIXED_BYTES: usize = {
    use tally_wire::footprint::{table_planned_fixed, vec};
    FIXED_TABLES_BYTES
        + table_planned_fixed::<PublicKey, HeldCopy>()
        + table_planned_fixed::<PublicKey, MonoDeadline>()
        + BYTES_PER_RECEIVER
        + vec::<PublicKey>(tally_wire::credit::MAX_DESCRIBED_RELAYS)
};

/// What every table but the receivers' allocates at most at its caps.
const FIXED_TABLES_BYTES: usize = {
    use tally_wire::footprint::{table_planned, vec};
    let described = table_planned::<PublicKey, (ReceiverInfo, u64)>(OWN_EVIDENCE + 1)
        + (OWN_EVIDENCE + 1) * DESCRIPTION_MOST;
    let receipts =
        table_planned::<(PublicKey, u64, u16, u8), (StripeReceipt, u64)>(OWN_EVIDENCE + 1)
            + (OWN_EVIDENCE + 1) * RECEIPT_MOST;
    let vouched = table_planned::<PublicKey, ()>(MAX_VOUCHED);
    let shown = table_planned::<PublicKey, Shown>(MAX_RELAYS_SHOWN + 1)
        + (MAX_RELAYS_SHOWN + 1)
            * (vec::<ShownFeeder>(tally_wire::credit::MAX_EVIDENCE)
                + vec::<Slice>(tally_wire::credit::MAX_EVIDENCE));
    let corroborated = table_planned::<PublicKey, MonoDeadline>(MAX_CORROBORATED_RELAYS + 1);
    let sessions = table_planned::<u64, Linked>(MAX_LINKED)
        + table_planned::<u64, ()>(ASKED_REMEMBERED)
        + table_planned::<u64, (Subscription, Subscription)>(ASKED_REMEMBERED + 1)
        + (ASKED_REMEMBERED + 1) * 2 * vec::<Region>(MAX_REGIONS);
    described + receipts + vouched + shown + corroborated + sessions
};

/// A table of the credit's, charged as it allocates ([`planned_bytes`]): its buckets, followed
/// as it grows (`footprint::Table`), and what its entries hold beside them (`heap`, each entry's
/// by `heap_of`). An entry goes in only once what it adds is charged, so a table past what its
/// store has room for takes nothing more.
struct Gauged<K, V> {
    map: HashMap<K, V>,
    table: footprint::Table,
    heap: usize,
    heap_of: fn(&V) -> usize,
}

impl<K, V> std::ops::Deref for Gauged<K, V> {
    type Target = HashMap<K, V>;

    fn deref(&self) -> &HashMap<K, V> {
        &self.map
    }
}

impl<K: Copy + Eq + StdHash, V> Gauged<K, V> {
    fn new(heap_of: fn(&V) -> usize) -> Self {
        Self {
            map: HashMap::new(),
            table: footprint::Table::default(),
            heap: 0,
            heap_of,
        }
    }

    /// What it allocates.
    fn bytes(&self) -> usize {
        self.table.bytes::<K, V>() + self.heap
    }

    /// `value` in at `key`, once what it adds (a table it grows into, what it holds more than the
    /// one it replaces) is charged to `charge`: false, and nothing changed, when it is not.
    fn insert(&mut self, charge: &mut Charge, key: K, value: V) -> bool {
        let old = self.map.get(&key).map_or(0, self.heap_of);
        let new = (self.heap_of)(&value);
        let growth = if self.map.contains_key(&key) {
            0
        } else {
            self.table
                .growth::<K, V>(self.map.len(), self.map.capacity())
        };
        let more = (growth + new).saturating_sub(old);
        if more > 0 && !charge.try_grow(more) {
            return false;
        }
        self.map.insert(key, value);
        self.table.inserted(self.map.capacity());
        self.heap = self.heap + new - old;
        true
    }

    /// Its table made anew no larger than `entries` take, if it is larger: what a lower figure
    /// leaves it planned at (`footprint::Table::shrunk`).
    fn shrink_within(&mut self, entries: usize) {
        if self.map.capacity() > entries {
            let len = self.map.len();
            self.map.shrink_to(entries.max(len));
            self.table.shrunk::<K, V>(len, entries.max(len));
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.map.remove(key);
        if let Some(value) = &removed {
            self.heap -= (self.heap_of)(value);
        }
        removed
    }

    fn retain(&mut self, mut keep: impl FnMut(&K, &V) -> bool) {
        let heap_of = self.heap_of;
        let mut freed = 0;
        self.map.retain(|key, value| {
            let kept = keep(key, value);
            if !kept {
                freed += heap_of(value);
            }
            kept
        });
        self.heap -= freed;
    }

    /// Kept at most `cap` long: past it, the oldest quarter by `time` goes (amortised, so a flood
    /// costs a sort per quarter of the cap, not per insert).
    fn trim(&mut self, cap: usize, time: impl Fn(&V) -> u64) {
        self.trim_ranked(cap, |_, value| time(value));
    }

    /// Kept at most `cap` long: past it, the lowest quarter by `rank` goes, as [`Gauged::trim`].
    fn trim_ranked<R: Ord>(&mut self, cap: usize, rank: impl Fn(&K, &V) -> R) {
        if self.map.len() <= cap {
            return;
        }
        let mut ranks: Vec<(R, K)> = self
            .map
            .iter()
            .map(|(key, value)| (rank(key, value), *key))
            .collect();
        ranks.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        let excess = self.map.len() - cap * 3 / 4;
        for (_, key) in ranks.into_iter().take(excess) {
            self.remove(&key);
        }
    }
}

fn nothing<V>(_: &V) -> usize {
    0
}

struct State {
    /// The keys this relay signs with (it may hold several during a rotation).
    own: Vec<PublicKey>,
    /// The upload cap, once told: before it, nothing is rationed.
    upload_cap: Option<u64>,
    /// Feeders' descriptions naming this relay, newest per feeder: its own evidence.
    described: Gauged<PublicKey, (ReceiverInfo, u64)>,
    /// Every feeder's newest description the relay holds, as a reference resolves against it.
    copies: Gauged<PublicKey, HeldCopy>,
    /// Children's receipts, newest per (child, cell, product, stripe).
    receipts: Gauged<(PublicKey, u64, u16, u8), (StripeReceipt, u64)>,
    /// The clients this relay vouches for (its operator's).
    vouched: Gauged<PublicKey, ()>,
    /// What each relay's evidence shows.
    shown: Gauged<PublicKey, Shown>,
    /// The receivers and relays corroborated first-hand, each until its corroboration lapses by
    /// `M` ([`CORROBORATION_LIFETIME_MS`] after it was last renewed): how long this relay keeps
    /// what it saw itself is its own schedule, so a step of its judging clock neither lapses a
    /// corroboration early nor stretches one (RFC-0171 §3.6).
    corroborated_receivers: Gauged<PublicKey, MonoDeadline>,
    corroborated_relays: Gauged<PublicKey, MonoDeadline>,
    /// When the corroborations are next swept for those lapsed (`Credit::expire`), by `M`.
    sweep_at: MonoDeadline,
    /// Corroborations not made because the clock did not judge, since start.
    unjudged: u64,
    /// Sessions linked by a credential, by the hub's connection id.
    linked: Gauged<u64, Linked>,
    /// Sessions served on the free tier now.
    free: Gauged<u64, ()>,
    /// What each client session last asked for, so it is admitted again as its credit changes.
    asked: Gauged<u64, (Subscription, Subscription)>,
    /// What every table allocates, charged to the budget's `Store::Credit` (`Credit::charge_to`).
    charge: Charge,
    /// The receiver figure the copies and the receivers' corroborations are held to
    /// (`Credit::set_receivers`).
    receivers: usize,
    /// What was let go because the store had no room for it.
    full: u64,
}

impl State {
    fn new(gauge: &Arc<Gauge>) -> Self {
        Self {
            own: Vec::new(),
            upload_cap: None,
            described: Gauged::new(|(info, _)| info.allocated()),
            copies: Gauged::new(|copy| footprint::vec::<PublicKey>(copy.relays.capacity())),
            receipts: Gauged::new(|(receipt, _)| receipt.allocated()),
            vouched: Gauged::new(nothing),
            shown: Gauged::new(|shown| {
                footprint::vec::<ShownFeeder>(shown.feeders.capacity())
                    + footprint::vec::<Slice>(shown.slices.capacity())
            }),
            corroborated_receivers: Gauged::new(nothing),
            corroborated_relays: Gauged::new(nothing),
            sweep_at: MonoDeadline::NEVER,
            unjudged: 0,
            linked: Gauged::new(nothing),
            free: Gauged::new(nothing),
            asked: Gauged::new(|(asked, served)| {
                footprint::vec::<Region>(asked.regions.capacity())
                    + footprint::vec::<Region>(served.regions.capacity())
            }),
            charge: gauge.empty(),
            full: 0,
            receivers: UNSIZED_RECEIVERS,
        }
    }

    /// What every table allocates now.
    fn bytes(&self) -> usize {
        self.described.bytes()
            + self.copies.bytes()
            + self.receipts.bytes()
            + self.vouched.bytes()
            + self.shown.bytes()
            + self.corroborated_receivers.bytes()
            + self.corroborated_relays.bytes()
            + self.linked.bytes()
            + self.free.bytes()
            + self.asked.bytes()
    }

    /// The charge brought down to what the tables allocate, after entries went or growth charged
    /// for was less than charged.
    fn settle(&mut self) {
        let bytes = self.bytes();
        self.charge.shrink_to(bytes);
    }

    /// Counts what was let go, the store full: false always, for the caller to return.
    fn let_go(&mut self) -> bool {
        self.full += 1;
        false
    }
}

/// Whether `key` stands corroborated: held, and (at `now`, when the caller has it) not lapsed. An
/// entry lapsed and not yet swept (`Credit::expire`) is past its lifetime by at most a sweep.
fn corroborated(map: &HashMap<PublicKey, MonoDeadline>, key: &PublicKey, now: Option<Now>) -> bool {
    map.get(key)
        .is_some_and(|until| now.is_none_or(|now| !until.passed(now)))
}

/// How often the corroborations are swept for those lapsed, by `M`.
const SWEEP_EVERY_MS: u64 = 60 * 1000;

/// The credit's state, its tables charged to a store of their own ([`planned_bytes`]).
pub struct Credit {
    state: Mutex<State>,
}

impl Default for Credit {
    fn default() -> Self {
        Self::new()
    }
}

impl Credit {
    /// Its tables charged to a store of no bound until the relay's is given (`charge_to`).
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::new(&Gauge::unlimited(Store::Credit))),
        }
    }

    /// Its tables are charged to `gauge` (the budget's `Store::Credit`) from now on, what they
    /// hold now moved to it: past its limit, what would grow them is let go, counted
    /// ([`Credit::full`]).
    pub fn charge_to(&self, gauge: &Arc<Gauge>) {
        let mut state = self.state();
        let bytes = state.bytes();
        // What it was charged before given back first, so a budget charged again holds it once.
        state.charge = gauge.empty();
        let mut charge = gauge.empty();
        let _ = charge.try_grow(bytes);
        state.charge = charge;
    }

    /// The copies and the receivers' corroborations held to `receivers` from now (the receiver
    /// figure, `budget::Budget::receivers`), the oldest let go past it and their tables made no
    /// larger than it needs, so they allocate what [`planned_bytes`] of it plans.
    pub fn set_receivers(&self, receivers: usize) {
        let mut state = self.state();
        let state = &mut *state;
        state.receivers = receivers.max(1);
        let cap = state.receivers;
        state.copies.trim(cap, |held| held.issued_ms);
        state.copies.shrink_within(cap + 1);
        state
            .corroborated_receivers
            .trim(cap, |until| until.mono_ms());
        state.corroborated_receivers.shrink_within(cap + 1);
        let bytes = state.bytes();
        state.charge.shrink_to(bytes);
    }

    /// What it let go because its store had no room: an entry not taken into a table.
    pub fn full(&self) -> u64 {
        self.state().full
    }

    /// What its tables allocate now, as charged.
    pub fn charged(&self) -> usize {
        self.state().charge.bytes()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A key this relay signs with: a credential it signed is its own client's.
    pub fn adopt_identity(&self, key: PublicKey) {
        let mut state = self.state();
        if !state.own.contains(&key) {
            state.own.push(key);
        }
    }

    /// The relay's upload cap, bytes a second (`--max-upload`): the free tier's share is a part of
    /// it. 0, like `Cap::NONE`, sends nothing billed and rations nothing.
    pub fn set_upload_cap(&self, bytes_per_sec: u64) {
        self.state().upload_cap = (bytes_per_sec > 0).then_some(bytes_per_sec);
    }

    /// Whether clients are rationed at all: only once the upload cap is known (and not zero).
    pub fn rations(&self) -> bool {
        self.state().upload_cap.is_some()
    }

    /// A receiver this relay corroborated first-hand (its receptions agreed with verified fixes
    /// that cite it): only such a receiver earns any relay credit here. Made only while the
    /// relay's clock judges (`Now::judging`), as what it agreed with was judged by that clock;
    /// kept [`CORROBORATION_LIFETIME_MS`] by `M`.
    pub fn corroborate_receiver(&self, receiver: PublicKey, now: impl Into<Now>) {
        let now = now.into();
        let mut state = self.state();
        let state = &mut *state;
        if !now.judging() {
            state.unjudged += 1;
            return;
        }
        if !state.corroborated_receivers.insert(
            &mut state.charge,
            receiver,
            now.after(CORROBORATION_LIFETIME_MS),
        ) {
            state.let_go();
        }
        state
            .corroborated_receivers
            .trim(state.receivers, |until| until.mono_ms());
        state.sweep_at = state.sweep_at.min(now.after(SWEEP_EVERY_MS));
        state.settle();
    }

    /// Whether `receiver` stands corroborated here at `now` (`corroborate_receiver`, not yet
    /// lapsed by `M`): the receivers the ingest rate (`shed`) gives a share of their own, where
    /// every other is held to its network group's.
    pub fn corroborated_receiver(&self, receiver: &PublicKey, now: impl Into<Now>) -> bool {
        corroborated(
            &self.state().corroborated_receivers,
            receiver,
            Some(now.into()),
        )
    }

    /// A relay this relay corroborated first-hand (a sharing peer it dealt with): only such a
    /// relay's receipts earn the relay it signed them for any credit here. Made only while the
    /// relay's clock judges, kept [`CORROBORATION_LIFETIME_MS`] by `M`, as a receiver's is.
    pub fn corroborate_relay(&self, relay: PublicKey, now: impl Into<Now>) {
        let now = now.into();
        let mut state = self.state();
        let state = &mut *state;
        if !now.judging() {
            state.unjudged += 1;
            return;
        }
        if !state.corroborated_relays.insert(
            &mut state.charge,
            relay,
            now.after(CORROBORATION_LIFETIME_MS),
        ) {
            state.let_go();
        }
        state
            .corroborated_relays
            .trim(MAX_CORROBORATED_RELAYS, |until| until.mono_ms());
        state.sweep_at = state.sweep_at.min(now.after(SWEEP_EVERY_MS));
        state.settle();
    }

    /// Lets go of the corroborations lapsed by `M`, at most once a [`SWEEP_EVERY_MS`]: the
    /// network's tick calls it every tick.
    pub fn expire(&self, now: impl Into<Now>) {
        let now = now.into();
        let mut state = self.state();
        if !state.sweep_at.passed(now) {
            return;
        }
        state
            .corroborated_receivers
            .retain(|_, until| !until.passed(now));
        state
            .corroborated_relays
            .retain(|_, until| !until.passed(now));
        state.sweep_at =
            if state.corroborated_receivers.is_empty() && state.corroborated_relays.is_empty() {
                MonoDeadline::NEVER
            } else {
                now.after(SWEEP_EVERY_MS)
            };
        state.settle();
    }

    /// Corroborations not made because the clock did not judge, since start.
    pub fn unjudged(&self) -> u64 {
        self.state().unjudged
    }

    /// Signs a credential for `client`.
    pub fn issue(
        &self,
        identity: &impl Signs,
        client: PublicKey,
        products: Streams,
        now: Judged,
    ) -> Result<FirehoseCredential, WireError> {
        let now_ms = now.ms();
        self.adopt_identity(identity.public());
        FirehoseCredential::sign(
            identity,
            &FirehoseCredentialContent {
                client,
                products,
                issued_ms: now_ms,
                expires_ms: now
                    .later(tally_wire::budget::policy::<_, CREDENTIAL_LIFETIME_MS>())
                    .ms(),
            },
        )
    }

    /// The clients this relay vouches for (its operator's): each is signed a credential on its
    /// sessions here ([`Credit::vouch`]), and served here as the credential says.
    /// At most [`MAX_VOUCHED`] of them.
    pub fn vouch_for(&self, clients: impl IntoIterator<Item = PublicKey>) {
        let mut state = self.state();
        let state = &mut *state;
        for client in clients {
            if state.vouched.len() >= MAX_VOUCHED
                || !state.vouched.insert(&mut state.charge, client, ())
            {
                state.let_go();
            }
        }
        state.settle();
    }

    /// Whether this relay vouches for `client`.
    pub fn vouches_for(&self, client: &PublicKey) -> bool {
        self.state().vouched.contains_key(client)
    }

    /// For a session of a client this relay vouches for: a fresh credential bound to the key its
    /// handshake proved, for every product, and this relay's evidence, signed now; the session is
    /// linked here by it. `None` for any other session, or when nothing could be signed.
    pub fn vouch(
        &self,
        identity: &impl Signs,
        asker: &Asker,
        now: Judged,
    ) -> Option<(FirehoseCredential, EvidenceBundle)> {
        if asker.role != AskerRole::Client || !self.vouches_for(&asker.key) {
            return None;
        }
        let credential = self.issue(identity, asker.key, KNOWN_PRODUCTS, now).ok()?;
        let evidence = self.bundle(identity, now).ok()?;
        self.link(asker, &credential, now).ok()?;
        Some((credential, evidence))
    }

    /// A feeder's signed description the hub kept (verified there), in either format: held as
    /// what a bundle's reference to it resolves against ([`resolves`]), and evidence when it names
    /// this relay. Its signature is checked again only when it becomes evidence this relay signs
    /// over, as before references: every description the relay holds passes here, and a check of
    /// each would cost a signature per description a second time.
    ///
    /// One dated further ahead of `now` than any clock skew is refused: it would stand as the
    /// newest for as long as its date is ahead. While the clock does not judge (`strikes::Now`),
    /// none is held: whether its date is ahead cannot be told, and its feeder signs it again.
    pub fn described(&self, info: ReceiverInfo, now: crate::strikes::Now) {
        if !now.judges() {
            return;
        }
        let now = now.judged();
        let (Ok(feeder), Ok(described)) = (info.receiver(), info.description()) else {
            return;
        };
        let (issued_ms, relays) = said(&described);
        // No feeder names more relays than it may publish to: one that does is no feeder's.
        if RECEIPT_AHEAD.ahead(issued_ms, now)
            || relays.len() > tally_wire::credit::MAX_DESCRIBED_RELAYS
        {
            return;
        }
        let mut state = self.state();
        let state = &mut *state;
        let newer = state
            .copies
            .get(&feeder)
            .is_none_or(|held| held.issued_ms < issued_ms);
        if newer {
            let copy = HeldCopy {
                issued_ms,
                description: tally_wire::credit::description_hash(&info),
                relays: relays.to_vec(),
            };
            if !state.copies.insert(&mut state.charge, feeder, copy) {
                state.let_go();
            }
            let receivers = state.receivers;
            state.copies.trim(receivers, |held| held.issued_ms);
        }
        if relays.iter().any(|relay| state.own.contains(relay)) && info.verify().is_ok() {
            let newer = state
                .described
                .get(&feeder)
                .is_none_or(|(_, issued)| *issued < issued_ms);
            if newer && info.as_bytes().len() <= DESCRIPTION_MOST {
                // Held exact (a clone allocates its bytes and no more), so it is charged what it
                // holds.
                if !state
                    .described
                    .insert(&mut state.charge, feeder, (info.clone(), issued_ms))
                {
                    state.let_go();
                }
                state.described.trim(OWN_EVIDENCE, |(_, issued)| *issued);
            }
        }
        state.settle();
    }

    /// This relay's evidence, bundled: the newest of each kind that names it, at most
    /// `MAX_EVIDENCE` each, fewer if they would not fit one record. The same evidence always
    /// bundles alike: newest first, ties in the order of the records' bytes.
    ///
    /// Feeders are named by reference (`EvidenceBundle::sign_referenced`: key, issued time, hash
    /// of the description), never carried: a bundle reaches clients, and an old feeder's
    /// description carries its site. A judging relay resolves each against its own copy.
    pub fn bundle(&self, identity: &impl Signs, now: Judged) -> Result<EvidenceBundle, WireError> {
        let now_ms = now.ms();
        let own = identity.public();
        self.adopt_identity(own);
        let fresh = |issued: u64| {
            !RECEIPT_AHEAD.ahead(issued, now)
                && !tally_wire::budget::EVIDENCE_AGE.older(issued, now)
        };
        let (mut feeders, mut receipts) = {
            let state = self.state();
            let feeders: Vec<(u64, ReceiverInfo)> = state
                .described
                .values()
                .filter(|(info, issued)| {
                    fresh(*issued)
                        && info
                            .description()
                            .is_ok_and(|described| said(&described).1.contains(&own))
                })
                .map(|(info, issued)| (*issued, info.clone()))
                .collect();
            let receipts: Vec<(u64, StripeReceipt)> = state
                .receipts
                .values()
                .filter(|(receipt, issued)| {
                    fresh(*issued) && receipt.content().is_ok_and(|content| content.parent == own)
                })
                .map(|(receipt, issued)| (*issued, receipt.clone()))
                .collect();
            (
                newest_first(feeders, |info| info.as_bytes()),
                newest_first(receipts, |receipt| receipt.as_bytes()),
            )
        };
        let most = tally_wire::credit::MAX_EVIDENCE;
        feeders.truncate(most);
        receipts.truncate(most);
        loop {
            let content = ReferencedEvidenceContent {
                issued_ms: now_ms,
                feeders: feeders
                    .iter()
                    .filter_map(|info| FeederReference::of(info).ok())
                    .collect(),
                receipts: receipts.clone(),
                // A relay's own answers are not evidence (the module's rules): none is carried.
                answers: Vec::new(),
            };
            match EvidenceBundle::sign_referenced(identity, &content) {
                Err(WireError::Oversize(_)) if !(feeders.is_empty() && receipts.is_empty()) => {
                    if feeders.len() >= receipts.len() {
                        feeders.truncate(feeders.len() / 2);
                    } else {
                        receipts.truncate(receipts.len() / 2);
                    }
                }
                signed => return signed,
            }
        }
    }

    /// A child's receipt for a slice this relay delivered: evidence. Only a receipt naming this
    /// relay as the one that delivered is kept; members' reports of shortfalls by others are
    /// sharing's, never this relay's evidence. One dated further ahead of `now` than any clock
    /// skew is refused, and none is kept while the clock does not judge (`strikes::Now`).
    pub fn record_receipt(&self, receipt: StripeReceipt, now: crate::strikes::Now) {
        if !now.judges() {
            return;
        }
        let now = now.judged();
        let (Ok(()), Ok(child), Ok(content)) =
            (receipt.verify(), receipt.signer(), receipt.content())
        else {
            return;
        };
        if !self.state().own.contains(&content.parent)
            || RECEIPT_AHEAD.ahead(content.issued_ms, now)
        {
            return;
        }
        let key = (
            child,
            content.cell.as_u64(),
            content.product.0,
            content.stripe,
        );
        let mut state = self.state();
        let state = &mut *state;
        let newer = state
            .receipts
            .get(&key)
            .is_none_or(|(_, issued)| *issued < content.issued_ms);
        if newer && receipt.as_bytes().len() <= RECEIPT_MOST {
            // A signer holds at most its share: a new one past it takes the place of its own
            // oldest, if it is newer, never another signer's.
            if !state.receipts.contains_key(&key) {
                let own = state
                    .receipts
                    .iter()
                    .filter(|(held, _)| held.0 == child)
                    .map(|(held, (_, issued))| (*issued, *held));
                let count = own.clone().count();
                if count >= RECEIPTS_PER_SIGNER {
                    match own.min() {
                        Some((oldest, held)) if oldest < content.issued_ms => {
                            state.receipts.remove(&held);
                        }
                        _ => {
                            state.settle();
                            return;
                        }
                    }
                }
            }
            // Held exact, as a description is.
            if !state
                .receipts
                .insert(&mut state.charge, key, (receipt.clone(), content.issued_ms))
            {
                state.let_go();
            }
            // Past the cap, a signer this relay never dealt with goes first, whatever the date it
            // put on its receipt: a key made for the purpose, dated as far ahead as is taken,
            // never evicts a known signer's.
            let known = &state.corroborated_relays;
            state
                .receipts
                .trim_ranked(OWN_EVIDENCE, |(signer, ..), (_, issued)| {
                    (known.contains_key(signer), *issued)
                });
        }
        state.settle();
    }

    /// A credential a client presented on its session.
    pub fn presented(&self, asker: &Asker, credential: FirehoseCredential, now: Judged) {
        let _ = self.link(asker, &credential, now);
    }

    /// Checks a credential and, if it holds, links the session to the relay that signed it.
    pub fn link(
        &self,
        asker: &Asker,
        credential: &FirehoseCredential,
        now: Judged,
    ) -> Result<(), Refused> {
        if asker.role != AskerRole::Client {
            return Err(Refused::NotAClient);
        }
        credential.verify().map_err(unreadable)?;
        let relay = credential.signer().map_err(unreadable)?;
        let content = credential.content().map_err(unreadable)?;
        // The key the session's handshake proved: a copied credential is someone else's.
        if content.client != asker.key {
            return Err(Refused::OtherKey);
        }
        if tally_wire::budget::expired(content.expires_ms, now) {
            return Err(Refused::Expired);
        }
        if RECEIPT_AHEAD.ahead(content.issued_ms, now) {
            return Err(Refused::Future);
        }
        let mut state = self.state();
        let state = &mut *state;
        if !state.linked.contains_key(&asker.source) && state.linked.len() >= MAX_LINKED {
            state
                .linked
                .retain(|_, link| !tally_wire::budget::expired(link.expires_ms, now));
            state.settle();
            if state.linked.len() >= MAX_LINKED {
                return Err(Refused::Full);
            }
        }
        let linked = Linked {
            client: content.client,
            relay,
            products: content.products,
            expires_ms: content.expires_ms,
        };
        let taken = state.linked.insert(&mut state.charge, asker.source, linked);
        state.settle();
        if taken {
            Ok(())
        } else {
            state.let_go();
            Err(Refused::Full)
        }
    }

    /// The evidence behind a credential a client presented.
    /// Each signature inside it is a token of `pace`, the asker's (`check`).
    pub fn evidence(
        &self,
        asker: &Asker,
        bundle: EvidenceBundle,
        now: Judged,
        pace: Option<&RecordPace>,
    ) {
        let _ = (asker, self.weigh(&bundle, now, pace));
    }

    /// Checks a bundle and keeps what its good records show of its relay, if it is newer than what
    /// is held. The bundle itself must verify and be in time; a bad record in it is skipped. Each
    /// signature inside it is a token of `pace` (`check`).
    pub fn weigh(
        &self,
        bundle: &EvidenceBundle,
        now: Judged,
        pace: Option<&RecordPace>,
    ) -> Result<(), Refused> {
        let shown = check(bundle, now, pace)?;
        let relay = bundle.signer().map_err(unreadable)?;
        let mut state = self.state();
        let state = &mut *state;
        let newer = state
            .shown
            .get(&relay)
            .is_none_or(|held| held.issued_ms < shown.issued_ms);
        if newer {
            if !state.shown.insert(&mut state.charge, relay, shown) {
                state.let_go();
            }
            state.shown.trim(MAX_RELAYS_SHOWN, |held| held.issued_ms);
        }
        state.settle();
        Ok(())
    }

    /// What `relay`'s evidence earns it here now, in bytes a second, before it is split.
    pub fn earned(&self, relay: &PublicKey, now: Judged) -> u64 {
        let state = self.state();
        earned(&state, relay, now)
    }

    /// The subscription a client is served, given what it asked for: held to its allowance
    /// (`allowance`). Any other role is granted nothing here: what it may receive is the link's
    /// to decide (`link`'s `Peer::grant`), so no role reaches a stream by being mistaken for a
    /// client's peer.
    pub fn admit(&self, asker: &Asker, asked: Subscription, now: Judged) -> Subscription {
        if asker.role != AskerRole::Client {
            return Subscription {
                streams: Streams(0),
                regions: Vec::new(),
            };
        }
        // A client on loopback is never billed (the egress counts it apart), so never rationed.
        if asker.loopback {
            return asked;
        }
        let served = self.admit_client(asker, &asked, now);
        self.remember(asker.source, asked, served.clone());
        served
    }

    /// A client session admitted again with what it last asked for: the new subscription when it
    /// changed (a credential expired, credit grew or shrank), else `None`.
    pub fn readmit(&self, asker: &Asker, now: Judged) -> Option<Subscription> {
        let (asked, before) = self.state().asked.get(&asker.source).cloned()?;
        let served = self.admit_client(asker, &asked, now);
        if served == before {
            return None;
        }
        if self.state().asked.contains_key(&asker.source) {
            self.remember(asker.source, asked, served.clone());
        }
        Some(served)
    }

    /// What `source` asked for and is served, remembered (exact, so it is charged what it holds)
    /// until the session leaves: the oldest sessions' go first past [`ASKED_REMEMBERED`]
    /// (connection ids grow). One the store has no room for is not remembered, counted.
    fn remember(&self, source: u64, mut asked: Subscription, mut served: Subscription) {
        asked.regions.shrink_to_fit();
        served.regions.shrink_to_fit();
        let mut state = self.state();
        let state = &mut *state;
        if !state
            .asked
            .insert(&mut state.charge, source, (asked, served))
        {
            state.let_go();
        }
        if state.asked.len() > ASKED_REMEMBERED {
            let mut sources: Vec<u64> = state.asked.keys().copied().collect();
            sources.sort_unstable();
            for source in sources.into_iter().take(ASKED_REMEMBERED / 4) {
                state.asked.remove(&source);
            }
        }
        state.settle();
    }

    fn admit_client(&self, asker: &Asker, asked: &Subscription, now: Judged) -> Subscription {
        let asked = asked.clone();
        let mut state = self.state();
        let state = &mut *state;
        let Some(cap) = state.upload_cap else {
            return asked;
        };
        let (allowance, free) = allowance_of(state, |source, _| source == asker.source, now);
        let served = narrow(&asked, &allowance);
        if !free || served.streams.0 == 0 {
            state.free.remove(&asker.source);
            state.settle();
            return served;
        }
        let room = cap / FREE_SHARE_OF_CAP.1 * FREE_SHARE_OF_CAP.0 / Allowance::FREE.bytes_per_sec;
        let room = usize::try_from(room)
            .unwrap_or(usize::MAX)
            .min(ASKED_REMEMBERED);
        if state.free.contains_key(&asker.source)
            || (state.free.len() < room && state.free.insert(&mut state.charge, asker.source, ()))
        {
            served
        } else {
            Subscription {
                streams: Streams(0),
                regions: Vec::new(),
            }
        }
    }

    /// A session ended: its link, its free-tier place and what it asked for go.
    pub fn left(&self, source: u64) {
        let mut state = self.state();
        state.linked.remove(&source);
        state.free.remove(&source);
        state.asked.remove(&source);
        state.settle();
    }

    /// What `client` may read now: the best of its sessions' links, or the free tier.
    pub fn allowance(&self, client: &PublicKey, now: Judged) -> Allowance {
        let state = self.state();
        allowance_of(&state, |_, link| link.client == *client, now).0
    }
}

/// What a description of either format says of the relays it chose, and when it said it.
fn said(described: &tally_wire::batch::Description) -> (u64, &[PublicKey]) {
    match described {
        tally_wire::batch::Description::Site(content) => (content.issued_ms, &content.relays),
        tally_wire::batch::Description::Public(content) => (content.issued_ms, &content.relays),
    }
}

/// Whether a feeder a bundle of `relay` shows counts at a judge holding `copy`, its own copy of
/// that feeder's newest description: one carried whole was checked already; one named by
/// reference counts when the judge holds the very description named (same hash) and it names
/// `relay`, or a newer one that still names it (the feeder signed again since; it still chose
/// the relay). A reference the judge cannot resolve counts nothing: a relay cannot be credited
/// for a feeder on its own word.
fn resolves(copy: Option<&HeldCopy>, shown: &ShownFeeder, relay: &PublicKey) -> bool {
    let Some(named) = shown.description else {
        return true;
    };
    copy.is_some_and(|copy| {
        copy.relays.contains(relay)
            && (copy.description == named || copy.issued_ms > shown.issued_ms)
    })
}

/// `dated` records, newest first, ties in the order of their bytes: one order however they were
/// held.
fn newest_first<T>(mut dated: Vec<(u64, T)>, bytes: impl Fn(&T) -> &[u8]) -> Vec<T> {
    dated.sort_by(|(a_issued, a), (b_issued, b)| {
        b_issued.cmp(a_issued).then_with(|| bytes(a).cmp(bytes(b)))
    });
    dated.into_iter().map(|(_, record)| record).collect()
}

/// What `bundle` shows of the relay that signed it: the bundle's own signature and time are
/// checked (refused whole if either fails), then each record by its own signature, body and time
/// and that it says what it must of that relay; a record that fails any is skipped. Delivery
/// answers are the relay's own word and never weighed.
///
/// Every signature verified inside it is one token of `pace`, the pace the bundle's asker's
/// records were taken by (`ingest::RecordPace::owe`), owed and paid before that connection's next
/// record is read: a bundle is one record on the wire but up to
/// `ingest::EVIDENCE_SIGNATURES` and its own verifications, some 3.5 ms of a core, while its record
/// was planned as one (`cores::RUNTIME_NANOS_PER_RECORD`). Before, a session sending bundles at
/// its records' pace had the relay verify some 130 times what the cores planned for it. `None`
/// for a bundle no session brought (the relay's own).
pub fn check(
    bundle: &EvidenceBundle,
    now: Judged,
    pace: Option<&RecordPace>,
) -> Result<Shown, Refused> {
    let spend = || {
        if let Some(pace) = pace {
            pace.owe(1);
        }
    };
    bundle.verify().map_err(unreadable)?;
    let relay = bundle.signer().map_err(unreadable)?;
    let (issued_ms, receipts) = match bundle.evidence().map_err(unreadable)? {
        Evidence::Carried(content) => {
            let mut feeders = Vec::with_capacity(content.feeders.len());
            for info in &content.feeders {
                spend();
                let (Ok(()), Ok(feeder), Ok(described)) =
                    (info.verify(), info.receiver(), info.description())
                else {
                    continue;
                };
                let (issued_ms, relays) = said(&described);
                if RECEIPT_AHEAD.ahead(issued_ms, now)
                    || feeder == relay
                    || !relays.contains(&relay)
                {
                    continue;
                }
                feeders.push(ShownFeeder {
                    feeder,
                    issued_ms,
                    description: None,
                });
            }
            (content.issued_ms, (feeders, content.receipts))
        }
        // By reference: nothing to verify here; each counts only where the judge's own copy
        // resolves it (`resolves`).
        Evidence::Referenced(content) => {
            let feeders = content
                .feeders
                .iter()
                .filter(|named| !RECEIPT_AHEAD.ahead(named.issued_ms, now) && named.feeder != relay)
                .map(|named| ShownFeeder {
                    feeder: named.feeder,
                    issued_ms: named.issued_ms,
                    description: Some(named.description),
                })
                .collect();
            (content.issued_ms, (feeders, content.receipts))
        }
    };
    let (feeders, receipts) = receipts;
    if RECEIPT_AHEAD.ahead(issued_ms, now) {
        return Err(Refused::Future);
    }
    if tally_wire::budget::EVIDENCE_AGE.older(issued_ms, now) {
        return Err(Refused::Stale);
    }
    let mut shown = Shown {
        issued_ms,
        feeders,
        slices: Vec::with_capacity(receipts.len()),
    };
    for receipt in &receipts {
        spend();
        let (Ok(()), Ok(child), Ok(slice)) =
            (receipt.verify(), receipt.signer(), receipt.content())
        else {
            continue;
        };
        if RECEIPT_AHEAD.ahead(slice.issued_ms, now) || child == relay || slice.parent != relay {
            continue;
        }
        // No stripe of one area carries more than the area's whole raw. `seconds` is at least 1.
        let ceiling = AREA_FEEDERS * FEEDER_BYTES_PER_SEC;
        shown.slices.push(Slice {
            child,
            rate: (slice.bytes / slice.seconds()).min(ceiling),
            issued_ms: slice.issued_ms,
        });
    }
    // Exact, so a table holding it is charged what it holds (`planned_bytes`).
    shown.feeders.shrink_to_fit();
    shown.slices.shrink_to_fit();
    Ok(shown)
}

/// What a weigher accepts of a bundle's items, beyond their signatures ([`worth`]).
pub struct Corroboration<'a> {
    /// Whether a feeder the bundle shows naming the relay counts (by reference, only where it
    /// resolves: [`resolves`]).
    pub feeder: &'a dyn Fn(&ShownFeeder) -> bool,
    /// What a child's receipts count once per (the child itself, or its network), if the child's
    /// receipts count at all.
    pub child: &'a dyn Fn(&PublicKey) -> Option<Unit>,
    /// When set, what every unit of children counted is worth, whatever its receipts say it
    /// delivered (and undecayed, while its newest receipt is younger than `tally_wire::budget::EVIDENCE_AGE`):
    /// for a weigher that must not take the parties' own figures, since a child signs whatever
    /// rate its parent asks of it, and counts witnesses instead.
    pub flat: Option<u64>,
}

/// What one child's receipts are counted once per ([`Corroboration::child`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unit {
    /// One child: many slices from it still saw one relay deliver to it.
    Child(PublicKey),
    /// One network: children on one network, however many keys, are one witness.
    Network(u64),
}

/// What `shown`, the evidence of `relay`, is worth at `now_ms` under `corroboration`, in bytes a
/// second: the one weigher of evidence. Each feeder counted once (`FEEDER_CREDIT`), each unit of
/// children once (its best receipt's delivered rate), each item decayed by the age of its own
/// signature. Firehose credit weighs with what this relay corroborated first-hand
/// ([`Credit::earned`]); the provider directory weighs with what every relay holds alike, so
/// that the same evidence ranks alike everywhere (`directory`).
pub fn worth(
    shown: &Shown,
    relay: &PublicKey,
    corroboration: &Corroboration<'_>,
    now: Judged,
) -> u64 {
    let mut hosted: HashMap<PublicKey, u64> = HashMap::new();
    for shown in &shown.feeders {
        if (corroboration.feeder)(shown) {
            let newest = hosted.entry(shown.feeder).or_insert(shown.issued_ms);
            *newest = (*newest).max(shown.issued_ms);
        }
    }
    let mut children: HashMap<Unit, u64> = HashMap::new();
    for slice in &shown.slices {
        if slice.child == *relay {
            continue;
        }
        if let Some(unit) = (corroboration.child)(&slice.child) {
            let value = match corroboration.flat {
                Some(_) if tally_wire::budget::EVIDENCE_AGE.older(slice.issued_ms, now) => 0,
                Some(flat) => flat,
                None => decayed(slice.rate, slice.issued_ms, now),
            };
            let best = children.entry(unit).or_insert(0);
            *best = (*best).max(value);
        }
    }
    hosted
        .values()
        .map(|issued| decayed(FEEDER_CREDIT, *issued, now))
        .chain(children.into_values())
        .fold(0, u64::saturating_add)
}

/// What `relay`'s evidence earns it at this relay now: [`worth`], counting only the receivers and
/// relays this relay corroborated first-hand, one witness per child.
fn earned(state: &State, relay: &PublicKey, now: Judged) -> u64 {
    let Some(shown) = state.shown.get(relay) else {
        return 0;
    };
    let feeder = |shown: &ShownFeeder| {
        corroborated(&state.corroborated_receivers, &shown.feeder, None)
            && resolves(state.copies.get(&shown.feeder), shown, relay)
    };
    let child = |key: &PublicKey| {
        corroborated(&state.corroborated_relays, key, None).then_some(Unit::Child(*key))
    };
    worth(
        shown,
        relay,
        &Corroboration {
            feeder: &feeder,
            child: &child,
            flat: None,
        },
        now,
    )
}

/// The allowance of the sessions `matches` picks: the best of their links (a relay's own client
/// as asked; a linked one by its share of its relay's credit, split across every session linked
/// to that relay), or the free tier. The flag says whether it is the free tier.
fn allowance_of(
    state: &State,
    matches: impl Fn(u64, &Linked) -> bool,
    now: Judged,
) -> (Allowance, bool) {
    let mut best: Option<Allowance> = None;
    for (source, link) in state.linked.iter() {
        if tally_wire::budget::expired(link.expires_ms, now) || !matches(*source, link) {
            continue;
        }
        let allowance = if state.own.contains(&link.relay) {
            Allowance::vouched(link.products)
        } else {
            let sessions = state
                .linked
                .values()
                .filter(|other| {
                    other.relay == link.relay && !tally_wire::budget::expired(other.expires_ms, now)
                })
                .count()
                .max(1);
            let share = earned(state, &link.relay, now) / sessions as u64;
            if share <= Allowance::FREE.bytes_per_sec {
                continue;
            }
            Allowance::linked(link.products, share)
        };
        if best.is_none_or(|held| held.bytes_per_sec < allowance.bytes_per_sec) {
            best = Some(allowance);
        }
    }
    match best {
        Some(allowance) => (allowance, false),
        None => (Allowance::FREE, true),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use tally_wire::Identity;
    use tally_wire::batch::{Clock, ReceiverInfoContent};
    use tally_wire::clocks::recorded::judged;
    use tally_wire::{
        DeliveryAnswer, DeliveryAnswerContent, Location, Possession, StripeReceiptContent,
    };

    use super::*;
    use std::time::Duration;
    use tally_wire::EvidenceBundleContent;

    type Result<T = ()> = std::result::Result<T, String>;

    const NOW: u64 = 1_791_244_800_000;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn identity() -> Result<Identity> {
        Identity::generate().map_err(text)
    }

    /// An area cell over the Los Angeles basin, and one of its neighbours' worth of others.
    fn area(lon_e7: i32) -> Result<Region> {
        let location = Location {
            lat_e7: 340_000_000,
            lon_e7,
            alt_m: 0,
            precision_m: 0,
        };
        Region::containing(&location, AREA_RESOLUTION).map_err(text)
    }

    fn areas(count: usize) -> Result<Vec<Region>> {
        let mut found: Vec<Region> = Vec::new();
        let mut lon = -1_180_000_000;
        while found.len() < count {
            let cell = area(lon)?;
            if !found.contains(&cell) {
                found.push(cell);
            }
            lon += 5_000_000;
        }
        Ok(found)
    }

    fn asker(role: AskerRole, key: PublicKey, source: u64) -> Asker {
        Asker {
            role,
            key,
            source,
            loopback: false,
            address: None,
        }
    }

    fn info(feeder: &Identity, relay: PublicKey, issued_ms: u64) -> Result<ReceiverInfo> {
        ReceiverInfo::sign(
            feeder,
            &ReceiverInfoContent {
                issued_ms,
                location: None,
                clock: Clock::Beast,
                software: "tally-feed".to_owned(),
                relays: vec![relay],
            },
        )
        .map_err(text)
    }

    fn receipt(
        child: &Identity,
        parent: PublicKey,
        bytes_per_sec: u64,
        issued_ms: u64,
    ) -> Result<StripeReceipt> {
        StripeReceipt::sign(
            child,
            &StripeReceiptContent {
                parent,
                cell: area(-1_180_000_000)?,
                product: Streams::RAW,
                stripe: 1,
                stripes_of: 4,
                first_second: 100,
                last_second: 159,
                records: 900,
                bytes: bytes_per_sec * 60,
                digest: [7; 32],
                issued_ms,
            },
        )
        .map_err(text)
    }

    /// A receipt from `child` to `parent` for `stripe`, issued at `issued_ms`.
    fn receipt_of(
        child: &Identity,
        parent: PublicKey,
        degree: i32,
        issued_ms: u64,
    ) -> Result<StripeReceipt> {
        StripeReceipt::sign(
            child,
            &StripeReceiptContent {
                parent,
                cell: area(-1_180_000_000 + degree * 5_000_000)?,
                product: Streams::RAW,
                stripe: 0,
                stripes_of: 4,
                first_second: 100,
                last_second: 159,
                records: 900,
                bytes: 60_000,
                digest: [7; 32],
                issued_ms,
            },
        )
        .map_err(text)
    }

    /// The receipts a relay holds as its evidence are bounded per signer, and a signer it never
    /// dealt with goes first: keys made for the purpose, each signing a receipt dated as far ahead
    /// as is taken, evict none of a known child's, and one key holds no more than its share.
    /// Before, the newest by date were kept, so such receipts pushed every genuine one out.
    #[test]
    fn receipts_from_fresh_keys_dated_ahead_evict_no_known_childs() -> Result {
        let relay = identity()?;
        let credit = rationing();
        credit.adopt_identity(relay.public());
        let now = crate::strikes::Now::judging(NOW);
        let children: Vec<Identity> = (0..16).map(|_| identity()).collect::<Result<_>>()?;
        for child in &children {
            credit.corroborate_relay(child.public(), crate::sharing::Now::from(NOW));
            for degree in 0..8 {
                credit.record_receipt(receipt_of(child, relay.public(), degree, NOW)?, now);
            }
        }
        for _ in 0..2 * OWN_EVIDENCE {
            let fresh = identity()?;
            credit.record_receipt(receipt_of(&fresh, relay.public(), 0, NOW + 10_000)?, now);
        }
        let known: std::collections::HashSet<PublicKey> =
            children.iter().map(Identity::public).collect();
        let held = credit
            .state()
            .receipts
            .keys()
            .filter(|(signer, ..)| known.contains(signer))
            .count();
        let cells: std::collections::HashSet<u64> = (0..8)
            .map(|degree| area(-1_180_000_000 + degree * 5_000_000).map(|cell| cell.as_u64()))
            .collect::<Result<_>>()?;
        assert_eq!(held, 16 * cells.len(), "known children's receipts evicted");
        // One key, as many receipts as it can sign: its share at most.
        let greedy = identity()?;
        for degree in 0..250 {
            credit.record_receipt(receipt_of(&greedy, relay.public(), degree, NOW)?, now);
        }
        let own = credit
            .state()
            .receipts
            .keys()
            .filter(|(signer, ..)| *signer == greedy.public())
            .count();
        assert!(own <= RECEIPTS_PER_SIGNER, "one signer holds {own}");
        Ok(())
    }

    /// A corroboration is made only while the clock judges, and lapses by `M`: a step of the
    /// judging clock an hour back or a day on neither keeps one past its lifetime nor lets it go
    /// before.
    #[test]
    fn corroborations_need_a_judging_clock_and_lapse_by_the_monotonic_one() -> Result {
        let credit = Credit::new();
        let at = |judged: u64, mono: u64, judging: bool| {
            crate::sharing::Now::from(crate::ingest::Stamp::recorded(
                mono, 0, judged, judged, judging,
            ))
        };
        let unsynced = identity()?.public();
        credit.corroborate_receiver(unsynced, at(NOW, 1_000, false));
        credit.corroborate_relay(unsynced, at(NOW, 1_000, false));
        assert!(!credit.corroborated_receiver(&unsynced, at(NOW, 1_000, true)));
        assert_eq!(credit.unjudged(), 2);
        let seen = identity()?.public();
        credit.corroborate_receiver(seen, at(NOW, 1_000, true));
        let day = 24 * 60 * 60 * 1000;
        // `J` a day on, `M` a second: still corroborated.
        assert!(credit.corroborated_receiver(&seen, at(NOW + 2 * day, 2_000, true)));
        // `J` an hour back, `M` past the lifetime: lapsed, and swept.
        let lapsed = at(NOW - 3_600_000, 1_000 + CORROBORATION_LIFETIME_MS, true);
        assert!(!credit.corroborated_receiver(&seen, lapsed));
        credit.expire(lapsed);
        assert!(credit.state().corroborated_receivers.is_empty());
        Ok(())
    }

    fn answer(relay: &Identity, receiver: PublicKey, issued_ms: u64) -> Result<DeliveryAnswer> {
        DeliveryAnswer::sign(
            relay,
            &DeliveryAnswerContent {
                nonce: [1; 32],
                receiver,
                boot_id: 1,
                issued_ms,
                takes_area: true,
                entries: vec![(
                    1,
                    Possession::Proved {
                        key: 2,
                        tag: [2; 16],
                    },
                )],
            },
        )
        .map_err(text)
    }

    fn bundle(
        relay: &Identity,
        feeders: Vec<ReceiverInfo>,
        receipts: Vec<StripeReceipt>,
        answers: Vec<DeliveryAnswer>,
    ) -> Result<EvidenceBundle> {
        EvidenceBundle::sign(
            relay,
            &EvidenceBundleContent {
                issued_ms: NOW,
                feeders,
                receipts,
                answers,
            },
        )
        .map_err(text)
    }

    /// `count` feeders naming `relay`, each corroborated at `judge`.
    fn hosted(judge: &Credit, relay: &Identity, count: usize) -> Result<Vec<ReceiverInfo>> {
        (0..count)
            .map(|_| {
                let feeder = identity()?;
                judge.corroborate_receiver(feeder.public(), crate::sharing::Now::from(NOW));
                info(&feeder, relay.public(), NOW)
            })
            .collect()
    }

    fn rationing() -> Credit {
        let credit = Credit::new();
        credit.set_upload_cap(1 << 30);
        credit
    }

    fn sub(streams: Streams, regions: Vec<Region>) -> Subscription {
        Subscription { streams, regions }
    }

    fn nothing() -> Subscription {
        sub(Streams(0), Vec::new())
    }

    /// Every table is charged what it allocates (`Store::Credit`): after descriptions, receipts,
    /// bundles, corroborations, links, subscriptions and the operator's clients come and some go,
    /// what its tables hold allocated on this thread is what it is charged, to the byte. Before,
    /// the tables sat under no gauge at all, bounded only by their caps.
    #[test]
    fn the_credit_is_charged_what_its_tables_allocate() -> Result {
        let relay = identity()?;
        let credit = rationing();
        credit.adopt_identity(relay.public());
        let base = tally_counting::Counting::live();
        for n in 0..120u64 {
            let feeder = identity()?;
            credit.corroborate_receiver(feeder.public(), crate::sharing::Now::from(NOW + n));
            credit.described(
                info(&feeder, relay.public(), NOW + n)?,
                crate::strikes::Now::judging(NOW + n),
            );
            if n % 3 == 0 {
                credit.corroborate_relay(feeder.public(), crate::sharing::Now::from(NOW + n));
                credit.record_receipt(
                    receipt(&feeder, relay.public(), 1_000, NOW)?,
                    crate::strikes::Now::judging(NOW + n),
                );
            }
        }
        // Another relay's descriptions, held only to resolve references by.
        let other = identity()?;
        for _ in 0..40 {
            let feeder = identity()?;
            credit.described(
                info(&feeder, other.public(), NOW)?,
                crate::strikes::Now::judging(NOW),
            );
        }
        for _ in 0..4 {
            let shown = identity()?;
            let feeders = hosted(&credit, &shown, 8)?;
            credit
                .weigh(
                    &bundle(&shown, feeders, Vec::new(), Vec::new())?,
                    judged(NOW),
                    None,
                )
                .map_err(text)?;
        }
        let clients: Vec<Identity> = (0..12).map(|_| identity()).collect::<Result<_>>()?;
        credit.vouch_for(clients.iter().map(Identity::public));
        for (source, client) in clients.iter().enumerate() {
            let session = asker(AskerRole::Client, client.public(), source as u64);
            let credential = credit
                .issue(&relay, client.public(), Streams::RAW, judged(NOW))
                .map_err(text)?;
            credit
                .link(&session, &credential, judged(NOW))
                .map_err(|e| format!("{e:?}"))?;
            let _ = credit.admit(&session, sub(Streams::POSITIONS, areas(3)?), judged(NOW));
        }
        for source in 0..4 {
            credit.left(source);
        }
        drop((clients, other));
        let measured = tally_counting::Counting::live() - base;
        assert_eq!(
            credit.charged() as isize,
            measured,
            "charged {}, allocated {measured}",
            credit.charged()
        );
        assert!(credit.charged() <= planned_bytes(UNSIZED_RECEIVERS));
        assert_eq!(credit.full(), 0);
        Ok(())
    }

    /// The copies and the receivers' corroborations held to a receiver figure, churned past it
    /// by three times its receivers, allocate no more than [`planned_bytes`] of the figure plans,
    /// whatever else the credit holds within its own caps. Measured by the allocator, on this
    /// thread.
    #[test]
    fn the_receivers_tables_stay_within_their_plan_at_a_figure() -> Result {
        const RECEIVERS: usize = 200;
        let relay = identity()?;
        let credit = rationing();
        credit.adopt_identity(relay.public());
        credit.set_receivers(RECEIVERS);
        let feeders: Vec<Identity> = (0..3 * RECEIVERS)
            .map(|_| identity())
            .collect::<Result<_>>()?;
        let other = identity()?;
        let infos: Vec<ReceiverInfo> = feeders
            .iter()
            .enumerate()
            .map(|(n, feeder)| info(feeder, other.public(), NOW + n as u64))
            .collect::<Result<_>>()?;
        let base = tally_counting::Counting::peak_base();
        for (n, (feeder, described)) in feeders.iter().zip(infos).enumerate() {
            let at = NOW + n as u64;
            credit.corroborate_receiver(feeder.public(), crate::sharing::Now::from(at));
            credit.described(described, crate::strikes::Now::judging(at));
        }
        let peak = usize::try_from(tally_counting::Counting::peak_since(base)).unwrap_or(0);
        let state = credit.state();
        assert!(state.copies.len() <= RECEIVERS + 1);
        assert!(state.corroborated_receivers.len() <= RECEIVERS + 1);
        drop(state);
        // The receivers' tables' share of the plan: the other tables are untouched here.
        let planned = planned_bytes(RECEIVERS) - FIXED_TABLES_BYTES;
        assert!(peak <= planned, "{peak} at the peak, {planned} planned");
        Ok(())
    }

    /// A description and a receipt are charged what their bytes allocate (`allocated`, their
    /// capacity), not their length: held with room to spare, the room is charged too. Before,
    /// the length was, exact only while every one held was a clone.
    #[test]
    fn a_held_description_and_receipt_are_charged_their_capacity() -> Result {
        let relay = identity()?;
        let feeder = identity()?;
        let roomy = |bytes: &[u8]| {
            let mut held = Vec::with_capacity(bytes.len() + 4_096);
            held.extend_from_slice(bytes);
            held
        };
        let mut state = State::new(&Gauge::new(Store::Credit, usize::MAX));
        let base = tally_counting::Counting::live();
        let described = {
            let signed = info(&feeder, relay.public(), NOW)?;
            ReceiverInfo::from_bytes(roomy(signed.as_bytes())).map_err(text)?
        };
        let held = {
            let signed = receipt(&feeder, relay.public(), 1_000, NOW)?;
            StripeReceipt::from_bytes(roomy(signed.as_bytes())).map_err(text)?
        };
        let State {
            described: table,
            receipts,
            charge,
            ..
        } = &mut state;
        assert!(table.insert(charge, feeder.public(), (described, NOW)));
        assert!(receipts.insert(charge, (feeder.public(), 0, 0, 0), (held, NOW)));
        state.settle();
        // All the two tables allocate, the entries' spare room with them, to the byte.
        let measured = tally_counting::Counting::live() - base;
        let charged = state.bytes();
        assert_eq!(
            charged as isize, measured,
            "charged {charged}, allocated {measured}"
        );
        assert!(charged > 2 * 4_096, "{charged}");
        Ok(())
    }

    /// A store with no room lets what would grow a table go, counted, and holds within its
    /// limit: what was taken first stays.
    #[test]
    fn a_full_credit_store_lets_entries_go() -> Result {
        let credit = Credit::new();
        let limit = 16 << 10;
        credit.charge_to(&Gauge::new(Store::Credit, limit));
        let first = identity()?.public();
        credit.corroborate_receiver(first, crate::sharing::Now::from(NOW));
        for _ in 0..2_000 {
            credit.corroborate_receiver(identity()?.public(), crate::sharing::Now::from(NOW));
        }
        assert!(credit.full() > 0, "nothing was let go");
        assert!(credit.charged() <= limit);
        assert!(credit.corroborated_receiver(&first, crate::sharing::Now::from(NOW)));
        Ok(())
    }

    /// The most a held description and a receipt take are within what the plan holds for each
    /// (`DESCRIPTION_MOST`, `RECEIPT_MOST`): a description with a site, a software name of 255
    /// bytes and the most relays one may name; and a description naming more relays than any
    /// feeder does is not held at all, neither as a copy nor as evidence.
    #[test]
    fn what_the_credit_holds_is_within_its_plan() -> Result {
        let feeder = identity()?;
        let relays: Vec<PublicKey> = (0..tally_wire::credit::MAX_DESCRIBED_RELAYS)
            .map(|_| identity().map(|relay| relay.public()))
            .collect::<Result<_>>()?;
        let largest = |relays: Vec<PublicKey>| {
            ReceiverInfo::sign(
                &feeder,
                &ReceiverInfoContent {
                    issued_ms: NOW,
                    location: Some(Location {
                        lat_e7: -899_999_999,
                        lon_e7: -1_799_999_999,
                        alt_m: -400,
                        precision_m: u32::MAX,
                    }),
                    clock: Clock::Beast,
                    software: "x".repeat(255),
                    relays,
                },
            )
            .map_err(text)
        };
        let most = largest(relays.clone())?;
        assert!(
            most.as_bytes().len() <= DESCRIPTION_MOST,
            "{}",
            most.as_bytes().len()
        );
        let child = identity()?;
        let held = receipt(&child, relays[0], u64::MAX / 60, NOW)?;
        assert!(
            held.as_bytes().len() <= RECEIPT_MOST,
            "{}",
            held.as_bytes().len()
        );
        // One relay more than a description may name: neither copy nor evidence.
        let credit = Credit::new();
        credit.adopt_identity(relays[0]);
        let mut more = relays.clone();
        more.push(identity()?.public());
        credit.described(largest(more)?, crate::strikes::Now::judging(NOW));
        let held = |credit: &Credit| {
            let state = credit.state();
            (state.copies.len(), state.described.len())
        };
        assert_eq!(held(&credit), (0, 0));
        credit.described(most, crate::strikes::Now::judging(NOW));
        assert_eq!(held(&credit), (1, 1));
        Ok(())
    }

    #[test]
    fn a_credential_bound_to_another_key_is_refused() -> Result {
        let (relay, client, thief) = (identity()?, identity()?, identity()?);
        let issuer = Credit::new();
        let credential = issuer
            .issue(&relay, client.public(), Streams::RAW, judged(NOW))
            .map_err(text)?;
        let judge = Credit::new();
        let copied = asker(AskerRole::Client, thief.public(), 1);
        assert_eq!(
            judge.link(&copied, &credential, judged(NOW)),
            Err(Refused::OtherKey)
        );
        assert_eq!(
            judge.allowance(&thief.public(), judged(NOW)),
            Allowance::FREE
        );
        // Presented by its own key it links; by a relay's session it does not.
        let own = asker(AskerRole::Client, client.public(), 2);
        assert_eq!(judge.link(&own, &credential, judged(NOW)), Ok(()));
        let relay_session = asker(AskerRole::Relay, client.public(), 3);
        assert_eq!(
            judge.link(&relay_session, &credential, judged(NOW)),
            Err(Refused::NotAClient)
        );
        // A tampered credential does not verify.
        let mut bytes = credential.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let forged = FirehoseCredential::from_bytes(bytes).map_err(text)?;
        assert!(matches!(
            judge.link(&own, &forged, judged(NOW)),
            Err(Refused::Unreadable(_))
        ));
        Ok(())
    }

    #[test]
    fn an_expired_credential_is_refused_and_a_lapsed_link_is_the_free_tier() -> Result {
        let (relay, client) = (identity()?, identity()?);
        let judge = rationing();
        let credential = Credit::new()
            .issue(&relay, client.public(), Streams::POSITIONS, judged(NOW))
            .map_err(text)?;
        let session = asker(AskerRole::Client, client.public(), 1);
        assert_eq!(
            judge.link(&session, &credential, judged(NOW + CREDENTIAL_LIFETIME_MS)),
            Err(Refused::Expired)
        );
        let early = Credit::new()
            .issue(
                &relay,
                client.public(),
                Streams::POSITIONS,
                judged(
                    NOW + 2 * tally_wire::budget::RECEIPT_AHEAD
                        .span::<tally_wire::clocks::Judged>()
                        .ms(),
                ),
            )
            .map_err(text)?;
        assert_eq!(
            judge.link(&session, &early, judged(NOW)),
            Err(Refused::Future)
        );
        // Linked while valid, with credit enough to lift it; once expired, the free tier.
        judge
            .weigh(
                &bundle(&relay, hosted(&judge, &relay, 8)?, vec![], vec![])?,
                judged(NOW),
                None,
            )
            .map_err(text)?;
        judge
            .link(&session, &credential, judged(NOW))
            .map_err(text)?;
        assert!(
            judge.allowance(&client.public(), judged(NOW)).bytes_per_sec
                > Allowance::FREE.bytes_per_sec
        );
        assert_eq!(
            judge.allowance(&client.public(), judged(NOW + CREDENTIAL_LIFETIME_MS)),
            Allowance::FREE
        );
        Ok(())
    }

    #[test]
    fn a_bad_record_in_a_bundle_is_skipped_and_the_rest_counts() -> Result {
        let relay = identity()?;
        let judge = Credit::new();
        let mut feeders = hosted(&judge, &relay, 5)?;
        let mut bytes = feeders[2].as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        feeders[2] = ReceiverInfo::from_bytes(bytes).map_err(text)?;
        // A description naming another relay, one dated ahead of any skew, a receipt for another
        // parent: each is skipped, and the four good descriptions count.
        let other = identity()?;
        feeders.extend(hosted(&judge, &other, 1)?);
        let early = identity()?;
        judge.corroborate_receiver(early.public(), crate::sharing::Now::from(NOW));
        feeders.push(info(
            &early,
            relay.public(),
            NOW + 2 * tally_wire::budget::RECEIPT_AHEAD
                .span::<tally_wire::clocks::Judged>()
                .ms(),
        )?);
        let child = identity()?;
        judge.corroborate_relay(child.public(), crate::sharing::Now::from(NOW));
        let mixed = bundle(
            &relay,
            feeders,
            vec![
                receipt(&child, other.public(), 1_000, NOW)?,
                receipt(
                    &child,
                    relay.public(),
                    3_000,
                    NOW + 2 * tally_wire::budget::RECEIPT_AHEAD
                        .span::<tally_wire::clocks::Judged>()
                        .ms(),
                )?,
            ],
            vec![],
        )?;
        judge.weigh(&mixed, judged(NOW), None).map_err(text)?;
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW)),
            4 * FEEDER_CREDIT
        );
        // The bundle's own signature and time are not skipped: a forged or future bundle is
        // refused whole.
        let mut bytes = mixed.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let forged = EvidenceBundle::from_bytes(bytes).map_err(text)?;
        assert!(matches!(
            judge.weigh(&forged, judged(NOW), None),
            Err(Refused::Unreadable(_))
        ));
        let future = EvidenceBundle::sign(
            &relay,
            &EvidenceBundleContent {
                issued_ms: NOW
                    + 2 * tally_wire::budget::RECEIPT_AHEAD
                        .span::<tally_wire::clocks::Judged>()
                        .ms(),
                feeders: vec![],
                receipts: vec![],
                answers: vec![],
            },
        )
        .map_err(text)?;
        assert_eq!(
            judge.weigh(&future, judged(NOW), None),
            Err(Refused::Future)
        );
        Ok(())
    }

    #[test]
    fn a_relay_with_no_feeders_earns_nothing_from_its_own_answers() -> Result {
        let relay = identity()?;
        let judge = Credit::new();
        // Every answer genuinely signed and "proved", about receivers the judge corroborated:
        // still the relay's own word, so nothing.
        let receivers: Vec<Identity> = (0..8).map(|_| identity()).collect::<Result<_>>()?;
        let answers = receivers
            .iter()
            .map(|receiver| {
                judge.corroborate_receiver(receiver.public(), crate::sharing::Now::from(NOW));
                answer(&relay, receiver.public(), NOW)
            })
            .collect::<Result<Vec<_>>>()?;
        judge
            .weigh(&bundle(&relay, vec![], vec![], answers)?, judged(NOW), None)
            .map_err(text)?;
        assert_eq!(judge.earned(&relay.public(), judged(NOW)), 0);
        // And its own bundle never carries one.
        let own = Credit::new();
        let bundled = own.bundle(&relay, judged(NOW)).map_err(text)?;
        assert!(bundled.referenced().map_err(text)?.answers.is_empty());
        Ok(())
    }

    #[test]
    fn a_zero_span_receipt_counts_its_one_second() -> Result {
        let (relay, child) = (identity()?, identity()?);
        let judge = Credit::new();
        judge.corroborate_relay(child.public(), crate::sharing::Now::from(NOW));
        let instant = StripeReceipt::sign(
            &child,
            &StripeReceiptContent {
                parent: relay.public(),
                cell: area(-1_180_000_000)?,
                product: Streams::RAW,
                stripe: 0,
                stripes_of: 1,
                first_second: 100,
                last_second: 100,
                records: 10,
                bytes: 5_000,
                digest: [7; 32],
                issued_ms: NOW,
            },
        )
        .map_err(text)?;
        judge
            .weigh(
                &bundle(&relay, vec![], vec![instant], vec![])?,
                judged(NOW),
                None,
            )
            .map_err(text)?;
        assert_eq!(judge.earned(&relay.public(), judged(NOW)), 5_000);
        Ok(())
    }

    #[test]
    fn a_client_with_no_credential_gets_the_free_tier() -> Result {
        let judge = rationing();
        let client = identity()?;
        let session = asker(AskerRole::Client, client.public(), 1);
        let cells = areas(2)?;
        assert_eq!(
            judge.allowance(&client.public(), judged(NOW)),
            Allowance::FREE
        );
        // Raw and the world are not free: only positions, for one area.
        let everything = Streams(0x7f);
        assert_eq!(
            judge.admit(&session, sub(everything, cells.clone()), judged(NOW)),
            sub(
                Streams::POSITIONS.with(Streams::PROVISIONAL),
                vec![cells[0]]
            )
        );
        assert_eq!(
            judge.admit(&session, sub(Streams::POSITIONS, Vec::new()), judged(NOW)),
            nothing()
        );
        assert_eq!(
            judge.admit(&session, sub(Streams::RAW, vec![cells[0]]), judged(NOW)),
            nothing()
        );
        // A region coarser than an area is refused, and refusing every region never widens to
        // the world.
        let coarse = {
            let location = Location {
                lat_e7: 340_000_000,
                lon_e7: -1_180_000_000,
                alt_m: 0,
                precision_m: 0,
            };
            Region::containing(&location, 1).map_err(text)?
        };
        assert_eq!(
            judge.admit(&session, sub(Streams::POSITIONS, vec![coarse]), judged(NOW)),
            nothing()
        );
        Ok(())
    }

    #[test]
    fn the_free_tier_together_is_a_share_of_the_cap() -> Result {
        let judge = Credit::new();
        // Room for three free clients.
        judge.set_upload_cap(
            Allowance::FREE.bytes_per_sec * 3 * FREE_SHARE_OF_CAP.1 / FREE_SHARE_OF_CAP.0,
        );
        let cell = areas(1)?;
        let ask = || sub(Streams::POSITIONS, cell.clone());
        let mut served = Vec::new();
        for source in 0..4 {
            let session = asker(AskerRole::Client, identity()?.public(), source);
            served.push(judge.admit(&session, ask(), judged(NOW)));
        }
        assert_eq!(served[..3], [ask(), ask(), ask()]);
        assert_eq!(served[3], nothing());
        // A client already served keeps its place on a new Subscribe; one leaving makes room.
        let again = asker(AskerRole::Client, identity()?.public(), 0);
        assert_eq!(judge.admit(&again, ask(), judged(NOW)), ask());
        judge.left(1);
        let fourth = asker(AskerRole::Client, identity()?.public(), 3);
        assert_eq!(judge.admit(&fourth, ask(), judged(NOW)), ask());
        Ok(())
    }

    #[test]
    fn a_relay_with_evidence_lifts_its_clients() -> Result {
        let (relay, client) = (identity()?, identity()?);
        let judge = rationing();
        judge
            .weigh(
                &bundle(&relay, hosted(&judge, &relay, 24)?, vec![], vec![])?,
                judged(NOW),
                None,
            )
            .map_err(text)?;
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW)),
            24 * FEEDER_CREDIT
        );
        let session = asker(AskerRole::Client, client.public(), 1);
        let positions = Streams::POSITIONS.with(Streams::PROVISIONAL);
        let three = areas(3)?;
        // Free, one area; linked, all three.
        assert_eq!(
            judge.admit(&session, sub(positions, three.clone()), judged(NOW)),
            sub(positions, vec![three[0]])
        );
        let credential = Credit::new()
            .issue(
                &relay,
                client.public(),
                positions.with(Streams::RAW),
                judged(NOW),
            )
            .map_err(text)?;
        judge.presented(&session, credential, judged(NOW));
        assert_eq!(
            judge.admit(&session, sub(positions, three.clone()), judged(NOW)),
            sub(positions, three.clone())
        );
        // Still in proportion: an area's raw costs more than 24 feeders earn.
        assert_eq!(
            judge.admit(
                &session,
                sub(positions.with(Streams::RAW), three.clone()),
                judged(NOW)
            ),
            sub(positions, three)
        );
        // A relay with no evidence earns its clients nothing.
        let (idle, other) = (identity()?, identity()?);
        let idle_session = asker(AskerRole::Client, other.public(), 2);
        let idle_credential = Credit::new()
            .issue(&idle, other.public(), positions, judged(NOW))
            .map_err(text)?;
        judge.presented(&idle_session, idle_credential, judged(NOW));
        assert_eq!(
            judge.allowance(&other.public(), judged(NOW)),
            Allowance::FREE
        );
        Ok(())
    }

    #[test]
    fn only_a_client_is_granted_anything_here() -> Result {
        let judge = rationing();
        let asked = sub(Streams::RAW.with(Streams::CLOCK_MODELS), Vec::new());
        for (source, role) in [
            AskerRole::Relay,
            AskerRole::Engine,
            AskerRole::Feeder,
            AskerRole::Probe,
        ]
        .into_iter()
        .enumerate()
        {
            let peer = asker(role, identity()?.public(), source as u64);
            assert_eq!(
                judge.admit(&peer, asked.clone(), judged(NOW)),
                nothing(),
                "{role:?}"
            );
            let mut loopback = peer;
            loopback.loopback = true;
            assert_eq!(
                judge.admit(&loopback, asked.clone(), judged(NOW)),
                nothing()
            );
        }
        // A relay told no cap sends nothing billed, and serves its clients as they ask.
        let uncapped = Credit::new();
        let client = asker(AskerRole::Client, identity()?.public(), 9);
        assert_eq!(uncapped.admit(&client, asked.clone(), judged(NOW)), asked);
        uncapped.set_upload_cap(0);
        assert_eq!(uncapped.admit(&client, asked.clone(), judged(NOW)), asked);
        Ok(())
    }

    #[test]
    fn a_relay_vouches_only_for_its_operators_clients() -> Result {
        let (relay, client, stranger, feeder) =
            (identity()?, identity()?, identity()?, identity()?);
        let own = rationing();
        own.adopt_identity(relay.public());
        own.vouch_for([client.public()]);
        own.described(
            info(&feeder, relay.public(), NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        let session = asker(AskerRole::Client, client.public(), 1);
        let (credential, evidence) = own
            .vouch(&relay, &session, judged(NOW))
            .ok_or("not vouched")?;
        let content = credential.content().map_err(text)?;
        assert_eq!(
            (content.client, credential.signer().map_err(text)?),
            (client.public(), relay.public())
        );
        assert_eq!(evidence.referenced().map_err(text)?.feeders.len(), 1);
        // Served here as the credential says: anything, anywhere.
        assert_eq!(
            own.admit(&session, sub(Streams::RAW, Vec::new()), judged(NOW)),
            sub(Streams::RAW, Vec::new())
        );
        // A stranger, or the client's key on a relay's session, is vouched for by nobody.
        assert!(
            own.vouch(
                &relay,
                &asker(AskerRole::Client, stranger.public(), 2),
                judged(NOW)
            )
            .is_none()
        );
        assert!(
            own.vouch(
                &relay,
                &asker(AskerRole::Relay, client.public(), 3),
                judged(NOW)
            )
            .is_none()
        );
        Ok(())
    }

    #[test]
    fn a_relays_own_clients_are_served_as_their_credential_says() -> Result {
        let (relay, client) = (identity()?, identity()?);
        let judge = rationing();
        let credential = judge
            .issue(
                &relay,
                client.public(),
                Streams::RAW.with(Streams::POSITIONS),
                judged(NOW),
            )
            .map_err(text)?;
        let session = asker(AskerRole::Client, client.public(), 1);
        judge.presented(&session, credential, judged(NOW));
        assert_eq!(
            judge.admit(&session, sub(Streams(0x7f), Vec::new()), judged(NOW)),
            sub(Streams::RAW.with(Streams::POSITIONS), Vec::new())
        );
        Ok(())
    }

    /// Every signature `check` verifies inside a bundle is a token of the pace its
    /// asker's records were taken by, owed and paid before that connection's next record: a bundle
    /// of 6 descriptions and 4 receipts on a pace of one a second holds the next record 11 s (its
    /// ten signatures, then its own token).
    /// Before, a bundle was one token whatever it held, its up to 128 signatures unplanned.
    #[tokio::test(start_paused = true)]
    async fn each_signature_inside_a_bundle_is_a_token_of_its_askers_pace() -> Result {
        let relay = identity()?;
        let feeders = (0..6)
            .map(|_| info(&identity()?, relay.public(), NOW))
            .collect::<Result<Vec<_>>>()?;
        let receipts = (0..4)
            .map(|_| receipt(&identity()?, relay.public(), 1_000, NOW))
            .collect::<Result<Vec<_>>>()?;
        let evidence = bundle(&relay, feeders, receipts, vec![])?;
        let pace = RecordPace::with_burst(1, 1);
        // The record itself, taken as the read loop takes it.
        pace.take().await;
        let started = tokio::time::Instant::now();
        check(&evidence, judged(NOW), Some(&pace)).map_err(|refused| format!("{refused:?}"))?;
        pace.take().await;
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_secs(11) && waited < Duration::from_secs(12),
            "the next record waited {waited:?}"
        );
        // A bundle no session brought owes nothing.
        let started = tokio::time::Instant::now();
        check(&evidence, judged(NOW), None).map_err(|refused| format!("{refused:?}"))?;
        pace.take().await;
        assert!(started.elapsed() <= Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn fake_feeder_keys_naming_a_relay_earn_nothing_without_corroboration() -> Result {
        let relay = identity()?;
        let judge = Credit::new();
        let fakes: Vec<Identity> = (0..tally_wire::credit::MAX_EVIDENCE)
            .map(|_| identity())
            .collect::<Result<_>>()?;
        let feeders = fakes
            .iter()
            .map(|fake| info(fake, relay.public(), NOW))
            .collect::<Result<Vec<_>>>()?;
        // Every record is genuinely signed, so the bundle is accepted, and earns nothing.
        judge
            .weigh(&bundle(&relay, feeders, vec![], vec![])?, judged(NOW), None)
            .map_err(text)?;
        assert_eq!(judge.earned(&relay.public(), judged(NOW)), 0);
        // Two of them turn out real: those two count.
        judge.corroborate_receiver(fakes[0].public(), crate::sharing::Now::from(NOW));
        judge.corroborate_receiver(fakes[1].public(), crate::sharing::Now::from(NOW));
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW)),
            2 * FEEDER_CREDIT
        );
        // Corroboration lapses.
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW + CORROBORATION_LIFETIME_MS + 1)),
            0
        );
        Ok(())
    }

    #[test]
    fn one_relay_vouching_for_a_hundred_clients_divides_its_credit() -> Result {
        let relay = identity()?;
        let judge = rationing();
        judge
            .weigh(
                &bundle(&relay, hosted(&judge, &relay, 50)?, vec![], vec![])?,
                judged(NOW),
                None,
            )
            .map_err(text)?;
        let earned = judge.earned(&relay.public(), judged(NOW));
        assert_eq!(earned, 50 * FEEDER_CREDIT);
        let issuer = Credit::new();
        let mut clients = Vec::new();
        for source in 0..100 {
            let client = identity()?;
            let credential = issuer
                .issue(&relay, client.public(), Streams::POSITIONS, judged(NOW))
                .map_err(text)?;
            judge.presented(
                &asker(AskerRole::Client, client.public(), source),
                credential,
                judged(NOW),
            );
            clients.push(client.public());
            let each = judge.allowance(&clients[0], judged(NOW));
            let share = earned / (source + 1);
            if share > Allowance::FREE.bytes_per_sec {
                assert_eq!(each.bytes_per_sec, share);
            } else {
                assert_eq!(each, Allowance::FREE);
            }
        }
        // A hundred ways, each below the free tier: no client is better off for the link.
        for client in &clients {
            assert_eq!(judge.allowance(client, judged(NOW)), Allowance::FREE);
        }
        // One credential shared by two sessions halves it too.
        let lone_relay = identity()?;
        judge
            .weigh(
                &bundle(
                    &lone_relay,
                    hosted(&judge, &lone_relay, 20)?,
                    vec![],
                    vec![],
                )?,
                judged(NOW),
                None,
            )
            .map_err(text)?;
        let shared = identity()?;
        let credential = issuer
            .issue(
                &lone_relay,
                shared.public(),
                Streams::POSITIONS,
                judged(NOW),
            )
            .map_err(text)?;
        judge.presented(
            &asker(AskerRole::Client, shared.public(), 200),
            credential.clone(),
            judged(NOW),
        );
        assert_eq!(
            judge.allowance(&shared.public(), judged(NOW)).bytes_per_sec,
            20 * FEEDER_CREDIT
        );
        judge.presented(
            &asker(AskerRole::Client, shared.public(), 201),
            credential,
            judged(NOW),
        );
        assert_eq!(
            judge.allowance(&shared.public(), judged(NOW)).bytes_per_sec,
            10 * FEEDER_CREDIT
        );
        judge.left(201);
        assert_eq!(
            judge.allowance(&shared.public(), judged(NOW)).bytes_per_sec,
            20 * FEEDER_CREDIT
        );
        Ok(())
    }

    #[test]
    fn a_relay_that_uploads_only_to_colluders_gains_nothing_elsewhere() -> Result {
        let relay = identity()?;
        let colluders: Vec<Identity> = (0..8).map(|_| identity()).collect::<Result<_>>()?;
        let receipts = colluders
            .iter()
            .map(|child| receipt(child, relay.public(), 100_000, NOW))
            .collect::<Result<Vec<_>>>()?;
        let shown = bundle(&relay, vec![], receipts.clone(), vec![])?;
        // An honest relay that never dealt with the colluders: nothing.
        let honest = Credit::new();
        honest.weigh(&shown, judged(NOW), None).map_err(text)?;
        assert_eq!(honest.earned(&relay.public(), judged(NOW)), 0);
        // The colluders vouching for each other the same way earn nothing either.
        for (index, colluder) in colluders.iter().enumerate() {
            let next = &colluders[(index + 1) % colluders.len()];
            let mutual = bundle(
                colluder,
                vec![],
                vec![receipt(next, colluder.public(), 100_000, NOW)?],
                vec![],
            )?;
            honest.weigh(&mutual, judged(NOW), None).map_err(text)?;
            assert_eq!(honest.earned(&colluder.public(), judged(NOW)), 0);
        }
        // A real child this relay knows counts, once, however many receipts it signs, and no
        // more than an area's raw a second.
        let known = identity()?;
        honest.corroborate_relay(known.public(), crate::sharing::Now::from(NOW));
        let mut with_known = receipts;
        with_known.push(receipt(&known, relay.public(), 1_000, NOW)?);
        with_known.push(receipt(&known, relay.public(), 2_000, NOW)?);
        let later = EvidenceBundle::sign(
            &relay,
            &EvidenceBundleContent {
                issued_ms: NOW + 1,
                feeders: vec![],
                receipts: with_known,
                answers: vec![],
            },
        )
        .map_err(text)?;
        honest.weigh(&later, judged(NOW + 1), None).map_err(text)?;
        assert_eq!(
            honest.earned(&relay.public(), judged(NOW + 1)),
            decayed(2_000, NOW, judged(NOW + 1))
        );
        let flood = bundle(
            &known,
            vec![],
            vec![receipt(&relay, known.public(), u64::MAX / 120, NOW)?],
            vec![],
        )?;
        honest.corroborate_relay(relay.public(), crate::sharing::Now::from(NOW));
        honest.weigh(&flood, judged(NOW), None).map_err(text)?;
        assert_eq!(
            honest.earned(&known.public(), judged(NOW)),
            AREA_FEEDERS * FEEDER_BYTES_PER_SEC
        );
        Ok(())
    }

    #[test]
    fn credit_decays_with_the_age_of_its_evidence() -> Result {
        let aged = |age_ms: u64| decayed(1_000, NOW, judged(NOW + age_ms));
        let past = |at: u64| {
            tally_wire::budget::EVIDENCE_AGE
                .after(judged(at))
                .later(tally_wire::budget::policy::<_, 1>())
        };
        assert_eq!(aged(0), 1_000);
        assert_eq!(aged(HALF_LIFE_MS / 2), 750);
        assert_eq!(aged(HALF_LIFE_MS), 500);
        assert_eq!(aged(2 * HALF_LIFE_MS), 250);
        assert_eq!(decayed(1_000, NOW, past(NOW)), 0);
        let relay = identity()?;
        let judge = Credit::new();
        judge
            .weigh(
                &bundle(&relay, hosted(&judge, &relay, 4)?, vec![], vec![])?,
                judged(NOW),
                None,
            )
            .map_err(text)?;
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW)),
            4 * FEEDER_CREDIT
        );
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW + HALF_LIFE_MS)),
            2 * FEEDER_CREDIT
        );
        assert!(
            judge
                .weigh(&bundle(&relay, vec![], vec![], vec![])?, past(NOW), None)
                .is_err()
        );
        // An older bundle never replaces a newer one.
        let stale = EvidenceBundle::sign(
            &relay,
            &EvidenceBundleContent {
                issued_ms: NOW - 1,
                feeders: vec![],
                receipts: vec![],
                answers: vec![],
            },
        )
        .map_err(text)?;
        judge.weigh(&stale, judged(NOW), None).map_err(text)?;
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW)),
            4 * FEEDER_CREDIT
        );
        Ok(())
    }

    #[test]
    fn a_relays_own_evidence_bundles_and_is_scored_elsewhere() -> Result {
        let (relay, child, feeder) = (identity()?, identity()?, identity()?);
        let own = Credit::new();
        // Receipts are kept only for this relay's own keys, adopted when it serves.
        own.adopt_identity(relay.public());
        own.described(
            info(&feeder, relay.public(), NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        // A description naming someone else, and a receipt for another parent, stay out.
        own.described(
            info(&identity()?, identity()?.public(), NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        own.record_receipt(
            receipt(&child, relay.public(), 4_000, NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        own.record_receipt(
            receipt(&child, identity()?.public(), 4_000, NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        let bundled = own.bundle(&relay, judged(NOW)).map_err(text)?;
        // By reference: no description, so no site, rides in it.
        assert!(!bundled.carries_site());
        let content = bundled.referenced().map_err(text)?;
        assert_eq!(
            (
                content.feeders.len(),
                content.receipts.len(),
                content.answers.len()
            ),
            (1, 1, 0)
        );
        let judge = Credit::new();
        judge.corroborate_receiver(feeder.public(), crate::sharing::Now::from(NOW));
        judge.corroborate_relay(child.public(), crate::sharing::Now::from(NOW));
        judge.weigh(&bundled, judged(NOW), None).map_err(text)?;
        // A judge holding no copy of the description cannot resolve the reference: the feeder
        // counts nothing on the relay's word alone.
        assert_eq!(judge.earned(&relay.public(), judged(NOW)), 4_000);
        // Holding the same description, it resolves.
        judge.described(
            info(&feeder, relay.public(), NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        assert_eq!(
            judge.earned(&relay.public(), judged(NOW)),
            FEEDER_CREDIT + 4_000
        );
        // A full evidence store still bundles into one record, and alike every time.
        for _ in 0..200 {
            own.described(
                info(&identity()?, relay.public(), NOW)?,
                crate::strikes::Now::judging(NOW),
            );
        }
        let full = own.bundle(&relay, judged(NOW)).map_err(text)?;
        full.verify().map_err(text)?;
        let content = full.referenced().map_err(text)?;
        assert!(content.feeders.len() <= tally_wire::credit::MAX_EVIDENCE);
        assert!(!content.feeders.is_empty());
        assert_eq!(
            own.bundle(&relay, judged(NOW))
                .map_err(text)?
                .referenced()
                .map_err(text)?,
            content
        );
        Ok(())
    }

    #[test]
    fn evidence_dated_ahead_of_the_clock_is_never_stored() -> Result {
        let (relay, child, feeder, early) = (identity()?, identity()?, identity()?, identity()?);
        let own = Credit::new();
        own.adopt_identity(relay.public());
        own.described(
            info(&feeder, relay.public(), NOW)?,
            crate::strikes::Now::judging(NOW),
        );
        // Dated past the skew: refused, so it can never stand as the newest description.
        own.described(
            info(
                &feeder,
                relay.public(),
                NOW + 2 * tally_wire::budget::RECEIPT_AHEAD
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            )?,
            crate::strikes::Now::judging(NOW),
        );
        own.described(
            info(
                &early,
                relay.public(),
                NOW + 2 * tally_wire::budget::RECEIPT_AHEAD
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            )?,
            crate::strikes::Now::judging(NOW),
        );
        own.record_receipt(
            receipt(
                &child,
                relay.public(),
                4_000,
                NOW + 2 * tally_wire::budget::RECEIPT_AHEAD
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            )?,
            crate::strikes::Now::judging(NOW),
        );
        let content = own
            .bundle(&relay, judged(NOW))
            .map_err(text)?
            .referenced()
            .map_err(text)?;
        assert_eq!((content.feeders.len(), content.receipts.len()), (1, 0));
        assert_eq!(content.feeders[0].issued_ms, NOW);
        // Within the skew is a clock's ordinary disagreement, and is kept.
        own.described(
            info(
                &early,
                relay.public(),
                NOW + tally_wire::budget::RECEIPT_AHEAD
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            )?,
            crate::strikes::Now::judging(NOW),
        );
        let content = own
            .bundle(&relay, judged(NOW))
            .map_err(text)?
            .referenced()
            .map_err(text)?;
        assert_eq!(content.feeders.len(), 2);
        Ok(())
    }

    /// A reference resolves against the judge's own copy: the very description named, or a newer
    /// one still naming the relay; never one that names another relay, nor a hash the judge does
    /// not hold.
    #[test]
    fn a_reference_counts_only_where_the_judges_copy_resolves_it() -> Result {
        let (relay, feeder) = (identity()?, identity()?);
        let own = Credit::new();
        own.adopt_identity(relay.public());
        own.described(
            info(&feeder, relay.public(), NOW - 10)?,
            crate::strikes::Now::judging(NOW),
        );
        let bundled = own.bundle(&relay, judged(NOW)).map_err(text)?;
        let judge_of = |copy: Option<ReceiverInfo>| -> Result<u64> {
            let judge = Credit::new();
            judge.corroborate_receiver(feeder.public(), crate::sharing::Now::from(NOW));
            if let Some(copy) = copy {
                judge.described(copy, crate::strikes::Now::judging(NOW));
            }
            judge.weigh(&bundled, judged(NOW), None).map_err(text)?;
            Ok(judge.earned(&relay.public(), judged(NOW)))
        };
        assert_eq!(judge_of(None)?, 0);
        assert_eq!(
            judge_of(Some(info(&feeder, relay.public(), NOW - 10)?))?,
            FEEDER_CREDIT
        );
        // Re-signed since, still naming the relay: it still chose it.
        assert!(judge_of(Some(info(&feeder, relay.public(), NOW - 5)?))? > 0);
        // Re-signed naming another relay: the reference is stale, and counts nothing.
        assert_eq!(
            judge_of(Some(info(&feeder, identity()?.public(), NOW - 5)?))?,
            0
        );
        // An older copy than the one named, with another hash: unresolved.
        assert_eq!(judge_of(Some(info(&feeder, relay.public(), NOW - 20)?))?, 0);
        Ok(())
    }

    /// An old relay's bundle, carrying its feeders' format 1 descriptions whole, still counts
    /// as it did, with no copy needed.
    #[test]
    fn a_carried_bundle_of_an_old_relay_still_counts() -> Result {
        let (relay, feeder) = (identity()?, identity()?);
        let carried = bundle(
            &relay,
            vec![info(&feeder, relay.public(), NOW)?],
            vec![],
            vec![],
        )?;
        assert!(carried.carries_site());
        let judge = Credit::new();
        judge.corroborate_receiver(feeder.public(), crate::sharing::Now::from(NOW));
        judge.weigh(&carried, judged(NOW), None).map_err(text)?;
        assert_eq!(judge.earned(&relay.public(), judged(NOW)), FEEDER_CREDIT);
        Ok(())
    }

    #[test]
    fn cost_follows_the_areas_named() -> Result {
        let cell = areas(1)?;
        assert_eq!(cost(Streams::POSITIONS, &cell), AREA_AIRCRAFT * FIX_BYTES);
        assert_eq!(cost(Streams::POSITIONS, &[]), WORLD_AIRCRAFT * FIX_BYTES);
        assert_eq!(
            cost(Streams::POSITIONS.with(Streams::PROVISIONAL), &cell),
            Allowance::FREE.bytes_per_sec
        );
        // Each world feed is its own product, costed as one, whatever the areas named.
        let world = WORLD_PRODUCT_AIRCRAFT * WORLD_FIX_BYTES;
        assert_eq!(cost(Streams::WORLD, &cell), world);
        assert_eq!(cost(Streams::WORLD_PRECISE, &[]), world);
        assert_eq!(
            cost(Streams::WORLD.with(Streams::WORLD_PRECISE), &cell),
            2 * world
        );
        Ok(())
    }
}
