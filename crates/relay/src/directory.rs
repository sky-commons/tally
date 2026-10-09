//! The provider directory (RFC-0174 §2.6): the `ProviderOffer`s this relay holds, each checked
//! (its signature, its lifetime, and by a handshake with its address that the key answers there)
//! before it is held or gossiped, capped per key and per cell, forgotten when it expires; the
//! relay's own offers, re-signed while it serves; and the answer to a `ProviderQuery` (the offers
//! for a cell and its ancestors). The MLAT relays of an area are chosen from what this holds
//! (`selection`), so what it holds is hardened against being filled by one party (§4.1):
//!
//! - **Verified before held or gossiped.** An offer is held only once this relay has dialled its
//!   address and the Noise handshake there proved the offer's key (Noise IK to that key, which
//!   only its holder completes). Dials are bounded: a few at once, a bounded queue, a bounded
//!   share of it per asker, one dial per address at a time, and an address that did not answer is
//!   not dialled again for `UNANSWERED_FOR_MS`, so offers naming a stranger's address cannot turn
//!   relays into a flood against it. A key verified at an address is trusted there for
//!   `VERIFIED_FOR_MS`, so its re-signed offers are held without a new dial.
//! - **Buckets by network group.** An offer names the address it answers at by number (an IP and
//!   port, never a host name), and that address, which every peer dials, puts it in a group (an
//!   IPv4 /16, an IPv6 /32: `Group::of_address`). The group is read from the signed offer alone,
//!   so every relay, the signer included, puts one offer in one group: no relay's resolver has a
//!   say, as one could if each resolved a host name its own way. An offer naming a host name is
//!   not taken. A cell holds at most `OFFERS_PER_GROUP_IN_CELL` of one group and
//!   `OFFERS_PER_CELL` in all, so a flood of keys from a few networks displaces only itself. The
//!   relay's own offers are no exception: they are held under the group of the address they name,
//!   as every peer that verified them there holds them (`State::hold_own`; an advertised host name
//!   is resolved once and the offers name the address it resolved to), and compete under every cap
//!   as a peer's would, so this relay holds the same offers its peers do and lays out the same
//!   trees and MLAT choice. Past those, a group holds at most `OFFERS_PER_GROUP`
//!   anywhere, a key at most `OFFERS_PER_KEY`, and the directory `OFFERS_HELD`: bounds on a flood,
//!   which an honest network never reaches.
//! - **Held by rank, never by arrival.** Every cap (a group's share of a cell, the cell, a group
//!   anywhere, a key, the directory) is kept by rank, never by which came first: a newcomer to a
//!   full cap displaces the lowest-ranked offer under it only when it outranks it, and is refused
//!   otherwise (`State::hold`). Within a cell the rank is the cell's ranking (`ranked`: tier, then
//!   the wire's rendezvous ranking over (cell, key), `rendezvous::rank`). Across cells it is
//!   `Standing`: the tier, then how deep the offer sits in its own cell's ranking, so the offer
//!   given up is the one least likely to be chosen anywhere, and two offers in one cell stand as
//!   their cell ranks them. So the held set is a function of the offers verified, the same set on
//!   every relay that verified the same offers, and the sharing trees laid out over it
//!   (`sharing`) are the same trees everywhere. What it cannot be is a reward for tenure: a party
//!   that grinds keys to rank high for a cell, from more networks than a cell's group cap allows
//!   each, is held there, and it is the sharing duty (receipts and demotion) that drops it once
//!   held.
//! - **A change costs its readers once per `CHANGED_AT_MOST_EVERY_MS`.** A held offer re-signed
//!   saying something new takes effect at most that often per (key, cell): one sooner waits, the
//!   newest kept, until its turn (`State::apply_deferred`). So a peer re-signing changed offers
//!   in a loop costs the readers (the sharing trees, the MLAT choice) what an honest relay's
//!   changes cost, however fast it signs.
//! - **A re-signing that changes nothing is taken at most once per `RESIGNED_AT_MOST_EVERY_MS`**
//!   per (key, cell), by the signed `issued_ms` (an honest relay re-signs a minute apart, ten
//!   seconds at the least): one sooner is neither held nor gossiped. One taken replaces the held
//!   offer in place (`State::renew`), so it moves no group, network or tier and costs no reader a
//!   re-weigh.
//! - **Checked once.** An offer's signature is verified and its content decoded when it arrives,
//!   and what is held is that check (`Checked`): every reader gets it, so none verifies or decodes
//!   a held offer again.
//! - **No reflection.** Every offer is acted on once, by its hash: one that comes back round a
//!   gossip loop is neither dialled nor gossiped again; the relay's own offers coming back are
//!   ignored; and an offer is gossiped once, when it is first verified.
//! - **Expiry by the reader's clock.** An offer already expired, or issued in the future past the
//!   allowed skew, is not taken, and one that expires while held is forgotten.
//! - **Readers follow changes, never scan.** What the held offers answer changes only when an
//!   offer comes, goes or says something new, or the tiers move: [`Directory::version`] names that
//!   state, and [`Directory::take_changed_cells`] the cells whose answer changed since the last
//!   look. A re-signing that says what the held offer said changes neither, so a relay that holds
//!   offers for every area of the world costs its readers nothing while nothing changes (the MLAT
//!   choice in `selection`, the sharing trees in `sharing`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tally_wire::rendezvous::{self, Weighted};
use tally_wire::{
    EvidenceBundle, Identity, ProviderOffer, ProviderOfferContent, ProviderQuery, PublicKey,
    Record, Region, Streams, WireError, noise,
};
use tokio::net::TcpStream;

use crate::bounded::Bounded;
use crate::credit::{self, Corroboration, Shown, Unit};
use crate::hub::Hub;
use crate::network::{Asker, AskerRole};
use crate::sharing::locks::lock;

/// Offers held per signing key, at most: as many as one network group may hold
/// (`OFFERS_PER_GROUP`), so a key is bounded as its network is. A relay's own offers are the
/// regions it takes at their fewest (`Bundles::offered`), all of them, and a relay whose regions
/// need more than this refuses to start (`offerable`), so no relay's offers are cut by its peers'
/// bound: the whole world at its coarsest (`BASE_CELLS`) always fits.
pub const OFFERS_PER_KEY: usize = OFFERS_PER_GROUP;
const _: () = assert!(OFFERS_PER_KEY >= tally_wire::region::BASE_CELLS);

/// Whether a relay taking `regions` can offer all of them: its offers are at most the regions at
/// their fewest (`Bundles::offered`), and every peer holds at most `OFFERS_PER_KEY` of one key.
/// The error says how many cells they are, for a relay to refuse to start on.
pub fn offerable(regions: &[Region]) -> Result<(), String> {
    let cells = tally_wire::Regions::new(regions.iter().copied()).len();
    if cells > OFFERS_PER_KEY {
        return Err(format!(
            "the areas taken are {cells} cells at their fewest, and a relay's peers hold at most \
             {OFFERS_PER_KEY} offers of one key: name them by coarser cells"
        ));
    }
    Ok(())
}
/// Offers held per cell, at most.
pub const OFFERS_PER_CELL: usize = 32;
/// Offers held per cell from one network group, at most.
pub const OFFERS_PER_GROUP_IN_CELL: usize = 4;
/// Offers held from one network group, over every cell, at most.
pub const OFFERS_PER_GROUP: usize = 256;
/// Offers held in all, at most.
pub const OFFERS_HELD: usize = 16_384;
/// How far in the future an offer may say it was issued, for clocks that differ.
pub const CLOCK_SKEW_MS: u64 = 60 * 1000;
/// Offers waiting for their handshake, at most, and at most per asker.
pub const PENDING: usize = 256;
pub const PENDING_PER_ASKER: usize = 16;
/// Handshakes in flight at once, at most.
pub const VERIFYING_AT_ONCE: usize = 8;
/// How long a key that answered at an address is trusted there without another dial.
pub const VERIFIED_FOR_MS: u64 = 30 * 60 * 1000;
/// How long an address that did not answer as its key is not dialled again.
pub const UNANSWERED_FOR_MS: u64 = 10 * 60 * 1000;
/// Addresses remembered as verified or as not answering, each, at most.
pub const ADDRESSES_REMEMBERED: usize = 4096;
/// Offer hashes remembered as acted on, at most.
pub const SEEN_REMEMBERED: usize = 65_536;
/// How often a relay bundles its own evidence for the directory (`State::tier`): a tenth of the
/// evidence's half-life (`credit::HALF_LIFE_MS`), so its tier, a factor of two wide, follows what it
/// does within minutes and the bundles cost the directory links little.
pub const OWN_EVIDENCE_EVERY_MS: u64 = credit::HALF_LIFE_MS / 10;
/// Relays' evidence held, at most: one a key, as many as offers may be held.
pub const EVIDENCE_HELD: usize = OFFERS_HELD;
/// How often a relay re-signs its own offers while it serves: once a minute.
pub const OWN_RESIGN_EVERY_MS: u64 = 60 * 1000;
/// How long an offer lives, by the signed times in it: three re-signings. A relay that dies is
/// therefore out of every relay's directory, and so of every area's MLAT ranking and every
/// sharing tree, within three minutes of its last re-signing, by its own signature and not by
/// when anyone heard it, alike on every relay. The figure is the directory's own timing:
///
/// - one re-signing (60 s), the wait for the next offer;
/// - the clock skew a reader allows (`CLOCK_SKEW_MS`, 60 s): to a reader whose clock is a minute
///   ahead, every offer is a minute older than its signer meant;
/// - and a re-signing again (60 s) for the offer to spread: a re-signed offer from a key already
///   verified at its address is held at once and gossiped at the next tick (`network::TICK`,
///   100 ms) on every directory link, so a hop costs a tick and a round trip, and tens of hops
///   seconds; the first offer from a new address waits for one handshake (`CONNECT_TIMEOUT` and
///   the handshake's own deadline, 10 s each), and a re-signed one also survives one lost copy.
///
/// An offer saying it lives longer is held only this long (`expiry`), so no relay keeps a dead
/// one past it, whatever its signer claimed.
pub const OFFER_LIFETIME_MS: u64 = 3 * OWN_RESIGN_EVERY_MS;
/// The soonest the relay re-signs its own offers again when what they declare changes.
pub const OWN_RESIGN_AT_MOST_EVERY_MS: u64 = 10 * 1000;
/// The soonest, by the offers' own signed `issued_ms`, a peer's held offer for one cell is
/// renewed by a re-signing that says the same: what an honest relay's re-signings are at the
/// closest (`OWN_RESIGN_AT_MOST_EVERY_MS`), so one is never refused, and a peer re-signing in a
/// loop is taken (and gossiped) no oftener, however fast it signs.
pub const RESIGNED_AT_MOST_EVERY_MS: u64 = OWN_RESIGN_AT_MOST_EVERY_MS;
/// The soonest a peer's held offer for one cell takes a change again: what a relay's own changes
/// are held to (`OWN_RESIGN_AT_MOST_EVERY_MS`), so an honest relay's changes are never deferred
/// but by the clocks between them.
pub const CHANGED_AT_MOST_EVERY_MS: u64 = OWN_RESIGN_AT_MOST_EVERY_MS;
/// Offers in one answer to a query, at most: replies are written as control, 64 waiting a link.
pub const QUERY_ANSWER_MAX: usize = 32;
/// How long a dial may take to connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long after the relay's advertised host name failed to resolve it is tried again.
const RESOLVE_AGAIN_MS: u64 = 10 * 1000;
/// The products the relay offers for each region it takes: what it shares of them (§2.5, §2.11),
/// with its relay duties on. With them off it hosts no feeders, so it has no raw of its own to seed
/// or to pass an MLAT relay one hop, and its offers leave raw out (`own_products`).
const OWN_PRODUCTS: Streams = Streams(
    Streams::RAW.0
        | Streams::POSITIONS.0
        | Streams::CLOCK_MODELS.0
        | Streams::PROVISIONAL.0
        | Streams::REGIONAL.0,
);

/// What the relay's own offers declare it provides: `OWN_PRODUCTS`, less raw when its relay
/// duties are off. An offer of raw is what an MLAT relay dials for one-hop raw
/// (`selection::raw_sources`) and what puts it in an area's raw group, so a relay with no feeders
/// that offered it would be dialled for raw it does not have, and would pass on raw it had only
/// from its group, a second hop.
fn own_products(duties: bool) -> Streams {
    if duties {
        OWN_PRODUCTS
    } else {
        Streams(OWN_PRODUCTS.0 & !Streams::RAW.0)
    }
}

/// Where an offer answered from: the unit a flood is bucketed by. The relay's own offers are in
/// the group of the address they advertise, as its peers see them: there is no group of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    /// An IPv4 /16.
    V4(u16),
    /// An IPv6 /32.
    V6(u32),
}

impl Group {
    /// The group as one number, distinct per group: what a contribution counts witnesses by.
    pub fn as_u64(self) -> u64 {
        match self {
            Self::V4(prefix) => (1 << 32) | u64::from(prefix),
            Self::V6(prefix) => (2 << 32) | u64::from(prefix),
        }
    }

    /// The group of an offer naming `address` (its `HOST:PORT`): the group of the IP it names,
    /// which is the address every peer dials and its signer answers at. `None` for a host name,
    /// which each relay's resolver may answer differently: such an offer is in no group, and is
    /// not taken. The one place an offer's group is decided, for its signer and its peers alike.
    pub fn of_address(address: &str) -> Option<Self> {
        address
            .parse::<std::net::SocketAddr>()
            .ok()
            .map(|address| Self::of(address.ip()))
    }

    /// The group of an IP address. An IPv4 address mapped into IPv6 is its IPv4 address.
    pub fn of(address: IpAddr) -> Self {
        match address.to_canonical() {
            IpAddr::V4(v4) => {
                let [a, b, _, _] = v4.octets();
                Self::V4(u16::from_be_bytes([a, b]))
            }
            IpAddr::V6(v6) => {
                let [a, b, c, d, ..] = v6.octets();
                Self::V6(u32::from_be_bytes([a, b, c, d]))
            }
        }
    }
}

#[derive(Default)]
pub struct Directory {
    /// Shared with the handshakes in flight, which write their outcome back.
    state: Arc<Mutex<State>>,
}

struct State {
    own: Option<PublicKey>,
    /// What the own offers last declared, and when they were signed.
    own_basis: Option<Basis>,
    own_signed_ms: u64,
    /// Held offers by cell, then signer.
    cells: HashMap<u64, HashMap<PublicKey, Held>>,
    /// The cells each key's held offers are for, and the offers each group's are: what the per-key
    /// and per-group caps count and contest.
    per_key: HashMap<PublicKey, HashSet<u64>>,
    per_group: HashMap<Group, HashSet<(u64, PublicKey)>>,
    held: usize,
    /// Each cell's ranking of every offer held there (`ranked`), as last computed: dropped when the
    /// cell's offers change, and all of them when the tiers may move (`State::clear_tiers`).
    ranks: HashMap<u64, Vec<PublicKey>>,
    /// Changes deferred (`CHANGED_AT_MOST_EVERY_MS`), by when they are due: (due, cell, key). The
    /// change itself waits in its held offer (`Held::deferred`).
    deferred: BTreeSet<(u64, u64, PublicKey)>,
    pending: VecDeque<Pending>,
    /// Addresses being dialled now.
    dialling: HashSet<String>,
    verifying: usize,
    /// (key, address) that answered, and until when it is trusted there.
    verified: Bounded<(PublicKey, String), u64>,
    /// Addresses that did not answer, until when they are not dialled again.
    unanswered: Bounded<String, u64>,
    /// Offer hashes acted on.
    seen: Bounded<[u8; 32], ()>,
    /// Newly verified offers, gossiped once at the next tick.
    gossip: Vec<ProviderOffer>,
    /// What each relay holding an offer here showed of its contribution, from its newest
    /// evidence bundle (`credit::check`): what its offers are ranked by first.
    evidence: HashMap<PublicKey, (Shown, EvidenceBundle)>,
    /// New evidence held, gossiped once at the next tick.
    evidence_gossip: Vec<EvidenceBundle>,
    /// When the relay's own evidence was last bundled.
    own_evidence_ms: Option<u64>,
    /// The network group of the address the relay's own offers as last signed name
    /// (`Group::of_address`), as every peer that dials it finds it: what its own offers are held
    /// under. `None` while it signs none.
    own_group: Option<Group>,
    /// The relay's own offers as last signed (`resign`): held under `own_group` (`hold_own`).
    own_offers: Vec<Checked>,
    /// The advertised host name last resolved, the address it resolved to (what the relay's
    /// offers name), and until when that is taken without resolving again (`VERIFIED_FOR_MS`).
    own_resolved: Option<(String, std::net::SocketAddr, u64)>,
    /// The host name being resolved, and when it may be tried again: never while a resolution is
    /// under way, `RESOLVE_AGAIN_MS` after one failed.
    own_resolving: Option<(String, u64)>,
    /// The groups each key's held offers answered from, with how many offers each.
    key_groups: HashMap<PublicKey, BTreeMap<Group, usize>>,
    /// Each key's tier, weighed at `tiers_at`; cleared whenever what they are weighed from changes.
    tiers: HashMap<PublicKey, u32>,
    tiers_at: u64,
    /// Bumped whenever what the held offers answer may have changed: an offer held or let go, one
    /// that says something new, evidence that moves the tiers (`Directory::version`).
    version: u64,
    /// The cells whose answer changed since sharing last looked (`Directory::take_changed_cells`).
    changed: HashSet<u64>,
    /// The minute the tiers were last weighed for readers (`State::roll_tiers`), and the tiers
    /// above 0 then, sorted.
    rolled_at: u64,
    rolled: Vec<(PublicKey, u32)>,
    /// When held offers expire: each instant, with how many expire then. What makes expiry cost
    /// nothing until one is due.
    expiries: BTreeMap<u64, usize>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            own: None,
            own_basis: None,
            own_signed_ms: 0,
            cells: HashMap::new(),
            per_key: HashMap::new(),
            per_group: HashMap::new(),
            held: 0,
            ranks: HashMap::new(),
            deferred: BTreeSet::new(),
            pending: VecDeque::new(),
            dialling: HashSet::new(),
            verifying: 0,
            verified: Bounded::new(ADDRESSES_REMEMBERED),
            unanswered: Bounded::new(ADDRESSES_REMEMBERED),
            seen: Bounded::new(SEEN_REMEMBERED),
            gossip: Vec::new(),
            evidence: HashMap::new(),
            evidence_gossip: Vec::new(),
            own_evidence_ms: None,
            own_group: None,
            own_offers: Vec::new(),
            own_resolved: None,
            own_resolving: None,
            key_groups: HashMap::new(),
            tiers: HashMap::new(),
            tiers_at: 0,
            version: 0,
            changed: HashSet::new(),
            rolled_at: 0,
            rolled: Vec::new(),
            expiries: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
struct Held {
    offer: Checked,
    issued_ms: u64,
    expires_ms: u64,
    group: Group,
    /// When what it says last changed here (by this relay's clock): a change sooner than
    /// `CHANGED_AT_MOST_EVERY_MS` after waits.
    changed_ms: u64,
    /// The newest change of it that is waiting, with the group it answered from.
    deferred: Option<(Checked, Group)>,
}

impl Held {
    /// The newest signing held of it: its own, or the change waiting.
    fn newest_ms(&self) -> u64 {
        self.deferred
            .as_ref()
            .map_or(self.issued_ms, |(waiting, _)| {
                waiting.content().issued_ms.max(self.issued_ms)
            })
    }

    fn signer(&self) -> PublicKey {
        self.offer.signer()
    }

    fn products(&self) -> Streams {
        self.offer.content().products
    }
}

/// An offer as the directory checked it on arrival: its signature verified, its signer and content
/// read, once. What is held, and what every reader of the held offers is given, so none verifies or
/// decodes a held offer again. Only the directory makes one. Cheap to clone.
#[derive(Clone)]
pub struct Checked(Arc<CheckedOffer>);

struct CheckedOffer {
    offer: ProviderOffer,
    signer: PublicKey,
    content: ProviderOfferContent,
}

impl Checked {
    /// The offer as signed: what is gossiped and answered.
    pub fn offer(&self) -> &ProviderOffer {
        &self.0.offer
    }

    pub fn signer(&self) -> PublicKey {
        self.0.signer
    }

    pub fn content(&self) -> &ProviderOfferContent {
        &self.0.content
    }
}

impl std::fmt::Debug for Checked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.offer.fmt(formatter)
    }
}

impl PartialEq for Checked {
    fn eq(&self, other: &Self) -> bool {
        self.0.offer == other.0.offer
    }
}

impl PartialEq<ProviderOffer> for Checked {
    fn eq(&self, other: &ProviderOffer) -> bool {
        self.0.offer == *other
    }
}

/// Where a held offer stands against the others under a cap (`State::hold`), the lowest given up
/// first: its key's tier, then how deep it sits in its own cell's ranking (`ranked`, the deeper
/// the lower), then its cell and key, so two offers never stand alike. Restricted to one cell it
/// is that cell's ranking, since the ranking puts every higher tier first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Standing {
    tier: u32,
    depth: std::cmp::Reverse<usize>,
    cell: u64,
    key: PublicKey,
}

/// The caps an offer is held under, besides the relay's own (which count against none).
#[derive(Clone, Copy, Debug)]
enum Cap {
    /// One network group's share of the cell.
    GroupInCell,
    Cell,
    /// One network group, over every cell.
    Group,
    /// One key, over every cell.
    Key,
    /// The directory.
    Held,
}

impl Cap {
    const ALL: [Self; 5] = [
        Self::GroupInCell,
        Self::Cell,
        Self::Group,
        Self::Key,
        Self::Held,
    ];

    fn limit(self) -> usize {
        match self {
            Self::GroupInCell => OFFERS_PER_GROUP_IN_CELL,
            Self::Cell => OFFERS_PER_CELL,
            Self::Group => OFFERS_PER_GROUP,
            Self::Key => OFFERS_PER_KEY,
            Self::Held => OFFERS_HELD,
        }
    }
}

/// `keys`, best first: by their contribution tier (`tier`, higher first), and within a tier by
/// the wire's rendezvous ranking for `cell`, every key weighted alike. The one order every relay
/// puts a cell's offers in: the tiers are a function of the evidence held and the offers held
/// (`State::tier`), so the same of both orders alike everywhere.
fn ranked(cell: Region, keys: impl IntoIterator<Item = (PublicKey, u32)>) -> Vec<PublicKey> {
    let keys: Vec<(PublicKey, u32)> = keys.into_iter().collect();
    let tiers: HashMap<PublicKey, u32> = keys.iter().copied().collect();
    let candidates: Vec<Weighted> = keys
        .into_iter()
        .map(|(key, _)| Weighted {
            key,
            weight: 1,
            network: 0,
            host: None,
        })
        .collect();
    let order: Vec<PublicKey> = rendezvous::rank(cell, &candidates)
        .unwrap_or_default()
        .into_iter()
        .map(|candidate| candidate.key)
        .collect();
    by_tier(order, |key| tiers.get(key).copied().unwrap_or(0))
}

/// `order` (a rendezvous ranking, best first) with every higher contribution tier ahead of every
/// lower one, and the ranking kept within a tier: the one rule by which contribution outranks a
/// hash, for the directory's held offers (`ranked`) and for an area's MLAT relays
/// (`selection::mlat_relays`). Where no relay has a tier, the ranking is unchanged.
pub fn by_tier<T>(mut order: Vec<T>, tier: impl Fn(&T) -> u32) -> Vec<T> {
    // Stable: within a tier, the rendezvous order stands.
    order.sort_by_key(|item| std::cmp::Reverse(tier(item)));
    order
}

/// A contribution's tier: its bit length, so each tier is twice the witnesses of the one below
/// and 0 is none. Coarse on purpose: evidence that differs a little (a witness more or less)
/// moves a relay at most one tier, and two relays within a factor of two of each other are
/// ordered by rendezvous alone.
pub fn tier(witnesses: u64) -> u32 {
    u64::BITS - witnesses.leading_zeros()
}

/// The clock a contribution is weighed at: the minute `now_ms` falls in, so relays that weigh the
/// same evidence within one minute weigh it alike, and the tiers are weighed once a minute.
const WEIGHED_EVERY_MS: u64 = 60 * 1000;

#[derive(Clone)]
struct Pending {
    offer: Checked,
    asker: PublicKey,
}

/// What the relay's own offers declare: re-signed when it changes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Basis {
    address: String,
    cells: Vec<Region>,
    /// Per cell, the stripes this relay forwards there (`sharing`'s trees), out of
    /// `sharing::stripes::STRIPES`.
    stripes: Vec<u32>,
    mlat_cores: u16,
    products: Streams,
    /// The feeder slots, by power of two (0 is none): a change of a few slots is not news.
    slots_class: u32,
    feeder_slots: u32,
    network: u32,
}

impl Basis {
    fn same(&self, other: &Self) -> bool {
        self.address == other.address
            && self.cells == other.cells
            && self.stripes == other.stripes
            && self.mlat_cores == other.mlat_cores
            && self.products == other.products
            && self.slots_class == other.slots_class
            && self.network == other.network
    }
}

/// When an offer stops being held: when it says, but never later than `OFFER_LIFETIME_MS` after
/// it was signed.
pub fn expiry(content: &ProviderOfferContent) -> u64 {
    content
        .expires_ms
        .min(content.issued_ms.saturating_add(OFFER_LIFETIME_MS))
}

/// Whether two offers of one signer for one cell say the same, but for when they were signed, how
/// long they live and the feeder slots they count (which only a feeder's query reads): a
/// re-signing that changes nothing any reader of the held offers follows.
fn same_offer(held: &ProviderOfferContent, new: &ProviderOfferContent) -> bool {
    let plain = |content: &ProviderOfferContent| ProviderOfferContent {
        issued_ms: 0,
        expires_ms: 0,
        feeder_slots: 0,
        ..content.clone()
    };
    plain(held) == plain(new)
}

/// An offer whose signature verifies and whose lifetime holds at `now_ms`, checked: the one place
/// an offer is verified.
fn checked(offer: &ProviderOffer, now_ms: u64) -> Option<Checked> {
    offer.verify().ok()?;
    let content = offer.content().ok()?;
    let signer = offer.signer().ok()?;
    live(&content, now_ms).then(|| {
        Checked(Arc::new(CheckedOffer {
            offer: offer.clone(),
            signer,
            content,
        }))
    })
}

/// Whether an offer's lifetime holds at `now_ms`: not expired, and not issued in the future past
/// the allowed skew.
fn live(content: &ProviderOfferContent, now_ms: u64) -> bool {
    expiry(content) > now_ms && content.issued_ms <= now_ms + CLOCK_SKEW_MS
}

/// What the held offers answer, named (`Directory::version`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Version {
    held: u64,
    expired: u64,
}

/// The live offers of the cells no finer than an area (`Directory::coverage`).
#[derive(Clone, Debug, Default)]
pub struct Coverage {
    offers: HashMap<u64, Vec<Checked>>,
    /// Every cell some covered cell lies strictly inside.
    inside: HashSet<u64>,
}

impl Coverage {
    /// The offers held for `cell` itself, in rank order.
    pub fn at(&self, cell: Region) -> &[Checked] {
        self.offers.get(&cell.as_u64()).map_or(&[], Vec::as_slice)
    }

    /// Whether some cell strictly inside `cell` (and no finer than an area) holds offers: if
    /// not, every area under `cell` is covered by the same offers.
    pub fn inside(&self, cell: Region) -> bool {
        self.inside.contains(&cell.as_u64())
    }

    /// The cells holding offers, with them.
    pub fn cells(&self) -> impl Iterator<Item = (Region, &[Checked])> {
        self.offers.iter().filter_map(|(cell, offers)| {
            Region::from_u64(*cell)
                .ok()
                .map(|cell| (cell, offers.as_slice()))
        })
    }
}

impl Directory {
    pub fn new() -> Self {
        Self::default()
    }

    /// The key the relay's own offers are signed with, once it has offered.
    pub fn own_key(&self) -> Option<PublicKey> {
        lock(&self.state).own
    }

    #[cfg(test)]
    pub(crate) fn adopt_own_key(&self, key: PublicKey) {
        lock(&self.state).own = Some(key);
    }

    /// An offer a peer sent or gossiped: checked, then held at once if its key already answered
    /// at its address, else queued for the handshake (`tick` dials). Acted on once by its hash.
    pub fn offered(&self, asker: &Asker, offer: ProviderOffer, now_ms: u64) {
        lock(&self.state).offered(asker, offer, now_ms);
    }

    /// The offers held for `query.cell` and its ancestors, live at `now_ms`, of the products
    /// asked (any, when none is named): the finest cell first, in rank order within a cell; at
    /// most `QUERY_ANSWER_MAX`.
    pub fn query(&self, query: &ProviderQuery, now_ms: u64) -> Vec<ProviderOffer> {
        let Ok(path) = rendezvous::ancestors(query.cell) else {
            return Vec::new();
        };
        let mut state = lock(&self.state);
        let mut answer = Vec::new();
        for cell in path {
            let offers = state.ranked_offers(cell, now_ms, |held| {
                query.products.0 == 0 || held.products().0 & query.products.0 != 0
            });
            answer.extend(offers.into_iter().map(|offer| offer.offer().clone()));
            if answer.len() >= QUERY_ANSWER_MAX {
                break;
            }
        }
        answer.truncate(QUERY_ANSWER_MAX);
        answer
    }

    /// Every live offer that covers `cell`: for the cell itself and each of its ancestors (an
    /// offer for a parent provides every cell under it), each cell's in rank order and at most
    /// `OFFERS_PER_CELL`. For the MLAT choice and the sharing trees, so unpaged: the same offers
    /// held give the same answer on every relay.
    pub fn offers_for(&self, cell: Region, now_ms: u64) -> Vec<Checked> {
        let Ok(path) = rendezvous::ancestors(cell) else {
            return Vec::new();
        };
        let mut state = lock(&self.state);
        path.iter()
            .flat_map(|cell| state.ranked_offers(*cell, now_ms, |_| true))
            .collect()
    }

    /// The cells `key`'s live offers held name (its own, for this relay's key), each once,
    /// sorted.
    pub fn cells_of(&self, key: &PublicKey, now_ms: u64) -> Vec<Region> {
        let state = lock(&self.state);
        let mut cells: Vec<Region> = state
            .held_of(key)
            .filter(|held| held.expires_ms > now_ms)
            .map(|held| held.offer.content().cell)
            .collect();
        cells.sort_by_key(|cell| cell.as_u64());
        cells.dedup();
        cells
    }

    /// What the held offers answer at `now_ms`, named: two equal versions answer `offers_for`,
    /// `coverage` and `tier_of` alike, so a reader keeps what it computed from them until the
    /// version moves. It moves when an offer is held, let go or says something new, when a tier
    /// moves (by new evidence, or weighed again in a new minute), and when a held offer's expiry
    /// passes.
    pub fn version(&self, now_ms: u64) -> Version {
        let mut state = lock(&self.state);
        state.roll_tiers(now_ms);
        Version {
            held: state.version,
            expired: state
                .expiries
                .range(..=now_ms)
                .next_back()
                .map_or(0, |(at, _)| *at),
        }
    }

    /// The cells whose held offers answer differently since the last call, sorted: offers that
    /// expired by `now_ms` let go first, and every crowded cell when the tiers are weighed again.
    /// For sharing, which lays out the trees of only the areas under these.
    pub fn take_changed_cells(&self, now_ms: u64) -> Vec<Region> {
        let mut state = lock(&self.state);
        state.expire_offers(now_ms);
        state.roll_tiers(now_ms);
        let mut cells: Vec<Region> = state
            .changed
            .drain()
            .filter_map(|cell| Region::from_u64(cell).ok())
            .collect();
        cells.sort_by_key(|cell| cell.as_u64());
        cells
    }

    /// Every cell another relay than `own` holds an offer for, sorted.
    pub fn cells_held_by_others(&self, own: &PublicKey) -> Vec<Region> {
        let state = lock(&self.state);
        let mut cells: Vec<Region> = state
            .cells
            .iter()
            .filter(|(_, offers)| offers.keys().any(|key| key != own))
            .filter_map(|(cell, _)| Region::from_u64(*cell).ok())
            .collect();
        cells.sort_by_key(|cell| cell.as_u64());
        cells
    }

    /// Whether another relay than `own` holds an offer for `cell` itself.
    pub fn others_hold(&self, cell: Region, own: &PublicKey) -> bool {
        lock(&self.state)
            .cells
            .get(&cell.as_u64())
            .is_some_and(|offers| offers.keys().any(|key| key != own))
    }

    /// The live offers of every cell no finer than an area, each cell's as `offers_for` takes
    /// them (in rank order, at most `OFFERS_PER_CELL`): what covers the areas, read once for a
    /// whole region rather than area by area (`selection`).
    pub fn coverage(&self, now_ms: u64) -> Coverage {
        let mut state = lock(&self.state);
        let cells: Vec<u64> = state.cells.keys().copied().collect();
        let mut coverage = Coverage::default();
        for cell in cells {
            let Ok(region) = Region::from_u64(cell) else {
                continue;
            };
            if region.resolution() > rendezvous::AREA_RESOLUTION {
                continue;
            }
            let offers = state.ranked_offers(region, now_ms, |_| true);
            if offers.is_empty() {
                continue;
            }
            for resolution in 0..region.resolution() {
                if let Some(ancestor) = region.ancestor(resolution) {
                    coverage.inside.insert(ancestor.as_u64());
                }
            }
            coverage.offers.insert(cell, offers);
        }
        coverage
    }

    /// Whether a live offer signed by `key` is held (one this relay verified, by a handshake at
    /// its address): such a relay may exchange a sharing group's addressed records with this one.
    /// A lookup, not a scan: every session asks it of every record (`Hub::relay_trust`). An
    /// offer that expired is forgotten at the next tick (`network::TICK`).
    pub fn knows(&self, key: &PublicKey) -> bool {
        let state = lock(&self.state);
        state.own != Some(*key) && state.per_key.contains_key(key)
    }

    /// Where a relay whose live offer is held answers: the address its handshake was proved at.
    pub fn address_of(&self, key: &PublicKey) -> Option<String> {
        let now_ms = crate::network::wall_ms();
        let state = lock(&self.state);
        if state.own == Some(*key) {
            return None;
        }
        state
            .held_of(key)
            .filter(|held| held.expires_ms > now_ms)
            .min_by_key(|held| held.offer.content().cell.as_u64())
            .map(|held| held.offer.content().address.clone())
    }

    /// Every live offer held, and this relay's own as last signed (held here or not: a peer
    /// holds them by its own caps), each once: what a new directory link is sent first.
    pub fn live_offers(&self, now_ms: u64) -> Vec<ProviderOffer> {
        let state = lock(&self.state);
        let mut seen = HashSet::new();
        let own = state
            .own_offers
            .iter()
            .filter(|offer| live(offer.content(), now_ms));
        state
            .cells
            .values()
            .flat_map(HashMap::values)
            .filter(|held| held.expires_ms > now_ms)
            .map(|held| &held.offer)
            .chain(own)
            .filter(|offer| seen.insert(offer.offer().hash()))
            .map(|offer| offer.offer().clone())
            .collect()
    }

    /// A relay's evidence bundle, gossiped on a directory link: checked by credit's own
    /// verifier (`credit::check`) and held if it is newer than what is held of its signer. True
    /// when held, and then gossiped once at the next tick.
    pub fn evidence(&self, bundle: &EvidenceBundle, now_ms: u64) -> bool {
        lock(&self.state).evidence(bundle, now_ms)
    }

    /// Every evidence bundle held: what a new directory link is sent beside the offers.
    pub fn live_evidence(&self) -> Vec<EvidenceBundle> {
        let state = lock(&self.state);
        let mut bundles: Vec<EvidenceBundle> = state
            .evidence
            .values()
            .map(|(_, bundle)| bundle.clone())
            .collect();
        bundles.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        bundles
    }

    /// `key`'s contribution tier now (`tier`): what its offers are ranked by first.
    pub fn tier_of(&self, key: &PublicKey, now_ms: u64) -> u32 {
        lock(&self.state).tier(key, now_ms)
    }

    /// Offers held now.
    pub fn len(&self) -> usize {
        lock(&self.state).held
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What to publish now: the relay's own offers when due for re-signing, and the offers newly
    /// verified, each once. Also forgets what expired and starts the handshakes waiting.
    pub fn tick(&self, hub: &Hub, identity: Option<&Identity>, now_ms: u64) -> Vec<Record> {
        let Some(identity) = identity else {
            return Vec::new();
        };
        let basis = own_basis(hub, identity);
        let offering = basis.is_some();
        let mut out = Vec::new();
        let mut evidence = Vec::new();
        let mut resolve = None;
        let evidence_due = {
            let mut state = lock(&self.state);
            state.own = Some(identity.public());
            // The offers name the advertised address by number: a host name as it last resolved,
            // and nothing is signed (or withdrawn) before it first resolves.
            let mut unresolved = false;
            let basis = basis.and_then(|mut basis| {
                let (address, due) = state.own_address_of(&basis.address, now_ms);
                if due {
                    resolve = Some(basis.address.clone());
                }
                let Some(address) = address else {
                    unresolved = true;
                    return None;
                };
                basis.address = address.to_string();
                Some(basis)
            });
            state.expire(now_ms);
            if !unresolved && let Some(offers) = state.resign(identity, basis, now_ms) {
                out.extend(offers);
            }
            out.append(&mut state.gossip);
            evidence.append(&mut state.evidence_gossip);
            offering
                && state
                    .own_evidence_ms
                    .is_none_or(|at| now_ms.saturating_sub(at) >= OWN_EVIDENCE_EVERY_MS)
        };
        // The relay's own evidence goes with its offers, so every relay ranks them by the same
        // evidence (`State::tier`).
        if evidence_due && let Ok(bundle) = hub.network().credit.bundle(identity, now_ms) {
            let mut state = lock(&self.state);
            state.own_evidence_ms = Some(now_ms);
            if state.evidence(&bundle, now_ms) {
                evidence.push(bundle);
            }
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // The advertised host name, resolved: the address its own offers name from then on,
            // which puts them in their group for every relay alike.
            if let Some(address) = resolve {
                lock(&self.state).own_resolving = Some((address.clone(), u64::MAX));
                let state = Arc::clone(&self.state);
                runtime.spawn(async move {
                    let resolved = resolved_address(&address).await;
                    // By the clock of the tick that asked.
                    lock(&state).resolved(&address, resolved, now_ms);
                });
            }
            while let Some(pending) = self.next_to_verify() {
                let state = Arc::clone(&self.state);
                let identity = identity.clone();
                runtime.spawn(async move {
                    let answered = answers_as(
                        &pending.offer.content().address,
                        &identity,
                        &pending.offer.signer(),
                    )
                    .await;
                    lock(&state).verified(pending, answered, crate::network::wall_ms());
                });
            }
        }
        out.into_iter()
            .map(Record::ProviderOffer)
            .chain(evidence.into_iter().map(Record::EvidenceBundle))
            .collect()
    }

    /// Dials every offer waiting, one after another, and records each outcome at `now_ms`: the
    /// handshakes `tick` runs concurrently, run in line (for tests, and a caller with its own
    /// task).
    pub async fn verify_pending(&self, identity: &Identity, now_ms: u64) {
        while let Some(pending) = self.next_to_verify() {
            let answered = answers_as(
                &pending.offer.content().address,
                identity,
                &pending.offer.signer(),
            )
            .await;
            lock(&self.state).verified(pending, answered, now_ms);
        }
    }

    /// The next offer to dial, if fewer than `VERIFYING_AT_ONCE` are in flight; marks it
    /// dialling.
    fn next_to_verify(&self) -> Option<Pending> {
        let mut state = lock(&self.state);
        if state.verifying >= VERIFYING_AT_ONCE {
            return None;
        }
        let at = state
            .pending
            .iter()
            .position(|pending| !state.dialling.contains(&pending.offer.content().address))?;
        let pending = state.pending.remove(at)?;
        state
            .dialling
            .insert(pending.offer.content().address.clone());
        state.verifying += 1;
        Some(pending)
    }

    /// Holds an offer as verified from `group`, without a dial: for the relay's own path and tests.
    #[cfg(test)]
    pub(crate) fn hold_verified(
        &self,
        offer: ProviderOffer,
        group: Group,
        now_ms: u64,
    ) -> Result<bool, String> {
        let offer = checked(&offer, now_ms).ok_or("not a live, signed offer")?;
        Ok(lock(&self.state).hold(offer, group, now_ms))
    }
}

impl Directory {
    /// Holds what an offer of `signer` saying `content` would be once checked, standing in
    /// `stand_in`'s bytes, without signing or verifying it: for tests of the caps over tens of
    /// thousands of offers, which signatures would make slow. Only what the caps and readers read
    /// of a held offer (its signer and content) is real.
    #[cfg(test)]
    pub(crate) fn hold_unsigned(
        &self,
        stand_in: &ProviderOffer,
        signer: PublicKey,
        content: ProviderOfferContent,
        group: Group,
        now_ms: u64,
    ) -> bool {
        let offer = Checked(Arc::new(CheckedOffer {
            offer: stand_in.clone(),
            signer,
            content,
        }));
        lock(&self.state).hold(offer, group, now_ms)
    }
}

/// The address the advertised `address` (a `HOST:PORT`) resolves to first: what the relay's own
/// offers name, so no peer resolves it.
async fn resolved_address(address: &str) -> Option<std::net::SocketAddr> {
    let mut addresses = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host(address))
        .await
        .ok()?
        .ok()?;
    addresses.next()
}

/// Dials `address` (an offer's, an IP and port: `Group::of_address`) and runs the handshake to
/// `key`: true if it answered as `key`. A refusal after the handshake (a full relay's `Goodbye`)
/// still proves the key, since only its holder completes the handshake. Never resolves a name.
async fn answers_as(address: &str, identity: &Identity, key: &PublicKey) -> bool {
    let Ok(address) = address.parse::<std::net::SocketAddr>() else {
        return false;
    };
    let ip = address.ip();
    if ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let Ok(Ok(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address)).await
    else {
        return false;
    };
    matches!(
        noise::connect(stream, identity, key, tally_wire::Role::Subscriber).await,
        Ok(_) | Err(WireError::Refused { .. })
    )
}

/// What the relay's own offers should declare now, or `None` if it has nothing to offer (no
/// region taken, or no address advertised under its key, which no one could verify).
fn own_basis(hub: &Hub, identity: &Identity) -> Option<Basis> {
    let network = hub.network();
    let own = identity.public();
    let address = hub
        .hints()
        .iter()
        .find(|hint| hint.key == own)?
        .address
        .clone();
    // The areas taken, and the parents this relay has gathered every child of (bundles, §2.6),
    // as the fewest cells that cover them: every one, never cut to a count.
    let cells: Vec<Region> = network
        .sharing
        .bundles
        .offered(&network.selection.taken())
        .cells()
        .to_vec();
    if cells.is_empty() {
        return None;
    }
    let stripes = cells
        .iter()
        .map(|cell| forwarded_stripes(&network.sharing, *cell, &own))
        .collect();
    let headroom = network.admission.headroom(hub);
    Some(Basis {
        address,
        cells,
        stripes,
        mlat_cores: headroom.mlat_cores,
        products: own_products(network.admission.duties()),
        slots_class: u32::BITS - headroom.feeder_slots.leading_zeros(),
        feeder_slots: headroom.feeder_slots,
        network: network.admission.network(),
    })
}

/// The stripes this relay forwards in `cell`'s groups: none where it has withdrawn because its
/// upload cap is shedding the peers it forwards to (`sharing::withdrawal`); else those where its
/// trees make it interior, over every product shared. Before the trees are laid out (or for a cell
/// with no group yet), every stripe: a relay that takes an area is willing to forward any slice
/// of it.
fn forwarded_stripes(sharing: &crate::sharing::Sharing, cell: Region, own: &PublicKey) -> u32 {
    if sharing.withdrawn(cell) {
        return 0;
    }
    let all = (1u32 << crate::sharing::stripes::STRIPES) - 1;
    let mut stripes = 0;
    let mut laid_out = false;
    for product in crate::sharing::SHARED_PRODUCTS {
        if let Some(homes) = sharing.homes(cell, product, own) {
            laid_out = true;
            for stripe in homes {
                stripes |= 1 << stripe;
            }
        }
    }
    if laid_out && stripes != 0 {
        stripes
    } else {
        all
    }
}

impl State {
    /// The held offers of `cell` live at `now_ms` that `keep` allows, in rank order (`ranked`), at
    /// most `OFFERS_PER_CELL`: what the cell is answered with, the relay's own offer ranked among
    /// the rest exactly as every other relay ranks it.
    fn ranked_offers(
        &mut self,
        cell: Region,
        now_ms: u64,
        keep: impl Fn(&Held) -> bool,
    ) -> Vec<Checked> {
        let order = self.ranking(cell.as_u64(), now_ms).to_vec();
        let Some(offers) = self.cells.get(&cell.as_u64()) else {
            return Vec::new();
        };
        order
            .iter()
            .filter_map(|key| offers.get(key))
            .filter(|held| held.expires_ms > now_ms && keep(held))
            .take(OFFERS_PER_CELL)
            .map(|held| held.offer.clone())
            .collect()
    }

    /// Every offer held for `cell`, ranked (`ranked`): kept until the cell's offers or the tiers
    /// change.
    fn ranking(&mut self, cell: u64, now_ms: u64) -> &[PublicKey] {
        self.weigh_at(now_ms);
        if !self.ranks.contains_key(&cell) {
            let keys: Vec<PublicKey> = self
                .cells
                .get(&cell)
                .map(|offers| offers.keys().copied().collect())
                .unwrap_or_default();
            let tiered: Vec<(PublicKey, u32)> = keys
                .into_iter()
                .map(|key| (key, self.tier(&key, now_ms)))
                .collect();
            let order = Region::from_u64(cell)
                .map(|region| ranked(region, tiered))
                .unwrap_or_default();
            self.ranks.insert(cell, order);
        }
        self.ranks.get(&cell).map_or(&[], Vec::as_slice)
    }

    /// The tiers are weighed by the minute: a new minute forgets them, and the rankings made from
    /// them.
    fn weigh_at(&mut self, now_ms: u64) {
        let at = now_ms - now_ms % WEIGHED_EVERY_MS;
        if at != self.tiers_at {
            self.tiers_at = at;
            self.clear_tiers();
        }
    }

    /// The tiers are weighed again: forget them, and every ranking made from them.
    fn clear_tiers(&mut self) {
        self.tiers.clear();
        self.ranks.clear();
    }

    /// What `keys`' tiers are weighed from changed (their own evidence): forget their tiers, and
    /// the rankings of the cells they hold offers for. A key's evidence weighs in its own tier and
    /// no other's.
    fn retier(&mut self, keys: impl IntoIterator<Item = PublicKey>) {
        for key in keys {
            self.tiers.remove(&key);
            for cell in self.per_key.get(&key).into_iter().flatten() {
                self.ranks.remove(cell);
            }
        }
    }

    /// The networks some key answers from changed, which witnesses count by (`State::tier`): only
    /// a key with evidence has a tier to move (one with none is tier 0 whatever networks answer),
    /// so theirs are weighed again.
    fn networks_moved(&mut self) {
        let evidenced: Vec<PublicKey> = self.evidence.keys().copied().collect();
        self.retier(evidenced);
    }

    /// Where the held offer of `key` for `cell` stands (`Standing`); `with` is a newcomer to rank
    /// as if held, beside the cell's offers when it is the same cell.
    fn standing(
        &mut self,
        (cell, key): (u64, PublicKey),
        with: Option<(u64, PublicKey)>,
        now_ms: u64,
    ) -> Standing {
        let tier = self.tier(&key, now_ms);
        let depth = match with {
            Some((with_cell, with_key)) if with_cell == cell => {
                let mut keys: Vec<PublicKey> = self.ranking(cell, now_ms).to_vec();
                if !keys.contains(&with_key) {
                    keys.push(with_key);
                }
                let tiered: Vec<(PublicKey, u32)> = keys
                    .into_iter()
                    .map(|one| (one, self.tier(&one, now_ms)))
                    .collect();
                Region::from_u64(cell)
                    .map(|region| ranked(region, tiered))
                    .unwrap_or_default()
                    .iter()
                    .position(|one| *one == key)
            }
            _ => self
                .ranking(cell, now_ms)
                .iter()
                .position(|one| *one == key),
        }
        .unwrap_or(usize::MAX);
        Standing {
            tier,
            depth: std::cmp::Reverse(depth),
            cell,
            key,
        }
    }

    /// The held offers under `cap` for a newcomer of `signer` for `cell` from `group`.
    fn under(
        &self,
        cap: Cap,
        (cell, signer, group): (u64, PublicKey, Group),
    ) -> Vec<(u64, PublicKey)> {
        let in_cell = || self.cells.get(&cell).into_iter().flat_map(HashMap::values);
        match cap {
            Cap::GroupInCell => in_cell()
                .filter(|held| held.group == group)
                .map(|held| (cell, held.signer()))
                .collect(),
            Cap::Cell => in_cell().map(|held| (cell, held.signer())).collect(),
            Cap::Group => self
                .per_group
                .get(&group)
                .into_iter()
                .flatten()
                .copied()
                .collect(),
            Cap::Key => self
                .per_key
                .get(&signer)
                .into_iter()
                .flatten()
                .map(|held_cell| (*held_cell, signer))
                .collect(),
            Cap::Held => self
                .cells
                .iter()
                .flat_map(|(held_cell, offers)| {
                    offers.values().map(move |held| (*held_cell, held.signer()))
                })
                .collect(),
        }
    }

    /// How many held offers are under `cap` for a newcomer of `signer` for `cell` from `group`,
    /// without listing them where a count is kept.
    fn count_under(&self, cap: Cap, (cell, signer, group): (u64, PublicKey, Group)) -> usize {
        match cap {
            Cap::GroupInCell | Cap::Cell => self.under(cap, (cell, signer, group)).len(),
            Cap::Group => self.per_group.get(&group).map_or(0, HashSet::len),
            Cap::Key => self.per_key.get(&signer).map_or(0, HashSet::len),
            Cap::Held => self.held,
        }
    }

    /// The held offers `key` signed, in no order.
    fn held_of<'a>(&'a self, key: &PublicKey) -> impl Iterator<Item = &'a Held> + 'a {
        let key = *key;
        self.per_key
            .get(&key)
            .into_iter()
            .flatten()
            .filter_map(move |cell| self.cells.get(cell)?.get(&key))
    }

    /// `key`'s contribution tier at `now_ms`'s minute: `tier` of what its evidence is worth by
    /// credit's one weigher (`credit::worth`), counting what every relay holding the same offers
    /// counts alike and nothing a party can mint for free:
    ///
    /// - a child's receipts only when the child is a relay with an offer held here, verified at
    ///   its address, once per network group it answered from, and never from a group the relay
    ///   itself answers from: a witness costs an address on another network, as an offer does;
    /// - each such network one witness, whatever its receipts say was delivered (`flat`): the
    ///   rates are the two parties' own figures, so a party with one network could otherwise
    ///   sign itself the highest rate there is;
    /// - no feeder's description, since a feeder key is free and what corroborates one (receiver
    ///   standing, `credit::Credit::corroborate_receiver`) is each relay's own, and so would rank
    ///   a cell differently relay to relay.
    ///
    /// So the tier is the bit length of the count of networks that witnessed the relay deliver: a
    /// key that showed no evidence is tier 0, below every relay with a witness, and to outrank a
    /// relay with `n` witnesses a party needs relays answering on more than `n` networks.
    fn tier(&mut self, key: &PublicKey, now_ms: u64) -> u32 {
        self.weigh_at(now_ms);
        let at = self.tiers_at;
        if let Some(tier) = self.tiers.get(key) {
            return *tier;
        }
        let weighed = self.evidence.get(key).map_or(0, |(shown, _)| {
            let groups_of = |of: &PublicKey| -> Vec<Group> {
                let mut groups: Vec<Group> = self
                    .key_groups
                    .get(of)
                    .into_iter()
                    .flat_map(BTreeMap::keys)
                    .copied()
                    .collect();
                groups.sort();
                groups
            };
            let own_groups = groups_of(key);
            let child = |child: &PublicKey| -> Option<Unit> {
                let group = groups_of(child).into_iter().next()?;
                (!own_groups.contains(&group)).then_some(Unit::Network(group.as_u64()))
            };
            let feeder = |_: &PublicKey| false;
            credit::worth(
                shown,
                key,
                &Corroboration {
                    feeder: &feeder,
                    child: &child,
                    flat: Some(1),
                },
                at,
            )
        });
        let tier = tier(weighed);
        self.tiers.insert(*key, tier);
        tier
    }

    /// See `Directory::evidence`.
    fn evidence(&mut self, bundle: &EvidenceBundle, now_ms: u64) -> bool {
        let Ok(signer) = bundle.signer() else {
            return false;
        };
        let Ok(shown) = credit::check(bundle, now_ms) else {
            return false;
        };
        // Held whether or not the signer's offer is yet (it may be waiting for its handshake), so
        // its offer is ranked by it on arrival; bounded, and a signer with an offer held keeps
        // its evidence over one without.
        if !self.evidence.contains_key(&signer) && self.evidence.len() >= EVIDENCE_HELD {
            let per_key = &self.per_key;
            let unheld = self
                .evidence
                .iter()
                .filter(|(key, _)| !per_key.contains_key(key))
                .min_by_key(|(key, (shown, _))| (shown.issued_ms(), **key))
                .map(|(key, _)| *key);
            match unheld {
                Some(key) => {
                    self.evidence.remove(&key);
                    self.retier([key]);
                }
                None => return false,
            }
        }
        let newer = self
            .evidence
            .get(&signer)
            .is_none_or(|(held, _)| held.issued_ms() < shown.issued_ms());
        if !newer {
            return false;
        }
        let before = self.tier(&signer, now_ms);
        self.evidence.insert(signer, (shown, bundle.clone()));
        self.retier([signer]);
        // A key's evidence weighs in its own tier and no other's.
        if self.tier(&signer, now_ms) != before {
            self.tiers_moved();
        }
        if Some(signer) != self.own {
            self.evidence_gossip.push(bundle.clone());
        }
        true
    }

    fn offered(&mut self, asker: &Asker, offer: ProviderOffer, now_ms: u64) {
        let hash = offer.hash();
        if self.seen.get(&hash).is_some() {
            return;
        }
        self.seen.insert(hash, ());
        let Some(offer) = checked(&offer, now_ms) else {
            return;
        };
        let (signer, content) = (offer.signer(), offer.content());
        // In no group (a host name): no two relays could be sure to put it in the same one.
        let Some(group) = Group::of_address(&content.address) else {
            return;
        };
        // The relay's own offers, come back: never taken from outside.
        if Some(signer) == self.own {
            return;
        }
        // Only a relay carries offers it did not sign.
        if asker.role != AskerRole::Relay && asker.key != signer {
            return;
        }
        let stale = self
            .cells
            .get(&content.cell.as_u64())
            .and_then(|cell| cell.get(&signer))
            .is_some_and(|held| held.newest_ms() >= content.issued_ms);
        if stale {
            return;
        }
        let trusted = self
            .verified
            .get(&(signer, content.address.clone()))
            .is_some_and(|until| *until > now_ms);
        if trusted {
            if self.hold(offer.clone(), group, now_ms) {
                self.gossip.push(offer.offer().clone());
            }
            return;
        }
        if self
            .unanswered
            .get(&content.address)
            .is_some_and(|until| *until > now_ms)
        {
            return;
        }
        // One waiting per (key, address, cell), the newest.
        if let Some(waiting) = self.pending.iter_mut().find(|waiting| {
            let held = waiting.offer.content();
            waiting.offer.signer() == signer
                && held.address == content.address
                && held.cell == content.cell
        }) {
            if waiting.offer.content().issued_ms < content.issued_ms {
                waiting.offer = offer;
            }
            return;
        }
        let from_asker = self
            .pending
            .iter()
            .filter(|waiting| waiting.asker == asker.key)
            .count();
        if self.pending.len() >= PENDING || from_asker >= PENDING_PER_ASKER {
            return;
        }
        self.pending.push_back(Pending {
            offer,
            asker: asker.key,
        });
    }

    /// A handshake's outcome.
    fn verified(&mut self, pending: Pending, answered: bool, now_ms: u64) {
        let (signer, content) = (pending.offer.signer(), pending.offer.content());
        self.dialling.remove(&content.address);
        self.verifying = self.verifying.saturating_sub(1);
        // Only an offer in a group is queued (`offered`).
        match Group::of_address(&content.address).filter(|_| answered) {
            Some(group) => {
                self.verified
                    .insert((signer, content.address.clone()), now_ms + VERIFIED_FOR_MS);
                // Checked when it came; only its lifetime may have run out since.
                if live(content, now_ms) && self.hold(pending.offer.clone(), group, now_ms) {
                    self.gossip.push(pending.offer.offer().clone());
                }
            }
            None => {
                self.unanswered
                    .insert(content.address.clone(), now_ms + UNANSWERED_FOR_MS);
            }
        }
    }

    /// Holds a verified offer if the caps allow it, by rank (see the module). True when held
    /// (new, or newer for its key and cell); false when refused, or when it is a change that must
    /// wait its turn (`CHANGED_AT_MOST_EVERY_MS`), which is then held when due.
    fn hold(&mut self, offer: Checked, group: Group, now_ms: u64) -> bool {
        let (signer, content) = (offer.signer(), offer.content().clone());
        let cell_key = content.cell.as_u64();
        let replacing = self
            .cells
            .get(&cell_key)
            .and_then(|cell| cell.get(&signer))
            .map(|held| {
                (
                    held.newest_ms(),
                    held.issued_ms,
                    held.group,
                    held.changed_ms,
                    same_offer(held.offer.content(), &content),
                )
            });
        let changed_ms = now_ms;
        if let Some((newest_ms, held_issued_ms, held_group, held_changed_ms, same)) = replacing {
            if newest_ms >= content.issued_ms {
                return false;
            }
            // Re-signed from the same network: its rank and its group are unchanged, so it keeps
            // its place. From another network it competes there as a newcomer. Re-signed saying
            // what it said, it changes no answer and supersedes any change waiting: taken no
            // sooner than `RESIGNED_AT_MOST_EVERY_MS` after the one held by their signed times,
            // and then in place, moving nothing a reader or a tier is weighed from.
            if held_group == group && same {
                if content.issued_ms < held_issued_ms.saturating_add(RESIGNED_AT_MOST_EVERY_MS) {
                    return false;
                }
                self.renew(cell_key, offer);
                return true;
            }
            // The relay's own changes are held to `OWN_RESIGN_AT_MOST_EVERY_MS` where it signs.
            let due = held_changed_ms.saturating_add(CHANGED_AT_MOST_EVERY_MS);
            if Some(signer) != self.own && now_ms < due {
                if let Some(held) = self
                    .cells
                    .get_mut(&cell_key)
                    .and_then(|cell| cell.get_mut(&signer))
                {
                    held.deferred = Some((offer, group));
                    self.deferred.insert((due, cell_key, signer));
                }
                return false;
            }
            self.remove(cell_key, &signer);
            if held_group == group {
                self.insert(offer, group, changed_ms);
                return true;
            }
        }
        // Every offer, the relay's own among them, is held under every cap by rank: so this relay
        // holds what its peers hold of its own network, and its own offers no more than they do.
        {
            let newcomer = (cell_key, signer, group);
            let mut given_up: Vec<(u64, PublicKey)> = Vec::new();
            for cap in Cap::ALL {
                let full = |state: &Self, given_up: &[(u64, PublicKey)]| {
                    let under = state.count_under(cap, newcomer);
                    under >= cap.limit()
                        && under - given_up_under(state, cap, newcomer, given_up) >= cap.limit()
                };
                while full(self, &given_up) {
                    let contest: Vec<(u64, PublicKey)> = self
                        .under(cap, newcomer)
                        .into_iter()
                        .filter(|held| !given_up.contains(held))
                        .chain([(cell_key, signer)])
                        .collect();
                    let lowest = contest
                        .into_iter()
                        .map(|held| self.standing(held, Some((cell_key, signer)), now_ms))
                        .min();
                    match lowest {
                        Some(lowest) if (lowest.cell, lowest.key) != (cell_key, signer) => {
                            given_up.push((lowest.cell, lowest.key));
                        }
                        _ => return false,
                    }
                }
            }
            for (cell, key) in given_up {
                self.remove(cell, &key);
            }
        }
        self.insert(offer, group, changed_ms);
        true
    }

    /// The changes whose turn has come (`CHANGED_AT_MOST_EVERY_MS`), held now; each held is
    /// gossiped, as an offer newly held is.
    fn apply_deferred(&mut self, now_ms: u64) {
        while let Some((due, cell, key)) = self.deferred.first().copied() {
            if due > now_ms {
                break;
            }
            self.deferred.pop_first();
            let waiting = self
                .cells
                .get_mut(&cell)
                .and_then(|offers| offers.get_mut(&key))
                .and_then(|held| held.deferred.take());
            if let Some((offer, group)) = waiting
                && live(offer.content(), now_ms)
                && self.hold(offer.clone(), group, now_ms)
            {
                self.gossip.push(offer.offer().clone());
            }
        }
    }

    /// Holds `offer`, new for its signer and cell (or replacing one `remove`d): what the held
    /// offers answer changes. A re-signing that says the same is `renew`ed instead.
    fn insert(&mut self, offer: Checked, group: Group, changed_ms: u64) {
        let (signer, content) = (offer.signer(), offer.content());
        let cell_key = content.cell.as_u64();
        let expires_ms = expiry(content);
        let issued_ms = content.issued_ms;
        self.cells.entry(cell_key).or_default().insert(
            signer,
            Held {
                offer,
                issued_ms,
                expires_ms,
                group,
                changed_ms,
                deferred: None,
            },
        );
        self.per_key.entry(signer).or_default().insert(cell_key);
        self.per_group
            .entry(group)
            .or_default()
            .insert((cell_key, signer));
        let in_group = self
            .key_groups
            .entry(signer)
            .or_default()
            .entry(group)
            .or_insert(0);
        *in_group += 1;
        let new_group = *in_group == 1;
        *self.expiries.entry(expires_ms).or_insert(0) += 1;
        self.held += 1;
        self.ranks.remove(&cell_key);
        self.changed_cell(cell_key);
        // A network a key answers from is what witnesses count by (`State::tier`): the tiers move
        // only when a key's networks do.
        if new_group {
            self.networks_moved();
            self.tiers_moved();
        }
    }

    /// The held offer of `offer`'s signer for its cell, re-signed saying the same (`same_offer`,
    /// from the same group): swapped in place, its new bytes and lifetime, any change waiting
    /// superseded. Its key, cell, group and rank are what they were, so nothing a reader follows
    /// or a tier is weighed from moves, and nothing is told.
    fn renew(&mut self, cell_key: u64, offer: Checked) {
        let signer = offer.signer();
        let Some(held) = self
            .cells
            .get_mut(&cell_key)
            .and_then(|cell| cell.get_mut(&signer))
        else {
            return;
        };
        let was = held.expires_ms;
        held.issued_ms = offer.content().issued_ms;
        held.expires_ms = expiry(offer.content());
        held.deferred = None;
        held.offer = offer;
        let now = held.expires_ms;
        if let Some(count) = self.expiries.get_mut(&was) {
            *count -= 1;
            if *count == 0 {
                self.expiries.remove(&was);
            }
        }
        *self.expiries.entry(now).or_insert(0) += 1;
    }

    fn remove(&mut self, cell_key: u64, signer: &PublicKey) {
        let Some(cell) = self.cells.get_mut(&cell_key) else {
            return;
        };
        let Some(held) = cell.remove(signer) else {
            return;
        };
        if cell.is_empty() {
            self.cells.remove(&cell_key);
        }
        if let Some(cells) = self.per_key.get_mut(signer) {
            cells.remove(&cell_key);
            if cells.is_empty() {
                self.per_key.remove(signer);
            }
        }
        if let Some(offers) = self.per_group.get_mut(&held.group) {
            offers.remove(&(cell_key, *signer));
            if offers.is_empty() {
                self.per_group.remove(&held.group);
            }
        }
        let mut left_group = false;
        if let Some(groups) = self.key_groups.get_mut(signer) {
            if let Some(count) = groups.get_mut(&held.group) {
                *count -= 1;
                if *count == 0 {
                    groups.remove(&held.group);
                    left_group = true;
                }
            }
            if groups.is_empty() {
                self.key_groups.remove(signer);
            }
        }
        if left_group {
            self.networks_moved();
            self.tiers_moved();
        }
        if let Some(count) = self.expiries.get_mut(&held.expires_ms) {
            *count -= 1;
            if *count == 0 {
                self.expiries.remove(&held.expires_ms);
            }
        }
        self.held -= 1;
        self.ranks.remove(&cell_key);
        self.changed_cell(cell_key);
    }

    /// What `cell`'s held offers answer may have changed.
    fn changed_cell(&mut self, cell_key: u64) {
        self.version += 1;
        self.changed.insert(cell_key);
    }

    /// The tiers may have moved: every cell holding more offers than it answers with may answer
    /// with others now (`ranked_offers` keeps the top `OFFERS_PER_CELL` by tier), and the MLAT
    /// choice ranks by tier first.
    fn tiers_moved(&mut self) {
        self.version += 1;
        let crowded: Vec<u64> = self
            .cells
            .iter()
            .filter(|(_, offers)| offers.len() > OFFERS_PER_CELL)
            .map(|(cell, _)| *cell)
            .collect();
        self.changed.extend(crowded);
    }

    /// Weighs the tiers of the minute `now_ms` falls in, once a minute, for readers that follow the
    /// version: a tier that moved since the last minute moves it; tiers that stood still do not.
    fn roll_tiers(&mut self, now_ms: u64) {
        let at = now_ms - now_ms % WEIGHED_EVERY_MS;
        if at == self.rolled_at {
            return;
        }
        self.rolled_at = at;
        let keys: Vec<PublicKey> = self.evidence.keys().copied().collect();
        let mut tiers: Vec<(PublicKey, u32)> = keys
            .into_iter()
            .map(|key| (key, self.tier(&key, now_ms)))
            .filter(|(_, tier)| *tier > 0)
            .collect();
        tiers.sort();
        if tiers != self.rolled {
            self.rolled = tiers;
            self.tiers_moved();
        }
    }

    /// Forgets every offer expired at `now_ms`: nothing to do, and no scan, until the soonest
    /// expiry held is due.
    fn expire_offers(&mut self, now_ms: u64) {
        if self
            .expiries
            .first_key_value()
            .is_none_or(|(at, _)| *at > now_ms)
        {
            return;
        }
        let expired: Vec<(u64, PublicKey)> = self
            .cells
            .iter()
            .flat_map(|(cell, offers)| {
                offers
                    .iter()
                    .filter(|(_, held)| held.expires_ms <= now_ms)
                    .map(move |(key, _)| (*cell, *key))
            })
            .collect();
        for (cell, key) in expired {
            self.remove(cell, &key);
        }
    }

    /// Forgets every offer expired at `now_ms`, and the addresses no longer trusted or shunned.
    fn expire(&mut self, now_ms: u64) {
        self.apply_deferred(now_ms);
        self.expire_offers(now_ms);
        // Evidence is held for the relays whose offers are held, and for one whose offer has not
        // come for a while (its handshake under way) until its offer would have.
        let own = self.own;
        let per_key = &self.per_key;
        let mut dropped = Vec::new();
        self.evidence.retain(|key, (shown, _)| {
            let kept = Some(*key) == own
                || per_key.contains_key(key)
                || now_ms.saturating_sub(shown.issued_ms()) <= 2 * OWN_EVIDENCE_EVERY_MS;
            if !kept {
                dropped.push(*key);
            }
            kept
        });
        self.retier(dropped);
        while self
            .verified
            .first()
            .is_some_and(|(_, until)| *until <= now_ms)
        {
            self.verified.pop_first();
        }
        while self
            .unanswered
            .first()
            .is_some_and(|(_, until)| *until <= now_ms)
        {
            self.unanswered.pop_first();
        }
    }

    /// The relay's own offers, re-signed when what they declare changed (at most every
    /// `OWN_RESIGN_AT_MOST_EVERY_MS`) or every `OWN_RESIGN_EVERY_MS`, and held as its own;
    /// cells no longer taken are withdrawn. `Some` with what to gossip when re-signed.
    fn resign(
        &mut self,
        identity: &Identity,
        basis: Option<Basis>,
        now_ms: u64,
    ) -> Option<Vec<ProviderOffer>> {
        let own = identity.public();
        let changed = match (&basis, &self.own_basis) {
            (Some(new), Some(old)) => !new.same(old),
            (None, None) => false,
            _ => true,
        };
        let since = now_ms.saturating_sub(self.own_signed_ms);
        let due = since >= OWN_RESIGN_EVERY_MS;
        if !(due || changed && since >= OWN_RESIGN_AT_MOST_EVERY_MS) {
            return None;
        }
        // Withdraw whatever is no longer offered.
        let offered: HashSet<u64> = basis
            .iter()
            .flat_map(|basis| basis.cells.iter().map(|cell| cell.as_u64()))
            .collect();
        let withdrawn: Vec<u64> = self
            .cells
            .iter()
            .filter(|(cell, offers)| offers.contains_key(&own) && !offered.contains(cell))
            .map(|(cell, _)| *cell)
            .collect();
        for cell in withdrawn {
            self.remove(cell, &own);
        }
        self.own_signed_ms = now_ms;
        self.own_basis.clone_from(&basis);
        self.own_offers.clear();
        let Some(basis) = basis else {
            self.set_own_group(None, now_ms);
            return None;
        };
        let group = Group::of_address(&basis.address);
        let mut signed = Vec::new();
        for (cell, stripes) in basis.cells.iter().zip(&basis.stripes) {
            let content = ProviderOfferContent {
                address: basis.address.clone(),
                cell: *cell,
                products: basis.products,
                stripes_of: crate::sharing::stripes::STRIPES,
                stripes: *stripes,
                mlat_cores: basis.mlat_cores,
                feeder_slots: basis.feeder_slots,
                network: basis.network,
                issued_ms: now_ms,
                expires_ms: now_ms + OFFER_LIFETIME_MS,
            };
            let Ok(offer) = ProviderOffer::sign(identity, &content) else {
                continue;
            };
            self.seen.insert(offer.hash(), ());
            let Some(checked) = checked(&offer, now_ms) else {
                continue;
            };
            self.own_offers.push(checked);
            // Gossiped whether or not held here: each peer holds it by its own caps, as this
            // relay does, from the same offers.
            signed.push(offer);
        }
        // Held under the group of the address they name, as every peer holds them.
        self.set_own_group(group, now_ms);
        Some(signed)
    }

    /// The address the relay's own offers name for its advertised `address`: one named by number
    /// is itself; a host name the address it last resolved to. `true` when it is to be resolved
    /// now (never resolved, or resolved over `VERIFIED_FOR_MS` ago), and no resolution of it is
    /// under way.
    fn own_address_of(&self, address: &str, now_ms: u64) -> (Option<std::net::SocketAddr>, bool) {
        if let Ok(address) = address.parse::<std::net::SocketAddr>() {
            return (Some(address), false);
        }
        let resolved = self
            .own_resolved
            .as_ref()
            .filter(|(name, _, _)| name == address);
        let resolving = self
            .own_resolving
            .as_ref()
            .is_some_and(|(name, again_ms)| name == address && now_ms < *again_ms);
        let due = resolved.is_none_or(|(_, _, until)| *until <= now_ms);
        (
            resolved.map(|(_, resolved, _)| *resolved),
            due && !resolving,
        )
    }

    /// `address` resolved to `resolved` (none: it did not resolve, and is tried again
    /// `RESOLVE_AGAIN_MS` on, the address it last resolved to still named): the relay's own
    /// offers name it from their next signing, by the tick's clock (`own_address_of`).
    fn resolved(&mut self, address: &str, resolved: Option<std::net::SocketAddr>, now_ms: u64) {
        let Some(resolved) = resolved else {
            self.own_resolving = Some((address.to_owned(), now_ms + RESOLVE_AGAIN_MS));
            return;
        };
        if self
            .own_resolving
            .as_ref()
            .is_some_and(|(name, _)| name == address)
        {
            self.own_resolving = None;
        }
        self.own_resolved = Some((address.to_owned(), resolved, now_ms + VERIFIED_FOR_MS));
    }

    /// The relay's own offers are in `group` from now on (the group of the address they name):
    /// they leave the one they were held under and are held under this one by its caps. The
    /// relay's own network is also one no witness of its own may come from (`State::tier`), which
    /// its offers' group says.
    fn set_own_group(&mut self, group: Option<Group>, now_ms: u64) {
        if self.own_group == group {
            self.hold_own(now_ms);
            return;
        }
        self.own_group = group;
        if let Some(own) = self.own {
            let held: Vec<u64> = self
                .per_key
                .get(&own)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            for cell in held {
                self.remove(cell, &own);
            }
        }
        self.networks_moved();
        self.tiers_moved();
        self.hold_own(now_ms);
    }

    /// Holds the relay's own offers as last signed under its own group, by every cap, as a peer
    /// that verified them there holds them: one held already is left as it is. None while the
    /// group is not known.
    fn hold_own(&mut self, now_ms: u64) {
        let (Some(own), Some(group)) = (self.own, self.own_group) else {
            return;
        };
        for offer in self.own_offers.clone() {
            let content = offer.content();
            let cell = content.cell.as_u64();
            let held = self.cells.get(&cell).and_then(|offers| offers.get(&own));
            if !live(content, now_ms)
                || held
                    .is_some_and(|held| held.group == group && held.issued_ms >= content.issued_ms)
            {
                continue;
            }
            if held.is_some_and(|held| held.group != group) {
                self.remove(cell, &own);
            }
            self.hold(offer, group, now_ms);
        }
    }
}

/// How many of `given_up` are under `cap` for `newcomer`: already counted out of it.
fn given_up_under(
    state: &State,
    cap: Cap,
    (cell, signer, group): (u64, PublicKey, Group),
    given_up: &[(u64, PublicKey)],
) -> usize {
    given_up
        .iter()
        .filter(|(held_cell, key)| {
            let held = state
                .cells
                .get(held_cell)
                .and_then(|offers| offers.get(key));
            match cap {
                Cap::GroupInCell => {
                    *held_cell == cell && held.is_some_and(|held| held.group == group)
                }
                Cap::Cell => *held_cell == cell,
                Cap::Group => held.is_some_and(|held| held.group == group),
                Cap::Key => *key == signer,
                Cap::Held => true,
            }
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tally_wire::Location;
    use tally_wire::rendezvous::area_of;
    use tokio::net::TcpListener;

    type Result = std::result::Result<(), String>;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    const NOW: u64 = 1_800_000_000_000;

    fn area() -> std::result::Result<Region, String> {
        area_of(&Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)
    }

    fn content(address: &str, cell: Region, issued_ms: u64) -> ProviderOfferContent {
        ProviderOfferContent {
            address: address.to_owned(),
            cell,
            products: Streams::RAW.with(Streams::POSITIONS),
            stripes_of: 1,
            stripes: 1,
            mlat_cores: 8,
            feeder_slots: 10,
            network: 64_500,
            issued_ms,
            expires_ms: issued_ms + 10 * 60 * 1000,
        }
    }

    fn sign(
        relay: &Identity,
        content: &ProviderOfferContent,
    ) -> std::result::Result<ProviderOffer, String> {
        ProviderOffer::sign(relay, content).map_err(text)
    }

    fn relay_asker(key: PublicKey) -> Asker {
        Asker {
            role: AskerRole::Relay,
            key,
            source: 1,
            loopback: false,
        }
    }

    fn v4(a: u8, b: u8) -> Group {
        Group::of(IpAddr::V4(Ipv4Addr::new(a, b, 1, 1)))
    }

    /// A Noise responder on loopback answering as `identities`, for as long as the test runs.
    async fn answering(identities: Vec<Identity>) -> std::result::Result<String, String> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let address = listener.local_addr().map_err(text)?.to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let identities = identities.clone();
                tokio::spawn(async move {
                    if let Ok(accepted) = noise::accept(stream, &identities).await {
                        // Hold the session a moment, as a relay would.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        drop(accepted);
                    }
                });
            }
        });
        Ok(address)
    }

    #[tokio::test]
    async fn an_offer_is_held_and_gossiped_only_once_its_address_answers_as_its_key() -> Result {
        let local = Identity::generate().map_err(text)?;
        let honest = Identity::generate().map_err(text)?;
        let impostor = Identity::generate().map_err(text)?;
        let honest_at = answering(vec![honest.clone()]).await?;
        // The impostor's address answers, but as another key.
        let impostor_at = answering(vec![Identity::generate().map_err(text)?]).await?;
        let directory = Directory::new();
        let cell = area()?;
        let good = sign(&honest, &content(&honest_at, cell, NOW))?;
        let lying = sign(&impostor, &content(&impostor_at, cell, NOW))?;
        directory.offered(&relay_asker(honest.public()), good.clone(), NOW);
        directory.offered(&relay_asker(honest.public()), lying.clone(), NOW);
        assert!(directory.is_empty(), "nothing held before the handshake");
        directory.verify_pending(&local, NOW).await;
        assert_eq!(directory.offers_for(cell, NOW), vec![good.clone()]);
        // Gossiped once, at the next tick; a second offer of the same bytes is not acted on.
        let gossip = directory.state.lock().map_err(text)?.gossip.clone();
        assert_eq!(gossip, vec![good.clone()]);
        directory.state.lock().map_err(text)?.gossip.clear();
        directory.offered(&relay_asker(honest.public()), good, NOW);
        assert!(directory.state.lock().map_err(text)?.gossip.is_empty());
        // The impostor's address is not dialled again for a while, even for a new offer.
        let again = sign(&impostor, &content(&impostor_at, cell, NOW + 1))?;
        directory.offered(&relay_asker(honest.public()), again, NOW + 1);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // A re-signed offer from a key already verified there is held without a dial.
        let renewed = sign(&honest, &content(&honest_at, cell, NOW + 60_000))?;
        directory.offered(&relay_asker(honest.public()), renewed.clone(), NOW + 60_000);
        assert_eq!(directory.offers_for(cell, NOW + 60_000), vec![renewed]);
        Ok(())
    }

    #[tokio::test]
    async fn a_forged_an_expired_and_an_unanswering_offer_are_not_held() -> Result {
        let local = Identity::generate().map_err(text)?;
        let relay = Identity::generate().map_err(text)?;
        let at = answering(vec![relay.clone()]).await?;
        let directory = Directory::new();
        let cell = area()?;
        let asker = relay_asker(relay.public());
        // Forged: one byte of the signed body changed.
        let good = sign(&relay, &content(&at, cell, NOW))?;
        let mut bytes = good.as_bytes().to_vec();
        let at_byte = bytes.len() - 70;
        bytes[at_byte] ^= 1;
        let forged = ProviderOffer::from_bytes(bytes).map_err(text)?;
        directory.offered(&asker, forged, NOW);
        // Expired by this relay's clock, and issued too far in the future.
        let old = sign(&relay, &content(&at, cell, NOW - 20 * 60 * 1000))?;
        directory.offered(&asker, old, NOW);
        let future = sign(&relay, &content(&at, cell, NOW + 2 * CLOCK_SKEW_MS))?;
        directory.offered(&asker, future, NOW);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // Nobody listening at the address.
        let closed = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let nowhere = closed.local_addr().map_err(text)?.to_string();
        drop(closed);
        let silent = Identity::generate().map_err(text)?;
        directory.offered(
            &relay_asker(silent.public()),
            sign(&silent, &content(&nowhere, cell, NOW))?,
            NOW,
        );
        directory.verify_pending(&local, NOW).await;
        assert!(directory.is_empty());
        // An offer expires while held.
        directory.offered(&asker, good, NOW);
        directory.verify_pending(&local, NOW).await;
        assert_eq!(directory.len(), 1);
        directory
            .state
            .lock()
            .map_err(text)?
            .expire(NOW + 10 * 60 * 1000);
        assert!(directory.is_empty());
        Ok(())
    }

    /// A bundle of `relay`'s receipts, one from each child, each for `bytes_per_sec` delivered.
    fn evidence_of(
        relay: &Identity,
        children: &[Identity],
        bytes_per_sec: u64,
    ) -> std::result::Result<EvidenceBundle, String> {
        let cell = area()?;
        let receipts = children
            .iter()
            .map(|child| {
                tally_wire::StripeReceipt::sign(
                    child,
                    &tally_wire::StripeReceiptContent {
                        parent: relay.public(),
                        cell,
                        product: Streams::RAW,
                        stripe: 0,
                        stripes_of: 4,
                        first_second: 100,
                        last_second: 159,
                        records: 900,
                        bytes: bytes_per_sec * 60,
                        digest: [7; 32],
                        issued_ms: NOW,
                    },
                )
                .map_err(text)
            })
            .collect::<std::result::Result<Vec<_>, String>>()?;
        EvidenceBundle::sign(
            relay,
            &tally_wire::EvidenceBundleContent {
                issued_ms: NOW,
                feeders: Vec::new(),
                receipts,
                answers: Vec::new(),
            },
        )
        .map_err(text)
    }

    /// One arrival at a directory, in a test that holds the same arrivals in different orders.
    type Step = Box<dyn Fn(&Directory) -> Result>;

    /// RFC-0174 §2.6, a cell's held offers ranked by contribution first: honest relays whose
    /// children (relays verified on networks of their own) signed receipts for what they
    /// delivered are never displaced by keys ground to rank high by rendezvous and showing no
    /// evidence, however many, from however many networks; nor by keys whose only evidence is
    /// receipts from children no relay verified (free keys), or from one network. And the same
    /// offers and evidence, held in any order, give the same held set.
    #[test]
    fn honest_relays_with_receipts_are_never_displaced_by_ground_keys() -> Result {
        let cell = area()?;
        let honest: Vec<Identity> = (0..6)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;
        // Each honest relay's two children, relays with verified offers on networks of their own.
        let children: Vec<Vec<Identity>> = (0..honest.len())
            .map(|_| {
                (0..2)
                    .map(|_| Identity::generate().map_err(text))
                    .collect::<std::result::Result<Vec<_>, _>>()
            })
            .collect::<std::result::Result<_, _>>()?;
        let elsewhere = area_of(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        // Ground keys: more than the cell holds, each from a network of its own, the half of them
        // with receipts from free keys or from children on one network.
        let ground: Vec<Identity> = (0..3 * OFFERS_PER_CELL)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;
        let free: Vec<Identity> = (0..4)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;
        let one_network: Vec<Identity> = (0..4)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;

        let held_set = |reversed: bool| -> std::result::Result<Vec<PublicKey>, String> {
            let directory = Directory::new();
            let mut steps: Vec<Step> = Vec::new();
            for (at, (child_set, relay)) in children.iter().zip(&honest).enumerate() {
                for (index, child) in child_set.iter().enumerate() {
                    let child = child.clone();
                    steps.push(Box::new(move |directory: &Directory| {
                        let offer = sign(&child, &content("child.example:1", elsewhere, NOW))?;
                        directory.hold_verified(offer, v4(20 + at as u8, index as u8), NOW)?;
                        Ok(())
                    }));
                }
                let relay = relay.clone();
                let child_set = child_set.clone();
                steps.push(Box::new(move |directory: &Directory| {
                    let offer = sign(&relay, &content("honest.example:1", cell, NOW))?;
                    directory.hold_verified(offer, v4(10, at as u8), NOW)?;
                    directory.evidence(&evidence_of(&relay, &child_set, 10_000)?, NOW);
                    Ok(())
                }));
            }
            for (index, child) in one_network.iter().enumerate() {
                let child = child.clone();
                steps.push(Box::new(move |directory: &Directory| {
                    let offer = sign(&child, &content("one.example:1", elsewhere, NOW))?;
                    // Every one of them on one network.
                    directory.hold_verified(offer, v4(30, 0), NOW + index as u64)?;
                    Ok(())
                }));
            }
            for (index, key) in ground.iter().enumerate() {
                let key = key.clone();
                let free = free.clone();
                let one_network = one_network.clone();
                steps.push(Box::new(move |directory: &Directory| {
                    let offer = sign(&key, &content("ground.example:1", cell, NOW))?;
                    directory.hold_verified(
                        offer,
                        v4(100 + (index / 200) as u8, index as u8),
                        NOW,
                    )?;
                    match index % 3 {
                        0 => {}
                        1 => {
                            directory.evidence(&evidence_of(&key, &free, 1_000_000)?, NOW);
                        }
                        _ => {
                            directory.evidence(&evidence_of(&key, &one_network, 1_000_000)?, NOW);
                        }
                    }
                    Ok(())
                }));
            }
            if reversed {
                steps.reverse();
            }
            for step in &steps {
                step(&directory)?;
            }
            // A relay re-signs its offers each minute (`OWN_RESIGN_EVERY_MS`): one round of that,
            // in the same order, and each offer refused while its evidence had not come is
            // weighed again with it.
            let mut resigned: Vec<(&Identity, &str, Group)> = honest
                .iter()
                .enumerate()
                .map(|(at, relay)| (relay, "honest.example:1", v4(10, at as u8)))
                .chain(ground.iter().enumerate().map(|(index, key)| {
                    (
                        key,
                        "ground.example:1",
                        v4(100 + (index / 200) as u8, index as u8),
                    )
                }))
                .collect();
            if reversed {
                resigned.reverse();
            }
            for (key, address, group) in resigned {
                let offer = sign(key, &content(address, cell, NOW + 1))?;
                directory.hold_verified(offer, group, NOW + 1)?;
            }
            Ok(directory
                .offers_for(cell, NOW + 2)
                .iter()
                .map(Checked::signer)
                .collect())
        };
        let forwards = held_set(false)?;
        assert!(forwards.len() <= OFFERS_PER_CELL);
        // Every honest relay is held, and ranks above every ground key.
        let honest_keys: Vec<PublicKey> = honest.iter().map(Identity::public).collect();
        assert_eq!(
            forwards[..honest.len()]
                .iter()
                .copied()
                .collect::<HashSet<_>>(),
            honest_keys.iter().copied().collect::<HashSet<_>>(),
        );
        // A ground key's free children count nothing, and its children on one network, however
        // many and whatever rate they sign, are one witness: below the honest relays' two.
        let one = Directory::new();
        for (index, child) in one_network.iter().enumerate() {
            let offer = sign(child, &content("one.example:1", elsewhere, NOW))?;
            one.hold_verified(offer, v4(30, 0), NOW + index as u64)?;
        }
        let witness = &ground[2];
        one.hold_verified(
            sign(witness, &content("ground.example:1", cell, NOW))?,
            v4(99, 0),
            NOW,
        )?;
        one.evidence(&evidence_of(witness, &one_network, 1_000_000)?, NOW);
        assert_eq!(one.tier_of(&witness.public(), NOW), tier(1));
        assert_eq!(tier(1), 1);
        // The same evidence, held in the opposite order: the same set, in the same order.
        assert_eq!(held_set(true)?, forwards);
        Ok(())
    }

    /// RFC-0174 §2.3 by contribution: an area's MLAT relays are the evidenced relays, however many
    /// keys name every core there is from however many networks; with no evidence anywhere (a new
    /// network) the cores decide, as before, and those keys win.
    #[test]
    fn ground_keys_with_many_cores_never_displace_evidenced_mlat_relays() -> Result {
        let cell = area()?;
        let elsewhere = area_of(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        let honest: Vec<Identity> = (0..4)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;
        let children: Vec<Identity> = (0..2)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;
        let ground: Vec<Identity> = (0..200)
            .map(|_| Identity::generate().map_err(text))
            .collect::<std::result::Result<_, _>>()?;
        let build = |evidenced: bool| -> std::result::Result<Vec<PublicKey>, String> {
            let directory = Directory::new();
            for (index, child) in children.iter().enumerate() {
                let offer = sign(child, &content("child.example:1", elsewhere, NOW))?;
                directory.hold_verified(offer, v4(20, index as u8), NOW)?;
            }
            for (at, relay) in honest.iter().enumerate() {
                // One core each: the least a relay offering MLAT can name.
                let mut offered = content("honest.example:1", cell, NOW);
                offered.mlat_cores = 1;
                directory.hold_verified(sign(relay, &offered)?, v4(10, at as u8), NOW)?;
                if evidenced {
                    directory.evidence(&evidence_of(relay, &children, 10_000)?, NOW);
                }
            }
            for (index, key) in ground.iter().enumerate() {
                let mut lure = content("ground.example:1", cell, NOW);
                lure.mlat_cores = u16::MAX;
                directory.hold_verified(
                    sign(key, &lure)?,
                    v4(100 + (index / 200) as u8, index as u8),
                    NOW,
                )?;
            }
            Ok(crate::selection::mlat_relays(cell, &directory, NOW))
        };
        let honest_keys: HashSet<PublicKey> = honest.iter().map(Identity::public).collect();
        let chosen = build(true)?;
        assert_eq!(chosen.len(), rendezvous::MLAT_RELAYS_PER_AREA);
        assert!(
            chosen.iter().all(|key| honest_keys.contains(key)),
            "{chosen:?}"
        );
        // No witness anywhere: the cores decide, and 64 cores beat one.
        let fresh = build(false)?;
        assert!(
            fresh.iter().all(|key| !honest_keys.contains(key)),
            "{fresh:?}"
        );
        Ok(())
    }

    /// RFC-0174 §2.6, liveness: an offer is held for `OFFER_LIFETIME_MS` from its signing at most,
    /// whatever lifetime it claims, so a relay that died leaves every directory then.
    #[test]
    fn an_offer_is_held_three_minutes_at_most_whatever_it_claims() -> Result {
        let relay = Identity::generate().map_err(text)?;
        let cell = area()?;
        let directory = Directory::new();
        // It claims ten minutes.
        let offer = sign(&relay, &content("relay.example:1", cell, NOW))?;
        directory.hold_verified(offer, v4(1, 1), NOW)?;
        let held = |at: u64| !directory.offers_for(cell, at).is_empty();
        assert!(held(NOW + OFFER_LIFETIME_MS - 1));
        assert!(!held(NOW + OFFER_LIFETIME_MS));
        assert_eq!(OFFER_LIFETIME_MS, 3 * OWN_RESIGN_EVERY_MS);
        Ok(())
    }

    #[test]
    fn only_a_relay_carries_offers_it_did_not_sign_and_own_offers_are_not_reflected() -> Result {
        let directory = Directory::new();
        let own = Identity::generate().map_err(text)?;
        let other = Identity::generate().map_err(text)?;
        directory.adopt_own_key(own.public());
        let cell = area()?;
        let offer = sign(&other, &content("192.0.2.7:7450", cell, NOW))?;
        let client = Asker {
            role: AskerRole::Client,
            key: Identity::generate().map_err(text)?.public(),
            source: 2,
            loopback: false,
        };
        directory.offered(&client, offer.clone(), NOW);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // The relay's own offer, come back round a gossip loop.
        let mine = sign(&own, &content("192.0.2.8:7450", cell, NOW))?;
        directory.offered(&relay_asker(other.public()), mine, NOW);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // A client announcing its own offer is queued.
        let announcing = Asker {
            key: other.public(),
            ..client
        };
        let fresh = sign(&other, &content("192.0.2.7:7450", cell, NOW + 1))?;
        directory.offered(&announcing, fresh, NOW + 1);
        assert_eq!(directory.state.lock().map_err(text)?.pending.len(), 1);
        Ok(())
    }

    #[test]
    fn the_caps_hold_under_a_flood_of_keys() -> Result {
        let directory = Directory::new();
        let cell = area()?;
        // A flood from one network group: at most its share of the cell.
        for seed in 0..100_u32 {
            let mut bytes = [9; 32];
            bytes[..4].copy_from_slice(&seed.to_be_bytes());
            let key = Identity::from_seed(bytes);
            let offer = sign(&key, &content("flood.example:1", cell, NOW))?;
            directory.hold_verified(offer, v4(10, 0), NOW)?;
        }
        assert_eq!(directory.len(), OFFERS_PER_GROUP_IN_CELL);
        // From many groups: the cell holds at most its cap.
        for seed in 0..400_u32 {
            let mut bytes = [7; 32];
            bytes[..4].copy_from_slice(&seed.to_be_bytes());
            let key = Identity::from_seed(bytes);
            let offer = sign(&key, &content("flood.example:1", cell, NOW))?;
            directory.hold_verified(offer, v4(11, seed as u8), NOW)?;
        }
        assert_eq!(directory.offers_for(cell, NOW).len(), OFFERS_PER_CELL);
        // One key over many cells: at most its cap.
        let busy = Identity::generate().map_err(text)?;
        let state = Region::containing(
            &Location {
                lat_e7: 515_000_000,
                lon_e7: -1_200_000,
                alt_m: 0,
                precision_m: 0,
            },
            1,
        )
        .map_err(text)?;
        let continent = state.ancestor(0).ok_or("no base cell")?;
        let cells = rendezvous::areas_of(continent).map_err(text)?;
        assert!(cells.len() > OFFERS_PER_KEY);
        let mut held = 0;
        for (index, cell) in cells.iter().cycle().take(400).enumerate() {
            let content = content("busy.example:1", *cell, NOW + index as u64);
            if directory.hold_verified(sign(&busy, &content)?, v4(12, (index % 200) as u8), NOW)? {
                held += 1;
            }
        }
        let state = directory.state.lock().map_err(text)?;
        assert!(state.per_key.get(&busy.public()).map_or(0, HashSet::len) <= OFFERS_PER_KEY);
        assert!(held >= cells.len().min(OFFERS_PER_KEY));
        assert!(state.held <= OFFERS_HELD);
        Ok(())
    }

    #[test]
    fn a_flood_from_a_few_networks_displaces_only_itself() -> Result {
        let directory = Directory::new();
        let cell = area()?;
        // Seven honest relays, each on a network of its own.
        let honest: Vec<Identity> = (0..7_u8)
            .map(|seed| Identity::from_seed([seed + 100; 32]))
            .collect();
        for (relay, index) in honest.iter().zip(0_u8..) {
            let offer = sign(relay, &content("honest.example:1", cell, NOW))?;
            assert!(directory.hold_verified(offer, v4(1, index), NOW)?);
        }
        // An attacker with 1,000 keys from two networks, each offer with every MLAT core it can
        // name.
        for seed in 0..1_000_u32 {
            let mut bytes = [5; 32];
            bytes[..4].copy_from_slice(&seed.to_be_bytes());
            let attacker = Identity::from_seed(bytes);
            let mut lure = content("attacker.example:1", cell, NOW);
            lure.mlat_cores = u16::MAX;
            directory.hold_verified(sign(&attacker, &lure)?, v4(200, (seed % 2) as u8), NOW)?;
        }
        let held = directory.offers_for(cell, NOW);
        assert_eq!(held.len(), honest.len() + 2 * OFFERS_PER_GROUP_IN_CELL);
        for relay in &honest {
            assert!(
                held.iter().any(|offer| offer.signer() == relay.public()),
                "an honest relay was displaced"
            );
        }
        // The MLAT choice still ranks every relay held, each counted for at most
        // `MLAT_CORES_COUNTED` cores whatever it names.
        let chosen = crate::selection::mlat_relays(cell, &directory, NOW);
        assert_eq!(chosen.len(), rendezvous::MLAT_RELAYS_PER_AREA);
        Ok(())
    }

    /// The areas under the base cells round Atlanta and London: 686 cells to spread offers over.
    fn many_cells() -> std::result::Result<Vec<Region>, String> {
        let mut cells = Vec::new();
        for (lat_e7, lon_e7) in [(337_490_000, -843_880_000), (515_000_000, -1_200_000)] {
            let base = Region::containing(
                &Location {
                    lat_e7,
                    lon_e7,
                    alt_m: 0,
                    precision_m: 0,
                },
                0,
            )
            .map_err(text)?;
            cells.extend(rendezvous::areas_of(base).map_err(text)?);
        }
        Ok(cells)
    }

    /// An offer of `key` for `cell`, as the cap tests hold it (`Directory::hold_unsigned`).
    type Unsigned = (PublicKey, ProviderOfferContent, Group);

    /// Every offer held after `offers` are held in `order`, as (cell, key), sorted.
    fn held_after(
        offers: &[Unsigned],
        order: impl Iterator<Item = usize>,
    ) -> std::result::Result<Vec<(u64, PublicKey)>, String> {
        let stand_in = sign(
            &Identity::from_seed([1; 32]),
            &content("s.example:1", area()?, NOW),
        )?;
        let directory = Directory::new();
        for index in order {
            let (key, content, group) = &offers[index];
            directory.hold_unsigned(&stand_in, *key, content.clone(), *group, NOW);
        }
        let state = directory.state.lock().map_err(text)?;
        let mut held: Vec<(u64, PublicKey)> = state
            .cells
            .iter()
            .flat_map(|(cell, offers)| offers.keys().map(move |key| (*cell, *key)))
            .collect();
        held.sort();
        Ok(held)
    }

    /// Each order `offers` may come in: as listed, reversed, and shuffled.
    fn orders(len: usize) -> [Vec<usize>; 3] {
        [
            (0..len).collect(),
            (0..len).rev().collect(),
            (0..len).map(|index| (index * 7919) % len).collect(),
        ]
    }

    fn key_of(salt: u8, index: u64) -> PublicKey {
        let mut seed = [salt; 32];
        seed[..8].copy_from_slice(&index.to_be_bytes());
        Identity::from_seed(seed).public()
    }

    /// Item 3 of the sweep: a full cap over many cells (a network group's, a key's) gives up the
    /// lowest-ranked offer under it for a newcomer that outranks it, never "full, refused" by
    /// arrival, so the set held is the same whatever order the offers came in.
    #[test]
    fn a_groups_and_a_keys_cap_keep_the_same_offers_whatever_the_arrival_order() -> Result {
        let cells = many_cells()?;
        let over = OFFERS_PER_GROUP + 44;
        assert!(cells.len() >= over);
        // One network, a key of its own in each cell.
        let one_group: Vec<Unsigned> = (0..over)
            .map(|index| {
                (
                    key_of(21, index as u64),
                    content("g.example:1", cells[index], NOW),
                    v4(60, 0),
                )
            })
            .collect();
        // One key, in each cell from a network of its own.
        let busy = key_of(22, 0);
        let one_key: Vec<Unsigned> = (0..over)
            .map(|index| {
                (
                    busy,
                    content("k.example:1", cells[index], NOW),
                    v4(61 + (index / 250) as u8, index as u8),
                )
            })
            .collect();
        for (offers, cap) in [(&one_group, OFFERS_PER_GROUP), (&one_key, OFFERS_PER_KEY)] {
            let [forward, backward, shuffled] = orders(offers.len());
            let first = held_after(offers, forward.into_iter())?;
            assert_eq!(first.len(), cap);
            assert_eq!(held_after(offers, backward.into_iter())?, first);
            assert_eq!(held_after(offers, shuffled.into_iter())?, first);
        }
        Ok(())
    }

    /// Item 3 of the sweep: the directory's own bound (`OFFERS_HELD`) gives up the lowest-ranked
    /// offer anywhere, the same set whatever the order.
    #[test]
    fn the_directorys_bound_keeps_the_same_offers_whatever_the_arrival_order() -> Result {
        let cells = many_cells()?;
        // Keys of a network of their own, each in as many cells as a key may hold, spread so no
        // cell holds more than 24: only the directory's bound binds.
        let keys = (OFFERS_HELD / OFFERS_PER_KEY + 1) as u64;
        let offers: Vec<Unsigned> = (0..keys)
            .flat_map(|index| {
                let key = key_of(23, index);
                let cells = &cells;
                (0..OFFERS_PER_KEY).map(move |at| {
                    let spread = index as usize * cells.len() / keys as usize;
                    let cell = cells[(spread + at) % cells.len()];
                    (
                        key,
                        content("h.example:1", cell, NOW),
                        v4(100 + (index / 200) as u8, index as u8),
                    )
                })
            })
            .collect();
        assert!(offers.len() > OFFERS_HELD);
        let [forward, backward, shuffled] = orders(offers.len());
        let first = held_after(&offers, forward.into_iter())?;
        assert_eq!(first.len(), OFFERS_HELD);
        assert_eq!(held_after(&offers, backward.into_iter())?, first);
        assert_eq!(held_after(&offers, shuffled.into_iter())?, first);
        Ok(())
    }

    /// Item 4 of the sweep: a peer re-signing changed offers in a loop changes what its readers
    /// see at most once per `CHANGED_AT_MOST_EVERY_MS` per (key, cell); the newest change waiting
    /// is held when its turn comes, and a re-signing that changes nothing is held at once.
    #[test]
    fn a_peer_re_signing_changes_in_a_loop_costs_its_readers_once_a_turn() -> Result {
        let relay = Identity::from_seed([31; 32]);
        let cell = area()?;
        let directory = Directory::new();
        let first = sign(&relay, &content("r.example:1", cell, NOW))?;
        assert!(directory.hold_verified(first, v4(1, 1), NOW)?);
        assert_eq!(directory.take_changed_cells(NOW), vec![cell]);
        let version = directory.version(NOW);
        let mut newest = None;
        for step in 1..=200_u64 {
            let mut changed = content("r.example:1", cell, NOW + step);
            // Never the 8 cores first held: each says something new.
            changed.mlat_cores = (step % 60) as u16 + 9;
            let offer = sign(&relay, &changed)?;
            // Every 10 ms: deferred, and no reader is told.
            assert!(!directory.hold_verified(offer.clone(), v4(1, 1), NOW + step * 10)?);
            newest = Some(offer);
        }
        assert_eq!(directory.version(NOW + 2_000), version);
        assert!(directory.take_changed_cells(NOW + 2_000).is_empty());
        // Its turn: the newest change is held, told once, and gossiped once.
        let due = NOW + CHANGED_AT_MOST_EVERY_MS;
        directory.state.lock().map_err(text)?.expire(due);
        let newest = newest.ok_or("no change")?;
        assert_eq!(directory.offers_for(cell, due), vec![newest.clone()]);
        assert_eq!(directory.take_changed_cells(due), vec![cell]);
        assert_eq!(
            directory.state.lock().map_err(text)?.gossip,
            vec![newest.clone()]
        );
        // A re-signing saying the same, its turn come (`RESIGNED_AT_MOST_EVERY_MS` by the signed
        // times), is held at once, and tells no reader.
        let mut same = newest.content().map_err(text)?;
        same.issued_ms += RESIGNED_AT_MOST_EVERY_MS;
        let quiet = sign(&relay, &same)?;
        assert!(directory.hold_verified(quiet.clone(), v4(1, 1), due + 1)?);
        assert_eq!(directory.offers_for(cell, due + 1), vec![quiet]);
        assert!(directory.take_changed_cells(due + 1).is_empty());
        // And the next change waits its turn from the last.
        let mut later = same.clone();
        later.issued_ms += 1;
        later.mlat_cores = 99;
        assert!(!directory.hold_verified(sign(&relay, &later)?, v4(1, 1), due + 2)?);
        Ok(())
    }

    #[test]
    fn the_held_set_is_the_top_of_the_ranking_whatever_the_arrival_order() -> Result {
        let cell = area()?;
        // 150 relays over 25 networks of six each: both the cell's cap and each network's share
        // of it bind.
        let relays: Vec<(Identity, Group)> = (0..150_u32)
            .map(|seed| {
                let mut bytes = [3; 32];
                bytes[..4].copy_from_slice(&seed.to_be_bytes());
                (Identity::from_seed(bytes), v4(20, (seed / 6) as u8))
            })
            .collect();
        let offers: Vec<(ProviderOffer, Group)> = relays
            .iter()
            .map(|(relay, group)| Ok((sign(relay, &content("r.example:1", cell, NOW))?, *group)))
            .collect::<std::result::Result<_, String>>()?;
        let held_in = |order: &[usize]| -> std::result::Result<Vec<PublicKey>, String> {
            let directory = Directory::new();
            for index in order {
                let (offer, group) = &offers[*index];
                directory.hold_verified(offer.clone(), *group, NOW)?;
            }
            let mut keys: Vec<PublicKey> = directory
                .offers_for(cell, NOW)
                .iter()
                .map(Checked::signer)
                .collect();
            keys.sort();
            Ok(keys)
        };
        let forward: Vec<usize> = (0..offers.len()).collect();
        let backward: Vec<usize> = forward.iter().rev().copied().collect();
        let shuffled: Vec<usize> = (0..offers.len()).map(|i| (i * 67) % 150).collect();
        let first = held_in(&forward)?;
        assert_eq!(first, held_in(&backward)?);
        assert_eq!(first, held_in(&shuffled)?);
        // And it is the greedy top of the ranking: best first, each network up to its share.
        let group_of: HashMap<PublicKey, Group> = relays
            .iter()
            .map(|(relay, group)| (relay.public(), *group))
            .collect();
        let mut taken: HashMap<Group, usize> = HashMap::new();
        let mut expected = Vec::new();
        for key in ranked(cell, relays.iter().map(|(relay, _)| (relay.public(), 0))) {
            let share = taken.entry(group_of[&key]).or_insert(0);
            if *share < OFFERS_PER_GROUP_IN_CELL && expected.len() < OFFERS_PER_CELL {
                *share += 1;
                expected.push(key);
            }
        }
        expected.sort();
        assert_eq!(first, expected);
        Ok(())
    }

    #[test]
    fn a_withdrawn_cell_is_offered_with_no_stripes() -> Result {
        let identity = Identity::generate().map_err(text)?;
        let hub = Hub::new(8).advertising(vec![tally_wire::RelayAddress {
            key: identity.public(),
            address: "me.example:7450".to_owned(),
        }]);
        let cell = area()?;
        hub.network().selection.set_taken(vec![cell]);
        let sharing = &hub.network().sharing;
        assert_ne!(forwarded_stripes(sharing, cell, &identity.public()), 0);
        // The egress sheds a forwarding peer: the relay withdraws its one region.
        let _ = sharing.tick_shed(&hub, Some(&identity), 0, NOW);
        let _ = sharing.tick_shed(&hub, Some(&identity), 1, NOW + 1_000);
        assert!(sharing.withdrawn(cell));
        assert_eq!(forwarded_stripes(sharing, cell, &identity.public()), 0);
        Ok(())
    }

    #[test]
    fn a_query_returns_the_ancestors_offers_too() -> Result {
        let directory = Directory::new();
        let cell = area()?;
        let point = Region::point(&Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        let path = rendezvous::ancestors(point).map_err(text)?;
        let parent = path[path.len() - 2];
        let finer = path[5];
        let relays: Vec<Identity> = (0..3_u8)
            .map(|seed| Identity::from_seed([seed + 40; 32]))
            .collect();
        let offers = [
            sign(&relays[0], &content("a.example:1", cell, NOW))?,
            sign(&relays[1], &content("b.example:1", parent, NOW))?,
            sign(&relays[2], &content("c.example:1", finer, NOW))?,
        ];
        for (offer, index) in offers.iter().zip(0_u8..) {
            directory.hold_verified(offer.clone(), v4(2, index), NOW)?;
        }
        let answer = directory.query(
            &ProviderQuery {
                cell,
                products: Streams(0),
            },
            NOW,
        );
        // The cell's own and its parent's, finest first; not the finer cell's.
        assert_eq!(answer, vec![offers[0].clone(), offers[1].clone()]);
        assert_eq!(directory.offers_for(cell, NOW), answer);
        // Products filter.
        let none = directory.query(
            &ProviderQuery {
                cell,
                products: Streams::WORLD,
            },
            NOW,
        );
        assert!(none.is_empty());
        // Expired ones are not answered.
        assert!(
            directory
                .query(
                    &ProviderQuery {
                        cell,
                        products: Streams(0),
                    },
                    NOW + 11 * 60 * 1000,
                )
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn the_relay_offers_what_it_takes_re_signs_and_withdraws() -> Result {
        let identity = Identity::generate().map_err(text)?;
        let hub = Hub::new(8).advertising(vec![tally_wire::RelayAddress {
            key: identity.public(),
            address: "198.51.100.7:7450".to_owned(),
        }]);
        let cell = area()?;
        hub.network().selection.set_taken(vec![cell]);
        hub.network().admission.configure(64_496, true);
        let directory = Directory::new();
        let published = directory.tick(&hub, Some(&identity), NOW);
        // Its offer, and its evidence beside it, by which every relay ranks the offer.
        let [
            Record::ProviderOffer(offer),
            Record::EvidenceBundle(evidence),
        ] = &published[..]
        else {
            return Err(format!("published {published:?}"));
        };
        offer.verify().map_err(text)?;
        assert_eq!(evidence.signer().map_err(text)?, identity.public());
        assert_eq!(directory.live_evidence(), vec![evidence.clone()]);
        let declared = offer.content().map_err(text)?;
        assert_eq!(declared.cell, cell);
        assert_eq!(declared.address, "198.51.100.7:7450");
        assert_eq!(declared.network, 64_496);
        assert_eq!(declared.expires_ms, NOW + OFFER_LIFETIME_MS);
        assert!(declared.products.contains(Streams::RAW));
        assert_eq!(directory.own_key(), Some(identity.public()));
        assert_eq!(directory.offers_for(cell, NOW), vec![offer.clone()]);
        // Nothing new a moment later; re-signed a minute on, its evidence not yet again.
        assert!(
            directory
                .tick(&hub, Some(&identity), NOW + 1_000)
                .is_empty()
        );
        let half = NOW + OWN_RESIGN_EVERY_MS;
        assert_eq!(directory.tick(&hub, Some(&identity), half).len(), 1);
        // Its relay duties turned off, it hosts no feeders: its offers no longer say raw, so no
        // MLAT relay dials it for raw it does not have.
        hub.network().admission.configure(64_496, false);
        let resigned = directory.tick(&hub, Some(&identity), half + OWN_RESIGN_AT_MOST_EVERY_MS);
        let [Record::ProviderOffer(without)] = &resigned[..] else {
            return Err(format!("published {resigned:?}"));
        };
        let products = without.content().map_err(text)?.products;
        assert!(!products.contains(Streams::RAW));
        assert!(products.contains(Streams::POSITIONS));
        // An area no longer taken is withdrawn.
        let half = half + OWN_RESIGN_AT_MOST_EVERY_MS;
        hub.network().selection.set_taken(Vec::new());
        assert!(
            directory
                .tick(&hub, Some(&identity), half + OWN_RESIGN_AT_MOST_EVERY_MS)
                .is_empty()
        );
        assert!(directory.is_empty());
        Ok(())
    }

    /// A relay at `address` taking `cell`, its duties on.
    fn own_relay(identity: &Identity, address: &str, cell: Region) -> Hub {
        let hub = Hub::new(8).advertising(vec![tally_wire::RelayAddress {
            key: identity.public(),
            address: address.to_owned(),
        }]);
        hub.network().selection.set_taken(vec![cell]);
        hub.network().admission.configure(64_496, true);
        hub
    }

    /// The signers held for `cell`, sorted.
    fn held_keys(directory: &Directory, cell: Region, now_ms: u64) -> Vec<PublicKey> {
        let mut keys: Vec<PublicKey> = directory
            .offers_for(cell, now_ms)
            .iter()
            .map(Checked::signer)
            .collect();
        keys.sort();
        keys
    }

    /// Sweep 3, N6: the relay's own offer is held under the group of the address it advertises
    /// and by every cap, as its peers hold it. Its network already holds a group's share of the
    /// cell in peers' offers: the relay holds exactly what a peer that verified the same offers
    /// holds (the top of the ranking of the five, four of them), never its own beside all four.
    #[test]
    fn the_relays_own_offer_is_held_by_its_networks_caps_as_its_peers_hold_it() -> Result {
        let cell = area()?;
        let identity = Identity::from_seed([71; 32]);
        let hub = own_relay(&identity, "198.51.100.7:7450", cell);
        let mine = Directory::new();
        let published = mine.tick(&hub, Some(&identity), NOW);
        let Some(Record::ProviderOffer(own)) = published.first() else {
            return Err(format!("published {published:?}"));
        };
        let group = Group::of(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
        let peer = Directory::new();
        peer.hold_verified(own.clone(), group, NOW)?;
        for seed in 0..OFFERS_PER_GROUP_IN_CELL {
            let neighbour = Identity::from_seed([72 + seed as u8; 32]);
            let offer = sign(&neighbour, &content("198.51.7.1:7450", cell, NOW))?;
            mine.offered(&relay_asker(neighbour.public()), offer.clone(), NOW);
            lock(&mine.state).hold(checked(&offer, NOW).ok_or("unchecked")?, group, NOW);
            peer.hold_verified(offer, group, NOW)?;
        }
        let held = held_keys(&mine, cell, NOW);
        assert_eq!(held.len(), OFFERS_PER_GROUP_IN_CELL);
        assert_eq!(held, held_keys(&peer, cell, NOW));
        // Re-signed a minute on, it competes again, and both still hold the same.
        mine.tick(&hub, Some(&identity), NOW + OWN_RESIGN_EVERY_MS);
        assert_eq!(held_keys(&mine, cell, NOW + OWN_RESIGN_EVERY_MS), held);
        Ok(())
    }

    /// R-P3 of sweep 4: a relay advertising a host name signs offers naming the address it
    /// resolved to, and holds them under that address's group; a peer that verifies the gossiped
    /// offer by dialling the address it names holds it under the very same group. Neither
    /// resolves anything for the group.
    #[tokio::test]
    async fn a_relay_advertising_a_host_name_is_in_the_group_its_peers_put_it_in() -> Result {
        let cell = area()?;
        let identity = Identity::from_seed([81; 32]);
        // Answering as the relay at whichever loopback address `localhost` resolves to.
        let v4 = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let port = v4.local_addr().map_err(text)?.port();
        let v6 = TcpListener::bind(("::1", port)).await.ok();
        for listener in std::iter::once(v4).chain(v6) {
            let identities = vec![identity.clone()];
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let identities = identities.clone();
                    tokio::spawn(async move {
                        let _ = noise::accept(stream, &identities).await;
                    });
                }
            });
        }
        let hub = own_relay(&identity, &format!("localhost:{port}"), cell);
        let mine = Directory::new();
        let mut now = NOW;
        let mut gossiped = mine.tick(&hub, Some(&identity), now);
        for _ in 0..100 {
            if !mine.offers_for(cell, now).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            now += 100;
            gossiped.extend(mine.tick(&hub, Some(&identity), now));
        }
        let offer = gossiped
            .into_iter()
            .find_map(|record| match record {
                Record::ProviderOffer(offer) => Some(offer),
                _ => None,
            })
            .ok_or("no offer of its own was gossiped")?;
        let named = offer.content().map_err(text)?.address;
        let group = Group::of_address(&named).ok_or("the offer names a host name")?;
        {
            let state = lock(&mine.state);
            let held = state
                .cells
                .get(&cell.as_u64())
                .and_then(|offers| offers.get(&identity.public()))
                .ok_or("the relay's own offer is not held")?;
            assert_eq!(held.group, group);
            assert!(matches!(held.group, Group::V4(0x7f00) | Group::V6(0)));
        }
        // A peer, given the gossiped offer, dials the address it names and holds it there.
        let peer = Directory::new();
        peer.offered(&relay_asker(identity.public()), offer, now);
        peer.verify_pending(&Identity::generate().map_err(text)?, now)
            .await;
        let state = lock(&peer.state);
        let held = state
            .cells
            .get(&cell.as_u64())
            .and_then(|offers| offers.get(&identity.public()))
            .ok_or("the peer did not hold the relay's offer")?;
        assert_eq!(held.group, group);
        Ok(())
    }

    /// R-P3 of sweep 4: an offer naming a host name is in no group every relay agrees on (each
    /// resolver may answer it differently), so it is not taken: never queued for a dial.
    #[test]
    fn an_offer_naming_a_host_name_is_not_taken() -> Result {
        let directory = Directory::new();
        let relay = Identity::generate().map_err(text)?;
        let cell = area()?;
        let named = sign(&relay, &content("relay.example:7450", cell, NOW))?;
        directory.offered(&relay_asker(relay.public()), named, NOW);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        let numbered = sign(&relay, &content("192.0.2.7:7450", cell, NOW + 1))?;
        directory.offered(&relay_asker(relay.public()), numbered, NOW + 1);
        assert_eq!(directory.state.lock().map_err(text)?.pending.len(), 1);
        Ok(())
    }

    /// Sweep 3, N13: a peer re-signing an offer that says nothing new is taken at most once per
    /// `RESIGNED_AT_MOST_EVERY_MS` by the signed times, never gossiped sooner; and one taken is
    /// swapped in place, so it moves no ranking, version or tier a reader follows.
    #[test]
    fn a_re_signing_that_changes_nothing_is_taken_once_a_turn_and_in_place() -> Result {
        let relay = Identity::from_seed([91; 32]);
        let cell = area()?;
        let directory = Directory::new();
        let first = sign(&relay, &content("203.0.113.9:1", cell, NOW))?;
        assert!(directory.hold_verified(first.clone(), v4(203, 0), NOW)?);
        let ranked = directory.offers_for(cell, NOW);
        let version = directory.version(NOW);
        let _ = directory.take_changed_cells(NOW);
        // Re-signed a millisecond apart, a thousand times: none taken.
        for step in 1..=1_000 {
            let again = sign(&relay, &content("203.0.113.9:1", cell, NOW + step))?;
            assert!(!directory.hold_verified(again, v4(203, 0), NOW + step)?);
        }
        assert_eq!(directory.offers_for(cell, NOW + 1_000), vec![first]);
        // Its turn come: taken, in place.
        let at = NOW + RESIGNED_AT_MOST_EVERY_MS;
        let renewed = sign(&relay, &content("203.0.113.9:1", cell, at))?;
        assert!(directory.hold_verified(renewed.clone(), v4(203, 0), at)?);
        {
            let state = lock(&directory.state);
            assert!(
                state.ranks.contains_key(&cell.as_u64()),
                "the cell's ranking was dropped: not renewed in place"
            );
        }
        assert_eq!(directory.version(at).held, version.held);
        assert!(directory.take_changed_cells(at).is_empty());
        assert_eq!(directory.offers_for(cell, at), vec![renewed]);
        assert_eq!(ranked.len(), 1);
        Ok(())
    }
}
