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
//! - **Buckets by network group.** The address a verified offer answered at puts it in a group (an
//!   IPv4 /16, an IPv6 /32). A cell holds at most `OFFERS_PER_GROUP_IN_CELL` of one group and
//!   `OFFERS_PER_CELL` in all (the relay's own offer aside), so a flood of keys from a few
//!   networks displaces only itself. Past those, a group holds at most `OFFERS_PER_GROUP`
//!   anywhere, a key at most `OFFERS_PER_KEY`, and the directory `OFFERS_HELD`: bounds on a flood,
//!   which an honest network never reaches.
//! - **Held by rank, never by arrival.** Within a cell, which offers are held is decided by the
//!   wire's rendezvous ranking over (cell, key) (`rendezvous::rank`), never by which came first: a
//!   newcomer to a full cell (or a full group within it) displaces the lowest-ranked offer there
//!   only when it outranks it, and is refused otherwise. So the cell's held set is the top of the
//!   ranking of the offers verified, the same set on every relay that verified the same offers, and
//!   the sharing trees laid out over it (`sharing`) are the same trees everywhere. What it cannot
//!   be is a reward for tenure: a party that grinds keys to rank high for a cell, from more
//!   networks than a cell's group cap allows each, is held there, and it is the sharing duty
//!   (receipts and demotion) that drops it once held.
//! - **No reflection.** Every offer is acted on once, by its hash: one that comes back round a
//!   gossip loop is neither dialled nor gossiped again; the relay's own offers coming back are
//!   ignored; and an offer is gossiped once, when it is first verified.
//! - **Expiry by the reader's clock.** An offer already expired, or issued in the future past the
//!   allowed skew, is not taken, and one that expires while held is forgotten.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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

/// Offers held per signing key, at most.
pub const OFFERS_PER_KEY: usize = 64;
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
/// Offers in one answer to a query, at most: replies are written as control, 64 waiting a link.
pub const QUERY_ANSWER_MAX: usize = 32;
/// How long a dial may take to connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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

/// Where an offer answered from: the unit a flood is bucketed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    /// The relay's own offers.
    Own,
    /// An IPv4 /16.
    V4(u16),
    /// An IPv6 /32.
    V6(u32),
}

impl Group {
    /// The group as one number, distinct per group: what a contribution counts witnesses by.
    pub fn as_u64(self) -> u64 {
        match self {
            Self::Own => 0,
            Self::V4(prefix) => (1 << 32) | u64::from(prefix),
            Self::V6(prefix) => (2 << 32) | u64::from(prefix),
        }
    }

    /// The group of an address an offer's key answered at. An IPv4 address mapped into IPv6 is
    /// its IPv4 address.
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
    per_key: HashMap<PublicKey, usize>,
    per_group: HashMap<Group, usize>,
    held: usize,
    pending: VecDeque<Pending>,
    /// Addresses being dialled now.
    dialling: HashSet<String>,
    verifying: usize,
    /// (key, address) that answered, with its group and until when it is trusted.
    verified: Bounded<(PublicKey, String), (Group, u64)>,
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
    /// The network group the relay's own advertised address is in, if it names an address.
    own_group: Option<Group>,
    /// The groups each key's held offers answered from, with how many offers each.
    key_groups: HashMap<PublicKey, BTreeMap<Group, usize>>,
    /// Each key's tier, weighed at `tiers_at`; cleared whenever what they are weighed from changes.
    tiers: HashMap<PublicKey, u32>,
    tiers_at: u64,
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
            key_groups: HashMap::new(),
            tiers: HashMap::new(),
            tiers_at: 0,
        }
    }
}

#[derive(Clone)]
struct Held {
    offer: ProviderOffer,
    signer: PublicKey,
    products: Streams,
    issued_ms: u64,
    expires_ms: u64,
    group: Group,
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
    offer: ProviderOffer,
    signer: PublicKey,
    content: ProviderOfferContent,
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

/// An offer whose signature verifies and whose lifetime holds at `now_ms`.
fn checked(offer: &ProviderOffer, now_ms: u64) -> Option<(PublicKey, ProviderOfferContent)> {
    offer.verify().ok()?;
    let content = offer.content().ok()?;
    let live = expiry(&content) > now_ms && content.issued_ms <= now_ms + CLOCK_SKEW_MS;
    live.then_some((offer.signer().ok()?, content))
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
                query.products.0 == 0 || held.products.0 & query.products.0 != 0
            });
            answer.extend(offers);
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
    pub fn offers_for(&self, cell: Region, now_ms: u64) -> Vec<ProviderOffer> {
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
            .cells
            .values()
            .filter_map(|offers| offers.get(key))
            .filter(|held| held.expires_ms > now_ms)
            .filter_map(|held| held.offer.content().ok().map(|content| content.cell))
            .collect();
        cells.sort_by_key(|cell| cell.as_u64());
        cells.dedup();
        cells
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
            .cells
            .values()
            .filter_map(|offers| offers.get(key))
            .filter(|held| held.expires_ms > now_ms)
            .find_map(|held| held.offer.content().ok().map(|content| content.address))
    }

    /// Every live offer held, this relay's own included, each once: what a new directory link is
    /// sent first.
    pub fn live_offers(&self, now_ms: u64) -> Vec<ProviderOffer> {
        let state = lock(&self.state);
        let mut seen = HashSet::new();
        state
            .cells
            .values()
            .flat_map(HashMap::values)
            .filter(|held| held.expires_ms > now_ms && seen.insert(held.offer.hash()))
            .map(|held| held.offer.clone())
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
        let evidence_due = {
            let mut state = lock(&self.state);
            state.own = Some(identity.public());
            state.own_group = basis
                .as_ref()
                .and_then(|basis| basis.address.parse::<std::net::SocketAddr>().ok())
                .map(|address| Group::of(address.ip()));
            state.expire(now_ms);
            if let Some(offers) = state.resign(identity, basis, now_ms) {
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
            while let Some(pending) = self.next_to_verify() {
                let state = Arc::clone(&self.state);
                let identity = identity.clone();
                runtime.spawn(async move {
                    let answered =
                        answers_as(&pending.content.address, &identity, &pending.signer).await;
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
            let answered = answers_as(&pending.content.address, identity, &pending.signer).await;
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
            .position(|pending| !state.dialling.contains(&pending.content.address))?;
        let pending = state.pending.remove(at)?;
        state.dialling.insert(pending.content.address.clone());
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
        let (signer, content) = checked(&offer, now_ms).ok_or("not a live, signed offer")?;
        Ok(lock(&self.state).hold(offer, signer, &content, group, now_ms))
    }
}

/// Dials `address` and runs the handshake to `key`: the group it answered from, or `None` if it
/// did not answer as `key`. A refusal after the handshake (a full relay's `Goodbye`) still proves
/// the key, since only its holder completes the handshake.
async fn answers_as(address: &str, identity: &Identity, key: &PublicKey) -> Option<Group> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;
    let ip = stream.peer_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    match noise::connect(stream, identity, key, tally_wire::Role::Subscriber).await {
        Ok(_) | Err(WireError::Refused { .. }) => Some(Group::of(ip)),
        Err(_) => None,
    }
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
    // The areas taken, and the parents this relay has gathered every child of (bundles, §2.6).
    let mut cells = network.selection.taken();
    cells.extend(network.sharing.bundle_offers());
    cells.sort_by_key(|cell| cell.as_u64());
    cells.dedup();
    cells.truncate(OFFERS_PER_KEY);
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
        if let Some(layout) = sharing.layout(cell, product)
            && layout.contains(own)
        {
            laid_out = true;
            for stripe in layout.homes(own) {
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
    ) -> Vec<ProviderOffer> {
        let live: Vec<PublicKey> = self
            .cells
            .get(&cell.as_u64())
            .into_iter()
            .flat_map(HashMap::values)
            .filter(|held| held.expires_ms > now_ms && keep(held))
            .map(|held| held.signer)
            .collect();
        let tiered: Vec<(PublicKey, u32)> = live
            .into_iter()
            .map(|key| (key, self.tier(&key, now_ms)))
            .collect();
        let Some(offers) = self.cells.get(&cell.as_u64()) else {
            return Vec::new();
        };
        ranked(cell, tiered)
            .into_iter()
            .filter_map(|key| offers.get(&key))
            .take(OFFERS_PER_CELL)
            .map(|held| held.offer.clone())
            .collect()
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
        let at = now_ms - now_ms % WEIGHED_EVERY_MS;
        if at != self.tiers_at {
            self.tiers.clear();
            self.tiers_at = at;
        }
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
                    .map(|group| match group {
                        Group::Own => self.own_group.unwrap_or(Group::Own),
                        group => *group,
                    })
                    .collect();
                groups.sort();
                groups
            };
            let own_groups = groups_of(key);
            let child = |child: &PublicKey| -> Option<Unit> {
                let group = groups_of(child)
                    .into_iter()
                    .find(|group| *group != Group::Own)?;
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
        self.evidence.insert(signer, (shown, bundle.clone()));
        self.tiers.clear();
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
        let Some((signer, content)) = checked(&offer, now_ms) else {
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
            .is_some_and(|held| held.issued_ms >= content.issued_ms);
        if stale {
            return;
        }
        let trusted = self
            .verified
            .get(&(signer, content.address.clone()))
            .filter(|(_, until)| *until > now_ms)
            .map(|(group, _)| *group);
        if let Some(group) = trusted {
            if self.hold(offer.clone(), signer, &content, group, now_ms) {
                self.gossip.push(offer);
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
            waiting.signer == signer
                && waiting.content.address == content.address
                && waiting.content.cell == content.cell
        }) {
            if waiting.content.issued_ms < content.issued_ms {
                waiting.offer = offer;
                waiting.content = content;
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
            signer,
            content,
            asker: asker.key,
        });
    }

    /// A handshake's outcome.
    fn verified(&mut self, pending: Pending, answered: Option<Group>, now_ms: u64) {
        self.dialling.remove(&pending.content.address);
        self.verifying = self.verifying.saturating_sub(1);
        match answered {
            Some(group) => {
                self.verified.insert(
                    (pending.signer, pending.content.address.clone()),
                    (group, now_ms + VERIFIED_FOR_MS),
                );
                let live = checked(&pending.offer, now_ms).is_some();
                if live
                    && self.hold(
                        pending.offer.clone(),
                        pending.signer,
                        &pending.content,
                        group,
                        now_ms,
                    )
                {
                    self.gossip.push(pending.offer);
                }
            }
            None => {
                self.unanswered
                    .insert(pending.content.address, now_ms + UNANSWERED_FOR_MS);
            }
        }
    }

    /// Holds a verified offer if the caps allow it, by rank (see the module). True when held
    /// (new, or newer for its key and cell).
    fn hold(
        &mut self,
        offer: ProviderOffer,
        signer: PublicKey,
        content: &ProviderOfferContent,
        group: Group,
        now_ms: u64,
    ) -> bool {
        let cell_key = content.cell.as_u64();
        let replacing = self
            .cells
            .get(&cell_key)
            .and_then(|cell| cell.get(&signer))
            .cloned();
        if let Some(existing) = replacing {
            if existing.issued_ms >= content.issued_ms {
                return false;
            }
            self.remove(cell_key, &signer);
            // Re-signed from the same network: its rank and its group are unchanged, so it keeps
            // its place. From another network it competes there as a newcomer.
            if existing.group == group {
                self.insert(offer, signer, content, group);
                return true;
            }
        }
        // The relay's own offers are always held (at most `OFFERS_PER_KEY`, by `own_basis`) and
        // count against no cap; they are ranked among the rest when answered.
        if group != Group::Own {
            if self.per_key.get(&signer).copied().unwrap_or(0) >= OFFERS_PER_KEY
                || self.per_group.get(&group).copied().unwrap_or(0) >= OFFERS_PER_GROUP
                || self.held >= OFFERS_HELD
            {
                return false;
            }
            let others: Vec<(PublicKey, Group)> = self
                .cells
                .get(&cell_key)
                .into_iter()
                .flat_map(HashMap::values)
                .filter(|held| held.group != Group::Own)
                .map(|held| (held.signer, held.group))
                .collect();
            let in_group: Vec<PublicKey> = others
                .iter()
                .filter(|(_, other)| *other == group)
                .map(|(key, _)| *key)
                .collect();
            let contest = if in_group.len() >= OFFERS_PER_GROUP_IN_CELL {
                Some(in_group)
            } else if others.len() >= OFFERS_PER_CELL {
                Some(others.iter().map(|(key, _)| *key).collect())
            } else {
                None
            };
            if let Some(mut contest) = contest {
                contest.push(signer);
                let tiered: Vec<(PublicKey, u32)> = contest
                    .into_iter()
                    .map(|key| (key, self.tier(&key, now_ms)))
                    .collect();
                let lowest = ranked(content.cell, tiered).pop();
                match lowest {
                    Some(lowest) if lowest != signer => self.remove(cell_key, &lowest),
                    _ => return false,
                }
            }
        }
        self.insert(offer, signer, content, group);
        true
    }

    fn insert(
        &mut self,
        offer: ProviderOffer,
        signer: PublicKey,
        content: &ProviderOfferContent,
        group: Group,
    ) {
        self.cells.entry(content.cell.as_u64()).or_default().insert(
            signer,
            Held {
                offer,
                signer,
                products: content.products,
                issued_ms: content.issued_ms,
                expires_ms: expiry(content),
                group,
            },
        );
        *self.per_key.entry(signer).or_insert(0) += 1;
        *self.per_group.entry(group).or_insert(0) += 1;
        *self
            .key_groups
            .entry(signer)
            .or_default()
            .entry(group)
            .or_insert(0) += 1;
        self.held += 1;
        self.tiers.clear();
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
        decrement(&mut self.per_key, signer);
        decrement(&mut self.per_group, &held.group);
        if let Some(groups) = self.key_groups.get_mut(signer) {
            if let Some(count) = groups.get_mut(&held.group) {
                *count -= 1;
                if *count == 0 {
                    groups.remove(&held.group);
                }
            }
            if groups.is_empty() {
                self.key_groups.remove(signer);
            }
        }
        self.held -= 1;
        self.tiers.clear();
    }

    /// Forgets every offer expired at `now_ms`, and the addresses no longer trusted or shunned.
    fn expire(&mut self, now_ms: u64) {
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
        // Evidence is held for the relays whose offers are held, and for one whose offer has not
        // come for a while (its handshake under way) until its offer would have.
        let own = self.own;
        let per_key = &self.per_key;
        self.evidence.retain(|key, (shown, _)| {
            Some(*key) == own
                || per_key.contains_key(key)
                || now_ms.saturating_sub(shown.issued_ms()) <= 2 * OWN_EVIDENCE_EVERY_MS
        });
        while self
            .verified
            .first()
            .is_some_and(|(_, (_, until))| *until <= now_ms)
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
        let basis = basis?;
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
            if self.hold(offer.clone(), own, &content, Group::Own, now_ms) {
                signed.push(offer);
            }
        }
        Some(signed)
    }
}

fn decrement<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, usize>, key: &K) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
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
                .filter_map(|offer| offer.signer().ok())
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
        let offer = sign(&other, &content("relay.example:7450", cell, NOW))?;
        let client = Asker {
            role: AskerRole::Client,
            key: Identity::generate().map_err(text)?.public(),
            source: 2,
            loopback: false,
        };
        directory.offered(&client, offer.clone(), NOW);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // The relay's own offer, come back round a gossip loop.
        let mine = sign(&own, &content("me.example:7450", cell, NOW))?;
        directory.offered(&relay_asker(other.public()), mine, NOW);
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // A client announcing its own offer is queued.
        let announcing = Asker {
            key: other.public(),
            ..client
        };
        let fresh = sign(&other, &content("relay.example:7450", cell, NOW + 1))?;
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
        let cells = rendezvous::areas_of(state).map_err(text)?;
        let mut held = 0;
        for (index, cell) in cells.iter().cycle().take(100).enumerate() {
            let content = content("busy.example:1", *cell, NOW + index as u64);
            if directory.hold_verified(sign(&busy, &content)?, v4(12, (index % 200) as u8), NOW)? {
                held += 1;
            }
        }
        let state = directory.state.lock().map_err(text)?;
        assert!(state.per_key.get(&busy.public()).copied().unwrap_or(0) <= OFFERS_PER_KEY);
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
                held.iter()
                    .any(|offer| offer.signer().ok() == Some(relay.public())),
                "an honest relay was displaced"
            );
        }
        // The MLAT choice still ranks every relay held, each counted for at most
        // `MLAT_CORES_COUNTED` cores whatever it names.
        let chosen = crate::selection::mlat_relays(cell, &directory, NOW);
        assert_eq!(chosen.len(), rendezvous::MLAT_RELAYS_PER_AREA);
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
                .filter_map(|offer| offer.signer().ok())
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
            address: "me.example:7450".to_owned(),
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
        assert_eq!(declared.address, "me.example:7450");
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
}
