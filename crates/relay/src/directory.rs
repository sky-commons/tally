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
//!   state, and [`Directory::take_changed`] the cells whose answer changed since the last
//!   look. A re-signing that says what the held offer said changes neither, so a relay that holds
//!   offers for every area of the world costs its readers nothing while nothing changes (the MLAT
//!   choice in `selection`, the sharing trees in `sharing`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tally_wire::Signs;
use tally_wire::budget::policy;
use tally_wire::clocks::{Judged, Mono};
use tally_wire::rendezvous::{self, Weighted};
use tally_wire::{
    EvidenceBundle, ProviderOffer, ProviderOfferContent, ProviderQuery, PublicKey, Record, Region,
    Streams, WireError, noise,
};
use tokio::net::TcpStream;

use crate::bounded::Bounded;
use crate::budget::{Charge, Gauge};
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
/// The generations the hashes acted on are remembered in ([`Seen`]): the oldest is let go whole
/// when a new one begins.
const SEEN_GENERATIONS: usize = 4;
/// The hashes one generation remembers at most: its table is made for them, and a new generation
/// begins once it holds them, so no generation's table ever grows. The most a table of 16,384
/// buckets holds (seven eighths of them, `footprint::buckets_for`), so it is made at that and not
/// at twice it, as a power of two would be.
const SEEN_PER_GENERATION: usize = 16_384 / 8 * 7;
/// Offer hashes remembered as acted on, at most ([`Seen`]): every generation's.
pub const SEEN_REMEMBERED: usize = SEEN_GENERATIONS * SEEN_PER_GENERATION;
/// How long a generation takes hashes for, by `M`, at most: so the generations kept besides the
/// newest cover an offer's lifetime and the clock skew a reader allows (`OFFER_LIFETIME_MS` and
/// `tally_wire::budget::K`) whenever they fill no faster.
const SEEN_SPAN_MS: u64 = (OFFER_LIFETIME_MS + tally_wire::budget::K.duration().as_millis() as u64)
    .div_ceil(SEEN_GENERATIONS as u64 - 1);
/// How often a relay bundles its own evidence for the directory (`State::tier`): a tenth of the
/// evidence's half-life (`credit::HALF_LIFE_MS`), so its tier, a factor of two wide, follows what it
/// does within minutes and the bundles cost the directory links little.
pub const OWN_EVIDENCE_EVERY_MS: u64 = credit::HALF_LIFE_MS / 10;
// What another relay's evidence is held for while its offer has not come: two of its bundles.
const _: () = assert!(
    tally_wire::budget::EVIDENCE_AWAITED.span::<Judged>().ms() == 2 * OWN_EVIDENCE_EVERY_MS
);
/// Relays' evidence held, at most: one a key, as many as offers may be held.
pub const EVIDENCE_HELD: usize = OFFERS_HELD;
/// The bytes the evidence held may take at most ([`evidence_cost`] of each bundle: held once, and
/// shared with its gossip), charged to the directory's store as it is held: a bundle may be as
/// large as a record (`tally_wire::record::MAX_BODY`), so the count alone ([`EVIDENCE_HELD`])
/// bounded nothing a plan could hold. Before, each bundle was held twice (and its copy waiting to
/// be gossiped charged beside it) in a room of 64 MiB: this holds the same bundles. Past it the
/// evidence held is given up by rank ([`evidence_rank`]), the same set whatever order the bundles
/// came in.
pub const EVIDENCE_ROOM_BYTES: usize = 32 << 20;
/// Offers waiting to be gossiped at the next tick, at most: past it one newly held is not
/// gossiped, counted (`Directory::gossip_dropped`), and its signer's next signing is.
pub const GOSSIP_HELD: usize = OFFERS_HELD;
/// Cells remembered as changed between two of sharing's looks, at most: past it every cell is
/// taken as changed (`Changed::All`).
pub const CHANGED_HELD: usize = OFFERS_HELD;
/// What one checked offer allocates at most: its shared record, its bytes and its address.
const OFFER_HEAP_BYTES: usize =
    tally_wire::footprint::arc::<CheckedOffer>() + ProviderOffer::MAX_LEN + ADDRESS_MOST_BYTES;
/// An offer's address at most (`ProviderOfferContent::address`, a length byte's worth).
const ADDRESS_MOST_BYTES: usize = 255;
/// What each held offer adds to the directory's tables at most, beside the tables' own slots at
/// their caps: itself and a change of it waiting (its gossip shares it, `State::gossip`), and its
/// entries in each cell's, key's and group's sets (each kept within twice what it holds, `keep_within`), its cell's ranking and its
/// key's networks.
const PER_OFFER_BYTES: usize = {
    use tally_wire::footprint::{btree_planned, table_per_entry, vec};
    2 * OFFER_HEAP_BYTES
        + table_per_entry::<PublicKey, Held>(KEPT_WITHIN)
        + table_per_entry::<u64, ()>(KEPT_WITHIN)
        + table_per_entry::<(u64, PublicKey), ()>(KEPT_WITHIN)
        + vec::<PublicKey>(2)
        + btree_planned::<Group, usize>(1)
};
/// How many times its entries an inner set of the directory's keeps its capacity within
/// (`keep_within`), so what the sets allocate follows what is held.
const KEPT_WITHIN: usize = 2;
/// What the directory's tables allocate at most, at their caps, whatever the relay carries
/// (`budget::Store::Directory`, charged whole when the store is): the offers held and every table
/// keyed by them, the offers waiting for a handshake or to be gossiped, the hashes acted on, the
/// addresses trusted or shunned, and the evidence's slots (its bytes are [`EVIDENCE_ROOM_BYTES`]).
/// Before, none of it was charged to any store.
pub const TABLES_PLANNED_BYTES: usize = {
    use tally_wire::footprint::{btree_planned, table_churned, vec};
    let offers = OFFERS_HELD * PER_OFFER_BYTES
        + table_churned::<u64, HashMap<PublicKey, Held>>(OFFERS_HELD)
        + table_churned::<PublicKey, HashSet<u64>>(OFFERS_HELD)
        + table_churned::<Group, HashSet<(u64, PublicKey)>>(OFFERS_HELD)
        + table_churned::<u64, Vec<PublicKey>>(OFFERS_HELD)
        + table_churned::<PublicKey, BTreeMap<Group, usize>>(OFFERS_HELD)
        + table_churned::<PublicKey, u32>(OFFERS_HELD + EVIDENCE_HELD)
        + table_churned::<u64, ()>(CHANGED_HELD)
        + btree_planned::<u64, usize>(OFFERS_HELD)
        + btree_planned::<(Mono, u64, PublicKey), ()>(OFFERS_HELD);
    let evidence = table_churned::<PublicKey, (Shown, Arc<EvidenceBundle>)>(EVIDENCE_HELD + 1)
        + btree_planned::<PublicKey, Arc<EvidenceBundle>>(EVIDENCE_HELD)
        + vec::<(PublicKey, u32)>(2 * EVIDENCE_HELD);
    // The offers to gossip share their held offers' bytes, and go when they are let go.
    let waiting = btree_planned::<(u64, PublicKey), Checked>(GOSSIP_HELD)
        + vec::<Pending>(2 * PENDING)
        + PENDING * OFFER_HEAP_BYTES
        + vec::<Checked>(2 * OFFERS_PER_KEY)
        + OFFERS_PER_KEY * OFFER_HEAP_BYTES
        + table_churned::<String, ()>(VERIFYING_AT_ONCE)
        + VERIFYING_AT_ONCE * ADDRESS_MOST_BYTES;
    let remembered = Seen::PLANNED_BYTES
        + Bounded::<(PublicKey, String), Mono>::planned_bytes(ADDRESSES_REMEMBERED)
        + Bounded::<String, Mono>::planned_bytes(ADDRESSES_REMEMBERED)
        + 2 * (ADDRESSES_REMEMBERED + 1) * ADDRESS_MOST_BYTES;
    offers + evidence + waiting + remembered
};
/// What the directory's store is planned at (`budget::Store::Directory`): its tables at their
/// caps and the evidence's room.
pub const PLANNED_BYTES: usize = TABLES_PLANNED_BYTES + EVIDENCE_ROOM_BYTES;

/// What a held bundle costs the evidence's room ([`EVIDENCE_ROOM_BYTES`]): its bytes, held once
/// in a shared allocation its gossip shares, and what was read of it.
fn evidence_cost(shown: &Shown, bundle: &EvidenceBundle) -> usize {
    tally_wire::footprint::arc::<EvidenceBundle>() + bundle.allocated() + shown.allocated()
}

/// Where a relay's evidence stands for the room ([`EVIDENCE_ROOM_BYTES`], [`EVIDENCE_HELD`]):
/// kept before every one that ranks after it. The relay's own first, then a signer with an offer
/// held here, then the rest; within each, the cheaper first, then by key. Decided by what is held
/// and what the bundles are, never by when they came, so two relays given the same bundles hold
/// the same evidence whatever order they came in: the room holds the longest run of them in rank
/// order that fits. A rank that grows with the cost is what makes that run the same whatever order
/// the bundles came in (one that did not could let a costly bundle push out cheaper ones that a
/// relay given them in another order still holds beside it), and it gives up first the bytes a
/// flood is made of, since a stranger's key costs nothing and its bundle may be as large as a
/// record.
fn evidence_rank(own: bool, held: bool, cost: usize, key: PublicKey) -> (u8, usize, PublicKey) {
    let class = if own {
        0
    } else if held {
        1
    } else {
        2
    };
    (class, cost, key)
}

/// The offer hashes acted on (`State::offered`), each a keyed fingerprint of eight bytes (a
/// SipHash of its hash under this directory's secret, `tally_wire::decoded::keyed::OFFER_SEEN`)
/// in generations ([`SEEN_GENERATIONS`], each [`SEEN_SPAN_MS`] long at most and
/// [`SEEN_PER_GENERATION`] at most): so the hashes held cover an offer's lifetime when they come
/// no faster, and cost a fingerprint each, not a hash and a place in a recency order. Before, a
/// table of 65,536 hashes in recency order, 23.5 MB at its cap.
///
/// What is remembered only saves work (an offer checked and acted on once): forgetting one early,
/// under a flood, or a fingerprint met by chance, lets nothing in. A returning offer is refused by
/// its own signed times: once its lifetime is past it has expired (`checked`), and while it lives
/// a held offer of its key and cell at least as new refuses it (`State::offered`, `newest_ms`), so
/// no offer is held twice, or held again after a newer, whatever is remembered here. Two offers
/// meet in a generation only by chance, with probability its fingerprints over `2^64`, which no
/// sender can choose since the secret is this directory's: the newer is then not acted on here,
/// and its signer's next re-signing is.
struct Seen {
    key: tally_wire::FingerprintKey,
    /// Each generation with when it began, by `M`, the newest last.
    generations: VecDeque<(Mono, HashSet<u64>)>,
}

impl Seen {
    /// What the generations allocate at most: each table made for its hashes, never grown.
    const PLANNED_BYTES: usize = SEEN_GENERATIONS
        * tally_wire::footprint::table_made::<u64, ()>(SEEN_PER_GENERATION)
        + tally_wire::footprint::vec::<(Mono, HashSet<u64>)>(SEEN_GENERATIONS + 1);

    fn new() -> Self {
        Self {
            key: tally_wire::FingerprintKey::random(),
            generations: VecDeque::with_capacity(SEEN_GENERATIONS + 1),
        }
    }

    fn fingerprint(&self, hash: &[u8; 32]) -> u64 {
        self.key
            .fingerprint(tally_wire::decoded::keyed::OFFER_SEEN, hash) as u64
    }

    fn contains(&self, hash: &[u8; 32]) -> bool {
        let fingerprint = self.fingerprint(hash);
        self.generations
            .iter()
            .any(|(_, generation)| generation.contains(&fingerprint))
    }

    /// Remembers `hash` at `mono`: in the newest generation, or in a new one when it has taken
    /// hashes for its span or is full, the oldest let go once there are more than
    /// [`SEEN_GENERATIONS`].
    fn insert(&mut self, hash: &[u8; 32], mono: Mono) {
        let fingerprint = self.fingerprint(hash);
        let fresh = self.generations.back().is_none_or(|(began, generation)| {
            mono.since(*began) >= policy::<_, SEEN_SPAN_MS>()
                || generation.len() >= SEEN_PER_GENERATION
        });
        if fresh {
            if self.generations.len() >= SEEN_GENERATIONS {
                self.generations.pop_front();
            }
            self.generations
                .push_back((mono, HashSet::with_capacity(SEEN_PER_GENERATION)));
        }
        if let Some((_, generation)) = self.generations.back_mut() {
            generation.insert(fingerprint);
        }
    }

    /// The hashes remembered, over every generation.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.generations
            .iter()
            .map(|(_, generation)| generation.len())
            .sum()
    }
}

/// `map`'s capacity brought within [`KEPT_WITHIN`] times what it holds, and a few more.
fn keep_within<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
    if map.capacity() > KEPT_WITHIN * map.len() + 4 {
        map.shrink_to_fit();
    }
}

/// As [`keep_within`], for a set.
fn keep_set_within<T: Eq + std::hash::Hash>(set: &mut HashSet<T>) {
    if set.capacity() > KEPT_WITHIN * set.len() + 4 {
        set.shrink_to_fit();
    }
}

/// What the cells changed since sharing last looked are (`Directory::take_changed`).
#[derive(Debug, PartialEq, Eq)]
pub enum Changed {
    /// These, sorted.
    Cells(Vec<Region>),
    /// More than [`CHANGED_HELD`]: every cell is to be taken as changed.
    All,
}
/// How often a relay re-signs its own offers while it serves: once a minute.
pub const OWN_RESIGN_EVERY_MS: u64 = 60 * 1000;
/// How long an offer lives, by the signed times in it: three re-signings. A relay that dies is
/// therefore out of every relay's directory, and so of every area's MLAT ranking and every
/// sharing tree, within three minutes of its last re-signing, by its own signature and not by
/// when anyone heard it, alike on every relay. The figure is the directory's own timing:
///
/// - one re-signing (60 s), the wait for the next offer;
/// - the clock skew a reader allows (`tally_wire::budget::K`, 15 s) and 45 s to spare, 60 s in all: to a
///   reader whose clock is that far ahead, every offer is that much older than its signer meant;
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

pub struct Directory {
    /// Shared with the handshakes in flight, which write their outcome back.
    state: Arc<Mutex<State>>,
    /// The tables' charge ([`TABLES_PLANNED_BYTES`]) on the directory's store, whole, or nothing
    /// when the store cannot hold it (a start then refuses, `charged_in_full`).
    tables: Mutex<Charge>,
    /// The relay's one clock (`clock::RelayClock`): what a handshake's outcome and an address
    /// asked for are judged by, as everything the duties hand in is.
    clock: crate::clock::RelayClock,
}

struct State {
    own: Option<PublicKey>,
    /// What the own offers last declared, and when they were signed, by `M`: re-signing is this
    /// relay's own schedule, so a step of `J` neither stops nor hurries it.
    own_basis: Option<Basis>,
    own_signed: Option<Mono>,
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
    /// Changes deferred (`CHANGED_AT_MOST_EVERY_MS`), by when they are due on `M`: (due, cell,
    /// key). The change itself waits in its held offer (`Held::deferred`).
    deferred: BTreeSet<(Mono, u64, PublicKey)>,
    pending: VecDeque<Pending>,
    /// Addresses being dialled now.
    dialling: HashSet<String>,
    verifying: usize,
    /// (key, address) that answered, and until when it is trusted there, by `M`: a dial's
    /// outcome is this relay's own, timed by its own clock, so a step of `J` neither ends the trust
    /// at once nor keeps it an hour.
    verified: Bounded<(PublicKey, String), Mono>,
    /// Addresses that did not answer, until when they are not dialled again, by `M`.
    unanswered: Bounded<String, Mono>,
    /// Offer hashes acted on.
    seen: Seen,
    /// Newly held offers, gossiped once at the next tick, by cell and signer: each shares its
    /// held offer, and goes when it is let go (`State::remove`), so the gossip holds no offer's
    /// bytes of its own.
    gossip: BTreeMap<(u64, PublicKey), Checked>,
    /// What each relay holding an offer here showed of its contribution, from its newest
    /// evidence bundle (`credit::check`): what its offers are ranked by first.
    evidence: HashMap<PublicKey, (Shown, Arc<EvidenceBundle>)>,
    /// New evidence held, gossiped once at the next tick: each shares its held bundle, and goes
    /// when it is let go (`State::forget_evidence`).
    evidence_gossip: BTreeMap<PublicKey, Arc<EvidenceBundle>>,
    /// What the evidence held costs its room ([`evidence_cost`] of each), charged to the store
    /// (`evidence_charge`), at most [`EVIDENCE_ROOM_BYTES`].
    evidence_bytes: usize,
    evidence_charge: Charge,
    /// The evidence's room: [`EVIDENCE_ROOM_BYTES`], a test's smaller.
    evidence_room: usize,
    /// Bundles refused for the evidence's room, and offers not gossiped for the gossip's.
    evidence_refused: u64,
    gossip_dropped: u64,
    /// More cells changed than [`CHANGED_HELD`] since sharing last looked.
    changed_all: bool,
    /// When the relay's own evidence was last bundled, by `M`.
    own_evidence_at: Option<Mono>,
    /// The network group of the address the relay's own offers as last signed name
    /// (`Group::of_address`), as every peer that dials it finds it: what its own offers are held
    /// under. `None` while it signs none.
    own_group: Option<Group>,
    /// The relay's own offers as last signed (`resign`): held under `own_group` (`hold_own`).
    own_offers: Vec<Checked>,
    /// The advertised host name last resolved, the address it resolved to (what the relay's
    /// offers name), and until when, by `M`, that is taken without resolving again
    /// (`VERIFIED_FOR_MS`).
    own_resolved: Option<(String, std::net::SocketAddr, Mono)>,
    /// The host name being resolved, and when, by `M`, it may be tried again: never while a
    /// resolution is under way (`None`), `RESOLVE_AGAIN_MS` after one failed.
    own_resolving: Option<(String, Option<Mono>)>,
    /// Host names answered from here and not by the system's resolver: a test's, whose sandbox may
    /// have no resolver at all (`Directory::pin_host`). Empty in a running relay.
    hosts: HashMap<String, std::net::IpAddr>,
    /// The groups each key's held offers answered from, with how many offers each.
    key_groups: HashMap<PublicKey, BTreeMap<Group, usize>>,
    /// Each key's tier, weighed at `tiers_at`; cleared whenever what they are weighed from changes.
    tiers: HashMap<PublicKey, u32>,
    tiers_at: Option<Judged>,
    /// Bumped whenever what the held offers answer may have changed: an offer held or let go, one
    /// that says something new, evidence that moves the tiers (`Directory::version`).
    version: u64,
    /// The cells whose answer changed since sharing last looked (`Directory::take_changed`), at
    /// most [`CHANGED_HELD`] (past them, `changed_all`).
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
            own_signed: None,
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
            seen: Seen::new(),
            gossip: BTreeMap::new(),
            evidence: HashMap::new(),
            evidence_gossip: BTreeMap::new(),
            evidence_bytes: 0,
            evidence_charge: Gauge::unlimited(crate::budget::Store::Directory).empty(),
            evidence_room: EVIDENCE_ROOM_BYTES,
            evidence_refused: 0,
            gossip_dropped: 0,
            changed_all: false,
            own_evidence_at: None,
            own_group: None,
            own_offers: Vec::new(),
            own_resolved: None,
            own_resolving: None,
            hosts: HashMap::new(),
            key_groups: HashMap::new(),
            tiers: HashMap::new(),
            tiers_at: None,
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
    /// When what it says last changed here, by this relay's `M`: a change sooner than
    /// `CHANGED_AT_MOST_EVERY_MS` after waits.
    changed: Mono,
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
fn checked(offer: &ProviderOffer, now: Judged) -> Option<Checked> {
    offer.verify().ok()?;
    let content = offer.content().ok()?;
    let signer = offer.signer().ok()?;
    live(&content, now).then(|| {
        Checked(Arc::new(CheckedOffer {
            offer: offer.clone(),
            signer,
            content,
        }))
    })
}

/// Whether an offer's lifetime holds at `now_ms`: not expired, and not issued in the future past
/// the allowed skew.
fn live(content: &ProviderOfferContent, now: Judged) -> bool {
    !tally_wire::budget::expired(expiry(content), now)
        && !tally_wire::budget::K.ahead(content.issued_ms, now)
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

impl State {
    /// `address` (a host name and port) as `Directory::pin_host` pinned its host, if it did.
    fn pinned(&self, address: &str) -> Option<std::net::SocketAddr> {
        let (host, port) = address.rsplit_once(':')?;
        let ip = self.hosts.get(host)?;
        Some(std::net::SocketAddr::new(*ip, port.parse().ok()?))
    }
}

/// A test's: on a clock of its own, as a relay started now reads it.
#[cfg(test)]
impl Default for Directory {
    fn default() -> Self {
        Self::on(crate::clock::RelayClock::system())
    }
}

impl Directory {
    /// A directory judging by `clock`, the relay's one clock (`network::Network::new`).
    pub fn on(clock: crate::clock::RelayClock) -> Self {
        Self {
            state: Arc::default(),
            tables: Mutex::new(Charge::none()),
            clock,
        }
    }

    /// A test's: on a clock of its own, as a relay started now reads it.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    /// The directory is charged to `gauge` (the budget's `Store::Directory`) from now on: its
    /// tables whole ([`TABLES_PLANNED_BYTES`], nothing when the store cannot hold them), and the
    /// evidence held as it is held, within [`EVIDENCE_ROOM_BYTES`]. Evidence the store cannot take
    /// is let go, the relay's own kept.
    pub fn charge_to(&self, gauge: &Arc<Gauge>) {
        {
            let mut tables = lock(&self.tables);
            *tables = Charge::none();
            let mut charge = gauge.empty();
            if gauge.limit() >= PLANNED_BYTES {
                let _ = charge.try_grow(TABLES_PLANNED_BYTES);
            }
            *tables = charge;
        }
        let mut state = lock(&self.state);
        state.evidence_charge = Charge::none();
        let mut moved = gauge.empty();
        if !moved.try_grow(state.evidence_bytes) {
            let own = state.own;
            let others: Vec<PublicKey> = state
                .evidence
                .keys()
                .copied()
                .filter(|key| Some(*key) != own)
                .collect();
            for key in others {
                state.drop_evidence(&key);
            }
            let _ = moved.try_grow(state.evidence_bytes);
        }
        state.evidence_charge = moved;
    }

    /// Whether its tables are charged whole: a relay whose budget cannot hold them refuses to
    /// start (`network::Network::fixed_charged`).
    pub fn charged_in_full(&self) -> Result<(), String> {
        if lock(&self.tables).bytes() >= TABLES_PLANNED_BYTES {
            Ok(())
        } else {
            Err(format!(
                "the directory's store cannot hold its tables ({TABLES_PLANNED_BYTES} bytes)"
            ))
        }
    }

    /// What the evidence held is charged now, bundles refused for its room since start, and offers
    /// newly held that were not gossiped for want of room.
    pub fn evidence_held(&self) -> (usize, u64, u64) {
        let state = lock(&self.state);
        (
            state.evidence_charge.bytes(),
            state.evidence_refused,
            state.gossip_dropped,
        )
    }

    /// The key the relay's own offers are signed with, once it has offered.
    pub fn own_key(&self) -> Option<PublicKey> {
        lock(&self.state).own
    }

    /// Answers `host` with `ip` whatever the system's resolver says: a test of resolving a host
    /// name must not depend on the resolver of the machine (or sandbox) it runs in.
    #[cfg(test)]
    pub(crate) fn pin_host(&self, host: &str, ip: std::net::IpAddr) {
        lock(&self.state).hosts.insert(host.to_owned(), ip);
    }

    #[doc(hidden)]
    pub fn adopt_own_key(&self, key: PublicKey) {
        lock(&self.state).own = Some(key);
    }

    /// An offer a peer sent or gossiped: checked, then held at once if its key already answered
    /// at its address, else queued for the handshake (`tick` dials). Acted on once by its hash.
    pub fn offered(&self, asker: &Asker, offer: ProviderOffer, now: Judged) {
        let mono = self.clock.mono();
        lock(&self.state).offered(asker, offer, now, mono);
    }

    /// The offers held for `query.cell` and its ancestors, live at `now_ms`, of the products
    /// asked (any, when none is named): the finest cell first, in rank order within a cell; at
    /// most `QUERY_ANSWER_MAX`.
    pub fn query(&self, query: &ProviderQuery, now: Judged) -> Vec<ProviderOffer> {
        let Ok(path) = rendezvous::ancestors(query.cell) else {
            return Vec::new();
        };
        let mut state = lock(&self.state);
        let mut answer = Vec::new();
        for cell in path {
            let offers = state.ranked_offers(cell, now, |held| {
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
    pub fn offers_for(&self, cell: Region, now: Judged) -> Vec<Checked> {
        let Ok(path) = rendezvous::ancestors(cell) else {
            return Vec::new();
        };
        let mut state = lock(&self.state);
        path.iter()
            .flat_map(|cell| state.ranked_offers(*cell, now, |_| true))
            .collect()
    }

    /// The cells `key`'s live offers held name (its own, for this relay's key), each once,
    /// sorted.
    pub fn cells_of(&self, key: &PublicKey, now: Judged) -> Vec<Region> {
        let state = lock(&self.state);
        let mut cells: Vec<Region> = state
            .held_of(key)
            .filter(|held| !tally_wire::budget::expired(held.expires_ms, now))
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
    pub fn version(&self, now: Judged) -> Version {
        let now_ms = now.ms();
        let mut state = lock(&self.state);
        state.roll_tiers(now);
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
    pub fn take_changed(&self, now: Judged) -> Changed {
        let mut state = lock(&self.state);
        state.expire_offers(now);
        state.roll_tiers(now);
        let mut cells: Vec<Region> = state
            .changed
            .drain()
            .filter_map(|cell| Region::from_u64(cell).ok())
            .collect();
        if std::mem::take(&mut state.changed_all) {
            return Changed::All;
        }
        cells.sort_by_key(|cell| cell.as_u64());
        Changed::Cells(cells)
    }

    /// As `take_changed`, the cells alone: a test's, which never changes more than
    /// [`CHANGED_HELD`].
    #[cfg(test)]
    pub fn take_changed_cells(&self, now: Judged) -> Vec<Region> {
        match self.take_changed(now) {
            Changed::Cells(cells) => cells,
            Changed::All => Vec::new(),
        }
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
    pub fn coverage(&self, now: Judged) -> Coverage {
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
            let offers = state.ranked_offers(region, now, |_| true);
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
    /// An offer's expiry is a time its signer set, so it is compared with `J` only while `J`
    /// judges: before, the offers are those last judged live (the tick lets none go until it
    /// judges, as `knows` holds them), and a clock not synced and ahead read every one expired,
    /// so the sends drained for them went nowhere.
    pub fn address_of(&self, key: &PublicKey) -> Option<String> {
        let (now, judging) = (self.clock.judged(), self.clock.judging());
        let state = lock(&self.state);
        if state.own == Some(*key) {
            return None;
        }
        state
            .held_of(key)
            .filter(|held| !judging || !tally_wire::budget::expired(held.expires_ms, now))
            .min_by_key(|held| held.offer.content().cell.as_u64())
            .map(|held| held.offer.content().address.clone())
    }

    /// Every live offer held, and this relay's own as last signed (held here or not: a peer
    /// holds them by its own caps), each once: what a new directory link is sent first.
    pub fn live_offers(&self, now: Judged) -> Vec<ProviderOffer> {
        let state = lock(&self.state);
        let mut seen = HashSet::new();
        let own = state
            .own_offers
            .iter()
            .filter(|offer| live(offer.content(), now));
        state
            .cells
            .values()
            .flat_map(HashMap::values)
            .filter(|held| !tally_wire::budget::expired(held.expires_ms, now))
            .map(|held| &held.offer)
            .chain(own)
            .filter(|offer| seen.insert(offer.offer().hash()))
            .map(|offer| offer.offer().clone())
            .collect()
    }

    /// A relay's evidence bundle, gossiped on a directory link: checked by credit's own
    /// verifier (`credit::check`) and held if it is newer than what is held of its signer. True
    /// when held, and then gossiped once at the next tick. Each signature inside it is a token of
    /// `pace`, the link's (`credit::check`).
    pub fn evidence(
        &self,
        bundle: &EvidenceBundle,
        now: Judged,
        pace: Option<&crate::ingest::RecordPace>,
    ) -> bool {
        lock(&self.state).evidence(bundle, now, pace)
    }

    /// Every evidence bundle held: what a new directory link is sent beside the offers.
    pub fn live_evidence(&self) -> Vec<EvidenceBundle> {
        let state = lock(&self.state);
        let mut bundles: Vec<EvidenceBundle> = state
            .evidence
            .values()
            .map(|(_, bundle)| (**bundle).clone())
            .collect();
        bundles.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        bundles
    }

    /// `key`'s contribution tier now (`tier`): what its offers are ranked by first.
    pub fn tier_of(&self, key: &PublicKey, now: Judged) -> u32 {
        lock(&self.state).tier(key, now)
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
    ///
    /// Called only while the relay's clock judges (`network::Network::tick`): an offer's lifetime
    /// and a key's rank are times others signed, judged by `J`, so while it does not judge nothing
    /// expires, and what was last judged live is held and addressed (`address_of`). Its own
    /// offers and evidence are signed through the signer (`signer::Signer::with`). What it
    /// schedules for itself (re-signing, evidence, the trust and shunning of dialled addresses,
    /// deferred changes, resolving its host name) runs on `M`, so a step of `J` neither stops nor
    /// hurries any of it.
    pub fn tick(
        &self,
        hub: &Hub,
        signer: Option<&crate::signer::Signer>,
        at: impl Into<crate::sharing::Now>,
    ) -> Vec<Record> {
        let Some(signer) = signer else {
            return Vec::new();
        };
        let at: crate::sharing::Now = at.into();
        let now = at.judged();
        // What the directory schedules for itself (re-signing, evidence, dials, resolving) runs
        // on `M`; `J` only judges and signs.
        let mono = at.mono();
        let basis = own_basis(hub, &signer.public());
        let offering = basis.is_some();
        let mut out = Vec::new();
        let mut evidence = Vec::new();
        let mut resolve = None;
        let evidence_due = {
            let mut state = lock(&self.state);
            state.own = Some(signer.public());
            // The offers name the advertised address by number: a host name as it last resolved,
            // and nothing is signed (or withdrawn) before it first resolves.
            let mut unresolved = false;
            let basis = basis.and_then(|mut basis| {
                let (address, due) = state.own_address_of(&basis.address, mono);
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
            state.expire(now, mono);
            if !unresolved
                && let Some(offers) = crate::signer::with(signer, at, |signing| {
                    signing.and_then(|identity| state.resign(identity, basis, now, mono))
                })
            {
                out.extend(offers);
            }
            out.extend(
                std::mem::take(&mut state.gossip)
                    .into_values()
                    .map(|offer| offer.offer().clone()),
            );
            evidence.extend(
                std::mem::take(&mut state.evidence_gossip)
                    .into_values()
                    .map(|bundle| (*bundle).clone()),
            );
            offering
                && state
                    .own_evidence_at
                    .is_none_or(|at| mono.since(at) >= policy::<_, OWN_EVIDENCE_EVERY_MS>())
        };
        // The relay's own evidence goes with its offers, so every relay ranks them by the same
        // evidence (`State::tier`).
        if evidence_due
            && let Some(Ok(bundle)) = crate::signer::with(signer, at, |signing| {
                signing.map(|identity| hub.network().credit.bundle(identity, now))
            })
        {
            let mut state = lock(&self.state);
            state.own_evidence_at = Some(mono);
            if state.evidence(&bundle, now, None) {
                evidence.push(bundle);
            }
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // The advertised host name, resolved: the address its own offers name from then on,
            // which puts them in their group for every relay alike.
            if let Some(address) = resolve {
                lock(&self.state).own_resolving = Some((address.clone(), None));
                let state = Arc::clone(&self.state);
                let pinned = lock(&state).pinned(&address);
                runtime.spawn(async move {
                    let resolved = match pinned {
                        Some(address) => Some(address),
                        None => resolved_address(&address).await,
                    };
                    // By the clock of the tick that asked.
                    lock(&state).resolved(&address, resolved, mono);
                });
            }
            while let Some(pending) = self.next_to_verify() {
                let state = Arc::clone(&self.state);
                // The handshake's key, which signs no record.
                let identity = signer.handshake();
                let clock = self.clock.clone();
                runtime.spawn(async move {
                    let answered = answers_as(
                        &pending.offer.content().address,
                        &identity,
                        &pending.offer.signer(),
                    )
                    .await;
                    let read = clock.read();
                    lock(&state).verified(pending, answered, read.judged(), read.mono());
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
    pub async fn verify_pending(&self, identity: &impl tally_wire::Handshakes, now: Judged) {
        while let Some(pending) = self.next_to_verify() {
            let answered = answers_as(
                &pending.offer.content().address,
                identity,
                &pending.offer.signer(),
            )
            .await;
            let mono = self.clock.mono();
            lock(&self.state).verified(pending, answered, now, mono);
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

    /// Holds an offer as verified from `group`, without a dial: for the relay's own path and tests
    /// (also those of the integration suites, which have no peer to dial).
    #[doc(hidden)]
    pub fn hold_verified(
        &self,
        offer: ProviderOffer,
        group: Group,
        now: Judged,
    ) -> Result<bool, String> {
        let offer = checked(&offer, now).ok_or("not a live, signed offer")?;
        let mono = self.clock.mono();
        Ok(lock(&self.state).hold(offer, group, now, mono))
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
        now: Judged,
    ) -> bool {
        let offer = Checked(Arc::new(CheckedOffer {
            offer: stand_in.clone(),
            signer,
            content,
        }));
        let mono = self.clock.mono();
        lock(&self.state).hold(offer, group, now, mono)
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
async fn answers_as(
    address: &str,
    identity: &impl tally_wire::Handshakes,
    key: &PublicKey,
) -> bool {
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
    crate::sockets::configure(&stream, crate::sockets::Role::Feeder);
    matches!(
        noise::connect(stream, identity, key, tally_wire::Role::Subscriber).await,
        Ok(_) | Err(WireError::Refused { .. })
    )
}

/// What the relay's own offers should declare now, or `None` if it has nothing to offer (no
/// region taken, or no address advertised under its key, which no one could verify).
fn own_basis(hub: &Hub, own: &PublicKey) -> Option<Basis> {
    let network = hub.network();
    let own = *own;
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
        now: Judged,
        keep: impl Fn(&Held) -> bool,
    ) -> Vec<Checked> {
        let order = self.ranking(cell.as_u64(), now).to_vec();
        let Some(offers) = self.cells.get(&cell.as_u64()) else {
            return Vec::new();
        };
        order
            .iter()
            .filter_map(|key| offers.get(key))
            .filter(|held| !tally_wire::budget::expired(held.expires_ms, now) && keep(held))
            .take(OFFERS_PER_CELL)
            .map(|held| held.offer.clone())
            .collect()
    }

    /// Every offer held for `cell`, ranked (`ranked`): kept until the cell's offers or the tiers
    /// change.
    fn ranking(&mut self, cell: u64, now: Judged) -> &[PublicKey] {
        self.weigh_at(now);
        if !self.ranks.contains_key(&cell) {
            let keys: Vec<PublicKey> = self
                .cells
                .get(&cell)
                .map(|offers| offers.keys().copied().collect())
                .unwrap_or_default();
            let tiered: Vec<(PublicKey, u32)> = keys
                .into_iter()
                .map(|key| (key, self.tier(&key, now)))
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
    fn weigh_at(&mut self, now: Judged) -> Judged {
        let at = now.floor(policy::<_, WEIGHED_EVERY_MS>());
        if Some(at) != self.tiers_at {
            self.tiers_at = Some(at);
            self.clear_tiers();
        }
        at
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
        now: Judged,
    ) -> Standing {
        let tier = self.tier(&key, now);
        let depth = match with {
            Some((with_cell, with_key)) if with_cell == cell => {
                let mut keys: Vec<PublicKey> = self.ranking(cell, now).to_vec();
                if !keys.contains(&with_key) {
                    keys.push(with_key);
                }
                let tiered: Vec<(PublicKey, u32)> = keys
                    .into_iter()
                    .map(|one| (one, self.tier(&one, now)))
                    .collect();
                Region::from_u64(cell)
                    .map(|region| ranked(region, tiered))
                    .unwrap_or_default()
                    .iter()
                    .position(|one| *one == key)
            }
            _ => self.ranking(cell, now).iter().position(|one| *one == key),
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
    fn tier(&mut self, key: &PublicKey, now: Judged) -> u32 {
        let at = self.weigh_at(now);
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
            let feeder = |_: &credit::ShownFeeder| false;
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
    fn evidence(
        &mut self,
        bundle: &EvidenceBundle,
        now: Judged,
        pace: Option<&crate::ingest::RecordPace>,
    ) -> bool {
        let Ok(signer) = bundle.signer() else {
            return false;
        };
        let Ok(shown) = credit::check(bundle, now, pace) else {
            return false;
        };
        let newer = self
            .evidence
            .get(&signer)
            .is_none_or(|(held, _)| held.issued_ms() < shown.issued_ms());
        if !newer {
            return false;
        }
        // Held whether or not the signer's offer is yet (it may be waiting for its handshake), so
        // its offer is ranked by it on arrival; bounded in count and in bytes by rank
        // (`evidence_rank`): the room keeps the longest run of the evidence, this bundle in its
        // signer's place, in rank order that fits, and gives up the rest. Chosen before any goes,
        // so a bundle the room has no place for takes nobody's.
        let bundle = Arc::new(bundle.clone());
        let cost = evidence_cost(&shown, &bundle);
        let replaced = self
            .evidence
            .get(&signer)
            .map_or(0, |(held, held_bundle)| evidence_cost(held, held_bundle));
        let (per_key, own) = (&self.per_key, self.own);
        let rank = |key: PublicKey, cost: usize| {
            evidence_rank(Some(key) == own, per_key.contains_key(&key), cost, key)
        };
        let count = self.evidence.len() + usize::from(!self.evidence.contains_key(&signer));
        let (mut going, mut freed) = (Vec::new(), 0);
        if count > EVIDENCE_HELD || self.evidence_bytes - replaced + cost > self.evidence_room {
            let mut ranked: Vec<((u8, usize, PublicKey), usize)> = self
                .evidence
                .iter()
                .filter(|(key, _)| **key != signer)
                .map(|(key, (shown, held))| {
                    let cost = evidence_cost(shown, held);
                    (rank(*key, cost), cost)
                })
                .chain(std::iter::once((rank(signer, cost), cost)))
                .collect();
            ranked.sort_unstable();
            let (mut kept, mut bytes) = (0usize, 0usize);
            let mut fits = true;
            for ((_, _, key), cost) in ranked {
                fits = fits && kept < EVIDENCE_HELD && bytes + cost <= self.evidence_room;
                if fits {
                    kept += 1;
                    bytes += cost;
                } else if key == signer {
                    self.evidence_refused += 1;
                    return false;
                } else {
                    going.push(key);
                    freed += cost;
                }
            }
        }
        let after = self.evidence_bytes - replaced - freed + cost;
        if after > self.evidence_bytes
            && !self.evidence_charge.try_grow(after - self.evidence_bytes)
        {
            self.evidence_refused += 1;
            return false;
        }
        for key in going {
            self.forget_evidence(&key);
        }
        self.evidence_bytes = after;
        self.evidence_charge.shrink_to(self.evidence_bytes);
        let before = self.tier(&signer, now);
        self.evidence.insert(signer, (shown, Arc::clone(&bundle)));
        self.retier([signer]);
        // A key's evidence weighs in its own tier and no other's.
        if self.tier(&signer, now) != before {
            self.tiers_moved();
        }
        if Some(signer) != self.own {
            self.evidence_gossip.insert(signer, bundle);
        }
        true
    }

    /// Lets `key`'s evidence go, its room given back.
    fn drop_evidence(&mut self, key: &PublicKey) {
        self.forget_evidence(key);
        self.evidence_charge.shrink_to(self.evidence_bytes);
    }

    /// Lets `key`'s evidence go from what is held and counted, its charge left to the caller.
    fn forget_evidence(&mut self, key: &PublicKey) {
        if let Some((shown, bundle)) = self.evidence.remove(key) {
            self.evidence_bytes -= evidence_cost(&shown, &bundle);
            self.evidence_gossip.remove(key);
            self.retier([*key]);
        }
    }

    /// Queues `offer`, just held, to be gossiped at the next tick, within [`GOSSIP_HELD`]: in its
    /// cell and signer's place, a newer one taking the place of one still waiting.
    fn gossip(&mut self, offer: Checked) {
        let place = (offer.content().cell.as_u64(), offer.signer());
        if self.gossip.len() < GOSSIP_HELD || self.gossip.contains_key(&place) {
            self.gossip.insert(place, offer);
        } else {
            self.gossip_dropped += 1;
        }
    }

    fn offered(&mut self, asker: &Asker, offer: ProviderOffer, now: Judged, mono: Mono) {
        let hash = offer.hash();
        if self.seen.contains(&hash) {
            return;
        }
        self.seen.insert(&hash, mono);
        let Some(offer) = checked(&offer, now) else {
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
            .is_some_and(|until| !mono.reached(*until));
        if trusted {
            if self.hold(offer.clone(), group, now, mono) {
                self.gossip(offer);
            }
            return;
        }
        if self
            .unanswered
            .get(&content.address)
            .is_some_and(|until| !mono.reached(*until))
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

    /// A handshake's outcome, judged at `now` and remembered by `mono`.
    fn verified(&mut self, pending: Pending, answered: bool, now: Judged, mono: Mono) {
        let (signer, content) = (pending.offer.signer(), pending.offer.content());
        self.dialling.remove(&content.address);
        self.verifying = self.verifying.saturating_sub(1);
        // Only an offer in a group is queued (`offered`).
        match Group::of_address(&content.address).filter(|_| answered) {
            Some(group) => {
                self.verified.insert(
                    (signer, content.address.clone()),
                    mono.later(policy::<_, VERIFIED_FOR_MS>()),
                );
                // Checked when it came; only its lifetime may have run out since.
                if live(content, now) && self.hold(pending.offer.clone(), group, now, mono) {
                    self.gossip(pending.offer);
                }
            }
            None => {
                self.unanswered.insert(
                    content.address.clone(),
                    mono.later(policy::<_, UNANSWERED_FOR_MS>()),
                );
            }
        }
    }

    /// Holds a verified offer if the caps allow it, by rank (see the module). True when held
    /// (new, or newer for its key and cell); false when refused, or when it is a change that must
    /// wait its turn (`CHANGED_AT_MOST_EVERY_MS`), which is then held when due.
    fn hold(&mut self, offer: Checked, group: Group, now: Judged, mono: Mono) -> bool {
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
                    held.changed,
                    same_offer(held.offer.content(), &content),
                )
            });
        if let Some((newest_ms, held_issued_ms, held_group, held_changed, same)) = replacing {
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
            let due = held_changed.later(policy::<_, CHANGED_AT_MOST_EVERY_MS>());
            if Some(signer) != self.own && !mono.reached(due) {
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
                self.insert(offer, group, mono);
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
                        .map(|held| self.standing(held, Some((cell_key, signer)), now))
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
        self.insert(offer, group, mono);
        true
    }

    /// The changes whose turn has come (`CHANGED_AT_MOST_EVERY_MS`), held now; each held is
    /// gossiped, as an offer newly held is.
    fn apply_deferred(&mut self, now: Judged, mono: Mono) {
        while let Some((due, cell, key)) = self.deferred.first().copied() {
            if !mono.reached(due) {
                break;
            }
            self.deferred.pop_first();
            let waiting = self
                .cells
                .get_mut(&cell)
                .and_then(|offers| offers.get_mut(&key))
                .and_then(|held| held.deferred.take());
            if let Some((offer, group)) = waiting
                && live(offer.content(), now)
                && self.hold(offer.clone(), group, now, mono)
            {
                self.gossip(offer);
            }
        }
    }

    /// Holds `offer`, new for its signer and cell (or replacing one `remove`d): what the held
    /// offers answer changes. A re-signing that says the same is `renew`ed instead.
    fn insert(&mut self, offer: Checked, group: Group, changed: Mono) {
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
                changed,
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
        // Its gossip, if it waits, goes with it: what is gossiped is what is held.
        self.gossip.remove(&(cell_key, *signer));
        keep_within(cell);
        if cell.is_empty() {
            self.cells.remove(&cell_key);
        }
        // A change of it waiting goes with it.
        if held.deferred.is_some() {
            self.deferred.remove(&(
                held.changed.later(policy::<_, CHANGED_AT_MOST_EVERY_MS>()),
                cell_key,
                *signer,
            ));
        }
        if let Some(cells) = self.per_key.get_mut(signer) {
            cells.remove(&cell_key);
            keep_set_within(cells);
            if cells.is_empty() {
                self.per_key.remove(signer);
            }
        }
        if let Some(offers) = self.per_group.get_mut(&held.group) {
            offers.remove(&(cell_key, *signer));
            keep_set_within(offers);
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
        if self.changed.len() < CHANGED_HELD {
            self.changed.insert(cell_key);
        } else if !self.changed.contains(&cell_key) {
            self.changed_all = true;
        }
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
    fn roll_tiers(&mut self, now: Judged) {
        let now_ms = now.ms();
        let at = now_ms - now_ms % WEIGHED_EVERY_MS;
        if at == self.rolled_at {
            return;
        }
        self.rolled_at = at;
        let keys: Vec<PublicKey> = self.evidence.keys().copied().collect();
        let mut tiers: Vec<(PublicKey, u32)> = keys
            .into_iter()
            .map(|key| (key, self.tier(&key, now)))
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
    fn expire_offers(&mut self, now: Judged) {
        if self
            .expiries
            .first_key_value()
            .is_none_or(|(at, _)| !tally_wire::budget::expired(*at, now))
        {
            return;
        }
        let expired: Vec<(u64, PublicKey)> = self
            .cells
            .iter()
            .flat_map(|(cell, offers)| {
                offers
                    .iter()
                    .filter(|(_, held)| tally_wire::budget::expired(held.expires_ms, now))
                    .map(move |(key, _)| (*cell, *key))
            })
            .collect();
        for (cell, key) in expired {
            self.remove(cell, &key);
        }
    }

    /// Forgets every offer expired at `now_ms`, and the addresses no longer trusted or shunned.
    fn expire(&mut self, now: Judged, mono: Mono) {
        self.apply_deferred(now, mono);
        self.expire_offers(now);
        // Evidence is held for the relays whose offers are held, and for one whose offer has not
        // come for a while (its handshake under way) until its offer would have.
        let own = self.own;
        let per_key = &self.per_key;
        let dropped: Vec<PublicKey> = self
            .evidence
            .iter()
            .filter(|(key, (shown, _))| {
                Some(**key) != own
                    && !per_key.contains_key(key)
                    && tally_wire::budget::EVIDENCE_AWAITED.older(shown.issued_ms(), now)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in dropped {
            self.drop_evidence(&key);
        }
        keep_within(&mut self.evidence);
        while self
            .verified
            .first()
            .is_some_and(|(_, until)| mono.reached(*until))
        {
            self.verified.pop_first();
        }
        while self
            .unanswered
            .first()
            .is_some_and(|(_, until)| mono.reached(*until))
        {
            self.unanswered.pop_first();
        }
    }

    /// The relay's own offers, re-signed when what they declare changed (at most every
    /// `OWN_RESIGN_AT_MOST_EVERY_MS`) or every `OWN_RESIGN_EVERY_MS`, and held as its own;
    /// cells no longer taken are withdrawn. `Some` with what to gossip when re-signed.
    fn resign(
        &mut self,
        identity: &impl Signs,
        basis: Option<Basis>,
        now: Judged,
        mono: Mono,
    ) -> Option<Vec<ProviderOffer>> {
        let now_ms = now.ms();
        let own = identity.public();
        let changed = match (&basis, &self.own_basis) {
            (Some(new), Some(old)) => !new.same(old),
            (None, None) => false,
            _ => true,
        };
        let since = self
            .own_signed
            .map_or(u64::MAX, |signed| mono.since(signed).ms());
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
        self.own_signed = Some(mono);
        self.own_basis.clone_from(&basis);
        self.own_offers.clear();
        let Some(basis) = basis else {
            self.set_own_group(None, now, mono);
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
            self.seen.insert(&offer.hash(), mono);
            let Some(checked) = checked(&offer, now) else {
                continue;
            };
            self.own_offers.push(checked);
            // Gossiped whether or not held here: each peer holds it by its own caps, as this
            // relay does, from the same offers.
            signed.push(offer);
        }
        // Held under the group of the address they name, as every peer holds them.
        self.set_own_group(group, now, mono);
        Some(signed)
    }

    /// The address the relay's own offers name for its advertised `address`: one named by number
    /// is itself; a host name the address it last resolved to. `true` when it is to be resolved
    /// now (never resolved, or resolved over `VERIFIED_FOR_MS` ago), and no resolution of it is
    /// under way.
    fn own_address_of(&self, address: &str, mono: Mono) -> (Option<std::net::SocketAddr>, bool) {
        if let Ok(address) = address.parse::<std::net::SocketAddr>() {
            return (Some(address), false);
        }
        let resolved = self
            .own_resolved
            .as_ref()
            .filter(|(name, _, _)| name == address);
        let resolving = self.own_resolving.as_ref().is_some_and(|(name, again)| {
            name == address && again.is_none_or(|at| !mono.reached(at))
        });
        let due = resolved.is_none_or(|(_, _, until)| mono.reached(*until));
        (
            resolved.map(|(_, resolved, _)| *resolved),
            due && !resolving,
        )
    }

    /// `address` resolved to `resolved` (none: it did not resolve, and is tried again
    /// `RESOLVE_AGAIN_MS` on, the address it last resolved to still named): the relay's own
    /// offers name it from their next signing, by the tick's clock (`own_address_of`).
    fn resolved(&mut self, address: &str, resolved: Option<std::net::SocketAddr>, mono: Mono) {
        let Some(resolved) = resolved else {
            self.own_resolving = Some((
                address.to_owned(),
                Some(mono.later(policy::<_, RESOLVE_AGAIN_MS>())),
            ));
            return;
        };
        if self
            .own_resolving
            .as_ref()
            .is_some_and(|(name, _)| name == address)
        {
            self.own_resolving = None;
        }
        self.own_resolved = Some((
            address.to_owned(),
            resolved,
            mono.later(policy::<_, VERIFIED_FOR_MS>()),
        ));
    }

    /// The relay's own offers are in `group` from now on (the group of the address they name):
    /// they leave the one they were held under and are held under this one by its caps. The
    /// relay's own network is also one no witness of its own may come from (`State::tier`), which
    /// its offers' group says.
    fn set_own_group(&mut self, group: Option<Group>, now: Judged, mono: Mono) {
        if self.own_group == group {
            self.hold_own(now, mono);
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
        self.hold_own(now, mono);
    }

    /// Holds the relay's own offers as last signed under its own group, by every cap, as a peer
    /// that verified them there holds them: one held already is left as it is. None while the
    /// group is not known.
    fn hold_own(&mut self, now: Judged, mono: Mono) {
        let (Some(own), Some(group)) = (self.own, self.own_group) else {
            return;
        };
        for offer in self.own_offers.clone() {
            let content = offer.content();
            let cell = content.cell.as_u64();
            let held = self.cells.get(&cell).and_then(|offers| offers.get(&own));
            if !live(content, now)
                || held
                    .is_some_and(|held| held.group == group && held.issued_ms >= content.issued_ms)
            {
                continue;
            }
            if held.is_some_and(|held| held.group != group) {
                self.remove(cell, &own);
            }
            self.hold(offer, group, now, mono);
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
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use super::*;
    use std::net::Ipv4Addr;
    use tally_wire::Identity;
    use tally_wire::Location;
    use tally_wire::clocks::recorded::judged;
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
            address: None,
        }
    }

    fn v4(a: u8, b: u8) -> Group {
        Group::of(IpAddr::V4(Ipv4Addr::new(a, b, 1, 1)))
    }

    /// A Noise responder on loopback answering as `identities`, for as long as the test runs.
    async fn answering(identities: Vec<Identity>) -> std::result::Result<String, String> {
        let identities: Vec<tally_wire::NoiseKey> = identities
            .into_iter()
            .map(tally_wire::NoiseKey::of)
            .collect();
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
        let honest_at = answering(vec![crate::signer::twin(&honest)]).await?;
        // The impostor's address answers, but as another key.
        let impostor_at = answering(vec![Identity::generate().map_err(text)?]).await?;
        let directory = Directory::new();
        let cell = area()?;
        let good = sign(&honest, &content(&honest_at, cell, NOW))?;
        let lying = sign(&impostor, &content(&impostor_at, cell, NOW))?;
        directory.offered(&relay_asker(honest.public()), good.clone(), judged(NOW));
        directory.offered(&relay_asker(honest.public()), lying.clone(), judged(NOW));
        assert!(directory.is_empty(), "nothing held before the handshake");
        directory.verify_pending(&local, judged(NOW)).await;
        assert_eq!(directory.offers_for(cell, judged(NOW)), vec![good.clone()]);
        // Gossiped once, at the next tick; a second offer of the same bytes is not acted on.
        let gossip: Vec<ProviderOffer> = directory
            .state
            .lock()
            .map_err(text)?
            .gossip
            .values()
            .map(|offer| offer.offer().clone())
            .collect();
        assert_eq!(gossip, vec![good.clone()]);
        directory.state.lock().map_err(text)?.gossip.clear();
        directory.offered(&relay_asker(honest.public()), good, judged(NOW));
        assert!(directory.state.lock().map_err(text)?.gossip.is_empty());
        // The impostor's address is not dialled again for a while, even for a new offer.
        let again = sign(&impostor, &content(&impostor_at, cell, NOW + 1))?;
        directory.offered(&relay_asker(honest.public()), again, judged(NOW + 1));
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // A re-signed offer from a key already verified there is held without a dial.
        let renewed = sign(&honest, &content(&honest_at, cell, NOW + 60_000))?;
        directory.offered(
            &relay_asker(honest.public()),
            renewed.clone(),
            judged(NOW + 60_000),
        );
        assert_eq!(
            directory.offers_for(cell, judged(NOW + 60_000)),
            vec![renewed]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_forged_an_expired_and_an_unanswering_offer_are_not_held() -> Result {
        let local = Identity::generate().map_err(text)?;
        let relay = Identity::generate().map_err(text)?;
        let at = answering(vec![crate::signer::twin(&relay)]).await?;
        let directory = Directory::new();
        let cell = area()?;
        let asker = relay_asker(relay.public());
        // Forged: one byte of the signed body changed.
        let good = sign(&relay, &content(&at, cell, NOW))?;
        let mut bytes = good.as_bytes().to_vec();
        let at_byte = bytes.len() - 70;
        bytes[at_byte] ^= 1;
        let forged = ProviderOffer::from_bytes(bytes).map_err(text)?;
        directory.offered(&asker, forged, judged(NOW));
        // Expired by this relay's clock, and issued too far in the future.
        let old = sign(&relay, &content(&at, cell, NOW - 20 * 60 * 1000))?;
        directory.offered(&asker, old, judged(NOW));
        let future = sign(
            &relay,
            &content(
                &at,
                cell,
                NOW + 2 * tally_wire::budget::K
                    .span::<tally_wire::clocks::Judged>()
                    .ms(),
            ),
        )?;
        directory.offered(&asker, future, judged(NOW));
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // Nobody listening at the address.
        let closed = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
        let nowhere = closed.local_addr().map_err(text)?.to_string();
        drop(closed);
        let silent = Identity::generate().map_err(text)?;
        directory.offered(
            &relay_asker(silent.public()),
            sign(&silent, &content(&nowhere, cell, NOW))?,
            judged(NOW),
        );
        directory.verify_pending(&local, judged(NOW)).await;
        assert!(directory.is_empty());
        // An offer expires while held.
        directory.offered(&asker, good, judged(NOW));
        directory.verify_pending(&local, judged(NOW)).await;
        assert_eq!(directory.len(), 1);
        directory
            .state
            .lock()
            .map_err(text)?
            .expire(judged(NOW + 10 * 60 * 1000), directory.clock.mono());
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
    type Step<'a> = Box<dyn Fn(&Directory) -> Result + 'a>;

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
            let mut steps: Vec<Step<'_>> = Vec::new();
            for (at, (child_set, relay)) in children.iter().zip(&honest).enumerate() {
                for (index, child) in child_set.iter().enumerate() {
                    steps.push(Box::new(move |directory: &Directory| {
                        let offer = sign(child, &content("child.example:1", elsewhere, NOW))?;
                        directory.hold_verified(
                            offer,
                            v4(20 + at as u8, index as u8),
                            judged(NOW),
                        )?;
                        Ok(())
                    }));
                }
                steps.push(Box::new(move |directory: &Directory| {
                    let offer = sign(relay, &content("honest.example:1", cell, NOW))?;
                    directory.hold_verified(offer, v4(10, at as u8), judged(NOW))?;
                    directory.evidence(&evidence_of(relay, child_set, 10_000)?, judged(NOW), None);
                    Ok(())
                }));
            }
            for (index, child) in one_network.iter().enumerate() {
                steps.push(Box::new(move |directory: &Directory| {
                    let offer = sign(child, &content("one.example:1", elsewhere, NOW))?;
                    // Every one of them on one network.
                    directory.hold_verified(offer, v4(30, 0), judged(NOW + index as u64))?;
                    Ok(())
                }));
            }
            for (index, key) in ground.iter().enumerate() {
                let (free, one_network) = (&free, &one_network);
                steps.push(Box::new(move |directory: &Directory| {
                    let offer = sign(key, &content("ground.example:1", cell, NOW))?;
                    directory.hold_verified(
                        offer,
                        v4(100 + (index / 200) as u8, index as u8),
                        judged(NOW),
                    )?;
                    match index % 3 {
                        0 => {}
                        1 => {
                            directory.evidence(
                                &evidence_of(key, free, 1_000_000)?,
                                judged(NOW),
                                None,
                            );
                        }
                        _ => {
                            directory.evidence(
                                &evidence_of(key, one_network, 1_000_000)?,
                                judged(NOW),
                                None,
                            );
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
                directory.hold_verified(offer, group, judged(NOW + 1))?;
            }
            Ok(directory
                .offers_for(cell, judged(NOW + 2))
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
            one.hold_verified(offer, v4(30, 0), judged(NOW + index as u64))?;
        }
        let witness = &ground[2];
        one.hold_verified(
            sign(witness, &content("ground.example:1", cell, NOW))?,
            v4(99, 0),
            judged(NOW),
        )?;
        one.evidence(
            &evidence_of(witness, &one_network, 1_000_000)?,
            judged(NOW),
            None,
        );
        assert_eq!(one.tier_of(&witness.public(), judged(NOW)), tier(1));
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
                directory.hold_verified(offer, v4(20, index as u8), judged(NOW))?;
            }
            for (at, relay) in honest.iter().enumerate() {
                // One core each: the least a relay offering MLAT can name.
                let mut offered = content("honest.example:1", cell, NOW);
                offered.mlat_cores = 1;
                directory.hold_verified(sign(relay, &offered)?, v4(10, at as u8), judged(NOW))?;
                if evidenced {
                    directory.evidence(&evidence_of(relay, &children, 10_000)?, judged(NOW), None);
                }
            }
            for (index, key) in ground.iter().enumerate() {
                let mut lure = content("ground.example:1", cell, NOW);
                lure.mlat_cores = u16::MAX;
                directory.hold_verified(
                    sign(key, &lure)?,
                    v4(100 + (index / 200) as u8, index as u8),
                    judged(NOW),
                )?;
            }
            Ok(crate::selection::mlat_relays(cell, &directory, judged(NOW)))
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
        directory.hold_verified(offer, v4(1, 1), judged(NOW))?;
        let held = |at: u64| !directory.offers_for(cell, judged(at)).is_empty();
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
            address: None,
        };
        directory.offered(&client, offer.clone(), judged(NOW));
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // The relay's own offer, come back round a gossip loop.
        let mine = sign(&own, &content("192.0.2.8:7450", cell, NOW))?;
        directory.offered(&relay_asker(other.public()), mine, judged(NOW));
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        // A client announcing its own offer is queued.
        let announcing = Asker {
            key: other.public(),
            ..client
        };
        let fresh = sign(&other, &content("192.0.2.7:7450", cell, NOW + 1))?;
        directory.offered(&announcing, fresh, judged(NOW + 1));
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
            directory.hold_verified(offer, v4(10, 0), judged(NOW))?;
        }
        assert_eq!(directory.len(), OFFERS_PER_GROUP_IN_CELL);
        // From many groups: the cell holds at most its cap.
        for seed in 0..400_u32 {
            let mut bytes = [7; 32];
            bytes[..4].copy_from_slice(&seed.to_be_bytes());
            let key = Identity::from_seed(bytes);
            let offer = sign(&key, &content("flood.example:1", cell, NOW))?;
            directory.hold_verified(offer, v4(11, seed as u8), judged(NOW))?;
        }
        assert_eq!(
            directory.offers_for(cell, judged(NOW)).len(),
            OFFERS_PER_CELL
        );
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
            if directory.hold_verified(
                sign(&busy, &content)?,
                v4(12, (index % 200) as u8),
                judged(NOW),
            )? {
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
            assert!(directory.hold_verified(offer, v4(1, index), judged(NOW))?);
        }
        // An attacker with 1,000 keys from two networks, each offer with every MLAT core it can
        // name.
        for seed in 0..1_000_u32 {
            let mut bytes = [5; 32];
            bytes[..4].copy_from_slice(&seed.to_be_bytes());
            let attacker = Identity::from_seed(bytes);
            let mut lure = content("attacker.example:1", cell, NOW);
            lure.mlat_cores = u16::MAX;
            directory.hold_verified(
                sign(&attacker, &lure)?,
                v4(200, (seed % 2) as u8),
                judged(NOW),
            )?;
        }
        let held = directory.offers_for(cell, judged(NOW));
        assert_eq!(held.len(), honest.len() + 2 * OFFERS_PER_GROUP_IN_CELL);
        for relay in &honest {
            assert!(
                held.iter().any(|offer| offer.signer() == relay.public()),
                "an honest relay was displaced"
            );
        }
        // The MLAT choice still ranks every relay held, each counted for at most
        // `MLAT_CORES_COUNTED` cores whatever it names.
        let chosen = crate::selection::mlat_relays(cell, &directory, judged(NOW));
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
            directory.hold_unsigned(&stand_in, *key, content.clone(), *group, judged(NOW));
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

    /// A full cap over many cells (a network group's, a key's) gives up the
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

    /// The directory's own bound (`OFFERS_HELD`) gives up the lowest-ranked
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

    /// A peer re-signing changed offers in a loop changes what its readers
    /// see at most once per `CHANGED_AT_MOST_EVERY_MS` per (key, cell); the newest change waiting
    /// is held when its turn comes, and a re-signing that changes nothing is held at once.
    #[test]
    fn a_peer_re_signing_changes_in_a_loop_costs_its_readers_once_a_turn() -> Result {
        let relay = Identity::from_seed([31; 32]);
        let cell = area()?;
        // Both clocks at `at`: a change's turn is the directory's own, by `M`.
        let at = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
        let read = Arc::clone(&at);
        let directory = Directory::on(crate::clock::RelayClock::scripted(Arc::new(move || {
            read.load(std::sync::atomic::Ordering::Relaxed)
        })));
        let set = |ms: u64| at.store(ms, std::sync::atomic::Ordering::Relaxed);
        let first = sign(&relay, &content("r.example:1", cell, NOW))?;
        assert!(directory.hold_verified(first, v4(1, 1), judged(NOW))?);
        assert_eq!(directory.take_changed_cells(judged(NOW)), vec![cell]);
        let version = directory.version(judged(NOW));
        let mut newest = None;
        for step in 1..=200_u64 {
            let mut changed = content("r.example:1", cell, NOW + step);
            // Never the 8 cores first held: each says something new.
            changed.mlat_cores = (step % 60) as u16 + 9;
            let offer = sign(&relay, &changed)?;
            // Every 10 ms: deferred, and no reader is told.
            set(NOW + step * 10);
            assert!(!directory.hold_verified(offer.clone(), v4(1, 1), judged(NOW + step * 10))?);
            newest = Some(offer);
        }
        assert_eq!(directory.version(judged(NOW + 2_000)), version);
        assert!(directory.take_changed_cells(judged(NOW + 2_000)).is_empty());
        // Its turn: the newest change is held, told once, and gossiped once.
        let due = NOW + CHANGED_AT_MOST_EVERY_MS;
        set(due);
        directory
            .state
            .lock()
            .map_err(text)?
            .expire(judged(due), directory.clock.mono());
        let newest = newest.ok_or("no change")?;
        assert_eq!(
            directory.offers_for(cell, judged(due)),
            vec![newest.clone()]
        );
        assert_eq!(directory.take_changed_cells(judged(due)), vec![cell]);
        assert_eq!(
            directory
                .state
                .lock()
                .map_err(text)?
                .gossip
                .values()
                .map(|offer| offer.offer().clone())
                .collect::<Vec<_>>(),
            vec![newest.clone()]
        );
        // A re-signing saying the same, its turn come (`RESIGNED_AT_MOST_EVERY_MS` by the signed
        // times), is held at once, and tells no reader.
        let mut same = newest.content().map_err(text)?;
        same.issued_ms += RESIGNED_AT_MOST_EVERY_MS;
        let quiet = sign(&relay, &same)?;
        set(due + 1);
        assert!(directory.hold_verified(quiet.clone(), v4(1, 1), judged(due + 1))?);
        assert_eq!(directory.offers_for(cell, judged(due + 1)), vec![quiet]);
        assert!(directory.take_changed_cells(judged(due + 1)).is_empty());
        // And the next change waits its turn from the last.
        let mut later = same.clone();
        later.issued_ms += 1;
        later.mlat_cores = 99;
        set(due + 2);
        assert!(!directory.hold_verified(sign(&relay, &later)?, v4(1, 1), judged(due + 2))?);
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
                directory.hold_verified(offer.clone(), *group, judged(NOW))?;
            }
            let mut keys: Vec<PublicKey> = directory
                .offers_for(cell, judged(NOW))
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
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![
            tally_wire::RelayAddress {
                key: identity.public(),
                address: "me.example:7450".to_owned(),
            },
        ]);
        let cell = area()?;
        hub.network().selection.set_taken(vec![cell]);
        let sharing = &hub.network().sharing;
        assert_ne!(forwarded_stripes(sharing, cell, &identity.public()), 0);
        // The egress sheds a forwarding peer: the relay withdraws its one region.
        let _ = sharing.tick_shed(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            0,
            NOW,
        );
        let _ = sharing.tick_shed(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            1,
            NOW + 1_000,
        );
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
            directory.hold_verified(offer.clone(), v4(2, index), judged(NOW))?;
        }
        let answer = directory.query(
            &ProviderQuery {
                cell,
                products: Streams(0),
            },
            judged(NOW),
        );
        // The cell's own and its parent's, finest first; not the finer cell's.
        assert_eq!(answer, vec![offers[0].clone(), offers[1].clone()]);
        assert_eq!(directory.offers_for(cell, judged(NOW)), answer);
        // Products filter.
        let none = directory.query(
            &ProviderQuery {
                cell,
                products: Streams::WORLD,
            },
            judged(NOW),
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
                    judged(NOW + 11 * 60 * 1000),
                )
                .is_empty()
        );
        Ok(())
    }

    /// RFC-0171 §3.6: the relay signs no offer and no evidence while its clock is unsynced
    /// (`signer::Signer::with`); its offer goes out at the first tick after it is synced.
    /// Before, the directory held the key itself and signed by whatever the clock read.
    #[test]
    fn the_relay_offers_nothing_while_its_clock_is_unsynced() -> Result {
        let identity = Identity::generate().map_err(text)?;
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![
            tally_wire::RelayAddress {
                key: identity.public(),
                address: "198.51.100.7:7450".to_owned(),
            },
        ]);
        hub.network().selection.set_taken(vec![area()?]);
        hub.network().admission.configure(64_496, true);
        let directory = Directory::new();
        let clock = crate::clock::RelayClock::scripted(Arc::new(|| NOW));
        let signer = crate::signer::on(identity, clock.clone());
        clock.set_error(None);
        assert!(
            directory
                .tick(&hub, Some(&signer), crate::sharing::Now::from(NOW))
                .is_empty()
        );
        clock.set_error(Some(5));
        let published = directory.tick(&hub, Some(&signer), crate::sharing::Now::from(NOW + 1_000));
        assert!(
            published
                .iter()
                .any(|record| matches!(record, Record::ProviderOffer(_))),
            "{published:?}"
        );
        Ok(())
    }

    /// What a dial found out is remembered by `M`: an address that did not answer is dialled
    /// again `UNANSWERED_FOR_MS` on whatever the judging clock stepped back meanwhile, and one that
    /// answered stays trusted for `VERIFIED_FOR_MS` whatever it stepped ahead. Before, both were
    /// spans of `J`: an hour's step back shunned an honest relay's address for the hour, and a
    /// step ahead dropped every trust at once.
    #[test]
    fn a_dials_outcome_is_remembered_by_the_monotonic_clock() -> Result {
        use tally_wire::clocks::recorded::mono;
        let cell = area()?;
        let (silent, honest) = (Identity::from_seed([95; 32]), Identity::from_seed([96; 32]));
        let pending =
            |identity: &Identity, address: &str| -> std::result::Result<Pending, String> {
                let offer = sign(identity, &content(address, cell, NOW))?;
                Ok(Pending {
                    offer: checked(&offer, judged(NOW)).ok_or("unchecked")?,
                    asker: identity.public(),
                })
            };
        let mut state = State::default();
        state.verified(
            pending(&silent, "198.51.100.8:7450")?,
            false,
            judged(NOW),
            mono(NOW),
        );
        state.verified(
            pending(&honest, "198.51.100.9:7450")?,
            true,
            judged(NOW),
            mono(NOW),
        );
        // The judging clock an hour ahead, `M` a second on: still trusted, still shunned.
        state.expire(judged(NOW + 3_600_000), mono(NOW + 1_000));
        assert_eq!((state.verified.len(), state.unanswered.len()), (1, 1));
        // The judging clock an hour back, `M` past the shunning: dialled again, still trusted.
        state.expire(judged(NOW - 3_600_000), mono(NOW + UNANSWERED_FOR_MS));
        assert_eq!((state.verified.len(), state.unanswered.len()), (1, 0));
        state.expire(judged(NOW - 3_600_000), mono(NOW + VERIFIED_FOR_MS));
        assert_eq!(state.verified.len(), 0);
        Ok(())
    }

    /// The evidence held is bounded in bytes, not only in count: past its room the evidence of a
    /// signer with no offer held goes first, by rank (the costlier, then the greater key), and
    /// with none such a new bundle is refused, counted; what is held is charged to the store, and
    /// let go is given back. Before, 16,384 bundles of up to a record's size each were held,
    /// charged to nothing.
    #[test]
    fn the_evidence_held_stays_within_its_room_and_its_charge() -> Result {
        let gauge = Gauge::new(crate::budget::Store::Directory, PLANNED_BYTES);
        let directory = Directory::new();
        directory.charge_to(&gauge);
        let children: Vec<Identity> = (0..4_u8)
            .map(|n| Identity::from_seed([120 + n; 32]))
            .collect();
        let relays: Vec<Identity> = (0..12_u8)
            .map(|n| Identity::from_seed([140 + n; 32]))
            .collect();
        let bundles: Vec<EvidenceBundle> = relays
            .iter()
            .map(|relay| evidence_of(relay, &children, 10_000))
            .collect::<std::result::Result<_, String>>()?;
        let cost = {
            let shown = credit::check(&bundles[0], judged(NOW), None).map_err(text)?;
            evidence_cost(&shown, &bundles[0])
        };
        // Room for four.
        lock(&directory.state).evidence_room = 4 * cost + cost / 2;
        // Two of them hold offers.
        for relay in &relays[..2] {
            directory.hold_unsigned(
                &sign(relay, &content("198.51.100.1:7450", area()?, NOW))?,
                relay.public(),
                content("198.51.100.1:7450", area()?, NOW),
                v4(10, 1),
                judged(NOW),
            );
        }
        for bundle in &bundles[..4] {
            assert!(directory.evidence(bundle, judged(NOW), None));
        }
        // Full: each new one is ranked with those without an offer, all of a cost, by key.
        for bundle in &bundles[4..8] {
            directory.evidence(bundle, judged(NOW), None);
        }
        {
            let state = lock(&directory.state);
            assert!(state.evidence_bytes <= state.evidence_room);
            for relay in &relays[..2] {
                assert!(
                    state.evidence.contains_key(&relay.public()),
                    "a held offer's evidence went"
                );
            }
            let mut strangers: Vec<PublicKey> = relays[2..8].iter().map(Identity::public).collect();
            strangers.sort_unstable();
            for (at, key) in strangers.iter().enumerate() {
                assert_eq!(state.evidence.contains_key(key), at < 2, "{at}");
            }
            assert_eq!(state.evidence.len(), 4);
            assert_eq!(state.evidence_charge.bytes(), state.evidence_bytes);
        }
        let (charged, _, _) = directory.evidence_held();
        assert_eq!(gauge.held(), TABLES_PLANNED_BYTES + charged);
        // Every one left holds an offer: a new one is refused, counted.
        for relay in &relays[4..8] {
            directory.hold_unsigned(
                &sign(relay, &content("198.51.100.2:7450", area()?, NOW))?,
                relay.public(),
                content("198.51.100.2:7450", area()?, NOW),
                v4(10, 2),
                judged(NOW),
            );
        }
        let held: Vec<PublicKey> = lock(&directory.state).evidence.keys().copied().collect();
        for key in &held {
            let relay = relays
                .iter()
                .find(|relay| relay.public() == *key)
                .ok_or("unknown")?;
            if !lock(&directory.state).per_key.contains_key(key) {
                directory.hold_unsigned(
                    &sign(relay, &content("198.51.100.3:7450", area()?, NOW))?,
                    relay.public(),
                    content("198.51.100.3:7450", area()?, NOW),
                    v4(10, 3),
                    judged(NOW),
                );
            }
        }
        let refused = directory.evidence_held().1;
        assert!(!directory.evidence(&bundles[8], judged(NOW), None));
        assert_eq!(directory.evidence_held().1, refused + 1);
        Ok(())
    }

    /// A bundle the store has no room for takes nobody's place: whose evidence would make way for
    /// it is chosen first, and none goes unless the store can hold what it then holds. Four held,
    /// a fifth larger, the room enough once the oldest goes, and the store exactly full: the fifth
    /// is refused, counted, and all four stay. Before, the oldest was let go first, then the
    /// store refused the fifth, and a signer's evidence was lost for nothing.
    #[test]
    fn a_bundle_the_store_cannot_hold_takes_no_signers_place() -> Result {
        let children: Vec<Identity> = (0..8_u8)
            .map(|n| Identity::from_seed([120 + n; 32]))
            .collect();
        let relays: Vec<Identity> = (0..5_u8)
            .map(|n| Identity::from_seed([160 + n; 32]))
            .collect();
        let mut bundles: Vec<EvidenceBundle> = relays[..4]
            .iter()
            .map(|relay| evidence_of(relay, &children[..4], 10_000))
            .collect::<std::result::Result<_, String>>()?;
        bundles.push(evidence_of(&relays[4], &children, 10_000)?);
        let cost = |bundle: &EvidenceBundle| -> std::result::Result<usize, String> {
            let shown = credit::check(bundle, judged(NOW), None).map_err(text)?;
            Ok(evidence_cost(&shown, bundle))
        };
        let (small, large) = (cost(&bundles[0])?, cost(&bundles[4])?);
        assert!(large > small);
        let gauge = Gauge::new(crate::budget::Store::Directory, 4 * small);
        let directory = Directory::new();
        directory.charge_to(&gauge);
        lock(&directory.state).evidence_room = 3 * small + large;
        for bundle in &bundles[..4] {
            assert!(directory.evidence(bundle, judged(NOW), None));
        }
        assert_eq!(gauge.held(), 4 * small);
        assert!(!directory.evidence(&bundles[4], judged(NOW), None));
        assert_eq!(directory.evidence_held().1, 1, "not counted refused");
        let state = lock(&directory.state);
        for relay in &relays[..4] {
            assert!(
                state.evidence.contains_key(&relay.public()),
                "a signer's evidence went for a bundle refused"
            );
        }
        assert_eq!(state.evidence_bytes, 4 * small);
        assert_eq!(gauge.held(), 4 * small);
        Ok(())
    }

    /// Two relays given the same bundles in different orders hold the same evidence: the room
    /// keeps them by rank (`evidence_rank`: an offer held first, then the cheaper, then by key),
    /// never by when they came. Before, past the room a new bundle was refused whenever every
    /// holder had an offer held, and otherwise took the oldest's place, so relays ranked offers by
    /// different evidence.
    #[test]
    fn relays_given_the_same_bundles_in_any_order_hold_the_same_evidence() -> Result {
        let children: Vec<Identity> = (0..4_u8)
            .map(|n| Identity::from_seed([120 + n; 32]))
            .collect();
        let relays: Vec<Identity> = (0..12_u8)
            .map(|n| Identity::from_seed([170 + n; 32]))
            .collect();
        let bundles: Vec<EvidenceBundle> = relays
            .iter()
            .enumerate()
            .map(|(n, relay)| evidence_of(relay, &children[..1 + n % 4], 10_000))
            .collect::<std::result::Result<_, String>>()?;
        let costs: Vec<usize> = bundles
            .iter()
            .map(|bundle| {
                credit::check(bundle, judged(NOW), None)
                    .map(|shown| evidence_cost(&shown, bundle))
                    .map_err(text)
            })
            .collect::<std::result::Result<_, String>>()?;
        let room = costs.iter().sum::<usize>() / 2;
        let held_after = |order: &[usize]| -> std::result::Result<BTreeSet<PublicKey>, String> {
            let directory = Directory::new();
            lock(&directory.state).evidence_room = room;
            // Three of them hold offers, the costliest of them among them.
            for relay in [&relays[3], &relays[5], &relays[8]] {
                directory.hold_unsigned(
                    &sign(relay, &content("198.51.100.1:7450", area()?, NOW))?,
                    relay.public(),
                    content("198.51.100.1:7450", area()?, NOW),
                    v4(10, 1),
                    judged(NOW),
                );
            }
            for at in order {
                directory.evidence(&bundles[*at], judged(NOW), None);
            }
            let state = lock(&directory.state);
            assert!(state.evidence_bytes <= state.evidence_room);
            Ok(state.evidence.keys().copied().collect())
        };
        let forward: Vec<usize> = (0..bundles.len()).collect();
        let reverse: Vec<usize> = forward.iter().rev().copied().collect();
        let mixed: Vec<usize> = forward
            .iter()
            .map(|n| (n * 5 + 3) % bundles.len())
            .collect();
        let held = held_after(&forward)?;
        assert_eq!(held_after(&reverse)?, held);
        assert_eq!(held_after(&mixed)?, held);
        // A held offer's evidence before any other's, and the cheapest of the rest.
        for relay in [&relays[3], &relays[5], &relays[8]] {
            assert!(held.contains(&relay.public()));
        }
        assert!(held.len() > 3 && held.len() < bundles.len());
        let cheapest = (0..bundles.len())
            .filter(|n| ![3, 5, 8].contains(n))
            .min_by_key(|n| (costs[*n], relays[*n].public()))
            .ok_or("none")?;
        assert!(held.contains(&relays[cheapest].public()));
        Ok(())
    }

    /// The offer hashes acted on are remembered a generation's span after the newest came, and
    /// let go whole a generation at a time: a hash is remembered for an offer's lifetime when they
    /// come no faster, and a flood fills new generations, never a larger table, within what the
    /// ring is planned at. Measured by the allocator, on this thread.
    #[test]
    fn the_hashes_acted_on_are_a_ring_of_generations_that_never_grows() {
        use tally_counting::Counting;
        use tally_wire::clocks::recorded::mono;
        let hash = |n: u64| {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&n.to_be_bytes());
            bytes
        };
        let base = Counting::peak_base();
        let mut seen = Seen::new();
        seen.insert(&hash(0), mono(NOW));
        // Remembered over the offer's lifetime and the skew a reader allows.
        let lifetime = OFFER_LIFETIME_MS + tally_wire::budget::K.duration().as_millis() as u64;
        for step in 1..SEEN_GENERATIONS as u64 {
            seen.insert(&hash(step), mono(NOW + step * SEEN_SPAN_MS));
        }
        assert!((SEEN_GENERATIONS as u64 - 1) * SEEN_SPAN_MS >= lifetime);
        assert!(seen.contains(&hash(0)));
        // A generation on, the first is let go whole.
        seen.insert(
            &hash(99),
            mono(NOW + SEEN_GENERATIONS as u64 * SEEN_SPAN_MS),
        );
        assert!(!seen.contains(&hash(0)));
        assert!(seen.contains(&hash(1)));
        // A flood within one span: new generations, at most the ring's hashes.
        for n in 0..3 * SEEN_REMEMBERED as u64 {
            seen.insert(&hash(1_000 + n), mono(NOW + 10 * SEEN_SPAN_MS));
        }
        assert!(seen.len() <= SEEN_REMEMBERED);
        assert!(seen.contains(&hash(1_000 + 3 * SEEN_REMEMBERED as u64 - 1)));
        let peak = Counting::peak_since(base);
        assert!(
            peak <= Seen::PLANNED_BYTES as isize,
            "{peak} > {}",
            Seen::PLANNED_BYTES
        );
        // And the plan is tight: the ring at its hashes holds most of it.
        assert!(peak >= (Seen::PLANNED_BYTES * 9 / 10) as isize, "{peak}");
    }

    /// The directory's tables at their caps, churned past them, allocate no more than they are
    /// planned at ([`TABLES_PLANNED_BYTES`], charged whole to the store): offers from more keys,
    /// networks and cells than are held, every one replacing another, a change of each deferred,
    /// and more addresses trusted and shunned than are remembered, each as long as an address may
    /// be. Measured by the allocator, on this thread.
    #[test]
    fn the_directorys_tables_stay_within_their_plan_at_their_caps() -> Result {
        use tally_counting::Counting;
        let cells = many_cells()?;
        let long = format!("{}:1", "a".repeat(ADDRESS_MOST_BYTES - 2));
        let stand_in = sign(&Identity::from_seed([1; 32]), &content(&long, area()?, NOW))?;
        let keys: Vec<PublicKey> = (0..(OFFERS_HELD + OFFERS_HELD / 4) as u32)
            .map(|seed| {
                let mut bytes = [9; 32];
                bytes[..4].copy_from_slice(&seed.to_be_bytes());
                Identity::from_seed(bytes).public()
            })
            .collect();
        let base = Counting::peak_base();
        let mut state = State::default();
        let mono = tally_wire::clocks::recorded::mono;
        // Every key once, then a change of an eighth of them, deferred.
        for round in 0..2_u64 {
            let changed = if round == 0 {
                keys.len()
            } else {
                keys.len() / 8
            };
            for (n, key) in keys.iter().enumerate().take(changed) {
                let cell = cells[n % cells.len()];
                let mut said = content(&long, cell, NOW + round);
                said.mlat_cores = 8 + round as u16;
                let offer = Checked(Arc::new(CheckedOffer {
                    offer: stand_in.clone(),
                    signer: *key,
                    content: said,
                }));
                let group = v4(30 + (n / 200 % 200) as u8, (n % 200) as u8);
                state.hold(offer, group, judged(NOW + round), mono(NOW + round));
            }
        }
        for n in 0..(ADDRESSES_REMEMBERED + 64) as u32 {
            let key = keys[n as usize];
            let mut said = content(
                &format!("{}{n}:1", "b".repeat(ADDRESS_MOST_BYTES - 12)),
                cells[0],
                NOW,
            );
            said.address.truncate(ADDRESS_MOST_BYTES);
            let pending = Pending {
                offer: Checked(Arc::new(CheckedOffer {
                    offer: stand_in.clone(),
                    signer: key,
                    content: said,
                })),
                asker: key,
            };
            state.verified(pending, n % 2 == 0, judged(NOW), mono(NOW));
        }
        let peak = Counting::peak_since(base);
        assert!(
            state.held >= OFFERS_HELD / 2,
            "the caps were never reached: {}",
            state.held
        );
        assert!(
            peak <= TABLES_PLANNED_BYTES as isize,
            "{peak} allocated at the most, {TABLES_PLANNED_BYTES} planned"
        );
        // Most of each cell let go: what is left of the cells' and networks' sets is kept within
        // twice what they hold, the shape the plan counts each offer by.
        let held: Vec<(u64, PublicKey)> = state
            .cells
            .iter()
            .flat_map(|(cell, offers)| offers.keys().skip(1).map(move |key| (*cell, *key)))
            .collect();
        for (cell, key) in held {
            state.remove(cell, &key);
        }
        let within = |capacity: usize, len: usize| capacity <= KEPT_WITHIN * len + 4;
        assert!(
            state
                .cells
                .values()
                .all(|offers| within(offers.capacity(), offers.len()))
        );
        assert!(
            state
                .per_group
                .values()
                .all(|offers| within(offers.capacity(), offers.len()))
        );
        assert!(
            state
                .per_key
                .values()
                .all(|cells| within(cells.capacity(), cells.len()))
        );
        drop(state);
        Ok(())
    }

    /// The relay's own re-signing runs on `M`: the judging clock stepped five minutes back
    /// re-signs on time all the same, and the evidence with it on its own schedule. Before, the
    /// schedule was a span of `J`, and a step back held every re-signing until `J` caught up, the
    /// offers expiring at every peer meanwhile.
    #[test]
    fn a_step_back_of_the_judging_clock_keeps_the_own_offers_re_signed() -> Result {
        let identity = Identity::generate().map_err(text)?;
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![
            tally_wire::RelayAddress {
                key: identity.public(),
                address: "198.51.100.7:7450".to_owned(),
            },
        ]);
        hub.network().selection.set_taken(vec![area()?]);
        hub.network().admission.configure(64_496, true);
        let directory = Directory::new();
        let signer = crate::signer::synced(crate::signer::twin(&identity));
        let at = |judged_ms: u64, mono_ms: u64| {
            crate::sharing::Now::from(crate::ingest::Stamp::recorded(
                mono_ms, 0, judged_ms, judged_ms, true,
            ))
        };
        let offers = |published: &[Record]| {
            published
                .iter()
                .filter(|record| matches!(record, Record::ProviderOffer(_)))
                .count()
        };
        assert_eq!(
            offers(&directory.tick(&hub, Some(&signer), at(NOW, NOW))),
            1
        );
        let back = 5 * 60 * 1000;
        for turn in 1..=3 {
            let mono = NOW + turn * OWN_RESIGN_EVERY_MS;
            let published = directory.tick(&hub, Some(&signer), at(mono - back, mono));
            assert_eq!(offers(&published), 1, "turn {turn}: not re-signed");
        }
        Ok(())
    }

    #[test]
    fn the_relay_offers_what_it_takes_re_signs_and_withdraws() -> Result {
        let identity = Identity::generate().map_err(text)?;
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![
            tally_wire::RelayAddress {
                key: identity.public(),
                address: "198.51.100.7:7450".to_owned(),
            },
        ]);
        let cell = area()?;
        hub.network().selection.set_taken(vec![cell]);
        hub.network().admission.configure(64_496, true);
        let directory = Directory::new();
        let published = directory.tick(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            crate::sharing::Now::from(NOW),
        );
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
        assert_eq!(directory.offers_for(cell, judged(NOW)), vec![offer.clone()]);
        // Nothing new a moment later; re-signed a minute on, its evidence not yet again.
        assert!(
            directory
                .tick(
                    &hub,
                    Some(&crate::signer::synced(crate::signer::twin(&identity))),
                    crate::sharing::Now::from(NOW + 1_000)
                )
                .is_empty()
        );
        let half = NOW + OWN_RESIGN_EVERY_MS;
        assert_eq!(
            directory
                .tick(
                    &hub,
                    Some(&crate::signer::synced(crate::signer::twin(&identity))),
                    crate::sharing::Now::from(half)
                )
                .len(),
            1
        );
        // Its relay duties turned off, it hosts no feeders: its offers no longer say raw, so no
        // MLAT relay dials it for raw it does not have.
        hub.network().admission.configure(64_496, false);
        let resigned = directory.tick(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            crate::sharing::Now::from(half + OWN_RESIGN_AT_MOST_EVERY_MS),
        );
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
                .tick(
                    &hub,
                    Some(&crate::signer::synced(crate::signer::twin(&identity))),
                    crate::sharing::Now::from(half + OWN_RESIGN_AT_MOST_EVERY_MS)
                )
                .is_empty()
        );
        assert!(directory.is_empty());
        Ok(())
    }

    /// A relay at `address` taking `cell`, its duties on.
    fn own_relay(identity: &Identity, address: &str, cell: Region) -> Hub {
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY).advertising(vec![
            tally_wire::RelayAddress {
                key: identity.public(),
                address: address.to_owned(),
            },
        ]);
        hub.network().selection.set_taken(vec![cell]);
        hub.network().admission.configure(64_496, true);
        hub
    }

    /// The signers held for `cell`, sorted.
    fn held_keys(directory: &Directory, cell: Region, now: Judged) -> Vec<PublicKey> {
        let now_ms = now.ms();
        let mut keys: Vec<PublicKey> = directory
            .offers_for(cell, judged(now_ms))
            .iter()
            .map(Checked::signer)
            .collect();
        keys.sort();
        keys
    }

    /// The relay's own offer is held under the group of the address it advertises
    /// and by every cap, as its peers hold it. Its network already holds a group's share of the
    /// cell in peers' offers: the relay holds exactly what a peer that verified the same offers
    /// holds (the top of the ranking of the five, four of them), never its own beside all four.
    #[test]
    fn the_relays_own_offer_is_held_by_its_networks_caps_as_its_peers_hold_it() -> Result {
        let cell = area()?;
        let identity = Identity::from_seed([71; 32]);
        let hub = own_relay(&identity, "198.51.100.7:7450", cell);
        let mine = Directory::new();
        let published = mine.tick(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            crate::sharing::Now::from(NOW),
        );
        let Some(Record::ProviderOffer(own)) = published.first() else {
            return Err(format!("published {published:?}"));
        };
        let group = Group::of(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));
        let peer = Directory::new();
        peer.hold_verified(own.clone(), group, judged(NOW))?;
        for seed in 0..OFFERS_PER_GROUP_IN_CELL {
            let neighbour = Identity::from_seed([72 + seed as u8; 32]);
            let offer = sign(&neighbour, &content("198.51.7.1:7450", cell, NOW))?;
            mine.offered(&relay_asker(neighbour.public()), offer.clone(), judged(NOW));
            lock(&mine.state).hold(
                checked(&offer, judged(NOW)).ok_or("unchecked")?,
                group,
                judged(NOW),
                mine.clock.mono(),
            );
            peer.hold_verified(offer, group, judged(NOW))?;
        }
        let held = held_keys(&mine, cell, judged(NOW));
        assert_eq!(held.len(), OFFERS_PER_GROUP_IN_CELL);
        assert_eq!(held, held_keys(&peer, cell, judged(NOW)));
        // Re-signed a minute on, it competes again, and both still hold the same.
        mine.tick(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            crate::sharing::Now::from(NOW + OWN_RESIGN_EVERY_MS),
        );
        assert_eq!(
            held_keys(&mine, cell, judged(NOW + OWN_RESIGN_EVERY_MS)),
            held
        );
        Ok(())
    }

    /// A relay advertising a host name signs offers naming the address it
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
            let identities = vec![tally_wire::NoiseKey::of(crate::signer::twin(&identity))];
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
        // The sandbox this runs in may have no resolver, so `localhost` is pinned to where the
        // listener above answers.
        mine.pin_host("localhost", std::net::Ipv4Addr::LOCALHOST.into());
        let mut now = NOW;
        let mut gossiped = mine.tick(
            &hub,
            Some(&crate::signer::synced(crate::signer::twin(&identity))),
            crate::sharing::Now::from(now),
        );
        // Until its own offer is held (the host name resolved, then signed): waited for as long as
        // that takes, failing only on a hang, never on how many ticks fit a span of the clock.
        let started = std::time::Instant::now();
        while mine.offers_for(cell, judged(now)).is_empty() {
            if started.elapsed() > Duration::from_secs(120) {
                return Err("its own offer was never held".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            now += 100;
            gossiped.extend(mine.tick(
                &hub,
                Some(&crate::signer::synced(crate::signer::twin(&identity))),
                crate::sharing::Now::from(now),
            ));
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
        peer.offered(&relay_asker(identity.public()), offer, judged(now));
        peer.verify_pending(&Identity::generate().map_err(text)?, judged(now))
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

    /// An offer naming a host name is in no group every relay agrees on (each
    /// resolver may answer it differently), so it is not taken: never queued for a dial.
    #[test]
    fn an_offer_naming_a_host_name_is_not_taken() -> Result {
        let directory = Directory::new();
        let relay = Identity::generate().map_err(text)?;
        let cell = area()?;
        let named = sign(&relay, &content("relay.example:7450", cell, NOW))?;
        directory.offered(&relay_asker(relay.public()), named, judged(NOW));
        assert!(directory.state.lock().map_err(text)?.pending.is_empty());
        let numbered = sign(&relay, &content("192.0.2.7:7450", cell, NOW + 1))?;
        directory.offered(&relay_asker(relay.public()), numbered, judged(NOW + 1));
        assert_eq!(directory.state.lock().map_err(text)?.pending.len(), 1);
        Ok(())
    }

    /// A peer re-signing an offer that says nothing new is taken at most once per
    /// `RESIGNED_AT_MOST_EVERY_MS` by the signed times, never gossiped sooner; and one taken is
    /// swapped in place, so it moves no ranking, version or tier a reader follows.
    #[test]
    fn a_re_signing_that_changes_nothing_is_taken_once_a_turn_and_in_place() -> Result {
        let relay = Identity::from_seed([91; 32]);
        let cell = area()?;
        let directory = Directory::new();
        let first = sign(&relay, &content("203.0.113.9:1", cell, NOW))?;
        assert!(directory.hold_verified(first.clone(), v4(203, 0), judged(NOW))?);
        let ranked = directory.offers_for(cell, judged(NOW));
        let version = directory.version(judged(NOW));
        let _ = directory.take_changed_cells(judged(NOW));
        // Re-signed a millisecond apart, a thousand times: none taken.
        for step in 1..=1_000 {
            let again = sign(&relay, &content("203.0.113.9:1", cell, NOW + step))?;
            assert!(!directory.hold_verified(again, v4(203, 0), judged(NOW + step))?);
        }
        assert_eq!(directory.offers_for(cell, judged(NOW + 1_000)), vec![first]);
        // Its turn come: taken, in place.
        let at = NOW + RESIGNED_AT_MOST_EVERY_MS;
        let renewed = sign(&relay, &content("203.0.113.9:1", cell, at))?;
        assert!(directory.hold_verified(renewed.clone(), v4(203, 0), judged(at))?);
        {
            let state = lock(&directory.state);
            assert!(
                state.ranks.contains_key(&cell.as_u64()),
                "the cell's ranking was dropped: not renewed in place"
            );
        }
        assert_eq!(directory.version(judged(at)).held, version.held);
        assert!(directory.take_changed_cells(judged(at)).is_empty());
        assert_eq!(directory.offers_for(cell, judged(at)), vec![renewed]);
        assert_eq!(ranked.len(), 1);
        Ok(())
    }
}
