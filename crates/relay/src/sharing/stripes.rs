//! The striped forwarding trees (RFC-0174 §2.5, the SplitStream shape).
//!
//! A cell's product is cut into [`DATA_STRIPES`] stripes by record hash, plus one parity stripe
//! ([`PARITY_STRIPE`]) that carries, per origin and second, the XOR of the data stripes' slices
//! (`parity`). Each stripe has its own tree over the group, and every member computes the same
//! trees from the same members, with no coordination:
//!
//! 1. **Homes.** Each forwarding member is an interior candidate in exactly one stripe. Members
//!    are taken in the order of their home score (a rendezvous hash over cell, product and key),
//!    and each takes the stripe it scores highest that still has room; the rooms are equal, the
//!    first `forwarders % STRIPES` stripes one larger. So a member's parents in different stripes
//!    are different members, and losing one member costs any other member at most one stripe,
//!    which parity restores. A group smaller than [`STRIPES`] cannot give every stripe its own
//!    interior; there member `i` (in home order) is the interior of every stripe `s` with
//!    `s % forwarders == i`.
//! 2. **Order.** In stripe `s` the interior candidates come first, ordered by their stripe score
//!    (a rendezvous hash over cell, product, stripe and key), then every other member in the same
//!    order. The tree is the heap over that order: position `p`'s children are positions
//!    `p * fanout + 1 ..= p * fanout + fanout`. The fanout is [`FANOUT`], raised only when a
//!    stripe has too few interior candidates to hold every position that has children, so a leaf
//!    never forwards.
//! 3. **Seed.** The root of each stripe (position 0) is its seed: where every origin sends that
//!    stripe. It rotates every `seeds::SEED_ROTATION_SECONDS` among the stripe's interior
//!    candidates by a rendezvous over (cell, product, stripe, epoch, key): the epoch's seed swaps
//!    places with whoever held the root, so a rotation moves two members, never the tree.
//!
//! A record travels down its stripe's tree from the root: one hop from its origin to the seed,
//! then one per level, forwarded the moment it arrives (cut-through).

use tally_wire::batch::Hash;
use tally_wire::sharing::{receipt_digest, stripe_of};
use tally_wire::{PublicKey, Region, Streams};

/// The stripes records are cut into.
pub const DATA_STRIPES: u8 = 3;
/// The parity stripe's index: one more stripe, after the data stripes.
pub const PARITY_STRIPE: u8 = DATA_STRIPES;
/// Every stripe, data and parity: what `stripes_of` says on the wire.
pub const STRIPES: u8 = DATA_STRIPES + 1;
/// Children per interior member (raised in a stripe with too few interior candidates).
pub const FANOUT: usize = 4;

/// The data stripe a record is in.
pub fn data_stripe(record: &Hash) -> u8 {
    stripe_of(record, DATA_STRIPES)
}

/// One member's place in one stripe's tree.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Place {
    pub parent: Option<PublicKey>,
    pub children: Vec<PublicKey>,
}

/// A rendezvous score: BLAKE2s (the wire's receipt digest, under a domain block of its own) over
/// a domain tag, the cell, product, stripe and a number, and some keys. Compared as big-endian
/// bytes; integer work only, so every party orders alike.
pub(crate) fn score(
    tag: &[u8],
    cell: Region,
    product: Streams,
    stripe: u8,
    number: u64,
    keys: &[&PublicKey],
) -> Hash {
    let domain = domain_block(tag);
    let mut head = [0u8; 32];
    head[..8].copy_from_slice(&cell.as_u64().to_be_bytes());
    head[8..10].copy_from_slice(&product.0.to_be_bytes());
    head[10] = stripe;
    head[11..19].copy_from_slice(&number.to_be_bytes());
    let mut blocks = Vec::with_capacity(2 + keys.len());
    blocks.push(domain);
    blocks.push(head);
    blocks.extend(keys.iter().map(|key| *key.as_bytes()));
    receipt_digest(&blocks)
}

/// A domain tag as one 32-byte block, zero-padded.
pub(crate) fn domain_block(tag: &[u8]) -> Hash {
    let mut domain = [0u8; 32];
    let tag = &tag[..tag.len().min(32)];
    domain[..tag.len()].copy_from_slice(tag);
    domain
}

const HOME: &[u8] = b"tally sharing home";
const STRIPE: &[u8] = b"tally sharing stripe";
pub(crate) const SEED: &[u8] = b"tally sharing seed";

/// Every stripe's tree over one group, before seed rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    cell: Region,
    product: Streams,
    trees: Vec<Tree>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Tree {
    /// Heap order: interior candidates first.
    order: Vec<PublicKey>,
    /// How many of `order` are interior candidates.
    interior: usize,
    fanout: usize,
}

impl Layout {
    /// The trees over `members` (repeats ignored). A member in `leaves_only` withdrew from
    /// forwarding (§2.5: a relay that cannot carry its slice says so) and is a leaf in every
    /// stripe; if every member withdrew, none is honoured, since a group must forward to deliver.
    pub fn new(
        cell: Region,
        product: Streams,
        members: &[PublicKey],
        leaves_only: &[PublicKey],
    ) -> Self {
        let mut members = members.to_vec();
        members.sort();
        members.dedup();
        let mut forwarders: Vec<PublicKey> = members
            .iter()
            .filter(|key| !leaves_only.contains(key))
            .copied()
            .collect();
        if forwarders.is_empty() {
            forwarders.clone_from(&members);
        }
        let homes = homes(cell, product, &forwarders);
        let trees = (0..STRIPES)
            .map(|stripe| {
                let rank = |key: &PublicKey| score(STRIPE, cell, product, stripe, 0, &[key]);
                let mut interior: Vec<PublicKey> = homes
                    .iter()
                    .filter(|(_, stripes)| stripes.contains(&stripe))
                    .map(|(key, _)| *key)
                    .collect();
                interior.sort_by_key(|key| std::cmp::Reverse((rank(key), *key)));
                let mut rest: Vec<PublicKey> = members
                    .iter()
                    .filter(|key| !interior.contains(key))
                    .copied()
                    .collect();
                rest.sort_by_key(|key| std::cmp::Reverse((rank(key), *key)));
                let n = members.len();
                let fanout = if interior.is_empty() || n < 2 {
                    FANOUT
                } else {
                    FANOUT.max((n - 1).div_ceil(interior.len()))
                };
                let count = interior.len();
                interior.extend(rest);
                Tree {
                    order: interior,
                    interior: count,
                    fanout,
                }
            })
            .collect();
        Self {
            cell,
            product,
            trees,
        }
    }

    pub fn cell(&self) -> Region {
        self.cell
    }

    pub fn product(&self) -> Streams {
        self.product
    }

    pub fn len(&self) -> usize {
        self.trees.first().map_or(0, |tree| tree.order.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.trees
            .first()
            .is_some_and(|tree| tree.order.contains(key))
    }

    /// Every member, sorted.
    pub fn members(&self) -> Vec<PublicKey> {
        let mut members = self
            .trees
            .first()
            .map(|tree| tree.order.clone())
            .unwrap_or_default();
        members.sort();
        members
    }

    /// The interior candidates of `stripe`.
    pub fn interior(&self, stripe: u8) -> &[PublicKey] {
        self.trees
            .get(usize::from(stripe))
            .map_or(&[], |tree| &tree.order[..tree.interior])
    }

    /// The stripes `member` is an interior candidate in: exactly one in a group of at least
    /// `STRIPES` forwarders.
    pub fn homes(&self, member: &PublicKey) -> Vec<u8> {
        (0..STRIPES)
            .filter(|stripe| self.interior(*stripe).contains(member))
            .collect()
    }

    /// The seed (root) of `stripe` in `epoch`: the stripe's interior candidate that scores
    /// highest over (cell, product, stripe, epoch, key). Anyone with the members can check it.
    pub fn seed(&self, stripe: u8, epoch: u64) -> Option<PublicKey> {
        self.interior(stripe)
            .iter()
            .max_by_key(|key| {
                (
                    score(SEED, self.cell, self.product, stripe, epoch, &[key]),
                    **key,
                )
            })
            .copied()
    }

    /// The heap order of `stripe` in `epoch`: the epoch's seed swapped into the root.
    fn order(&self, stripe: u8, epoch: u64) -> Option<(Vec<PublicKey>, usize)> {
        let tree = self.trees.get(usize::from(stripe))?;
        let mut order = tree.order.clone();
        if let Some(seed) = self.seed(stripe, epoch)
            && let Some(at) = order.iter().position(|key| *key == seed)
        {
            order.swap(0, at);
        }
        Some((order, tree.fanout))
    }

    /// `member`'s place in `stripe`'s tree in `epoch`; `None` when it is not a member.
    pub fn place(&self, stripe: u8, epoch: u64, member: &PublicKey) -> Option<Place> {
        let (order, fanout) = self.order(stripe, epoch)?;
        let at = order.iter().position(|key| key == member)?;
        let parent = (at > 0).then(|| order[(at - 1) / fanout]);
        let first = at * fanout + 1;
        let children = order
            .get(first.min(order.len())..(first + fanout).min(order.len()))
            .map(<[PublicKey]>::to_vec)
            .unwrap_or_default();
        Some(Place { parent, children })
    }

    /// The most hops from a stripe's root to any member.
    pub fn depth(&self, stripe: u8) -> usize {
        let Some(tree) = self.trees.get(usize::from(stripe)) else {
            return 0;
        };
        let mut depth = 0;
        let mut at = tree.order.len().saturating_sub(1);
        while at > 0 {
            at = (at - 1) / tree.fanout;
            depth += 1;
        }
        depth
    }
}

/// Each forwarder's home stripes (see the module doc).
fn homes(cell: Region, product: Streams, forwarders: &[PublicKey]) -> Vec<(PublicKey, Vec<u8>)> {
    let mut ordered = forwarders.to_vec();
    ordered.sort_by_key(|key| std::cmp::Reverse((score(HOME, cell, product, 0, 0, &[key]), *key)));
    let stripes = usize::from(STRIPES);
    if ordered.len() < stripes {
        let count = ordered.len();
        return ordered
            .into_iter()
            .enumerate()
            .map(|(index, key)| {
                let homes = (0..STRIPES)
                    .filter(|stripe| usize::from(*stripe) % count == index)
                    .collect();
                (key, homes)
            })
            .collect();
    }
    let base = ordered.len() / stripes;
    let extra = ordered.len() % stripes;
    let mut room: Vec<usize> = (0..stripes)
        .map(|stripe| base + usize::from(stripe < extra))
        .collect();
    ordered
        .into_iter()
        .map(|key| {
            let home = (0..STRIPES)
                .filter(|stripe| room[usize::from(*stripe)] > 0)
                .max_by_key(|stripe| score(STRIPE, cell, product, *stripe, 1, &[&key]))
                .unwrap_or(0);
            if let Some(left) = room.get_mut(usize::from(home)) {
                *left = left.saturating_sub(1);
            }
            (key, vec![home])
        })
        .collect()
}

/// `member`'s place in the tree of `stripe` over `members` (no withdrawals), in `epoch`.
pub fn place(
    cell: Region,
    product: Streams,
    stripe: u8,
    epoch: u64,
    members: &[PublicKey],
    member: &PublicKey,
) -> Option<Place> {
    Layout::new(cell, product, members, &[]).place(stripe, epoch, member)
}
