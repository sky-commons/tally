//! Sharing group membership (RFC-0174 §2.5): per (area cell, product), the relays that take the
//! cell. A relay is a member while it has a live `ProviderOffer` for the cell and product (from
//! `directory`), or while it recently asked a member for stripes (`StripeAssignment`), and this
//! relay is always a member of the groups of the areas it takes (without an entry: a group only
//! this relay is in has no book). A member that offers no stripes
//! withdrew from forwarding and is a leaf in every tree. A member its children report as starving
//! them is demoted: out of every tree, for [`DEMOTION_MS`].

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::RwLock;

use tally_wire::{PublicKey, Region, Streams};

use super::locks::{read, write};

/// How long a demoted member stays out of the trees.
pub const DEMOTION_MS: u64 = 10 * 60 * 1000;
/// How long an ask (`StripeAssignment`) keeps its sender a member without an offer.
pub const ASK_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// One group: an area cell and one product.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupKey {
    pub cell: Region,
    pub product: Streams,
}

impl GroupKey {
    pub fn new(cell: Region, product: Streams) -> Self {
        Self { cell, product }
    }

    fn sort_key(&self) -> (u64, u16) {
        (self.cell.as_u64(), self.product.0)
    }
}

impl Ord for GroupKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl PartialOrd for GroupKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Entry {
    /// A member by asking until then (0: never asked, or lapsed).
    asked_until_ms: u64,
    /// A leaf, as its ask said (a newcomer's only).
    asked_leaf: bool,
    /// A member by its verified offers, held now: `Some(leaf)`, a leaf when any of them forwards
    /// nothing here. Kept exactly what the directory holds (`Groups::set_offers`), so it lapses
    /// when the offers do.
    offered: Option<bool>,
}

impl Entry {
    fn leaf_only(&self) -> bool {
        self.offered.unwrap_or(self.asked_leaf)
    }

    fn lapsed(&self, now_ms: u64) -> bool {
        self.offered.is_none() && self.asked_until_ms <= now_ms
    }
}

#[derive(Default)]
struct Book {
    members: BTreeMap<PublicKey, Entry>,
    demoted: BTreeMap<PublicKey, u64>,
}

impl Book {
    fn is_empty(&self) -> bool {
        self.members.is_empty() && self.demoted.is_empty()
    }
}

/// The books of the groups some other relay is in. This relay is in every group of the areas it
/// takes without an entry here (`Sharing` adds it to each tree it lays out): a group no other relay
/// is in has no book, so holding the whole world costs nothing per area.
#[derive(Default)]
pub struct Groups {
    books: RwLock<BTreeMap<GroupKey, Book>>,
    /// The soonest an ask lapses or a demotion ends: `expire` does nothing before it.
    next_expiry_ms: RwLock<u64>,
}

impl Groups {
    pub fn new() -> Self {
        Self::default()
    }

    /// `member` asked for stripes: in the group until `until_ms` (or later, if it already was).
    /// A member only by asking may send the group's records here and is sent its stripes'
    /// records, but it is in no tree ([`Groups::tree`]): a relay that has not verified its offer
    /// may not lay it out where every other relay does. `leaf_only` holds only for a newcomer;
    /// an ask never changes what a member's offers said.
    pub fn admit(&self, group: GroupKey, member: PublicKey, until_ms: u64, leaf_only: bool) {
        let mut books = write(&self.books);
        let entry = books
            .entry(group)
            .or_default()
            .members
            .entry(member)
            .or_insert(Entry {
                asked_leaf: leaf_only,
                ..Entry::default()
            });
        entry.asked_until_ms = entry.asked_until_ms.max(until_ms);
        self.expires_at(until_ms);
    }

    /// The members whose verified offers cover the group now, each a leaf when any of its offers
    /// forwards nothing here: what the offers say replaces what an ask said, and a member whose
    /// offers are gone is a member by its ask alone, if it asked. The offers are the members' own
    /// signed word, and every relay that holds them reads them alike.
    pub fn set_offers(&self, group: GroupKey, offers: &BTreeMap<PublicKey, bool>) {
        let mut books = write(&self.books);
        if offers.is_empty() && !books.contains_key(&group) {
            return;
        }
        let book = books.entry(group).or_default();
        for entry in book.members.values_mut() {
            entry.offered = None;
        }
        for (member, leaf) in offers {
            book.members.entry(*member).or_default().offered = Some(*leaf);
        }
        book.members
            .retain(|_, entry| entry.offered.is_some() || entry.asked_until_ms > 0);
        if book.is_empty() {
            books.remove(&group);
        }
    }

    /// Out of the group's trees until `until_ms`.
    pub fn demote(&self, group: GroupKey, member: PublicKey, until_ms: u64) {
        let mut books = write(&self.books);
        let demoted = books.entry(group).or_default().demoted.entry(member);
        let until = demoted.or_insert(until_ms);
        *until = (*until).max(until_ms);
        self.expires_at(until_ms);
    }

    pub fn is_demoted(&self, group: GroupKey, member: &PublicKey) -> bool {
        read(&self.books)
            .get(&group)
            .is_some_and(|book| book.demoted.contains_key(member))
    }

    /// Forgets asks and demotions whose time is up, and groups left empty: nothing to do, and no
    /// scan, before the soonest is due. The groups whose trees changed (a demotion ended).
    pub fn expire(&self, now_ms: u64) -> Vec<GroupKey> {
        if *read(&self.next_expiry_ms) > now_ms {
            return Vec::new();
        }
        let mut books = write(&self.books);
        let mut changed = Vec::new();
        let mut next = u64::MAX;
        for (key, book) in books.iter_mut() {
            for entry in book.members.values_mut() {
                if entry.asked_until_ms <= now_ms {
                    entry.asked_until_ms = 0;
                } else {
                    next = next.min(entry.asked_until_ms);
                }
            }
            book.members.retain(|_, entry| !entry.lapsed(now_ms));
            let before = book.demoted.len();
            book.demoted.retain(|_, until| *until > now_ms);
            if book.demoted.len() != before {
                changed.push(*key);
            }
            next = book
                .demoted
                .values()
                .fold(next, |next, until| next.min(*until));
        }
        books.retain(|_, book| !book.is_empty());
        *write(&self.next_expiry_ms) = next;
        changed
    }

    fn expires_at(&self, until_ms: u64) {
        let mut next = write(&self.next_expiry_ms);
        *next = (*next).min(until_ms);
    }

    /// The members of a cell's product group, sorted by key, demoted members left out: who may
    /// send this relay the group's records.
    pub fn members(&self, cell: Region, product: Streams) -> Vec<PublicKey> {
        self.book(GroupKey::new(cell, product), |_| true)
    }

    /// The members the group's trees are laid out over: those whose verified offers cover the
    /// group now, demoted members left out, and of them the ones that forward nothing. A function
    /// of the offers held, so two relays that hold the same offers lay out the same trees. This
    /// relay is not among them (`Sharing` adds it).
    pub fn tree(&self, group: GroupKey) -> (Vec<PublicKey>, Vec<PublicKey>) {
        let members = self.book(group, |entry| entry.offered.is_some());
        let leaves = self.book(group, |entry| entry.offered == Some(true));
        (members, leaves)
    }

    /// The members that forward nothing.
    pub fn leaves_only(&self, group: GroupKey) -> Vec<PublicKey> {
        self.book(group, Entry::leaf_only)
    }

    /// Every group with a member.
    pub fn keys(&self) -> Vec<GroupKey> {
        read(&self.books).keys().copied().collect()
    }

    fn book(&self, group: GroupKey, keep: impl Fn(&Entry) -> bool) -> Vec<PublicKey> {
        read(&self.books)
            .get(&group)
            .map(|book| {
                book.members
                    .iter()
                    .filter(|(key, entry)| !book.demoted.contains_key(key) && keep(entry))
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default()
    }
}
