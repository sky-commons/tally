//! Sharing group membership (RFC-0174 §2.5): per (area cell, product), the relays that take the
//! cell. A relay is a member while it has a live `ProviderOffer` for the cell and product (from
//! `directory`), or while it recently asked a member for stripes (`StripeAssignment`), and this
//! relay is always a member of the groups of the areas it takes. A member that offers no stripes
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

#[derive(Clone, Copy, Debug)]
struct Entry {
    until_ms: u64,
    leaf_only: bool,
    /// Admitted by a verified offer (until `offered_until_ms`), not only by an ask.
    offered_until_ms: u64,
}

#[derive(Default)]
struct Book {
    members: BTreeMap<PublicKey, Entry>,
    demoted: BTreeMap<PublicKey, u64>,
}

#[derive(Default)]
pub struct Groups {
    books: RwLock<BTreeMap<GroupKey, Book>>,
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
                until_ms,
                leaf_only,
                offered_until_ms: 0,
            });
        entry.until_ms = entry.until_ms.max(until_ms);
    }

    /// `member`'s verified offers cover the group until `until_ms`; `leaf_only` when any of them
    /// forwards nothing there. What the offers say replaces what an ask said: the offers are the
    /// member's own signed word, and every relay that holds them reads them alike.
    pub fn offered(&self, group: GroupKey, member: PublicKey, until_ms: u64, leaf_only: bool) {
        let mut books = write(&self.books);
        let entry = books
            .entry(group)
            .or_default()
            .members
            .entry(member)
            .or_insert(Entry {
                until_ms,
                leaf_only,
                offered_until_ms: until_ms,
            });
        entry.until_ms = entry.until_ms.max(until_ms);
        entry.offered_until_ms = until_ms;
        entry.leaf_only = leaf_only;
    }

    /// This relay itself: in the group until `until_ms`, a leaf exactly when `leaf_only` (its own
    /// withdrawal, which nothing else overrides).
    pub fn own(&self, group: GroupKey, member: PublicKey, until_ms: u64, leaf_only: bool) {
        write(&self.books).entry(group).or_default().members.insert(
            member,
            Entry {
                until_ms,
                leaf_only,
                offered_until_ms: until_ms,
            },
        );
    }

    /// Out of the group's trees until `until_ms`.
    pub fn demote(&self, group: GroupKey, member: PublicKey, until_ms: u64) {
        let mut books = write(&self.books);
        let demoted = books.entry(group).or_default().demoted.entry(member);
        let until = demoted.or_insert(until_ms);
        *until = (*until).max(until_ms);
    }

    pub fn is_demoted(&self, group: GroupKey, member: &PublicKey) -> bool {
        read(&self.books)
            .get(&group)
            .is_some_and(|book| book.demoted.contains_key(member))
    }

    /// Forgets members and demotions whose time is up, and groups left empty.
    pub fn expire(&self, now_ms: u64) {
        let mut books = write(&self.books);
        for book in books.values_mut() {
            book.members.retain(|_, entry| entry.until_ms > now_ms);
            book.demoted.retain(|_, until| *until > now_ms);
        }
        books.retain(|_, book| !book.members.is_empty() || !book.demoted.is_empty());
    }

    /// The members of a cell's product group, sorted by key, demoted members left out: who may
    /// send this relay the group's records.
    pub fn members(&self, cell: Region, product: Streams) -> Vec<PublicKey> {
        self.book(GroupKey::new(cell, product), |_| true)
    }

    /// The members the group's trees are laid out over at `now_ms`: those whose verified offers
    /// (or, for this relay, its own word) cover the group now, demoted members left out, and
    /// of them the ones that forward nothing. A function of the offers held, so two relays that
    /// hold the same offers lay out the same trees.
    pub fn tree(&self, group: GroupKey, now_ms: u64) -> (Vec<PublicKey>, Vec<PublicKey>) {
        let members = self.book(group, |entry| entry.offered_until_ms > now_ms);
        let leaves = self.book(group, |entry| {
            entry.offered_until_ms > now_ms && entry.leaf_only
        });
        (members, leaves)
    }

    /// The members that forward nothing.
    pub fn leaves_only(&self, group: GroupKey) -> Vec<PublicKey> {
        self.book(group, |entry| entry.leaf_only)
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
