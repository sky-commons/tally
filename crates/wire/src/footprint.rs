//! What a collection allocates, by its own arithmetic: the one way a store's charge for a map, a
//! set, a vector or a deque is reckoned (a relay's `budget::Store`, and the MLAT engine's tables a
//! relay charges to one). A store is sized on its charge, so a collection charged to one is charged
//! what it allocates as it is now, growth included, read from the collection itself (its capacity,
//! or its length where the length bounds it), never an assumed cost of an entry that the
//! collection can exceed.
//!
//! - A `Vec` or a `VecDeque` allocates its capacity of elements ([`vec`]), and nothing while its
//!   capacity is zero.
//! - A `BTreeMap` (and a `BTreeSet`, a map to nothing) allocates one node for every eleven keys
//!   at best and every five at worst: every node but its root holds at least `B - 1` keys, which
//!   the map keeps as entries come and go. [`btree`] is what it allocates at most for its length,
//!   whatever order the entries came and went in.
//! - A `Vec` or a `VecDeque` a store keeps is a [`Deque`]: it grows by a quarter (and at least
//!   [`Deque::LEAST`]) when full and shrinks back once it holds less than four fifths of that, so
//!   what it allocates is bounded by its length ([`Deque::bytes_at_most`]), not by the most it
//!   ever held.
//! - A `HashMap` allocates one table of buckets, which grows as entries come and never shrinks as
//!   they go, until it is told to ([`Table`]). Its buckets are not read from its length, so they
//!   are followed from its capacity as it changes.
//!
//! The layouts are the standard library's (`alloc::collections::btree::node`, and the `hashbrown`
//! tables behind `std::collections::HashMap`); `tests/footprint_bytes.rs` holds every figure here
//! to what an allocator counting each byte sees, under churn, so a toolchain whose collections
//! allocate otherwise fails there.

use std::collections::{BTreeMap, VecDeque};
use std::mem::{align_of, size_of};

/// What `bytes::Bytes` holding an allocation of `len` bytes allocates at most: the bytes, made
/// exactly as long ([`exact`]), and the shared header it makes the first time it is cloned or
/// sliced.
pub const fn shared_bytes(len: usize) -> usize {
    len + 4 * size_of::<usize>()
}

/// `bytes` with no spare capacity, so what it allocates is its length ([`shared_bytes`]).
pub fn exact(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.shrink_to_fit();
    bytes
}

/// What a `Vec<T>` or a `VecDeque<T>` of `capacity` allocates.
pub const fn vec<T>(capacity: usize) -> usize {
    capacity * size_of::<T>()
}

/// What an `Arc<T>` allocates: its counts and its value.
pub const fn arc<T>() -> usize {
    crate::decoded::ARC_HEADER + size_of::<T>()
}

/// The keys a `BTreeMap` node holds at most (`2 * B - 1`, `B` six).
const NODE_KEYS: usize = 11;
/// The keys every node but the root holds at least (`B - 1`).
const MIN_KEYS: usize = 5;

const fn round_up(bytes: usize, align: usize) -> usize {
    bytes.div_ceil(align) * align
}

const fn max(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// A leaf of a `BTreeMap<K, V>`, at most: its parent's pointer, its index there and its length,
/// and room for its keys and values, each padded to its alignment, whatever order the compiler
/// lays them in.
const fn leaf<K, V>() -> usize {
    let align = max(max(align_of::<K>(), align_of::<V>()), align_of::<usize>());
    round_up(
        size_of::<usize>()
            + 2 * size_of::<u16>()
            + NODE_KEYS * size_of::<K>()
            + (align_of::<K>() - 1)
            + NODE_KEYS * size_of::<V>()
            + (align_of::<V>() - 1),
        align,
    )
}

/// An internal node: a leaf and its children's pointers, one more than its keys.
const fn internal<K, V>() -> usize {
    round_up(leaf::<K, V>(), align_of::<usize>()) + (NODE_KEYS + 1) * size_of::<usize>()
}

/// What a `BTreeMap<K, V>` of `len` entries allocates at most (a `BTreeSet<K>` is one of
/// `BTreeMap<K, ()>`): as many nodes as it can have, every one but the root holding the fewest
/// keys it may, and as many of them internal as can be. One emptied by removals keeps its root, a
/// leaf, until it is cleared or dropped.
pub const fn btree<K, V>(len: usize) -> usize {
    if len == 0 {
        return leaf::<K, V>();
    }
    let nodes = (len - 1) / MIN_KEYS + 1;
    // An internal root has two children at least and every other internal node `B`: `nodes - 1`
    // children in all.
    let internals = (nodes + 3) / (MIN_KEYS + 1);
    (nodes - internals) * leaf::<K, V>() + internals * internal::<K, V>()
}

/// What a `BTreeMap<K, V>` of `len` entries is planned at: a node, and for each entry a fifth of
/// one, as though every node were internal. Never less than [`btree`] of `len`: what a plan that
/// counts entries takes for a map.
pub const fn btree_planned<K, V>(len: usize) -> usize {
    internal::<K, V>() + len * internal::<K, V>().div_ceil(MIN_KEYS)
}

/// A `BTreeMap` that says what it allocates ([`Tree::bytes`]): every change goes through it, and
/// one emptied lets its last node go, so an empty tree allocates nothing and [`btree`] of its
/// length bounds it otherwise. Read as the map it is.
#[derive(Debug)]
pub struct Tree<K, V>(BTreeMap<K, V>);

impl<K, V> Default for Tree<K, V> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K, V> std::ops::Deref for Tree<K, V> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

impl<K: Ord, V> Tree<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    /// What it allocates at most.
    pub fn bytes(&self) -> usize {
        Self::bytes_at(self.0.len())
    }

    /// What a tree of `len` entries allocates at most.
    pub const fn bytes_at(len: usize) -> usize {
        if len == 0 { 0 } else { btree::<K, V>(len) }
    }

    /// What one more entry may allocate more, at most.
    pub fn growth(&self) -> usize {
        Self::bytes_at(self.0.len() + 1) - Self::bytes_at(self.0.len())
    }

    /// What a tree of `len` entries is planned at ([`btree_planned`]).
    pub const fn bytes_planned(len: usize) -> usize {
        btree_planned::<K, V>(len)
    }

    /// What a plan takes for each entry more ([`btree_planned`]).
    pub const fn bytes_per_entry() -> usize {
        btree_planned::<K, V>(1) - btree_planned::<K, V>(0)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.0.insert(key, value)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.0.get_mut(key)
    }

    /// Its entry for `key`, to insert or change in place. It cannot remove: a removal goes
    /// through [`Tree::remove`], so an emptied tree is always made anew and lets its root go.
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V> {
        Entry(self.0.entry(key))
    }

    pub fn values_mut(&mut self) -> std::collections::btree_map::ValuesMut<'_, K, V> {
        self.0.values_mut()
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let removed = self.0.remove(key);
        self.tidy();
        removed
    }

    pub fn pop_first(&mut self) -> Option<(K, V)> {
        let first = self.0.pop_first();
        self.tidy();
        first
    }

    pub fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool) {
        self.0.retain(keep);
        self.tidy();
    }

    pub fn clear(&mut self) {
        self.0 = BTreeMap::new();
    }

    /// The entries from `key` on, taken out into a tree of their own (`BTreeMap::split_off`, which
    /// leaves both halves as full as any tree its length).
    pub fn split_off(&mut self, key: &K) -> Self {
        let later = self.0.split_off(key);
        self.tidy();
        let mut later = Self(later);
        later.tidy();
        later
    }

    /// Everything it holds, taken out; it allocates nothing after.
    pub fn take(&mut self) -> BTreeMap<K, V> {
        std::mem::take(&mut self.0)
    }

    /// An emptied map keeps its root until it is made anew.
    fn tidy(&mut self) {
        if self.0.is_empty() {
            self.0 = BTreeMap::new();
        }
    }
}

/// A [`Tree`]'s entry: `BTreeMap`'s, with no way to remove what it names (`OccupiedEntry::remove`
/// would leave an emptied tree holding its root, which [`Tree::remove`] lets go).
pub struct Entry<'a, K, V>(std::collections::btree_map::Entry<'a, K, V>);

impl<'a, K: Ord, V> Entry<'a, K, V> {
    pub fn or_insert(self, default: V) -> &'a mut V {
        self.0.or_insert(default)
    }

    pub fn or_insert_with(self, default: impl FnOnce() -> V) -> &'a mut V {
        self.0.or_insert_with(default)
    }

    pub fn or_default(self) -> &'a mut V
    where
        V: Default,
    {
        self.0.or_default()
    }

    #[must_use]
    pub fn and_modify(self, change: impl FnOnce(&mut V)) -> Self {
        Self(self.0.and_modify(change))
    }

    pub fn key(&self) -> &K {
        self.0.key()
    }
}

/// A `VecDeque` that says what it allocates ([`Deque::bytes`]) and is bounded by what it holds:
/// full, it grows by a quarter and at least [`Deque::LEAST`] ([`Deque::grown`]), never by the
/// standard library's doubling; and every change that lets entries go shrinks it back once its
/// capacity passes a quarter again what is left and `LEAST` more. So it allocates at most
/// [`Deque::bytes_at_most`] of its length, whatever it held before, and one more entry costs at
/// most [`Deque::growth`]. `L` is [`Deque::LEAST`]: four, or one for many short deques (a list
/// for each of many keys), each of which would otherwise keep four slots for one entry. Read as
/// the deque it is; every change goes through it.
#[derive(Debug)]
pub struct Deque<T, const L: usize = 4>(VecDeque<T>);

impl<T, const L: usize> Default for Deque<T, L> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<T, const L: usize> std::ops::Deref for Deque<T, L> {
    type Target = VecDeque<T>;

    fn deref(&self) -> &VecDeque<T> {
        &self.0
    }
}

impl<T, const L: usize> Deque<T, L> {
    /// What a full deque grows by at least, and what it may keep beyond a quarter again what it
    /// holds.
    pub const LEAST: usize = L;

    /// What each entry's holder is charged beside the entry itself so that, with
    /// [`Self::SPARE_FIXED`], what the holders are charged together is never less than what the
    /// deque allocates: a quarter of an entry, rounded up, since a deque of `len` keeps at most a
    /// quarter again and [`Self::LEAST`] more ([`Self::capacity_at_most`]). For a deque whose
    /// entries carry charges of their own, where the deque's growth cannot be charged as it comes.
    pub const SPARE_PER_ENTRY: usize = size_of::<T>().div_ceil(4);

    /// What the deque keeps beyond its entries' shares ([`Self::SPARE_PER_ENTRY`]): `LEAST`
    /// entries.
    pub const SPARE_FIXED: usize = vec::<T>(L);

    pub fn new() -> Self {
        Self::default()
    }

    /// What it allocates.
    pub fn bytes(&self) -> usize {
        vec::<T>(self.0.capacity())
    }

    /// The capacity one of `len` entries keeps at most: a quarter again and [`Self::LEAST`] more.
    pub const fn capacity_at_most(len: usize) -> usize {
        len + len / 4 + Self::LEAST
    }

    /// What one of `len` entries allocates at most ([`Self::capacity_at_most`]).
    pub const fn bytes_at_most(len: usize) -> usize {
        vec::<T>(Self::capacity_at_most(len))
    }

    /// The capacity a full deque of `capacity` grows to: a quarter again, at least `LEAST` more.
    pub const fn grown(capacity: usize) -> usize {
        capacity + max(capacity / 4, Self::LEAST)
    }

    /// What one more entry allocates more: nothing while it has room, else its growth.
    pub fn growth(&self) -> usize {
        let capacity = self.0.capacity();
        if self.0.len() < capacity {
            0
        } else {
            vec::<T>(Self::grown(capacity)) - vec::<T>(capacity)
        }
    }

    /// What `more` entries pushed one by one allocate more, at most: its growth, each time it is
    /// full, as [`Deque::grown`] grows it.
    pub fn growth_by(&self, more: usize) -> usize {
        let start = self.0.capacity();
        let (mut capacity, mut len) = (start, self.0.len());
        for _ in 0..more {
            if len == capacity {
                capacity = Self::grown(capacity);
            }
            len += 1;
        }
        vec::<T>(capacity) - vec::<T>(start)
    }

    fn room(&mut self) {
        let capacity = self.0.capacity();
        if self.0.len() == capacity {
            self.0.reserve_exact(Self::grown(capacity) - self.0.len());
        }
    }

    /// Shrinks it once its capacity passes what its length keeps, to an eighth again its length.
    fn kept(&mut self) {
        let len = self.0.len();
        if self.0.capacity() > Self::capacity_at_most(len) {
            self.0.shrink_to(len + len / 8);
        }
    }

    pub fn push_back(&mut self, value: T) {
        self.room();
        self.0.push_back(value);
    }

    pub fn push_front(&mut self, value: T) {
        self.room();
        self.0.push_front(value);
    }

    pub fn pop_front(&mut self) -> Option<T> {
        let first = self.0.pop_front();
        self.kept();
        first
    }

    pub fn pop_back(&mut self) -> Option<T> {
        let last = self.0.pop_back();
        self.kept();
        last
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.0.front_mut()
    }

    pub fn back_mut(&mut self) -> Option<&mut T> {
        self.0.back_mut()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.0.get_mut(index)
    }

    pub fn iter_mut(&mut self) -> std::collections::vec_deque::IterMut<'_, T> {
        self.0.iter_mut()
    }

    /// Inserts `value` at `index`, as `VecDeque::insert`.
    pub fn insert(&mut self, index: usize, value: T) {
        self.room();
        self.0.insert(index, value);
    }

    pub fn remove(&mut self, index: usize) -> Option<T> {
        let removed = self.0.remove(index);
        self.kept();
        removed
    }

    pub fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.0.retain(keep);
        self.kept();
    }

    pub fn retain_mut(&mut self, keep: impl FnMut(&mut T) -> bool) {
        self.0.retain_mut(keep);
        self.kept();
    }

    /// Takes out the entries `take` says, in order, keeping the rest in order in a deque made as
    /// long as they are. Each is asked once, and both lists are made at their length before
    /// anything moves, so neither grows by doubling past what it holds: what it allocates beside
    /// the deque while it works is the two lists and a byte an entry. Before, both grew by
    /// pushing, each up to twice what it held.
    pub fn take_where(&mut self, take: impl FnMut(&T) -> bool) -> Vec<T> {
        let chosen: Vec<bool> = self.0.iter().map(take).collect();
        let count = chosen.iter().filter(|chosen| **chosen).count();
        let mut taken = Vec::with_capacity(count);
        let mut kept = Vec::with_capacity(chosen.len() - count);
        for (value, chosen) in std::mem::take(&mut self.0).into_iter().zip(chosen) {
            if chosen {
                taken.push(value);
            } else {
                kept.push(value);
            }
        }
        self.0 = VecDeque::from(kept);
        taken
    }

    /// Lets everything go, and what it allocated with it.
    pub fn clear(&mut self) {
        self.0 = VecDeque::new();
    }

    /// Everything it holds, taken out; it allocates nothing after.
    pub fn take(&mut self) -> VecDeque<T> {
        std::mem::take(&mut self.0)
    }

    /// A deque of `values`, made exactly as long.
    pub fn of(mut values: Vec<T>) -> Self {
        values.shrink_to_fit();
        Self(VecDeque::from(values))
    }
}

/// The width of a table's control group: what `hashbrown` scans at once.
#[cfg(any(
    all(target_arch = "x86_64", target_feature = "sse2"),
    all(target_arch = "x86", target_feature = "sse2"),
))]
const GROUP_WIDTH: usize = 16;
#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "sse2"),
    all(target_arch = "x86", target_feature = "sse2"),
)))]
const GROUP_WIDTH: usize = 8;

/// The entries a table of `buckets` takes before it grows: all but one up to eight buckets, seven
/// eighths past.
pub const fn capacity_of(buckets: usize) -> usize {
    if buckets <= 8 {
        buckets.saturating_sub(1)
    } else {
        buckets / 8 * 7
    }
}

/// The buckets a table is made with to take `entries` of `entry` bytes: the fewest whose capacity
/// is enough, at least four, and for an entry of a few bytes enough that its buckets are not all
/// padding.
const fn buckets_for(entries: usize, entry: usize) -> usize {
    if entries == 0 {
        return 0;
    }
    if entries < 15 {
        let least = match (GROUP_WIDTH, entry) {
            (16, 0..=1) => 14,
            (16, 2..=3) => 7,
            (8, 0..=1) => 7,
            _ => 3,
        };
        let entries = max(least, entries);
        return if entries < 4 {
            4
        } else if entries < 8 {
            8
        } else {
            16
        };
    }
    (entries * 8 / 7).next_power_of_two()
}

/// What a table of `buckets` of `(K, V)` allocates: the entries, padded to the control bytes'
/// alignment, then a control byte for each bucket and a group more.
pub const fn table<K, V>(buckets: usize) -> usize {
    if buckets == 0 {
        return 0;
    }
    let align = max(align_of::<(K, V)>(), GROUP_WIDTH);
    round_up(buckets * size_of::<(K, V)>(), align) + buckets + GROUP_WIDTH
}

/// What a `HashMap<K, V>` holding at most `held` entries, as many removed as are inserted (a
/// bounded cache churned at its cap), allocates at most at any instant. Removing leaves deleted
/// slots, and once no slot is free hashbrown rehashes in place only while its entries fill no more
/// than half its capacity; past that it moves to a table of twice the buckets, holding the old one
/// and the new one at once. So it grows until `held` and one more fill half its capacity, the
/// buckets that take twice them, and on the way holds that table and the one of half its buckets.
pub const fn table_churned<K, V>(held: usize) -> usize {
    let buckets = buckets_for(2 * (held + 1), size_of::<(K, V)>());
    table::<K, V>(buckets) + table::<K, V>(buckets / 2)
}

/// What a `HashMap<K, V>` whose capacity is kept within `entries` allocates at most, linear in
/// them: the buckets of the fewest that take them are under twice their eight sevenths, and never
/// more than sixteen for under fifteen. What a plan that counts entries takes for a map.
pub const fn table_planned<K, V>(entries: usize) -> usize {
    let buckets = 16 + (entries * 16).div_ceil(7);
    let align = max(align_of::<(K, V)>(), GROUP_WIDTH);
    buckets * size_of::<(K, V)>() + (align - 1) + buckets + GROUP_WIDTH
}

/// The most a `HashMap<K, V>` holding at least one entry allocates for each, while its capacity is
/// kept within `per` times its entries ([`Table::kept`]): the buckets that capacity names (eight
/// sevenths of it, or one more up to eight), rounded up and with one more, each with its control
/// byte, and the table's control group and padding, which one entry at least shares. So a table of
/// `len` entries, `len` at least one, allocates no more than `len` times this.
///
/// A small table is never made with fewer buckets than hashbrown's least ([`buckets_for`]: four,
/// and for an entry of a few bytes eight or sixteen), whatever its capacity is kept within, so a
/// table of a few entries may allocate more for each than its capacity names: the most of that
/// for each of up to fifteen entries is taken too. Before, a table of one tiny entry allocated
/// sixteen buckets and was reckoned at three.
pub const fn table_per_entry<K, V>(per: usize) -> usize {
    let align = max(align_of::<(K, V)>(), GROUP_WIDTH);
    let kept = ((per * 8).div_ceil(7) + 1) * (size_of::<(K, V)>() + 1) + (align - 1) + GROUP_WIDTH;
    let mut most = kept;
    let mut len = 1;
    while len < 15 {
        let least = table::<K, V>(buckets_for(len, size_of::<(K, V)>())).div_ceil(len);
        most = max(most, least);
        len += 1;
    }
    most
}

/// The buckets of one `HashMap<K, V>`, followed as it changes, and so what it allocates
/// ([`Table::bytes`]). A table's capacity is its buckets' only while it holds no tombstone (an
/// entry removed from a probe another passes), and a table grows only when an insert finds no room
/// for one more, which then leaves none: so the buckets are the most its capacity has named since
/// it was last shrunk. Every insert is told (`inserted`), and every shrink (`shrunk`); an insert
/// that may grow it is charged first ([`Table::growth`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Table {
    buckets: usize,
}

impl Table {
    /// Its buckets now.
    pub const fn buckets(&self) -> usize {
        self.buckets
    }

    /// What its map allocates now.
    pub const fn bytes<K, V>(&self) -> usize {
        table::<K, V>(self.buckets)
    }

    /// What its map allocates more, at its peak, if one more entry goes in now, its `len` entries
    /// and `capacity` as they are: nothing while it has room, else the whole table it is made
    /// into, unless it is only rehashed in place (tombstones fill it, and its entries take no more
    /// than half). A resize allocates the new table while the old is still held and frees the old
    /// after it has moved every entry, so the peak is both: charged before the insert, and the
    /// charge brought down to [`Table::bytes`] after it, as a set's growth is charged its old
    /// slots and its new. Before, only what the new table held past the old was charged, and the
    /// peak passed the store by the old table.
    pub const fn growth<K, V>(&self, len: usize, capacity: usize) -> usize {
        if len < capacity {
            return 0;
        }
        let full = capacity_of(self.buckets);
        if self.buckets > 0 && len < full / 2 {
            return 0;
        }
        let entries = max(len + 1, full + 1);
        table::<K, V>(buckets_for(entries, size_of::<(K, V)>()))
    }

    /// An entry went in, and its map's capacity reads `capacity`: a table grown, if it names more
    /// buckets than it had.
    pub fn inserted(&mut self, capacity: usize) {
        let buckets = if capacity == 0 {
            0
        } else if capacity < 8 {
            capacity + 1
        } else {
            (capacity / 7 * 8).next_power_of_two()
        };
        // Only a table freshly made reads its whole capacity, and only a growth names more.
        if buckets > self.buckets && capacity == capacity_of(buckets) {
            self.buckets = buckets;
        }
    }

    /// Keeps its map's capacity within `per` times its `len` entries (and frees it when it holds
    /// none): shrinks it to twice them once its capacity is past that. Called after entries go,
    /// so with growth (which never takes a table past four times its entries) a table kept so at
    /// four allocates at most [`table_per_entry`] of four for each entry.
    pub fn kept<K, V>(&mut self, map: &mut std::collections::HashMap<K, V>, per: usize)
    where
        K: Eq + std::hash::Hash,
    {
        let len = map.len();
        if self.buckets > 0 && capacity_of(self.buckets) > per * len {
            map.shrink_to(2 * len);
            self.shrunk::<K, V>(len, 2 * len);
        }
    }

    /// What a map of `len` entries that holds this table allocates for its new table while
    /// `shrink_to(to)` moves it there (nothing when it would not shrink): the copy beside the old
    /// one, which its peak holds (`Table::shrunk` then follows it).
    pub const fn shrinking<K, V>(&self, len: usize, to: usize) -> usize {
        let want = buckets_for(if len > to { len } else { to }, size_of::<(K, V)>());
        if want < self.buckets {
            table::<K, V>(want)
        } else {
            0
        }
    }

    /// Its map was shrunk to hold at least `to` (`shrink_to`), with `len` entries: made anew with
    /// as few buckets as take them, if that is fewer than it had, or else left as it was. Freed
    /// whole when it holds none and is shrunk to none.
    pub fn shrunk<K, V>(&mut self, len: usize, to: usize) {
        let want = buckets_for(max(len, to), size_of::<(K, V)>());
        if want < self.buckets {
            self.buckets = want;
        }
    }
}

#[cfg(test)]
mod tests {

    /// What `take_where` takes and keeps is allocated at its length, so neither list holds more
    /// than it was made for: the taken entries' list exactly theirs, the deque exactly what is
    /// kept. Before, both grew by pushing, up to twice what they held.
    #[test]
    fn take_where_allocates_what_it_takes_and_keeps() {
        let mut deque: Deque<u64> = Deque::new();
        for n in 0..1_000u64 {
            deque.push_back(n);
        }
        let taken = deque.take_where(|n| n % 3 == 0);
        assert_eq!(taken.len(), 334);
        assert_eq!(taken.capacity(), taken.len());
        assert_eq!(deque.len(), 666);
        assert_eq!(deque.capacity(), deque.len());
        assert!(taken.iter().all(|n| n % 3 == 0));
        assert!(deque.iter().all(|n| n % 3 != 0));
        assert!(deque.iter().zip(deque.iter().skip(1)).all(|(a, b)| a < b));
    }

    use super::*;
    use std::collections::HashMap;

    /// A table followed through growth, churn and shrinking names the buckets `hashbrown` gives it,
    /// read where they can be read (its capacity right after it is made anew), and growth is
    /// foretold before the insert that grows it.
    #[test]
    fn a_table_follows_its_maps_buckets_through_churn() {
        let mut map: HashMap<u64, [u8; 24]> = HashMap::new();
        let mut table = Table::default();
        let mut next = 0u64;
        for round in 0..2_000u64 {
            // Grow, then remove most, again and again: tombstones and rehashes in place.
            let keep = (round % 7) as usize * 50;
            while map.len() < keep + 300 {
                let growth = table.growth::<u64, [u8; 24]>(map.len(), map.capacity());
                let before = table.bytes::<u64, [u8; 24]>();
                map.insert(next, [0; 24]);
                next += 1;
                table.inserted(map.capacity());
                assert!(table.bytes::<u64, [u8; 24]>() <= before + growth);
            }
            let gone: Vec<u64> = map.keys().copied().skip(keep).collect();
            for key in gone {
                map.remove(&key);
            }
            if round % 5 == 0 {
                let to = map.len();
                map.shrink_to(to);
                table.shrunk::<u64, [u8; 24]>(map.len(), to);
            }
            assert!(capacity_of(table.buckets) >= map.capacity());
        }
        map.clear();
        map.shrink_to(0);
        table.shrunk::<u64, [u8; 24]>(0, 0);
        assert_eq!(table.bytes::<u64, [u8; 24]>(), 0);
    }

    /// The table that takes any number of entries allocates within their plan.
    #[test]
    fn a_table_for_entries_is_within_their_plan() {
        for entries in 0..100_000 {
            assert!(
                table::<[u8; 33], [u64; 6]>(buckets_for(
                    entries,
                    size_of::<([u8; 33], [u64; 6])>()
                )) <= table_planned::<[u8; 33], [u64; 6]>(entries)
            );
            assert!(table::<u8, ()>(buckets_for(entries, 1)) <= table_planned::<u8, ()>(entries));
        }
    }

    #[test]
    fn a_btree_bound_grows_with_its_length_and_is_none_empty() {
        assert_eq!(btree::<u64, u64>(0), leaf::<u64, u64>());
        let mut last = 0;
        for len in 1..10_000 {
            let bound = btree::<u64, u64>(len);
            assert!(bound >= last);
            assert!(bound <= btree_planned::<u64, u64>(len));
            last = bound;
        }
    }
}
