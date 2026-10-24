//! A map that holds at most a fixed number of keys. Everything a relay remembers per author
//! (receivers, boots, engines) lives in one, so no stranger can grow the relay's memory by
//! inventing keys.
//!
//! When full it forgets the key least recently *active*: a key's place is the later of when it was
//! first written and when the caller last marked it active. Rewriting a key it holds does not
//! refresh it; only the caller's mark does. Marking is how a caller says which keys earn their
//! place by something a stranger cannot cheaply fake: a receiver's description is marked by its
//! forwarded batches, never by another description. So a flood of fresh keys forgets itself oldest
//! first, a key that keeps showing activity keeps its place, and a key just written is never the
//! one forgotten to make its own room: a new honest key holds its place until enough newer keys
//! have arrived since it last showed activity, the same as every other.
//!
//! Its layout is chosen so what it allocates is planned exactly, whatever it is written
//! ([`Bounded::planned_bytes`]). Each entry lives in a slot of fixed pages ([`PAGE`] slots each),
//! made as entries come and never moved, the slots linked in the order they are forgotten (an
//! intrusive list: the least recently active first) with a list of the free ones beside it. A
//! table holds each key and its slot's number, four bytes, never the value: so a large value is
//! held once, in its slot, and only the small table is ever made anew. The table is never let
//! grow on its own: before a new key would find it full (its capacity spent by entries and by the
//! slots removals leave deleted), it is made anew here at the size its keys need and an eighth
//! more, and the old one let go once every key has moved. So its peak is two tables of that size,
//! whatever was written and in whatever order, with no reliance on how `hashbrown` reuses a
//! deleted slot or rehashes in place.

use std::collections::HashMap;
use std::hash::Hash;
use std::mem::size_of;

use tally_wire::footprint::{table_made, table_planned, vec};

/// The slots a page holds: a map of fewer keys makes one page of just its capacity.
pub const PAGE: usize = 64;

/// The most keys a map holds: a slot's number is four bytes, one of them meaning none.
const MOST: usize = (u32::MAX - 1) as usize;

const NONE: u32 = u32::MAX;

/// One slot: an entry, or none while it is free, and its neighbours in the order of forgetting
/// (the free list's next, while it is free).
struct Slot<K, V> {
    entry: Option<(K, V)>,
    prev: u32,
    next: u32,
}

pub struct Bounded<K, V> {
    capacity: usize,
    /// Each key's slot.
    index: HashMap<K, u32>,
    pages: Vec<Box<[Slot<K, V>]>>,
    /// The slots a page holds, for this map's capacity.
    page: usize,
    /// The key least recently active, forgotten first; and the most recently active.
    head: u32,
    tail: u32,
    /// The first free slot of the pages made.
    free: u32,
}

/// The keys a map of `capacity` keys holds: at least one, and at most a slot's number allows.
const fn clamped(capacity: usize) -> usize {
    if capacity == 0 {
        1
    } else if capacity > MOST {
        MOST
    } else {
        capacity
    }
}

/// The slots a page holds for a map of `capacity` keys.
const fn page_of(capacity: usize) -> usize {
    if capacity < PAGE { capacity } else { PAGE }
}

/// What a table made for `keys` keys is asked to take: an eighth more than them, so the slots
/// removals leave deleted take that many writes of new keys to fill, and making it anew costs a
/// few moves for each write, never one for every write.
const fn table_room(keys: usize) -> usize {
    keys + keys / 8 + 1
}

impl<K, V> Bounded<K, V> {
    /// What a map of `capacity` keys allocates at most, at every instant, whatever it is written:
    /// its pages, made one at a time as entries come, all of them at its capacity; the list of
    /// them, which may grow beside the one it replaces; and its table of slots, made anew at
    /// [`table_room`] of its capacity, the old one and the new one held at once while its keys
    /// move. The table is never let grow on its own, so no larger one is ever made.
    pub const fn planned_bytes(capacity: usize) -> usize {
        let capacity = clamped(capacity);
        let page = page_of(capacity);
        let pages = capacity.div_ceil(page);
        pages * page * size_of::<Slot<K, V>>()
            + 2 * vec::<Box<[Slot<K, V>]>>(pages)
            + 2 * table_made::<K, u32>(table_room(capacity))
    }

    /// What [`Bounded::planned_bytes`] takes for each key at most, linear in the keys with
    /// [`Bounded::fixed_bytes`]: its slot, its share of the list of pages, and its share of the
    /// two tables (`footprint::table_planned`, which no table made for that many exceeds, of an
    /// eighth more than the keys). What a plan that sizes a map by the keys it may hold charges
    /// for each.
    pub const fn bytes_per_key() -> usize {
        let entry = size_of::<(K, u32)>() + 1;
        size_of::<Slot<K, V>>()
            + (2 * size_of::<Box<[Slot<K, V>]>>()).div_ceil(PAGE)
            + 2 * (18 * entry).div_ceil(7)
    }

    /// What [`Bounded::planned_bytes`] takes beside [`Bounded::bytes_per_key`] for each key: a
    /// page's slack, the list's least, and the two tables' fixed part (their least buckets, a
    /// control group, the padding, and the rounding up of a key's share).
    pub const fn fixed_bytes() -> usize {
        let entry = size_of::<(K, u32)>() + 1;
        PAGE * size_of::<Slot<K, V>>()
            + 2 * size_of::<Box<[Slot<K, V>]>>()
            + 2 * (table_planned::<K, u32>(0) + 3 * entry)
    }
}

impl<K: Hash + Eq + Clone, V> Bounded<K, V> {
    /// At least one key is always held.
    pub fn new(capacity: usize) -> Self {
        let capacity = clamped(capacity);
        Self {
            capacity,
            index: HashMap::new(),
            pages: Vec::new(),
            page: page_of(capacity),
            head: NONE,
            tail: NONE,
            free: NONE,
        }
    }

    /// The keys it holds at most.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn slot(&self, at: u32) -> &Slot<K, V> {
        let at = at as usize;
        &self.pages[at / self.page][at % self.page]
    }

    fn slot_mut(&mut self, at: u32) -> &mut Slot<K, V> {
        let at = at as usize;
        let page = self.page;
        &mut self.pages[at / page][at % page]
    }

    /// Reading a key does not count as activity.
    pub fn get(&self, key: &K) -> Option<&V> {
        let at = *self.index.get(key)?;
        self.slot(at).entry.as_ref().map(|(_, value)| value)
    }

    /// Changing a value in place does not count as activity either.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let at = *self.index.get(key)?;
        self.slot_mut(at).entry.as_mut().map(|(_, value)| value)
    }

    /// Writes `key`. A key not held is placed as active now; a key held keeps its place. Forgets
    /// the key least recently active if that is one too many, and returns it: never `key` itself.
    pub fn insert(&mut self, key: K, value: V) -> Option<K> {
        self.write(key, value, false)
    }

    /// Writes `key` and marks it active now, in one step. Returns the key forgotten, if any.
    pub fn insert_active(&mut self, key: K, value: V) -> Option<K> {
        self.write(key, value, true)
    }

    /// Forgets the key least recently active, for a caller holding the map to a budget of its own
    /// beside the count. Returns it.
    pub fn forget_first(&mut self) -> Option<K> {
        self.pop_first().map(|(key, _)| key)
    }

    /// The key least recently active, and its value: the next `forget_first` forgets.
    pub fn first(&self) -> Option<(&K, &V)> {
        if self.head == NONE {
            return None;
        }
        self.slot(self.head)
            .entry
            .as_ref()
            .map(|(key, value)| (key, value))
    }

    /// Forgets the key least recently active and returns it with its value, for a caller that
    /// accounts for what each value holds.
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        if self.head == NONE {
            return None;
        }
        let at = self.head;
        let (key, value) = self.release(at)?;
        self.index.remove(&key);
        Some((key, value))
    }

    /// Forgets `key`, returning its value.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let at = self.index.remove(key)?;
        self.release(at).map(|(_, value)| value)
    }

    /// Takes slot `at` out of the order and frees it, returning what it held.
    fn release(&mut self, at: u32) -> Option<(K, V)> {
        self.unlink(at);
        let free = self.free;
        let slot = self.slot_mut(at);
        let entry = slot.entry.take();
        slot.next = free;
        slot.prev = NONE;
        self.free = at;
        entry
    }

    /// Takes slot `at` out of the order, leaving its entry.
    fn unlink(&mut self, at: u32) {
        let (prev, next) = {
            let slot = self.slot(at);
            (slot.prev, slot.next)
        };
        if prev == NONE {
            self.head = next;
        } else {
            self.slot_mut(prev).next = next;
        }
        if next == NONE {
            self.tail = prev;
        } else {
            self.slot_mut(next).prev = prev;
        }
    }

    /// Puts slot `at` last in the order: the most recently active.
    fn link_last(&mut self, at: u32) {
        let tail = self.tail;
        {
            let slot = self.slot_mut(at);
            slot.prev = tail;
            slot.next = NONE;
        }
        if tail == NONE {
            self.head = at;
        } else {
            self.slot_mut(tail).next = at;
        }
        self.tail = at;
    }

    /// A free slot, a page made for it if none is: only while fewer than the capacity are held,
    /// so the pages never pass the capacity.
    fn take_free(&mut self) -> u32 {
        if self.free == NONE {
            let first = self.pages.len() * self.page;
            if self.pages.len() == self.pages.capacity() {
                // The list grows to at most the pages its capacity needs, doubling till then.
                let most = self.capacity.div_ceil(self.page);
                let want = most.min(2 * self.pages.len()).max(1);
                self.pages.reserve_exact(want - self.pages.len());
            }
            let page: Box<[Slot<K, V>]> = (0..self.page)
                .map(|n| Slot {
                    entry: None,
                    prev: NONE,
                    next: if n + 1 < self.page {
                        (first + n + 1) as u32
                    } else {
                        NONE
                    },
                })
                .collect();
            self.pages.push(page);
            self.free = first as u32;
        }
        let at = self.free;
        self.free = self.slot(at).next;
        at
    }

    /// Room in the table for one key more, making it anew first if it has none: at
    /// [`table_room`] of the keys it may come to hold, its capacity or twice what it holds, the
    /// lesser. Before it is full, so it never grows (or rehashes) on its own.
    fn table_room_for_one(&mut self) {
        if self.index.len() < self.index.capacity() {
            return;
        }
        let keys = self
            .capacity
            .min(2 * (self.index.len() + 1))
            .max(self.index.len() + 1);
        let mut made = HashMap::with_capacity(table_room(keys));
        made.extend(self.index.drain());
        self.index = made;
    }

    fn write(&mut self, key: K, value: V, active: bool) -> Option<K> {
        if let Some(&at) = self.index.get(&key) {
            if let Some((_, held)) = self.slot_mut(at).entry.as_mut() {
                *held = value;
            }
            if active {
                self.unlink(at);
                self.link_last(at);
            }
            return None;
        }
        // One write adds at most one key, so at most one is forgotten, and never the key being
        // written: it is not held yet, and goes in last.
        let forgotten = if self.index.len() >= self.capacity {
            self.forget_first()
        } else {
            None
        };
        self.table_room_for_one();
        let at = self.take_free();
        self.slot_mut(at).entry = Some((key.clone(), value));
        self.link_last(at);
        self.index.insert(key, at);
        forgotten
    }

    /// Marks `key` active now, so it is forgotten after every key active longer ago. A key not
    /// held is left unheld.
    pub fn touch(&mut self, key: &K) {
        if let Some(&at) = self.index.get(key) {
            self.unlink(at);
            self.link_last(at);
        }
    }

    /// Holds at most `capacity` keys from now (at least one), forgetting the least recently
    /// active past it; returned, first first. A map made smaller is made anew at its new capacity,
    /// its keys in the same order, so it allocates what [`Bounded::planned_bytes`] of the new
    /// capacity says (the old pages are held beside the new ones while the keys move).
    pub fn set_capacity(&mut self, capacity: usize) -> Vec<(K, V)> {
        let capacity = clamped(capacity);
        let mut forgotten = Vec::new();
        while self.index.len() > capacity {
            if let Some(entry) = self.pop_first() {
                forgotten.push(entry);
            }
        }
        if capacity < self.capacity {
            let mut made = Self::new(capacity);
            while let Some((key, value)) = self.pop_first() {
                made.write(key, value, false);
            }
            *self = made;
        } else {
            self.capacity = capacity;
            // A map made of one short page keeps it; pages made from now are as long as the new
            // capacity needs, and the slots are numbered by the pages' length, so it is kept.
            if self.pages.is_empty() {
                self.page = page_of(capacity);
            } else if self.page < PAGE && self.page < capacity {
                let mut made = Self::new(capacity);
                while let Some((key, value)) = self.pop_first() {
                    made.write(key, value, false);
                }
                *self = made;
            }
        }
        forgotten
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, value)| value)
    }

    /// Every key held, with its value, least recently active first.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut at = self.head;
        std::iter::from_fn(move || {
            if at == NONE {
                return None;
            }
            let slot = self.slot(at);
            at = slot.next;
            slot.entry.as_ref().map(|(key, value)| (key, value))
        })
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_full_the_key_least_recently_active_is_forgotten() {
        let mut map = Bounded::new(2);
        map.insert("a", 1);
        map.insert("b", 2);
        // Neither reading nor rewriting `a` refreshes it; marking it does.
        assert_eq!(map.get(&"a"), Some(&1));
        map.insert("a", 3);
        assert_eq!(map.insert("c", 4), Some("a"));
        map.touch(&"b");
        map.insert_active("c", 5);
        assert_eq!(map.insert("d", 6), Some("b"));
        assert_eq!(
            (map.get(&"b"), map.get(&"c"), map.get(&"d")),
            (None, Some(&5), Some(&6))
        );
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn a_new_key_is_never_forgotten_on_its_first_write_however_many_are_active() {
        const CAPACITY: u32 = 1_000;
        let mut map = Bounded::new(CAPACITY as usize);
        for n in 0..CAPACITY {
            map.insert(n, n);
            map.touch(&n);
        }
        // Every key held has been active; a new one still takes the place of the stalest.
        assert_eq!(map.insert(CAPACITY, 0), Some(0));
        assert_eq!(map.get(&CAPACITY), Some(&0));
        // And it holds its place until as many newer keys have arrived as the map holds.
        for n in 1..CAPACITY {
            assert_ne!(map.insert(CAPACITY + n, 0), Some(CAPACITY));
        }
        assert_eq!(map.get(&CAPACITY), Some(&0));
        assert_eq!(map.insert(2 * CAPACITY, 0), Some(CAPACITY));
    }

    #[test]
    fn a_flood_of_fresh_keys_forgets_itself_and_never_a_key_that_keeps_showing_activity() {
        const CAPACITY: usize = 16;
        const HONEST: u32 = u32::MAX;
        let mut map = Bounded::new(CAPACITY);
        map.insert(HONEST, 0);
        for n in 0..(100 * CAPACITY as u32) {
            // Rewriting it alone would not keep it; its activity, at least once per map's worth of
            // fresh keys, does.
            map.insert(HONEST, n);
            if n % (CAPACITY as u32 / 2) == 0 {
                map.touch(&HONEST);
            }
            map.insert(n, n);
            assert!(map.get(&HONEST).is_some(), "forgot the active key at {n}");
            assert!(map.len() <= CAPACITY);
        }
        // The fresh keys held are the newest, the oldest forgotten first.
        let last = 100 * CAPACITY as u32;
        assert!(map.get(&(last - 1)).is_some());
        assert!(map.get(&(last - CAPACITY as u32)).is_none());
    }

    /// Removing keys from anywhere, and writing new ones, keeps the order of forgetting: the
    /// survivors are forgotten oldest first, and a freed slot is reused, so the pages made never
    /// pass the capacity.
    #[test]
    fn removals_keep_the_order_and_reuse_their_slots() {
        const CAPACITY: usize = 200;
        let mut map = Bounded::new(CAPACITY);
        for n in 0..10_000u32 {
            map.insert(n, n);
            if n % 3 == 0 {
                map.remove(&(n / 2));
            }
            assert!(map.pages.len() * map.page <= CAPACITY.div_ceil(PAGE) * PAGE);
        }
        let held: Vec<u32> = map.iter().map(|(key, _)| *key).collect();
        let mut sorted = held.clone();
        sorted.sort_unstable();
        assert_eq!(held, sorted, "not forgotten in the order written");
        assert_eq!(map.first().map(|(key, _)| *key), held.first().copied());
        assert_eq!(held.len(), map.len());
    }

    /// A map made smaller forgets its least recently active keys, keeps the rest in order, and is
    /// made anew at its new capacity; made larger, it takes more.
    #[test]
    fn a_new_capacity_forgets_the_stalest_and_keeps_the_order() {
        let mut map = Bounded::new(100);
        for n in 0..100u32 {
            map.insert(n, n);
        }
        map.touch(&0);
        let forgotten: Vec<u32> = map.set_capacity(10).into_iter().map(|(k, _)| k).collect();
        assert_eq!(forgotten, (1..91).collect::<Vec<_>>());
        let held: Vec<u32> = map.iter().map(|(key, _)| *key).collect();
        assert_eq!(held, [91, 92, 93, 94, 95, 96, 97, 98, 99, 0]);
        assert_eq!(map.pages.len() * map.page, 10);
        map.set_capacity(300);
        for n in 1_000..1_290u32 {
            assert_eq!(map.insert(n, n), None);
        }
        assert_eq!(map.len(), 300);
        assert_eq!(map.insert(5_000, 0), Some(91));
    }

    /// The linear figures a plan sizes the map by are never below what it allocates at most, on
    /// each side of every doubling of its table and its pages.
    #[test]
    fn the_linear_figures_cover_the_plan() {
        fn check<K, V>() {
            let mut capacity = 1usize;
            while capacity < 4_000_000 {
                for at in [capacity.saturating_sub(1).max(1), capacity, capacity + 1] {
                    let planned = Bounded::<K, V>::planned_bytes(at);
                    let linear =
                        Bounded::<K, V>::fixed_bytes() + at * Bounded::<K, V>::bytes_per_key();
                    assert!(
                        planned <= linear,
                        "{at}: {planned} planned, {linear} linear"
                    );
                }
                capacity = capacity * 8 / 7 + 1;
            }
        }
        check::<[u8; 32], [u8; 150]>();
        check::<u64, ()>();
        check::<[u8; 32], u64>();
    }
}
