//! A map that holds at most a fixed number of keys. Everything a relay remembers per author
//! (receivers, boots, engines) lives in one, so no stranger can grow the relay's memory by
//! inventing keys.
//!
//! When full it forgets the key least recently *active*: a key's rank is the later of when it was
//! first written and when the caller last marked it active. Rewriting a key it holds does not
//! refresh it; only the caller's mark does. Marking is how a caller says which keys earn their
//! place by something a stranger cannot cheaply fake: a receiver's description is marked by its
//! forwarded batches, never by another description. So a flood of fresh keys forgets itself oldest
//! first, a key that keeps showing activity keeps its place, and a key just written is never the
//! one forgotten to make its own room: a new honest key holds its place until enough newer keys
//! have arrived since it last showed activity, the same as every other.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

/// The tick a key was last active (first written, or marked). Ticks are unique, so no two keys
/// share a rank.
type Rank = u64;

pub struct Bounded<K, V> {
    capacity: usize,
    /// Each key's value, and its rank.
    entries: HashMap<K, (Rank, V)>,
    /// The keys in the order they are forgotten, first first.
    order: BTreeMap<Rank, K>,
    tick: u64,
}

impl<K, V> Bounded<K, V> {
    /// What a map of `capacity` keys allocates at most, at every instant, whatever it holds: its
    /// order's tree at one past its capacity (a write adds its key before it forgets one), and its
    /// entries' table as a table churned at that many (`footprint::table_churned`: a map that
    /// forgets as many keys as it is written grows its table past twice its keys, and holds the
    /// old table and the new one as it does).
    pub const fn planned_bytes(capacity: usize) -> usize {
        let held = if capacity == 0 { 1 } else { capacity } + 1;
        tally_wire::footprint::table_churned::<K, (Rank, V)>(held)
            + tally_wire::footprint::btree_planned::<Rank, K>(held)
    }
}

impl<K: Hash + Eq + Clone, V> Bounded<K, V> {
    /// At least one key is always held.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
        }
    }

    /// Reading a key does not count as activity.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|(_, value)| value)
    }

    /// Changing a value in place does not count as activity either.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key).map(|(_, value)| value)
    }

    /// Writes `key`. A key not held is ranked as active now; a key held keeps its rank. Forgets
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
        let (_, first) = self.order.pop_first()?;
        self.entries.remove(&first);
        Some(first)
    }

    /// The key least recently active, and its value: the next `forget_first` forgets.
    pub fn first(&self) -> Option<(&K, &V)> {
        let (_, key) = self.order.first_key_value()?;
        self.entries.get(key).map(|(_, value)| (key, value))
    }

    /// Forgets the key least recently active and returns it with its value, for a caller that
    /// accounts for what each value holds.
    pub fn pop_first(&mut self) -> Option<(K, V)> {
        let (_, first) = self.order.pop_first()?;
        let (_, value) = self.entries.remove(&first)?;
        Some((first, value))
    }

    /// Forgets `key`, returning its value.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (rank, value) = self.entries.remove(key)?;
        self.order.remove(&rank);
        Some(value)
    }

    fn write(&mut self, key: K, value: V, active: bool) -> Option<K> {
        self.tick += 1;
        let rank = match self.entries.get_mut(&key) {
            Some((rank, held)) => {
                *held = value;
                if active {
                    self.order.remove(rank);
                    *rank = self.tick;
                    self.order.insert(*rank, key);
                }
                return None;
            }
            None => self.tick,
        };
        self.entries.insert(key.clone(), (rank, value));
        self.order.insert(rank, key);
        // One write adds at most one key, so at most one is forgotten, and it is never the key
        // just written: that one holds the newest rank, and at least one other is held.
        if self.entries.len() > self.capacity {
            self.forget_first()
        } else {
            None
        }
    }

    /// Marks `key` active now, so it is forgotten after every key active longer ago. A key not
    /// held is left unheld.
    pub fn touch(&mut self, key: &K) {
        self.tick += 1;
        let tick = self.tick;
        if let Some((rank, _)) = self.entries.get_mut(key) {
            self.order.remove(rank);
            *rank = tick;
            self.order.insert(tick, key.clone());
        }
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values().map(|(_, value)| value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, (_, value))| (key, value))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
}
