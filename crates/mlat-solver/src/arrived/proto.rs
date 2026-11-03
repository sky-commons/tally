//! The probe's incremental gather (RFC-0198 Appendix C, the held-read prototype): an area's inputs
//! as `Arrived::collect` makes them, kept between refits and changed by what changed. Each cited
//! part (a batch's sync and status entries in one slice) is read once, when it is first cited; its
//! entries enter and leave the window as the window slides. A reception's identity holds its
//! copies; a message's identities are its hearers (`collect`'s count, after each member's copies
//! are taken once); an event is a sync message two or more identities heard; a status identity is
//! kept while its aircraft has an event. What the window keeps is told downstream as changes:
//! each kept identity added or removed at its wall clock (the earliest of its copies in the
//! window). The citation is made from the parts as `collect` makes it.

use super::*;

/// A fast hasher for the prototype's own tables (their keys are counters and hashes already, and
/// a table's order is never read).
#[derive(Default, Clone, Copy)]
pub(crate) struct Fx(u64);

impl Fx {
    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

impl std::hash::Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.add(u64::from_le_bytes(word));
        }
    }
    fn write_u8(&mut self, value: u8) {
        self.add(u64::from(value));
    }
    fn write_u32(&mut self, value: u32) {
        self.add(u64::from(value));
    }
    fn write_u64(&mut self, value: u64) {
        self.add(value);
    }
    fn write_usize(&mut self, value: usize) {
        self.add(value as u64);
    }
}

/// A table under `Fx`.
pub(crate) type FxMap<K, V> = HashMap<K, V, std::hash::BuildHasherDefault<Fx>>;

/// A reception's identity in an area's gather: its member (by place in the scope), epoch,
/// counter, and message (by the gather's own number).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Id {
    pub(crate) member: u32,
    pub(crate) epoch: u32,
    pub(crate) timestamp: u64,
    pub(crate) message: u32,
}

/// A kept identity added to or removed from the window, at the wall clock it is kept at.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Change {
    Added(Id, u64),
    Removed(Id, u64),
}

/// A message as the gather holds it.
pub(crate) struct Held {
    pub(crate) hash: [u8; 32],
    pub(crate) data: Box<[u8]>,
    /// A sync message (an airborne position with an altitude), else a status (a NACp).
    pub(crate) sync: bool,
    pub(crate) address: u32,
    /// The items of held parts that carry it, active or not: it is let go at none.
    items: u32,
    /// Whether it is an event (a sync message two or more identities heard).
    event: bool,
    /// Its active identities (its hearers, `collect`'s count).
    identities: Vec<Id>,
}

/// A part's entries, by wall clock, which of them are in the window (`[lo, hi)`), and the update
/// that last cited it.
struct PartItems {
    items: Vec<(u64, Id)>,
    active: (usize, usize),
    seen: u64,
}

/// An identity's copies in the window (their wall clocks) and where it is kept, if it is.
#[derive(Default)]
struct IdState {
    walls: Vec<u64>,
    kept_at: Option<u64>,
}

/// One area's gather.
#[derive(Default)]
pub(crate) struct Gather {
    pub(crate) scope: Vec<Site>,
    /// The scope's receivers, by member index.
    pub(crate) members: Vec<PublicKey>,
    member_of: FxMap<PublicKey, u32>,
    generation: u64,
    scratch: Vec<(u64, Id)>,
    parts: BTreeMap<(u32, u64, u64, u64), PartItems>,
    pub(crate) messages: FxMap<u32, Held>,
    by_hash: FxMap<[u8; 32], u32>,
    next_message: u32,
    ids: FxMap<Id, IdState>,
    /// Each aircraft's sync messages that are events, and its status messages.
    events_of: FxMap<u32, u32>,
    status_of: FxMap<u32, Vec<u32>>,
    kept: usize,
    pub(crate) changes: Vec<Change>,
}

impl Gather {
    /// Bytes it holds, roughly as allocated.
    pub(crate) fn bytes(&self) -> usize {
        let parts: usize = self
            .parts
            .values()
            .map(|part| 64 + part.items.capacity() * size_of::<(u64, Id)>())
            .sum();
        let messages: usize = self
            .messages
            .values()
            .map(|held| 96 + held.data.len() + held.identities.capacity() * size_of::<Id>())
            .sum();
        let ids: usize = self
            .ids
            .values()
            .map(|state| 64 + state.walls.capacity() * 8)
            .sum();
        parts
            + messages
            + ids
            + self.by_hash.capacity() * 40
            + self.events_of.capacity() * 16
            + self.status_of.capacity() * 40
            + self.changes.capacity() * size_of::<Change>()
    }

    /// The inputs' scope, frontier and citation of `area` at `trailing` as `area_inputs_over`
    /// finds them, the gather brought to them, and what the window keeps changed in `changes`;
    /// `None` with fewer than two members. Whether its scope changed is the last.
    pub(crate) fn update(
        &mut self,
        arrived: &Arrived,
        area: Region,
        sites: &Sites,
        trailing: Trailing,
    ) -> Option<(Vec<Site>, Vec<Frontier>, Citation, bool)> {
        self.changes.clear();
        let scope: Vec<Site> = sites.members(area).to_vec();
        if scope.len() < 2 {
            return None;
        }
        let mut touched: Vec<Id> = Vec::new();
        let mut heard: Vec<u32> = Vec::new();
        let mut unheld: Vec<u32> = Vec::new();
        // A new scope keeps what it held of the members it keeps: a member's number is its own
        // for as long as the gather is (members are only added), and a member gone is no longer
        // cited (its parts leave below). Nothing here reads a site.
        let changed_scope = scope != self.scope;
        if changed_scope {
            for site in &scope {
                if !self.member_of.contains_key(&site.receiver) {
                    let member = self.members.len() as u32;
                    self.members.push(site.receiver);
                    self.member_of.insert(site.receiver, member);
                }
            }
            self.scope = scope.clone();
        }
        let frontier: Vec<Frontier> = scope
            .iter()
            .filter_map(|site| {
                let feed = arrived
                    .feeds
                    .get(&site.receiver)
                    .filter(|feed| feed.whole_over(&trailing))?;
                arrived.cited(site.receiver, feed, &trailing)
            })
            .collect();
        let first_slice = trailing.read_from_ms() / SLICE_MS;
        let last_slice = trailing.edge_ms / SLICE_MS;
        // The parts cited, in `collect`'s order, each read in when first cited.
        let mut parts: Vec<Part> = Vec::new();
        self.generation += 1;
        let generation = self.generation;
        for cite in &frontier {
            let Some(feed) = arrived
                .feeds
                .get(&cite.receiver)
                .filter(|feed| feed.boot_id == cite.boot_id)
            else {
                continue;
            };
            let Some(&member) = self.member_of.get(&cite.receiver) else {
                continue;
            };
            let first_part = parts.len();
            for held in &feed.batches {
                if held.slice < first_slice
                    || held.slice > last_slice
                    || held.sequence > cite.through_sequence
                {
                    continue;
                }
                let Some(slice) = arrived.slices.get(&held.slice) else {
                    continue;
                };
                let Some(batch) = slice.batches.get(held.at as usize) else {
                    continue;
                };
                if batch.forgotten || batch.sync == 0 {
                    continue;
                }
                parts.push(Part {
                    receiver: cite.receiver,
                    boot_id: cite.boot_id,
                    sequence: held.sequence,
                    slice: held.slice,
                    digest: batch.digest,
                });
                let key = (member, cite.boot_id, held.sequence, held.slice);
                if let Some(part) = self.parts.get_mut(&key) {
                    part.seen = generation;
                } else {
                    crate::probe::add(crate::probe::P::proto_parts_new, 1);
                    let entries = slice
                        .entries
                        .get(batch.first as usize..(batch.first + batch.sync) as usize)
                        .unwrap_or_default();
                    let mut items: Vec<(u64, Id)> = Vec::with_capacity(entries.len());
                    for one in entries {
                        let message = &slice.messages[one.message as usize];
                        let number = self.register(message);
                        items.push((
                            held.slice * SLICE_MS + u64::from(one.into_ms),
                            Id {
                                member,
                                epoch: one.epoch,
                                timestamp: one.counter(),
                                message: number,
                            },
                        ));
                    }
                    items.sort_unstable_by_key(|(wall, id)| (*wall, *id));
                    self.parts.insert(
                        key,
                        PartItems {
                            items,
                            active: (0, 0),
                            seen: generation,
                        },
                    );
                }
            }
            parts[first_part..].sort_unstable_by_key(|part| (part.sequence, part.slice));
        }
        // What entered and left the window: parts no longer cited, and each part's entries by
        // the window's span.
        let (from, to) = (trailing.read_from_ms(), trailing.edge_ms);
        let gone: Vec<(u32, u64, u64, u64)> = self
            .parts
            .iter()
            .filter(|(_, part)| part.seen != generation)
            .map(|(key, _)| *key)
            .collect();
        crate::probe::add(crate::probe::P::proto_parts_gone, gone.len() as u64);
        for key in gone {
            let Some(part) = self.parts.remove(&key) else {
                continue;
            };
            for (wall, id) in &part.items[part.active.0..part.active.1] {
                self.leave(*id, *wall, &mut touched, &mut heard);
            }
            unheld.extend(part.items.iter().map(|(_, id)| id.message));
        }
        // A part's entries enter and leave as the window passes its slice: only a part of a slice
        // at either end of the window, or one not yet whole in it, changes.
        let mut scratch = std::mem::take(&mut self.scratch);
        for part in self.parts.values_mut() {
            let lo = part.items.partition_point(|(wall, _)| *wall < from);
            let hi = part.items.partition_point(|(wall, _)| *wall < to);
            let old = part.active;
            if old == (lo, hi) {
                continue;
            }
            for at in old.0..old.1 {
                if at < lo || at >= hi {
                    scratch.push((part.items[at].0 | 1 << 63, part.items[at].1));
                }
            }
            for at in lo..hi {
                if at < old.0 || at >= old.1 {
                    scratch.push(part.items[at]);
                }
            }
            part.active = (lo, hi);
        }
        for (wall, id) in scratch.drain(..) {
            if wall & 1 << 63 != 0 {
                self.leave(id, wall & !(1 << 63), &mut touched, &mut heard);
            } else {
                self.enter(id, wall, &mut touched, &mut heard);
            }
        }
        self.scratch = scratch;
        // Events whose hearers changed: where one became or stopped being an event, its
        // identities, and where its aircraft gained its first or lost its last, its status ones.
        heard.sort_unstable();
        heard.dedup();
        let mut flipped: Vec<u32> = Vec::new();
        for number in heard {
            let Some(held) = self.messages.get_mut(&number) else {
                continue;
            };
            if !held.sync {
                continue;
            }
            let now = held.identities.len() >= 2;
            if now == held.event {
                continue;
            }
            held.event = now;
            touched.extend(held.identities.iter().copied());
            let count = self.events_of.entry(held.address).or_insert(0);
            let before = *count > 0;
            if now {
                *count += 1;
            } else {
                *count -= 1;
            }
            if before != (*count > 0) {
                flipped.push(held.address);
            }
            if *count == 0 {
                self.events_of.remove(&held.address);
            }
        }
        for address in flipped {
            if let Some(statuses) = self.status_of.get(&address) {
                for number in statuses {
                    if let Some(held) = self.messages.get(number) {
                        touched.extend(held.identities.iter().copied());
                    }
                }
            }
        }
        touched.sort_unstable();
        touched.dedup();
        crate::probe::add(crate::probe::P::proto_touched, touched.len() as u64);
        for id in touched {
            let kept_now = self.kept_wall(&id);
            let Some(state) = self.ids.get_mut(&id) else {
                continue;
            };
            let was = state.kept_at;
            if was == kept_now {
                if state.walls.is_empty() {
                    self.ids.remove(&id);
                }
                continue;
            }
            state.kept_at = kept_now;
            if let Some(wall) = was {
                self.changes.push(Change::Removed(id, wall));
                self.kept -= 1;
            }
            if let Some(wall) = kept_now {
                self.changes.push(Change::Added(id, wall));
                self.kept += 1;
            }
            if state.walls.is_empty() {
                self.ids.remove(&id);
            }
        }
        crate::probe::add(crate::probe::P::proto_changes, self.changes.len() as u64);
        for number in unheld {
            self.unregister(number);
        }
        let citation = Citation::of_parts(&parts, self.kept);
        Some((scope, frontier, citation, changed_scope))
    }

    /// Where `id` is kept now: its earliest copy's wall clock, when its message is an event or
    /// a status of an aircraft with one.
    fn kept_wall(&self, id: &Id) -> Option<u64> {
        let state = self.ids.get(id)?;
        let wall = state.walls.iter().min().copied()?;
        let held = self.messages.get(&id.message)?;
        let kept = if held.sync {
            held.event
        } else {
            self.events_of.get(&held.address).copied().unwrap_or(0) > 0
        };
        kept.then_some(wall)
    }

    fn enter(&mut self, id: Id, wall: u64, touched: &mut Vec<Id>, heard: &mut Vec<u32>) {
        let state = self.ids.entry(id).or_default();
        let first = state.walls.is_empty();
        state.walls.push(wall);
        touched.push(id);
        if first && let Some(held) = self.messages.get_mut(&id.message) {
            held.identities.push(id);
            heard.push(id.message);
        }
    }

    fn leave(&mut self, id: Id, wall: u64, touched: &mut Vec<Id>, heard: &mut Vec<u32>) {
        let Some(state) = self.ids.get_mut(&id) else {
            return;
        };
        if let Some(at) = state.walls.iter().position(|held| *held == wall) {
            state.walls.swap_remove(at);
        }
        touched.push(id);
        if state.walls.is_empty()
            && let Some(held) = self.messages.get_mut(&id.message)
        {
            if let Some(at) = held.identities.iter().position(|one| *one == id) {
                held.identities.swap_remove(at);
            }
            heard.push(id.message);
        }
    }

    fn register(&mut self, message: &Message) -> u32 {
        if let Some(number) = self.by_hash.get(&message.hash) {
            if let Some(held) = self.messages.get_mut(number) {
                held.items += 1;
            }
            return *number;
        }
        let number = self.next_message;
        self.next_message += 1;
        let sync = message.kind == Kind::Sync;
        self.by_hash.insert(message.hash, number);
        self.messages.insert(
            number,
            Held {
                hash: message.hash,
                data: message.key.bytes().into(),
                sync,
                address: message.address,
                items: 1,
                event: false,
                identities: Vec::new(),
            },
        );
        if !sync {
            self.status_of
                .entry(message.address)
                .or_default()
                .push(number);
        }
        number
    }

    fn unregister(&mut self, number: u32) {
        let Some(held) = self.messages.get_mut(&number) else {
            return;
        };
        held.items -= 1;
        if held.items > 0 {
            return;
        }
        let Some(held) = self.messages.remove(&number) else {
            return;
        };
        self.by_hash.remove(&held.hash);
        if !held.sync
            && let Some(list) = self.status_of.get_mut(&held.address)
        {
            list.retain(|one| *one != number);
            if list.is_empty() {
                self.status_of.remove(&held.address);
            }
        }
    }
}
