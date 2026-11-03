//! The probe's held-read prototype (RFC-0198 Appendix C): an area's refit that keeps its read
//! between refits and pays for what changed. Its gather is `arrived::proto::Gather`; each kept
//! reception it adds or removes is placed in its second here, linearized once. Each second's
//! digest is #45's rule (a position for its own second, with whether the window holds its
//! clock; a NACp for each second near it holding a position of its aircraft), kept by adding and
//! taking away each reception's part. A second's formed points (its events' points by pair) are
//! held by the digest of the seconds they read (`LOOK_BACK_S` before to `SPAN_AFTER_S` after) and
//! formed again only when it changed, by a `Reader` of those seconds alone; a block is held by
//! the digest of the seconds it reads, as `BlockCache` holds it, and built from held formed
//! seconds. The window's clocks (their lowest count and when it was heard) are found by one pass
//! over the window's receptions. The fit is the engine's, from the same window. Its model is
//! compared with a cold refit by the probe's shadow (`tally_mlat::fix`), byte for byte.

use super::*;
use crate::arrived::Arrived;
use crate::arrived::proto::{Change, FxMap, Gather, Id};
use crate::probe::{self as probe_counters, P};
use crate::scope::Sites;
use crate::sync::held::{HeldRead, HeldRx};
use crate::sync::{Reads, SiteInfo};
use blocks::RawPoint;
use std::time::Instant;

type Digest = u128;

/// A pair of the prototype's clocks (by its own numbering), the lower key first.
type ClockPair = (u32, u32);

/// One kept reception as the prototype holds it.
#[derive(Clone, Copy)]
struct Rec {
    clock: u32,
    linear: i64,
    wall: u64,
    address: u32,
    position: bool,
    /// Its place in the held read.
    slot: u32,
    /// Its digest's part: a NACp's (`[0]`), or a position's with its clock out of the window
    /// (`[0]`) and in it (`[1]`).
    parts: [Digest; 2],
}

/// One second's kept receptions.
#[derive(Default)]
struct SecondStore {
    recs: Vec<(Id, Rec)>,
    index: FxMap<Id, u32>,
}

impl SecondStore {
    fn insert(&mut self, id: Id, rec: Rec) {
        self.index.insert(id, self.recs.len() as u32);
        self.recs.push((id, rec));
    }

    fn remove(&mut self, id: &Id) -> Option<Rec> {
        let at = self.index.remove(id)? as usize;
        let (_, rec) = self.recs.swap_remove(at);
        if let Some((moved, _)) = self.recs.get(at) {
            self.index.insert(*moved, at as u32);
        }
        Some(rec)
    }
}

struct ClockState {
    key: ClockKey,
    site: SiteInfo,
    /// Whether the window holds it (a reception of it in the window's own seconds), as its
    /// positions' digest parts were last given.
    window: bool,
}

/// One second's formed points: its events, and its points by pair, as `Raw::second` forms them.
pub(super) struct Formed {
    events: usize,
    pairs: FxMap<ClockPair, Vec<RawPoint>>,
}

/// The held formed seconds a refit's `Raw` builds its cut blocks from.
pub(super) struct Pool {
    /// Each window clock's number.
    clocks: Vec<u32>,
    formed: BTreeMap<u64, Arc<Formed>>,
}

impl Pool {
    /// As `Raw::block`, from the held formed seconds.
    pub(super) fn block(
        &self,
        (a, b): (u32, u32),
        own: u64,
        timebases: (Timebase, Timebase),
        from: (Option<i64>, Option<i64>),
    ) -> Option<PairBlock> {
        let key = (self.clocks[a as usize], self.clocks[b as usize]);
        let mut pooled: Vec<(u64, RawPoint)> = Vec::new();
        for second in own.saturating_sub(blocks::LINE_BLOCKS - 1)..=own {
            if let Some(list) = self
                .formed
                .get(&second)
                .and_then(|formed| formed.pairs.get(&key))
            {
                pooled.extend(
                    list.iter()
                        .filter(|p| {
                            from.0.is_none_or(|from| p.la >= from)
                                && from.1.is_none_or(|from| p.lb >= from)
                        })
                        .map(|p| (second, *p)),
                );
            }
        }
        blocks::build(own, &pooled, timebases)
    }
}

/// One second's blocks, held by what they read.
struct HeldBlocks {
    digest: Digest,
    events: usize,
    pairs: Vec<(ClockPair, Arc<PairBlock>)>,
}

/// One area's held read.
#[derive(Default)]
pub(crate) struct Proto {
    gather: Gather,
    ready: bool,
    key: [u64; 2],
    sites: BTreeMap<PublicKey, SiteInfo>,
    clock_of: FxMap<ClockKey, u32>,
    clocks: Vec<ClockState>,
    seconds: BTreeMap<u64, SecondStore>,
    digest: BTreeMap<u64, Digest>,
    positions: FxMap<(u32, u64), u32>,
    nacp: FxMap<(u32, u64), Digest>,
    formed: BTreeMap<u64, (Digest, Arc<Formed>)>,
    blocks: BTreeMap<u64, HeldBlocks>,
    held: HeldRead,
    /// Each clock's place in key order, as last found (`places`).
    order: Vec<u32>,
    refits: u64,
}

fn mix(key: u64, words: &[u64]) -> u64 {
    let mut h = key ^ 0x9e37_79b9_7f4a_7c15;
    for word in words {
        h = (h ^ word).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        h ^= h >> 31;
    }
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 29)
}

/// Digests of consecutive seconds, combined in order (`BlockCache::update`'s).
fn combined(digest: &BTreeMap<u64, Digest>, from: u64, to: u64) -> Digest {
    let mut out: Digest = 0;
    for second in from..=to {
        out = out
            .wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b)
            .wrapping_add(digest.get(&second).copied().unwrap_or(0));
    }
    out
}

impl Proto {
    /// Bytes it holds, roughly as allocated.
    pub(crate) fn bytes(&self) -> usize {
        let seconds: usize = self
            .seconds
            .values()
            .map(|store| {
                48 + store.recs.capacity() * size_of::<(Id, Rec)>()
                    + store.index.capacity() * (size_of::<Id>() + 8)
            })
            .sum();
        let formed: usize = self
            .formed
            .values()
            .map(|(_, formed)| {
                64 + formed
                    .pairs
                    .values()
                    .map(|list| 48 + list.capacity() * size_of::<RawPoint>())
                    .sum::<usize>()
            })
            .sum();
        let blocks: usize = self
            .blocks
            .values()
            .map(|held| {
                64 + held
                    .pairs
                    .iter()
                    .map(|(_, block)| 32 + block.bytes())
                    .sum::<usize>()
            })
            .sum();
        self.gather.bytes()
            + self.held.bytes()
            + seconds
            + formed
            + blocks
            + self.digest.len() * 48
            + self.positions.capacity() * 24
            + self.nacp.capacity() * 40
            + self.clocks.capacity() * size_of::<ClockState>()
            + self.clock_of.capacity() * 48
    }

    fn reset(&mut self) {
        let gather = std::mem::take(&mut self.gather);
        *self = Self::default();
        self.gather = gather;
        use std::hash::{BuildHasher, Hasher};
        let state = std::collections::hash_map::RandomState::new();
        let draw = |salt: u64| {
            let mut hasher = state.build_hasher();
            hasher.write_u64(salt);
            hasher.finish()
        };
        self.key = [draw(1), draw(2)];
    }

    fn add_digest(&mut self, second: u64, part: Digest, sign: bool) {
        let entry = self.digest.entry(second).or_insert(0);
        *entry = if sign {
            entry.wrapping_add(part)
        } else {
            entry.wrapping_sub(part)
        };
    }

    /// Places or takes away `rec` at `second`, with its digest's parts.
    fn place(&mut self, second: u64, rec: &Rec, adding: bool) {
        let (back, after) = (sync::LOOK_BACK_S, sync::SPAN_AFTER_S);
        if rec.position {
            let window = self.clocks[rec.clock as usize].window;
            self.add_digest(second, rec.parts[usize::from(window)], adding);
            let count = self.positions.entry((rec.address, second)).or_insert(0);
            let flipped = if adding {
                *count += 1;
                *count == 1
            } else {
                *count -= 1;
                *count == 0
            };
            if *count == 0 {
                self.positions.remove(&(rec.address, second));
            }
            if flipped {
                let mut nacp: Digest = 0;
                for near in second.saturating_sub(back)..=second + after {
                    nacp = nacp
                        .wrapping_add(self.nacp.get(&(rec.address, near)).copied().unwrap_or(0));
                }
                self.add_digest(second, nacp, adding);
            }
        } else {
            let entry = self.nacp.entry((rec.address, second)).or_insert(0);
            *entry = if adding {
                entry.wrapping_add(rec.parts[0])
            } else {
                entry.wrapping_sub(rec.parts[0])
            };
            if *entry == 0 {
                self.nacp.remove(&(rec.address, second));
            }
            for event in second.saturating_sub(after)..=second + back {
                if self.positions.contains_key(&(rec.address, event)) {
                    self.add_digest(event, rec.parts[0], adding);
                }
            }
        }
    }

    /// The gather's changes placed: each kept reception linearized as `sync::linearize` does
    /// (none where its receiver has no usable site or its counter no linear count).
    fn apply(&mut self) {
        let changes = std::mem::take(&mut self.gather.changes);
        for change in &changes {
            match *change {
                Change::Removed(id, wall) => {
                    let second = wall / 1000;
                    let Some(rec) = self
                        .seconds
                        .get_mut(&second)
                        .and_then(|store| store.remove(&id))
                    else {
                        continue;
                    };
                    if self
                        .seconds
                        .get(&second)
                        .is_some_and(|store| store.recs.is_empty())
                    {
                        self.seconds.remove(&second);
                    }
                    self.held.remove(rec.slot);
                    self.place(second, &rec, false);
                }
                Change::Added(id, wall) => self.add_rec(id, wall),
            }
        }
        self.gather.changes = changes;
    }

    /// Places the kept reception `id` at `wall`, linearized as `sync::linearize` does (none where
    /// its receiver has no usable site or its counter no linear count).
    fn add_rec(&mut self, id: Id, wall: u64) {
        let receiver = self.gather.members[id.member as usize];
        let Some(site) = self.sites.get(&receiver).copied() else {
            return;
        };
        let Some(linear) = sync::linear_of(site.timebase, id.timestamp, wall) else {
            return;
        };
        let Some(message) = self.gather.messages.get(&id.message) else {
            return;
        };
        let key = ClockKey {
            receiver,
            epoch: id.epoch,
        };
        let clock = match self.clock_of.get(&key) {
            Some(clock) => *clock,
            None => {
                let at = self.clocks.len() as u32;
                self.clocks.push(ClockState {
                    key,
                    site,
                    window: false,
                });
                self.clock_of.insert(key, at);
                at
            }
        };
        let bytes = receiver.as_bytes();
        let word = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        let hashed =
            |at: usize| u64::from_le_bytes(message.hash[at..at + 8].try_into().unwrap_or([0; 8]));
        let part = |flag: u64| {
            let words = [
                word(0),
                word(8),
                word(16),
                word(24),
                u64::from(id.epoch),
                linear as u64,
                wall,
                hashed(0),
                hashed(8),
                hashed(16),
                flag,
            ];
            u128::from(mix(self.key[0], &words)) << 64 | u128::from(mix(self.key[1], &words))
        };
        let parts = [part(0), part(1)];
        let (address, position) = (message.address, message.sync);
        let slot = self.held.add(
            HeldRx {
                clock,
                linear,
                wall,
                message: id.message,
            },
            &message.data,
        );
        let rec = Rec {
            clock,
            linear,
            wall,
            address,
            position,
            slot,
            parts,
        };
        let second = wall / 1000;
        self.seconds.entry(second).or_default().insert(id, rec);
        self.place(second, &rec, true);
    }

    /// Every reception of the receivers `changed` (their site changed or went) taken away and
    /// placed again under their sites now.
    fn relinearize(&mut self, changed: &BTreeSet<PublicKey>) {
        if changed.is_empty() {
            return;
        }
        let mut again: Vec<(u64, Id)> = Vec::new();
        for store in self.seconds.values() {
            for (id, rec) in &store.recs {
                if changed.contains(&self.gather.members[id.member as usize]) {
                    again.push((rec.wall, *id));
                }
            }
        }
        for (wall, id) in &again {
            let second = wall / 1000;
            let Some(rec) = self
                .seconds
                .get_mut(&second)
                .and_then(|store| store.remove(id))
            else {
                continue;
            };
            self.held.remove(rec.slot);
            self.place(second, &rec, false);
        }
        for (wall, id) in again {
            self.add_rec(id, wall);
        }
    }

    /// The window's clocks (those with a reception in `[first, end)`), each with its number,
    /// lowest count and when it was heard, in key order; the window flags brought to them (a
    /// clock that joined or left the window has its positions' digest parts given again).
    fn window_clocks(&mut self, (first, end): (u64, u64)) -> Vec<(u32, Clock)> {
        let mut lowest: Vec<Option<i64>> = vec![None; self.clocks.len()];
        for (_, store) in self.seconds.range(first..end) {
            for (_, rec) in &store.recs {
                let held = &mut lowest[rec.clock as usize];
                *held = Some(held.map_or(rec.linear, |low| low.min(rec.linear)));
            }
        }
        let flipped: Vec<u32> = (0..self.clocks.len() as u32)
            .filter(|at| self.clocks[*at as usize].window != lowest[*at as usize].is_some())
            .collect();
        if !flipped.is_empty() {
            let mut moves: Vec<(u64, Digest, Digest)> = Vec::new();
            for (second, store) in &self.seconds {
                for (_, rec) in &store.recs {
                    if rec.position && flipped.binary_search(&rec.clock).is_ok() {
                        let was = usize::from(self.clocks[rec.clock as usize].window);
                        moves.push((*second, rec.parts[was], rec.parts[1 - was]));
                    }
                }
            }
            for (second, old, new) in moves {
                self.add_digest(second, old, false);
                self.add_digest(second, new, true);
            }
            for at in &flipped {
                let state = &mut self.clocks[*at as usize];
                state.window = !state.window;
            }
        }
        let mut heard: Vec<u64> = vec![u64::MAX; self.clocks.len()];
        for (_, store) in self.seconds.range(first..end) {
            for (_, rec) in &store.recs {
                let at = rec.clock as usize;
                let Some(low) = lowest[at] else {
                    continue;
                };
                let bound = heard_bound(
                    self.clocks[at].site.timebase,
                    low,
                    std::iter::once((rec.linear, rec.wall)),
                );
                heard[at] = heard[at].min(bound);
            }
        }
        let mut out: Vec<(u32, Clock)> = (0..self.clocks.len())
            .filter_map(|at| {
                let low = lowest[at]?;
                let state = &self.clocks[at];
                let sigma = state.site.sigma_mm as f64 / 1000.0;
                Some((
                    at as u32,
                    Clock {
                        key: state.key,
                        timebase: state.site.timebase,
                        site: state.site.ecef,
                        site_mm: state.site.mm,
                        site_m2: sigma * sigma,
                        lowest: low,
                        heard_ns: heard[at],
                    },
                ))
            })
            .collect();
        out.sort_unstable_by_key(|(_, clock)| clock.key);
        out
    }
}

/// The window's clocks as formation reads them, by the prototype's numbering: each one's place in
/// key order (`u32::MAX`: not in the window), and its network neighbours in the window.
struct WindowOf {
    rank: Vec<u32>,
    neighbours: Vec<Vec<u32>>,
}

impl Proto {
    /// Each clock's place in key order.
    fn places(&mut self) {
        if self.order.len() == self.clocks.len() {
            return;
        }
        let mut sorted: Vec<u32> = (0..self.clocks.len() as u32).collect();
        sorted.sort_unstable_by_key(|at| self.clocks[*at as usize].key);
        self.order = vec![0; self.clocks.len()];
        for (place, at) in sorted.iter().enumerate() {
            self.order[*at as usize] = place as u32;
        }
    }

    /// Forms the seconds `dirty` from the held read.
    fn form(&mut self, dirty: &[u64], window: &WindowOf) -> Vec<(u64, Formed)> {
        self.places();
        let started = Instant::now();
        let sites: Vec<SiteInfo> = self.clocks.iter().map(|state| state.site).collect();
        let mut out = Vec::new();
        let mut hears: Vec<(u32, u32, i64, f64)> = Vec::new();
        for second in dirty {
            let events = self.held.events(*second, &self.order, &sites);
            let mut formed = Formed {
                events: events.len(),
                pairs: FxMap::default(),
            };
            for event in &events {
                hears.clear();
                for (slot, range_m) in &event.hearers {
                    let Some(rx) = self.held.rx(*slot) else {
                        continue;
                    };
                    let rank = window
                        .rank
                        .get(rx.clock as usize)
                        .copied()
                        .unwrap_or(u32::MAX);
                    if rank != u32::MAX {
                        hears.push((rank, rx.clock, rx.linear, range_m / C * 1e9));
                    }
                }
                hears.sort_by_key(|(rank, _, _, _)| *rank);
                let hearers = event.hearers.len() as u32;
                for (i, (_, a, la, range_a)) in hears.iter().enumerate() {
                    let neighbours = &window.neighbours[*a as usize];
                    for (_, b, lb, range_b) in &hears[i + 1..] {
                        if neighbours.binary_search(b).is_err() {
                            continue;
                        }
                        formed.pairs.entry((*a, *b)).or_default().push(RawPoint {
                            la: *la,
                            lb: *lb,
                            range_a: *range_a,
                            range_b: *range_b,
                            hearers,
                            address: event.address,
                        });
                    }
                }
            }
            out.push((*second, formed));
        }
        probe_counters::since(P::proto_formation_ns, started);
        out
    }
}

/// The probe's sample of `cache`'s held read's bytes (`Proto::bytes`), one refit of an area in 16,
/// outside any refit's time.
pub fn sample_proto_bytes(cache: &mut PairCache) {
    if let Some(proto) = cache.proto.as_mut() {
        proto.refits += 1;
        if proto.refits.is_multiple_of(16) {
            probe_counters::add(P::proto_bytes, proto.bytes() as u64);
            probe_counters::add(P::proto_bytes_samples, 1);
        }
    }
}

/// The probe's held-read refit of `area` at `edge_ms` (module docs): `None` with fewer than two
/// members, as `Arrived::area_inputs`.
pub fn fit_proto(
    arrived: &Arrived,
    sites: &Sites,
    area: Region,
    edge_ms: u64,
    warm: Option<&PairModel>,
    cache: &mut PairCache,
    reads: &Reads,
) -> Option<Result<Fitted, PairError>> {
    let started = std::time::Instant::now();
    // The held read keeps its own parse of each message, so the shared memos are not read.
    let _ = reads;
    let trailing = Trailing::at(edge_ms);
    let proto = cache.proto.get_or_insert_with(|| {
        let mut proto = Box::<Proto>::default();
        proto.reset();
        proto
    });
    let gathering = Instant::now();
    let (scope, frontier, citation, changed_scope) =
        proto.gather.update(arrived, area, sites, trailing)?;
    probe_counters::since(P::proto_gather_ns, gathering);
    let storing = Instant::now();
    if !proto.ready {
        proto.ready = true;
    }
    if changed_scope {
        // A new scope: its sites (a member's clock and place), and with them its network, so
        // every formed second and block is let go (as `BlockCache` is); the read is kept.
        probe_counters::add(P::proto_resets, 1);
        let sites_now = sync::sites_of(&scope);
        let changed: BTreeSet<PublicKey> = proto
            .gather
            .members
            .iter()
            .filter(|key| {
                let (was, now) = (proto.sites.get(key), sites_now.get(key));
                was.map(|site| (site.timebase, site.mm, site.sigma_mm))
                    != now.map(|site| (site.timebase, site.mm, site.sigma_mm))
            })
            .copied()
            .collect();
        proto.sites = sites_now;
        for state in &mut proto.clocks {
            if let Some(site) = proto.sites.get(&state.key.receiver) {
                state.site = *site;
            }
        }
        proto.relinearize(&changed);
        proto.formed.clear();
        proto.blocks.clear();
    }
    proto.apply();
    let first_ms = trailing.first_ms();
    let (first, end) = (first_ms / 1000, edge_ms / 1000);
    let read_from = trailing.read_from_ms() / 1000;
    let clocks = proto.window_clocks((first, end));
    probe_counters::since(P::proto_store_ns, storing);
    let network = PairCache::network_of(&mut cache.network, &mut cache.blocks, area, &scope);
    let proto = cache.proto.as_mut()?;
    // The window's clocks by number: their place, and their neighbours in the window.
    let digesting = Instant::now();
    let mut rank = vec![u32::MAX; proto.clocks.len()];
    let mut by_receiver: BTreeMap<PublicKey, Vec<u32>> = BTreeMap::new();
    for (at, (number, clock)) in clocks.iter().enumerate() {
        rank[*number as usize] = at as u32;
        by_receiver
            .entry(clock.key.receiver)
            .or_default()
            .push(*number);
    }
    let mut neighbours: Vec<Vec<u32>> = vec![Vec::new(); proto.clocks.len()];
    for (number, clock) in &clocks {
        let mut list: Vec<u32> = network
            .neighbours(&clock.key.receiver)
            .iter()
            .flat_map(|other| by_receiver.get(other).map_or(&[][..], Vec::as_slice))
            .copied()
            .collect();
        list.sort_unstable();
        neighbours[*number as usize] = list;
    }
    let window_of = WindowOf { rank, neighbours };
    // The formed seconds the window's blocks pool, and the blocks, each held by what it reads.
    let pooled_from = first.saturating_sub(blocks::LINE_BLOCKS - 1);
    let (back, after) = (sync::LOOK_BACK_S, sync::SPAN_AFTER_S);
    let formed_digest: BTreeMap<u64, Digest> = (pooled_from..end)
        .map(|second| {
            (
                second,
                combined(&proto.digest, second.saturating_sub(back), second + after),
            )
        })
        .collect();
    let block_digest: BTreeMap<u64, Digest> = (first..end)
        .map(|second| {
            (
                second,
                combined(
                    &proto.digest,
                    second.saturating_sub(blocks::READ_BACK_MS / 1000),
                    second + after,
                ),
            )
        })
        .collect();
    proto
        .formed
        .retain(|second, _| (pooled_from..end).contains(second));
    proto
        .blocks
        .retain(|second, _| (first..end).contains(second));
    proto.seconds.retain(|second, _| *second >= read_from);
    proto.digest.retain(|second, _| *second >= read_from);
    let rebuilt: Vec<u64> = (first..end)
        .filter(|second| {
            proto
                .blocks
                .get(second)
                .is_none_or(|held| held.digest != block_digest[second])
        })
        .collect();
    let mut dirty: Vec<u64> = rebuilt
        .iter()
        .flat_map(|second| {
            second
                .saturating_sub(blocks::LINE_BLOCKS - 1)
                .max(pooled_from)..=*second
        })
        .filter(|second| {
            proto
                .formed
                .get(second)
                .is_none_or(|(digest, _)| *digest != formed_digest[second])
        })
        .collect();
    dirty.sort_unstable();
    dirty.dedup();
    probe_counters::since(P::proto_digest_ns, digesting);
    probe_counters::add(P::proto_formed, dirty.len() as u64);
    probe_counters::add(
        P::proto_formed_held,
        (end - pooled_from).saturating_sub(dirty.len() as u64),
    );
    let formed = proto.form(&dirty, &window_of);
    for (second, formed) in formed {
        proto
            .formed
            .insert(second, (formed_digest[&second], Arc::new(formed)));
    }
    // The blocks built again, from the held formed seconds.
    let building = Instant::now();
    let mut pooled: Vec<(u64, RawPoint)> = Vec::new();
    for second in &rebuilt {
        let mut pairs = Vec::new();
        let Some((_, own)) = proto.formed.get(second) else {
            proto.blocks.insert(
                *second,
                HeldBlocks {
                    digest: block_digest[second],
                    events: 0,
                    pairs,
                },
            );
            continue;
        };
        let own = Arc::clone(own);
        let line: Vec<(u64, Arc<Formed>)> = (second.saturating_sub(blocks::LINE_BLOCKS - 1)
            ..=*second)
            .filter_map(|at| {
                proto
                    .formed
                    .get(&at)
                    .map(|(_, formed)| (at, Arc::clone(formed)))
            })
            .collect();
        for key in own.pairs.keys() {
            pooled.clear();
            for (at, formed) in &line {
                if let Some(list) = formed.pairs.get(key) {
                    pooled.extend(list.iter().map(|p| (*at, *p)));
                }
            }
            let timebases = (
                proto.clocks[key.0 as usize].site.timebase,
                proto.clocks[key.1 as usize].site.timebase,
            );
            if let Some(block) = blocks::build(*second, &pooled, timebases) {
                pairs.push((*key, Arc::new(block)));
            }
        }
        proto.blocks.insert(
            *second,
            HeldBlocks {
                digest: block_digest[second],
                events: own.events,
                pairs,
            },
        );
    }
    probe_counters::since(P::proto_build_ns, building);
    probe_counters::add(P::proto_blocks_built, rebuilt.len() as u64);
    probe_counters::add(
        P::proto_blocks_held,
        (end - first).saturating_sub(rebuilt.len() as u64),
    );
    // The window, as `Window::read` makes it from its held blocks.
    let assembling = Instant::now();
    let mut events = 0;
    let mut found: FoundBlocks = BTreeMap::new();
    for second in first..end {
        let Some(held) = proto.blocks.get(&second) else {
            continue;
        };
        events += held.events;
        for ((ka, kb), block) in &held.pairs {
            let (a, b) = (window_of.rank[*ka as usize], window_of.rank[*kb as usize]);
            if a != u32::MAX && b != u32::MAX {
                found
                    .entry((a, b))
                    .or_default()
                    .push((second, Arc::clone(block)));
            }
        }
    }
    found.retain(|_, list| {
        list.iter()
            .map(|(_, block)| block.points as usize)
            .sum::<usize>()
            >= sync::SPAN_RECEPTIONS_LEAST
    });
    let mut keys = Vec::with_capacity(found.len());
    let mut blocks_of = Vec::with_capacity(found.len());
    let mut slots = HashMap::with_capacity(found.len());
    let mut of_clock: Vec<Vec<u32>> = vec![Vec::new(); clocks.len()];
    for (at, (key, list)) in found.into_iter().enumerate() {
        slots.insert(key, at as u32);
        of_clock[key.0 as usize].push(at as u32);
        of_clock[key.1 as usize].push(at as u32);
        keys.push(key);
        blocks_of.push(list);
    }
    let pool = Pool {
        clocks: clocks.iter().map(|(number, _)| *number).collect(),
        formed: proto
            .formed
            .iter()
            .map(|(second, (_, formed))| (*second, Arc::clone(formed)))
            .collect(),
    };
    let built = rebuilt.len();
    let window = Window {
        clocks: clocks.into_iter().map(|(_, clock)| clock).collect(),
        seconds: (first, end),
        events,
        keys,
        blocks: blocks_of,
        slots,
        of_clock,
        built,
        reused: (end - first) as usize - built,
    };
    probe_counters::add(P::proto_refits, 1);
    let inputs = Inputs {
        area,
        trailing,
        scope,
        frontier,
        sync: Vec::new(),
        messages: Vec::new(),
        citation,
    };
    let mut none = ReadCache::default();
    let mut raw = Raw::new(
        sync::Reader::new(&inputs, &mut none, None),
        Vec::new(),
        Vec::new(),
    );
    raw.proto = Some(pool);
    probe_counters::since(P::proto_window_ns, assembling);
    let read_ns = started.elapsed().as_nanos() as u64;
    Some(fit_window(&inputs, window, raw, warm, started, read_ns))
}

/// `fit_reading` from its window on: the noise and rates at the fixed point, and the model.
fn fit_window(
    inputs: &Inputs,
    window: Window,
    mut raw: Raw<'_>,
    warm: Option<&PairModel>,
    started: std::time::Instant,
    read_ns: u64,
) -> Result<Fitted, PairError> {
    let n = window.clocks.len();
    let index = window.index();
    let mut conditions = Conditions {
        noise_ns: window
            .clocks
            .iter()
            .map(|clock| default_noise_ns(clock.timebase))
            .collect(),
        rates: vec![0.0; n],
    };
    let mut white_ns: Vec<f64> = conditions.noise_ns.clone();
    if let Some(warm) = warm {
        for clock in &warm.clocks {
            if let Some(at) = index.get(&clock.key) {
                conditions.noise_ns[*at as usize] = clock.noise_ns;
                conditions.rates[*at as usize] = clock.rate;
                white_ns[*at as usize] = clock.white_ns;
            }
        }
    }
    let all: Vec<u32> = (0..window.keys.len() as u32).collect();
    #[cfg(tally_refit_probe)]
    let (settling, nested) = (std::time::Instant::now(), crate::probe::nested());
    let (outcomes, from) = settle(&window, &mut raw, &all);
    drop(raw);
    // Settling less the cut blocks it rebuilt, which their phases count; those builds, apart, are
    // what the per-pair oracle still pays.
    #[cfg(tally_refit_probe)]
    crate::probe::add(
        crate::probe::P::cut_build_ns,
        crate::probe::nested() - nested,
    );
    #[cfg(tally_refit_probe)]
    crate::probe::add(
        crate::probe::P::settle_ns,
        u64::try_from(settling.elapsed().as_nanos())
            .unwrap_or(u64::MAX)
            .saturating_sub(crate::probe::nested() - nested),
    );
    #[cfg(tally_refit_probe)]
    let passes_started = std::time::Instant::now();
    let valid: Vec<(u32, &PairSums)> = outcomes
        .iter()
        .filter_map(|(at, outcome)| match outcome {
            Outcome::Fit(sums) => Some((*at, sums.as_ref())),
            _ => None,
        })
        .collect();
    if valid.is_empty() {
        return Err(PairError::Empty);
    }
    let var_of = |noise: &[f64], (a, b): (u32, u32)| {
        let (sa, sb) = (noise[a as usize], noise[b as usize]);
        sa * sa + sb * sb
    };
    let rates_of = |rates: &[f64], (a, b): (u32, u32)| (rates[a as usize], rates[b as usize]);
    // How far rates `to` move a pair fitted at rates `from` from its optimum: `Δᵀ (dᵀWd - S) Δ`.
    let drift = |fit: &PairFit, from: (f64, f64), to: (f64, f64)| {
        let (da, db) = (to.0 - from.0, to.1 - from.1);
        let e = fit.explained;
        da * da * e[0] + 2.0 * da * db * e[1] + db * db * e[2]
    };
    let mut again = [0usize; 2];
    let mut refitted = 0usize;
    for pass in 0..PASSES_MOST {
        let mut fits: Vec<((u32, u32), PairFit)> = Vec::with_capacity(valid.len());
        for (at, sums) in &valid {
            let key = window.keys[*at as usize];
            let fit = sums
                .solve(
                    var_of(&conditions.noise_ns, key),
                    rates_of(&conditions.rates, key),
                )
                .ok_or(PairError::NotConverged)?;
            fits.push((key, fit));
        }
        if pass > 0 {
            refitted += fits.len();
        }
        let kappa = pooled(fits.iter().map(|(_, fit)| fit));
        for (_, fit) in &mut fits {
            fit.kappa = kappa_of(fit, kappa);
        }
        let whole = noise_estimate(&window.clocks, fits.iter().map(|(key, fit)| (*key, fit)), 0);
        let within = white_estimate(&window.clocks, fits.iter().map(|(key, fit)| (*key, fit)));
        let (system, gradient) = rate_system(
            &window.clocks,
            &conditions.rates,
            fits.iter().map(|(key, fit)| (*key, fit)),
        );
        let step = system.solve(&gradient);
        let rates: Vec<f64> = conditions
            .rates
            .iter()
            .zip(&step)
            .map(|(rate, step)| rate - step)
            .collect();
        // Held within half the verifier's band of its estimate either way, else the estimate.
        let hold = |held: f64, estimate: f64| {
            if held >= (1.0 - NOISE_HOLD) * estimate && held <= (1.0 + NOISE_HOLD) * estimate {
                held
            } else {
                estimate
            }
        };
        let noise_ns: Vec<f64> = conditions
            .noise_ns
            .iter()
            .zip(&whole)
            .map(|(held, estimate)| hold(*held, *estimate))
            .collect();
        white_ns = white_ns
            .iter()
            .zip(&within)
            .map(|(held, estimate)| hold(*held, *estimate))
            .collect();
        let moved = fits
            .iter()
            .map(|(key, fit)| {
                drift(
                    fit,
                    rates_of(&conditions.rates, *key),
                    rates_of(&rates, *key),
                )
            })
            .fold(0.0, f64::max);
        let noise_held = noise_ns == conditions.noise_ns;
        let rates_held = moved <= PAIR_OPTIMALITY_TOLERANCE / 10.0;
        again[0] += usize::from(!noise_held);
        again[1] += usize::from(!rates_held);
        if noise_held && rates_held {
            // What is published of each pair is its assessment at the published noise and rates,
            // at its own knots: the verifier's computation, so its inflation, covariance and slope
            // are the verifier's to the bit.
            let mut replayed: Vec<((u32, u32), PairFit)> = Vec::with_capacity(fits.len());
            for ((_, sums), (key, fit)) in valid.iter().zip(&fits) {
                match sums.assess(
                    var_of(&noise_ns, *key),
                    rates_of(&rates, *key),
                    fit.knots.clone(),
                ) {
                    Some(again) if again.distance <= PAIR_OPTIMALITY_TOLERANCE => {
                        replayed.push((*key, again));
                    }
                    _ => break,
                }
            }
            if replayed.len() == fits.len() {
                // At the precision they are published at (`ClockPair::cov`), so the rates'
                // variances are made of what the verifier reads, as its are.
                let kappa = single(pooled(replayed.iter().map(|(_, fit)| fit)));
                for (_, fit) in &mut replayed {
                    fit.kappa = single(kappa_of(fit, kappa));
                    fit.slope_var = single(fit.slope_var);
                }
                let (system, _) = rate_system(
                    &window.clocks,
                    &rates,
                    replayed.iter().map(|(key, fit)| (*key, fit)),
                );
                let (rate_var, common_var) = rate_variances(&system);
                let stats = Stats {
                    clocks: n,
                    events: window.events,
                    candidates: window.keys.len(),
                    valid: replayed.len(),
                    points: replayed.iter().map(|(_, fit)| fit.points).sum(),
                    inliers: replayed.iter().map(|(_, fit)| fit.inliers).sum(),
                    jumped: from.iter().flatten().count(),
                    unattributed: outcomes
                        .values()
                        .filter(|outcome| {
                            matches!(outcome, Outcome::Invalid(Invalid::Unattributed))
                        })
                        .count(),
                    inflated: replayed.iter().filter(|(_, fit)| fit.kappa > 1.0).count(),
                    passes: pass + 1,
                    again_noise: again[0],
                    again_rates: again[1],
                    refitted,
                    blocks_built: window.built,
                    blocks_reused: window.reused,
                    read_ns,
                    fit_ns: started.elapsed().as_nanos() as u64 - read_ns,
                };
                let model = assemble(
                    inputs,
                    &window,
                    &replayed,
                    &Conditions {
                        noise_ns: conditions.noise_ns.clone(),
                        rates,
                    },
                    &from,
                    &white_ns,
                    (&rate_var, &common_var),
                    kappa,
                );
                #[cfg(tally_refit_probe)]
                {
                    crate::probe::since(crate::probe::P::passes_ns, passes_started);
                    crate::probe::add(crate::probe::P::refits, 1);
                    crate::probe::dump_if_due();
                }
                return Ok(Fitted { model, stats });
            }
            again[1] += 1;
        }
        conditions.noise_ns = noise_ns;
        conditions.rates = rates;
    }
    Err(PairError::NotConverged)
}
