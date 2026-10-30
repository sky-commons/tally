//! Reading an area's inputs as the pairwise blocks read them (crate docs, § Sync events, § The
//! pairwise path, blocks): each receiver's linear counts, and each block's sync events, each a
//! message with its prior and its receptions by the members within range, read by its aircraft's
//! CPR reference and NACp in the block's own read span; and the constants the pairs' robust
//! fit, jumps and noise share (crate docs, § The pairwise path). Every loop runs in a canonical
//! order (`BTreeMap`, sorted vectors), so what is read does not depend on the order of the input.

use std::collections::BTreeMap;

use tally_wire::PublicKey;

use crate::clock::{ClockKey, DAY_NS, Timebase};
use crate::geo::{self, Geodetic};
use crate::linalg::{self, Vec3};
use crate::modes;
use crate::obs::Site;
use crate::scope::{Inputs, SyncMessage, SyncReception};

/// The most a clock's noise may be estimated at, seconds: ten times the worst common class
/// (`Timebase::default_noise_s`), every clock's ceiling (`Timebase::noise_ceiling_s`), and the top
/// of the range a pair model's noise split is held to (crate docs, § The pairwise path, noise). A
/// declared GNSS clock is the feeder's word: one whose counter is noise (milliseconds) is held to
/// this, and its points beyond it carry no weight in any pair.
pub const GAUGE_NOISE_MOST_S: f64 = 5e-6;

/// A point of a pair further than this many of its block's robust scales from its block's robust
/// line is an outlier (crate docs, § The pairwise path, blocks).
pub const SYNC_CUTOFF: f64 = 10.0;
/// A pair's jump score's threshold (crate docs, § The pairwise path, jumps).
pub const JUMP_THRESHOLD: f64 = 8.0;
/// Points on each side of a pair's jump its score compares, at most.
pub const JUMP_SIDE: usize = 5;
/// Points a pair needs to be fitted at all: fewer, and it is no valid pair (crate docs, § The
/// pairwise path, a pair's fit).
pub const SPAN_RECEPTIONS_LEAST: usize = 20;
/// The weakest horizontal prior a sync aircraft's position bias may have, metres (one standard
/// deviation).
pub const MAX_PRIOR_SIGMA_M: f64 = 100.0;
/// The floor on a sync aircraft's horizontal bias prior, metres.
pub const MIN_PRIOR_SIGMA_M: f64 = 5.0;
/// The floor on a receiver's estimated timing noise, seconds.
pub const MIN_NOISE_S: f64 = 10e-9;
/// The farthest a receiver may be from a position it is said to have heard, metres.
pub const MAX_RANGE_M: f64 = 600_000.0;
/// The farthest a locally decoded position may lie from its aircraft's reference, metres.
pub const MAX_LOCAL_DECODE_M: f64 = 100_000.0;
/// The standard deviation of R95 for a circular normal, the divisor from a 95% radius.
const R95: f64 = 2.448;

#[derive(Clone, Copy)]
pub(crate) struct SiteInfo {
    pub(crate) timebase: Timebase,
    pub(crate) mm: [i64; 3],
    pub(crate) ecef: Vec3,
    pub(crate) sigma_mm: i64,
}

pub(crate) struct Rx {
    pub(crate) receiver: PublicKey,
    pub(crate) epoch: u32,
    /// Which (receiver, epoch) of the read it is: they run in key order.
    pub(crate) clock: usize,
    /// Its message, by its place in `Inputs::messages`: distinct bytes, distinct places.
    pub(crate) message: u32,
    pub(crate) linear: i64,
    /// The wall clock of the batch that carried it (of copies, the earliest).
    pub(crate) wall_ms: u64,
}

impl Rx {
    pub(crate) fn key(&self) -> ClockKey {
        ClockKey {
            receiver: self.receiver,
            epoch: self.epoch,
        }
    }
}

fn site_table(sites: &[Site]) -> BTreeMap<PublicKey, SiteInfo> {
    sites
        .iter()
        .filter(|site| site.usable())
        .filter_map(|site| {
            let timebase = Timebase::of(site.clock)?;
            let mm = site.mm();
            Some((
                site.receiver,
                SiteInfo {
                    timebase,
                    mm,
                    ecef: geo::from_mm(mm),
                    sigma_mm: site.sigma_mm(),
                },
            ))
        })
        .collect()
}

/// Each distinct message as read, by its hash, kept while some reads carry it: one not used by a
/// read is let go once the unused outnumber the used (`finish`).
#[derive(Default)]
pub(crate) struct ReadCache {
    /// The read the entries were last used by.
    generation: u64,
    /// Each message's place in `parsed`, by its hash (`obs::ByDigest`: what the table grows to,
    /// its deleted slots taken in turn, is the same on every run, so what an area's memos hold,
    /// `mlat_host::AREA_CACHE_BYTES_PER_RECEIVER`, is measured, not drawn).
    index: std::collections::HashMap<[u8; 32], u32, crate::obs::ByDigest>,
    parsed: Vec<Parsed>,
    /// Entries the read under way used.
    used: usize,
}

/// One message's bytes as the fit reads them.
struct Parsed {
    seen: u64,
    address: Option<u32>,
    nacp: Option<u8>,
    /// Its airborne position, when it is a sync message (a DF17/18 position with a type code).
    position: Option<modes::AirbornePosition>,
    /// Its local decode against `reference`: the reference, whether it lands within
    /// `MAX_LOCAL_DECODE_M` of it, and its prior's ECEF.
    decoded: Option<Decoded>,
}

#[derive(Clone, Copy)]
struct Decoded {
    reference: modes::LatLon,
    near: bool,
    prior: Vec3,
}

impl Parsed {
    fn of(data: &[u8], seen: u64) -> Self {
        Self {
            seen,
            address: modes::address(data),
            nacp: modes::nacp(data),
            position: modes::type_code(data).and_then(|_| modes::airborne_position(data)),
            decoded: None,
        }
    }

    /// Its decode against `reference` (crate docs, § Sync events, 4): memoized by reference.
    fn decode(&mut self, reference: modes::LatLon) -> Option<Decoded> {
        let position = self.position?;
        let altitude = position.altitude?;
        if let Some(held) = self.decoded.filter(|held| held.reference == reference) {
            return Some(held);
        }
        let decoded = modes::cpr_local(
            (position.lat_cpr, position.lon_cpr),
            position.odd,
            reference,
        );
        let at = |lat_deg: f64, lon_deg: f64| {
            geo::to_ecef(Geodetic {
                lat_deg,
                lon_deg,
                height_m: 0.0,
            })
        };
        let near = linalg::norm(linalg::sub(
            at(decoded.lat_deg, decoded.lon_deg),
            at(reference.lat_deg, reference.lon_deg),
        )) <= MAX_LOCAL_DECODE_M;
        let held = Decoded {
            reference,
            near,
            prior: geo::to_ecef(Geodetic {
                lat_deg: decoded.lat_deg,
                lon_deg: decoded.lon_deg,
                height_m: altitude.metres(),
            }),
        };
        self.decoded = Some(held);
        Some(held)
    }
}

impl ReadCache {
    /// Bytes it holds, as allocated: each message's hash and place, and what was read of it.
    pub(crate) fn bytes(&self) -> usize {
        self.index.capacity() * (size_of::<[u8; 32]>() + size_of::<u32>() + 8)
            + self.parsed.capacity() * size_of::<Parsed>()
    }

    /// Starts a read: entries not used by it may be let go at its end (`finish`).
    fn begin(&mut self) {
        self.generation += 1;
        self.used = 0;
    }

    /// The place of `message`'s entry, read now if it has none.
    fn slot(&mut self, message: &SyncMessage) -> u32 {
        let generation = self.generation;
        let next = u32::try_from(self.parsed.len()).unwrap_or(u32::MAX);
        let at = *self.index.entry(message.hash).or_insert(next);
        if at == next {
            self.parsed.push(Parsed::of(&message.data, generation));
            self.used += 1;
        } else if let Some(parsed) = self.parsed.get_mut(at as usize)
            && parsed.seen != generation
        {
            parsed.seen = generation;
            self.used += 1;
        }
        at
    }

    /// Ends a read: once the entries it did not use outnumber those it did, they are let go.
    fn finish(&mut self) {
        if self.parsed.len() <= 2 * self.used {
            return;
        }
        let generation = self.generation;
        let mut renumbered = vec![u32::MAX; self.parsed.len()];
        let mut kept = 0u32;
        for (at, parsed) in self.parsed.iter().enumerate() {
            if parsed.seen == generation {
                renumbered[at] = kept;
                kept += 1;
            }
        }
        self.parsed.retain(|parsed| parsed.seen == generation);
        self.index.retain(|_, at| {
            *at = renumbered[*at as usize];
            *at != u32::MAX
        });
    }
}

/// The messages of one read (`Inputs::messages`), each resolved to its cache entry once.
struct Messages<'r> {
    cache: &'r mut ReadCache,
    of: &'r [SyncMessage],
    slots: Vec<u32>,
}

impl<'r> Messages<'r> {
    fn new(cache: &'r mut ReadCache, of: &'r [SyncMessage]) -> Self {
        Self {
            cache,
            of,
            slots: vec![u32::MAX; of.len()],
        }
    }

    fn data(&self, message: u32) -> &'r [u8] {
        &self.of[message as usize].data
    }

    fn hash(&self, message: u32) -> [u8; 32] {
        self.of[message as usize].hash
    }

    fn parsed(&mut self, message: u32) -> &mut Parsed {
        let slot = &mut self.slots[message as usize];
        if *slot == u32::MAX {
            *slot = self.cache.slot(&self.of[message as usize]);
        }
        &mut self.cache.parsed[*slot as usize]
    }
}

/// Deduplicates by identity, drops receptions of unusable receivers, and linearizes counters: a
/// GPS time of day is moved to the UTC day its reception's wall clock is in (the one that puts it
/// within half a day of the wall clock, `origin_unix_ns`), so a GNSS-disciplined clock's linear
/// count is Unix nanoseconds, the same in every read whatever else the window holds; a 12 MHz count
/// is taken as it is.
fn linearize(sites: &BTreeMap<PublicKey, SiteInfo>, inputs: &Inputs) -> (Vec<Rx>, Vec<SiteInfo>) {
    let hash = |reception: &SyncReception| &inputs.messages[reception.message as usize].hash;
    // Within one receiver, identity order and of copies the earliest wall clock first; the same
    // identity, the message compared only when the counter is.
    let within = |a: &SyncReception, b: &SyncReception| {
        (a.epoch, a.timestamp)
            .cmp(&(b.epoch, b.timestamp))
            .then_with(|| hash(a).cmp(hash(b)))
            .then(a.wall_ms.cmp(&b.wall_ms))
    };
    let same = |a: &SyncReception, b: &SyncReception| {
        a.epoch == b.epoch && a.timestamp == b.timestamp && hash(a) == hash(b)
    };
    // Inputs come in identity order (`Inputs::sync`): receiver runs ascending, each sorted, which
    // is checked run by run (the receiver compared whole only where it changes), not sorted.
    let mut runs: Vec<&[SyncReception]> = inputs
        .sync
        .chunk_by(|a, b| a.receiver == b.receiver)
        .collect();
    let ordered = runs
        .windows(2)
        .all(|pair| pair[0][0].receiver < pair[1][0].receiver)
        && runs.iter().all(|run| {
            run.windows(2)
                .all(|pair| within(&pair[0], &pair[1]).is_le())
        });
    let sorted: Vec<SyncReception>;
    if !ordered {
        sorted = {
            let mut sorted = inputs.sync.clone();
            sorted.sort_by(|a, b| a.receiver.cmp(&b.receiver).then(within(a, b)));
            sorted
        };
        runs = sorted.chunk_by(|a, b| a.receiver == b.receiver).collect();
    }
    let mut out: Vec<Rx> = Vec::with_capacity(inputs.sync.len());
    let mut clocks: Vec<SiteInfo> = Vec::new();
    let mut clock = 0;
    for run in runs {
        let receiver = run[0].receiver;
        let Some(site) = sites.get(&receiver) else {
            continue;
        };
        for epoch_run in run.chunk_by(|a, b| a.epoch == b.epoch) {
            let epoch = epoch_run[0].epoch;
            clocks.push(*site);
            // Unique by identity, of copies the earliest wall clock (the first of its run).
            for (at, reception) in epoch_run.iter().enumerate() {
                if at > 0 && same(&epoch_run[at - 1], reception) {
                    continue;
                }
                let Some(value) = site.timebase.linear(reception.timestamp) else {
                    continue;
                };
                let linear = match site.timebase {
                    Timebase::Mhz12 => value,
                    Timebase::GpsNanos => {
                        let wall_ns = i128::from(reception.wall_ms) * 1_000_000;
                        let day = i128::from(DAY_NS);
                        let start = (wall_ns - i128::from(value) + day / 2).div_euclid(day) * day;
                        let Ok(linear) = i64::try_from(start + i128::from(value)) else {
                            continue;
                        };
                        linear
                    }
                };
                out.push(Rx {
                    receiver,
                    epoch,
                    clock,
                    message: reception.message,
                    linear,
                    wall_ms: reception.wall_ms,
                });
            }
            clock += 1;
        }
    }
    (out, clocks)
}

/// One reception of a position message, as the CPR reference reads it: (its clock, linear count,
/// message, odd).
type Heard = (usize, i64, u32, bool);

/// The CPR reference of one address (crate docs, § Sync events, 3): of the pairs of an even and an
/// odd position message one clock heard within its pair window (`heard`, sorted by clock and
/// count), as `(even, odd, odd is later)`, the first in that order that decodes globally, ordered
/// by the messages' bytes (`rank`: each message's place in byte order). Each even's pairs are
/// gathered in byte order of the evens, and the first even with a pair that decodes ends it: no
/// pair of a later even comes first.
fn cpr_reference(
    heard: &[Heard],
    windows: &[i64],
    rank: &[u32],
    messages: &mut Messages<'_>,
) -> Option<(modes::LatLon, u32, u32, bool)> {
    let mut evens: Vec<u32> = heard
        .iter()
        .filter(|(_, _, _, odd)| !odd)
        .map(|(_, _, message, _)| *message)
        .collect();
    evens.sort_unstable_by_key(|message| rank[*message as usize]);
    evens.dedup();
    let mut candidates: Vec<(u32, bool)> = Vec::new();
    for even in evens {
        candidates.clear();
        for (at, (clock, time, message, odd)) in heard.iter().enumerate() {
            if *odd || *message != even {
                continue;
            }
            let window = windows[*clock];
            // This clock's run of `heard`, and within it the odds within the window either side.
            let low = heard[..at].partition_point(|(c, t, _, _)| *c < *clock || *t < time - window);
            for (_, odd_time, odd_message, is_odd) in heard[low..]
                .iter()
                .take_while(|(c, t, _, _)| *c == *clock && *t <= time + window)
            {
                if *is_odd {
                    candidates.push((*odd_message, odd_time > time));
                }
            }
        }
        candidates
            .sort_unstable_by_key(|(message, odd_latest)| (rank[*message as usize], *odd_latest));
        candidates.dedup();
        let Some(even_position) = messages.parsed(even).position else {
            continue;
        };
        for (odd, odd_latest) in &candidates {
            let Some(odd_position) = messages.parsed(*odd).position else {
                continue;
            };
            if let Some(position) = modes::cpr_global(
                (even_position.lat_cpr, even_position.lon_cpr),
                (odd_position.lat_cpr, odd_position.lon_cpr),
                *odd_latest,
            ) {
                return Some((position, even, *odd, *odd_latest));
            }
        }
    }
    None
}

/// Seconds of wall clock before a block's own second its events read (crate docs, § The pairwise
/// path, blocks): a message heard in them is not new in the block, and its aircraft's CPR
/// reference and NACp are read over them too.
pub const LOOK_BACK_S: u64 = 2;
/// Seconds of wall clock after a block's own second an event of it gathers its receptions over:
/// `tally_wire::budget::MLAT_BATCHING`, how far apart in wall clock an honest transmission's
/// receptions are batched.
pub const SPAN_AFTER_S: u64 = 2;

const _: () = assert!(
    SPAN_AFTER_S * 1000
        == tally_wire::budget::MLAT_BATCHING
            .span::<tally_wire::clocks::Judged>()
            .ms()
);

/// A sync event of one block (crate docs, § The pairwise path, blocks): one position message of a
/// reference aircraft, new in the block's second, and its receptions within range of its prior
/// by clocks that heard it once (each its place in `Reader::rxs` and its range, metres).
pub(crate) struct Event {
    pub(crate) address: u32,
    pub(crate) hearers: Vec<(u32, f64)>,
}

/// One reception of a position message as a block reads it: its clock, linear count, message,
/// whether it is odd, and its wall clock.
type Position = (usize, i64, u32, bool, u64);

/// A NACp reception: its clock, linear count, value and wall clock.
type Nacp = (usize, i64, u8, u64);

/// The inputs as the pairwise blocks read them: each reception linearized once, and each message,
/// second and address indexed, so a block reads only the seconds it is a function of.
pub(crate) struct Reader<'r> {
    /// Each clock's site, by `Rx::clock`: (receiver, epoch) in key order.
    pub(crate) clocks: Vec<SiteInfo>,
    pub(crate) rxs: Vec<Rx>,
    messages: Messages<'r>,
    /// Each message's place in byte order.
    rank: Vec<u32>,
    /// Each clock's CPR pair window, linear counts.
    windows: Vec<i64>,
    /// Each message's receptions, `(wall clock, place in rxs)` sorted, at
    /// `by_message[starts[m]..starts[m + 1]]`.
    starts: Vec<usize>,
    by_message: Vec<(u64, u32)>,
    /// Each wall-clock second's messages (distinct, in byte order).
    by_second: BTreeMap<u64, Vec<u32>>,
    /// Each address's position receptions, sorted by clock, count, rank and odd.
    positions: BTreeMap<u32, Vec<Position>>,
    /// Each address's NACp receptions, sorted by clock, count and value.
    nacp: BTreeMap<u32, Vec<Nacp>>,
    /// Each (address, second)'s CPR reference, once found.
    references: BTreeMap<(u32, u64), Option<modes::LatLon>>,
}

impl<'r> Reader<'r> {
    /// The inputs read once: every reception linearized and indexed.
    pub(crate) fn new(inputs: &'r Inputs, cache: &'r mut ReadCache) -> Self {
        cache.begin();
        let sites = site_table(&inputs.scope);
        let (rxs, clocks) = linearize(&sites, inputs);
        let mut messages = Messages::new(cache, &inputs.messages);
        let count = inputs.messages.len();
        let mut starts = vec![0usize; count + 1];
        for rx in &rxs {
            starts[rx.message as usize + 1] += 1;
        }
        for at in 1..starts.len() {
            starts[at] += starts[at - 1];
        }
        let mut by_message = vec![(0u64, 0u32); rxs.len()];
        let mut next = starts.clone();
        for (index, rx) in rxs.iter().enumerate() {
            let place = &mut next[rx.message as usize];
            by_message[*place] = (rx.wall_ms, index as u32);
            *place += 1;
        }
        for m in 0..count {
            by_message[starts[m]..starts[m + 1]].sort_unstable();
        }
        let mut distinct: Vec<u32> = (0..count as u32)
            .filter(|m| starts[*m as usize + 1] > starts[*m as usize])
            .collect();
        distinct.sort_unstable_by(|a, b| messages.data(*a).cmp(messages.data(*b)));
        let mut rank = vec![u32::MAX; count];
        for (at, message) in distinct.iter().enumerate() {
            rank[*message as usize] = at as u32;
        }
        let mut by_second: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
        let mut positions: BTreeMap<u32, Vec<Position>> = BTreeMap::new();
        let mut nacp: BTreeMap<u32, Vec<Nacp>> = BTreeMap::new();
        for message in &distinct {
            let receptions = &by_message[starts[*message as usize]..starts[*message as usize + 1]];
            let mut last = None;
            for (wall, _) in receptions {
                let second = wall / 1000;
                if last != Some(second) {
                    by_second.entry(second).or_default().push(*message);
                    last = Some(second);
                }
            }
            let parsed = messages.parsed(*message);
            let Some(address) = parsed.address else {
                continue;
            };
            let (value, position) = (parsed.nacp, parsed.position);
            for (wall, index) in receptions {
                let rx = &rxs[*index as usize];
                if let Some(value) = value {
                    nacp.entry(address)
                        .or_default()
                        .push((rx.clock, rx.linear, value, *wall));
                }
                if let Some(position) = position {
                    positions.entry(address).or_default().push((
                        rx.clock,
                        rx.linear,
                        *message,
                        position.odd,
                        *wall,
                    ));
                }
            }
        }
        for list in positions.values_mut() {
            list.sort_unstable_by_key(|(clock, linear, message, odd, wall)| {
                (*clock, *linear, rank[*message as usize], *odd, *wall)
            });
        }
        for list in nacp.values_mut() {
            list.sort_unstable();
        }
        let windows = clocks
            .iter()
            .map(|site| site.timebase.pair_counts())
            .collect();
        Self {
            clocks,
            rxs,
            messages,
            rank,
            windows,
            starts,
            by_message,
            by_second,
            positions,
            nacp,
            references: BTreeMap::new(),
        }
    }

    /// Ends the read: the parse memos it did not use may be let go (`ReadCache::finish`).
    pub(crate) fn finish(self) {
        self.messages.cache.finish();
    }

    /// The hash of message `message`.
    pub(crate) fn hash(&self, message: u32) -> [u8; 32] {
        self.messages.hash(message)
    }

    /// The wall-clock span a block of second `second` reads: from `LOOK_BACK_S` before it to
    /// `SPAN_AFTER_S` after, milliseconds.
    fn read_span(second: u64) -> (u64, u64) {
        (
            second.saturating_sub(LOOK_BACK_S) * 1000,
            (second + 1 + SPAN_AFTER_S) * 1000,
        )
    }

    /// The CPR reference of `address` for the block of `second` (crate docs, § Sync events, 3):
    /// the search over its position receptions in the block's read span alone.
    fn reference(&mut self, address: u32, second: u64) -> Option<modes::LatLon> {
        if let Some(found) = self.references.get(&(address, second)) {
            return *found;
        }
        let (from, to) = Self::read_span(second);
        let heard: Vec<Heard> = self
            .positions
            .get(&address)
            .map(|list| {
                list.iter()
                    .filter(|(_, _, _, _, wall)| (from..to).contains(wall))
                    .map(|(clock, linear, message, odd, _)| (*clock, *linear, *message, *odd))
                    .collect()
            })
            .unwrap_or_default();
        let found = cpr_reference(&heard, &self.windows, &self.rank, &mut self.messages)
            .map(|(reference, _, _, _)| reference);
        self.references.insert((address, second), found);
        found
    }

    /// The NACp in force at an event of `address` in the block of `second`, its receptions
    /// `indices` (into `rxs`): of the address's NACp receptions in the block's read span on the
    /// event's clocks, the latest at or before one of the event's receptions on the same clock,
    /// nearest in that clock's nominal time; with none before, the earliest after, nearest; of
    /// equals the lower value. Each clock's counts are compared only with its own.
    fn nacp_at(&self, address: u32, second: u64, indices: &[u32]) -> Option<u8> {
        let list = self.nacp.get(&address)?;
        let (from, to) = Self::read_span(second);
        let mut best: Option<(bool, i128, u8)> = None;
        for index in indices {
            let rx = &self.rxs[*index as usize];
            let site = &self.clocks[rx.clock];
            let low = list.partition_point(|(clock, _, _, _)| *clock < rx.clock);
            let run = &list[low..];
            let run = &run[..run.partition_point(|(clock, _, _, _)| *clock == rx.clock)];
            let mut before: Option<(i64, u8)> = None;
            let mut after: Option<(i64, u8)> = None;
            for (_, linear, value, wall) in run {
                if !(from..to).contains(wall) {
                    continue;
                }
                if *linear <= rx.linear {
                    // Sorted by count then value: the latest, of equals the lower value.
                    if before.is_none_or(|(held, _)| *linear > held) {
                        before = Some((*linear, *value));
                    }
                } else if after.is_none_or(|(held, _)| *linear < held) {
                    after = Some((*linear, *value));
                }
            }
            let candidates = [
                before.map(|(linear, value)| {
                    (
                        false,
                        site.timebase
                            .elapsed_ps(i128::from(rx.linear) - i128::from(linear)),
                        value,
                    )
                }),
                after.map(|(linear, value)| {
                    (
                        true,
                        site.timebase
                            .elapsed_ps(i128::from(linear) - i128::from(rx.linear)),
                        value,
                    )
                }),
            ];
            for candidate in candidates.into_iter().flatten() {
                if best.is_none_or(|known| candidate < known) {
                    best = Some(candidate);
                }
            }
        }
        best.map(|(_, _, value)| value)
    }

    /// The sync events of the block of wall-clock second `second` (crate docs, § The pairwise
    /// path, blocks), in byte order of their messages: each message heard in the second and not
    /// in the `LOOK_BACK_S` before it, with its receptions within `SPAN_AFTER_S` after the second,
    /// a clock that heard it twice there left out, read by its aircraft's reference and NACp in
    /// the block's read span. A function of the receptions in that span alone.
    pub(crate) fn events(&mut self, second: u64) -> Vec<Event> {
        let Some(messages) = self.by_second.get(&second).cloned() else {
            return Vec::new();
        };
        let (look_from, _) = Self::read_span(second);
        let (own_from, own_to) = (second * 1000, (second + 1 + SPAN_AFTER_S) * 1000);
        let mut events = Vec::new();
        let mut indices: Vec<u32> = Vec::new();
        for message in messages {
            let receptions = &self.by_message
                [self.starts[message as usize]..self.starts[message as usize + 1]];
            if receptions
                .iter()
                .any(|(wall, _)| *wall >= look_from && *wall < own_from)
            {
                continue;
            }
            indices.clear();
            indices.extend(
                receptions
                    .iter()
                    .filter(|(wall, _)| (own_from..own_to).contains(wall))
                    .map(|(_, index)| *index),
            );
            let parsed = self.messages.parsed(message);
            let (Some(address), Some(position)) = (parsed.address, parsed.position) else {
                continue;
            };
            if position.altitude.is_none() {
                continue;
            }
            let Some(reference) = self.reference(address, second) else {
                continue;
            };
            let Some(decoded) = self.messages.parsed(message).decode(reference) else {
                continue;
            };
            if !decoded.near {
                continue;
            }
            let declared = self
                .nacp_at(address, second, &indices)
                .and_then(modes::epu_m)
                .or_else(|| modes::containment_m(position.type_code));
            let Some(declared) = declared else {
                continue;
            };
            let sigma_h = (declared / R95).max(MIN_PRIOR_SIGMA_M);
            if sigma_h > MAX_PRIOR_SIGMA_M {
                continue;
            }
            // A clock that heard the message twice in the event's span is left out of it.
            let mut by_clock: Vec<(usize, u32)> = indices
                .iter()
                .map(|index| (self.rxs[*index as usize].clock, *index))
                .collect();
            by_clock.sort_unstable();
            let mut hearers = Vec::new();
            for (at, (clock, index)) in by_clock.iter().enumerate() {
                let twice = (at > 0 && by_clock[at - 1].0 == *clock)
                    || by_clock.get(at + 1).is_some_and(|next| next.0 == *clock);
                if twice {
                    continue;
                }
                let range_m = linalg::norm(linalg::sub(decoded.prior, self.clocks[*clock].ecef));
                if range_m <= MAX_RANGE_M {
                    hearers.push((*index, range_m));
                }
            }
            if hearers.len() < 2 {
                continue;
            }
            events.push(Event { address, hearers });
        }
        events
    }
}

/// The Unix time of a clock's linear count `anchor`, given a wall clock (Unix nanoseconds) of when
/// it was heard. A GNSS-disciplined clock's linear count is nanoseconds of the UTC day, so the
/// wall clock only picks the day (the one that puts the count within half a day of it) and the
/// time is exact; a free-running clock has no absolute time, and the wall clock is returned.
pub fn origin_unix_ns(timebase: Timebase, anchor: i64, wall_unix_ns: u64) -> Option<u64> {
    match timebase {
        Timebase::Mhz12 => Some(wall_unix_ns),
        Timebase::GpsNanos => {
            let day = i128::from(DAY_NS);
            let wall = i128::from(wall_unix_ns);
            let anchor = i128::from(anchor);
            let start = (wall - anchor + day / 2).div_euclid(day) * day;
            u64::try_from(start + anchor).ok()
        }
    }
}
