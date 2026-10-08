//! Windows, tiles and assignment (crate docs, § Windows, § Tiles, § Assignment): which raw a
//! tile's shared clock model is a function of, and which tile each aircraft is solved under.
//! Decided by the content alone, never by when anything arrived, so two engines holding the same
//! raw build the same inputs. A window is assembled from the sealed bins it spans
//! (`held::Bin`), each indexed once when it was sealed; nothing here copies the raw, except the
//! few receptions a tile's fit or an aircraft's solve takes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use blake2::{Blake2s256, Digest};
use tally_wire::PublicKey;

use crate::held::Bin;
use crate::obs::{ObservationId, Reception, Site};
use crate::tile::{self, Tile};

/// The wall clock grid, milliseconds: an observation's bin is its batch wall clock over this.
pub const GRID_MS: u64 = 5_000;
/// Bins of the canonical window before the bin its transmissions are solved in.
pub const BEFORE: i64 = 11;
/// Bins of the canonical window after it (`L`).
pub const AFTER: i64 = 1;
/// What the input citation is hashed under.
const CITATION_DOMAIN: &[u8] = b"tally clock model inputs";
/// What a sync aircraft's rank in a tile's window is hashed under.
const RANK_DOMAIN: &[u8] = b"tally sync aircraft rank";
/// Sync events a receiver keeps per grid bin (`K`).
pub const EVENTS_PER_RECEIVER: usize = 10;
/// Sync events a pair of receivers keeps per grid bin, when they hear one together (`P`).
pub const EVENTS_PER_PAIR: usize = 1;
/// Distinct sync aircraft a tile's window takes its events from (`A_max`), by rank.
pub const SYNC_AIRCRAFT_MAX: usize = 16;
/// Bins solved under one window (`s`): a tile is fitted once per this many bins.
pub const STRIDE: i64 = 8;
/// Transmissions solved per aircraft per bin, at most (about one a second), by rank.
pub const TRANSMISSIONS_PER_BIN: usize = 5;
/// What a transmission's rank is hashed under.
const TRANSMISSION_DOMAIN: &[u8] = b"tally transmission rank";

/// The grid bin of a wall clock.
pub fn bin_of(wall_ms: u64) -> i64 {
    (wall_ms / GRID_MS) as i64
}

/// A span of grid bins, both ends included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Window {
    pub first: i64,
    pub last: i64,
}

impl Window {
    /// The window a transmission in `bin` is solved under, at the specification's stride.
    pub fn canonical(bin: i64) -> Self {
        Self::strided(bin, STRIDE)
    }

    /// The window that solves `bin` at stride `s`: with `ks` the least multiple of `s` at or above
    /// `bin`, `[ks - BEFORE - (s - 1), ks + AFTER]`, which solves bins `ks - (s - 1)` to `ks`, each
    /// with at least `BEFORE` bins before it and `AFTER` after.
    pub fn strided(bin: i64, stride: i64) -> Self {
        let stride = stride.max(1);
        let top = (bin + stride - 1).div_euclid(stride) * stride;
        Self {
            first: top - BEFORE - (stride - 1),
            last: top + AFTER,
        }
    }

    /// The stride the window was made at.
    pub fn stride(&self) -> i64 {
        (self.last - self.first + 1 - BEFORE - AFTER).max(1)
    }

    /// The last bin the window solves.
    pub fn bin(&self) -> i64 {
        self.last - AFTER
    }

    /// The bins the window solves.
    pub fn solved(&self) -> std::ops::RangeInclusive<i64> {
        self.bin() - (self.stride() - 1)..=self.bin()
    }

    pub fn holds(&self, wall_ms: u64) -> bool {
        let bin = bin_of(wall_ms);
        bin >= self.first && bin <= self.last
    }
}

/// The bin a transmission belongs to: its receptions' wall clocks' lower median's.
pub fn bin_of_transmission(walls: &mut [u64]) -> Option<i64> {
    walls.sort_unstable();
    let middle = walls.len().checked_sub(1)? / 2;
    Some(bin_of(walls[middle]))
}

/// A set of observations cited by hash and count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Citation {
    /// BLAKE2s-256 over `"tally clock model inputs" 0x00`, then each distinct (identity, wall
    /// clock) in order as receiver key (32), epoch (4), counter (6), message hash (32), wall
    /// clock (8), all big-endian.
    pub hash: [u8; 32],
    pub count: u32,
}

impl Citation {
    pub fn of<'a>(receptions: impl IntoIterator<Item = &'a Reception>) -> Self {
        Self::of_identities(
            receptions
                .into_iter()
                .map(|reception| (reception.id(), reception.wall_ms)),
        )
    }

    pub fn of_identities(entries: impl IntoIterator<Item = (ObservationId, u64)>) -> Self {
        let entries: BTreeSet<(ObservationId, u64)> = entries.into_iter().collect();
        let mut hasher = Blake2s256::new();
        hasher.update(CITATION_DOMAIN);
        hasher.update([0]);
        for (id, wall) in &entries {
            hasher.update(id.receiver.as_bytes());
            hasher.update(id.epoch.to_be_bytes());
            hasher.update(&id.timestamp.to_be_bytes()[2..]);
            hasher.update(id.message);
            hasher.update(wall.to_be_bytes());
        }
        Self {
            hash: hasher.finalize().into(),
            count: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        }
    }

    /// As the wire carries it in a solution.
    pub fn to_wire(self) -> tally_wire::AddressedCitation {
        tally_wire::AddressedCitation {
            hash: self.hash,
            count: self.count,
        }
    }
}

/// What one tile's clock model in one window is a function of.
#[derive(Clone, Debug, PartialEq)]
pub struct Inputs {
    pub tile: Tile,
    pub window: Window,
    /// The tile's members, sorted by key.
    pub scope: Vec<Site>,
    /// The sync material: the members' receptions of the sync events kept (§ Thinning), and of
    /// each distinct operational status of a kept event's aircraft its lowest-identity member
    /// reception. Sorted by identity.
    pub sync: Vec<Reception>,
    pub citation: Citation,
}

impl Inputs {
    /// The members' keys, sorted.
    pub fn keys(&self) -> Vec<PublicKey> {
        self.scope.iter().map(|site| site.receiver).collect()
    }
}

/// The receivers that may take part, each with its millimetre site: one per receiver, usable
/// (a receiver described twice, or unusable, takes no part).
#[derive(Clone, Debug, Default)]
pub struct Sites {
    by_key: BTreeMap<PublicKey, (Site, [i64; 3])>,
}

impl Sites {
    pub fn new(sites: &[Site]) -> Self {
        let mut count: BTreeMap<PublicKey, usize> = BTreeMap::new();
        for site in sites {
            *count.entry(site.receiver).or_default() += 1;
        }
        Self {
            by_key: sites
                .iter()
                .filter(|site| count.get(&site.receiver) == Some(&1) && site.usable())
                .map(|site| (site.receiver, (*site, site.mm())))
                .collect(),
        }
    }

    pub fn get(&self, key: &PublicKey) -> Option<&(Site, [i64; 3])> {
        self.by_key.get(key)
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PublicKey, &(Site, [i64; 3]))> {
        self.by_key.iter()
    }
}

/// Which tile an aircraft is solved under, and which of its hearers are its scope there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub tile: Tile,
    /// Its hearers among the tile's members, sorted.
    pub scope: Vec<PublicKey>,
}

/// One target's hearers (with their sites) and its tile at each level.
type Candidates = (u32, Vec<(PublicKey, [i64; 3])>, Vec<Tile>);

/// A bin's work: every aircraft heard in it with its tile, and every tile's members.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub assignments: BTreeMap<u32, Assignment>,
    /// Every tile looked at, chosen or not.
    pub members: BTreeMap<Tile, Vec<PublicKey>>,
}

impl Plan {
    /// The distinct tiles the bin's aircraft chose, in order: the bin's fits.
    pub fn tiles(&self) -> Vec<Tile> {
        let chosen: BTreeSet<Tile> = self
            .assignments
            .values()
            .map(|assignment| assignment.tile)
            .collect();
        chosen.into_iter().collect()
    }
}

/// One window, assembled from the sealed bins it spans.
pub struct WindowIndex<'a> {
    pub window: Window,
    bins: Vec<Arc<Bin>>,
    sites: &'a Sites,
    /// The window's sync-active usable receivers, with their sites, by key.
    active: Vec<(PublicKey, [i64; 3])>,
    /// The same, by the level-3 cube their site is in: what a footprint looks through.
    grid: BTreeMap<[i64; 3], Vec<usize>>,
    /// Per bin, per receiver index, its usable site (looked up once).
    usable: Vec<Vec<Option<[i64; 3]>>>,
    sync_aircraft_max: Option<usize>,
}

impl<'a> WindowIndex<'a> {
    /// `bins`: any, in any order; only those in the window are kept.
    pub fn new(window: Window, bins: &[Arc<Bin>], sites: &'a Sites) -> Self {
        Self::with_sync_aircraft(window, bins, sites, Some(SYNC_AIRCRAFT_MAX))
    }

    /// As `new`, with `A_max` other than the specification's (for measuring it).
    pub fn with_sync_aircraft(
        window: Window,
        bins: &[Arc<Bin>],
        sites: &'a Sites,
        sync_aircraft_max: Option<usize>,
    ) -> Self {
        let mut bins: Vec<Arc<Bin>> = bins
            .iter()
            .filter(|bin| bin.bin >= window.first && bin.bin <= window.last)
            .cloned()
            .collect();
        bins.sort_by_key(|bin| bin.bin);
        bins.dedup_by_key(|bin| bin.bin);
        let usable: Vec<Vec<Option<[i64; 3]>>> = bins
            .iter()
            .map(|bin| {
                bin.receivers
                    .iter()
                    .map(|key| sites.get(key).map(|(_, mm)| *mm))
                    .collect()
            })
            .collect();
        let mut active: BTreeMap<PublicKey, [i64; 3]> = BTreeMap::new();
        for (bin, usable) in bins.iter().zip(&usable) {
            for (index, key) in bin.receivers.iter().enumerate() {
                if bin.sync_active[index]
                    && let Some(mm) = usable[index]
                {
                    active.insert(*key, mm);
                }
            }
        }
        let active: Vec<(PublicKey, [i64; 3])> = active.into_iter().collect();
        let mut grid: BTreeMap<[i64; 3], Vec<usize>> = BTreeMap::new();
        for (at, (_, mm)) in active.iter().enumerate() {
            grid.entry(Tile::containing(tile::LEVELS - 1, *mm).cube)
                .or_default()
                .push(at);
        }
        Self {
            window,
            bins,
            sites,
            active,
            grid,
            usable,
            sync_aircraft_max,
        }
    }

    pub fn bins(&self) -> &[Arc<Bin>] {
        &self.bins
    }

    /// The window's MLAT targets, in order (§ Targets): the aircraft heard in a bin it solves
    /// with no ADS-B position anywhere in the window, and those of the calibration sample.
    pub fn addresses(&self) -> Vec<u32> {
        let adsb: BTreeSet<u32> = self
            .bins
            .iter()
            .flat_map(|bin| bin.adsb.iter().copied())
            .collect();
        let solved = self.window.solved();
        let mut out: BTreeSet<u32> = BTreeSet::new();
        for (bin, usable) in self.bins.iter().zip(&self.usable) {
            if !solved.contains(&bin.bin) {
                continue;
            }
            for (address, records) in &bin.by_address {
                let heard = records.iter().any(|record| {
                    let record = &bin.records[*record as usize];
                    usable[record.receiver as usize].is_some()
                        && !bin.messages[record.message as usize].sync
                });
                let target = !adsb.contains(address) || crate::held::sampled(*address, bin.bin);
                if heard && target {
                    out.insert(*address);
                }
            }
        }
        out.into_iter().collect()
    }

    /// The members of `tile` in this window (§ Tiles): its footprint's sync-active receivers, at
    /// most `tile::MEMBERS_MAX` by farthest point. Sorted.
    pub fn members(&self, tile: Tile) -> Vec<PublicKey> {
        // Every level-3 cube the footprint can reach: its centre's, and those within the reach
        // (the footprint radius over the level-3 edge, rounded up, and one more).
        let centre = Tile::containing(tile::LEVELS - 1, tile.centre_mm()).cube;
        let reach = tile::footprint_mm(tile.level) / tile::edge_mm(tile::LEVELS - 1) + 1;
        let mut inside: Vec<(PublicKey, [i64; 3])> = Vec::new();
        for x in -reach..=reach {
            for y in -reach..=reach {
                for z in -reach..=reach {
                    let cube = [centre[0] + x, centre[1] + y, centre[2] + z];
                    for at in self.grid.get(&cube).map_or(&[][..], Vec::as_slice) {
                        let (key, mm) = self.active[*at];
                        if tile.holds(mm) {
                            inside.push((key, mm));
                        }
                    }
                }
            }
        }
        tile::members(&inside)
    }

    /// The usable receivers that heard `address` in the window, with their sites, by key.
    pub fn hearers(&self, address: u32) -> Vec<(PublicKey, [i64; 3])> {
        let mut out: Vec<(PublicKey, [i64; 3])> = Vec::new();
        for (bin, usable) in self.bins.iter().zip(&self.usable) {
            let mut last = u32::MAX;
            for record in bin.by_address.get(&address).map_or(&[][..], Vec::as_slice) {
                let receiver = bin.records[*record as usize].receiver;
                if receiver == last {
                    continue;
                }
                last = receiver;
                if let Some(mm) = usable[receiver as usize] {
                    out.push((bin.receivers[receiver as usize], mm));
                }
            }
        }
        out.sort_unstable_by_key(|(key, _)| *key);
        out.dedup_by_key(|(key, _)| *key);
        out
    }

    /// Every target of the window assigned (§ Assignment), in address order.
    pub fn plan(&self) -> Plan {
        self.plan_on(1)
    }

    /// As `plan`, on `threads` threads: each target's hearers and candidate tiles, then each
    /// distinct candidate's members, then the choice. The same whatever the threads.
    pub fn plan_on(&self, threads: usize) -> Plan
    where
        Self: Sync,
    {
        let addresses = self.addresses();
        let threads = threads.clamp(1, addresses.len().max(1));
        let split = |count: usize| count.div_ceil(threads).max(1);
        // Each target's hearers and its tile at every level.
        let candidates: Vec<Candidates> = std::thread::scope(|scope| {
            let handles: Vec<_> = addresses
                .chunks(split(addresses.len()))
                .map(|chunk| {
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .filter_map(|address| {
                                let hearers = self.hearers(*address);
                                let points: Vec<[i64; 3]> =
                                    hearers.iter().map(|(_, mm)| *mm).collect();
                                let median = tile::lower_median(&points)?;
                                let tiles = (0..tile::LEVELS)
                                    .map(|level| Tile::containing(level, median))
                                    .collect();
                                Some((*address, hearers, tiles))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap_or_default())
                .collect()
        });
        // Every distinct candidate's members.
        let tiles: Vec<Tile> = candidates
            .iter()
            .flat_map(|(_, _, tiles)| tiles.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let members: BTreeMap<Tile, Vec<PublicKey>> = std::thread::scope(|scope| {
            let handles: Vec<_> = tiles
                .chunks(split(tiles.len()))
                .map(|chunk| {
                    scope.spawn(move || {
                        chunk
                            .iter()
                            .map(|tile| (*tile, self.members(*tile)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap_or_default())
                .collect()
        });
        // The choice, by the rule.
        let mut plan = Plan {
            assignments: BTreeMap::new(),
            members,
        };
        for (address, hearers, _) in &candidates {
            if let Some((tile, scope)) = tile::assign(hearers, |tile| {
                plan.members.get(&tile).cloned().unwrap_or_default()
            }) {
                plan.assignments
                    .insert(*address, Assignment { tile, scope });
            }
        }
        plan
    }

    /// The tile `address` is solved under (§ Assignment), with `members` remembering what each
    /// tile's members are.
    pub fn assign(
        &self,
        address: u32,
        members: &mut BTreeMap<Tile, Vec<PublicKey>>,
    ) -> Option<Assignment> {
        let hearers = self.hearers(address);
        let (tile, scope) = tile::assign(&hearers, |tile| {
            members
                .entry(tile)
                .or_insert_with(|| self.members(tile))
                .clone()
        })?;
        Some(Assignment { tile, scope })
    }

    /// Every usable receiver's receptions of `address` in the window: what chose its tile, as the
    /// solution cites it.
    pub fn addressed_citation(&self, address: u32) -> Citation {
        let mut entries = Vec::new();
        for bin in &self.bins {
            for record in bin.by_address.get(&address).map_or(&[][..], Vec::as_slice) {
                let id = bin.id(*record);
                if self.sites.get(&id.receiver).is_some() {
                    entries.push((id, bin.wall_ms(&bin.records[*record as usize])));
                }
            }
        }
        Citation::of_identities(entries)
    }

    /// The receptions of `address` in the window by `scope` receivers: what its transmissions are
    /// grouped and solved from (never its ADS-B positions, which sync the clocks). Sorted by
    /// identity.
    pub fn receptions(&self, address: u32, scope: &[PublicKey]) -> Vec<Reception> {
        let wanted: BTreeSet<&PublicKey> = scope.iter().collect();
        let mut out = Vec::new();
        for bin in &self.bins {
            for record in bin.by_address.get(&address).map_or(&[][..], Vec::as_slice) {
                let held = &bin.records[*record as usize];
                let key = &bin.receivers[held.receiver as usize];
                if wanted.contains(key) && !bin.messages[held.message as usize].sync {
                    out.push(bin.reception(*record));
                }
            }
        }
        out.sort_by_cached_key(Reception::id);
        out
    }

    /// A sync aircraft's rank in this window: BLAKE2s-256 over `"tally sync aircraft rank" 0x00`,
    /// the address and the window's first and last bins, big-endian.
    pub fn rank(&self, address: u32) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(RANK_DOMAIN);
        hasher.update([0]);
        hasher.update(address.to_be_bytes());
        hasher.update(self.window.first.to_be_bytes());
        hasher.update(self.window.last.to_be_bytes());
        hasher.finalize().into()
    }

    /// Everything `tile`'s model in this window is a function of (§ Thinning), or `None` when it
    /// has fewer than two members.
    pub fn inputs(&self, tile: Tile, members: &[PublicKey]) -> Option<Inputs> {
        if members.len() < 2 {
            return None;
        }
        let scope: Vec<Site> = members
            .iter()
            .filter_map(|key| self.sites.get(key).map(|(site, _)| *site))
            .collect();
        // Per bin, the candidates the members heard, each with the members' records of it.
        struct Event<'b> {
            bin: &'b Bin,
            records: Vec<u32>,
            places: Vec<usize>,
            address: u32,
            hash: [u8; 32],
        }
        let mut events: Vec<Event<'_>> = Vec::new();
        for bin in &self.bins {
            let locals: Vec<(usize, u32)> = members
                .iter()
                .enumerate()
                .filter_map(|(place, key)| bin.receiver(key).map(|local| (place, local)))
                .collect();
            let mut heard: Vec<u32> = locals
                .iter()
                .flat_map(|(_, local)| bin.heard[*local as usize].iter().copied())
                .collect();
            heard.sort_unstable();
            heard.dedup();
            let place_of: BTreeMap<u32, usize> = locals
                .iter()
                .map(|(place, local)| (*local, *place))
                .collect();
            for candidate in heard {
                let candidate = &bin.candidates[candidate as usize];
                let message = &bin.messages[candidate.message as usize];
                let Some(address) = message.address else {
                    continue;
                };
                let mut records = Vec::new();
                let mut places = Vec::new();
                for record in &candidate.records {
                    let local = bin.records[*record as usize].receiver;
                    if let Some(place) = place_of.get(&local) {
                        // One receiver twice in one event: the fit drops it; keep the first.
                        if places.last() != Some(place) {
                            records.push(*record);
                            places.push(*place);
                        }
                    }
                }
                if places.len() >= 2 {
                    events.push(Event {
                        bin,
                        records,
                        places,
                        address,
                        hash: message.hash,
                    });
                }
            }
        }
        // The sync aircraft, by rank: at most `A_max`.
        let mut aircraft: Vec<u32> = events.iter().map(|event| event.address).collect();
        aircraft.sort_unstable();
        aircraft.dedup();
        aircraft.sort_by_cached_key(|address| self.rank(*address));
        if let Some(cap) = self.sync_aircraft_max {
            aircraft.truncate(cap);
        }
        let kept_aircraft: BTreeSet<u32> = aircraft.into_iter().collect();
        events.retain(|event| kept_aircraft.contains(&event.address));
        // Thinning: per bin, in rank order (the message hash), an event is kept when one of its
        // members has kept fewer than `K` there, or one pair of them fewer than `P` together.
        events.sort_by(|a, b| a.bin.bin.cmp(&b.bin.bin).then(a.hash.cmp(&b.hash)));
        let n = members.len();
        let bins = usize::try_from(self.window.last - self.window.first + 1).unwrap_or(0);
        let mut per_receiver = vec![0usize; n * bins];
        let mut per_pair = vec![0usize; n * n * bins];
        let mut sync: Vec<Reception> = Vec::new();
        for event in &events {
            let Some(slot) = usize::try_from(event.bin.bin - self.window.first)
                .ok()
                .filter(|slot| *slot < bins)
            else {
                continue;
            };
            let wanted = event
                .places
                .iter()
                .any(|r| per_receiver[r * bins + slot] < EVENTS_PER_RECEIVER)
                || event.places.iter().enumerate().any(|(i, a)| {
                    event.places[i + 1..].iter().any(|b| {
                        let (low, high) = if a < b { (a, b) } else { (b, a) };
                        per_pair[(low * n + high) * bins + slot] < EVENTS_PER_PAIR
                    })
                });
            if !wanted {
                continue;
            }
            for (i, a) in event.places.iter().enumerate() {
                per_receiver[a * bins + slot] += 1;
                for b in &event.places[i + 1..] {
                    let (low, high) = if a < b { (a, b) } else { (b, a) };
                    per_pair[(low * n + high) * bins + slot] += 1;
                }
            }
            sync.extend(
                event
                    .records
                    .iter()
                    .map(|record| event.bin.reception(*record)),
            );
        }
        // The operational status of the kept events' aircraft: of each distinct message, its
        // lowest-identity member reception in the window.
        let used: BTreeSet<u32> = sync
            .iter()
            .filter_map(|reception| crate::modes::address(&reception.observation.data))
            .collect();
        let wanted: BTreeSet<&PublicKey> = members.iter().collect();
        let mut status: BTreeMap<[u8; 32], Reception> = BTreeMap::new();
        for bin in &self.bins {
            for address in &used {
                for (message, records) in bin.status.get(address).map_or(&[][..], Vec::as_slice) {
                    // The lowest-identity member record of the message in this bin.
                    let first = records
                        .iter()
                        .find(|record| {
                            let local = bin.records[**record as usize].receiver;
                            wanted.contains(&bin.receivers[local as usize])
                        })
                        .map(|record| bin.reception(*record));
                    if let Some(first) = first {
                        let hash = bin.messages[*message as usize].hash;
                        let keep = status.get(&hash).is_none_or(|held| first.id() < held.id());
                        if keep {
                            status.insert(hash, first);
                        }
                    }
                }
            }
        }
        sync.extend(status.into_values());
        sync.sort_by_cached_key(Reception::id);
        sync.dedup_by(|later, earlier| later.id() == earlier.id());
        let citation = Citation::of(&sync);
        Some(Inputs {
            tile,
            window: self.window,
            scope,
            sync,
            citation,
        })
    }
}

/// The transmissions of `grouping` the window solves (§ Targets): those of a bin it solves, at
/// most `TRANSMISSIONS_PER_BIN` a bin, the lowest-ranked first. A transmission's rank is
/// BLAKE2s-256 over `"tally transmission rank" 0x00` and its lowest-identity reception's identity
/// (receiver key, epoch, counter (8), message hash).
pub fn chosen(
    window: &Window,
    transmissions: Vec<crate::group::Transmission>,
) -> Vec<crate::group::Transmission> {
    let rank = |transmission: &crate::group::Transmission| -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        hasher.update(TRANSMISSION_DOMAIN);
        hasher.update([0]);
        if let Some(first) = transmission.receptions.iter().map(|timed| timed.id).min() {
            hasher.update(first.receiver.as_bytes());
            hasher.update(first.epoch.to_be_bytes());
            hasher.update(first.timestamp.to_be_bytes());
            hasher.update(first.message);
        }
        hasher.finalize().into()
    };
    let solved = window.solved();
    let mut by_bin: BTreeMap<i64, Vec<([u8; 32], crate::group::Transmission)>> = BTreeMap::new();
    for transmission in transmissions {
        if let Some(bin) = transmission.bin().filter(|bin| solved.contains(bin)) {
            by_bin
                .entry(bin)
                .or_default()
                .push((rank(&transmission), transmission));
        }
    }
    let mut out = Vec::new();
    for mut list in by_bin.into_values() {
        list.sort_by_key(|entry| entry.0);
        out.extend(
            list.into_iter()
                .take(TRANSMISSIONS_PER_BIN)
                .map(|(_, transmission)| transmission),
        );
    }
    out
}
