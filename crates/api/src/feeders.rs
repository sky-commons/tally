//! FEEDER FIGURES AND LEADERBOARDS (RFC-0174 §2.12), as this API computes them as one client of the
//! network. No relay computes or vouches for any of it: every figure is a function of public signed
//! records the API reads like any other client (receivers' signed batches, the signed final
//! positions that cite their receptions) and of where each receiver says it is (its own signed
//! description, which the relay's station report carries), so anyone who reads the same records
//! computes the same figures.
//!
//! Over the window (the hour now and the 23 before it, `WINDOW_HOURS`), per receiver:
//!
//! - **uptime**: the share of the window's minutes in which a batch of it was published, by the
//!   batch's own signed wall clock (a batch whose clock is more than `FRESH_WITHIN_MS` from the
//!   API's is not counted, so no history can be signed after the fact);
//! - **messages**: receptions in its batches, and their rate over the window;
//! - **aircraft**: distinct addresses it heard in a checked format (DF11, DF17, DF18: the CRC
//!   proves the address, which the address-parity formats cannot);
//! - **range**: the farthest positioned aircraft it heard, from where it says it is;
//! - **coverage** and **unique coverage**: the coverage cells (H3, `COVERAGE_RESOLUTION`) holding
//!   an aircraft at a second it heard that aircraft, and those of them no other receiver heard;
//! - **MLAT help**: distinct final positions (by observation set) the MLAT merge accepted that cite
//!   one of its receptions, a reception its own signed raw holds.
//!
//! A row is made only by a receiver's own signed batch: a position citing a key that never
//! published one makes no row and earns nothing. A final position counts only by the merge's
//! verdict ([`Verdict`]): one the merge did not accept (a convicted signer's, a refused superset,
//! one failing a check) neither places an aircraft nor credits anyone, and a reception it cites
//! credits its receiver only when that receiver's own signed raw holds it, so citing a key does
//! not hand it coverage or MLAT help. Without the merge's raw (`--mlat-raw`) no reception can be
//! checked, so MLAT credits nobody.
//!
//! An aircraft is positioned at a second by a global CPR decode of an even and an odd airborne
//! position one receiver heard within `PAIR_WITHIN_MS`, or by an accepted final MLAT position;
//! when a second holds several, the least by latitude then longitude stands, so the order records
//! arrive in decides nothing. A receiver heard an aircraft at a second when it holds a reception of
//! its checked address then; that second's position is the nearest within `NEAR_SECS`. A second is
//! settled `SETTLE_SECS` after it ends (time for the slowest record), and what arrives for a settled
//! second counts toward messages and aircraft but no longer toward coverage.
//!
//! **Leaderboards** rank, per area (`tally_wire::rendezvous::area_at` of where a receiver says it
//! is, the network's own areas), by unique coverage and by MLAT help, never by raw message counts, and rank
//! only receivers with standing (RFC-0174 §2.12, the merge's ledger): a new key, or one whose
//! receptions keep disagreeing with verified fixes, is listed nowhere.
//!
//! Memory is bounded: receivers, aircraft and cited observation sets each by count, least recently
//! active forgotten first (`Bounded`), and each receiver's aircraft and cells by `MAX_PER_FEEDER`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use h3o::{CellIndex, LatLng, Resolution};
use tally_api_types::{
    FeederStats, Leaderboard, LeaderboardArea, LeaderboardEntry, Leaderboards, Position, Ranks,
};
use tally_mlat_solver::modes;
use tally_relay::bounded::Bounded;
use tally_wire::batch::Hash;
use tally_wire::rendezvous::{AREA_RESOLUTION, area_at};
use tally_wire::{Batch, Positions, PublicKey, Reception, Record, Solution};

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 3_600_000;
/// The window every figure covers: the hour now and the ones before it, this many in all.
pub const WINDOW_HOURS: u64 = 24;
/// A second is settled (credited to coverage) this long after it ends.
pub const SETTLE_SECS: u64 = 30;
/// How far from a second a position may be and still place an aircraft heard then.
pub const NEAR_SECS: u64 = 2;
/// How close in time an even and an odd airborne position must be to decode globally.
pub const PAIR_WITHIN_MS: u64 = 10_000;
/// A batch or a position whose own clock is further than this from the API's is not counted.
pub const FRESH_WITHIN_MS: u64 = 120_000;
/// Beyond this from where a receiver says it is, a position it is credited with is not its own:
/// past the radio horizon of an aircraft at 45,000 ft and an antenna on a tall mast.
pub const MAX_RANGE_M: f64 = 600_000.0;
/// Coverage cells: H3 resolution 5, about 250 km² each.
pub const COVERAGE_RESOLUTION: Resolution = Resolution::Five;
/// Feeders each leaderboard lists.
pub const BOARD_LENGTH: usize = 20;
/// Receivers held.
pub const MAX_FEEDERS: usize = 8_192;
/// Aircraft and coverage cells held per receiver, each.
pub const MAX_PER_FEEDER: usize = 16_384;
/// Aircraft held for coverage (their unsettled seconds).
pub const MAX_AIRCRAFT: usize = 16_384;
/// Observation sets remembered, so a position many relays publish is counted once.
pub const MAX_CITED: usize = 262_144;
/// The mean Earth radius, metres (IUGG).
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// One hour of a receiver's counts.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Hour {
    messages: u64,
    range_m: Option<f64>,
}

/// One half of a CPR pair: its fields and when it was heard.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Half {
    lat: u32,
    lon: u32,
    at_ms: u64,
}

#[derive(Debug, Default)]
struct Feeder {
    /// Minutes (Unix minutes) with a batch.
    minutes: BTreeSet<u64>,
    /// Counts by Unix hour.
    hours: BTreeMap<u64, Hour>,
    /// Aircraft heard, and when last.
    aircraft: HashMap<u32, u64>,
    /// Coverage cells heard in, and when last.
    cells: HashMap<u64, u64>,
    /// Each aircraft's latest even and odd airborne position.
    cpr: HashMap<u32, [Option<Half>; 2]>,
}

impl Feeder {
    fn hour(&mut self, at_ms: u64) -> &mut Hour {
        self.hours.entry(at_ms / HOUR_MS).or_default()
    }

    /// A new airborne position: the aircraft's position when it completes a pair.
    fn pair(
        &mut self,
        address: u32,
        position: modes::AirbornePosition,
        at_ms: u64,
    ) -> Option<LatLon> {
        if !self.cpr.contains_key(&address) && self.cpr.len() >= MAX_PER_FEEDER {
            return None;
        }
        let halves = self.cpr.entry(address).or_default();
        let this = Half {
            lat: position.lat_cpr,
            lon: position.lon_cpr,
            at_ms,
        };
        let other = halves[usize::from(!position.odd)];
        halves[usize::from(position.odd)] = Some(this);
        let other = other.filter(|other| at_ms.abs_diff(other.at_ms) <= PAIR_WITHIN_MS)?;
        let (even, odd) = if position.odd {
            (other, this)
        } else {
            (this, other)
        };
        let decoded = modes::cpr_global((even.lat, even.lon), (odd.lat, odd.lon), position.odd)?;
        Some(LatLon {
            lat: decoded.lat_deg,
            lon: decoded.lon_deg,
        })
    }

    fn is_empty(&self) -> bool {
        self.minutes.is_empty()
            && self.hours.is_empty()
            && self.aircraft.is_empty()
            && self.cells.is_empty()
    }
}

/// A place, degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

impl LatLon {
    /// The order a second's positions are chosen by: least latitude, then least longitude.
    fn least(self, other: Self) -> Self {
        match self
            .lat
            .total_cmp(&other.lat)
            .then(self.lon.total_cmp(&other.lon))
        {
            std::cmp::Ordering::Greater => other,
            _ => self,
        }
    }

    fn cell(self, resolution: Resolution) -> Option<CellIndex> {
        LatLng::new(self.lat, self.lon)
            .ok()
            .map(|place| place.to_cell(resolution))
    }

    /// Great-circle distance, metres.
    fn distance_m(self, other: Self) -> f64 {
        let (a, b) = (self.lat.to_radians(), other.lat.to_radians());
        let dlat = b - a;
        let dlon = (other.lon - self.lon).to_radians();
        let h = (dlat / 2.0).sin().powi(2) + a.cos() * b.cos() * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_M * h.sqrt().min(1.0).asin()
    }
}

/// One second of one aircraft: where it was, and who heard it.
#[derive(Debug, Default)]
struct Second {
    position: Option<LatLon>,
    receivers: BTreeSet<PublicKey>,
}

/// Everything the figures are computed from.
pub struct Ledger {
    /// When the first counted record was stamped: the window never reaches before it.
    observed_since_ms: Option<u64>,
    feeders: Bounded<PublicKey, Feeder>,
    /// MLAT help by receiver, by Unix hour: kept apart from the rows (which only a receiver's own
    /// batches make), so a position credited before the receiver's batch arrived counts the same
    /// as one after. Only a receiver the merge holds raw of is ever credited (`Verdict::heard`).
    mlat: Bounded<PublicKey, BTreeMap<u64, u64>>,
    aircraft: Bounded<u32, BTreeMap<u64, Second>>,
    cited: Bounded<Hash, ()>,
    /// Every second up to and including this one is settled.
    settled_through: u64,
    /// Where each receiver says it is.
    locations: HashMap<PublicKey, LatLon>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            observed_since_ms: None,
            feeders: Bounded::new(MAX_FEEDERS),
            mlat: Bounded::new(MAX_FEEDERS),
            aircraft: Bounded::new(MAX_AIRCRAFT),
            cited: Bounded::new(MAX_CITED),
            settled_through: 0,
            locations: HashMap::new(),
        }
    }
}

/// What the MLAT merge decided, as the figures need it (implemented by `tally_merge::Merge` in
/// `crate::mlat`): the only way a final position counts.
pub trait Verdict {
    /// Whether the merge accepted `solution`: it holds it as a final fix of its aircraft.
    fn accepted(&self, solution: &Solution) -> bool;
    /// Whether `reception`, of `message` transmitted at `transmitted_ms`, is in its receiver's own
    /// signed raw, as the merge holds it.
    fn heard(&self, reception: &Reception, message: &[u8], transmitted_ms: u64) -> bool;
}

/// The address a message proves by its CRC: DF11, DF17 and DF18 only.
fn checked_address(message: &[u8]) -> Option<u32> {
    let df = modes::downlink_format(message)?;
    matches!(df, 11 | 17 | 18)
        .then(|| modes::address(message))
        .flatten()
}

impl Ledger {
    /// Where each receiver says it is, as the relay's station reports carry it from the
    /// receiver's own signed description; replaces what was held.
    pub fn locate(&mut self, locations: impl IntoIterator<Item = (PublicKey, LatLon)>) {
        self.locations = locations.into_iter().collect();
    }

    /// One record a relay delivered, at `now_ms` on the API's clock, once the merge has taken it:
    /// `verdict` is what the merge decided of a final position and the raw it holds.
    pub fn ingest(&mut self, record: &Record, now_ms: u64, verdict: &impl Verdict) {
        match record {
            Record::Batch(batch) => self.batch(batch, now_ms),
            Record::Positions(positions) if !positions.is_provisional() => {
                self.positions(positions, now_ms, verdict);
            }
            _ => {}
        }
    }

    fn observed(&mut self, at_ms: u64) {
        let since = self.observed_since_ms.get_or_insert(at_ms);
        *since = (*since).min(at_ms);
    }

    /// The receiver's row for a batch it signed: written if it is new, and marked active. The only
    /// way a row is made.
    fn feeder(&mut self, key: PublicKey) -> Option<&mut Feeder> {
        if self.feeders.get(&key).is_none() {
            self.feeders.insert_active(key, Feeder::default());
        } else {
            self.feeders.touch(&key);
        }
        self.feeders.get_mut(&key)
    }

    fn batch(&mut self, batch: &Batch, now_ms: u64) {
        let (Ok(()), Ok(receiver), Ok(content)) =
            (batch.verify(), batch.receiver(), batch.content())
        else {
            return;
        };
        let at = content.wall_ms;
        if at.abs_diff(now_ms) > FRESH_WITHIN_MS {
            return;
        }
        self.observed(at);
        let Some(feeder) = self.feeder(receiver) else {
            return;
        };
        feeder.minutes.insert(at / MINUTE_MS);
        feeder.hour(at).messages += content.observations.len() as u64;
        let mut heard = Vec::new();
        let mut placed = Vec::new();
        for observation in &content.observations {
            let Some(address) = checked_address(&observation.data) else {
                continue;
            };
            if feeder.aircraft.contains_key(&address) || feeder.aircraft.len() < MAX_PER_FEEDER {
                feeder.aircraft.insert(address, at);
            }
            heard.push(address);
            if let Some(airborne) = modes::airborne_position(&observation.data)
                && let Some(place) = feeder.pair(address, airborne, at)
            {
                placed.push((address, place));
            }
        }
        let second = at / 1000;
        for address in heard {
            self.heard(address, second, receiver);
        }
        for (address, place) in placed {
            self.placed(address, second, place);
        }
    }

    fn positions(&mut self, positions: &Positions, now_ms: u64, verdict: &impl Verdict) {
        let (Ok(()), Ok(content)) = (positions.verify(), positions.solutions()) else {
            return;
        };
        for solution in content.solutions {
            let at = solution.transmitted.unix_ms;
            if at.abs_diff(now_ms) > FRESH_WITHIN_MS || !verdict.accepted(&solution) {
                continue;
            }
            self.observed(at);
            let set = solution.observations.hash();
            let new = self.cited.get(&set).is_none();
            if new {
                self.cited.insert(set, ());
            }
            let second = at / 1000;
            self.placed(
                solution.address,
                second,
                LatLon {
                    lat: f64::from(solution.lat_e7) / 1e7,
                    lon: f64::from(solution.lon_e7) / 1e7,
                },
            );
            // Only a reception the receiver's own signed raw holds credits it, and only a row
            // its own batches made.
            let message = solution.observations.message();
            let receivers: BTreeSet<PublicKey> = solution
                .observations
                .receptions()
                .iter()
                .filter(|reception| verdict.heard(reception, message, at))
                .map(|reception| reception.receiver)
                .collect();
            for receiver in receivers {
                self.heard(solution.address, second, receiver);
                if new {
                    if self.mlat.get(&receiver).is_none() {
                        self.mlat.insert_active(receiver, BTreeMap::new());
                    } else {
                        self.mlat.touch(&receiver);
                    }
                    if let Some(hours) = self.mlat.get_mut(&receiver) {
                        *hours.entry(at / HOUR_MS).or_default() += 1;
                    }
                }
            }
        }
    }

    fn second(&mut self, address: u32, second: u64) -> Option<&mut Second> {
        if second <= self.settled_through {
            return None;
        }
        if self.aircraft.get(&address).is_none() {
            self.aircraft.insert(address, BTreeMap::new());
        }
        Some(self.aircraft.get_mut(&address)?.entry(second).or_default())
    }

    fn heard(&mut self, address: u32, second: u64, receiver: PublicKey) {
        if let Some(held) = self.second(address, second) {
            held.receivers.insert(receiver);
        }
    }

    fn placed(&mut self, address: u32, second: u64, place: LatLon) {
        if let Some(held) = self.second(address, second) {
            held.position = Some(held.position.map_or(place, |was| was.least(place)));
        }
    }

    /// Credits every second ended `SETTLE_SECS` before `now_ms`.
    pub fn settle(&mut self, now_ms: u64) {
        let cutoff = (now_ms / 1000).saturating_sub(SETTLE_SECS);
        if cutoff <= self.settled_through {
            return;
        }
        let mut credits = Vec::new();
        let addresses: Vec<u32> = self.aircraft.iter().map(|(address, _)| *address).collect();
        for address in addresses {
            let Some(seconds) = self.aircraft.get_mut(&address) else {
                continue;
            };
            for (&at, second) in seconds.range(self.settled_through + 1..=cutoff) {
                if let Some(place) = nearest(seconds, at) {
                    credits.extend(second.receivers.iter().map(|key| (*key, at, place)));
                }
            }
            // The newest settled seconds stay, as the neighbours of the next to settle.
            seconds.retain(|at, _| *at + NEAR_SECS > cutoff);
            if seconds.is_empty() {
                self.aircraft.remove(&address);
            }
        }
        self.settled_through = cutoff;
        for (key, second, place) in credits {
            let at_ms = second * 1000;
            let from = self.locations.get(&key).copied();
            let Some(feeder) = self.feeders.get_mut(&key) else {
                continue;
            };
            if let Some(from) = from {
                let range = from.distance_m(place);
                if range > MAX_RANGE_M {
                    continue;
                }
                let hour = feeder.hour(at_ms);
                hour.range_m = Some(hour.range_m.map_or(range, |was| was.max(range)));
            }
            if let Some(cell) = place.cell(COVERAGE_RESOLUTION) {
                let cell = u64::from(cell);
                if feeder.cells.contains_key(&cell) || feeder.cells.len() < MAX_PER_FEEDER {
                    let last = feeder.cells.entry(cell).or_insert(at_ms);
                    *last = (*last).max(at_ms);
                }
            }
        }
    }

    /// Forgets what is older than the window and pairs too old to complete.
    fn prune(&mut self, now_ms: u64) {
        let start = window_start_ms(now_ms);
        let keys: Vec<PublicKey> = self.feeders.iter().map(|(key, _)| *key).collect();
        for key in keys {
            let Some(feeder) = self.feeders.get_mut(&key) else {
                continue;
            };
            feeder.minutes.retain(|minute| *minute >= start / MINUTE_MS);
            feeder.hours.retain(|hour, _| *hour >= start / HOUR_MS);
            feeder.aircraft.retain(|_, last| *last >= start);
            feeder.cells.retain(|_, last| *last >= start);
            feeder.cpr.retain(|_, halves| {
                halves
                    .iter()
                    .flatten()
                    .any(|half| half.at_ms + PAIR_WITHIN_MS >= now_ms)
            });
            if feeder.is_empty() {
                self.feeders.remove(&key);
            }
        }
        let keys: Vec<PublicKey> = self.mlat.iter().map(|(key, _)| *key).collect();
        for key in keys {
            if let Some(hours) = self.mlat.get_mut(&key) {
                hours.retain(|hour, _| *hour >= start / HOUR_MS);
                if hours.is_empty() {
                    self.mlat.remove(&key);
                }
            }
        }
    }

    /// Settles, forgets what the window has passed, and computes every figure and board as of
    /// `now_ms`. `has_standing` says which receivers the merge's ledger gives standing.
    pub fn board(&mut self, now_ms: u64, has_standing: impl Fn(&PublicKey) -> bool) -> Board {
        self.settle(now_ms);
        self.prune(now_ms);
        let since = window_start_ms(now_ms).max(self.observed_since_ms.unwrap_or(now_ms));
        let window_for_ms = now_ms.saturating_sub(since);
        let mut heard_by: HashMap<u64, u32> = HashMap::new();
        for (_, feeder) in self.feeders.iter() {
            for cell in feeder.cells.keys() {
                *heard_by.entry(*cell).or_default() += 1;
            }
        }
        let minutes = window_for_ms.div_ceil(MINUTE_MS).max(1);
        let mut feeders: BTreeMap<PublicKey, FeederStats> = BTreeMap::new();
        for (key, feeder) in self.feeders.iter() {
            let active = feeder.minutes.range(since / MINUTE_MS..).count() as u64;
            let messages: u64 = feeder.hours.values().map(|hour| hour.messages).sum();
            let mlat_positions: u64 = self.mlat.get(key).map_or(0, |hours| hours.values().sum());
            let range_m = feeder
                .hours
                .values()
                .filter_map(|hour| hour.range_m)
                .reduce(f64::max)
                .map(|metres| metres.round());
            // Summed in cell order, so the same cells always sum to the same double.
            let mut cells: Vec<u64> = feeder.cells.keys().copied().collect();
            cells.sort_unstable();
            let (mut coverage, mut unique) = (0.0, 0.0);
            for cell in cells {
                let area = CellIndex::try_from(cell).map_or(0.0, CellIndex::area_km2);
                coverage += area;
                if heard_by.get(&cell) == Some(&1) {
                    unique += area;
                }
            }
            let area = self.locations.get(key).and_then(|place| area_name(*place));
            let seconds = window_for_ms as f64 / 1000.0;
            feeders.insert(
                *key,
                FeederStats {
                    now_ms,
                    key: key.to_base64(),
                    window_for_ms,
                    uptime: (active as f64 / minutes as f64).min(1.0),
                    messages,
                    messages_per_sec: if seconds > 0.0 {
                        messages as f64 / seconds
                    } else {
                        0.0
                    },
                    aircraft: u32::try_from(feeder.aircraft.len()).unwrap_or(u32::MAX),
                    range_m,
                    coverage_km2: tenths(coverage),
                    unique_coverage_km2: tenths(unique),
                    mlat_positions,
                    area,
                    standing: has_standing(key),
                    ranks: None,
                },
            );
        }
        rank(now_ms, window_for_ms, feeders)
    }
}

/// The start of the window at `now_ms`: the start of the hour `WINDOW_HOURS - 1` before this one.
fn window_start_ms(now_ms: u64) -> u64 {
    (now_ms / HOUR_MS).saturating_sub(WINDOW_HOURS - 1) * HOUR_MS
}

fn tenths(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

/// The position nearest `at` within `NEAR_SECS`: `at` first, then earlier before later.
fn nearest(seconds: &BTreeMap<u64, Second>, at: u64) -> Option<LatLon> {
    std::iter::once(at)
        .chain(
            (1..=NEAR_SECS).flat_map(|d| [at.checked_sub(d), Some(at + d)].into_iter().flatten()),
        )
        .find_map(|second| seconds.get(&second)?.position)
}

/// Every figure and board, as of one instant.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Board {
    pub now_ms: u64,
    pub window_for_ms: u64,
    feeders: BTreeMap<PublicKey, FeederStats>,
    areas: BTreeMap<String, Leaderboard>,
    index: Vec<LeaderboardArea>,
}

impl Board {
    pub fn feeder(&self, key: &PublicKey) -> Option<FeederStats> {
        self.feeders.get(key).cloned()
    }

    pub fn leaderboards(&self) -> Leaderboards {
        Leaderboards {
            now_ms: self.now_ms,
            window_for_ms: self.window_for_ms,
            areas: self.index.clone(),
        }
    }

    /// One area's boards, `None` when it ranks no one.
    pub fn leaderboard(&self, area: &CellIndex) -> Option<Leaderboard> {
        self.areas.get(&area.to_string()).cloned()
    }
}

/// An area named in a path: an H3 cell at the network's area resolution, as hex.
pub fn parse_area(text: &str) -> Option<CellIndex> {
    text.parse::<CellIndex>()
        .ok()
        .filter(|cell| u8::from(cell.resolution()) == AREA_RESOLUTION)
}

/// The area a place is in, as a board names it: the network's own (`area_at`), as hex.
pub fn area_name(place: LatLon) -> Option<String> {
    area_at(place.lat, place.lon)
        .ok()
        .map(|area| format!("{:x}", area.as_u64()))
}

fn by_unique(a: &FeederStats, b: &FeederStats) -> std::cmp::Ordering {
    b.unique_coverage_km2
        .total_cmp(&a.unique_coverage_km2)
        .then(b.mlat_positions.cmp(&a.mlat_positions))
        .then(a.key.cmp(&b.key))
}

fn by_mlat(a: &FeederStats, b: &FeederStats) -> std::cmp::Ordering {
    b.mlat_positions
        .cmp(&a.mlat_positions)
        .then(b.unique_coverage_km2.total_cmp(&a.unique_coverage_km2))
        .then(a.key.cmp(&b.key))
}

fn entry(rank: usize, stats: &FeederStats) -> LeaderboardEntry {
    LeaderboardEntry {
        rank: u32::try_from(rank + 1).unwrap_or(u32::MAX),
        key: stats.key.clone(),
        unique_coverage_km2: stats.unique_coverage_km2,
        mlat_positions: stats.mlat_positions,
    }
}

/// Ranks every feeder with standing and an area within its area, and builds the boards.
fn rank(now_ms: u64, window_for_ms: u64, mut feeders: BTreeMap<PublicKey, FeederStats>) -> Board {
    let mut by_area: BTreeMap<String, Vec<PublicKey>> = BTreeMap::new();
    for (key, stats) in &feeders {
        if let (true, Some(area)) = (stats.standing, &stats.area) {
            by_area.entry(area.clone()).or_default().push(*key);
        }
    }
    let mut areas = BTreeMap::new();
    let mut index = Vec::new();
    for (area, keys) in by_area {
        let mut ranked: Vec<FeederStats> = keys
            .iter()
            .filter_map(|key| feeders.get(key).cloned())
            .collect();
        let of = u32::try_from(ranked.len()).unwrap_or(u32::MAX);
        ranked.sort_by(by_unique);
        let by_unique_coverage: Vec<LeaderboardEntry> = ranked
            .iter()
            .enumerate()
            .map(|(n, s)| entry(n, s))
            .collect();
        ranked.sort_by(by_mlat);
        let by_mlat: Vec<LeaderboardEntry> = ranked
            .iter()
            .enumerate()
            .map(|(n, s)| entry(n, s))
            .collect();
        for (key, stats) in &mut feeders {
            if stats.area.as_ref() != Some(&area) || !stats.standing {
                continue;
            }
            let place = |board: &[LeaderboardEntry]| {
                board
                    .iter()
                    .find(|entry| entry.key == key.to_base64())
                    .map_or(0, |entry| entry.rank)
            };
            stats.ranks = Some(Ranks {
                unique_coverage: place(&by_unique_coverage),
                mlat: place(&by_mlat),
                of,
            });
        }
        let Some(center) = parse_area(&area).map(|cell| {
            let centre = LatLng::from(cell);
            Position {
                lat: micro_degrees(centre.lat()),
                lon: micro_degrees(centre.lng()),
            }
        }) else {
            continue;
        };
        index.push(LeaderboardArea {
            area: area.clone(),
            center,
            ranked: of,
        });
        areas.insert(
            area.clone(),
            Leaderboard {
                now_ms,
                window_for_ms,
                area,
                center,
                ranked: of,
                by_unique_coverage: by_unique_coverage.into_iter().take(BOARD_LENGTH).collect(),
                by_mlat: by_mlat.into_iter().take(BOARD_LENGTH).collect(),
            },
        );
    }
    index.sort_by(|a, b| b.ranked.cmp(&a.ranked).then(a.area.cmp(&b.area)));
    Board {
        now_ms,
        window_for_ms,
        feeders,
        areas,
        index,
    }
}

/// Degrees to six places: a cell's centre, written in as few digits as it needs.
fn micro_degrees(degrees: f64) -> f64 {
    (degrees * 1e6).round() / 1e6
}

#[cfg(test)]
pub(crate) mod tests;
