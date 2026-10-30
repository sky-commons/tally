//! FEEDER FIGURES (RFC-0174 §2.12, as amended 2026-10-19): what this relay computes of the
//! receivers it hosts or carries, signed as its own claim (`tally_wire::FeederFigures`) and sent
//! on client links like any other product, for any client (the API among them) to read and serve.
//!
//! Only a relay holds what the figures are computed from: receivers' raw batches and the raw
//! positions citing their receptions are relay-only (wire version 3). So a relay computes them,
//! and no client is special: each reads the same signed records. What a record says carries no
//! site: each receiver's public cell, counts, coverage in square kilometres of cells
//! (`COVERAGE_RESOLUTION`, coarser than the public cell), and a range from the public cell's
//! centre, never from the site (module `tally_wire::figures`).
//!
//! Over the window (the 24 whole hours before the hour now, `WINDOW_HOURS`), per receiver, each
//! counted in whole-hour buckets and published once an hour (`PUBLISH_EVERY_MS`) as of the hour's
//! start: the finest series a client can difference out of two records is an hour's, never a
//! minute's (`tally_wire::FIGURES_BUCKET_MS`, which the wire holds every record to):
//!
//! - **uptime**: the share of the window's minutes in which a batch of it was forwarded here, by
//!   the batch's own signed wall clock (one outside `tally_wire::budget::Window::FIGURES` by the
//!   relay's one clock, `Hub::now_ms`, is not counted, so no history is signed after the fact);
//! - **messages**: receptions in its batches;
//! - **aircraft**: distinct addresses it heard in a checked format (DF11, DF17, DF18: the CRC
//!   proves the address);
//! - **range**: the farthest positioned aircraft it heard, from its public cell's centre (no
//!   further than `MAX_RANGE_M`);
//! - **coverage** and **unique coverage**: the coverage cells holding an aircraft when it heard
//!   it, and those of them no other receiver this relay holds heard;
//! - **MLAT help**: distinct MLAT fixes (by the receptions they used) using one of its receptions,
//!   counted only for an aircraft its own batches here heard;
//! - **standing**: from this relay's own ledger (`standing`).
//!
//! An aircraft is placed by a global CPR decode of an even and an odd airborne position one
//! receiver heard within `PAIR_WITHIN_MS`, or by an MLAT fix; a receiver that hears it
//! within `NEAR_MS` of where it was last placed is credited that place.
//!
//! Memory is charged: a receiver's row is made only by a batch of its own, and only when the
//! budget's `Store::Figures` takes its fixed charge (`PER_RECEIVER_BYTES`, everything a row may
//! grow to, its share of the aircraft placed and of the positions remembered included). Past it a
//! receiver has no row, counted (`refused`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use h3o::{CellIndex, LatLng, Resolution};
use tally_mlat_solver::modes;
use tally_wire::Signs;
use tally_wire::batch::Hash;
use tally_wire::clocks::Judged;
use tally_wire::{
    Decoded, FeederFigure, FeederFigures, FeederFiguresContent, MAX_FEEDER_FIGURES, Positions,
    PublicKey, Region,
};

use crate::bounded::Bounded;
use crate::budget::{Charge, Gauge, Store};
use crate::exchange::{SHARDS, raw_shard};

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = tally_wire::FIGURES_BUCKET_MS;
/// The window every figure covers: the whole hours before the hour now, this many in all.
pub const WINDOW_HOURS: u64 = tally_wire::FIGURES_WINDOW_MS / HOUR_MS;
/// How far apart a reception and the aircraft's last placing may be for the reception to place
/// it.
pub const NEAR_MS: u64 = 2_000;
/// How close in time an even and an odd airborne position must be to decode globally.
pub const PAIR_WITHIN_MS: u64 = 10_000;
/// Beyond this from a receiver's public cell's centre, a position it is credited with is not its
/// own: past the radio horizon of an aircraft at 45,000 ft and an antenna on a tall mast, plus
/// the public cell's own reach.
pub const MAX_RANGE_M: f64 = 610_000.0;
/// Coverage cells: H3 resolution 5, about 250 km² each, coarser than the public cell.
pub const COVERAGE_RESOLUTION: Resolution = Resolution::Five;
/// Aircraft, coverage cells and CPR halves held per receiver, each.
pub const MAX_PER_FEEDER: usize = 512;
/// Aircraft placings and positions remembered, per receiver with a row: what a row's charge
/// covers of the two tables every row shares.
pub const SHARED_PER_FEEDER: usize = 64;
/// What one receiver's row may hold at most, its share of the shared tables included: the
/// minutes of the window and the hour after it, its hours, its aircraft, cells and CPR halves at
/// their caps (each table at the capacity its cap grows it to). Measured, not estimated: the
/// `figures_bytes` test fills a row to every cap under a counting allocator and holds it within
/// this (about 145 KiB; it was 96 KiB, under what a full row allocates). What each row is charged.
pub const ROW_BYTES: usize = 160 * 1024;
/// What one receiver costs the store at most: its row ([`ROW_BYTES`]) and its slot in its shard's
/// table of rows, which is charged what it allocates as it grows and is kept within four times
/// the rows it holds (`footprint::table_per_entry`).
pub const PER_RECEIVER_BYTES: usize =
    ROW_BYTES + crate::footprint::table_per_entry::<PublicKey, Feeder>(ROWS_KEPT_WITHIN);
/// A shard's table of rows is kept within this many times the rows it holds (`Table::kept`).
const ROWS_KEPT_WITHIN: usize = 4;
/// How often the figures are signed and published: once an hour, as its bucket closes.
pub const PUBLISH_EVERY_MS: u64 = HOUR_MS;
/// The mean Earth radius, metres (IUGG).
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// A place, degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

/// A place and its coverage cell (`COVERAGE_RESOLUTION`), found once where it is placed: every
/// row credited with it reads the cell. Before (2026-10-27), each credit found the cell again, and
/// an aircraft's placing credits every row that heard it: H3's cell was a sixth of the ingest
/// workers' time at 2,000 feeders.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Placed {
    place: LatLon,
    cell: Option<u64>,
}

impl Placed {
    fn at(place: LatLon) -> Self {
        Self {
            place,
            cell: place.cell(COVERAGE_RESOLUTION).map(u64::from),
        }
    }
}

impl LatLon {
    fn cell(self, resolution: Resolution) -> Option<CellIndex> {
        LatLng::new(self.lat, self.lon)
            .ok()
            .map(|place| place.to_cell(resolution))
    }

    /// Great-circle distance, metres.
    pub fn distance_m(self, other: Self) -> f64 {
        let (a, b) = (self.lat.to_radians(), other.lat.to_radians());
        let dlat = b - a;
        let dlon = (other.lon - self.lon).to_radians();
        let h = (dlat / 2.0).sin().powi(2) + a.cos() * b.cos() * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_M * h.sqrt().min(1.0).asin()
    }

    /// The centre of a cell.
    pub fn centre_of(cell: Region) -> Option<Self> {
        let centre = LatLng::from(CellIndex::try_from(cell.as_u64()).ok()?);
        Some(Self {
            lat: centre.lat(),
            lon: centre.lng(),
        })
    }
}

/// One half of a CPR pair: its fields and when it was heard.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Half {
    lat: u32,
    lon: u32,
    at_ms: u64,
}

/// One hour of a receiver's counts.
/// When something was last heard, and the latest whole hour it was heard in before that one: all
/// a window of whole hours ending at the hour now needs to know whether it was heard in it,
/// whether or not it was heard again since the hour began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Heard {
    last_ms: u64,
    /// The latest Unix hour heard in before `last_ms`'s, 0 for none.
    before_hour: u32,
}

impl Heard {
    fn at(at_ms: u64) -> Self {
        Self {
            last_ms: at_ms,
            before_hour: 0,
        }
    }

    fn heard(&mut self, at_ms: u64) {
        let (hour, last) = (at_ms / HOUR_MS, self.last_ms / HOUR_MS);
        let as_u32 = |hour: u64| u32::try_from(hour).unwrap_or(u32::MAX);
        if hour > last {
            self.before_hour = as_u32(last);
            self.last_ms = at_ms;
        } else if hour == last {
            self.last_ms = self.last_ms.max(at_ms);
        } else {
            self.before_hour = self.before_hour.max(as_u32(hour));
        }
    }

    /// Whether it was heard in an hour from `since_hour` up to `end_hour`, `end_hour` the hour
    /// now: none after it has passed.
    fn within(&self, since_hour: u64, end_hour: u64) -> bool {
        let last = self.last_ms / HOUR_MS;
        let hour = if last < end_hour {
            last
        } else {
            u64::from(self.before_hour)
        };
        hour != 0 && hour >= since_hour && hour < end_hour
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Hour {
    messages: u64,
    range_m: Option<f64>,
    mlat: u64,
}

/// One shard's rows, and what its table allocates, charged to the store as it grows
/// (`footprint::Table`): read as the map it is; a row is made only by [`Rows::make`].
#[derive(Default)]
struct Rows {
    map: HashMap<PublicKey, Feeder>,
    table: crate::footprint::Table,
    charge: Charge,
}

impl std::ops::Deref for Rows {
    type Target = HashMap<PublicKey, Feeder>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl Rows {
    fn get_mut(&mut self, receiver: &PublicKey) -> Option<&mut Feeder> {
        self.map.get_mut(receiver)
    }

    /// `receiver`'s row, made with `charge` if the store has room for what the table grows by;
    /// false when it has none.
    fn make(&mut self, receiver: PublicKey, row: Feeder) -> bool {
        let growth = self
            .table
            .growth::<PublicKey, Feeder>(self.map.len(), self.map.capacity());
        if !self.charge.try_grow(growth) {
            return false;
        }
        self.map.insert(receiver, row);
        self.table.inserted(self.map.capacity());
        self.charge
            .shrink_to(self.table.bytes::<PublicKey, Feeder>());
        true
    }

    /// `emptied`'s rows let go, the table kept within four times the rows left and its charge
    /// brought down to what it allocates.
    fn let_go(&mut self, emptied: &[PublicKey]) -> usize {
        let before = self.map.len();
        for key in emptied {
            self.map.remove(key);
        }
        self.table.kept(&mut self.map, ROWS_KEPT_WITHIN);
        self.charge
            .shrink_to(self.table.bytes::<PublicKey, Feeder>());
        before - self.map.len()
    }
}

/// One receiver's row: made only by a batch of its own, charged for all it may grow to.
struct Feeder {
    _charge: Charge,
    /// Its public cell, as its description names it (`set_public`).
    public: Option<Region>,
    /// The centre of `public`, found once when it is set: each credited position's range is from
    /// it. Before (2026-10-27), found again for every position, a fifth of `credit`.
    centre: Option<LatLon>,
    /// Minutes (Unix minutes) with a batch.
    minutes: BTreeSet<u64>,
    /// Counts by Unix hour.
    hours: BTreeMap<u64, Hour>,
    /// Aircraft heard, and in which hours last.
    aircraft: HashMap<u32, Heard>,
    /// Coverage cells heard in, and in which hours last.
    cells: HashMap<u64, Heard>,
    /// Each aircraft's latest even and odd airborne position.
    cpr: HashMap<u32, [Option<Half>; 2]>,
}

impl Feeder {
    /// Its public cell, and the centre its ranges are from.
    fn set_public(&mut self, public: Option<Region>) {
        if public != self.public {
            self.public = public;
            self.centre = public.and_then(LatLon::centre_of);
        }
    }

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

    /// An aircraft placed at `place` when it heard it, at `at_ms`: its coverage cell, and its range
    /// from the public cell's centre.
    fn credit(&mut self, placed: Placed, at_ms: u64) {
        let Placed { place, cell } = placed;
        if let Some(centre) = self.centre {
            let range = centre.distance_m(place);
            if range > MAX_RANGE_M {
                return;
            }
            let hour = self.hour(at_ms);
            hour.range_m = Some(hour.range_m.map_or(range, |was| was.max(range)));
        }
        if let Some(cell) = cell
            && (self.cells.contains_key(&cell) || self.cells.len() < MAX_PER_FEEDER)
        {
            self.cells
                .entry(cell)
                .and_modify(|heard| heard.heard(at_ms))
                .or_insert(Heard::at(at_ms));
        }
    }

    /// Forgets what is older than the window, and pairs too old to complete.
    fn prune(&mut self, start_ms: u64, now: Judged) {
        let now_ms = now.ms();
        self.minutes
            .retain(|minute| *minute >= start_ms / MINUTE_MS);
        self.hours.retain(|hour, _| *hour >= start_ms / HOUR_MS);
        self.aircraft.retain(|_, heard| heard.last_ms >= start_ms);
        self.cells.retain(|_, heard| heard.last_ms >= start_ms);
        self.cpr.retain(|_, halves| {
            halves
                .iter()
                .flatten()
                .any(|half| half.at_ms + PAIR_WITHIN_MS >= now_ms)
        });
    }
}

/// The address a message proves by its CRC: DF11, DF17 and DF18 only.
fn checked_address(message: &[u8]) -> Option<u32> {
    let df = modes::downlink_format(message)?;
    matches!(df, 11 | 17 | 18)
        .then(|| modes::address(message))
        .flatten()
}

/// What every row shares: where each aircraft was last placed, and the positions already
/// counted (so one many relays carry counts once).
struct Shared {
    placed: Bounded<u32, (Placed, u64)>,
    cited: Bounded<Hash, ()>,
}

/// Every area's figures, keyed by the area's index (0 for the record of no area).
pub type Areas = BTreeMap<u64, (Option<Region>, Vec<FeederFigure>)>;

/// One receiver's sums for a window, before its coverage is weighed against every other's.
struct Row {
    key: PublicKey,
    public: Option<Region>,
    active: u64,
    messages: u64,
    aircraft: u32,
    range: Option<f64>,
    mlat: u64,
    cells: Vec<u64>,
}

/// Everything the figures are computed from, sharded by receiver as the raw is
/// (`exchange::raw_shard`): a batch takes only its receiver's shard.
pub struct Figures {
    shards: Box<[Mutex<Rows>]>,
    shared: Mutex<Shared>,
    /// Rows held, every shard's: what the shared tables are held to (`SHARED_PER_FEEDER` each).
    rows: AtomicUsize,
    gauge: Mutex<Arc<Gauge>>,
    /// When the first counted record was stamped: the window never reaches before it.
    observed_since_ms: AtomicU64,
    /// When the figures were last signed (`Figures::sign`): none yet at zero.
    published_ms: AtomicU64,
    /// How often they are signed (`PUBLISH_EVERY_MS` unless set, `publish_every`).
    every_ms: AtomicU64,
    /// What was signed last: what a client joining is sent at once, as the directory is, rather
    /// than waiting for the next signing (`Hub::client_infos`). At most one record per area of the
    /// receivers this relay holds, each bounded by the wire.
    latest: Mutex<Arc<[FeederFigures]>>,
    /// Receivers given no row: the store was full.
    refused: AtomicU64,
}

impl Default for Figures {
    fn default() -> Self {
        Self::new()
    }
}

impl Figures {
    pub fn new() -> Self {
        let gauge = Gauge::unlimited(Store::Figures);
        Self {
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Rows {
                        charge: gauge.empty(),
                        ..Rows::default()
                    })
                })
                .collect(),
            shared: Mutex::new(Shared {
                placed: Bounded::new(usize::MAX),
                cited: Bounded::new(usize::MAX),
            }),
            rows: AtomicUsize::new(0),
            gauge: Mutex::new(gauge),
            observed_since_ms: AtomicU64::new(u64::MAX),
            published_ms: AtomicU64::new(0),
            every_ms: AtomicU64::new(PUBLISH_EVERY_MS),
            latest: Mutex::new(Arc::from(Vec::new())),
            refused: AtomicU64::new(0),
        }
    }

    /// Signs every `every_ms` from now on, instead of `PUBLISH_EVERY_MS`.
    pub fn publish_every(&self, every_ms: u64) {
        self.every_ms.store(every_ms, Ordering::Relaxed);
    }

    /// What was signed last (`latest`).
    pub fn latest(&self) -> Arc<[FeederFigures]> {
        self.latest
            .lock()
            .map(|latest| Arc::clone(&latest))
            .unwrap_or_else(|_| Arc::from(Vec::new()))
    }

    /// Rows are charged to `gauge` (the budget's `Store::Figures`) from now on, and the shards'
    /// tables moved there (made before any row, so they hold nothing yet).
    pub fn charge_to(&self, gauge: Arc<Gauge>) {
        for shard in self.shards.iter() {
            if let Ok(mut rows) = shard.lock() {
                let mut moved = gauge.empty();
                if moved.try_grow(rows.charge.bytes()) {
                    rows.charge = moved;
                }
            }
        }
        if let Ok(mut held) = self.gauge.lock() {
            *held = gauge;
        }
    }

    /// Receivers given no row because the store was full.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Receivers with a row now.
    pub fn rows(&self) -> usize {
        self.rows.load(Ordering::Relaxed)
    }

    /// What the rows and their tables are charged, counted afresh: each row's [`ROW_BYTES`] and
    /// what each table's buckets allocate, every table within its plan for the rows it holds.
    #[cfg(test)]
    fn counted(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.lock().ok())
            .map(|rows| {
                let table = rows.table.bytes::<PublicKey, Feeder>();
                assert!(rows.map.capacity() <= crate::footprint::capacity_of(rows.table.buckets()));
                assert!(table <= rows.map.len() * (PER_RECEIVER_BYTES - ROW_BYTES));
                rows.map.len() * ROW_BYTES + table
            })
            .sum()
    }

    fn shard(&self, receiver: &PublicKey) -> &Mutex<Rows> {
        &self.shards[usize::from(raw_shard(receiver).0) % self.shards.len()]
    }

    fn observed(&self, at_ms: u64) {
        self.observed_since_ms.fetch_min(at_ms, Ordering::Relaxed);
    }

    /// A receiver's description, kept by the hub: its public cell, for its row's range.
    pub fn described(&self, receiver: &PublicKey, public: Option<Region>) {
        if let Ok(mut shard) = self.shard(receiver).lock()
            && let Some(feeder) = shard.get_mut(receiver)
        {
            feeder.set_public(public);
        }
    }

    /// A batch the hub forwarded, decoded once, of a receiver whose public cell is `public`, at
    /// `now_ms` by the relay's clock. Only the receptions of the products count: an
    /// ACARS-family message is none of them, and leaves the relay by `--acars-out` alone, so a
    /// batch of them is no activity, no message and no aircraft.
    pub fn batch(&self, decoded: &Decoded, public: Option<Region>, now: Judged) {
        let at = decoded.wall_ms();
        let products = || {
            decoded
                .observations()
                .iter()
                .filter(|observation| tally_wire::batch::format::in_products(observation.format))
        };
        if !tally_wire::budget::Window::FIGURES.holds(at, now) || products().next().is_none() {
            return;
        }
        let receiver = decoded.receiver();
        let mut heard = Vec::new();
        let mut placed = Vec::new();
        {
            let Ok(mut shard) = self.shard(&receiver).lock() else {
                return;
            };
            if !shard.contains_key(&receiver) {
                let gauge = self
                    .gauge
                    .lock()
                    .map(|gauge| Arc::clone(&gauge))
                    .unwrap_or_else(|_| Gauge::unlimited(Store::Figures));
                let made = gauge.try_charge(ROW_BYTES).is_some_and(|charge| {
                    shard.make(
                        receiver,
                        Feeder {
                            _charge: charge,
                            public,
                            centre: public.and_then(LatLon::centre_of),
                            minutes: BTreeSet::new(),
                            hours: BTreeMap::new(),
                            aircraft: HashMap::new(),
                            cells: HashMap::new(),
                            cpr: HashMap::new(),
                        },
                    )
                });
                if !made {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                self.rows.fetch_add(1, Ordering::Relaxed);
            }
            let Some(feeder) = shard.get_mut(&receiver) else {
                return;
            };
            feeder.set_public(public.or(feeder.public));
            feeder.minutes.insert(at / MINUTE_MS);
            feeder.hour(at).messages += products().count() as u64;
            for observation in products() {
                let data = decoded.data(observation);
                let Some(address) = checked_address(data) else {
                    continue;
                };
                if feeder.aircraft.contains_key(&address) || feeder.aircraft.len() < MAX_PER_FEEDER
                {
                    feeder
                        .aircraft
                        .entry(address)
                        .and_modify(|heard| heard.heard(at))
                        .or_insert(Heard::at(at));
                }
                if let Some(airborne) = modes::airborne_position(data)
                    && let Some(place) = feeder.pair(address, airborne, at)
                {
                    placed.push((address, place));
                } else {
                    heard.push(address);
                }
            }
        }
        self.observed(at);
        // Each placing's coverage cell: another feeder's placing of the same aircraft at the same
        // place found it already (every feeder that heard a message pair decodes it to the same
        // place), else found here, outside the lock. Before (2026-10-27), every feeder found the
        // cell of every placing, a tenth of an ingest worker's time at 2,000 feeders.
        let known: Vec<Option<Placed>> = match self.shared.lock() {
            Ok(shared) => placed
                .iter()
                .map(|(address, place)| {
                    shared
                        .placed
                        .get(address)
                        .map(|(was, _)| *was)
                        .filter(|was| was.place == *place)
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        let placed: Vec<(u32, Placed)> = placed
            .into_iter()
            .enumerate()
            .map(|(index, (address, place))| {
                let found = known.get(index).copied().flatten();
                (address, found.unwrap_or_else(|| Placed::at(place)))
            })
            .collect();
        // Where each aircraft it heard was last placed, near enough in time; its own placings
        // first, so they stand for the others too.
        let mut credits: Vec<Placed> = placed.iter().map(|(_, placed)| *placed).collect();
        if let Ok(mut shared) = self.shared.lock() {
            let room = self.rows().saturating_mul(SHARED_PER_FEEDER);
            for (address, place) in &placed {
                if shared.placed.get(address).is_some() || shared.placed.len() < room {
                    shared.placed.insert_active(*address, (*place, at));
                }
            }
            for address in heard {
                if let Some((place, when)) = shared.placed.get(&address).copied()
                    && when.abs_diff(at) <= NEAR_MS
                {
                    credits.push(place);
                }
            }
        }
        if credits.is_empty() {
            return;
        }
        if let Ok(mut shard) = self.shard(&receiver).lock()
            && let Some(feeder) = shard.get_mut(&receiver)
        {
            for place in credits {
                feeder.credit(place, at);
            }
        }
    }

    /// Positions the hub forwarded (new, verified), raw, at `now_ms` by the relay's clock: each
    /// fix places its aircraft, and credits each receiver it used that heard that aircraft here.
    pub fn positions(&self, positions: &Positions, now: Judged) {
        if positions.is_tagged() {
            return;
        }
        let Ok(content) = positions.fixes() else {
            return;
        };
        for fix in content.fixes {
            let at = fix.transmitted.unix_ms;
            if !tally_wire::budget::Window::FIGURES_POSITIONS.holds(at, now) {
                continue;
            }
            self.observed(at);
            let place = Placed::at(LatLon {
                lat: f64::from(fix.lat_e7) / 1e7,
                lon: f64::from(fix.lon_e7) / 1e7,
            });
            let new = {
                let Ok(mut shared) = self.shared.lock() else {
                    return;
                };
                let room = self.rows().saturating_mul(SHARED_PER_FEEDER);
                if shared.placed.get(&fix.address).is_some() || shared.placed.len() < room {
                    shared.placed.insert_active(fix.address, (place, at));
                }
                let set = fix.used().hash();
                let new = shared.cited.get(&set).is_none();
                if new && shared.cited.len() < room {
                    shared.cited.insert_active(set, ());
                } else if new {
                    // Full: the oldest remembered makes way.
                    let _ = shared.cited.forget_first();
                    shared.cited.insert_active(set, ());
                }
                new
            };
            let receivers: BTreeSet<PublicKey> = fix
                .used()
                .receptions()
                .iter()
                .map(|reception| reception.receiver)
                .collect();
            for receiver in receivers {
                let Ok(mut shard) = self.shard(&receiver).lock() else {
                    continue;
                };
                // Only a row its own batches made, of an aircraft its own batches heard.
                let Some(feeder) = shard.get_mut(&receiver) else {
                    continue;
                };
                if !feeder.aircraft.contains_key(&fix.address) {
                    continue;
                }
                feeder.credit(place, at);
                if new {
                    feeder.hour(at).mlat += 1;
                }
            }
        }
    }

    /// Whether the figures are due at `now_ms`: once a bucket of `PUBLISH_EVERY_MS` (or as set)
    /// has begun since they were last signed. Only signing them takes the bucket
    /// ([`Figures::sign`]), so figures due while no key could sign them (the clock stopped
    /// judging between the two) are signed at the next tick that can. Before, asking took it, and
    /// a bucket whose signing found no key was lost, uncounted.
    pub fn due(&self, now: Judged) -> bool {
        let now_ms = now.ms();
        let last = self.published_ms.load(Ordering::Relaxed);
        let every = self.every_ms.load(Ordering::Relaxed).max(1);
        last == 0 || now_ms / every > last / every
    }

    /// Every receiver's figures as of the start of the hour holding `now_ms` (`end`), over the
    /// whole hours before it, forgetting what the window has passed (and a row left empty, its
    /// charge with it): by area, each area's receivers ascending by key. What was heard since the
    /// hour began counts in the next. The window starts at the hour the relay first observed
    /// anything (uptime counted from that moment, not the hour's start). Returns the window's end,
    /// its length, and the areas.
    pub fn compute(
        &self,
        now: Judged,
        has_standing: impl Fn(&PublicKey) -> bool,
    ) -> (u64, u64, Areas) {
        let now_ms = now.ms();
        let end = now_ms / HOUR_MS * HOUR_MS;
        let start = window_start_ms(now);
        let observed = self.observed_since_ms.load(Ordering::Relaxed);
        let observed = if observed == u64::MAX { end } else { observed };
        let since = start.max(observed / HOUR_MS * HOUR_MS).min(end);
        let window_for_ms = end - since;
        let minutes = end
            .saturating_sub(start.max(observed))
            .div_ceil(MINUTE_MS)
            .max(1);
        let (since_hour, end_hour) = (since / HOUR_MS, end / HOUR_MS);
        // Each row's coverage cells, and how many rows heard in each.
        let mut rows: Vec<Row> = Vec::new();
        let mut heard_by: HashMap<u64, u32> = HashMap::new();
        for shard in self.shards.iter() {
            let Ok(mut shard) = shard.lock() else {
                continue;
            };
            let mut emptied = Vec::new();
            for (key, feeder) in shard.map.iter_mut() {
                feeder.prune(start, now);
                if feeder.minutes.is_empty() && feeder.hours.is_empty() {
                    emptied.push(*key);
                    continue;
                }
                let active = feeder
                    .minutes
                    .range(since / MINUTE_MS..end / MINUTE_MS)
                    .count() as u64;
                // Nothing of the window heard: in no record, however much since the hour began.
                if active == 0 {
                    continue;
                }
                let hours = || {
                    feeder
                        .hours
                        .range(since_hour..end_hour)
                        .map(|(_, hour)| hour)
                };
                let messages = hours().map(|hour| hour.messages).sum();
                let mlat = hours().map(|hour| hour.mlat).sum();
                let range = hours().filter_map(|hour| hour.range_m).reduce(f64::max);
                let aircraft = feeder
                    .aircraft
                    .values()
                    .filter(|heard| heard.within(since_hour, end_hour))
                    .count();
                let mut cells: Vec<u64> = feeder
                    .cells
                    .iter()
                    .filter(|(_, heard)| heard.within(since_hour, end_hour))
                    .map(|(cell, _)| *cell)
                    .collect();
                cells.sort_unstable();
                for cell in &cells {
                    *heard_by.entry(*cell).or_default() += 1;
                }
                rows.push(Row {
                    key: *key,
                    public: feeder.public,
                    active,
                    messages,
                    aircraft: u32::try_from(aircraft).unwrap_or(u32::MAX),
                    range,
                    mlat,
                    cells,
                });
            }
            let gone = shard.let_go(&emptied);
            self.rows.fetch_sub(gone, Ordering::Relaxed);
        }
        let mut areas: Areas = BTreeMap::new();
        for Row {
            key,
            public,
            active,
            messages,
            aircraft,
            range,
            mlat,
            cells,
        } in rows
        {
            // A receiver with no public cell is in the record of no area: nothing places it. One
            // whose cell has no area (none can fail to) is counted with them, unplaced.
            let area = public.and_then(tally_wire::rendezvous::area_of_public);
            let public = area.and(public);
            // Summed in cell order, so the same cells always sum to the same figure.
            let (mut coverage, mut unique) = (0.0, 0.0);
            for cell in cells {
                let size = CellIndex::try_from(cell).map_or(0.0, CellIndex::area_km2);
                coverage += size;
                if heard_by.get(&cell) == Some(&1) {
                    unique += size;
                }
            }
            let tenths = |km2: f64| u32::try_from((km2 * 10.0).round() as u64).unwrap_or(u32::MAX);
            let (coverage, unique) = (tenths(coverage), tenths(unique));
            areas
                .entry(area.map_or(0, Region::as_u64))
                .or_insert_with(|| (area, Vec::new()))
                .1
                .push(FeederFigure {
                    receiver: key,
                    cell: public,
                    uptime_permille: u16::try_from((active * 1000 / minutes).min(1000))
                        .unwrap_or(1000),
                    messages,
                    aircraft,
                    range_m: range.map(|metres| metres.round().min(f64::from(u32::MAX - 1)) as u32),
                    coverage_dkm2: coverage,
                    unique_coverage_dkm2: unique.min(coverage),
                    mlat_positions: mlat,
                    standing: has_standing(&key),
                });
        }
        for (_, figures) in areas.values_mut() {
            figures.sort_by_key(|figure| *figure.receiver.as_bytes());
        }
        (end, window_for_ms, areas)
    }

    /// The figures as of the hour holding `now_ms` began (`compute`), signed by `identity` and
    /// issued at that hour's start: one record per area, more where an area holds more receivers
    /// than one record does.
    pub fn sign(
        &self,
        identity: &impl Signs,
        now: Judged,
        has_standing: impl Fn(&PublicKey) -> bool,
    ) -> Vec<FeederFigures> {
        let (issued_ms, window_for_ms, areas) = self.compute(now, has_standing);
        let mut signed = Vec::new();
        for (_, (area, figures)) in areas {
            for part in figures.chunks(MAX_FEEDER_FIGURES) {
                let content = FeederFiguresContent {
                    issued_ms,
                    window_for_ms,
                    area,
                    feeders: part.to_vec(),
                };
                if let Ok(record) = FeederFigures::sign(identity, &content) {
                    signed.push(record);
                }
            }
        }
        if let Ok(mut latest) = self.latest.lock() {
            *latest = Arc::from(signed.clone());
        }
        // Their bucket taken: they are due again at the next.
        self.published_ms.fetch_max(now.ms(), Ordering::Relaxed);
        signed
    }
}

/// The start of the window at `now_ms`: the start of the hour `WINDOW_HOURS` before this one.
fn window_start_ms(now: Judged) -> u64 {
    let now_ms = now.ms();
    (now_ms / HOUR_MS).saturating_sub(WINDOW_HOURS) * HOUR_MS
}

#[cfg(test)]
mod tests;
