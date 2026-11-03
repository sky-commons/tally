//! LOCATION SANITY CHECK (RFC-0204): whether a receiver's claimed site fits the aircraft it hears.
//!
//! MLAT needs each antenna's site to within about ten metres, and nothing else in the network
//! notices a site that is kilometres off: a receiver set up with a guessed location (ours was 45
//! km off) solves nothing and spoils the clock models it is paired in. A relay that carries a
//! receiver's batches decodes the receiver's own airborne positions anyway (`figures`, a global CPR
//! decode of an even and an odd position one receiver heard). This module keeps what those
//! positions say about where the receiver can be, around the site it claims, and judges the claim.
//! It catches gross errors, kilometres to hundreds of kilometres; never metres.
//!
//! - **What is kept** ([`Heard`]), per receiver with a site, for two half-day epochs by the
//!   batches' own signed clocks (so 12 to 24 hours): a grid of [`CELL_KM`] cells within
//!   [`GRID_KM`] of the claimed site, and, beyond it, bins by bearing ([`SECTORS`]) and distance
//!   ([`FAR_EDGES_KM`]). Each cell or bin holds how many positions fell in it (saturating), the
//!   lowest altitude among them, and sixteen bits of which aircraft (a hash of each address), never
//!   an address, a time or a position. All of it is relative to the claimed site, so a new site
//!   starts it over ([`Heard::set_site`]). A fixed size whatever the receiver hears: about 13 KiB.
//! - **What is judged** ([`Heard::judge`]), three ways, each of which a correct site passes with a
//!   wide margin, so a correct receiver is never flagged by a quiet day or an odd antenna. The
//!   last two ask first that the site be *outside* what the receiver hears: every position, near
//!   or far, in at most [`OUTSIDE_SECTORS`] of its eight compass sectors. A receiver that hears
//!   all round its site, however far, is never found wrong by them.
//!   - *Horizon.* A position farther from the claimed site than the radio horizon of an aircraft
//!     at its altitude and an antenna well above anything an owner claims cannot have been heard
//!     there. Enough of them ([`HORIZON_BINS`], from at least [`HORIZON_AIRCRAFT`] aircraft,
//!     [`HORIZON_SHARE_OF_FAR`] of what it hears past the grid) and the site is wrong. Catches
//!     errors larger than the horizon's margin (about 100 km), for a receiver of any size.
//!   - *Near field.* A receiver hears the aircraft close to it from every side, whatever its
//!     antenna: an aircraft within [`NEAR_KM`] is tens of decibels louder than one at the edge of
//!     its range, through a window, a wall or a roof. So a correct site is *surrounded*: positions
//!     within [`NEAR_KM`] of it in at least [`SURROUNDED_SECTORS`] of its eight compass sectors.
//!     A site is wrong when it is not surrounded (at most [`OPEN_SECTORS`]), the nearest positions
//!     to it are at least [`HOLE_KM`] away, and somewhere at least [`WRONG_KM`] away is surrounded
//!     on nearly every side ([`FOUND_SECTORS`], by at least [`FOUND_AIRCRAFT`] aircraft): the
//!     receiver is there. Catches an error larger than the receiver's own reach, which for the
//!     quiet indoor receivers most hobbyists start with is a few tens of kilometres.
//!   - *Nothing near.* Nothing heard within [`EMPTY_KM`] of the site, from a receiver that has
//!     heard [`EMPTY_POSITIONS`] positions: it is about as far off as the typical one. Catches a
//!     quiet receiver too far off for its near field to fall in the grid.
//!   - What none of them can tell is *unjudged*, never wrong: too little heard ([`LEAST_AIRCRAFT`],
//!     [`LEAST_PLACES`]), or a receiver that hears far but not around its site (no traffic near
//!     it) with nowhere else surrounded either.
//! - **What it says** ([`Judgment`]): the site fits, is unjudged, or is wrong by about so many
//!   kilometres, rounded to [`ROUND_KM`]. Never the place the receiver seems to be at, or which
//!   way: a distance from the claimed site in steps coarser than the public cell tells no one
//!   where the antenna is. The relay holds a receiver whose site is wrong out of MLAT (its raw
//!   still feeds the map and every product), and its station report says so (`network`).

/// The grid's cells, kilometres a side.
pub const CELL_KM: f64 = 5.0;
/// The grid reaches this far from the claimed site, east, west, north and south.
pub const GRID_KM: f64 = 100.0;
/// Cells a side.
const SIDE: usize = (2.0 * GRID_KM / CELL_KM) as usize;
const GRID_CELLS: usize = SIDE * SIDE;
/// Compass sectors, 45 degrees each, clockwise from north.
pub const SECTORS: usize = 8;
/// The far bins' distances from the claimed site, kilometres: a bin from each edge to the next,
/// the last one past the last edge. The first begins where the grid ends (its corners reach 141 km;
/// a position past [`GRID_KM`] east or north but within 141 km is in the first bin).
pub const FAR_EDGES_KM: [f64; 9] = [
    100.0, 150.0, 200.0, 250.0, 300.0, 350.0, 400.0, 500.0, 700.0,
];
const FAR_BINS: usize = SECTORS * FAR_EDGES_KM.len();
/// An epoch of what is kept: half a day by the batches' signed clocks; two are kept.
pub const EPOCH_MS: u64 = 12 * 3_600_000;
/// An altitude bucket, feet: a cell keeps the lowest bucket heard in it.
const ALTITUDE_STEP_FT: i32 = 500;
/// No altitude heard in a cell.
const NO_ALTITUDE: u8 = u8::MAX;

/// Distinct aircraft (by the figures row's count) and occupied cells and bins below which nothing
/// is judged.
pub const LEAST_AIRCRAFT: usize = 15;
pub const LEAST_PLACES: usize = 12;
/// The near field: an aircraft this close is heard from every side.
pub const NEAR_KM: f64 = 25.0;
/// A cell this close to a place gives it no bearing (the place's own cell, about).
const OWN_CELL_KM: f64 = 3.0;
/// A site with positions in this many sectors of its near field fits.
pub const SURROUNDED_SECTORS: usize = 5;
/// A site with positions in no more than this many sectors of its near field is open.
pub const OPEN_SECTORS: usize = 3;
/// How far the nearest positions (the third nearest cell) must be from a site found wrong.
pub const HOLE_KM: f64 = 15.0;
/// A place found surrounded instead: this many sectors, by at least this many aircraft bits.
pub const FOUND_SECTORS: usize = 7;
pub const FOUND_AIRCRAFT: u32 = 8;
/// The least distance a site is found wrong by.
pub const WRONG_KM: f64 = 25.0;
/// The horizon's allowance: the antenna is taken this far above what the site claims (an owner's
/// altitude is often the ground's, or a guess), and a position is past the horizon only past this
/// share of it and this many kilometres more (refraction, ducting, a cell's own size).
pub const HORIZON_ANTENNA_M: f64 = 100.0;
pub const HORIZON_SHARE: f64 = 1.1;
pub const HORIZON_SLACK_KM: f64 = 20.0;
/// Far bins past the horizon that make a site wrong, from at least this many aircraft bits, and
/// holding at least this share of the positions past the grid: a night of ducting is a sliver.
pub const HORIZON_BINS: usize = 3;
pub const HORIZON_AIRCRAFT: u32 = 3;
pub const HORIZON_SHARE_OF_FAR: f64 = 0.05;
/// A site with nothing heard within this (past its third nearest place), at least this many
/// positions heard, all outside it ([`OUTSIDE_SECTORS`]), is wrong by about as far as the typical
/// one: an antenna hears what passes within tens of kilometres before anything farther, so a
/// receiver that hears only far off, and only one way, is not where it says.
pub const EMPTY_KM: f64 = 60.0;
pub const EMPTY_POSITIONS: u32 = 60;
/// A site found wrong by its near field is outside what the receiver hears: every position, near
/// or far, lies in at most this many of its sectors. A receiver that hears all round its site
/// (one with no traffic near it, hearing a ring) is never found wrong by its near field.
pub const OUTSIDE_SECTORS: usize = 4;
/// A distance said is rounded to this many kilometres: coarser than the public cell.
pub const ROUND_KM: u32 = 5;

/// The mean Earth radius, kilometres (IUGG).
const EARTH_RADIUS_KM: f64 = 6_371.008_8;

/// A claimed site: degrees, and the claimed altitude (metres above the ellipsoid) if known.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Site {
    pub lat: f64,
    pub lon: f64,
    pub alt_m: Option<i32>,
}

impl Site {
    /// Great-circle distance, kilometres.
    fn distance_km(&self, lat: f64, lon: f64) -> f64 {
        let (a, b) = (self.lat.to_radians(), lat.to_radians());
        let dlat = b - a;
        let dlon = (lon - self.lon).to_radians();
        let h = (dlat / 2.0).sin().powi(2) + a.cos() * b.cos() * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_KM * h.sqrt().min(1.0).asin()
    }

    /// The initial bearing to (`lat`, `lon`), degrees clockwise from north, 0 to below 360.
    fn bearing_deg(&self, lat: f64, lon: f64) -> f64 {
        let (a, b) = (self.lat.to_radians(), lat.to_radians());
        let dlon = (lon - self.lon).to_radians();
        let y = dlon.sin() * b.cos();
        let x = a.cos() * b.sin() - a.sin() * b.cos() * dlon.cos();
        y.atan2(x).to_degrees().rem_euclid(360.0)
    }

    /// East and north of the site, kilometres, on its local plane (good to a fraction of a
    /// percent within the grid).
    fn local_km(&self, lat: f64, lon: f64) -> (f64, f64) {
        let dlon = (lon - self.lon + 540.0).rem_euclid(360.0) - 180.0;
        let east = dlon.to_radians() * EARTH_RADIUS_KM * self.lat.to_radians().cos();
        let north = (lat - self.lat).to_radians() * EARTH_RADIUS_KM;
        (east, north)
    }

    /// Whether `other` is the same site for what is kept: within a kilometre.
    fn same_place(&self, other: &Self) -> bool {
        self.distance_km(other.lat, other.lon) <= 1.0
    }
}

/// What one cell or bin holds: positions (saturating), the lowest altitude bucket, which aircraft.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cell {
    count: u8,
    low: u8,
    aircraft: u16,
}

impl Cell {
    const EMPTY: Self = Self {
        count: 0,
        low: NO_ALTITUDE,
        aircraft: 0,
    };

    fn add(&mut self, low: u8, aircraft: u16) {
        self.count = self.count.saturating_add(1);
        self.low = self.low.min(low);
        self.aircraft |= aircraft;
    }

    fn merged(self, other: Self) -> Self {
        Self {
            count: self.count.saturating_add(other.count),
            low: self.low.min(other.low),
            aircraft: self.aircraft | other.aircraft,
        }
    }

    fn occupied(self) -> bool {
        self.count > 0
    }

    /// The highest altitude, metres, its lowest bucket allows: the horizon is judged at it, so a
    /// bucket's width never makes a position look farther than it was.
    fn ceiling_m(self) -> Option<f64> {
        (self.low != NO_ALTITUDE)
            .then(|| f64::from((i32::from(self.low) + 1) * ALTITUDE_STEP_FT) * 0.3048)
    }
}

/// The altitude bucket of `feet` (none for none).
fn bucket(feet: Option<i32>) -> u8 {
    feet.map_or(NO_ALTITUDE, |feet| {
        u8::try_from((feet.max(0) / ALTITUDE_STEP_FT).min(i32::from(NO_ALTITUDE) - 1))
            .unwrap_or(NO_ALTITUDE - 1)
    })
}

/// The one of sixteen bits an aircraft's address is kept as.
fn aircraft_bit(address: u32) -> u16 {
    1 << (address.wrapping_mul(0x9E37_79B1) >> 28)
}

/// One epoch of what was heard.
#[derive(Clone, Debug)]
struct Epoch {
    /// The epoch (signed wall clock over [`EPOCH_MS`]) it holds.
    id: u64,
    /// Made by its first position inside the grid.
    grid: Option<Box<[Cell]>>,
    far: [Cell; FAR_BINS],
}

impl Epoch {
    fn new(id: u64) -> Self {
        Self {
            id,
            grid: None,
            far: [Cell::EMPTY; FAR_BINS],
        }
    }
}

/// What a receiver's own positions say of where it can be, around the site it claims (module
/// docs).
#[derive(Clone, Debug, Default)]
pub struct Heard {
    site: Option<Site>,
    /// Bumped each time the site moves (and what was kept starts over): a verdict on the site
    /// before is no verdict on this one ([`Verdicts`]).
    generation: u32,
    epochs: [Option<Epoch>; 2],
}

/// What [`Heard::judge`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgment {
    /// Too little heard, or nothing that can tell.
    Unjudged,
    /// The site fits what it hears.
    Fits,
    /// The site is wrong by about `off_km` (rounded to [`ROUND_KM`]), found by `by`.
    Wrong { off_km: u32, by: Evidence },
}

/// What found a site wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    Horizon,
    NearField,
    NothingNear,
}

/// The heaviest a [`Heard`] grows, itself and both its epochs' grids: what a full row's charge
/// covers of it (`figures::ROW_BYTES`).
pub const MAX_BYTES: usize =
    std::mem::size_of::<Heard>() + 2 * GRID_CELLS * std::mem::size_of::<Cell>();

impl Heard {
    /// The site claimed now (`None`: it claims none, and nothing is kept). A site other than the
    /// one kept for (more than a kilometre away) starts what is kept over; the same site with a
    /// new altitude keeps it.
    pub fn set_site(&mut self, site: Option<Site>) {
        match (&mut self.site, site) {
            (Some(held), Some(site)) if held.same_place(&site) => {
                if site.alt_m.is_some() {
                    held.alt_m = site.alt_m;
                }
            }
            (held, site) => {
                if held.is_some() || site.is_some() {
                    *held = site;
                    self.epochs = [None, None];
                    self.generation = self.generation.wrapping_add(1);
                }
            }
        }
    }

    /// The site claimed, if any.
    pub fn site(&self) -> Option<Site> {
        self.site
    }

    /// Which site this is (bumped each time it moves).
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// An aircraft `address` the receiver itself placed at (`lat`, `lon`), at `feet` if its
    /// position said, in a batch signed at `at_ms`.
    pub fn heard(&mut self, lat: f64, lon: f64, feet: Option<i32>, address: u32, at_ms: u64) {
        let Some(site) = self.site else {
            return;
        };
        if !(lat.is_finite() && lon.is_finite()) {
            return;
        }
        let id = at_ms / EPOCH_MS;
        let slot = usize::from(id % 2 == 1);
        match &self.epochs[slot] {
            Some(epoch) if epoch.id == id => {}
            // An epoch older than the one held there is past both kept.
            Some(epoch) if epoch.id > id => return,
            _ => self.epochs[slot] = Some(Epoch::new(id)),
        }
        let Some(epoch) = self.epochs[slot].as_mut() else {
            return;
        };
        let (low, bit) = (bucket(feet), aircraft_bit(address));
        let (east, north) = site.local_km(lat, lon);
        if east.abs() < GRID_KM && north.abs() < GRID_KM {
            let column = ((east + GRID_KM) / CELL_KM) as usize;
            let row = ((north + GRID_KM) / CELL_KM) as usize;
            let grid = epoch
                .grid
                .get_or_insert_with(|| vec![Cell::EMPTY; GRID_CELLS].into_boxed_slice());
            if let Some(cell) = grid.get_mut(row.min(SIDE - 1) * SIDE + column.min(SIDE - 1)) {
                cell.add(low, bit);
            }
        } else {
            let distance = site.distance_km(lat, lon);
            let sector = (site.bearing_deg(lat, lon) / 45.0) as usize % SECTORS;
            let band = FAR_EDGES_KM
                .iter()
                .rposition(|edge| distance >= *edge)
                .unwrap_or(0);
            epoch.far[sector * FAR_EDGES_KM.len() + band].add(low, bit);
        }
    }

    /// What was heard over the epochs still kept at `now_ms` (this one and the one before),
    /// merged.
    fn view(&self, now_ms: u64) -> (Vec<Cell>, [Cell; FAR_BINS]) {
        let current = now_ms / EPOCH_MS;
        let mut grid = Vec::new();
        let mut far = [Cell::EMPTY; FAR_BINS];
        for epoch in self.epochs.iter().flatten() {
            if epoch.id + 1 < current || epoch.id > current {
                continue;
            }
            if let Some(cells) = &epoch.grid {
                if grid.is_empty() {
                    grid = vec![Cell::EMPTY; GRID_CELLS];
                }
                for (merged, cell) in grid.iter_mut().zip(cells.iter()) {
                    *merged = merged.merged(*cell);
                }
            }
            for (merged, cell) in far.iter_mut().zip(epoch.far.iter()) {
                *merged = merged.merged(*cell);
            }
        }
        (grid, far)
    }

    /// Judges the claimed site at `now_ms` (module docs), the receiver having heard `aircraft`
    /// distinct aircraft over the figures' window.
    pub fn judge(&self, now_ms: u64, aircraft: usize) -> Judgment {
        let Some(site) = self.site else {
            return Judgment::Unjudged;
        };
        let (grid, far) = self.view(now_ms);
        let cells: Vec<Place> = grid
            .iter()
            .enumerate()
            .filter(|(_, cell)| cell.occupied())
            .map(|(index, cell)| Place {
                east: ((index % SIDE) as f64 + 0.5) * CELL_KM - GRID_KM,
                north: ((index / SIDE) as f64 + 0.5) * CELL_KM - GRID_KM,
                count: cell.count,
                aircraft: cell.aircraft,
            })
            .collect();
        if aircraft < LEAST_AIRCRAFT {
            return Judgment::Unjudged;
        }
        let mut sectors = [false; SECTORS];
        for cell in &cells {
            if cell.east.hypot(cell.north) > OWN_CELL_KM {
                sectors[sector_of(cell.east, cell.north)] = true;
            }
        }
        for (index, cell) in far.iter().enumerate() {
            if cell.occupied() {
                sectors[index / FAR_EDGES_KM.len()] = true;
            }
        }
        let outside = sectors.iter().filter(|held| **held).count() <= OUTSIDE_SECTORS;
        // Every position's distance from the site, by how many fell there: a grid cell's centre,
        // a far bin's middle (its inner edge for the nearest).
        let mut heard: Vec<(f64, f64, u32)> = cells
            .iter()
            .map(|cell| {
                let distance = cell.east.hypot(cell.north);
                (distance, distance, u32::from(cell.count))
            })
            .chain(
                far.iter()
                    .enumerate()
                    .filter(|(_, cell)| cell.occupied())
                    .map(|(index, cell)| {
                        let band = index % FAR_EDGES_KM.len();
                        let inner = FAR_EDGES_KM[band];
                        let outer = FAR_EDGES_KM.get(band + 1).copied().unwrap_or(inner + 200.0);
                        (inner, (inner + outer) / 2.0, u32::from(cell.count))
                    }),
            )
            .collect();
        let empty = nothing_near(&mut heard);
        if let Some(past) = past_horizon(&site, &far) {
            // How far past the horizon is the least it can be off; a site outside what it hears
            // is about as far off as the typical position.
            let off_km = empty.filter(|_| outside).unwrap_or(past);
            return Judgment::Wrong {
                off_km: rounded(off_km),
                by: Evidence::Horizon,
            };
        }
        if outside && let Some(off_km) = empty {
            return Judgment::Wrong {
                off_km: rounded(off_km),
                by: Evidence::NothingNear,
            };
        }
        if cells.len() + far.iter().filter(|cell| cell.occupied()).count() < LEAST_PLACES {
            return Judgment::Unjudged;
        }
        near_field(&cells, outside)
    }
}

/// An occupied grid cell, on the site's local plane.
#[derive(Clone, Copy, Debug)]
struct Place {
    east: f64,
    north: f64,
    count: u8,
    aircraft: u16,
}

/// The near field around (`east`, `north`): the sectors holding a position within [`NEAR_KM`],
/// the aircraft bits among them, and the cells.
fn around(cells: &[Place], east: f64, north: f64) -> (usize, u32, usize) {
    let mut sectors = [false; SECTORS];
    let (mut aircraft, mut count) = (0u16, 0);
    for cell in cells {
        let (de, dn) = (cell.east - east, cell.north - north);
        let distance = de.hypot(dn);
        if distance > NEAR_KM {
            continue;
        }
        count += 1;
        aircraft |= cell.aircraft;
        if distance > OWN_CELL_KM {
            sectors[sector_of(de, dn)] = true;
        }
    }
    (
        sectors.iter().filter(|held| **held).count(),
        aircraft.count_ones(),
        count,
    )
}

/// The compass sector of a point `east` and `north` of a place.
fn sector_of(east: f64, north: f64) -> usize {
    let bearing = east.atan2(north).to_degrees().rem_euclid(360.0);
    (bearing / 45.0) as usize % SECTORS
}

/// The near-field judgment (module docs), of a site `outside` what the receiver hears (every
/// position in at most [`OUTSIDE_SECTORS`] of its sectors) or not: one inside is never wrong.
fn near_field(cells: &[Place], outside: bool) -> Judgment {
    let (sectors, _, _) = around(cells, 0.0, 0.0);
    if sectors >= SURROUNDED_SECTORS {
        return Judgment::Fits;
    }
    if sectors > OPEN_SECTORS || !outside {
        return Judgment::Unjudged;
    }
    let mut nearest: Vec<f64> = cells
        .iter()
        .map(|cell| cell.east.hypot(cell.north))
        .collect();
    nearest.sort_by(f64::total_cmp);
    if nearest.get(2).is_none_or(|third| *third < HOLE_KM) {
        return Judgment::Unjudged;
    }
    // Every place surrounded on nearly every side, by how many cells are near it.
    let found: Vec<(usize, &Place)> = cells
        .iter()
        .filter_map(|cell| {
            let (sectors, aircraft, count) = around(cells, cell.east, cell.north);
            (sectors >= FOUND_SECTORS && aircraft >= FOUND_AIRCRAFT).then_some((count, cell))
        })
        .collect();
    // The most surrounded, the first in the grid's order of those as surrounded, and the found
    // places within its near field: where the receiver is, about.
    let Some((_, best)) = found
        .iter()
        .copied()
        .reduce(|best, next| if next.0 > best.0 { next } else { best })
    else {
        return Judgment::Unjudged;
    };
    let group: Vec<&Place> = found
        .iter()
        .map(|(_, place)| *place)
        .filter(|place| (place.east - best.east).hypot(place.north - best.north) <= NEAR_KM)
        .collect();
    let n = group.len() as f64;
    let east = group.iter().map(|place| place.east).sum::<f64>() / n;
    let north = group.iter().map(|place| place.north).sum::<f64>() / n;
    let off_km = east.hypot(north);
    if off_km < WRONG_KM {
        return Judgment::Unjudged;
    }
    Judgment::Wrong {
        off_km: rounded(off_km),
        by: Evidence::NearField,
    }
}

/// The nothing-near judgment (module docs) of what was heard, as (nearest distance, typical
/// distance, positions) from the site: when nothing was heard within [`EMPTY_KM`] (past the third
/// nearest place, or the last of fewer) and at least [`EMPTY_POSITIONS`] positions were heard, how far the typical one
/// is (the median, by positions).
fn nothing_near(heard: &mut [(f64, f64, u32)]) -> Option<f64> {
    heard.sort_by(|a, b| a.0.total_cmp(&b.0));
    let positions: u32 = heard.iter().map(|(_, _, count)| *count).sum();
    // The third nearest place, or the farthest of fewer (a quiet receiver far off fills a bin or
    // two of the far ones).
    let nearest = heard.get(2).or(heard.last());
    if positions < EMPTY_POSITIONS || nearest.is_none_or(|nearest| nearest.0 < EMPTY_KM) {
        return None;
    }
    heard.sort_by(|a, b| a.1.total_cmp(&b.1));
    let mut passed = 0;
    heard.iter().find_map(|(_, typical, count)| {
        passed += count;
        (passed * 2 >= positions).then_some(*typical)
    })
}

/// The radio horizon, kilometres, of an antenna `antenna_m` and an aircraft `aircraft_m` above
/// the surface, under the usual four-thirds Earth.
pub fn horizon_km(antenna_m: f64, aircraft_m: f64) -> f64 {
    4.12 * (antenna_m.max(0.0).sqrt() + aircraft_m.max(0.0).sqrt())
}

/// The horizon judgment (module docs): how far past the horizon the typical bin past it is, when
/// enough are.
fn past_horizon(site: &Site, far: &[Cell; FAR_BINS]) -> Option<f64> {
    let antenna = f64::from(site.alt_m.unwrap_or(0).max(0)) + HORIZON_ANTENNA_M;
    let mut aircraft = 0u16;
    let mut excess: Vec<f64> = Vec::new();
    let (mut past, mut all) = (0u32, 0u32);
    for (index, cell) in far.iter().enumerate() {
        all += u32::from(cell.count);
        let Some(ceiling) = cell.ceiling_m().filter(|_| cell.occupied()) else {
            continue;
        };
        let inner = FAR_EDGES_KM[index % FAR_EDGES_KM.len()];
        let allowed = HORIZON_SHARE * horizon_km(antenna, ceiling) + HORIZON_SLACK_KM;
        if inner > allowed {
            aircraft |= cell.aircraft;
            past += u32::from(cell.count);
            excess.push(inner - allowed);
        }
    }
    let enough = excess.len() >= HORIZON_BINS
        && aircraft.count_ones() >= HORIZON_AIRCRAFT
        && f64::from(past) >= HORIZON_SHARE_OF_FAR * f64::from(all);
    if !enough {
        return None;
    }
    excess.sort_by(f64::total_cmp);
    excess.get(excess.len() / 2).copied()
}

/// `km` in steps of [`ROUND_KM`], at least one step.
fn rounded(km: f64) -> u32 {
    let steps = (km / f64::from(ROUND_KM)).round().max(1.0);
    (steps as u32).saturating_mul(ROUND_KM)
}

/// A receiver's site is held wrong once this many judgments in a row found it wrong, and fits
/// again once this many in a row did not, or at once when its site moves: one odd half hour
/// flags nothing, and an owner who fixes the site is taken back at once.
pub const WRONG_AFTER: u8 = 3;
pub const CLEARED_AFTER: u8 = 3;

/// What the relay says of a receiver's site (`stations`, `GET /stations`): whether it fits,
/// and, when it is held wrong, by about how far. Never where the receiver seems to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocationCheck {
    pub state: CheckState,
    /// About how far off the site is, in steps of [`ROUND_KM`]: only when `state` is `wrong`.
    pub off_km: Option<u32>,
}

/// A site's state as said.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    /// Too little heard yet, or nothing that can tell.
    Unjudged,
    /// It fits what the receiver hears.
    Fits,
    /// It is held wrong: the relay keeps the receiver out of MLAT until it changes.
    Wrong,
}

/// One receiver's run of judgments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Verdict {
    generation: u32,
    last: Judgment,
    wrong_run: u8,
    other_run: u8,
    /// Held wrong, by about this far.
    wrong_by: Option<u32>,
}

/// Every receiver's verdict, from the judgments of its row ([`Verdicts::judged`]): one for each
/// row the figures hold, so as bounded as they are.
#[derive(Clone, Debug, Default)]
pub struct Verdicts {
    held: std::collections::BTreeMap<tally_wire::PublicKey, Verdict>,
}

impl Verdicts {
    /// The judgments of every row now, each with its site's generation: the runs carried on, a
    /// receiver whose site moved starting over, one with no row any more forgotten.
    pub fn judged(&mut self, judged: Vec<(tally_wire::PublicKey, u32, Judgment)>) {
        let mut held = std::collections::BTreeMap::new();
        for (key, generation, judgment) in judged {
            let mut verdict = self
                .held
                .get(&key)
                .copied()
                .filter(|verdict| verdict.generation == generation)
                .unwrap_or(Verdict {
                    generation,
                    last: Judgment::Unjudged,
                    wrong_run: 0,
                    other_run: 0,
                    wrong_by: None,
                });
            verdict.last = judgment;
            if let Judgment::Wrong { off_km, .. } = judgment {
                verdict.wrong_run = verdict.wrong_run.saturating_add(1);
                verdict.other_run = 0;
                if verdict.wrong_run >= WRONG_AFTER || verdict.wrong_by.is_some() {
                    verdict.wrong_by = Some(off_km);
                }
            } else {
                verdict.other_run = verdict.other_run.saturating_add(1);
                verdict.wrong_run = 0;
                if verdict.other_run >= CLEARED_AFTER {
                    verdict.wrong_by = None;
                }
            }
            held.insert(key, verdict);
        }
        self.held = held;
    }

    /// The receivers held wrong: the ones the relay keeps out of MLAT.
    pub fn misplaced(&self) -> std::collections::BTreeSet<tally_wire::PublicKey> {
        self.held
            .iter()
            .filter(|(_, verdict)| verdict.wrong_by.is_some())
            .map(|(key, _)| *key)
            .collect()
    }

    /// What is said of `receiver`'s site, if it has been judged.
    pub fn check(&self, receiver: &tally_wire::PublicKey) -> Option<LocationCheck> {
        let verdict = self.held.get(receiver)?;
        Some(match (verdict.wrong_by, verdict.last) {
            (Some(off_km), _) => LocationCheck {
                state: CheckState::Wrong,
                off_km: Some(off_km),
            },
            (None, Judgment::Fits) => LocationCheck {
                state: CheckState::Fits,
                off_km: None,
            },
            (None, _) => LocationCheck {
                state: CheckState::Unjudged,
                off_km: None,
            },
        })
    }
}

#[cfg(test)]
mod tests;
