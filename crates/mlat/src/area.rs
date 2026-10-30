//! What an MLAT relay holds for the areas it solves (RFC-0174 §2.3): each area's border band, the
//! cells whose receivers' sites and raw it must hold so that every area it fits has its whole
//! model's members in hand; and which area's relays take a transmission up ([`owner`]). One
//! definition, so the raw a relay asks its neighbours for (the region-cut raw subscription,
//! `tally_relay::selection`), the models it asks for (`tally_relay::network`) and the receivers its
//! engine lets take part (`tally_relay::mlat_host`) are the same cells.
//!
//! The band's width is not a chosen number: it follows from the pairs. An area's pair model
//! (`tally_mlat_solver` crate docs, § Areas) has for members its receivers and every receiver one
//! of them keeps as a pair's other end: its `PAIR_NEIGHBOURS` nearest within `PAIR_BASELINE_MM`
//! (600 km) by exact distance between millimetre sites (`pair::Network`). Knowing which those are
//! takes every site within that baseline of each of the area's receivers, and fitting the pairs
//! takes their raw; so the band is every cell that could hold a point within the baseline of any
//! point of the area ([`reach_km`]). The tiles' band before it reached a top-level tile's footprint
//! (about 573 km) from a tile centre in the area; RFC-0174's first "one reception radius (about
//! 400 km)" would leave a boundary receiver's farther pairs out of its area's model, and two relays
//! holding different bands would fit different members, so different bytes.
//!
//! A transmission's other hearers are in the band too (a relay holds only the raw of receivers that
//! take part, and those are the band's), and their areas' models are the ones a fix may cite beside
//! its owner's: the models a relay asks its neighbours for are the band's areas'.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use h3o::{CellIndex, LatLng};
use tally_mlat_solver::Sites;
use tally_mlat_solver::pair::PAIR_BASELINE_MM;
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{PublicKey, Region, Regions};

/// The area whose relays take up a transmission heard by `hearers` (`fix` module docs, By whom):
/// the area most of them are in (`Sites::area`), ties to the lowest. `None` when none is in any.
/// A function of the hearers' signed sites alone, so twin relays take up the same transmissions.
pub fn owner(sites: &Sites, hearers: impl IntoIterator<Item = PublicKey>) -> Option<Region> {
    let mut counts: BTreeMap<Region, usize> = BTreeMap::new();
    for hearer in hearers {
        if let Some(area) = sites.area(&hearer) {
            *counts.entry(area).or_default() += 1;
        }
    }
    let most = counts.values().copied().max()?;
    counts
        .into_iter()
        .find(|(_, count)| *count == most)
        .map(|(area, _)| area)
}

/// The steps an area's refits come in turns of: one each `REFIT_EVERY` (two steps of
/// `ARRIVED_SLICE`), so each area is refit at one of them, its turn ([`refit_turn`]).
pub const REFIT_TURNS: u64 = tally_wire::budget::REFIT_EVERY_MS
    / tally_wire::budget::ARRIVED_SLICE
        .span::<tally_wire::clocks::Judged>()
        .ms();

/// The step of the refit grid at which `area` is refit (`tally_mlat::engine`, One step a second):
/// that many steps after the step its edge moves on, so an engine's areas are refit half at each
/// step and no step carries them all. A function of the cell alone, so every relay holding the
/// area refits it at the same step, from the same raw. Its edge is still the grid's
/// (`Trailing::fitted_at`): the turn moves when the model is fitted, never what it is fitted at.
/// Before (2026-10-26), every area was refit at the step its edge moved on, and that step carried
/// every refit: at 500 seats a quarter of its second.
pub fn refit_turn(area: Region) -> u64 {
    // SplitMix64's finaliser over the cell index: H3 cells of one resolution differ in a few
    // bits, so the index's own low bits would put neighbours on one turn.
    let mut z = area.as_u64().wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (z ^ (z >> 31)) % REFIT_TURNS
}

/// How far from its area a cell of the band may be, kilometres: the pair baseline, by ECEF chord
/// between millimetre sites, as the great-circle distance on H3's sphere that the band is walked
/// by, with a margin of a hundredth for both (the chord is shorter than its arc, by under a twentieth
/// of a percent at 600 km, and the sphere's radius is within a third of a percent of
/// the ellipsoid's at any latitude).
pub fn reach_km() -> f64 {
    PAIR_BASELINE_MM as f64 / 1e6 * 1.01
}

/// The farthest a cell's boundary is from its centre, kilometres.
fn circumradius_km(cell: CellIndex) -> f64 {
    let centre = LatLng::from(cell);
    cell.boundary()
        .iter()
        .map(|vertex| centre.distance_km(*vertex))
        .fold(0.0, f64::max)
}

/// Whether some point of `cell` may be within the reach of some point of an area centred at
/// `centre` with circumradius `radius_km`. Symmetric (the distance between the centres less both
/// circumradii, against the reach), so a cell is in an area's band exactly when the area is in the
/// cell's.
fn near_to(centre: LatLng, radius_km: f64, cell: CellIndex) -> bool {
    LatLng::from(cell).distance_km(centre) - circumradius_km(cell) - radius_km <= reach_km()
}

/// One area's band, the area itself included, at the area's resolution: computed once per area
/// and remembered (`BANDS_REMEMBERED`), since it is a function of the area alone and every
/// caller (the MLAT relay's raw links each second, every engine's grant, the engine's scope) asks
/// for the same few areas again and again.
fn band_of(area: CellIndex) -> Arc<[CellIndex]> {
    BAND_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
    let memo = BANDS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(band) = memo
        .lock()
        .ok()
        .and_then(|held| held.get(&u64::from(area)).cloned())
    {
        return band;
    }
    let band: Arc<[CellIndex]> = walk_band(area).into();
    if let Ok(mut held) = memo.lock() {
        if held.len() >= BANDS_REMEMBERED {
            held.clear();
        }
        held.insert(u64::from(area), Arc::clone(&band));
    }
    band
}

/// Areas' bands this thread has looked up (remembered or walked): the work a band's building
/// does, which a test reads to hold a grant or a band to the lookups its areas need rather than
/// to a clock.
pub fn band_lookups_here() -> u64 {
    BAND_LOOKUPS.with(std::cell::Cell::get)
}

thread_local! {
    static BAND_LOOKUPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Every cell near `area` (`near`), sorted: walked outward from the area a neighbour at a time,
/// keeping the near ones, until the walk meets none. The cells within a reach of an area are one
/// patch of the grid, so the walk finds every one. Its neighbours are H3's safe disk, correct at
/// the twelve pentagons: H3's ring iterator (`grid_ring_fast`) reports a pentagon by yielding a
/// failure without moving on, so a walk ring by ring that skipped failures never ended for an area
/// whose band reaches a pentagon, and a relay solving such an area spun there for good.
fn walk_band(area: CellIndex) -> Vec<CellIndex> {
    let (centre, radius_km) = (LatLng::from(area), circumradius_km(area));
    let mut seen: HashSet<CellIndex> = HashSet::from([area]);
    let mut cells = vec![area];
    let mut frontier = vec![area];
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for cell in frontier {
            for neighbour in cell.grid_disk_safe(1) {
                if seen.insert(neighbour) && near_to(centre, radius_km, neighbour) {
                    cells.push(neighbour);
                    next.push(neighbour);
                }
            }
        }
        frontier = next;
    }
    cells.sort_unstable();
    cells
}

/// Areas whose band is remembered, at most: every area of the world at the area resolution
/// (41,162 cells at resolution 3, each band about a hundred and fifty cells, some 50 MB at the
/// very most, for a relay solving the whole world), and room beside them.
const BANDS_REMEMBERED: usize = 65_536;
static BANDS: OnceLock<Mutex<HashMap<u64, Arc<[CellIndex]>>>> = OnceLock::new();

/// The cells an MLAT relay for some areas holds the raw of: every area's band, at the area
/// resolution. The one definition behind [`border_band`] (the cells a relay asks its neighbours for
/// and lets its engine take part) and [`Band::holds`] (what a relay grants an engine), so the two
/// cannot disagree.
///
/// Held as the areas themselves (`inside`, as compact as they were named) and the band's cells
/// beyond them (`beyond`), never as the areas' bands one by one: a cell inside the areas is in the
/// band, and a cell beyond them is in it exactly when some area is in its own band (`near` is
/// symmetric, and an area's near cells are one patch). So the work is the areas' edge, not their
/// count: the whole world, named as its 122 base cells, has no edge and costs nothing, where its
/// 41,162 areas one by one cost seconds of a core.
#[derive(Clone, Debug, Default)]
pub struct Band {
    /// The areas, as the fewest cells that cover them.
    inside: Regions,
    /// The cells at the area resolution beyond the areas that some area reaches.
    beyond: HashSet<u64>,
}

/// The finest a region named against a band may be split, in resolutions, to be checked cell by
/// cell: a region three resolutions coarser than the band's areas is 343 of them.
const SPLIT_AT_MOST: u8 = 3;

/// How far around a cell coarser than an area its edge is looked for (`Band::edge`): two rings,
/// so that a finer cell's neighbour, whose coarser cell need not be the coarser neighbour of its
/// own, is still within the cells looked at.
const EDGE_RINGS: u32 = 2;

fn region(cell: CellIndex) -> Option<Region> {
    Region::from_u64(u64::from(cell)).ok()
}

impl Band {
    /// The band of `areas`: every cell any of them reaches. A region finer than an area stands
    /// for the area it lies in.
    pub fn of(areas: &Regions) -> Self {
        let inside = if areas.iter().any(|cell| cell.resolution() > AREA_RESOLUTION) {
            areas
                .iter()
                .filter_map(|cell| cell.ancestor(cell.resolution().min(AREA_RESOLUTION)))
                .collect()
        } else {
            areas.clone()
        };
        let mut beyond = HashSet::new();
        let mut seen = HashSet::new();
        let mut frontier: Vec<CellIndex> = Vec::new();
        for edge in Self::edge(&inside) {
            for neighbour in edge.grid_disk_safe(1) {
                if region(neighbour).is_some_and(|cell| !inside.contains(cell))
                    && seen.insert(neighbour)
                {
                    frontier.push(neighbour);
                }
            }
        }
        while let Some(cell) = frontier.pop() {
            let reached = band_of(cell)
                .iter()
                .filter_map(|area| region(*area))
                .any(|area| inside.contains(area));
            if !reached {
                continue;
            }
            beyond.insert(u64::from(cell));
            for neighbour in cell.grid_disk_safe(1) {
                if region(neighbour).is_some_and(|cell| !inside.contains(cell))
                    && seen.insert(neighbour)
                {
                    frontier.push(neighbour);
                }
            }
        }
        Self { inside, beyond }
    }

    /// The areas of `inside` with a neighbour outside it: found from each cell listed by keeping,
    /// a resolution at a time, only the children near its edge, so a cell whose surroundings are
    /// all inside is never split.
    fn edge(inside: &Regions) -> Vec<CellIndex> {
        let outside_near = |cell: CellIndex, rings: u32| {
            cell.grid_disk_safe(rings)
                .any(|near| region(near).is_none_or(|near| !inside.contains(near)))
        };
        let Ok(area_resolution) = h3o::Resolution::try_from(AREA_RESOLUTION) else {
            return Vec::new();
        };
        let mut edge = Vec::new();
        for listed in inside.iter() {
            let Ok(cell) = CellIndex::try_from(listed.as_u64()) else {
                continue;
            };
            let mut level = vec![cell];
            while let Some(first) = level.first()
                && first.resolution() < area_resolution
            {
                level.retain(|cell| outside_near(*cell, EDGE_RINGS));
                let Some(finer) = level.first().and_then(|cell| cell.resolution().succ()) else {
                    break;
                };
                level = level.iter().flat_map(|cell| cell.children(finer)).collect();
            }
            edge.extend(level.into_iter().filter(|cell| outside_near(*cell, 1)));
        }
        edge
    }

    pub fn is_empty(&self) -> bool {
        self.inside.is_empty()
    }

    /// Whether an area-resolution cell is in the band.
    fn has(&self, area: Region) -> bool {
        self.inside.contains(area) || self.beyond.contains(&area.as_u64())
    }

    /// Whether every place in `region` is in the band: `region`'s area (if finer) is in it, or
    /// every area under `region` is. A region coarser than an area by more than
    /// `SPLIT_AT_MOST` resolutions is not held, whatever it covers.
    pub fn holds(&self, region: Region) -> bool {
        if region.resolution() >= AREA_RESOLUTION {
            return region
                .ancestor(AREA_RESOLUTION)
                .is_some_and(|area| self.has(area));
        }
        self.inside.contains(region)
            || (AREA_RESOLUTION - region.resolution() <= SPLIT_AT_MOST
                && region.children(AREA_RESOLUTION).all(|area| self.has(area)))
    }

    /// The band as few cells as cover it.
    pub fn regions(&self) -> Regions {
        self.inside
            .iter()
            .chain(
                self.beyond
                    .iter()
                    .filter_map(|cell| Region::from_u64(*cell).ok()),
            )
            .collect()
    }
}

/// The cells an MLAT relay for `areas` holds the raw of: every area and its border band, as few
/// cells as cover them. Empty for no area.
pub fn border_band(areas: &Regions) -> Regions {
    Band::of(areas).regions()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regions<const N: usize>(cells: [Region; N]) -> Regions {
        Regions::new(cells)
    }

    fn near(area: CellIndex, cell: CellIndex) -> bool {
        near_to(LatLng::from(area), circumradius_km(area), cell)
    }
    use tally_mlat_solver::geo;
    use tally_wire::Location;

    fn at(lat: f64, lon: f64) -> Location {
        Location {
            lat_e7: (lat * 1e7) as i32,
            lon_e7: (lon * 1e7) as i32,
            alt_m: 0,
            precision_m: 0,
        }
    }

    fn area(lat: f64, lon: f64) -> Result<Region, String> {
        Region::containing(&at(lat, lon), AREA_RESOLUTION).map_err(|error| error.to_string())
    }

    /// An engine's areas are refit half at each step of the grid (`refit_turn`): over the 91 areas
    /// within five of one, each turn takes at least a third, whatever their H3 indices share.
    #[test]
    fn neighbouring_areas_are_refit_on_both_turns() -> Result<(), String> {
        let centre = CellIndex::try_from(area(51.5, -0.1)?.as_u64()).map_err(|e| e.to_string())?;
        let mut turns = [0usize; REFIT_TURNS as usize];
        let disk: Vec<CellIndex> = centre.grid_disk_safe(5).collect();
        for cell in &disk {
            let region = Region::from_u64(u64::from(*cell)).map_err(|e| e.to_string())?;
            turns[usize::try_from(refit_turn(region)).map_err(|e| e.to_string())?] += 1;
        }
        assert_eq!(disk.len(), 91);
        assert!(
            turns.iter().all(|count| *count * 3 >= disk.len()),
            "{turns:?}"
        );
        Ok(())
    }

    /// Points of the area: its centre and its boundary's vertices, a little inside.
    fn points_of(area: Region) -> Result<Vec<LatLng>, String> {
        let cell = CellIndex::try_from(area.as_u64()).map_err(|error| error.to_string())?;
        let centre = LatLng::from(cell);
        let mut points = vec![centre];
        for vertex in cell.boundary().iter() {
            let lat = centre.lat() + (vertex.lat() - centre.lat()) * 0.95;
            let lng = centre.lng() + (vertex.lng() - centre.lng()) * 0.95;
            points.push(LatLng::new(lat, lng).map_err(|error| error.to_string())?);
        }
        Ok(points)
    }

    /// The point `km` along the sphere from `from` on `bearing` (radians from north).
    fn towards(from: LatLng, bearing: f64, km: f64) -> Result<LatLng, String> {
        let angle = km / 6_371.008_8;
        let (lat, lng) = (from.lat_radians(), from.lng_radians());
        let to_lat = (lat.sin() * angle.cos() + lat.cos() * angle.sin() * bearing.cos()).asin();
        let to_lng = lng
            + (bearing.sin() * angle.sin() * lat.cos())
                .atan2(angle.cos() - lat.sin() * to_lat.sin());
        LatLng::from_radians(to_lat, to_lng).map_err(|error| error.to_string())
    }

    fn ecef(point: LatLng) -> [f64; 3] {
        geo::to_ecef(geo::Geodetic {
            lat_deg: point.lat(),
            lon_deg: point.lng(),
            height_m: 0.0,
        })
    }

    /// Every place a receiver of an area may keep as a pair's other end (within the pair baseline
    /// of it, by ECEF chord, as `pair::Network` measures) is inside the area's band: an MLAT relay
    /// holding the band holds every member of every model it fits.
    #[test]
    fn the_band_holds_every_place_within_the_pair_baseline_of_its_area() -> Result<(), String> {
        let baseline_m = PAIR_BASELINE_MM as f64 / 1000.0;
        for (lat, lon) in [
            (52.1, 5.1),
            (40.4, -3.7),
            (33.7, -84.4),
            (64.1, -21.9),
            (-33.9, 151.2),
        ] {
            let area = area(lat, lon)?;
            let band = border_band(&regions([area]));
            let mut checked = 0;
            for point in points_of(area)? {
                for step in 0..24 {
                    let bearing = f64::from(step) * std::f64::consts::TAU / 24.0;
                    for km in [100.0, 400.0, 590.0, 600.0, 605.0] {
                        let place = towards(point, bearing, km)?;
                        let apart = tally_mlat_solver::linalg::norm(
                            tally_mlat_solver::linalg::sub(ecef(place), ecef(point)),
                        );
                        if apart > baseline_m {
                            continue;
                        }
                        let location = at(place.lat(), place.lng());
                        assert!(
                            band.iter().any(|cell| cell.covers(&location)),
                            "{place:?}, {km} km from ({lat}, {lon})"
                        );
                        checked += 1;
                    }
                }
            }
            assert!(checked > 500);
        }
        Ok(())
    }

    /// The owner of a set of hearers is the area most of them are in, ties to the lowest.
    #[test]
    fn a_transmission_is_owned_by_the_area_most_of_its_hearers_are_in() -> Result<(), String> {
        let text = |error: tally_wire::WireError| error.to_string();
        let key = |n: u8| tally_wire::Identity::from_seed([n; 32]).public();
        let site = |n: u8, lat: f64, lon: f64| tally_mlat_solver::Site {
            receiver: key(n),
            id: tally_wire::SiteId([n; 32]),
            location: at(lat, lon),
            clock: tally_wire::Clock::Dump1090,
        };
        let sites = [
            site(1, 52.1, 5.1),
            site(2, 52.11, 5.12),
            site(3, 48.8, 2.3),
            site(4, 48.81, 2.31),
            site(5, 40.4, -3.7),
        ];
        let indexed = Sites::new(&sites);
        let keys = |of: &[u8]| -> Vec<PublicKey> { of.iter().map(|n| key(*n)).collect() };
        let amsterdam = Region::containing(&at(52.1, 5.1), AREA_RESOLUTION).map_err(text)?;
        let paris = Region::containing(&at(48.8, 2.3), AREA_RESOLUTION).map_err(text)?;
        assert_eq!(owner(&indexed, keys(&[1, 2, 3])), Some(amsterdam));
        assert_eq!(owner(&indexed, keys(&[3, 4, 5, 1])), Some(paris));
        assert_eq!(owner(&indexed, keys(&[1, 3])), Some(amsterdam.min(paris)));
        assert_eq!(owner(&indexed, keys(&[9])), None);
        Ok(())
    }

    #[test]
    fn the_band_holds_its_area_and_reaches_the_baseline_beyond_it_and_no_further()
    -> Result<(), String> {
        let area = area(52.1, 5.1)?;
        let band = border_band(&regions([area]));
        let inside = |location: &Location| band.iter().any(|cell| cell.covers(location));
        assert!(inside(&at(52.1, 5.1)));
        // 560 km east is within the pair baseline; 1,000 km is not.
        assert!(inside(&at(
            52.1,
            5.1 + 560.0 / (111.32 * 52.1_f64.to_radians().cos())
        )));
        assert!(!inside(&at(
            52.1,
            5.1 + 1_000.0 / (111.32 * 52.1_f64.to_radians().cos())
        )));
        Ok(())
    }

    /// `Band::holds` and `border_band` are one definition: every cell the band lists is held, a
    /// coarser cell only partly inside is not, and a cell is in an area's band exactly when the
    /// area is in the cell's.
    #[test]
    fn a_band_holds_what_it_lists_and_nothing_partly_outside() -> Result<(), String> {
        let one = area(52.1, 5.1)?;
        let two = area(52.6, 5.9)?;
        let band = Band::of(&regions([one, two]));
        let listed = band.regions();
        assert_eq!(listed, border_band(&regions([one, two])));
        for cell in listed.iter() {
            assert!(band.holds(cell), "{cell:?}");
        }
        // A receiver's point inside is held; one 1,000 km away is not, nor is the continent.
        let inside = Region::point(&at(52.1, 9.0)).map_err(|error| error.to_string())?;
        let outside = Region::point(&at(52.1, 20.0)).map_err(|error| error.to_string())?;
        assert!(band.holds(inside));
        assert!(!band.holds(outside));
        let continent = Region::containing(&at(52.1, 5.1), 0).map_err(|error| error.to_string())?;
        assert!(!band.holds(continent));
        // Symmetric: the far edge of the band reaches back to the area.
        let edge = *listed.cells().last().ok_or("an empty band")?;
        for edge_area in
            tally_wire::rendezvous::areas_of(edge).map_err(|error| error.to_string())?
        {
            let back = Band::of(&regions([edge_area]));
            if band_of(CellIndex::try_from(one.as_u64()).map_err(|error| error.to_string())?)
                .contains(
                    &CellIndex::try_from(edge_area.as_u64()).map_err(|error| error.to_string())?,
                )
            {
                assert!(back.holds(one));
            }
        }
        Ok(())
    }

    #[test]
    fn bands_merge_and_name_each_place_once() -> Result<(), String> {
        let one = area(52.1, 5.1)?;
        let two = area(52.6, 5.9)?;
        let both = border_band(&regions([one, two, one]));
        assert!(border_band(&regions([])).is_empty());
        for (index, cell) in both.cells().iter().enumerate() {
            for other in &both.cells()[index + 1..] {
                assert!(!cell.contains(*other) && !other.contains(*cell));
            }
        }
        // Every place either band holds, the merged band holds.
        for place in [at(52.1, 9.0), at(52.6, 13.5), at(49.0, 5.5)] {
            let either = [one, two].iter().any(|area| {
                border_band(&regions([*area]))
                    .iter()
                    .any(|cell| cell.covers(&place))
            });
            assert_eq!(both.iter().any(|cell| cell.covers(&place)), either);
        }
        assert_eq!(border_band(&regions([two, one])), both);
        Ok(())
    }

    /// Rings out from an area the brute-force band looks at: more than its reach at the area
    /// resolution (about 700 km to the farthest cell, at least 60 km a ring), checked by finding
    /// nothing near on the outermost.
    const BRUTE_RINGS: u32 = 12;

    /// An area's band by brute force, with no walk: every cell of the area's disk of
    /// `BRUTE_RINGS` (H3's safe disk, correct at the pentagons) that is near it, sorted. Nothing on
    /// the outermost ring is near, so no near cell lies beyond the disk.
    fn brute_band(area: CellIndex) -> Result<Vec<CellIndex>, String> {
        let disk: Vec<(CellIndex, u32)> = area.grid_disk_distances_safe(BRUTE_RINGS).collect();
        if disk
            .iter()
            .any(|(cell, ring)| *ring == BRUTE_RINGS && near(area, *cell))
        {
            return Err(format!("{area}: the band reaches past {BRUTE_RINGS} rings"));
        }
        let mut cells: Vec<CellIndex> = disk
            .into_iter()
            .map(|(cell, _)| cell)
            .filter(|cell| near(area, *cell))
            .collect();
        cells.sort_unstable();
        cells.dedup();
        Ok(cells)
    }

    /// The band of an area at a pentagon, beside one and far from any is exactly the cells near it,
    /// none missing and none extra, against a brute-force search of its disk: the walk H3's ring
    /// iterator made never ended at a pentagon, and a walk that ended early would miss cells.
    #[test]
    fn a_band_at_a_pentagon_and_elsewhere_is_every_cell_near_its_area() -> Result<(), String> {
        let text = |error: h3o::error::InvalidCellIndex| error.to_string();
        let at = h3o::Resolution::try_from(AREA_RESOLUTION).map_err(|error| error.to_string())?;
        // Base cell 4 is a pentagon; its centre child at the area resolution is one too.
        let pentagon = CellIndex::try_from(0x0800_9fff_ffff_ffff_u64).map_err(text)?;
        let centre = pentagon.center_child(at).ok_or("no centre child")?;
        assert!(centre.is_pentagon());
        let mut areas = vec![centre];
        // Its neighbours, beside the pentagon, and a cell two rings out.
        areas.extend(centre.grid_disk_safe(1).filter(|cell| *cell != centre));
        areas.extend(centre.grid_ring_fast(2).flatten().take(1));
        // Every pentagon at the area resolution.
        areas.extend(
            CellIndex::base_cells()
                .filter_map(|cell| cell.is_pentagon().then(|| cell.center_child(at)).flatten()),
        );
        // Far from any pentagon.
        for (lat, lon) in [(33.7, -84.4), (51.5, -0.1), (-33.9, 151.2), (35.7, 139.7)] {
            areas.push(
                LatLng::new(lat, lon)
                    .map_err(|error| error.to_string())?
                    .to_cell(at),
            );
        }
        assert!(areas.iter().filter(|area| area.is_pentagon()).count() >= 12);
        for area in areas {
            let band = walk_band(area);
            assert!(band.contains(&area) && band.len() > 1, "{area}");
            assert_eq!(band, brute_band(area)?, "{area}");
        }
        Ok(())
    }

    /// The band of areas by brute force: every area under them one by one, each area's band
    /// searched over its disk (`brute_band`, no walk), merged. What `Band::of` computes from the
    /// areas' edge, through the walk, must be exactly this.
    fn band_area_by_area(areas: &Regions) -> Result<Regions, String> {
        let mut cells = Vec::new();
        for listed in areas.iter() {
            for area in
                tally_wire::rendezvous::areas_of(listed).map_err(|error| error.to_string())?
            {
                let cell = CellIndex::try_from(area.as_u64()).map_err(|error| error.to_string())?;
                cells.extend(brute_band(cell)?.into_iter().filter_map(region));
            }
        }
        Ok(Regions::new(cells))
    }

    /// Named compactly, areas band exactly as they do one by one: single areas, a cluster, a
    /// resolution-1 and a resolution-0 region, cells around a pentagon, a ring of regions with a
    /// hole, and the whole world (which has no edge, so nothing beyond it to find).
    #[test]
    fn a_band_from_the_areas_edge_is_the_band_area_by_area() -> Result<(), String> {
        let text = |error: tally_wire::WireError| error.to_string();
        let cell = |lat: f64, lon: f64, resolution: u8| {
            Region::containing(&at(lat, lon), resolution).map_err(text)
        };
        let pentagon = Region::from_u64(0x0800_9fff_ffff_ffff_u64).map_err(text)?;
        let pentagon_child = pentagon.first_child(1).ok_or("no centre child")?;
        let ring: Vec<Region> = cell(47.0, 8.0, 1)?
            .ancestor(1)
            .into_iter()
            .flat_map(|centre| {
                CellIndex::try_from(centre.as_u64())
                    .map(|centre| centre.grid_ring_fast(1).flatten().collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .filter_map(region)
            .collect();
        let sets: Vec<Regions> = vec![
            regions([cell(52.1, 5.1, 3)?]),
            regions([
                cell(52.1, 5.1, 3)?,
                cell(52.6, 5.9, 3)?,
                cell(48.8, 2.3, 3)?,
            ]),
            regions([cell(33.7, -84.4, 1)?]),
            regions([cell(-33.9, 151.2, 0)?]),
            regions([pentagon_child, cell(64.1, -21.9, 2)?]),
            Regions::new(pentagon.children(2).take(20)),
            Regions::new(ring),
        ];
        for areas in sets {
            let band = Band::of(&areas);
            let expected = band_area_by_area(&areas)?;
            assert_eq!(band.regions(), expected, "{areas:?}");
            // `holds` agrees with the listed cells, at, above and below the area resolution.
            let probes: Vec<Region> = expected
                .iter()
                .flat_map(|listed| {
                    let up = listed.ancestor(listed.resolution().saturating_sub(1));
                    let down = listed.first_child(5);
                    [Some(listed), up, down]
                })
                .flatten()
                .collect();
            for probe in probes {
                let wholly = if probe.resolution() >= AREA_RESOLUTION {
                    probe
                        .ancestor(AREA_RESOLUTION)
                        .is_some_and(|area| expected.contains(area))
                } else {
                    probe
                        .children(AREA_RESOLUTION)
                        .all(|area| expected.contains(area))
                };
                assert_eq!(band.holds(probe), wholly, "{probe:?} in {areas:?}");
            }
        }
        let world: Regions = h3o::CellIndex::base_cells().filter_map(region).collect();
        let band = Band::of(&world);
        assert_eq!(band.regions(), world);
        assert!(band.beyond.is_empty());
        Ok(())
    }
}
