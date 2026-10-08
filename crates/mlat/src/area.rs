//! What an MLAT relay holds for the areas it solves (RFC-0174 §2.3): each area's border band, the
//! cells whose receivers' raw it must hold so that every tile it fits has its whole footprint in
//! hand. One definition, so the raw a relay asks its neighbours for (the region-cut raw
//! subscription, `tally_relay::selection`) and the receivers its engine lets take part
//! (`tally_relay::mlat_host`) are the same cells.
//!
//! The band's width is not a chosen number: it follows from the tiles. A relay fits the tiles
//! whose centre is in one of its areas (`crate::window::owns`), and publishes one only if it holds
//! every receiver of its footprint (`crate::window::covers`), which reaches
//! `tally_mlat_solver::tile::footprint_mm` of the top level (about 573 km) from the centre. So the
//! band is every cell that could hold a point within that reach of any point of the area. RFC-0174's
//! first "one reception radius (about 400 km)" was the reach of a tile's radius alone; the footprint
//! adds half its cube's diagonal, and a band of 400 km would leave every top-level tile unpublished.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use h3o::{CellIndex, LatLng};
use tally_mlat_solver::geo;
use tally_mlat_solver::tile::{LEVELS, Tile, footprint_mm};
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{Location, Region, Regions};

/// A tile's centre on the ground, as a location: the one projection of a tile into the area tree,
/// which decides both which area's MLAT relays fit it (`crate::window::owns`) and which region a
/// clock model of it is routed by (`tally_relay::network::model_point`).
pub fn centre(tile: Tile) -> Location {
    let centre = geo::from_ecef(geo::from_mm(tile.centre_mm()));
    Location {
        lat_e7: (centre.lat_deg * 1e7).round() as i32,
        lon_e7: (centre.lon_deg * 1e7).round() as i32,
        alt_m: 0,
        precision_m: 0,
    }
}

/// The farthest from a tile's centre a receiver of its footprint can be, kilometres.
fn reach_km() -> f64 {
    footprint_mm(LEVELS - 1) as f64 / 1e6
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
    use crate::window::{covers, owns};
    use tally_mlat_solver::geo;
    use tally_mlat_solver::tile::Tile;
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

    /// The tiles of every level whose cube holds a point of the area (its centre and its
    /// boundary's vertices, a little inside).
    fn tiles_of(area: Region) -> Result<Vec<Tile>, String> {
        let cell = CellIndex::try_from(area.as_u64()).map_err(|error| error.to_string())?;
        let centre = LatLng::from(cell);
        let mut points = vec![centre];
        for vertex in cell.boundary().iter() {
            let lat = centre.lat() + (vertex.lat() - centre.lat()) * 0.95;
            let lng = centre.lng() + (vertex.lng() - centre.lng()) * 0.95;
            points.push(LatLng::new(lat, lng).map_err(|error| error.to_string())?);
        }
        let mut tiles = Vec::new();
        for point in points {
            let ecef = geo::to_ecef(geo::Geodetic {
                lat_deg: point.lat(),
                lon_deg: point.lng(),
                height_m: 0.0,
            });
            let mm = ecef.map(|axis| (axis * 1000.0) as i64);
            for level in 0..LEVELS {
                tiles.push(Tile::containing(level, mm));
            }
        }
        Ok(tiles)
    }

    /// Every tile an area owns, at every level, has its whole footprint inside the area's band: an
    /// MLAT relay holding the band can publish every tile it is chosen to fit.
    #[test]
    fn the_band_covers_the_footprint_of_every_tile_its_area_owns() -> Result<(), String> {
        for (lat, lon) in [
            (52.1, 5.1),
            (40.4, -3.7),
            (33.7, -84.4),
            (64.1, -21.9),
            (-33.9, 151.2),
        ] {
            let area = area(lat, lon)?;
            let band = border_band(&regions([area]));
            for tile in tiles_of(area)? {
                if owns(&regions([area]), tile) {
                    assert!(covers(&band, tile), "{tile:?} at ({lat}, {lon})");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn the_band_holds_its_area_and_reaches_a_footprint_beyond_it_and_no_further()
    -> Result<(), String> {
        let area = area(52.1, 5.1)?;
        let band = border_band(&regions([area]));
        let inside = |location: &Location| band.iter().any(|cell| cell.covers(location));
        assert!(inside(&at(52.1, 5.1)));
        // 560 km east is within the top tile's reach; 1,000 km is not.
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
