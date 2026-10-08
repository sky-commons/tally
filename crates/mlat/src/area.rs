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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use h3o::{CellIndex, LatLng};
use tally_mlat_solver::geo;
use tally_mlat_solver::tile::{LEVELS, Tile, footprint_mm};
use tally_wire::{Location, Region};

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

/// Whether some point of `cell` may be within the reach of some point of `area`. Symmetric (the
/// distance between the centres less both circumradii, against the reach), so a cell is in an
/// area's band exactly when the area is in the cell's.
fn near(area: CellIndex, cell: CellIndex) -> bool {
    LatLng::from(cell).distance_km(LatLng::from(area))
        - circumradius_km(cell)
        - circumradius_km(area)
        <= reach_km()
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
    let mut cells = vec![area];
    for ring in 1.. {
        let found: Vec<CellIndex> = area
            .grid_ring_fast(ring)
            .flatten()
            .filter(|cell| near(area, *cell))
            .collect();
        if found.is_empty() {
            break;
        }
        cells.extend(found);
    }
    cells.sort_unstable();
    cells.dedup();
    let band: Arc<[CellIndex]> = cells.into();
    if let Ok(mut held) = memo.lock() {
        if held.len() >= BANDS_REMEMBERED {
            held.clear();
        }
        held.insert(u64::from(area), Arc::clone(&band));
    }
    band
}

/// Areas whose band is remembered, at most: every area of the world at the area resolution
/// (41,162 cells at resolution 3, each band about a hundred and fifty cells, some 50 MB at the
/// very most, for a relay solving the whole world), and room beside them.
const BANDS_REMEMBERED: usize = 65_536;
static BANDS: OnceLock<Mutex<HashMap<u64, Arc<[CellIndex]>>>> = OnceLock::new();

/// The cells an MLAT relay for some areas holds the raw of: each area's band, as a set of cells at
/// that area's resolution. The one definition behind [`border_band`] (the cells a relay asks its
/// neighbours for and lets its engine take part) and [`Band::holds`] (what a relay grants an
/// engine), so the two cannot disagree.
#[derive(Clone, Debug, Default)]
pub struct Band {
    /// By resolution, the cells of every area's band at that resolution.
    cells: BTreeMap<u8, HashSet<u64>>,
}

/// The finest a region named against a band may be split, in resolutions, to be checked cell by
/// cell: a region three resolutions coarser than the band's areas is 343 of them.
const SPLIT_AT_MOST: u8 = 3;

impl Band {
    /// The band of `areas`: every cell any of them reaches.
    pub fn of(areas: &[Region]) -> Self {
        let mut band = Self::default();
        for area in areas {
            let Ok(cell) = CellIndex::try_from(area.as_u64()) else {
                continue;
            };
            band.cells
                .entry(area.resolution())
                .or_default()
                .extend(band_of(cell).iter().map(|cell| u64::from(*cell)));
        }
        band
    }

    pub fn is_empty(&self) -> bool {
        self.cells.values().all(HashSet::is_empty)
    }

    /// Whether every place in `region` is in the band: at some resolution the band is kept at,
    /// `region`'s cell there (if finer) is in it, or every cell under `region` there is. A region
    /// coarser than that by more than `SPLIT_AT_MOST` resolutions is not held, whatever it covers.
    pub fn holds(&self, region: Region) -> bool {
        let Ok(cell) = CellIndex::try_from(region.as_u64()) else {
            return false;
        };
        self.cells.iter().any(|(resolution, cells)| {
            let Ok(at) = h3o::Resolution::try_from(*resolution) else {
                return false;
            };
            if region.resolution() >= *resolution {
                return cell
                    .parent(at)
                    .is_some_and(|parent| cells.contains(&u64::from(parent)));
            }
            *resolution - region.resolution() <= SPLIT_AT_MOST
                && cell
                    .children(at)
                    .all(|child| cells.contains(&u64::from(child)))
        })
    }

    /// The band as few cells as cover it (full sets of siblings merged into their parent), every
    /// cell inside a coarser one listed left out, sorted.
    pub fn regions(&self) -> Vec<Region> {
        let mut out: Vec<CellIndex> = Vec::new();
        for cells in self.cells.values() {
            let mut cells: Vec<CellIndex> = cells
                .iter()
                .filter_map(|cell| CellIndex::try_from(*cell).ok())
                .collect();
            cells.sort_unstable();
            let mut compacted = cells.clone();
            if CellIndex::compact(&mut compacted).is_ok() {
                cells = compacted;
            }
            out.extend(cells);
        }
        // A cell inside a coarser one listed (bands of areas of different resolutions) adds
        // nothing: each cell's ancestors are looked up, never every pair compared.
        let listed: HashSet<u64> = out.iter().map(|cell| u64::from(*cell)).collect();
        let mut kept: Vec<Region> = out
            .into_iter()
            .filter(|cell| {
                (0..u8::from(cell.resolution())).all(|coarser| {
                    h3o::Resolution::try_from(coarser)
                        .ok()
                        .and_then(|at| cell.parent(at))
                        .is_none_or(|parent| !listed.contains(&u64::from(parent)))
                })
            })
            .filter_map(|cell| Region::from_u64(u64::from(cell)).ok())
            .collect();
        kept.sort_unstable_by_key(|region| region.as_u64());
        kept.dedup();
        kept
    }
}

/// The cells an MLAT relay for `areas` holds the raw of: every area and its border band, as few
/// cells as cover them (full sets of siblings merged into their parent), sorted. Empty for no area.
pub fn border_band(areas: &[Region]) -> Vec<Region> {
    Band::of(areas).regions()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::{covers, owns};
    use tally_mlat_solver::geo;
    use tally_mlat_solver::tile::Tile;
    use tally_wire::Location;
    use tally_wire::rendezvous::AREA_RESOLUTION;

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
            let band = border_band(&[area]);
            for tile in tiles_of(area)? {
                if owns(&[area], tile) {
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
        let band = border_band(&[area]);
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
        let band = Band::of(&[one, two]);
        let listed = band.regions();
        assert_eq!(listed, border_band(&[one, two]));
        for cell in &listed {
            assert!(band.holds(*cell), "{cell:?}");
        }
        // A receiver's point inside is held; one 1,000 km away is not, nor is the continent.
        let inside = Region::point(&at(52.1, 9.0)).map_err(|error| error.to_string())?;
        let outside = Region::point(&at(52.1, 20.0)).map_err(|error| error.to_string())?;
        assert!(band.holds(inside));
        assert!(!band.holds(outside));
        let continent = Region::containing(&at(52.1, 5.1), 0).map_err(|error| error.to_string())?;
        assert!(!band.holds(continent));
        // Symmetric: the far edge of the band reaches back to the area.
        let edge = *listed.last().ok_or("an empty band")?;
        for edge_area in
            tally_wire::rendezvous::areas_of(edge).map_err(|error| error.to_string())?
        {
            let back = Band::of(&[edge_area]);
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
        let both = border_band(&[one, two, one]);
        assert!(border_band(&[]).is_empty());
        for (index, cell) in both.iter().enumerate() {
            for other in &both[index + 1..] {
                assert!(!cell.contains(*other) && !other.contains(*cell));
            }
        }
        // Every place either band holds, the merged band holds.
        for place in [at(52.1, 9.0), at(52.6, 13.5), at(49.0, 5.5)] {
            let either = [one, two]
                .iter()
                .any(|area| border_band(&[*area]).iter().any(|cell| cell.covers(&place)));
            assert_eq!(both.iter().any(|cell| cell.covers(&place)), either);
        }
        assert_eq!(border_band(&[two, one]), both);
        Ok(())
    }
}
