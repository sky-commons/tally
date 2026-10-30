//! Regions are H3 cells (RFC-0171 §3.6). A subscriber names the cells it wants, at any resolution;
//! a relay routes a receiver's batches by the cell the receiver's own declared location falls in,
//! never by where any aircraft is, so a relay decodes nothing to route. This module is the one
//! place that says whether a receiver is inside a region, so relays and consumers cannot disagree.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use h3o::{CellIndex, LatLng};

use crate::WireError;
use crate::batch::Location;

/// A region: one H3 cell, of any resolution. Ordered by its index as a `u64` ([`Region::as_u64`]),
/// so every party orders regions alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Region(CellIndex);

impl Ord for Region {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_u64().cmp(&other.as_u64())
    }
}

impl PartialOrd for Region {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Region {
    pub fn from_u64(index: u64) -> Result<Self, WireError> {
        CellIndex::try_from(index)
            .map(Self)
            .map_err(|_| WireError::Invalid {
                field: "H3 cell",
                value: index,
            })
    }

    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }

    /// The cell's resolution, 0 (coarsest) to 15: its level in the area tree.
    pub fn resolution(self) -> u8 {
        u8::from(self.0.resolution())
    }

    /// The region of the given resolution (0, coarsest, to 15) a location falls in.
    pub fn containing(location: &Location, resolution: u8) -> Result<Self, WireError> {
        let resolution = h3o::Resolution::try_from(resolution).map_err(|_| WireError::Invalid {
            field: "H3 resolution",
            value: u64::from(resolution),
        })?;
        Ok(Self(lat_lng(location)?.to_cell(resolution)))
    }

    /// The finest cell a location falls in. Computed once per receiver and kept, so a region test
    /// is integer work (`contains`), never a projection.
    pub fn point(location: &Location) -> Result<Self, WireError> {
        Self::containing(location, 15)
    }

    /// The cell of `resolution` this one lies in: itself at its own resolution, `None` for a
    /// finer resolution than its own (or one past 15).
    pub fn ancestor(self, resolution: u8) -> Option<Self> {
        let resolution = h3o::Resolution::try_from(resolution).ok()?;
        self.0.parent(resolution).map(Self)
    }

    /// True if `cell` (a finer or equal cell, such as a receiver's `point`) is inside this region.
    pub fn contains(self, cell: Region) -> bool {
        cell.0.parent(self.0.resolution()) == Some(self.0)
    }

    /// The range of finest-cell numbers inside this region: a `point` is in the region exactly when
    /// its number is in the range. H3 numbers a cell's descendants by appending one 3-bit digit (0
    /// to 6) per finer resolution, so every finest descendant shares the region's prefix, and the
    /// smallest and largest are the region with every remaining digit 0 and 6. A relay can then
    /// answer "which receivers are in these regions" with range reads over receivers sorted by
    /// point, never by testing each one.
    pub fn span(self) -> std::ops::RangeInclusive<u64> {
        const RESOLUTION_SHIFT: u32 = 52;
        const RESOLUTION_MASK: u64 = 0xf << RESOLUTION_SHIFT;
        let resolution = u32::from(u8::from(self.0.resolution()));
        let mut low = (u64::from(self.0) & !RESOLUTION_MASK) | (15 << RESOLUTION_SHIFT);
        let mut high = low;
        for digit in resolution + 1..=15 {
            let shift = (15 - digit) * 3;
            low &= !(0b111 << shift);
            high = (high & !(0b111 << shift)) | (0b110 << shift);
        }
        low..=high
    }

    /// True if the location is inside this region.
    pub fn covers(self, location: &Location) -> bool {
        Self::point(location).is_ok_and(|point| self.contains(point))
    }

    /// The cells of `resolution` this one is made of: seven a resolution finer, or six under a
    /// pentagon, and so on down. Empty for a resolution coarser than its own (or past 15); itself
    /// at its own.
    pub fn children(self, resolution: u8) -> impl Iterator<Item = Self> {
        let resolution = h3o::Resolution::try_from(resolution)
            .ok()
            .filter(|at| *at >= self.0.resolution());
        resolution
            .into_iter()
            .flat_map(move |at| self.0.children(at).map(Self))
    }

    /// How many cells of `resolution` this one is made of (`children`).
    pub fn children_count(self, resolution: u8) -> u64 {
        h3o::Resolution::try_from(resolution)
            .ok()
            .filter(|at| *at >= self.0.resolution())
            .map_or(0, |at| self.0.children_count(at))
    }

    /// The finest-numbered of the cells of `resolution` this one is made of (every remaining digit
    /// 0, its centre child): the smallest number among `children(resolution)`.
    pub fn first_child(self, resolution: u8) -> Option<Self> {
        let at = h3o::Resolution::try_from(resolution).ok()?;
        self.0.center_child(at).map(Self)
    }
}

/// H3's resolution-0 cells: the whole world, at its coarsest, is this many cells.
pub const BASE_CELLS: usize = 122;

/// A set of places, held as the fewest cells that cover it (RFC-0181): no cell inside another
/// listed, and every full set of siblings merged into their parent, recursively. So two `Regions`
/// covering the same places are equal, whatever cells they were named by, and one covering the
/// whole world is the 122 resolution-0 cells. Membership is decided by ancestor (a cell is in the
/// set when it, or the cell of one of the set's resolutions it lies in, is listed), so a question
/// costs a lookup per resolution the set uses, never a walk over what it covers. Cheap to clone.
#[derive(Clone, Default)]
pub struct Regions {
    /// The cells, sorted by number.
    cells: Arc<[Region]>,
    /// The cells' numbers, and the resolutions they use (bit `r` for resolution `r`).
    index: Arc<HashSet<u64>>,
    resolutions: u16,
}

impl Regions {
    /// The places `cells` cover, as the fewest cells that cover them.
    pub fn new(cells: impl IntoIterator<Item = Region>) -> Self {
        // Coarsest first, so a cell inside one already kept is dropped.
        let mut by_resolution: BTreeMap<u8, HashSet<u64>> = BTreeMap::new();
        let mut sorted: Vec<Region> = cells.into_iter().collect();
        sorted.sort_by_key(|cell| (cell.resolution(), cell.as_u64()));
        let mut resolutions = 0u16;
        for cell in sorted {
            let inside = (0..cell.resolution())
                .filter(|resolution| resolutions & (1 << resolution) != 0)
                .filter_map(|resolution| cell.ancestor(resolution))
                .any(|ancestor| {
                    by_resolution
                        .get(&ancestor.resolution())
                        .is_some_and(|cells| cells.contains(&ancestor.as_u64()))
                });
            if !inside {
                by_resolution
                    .entry(cell.resolution())
                    .or_default()
                    .insert(cell.as_u64());
                resolutions |= 1 << cell.resolution();
            }
        }
        // Finest first, every full set of siblings becomes its parent, which may complete a set a
        // resolution coarser. No cell is inside another, so a parent's children counted are
        // distinct and none of them is listed coarser.
        for resolution in (1..=15u8).rev() {
            let Some(cells) = by_resolution.get(&resolution) else {
                continue;
            };
            let mut siblings: HashMap<u64, Vec<u64>> = HashMap::new();
            for cell in cells {
                if let Some(parent) = Region::from_u64(*cell)
                    .ok()
                    .and_then(|cell| cell.ancestor(resolution - 1))
                {
                    siblings.entry(parent.as_u64()).or_default().push(*cell);
                }
            }
            let full: Vec<(u64, Vec<u64>)> = siblings
                .into_iter()
                .filter(|(parent, children)| {
                    Region::from_u64(*parent).is_ok_and(|parent| {
                        parent.children_count(resolution) == children.len() as u64
                    })
                })
                .collect();
            for (parent, children) in full {
                if let Some(cells) = by_resolution.get_mut(&resolution) {
                    for child in children {
                        cells.remove(&child);
                    }
                }
                by_resolution
                    .entry(resolution - 1)
                    .or_default()
                    .insert(parent);
            }
        }
        let mut cells: Vec<Region> = by_resolution
            .values()
            .flatten()
            .filter_map(|cell| Region::from_u64(*cell).ok())
            .collect();
        cells.sort_unstable_by_key(|cell| cell.as_u64());
        let index: HashSet<u64> = cells.iter().map(|cell| cell.as_u64()).collect();
        let resolutions = cells
            .iter()
            .fold(0u16, |bits, cell| bits | (1 << cell.resolution()));
        Self {
            cells: cells.into(),
            index: Arc::new(index),
            resolutions,
        }
    }

    /// The whole world: the `BASE_CELLS` resolution-0 cells.
    pub fn world() -> Self {
        Self::new(CellIndex::base_cells().map(Region))
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// How many cells the set is held as.
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// The cells, sorted by number: the fewest that cover the set.
    pub fn cells(&self) -> &[Region] {
        &self.cells
    }

    pub fn iter(&self) -> impl Iterator<Item = Region> + '_ {
        self.cells.iter().copied()
    }

    /// Whether `cell` lies wholly inside the set: it, or one of the cells it lies in, is listed.
    /// A cell only partly inside (coarser than the cells listed under it) is not.
    pub fn contains(&self, cell: Region) -> bool {
        (0..=cell.resolution())
            .filter(|resolution| self.resolutions & (1 << resolution) != 0)
            .filter_map(|resolution| cell.ancestor(resolution))
            .any(|ancestor| self.index.contains(&ancestor.as_u64()))
    }

    /// Whether some place in `cell` is in the set: it lies inside the set, or a cell listed lies
    /// inside it.
    pub fn touches(&self, cell: Region) -> bool {
        self.contains(cell) || self.cells.iter().any(|listed| cell.contains(*listed))
    }

    /// Whether the location is inside the set.
    pub fn covers(&self, location: &Location) -> bool {
        Region::point(location).is_ok_and(|point| self.contains(point))
    }
}

impl PartialEq for Regions {
    fn eq(&self, other: &Self) -> bool {
        self.cells == other.cells
    }
}

impl Eq for Regions {}

impl std::fmt::Debug for Regions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.cells.iter()).finish()
    }
}

impl FromIterator<Region> for Regions {
    fn from_iter<I: IntoIterator<Item = Region>>(cells: I) -> Self {
        Self::new(cells)
    }
}

fn lat_lng(location: &Location) -> Result<LatLng, WireError> {
    LatLng::new(
        f64::from(location.lat_e7) / 1e7,
        f64::from(location.lon_e7) / 1e7,
    )
    .map_err(|_| WireError::Invalid {
        field: "location",
        value: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(lat: f64, lon: f64) -> Location {
        Location {
            lat_e7: (lat * 1e7) as i32,
            lon_e7: (lon * 1e7) as i32,
            alt_m: 0,
            precision_m: 0,
        }
    }

    #[test]
    fn a_region_covers_its_own_receivers_and_not_others() -> Result<(), WireError> {
        let palo_alto = at(37.44, -122.14);
        let london = at(51.5, -0.12);
        for resolution in [0, 2, 4, 7] {
            let region = Region::containing(&palo_alto, resolution)?;
            assert!(region.covers(&palo_alto), "resolution {resolution}");
            assert!(region.contains(Region::point(&palo_alto)?));
            assert!(!region.contains(Region::point(&london)?));
            assert!(!region.covers(&london), "resolution {resolution}");
            assert_eq!(Region::from_u64(region.as_u64())?, region);
        }
        Ok(())
    }

    #[test]
    fn a_regions_span_holds_exactly_the_points_inside_it() -> Result<(), WireError> {
        let places = [
            at(37.44, -122.14),
            at(51.5, -0.12),
            at(-33.9, 151.2),
            at(64.1, -21.9),
            at(0.1, 0.1),
        ];
        // A dense grid around every place, so points just inside and just outside each region's
        // edge are both tested.
        let mut grid = Vec::new();
        for place in &places {
            for step_lat in -20..=20 {
                for step_lon in -20..=20 {
                    grid.push(Location {
                        lat_e7: place.lat_e7 + step_lat * 1_000_000,
                        lon_e7: place.lon_e7 + step_lon * 1_000_000,
                        alt_m: 0,
                        precision_m: 0,
                    });
                }
            }
        }
        let points: Vec<Region> = grid.iter().map(Region::point).collect::<Result<_, _>>()?;
        for place in &places {
            for resolution in [0, 1, 3, 5, 8, 12, 15] {
                let region = Region::containing(place, resolution)?;
                let span = region.span();
                for point in &points {
                    assert_eq!(
                        span.contains(&point.as_u64()),
                        region.contains(*point),
                        "resolution {resolution}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn a_number_that_is_not_a_cell_is_refused() {
        assert!(Region::from_u64(0).is_err());
        assert!(Region::from_u64(u64::MAX).is_err());
    }

    fn base_cells() -> Vec<Region> {
        h3o::CellIndex::base_cells()
            .filter_map(|cell| Region::from_u64(u64::from(cell)).ok())
            .collect()
    }

    #[test]
    fn regions_are_the_fewest_cells_that_cover_them() -> Result<(), WireError> {
        let world = base_cells();
        assert_eq!(world.len(), BASE_CELLS);
        assert_eq!(
            Regions::world().cells(),
            Regions::new(world.clone()).cells()
        );
        // Every resolution-1 cell of the world merges back into the 122 base cells, pentagons
        // (six children) included; named twice, or with cells inside them, the same.
        let ones: Vec<Region> = world.iter().flat_map(|cell| cell.children(1)).collect();
        assert_eq!(Regions::new(ones.clone()), Regions::new(world.clone()));
        let mut nested = ones.clone();
        nested.extend(world.iter().take(5).flat_map(|cell| cell.children(3)));
        nested.extend(world.iter().take(3).copied());
        assert_eq!(Regions::new(nested), Regions::new(world.clone()));
        assert_eq!(Regions::new(world.clone()).len(), 122);
        // One child short: the parent is not listed, its six other children are.
        let base = Region::containing(&at(37.44, -122.14), 0)?;
        let mut short: Vec<Region> = base.children(1).collect();
        let missing = short.pop().ok_or(WireError::Invalid {
            field: "child",
            value: 0,
        })?;
        let regions = Regions::new(short.clone());
        assert_eq!(regions.len(), short.len());
        assert!(!regions.contains(base));
        assert!(regions.touches(base));
        assert!(!regions.contains(missing));
        for child in &short {
            assert!(regions.contains(*child));
            for finer in child.children(3) {
                assert!(regions.contains(finer));
            }
        }
        assert!(Regions::new([]).is_empty());
        Ok(())
    }

    #[test]
    fn a_location_is_in_regions_exactly_when_in_one_of_its_cells() -> Result<(), WireError> {
        let palo_alto = at(37.44, -122.14);
        let london = at(51.5, -0.12);
        let near = Region::containing(&palo_alto, 2)?;
        let regions = Regions::new([near, Region::containing(&at(-33.9, 151.2), 4)?]);
        assert!(regions.covers(&palo_alto));
        assert!(!regions.covers(&london));
        assert!(regions.contains(Region::point(&palo_alto)?));
        assert!(Regions::new(base_cells()).covers(&london));
        Ok(())
    }
}
