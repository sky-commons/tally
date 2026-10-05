//! Regions are H3 cells (RFC-0166 §3.6). A subscriber names the cells it wants, at any resolution;
//! a relay routes a receiver's batches by the cell the receiver's own declared location falls in,
//! never by where any aircraft is, so a relay decodes nothing to route. This module is the one
//! place that says whether a receiver is inside a region, so relays and consumers cannot disagree.

use h3o::{CellIndex, LatLng};

use crate::WireError;
use crate::batch::Location;

/// A region: one H3 cell, of any resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Region(CellIndex);

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
}
