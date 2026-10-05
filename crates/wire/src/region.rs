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

    /// True if the location is inside this region.
    pub fn covers(self, location: &Location) -> bool {
        lat_lng(location).is_ok_and(|point| point.to_cell(self.0.resolution()) == self.0)
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
            assert!(!region.covers(&london), "resolution {resolution}");
            assert_eq!(Region::from_u64(region.as_u64())?, region);
        }
        Ok(())
    }

    #[test]
    fn a_number_that_is_not_a_cell_is_refused() {
        assert!(Region::from_u64(0).is_err());
        assert!(Region::from_u64(u64::MAX).is_err());
    }
}
