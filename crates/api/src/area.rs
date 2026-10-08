//! The viewport an aircraft query names, and the readsb boxes that answer it.

use std::fmt;

/// The widest and tallest viewport served, in degrees, so one query never asks for the world.
pub const MAX_SPAN_DEG: f64 = 60.0;

/// A checked viewport: south below north, each edge on the globe, at most `MAX_SPAN_DEG` each
/// way. `west` greater than `east` crosses the antimeridian.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Area {
    west: f64,
    south: f64,
    east: f64,
    north: f64,
}

/// One box in readsb's own order (`?box=south,north,west,east`), never crossing the antimeridian.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReadsbBox {
    pub south: f64,
    pub north: f64,
    pub west: f64,
    pub east: f64,
}

impl fmt::Display for ReadsbBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},{},{},{}",
            self.south, self.north, self.west, self.east
        )
    }
}

impl Area {
    pub fn new(west: f64, south: f64, east: f64, north: f64) -> Result<Self, String> {
        let edges = [west, south, east, north];
        if edges.iter().any(|edge| !edge.is_finite()) {
            return Err("every edge must be a number".to_owned());
        }
        if !(-90.0..=90.0).contains(&south) || !(-90.0..=90.0).contains(&north) {
            return Err("south and north must be within -90 and 90".to_owned());
        }
        if !(-180.0..=180.0).contains(&west) || !(-180.0..=180.0).contains(&east) {
            return Err("west and east must be within -180 and 180".to_owned());
        }
        if south >= north {
            return Err("south must be below north".to_owned());
        }
        if west == east {
            return Err("west and east must differ".to_owned());
        }
        let area = Self {
            west,
            south,
            east,
            north,
        };
        if north - south > MAX_SPAN_DEG || area.width() > MAX_SPAN_DEG {
            return Err(format!(
                "a box spans at most {MAX_SPAN_DEG} degrees each way"
            ));
        }
        Ok(area)
    }

    /// Degrees of longitude from west to east, eastward.
    pub fn width(&self) -> f64 {
        if self.west < self.east {
            self.east - self.west
        } else {
            self.east + 360.0 - self.west
        }
    }

    /// Whether a position is inside: south and west edges included, north and east excluded, so
    /// a position on a shared edge is in one viewport of a tiling.
    pub fn contains(&self, lat: f64, lon: f64) -> bool {
        let across = if self.west < self.east {
            (self.west..self.east).contains(&lon)
        } else {
            lon >= self.west || lon < self.east
        };
        (self.south..self.north).contains(&lat) && across
    }

    /// The readsb boxes that cover it: one, or two either side of the antimeridian.
    pub fn boxes(&self) -> Vec<ReadsbBox> {
        let part = |west, east| ReadsbBox {
            south: self.south,
            north: self.north,
            west,
            east,
        };
        if self.west < self.east {
            vec![part(self.west, self.east)]
        } else {
            vec![part(self.west, 180.0), part(-180.0, self.east)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_is_inside_on_either_side_of_the_antimeridian() -> Result<(), String> {
        let plain = Area::new(-123.0, 37.0, -121.0, 38.0)?;
        assert!(plain.contains(37.5, -122.0) && !plain.contains(37.5, -120.0));
        let across = Area::new(170.0, -10.0, -170.0, 10.0)?;
        assert!(across.contains(0.0, 175.0) && across.contains(0.0, -175.0));
        assert!(!across.contains(0.0, 0.0) && !across.contains(20.0, 175.0));
        Ok(())
    }

    #[test]
    fn a_box_is_checked_edge_by_edge_and_held_to_sixty_degrees() {
        assert!(Area::new(-123.0, 37.0, -121.0, 38.0).is_ok());
        assert!(Area::new(-120.0, 0.0, -60.0, 60.0).is_ok());
        for (west, south, east, north) in [
            // West of east the long way round: 358 degrees.
            (-121.0, 37.0, -123.0, 38.0),
            (-120.0, 0.0, -59.9, 10.0),
            (-120.0, 0.0, -110.0, 60.1),
            (-120.0, 38.0, -110.0, 37.0),
            (-120.0, 37.0, -120.0, 38.0),
            (-181.0, 37.0, -120.0, 38.0),
            (-120.0, -91.0, -110.0, 0.0),
            (f64::NAN, 37.0, -120.0, 38.0),
            (-120.0, 37.0, f64::INFINITY, 38.0),
        ] {
            assert!(
                Area::new(west, south, east, north).is_err(),
                "{west},{south},{east},{north}"
            );
        }
    }

    #[test]
    fn a_box_across_the_antimeridian_is_two_readsb_boxes() -> Result<(), String> {
        let area = Area::new(170.0, -20.0, -170.0, -10.0)?;
        assert!((area.width() - 20.0).abs() < 1e-9);
        let boxes: Vec<String> = area.boxes().iter().map(ToString::to_string).collect();
        assert_eq!(boxes, ["-20,-10,170,180", "-20,-10,-180,-170"]);
        // Wide the other way round is refused.
        assert!(Area::new(10.0, 0.0, -10.0, 10.0).is_err());
        Ok(())
    }

    #[test]
    fn a_box_is_put_in_readsbs_order() -> Result<(), String> {
        let area = Area::new(-123.5, 37.25, -121.0, 38.0)?;
        let boxes: Vec<String> = area.boxes().iter().map(ToString::to_string).collect();
        assert_eq!(boxes, ["37.25,38,-123.5,-121"]);
        Ok(())
    }
}
