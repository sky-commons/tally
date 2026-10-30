//! Areas (crate docs, § Areas): where a pair model is fitted and which ones a fix cites. A
//! receiver's area is its public cell's parent at `tally_wire::rendezvous::AREA_RESOLUTION`
//! (RFC-0174 §2.2), the area it is grouped, selected and published in; an area's members are its
//! receivers and every receiver one of them keeps as a pair's other end (`pair::Network`); a fix
//! cites the model of each area its used hearers are in (`pair::Models`). Each is a function of
//! signed site records and of the fix's own hearers alone, so every holder of the same records
//! decides it the same.

use tally_wire::{Region, rendezvous};

use crate::obs::Site;

/// The area a receiver is in: its public cell's area (`rendezvous::area_of_public`), never the
/// area its site lies in (H3 cells do not nest exactly, and the two can differ). `None` for a
/// site whose public cell cannot be computed.
pub fn of(site: &Site) -> Option<Region> {
    Region::public_cell(&site.location)
        .ok()
        .and_then(rendezvous::area_of_public)
}
