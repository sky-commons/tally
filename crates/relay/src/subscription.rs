//! What a subscriber or engine asked for (RFC-0166 §3.6), and the one rule for whether a record
//! on the fan-out is in it.

use tally_wire::{Location, Record, Region, Streams};

use crate::hub::Item;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscription {
    pub streams: Streams,
    /// Empty is the whole world.
    pub regions: Vec<Region>,
}

impl Default for Subscription {
    /// Before any `Subscribe`, every receiver's raw batches, as wire version 1's first
    /// subscribers had.
    fn default() -> Self {
        Self {
            streams: Streams::RAW,
            regions: Vec::new(),
        }
    }
}

impl Subscription {
    pub fn wants(&self, item: &Item) -> bool {
        match &*item.record {
            // A receiver's description travels with its raw batches, under the same regions.
            Record::Batch(_) | Record::ReceiverInfo(_) => {
                self.streams.contains(Streams::RAW) && self.covers(item.place.as_ref())
            }
            // Version 1 serves the deduplicated stream for the whole world only: one copy of a
            // message heard by receivers in several regions has no single receiver to route by,
            // so regions apply to the raw stream alone.
            Record::RelayBatch(_) => self.streams.contains(Streams::DEDUPLICATED),
            // Positions are never routed by where the aircraft is, so they too are whole-world.
            Record::Positions(_) => self.streams.contains(Streams::POSITIONS),
            _ => false,
        }
    }

    /// Whether a receiver at `place` is inside the subscription. A receiver that declared no
    /// location is in the whole world and in no region.
    fn covers(&self, place: Option<&Location>) -> bool {
        self.regions.is_empty()
            || place.is_some_and(|place| self.regions.iter().any(|region| region.covers(place)))
    }
}

/// What a link to another relay carries: everything but the deduplicated stream, which every
/// relay derives for itself.
pub fn peer_wants(item: &Item) -> bool {
    matches!(
        &*item.record,
        Record::Batch(_) | Record::ReceiverInfo(_) | Record::Positions(_)
    )
}
