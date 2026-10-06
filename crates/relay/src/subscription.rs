//! What a subscriber or engine asked for (RFC-0171 §3.6), and the one rule for whether a record
//! on the fan-out is in it.

use std::ops::RangeInclusive;

use tally_wire::{Record, Region, Streams};

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
                self.streams.contains(Streams::RAW) && self.covers(item.cell)
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

    /// Whether a receiver whose finest cell is `cell` is inside the subscription: integer work
    /// (`Region::contains`), never a projection, so a batch costs a 64-region subscriber a few
    /// hundred nanoseconds. A receiver that declared no location is in the whole world and in no
    /// region.
    fn covers(&self, cell: Option<Region>) -> bool {
        self.regions.is_empty()
            || cell.is_some_and(|cell| self.regions.iter().any(|region| region.contains(cell)))
    }
}

/// Which receivers' descriptions a subscription wants, in the shape the relay's index answers:
/// what `Subscription::wants` decides for a `ReceiverInfo`, one range read per region instead of
/// one test per receiver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Described {
    None,
    /// Every receiver, located or not.
    All,
    /// The receivers whose finest cell's number is in one of these ranges: disjoint and in
    /// order, so no receiver is read twice.
    Within(Vec<RangeInclusive<u64>>),
}

impl Subscription {
    pub fn described(&self) -> Described {
        if !self.streams.contains(Streams::RAW) {
            return Described::None;
        }
        if self.regions.is_empty() {
            return Described::All;
        }
        let mut spans: Vec<RangeInclusive<u64>> =
            self.regions.iter().map(|region| region.span()).collect();
        spans.sort_by_key(|span| *span.start());
        // Two cells' spans are nested or disjoint; a region named twice, or inside another, is
        // folded into the one around it.
        let mut merged: Vec<RangeInclusive<u64>> = Vec::with_capacity(spans.len());
        for span in spans {
            match merged.last_mut() {
                Some(last) if *span.start() <= *last.end() => {
                    let end = (*last.end()).max(*span.end());
                    *last = *last.start()..=end;
                }
                _ => merged.push(span),
            }
        }
        Described::Within(merged)
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
