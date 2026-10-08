//! What a subscriber or engine asked for (RFC-0171 §3.6), the one rule for whether a record on
//! the fan-out is in it, and what an engine may be granted ([`engine_grant`]).

use std::ops::RangeInclusive;

use tally_mlat::area::Band;
use tally_wire::{PublicKey, Record, Region, Streams};

use crate::directory::Directory;
use crate::hub::Item;
use crate::selection::areas_solved_by;

/// The products a parent bundle carries (RFC-0174 §2.5): raw, positions, provisional positions
/// and clock models.
const BUNDLED: Streams = Streams(
    Streams::RAW.0 | Streams::POSITIONS.0 | Streams::PROVISIONAL.0 | Streams::CLOCK_MODELS.0,
);

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
            // Positions are routed by where the aircraft are, as raw is by where receivers are:
            // a client of one area is sent that area's fixes, not the world's. A fault proof goes
            // to every reader of positions, who must act on it.
            Record::Positions(_) => {
                self.streams.contains(Streams::POSITIONS) && self.places(item.points.as_deref())
            }
            Record::FaultProof(_) => self.streams.contains(Streams::POSITIONS),
            // Provisional positions go only to whoever asked for them: most readers of positions
            // want only the final ones, and every provisional is followed by one.
            Record::Provisional(_) => {
                self.streams.contains(Streams::PROVISIONAL) && self.places(item.points.as_deref())
            }
            // The regional product, by the area its origin signed it for (`Item::cell`).
            Record::RegionalBatch(_) => {
                self.streams.contains(Streams::REGIONAL) && self.covers(item.cell)
            }
            // The world product is the world's.
            Record::WorldPositions(_) => self.streams.contains(Streams::WORLD),
            Record::WorldPrecise(_) => self.streams.contains(Streams::WORLD_PRECISE),
            // A bundle's index, to whoever reads the parent cell it indexes (`Item::cell`), of
            // any product a bundle carries.
            Record::BundleIndex(_) => self.streams.0 & BUNDLED.0 != 0 && self.covers(item.cell),
            // A clock model by where its tile is, so a reader of an area gets the models its
            // positions cite; a part travels whole-world, as its manifest may need it anywhere.
            Record::ClockModel(_) => {
                self.streams.contains(Streams::CLOCK_MODELS) && self.places(item.points.as_deref())
            }
            Record::ClockModelPart(_) => self.streams.contains(Streams::CLOCK_MODELS),
            _ => false,
        }
    }

    /// Whether a record placing aircraft at `points` is inside the subscription: any point in a
    /// region. Unplaced (`None`), it is whole-world.
    fn places(&self, points: Option<&[Region]>) -> bool {
        match points {
            None => true,
            Some(points) => {
                self.regions.is_empty()
                    || points
                        .iter()
                        .any(|point| self.regions.iter().any(|region| region.contains(*point)))
            }
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

impl Subscription {
    /// Nothing at all: what a role is granted that may receive no stream.
    pub fn nothing() -> Self {
        Self {
            streams: Streams(0),
            regions: Vec::new(),
        }
    }
}

/// What an engine may take (RFC-0174 §2.3): an engine is another relay's MLAT taking an area's
/// raw one hop, so it is granted raw and nothing else, and only of the regions it asked for that
/// lie inside the border band of the areas it is an MLAT relay for, by the ranking every relay
/// computes alike from the offers it holds (`selection::areas_solved_by`). The whole world,
/// another product, or a region outside the band is refused: an engine reads near home, never
/// the firehose.
///
/// The work is the engine's own areas' band (each area's remembered, `tally_mlat::area`) and one
/// lookup per region asked, never a band per region asked: what it costs is bounded by what the
/// engine offers, not by what it names.
pub fn engine_grant(
    directory: &Directory,
    engine: &PublicKey,
    asked: &Subscription,
    now_ms: u64,
) -> Subscription {
    if !asked.streams.contains(Streams::RAW) || asked.regions.is_empty() {
        return Subscription::nothing();
    }
    let band = Band::of(&areas_solved_by(directory, engine, now_ms));
    let regions: Vec<Region> = asked
        .regions
        .iter()
        .filter(|region| band.holds(**region))
        .copied()
        .collect();
    if regions.is_empty() {
        return Subscription::nothing();
    }
    Subscription {
        streams: Streams::RAW,
        regions,
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

/// What a link to another relay is sent from the fan-out: the directory, nothing else
/// (RFC-0174 §2.5). Every record of data reaches another relay addressed to it, over the sharing
/// groups' member links and the one-hop raw links, never a relay link's fan-out.
pub fn directory_wants(item: &Item) -> bool {
    matches!(
        &*item.record,
        Record::ProviderOffer(_) | Record::EvidenceBundle(_)
    )
}

/// What a relay link may carry in (RFC-0174 §2.5): the directory (offers and queries), the probes
/// and delivery checks, and the have-summaries that let groups find gaps. Anything else on it is
/// not taken: data is taken only from a member link, a feeder or an engine.
pub fn on_directory_link(record: &Record) -> bool {
    matches!(
        record,
        Record::ProviderOffer(_)
            | Record::ProviderQuery(_)
            | Record::EvidenceBundle(_)
            | Record::Echo(_)
            | Record::EchoReply(_)
            | Record::DeliveryQuery(_)
            | Record::DeliveryAnswer(_)
            | Record::HaveSummary(_)
            | Record::Heartbeat
            | Record::Goodbye { .. }
            | Record::Redirect { .. }
            | Record::RelayList(_)
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tally_wire::rendezvous::AREA_RESOLUTION;
    use tally_wire::{
        Identity, Location, Positions, ProviderOffer, ProviderOfferContent, Record, Region,
        SolutionsContent, Streams,
    };

    use super::{Subscription, engine_grant};
    use crate::directory::{Directory, Group};
    use crate::egress::{Class, Kind};
    use crate::hub::Item;

    const NOW: u64 = 1_791_244_800_000;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn area_at(lat_e7: i32, lon_e7: i32) -> Result<Region, String> {
        Region::containing(
            &Location {
                lat_e7,
                lon_e7,
                alt_m: 0,
                precision_m: 0,
            },
            AREA_RESOLUTION,
        )
        .map_err(text)
    }

    fn offer(relay: &Identity, cell: Region, cores: u16) -> Result<ProviderOffer, String> {
        ProviderOffer::sign(
            relay,
            &ProviderOfferContent {
                address: "relay.example:10900".to_owned(),
                cell,
                products: Streams::RAW,
                stripes_of: 1,
                stripes: 1,
                mlat_cores: cores,
                feeder_slots: 10,
                network: 64_512,
                issued_ms: NOW,
                expires_ms: NOW + 600_000,
            },
        )
        .map_err(text)
    }

    #[test]
    fn an_engine_is_granted_raw_only_inside_the_band_of_an_area_it_solves() -> Result<(), String> {
        // Atlanta's area, solved by the engine's relay (the only MLAT offer for it), and Sydney's,
        // which it does not solve.
        let atlanta = area_at(337_490_000, -843_880_000)?;
        let sydney = area_at(-338_680_000, 1_512_090_000)?;
        let (engine, other) = (
            Identity::generate().map_err(text)?,
            Identity::generate().map_err(text)?,
        );
        let directory = Directory::new();
        directory.hold_verified(offer(&engine, atlanta, 8)?, Group::V4(1), NOW)?;
        directory.hold_verified(offer(&other, sydney, 8)?, Group::V4(2), NOW)?;
        let band = tally_mlat::area::border_band(&tally_wire::Regions::new([atlanta]));
        let edge = *band.cells().last().ok_or("an empty band")?;
        let asked = Subscription {
            streams: Streams::RAW.with(Streams::POSITIONS).with(Streams::WORLD),
            regions: vec![atlanta, edge, sydney],
        };
        assert_eq!(
            engine_grant(&directory, &engine.public(), &asked, NOW),
            Subscription {
                streams: Streams::RAW,
                regions: vec![atlanta, edge],
            }
        );
        // The world, or anything but raw, is nothing; so is every region for a key that solves
        // no area, or one whose offer has lapsed.
        let world = Subscription {
            streams: Streams::RAW,
            regions: Vec::new(),
        };
        assert_eq!(
            engine_grant(&directory, &engine.public(), &world, NOW),
            Subscription::nothing()
        );
        let positions = Subscription {
            streams: Streams::POSITIONS,
            regions: vec![atlanta],
        };
        assert_eq!(
            engine_grant(&directory, &engine.public(), &positions, NOW),
            Subscription::nothing()
        );
        assert_eq!(
            engine_grant(&directory, &other.public(), &asked, NOW),
            Subscription {
                streams: Streams::RAW,
                regions: vec![sydney],
            }
        );
        let stranger = Identity::generate().map_err(text)?;
        assert_eq!(
            engine_grant(&directory, &stranger.public(), &asked, NOW),
            Subscription::nothing()
        );
        assert_eq!(
            engine_grant(&directory, &engine.public(), &asked, NOW + 600_001),
            Subscription::nothing()
        );
        Ok(())
    }

    /// The grant is one band over the engine's own areas and a lookup per region asked: an MLAT
    /// relay for fifteen areas at 52 degrees north, asking for their whole band (cells as coarse as
    /// resolution 1, each the band of dozens of areas), is granted it at once. It once took a
    /// band per region asked, minutes of a runtime worker for one `Subscribe`, during which
    /// every session on that worker stalled.
    #[test]
    fn an_engine_asking_for_its_whole_band_is_granted_it_at_once() -> Result<(), String> {
        let engine = Identity::generate().map_err(text)?;
        let directory = Directory::new();
        let mut areas = Vec::new();
        for north in -2..=2 {
            for east in -2..=2 {
                let area = area_at(
                    521_000_000 + north * 6_000_000,
                    51_000_000 + east * 10_000_000,
                )?;
                if !areas.contains(&area) {
                    areas.push(area);
                    directory.hold_verified(offer(&engine, area, 8)?, Group::V4(1), NOW)?;
                }
            }
        }
        let band = tally_mlat::area::border_band(&tally_wire::Regions::new(areas.clone()));
        assert!(
            band.iter()
                .any(|region| region.resolution() < AREA_RESOLUTION - 1)
        );
        let started = std::time::Instant::now();
        for chunk in band.cells().chunks(tally_wire::record::MAX_REGIONS) {
            let asked = Subscription {
                streams: Streams::RAW,
                regions: chunk.to_vec(),
            };
            assert_eq!(
                engine_grant(&directory, &engine.public(), &asked, NOW),
                asked
            );
        }
        // Milliseconds; minutes before. Generous, for a loaded machine.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        Ok(())
    }

    fn provisional() -> Result<Record, String> {
        let engine = Identity::generate().map_err(|error| error.to_string())?;
        Positions::sign_provisional(
            &engine,
            &SolutionsContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 3,
                solutions: Vec::new(),
            },
        )
        .map(Record::Provisional)
        .map_err(|error| error.to_string())
    }

    #[test]
    fn provisional_positions_are_sent_only_when_asked_for_and_below_the_final_ones()
    -> Result<(), String> {
        let item = Item {
            source: 0,
            record: Arc::new(provisional()?),
            cell: None,
            points: None,
            decoded: None,
            stamp_ms: 0,
        };
        let asked = |streams: Streams| {
            Subscription {
                streams,
                regions: Vec::new(),
            }
            .wants(&item)
        };
        assert!(!asked(Streams::POSITIONS.with(Streams::CLOCK_MODELS)));
        assert!(asked(Streams::PROVISIONAL));
        assert!(!super::directory_wants(&item));
        // To a relay link, the class held for them; to a plain subscriber, a taker's.
        assert_eq!(Class::of(&item.record, Kind::Relay), Class::Provisional);
        assert_eq!(Class::of(&item.record, Kind::Taker), Class::Taker);
        Ok(())
    }
}
