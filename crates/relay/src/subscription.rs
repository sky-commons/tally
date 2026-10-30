//! What a subscriber or engine asked for (RFC-0171 §3.6), the one rule for whether a record on
//! the fan-out is in it, and what an engine may be granted ([`engine_grant`]).

use std::ops::RangeInclusive;
use std::sync::Arc;

use tally_mlat::area::Band;
use tally_wire::{ClientRecord, PublicKey, Record, Region, Streams};

use crate::directory::Directory;
use crate::hub::Item;
use crate::selection::areas_solved_by;

/// The products a parent bundle carries (RFC-0174 §2.5): raw, positions and clock models.
const BUNDLED: Streams = Streams(Streams::RAW.0 | Streams::POSITIONS.0 | Streams::CLOCK_MODELS.0);

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
    /// Whether a relay-role subscriber (an engine) wants `item`: receivers routed by their sites'
    /// finest cells (`Item::cell`).
    pub fn wants(&self, item: &Item) -> bool {
        match &*item.record {
            // A receiver's description, and its site, travel with its raw batches, under the same
            // regions.
            Record::Batch(_) | Record::ReceiverInfo(_) | Record::ReceiverSite(_) => {
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
            // The regional product, by the area its origin signed it for (`Item::cell`).
            Record::RegionalBatch(_) => {
                self.streams.contains(Streams::REGIONAL) && self.covers(item.cell)
            }
            // The world product is the world's.
            Record::WorldPositions(_) => self.streams.contains(Streams::WORLD),
            // A bundle's index, to whoever reads the parent cell it indexes (`Item::cell`), of
            // any product a bundle carries.
            Record::BundleIndex(_) => self.streams.0 & BUNDLED.0 != 0 && self.covers(item.cell),
            // A clock model by its area, so a reader of an area and its band (an MLAT relay's raw
            // link, `selection::RawSource`) gets the models of the areas its fixes cite; a part
            // travels whole-world, as its manifest may need it anywhere.
            Record::ClockModel(_) => {
                self.streams.contains(Streams::CLOCK_MODELS)
                    && self.overlaps(item.points.as_deref())
            }
            Record::ClockModelPart(_) => self.streams.contains(Streams::CLOCK_MODELS),
            _ => false,
        }
    }

    /// What a client may subscribe to of `self` (`ClientSubscription`, the only way one is
    /// made): each region no finer than a receiver's public cell (`Region::clamped_to_public`),
    /// named once. A finer region would let a client test which receivers lie inside it, and so
    /// place one finer than its public cell.
    pub fn for_client(self) -> ClientSubscription {
        let mut regions: Vec<Region> = Vec::with_capacity(self.regions.len());
        for region in self.regions {
            let clamped = region.clamped_to_public();
            if !regions.contains(&clamped) {
                regions.push(clamped);
            }
        }
        ClientSubscription(Self {
            streams: self.streams,
            regions,
        })
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

    /// Whether a record of the cells `cells` (a model's area) overlaps the subscription: a cell
    /// in a region or a region in a cell. Unplaced (`None`), it is whole-world.
    fn overlaps(&self, cells: Option<&[Region]>) -> bool {
        match cells {
            None => true,
            Some(cells) => {
                self.regions.is_empty()
                    || cells.iter().any(|cell| {
                        self.regions
                            .iter()
                            .any(|region| region.contains(*cell) || cell.contains(*region))
                    })
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

/// A client's subscription: its regions no finer than a public cell, made only by
/// [`Subscription::for_client`]. It routes a [`ClientItem`] and nothing else, so no client's
/// routing can read what the relay alone holds of a record (`Item::cell`, a receiver's site).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientSubscription(Subscription);

impl ClientSubscription {
    pub fn streams(&self) -> Streams {
        self.0.streams
    }

    /// Its regions, each no finer than a public cell. Empty is the whole world.
    pub fn regions(&self) -> &[Region] {
        &self.0.regions
    }

    /// As the plain subscription it is, clamped: what the directory's client answer and the
    /// credit read.
    pub fn as_subscription(&self) -> &Subscription {
        &self.0
    }

    /// The plain subscription it is, clamped: what the credit narrows (`Credit::admit`) and a
    /// session's updates carry. Clamped again when it is made a client's (`for_client`).
    pub fn into_subscription(self) -> Subscription {
        self.0
    }

    /// Whether the client wants `item`: by its client form's kind and the client's streams, and
    /// by its client place ([`ClientPlace`]), never by anything finer than a public cell.
    pub fn serves(&self, item: &ClientItem) -> bool {
        let streams = self.0.streams;
        match &*item.record {
            // A client is sent no raw: its receivers' public descriptions are what it is sent of
            // the raw stream.
            ClientRecord::ReceiverInfo(_) => {
                streams.contains(Streams::RAW) && self.holds(&item.place)
            }
            ClientRecord::Positions(_) => {
                streams.contains(Streams::POSITIONS) && self.holds(&item.place)
            }
            ClientRecord::FaultProof(_) => streams.contains(Streams::POSITIONS),
            // The regional product, counters stripped, by the area its origin signed it for.
            ClientRecord::RegionalBatch(_) => {
                streams.contains(Streams::REGIONAL) && self.holds(&item.place)
            }
            ClientRecord::WorldPositions(_) => streams.contains(Streams::WORLD),
            // A relay's figures of an area's receivers, by that area.
            ClientRecord::FeederFigures(_) => {
                streams.contains(Streams::FEEDER_FIGURES) && self.holds(&item.place)
            }
            // A clock model without its offsets, by its area and the areas whose band holds it.
            ClientRecord::ClockModel(_) => {
                streams.contains(Streams::CLOCK_MODELS) && self.holds(&item.place)
            }
            _ => false,
        }
    }

    /// Whether `place` is inside the subscription. A cell is when it and a region overlap (one
    /// holds the other): a client of a public cell is sent its area's records, a client of an
    /// area its public cells'. Aircraft are when any lies in a region. A record of no place a
    /// client may name goes to whole-world clients alone.
    fn holds(&self, place: &ClientPlace) -> bool {
        let regions = &self.0.regions;
        match place {
            ClientPlace::World => true,
            ClientPlace::Unplaced => regions.is_empty(),
            ClientPlace::Cell(cell) => {
                regions.is_empty()
                    || regions
                        .iter()
                        .any(|region| region.contains(cell.0) || cell.0.contains(*region))
            }
            ClientPlace::Cells(cells) => {
                regions.is_empty()
                    || cells.iter().any(|cell| {
                        regions
                            .iter()
                            .any(|region| region.contains(*cell) || cell.contains(*region))
                    })
            }
            ClientPlace::Aircraft(points) => {
                regions.is_empty()
                    || points
                        .iter()
                        .any(|point| regions.iter().any(|region| region.contains(*point)))
            }
        }
    }
}

/// A cell no finer than a receiver's public cell: the only cell a client is routed by. Made only
/// by [`Coarse::of`], which clamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Coarse(Region);

impl Coarse {
    pub fn of(region: Region) -> Self {
        Self(region.clamped_to_public())
    }

    pub fn region(self) -> Region {
        self.0
    }

    pub fn as_region(&self) -> &Region {
        &self.0
    }
}

/// Where a client may be routed a record, read from its client form alone (and, for a clock
/// model, its full model's area and the areas whose band holds it): never a receiver's site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientPlace {
    /// Of the whole world: every client that takes its stream, whatever its regions.
    World,
    /// Of no place a client may name (a receiver whose description names no public cell, figures
    /// of no area): whole-world clients only.
    Unplaced,
    /// In one cell no finer than a public cell: a receiver's public cell, an area.
    Cell(Coarse),
    /// In any of these cells, each an area or coarser: a clock model's area and the areas whose
    /// band holds it, the clients whose fixes may cite it.
    Cells(Arc<[Region]>),
    /// The aircraft it places, by their finest cells: where aircraft are, not receivers.
    Aircraft(Arc<[Region]>),
}

/// What a client link may be sent of a fan-out item, and where it is routed: its client form and
/// its client place, made together, once ([`ClientItem::new`]).
#[derive(Clone, Debug)]
pub struct ClientItem {
    pub record: Arc<ClientRecord>,
    place: ClientPlace,
}

impl ClientItem {
    /// `record`'s client item. Its place is read from the record: a description's public cell, a
    /// regional product's or figures' area, the aircraft of positions (`aircraft`, the points the
    /// hub placed them by), and, for a client clock model, its area and the areas whose band holds
    /// it (`aircraft`, as `Network::client_model_places` placed it, each coarsened to its area
    /// whatever it was, or to a public cell at finest).
    pub fn new(record: Arc<ClientRecord>, aircraft: Option<&Arc<[Region]>>) -> Self {
        let cell = |cell: Option<Region>| match cell {
            Some(cell) => ClientPlace::Cell(Coarse::of(cell)),
            None => ClientPlace::Unplaced,
        };
        let place = match &*record {
            ClientRecord::ReceiverInfo(info) => cell(info.get().public_cell().ok().flatten()),
            ClientRecord::RegionalBatch(regional) => {
                cell(regional.content().ok().map(|content| content.cell))
            }
            ClientRecord::FeederFigures(figures) => {
                cell(figures.content().ok().and_then(|content| content.area))
            }
            ClientRecord::ClockModel(_) => match aircraft {
                Some(places) if !places.is_empty() => ClientPlace::Cells(
                    places
                        .iter()
                        .map(|place| {
                            tally_wire::rendezvous::area_of_cell(*place)
                                .unwrap_or_else(|| Coarse::of(*place).region())
                        })
                        .collect(),
                ),
                _ => ClientPlace::Unplaced,
            },
            ClientRecord::Positions(_) => match aircraft {
                Some(points) => ClientPlace::Aircraft(Arc::clone(points)),
                None => ClientPlace::World,
            },
            _ => ClientPlace::World,
        };
        Self { record, place }
    }

    pub fn place(&self) -> &ClientPlace {
        &self.place
    }
}

/// What an engine may take (RFC-0174 §2.3): an engine is another relay's MLAT taking an area's
/// raw one hop, so it is granted raw and the clock models of the same regions (the neighbouring
/// areas' models its fixes may cite) and nothing else, and only of the regions it asked for that
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
    now: tally_wire::clocks::Judged,
) -> Subscription {
    if !asked.streams.contains(Streams::RAW) || asked.regions.is_empty() {
        return Subscription::nothing();
    }
    let band = Band::of(&areas_solved_by(directory, engine, now));
    let regions: Vec<Region> = asked
        .regions
        .iter()
        .filter(|region| band.holds(**region))
        .copied()
        .collect();
    if regions.is_empty() {
        return Subscription::nothing();
    }
    // The models of the band's areas with their raw: the ones its fixes may cite beside its
    // own areas' (`tally_mlat::area`), each by its area (`Subscription::wants`).
    Subscription {
        streams: if asked.streams.contains(Streams::CLOCK_MODELS) {
            Streams::RAW.with(Streams::CLOCK_MODELS)
        } else {
            Streams::RAW
        },
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
            | Record::TimedHeartbeat(_)
            | Record::Goodbye { .. }
            | Record::Redirect { .. }
            | Record::RelayList(_)
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    use std::sync::Arc;
    use tally_wire::clocks::recorded::judged;

    use tally_wire::rendezvous::AREA_RESOLUTION;
    use tally_wire::{
        FixesContent, Identity, Location, Positions, ProviderOffer, ProviderOfferContent, Record,
        Region, Streams,
    };

    use super::{
        Band, ClientItem, ClientPlace, Coarse, Subscription, areas_solved_by, engine_grant,
    };
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

    /// A client's regions are clamped to public cells: a finer one is its public cell (so it
    /// cannot ask which receivers lie in a few hundred metres), a coarser one stays, and a region
    /// named twice once clamped is named once. And a receiver reaches it by its public cell: a
    /// region holding its site but not its public cell is no way to reach it.
    #[test]
    fn a_clients_regions_are_clamped_to_public_cells_and_route_by_them() -> Result<(), String> {
        use tally_wire::PUBLIC_CELL_RESOLUTION;
        let site = Location {
            lat_e7: 337_501_234,
            lon_e7: -843_887_654,
            alt_m: 301,
            precision_m: 0,
        };
        let public = Region::public_cell(&site).map_err(text)?;
        let fine = Region::containing(&site, PUBLIC_CELL_RESOLUTION + 4).map_err(text)?;
        let finer = Region::point(&site).map_err(text)?;
        let area = area_at(site.lat_e7, site.lon_e7)?;
        let asked = Subscription {
            streams: Streams::RAW,
            regions: vec![fine, finer, area],
        }
        .for_client();
        assert_eq!(asked.regions(), [public, area]);
        for region in asked.regions() {
            assert!(region.resolution() <= PUBLIC_CELL_RESOLUTION);
        }
        // Routed by the public cell: served to a client of that cell, never by the site's cell.
        let receiver = Identity::from_seed([4; 32]);
        let described = |cell: Option<Region>| -> Result<ClientItem, String> {
            let info = tally_wire::ReceiverInfo::sign_public(
                &receiver,
                &tally_wire::batch::PublicInfoContent {
                    issued_ms: NOW,
                    cell,
                    clock: tally_wire::Clock::Dump1090,
                    software: String::new(),
                    relays: Vec::new(),
                },
            )
            .map_err(text)?;
            let record = Record::ReceiverInfo(info);
            let client = crate::outbound::client_form(&record).ok_or("no client form")?;
            Ok(ClientItem::new(client, None))
        };
        let only = |region| Subscription {
            streams: Streams::RAW,
            regions: vec![region],
        };
        let item = described(Some(public))?;
        assert_eq!(item.place(), &ClientPlace::Cell(Coarse::of(public)));
        assert!(only(public).for_client().serves(&item));
        // A neighbouring public cell's client does not get it.
        let neighbour = Region::public_cell(&Location {
            lat_e7: site.lat_e7 + 1_000_000,
            ..site
        })
        .map_err(text)?;
        assert_ne!(neighbour, public);
        assert!(!only(neighbour).for_client().serves(&item));
        // A client of the site's finest cell is a client of its public cell: nothing finer.
        assert!(only(finer).for_client().serves(&item));
        // With no public cell, a receiver is in the whole world and no region.
        let unplaced = described(None)?;
        assert!(!only(public).for_client().serves(&unplaced));
        assert!(
            Subscription {
                streams: Streams::RAW,
                regions: Vec::new(),
            }
            .for_client()
            .serves(&unplaced)
        );
        Ok(())
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
        directory.hold_verified(offer(&engine, atlanta, 8)?, Group::V4(1), judged(NOW))?;
        directory.hold_verified(offer(&other, sydney, 8)?, Group::V4(2), judged(NOW))?;
        let band = tally_mlat::area::border_band(&tally_wire::Regions::new([atlanta]));
        let edge = *band.cells().last().ok_or("an empty band")?;
        let asked = Subscription {
            streams: Streams::RAW.with(Streams::POSITIONS).with(Streams::WORLD),
            regions: vec![atlanta, edge, sydney],
        };
        assert_eq!(
            engine_grant(&directory, &engine.public(), &asked, judged(NOW)),
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
            engine_grant(&directory, &engine.public(), &world, judged(NOW)),
            Subscription::nothing()
        );
        let positions = Subscription {
            streams: Streams::POSITIONS,
            regions: vec![atlanta],
        };
        assert_eq!(
            engine_grant(&directory, &engine.public(), &positions, judged(NOW)),
            Subscription::nothing()
        );
        assert_eq!(
            engine_grant(&directory, &other.public(), &asked, judged(NOW)),
            Subscription {
                streams: Streams::RAW,
                regions: vec![sydney],
            }
        );
        let stranger = Identity::generate().map_err(text)?;
        assert_eq!(
            engine_grant(&directory, &stranger.public(), &asked, judged(NOW)),
            Subscription::nothing()
        );
        assert_eq!(
            engine_grant(&directory, &engine.public(), &asked, judged(NOW + 600_001)),
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
                    directory.hold_verified(offer(&engine, area, 8)?, Group::V4(1), judged(NOW))?;
                }
            }
        }
        let band = tally_mlat::area::border_band(&tally_wire::Regions::new(areas.clone()));
        assert!(
            band.iter()
                .any(|region| region.resolution() < AREA_RESOLUTION - 1)
        );
        // The work is counted, not timed: the band lookups one band of the engine's areas takes.
        let before = tally_mlat::area::band_lookups_here();
        let _ = Band::of(&areas_solved_by(&directory, &engine.public(), judged(NOW)));
        let one_band = tally_mlat::area::band_lookups_here() - before;
        assert!(one_band > 0);
        let chunks = band.cells().chunks(tally_wire::record::MAX_REGIONS).len() as u64;
        let before = tally_mlat::area::band_lookups_here();
        for chunk in band.cells().chunks(tally_wire::record::MAX_REGIONS) {
            let asked = Subscription {
                streams: Streams::RAW,
                regions: chunk.to_vec(),
            };
            assert_eq!(
                engine_grant(&directory, &engine.public(), &asked, judged(NOW)),
                asked
            );
        }
        // One band a grant, however many regions it asks for (before, a band a region).
        let looked_up = tally_mlat::area::band_lookups_here() - before;
        assert_eq!(
            looked_up,
            chunks * one_band,
            "{looked_up} band lookups for {chunks} grants of {} regions",
            band.cells().len()
        );
        Ok(())
    }

    fn fix() -> Result<Record, String> {
        let engine = Identity::generate().map_err(|error| error.to_string())?;
        Positions::sign_fix(
            &engine,
            &FixesContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1,
                spec_version: 7,
                fixes: Vec::new(),
            },
        )
        .map(Record::Positions)
        .map_err(|error| error.to_string())
    }

    /// There is one kind of MLAT fix (RFC-0171 §3.8.1 as amended 2026-10-24): its positions go to
    /// every reader of positions, in the positions class to a relay link, and to nobody else.
    #[test]
    fn fixes_are_sent_to_readers_of_positions_in_the_positions_class() -> Result<(), String> {
        let item = Item {
            source: 0,
            record: Arc::new(fix()?),
            cell: None,
            points: None,
            decoded: None,
            stamp: tally_wire::clocks::recorded::mono(0),
            client: None,
        };
        let asked = |streams: Streams| {
            Subscription {
                streams,
                regions: Vec::new(),
            }
            .wants(&item)
        };
        assert!(asked(Streams::POSITIONS));
        assert!(!asked(Streams::RAW.with(Streams::CLOCK_MODELS)));
        assert!(!super::directory_wants(&item));
        // To a relay link, the positions class; to a plain subscriber, a taker's.
        assert_eq!(Class::of(&item.record, Kind::Relay), Class::Positions);
        assert_eq!(Class::of(&item.record, Kind::Taker), Class::Taker);
        Ok(())
    }
}
