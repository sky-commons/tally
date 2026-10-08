//! Which areas this relay takes and which it is an MLAT relay for (RFC-0174 §2.1, §2.3). The
//! areas it takes are its operator's (configuration). The areas it solves are the ones where it is
//! among the first `tally_wire::rendezvous::MLAT_RELAYS_PER_AREA` of the weighted rendezvous
//! ranking of the relays offering MLAT cores for the area (`directory`), which every relay
//! computes alike; it then asks the other relays holding the area's feeders for their raw, plus
//! the border band, over the region-cut raw subscription ([`Selection::raw_sources`]).

use std::collections::BTreeMap;
use std::sync::RwLock;

use tally_wire::record::MAX_REGIONS;
use tally_wire::rendezvous::{self, MLAT_RELAYS_PER_AREA, Weighted};
use tally_wire::{ProviderOffer, ProviderOfferContent, PublicKey, Region, RelayAddress, Streams};

use crate::directory::Directory;

#[derive(Default)]
pub struct Selection {
    taken: RwLock<Vec<Region>>,
}

/// A one-hop raw link an MLAT relay keeps (§2.3): `Subscribe { streams: RAW, regions }` to
/// `relay`, which holds feeders of the areas the regions are cut around.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSource {
    pub relay: RelayAddress,
    /// At most `MAX_REGIONS`, sorted: the MLAT areas this relay solves that `relay` offers raw
    /// for, each with its border band.
    pub regions: Vec<Region>,
}

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    /// The operator's areas (configuration).
    pub fn set_taken(&self, areas: Vec<Region>) {
        if let Ok(mut taken) = self.taken.write() {
            *taken = areas;
        }
    }

    pub fn taken(&self) -> Vec<Region> {
        self.taken
            .read()
            .map(|taken| taken.clone())
            .unwrap_or_default()
    }

    /// The areas (`tally_wire::rendezvous::AREA_RESOLUTION` cells) the relay takes: every area
    /// under or around the operator's regions, sorted and once each.
    pub fn taken_areas(&self) -> Vec<Region> {
        let mut areas: Vec<Region> = self
            .taken()
            .into_iter()
            .filter_map(|region| rendezvous::areas_of(region).ok())
            .flatten()
            .collect();
        areas.sort_by_key(|area| area.as_u64());
        areas.dedup();
        areas
    }

    /// Whether the relay takes the area `cell` is in: `cell` (a receiver's point, an area, or any
    /// cell finer than a region taken) lies inside a region the operator named. A cell coarser
    /// than every region taken is only partly taken, which is not taking it.
    pub fn takes(&self, cell: Region) -> bool {
        self.taken
            .read()
            .is_ok_and(|taken| taken.iter().any(|region| region.contains(cell)))
    }

    /// Whether the relay takes the area of a receiver whose signed location falls at `point`
    /// (the finest cell, as the hub projects each description once). A receiver the relay holds
    /// no located description of is not known to be in its areas, so it is not taken.
    pub fn takes_receiver(&self, point: Option<Region>) -> bool {
        point.is_some_and(|point| self.takes(point))
    }

    /// The areas this relay is an MLAT relay for now: of the areas it takes, those where its own
    /// offer is among the first `MLAT_RELAYS_PER_AREA` of the ranking of every live offer for the
    /// area with MLAT cores, weighted by the cores. Every relay holding the same offers computes
    /// the same choice. None before the relay has offered anything (`Directory::own_key`).
    pub fn mlat_areas(&self, directory: &Directory, now_ms: u64) -> Vec<Region> {
        let Some(own) = directory.own_key() else {
            return Vec::new();
        };
        solving(directory, &own, self.taken_areas(), now_ms)
    }

    /// The one-hop raw links to keep (§2.3): for each area this relay solves, every other relay
    /// offering the area's raw is asked for it, cut to the area and its border band. One entry per
    /// relay while its regions fit one `Subscribe`, more beyond. Sorted by key, so the set is the
    /// same however the offers arrived.
    pub fn raw_sources(&self, directory: &Directory, now_ms: u64) -> Vec<RawSource> {
        let own = directory.own_key();
        let mut wanted: BTreeMap<PublicKey, (String, Vec<Region>)> = BTreeMap::new();
        for area in self.mlat_areas(directory, now_ms) {
            for offer in directory.offers_for(area, now_ms) {
                let Some((key, content)) = live(&offer) else {
                    continue;
                };
                if Some(key) == own || !content.products.contains(Streams::RAW) {
                    continue;
                }
                let entry = wanted
                    .entry(key)
                    .or_insert_with(|| (content.address.clone(), Vec::new()));
                entry.1.push(area);
            }
        }
        let mut sources = Vec::new();
        for (key, (address, areas)) in wanted {
            // The one definition of the band (`tally_mlat::area`), over every area this relay
            // asks `key` for at once: the cells the hosted MLAT lets take part, and the cells
            // `key` grants an engine (`subscription::engine_grant`), as few as cover them.
            let regions = tally_mlat::area::border_band(&areas);
            for chunk in regions.chunks(MAX_REGIONS) {
                sources.push(RawSource {
                    relay: RelayAddress {
                        key,
                        address: address.clone(),
                    },
                    regions: chunk.to_vec(),
                });
            }
        }
        sources
    }
}

/// The areas `relay` is an MLAT relay for, as every relay holding the same offers computes it: of
/// the areas under the cells its live offers name, those where it is among the first
/// `MLAT_RELAYS_PER_AREA` of the ranking (`mlat_relays`). What an engine is granted is the band
/// of these (`subscription::engine_grant`), and this relay's own are the same rule over the areas
/// it takes ([`Selection::mlat_areas`]).
pub fn areas_solved_by(directory: &Directory, relay: &PublicKey, now_ms: u64) -> Vec<Region> {
    let mut areas: Vec<Region> = directory
        .cells_of(relay, now_ms)
        .into_iter()
        .filter_map(|cell| rendezvous::areas_of(cell).ok())
        .flatten()
        .collect();
    areas.sort_by_key(|area| area.as_u64());
    areas.dedup();
    solving(directory, relay, areas, now_ms)
}

/// Of `areas`, those `relay` is among the MLAT relays of.
fn solving(
    directory: &Directory,
    relay: &PublicKey,
    areas: Vec<Region>,
    now_ms: u64,
) -> Vec<Region> {
    areas
        .into_iter()
        .filter(|area| mlat_relays(*area, directory, now_ms).contains(relay))
        .collect()
}

/// The most cores an offer counts for in the MLAT choice: more than the whole world's MLAT takes
/// (27 cores, RFC-0174 §2.3), so a relay claiming more is not believed past it.
pub const MLAT_CORES_COUNTED: u16 = 64;

/// An area's MLAT relays (§2.3): the first `MLAT_RELAYS_PER_AREA` of the live offers covering
/// `area` that `directory` holds, ranked by contribution tier first (`directory::by_tier`, each
/// relay's tier as the directory weighs it, `Directory::tier_of`), and within a tier by weighted
/// rendezvous over MLAT cores, each counted up to `MLAT_CORES_COUNTED`. Where no relay has shown a
/// witness (a new network) every tier is 0 and the cores decide alone; once relays have, a key
/// with none (one ground for its hash, naming every core there is) ranks below all of them.
pub fn mlat_relays(area: Region, directory: &Directory, now_ms: u64) -> Vec<PublicKey> {
    let candidates: Vec<Weighted> = directory
        .offers_for(area, now_ms)
        .iter()
        .filter_map(live)
        .map(|(key, content)| Weighted {
            key,
            weight: u64::from(content.mlat_cores.min(MLAT_CORES_COUNTED)),
            network: content.network,
            // The ranking reads no address; only a pair of destinations does.
            host: None,
        })
        .collect();
    let ranked: Vec<PublicKey> = rendezvous::rank(area, &candidates)
        .unwrap_or_default()
        .into_iter()
        .map(|candidate| candidate.key)
        .collect();
    let tiers: std::collections::HashMap<PublicKey, u32> = ranked
        .iter()
        .map(|key| (*key, directory.tier_of(key, now_ms)))
        .collect();
    crate::directory::by_tier(ranked, |key| tiers.get(key).copied().unwrap_or(0))
        .into_iter()
        .take(MLAT_RELAYS_PER_AREA)
        .collect()
}

fn live(offer: &ProviderOffer) -> Option<(PublicKey, ProviderOfferContent)> {
    Some((offer.signer().ok()?, offer.content().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::Group;
    use tally_wire::rendezvous::{AREA_RESOLUTION, area_of};
    use tally_wire::{Identity, Location};

    type Result = std::result::Result<(), String>;

    fn text(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    fn atlanta() -> Location {
        Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        }
    }

    fn offer(
        relay: &Identity,
        cell: Region,
        cores: u16,
        products: Streams,
        now_ms: u64,
    ) -> std::result::Result<ProviderOffer, String> {
        ProviderOffer::sign(
            relay,
            &ProviderOfferContent {
                address: format!("{}:7450", relay.public().to_base64url()),
                cell,
                products,
                stripes_of: 1,
                stripes: 1,
                mlat_cores: cores,
                feeder_slots: 10,
                network: u32::from(relay.public().as_bytes()[0]),
                issued_ms: now_ms,
                expires_ms: now_ms + 600_000,
            },
        )
        .map_err(text)
    }

    #[test]
    fn a_relay_takes_the_areas_under_its_regions_and_their_receivers() -> Result {
        let selection = Selection::new();
        let here = atlanta();
        let area = area_of(&here).map_err(text)?;
        let state = Region::containing(&here, 1).map_err(text)?;
        let point = Region::point(&here).map_err(text)?;
        assert!(!selection.takes(area));
        assert!(!selection.takes_receiver(Some(point)));
        selection.set_taken(vec![state]);
        assert!(selection.takes(area));
        assert!(selection.takes(point));
        assert!(selection.takes_receiver(Some(point)));
        assert!(!selection.takes_receiver(None), "no location, not known");
        let london = Region::point(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })
        .map_err(text)?;
        assert!(!selection.takes_receiver(Some(london)));
        // Coarser than any region taken: only partly taken.
        assert!(!selection.takes(Region::containing(&here, 0).map_err(text)?));
        let areas = selection.taken_areas();
        assert_eq!(areas.len(), 49);
        assert!(areas.contains(&area));
        assert!(
            areas
                .iter()
                .all(|cell| cell.resolution() == AREA_RESOLUTION)
        );
        Ok(())
    }

    #[test]
    fn every_relay_computes_the_same_mlat_relays_and_solves_where_it_is_one() -> Result {
        let now = 1_000_000;
        let area = area_of(&atlanta()).map_err(text)?;
        let relays: Vec<Identity> = (0..8_u8)
            .map(|seed| Identity::from_seed([seed + 1; 32]))
            .collect();
        let offers: Vec<ProviderOffer> = relays
            .iter()
            .zip(0_u16..)
            .map(|(relay, cores)| offer(relay, area, cores * 4, Streams::RAW, now))
            .collect::<std::result::Result<_, _>>()?;
        let holding = |offers: &[ProviderOffer]| -> std::result::Result<Directory, String> {
            let directory = Directory::new();
            for (offer, group) in offers.iter().zip(0_u16..) {
                directory.hold_verified(offer.clone(), Group::V4(group), now)?;
            }
            Ok(directory)
        };
        let chosen = mlat_relays(area, &holding(&offers)?, now);
        assert_eq!(chosen.len(), MLAT_RELAYS_PER_AREA);
        let mut reversed = offers.clone();
        reversed.reverse();
        assert_eq!(mlat_relays(area, &holding(&reversed)?, now), chosen);
        // The relay offering no cores is never chosen.
        assert!(!chosen.contains(&relays[0].public()));
        // Each relay holding the offers solves the area exactly when it is chosen.
        for relay in &relays {
            let directory = Directory::new();
            directory.adopt_own_key(relay.public());
            for (offer, group) in offers.iter().zip(0_u16..) {
                directory.hold_verified(offer.clone(), Group::V4(group), now)?;
            }
            let selection = Selection::new();
            selection.set_taken(vec![area]);
            let solves = selection.mlat_areas(&directory, now);
            assert_eq!(
                solves == vec![area],
                chosen.contains(&relay.public()),
                "{}",
                relay.public()
            );
            // It asks every other relay offering the area's raw, cut to the area and its band.
            let sources = selection.raw_sources(&directory, now);
            if solves.is_empty() {
                assert!(sources.is_empty());
            } else {
                // Each other relay is asked for the whole band, in as many `Subscribe`s as it
                // takes (`MAX_REGIONS` regions each).
                let band = tally_mlat::area::border_band(&[area]);
                let mut asked: BTreeMap<PublicKey, Vec<Region>> = BTreeMap::new();
                for source in &sources {
                    assert_ne!(source.relay.key, relay.public());
                    assert!(source.regions.len() <= MAX_REGIONS);
                    asked
                        .entry(source.relay.key)
                        .or_default()
                        .extend(source.regions.iter().copied());
                }
                assert_eq!(asked.len(), relays.len() - 1);
                for regions in asked.values_mut() {
                    regions.sort_by_key(|region| region.as_u64());
                    assert_eq!(*regions, band);
                }
            }
        }
        Ok(())
    }
}
