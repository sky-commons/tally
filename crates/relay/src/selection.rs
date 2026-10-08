//! Which areas this relay takes and which it is an MLAT relay for (RFC-0174 §2.1, §2.3). The
//! areas it takes are its operator's (configuration). The areas it solves are the ones where it is
//! among the first `tally_wire::rendezvous::MLAT_RELAYS_PER_AREA` of the weighted rendezvous
//! ranking of the relays offering MLAT cores for the area (`directory`), which every relay
//! computes alike; it then asks the other relays holding the area's feeders for their raw, plus
//! the border band, over the region-cut raw subscription ([`Selection::raw_sources`]).

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tally_wire::record::MAX_REGIONS;
use tally_wire::rendezvous::{self, AREA_RESOLUTION, MLAT_RELAYS_PER_AREA, Weighted};
use tally_wire::{
    ProviderOffer, ProviderOfferContent, PublicKey, Region, Regions, RelayAddress, Streams,
};

use crate::directory::{Coverage, Directory, Version};

#[derive(Default)]
pub struct Selection {
    taken: RwLock<Arc<Taken>>,
    /// The MLAT choice and the raw links it asks for, as last computed, with what they were
    /// computed from: recomputed only when that moves.
    solved: Mutex<Option<Solved>>,
}

/// The regions a relay takes, indexed so that whether a cell or an area is taken is a few lookups
/// up the cell's ancestors, never a scan of the regions or of the areas under them: a relay taking
/// the whole world (122 regions, 41,162 areas) holds 122 entries here and nothing per area.
#[derive(Debug, Default)]
pub struct Taken {
    regions: Vec<Region>,
    cells: HashSet<u64>,
    /// The areas holding a region finer than an area (`rendezvous::areas_of` counts such an area
    /// taken).
    finer: HashSet<u64>,
    /// Which configuration this is, unique in the process: a reader that kept what it computed
    /// from one knows when it moved.
    version: u64,
}

static TAKEN_VERSIONS: AtomicU64 = AtomicU64::new(1);

impl Taken {
    /// The index of `regions`.
    pub fn of(regions: Vec<Region>) -> Self {
        let cells = regions.iter().map(|region| region.as_u64()).collect();
        let finer = regions
            .iter()
            .filter(|region| region.resolution() > AREA_RESOLUTION)
            .filter_map(|region| region.ancestor(AREA_RESOLUTION))
            .map(Region::as_u64)
            .collect();
        Self {
            regions,
            cells,
            finer,
            version: TAKEN_VERSIONS.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// The operator's regions, as configured.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Whether `cell` is itself one of the regions taken.
    pub fn names(&self, cell: Region) -> bool {
        self.cells.contains(&cell.as_u64())
    }

    /// Whether `cell` lies inside a region taken (`Selection::takes`).
    pub fn takes(&self, cell: Region) -> bool {
        !self.cells.is_empty()
            && (0..=cell.resolution()).any(|resolution| {
                cell.ancestor(resolution)
                    .is_some_and(|ancestor| self.cells.contains(&ancestor.as_u64()))
            })
    }

    /// Whether `area` (a cell at `AREA_RESOLUTION`) is one of the areas taken
    /// (`Selection::taken_areas`): under or equal to a region taken, or holding one finer.
    pub fn takes_area(&self, area: Region) -> bool {
        area.resolution() == AREA_RESOLUTION
            && (self.takes(area) || self.finer.contains(&area.as_u64()))
    }

    /// Whether some area under `cell` (a cell no finer than an area) is taken: `cell` lies in a
    /// region taken, or a region taken lies in it.
    pub fn touches(&self, cell: Region) -> bool {
        self.takes(cell) || self.regions.iter().any(|region| cell.contains(*region))
    }

    /// Every area taken, sorted and once each: expanded, so only for a caller that must hold the
    /// list (the hosted MLAT's scope), never for a question about one area.
    pub fn areas(&self) -> Vec<Region> {
        let mut areas: Vec<Region> = self
            .regions
            .iter()
            .filter_map(|region| rendezvous::areas_of(*region).ok())
            .flatten()
            .collect();
        areas.sort_by_key(|area| area.as_u64());
        areas.dedup();
        areas
    }
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

/// The MLAT choice as last computed, and what from.
struct Solved {
    from: (u64, Option<PublicKey>, Version),
    /// Counts the computations, so a reader knows when the areas may differ.
    generation: u64,
    areas: Regions,
    raw: Option<Vec<RawSource>>,
}

impl Selection {
    pub fn new() -> Self {
        Self::default()
    }

    /// The operator's areas (configuration).
    pub fn set_taken(&self, areas: Vec<Region>) {
        if let Ok(mut taken) = self.taken.write() {
            *taken = Arc::new(Taken::of(areas));
        }
    }

    pub fn taken(&self) -> Vec<Region> {
        self.taken_index().regions.clone()
    }

    /// The regions taken, indexed: shared, so a reader keeps it until its version moves.
    pub fn taken_index(&self) -> Arc<Taken> {
        self.taken
            .read()
            .map(|taken| Arc::clone(&taken))
            .unwrap_or_default()
    }

    /// The areas (`tally_wire::rendezvous::AREA_RESOLUTION` cells) the relay takes: every area
    /// under or around the operator's regions, sorted and once each.
    pub fn taken_areas(&self) -> Vec<Region> {
        self.taken_index().areas()
    }

    /// Whether the relay takes the area `cell` is in: `cell` (a receiver's point, an area, or any
    /// cell finer than a region taken) lies inside a region the operator named. A cell coarser
    /// than every region taken is only partly taken, which is not taking it.
    pub fn takes(&self, cell: Region) -> bool {
        self.taken.read().is_ok_and(|taken| taken.takes(cell))
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
    pub fn mlat_areas(&self, directory: &Directory, now_ms: u64) -> Regions {
        self.solved(directory, now_ms).1
    }

    /// [`Selection::mlat_areas`], shared, with the generation of the computation: computed only
    /// when the regions taken, the relay's key or what the directory answers moved
    /// (`Directory::version`), so a relay that asks every tick pays for it only on a change.
    pub fn solved(&self, directory: &Directory, now_ms: u64) -> (u64, Regions) {
        self.with_solved(directory, now_ms, |solved| {
            (solved.generation, solved.areas.clone())
        })
    }

    /// The one-hop raw links to keep (§2.3): for each area this relay solves, every other relay
    /// offering the area's raw is asked for it, cut to the area and its border band. One entry per
    /// relay while its regions fit one `Subscribe`, more beyond. Sorted by key, so the set is the
    /// same however the offers arrived. Kept with the MLAT choice it follows.
    pub fn raw_sources(&self, directory: &Directory, now_ms: u64) -> Vec<RawSource> {
        self.with_solved(directory, now_ms, |solved| {
            if solved.raw.is_none() {
                solved.raw = Some(raw_sources_of(
                    directory,
                    directory.own_key(),
                    &solved.areas,
                    now_ms,
                ));
            }
            solved.raw.clone().unwrap_or_default()
        })
    }

    fn with_solved<T>(
        &self,
        directory: &Directory,
        now_ms: u64,
        read: impl FnOnce(&mut Solved) -> T,
    ) -> T {
        let taken = self.taken_index();
        let own = directory.own_key();
        let from = (taken.version, own, directory.version(now_ms));
        let mut held = self
            .solved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = match held.as_ref() {
            Some(solved) if solved.from == from => solved.generation,
            Some(solved) => {
                let next = solved.generation + 1;
                *held = None;
                next
            }
            None => 1,
        };
        let solved = held.get_or_insert_with(|| Solved {
            from,
            generation,
            areas: match own {
                Some(own) => solving(directory, &own, taken.regions(), now_ms),
                None => Regions::default(),
            },
            raw: None,
        });
        read(solved)
    }
}

/// One relay's raw asked for: where its address came from (first area, finest cell first), the
/// address, and the areas (as regions, never expanded).
type Wanted = ((u64, u8), String, Vec<Region>);

/// The raw links for `areas`, from the offers covering them: each other relay offering raw for a
/// cell over some of them is asked for those, with their band. Region by region: what a cell
/// offered shares with the areas is the cell itself where the areas cover it, and else the cells
/// of the areas inside it, never the areas one by one.
fn raw_sources_of(
    directory: &Directory,
    own: Option<PublicKey>,
    areas: &Regions,
    now_ms: u64,
) -> Vec<RawSource> {
    if areas.is_empty() {
        return Vec::new();
    }
    // Per key, its address (from its offer for the smallest area, finest cell first: the one an
    // area-by-area walk meets first) and the areas.
    let mut wanted: BTreeMap<PublicKey, Wanted> = BTreeMap::new();
    for (cell, offers) in directory.coverage(now_ms).cells() {
        let cell = cell
            .ancestor(cell.resolution().min(AREA_RESOLUTION))
            .unwrap_or(cell);
        let under: Vec<Region> = if areas.contains(cell) {
            vec![cell]
        } else {
            areas
                .iter()
                .filter(|listed| cell.contains(*listed))
                .collect()
        };
        // The smallest area under them: each cell's centre child at the area resolution is the
        // smallest-numbered of its areas.
        let Some(first) = under
            .iter()
            .filter_map(|region| region.first_child(AREA_RESOLUTION))
            .map(Region::as_u64)
            .min()
        else {
            continue;
        };
        let order = (first, u8::MAX - cell.resolution());
        for offer in offers {
            let Some((key, content)) = live(offer) else {
                continue;
            };
            if Some(key) == own || !content.products.contains(Streams::RAW) {
                continue;
            }
            let entry = wanted
                .entry(key)
                .or_insert_with(|| (order, content.address.clone(), Vec::new()));
            if order < entry.0 {
                entry.0 = order;
                entry.1.clone_from(&content.address);
            }
            entry.2.extend(under.iter().copied());
        }
    }
    let mut sources = Vec::new();
    for (key, (_, address, areas)) in wanted {
        // The one definition of the band (`tally_mlat::area`), over every area this relay
        // asks `key` for at once: the cells the hosted MLAT lets take part, and the cells
        // `key` grants an engine (`subscription::engine_grant`), as few as cover them.
        let regions = tally_mlat::area::border_band(&Regions::new(areas));
        for chunk in regions.cells().chunks(MAX_REGIONS) {
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

/// The areas `relay` is an MLAT relay for, as every relay holding the same offers computes it: of
/// the areas under the cells its live offers name, those where it is among the first
/// `MLAT_RELAYS_PER_AREA` of the ranking (`mlat_relays`). What an engine is granted is the band
/// of these (`subscription::engine_grant`), and this relay's own are the same rule over the areas
/// it takes ([`Selection::mlat_areas`]).
pub fn areas_solved_by(directory: &Directory, relay: &PublicKey, now_ms: u64) -> Regions {
    let cells = directory.cells_of(relay, now_ms);
    solving(directory, relay, &cells, now_ms)
}

/// Of the areas under or around `regions` (`rendezvous::areas_of`), those `relay` is among the
/// MLAT relays of, as the fewest cells that cover them. Region by region, not area by area: where
/// no cell inside a region holds an offer, every area under it is covered by the same offers, and
/// where those name at most `MLAT_RELAYS_PER_AREA` relays with cores, every one of them is chosen
/// for every area, whatever the ranking, and the region is chosen whole; only where more contest
/// an area is it ranked on its own. So a relay alone in the world decides its 41,162 areas from
/// 122 regions, and holds them as those 122.
fn solving(directory: &Directory, relay: &PublicKey, regions: &[Region], now_ms: u64) -> Regions {
    if regions.is_empty() {
        return Regions::default();
    }
    let coverage = directory.coverage(now_ms);
    let mut out = Vec::new();
    let mut tops: Vec<Region> = regions
        .iter()
        .filter_map(|region| region.ancestor(region.resolution().min(AREA_RESOLUTION)))
        .collect();
    tops.sort_by_key(|cell| cell.as_u64());
    tops.dedup();
    for top in tops {
        // The offers of every cell strictly above the region cover each area under it.
        let inherited: Vec<ProviderOffer> = (0..top.resolution())
            .filter_map(|resolution| top.ancestor(resolution))
            .flat_map(|cell| coverage.at(cell).iter().cloned())
            .collect();
        solve_under(
            directory, &coverage, relay, top, inherited, now_ms, &mut out,
        );
    }
    Regions::new(out)
}

/// The areas under `cell` that `relay` solves, given the offers of the cells above it.
fn solve_under(
    directory: &Directory,
    coverage: &Coverage,
    relay: &PublicKey,
    cell: Region,
    mut offers: Vec<ProviderOffer>,
    now_ms: u64,
    out: &mut Vec<Region>,
) {
    offers.extend(coverage.at(cell).iter().cloned());
    if cell.resolution() >= AREA_RESOLUTION {
        if choose(cell, &offers, directory, now_ms).contains(relay) {
            out.push(cell);
        }
        return;
    }
    if coverage.inside(cell) {
        for child in crate::sharing::bundles::children(cell) {
            solve_under(
                directory,
                coverage,
                relay,
                child,
                offers.clone(),
                now_ms,
                out,
            );
        }
        return;
    }
    let mut keys: Vec<PublicKey> = offers
        .iter()
        .filter_map(live)
        .filter(|(_, content)| content.mlat_cores > 0)
        .map(|(key, _)| key)
        .collect();
    keys.sort();
    keys.dedup();
    if keys.len() <= MLAT_RELAYS_PER_AREA {
        // Every relay with cores is chosen for every area here: the cell, whole.
        if keys.contains(relay) {
            out.push(cell);
        }
        return;
    }
    if !keys.contains(relay) {
        return;
    }
    out.extend(
        rendezvous::areas_of(cell)
            .unwrap_or_default()
            .into_iter()
            .filter(|area| choose(*area, &offers, directory, now_ms).contains(relay)),
    );
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
    choose(area, &directory.offers_for(area, now_ms), directory, now_ms)
}

/// [`mlat_relays`] of `area` from `offers`, the live offers covering it (in any order: the
/// ranking is a function of the set).
fn choose(
    area: Region,
    offers: &[ProviderOffer],
    directory: &Directory,
    now_ms: u64,
) -> Vec<PublicKey> {
    let candidates: Vec<Weighted> = offers
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
                solves == Regions::new([area]),
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
                let band = tally_mlat::area::border_band(&Regions::new([area]));
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
                    assert_eq!(regions.as_slice(), band.cells());
                }
            }
        }
        Ok(())
    }
}
