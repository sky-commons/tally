//! The shared choices of RFC-0174, one implementation for feeders and relays so they cannot rank
//! differently: a feeder's area ([`area_of`]), the weighted rendezvous ranking of relays over an
//! area (§2.2: the band's relays by declared spare feeder capacity; §2.3: the MLAT relays of an
//! area by offered cores, of which the first `k` solve it), the two destinations on distinct
//! networks, and the one rule for whether two relays are on distinct networks at all
//! ([`distinct_networks`]). Every party that sees the same candidates computes the same order,
//! with no coordination.
//!
//! **The score.** Weighted rendezvous hashing (Schindelhauer and Schomaker's logarithmic method):
//! each candidate draws `u`, uniform in (0, 1], from a hash of (area, key), and scores
//! `weight / -ln(u)`; the highest score ranks first. A candidate then ranks first with
//! probability exactly its share of the total weight, and a candidate that comes or goes changes
//! nobody else's score, so it moves only its own share. The logarithm is base 2 here (a common
//! factor, so the order is the same) and computed in integer fixed point ([`neg_log2`]), and
//! scores are compared by cross-multiplying in `u128`, so the order is exact and the same on
//! every platform: no float is involved anywhere.

use std::net::IpAddr;

use blake2::{Blake2s256, Digest};
use h3o::{CellIndex, LatLng, Resolution};

use crate::WireError;
use crate::batch::Location;
use crate::key::PublicKey;
use crate::region::Region;

/// The H3 resolution of an area: what a feeder's signed location is cut to for the per-area pick
/// (§2.2), and what an MLAT relay is chosen per (§2.3). Resolution 3: cells of about 12,400 km²
/// (some 110 km across), well inside one reception radius, so an area's feeders hear one sky.
pub const AREA_RESOLUTION: u8 = 3;
/// How many relays solve each area's MLAT (§2.3: two or three).
pub const MLAT_RELAYS_PER_AREA: usize = 3;
/// Fractional bits of the fixed-point logarithm: 2^-32 of a bit, far finer than any two hashes
/// of 64 bits are apart, so a tie in score is a tie in hash.
const FRACTION_BITS: u32 = 32;
const RENDEZVOUS_DOMAIN: &[u8] = b"tally rendezvous";

/// The area a location is in.
pub fn area_of(location: &Location) -> Result<Region, WireError> {
    Region::containing(location, AREA_RESOLUTION)
}

/// The area a point given in degrees is in: [`area_of`] for a caller that holds a latitude and
/// longitude rather than a signed `Location`. Refused off the globe.
pub fn area_at(lat_deg: f64, lon_deg: f64) -> Result<Region, WireError> {
    let off = || WireError::Invalid {
        field: "location",
        value: 0,
    };
    if !(lat_deg.abs() <= 90.0 && lon_deg.abs() <= 180.0) {
        return Err(off());
    }
    let place = LatLng::new(lat_deg, lon_deg).map_err(|_| off())?;
    Region::from_u64(u64::from(place.to_cell(area_resolution()?)))
}

/// The area a cell lies in: the cell itself at `AREA_RESOLUTION`, its ancestor there when it is
/// finer (a receiver's `Region::point`, a clock model tile's centre), and `None` when it is
/// coarser than an area, so it lies in many.
pub fn area_of_cell(cell: Region) -> Option<Region> {
    cell.ancestor(AREA_RESOLUTION)
}

/// The areas a region is made of: itself when it is an area, the area it lies in when it is
/// finer, and every area under it when it is coarser (at most 343, under a resolution 0 cell).
pub fn areas_of(region: Region) -> Result<Vec<Region>, WireError> {
    let cell = cell_of(region)?;
    let area = area_resolution()?;
    if cell.resolution() >= area {
        let parent = cell.parent(area).ok_or(WireError::Invalid {
            field: "H3 cell",
            value: region.as_u64(),
        })?;
        return Ok(vec![Region::from_u64(u64::from(parent))?]);
    }
    cell.children(area)
        .map(|child| Region::from_u64(u64::from(child)))
        .collect()
}

/// A cell and every coarser cell that contains it, finest first: its path up the area tree
/// (§2.6), where a provider of any of them provides it.
pub fn ancestors(region: Region) -> Result<Vec<Region>, WireError> {
    let cell = cell_of(region)?;
    let mut path = vec![region];
    for resolution in (0..region.resolution()).rev() {
        let resolution = Resolution::try_from(resolution).map_err(|_| WireError::Invalid {
            field: "H3 resolution",
            value: u64::from(resolution),
        })?;
        if let Some(parent) = cell.parent(resolution) {
            path.push(Region::from_u64(u64::from(parent))?);
        }
    }
    Ok(path)
}

fn cell_of(region: Region) -> Result<CellIndex, WireError> {
    CellIndex::try_from(region.as_u64()).map_err(|_| WireError::Invalid {
        field: "H3 cell",
        value: region.as_u64(),
    })
}

fn area_resolution() -> Result<Resolution, WireError> {
    Resolution::try_from(AREA_RESOLUTION).map_err(|_| WireError::Invalid {
        field: "H3 resolution",
        value: u64::from(AREA_RESOLUTION),
    })
}

/// Where a relay sits, for telling networks apart: the network it declares and the address it
/// was seen at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Placement {
    /// The autonomous system it declares in its signed echo reply or offer; 0 when it does not
    /// say.
    pub network: u32,
    /// The address the judging party observed it at (the peer address of a session it opened to
    /// it); `None` when it has not observed one. A declared address is not an observation.
    pub host: Option<IpAddr>,
}

/// The prefix of an address that one operator's machines usually share: the /24 of an IPv4
/// address, the /48 of an IPv6 one (an IPv4-mapped IPv6 address is its IPv4 address).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HostPrefix {
    V4([u8; 3]),
    V6([u8; 6]),
}

/// The prefix `host` is in ([`HostPrefix`]).
pub fn host_prefix(host: IpAddr) -> HostPrefix {
    match host {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            HostPrefix::V4([a, b, c])
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => host_prefix(IpAddr::V4(v4)),
            None => {
                let octets = v6.octets();
                let mut prefix = [0; 6];
                prefix.copy_from_slice(&octets[..6]);
                HostPrefix::V6(prefix)
            }
        },
    }
}

/// Whether two relays are known to be on distinct networks: both declare a network and the two
/// differ, AND both were observed and their addresses are in different prefixes (/24, /48). The
/// one rule every party uses wherever two relays must not share a failure (a feeder's two
/// destinations, the members a delivery check asks): a declaration alone is a claim anyone can
/// make, and an address alone misses two prefixes of one operator, so it takes both. Unknown on
/// either side is never distinct.
pub fn distinct_networks(a: Placement, b: Placement) -> bool {
    let declared = a.network != 0 && b.network != 0 && a.network != b.network;
    let observed = match (a.host, b.host) {
        (Some(a), Some(b)) => host_prefix(a) != host_prefix(b),
        _ => false,
    };
    declared && observed
}

/// Whether two relays are known to share a network: one declared network, or addresses observed
/// in one prefix. Neither known distinct nor known the same is "may differ", the fallback when no
/// relay is known distinct.
pub fn same_network(a: Placement, b: Placement) -> bool {
    let declared = a.network != 0 && a.network == b.network;
    let observed = match (a.host, b.host) {
        (Some(a), Some(b)) => host_prefix(a) == host_prefix(b),
        _ => false,
    };
    declared || observed
}

/// One relay as the ranking sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weighted {
    pub key: PublicKey,
    /// What it declared (spare feeder slots, or MLAT cores); zero is never chosen.
    pub weight: u64,
    /// The autonomous system it says it is on (0: unknown).
    pub network: u32,
    /// Where the ranking party observed it, if it has (`Placement::host`). The ranking ignores
    /// it; [`pair`] reads it.
    pub host: Option<IpAddr>,
}

impl Weighted {
    pub fn placement(&self) -> Placement {
        Placement {
            network: self.network,
            host: self.host,
        }
    }
}

/// The candidates ranked for `area` by weighted rendezvous hashing, best first: each scored
/// `weight / -log2(u)` with `u` from a hash of (area, key) (see the module), so the order is the
/// same for everyone who sees the same candidates and shifts only by the candidates that come or
/// go. A candidate of weight zero is left out (it is never chosen), and a key named twice counts
/// once, by its greatest weight, so the input's order never matters.
pub fn rank(area: Region, candidates: &[Weighted]) -> Result<Vec<Weighted>, WireError> {
    let mut unique: Vec<Weighted> = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.weight > 0)
        .collect();
    // One entry per key, the greatest (weight, network) kept: a choice of the set, not the order.
    unique.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then(b.weight.cmp(&a.weight))
            .then(b.network.cmp(&a.network))
    });
    unique.dedup_by_key(|candidate| candidate.key);
    let mut scored: Vec<(Weighted, u64)> = unique
        .into_iter()
        .map(|candidate| (candidate, neg_log2(draw(area, &candidate.key))))
        .collect();
    // Higher score first: a / la > b / lb exactly when a * lb > b * la, every product exact in
    // u128 (a weight under 2^64 times a logarithm under 2^38). A tie, which needs two equal hashes
    // and equal weights, falls to the key.
    scored.sort_by(|(a, la), (b, lb)| {
        let left = u128::from(a.weight) * u128::from(*lb);
        let right = u128::from(b.weight) * u128::from(*la);
        right.cmp(&left).then(a.key.cmp(&b.key))
    });
    Ok(scored.into_iter().map(|(candidate, _)| candidate).collect())
}

/// The two destinations of a ranked list (§2.2): the first, and the best after it on a network
/// known distinct from the first's ([`distinct_networks`]: declared and observed both differ).
/// When none is, the best not known to share the first's network ([`same_network`]), and failing
/// that the next at all (two destinations still survive one relay failing, if not one network).
pub fn pair(ranked: &[Weighted]) -> Result<(Option<Weighted>, Option<Weighted>), WireError> {
    let Some((first, rest)) = ranked.split_first() else {
        return Ok((None, None));
    };
    let others = || rest.iter().filter(|other| other.key != first.key);
    let second = others()
        .find(|other| distinct_networks(first.placement(), other.placement()))
        .or_else(|| others().find(|other| !same_network(first.placement(), other.placement())))
        .or_else(|| others().next());
    Ok((Some(*first), second.copied()))
}

/// The 63-bit draw of `key` for `area`, as `x` in 1..=2^63 (`u = x / 2^63`).
fn draw(area: Region, key: &PublicKey) -> u64 {
    let mut hasher = Blake2s256::new();
    hasher.update(RENDEZVOUS_DOMAIN);
    hasher.update([0]);
    hasher.update(area.as_u64().to_be_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut first = [0; 8];
    first.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(first) >> 1) + 1
}

/// `-log2(x / 2^63)` for `x` in 1..=2^63, in fixed point with `FRACTION_BITS` fractional bits,
/// at least 1 (so every score is finite): `63 - log2(x)`, the integer part from the leading bit
/// and each fractional bit by squaring the normalised mantissa (the classic binary logarithm,
/// exact integer work).
fn neg_log2(x: u64) -> u64 {
    const ONE: u128 = 1 << 62;
    let x = x.max(1);
    let whole = 63 - x.leading_zeros();
    // The mantissa in [1, 2) as Q2.62.
    let mut mantissa: u128 = if whole <= 62 {
        u128::from(x) << (62 - whole)
    } else {
        u128::from(x) >> (whole - 62)
    };
    let mut log = u64::from(whole) << FRACTION_BITS;
    for bit in (0..FRACTION_BITS).rev() {
        mantissa = (mantissa * mantissa) >> 62;
        if mantissa >= 2 * ONE {
            mantissa >>= 1;
            log |= 1 << bit;
        }
    }
    ((63_u64 << FRACTION_BITS) - log).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Identity;

    fn key(seed: u32) -> PublicKey {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        Identity::from_seed(bytes).public()
    }

    /// An observed address of its own /24 for each seed.
    fn host_of(seed: u32) -> IpAddr {
        let [_, a, b, c] = seed.to_be_bytes();
        IpAddr::V4(std::net::Ipv4Addr::new(10 ^ a, b, c, 1))
    }

    fn atlanta() -> Result<Region, WireError> {
        area_of(&Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })
    }

    fn relays(count: u32, weight: u64) -> Vec<Weighted> {
        (0..count)
            .map(|seed| Weighted {
                key: key(seed),
                weight,
                network: 64_500 + seed % 7,
                host: Some(host_of(seed)),
            })
            .collect()
    }

    /// A small deterministic generator, so the tests are the same on every run.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 11
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    #[test]
    fn the_fixed_point_logarithm_is_exact_at_powers_of_two_close_elsewhere_and_monotone() {
        let one = 1_u64 << FRACTION_BITS;
        assert_eq!(neg_log2(1 << 63), 1, "u = 1 scores finitely");
        assert_eq!(neg_log2(1 << 62), one);
        assert_eq!(neg_log2(1 << 32), 31 * one);
        assert_eq!(neg_log2(1), 63 * one);
        // log2(3) = 1.584962500721156...
        let three = neg_log2(3 << 61);
        let expected = (2 * one) - 6_807_362_062; // 2 - log2(3) = 0.41503749927884...
        // Each squaring truncates, so the last few of the 32 bits are approximate (deterministic
        // all the same): within 2^-26 of a bit.
        assert!(three.abs_diff(expected) <= 64, "{three} against {expected}");
        let mut previous = u64::MAX;
        for x in (1..64).map(|shift| (1_u64 << shift) - 1) {
            let log = neg_log2(x);
            assert!(log < previous, "falls as x grows");
            previous = log;
        }
    }

    #[test]
    fn the_ranking_is_deterministic_and_independent_of_input_order() -> Result<(), WireError> {
        let area = atlanta()?;
        let mut candidates: Vec<Weighted> = (0..40)
            .map(|seed| Weighted {
                key: key(seed),
                weight: 1 + u64::from(seed % 5) * 10,
                network: seed,
                host: Some(host_of(seed)),
            })
            .collect();
        let ranked = rank(area, &candidates)?;
        assert_eq!(ranked.len(), 40);
        assert_eq!(rank(area, &candidates)?, ranked);
        let mut random = Lcg(7);
        for _ in 0..20 {
            for at in (1..candidates.len()).rev() {
                let other = random.below(at as u64 + 1) as usize;
                candidates.swap(at, other);
            }
            assert_eq!(rank(area, &candidates)?, ranked);
        }
        // A key named twice counts once, by its greatest weight, whatever the order.
        let mut doubled = candidates.clone();
        doubled.push(Weighted {
            weight: 1,
            ..candidates[3]
        });
        assert_eq!(rank(area, &doubled)?, ranked);
        doubled.reverse();
        assert_eq!(rank(area, &doubled)?, ranked);
        // Another area ranks differently.
        let elsewhere = area_of(&Location {
            lat_e7: 515_000_000,
            lon_e7: -1_200_000,
            alt_m: 0,
            precision_m: 0,
        })?;
        assert_ne!(rank(elsewhere, &candidates)?, ranked);
        Ok(())
    }

    #[test]
    fn zero_weight_is_never_chosen() -> Result<(), WireError> {
        let mut candidates = relays(5, 0);
        candidates[2].weight = 1;
        let ranked = rank(atlanta()?, &candidates)?;
        assert_eq!(ranked, vec![candidates[2]]);
        assert!(rank(atlanta()?, &relays(5, 0))?.is_empty());
        Ok(())
    }

    #[test]
    fn weights_skew_the_choice_in_proportion() -> Result<(), WireError> {
        // Three relays weighted 1, 2 and 5: over many areas each ranks first in its share of
        // the weight (1/8, 2/8, 5/8).
        let candidates = [1_u64, 2, 5]
            .iter()
            .zip(0_u32..)
            .map(|(weight, seed)| Weighted {
                key: key(seed),
                weight: *weight,
                network: seed + 1,
                host: Some(host_of(seed)),
            })
            .collect::<Vec<_>>();
        let mut firsts = [0_u32; 3];
        let areas = (0..122)
            .flat_map(|base| areas_of(Region::from_u64(base_cell(base)).ok()?).ok())
            .flatten()
            .take(8_000)
            .collect::<Vec<_>>();
        assert_eq!(areas.len(), 8_000);
        for area in &areas {
            let first = rank(*area, &candidates)?[0];
            let index = candidates
                .iter()
                .position(|candidate| candidate.key == first.key)
                .ok_or(WireError::Invalid {
                    field: "rank",
                    value: 0,
                })?;
            firsts[index] += 1;
        }
        let total: u32 = firsts.iter().sum();
        for (count, weight) in firsts.iter().zip([1, 2, 5]) {
            let expected = f64::from(total) * f64::from(weight) / 8.0;
            let error = (f64::from(*count) - expected).abs() / expected;
            assert!(error < 0.08, "{firsts:?}: weight {weight} off by {error}");
        }
        Ok(())
    }

    /// The 122 resolution 0 cells, by their base cell number.
    fn base_cell(base: u64) -> u64 {
        0x0800_1fff_ffff_ffff | (base << 45)
    }

    #[test]
    fn a_relay_coming_or_going_moves_only_its_own_share() -> Result<(), WireError> {
        let candidates = relays(30, 10);
        let areas = areas_of(Region::from_u64(base_cell(20))?)?;
        let newcomer = Weighted {
            key: key(999),
            weight: 10,
            network: 1,
            host: Some(host_of(999)),
        };
        let mut grown = candidates.clone();
        grown.push(newcomer);
        let mut moved = 0;
        for area in &areas {
            let before = rank(*area, &candidates)?;
            let after = rank(*area, &grown)?;
            // Removing the newcomer from the new order gives the old order exactly.
            let without: Vec<_> = after
                .iter()
                .copied()
                .filter(|candidate| candidate.key != newcomer.key)
                .collect();
            assert_eq!(without, before);
            if after[0].key != before[0].key {
                assert_eq!(after[0].key, newcomer.key, "only to the newcomer");
                moved += 1;
            }
        }
        // About one area in 31 moves, all to the newcomer.
        assert!(moved > 0 && moved < areas.len() / 10, "{moved} moved");
        Ok(())
    }

    #[test]
    fn the_pair_falls_on_distinct_networks() -> Result<(), WireError> {
        let area = atlanta()?;
        // Ten relays on two networks: whoever ranks first, the second is on the other.
        let candidates: Vec<Weighted> = (0..10)
            .map(|seed| Weighted {
                key: key(seed),
                weight: 10,
                network: 100 + seed % 2,
                host: Some(host_of(seed)),
            })
            .collect();
        for shift in 0..10 {
            let mut some = candidates.clone();
            some.rotate_left(shift);
            some.truncate(6);
            let ranked = rank(area, &some)?;
            let (Some(first), Some(second)) = pair(&ranked)? else {
                return Err(WireError::Invalid {
                    field: "pair",
                    value: 0,
                });
            };
            assert_eq!(first, ranked[0]);
            assert_ne!(first.network, second.network);
            let best_other = ranked
                .iter()
                .find(|candidate| candidate.network != first.network)
                .copied();
            assert_eq!(Some(second), best_other, "the best on another network");
        }
        // One network only: the second is the next on it.
        let lone = rank(area, &relays(3, 1))?;
        let same: Vec<Weighted> = lone
            .iter()
            .map(|candidate| Weighted {
                network: 5,
                ..*candidate
            })
            .collect();
        assert_eq!(pair(&same)?, (Some(same[0]), Some(same[1])));
        // Nothing, or one relay.
        assert_eq!(pair(&[])?, (None, None));
        assert_eq!(pair(&same[..1])?, (Some(same[0]), None));
        // A relay that says nothing is never taken over one known to be elsewhere.
        let mixed = vec![
            Weighted {
                network: 7,
                ..same[0]
            },
            Weighted {
                network: 0,
                ..same[1]
            },
            Weighted {
                network: 8,
                ..same[2]
            },
        ];
        assert_eq!(pair(&mixed)?.1, Some(mixed[2]));
        Ok(())
    }

    #[test]
    fn distinct_networks_takes_both_the_declaration_and_the_observation() {
        let at = |text: &str| text.parse::<IpAddr>().ok();
        let place = |network, host: &str| Placement {
            network,
            host: at(host),
        };
        // Both differ: distinct.
        assert!(distinct_networks(
            place(1, "192.0.2.1"),
            place(2, "198.51.100.1")
        ));
        // One /24, whatever is declared: not distinct, and known the same.
        let (a, b) = (place(1, "192.0.2.1"), place(2, "192.0.2.200"));
        assert!(!distinct_networks(a, b) && same_network(a, b));
        // One declared network on two prefixes: not distinct, and known the same.
        let (a, b) = (place(7, "192.0.2.1"), place(7, "198.51.100.1"));
        assert!(!distinct_networks(a, b) && same_network(a, b));
        // IPv6 by /48, and a mapped IPv4 address as itself.
        assert!(!distinct_networks(
            place(1, "2001:db8:1::1"),
            place(2, "2001:db8:1:ffff::1")
        ));
        assert!(distinct_networks(
            place(1, "2001:db8:1::1"),
            place(2, "2001:db8:2::1")
        ));
        assert!(same_network(
            place(1, "::ffff:192.0.2.9"),
            place(2, "192.0.2.10")
        ));
        // Unknown on either side is never distinct, and not known the same.
        for (a, b) in [
            (place(0, "192.0.2.1"), place(2, "198.51.100.1")),
            (
                Placement {
                    network: 1,
                    host: None,
                },
                place(2, "198.51.100.1"),
            ),
        ] {
            assert!(!distinct_networks(a, b) && !same_network(a, b));
        }
    }

    #[test]
    fn the_area_of_a_point_is_one_cell_however_it_is_given() -> Result<(), WireError> {
        let location = Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        };
        let area = area_of(&location)?;
        assert_eq!(area.resolution(), AREA_RESOLUTION);
        assert_eq!(area_at(33.749, -84.388)?, area);
        assert_eq!(area_of_cell(Region::point(&location)?), Some(area));
        assert_eq!(area_of_cell(area), Some(area));
        assert_eq!(area_of_cell(Region::containing(&location, 1)?), None);
        assert!(area_at(91.0, 0.0).is_err());
        Ok(())
    }

    #[test]
    fn every_relay_computes_the_same_k_mlat_relays() -> Result<(), WireError> {
        // Each relay sees the offers in its own order (gossip arrives as it arrives).
        let area = atlanta()?;
        let offers: Vec<Weighted> = (0..12)
            .map(|seed| Weighted {
                key: key(seed),
                weight: u64::from(seed % 4) * 8,
                network: seed,
                host: Some(host_of(seed)),
            })
            .collect();
        let chosen = |seen: &[Weighted]| -> Result<Vec<PublicKey>, WireError> {
            Ok(rank(area, seen)?
                .into_iter()
                .take(MLAT_RELAYS_PER_AREA)
                .map(|candidate| candidate.key)
                .collect())
        };
        let expected = chosen(&offers)?;
        assert_eq!(expected.len(), MLAT_RELAYS_PER_AREA);
        let mut random = Lcg(99);
        for _ in 0..12 {
            let mut seen = offers.clone();
            for at in (1..seen.len()).rev() {
                seen.swap(at, random.below(at as u64 + 1) as usize);
            }
            assert_eq!(chosen(&seen)?, expected);
        }
        // A relay offering no cores is never among them.
        for key in &expected {
            assert!(
                offers
                    .iter()
                    .any(|offer| offer.key == *key && offer.weight > 0)
            );
        }
        Ok(())
    }

    /// The distributed-systems critic's question (RFC-0174 §1): 200 relays, an area's 10
    /// receivers. At random, under 1% of transmissions had any relay holding 4 of the receptions.
    /// Here each feeder measures its own band (the true round-trip times, its own noise), ranks
    /// the band for its area and sends to the pair; a relay must hold at least 4 of the 10.
    #[test]
    fn an_areas_feeders_land_on_the_same_few_relays() -> Result<(), WireError> {
        const RELAYS: u32 = 200;
        const FEEDERS: usize = 10;
        const TRIALS: usize = 400;
        let mut random = Lcg(2026);
        let mut held = 0;
        let mut random_held = 0;
        let areas = areas_of(Region::from_u64(base_cell(30))?)?;
        for trial in 0..TRIALS {
            let area = areas[trial % areas.len()];
            // Every relay's true round trip from the area (ms), and its declared spare slots.
            let relays: Vec<(Weighted, u64)> = (0..RELAYS)
                .map(|seed| {
                    let weighted = Weighted {
                        key: key(seed + 1000 * trial as u32),
                        weight: 50 + random.below(500),
                        network: 1 + (random.below(40) as u32),
                        host: Some(host_of(seed + 1000 * trial as u32)),
                    };
                    (weighted, 5 + random.below(200))
                })
                .collect();
            let mut counts = vec![0_u32; RELAYS as usize];
            let mut random_counts = vec![0_u32; RELAYS as usize];
            for _ in 0..FEEDERS {
                // Each feeder's measurement: the true time plus up to 3 ms of its own noise (and
                // its own access link, the same for every relay, which the band's rule absorbs).
                let access = random.below(30);
                let measured: Vec<u64> = relays
                    .iter()
                    .map(|(_, rtt)| rtt + access + random.below(4))
                    .collect();
                let closest = measured.iter().copied().min().unwrap_or(0);
                let edge = (closest + closest / 2).max(closest + 10);
                let band: Vec<Weighted> = relays
                    .iter()
                    .zip(&measured)
                    .filter(|(_, time)| **time <= edge)
                    .map(|((weighted, _), _)| *weighted)
                    .collect();
                let (first, second) = pair(&rank(area, &band)?)?;
                for chosen in [first, second].into_iter().flatten() {
                    if let Some(index) =
                        relays.iter().position(|(relay, _)| relay.key == chosen.key)
                    {
                        counts[index] += 1;
                    }
                }
                for _ in 0..2 {
                    random_counts[random.below(u64::from(RELAYS)) as usize] += 1;
                }
            }
            if counts.iter().any(|count| *count >= 4) {
                held += 1;
            }
            if random_counts.iter().any(|count| *count >= 4) {
                random_held += 1;
            }
        }
        let share = f64::from(held) / TRIALS as f64;
        let random_share = f64::from(random_held) / TRIALS as f64;
        assert!(share > 0.95, "an area's feeders scattered: {share}");
        assert!(random_share < 0.05, "the random baseline: {random_share}");
        Ok(())
    }

    #[test]
    fn a_region_names_its_areas_and_its_ancestors() -> Result<(), WireError> {
        let area = atlanta()?;
        // A finer region names its area; a coarser one its areas.
        let point = Region::point(&Location {
            lat_e7: 337_490_000,
            lon_e7: -843_880_000,
            alt_m: 0,
            precision_m: 0,
        })?;
        assert_eq!(areas_of(point)?, vec![area]);
        let coarse = Region::from_u64(base_cell(20))?;
        let under = areas_of(coarse)?;
        assert_eq!(under.len(), 343);
        assert!(under.iter().all(|cell| coarse.contains(*cell)));
        let path = ancestors(point)?;
        assert_eq!(path.len(), 16);
        assert_eq!(path[0], point);
        assert!(path.contains(&area));
        assert!(path.iter().all(|cell| cell.contains(point)));
        assert_eq!(ancestors(coarse)?, vec![coarse]);
        Ok(())
    }
}
