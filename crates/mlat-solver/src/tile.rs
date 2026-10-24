//! Canonical tiles (crate docs, § Tiles): where a shared clock model is fitted, which receivers
//! are its members, and which tile an aircraft is solved under. Every decision here is exact
//! integer arithmetic on millimetre sites, so independent implementations agree on it bit for
//! bit; the module refuses floating point at compile time.

#![deny(clippy::float_arithmetic)]

use std::collections::BTreeSet;

use tally_wire::PublicKey;

/// Tile levels: 0 to `LEVELS - 1`.
pub const LEVELS: u8 = 4;
/// Each level's footprint radius, millimetres: 50, 100, 200 and 400 km.
pub const RADIUS_MM: [i64; LEVELS as usize] = [50_000_000, 100_000_000, 200_000_000, 400_000_000];
/// The most members a tile has (`M`).
pub const MEMBERS_MAX: usize = 48;
/// The most tiles, over every level, that may hold a receiver's site in their footprint and be
/// fitted: a tile is fitted only where it holds the lower median of some aircraft's hearers
/// (`assign`), which lies within a hearer's spread of the ground, so every such tile's cube meets
/// the shell from 25 km under the ellipsoid to 10 km over it, and its centre is within the
/// level's footprint of the site. Counted by enumerating the cubes about sites at every latitude
/// (the test `no_site_is_in_more_tiles_than_planned` holds it): 90, 72, 64 and 58 by level.
pub const SITE_TILES_MOST: usize = 90 + 72 + 64 + 58;

/// One tile: a level and the integer ECEF cube (edge half the level's radius) its centre is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tile {
    pub level: u8,
    pub cube: [i64; 3],
}

/// A cube's edge at `level`, millimetres: half the footprint radius.
pub fn edge_mm(level: u8) -> i64 {
    RADIUS_MM[usize::from(level.min(LEVELS - 1))] / 2
}

/// The least integer at or above the square root of `value`.
fn isqrt_ceil(value: i128) -> i128 {
    if value <= 0 {
        return 0;
    }
    let mut x: i128 = 1;
    while x * x < value {
        x *= 2;
    }
    // Bisect between x / 2 and x for the least root whose square reaches `value`.
    let (mut low, mut high) = (x / 2, x);
    while low + 1 < high {
        let middle = (low + high) / 2;
        if middle * middle >= value {
            high = middle;
        } else {
            low = middle;
        }
    }
    if low * low >= value { low } else { high }
}

/// The footprint radius at `level`, millimetres: the level's radius plus half the cube's diagonal
/// (rounded up), so the footprint holds every receiver within the radius of any point in the cube.
pub fn footprint_mm(level: u8) -> i64 {
    let half = i128::from(edge_mm(level)) / 2;
    let half_diagonal = isqrt_ceil(3 * half * half);
    RADIUS_MM[usize::from(level.min(LEVELS - 1))] + i64::try_from(half_diagonal).unwrap_or(0)
}

impl Tile {
    /// The tile at `level` whose cube contains `point` (ECEF millimetres).
    pub fn containing(level: u8, point: [i64; 3]) -> Self {
        let edge = edge_mm(level);
        Self {
            level,
            cube: point.map(|axis| axis.div_euclid(edge)),
        }
    }

    /// The cube's centre, ECEF millimetres (the edge is even, so it is whole).
    pub fn centre_mm(&self) -> [i64; 3] {
        let edge = edge_mm(self.level);
        self.cube.map(|index| index * edge + edge / 2)
    }

    /// Whether a site is in the footprint: within `footprint_mm` of the centre, exactly.
    pub fn holds(&self, site_mm: [i64; 3]) -> bool {
        let reach = i128::from(footprint_mm(self.level));
        squared_distance(self.centre_mm(), site_mm) <= reach * reach
    }

    /// Big-endian: level, then the cube's three indices.
    pub fn bytes(&self) -> [u8; 25] {
        let mut out = [0u8; 25];
        out[0] = self.level;
        for (axis, value) in self.cube.iter().enumerate() {
            out[1 + 8 * axis..9 + 8 * axis].copy_from_slice(&value.to_be_bytes());
        }
        out
    }
}

/// Exact squared distance between two millimetre points.
pub fn squared_distance(a: [i64; 3], b: [i64; 3]) -> i128 {
    (0..3)
        .map(|axis| {
            let d = i128::from(a[axis]) - i128::from(b[axis]);
            d * d
        })
        .sum()
}

/// The coordinate-wise lower median of `points`, or `None` for none.
pub fn lower_median(points: &[[i64; 3]]) -> Option<[i64; 3]> {
    let middle = points.len().checked_sub(1)? / 2;
    let mut out = [0i64; 3];
    for (axis, slot) in out.iter_mut().enumerate() {
        let mut values: Vec<i64> = points.iter().map(|point| point[axis]).collect();
        values.sort_unstable();
        *slot = values[middle];
    }
    Some(out)
}

/// A tile's members from the sync-active receivers of its footprint (`candidates`, each with its
/// millimetre site): all of them when at most `MEMBERS_MAX`, else `MEMBERS_MAX` chosen by
/// farthest-point selection (`farthest`). Sorted by key.
pub fn members(candidates: &[(PublicKey, [i64; 3])]) -> Vec<PublicKey> {
    if candidates.len() <= MEMBERS_MAX {
        let mut all: Vec<PublicKey> = candidates.iter().map(|(key, _)| *key).collect();
        all.sort_unstable();
        all.dedup();
        return all;
    }
    farthest(candidates, MEMBERS_MAX)
}

/// Up to `count` of `candidates`, each in turn the one farthest (exact squared millimetres) from
/// everything already chosen, ties to the lowest key; the first, the lowest key. Sorted by key.
pub fn farthest(candidates: &[(PublicKey, [i64; 3])], count: usize) -> Vec<PublicKey> {
    let mut sorted: Vec<(PublicKey, [i64; 3])> = candidates.to_vec();
    sorted.sort_unstable_by_key(|(key, _)| *key);
    sorted.dedup_by_key(|(key, _)| *key);
    let mut nearest: Vec<i128> = vec![i128::MAX; sorted.len()];
    let mut taken = vec![false; sorted.len()];
    let mut chosen = Vec::new();
    while chosen.len() < count && chosen.len() < sorted.len() {
        // The largest distance to the chosen; of equals, the lowest key (the first in order).
        let mut best: Option<usize> = None;
        for (index, value) in nearest.iter().enumerate() {
            if taken[index] {
                continue;
            }
            if best.is_none_or(|top| *value > nearest[top]) {
                best = Some(index);
            }
        }
        let Some(index) = best else { break };
        taken[index] = true;
        chosen.push(sorted[index].0);
        let here = sorted[index].1;
        for (other, value) in nearest.iter_mut().enumerate() {
            if !taken[other] {
                *value = (*value).min(squared_distance(here, sorted[other].1));
            }
        }
    }
    chosen.sort_unstable();
    chosen
}

/// The tile an aircraft is solved under (crate docs, § Assignment), given its hearers' sites and
/// the members of any tile: at each level, the tile whose cube contains the hearers' lower median;
/// of those, the one holding the most hearers among its members, ties to the lower level. `None`
/// for no hearers.
pub fn assign(
    hearers: &[(PublicKey, [i64; 3])],
    mut members_of: impl FnMut(Tile) -> Vec<PublicKey>,
) -> Option<(Tile, Vec<PublicKey>)> {
    let points: Vec<[i64; 3]> = hearers.iter().map(|(_, site)| *site).collect();
    let median = lower_median(&points)?;
    let keys: BTreeSet<PublicKey> = hearers.iter().map(|(key, _)| *key).collect();
    let mut best: Option<(Tile, Vec<PublicKey>)> = None;
    for level in 0..LEVELS {
        let tile = Tile::containing(level, median);
        let scope: Vec<PublicKey> = members_of(tile)
            .into_iter()
            .filter(|member| keys.contains(member))
            .collect();
        if best
            .as_ref()
            .is_none_or(|(_, held)| scope.len() > held.len())
        {
            best = Some((tile, scope));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    fn key(seed: u8) -> PublicKey {
        Identity::from_seed([seed; 32]).public()
    }

    #[test]
    fn a_cube_holds_its_points_and_its_footprint_reaches_the_radius_from_any_of_them() {
        for level in 0..LEVELS {
            let edge = edge_mm(level);
            assert_eq!(edge * 2, RADIUS_MM[usize::from(level)]);
            let point = [3_900_123_456, 300_987_654, 5_000_111_222];
            let tile = Tile::containing(level, point);
            let centre = tile.centre_mm();
            for axis in 0..3 {
                assert!(point[axis] >= centre[axis] - edge / 2);
                assert!(point[axis] < centre[axis] + edge / 2);
            }
            // A site the radius from the cube's farthest corner is still in the footprint.
            let corner = [
                centre[0] - edge / 2,
                centre[1] - edge / 2,
                centre[2] - edge / 2,
            ];
            let far = [
                corner[0] - RADIUS_MM[usize::from(level)],
                corner[1],
                corner[2],
            ];
            assert!(tile.holds(corner) && tile.holds(far));
            let beyond = [centre[0] - footprint_mm(level) - 1, centre[1], centre[2]];
            assert!(!tile.holds(beyond));
        }
        assert_eq!(isqrt_ceil(16), 4);
        assert_eq!(isqrt_ceil(17), 5);
    }

    #[test]
    fn members_are_capped_by_farthest_point_and_assignment_prefers_the_lower_level() {
        let many: Vec<(PublicKey, [i64; 3])> = (0..60u8)
            .map(|seed| (key(seed), [i64::from(seed) * 1_000_000, 0, 0]))
            .collect();
        let chosen = members(&many);
        assert_eq!(chosen.len(), MEMBERS_MAX);
        assert_eq!(members(&many[..10]).len(), 10);
        let hearers = &many[..5];
        let (tile, scope) = assign(hearers, |_| many.iter().map(|(k, _)| *k).collect())
            .unwrap_or((Tile::containing(3, [0; 3]), Vec::new()));
        assert_eq!(tile.level, 0, "every level holds them all: the lowest wins");
        assert_eq!(scope.len(), 5);
    }
}
