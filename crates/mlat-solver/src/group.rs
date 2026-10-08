//! Grouping receptions into transmissions (crate docs, § Grouping): integer arithmetic on raw
//! counters through the fixed-point clock model, so every implementation groups identically.

use std::collections::{BTreeMap, BTreeSet};

use crate::clock::{ClockModel, ModelTime, Reach};
use crate::obs::{ObservationId, Reception};

/// The grouping gate, picoseconds: 3 ms, the light time across 900 km, more than any two
/// receivers that can hear one aircraft are apart (each within 450 km of it), and far less than
/// the shortest interval between two identical transmissions (an all-call squitter repeats after
/// 0.8 s at the earliest).
pub const GATE_PS: i128 = 3_000_000_000;

/// One reception mapped to model time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timed {
    pub id: ObservationId,
    pub time: ModelTime,
    /// The wall clock of the batch that carried it (the earliest copy's).
    pub wall_ms: u64,
}

/// The receptions of one transmission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmission {
    /// The message bytes.
    pub data: Vec<u8>,
    /// Sorted by identity.
    pub receptions: Vec<Timed>,
}

/// Every reception, accounted for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grouping {
    /// Sorted by (earliest model time, bytes).
    pub transmissions: Vec<Transmission>,
    /// Receptions in a cluster where one receiver appears twice: identical bytes the gate cannot
    /// tell apart. Sorted.
    pub ambiguous: Vec<ObservationId>,
    /// Receptions the clock model cannot map (unknown receiver or epoch, outside its bins).
    /// Sorted.
    pub unmapped: Vec<ObservationId>,
}

/// Groups receptions into transmissions:
///
/// 1. Receptions are deduplicated by identity, and each is mapped to model time
///    (`ClockModel::time`); one that maps to nothing is `unmapped`.
/// 2. Receptions are partitioned by message bytes, and each part is sorted by
///    (model time, identity).
/// 3. Walking each part in order, a reception joins the open cluster if its model time is at
///    most `GATE_PS` after the cluster's first reception; otherwise it opens a new cluster.
/// 4. A cluster in which one receiver key appears twice is `ambiguous`, all of it; every other
///    cluster is a transmission.
pub fn group(model: &ClockModel, receptions: &[Reception]) -> Grouping {
    group_reach(model, receptions, Reach::Window)
}

/// As `group`, mapping each reception with `ClockModel::time_reach` at `reach`: what a
/// provisional solution groups by, the model carried past its knots.
pub fn group_reach(model: &ClockModel, receptions: &[Reception], reach: Reach) -> Grouping {
    let mut unique: BTreeMap<ObservationId, &Reception> = BTreeMap::new();
    for reception in receptions {
        let entry = unique.entry(reception.id()).or_insert(reception);
        if reception.wall_ms < entry.wall_ms {
            *entry = reception;
        }
    }
    let mut grouping = Grouping::default();
    let mut parts: BTreeMap<&[u8], Vec<Timed>> = BTreeMap::new();
    for (id, reception) in unique {
        let mapped = model.time_reach(
            &reception.receiver,
            reception.epoch,
            reception.observation.timestamp,
            reach,
        );
        match mapped {
            None => grouping.unmapped.push(id),
            Some(time) => parts
                .entry(&reception.observation.data)
                .or_default()
                .push(Timed {
                    id,
                    time,
                    wall_ms: reception.wall_ms,
                }),
        }
    }
    for (data, mut list) in parts {
        list.sort_by(|a, b| a.time.ps.cmp(&b.time.ps).then(a.id.cmp(&b.id)));
        let mut clusters: Vec<Vec<Timed>> = Vec::new();
        for timed in list {
            match clusters.last_mut() {
                Some(cluster) if timed.time.ps - cluster[0].time.ps <= GATE_PS => {
                    cluster.push(timed);
                }
                _ => clusters.push(vec![timed]),
            }
        }
        for mut cluster in clusters {
            let receivers: BTreeSet<_> = cluster.iter().map(|timed| timed.id.receiver).collect();
            if receivers.len() != cluster.len() {
                grouping
                    .ambiguous
                    .extend(cluster.iter().map(|timed| timed.id));
                continue;
            }
            cluster.sort_by_key(|timed| timed.id);
            grouping.transmissions.push(Transmission {
                data: data.to_vec(),
                receptions: cluster,
            });
        }
    }
    grouping.transmissions.sort_by(|a, b| {
        let first = |t: &Transmission| t.receptions.iter().map(|r| r.time.ps).min();
        first(a).cmp(&first(b)).then(a.data.cmp(&b.data))
    });
    grouping.ambiguous.sort_unstable();
    grouping.unmapped.sort_unstable();
    grouping
}

impl Transmission {
    /// The window bin the transmission belongs to (crate docs, § Windows): its receptions' wall
    /// clocks' lower median's.
    pub fn bin(&self) -> Option<i64> {
        let mut walls: Vec<u64> = self.receptions.iter().map(|timed| timed.wall_ms).collect();
        crate::scope::bin_of_transmission(&mut walls)
    }
}
