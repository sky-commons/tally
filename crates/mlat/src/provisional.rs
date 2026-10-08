//! Provisional positions (RFC-0171 §3.8.1, RFC-0174 §2.4): a final position comes 7 to 47 s after
//! its transmission (the stride), so the engine also solves each target's transmissions about a
//! second after they are heard, under the newest model it has published of a tile holding their
//! receivers, carried past that model's knots (`tally_mlat_solver::Reach::Carried`, crate docs
//! § Provisional solutions), and publishes them as `Record::Provisional`. A final position of the
//! same transmission supersedes each one (`tally_merge`).
//!
//! - **What is solved** is what a window would solve: the replies (never the ADS-B positions,
//!   which sync clocks) of an aircraft no ADS-B position of which was heard in the last
//!   `ADSB_HORIZON_MS` (the span of a window), or which is in its bin's calibration sample
//!   (`tally_mlat_solver::held::sampled`).
//! - **When**: a transmission is due once `SETTLE_MS` has passed by the engine's clock since the
//!   first of its receptions arrived, and it holds enough receivers to be solved (until then its
//!   receptions wait, to `KEPT_PAST_SETTLE_MS`: the rest may be a hop away, on another relay). A feeder seals a batch once a second, so a transmission's
//!   receptions reach the engine spread over that second by the receivers' sealing phases, plus
//!   the network's spread; mlat-server's 0.9 s (adsb.lol's `MLAT_DELAY`) is for clients that
//!   stream, and a second and a tenth collects what a second's batching spreads. What arrives later
//!   is not waited for: the final position has it.
//! - **Which model**: of the newest published model of each tile (at most one per tile, at most
//!   `MAX_CARRY_PS` carried), the one whose members are the most of the receivers heard, ties to
//!   the newest window and then the lower tile. Each provisional names its model, and is a
//!   deterministic function of the model, its receptions and the spec, as a final one is, so the
//!   fault proofs that hold finals hold provisionals.
//! - **How many**: at most one per aircraft per second, the first due in each second of its
//!   receptions' earliest wall clock: about the rate a window solves (crate docs, § Targets).
//! - **Checked**: every one is read back and verified with the model carried (`verify_reach`)
//!   against the receptions it was solved from, as any checker would
//!   (`publish::solve_published`); one that fails is dropped and counted.
//! - **Bounded**: receptions waiting by count (`MAX_WAITING`), the oldest first; a model is
//!   forgotten once it can be carried no further.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tally_mlat_solver::held::sampled;
use tally_mlat_solver::scope::{GRID_MS, Window, bin_of};
use tally_mlat_solver::{
    Calibrated, Citation, ClockModel as Model, MAX_CARRY_PS, ObservationId, Reach, Reception,
    SPEC_VERSION, Tile, Transmission, Unpublished, modes, publish,
};
use tally_wire::batch::Hash;
use tally_wire::{Decoded, Identity, Positions, PublicKey, Record, SolutionsContent};

use crate::window::{Part, parallel};

/// How long after the first of a transmission's receptions arrives it is solved.
pub const SETTLE_MS: u64 = 1_100;
/// How long after an aircraft's last ADS-B position it is a target again: a window's span.
pub const ADSB_HORIZON_MS: u64 =
    (tally_mlat_solver::scope::BEFORE as u64 + 1 + tally_mlat_solver::scope::AFTER as u64)
        * GRID_MS;
/// Receptions waiting to be solved, at most: a second and a tenth of the whole world's targets'
/// replies many times over.
pub const MAX_WAITING: usize = 1 << 20;
/// How long a waiting reception is kept past its settling time when no model can carry it, or
/// while too few receivers of its transmission have come to solve it.
const KEPT_PAST_SETTLE_MS: u64 = 1_000;

/// A published tile model, carried for provisional solutions.
pub struct Carried {
    pub tile: Tile,
    pub window: Window,
    /// The signed manifest's id, which a provisional cites.
    pub id: Hash,
    pub model: Model,
    pub calibrated: Calibrated,
}

impl Carried {
    /// The wall clock past which the model can be carried no further.
    fn spent_ms(&self) -> u64 {
        (self.window.last.max(0) as u64 + 1) * GRID_MS + (MAX_CARRY_PS / 1_000_000_000) as u64
    }
}

struct Waiting {
    reception: Reception,
    arrived_ms: u64,
}

/// What provisional solving did since the last time it was asked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Transmissions chosen for solving.
    pub transmissions: usize,
    pub solved: usize,
    pub unsolved: usize,
    pub rejected: usize,
    /// Receptions no model held could map, given up on.
    pub unmodelled: usize,
    /// Receptions dropped for room.
    pub dropped: usize,
    pub records: usize,
}

impl Part for Report {
    fn add(&mut self, other: &Report) {
        self.transmissions += other.transmissions;
        self.solved += other.solved;
        self.unsolved += other.unsolved;
        self.rejected += other.rejected;
        self.unmodelled += other.unmodelled;
        self.dropped += other.dropped;
        self.records += other.records;
    }
}

/// The provisional side of the engine's state.
#[derive(Default)]
pub struct Provisional {
    models: BTreeMap<Tile, Arc<Carried>>,
    by_receiver: BTreeMap<PublicKey, BTreeSet<Tile>>,
    waiting: BTreeMap<u32, Vec<Waiting>>,
    count: usize,
    /// The newest wall clock of each aircraft's ADS-B position.
    adsb: BTreeMap<u32, u64>,
    /// The last second each aircraft was solved in.
    solved_second: BTreeMap<u32, u64>,
    sequence: u64,
    report: Report,
}

/// A provisional step's work, owned.
pub struct Job {
    pub identity: Identity,
    pub boot_id: u64,
    pub issued_ms: u64,
    pub threads: usize,
    pub sequence: u64,
    /// The transmissions, each with its model and the receptions it was grouped from.
    pub work: Vec<(Arc<Carried>, Transmission)>,
}

/// A finished provisional step.
pub struct Outcome {
    pub records: Vec<Record>,
    pub sequence: u64,
    pub report: Report,
}

impl Provisional {
    /// Takes a published model: the newest of its tile replaces the one held.
    pub fn adopt(&mut self, carried: Carried) {
        if self
            .models
            .get(&carried.tile)
            .is_some_and(|held| held.window.last >= carried.window.last)
        {
            return;
        }
        self.forget_model(carried.tile);
        for site in &carried.model.scope {
            self.by_receiver
                .entry(site.receiver)
                .or_default()
                .insert(carried.tile);
        }
        self.models.insert(carried.tile, Arc::new(carried));
    }

    fn forget_model(&mut self, tile: Tile) {
        let Some(held) = self.models.remove(&tile) else {
            return;
        };
        for site in &held.model.scope {
            if let Some(tiles) = self.by_receiver.get_mut(&site.receiver) {
                tiles.remove(&tile);
                if tiles.is_empty() {
                    self.by_receiver.remove(&site.receiver);
                }
            }
        }
    }

    /// Models held now.
    pub fn models(&self) -> usize {
        self.models.len()
    }

    /// Takes a batch the engine admitted from `receiver`, arrived at `now_ms`.
    pub fn hear(&mut self, batch: &Decoded, now_ms: u64) {
        let receiver = batch.receiver();
        let wall_ms = batch.wall_ms();
        for observation in batch.views() {
            let data = observation.data;
            let Some(address) = modes::address(data) else {
                continue;
            };
            match modes::downlink_format(data) {
                Some(17 | 18) => {
                    if modes::airborne_position(data).is_some() {
                        let newest = self.adsb.entry(address).or_insert(wall_ms);
                        *newest = (*newest).max(wall_ms);
                    }
                }
                Some(0 | 4 | 5 | 11 | 16 | 20 | 21) => {
                    if !self.target(address, wall_ms) {
                        continue;
                    }
                    if self.count >= MAX_WAITING {
                        self.report.dropped += 1;
                        continue;
                    }
                    self.count += 1;
                    self.waiting.entry(address).or_default().push(Waiting {
                        reception: Reception {
                            receiver,
                            epoch: batch.counter_epoch(),
                            observation: observation.to_observation(),
                            wall_ms,
                        },
                        arrived_ms: now_ms,
                    });
                }
                _ => {}
            }
        }
    }

    /// Whether a reply of `address` heard at `wall_ms` is a target's (module docs).
    fn target(&self, address: u32, wall_ms: u64) -> bool {
        let quiet = self
            .adsb
            .get(&address)
            .is_none_or(|newest| wall_ms.saturating_sub(*newest) > ADSB_HORIZON_MS);
        quiet || sampled(address, bin_of(wall_ms))
    }

    /// Hands out the transmissions due by `now_ms`, and forgets what can no longer be solved.
    /// `None` when nothing is due.
    pub fn due(
        &mut self,
        now_ms: u64,
        identity: &Identity,
        boot_id: u64,
        issued_ms: u64,
        threads: usize,
    ) -> Option<Job> {
        let spent: Vec<Tile> = self
            .models
            .iter()
            .filter(|(_, held)| held.spent_ms() < now_ms)
            .map(|(tile, _)| *tile)
            .collect();
        for tile in spent {
            self.forget_model(tile);
        }
        self.adsb
            .retain(|_, newest| now_ms.saturating_sub(*newest) <= 2 * ADSB_HORIZON_MS);
        let settled = now_ms.saturating_sub(SETTLE_MS);
        let mut work = Vec::new();
        let addresses: Vec<u32> = self
            .waiting
            .iter()
            .filter(|(_, list)| list.iter().any(|one| one.arrived_ms <= settled))
            .map(|(address, _)| *address)
            .collect();
        for address in addresses {
            let Some(list) = self.waiting.remove(&address) else {
                continue;
            };
            self.count -= list.len();
            let kept = self.solve_due(address, list, settled, &mut work);
            if !kept.is_empty() {
                self.count += kept.len();
                self.waiting.insert(address, kept);
            }
        }
        self.solved_second
            .retain(|_, second| now_ms / 1000 <= *second + ADSB_HORIZON_MS / 1000);
        if work.is_empty() {
            return None;
        }
        let job = Job {
            identity: identity.clone(),
            boot_id,
            issued_ms,
            threads: threads.max(1),
            sequence: self.sequence,
            work,
        };
        Some(job)
    }

    /// One aircraft's waiting receptions: its due transmissions handed out (the first of each
    /// second), and what is not yet due kept.
    fn solve_due(
        &mut self,
        address: u32,
        list: Vec<Waiting>,
        settled: u64,
        work: &mut Vec<(Arc<Carried>, Transmission)>,
    ) -> Vec<Waiting> {
        let expired = |one: &Waiting| one.arrived_ms + KEPT_PAST_SETTLE_MS <= settled;
        let Some(carried) = self.model_for(&list) else {
            let before = list.len();
            let kept: Vec<Waiting> = list.into_iter().filter(|one| !expired(one)).collect();
            self.report.unmodelled += before - kept.len();
            return kept;
        };
        let receptions: Vec<Reception> = list.iter().map(|one| one.reception.clone()).collect();
        let arrived: BTreeMap<ObservationId, u64> = list
            .iter()
            .map(|one| (one.reception.id(), one.arrived_ms))
            .collect();
        let grouping = tally_mlat_solver::group_reach(&carried.model, &receptions, Reach::Carried);
        let mut used: BTreeSet<ObservationId> = BTreeSet::new();
        for transmission in grouping.transmissions {
            let first = transmission
                .receptions
                .iter()
                .filter_map(|timed| arrived.get(&timed.id))
                .min()
                .copied()
                .unwrap_or(u64::MAX);
            if first > settled {
                continue;
            }
            // Fewer receivers than any solve takes: what else heard it is still on its way (from
            // the relays that hold those receivers, RFC-0174 §2.3), so it waits until it can be
            // solved or expires; it never takes the aircraft's second meanwhile.
            let receivers: BTreeSet<PublicKey> = transmission
                .receptions
                .iter()
                .map(|timed| timed.id.receiver)
                .collect();
            if receivers.len() < tally_mlat_solver::solve::MIN_RECEIVERS_WITH_ALTITUDE {
                continue;
            }
            used.extend(transmission.receptions.iter().map(|timed| timed.id));
            let second = transmission
                .receptions
                .iter()
                .map(|timed| timed.wall_ms / 1000)
                .min()
                .unwrap_or(0);
            if self
                .solved_second
                .get(&address)
                .is_some_and(|last| *last >= second)
            {
                continue;
            }
            self.solved_second.insert(address, second);
            work.push((Arc::clone(&carried), transmission));
        }
        let (_, rest): (Vec<Waiting>, Vec<Waiting>) = list
            .into_iter()
            .partition(|one| used.contains(&one.reception.id()));
        let (gone, kept): (Vec<Waiting>, Vec<Waiting>) = rest.into_iter().partition(expired);
        self.report.unmodelled += gone.len();
        kept
    }

    /// The model the most of `list`'s receivers are members of (module docs).
    fn model_for(&self, list: &[Waiting]) -> Option<Arc<Carried>> {
        let receivers: BTreeSet<PublicKey> =
            list.iter().map(|one| one.reception.receiver).collect();
        let mut counts: BTreeMap<Tile, usize> = BTreeMap::new();
        for receiver in &receivers {
            for tile in self.by_receiver.get(receiver).into_iter().flatten() {
                *counts.entry(*tile).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .filter_map(|(tile, count)| self.models.get(&tile).map(|held| (count, held)))
            .max_by(|(a, x), (b, y)| {
                a.cmp(b)
                    .then(x.window.last.cmp(&y.window.last))
                    .then(y.tile.cmp(&x.tile))
            })
            .map(|(_, held)| Arc::clone(held))
    }

    /// Takes a finished job: its records are the next in this boot's provisional sequence.
    pub fn apply(&mut self, outcome: &Outcome) {
        self.sequence = outcome.sequence;
        self.report.add(&outcome.report);
    }

    /// What provisional solving did since the last call.
    pub fn take_report(&mut self) -> Report {
        std::mem::take(&mut self.report)
    }
}

impl Job {
    pub fn run(self) -> Outcome {
        let (solved, mut report) = parallel(self.threads, &self.work, solve_one);
        let solutions: Vec<tally_wire::Solution> = solved.into_iter().flatten().collect();
        let records = crate::window::pack_with(
            self.sequence,
            solutions,
            |sequence, run: &[tally_wire::Solution]| {
                Positions::sign_provisional(
                    &self.identity,
                    &SolutionsContent {
                        boot_id: self.boot_id,
                        sequence,
                        issued_ms: self.issued_ms,
                        spec_version: SPEC_VERSION,
                        solutions: run.to_vec(),
                    },
                )
            },
        );
        report.records = records.len();
        Outcome {
            sequence: self.sequence + records.len() as u64,
            records: records.into_iter().map(Record::Provisional).collect(),
            report,
        }
    }
}

/// Solves one transmission under its carried model, to the wire's form, verified as any checker
/// would (`publish::solve_published`).
fn solve_one(
    (carried, transmission): &(Arc<Carried>, Transmission),
    report: &mut Report,
) -> Option<tally_wire::Solution> {
    report.transmissions += 1;
    match publish::solve_published(
        &carried.calibrated,
        transmission,
        carried.id,
        Citation::default(),
    ) {
        Ok((_, wire)) => {
            report.solved += 1;
            Some(tally_wire::Solution {
                addressed: tally_wire::AddressedCitation::default(),
                ..wire
            })
        }
        Err(Unpublished::Refuted(_)) => {
            report.rejected += 1;
            None
        }
        Err(_) => {
            report.unsolved += 1;
            None
        }
    }
}

#[cfg(test)]
#[path = "provisional_tests.rs"]
mod tests;
