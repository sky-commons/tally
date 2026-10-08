//! Where a v2 feeder sends (RFC-0174 §2.2): the two nearest healthy relays on different networks.
//! Of the band (`probe::band`), ranked by `tally_wire::rendezvous::rank` over the feeder's area
//! weighted by each relay's signed spare feeder capacity, the first, and the best after it on
//! another network; with hysteresis (a newcomer displaces a held relay only after three rounds in
//! a row ranked above it and in the band; a held relay leaves the band only after three rounds
//! outside it), failover to the next in the ranking, and relays remembered as swallowing
//! (`delivery_check`) left out. The home, anchor and random slots go.
//!
//! Decisions the RFC leaves to the build:
//! - **Two networks.** The pair is `rendezvous::pair`'s, and "distinct" is
//!   `rendezvous::distinct_networks`, the one rule relays use too: the declared networks
//!   (autonomous systems) differ and the addresses the feeder's probes reached are in different
//!   prefixes (/24, /48). A network of 0 or an address not observed is never known to differ.
//!   When the band has no relay known to be on another network than the first, the nearest beyond
//!   the band that is one is the second. Two networks matter more than a few milliseconds.
//! - **A held relay keeps its place in the band.** It already holds this feeder's slot, so it is
//!   measured as able to take this feeder whatever its probe said of its capacity (no spare slot,
//!   or turned away as full): a relay is never left because the feeder, or other feeders, took
//!   its last slot. One that turns this feeder's own session away is `failed`.
//! - **No location, or no ranking.** A feeder with no area (no `--lat`/`--lon`), or a ranking that
//!   cannot be computed, orders the band by measured time, nearest first.
//! - **Failover.** A relay that failed, refused or redirected is left out of the next
//!   `FAILED_ROUNDS` rounds (a relay that asked to be left for longer is avoided by the caller for
//!   as long as it asked), and its place goes at once to the next in the last ranking that can
//!   stand beside the remaining relay (on a network known to differ, failing that not known to be
//!   the same). The new session is dialled after `failover_jitter`, so an
//!   area's feeders do not all arrive at the next relay in the same instant.
//! - **The feeder's own probes decide that a relay is gone.** A held relay probed and not measured
//!   (no connection, no signed reply) for `FAILED_ROUNDS` rounds in a row is dropped and its place
//!   filled, whatever the directory still says of it (an offer lives three minutes): being slow is
//!   the band's hysteresis, being silent is failure. Its session usually says so sooner (`relays`).

use std::collections::HashMap;
use std::time::Duration;

use tally_wire::rendezvous::{self, Placement, Weighted};
use tally_wire::{PublicKey, Region, RelayAddress};

use crate::probe::{self, Measured};

/// Rounds a change must hold before the choice moves.
pub const HYSTERESIS_ROUNDS: u32 = 3;
/// Rounds a relay that failed is left out of the ranking, and rounds in a row a held relay's probe
/// may fail before it is dropped.
pub const FAILED_ROUNDS: u32 = 2;
/// The most a failover's first dial is delayed.
pub const FAILOVER_JITTER: Duration = Duration::from_secs(10);
/// How many relays a feeder publishes to.
pub const DESTINATIONS: usize = 2;

/// The feeder's two destinations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Choice {
    pub first: Option<RelayAddress>,
    pub second: Option<RelayAddress>,
}

impl Choice {
    /// The relays chosen, first first.
    pub fn relays(&self) -> Vec<RelayAddress> {
        self.first.iter().chain(&self.second).cloned().collect()
    }

    pub fn keys(&self) -> Vec<PublicKey> {
        self.relays().iter().map(|relay| relay.key).collect()
    }
}

/// How a feeder chooses its relays from a round's measurements.
pub trait RelaySelection: Send {
    /// The choice after a round. `area` is the feeder's (`tally_wire::rendezvous::area_of`), none
    /// without a location; `avoid` the relays remembered as swallowing, and those that asked to be
    /// left.
    fn choose(
        &mut self,
        area: Option<Region>,
        measured: &[Measured],
        avoid: &[PublicKey],
    ) -> Choice;

    /// A held relay failed, refused or redirected: the next in the ranking takes its place. With
    /// no other to take it, the relay is kept, to be dialled again at the backoff's pace.
    fn failed(&mut self, relay: &PublicKey) -> Choice;

    /// A held relay is to be left whatever else there is (found swallowing): its place goes to the
    /// next in the ranking, or stays empty.
    fn left(&mut self, relay: &PublicKey) -> Choice;
}

/// A relay as the choice sees it: where to dial it, and where it sits (what it declares, and
/// the address the probe reached).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    relay: RelayAddress,
    placement: Placement,
}

impl Candidate {
    fn of(measured: &Measured) -> Self {
        Self {
            relay: measured.relay.clone(),
            placement: measured.placement(),
        }
    }

    /// Known to be on another network (`rendezvous::distinct_networks`).
    fn known_distinct(&self, other: &Self) -> bool {
        rendezvous::distinct_networks(self.placement, other.placement)
    }

    /// Another relay not known to share a network (`rendezvous::same_network`).
    fn may_differ(&self, other: &Self) -> bool {
        self.relay.key != other.relay.key
            && !rendezvous::same_network(self.placement, other.placement)
    }

    fn weighted(&self) -> Weighted {
        Weighted {
            key: self.relay.key,
            weight: 1,
            network: self.placement.network,
            host: self.placement.host,
        }
    }
}

/// The best of `candidates` to stand beside `others`: one known to be on another network than
/// each, failing that one not known to share a network with any, failing that any (two relays on
/// one network still survive one relay failing).
fn beside<'a>(
    others: &[&Candidate],
    mut candidates: impl Iterator<Item = &'a Candidate> + Clone,
) -> Option<&'a Candidate> {
    let fresh = |candidate: &&Candidate| {
        others
            .iter()
            .all(|other| other.relay.key != candidate.relay.key)
    };
    candidates
        .clone()
        .filter(fresh)
        .find(|candidate| others.iter().all(|other| other.known_distinct(candidate)))
        .or_else(|| {
            candidates
                .clone()
                .filter(fresh)
                .find(|candidate| others.iter().all(|other| other.may_differ(candidate)))
        })
        .or_else(|| candidates.find(fresh))
}

/// A relay the feeder holds.
#[derive(Clone, Debug)]
struct Held {
    candidate: Candidate,
    /// Rounds in a row it has been outside the band.
    outside: u32,
    /// Rounds in a row its probe failed.
    silent: u32,
}

/// The band, the per-area weighted rendezvous ranking, two networks, and hysteresis.
#[derive(Default)]
pub struct BandRendezvous {
    held: Vec<Held>,
    /// The pair that has outranked the held one, and for how many rounds in a row.
    pending: Option<(Vec<PublicKey>, u32)>,
    /// The last round's order: the band ranked, then the rest by time. Failover reads it.
    ranking: Vec<Candidate>,
    /// Relays that failed, and the rounds they are still left out.
    failed: HashMap<PublicKey, u32>,
}

impl BandRendezvous {
    pub fn new() -> Self {
        Self::default()
    }

    fn choice(&self) -> Choice {
        let mut relays = self.held.iter().map(|held| held.candidate.relay.clone());
        Choice {
            first: relays.next(),
            second: relays.next(),
        }
    }

    /// Fills empty places from the ranking, each beside the others held (`beside`).
    fn fill(&mut self) {
        while self.held.len() < DESTINATIONS {
            let others: Vec<&Candidate> = self.held.iter().map(|held| &held.candidate).collect();
            let open = self
                .ranking
                .iter()
                .filter(|candidate| !self.failed.contains_key(&candidate.relay.key));
            let Some(next) = beside(&others, open).cloned() else {
                return;
            };
            self.held.push(Held {
                candidate: next,
                outside: 0,
                silent: 0,
            });
        }
    }
}

/// The ranking of `band` for `area`: weighted rendezvous over the area, or by time without one.
fn ranked(area: Option<Region>, band: &[Measured], held: &[PublicKey]) -> Vec<Candidate> {
    let by_time = || {
        let mut sorted: Vec<&Measured> = band.iter().collect();
        sorted.sort_by_key(|each| each.rtt);
        sorted.into_iter().map(Candidate::of).collect()
    };
    let Some(area) = area else {
        return by_time();
    };
    let weighted: Vec<Weighted> = band
        .iter()
        .map(|each| Weighted {
            key: each.relay.key,
            weight: if held.contains(&each.relay.key) {
                each.weight().max(1)
            } else {
                each.weight()
            },
            network: each.network(),
            host: each.observed,
        })
        .collect();
    match rendezvous::rank(area, &weighted) {
        Ok(order) => order
            .iter()
            .filter_map(|ranked| band.iter().find(|each| each.relay.key == ranked.key))
            .map(Candidate::of)
            .collect(),
        Err(error) => {
            eprintln!("tally-feed: ranking the band: {error}; nearest first");
            by_time()
        }
    }
}

/// The two destinations: `rendezvous::pair` over the band's ranking (the first, and the best
/// after it on a network known to differ, or failing one, not known to be the same), then, when
/// the band has no second known to be elsewhere, the nearest beyond the band that is; and never a
/// second on the first's own host.
fn target_of(band: &[Candidate], beyond: &[Candidate]) -> Vec<Candidate> {
    let weighted: Vec<Weighted> = band.iter().map(Candidate::weighted).collect();
    let (first, second) = rendezvous::pair(&weighted).unwrap_or((None, None));
    let find = |weighted: Option<Weighted>| {
        weighted.and_then(|weighted| band.iter().find(|each| each.relay.key == weighted.key))
    };
    let Some(first) = find(first) else {
        return Vec::new();
    };
    let paired = find(second);
    let second = match paired {
        Some(second) if first.known_distinct(second) => Some(second),
        _ => beyond
            .iter()
            .find(|each| first.known_distinct(each))
            .or(paired.filter(|second| first.may_differ(second)))
            .or_else(|| beside(&[first], band.iter().chain(beyond))),
    };
    std::iter::once(first).chain(second).cloned().collect()
}

fn keys_of(candidates: &[Candidate]) -> Vec<PublicKey> {
    let mut keys: Vec<PublicKey> = candidates.iter().map(|each| each.relay.key).collect();
    keys.sort_unstable_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
    keys
}

impl RelaySelection for BandRendezvous {
    fn choose(
        &mut self,
        area: Option<Region>,
        measured: &[Measured],
        avoid: &[PublicKey],
    ) -> Choice {
        let held_keys: Vec<PublicKey> = self
            .held
            .iter()
            .map(|held| held.candidate.relay.key)
            .collect();
        // A held relay is measured as able to take this feeder: it already holds its slot, however
        // full of other feeders it is.
        let usable: Vec<Measured> = measured
            .iter()
            .filter(|each| {
                !avoid.contains(&each.relay.key) && !self.failed.contains_key(&each.relay.key)
            })
            .map(|each| {
                let mut each = each.clone();
                if held_keys.contains(&each.relay.key) && each.weight() == 0 {
                    each.full = false;
                    each.reply.headroom.feeder_slots = 1;
                }
                each
            })
            .collect();
        let band = probe::band(&usable);
        let mut ranking = ranked(area, &band, &held_keys);
        // Beyond the band, the rest that can take a feeder, nearest first: a second network, and
        // failover, when the band has none.
        let mut beyond: Vec<&Measured> = usable
            .iter()
            .filter(|each| each.weight() > 0)
            .filter(|each| {
                !band
                    .iter()
                    .any(|in_band| in_band.relay.key == each.relay.key)
            })
            .collect();
        beyond.sort_by_key(|each| each.rtt);
        let band_len = ranking.len();
        ranking.extend(beyond.into_iter().map(Candidate::of));
        let target = target_of(&ranking[..band_len], &ranking[band_len..]);
        self.ranking = ranking;

        // Held relays: avoided ones go at once; one outside the band goes after three rounds, and
        // one whose probe failed after `FAILED_ROUNDS` in a row.
        let in_band = |key: &PublicKey| band.iter().any(|each| each.relay.key == *key);
        self.held
            .retain(|held| !avoid.contains(&held.candidate.relay.key));
        // A round that measured nothing at all says more of the feeder's own network than of any
        // relay: it counts against none.
        let heard_any = !measured.is_empty();
        for held in self.held.iter_mut().filter(|_| heard_any) {
            if measured
                .iter()
                .any(|each| each.relay.key == held.candidate.relay.key)
            {
                held.silent = 0;
            } else {
                held.silent += 1;
            }
            if in_band(&held.candidate.relay.key) {
                held.outside = 0;
                if let Some(now) = band
                    .iter()
                    .find(|each| each.relay.key == held.candidate.relay.key)
                {
                    held.candidate = Candidate::of(now);
                }
            } else {
                held.outside += 1;
            }
        }
        self.held
            .retain(|held| held.outside < HYSTERESIS_ROUNDS && held.silent < FAILED_ROUNDS);
        let choice = self.follow(target);
        // This round is over for the relays left out of it.
        self.failed.retain(|_, rounds| {
            *rounds = rounds.saturating_sub(1);
            *rounds > 0
        });
        choice
    }

    fn failed(&mut self, relay: &PublicKey) -> Choice {
        let Some(at) = self
            .held
            .iter()
            .position(|held| held.candidate.relay.key == *relay)
        else {
            return self.choice();
        };
        let before = self.held.len();
        let removed = self.held.remove(at);
        self.failed.insert(*relay, FAILED_ROUNDS);
        self.fill();
        if self.held.len() < before {
            // Nothing else can take its place: keep it, and keep ranking it.
            self.failed.remove(relay);
            self.held.insert(at, removed);
        } else {
            self.pending = None;
        }
        self.choice()
    }

    fn left(&mut self, relay: &PublicKey) -> Choice {
        self.held.retain(|held| held.candidate.relay.key != *relay);
        self.failed.insert(*relay, FAILED_ROUNDS);
        self.pending = None;
        self.fill();
        self.choice()
    }
}

impl BandRendezvous {
    /// Moves the held relays toward `target`: at once when nothing is held, otherwise only once
    /// the same target has held for `HYSTERESIS_ROUNDS` rounds; then fills any empty place.
    fn follow(&mut self, target: Vec<Candidate>) -> Choice {
        if self.held.is_empty() {
            // Nothing to keep: the ranking's pair, at once.
            self.held = target
                .into_iter()
                .map(|candidate| Held {
                    candidate,
                    outside: 0,
                    silent: 0,
                })
                .collect();
            self.pending = None;
            self.fill();
            return self.choice();
        }

        // The target completed with what is held, so a shorter target never drops a destination.
        let mut wanted = target;
        for held in &self.held {
            if wanted.len() < DESTINATIONS
                && !wanted
                    .iter()
                    .any(|each| each.relay.key == held.candidate.relay.key)
                && wanted.iter().all(|each| each.may_differ(&held.candidate))
            {
                wanted.push(held.candidate.clone());
            }
        }
        let wanted_keys = keys_of(&wanted);
        let held_now: Vec<Candidate> = self
            .held
            .iter()
            .map(|held| held.candidate.clone())
            .collect();
        if wanted_keys == keys_of(&held_now) || wanted.len() < self.held.len() {
            self.pending = None;
        } else {
            let rounds = match &self.pending {
                Some((keys, rounds)) if *keys == wanted_keys => rounds + 1,
                _ => 1,
            };
            if rounds >= HYSTERESIS_ROUNDS {
                let kept: Vec<Held> = std::mem::take(&mut self.held);
                self.held = wanted
                    .into_iter()
                    .map(|candidate| {
                        let kept = kept
                            .iter()
                            .find(|held| held.candidate.relay.key == candidate.relay.key);
                        Held {
                            candidate,
                            outside: kept.map_or(0, |held| held.outside),
                            silent: kept.map_or(0, |held| held.silent),
                        }
                    })
                    .collect();
                self.pending = None;
            } else {
                self.pending = Some((wanted_keys, rounds));
            }
        }
        self.fill();
        self.choice()
    }
}

/// How long a failover waits before its first dial: uniform below `FAILOVER_JITTER`.
pub fn failover_jitter() -> Duration {
    let mut bytes = [0; 8];
    let _ = getrandom::getrandom(&mut bytes);
    let millis = u64::try_from(FAILOVER_JITTER.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    Duration::from_millis(u64::from_be_bytes(bytes) % millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::tests::measured as relay_at;
    use tally_wire::{Identity, Location};

    fn key() -> Result<PublicKey, String> {
        Ok(Identity::generate()
            .map_err(|error| error.to_string())?
            .public())
    }

    fn area() -> Result<Region, String> {
        rendezvous::area_of(&Location {
            lat_e7: 339_400_000,
            lon_e7: -1_184_000_000,
            alt_m: 30,
            precision_m: 0,
        })
        .map_err(|error| error.to_string())
    }

    fn networks(choice: &Choice, measured: &[Measured]) -> Vec<u32> {
        choice
            .keys()
            .iter()
            .filter_map(|key| measured.iter().find(|each| each.relay.key == *key))
            .map(Measured::network)
            .collect()
    }

    #[test]
    fn two_relays_are_chosen_on_distinct_networks() -> Result<(), String> {
        let area = area()?;
        // Eight relays in the band, on two networks only, half of them on each.
        let measured: Vec<Measured> = (0..8)
            .map(|at| Ok(relay_at(key()?, 20 + at, 50, 100 + at as u32 % 2)))
            .collect::<Result<_, String>>()?;
        for _ in 0..20 {
            let mut selection = BandRendezvous::new();
            let choice = selection.choose(Some(area), &measured, &[]);
            let nets = networks(&choice, &measured);
            assert_eq!(nets.len(), 2, "{choice:?}");
            assert_ne!(nets[0], nets[1]);
        }
        // With one network in the band, the second comes from beyond it.
        let mut one_network: Vec<Measured> = (0..4)
            .map(|at| Ok(relay_at(key()?, 20 + at, 50, 7)))
            .collect::<Result<_, String>>()?;
        one_network.push(relay_at(key()?, 200, 50, 8));
        let choice = BandRendezvous::new().choose(Some(area), &one_network, &[]);
        assert_eq!(networks(&choice, &one_network), vec![7, 8]);
        Ok(())
    }

    #[test]
    fn an_areas_feeders_agree_on_the_pick_whatever_order_they_measured_in() -> Result<(), String> {
        let area = area()?;
        let measured: Vec<Measured> = (0..12)
            .map(|at| {
                Ok(relay_at(
                    key()?,
                    30 + at % 7,
                    20 + at as u32 * 5,
                    at as u32 + 1,
                ))
            })
            .collect::<Result<_, String>>()?;
        let first = BandRendezvous::new().choose(Some(area), &measured, &[]);
        assert!(first.second.is_some());
        for turn in 1..12 {
            let mut shuffled = measured.clone();
            shuffled.rotate_left(turn);
            if turn % 2 == 0 {
                shuffled.reverse();
            }
            // Each feeder measures slightly different times; the band is the same.
            for (at, each) in shuffled.iter_mut().enumerate() {
                if at % 3 == 0 {
                    each.rtt += Duration::from_millis(1);
                }
            }
            let choice = BandRendezvous::new().choose(Some(area), &shuffled, &[]);
            assert_eq!(choice, first, "feeder {turn} chose differently");
        }
        Ok(())
    }

    /// The choice's keys as a sorted set, to compare across rounds.
    fn set(choice: &Choice) -> Vec<PublicKey> {
        let mut keys = choice.keys();
        keys.sort_unstable_by(|one, other| one.as_bytes().cmp(other.as_bytes()));
        keys
    }

    #[test]
    fn a_newcomer_displaces_a_held_relay_only_after_three_rounds_in_a_row() -> Result<(), String> {
        let area = area()?;
        let mut measured: Vec<Measured> = (0..4)
            .map(|at| Ok(relay_at(key()?, 20, 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        let held = set(&selection.choose(Some(area), &measured, &[]));
        // A newcomer of overwhelming declared capacity, on its own network: it outranks.
        let newcomer = relay_at(key()?, 20, 1_000_000, 99);
        measured.push(newcomer.clone());
        let target = set(&BandRendezvous::new().choose(Some(area), &measured, &[]));
        assert!(
            target.contains(&newcomer.relay.key),
            "the newcomer never outranks"
        );
        assert_eq!(set(&selection.choose(Some(area), &measured, &[])), held);
        assert_eq!(set(&selection.choose(Some(area), &measured, &[])), held);
        // A round without it breaks the run: three more are needed.
        let without: Vec<Measured> = measured[..4].to_vec();
        assert_eq!(set(&selection.choose(Some(area), &without, &[])), held);
        assert_eq!(set(&selection.choose(Some(area), &measured, &[])), held);
        assert_eq!(set(&selection.choose(Some(area), &measured, &[])), held);
        assert_eq!(set(&selection.choose(Some(area), &measured, &[])), target);
        Ok(())
    }

    #[test]
    fn a_held_relay_leaves_the_band_only_after_three_rounds_outside() -> Result<(), String> {
        let measured: Vec<Measured> = (0..4)
            .map(|at| Ok(relay_at(key()?, 20 + u64::from(at), 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        // No area: nearest first, so the held pair is the two nearest.
        let held = selection.choose(None, &measured, &[]);
        let first = held.first.clone().ok_or("no first")?;
        // The first slows far outside the band.
        let mut slowed = measured.clone();
        for each in &mut slowed {
            if each.relay.key == first.key {
                each.rtt = Duration::from_millis(400);
            }
        }
        assert!(
            selection
                .choose(None, &slowed, &[])
                .keys()
                .contains(&first.key)
        );
        assert!(
            selection
                .choose(None, &slowed, &[])
                .keys()
                .contains(&first.key)
        );
        // Back inside for a round: the count starts again.
        assert!(
            selection
                .choose(None, &measured, &[])
                .keys()
                .contains(&first.key)
        );
        assert!(
            selection
                .choose(None, &slowed, &[])
                .keys()
                .contains(&first.key)
        );
        assert!(
            selection
                .choose(None, &slowed, &[])
                .keys()
                .contains(&first.key)
        );
        let after = selection.choose(None, &slowed, &[]);
        assert!(!after.keys().contains(&first.key), "{after:?}");
        assert_eq!(after.keys().len(), 2);
        Ok(())
    }

    #[test]
    fn a_relay_that_takes_its_last_slot_for_this_feeder_is_kept() -> Result<(), String> {
        let mut measured: Vec<Measured> = (0..3)
            .map(|at| Ok(relay_at(key()?, 20, 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        let held = set(&selection.choose(None, &measured, &[]));
        for each in &mut measured {
            if held.contains(&each.relay.key) {
                each.reply.headroom.feeder_slots = 0;
            }
        }
        for _ in 0..5 {
            assert_eq!(set(&selection.choose(None, &measured, &[])), held);
        }
        Ok(())
    }

    #[test]
    fn a_held_relay_full_of_other_feeders_is_kept() -> Result<(), String> {
        // Its probe takes no slot (`Role::Probe`) and finds it full of other feeders: no spare
        // slot declared, or turned away as full. This feeder's session there is unaffected.
        let mut measured: Vec<Measured> = (0..3)
            .map(|at| Ok(relay_at(key()?, 20, 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        let held = set(&selection.choose(None, &measured, &[]));
        for each in &mut measured {
            if held.contains(&each.relay.key) {
                each.full = true;
                each.reply.headroom.feeder_slots = 0;
            }
        }
        for round in 0..5 {
            assert_eq!(
                set(&selection.choose(None, &measured, &[])),
                held,
                "round {round}"
            );
        }
        // A full relay it does not hold is still never chosen.
        let fresh = BandRendezvous::new().choose(None, &measured, &[]);
        assert!(fresh.keys().iter().all(|key| !held.contains(key)));
        Ok(())
    }

    #[test]
    fn a_failed_relay_is_left_out_of_exactly_failed_rounds_rounds() -> Result<(), String> {
        let measured: Vec<Measured> = (0..5)
            .map(|at| Ok(relay_at(key()?, 20, 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        let choice = selection.choose(None, &measured, &[]);
        let failed = choice.first.clone().ok_or("no first")?;
        selection.failed(&failed.key);
        let ranked = |selection: &BandRendezvous| {
            selection
                .ranking
                .iter()
                .any(|candidate| candidate.relay.key == failed.key)
        };
        for round in 1..=FAILED_ROUNDS {
            selection.choose(None, &measured, &[]);
            assert!(!ranked(&selection), "ranked again in round {round}");
        }
        selection.choose(None, &measured, &[]);
        assert!(
            ranked(&selection),
            "still left out after {FAILED_ROUNDS} rounds"
        );
        Ok(())
    }

    #[test]
    fn a_held_relay_whose_probe_fails_is_dropped_after_failed_rounds() -> Result<(), String> {
        let measured: Vec<Measured> = (0..4)
            .map(|at| Ok(relay_at(key()?, 20 + u64::from(at), 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        let held = selection.choose(None, &measured, &[]);
        let dead = held.first.clone().ok_or("no first")?;
        // Its probe fails from now on, whatever its offer still says.
        let without: Vec<Measured> = measured
            .iter()
            .filter(|each| each.relay.key != dead.key)
            .cloned()
            .collect();
        for round in 1..FAILED_ROUNDS {
            let choice = selection.choose(None, &without, &[]);
            assert!(
                choice.keys().contains(&dead.key),
                "dropped in round {round}"
            );
        }
        let after = selection.choose(None, &without, &[]);
        assert!(!after.keys().contains(&dead.key), "{after:?}");
        assert_eq!(after.keys().len(), 2);
        // A probe that answers again in between starts the count over.
        let mut selection = BandRendezvous::new();
        let held = selection.choose(None, &measured, &[]);
        let flaky = held.first.clone().ok_or("no first")?;
        let without: Vec<Measured> = measured
            .iter()
            .filter(|each| each.relay.key != flaky.key)
            .cloned()
            .collect();
        for _ in 0..3 {
            assert!(
                selection
                    .choose(None, &without, &[])
                    .keys()
                    .contains(&flaky.key)
            );
            assert!(
                selection
                    .choose(None, &measured, &[])
                    .keys()
                    .contains(&flaky.key)
            );
        }
        // A round that measured nothing at all is the feeder's network, not the relays'.
        for _ in 0..3 {
            assert_eq!(selection.choose(None, &[], &[]).keys().len(), 2);
        }
        Ok(())
    }

    #[test]
    fn a_full_relay_is_never_chosen_and_one_that_redirects_is_replaced_by_the_next()
    -> Result<(), String> {
        let area = area()?;
        let mut measured: Vec<Measured> = (0..6)
            .map(|at| Ok(relay_at(key()?, 20, 50, at + 1)))
            .collect::<Result<_, String>>()?;
        // Full: turned the probe away whatever it declared.
        measured[0].full = true;
        let mut selection = BandRendezvous::new();
        let choice = selection.choose(Some(area), &measured, &[]);
        assert!(!choice.keys().contains(&measured[0].relay.key));
        // One chosen redirects: the next in the ranking takes its place at once, on a network
        // distinct from the one kept.
        let left = choice.first.clone().ok_or("no first")?;
        let kept = choice.second.clone().ok_or("no second")?;
        let after = selection.failed(&left.key);
        assert_eq!(after.keys().len(), 2);
        assert!(after.keys().contains(&kept.key));
        assert!(!after.keys().contains(&left.key));
        // It stays out of the next rounds, then is a candidate again.
        let next = selection.choose(Some(area), &measured, &[]);
        assert!(!next.keys().contains(&left.key));
        Ok(())
    }

    #[test]
    fn a_failed_relay_with_no_other_to_take_its_place_is_kept_to_retry() -> Result<(), String> {
        let only = vec![relay_at(key()?, 20, 50, 1)];
        let mut selection = BandRendezvous::new();
        let choice = selection.choose(None, &only, &[]);
        let relay = choice.first.clone().ok_or("no first")?;
        assert_eq!(selection.failed(&relay.key), choice);
        // Found swallowing, it is left even so.
        assert_eq!(selection.left(&relay.key), Choice::default());
        Ok(())
    }

    #[test]
    fn a_swallower_is_left_out_at_once() -> Result<(), String> {
        let area = area()?;
        let measured: Vec<Measured> = (0..5)
            .map(|at| Ok(relay_at(key()?, 20, 50, at + 1)))
            .collect::<Result<_, String>>()?;
        let mut selection = BandRendezvous::new();
        let choice = selection.choose(Some(area), &measured, &[]);
        let swallower = choice.first.clone().ok_or("no first")?;
        let after = selection.choose(Some(area), &measured, &[swallower.key]);
        assert!(!after.keys().contains(&swallower.key));
        assert_eq!(after.keys().len(), 2);
        Ok(())
    }

    #[test]
    fn failover_is_jittered_within_its_bound() {
        let delays: Vec<Duration> = (0..64).map(|_| failover_jitter()).collect();
        assert!(delays.iter().all(|delay| *delay < FAILOVER_JITTER));
        let spread = delays.iter().max().copied().unwrap_or_default()
            - delays.iter().min().copied().unwrap_or_default();
        assert!(spread > FAILOVER_JITTER / 4, "{delays:?}");
    }

    #[test]
    fn relays_in_one_prefix_are_one_network_whatever_they_declare() -> Result<(), String> {
        let at = |text: &str| text.parse().ok();
        let mut one = relay_at(key()?, 20, 50, 0);
        let mut other = relay_at(key()?, 21, 50, 0);
        one.observed = at("192.0.2.1");
        other.observed = at("192.0.2.77");
        let mut elsewhere = relay_at(key()?, 22, 50, 0);
        elsewhere.observed = at("198.51.100.1");
        let choice = BandRendezvous::new().choose(
            None,
            &[one.clone(), other.clone(), elsewhere.clone()],
            &[],
        );
        assert_eq!(
            choice.second.map(|relay| relay.key),
            Some(elsewhere.relay.key)
        );
        // Declaring two networks from one /24 does not make two networks.
        one.reply.network = 1;
        other.reply.network = 2;
        elsewhere.reply.network = 3;
        let choice = BandRendezvous::new().choose(None, &[one, other, elsewhere.clone()], &[]);
        assert!(choice.keys().contains(&elsewhere.relay.key), "{choice:?}");
        Ok(())
    }
}
