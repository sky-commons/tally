//! The merge rules over what real engines publish: the simulator's receivers, two engines whose
//! regions overlap (so the aircraft they share are solved from different receivers, under
//! different models), and records re-signed or cut down where a rule needs a case engines do not
//! produce on their own.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::*;
use tally_mlat::engine::{Engine, Settings as EngineSettings};
use tally_mlat_solver::SPEC_VERSION;
use tally_mlat_solver::scope::{GRID_MS, Window};
use tally_mlat_solver::sim::{self, Scenario};
use tally_wire::{Identity, SolutionsContent};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// What the receivers published, and what two engines with overlapping regions published from it.
struct World {
    raw: Vec<Record>,
    west: Vec<Record>,
    east: Vec<Record>,
    /// What an engine holding all of the raw published.
    full: Vec<Record>,
    west_key: Identity,
    east_key: Identity,
    now: u64,
}

const SETTLE_MS: u64 = 1_000;

fn build() -> Result<World, String> {
    let simulation = sim::run(&Scenario {
        duration_s: 30.0,
        modes_aircraft: 16,
        ..Scenario::new(31)
    });
    let feeds = simulation.feeds().map_err(text)?;
    let mut raw: Vec<Record> = feeds
        .iter()
        .map(|feed| Record::ReceiverInfo(feed.info.clone()))
        .collect();
    raw.extend(
        feeds
            .iter()
            .flat_map(|feed| feed.batches.iter().cloned().map(Record::Batch)),
    );
    let last = simulation
        .receptions
        .iter()
        .map(|reception| bin_of(reception.wall_ms))
        .max()
        .unwrap_or(0);
    let now = (Window::canonical(last).last + 1) as u64 * GRID_MS + SETTLE_MS;
    let west_key = Identity::from_seed([41; 32]);
    // Two whole-world engines that hold different raw: the west the batches of the first seven
    // receivers, the east of the last seven (every description reaches both). Their tiles'
    // members differ where their raw does, so the aircraft they share are solved under models of
    // different inputs, from different receptions.
    let run =
        |identity: Identity, receivers: std::ops::Range<usize>| -> Result<Vec<Record>, String> {
            let keys: BTreeSet<tally_wire::PublicKey> = simulation.receivers[receivers]
                .iter()
                .map(|receiver| receiver.key)
                .collect();
            let mut engine = Engine::new(
                identity,
                0xb007,
                EngineSettings {
                    regions: tally_wire::Regions::default(),
                    settle_ms: SETTLE_MS,
                    threads: 4,
                    capacity: Default::default(),
                },
            );
            for record in &raw {
                let wanted = match record {
                    Record::Batch(batch) => batch.receiver().is_ok_and(|key| keys.contains(&key)),
                    _ => true,
                };
                if wanted {
                    engine.ingest(record, tally_mlat::replay::sent_ms(record))?;
                }
            }
            Ok(engine.step(now, now).0)
        };
    let west = run(west_key.clone(), 0..7)?;
    let east_key = Identity::from_seed([42; 32]);
    let east = run(east_key.clone(), 3..10)?;
    let full = run(Identity::from_seed([45; 32]), 0..simulation.receivers.len())?;
    Ok(World {
        raw,
        west,
        east,
        full,
        west_key,
        east_key,
        now,
    })
}

fn world() -> Result<&'static World, String> {
    static WORLD: OnceLock<Result<World, String>> = OnceLock::new();
    WORLD.get_or_init(build).as_ref().map_err(Clone::clone)
}

fn feed(merge: &mut Merge, records: &[Record], now: u64) -> Result<(), String> {
    for record in records {
        merge.ingest(record, now)?;
    }
    Ok(())
}

/// Every transmission held as (address, current input set, check, alternatives' input sets).
type Summary = Vec<(u32, Hash, Check, Vec<Hash>)>;

fn summary(merge: &Merge) -> Summary {
    merge
        .tracks()
        .into_iter()
        .flat_map(|track| &track.transmissions)
        .map(|transmission| {
            let current = transmission.current();
            (
                current.address,
                current.input_set,
                current.check,
                transmission
                    .alternatives()
                    .iter()
                    .map(|alternative| alternative.input_set)
                    .collect(),
            )
        })
        .collect()
}

/// Every transmission held.
fn transmissions(merge: &Merge) -> Vec<&Transmission> {
    merge
        .tracks()
        .into_iter()
        .flat_map(|track| &track.transmissions)
        .collect()
}

/// Every fix held.
fn fixes(merge: &Merge) -> Vec<&Fix> {
    transmissions(merge)
        .into_iter()
        .flat_map(|transmission| &transmission.fixes)
        .collect()
}

/// `records` as another engine would have published the same content: every model re-signed by
/// `identity`, and every solution citing its new id.
fn resign(records: &[Record], identity: &Identity) -> Result<Vec<Record>, String> {
    let mut ids: BTreeMap<Hash, Hash> = BTreeMap::new();
    let mut out = Vec::new();
    for record in records {
        match record {
            Record::ClockModel(manifest) => {
                let content = manifest.content(&[]).map_err(text)?;
                let signed = ClockModel::sign(identity, &content).map_err(text)?;
                ids.insert(manifest.id(), signed.manifest.id());
                out.extend(signed.records());
            }
            Record::Positions(positions) => {
                let mut content = positions.solutions().map_err(text)?;
                for solution in &mut content.solutions {
                    solution.clock_model = *ids.get(&solution.clock_model).ok_or("uncited")?;
                }
                let signed = Positions::sign_solutions(identity, &content).map_err(text)?;
                out.push(Record::Positions(signed));
            }
            _ => {}
        }
    }
    Ok(out)
}

fn solutions(records: &[Record]) -> Result<Vec<tally_wire::Solution>, String> {
    let mut out = Vec::new();
    for record in records {
        if let Record::Positions(positions) = record {
            out.extend(positions.solutions().map_err(text)?.solutions);
        }
    }
    Ok(out)
}

fn models(records: &[Record]) -> Vec<Record> {
    records
        .iter()
        .filter(|record| matches!(record, Record::ClockModel(_) | Record::ClockModelPart(_)))
        .cloned()
        .collect()
}

#[test]
fn the_same_input_set_is_a_duplicate_whoever_signed_it_and_whatever_the_order() -> Result<(), String>
{
    let world = world()?;
    let mut once = Merge::new(Settings::new(false));
    feed(&mut once, &world.west, world.now)?;
    assert!(once.tracks().len() >= 5, "{} tracks", once.tracks().len());
    // Twice (two relays), backwards (positions before their models), and re-signed by a second
    // engine holding the same raw: the same tracks, with both engines behind every fix.
    let mut many = Merge::new(Settings::new(false));
    let mut backwards = world.west.clone();
    backwards.reverse();
    feed(&mut many, &backwards, world.now)?;
    feed(&mut many, &world.west, world.now)?;
    let other = Identity::from_seed([43; 32]);
    let resigned = resign(&world.west, &other)?;
    for record in &resigned {
        let ingested = many.ingest(record, world.now)?;
        if let Ingested::Solutions { accepted, .. } = ingested {
            assert_eq!(accepted, 0, "a duplicate changed a track");
        }
    }
    assert_eq!(summary(&once), summary(&many));
    for fix in fixes(&many) {
        assert!(fix.engines.contains(&other.public()));
        assert!(fix.engines.contains(&world.west_key.public()));
        assert_eq!(fix.check, Check::Signature);
        assert!(fix.horizontal_sigma_m > 0.0);
    }
    Ok(())
}

#[test]
fn a_superset_of_the_same_models_inputs_wins_in_either_order() -> Result<(), String> {
    let world = world()?;
    let all = solutions(&world.west)?;
    // The most recent transmission of the aircraft with the most receptions.
    let full = all
        .iter()
        .filter(|solution| solution.observations.receptions().len() >= 5)
        .max_by_key(|solution| (solution.transmitted, solution.address))
        .ok_or("no solution of five receptions")?
        .clone();
    let mut cut = full.clone();
    let receptions = full.observations.receptions();
    cut.observations = ObservationSet::new(
        full.observations.message().to_vec(),
        receptions[..receptions.len() - 1].to_vec(),
    )
    .map_err(text)?;
    let sign = |solution: &tally_wire::Solution, sequence: u64| -> Result<Record, String> {
        Positions::sign_solutions(
            &world.west_key,
            &SolutionsContent {
                boot_id: 0xb007,
                sequence: 1_000 + sequence,
                issued_ms: world.now,
                spec_version: SPEC_VERSION,
                solutions: vec![solution.clone()],
            },
        )
        .map(Record::Positions)
        .map_err(text)
    };
    let (full_record, cut_record) = (sign(&full, 0)?, sign(&cut, 1)?);
    for order in [[&cut_record, &full_record], [&full_record, &cut_record]] {
        let mut merge = Merge::new(Settings::new(false));
        feed(&mut merge, &models(&world.west), world.now)?;
        for record in order {
            merge.ingest(record, world.now)?;
        }
        let track = merge.track(full.address).ok_or("no track")?;
        let transmission = track.latest().ok_or("no final transmission")?;
        assert_eq!(transmission.current().observations, full.observations);
        assert!(
            transmission.alternatives().is_empty(),
            "a subset is not an alternative"
        );
    }
    Ok(())
}

#[test]
fn incomparable_sets_without_raw_keep_the_first_by_the_tie_rule_and_record_the_other()
-> Result<(), String> {
    let world = world()?;
    let mut first = Merge::new(Settings::new(false));
    feed(&mut first, &world.west, world.now)?;
    feed(&mut first, &world.east, world.now)?;
    let mut second = Merge::new(Settings::new(false));
    feed(&mut second, &world.east, world.now)?;
    feed(&mut second, &world.west, world.now)?;
    // What is served, every aircraft's current fix, is the same in either order.
    let current = |merge: &Merge| -> Vec<(u32, Hash)> {
        merge
            .tracks()
            .iter()
            .filter_map(|track| track.current().map(|fix| (fix.address, fix.input_set)))
            .collect()
    };
    assert_eq!(current(&first), current(&second), "the order decided");
    let contested: Vec<&Transmission> = transmissions(&first)
        .into_iter()
        .filter(|transmission| !transmission.alternatives().is_empty())
        .collect();
    assert!(!contested.is_empty(), "no transmission both engines solved");
    for transmission in contested {
        let current = transmission.current();
        assert_eq!(current.check, Check::Signature);
        for alternative in transmission.alternatives() {
            assert_eq!(
                current.observations.message(),
                alternative.observations.message()
            );
            assert!(
                current.rank() < alternative.rank(),
                "{} {:?} against {} {:?}",
                current.weight,
                current.input_set,
                alternative.weight,
                alternative.input_set
            );
        }
    }
    Ok(())
}

#[test]
fn the_tie_rule_is_weight_then_the_lowest_input_set_hash() -> Result<(), String> {
    let world = world()?;
    let solution = solutions(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let fix = |weight: u64, hash: u8| Fix {
        kind: Kind::Final,
        address: solution.address,
        transmitted: solution.transmitted,
        lat_e7: 0,
        lon_e7: 0,
        alt_hae_mm: None,
        altitude_ft: None,
        horizontal_sigma_m: 1.0,
        covariance: solution.covariance,
        observations: solution.observations.clone(),
        model: [hash; 32],
        model_inputs: [hash; 32],
        input_set: [hash; 32],
        weight,
        check: Check::Signature,
        engines: BTreeSet::new(),
        standing: 0,
        confidence: Confidence::Unconfirmed,
        consistent: true,
    };
    let mut fixes = [fix(10, 1), fix(12, 9), fix(12, 3), fix(11, 0)];
    fixes.sort_by(order);
    let ranked: Vec<(u64, u8)> = fixes
        .iter()
        .map(|fix| (fix.weight, fix.input_set[0]))
        .collect();
    assert_eq!(ranked, vec![(12, 3), (12, 9), (11, 0), (10, 1)]);
    let mut resolved = fix(1, 200);
    resolved.check = Check::Resolved;
    assert_eq!(order(&resolved, &fix(12, 3)), std::cmp::Ordering::Less);
    Ok(())
}

/// A client holding all the raw: the models of an engine that held the same raw are verified by
/// the model verifier and their solutions by the solution verifier and the assignment check; the
/// models of engines that held only part of it are not the client's to verify (their members
/// and citations differ from what its raw gives), so they count on their signatures alone; and
/// where two of those are incomparable, the client solves the transmission itself.
#[test]
fn holding_the_raw_verifies_every_model_and_solves_the_union_of_incomparable_sets()
-> Result<(), String> {
    let world = world()?;
    let mut alone = Merge::new(Settings::new(true));
    feed(&mut alone, &world.raw, world.now)?;
    assert!(alone.held() > 0);
    feed(&mut alone, &world.full, world.now)?;
    assert!(!alone.tracks().is_empty());
    for fix in fixes(&alone) {
        assert_eq!(fix.check, Check::Model, "{:06x}", fix.address);
    }
    let mut merge = Merge::new(Settings::new(true));
    feed(&mut merge, &world.raw, world.now)?;
    feed(&mut merge, &world.west, world.now)?;
    feed(&mut merge, &world.east, world.now)?;
    assert!(!merge.tracks().is_empty());
    let resolved: Vec<&Transmission> = transmissions(&merge)
        .into_iter()
        .filter(|transmission| transmission.current().check == Check::Resolved)
        .collect();
    assert!(!resolved.is_empty(), "{:?}", summary(&merge));
    for transmission in resolved {
        let current = transmission.current();
        assert!(current.engines.is_empty());
        for alternative in transmission.alternatives() {
            assert_eq!(
                current.observations.message(),
                alternative.observations.message()
            );
            // The union holds at least as many observations as either side.
            assert!(
                current.observations.receptions().len()
                    >= alternative.observations.receptions().len(),
                "{:06x}",
                current.address
            );
        }
    }
    Ok(())
}

#[test]
fn a_fault_proof_convicts_its_engine_and_drops_what_stood_on_its_word_alone() -> Result<(), String>
{
    let world = world()?;
    let witness = Identity::from_seed([44; 32]);
    let mut merge = Merge::new(Settings::new(false));
    feed(&mut merge, &world.west, world.now)?;
    feed(&mut merge, &world.east, world.now)?;
    // Some of the west engine's fixes (its even addresses') are also signed by a witness.
    let mut witnessed = Vec::new();
    for record in resign(&world.west, &witness)? {
        match record {
            Record::Positions(positions) => {
                let mut content = positions.solutions().map_err(text)?;
                content
                    .solutions
                    .retain(|solution| solution.address % 2 == 0);
                if !content.solutions.is_empty() {
                    witnessed.push(Record::Positions(
                        Positions::sign_solutions(&witness, &content).map_err(text)?,
                    ));
                }
            }
            record => witnessed.push(record),
        }
    }
    feed(&mut merge, &witnessed, world.now)?;
    let west = world.west_key.public();
    assert!(fixes(&merge).iter().any(|fix| fix.engines == [west].into()));
    // Two solutions of one observation set under one model, both signed by the west engine,
    // that disagree by far more than the specification allows. (Two different models of one
    // inputs are no fault from specification version 3: optimality, not bytes, is the rule.)
    let honest = solutions(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let mut moved = honest.clone();
    moved.lat_e7 += 10_000;
    let first = match signed(&world.west_key, 50, honest)? {
        Record::Positions(positions) => positions,
        _ => return Err("not positions".to_owned()),
    };
    let second = match signed(&world.west_key, 51, moved)? {
        Record::Positions(positions) => positions,
        _ => return Err("not positions".to_owned()),
    };
    let proof = FaultProof::new(&first, 0, &second, 0).map_err(text)?;
    assert_eq!(
        merge.ingest(&Record::FaultProof(proof), world.now)?,
        Ingested::Fault
    );
    assert!(merge.is_faulted(&west));
    for fix in fixes(&merge) {
        assert!(!fix.engines.contains(&west), "{:06x}", fix.address);
        assert!(!fix.engines.is_empty());
    }
    assert!(
        fixes(&merge)
            .iter()
            .any(|fix| fix.engines.contains(&witness.public()))
    );
    // Nothing the convicted engine signs counts any more.
    let left = summary(&merge);
    feed(&mut merge, &world.west, world.now)?;
    assert_eq!(summary(&merge), left);
    Ok(())
}

#[test]
fn every_table_is_bounded() -> Result<(), String> {
    let world = world()?;
    let settings = Settings {
        max_aircraft: 3,
        max_models: 4,
        max_pending: 2,
        max_held: 1_000,
        max_resolved: 1,
        ..Settings::new(true)
    };
    let mut merge = Merge::new(settings);
    let mut backwards = world.west.clone();
    backwards.reverse();
    feed(&mut merge, &world.raw, world.now)?;
    feed(&mut merge, &backwards, world.now)?;
    feed(&mut merge, &world.east, world.now)?;
    assert!(merge.tracks().len() <= 3);
    assert!(merge.models() <= 4);
    assert!(merge.held() <= 1_000);
    assert!(merge.pending.len() <= 2);
    assert!(merge.resolved.len() <= 1);
    // Raw is forgotten by bin as the clock moves on.
    merge.ingest(&world.raw[world.raw.len() - 1], world.now + 3_600_000)?;
    assert!(merge.held() <= 1);
    Ok(())
}

/// The decoded model `records` publish under `id`.
fn decoded(records: &[Record], id: &Hash) -> Result<tally_mlat_solver::ClockModel, String> {
    for record in records {
        if let Record::ClockModel(manifest) = record
            && manifest.id() == *id
        {
            let content = manifest.content(&[]).map_err(text)?;
            return publish::decode(&content.model, content.spec_version).map_err(text);
        }
    }
    Err("no such model".to_owned())
}

fn signed(
    identity: &Identity,
    sequence: u64,
    solution: tally_wire::Solution,
) -> Result<Record, String> {
    Positions::sign_solutions(
        identity,
        &SolutionsContent {
            boot_id: 0xb007,
            sequence: 2_000 + sequence,
            issued_ms: 0,
            spec_version: SPEC_VERSION,
            solutions: vec![solution],
        },
    )
    .map(Record::Positions)
    .map_err(text)
}

/// One DF11 transmission both engines solved (they share a reception), and the east engine's
/// receptions of it from receivers the west engine's solution does not cite.
struct Shared {
    west: tally_wire::Solution,
    east: tally_wire::Solution,
    others: Vec<tally_wire::Reception>,
}

fn is_df11(solution: &tally_wire::Solution) -> bool {
    solution.observations.message()[0] >> 3 == 11
}

fn shared(world: &World) -> Result<Shared, String> {
    let east_all = solutions(&world.east)?;
    for west in solutions(&world.west)?.into_iter().filter(is_df11) {
        let cited: BTreeSet<PublicKey> = west
            .observations
            .receptions()
            .iter()
            .map(|reception| reception.receiver)
            .collect();
        for east in &east_all {
            if east.address != west.address
                || east.observations.message() != west.observations.message()
                || east
                    .observations
                    .receptions()
                    .iter()
                    .all(|reception| !west.observations.receptions().contains(reception))
            {
                continue;
            }
            let others: Vec<tally_wire::Reception> = east
                .observations
                .receptions()
                .iter()
                .filter(|reception| !cited.contains(&reception.receiver))
                .copied()
                .collect();
            if !others.is_empty() {
                return Ok(Shared {
                    west,
                    east: east.clone(),
                    others,
                });
            }
        }
    }
    Err("no DF11 transmission both engines solved with receivers to spare".to_owned())
}

/// The transmission of a fix in `merge` whose observations are `set`.
fn holding(merge: &Merge, address: u32, set: &ObservationSet) -> Option<usize> {
    merge
        .track(address)?
        .transmissions
        .iter()
        .position(|transmission| {
            transmission
                .fixes
                .iter()
                .any(|fix| fix.observations == *set)
        })
}

/// A Mode S reply repeats its bytes exactly, milliseconds apart, to another interrogator. One
/// engine's DF11 solution cut in two by receivers: the second half moved 50 ms later (counters
/// and transmit time) is a second transmission with the same bytes, no reception in common and
/// a transmit time well within what a rule by times would join, and is never joined; unmoved it
/// is the same transmission, tied through the model, and joined.
#[test]
fn identical_df11_replies_50_ms_apart_are_never_joined_and_a_tie_joins_the_same_one()
-> Result<(), String> {
    let world = world()?;
    let whole = solutions(&world.west)?
        .into_iter()
        .filter(is_df11)
        .find(|solution| {
            let model = decoded(&world.west, &solution.clock_model);
            solution.observations.receptions().len() >= 4
                && model.is_ok_and(|model| {
                    solution.observations.receptions().iter().all(|reception| {
                        model.scope.iter().any(|site| {
                            site.receiver == reception.receiver
                                && tally_mlat_solver::Timebase::of(site.clock)
                                    == Some(tally_mlat_solver::Timebase::Mhz12)
                        })
                    })
                })
        })
        .ok_or("no DF11 solution of four 12 MHz receptions")?;
    let receptions = whole.observations.receptions();
    let half = receptions.len() / 2;
    let message = whole.observations.message().to_vec();
    let mut first = whole.clone();
    first.observations =
        ObservationSet::new(message.clone(), receptions[..half].to_vec()).map_err(text)?;
    for (shift_ms, joined) in [(50u64, false), (0, true)] {
        let mut later = whole.clone();
        later.transmitted = TransmitTime::new(
            later.transmitted.unix_ms + shift_ms,
            later.transmitted.sub_ms_ps,
        )
        .map_err(text)?;
        let moved = receptions[half..]
            .iter()
            .map(|reception| tally_wire::Reception {
                // 12 MHz: 12 000 counts a millisecond.
                counter: reception.counter + shift_ms * 12_000,
                ..*reception
            })
            .collect();
        later.observations = ObservationSet::new(message.clone(), moved).map_err(text)?;
        let mut merge = Merge::new(Settings::new(false));
        feed(&mut merge, &models(&world.west), world.now)?;
        merge.ingest(&signed(&world.west_key, 0, first.clone())?, world.now)?;
        merge.ingest(&signed(&world.west_key, 1, later.clone())?, world.now)?;
        let a = holding(&merge, whole.address, &first.observations);
        let b = holding(&merge, whole.address, &later.observations);
        assert!(a.is_some() && b.is_some(), "{a:?} {b:?}");
        assert_eq!(a == b, joined, "shifted {shift_ms} ms");
    }
    Ok(())
}

/// Two engines whose gauges' time origins are far apart (the west's GNSS, the east's a receiver's
/// wall clock) solve one transmission; with every shared reception taken out of the east's, they
/// are still matched, through the tie the west's receptions make in the east's model. The same
/// receptions moved 50 ms later are not.
#[test]
fn gauges_far_apart_are_matched_by_a_tie_with_no_reception_in_common() -> Result<(), String> {
    let world = world()?;
    let shared = shared(world)?;
    let gap_ms = shared
        .west
        .transmitted
        .unix_ps()
        .abs_diff(shared.east.transmitted.unix_ps())
        / 1_000_000_000;
    // Far beyond the tie's microseconds, and beyond what any rule by transmit times could
    // accept as one transmission (the replies of the other test are 50 ms apart).
    assert!(gap_ms >= 50, "the origins are only {gap_ms} ms apart");
    for (shift_ms, joined) in [(0u64, true), (50, false)] {
        let mut east = shared.east.clone();
        east.transmitted = TransmitTime::new(
            east.transmitted.unix_ms + shift_ms,
            east.transmitted.sub_ms_ps,
        )
        .map_err(text)?;
        let moved = shared
            .others
            .iter()
            .map(|reception| tally_wire::Reception {
                counter: reception.counter + shift_ms * 12_000,
                ..*reception
            })
            .collect();
        east.observations =
            ObservationSet::new(east.observations.message().to_vec(), moved).map_err(text)?;
        let mut merge = Merge::new(Settings::new(false));
        feed(&mut merge, &models(&world.west), world.now)?;
        feed(&mut merge, &models(&world.east), world.now)?;
        merge.ingest(&signed(&world.west_key, 0, shared.west.clone())?, world.now)?;
        merge.ingest(&signed(&world.east_key, 0, east.clone())?, world.now)?;
        let a = holding(&merge, shared.west.address, &shared.west.observations);
        let b = holding(&merge, shared.west.address, &east.observations);
        assert!(a.is_some() && b.is_some(), "{a:?} {b:?}");
        assert_eq!(
            a == b,
            joined,
            "shifted {shift_ms} ms, origins {gap_ms} ms apart"
        );
    }
    Ok(())
}

/// `solution` as a provisional record by `identity`: no addressed citation, as a provisional
/// names none.
fn early(
    identity: &Identity,
    sequence: u64,
    mut solution: tally_wire::Solution,
) -> Result<Record, String> {
    solution.addressed = tally_wire::AddressedCitation::default();
    Positions::sign_provisional(
        identity,
        &SolutionsContent {
            boot_id: 0xb007,
            sequence,
            issued_ms: 0,
            spec_version: SPEC_VERSION,
            solutions: vec![solution],
        },
    )
    .map(Record::Provisional)
    .map_err(text)
}

#[test]
fn a_provisional_fix_is_served_while_it_is_later_and_superseded_by_a_final_of_its_transmission()
-> Result<(), String> {
    let world = world()?;
    let final_one = solutions(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let address = final_one.address;
    let mut merge = Merge::new(Settings::new(false));
    feed(&mut merge, &models(&world.west), world.now)?;
    // The same transmission, solved a second after it was heard: held and served.
    let ingested = merge.ingest(&early(&world.west_key, 0, final_one.clone())?, world.now)?;
    assert_eq!(
        ingested,
        Ingested::Provisional {
            accepted: 1,
            dropped: 0
        }
    );
    let served = merge
        .track(address)
        .and_then(Track::served)
        .ok_or("nothing served")?;
    assert_eq!(served.kind, Kind::Provisional);
    assert_eq!(served.check, Check::Signature);
    // The final one of the same transmission arrives: it supersedes the provisional, which is
    // served no more.
    merge.ingest(&signed(&world.west_key, 0, final_one.clone())?, world.now)?;
    let track = merge.track(address).ok_or("no track")?;
    assert!(track.provisional.is_empty());
    assert_eq!(track.served().map(|fix| fix.kind), Some(Kind::Final));
    assert_eq!(merge.provisional_counts().superseded, 1);
    // A provisional arriving after the final of its transmission is not held.
    let late = merge.ingest(&early(&world.west_key, 1, final_one)?, world.now)?;
    assert_eq!(
        late,
        Ingested::Provisional {
            accepted: 0,
            dropped: 1
        }
    );
    assert_eq!(merge.provisional_counts().late, 1);
    Ok(())
}

#[test]
fn a_later_provisional_is_served_over_a_final_and_an_unconfirmed_one_is_retracted_at_its_deadline()
-> Result<(), String> {
    let world = world()?;
    let all = solutions(&world.west)?;
    let final_one = all.first().ok_or("no solution")?.clone();
    let address = final_one.address;
    // Another transmission of the same aircraft, its time moved half a minute on and its position
    // far off: no final one supersedes or confirms it.
    let mut stray = all
        .iter()
        .find(|other| other.address == address && other.observations != final_one.observations)
        .ok_or("one transmission only")?
        .clone();
    stray.transmitted =
        TransmitTime::new(final_one.transmitted.unix_ms + 30_000, 0).map_err(text)?;
    stray.lat_e7 += 1_000_000;
    let mut merge = Merge::new(Settings::new(false));
    feed(&mut merge, &models(&world.west), world.now)?;
    merge.ingest(&signed(&world.west_key, 0, final_one)?, world.now)?;
    merge.ingest(&early(&world.west_key, 0, stray)?, world.now)?;
    let served = merge
        .track(address)
        .and_then(Track::served)
        .ok_or("nothing served")?;
    assert_eq!(served.kind, Kind::Provisional, "the later is served");
    // Its deadline passes, by the client's clock, with nothing to confirm it: retracted, and
    // counted against its engine.
    merge.ingest(&Record::Heartbeat, world.now + PROVISIONAL_DEADLINE_MS + 1)?;
    let track = merge.track(address).ok_or("the final track went with it")?;
    assert!(track.provisional.is_empty());
    assert_eq!(track.served().map(|fix| fix.kind), Some(Kind::Final));
    assert_eq!(merge.provisional_counts().retracted, 1);
    assert_eq!(merge.retractions(&world.west_key.public()), 1);
    Ok(())
}

#[test]
fn a_signer_is_held_to_two_provisionals_an_aircraft_a_second() -> Result<(), String> {
    let world = world()?;
    let all = solutions(&world.west)?;
    let address = all.first().ok_or("no solution")?.address;
    let theirs: Vec<tally_wire::Solution> = all
        .iter()
        .filter(|solution| solution.address == address)
        .take(3)
        .cloned()
        .collect();
    assert_eq!(theirs.len(), 3, "too few transmissions of one aircraft");
    let second = theirs[0].transmitted.unix_ms / 1000 * 1000;
    let mut merge = Merge::new(Settings::new(false));
    feed(&mut merge, &models(&world.west), world.now)?;
    let mut accepted = 0;
    for (at, mut solution) in theirs.into_iter().enumerate() {
        solution.transmitted = TransmitTime::new(second + at as u64 * 100, 0).map_err(text)?;
        if let Ingested::Provisional { accepted: one, .. } =
            merge.ingest(&early(&world.west_key, at as u64, solution)?, world.now)?
        {
            accepted += one;
        }
    }
    assert_eq!(accepted, PROVISIONAL_PER_SECOND);
    Ok(())
}

#[test]
fn a_live_engines_provisionals_are_superseded_or_confirmed_by_its_finals() -> Result<(), String> {
    let mut simulation = sim::run(&tally_mlat::replay::scenario(31, 110.0));
    let delivered = tally_mlat::replay::arrivals(&mut simulation, 7)?;
    // On until the last window has been solved, so every transmission has had its final chance.
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let identity = Identity::from_seed([47; 32]);
    let mut engine = Engine::new(
        identity.clone(),
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            settle_ms: SETTLE_MS,
            threads: 2,
            capacity: Default::default(),
        },
    );
    let published = tally_mlat::replay::replay(&mut engine, &delivered, 100, until)?;
    let mut merge = Merge::new(Settings::new(false));
    let mut served_provisional = 0;
    for (at, record) in &published {
        merge.ingest(record, *at)?;
        if matches!(record, Record::Provisional(_)) {
            served_provisional += merge
                .tracks()
                .iter()
                .filter(|track| {
                    track
                        .served()
                        .is_some_and(|fix| fix.kind == Kind::Provisional)
                })
                .count();
        }
    }
    let end = until + PROVISIONAL_DEADLINE_MS + 1;
    merge.ingest(&Record::Heartbeat, end)?;
    let counts = merge.provisional_counts();
    eprintln!("{counts:?}");
    assert!(counts.accepted >= 200, "{counts:?}");
    assert!(served_provisional > 0, "a provisional was never served");
    // Every one is accounted for by the end, and few are retracted: the final positions that
    // followed confirmed or superseded the rest.
    let settled = counts.superseded + counts.confirmed;
    assert_eq!(
        settled + counts.retracted + counts.forgotten,
        counts.accepted,
        "{counts:?}"
    );
    assert!(
        counts.retracted * 20 <= counts.accepted,
        "{counts:?}: more than one in twenty retracted"
    );
    assert!(settled * 10 >= counts.accepted * 9, "{counts:?}");
    assert_eq!(merge.retractions(&identity.public()), counts.retracted);
    Ok(())
}
