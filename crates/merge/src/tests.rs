//! The merge rules over what real engines publish for clients: the simulator's receivers, two
//! engines whose regions overlap (so the aircraft they share are solved from different receivers,
//! under different models), and records re-signed or cut down where a rule needs a case engines do
//! not produce on their own. A case is built from an engine's raw solution, as only a relay holds
//! it, and tagged with the receivers' reception keys, as the engine tags what it publishes.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::*;
use tally_mlat::engine::{Engine, Settings as EngineSettings};
use tally_mlat_solver::SPEC_VERSION;
use tally_mlat_solver::scope::{GRID_MS, Window, bin_of};
use tally_mlat_solver::sim::{self, Scenario};
use tally_wire::{
    FaultProof, Identity, ObservationSet, ReceptionKey, Record, SolutionsContent,
    TaggedSolutionsContent,
};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// What two engines with overlapping regions published from the receivers' raw.
struct World {
    west: Vec<Record>,
    east: Vec<Record>,
    west_key: Identity,
    /// Every receiver's reception key, as a relay holding its site has it.
    keys: BTreeMap<PublicKey, ReceptionKey>,
    now: u64,
}

const SETTLE_MS: u64 = 1_000;
/// How late every simulated receiver host's wall clock reads (`build`).
const HOST_CLOCK_LATE_MS: u64 = 400;

fn build() -> Result<World, String> {
    let simulation = sim::run(&Scenario {
        duration_s: 30.0,
        modes_aircraft: 16,
        ..Scenario::new(31)
    });
    let feeds = simulation.feeds().map_err(text)?;
    let mut raw: Vec<Record> = feeds
        .iter()
        .flat_map(|feed| {
            [
                Record::ReceiverInfo(feed.info.clone()),
                Record::ReceiverSite(feed.site.clone()),
            ]
        })
        .collect();
    // Every receiver's host clock reads `HOST_CLOCK_LATE_MS` late, as an unsynchronised one may:
    // its batches carry that wall clock. A GNSS gauge's origin takes only the day from it; a
    // free-running gauge's origin is dated by it, so the two engines' origins sit that far apart.
    for feed in &feeds {
        let mut previous = [0; 32];
        for batch in &feed.batches {
            let mut content = batch.content().map_err(text)?;
            content.wall_ms += HOST_CLOCK_LATE_MS;
            content.previous = previous;
            let late = tally_wire::Batch::sign(&feed.identity, &content).map_err(text)?;
            previous = late.hash();
            raw.push(Record::Batch(late));
        }
    }
    let last = simulation
        .receptions
        .iter()
        .map(|reception| bin_of(reception.wall_ms + HOST_CLOCK_LATE_MS))
        .max()
        .unwrap_or(0);
    let now = (Window::canonical(last).last + 1) as u64 * GRID_MS + SETTLE_MS;
    let west_key = Identity::from_seed([41; 32]);
    // Two whole-world engines that hold different raw: the west the batches of the first seven
    // receivers, the east of the last seven (every site reaches both). Their tiles' members
    // differ where their raw does, so the aircraft they share are solved under models of
    // different inputs, from different receptions.
    let run =
        |identity: Identity, receivers: std::ops::Range<usize>| -> Result<Vec<Record>, String> {
            let keys: BTreeSet<PublicKey> = simulation.receivers[receivers]
                .iter()
                .map(|receiver| receiver.key)
                .collect();
            let mut engine = Engine::new(
                tally_wire::Signer::new(identity, std::sync::Arc::new(|| true)),
                0xb007,
                EngineSettings {
                    regions: tally_wire::Regions::default(),
                    settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
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
                    engine.ingest(
                        record,
                        tally_wire::clocks::recorded::aligned(tally_mlat::replay::sent_ms(record)),
                    )?;
                }
            }
            Ok(engine.step(tally_wire::clocks::recorded::aligned(now)).0)
        };
    let west = run(Identity::from_seed([41; 32]), 0..7)?;
    let east = run(Identity::from_seed([42; 32]), 3..10)?;
    let keys = simulation
        .receivers
        .iter()
        .map(|receiver| (receiver.key, receiver.record.reception_key()))
        .collect();
    Ok(World {
        west,
        east,
        west_key,
        keys,
        now,
    })
}

fn world() -> Result<&'static World, String> {
    static WORLD: OnceLock<Result<World, String>> = OnceLock::new();
    WORLD.get_or_init(build).as_ref().map_err(Clone::clone)
}

/// What a client is sent of `records`: every client form, every relay-only one refused.
fn client(records: &[Record]) -> Vec<ClientRecord> {
    records
        .iter()
        .filter_map(|record| ClientRecord::try_from(record.clone()).ok())
        .collect()
}

fn feed(merge: &mut Merge, records: &[ClientRecord], now: u64) -> Result<(), String> {
    for record in records {
        merge.ingest(record, now)?;
    }
    Ok(())
}

/// Every transmission held as (address, current input set, alternatives' input sets).
type Summary = Vec<(u32, Hash, Vec<Hash>)>;

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

/// `records`' client forms as another engine would sign the same content: every model summary
/// and every tagged record re-signed by `identity`.
fn resign(records: &[Record], identity: &Identity) -> Result<Vec<ClientRecord>, String> {
    let mut out = Vec::new();
    for record in client(records) {
        match record {
            ClientRecord::ClockModel(model) => {
                let content = model.content().map_err(text)?;
                let signed = ClientClockModel::sign(identity, &content).map_err(text)?;
                out.push(ClientRecord::ClockModel(signed));
            }
            ClientRecord::Positions(positions) => {
                let content = positions.get().tagged_solutions().map_err(text)?;
                out.push(tagged_record(identity, &content, false)?);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn tagged_record(
    identity: &Identity,
    content: &TaggedSolutionsContent,
    provisional: bool,
) -> Result<ClientRecord, String> {
    if provisional {
        let signed = Positions::sign_tagged_provisional(identity, content).map_err(text)?;
        Ok(ClientRecord::Provisional(
            tally_wire::TaggedPositions::new(signed).map_err(|_| "untagged")?,
        ))
    } else {
        let signed = Positions::sign_tagged(identity, content).map_err(text)?;
        Ok(ClientRecord::Positions(
            tally_wire::TaggedPositions::new(signed).map_err(|_| "untagged")?,
        ))
    }
}

/// The raw final solutions `records` publish, as a relay holds them.
fn solutions(records: &[Record]) -> Result<Vec<tally_wire::Solution>, String> {
    let mut out = Vec::new();
    for record in records {
        if let Record::Positions(positions) = record
            && !positions.is_tagged()
        {
            out.extend(positions.solutions().map_err(text)?.solutions);
        }
    }
    Ok(out)
}

/// The model summaries `records` publish for clients.
fn models(records: &[Record]) -> Vec<ClientRecord> {
    client(records)
        .into_iter()
        .filter(|record| matches!(record, ClientRecord::ClockModel(_)))
        .collect()
}

/// `solution` tagged as its engine would publish it.
fn tag(world: &World, solution: &tally_wire::Solution) -> Result<TaggedSolution, String> {
    solution
        .tagged(|key| world.keys.get(key).copied())
        .map_err(text)
}

/// `solution` tagged and signed by `identity` as one final record.
fn signed(
    world: &World,
    identity: &Identity,
    sequence: u64,
    solution: &tally_wire::Solution,
) -> Result<ClientRecord, String> {
    tagged_record(
        identity,
        &SolutionsContent {
            boot_id: 0xb007,
            sequence: 2_000 + sequence,
            issued_ms: 0,
            spec_version: SPEC_VERSION,
            solutions: vec![tag(world, solution)?],
        },
        false,
    )
}

/// `solution` tagged and signed by `identity` as one provisional record: no addressed citation,
/// as a provisional names none.
fn early(
    world: &World,
    identity: &Identity,
    sequence: u64,
    solution: &tally_wire::Solution,
) -> Result<ClientRecord, String> {
    let mut solution = tag(world, solution)?;
    solution.addressed = tally_wire::AddressedCitation::default();
    tagged_record(
        identity,
        &SolutionsContent {
            boot_id: 0xb007,
            sequence,
            issued_ms: 0,
            spec_version: SPEC_VERSION,
            solutions: vec![solution],
        },
        true,
    )
}

/// A client is sent tagged solutions and model summaries only; a relay-only form is not a
/// `ClientRecord` at all, and every solution's tags rematch, at a relay, to the raw one.
#[test]
fn a_client_is_sent_only_tagged_forms_and_their_tags_rematch_at_a_relay() -> Result<(), String> {
    let world = world()?;
    let sent = client(&world.west);
    assert!(sent.len() < world.west.len());
    for record in &world.west {
        let refused = ClientRecord::try_from(record.clone()).is_err();
        let relay_only = matches!(record, Record::ClockModel(_) | Record::ClockModelPart(_))
            || matches!(record, Record::Positions(positions) if !positions.is_tagged());
        assert_eq!(refused, relay_only, "{record:?}");
    }
    let raw = solutions(&world.west)?;
    let mut tagged = Vec::new();
    for record in &sent {
        if let ClientRecord::Positions(positions) = record {
            tagged.extend(positions.get().tagged_solutions().map_err(text)?.solutions);
        }
    }
    assert_eq!(tagged.len(), raw.len());
    for (one, wire) in tagged.iter().zip(&raw) {
        let back = tally_mlat_solver::publish::rematch(
            one,
            wire.observations.receptions().iter().copied(),
            |key| world.keys.get(key).copied(),
        );
        assert_eq!(back.as_ref(), Some(wire));
    }
    Ok(())
}

#[test]
fn the_same_input_set_is_a_duplicate_whoever_signed_it_and_whatever_the_order() -> Result<(), String>
{
    let world = world()?;
    let west = client(&world.west);
    let mut once = Merge::new(Settings::default());
    feed(&mut once, &west, world.now)?;
    assert!(once.tracks().len() >= 5, "{} tracks", once.tracks().len());
    // Twice (two relays), backwards (positions before their models), and re-signed by a second
    // engine holding the same raw: the same tracks, with both engines behind every fix.
    let mut many = Merge::new(Settings::default());
    let mut backwards = west.clone();
    backwards.reverse();
    feed(&mut many, &backwards, world.now)?;
    feed(&mut many, &west, world.now)?;
    let other = Identity::from_seed([43; 32]);
    for record in &resign(&world.west, &other)? {
        let ingested = many.ingest(record, world.now)?;
        if let Ingested::Solutions { accepted, .. } = ingested {
            assert_eq!(accepted, 0, "a duplicate changed a track");
        }
    }
    assert_eq!(summary(&once), summary(&many));
    for fix in fixes(&many) {
        assert!(fix.engines.contains(&other.public()));
        assert!(fix.engines.contains(&world.west_key.public()));
        assert!(fix.horizontal_sigma_m > 0.0);
    }
    Ok(())
}

/// A solution counts only under a model summary its own engine signed: another key's summary
/// naming the same model id holds nothing up, and the solution waits.
#[test]
fn a_solution_counts_only_under_its_own_engines_model_summary() -> Result<(), String> {
    let world = world()?;
    let other = Identity::from_seed([48; 32]);
    let mut merge = Merge::new(Settings::default());
    let summaries: Vec<ClientRecord> = resign(&world.west, &other)?
        .into_iter()
        .filter(|record| matches!(record, ClientRecord::ClockModel(_)))
        .collect();
    feed(&mut merge, &summaries, world.now)?;
    let solution = solutions(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let ingested = merge.ingest(&signed(world, &world.west_key, 0, &solution)?, world.now)?;
    assert_eq!(
        ingested,
        Ingested::Solutions {
            accepted: 0,
            duplicate: 0,
            dropped: 0,
            pending: 1
        }
    );
    feed(&mut merge, &models(&world.west), world.now)?;
    assert!(merge.holds(&tag(world, &solution)?));
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
    let (full_record, cut_record) = (
        signed(world, &world.west_key, 0, &full)?,
        signed(world, &world.west_key, 1, &cut)?,
    );
    let tagged = tag(world, &full)?;
    for order in [[&cut_record, &full_record], [&full_record, &cut_record]] {
        let mut merge = Merge::new(Settings::default());
        feed(&mut merge, &models(&world.west), world.now)?;
        for record in order {
            merge.ingest(record, world.now)?;
        }
        let track = merge.track(full.address).ok_or("no track")?;
        let transmission = track.latest().ok_or("no final transmission")?;
        assert_eq!(transmission.current().observations, tagged.observations);
        assert!(
            transmission.alternatives().is_empty(),
            "a subset is not an alternative"
        );
    }
    Ok(())
}

#[test]
fn incomparable_sets_keep_the_first_by_the_tie_rule_and_record_the_other() -> Result<(), String> {
    let world = world()?;
    let (west, east) = (client(&world.west), client(&world.east));
    let mut first = Merge::new(Settings::default());
    feed(&mut first, &west, world.now)?;
    feed(&mut first, &east, world.now)?;
    let mut second = Merge::new(Settings::default());
    feed(&mut second, &east, world.now)?;
    feed(&mut second, &west, world.now)?;
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
    let tagged = tag(world, &solution)?;
    let fix = |weight: u64, hash: u8| Fix {
        kind: Kind::Final,
        address: tagged.address,
        transmitted: tagged.transmitted,
        lat_e7: 0,
        lon_e7: 0,
        alt_hae_mm: None,
        altitude_ft: None,
        horizontal_sigma_m: 1.0,
        covariance: tagged.covariance,
        observations: tagged.observations.clone(),
        model: [hash; 32],
        model_inputs: [hash; 32],
        input_set: [hash; 32],
        weight,
        engines: BTreeSet::new(),
    };
    let mut fixes = [fix(10, 1), fix(12, 9), fix(12, 3), fix(11, 0)];
    fixes.sort_by(order);
    let ranked: Vec<(u64, u8)> = fixes
        .iter()
        .map(|fix| (fix.weight, fix.input_set[0]))
        .collect();
    assert_eq!(ranked, vec![(12, 3), (12, 9), (11, 0), (10, 1)]);
    Ok(())
}

/// A tagged fault proof, as a client is sent it, convicts: two tagged solutions of one tag set
/// under one model, both signed by the west engine, that disagree by far more than the
/// specification allows.
#[test]
fn a_fault_proof_convicts_its_engine_and_drops_what_stood_on_its_word_alone() -> Result<(), String>
{
    let world = world()?;
    let witness = Identity::from_seed([44; 32]);
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &client(&world.west), world.now)?;
    feed(&mut merge, &client(&world.east), world.now)?;
    // Some of the west engine's fixes (its even addresses') are also signed by a witness.
    let mut witnessed = Vec::new();
    for record in resign(&world.west, &witness)? {
        match record {
            ClientRecord::Positions(positions) => {
                let mut content = positions.get().tagged_solutions().map_err(text)?;
                content
                    .solutions
                    .retain(|solution| solution.address % 2 == 0);
                if !content.solutions.is_empty() {
                    witnessed.push(tagged_record(&witness, &content, false)?);
                }
            }
            record => witnessed.push(record),
        }
    }
    feed(&mut merge, &witnessed, world.now)?;
    let west = world.west_key.public();
    assert!(fixes(&merge).iter().any(|fix| fix.engines == [west].into()));
    let honest = solutions(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let mut moved = honest.clone();
    moved.lat_e7 += 10_000;
    let positions = |record: ClientRecord| match record {
        ClientRecord::Positions(positions) => Ok(positions.get().clone()),
        _ => Err("not positions".to_owned()),
    };
    let first = positions(signed(world, &world.west_key, 50, &honest)?)?;
    let second = positions(signed(world, &world.west_key, 51, &moved)?)?;
    let proof = FaultProof::new(&first, 0, &second, 0).map_err(text)?;
    let proof = ClientFaultProof::new(proof).map_err(|_| "a tagged proof refused")?;
    assert_eq!(
        merge.ingest(&ClientRecord::FaultProof(proof), world.now)?,
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
    feed(&mut merge, &client(&world.west), world.now)?;
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
        ..Settings::default()
    };
    let mut merge = Merge::new(settings);
    let mut backwards = client(&world.west);
    backwards.reverse();
    feed(&mut merge, &backwards, world.now)?;
    feed(&mut merge, &client(&world.east), world.now)?;
    assert!(merge.tracks().len() <= 3);
    assert!(merge.models() <= 4);
    assert!(merge.pending.len() <= 2);
    Ok(())
}

fn is_df11(solution: &tally_wire::Solution) -> bool {
    solution.observations.message()[0] >> 3 == 11
}

/// The transmission of a fix in `merge` whose tags are `set`'s.
fn holding(merge: &Merge, address: u32, set: &TaggedSet) -> Option<usize> {
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

/// A Mode S reply repeats its bytes exactly, milliseconds apart, to another interrogator, so the
/// bytes and transmit times never join two solutions: only a tag in common does. One engine's
/// DF11 solution cut in two by receivers, the second half moved 50 ms later (counters and
/// transmit time) or not: halves that share no tag are never joined (a client cannot tie them
/// through a model, which needs the receivers' sites), and one tag in common joins them.
#[test]
fn identical_df11_replies_are_joined_only_by_a_tag_in_common() -> Result<(), String> {
    let world = world()?;
    let whole = solutions(&world.west)?
        .into_iter()
        .filter(is_df11)
        .find(|solution| solution.observations.receptions().len() >= 4)
        .ok_or("no DF11 solution of four receptions")?;
    let receptions = whole.observations.receptions();
    let half = receptions.len() / 2;
    let message = whole.observations.message().to_vec();
    let mut first = whole.clone();
    first.observations =
        ObservationSet::new(message.clone(), receptions[..half].to_vec()).map_err(text)?;
    for (shift_ms, shared, joined) in [(50u64, false, false), (0, false, false), (0, true, true)] {
        let mut later = whole.clone();
        later.transmitted = TransmitTime::new(
            later.transmitted.unix_ms + shift_ms,
            later.transmitted.sub_ms_ps,
        )
        .map_err(text)?;
        let mut moved: Vec<tally_wire::Reception> = receptions[half..]
            .iter()
            .map(|reception| tally_wire::Reception {
                // 12 MHz: 12 000 counts a millisecond.
                counter: reception.counter + shift_ms * 12_000,
                ..*reception
            })
            .collect();
        if shared {
            moved.push(receptions[0]);
        }
        later.observations = ObservationSet::new(message.clone(), moved).map_err(text)?;
        let mut merge = Merge::new(Settings::default());
        feed(&mut merge, &models(&world.west), world.now)?;
        merge.ingest(&signed(world, &world.west_key, 0, &first)?, world.now)?;
        merge.ingest(&signed(world, &world.west_key, 1, &later)?, world.now)?;
        let a = holding(&merge, whole.address, &tag(world, &first)?.observations);
        let b = holding(&merge, whole.address, &tag(world, &later)?.observations);
        assert!(a.is_some() && b.is_some(), "{a:?} {b:?}");
        assert_eq!(a == b, joined, "shifted {shift_ms} ms, shared {shared}");
    }
    Ok(())
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
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &models(&world.west), world.now)?;
    // The same transmission, solved a second after it was heard: held and served.
    let ingested = merge.ingest(&early(world, &world.west_key, 0, &final_one)?, world.now)?;
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
    // The final one of the same transmission arrives: it supersedes the provisional, which is
    // served no more.
    merge.ingest(&signed(world, &world.west_key, 0, &final_one)?, world.now)?;
    let track = merge.track(address).ok_or("no track")?;
    assert!(track.provisional.is_empty());
    assert_eq!(track.served().map(|fix| fix.kind), Some(Kind::Final));
    assert_eq!(merge.provisional_counts().superseded, 1);
    // A provisional arriving after the final of its transmission is not held.
    let late = merge.ingest(&early(world, &world.west_key, 1, &final_one)?, world.now)?;
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
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &models(&world.west), world.now)?;
    merge.ingest(&signed(world, &world.west_key, 0, &final_one)?, world.now)?;
    merge.ingest(&early(world, &world.west_key, 0, &stray)?, world.now)?;
    let served = merge
        .track(address)
        .and_then(Track::served)
        .ok_or("nothing served")?;
    assert_eq!(served.kind, Kind::Provisional, "the later is served");
    // Its deadline passes, by the client's clock, with nothing to confirm it: retracted, and
    // counted against its engine.
    merge.ingest(
        &ClientRecord::Heartbeat,
        world.now + PROVISIONAL_DEADLINE_MS + 1,
    )?;
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
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &models(&world.west), world.now)?;
    let mut accepted = 0;
    for (at, mut solution) in theirs.into_iter().enumerate() {
        solution.transmitted = TransmitTime::new(second + at as u64 * 100, 0).map_err(text)?;
        if let Ingested::Provisional { accepted: one, .. } = merge.ingest(
            &early(world, &world.west_key, at as u64, &solution)?,
            world.now,
        )? {
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
        tally_wire::Signer::new(Identity::from_seed([47; 32]), std::sync::Arc::new(|| true)),
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
            threads: 2,
            capacity: Default::default(),
        },
    );
    let published = tally_mlat::replay::replay(&mut engine, &delivered, 100, until)?;
    let mut merge = Merge::new(Settings::default());
    let mut served_provisional = 0;
    for (at, record) in published {
        let Ok(record) = ClientRecord::try_from(record) else {
            continue;
        };
        merge.ingest(&record, at)?;
        if matches!(record, ClientRecord::Provisional(_)) {
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
    merge.ingest(&ClientRecord::Heartbeat, end)?;
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
