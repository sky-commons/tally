//! The merge rules over what real engines publish for clients: the simulator's receivers, two
//! engines whose regions overlap (so the aircraft they share are solved from different receivers,
//! under different models), and records re-signed or cut down where a rule needs a case engines do
//! not produce on their own. A case is built from an engine's raw fix, as only a relay holds
//! it, and tagged with the receivers' reception keys, as the engine tags what it publishes.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use super::*;
use tally_mlat::engine::{Capacity, Engine, STEP_MS, Settings as EngineSettings};
use tally_mlat::replay::replay;
use tally_mlat_solver::SPEC_VERSION;
use tally_mlat_solver::sim::{self, Scenario};
use tally_wire::{
    FaultProof, FixSets, Identity, ObservationSet, ReceptionKey, Record, Signer, TaggedFixesContent,
};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// What two engines with overlapping regions published from the receivers' raw, in publish
/// order.
struct World {
    west: Vec<Record>,
    east: Vec<Record>,
    west_key: Identity,
    /// Every receiver's reception key, as a relay holding its site has it.
    keys: BTreeMap<PublicKey, ReceptionKey>,
}

const SEED: u64 = 31;

fn settings() -> EngineSettings {
    EngineSettings {
        regions: tally_wire::Regions::default(),
        threads: 4,
        capacity: Capacity::default(),
    }
}

/// Every record `steps` published, in order.
fn published(steps: Vec<(u64, tally_mlat::engine::Step)>) -> Vec<Record> {
    steps
        .into_iter()
        .flat_map(|(_, step)| step.records())
        .collect()
}

fn build() -> Result<World, String> {
    let mut simulation = sim::run(&Scenario {
        duration_s: 45.0,
        modes_aircraft: 16,
        ..Scenario::new(SEED)
    });
    let delivered = sim::arrived_records(&mut simulation, SEED).map_err(text)?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 2 * STEP_MS;
    let west_key = Identity::from_seed([41; 32]);
    // Two whole-world engines that hold different raw: the west the batches of the first seven
    // receivers, the east of the last seven (every site reaches both). Their areas' frontiers
    // differ where their raw does, so the aircraft they share are solved under models of
    // different inputs, from different receptions.
    let run = |seed: u8, receivers: std::ops::Range<usize>| -> Result<Vec<Record>, String> {
        let keys: BTreeSet<PublicKey> = simulation.receivers[receivers]
            .iter()
            .map(|receiver| receiver.key)
            .collect();
        let held: Vec<(u64, Record)> = delivered
            .iter()
            .filter(|(_, record)| match record {
                Record::Batch(batch) => batch.receiver().is_ok_and(|key| keys.contains(&key)),
                _ => true,
            })
            .cloned()
            .collect();
        let signer = Signer::new(Identity::from_seed([seed; 32]), Arc::new(|| true));
        let mut engine = Engine::new(0xb007, settings());
        Ok(published(replay(&mut engine, &held, &signer, until)?))
    };
    let west = run(41, 0..7)?;
    let east = run(42, 3..10)?;
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

fn feed(merge: &mut Merge, records: &[ClientRecord]) -> Result<(), String> {
    for record in records {
        merge.ingest(record)?;
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
                let content = positions.get().tagged_fixes().map_err(text)?;
                out.push(tagged_record(identity, &content)?);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn tagged_record(
    identity: &Identity,
    content: &TaggedFixesContent,
) -> Result<ClientRecord, String> {
    let signed = Positions::sign_tagged_fix(identity, content).map_err(text)?;
    Ok(ClientRecord::Positions(
        tally_wire::TaggedPositions::new(signed).map_err(|_| "untagged")?,
    ))
}

/// The raw fixes `records` publish, as a relay holds them.
fn raw_fixes(records: &[Record]) -> Result<Vec<tally_wire::Fix>, String> {
    let mut out = Vec::new();
    for record in records {
        if let Record::Positions(positions) = record
            && !positions.is_tagged()
        {
            out.extend(positions.fixes().map_err(text)?.fixes);
        }
    }
    Ok(out)
}

/// `fix` over `receptions` alone, considered and used: a fix an engine would have published had
/// only those arrived.
fn over(
    fix: &tally_wire::Fix,
    receptions: Vec<tally_wire::Reception>,
) -> Result<tally_wire::Fix, String> {
    let set = ObservationSet::new(fix.considered().message().to_vec(), receptions).map_err(text)?;
    Ok(tally_wire::Fix {
        sets: FixSets::new(set.clone(), set).map_err(text)?,
        ..fix.clone()
    })
}

/// The model summaries `records` publish for clients.
fn models(records: &[Record]) -> Vec<ClientRecord> {
    client(records)
        .into_iter()
        .filter(|record| matches!(record, ClientRecord::ClockModel(_)))
        .collect()
}

/// `solution` tagged as its engine would publish it.
fn tag(world: &World, solution: &tally_wire::Fix) -> Result<TaggedFix, String> {
    solution
        .tagged(|key| world.keys.get(key).copied())
        .map_err(text)
}

/// `solution` tagged and signed by `identity` as one final record.
fn signed(
    world: &World,
    identity: &Identity,
    sequence: u64,
    solution: &tally_wire::Fix,
) -> Result<ClientRecord, String> {
    tagged_record(
        identity,
        &TaggedFixesContent {
            boot_id: 0xb007,
            sequence: 2_000 + sequence,
            issued_ms: 0,
            spec_version: SPEC_VERSION,
            fixes: vec![tag(world, solution)?],
        },
    )
}

/// A client is sent tagged fixes and model summaries only; a relay-only form is not a
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
    let raw = raw_fixes(&world.west)?;
    let mut tagged = Vec::new();
    for record in &sent {
        if let ClientRecord::Positions(positions) = record {
            tagged.extend(positions.get().tagged_fixes().map_err(text)?.fixes);
        }
    }
    assert_eq!(tagged.len(), raw.len());
    for (one, wire) in tagged.iter().zip(&raw) {
        let back = tally_mlat_solver::publish::rematch(
            one,
            wire.considered().receptions().iter().copied(),
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
    feed(&mut once, &west)?;
    assert!(once.tracks().len() >= 5, "{} tracks", once.tracks().len());
    // Twice (two relays), backwards (positions before their models), and re-signed by a second
    // engine holding the same raw: the same tracks, with both engines behind every fix.
    let mut many = Merge::new(Settings::default());
    let mut backwards = west.clone();
    backwards.reverse();
    feed(&mut many, &backwards)?;
    feed(&mut many, &west)?;
    let other = Identity::from_seed([43; 32]);
    for record in &resign(&world.west, &other)? {
        let ingested = many.ingest(record)?;
        if let Ingested::Fixes { accepted, .. } = ingested {
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

/// A fix waits for the models it cites, and counts under a summary any engine not faulted signed:
/// a neighbouring area's model is its own relays', so the summary a fix stands on need not be its
/// own engine's.
#[test]
fn a_fix_waits_for_its_models_and_counts_under_any_engines_summary() -> Result<(), String> {
    let world = world()?;
    let other = Identity::from_seed([48; 32]);
    let mut merge = Merge::new(Settings::default());
    let solution = raw_fixes(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let ingested = merge.ingest(&signed(world, &world.west_key, 0, &solution)?)?;
    assert_eq!(
        ingested,
        Ingested::Fixes {
            accepted: 0,
            duplicate: 0,
            dropped: 0,
            pending: 1
        }
    );
    let summaries: Vec<ClientRecord> = resign(&world.west, &other)?
        .into_iter()
        .filter(|record| matches!(record, ClientRecord::ClockModel(_)))
        .collect();
    feed(&mut merge, &summaries)?;
    assert!(merge.holds(&tag(world, &solution)?));
    // The same summaries from the fix's own engine agree, and change nothing.
    feed(&mut merge, &models(&world.west))?;
    assert!(merge.holds(&tag(world, &solution)?));
    Ok(())
}

/// Two summaries of one model id that disagree dispute it: every fix citing it is dropped,
/// whichever came first, and a fix citing it later does not count.
#[test]
fn a_disputed_model_drops_every_fix_citing_it() -> Result<(), String> {
    let world = world()?;
    let liar = Identity::from_seed([49; 32]);
    let solution = raw_fixes(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let record = signed(world, &world.west_key, 0, &solution)?;
    let tagged = tag(world, &solution)?;
    let mut lies = Vec::new();
    for summary in models(&world.west) {
        if let ClientRecord::ClockModel(model) = summary {
            let mut content = model.content().map_err(text)?;
            if tagged.models.contains(&content.model) {
                content.inputs[0] ^= 1;
                lies.push(ClientRecord::ClockModel(
                    ClientClockModel::sign(&liar, &content).map_err(text)?,
                ));
            }
        }
    }
    assert!(!lies.is_empty(), "no summary of the fix's models");
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &models(&world.west))?;
    merge.ingest(&record)?;
    assert!(merge.holds(&tagged));
    feed(&mut merge, &lies)?;
    assert!(!merge.holds(&tagged), "a fix under a disputed model stood");
    let mut later = Merge::new(Settings::default());
    feed(&mut later, &models(&world.west))?;
    feed(&mut later, &lies)?;
    later.ingest(&record)?;
    assert!(!later.holds(&tagged));
    Ok(())
}

#[test]
fn a_superset_of_the_same_models_inputs_wins_in_either_order() -> Result<(), String> {
    let world = world()?;
    let all = raw_fixes(&world.west)?;
    // The most recent transmission of the aircraft with the most receptions.
    let full = all
        .iter()
        .filter(|solution| solution.considered().receptions().len() >= 5)
        .max_by_key(|solution| (solution.transmitted, solution.address))
        .ok_or("no solution of five receptions")?
        .clone();
    let receptions = full.considered().receptions();
    let cut = over(&full, receptions[..receptions.len() - 1].to_vec())?;
    let (full_record, cut_record) = (
        signed(world, &world.west_key, 0, &full)?,
        signed(world, &world.west_key, 1, &cut)?,
    );
    let tagged = tag(world, &full)?;
    for order in [[&cut_record, &full_record], [&full_record, &cut_record]] {
        let mut merge = Merge::new(Settings::default());
        feed(&mut merge, &models(&world.west))?;
        for record in order {
            merge.ingest(record)?;
        }
        let track = merge.track(full.address).ok_or("no track")?;
        let transmission = track.latest().ok_or("no final transmission")?;
        assert_eq!(transmission.current().considered, *tagged.considered());
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
    feed(&mut first, &west)?;
    feed(&mut first, &east)?;
    let mut second = Merge::new(Settings::default());
    feed(&mut second, &east)?;
    feed(&mut second, &west)?;
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
                current.considered.message(),
                alternative.considered.message()
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
    let solution = raw_fixes(&world.west)?
        .into_iter()
        .next()
        .ok_or("no solution")?;
    let tagged = tag(world, &solution)?;
    let fix = |weight: u64, hash: u8| Fix {
        address: tagged.address,
        transmitted: tagged.transmitted,
        lat_e7: 0,
        lon_e7: 0,
        alt_hae_mm: None,
        altitude_ft: None,
        horizontal_sigma_m: 1.0,
        covariance: tagged.covariance,
        considered: tagged.considered().clone(),
        used: tagged.used().clone(),
        models: vec![[hash; 32]],
        spec: SPEC_VERSION,
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

/// A tagged fault proof, as a client is sent it, convicts: two tagged fixes of one tag set
/// under one model, both signed by the west engine, that disagree by far more than the
/// specification allows.
#[test]
fn a_fault_proof_convicts_its_engine_and_drops_what_stood_on_its_word_alone() -> Result<(), String>
{
    let world = world()?;
    let witness = Identity::from_seed([44; 32]);
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &client(&world.west))?;
    feed(&mut merge, &client(&world.east))?;
    // Some of the west engine's fixes (its even addresses') are also signed by a witness.
    let mut witnessed = Vec::new();
    for record in resign(&world.west, &witness)? {
        match record {
            ClientRecord::Positions(positions) => {
                let mut content = positions.get().tagged_fixes().map_err(text)?;
                content.fixes.retain(|fix| fix.address % 2 == 0);
                if !content.fixes.is_empty() {
                    witnessed.push(tagged_record(&witness, &content)?);
                }
            }
            record => witnessed.push(record),
        }
    }
    feed(&mut merge, &witnessed)?;
    let west = world.west_key.public();
    assert!(fixes(&merge).iter().any(|fix| fix.engines == [west].into()));
    let honest = raw_fixes(&world.west)?
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
        merge.ingest(&ClientRecord::FaultProof(proof))?,
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
    feed(&mut merge, &client(&world.west))?;
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
    feed(&mut merge, &backwards)?;
    feed(&mut merge, &client(&world.east))?;
    assert!(merge.tracks().len() <= 3);
    assert!(merge.models() <= 4);
    assert!(merge.pending.len() <= 2);
    Ok(())
}

fn is_df11(solution: &tally_wire::Fix) -> bool {
    solution.considered().message()[0] >> 3 == 11
}

/// The transmission of a fix in `merge` whose tags are `set`'s.
fn holding(merge: &Merge, address: u32, set: &TaggedSet) -> Option<usize> {
    merge
        .track(address)?
        .transmissions
        .iter()
        .position(|transmission| transmission.fixes.iter().any(|fix| fix.considered == *set))
}

/// A Mode S reply repeats its bytes exactly, milliseconds apart, to another interrogator, so the
/// bytes and transmit times never join two fixes: only a tag in common does. One engine's
/// DF11 solution cut in two by receivers, the second half moved 50 ms later (counters and
/// transmit time) or not: halves that share no tag are never joined (a client cannot tie them
/// through a model, which needs the receivers' sites), and one tag in common joins them.
#[test]
fn identical_df11_replies_are_joined_only_by_a_tag_in_common() -> Result<(), String> {
    let world = world()?;
    let whole = raw_fixes(&world.west)?
        .into_iter()
        .filter(is_df11)
        .find(|solution| solution.considered().receptions().len() >= 4)
        .ok_or("no DF11 solution of four receptions")?;
    let receptions = whole.considered().receptions();
    let half = receptions.len() / 2;
    let first = over(&whole, receptions[..half].to_vec())?;
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
        let later = over(&later, moved)?;
        let mut merge = Merge::new(Settings::default());
        feed(&mut merge, &models(&world.west))?;
        merge.ingest(&signed(world, &world.west_key, 0, &first)?)?;
        merge.ingest(&signed(world, &world.west_key, 1, &later)?)?;
        let a = holding(&merge, whole.address, tag(world, &first)?.considered());
        let b = holding(&merge, whole.address, tag(world, &later)?.considered());
        assert!(a.is_some() && b.is_some(), "{a:?} {b:?}");
        assert_eq!(a == b, joined, "shifted {shift_ms} ms, shared {shared}");
    }
    Ok(())
}

/// An engine publishes a fix as soon as it can solve one and again as more receptions of the
/// transmission arrive, under the model of the moment: what a client holds of a live engine's
/// records, in the order it published them, is what it holds of them backwards, the fix served
/// of each transmission ranks before every alternative it was preferred to, and none of those is
/// a smaller fix of the same model's inputs.
#[test]
fn a_live_engines_bigger_fixes_follow_and_the_order_never_decides() -> Result<(), String> {
    let world = world()?;
    let sent = client(&world.west);
    let mut forwards = Merge::new(Settings::default());
    feed(&mut forwards, &sent)?;
    let mut backwards = Merge::new(Settings::default());
    let mut reversed = sent.clone();
    reversed.reverse();
    feed(&mut backwards, &reversed)?;
    assert_eq!(summary(&forwards), summary(&backwards));
    // A bigger fix of the same model's inputs replaced the smaller one: no alternative is a
    // subset of the current fix under the same inputs.
    for transmission in transmissions(&forwards) {
        let current = transmission.current();
        for alternative in transmission.alternatives() {
            assert!(current.rank() < alternative.rank());
            assert!(
                alternative.model_inputs != current.model_inputs
                    || alternative.considered.relation(&current.considered)
                        != tally_wire::observation_set::Relation::Subset,
                "a dominated fix kept"
            );
        }
    }
    Ok(())
}
