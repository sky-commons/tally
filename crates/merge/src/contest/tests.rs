//! The agreeing-superset rule (RFC-0174 §2.12) over tag sets, on what a real engine publishes: a
//! simulated region of 24 receivers, an engine holding all of their raw, and records cut down or
//! fabricated where an attacker would. The attack is built as only a relay could (from the raw
//! solution and the full model), then tagged and signed as a client is sent it.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use tally_mlat::engine::{Capacity, Engine, STEP_MS, Settings as EngineSettings};
use tally_mlat::replay::replay;
use tally_mlat_solver::pair::{Models, Prepared};
use tally_mlat_solver::sim::{self, Scenario};
use tally_mlat_solver::standing::{self as rule, Claimed};
use tally_mlat_solver::{SPEC_VERSION, Timebase, geo, linalg, publish};
use tally_wire::{
    ClientFaultProof, ClientRecord, FaultProof, FixSets, Identity, ObservationSet, Positions,
    PublicKey, ReceptionKey, Record, Signer, TaggedFixesContent, TaggedPositions,
};

use crate::{Merge, Settings};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

struct World {
    published: Vec<Record>,
    engine: Identity,
    /// Every receiver's reception key, as a relay holding its site has it.
    keys: BTreeMap<PublicKey, ReceptionKey>,
    /// When the replay ended: what the records signed here are issued at.
    now: u64,
}

const SEED: u64 = 53;

fn build() -> Result<World, String> {
    let mut simulation = sim::run(&Scenario {
        duration_s: 40.0,
        modes_aircraft: 10,
        receivers: 24,
        spread_m: 120_000.0,
        ..Scenario::new(SEED)
    });
    let delivered = sim::arrived_records(&mut simulation, SEED).map_err(text)?;
    let now = delivered.last().map_or(0, |(at, _)| *at) + 2 * STEP_MS;
    let engine = Identity::from_seed([61; 32]);
    let signer = Signer::new(Identity::from_seed([61; 32]), Arc::new(|| true));
    let mut running = Engine::new(
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            threads: 4,
            capacity: Capacity::default(),
        },
    );
    let published = replay(&mut running, &delivered, &signer, now)?
        .into_iter()
        .flat_map(|(_, step)| step.records())
        .collect();
    let keys = simulation
        .receivers
        .iter()
        .map(|receiver| (receiver.key, receiver.record.reception_key()))
        .collect();
    Ok(World {
        published,
        engine,
        keys,
        now,
    })
}

fn world() -> Result<&'static World, String> {
    static WORLD: OnceLock<Result<World, String>> = OnceLock::new();
    WORLD.get_or_init(build).as_ref().map_err(Clone::clone)
}

/// The model summaries `records` publish for clients.
fn models(records: &[Record]) -> Vec<ClientRecord> {
    records
        .iter()
        .filter_map(|record| match record {
            Record::ClientClockModel(model) => Some(ClientRecord::ClockModel(model.clone())),
            _ => None,
        })
        .collect()
}

fn solutions(records: &[Record]) -> Result<Vec<tally_wire::Fix>, String> {
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

/// `fix` over `receptions` alone, considered and used.
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

/// The pair models `ids` name, as `records` publish them, each with its indices built.
fn decoded(records: &[Record], ids: &[[u8; 32]]) -> Result<Vec<Prepared>, String> {
    ids.iter()
        .map(|id| {
            for record in records {
                if let Record::ClockModel(manifest) = record {
                    let content = manifest.content(&[]).map_err(text)?;
                    if publish::pair_model_id(&content.model) == *id {
                        let model = publish::decode_pairs(&content.model).map_err(text)?;
                        return Prepared::of(model, *id).ok_or_else(|| "unprepared".to_owned());
                    }
                }
            }
            Err("no such model".to_owned())
        })
        .collect()
}

/// Tags `solution` and signs it as `identity`'s final positions, issued at `issued_ms`, as a
/// client is sent it.
fn signed(
    world: &World,
    identity: &Identity,
    issued_ms: u64,
    solution: &tally_wire::Fix,
) -> Result<ClientRecord, String> {
    let tagged = solution
        .tagged(|key| world.keys.get(key).copied())
        .map_err(text)?;
    let content = TaggedFixesContent {
        boot_id: 0x5ea1,
        sequence: issued_ms,
        issued_ms,
        spec_version: SPEC_VERSION,
        fixes: vec![tagged],
    };
    let signed = Positions::sign_tagged_fix(identity, &content).map_err(text)?;
    Ok(ClientRecord::Positions(
        TaggedPositions::new(signed).map_err(|_| "untagged")?,
    ))
}

fn feed(merge: &mut Merge, records: &[ClientRecord]) -> Result<(), String> {
    for record in records {
        merge.ingest(record)?;
    }
    Ok(())
}

fn is_12mhz(models: &[Prepared], receiver: &PublicKey) -> bool {
    models.iter().any(|prepared| {
        prepared.model.scope.iter().any(|site| {
            site.receiver == *receiver && Timebase::of(site.clock) == Some(Timebase::Mhz12)
        })
    })
}

fn site(models: &[Prepared], receiver: &PublicKey) -> Option<linalg::Vec3> {
    models.iter().find_map(|prepared| {
        let site = prepared
            .model
            .scope
            .iter()
            .find(|site| site.receiver == *receiver)?;
        Some(geo::from_mm(site.mm()))
    })
}

fn claimed_ecef(solution: &tally_wire::Fix) -> Result<linalg::Vec3, String> {
    Claimed::of(solution)
        .ecef()
        .ok_or_else(|| "no height".to_owned())
}

/// The attack (RFC-0174 §2.12): an honest fix, and the same plus ten receivers' fabricated
/// receptions, which put the aircraft 3 km east.
struct Attack {
    /// The honest fix: an engine's fix with ten of its receivers taken out.
    honest: tally_wire::Fix,
    /// The honest fix plus ten fabricated receptions, solved 3 km east.
    padded: tally_wire::Fix,
    /// Who the ten are.
    padders: Vec<PublicKey>,
}

fn attack(world: &World) -> Result<Attack, String> {
    const SHIFT_M: f64 = 3_000.0;
    for whole in solutions(&world.published)? {
        let message = whole.considered().message().to_vec();
        if !rule::eligible(&message, whole.transmitted) || whole.used().receptions().len() < 15 {
            continue;
        }
        let model = decoded(&world.published, &whole.models)?;
        let here = claimed_ecef(&whole)?;
        let mut moved = whole.clone();
        let lat = f64::from(whole.lat_e7) * 1e-7;
        moved.lon_e7 += (SHIFT_M / (111_320.0 * lat.to_radians().cos()) * 1e7) as i32;
        let there = claimed_ecef(&moved)?;
        // The ten 12 MHz receivers whose ranges the move changes most.
        let mut candidates: Vec<(i64, tally_wire::Reception)> = Vec::new();
        for reception in whole.used().receptions() {
            if !is_12mhz(&model, &reception.receiver) {
                continue;
            }
            let Some(at) = site(&model, &reception.receiver) else {
                continue;
            };
            let change = linalg::norm(linalg::sub(there, at)) - linalg::norm(linalg::sub(here, at));
            candidates.push((-(change.abs() as i64), *reception));
        }
        if candidates.len() < 10 {
            continue;
        }
        candidates.sort();
        let padders: Vec<tally_wire::Reception> = candidates
            .iter()
            .take(10)
            .map(|(_, reception)| *reception)
            .collect();
        let keys: BTreeSet<PublicKey> =
            padders.iter().map(|reception| reception.receiver).collect();
        let kept: Vec<tally_wire::Reception> = whole
            .used()
            .receptions()
            .iter()
            .filter(|reception| !keys.contains(&reception.receiver))
            .copied()
            .collect();
        let mut honest = over(&whole, kept.clone())?;
        let widen = whole.used().receptions().len() as f32 / kept.len() as f32;
        for term in [
            &mut honest.covariance.xx,
            &mut honest.covariance.xy,
            &mut honest.covariance.xz,
            &mut honest.covariance.yy,
            &mut honest.covariance.yz,
            &mut honest.covariance.zz,
        ] {
            *term *= widen;
        }
        // Each padder's reception where the moved position puts it: its counter moved by the
        // change in range, at 12 000 000 counts a second.
        let mut fabricated = Vec::new();
        for reception in &padders {
            let at = site(&model, &reception.receiver).ok_or("no site")?;
            let change = linalg::norm(linalg::sub(there, at)) - linalg::norm(linalg::sub(here, at));
            let counts = (change / geo::C * 12e6).round() as i64;
            let counter = reception
                .counter
                .checked_add_signed(counts)
                .ok_or("counter")?;
            fabricated.push(tally_wire::Reception {
                counter,
                ..*reception
            });
        }
        let mut all = kept;
        all.extend(fabricated);
        let mut padded = over(&moved, all)?;
        padded.covariance = whole.covariance;
        return Ok(Attack {
            honest,
            padded,
            padders: keys.into_iter().collect(),
        });
    }
    Err("no eligible solution of fifteen receptions with ten 12 MHz receivers".to_owned())
}

/// Every honest fix is consistent with its own receptions under the models it cites. A client cannot
/// tell (it has no model's sites) and takes every fix as consistent, trusting the relay's gate; a
/// relay can, and drops one that is not before it forwards it, which never drops an honest one.
#[test]
fn honest_fixes_are_consistent_with_their_own_receptions() -> Result<(), String> {
    let world = world()?;
    let fixes = solutions(&world.published)?;
    assert!(fixes.len() > 100, "{} fixes", fixes.len());
    for fix in &fixes {
        let prepared = decoded(&world.published, &fix.models)?;
        let models = Models::new(prepared.iter().collect()).ok_or("models")?;
        assert!(rule::consistent(&models, fix.used(), &Claimed::of(fix)));
    }
    Ok(())
}

/// The fake-receiver attack, on tags: an honest fix and the same plus ten fabricated receivers'
/// receptions that move it 3 km. Whichever comes first, the honest fix is served, and the padded
/// one is refused and reported contested, naming the ten tags it added (what a relay rematches to
/// the receivers that pay for it). The same receptions at the honest position agree, and the
/// larger set wins.
#[test]
fn ten_fabricated_receivers_do_not_move_the_served_position_and_are_contested() -> Result<(), String>
{
    let world = world()?;
    let attack = attack(world)?;
    let attacker = Identity::from_seed([66; 32]);
    let honest = signed(world, &world.engine, world.now, &attack.honest)?;
    let padded = signed(world, &attacker, world.now + 1_000, &attack.padded)?;
    let tags = |solution: &tally_wire::Fix| -> Result<tally_wire::TaggedSet, String> {
        Ok(solution
            .tagged(|key| world.keys.get(key).copied())
            .map_err(text)?
            .considered()
            .clone())
    };
    let (honest_tags, padded_tags) = (tags(&attack.honest)?, tags(&attack.padded)?);
    // The padded fix cites the engine's model under the attacker's signature; the attacker signs
    // that model's summary too, as an engine colluding with it would, and it agrees.
    let mut summaries = models(&world.published);
    for record in models(&world.published) {
        if let ClientRecord::ClockModel(model) = record {
            let content = model.content().map_err(text)?;
            summaries.push(ClientRecord::ClockModel(
                tally_wire::ClientClockModel::sign(&attacker, &content).map_err(text)?,
            ));
        }
    }
    for order in [[&honest, &padded], [&padded, &honest]] {
        let mut merge = Merge::new(Settings::default());
        feed(&mut merge, &summaries)?;
        for record in order {
            merge.ingest(record)?;
        }
        let track = merge.track(attack.honest.address).ok_or("no track")?;
        let served = track.current().ok_or("nothing served")?;
        assert_eq!(served.considered, honest_tags);
        assert_eq!(
            (served.lat_e7, served.lon_e7),
            (attack.honest.lat_e7, attack.honest.lon_e7)
        );
        let transmission = track.latest().ok_or("no transmission")?;
        assert!(transmission.is_contested());
        assert_eq!(transmission.refused.len(), 1);
        assert_eq!(transmission.refused[0].considered, padded_tags);
        let contest = &transmission.contests[0];
        assert!(
            contest.chi2 > crate::contest::AGREE_CHI2,
            "{}",
            contest.chi2
        );
        assert_eq!(contest.added.len(), attack.padders.len());
        assert!(
            contest
                .added
                .iter()
                .all(|tag| padded_tags.tags().contains(tag) && !honest_tags.tags().contains(tag))
        );
        assert_eq!(merge.contested(), 1);
    }
    let mut agreeing = attack.padded.clone();
    agreeing.lat_e7 = attack.honest.lat_e7;
    agreeing.lon_e7 = attack.honest.lon_e7;
    let mut merge = Merge::new(Settings::default());
    feed(&mut merge, &summaries)?;
    merge.ingest(&honest)?;
    merge.ingest(&signed(world, &attacker, world.now, &agreeing)?)?;
    let track = merge.track(attack.honest.address).ok_or("no track")?;
    assert_eq!(
        track.current().map(|fix| &fix.considered),
        Some(&tags(&agreeing)?)
    );
    assert!(!track.latest().is_some_and(|latest| latest.is_contested()));
    Ok(())
}

/// Every model summary of `records` signed again by `identity`, as an engine colluding with the
/// one that fitted them would.
fn summaries_signed_by(
    records: &[Record],
    identity: &Identity,
) -> Result<Vec<ClientRecord>, String> {
    let mut out = Vec::new();
    for record in models(records) {
        if let ClientRecord::ClockModel(model) = record {
            let content = model.content().map_err(text)?;
            out.push(ClientRecord::ClockModel(
                tally_wire::ClientClockModel::sign(identity, &content).map_err(text)?,
            ));
        }
    }
    Ok(out)
}

/// The fix of `address`'s latest transmission the merge serves, by its considered tags.
fn served(merge: &Merge, address: u32) -> Option<tally_wire::TaggedSet> {
    merge
        .track(address)?
        .current()
        .map(|fix| fix.considered.clone())
}

/// Early publishing's attack on the rule (mlat-shape §5): an engine publishes fast a favourable
/// subset (the honest fix's receptions less ten, moved 3 km), so that the honest bigger fix, which
/// disagrees with it, is a contested superset. A client cannot verify the bigger fix (it holds no
/// raw), so the superset stays contested while it is unjudged and the subset is served; the
/// verdict that reaches a client is a fault proof against the liar (two fixes of one used set
/// under one model that disagree, as a relay holding the raw convicts it), and it can arrive at
/// any point, before, between or after the fixes, and again by another relay. In every order the
/// same answer is held at the end (the honest bigger fix): what a merge serves is a function of
/// the records it holds, never of their order, so the bigger fix served alone before the subset
/// arrives is left for the subset while both are unjudged, as in any order. Once the verdict is
/// held, the honest fix is served from the first record that brings it and never left again (no
/// flapping), and a record of the convicted liar delivered after its verdict changes nothing.
#[test]
fn a_delayed_verdict_moves_the_served_fix_once_and_never_back() -> Result<(), String> {
    let world = world()?;
    let liar = Identity::from_seed([67; 32]);
    // The honest bigger fix: one the engine published over six receptions or more.
    let bigger = solutions(&world.published)?
        .into_iter()
        .find(|fix| fix.considered().receptions().len() >= 6)
        .ok_or("no fix of six receptions")?;
    let receptions = bigger.considered().receptions().to_vec();
    // The liar's fast subset: the bigger set less two receptions, moved 3 km east under the
    // bigger fix's covariance.
    let mut subset = over(&bigger, receptions[..receptions.len() - 2].to_vec())?;
    let lat = f64::from(bigger.lat_e7) * 1e-7;
    subset.lon_e7 += (3_000.0 / (111_320.0 * lat.to_radians().cos()) * 1e7) as i32;
    // Its second, contradicting fix of the same used set: what the proof is made of.
    let mut contradicting = subset.clone();
    contradicting.lat_e7 += 10_000;
    let subset_record = signed(world, &liar, world.now, &subset)?;
    let contradicting_record = signed(world, &liar, world.now + 1, &contradicting)?;
    let bigger_record = signed(world, &world.engine, world.now + 2, &bigger)?;
    let positions = |record: &ClientRecord| match record {
        ClientRecord::Positions(positions) => Ok(positions.get().clone()),
        _ => Err("not positions".to_owned()),
    };
    let proof = FaultProof::new(
        &positions(&subset_record)?,
        0,
        &positions(&contradicting_record)?,
        0,
    )
    .map_err(text)?;
    let proof = ClientRecord::FaultProof(
        ClientFaultProof::new(proof).map_err(|_| "a tagged proof refused")?,
    );
    let tags = |fix: &tally_wire::Fix| -> Result<tally_wire::TaggedSet, String> {
        Ok(fix
            .tagged(|key| world.keys.get(key).copied())
            .map_err(text)?
            .considered()
            .clone())
    };
    let (subset_tags, bigger_tags) = (tags(&subset)?, tags(&bigger)?);
    let mut summaries = models(&world.published);
    summaries.extend(summaries_signed_by(&world.published, &liar)?);

    // Unjudged, the bigger fix is contested and the subset served, whichever came first.
    for order in [
        [&subset_record, &bigger_record],
        [&bigger_record, &subset_record],
    ] {
        let mut merge = Merge::new(Settings::default());
        feed(&mut merge, &summaries)?;
        for record in order {
            merge.ingest(record)?;
        }
        assert_eq!(served(&merge, bigger.address), Some(subset_tags.clone()));
        let track = merge.track(bigger.address).ok_or("no track")?;
        assert!(track.latest().is_some_and(|latest| latest.is_contested()));
    }

    // The proof at every point among the two fixes, and delivered twice.
    let fixes = [&subset_record, &bigger_record];
    for first in 0..2 {
        let order = [fixes[first], fixes[1 - first]];
        for at in 0..=2 {
            let mut records: Vec<&ClientRecord> = order.to_vec();
            records.insert(at, &proof);
            records.push(&proof);
            let mut merge = Merge::new(Settings::default());
            feed(&mut merge, &summaries)?;
            let mut proven = false;
            let mut honest = false;
            for record in records {
                merge.ingest(record)?;
                proven |= std::ptr::eq(record, &proof);
                let now = served(&merge, bigger.address);
                if proven && now.as_ref() == Some(&bigger_tags) {
                    honest = true;
                }
                if honest {
                    assert_eq!(
                        now.as_ref(),
                        Some(&bigger_tags),
                        "the served fix left the honest one, order {first}, proof at {at}"
                    );
                }
            }
            assert!(honest, "order {first}, proof at {at}");
            assert!(merge.is_faulted(&liar.public()));
            let track = merge.track(bigger.address).ok_or("no track")?;
            assert!(!track.latest().is_some_and(|latest| latest.is_contested()));
            // The liar's fix again, by another relay, after its verdict: nothing changes.
            merge.ingest(&subset_record)?;
            assert_eq!(served(&merge, bigger.address), Some(bigger_tags.clone()));
        }
    }
    Ok(())
}
