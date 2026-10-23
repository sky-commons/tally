//! The agreeing-superset rule (RFC-0174 §2.12) over tag sets, on what a real engine publishes: a
//! simulated region of 24 receivers, an engine holding all of their raw, and records cut down or
//! fabricated where an attacker would. The attack is built as only a relay could (from the raw
//! solution and the full model), then tagged and signed as a client is sent it.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use tally_mlat::engine::{Engine, Settings as EngineSettings};
use tally_mlat_solver::scope::{GRID_MS, Window, bin_of};
use tally_mlat_solver::sim::{self, Scenario};
use tally_mlat_solver::standing::{self as rule, Claimed};
use tally_mlat_solver::{ClockModel as Model, Reach, SPEC_VERSION, Timebase, geo, linalg, publish};
use tally_wire::{
    ClientRecord, Identity, ObservationSet, Positions, PublicKey, ReceptionKey, Record,
    SolutionsContent, TaggedPositions,
};

use crate::{Merge, Settings};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const SETTLE_MS: u64 = 1_000;

struct World {
    published: Vec<Record>,
    engine: Identity,
    /// Every receiver's reception key, as a relay holding its site has it.
    keys: BTreeMap<PublicKey, ReceptionKey>,
    now: u64,
}

fn build() -> Result<World, String> {
    let simulation = sim::run(&Scenario {
        duration_s: 40.0,
        modes_aircraft: 10,
        receivers: 24,
        spread_m: 120_000.0,
        ..Scenario::new(53)
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
    let engine = Identity::from_seed([61; 32]);
    let mut running = Engine::new(
        tally_wire::Signer::new(Identity::from_seed([61; 32]), std::sync::Arc::new(|| true)),
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
            threads: 4,
            capacity: Default::default(),
        },
    );
    for record in &raw {
        running.ingest(
            record,
            tally_wire::clocks::recorded::aligned(tally_mlat::replay::sent_ms(record)),
        )?;
    }
    let published = running.step(tally_wire::clocks::recorded::aligned(now)).0;
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

fn decoded(records: &[Record], id: &[u8; 32]) -> Result<Model, String> {
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

/// Tags `solution` and signs it as `identity`'s final positions, issued at `issued_ms`, as a
/// client is sent it.
fn signed(
    world: &World,
    identity: &Identity,
    issued_ms: u64,
    solution: &tally_wire::Solution,
) -> Result<ClientRecord, String> {
    let tagged = solution
        .tagged(|key| world.keys.get(key).copied())
        .map_err(text)?;
    let content = SolutionsContent {
        boot_id: 0x5ea1,
        sequence: 1,
        issued_ms,
        spec_version: SPEC_VERSION,
        solutions: vec![tagged],
    };
    let signed = Positions::sign_tagged(identity, &content).map_err(text)?;
    Ok(ClientRecord::Positions(
        TaggedPositions::new(signed).map_err(|_| "untagged")?,
    ))
}

fn feed(merge: &mut Merge, records: &[ClientRecord], now: u64) -> Result<(), String> {
    for record in records {
        merge.ingest(record, now)?;
    }
    Ok(())
}

fn is_12mhz(model: &Model, receiver: &PublicKey) -> bool {
    model
        .scope
        .iter()
        .any(|site| site.receiver == *receiver && Timebase::of(site.clock) == Some(Timebase::Mhz12))
}

fn site(model: &Model, receiver: &PublicKey) -> Option<linalg::Vec3> {
    let piece = model.pieces_of(receiver, 1).next()?;
    Some(geo::from_mm(model.pieces[piece].site_mm))
}

fn claimed_ecef(solution: &tally_wire::Solution) -> Result<linalg::Vec3, String> {
    Claimed::of(solution)
        .ecef()
        .ok_or_else(|| "no height".to_owned())
}

/// The attack (RFC-0174 §2.12): an honest fix, and the same plus ten receivers' fabricated
/// receptions, which put the aircraft 3 km east.
struct Attack {
    /// The honest fix: an engine's solution with ten of its receivers taken out.
    honest: tally_wire::Solution,
    /// The honest fix plus ten fabricated receptions, solved 3 km east.
    padded: tally_wire::Solution,
    /// Who the ten are.
    padders: Vec<PublicKey>,
}

fn attack(world: &World) -> Result<Attack, String> {
    const SHIFT_M: f64 = 3_000.0;
    for whole in solutions(&world.published)? {
        let message = whole.observations.message().to_vec();
        if !rule::eligible(&message, whole.transmitted)
            || whole.observations.receptions().len() < 15
        {
            continue;
        }
        let model = decoded(&world.published, &whole.clock_model)?;
        let here = claimed_ecef(&whole)?;
        let mut moved = whole.clone();
        let lat = f64::from(whole.lat_e7) * 1e-7;
        moved.lon_e7 += (SHIFT_M / (111_320.0 * lat.to_radians().cos()) * 1e7) as i32;
        let there = claimed_ecef(&moved)?;
        // The ten 12 MHz receivers whose ranges the move changes most.
        let mut candidates: Vec<(i64, tally_wire::Reception)> = Vec::new();
        for reception in whole.observations.receptions() {
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
            .observations
            .receptions()
            .iter()
            .filter(|reception| !keys.contains(&reception.receiver))
            .copied()
            .collect();
        let mut honest = whole.clone();
        honest.observations = ObservationSet::new(message.clone(), kept.clone()).map_err(text)?;
        let widen = whole.observations.receptions().len() as f32 / kept.len() as f32;
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
        let mut padded = moved;
        padded.covariance = whole.covariance;
        let mut all = kept;
        all.extend(fabricated);
        padded.observations = ObservationSet::new(message, all).map_err(text)?;
        return Ok(Attack {
            honest,
            padded,
            padders: keys.into_iter().collect(),
        });
    }
    Err("no eligible solution of fifteen receptions with ten 12 MHz receivers".to_owned())
}

/// Every honest fix is consistent with its own receptions under its own model: final ones under
/// the window, and a live engine's provisional ones carried. A client cannot tell (it has no
/// model's sites) and takes every fix as consistent; a relay can, and drops one that is not
/// before it forwards it, which never drops an honest one.
#[test]
fn honest_fixes_are_consistent_with_their_own_receptions() -> Result<(), String> {
    let world = world()?;
    let finals = solutions(&world.published)?;
    assert!(finals.len() > 100);
    for solution in &finals {
        let model = decoded(&world.published, &solution.clock_model)?;
        assert!(rule::consistent(
            &model,
            Reach::Window,
            &solution.observations,
            &Claimed::of(solution)
        ));
    }
    let mut simulation = sim::run(&tally_mlat::replay::scenario(31, 110.0));
    let delivered = tally_mlat::replay::arrivals(&mut simulation, 7)?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = Engine::new(
        tally_wire::Signer::new(Identity::from_seed([62; 32]), std::sync::Arc::new(|| true)),
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, SETTLE_MS>(),
            threads: 2,
            capacity: Default::default(),
        },
    );
    let published: Vec<Record> = tally_mlat::replay::replay(&mut engine, &delivered, 100, until)?
        .into_iter()
        .map(|(_, record)| record)
        .collect();
    let (mut provisional, mut consistent) = (0, 0);
    for record in &published {
        let Record::Provisional(positions) = record else {
            continue;
        };
        if positions.is_tagged() {
            continue;
        }
        for solution in positions.solutions().map_err(text)?.solutions {
            let model = decoded(&published, &solution.clock_model)?;
            provisional += 1;
            consistent += usize::from(rule::consistent(
                &model,
                Reach::Carried,
                &solution.observations,
                &Claimed::of(&solution),
            ));
        }
    }
    assert!(provisional > 100, "{provisional} provisional fixes");
    assert_eq!(consistent, provisional);
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
    let tags = |solution: &tally_wire::Solution| -> Result<tally_wire::TaggedSet, String> {
        Ok(solution
            .tagged(|key| world.keys.get(key).copied())
            .map_err(text)?
            .observations)
    };
    let (honest_tags, padded_tags) = (tags(&attack.honest)?, tags(&attack.padded)?);
    // The padded fix cites the engine's model under the attacker's signature, so the attacker
    // signs that model's summary too, as an engine colluding with it would.
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
        feed(&mut merge, &summaries, world.now)?;
        for record in order {
            merge.ingest(record, world.now)?;
        }
        let track = merge.track(attack.honest.address).ok_or("no track")?;
        let served = track.served().ok_or("nothing served")?;
        assert_eq!(served.observations, honest_tags);
        assert_eq!(
            (served.lat_e7, served.lon_e7),
            (attack.honest.lat_e7, attack.honest.lon_e7)
        );
        let transmission = track.latest().ok_or("no transmission")?;
        assert!(transmission.is_contested());
        assert_eq!(transmission.refused.len(), 1);
        assert_eq!(transmission.refused[0].observations, padded_tags);
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
    feed(&mut merge, &summaries, world.now)?;
    merge.ingest(&honest, world.now)?;
    merge.ingest(&signed(world, &attacker, world.now, &agreeing)?, world.now)?;
    let track = merge.track(attack.honest.address).ok_or("no track")?;
    assert_eq!(
        track.served().map(|fix| &fix.observations),
        Some(&tags(&agreeing)?)
    );
    assert!(!track.latest().is_some_and(|latest| latest.is_contested()));
    Ok(())
}
