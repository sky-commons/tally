//! Receiver standing and the agreeing-superset rule (RFC-0174 §2.12) over what a real engine
//! publishes: a simulated region of 24 receivers, an engine holding all of their raw, and records
//! cut down or fabricated where an attacker would.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use tally_mlat::engine::{Engine, Settings as EngineSettings};
use tally_mlat_solver::scope::{GRID_MS, Window, bin_of};
use tally_mlat_solver::sim::{self, Feed, Scenario, Simulation};
use tally_mlat_solver::standing::{self as rule, Claimed, ReceiverStanding};
use tally_mlat_solver::{ClockModel as Model, Reach, SPEC_VERSION, Timebase, geo, linalg, publish};
use tally_wire::{
    Batch, BatchContent, Identity, ObservationSet, Positions, PublicKey, Record, SolutionsContent,
};

use crate::{Confidence, Merge, Settings, Transmission};

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const SETTLE_MS: u64 = 1_000;

struct World {
    simulation: Simulation,
    feeds: Vec<Feed>,
    raw: Vec<Record>,
    published: Vec<Record>,
    engine: Identity,
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
    let engine = Identity::from_seed([61; 32]);
    let mut running = Engine::new(
        engine.clone(),
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            settle_ms: SETTLE_MS,
            threads: 4,
            capacity: Default::default(),
        },
    );
    for record in &raw {
        running.ingest(record, tally_mlat::replay::sent_ms(record))?;
    }
    let published = running.step(now, now).0;
    Ok(World {
        simulation,
        feeds,
        raw,
        published,
        engine,
        now,
    })
}

fn world() -> Result<&'static World, String> {
    static WORLD: OnceLock<Result<World, String>> = OnceLock::new();
    WORLD.get_or_init(build).as_ref().map_err(Clone::clone)
}

fn models(records: &[Record]) -> Vec<Record> {
    records
        .iter()
        .filter(|record| matches!(record, Record::ClockModel(_) | Record::ClockModelPart(_)))
        .cloned()
        .collect()
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

/// Signs `solutions` as `identity`'s final or provisional positions, issued at `issued_ms`.
fn signed(
    identity: &Identity,
    sequence: u64,
    issued_ms: u64,
    provisional: bool,
    mut solutions: Vec<tally_wire::Solution>,
) -> Result<Record, String> {
    if provisional {
        // A provisional names no addressed citation.
        for solution in &mut solutions {
            solution.addressed = tally_wire::AddressedCitation::default();
        }
    }
    let content = SolutionsContent {
        boot_id: 0x5ea1,
        sequence,
        issued_ms,
        spec_version: SPEC_VERSION,
        solutions,
    };
    if provisional {
        Positions::sign_provisional(identity, &content)
            .map(Record::Provisional)
            .map_err(text)
    } else {
        Positions::sign_solutions(identity, &content)
            .map(Record::Positions)
            .map_err(text)
    }
}

fn feed(merge: &mut Merge, records: &[Record], now: u64) -> Result<(), String> {
    for record in records {
        merge.ingest(record, now)?;
    }
    Ok(())
}

/// What a client holding raw makes of `records` once every transmission has settled.
fn settled(records: &[Record], now: u64) -> Result<Merge, String> {
    let mut merge = Merge::new(Settings::new(true));
    feed(&mut merge, records, now)?;
    merge.tick(now + rule::SETTLE_MS + 1);
    Ok(merge)
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
    /// Who the ten are, and their fabricated receptions as signed batches.
    padders: Vec<PublicKey>,
    batches: Vec<Record>,
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
        let mut batches = Vec::new();
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
            // Published as the padder's own raw, in time.
            let index = world
                .simulation
                .receivers
                .iter()
                .position(|receiver| receiver.key == reception.receiver)
                .ok_or("not a simulated receiver")?;
            let real = world
                .simulation
                .receptions
                .iter()
                .find(|heard| {
                    heard.receiver == reception.receiver
                        && heard.observation.timestamp == reception.counter
                })
                .ok_or("no real reception")?;
            let mut observation = real.observation.clone();
            observation.timestamp = counter;
            let batch = Batch::sign(
                &world.feeds[index].identity,
                &BatchContent {
                    boot_id: 2,
                    sequence: 0,
                    counter_epoch: reception.epoch,
                    wall_ms: real.wall_ms,
                    dropped: 0,
                    previous: [0; 32],
                    observations: vec![observation],
                },
            )
            .map_err(text)?;
            batches.push(Record::Batch(batch));
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
            batches,
        });
    }
    Err("no eligible solution of fifteen receptions with ten 12 MHz receivers".to_owned())
}

/// Every honest fix is consistent with its own receptions under its own model: final ones under
/// the window, and a live engine's provisional ones carried.
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
        Identity::from_seed([62; 32]),
        0xb007,
        EngineSettings {
            regions: tally_wire::Regions::default(),
            settle_ms: SETTLE_MS,
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

/// The fake-receiver attack: an honest fix and the same plus ten fabricated receivers that move
/// it 3 km. Whichever comes first, the honest fix is served, and the padded one is refused and
/// reported contested.
#[test]
fn ten_fabricated_receivers_do_not_move_the_served_position_and_are_contested() -> Result<(), String>
{
    let world = world()?;
    let attack = attack(world)?;
    let attacker = Identity::from_seed([66; 32]);
    let honest = signed(
        &world.engine,
        1,
        world.now,
        false,
        vec![attack.honest.clone()],
    )?;
    let padded = signed(
        &attacker,
        1,
        world.now + 1_000,
        false,
        vec![attack.padded.clone()],
    )?;
    for order in [[&honest, &padded], [&padded, &honest]] {
        let mut merge = Merge::new(Settings::new(false));
        feed(&mut merge, &models(&world.published), world.now)?;
        for record in order {
            merge.ingest(record, world.now)?;
        }
        let track = merge.track(attack.honest.address).ok_or("no track")?;
        let served = track.served().ok_or("nothing served")?;
        assert_eq!(served.observations, attack.honest.observations);
        assert_eq!(
            (served.lat_e7, served.lon_e7),
            (attack.honest.lat_e7, attack.honest.lon_e7)
        );
        let transmission = track.latest().ok_or("no transmission")?;
        assert!(transmission.is_contested());
        assert_eq!(transmission.refused.len(), 1);
        assert_eq!(
            transmission.refused[0].observations,
            attack.padded.observations
        );
        let contest = &transmission.contests[0];
        assert!(
            contest.chi2 > crate::standing::AGREE_CHI2,
            "{}",
            contest.chi2
        );
        assert_eq!(contest.added.len(), 10);
        assert_eq!(merge.contested(), 1);
        // Nobody here has standing: the position is drawn, labelled unconfirmed.
        assert_eq!(served.confidence, Confidence::Unconfirmed);
    }
    // The same receptions with the honest position agree, and the larger set wins.
    let mut agreeing = attack.padded.clone();
    agreeing.lat_e7 = attack.honest.lat_e7;
    agreeing.lon_e7 = attack.honest.lon_e7;
    let mut merge = Merge::new(Settings::new(false));
    feed(&mut merge, &models(&world.published), world.now)?;
    merge.ingest(&honest, world.now)?;
    merge.ingest(
        &signed(&attacker, 2, world.now, false, vec![agreeing.clone()])?,
        world.now,
    )?;
    let track = merge.track(attack.honest.address).ok_or("no track")?;
    assert_eq!(
        track.served().map(|fix| &fix.observations),
        Some(&agreeing.observations)
    );
    assert!(!track.latest().is_some_and(|latest| latest.is_contested()));
    Ok(())
}

/// The padders publish their fabricated receptions as their own raw. When the transmission
/// settles, every one of them disagrees with the fix that stands, and its receiver loses standing;
/// the honest fix's receivers, heard before any solution existed, earn.
#[test]
fn padding_a_fix_with_bad_receptions_loses_the_padders_their_standing() -> Result<(), String> {
    let world = world()?;
    let attack = attack(world)?;
    let attacker = Identity::from_seed([66; 32]);
    let mut records = world.raw.clone();
    records.extend(attack.batches.iter().cloned());
    records.extend(models(&world.published));
    records.push(signed(
        &world.engine,
        1,
        world.now,
        false,
        vec![attack.honest.clone()],
    )?);
    records.push(signed(
        &attacker,
        1,
        world.now + 1_000,
        false,
        vec![attack.padded.clone()],
    )?);
    let merge = settled(&records, world.now)?;
    let period = rule::period_of(attack.honest.transmitted.unix_ms);
    let standing = merge.standing();
    for padder in &attack.padders {
        let theirs = standing.of(padder);
        assert!(theirs.score(period) < 0, "{theirs:?}");
        assert_eq!(theirs.periods[&period].agreed, 0);
    }
    for reception in attack.honest.observations.receptions() {
        let theirs = standing.of(&reception.receiver);
        assert_eq!(theirs.periods[&period].agreed, 1, "{theirs:?}");
        assert!(theirs.score(period) > 0);
    }
    Ok(())
}

/// Every receiver the engine's solutions cite, heard before any solution existed and agreeing
/// with the final fix, earns: a count each eligible transmission, never more than a period's cap,
/// and not yet enough for any position to be confirmed. Standing is the same whatever order the
/// records came in, and the same at a relay that forwarded them.
#[test]
fn honest_receivers_earn_standing_the_same_at_every_keeper() -> Result<(), String> {
    let world = world()?;
    let mut records = world.raw.clone();
    records.extend(models(&world.published));
    let positions: Vec<Record> = world
        .published
        .iter()
        .filter(|record| matches!(record, Record::Positions(_)))
        .cloned()
        .collect();
    records.extend(positions.iter().cloned());
    let forward = settled(&records, world.now)?;
    let book = forward.standing().book();
    assert!(book.counts().earned > 1_000, "{:?}", book.counts());
    assert_eq!(book.counts().disagreed, 0, "{:?}", book.counts());
    // What each receiver should have earned: one a reception of an eligible transmission.
    let mut expected: std::collections::BTreeMap<PublicKey, u32> = Default::default();
    for solution in solutions(&positions)? {
        if rule::eligible(solution.observations.message(), solution.transmitted) {
            for reception in solution.observations.receptions() {
                *expected.entry(reception.receiver).or_default() += 1;
            }
        }
    }
    assert!(expected.len() >= 20);
    for (receiver, count) in &expected {
        let theirs = forward.standing().of(receiver);
        let agreed: u32 = theirs.periods.values().map(|tally| tally.agreed).sum();
        assert_eq!(agreed, *count);
        let latest = theirs.periods.keys().next_back().copied().unwrap_or(0);
        assert!(theirs.score(latest) > 0);
        assert!(!theirs.has_standing(latest), "one period is never enough");
    }
    for track in forward.tracks() {
        for transmission in &track.transmissions {
            assert_eq!(transmission.current().confidence, Confidence::Unconfirmed);
        }
    }
    // Another order: the positions backwards, the models after the first of them.
    let mut shuffled = world.raw.clone();
    let mut later: Vec<Record> = positions.iter().rev().cloned().collect();
    let first = later.remove(0);
    shuffled.push(first);
    shuffled.extend(models(&world.published));
    shuffled.extend(later);
    let backward = settled(&shuffled, world.now)?;
    assert_eq!(backward.standing().book().receivers(), book.receivers());
    // A relay that forwarded the same records: its standing reads the raw its hosted engine
    // sealed (one store of raw per relay), for receivers in the areas it holds raw for.
    let relay = std::sync::Arc::new(tally_relay::standing::Standing::new());
    // Standing takes records in on a thread of its own, as the relay starts it.
    tally_relay::standing::Standing::start(&relay, None)?;
    let mut held = tally_mlat_solver::held::Held::new(1 << 30);
    for record in &records {
        if let Record::Batch(batch) = record {
            let decoded = tally_wire::Decoded::from_verified(batch.clone(), world.now, 0)
                .map_err(|undecodable| undecodable.error.to_string())?;
            held.add_decoded(&decoded);
        }
    }
    held.seal_through(bin_of(world.now) + 1);
    relay.read_bins(held.sealed_bins().clone());
    let cell = tally_wire::Region::point(&tally_wire::Location {
        lat_e7: 337_490_000,
        lon_e7: -843_880_000,
        alt_m: 0,
        precision_m: 0,
    })
    .map_err(|error| error.to_string())?;
    let area = cell
        .ancestor(tally_wire::rendezvous::AREA_RESOLUTION)
        .ok_or("no area")?;
    relay.set_areas(&tally_wire::Regions::new([area]));
    for record in &records {
        match record {
            Record::ClockModel(_) | Record::ClockModelPart(_) => relay.model(record, world.now),
            Record::Positions(positions) => relay.positions(positions, world.now),
            _ => {}
        }
    }
    relay.tick(world.now + rule::SETTLE_MS + 1);
    assert!(
        relay.wait_idle(std::time::Duration::from_secs(120)),
        "standing never finished taking the records in"
    );
    for receiver in expected.keys() {
        assert_eq!(
            relay.of(receiver, Some(cell)),
            Some(forward.standing().of(receiver))
        );
    }
    let relays: Vec<ReceiverStanding> = world
        .simulation
        .receivers
        .iter()
        .filter_map(|receiver| relay.of(&receiver.key, Some(cell)))
        .collect();
    let clients: Vec<ReceiverStanding> = world
        .simulation
        .receivers
        .iter()
        .map(|receiver| forward.standing().of(&receiver.key))
        .collect();
    assert_eq!(relays, clients);
    Ok(())
}

/// A receiver that only ever copies what a published fix says (here, one whose every reception
/// first appears in a final solution issued after a provisional one of its transmission) earns
/// nothing, however well it agrees; the receivers of the earliest solutions earn as ever.
#[test]
fn a_receiver_that_only_copies_published_fixes_earns_nothing() -> Result<(), String> {
    let world = world()?;
    let all = solutions(&world.published)?;
    // The copier: the receiver cited most.
    let mut cited: std::collections::BTreeMap<PublicKey, usize> = Default::default();
    for solution in &all {
        for reception in solution.observations.receptions() {
            *cited.entry(reception.receiver).or_default() += 1;
        }
    }
    let copier = cited
        .iter()
        .max_by_key(|(key, count)| (**count, **key))
        .map(|(key, _)| *key)
        .ok_or("no receptions")?;
    let mut early = Vec::new();
    let mut late = Vec::new();
    for solution in all {
        if !solution
            .observations
            .receptions()
            .iter()
            .any(|reception| reception.receiver == copier)
        {
            early.push(solution);
            continue;
        }
        let without: Vec<tally_wire::Reception> = solution
            .observations
            .receptions()
            .iter()
            .filter(|reception| reception.receiver != copier)
            .copied()
            .collect();
        let mut first = solution.clone();
        first.observations =
            ObservationSet::new(solution.observations.message().to_vec(), without).map_err(text)?;
        early.push(first);
        late.push(solution);
    }
    assert!(late.len() > 50);
    let mut records = world.raw.clone();
    records.extend(models(&world.published));
    // The early ones are provisional, as they are: solved from what had arrived a second after
    // the transmission, so a final one may cite more.
    for (at, chunk) in early.chunks(64).enumerate() {
        records.push(signed(
            &world.engine,
            at as u64,
            world.now,
            true,
            chunk.to_vec(),
        )?);
    }
    for (at, chunk) in late.chunks(64).enumerate() {
        records.push(signed(
            &world.engine,
            1_000 + at as u64,
            world.now + 1_000,
            false,
            chunk.to_vec(),
        )?);
    }
    let merge = settled(&records, world.now)?;
    let theirs = merge.standing().of(&copier);
    assert!(
        theirs
            .periods
            .values()
            .all(|tally| tally.agreed == 0 && tally.disagreed == 0),
        "{theirs:?}"
    );
    let earners = world
        .simulation
        .receivers
        .iter()
        .filter(|receiver| receiver.key != copier)
        .filter(|receiver| {
            merge
                .standing()
                .of(&receiver.key)
                .periods
                .values()
                .any(|tally| tally.agreed > 0)
        })
        .count();
    assert!(earners >= 20, "{earners}");
    Ok(())
}

/// A provisional fix published before every final one is the earliest: the receivers it cites
/// earn, and a final fix's other receivers, heard after it, do not.
#[test]
fn the_earliest_solution_of_a_transmission_is_what_arrived_before_any_solution()
-> Result<(), String> {
    let world = world()?;
    let attack = attack(world)?;
    // The engine's whole solution, and before it a provisional of the honest receptions only,
    // issued when they had all been heard.
    let whole = solutions(&world.published)?
        .into_iter()
        .find(|solution| {
            solution.observations.message() == attack.honest.observations.message()
                && solution.transmitted == attack.honest.transmitted
        })
        .ok_or("the whole solution")?;
    let heard_by = world
        .simulation
        .receptions
        .iter()
        .filter(|heard| heard.observation.data == whole.observations.message())
        .map(|heard| heard.wall_ms)
        .max()
        .ok_or("never heard")?;
    let early_ms = heard_by + 1;
    let provisional = signed(
        &world.engine,
        3,
        early_ms,
        true,
        vec![attack.honest.clone()],
    )?;
    let mut records = world.raw.clone();
    records.extend(models(&world.published));
    records.push(provisional);
    records.push(signed(
        &world.engine,
        4,
        world.now,
        false,
        vec![whole.clone()],
    )?);
    let merge = settled(&records, world.now)?;
    let period = rule::period_of(whole.transmitted.unix_ms);
    let earned = |key: &PublicKey| {
        merge
            .standing()
            .of(key)
            .periods
            .get(&period)
            .map_or(0, |tally| tally.agreed)
    };
    for reception in attack.honest.observations.receptions() {
        assert_eq!(earned(&reception.receiver), 1);
    }
    for padder in &attack.padders {
        assert_eq!(
            earned(padder),
            0,
            "heard after the provisional, cited only by the final"
        );
    }
    Ok(())
}

/// Standing is read when a transmission is ranked, never frozen when a fix arrived (RFC-0174
/// §2.12: every party that reads the same record computes the same answer). Two clients take the
/// same records, the two incomparable fixes of one transmission in opposite orders with the
/// standing of every receiver settled between them; once both hold every record they rank the
/// transmission the same and hold the same standing. With standing frozen at intake, the fix that
/// came after the settlement outranked the one before it, so the order decided the answer.
#[test]
fn the_ranking_is_a_function_of_the_records_held_not_of_when_they_arrived() -> Result<(), String> {
    let world = world()?;
    let all = solutions(&world.published)?;
    // The latest transmission of its aircraft, so the track's bound keeps it.
    let latest = |solution: &tally_wire::Solution| {
        all.iter().all(|other| {
            other.address != solution.address || other.transmitted <= solution.transmitted
        })
    };
    let whole = all
        .iter()
        .find(|solution| {
            rule::eligible(solution.observations.message(), solution.transmitted)
                && solution.observations.receptions().len() >= 6
                && latest(solution)
        })
        .cloned()
        .ok_or("no eligible latest solution of six receptions")?;
    // Two genuine solutions of it, each by an engine that never held one of its receivers' raw:
    // each an optimum of its own receptions under its own model, neither a subset of the other.
    let without = |at: usize| -> Result<(Vec<Record>, tally_wire::Solution), String> {
        let receiver = whole.observations.receptions()[at].receiver;
        let mut engine = Engine::new(
            Identity::from_seed([70 + at as u8; 32]),
            0xb007,
            EngineSettings {
                regions: tally_wire::Regions::default(),
                settle_ms: SETTLE_MS,
                threads: 4,
                capacity: Default::default(),
            },
        );
        for record in &world.raw {
            if let Record::Batch(batch) = record
                && batch.receiver().map_err(text)? == receiver
            {
                continue;
            }
            engine.ingest(record, tally_mlat::replay::sent_ms(record))?;
        }
        let published = engine.step(world.now, world.now).0;
        let solution = solutions(&published)?
            .into_iter()
            .find(|solution| {
                solution.observations.message() == whole.observations.message()
                    && solution.observations.receptions().len() + 1
                        == whole.observations.receptions().len()
                    && solution
                        .observations
                        .receptions()
                        .iter()
                        .all(|reception| whole.observations.receptions().contains(reception))
            })
            .ok_or("the transmission is not solved without one receiver")?;
        Ok((models(&published), solution))
    };
    let ((first_models, first), (second_models, second)) = (without(0)?, without(1)?);
    // Everything else the engine solved, whose receivers earn standing when it settles; the
    // whole solution is left out, so neither part is dominated by it.
    let mut records = world.raw.clone();
    records.extend(models(&world.published));
    records.extend(first_models);
    records.extend(second_models);
    let mut sequence = 10;
    for record in &world.published {
        if let Record::Positions(positions) = record {
            let others: Vec<tally_wire::Solution> = positions
                .solutions()
                .map_err(text)?
                .solutions
                .into_iter()
                .filter(|solution| solution.observations != whole.observations)
                .collect();
            if !others.is_empty() {
                records.push(signed(&world.engine, sequence, world.now, false, others)?);
                sequence += 1;
            }
        }
    }
    let parts = [first.observations.clone(), second.observations.clone()];
    let first = signed(
        &Identity::from_seed([70; 32]),
        1,
        world.now,
        false,
        vec![first],
    )?;
    let second = signed(
        &Identity::from_seed([71; 32]),
        1,
        world.now,
        false,
        vec![second],
    )?;
    let settles = world.now + rule::SETTLE_MS + 1;
    let after = settles + rule::SETTLE_MS + 1;
    let client = |early: &Record, late: &Record| -> Result<Merge, String> {
        let mut merge = Merge::new(Settings::new(true));
        feed(&mut merge, &records, world.now)?;
        merge.ingest(early, world.now)?;
        // Every receiver's standing changes here, the early fix's transmission among them.
        merge.tick(settles);
        merge.ingest(late, settles)?;
        merge.tick(after);
        Ok(merge)
    };
    let forward = client(&first, &second)?;
    let backward = client(&second, &first)?;
    assert!(
        forward.standing().book().counts().earned > 1_000,
        "{:?}",
        forward.standing().book().counts()
    );
    assert_eq!(
        forward.standing().book().receivers(),
        backward.standing().book().receivers()
    );
    let track = |merge: &Merge| -> Result<Vec<Transmission>, String> {
        Ok(merge
            .track(whole.address)
            .ok_or("no track")?
            .transmissions
            .clone())
    };
    let (ours, theirs) = (track(&forward)?, track(&backward)?);
    let held = ours
        .iter()
        .find(|transmission| {
            transmission
                .fixes
                .iter()
                .any(|fix| parts.contains(&fix.observations))
        })
        .ok_or("the transmission is not held")?;
    assert!(held.fixes.len() >= 2, "{held:?}");
    // Its fixes carry the standing their receivers hold now, which settling gave them.
    assert!(held.fixes.iter().all(|fix| fix.standing > 0), "{held:?}");
    assert_eq!(ours, theirs);
    Ok(())
}
