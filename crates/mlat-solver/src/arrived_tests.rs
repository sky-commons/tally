use super::*;
use crate::sim::{self, Arrival, Rng, Scenario, Simulation};
use tally_wire::Identity;

fn key(seed: u8) -> PublicKey {
    Identity::from_seed([seed; 32]).public()
}

/// A DF11 all-call reply of `address`, which MLAT solves.
fn df11(address: u32) -> Vec<u8> {
    let body = [
        (11 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    modes::with_parity(&body, 0)
}

/// A DF17 of `address` carrying `me`.
fn df17(address: u32, me: [u8; 7]) -> Vec<u8> {
    let mut body = vec![
        (17 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    body.extend_from_slice(&me);
    modes::with_parity(&body, 0)
}

/// An airborne position with an altitude of `address`, its CPR `lat` distinguishing messages.
fn position(address: u32, lat: u32) -> Vec<u8> {
    df17(
        address,
        modes::encode_airborne_position(11, 0x0c38, lat % 2 == 1, lat, 1_000),
    )
}

/// An operational status with a NACp of `address`.
fn status(address: u32) -> Vec<u8> {
    let mut me = [0u8; 7];
    me[0] = 31 << 3;
    me[5] = (2 << 5) | 9;
    df17(address, me)
}

/// The first addresses from `from` that are reference aircraft.
fn references(from: u32, count: usize) -> Vec<u32> {
    (from..)
        .filter(|address| reference(*address))
        .take(count)
        .collect()
}

fn reception(receiver: PublicKey, wall_ms: u64, timestamp: u64, data: Vec<u8>) -> Reception {
    Reception {
        receiver,
        epoch: 3,
        timestamp,
        message: crate::obs::ModeS::new(&data).unwrap_or_else(|| panic!("{data:?} is no Mode S")),
        wall_ms,
    }
}

fn batch(receiver: PublicKey, sequence: u64) -> BatchId {
    BatchId {
        receiver,
        boot_id: 7,
        sequence,
    }
}

/// `count` replies of distinct addresses at `wall_ms`, timestamps from `first`.
fn replies(receiver: PublicKey, wall_ms: u64, count: u32, first: u64) -> Vec<Reception> {
    (0..count)
        .map(|n| reception(receiver, wall_ms, first + u64::from(n), df11(0x40_0000 + n)))
        .collect()
}

const AT: u64 = 1_791_288_000_000;

#[test]
fn a_batch_keeps_the_reference_aircrafts_sync_and_the_targets_replies() {
    let receiver = key(1);
    let reference_aircraft = references(0x40_0000, 1)[0];
    // A target: an aircraft with no ADS-B position, whatever its reference key.
    let [target] = [0x50_1234];
    let batch_receptions = vec![
        reception(receiver, AT, 10, position(reference_aircraft, 2)),
        reception(receiver, AT, 11, status(reference_aircraft)),
        // The reference aircraft's own reply: it is no target, the batch carrying its position.
        reception(receiver, AT, 14, df11(reference_aircraft)),
        reception(receiver, AT, 15, df11(target)),
        // Damaged, and not Mode S: never held.
        reception(receiver, AT, 16, vec![0x5d, 1, 2, 3, 4, 5, 6]),
    ];
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    let admitted = arrived.admit(batch(receiver, 0), AT + 100, &batch_receptions);
    // The reference aircraft's position and status, and the target's reply, unless the reference
    // aircraft is in the calibration sample (its reply then kept too).
    let sample = u32::from(sampled(reference_aircraft, AT));
    assert_eq!(admitted.kept, 3 + sample);
    assert_eq!(admitted.thinned, 2 - sample);
    assert_eq!(admitted.refused, None);
    assert_eq!(arrived.len(), (3 + sample) as usize);
    assert_eq!(size_of::<Entry>(), 16);
    assert_eq!(
        arrived.frontier(receiver),
        Some(Frontier {
            receiver,
            boot_id: 7,
            through_sequence: 0,
        })
    );
    // The target's reply settles, then is due with what had arrived.
    arrived.seal(AT + 100 + SETTLE_MS - 1);
    assert_eq!(arrived.due(AT + 100 + SETTLE_MS - 1).count(), 0);
    arrived.seal(AT + 100 + SETTLE_MS);
    let due: Vec<Considered> = arrived.due(AT + 100 + SETTLE_MS).collect();
    let target_due: Vec<&Considered> = due
        .iter()
        .filter(|considered| considered.key.message == message_hash(&df11(target)))
        .collect();
    assert_eq!(target_due.len(), 1);
    assert_eq!(target_due[0].receptions, vec![batch_receptions[3].clone()]);
    assert_eq!(target_due[0].first_arrival_ms, AT + 100);
}

#[test]
fn a_due_set_considers_what_arrived_and_is_due_again_once_it_grows() {
    let (one, two, three, four) = (key(1), key(2), key(3), key(4));
    let target = 0x50_1234;
    let heard = |receiver, timestamp| reception(receiver, AT, timestamp, df11(target));
    let sorted = |mut receptions: Vec<Reception>| {
        receptions.sort_by_cached_key(Reception::id);
        receptions
    };
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    arrived.admit(batch(one, 0), AT + 50, &[heard(one, 100)]);
    arrived.admit(batch(two, 0), AT + 700, &[heard(two, 200)]);
    let settled = AT + 50 + SETTLE_MS;
    arrived.seal(settled - 1);
    assert_eq!(arrived.due(settled - 1).count(), 0);
    arrived.seal(settled);
    let due: Vec<Considered> = arrived.due(settled).collect();
    assert_eq!(due.len(), 1);
    assert_eq!(
        due[0].receptions,
        sorted(vec![heard(one, 100), heard(two, 200)])
    );
    assert_eq!(
        due[0].key,
        TransmissionKey {
            message: message_hash(&df11(target)),
            slice: (AT + 50) / SLICE_MS,
        }
    );
    // Nothing joined: not due again.
    arrived.seal(settled + 1_000);
    assert_eq!(arrived.due(settled + 1_000).count(), 0);
    // A later reception joins it, under the same key, and it is due again with all of them.
    arrived.admit(batch(three, 0), settled + 1_500, &[heard(three, 300)]);
    arrived.seal(settled + 2_000);
    let grown: Vec<Considered> = arrived.due(settled + 2_000).collect();
    assert_eq!(grown.len(), 1);
    assert_eq!(grown[0].key, due[0].key);
    assert_eq!(grown[0].first_arrival_ms, AT + 50);
    assert_eq!(
        grown[0].receptions,
        sorted(vec![heard(one, 100), heard(two, 200), heard(three, 300)])
    );
    // The last reception within `JOIN_MS` of its first joins it; the seal that lets it go finds it
    // due once more, with all of them.
    arrived.admit(batch(four, 0), AT + 50 + JOIN_MS, &[heard(four, 400)]);
    arrived.seal(AT + 51 + JOIN_MS);
    let last: Vec<Considered> = arrived.due(AT + 51 + JOIN_MS).collect();
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].key, due[0].key);
    assert_eq!(last[0].receptions.len(), 4);
    // Past `JOIN_MS` of its first, a reception of the same bytes starts another set.
    arrived.admit(batch(four, 1), AT + 52 + JOIN_MS, &[heard(four, 500)]);
    arrived.seal(AT + 52 + JOIN_MS + SETTLE_MS);
    let other: Vec<Considered> = arrived.due(AT + 52 + JOIN_MS + SETTLE_MS).collect();
    assert_eq!(other.len(), 1);
    assert_ne!(other[0].key, due[0].key);
    assert_eq!(other[0].receptions, vec![heard(four, 500)]);
    assert_eq!(arrived.held, arrived.recounted());
}

#[test]
fn repeats_of_the_same_bytes_are_one_due_set_for_the_solver_to_split() {
    let (one, two) = (key(1), key(2));
    let target = 0x50_1234;
    let heard = |receiver, timestamp| reception(receiver, AT, timestamp, df11(target));
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    // The aircraft replies twice with the same bytes a second apart; both receivers hear both,
    // and the second receiver's second reception comes in a batch of its own.
    arrived.admit(
        batch(one, 0),
        AT + 50,
        &[heard(one, 100), heard(one, 12_000_100)],
    );
    arrived.admit(batch(two, 0), AT + 300, &[heard(two, 200)]);
    arrived.seal(AT + 50 + SETTLE_MS);
    let due: Vec<Considered> = arrived.due(AT + 50 + SETTLE_MS).collect();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].receptions.len(), 3);
    arrived.admit(
        batch(two, 1),
        AT + 1_300,
        &[reception(two, AT + 1_000, 12_000_200, df11(target))],
    );
    // The last joins the same set, which is due again with all four: the repeat is a new
    // transmission, solved at once.
    arrived.seal(AT + 1_300 + SLICE_MS);
    let grown: Vec<Considered> = arrived.due(AT + 1_300 + SLICE_MS).collect();
    assert_eq!(grown.len(), 1);
    assert_eq!(grown[0].key, due[0].key);
    assert_eq!(grown[0].receptions.len(), 4);
    // Nothing more joins: not due while it is open, and due once more as it closes, since it grew
    // after it was first due (a solver that held a grown transmission back solves it now).
    arrived.seal(AT + 1_300 + 2 * SLICE_MS);
    assert_eq!(arrived.due(AT + 1_300 + 2 * SLICE_MS).count(), 0);
    arrived.seal(AT + 51 + JOIN_MS);
    let closing: Vec<Considered> = arrived.due(AT + 51 + JOIN_MS).collect();
    assert_eq!(closing.len(), 1);
    assert_eq!(closing[0].receptions, grown[0].receptions);
    assert_eq!(arrived.held, arrived.recounted());
}

#[test]
fn over_its_slice_cap_a_batch_is_refused_whole_and_leaves_a_gap() {
    let receiver = key(1);
    let mut arrived = Arrived::new(Limits {
        per_receiver_slice: 100,
        ..Limits::UNBOUNDED
    });
    let first = arrived.admit(batch(receiver, 0), AT, &replies(receiver, AT, 60, 0));
    assert_eq!((first.kept, first.refused), (60, None));
    // Sixty more in the same slice: over the cap, refused whole.
    let second = arrived.admit(
        batch(receiver, 1),
        AT,
        &replies(receiver, AT + 10, 60, 1_000),
    );
    assert_eq!(second.kept, 0);
    assert_eq!(
        second.refused,
        Some(Refused::OverCap {
            what: "receptions one receiver holds in a slice",
            count: 120,
            cap: 100,
        })
    );
    assert_eq!(arrived.len(), 60);
    // The next slice is the receiver's own again, but its frontier stops below the gap.
    let third = arrived.admit(
        batch(receiver, 2),
        AT + 1_000,
        &replies(receiver, AT + 1_000, 60, 2_000),
    );
    assert_eq!(third.refused, None);
    assert_eq!(
        arrived.frontier(receiver).map(|f| f.through_sequence),
        Some(0)
    );
}

#[test]
fn beyond_the_pool_a_batch_is_refused_whole_and_the_pool_is_never_passed() {
    let mut simulation = sim::run(&Scenario {
        duration_s: 12.0,
        adsb_aircraft: 30,
        modes_aircraft: 20,
        ..Scenario::new(31)
    });
    let arrivals = sim::arrivals(&mut simulation, 5);
    let pool = 120_000;
    let mut arrived = Arrived::new(Limits::bytes(pool));
    let (mut refused, mut kept) = (0, 0);
    for arrival in &arrivals {
        let admitted = arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
        assert!(arrived.bytes() <= pool, "{} > {pool}", arrived.bytes());
        assert_eq!(arrived.held, arrived.recounted());
        match admitted.refused {
            Some(Refused::OverCap { what, count, cap }) => {
                assert_eq!((what, cap), ("bytes held", pool));
                assert!(count > pool);
                assert_eq!(admitted.kept, 0);
                refused += 1;
            }
            None => kept += admitted.kept,
            Some(other) => panic!("{other:?}"),
        }
    }
    assert!(refused > 0 && kept > 0, "{refused} refused, {kept} kept");
}

#[test]
fn a_frontier_is_the_run_with_no_gap_and_a_gap_older_than_held_raw_is_passed() {
    let receiver = key(1);
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    let one = |sequence: u64| replies(receiver, AT + sequence * 1_000, 2, sequence * 10);
    let through = |arrived: &Arrived| arrived.frontier(receiver).map(|f| f.through_sequence);
    for sequence in [0, 1, 3, 4] {
        arrived.admit(
            batch(receiver, sequence),
            AT + sequence * 1_000 + 100,
            &one(sequence),
        );
    }
    assert_eq!(through(&arrived), Some(1));
    // A copy adds nothing.
    let copy = arrived.admit(batch(receiver, 3), AT + 4_200, &one(3));
    assert_eq!(copy, Admitted::default());
    assert_eq!(arrived.len(), 8);
    // The gap fills: the run takes what waited above it.
    arrived.admit(batch(receiver, 2), AT + 4_300, &one(2));
    assert_eq!(through(&arrived), Some(4));
    // A gap that never fills is passed once the batch above it is older than anything held.
    arrived.admit(batch(receiver, 6), AT + 6_100, &one(6));
    arrived.seal(AT + 6_000 + HELD_MS);
    assert_eq!(through(&arrived), Some(4));
    arrived.seal(AT + 6_001 + HELD_MS);
    assert_eq!(through(&arrived), Some(6));
    assert_eq!(arrived.held, arrived.recounted());
    // A newer boot starts the frontier afresh; a late batch of the old one does not go back.
    let now = AT + 7_000 + HELD_MS;
    let rebooted = BatchId {
        receiver,
        boot_id: 8,
        sequence: 0,
    };
    arrived.admit(rebooted, now, &replies(receiver, now, 2, 900));
    assert_eq!(
        arrived.frontier(receiver),
        Some(Frontier {
            receiver,
            boot_id: 8,
            through_sequence: 0,
        })
    );
    arrived.admit(
        batch(receiver, 7),
        now + 10,
        &replies(receiver, now - 500, 2, 950),
    );
    assert_eq!(arrived.frontier(receiver).map(|f| f.boot_id), Some(8));
}

#[test]
fn a_batch_signed_too_far_ahead_or_behind_is_refused() {
    let receiver = key(1);
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    let ahead = arrived.admit(
        batch(receiver, 0),
        AT,
        &replies(receiver, AT + AHEAD_MS + 1, 2, 0),
    );
    assert_eq!(
        ahead.refused,
        Some(Refused::Ahead {
            wall_ms: AT + AHEAD_MS + 1
        })
    );
    let held = arrived.admit(
        batch(receiver, 0),
        AT,
        &replies(receiver, AT + AHEAD_MS, 2, 0),
    );
    assert_eq!(held.kept, 2);
    let late = arrived.admit(
        batch(receiver, 1),
        AT + 2 * HELD_MS,
        &replies(receiver, AT + HELD_MS - 1, 2, 10),
    );
    assert_eq!(
        late.refused,
        Some(Refused::Late {
            wall_ms: AT + HELD_MS - 1
        })
    );
    // Nothing it held could be cited: it is passed in its frontier.
    assert_eq!(
        arrived.frontier(receiver).map(|f| f.through_sequence),
        Some(1)
    );
}

/// A scenario with enough ADS-B aircraft that an area has reference aircraft, its arrivals, and
/// its sites.
fn sky(seed: u64) -> (Simulation, Vec<Arrival>, Sites) {
    let mut simulation = sim::run(&Scenario {
        duration_s: 30.0,
        adsb_aircraft: 40,
        modes_aircraft: 10,
        ..Scenario::new(seed)
    });
    let arrivals = sim::arrivals(&mut simulation, seed + 1);
    let sites = Sites::new(&simulation.sites());
    (simulation, arrivals, sites)
}

/// Every arrival admitted in turn, sealing each second, through `until_ms`.
fn hold(arrivals: &[Arrival], until_ms: u64, keep: impl Fn(&Arrival) -> bool) -> Arrived {
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    let mut sealed = 0;
    for arrival in arrivals.iter().filter(|arrival| arrival.at_ms <= until_ms) {
        if arrival.at_ms / SLICE_MS > sealed {
            sealed = arrival.at_ms / SLICE_MS;
            arrived.seal(sealed * SLICE_MS);
        }
        if keep(arrival) {
            arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
        }
    }
    arrived
}

/// The area holding the most of the scenario's receivers, ties to the lowest.
fn area_of(sites: &Sites) -> Region {
    let mut best: Option<(usize, Region)> = None;
    for (area, keys) in sites.areas() {
        if best.is_none_or(|(most, _)| keys.len() > most) {
            best = Some((keys.len(), *area));
        }
    }
    best.map(|(_, area)| area)
        .unwrap_or_else(|| unreachable!("a scenario has receivers"))
}

/// A model citing `inputs`, for `rebuild`: only what a rebuild reads matters.
fn citing(inputs: &Inputs) -> PairModel {
    PairModel {
        spec: crate::clock::SPEC_VERSION,
        area: inputs.area,
        trailing: inputs.trailing,
        scope: inputs.scope.clone(),
        frontier: inputs.frontier.clone(),
        input: inputs.citation,
        kappa: 1.0,
        clocks: Vec::new(),
        pairs: Vec::new(),
    }
}

#[test]
fn a_holder_of_the_cited_batches_rebuilds_the_inputs_in_any_order() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(41);
    let area = area_of(&sites);
    let edge = simulation.scenario.start_ms() + 25_000;
    let fitted = hold(&arrivals, edge, |_| true);
    let inputs = fitted
        .area_inputs(area, &sites, edge)
        .ok_or("two members or more")?;
    assert!(inputs.sync.len() > 100, "{}", inputs.sync.len());
    assert!(inputs.frontier.len() >= 2);
    assert_eq!(inputs.citation.count as usize, inputs.sync.len());
    // Another holder, given every batch in another order and five seconds more of them.
    let mut shuffled: Vec<Arrival> = arrivals
        .iter()
        .filter(|arrival| arrival.at_ms <= edge + 5_000)
        .cloned()
        .collect();
    let mut rng = Rng::new(9);
    for at in (1..shuffled.len()).rev() {
        shuffled.swap(at, (rng.next_u64() % (at as u64 + 1)) as usize);
    }
    let mut other = Arrived::new(Limits::UNBOUNDED);
    for arrival in &shuffled {
        other.admit(arrival.batch, edge, &arrival.receptions);
    }
    assert_eq!(other.rebuild(&citing(&inputs)), Ok(inputs.clone()));
    // A holder whose copy of a cited batch holds other receptions cites other inputs: the
    // citation commits to every cited part's receptions.
    let altered_batch = inputs
        .frontier
        .iter()
        .filter_map(|cited| {
            arrivals.iter().find(|arrival| {
                arrival.batch
                    == BatchId {
                        receiver: cited.receiver,
                        boot_id: cited.boot_id,
                        sequence: cited.through_sequence,
                    }
            })
        })
        .max_by_key(|arrival| arrival.receptions.len())
        .map(|arrival| arrival.batch)
        .ok_or("a cited batch")?;
    let mut altered = Arrived::new(Limits::UNBOUNDED);
    for arrival in arrivals.iter().filter(|arrival| arrival.at_ms <= edge) {
        let mut receptions = arrival.receptions.clone();
        if arrival.batch == altered_batch {
            for reception in &mut receptions {
                reception.timestamp += 1;
            }
        }
        altered.admit(arrival.batch, edge, &receptions);
    }
    let rebuilt = altered
        .rebuild(&citing(&inputs))
        .map_err(|why| format!("{why:?}"))?;
    assert_ne!(rebuilt.citation, inputs.citation);
    // A holder that lacks a cited batch says which, and judges nothing.
    let cited = inputs.frontier[0];
    let lacking = hold(&arrivals, edge, |arrival| {
        arrival.batch
            != BatchId {
                receiver: cited.receiver,
                boot_id: cited.boot_id,
                sequence: cited.through_sequence,
            }
    });
    match lacking.rebuild(&citing(&inputs)) {
        Err(PairModelFailure::Unjudged { missing }) => assert_eq!(
            missing,
            vec![BatchId {
                receiver: cited.receiver,
                boot_id: cited.boot_id,
                sequence: cited.through_sequence,
            }]
        ),
        other => panic!("{other:?}"),
    }
    // Frontiers out of order, or of no member, are the model's fault.
    let mut model = citing(&inputs);
    model.frontier.reverse();
    assert_eq!(other.rebuild(&model), Err(PairModelFailure::Frontier));
    let mut model = citing(&inputs);
    model.frontier[0].receiver = key(99);
    model.frontier.sort();
    assert_eq!(other.rebuild(&model), Err(PairModelFailure::Frontier));
    Ok(())
}

/// Two holders of every batch at or before an edge fit the same inputs there, frontiers and all,
/// however much more one holds and whatever order it came in: a model's inputs are a function of
/// its edge and the raw, never of when a batch arrived (crate docs, The trailing window).
#[test]
fn two_holders_of_the_edges_raw_cite_the_same_inputs() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(47);
    let area = area_of(&sites);
    let judged = simulation.scenario.start_ms() + 25_000;
    let edge = Trailing::fitted_at(judged).edge_ms;
    let first = hold(&arrivals, judged, |_| true);
    let mut later: Vec<Arrival> = arrivals
        .iter()
        .filter(|arrival| arrival.at_ms <= judged + 5_000)
        .cloned()
        .collect();
    later.reverse();
    let mut second = Arrived::new(Limits::UNBOUNDED);
    for arrival in &later {
        second.admit(arrival.batch, judged + 5_000, &arrival.receptions);
    }
    let one = first.area_inputs(area, &sites, edge).ok_or("members")?;
    let other = second.area_inputs(area, &sites, edge).ok_or("members")?;
    assert!(one.frontier.len() >= 2 && one.sync.len() > 100);
    assert_eq!(one, other);
    // What the second holds past the edge is held, and cited by a later edge.
    let further = second
        .area_inputs(area, &sites, edge + 3_000)
        .ok_or("members")?;
    assert!(
        further
            .frontier
            .iter()
            .zip(&one.frontier)
            .any(|(later, earlier)| later.through_sequence > earlier.through_sequence)
    );
    Ok(())
}

#[test]
fn a_holder_of_more_batches_holds_a_superset_of_the_inputs() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(43);
    let area = area_of(&sites);
    let edge = simulation.scenario.start_ms() + 25_000;
    let all = hold(&arrivals, edge, |_| true);
    // Fewer: every third receiver's batches after its tenth never came, and one batch of each
    // other receiver is missing midway.
    let receivers: Vec<PublicKey> = simulation.receivers.iter().map(|r| r.key).collect();
    let fewer = hold(&arrivals, edge, |arrival| {
        let index = receivers
            .iter()
            .position(|key| *key == arrival.batch.receiver)
            .unwrap_or(0);
        if index % 3 == 0 {
            arrival.batch.sequence < 10
        } else {
            arrival.batch.sequence != 15
        }
    });
    let more = all.area_inputs(area, &sites, edge).ok_or("members")?;
    let less = fewer.area_inputs(area, &sites, edge).ok_or("members")?;
    assert_eq!(more.scope, less.scope, "members follow the sites alone");
    assert!(less.sync.len() < more.sync.len());
    assert!(!less.sync.is_empty());
    let held: BTreeSet<(ObservationId, u64)> =
        more.sync.iter().map(|r| (more.id(r), r.wall_ms)).collect();
    for reception in &less.sync {
        assert!(held.contains(&(less.id(reception), reception.wall_ms)));
    }
    for frontier in &less.frontier {
        let wider = more
            .frontier
            .iter()
            .find(|other| other.receiver == frontier.receiver)
            .ok_or("the same receivers")?;
        assert!(frontier.through_sequence <= wider.through_sequence);
    }
    Ok(())
}

#[test]
fn the_pool_is_sized_on_what_a_reception_costs() {
    let (simulation, arrivals, _) = sky(47);
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    let mut sealed = 0;
    let mut kept = 0u64;
    for arrival in &arrivals {
        if arrival.at_ms / SLICE_MS > sealed {
            sealed = arrival.at_ms / SLICE_MS;
            arrived.seal(sealed * SLICE_MS);
        }
        kept += u64::from(
            arrived
                .admit(arrival.batch, arrival.at_ms, &arrival.receptions)
                .kept,
        );
        assert_eq!(arrived.held, arrived.recounted());
    }
    let receivers = simulation.receivers.len();
    let slices = arrived.slices.len();
    let planned = arrived.len() * BYTES_PER_KEPT
        + receivers * slices * BYTES_PER_RECEIVER_SLICE
        + receivers * BYTES_PER_RECEIVER
        + 16_384;
    eprintln!(
        "{} bytes for {} receptions ({} kept in all) of {receivers} receivers over {slices} slices: \
         planned {planned}",
        arrived.bytes(),
        arrived.len(),
        kept
    );
    assert!(
        arrived.bytes() <= planned,
        "{} > {planned}",
        arrived.bytes()
    );
    // What a receiver at the measured rates costs follows its rates.
    let cost = Rates::MEASURED.cost();
    let double = Rates {
        kept_per_s: 2 * Rates::MEASURED.kept_per_s,
        ..Rates::MEASURED
    }
    .cost();
    assert_eq!(
        double - cost,
        (Rates::MEASURED.kept_per_s as u64 * HELD_MS / 1_000) as usize * BYTES_PER_KEPT
    );
    assert_eq!(
        Limits::for_receivers(10, Rates::MEASURED),
        Limits {
            bytes: 10 * cost,
            per_receiver_slice: 1_800,
            held_ms: HELD_MS,
        }
    );
}

#[test]
fn a_receiver_forgotten_is_never_read_again() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(53);
    let area = area_of(&sites);
    let edge = simulation.scenario.start_ms() + 25_000;
    let mut arrived = hold(&arrivals, edge, |_| true);
    let inputs = arrived.area_inputs(area, &sites, edge).ok_or("members")?;
    let gone = inputs.frontier[0].receiver;
    arrived.forget(gone);
    assert_eq!(arrived.held, arrived.recounted());
    assert_eq!(arrived.frontier(gone), None);
    let after = arrived.area_inputs(area, &sites, edge).ok_or("members")?;
    assert!(
        after
            .sync
            .iter()
            .all(|reception| reception.receiver != gone)
    );
    assert!(
        after
            .frontier
            .iter()
            .all(|frontier| frontier.receiver != gone)
    );
    arrived.seal(edge + SETTLE_MS);
    for considered in arrived.due(edge + SETTLE_MS) {
        assert!(considered.receptions.iter().all(|r| r.receiver != gone));
    }
    Ok(())
}

#[test]
fn holding_a_run_is_admitting_its_batches_at_their_signed_time() -> Result<(), String> {
    let (simulation, _, sites) = sky(59);
    let area = area_of(&sites);
    let edge = simulation.scenario.start_ms() + 25_000;
    let held = Arrived::holding(&simulation.receptions);
    let inputs = held.area_inputs(area, &sites, edge).ok_or("members")?;
    assert!(!inputs.sync.is_empty());
    assert_eq!(held.len(), {
        let mut admitted = Arrived::new(Limits::UNBOUNDED);
        let mut by: BTreeMap<(PublicKey, u64), Vec<Reception>> = BTreeMap::new();
        for reception in &simulation.receptions {
            by.entry((reception.receiver, reception.wall_ms))
                .or_default()
                .push(reception.clone());
        }
        let mut sequences: BTreeMap<PublicKey, u64> = BTreeMap::new();
        for ((receiver, wall_ms), receptions) in by {
            let sequence = sequences.entry(receiver).or_default();
            admitted.admit(
                BatchId {
                    receiver,
                    boot_id: sim::BOOT_ID,
                    sequence: *sequence,
                },
                wall_ms,
                &receptions,
            );
            *sequence += 1;
        }
        admitted.len()
    });
    Ok(())
}

#[test]
fn a_held_reception_is_found_by_its_identity_with_its_earliest_batchs_arrival() {
    let one = key(1);
    // A target: an aircraft with no ADS-B position.
    let target = 0x50_1234;
    let first = reception(one, AT, 12_000_000, df11(target));
    let second = reception(one, AT + 200, 12_400_000, df11(target + 1));
    let mut arrived = Arrived::new(Limits::UNBOUNDED);
    arrived.admit(batch(one, 0), AT + 50, std::slice::from_ref(&first));
    // A later batch carrying the first again: its copy is not the one found.
    arrived.admit(batch(one, 1), AT + 400, &[first.clone(), second.clone()]);
    let unheard = reception(one, AT, 12_000_001, df11(target)).id();
    let found = arrived.held(&[second.id(), unheard, first.id()], AT + 100);
    let found: Vec<(ObservationId, u64, u64, Vec<u8>)> = found
        .into_iter()
        .map(|(r, arrived_ms)| (r.id(), r.wall_ms, arrived_ms, r.message.to_vec()))
        .collect();
    assert_eq!(
        found,
        vec![
            (
                second.id(),
                second.wall_ms,
                AT + 400,
                second.message.to_vec()
            ),
            (first.id(), first.wall_ms, AT + 50, first.message.to_vec()),
        ]
    );
    // Looked for around another transmit time, it is not in the slices searched.
    assert!(
        arrived
            .held(&[first.id()], AT + 2 * (AHEAD_MS + SLICE_MS) + SLICE_MS)
            .is_empty()
    );
    // A receiver forgotten is never found.
    arrived.forget(one);
    assert!(arrived.held(&[first.id(), second.id()], AT).is_empty());
}

/// Admits the arrivals after `from_ms` through `until_ms` into `arrived`, sealing each second.
fn hold_into(arrived: &mut Arrived, arrivals: &[Arrival], from_ms: u64, until_ms: u64) {
    let mut sealed = from_ms / SLICE_MS;
    for arrival in arrivals
        .iter()
        .filter(|arrival| arrival.at_ms > from_ms && arrival.at_ms <= until_ms)
    {
        if arrival.at_ms / SLICE_MS > sealed {
            sealed = arrival.at_ms / SLICE_MS;
            arrived.seal(sealed * SLICE_MS);
        }
        arrived.admit(arrival.batch, arrival.at_ms, &arrival.receptions);
    }
}

/// `late`, a holder whose raw of `receiver` began inside the window of `edge`, does not cite it,
/// and a holder of every batch rebuilds exactly the inputs it cites.
fn cites_only_whole_members(
    late: &Arrived,
    every: &Arrived,
    receiver: PublicKey,
    area: Region,
    sites: &Sites,
    edge: u64,
) -> Result<(), String> {
    let inputs = late.area_inputs(area, sites, edge).ok_or("members")?;
    assert!(late.frontier(receiver).is_some(), "its raw is held");
    assert!(
        inputs.frontier.iter().all(|f| f.receiver != receiver),
        "a member whose first batch arrived inside the window is not cited"
    );
    assert_eq!(late.rebuild(&citing(&inputs)), Ok(inputs.clone()));
    assert_eq!(every.rebuild(&citing(&inputs)), Ok(inputs));
    Ok(())
}

#[test]
fn a_member_whose_first_batch_arrived_inside_the_window_is_not_cited() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(61);
    let area = area_of(&sites);
    let start = simulation.scenario.start_ms();
    let edge = start + 25_000;
    let every = hold(&arrivals, edge, |_| true);
    let inputs = every.area_inputs(area, &sites, edge).ok_or("members")?;
    let receiver = inputs.frontier[0].receiver;
    // Its batches came only once it was described, inside the window.
    let described = start + 12_000;
    let late = hold(&arrivals, edge, |arrival| {
        arrival.batch.receiver != receiver || arrival.at_ms > described
    });
    cites_only_whole_members(&late, &every, receiver, area, &sites, edge)?;
    // Once its first batch held is older than the window, it is cited again.
    let later = start + 29_500;
    let late = hold(&arrivals, later, |arrival| {
        arrival.batch.receiver != receiver || arrival.at_ms > start + 7_000
    });
    let inputs = late.area_inputs(area, &sites, later).ok_or("members")?;
    assert!(inputs.frontier.iter().any(|f| f.receiver == receiver));
    Ok(())
}

#[test]
fn a_member_forgotten_inside_the_window_is_not_cited_on_its_return() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(67);
    let area = area_of(&sites);
    let start = simulation.scenario.start_ms();
    let edge = start + 25_000;
    let every = hold(&arrivals, edge, |_| true);
    let inputs = every.area_inputs(area, &sites, edge).ok_or("members")?;
    let receiver = inputs.frontier[0].receiver;
    let gone = start + 12_000;
    let mut late = hold(&arrivals, gone, |_| true);
    late.forget(receiver);
    hold_into(&mut late, &arrivals, gone, edge);
    cites_only_whole_members(&late, &every, receiver, area, &sites, edge)
}

#[test]
fn a_holder_restarted_inside_the_window_cites_none_it_began_mid_window() -> Result<(), String> {
    let (simulation, arrivals, sites) = sky(71);
    let area = area_of(&sites);
    let start = simulation.scenario.start_ms();
    let edge = start + 25_000;
    let every = hold(&arrivals, edge, |_| true);
    let inputs = every.area_inputs(area, &sites, edge).ok_or("members")?;
    let receiver = inputs.frontier[0].receiver;
    let mut restarted = Arrived::new(Limits::UNBOUNDED);
    hold_into(&mut restarted, &arrivals, start + 12_000, edge);
    cites_only_whole_members(&restarted, &every, receiver, area, &sites, edge)?;
    let inputs = restarted.area_inputs(area, &sites, edge).ok_or("members")?;
    assert!(inputs.frontier.is_empty() && inputs.sync.is_empty());
    Ok(())
}
