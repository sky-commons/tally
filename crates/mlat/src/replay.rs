//! An engine driven over the simulator on a virtual clock, as a relay's hosted MLAT
//! (`tally_relay::mlat_host`) drives it on the real one: what the latency of provisional positions and their supersession by final ones are
//! measured with (here and in `tally-merge`'s tests).
//!
//! - **Feeders as they are** (`arrivals`): each simulated receiver seals a batch once a second, at
//!   a phase of its own (tally-feed's `SEAL_EVERY`; the simulator's own batches all seal on the
//!   whole second, which would make every reception of a transmission arrive together), and each
//!   batch reaches the engine after a delay of its receiver's path (40 to 250 ms) and a little
//!   jitter.
//! - **The engine as it runs** (`replay`): at every multiple of `tick_ms` of the virtual clock (a
//!   step), what arrived before it is ingested, provisional work is solved and published, and a due
//!   window is stepped. A receiver's description takes effect at the step after it arrived, as a
//!   relay's does (`tally_relay::mlat_host`, descriptions stamped and applied at their step): the
//!   batches that arrived before that step are taken as the receiver stood before it (those of a
//!   receiver not yet described wait for it, `intake::Intake::hold_orphan`), and the batches that
//!   waited are let go once they have waited `intake::ORPHAN_MS` of steps. Each record published is returned with its step. These are the hosted
//!   MLAT's steps (`tally_relay::mlat_host`: the multiples of its `STEP_MS` the stamp watermark
//!   passes, each weighing the batches stamped before it), so this is the reference the relay is
//!   held to byte for byte. The relay runs the two off the ingesting thread; here they run in
//!   line, which only makes them faster.

use tally_mlat_solver::sim::{self, Rng, Simulation};
use tally_wire::Record;

use crate::engine::Engine;

/// What `simulation`'s receivers publish, each record with when it reaches the engine: every
/// description at the start, then each batch at its seal time plus its path's delay. Sorted by
/// arrival. The simulation's receptions are rewritten in place to the wall clocks of the batches
/// they now travel in.
pub fn arrivals(simulation: &mut Simulation, seed: u64) -> Result<Vec<(u64, Record)>, String> {
    let mut rng = Rng::new(seed);
    let start_ms =
        simulation.scenario.midnight_unix_ms + (simulation.scenario.start_tod_s * 1000.0) as u64;
    // When each receiver seals its batches: this far into each second, in milliseconds.
    let phases: Vec<u64> = (0..simulation.receivers.len())
        .map(|_| (rng.uniform() * 1000.0) as u64)
        .collect();
    let delays: Vec<u64> = (0..simulation.receivers.len())
        .map(|_| 40 + (rng.uniform() * 210.0) as u64)
        .collect();
    let index_of: std::collections::BTreeMap<_, usize> = simulation
        .receivers
        .iter()
        .enumerate()
        .map(|(index, receiver)| (receiver.key, index))
        .collect();
    let times: Vec<f64> = simulation
        .sources
        .iter()
        .map(|source| simulation.transmissions[*source].time)
        .collect();
    for (reception, time) in simulation.receptions.iter_mut().zip(times) {
        let Some(index) = index_of.get(&reception.receiver) else {
            continue;
        };
        // The first seal after the reception: whole seconds plus the receiver's phase.
        let heard_ms = (time.max(0.0) * 1000.0) as u64;
        let phase = phases[*index];
        let seconds = (heard_ms + 1000 - phase) / 1000;
        reception.wall_ms = start_ms + seconds * 1000 + phase;
    }
    let feeds = simulation.feeds().map_err(|error| error.to_string())?;
    let mut out = Vec::new();
    for (index, feed) in feeds.iter().enumerate() {
        out.push((start_ms, Record::ReceiverInfo(feed.info.clone())));
        for batch in &feed.batches {
            let wall = batch.content().map_err(|error| error.to_string())?.wall_ms;
            let jitter = (rng.uniform() * 30.0) as u64;
            out.push((wall + delays[index] + jitter, Record::Batch(batch.clone())));
        }
    }
    out.sort_by_key(|(at, _)| *at);
    Ok(out)
}

/// What orders two descriptions taking effect at one step after their stamps: the receiver's key,
/// then the bytes (a relay applies them in the same order).
fn description_key(record: &Record) -> (Vec<u8>, Vec<u8>) {
    match record {
        Record::ReceiverInfo(info) => (
            info.receiver()
                .map(|key| key.as_bytes().to_vec())
                .unwrap_or_default(),
            info.as_bytes().to_vec(),
        ),
        _ => (Vec::new(), Vec::new()),
    }
}

/// `delivered` (`arrivals` of `simulation`) with two receivers' descriptions moved midway, for a
/// test that descriptions take effect where their stamps say: the first receiver described again
/// out of every area (its location moved 20 degrees north) a third of the way in and back ten
/// seconds later, so it stops taking part and takes part again; and the second described first
/// halfway in, so its batches before wait for it and those that waited too long are let go. In
/// arrival order.
pub fn described_midway(
    simulation: &Simulation,
    delivered: &[(u64, Record)],
) -> Result<Vec<(u64, Record)>, String> {
    let feeds = simulation.feeds().map_err(|error| error.to_string())?;
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let last = delivered.last().map_or(0, |(at, _)| *at);
    let third = first + (last - first) / 3;
    let half = first + (last - first) / 2;
    let [moved, late, ..] = feeds.as_slice() else {
        return Err("fewer than two receivers".to_owned());
    };
    let late_key = late.identity.public();
    let mut changed: Vec<(u64, Record)> = delivered
        .iter()
        .filter(|(_, record)| {
            !matches!(record, Record::ReceiverInfo(info) if info.receiver().ok() == Some(late_key))
        })
        .cloned()
        .collect();
    let content = moved.info.content().map_err(|error| error.to_string())?;
    let away = tally_wire::batch::ReceiverInfoContent {
        issued_ms: content.issued_ms + 1,
        location: content.location.map(|location| tally_wire::Location {
            lat_e7: location.lat_e7.saturating_add(200_000_000),
            ..location
        }),
        ..content.clone()
    };
    let back = tally_wire::batch::ReceiverInfoContent {
        issued_ms: content.issued_ms + 2,
        ..content
    };
    for (at, content) in [(third, away), (third + 10_000, back)] {
        let info = tally_wire::ReceiverInfo::sign(&moved.identity, &content)
            .map_err(|error| error.to_string())?;
        changed.push((at, Record::ReceiverInfo(info)));
    }
    changed.push((half, Record::ReceiverInfo(late.info.clone())));
    changed.sort_by_key(|(at, _)| *at);
    Ok(changed)
}

/// The unix milliseconds of a simulated transmission.
pub fn transmitted_ms(simulation: &Simulation, source: usize) -> u64 {
    let start_ms =
        simulation.scenario.midnight_unix_ms + (simulation.scenario.start_tod_s * 1000.0) as u64;
    start_ms + (simulation.transmissions[source].time.max(0.0) * 1000.0) as u64
}

/// Drives `engine` over `arrivals` on the steps from the first arrival to `until_ms` (module docs):
/// every multiple of `tick_ms` after the first arrival, each taking what arrived before it. Every
/// record it published, with its step.
pub fn replay(
    engine: &mut Engine,
    arrivals: &[(u64, Record)],
    tick_ms: u64,
    until_ms: u64,
) -> Result<Vec<(u64, Record)>, String> {
    let Some(first) = arrivals.first().map(|(at, _)| *at) else {
        return Ok(Vec::new());
    };
    let tick_ms = tick_ms.max(1);
    let mut next = 0;
    let mut published = Vec::new();
    let mut now = (first / tick_ms + 1) * tick_ms;
    let mut descriptions: Vec<(u64, &Record)> = Vec::new();
    while now <= until_ms {
        while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at < now) {
            if matches!(record, Record::ReceiverInfo(_)) {
                descriptions.push((*at, record));
            } else {
                engine.ingest(record, *at)?;
            }
            next += 1;
        }
        engine.expire_orphans(now);
        descriptions.sort_by_cached_key(|(at, record)| (*at, description_key(record)));
        for (at, record) in descriptions.drain(..) {
            engine.ingest(record, at)?;
        }
        for record in engine.provisional_step(now, now) {
            published.push((now, record));
        }
        let (records, _) = engine.step(now, now);
        published.extend(records.into_iter().map(|record| (now, record)));
        now += tick_ms;
    }
    Ok(published)
}

/// A simulator scenario long enough for windows to publish models and provisionals to be carried
/// under them: the default region, more Mode S-only aircraft (the targets), `duration_s` long.
pub fn scenario(seed: u64, duration_s: f64) -> sim::Scenario {
    sim::Scenario {
        duration_s,
        modes_aircraft: 12,
        ..sim::Scenario::new(seed)
    }
}
