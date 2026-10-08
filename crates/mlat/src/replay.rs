//! An engine driven over the simulator on a virtual clock, as a relay's hosted MLAT
//! (`tally_relay::mlat_host`) drives it on the real one: what the latency of provisional positions and their supersession by final ones are
//! measured with (here and in `tally-merge`'s tests).
//!
//! - **Feeders as they are** (`arrivals`): each simulated receiver seals a batch once a second, at
//!   a phase of its own (tally-feed's `SEAL_EVERY`; the simulator's own batches all seal on the
//!   whole second, which would make every reception of a transmission arrive together), and each
//!   batch reaches the engine after a delay of its receiver's path (40 to 250 ms) and a little
//!   jitter.
//! - **The engine as it runs** (`replay`): every `tick_ms` of the virtual clock, what has arrived
//!   is ingested, provisional work is solved and published, and a due window is stepped. Each
//!   record published is returned with the clock it was published at. The relay runs the two
//!   off the ingesting thread; here they run in line, which only makes them faster.

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

/// The unix milliseconds of a simulated transmission.
pub fn transmitted_ms(simulation: &Simulation, source: usize) -> u64 {
    let start_ms =
        simulation.scenario.midnight_unix_ms + (simulation.scenario.start_tod_s * 1000.0) as u64;
    start_ms + (simulation.transmissions[source].time.max(0.0) * 1000.0) as u64
}

/// Drives `engine` over `arrivals` from the first to `until_ms` (module docs). Every record it
/// published, with when.
pub fn replay(
    engine: &mut Engine,
    arrivals: &[(u64, Record)],
    tick_ms: u64,
    until_ms: u64,
) -> Result<Vec<(u64, Record)>, String> {
    let Some(first) = arrivals.first().map(|(at, _)| *at) else {
        return Ok(Vec::new());
    };
    let mut next = 0;
    let mut published = Vec::new();
    let mut now = first;
    while now <= until_ms {
        while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at <= now) {
            engine.ingest(record, *at)?;
            next += 1;
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
