//! An engine driven over the simulator on a virtual clock, as a relay's hosted MLAT
//! (`tally_relay::mlat_host`) drives it on the real one: what the latency of fixes, and how a late
//! reception's bigger set follows, are measured with (here and in `tally-merge`'s tests).
//!
//! - **Feeders as they are** (`tally_mlat_solver::sim::arrived_records`): each simulated receiver
//!   seals a batch once a second, at a phase of its own, and each batch reaches the engine after a
//!   delay of its receiver's path (40 to 250 ms) and a little jitter.
//! - **The engine as it runs** ([`replay`]): at every multiple of [`STEP_MS`] of the virtual clock
//!   (a step), what arrived before it is ingested and the engine steps. A receiver's site
//!   (`intake::SiteRecord`) takes effect at the step after it arrived, as a relay's does
//!   (`tally_relay::mlat_host`, sites stamped and applied at their step); its format 2
//!   description, which carries no site, places nothing, and a batch that arrived before its
//!   receiver's site took effect is held until it does (`intake` module docs). Each step that
//!   published anything is returned with
//!   its time. These are the hosted MLAT's steps, so this is the reference the relay is held to
//!   byte for byte.

use tally_mlat_solver::sim::{self, Simulation};
use tally_wire::clocks::recorded::aligned;
use tally_wire::{Record, Signer};

use crate::engine::{Engine, STEP_MS, Step};
use crate::intake::SiteRecord;

/// When a record a receiver sent reaches an engine at the soonest, by the engine's clock: a batch
/// when its receiver sealed it (its own wall clock), a description at once. For a test that hands
/// an engine every record at once: the pool refuses raw signed too far past its arrival
/// (`tally_mlat_solver::arrived::AHEAD_MS`), so none is handed raw from the future.
pub fn sent_ms(record: &Record) -> u64 {
    match record {
        Record::Batch(batch) => batch.content().map_or(0, |content| content.wall_ms),
        _ => 0,
    }
}

/// `delivered` (`sim::arrived_records` of `simulation`) with two receivers' sites moved midway,
/// for a test that sites take effect where their stamps say: the first receiver's site signed
/// again out of every area (moved 20 degrees north) a third of the way in and back ten seconds
/// later, so it stops taking part and takes part again; and the second's site first sent halfway
/// in, so its batches before are held and it takes part from then. In arrival order.
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
            !matches!(record, Record::ReceiverSite(site) if site.receiver().ok() == Some(late_key))
        })
        .cloned()
        .collect();
    let content = moved.site.content().map_err(|error| error.to_string())?;
    let away = tally_wire::ReceiverSiteContent {
        issued_ms: content.issued_ms + 1,
        location: tally_wire::Location {
            lat_e7: content.location.lat_e7.saturating_add(200_000_000),
            ..content.location
        },
        ..content
    };
    let back = tally_wire::ReceiverSiteContent {
        issued_ms: content.issued_ms + 2,
        ..content
    };
    for (at, content) in [(third, away), (third + 10_000, back)] {
        let site = tally_wire::ReceiverSite::sign(&moved.identity, &content)
            .map_err(|error| error.to_string())?;
        changed.push((at, Record::ReceiverSite(site)));
    }
    changed.push((half, Record::ReceiverSite(late.site.clone())));
    changed.sort_by_key(|(at, _)| *at);
    Ok(changed)
}

/// The unix milliseconds of a simulated transmission.
pub fn transmitted_ms(simulation: &Simulation, source: usize) -> u64 {
    simulation.scenario.start_ms()
        + (simulation.transmissions[source].time.max(0.0) * 1000.0) as u64
}

/// Drives `engine` over `arrivals` on the steps from the first arrival to `until_ms` (module docs):
/// every multiple of `STEP_MS` after the first arrival, each taking what arrived before it and
/// signing with `signer`. Every step that published anything, with its time. A replay's clock
/// never steps, so each instant reads alike on both clocks (`tally_wire::clocks::recorded::aligned`).
pub fn replay(
    engine: &mut Engine,
    arrivals: &[(u64, Record)],
    signer: &Signer,
    until_ms: u64,
) -> Result<Vec<(u64, Step)>, String> {
    replay_with(engine, arrivals, signer, until_ms, |_, _| {})
}

/// [`replay`], with `before` handed the engine and the step's time just before each step, after
/// what arrived before it was ingested: what a host hands its engine at a step besides the raw
/// (`tally_relay::mlat_host`: the neighbouring areas' models, `Engine::hold`).
#[allow(clippy::disallowed_methods, reason = "a replay's instants")]
pub fn replay_with(
    engine: &mut Engine,
    arrivals: &[(u64, Record)],
    signer: &Signer,
    until_ms: u64,
    mut before: impl FnMut(&mut Engine, u64),
) -> Result<Vec<(u64, Step)>, String> {
    let Some(first) = arrivals.first().map(|(at, _)| *at) else {
        return Ok(Vec::new());
    };
    let mut next = 0;
    let mut published = Vec::new();
    let mut now = (first / STEP_MS + 1) * STEP_MS;
    let mut descriptions: Vec<(u64, SiteRecord)> = Vec::new();
    while now <= until_ms {
        while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at < now) {
            match SiteRecord::of(record) {
                Some(site) => descriptions.push((*at, site)),
                // A format 2 description carries no site: nothing to take effect.
                None if matches!(record, Record::ReceiverInfo(_)) => {}
                None => {
                    engine.ingest_record(record, aligned(*at))?;
                }
            }
            next += 1;
        }
        for (at, site) in crate::intake::taking_effect(descriptions.drain(..)) {
            engine.ingest_record(&site.record(), aligned(at))?;
        }
        before(engine, now);
        let step = engine.step(aligned(now), signer);
        if !step.models.is_empty() || !step.fixes.is_empty() {
            published.push((now, step));
        }
        now += STEP_MS;
    }
    Ok(published)
}

/// A simulator scenario long enough for trailing windows to fill and targets to be solved: the
/// default region, more Mode S-only aircraft (the targets), `duration_s` long.
pub fn scenario(seed: u64, duration_s: f64) -> sim::Scenario {
    sim::Scenario {
        duration_s,
        modes_aircraft: 12,
        ..sim::Scenario::new(seed)
    }
}
