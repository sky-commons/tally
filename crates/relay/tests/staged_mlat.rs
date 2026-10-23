//! The hosted MLAT's invariants on the staged relay's own threads (RFC-0181, "Invariants the tests
//! hold", 1 to 3 and 7): the relay holds MLAT's raw once, in its raw shards, taken there by the
//! ingest workers and sealed from them, and its provisional state in address shards; the host steps
//! by the stamp watermark the products seal by, asked as the network task asks it, on a thread of
//! its own, never waited on step by step, only kept within its limits of the watermark
//! (`PROVISIONAL_BEHIND` and `WINDOW_STEPS_BEHIND`), past which a host sheds whole steps (`mlat_host`, Behind: what a host that cannot keep up does,
//! counted, and asserted here never to happen). The same stamped trace makes the same clock models,
//! positions and provisional positions, byte for byte, on 1, 2 and 8 ingest workers and as many MLAT
//! threads, with delays injected inside every stage of the host and between the batches, and they
//! are what the reference engine, holding all the raw itself and driven in line on the same steps,
//! makes of it (`tally_mlat::replay`). At capacity the same receivers are refused, whole, whatever
//! the order the descriptions came in and however they raced.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tally_wire::clocks::recorded::judged;

use tally_relay::hub::{Description, Hub, Inbound, Origin};
use tally_relay::ingest::{Stamp, Threads};
use tally_relay::mlat_host::{
    Cut, HostedMlat, MlatHost, MlatReport, PROVISIONAL_BEHIND, STEP_MS, Stage, WINDOW_STEPS_BEHIND,
    WindowClock,
};
use tally_wire::{Identity, Location, PublicKey, ReceiverInfo, Record, Region, Regions};

/// `delivered` with each site that moves its receiver out of the public cell its description
/// names followed, at its stamp, by the description its feeder reissues with it (format 2, the new
/// cell): a relay pairs a site only with a description whose public cell holds it
/// (`Hub::keep_site`), as a moved feeder signs both. A reference engine places receivers by their
/// sites alone, so the descriptions change nothing it does.
fn reissued(
    simulation: &tally_mlat_solver::sim::Simulation,
    delivered: &[(u64, Record)],
) -> Result<Vec<(u64, Record)>> {
    let feeds = simulation.feeds().map_err(text)?;
    let mut named: std::collections::HashMap<PublicKey, tally_wire::PublicInfoContent> =
        std::collections::HashMap::new();
    let mut out = Vec::with_capacity(delivered.len());
    for (at, record) in delivered {
        out.push((*at, record.clone()));
        match record {
            Record::ReceiverInfo(info) => {
                named.insert(info.receiver().map_err(text)?, info.public().map_err(text)?);
            }
            Record::ReceiverSite(site) => {
                let receiver = site.receiver().map_err(text)?;
                let content = site.content().map_err(text)?;
                let Some(held) = named.get(&receiver) else {
                    continue;
                };
                if held.holds(&content.location) {
                    continue;
                }
                let identity = &feeds
                    .iter()
                    .find(|feed| feed.identity.public() == receiver)
                    .ok_or("a site of no feed")?
                    .identity;
                let renamed = tally_wire::PublicInfoContent {
                    issued_ms: content.issued_ms,
                    cell: Some(Region::public_cell(&content.location).map_err(text)?),
                    ..held.clone()
                };
                let info = ReceiverInfo::sign_public(identity, &renamed).map_err(text)?;
                named.insert(receiver, renamed);
                out.push((*at, Record::ReceiverInfo(info)));
            }
            _ => {}
        }
    }
    Ok(out)
}

/// What a description declares: when it was issued and, a format 1 one, its site (a format 2
/// one's site comes apart, as a `ReceiverSite`).
fn declared(info: &ReceiverInfo) -> Result<(u64, Option<Location>)> {
    Ok(match info.description().map_err(text)? {
        tally_wire::Description::Public(content) => (content.issued_ms, None),
        tally_wire::Description::Site(content) => (content.issued_ms, content.location),
    })
}

type Result<T = ()> = std::result::Result<T, String>;

/// The same key again, from its file form, for a test that hands a key over and still signs or
/// dials as it: `Identity` is not `Clone`.
fn twin(identity: &Identity) -> Result<Identity> {
    Identity::from_base64(&identity.to_base64()).map_err(|error| error.to_string())
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// The areas within about 150 km of the simulator's centre, where its receivers and aircraft are.
fn mlat_areas() -> Result<Regions> {
    let (lat, lon) = tally_mlat_solver::sim::CENTRE;
    let mut areas = Vec::new();
    for north in -2..=2 {
        for east in -2..=2 {
            let location = Location {
                lat_e7: ((lat + f64::from(north) * 0.6) * 1e7) as i32,
                lon_e7: ((lon + f64::from(east) * 1.0) * 1e7) as i32,
                alt_m: 0,
                precision_m: 0,
            };
            let area = Region::containing(&location, tally_wire::rendezvous::AREA_RESOLUTION)
                .map_err(text)?;
            areas.push(area);
        }
    }
    Ok(Regions::new(areas))
}

const MLAT_BOOT: u64 = 0xb007;

fn mlat_settings(threads: usize) -> tally_mlat::engine::Settings {
    tally_mlat::engine::Settings {
        regions: Regions::default(),
        settle: tally_relay::mlat_host::SETTLE,
        threads,
        capacity: tally_mlat::engine::Capacity::default(),
    }
}

/// How the receivers' descriptions before the first batch reach a relay in `mlat_run_with` (those
/// after it reach the host at their stamps, as the relay stamps them).
#[derive(Clone, Copy, Debug)]
enum Describing {
    /// In the trace's order, or reversed.
    Before { reversed: bool },
    /// From several threads at once, each pausing pseudorandomly between them: an interleaving
    /// nobody chose.
    Racing { seed: u64 },
}

/// Hands every description and site of `arrivals` that comes before the first batch to `hub` as
/// `describing` says (the rest come at their stamps, `mlat_run_with`): a site and its description
/// pair in whichever order they come.
fn describe_all(hub: &Arc<Hub>, arrivals: &[(u64, Record)], describing: Describing) -> Result {
    let mut infos: Vec<Record> = arrivals
        .iter()
        .take_while(|(_, record)| !matches!(record, Record::Batch(_)))
        .filter(|(_, record)| matches!(record, Record::ReceiverInfo(_) | Record::ReceiverSite(_)))
        .map(|(_, record)| record.clone())
        .collect();
    let publish = |hub: &Hub, record: &Record| -> Result {
        match record {
            Record::ReceiverInfo(info) => {
                let (issued_ms, place) = declared(info)?;
                hub.publish_info(
                    1,
                    info.clone(),
                    info.receiver().map_err(text)?,
                    issued_ms,
                    place,
                    true,
                );
            }
            Record::ReceiverSite(site) => {
                hub.publish_site(1, site.clone());
            }
            _ => {}
        }
        Ok(())
    };
    match describing {
        Describing::Before { reversed } => {
            if reversed {
                infos.reverse();
            }
            for info in &infos {
                publish(hub, info)?;
            }
        }
        Describing::Racing { seed } => {
            const RACERS: usize = 4;
            std::thread::scope(|scope| -> Result {
                let handles: Vec<_> = (0..RACERS)
                    .map(|racer| {
                        let infos = &infos;
                        let publish = &publish;
                        scope.spawn(move || -> Result {
                            for (n, info) in infos.iter().enumerate().skip(racer).step_by(RACERS) {
                                let pause = (n as u64 ^ seed).wrapping_mul(2_654_435_761) % 700;
                                std::thread::sleep(Duration::from_micros(pause));
                                publish(hub, info)?;
                            }
                            Ok(())
                        })
                    })
                    .collect();
                for handle in handles {
                    handle.join().map_err(|_| "a racer panicked".to_owned())??;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

/// A pseudorandom pause of up to `most` microseconds, the `n`th of `seed`'s.
fn pause(seed: u64, n: u64, most: u64) -> Duration {
    let mixed = (n ^ seed.rotate_left(17))
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .rotate_left(29);
    Duration::from_micros(mixed % most.max(1))
}

/// Delays injected inside the host (`HostedMlat::delaying`) and between the batches handed in:
/// none, pseudorandom ones from a seed, or every window step that solves something held `held_ms`
/// while the watermark runs up to `behind` steps past the last window step that reported.
#[derive(Clone, Copy, Debug)]
enum Delays {
    None,
    Seeded(u64),
    Windows { held_ms: u64, behind: u64 },
}

/// What a staged relay on `threads` hosting MLAT for `areas` (on `settings`) signs from `arrivals`,
/// on the real concurrent path: the descriptions handed in as `describing` says, then each step's
/// batches (each stamped when it arrived) handed to the ingest workers and every worker ticked to
/// the step, never waiting for them, only for the host to be within its limits of the next
/// (`PROVISIONAL_BEHIND`, `WINDOW_STEPS_BEHIND`; a host further behind sheds, which a relay's real-time watermark gives it the seconds
/// not to); meanwhile another thread asks the host with the products' watermark as the network
/// task does, never waiting for it either. Only at the end is the host waited on, once. Its records, provisional ones apart from the rest, each encoded in order; its
/// report; and the receivers whose raw it held.
fn mlat_run_with(
    arrivals: &[(u64, Record)],
    areas: &Regions,
    threads: Threads,
    settings: tally_mlat::engine::Settings,
    describing: Describing,
    delays: Delays,
) -> Result<(Signed, MlatReport, Vec<PublicKey>)> {
    let run = mlat_run_cuts(
        arrivals,
        areas,
        threads,
        settings,
        describing,
        delays,
        Cutting::default(),
    )?;
    Ok((run.signed, run.report, run.held))
}

/// An overloaded host's window steps: each declares it ran 600 ms against a budget of 200, so
/// every judgment is overload, the same however fast the machine running the test is.
const OVERLOADED: WindowClock = WindowClock::Declared {
    ran_ms: 600,
    budget_ms: 200,
};

/// What a run of `mlat_run_cuts` is given to cut by: what its window steps declare they ran
/// against what budget (none: a host that keeps up, `WindowClock::KEEPING_UP`), and the cuts other
/// relays published, offered before the first step.
#[derive(Clone, Debug, Default)]
struct Cutting {
    window_clock: Option<WindowClock>,
    offered: Vec<Cut>,
    /// The relays' network: this relay's key and the one other relay holding its areas, and the
    /// records that relay addressed this one, handed to the duties as a link hands them
    /// (`Network::handle`) before the first step.
    network: Option<Neighbours>,
}

/// Two relays holding every area of the trace, each with the other's verified offer.
#[derive(Clone, Debug)]
struct Neighbours {
    me: Arc<Identity>,
    other: Arc<Identity>,
    carried: Vec<Record>,
}

/// Makes `hub` a relay `me` that takes `areas` and holds the verified offers of `me` and `other`
/// for each, the choice and the raw links that make `other` an area's neighbour
/// (`Selection::raw_sources`).
fn neighbouring(hub: &Hub, me: &Identity, other: &Identity, areas: &Regions, now: u64) -> Result {
    use tally_relay::directory::Group;
    use tally_wire::{ProviderOffer, ProviderOfferContent, Streams};
    let network = hub.network();
    network.adopt_identity(twin(me)?);
    network.directory.adopt_own_key(me.public());
    network.selection.set_taken(areas.cells().to_vec());
    for (group, relay) in [me, other].into_iter().enumerate() {
        for cell in areas.cells() {
            let offer = ProviderOffer::sign(
                relay,
                &ProviderOfferContent {
                    address: format!("{}:7450", relay.public().to_base64url()),
                    cell: *cell,
                    products: Streams::RAW,
                    stripes_of: 1,
                    stripes: 1,
                    mlat_cores: 8,
                    feeder_slots: 10,
                    network: 1 + group as u32,
                    issued_ms: now,
                    expires_ms: now + 600_000,
                },
            )
            .map_err(text)?;
            network
                .directory
                .hold_verified(offer, Group::V4(group as u16), judged(now))?;
        }
    }
    Ok(())
}

/// A run's records, report, the receivers whose raw it held, and the cuts it decided.
struct Run {
    signed: Signed,
    report: MlatReport,
    held: Vec<PublicKey>,
    cuts: Vec<Cut>,
    /// The cuts as the relay addressed them to its neighbour (`Network::publish_cuts`), signed.
    sent: Vec<Record>,
    /// Cuts the relay took from its neighbour and refused (`Network::cuts`).
    network_cuts: (u64, u64, u64),
}

/// As `mlat_run_with`, under `cutting`.
#[allow(clippy::too_many_arguments)]
fn mlat_run_cuts(
    arrivals: &[(u64, Record)],
    areas: &Regions,
    threads: Threads,
    settings: tally_mlat::engine::Settings,
    describing: Describing,
    delays: Delays,
    cutting: Cutting,
) -> Result<Run> {
    // It takes the areas it solves, as a relay hosting MLAT for them does, so its budget plans
    // the member sessions they bring and what sharing holds and addresses them
    // (`Store::Batches`, planned only beside members): an overload cut is addressed to a raw
    // source through it. Untaken, the store was planned nothing and held one cut at a time.
    let hub = Arc::new(
        Hub::clocked(8, Arc::new(|| 0), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .taking(areas.cells().to_vec())
            .staged(threads)?,
    );
    let host = Arc::new(HostedMlat::new(
        tally_wire::Signer::new(Identity::from_seed([5; 32]), std::sync::Arc::new(|| true)),
        MLAT_BOOT,
        settings,
        cutting.window_clock.unwrap_or(WindowClock::KEEPING_UP),
    )?);
    match delays {
        Delays::Seeded(seed) => {
            let count = Arc::new(AtomicU64::new(0));
            host.delaying(Arc::new(move |stage: Stage| {
                let n = count.fetch_add(1, Ordering::Relaxed);
                let most = match stage {
                    // An ingest worker held up on its way to the host (the message exchange
                    // pushing back on `route`).
                    Stage::Offer => 400,
                    // Each address shard a provisional step reads, holding it: many a step.
                    Stage::Reading => 200,
                    _ => 30_000,
                };
                std::thread::sleep(pause(seed, n, most));
            }));
        }
        Delays::Windows { held_ms, .. } => {
            host.delaying(Arc::new(move |stage: Stage| {
                if stage == Stage::Window {
                    std::thread::sleep(Duration::from_millis(held_ms));
                }
            }));
        }
        Delays::None => {}
    }
    // The cuts other relays published, offered as the stamps reach the step `CUT_LEAD_STEPS` before
    // each: as a link hands them in, never all at once before the first step.
    let mut offered: Vec<Cut> = cutting.offered.clone();
    offered.sort_by_key(|cut| cut.from_ms);
    let mut offered = std::collections::VecDeque::from(offered);
    hub.network()
        .host_mlat(Arc::clone(&host) as Arc<dyn MlatHost>);
    host.set_areas(areas.clone(), Vec::new());
    let now = tally_relay::clock::RelayClock::system().judged().ms();
    let mut carried: std::collections::VecDeque<(u64, Record)> = Default::default();
    let mut link = None;
    if let Some(neighbours) = &cutting.network {
        neighbouring(&hub, &neighbours.me, &neighbours.other, areas, now)?;
        let asker = tally_relay::network::Asker {
            role: tally_relay::network::AskerRole::Relay,
            key: neighbours.other.public(),
            source: 77,
            loopback: true,
            address: None,
        };
        carried = neighbours
            .carried
            .iter()
            .map(|record| {
                let from_ms = match record {
                    Record::MlatCut(cut) => {
                        cut.content().map(|content| content.from_ms).unwrap_or(0)
                    }
                    _ => 0,
                };
                (from_ms, record.clone())
            })
            .collect();
        carried
            .make_contiguous()
            .sort_by_key(|(from_ms, _)| *from_ms);
        link = Some(asker);
    }
    describe_all(&hub, arrivals, describing)?;
    let first = arrivals.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = arrivals.last().map_or(0, |(at, _)| *at) + 60_000;
    let last_step = until / STEP_MS * STEP_MS;
    let published: Mutex<Vec<Record>> = Mutex::new(Vec::new());
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| -> Result {
        // The network task's ask: the products' watermark, as it stands, every few milliseconds.
        let asker = scope.spawn(|| {
            let mut n = 0;
            while !done.load(Ordering::SeqCst) {
                let records = host.take_published(hub.network().products.watermark());
                if let Ok(mut published) = published.lock() {
                    published.extend(records);
                }
                n += 1;
                let most = match delays {
                    Delays::None | Delays::Windows { .. } => 2_000,
                    Delays::Seeded(seed) => 2_000 + pause(seed, n, 8_000).as_micros() as u64,
                };
                std::thread::sleep(Duration::from_micros(most));
            }
        });
        let mut next = 0;
        let mut step = (first / STEP_MS + 1) * STEP_MS;
        // The host's tighter limit: its provisional steps' (`PROVISIONAL_BEHIND`, below
        // `WINDOW_STEPS_BEHIND`). A step handed in once every part of the one this many steps before it
        // has reported finds at most that many not started behind the one running, so nothing is
        // shed.
        let ahead = (PROVISIONAL_BEHIND as u64 + 1) * STEP_MS;
        // Window steps may fall further behind when a test says so (`Delays::Windows`).
        let windows_ahead = match delays {
            Delays::Windows { behind, .. } => behind * STEP_MS,
            _ => ahead,
        };
        let base = first / STEP_MS * STEP_MS;
        let since = Instant::now();
        while step <= until {
            // Within the host's limits (`PROVISIONAL_BEHIND` steps, the tighter, and
            // `WINDOW_STEPS_BEHIND`), as a real-time watermark keeps it; and what it signed taken by the
            // asker before the watermark moves on a step, as a real-time watermark moves a tenth
            // of a step between the network task's asks (a provisional step's records taken past
            // `PROVISIONAL_PUBLISH_MS` after it are late by the stamps, and refused).
            while step > host.provisionals_stepped_ms().max(base) + ahead
                || step > host.windows_stepped_ms().max(base) + windows_ahead
                || host.untaken() > 0
            {
                if since.elapsed() > Duration::from_secs(300) {
                    return Err(format!(
                        "the hosted MLAT stepped to {}, {step} handed in",
                        host.stepped_ms()
                    ));
                }
                std::thread::sleep(Duration::from_micros(200));
            }
            while let Some((at, record)) = arrivals.get(next).filter(|(at, _)| *at < step) {
                // A description after the first batch, stamped when it came, handed in as a link
                // hands one in: through the ingest stage, on its receiver's worker among its
                // batches, stamped there (`Hub::describe`); it takes effect at its step.
                if let Record::ReceiverInfo(info) = record
                    && next > 0
                    && arrivals[..next]
                        .iter()
                        .any(|(_, record)| matches!(record, Record::Batch(_)))
                {
                    if let Delays::Seeded(seed) = delays {
                        std::thread::sleep(pause(seed, next as u64, 200));
                    }
                    let (issued_ms, place) = declared(info)?;
                    hub.describe(Description {
                        source: 2,
                        info: info.clone(),
                        receiver: info.receiver().map_err(text)?,
                        issued_ms,
                        place,
                        publishing: false,
                        stamp: Some(Stamp::recorded(*at, next as u64, *at, *at, true)),
                        in_flight: hub.in_flight_of(info.as_bytes().len()),
                    });
                }
                // A site after the first batch, likewise: it takes effect at its step.
                if let Record::ReceiverSite(site) = record
                    && next > 0
                    && arrivals[..next]
                        .iter()
                        .any(|(_, record)| matches!(record, Record::Batch(_)))
                {
                    if let Delays::Seeded(seed) = delays {
                        std::thread::sleep(pause(seed, next as u64, 200));
                    }
                    hub.keep_site(
                        2,
                        site.clone(),
                        site.receiver().map_err(text)?,
                        Some(Stamp::recorded(*at, next as u64, *at, *at, true)),
                        hub.in_flight_of(site.as_bytes().len()),
                    );
                }
                if let Record::Batch(batch) = record {
                    if let Delays::Seeded(seed) = delays {
                        std::thread::sleep(pause(seed, next as u64, 200));
                    }
                    let in_flight = hub.in_flight_for(batch);
                    hub.ingest(Inbound {
                        source: 2,
                        batch: batch.clone(),
                        origin: Origin::Elsewhere,
                        verify: true,
                        stamp: Some(Stamp::recorded(*at, next as u64, *at, *at, true)),
                        arrived: None,
                        in_flight,
                        refusal: None,
                    });
                }
                next += 1;
            }
            // The cuts other relays published, as their step comes within `CUT_LEAD_STEPS`.
            let lead = tally_relay::mlat_host::CUT_LEAD_STEPS * STEP_MS;
            while offered
                .front()
                .is_some_and(|cut| cut.from_ms <= step + lead)
            {
                if let Some(cut) = offered.pop_front() {
                    host.offer_cut(cut);
                }
            }
            while carried
                .front()
                .is_some_and(|(from_ms, _)| *from_ms <= step + lead)
            {
                if let (Some((_, record)), Some(asker)) = (carried.pop_front(), &link) {
                    // One clock in this test: what it judges by is what it keeps by.
                    let at = tally_relay::sharing::Now::from(tally_relay::ingest::Stamp::recorded(
                        now, 0, now, now, true,
                    ));
                    hub.network().handle(&hub, asker, record, at, None);
                }
            }
            // Everything stamped before the step is handed in: every worker ticks to it.
            hub.advance(step);
            step += STEP_MS;
        }
        let started = Instant::now();
        let mut failed = None;
        while host.stepped_ms() < last_step || host.in_flight() > 0 {
            if started.elapsed() > Duration::from_secs(300) {
                failed = Some(format!(
                    "the hosted MLAT stepped to {} of {last_step}; the products' watermark is {}",
                    host.stepped_ms(),
                    hub.network().products.watermark_ms()
                ));
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        done.store(true, Ordering::SeqCst);
        asker.join().map_err(|_| "the asker panicked".to_owned())?;
        failed.map_or(Ok(()), Err)
    })?;
    let mut published = published.into_inner().map_err(text)?;
    published.extend(host.take_signed());
    // The receivers whose raw the engine held, by the sealed bins it kept.
    let sealed = host.sealed_bins().ok_or("no sealed bins")?;
    let mut held: Vec<PublicKey> = sealed
        .bins(i64::MIN, i64::MAX)
        .iter()
        .flat_map(|bin| bin.receivers.clone())
        .collect();
    held.sort_unstable();
    held.dedup();
    let cuts = host.take_cuts();
    let mut sent = Vec::new();
    if cutting.network.is_some() {
        hub.network().publish_cuts(
            cuts.clone(),
            tally_relay::strikes::Now::from(hub.clock().stamp(0)),
        );
        sent = hub
            .network()
            .sharing
            .take_outbox()
            .into_iter()
            .map(|addressed| addressed.record)
            .collect();
    }
    Ok(Run {
        signed: encoded(&published),
        report: host.report(),
        held,
        cuts,
        sent,
        network_cuts: hub.network().cuts(),
    })
}

/// Records as bytes, in order: provisional positions, and the rest.
type Signed = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Each record's bytes, provisional positions apart from the rest, each in order.
fn encoded(records: &[Record]) -> Signed {
    let mut provisional = Vec::new();
    let mut rest = Vec::new();
    for record in records {
        let mut bytes = Vec::new();
        if record.encode(&mut bytes).is_err() {
            continue;
        }
        if matches!(record, Record::Provisional(_)) {
            provisional.push(bytes);
        } else {
            rest.push(bytes);
        }
    }
    (provisional, rest)
}

/// RFC-0181 §3, §4, §5 and invariants 1 to 3: the same stamped trace makes the same clock models,
/// positions and provisional positions, byte for byte, on 1, 2 and 8 ingest workers and as many
/// MLAT threads, with and without delays injected inside every stage of the host (an offer held up
/// on its way, a provisional step, a seal and a window step each slowed by up to 30 ms) and between
/// the batches, the host asked by the watermark on a thread of its own and never waited on step by
/// step (only kept within its limits of it); and they are what the reference engine makes of
/// the same raw on the same steps (`tally_mlat::replay`). Nothing is refused, shed or let go on the
/// way.
#[test]
fn hosted_mlat_makes_the_same_bytes_on_any_threads_with_any_delays_and_the_reference_engines()
-> Result {
    use tally_mlat::replay::{arrivals, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    let run = |ingest: usize, message: usize, delays: Delays| -> Result<Signed> {
        let (signed, report, _) = mlat_run_with(
            &delivered,
            &areas,
            Threads {
                ingest,
                message,
                seal: message,
            },
            mlat_settings(ingest),
            Describing::Before { reversed: false },
            delays,
        )?;
        assert_eq!(
            (
                report.refused,
                report.overflowed,
                report.steps_discarded,
                report.ingest_errors,
                report.steps_shed,
                report.provisional_steps_shed,
                report.shed,
                report.provisional_models_late,
                report.waiting_dropped
            ),
            (0, 0, 0, 0, 0, 0, 0, 0, 0),
            "{ingest} threads, {delays:?}: {report:?}"
        );
        Ok(signed)
    };
    let one = run(1, 1, Delays::None)?;
    assert!(!one.0.is_empty(), "no provisional positions");
    let positions = one
        .1
        .iter()
        .filter_map(|bytes| Record::decode(bytes).ok().and_then(|(record, _)| record))
        .filter(|record| matches!(record, Record::Positions(_)))
        .count();
    assert!(positions > 0, "no positions");
    for (ingest, message, delays) in [
        (2, 2, Delays::None),
        (8, 8, Delays::None),
        (8, 3, Delays::None),
        (1, 1, Delays::Seeded(1)),
        (2, 2, Delays::Seeded(2)),
        (8, 8, Delays::Seeded(3)),
    ] {
        let many = run(ingest, message, delays)?;
        assert_eq!(
            one.1, many.1,
            "{ingest} ingest threads, {delays:?}: models and positions differ"
        );
        assert_eq!(
            one.0, many.0,
            "{ingest} ingest threads, {delays:?}: provisionals differ"
        );
    }
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = tally_mlat::engine::Engine::new(
        tally_wire::Signer::new(Identity::from_seed([5; 32]), std::sync::Arc::new(|| true)),
        MLAT_BOOT,
        mlat_settings(2),
    );
    engine.set_scope(tally_mlat::area::border_band(&areas), areas.clone());
    let reference: Vec<Record> = replay(&mut engine, &delivered, STEP_MS, until)?
        .into_iter()
        .filter(|(at, _)| *at >= first)
        .map(|(_, record)| record)
        .collect();
    let reference = encoded(&reference);
    assert_eq!(
        one.1, reference.1,
        "models and positions differ from the reference"
    );
    assert_eq!(one.0, reference.0, "provisionals differ from the reference");
    Ok(())
}

/// RFC-0181 §9 and invariant 1 at capacity: a relay whose MLAT seats fewer receivers than are
/// described refuses the same ones, whole, whatever order the descriptions came in, however they
/// raced, and on any number of threads, with delays or none: the best ranked are seated
/// (`tally_mlat::intake::Seats`: taking part first, then the draw under the relay's secret,
/// `tally_mlat::intake::draw`, never the key itself, which a feeder could grind), every other one
/// refused and counted, and the same records signed byte for byte.
#[test]
fn at_capacity_the_same_receivers_are_refused_whatever_the_order_and_the_threads() -> Result {
    use tally_mlat::replay::{arrivals, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    let mut keys: Vec<PublicKey> = delivered
        .iter()
        .filter_map(|(_, record)| match record {
            Record::ReceiverInfo(info) => info.receiver().ok(),
            _ => None,
        })
        .collect();
    // Every receiver of the trace takes part (they are all inside the areas), so the seats go by
    // the draw alone.
    keys.sort_unstable_by_key(|key| (tally_mlat::intake::draw(key), *key));
    // Two seats short: the two with the worst draws are refused.
    const SHORT: usize = 2;
    assert!(keys.len() > SHORT + 3, "{} receivers", keys.len());
    let seats = keys.len() - SHORT;
    let mut seated = keys[..seats].to_vec();
    seated.sort_unstable();
    let settings = |threads: usize| tally_mlat::engine::Settings {
        capacity: tally_mlat::engine::Capacity {
            receivers: seats,
            rates: tally_mlat_solver::held::Rates::MEASURED,
        },
        ..mlat_settings(threads)
    };
    let mut runs = Vec::new();
    for (ingest, describing, delays) in [
        (1, Describing::Before { reversed: false }, Delays::None),
        (2, Describing::Before { reversed: true }, Delays::None),
        (8, Describing::Before { reversed: false }, Delays::Seeded(4)),
        (1, Describing::Racing { seed: 1 }, Delays::None),
        (2, Describing::Racing { seed: 2 }, Delays::Seeded(5)),
        (8, Describing::Racing { seed: 3 }, Delays::None),
    ] {
        let threads = Threads {
            ingest,
            message: ingest,
            seal: ingest,
        };
        let (signed, report, held) = mlat_run_with(
            &delivered,
            &areas,
            threads,
            settings(ingest),
            describing,
            delays,
        )?;
        assert_eq!(
            report.receivers_refused, SHORT as u64,
            "{ingest} threads, {describing:?}, {delays:?}: {report:?}"
        );
        assert_eq!(
            (
                report.steps_shed,
                report.provisional_steps_shed,
                report.shed,
                report.provisional_models_late,
                report.waiting_dropped
            ),
            (0, 0, 0, 0, 0),
            "{ingest} threads, {describing:?}, {delays:?}: {report:?}"
        );
        assert_eq!(
            held, seated,
            "{ingest} threads, {describing:?}, {delays:?}: other receivers held"
        );
        runs.push((ingest, describing, delays, signed));
    }
    let (_, _, _, first) = &runs[0];
    assert!(!first.0.is_empty(), "no provisional positions");
    for (ingest, describing, delays, signed) in &runs[1..] {
        assert_eq!(
            first, signed,
            "{ingest} threads, {describing:?}, {delays:?}: the records differ"
        );
    }
    Ok(())
}

/// RFC-0181 §4 and invariant 2 for descriptions: a receiver described again
/// midway (out of the areas, so it stops taking part, and back ten seconds later) and one whose
/// first description comes halfway in (its batches before it waiting, those that waited too long
/// let go), each description stamped when it came and taking effect at the step after, make the
/// same clock models, positions and provisional positions on 1, 2 and 8 ingest workers, with
/// delays inside every stage of the host and between the batches, as the reference engine driven
/// in line makes of them (`tally_mlat::replay`); and other bytes than the same trace with no
/// change.
#[test]
fn descriptions_midway_make_the_same_bytes_with_any_delays_and_the_reference_engines() -> Result {
    use tally_mlat::replay::{arrivals, described_midway, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let plain = arrivals(&mut simulation, 3)?;
    let delivered = reissued(&simulation, &described_midway(&simulation, &plain)?)?;
    let areas = mlat_areas()?;
    let run = |delivered: &[(u64, Record)], ingest: usize, delays: Delays| -> Result<Signed> {
        let (signed, report, _) = mlat_run_with(
            delivered,
            &areas,
            Threads {
                ingest,
                message: ingest,
                seal: ingest,
            },
            mlat_settings(ingest),
            Describing::Before { reversed: false },
            delays,
        )?;
        assert_eq!(
            (
                report.steps_shed,
                report.provisional_steps_shed,
                report.shed,
                report.steps_discarded,
                report.provisional_models_late,
                report.waiting_dropped
            ),
            (0, 0, 0, 0, 0, 0),
            "{ingest} threads, {delays:?}: {report:?}"
        );
        assert!(report.orphans_expired > 0, "{report:?}");
        Ok(signed)
    };
    let one = run(&delivered, 1, Delays::None)?;
    for (ingest, delays) in [
        (2, Delays::Seeded(6)),
        (8, Delays::Seeded(7)),
        (8, Delays::None),
    ] {
        let many = run(&delivered, ingest, delays)?;
        assert_eq!(one.1, many.1, "{ingest} threads, {delays:?}: models differ");
        assert_eq!(
            one.0, many.0,
            "{ingest} threads, {delays:?}: provisionals differ"
        );
    }
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = tally_mlat::engine::Engine::new(
        tally_wire::Signer::new(Identity::from_seed([5; 32]), std::sync::Arc::new(|| true)),
        MLAT_BOOT,
        mlat_settings(2),
    );
    engine.set_scope(tally_mlat::area::border_band(&areas), areas.clone());
    let reference: Vec<Record> = replay(&mut engine, &delivered, STEP_MS, until)?
        .into_iter()
        .filter(|(at, _)| *at >= first)
        .map(|(_, record)| record)
        .collect();
    let reference = encoded(&reference);
    assert_eq!(one.1, reference.1, "models differ from the reference");
    assert_eq!(one.0, reference.0, "provisionals differ from the reference");
    let unchanged = mlat_run_with(
        &plain,
        &areas,
        Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        },
        mlat_settings(1),
        Describing::Before { reversed: false },
        Delays::None,
    )?;
    assert_ne!(
        one.1, unchanged.0.1,
        "the descriptions midway changed nothing"
    );
    Ok(())
}

/// A window step that runs long, past the old ripening and past as many steps
/// as `WINDOW_STEPS_BEHIND` (which sheds none: a window step is queued only at a step a window falls due
/// at; before, every step it ran past queued as one, and those past the limit were
/// shed), changes no provisional byte: a provisional step carries exactly the models of the window steps
/// `MODELS_RIPEN_MS` before it, by their stamp, and the ripening covers a window step on the
/// planned threads (measured 9 to 11 s: here every window step that solves is held while the
/// watermark runs ten steps past it). Before, a provisional step five seconds after a window step
/// still running started without its models and adopted them at whichever step came after they
/// reported, so the provisional bytes were the thread timing's. They are the reference engine's,
/// and no provisional step is shed or started late.
#[test]
fn a_window_step_that_runs_long_changes_no_provisional_byte() -> Result {
    use tally_mlat::replay::{arrivals, replay, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    const BEHIND: u64 = 10;
    const {
        assert!(BEHIND * STEP_MS > (WINDOW_STEPS_BEHIND as u64 + 1) * STEP_MS);
        assert!(BEHIND * STEP_MS <= tally_mlat::engine::MODELS_RIPEN_MS);
    }
    let (signed, report, _) = mlat_run_with(
        &delivered,
        &areas,
        Threads {
            ingest: 2,
            message: 2,
            seal: 2,
        },
        mlat_settings(2),
        Describing::Before { reversed: false },
        Delays::Windows {
            held_ms: 1_500,
            behind: BEHIND,
        },
    )?;
    // The steps it ran past were sealed in their turn, and none was shed.
    assert_eq!(
        (
            report.steps_shed,
            report.provisional_steps_shed,
            report.provisional_models_late,
            report.provisional_steps_late,
            report.shed,
            report.steps_discarded,
            report.waiting_dropped
        ),
        (0, 0, 0, 0, 0, 0, 0),
        "{report:?}"
    );
    assert!(!signed.0.is_empty(), "no provisional positions");
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = tally_mlat::engine::Engine::new(
        tally_wire::Signer::new(Identity::from_seed([5; 32]), std::sync::Arc::new(|| true)),
        MLAT_BOOT,
        mlat_settings(2),
    );
    engine.set_scope(tally_mlat::area::border_band(&areas), areas.clone());
    let reference: Vec<Record> = replay(&mut engine, &delivered, STEP_MS, until)?
        .into_iter()
        .filter(|(at, _)| *at >= first)
        .map(|(_, record)| record)
        .collect();
    let reference = encoded(&reference);
    assert_eq!(
        signed.0, reference.0,
        "provisionals differ from the reference"
    );
    assert_eq!(
        signed.1, reference.1,
        "models and positions differ from the reference"
    );
    Ok(())
}

/// The receivers of a trace, and settings seating all of them with room to spare.
type CutTrace = (
    Vec<(u64, Record)>,
    Regions,
    usize,
    tally_mlat::engine::Settings,
);

fn cut_trace() -> Result<CutTrace> {
    use tally_mlat::replay::{arrivals, scenario};
    let mut simulation = tally_mlat_solver::sim::run(&scenario(17, 60.0));
    let delivered = arrivals(&mut simulation, 3)?;
    let areas = mlat_areas()?;
    let receivers = delivered
        .iter()
        .filter(|(_, record)| matches!(record, Record::ReceiverInfo(_)))
        .count();
    let settings = tally_mlat::engine::Settings {
        capacity: tally_mlat::engine::Capacity {
            receivers: receivers + 2,
            rates: tally_mlat_solver::held::Rates::MEASURED,
        },
        ..mlat_settings(2)
    };
    Ok((delivered, areas, receivers, settings))
}

/// The draws of the trace's receivers, best first (`tally_mlat::intake::draw`).
fn draws_of(delivered: &[(u64, Record)]) -> Result<Vec<u128>> {
    let mut draws: Vec<u128> = Vec::new();
    for (_, record) in delivered {
        if let Record::ReceiverInfo(info) = record {
            draws.push(tally_mlat::intake::draw(&info.receiver().map_err(text)?));
        }
    }
    draws.sort_unstable();
    Ok(draws)
}

/// The announcements of a standing cut, as its signer sends them: one every `CUT_REFRESH_MS` from
/// `from_ms` to `until_ms`, each for `areas`.
fn standing(
    origin: PublicKey,
    areas: &Regions,
    below: u128,
    from_ms: u64,
    until_ms: u64,
) -> Vec<Cut> {
    let mut cuts = Vec::new();
    let mut at = from_ms / STEP_MS * STEP_MS;
    while at <= until_ms {
        cuts.push(Cut {
            from_ms: at,
            origin,
            below,
            areas: areas.cells().to_vec(),
        });
        at += tally_relay::mlat_host::CUT_REFRESH_MS;
    }
    cuts
}

/// RFC-0181 §10, the cut by key rank: two relays holding one area, offered one published cut
/// (from a step, so many seats), solve the same receivers from that step whatever order their
/// descriptions came in, on any threads, with delays or none, and make the same bytes; the
/// receivers cut are the worst ranked, counted; and the cut changes the bytes (it is not vacuous).
/// Before, the seats were drawn under each process's own secret and a host's cut was how far
/// behind it was, which no other relay could share.
#[test]
fn two_relays_offered_one_cut_solve_the_same_receivers_and_make_the_same_bytes() -> Result {
    let (delivered, areas, receivers, settings) = cut_trace()?;
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    const CUT: usize = 2;
    assert!(
        receivers >= CUT + tally_relay::mlat_host::MIN_CUT_SEATS,
        "{receivers} receivers"
    );
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let draws = draws_of(&delivered)?;
    // The cut asks for every receiver but the CUT worst ranked: the first receiver cut is the
    // (receivers - CUT)th, and everything below its draw stays.
    let cuts = standing(
        Identity::from_seed([9; 32]).public(),
        &areas,
        draws[receivers - CUT],
        first + 20_000,
        until,
    );
    let run = |ingest: usize, describing: Describing, delays: Delays, offered: Vec<Cut>| {
        mlat_run_cuts(
            &delivered,
            &areas,
            Threads {
                ingest,
                message: ingest,
                seal: ingest,
            },
            settings.clone(),
            describing,
            delays,
            Cutting {
                window_clock: None,
                offered,
                network: None,
            },
        )
    };
    let relay_a = run(
        1,
        Describing::Before { reversed: false },
        Delays::None,
        cuts.clone(),
    )?;
    let relay_b = run(
        8,
        Describing::Before { reversed: true },
        Delays::Seeded(6),
        cuts.clone(),
    )?;
    let relay_c = run(
        2,
        Describing::Racing { seed: 4 },
        Delays::None,
        cuts.clone(),
    )?;
    let uncut = run(
        1,
        Describing::Before { reversed: false },
        Delays::None,
        Vec::new(),
    )?;
    for (name, relay) in [("a", &relay_a), ("b", &relay_b), ("c", &relay_c)] {
        assert_eq!(
            relay.report.seat_cap,
            (receivers - CUT) as u64,
            "{name}: {:?}",
            relay.report
        );
        assert_eq!(relay.report.receivers_refused, CUT as u64, "{name}");
        assert_eq!(
            (
                relay.report.steps_shed,
                relay.report.provisional_steps_shed,
                relay.report.cuts_late
            ),
            (0, 0, 0),
            "{name}: {:?}",
            relay.report
        );
        assert!(
            relay.cuts.is_empty(),
            "{name} decided a cut of its own: {:?}",
            relay.cuts
        );
    }
    assert_eq!(uncut.report.seat_cap, (receivers + 2) as u64);
    assert_eq!(uncut.report.receivers_refused, 0);
    assert!(!relay_a.signed.0.is_empty(), "no provisional positions");
    assert_eq!(relay_a.signed, relay_b.signed, "relays a and b differ");
    assert_eq!(relay_a.signed, relay_c.signed, "relays a and c differ");
    assert_ne!(relay_a.signed, uncut.signed, "the cut changed nothing");
    Ok(())
}

/// RFC-0181 §10, overload: a host whose window step runs past its budget cuts its seats to what
/// that run carries within the budget, from a step a few ahead of its watermark, published for its
/// peers (`take_cuts`); and a peer that is offered that cut makes the same bytes as the host did,
/// receiver for receiver, though it never ran long. Before, the host shed the steps it was behind
/// on, by how far behind it was, and no peer could shed the same.
#[test]
fn an_overloaded_host_cuts_by_rank_and_a_peer_offered_the_cut_makes_the_same_bytes() -> Result {
    let (delivered, areas, receivers, settings) = cut_trace()?;
    let threads = Threads {
        ingest: 2,
        message: 2,
        seal: 2,
    };
    // Every window step is held 600 ms, and declares it ran that long against a budget of 200:
    // overload at the first.
    let overloaded = mlat_run_cuts(
        &delivered,
        &areas,
        threads,
        settings.clone(),
        Describing::Before { reversed: false },
        Delays::Windows {
            held_ms: 600,
            behind: 10,
        },
        Cutting {
            window_clock: Some(OVERLOADED),
            offered: Vec::new(),
            network: None,
        },
    )?;
    assert!(
        !overloaded.cuts.is_empty(),
        "no cut: {:?}",
        overloaded.report
    );
    // Each decision is announced, and again while it stands.
    assert!(
        overloaded.report.cuts_decided >= 1,
        "{:?}",
        overloaded.report
    );
    assert!(
        overloaded.cuts.len() as u64 >= overloaded.report.cuts_decided,
        "{:?}",
        overloaded.cuts
    );
    for cut in &overloaded.cuts {
        assert_eq!(cut.from_ms % STEP_MS, 0, "{cut:?}");
        assert!(!cut.areas.is_empty(), "{cut:?}");
        assert!(cut.areas.len() <= tally_wire::MAX_CUT_AREAS, "{cut:?}");
    }
    // A standing cut is announced again, at a later step with the same threshold, so a relay
    // that started late or lost the first learns it, and it expires when no longer announced.
    let refreshed = overloaded.cuts.iter().any(|cut| {
        overloaded.cuts.iter().any(|later| {
            later.below == cut.below
                && later.below != u128::MAX
                && later.from_ms >= cut.from_ms + tally_relay::mlat_host::CUT_REFRESH_MS
        })
    });
    assert!(refreshed, "no refresh: {:?}", overloaded.cuts);
    // Nothing was shed by lateness: the cut came before it was needed.
    assert_eq!(
        (
            overloaded.report.steps_shed,
            overloaded.report.provisional_steps_shed,
            overloaded.report.provisional_models_late,
        ),
        (0, 0, 0),
        "{:?}",
        overloaded.report
    );
    assert!(overloaded.report.seat_cap < (receivers + 2) as u64);
    let peer = mlat_run_cuts(
        &delivered,
        &areas,
        Threads {
            ingest: 8,
            message: 8,
            seal: 8,
        },
        settings.clone(),
        Describing::Before { reversed: true },
        Delays::Seeded(7),
        Cutting {
            window_clock: None,
            offered: overloaded.cuts.clone(),
            network: None,
        },
    )?;
    assert_eq!(peer.report.seat_cap, overloaded.report.seat_cap);
    assert_eq!(
        peer.report.receivers_refused,
        overloaded.report.receivers_refused
    );
    assert_eq!(peer.signed, overloaded.signed, "the peer differs");
    let uncut = mlat_run_cuts(
        &delivered,
        &areas,
        threads,
        settings,
        Describing::Before { reversed: false },
        Delays::None,
        Cutting::default(),
    )?;
    assert_ne!(uncut.signed, overloaded.signed, "the cut changed nothing");
    Ok(())
}

/// RFC-0181 §10, the cut on the wire: relay A, overloaded, signs the cut it decided and addresses it
/// to relay B, which holds the same areas (`Network::publish_cuts`); B takes it from A as a link
/// hands it (`Network::handle`) and, though it never ran long, applies the same cut at the same
/// step, so it solves the same receivers and makes the same bytes as A did. A cut from a key that
/// is not the sender's, or from a relay holding none of B's areas, is refused and counted, and
/// changes nothing.
#[test]
fn an_overloaded_relays_cut_reaches_the_relay_holding_its_area_and_both_make_the_same_bytes()
-> Result {
    let (delivered, areas, receivers, settings) = cut_trace()?;
    let relay_a = Arc::new(Identity::from_seed([6; 32]));
    let relay_b = Arc::new(Identity::from_seed([7; 32]));
    let stranger = Identity::from_seed([8; 32]);
    let threads = Threads {
        ingest: 2,
        message: 2,
        seal: 2,
    };
    let overloaded = mlat_run_cuts(
        &delivered,
        &areas,
        threads,
        settings.clone(),
        Describing::Before { reversed: false },
        Delays::Windows {
            held_ms: 600,
            behind: 10,
        },
        Cutting {
            window_clock: Some(OVERLOADED),
            offered: Vec::new(),
            network: Some(Neighbours {
                me: relay_a.clone(),
                other: relay_b.clone(),
                carried: Vec::new(),
            }),
        },
    )?;
    assert!(!overloaded.cuts.is_empty(), "{:?}", overloaded.report);
    // One signed record per cut, to the one neighbour, each saying what the host decided.
    assert_eq!(overloaded.sent.len(), overloaded.cuts.len());
    assert_eq!(overloaded.network_cuts.0, overloaded.cuts.len() as u64);
    for (record, cut) in overloaded.sent.iter().zip(&overloaded.cuts) {
        let Record::MlatCut(signed) = record else {
            return Err(format!("sent {record:?}"));
        };
        signed.verify().map_err(text)?;
        assert_eq!(signed.signer().map_err(text)?, relay_a.public());
        let content = signed.content().map_err(text)?;
        assert_eq!(
            (content.from_ms, content.below, content.areas.clone()),
            (cut.from_ms, cut.below, cut.areas.clone())
        );
        // And it travels as a record does.
        let mut bytes = Vec::new();
        record.encode(&mut bytes).map_err(text)?;
        assert_eq!(
            Record::decode(&bytes).map_err(text)?.0.as_ref(),
            Some(record)
        );
    }
    let peer = |carried: Vec<Record>, threads: usize, delays: Delays| {
        mlat_run_cuts(
            &delivered,
            &areas,
            Threads {
                ingest: threads,
                message: threads,
                seal: threads,
            },
            settings.clone(),
            Describing::Before { reversed: true },
            delays,
            Cutting {
                window_clock: None,
                offered: Vec::new(),
                network: Some(Neighbours {
                    me: relay_b.clone(),
                    other: relay_a.clone(),
                    carried,
                }),
            },
        )
    };
    let relay_b_run = peer(overloaded.sent.clone(), 8, Delays::Seeded(7))?;
    assert_eq!(
        relay_b_run.network_cuts,
        (0, overloaded.cuts.len() as u64, 0),
        "{:?}",
        relay_b_run.report
    );
    assert_eq!(relay_b_run.report.cuts_late, 0);
    assert_eq!(relay_b_run.report.seat_cap, overloaded.report.seat_cap);
    assert_eq!(
        relay_b_run.report.receivers_refused,
        overloaded.report.receivers_refused
    );
    assert_eq!(
        relay_b_run.signed, overloaded.signed,
        "relay b differs from the overloaded relay a"
    );
    assert!(overloaded.report.seat_cap < (receivers + 2) as u64);
    // The same cut signed by a key that is not the relay that sent it, or sent by a relay that
    // holds none of its areas, is refused: B solves everything it is given, as with no cut.
    let forged: Vec<Record> = overloaded
        .cuts
        .iter()
        .map(|cut| {
            tally_wire::MlatCut::sign(
                &stranger,
                &tally_wire::MlatCutContent {
                    from_ms: cut.from_ms,
                    below: cut.below,
                    areas: cut.areas.clone(),
                },
            )
            .map(Record::MlatCut)
            .map_err(text)
        })
        .collect::<Result<_>>()?;
    let refused = peer(forged, 2, Delays::None)?;
    assert_eq!(
        refused.network_cuts,
        (0, 0, overloaded.cuts.len() as u64),
        "{:?}",
        refused.report
    );
    assert_eq!(refused.report.seat_cap, (receivers + 2) as u64);
    assert_eq!(refused.report.receivers_refused, 0);
    assert_ne!(
        refused.signed, overloaded.signed,
        "a refused cut changed things"
    );
    Ok(())
}
