//! One program, end to end (RFC-0174 §2.1, §2.3): the simulator's receivers feed a real relay as
//! feeders, the relay hosts the MLAT engine for the area they are in, and a plain client of that
//! relay receives clock models, positions and provisional positions signed by the relay's own key,
//! with no engine process and no engine link anywhere. The client checks them as anyone would:
//! every model by the model verifier against the raw, every solution as a claim under the model it
//! cites. Then the same across two relays: the feeders on a relay that solves nothing, whose raw
//! reaches the relay that solves their area in one hop. Then RFC-0174 whole, across three relays
//! that find one another from signed offers alone: selection, one-hop raw, sharing, and the
//! regional and both world products, each checked by the client. And the choice itself across four
//! relays: one is not chosen for an area (k is three), and when a chosen one dies outright, the
//! area moves to the next by rendezvous once its offers lapse.
//!
//! In the first three tests the host is pinned to the simulator's areas, so they test the hosting
//! and nothing else. The first step is held until every batch of the first phase is in the engine:
//! the scenario's first window is due the moment the relay looks, and a step on the wall clock
//! would solve whatever raw a slow machine had delivered by then.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tally_mlat::engine::Settings;
use tally_mlat_solver::scope::{GRID_MS, STRIDE, Sites, WindowIndex, bin_of};
use tally_mlat_solver::sim::{self, Scenario, Simulation};
use tally_mlat_solver::{
    Calibrated, ClockModel as Model, Reception, publish, verify, verify_model,
};
use tally_relay::hub::Hub;
use tally_relay::mlat_host::{HostedMlat, MlatHost, MlatReport, SETTLE_MS};
use tally_wire::noise;
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{
    Assembler, Identity, Location, Positions, PublicKey, Reader, Record, Region, RelayAddress,
    Role, Streams,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;

/// Each relay's stages on threads of their own, as a relay runs them (`Hub::staged`): its seals
/// never hold up its connections, and its MLAT raw is taken into its raw shards by its ingest
/// workers, never on its engine's thread. Two threads a stage, so the shards are split between
/// workers as they are on a relay.
const RELAY_THREADS: tally_relay::ingest::Threads = tally_relay::ingest::Threads {
    ingest: 2,
    message: 2,
};

type Result<T = ()> = std::result::Result<T, String>;

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

const WAIT: Duration = Duration::from_secs(90);

/// The relay's hosted MLAT, its areas pinned (in place of `selection`'s choice) and its steps held
/// until the test opens it.
struct Pinned {
    host: HostedMlat,
    areas: Vec<Region>,
    open: AtomicBool,
}

impl MlatHost for Pinned {
    fn set_areas(&self, _chosen: Vec<Region>, descriptions: Vec<tally_wire::ReceiverInfo>) {
        self.host.set_areas(self.areas.clone(), descriptions);
    }

    fn offer(&self, record: &Record, now_ms: u64) {
        self.host.offer(record, now_ms);
    }

    fn offer_batch(&self, batch: &std::sync::Arc<tally_wire::Decoded>, now_ms: u64) {
        self.host.offer_batch(batch, now_ms);
    }

    fn sealed_bins(&self) -> Option<tally_mlat_solver::held::SealedBins> {
        self.host.sealed_bins()
    }

    fn take_published(&self, now_ms: u64) -> Vec<Record> {
        if self.open.load(Ordering::SeqCst) {
            self.host.take_published(now_ms)
        } else {
            Vec::new()
        }
    }

    fn cores(&self) -> u16 {
        self.host.cores()
    }

    fn report(&self) -> MlatReport {
        self.host.report()
    }
}

/// The areas within about 150 km of the simulator's centre.
fn areas() -> Result<Vec<Region>> {
    let (lat, lon) = sim::CENTRE;
    let mut areas = Vec::new();
    for north in -2..=2 {
        for east in -2..=2 {
            let location = Location {
                lat_e7: ((lat + f64::from(north) * 0.6) * 1e7) as i32,
                lon_e7: ((lon + f64::from(east) * 1.0) * 1e7) as i32,
                alt_m: 0,
                precision_m: 0,
            };
            let area = Region::containing(&location, AREA_RESOLUTION).map_err(text)?;
            if !areas.contains(&area) {
                areas.push(area);
            }
        }
    }
    Ok(areas)
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// A scenario whose first 30 seconds fill the solved bins of the newest window already due by the
/// relay's clock, and whose last 15 come after it: the first phase is solved the moment the relay
/// steps, and the second is recent enough for that window's models to carry.
fn recent(seed: u64) -> (Scenario, u64) {
    recent_at(seed, wall_ms())
}

/// As `recent`, by the relay's clock at `now_ms`.
fn recent_at(seed: u64, now_ms: u64) -> (Scenario, u64) {
    let settled = bin_of(now_ms.saturating_sub(SETTLE_MS)) - 1;
    // The window solving bins `top - STRIDE + 1 ..= top` ends with bin `top + 1`.
    let top = (settled - 1).div_euclid(STRIDE) * STRIDE;
    let start_ms = (top - 5) as u64 * GRID_MS + 200;
    let split_ms = (top + 1) as u64 * GRID_MS;
    let scenario = Scenario {
        duration_s: 45.0,
        modes_aircraft: 16,
        midnight_unix_ms: start_ms - start_ms % 86_400_000,
        start_tod_s: (start_ms % 86_400_000) as f64 / 1000.0,
        ..Scenario::new(seed)
    };
    (scenario, split_ms)
}

/// A relay with a fresh key that accepts `relays` as relays, hosting `mlat` if given.
async fn relay(
    identity: Identity,
    relays: &[PublicKey],
    mlat: Option<Arc<Pinned>>,
) -> Result<(RelayAddress, Arc<Hub>)> {
    let key = identity.public();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    // Every feeder here comes from loopback: more than one host's share of connections.
    let hub = Arc::new(
        Hub::new(8)
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(64)
            .staged(RELAY_THREADS),
    );
    if let Some(mlat) = mlat {
        hub.network().host_mlat(mlat);
    }
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok((
        RelayAddress {
            key,
            address: address.to_string(),
        },
        hub,
    ))
}

fn pinned(identity: &Identity) -> Result<Arc<Pinned>> {
    let areas = areas()?;
    let host = HostedMlat::new(
        identity.clone(),
        7,
        Settings {
            regions: Vec::new(),
            settle_ms: SETTLE_MS,
            threads: 4,
            capacity: tally_mlat::engine::Capacity::default(),
        },
    );
    // Solving from the first offer on: the relay's own network task re-states it every tick.
    host.set_areas(areas.clone(), Vec::new());
    Ok(Arc::new(Pinned {
        host,
        areas,
        open: AtomicBool::new(false),
    }))
}

/// A client of the relay's clock models, positions and provisional positions: its reading half.
async fn client(relay: &RelayAddress) -> Result<Reader<TcpStream>> {
    let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
    let mut session = noise::connect(
        stream,
        &Identity::generate().map_err(text)?,
        &relay.key,
        Role::Subscriber,
    )
    .await
    .map_err(text)?;
    session
        .writer
        .send(&[Record::Subscribe {
            streams: Streams::POSITIONS
                .with(Streams::CLOCK_MODELS)
                .with(Streams::PROVISIONAL),
            regions: Vec::new(),
        }])
        .await
        .map_err(text)?;
    // The writing half stays open for as long as the client reads.
    tokio::spawn(async move {
        let writer = session.writer;
        std::future::pending::<()>().await;
        drop(writer);
    });
    Ok(session.reader)
}

/// Waits until `hub` has `links` more links in its fan-out than `before`.
async fn listening(hub: &Hub, before: usize, links: usize) -> Result {
    timeout(WAIT, async {
        while hub.listening() < before + links {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "the links never joined the fan-out".to_owned())
}

/// Every simulated receiver, a feeder of `relay`: its description and the batches up to
/// `split_ms` at once, the rest once `second` turns true. The batches of the first phase.
async fn feed(
    simulation: &Simulation,
    relay: &RelayAddress,
    split_ms: u64,
    second: &watch::Receiver<bool>,
) -> Result<u64> {
    let mut first_phase = 0;
    for feed in simulation.feeds().map_err(text)? {
        let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
        let mut session = noise::connect(stream, &feed.identity, &relay.key, Role::Feeder)
            .await
            .map_err(text)?;
        let mut early = vec![Record::ReceiverInfo(feed.info.clone())];
        let mut late = Vec::new();
        for batch in feed.batches {
            let wall = batch.content().map_err(text)?.wall_ms;
            if wall < split_ms {
                first_phase += 1;
                early.push(Record::Batch(batch));
            } else {
                late.push(Record::Batch(batch));
            }
        }
        let mut second = second.clone();
        tokio::spawn(async move {
            for record in early {
                if session.writer.send(&[record]).await.is_err() {
                    return;
                }
            }
            if second.wait_for(|go| *go).await.is_err() {
                return;
            }
            for record in late {
                if session.writer.send(&[record]).await.is_err() {
                    return;
                }
            }
            // The feeder stays connected, as a real one does.
            std::future::pending::<()>().await;
            drop(session);
        });
    }
    Ok(first_phase)
}

/// Waits until the host has taken `batches` batches, then lets it step.
async fn all_in(mlat: &Pinned, batches: u64) -> Result {
    timeout(WAIT, async {
        while mlat.host.ingested() < batches {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "{} of {batches} batches reached the engine",
            mlat.host.ingested()
        )
    })?;
    mlat.open.store(true, Ordering::SeqCst);
    Ok(())
}

/// The raw the client holds (the simulator's receptions before `split_ms`), sealed in its bins.
struct Raw {
    bins: Vec<Arc<tally_mlat_solver::held::Bin>>,
    sites: Sites,
}

impl Raw {
    fn of(simulation: &Simulation, split_ms: u64) -> Self {
        let early: Vec<Reception> = simulation
            .receptions
            .iter()
            .filter(|reception| reception.wall_ms < split_ms)
            .cloned()
            .collect();
        Self {
            bins: tally_mlat_solver::held::bins_of(&early)
                .into_values()
                .collect(),
            sites: Sites::new(&simulation.sites()),
        }
    }
}

struct Checked {
    model: Model,
    calibrated: Calibrated,
}

/// A model reassembled from the relay's records, checked by the model verifier against the raw.
fn check_model(model: Model, raw: &Raw) -> Result<Checked> {
    let index = WindowIndex::new(model.window, &raw.bins, &raw.sites);
    let members = index.members(model.tile);
    let inputs = index
        .inputs(model.tile, &members)
        .ok_or("a model of a tile with no members")?;
    let (verdict, calibrated) = verify_model(&model, &inputs);
    assert!(verdict.passed(), "{:?}", verdict.failures);
    Ok(Checked {
        model,
        calibrated: calibrated.ok_or("no calibration")?,
    })
}

/// Every solution of a final positions record, checked as a claim under the model it cites
/// against the raw; how many.
fn check_positions(
    positions: &Positions,
    relay: PublicKey,
    models: &BTreeMap<[u8; 32], Checked>,
    raw: &Raw,
) -> Result<usize> {
    positions.verify().map_err(text)?;
    assert_eq!(positions.engine().map_err(text)?, relay);
    let content = positions.solutions().map_err(text)?;
    for solution in &content.solutions {
        let checked = models
            .get(&solution.clock_model)
            .ok_or("a solution cites a clock model the client never received")?;
        let index = WindowIndex::new(checked.model.window, &raw.bins, &raw.sites);
        tally_mlat_solver::verify_assignment(
            &index,
            solution.address,
            &checked.model,
            &solution.addressed,
        )
        .map_err(|failure| format!("{failure:?}"))?;
        let mut members = BTreeMap::new();
        let assignment = index
            .assign(solution.address, &mut members)
            .ok_or("no assignment")?;
        let candidates = index.receptions(solution.address, &assignment.scope);
        let claim = publish::claim(&checked.model, solution, content.spec_version).map_err(text)?;
        let verdict = verify(&checked.calibrated, &candidates, &claim);
        assert!(verdict.passed(), "{:?}", verdict.failures);
    }
    Ok(content.solutions.len())
}

/// What the client heard.
#[derive(Debug, Default)]
struct Heard {
    verified: usize,
    models: usize,
    provisional: usize,
}

/// Reads the client until `want` final solutions are verified and, if `provisional`, a
/// provisional position citing a model it holds has come; `second` is let go once the finals are
/// in, so the second phase's receptions are solved under the carried models.
async fn listen(
    reader: &mut Reader<TcpStream>,
    relay: PublicKey,
    raw: &Raw,
    want: usize,
    provisional: Option<&watch::Sender<bool>>,
) -> Result<Heard> {
    let mut assembler = Assembler::new(256 * 1024 * 1024, 1_024);
    let mut models: BTreeMap<[u8; 32], Checked> = BTreeMap::new();
    let mut heard = Heard::default();
    let outcome = timeout(WAIT, async {
        while heard.verified < want || (provisional.is_some() && heard.provisional == 0) {
            let mut got = Vec::new();
            reader.recv(&mut got).await.map_err(text)?;
            for record in got {
                let assembled = match record {
                    Record::ClockModelPart(part) => assembler.part(part),
                    Record::ClockModel(model) => {
                        model.verify().map_err(text)?;
                        assert_eq!(model.engine().map_err(text)?, relay);
                        assembler.manifest(model).map_err(text)?
                    }
                    Record::Positions(positions) => {
                        heard.verified += check_positions(&positions, relay, &models, raw)?;
                        None
                    }
                    Record::Provisional(positions) => {
                        positions.verify().map_err(text)?;
                        assert_eq!(positions.engine().map_err(text)?, relay);
                        for solution in positions.solutions().map_err(text)?.solutions {
                            assert!(
                                models.contains_key(&solution.clock_model),
                                "a provisional position cites a model the client never received"
                            );
                            heard.provisional += 1;
                        }
                        None
                    }
                    _ => None,
                };
                if let Some((manifest, content)) = assembled {
                    heard.models += 1;
                    let model =
                        publish::decode(&content.model, content.spec_version).map_err(text)?;
                    assert_eq!(content.inputs, publish::inputs_id(&model));
                    models.insert(manifest.id(), check_model(model, raw)?);
                }
            }
            if heard.verified >= want
                && let Some(second) = provisional
            {
                let _ = second.send(true);
            }
        }
        Ok::<_, String>(())
    })
    .await;
    match outcome {
        Ok(result) => result.map(|()| heard),
        Err(_) => Err(format!("before the deadline: {heard:?}")),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feeders_of_a_relay_hosting_mlat_give_its_clients_verifiable_positions_and_provisionals()
-> Result {
    // A window has just come due, so the one `recent` fills is as young as it can be and its
    // finals reach the precise world well inside its 90 s.
    timeout(WAIT, async {
        while (bin_of(wall_ms().saturating_sub(SETTLE_MS)) - 2).rem_euclid(STRIDE) != 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| "no window came due".to_owned())?;
    let (scenario, split_ms) = recent(31);
    let simulation = sim::run(&scenario);
    let raw = Raw::of(&simulation, split_ms);
    let identity = Identity::generate().map_err(text)?;
    let mlat = pinned(&identity)?;
    let (relay, hub) = relay(identity, &[], Some(Arc::clone(&mlat))).await?;
    let before = hub.listening();
    let mut reader = client(&relay).await?;
    listening(&hub, before, 1).await?;
    let (second, go) = watch::channel(false);
    let batches = feed(&simulation, &relay, split_ms, &go).await?;
    all_in(&mlat, batches).await?;
    let heard = listen(&mut reader, relay.key, &raw, 100, Some(&second)).await?;
    assert!(heard.models > 0, "{heard:?}");
    // Nothing offered was let go, and the steps' reports were kept.
    let report = mlat.host.report();
    assert_eq!((report.refused, report.overflowed), (0, 0), "{report:?}");
    assert!(
        report.steps > 0 && report.steps_total.solved > 0,
        "{report:?}"
    );
    Ok(())
}

/// Seed 53 once published exactly determined fixes (no redundancy) whose chi-square, rounded to
/// the wire, was above the verifier's limit, because the engine checked only one in sixteen and the
/// two sides held different limits. Every final it publishes now passes the client's check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_final_a_relay_publishes_passes_the_verifier_seed_53() -> Result {
    let (scenario, split_ms) = recent(53);
    let simulation = sim::run(&scenario);
    let raw = Raw::of(&simulation, split_ms);
    let identity = Identity::generate().map_err(text)?;
    let mlat = pinned(&identity)?;
    let (relay, hub) = relay(identity, &[], Some(Arc::clone(&mlat))).await?;
    let before = hub.listening();
    let mut reader = client(&relay).await?;
    listening(&hub, before, 1).await?;
    let (_second, go) = watch::channel(false);
    let batches = feed(&simulation, &relay, split_ms, &go).await?;
    all_in(&mlat, batches).await?;
    let heard = listen(&mut reader, relay.key, &raw, 100, None).await?;
    assert!(heard.models > 0, "{heard:?}");
    Ok(())
}

/// The relay holding the feeders offers no MLAT; the solving relay, the only one offering cores,
/// is chosen for the area. The feeders' relay verifies the solver's signed offer over a directory
/// link (`--upstream`, `--accept-relay`), so the solver's one-hop raw link (`peers`, which it opens
/// itself) is granted the raw of the area's border band, and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_from_a_relay_that_solves_nothing_reaches_the_relay_that_solves_its_area_in_one_hop()
-> Result {
    let (scenario, split_ms) = recent(41);
    let simulation = sim::run(&scenario);
    let raw = Raw::of(&simulation, split_ms);
    let areas = areas()?;
    let solving = Identity::generate().map_err(text)?;
    let holding = Identity::generate().map_err(text)?;
    let mlat = pinned(&solving)?;
    let (feeders, feeders_hub) =
        offering(holding.clone(), &areas, 64_521, None, &[solving.public()]).await?;
    let (solver, solver_hub) = offering(
        solving.clone(),
        &areas,
        64_522,
        Some(Arc::clone(&mlat)),
        &[],
    )
    .await?;
    tokio::spawn(tally_relay::link::upstream(
        tally_relay::config::Upstream {
            address: feeders.address.clone(),
            key: feeders.key,
        },
        solving.clone(),
        Arc::clone(&solver_hub),
    ));
    // The feeders' relay holds the solver's verified offer, and the solver keeps its one-hop raw
    // link to it.
    timeout(WAIT, async {
        loop {
            let now = tally_relay::network::wall_ms();
            let network = solver_hub.network();
            if feeders_hub.network().directory.knows(&solver.key)
                && !network
                    .selection
                    .raw_sources(&network.directory, now)
                    .is_empty()
                && network.peers.counts().1 >= 1
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "the solver never linked to the feeders' relay for raw".to_owned())?;
    let before = solver_hub.listening();
    let mut reader = client(&solver).await?;
    listening(&solver_hub, before, 1).await?;
    let (_second, go) = watch::channel(false);
    let batches = feed(&simulation, &feeders, split_ms, &go).await?;
    all_in(&mlat, batches).await?;
    let heard = listen(&mut reader, solver.key, &raw, 40, None).await?;
    assert!(heard.models > 0, "{heard:?}");
    Ok(())
}

/// A relay taking `areas` on network `asn`, advertising its own address (so its offers can be
/// verified), accepting `relays` on directory links, and hosting `mlat` if given (else offering no
/// MLAT cores).
async fn offering(
    identity: Identity,
    areas: &[Region],
    asn: u32,
    mlat: Option<Arc<Pinned>>,
    relays: &[PublicKey],
) -> Result<(RelayAddress, Arc<Hub>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = RelayAddress {
        key: identity.public(),
        address: listener.local_addr().map_err(text)?.to_string(),
    };
    let hub = Arc::new(
        Hub::new(64)
            .advertising(vec![address.clone()])
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(256)
            .staged(RELAY_THREADS),
    );
    let network = hub.network();
    network.selection.set_taken(areas.to_vec());
    network.products.set_taken(areas.to_vec());
    network.admission.configure(asn, true);
    if let Some(mlat) = mlat {
        network.host_mlat(mlat);
    }
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok((address, hub))
}

/// A relay's hosted MLAT whose areas are `selection`'s (unlike [`Pinned`]) and whose steps are
/// held until the test opens it, for the reason the module docs give.
struct Gated {
    host: HostedMlat,
    open: AtomicBool,
}

impl MlatHost for Gated {
    fn set_areas(&self, chosen: Vec<Region>, descriptions: Vec<tally_wire::ReceiverInfo>) {
        self.host.set_areas(chosen, descriptions);
    }

    fn offer(&self, record: &Record, now_ms: u64) {
        self.host.offer(record, now_ms);
    }

    fn offer_batch(&self, batch: &std::sync::Arc<tally_wire::Decoded>, now_ms: u64) {
        self.host.offer_batch(batch, now_ms);
    }

    fn sealed_bins(&self) -> Option<tally_mlat_solver::held::SealedBins> {
        self.host.sealed_bins()
    }

    fn take_published(&self, now_ms: u64) -> Vec<Record> {
        if self.open.load(Ordering::SeqCst) {
            self.host.take_published(now_ms)
        } else {
            Vec::new()
        }
    }

    fn cores(&self) -> u16 {
        self.host.cores()
    }

    fn report(&self) -> MlatReport {
        self.host.report()
    }
}

/// One relay of the three-relay network: its address, hub and hosted MLAT.
struct Member {
    address: RelayAddress,
    hub: Arc<Hub>,
    mlat: Arc<Gated>,
}

/// A relay as `tally-relay` configures one: taking `areas`, advertising its own address, on
/// network `asn`, with relay duties on, hosting MLAT on two threads for the areas `selection`
/// chooses it for, and gathering both world products when `world`. It accepts `relays` on
/// directory links (`--accept-relay`).
async fn member(
    identity: Identity,
    areas: &[Region],
    asn: u32,
    world: bool,
    relays: &[PublicKey],
) -> Result<Member> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = RelayAddress {
        key: identity.public(),
        address: listener.local_addr().map_err(text)?.to_string(),
    };
    // Subscribers here: the client, the other relays' one-hop raw links (one per chunk of the
    // border band) and their directory checks.
    let hub = Arc::new(
        Hub::new(64)
            .advertising(vec![address.clone()])
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(256)
            .staged(RELAY_THREADS),
    );
    let network = hub.network();
    network.selection.set_taken(areas.to_vec());
    network.products.set_taken(areas.to_vec());
    network.products.set_world(world);
    network.products.set_world_precise(world);
    network.admission.configure(asn, true);
    let mlat = Arc::new(Gated {
        host: HostedMlat::new(
            identity.clone(),
            u64::from(asn),
            Settings {
                regions: Vec::new(),
                settle_ms: SETTLE_MS,
                threads: 2,
                capacity: tally_mlat::engine::Capacity::default(),
            },
        ),
        open: AtomicBool::new(false),
    });
    network.host_mlat(Arc::clone(&mlat) as Arc<dyn MlatHost>);
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok(Member { address, hub, mlat })
}

/// What the network's client heard and checked.
#[derive(Debug, Default)]
struct Network {
    /// Final solutions checked against the raw under the model each cites.
    verified: usize,
    /// The relays whose finals were checked.
    solvers: std::collections::BTreeSet<PublicKey>,
    /// Models the verifier passed, and those whose inputs are not the client's raw (a window the
    /// client holds only part of).
    models: usize,
    unconfirmed: usize,
    provisional: usize,
    /// The longest a provisional record of the live phase (fed as it happens) reached the client
    /// after its newest transmission.
    provisional_lag_ms: u64,
    regional: usize,
    /// World fixes checked against the record each cites (`products::check_fix`), live and
    /// precise; and how many of the precise were multilaterated, checked against final positions.
    live_fixes: usize,
    /// Of the live world's fixes, those multilaterated (traced to provisional positions).
    live_mlat: usize,
    precise_fixes: usize,
    precise_mlat: usize,
}

impl Network {
    fn done(&self) -> bool {
        self.verified >= 40
            && self.solvers.len() >= 3
            && self.regional > 0
            && self.live_fixes > 0
            && self.live_mlat > 0
            && self.precise_mlat > 0
    }
}

/// Checks every fix of one world record whose origin the client holds: (checked, of them MLAT).
fn check_world(
    content: &tally_wire::WorldPositionsContent,
    origins: &BTreeMap<[u8; 32], Record>,
    inputs: &BTreeMap<[u8; 32], [u8; 32]>,
    precise: bool,
) -> Result<(usize, usize)> {
    let (mut checked, mut mlat) = (0, 0);
    for fix in &content.fixes {
        if precise {
            assert!(!fix.provisional, "a provisional fix in the precise world");
        }
        let Some(origin) = origins.get(&fix.origin) else {
            continue;
        };
        tally_relay::products::check_fix(fix, origin, |model| inputs.get(model).copied())
            .map_err(|error| format!("a world fix refuted by its origin: {error}"))?;
        checked += 1;
        if fix.mlat {
            mlat += 1;
        }
    }
    Ok((checked, mlat))
}

/// A model reassembled from a relay's records, checked by the model verifier against the raw the
/// client holds; `None` for a model whose inputs are not that raw (the verifier finds its scope
/// or citation not the client's).
fn confirm_model(model: Model, raw: &Raw) -> Result<Option<Checked>> {
    let index = WindowIndex::new(model.window, &raw.bins, &raw.sites);
    let members = index.members(model.tile);
    let Some(inputs) = index.inputs(model.tile, &members) else {
        return Ok(None);
    };
    let (verdict, calibrated) = verify_model(&model, &inputs);
    if verdict.failures.iter().all(|failure| {
        matches!(
            failure,
            tally_mlat_solver::ModelFailure::Scope | tally_mlat_solver::ModelFailure::Citation
        )
    }) && !verdict.passed()
    {
        return Ok(None);
    }
    assert!(verdict.passed(), "{:?}", verdict.failures);
    Ok(Some(Checked {
        model,
        calibrated: calibrated.ok_or("no calibration")?,
    }))
}

/// RFC-0174 end to end: three relays on three networks take the same areas; the simulator's
/// receivers feed them, a third each; the second and third each have one directory link
/// (`--upstream`) to the first, which accepts them (`--accept-relay`), and those links carry the
/// directory and nothing else. From the offers alone each relay verifies the others, `selection` chooses the
/// MLAT relays of each area (all three: k is three), each keeps one-hop raw links to the others,
/// and the sharing groups carry each relay's feeders' data (descriptions first) to the rest. The
/// client, on the relay that gathers both world products, receives clock models and final
/// positions from more than one relay, checked against the raw by the model verifier and the
/// claim check; the regional product; a live world whose fixes it traces to the records they cite,
/// multilaterated ones among them (provisional positions, under models carried); and a precise
/// world whose MLAT fixes it traces to the final positions they cite. Every record of data crosses
/// between relays over member links: each relay takes group records from its members, and no
/// directory link carries any.
///
/// The first 30 s of the scenario are past, fed at once and solved together once every relay
/// holds them, as the first test holds its one relay; the rest is fed as it happens, solved
/// provisionally under the models carried. The precise world seals a second 90 s after it, so
/// this takes about two minutes.
///
/// It runs three relays in real time, so it states what it needs: an optimised build (Cargo's
/// `--release`; Bazel builds it so, `crates/relay/BUILD.bazel`) and the cores the target declares.
/// A debug build cannot keep up with the clock and is skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[cfg_attr(
    debug_assertions,
    ignore = "runs relays in real time: build it optimised (cargo test --release)"
)]
async fn three_relays_share_solve_and_serve_verifiable_positions_and_both_world_products() -> Result
{
    let areas = areas()?;
    let identities = [
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
    ];
    let joining: Vec<PublicKey> = identities[1..].iter().map(Identity::public).collect();
    let mut members = Vec::new();
    for (identity, asn) in identities.iter().zip([64_501, 64_502, 64_503]) {
        let accepted = if asn == 64_501 { &joining[..] } else { &[] };
        members.push(member(identity.clone(), &areas, asn, asn == 64_501, accepted).await?);
    }
    for (identity, joiner) in identities[1..].iter().zip(&members[1..]) {
        tokio::spawn(tally_relay::link::upstream(
            tally_relay::config::Upstream {
                address: members[0].address.address.clone(),
                key: members[0].address.key,
            },
            identity.clone(),
            Arc::clone(&joiner.hub),
        ));
    }

    // Every relay has verified the others' offers, chosen itself an MLAT relay of every area, and
    // asked the others for their raw.
    let keys: Vec<PublicKey> = members.iter().map(|m| m.address.key).collect();
    timeout(WAIT, async {
        loop {
            let ready = members.iter().all(|m| {
                let network = m.hub.network();
                let now = tally_relay::network::wall_ms();
                network.selection.mlat_areas(&network.directory, now).len() == areas.len()
                    && network.selection.raw_sources(&network.directory, now).len() >= 2
                    && network.peers.counts().1 >= 2
                    && keys
                        .iter()
                        .filter(|key| **key != m.address.key)
                        .all(|key| network.directory.knows(key))
            });
            if ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "the relays never found one another".to_owned())?;

    // The feeding starts the moment a window comes due, so the one `recent` fills is as young as
    // it can be and its finals reach the precise world well inside its 90 s. The scenario is
    // built, and its feeds signed, before that moment comes: a minute ahead.
    let mut at = wall_ms() + 60_000;
    while (bin_of(at.saturating_sub(SETTLE_MS)) - 2).rem_euclid(STRIDE) != 0 {
        at += 100;
    }
    let (scenario, split_ms) = recent_at(31, at);
    let scenario = Scenario {
        // A second phase long enough to outlast the first window's models reaching the relays
        // (they carry 90 s past its end), however slow the machine.
        duration_s: scenario.duration_s + 90.0,
        // Fewer ADS-B aircraft than `recent`'s: enough to keep the clocks, and a stream three
        // relays in one test process keep up with in real time.
        adsb_aircraft: 4,
        ..scenario
    };
    let simulation = sim::run(&scenario);
    let raw = Raw::of(&simulation, split_ms);
    let feeds = simulation.feeds().map_err(text)?;

    let client = &members[0];
    let stream = TcpStream::connect(&client.address.address)
        .await
        .map_err(text)?;
    let mut session = noise::connect(
        stream,
        &Identity::generate().map_err(text)?,
        &client.address.key,
        Role::Subscriber,
    )
    .await
    .map_err(text)?;
    session
        .writer
        .send(&[Record::Subscribe {
            streams: Streams::POSITIONS
                .with(Streams::CLOCK_MODELS)
                .with(Streams::PROVISIONAL)
                .with(Streams::REGIONAL)
                .with(Streams::WORLD)
                .with(Streams::WORLD_PRECISE),
            regions: Vec::new(),
        }])
        .await
        .map_err(text)?;
    // The client reads as fast as the relay sends and checks apart (the checks are slower than
    // the stream), and says it is there as a real one does.
    let mut reader = session.reader;
    let mut writer = session.writer;
    tokio::spawn(async move {
        let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
        loop {
            heartbeat.tick().await;
            if writer.send(&[Record::Heartbeat]).await.is_err() {
                return;
            }
        }
    });
    // Each record with when it reached the client: the checks below take their time (a model is
    // verified against the raw), and a record waiting behind them has already arrived.
    let (received, mut records) = tokio::sync::mpsc::unbounded_channel::<(u64, Record)>();
    tokio::spawn(async move {
        let mut got = Vec::new();
        while reader.recv(&mut got).await.is_ok() {
            let arrived = wall_ms();
            for record in got.drain(..) {
                if received.send((arrived, record)).is_err() {
                    return;
                }
            }
        }
    });

    // A third of the receivers on each relay, each naming the relay it chose (as tally-feed's
    // description does: that relay is the origin of its regional product): the past at once,
    // then each batch once its second has ended.
    // Connected ahead too; each sends from the moment `start` turns.
    let (start, started) = watch::channel(false);
    let (second, go) = watch::channel(false);
    let mut first_phase = 0;
    for (index, feed) in feeds.into_iter().enumerate() {
        let relay = members[index % members.len()].address.clone();
        let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
        let mut session = noise::connect(stream, &feed.identity, &relay.key, Role::Feeder)
            .await
            .map_err(text)?;
        let mut described = feed.info.content().map_err(text)?;
        described.relays = vec![relay.key];
        let info = tally_wire::ReceiverInfo::sign(&feed.identity, &described).map_err(text)?;
        let mut early = vec![Record::ReceiverInfo(info)];
        let mut late = Vec::new();
        for batch in feed.batches {
            let wall = batch.content().map_err(text)?.wall_ms;
            // The bin right after the first phase is the last of its window's (`recent`), which
            // the relays solve as the test opens them; it is left empty, so the models are the
            // first phase's alone wherever the second phase has reached. Everything after it is
            // fed as it happens.
            if wall < split_ms {
                first_phase += 1;
                early.push(Record::Batch(batch));
            } else if wall >= split_ms + GRID_MS {
                late.push((wall, Record::Batch(batch)));
            }
        }
        let mut go = go.clone();
        let mut started = started.clone();
        tokio::spawn(async move {
            if started.wait_for(|start| *start).await.is_err() {
                return;
            }
            for record in early {
                if session.writer.send(&[record]).await.is_err() {
                    return;
                }
            }
            if go.wait_for(|go| *go).await.is_err() {
                return;
            }
            for (wall, record) in late {
                let wait = wall.saturating_sub(wall_ms());
                tokio::time::sleep(Duration::from_millis(wait)).await;
                if session.writer.send(&[record]).await.is_err() {
                    return;
                }
            }
            std::future::pending::<()>().await;
            drop(session);
        });
    }
    tokio::time::sleep(Duration::from_millis(at.saturating_sub(wall_ms()))).await;
    let _ = start.send(true);
    // Every relay's engine holds every receiver's first phase, by its own feeders, its sharing
    // members and its one-hop raw links; then they solve.
    for member in &members {
        timeout(WAIT, async {
            while member.mlat.host.ingested() < first_phase {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| {
            let state: Vec<_> = members
                .iter()
                .map(|m| {
                    let network = m.hub.network();
                    (
                        m.mlat.host.ingested(),
                        network.shared_in(),
                        network.peers.counts(),
                        network.directory.len(),
                    )
                })
                .collect();
            format!(
                "an engine short of {first_phase} batches: (ingested, shared in, links, offers) \
                 per relay {state:?}"
            )
        })?;
    }
    for member in &members {
        member.mlat.open.store(true, Ordering::SeqCst);
    }
    let _ = second.send(true);

    let mut assembler = Assembler::new(256 * 1024 * 1024, 1_024);
    let mut models: BTreeMap<[u8; 32], Checked> = BTreeMap::new();
    let mut inputs: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
    let mut origins: BTreeMap<[u8; 32], Record> = BTreeMap::new();
    let mut heard = Network::default();
    let mut waiting: Vec<Positions> = Vec::new();
    let outcome = timeout(Duration::from_secs(240), async {
        while !heard.done() {
            let (arrived, record) = records
                .recv()
                .await
                .ok_or("the relay closed the client's session")?;
            let assembled = match &record {
                Record::ClockModelPart(part) => assembler.part(part.clone()),
                Record::ClockModel(model) => {
                    model.verify().map_err(text)?;
                    assert!(keys.contains(&model.engine().map_err(text)?));
                    assembler.manifest(model.clone()).map_err(text)?
                }
                Record::Positions(positions) => {
                    positions.verify().map_err(text)?;
                    let engine = positions.engine().map_err(text)?;
                    assert!(keys.contains(&engine), "positions from outside the network");
                    // Checked once the client holds every model it cites: a model and the
                    // positions under it may come by different relays, in either order.
                    waiting.push(positions.clone());
                    origins.insert(positions.hash(), record.clone());
                    None
                }
                Record::Provisional(positions) => {
                    positions.verify().map_err(text)?;
                    heard.provisional += 1;
                    let newest = positions
                        .solutions()
                        .map_err(text)?
                        .solutions
                        .iter()
                        .map(|solution| solution.transmitted.unix_ms)
                        .max()
                        .unwrap_or(0);
                    // The first phase is fed all at once, long after it was heard; only what is
                    // fed as it happens says how fast a provisional comes.
                    if newest >= split_ms + GRID_MS {
                        heard.provisional_lag_ms =
                            heard.provisional_lag_ms.max(arrived.saturating_sub(newest));
                    }
                    origins.insert(positions.hash(), record.clone());
                    None
                }
                Record::RegionalBatch(regional) => {
                    regional.verify().map_err(text)?;
                    assert!(keys.contains(&regional.signer().map_err(text)?));
                    heard.regional += 1;
                    origins.insert(regional.hash(), record.clone());
                    None
                }
                Record::WorldPositions(world) => {
                    world.verify().map_err(text)?;
                    assert_eq!(world.signer().map_err(text)?, client.address.key);
                    let content = world.content().map_err(text)?;
                    let (checked, mlat) = check_world(&content, &origins, &inputs, false)?;
                    heard.live_fixes += checked;
                    heard.live_mlat += mlat;
                    None
                }
                Record::WorldPrecise(world) => {
                    world.verify().map_err(text)?;
                    assert_eq!(world.signer().map_err(text)?, client.address.key);
                    let content = world.content().map_err(text)?;
                    let (checked, mlat) = check_world(&content, &origins, &inputs, true)?;
                    heard.precise_fixes += checked;
                    heard.precise_mlat += mlat;
                    None
                }
                _ => None,
            };
            if let Some((manifest, content)) = assembled {
                let model = publish::decode(&content.model, content.spec_version).map_err(text)?;
                assert_eq!(content.inputs, publish::inputs_id(&model));
                inputs.insert(manifest.id(), content.inputs);
                match confirm_model(model, &raw)? {
                    Some(checked) => {
                        heard.models += 1;
                        models.insert(manifest.id(), checked);
                    }
                    None => heard.unconfirmed += 1,
                }
            }
            let (ready, still): (Vec<_>, Vec<_>) = std::mem::take(&mut waiting)
                .into_iter()
                .partition(|positions| {
                    positions.solutions().is_ok_and(|content| {
                        content
                            .solutions
                            .iter()
                            .all(|solution| models.contains_key(&solution.clock_model))
                    })
                });
            waiting = still;
            for positions in ready {
                let engine = positions.engine().map_err(text)?;
                heard.verified += check_positions(&positions, engine, &models, &raw)?;
                heard.solvers.insert(engine);
            }
        }
        Ok::<_, String>(())
    })
    .await;
    let links: Vec<_> = members
        .iter()
        .map(|m| m.hub.network().peers.counts())
        .collect();
    eprintln!(
        "network: {heard:?}; (sharing member links, one-hop raw links) per relay {links:?}; \
         world {:?}",
        client.hub.network().products.report()
    );
    match outcome {
        Ok(result) => result?,
        Err(_) => return Err(format!("before the deadline: {heard:?}")),
    }
    for (members_up, raw_up) in links {
        assert!(raw_up >= 2, "one-hop raw links: {raw_up}");
        assert!(members_up >= 1, "sharing member links: {members_up}");
    }
    // Data moved over member links only: every relay took group records from its members, and no
    // directory link brought any.
    for member in &members {
        let network = member.hub.network();
        assert!(network.shared_in() > 0, "no group record reached a relay");
        assert_eq!(network.data_on_directory_links(), 0);
    }
    // Fast MLAT is fast (RFC-0174 §2.4): a provisional position reaches the client within the
    // live world's seal (`WORLD_SETTLE_MS`, 4 s: about 3 s at most to publish, measured, with the
    // hops between relays), or the live world would have sealed its second without it. The RFC's
    // median is 1.34 s and its 95th percentile 1.65 s; this is the longest of all of them, three
    // relays in one test process.
    assert!(heard.provisional > 0, "{heard:?}");
    assert!(
        heard.provisional_lag_ms <= tally_relay::products::WORLD_SETTLE_MS,
        "a provisional reached the client {} ms after its transmission",
        heard.provisional_lag_ms
    );
    Ok(())
}

/// Every relay's MLAT choice for each area, as it computes it: (relay, areas it solves).
fn choices(members: &[Member]) -> Vec<(PublicKey, Vec<Region>)> {
    let now = tally_relay::network::wall_ms();
    members
        .iter()
        .map(|m| {
            let network = m.hub.network();
            (
                m.address.key,
                network.selection.mlat_areas(&network.directory, now),
            )
        })
        .collect()
}

/// The relays solving `area`, by their own choice.
fn solving(choices: &[(PublicKey, Vec<Region>)], area: Region) -> BTreeSet<PublicKey> {
    choices
        .iter()
        .filter(|(_, areas)| areas.contains(&area))
        .map(|(key, _)| *key)
        .collect()
}

/// A relay on a runtime of its own, so that it can be killed outright: every task of it (its
/// listener, its links, its network duties, its MLAT's steps) ends at once and it signs nothing
/// more, as a relay whose host died.
struct Killable {
    member: Member,
    kill: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Killable {
    /// `member`'s relay, dialling `upstream` for the directory if given.
    fn start(
        identity: Identity,
        areas: Vec<Region>,
        asn: u32,
        accepted: Vec<PublicKey>,
        upstream: Option<RelayAddress>,
    ) -> Result<Self> {
        let (started, member_out) = std::sync::mpsc::channel::<Result<Member>>();
        let (kill, killed) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = started.send(Err(error.to_string()));
                    return;
                }
            };
            let made = runtime.block_on(async {
                let made = member(identity.clone(), &areas, asn, false, &accepted).await?;
                if let Some(upstream) = upstream {
                    tokio::spawn(tally_relay::link::upstream(
                        tally_relay::config::Upstream {
                            address: upstream.address,
                            key: upstream.key,
                        },
                        identity,
                        Arc::clone(&made.hub),
                    ));
                }
                Ok(made)
            });
            let _ = started.send(made);
            let _ = killed.recv();
            runtime.shutdown_background();
        });
        let member = member_out.recv().map_err(text)??;
        Ok(Self {
            member,
            kill: Some(kill),
            thread: Some(thread),
        })
    }

    fn kill(&mut self) {
        self.kill.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Killable {
    fn drop(&mut self) {
        self.kill();
    }
}

/// RFC-0174 §2.3 across four relays taking the same areas and offering MLAT: each area is solved
/// by exactly three of them, the first three of the weighted rendezvous ranking, which every relay
/// computes alike; the fourth is not chosen and solves nothing there. When a chosen relay dies
/// outright (killed: it withdraws nothing and says nothing), its areas move to the next in the
/// ranking once its last offer has lapsed (`directory::OFFER_LIFETIME_MS`, three minutes from its
/// last re-signing, by its own signed times): the relay that was not chosen takes them, and the
/// other two keep theirs, on every surviving relay alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_four_relays_three_solve_an_area_and_a_dead_one_is_replaced_by_the_next() -> Result {
    let areas = areas()?;
    let identities: Vec<Identity> = (0..4)
        .map(|_| Identity::generate().map_err(text))
        .collect::<Result<_>>()?;
    let joining: Vec<PublicKey> = identities[1..].iter().map(Identity::public).collect();
    let mut relays: Vec<Killable> = Vec::new();
    for (at, identity) in identities.iter().enumerate() {
        let asn = 64_510 + at as u32;
        let accepted = if at == 0 { joining.clone() } else { Vec::new() };
        let upstream = relays.first().map(|first| first.member.address.clone());
        relays.push(Killable::start(
            identity.clone(),
            areas.clone(),
            asn,
            accepted,
            upstream,
        )?);
    }
    let alive = |relays: &[Killable]| -> Vec<Member> {
        relays
            .iter()
            .filter(|relay| relay.thread.is_some())
            .map(|relay| Member {
                address: relay.member.address.clone(),
                hub: Arc::clone(&relay.member.hub),
                mlat: Arc::clone(&relay.member.mlat),
            })
            .collect()
    };
    let keys: BTreeSet<PublicKey> = relays.iter().map(|r| r.member.address.key).collect();
    // Every relay knows the other three, and each area has its three.
    let settled = |members: &[Member], expect: &dyn Fn(&BTreeSet<PublicKey>) -> bool| {
        let choices = choices(members);
        areas.iter().all(|area| expect(&solving(&choices, *area)))
    };
    let members = alive(&relays);
    timeout(WAIT, async {
        loop {
            let known = members.iter().all(|m| {
                keys.iter()
                    .filter(|key| **key != m.address.key)
                    .all(|key| m.hub.network().directory.knows(key))
            });
            if known && settled(&members, &|solvers| solvers.len() == 3) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "the relays never chose three an area: {:?}",
            choices(&members)
        )
    })?;
    let before = choices(&members);
    // An area some relay was not chosen for: it solves nothing there.
    let (area, left_out) = areas
        .iter()
        .find_map(|area| {
            let solvers = solving(&before, *area);
            keys.iter()
                .find(|key| !solvers.contains(key))
                .map(|key| (*area, *key))
        })
        .ok_or("every relay chosen for every area")?;
    let chosen = solving(&before, area);
    assert_eq!(chosen.len(), 3);
    assert!(!chosen.contains(&left_out));
    // Not chosen, it hosts no MLAT for the area: its engine was handed no area of it.
    let unchosen = members
        .iter()
        .find(|m| m.address.key == left_out)
        .ok_or("no such relay")?;
    assert!(
        !unchosen
            .hub
            .network()
            .selection
            .mlat_areas(&unchosen.hub.network().directory, wall_ms())
            .contains(&area)
    );

    // One chosen relay dies outright: not the first, whose directory link the others joined by,
    // so what is tested is the offer's lapse and not a directory going dark.
    let first = relays[0].member.address.key;
    let gone = *chosen
        .iter()
        .find(|key| **key != first)
        .ok_or("only the first chosen")?;
    let dead = relays
        .iter()
        .position(|relay| relay.member.address.key == gone)
        .ok_or("no such relay")?;
    let killed_at = std::time::Instant::now();
    relays[dead].kill();
    let members = alive(&relays);
    let expected: BTreeSet<PublicKey> = chosen
        .iter()
        .copied()
        .filter(|key| *key != gone)
        .chain([left_out])
        .collect();
    // Its last re-signing was at most `OWN_RESIGN_EVERY_MS` before it died, so its offers lapse
    // within `OFFER_LIFETIME_MS` of the kill; a tick and a step on top.
    let lifetime = Duration::from_millis(tally_relay::directory::OFFER_LIFETIME_MS);
    let margin = Duration::from_secs(15);
    timeout(lifetime + margin, async {
        loop {
            let choices = choices(&members);
            // Every surviving relay sees the new three.
            if solving(&choices, area) == expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "the area never moved from the dead relay within {:?}: expected {expected:?}, have {:?}",
            lifetime + margin,
            solving(&choices(&members), area)
        )
    })?;
    let moved = killed_at.elapsed();
    // Not before its offers could lapse: only a signed offer, or its lapse, moves the choice.
    assert!(
        moved
            >= lifetime.saturating_sub(Duration::from_millis(
                tally_relay::directory::OWN_RESIGN_EVERY_MS
            )),
        "moved {moved:?} after the kill, before its offers could lapse"
    );
    // And no surviving relay still counts the dead one anywhere.
    timeout(WAIT, async {
        loop {
            if settled(&members, &|solvers| {
                !solvers.contains(&gone) && solvers.len() == 3
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .map_err(|_| format!("the dead relay still solves: {:?}", choices(&members)))?;
    Ok(())
}
