//! One program, end to end (RFC-0174 §2.1, §2.3): the simulator's receivers feed a real relay as
//! feeders, the relay hosts the MLAT engine for the area they are in, and what it signs with its
//! own key reaches its readers, with no engine process and no engine link anywhere. A relay link
//! is handed the clock models and raw positions (read in process, as a member's sharing carries
//! them: [`relay_view`]), and the test checks them as any relay would: every model by the model
//! verifier against the raw, every fix by the fix verifier under the model it cites. A plain
//! client of the relay is sent their client forms alone (RFC-0171 §3.5): positions tagged, and
//! passed only once the relay checked them against its own raw; model summaries; never raw, a site
//! or a full model. Then the same across two relays: the feeders on a relay that solves nothing, whose raw
//! reaches the relay that solves their area in one hop. Then RFC-0174 whole, across three relays
//! that find one another from signed offers alone: selection, one-hop raw, sharing, and the
//! regional and world products, each checked by the client. And the choice itself across four
//! relays: one is not chosen for an area (k is three), and when a chosen one dies outright, the
//! area moves to the next by rendezvous once its offers lapse.
//!
//! In the first three tests the host is pinned to the simulator's areas, so they test the hosting
//! and nothing else. The scenario begins in the past, so the relays' ingest clock ([`Clock`])
//! walks it a step at a time from its start, and each feeder sends a batch once the clock reaches
//! the batch's own wall clock: raw is late by its stamp, never by when a step ran (RFC-0181). The
//! clock moves a step only once every relay has been offered what was fed and its hosted MLAT has
//! stepped to it and published (`stepping`), and never past the wall clock: through the past as
//! fast as the relays keep up, then as it happens. So nothing here measures time, and no step runs
//! on a clock a slow machine has not caught up with; what it asserts it asserts in stamps (how
//! fast a fix comes on the wall clock is `tally-load`'s to measure, a bed).
//!
//! The client of the checks holds the whole simulation's raw (`Raw`): a model cites the batches
//! at or below its frontiers, which it rebuilds from what it holds, and a fix is judged within
//! what it considered, so holding more than an engine had is never held against it.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;
use tally_wire::clocks::recorded::judged;

use tally_mlat::engine::Settings;
use tally_mlat_solver::pair::Models;
use tally_mlat_solver::sim::{self, Scenario, Simulation};
use tally_mlat_solver::{
    Arrived, PairCache, PairModel, Prepared, Reception, Sites, publish, verify_pair_fix,
    verify_pair_model_held,
};
use tally_relay::fanout::Filter;
use tally_relay::hub::Hub;
use tally_relay::mlat_host::stepping::{Clock, Hosting, step};
use tally_relay::mlat_host::{HostedMlat, MlatHost, MlatReport, StepClock};
use tally_relay::subscription::Subscription;
use tally_wire::noise;
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{
    Assembler, Identity, Location, Positions, PublicKey, Reader, Record, Region, Regions,
    RelayAddress, Role, Streams,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Each relay's stages on threads of their own, as a relay runs them (`Hub::staged`): its seals
/// never hold up its connections, and its MLAT raw is taken into its raw shards by its ingest
/// workers, never on its engine's thread. Two threads a stage, so the shards are split between
/// workers as they are on a relay.
const RELAY_THREADS: tally_relay::ingest::Threads = tally_relay::ingest::Threads {
    ingest: 2,
    message: 2,
    seal: 2,
};

type Result<T = ()> = std::result::Result<T, String>;

/// The same key again, from its file form, for a test that hands a key over and still signs or
/// dials as it: `Identity` is not `Clone`.
fn twin(identity: &Identity) -> Result<Identity> {
    Identity::from_base64(&identity.to_base64()).map_err(|error| error.to_string())
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// How long a test waits for the event it asserts before calling it a hang: a guard on a relay
/// that never gets there, never a verdict on how fast the machine running the test is.
const WAIT: Duration = Duration::from_secs(180);
/// How long the clock may stand still before the test says why (`stepping`): inside `WAIT`, so
/// its reason comes before the client's deadline.
const STOOD: Duration = Duration::from_secs(120);

/// Moves `clock` for as long as the test runs, every host fed every batch of `walls`
/// (`stepping::step`).
fn stepping(
    clock: Arc<Clock>,
    hosts: Vec<Arc<dyn Hosting>>,
    walls: Vec<u64>,
) -> tokio::task::JoinHandle<Result> {
    step(
        clock,
        hosts
            .into_iter()
            .map(|host| (host, walls.clone()))
            .collect(),
        STOOD,
    )
}

/// The relay's hosted MLAT, its areas pinned (in place of `selection`'s choice).
struct Pinned {
    host: HostedMlat,
    areas: Regions,
}

impl Hosting for Pinned {
    fn host(&self) -> &HostedMlat {
        &self.host
    }
}

impl MlatHost for Pinned {
    fn set_areas(&self, _chosen: Regions, descriptions: Vec<tally_mlat::intake::SiteRecord>) {
        self.host.set_areas(self.areas.clone(), descriptions);
    }

    fn offer_description(&self, info: &tally_mlat::intake::SiteRecord, stamp_ms: u64) {
        self.host.offer_description(info, stamp_ms);
    }

    fn offer_batch(&self, batch: &std::sync::Arc<tally_wire::Decoded>, now_ms: u64) {
        self.host.offer_batch(batch, now_ms);
    }

    fn raw(&self) -> Option<Arc<dyn tally_relay::standing::Raw>> {
        self.host.raw()
    }

    fn gate(&self) -> Option<Arc<tally_mlat_solver::gate::Gate>> {
        self.host.gate()
    }

    fn take_published(&self, watermark: tally_relay::products::Watermark) -> Vec<Record> {
        self.host.take_published(watermark)
    }

    fn cores(&self) -> u16 {
        self.host.cores()
    }

    fn report(&self) -> MlatReport {
        self.host.report()
    }

    fn take_own_models(&self) -> Vec<tally_relay::mlat_host::OwnModel> {
        self.host.take_own_models()
    }
}

/// The tests of this binary, as the build runs them: one target each (`crates/relay/BUILD.bazel`,
/// `_MLAT_HOST_TESTS`, each `--exact` with [`EVERY_TEST_HAS_ONE_TARGET`]), whose names the build
/// hands the binary when it compiles it. None under Cargo, which runs every test of the binary at
/// once and so selects none by name.
const TARGETS: Option<&str> = option_env!("MLAT_HOST_TESTS");

/// The guard every target runs beside its own test (`every_test_has_one_target`).
const EVERY_TEST_HAS_ONE_TARGET: &str = "every_test_has_one_target";

/// A target selects its test by exact name, and libtest runs no test at all, green,
/// for a name it does not have. So every target runs this beside its own: the tests this binary
/// has, as libtest lists them (the binary asked for its own list), are exactly the ones the
/// build's targets name, so a test renamed, added or removed without its target fails every
/// target, and no target can run nothing and pass.
#[test]
fn every_test_has_one_target() -> Result {
    let Some(targets) = TARGETS else {
        // Under Cargo every test here runs in this one binary: there is no target to miss one.
        return Ok(());
    };
    let named: BTreeSet<&str> = targets.split_whitespace().collect();
    let exe = std::env::current_exe().map_err(text)?;
    let listed = std::process::Command::new(&exe)
        .args(["--list", "--format", "terse"])
        .output()
        .map_err(text)?;
    if !listed.status.success() {
        return Err(format!("{} --list: {}", exe.display(), listed.status));
    }
    let listed = String::from_utf8(listed.stdout).map_err(text)?;
    let tests: BTreeSet<&str> = listed
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .filter(|test| *test != EVERY_TEST_HAS_ONE_TARGET)
        .collect();
    assert!(!tests.is_empty(), "libtest listed no tests: {listed}");
    assert_eq!(
        tests, named,
        "the tests here and the targets that run them (crates/relay/BUILD.bazel, _MLAT_HOST_TESTS)"
    );
    // And the test this run was asked for is one of them.
    let asked: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| !arg.starts_with('-') && arg != EVERY_TEST_HAS_ONE_TARGET)
        .collect();
    for test in &asked {
        assert!(
            named.contains(test.as_str()),
            "asked for {test}, which no target names"
        );
    }
    Ok(())
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

/// The wall clock now (a relay's clock started now reads it).
fn wall_ms() -> u64 {
    tally_relay::clock::RelayClock::system().judged().ms()
}

/// How far in the past a scenario starts: its first half is fed as fast as the relays keep up,
/// and its trailing windows fill (`tally_wire::budget::TRAILING_WINDOW`) before it is fed as it
/// happens.
const PAST_MS: u64 = 30_000;

/// A scenario of a minute whose first half is past by the relay's clock and whose second comes
/// as it happens: a step a second solves what had arrived (RFC-0171 §3.8.1, "MLAT in seconds").
fn recent(seed: u64) -> Scenario {
    recent_at(seed, wall_ms())
}

/// As `recent`, by the relay's clock at `now_ms`.
fn recent_at(seed: u64, now_ms: u64) -> Scenario {
    let start_ms = now_ms - PAST_MS;
    Scenario {
        duration_s: 60.0,
        modes_aircraft: 16,
        midnight_unix_ms: start_ms - start_ms % 86_400_000,
        start_tod_s: (start_ms % 86_400_000) as f64 / 1000.0,
        ..Scenario::new(seed)
    }
}

/// A relay with a fresh key that accepts `relays` as relays, hosting `mlat` if given.
async fn relay(
    identity: Identity,
    relays: &[PublicKey],
    mlat: Option<Arc<Pinned>>,
    clock: &Arc<Clock>,
) -> Result<(RelayAddress, Arc<Hub>)> {
    let key = identity.public();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = listener.local_addr().map_err(text)?;
    // Every feeder here comes from loopback: more than one host's share of connections.
    let hub = Arc::new(
        Hub::clocked(8, clock.clock(), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(64)
            // Its raw planned where it hosts MLAT, as `tally-relay` plans it.
            .memory(tally_relay::hub::DEFAULT_MEMORY, mlat.is_some())
            .staged(RELAY_THREADS)?,
    );
    if let Some(mlat) = mlat {
        hub.host_mlat(mlat)?;
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
        tally_wire::Signer::new(twin(identity)?, std::sync::Arc::new(|| true)),
        7,
        Settings {
            regions: Regions::default(),
            threads: 4,
            capacity: tally_mlat::engine::Capacity::default(),
        },
        // Its clock walks no faster than it keeps up (`stepping`): it is never overloaded.
        StepClock::KEEPING_UP,
    )?;
    // Solving from the first offer on: the relay's own network task re-states it every tick.
    let areas = Regions::new(areas);
    host.set_areas(areas.clone(), Vec::new());
    Ok(Arc::new(Pinned { host, areas }))
}

/// A client of the relay's clock models and positions: its reading half.
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
            streams: mlat_streams(),
            regions: Vec::new(),
        }])
        .await
        .map_err(text)?;
    // The writing half stays open for as long as the client reads, and says it is there as a
    // real client does.
    tokio::spawn(async move {
        let mut writer = session.writer;
        let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
        loop {
            heartbeat.tick().await;
            if writer.send(&[Record::Heartbeat]).await.is_err() {
                return;
            }
        }
    });
    Ok(session.reader)
}

/// What `hub`'s fan-out hands a relay link subscribed to `streams` of the whole world, record by
/// record: the clock models and raw positions a member's sharing carries to other relays, which
/// no test session can hold, read in process and as fast as they come (the checks are slower
/// than the stream).
fn relay_view(hub: &Hub, streams: Streams) -> mpsc::UnboundedReceiver<Record> {
    let listener = hub.listen(
        u64::MAX - 1,
        Filter::Subscription(Subscription {
            streams,
            regions: Vec::new(),
        }),
    );
    let (sent, received) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut taken = Vec::new();
        while listener.recv_many(&mut taken, 256).await.is_ok() {
            for one in taken.drain(..) {
                if sent.send((*one.into_item().record).clone()).is_err() {
                    return;
                }
            }
        }
    });
    received
}

/// A client's session read as fast as the relay sends, record by record.
fn pumped(mut reader: Reader<TcpStream>) -> mpsc::UnboundedReceiver<Record> {
    let (sent, received) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut got = Vec::new();
        while reader.recv(&mut got).await.is_ok() {
            for record in got.drain(..) {
                if sent.send(record).is_err() {
                    return;
                }
            }
        }
    });
    received
}

/// What no client may be sent (RFC-0171 §3.5): raw, a site, a description that carries one, a
/// regional batch's counters, raw positions, or a full clock model.
fn relay_only(record: &Record) -> bool {
    match record {
        Record::ReceiverInfo(info) => info.carries_site(),
        Record::Batch(_)
        | Record::RelayBatch(_)
        | Record::RegionalBatch(_)
        | Record::ReceiverSite(_)
        | Record::ClockModel(_)
        | Record::ClockModelPart(_) => true,
        Record::Positions(positions) => !positions.is_tagged(),
        _ => false,
    }
}

/// What a client was sent of the MLAT.
#[derive(Debug, Default)]
struct Told {
    fixes: usize,
    summaries: usize,
}

/// Reads a client until it holds tagged fixes and a model summary, each signed by one of
/// `relays`; fails on anything no client may be sent.
async fn told(client: &mut mpsc::UnboundedReceiver<Record>, relays: &[PublicKey]) -> Result<Told> {
    let mut told = Told::default();
    let outcome = timeout(WAIT, async {
        while told.fixes == 0 || told.summaries == 0 {
            let record = client
                .recv()
                .await
                .ok_or("the relay closed the client's session")?;
            assert!(!relay_only(&record), "a client was sent {record:?}");
            match &record {
                Record::Positions(positions) => {
                    positions.verify().map_err(text)?;
                    assert!(relays.contains(&positions.engine().map_err(text)?));
                    told.fixes += positions.tagged_fixes().map_err(text)?.fixes.len();
                }
                Record::ClientClockModel(summary) => {
                    assert!(relays.contains(&summary.signer().map_err(text)?));
                    told.summaries += 1;
                }
                _ => {}
            }
        }
        Ok::<_, String>(())
    })
    .await;
    match outcome {
        Ok(result) => result.map(|()| told),
        Err(_) => Err(format!("before the deadline: {told:?}")),
    }
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

/// Every simulated receiver of `simulation`, a feeder of `relay`: its description at once, then
/// each batch once `clock` reaches its wall clock. The wall clocks of the batches fed.
async fn feed(
    simulation: &Simulation,
    relay: &RelayAddress,
    clock: &Arc<Clock>,
) -> Result<Vec<u64>> {
    let mut walls = Vec::new();
    for feed in simulation.feeds().map_err(text)? {
        let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
        let session = noise::connect(stream, &feed.identity, &relay.key, Role::Feeder)
            .await
            .map_err(text)?;
        let mut batches = Vec::new();
        for batch in feed.batches {
            let wall = batch.content().map_err(text)?.wall_ms;
            walls.push(wall);
            batches.push((wall, Record::Batch(batch)));
        }
        sending(
            session,
            vec![
                Record::ReceiverInfo(feed.info),
                Record::ReceiverSite(feed.site),
            ],
            batches,
            clock,
        );
    }
    Ok(walls)
}

/// A feeder's session sending `described` (its description and its site), then each of
/// `batches` once `clock` reaches its wall clock; connected for as long as the test runs, as a
/// real feeder stays.
fn sending(
    mut session: tally_wire::noise::Session<TcpStream>,
    described: Vec<Record>,
    batches: Vec<(u64, Record)>,
    clock: &Arc<Clock>,
) {
    let clock = Arc::clone(clock);
    tokio::spawn(async move {
        if session.writer.send(&described).await.is_err() {
            return;
        }
        for (wall, record) in batches {
            clock.reached(wall).await;
            if session.writer.send(&[record]).await.is_err() {
                return;
            }
        }
        std::future::pending::<()>().await;
        drop(session);
    });
}

/// The clock of a scenario's start: the step its first batch is in.
fn start_of(simulation: &Simulation) -> Result<u64> {
    let first = simulation
        .receptions
        .iter()
        .map(|reception| reception.wall_ms)
        .min()
        .ok_or("a scenario heard nothing")?;
    Ok(first / tally_relay::mlat_host::STEP_MS * tally_relay::mlat_host::STEP_MS)
}

/// The raw the client holds: the whole simulation's, as its receivers' batches arrived, by the
/// receivers' signed sites, and its receptions by their message for the fix verifier.
struct Raw {
    arrived: Arrived,
    sites: Sites,
    by_message: BTreeMap<Vec<u8>, Vec<Reception>>,
}

impl Raw {
    fn of(simulation: &Simulation) -> Self {
        let mut by_message: BTreeMap<Vec<u8>, Vec<Reception>> = BTreeMap::new();
        for reception in &simulation.receptions {
            by_message
                .entry(reception.message.to_vec())
                .or_default()
                .push(reception.clone());
        }
        Self {
            arrived: Arrived::holding(&simulation.receptions),
            sites: Sites::new(&simulation.sites()),
            by_message,
        }
    }
}

/// A model the model verifier passed, prepared: what the fixes under it are checked by.
type Checked = Prepared;

/// A model reassembled from the relay's records (`content`), checked by the model verifier against
/// the raw, with its pair model id (what fixes cite it by).
fn check_model(content: &tally_wire::ClockModelContent, raw: &Raw) -> Result<([u8; 32], Checked)> {
    let model: PairModel = publish::decode_pairs(&content.model).map_err(text)?;
    assert_eq!(Some(content.inputs), publish::inputs_id(&model));
    let verdict =
        verify_pair_model_held(&raw.sites, &model, &raw.arrived, &mut PairCache::default());
    assert!(verdict.passed(), "{:?}", verdict.failures);
    let id = publish::pair_model_id(&content.model);
    Ok((
        id,
        Prepared::of(model, id).ok_or("a model that cannot be prepared")?,
    ))
}

/// Every fix of a raw positions record, checked by the fix verifier under the models it cites
/// against the raw (one of each area its used hearers are in, its solution within what it
/// considered); how many.
fn check_positions(
    positions: &Positions,
    relay: PublicKey,
    models: &BTreeMap<[u8; 32], Checked>,
    raw: &Raw,
) -> Result<usize> {
    positions.verify().map_err(text)?;
    assert_eq!(positions.engine().map_err(text)?, relay);
    let content = positions.fixes().map_err(text)?;
    for fix in &content.fixes {
        let cited = fix
            .models
            .iter()
            .map(|id| models.get(id))
            .collect::<Option<Vec<_>>>()
            .ok_or("a fix cites a clock model the client never received")?;
        let under = Models::new(cited).ok_or("models that are no one fix's")?;
        let held = raw
            .by_message
            .get(fix.used().message())
            .map_or(&[][..], Vec::as_slice);
        let verdict = verify_pair_fix(
            &under,
            &publish::Stated::of(fix),
            content.spec_version,
            held,
        );
        assert!(verdict.passed(), "{:?}", verdict.failures);
    }
    Ok(content.fixes.len())
}

/// What a relay link was handed, checked.
#[derive(Debug, Default)]
struct Heard {
    verified: usize,
    models: usize,
}

/// Reads a relay link until `want` fixes are verified.
async fn listen(
    reader: &mut mpsc::UnboundedReceiver<Record>,
    relay: PublicKey,
    raw: &Raw,
    want: usize,
) -> Result<Heard> {
    let mut assembler = Assembler::new(256 * 1024 * 1024, 1_024);
    let mut models: BTreeMap<[u8; 32], Checked> = BTreeMap::new();
    let mut heard = Heard::default();
    let outcome = timeout(WAIT, async {
        while heard.verified < want {
            let record = reader
                .recv()
                .await
                .ok_or("the relay's fan-out let its relay link go")?;
            {
                let assembled = match record {
                    Record::ClockModelPart(part) => assembler.part(part),
                    Record::ClockModel(model) => {
                        model.verify().map_err(text)?;
                        assert_eq!(model.engine().map_err(text)?, relay);
                        assembler.manifest(model).map_err(text)?
                    }
                    // A relay link is handed the client forms too; the raw ones are what it checks.
                    Record::Positions(positions) if positions.is_tagged() => None,
                    // Each step's models come before the fixes that cite them (RFC-0174 §2.4).
                    Record::Positions(positions) => {
                        heard.verified += check_positions(&positions, relay, &models, raw)?;
                        None
                    }
                    _ => None,
                };
                if let Some((_, content)) = assembled {
                    heard.models += 1;
                    let (id, checked) = check_model(&content, raw)?;
                    models.insert(id, checked);
                }
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

/// The MLAT's streams, as a relay link and a client subscribe to them.
fn mlat_streams() -> Streams {
    Streams::POSITIONS.with(Streams::CLOCK_MODELS)
}

/// A relay link's records checked (`listen`), then what a client was sent of the same (`told`).
async fn read_both(
    view: &mut mpsc::UnboundedReceiver<Record>,
    client: &mut mpsc::UnboundedReceiver<Record>,
    relay: PublicKey,
    raw: &Raw,
    want: usize,
) -> Result<(Heard, Told)> {
    let heard = listen(view, relay, raw, want).await?;
    let told = told(client, &[relay]).await?;
    Ok((heard, told))
}

/// What a test heard, or why not: the clock's own error first when it stood still (a relay that
/// never caught up), which the client's deadline only follows from. The clock stops with the test.
async fn settled<T>(heard: Result<T>, stepper: tokio::task::JoinHandle<Result>) -> Result<T> {
    if heard.is_err() && stepper.is_finished() {
        stepper.await.map_err(text)??;
    } else {
        stepper.abort();
    }
    heard
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feeders_of_a_relay_hosting_mlat_give_its_clients_verifiable_positions() -> Result {
    let simulation = sim::run(&recent(31));
    let raw = Raw::of(&simulation);
    let identity = Identity::generate().map_err(text)?;
    let clock = Clock::at(start_of(&simulation)?);
    let mlat = pinned(&identity)?;
    let (relay, hub) = relay(identity, &[], Some(Arc::clone(&mlat)), &clock).await?;
    let before = hub.listening();
    let mut view = relay_view(&hub, mlat_streams());
    let mut client = pumped(client(&relay).await?);
    listening(&hub, before, 2).await?;
    let walls = feed(&simulation, &relay, &clock).await?;
    let stepper = stepping(clock, vec![Arc::clone(&mlat) as Arc<dyn Hosting>], walls);
    let heard = read_both(&mut view, &mut client, relay.key, &raw, 100).await;
    let (heard, told) = settled(heard, stepper).await?;
    assert!(heard.models > 0, "{heard:?}");
    assert!(told.fixes > 0 && told.summaries > 0, "{told:?}");
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
/// two sides held different limits. Every fix it publishes now passes the client's check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_fix_a_relay_publishes_passes_the_verifier_seed_53() -> Result {
    let simulation = sim::run(&recent(53));
    let raw = Raw::of(&simulation);
    let identity = Identity::generate().map_err(text)?;
    let clock = Clock::at(start_of(&simulation)?);
    let mlat = pinned(&identity)?;
    let (relay, hub) = relay(identity, &[], Some(Arc::clone(&mlat)), &clock).await?;
    let before = hub.listening();
    let mut view = relay_view(&hub, mlat_streams());
    let mut client = pumped(client(&relay).await?);
    listening(&hub, before, 2).await?;
    let walls = feed(&simulation, &relay, &clock).await?;
    let stepper = stepping(clock, vec![Arc::clone(&mlat) as Arc<dyn Hosting>], walls);
    let heard = read_both(&mut view, &mut client, relay.key, &raw, 100).await;
    let (heard, told) = settled(heard, stepper).await?;
    assert!(heard.models > 0, "{heard:?}");
    assert!(told.fixes > 0 && told.summaries > 0, "{told:?}");
    Ok(())
}

/// The relay holding the feeders offers no MLAT; the solving relay, the only one offering cores,
/// is chosen for the area. The feeders' relay verifies the solver's signed offer over a directory
/// link (`--upstream`, `--accept-relay`), so the solver's one-hop raw link (`peers`, which it opens
/// itself) is granted the raw of the area's border band, and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn raw_from_a_relay_that_solves_nothing_reaches_the_relay_that_solves_its_area_in_one_hop()
-> Result {
    let simulation = sim::run(&recent(41));
    let raw = Raw::of(&simulation);
    let areas = areas()?;
    let solving = Identity::generate().map_err(text)?;
    let holding = Identity::generate().map_err(text)?;
    let clock = Clock::at(start_of(&simulation)?);
    let mlat = pinned(&solving)?;
    let (feeders, feeders_hub) = offering(
        twin(&holding)?,
        &areas,
        64_521,
        None,
        &[solving.public()],
        &clock,
    )
    .await?;
    let (solver, solver_hub) = offering(
        twin(&solving)?,
        &areas,
        64_522,
        Some(Arc::clone(&mlat)),
        &[],
        &clock,
    )
    .await?;
    tokio::spawn(tally_relay::link::upstream(
        tally_relay::config::Upstream {
            address: feeders.address.clone(),
            key: feeders.key,
        },
        tally_wire::NoiseKey::of(twin(&solving)?),
        Arc::clone(&solver_hub),
    ));
    // The feeders' relay holds the solver's verified offer, and the solver keeps its one-hop raw
    // link to it.
    timeout(WAIT, async {
        loop {
            // By the relays' one clock, which their offers are signed and judged by.
            let now = solver_hub.now();
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
    let mut view = relay_view(&solver_hub, mlat_streams());
    let mut client = pumped(client(&solver).await?);
    listening(&solver_hub, before, 2).await?;
    let walls = feed(&simulation, &feeders, &clock).await?;
    let stepper = stepping(clock, vec![Arc::clone(&mlat) as Arc<dyn Hosting>], walls);
    let heard = read_both(&mut view, &mut client, solver.key, &raw, 40).await;
    let (heard, told) = settled(heard, stepper).await?;
    assert!(heard.models > 0, "{heard:?}");
    assert!(told.fixes > 0 && told.summaries > 0, "{told:?}");
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
    clock: &Arc<Clock>,
) -> Result<(RelayAddress, Arc<Hub>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = RelayAddress {
        key: identity.public(),
        address: listener.local_addr().map_err(text)?.to_string(),
    };
    let hub = Arc::new(
        Hub::clocked(64, clock.clock(), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .advertising(vec![address.clone()])
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(256)
            // Its areas, which its member sessions are planned from, as `tally-relay` plans them.
            .taking(areas.to_vec())
            // Its raw planned where it hosts MLAT, as `tally-relay` plans it.
            .memory(tally_relay::hub::DEFAULT_MEMORY, mlat.is_some())
            .staged(RELAY_THREADS)?,
    );
    let network = hub.network();
    network.admission.configure(asn, true);
    if let Some(mlat) = mlat {
        hub.host_mlat(mlat)?;
    }
    tokio::spawn(tally_relay::serve(
        listener,
        vec![identity],
        Arc::clone(&hub),
    ));
    Ok((address, hub))
}

/// A relay's hosted MLAT whose areas are `selection`'s (unlike [`Pinned`]).
struct Gated {
    host: HostedMlat,
}

impl Hosting for Gated {
    fn host(&self) -> &HostedMlat {
        &self.host
    }
}

impl MlatHost for Gated {
    fn set_areas(&self, chosen: Regions, descriptions: Vec<tally_mlat::intake::SiteRecord>) {
        self.host.set_areas(chosen, descriptions);
    }

    fn offer_description(&self, info: &tally_mlat::intake::SiteRecord, stamp_ms: u64) {
        self.host.offer_description(info, stamp_ms);
    }

    fn offer_batch(&self, batch: &std::sync::Arc<tally_wire::Decoded>, now_ms: u64) {
        self.host.offer_batch(batch, now_ms);
    }

    fn raw(&self) -> Option<Arc<dyn tally_relay::standing::Raw>> {
        self.host.raw()
    }

    fn gate(&self) -> Option<Arc<tally_mlat_solver::gate::Gate>> {
        self.host.gate()
    }

    fn take_published(&self, watermark: tally_relay::products::Watermark) -> Vec<Record> {
        self.host.take_published(watermark)
    }

    fn cores(&self) -> u16 {
        self.host.cores()
    }

    fn report(&self) -> MlatReport {
        self.host.report()
    }

    fn take_own_models(&self) -> Vec<tally_relay::mlat_host::OwnModel> {
        self.host.take_own_models()
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
/// chooses it for, and gathering the world product when `world`. It accepts `relays` on
/// directory links (`--accept-relay`).
async fn member(
    identity: Identity,
    areas: &[Region],
    asn: u32,
    world: bool,
    relays: &[PublicKey],
    clock: &Arc<Clock>,
) -> Result<Member> {
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let address = RelayAddress {
        key: identity.public(),
        address: listener.local_addr().map_err(text)?.to_string(),
    };
    // Subscribers here: the client, the other relays' one-hop raw links (one per chunk of the
    // border band) and their directory checks.
    let hub = Arc::new(
        Hub::clocked(64, clock.clock(), tally_relay::sharing::Deadlines::RELAY)
            .accepting_relays([tally_mlat_solver::sim::anchoring_relay().public()])
            .advertising(vec![address.clone()])
            .accepting_relays(relays.iter().copied())
            .max_connections_per_address(256)
            // Its areas, which its member sessions are planned from, as `tally-relay` plans them.
            .taking(areas.to_vec())
            // The world product when `world`, its fixes' store planned, as `--world` does.
            .gathering_world(world)
            // Its raw planned, as `tally-relay` plans a relay hosting MLAT.
            .memory(tally_relay::hub::DEFAULT_MEMORY, true)
            .staged(RELAY_THREADS)?,
    );
    let network = hub.network();
    network.admission.configure(asn, true);
    let mlat = Arc::new(Gated {
        host: HostedMlat::new(
            tally_wire::Signer::new(twin(&identity)?, std::sync::Arc::new(|| true)),
            u64::from(asn),
            Settings {
                regions: Regions::default(),
                threads: 2,
                capacity: tally_mlat::engine::Capacity::default(),
            },
            StepClock::KEEPING_UP,
        )?,
    });
    hub.host_mlat(Arc::clone(&mlat) as Arc<dyn MlatHost>)?;
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
    /// Fixes checked against the raw under the model each cites.
    verified: usize,
    /// The relays whose fixes were checked.
    solvers: std::collections::BTreeSet<PublicKey>,
    /// Models the verifier passed.
    models: usize,
    /// The most any positions record was published (its step, `issued_ms`) after its newest
    /// transmission.
    lag_ms: u64,
    regional: usize,
    /// World fixes checked against the record each cites (`products::check_fix`), and how many
    /// were multilaterated, traced to the positions they cite.
    world_fixes: usize,
    world_mlat: usize,
    /// The world's seconds the client was sent: the newest may still be filling, so the seal is
    /// checked over the ones before it (two at least).
    world_seconds: usize,
}

impl Network {
    fn done(&self) -> bool {
        self.verified >= 40
            && self.solvers.len() >= 3
            && self.regional > 0
            && self.world_fixes > 0
            && self.world_mlat > 0
            && self.world_seconds >= 2
    }
}

/// Checks every fix of one world record whose origin the client holds: (checked, of them MLAT).
fn check_world(
    content: &tally_wire::WorldPositionsContent,
    origins: &BTreeMap<[u8; 32], Record>,
    inputs: &BTreeMap<[u8; 32], [u8; 32]>,
) -> Result<(usize, usize)> {
    let (mut checked, mut mlat) = (0, 0);
    for fix in &content.fixes {
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

/// RFC-0174 end to end: three relays on three networks take the same areas; the simulator's
/// receivers feed them, a third each; the second and third each have one directory link
/// (`--upstream`) to the first, which accepts them (`--accept-relay`), and those links carry the
/// directory and nothing else. From the offers alone each relay verifies the others, `selection` chooses the
/// MLAT relays of each area (all three: k is three), each keeps one-hop raw links to the others,
/// and the sharing groups carry each relay's feeders' data (descriptions first) to the rest. A
/// relay link of the relay that gathers the world product is handed clock models and positions
/// from more than one relay, checked against the raw by the model verifier and the fix verifier;
/// the regional product; and a world whose fixes it traces to the records they cite,
/// multilaterated ones among them. A plain client of that relay is sent each product's
/// client form and nothing a client may not be (RFC-0171 §3.5). Every record of data crosses
/// between relays over member links: each relay takes group records from its members, and no
/// directory link carries any.
///
/// The first 30 s of the scenario are past, fed as fast as every relay keeps up, as the first test
/// holds its one relay; the rest is fed as it happens, each relay solving a step a second what
/// had arrived. The world seals a second `products::WORLD_SETTLE_MS` after it, so this takes about
/// two minutes.
///
/// It runs three relays in real time, so it states what it needs: an optimised build (Cargo's
/// `--release`; Bazel builds it so, `crates/relay/BUILD.bazel`) and the cores the target declares.
/// A debug build cannot keep up with the clock and is skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[cfg_attr(
    debug_assertions,
    ignore = "runs relays in real time: build it optimised (cargo test --release)"
)]
async fn three_relays_share_solve_and_serve_verifiable_positions_and_the_world_product() -> Result {
    let areas = areas()?;
    let identities = [
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
        Identity::generate().map_err(text)?,
    ];
    let joining: Vec<PublicKey> = identities[1..].iter().map(Identity::public).collect();
    // The relays' one clock: a minute behind the wall clock while they find one another (their
    // offers signed and judged by it), set to the scenario's start once it is built, which is
    // ahead of that and inside the offers' lifetime, then stepped (`stepping`).
    let clock = Clock::at(wall_ms() - 60_000);
    let mut members = Vec::new();
    for (identity, asn) in identities.iter().zip([64_501, 64_502, 64_503]) {
        let accepted = if asn == 64_501 { &joining[..] } else { &[] };
        members.push(
            member(
                twin(identity)?,
                &areas,
                asn,
                asn == 64_501,
                accepted,
                &clock,
            )
            .await?,
        );
    }
    for (identity, joiner) in identities[1..].iter().zip(&members[1..]) {
        tokio::spawn(tally_relay::link::upstream(
            tally_relay::config::Upstream {
                address: members[0].address.address.clone(),
                key: members[0].address.key,
            },
            tally_wire::NoiseKey::of(twin(identity)?),
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
                // By the relay's one clock, which its offers are signed and judged by.
                let now = m.hub.now();
                network.selection.mlat_areas(&network.directory, now) == Regions::new(areas.clone())
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

    // The feeding starts a minute from now: the scenario is built, and its feeds signed, before
    // that moment comes.
    let at = wall_ms() + 60_000;
    let scenario = recent_at(31, at);
    let scenario = Scenario {
        // A second phase long enough for its last seconds to reach the world
        // (`products::WORLD_SETTLE_MS` after them), however slow the machine.
        duration_s: scenario.duration_s + 60.0,
        // Fewer ADS-B aircraft than `recent`'s: enough to keep the clocks, and a stream three
        // relays in one test process keep up with in real time.
        adsb_aircraft: 4,
        ..scenario
    };
    let simulation = sim::run(&scenario);
    let raw = Raw::of(&simulation);
    let feeds = simulation.feeds().map_err(text)?;

    let client = &members[0];
    let every = Streams::POSITIONS
        .with(Streams::CLOCK_MODELS)
        .with(Streams::REGIONAL)
        .with(Streams::WORLD);
    // What a relay link of the client's relay is handed, checked below as any relay would: the
    // models, the raw positions and the regional batches with their counters.
    let mut records = relay_view(&client.hub, every);
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
            streams: every,
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
    // The client is sent the client forms alone: what it was sent, kind by kind, and anything no
    // client may be sent, counted as it comes.
    let sent_to_client = Arc::new(std::sync::Mutex::new(BTreeMap::<&'static str, usize>::new()));
    {
        let sent_to_client = Arc::clone(&sent_to_client);
        tokio::spawn(async move {
            let mut got = Vec::new();
            while reader.recv(&mut got).await.is_ok() {
                for record in got.drain(..) {
                    let kind = match &record {
                        record if relay_only(record) => "relay-only",
                        Record::Positions(_) => "positions",
                        Record::ClientClockModel(_) => "model summary",
                        Record::ClientRegionalBatch(_) => "regional",
                        Record::WorldPositions(_) => "world",
                        _ => continue,
                    };
                    if let Ok(mut sent) = sent_to_client.lock() {
                        *sent.entry(kind).or_default() += 1;
                    }
                }
            }
        });
    }

    // A third of the receivers on each relay, each naming the relay it chose (as tally-feed's
    // description does: that relay is the origin of its regional product), each batch sent once
    // the clock reaches it.
    let mut walls = Vec::new();
    for (index, feed) in feeds.into_iter().enumerate() {
        let relay = members[index % members.len()].address.clone();
        let stream = TcpStream::connect(&relay.address).await.map_err(text)?;
        let session = noise::connect(stream, &feed.identity, &relay.key, Role::Feeder)
            .await
            .map_err(text)?;
        let mut described = feed.info.public().map_err(text)?;
        described.relays = vec![relay.key];
        let info =
            tally_wire::ReceiverInfo::sign_public(&feed.identity, &described).map_err(text)?;
        let mut batches = Vec::new();
        for batch in feed.batches {
            let wall = batch.content().map_err(text)?.wall_ms;
            walls.push(wall);
            batches.push((wall, Record::Batch(batch)));
        }
        sending(
            session,
            vec![Record::ReceiverInfo(info), Record::ReceiverSite(feed.site)],
            batches,
            &clock,
        );
    }
    // Once that minute is up, the clock walks the scenario from its start, its past as fast as the
    // relays keep up: every relay's engine is offered every receiver's batches,
    // by its own feeders, its sharing members and its one-hop raw links, before it moves past them.
    tokio::time::sleep(Duration::from_millis(at.saturating_sub(wall_ms()))).await;
    let start = start_of(&simulation)?;
    if start < clock.now() {
        return Err(format!(
            "the scenario starts at {start}, before the relays' clock ({})",
            clock.now()
        ));
    }
    clock.set(start);
    let stepper = stepping(
        Arc::clone(&clock),
        members
            .iter()
            .map(|member| Arc::clone(&member.mlat) as Arc<dyn Hosting>)
            .collect(),
        walls,
    );

    let mut assembler = Assembler::new(256 * 1024 * 1024, 1_024);
    let mut models: BTreeMap<[u8; 32], Checked> = BTreeMap::new();
    let mut inputs: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
    let mut origins: BTreeMap<[u8; 32], Record> = BTreeMap::new();
    let mut heard = Network::default();
    let mut waiting: Vec<Positions> = Vec::new();
    // The client's relay's own fixes, by (address, second transmitted), and the aircraft the world
    // drew in each second it sealed.
    let mut own: BTreeMap<(u32, u64), u64> = BTreeMap::new();
    let mut drawn: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    // The scenario's 240 s at the wall clock's pace at most, and a hang guard beyond: the clock
    // walks no faster than the relays keep up, so a loaded machine takes longer, and only a clock
    // that stands still (`STOOD`) or a relay that never answers is a failure.
    let outcome = timeout(Duration::from_secs(240) + WAIT, async {
        while !heard.done() {
            let record = records
                .recv()
                .await
                .ok_or("the relay's fan-out let its relay link go")?;
            let assembled = match &record {
                Record::ClockModelPart(part) => assembler.part(part.clone()),
                Record::ClockModel(model) => {
                    model.verify().map_err(text)?;
                    assert!(keys.contains(&model.engine().map_err(text)?));
                    assembler.manifest(model.clone()).map_err(text)?
                }
                // A relay link is handed the client forms too; the raw ones are what it checks.
                Record::Positions(positions) if positions.is_tagged() => None,
                Record::Positions(positions) => {
                    positions.verify().map_err(text)?;
                    let engine = positions.engine().map_err(text)?;
                    assert!(keys.contains(&engine), "positions from outside the network");
                    let content = positions.fixes().map_err(text)?;
                    // In stamps: the step that published it, against its newest transmission.
                    let newest = content
                        .fixes
                        .iter()
                        .map(|fix| fix.transmitted.unix_ms)
                        .max()
                        .unwrap_or(0);
                    heard.lag_ms = heard.lag_ms.max(content.issued_ms.saturating_sub(newest));
                    if engine == client.address.key {
                        for fix in &content.fixes {
                            own.entry((fix.address, fix.transmitted.unix_ms / 1_000))
                                .or_insert(content.issued_ms);
                        }
                    }
                    // Checked once the client holds every model it cites: a model and the
                    // positions under it may come by different relays, in either order.
                    waiting.push(positions.clone());
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
                    if !drawn.contains_key(&content.second) {
                        heard.world_seconds += 1;
                    }
                    drawn
                        .entry(content.second)
                        .or_default()
                        .extend(content.fixes.iter().map(|fix| fix.address));
                    let (checked, mlat) = check_world(&content, &origins, &inputs)?;
                    heard.world_fixes += checked;
                    heard.world_mlat += mlat;
                    None
                }
                _ => None,
            };
            if let Some((_, content)) = assembled {
                let (id, checked) = check_model(&content, &raw)?;
                inputs.insert(id, content.inputs);
                heard.models += 1;
                models.insert(id, checked);
            }
            let (ready, still): (Vec<_>, Vec<_>) = std::mem::take(&mut waiting)
                .into_iter()
                .partition(|positions| {
                    positions.fixes().is_ok_and(|content| {
                        content
                            .fixes
                            .iter()
                            .all(|fix| fix.models.iter().all(|id| models.contains_key(id)))
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
    let outcome = match outcome {
        Ok(result) => result,
        Err(_) => Err(format!("before the deadline: {heard:?}")),
    };
    settled(outcome, stepper).await?;
    // The client was sent every product's client form, and nothing a client may not be.
    let sent = sent_to_client
        .lock()
        .map_err(|_| "the client's count was poisoned")?
        .clone();
    eprintln!("sent to the client: {sent:?}");
    assert_eq!(sent.get("relay-only"), None, "{sent:?}");
    for kind in ["positions", "model summary", "regional", "world"] {
        assert!(
            sent.get(kind).is_some_and(|n| *n > 0),
            "no {kind}: {sent:?}"
        );
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
    // MLAT in seconds (RFC-0171 §3.8.1, RFC-0174 §2.4), in stamps: a positions record is
    // published (by the step that signs it) within a fix's way out of its newest transmission
    // (`tally_wire::budget::FIX_LEAVES`: its receptions' signed lag and the step's solve); every fix
    // the client's relay published before its second's seal is in the world for that second;
    // and nearly all are published before it (a transmission whose receptions straggle waits for
    // them). Every second the client holds whole (all but the newest) is checked. How fast on the
    // wall clock is `tally-load`'s to measure.
    assert!(heard.verified > 0, "{heard:?}");
    assert!(
        heard.lag_ms
            <= tally_wire::budget::FIX_LEAVES
                .span::<tally_wire::clocks::Judged>()
                .ms(),
        "a fix was published {} ms after its transmission",
        heard.lag_ms
    );
    let newest = drawn.keys().next_back().copied().unwrap_or(0);
    let (mut in_world, mut after_seal) = (0, 0);
    for ((address, second), issued_ms) in &own {
        if *second >= newest {
            continue;
        }
        let Some(aircraft) = drawn.get(second) else {
            continue;
        };
        let sealed_ms = (second + 1) * 1_000 + tally_relay::products::WORLD_SETTLE_MS;
        if *issued_ms >= sealed_ms {
            after_seal += 1;
            continue;
        }
        assert!(
            aircraft.contains(address),
            "{address:06x}'s fix of second {second}, published at {issued_ms}, before its seal, \
             is not in its world ({} aircraft drawn: {aircraft:06x?})",
            aircraft.len()
        );
        in_world += 1;
    }
    eprintln!("fixes: {in_world} in their world, {after_seal} after its seal");
    assert!(
        after_seal * 10 <= in_world + after_seal,
        "{after_seal} of {} fixes published after their second's seal",
        in_world + after_seal
    );
    assert!(in_world > 0, "no fix of a sealed second: {heard:?}");
    Ok(())
}

/// Every relay's MLAT choice for each area, as it computes it: (relay, areas it solves).
fn choices(members: &[Member]) -> Vec<(PublicKey, Regions)> {
    members
        .iter()
        .map(|m| {
            let network = m.hub.network();
            let now = m.hub.now();
            (
                m.address.key,
                network.selection.mlat_areas(&network.directory, now),
            )
        })
        .collect()
}

/// The relays solving `area`, by their own choice.
fn solving(choices: &[(PublicKey, Regions)], area: Region) -> BTreeSet<PublicKey> {
    choices
        .iter()
        .filter(|(_, areas)| areas.contains(area))
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
                let made = member(
                    twin(&identity)?,
                    &areas,
                    asn,
                    false,
                    &accepted,
                    &Clock::wall(),
                )
                .await?;
                if let Some(upstream) = upstream {
                    tokio::spawn(tally_relay::link::upstream(
                        tally_relay::config::Upstream {
                            address: upstream.address,
                            key: upstream.key,
                        },
                        tally_wire::NoiseKey::of(identity),
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
            twin(identity)?,
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
            .mlat_areas(&unchosen.hub.network().directory, judged(wall_ms()))
            .contains(area)
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
    // within `OFFER_LIFETIME_MS` of the kill; then ticks and steps, waited for as long as they
    // take (`WAIT`, a hang guard): when it moved is held from below, which load cannot break.
    let lifetime = Duration::from_millis(tally_relay::directory::OFFER_LIFETIME_MS);
    let margin = WAIT;
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
