//! The replay: two passes over a subset, the second driving the engine a relay hosts on a
//! virtual clock and scoring what it publishes as it publishes it (crate docs).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::io::Write;

use tally_mlat::engine::{Engine, STEP_MS, Settings as EngineSettings};
use tally_mlat::fix::{Part, Report};
use tally_wire::batch::format;
use tally_wire::clocks::recorded::aligned;
use tally_wire::{
    Batch, BatchContent, Identity, Observation, PublicKey, ReceiverSite, ReceiverSiteContent,
    Record, Signer,
};

use crate::locards::{self, Row, Subset};
use crate::mapping::{self, ClockClass, Receiver, Reply, Survey};
use crate::reference::Reference;
use crate::score::{self, Count, Planar, Slice, Truth};

/// How often the virtual clock ticks: what has arrived is ingested and the engine steps, as a
/// relay's hosted MLAT steps it (`tally_mlat::engine::STEP_MS`).
pub const TICK_MS: u64 = STEP_MS;
/// The most observations a batch carries (the simulator's feeds).
const MAX_BATCH: usize = 400;
/// The engine fits no model before its trailing window (`tally_wire::budget::TRAILING_WINDOW`)
/// holds a window's sync history: transmissions in the first this many milliseconds are not
/// counted in the solved fraction.
const WARM_UP_MS: u64 = tally_wire::budget::TRAILING_WINDOW_MS;
/// How long the clock runs on past the last row: every fix of the last rows has surely been
/// published and arrived by then (`tally_wire::budget::FIX_ARRIVED`).
const RUN_OUT_MS: u64 = tally_wire::budget::FIX_ARRIVED_MS;
/// The slot the solved fraction counts by: an aircraft is solved in a slot when any fix of a
/// withheld transmission of it in the slot (by the lower median of its receptions' wall clocks)
/// was published.
const SLOT_MS: u64 = 5_000;

/// What to run.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Withhold one aircraft in this many.
    pub withhold_one_in: u32,
    pub reply: Reply,
    /// Synthesise operational status messages declaring this NACp for every sync aircraft.
    pub nacp: Option<u8>,
    /// Only sensors LocaRDS verified (`good`).
    pub good_sensors_only: bool,
    /// The precision the sensors LocaRDS did not verify declare their sites to, metres (0 is
    /// exact; the engine adds `(p / sqrt 3)^2` to each reception's variance).
    pub unverified_precision_m: u32,
    /// Seconds into the hour to start at, and how long to run.
    pub start_s: f64,
    pub duration_s: f64,
    pub threads: usize,
    /// Where to write every scored solution, one line each, for analysis.
    pub samples: Option<std::path::PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            withhold_one_in: 8,
            reply: Reply::Df4,
            nacp: None,
            good_sensors_only: false,
            unverified_precision_m: 0,
            start_s: 0.0,
            duration_s: 3_600.0,
            threads: std::thread::available_parallelism().map_or(4, |n| n.get()),
            samples: None,
        }
    }
}

/// Everything measured.
#[derive(Debug, Default)]
pub struct Outcome {
    pub sensors_described: usize,
    pub sensors_gnss: usize,
    pub rows_read: u64,
    pub receptions: u64,
    pub withheld_aircraft: usize,
    pub withheld_transmissions: u64,
    /// (aircraft, slot) with a withheld transmission heard by at least three receivers after
    /// warm-up, and how many transmissions it could have had solved (at most five).
    pub eligible_bins: u64,
    pub eligible_transmissions: u64,
    pub solved_bins: u64,
    pub fixes: Scores,
    pub models: u64,
    /// What the engine's steps reported, summed (`tally_mlat::fix::Report`).
    pub engine: Report,
    pub unknown_solutions: u64,
    /// The truth's own error (`score::TruthModel`), fitted to the reference fixes.
    pub truth_model: score::TruthModel,
    /// The reference fixes: how many, their median chi-square per degree of freedom, and their
    /// coverage against the raw truth (horizontal, two degrees of freedom).
    pub reference_fixes: usize,
    pub reference_chi2_per_dof: f64,
    pub reference_raw: Count,
    /// The reference against the truth model: 0.95 or near it by construction (the model is
    /// fitted along and across the track apart; this is both at once).
    pub reference_against: Count,
}

/// The fixes' scoring, overall and sliced.
#[derive(Debug, Default)]
pub struct Scores {
    pub overall: Slice,
    /// The aircraft LocaRDS verified.
    pub trusted: Slice,
    /// Below 6 km, 6 to 9 km, from 9 km (the report's barometric altitude).
    pub bands: [Slice; 3],
    /// Receptions used: 3, 4, 5-6, 7-9, 10 or more.
    pub receivers: [Slice; 5],
    /// The areas whose models it cites (one per area of its used hearers): 1, 2, 3, 4 or more.
    pub areas: [Slice; 4],
    /// Whether every receiver it used is GNSS-disciplined, some are, or none.
    pub clocks: [Slice; 3],
}

impl Scores {
    fn add(
        &mut self,
        scored: &score::Scored,
        truth: &Truth,
        used: usize,
        areas: usize,
        gnss: usize,
    ) {
        self.overall.add(scored);
        if truth.trusted == Some(true) {
            self.trusted.add(scored);
        }
        let band = if truth.baro_m < 6_000.0 {
            0
        } else if truth.baro_m < 9_000.0 {
            1
        } else {
            2
        };
        self.bands[band].add(scored);
        let bucket = match used {
            0..=3 => 0,
            4 => 1,
            5 | 6 => 2,
            7..=9 => 3,
            _ => 4,
        };
        self.receivers[bucket].add(scored);
        if areas > 0 {
            self.areas[areas.min(4) - 1].add(scored);
        }
        let clocks = if gnss == used {
            0
        } else if gnss > 0 {
            1
        } else {
            2
        };
        self.clocks[clocks].add(scored);
    }
}

/// One receiver's feed as it is being made.
struct Feeding {
    receiver: Receiver,
    key: PublicKey,
    /// When its batches seal, milliseconds into each second, and how long they take to arrive.
    phase_ms: u64,
    delay_ms: u64,
    sequence: u64,
    previous: [u8; 32],
    open_wall: u64,
    open: Vec<Observation>,
}

/// A deterministic spread for each receiver's phase and path delay (as `tally_mlat::replay`).
fn spread(serial: u32, salt: u64, modulus: u64) -> u64 {
    let mut x = u64::from(serial)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(salt);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (x ^ (x >> 31)) % modulus
}

impl Feeding {
    /// The wall clock of the batch a reception heard at `heard_ms` travels in: the first seal
    /// after it.
    fn wall_of(&self, heard_ms: u64) -> u64 {
        let start = mapping::start_ms();
        let into = heard_ms.saturating_sub(start);
        let seconds = (into + 1000 - self.phase_ms) / 1000;
        start + seconds * 1000 + self.phase_ms
    }

    fn seal(&mut self) -> Result<Option<(u64, Batch)>, String> {
        if self.open.is_empty() {
            return Ok(None);
        }
        let batch = Batch::sign(
            &self.receiver.identity,
            &BatchContent {
                boot_id: 1,
                sequence: self.sequence,
                counter_epoch: 1,
                wall_ms: self.open_wall,
                dropped: 0,
                previous: self.previous,
                observations: std::mem::take(&mut self.open),
            },
        )
        .map_err(|e| e.to_string())?;
        self.sequence += 1;
        self.previous = batch.hash();
        Ok(Some((self.open_wall + self.delay_ms, batch)))
    }
}

/// A withheld transmission's truth, and what it needs to be counted.
struct Pending {
    truth: Truth,
    /// The lower median of its receptions' wall clocks: what its slot is.
    median_wall: u64,
    /// Distinct receivers that heard it.
    hearers: usize,
}

/// Each aircraft's reports: (seconds, latitude, longitude), in time order once sorted.
type Tracks = HashMap<u32, Vec<(f64, f64, f64)>>;

/// The first pass: every sensor's survey, and every aircraft's reports' times and positions (for
/// the truth's velocity).
fn survey(subset: &Subset, settings: &Settings) -> Result<(BTreeMap<u32, Survey>, Tracks), String> {
    let mut surveys: BTreeMap<u32, Survey> = BTreeMap::new();
    let mut tracks: Tracks = HashMap::new();
    let end = settings.start_s + settings.duration_s;
    locards::rows(&subset.rows, &mut |row| {
        if row.server_s < settings.start_s || row.server_s > end {
            return Ok(());
        }
        for (sensor, ns) in &row.measurements {
            surveys.entry(*sensor).or_default().add(row.server_s, *ns);
        }
        tracks
            .entry(row.aircraft)
            .or_default()
            .push((row.server_s, row.lat_deg, row.lon_deg));
        Ok(())
    })?;
    Ok((surveys, tracks))
}

/// East and north speed at `t` from the reports either side within 10 s.
fn velocity(track: &[(f64, f64, f64)], t: f64) -> [f64; 2] {
    let at = track.partition_point(|(s, _, _)| *s < t);
    let before = track[..at]
        .iter()
        .rev()
        .find(|(s, _, _)| t - *s >= 1.0 && t - *s <= 10.0);
    let after = track[at..]
        .iter()
        .find(|(s, _, _)| *s - t >= 1.0 && *s - t <= 10.0);
    let (Some(a), Some(b)) = (before.or(track.get(at)), after.or(track.get(at))) else {
        return [0.0; 2];
    };
    let dt = b.0 - a.0;
    if dt < 1.0 {
        return [0.0; 2];
    }
    let north = (b.1 - a.1) * 111_132.0 / dt;
    let east = (b.2 - a.2) * 111_320.0 * a.1.to_radians().cos() / dt;
    [east, north]
}

/// Runs the calibration over `subset`, reporting progress to `progress`.
#[allow(
    clippy::disallowed_methods,
    reason = "a replay's engine signs by the recording's instants, whose clock always judges"
)]
pub fn run(
    subset: &Subset,
    settings: &Settings,
    progress: &mut dyn FnMut(&str),
) -> Result<Outcome, String> {
    let mut out = Outcome::default();
    let sensors = locards::sensors(&subset.sensors)?;
    let trusted = locards::aircraft(&subset.aircraft)?;
    progress("surveying the sensors' timestamps");
    let (surveys, mut tracks) = survey(subset, settings)?;
    for track in tracks.values_mut() {
        track.sort_by(|a, b| a.0.total_cmp(&b.0));
    }
    let mut feeds: BTreeMap<u32, Feeding> = BTreeMap::new();
    for sensor in &sensors {
        let Some(survey) = surveys.get(&sensor.serial) else {
            continue;
        };
        if settings.good_sensors_only && !sensor.good {
            continue;
        }
        let precision = if sensor.good {
            0
        } else {
            settings.unverified_precision_m
        };
        let Some(receiver) = mapping::receiver(sensor, survey.class(), precision) else {
            continue;
        };
        let key = receiver.identity.public();
        feeds.insert(
            sensor.serial,
            Feeding {
                receiver,
                key,
                phase_ms: spread(sensor.serial, 1, 1000),
                delay_ms: 40 + spread(sensor.serial, 2, 210),
                sequence: 0,
                previous: [0; 32],
                open_wall: 0,
                open: Vec::new(),
            },
        );
    }
    out.sensors_described = feeds.len();
    out.sensors_gnss = feeds
        .values()
        .filter(|f| f.receiver.class == ClockClass::Gnss)
        .count();
    let gnss_keys: BTreeSet<PublicKey> = feeds
        .values()
        .filter(|f| f.receiver.class == ClockClass::Gnss)
        .map(|f| f.key)
        .collect();
    let index_of: BTreeMap<PublicKey, u32> =
        feeds.iter().map(|(serial, f)| (f.key, *serial)).collect();
    progress(&format!(
        "{} sensors take part, {} of them GNSS-disciplined",
        out.sensors_described, out.sensors_gnss
    ));

    let start_ms = mapping::start_ms() + (settings.start_s * 1000.0) as u64;
    let reference = Reference::new(&sensors, &|serial| {
        surveys
            .get(&serial)
            .is_some_and(|survey| survey.class() == ClockClass::Gnss)
    });
    let mut replay = Replay {
        reference: Vec::new(),
        reference_chi2: Vec::new(),
        engine: Engine::new(
            1,
            EngineSettings {
                regions: tally_wire::Regions::default(),
                threads: settings.threads.max(1),
                capacity: tally_mlat::engine::Capacity::default(),
            },
        ),
        signer: Signer::new(
            Identity::from_seed([0x17; 32]),
            std::sync::Arc::new(|| true),
        ),
        feeds,
        index_of,
        gnss_keys,
        arrivals: BinaryHeap::new(),
        in_flight: HashMap::new(),
        next_flight: 0,
        pending: Vec::new(),
        by_reception: HashMap::new(),
        solved_bins: HashSet::new(),
        out,
        samples: match &settings.samples {
            Some(path) => {
                let mut file = std::io::BufWriter::new(
                    std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?,
                );
                writeln!(file, "{SAMPLE_HEADER}").map_err(|e| e.to_string())?;
                Some(file)
            }
            None => None,
        },
    };
    replay.describe(start_ms)?;
    let mut odd: HashMap<u32, bool> = HashMap::new();
    let mut now = start_ms;
    let end_s = settings.start_s + settings.duration_s;
    let mut last_report = std::time::Instant::now();

    progress("replaying");
    let replayed = locards::rows(&subset.rows, &mut |row: Row| {
        if row.server_s < settings.start_s {
            return Ok(());
        }
        if row.server_s > end_s {
            return Err(END.to_owned());
        }
        replay.out.rows_read += 1;
        let heard_ms = mapping::start_ms() + (row.server_s * 1000.0).round() as u64;
        while now + TICK_MS <= heard_ms {
            now += TICK_MS;
            replay.tick(now)?;
        }
        let velocity = tracks
            .get(&row.aircraft)
            .map_or([0.0; 2], |track| velocity(track, row.server_s));
        if let Some(fix) = reference.solve(&row, velocity) {
            replay.reference.push(fix.planar);
            replay.reference_chi2.push(fix.chi2_per_dof);
        }
        let address = mapping::address(row.aircraft);
        let withheld = mapping::withheld(row.aircraft, settings.withhold_one_in);
        let message = if withheld {
            mapping::reply_message(address, &row, settings.reply)
        } else {
            let parity = odd.entry(row.aircraft).or_insert(false);
            let message = mapping::position_message(address, &row, *parity);
            *parity = !*parity;
            message
        };
        let Some(message) = message else {
            return Ok(());
        };
        let status = settings
            .nacp
            .filter(|_| !withheld && row.id.is_multiple_of(5))
            .map(|nacp| mapping::status_message(address, nacp));
        let heard = replay.hear(&row, heard_ms, &message, status.as_deref())?;
        if withheld && !heard.is_empty() {
            let truth = Truth {
                aircraft: row.aircraft,
                heard_ms,
                lat_deg: row.lat_deg,
                lon_deg: row.lon_deg,
                geo_m: row.geo_m,
                baro_m: row.baro_m.unwrap_or(0.0),
                trusted: trusted.get(&row.aircraft).copied(),
                velocity,
            };
            replay.withhold(truth, heard);
        }
        if last_report.elapsed().as_secs() >= 30 {
            last_report = std::time::Instant::now();
            let fixes = &replay.out.fixes.overall.horizontal;
            let line = format!(
                "{:.0} s of {:.0}: {} fixes ({fixes})",
                row.server_s - settings.start_s,
                settings.duration_s,
                fixes.total,
            );
            progress(&line);
        }
        Ok(())
    });
    match replayed {
        Err(error) if error != END => return Err(error),
        _ => {}
    }
    let last = now + RUN_OUT_MS;
    while now < last {
        now += TICK_MS;
        replay.tick(now)?;
    }
    let scored_to = mapping::start_ms() + (end_s * 1000.0) as u64;
    let withheld = tracks
        .keys()
        .filter(|aircraft| mapping::withheld(**aircraft, settings.withhold_one_in))
        .count();
    Ok(replay.finish(withheld, start_ms + WARM_UP_MS, scored_to))
}

/// The columns of `Settings::samples`: the aircraft, when it was heard (Unix ms), receptions used and how many GNSS, the areas whose models it cites, the truth less the fix (east, north,
/// up), the stripped ENU covariance (ee, en, nn, eu, nu, uu), the truth's velocity, the error
/// along the track, the barometric and GNSS altitudes, and LocaRDS's verification.
const SAMPLE_HEADER: &str = "aircraft,heard_ms,used,gnss,areas,east,north,up,ee,en,nn,eu,nu,uu,ve,\
                             vn,along,baro,geo,trusted";

/// What stops the pass over the rows at the end of the duration.
const END: &str = "end of the duration";

/// The replay's state: the engine, the feeds into it, what is in flight to it, and what its
/// publications are scored against.
struct Replay {
    /// The reference fixes (`reference`) and their chi-square per degree of freedom.
    reference: Vec<Planar>,
    reference_chi2: Vec<f64>,
    engine: Engine,
    /// What the engine signs with.
    signer: Signer,
    feeds: BTreeMap<u32, Feeding>,
    /// Each receiver's sensor serial.
    index_of: BTreeMap<PublicKey, u32>,
    gnss_keys: BTreeSet<PublicKey>,
    /// Batches sealed and not yet arrived: (arrival, id), the batch by id.
    arrivals: BinaryHeap<Reverse<(u64, u64)>>,
    in_flight: HashMap<u64, Batch>,
    next_flight: u64,
    /// Every withheld transmission, and each of its receptions by (sensor, counter).
    pending: Vec<Pending>,
    by_reception: HashMap<(u32, u64), u32>,
    /// (aircraft, slot) with a fix.
    solved_bins: HashSet<(u32, u64)>,
    out: Outcome,
    samples: Option<std::io::BufWriter<std::fs::File>>,
}

impl Replay {
    /// Every feeder signs its site at the start, as a new feeder does (relay-only: the engine is
    /// hosted by a relay). The virtual clock never steps, so an instant reads alike on both.
    #[allow(clippy::disallowed_methods, reason = "a replay's instants")]
    fn describe(&mut self, start_ms: u64) -> Result<(), String> {
        for feed in self.feeds.values() {
            let site = ReceiverSite::sign(
                &feed.receiver.identity,
                &ReceiverSiteContent {
                    issued_ms: start_ms,
                    location: feed.receiver.location,
                    clock: feed.receiver.clock,
                },
            )
            .map_err(|e| e.to_string())?;
            self.engine
                .ingest_record(&Record::ReceiverSite(site), aligned(start_ms))?;
        }
        Ok(())
    }

    fn send(&mut self, sealed: Option<(u64, Batch)>) {
        if let Some((at, batch)) = sealed {
            self.in_flight.insert(self.next_flight, batch);
            self.arrivals.push(Reverse((at, self.next_flight)));
            self.next_flight += 1;
        }
    }

    /// Each sensor's reception of `row`, as `message` (and `status` beside it), put in its open
    /// batch. Returns each reception's (sensor, counter, batch wall clock).
    fn hear(
        &mut self,
        row: &Row,
        heard_ms: u64,
        message: &[u8],
        status: Option<&[u8]>,
    ) -> Result<Vec<(u32, u64, u64)>, String> {
        let format = if message.len() == 14 {
            format::MODE_S_LONG
        } else {
            format::MODE_S_SHORT
        };
        let mut heard = Vec::new();
        for (sensor, ns) in &row.measurements {
            let Some(feed) = self.feeds.get_mut(sensor) else {
                continue;
            };
            let Some(counter) = mapping::counter(feed.receiver.class, *ns) else {
                continue;
            };
            let wall = feed.wall_of(heard_ms);
            if feed.open_wall != wall || feed.open.len() + 2 > MAX_BATCH {
                let sealed = feed.seal()?;
                feed.open_wall = wall;
                self.send(sealed);
            }
            let Some(feed) = self.feeds.get_mut(sensor) else {
                continue;
            };
            feed.open.push(Observation {
                format,
                timestamp: counter,
                signal: 128,
                data: message.to_vec(),
            });
            if let Some(status) = status {
                // A status is never timed: a millisecond after the position, on the same clock.
                let later = match feed.receiver.class {
                    ClockClass::Gnss => counter + 1_000_000,
                    ClockClass::Free => counter + 12_000,
                };
                feed.open.push(Observation {
                    format: format::MODE_S_LONG,
                    timestamp: later,
                    signal: 128,
                    data: status.to_vec(),
                });
            }
            self.out.receptions += 1;
            heard.push((*sensor, counter, wall));
        }
        Ok(heard)
    }

    /// Keeps a withheld transmission's truth, findable by any of its receptions.
    fn withhold(&mut self, truth: Truth, heard: Vec<(u32, u64, u64)>) {
        let index = self.pending.len() as u32;
        let mut walls: Vec<u64> = heard.iter().map(|(_, _, wall)| *wall).collect();
        walls.sort_unstable();
        let median_wall = walls[(walls.len() - 1) / 2];
        let mut hearers: Vec<u32> = heard.iter().map(|(sensor, _, _)| *sensor).collect();
        hearers.sort_unstable();
        hearers.dedup();
        for (sensor, counter, _) in heard {
            self.by_reception.insert((sensor, counter), index);
        }
        self.pending.push(Pending {
            truth,
            median_wall,
            hearers: hearers.len(),
        });
    }

    /// One tick of the virtual clock at `now`: batches due are sealed, what has arrived is
    /// ingested, and the engine steps and what it published is scored. The virtual clock never
    /// steps, so an instant reads alike on both.
    #[allow(clippy::disallowed_methods, reason = "a replay's instants")]
    fn tick(&mut self, now: u64) -> Result<(), String> {
        let mut sealed = Vec::new();
        for feed in self.feeds.values_mut() {
            if !feed.open.is_empty() && feed.open_wall <= now {
                sealed.push(feed.seal()?);
            }
        }
        for batch in sealed {
            self.send(batch);
        }
        while let Some(Reverse((at, id))) = self.arrivals.peek().copied() {
            if at > now {
                break;
            }
            self.arrivals.pop();
            if let Some(batch) = self.in_flight.remove(&id) {
                self.engine
                    .ingest_record(&Record::Batch(batch), aligned(at))?;
            }
        }
        let step = self.engine.step(aligned(now), &self.signer);
        add_report(&mut self.out.engine, &step.report);
        for record in step.records() {
            self.take(&record)?;
        }
        Ok(())
    }

    /// Scores one published record.
    fn take(&mut self, record: &Record) -> Result<(), String> {
        match record {
            Record::ClockModel(_) => self.out.models += 1,
            // The tagged form is the same fixes for clients: scored once, raw.
            Record::Positions(positions) if !positions.is_tagged() => {
                let content = positions.fixes().map_err(|e| e.to_string())?;
                for solution in &content.fixes {
                    let receptions = solution.used().receptions();
                    let found = receptions.iter().find_map(|reception| {
                        let serial = self.index_of.get(&reception.receiver)?;
                        self.by_reception.get(&(*serial, reception.counter))
                    });
                    let Some(index) = found else {
                        self.out.unknown_solutions += 1;
                        continue;
                    };
                    let transmission = &self.pending[*index as usize];
                    let scored = score::score(solution, &transmission.truth);
                    let used = receptions.len();
                    let gnss_used = receptions
                        .iter()
                        .filter(|reception| self.gnss_keys.contains(&reception.receiver))
                        .count();
                    let areas = solution.models.len();
                    self.solved_bins.insert((
                        transmission.truth.aircraft,
                        transmission.median_wall / SLOT_MS,
                    ));
                    self.out
                        .fixes
                        .add(&scored, &transmission.truth, used, areas, gnss_used);
                    if let Some(file) = &mut self.samples {
                        let truth = &transmission.truth;
                        let c = scored.stripped;
                        writeln!(
                            file,
                            "{},{},{},{},{},{:.2},{:.2},{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},\
                             {:.2},{:.2},{:.2},{:.1},{},{}",
                            truth.aircraft,
                            truth.heard_ms,
                            used,
                            gnss_used,
                            areas,
                            scored.east_m,
                            scored.north_m,
                            scored.up_m.map_or(String::new(), |up| format!("{up:.2}")),
                            c[0][0],
                            c[0][1],
                            c[1][1],
                            c[0][2],
                            c[1][2],
                            c[2][2],
                            truth.velocity[0],
                            truth.velocity[1],
                            scored.along_m,
                            truth.baro_m,
                            truth.geo_m.map_or(String::new(), |g| format!("{g:.1}")),
                            truth.trusted.map_or("", |t| if t { "1" } else { "0" }),
                        )
                        .map_err(|e| e.to_string())?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The solved fraction, over (aircraft, slot) pairs, of withheld transmissions heard by three
    /// or more receivers between `from` and `to` (Unix milliseconds; the last 10 s left out).
    fn finish(mut self, withheld_aircraft: usize, from: u64, to: u64) -> Outcome {
        if let Some(file) = &mut self.samples {
            let _ = file.flush();
        }
        self.out.withheld_aircraft = withheld_aircraft;
        self.out.truth_model = score::TruthModel::fit(&self.reference);
        self.out.reference_fixes = self.reference.len();
        self.out.reference_chi2_per_dof = Slice::percentile(&self.reference_chi2, 0.5);
        for planar in &self.reference {
            if planar.along.is_some() {
                self.out
                    .reference_against
                    .add(self.out.truth_model.inside(planar, false));
            }
            self.out.reference_raw.add(
                score::distance(planar.error, planar.stripped)
                    .is_some_and(|d2| d2 < score::CHI2_2_95),
            );
        }
        self.out.withheld_transmissions = self.pending.len() as u64;
        let mut eligible: BTreeMap<(u32, u64), u64> = BTreeMap::new();
        for transmission in &self.pending {
            let median = transmission.median_wall;
            if transmission.hearers < 3 || median < from || median + 10_000 > to {
                continue;
            }
            *eligible
                .entry((transmission.truth.aircraft, median / SLOT_MS))
                .or_default() += 1;
        }
        self.out.eligible_bins = eligible.len() as u64;
        self.out.eligible_transmissions = eligible.values().map(|n| (*n).min(5)).sum();
        self.out.solved_bins = eligible
            .keys()
            .filter(|key| self.solved_bins.contains(key))
            .count() as u64;
        self.out
    }
}

/// Adds one step's report to the run's: what every thread's share adds (`Part::add`), and what a
/// step reports once.
fn add_report(total: &mut Report, step: &Report) {
    total.add(step);
    total.due += step.due;
    total.grown += step.grown;
    total.too_few += step.too_few;
    total.late += step.late;
    total.unowned += step.unowned;
    total.unassigned += step.unassigned;
    total.unjudged += step.unjudged;
    total.refits += step.refits;
    total.models += step.models;
    total.model_parts += step.model_parts;
    total.model_bytes += step.model_bytes;
    total.positions += step.positions;
    total.positions_bytes += step.positions_bytes;
    total.tagged_positions += step.tagged_positions;
    total.tagged_positions_bytes += step.tagged_positions_bytes;
    total.elapsed += step.elapsed;
}
