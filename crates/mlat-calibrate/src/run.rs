//! The replay: two passes over a subset, the second driving the engine a relay hosts on a
//! virtual clock and scoring what it publishes as it publishes it (crate docs).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet};
use std::io::Write;

use tally_mlat::engine::{Engine, Settings as EngineSettings};
use tally_mlat_solver::publish;
use tally_wire::batch::format;
use tally_wire::{
    Batch, BatchContent, Identity, Observation, PublicKey, ReceiverSite, ReceiverSiteContent,
    Record,
};

use crate::locards::{self, Row, Subset};
use crate::mapping::{self, ClockClass, Receiver, Reply, Survey};
use crate::reference::Reference;
use crate::score::{self, Count, Planar, Slice, Truth};

/// What the relay's hosted MLAT waits after a window's last bin (`tally_relay::mlat_host`).
pub const SETTLE_MS: u64 = 2_000;
/// How often the virtual clock ticks: what has arrived is ingested, provisional work solved and a
/// due window stepped.
pub const TICK_MS: u64 = 100;
/// The most observations a batch carries (the simulator's feeds).
const MAX_BATCH: usize = 400;
/// The engine solves nothing before its first window has history: transmissions in the first
/// this many milliseconds are not counted in the solved fraction.
const WARM_UP_MS: u64 = 65_000;
/// How long the clock runs on past the last row, so the last windows are published.
const RUN_OUT_MS: u64 = 120_000;

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
    /// (aircraft, engine bin) with a withheld transmission heard by at least three receivers
    /// after warm-up, and how many transmissions it could have had solved (at most five).
    pub eligible_bins: u64,
    pub eligible_transmissions: u64,
    pub solved_bins: u64,
    pub finals: Finals,
    pub provisionals: Finals,
    pub models: u64,
    pub window: tally_mlat::window::Report,
    pub provisional: tally_mlat::provisional::Report,
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

/// One kind's scoring, overall and sliced.
#[derive(Debug, Default)]
pub struct Finals {
    pub overall: Slice,
    /// The aircraft LocaRDS verified.
    pub trusted: Slice,
    /// Below 6 km, 6 to 9 km, from 9 km (the report's barometric altitude).
    pub bands: [Slice; 3],
    /// Receptions used: 3, 4, 5-6, 7-9, 10 or more.
    pub receivers: [Slice; 5],
    /// The model's tile level.
    pub levels: [Slice; 4],
    /// Whether every receiver it used is GNSS-disciplined, some are, or none.
    pub clocks: [Slice; 3],
}

impl Finals {
    fn add(
        &mut self,
        scored: &score::Scored,
        truth: &Truth,
        used: usize,
        level: Option<u8>,
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
        if let Some(level) = level.filter(|l| *l < 4) {
            self.levels[usize::from(level)].add(scored);
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
    /// Its bin as the engine decides it: the lower median of its receptions' wall clocks.
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
            Identity::from_seed([0x17; 32]),
            1,
            EngineSettings {
                regions: tally_wire::Regions::default(),
                settle_ms: SETTLE_MS,
                threads: settings.threads.max(1),
                capacity: tally_mlat::engine::Capacity::default(),
            },
        ),
        feeds,
        index_of,
        gnss_keys,
        arrivals: BinaryHeap::new(),
        in_flight: HashMap::new(),
        next_flight: 0,
        pending: Vec::new(),
        by_reception: HashMap::new(),
        levels: HashMap::new(),
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
            let finals = &replay.out.finals.overall.horizontal;
            let line = format!(
                "{:.0} s of {:.0}: {} finals ({finals}), {} provisionals ({})",
                row.server_s - settings.start_s,
                settings.duration_s,
                finals.total,
                replay.out.provisionals.overall.horizontal.total,
                replay.out.provisionals.overall.horizontal,
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

/// The columns of `Settings::samples`: provisional or not, the aircraft, when it was heard (Unix
/// ms), receptions used and how many GNSS, the tile level, the truth less the fix (east, north,
/// up), the stripped ENU covariance (ee, en, nn, eu, nu, uu), the truth's velocity, the error
/// along the track, the barometric and GNSS altitudes, and LocaRDS's verification.
const SAMPLE_HEADER: &str = "provisional,aircraft,heard_ms,used,gnss,level,east,north,up,ee,en,nn,\
                             eu,nu,uu,ve,vn,along,baro,geo,trusted";

/// What stops the pass over the rows at the end of the duration.
const END: &str = "end of the duration";

/// The replay's state: the engine, the feeds into it, what is in flight to it, and what its
/// publications are scored against.
struct Replay {
    /// The reference fixes (`reference`) and their chi-square per degree of freedom.
    reference: Vec<Planar>,
    reference_chi2: Vec<f64>,
    engine: Engine,
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
    /// Each published model's tile level, by id.
    levels: HashMap<[u8; 32], u8>,
    /// (aircraft, bin) with a final solution.
    solved_bins: HashSet<(u32, u64)>,
    out: Outcome,
    samples: Option<std::io::BufWriter<std::fs::File>>,
}

impl Replay {
    /// Every feeder signs its site at the start, as a new feeder does (relay-only: the engine is
    /// hosted by a relay).
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
            self.engine.ingest(&Record::ReceiverSite(site), start_ms)?;
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
    /// ingested, and the engine's provisional and window work is run and scored.
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
                self.engine.ingest(&Record::Batch(batch), at)?;
            }
        }
        let mut published = self.engine.provisional_step(now, now);
        let (records, report) = self.engine.step(now, now);
        published.extend(records);
        add_report(&mut self.out.window, &report);
        let provisional = self.engine.provisional_report();
        add_provisional(&mut self.out.provisional, &provisional);
        for record in published {
            self.take(&record)?;
        }
        Ok(())
    }

    /// Scores one published record.
    fn take(&mut self, record: &Record) -> Result<(), String> {
        match record {
            Record::ClockModel(model) => {
                self.out.models += 1;
                let manifest = model.manifest().map_err(|e| e.to_string())?;
                if let Ok(tile) = publish::tile_of(&manifest.inline) {
                    self.levels.insert(model.id(), tile.level);
                }
            }
            Record::ClockModelPart(part) => {
                if part.index().ok() == Some(0)
                    && let (Ok(model), Ok(tile)) = (part.model(), publish::tile_of(part.data()))
                {
                    self.levels.insert(model, tile.level);
                }
            }
            // The tagged form is the same solutions for clients: scored once, raw.
            Record::Positions(positions) | Record::Provisional(positions)
                if !positions.is_tagged() =>
            {
                let provisional = matches!(record, Record::Provisional(_));
                let content = positions.solutions().map_err(|e| e.to_string())?;
                for solution in &content.solutions {
                    let receptions = solution.observations.receptions();
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
                    let level = self.levels.get(&solution.clock_model).copied();
                    let finals = if provisional {
                        &mut self.out.provisionals
                    } else {
                        self.solved_bins
                            .insert((transmission.truth.aircraft, transmission.median_wall / 5000));
                        &mut self.out.finals
                    };
                    finals.add(&scored, &transmission.truth, used, level, gnss_used);
                    if let Some(file) = &mut self.samples {
                        let truth = &transmission.truth;
                        let c = scored.stripped;
                        writeln!(
                            file,
                            "{},{},{},{},{},{},{:.2},{:.2},{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},\
                             {:.2},{:.2},{:.2},{:.1},{},{}",
                            u8::from(provisional),
                            truth.aircraft,
                            truth.heard_ms,
                            used,
                            gnss_used,
                            level.map_or(-1, i32::from),
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

    /// The solved fraction, over the engine's own bins, of withheld transmissions heard by three
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
                .entry((transmission.truth.aircraft, median / 5000))
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

fn add_report(total: &mut tally_mlat::window::Report, step: &tally_mlat::window::Report) {
    total.windows += step.windows;
    total.bins += step.bins;
    total.targets += step.targets;
    total.tiles += step.tiles;
    total.uncovered += step.uncovered;
    total.fits += step.fits;
    total.unfitted += step.unfitted;
    if total.unfitted_reason.is_none() {
        total.unfitted_reason = step.unfitted_reason.clone();
    }
    total.transmissions += step.transmissions;
    total.solved += step.solved;
    total.unsolved += step.unsolved;
    total.rejected += step.rejected;
    total.clock_models += step.clock_models;
    total.positions += step.positions;
    total.fit_time += step.fit_time;
    total.solve_time += step.solve_time;
    total.elapsed += step.elapsed;
}

fn add_provisional(
    total: &mut tally_mlat::provisional::Report,
    step: &tally_mlat::provisional::Report,
) {
    total.transmissions += step.transmissions;
    total.solved += step.solved;
    total.unsolved += step.unsolved;
    total.rejected += step.rejected;
    total.unmodelled += step.unmodelled;
    total.dropped += step.dropped;
    total.records += step.records;
}
