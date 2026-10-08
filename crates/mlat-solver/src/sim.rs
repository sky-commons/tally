//! A simulator of aircraft, receivers and drifting clocks, producing raw receptions exactly as
//! feeders would publish them, with the truth kept beside them. It is part of the library so the
//! engine built over this crate can test against it too. Deterministic: a seed fixes everything.

use tally_wire::batch::ReceiverInfoContent;
use tally_wire::batch::format;
use tally_wire::{
    Batch, BatchContent, Clock, Identity, Location, Observation, PublicKey, ReceiverInfo, WireError,
};

use crate::clock::Timebase;
use crate::geo::{self, C, Geodetic};
use crate::linalg::{self, Vec3};
use crate::modes;
use crate::obs::{Reception, Site};

/// xoshiro256** seeded through SplitMix64: small, fast, and the same everywhere.
#[derive(Clone, Debug)]
pub struct Rng {
    state: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut x = seed;
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Self {
            state: [next(), next(), next(), next()],
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.state[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);
        result
    }

    /// Uniform in [0, 1).
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn range(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * self.uniform()
    }

    /// Standard normal, by Box-Muller.
    pub fn normal(&mut self) -> f64 {
        let u = 1.0 - self.uniform();
        let v = self.uniform();
        (-2.0 * u.ln()).sqrt() * (2.0 * std::f64::consts::PI * v).cos()
    }
}

/// A receiver's clock, as it truly behaves.
#[derive(Clone, Debug)]
pub struct ClockTruth {
    pub timebase: Timebase,
    /// The 12 MHz counter's value at true time zero.
    pub start_counts: f64,
    /// Phase error (seconds) on a 0.1 s grid from `GRID_START`.
    phase: Vec<f64>,
    /// (true time, step seconds): the counter reads late by `step` from `time` on.
    pub jumps: Vec<(f64, f64)>,
    /// A constant the counter reads late by, seconds: a receiver that stamps the end of a
    /// message rather than its start, or a long antenna cable, behind a clock that is otherwise
    /// what it says.
    pub offset_s: f64,
    /// One standard deviation of a reception's timing jitter, seconds.
    pub jitter_s: f64,
}

const GRID_START: f64 = -5.0;
const GRID_STEP: f64 = 0.1;

impl ClockTruth {
    /// The clock's reading error at true time `t`, seconds (phase plus jumps).
    pub fn error(&self, t: f64) -> f64 {
        let position = ((t - GRID_START) / GRID_STEP).max(0.0);
        let index = (position.floor() as usize).min(self.phase.len().saturating_sub(2));
        let fraction = position - index as f64;
        let phase = self.phase[index] + (self.phase[index + 1] - self.phase[index]) * fraction;
        let jumps: f64 = self
            .jumps
            .iter()
            .filter(|(at, _)| t >= *at)
            .map(|(_, step)| step)
            .sum();
        phase + jumps + self.offset_s
    }

    /// The raw counter at true time `t` (seconds after the scenario's start, which is
    /// `start_tod_s` into the UTC day), with `noise` seconds of jitter added.
    pub fn counter(&self, t: f64, start_tod_s: f64, noise: f64) -> u64 {
        let local = t + self.error(t) + noise;
        match self.timebase {
            Timebase::Mhz12 => (self.start_counts + local * 12e6).floor() as u64,
            Timebase::GpsNanos => {
                let tod = start_tod_s + local;
                let tod = tod.rem_euclid(86_400.0);
                let seconds = tod.floor();
                let nanos = ((tod - seconds) * 1e9).floor().min(999_999_999.0);
                ((seconds as u64) << 30) | nanos as u64
            }
        }
    }
}

/// A simulated receiver.
#[derive(Clone, Debug)]
pub struct SimReceiver {
    pub key: PublicKey,
    pub site: Site,
    pub ecef: Vec3,
    pub truth: ClockTruth,
}

/// One transmission as it truly happened.
#[derive(Clone, Debug)]
pub struct TruthTransmission {
    pub address: u32,
    /// Whether the aircraft broadcasts ADS-B positions.
    pub adsb: bool,
    pub time: f64,
    pub ecef: Vec3,
    pub data: Vec<u8>,
}

/// A simulated aircraft: a straight line at constant height and speed.
#[derive(Clone, Debug)]
pub struct SimAircraft {
    pub address: u32,
    pub adsb: bool,
    pub start: Geodetic,
    /// East and north speed, metres per second.
    pub velocity: [f64; 2],
    /// Pressure altitude minus height above the ellipsoid, metres.
    pub baro_offset_m: f64,
    pub nacp: u8,
    /// Its GNSS position error over the scenario, east and north metres: near constant over a
    /// minute, as a receiver's is, drawn from the 95% bound its NACp declares.
    pub position_bias_m: [f64; 2],
}

/// The part of a reported position's error that changes from message to message, metres per
/// axis: GNSS noise and CPR quantisation beside the aircraft's near-constant bias.
pub const POSITION_NOISE_M: f64 = 2.0;

impl SimAircraft {
    pub fn position(&self, t: f64) -> Geodetic {
        let metres_per_degree_lat = 111_132.0;
        let metres_per_degree_lon = 111_320.0 * self.start.lat_deg.to_radians().cos();
        Geodetic {
            lat_deg: self.start.lat_deg + self.velocity[1] * t / metres_per_degree_lat,
            lon_deg: self.start.lon_deg + self.velocity[0] * t / metres_per_degree_lon,
            height_m: self.start.height_m,
        }
    }
}

/// What a scenario looks like.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub seed: u64,
    pub duration_s: f64,
    /// The UTC day the scenario runs on, as Unix milliseconds at its midnight.
    pub midnight_unix_ms: u64,
    pub start_tod_s: f64,
    pub adsb_aircraft: usize,
    pub modes_aircraft: usize,
    /// How many receivers: the first `RECEIVERS.len()` are those (moved with `centre`), and any
    /// beyond are placed on a spiral out to `spread_m` around `centre`.
    pub receivers: usize,
    /// Where the scenario is: `RECEIVERS` move with it, and aircraft are placed around it.
    pub centre: (f64, f64),
    /// How far from the centre aircraft and the extra receivers are placed, metres.
    pub spread_m: f64,
    /// Which receivers (by index) are GNSS-disciplined.
    pub gps: Vec<usize>,
    /// (receiver index, true time, step seconds).
    pub jumps: Vec<(usize, f64, f64)>,
    pub reception_probability: f64,
    /// Every free-running clock's rate error at the start, when set, instead of a random one
    /// (parts per million): every clock wrong the same way, so nothing but the sync ranges shows
    /// the gauge's.
    pub rate_ppm: Option<f64>,
    /// Every free-running receiver's timing jitter, seconds, when set, instead of the mix (one
    /// standard deviation).
    pub jitter_s: Option<f64>,
    /// Receivers (by index) whose clocks misbehave: a counter step of 5 to 10 microseconds every
    /// two seconds, as a failing oscillator or a driver that drops counts does.
    pub bad: Vec<usize>,
    /// Whether the first receivers are `RECEIVERS`; when not, every receiver is on the spiral.
    pub named: bool,
    /// (receiver index, seconds): receivers whose counter reads late by a constant
    /// (`ClockTruth::offset_s`), whatever they declare.
    pub offsets: Vec<(usize, f64)>,
    /// (receiver index, seconds): receivers whose timing jitter is this instead, whatever they
    /// declare: a counter that is not the clock it says it is (a GNSS receiver without its lock
    /// stamping from a coarse clock, as real ones in OpenSky's data do at hundreds of
    /// microseconds).
    pub jitters: Vec<(usize, f64)>,
}

impl Scenario {
    /// The wall clock of the batch carrying a reception heard at `t` seconds into the scenario:
    /// receivers seal a batch at every whole second of a correct clock, so its end.
    pub fn wall_ms(&self, t: f64) -> u64 {
        self.midnight_unix_ms
            + (self.start_tod_s * 1000.0) as u64
            + (t.max(0.0).floor() as u64 + 1) * 1000
    }

    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            duration_s: 30.0,
            midnight_unix_ms: 1_791_244_800_000,
            start_tod_s: 43_200.0,
            adsb_aircraft: 8,
            modes_aircraft: 6,
            receivers: RECEIVERS.len(),
            centre: CENTRE,
            spread_m: 150_000.0,
            gps: vec![2],
            jumps: Vec::new(),
            reception_probability: 0.85,
            rate_ppm: None,
            jitter_s: None,
            bad: Vec::new(),
            named: true,
            offsets: Vec::new(),
            jitters: Vec::new(),
        }
    }
}

/// Receivers at real places in the Netherlands and Belgium: name, latitude, longitude, metres.
pub const RECEIVERS: [(&str, f64, f64, f64); 10] = [
    ("Amsterdam", 52.3702, 4.8952, 10.0),
    ("Rotterdam", 51.9244, 4.4777, 15.0),
    ("Utrecht", 52.0907, 5.1214, 20.0),
    ("Eindhoven", 51.4416, 5.4697, 30.0),
    ("Groningen", 53.2194, 6.5665, 12.0),
    ("Zwolle", 52.5168, 6.0830, 10.0),
    ("The Hague", 52.0705, 4.3007, 8.0),
    ("Antwerp", 51.2194, 4.4025, 15.0),
    ("Nijmegen", 51.8126, 5.8372, 25.0),
    ("Alkmaar", 52.6324, 4.7534, 5.0),
];

/// The centre aircraft are placed around.
pub const CENTRE: (f64, f64) = (52.1, 5.1);

/// Everything a run produced.
#[derive(Clone, Debug)]
pub struct Simulation {
    pub scenario: Scenario,
    pub receivers: Vec<SimReceiver>,
    pub aircraft: Vec<SimAircraft>,
    pub transmissions: Vec<TruthTransmission>,
    pub receptions: Vec<Reception>,
    /// For each reception, the index of its transmission.
    pub sources: Vec<usize>,
}

impl Simulation {
    pub fn sites(&self) -> Vec<Site> {
        self.receivers
            .iter()
            .map(|receiver| receiver.site)
            .collect()
    }

    pub fn receiver(&self, key: &PublicKey) -> Option<&SimReceiver> {
        self.receivers.iter().find(|receiver| receiver.key == *key)
    }

    /// What each receiver would publish (RFC-0171 §3.1): its signed description, then its
    /// receptions in the order it heard them, one signed batch per wall clock second (each
    /// reception's `wall_ms`), at most `MAX_BATCH` observations a batch. Counter epoch 1, as `run`
    /// gives the receptions.
    pub fn feeds(&self) -> Result<Vec<Feed>, WireError> {
        const MAX_BATCH: usize = 400;
        let start_ms = self.scenario.midnight_unix_ms + (self.scenario.start_tod_s * 1000.0) as u64;
        let mut feeds = Vec::with_capacity(self.receivers.len());
        for (index, receiver) in self.receivers.iter().enumerate() {
            let identity = receiver_identity(self.scenario.seed, index);
            let info = ReceiverInfo::sign(
                &identity,
                &ReceiverInfoContent {
                    issued_ms: start_ms,
                    location: Some(receiver.site.location),
                    clock: receiver.site.clock,
                    software: "tally-mlat-solver sim".to_owned(),
                    relays: Vec::new(),
                },
            )?;
            let mut heard: Vec<(f64, &Reception)> = self
                .receptions
                .iter()
                .zip(&self.sources)
                .filter(|(reception, _)| reception.receiver == receiver.key)
                .map(|(reception, source)| (self.transmissions[*source].time, reception))
                .collect();
            heard.sort_by(|a, b| a.0.total_cmp(&b.0));
            let mut by_wall: Vec<Vec<&Reception>> = Vec::new();
            for (_, reception) in heard {
                match by_wall.last_mut() {
                    Some(batch)
                        if batch[0].wall_ms == reception.wall_ms && batch.len() < MAX_BATCH =>
                    {
                        batch.push(reception);
                    }
                    _ => by_wall.push(vec![reception]),
                }
            }
            let mut batches = Vec::new();
            let mut previous = [0; 32];
            for (sequence, chunk) in by_wall.iter().enumerate() {
                let batch = Batch::sign(
                    &identity,
                    &BatchContent {
                        boot_id: 1,
                        sequence: sequence as u64,
                        counter_epoch: 1,
                        wall_ms: chunk[0].wall_ms,
                        dropped: 0,
                        previous,
                        observations: chunk.iter().map(|r| r.observation.clone()).collect(),
                    },
                )?;
                previous = batch.hash();
                batches.push(batch);
            }
            feeds.push(Feed {
                identity,
                info,
                batches,
            });
        }
        Ok(feeds)
    }
}

/// One simulated receiver's signed traffic.
#[derive(Clone, Debug)]
pub struct Feed {
    pub identity: Identity,
    pub info: ReceiverInfo,
    pub batches: Vec<Batch>,
}

/// One receiver's timing jitter in the default mix, seconds: a third Beast-class (50 to 100 ns),
/// a third dump1090-class at 250 ns, a third dump1090-class at 500 ns (a cheap dongle at its
/// usual sample rate).
fn mixed_jitter(rng: &mut Rng, index: usize) -> f64 {
    match index % 3 {
        0 => rng.range(50e-9, 100e-9),
        1 => 500e-9,
        _ => 250e-9,
    }
}

fn clock_truth(rng: &mut Rng, gps: bool, duration: f64, rate_ppm: Option<f64>) -> ClockTruth {
    let steps = ((duration - GRID_START + 10.0) / GRID_STEP).ceil() as usize + 2;
    let (offset, mut rate, rate_walk, phase_walk, jitter) = if gps {
        (20e-9 * rng.normal(), 0.0, 0.1e-9, 1e-9, 20e-9)
    } else {
        (
            0.0,
            30e-6 * rng.normal(),
            2.2e-9,
            2e-9,
            rng.range(50e-9, 100e-9),
        )
    };
    if let Some(ppm) = rate_ppm.filter(|_| !gps) {
        rate = ppm * 1e-6;
    }
    let mut phase = Vec::with_capacity(steps);
    let mut value = offset;
    for _ in 0..steps {
        phase.push(value);
        value += rate * GRID_STEP + phase_walk * GRID_STEP.sqrt() * rng.normal();
        rate += rate_walk * GRID_STEP.sqrt() * rng.normal();
    }
    ClockTruth {
        timebase: if gps {
            Timebase::GpsNanos
        } else {
            Timebase::Mhz12
        },
        start_counts: (rng.next_u64() >> 24) as f64,
        phase,
        jumps: Vec::new(),
        offset_s: 0.0,
        jitter_s: jitter,
    }
}

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

fn df11(address: u32) -> Vec<u8> {
    let body = [
        (11 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    modes::with_parity(&body, 0)
}

fn df4(address: u32, feet: i32) -> Vec<u8> {
    let ac = modes::encode_ac13_q(feet).unwrap_or(0);
    let body = [4 << 3, 0, (ac >> 8) as u8 & 0x1f, ac as u8];
    modes::with_parity(&body, address)
}

fn pressure_feet(aircraft: &SimAircraft, height: f64) -> i32 {
    let feet = (height + aircraft.baro_offset_m) / 0.3048;
    ((feet / 25.0).round() as i32) * 25
}

/// Where receiver `index` stands: one of `RECEIVERS`, or beyond them a point on a sunflower
/// spiral out to `spread_m` around the centre (the golden angle apart, so no two coincide), 10 m
/// up.
fn site_of(scenario: &Scenario, index: usize) -> (f64, f64, f64) {
    let (lat0, lon0) = scenario.centre;
    let named = if scenario.named { RECEIVERS.len() } else { 0 };
    if let Some((_, lat, lon, alt)) = RECEIVERS.get(index).filter(|_| scenario.named) {
        return (lat - CENTRE.0 + lat0, lon - CENTRE.1 + lon0, *alt);
    }
    let golden = std::f64::consts::PI * (3.0 - 5f64.sqrt());
    let k = (index - named) as f64;
    let total = scenario.receivers.saturating_sub(named).max(1) as f64;
    let radius = scenario.spread_m * ((k + 0.5) / total).sqrt().min(1.0);
    let bearing = k * golden;
    (
        lat0 + radius * bearing.cos() / 111_132.0,
        lon0 + radius * bearing.sin() / (111_320.0 * lat0.to_radians().cos()),
        10.0,
    )
}

/// The identity of receiver `index` in the scenario seeded `seed`, so a test
/// can sign the simulated receiver's batches as the receiver itself.
pub fn receiver_identity(seed: u64, index: usize) -> Identity {
    let mut bytes = [0u8; 32];
    bytes[0..2].copy_from_slice(&(index as u16 + 1).to_be_bytes());
    bytes[2..10].copy_from_slice(&seed.to_be_bytes());
    Identity::from_seed(bytes)
}

/// Runs a scenario.
pub fn run(scenario: &Scenario) -> Simulation {
    let mut receptions = Vec::new();
    let mut sources = Vec::new();
    let mut simulation = run_into(scenario, &mut |reception, source| {
        receptions.push(reception);
        sources.push(source);
    });
    simulation.receptions = receptions;
    simulation.sources = sources;
    simulation
}

/// As `run`, handing each reception (with the index of its transmission) to `sink` as it is made
/// instead of keeping it: what a world-scale scenario's hundreds of millions of receptions need.
/// The `Simulation` returned holds no receptions.
pub fn run_into(scenario: &Scenario, sink: &mut dyn FnMut(Reception, usize)) -> Simulation {
    let mut rng = Rng::new(scenario.seed);
    let receivers: Vec<SimReceiver> = (0..scenario.receivers.min(usize::from(u16::MAX) - 1))
        .map(|index| {
            let (lat, lon, alt) = site_of(scenario, index);
            let key = receiver_identity(scenario.seed, index).public();
            let gps = scenario.gps.contains(&index);
            let mut truth = clock_truth(&mut rng, gps, scenario.duration_s, scenario.rate_ppm);
            if !gps {
                let mixed = mixed_jitter(&mut rng, index);
                truth.jitter_s = scenario.jitter_s.unwrap_or(mixed);
            }
            if let Some((_, offset)) = scenario.offsets.iter().find(|(at, _)| *at == index) {
                truth.offset_s = *offset;
            }
            if let Some((_, jitter)) = scenario.jitters.iter().find(|(at, _)| *at == index) {
                truth.jitter_s = *jitter;
            }
            truth.jumps = scenario
                .jumps
                .iter()
                .filter(|(receiver, _, _)| *receiver == index)
                .map(|(_, at, step)| (*at, *step))
                .collect();
            if scenario.bad.contains(&index) {
                let mut at = 1.0;
                while at < scenario.duration_s {
                    let size = rng.range(5e-6, 10e-6);
                    let sign = if rng.uniform() < 0.5 { -1.0 } else { 1.0 };
                    truth.jumps.push((at, sign * size));
                    at += 2.0;
                }
            }
            let clock = if gps {
                Clock::RadarcapeGps
            } else if index % 3 == 0 {
                Clock::Beast
            } else {
                Clock::Dump1090
            };
            let location = Location {
                lat_e7: (lat * 1e7).round() as i32,
                lon_e7: (lon * 1e7).round() as i32,
                alt_m: alt as i32,
                precision_m: 0,
            };
            let ecef = geo::to_ecef(Geodetic {
                lat_deg: f64::from(location.lat_e7) * 1e-7,
                lon_deg: f64::from(location.lon_e7) * 1e-7,
                height_m: f64::from(location.alt_m),
            });
            SimReceiver {
                key,
                site: Site {
                    receiver: key,
                    clock,
                    location,
                },
                ecef,
                truth,
            }
        })
        .collect();
    let mut aircraft = Vec::new();
    for index in 0..scenario.adsb_aircraft + scenario.modes_aircraft {
        let distance = scenario.spread_m * rng.uniform().sqrt();
        let bearing = rng.range(0.0, 2.0 * std::f64::consts::PI);
        let heading = rng.range(0.0, 2.0 * std::f64::consts::PI);
        let speed = rng.range(120.0, 250.0);
        // A third each of NACp 8, 9 and 10 (EPU 93 m, 30 m and 10 m), as an airliner fleet is.
        let nacp = 8 + (rng.uniform() * 3.0).min(2.0) as u8;
        let sigma = modes::epu_m(nacp).unwrap_or(30.0) / 2.448;
        aircraft.push(SimAircraft {
            address: 0x480000 + index as u32 * 0x111 + (scenario.seed as u32 & 0xff),
            adsb: index < scenario.adsb_aircraft,
            start: Geodetic {
                lat_deg: scenario.centre.0 + distance * bearing.cos() / 111_132.0,
                lon_deg: scenario.centre.1
                    + distance * bearing.sin() / (111_320.0 * scenario.centre.0.to_radians().cos()),
                height_m: rng.range(3_000.0, 12_000.0),
            },
            velocity: [speed * heading.sin(), speed * heading.cos()],
            baro_offset_m: 100.0 * rng.normal(),
            nacp,
            position_bias_m: [sigma * rng.normal(), sigma * rng.normal()],
        });
    }
    let mut transmissions = Vec::new();
    for plane in &aircraft {
        let mut schedule: Vec<(f64, u8)> = Vec::new();
        // Kinds: 0 position, 1 operational status, 2 all-call squitter, 3 altitude reply.
        let mut t = rng.range(0.0, 0.5);
        while t < scenario.duration_s {
            if plane.adsb {
                schedule.push((t, 0));
            } else {
                schedule.push((t, 3));
            }
            t += rng.range(0.4, 0.6);
        }
        let mut t = rng.range(0.0, 1.0);
        while t < scenario.duration_s {
            schedule.push((t, 2));
            t += rng.range(0.8, 1.2);
        }
        if plane.adsb {
            let mut t = rng.range(0.0, 2.5);
            while t < scenario.duration_s {
                schedule.push((t, 1));
                t += rng.range(2.3, 2.7);
            }
        }
        schedule.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut odd = false;
        for (time, kind) in schedule {
            let truth = plane.position(time);
            let ecef = geo::to_ecef(truth);
            let data = match kind {
                0 => {
                    let basis = geo::enu_basis(truth.lat_deg, truth.lon_deg);
                    let [east, north] = plane.position_bias_m;
                    let noisy = linalg::add(
                        ecef,
                        linalg::add(
                            linalg::scale(basis[0], east + POSITION_NOISE_M * rng.normal()),
                            linalg::scale(basis[1], north + POSITION_NOISE_M * rng.normal()),
                        ),
                    );
                    let reported = geo::from_ecef(noisy);
                    let feet = pressure_feet(plane, truth.height_m);
                    let field = modes::ac13_to_ac12(modes::encode_ac13_q(feet).unwrap_or(0));
                    let (lat, lon) = modes::cpr_encode(
                        modes::LatLon {
                            lat_deg: reported.lat_deg,
                            lon_deg: reported.lon_deg,
                        },
                        odd,
                    );
                    let me = modes::encode_airborne_position(11, field, odd, lat, lon);
                    odd = !odd;
                    df17(plane.address, me)
                }
                1 => {
                    let mut me = [0u8; 7];
                    me[0] = 31 << 3;
                    me[5] = (2 << 5) | plane.nacp;
                    df17(plane.address, me)
                }
                2 => df11(plane.address),
                _ => df4(plane.address, pressure_feet(plane, truth.height_m)),
            };
            transmissions.push(TruthTransmission {
                address: plane.address,
                adsb: plane.adsb,
                time,
                ecef,
                data,
            });
        }
    }
    // Receivers by 2-degree cell, so a transmission looks only at those within reach (400 km);
    // in index order, as every one would be looked at, so the draws are the same.
    let cell = |lat: f64, lon: f64| ((lat / 2.0).floor() as i32, (lon / 2.0).floor() as i32);
    let mut cells: std::collections::HashMap<(i32, i32), Vec<usize>> =
        std::collections::HashMap::new();
    for (index, receiver) in receivers.iter().enumerate() {
        let location = receiver.site.location;
        cells
            .entry(cell(
                f64::from(location.lat_e7) * 1e-7,
                f64::from(location.lon_e7) * 1e-7,
            ))
            .or_default()
            .push(index);
    }
    for (index, transmission) in transmissions.iter().enumerate() {
        let at = geo::from_ecef(transmission.ecef);
        let (row, column) = cell(at.lat_deg, at.lon_deg);
        let reach = (4.0 / at.lat_deg.to_radians().cos().max(0.2)).ceil() as i32;
        let mut near: Vec<usize> = Vec::new();
        for dr in -3..=3 {
            for dc in -reach..=reach {
                if let Some(list) = cells.get(&(row + dr, column + dc)) {
                    near.extend(list);
                }
            }
        }
        near.sort_unstable();
        for receiver in near.iter().map(|index| &receivers[*index]) {
            let delta = linalg::sub(transmission.ecef, receiver.ecef);
            let range = linalg::norm(delta);
            let up = geo::enu_basis(
                receiver.site.location.lat_e7 as f64 * 1e-7,
                receiver.site.location.lon_e7 as f64 * 1e-7,
            )[2];
            let elevation = (linalg::dot(delta, up) / range).asin().to_degrees();
            if range > 400_000.0 || elevation < 0.5 {
                continue;
            }
            if rng.uniform() >= scenario.reception_probability {
                continue;
            }
            let arrival = transmission.time + range / C;
            let noise = receiver.truth.jitter_s * rng.normal();
            let raw = receiver.truth.counter(arrival, scenario.start_tod_s, noise);
            sink(
                Reception {
                    receiver: receiver.key,
                    epoch: 1,
                    wall_ms: scenario.wall_ms(arrival),
                    observation: Observation {
                        format: if transmission.data.len() == 14 {
                            format::MODE_S_LONG
                        } else {
                            format::MODE_S_SHORT
                        },
                        timestamp: raw,
                        signal: 128,
                        data: transmission.data.clone(),
                    },
                },
                index,
            );
        }
    }
    Simulation {
        scenario: scenario.clone(),
        receivers,
        aircraft,
        transmissions,
        receptions: Vec::new(),
        sources: Vec::new(),
    }
}
