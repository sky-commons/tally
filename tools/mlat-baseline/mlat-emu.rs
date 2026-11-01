//! mlat-emu: the RFC-0198 baseline load generator (never shipped). N mlat-clients replaying
//! tally-load's scene (`tally_load::traffic`: the same scenarios, receivers, aircraft and reception
//! probability) to wiedehopf's mlat-server over its JSON protocol, TCP with zlib2 framing, as
//! mlat-client (wiedehopf/mlat-client `28ae4f7`) speaks it; and `eval`, which scores a run's fixes
//! (mlat-server's or Tally's) against the scene's truth.
//!
//! `mlat-emu run --server HOST:PORT --feeders N --seconds S --workers W`
//! `mlat-emu eval --feeders N --world-seconds S --fixes FILE --t0-unix-ms MS --from T --to T`

use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::inflate::stream::InflateState;
use miniz_oxide::{DataFormat, MZFlush};
use tally_mlat_solver::clock::Timebase;
use tally_mlat_solver::geo::{self, Geodetic};
use tally_mlat_solver::sim::{Heard, Scenario, World};
use tally_wire::modes;

// ---------------------------------------------------------------- the scene, as traffic.rs makes it

const CLUSTERS: [((f64, f64), f64); 2] =
    [((50.0, 10.0), 1_500_000.0), ((39.0, -95.0), 2_000_000.0)];
const WORLD_FEEDERS: usize = 20_000;
const GPS_EVERY: usize = 50;
/// The run plays from the scenario's second 1 (traffic.rs `SKIPPED_S`).
const FIRST_S: f64 = 1.0;

fn layout(feeders: usize) -> [usize; 2] {
    [feeders.div_ceil(2), feeders / 2]
}

fn scenario(
    aircraft: usize,
    seed: u64,
    cluster: usize,
    receivers: usize,
    duration_s: f64,
    p: f64,
) -> Scenario {
    let ((lat, lon), spread_m) = CLUSTERS[cluster];
    let share = receivers as f64 / layout(WORLD_FEEDERS)[cluster] as f64;
    let adsb = aircraft * 2 / 3;
    Scenario {
        duration_s,
        receivers,
        adsb_aircraft: adsb,
        modes_aircraft: aircraft - adsb,
        centre: (lat, lon),
        spread_m,
        receiver_spread_m: Some(spread_m * share.sqrt().min(1.0)),
        reception_probability: p,
        named: false,
        gps: (0..receivers).step_by(GPS_EVERY).collect(),
        unwanted: true,
        ..Scenario::new(901 + seed * 2 + cluster as u64)
    }
}

fn second_of(scenario: &Scenario, wall_ms: u64) -> u64 {
    let start = scenario.midnight_unix_ms + (scenario.start_tod_s * 1000.0) as u64;
    (wall_ms.saturating_sub(start) / 1000).saturating_sub(1)
}

fn chunks<T: Send>(
    count: usize,
    workers: usize,
    work: impl Fn(std::ops::Range<usize>) -> T + Sync,
) -> Vec<T> {
    let each = count.div_ceil(workers.max(1)).max(1);
    let ranges: Vec<_> = (0..count)
        .step_by(each)
        .map(|f| f..(f + each).min(count))
        .collect();
    std::thread::scope(|s| {
        let handles: Vec<_> = ranges
            .iter()
            .cloned()
            .map(|r| {
                let w = &work;
                s.spawn(move || w(r))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// The reception probability traffic.rs's first pass sets (`Traffic::build_for`).
fn probability(feeders: usize, aircraft: usize, seed: u64, rps: f64, threads: usize) -> f64 {
    let sizes = layout(feeders);
    let mut in_reach = 0u64;
    for (cluster, &receivers) in sizes.iter().enumerate() {
        if receivers == 0 {
            continue;
        }
        let sc = scenario(aircraft, seed, cluster, receivers, 2.0, 1.0);
        let world = World::build(&sc);
        let everyone = 0..receivers;
        in_reach += chunks(world.transmissions.len(), threads, |range| {
            let (mut near, mut heard) = (Vec::new(), Vec::new());
            let mut count = 0u64;
            for index in range {
                heard.clear();
                world.hear(index, &everyone, false, 1.0, &mut near, &mut heard);
                count += heard
                    .iter()
                    .filter(|h| second_of(&sc, h.wall_ms) == 1)
                    .count() as u64;
            }
            count
        })
        .into_iter()
        .sum::<u64>();
    }
    (rps / (in_reach as f64 / feeders as f64)).min(1.0)
}

fn worlds(feeders: usize, aircraft: usize, seed: u64, seconds: f64, p: f64) -> Vec<World> {
    let sizes = layout(feeders);
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..2)
            .map(|c| {
                let n = sizes[c];
                s.spawn(move || World::build(&scenario(aircraft, seed, c, n, seconds, p)))
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

/// What an mlat-client passes on at all: DF17 airborne positions, DF11 and DF4 (the scene's
/// other DF17 kinds only count towards an aircraft's ten messages, `received_df17`).
fn relevant(data: &[u8]) -> bool {
    match data[0] >> 3 {
        17 => (9..=18).contains(&(data[4] >> 3)),
        11 | 4 | 0 | 5 | 16 | 20 | 21 => true,
        _ => false,
    }
}

// ---------------------------------------------------------------- one mlat-client

#[derive(Default)]
struct Ac {
    messages: u32,
    last_message: f64,
    last_even: f64,
    last_odd: f64,
    adsb_good: bool,
    even: Option<(u64, Vec<u8>)>,
    odd: Option<(u64, Vec<u8>)>,
    requested: bool,
    recent_adsb_positions: u32,
    rate_start: f64,
}

struct Client {
    stream: TcpStream,
    aircraft: HashMap<u32, Ac>,
    requested: HashSet<u32>,
    reported: HashSet<u32>,
    lines: Vec<String>,
    out: Vec<u8>,
    compressor: Box<CompressorOxide>,
    inflater: Box<InflateState>,
    inbuf: Vec<u8>,
    linebuf: Vec<u8>,
    next_update: f64,
    last_update: f64,
    next_report: f64,
    next_send: f64,
    next_heartbeat: f64,
    rng: u64,
}

const UPDATE_INTERVAL: f64 = 4.5;
const REPORT_INTERVAL: f64 = 4.0;
const POSITION_EXPIRY: f64 = 30.0;
const EXPIRY: f64 = 120.0;
const FREQ: f64 = 12e6;

#[derive(Default)]
struct Counts {
    sync: AtomicU64,
    mlat: AtomicU64,
    seen: AtomicU64,
    rate_reports: AtomicU64,
    bytes_out: AtomicU64,
    overflows: AtomicU64,
    backlog_max: AtomicU64,
    results: AtomicU64,
    start_sending: AtomicU64,
    stop_sending: AtomicU64,
    lag_ms_max: AtomicU64,
    receptions: AtomicU64,
}

fn rand01(state: &mut u64) -> f64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 11) as f64 / (1u64 << 53) as f64
}

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl Client {
    fn connect(
        server: &str,
        user: String,
        lat: f64,
        lon: f64,
        alt: f64,
        seed: u64,
    ) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect(server)?;
        stream.set_nodelay(true)?;
        // mlat-client's handshake (`start_connection`), with the receiver's own fields.
        let hs = serde_json::json!({
            "version": 3, "client_version": "wiedehopf-0.4.2-emu", "compress": ["none", "zlib", "zlib2"],
            "selective_traffic": true, "heartbeat": true, "return_results": true,
            "udp_transport": false, "return_result_format": "ecef", "return_stats": true,
            "uuid": format!("00000000-0000-4000-8000-{:012x}", seed), "lat": lat, "lon": lon, "alt": alt,
            "user": user, "clock_type": "dump1090", "privacy": false,
        });
        stream.write_all(format!("{}{}\n", hs, " ".repeat(128)).as_bytes())?;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        let response: serde_json::Value =
            serde_json::from_slice(&line).map_err(std::io::Error::other)?;
        if response.get("deny").is_some() || response["compress"] != "zlib2" {
            return Err(std::io::Error::other(format!("handshake: {response}")));
        }
        stream.set_nonblocking(true)?;
        let flags = create_comp_flags_from_zip_params(1, 15, 0);
        let mut client = Self {
            stream,
            aircraft: HashMap::new(),
            requested: HashSet::new(),
            reported: HashSet::new(),
            lines: Vec::new(),
            out: Vec::new(),
            compressor: Box::new(CompressorOxide::new(flags)),
            inflater: InflateState::new_boxed(DataFormat::Zlib),
            inbuf: Vec::new(),
            linebuf: Vec::new(),
            next_update: 0.0,
            last_update: 0.0,
            next_report: 0.0,
            next_send: 0.0,
            next_heartbeat: 0.0,
            rng: seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1,
        };
        // A dummy rate report says rate reports will come (`handle_handshake_response`).
        client.lines.push("{\"rate_report\":{}}".to_owned());
        Ok(client)
    }

    fn start(&mut self, now: f64) {
        self.next_report = rand01(&mut self.rng) * REPORT_INTERVAL;
        self.next_update = now + UPDATE_INTERVAL + rand01(&mut self.rng);
        self.next_send = now + rand01(&mut self.rng) * 0.25;
        self.next_heartbeat = now + 30.0;
    }

    /// One message off the receiver, at counter `ticks`, `now` seconds (mlat-client's
    /// `received_df17`, `received_df11`, `received_df_misc`).
    fn message(&mut self, data: &[u8], ticks: u64, now: f64, counts: &Counts) {
        let df = data[0] >> 3;
        match df {
            17 => {
                let address =
                    u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
                let requested = self.requested.contains(&address);
                let ac = match self.aircraft.get_mut(&address) {
                    Some(ac) => ac,
                    None => {
                        self.aircraft.insert(
                            address,
                            Ac {
                                messages: 1,
                                last_message: now,
                                rate_start: now,
                                requested,
                                ..Ac::default()
                            },
                        );
                        return;
                    }
                };
                ac.messages += 1;
                ac.last_message = now;
                if ac.messages < 10 {
                    return;
                }
                let tc = data[4] >> 3;
                if !(9..=18).contains(&tc) {
                    return;
                }
                let odd = data[6] & 0x04 != 0;
                if odd {
                    ac.odd = Some((ticks, data.to_vec()));
                } else {
                    ac.even = Some((ticks, data.to_vec()));
                }
                let (Some(even), Some(oddm)) = (&ac.even, &ac.odd) else {
                    return;
                };
                if (even.0 as f64 - oddm.0 as f64).abs() > 5.0 * FREQ {
                    return;
                }
                let alt_field = (u16::from(data[5]) << 4) | u16::from(data[6] >> 4);
                if alt_field == 0 {
                    return;
                }
                if 18 - tc < 6 {
                    return; // NUCp below 6
                }
                ac.recent_adsb_positions += 1;
                if odd {
                    ac.last_odd = now
                } else {
                    ac.last_even = now
                }
                ac.adsb_good =
                    now - ac.last_even < POSITION_EXPIRY && now - ac.last_odd < POSITION_EXPIRY;
                if !ac.requested {
                    return;
                }
                let line = format!(
                    "{{\"sync\":{{\"et\":{},\"em\":\"{}\",\"ot\":{},\"om\":\"{}\"}}}}",
                    even.0,
                    hex(&even.1),
                    oddm.0,
                    hex(&oddm.1)
                );
                self.lines.push(line);
                counts.sync.fetch_add(1, Ordering::Relaxed);
            }
            11 => {
                let address =
                    u32::from(data[1]) << 16 | u32::from(data[2]) << 8 | u32::from(data[3]);
                let requested = self.requested.contains(&address);
                let ac = match self.aircraft.get_mut(&address) {
                    Some(ac) => ac,
                    None => {
                        self.aircraft.insert(
                            address,
                            Ac {
                                messages: 1,
                                last_message: now,
                                rate_start: now,
                                requested,
                                ..Ac::default()
                            },
                        );
                        return;
                    }
                };
                ac.messages += 1;
                ac.last_message = now;
                if ac.messages < 10 || !ac.requested || ac.adsb_good {
                    return;
                }
                self.lines.push(format!(
                    "{{\"mlat\":{{\"t\":{},\"m\":\"{}\"}}}}",
                    ticks,
                    hex(data)
                ));
                counts.mlat.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                let Some(address) = modes::address(data) else {
                    return;
                };
                let Some(ac) = self.aircraft.get_mut(&address) else {
                    return;
                };
                ac.messages += 1;
                ac.last_message = now;
                if ac.messages < 10 || !ac.requested || ac.adsb_good {
                    return;
                }
                self.lines.push(format!(
                    "{{\"mlat\":{{\"t\":{},\"m\":\"{}\"}}}}",
                    ticks,
                    hex(data)
                ));
                counts.mlat.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The coordinator's heartbeat: aircraft updates and the seen, lost and rate reports.
    #[allow(
        clippy::disallowed_methods,
        reason = "mlat-client's heartbeat carries the host's time, as it does"
    )]
    fn heartbeat(&mut self, now: f64, counts: &Counts) {
        if now >= self.next_update {
            self.next_update = now + UPDATE_INTERVAL + rand01(&mut self.rng);
            let last = self.last_update;
            self.aircraft
                .retain(|_, ac| now - ac.last_message <= EXPIRY);
            for ac in self.aircraft.values_mut() {
                if ac.last_message <= last {
                    ac.messages += 1;
                    ac.last_message = now;
                }
                ac.adsb_good =
                    now - ac.last_even < POSITION_EXPIRY && now - ac.last_odd < POSITION_EXPIRY;
            }
            self.last_update = now;
            self.next_report += 1.0;
            if self.next_report >= REPORT_INTERVAL {
                self.next_report = 0.0;
                let all: HashSet<u32> = self
                    .aircraft
                    .iter()
                    .filter(|(_, ac)| ac.messages > 1)
                    .map(|(a, _)| *a)
                    .collect();
                let seen: Vec<String> = all
                    .difference(&self.reported)
                    .map(|a| format!("\"{a:06x}\""))
                    .collect();
                let lost: Vec<String> = self
                    .reported
                    .difference(&all)
                    .map(|a| format!("\"{a:06x}\""))
                    .collect();
                if !seen.is_empty() {
                    self.lines
                        .push(format!("{{\"seen\":[{}]}}", seen.join(",")));
                    counts.seen.fetch_add(1, Ordering::Relaxed);
                }
                if !lost.is_empty() {
                    self.lines
                        .push(format!("{{\"lost\":[{}]}}", lost.join(",")));
                }
                self.reported = all;
                let mut report = Vec::new();
                for (address, ac) in &mut self.aircraft {
                    let interval = now - ac.rate_start;
                    if interval > 0.0 && ac.recent_adsb_positions > 0 {
                        let rate = f64::from(ac.recent_adsb_positions) / interval;
                        ac.rate_start = now;
                        ac.recent_adsb_positions = 0;
                        report.push(format!("\"{address:06X}\":{:.2}", rate));
                    }
                }
                if !report.is_empty() {
                    self.lines
                        .push(format!("{{\"rate_report\":{{{}}}}}", report.join(",")));
                    counts.rate_reports.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if now >= self.next_heartbeat {
            self.next_heartbeat = now + 30.0;
            let unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            self.lines
                .push(format!("{{\"heartbeat\":{{\"client_time\":{unix:.3}}}}}"));
        }
    }

    fn deflate_into(&mut self, input: &[u8], flush: MZFlush, into: &mut Vec<u8>) {
        let mut buf = vec![0u8; 65536];
        let mut input = input;
        loop {
            let r =
                miniz_oxide::deflate::stream::deflate(&mut self.compressor, input, &mut buf, flush);
            into.extend_from_slice(&buf[..r.bytes_written]);
            input = &input[r.bytes_consumed..];
            if input.is_empty() && r.bytes_written < buf.len() {
                break;
            }
        }
    }

    /// mlat-client's `fill_zlib`, every 0.25 s (`server_send`), then the socket write.
    fn send(&mut self, now: f64, counts: &Counts) {
        if now >= self.next_send && !self.lines.is_empty() {
            self.next_send = now + 0.25;
            let lines = std::mem::take(&mut self.lines);
            let mut data = Vec::new();
            let mut pending = false;
            for line in lines {
                let mut l = line.into_bytes();
                l.push(b'\n');
                self.deflate_into(&l, MZFlush::None, &mut data);
                pending = true;
                if data.len() >= 32768 {
                    self.frame(&mut data);
                    pending = false;
                }
            }
            if pending {
                self.frame(&mut data);
            }
        } else if now >= self.next_send {
            self.next_send = now + 0.25;
        }
        while !self.out.is_empty() {
            match self.stream.write(&self.out) {
                Ok(n) => {
                    counts.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    self.out.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.out.clear();
                    break;
                }
            }
        }
        let backlog = self.out.len() as u64;
        counts.backlog_max.fetch_max(backlog, Ordering::Relaxed);
        if backlog > 65536 {
            // mlat-client raises 'Server write buffer overflow' here and reconnects.
            counts.overflows.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn frame(&mut self, data: &mut Vec<u8>) {
        self.deflate_into(&[], MZFlush::Sync, data);
        if data.ends_with(&[0, 0, 0xff, 0xff]) {
            data.truncate(data.len() - 4);
        }
        self.out
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.out.extend_from_slice(data);
        data.clear();
    }

    fn receive(&mut self, counts: &Counts) {
        let mut buf = [0u8; 65536];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => self.inbuf.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        loop {
            if self.inbuf.len() < 2 {
                break;
            }
            let len = usize::from(u16::from_be_bytes([self.inbuf[0], self.inbuf[1]]));
            if self.inbuf.len() < 2 + len {
                break;
            }
            let mut packet: Vec<u8> = self.inbuf[2..2 + len].to_vec();
            packet.extend_from_slice(&[0, 0, 0xff, 0xff]);
            self.inbuf.drain(..2 + len);
            let mut input = &packet[..];
            let mut out = vec![0u8; 65536];
            loop {
                let r = miniz_oxide::inflate::stream::inflate(
                    &mut self.inflater,
                    input,
                    &mut out,
                    MZFlush::None,
                );
                self.linebuf.extend_from_slice(&out[..r.bytes_written]);
                input = &input[r.bytes_consumed..];
                if input.is_empty() && r.bytes_written < out.len()
                    || (r.bytes_consumed == 0 && r.bytes_written == 0)
                {
                    break;
                }
            }
            while let Some(at) = self.linebuf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.linebuf.drain(..=at).collect();
                self.server_line(&line, counts);
            }
        }
    }

    fn server_line(&mut self, line: &[u8], counts: &Counts) {
        if line.starts_with(b"{\"result\"") {
            counts.results.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) else {
            return;
        };
        let list = |key: &str| -> Option<Vec<u32>> {
            v.get(key)?.as_array().map(|a| {
                a.iter()
                    .filter_map(|x| u32::from_str_radix(x.as_str()?, 16).ok())
                    .collect()
            })
        };
        if let Some(start) = list("start_sending") {
            counts
                .start_sending
                .fetch_add(start.len() as u64, Ordering::Relaxed);
            for a in start {
                if let Some(ac) = self.aircraft.get_mut(&a) {
                    ac.requested = true;
                }
                self.requested.insert(a);
            }
        } else if let Some(stop) = list("stop_sending") {
            counts
                .stop_sending
                .fetch_add(stop.len() as u64, Ordering::Relaxed);
            for a in stop {
                if let Some(ac) = self.aircraft.get_mut(&a) {
                    ac.requested = false;
                }
                self.requested.remove(&a);
            }
        }
    }
}

fn ticks_of(timebase: Timebase, counter: u64) -> u64 {
    match timebase {
        Timebase::Mhz12 => counter,
        // A GNSS-disciplined receiver's time of day, given as a 12 MHz count (sent as dump1090).
        Timebase::GpsNanos => {
            let nanos =
                (counter >> 30) as u128 * 1_000_000_000 + (counter & ((1 << 30) - 1)) as u128;
            (nanos * 12 / 1000) as u64
        }
    }
}

// ---------------------------------------------------------------- run

fn arg<T: std::str::FromStr>(args: &[String], name: &str, default: Option<T>) -> T {
    match args.iter().position(|a| a == name) {
        Some(at) => args[at + 1]
            .parse()
            .ok()
            .unwrap_or_else(|| panic!("{name}")),
        None => default.unwrap_or_else(|| panic!("{name} is required")),
    }
}

/// One worker's clients: each cluster's, with the cluster and their range of its receivers.
type Shard = Vec<(usize, std::ops::Range<usize>, Vec<Client>)>;

#[allow(
    clippy::disallowed_methods,
    reason = "the emulator plays the scene on the host's clock, as a real client hears it"
)]
fn run(args: &[String]) {
    let server: String = arg(args, "--server", None);
    let feeders: usize = arg(args, "--feeders", None);
    let seconds: f64 = arg(args, "--seconds", None);
    let workers: usize = arg(args, "--workers", Some(8));
    let aircraft: usize = arg(args, "--aircraft", Some(9000));
    let seed: u64 = arg(args, "--seed", Some(0));
    let rps: f64 = arg(args, "--receptions-per-sec", Some(600.0));
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let built = Instant::now();
    let p = probability(feeders, aircraft, seed, rps, threads);
    let world_seconds = seconds + FIRST_S + 3.0;
    let worlds = Arc::new(worlds(feeders, aircraft, seed, world_seconds, p));
    let order: Arc<Vec<Vec<u32>>> = Arc::new(
        worlds
            .iter()
            .map(|w| {
                let mut o: Vec<u32> = (0..w.transmissions.len() as u32)
                    .filter(|i| relevant(&w.transmissions[*i as usize].data))
                    .collect();
                o.sort_by(|a, b| {
                    w.transmissions[*a as usize]
                        .time
                        .total_cmp(&w.transmissions[*b as usize].time)
                });
                o
            })
            .collect(),
    );
    eprintln!(
        "EMU built p={p:.4} world_seconds={world_seconds} transmissions={},{} relevant={},{} in {:.0} s",
        worlds[0].transmissions.len(),
        worlds[1].transmissions.len(),
        order[0].len(),
        order[1].len(),
        built.elapsed().as_secs_f64()
    );
    // Connect every client, cluster by cluster, worker by worker.
    let sizes = layout(feeders);
    let mut shards: Vec<Shard> = (0..workers).map(|_| Vec::new()).collect();
    for (c, &n) in sizes.iter().enumerate() {
        for (w, shard) in shards.iter_mut().enumerate() {
            let range = n * w / workers..n * (w + 1) / workers;
            let mut clients = Vec::with_capacity(range.len());
            for i in range.clone() {
                let r = &worlds[c].receivers[i];
                let loc = r.site.location;
                let user = format!("c{c}r{i}");
                let client = loop {
                    match Client::connect(
                        &server,
                        user.clone(),
                        f64::from(loc.lat_e7) * 1e-7,
                        f64::from(loc.lon_e7) * 1e-7,
                        f64::from(loc.alt_m),
                        (c as u64) << 32 | i as u64,
                    ) {
                        Ok(client) => break client,
                        Err(e) => {
                            eprintln!("EMU connect {user}: {e}; retrying");
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                };
                clients.push(client);
            }
            shard.push((c, range, clients));
        }
    }
    let t0 = SystemTime::now() + Duration::from_secs(2);
    let t0_unix_ms = t0.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let start = Instant::now() + Duration::from_secs(2);
    eprintln!("EMU connected {feeders} clients; t0_unix_ms={t0_unix_ms} (scene t={FIRST_S})");
    let counts = Arc::new(Counts::default());
    let end = seconds;
    let handles: Vec<_> = shards
        .into_iter()
        .map(|mut shard| {
            let (worlds, order, counts) =
                (Arc::clone(&worlds), Arc::clone(&order), Arc::clone(&counts));
            std::thread::spawn(move || {
                let mut next = [0usize; 2];
                let (mut near, mut heard): (Vec<usize>, Vec<Heard>) = (Vec::new(), Vec::new());
                for (_, _, clients) in &mut shard {
                    for client in clients.iter_mut() {
                        client.start(FIRST_S);
                    }
                }
                let tick = Duration::from_millis(20);
                let mut at = start;
                loop {
                    let now_i = Instant::now();
                    if now_i < at {
                        std::thread::sleep(at - now_i);
                    } else {
                        counts
                            .lag_ms_max
                            .fetch_max((now_i - at).as_millis() as u64, Ordering::Relaxed);
                    }
                    let elapsed = Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64();
                    if elapsed > end {
                        break;
                    }
                    let now = FIRST_S + elapsed;
                    for (c, range, clients) in &mut shard {
                        let world = &worlds[*c];
                        let list = &order[*c];
                        while next[*c] < list.len()
                            && world.transmissions[list[next[*c]] as usize].time <= now
                        {
                            let index = list[next[*c]] as usize;
                            next[*c] += 1;
                            let t = &world.transmissions[index];
                            if t.time < FIRST_S {
                                continue;
                            }
                            heard.clear();
                            world.hear(
                                index,
                                range,
                                false,
                                world.scenario.reception_probability,
                                &mut near,
                                &mut heard,
                            );
                            counts
                                .receptions
                                .fetch_add(heard.len() as u64, Ordering::Relaxed);
                            for h in &heard {
                                let tb = world.receivers[h.receiver].truth.timebase;
                                clients[h.receiver - range.start].message(
                                    &t.data,
                                    ticks_of(tb, h.counter),
                                    now,
                                    &counts,
                                );
                            }
                        }
                        for client in clients.iter_mut() {
                            client.heartbeat(now, &counts);
                            client.send(now, &counts);
                            client.receive(&counts);
                        }
                    }
                    at += tick;
                }
                drop(shard);
            })
        })
        .collect();
    let mut last = [0u64; 6];
    let mut second = 0u64;
    while handles.iter().any(|h| !h.is_finished()) {
        std::thread::sleep(Duration::from_secs(10));
        second += 10;
        let now = [
            counts.sync.load(Ordering::Relaxed),
            counts.mlat.load(Ordering::Relaxed),
            counts.results.load(Ordering::Relaxed),
            counts.bytes_out.load(Ordering::Relaxed),
            counts.receptions.load(Ordering::Relaxed),
            counts.start_sending.load(Ordering::Relaxed),
        ];
        eprintln!(
            "EMU t+{second}s sync/s {:.0} mlat/s {:.0} results/s {:.0} kB/s {:.0} receptions/s {:.0} start_sending {} overflows {} backlog_max {} lag_ms_max {}",
            (now[0] - last[0]) as f64 / 10.0,
            (now[1] - last[1]) as f64 / 10.0,
            (now[2] - last[2]) as f64 / 10.0,
            (now[3] - last[3]) as f64 / 10240.0,
            (now[4] - last[4]) as f64 / 10.0,
            now[5],
            counts.overflows.load(Ordering::Relaxed),
            counts.backlog_max.load(Ordering::Relaxed),
            counts.lag_ms_max.load(Ordering::Relaxed)
        );
        last = now;
    }
    for h in handles {
        let _ = h.join();
    }
    println!(
        "{}",
        serde_json::json!({
            "feeders": feeders, "seconds": seconds, "world_seconds": world_seconds, "p": p, "t0_unix_ms": t0_unix_ms,
            "sync": counts.sync.load(Ordering::Relaxed), "mlat": counts.mlat.load(Ordering::Relaxed),
            "results": counts.results.load(Ordering::Relaxed), "bytes_out": counts.bytes_out.load(Ordering::Relaxed),
            "receptions": counts.receptions.load(Ordering::Relaxed), "overflows": counts.overflows.load(Ordering::Relaxed),
            "lag_ms_max": counts.lag_ms_max.load(Ordering::Relaxed),
        })
    );
}

// ---------------------------------------------------------------- eval

fn horizontal(truth: [f64; 3], lat: f64, lon: f64) -> f64 {
    let t = geo::from_ecef(truth);
    let fix = geo::to_ecef(Geodetic {
        lat_deg: lat,
        lon_deg: lon,
        height_m: t.height_m,
    });
    let basis = geo::enu_basis(t.lat_deg, t.lon_deg);
    let d = [fix[0] - truth[0], fix[1] - truth[1], fix[2] - truth[2]];
    let e = d[0] * basis[0][0] + d[1] * basis[0][1] + d[2] * basis[0][2];
    let n = d[0] * basis[1][0] + d[1] * basis[1][1] + d[2] * basis[1][2];
    (e * e + n * n).sqrt()
}

fn percentile(v: &mut [f64], q: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(f64::total_cmp);
    v[((v.len() - 1) as f64 * q).round() as usize]
}

/// Scores fixes (`ADDR_HEX,UNIX_S,LAT,LON` lines) against the scene: of the Mode S-only aircraft,
/// the (aircraft, 0.7 s slot) pairs with a transmission heard by four or more receivers, the share
/// with a fix, and each fix's horizontal error at its stated time and at the nearest point of its
/// aircraft's track within a second.
fn eval(args: &[String]) {
    let feeders: usize = arg(args, "--feeders", None);
    let world_seconds: f64 = arg(args, "--world-seconds", None);
    let aircraft: usize = arg(args, "--aircraft", Some(9000));
    let seed: u64 = arg(args, "--seed", Some(0));
    let rps: f64 = arg(args, "--receptions-per-sec", Some(600.0));
    let fixes_path: String = arg(args, "--fixes", None);
    let t0_unix_ms: f64 = arg(args, "--t0-unix-ms", None);
    let (from, to): (f64, f64) = (arg(args, "--from", None), arg(args, "--to", None));
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let p = probability(feeders, aircraft, seed, rps, threads);
    let worlds = worlds(feeders, aircraft, seed, world_seconds, p);
    // Each aircraft's track (its transmissions are contiguous and in time order) and whether it
    // sends ADS-B.
    let mut tracks: HashMap<u32, Vec<(usize, usize, usize, bool)>> = HashMap::new();
    for (c, w) in worlds.iter().enumerate() {
        let mut i = 0;
        while i < w.transmissions.len() {
            let a = w.transmissions[i].address;
            let mut j = i;
            while j < w.transmissions.len() && w.transmissions[j].address == a {
                j += 1;
            }
            tracks
                .entry(a)
                .or_default()
                .push((c, i, j, w.transmissions[i].adsb));
            i = j;
        }
    }
    let at = |c: usize, i: usize, j: usize, t: f64| -> [f64; 3] {
        let tx = &worlds[c].transmissions[i..j];
        let k = tx.partition_point(|x| x.time < t).clamp(1, tx.len() - 1);
        let (a, b) = (&tx[k - 1], &tx[k]);
        let f = if b.time > a.time {
            (t - a.time) / (b.time - a.time)
        } else {
            0.0
        };
        [0, 1, 2].map(|q| a.ecef[q] + (b.ecef[q] - a.ecef[q]) * f)
    };
    // Eligible slots.
    let mut eligible: HashSet<(u32, i64)> = HashSet::new();
    for (c, w) in worlds.iter().enumerate() {
        let n = w.receivers.len();
        let idx: Vec<usize> = (0..w.transmissions.len())
            .filter(|i| {
                let t = &w.transmissions[*i];
                !t.adsb && t.time >= from && t.time < to && relevant(&t.data)
            })
            .collect();
        let parts = chunks(idx.len(), threads, |range| {
            let (mut near, mut heard) = (Vec::new(), Vec::new());
            let mut out = Vec::new();
            for &i in &idx[range] {
                heard.clear();
                w.hear(
                    i,
                    &(0..n),
                    false,
                    w.scenario.reception_probability,
                    &mut near,
                    &mut heard,
                );
                if heard.len() >= 4 {
                    let t = &w.transmissions[i];
                    out.push((t.address, (t.time / 0.7).floor() as i64));
                }
            }
            out
        });
        let _ = c;
        for part in parts {
            eligible.extend(part);
        }
    }
    let text = std::fs::read_to_string(&fixes_path).expect("fixes");
    let (mut at_time, mut on_track) = (Vec::new(), Vec::new());
    let (mut fixes, mut adsb_fixes, mut unknown) = (0usize, 0usize, 0usize);
    let mut solved: HashSet<(u32, i64)> = HashSet::new();
    let mut seen_fix: HashSet<(u32, i64)> = HashSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 4 {
            continue;
        }
        let (Ok(a), Ok(unix), Ok(lat), Ok(lon)) = (
            u32::from_str_radix(f[0], 16),
            f[1].parse::<f64>(),
            f[2].parse::<f64>(),
            f[3].parse::<f64>(),
        ) else {
            continue;
        };
        let t = FIRST_S + (unix * 1000.0 - t0_unix_ms) / 1000.0;
        if t < from || t >= to {
            continue;
        }
        if !seen_fix.insert((a, (t * 1000.0).round() as i64)) {
            continue; // the same fix again (a bigger considered set, or a twin)
        }
        let Some(list) = tracks.get(&a) else {
            unknown += 1;
            continue;
        };
        // The cluster whose aircraft of this address is nearest the fix.
        let best = list
            .iter()
            .map(|&(c, i, j, adsb)| (horizontal(at(c, i, j, t), lat, lon), c, i, j, adsb))
            .min_by(|x, y| x.0.total_cmp(&y.0))
            .unwrap();
        if best.4 {
            adsb_fixes += 1;
            continue;
        }
        fixes += 1;
        at_time.push(best.0);
        let mut least = f64::MAX;
        let mut dt = -1.0;
        while dt <= 1.0 {
            least = least.min(horizontal(at(best.1, best.2, best.3, t + dt), lat, lon));
            dt += 0.005;
        }
        on_track.push(least);
        solved.insert((a, (t / 0.7).floor() as i64));
    }
    let solved_eligible = solved.intersection(&eligible).count();
    println!(
        "{}",
        serde_json::json!({
            "feeders": feeders, "window_s": to - from, "eligible_slots": eligible.len(), "solved_slots": solved_eligible,
            "solved_fraction": solved_eligible as f64 / eligible.len().max(1) as f64,
            "modes_fixes": fixes, "modes_fixes_per_s": fixes as f64 / (to - from), "adsb_fixes": adsb_fixes, "unknown": unknown,
            "h_at_time_p50": percentile(&mut at_time.clone(), 0.5), "h_at_time_p95": percentile(&mut at_time, 0.95),
            "h_on_track_p50": percentile(&mut on_track.clone(), 0.5), "h_on_track_p95": percentile(&mut on_track, 0.95),
        })
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => run(&args),
        Some("eval") => eval(&args),
        _ => eprintln!("mlat-emu run|eval ..."),
    }
}
