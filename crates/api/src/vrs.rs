//! Routes (RFC-0187 §2): a callsign's scheduled route from VRS standing data (Virtual Radar
//! Server's, github.com/vradarserver/standing-data, CC0), answered in adsb.lol's shape and judged
//! against where the aircraft is by adsb.lol's plausibility threshold (github.com/adsblol/api,
//! BSD-3-Clause: `api_routes.py`, `plausible.py` and the route reading of `provider.py`, ported
//! here, their notice below; `plausible` says where the check departs from theirs).
//!
//! - `POST /api/0/routeset`: the body tar1090 sends (its `routeApiUrl`), at most `MAX_PLANES`
//!   callsigns with positions, answered with one route per distinct callsign in the order asked.
//! - `GET /api/0/route/{callsign}/{lat}/{lon}`: one.
//!
//! The data is a directory the operator keeps (`--routes DIR`, a checkout of standing-data holding
//! its `routes/` and `airports/` CSV files), read at start and again whenever its files change
//! (`keep`), into a compact table (`Standing`). Without the flag the routes answer `404` and say
//! why; with it, `503` until the first read.
//
// Copyright (c) 2023, Katia Esposito
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path as FilePath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tally_api_types::{Route, RouteAirport, RoutePlane, RouteSetRequest};

use crate::routes::refuse;
use crate::{App, v2};

/// The most callsigns one `routeset` may ask: adsb.lol's, and as many as tar1090 sends at once.
pub const MAX_PLANES: usize = 100;
/// The largest `routeset` body read: `MAX_PLANES` planes at well under 100 bytes each, with room.
/// A larger one is refused (`413`) before it is read whole.
pub const MAX_BODY_BYTES: usize = 16 * 1024;
/// How often the directory is looked at for changed files.
pub const CHECK_EVERY: Duration = Duration::from_secs(60);
/// What every code of a route the data does not hold reads.
pub const UNKNOWN: &str = "unknown";

const EARTH_RADIUS_M: f64 = 6_371_000.0;
const METRES_PER_NM: f64 = 1852.0;

/// No airport: what `Standing::airport_of` holds for a code the airports files do not name.
const NO_AIRPORT: u32 = u32::MAX;

/// Strings held once each, end to end in one text, each named by its place among them.
#[derive(Debug, Default)]
struct Texts {
    text: String,
    ends: Vec<u32>,
}

impl Texts {
    fn get(&self, id: u32) -> &str {
        let id = id as usize;
        let start = id
            .checked_sub(1)
            .map_or(0, |before| self.ends[before] as usize);
        &self.text[start..self.ends[id] as usize]
    }

    fn len(&self) -> usize {
        self.ends.len()
    }

    fn shrink_to_fit(&mut self) {
        self.text.shrink_to_fit();
        self.ends.shrink_to_fit();
    }
}

/// `Texts` being written: each string's name, found by the string, while the data is read.
#[derive(Debug, Default)]
struct Interner {
    texts: Texts,
    ids: HashMap<Box<str>, u32>,
}

impl Interner {
    fn id(&mut self, text: &str) -> std::io::Result<u32> {
        if let Some(&id) = self.ids.get(text) {
            return Ok(id);
        }
        let id = index(self.texts.ends.len())?;
        self.texts.text.push_str(text);
        self.texts.ends.push(index(self.texts.text.len())?);
        self.ids.insert(text.into(), id);
        Ok(id)
    }

    fn done(self) -> Texts {
        let mut texts = self.texts;
        texts.shrink_to_fit();
        texts
    }
}

/// `n` as a place in one of the standing data's lists, which a `u32` names.
fn index(n: usize) -> std::io::Result<u32> {
    u32::try_from(n).map_err(|_| std::io::Error::other("the standing data is too large to hold"))
}

/// One route row (`Callsign,Code,Number,AirlineCode,AirportCodes`): its number and airline's code
/// names in `Standing::texts`, and where its callsign and airport codes start in `Rows`.
#[derive(Clone, Copy, Debug)]
struct Row {
    callsign: u32,
    number: u32,
    airline_code: u32,
    codes: u32,
}

/// The route rows in reading order. A row's callsign (upper case) runs in `callsigns`, and its
/// airport codes (the row's codes between its dashes, as names in `Standing::codes`) in `codes`,
/// from its own start to the next row's.
#[derive(Debug, Default)]
struct Rows {
    callsigns: String,
    rows: Vec<Row>,
    codes: Vec<u32>,
}

impl Rows {
    fn callsign(&self, row: u32) -> &str {
        let row = row as usize;
        let end = self
            .rows
            .get(row + 1)
            .map_or(self.callsigns.len(), |next| next.callsign as usize);
        &self.callsigns[self.rows[row].callsign as usize..end]
    }

    fn codes(&self, row: u32) -> &[u32] {
        let row = row as usize;
        let end = self
            .rows
            .get(row + 1)
            .map_or(self.codes.len(), |next| next.codes as usize);
        &self.codes[self.rows[row].codes as usize..end]
    }

    fn shrink_to_fit(&mut self) {
        self.callsigns.shrink_to_fit();
        self.rows.shrink_to_fit();
        self.codes.shrink_to_fit();
    }
}

/// One airports row (`Code,Name,ICAO,IATA,Location,CountryISO2,Latitude,Longitude,
/// AltitudeFeet`): its code a name in `Standing::codes`, its words names in `Standing::texts`.
#[derive(Clone, Copy, Debug)]
struct Airport {
    code: u32,
    name: u32,
    iata: u32,
    location: u32,
    country: u32,
    lat: f64,
    lon: f64,
    alt_feet: f64,
}

/// The standing data being read, file by file (`Load::add_routes`, `Load::add_airports`), until
/// it is held (`Load::finish`).
#[derive(Debug, Default)]
pub struct Load {
    rows: Rows,
    codes: Interner,
    texts: Interner,
    airports: Vec<Airport>,
    airport_of: Vec<u32>,
}

impl Load {
    /// Adds one routes file's rows; its header, and a row too short to be one, are passed over.
    /// A callsign read again is the later row's.
    pub fn add_routes(&mut self, file: impl BufRead) -> std::io::Result<()> {
        let mut row = Vec::new();
        each_line(file, |line| {
            fields(line, &mut row);
            let [callsign, _, number, airline_code, airport_codes] = row.as_slice() else {
                return Ok(());
            };
            if callsign == "Callsign" {
                return Ok(());
            }
            let rows = &mut self.rows;
            let (start, codes) = (rows.callsigns.len(), rows.codes.len());
            rows.callsigns.push_str(callsign);
            rows.callsigns[start..].make_ascii_uppercase();
            for code in airport_codes.split('-') {
                rows.codes.push(self.codes.id(code)?);
            }
            // Every row has a code (`split` yields at least one), so `codes` checks how many rows.
            index(rows.codes.len())?;
            rows.rows.push(Row {
                callsign: index(start)?,
                number: self.texts.id(number)?,
                airline_code: self.texts.id(airline_code)?,
                codes: index(codes)?,
            });
            index(rows.callsigns.len())?;
            Ok(())
        })
    }

    /// Adds one airports file's rows. A row whose place or height is not a number is no airport,
    /// as adsb.lol reads it, and a code read again is the later row's.
    pub fn add_airports(&mut self, file: impl BufRead) -> std::io::Result<()> {
        let mut row = Vec::new();
        each_line(file, |line| {
            fields(line, &mut row);
            let [code, name, _, iata, location, country, lat, lon, alt_feet] = row.as_slice()
            else {
                return Ok(());
            };
            let (Ok(lat), Ok(lon), Ok(alt_feet)) = (
                lat.parse::<f64>(),
                lon.parse::<f64>(),
                alt_feet.parse::<f64>(),
            ) else {
                return Ok(());
            };
            let code = self.codes.id(code)?;
            let airport = Airport {
                code,
                name: self.texts.id(name)?,
                iata: self.texts.id(iata)?,
                location: self.texts.id(location)?,
                country: self.texts.id(country)?,
                lat,
                lon,
                alt_feet,
            };
            let slot = code as usize;
            if self.airport_of.len() <= slot {
                self.airport_of.resize(slot + 1, NO_AIRPORT);
            }
            match self.airport_of[slot] {
                NO_AIRPORT => {
                    self.airport_of[slot] = index(self.airports.len())?;
                    self.airports.push(airport);
                }
                held => self.airports[held as usize] = airport,
            }
            Ok(())
        })
    }

    /// The data as held: the rows as read, ordered by callsign with each callsign's last row, and
    /// nothing of the reading kept.
    pub fn finish(self) -> Standing {
        let (codes, texts) = (self.codes.done(), self.texts.done());
        let mut rows = self.rows;
        rows.shrink_to_fit();
        // Within `u32`: `add_routes` checked as many codes, and every row has one.
        let mut order: Vec<u32> = (0..rows.rows.len() as u32).collect();
        // In callsign order, and in reading order within one callsign (the sort is stable), so the
        // last of each run is the row read last.
        order.sort_by(|&a, &b| rows.callsign(a).cmp(rows.callsign(b)));
        order.dedup_by(|later, earlier| {
            let same = rows.callsign(*later) == rows.callsign(*earlier);
            if same {
                *earlier = *later;
            }
            same
        });
        order.shrink_to_fit();
        let mut airport_of = self.airport_of;
        airport_of.resize(codes.len(), NO_AIRPORT);
        airport_of.shrink_to_fit();
        let mut airports = self.airports;
        airports.shrink_to_fit();
        Standing {
            rows,
            order,
            codes,
            airport_of,
            airports,
            texts,
        }
    }
}

/// The standing data as held: routes by callsign, airports by code.
///
/// Held compact, because the API runs in 256 MiB: every string once (a code, a flight number, an
/// airline's code, an airport's words) in one text, a route four `u32`s and its place in the
/// callsign order a fifth, its callsign and codes runs of shared lists, found by binary search.
///
/// Measured on standing-data of 2026-10-19 (620,736 routes, 34,128 airports, a counting allocator
/// in a release build): it holds 24.3 MiB of heap (36 MiB resident in all), against 122.8 MiB
/// (198 MiB resident) as maps of owned strings. Reading it peaks at 43.9 MiB, so a read beside
/// the data it replaces (`keep`) peaks at 68.2 MiB, against 278 MiB (394 MiB resident).
#[derive(Debug, Default)]
pub struct Standing {
    rows: Rows,
    /// The rows by callsign, each callsign's last.
    order: Vec<u32>,
    /// Every airport code, of routes and airports alike.
    codes: Texts,
    /// For each code, its airport's place in `airports`, or `NO_AIRPORT`.
    airport_of: Vec<u32>,
    airports: Vec<Airport>,
    /// Every other string: flight numbers, airlines' codes, airports' words.
    texts: Texts,
}

impl Standing {
    /// Reads every CSV file under `dir`'s `routes/` and `airports/`, however deep (standing-data
    /// splits each by its first letters), a line at a time.
    pub fn load(dir: &FilePath) -> Result<Self, String> {
        let mut load = Load::default();
        let open = |file: &FilePath| {
            std::fs::File::open(file)
                .map(BufReader::new)
                .map_err(|error| format!("{}: {error}", file.display()))
        };
        for file in csv_files(&dir.join("routes"))? {
            load.add_routes(open(&file)?)
                .map_err(|error| format!("{}: {error}", file.display()))?;
        }
        for file in csv_files(&dir.join("airports"))? {
            load.add_airports(open(&file)?)
                .map_err(|error| format!("{}: {error}", file.display()))?;
        }
        Ok(load.finish())
    }

    pub fn routes(&self) -> usize {
        self.order.len()
    }

    pub fn airports(&self) -> usize {
        self.airports.len()
    }

    /// The row of the route `callsign` names (upper case), by binary search.
    fn find(&self, callsign: &str) -> Option<u32> {
        let at = self
            .order
            .binary_search_by(|&row| self.rows.callsign(row).cmp(callsign))
            .ok()?;
        Some(self.order[at])
    }

    /// The airport `code` names, as the routes answer it, when the data holds one.
    fn airport(&self, code: u32) -> Option<RouteAirport> {
        let airport = self
            .airports
            .get(*self.airport_of.get(code as usize)? as usize)?;
        let text = |id| self.texts.get(id).to_owned();
        Some(RouteAirport {
            name: text(airport.name),
            icao: self.codes.get(airport.code).to_owned(),
            iata: text(airport.iata),
            location: text(airport.location),
            countryiso2: text(airport.country),
            lat: airport.lat,
            lon: airport.lon,
            alt_feet: airport.alt_feet,
            alt_meters: (airport.alt_feet * 0.3048 * 100.0).round() / 100.0,
        })
    }

    /// `callsign`'s route, judged against `at` (latitude, longitude) when the client gave it.
    pub fn route(&self, callsign: &str, at: Option<(f64, f64)>) -> Route {
        let unknown = |number: &str, airline_code: &str| Route {
            callsign: callsign.to_owned(),
            number: number.to_owned(),
            airline_code: airline_code.to_owned(),
            airport_codes: UNKNOWN.to_owned(),
            airport_codes_iata: UNKNOWN.to_owned(),
            airports: Vec::new(),
            plausible: None,
        };
        let Some(found) = self.find(&callsign.trim().to_ascii_uppercase()) else {
            return unknown(UNKNOWN, UNKNOWN);
        };
        let row = self.rows.rows[found as usize];
        let (number, airline_code) = (self.texts.get(row.number), self.texts.get(row.airline_code));
        let ids = self.rows.codes(found);
        let codes: Vec<&str> = ids.iter().map(|&code| self.codes.get(code)).collect();
        let airport_codes = codes.join("-");
        if airport_codes == UNKNOWN {
            return unknown(number, airline_code);
        }
        let known: Vec<Option<RouteAirport>> = ids.iter().map(|&code| self.airport(code)).collect();
        let airports: Vec<RouteAirport> = known.iter().flatten().cloned().collect();
        // Each ICAO code written as its airport's IATA code, where it has one, code by code.
        let airport_codes_iata = codes
            .iter()
            .zip(&known)
            .map(|(code, known)| match known {
                Some(airport) if code.len() == 4 && !airport.iata.is_empty() => {
                    airport.iata.as_str()
                }
                _ => code,
            })
            .collect::<Vec<_>>()
            .join("-");
        // The legs are the route's, code after code: a leg with an end the data does not hold is
        // not known, and is never bridged by joining the airports either side of it.
        let legs: Vec<(&RouteAirport, &RouteAirport)> = known
            .windows(2)
            .filter_map(|pair| Some((pair[0].as_ref()?, pair[1].as_ref()?)))
            .collect();
        let plausible = at
            .filter(|_| !legs.is_empty())
            .map(|(lat, lon)| on_route(&legs, lat, lon));
        Route {
            callsign: callsign.to_owned(),
            number: number.to_owned(),
            airline_code: airline_code.to_owned(),
            airport_codes,
            airport_codes_iata,
            airports,
            plausible,
        }
    }
}

/// Whether an aircraft at `lat`, `lon` is plausibly flying one of `legs` (each a route's airport and
/// the next): near any of them (`plausible`), everything to three decimals as adsb.lol rounds it.
/// A route with no known leg has no plausibility at all (`Standing::route` answers `null`).
pub fn on_route(legs: &[(&RouteAirport, &RouteAirport)], lat: f64, lon: f64) -> bool {
    let round = |degrees: f64| (degrees * 1000.0).round() / 1000.0;
    legs.iter().any(|(from, to)| {
        plausible(
            (round(lat), round(lon)),
            (round(from.lat), round(from.lon)),
            (round(to.lat), round(to.lon)),
        )
    })
}

fn hav(x: f64) -> f64 {
    (1.0 - x.cos()) / 2.0
}

/// The angle between two places (latitude, longitude, in radians), by the haversine.
fn angle(a: (f64, f64), b: (f64, f64)) -> f64 {
    let hav_distance = hav(b.0 - a.0) + a.0.cos() * b.0.cos() * hav(b.1 - a.1);
    2.0 * hav_distance.sqrt().asin()
}

/// The initial bearing from `a` to `b`, radians.
fn bearing(a: (f64, f64), b: (f64, f64)) -> f64 {
    let dlon = b.1 - a.1;
    (dlon.sin() * b.0.cos()).atan2(a.0.cos() * b.0.sin() - a.0.sin() * b.0.cos() * dlon.cos())
}

/// Whether a place `at` is near the great-circle leg from `a` to `b` (each latitude, longitude, in
/// degrees): within adsb.lol's threshold, 50 nm or a fifth of the leg's length, whichever is more,
/// of the nearest point of the leg (an end, or the foot of the cross-track distance when it falls
/// between them).
///
/// adsb.lol's threshold, measured as its check means to measure it: its `_plausible_sync`
/// compares the distance from the first airport and then a product it calls a cross-track
/// approximation (that distance's haversine times the haversine of the leg's span of longitude),
/// which is no distance from the leg, so an aircraft arriving at the second airport fails it; and
/// its `calc_plausible` tests the tuple the check returns, which is always true, so every route
/// with two airports it holds reads plausible.
pub fn plausible(at: (f64, f64), a: (f64, f64), b: (f64, f64)) -> bool {
    let radians = |(lat, lon): (f64, f64)| (lat.to_radians(), lon.to_radians());
    let (at, a, b) = (radians(at), radians(a), radians(b));
    let leg = angle(a, b);
    let threshold = (50.0 * METRES_PER_NM).max(0.20 * leg * EARTH_RADIUS_M) / EARTH_RADIUS_M;
    let from_a = angle(a, at);
    if from_a <= threshold || angle(b, at) <= threshold {
        return true;
    }
    let turn = bearing(a, at) - bearing(a, b);
    let cross_track = (from_a.sin() * turn.sin()).asin();
    let along_track = (from_a.cos() / cross_track.cos()).clamp(-1.0, 1.0).acos();
    turn.cos() >= 0.0 && along_track <= leg && cross_track.abs() <= threshold
}

/// One CSV line's fields, into `fields`: commas separate them, and a field in double quotes may
/// hold commas and doubled quotes (standing-data quotes a place such as `"Lydd, Ashford"`).
fn fields(line: &str, fields: &mut Vec<String>) {
    fields.clear();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted => {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            }
            '"' if field.is_empty() => quoted = true,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            c => field.push(c),
        }
    }
    fields.push(field);
}

/// Each line of `file` to `each`, one at a time, split as `str::lines` splits a text (at `\n`,
/// and a `\r` before it), with the byte-order marks it starts with passed over.
fn each_line(
    mut file: impl BufRead,
    mut each: impl FnMut(&str) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut line = String::new();
    let mut first = true;
    loop {
        line.clear();
        if file.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut text = line.as_str();
        if std::mem::take(&mut first) {
            text = text.trim_start_matches('\u{feff}');
        }
        if let Some(ended) = text.strip_suffix('\n') {
            text = ended.strip_suffix('\r').unwrap_or(ended);
        }
        each(text)?;
    }
}

/// Every `.csv` file under `dir`, however deep, in name order. A symbolic link is passed over, file
/// or directory: one pointing back up the tree would walk it forever, and the data is the
/// checkout's own files.
fn csv_files(dir: &FilePath) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|error| format!("{}: {error}", dir.display()))?
                .path();
            let kind = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?
                .file_type();
            if kind.is_dir() {
                dirs.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "csv")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// What says the directory's files changed: each file's path, length and modification time.
pub type Fingerprint = Vec<(PathBuf, u64, Option<SystemTime>)>;

pub fn fingerprint(dir: &FilePath) -> Result<Fingerprint, String> {
    let mut files = csv_files(&dir.join("routes"))?;
    files.extend(csv_files(&dir.join("airports"))?);
    Ok(files
        .into_iter()
        .map(|file| {
            let metadata = std::fs::metadata(&file).ok();
            let length = metadata.as_ref().map_or(0, std::fs::Metadata::len);
            let modified = metadata.and_then(|metadata| metadata.modified().ok());
            (file, length, modified)
        })
        .collect())
}

/// The standing data the routes answer from: none until first read.
#[derive(Default)]
pub struct Held(RwLock<Option<Arc<Standing>>>);

impl Held {
    pub fn get(&self) -> Option<Arc<Standing>> {
        self.0.read().ok()?.clone()
    }

    pub fn set(&self, standing: Standing) {
        if let Ok(mut held) = self.0.write() {
            *held = Some(Arc::new(standing));
        }
    }
}

/// Reads `dir` into `held` when its files are not the ones `read` fingerprints (none: never read),
/// and says whether it read. Files unchanged are not read again: the data held is theirs. A read
/// that fails keeps what was held and `read` as it was, so the next look tries again.
pub fn look(dir: &FilePath, held: &Held, read: &mut Option<Fingerprint>) -> Result<bool, String> {
    let seen = fingerprint(dir)?;
    if read.as_ref() == Some(&seen) {
        return Ok(false);
    }
    let standing = Standing::load(dir)?;
    eprintln!(
        "tally-api: routes: {} routes, {} airports",
        standing.routes(),
        standing.airports()
    );
    held.set(standing);
    *read = Some(seen);
    Ok(true)
}

/// Reads `dir` into `held` now, and again whenever its files change (`look`, every
/// `CHECK_EVERY`), for as long as the API runs.
pub async fn keep(dir: PathBuf, held: Arc<Held>) {
    let mut read: Option<Fingerprint> = None;
    loop {
        let (dir, held) = (dir.clone(), Arc::clone(&held));
        let looked = tokio::task::spawn_blocking(move || {
            let looked = look(&dir, &held, &mut read);
            (looked, read)
        })
        .await;
        read = match looked {
            Ok((Ok(_), read)) => read,
            Ok((Err(error), read)) => {
                eprintln!("tally-api: routes: {error}");
                read
            }
            // The look did not finish: read again at the next.
            Err(error) => {
                eprintln!("tally-api: routes: {error}");
                None
            }
        };
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// The standing data, or why the routes cannot be answered.
fn standing(app: &App) -> Result<Arc<Standing>, (StatusCode, &'static str)> {
    if app.settings.routes.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "this API serves no routes: its operator gave it no --routes directory",
        ));
    }
    app.routes.get().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "the routes are not read yet",
    ))
}

/// `POST /api/0/routeset`.
pub async fn routeset(
    State(app): State<Arc<App>>,
    asked: Result<axum::Json<RouteSetRequest>, JsonRejection>,
) -> Response {
    let standing = match standing(&app) {
        Ok(standing) => standing,
        Err((status, why)) => return refuse(status, why),
    };
    let planes = match asked {
        Ok(axum::Json(asked))
            if (1..=MAX_PLANES).contains(&asked.planes.len())
                && asked
                    .planes
                    .iter()
                    .all(|plane| is_callsign(&plane.callsign)) =>
        {
            asked.planes
        }
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return refuse(StatusCode::PAYLOAD_TOO_LARGE, "the body is at most 16 KiB");
        }
        _ => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "the body is JSON, {\"planes\": [{\"callsign\", \"lat\", \"lng\"}]}, 1 to 100 of them, each callsign up to eight characters",
            );
        }
    };
    axum::Json(routes_of(&standing, &planes)).into_response()
}

/// The routes of `planes`: one per distinct callsign, in the order first asked, each judged against
/// the position it was first asked with.
pub fn routes_of(standing: &Standing, planes: &[RoutePlane]) -> Vec<Route> {
    let mut asked = HashSet::new();
    planes
        .iter()
        .filter(|plane| asked.insert(plane.callsign.as_str()))
        .map(|plane| standing.route(&plane.callsign, plane.lat.zip(plane.lng)))
        .collect()
}

/// Whether `text` can be a callsign, as `/v2`'s callsign rule bounds one (`v2::MAX_CALLSIGN`):
/// once trimmed, as `Standing::route` reads it, at most that many characters.
fn is_callsign(text: &str) -> bool {
    text.trim().chars().count() <= v2::MAX_CALLSIGN
}

/// `GET /api/0/route/{callsign}/{lat}/{lon}`.
pub async fn route(
    State(app): State<Arc<App>>,
    Path((callsign, lat, lon)): Path<(String, String, String)>,
) -> Response {
    let standing = match standing(&app) {
        Ok(standing) => standing,
        Err((status, why)) => return refuse(status, why),
    };
    let degrees = |text: &str, limit: f64| {
        text.parse::<f64>()
            .ok()
            .filter(|value| value.is_finite() && value.abs() <= limit)
    };
    if !is_callsign(&callsign) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "a callsign is up to eight characters",
        );
    }
    let (Some(lat), Some(lon)) = (degrees(&lat, 90.0), degrees(&lon, 180.0)) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "lat is degrees from -90 to 90, and lon degrees from -180 to 180",
        );
    };
    axum::Json(standing.route(&callsign, Some((lat, lon)))).into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Two routes files and two airports files, as standing-data lays them out: a header, a
    /// byte-order mark, a quoted place, a route of three airports, one whose airports are not
    /// known, and an airport whose height is not given.
    pub const ROUTES_B: &str = "\u{feff}Callsign,Code,Number,AirlineCode,AirportCodes\r\n\
        BAW1,BAW,1,BAW,EGLL-KJFK\r\n\
        BAW15,BAW,15,BAW,EGLL-VTBS-YSSY\r\n\
        BAW9X,BAW,9X,BAW,unknown\r\n";
    pub const ROUTES_E: &str = "\u{feff}Callsign,Code,Number,AirlineCode,AirportCodes\n\
        EZY12,EZY,12,EZY,EGMD-ZZZZ\n";
    pub const AIRPORTS_E: &str = "\u{feff}Code,Name,ICAO,IATA,Location,CountryISO2,Latitude,Longitude,AltitudeFeet\n\
        EGLL,London Heathrow Airport,EGLL,LHR,London,GB,51.4706,-0.461941,83\n\
        EGMD,Lydd Airport,EGMD,LYX,\"Lydd, Ashford\",GB,50.956100,0.939167,13\n\
        EG64,RAF Rufforth,EG64,,\"York, Rufforth\",GB,53.948290,-1.185575,\n";
    pub const AIRPORTS_K: &str = "Code,Name,ICAO,IATA,Location,CountryISO2,Latitude,Longitude,AltitudeFeet\n\
        KJFK,John F Kennedy International Airport,KJFK,JFK,New York,US,40.639801,-73.7789,13\n";

    /// The four files read, not yet held.
    pub fn read() -> std::io::Result<Load> {
        let mut load = Load::default();
        for (routes, airports) in [(ROUTES_B, AIRPORTS_E), (ROUTES_E, AIRPORTS_K)] {
            load.add_routes(routes.as_bytes())?;
            load.add_airports(airports.as_bytes())?;
        }
        Ok(load)
    }

    /// The four files held. They are text in memory, which reads; were it not, nothing would be
    /// held and every answer would say so.
    pub fn standing() -> Standing {
        read().map(Load::finish).unwrap_or_default()
    }

    /// `read` with more routes after it.
    fn standing_with(routes: &str) -> Result<Standing, String> {
        let mut load = read().map_err(|error| error.to_string())?;
        load.add_routes(routes.as_bytes())
            .map_err(|error| error.to_string())?;
        Ok(load.finish())
    }

    #[test]
    fn the_files_are_read_as_standing_data_writes_them() {
        let standing = standing();
        // An airport with no height (EG64) is none, as adsb.lol reads it.
        assert_eq!((standing.routes(), standing.airports()), (4, 3));
        let lydd = standing.route("EZY12", None).airports;
        let lydd: Vec<&str> = lydd.iter().map(|one| one.location.as_str()).collect();
        assert_eq!(lydd, ["Lydd, Ashford"]);
        let mut row = Vec::new();
        fields(r#"a,"b ""c"", d",,e"#, &mut row);
        assert_eq!(row, ["a", r#"b "c", d"#, "", "e"]);
    }

    /// A callsign read again, in one file or a later one, is the later row's, and an airport's
    /// code read again is the later row's too.
    #[test]
    fn a_row_read_again_is_the_later_one() -> Result<(), String> {
        let standing = standing_with(
            "TST1,TST,1,TST,EGLL-KJFK\nBAW1,BAW,1,BAW,EGLL-EGMD\ntst1,TST,1A,TST,KJFK-EGLL\r\nTST1A,TST,X,TST,unknown",
        )?;
        assert_eq!(standing.routes(), 6);
        let route = standing.route("TST1", None);
        assert_eq!(
            (route.number.as_str(), route.airport_codes.as_str()),
            ("1A", "KJFK-EGLL")
        );
        assert_eq!(standing.route("baw1", None).airport_codes_iata, "LHR-LYX");
        let route = standing.route("TST1A", Some((0.0, 0.0)));
        assert_eq!(
            (route.number.as_str(), route.airport_codes.as_str()),
            ("X", UNKNOWN)
        );
        let mut load = read().map_err(|error| error.to_string())?;
        load.add_airports("EGMD,Lydd,EGMD,LYD,Lydd,GB,50.9561,0.939167,13".as_bytes())
            .map_err(|error| error.to_string())?;
        let standing = load.finish();
        assert_eq!(standing.airports(), 3);
        assert_eq!(standing.route("EZY12", None).airport_codes_iata, "LYD-ZZZZ");
        Ok(())
    }

    #[test]
    fn a_known_route_names_its_airports_and_their_iata_codes() {
        let route = standing().route("baw1", Some((45.0, -40.0)));
        assert_eq!(
            (
                route.callsign.as_str(),
                route.number.as_str(),
                route.airline_code.as_str(),
                route.airport_codes.as_str(),
                route.airport_codes_iata.as_str(),
            ),
            ("baw1", "1", "BAW", "EGLL-KJFK", "LHR-JFK")
        );
        let codes: Vec<&str> = route.airports.iter().map(|one| one.icao.as_str()).collect();
        assert_eq!(codes, ["EGLL", "KJFK"]);
        assert_eq!(route.airports[0].alt_meters, 25.3);
        // An airport the data does not hold keeps its ICAO code, and is not listed.
        let route = standing().route("EZY12", None);
        assert_eq!(
            (route.airport_codes_iata.as_str(), route.airports.len()),
            ("LYX-ZZZZ", 1)
        );
        assert_eq!(route.plausible, None);
    }

    /// Each code is written as its own IATA code, never by replacing text inside the others: an
    /// airport's ICAO code that is part of another code is left whole.
    #[test]
    fn each_code_is_written_as_its_own_iata_code() -> Result<(), String> {
        let standing = standing_with("TST1,TST,1,TST,EGLL-XEGLLX-KJFK\n")?;
        let route = standing.route("TST1", None);
        assert_eq!(route.airport_codes_iata, "LHR-XEGLLX-JFK");
        Ok(())
    }

    /// The legs are the route's own, code after code: with an airport between two others unknown,
    /// no leg joins the two known ones, and a route with no known leg has no plausibility at all.
    #[test]
    fn a_leg_with_an_unknown_end_is_no_leg() -> Result<(), String> {
        let standing =
            standing_with("TST2,TST,2,TST,EGLL-ZZZZ-KJFK\nTST3,TST,3,TST,KJFK-ZZZZ-EGLL-EGMD\n")?;
        // Over the Atlantic on the great circle from London to New York.
        let atlantic = Some((52.3, -38.0));
        assert_eq!(standing.route("TST2", atlantic).plausible, None);
        // TST3's one known leg is Heathrow to Lydd: near Lydd is on it, and mid Atlantic is not,
        // as it would be on an invented New York to Heathrow leg.
        assert_eq!(
            standing.route("TST3", Some((50.96, 0.94))).plausible,
            Some(true)
        );
        assert_eq!(standing.route("TST3", atlantic).plausible, Some(false));
        Ok(())
    }

    /// Near the great-circle leg, by adsb.lol's threshold (for London to New York, a fifth of its
    /// 2,990 nm): at either end, over the Atlantic on the great circle, and not well off it, past
    /// its end or on the other side of the world.
    #[test]
    fn a_place_near_the_great_circle_leg_is_plausible() {
        let heathrow = (51.471, -0.462);
        let kennedy = (40.64, -73.779);
        for near in [(51.6, -1.0), (52.3, -38.0), (52.0, -30.0), (41.0, -70.0)] {
            assert!(plausible(near, heathrow, kennedy), "{near:?}");
        }
        // 830 nm south of the leg's middle; Chicago, 640 nm past New York; Sydney.
        for far in [(40.0, -38.0), (41.98, -87.9), (-33.9, 151.2)] {
            assert!(!plausible(far, heathrow, kennedy), "{far:?}");
        }
        // A short leg's threshold is 50 nm.
        assert!(plausible((51.0, 0.3), heathrow, (50.956, 0.939)));
        assert!(!plausible((49.0, 0.3), heathrow, (50.956, 0.939)));
        let route = standing().route("BAW1", Some((-33.9, 151.2)));
        assert_eq!(route.plausible, Some(false));
        let route = standing().route("BAW1", Some((41.0, -70.0)));
        assert_eq!(route.plausible, Some(true));
        // One airport known: no leg, so no plausibility at all.
        assert_eq!(
            standing().route("EZY12", Some((50.95, 0.94))).plausible,
            None
        );
    }

    #[test]
    fn the_directory_is_read_however_deep_and_changes_are_seen() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!(
            "tally-api-vrs-{}-{}",
            std::process::id(),
            crate::routes::wall_ms()
        ));
        let write = |path: &str, text: &str| -> Result<(), String> {
            let file = dir.join(path);
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            std::fs::write(file, text).map_err(|error| error.to_string())
        };
        assert!(Standing::load(&dir).is_err());
        write("routes/schema-01/B/BAW-all.csv", ROUTES_B)?;
        write("routes/schema-01/E/EZY-1.csv", ROUTES_E)?;
        write("airports/schema-01/E/EG.csv", AIRPORTS_E)?;
        write("airports/schema-01/K/KJ.csv", AIRPORTS_K)?;
        write("airports/README.md", "not data")?;
        let standing = Standing::load(&dir)?;
        assert_eq!((standing.routes(), standing.airports()), (4, 3));
        let before = fingerprint(&dir)?;
        write(
            "routes/schema-01/E/EZY-2.csv",
            "EZY13,EZY,13,EZY,EGMD-EGLL\n",
        )?;
        assert_ne!(fingerprint(&dir)?, before);
        assert_eq!(Standing::load(&dir)?.routes(), 5);
        std::fs::remove_dir_all(&dir).map_err(|error| error.to_string())
    }

    /// A look reads the directory when its files are new to it (the first look, a file added, a
    /// file rewritten), and passes over files it has read: the data held stays the one read.
    #[test]
    fn a_look_reads_only_changed_files() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!(
            "tally-api-vrs-look-{}-{}",
            std::process::id(),
            crate::routes::wall_ms()
        ));
        let write = |path: &str, text: &str| -> Result<(), String> {
            let file = dir.join(path);
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            std::fs::write(file, text).map_err(|error| error.to_string())
        };
        write("routes/B/BAW-all.csv", ROUTES_B)?;
        write("airports/E/EG.csv", AIRPORTS_E)?;
        let held = Held::default();
        let mut read = None;
        let routes = |held: &Held| held.get().map(|standing| standing.routes());
        assert!(look(&dir, &held, &mut read)?);
        assert_eq!(routes(&held), Some(3));
        let first = held.get().ok_or("nothing held")?;
        assert!(!look(&dir, &held, &mut read)?);
        let again = held.get().ok_or("nothing held")?;
        assert!(
            Arc::ptr_eq(&first, &again),
            "the same files were read again"
        );
        write("routes/E/EZY-1.csv", ROUTES_E)?;
        assert!(look(&dir, &held, &mut read)?);
        assert_eq!(routes(&held), Some(4));
        write(
            "routes/E/EZY-1.csv",
            "EZY12,EZY,12,EZY,EGMD-ZZZZ\nEZY13,EZY,13,EZY,EGMD-EGLL\n",
        )?;
        assert!(look(&dir, &held, &mut read)?);
        assert_eq!(routes(&held), Some(5));
        assert!(!look(&dir, &held, &mut read)?);
        // A read that fails keeps what was held, and is tried again at the next look.
        write("routes/E/EZY-2.csv", "\u{feff}EZY14,EZY,14,EZY,EGMD-EGLL\n")?;
        std::fs::write(dir.join("routes/E/EZY-3.csv"), [0xff, 0xfe, b'\n'])
            .map_err(|error| error.to_string())?;
        assert!(look(&dir, &held, &mut read).is_err());
        assert_eq!(routes(&held), Some(5));
        assert!(look(&dir, &held, &mut read).is_err());
        std::fs::remove_file(dir.join("routes/E/EZY-3.csv")).map_err(|error| error.to_string())?;
        assert!(look(&dir, &held, &mut read)?);
        assert_eq!(routes(&held), Some(6));
        std::fs::remove_dir_all(&dir).map_err(|error| error.to_string())
    }

    /// A symbolic link in the directory is passed over: one back up the tree is no loop, and a
    /// linked file is not read.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_not_followed() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!(
            "tally-api-vrs-links-{}-{}",
            std::process::id(),
            crate::routes::wall_ms()
        ));
        let at = |path: &str| dir.join(path);
        let error = |error: std::io::Error| error.to_string();
        std::fs::create_dir_all(at("routes/schema-01/B")).map_err(error)?;
        std::fs::create_dir_all(at("airports")).map_err(error)?;
        std::fs::write(at("routes/schema-01/B/BAW-all.csv"), ROUTES_B).map_err(error)?;
        std::fs::write(at("elsewhere.csv"), ROUTES_E).map_err(error)?;
        std::os::unix::fs::symlink(at("routes"), at("routes/schema-01/loop")).map_err(error)?;
        std::os::unix::fs::symlink(at("elsewhere.csv"), at("routes/EZY.csv")).map_err(error)?;
        let files = csv_files(&at("routes"))?;
        assert_eq!(files, [at("routes/schema-01/B/BAW-all.csv")]);
        assert_eq!(Standing::load(&dir)?.routes(), standing_of(ROUTES_B)?);
        std::fs::remove_dir_all(&dir).map_err(error)
    }

    fn standing_of(routes: &str) -> Result<usize, String> {
        let mut load = Load::default();
        load.add_routes(routes.as_bytes())
            .map_err(|error| error.to_string())?;
        Ok(load.finish().routes())
    }

    /// A callsign is at most eight characters once trimmed, as `/v2` bounds one.
    #[test]
    fn a_callsign_is_at_most_eight_characters() {
        for fits in ["BAW1", "ABCDEFGH", " ABCDEFGH ", ""] {
            assert!(is_callsign(fits), "{fits:?}");
        }
        for long in ["ABCDEFGHI", "BAW1BAW1BAW1"] {
            assert!(!is_callsign(long), "{long:?}");
        }
    }
}
