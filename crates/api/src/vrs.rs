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
//! its `routes/` and `airports/` CSV files), read whole at start and again when its files change or
//! every `RELOAD_EVERY` (`keep`). Without the flag the routes answer `404` and say why; with it,
//! `503` until the first read.
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
use std::path::{Path as FilePath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

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
/// How long the data is kept before it is read again, changed or not.
pub const RELOAD_EVERY: Duration = Duration::from_secs(3600);
/// What every code of a route the data does not hold reads.
pub const UNKNOWN: &str = "unknown";

const EARTH_RADIUS_M: f64 = 6_371_000.0;
const METRES_PER_NM: f64 = 1852.0;

/// One route row: `Callsign,Code,Number,AirlineCode,AirportCodes`.
#[derive(Clone, Debug)]
struct RouteRow {
    number: String,
    airline_code: String,
    airport_codes: String,
}

/// The standing data as read: routes by callsign, airports by code.
#[derive(Debug, Default)]
pub struct Standing {
    routes: HashMap<String, RouteRow>,
    airports: HashMap<String, RouteAirport>,
}

impl Standing {
    /// Reads every CSV file under `dir`'s `routes/` and `airports/`, however deep (standing-data
    /// splits each by its first letters).
    pub fn load(dir: &FilePath) -> Result<Self, String> {
        let mut standing = Self::default();
        for file in csv_files(&dir.join("routes"))? {
            standing.add_routes(&read(&file)?);
        }
        for file in csv_files(&dir.join("airports"))? {
            standing.add_airports(&read(&file)?);
        }
        Ok(standing)
    }

    /// Adds one routes file's rows; its header, and a row too short to be one, are passed over.
    pub fn add_routes(&mut self, text: &str) {
        for line in text.trim_start_matches('\u{feff}').lines() {
            let fields = fields(line);
            let [callsign, _, number, airline_code, airport_codes] = fields.as_slice() else {
                continue;
            };
            if callsign == "Callsign" {
                continue;
            }
            self.routes.insert(
                callsign.to_ascii_uppercase(),
                RouteRow {
                    number: number.clone(),
                    airline_code: airline_code.clone(),
                    airport_codes: airport_codes.clone(),
                },
            );
        }
    }

    /// Adds one airports file's rows (`Code,Name,ICAO,IATA,Location,CountryISO2,Latitude,
    /// Longitude,AltitudeFeet`). A row whose place or height is not a number is no airport, as
    /// adsb.lol reads it.
    pub fn add_airports(&mut self, text: &str) {
        for line in text.trim_start_matches('\u{feff}').lines() {
            let fields = fields(line);
            let [code, name, _, iata, location, country, lat, lon, alt_feet] = fields.as_slice()
            else {
                continue;
            };
            let (Ok(lat), Ok(lon), Ok(alt_feet)) = (
                lat.parse::<f64>(),
                lon.parse::<f64>(),
                alt_feet.parse::<f64>(),
            ) else {
                continue;
            };
            self.airports.insert(
                code.clone(),
                RouteAirport {
                    name: name.clone(),
                    icao: code.clone(),
                    iata: iata.clone(),
                    location: location.clone(),
                    countryiso2: country.clone(),
                    lat,
                    lon,
                    alt_feet,
                    alt_meters: (alt_feet * 0.3048 * 100.0).round() / 100.0,
                },
            );
        }
    }

    pub fn routes(&self) -> usize {
        self.routes.len()
    }

    pub fn airports(&self) -> usize {
        self.airports.len()
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
        let Some(row) = self.routes.get(&callsign.trim().to_ascii_uppercase()) else {
            return unknown(UNKNOWN, UNKNOWN);
        };
        if row.airport_codes == UNKNOWN {
            return unknown(&row.number, &row.airline_code);
        }
        let codes: Vec<&str> = row.airport_codes.split('-').collect();
        let known = |code: &str| self.airports.get(code);
        let airports: Vec<RouteAirport> = codes
            .iter()
            .filter_map(|code| known(code).cloned())
            .collect();
        // Each ICAO code written as its airport's IATA code, where it has one, code by code.
        let airport_codes_iata = codes
            .iter()
            .map(|code| match known(code) {
                Some(airport) if code.len() == 4 && !airport.iata.is_empty() => {
                    airport.iata.as_str()
                }
                _ => code,
            })
            .collect::<Vec<_>>()
            .join("-");
        // The legs are the route's, code after code: a leg with an end the data does not hold is
        // not known, and is never bridged by joining the airports either side of it.
        let legs: Vec<(&RouteAirport, &RouteAirport)> = codes
            .windows(2)
            .filter_map(|pair| Some((known(pair[0])?, known(pair[1])?)))
            .collect();
        let plausible = at
            .filter(|_| !legs.is_empty())
            .map(|(lat, lon)| on_route(&legs, lat, lon));
        Route {
            callsign: callsign.to_owned(),
            number: row.number.clone(),
            airline_code: row.airline_code.clone(),
            airport_codes: row.airport_codes.clone(),
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

/// One CSV line's fields: commas separate them, and a field in double quotes may hold commas and
/// doubled quotes (standing-data quotes a place such as `"Lydd, Ashford"`).
fn fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
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
    fields
}

fn read(file: &FilePath) -> Result<String, String> {
    std::fs::read_to_string(file).map_err(|error| format!("{}: {error}", file.display()))
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
type Fingerprint = Vec<(PathBuf, u64, Option<SystemTime>)>;

fn fingerprint(dir: &FilePath) -> Result<Fingerprint, String> {
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

/// Reads `dir` into `held` now, and again whenever its files change or `RELOAD_EVERY` has passed,
/// for as long as the API runs. A read that fails keeps what was held and is tried again at the
/// next look.
pub async fn keep(dir: PathBuf, held: Arc<Held>) {
    let mut read: Option<(Fingerprint, Instant)> = None;
    loop {
        let looked = {
            let dir = dir.clone();
            tokio::task::spawn_blocking(move || {
                let seen = fingerprint(&dir)?;
                Ok::<_, String>((seen, dir))
            })
            .await
        };
        match looked {
            Ok(Ok((seen, dir))) => {
                let due = read
                    .as_ref()
                    .is_none_or(|(before, at)| *before != seen || at.elapsed() >= RELOAD_EVERY);
                if due {
                    match tokio::task::spawn_blocking(move || Standing::load(&dir)).await {
                        Ok(Ok(standing)) => {
                            eprintln!(
                                "tally-api: routes: {} routes, {} airports",
                                standing.routes(),
                                standing.airports()
                            );
                            held.set(standing);
                            read = Some((seen, Instant::now()));
                        }
                        Ok(Err(error)) => eprintln!("tally-api: routes: {error}"),
                        Err(error) => eprintln!("tally-api: routes: {error}"),
                    }
                }
            }
            Ok(Err(error)) => eprintln!("tally-api: routes: {error}"),
            Err(error) => eprintln!("tally-api: routes: {error}"),
        }
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

    pub fn standing() -> Standing {
        let mut standing = Standing::default();
        standing.add_routes(ROUTES_B);
        standing.add_routes(ROUTES_E);
        standing.add_airports(AIRPORTS_E);
        standing.add_airports(AIRPORTS_K);
        standing
    }

    #[test]
    fn the_files_are_read_as_standing_data_writes_them() {
        let standing = standing();
        assert_eq!((standing.routes(), standing.airports()), (4, 3));
        let lydd = standing
            .airports
            .get("EGMD")
            .map(|airport| &airport.location);
        assert_eq!(lydd.map(String::as_str), Some("Lydd, Ashford"));
        // An airport with no height is none, as adsb.lol reads it.
        assert!(!standing.airports.contains_key("EG64"));
        assert_eq!(
            fields(r#"a,"b ""c"", d",,e"#),
            ["a", r#"b "c", d"#, "", "e"]
        );
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
    fn each_code_is_written_as_its_own_iata_code() {
        let mut standing = standing();
        standing.add_routes("TST1,TST,1,TST,EGLL-XEGLLX-KJFK\n");
        let route = standing.route("TST1", None);
        assert_eq!(route.airport_codes_iata, "LHR-XEGLLX-JFK");
    }

    /// The legs are the route's own, code after code: with an airport between two others unknown,
    /// no leg joins the two known ones, and a route with no known leg has no plausibility at all.
    #[test]
    fn a_leg_with_an_unknown_end_is_no_leg() {
        let mut standing = standing();
        standing.add_routes("TST2,TST,2,TST,EGLL-ZZZZ-KJFK\nTST3,TST,3,TST,KJFK-ZZZZ-EGLL-EGMD\n");
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
        assert_eq!(Standing::load(&dir)?.routes(), standing_of(ROUTES_B));
        std::fs::remove_dir_all(&dir).map_err(error)
    }

    fn standing_of(routes: &str) -> usize {
        let mut standing = Standing::default();
        standing.add_routes(routes);
        standing.routes()
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
