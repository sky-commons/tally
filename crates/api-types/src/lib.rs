//! THE TALLY API'S PUBLIC JSON (RFC-0173 §2.5), declared once: `tally-api` serialises these types
//! and every client deserialises them (the Flightlines client core's `tally-reads` among them), so a
//! field renamed here is renamed on both sides by the compiler, never by hand.
//!
//! Every time field says which kind of time it is:
//!
//! - an INSTANT is `*_at_ms`, Unix milliseconds on the API's own clock, beside the response's
//!   `now_ms` (when the API's data was current, on the same clock), so a client ages an instant
//!   against `now_ms`, or by its own clock through the offset an aircraft answer's `sent_at_ms`
//!   gives it (RFC-0184), never by its own clock read as the API's;
//! - a SPAN is `*_for_ms`, a count of milliseconds.
//!
//! No answer carries a receiver's exact place: a station's `location` is its declared place
//! blurred to about 5 km, the same on every read, and every figure that places a feeder (its area,
//! its range) is computed from that pin (`tally-api`'s `privacy`).
//!
//! A client may ignore a field it does not read; a field a type states is always present (an
//! optional one as `null`).
//!
//! [`fixtures`] holds one answer of each endpoint exactly as `tally-api` writes it: `tally-api`'s
//! own test serialises its answers and holds them equal to these, and a client's test reads them, so
//! the two sides are tested against one text.
//!
//! This file depends on `serde` alone and names nothing of its crate's own (no `crate::` path), so a
//! client in another build may compile this very file into itself (the Flightlines client core does,
//! as a module, `#[path]` from `core/crates/tally-reads`) rather than restate it.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// `GET /v1/aircraft?west=&south=&east=&north=[&feed=live|precise]`: the aircraft in a viewport.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AircraftResponse {
    /// When the data was current: Unix milliseconds on the API's clock. For the precise feed,
    /// the product's own second (about a minute and a half ago), so a client ages each aircraft
    /// against it and draws the feed where it was then.
    pub now_ms: u64,
    /// Which feed was served: what the client asked for (`live` when it named none).
    pub feed: Feed,
    pub aircraft: Vec<Aircraft>,
    /// When the API sent this answer: Unix milliseconds on the API's clock. A client that holds the
    /// least of (its receipt time minus `sent_at_ms`) over its answers holds the offset between the
    /// two clocks, transit included, and ages every instant by its own clock through it: a cached or
    /// slow answer then shows as late rather than moving the offset.
    pub sent_at_ms: u64,
}

/// `GET /v1/aircraft/stream?west=&south=&east=&north=[&feed=live|precise]`: the same viewport's
/// aircraft pushed as Server-Sent Events (RFC-0184), never cached. The first `aircraft` event is
/// `full` (every aircraft in the box); each later one carries the aircraft whose position or state
/// changed since the event before it and the addresses that left the box or went silent. A comment
/// line keeps the stream open while nothing changes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AircraftUpdate {
    /// When the data was current, as in [`AircraftResponse::now_ms`].
    pub now_ms: u64,
    /// When the API sent this event, as in [`AircraftResponse::sent_at_ms`].
    pub sent_at_ms: u64,
    pub feed: Feed,
    /// Whether `aircraft` is every aircraft in the box (the client replaces what it holds) or only
    /// those that changed (the client updates them in place).
    pub full: bool,
    pub aircraft: Vec<Aircraft>,
    /// Addresses the client holds that left the box or went silent; empty in a `full` event.
    pub gone: Vec<String>,
}

/// Which feed of positions a client reads (RFC-0174 §2.11), its choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Feed {
    /// Now: each aircraft at its newest position, an MLAT aircraft by its provisional fix a second
    /// or two after it was heard until its final fix replaces it.
    #[default]
    Live,
    /// The precise world product, about a minute and a half behind: every aircraft at one second,
    /// an MLAT aircraft by its final fix only. Each aircraft's `last_heard_at_ms` says how old.
    Precise,
}

/// One aircraft with a position: as the API's decoder (readsb) holds it, its position either
/// readsb's own (decoded from the aircraft's ADS-B) or, for an aircraft readsb holds no position
/// for, the API's merged MLAT solution (RFC-0171 §3.8.1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Aircraft {
    /// The 24-bit address as six lowercase hex digits (readsb prefixes a non-ICAO address `~`).
    pub hex: String,
    /// The callsign, trimmed; `null` when none was heard.
    pub flight: Option<String>,
    pub lat: f64,
    pub lon: f64,
    /// Barometric altitude in feet; `null` on the ground or when none was heard.
    pub alt_baro_ft: Option<i32>,
    pub gs_kt: Option<f64>,
    pub track_deg: Option<f64>,
    pub baro_rate_fpm: Option<i32>,
    pub on_ground: bool,
    /// When its last message of any kind was heard: Unix milliseconds on the API's clock, at or
    /// before `now_ms`. Says whether the aircraft is still heard, not how old its position is.
    pub last_heard_at_ms: u64,
    /// When the position in `lat` and `lon` was heard (for an MLAT position, when the transmission
    /// it was solved from was sent): Unix milliseconds on the API's clock, at or before
    /// `last_heard_at_ms`. A client projects the position forward from this instant, never from
    /// `last_heard_at_ms`, which a velocity or altitude message moves without a new position.
    pub position_at_ms: u64,
    /// Where `lat` and `lon` came from.
    pub position_source: PositionSource,
    /// An MLAT position's uncertainty and how it was checked; `null` for an ADS-B position.
    pub mlat: Option<Mlat>,
}

/// Where an aircraft's position came from: readsb's own `type` for a position it decoded, or
/// Tally's MLAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PositionSource {
    /// The aircraft's own ADS-B broadcast (readsb `adsb_icao`, `adsb_icao_nt`, `adsb_other`).
    Adsb,
    /// Multilateration: solved by Tally MLAT engines from receivers' timestamps.
    Mlat,
    /// Rebroadcast by a ground station of what an aircraft sent on the other link (readsb
    /// `adsr_icao`, `adsr_other`).
    Adsr,
    /// A ground station's radar track (readsb `tisb_icao`, `tisb_other`, `tisb_trackfile`).
    Tisb,
    /// Any other source readsb names (`adsc`, `mode_s`, `other`, its own `mlat`).
    Other,
}

/// Aircraft counted by where each one's position came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCounts {
    pub adsb: u32,
    pub mlat: u32,
    pub adsr: u32,
    pub tisb: u32,
    pub other: u32,
}

/// What an MLAT position is worth.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Mlat {
    /// One standard deviation of the horizontal position, metres, clock error included.
    pub horizontal_sigma_m: f64,
    pub check: MlatCheck,
    /// Final, or provisional until a final position replaces it.
    pub kind: MlatKind,
    /// Whether the receivers it was solved from have standing (RFC-0174 §2.12): `unconfirmed` is
    /// drawn, and labelled so.
    pub confidence: MlatConfidence,
    /// Whether a solution over more receptions of the same transmission disagreed with it: the
    /// position stands, and the disagreement is kept as evidence against the added receptions.
    pub contested: bool,
}

/// How far an MLAT position's receivers are trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MlatConfidence {
    /// At least the solver's minimum of its receivers have standing.
    Standing,
    /// Fewer, or the API has not weighed them (a precise world fix, read as its relay signed it).
    Unconfirmed,
}

/// Which MLAT position is served: the API serves a provisional one while it is later than every
/// final one it holds of the aircraft.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MlatKind {
    /// Solved under the clock model of the window holding its transmission: published some 7 to
    /// 47 s after it.
    Final,
    /// Solved about a second after its transmission under an older clock model carried forward,
    /// its uncertainty grown by how far: a final position of the same transmission follows and
    /// replaces it, and one no final position confirms is retracted.
    Provisional,
}

/// How the API checked an MLAT position before serving it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MlatCheck {
    /// The API holds the raw it was solved from: the clock model was verified by the model
    /// verifier and the solution by the solution verifier.
    Model,
    /// Signatures and content addresses only: the engine's solution and the model it cites are
    /// signed and whole, and agree with each other, but the API holds none of their raw.
    Signature,
    /// The API solved it itself, from the union of two engines' raw it holds.
    Resolved,
}

/// `GET /v1/network`: the network's totals.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Network {
    /// When the relay counted them: Unix milliseconds on the API's clock.
    pub now_ms: u64,
    pub receivers_online: u32,
    pub receivers_total: u32,
    pub messages_per_sec: f64,
    /// Aircraft with a position: the decoder's, and those only Tally MLAT places.
    pub aircraft: u32,
    /// `aircraft` by where each position came from; the counts sum to `aircraft`.
    pub aircraft_by_source: SourceCounts,
}

/// `GET /v1/stations/{key}`, the key in the path as base64url without padding: one receiver.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Station {
    /// When the relay reported it: Unix milliseconds on the API's clock.
    pub now_ms: u64,
    /// The receiver's public key as tally prints it (standard base64).
    pub key: String,
    /// The relay forwarded a batch of it recently.
    pub online: bool,
    /// What it is doing now: feeding, connected with nothing to send, or neither.
    pub state: StationState,
    /// When its feeder connection to the relay opened (the oldest, if more than one is open):
    /// Unix milliseconds on the API's clock; `null` when it is not connected to the relay itself
    /// (a station that feeds through another relay is `feeding` with this `null`).
    pub connected_since_at_ms: Option<u64>,
    /// When the relay first forwarded a batch of it: Unix milliseconds on the API's clock. For a
    /// station the relay has forwarded no batch of (`batches` 0), when it connected.
    pub first_seen_at_ms: u64,
    /// When the relay last forwarded a batch of it: Unix milliseconds on the API's clock. For a
    /// station the relay has forwarded no batch of (`batches` 0), when it connected.
    pub last_seen_at_ms: u64,
    pub messages_per_sec: f64,
    /// Signed batches the relay accepted from it.
    pub batches: u64,
    /// Batches of its sequence that never arrived.
    pub gaps: u64,
    /// About where it says it is: its declared place blurred to about 5 km, never the place itself
    /// (a pin inside the 0.05 degree cell that holds it, at an offset its key fixes, the same on
    /// every read). `null` when it does not say, and for a station
    /// the relay has forwarded no batch of (a connection alone publishes no place). The exact
    /// place travels only in its signed description, which MLAT reads.
    pub location: Option<Position>,
    /// What it runs, as it says; `null` when it says nothing.
    pub software: Option<String>,
}

/// `GET /v1/me`: the stations connected now from the asking client's own host (its IPv4 address or
/// IPv6 /64), as the relay saw it (an "am I feeding" check); empty when none is. Never any other station, and
/// never cached, since it depends on who asks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MeResponse {
    /// When the relay reported them: Unix milliseconds on the API's clock.
    pub now_ms: u64,
    /// By key, as `key` sorts.
    pub stations: Vec<MeStation>,
}

/// One station of the asking client's address.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MeStation {
    /// The receiver's public key as tally prints it (standard base64).
    pub key: String,
    /// The relay forwarded a batch of it recently.
    pub online: bool,
    pub messages_per_sec: f64,
    /// When the relay last forwarded a batch of it: Unix milliseconds on the API's clock.
    pub last_seen_at_ms: u64,
}

/// What a station is doing now, as the relay the API reads sees it. A key the relay knows
/// nothing of (never connected, or forgotten) is no station: `404 no such station`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StationState {
    /// A batch of it was forwarded recently (`online`): its receptions reach the network.
    Feeding,
    /// Connected to the relay, its key proved by the handshake, but no batch of it was forwarded
    /// recently: tally-feed is running and reaches the relay, and its decoder (readsb's BEAST
    /// output) is giving it nothing to send. `batches` 0 says it never has.
    Silent,
    /// Neither: not connected to the relay, and no batch of it forwarded recently.
    Offline,
}

/// `GET /v1/stations/{key}/stats`, the key as base64url without padding: what one feeder gave the
/// network over the window, as the API computes it (RFC-0174 §2.12) from public signed data alone
/// (the feeder's signed batches, the signed positions that cite its receptions, and its standing),
/// so anyone who reads the same records computes the same figures. The site that shows them is one
/// client of the network; no relay computes or vouches for any of them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeederStats {
    /// When the figures were computed: Unix milliseconds on the API's clock.
    pub now_ms: u64,
    /// The receiver's public key as tally prints it (standard base64).
    pub key: String,
    /// The span the figures cover: the last day, or less while the API has been reading for less.
    pub window_for_ms: u64,
    /// The share of the window's minutes in which a signed batch of it was published, 0 to 1.
    pub uptime: f64,
    /// Receptions in its signed batches over the window.
    pub messages: u64,
    /// `messages` over the window, a second.
    pub messages_per_sec: f64,
    /// Distinct aircraft whose checked address it heard over the window.
    pub aircraft: u32,
    /// The farthest positioned aircraft it heard, metres from its public pin (its place blurred to
    /// about 5 km, as `Station::location`), so it is never a measure from the exact place; `null`
    /// when it states no place or heard no positioned aircraft.
    pub range_m: Option<f64>,
    /// The sky it heard positioned aircraft in, square kilometres of coverage cells.
    pub coverage_km2: f64,
    /// The part of `coverage_km2` no other feeder heard over the window.
    pub unique_coverage_km2: f64,
    /// Distinct published MLAT positions that cite one of its receptions.
    pub mlat_positions: u64,
    /// Its area: the H3 cell (resolution 3, as hex) that holds its public pin (`Station::location`);
    /// `null` when it states no place.
    pub area: Option<String>,
    /// Its receptions have earned standing (RFC-0174 §2.12): only a feeder with standing is ranked.
    pub standing: bool,
    /// Its places on its area's leaderboards; `null` when it is not ranked (no standing, or no
    /// area).
    pub ranks: Option<Ranks>,
}

/// A feeder's places on its area's two leaderboards, 1 the first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ranks {
    pub unique_coverage: u32,
    pub mlat: u32,
    /// How many feeders the area ranks.
    pub of: u32,
}

/// `GET /v1/leaderboards`: every area with a feeder the API has figures for over the window, ranked
/// or not, the most ranked first, then the most feeders, then by area.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Leaderboards {
    /// When the boards were computed: Unix milliseconds on the API's clock.
    pub now_ms: u64,
    /// The span every board covers.
    pub window_for_ms: u64,
    pub areas: Vec<LeaderboardArea>,
}

/// One area, as the leaderboards list it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeaderboardArea {
    /// The H3 cell (resolution 3), as hex: the path `GET /v1/leaderboards/{area}` names.
    pub area: String,
    /// The cell's centre.
    pub center: Position,
    /// Feeders ranked in it.
    pub ranked: u32,
    /// Feeders the API has figures for in it over the window, ranked or not: `ranked` of them have
    /// standing.
    pub receivers: u32,
}

/// `GET /v1/leaderboards/{area}`: one area's two leaderboards, each its first feeders. Ranked by
/// what a feeder adds that no one else does (unique coverage) and by how much it helps MLAT, never
/// by raw message counts; only feeders with standing are ranked, and the rest are listed apart
/// (`unranked`), so an area with feeders but none ranked answers both boards empty.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Leaderboard {
    /// When the boards were computed: Unix milliseconds on the API's clock.
    pub now_ms: u64,
    pub window_for_ms: u64,
    pub area: String,
    pub center: Position,
    /// Feeders ranked in the area, of which each board lists the first.
    pub ranked: u32,
    /// Feeders the API has figures for in the area over the window, ranked or not.
    pub receivers: u32,
    /// By unique coverage, then MLAT help, then key.
    pub by_unique_coverage: Vec<LeaderboardEntry>,
    /// By MLAT help, then unique coverage, then key.
    pub by_mlat: Vec<LeaderboardEntry>,
    /// The area's feeders without standing, by key (as `key` sorts); at most as many as each board
    /// lists.
    pub unranked: Vec<UnrankedFeeder>,
}

/// One feeder an area lists but does not rank: it has no standing.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnrankedFeeder {
    /// The receiver's public key as tally prints it (standard base64), as a board would list it.
    pub key: String,
}

/// One feeder on a leaderboard.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LeaderboardEntry {
    /// 1 the first.
    pub rank: u32,
    /// The receiver's public key as tally prints it (standard base64).
    pub key: String,
    pub unique_coverage_km2: f64,
    pub mlat_positions: u64,
}

/// A place, in degrees.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Position {
    pub lat: f64,
    pub lon: f64,
}

/// `POST /api/0/routeset`'s body, as tar1090 sends it (its `routeApiUrl`) and adsb.lol's API reads
/// it: at most 100 callsigns, each with where the aircraft is, if the client knows.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteSetRequest {
    pub planes: Vec<RoutePlane>,
}

/// One callsign a client asks the route of.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RoutePlane {
    pub callsign: String,
    /// Where the aircraft is, in degrees; `null` or absent when the client does not know (tar1090
    /// leaves them out replaying a trace), and then the route is not judged (`plausible` `null`).
    pub lat: Option<f64>,
    pub lng: Option<f64>,
}

/// A callsign's scheduled route, as VRS standing data names it, in adsb.lol's shape: the answer to
/// `GET /api/0/route/{callsign}/{lat}/{lon}` and each element of `POST /api/0/routeset`'s, which
/// lists one per distinct callsign asked, in the order asked. A callsign the data does not hold is
/// answered with every code `unknown` and no airport.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    /// The callsign as the client asked it.
    pub callsign: String,
    /// The flight number, or `unknown`.
    pub number: String,
    /// The operator's ICAO code, or `unknown`.
    pub airline_code: String,
    /// The airports in order, ICAO codes joined by `-` (`EGLL-KJFK`), or `unknown`.
    pub airport_codes: String,
    /// `airport_codes` with each ICAO code that has an IATA one written as it (`LHR-JFK`).
    #[serde(rename = "_airport_codes_iata")]
    pub airport_codes_iata: String,
    /// The airports of `airport_codes` the data holds, in order.
    #[serde(rename = "_airports")]
    pub airports: Vec<RouteAirport>,
    /// Whether the aircraft is where the route would put it (near a leg's great circle, adsb.lol's
    /// check); `null` when the route is unknown or the client gave no position. tar1090 marks a
    /// route `??` when it is `false`.
    pub plausible: Option<bool>,
}

/// One airport of a route, as VRS standing data describes it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteAirport {
    pub name: String,
    pub icao: String,
    /// Empty when it has none.
    pub iata: String,
    /// The place it serves.
    pub location: String,
    pub countryiso2: String,
    pub lat: f64,
    pub lon: f64,
    pub alt_feet: f64,
    /// `alt_feet` in metres, to the centimetre.
    pub alt_meters: f64,
}

/// One answer of each endpoint, exactly as `tally-api` writes it (`testdata/`). `tally-api`'s test
/// holds its own serialised answers equal to these; a client's test reads them.
pub mod fixtures {
    /// `GET /v1/aircraft`: three aircraft: one named and airborne, one unnamed on the ground, both
    /// at their ADS-B positions, and one readsb holds no position for, at its MLAT position.
    pub const AIRCRAFT: &str = include_str!("../testdata/aircraft.json");
    /// One `aircraft` event of `GET /v1/aircraft/stream` after its first, to a client holding
    /// `AIRCRAFT`: the aircraft that moved since (one by readsb, one by its next MLAT fix, moving by
    /// its last two) and the address no longer heard.
    pub const AIRCRAFT_UPDATE: &str = include_str!("../testdata/aircraft_update.json");
    /// `GET /v1/aircraft?...&feed=precise`: one second of the precise world product, an ADS-B
    /// aircraft and an MLAT one.
    pub const AIRCRAFT_PRECISE: &str = include_str!("../testdata/aircraft_precise.json");
    /// `GET /v1/network`.
    pub const NETWORK: &str = include_str!("../testdata/network.json");
    /// `GET /v1/stations/{key}`: a located station.
    pub const STATION: &str = include_str!("../testdata/station.json");
    /// `GET /v1/stations/{key}`: a station that states neither place nor software.
    pub const STATION_BARE: &str = include_str!("../testdata/station_bare.json");
    /// `GET /v1/stations/{key}`: a station connected whose decoder has sent nothing, so the relay
    /// has forwarded no batch of it (`silent`, `batches` 0, placed nowhere).
    pub const STATION_SILENT: &str = include_str!("../testdata/station_silent.json");
    /// `GET /v1/stations/{key}`: a station that fed and is no longer connected (`offline`).
    pub const STATION_OFFLINE: &str = include_str!("../testdata/station_offline.json");
    /// The key the station fixtures name, as base64url without padding (the path's form).
    pub const STATION_KEY_URL: &str = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
    /// `GET /v1/me`: the one station of the asking client's address.
    pub const ME: &str = include_str!("../testdata/me.json");
    /// `GET /v1/stations/{key}/stats`: a located feeder with standing, ranked in its area.
    pub const FEEDER_STATS: &str = include_str!("../testdata/feeder_stats.json");
    /// `GET /v1/stations/{key}/stats`: a feeder that states no place and has no standing.
    pub const FEEDER_STATS_UNRANKED: &str = include_str!("../testdata/feeder_stats_unranked.json");
    /// `GET /v1/leaderboards`.
    pub const LEADERBOARDS: &str = include_str!("../testdata/leaderboards.json");
    /// `GET /v1/leaderboards/{area}`: the area `LEADERBOARDS` lists.
    pub const LEADERBOARD: &str = include_str!("../testdata/leaderboard.json");
    /// `GET /v1/leaderboards/{area}`: the same area while no feeder in it has standing, so both
    /// boards are empty and every feeder there is `unranked`.
    pub const LEADERBOARD_UNRANKED: &str = include_str!("../testdata/leaderboard_unranked.json");
    /// `POST /api/0/routeset`: two callsigns asked, one known and flown where its route goes, one
    /// the data does not hold.
    pub const ROUTESET: &str = include_str!("../testdata/routeset.json");
    /// The request `ROUTESET` answers, as tar1090 sends it.
    pub const ROUTESET_REQUEST: &str = include_str!("../testdata/routeset_request.json");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each fixture reads as its type and writes back as the same JSON: no field is lost, renamed
    /// or added on the way through.
    fn whole<T: serde::de::DeserializeOwned + Serialize>(text: &str) -> Result<(), String> {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let typed: T = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        let back = serde_json::to_value(&typed).map_err(|e| e.to_string())?;
        if back == value {
            Ok(())
        } else {
            Err(format!("{back} is not {value}"))
        }
    }

    #[test]
    fn every_fixture_is_its_type_whole() -> Result<(), String> {
        whole::<AircraftResponse>(fixtures::AIRCRAFT)?;
        whole::<AircraftResponse>(fixtures::AIRCRAFT_PRECISE)?;
        whole::<AircraftUpdate>(fixtures::AIRCRAFT_UPDATE)?;
        whole::<Network>(fixtures::NETWORK)?;
        whole::<Station>(fixtures::STATION)?;
        whole::<Station>(fixtures::STATION_BARE)?;
        whole::<Station>(fixtures::STATION_SILENT)?;
        whole::<Station>(fixtures::STATION_OFFLINE)?;
        whole::<FeederStats>(fixtures::FEEDER_STATS)?;
        whole::<FeederStats>(fixtures::FEEDER_STATS_UNRANKED)?;
        whole::<Leaderboards>(fixtures::LEADERBOARDS)?;
        whole::<Leaderboard>(fixtures::LEADERBOARD)?;
        whole::<Leaderboard>(fixtures::LEADERBOARD_UNRANKED)?;
        whole::<MeResponse>(fixtures::ME)?;
        whole::<Vec<Route>>(fixtures::ROUTESET)?;
        whole::<RouteSetRequest>(fixtures::ROUTESET_REQUEST)
    }

    /// tar1090 leaves a plane's position out when it has none to give: the request is still read.
    #[test]
    fn a_plane_without_a_position_is_asked() -> Result<(), String> {
        let asked: RouteSetRequest = serde_json::from_str(r#"{"planes":[{"callsign":"BAW1"}]}"#)
            .map_err(|e| e.to_string())?;
        assert_eq!((asked.planes[0].lat, asked.planes[0].lng), (None, None));
        Ok(())
    }

    #[test]
    fn a_stated_field_that_is_missing_is_refused() {
        assert!(serde_json::from_str::<AircraftResponse>(r#"{"aircraft":[]}"#).is_err());
        assert!(
            serde_json::from_str::<AircraftResponse>(
                r#"{"now_ms":1,"aircraft":[{"hex":"a","lat":1,"lon":2,"on_ground":false}]}"#
            )
            .is_err(),
            "last_heard_at_ms is stated"
        );
        assert!(serde_json::from_str::<Network>(r#"{"now_ms":"1"}"#).is_err());
    }
}
