//! The API's own answers, serialised, are `tally_api_types::fixtures` exactly: the text every
//! client's test reads (the Flightlines client core's `tally-reads` among them) is what this API
//! writes, so a field renamed, retyped or re-meant here turns this test red before any client can
//! read the old shape.

use tally_api_types::fixtures;
use tally_relay::stations::{StationLocation, StationReport, StationsReport};
use tally_wire::Identity;

use tally_api_types::{Aircraft, SourceCounts};

use crate::mlat::Served;
use crate::snapshot::Stations;
use crate::{mlat, readsb};

/// The station the fixtures name: a fixed seed, so its key is the same on every run.
fn station_key() -> tally_wire::PublicKey {
    Identity::from_seed([7; 32]).public()
}

const NOW_MS: u64 = 1_791_220_000_250;
/// When the API sent the answers that say so: a little after their data was current.
const SENT_AT_MS: u64 = 1_791_220_000_430;

/// readsb's answer the aircraft fixture is the API's reading of: a1b2c3's last message (1.5 s ago)
/// is newer than its position (2 s ago).
const READSB: &str = r#"{
    "now": 1791220000.25,
    "resultCount": 2,
    "aircraft": [
        {"hex": "A1B2C3", "type": "adsb_icao", "flight": "UAL123  ", "alt_baro": 35000,
         "gs": 451.5, "track": 271.0, "baro_rate": -640, "lat": 37.5, "lon": -122.25,
         "seen": 1.5, "seen_pos": 2.0},
        {"hex": "abcdef", "type": "tisb_other", "flight": "        ", "alt_baro": "ground",
         "lat": 37.62, "lon": -122.38, "seen": 0, "seen_pos": 0},
        {"hex": "c0ffee", "type": "mode_s", "alt_baro": 12000, "seen": 3.0}
    ]
}"#;

/// readsb's answer a second later, which the update fixture is the change to: a1b2c3 has a new
/// position, and abcdef is no longer heard.
const READSB_LATER: &str = r#"{
    "now": 1791220001.25,
    "aircraft": [
        {"hex": "A1B2C3", "type": "adsb_icao", "flight": "UAL123  ", "alt_baro": 35000,
         "gs": 451.5, "track": 271.0, "baro_rate": -640, "lat": 37.5, "lon": -122.2525,
         "seen": 0.1, "seen_pos": 0.1},
        {"hex": "c0ffee", "type": "mode_s", "alt_baro": 12000, "seen": 0.5}
    ]
}"#;

fn report(location: Option<StationLocation>, software: Option<&str>) -> StationReport {
    report_of(location, software, 120_000)
}

fn report_of(
    location: Option<StationLocation>,
    software: Option<&str>,
    observations: u64,
) -> StationReport {
    StationReport {
        key: station_key().to_base64(),
        online: true,
        connected: true,
        sessions: 2,
        first_seen_ms: NOW_MS - 3_600_000,
        last_seen_ms: NOW_MS - 1_000,
        batches: 9_001,
        gaps: 3,
        observations,
        location,
        software: software.map(str::to_owned),
        address: Some("203.0.113.7".to_owned()),
    }
}

fn same(written: &impl serde::Serialize, fixture: &str) -> Result<(), String> {
    let written = serde_json::to_value(written).map_err(|e| e.to_string())?;
    let fixture: serde_json::Value = serde_json::from_str(fixture).map_err(|e| e.to_string())?;
    if written == fixture {
        Ok(())
    } else {
        Err(format!(
            "the API writes\n{}\nbut the fixture says\n{}",
            serde_json::to_string_pretty(&written).unwrap_or_default(),
            serde_json::to_string_pretty(&fixture).unwrap_or_default()
        ))
    }
}

#[test]
fn the_station_key_is_the_fixtures() {
    assert_eq!(station_key().to_base64url(), fixtures::STATION_KEY_URL);
}

/// The merged MLAT positions beside readsb's answer: one of an aircraft readsb gives a position
/// for (served at readsb's ADS-B position, not this one), and one of c0ffee, which readsb names
/// but gives no position for.
fn mlat_positions() -> Vec<Served> {
    vec![
        mlat_fix(0xa1b2c3, 37.6, -122.3, 1_791_219_999_125),
        mlat_fix(0xc0ffee, 37.71, -122.45, 1_791_219_999_125),
    ]
}

/// The merged MLAT positions two seconds on: each aircraft's next fix, a little north-west.
fn mlat_positions_later() -> Vec<Served> {
    vec![
        mlat_fix(0xa1b2c3, 37.601, -122.301, 1_791_220_001_125),
        mlat_fix(0xc0ffee, 37.711, -122.451, 1_791_220_001_125),
    ]
}

fn mlat_fix(address: u32, lat: f64, lon: f64, transmitted_ms: u64) -> Served {
    Served {
        address,
        lat,
        lon,
        altitude_ft: Some(12_000),
        horizontal_sigma_m: 42.5,
        check: tally_api_types::MlatCheck::Model,
        kind: tally_api_types::MlatKind::Final,
        confidence: tally_api_types::MlatConfidence::Standing,
        contested: false,
        source: tally_api_types::PositionSource::Mlat,
        transmitted_ms,
        gs_kt: None,
        track_deg: None,
    }
}

/// The precise world feed's answer: one second of the precise world product, an ADS-B aircraft
/// decoded from regional data and an MLAT aircraft by its final fix, both as the relay signed
/// them (unweighed by the API).
#[test]
fn the_precise_feed_answer_is_the_fixture() -> Result<(), String> {
    let one = |address: u32, source, altitude_ft| Served {
        address,
        lat: 37.71,
        lon: -122.45,
        altitude_ft,
        horizontal_sigma_m: 61.25,
        check: tally_api_types::MlatCheck::Signature,
        kind: tally_api_types::MlatKind::Final,
        confidence: tally_api_types::MlatConfidence::Unconfirmed,
        contested: false,
        source,
        transmitted_ms: 1_791_219_908_100,
        gs_kt: None,
        track_deg: None,
    };
    let served = [
        one(
            0xa1b2c3,
            tally_api_types::PositionSource::Adsb,
            Some(35_000),
        ),
        one(
            0xc0ffee,
            tally_api_types::PositionSource::Mlat,
            Some(12_000),
        ),
    ];
    same(
        &crate::routes::precise_answer(&served, 1_791_219_908_000, SENT_AT_MS),
        fixtures::AIRCRAFT_PRECISE,
    )
}

/// The live feed of a readsb answer and the MLAT positions served beside it, as the API lists them.
fn live(readsb: &str, positions: &mlat::Positions) -> Result<(u64, Vec<Aircraft>), String> {
    let answer = readsb::parse(readsb.as_bytes())?;
    let mlat = positions.current(0, std::time::Duration::MAX);
    Ok((
        readsb::now_ms(&answer),
        mlat::answer(answer.positioned(), &mlat),
    ))
}

#[test]
fn the_aircraft_answer_is_the_fixture() -> Result<(), String> {
    let positions = mlat::Positions::default();
    positions.set(mlat_positions());
    let (now_ms, aircraft) = live(READSB, &positions)?;
    same(
        &tally_api_types::AircraftResponse {
            now_ms,
            feed: tally_api_types::Feed::Live,
            aircraft,
            sent_at_ms: SENT_AT_MS,
        },
        fixtures::AIRCRAFT,
    )
}

/// The stream's update a second after the aircraft fixture's answer, to a client holding it: the
/// aircraft that moved (a1b2c3 by readsb, c0ffee by its next MLAT fix, now moving by the two) and
/// the one no longer heard.
#[test]
fn the_streams_update_is_the_fixture() -> Result<(), String> {
    let positions = mlat::Positions::default();
    positions.set(mlat_positions());
    let (_, first) = live(READSB, &positions)?;
    let mut sent = first
        .into_iter()
        .map(|one| (one.hex.clone(), one))
        .collect();
    positions.set(mlat_positions_later());
    let (now_ms, later) = live(READSB_LATER, &positions)?;
    let (aircraft, gone) = crate::stream::changes(&mut sent, later);
    same(
        &tally_api_types::AircraftUpdate {
            now_ms,
            sent_at_ms: SENT_AT_MS + 1_000,
            feed: tally_api_types::Feed::Live,
            full: false,
            aircraft,
            gone,
        },
        fixtures::AIRCRAFT_UPDATE,
    )
}

/// The report four seconds before `report`'s, 169 observations fewer: a rate of 42.25 a second,
/// as the API derives it.
fn earlier(location: Option<StationLocation>, software: Option<&str>) -> Stations {
    Stations::from_report(
        StationsReport {
            now_ms: NOW_MS - 4_000,
            stations: vec![report_of(location, software, 120_000 - 169)],
        },
        None,
    )
}

#[test]
fn the_network_and_station_answers_are_the_fixtures() -> Result<(), String> {
    let place = Some(StationLocation {
        lat: 37.5,
        lon: -122.25,
        alt_m: 10,
        precision_m: 0,
    });
    let located = Stations::from_report(
        StationsReport {
            now_ms: NOW_MS,
            stations: vec![report(place, Some("tally-feed 0.3.1"))],
        },
        Some(&earlier(place, Some("tally-feed 0.3.1"))),
    );
    let counts = SourceCounts {
        adsb: 290,
        mlat: 12,
        adsr: 3,
        tisb: 5,
        other: 1,
    };
    same(&located.network(counts), fixtures::NETWORK)?;
    same(
        &located.station(&station_key()).ok_or("no station")?,
        fixtures::STATION,
    )?;
    let bare = Stations::from_report(
        StationsReport {
            now_ms: NOW_MS,
            stations: vec![report(None, None)],
        },
        Some(&earlier(None, None)),
    );
    same(
        &bare.station(&station_key()).ok_or("no station")?,
        fixtures::STATION_BARE,
    )?;
    let home: std::net::IpAddr = "203.0.113.7".parse().map_err(|_| "not an address")?;
    same(&located.mine(Some(home)), fixtures::ME)
}

/// The routes of the request tar1090 sends, over the routes module's own standing data.
#[test]
fn the_routeset_answer_is_the_fixture() -> Result<(), String> {
    let asked: tally_api_types::RouteSetRequest =
        serde_json::from_str(fixtures::ROUTESET_REQUEST).map_err(|e| e.to_string())?;
    same(
        &crate::vrs::routes_of(&crate::vrs::tests::standing(), &asked.planes),
        fixtures::ROUTESET,
    )
}

/// The feeder figures and boards the fixtures are: the feeders module's own records (two located
/// feeders with standing and one that states no place), computed a minute after the first.
fn board() -> crate::feeders::Board {
    use crate::feeders::tests::{T, ledger, records, standing};
    ledger(&records()).board(T + 60_000, standing)
}

#[test]
fn the_feeder_and_leaderboard_answers_are_the_fixtures() -> Result<(), String> {
    let board = board();
    same(
        &board.feeder(&station_key()).ok_or("no figures")?,
        fixtures::FEEDER_STATS,
    )?;
    same(
        &board
            .feeder(&Identity::from_seed([9; 32]).public())
            .ok_or("no figures")?,
        fixtures::FEEDER_STATS_UNRANKED,
    )?;
    let listed = board.leaderboards();
    same(&listed, fixtures::LEADERBOARDS)?;
    let area = listed.areas.first().ok_or("no area")?;
    let area = crate::feeders::parse_area(&area.area).ok_or("not an area")?;
    same(
        &board.leaderboard(&area).ok_or("no board")?,
        fixtures::LEADERBOARD,
    )?;
    // The same records while no feeder has standing: the area is answered, nobody is ranked.
    use crate::feeders::tests::{T, ledger, records};
    let unranked = ledger(&records()).board(T + 60_000, |_| false);
    same(
        &unranked.leaderboard(&area).ok_or("no board")?,
        fixtures::LEADERBOARD_UNRANKED,
    )
}
