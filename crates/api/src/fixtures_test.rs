//! The API's own answers, serialised, are `tally_api_types::fixtures` exactly: the text every
//! client's test reads (the Flightlines client core's `tally-reads` among them) is what this API
//! writes, so a field renamed, retyped or re-meant here turns this test red before any client can
//! read the old shape.

use tally_api_types::fixtures;
use tally_relay::stations::{StationLocation, StationReport, StationsReport};
use tally_wire::Identity;

use crate::mlat::Served;
use crate::snapshot::Stations;
use crate::{mlat, readsb};

/// The station the fixtures name: a fixed seed, so its key is the same on every run.
fn station_key() -> tally_wire::PublicKey {
    Identity::from_seed([7; 32]).public()
}

const NOW_MS: u64 = 1_791_220_000_250;

/// readsb's answer the aircraft fixture is the API's reading of.
const READSB: &str = r#"{
    "now": 1791220000.25,
    "resultCount": 2,
    "aircraft": [
        {"hex": "A1B2C3", "flight": "UAL123  ", "alt_baro": 35000, "gs": 451.5, "track": 271.0,
         "baro_rate": -640, "lat": 37.5, "lon": -122.25, "seen": 1.5},
        {"hex": "abcdef", "flight": "        ", "alt_baro": "ground", "lat": 37.62,
         "lon": -122.38, "seen": 0},
        {"hex": "c0ffee", "alt_baro": 12000, "seen": 3.0}
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
    let one = |address: u32, lat: f64, lon: f64| Served {
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
        transmitted_ms: 1_791_219_999_125,
    };
    vec![one(0xa1b2c3, 37.6, -122.3), one(0xc0ffee, 37.71, -122.45)]
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
        &crate::routes::precise_answer(&served, 1_791_219_908_000),
        fixtures::AIRCRAFT_PRECISE,
    )
}

#[test]
fn the_aircraft_answer_is_the_fixture() -> Result<(), String> {
    let answer = readsb::parse(READSB.as_bytes())?;
    let now_ms = readsb::now_ms(&answer);
    let adsb = answer
        .aircraft
        .iter()
        .filter_map(|entry| readsb::aircraft(entry, now_ms))
        .collect();
    let aircraft = mlat::answer(adsb, &mlat_positions());
    same(
        &tally_api_types::AircraftResponse {
            now_ms,
            feed: tally_api_types::Feed::Live,
            aircraft,
        },
        fixtures::AIRCRAFT,
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
    same(&located.network(311), fixtures::NETWORK)?;
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
    )
}
