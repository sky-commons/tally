//! The API's own answers, serialised, are `tally_api_types::fixtures` exactly: the text every
//! client's test reads (the Flightlines client core's `tally-reads` among them) is what this API
//! writes, so a field renamed, retyped or re-meant here turns this test red before any client can
//! read the old shape.

use tally_api_types::fixtures;
use tally_relay::stations::{StationReport, StationsReport, cell_name};
use tally_wire::{Identity, Location, Region};

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

/// The public cell a station at `lat`, `lon` states, as the relay names it: all the relay tells
/// a client of where a station is.
fn cell_at(lat: f64, lon: f64) -> Option<String> {
    Region::public_cell(&Location {
        lat_e7: (lat * 1e7).round() as i32,
        lon_e7: (lon * 1e7).round() as i32,
        alt_m: 10,
        precision_m: 0,
    })
    .ok()
    .map(cell_name)
}

fn report(cell: Option<String>, software: Option<&str>) -> StationReport {
    report_of(cell, software, 120_000)
}

fn report_of(cell: Option<String>, software: Option<&str>, observations: u64) -> StationReport {
    StationReport {
        key: station_key().to_base64(),
        online: true,
        connected: true,
        connected_since_ms: Some(NOW_MS - 3_600_000),
        sessions: 2,
        first_seen_ms: NOW_MS - 3_600_000,
        last_seen_ms: NOW_MS - 1_000,
        batches: 9_001,
        gaps: 3,
        observations,
        cell,
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
fn earlier(cell: Option<String>, software: Option<&str>) -> Stations {
    Stations::from_report(
        StationsReport {
            now_ms: NOW_MS - 4_000,
            stations: vec![report_of(cell, software, 120_000 - 169)],
        },
        None,
    )
}

#[test]
fn the_network_and_station_answers_are_the_fixtures() -> Result<(), String> {
    let place = cell_at(37.5, -122.25);
    let located = Stations::from_report(
        StationsReport {
            now_ms: NOW_MS,
            stations: vec![report(place.clone(), Some("tally-feed 0.3.1"))],
        },
        Some(&earlier(place.clone(), Some("tally-feed 0.3.1"))),
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
    // Connected two minutes ago, its decoder silent: the relay has forwarded no batch of it.
    let connected_ms = NOW_MS - 120_000;
    let silent = Stations::from_report(
        StationsReport {
            now_ms: NOW_MS,
            stations: vec![StationReport {
                key: station_key().to_base64(),
                online: false,
                connected: true,
                connected_since_ms: Some(connected_ms),
                sessions: 0,
                first_seen_ms: connected_ms,
                last_seen_ms: connected_ms,
                batches: 0,
                gaps: 0,
                observations: 0,
                cell: None,
                software: Some("tally-feed 0.3.0".to_owned()),
                address: None,
            }],
        },
        None,
    );
    same(
        &silent.station(&station_key()).ok_or("no station")?,
        fixtures::STATION_SILENT,
    )?;
    // Fed, then left: last forwarded ten minutes ago, no longer connected.
    let mut left = report(place, Some("tally-feed 0.3.1"));
    left.online = false;
    left.connected = false;
    left.connected_since_ms = None;
    left.last_seen_ms = NOW_MS - 600_000;
    let offline = Stations::from_report(
        StationsReport {
            now_ms: NOW_MS,
            stations: vec![left],
        },
        None,
    );
    same(
        &offline.station(&station_key()).ok_or("no station")?,
        fixtures::STATION_OFFLINE,
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

/// Every number in `value`, wherever it sits.
fn numbers(value: &serde_json::Value, into: &mut Vec<f64>) {
    match value {
        serde_json::Value::Number(number) => into.extend(number.as_f64()),
        serde_json::Value::Array(items) => items.iter().for_each(|item| numbers(item, into)),
        serde_json::Value::Object(fields) => fields.values().for_each(|item| numbers(item, into)),
        _ => {}
    }
}

/// No public answer that names a station carries its exact place: the relay tells the API its
/// public cell and nothing finer, and the station answer and the network's, as the API writes
/// them, hold neither coordinate the receiver is at.
#[test]
fn no_public_answer_carries_a_receivers_exact_place() -> Result<(), String> {
    let (lat, lon) = (37.512_345_6, -122.251_234_5);
    let stations = Stations::from_report(
        StationsReport {
            now_ms: NOW_MS,
            stations: vec![report(cell_at(lat, lon), Some("tally-feed 0.3.1"))],
        },
        None,
    );
    let station = stations.station(&station_key()).ok_or("no station")?;
    let pin = station.location.ok_or("no pin")?;
    let mut written = Vec::new();
    numbers(
        &serde_json::to_value(&station).map_err(|e| e.to_string())?,
        &mut written,
    );
    numbers(
        &serde_json::to_value(stations.network(SourceCounts::default()))
            .map_err(|e| e.to_string())?,
        &mut written,
    );
    for exact in [lat, lon] {
        assert!(!written.contains(&exact), "{exact} served");
    }
    // Near it: inside its public cell.
    assert_eq!(cell_at(pin.lat, pin.lon), cell_at(lat, lon), "{pin:?}");
    // The fixtures say the same of theirs: the place they were made from is not in them.
    for fixture in [fixtures::STATION, fixtures::STATION_OFFLINE] {
        let mut served = Vec::new();
        numbers(
            &serde_json::from_str(fixture).map_err(|e| e.to_string())?,
            &mut served,
        );
        assert!(!served.contains(&37.5) && !served.contains(&-122.25));
    }
    Ok(())
}

/// The feeder figures and boards the fixtures are: the feeders module's own records (one relay's
/// figures of two placed feeders with standing and one that names no cell), read as issued.
fn board() -> crate::feeders::Board {
    use crate::feeders::tests::{H, T, ledger, records};
    ledger(&records()).board(T + H)
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
    use crate::feeders::tests::{H, T, ledger, records_standing};
    let unranked = ledger(&records_standing(false, false)).board(T + H);
    same(
        &unranked.leaderboard(&area).ok_or("no board")?,
        fixtures::LEADERBOARD_UNRANKED,
    )
}
