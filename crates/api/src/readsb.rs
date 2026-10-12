//! readsb's JSON, as its API port (`--net-api-port`) and `aircraft.json` write it
//! (github.com/wiedehopf/readsb, README-json.md), read into the public shape. readsb is the
//! decoder (RFC-0119 §3.3); this only renames its fields, states when each aircraft was last heard
//! as an instant on readsb's clock (readsb says how many seconds before its `now`), and drops the
//! aircraft it holds no position for.

use serde::Deserialize;

use crate::area::ReadsbBox;
use tally_api_types::{Aircraft, PositionSource};

/// What one readsb answer is read as. Fields this does not name are ignored.
#[derive(Debug, Deserialize)]
pub struct Answer {
    /// Unix seconds, with a fraction, when readsb's data was current.
    pub now: f64,
    /// The API's count of aircraft in its answer, when it states one.
    #[serde(rename = "resultCount")]
    pub result_count: Option<u64>,
    /// `aircraft` in `aircraft.json` and the API; `ac` in the API's ADSBExchange v2 form (`&jv2`).
    #[serde(default, alias = "ac")]
    pub aircraft: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
pub struct Entry {
    pub hex: String,
    pub flight: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub alt_baro: Option<Altitude>,
    pub gs: Option<f64>,
    pub track: Option<f64>,
    pub baro_rate: Option<f64>,
    /// Seconds before `now` the last message was heard.
    pub seen: Option<f64>,
}

/// `alt_baro`: feet, or the word `ground`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Altitude {
    Feet(f64),
    Word(String),
}

/// The API query for one box: aircraft inside it with a position.
pub fn box_query(base: &str, area: &ReadsbBox) -> String {
    format!("{}/?box={area}&filter_with_pos", base.trim_end_matches('/'))
}

/// The API query for every aircraft with a position, for the network's count.
pub fn all_query(base: &str) -> String {
    format!("{}/?all_with_pos", base.trim_end_matches('/'))
}

pub fn parse(bytes: &[u8]) -> Result<Answer, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("readsb: {error}"))
}

/// Unix milliseconds of readsb's `now`.
pub fn now_ms(answer: &Answer) -> u64 {
    millis(answer.now)
}

impl Answer {
    /// How many aircraft it holds: its stated count, or those it lists.
    pub fn count(&self) -> u64 {
        self.result_count.unwrap_or(self.aircraft.len() as u64)
    }
}

/// The public form of one entry of an answer current at `now_ms`, or `None` when readsb holds no
/// position for it. readsb's `seen` (seconds before `now`) becomes the instant it was last heard;
/// an entry that states no `seen` was heard at `now`.
pub fn aircraft(entry: &Entry, now_ms: u64) -> Option<Aircraft> {
    let (lat, lon) = (entry.lat?, entry.lon?);
    let (alt_baro_ft, on_ground) = match &entry.alt_baro {
        Some(Altitude::Feet(feet)) => (Some(round_i32(*feet)), false),
        Some(Altitude::Word(word)) => (None, word == "ground"),
        None => (None, false),
    };
    let flight = entry
        .flight
        .as_deref()
        .map(str::trim)
        .filter(|flight| !flight.is_empty())
        .map(str::to_owned);
    Some(Aircraft {
        hex: entry.hex.to_ascii_lowercase(),
        flight,
        lat,
        lon,
        alt_baro_ft,
        gs_kt: entry.gs,
        track_deg: entry.track,
        baro_rate_fpm: entry.baro_rate.map(round_i32),
        on_ground,
        last_heard_at_ms: now_ms.saturating_sub(entry.seen.map_or(0, millis)),
        // seam stub (RFC-0184): the position's own time is readsb's `seen_pos`
        position_at_ms: now_ms.saturating_sub(entry.seen.map_or(0, millis)),
        position_source: PositionSource::Adsb,
        mlat: None,
    })
}

/// Seconds to whole milliseconds, never below zero.
fn millis(seconds: f64) -> u64 {
    // `as` saturates, and maps NaN to 0.
    (seconds * 1000.0).round().max(0.0) as u64
}

fn round_i32(value: f64) -> i32 {
    value.round() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANSWER: &str = r#"{
        "now": 1791220000.4,
        "resultCount": 4,
        "ptime": 0.1,
        "aircraft": [
            {"hex": "A1B2C3", "type": "adsb_icao", "flight": "UAL123  ", "alt_baro": 35000,
             "alt_geom": 35500, "gs": 451.3, "track": 271.9, "baro_rate": -64.0, "squawk": "1200",
             "lat": 37.5, "lon": -122.25, "seen_pos": 0.5, "seen": 0.2, "rssi": -20.1},
            {"hex": "abcdef", "flight": "        ", "alt_baro": "ground", "gs": 3.0,
             "lat": 37.62, "lon": -122.38, "seen": 1.25},
            {"hex": "~123456", "type": "tisb_other", "lat": 37.0, "lon": -122.0},
            {"hex": "c0ffee", "alt_baro": 12000, "seen": 3.0}
        ]
    }"#;

    #[test]
    fn readsbs_answer_is_read_into_the_public_shape() -> Result<(), String> {
        let answer = parse(ANSWER.as_bytes())?;
        assert_eq!((now_ms(&answer), answer.count()), (1_791_220_000_400, 4));
        let now = now_ms(&answer);
        let aircraft: Vec<Aircraft> = answer
            .aircraft
            .iter()
            .filter_map(|entry| aircraft(entry, now))
            .collect();
        assert_eq!(
            aircraft,
            vec![
                Aircraft {
                    hex: "a1b2c3".to_owned(),
                    flight: Some("UAL123".to_owned()),
                    lat: 37.5,
                    lon: -122.25,
                    alt_baro_ft: Some(35_000),
                    gs_kt: Some(451.3),
                    track_deg: Some(271.9),
                    baro_rate_fpm: Some(-64),
                    on_ground: false,
                    last_heard_at_ms: 1_791_220_000_200,
                    position_source: PositionSource::Adsb,
                    mlat: None,
                },
                Aircraft {
                    hex: "abcdef".to_owned(),
                    flight: None,
                    lat: 37.62,
                    lon: -122.38,
                    alt_baro_ft: None,
                    gs_kt: Some(3.0),
                    track_deg: None,
                    baro_rate_fpm: None,
                    on_ground: true,
                    last_heard_at_ms: 1_791_219_999_150,
                    position_source: PositionSource::Adsb,
                    mlat: None,
                },
                // A non-ICAO address keeps readsb's mark; one with no position is left out.
                Aircraft {
                    hex: "~123456".to_owned(),
                    flight: None,
                    lat: 37.0,
                    lon: -122.0,
                    alt_baro_ft: None,
                    gs_kt: None,
                    track_deg: None,
                    baro_rate_fpm: None,
                    on_ground: false,
                    last_heard_at_ms: 1_791_220_000_400,
                    position_source: PositionSource::Adsb,
                    mlat: None,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn the_v2_form_and_an_answer_with_no_count_are_read_too() -> Result<(), String> {
        let answer = parse(br#"{"now": 1.5, "ac": [{"hex": "a1b2c3", "lat": 1, "lon": 2}]}"#)?;
        assert_eq!((now_ms(&answer), answer.count()), (1_500, 1));
        let empty = parse(br#"{"now": 2}"#)?;
        assert_eq!(empty.count(), 0);
        assert!(parse(b"<html>").is_err());
        Ok(())
    }

    #[test]
    fn the_queries_are_readsbs_own() {
        let area = ReadsbBox {
            south: 37.0,
            north: 38.5,
            west: -123.0,
            east: -121.0,
        };
        assert_eq!(
            box_query("http://127.0.0.1:30152/", &area),
            "http://127.0.0.1:30152/?box=37,38.5,-123,-121&filter_with_pos"
        );
        assert_eq!(
            all_query("http://127.0.0.1:30152"),
            "http://127.0.0.1:30152/?all_with_pos"
        );
    }
}
