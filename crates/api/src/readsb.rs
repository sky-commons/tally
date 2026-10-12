//! readsb's JSON, as its API port (`--net-api-port`) and `aircraft.json` write it
//! (github.com/wiedehopf/readsb, README-json.md), read into the public shape. readsb is the
//! decoder (RFC-0119 §3.3); this only renames its fields, states when each aircraft was last heard
//! and when its position was as instants on readsb's clock (readsb says how many seconds before its
//! `now`), names where the position came from (readsb's `type`), and drops the aircraft it holds no
//! position for.

use serde::Deserialize;

use crate::area::ReadsbBox;
use tally_api_types::{Aircraft, PositionSource};

/// What one readsb answer is read as. Fields this does not name are ignored.
#[derive(Debug, Deserialize)]
pub struct Answer {
    /// Unix seconds, with a fraction, when readsb's data was current.
    pub now: f64,
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
    /// Seconds before `now` the position was last updated: what a client projects from.
    pub seen_pos: Option<f64>,
    /// Where readsb's data on it came from (`adsb_icao`, `mlat`, `tisb_other`, ...).
    #[serde(rename = "type")]
    pub kind: Option<String>,
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
    /// The public form of every entry it gives a position for, in its order.
    pub fn positioned(&self) -> Vec<Aircraft> {
        let now_ms = now_ms(self);
        self.aircraft
            .iter()
            .filter_map(|entry| aircraft(entry, now_ms))
            .collect()
    }
}

/// Where a position readsb decoded came from, by its `type` (the doc of each `PositionSource`
/// names readsb's words): readsb's own `mlat` is not Tally's, so it is `Other`, as is an entry
/// that names none.
pub fn source(kind: Option<&str>) -> PositionSource {
    match kind {
        Some("adsb_icao" | "adsb_icao_nt" | "adsb_other") => PositionSource::Adsb,
        Some("adsr_icao" | "adsr_other") => PositionSource::Adsr,
        Some("tisb_icao" | "tisb_other" | "tisb_trackfile") => PositionSource::Tisb,
        _ => PositionSource::Other,
    }
}

/// The public form of one entry of an answer current at `now_ms`, or `None` when readsb holds no
/// position for it. readsb's `seen` (seconds before `now`) becomes the instant it was last heard
/// and its `seen_pos` the instant of its position (its `seen` when it states no `seen_pos`); an
/// entry that states neither was heard at `now`. A position is a message, so the last heard is
/// never before it.
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
    let before = |seconds: Option<f64>| now_ms.saturating_sub(seconds.map_or(0, millis));
    let position_at_ms = before(entry.seen_pos.or(entry.seen));
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
        last_heard_at_ms: before(entry.seen).max(position_at_ms),
        position_at_ms,
        position_source: source(entry.kind.as_deref()),
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
        assert_eq!(now_ms(&answer), 1_791_220_000_400);
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
                    position_at_ms: 1_791_219_999_900,
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
                    // No `seen_pos`: its `seen`. No `type`: a source readsb does not name.
                    position_at_ms: 1_791_219_999_150,
                    position_source: PositionSource::Other,
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
                    position_at_ms: 1_791_220_000_400,
                    position_source: PositionSource::Tisb,
                    mlat: None,
                },
            ]
        );
        Ok(())
    }

    /// A velocity or altitude message moves `seen` and not `seen_pos`: the aircraft is heard
    /// later, and its position keeps the instant it was heard at.
    #[test]
    fn a_message_without_a_position_does_not_move_the_positions_instant() -> Result<(), String> {
        let at = |now: f64, seen: f64, seen_pos: f64| -> Result<(u64, u64), String> {
            let text = format!(
                r#"{{"now": {now}, "aircraft": [{{"hex": "a1b2c3", "type": "adsb_icao",
                    "lat": 37.5, "lon": -122.25, "seen": {seen}, "seen_pos": {seen_pos}}}]}}"#
            );
            let one = parse(text.as_bytes())?
                .positioned()
                .pop()
                .ok_or("no aircraft")?;
            Ok((one.last_heard_at_ms, one.position_at_ms))
        };
        assert_eq!(
            at(1_791_220_000.0, 0.0, 0.0)?,
            (1_791_220_000_000, 1_791_220_000_000)
        );
        // A second on, only a velocity message since: heard later, positioned as before.
        assert_eq!(
            at(1_791_220_001.0, 0.2, 1.0)?,
            (1_791_220_000_800, 1_791_220_000_000)
        );
        // `seen` rounded below `seen_pos` never puts the last heard before the position.
        assert_eq!(
            at(1_791_220_001.0, 0.5, 0.4)?,
            (1_791_220_000_600, 1_791_220_000_600)
        );
        Ok(())
    }

    /// readsb's every `type`, as the doc of each `PositionSource` names them.
    #[test]
    fn readsbs_type_names_the_positions_source() {
        for (kind, expected) in [
            ("adsb_icao", PositionSource::Adsb),
            ("adsb_icao_nt", PositionSource::Adsb),
            ("adsb_other", PositionSource::Adsb),
            ("adsr_icao", PositionSource::Adsr),
            ("adsr_other", PositionSource::Adsr),
            ("tisb_icao", PositionSource::Tisb),
            ("tisb_other", PositionSource::Tisb),
            ("tisb_trackfile", PositionSource::Tisb),
            ("adsc", PositionSource::Other),
            ("mode_s", PositionSource::Other),
            ("other", PositionSource::Other),
            // readsb's own MLAT is not Tally's.
            ("mlat", PositionSource::Other),
            ("something_new", PositionSource::Other),
        ] {
            assert_eq!(source(Some(kind)), expected, "{kind}");
        }
        assert_eq!(source(None), PositionSource::Other);
    }

    #[test]
    fn the_v2_form_and_an_answer_with_no_aircraft_are_read_too() -> Result<(), String> {
        let answer = parse(br#"{"now": 1.5, "ac": [{"hex": "a1b2c3", "lat": 1, "lon": 2}]}"#)?;
        assert_eq!((now_ms(&answer), answer.positioned().len()), (1_500, 1));
        let empty = parse(br#"{"now": 2}"#)?;
        assert!(empty.positioned().is_empty());
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
