//! `/v2/...`: the ADS-B Exchange-compatible API (RFC-0187 §2), the paths, aliases and answers
//! adsb.lol's `api_v2.py` serves (github.com/adsblol/api, BSD-3-Clause, Copyright (c) 2023 Katia
//! Esposito; the queries below are ported from it). Each path is one query of readsb's API port,
//! asked for ADS-B Exchange's v2 form (`&jv2`), and readsb's answer is served as it is: `ac` (each
//! aircraft as readsb's JSON gives it), `msg`, `now` (milliseconds), `total`, `ctime` and `ptime`.
//! readsb decides which aircraft match (github.com/wiedehopf/readsb, README-json.md); this only
//! refuses what is not a well-formed query (`400`) before readsb is asked.
//!
//! - `/v2/hex/{hex}` (`/v2/icao/{hex}`): `find_hex`, a 24-bit address as six hex digits.
//! - `/v2/callsign/{callsign}`: `find_callsign`.
//! - `/v2/registration/{reg}` (`/v2/reg/{reg}`): `find_reg`.
//! - `/v2/type/{type}`: `find_type`, an ICAO type designator.
//! - `/v2/squawk/{squawk}` (`/v2/sqk/{squawk}`): every aircraft, `filter_squawk`.
//! - `/v2/mil`, `/v2/ladd`, `/v2/pia`: every aircraft, `filter_mil`, `filter_ladd`, `filter_pia`.
//! - `/v2/point/{lat}/{lon}/{radius}` (`/v2/lat/{lat}/lon/{lon}/dist/{radius}`): `circle`, the
//!   radius in nautical miles, at most `MAX_RADIUS_NM`.
//! - `/v2/closest/{lat}/{lon}/{radius}`: `closest`, the one aircraft nearest within the radius.
//!
//! A value may be a comma-separated list, as adsb.lol and readsb take it (`/v2/hex/a1b2c3,c0ffee`).

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::App;
use crate::routes::refuse;

/// The largest radius `point` and `closest` take, nautical miles: adsb.lol's.
pub const MAX_RADIUS_NM: f64 = 250.0;
/// The most values one list may name: readsb answers at most this many matches of a `find_`.
pub const MAX_LISTED: usize = 1000;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/v2/hex/{value}", get(hex))
        .route("/v2/icao/{value}", get(hex))
        .route("/v2/callsign/{value}", get(callsign))
        .route("/v2/registration/{value}", get(registration))
        .route("/v2/reg/{value}", get(registration))
        .route("/v2/type/{value}", get(kind))
        .route("/v2/squawk/{value}", get(squawk))
        .route("/v2/sqk/{value}", get(squawk))
        .route("/v2/mil", get(mil))
        .route("/v2/ladd", get(ladd))
        .route("/v2/pia", get(pia))
        .route("/v2/point/{lat}/{lon}/{radius}", get(point))
        .route("/v2/lat/{lat}/lon/{lon}/dist/{radius}", get(point))
        .route("/v2/closest/{lat}/{lon}/{radius}", get(closest))
}

/// A query of readsb: its parameters, in adsb.lol's order, before `jv2`.
#[derive(Debug, PartialEq)]
pub struct Query(Vec<String>);

impl Query {
    /// The URL that asks readsb at `base` for it, in ADS-B Exchange's v2 form.
    pub fn url(&self, base: &str) -> String {
        format!("{}/?{}&jv2", base.trim_end_matches('/'), self.0.join("&"))
    }
}

/// `find_hex`: six hex digits each, sent lowercase.
pub fn hex_query(value: &str) -> Result<Query, String> {
    let listed = list(value, "a 24-bit address is six hex digits", |one| {
        one.len() == 6 && one.bytes().all(|byte| byte.is_ascii_hexdigit())
    })?;
    Ok(Query(vec![format!(
        "find_hex={}",
        listed.to_ascii_lowercase()
    )]))
}

/// The longest callsign: eight characters, as a transponder sends one. The routes hold theirs to it
/// too (`vrs`).
pub const MAX_CALLSIGN: usize = 8;

/// `find_callsign`: up to eight letters and digits each, as a transponder sends them.
pub fn callsign_query(value: &str) -> Result<Query, String> {
    let listed = list(
        value,
        "a callsign is up to eight letters and digits",
        |one| {
            (1..=MAX_CALLSIGN).contains(&one.len())
                && one.bytes().all(|byte| byte.is_ascii_alphanumeric())
        },
    )?;
    Ok(Query(vec![format!("find_callsign={listed}")]))
}

/// `find_reg`: letters, digits and hyphens each.
pub fn registration_query(value: &str) -> Result<Query, String> {
    let listed = list(
        value,
        "a registration is up to twelve letters, digits and hyphens",
        |one| {
            (1..=12).contains(&one.len())
                && one
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        },
    )?;
    Ok(Query(vec![format!("find_reg={listed}")]))
}

/// `find_type`: an ICAO type designator each, up to four letters and digits.
pub fn type_query(value: &str) -> Result<Query, String> {
    let listed = list(
        value,
        "a type is an ICAO designator of up to four letters and digits",
        |one| (1..=4).contains(&one.len()) && one.bytes().all(|byte| byte.is_ascii_alphanumeric()),
    )?;
    Ok(Query(vec![format!("find_type={listed}")]))
}

/// Every aircraft, `filter_squawk`: four octal digits each.
pub fn squawk_query(value: &str) -> Result<Query, String> {
    let listed = list(value, "a squawk is four octal digits", |one| {
        one.len() == 4 && one.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
    })?;
    Ok(Query(vec![
        "all".to_owned(),
        format!("filter_squawk={listed}"),
    ]))
}

/// Every aircraft with one of readsb's database flags: `filter_mil`, `filter_ladd`, `filter_pia`.
pub fn flagged_query(filter: &str) -> Query {
    Query(vec!["all".to_owned(), filter.to_owned()])
}

/// `circle` (`closest` when `nearest`): a place and a radius in nautical miles.
pub fn around_query(lat: &str, lon: &str, radius: &str, nearest: bool) -> Result<Query, String> {
    let degrees = |text: &str, limit: f64| {
        text.parse::<f64>()
            .ok()
            .filter(|value| value.is_finite() && value.abs() <= limit)
    };
    let (Some(lat), Some(lon)) = (degrees(lat, 90.0), degrees(lon, 180.0)) else {
        return Err("lat is degrees from -90 to 90, and lon degrees from -180 to 180".to_owned());
    };
    let Some(radius) = radius
        .parse::<f64>()
        .ok()
        .filter(|radius| (0.0..=MAX_RADIUS_NM).contains(radius))
    else {
        return Err(format!(
            "radius is nautical miles from 0 to {MAX_RADIUS_NM}"
        ));
    };
    let query = if nearest { "closest" } else { "circle" };
    Ok(Query(vec![format!("{query}={lat},{lon},{radius}")]))
}

/// A comma-separated list of at most `MAX_LISTED` values, each one `valid` accepts, or why not.
fn list<'a>(value: &'a str, why: &str, valid: impl Fn(&str) -> bool) -> Result<&'a str, String> {
    let mut count = 0;
    for one in value.split(',') {
        count += 1;
        if count > MAX_LISTED || !valid(one) {
            return Err(format!("{why}; at most {MAX_LISTED}, comma-separated"));
        }
    }
    Ok(value)
}

/// What readsb's v2 answer must be to be served: an object with its aircraft. Everything else in
/// it is served as readsb wrote it.
#[derive(Deserialize)]
struct Answer {
    #[expect(
        dead_code,
        reason = "read only to check the answer is readsb's v2 form"
    )]
    ac: Vec<serde::de::IgnoredAny>,
}

/// Asks readsb `query` and serves its answer, or why not: the query's own mistake (`400`), or
/// readsb not answering (`502`).
async fn ask(app: &App, query: Result<Query, String>) -> Response {
    let query = match query {
        Ok(query) => query,
        Err(why) => return refuse(StatusCode::BAD_REQUEST, &why),
    };
    let url = query.url(&app.settings.readsb);
    let body = match app.upstream.get(&url).await.and_then(|body| {
        serde_json::from_slice::<Answer>(&body)
            .map(|_| body)
            .map_err(|error| format!("{url}: {error}"))
    }) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("tally-api: {error}");
            return refuse(StatusCode::BAD_GATEWAY, "readsb did not answer");
        }
    };
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

async fn hex(State(app): State<Arc<App>>, Path(value): Path<String>) -> Response {
    ask(&app, hex_query(&value)).await
}

async fn callsign(State(app): State<Arc<App>>, Path(value): Path<String>) -> Response {
    ask(&app, callsign_query(&value)).await
}

async fn registration(State(app): State<Arc<App>>, Path(value): Path<String>) -> Response {
    ask(&app, registration_query(&value)).await
}

async fn kind(State(app): State<Arc<App>>, Path(value): Path<String>) -> Response {
    ask(&app, type_query(&value)).await
}

async fn squawk(State(app): State<Arc<App>>, Path(value): Path<String>) -> Response {
    ask(&app, squawk_query(&value)).await
}

async fn mil(State(app): State<Arc<App>>) -> Response {
    ask(&app, Ok(flagged_query("filter_mil"))).await
}

async fn ladd(State(app): State<Arc<App>>) -> Response {
    ask(&app, Ok(flagged_query("filter_ladd"))).await
}

async fn pia(State(app): State<Arc<App>>) -> Response {
    ask(&app, Ok(flagged_query("filter_pia"))).await
}

async fn point(
    State(app): State<Arc<App>>,
    Path((lat, lon, radius)): Path<(String, String, String)>,
) -> Response {
    ask(&app, around_query(&lat, &lon, &radius, false)).await
}

async fn closest(
    State(app): State<Arc<App>>,
    Path((lat, lon, radius)): Path<(String, String, String)>,
) -> Response {
    ask(&app, around_query(&lat, &lon, &radius, true)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const READSB: &str = "http://127.0.0.1:30152/";

    fn url(query: Result<Query, String>) -> Result<String, String> {
        query.map(|query| query.url(READSB))
    }

    /// Each path asks readsb what adsb.lol's asks it, in v2 form.
    #[test]
    fn each_path_is_adsb_lols_query() -> Result<(), String> {
        let base = "http://127.0.0.1:30152/?";
        for (query, expected) in [
            (hex_query("A1B2C3")?, "find_hex=a1b2c3&jv2"),
            (hex_query("a1b2c3,C0FFEE")?, "find_hex=a1b2c3,c0ffee&jv2"),
            (callsign_query("JBU1942")?, "find_callsign=JBU1942&jv2"),
            (registration_query("G-KELS")?, "find_reg=G-KELS&jv2"),
            (type_query("A320")?, "find_type=A320&jv2"),
            (squawk_query("7700")?, "all&filter_squawk=7700&jv2"),
            (flagged_query("filter_mil"), "all&filter_mil&jv2"),
            (flagged_query("filter_ladd"), "all&filter_ladd&jv2"),
            (flagged_query("filter_pia"), "all&filter_pia&jv2"),
            (
                around_query("51.89508", "2.79437", "250", false)?,
                "circle=51.89508,2.79437,250&jv2",
            ),
            (
                around_query("-33.9", "151.2", "12.5", true)?,
                "closest=-33.9,151.2,12.5&jv2",
            ),
        ] {
            assert_eq!(query.url(READSB), format!("{base}{expected}"));
        }
        Ok(())
    }

    /// What is not a well-formed value is refused before readsb is asked, so nothing a client
    /// writes reaches readsb's query but the values each path takes.
    #[test]
    fn a_malformed_value_is_refused() {
        for refused in [
            url(hex_query("a1b2c")),
            url(hex_query("a1b2cg")),
            url(hex_query("a1b2c3&all")),
            url(hex_query("a1b2c3,")),
            url(hex_query(&vec!["a1b2c3"; MAX_LISTED + 1].join(","))),
            url(callsign_query("JBU 1942")),
            url(callsign_query("ABCDEFGHI")),
            url(registration_query("G_KELS")),
            url(type_query("A3200")),
            url(squawk_query("7800")),
            url(squawk_query("770")),
            url(around_query("91", "0", "10", false)),
            url(around_query("0", "-180.5", "10", false)),
            url(around_query("0", "0", "250.1", false)),
            url(around_query("0", "0", "-1", true)),
            url(around_query("NaN", "0", "10", true)),
            url(around_query("0", "inf", "10", true)),
            url(around_query("north", "0", "10", true)),
        ] {
            assert!(refused.is_err(), "{refused:?}");
        }
        assert!(url(hex_query(&vec!["a1b2c3"; MAX_LISTED].join(","))).is_ok());
    }
}
