//! The endpoints, and the guard every request passes: a CORS preflight answered at once, else
//! the client's token bucket, the cap on requests in flight and the request's deadline (a stream,
//! which lasts as long as its connection, its own cap instead: `stream`), then CORS and
//! `Cache-Control` on whatever answers: no `Cache-Control` but `no-store` for what depends on who
//! asks (`/v1/me`) or is not a read (`POST`).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use tally_api_types::{Aircraft, AircraftResponse};
use tally_wire::PublicKey;

use crate::area::Area;
use crate::feeders::{Board, parse_area};
use crate::{App, mlat, readsb, stream, v2, vrs};

/// How long the edge may keep an aircraft answer: aircraft move.
pub const AIRCRAFT_MAX_AGE_SECS: u32 = 2;
/// How long the edge may keep any other answer: the relay's figures are read every few seconds.
pub const OTHER_MAX_AGE_SECS: u32 = 15;
/// The longest one request may take, upstream reads included.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The request headers a browser may send cross-origin, beyond the ones CORS always allows: what a
/// client asks with. The Flightlines client core stamps W3C trace context (`traceparent`) on every
/// request and asks for JSON (`accept`), so a preflight that did not allow both would refuse its
/// every read; tar1090 posts its routeset as JSON (`content-type`).
pub const ALLOW_HEADERS: &str = "accept, content-type, traceparent";
/// The response headers a page may read cross-origin, beyond the safelisted ones: `Retry-After`,
/// which a client honours after a `429`.
pub const EXPOSE_HEADERS: &str = "retry-after";
/// The methods the API answers: reads, and tar1090's routeset.
pub const ALLOW_METHODS: &str = "GET, POST";
/// How long a browser may keep a preflight's answer, in seconds (browsers cap it lower).
pub const PREFLIGHT_MAX_AGE_SECS: u32 = 86_400;

/// The path of the asking client's own stations.
pub const ME: &str = "/v1/me";

/// The connection's peer, set on every request by `serve`.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub SocketAddr);

/// Who a request is from (`client_of`), set on every request by the guard.
#[derive(Clone, Copy, Debug)]
pub struct Client {
    /// Who the request counts against: the proxy's header when one is configured and parses,
    /// else the connection's peer, else one shared client.
    pub counts_as: IpAddr,
    /// The client's own address, only when it is known: the proxy's header when one is
    /// configured (never the proxy's own address when the header is missing or does not parse),
    /// else the connection's peer. Only this ever names a client's stations (`GET /v1/me`).
    pub address: Option<IpAddr>,
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/v1/aircraft", get(aircraft))
        .route(stream::PATH, get(stream::open))
        .route("/v1/network", get(network))
        .route("/v1/stations/{key}", get(station))
        .route("/v1/stations/{key}/stats", get(feeder))
        .route("/v1/leaderboards", get(leaderboards))
        .route("/v1/leaderboards/{area}", get(leaderboard))
        .route(ME, get(me))
        .route(
            "/api/0/routeset",
            post(vrs::routeset).layer(DefaultBodyLimit::max(vrs::MAX_BODY_BYTES)),
        )
        .route("/api/0/route/{callsign}/{lat}/{lon}", get(vrs::route))
        .merge(v2::router())
        .layer(middleware::from_fn_with_state(Arc::clone(&app), guard))
        .with_state(app)
}

/// The query `/v1/aircraft` and its stream are asked with.
#[derive(Deserialize)]
pub struct Viewport {
    west: f64,
    south: f64,
    east: f64,
    north: f64,
}

/// The viewport a query asks for, or why it is refused (`400`).
pub fn viewport(viewport: Result<Query<Viewport>, QueryRejection>) -> Result<Area, String> {
    let Ok(Query(viewport)) = viewport else {
        return Err("west, south, east and north are each a number of degrees".to_owned());
    };
    Area::new(viewport.west, viewport.south, viewport.east, viewport.north)
}

/// The aircraft in `area`: readsb's (`readsb`, from an answer current at
/// `readsb_now_ms`), then the MLAT position of every aircraft there readsb gave no position for;
/// and the instant the data was current, at or after every instant in it (an MLAT position may be
/// newer than readsb's data).
pub fn live_answer(
    app: &App,
    area: &Area,
    readsb_now_ms: u64,
    readsb: Vec<Aircraft>,
) -> (u64, Vec<Aircraft>) {
    let positions = app.mlat.in_area(area, wall_ms(), app.settings.mlat.max_age);
    let aircraft = mlat::answer(readsb, &positions);
    let now_ms = aircraft
        .iter()
        .map(|one| one.last_heard_at_ms)
        .fold(readsb_now_ms, u64::max);
    (now_ms, aircraft)
}

async fn aircraft(
    State(app): State<Arc<App>>,
    viewport: Result<Query<Viewport>, QueryRejection>,
) -> Response {
    let area = match self::viewport(viewport) {
        Ok(asked) => asked,
        Err(why) => return refuse(StatusCode::BAD_REQUEST, &why),
    };
    let mut now_ms = 0;
    let mut heard = HashSet::new();
    let mut aircraft = Vec::new();
    for part in area.boxes() {
        let url = readsb::box_query(&app.settings.readsb, &part);
        let answer = match app
            .upstream
            .get(&url)
            .await
            .and_then(|body| readsb::parse(&body))
        {
            Ok(answer) => answer,
            Err(error) => {
                eprintln!("tally-api: {error}");
                return refuse(StatusCode::BAD_GATEWAY, "readsb did not answer");
            }
        };
        let answered_ms = readsb::now_ms(&answer);
        now_ms = now_ms.max(answered_ms);
        // Either side of the antimeridian, an aircraft on the line is listed once.
        for entry in &answer.aircraft {
            if let Some(one) = readsb::aircraft(entry, answered_ms)
                && heard.insert(one.hex.clone())
            {
                aircraft.push(one);
            }
        }
    }
    let (now_ms, aircraft) = live_answer(&app, &area, now_ms, aircraft);
    axum::Json(AircraftResponse {
        now_ms,
        aircraft,
        sent_at_ms: wall_ms(),
    })
    .into_response()
}

async fn network(State(app): State<Arc<App>>) -> Response {
    let now = Instant::now();
    match (app.snapshot.stations(now), app.snapshot.aircraft(now)) {
        (Some(stations), Some(aircraft)) => axum::Json(stations.network(aircraft)).into_response(),
        _ => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "the network is not known yet",
        ),
    }
}

async fn station(State(app): State<Arc<App>>, Path(key): Path<String>) -> Response {
    let Ok(key) = PublicKey::from_base64url(&key) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "a station is named by its key, base64url without padding",
        );
    };
    let Some(stations) = app.snapshot.stations(Instant::now()) else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "stations are not known yet",
        );
    };
    match stations.station(&key) {
        Some(station) => axum::Json(station).into_response(),
        None => refuse(StatusCode::NOT_FOUND, "no such station"),
    }
}

/// The connected stations whose session came from the asking client's address
/// (`Stations::mine`); none when its address is not known.
async fn me(State(app): State<Arc<App>>, Extension(client): Extension<Client>) -> Response {
    match app.snapshot.stations(Instant::now()) {
        Some(stations) => axum::Json(stations.mine(client.address)).into_response(),
        None => refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "stations are not known yet",
        ),
    }
}

/// The feeder figures, or why there are none (answered `503`).
fn board(app: &App) -> Result<Arc<Board>, &'static str> {
    if app.settings.mlat.relays.is_empty() {
        return Err("this API reads no relay, so it computes no feeder figures");
    }
    app.snapshot
        .board(Instant::now())
        .ok_or("feeder figures are not computed yet")
}

async fn feeder(State(app): State<Arc<App>>, Path(key): Path<String>) -> Response {
    let Ok(key) = PublicKey::from_base64url(&key) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "a station is named by its key, base64url without padding",
        );
    };
    match board(&app).map(|board| board.feeder(&key)) {
        Ok(Some(stats)) => axum::Json(stats).into_response(),
        Ok(None) => refuse(
            StatusCode::NOT_FOUND,
            "no figures for this station in the last day",
        ),
        Err(why) => refuse(StatusCode::SERVICE_UNAVAILABLE, why),
    }
}

async fn leaderboards(State(app): State<Arc<App>>) -> Response {
    match board(&app) {
        Ok(board) => axum::Json(board.leaderboards()).into_response(),
        Err(why) => refuse(StatusCode::SERVICE_UNAVAILABLE, why),
    }
}

async fn leaderboard(State(app): State<Arc<App>>, Path(area): Path<String>) -> Response {
    let Some(area) = parse_area(&area) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            "an area is an H3 cell at resolution 3, as hex",
        );
    };
    match board(&app).map(|board| board.leaderboard(&area)) {
        Ok(Some(boards)) => axum::Json(boards).into_response(),
        Ok(None) => refuse(
            StatusCode::NOT_FOUND,
            "no feeder has figures in this area in the last day",
        ),
        Err(why) => refuse(StatusCode::SERVICE_UNAVAILABLE, why),
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "the API host's clock, which ages what it serves"
)]
pub(crate) fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// An error as JSON: `{"error": why}`.
pub fn refuse(status: StatusCode, why: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": why }))).into_response()
}

async fn guard(State(app): State<Arc<App>>, mut request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let streamed = path == stream::PATH;
    // Kept by no one: a stream (pushed), an answer that depends on who asks, and a write.
    let kept = !streamed && path != ME && request.method() != Method::POST;
    let max_age = if path == "/v1/aircraft" || path.starts_with("/v2/") {
        AIRCRAFT_MAX_AGE_SECS
    } else {
        OTHER_MAX_AGE_SECS
    };
    let origin = allowed_origin(&app.settings.allow_origins, request.headers());
    let client = client_of(&app, &request);
    request.extensions_mut().insert(client);
    // A preflight is answered here and costs the client nothing: it reads nothing upstream, and a
    // refused one would reach the page as a failed connection rather than as the refusal it was.
    let mut response = if request.method() == Method::OPTIONS {
        preflight()
    } else if !app.limiter.admit(client.counts_as, Instant::now()) {
        let mut response = refuse(StatusCode::TOO_MANY_REQUESTS, "too many requests");
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        response
    } else if streamed {
        // A stream lasts as long as its connection, so no deadline and no place among the
        // requests in flight: its client's cap on open streams holds it instead.
        next.run(request).await
    } else if let Ok(_permit) = Arc::clone(&app.requests).try_acquire_owned() {
        match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
            Ok(response) => response,
            Err(_) => refuse(StatusCode::GATEWAY_TIMEOUT, "the request took too long"),
        }
    } else {
        refuse(StatusCode::SERVICE_UNAVAILABLE, "too busy")
    };
    let status = response.status();
    let headers = response.headers_mut();
    if let Some(origin) = origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static(EXPOSE_HEADERS),
    );
    if app.settings.allow_origins.len() > 1 {
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    let cache = if kept {
        cache_control(status, max_age)
    } else {
        // A refusal of any of them is no answer to keep either.
        HeaderValue::from_static("no-store")
    };
    headers.insert(header::CACHE_CONTROL, cache);
    response
}

/// The answer to a CORS preflight: `204`, the method and the headers a client may send, and how long
/// a browser may keep it. The guard adds the origin.
pub fn preflight() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(ALLOW_METHODS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(ALLOW_HEADERS),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from(PREFLIGHT_MAX_AGE_SECS),
    );
    response
}

/// What the edge may keep: an answer, or a client's own mistake (400, 404), for `max_age`; never
/// a refusal that depends on who asked or when (429, 503, a failed upstream).
pub fn cache_control(status: StatusCode, max_age: u32) -> HeaderValue {
    if status.is_success() || status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND {
        HeaderValue::from_str(&format!("public, max-age={max_age}"))
            .unwrap_or(HeaderValue::from_static("no-store"))
    } else {
        HeaderValue::from_static("no-store")
    }
}

/// The origin to allow: the request's own when it is one of `allowed`, else the first.
pub fn allowed_origin(allowed: &[String], headers: &HeaderMap) -> Option<HeaderValue> {
    let asked = headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok());
    let chosen = asked
        .and_then(|asked| allowed.iter().find(|origin| *origin == asked))
        .or_else(|| allowed.first())?;
    HeaderValue::from_str(chosen).ok()
}

/// Who a request is from (`Client`). Behind a proxy (`--client-ip-header`) the peer is the proxy,
/// so a request whose header is missing or does not parse still counts against the proxy, but has
/// no address of its own. A request with no peer (never from `serve`) counts as one shared client.
fn client_of(app: &App, request: &Request) -> Client {
    let peer = request.extensions().get::<Peer>().map(|peer| peer.0.ip());
    let address = match &app.settings.client_ip_header {
        Some(name) => from_header(request.headers(), name),
        None => peer,
    };
    Client {
        counts_as: address
            .or(peer)
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        address,
    }
}

/// The address the proxy's header `name` names, if it is there and parses.
fn from_header(headers: &HeaderMap, name: &HeaderName) -> Option<IpAddr> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allowed_origin_is_echoed_and_any_other_gets_the_first() {
        let allowed = vec![
            "https://tally.example".to_owned(),
            "http://localhost:5175".to_owned(),
        ];
        let with = |origin: Option<&'static str>| {
            let mut headers = HeaderMap::new();
            if let Some(origin) = origin {
                headers.insert(header::ORIGIN, HeaderValue::from_static(origin));
            }
            allowed_origin(&allowed, &headers)
        };
        assert_eq!(
            with(Some("http://localhost:5175")),
            Some(HeaderValue::from_static("http://localhost:5175"))
        );
        for other in [Some("https://evil.example"), None] {
            assert_eq!(
                with(other),
                Some(HeaderValue::from_static("https://tally.example"))
            );
        }
        // With no origin configured, no page on another site may read the API.
        let mut asked = HeaderMap::new();
        asked.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://tally.example"),
        );
        assert_eq!(allowed_origin(&[], &asked), None);
    }

    #[test]
    fn only_answers_and_a_clients_own_mistakes_are_cached() {
        let public = |age| HeaderValue::from_str(&format!("public, max-age={age}")).ok();
        assert_eq!(Some(cache_control(StatusCode::OK, 2)), public(2));
        assert_eq!(Some(cache_control(StatusCode::NOT_FOUND, 15)), public(15));
        assert_eq!(Some(cache_control(StatusCode::BAD_REQUEST, 2)), public(2));
        for status in [
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::BAD_GATEWAY,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert_eq!(
                cache_control(status, 15),
                HeaderValue::from_static("no-store")
            );
        }
    }
}
