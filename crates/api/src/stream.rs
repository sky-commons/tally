//! `GET /v1/aircraft/stream` (RFC-0184 §5): a viewport's aircraft pushed as Server-Sent Events.
//! Each `aircraft` event's data is an `AircraftUpdate`: the first every aircraft in the box
//! (`full`), each later one the aircraft that changed and the addresses that left, at most every
//! `EVERY`; a comment when nothing has been sent for `Settings::stream_heartbeat`, so the edge keeps
//! the stream open. The precise feed changes once a second, and each new second is sent whole.
//!
//! readsb is read once per `READ_EVERY` for every open stream (`Live`): one task reads every
//! aircraft readsb positions and publishes the decoded view on a watch channel each stream reads,
//! cutting out its own box. The task runs only while a stream is open: with none open, a read of
//! the whole world four or five times a second would be work for nobody, and the first viewer waits
//! one read for it. A stream is held to `MAX_PER_CLIENT` open per client (`Open`), the client as the
//! token bucket names it (`routes::client_of`), and sits outside the request deadline and the cap
//! on requests in flight: it lasts as long as its connection.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use tally_api_types::{Aircraft, AircraftUpdate, Feed};
use tally_relay::hub::source_of;
use tokio::sync::watch;

use crate::area::Area;
use crate::routes::{self, Client, Viewport};
use crate::{App, readsb, upstream};

/// Where a stream is opened.
pub const PATH: &str = "/v1/aircraft/stream";
/// The most often a stream sends an event after its first.
pub const EVERY: Duration = Duration::from_millis(250);
/// How often readsb is read while a stream is open: as often as readsb rebuilds its answer
/// (`--write-json-every 0.2`), so no stream is sent a view older than one of readsb's.
pub const READ_EVERY: Duration = Duration::from_millis(200);
/// How long a stream may send nothing before it sends a comment, by default: well inside the
/// edge's idle limit (about 100 s).
pub const HEARTBEAT: Duration = Duration::from_secs(15);
/// The most streams one client holds open at once.
pub const MAX_PER_CLIENT: usize = 4;
/// Beyond this since readsb last answered, a stream is ended rather than left showing an old sky:
/// the client opens another and is told readsb is not answering.
pub const STALE_AFTER: Duration = Duration::from_secs(10);
/// How long a stream's opening waits for readsb's first answer.
const FIRST_READ: Duration = upstream::UPSTREAM_TIMEOUT.saturating_add(Duration::from_secs(1));

/// readsb's positioned aircraft, as of one read.
#[derive(Debug)]
pub struct View {
    /// When it was read.
    pub at: Instant,
    /// readsb's `now`.
    pub now_ms: u64,
    pub aircraft: Vec<Aircraft>,
}

impl View {
    fn fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.at) <= STALE_AFTER
    }
}

type Views = watch::Receiver<Option<Arc<View>>>;

/// The one read of readsb every open stream shares.
pub struct Live {
    views: watch::Sender<Option<Arc<View>>>,
    /// Whether the reading task runs; changed only under this lock, with the count of receivers
    /// looked at under it, so a stream opened as the last one closes is never left unread.
    reading: Mutex<bool>,
}

impl Default for Live {
    fn default() -> Self {
        Self {
            views: watch::Sender::new(None),
            reading: Mutex::new(false),
        }
    }
}

impl Live {
    /// readsb's views, as read from now on: starts the reading task unless it runs.
    fn subscribe(app: &Arc<App>) -> Views {
        let views = app.live.views.subscribe();
        if let Ok(mut reading) = app.live.reading.lock()
            && !*reading
        {
            *reading = true;
            tokio::spawn(read(Arc::clone(app)));
        }
        views
    }
}

/// Reads every aircraft readsb positions every `READ_EVERY` and publishes it, until no stream reads
/// it; then forgets the last view, so the next stream waits for a new one.
async fn read(app: Arc<App>) {
    let url = readsb::all_query(&app.settings.readsb);
    let mut tick = tokio::time::interval(READ_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        {
            let Ok(mut reading) = app.live.reading.lock() else {
                return;
            };
            if app.live.views.receiver_count() == 0 {
                *reading = false;
                app.live.views.send_replace(None);
                return;
            }
        }
        match app
            .upstream
            .get(&url)
            .await
            .and_then(|body| readsb::parse(&body))
        {
            Ok(answer) => {
                let view = View {
                    at: Instant::now(),
                    now_ms: readsb::now_ms(&answer),
                    aircraft: answer.positioned(),
                };
                app.live.views.send_replace(Some(Arc::new(view)));
            }
            Err(error) => eprintln!("tally-api: stream: {error}"),
        }
    }
}

/// The streams each client holds open, by the client as the token bucket names it (an IPv4 address
/// or an IPv6 /64).
#[derive(Default)]
pub struct Open {
    by_client: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

/// One open stream's place in its client's count, given back when the stream is dropped (the
/// client went away, or the stream ended).
pub struct Place {
    by_client: Arc<Mutex<HashMap<IpAddr, usize>>>,
    client: IpAddr,
}

impl Open {
    /// A place for one more stream of `client`, or `None` when it holds `MAX_PER_CLIENT`.
    pub fn take(&self, client: IpAddr) -> Option<Place> {
        let client = source_of(client);
        let mut by_client = self.by_client.lock().ok()?;
        let open = by_client.entry(client).or_default();
        if *open >= MAX_PER_CLIENT {
            return None;
        }
        *open += 1;
        Some(Place {
            by_client: Arc::clone(&self.by_client),
            client,
        })
    }

    /// How many streams `client` holds open.
    pub fn held(&self, client: IpAddr) -> usize {
        self.by_client
            .lock()
            .ok()
            .and_then(|by_client| by_client.get(&source_of(client)).copied())
            .unwrap_or(0)
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        if let Ok(mut by_client) = self.by_client.lock()
            && let Some(open) = by_client.get_mut(&self.client)
        {
            *open = open.saturating_sub(1);
            if *open == 0 {
                by_client.remove(&self.client);
            }
        }
    }
}

/// Whether a client holding `before` must be sent `after`, the same aircraft: its position or
/// when it was heard there, its altitude, speed, track, climb, callsign, source or MLAT quality
/// changed. A message that changed none of these (`last_heard_at_ms` alone) is not sent.
fn changed(before: &Aircraft, after: &Aircraft) -> bool {
    before.position_at_ms != after.position_at_ms
        || before.lat != after.lat
        || before.lon != after.lon
        || before.alt_baro_ft != after.alt_baro_ft
        || before.on_ground != after.on_ground
        || before.gs_kt != after.gs_kt
        || before.track_deg != after.track_deg
        || before.baro_rate_fpm != after.baro_rate_fpm
        || before.flight != after.flight
        || before.position_source != after.position_source
        || before.mlat != after.mlat
}

/// What a client holding `sent` must be told for it to hold `now`: the aircraft that are new or
/// changed (in `now`'s order), and the addresses no longer in it (in order). `sent` becomes `now`.
pub fn changes(
    sent: &mut HashMap<String, Aircraft>,
    now: Vec<Aircraft>,
) -> (Vec<Aircraft>, Vec<String>) {
    let mut held = HashMap::with_capacity(now.len());
    let mut moved = Vec::new();
    for one in now {
        if sent
            .remove(&one.hex)
            .is_none_or(|before| changed(&before, &one))
        {
            moved.push(one.clone());
        }
        held.insert(one.hex.clone(), one);
    }
    let mut gone: Vec<String> = sent.drain().map(|(hex, _)| hex).collect();
    gone.sort_unstable();
    *sent = held;
    (moved, gone)
}

/// One stream: what it reads, and what its client holds.
struct Viewer {
    app: Arc<App>,
    area: Area,
    feed: Feed,
    /// readsb's views, for the live feed; `None` for the precise one, which reads no readsb.
    views: Option<Views>,
    /// What the client holds, by hex.
    sent: HashMap<String, Aircraft>,
    /// The precise second the client holds.
    second: Option<u64>,
    tick: tokio::time::Interval,
    _place: Place,
}

impl Viewer {
    /// The next update to send, waiting for one; `None` when the stream ends (readsb has not
    /// answered for `STALE_AFTER`, or the precise feed is no longer available).
    async fn next(&mut self) -> Option<AircraftUpdate> {
        loop {
            self.tick.tick().await;
            match self.feed {
                Feed::Live => {
                    let view = self.views.as_ref()?.borrow().clone()?;
                    if !view.fresh(Instant::now()) {
                        return None;
                    }
                    let (now_ms, aircraft) = in_view(&self.app, &self.area, &view);
                    let (aircraft, gone) = changes(&mut self.sent, aircraft);
                    if !aircraft.is_empty() || !gone.is_empty() {
                        return Some(update(now_ms, Feed::Live, false, aircraft, gone));
                    }
                }
                Feed::Precise => {
                    let (second, answer) = precise(&self.app, &self.area)?;
                    if self.second != Some(second) {
                        self.second = Some(second);
                        return Some(answer);
                    }
                }
            }
        }
    }
}

/// The live feed's aircraft in `area` from `view`: readsb's, then those only Tally MLAT places,
/// as `/v1/aircraft` answers them.
fn in_view(app: &App, area: &Area, view: &View) -> (u64, Vec<Aircraft>) {
    let readsb = view
        .aircraft
        .iter()
        .filter(|one| area.contains(one.lat, one.lon))
        .cloned()
        .collect();
    routes::live_answer(app, area, view.now_ms, readsb)
}

/// The precise feed's newest second in `area` as a full update, or `None` when unavailable.
fn precise(app: &App, area: &Area) -> Option<(u64, AircraftUpdate)> {
    let (second, served) =
        app.mlat
            .precise_in_area(area, routes::wall_ms(), app.settings.mlat.max_age)?;
    let answer = routes::precise_answer(&served, second.saturating_mul(1_000), routes::wall_ms());
    Some((
        second,
        update(
            answer.now_ms,
            Feed::Precise,
            true,
            answer.aircraft,
            Vec::new(),
        ),
    ))
}

/// An update sent now.
pub fn update(
    now_ms: u64,
    feed: Feed,
    full: bool,
    aircraft: Vec<Aircraft>,
    gone: Vec<String>,
) -> AircraftUpdate {
    AircraftUpdate {
        now_ms,
        sent_at_ms: routes::wall_ms(),
        feed,
        full,
        aircraft,
        gone,
    }
}

/// An update as the stream's `aircraft` event.
fn event(update: &AircraftUpdate) -> Result<Event, axum::Error> {
    Event::default().event("aircraft").json_data(update)
}

/// `GET /v1/aircraft/stream`: the viewport checked as `/v1/aircraft` checks it, a place among the
/// client's streams, and the first, full, update (readsb answering, or a precise second held)
/// before the stream's `200`, so a client that cannot be served is told why in its status.
pub async fn open(
    State(app): State<Arc<App>>,
    Extension(Client(client)): Extension<Client>,
    viewport: Result<Query<Viewport>, QueryRejection>,
) -> Response {
    let (area, feed) = match routes::viewport(viewport) {
        Ok(asked) => asked,
        Err(why) => return routes::refuse(StatusCode::BAD_REQUEST, &why),
    };
    let Some(place) = app.streams.take(client) else {
        let mut response = routes::refuse(
            StatusCode::TOO_MANY_REQUESTS,
            "too many streams open from this address",
        );
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(HEARTBEAT.as_secs()));
        return response;
    };
    let mut viewer = Viewer {
        area,
        feed,
        views: None,
        sent: HashMap::new(),
        second: None,
        tick: tokio::time::interval_at(tokio::time::Instant::now() + EVERY, EVERY),
        _place: place,
        app: Arc::clone(&app),
    };
    viewer
        .tick
        .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let first = match feed {
        Feed::Live => {
            let mut views = Live::subscribe(&app);
            let view = match tokio::time::timeout(
                FIRST_READ,
                views.wait_for(|view| view.as_ref().is_some_and(|view| view.fresh(Instant::now()))),
            )
            .await
            {
                Ok(Ok(view)) => view.clone(),
                _ => None,
            };
            let Some(view) = view else {
                return routes::refuse(StatusCode::BAD_GATEWAY, "readsb did not answer");
            };
            viewer.views = Some(views);
            let (now_ms, aircraft) = in_view(&app, &area, &view);
            viewer.sent = aircraft
                .iter()
                .map(|one| (one.hex.clone(), one.clone()))
                .collect();
            update(now_ms, Feed::Live, true, aircraft, Vec::new())
        }
        Feed::Precise => {
            let Some((second, first)) = precise(&app, &area) else {
                return routes::refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    routes::PRECISE_UNAVAILABLE,
                );
            };
            viewer.second = Some(second);
            first
        }
    };
    let events =
        futures_util::stream::unfold((Some(first), viewer), |(first, mut viewer)| async move {
            let update = match first {
                Some(first) => first,
                None => viewer.next().await?,
            };
            Some((event(&update), (None, viewer)))
        });
    Sse::new(events)
        .keep_alive(KeepAlive::new().interval(app.settings.stream_heartbeat))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tally_api_types::PositionSource;

    fn one(hex: &str, position_at_ms: u64) -> Aircraft {
        Aircraft {
            hex: hex.to_owned(),
            flight: None,
            lat: 37.5,
            lon: -122.25,
            alt_baro_ft: Some(35_000),
            gs_kt: Some(450.0),
            track_deg: Some(270.0),
            baro_rate_fpm: Some(0),
            on_ground: false,
            last_heard_at_ms: position_at_ms,
            position_at_ms,
            position_source: PositionSource::Adsb,
            mlat: None,
        }
    }

    /// A client is sent what is new or changed and told what left; a message that changed nothing
    /// the client draws (heard again, nothing else) is not sent.
    #[test]
    fn a_delta_is_what_changed_and_what_left() {
        let mut sent = HashMap::new();
        let (aircraft, gone) = changes(&mut sent, vec![one("a", 1), one("b", 1), one("c", 1)]);
        assert_eq!((aircraft.len(), gone.len()), (3, 0));
        let heard_again = Aircraft {
            last_heard_at_ms: 2,
            ..one("a", 1)
        };
        let climbing = Aircraft {
            baro_rate_fpm: Some(640),
            ..one("b", 1)
        };
        let (aircraft, gone) = changes(&mut sent, vec![heard_again, climbing.clone(), one("d", 2)]);
        assert_eq!(aircraft, vec![climbing, one("d", 2)]);
        assert_eq!(gone, ["c"]);
        // Nothing changed: nothing to send.
        let same = sent.values().cloned().collect();
        let (aircraft, gone) = changes(&mut sent, same);
        assert!(aircraft.is_empty() && gone.is_empty());
        let mut each = [
            Aircraft {
                position_at_ms: 9,
                ..one("a", 1)
            },
            Aircraft {
                flight: Some("UAL1".to_owned()),
                ..one("a", 1)
            },
            Aircraft {
                position_source: PositionSource::Tisb,
                ..one("a", 1)
            },
            Aircraft {
                alt_baro_ft: None,
                on_ground: true,
                ..one("a", 1)
            },
            Aircraft {
                gs_kt: None,
                ..one("a", 1)
            },
            Aircraft {
                track_deg: Some(90.0),
                ..one("a", 1)
            },
        ]
        .into_iter();
        assert!(each.all(|after| changed(&one("a", 1), &after)));
    }

    /// A client holds at most `MAX_PER_CLIENT` streams, an IPv6 /64 being one client, and a stream
    /// dropped gives its place back.
    #[test]
    fn a_client_holds_at_most_four_streams() {
        let open = Open::default();
        let host = |n: u16| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n));
        let places: Vec<Place> = (1..=4).filter_map(|n| open.take(host(n))).collect();
        assert_eq!(places.len(), 4);
        assert!(open.take(host(5)).is_none());
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(open.take(other).is_some());
        drop(places);
        assert_eq!(open.held(host(1)), 0);
        assert!(open.take(host(1)).is_some());
    }
}
