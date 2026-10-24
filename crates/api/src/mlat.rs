//! MLAT positions (RFC-0171 §3.8.1): the API subscribes to the positions and clock model streams
//! of every relay its operator names, as any client does, merges them by the one client merge rule
//! (`tally_merge`), and serves the merged position of an aircraft readsb holds no ADS-B position
//! for. The merge runs on a thread of its own; what requests read is the snapshot it publishes,
//! every aircraft's current fix. The same subscription carries the relays' signed feeder figures
//! (`crate::feeders`).
//!
//! A client holds no raw (wire version 3): a fix's check is its engine's signature, and its
//! confidence is unconfirmed, since standing is a relay's ledger, not a client's.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tally_api_types::{Aircraft, Mlat, MlatCheck, MlatConfidence, MlatKind, PositionSource};
use tally_merge::{Kind, Merge};
use tally_wire::{ClientRecord, Identity, PublicKey, RelayAddress};
use tokio::sync::mpsc;

use crate::area::Area;
use crate::feeders::{LatLon, Ledger};

/// How old an MLAT position may be and still be served, by default: readsb's own horizon for an
/// aircraft it has stopped hearing.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60);
/// How often the snapshot requests read is rebuilt while records arrive.
const PUBLISH_EVERY: Duration = Duration::from_millis(500);
/// Records waiting for the merge; beyond it a relay's session waits.
const INBOUND: usize = 4_096;
/// The nearest in time two fixes of an aircraft may be for its velocity to be taken from them:
/// closer, their uncertainty swamps the distance between them.
pub const VELOCITY_MIN_SPAN_MS: u64 = 1_000;
/// The furthest apart: beyond it the aircraft may have turned between them.
pub const VELOCITY_MAX_SPAN_MS: u64 = 60_000;
/// Metres a second in a knot (an international nautical mile, 1852 m, an hour).
const KNOTS_PER_M_S: f64 = 3_600.0 / 1_852.0;
// How far past the API's own clock a precise world second's seal may be and still be taken is
// `tally_wire::budget::PRODUCT_AHEAD`: the skew between a relay's clock and the API's, which holds
// only while the API's own clock is bounded (ClockBound's bound, checked before the API relies on
// it). A precise second is sealed once every final fix of it has surely arrived
// (`tally_wire::products::FINAL_FIX_ARRIVED_MS` after it ends, by its relay's clock), so an honest
// one's seal is never further ahead of the API's clock than the skew; one further ahead is a
// relay's lie, which would otherwise hold the feed at its second and refuse every honest one after
// it.

/// What the operator chose.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// The relays to subscribe to; none serves no MLAT.
    pub relays: Vec<RelayAddress>,
    pub max_age: Duration,
    /// The relay that vouches for this client's key (`--linked-relay`, one of `relays`): the
    /// firehose credential it signs is presented to every relay read.
    pub linked: Option<RelayAddress>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            max_age: DEFAULT_MAX_AGE,
            linked: None,
        }
    }
}

/// One aircraft's merged position, as served.
#[derive(Clone, Debug, PartialEq)]
pub struct Served {
    pub address: u32,
    pub lat: f64,
    pub lon: f64,
    pub altitude_ft: Option<i32>,
    pub horizontal_sigma_m: f64,
    pub check: MlatCheck,
    pub kind: MlatKind,
    pub confidence: MlatConfidence,
    pub contested: bool,
    /// MLAT, or (in the precise world feed) the aircraft's own broadcast.
    pub source: PositionSource,
    pub transmitted_ms: u64,
    /// Ground speed and track over the ground from the fix served before this one of the same
    /// aircraft (`velocity`); `None` without one that qualifies.
    pub gs_kt: Option<f64>,
    pub track_deg: Option<f64>,
}

impl Served {
    /// The hex readsb names the aircraft by.
    pub fn hex(&self) -> String {
        format!("{:06x}", self.address)
    }

    /// The public form: the position and what is known of it, nothing readsb would have said.
    pub fn aircraft(&self) -> Aircraft {
        Aircraft {
            hex: self.hex(),
            flight: None,
            lat: self.lat,
            lon: self.lon,
            alt_baro_ft: self.altitude_ft,
            gs_kt: self.gs_kt,
            track_deg: self.track_deg,
            baro_rate_fpm: None,
            on_ground: false,
            last_heard_at_ms: self.transmitted_ms,
            position_at_ms: self.transmitted_ms,
            position_source: self.source,
            mlat: (self.source == PositionSource::Mlat).then_some(Mlat {
                horizontal_sigma_m: self.horizontal_sigma_m,
                check: self.check,
                kind: self.kind,
                confidence: self.confidence,
                contested: self.contested,
            }),
        }
    }
}

/// Every aircraft's served fix: its latest final one, or a provisional one later than that
/// (`tally_merge::Track::served`).
pub fn served(merge: &Merge) -> Vec<Served> {
    merge
        .tracks()
        .into_iter()
        .filter_map(|track| track.served().map(|fix| (track, fix)))
        .map(|(track, fix)| {
            // Contested: a superset of the fix's transmission disagreed with it.
            let contested = track.transmissions.iter().any(|transmission| {
                transmission.is_contested()
                    && transmission
                        .fixes
                        .iter()
                        .any(|held| held.input_set == fix.input_set)
            });
            Served {
                address: fix.address,
                // Divided, not multiplied by 1e-7: the nearest double to the decimal, which JSON
                // then writes in as few digits as it has.
                lat: f64::from(fix.lat_e7) / 1e7,
                lon: f64::from(fix.lon_e7) / 1e7,
                altitude_ft: fix.altitude_ft,
                horizontal_sigma_m: fix.horizontal_sigma_m,
                // A client verifies a fix by its engine's signature: the model and resolved
                // checks need raw, which is relay-only.
                check: MlatCheck::Signature,
                kind: match fix.kind {
                    Kind::Final => MlatKind::Final,
                    Kind::Provisional => MlatKind::Provisional,
                },
                // Standing is a relay's ledger, kept from raw a client never holds.
                confidence: MlatConfidence::Unconfirmed,
                contested,
                source: PositionSource::Mlat,
                transmitted_ms: fix.transmitted.unix_ms,
                gs_kt: None,
                track_deg: None,
            }
        })
        .collect()
}

/// The ground speed (knots) and track (degrees true) of an aircraft that moved from `before` to
/// `after`, two fixes of it: along the great circle between them, the speed its length over their
/// time apart and the track its initial bearing. `None` unless both are MLAT fixes and they are
/// `VELOCITY_MIN_SPAN_MS` to `VELOCITY_MAX_SPAN_MS` apart; no track when they are at one place.
pub fn velocity(before: &Served, after: &Served) -> Option<(f64, Option<f64>)> {
    let mlat = |one: &Served| one.source == PositionSource::Mlat;
    if !mlat(before) || !mlat(after) || before.address != after.address {
        return None;
    }
    let span_ms = after.transmitted_ms.checked_sub(before.transmitted_ms)?;
    if !(VELOCITY_MIN_SPAN_MS..=VELOCITY_MAX_SPAN_MS).contains(&span_ms) {
        return None;
    }
    let (from, to) = (
        LatLon {
            lat: before.lat,
            lon: before.lon,
        },
        LatLon {
            lat: after.lat,
            lon: after.lon,
        },
    );
    let metres = from.distance_m(to);
    let gs_kt = metres / (span_ms as f64 / 1_000.0) * KNOTS_PER_M_S;
    let track = (metres > 0.0).then(|| from.bearing_deg(to));
    Some((gs_kt, track))
}

/// The newest whole second of the precise world product held: the second (Unix seconds) and its
/// aircraft.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Precise {
    pub second: u64,
    pub served: Arc<Vec<Served>>,
}

/// What requests read: the latest snapshot of the live feed (the merge's), each aircraft moving
/// by its last two served fixes, and the newest whole second of the precise world product, if any
/// has come.
#[derive(Default)]
pub struct Positions {
    served: RwLock<Arc<Vec<Served>>>,
    /// Each aircraft's fix served before its current one, of an earlier transmission: what its
    /// velocity is taken from.
    before: Mutex<HashMap<u32, Served>>,
    precise: RwLock<Option<Precise>>,
}

impl Positions {
    /// Serves `served`, the merge's current fixes, each with its velocity from the fix of the same
    /// aircraft served before it: a fix of a later transmission than the one held makes the held
    /// one the earlier; one of the same transmission (a final replacing a provisional) replaces it
    /// and keeps the earlier; one of an earlier transmission (a provisional retracted) keeps only an
    /// earlier fix still before it. An aircraft no longer served is forgotten.
    pub fn set(&self, mut served: Vec<Served>) {
        let Ok(mut held) = self.served.write() else {
            return;
        };
        let Ok(mut before) = self.before.lock() else {
            return;
        };
        let current: HashMap<u32, &Served> = held.iter().map(|one| (one.address, one)).collect();
        let mut next = HashMap::with_capacity(served.len());
        for one in &mut served {
            let earlier = match current.get(&one.address) {
                Some(now) if now.transmitted_ms < one.transmitted_ms => Some((*now).clone()),
                _ => before
                    .remove(&one.address)
                    .filter(|earlier| earlier.transmitted_ms < one.transmitted_ms),
            };
            let (gs_kt, track_deg) =
                match earlier.as_ref().and_then(|earlier| velocity(earlier, one)) {
                    Some((gs_kt, track_deg)) => (Some(gs_kt), track_deg),
                    None => (None, None),
                };
            (one.gs_kt, one.track_deg) = (gs_kt, track_deg);
            if let Some(earlier) = earlier {
                next.insert(one.address, earlier);
            }
        }
        *before = next;
        *held = Arc::new(served);
    }

    /// Every live position no older than `max_age` before `now_ms`, in address order.
    pub fn current(&self, now_ms: u64, max_age: Duration) -> Vec<Served> {
        let Ok(held) = self.served.read() else {
            return Vec::new();
        };
        let oldest = now_ms.saturating_sub(u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX));
        held.iter()
            .filter(|one| one.transmitted_ms >= oldest)
            .cloned()
            .collect()
    }

    pub fn set_precise(&self, second: u64, served: Vec<Served>) {
        if let Ok(mut held) = self.precise.write() {
            *held = Some(Precise {
                second,
                served: Arc::new(served),
            });
        }
    }

    /// The precise world feed in `area`: its newest second and the aircraft of it there, or
    /// `None` when there is no precise product to serve (none has come, or the newest is older
    /// than `max_age` before `now_ms` beyond the feed's own delay of about a minute and a half).
    /// A product held with no aircraft in `area` is an answer, not an absence.
    pub fn precise_in_area(
        &self,
        area: &Area,
        now_ms: u64,
        max_age: Duration,
    ) -> Option<(u64, Vec<Served>)> {
        let held = self.precise.read().ok()?.clone()?;
        let behind = tally_relay::products::WORLD_PRECISE_SETTLE_MS;
        let oldest = now_ms.saturating_sub(max_age.as_millis() as u64 + behind);
        if held.second.saturating_add(1).saturating_mul(1_000) < oldest {
            return None;
        }
        let served = held
            .served
            .iter()
            .filter(|one| one.transmitted_ms >= oldest && area.contains(one.lat, one.lon))
            .cloned()
            .collect();
        Some((held.second, served))
    }

    /// The positions in `area` no older than `max_age` before `now_ms`, in address order.
    pub fn in_area(&self, area: &Area, now_ms: u64, max_age: Duration) -> Vec<Served> {
        let Ok(held) = self.served.read() else {
            return Vec::new();
        };
        let oldest = now_ms.saturating_sub(u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX));
        held.iter()
            .filter(|one| one.transmitted_ms >= oldest && area.contains(one.lat, one.lon))
            .cloned()
            .collect()
    }
}

/// Subscribes to every relay and keeps `positions` and the feeder figures current, for as long as
/// the API runs.
pub fn start(
    settings: &Settings,
    clock: Clock,
    identity: Identity,
    positions: Arc<Positions>,
    feeders: Arc<Mutex<Ledger>>,
) -> Result<(), String> {
    if settings.relays.is_empty() {
        return Ok(());
    }
    // One vouching shared by every session: what the linked relay signs is presented to all.
    let vouching = match &settings.linked {
        Some(linked) => tally_merge::link::Vouching::linked_to(linked.key),
        None => tally_merge::link::Vouching::none(),
    };
    let (inbound, mut records) = mpsc::channel::<ClientRecord>(INBOUND);
    // What the merge reads, the relays' feeder figures among it; and the precise world product,
    // for the precise feed. No raw: it is relay-only.
    let streams = tally_merge::link::streams().with(tally_wire::Streams::WORLD_PRECISE);
    // The API's key only handshakes: as a subscriber it signs nothing.
    let identity = tally_wire::NoiseKey::of(identity);
    for relay in &settings.relays {
        tokio::spawn(tally_merge::link::subscribe_vouched(
            relay.clone(),
            identity.clone(),
            streams,
            inbound.clone(),
            vouching.clone(),
        ));
    }
    // The precise feed takes a part only from a relay it subscribes to.
    let relays: Vec<PublicKey> = settings.relays.iter().map(|relay| relay.key).collect();
    // The merge's checks and fits are computation, not I/O: a thread of their own.
    tokio::task::spawn_blocking(move || {
        let mut merge = Merge::new(tally_merge::Settings::default());
        let mut published = std::time::Instant::now();
        let mut dirty = false;
        let mut precise = PreciseWorld::of(relays);
        while let Some(record) = records.blocking_recv() {
            let now = clock.now();
            match &record {
                ClientRecord::WorldPrecise(world) => {
                    if precise.take(world, now) {
                        positions.set_precise(precise.second, precise.served());
                    }
                }
                ClientRecord::FeederFigures(figures) => {
                    if let Ok(mut ledger) = feeders.lock() {
                        ledger.ingest(figures, now);
                    }
                }
                // A provisional fix's deadline is a span, measured on the monotonic clock.
                _ => match merge.ingest(&record, now.mono()) {
                    Ok(_) => dirty = true,
                    Err(error) => eprintln!("tally-api: mlat: {error}"),
                },
            }
            if dirty && (records.is_empty() || published.elapsed() >= PUBLISH_EVERY) {
                positions.set(served(&merge));
                published = std::time::Instant::now();
                dirty = false;
            }
        }
    });
    Ok(())
}

/// The newest second of the precise world product, as its parts arrive: every part of one second
/// signed by one relay the API subscribes to, a newer second replacing it.
struct PreciseWorld {
    /// The relays it takes a part from: those it subscribes to, by key.
    relays: std::collections::BTreeSet<PublicKey>,
    second: u64,
    signer: Option<PublicKey>,
    fixes: std::collections::BTreeMap<u32, tally_wire::WorldFix>,
}

impl PreciseWorld {
    /// Takes parts signed by `relays` alone.
    fn of(relays: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            relays: relays.into_iter().collect(),
            second: 0,
            signer: None,
            fixes: std::collections::BTreeMap::new(),
        }
    }

    /// Takes a part, if it verifies, is signed by a relay the API subscribes to, could have been
    /// sealed by a clock within `PRODUCT_AHEAD` (`K`) of the API's (a precise second `s` is sealed no earlier than
    /// `(s + 1) * 1000 + FINAL_FIX_ARRIVED` by its relay's judging clock,
    /// `tally_wire::products::FINAL_FIX_ARRIVED_MS`), and is of the newest second (from the relay
    /// that signed the second's first part seen): true when what is held changed. None is taken
    /// while the API's clock does not judge (`Clock`): `K` holds only of clocks within `E`, and a
    /// lying relay's second far ahead would otherwise hold the feed. Before, the second's start
    /// was judged against `K`, which let a second some 110 s ahead of any honest relay's seal hold
    /// the feed, and a part signed by any key at all was taken.
    fn take(&mut self, world: &tally_wire::WorldPrecise, now: Now) -> bool {
        if !now.judging() {
            return false;
        }
        let (Ok(()), Ok(signer), Ok(content)) = (world.verify(), world.signer(), world.content())
        else {
            return false;
        };
        let sealed_ms = content
            .second
            .saturating_add(1)
            .saturating_mul(1_000)
            .saturating_add(tally_wire::products::FINAL_FIX_ARRIVED_MS);
        if !self.relays.contains(&signer)
            || tally_wire::budget::PRODUCT_AHEAD.ahead(sealed_ms, now.judged())
            || content.second < self.second
            || (content.second == self.second && self.signer.is_some_and(|held| held != signer))
        {
            return false;
        }
        if content.second > self.second {
            self.second = content.second;
            self.signer = Some(signer);
            self.fixes.clear();
        }
        for fix in content.fixes {
            self.fixes.insert(fix.address, fix);
        }
        true
    }

    fn served(&self) -> Vec<Served> {
        self.fixes
            .values()
            .map(|fix| Served {
                address: fix.address,
                lat: f64::from(fix.lat_e7) / 1e7,
                lon: f64::from(fix.lon_e7) / 1e7,
                altitude_ft: fix.pressure_altitude_ft,
                horizontal_sigma_m: tally_merge::horizontal_sigma_m(&fix.covariance),
                check: MlatCheck::Signature,
                kind: MlatKind::Final,
                confidence: MlatConfidence::Unconfirmed,
                contested: false,
                source: if fix.mlat {
                    PositionSource::Mlat
                } else {
                    PositionSource::Adsb
                },
                transmitted_ms: fix.transmitted.unix_ms,
                gs_kt: None,
                track_deg: None,
            })
            .collect()
    }
}

/// The API host's clock as it judges signed times: its wall clock, and whether the host's
/// ClockBound says it is synchronised now within `budget::E` (`tally_wire::clock_bound`, the one
/// reader and the one judgement of its word every end shares), read at each reading. What
/// `PRODUCT_AHEAD` and `K` are derived from is every judging clock within `E` of true time, so the
/// API relies on them only by a reading ClockBound vouched for: a host without ClockBound, or one
/// it says is not synchronised or bounds past `E`, judges nothing, and its reader counts each such
/// read by why (`tally_wire::clock_bound::Reader::health`). The bound is only as honest as chrony
/// and ClockBound are (RFC-0171 §3.6). And its monotonic clock, which every span it waits out is
/// measured on (a provisional fix's deadline, `tally_merge`): a step of the wall clock never
/// shortens one.
#[derive(Clone)]
pub struct Clock {
    mono: tally_wire::clocks::MonoReader,
    judged: tally_wire::clocks::JudgedReader,
    judging: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clock").finish_non_exhaustive()
    }
}

/// The host's wall clock read as the API's judging clock: the one place a reading of it is made.
#[allow(
    clippy::disallowed_methods,
    reason = "the API's reader of its host's wall clock: a reading is made where the clock is read"
)]
fn wall() -> tally_wire::clocks::Judged {
    tally_wire::clocks::recorded::judged(crate::routes::wall_ms())
}

/// The host's monotonic clock read as the API's, from `started`: the one place a reading of it is
/// made.
#[allow(
    clippy::disallowed_methods,
    reason = "the API's reader of its host's monotonic clock: a reading is made where the clock is read"
)]
fn monotonic(started: std::time::Instant) -> tally_wire::clocks::Mono {
    tally_wire::clocks::recorded::mono(
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    )
}

/// A test's script read as the API's monotonic clock.
#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
fn scripted_mono(ms: u64) -> tally_wire::clocks::Mono {
    tally_wire::clocks::recorded::mono(ms)
}

/// A test's script read as the API's judging clock.
#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
fn scripted(ms: u64) -> tally_wire::clocks::Judged {
    tally_wire::clocks::recorded::judged(ms)
}

impl Clock {
    /// The host's: its wall clock, judged by its ClockBound's word on it.
    pub fn system() -> Self {
        let started = std::time::Instant::now();
        Self {
            mono: tally_wire::clocks::MonoReader::of(move || monotonic(started)),
            judged: tally_wire::clocks::JudgedReader::of(wall),
            judging: std::sync::Arc::new(|| tally_wire::clock_bound::Reader::host().read().is_ok()),
        }
    }

    /// A test's: the host's clocks, judging as if its ClockBound said synchronised, since no test
    /// host runs ClockBound. An API's is [`Clock::system`]. Clippy refuses it outside a test
    /// (`clippy.toml`), so no API judges by it.
    pub fn host_stated() -> Self {
        Self {
            judging: std::sync::Arc::new(|| true),
            ..Self::system()
        }
    }

    /// A test's: both its clocks read `read`, and it judges as `judging` says.
    #[cfg(test)]
    pub fn scripted(
        read: impl Fn() -> u64 + Send + Sync + 'static,
        judging: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        let read = std::sync::Arc::new(read);
        let mono = std::sync::Arc::clone(&read);
        Self {
            mono: tally_wire::clocks::MonoReader::of(move || scripted_mono(mono())),
            judged: tally_wire::clocks::JudgedReader::of(move || scripted(read())),
            judging: std::sync::Arc::new(judging),
        }
    }

    /// The clock now, with whether it judges.
    pub fn now(&self) -> Now {
        Now {
            mono: self.mono.read(),
            judged: self.judged.read(),
            judging: (self.judging)(),
        }
    }
}

/// A reading of the API's clock and whether it judged as it was read (`Clock::now`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    mono: tally_wire::clocks::Mono,
    judged: tally_wire::clocks::Judged,
    judging: bool,
}

impl Now {
    /// The monotonic reading: what a span waited out is measured on.
    pub const fn mono(self) -> tally_wire::clocks::Mono {
        self.mono
    }

    /// The reading.
    pub const fn judged(self) -> tally_wire::clocks::Judged {
        self.judged
    }

    /// Whether ClockBound bounded the clock within `E` as it was read.
    pub const fn judging(self) -> bool {
        self.judging
    }

    /// A test's reading `ms`, judging or not.
    #[cfg(test)]
    #[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
    pub const fn at(ms: u64, judging: bool) -> Self {
        Self {
            mono: tally_wire::clocks::recorded::mono(ms),
            judged: tally_wire::clocks::recorded::judged(ms),
            judging,
        }
    }
}

/// The aircraft answer for a viewport: readsb's, each at its ADS-B position, then the MLAT
/// position of every aircraft in the viewport readsb gave no position for.
pub fn answer(adsb: Vec<Aircraft>, mlat: &[Served]) -> Vec<Aircraft> {
    let heard: std::collections::HashSet<String> =
        adsb.iter().map(|aircraft| aircraft.hex.clone()).collect();
    let mut aircraft = adsb;
    aircraft.extend(
        mlat.iter()
            .filter(|one| !heard.contains(&one.hex()))
            .map(Served::aircraft),
    );
    aircraft
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(address: u32, lat: f64, transmitted_ms: u64) -> Served {
        Served {
            address,
            lat,
            lon: 5.0,
            altitude_ft: None,
            horizontal_sigma_m: 30.0,
            check: MlatCheck::Signature,
            kind: MlatKind::Final,
            confidence: MlatConfidence::Unconfirmed,
            contested: false,
            source: PositionSource::Mlat,
            transmitted_ms,
            gs_kt: None,
            track_deg: None,
        }
    }

    #[test]
    fn a_provisional_position_says_so() -> Result<(), String> {
        let early = Served {
            kind: MlatKind::Provisional,
            ..one(0xc0ffee, 52.0, 1)
        };
        let json = serde_json::to_value(early.aircraft()).map_err(|e| e.to_string())?;
        assert_eq!(json["mlat"]["kind"], "provisional");
        assert_eq!(json["position_source"], "mlat");
        Ok(())
    }

    #[test]
    fn a_position_is_served_inside_its_viewport_and_within_its_age() -> Result<(), String> {
        let positions = Positions::default();
        positions.set(vec![
            one(1, 52.0, 100_000),
            one(2, 52.0, 30_000),
            one(3, 60.0, 100_000),
        ]);
        let area = Area::new(4.0, 51.0, 6.0, 53.0)?;
        let served = positions.in_area(&area, 110_000, Duration::from_secs(60));
        assert_eq!(
            served.iter().map(|one| one.address).collect::<Vec<_>>(),
            [1]
        );
        Ok(())
    }

    /// One part of the precise world at `second`, signed by `signer`, with one fix of `address`.
    fn precise(
        signer: &Identity,
        second: u64,
        address: u32,
    ) -> Result<tally_wire::WorldPrecise, String> {
        let fix = tally_wire::WorldFix {
            address,
            transmitted: tally_wire::TransmitTime {
                unix_ms: second * 1_000 + 100,
                sub_ms_ps: 0,
            },
            lat_e7: 520_000_000,
            lon_e7: 50_000_000,
            alt_hae_mm: None,
            pressure_altitude_ft: None,
            covariance: tally_wire::EnuCovariance {
                xx: 100.0,
                xy: 0.0,
                xz: 0.0,
                yy: 100.0,
                yz: 0.0,
                zz: 100.0,
            },
            provisional: false,
            mlat: true,
            input_set: [3; 32],
            source: signer.public(),
            origin: [4; 32],
            origin_index: 0,
        };
        tally_wire::WorldPrecise::sign(
            signer,
            &tally_wire::WorldPositionsContent {
                second,
                part: 0,
                fixes: vec![fix],
            },
        )
        .map_err(|error| error.to_string())
    }

    /// A precise second sealed further ahead than `K` is a relay's lie: its seal, `(s + 1) * 1000 +
    /// FINAL_FIX_ARRIVED` by the relay's clock, is judged against the skew, never its start, so a
    /// second one past the latest an honest relay `K` ahead can have sealed is refused, and it does
    /// not hold the feed against the honest seconds after it. While the API's clock does not judge
    /// (ClockBound bounds it past `E`, or not at all), nothing is taken, an honest second neither:
    /// `K` holds only of clocks within `E`.
    #[test]
    fn a_precise_second_from_the_future_is_refused() -> Result<(), String> {
        let now_ms = 1_791_220_000_000;
        let now = Now::at(now_ms, true);
        let skew = tally_wire::budget::PRODUCT_AHEAD
            .span::<tally_wire::clocks::Judged>()
            .ms();
        let liar = Identity::from_seed([1; 32]);
        let honest = Identity::from_seed([2; 32]);
        let mut held = PreciseWorld::of([liar.public(), honest.public()]);
        // The latest second a relay whose clock is `K` ahead has sealed.
        let latest = (now_ms + skew - tally_wire::products::FINAL_FIX_ARRIVED_MS) / 1_000 - 1;
        assert!(!held.take(&precise(&liar, latest + 1, 0xbad)?, now));
        assert!(!held.take(
            &precise(&liar, now_ms / 1_000 + 10 * 365 * 86_400, 0xbad)?,
            now
        ));
        let second = now_ms / 1_000 - 109;
        assert!(!held.take(&precise(&honest, second, 0xc0ffee)?, Now::at(now_ms, false)));
        assert_eq!(held.second, 0);
        assert!(held.take(&precise(&honest, second, 0xc0ffee)?, now));
        assert_eq!(held.second, second);
        assert_eq!(
            held.served()
                .iter()
                .map(|one| one.address)
                .collect::<Vec<_>>(),
            [0xc0ffee]
        );
        // Sealed within the skew is taken: the relay's clock may be up to `K` ahead of the API's.
        assert!(held.take(&precise(&honest, latest, 0xabc)?, now));
        // A scripted clock judges as its ClockBound says.
        let clock = Clock::scripted(move || now_ms, || false);
        assert_eq!(clock.now(), Now::at(now_ms, false));
        Ok(())
    }

    /// The precise feed takes a part only from a relay the API subscribes to: one signed by any
    /// other key, however well formed and timely, is refused. Before, any signer was taken, so
    /// anyone reaching a relay's stream could hold the feed with a second of their own.
    #[test]
    fn a_precise_part_from_a_relay_not_subscribed_to_is_refused() -> Result<(), String> {
        let now_ms = 1_791_220_000_000;
        let now = Now::at(now_ms, true);
        let known = Identity::from_seed([3; 32]);
        let stranger = Identity::from_seed([4; 32]);
        let mut held = PreciseWorld::of([known.public()]);
        let second = now_ms / 1_000 - 109;
        assert!(!held.take(&precise(&stranger, second, 0xbad)?, now));
        assert_eq!(held.second, 0);
        assert!(held.take(&precise(&known, second, 0xc0ffee)?, now));
        Ok(())
    }

    /// No precise product, or only a stale one, is no answer (the route's `503`); a recent one
    /// with nobody in the viewport is an empty answer.
    #[test]
    fn the_precise_feed_is_unavailable_without_a_recent_product() -> Result<(), String> {
        let positions = Positions::default();
        let area = Area::new(4.0, 51.0, 6.0, 53.0)?;
        let elsewhere = Area::new(-10.0, 30.0, -8.0, 32.0)?;
        let max_age = Duration::from_secs(60);
        let now_ms = 1_791_220_000_000;
        assert_eq!(positions.precise_in_area(&area, now_ms, max_age), None);
        let second = now_ms / 1_000 - 91;
        positions.set_precise(second, vec![one(7, 52.0, second * 1_000 + 100)]);
        let (got, served) = positions
            .precise_in_area(&area, now_ms, max_age)
            .ok_or("unavailable")?;
        assert_eq!((got, served.len()), (second, 1));
        assert_eq!(
            positions.precise_in_area(&elsewhere, now_ms, max_age),
            Some((second, Vec::new()))
        );
        // Ten minutes on, nothing newer has come: unavailable.
        assert_eq!(
            positions.precise_in_area(&area, now_ms + 600_000, max_age),
            None
        );
        Ok(())
    }

    /// The velocity of what `positions` serves of `address`.
    fn moving(positions: &Positions, address: u32) -> Option<(Option<f64>, Option<f64>)> {
        positions
            .current(0, Duration::MAX)
            .into_iter()
            .find(|one| one.address == address)
            .map(|one| (one.gs_kt, one.track_deg))
    }

    /// An MLAT aircraft moves by its last two served fixes: ground speed along the great circle
    /// between them over their time apart, track its initial bearing.
    #[test]
    fn an_mlat_aircraft_moves_by_its_last_two_served_fixes() -> Result<(), String> {
        let positions = Positions::default();
        positions.set(vec![one(1, 52.0, 100_000)]);
        // One fix: nothing to move by.
        assert_eq!(moving(&positions, 1), Some((None, None)));
        // A hundredth of a degree north in ten seconds.
        positions.set(vec![one(1, 52.01, 110_000)]);
        let (gs, track) = moving(&positions, 1).ok_or("not served")?;
        let expected = 0.01_f64.to_radians() * 6_371_008.8 / 10.0 * 3_600.0 / 1_852.0;
        assert!((gs.ok_or("no speed")? - expected).abs() < 1e-6, "{gs:?}");
        assert!(track.ok_or("no track")?.abs() < 1e-6, "{track:?}");
        // A fix of the same transmission (a final replacing a provisional) replaces it: the
        // velocity is still taken from the fix before.
        positions.set(vec![one(1, 52.01, 110_000), one(2, 52.0, 110_000)]);
        let (_, track) = moving(&positions, 1).ok_or("not served")?;
        assert!(track.ok_or("no track")?.abs() < 1e-6);
        // Republished unchanged: the same velocity, not a standing still.
        positions.set(vec![one(1, 52.01, 110_000)]);
        assert!(moving(&positions, 1).ok_or("not served")?.0.is_some());
        // Westward: track 270.
        positions.set(vec![Served {
            lon: 4.99,
            ..one(1, 52.01, 120_000)
        }]);
        let (_, track) = moving(&positions, 1).ok_or("not served")?;
        assert!((track.ok_or("no track")? - 270.0).abs() < 0.01, "{track:?}");
        Ok(())
    }

    /// Fixes closer than a second or further than a minute apart, or either not MLAT, give no
    /// velocity; nor do two at one place give a track. Standing is not asked: a client holds
    /// none, and every fix it serves is unconfirmed.
    #[test]
    fn a_velocity_needs_two_mlat_fixes_a_second_to_a_minute_apart() {
        let at = |lat, transmitted_ms| one(1, lat, transmitted_ms);
        let unconfirmed = Served {
            confidence: MlatConfidence::Unconfirmed,
            ..at(52.01, 110_000)
        };
        assert!(velocity(&at(52.0, 100_000), &unconfirmed).is_some());
        let adsb = Served {
            source: PositionSource::Adsb,
            ..at(52.01, 110_000)
        };
        assert!(velocity(&at(52.0, 100_000), &at(52.01, 101_000)).is_some());
        assert!(velocity(&at(52.0, 100_000), &at(52.01, 160_000)).is_some());
        for (before, after) in [
            (at(52.0, 100_000), at(52.01, 100_999)),
            (at(52.0, 100_000), at(52.01, 160_001)),
            (at(52.01, 110_000), at(52.0, 100_000)),
            (at(52.0, 100_000), adsb.clone()),
            (adsb, at(52.0, 120_000)),
            (one(2, 52.0, 100_000), at(52.01, 110_000)),
        ] {
            assert_eq!(velocity(&before, &after), None, "{before:?} {after:?}");
        }
        assert_eq!(
            velocity(&at(52.0, 100_000), &at(52.0, 110_000)),
            Some((0.0, None))
        );
        // Through `Positions`: a fix half a second after the last is served still, unmoving.
        let positions = Positions::default();
        positions.set(vec![at(52.0, 100_000)]);
        positions.set(vec![at(52.01, 100_500)]);
        assert_eq!(moving(&positions, 1), Some((None, None)));
    }

    #[test]
    fn readsbs_position_is_served_before_an_mlat_one_of_the_same_aircraft() {
        let mlat = one(0xabcdef, 52.0, 1);
        let mut adsb = mlat.aircraft();
        adsb.position_source = PositionSource::Adsb;
        adsb.mlat = None;
        let answer = answer(vec![adsb.clone()], &[mlat, one(0xc0ffee, 52.0, 1)]);
        assert_eq!(answer.len(), 2);
        assert_eq!(answer[0], adsb);
        assert_eq!(answer[1].position_source, PositionSource::Mlat);
    }
}
