//! MLAT positions (RFC-0171 §3.8.1): the API subscribes to the positions and clock model streams
//! of every relay its operator names, as any client does, merges them by the one client merge rule
//! (`tally_merge`), and serves the merged position of an aircraft readsb holds no ADS-B position
//! for. The merge runs on a thread of its own; what requests read is the snapshot it publishes,
//! every aircraft's current fix. The same subscription carries the relays' signed feeder figures
//! (`crate::feeders`).
//!
//! A client holds no raw (wire version 4): a fix's check is its engine's signature, and its
//! confidence is unconfirmed, since standing is a relay's ledger, not a client's. An engine
//! publishes a fix as soon as it can solve one and a bigger one as more receptions arrive, so
//! what is served is each aircraft's newest fix, a few seconds after it was heard.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tally_api_types::{Aircraft, Mlat, MlatCheck, MlatConfidence, PositionSource};
use tally_merge::Merge;
use tally_wire::{ClientRecord, Identity, RelayAddress};
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
    pub confidence: MlatConfidence,
    pub contested: bool,
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
            position_source: PositionSource::Mlat,
            mlat: Some(Mlat {
                horizontal_sigma_m: self.horizontal_sigma_m,
                check: self.check,
                confidence: self.confidence,
                contested: self.contested,
            }),
        }
    }
}

/// Every aircraft's served fix: its latest transmission's (`tally_merge::Track::current`).
pub fn served(merge: &Merge) -> Vec<Served> {
    merge
        .tracks()
        .into_iter()
        .filter_map(|track| track.current().map(|fix| (track, fix)))
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
                // Standing is a relay's ledger, kept from raw a client never holds.
                confidence: MlatConfidence::Unconfirmed,
                contested,
                transmitted_ms: fix.transmitted.unix_ms,
                gs_kt: None,
                track_deg: None,
            }
        })
        .collect()
}

/// The ground speed (knots) and track (degrees true) of an aircraft that moved from `before` to
/// `after`, two fixes of it: along the great circle between them, the speed its length over their
/// time apart and the track its initial bearing. `None` unless both are of one aircraft and they
/// are `VELOCITY_MIN_SPAN_MS` to `VELOCITY_MAX_SPAN_MS` apart; no track when they are at one place.
pub fn velocity(before: &Served, after: &Served) -> Option<(f64, Option<f64>)> {
    if before.address != after.address {
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

/// What requests read: the latest snapshot of the merge's fixes, each aircraft moving by its last
/// two served fixes.
#[derive(Default)]
pub struct Positions {
    served: RwLock<Arc<Vec<Served>>>,
    /// Each aircraft's fix served before its current one, of an earlier transmission: what its
    /// velocity is taken from.
    before: Mutex<HashMap<u32, Served>>,
}

impl Positions {
    /// Serves `served`, the merge's current fixes, each with its velocity from the fix of the same
    /// aircraft served before it: a fix of a later transmission than the one held makes the held
    /// one the earlier; one of the same transmission (a bigger fix of it, solved as more of its
    /// receptions arrived) replaces it and keeps the earlier; one of an earlier transmission (the
    /// later one's fix dropped with a convicted engine) keeps only an earlier fix still before it.
    /// An aircraft no longer served is forgotten.
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
    // What the merge reads, the relays' feeder figures among it. No raw: it is relay-only.
    let streams = tally_merge::link::streams();
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
    // The merge's checks and fits are computation, not I/O: a thread of their own.
    tokio::task::spawn_blocking(move || {
        let mut merge = Merge::new(tally_merge::Settings::default());
        let mut published = std::time::Instant::now();
        let mut dirty = false;
        while let Some(record) = records.blocking_recv() {
            match &record {
                ClientRecord::FeederFigures(figures) => {
                    if let Ok(mut ledger) = feeders.lock() {
                        ledger.ingest(figures, clock.now());
                    }
                }
                _ => match merge.ingest(&record) {
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

/// The API host's clock as it judges signed times: its wall clock, and whether the host's
/// ClockBound says it is synchronised now within `budget::E` (`tally_wire::clock_bound`, the one
/// reader and the one judgement of its word every end shares), read at each reading. What
/// `PRODUCT_AHEAD` and `K` are derived from is every judging clock within `E` of true time, so the
/// API relies on them only by a reading ClockBound vouched for: a host without ClockBound, or one
/// it says is not synchronised or bounds past `E`, judges nothing, and its reader counts each such
/// read by why (`tally_wire::clock_bound::Reader::health`). The bound is only as honest as chrony
/// and ClockBound are (RFC-0171 §3.6).
#[derive(Clone)]
pub struct Clock {
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

/// A test's script read as the API's judging clock.
#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
fn scripted(ms: u64) -> tally_wire::clocks::Judged {
    tally_wire::clocks::recorded::judged(ms)
}

impl Clock {
    /// The host's: its wall clock, judged by its ClockBound's word on it.
    pub fn system() -> Self {
        Self {
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

    /// A test's: it reads `read`, and it judges as `judging` says.
    #[cfg(test)]
    pub fn scripted(
        read: impl Fn() -> u64 + Send + Sync + 'static,
        judging: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            judged: tally_wire::clocks::JudgedReader::of(move || scripted(read())),
            judging: std::sync::Arc::new(judging),
        }
    }

    /// The clock now, with whether it judges.
    pub fn now(&self) -> Now {
        Now {
            judged: self.judged.read(),
            judging: (self.judging)(),
        }
    }
}

/// A reading of the API's clock and whether it judged as it was read (`Clock::now`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    judged: tally_wire::clocks::Judged,
    judging: bool,
}

impl Now {
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
            confidence: MlatConfidence::Unconfirmed,
            contested: false,
            transmitted_ms,
            gs_kt: None,
            track_deg: None,
        }
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
        // A fix of the same transmission (a bigger one of it) replaces it: the velocity is still
        // taken from the fix before.
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

    /// Fixes closer than a second or further than a minute apart, or of two aircraft, give no
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
        assert!(velocity(&at(52.0, 100_000), &at(52.01, 101_000)).is_some());
        assert!(velocity(&at(52.0, 100_000), &at(52.01, 160_000)).is_some());
        for (before, after) in [
            (at(52.0, 100_000), at(52.01, 100_999)),
            (at(52.0, 100_000), at(52.01, 160_001)),
            (at(52.01, 110_000), at(52.0, 100_000)),
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
