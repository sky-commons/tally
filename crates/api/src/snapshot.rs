//! What the API holds between requests: the relay's station reports, readsb's aircraft count and
//! the feeder figures, each read or computed on a schedule (`refresh`) rather than per request, so a crowd of clients costs the
//! relay and readsb nothing more. A value older than `STALE_AFTER` is not served.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tally_relay::stations::{StationReport, StationsReport};
use tally_wire::PublicKey;

use tally_api_types::{Network, Position, Station};

use crate::feeders::Board;

/// How often the relay's stations and readsb's count are read, by default.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(5);

/// Beyond this since its last good read, a value is not served: the API answers 503.
pub const STALE_AFTER: Duration = Duration::from_secs(60);

/// The relay's stations, by key, with the network's totals over them. The relay reports counts
/// only (RFC-0174 §2.12: no relay computes a feeder's figures); each station's message rate is
/// the API's own, the change in its forwarded observations since the previous report.
pub struct Stations {
    pub now_ms: u64,
    pub by_key: HashMap<PublicKey, StationReport>,
    /// Observations a second, per station, between the previous report and this one.
    pub rates: HashMap<PublicKey, f64>,
    pub online: u32,
    pub total: u32,
    pub messages_per_sec: f64,
}

impl Stations {
    /// The stations of `report`, each station's rate taken against `previous` (the report read
    /// before it): none for a station it did not hold, or a count that went backwards (the relay
    /// restarted).
    pub fn from_report(report: StationsReport, previous: Option<&Self>) -> Self {
        let mut by_key = HashMap::with_capacity(report.stations.len());
        for station in report.stations {
            // A key the relay printed is always one; one that is not is skipped, not trusted.
            if let Ok(key) = PublicKey::from_base64(&station.key) {
                by_key.insert(key, station);
            }
        }
        let online = by_key.values().filter(|station| station.online).count();
        let rates: HashMap<PublicKey, f64> = by_key
            .iter()
            .map(|(key, station)| {
                let rate = previous
                    .and_then(|previous| {
                        let before = previous.by_key.get(key)?;
                        let seconds = report
                            .now_ms
                            .checked_sub(previous.now_ms)
                            .filter(|ms| *ms > 0)? as f64
                            / 1000.0;
                        let more = station.observations.checked_sub(before.observations)?;
                        Some(more as f64 / seconds)
                    })
                    .unwrap_or(0.0);
                (*key, rate)
            })
            .collect();
        // Summed in key order, so the same report sums to the same double.
        let mut keys: Vec<&PublicKey> = rates.keys().collect();
        keys.sort_unstable();
        let messages_per_sec = keys.iter().filter_map(|key| rates.get(*key)).sum();
        Self {
            now_ms: report.now_ms,
            online: saturating_u32(online),
            total: saturating_u32(by_key.len()),
            messages_per_sec,
            rates,
            by_key,
        }
    }

    pub fn station(&self, key: &PublicKey) -> Option<Station> {
        self.by_key.get(key).map(|report| Station {
            now_ms: self.now_ms,
            key: report.key.clone(),
            online: report.online,
            first_seen_at_ms: report.first_seen_ms,
            last_seen_at_ms: report.last_seen_ms,
            messages_per_sec: self.rates.get(key).copied().unwrap_or(0.0),
            batches: report.batches,
            gaps: report.gaps,
            location: report.location.map(|location| Position {
                lat: location.lat,
                lon: location.lon,
            }),
            software: report.software.clone(),
        })
    }

    pub fn network(&self, aircraft: u32) -> Network {
        Network {
            now_ms: self.now_ms,
            receivers_online: self.online,
            receivers_total: self.total,
            messages_per_sec: self.messages_per_sec,
            aircraft,
            // seam stub (RFC-0184): counted by source
            aircraft_by_source: tally_api_types::SourceCounts {
                adsb: aircraft,
                ..Default::default()
            },
        }
    }
}

fn saturating_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

/// A value and when it was read.
struct Held<T> {
    at: Instant,
    value: T,
}

#[derive(Default)]
pub struct Snapshot {
    stations: RwLock<Option<Held<Arc<Stations>>>>,
    aircraft: RwLock<Option<Held<u32>>>,
    board: RwLock<Option<Held<Arc<Board>>>>,
}

impl Snapshot {
    pub fn set_stations(&self, stations: Stations, at: Instant) {
        if let Ok(mut held) = self.stations.write() {
            *held = Some(Held {
                at,
                value: Arc::new(stations),
            });
        }
    }

    pub fn set_aircraft(&self, count: u32, at: Instant) {
        if let Ok(mut held) = self.aircraft.write() {
            *held = Some(Held { at, value: count });
        }
    }

    pub fn set_board(&self, board: Board, at: Instant) {
        if let Ok(mut held) = self.board.write() {
            *held = Some(Held {
                at,
                value: Arc::new(board),
            });
        }
    }

    /// The feeder figures and leaderboards, unless never computed or stale at `now`.
    pub fn board(&self, now: Instant) -> Option<Arc<Board>> {
        let held = self.board.read().ok()?;
        let held = held.as_ref()?;
        fresh(held.at, now).then(|| Arc::clone(&held.value))
    }

    /// The stations, unless never read or stale at `now`.
    pub fn stations(&self, now: Instant) -> Option<Arc<Stations>> {
        let held = self.stations.read().ok()?;
        let held = held.as_ref()?;
        fresh(held.at, now).then(|| Arc::clone(&held.value))
    }

    /// The stations last read, however old.
    pub fn last_stations(&self) -> Option<Arc<Stations>> {
        let held = self.stations.read().ok()?;
        held.as_ref().map(|held| Arc::clone(&held.value))
    }

    pub fn aircraft(&self, now: Instant) -> Option<u32> {
        let held = self.aircraft.read().ok()?;
        let held = held.as_ref()?;
        fresh(held.at, now).then_some(held.value)
    }
}

fn fresh(at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(at) <= STALE_AFTER
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_relay::stations::StationLocation;
    use tally_wire::Identity;

    fn report(key: &PublicKey, online: bool, observations: u64) -> StationReport {
        StationReport {
            key: key.to_base64(),
            online,
            connected: online,
            sessions: 1,
            first_seen_ms: 1,
            last_seen_ms: 2,
            batches: 3,
            gaps: 4,
            observations,
            location: Some(StationLocation {
                lat: 37.5,
                lon: -122.25,
                alt_m: 10,
                precision_m: 0,
            }),
            software: Some("tally-feed 0.1.0".to_owned()),
        }
    }

    /// The rates are the API's: each station's change in forwarded observations between two
    /// reports, summed for the network. A first report, a station new to it, or a count that went
    /// backwards (the relay restarted) has none.
    #[test]
    fn the_network_totals_the_relays_stations() -> Result<(), String> {
        let a = Identity::generate().map_err(|e| e.to_string())?.public();
        let b = Identity::generate().map_err(|e| e.to_string())?.public();
        let c = Identity::generate().map_err(|e| e.to_string())?.public();
        let first = Stations::from_report(
            StationsReport {
                now_ms: 9_000,
                stations: vec![report(&a, true, 100), report(&b, false, 50)],
            },
            None,
        );
        assert_eq!(first.network(12).messages_per_sec, 0.0);
        let stations = Stations::from_report(
            StationsReport {
                now_ms: 13_000,
                stations: vec![
                    report(&a, true, 222),
                    report(&b, false, 52),
                    report(&c, true, 900),
                ],
            },
            Some(&first),
        );
        let network = stations.network(12);
        assert_eq!(
            (
                network.now_ms,
                network.receivers_online,
                network.receivers_total,
                network.aircraft
            ),
            (13_000, 2, 3, 12)
        );
        // 122 and 2 more over four seconds; c is new.
        assert!((network.messages_per_sec - 31.0).abs() < 1e-9);
        assert!((stations.station(&a).ok_or("no a")?.messages_per_sec - 30.5).abs() < 1e-9);
        assert_eq!(stations.station(&c).ok_or("no c")?.messages_per_sec, 0.0);
        let restarted = Stations::from_report(
            StationsReport {
                now_ms: 17_000,
                stations: vec![report(&a, true, 3)],
            },
            Some(&stations),
        );
        assert_eq!(restarted.network(0).messages_per_sec, 0.0);
        let station = stations.station(&a).ok_or("no station")?;
        assert_eq!(
            (station.key, station.batches, station.gaps, station.location),
            (
                a.to_base64(),
                3,
                4,
                Some(Position {
                    lat: 37.5,
                    lon: -122.25
                })
            )
        );
        Ok(())
    }

    #[test]
    fn a_value_is_not_served_once_stale() {
        let snapshot = Snapshot::default();
        let at = Instant::now();
        assert_eq!(snapshot.aircraft(at), None);
        snapshot.set_aircraft(7, at);
        assert_eq!(snapshot.aircraft(at + STALE_AFTER), Some(7));
        assert_eq!(
            snapshot.aircraft(at + STALE_AFTER + Duration::from_millis(1)),
            None
        );
    }
}
