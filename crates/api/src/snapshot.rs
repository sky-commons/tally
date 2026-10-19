//! What the API holds between requests: the relay's station reports, the aircraft count and
//! the feeder figures, each read or computed on a schedule (`refresh`) rather than per request, so a crowd of clients costs the
//! relay and readsb nothing more. A value older than `STALE_AFTER` is not served.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tally_relay::hub::source_of;
use tally_relay::stations::{StationReport, StationsReport};
use tally_wire::PublicKey;

use tally_api_types::{
    Aircraft, MeResponse, MeStation, Network, Position, PositionSource, SourceCounts, Station,
};

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

    /// The stations connected now from `client`'s host, by key. A host is what the relay counts a
    /// connection against (`source_of`): an IPv4 address exactly, an IPv6 /64 (a dual-stack home
    /// feeds from one temporary address and browses from another in the same /64), an IPv4
    /// address written as IPv6 (`::ffff:a.b.c.d`) the same as itself. Only a connected session
    /// has an address: once it ends the address may be a stranger's (a dynamic IP reassigned), so
    /// a station whose session ended is no one's. No stations when the client's address is not
    /// known (`routes::Client`), or is loopback or unspecified (a local process or a proxy, never
    /// a feeder's host).
    pub fn mine(&self, client: Option<IpAddr>) -> MeResponse {
        let client = client
            .map(|client| client.to_canonical())
            .filter(|client| !client.is_loopback() && !client.is_unspecified())
            .map(source_of);
        let mut keys: Vec<&PublicKey> = self
            .by_key
            .iter()
            .filter(|(_, report)| {
                report.connected
                    && report
                        .address
                        .as_deref()
                        .and_then(|address| address.parse::<IpAddr>().ok())
                        .is_some_and(|address| Some(source_of(address)) == client)
            })
            .map(|(key, _)| key)
            .collect();
        keys.sort_unstable();
        MeResponse {
            now_ms: self.now_ms,
            stations: keys
                .into_iter()
                .filter_map(|key| {
                    let report = self.by_key.get(key)?;
                    Some(MeStation {
                        key: report.key.clone(),
                        online: report.online,
                        messages_per_sec: self.rates.get(key).copied().unwrap_or(0.0),
                        last_seen_at_ms: report.last_seen_ms,
                    })
                })
                .collect(),
        }
    }

    /// The network's totals, with `aircraft` counted by source (`count`).
    pub fn network(&self, aircraft: SourceCounts) -> Network {
        Network {
            now_ms: self.now_ms,
            receivers_online: self.online,
            receivers_total: self.total,
            messages_per_sec: self.messages_per_sec,
            aircraft: total(&aircraft),
            aircraft_by_source: aircraft,
        }
    }
}

/// `aircraft` (each once, as `crate::mlat::answer` lists them: readsb's positioned aircraft, then
/// those only Tally MLAT places) counted by where each position came from.
pub fn count(aircraft: &[Aircraft]) -> SourceCounts {
    let mut counts = SourceCounts::default();
    for one in aircraft {
        let slot = match one.position_source {
            PositionSource::Adsb => &mut counts.adsb,
            PositionSource::Mlat => &mut counts.mlat,
            PositionSource::Adsr => &mut counts.adsr,
            PositionSource::Tisb => &mut counts.tisb,
            PositionSource::Other => &mut counts.other,
        };
        *slot = slot.saturating_add(1);
    }
    counts
}

/// What the counts sum to.
pub fn total(counts: &SourceCounts) -> u32 {
    let SourceCounts {
        adsb,
        mlat,
        adsr,
        tisb,
        other,
    } = *counts;
    [adsb, mlat, adsr, tisb, other]
        .into_iter()
        .fold(0, u32::saturating_add)
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
    aircraft: RwLock<Option<Held<SourceCounts>>>,
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

    pub fn set_aircraft(&self, count: SourceCounts, at: Instant) {
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

    pub fn aircraft(&self, now: Instant) -> Option<SourceCounts> {
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
            address: None,
        }
    }

    /// A client is answered the connected stations of its own host and none other: not one on
    /// another address, not one the relay names no address for, not one whose session ended,
    /// whatever the client's address is written as.
    #[test]
    fn a_client_is_answered_only_its_own_addresss_stations() -> Result<(), String> {
        let at = |key: &PublicKey, address: Option<&str>| StationReport {
            address: address.map(str::to_owned),
            ..report(key, true, 10)
        };
        let mut keys: Vec<PublicKey> = (0..5)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect();
        keys.sort_unstable();
        let stations = Stations::from_report(
            StationsReport {
                now_ms: 5_000,
                stations: vec![
                    at(&keys[3], Some("203.0.113.7")),
                    at(&keys[0], Some("203.0.113.7")),
                    at(&keys[1], Some("203.0.113.8")),
                    at(&keys[2], None),
                    // Its session ended: the address it named is no longer its own.
                    StationReport {
                        connected: false,
                        ..at(&keys[4], Some("203.0.113.7"))
                    },
                ],
            },
            None,
        );
        let home: IpAddr = "203.0.113.7".parse().map_err(|_| "not an address")?;
        let mine = stations.mine(Some(home));
        assert_eq!(mine.now_ms, 5_000);
        let named: Vec<&str> = mine.stations.iter().map(|one| one.key.as_str()).collect();
        assert_eq!(named, [keys[0].to_base64(), keys[3].to_base64()]);
        assert!(
            mine.stations
                .iter()
                .all(|one| one.online && one.last_seen_at_ms == 2)
        );
        // The same client through a dual-stack socket.
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().map_err(|_| "not an address")?;
        assert_eq!(stations.mine(Some(mapped)), mine);
        let stranger: IpAddr = "198.51.100.1".parse().map_err(|_| "not an address")?;
        assert!(stations.mine(Some(stranger)).stations.is_empty());
        // No address known, or one that is no feeder's host, names no station.
        assert!(stations.mine(None).stations.is_empty());
        Ok(())
    }

    /// IPv6 is matched by /64, as the relay counts a host: a dual-stack home's feeder and browser
    /// use different addresses of one /64. IPv4 is matched exactly.
    #[test]
    fn an_ipv6_host_is_its_64_and_an_ipv4_host_its_address() -> Result<(), String> {
        let mut keys: Vec<PublicKey> = (0..2)
            .map(|seed| Identity::from_seed([seed; 32]).public())
            .collect();
        keys.sort_unstable();
        let at = |key: &PublicKey, address: &str| StationReport {
            address: Some(address.to_owned()),
            ..report(key, true, 10)
        };
        let stations = Stations::from_report(
            StationsReport {
                now_ms: 5_000,
                stations: vec![
                    at(&keys[0], "2001:db8:1:2:aaaa::1"),
                    at(&keys[1], "203.0.113.7"),
                ],
            },
            None,
        );
        let named = |client: &str| -> Result<Vec<String>, String> {
            let client: IpAddr = client.parse().map_err(|_| "not an address")?;
            Ok(stations
                .mine(Some(client))
                .stations
                .into_iter()
                .map(|one| one.key)
                .collect())
        };
        // Another address in the same /64 is the same home.
        assert_eq!(
            named("2001:db8:1:2:bbbb:cccc:dddd:eeee")?,
            [keys[0].to_base64()]
        );
        // The next /64 is not.
        assert!(named("2001:db8:1:3:aaaa::1")?.is_empty());
        // IPv4 exactly, written either way; its neighbour is a stranger.
        assert_eq!(named("::ffff:203.0.113.7")?, [keys[1].to_base64()]);
        assert!(named("203.0.113.8")?.is_empty());
        // A loopback or unspecified client is no feeder's host, even beside a station that names one.
        let local = Stations::from_report(
            StationsReport {
                now_ms: 5_000,
                stations: vec![at(&keys[0], "127.0.0.1"), at(&keys[1], "::")],
            },
            None,
        );
        for client in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::"] {
            let client: IpAddr = client.parse().map_err(|_| "not an address")?;
            assert!(local.mine(Some(client)).stations.is_empty(), "{client}");
        }
        Ok(())
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
        let twelve = SourceCounts {
            adsb: 12,
            ..SourceCounts::default()
        };
        assert_eq!(first.network(twelve).messages_per_sec, 0.0);
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
        let network = stations.network(twelve);
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
        assert_eq!(
            restarted.network(SourceCounts::default()).messages_per_sec,
            0.0
        );
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

    /// The network's aircraft are readsb's positioned ones and those only Tally MLAT places, each
    /// once, and the counts by source sum to them.
    #[test]
    fn the_aircraft_counted_by_source_sum_to_the_networks_aircraft() -> Result<(), String> {
        let readsb = crate::readsb::parse(
            br#"{"now": 1791220000, "aircraft": [
                {"hex": "a1b2c3", "type": "adsb_icao", "lat": 1, "lon": 2},
                {"hex": "a1b2c4", "type": "adsb_icao_nt", "lat": 1, "lon": 2},
                {"hex": "a1b2c5", "type": "adsr_icao", "lat": 1, "lon": 2},
                {"hex": "a1b2c6", "type": "tisb_trackfile", "lat": 1, "lon": 2},
                {"hex": "a1b2c7", "type": "mlat", "lat": 1, "lon": 2},
                {"hex": "a1b2c8", "type": "adsb_icao"}
            ]}"#,
        )?;
        let mlat = |address| crate::mlat::Served {
            address,
            lat: 1.0,
            lon: 2.0,
            altitude_ft: None,
            horizontal_sigma_m: 30.0,
            check: tally_api_types::MlatCheck::Model,
            kind: tally_api_types::MlatKind::Final,
            confidence: tally_api_types::MlatConfidence::Standing,
            contested: false,
            source: PositionSource::Mlat,
            transmitted_ms: 1_791_220_000_000,
            gs_kt: None,
            track_deg: None,
        };
        // a1b2c3 readsb places itself; a1b2c8 readsb names without a position, so MLAT places it,
        // as it does c0ffee, which readsb does not name.
        let aircraft = crate::mlat::answer(
            readsb.positioned(),
            &[mlat(0xa1b2c3), mlat(0xa1b2c8), mlat(0xc0ffee)],
        );
        let counts = count(&aircraft);
        assert_eq!(
            counts,
            SourceCounts {
                adsb: 2,
                mlat: 2,
                adsr: 1,
                tisb: 1,
                other: 1,
            }
        );
        let stations = Stations::from_report(
            StationsReport {
                now_ms: 1,
                stations: Vec::new(),
            },
            None,
        );
        let network = stations.network(counts);
        assert_eq!(
            (network.aircraft, total(&network.aircraft_by_source)),
            (7, 7)
        );
        Ok(())
    }

    #[test]
    fn a_value_is_not_served_once_stale() {
        let snapshot = Snapshot::default();
        let at = Instant::now();
        let seven = SourceCounts {
            adsb: 7,
            ..SourceCounts::default()
        };
        assert_eq!(snapshot.aircraft(at), None);
        snapshot.set_aircraft(seven, at);
        assert_eq!(snapshot.aircraft(at + STALE_AFTER), Some(seven));
        assert_eq!(
            snapshot.aircraft(at + STALE_AFTER + Duration::from_millis(1)),
            None
        );
    }
}
