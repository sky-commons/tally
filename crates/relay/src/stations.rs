//! What a relay reports about each receiver it forwards for (RFC-0173 §2.5): how often it has fed
//! this relay directly, when it was first and last heard, how many batches and observations were
//! forwarded for it, and how many of its sequences never arrived. These are counts of the relay's
//! own traffic, not about aircraft; a receiver's location and software come from its own signed
//! description, which the hub holds (`Hub::stations`).
//!
//! No figure about a feeder is computed here (RFC-0174 §2.12: no relay computes, stores or vouches
//! for a feeder's uptime, message rate, planes heard, range, coverage or MLAT help). A rate is a
//! client's to derive: `tally-api` takes the change in `observations` between two reports.
//!
//! The table is bounded like the relay's others (`Bounded`): a receiver is active whenever a batch
//! of it is forwarded, so a churn of throwaway keys forgets itself oldest first and a receiver that
//! keeps publishing keeps its place. Only a forwarded batch, which its key signed, creates a row.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use tally_wire::{Location, PublicKey};

use crate::bounded::Bounded;
use crate::hub::RECEIVERS_REMEMBERED;

/// How many receivers' stats are held: as many as their descriptions (`RECEIVERS_REMEMBERED`). At
/// under 300 bytes a row, about 15 MB.
pub const STATIONS_REMEMBERED: usize = RECEIVERS_REMEMBERED;

/// A receiver is online while a batch of it was forwarded this recently. A feeder seals once a
/// second, so this is many missed seals, never one slow one.
pub const ONLINE_WITHIN_MS: u64 = 30_000;

/// Every station's report, as `GET /stations` serves it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StationsReport {
    pub now_ms: u64,
    pub stations: Vec<StationReport>,
}

/// One receiver as this relay knows it, as `GET /stations/{key}` serves it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StationReport {
    /// The receiver's public key, as tally prints it (base64).
    pub key: String,
    /// A batch of it was forwarded within `ONLINE_WITHIN_MS`.
    pub online: bool,
    /// It is feeding this relay directly right now.
    pub connected: bool,
    /// How many times it has fed this relay directly: a connection that forwarded a new batch.
    pub sessions: u64,
    /// Unix milliseconds of the first and the newest batch of it forwarded.
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub batches: u64,
    /// Sequences of its current and earlier boots that were skipped and have not arrived late.
    pub gaps: u64,
    pub observations: u64,
    /// Where its newest description says it is, if the relay holds one that says.
    pub location: Option<StationLocation>,
    /// The feeder software its newest description names.
    pub software: Option<String>,
    /// The address (no port) its connected session came from, as the socket saw it; `null` while
    /// no session of it is connected. An address is a session's, never the receiver's: once the
    /// session ends the address may be anyone's (a dynamic IP reassigned), so it goes with it.
    /// Who feeds from where is the operator's to know, never the public's: this report is served
    /// on loopback only (`config::parse_stats_listen`), and `tally-api` answers a client only the
    /// connected stations of the client's own address (`GET /v1/me`).
    pub address: Option<String>,
}

/// A receiver's declared location, in degrees and metres.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct StationLocation {
    pub lat: f64,
    pub lon: f64,
    pub alt_m: i32,
    pub precision_m: u32,
}

impl From<Location> for StationLocation {
    fn from(location: Location) -> Self {
        Self {
            lat: f64::from(location.lat_e7) / 1e7,
            lon: f64::from(location.lon_e7) / 1e7,
            alt_m: location.alt_m,
            precision_m: location.precision_m,
        }
    }
}

/// One receiver's running counts.
#[derive(Clone, Debug)]
struct Tally {
    sessions: u64,
    /// The connection currently feeding it directly, if one is.
    session: Option<u64>,
    /// The address `session` connected from, held only while `session` is.
    address: Option<IpAddr>,
    first_seen_ms: u64,
    last_seen_ms: u64,
    batches: u64,
    gaps: u64,
    observations: u64,
    /// Its newest boot and the highest sequence forwarded in it.
    stream: Option<(u64, u64)>,
}

impl Tally {
    fn new(now_ms: u64) -> Self {
        Self {
            sessions: 0,
            session: None,
            address: None,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            batches: 0,
            gaps: 0,
            observations: 0,
            stream: None,
        }
    }

    fn forwarded(&mut self, boot: u64, sequence: u64, observations: u64, now_ms: u64) {
        self.last_seen_ms = self.last_seen_ms.max(now_ms);
        self.batches += 1;
        self.observations += observations;
        self.stream = Some(match self.stream {
            Some((known, newest)) if known == boot => {
                if sequence > newest {
                    self.gaps += sequence - newest - 1;
                    (boot, sequence)
                } else {
                    // A late batch fills a gap counted when its successor arrived.
                    self.gaps = self.gaps.saturating_sub(1);
                    (boot, newest)
                }
            }
            // A new boot, or the first seen: where it starts is not a gap.
            _ => (boot, sequence),
        });
    }

    fn report(&self, key: &PublicKey, now_ms: u64) -> StationReport {
        StationReport {
            key: key.to_base64(),
            online: now_ms.saturating_sub(self.last_seen_ms) <= ONLINE_WITHIN_MS,
            connected: self.session.is_some(),
            sessions: self.sessions,
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            batches: self.batches,
            gaps: self.gaps,
            observations: self.observations,
            location: None,
            software: None,
            address: self.address.map(|address| address.to_string()),
        }
    }
}

pub struct Stations {
    table: Bounded<PublicKey, Tally>,
}

impl Stations {
    pub fn new(capacity: usize) -> Self {
        Self {
            table: Bounded::new(capacity),
        }
    }

    /// A new batch of `receiver` was forwarded: the activity that keeps its row.
    pub fn forwarded(
        &mut self,
        receiver: PublicKey,
        boot: u64,
        sequence: u64,
        observations: u64,
        now_ms: u64,
    ) {
        if let Some(tally) = self.table.get_mut(&receiver) {
            tally.forwarded(boot, sequence, observations, now_ms);
            self.table.touch(&receiver);
        } else {
            let mut tally = Tally::new(now_ms);
            tally.forwarded(boot, sequence, observations, now_ms);
            self.table.insert_active(receiver, tally);
        }
    }

    /// Connection `source`, a feeder publishing as `receiver` from `address`, just had a new batch
    /// forwarded: the first one on it counts a session, and its address is the receiver's. An IPv4
    /// client of a dual-stack socket is named as IPv4 (`::ffff:a.b.c.d` is `a.b.c.d`).
    pub fn fed_by(&mut self, receiver: &PublicKey, source: u64, address: Option<IpAddr>) {
        if let Some(tally) = self.table.get_mut(receiver)
            && tally.session != Some(source)
        {
            tally.session = Some(source);
            tally.sessions += 1;
            tally.address = address.map(|address| address.to_canonical());
        }
    }

    /// Connection `source` of a feeder publishing as `receiver` ended, and its address with it. A
    /// newer connection of the same receiver stays its session, with its own address.
    pub fn left(&mut self, receiver: &PublicKey, source: u64) {
        if let Some(tally) = self.table.get_mut(receiver)
            && tally.session == Some(source)
        {
            tally.session = None;
            tally.address = None;
        }
    }

    /// `receiver`'s report, without the location and software its description carries.
    pub fn report(&self, receiver: &PublicKey, now_ms: u64) -> Option<StationReport> {
        self.table
            .get(receiver)
            .map(|tally| tally.report(receiver, now_ms))
    }

    /// Every receiver held, with its key, unordered.
    pub fn reports(&self, now_ms: u64) -> Vec<(PublicKey, StationReport)> {
        self.table
            .iter()
            .map(|(key, tally)| (*key, tally.report(key, now_ms)))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    fn key() -> Result<PublicKey, String> {
        Ok(Identity::generate()
            .map_err(|error| error.to_string())?
            .public())
    }

    /// The relay counts its own traffic and computes no figure from it: a report carries counts
    /// and instants, never a feeder's rate (RFC-0174 §2.12).
    #[test]
    fn a_report_carries_counts_and_no_feeder_figure() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.forwarded(receiver, 1, 0, 5, 1_000);
        let report = stations.report(&receiver, 2_000).ok_or("no report")?;
        let json = serde_json::to_value(&report).map_err(|error| error.to_string())?;
        let fields: Vec<&str> = json
            .as_object()
            .ok_or("not an object")?
            .keys()
            .map(String::as_str)
            .collect();
        for figure in [
            "messages_per_sec",
            "uptime",
            "aircraft",
            "range_m",
            "coverage_km2",
        ] {
            assert!(!fields.contains(&figure), "{figure} in {fields:?}");
        }
        Ok(())
    }

    #[test]
    fn counts_batches_and_observations() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        // One batch of 50 a second for twelve seconds, from t = 1,000 s.
        for n in 0..12 {
            stations.forwarded(receiver, 7, n, 50, 1_000_000 + n * 1000);
        }
        let report = stations.report(&receiver, 1_011_500).ok_or("no report")?;
        assert_eq!(
            (report.batches, report.observations, report.gaps),
            (12, 600, 0)
        );
        assert_eq!(
            (report.first_seen_ms, report.last_seen_ms),
            (1_000_000, 1_011_000)
        );
        assert!(report.online);
        // Long after, the receiver is offline.
        let later = stations
            .report(&receiver, 1_011_000 + ONLINE_WITHIN_MS + 1)
            .ok_or("no report")?;
        assert!(!later.online);
        Ok(())
    }

    #[test]
    fn a_skipped_sequence_is_a_gap_until_it_arrives_late_and_a_new_boot_is_none()
    -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        stations.forwarded(receiver, 1, 10, 1, 0);
        stations.forwarded(receiver, 1, 14, 1, 0);
        let gaps = |stations: &Stations| stations.report(&receiver, 0).map(|report| report.gaps);
        assert_eq!(gaps(&stations), Some(3));
        stations.forwarded(receiver, 1, 12, 1, 0);
        assert_eq!(gaps(&stations), Some(2));
        // A reboot starts again at 0, and joining mid-stream is no gap either.
        stations.forwarded(receiver, 2, 0, 1, 0);
        stations.forwarded(receiver, 2, 1, 1, 0);
        assert_eq!(gaps(&stations), Some(2));
        Ok(())
    }

    #[test]
    fn a_session_is_a_connection_that_forwarded_and_ends_only_as_itself() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        // No row until a batch: a connection alone creates nothing.
        stations.fed_by(&receiver, 5, None);
        assert!(stations.is_empty());
        stations.forwarded(receiver, 1, 0, 1, 0);
        stations.fed_by(&receiver, 5, None);
        stations.fed_by(&receiver, 5, None);
        // The feeder reconnects before its old connection is noticed gone.
        stations.fed_by(&receiver, 6, None);
        stations.left(&receiver, 5);
        let report = stations.report(&receiver, 0).ok_or("no report")?;
        assert_eq!((report.sessions, report.connected), (2, true));
        stations.left(&receiver, 6);
        let report = stations.report(&receiver, 0).ok_or("no report")?;
        assert_eq!((report.sessions, report.connected), (2, false));
        Ok(())
    }

    /// The address is the connected session's, without its port, an IPv4 client of a dual-stack
    /// socket named as IPv4; none before the receiver fed this relay directly and none once its
    /// session ended, since the address may then be a stranger's.
    #[test]
    fn the_address_is_the_connected_sessions_only() -> Result<(), String> {
        let receiver = key()?;
        let mut stations = Stations::new(8);
        let address = |stations: &Stations| {
            stations
                .report(&receiver, 0)
                .and_then(|report| report.address)
        };
        stations.forwarded(receiver, 1, 0, 1, 0);
        assert_eq!(address(&stations), None);
        let home: IpAddr = "::ffff:203.0.113.7".parse().map_err(|_| "not an address")?;
        stations.fed_by(&receiver, 5, Some(home));
        assert_eq!(address(&stations).as_deref(), Some("203.0.113.7"));
        // The same session again changes nothing; a new one from elsewhere is the address now,
        // even before the old one is noticed gone.
        let away: IpAddr = "2001:db8::1".parse().map_err(|_| "not an address")?;
        stations.fed_by(&receiver, 5, Some(away));
        assert_eq!(address(&stations).as_deref(), Some("203.0.113.7"));
        stations.fed_by(&receiver, 6, Some(away));
        stations.left(&receiver, 5);
        assert_eq!(address(&stations).as_deref(), Some("2001:db8::1"));
        // A session that ends takes its address with it.
        stations.left(&receiver, 6);
        assert_eq!(address(&stations), None);
        let report = stations.report(&receiver, 0).ok_or("no report")?;
        assert!(!report.connected);
        Ok(())
    }

    #[test]
    fn the_table_is_bounded_and_keeps_the_receiver_that_publishes() -> Result<(), String> {
        let honest = key()?;
        let mut stations = Stations::new(4);
        for n in 0..40 {
            stations.forwarded(honest, 1, n, 1, 0);
            stations.forwarded(key()?, 1, 0, 1, 0);
            assert!(stations.len() <= 4);
        }
        assert!(stations.report(&honest, 0).is_some());
        Ok(())
    }
}
