//! FEEDER FIGURES AND LEADERBOARDS (RFC-0174 §2.12, as amended 2026-10-19), as this API serves
//! them as one client of the network, no different from any other.
//!
//! Only a relay holds what the figures are computed from: receivers' raw batches and the raw
//! positions that cite their receptions are relay-only (wire version 3). So each relay computes
//! the figures of the receivers it hosts or carries and publishes them, signed as its own claim,
//! on its client links (`tally_wire::FeederFigures`, `tally_relay::figures`). The API reads them
//! as any client may, keeps the newest of each receiver from the relays its operator names, and
//! serves and ranks them. What it reads carries no site: a receiver's public cell, counts,
//! coverage in square kilometres, a range from the public cell's centre.
//!
//! Over the relay's window (the 24 whole hours before the hour it was issued at; a relay
//! publishes once an hour, so nothing finer than an hour can be differenced out), per receiver: **uptime** (the
//! share of minutes with a batch), **messages**, **aircraft** (distinct checked addresses),
//! **range** (from the public cell's centre), **coverage** and **unique coverage** (coverage cells
//! no other receiver of that relay heard in), **MLAT help** (distinct final positions citing a
//! reception of it) and **standing** (the relay's own ledger).
//!
//! A figure counts only when its record verifies, is signed by one of the operator's relays
//! (`Settings::relays`), and was issued no later than `FRESH_WITHIN_MS` past the API's clock; a
//! receiver's figure is the newest such, by issue time, then by the signer's key. One not
//! re-issued within `STALE_MS` is no longer served.
//!
//! **Leaderboards** rank, per area (the record's: its receivers' public cells' parent at the
//! area resolution, `tally_wire::rendezvous::area_of_public`, which the wire holds every record
//! to), by unique coverage and by MLAT help, never by raw message counts, and rank only
//! receivers the relay says have standing. Every area with a receiver is listed all the same,
//! with how many it holds and which of them are unranked, so an area too new for MLAT (and so for
//! standing) shows its receivers rather than nothing. Memory is bounded: receivers by count,
//! least recently updated forgotten first (`Bounded`).

use std::collections::{BTreeMap, BTreeSet};

use h3o::{CellIndex, LatLng};
use tally_api_types::{
    FeederStats, Leaderboard, LeaderboardArea, LeaderboardEntry, Leaderboards, Position, Ranks,
    UnrankedFeeder,
};
use tally_relay::bounded::Bounded;
use tally_wire::rendezvous::AREA_RESOLUTION;
use tally_wire::{FeederFigure, FeederFigures, PublicKey, Region};

/// A record issued further than this past the API's clock is not taken.
pub const FRESH_WITHIN_MS: u64 = 120_000;
/// A receiver's figure not re-issued within this is no longer served: two of a relay's hourly
/// publishing intervals (`tally_relay::figures::PUBLISH_EVERY_MS`), so one missed publish is
/// carried and a relay gone is dropped within two hours.
pub const STALE_MS: u64 = 2 * tally_relay::figures::PUBLISH_EVERY_MS;
/// Feeders each leaderboard lists, and an area's unranked feeders at most.
pub const BOARD_LENGTH: usize = 20;
/// Receivers held.
pub const MAX_FEEDERS: usize = 65_536;
/// The mean Earth radius, metres (IUGG).
const EARTH_RADIUS_M: f64 = 6_371_008.8;

/// A place, degrees.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

impl LatLon {
    /// Great-circle distance, metres.
    pub(crate) fn distance_m(self, other: Self) -> f64 {
        let (a, b) = (self.lat.to_radians(), other.lat.to_radians());
        let dlat = b - a;
        let dlon = (other.lon - self.lon).to_radians();
        let h = (dlat / 2.0).sin().powi(2) + a.cos() * b.cos() * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_M * h.sqrt().min(1.0).asin()
    }

    /// The initial bearing of the great circle from here to `other`, degrees clockwise from true
    /// north, at least 0 and below 360.
    pub(crate) fn bearing_deg(self, other: Self) -> f64 {
        let (a, b) = (self.lat.to_radians(), other.lat.to_radians());
        let dlon = (other.lon - self.lon).to_radians();
        let y = dlon.sin() * b.cos();
        let x = a.cos() * b.sin() - a.sin() * b.cos() * dlon.cos();
        let degrees = y.atan2(x).to_degrees().rem_euclid(360.0);
        // -0.0 and a rounding up to 360 both read as north.
        if degrees >= 360.0 { 0.0 } else { degrees + 0.0 }
    }
}

/// One receiver's newest figure, as a relay signed it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Held {
    figure: FeederFigure,
    area: Option<Region>,
    issued_ms: u64,
    window_for_ms: u64,
    signer: PublicKey,
}

impl Held {
    /// Whether this replaces `held`: issued later, or at once by a lesser key.
    fn newer_than(&self, held: &Self) -> bool {
        (self.issued_ms, std::cmp::Reverse(*self.signer.as_bytes()))
            > (held.issued_ms, std::cmp::Reverse(*held.signer.as_bytes()))
    }
}

/// The newest figure of every receiver, from the relays the operator names.
pub struct Ledger {
    relays: BTreeSet<PublicKey>,
    feeders: Bounded<PublicKey, Held>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self::trusting(Vec::new())
    }
}

impl Ledger {
    /// A ledger taking the figures `relays` sign, and no one else's.
    pub fn trusting(relays: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            relays: relays.into_iter().collect(),
            feeders: Bounded::new(MAX_FEEDERS),
        }
    }

    /// One relay's figures, read at `now_ms` on the API's clock: each receiver's figure taken
    /// when the record verifies, its signer is one of the operator's relays, it is not dated
    /// ahead, and it is newer than the one held.
    pub fn ingest(&mut self, figures: &FeederFigures, now_ms: u64) {
        let (Ok(()), Ok(signer), Ok(content)) =
            (figures.verify(), figures.signer(), figures.content())
        else {
            return;
        };
        if !self.relays.contains(&signer)
            || content.issued_ms > now_ms.saturating_add(FRESH_WITHIN_MS)
            || content.issued_ms.saturating_add(STALE_MS) < now_ms
        {
            return;
        }
        for figure in content.feeders {
            let held = Held {
                figure,
                area: content.area,
                issued_ms: content.issued_ms,
                window_for_ms: content.window_for_ms,
                signer,
            };
            match self.feeders.get(&figure.receiver) {
                Some(was) if !held.newer_than(was) => {}
                Some(_) => {
                    if let Some(was) = self.feeders.get_mut(&figure.receiver) {
                        *was = held;
                    }
                    self.feeders.touch(&figure.receiver);
                }
                None => {
                    self.feeders.insert_active(figure.receiver, held);
                }
            }
        }
    }

    /// Forgets what is stale, and computes every figure and board as of `now_ms`.
    pub fn board(&mut self, now_ms: u64) -> Board {
        let stale: Vec<PublicKey> = self
            .feeders
            .iter()
            .filter(|(_, held)| held.issued_ms.saturating_add(STALE_MS) < now_ms)
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            self.feeders.remove(&key);
        }
        let window_for_ms = self
            .feeders
            .iter()
            .map(|(_, held)| held.window_for_ms)
            .max()
            .unwrap_or(0);
        let feeders = self
            .feeders
            .iter()
            .map(|(key, held)| (*key, stats(now_ms, held)))
            .collect();
        rank(now_ms, window_for_ms, feeders)
    }
}

/// What the API serves of a held figure.
fn stats(now_ms: u64, held: &Held) -> FeederStats {
    let figure = &held.figure;
    let seconds = held.window_for_ms as f64 / 1000.0;
    FeederStats {
        now_ms,
        key: figure.receiver.to_base64(),
        window_for_ms: held.window_for_ms,
        uptime: f64::from(figure.uptime_permille.min(1000)) / 1000.0,
        messages: figure.messages,
        messages_per_sec: if seconds > 0.0 {
            figure.messages as f64 / seconds
        } else {
            0.0
        },
        aircraft: figure.aircraft,
        range_m: figure.range_m.map(f64::from),
        coverage_km2: f64::from(figure.coverage_dkm2) / 10.0,
        unique_coverage_km2: f64::from(figure.unique_coverage_dkm2) / 10.0,
        mlat_positions: figure.mlat_positions,
        area: held.area.map(|area| format!("{:x}", area.as_u64())),
        standing: figure.standing,
        ranks: None,
    }
}

/// Every figure and board, as of one instant.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Board {
    pub now_ms: u64,
    pub window_for_ms: u64,
    feeders: BTreeMap<PublicKey, FeederStats>,
    areas: BTreeMap<String, Leaderboard>,
    index: Vec<LeaderboardArea>,
}

impl Board {
    pub fn feeder(&self, key: &PublicKey) -> Option<FeederStats> {
        self.feeders.get(key).cloned()
    }

    pub fn leaderboards(&self) -> Leaderboards {
        Leaderboards {
            now_ms: self.now_ms,
            window_for_ms: self.window_for_ms,
            areas: self.index.clone(),
        }
    }

    /// One area's boards, `None` when no feeder with figures is in it.
    pub fn leaderboard(&self, area: &CellIndex) -> Option<Leaderboard> {
        self.areas.get(&area.to_string()).cloned()
    }
}

/// An area named in a path: an H3 cell at the network's area resolution, as hex.
pub fn parse_area(text: &str) -> Option<CellIndex> {
    text.parse::<CellIndex>()
        .ok()
        .filter(|cell| u8::from(cell.resolution()) == AREA_RESOLUTION)
}

fn by_unique(a: &FeederStats, b: &FeederStats) -> std::cmp::Ordering {
    b.unique_coverage_km2
        .total_cmp(&a.unique_coverage_km2)
        .then(b.mlat_positions.cmp(&a.mlat_positions))
        .then(a.key.cmp(&b.key))
}

fn by_mlat(a: &FeederStats, b: &FeederStats) -> std::cmp::Ordering {
    b.mlat_positions
        .cmp(&a.mlat_positions)
        .then(b.unique_coverage_km2.total_cmp(&a.unique_coverage_km2))
        .then(a.key.cmp(&b.key))
}

fn entry(rank: usize, stats: &FeederStats) -> LeaderboardEntry {
    LeaderboardEntry {
        rank: u32::try_from(rank + 1).unwrap_or(u32::MAX),
        key: stats.key.clone(),
        unique_coverage_km2: stats.unique_coverage_km2,
        mlat_positions: stats.mlat_positions,
    }
}

/// Ranks every feeder with standing and an area within its area, and builds the boards: one for
/// every area a feeder is in, ranked or not.
fn rank(now_ms: u64, window_for_ms: u64, mut feeders: BTreeMap<PublicKey, FeederStats>) -> Board {
    let mut by_area: BTreeMap<String, Vec<PublicKey>> = BTreeMap::new();
    for (key, stats) in &feeders {
        if let Some(area) = &stats.area {
            by_area.entry(area.clone()).or_default().push(*key);
        }
    }
    let mut areas = BTreeMap::new();
    let mut index = Vec::new();
    for (area, keys) in by_area {
        let receivers = u32::try_from(keys.len()).unwrap_or(u32::MAX);
        let (mut ranked, unranked): (Vec<FeederStats>, Vec<FeederStats>) = keys
            .iter()
            .filter_map(|key| feeders.get(key).cloned())
            .partition(|stats| stats.standing);
        let of = u32::try_from(ranked.len()).unwrap_or(u32::MAX);
        ranked.sort_by(by_unique);
        let by_unique_coverage: Vec<LeaderboardEntry> = ranked
            .iter()
            .enumerate()
            .map(|(n, s)| entry(n, s))
            .collect();
        ranked.sort_by(by_mlat);
        let by_mlat: Vec<LeaderboardEntry> = ranked
            .iter()
            .enumerate()
            .map(|(n, s)| entry(n, s))
            .collect();
        let mut unranked: Vec<UnrankedFeeder> = unranked
            .into_iter()
            .map(|stats| UnrankedFeeder { key: stats.key })
            .collect();
        unranked.sort_by(|a, b| a.key.cmp(&b.key));
        for key in &keys {
            let Some(stats) = feeders.get_mut(key).filter(|stats| stats.standing) else {
                continue;
            };
            let place = |board: &[LeaderboardEntry]| {
                board
                    .iter()
                    .find(|entry| entry.key == stats.key)
                    .map_or(0, |entry| entry.rank)
            };
            stats.ranks = Some(Ranks {
                unique_coverage: place(&by_unique_coverage),
                mlat: place(&by_mlat),
                of,
            });
        }
        let Some(center) = parse_area(&area).map(|cell| {
            let centre = LatLng::from(cell);
            Position {
                lat: micro_degrees(centre.lat()),
                lon: micro_degrees(centre.lng()),
            }
        }) else {
            continue;
        };
        index.push(LeaderboardArea {
            area: area.clone(),
            center,
            ranked: of,
            receivers,
        });
        areas.insert(
            area.clone(),
            Leaderboard {
                now_ms,
                window_for_ms,
                area,
                center,
                ranked: of,
                receivers,
                by_unique_coverage: by_unique_coverage.into_iter().take(BOARD_LENGTH).collect(),
                by_mlat: by_mlat.into_iter().take(BOARD_LENGTH).collect(),
                unranked: unranked.into_iter().take(BOARD_LENGTH).collect(),
            },
        );
    }
    index.sort_by(|a, b| {
        b.ranked
            .cmp(&a.ranked)
            .then(b.receivers.cmp(&a.receivers))
            .then(a.area.cmp(&b.area))
    });
    Board {
        now_ms,
        window_for_ms,
        feeders,
        areas,
        index,
    }
}

/// Degrees to six places: a cell's centre, written in as few digits as it needs.
fn micro_degrees(degrees: f64) -> f64 {
    (degrees * 1e6).round() / 1e6
}

#[cfg(test)]
pub(crate) mod tests;
