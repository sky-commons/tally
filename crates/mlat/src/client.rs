//! One receiver's mlat-client, minus the sockets: what mlat-client decides to tell the server
//! about each message its receiver hears. A port of three pieces of mlat-client 0.4.2, each cited
//! where it is used:
//! - the reader's timestamp handling and filter (`feed_beast`, `timestamp_update` and
//!   `filter_message` in `modes_reader.c`), with the filters `ReceiverConnection` installs
//!   (`mlat/client/receiver.py`);
//! - the `Coordinator` (`mlat/client/coordinator.py`): which aircraft are tracked, when a DF17
//!   position pair is a sync message, when anything else is an mlat message, and the periodic
//!   seen/lost and rate reports;
//! - the line formats of `JsonServerConnection` (`protocol.rs`).
//!
//! Times are seconds on one monotonic clock (`now`), as mlat-client's `monotonic_time()`.
//! Nothing here reads a clock; the caller passes it in, so the selection is testable exactly.

use std::collections::{BTreeSet, HashMap, HashSet};

use tally_wire::Observation;
use tally_wire::batch::format;

use crate::modes::Message;
use crate::protocol::{self, Mode};

// Coordinator class constants.
const UPDATE_INTERVAL: f64 = 4.5;
const REPORT_INTERVAL: f64 = 4.0;
const POSITION_EXPIRY_AGE: f64 = 30.0;
const EXPIRY_AGE: f64 = 120.0;
/// `JsonServerConnection.heartbeat_interval`.
const SERVER_HEARTBEAT_INTERVAL: f64 = 120.0;
/// `send_clock_jump` sends at most one per half second.
const CLOCK_JUMP_SPACING: f64 = 0.5;
/// A message needs this many before the coordinator uses its aircraft for anything.
const MESSAGES_BEFORE_USE: u32 = 10;
/// `received_df17`: "need NUCp >= 6".
const MIN_NUC: u8 = 6;

/// readsb marks its own MLAT results with this timestamp (`MAGIC_MLAT_TIMESTAMP`); they are
/// never measurements.
const MAGIC_MLAT_TIMESTAMP: u64 = 0xFF00_4D4C_4154;
/// One UTC day in nanoseconds, the span of a GPS (Radarcape) clock.
const DAY_NS: u64 = 86_400 * 1_000_000_000;

/// `is_synthetic_timestamp` in modes_reader.c.
fn synthetic(timestamp: u64) -> bool {
    timestamp == 0 || (MAGIC_MLAT_TIMESTAMP..=MAGIC_MLAT_TIMESTAMP + 10).contains(&timestamp)
}

/// `class Aircraft` in coordinator.py. Times that Python starts at 0 ("long ago" on a monotonic
/// clock) start at minus infinity, which compares the same way.
struct Aircraft {
    messages: u32,
    last_message_time: f64,
    last_even_time: f64,
    last_odd_time: f64,
    adsb_good: bool,
    even_message: Option<Message>,
    odd_message: Option<Message>,
    requested: bool,
    rate_measurement_start: f64,
    recent_adsb_positions: u32,
}

impl Aircraft {
    fn new(requested: bool, now: f64) -> Self {
        Self {
            messages: 0,
            last_message_time: f64::NEG_INFINITY,
            last_even_time: f64::NEG_INFINITY,
            last_odd_time: f64::NEG_INFINITY,
            adsb_good: false,
            even_message: None,
            odd_message: None,
            requested,
            rate_measurement_start: now,
            recent_adsb_positions: 0,
        }
    }
}

pub struct Client {
    mode: Mode,
    // The reader (`modesreader`).
    last_timestamp: u64,
    seen: HashSet<u32>,
    /// `ReceiverConnection.interested_mlat`: the address filter for DF 0, 4, 5, 11, 16, 20, 21.
    interested_mlat: HashSet<u32>,
    // The coordinator.
    aircraft: HashMap<u32, Aircraft>,
    requested_traffic: HashSet<u32>,
    reported: BTreeSet<u32>,
    next_aircraft_update: f64,
    last_aircraft_update: f64,
    next_report: Option<f64>,
    recent_jumps: u32,
    // The server connection.
    split_sync: bool,
    server_heartbeat_at: Option<f64>,
    last_clock_reset: f64,
    lines: Vec<String>,
}

impl Client {
    pub fn new(mode: Mode, now: f64) -> Self {
        Self {
            mode,
            last_timestamp: 0,
            seen: HashSet::new(),
            interested_mlat: HashSet::new(),
            aircraft: HashMap::new(),
            requested_traffic: HashSet::new(),
            reported: BTreeSet::new(),
            next_aircraft_update: now,
            last_aircraft_update: now,
            next_report: None,
            recent_jumps: 0,
            split_sync: false,
            server_heartbeat_at: None,
            last_clock_reset: now,
            lines: Vec::new(),
        }
    }

    /// The lines to write to the server since the last call, in order.
    pub fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// `handle_handshake_response` then `Coordinator.server_connected`. `jitter` is a uniform
    /// random number in [0, 1), Python's `random.random()`.
    pub fn server_connected(&mut self, split_sync: bool, now: f64, jitter: f64) {
        self.split_sync = split_sync;
        self.server_heartbeat_at = Some(now + SERVER_HEARTBEAT_INTERVAL);
        self.requested_traffic.clear();
        self.aircraft.clear();
        self.reported.clear();
        self.next_report = Some(jitter * REPORT_INTERVAL);
        // "dummy rate report to indicate we'll be sending them".
        self.lines.push(protocol::rate_report_line(&[]));
    }

    /// `Coordinator.input_connected`, then the mode-change event mlat-client synthesises for an
    /// input whose type was configured (`ReceiverConnection.start_connection`).
    pub fn input_connected(&mut self) {
        self.lines.push(protocol::input_connected_line());
        self.recent_jumps = 0;
        self.lines.push(protocol::mode_change_line(self.mode));
    }

    /// `Coordinator.input_disconnected`, and the fresh reader `reset_connection` makes.
    pub fn input_disconnected(&mut self) {
        self.lines.push(protocol::input_disconnected_line());
        self.aircraft.clear();
        let lost: Vec<u32> = self.reported.iter().copied().collect();
        self.lines.push(protocol::addresses_line("lost", &lost));
        self.reported.clear();
        self.last_timestamp = 0;
        self.seen.clear();
    }

    /// `received_timestamp_jump_event`: the receiver's counter jumped where it should not have.
    pub fn clock_jump(&mut self, now: f64) {
        self.recent_jumps += 1;
        if now > self.last_clock_reset + CLOCK_JUMP_SPACING {
            self.last_clock_reset = now;
            self.lines.push(protocol::clock_jump_line());
        }
        // The reader takes the new timeline from here (`timestamp_update` past the outlier).
        self.last_timestamp = 0;
    }

    /// `server_start_sending`.
    pub fn start_sending(&mut self, addresses: &[u32]) {
        for address in addresses {
            if let Some(aircraft) = self.aircraft.get_mut(address) {
                aircraft.requested = true;
            }
        }
        self.requested_traffic.extend(addresses.iter().copied());
        self.update_receiver_filter();
    }

    /// `server_stop_sending`.
    pub fn stop_sending(&mut self, addresses: &[u32]) {
        for address in addresses {
            if let Some(aircraft) = self.aircraft.get_mut(address) {
                aircraft.requested = false;
            }
            self.requested_traffic.remove(address);
        }
        self.update_receiver_filter();
    }

    /// `update_receiver_filter`: mlat messages are wanted for aircraft the server asked for and
    /// that have not been giving good ADS-B positions. Only recomputed when the server's request
    /// changes, exactly as mlat-client does.
    fn update_receiver_filter(&mut self) {
        let wanted: HashSet<u32> = self
            .requested_traffic
            .iter()
            .copied()
            .filter(|address| {
                self.aircraft
                    .get(address)
                    .is_none_or(|aircraft| !aircraft.adsb_good)
            })
            .collect();
        self.interested_mlat = wanted;
    }

    /// The coordinator's half-second `heartbeat` and the server connection's: the periodic
    /// aircraft update, the seen/lost and rate reports, and the client heartbeat line.
    /// `wall_secs` is Unix time, for the heartbeat's `client_time`.
    pub fn heartbeat(&mut self, now: f64, wall_secs: f64, jitter: f64) {
        if let Some(at) = self.server_heartbeat_at
            && at < now
        {
            self.server_heartbeat_at = Some(now + SERVER_HEARTBEAT_INTERVAL);
            self.lines.push(protocol::heartbeat_line(wall_secs));
        }
        if now >= self.next_aircraft_update {
            self.next_aircraft_update = now + UPDATE_INTERVAL + jitter;
            self.update_aircraft(now);
            // "piggyback reporting on regular updates".
            if let Some(next_report) = self.next_report.as_mut() {
                *next_report += 1.0;
                if *next_report >= REPORT_INTERVAL {
                    *next_report = 0.0;
                    self.send_aircraft_report();
                    self.send_rate_report(now);
                }
            }
        }
    }

    /// `update_aircraft`.
    fn update_aircraft(&mut self, now: f64) {
        // `receiver.recent_aircraft()`: every address seen since the last call, filtered or not.
        for address in std::mem::take(&mut self.seen) {
            let requested = self.requested_traffic.contains(&address);
            let aircraft = self
                .aircraft
                .entry(address)
                .or_insert_with(|| Aircraft::new(requested, now));
            if aircraft.last_message_time <= self.last_aircraft_update {
                // "fudge it a bit, receiver has seen messages but they were all filtered".
                aircraft.messages += 1;
                aircraft.last_message_time = now;
            }
            aircraft.adsb_good = now - aircraft.last_even_time < POSITION_EXPIRY_AGE
                && now - aircraft.last_odd_time < POSITION_EXPIRY_AGE;
        }
        self.aircraft
            .retain(|_, aircraft| now - aircraft.last_message_time <= EXPIRY_AGE);
        self.last_aircraft_update = now;
    }

    /// `send_aircraft_report`: aircraft heard more than once, as changes since the last report.
    fn send_aircraft_report(&mut self) {
        let all: BTreeSet<u32> = self
            .aircraft
            .iter()
            .filter(|(_, aircraft)| aircraft.messages > 1)
            .map(|(address, _)| *address)
            .collect();
        let seen: Vec<u32> = all.difference(&self.reported).copied().collect();
        let lost: Vec<u32> = self.reported.difference(&all).copied().collect();
        if !seen.is_empty() {
            self.lines.push(protocol::addresses_line("seen", &seen));
        }
        if !lost.is_empty() {
            self.lines.push(protocol::addresses_line("lost", &lost));
        }
        self.reported = all;
    }

    /// `send_rate_report`: ADS-B positions per second since the last report, per aircraft.
    fn send_rate_report(&mut self, now: f64) {
        let mut rates = Vec::new();
        let mut addresses: Vec<u32> = self.aircraft.keys().copied().collect();
        addresses.sort_unstable();
        for address in addresses {
            let Some(aircraft) = self.aircraft.get_mut(&address) else {
                continue;
            };
            let interval = now - aircraft.rate_measurement_start;
            if interval > 0.0 && aircraft.recent_adsb_positions > 0 {
                rates.push((
                    address,
                    f64::from(aircraft.recent_adsb_positions) / interval,
                ));
                aircraft.rate_measurement_start = now;
                aircraft.recent_adsb_positions = 0;
            }
        }
        if !rates.is_empty() {
            self.lines.push(protocol::rate_report_line(&rates));
        }
    }

    /// One reception, raw from the receiver, through mlat-client's reader and coordinator.
    pub fn observe(&mut self, observation: &Observation, now: f64) {
        // `feed_beast`: Mode A/C (`'1'`) is skipped before any timestamp handling; only Mode S
        // short and long are messages. Anything else is not BEAST.
        let length = match observation.format {
            format::MODE_S_SHORT => 7,
            format::MODE_S_LONG => 14,
            _ => return,
        };
        if observation.data.len() != length {
            return;
        }
        let Some(timestamp) = self.reader_timestamp(observation) else {
            return;
        };
        let message = Message::decode(timestamp, &observation.data);
        if !self.filter(&message) {
            return;
        }
        // `Coordinator.df_handlers`.
        match message.df {
            0 | 4 | 5 | 16 | 20 | 21 => self.received_df_misc(message, now),
            11 => self.received_df11(message, now),
            17 => self.received_df17(message, now),
            _ => {}
        }
    }

    /// `feed_beast`'s timestamp handling: the per-format adjustment to the start of the frame,
    /// the GPS clock's conversion to contiguous nanoseconds, the midnight rollover, and
    /// `timestamp_update`. `None` when the message is dropped here.
    ///
    /// mlat-client also compares each counter with its own clock as the bytes arrive
    /// (`timestamp_check`); a Tally receiver's counters arrive a batch at a time, so that check is
    /// made per batch instead (`playout.rs`, which calls `clock_jump`), and a restarted counter is
    /// the batch's `counter_epoch` (`station.rs`).
    fn reader_timestamp(&mut self, observation: &Observation) -> Option<u64> {
        let mut timestamp = observation.timestamp;
        if !synthetic(timestamp) {
            match self.mode {
                Mode::Beast => {
                    // "Mode S short, timestamp reported at end of frame ... 768 cycles at 12MHz";
                    // "Mode S long, timestamp reported halfway through the frame (at bit 56)".
                    timestamp = timestamp.saturating_sub(768);
                }
                Mode::Radarcape => {
                    let nanos = timestamp & 0x3fff_ffff;
                    let mut secs = timestamp >> 30;
                    // `radarcape_utc_bugfix` is learned from status frames (`'4'`), which Tally
                    // does not carry, so it stays 0 as in a reader that never saw one: the
                    // receiver's second is taken to be one ahead of UTC.
                    secs = if secs == 0 { 86_399 } else { secs - 1 };
                    timestamp = nanos + secs * 1_000_000_000;
                    let adjust = if observation.format == format::MODE_S_SHORT {
                        64_000
                    } else {
                        120_000
                    };
                    timestamp = if adjust <= timestamp {
                        timestamp - adjust
                    } else {
                        timestamp + DAY_NS - adjust
                    };
                    if self.last_timestamp >= 86_340 * 1_000_000_000
                        && timestamp <= 60 * 1_000_000_000
                    {
                        self.lines.push(protocol::epoch_rollover_line());
                    }
                }
            }
            self.timestamp_update(timestamp);
        }
        Some(timestamp)
    }

    /// `timestamp_update`.
    fn timestamp_update(&mut self, timestamp: u64) {
        if self.last_timestamp == 0 {
            self.last_timestamp = timestamp;
            return;
        }
        let frequency = self.mode.frequency();
        if self.last_timestamp > timestamp && self.last_timestamp - timestamp < 90 * frequency {
            // "ignore small moves backwards".
            return;
        }
        if self.mode == Mode::Radarcape
            && timestamp >= 86_340 * 1_000_000_000
            && self.last_timestamp <= 60 * 1_000_000_000
        {
            // "don't allow last_timestamp to roll back to the previous day".
            return;
        }
        self.last_timestamp = timestamp;
    }

    /// `filter_message`, with `ReceiverConnection`'s filters: every DF17, and the mlat formats
    /// only for the addresses in `interested_mlat`. Records the seen set on the way.
    fn filter(&mut self, message: &Message) -> bool {
        if message.timestamp == MAGIC_MLAT_TIMESTAMP {
            return false;
        }
        if self.last_timestamp > message.timestamp {
            // "Ignore messages that jump backwards".
            return false;
        }
        if !message.valid {
            return false;
        }
        if matches!(message.df, 11 | 17 | 18)
            && let Some(address) = message.address
        {
            self.seen.insert(address);
        }
        if message.timestamp == 0 {
            return false;
        }
        match message.df {
            17 => true,
            0 | 4 | 5 | 11 | 16 | 20 | 21 => message
                .address
                .is_some_and(|address| self.interested_mlat.contains(&address)),
            _ => false,
        }
    }

    /// `received_df_misc`: an address/parity reply from a known aircraft.
    fn received_df_misc(&mut self, message: Message, now: f64) {
        let Some(address) = message.address else {
            return;
        };
        let Some(aircraft) = self.aircraft.get_mut(&address) else {
            return;
        };
        aircraft.messages += 1;
        aircraft.last_message_time = now;
        if aircraft.messages < MESSAGES_BEFORE_USE || !aircraft.requested || aircraft.adsb_good {
            return;
        }
        self.lines.push(protocol::mlat_line(&message));
    }

    /// `received_df11`.
    fn received_df11(&mut self, message: Message, now: f64) {
        let Some(address) = message.address else {
            return;
        };
        let Some(aircraft) = self.aircraft.get_mut(&address) else {
            let mut aircraft = Aircraft::new(self.requested_traffic.contains(&address), now);
            aircraft.messages += 1;
            aircraft.last_message_time = now;
            self.aircraft.insert(address, aircraft);
            return;
        };
        aircraft.messages += 1;
        aircraft.last_message_time = now;
        if aircraft.messages < MESSAGES_BEFORE_USE || !aircraft.requested || aircraft.adsb_good {
            return;
        }
        self.lines.push(protocol::mlat_line(&message));
    }

    /// `received_df17`: an ADS-B position pair close in time, with altitude and NUCp >= 6, is a
    /// sync message for an aircraft the server asked for.
    fn received_df17(&mut self, message: Message, now: f64) {
        let Some(address) = message.address else {
            return;
        };
        let Some(aircraft) = self.aircraft.get_mut(&address) else {
            let mut aircraft = Aircraft::new(self.requested_traffic.contains(&address), now);
            aircraft.messages += 1;
            aircraft.last_message_time = now;
            self.aircraft.insert(address, aircraft);
            return;
        };
        aircraft.messages += 1;
        aircraft.last_message_time = now;
        if aircraft.messages < MESSAGES_BEFORE_USE {
            return;
        }
        if !message.even_cpr && !message.odd_cpr {
            return;
        }
        if !message.valid {
            return;
        }
        let even = message.even_cpr;
        let altitude = message.altitude;
        let nuc = message.nuc;
        if even {
            aircraft.even_message = Some(message);
        } else {
            aircraft.odd_message = Some(message);
        }
        let (Some(even_message), Some(odd_message)) =
            (&aircraft.even_message, &aircraft.odd_message)
        else {
            return;
        };
        if even_message.timestamp.abs_diff(odd_message.timestamp) > 5 * self.mode.frequency() {
            return;
        }
        if altitude.is_none() || nuc < MIN_NUC {
            return;
        }
        aircraft.recent_adsb_positions += 1;
        if even {
            aircraft.last_even_time = now;
        } else {
            aircraft.last_odd_time = now;
        }
        aircraft.adsb_good = now - aircraft.last_even_time < POSITION_EXPIRY_AGE
            && now - aircraft.last_odd_time < POSITION_EXPIRY_AGE;
        if !aircraft.requested {
            return;
        }
        let line = if self.split_sync {
            // The server asked for one reference message at a time.
            let latest = if even { even_message } else { odd_message };
            protocol::split_sync_line(latest)
        } else {
            protocol::sync_line(even_message, odd_message)
        };
        self.lines.push(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modes::crc;
    use crate::modes::tests::{EVEN, ODD, bytes};

    fn long(timestamp: u64, hex: &str) -> Observation {
        Observation {
            format: format::MODE_S_LONG,
            timestamp,
            signal: 100,
            data: bytes(hex),
        }
    }

    fn short(timestamp: u64, data: Vec<u8>) -> Observation {
        Observation {
            format: format::MODE_S_SHORT,
            timestamp,
            signal: 100,
            data,
        }
    }

    /// A DF4 (surveillance altitude reply) whose parity overlays `address`.
    fn df4(address: u32) -> Vec<u8> {
        let mut data = vec![0x20, 0x00, 0x1b, 0x30];
        let parity = crc(&data) ^ address;
        data.extend_from_slice(&[(parity >> 16) as u8, (parity >> 8) as u8, parity as u8]);
        data
    }

    fn connected(now: f64) -> Client {
        let mut client = Client::new(Mode::Beast, now);
        client.server_connected(false, now, 0.0);
        client.input_connected();
        client.take_lines();
        client
    }

    #[test]
    fn connecting_says_what_mlat_client_says_in_its_order() {
        let mut client = Client::new(Mode::Beast, 0.0);
        client.server_connected(false, 0.0, 0.5);
        client.input_connected();
        assert_eq!(
            client.take_lines(),
            vec![
                r#"{"rate_report":{}}"#.to_owned(),
                r#"{"input_connected":"connected"}"#.to_owned(),
                r#"{"clock_reset":{"reason":"Decoder mode changed to BEAST","frequency":12000000,"epoch":null,"mode":"BEAST"}}"#.to_owned(),
            ]
        );
    }

    #[test]
    fn a_position_pair_becomes_a_sync_message_after_ten_messages_of_a_requested_aircraft() {
        let mut client = connected(0.0);
        client.start_sending(&[0x40621d]);
        let mut lines = Vec::new();
        for n in 0..12u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            client.observe(&long(1_000_000 + n * 6_000_000, hex), n as f64 * 0.5);
            lines.extend(client.take_lines());
        }
        // The tenth message (an odd one) is the first kept; each message after it completes a
        // pair: two syncs, each with the latest even and odd, timestamps 768 ticks earlier.
        let at = |n: u64| 1_000_000 + n * 6_000_000 - 768;
        assert_eq!(
            lines,
            vec![
                format!(
                    r#"{{"sync":{{"et":{},"em":"{EVEN}","ot":{},"om":"{ODD}"}}}}"#,
                    at(10),
                    at(9)
                ),
                format!(
                    r#"{{"sync":{{"et":{},"em":"{EVEN}","ot":{},"om":"{ODD}"}}}}"#,
                    at(10),
                    at(11)
                ),
            ]
        );
    }

    #[test]
    fn an_aircraft_the_server_did_not_ask_for_gives_no_sync() {
        let mut client = connected(0.0);
        for n in 0..20u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            client.observe(&long(1_000 + n * 6_000_000, hex), n as f64);
        }
        assert!(client.take_lines().is_empty());
    }

    #[test]
    fn a_pair_further_apart_than_five_seconds_is_not_a_sync() {
        let mut client = connected(0.0);
        client.start_sending(&[0x40621d]);
        for n in 0..12u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            // Six seconds of 12 MHz between messages.
            client.observe(&long(1_000 + n * 72_000_000, hex), n as f64);
        }
        assert!(client.take_lines().is_empty());
    }

    #[test]
    fn split_sync_sends_each_reference_message_alone() {
        let mut client = Client::new(Mode::Beast, 0.0);
        client.server_connected(true, 0.0, 0.0);
        client.take_lines();
        client.start_sending(&[0x40621d]);
        for n in 0..12u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            client.observe(&long(10_000 + n * 1_000, hex), 0.0);
        }
        let at = |n: u64| 10_000 + n * 1_000 - 768;
        assert_eq!(
            client.take_lines(),
            vec![
                format!(r#"{{"ssync":{{"t":{},"m":"{EVEN}"}}}}"#, at(10)),
                format!(r#"{{"ssync":{{"t":{},"m":"{ODD}"}}}}"#, at(11)),
            ]
        );
    }

    #[test]
    fn mode_s_replies_are_mlat_messages_for_requested_aircraft_without_adsb() {
        let address = 0xabcdef;
        let mut client = connected(0.0);
        // Not yet asked for: the reader filters DF4 out entirely, so it never becomes known.
        client.observe(&short(5_000, df4(address)), 0.0);
        client.start_sending(&[address]);
        // A DF4 alone never creates an aircraft (`received_df_misc` returns for an unknown one),
        // so the aircraft is made known through the seen set and the periodic update.
        client.seen.insert(address);
        client.heartbeat(1.0, 0.0, 0.0);
        client.take_lines();
        let mut lines = Vec::new();
        for n in 0..10u64 {
            client.observe(&short(10_000 + n * 1_000, df4(address)), 2.0);
            lines.extend(client.take_lines());
        }
        // The update counted one message; the ninth DF4 here is its tenth.
        assert_eq!(
            lines,
            vec![
                format!(
                    r#"{{"mlat":{{"t":{},"m":"{}"}}}}"#,
                    10_000 + 8 * 1_000 - 768,
                    crate::modes::hex(&df4(address))
                ),
                format!(
                    r#"{{"mlat":{{"t":{},"m":"{}"}}}}"#,
                    10_000 + 9 * 1_000 - 768,
                    crate::modes::hex(&df4(address))
                ),
            ]
        );
        client.stop_sending(&[address]);
        client.observe(&short(30_000, df4(address)), 3.0);
        assert!(client.take_lines().is_empty());
    }

    #[test]
    fn an_aircraft_with_good_adsb_is_not_multilaterated() {
        let mut client = connected(0.0);
        client.start_sending(&[0x40621d]);
        for n in 0..12u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            client.observe(&long(1_000 + n * 6_000_000, hex), 1.0);
        }
        client.take_lines();
        // The filter is recomputed only on the next request from the server, as in mlat-client.
        client.start_sending(&[]);
        assert!(!client.interested_mlat.contains(&0x40621d));
    }

    #[test]
    fn readsbs_own_mlat_results_and_older_timestamps_are_dropped() {
        let mut client = connected(0.0);
        client.start_sending(&[0x40621d]);
        for n in 0..9u64 {
            client.observe(&long(1_000_000_000 + n, EVEN), 0.0);
        }
        client.observe(&long(MAGIC_MLAT_TIMESTAMP, ODD), 0.0);
        // A minute behind: a "small move backwards", ignored by the reader and dropped.
        client.observe(&long(1_000_000_000 - 60 * 12_000_000, ODD), 0.0);
        assert!(client.take_lines().is_empty());
        assert_eq!(
            client
                .aircraft
                .get(&0x40621d)
                .map(|aircraft| aircraft.messages),
            Some(9)
        );
    }

    #[test]
    fn the_periodic_report_names_seen_aircraft_and_their_position_rate() {
        let mut client = Client::new(Mode::Beast, 0.0);
        // jitter 0.75: the first report comes on the first update (0.75 * 4 + 1 >= 4).
        client.server_connected(false, 0.0, 0.75);
        client.take_lines();
        for n in 0..12u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            client.observe(&long(1_000 + n * 6_000_000, hex), 1.0);
        }
        client.heartbeat(5.0, 0.0, 0.0);
        assert_eq!(
            client.take_lines(),
            vec![
                r#"{"seen":["40621d"]}"#.to_owned(),
                // Two positions in the four seconds since the aircraft was first heard, at 1.0.
                r#"{"rate_report":{"40621D":0.5}}"#.to_owned(),
            ]
        );
        // Silent past the expiry age: reported lost.
        client.heartbeat(200.0, 0.0, 0.0);
        client.heartbeat(205.0, 0.0, 0.0);
        client.heartbeat(210.0, 0.0, 0.0);
        client.heartbeat(215.0, 0.0, 0.0);
        let lines = client.take_lines();
        assert!(
            lines.contains(&r#"{"lost":["40621d"]}"#.to_owned()),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with(r#"{"heartbeat":"#))
        );
    }

    #[test]
    fn a_restarted_input_is_announced_and_forgets_everything() {
        let mut client = Client::new(Mode::Beast, 0.0);
        client.server_connected(false, 0.0, 0.75);
        for n in 0..4u64 {
            client.observe(&long(1_000 + n * 6_000_000, EVEN), 1.0);
        }
        client.heartbeat(5.0, 0.0, 0.0);
        client.take_lines();
        client.input_disconnected();
        client.input_connected();
        assert_eq!(
            client.take_lines(),
            vec![
                r#"{"input_disconnected":"disconnected"}"#.to_owned(),
                r#"{"lost":["40621d"]}"#.to_owned(),
                r#"{"input_connected":"connected"}"#.to_owned(),
                protocol::mode_change_line(Mode::Beast),
            ]
        );
        assert!(client.aircraft.is_empty());
        assert_eq!(client.last_timestamp, 0);
    }

    #[test]
    fn a_gps_clock_is_converted_to_nanoseconds_since_midnight_before_it_is_sent() {
        let mut client = Client::new(Mode::Radarcape, 0.0);
        client.server_connected(false, 0.0, 0.0);
        client.take_lines();
        client.start_sending(&[0x40621d]);
        // 3600 s and 500 µs on the receiver's clock, which runs a second ahead of UTC.
        let raw = (3_600u64 << 30) | 500_000;
        for n in 0..11u64 {
            let hex = if n % 2 == 0 { EVEN } else { ODD };
            client.observe(&long(raw + n, hex), 0.0);
        }
        let expected = |n: u64| 3_599 * 1_000_000_000 + 500_000 + n - 120_000;
        assert_eq!(
            client.take_lines(),
            vec![format!(
                r#"{{"sync":{{"et":{},"em":"{EVEN}","ot":{},"om":"{ODD}"}}}}"#,
                expected(10),
                expected(9)
            )]
        );
    }

    #[test]
    fn clock_jumps_are_reported_at_most_twice_a_second() {
        let mut client = connected(0.0);
        client.clock_jump(1.0);
        client.clock_jump(1.2);
        client.clock_jump(1.6);
        assert_eq!(
            client.take_lines(),
            vec![protocol::clock_jump_line(), protocol::clock_jump_line()]
        );
    }
}
