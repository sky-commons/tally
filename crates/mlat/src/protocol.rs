//! mlat-client's JSON protocol, client side: what the engine says to an unmodified mlat-server on
//! a receiver's behalf, and what it understands of the answers. Every line is written the way
//! mlat-client 0.4.2 writes it (`mlat/client/jsonclient.py`,
//! <https://github.com/wiedehopf/mlat-client/blob/master/mlat/client/jsonclient.py>), down to the
//! byte, and read the way mlat-server writes it (`mlat/jsonclient.py`,
//! <https://github.com/wiedehopf/mlat-server/blob/master/mlat/jsonclient.py>).
//!
//! Transport: plain TCP, newline-terminated JSON. The engine offers only `"compress": ["none"]`,
//! which mlat-server accepts (its `_compression_methods` include `none`), and no UDP
//! (`"udp_transport": false`), so everything stays on the one TCP connection.

use serde_json::Value;
use tally_wire::{Clock, Location, PublicKey};

use crate::modes::{Message, hex};

/// The client protocol version mlat-client speaks (`handshake_msg['version']`).
const PROTOCOL_VERSION: u32 = 3;
/// What the engine reports as its client version. mlat-server only logs it (`conn_info`).
const CLIENT_VERSION: &str = concat!("tally-mlat ", env!("CARGO_PKG_VERSION"));
/// mlat-client pads its handshake with 128 spaces before the newline (`16 * '        '`).
const HANDSHAKE_PADDING: usize = 128;
/// Metres per foot. mlat-client divides by 0.3038, a typo; the engine uses the real value.
const METRES_PER_FOOT: f64 = 0.3048;

/// How mlat-client names and paces a receiver's clock: `_receiver_types` in
/// `mlat/client/options.py` gives the decoder mode and the server clock type, and
/// `set_decoder_mode` in `modes_reader.c` the frequency and epoch of that mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `_modes.BEAST`: a 12 MHz counter, no epoch.
    Beast,
    /// `_modes.RADARCAPE`: nanoseconds since UTC midnight.
    Radarcape,
}

impl Mode {
    pub fn frequency(self) -> u64 {
        match self {
            Self::Beast => 12_000_000,
            Self::Radarcape => 1_000_000_000,
        }
    }

    pub fn epoch(self) -> Option<&'static str> {
        match self {
            Self::Beast => None,
            Self::Radarcape => Some("utc_midnight"),
        }
    }

    /// The reader's mode name, as the mode-change event reports it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Beast => "BEAST",
            Self::Radarcape => "RADARCAPE",
        }
    }

    /// Seconds on the receiver's own clock, for pacing only (`playout.rs`).
    pub fn seconds(self, raw: u64) -> f64 {
        match self {
            Self::Beast => raw as f64 / 12e6,
            Self::Radarcape => (raw >> 30) as f64 + (raw & 0x3fff_ffff) as f64 / 1e9,
        }
    }
}

/// A Tally receiver as the mlat-server will know it.
#[derive(Clone, Debug, PartialEq)]
pub struct Station {
    pub user: String,
    pub uuid: String,
    pub lat: f64,
    pub lon: f64,
    /// Metres above the WGS84 ellipsoid, which is what mlat-client's `--alt` is.
    pub alt: f64,
    /// The server clock type (`clock_type` in the handshake).
    pub clock_type: &'static str,
    pub mode: Mode,
}

impl Station {
    /// The station for a receiver, or `None` when mlat-server could not use it: no location, a
    /// location the owner rounded (MLAT needs the antenna exactly), or a clock mlat-client has no
    /// type for.
    pub fn of(key: &PublicKey, location: Option<Location>, clock: Clock) -> Option<Self> {
        let location = location.filter(|location| location.precision_m == 0)?;
        // `_receiver_types`: dump1090, beast and radarcape_12mhz are BEAST-mode 12 MHz clocks;
        // radarcape_gps is RADARCAPE mode. "auto"/"unknown" leaves the clock to autodetection,
        // which a counter carried without its status frames cannot do, so those are skipped.
        let (clock_type, mode) = match clock {
            Clock::Dump1090 => ("dump1090", Mode::Beast),
            Clock::Beast => ("beast", Mode::Beast),
            Clock::Radarcape12Mhz => ("radarcape_12mhz", Mode::Beast),
            Clock::RadarcapeGps => ("radarcape_gps", Mode::Radarcape),
            Clock::Unknown | Clock::Other(_) => return None,
        };
        let bytes = key.as_bytes();
        Some(Self {
            // mlat-server keeps `[A-Za-z0-9_.-]` and the first 40 characters, and a base64 key
            // has `+`, `/` and `=` and is 44 long, so the user is a hex prefix of the key: 96
            // bits, stable, and unique among any population of receivers.
            user: format!("tally-{}", hex(&bytes[..12])),
            uuid: uuid(bytes),
            lat: f64::from(location.lat_e7) / 1e7,
            lon: f64::from(location.lon_e7) / 1e7,
            alt: f64::from(location.alt_m),
            clock_type,
            mode,
        })
    }

    /// The handshake line, as `JsonServerConnection.start_connection` writes it:
    /// `json.dumps(handshake_msg, sort_keys=True)` (default separators, so `", "` and `": "`),
    /// 128 spaces, a newline. `return_results` is always on: results are the engine's output.
    pub fn handshake(&self) -> String {
        let epoch = self
            .mode
            .epoch()
            .map_or_else(|| "null".to_owned(), |epoch| format!("\"{epoch}\""));
        let fields = [
            ("alt", python_float(self.alt)),
            ("client_version", format!("\"{CLIENT_VERSION}\"")),
            ("clock_epoch", epoch),
            ("clock_frequency", self.mode.frequency().to_string()),
            ("clock_type", format!("\"{}\"", self.clock_type)),
            ("compress", "[\"none\"]".to_owned()),
            ("heartbeat", "true".to_owned()),
            ("lat", python_float(self.lat)),
            ("lon", python_float(self.lon)),
            // The owner never chose to appear on this server's coverage map.
            ("privacy", "true".to_owned()),
            ("return_result_format", "\"ecef\"".to_owned()),
            ("return_results", "true".to_owned()),
            ("return_stats", "true".to_owned()),
            ("selective_traffic", "true".to_owned()),
            ("udp_transport", "false".to_owned()),
            ("user", format!("\"{}\"", self.user)),
            ("uuid", format!("\"{}\"", self.uuid)),
            ("version", PROTOCOL_VERSION.to_string()),
        ];
        let body: Vec<String> = fields
            .iter()
            .map(|(key, value)| format!("\"{key}\": {value}"))
            .collect();
        format!("{{{}}}{}\n", body.join(", "), " ".repeat(HANDSHAKE_PADDING))
    }
}

/// A UUID derived from the receiver's key: the same receiver is the same uuid on every
/// connection, which is what lets mlat-server replace a stale session of it (`process_handshake`
/// closes an existing receiver whose user and uuid both match). Version 8 (custom), RFC 9562.
fn uuid(key: &[u8; 32]) -> String {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&key[16..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let text = hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    )
}

/// Python's `repr` of a float, which is what `json.dumps` writes: the shortest digits that read
/// back, a `.0` on integral values, and an exponent below 1e-4 or from 1e16.
pub fn python_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_owned();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if (-4..16).contains(&exponent) {
        let plain = format!("{value}");
        if plain.contains('.') {
            plain
        } else {
            format!("{plain}.0")
        }
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{mantissa}e{sign}{:02}", exponent.unsigned_abs())
    }
}

/// Python's `round(value, digits)`, near enough: it differs only on exact binary halves.
pub fn python_round(value: f64, digits: i32) -> f64 {
    let scale = 10f64.powi(digits);
    (value * scale).round() / scale
}

// The lines a client sends once the handshake is done. `_send_json` uses
// `json.dumps(o, separators=(',', ':'))`; the sync and mlat lines are formatted by hand
// (`send_tcp_sync`, `send_tcp_mlat`, `send_tcp_split_sync`), in this key order.

pub fn sync_line(even: &Message, odd: &Message) -> String {
    format!(
        "{{\"sync\":{{\"et\":{},\"em\":\"{}\",\"ot\":{},\"om\":\"{}\"}}}}",
        even.timestamp,
        even.hex(),
        odd.timestamp,
        odd.hex()
    )
}

pub fn split_sync_line(message: &Message) -> String {
    format!(
        "{{\"ssync\":{{\"t\":{},\"m\":\"{}\"}}}}",
        message.timestamp,
        message.hex()
    )
}

pub fn mlat_line(message: &Message) -> String {
    format!(
        "{{\"mlat\":{{\"t\":{},\"m\":\"{}\"}}}}",
        message.timestamp,
        message.hex()
    )
}

/// `send_seen` and `send_lost`: addresses as `'{0:06x}'`. mlat-client sends a Python set, in
/// whatever order it iterates; the server makes a set of it, so the engine sends them sorted.
pub fn addresses_line(kind: &str, addresses: &[u32]) -> String {
    let list: Vec<String> = addresses
        .iter()
        .map(|address| format!("\"{address:06x}\""))
        .collect();
    format!("{{\"{kind}\":[{}]}}", list.join(","))
}

/// `send_rate_report`: upper-case addresses (`'{0:06X}'`), rates `round(v, 2)`.
pub fn rate_report_line(rates: &[(u32, f64)]) -> String {
    let entries: Vec<String> = rates
        .iter()
        .map(|(address, rate)| {
            format!("\"{address:06X}\":{}", python_float(python_round(*rate, 2)))
        })
        .collect();
    format!("{{\"rate_report\":{{{}}}}}", entries.join(","))
}

pub fn input_connected_line() -> String {
    "{\"input_connected\":\"connected\"}".to_owned()
}

pub fn input_disconnected_line() -> String {
    "{\"input_disconnected\":\"disconnected\"}".to_owned()
}

/// `send_clock_reset` for a decoder mode change, which mlat-client synthesises every time its
/// input connects (`mode_change_event` in receiver.py, `received_mode_change_event`).
pub fn mode_change_line(mode: Mode) -> String {
    let epoch = mode
        .epoch()
        .map_or_else(|| "null".to_owned(), |epoch| format!("\"{epoch}\""));
    format!(
        "{{\"clock_reset\":{{\"reason\":\"Decoder mode changed to {}\",\"frequency\":{},\"epoch\":{},\"mode\":\"{}\"}}}}",
        mode.name(),
        mode.frequency(),
        epoch,
        mode.name()
    )
}

/// `send_clock_reset('Epoch rollover detected')`, for a GPS clock passing UTC midnight.
pub fn epoch_rollover_line() -> String {
    "{\"clock_reset\":{\"reason\":\"Epoch rollover detected\"}}".to_owned()
}

pub fn clock_jump_line() -> String {
    "{\"clock_jump\":true}".to_owned()
}

/// `{'heartbeat': {'client_time': round(time.time(), 3)}}`.
pub fn heartbeat_line(wall_secs: f64) -> String {
    format!(
        "{{\"heartbeat\":{{\"client_time\":{}}}}}",
        python_float(python_round(wall_secs, 3))
    )
}

/// The server's answer to the handshake (`process_handshake`'s `response`, or its `deny`).
#[derive(Debug, PartialEq)]
pub enum Welcome {
    Accepted {
        /// `split_sync` true asks for one `ssync` per position instead of `sync` pairs.
        split_sync: bool,
        /// How long to wait before reconnecting after this session ends.
        reconnect_in: Option<f64>,
    },
    Denied {
        reasons: Vec<String>,
        reconnect_in: Option<f64>,
    },
}

/// Reads the handshake answer as `handle_handshake_response` does.
pub fn welcome(line: &str) -> Result<Welcome, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let reconnect_in = value.get("reconnect_in").and_then(Value::as_f64);
    if let Some(deny) = value.get("deny") {
        let reasons = deny
            .as_array()
            .map(|reasons| {
                reasons
                    .iter()
                    .map(|reason| reason.as_str().unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        return Ok(Welcome::Denied {
            reasons,
            reconnect_in,
        });
    }
    match value.get("compress").and_then(Value::as_str) {
        Some("none") => {}
        other => return Err(format!("the server chose compression {other:?}, not none")),
    }
    if value.get("udp_transport").is_some() {
        return Err("the server assigned UDP transport, which was not offered".to_owned());
    }
    Ok(Welcome::Accepted {
        split_sync: value
            .get("split_sync")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reconnect_in,
    })
}

/// A solved position as the server returns it to a receiver that took part.
#[derive(Clone, Debug, PartialEq)]
pub struct Solution {
    pub address: u32,
    /// `@`: the server's clock, Unix seconds, when the copies of the message reached it.
    pub at: f64,
    pub lat: f64,
    pub lon: f64,
    pub alt_ft: Option<f64>,
    /// One standard deviation of the horizontal position, metres, when the server gave one.
    pub sigma_m: Option<f64>,
    /// Distinct receivers the solution used (`nd`, or `nstations` in the old format).
    pub receivers: u32,
}

/// What the server can send once the handshake is done (`handle_connected_request`).
#[derive(Debug, PartialEq)]
pub enum Request {
    StartSending(Vec<u32>),
    StopSending(Vec<u32>),
    Result(Solution),
    /// Heartbeats, statistics and anything else: nothing to do but note the server is alive.
    Other,
}

pub fn request(line: &str) -> Result<Request, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    if let Some(list) = value.get("start_sending") {
        return Ok(Request::StartSending(addresses(list)?));
    }
    if let Some(list) = value.get("stop_sending") {
        return Ok(Request::StopSending(addresses(list)?));
    }
    if value.get("heartbeat").is_some() {
        return Ok(Request::Other);
    }
    if let Some(result) = value.get("result") {
        return solution(result).map(Request::Result);
    }
    Ok(Request::Other)
}

fn addresses(list: &Value) -> Result<Vec<u32>, String> {
    list.as_array()
        .ok_or_else(|| "an address list that is not a list".to_owned())?
        .iter()
        .map(|address| {
            address
                .as_str()
                .and_then(|text| u32::from_str_radix(text, 16).ok())
                .ok_or_else(|| format!("bad address {address}"))
        })
        .collect()
}

/// A `result`, in the `ecef` format the handshake asks for, or the old format, read as
/// mlat-client reads them.
fn solution(result: &Value) -> Result<Solution, String> {
    let field = |name: &str| {
        result
            .get(name)
            .and_then(Value::as_f64)
            .ok_or_else(|| format!("result without {name}"))
    };
    let address = result
        .get("addr")
        .and_then(Value::as_str)
        .and_then(|text| u32::from_str_radix(text, 16).ok())
        .ok_or_else(|| "result without addr".to_owned())?;
    let at = field("@")?;
    match result.get("ecef").filter(|ecef| !ecef.is_null()) {
        Some(ecef) => {
            let ecef = triple(ecef).ok_or_else(|| "bad ecef".to_owned())?;
            let (lat, lon, alt_m) = ecef_to_llh(ecef);
            let cov: Option<Vec<f64>> = result
                .get("cov")
                .and_then(Value::as_array)
                .and_then(|cov| cov.iter().map(Value::as_f64).collect());
            let sigma_m = cov
                .as_deref()
                .and_then(|cov| horizontal_sigma(cov, lat, lon));
            Ok(Solution {
                address,
                at,
                lat,
                lon,
                alt_ft: Some(alt_m / METRES_PER_FOOT),
                sigma_m,
                receivers: field("nd")? as u32,
            })
        }
        None => Ok(Solution {
            address,
            at,
            lat: field("lat")?,
            lon: field("lon")?,
            alt_ft: result.get("alt").and_then(Value::as_f64),
            // mlat-client's own guess for the old format: `result['gdop'] * 300`.
            sigma_m: result
                .get("gdop")
                .and_then(Value::as_f64)
                .map(|gdop| gdop * 300.0)
                .filter(|sigma| *sigma > 0.0),
            receivers: field("nstations")? as u32,
        }),
    }
}

fn triple(value: &Value) -> Option<[f64; 3]> {
    let list = value.as_array()?;
    Some([
        list.first()?.as_f64()?,
        list.get(1)?.as_f64()?,
        list.get(2)?.as_f64()?,
    ])
}

// WGS84, as mlat/geodesy.py defines it.
const WGS84_A: f64 = 6_378_137.0;
const WGS84_F: f64 = 1.0 / 298.257_223_563;
const WGS84_B: f64 = WGS84_A * (1.0 - WGS84_F);
const WGS84_ECC_SQ: f64 = 1.0 - WGS84_B * WGS84_B / (WGS84_A * WGS84_A);

/// `ecef2llh` in mlat/geodesy.py (Bowring's method): degrees, degrees, metres.
pub fn ecef_to_llh([x, y, z]: [f64; 3]) -> (f64, f64, f64) {
    let ep2_b = (WGS84_A * WGS84_A - WGS84_B * WGS84_B) / (WGS84_B * WGS84_B) * WGS84_B;
    let e2_a = WGS84_ECC_SQ * WGS84_A;
    let lon = y.atan2(x);
    let p = (x * x + y * y).sqrt();
    let th = (WGS84_A * z).atan2(WGS84_B * p);
    let lat = (z + ep2_b * th.sin().powi(3)).atan2(p - e2_a * th.cos().powi(3));
    let n = WGS84_A / (1.0 - WGS84_ECC_SQ * lat.sin().powi(2)).sqrt();
    let alt = p / lat.cos() - n;
    (lat.to_degrees(), lon.to_degrees(), alt)
}

/// `llh2ecef` in mlat/geodesy.py.
pub fn llh_to_ecef(lat: f64, lon: f64, alt: f64) -> [f64; 3] {
    let (lat, lon) = (lat.to_radians(), lon.to_radians());
    let d = (1.0 - lat.sin() * lat.sin() * WGS84_ECC_SQ).sqrt();
    let rn = WGS84_A / d;
    [
        (rn + alt) * lat.cos() * lon.cos(),
        (rn + alt) * lat.cos() * lon.sin(),
        (rn * (1.0 - WGS84_ECC_SQ) + alt) * lat.sin(),
    ]
}

/// The horizontal standard deviation (DRMS) of an ECEF covariance, `cov` being the server's
/// upper triangle `(xx, xy, xz, yy, yz, zz)`: the east and north variances, rotated out at the
/// solved position. mlat-client reports `sqrt(xx + yy + zz)`, which folds in the vertical; a
/// `Position` promises horizontal.
pub fn horizontal_sigma(cov: &[f64], lat: f64, lon: f64) -> Option<f64> {
    let [xx, xy, xz, yy, yz, zz] = <[f64; 6]>::try_from(cov).ok()?;
    let c = [[xx, xy, xz], [xy, yy, yz], [xz, yz, zz]];
    let (lat, lon) = (lat.to_radians(), lon.to_radians());
    let east = [-lon.sin(), lon.cos(), 0.0];
    let north = [-lat.sin() * lon.cos(), -lat.sin() * lon.sin(), lat.cos()];
    let quadratic = |v: [f64; 3]| -> f64 {
        (0..3)
            .map(|i| (0..3).map(|j| v[i] * c[i][j] * v[j]).sum::<f64>())
            .sum()
    };
    let variance = quadratic(east) + quadratic(north);
    (variance >= 0.0).then(|| variance.sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Identity;

    fn station() -> Result<Station, String> {
        let key = Identity::from_seed([7; 32]).public();
        Station::of(
            &key,
            Some(Location {
                lat_e7: 374_100_000,
                lon_e7: -1_221_000_000,
                alt_m: 10,
                precision_m: 0,
            }),
            Clock::Dump1090,
        )
        .ok_or_else(|| "no station".to_owned())
    }

    #[test]
    fn the_handshake_is_byte_for_byte_what_json_dumps_sort_keys_writes() -> Result<(), String> {
        let station = station()?;
        // Python: json.dumps({...}, sort_keys=True) + 16 * '        ' + '\n'.
        let expected = format!(
            "{{\"alt\": 10.0, \"client_version\": \"{CLIENT_VERSION}\", \"clock_epoch\": null, \
             \"clock_frequency\": 12000000, \"clock_type\": \"dump1090\", \"compress\": [\"none\"], \
             \"heartbeat\": true, \"lat\": 37.41, \"lon\": -122.1, \"privacy\": true, \
             \"return_result_format\": \"ecef\", \"return_results\": true, \"return_stats\": true, \
             \"selective_traffic\": true, \"udp_transport\": false, \"user\": \"{}\", \
             \"uuid\": \"{}\", \"version\": 3}}{}\n",
            station.user,
            station.uuid,
            " ".repeat(128)
        );
        assert_eq!(station.handshake(), expected);
        let parsed: Value =
            serde_json::from_str(station.handshake().trim()).map_err(|error| error.to_string())?;
        assert_eq!(parsed["user"].as_str(), Some(station.user.as_str()));
        Ok(())
    }

    #[test]
    fn a_receiver_is_a_stable_name_mlat_server_keeps_whole() -> Result<(), String> {
        let station = station()?;
        assert_eq!(station, self::station()?);
        assert!(station.user.len() <= 40);
        assert!(
            station
                .user
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
        );
        assert_eq!(station.uuid.len(), 36);
        assert_eq!(&station.uuid[14..15], "8");
        Ok(())
    }

    #[test]
    fn receivers_mlat_cannot_use_are_skipped() {
        let key = Identity::from_seed([1; 32]).public();
        let exact = Location {
            lat_e7: 1,
            lon_e7: 1,
            alt_m: 0,
            precision_m: 0,
        };
        let rounded = Location {
            precision_m: 500,
            ..exact
        };
        assert!(Station::of(&key, None, Clock::Dump1090).is_none());
        assert!(Station::of(&key, Some(rounded), Clock::Dump1090).is_none());
        assert!(Station::of(&key, Some(exact), Clock::Unknown).is_none());
        assert!(Station::of(&key, Some(exact), Clock::Other(9)).is_none());
        let gps = Station::of(&key, Some(exact), Clock::RadarcapeGps);
        assert_eq!(
            gps.map(|station| (station.clock_type, station.mode)),
            Some(("radarcape_gps", Mode::Radarcape))
        );
    }

    #[test]
    fn floats_print_as_python_prints_them() {
        for (value, text) in [
            (10.0, "10.0"),
            (37.41, "37.41"),
            (-122.1, "-122.1"),
            (0.33, "0.33"),
            (1e-5, "1e-05"),
            (0.0001, "0.0001"),
            (1e16, "1e+16"),
            (1_791_220_000.123, "1791220000.123"),
            (0.0, "0.0"),
        ] {
            assert_eq!(python_float(value), text, "{value}");
        }
    }

    #[test]
    fn control_lines_are_mlat_clients() {
        assert_eq!(
            mode_change_line(Mode::Beast),
            r#"{"clock_reset":{"reason":"Decoder mode changed to BEAST","frequency":12000000,"epoch":null,"mode":"BEAST"}}"#
        );
        assert_eq!(
            mode_change_line(Mode::Radarcape),
            r#"{"clock_reset":{"reason":"Decoder mode changed to RADARCAPE","frequency":1000000000,"epoch":"utc_midnight","mode":"RADARCAPE"}}"#
        );
        assert_eq!(
            addresses_line("seen", &[0x40621d, 0xabc]),
            r#"{"seen":["40621d","000abc"]}"#
        );
        assert_eq!(addresses_line("lost", &[]), r#"{"lost":[]}"#);
        assert_eq!(rate_report_line(&[]), r#"{"rate_report":{}}"#);
        assert_eq!(
            rate_report_line(&[(0x40621d, 1.0 / 3.0), (0xabc, 2.0)]),
            r#"{"rate_report":{"40621D":0.33,"000ABC":2.0}}"#
        );
        assert_eq!(
            heartbeat_line(1_791_220_000.123_4),
            r#"{"heartbeat":{"client_time":1791220000.123}}"#
        );
    }

    #[test]
    fn the_servers_handshake_answer_is_read_as_mlat_client_reads_it() -> Result<(), String> {
        let accepted = r#"{"compress": "none", "reconnect_in": 10.3, "selective_traffic": true, "heartbeat": true, "return_results": true, "return_stats": true, "rate_reports": true, "motd": "\n\n  hello\n"}"#;
        assert_eq!(
            welcome(accepted)?,
            Welcome::Accepted {
                split_sync: false,
                reconnect_in: Some(10.3)
            }
        );
        let denied =
            r#"{"deny": ["Bad values in handshake: invalid latitude"], "reconnect_in": 905}"#;
        assert!(matches!(
            welcome(denied)?,
            Welcome::Denied { reasons, reconnect_in: Some(_) } if reasons.len() == 1
        ));
        assert!(welcome(r#"{"compress": "zlib2"}"#).is_err());
        Ok(())
    }

    #[test]
    fn an_ecef_result_becomes_a_position_with_a_horizontal_sigma() -> Result<(), String> {
        let ecef = llh_to_ecef(37.5, -122.0, 3_000.0);
        // 100 m standard deviation on every axis, uncorrelated: 141 m horizontal DRMS.
        let line = format!(
            r#"{{"result": {{"@": 1791220000.5, "addr": "40621d", "n": 5, "nd": 4, "cov": [10000.0, 0.0, 0.0, 10000.0, 0.0, 10000.0], "ecef": [{}, {}, {}]}}}}"#,
            ecef[0].round(),
            ecef[1].round(),
            ecef[2].round()
        );
        let Request::Result(solution) = request(&line)? else {
            return Err("not a result".to_owned());
        };
        assert_eq!((solution.address, solution.receivers), (0x40621d, 4));
        assert!((solution.lat - 37.5).abs() < 1e-4 && (solution.lon + 122.0).abs() < 1e-4);
        assert!((solution.alt_ft.unwrap_or(0.0) - 9_842.5).abs() < 5.0);
        assert!((solution.sigma_m.unwrap_or(0.0) - 141.42).abs() < 0.1);
        let without_cov = line.replace(
            r#""cov": [10000.0, 0.0, 0.0, 10000.0, 0.0, 10000.0]"#,
            r#""cov": null"#,
        );
        let Request::Result(solution) = request(&without_cov)? else {
            return Err("not a result".to_owned());
        };
        assert_eq!(solution.sigma_m, None);
        Ok(())
    }

    #[test]
    fn traffic_requests_are_hex_addresses() -> Result<(), String> {
        assert_eq!(
            request(r#"{"start_sending": ["40621d", "abc"]}"#)?,
            Request::StartSending(vec![0x40621d, 0xabc])
        );
        assert_eq!(
            request(r#"{"stop_sending": ["40621d"]}"#)?,
            Request::StopSending(vec![0x40621d])
        );
        assert_eq!(
            request(r#"{"heartbeat": {"server_time": 1.5}}"#)?,
            Request::Other
        );
        assert_eq!(request(r#"{"stats": {"peer_count": 3}}"#)?, Request::Other);
        Ok(())
    }
}
