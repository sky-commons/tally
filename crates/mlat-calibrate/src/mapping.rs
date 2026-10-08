//! How a LocaRDS reception becomes what a Tally feeder would have published (crate docs, § The
//! mapping): which receivers take part and with what clock, a timestamp as a raw counter, a
//! position report as the Mode S message a sync aircraft or a withheld target sends.

use blake2::{Blake2s256, Digest};
use tally_mlat_solver::modes;
use tally_wire::{Clock, Identity, Location};

use crate::locards::{Row, Sensor};

/// The UTC day the replay runs on, as Unix milliseconds at its midnight (the simulator's), and how
/// far into it the recording starts. LocaRDS gives no date, and nothing measured depends on one:
/// a GNSS stamp is placed `START_TOD_S` plus its nanoseconds into this day.
pub const MIDNIGHT_UNIX_MS: u64 = 1_791_244_800_000;
pub const START_TOD_S: u64 = 43_200;

/// Unix milliseconds of the recording's start.
pub fn start_ms() -> u64 {
    MIDNIGHT_UNIX_MS + START_TOD_S * 1000
}

/// What the timestamps of one sensor are, decided from the hour itself (`Survey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockClass {
    /// On the common GNSS time scale: whole nanoseconds, a constant fraction of a second or two
    /// behind the server's arrival time all hour.
    Gnss,
    /// Anything else: a free-running counter, made a 12 MHz count.
    Free,
}

/// A GNSS sensor's stamp (seconds) may sit this far from the server's arrival time.
pub const GNSS_BAND_S: (f64, f64) = (-1.0, 5.0);
/// Of a sensor's stamps, at least this fraction must lie in the band for it to be GNSS.
pub const GNSS_IN_BAND: f64 = 0.999;
/// A stamp is on the 12 MHz grid when it is within this many nanoseconds of a 12 MHz tick.
const GRID_NS: f64 = 1.0;

/// What one pass over the hour says of each sensor's timestamps.
#[derive(Clone, Copy, Debug, Default)]
pub struct Survey {
    pub receptions: u64,
    /// Stamps within `GNSS_BAND_S` of the server's arrival time.
    pub in_band: u64,
    /// Stamps on the 12 MHz grid (a dump1090 counter converted to nanoseconds).
    pub on_grid: u64,
}

impl Survey {
    pub fn add(&mut self, server_s: f64, ns: f64) {
        self.receptions += 1;
        let lag = ns / 1e9 - server_s;
        self.in_band += u64::from(GNSS_BAND_S.0 <= lag && lag <= GNSS_BAND_S.1);
        let ticks = ns * 0.012;
        self.on_grid += u64::from((ticks - ticks.round()).abs() * 1000.0 / 12.0 <= GRID_NS);
    }

    /// GNSS when nearly every stamp keeps to the server's clock and they are not 12 MHz ticks.
    pub fn class(&self) -> ClockClass {
        let n = self.receptions.max(1) as f64;
        if self.receptions >= 100
            && self.in_band as f64 / n >= GNSS_IN_BAND
            && (self.on_grid as f64 / n) < 0.5
        {
            ClockClass::Gnss
        } else {
            ClockClass::Free
        }
    }
}

/// The raw counter a feeder would have sent for a stamp of `ns` nanoseconds, or none when it has
/// no place on the clock's scale.
///
/// - GNSS: Radarcape GPS form, UTC seconds of the day above 30 bits of nanoseconds, the stamp
///   placed `START_TOD_S` into the day.
/// - Free: a 12 MHz count, `(ns + 10^12) * 12 / 1000` rounded. LocaRDS made dump1090's 12 MHz
///   counts nanoseconds by that factor, so this returns them exactly (up to a constant); another
///   rate's stamps gain at most 42 ns of rounding. The 10^12 keeps counts positive, where
///   OpenSky's alignment put a stamp a little before the recording.
pub fn counter(class: ClockClass, ns: f64) -> Option<u64> {
    if !ns.is_finite() {
        return None;
    }
    match class {
        ClockClass::Gnss => {
            let tod_ns = START_TOD_S as f64 * 1e9 + ns.round();
            if !(0.0..86_400e9).contains(&tod_ns) {
                return None;
            }
            let tod_ns = tod_ns as u64;
            Some(((tod_ns / 1_000_000_000) << 30) | (tod_ns % 1_000_000_000))
        }
        ClockClass::Free => {
            let count = ((ns + 1e12) * 0.012).round();
            (0.0..(1u64 << 48) as f64)
                .contains(&count)
                .then_some(count as u64)
        }
    }
}

/// A sensor that takes part, as its feeder describes itself.
#[derive(Clone, Debug)]
pub struct Receiver {
    pub serial: u32,
    pub identity: Identity,
    pub location: Location,
    pub clock: Clock,
    pub class: ClockClass,
    pub good: bool,
}

/// Each sensor's feeder identity: a seed from its serial, so a replay is the same every time.
pub fn identity(serial: u32) -> Identity {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(b"locards ");
    seed[8..12].copy_from_slice(&serial.to_be_bytes());
    Identity::from_seed(seed)
}

/// The feeder a sensor would be: its site as OpenSky holds it, declared to `precision_m` (0 for
/// exact, as a feeder's own survey is declared), and the clock its timestamps show. None for a
/// sensor with no location (0, 0).
pub fn receiver(sensor: &Sensor, class: ClockClass, precision_m: u32) -> Option<Receiver> {
    if sensor.lat_deg == 0.0 && sensor.lon_deg == 0.0 {
        return None;
    }
    if !(-90.0..=90.0).contains(&sensor.lat_deg) || !(-180.0..=180.0).contains(&sensor.lon_deg) {
        return None;
    }
    Some(Receiver {
        serial: sensor.serial,
        identity: identity(sensor.serial),
        location: Location {
            lat_e7: (sensor.lat_deg * 1e7).round() as i32,
            lon_e7: (sensor.lon_deg * 1e7).round() as i32,
            alt_m: sensor.height_m.round() as i32,
            precision_m,
        },
        clock: match class {
            ClockClass::Gnss => Clock::RadarcapeGps,
            ClockClass::Free => Clock::Dump1090,
        },
        class,
        good: sensor.good,
    })
}

/// Whether an aircraft is withheld: one in `one_in` by hash of its LocaRDS id, all hour.
pub fn withheld(aircraft: u32, one_in: u32) -> bool {
    let mut hasher = Blake2s256::new();
    hasher.update(b"tally mlat calibration withheld\0");
    hasher.update(aircraft.to_be_bytes());
    let first = hasher.finalize()[0];
    u32::from(first) * one_in.max(1) < 256
}

/// LocaRDS names aircraft by small integers, not ICAO addresses: each is given one, unique.
pub fn address(aircraft: u32) -> u32 {
    0x40_0000 + (aircraft & 0x3f_ffff)
}

/// What a withheld aircraft's transmissions are sent as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// An altitude reply, its AC13 the report's barometric altitude: the engine solves it with
    /// its altitude.
    Df4,
    /// An all-call reply, no altitude: solved from times alone.
    Df11,
}

/// Pressure altitude in feet, to the 25 ft a Q-bit altitude carries.
fn feet(baro_m: f64) -> i32 {
    ((baro_m / 0.3048 / 25.0).round() as i32) * 25
}

/// The DF17 airborne position (type code 11, barometric) a sync aircraft's report was: the
/// dataset's decoded position CPR-encoded again, `odd` alternating per aircraft.
pub fn position_message(address: u32, row: &Row, odd: bool) -> Option<Vec<u8>> {
    let baro = row.baro_m?;
    let field = modes::ac13_to_ac12(modes::encode_ac13_q(feet(baro))?);
    let (lat, lon) = modes::cpr_encode(
        modes::LatLon {
            lat_deg: row.lat_deg,
            lon_deg: row.lon_deg,
        },
        odd,
    );
    let me = modes::encode_airborne_position(11, field, odd, lat, lon);
    Some(df17(address, me))
}

/// An airborne operational status declaring `nacp` (only with `--nacp`).
pub fn status_message(address: u32, nacp: u8) -> Vec<u8> {
    let mut me = [0u8; 7];
    me[0] = 31 << 3;
    me[5] = (2 << 5) | (nacp & 0x0f);
    df17(address, me)
}

/// The reply a withheld aircraft's report is sent as.
pub fn reply_message(address: u32, row: &Row, reply: Reply) -> Option<Vec<u8>> {
    match reply {
        Reply::Df4 => {
            let ac = modes::encode_ac13_q(feet(row.baro_m?))?;
            let body = [4 << 3, 0, (ac >> 8) as u8 & 0x1f, ac as u8];
            Some(modes::with_parity(&body, address))
        }
        Reply::Df11 => {
            let body = [
                (11 << 3) | 5,
                (address >> 16) as u8,
                (address >> 8) as u8,
                address as u8,
            ];
            Some(modes::with_parity(&body, 0))
        }
    }
}

fn df17(address: u32, me: [u8; 7]) -> Vec<u8> {
    let mut body = vec![
        (17 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    body.extend_from_slice(&me);
    modes::with_parity(&body, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dump1090_stamp_is_its_12_mhz_count_again() {
        // 13761937166.6667 ns is 165143246 counts of 12 MHz, and 83.3 ns on is the next.
        let a = counter(ClockClass::Free, 13_761_937_166.666_7);
        let b = counter(ClockClass::Free, 13_761_937_250.0);
        assert_eq!(a.zip(b).map(|(a, b)| b - a), Some(1));
        assert_eq!(a, Some(12_000_000_000 + 165_143_246));
    }

    #[test]
    fn a_gnss_stamp_is_seconds_of_the_day_and_nanoseconds() {
        let raw = counter(ClockClass::Gnss, 3_600_943_678_046.0);
        let seconds = START_TOD_S + 3600;
        assert_eq!(raw, Some((seconds << 30) | 943_678_046));
    }

    #[test]
    fn the_survey_tells_a_gnss_sensor_from_a_counter() {
        let mut gnss = Survey::default();
        let mut free = Survey::default();
        for i in 0..1000 {
            let t = f64::from(i) * 3.6;
            gnss.add(t, (t + 0.9) * 1e9 + 123.0);
            // A dump1090 OpenSky aligned near the server's clock: on the grid all the same.
            free.add(t, ((t + 0.9) * 12e6).round() * 1000.0 / 12.0);
        }
        assert_eq!(gnss.class(), ClockClass::Gnss);
        assert_eq!(free.class(), ClockClass::Free);
    }

    #[test]
    fn messages_decode_as_the_engine_reads_them() {
        let row = Row {
            id: 1,
            server_s: 0.0,
            aircraft: 840,
            lat_deg: 51.280_781,
            lon_deg: -0.698_623,
            baro_m: Some(8907.78),
            geo_m: Some(8846.82),
            measurements: Vec::new(),
        };
        let address = address(row.aircraft);
        let even = position_message(address, &row, false).unwrap_or_default();
        let odd = position_message(address, &row, true).unwrap_or_default();
        assert_eq!(modes::crc_residual(&even), 0);
        assert_eq!(modes::address(&even), Some(address));
        let (Some(e), Some(o)) = (
            modes::airborne_position(&even),
            modes::airborne_position(&odd),
        ) else {
            panic!("not airborne positions");
        };
        let decoded = modes::cpr_global((e.lat_cpr, e.lon_cpr), (o.lat_cpr, o.lon_cpr), true);
        let decoded = decoded.unwrap_or(modes::LatLon {
            lat_deg: 0.0,
            lon_deg: 0.0,
        });
        assert!((decoded.lat_deg - row.lat_deg).abs() < 1e-4);
        assert!((decoded.lon_deg - row.lon_deg).abs() < 1e-4);
        let reply = reply_message(address, &row, Reply::Df4).unwrap_or_default();
        assert_eq!(modes::address(&reply), Some(address));
        let feet = modes::altitude(&reply).map(|a| a.metres());
        assert!(feet.is_some_and(|m| (m - 8907.78).abs() < 8.0), "{feet:?}");
        let all_call = reply_message(address, &row, Reply::Df11).unwrap_or_default();
        assert_eq!(modes::address(&all_call), Some(address));
    }
}
