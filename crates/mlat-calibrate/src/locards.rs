//! Reading LocaRDS (Strohmeier et al., "LocaRDS: A Localization Reference Data Set", 2021; Zenodo
//! 10.5281/zenodo.4739276, CC BY-SA 4.0): one hour of OpenSky Network receptions over Europe per
//! subset, three files.
//!
//! - `set_N.csv`: one row a deduplicated ADS-B airborne position, `id, timeAtServer, aircraft,
//!   latitude, longitude, baroAltitude, geoAltitude, numMeasurements, measurements`. `timeAtServer`
//!   is seconds since the recording began, when OpenSky's server first saw the report; latitude
//!   and longitude are the decoded position in degrees, both altitudes metres (geometric is the
//!   GNSS height). `measurements` is `"[[sensor, timestamp, rssi], ...]"`, the timestamp the
//!   sensor's own in nanoseconds, made continuous (OpenSky's overflow detection) and printed as R
//!   prints a double (`3.446e+09`, `39356140000`, `13761937166.6667`).
//! - `set_N_sensors.csv`: `serial, latitude, longitude, height, type, good`, `good` true when the
//!   sensor's timestamps did not drift over the hour and its location was verified by them.
//! - `set_N_aircraft.csv`: `aircraft, trusted`, true when the aircraft's reported positions were
//!   verified against GNSS-synchronised sensors, false when they are known to be poor, empty when
//!   the geometry could not say.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// A sensor as the dataset describes it.
#[derive(Clone, Debug, PartialEq)]
pub struct Sensor {
    pub serial: u32,
    pub lat_deg: f64,
    pub lon_deg: f64,
    /// Metres, as OpenSky's owners entered it (0 is often "not given").
    pub height_m: f64,
    pub kind: String,
    pub good: bool,
}

/// One deduplicated ADS-B position report and every sensor's reception of it.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub id: u64,
    pub server_s: f64,
    pub aircraft: u32,
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub baro_m: Option<f64>,
    pub geo_m: Option<f64>,
    /// (sensor serial, timestamp nanoseconds).
    pub measurements: Vec<(u32, f64)>,
}

/// The three files of subset `N` in `dir` (`subset_N` as unzipped).
#[derive(Clone, Debug)]
pub struct Subset {
    pub rows: PathBuf,
    pub sensors: PathBuf,
    pub aircraft: PathBuf,
}

impl Subset {
    /// Finds `set_N.csv` and its two companions in `dir`.
    pub fn find(dir: &Path) -> Result<Self, String> {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".csv") else {
                continue;
            };
            if stem.starts_with("set_") && stem[4..].chars().all(|c| c.is_ascii_digit()) {
                return Ok(Self {
                    rows: path.clone(),
                    sensors: dir.join(format!("{stem}_sensors.csv")),
                    aircraft: dir.join(format!("{stem}_aircraft.csv")),
                });
            }
        }
        Err(format!("no set_N.csv in {}", dir.display()))
    }
}

fn number(field: &str, what: &str) -> Result<f64, String> {
    field
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("{what}: {field:?} is not a number"))
}

fn optional(field: &str) -> Option<f64> {
    let field = field.trim();
    if field.is_empty() || field.eq_ignore_ascii_case("na") || field.eq_ignore_ascii_case("nan") {
        return None;
    }
    field.parse::<f64>().ok().filter(|v| v.is_finite())
}

fn lines(path: &Path) -> Result<std::io::Lines<BufReader<File>>, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(BufReader::with_capacity(1 << 20, file).lines())
}

/// Every sensor of the subset.
pub fn sensors(path: &Path) -> Result<Vec<Sensor>, String> {
    let mut out = Vec::new();
    for (index, line) in lines(path)?.enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if index == 0 || line.trim().is_empty() {
            continue;
        }
        out.push(sensor(&line)?);
    }
    Ok(out)
}

pub fn sensor(line: &str) -> Result<Sensor, String> {
    let fields: Vec<&str> = line.split(',').collect();
    let [serial, lat, lon, height, kind, good] = fields.as_slice() else {
        return Err(format!(
            "a sensor line of {} fields: {line:?}",
            fields.len()
        ));
    };
    Ok(Sensor {
        serial: number(serial, "serial")? as u32,
        lat_deg: number(lat, "latitude")?,
        lon_deg: number(lon, "longitude")?,
        height_m: optional(height).unwrap_or(0.0),
        kind: kind.trim().to_owned(),
        good: good.trim().eq_ignore_ascii_case("true"),
    })
}

/// Each aircraft's verification: `Some(true)` verified, `Some(false)` known poor, absent when the
/// dataset could not say.
pub fn aircraft(path: &Path) -> Result<BTreeMap<u32, bool>, String> {
    let mut out = BTreeMap::new();
    for (index, line) in lines(path)?.enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if index == 0 || line.trim().is_empty() {
            continue;
        }
        let Some((id, trusted)) = line.split_once(',') else {
            return Err(format!("an aircraft line {line:?}"));
        };
        let trusted = trusted.trim();
        if trusted.is_empty() {
            continue;
        }
        out.insert(
            number(id, "aircraft")? as u32,
            trusted.eq_ignore_ascii_case("true"),
        );
    }
    Ok(out)
}

/// One measurements row.
pub fn row(line: &str) -> Result<Row, String> {
    // Eight plain fields, then the quoted list.
    let mut fields = line.splitn(9, ',');
    let mut next = |what: &str| {
        fields
            .next()
            .ok_or_else(|| format!("no {what} in {line:?}"))
    };
    let id = number(next("id")?, "id")? as u64;
    let server_s = number(next("timeAtServer")?, "timeAtServer")?;
    let aircraft = number(next("aircraft")?, "aircraft")? as u32;
    let lat_deg = number(next("latitude")?, "latitude")?;
    let lon_deg = number(next("longitude")?, "longitude")?;
    let baro_m = optional(next("baroAltitude")?);
    let geo_m = optional(next("geoAltitude")?);
    let _count = next("numMeasurements")?;
    let list = next("measurements")?
        .trim()
        .trim_matches('"')
        .trim_start_matches('[')
        .trim_end_matches(']');
    let mut measurements = Vec::new();
    for item in list.split("],[") {
        let mut parts = item.split(',');
        let (Some(sensor), Some(timestamp)) = (parts.next(), parts.next()) else {
            return Err(format!("a measurement {item:?} in row {id}"));
        };
        measurements.push((
            number(sensor, "sensor")? as u32,
            number(timestamp, "timestamp")?,
        ));
    }
    Ok(Row {
        id,
        server_s,
        aircraft,
        lat_deg,
        lon_deg,
        baro_m,
        geo_m,
        measurements,
    })
}

/// Every row of the measurements file, in file order (ascending `timeAtServer`), handed to `each`.
pub fn rows(path: &Path, each: &mut dyn FnMut(Row) -> Result<(), String>) -> Result<(), String> {
    for (index, line) in lines(path)?.enumerate() {
        let line = line.map_err(|e| e.to_string())?;
        if index == 0 || line.trim().is_empty() {
            continue;
        }
        each(row(&line)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_reads_as_the_dataset_prints_it() -> Result<(), String> {
        let row = row(
            "4430,2.4539999961853,901,47.3506622314453,6.46366882324219,11407.14,11239.5,3,\
             \"[[470,3445380800,53],[598,3.446e+09,24],[310,39352575333.3333,12]]\"",
        )?;
        assert_eq!(row.id, 4430);
        assert_eq!(row.aircraft, 901);
        assert_eq!(row.baro_m, Some(11407.14));
        assert_eq!(
            row.measurements,
            vec![
                (470, 3_445_380_800.0),
                (598, 3_446_000_000.0),
                (310, 39_352_575_333.333_3)
            ]
        );
        Ok(())
    }

    #[test]
    fn a_sensor_and_a_missing_altitude_read() -> Result<(), String> {
        let sensor = sensor("10,47.40017,8.63068,430.6824,Radarcape,TRUE")?;
        assert_eq!(sensor.serial, 10);
        assert!(sensor.good);
        assert_eq!(sensor.kind, "Radarcape");
        let row = row("1,0,109,51.6,-0.2,,NaN,2,\"[[532,969020406,89],[216,969100125,23]]\"")?;
        assert_eq!((row.baro_m, row.geo_m), (None, None));
        Ok(())
    }
}
