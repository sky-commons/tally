//! The geoid's height above the WGS84 ellipsoid (N), from the release's EGM2008 grid
//! (packaging/geoid/geoid.txt), compiled in: what turns a height above sea level, which is what
//! receiver setups give (adsb.im's `FEEDER_ALT_M`, ultrafeeder's `ALT`), into the height above the
//! ellipsoid MLAT needs (`--alt`). It reads the grid as `install.sh`'s `geoid_of` does, bicubic
//! interpolation on the base grid or the finer patch a cell names, so the feeder and the installer
//! give the same N to the centimetre.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The grid, as packaging/geoid/make_grid.py writes it (its format is described there).
const GRID: &str = include_str!("../../../packaging/geoid/geoid.txt");

struct Grid {
    /// The node spacings, arc-minutes, the global base first.
    levels: Vec<u32>,
    /// The base cells interpolated on a finer patch: (base row, base column) to its spacing.
    cells: HashMap<(i64, i64), u32>,
    /// Every node: (spacing, row, column) to N in decimetres.
    nodes: HashMap<(u32, i64, i64), i64>,
}

fn grid() -> Result<&'static Grid, String> {
    static PARSED: OnceLock<Result<Grid, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| parse(GRID))
        .as_ref()
        .map_err(Clone::clone)
}

fn parse(text: &str) -> Result<Grid, String> {
    let mut grid = Grid {
        levels: Vec::new(),
        cells: HashMap::new(),
        nodes: HashMap::new(),
    };
    let number = |word: &str| -> Result<i64, String> {
        word.parse()
            .map_err(|_| format!("the geoid grid holds {word:?}, not a number"))
    };
    for line in text.lines() {
        if let Some(levels) = line.strip_prefix("# levels ") {
            for level in levels.split_whitespace() {
                grid.levels.push(
                    u32::try_from(number(level)?)
                        .map_err(|_| format!("the geoid grid's level {level} is negative"))?,
                );
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&"A") && words.len() >= 5 {
            let step = u32::try_from(number(words[1])?).map_err(|_| "a negative patch level")?;
            let (row, column, count) = (number(words[2])?, number(words[3])?, number(words[4])?);
            for k in 0..count {
                grid.cells.insert((row, column + k), step);
            }
            continue;
        }
        if words.len() >= 4 {
            let step = u32::try_from(number(words[0])?).map_err(|_| "a negative node spacing")?;
            let row = number(words[1])?;
            let mut column = number(words[2])?;
            let mut value = number(words[3])?;
            grid.nodes.insert((step, row, column), value);
            for delta in &words[4..] {
                value += number(delta)?;
                column += 1;
                grid.nodes.insert((step, row, column), value);
            }
        }
    }
    if grid.levels.is_empty() {
        return Err("the geoid grid has no levels line".to_owned());
    }
    Ok(grid)
}

/// Catmull-Rom's weight for node `k` (0..4) at fraction `t` of the cell, as the installer's.
fn weight(t: f64, k: usize) -> f64 {
    match k {
        0 => ((-0.5 * t + 1.0) * t - 0.5) * t,
        1 => (1.5 * t - 2.5) * t * t + 1.0,
        2 => ((-1.5 * t + 2.0) * t + 0.5) * t,
        _ => (0.5 * t - 0.5) * t * t,
    }
}

/// N, metres, at `lat` and `lon` degrees.
pub fn undulation(lat: f64, lon: f64) -> Result<f64, String> {
    if !lat.is_finite() || !lon.is_finite() || !(-90.0..=90.0).contains(&lat) {
        return Err(format!("no geoid height at {lat}, {lon}"));
    }
    let grid = grid()?;
    let base = grid.levels[0];
    let spacing = f64::from(base) / 60.0;
    let base_columns = (360.0 / spacing).round();
    let mut base_row = ((90.0 - lat) / spacing).trunc();
    if base_row > 180.0 / spacing - 1.0 {
        base_row = (180.0 / spacing).round() - 1.0;
    }
    let mut x = ((lon + 180.0) / spacing).rem_euclid(base_columns);
    if x >= base_columns {
        x = 0.0;
    }
    let step = grid
        .cells
        .get(&(base_row as i64, x.trunc() as i64))
        .copied()
        .unwrap_or(base);
    let spacing = f64::from(step) / 60.0;
    let rows = (180.0 / spacing).round() as i64 + 1;
    let columns = (360.0 / spacing).round() as i64;
    let y = (90.0 - lat) / spacing;
    let row0 = (y.trunc() as i64).min(rows - 2);
    let fy = y - row0 as f64;
    let x = ((lon + 180.0) / spacing).rem_euclid(columns as f64);
    let column0 = x.trunc() as i64;
    let fx = x - column0 as f64;
    let node = |row: i64, column: i64| {
        // Past a pole the grid goes on down the other side of the earth.
        let (row, column) = if row < 0 {
            (-row, column + columns / 2)
        } else if row > rows - 1 {
            (2 * (rows - 1) - row, column + columns / 2)
        } else {
            (row, column)
        };
        grid.nodes
            .get(&(step, row, column.rem_euclid(columns)))
            .copied()
            .ok_or_else(|| format!("the geoid grid lacks node {step} {row} {column}"))
    };
    let mut n = 0.0;
    for a in 0..4 {
        let mut across = 0.0;
        for b in 0..4 {
            let value = node(row0 - 1 + a as i64, column0 - 1 + b as i64)?;
            across += weight(fx, b) * value as f64;
        }
        n += weight(fy, a) * across;
    }
    Ok(n / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The installer's `geoid_of` on the same grid (packaging/tests/install.rs checks that against
    /// NGS's GEOID18), to the centimetre it prints.
    #[test]
    fn the_feeder_reads_the_grid_as_the_installer_does() -> Result<(), String> {
        for (lat, lon, installer) in [
            (37.778536, -122.418310, -32.53),
            (51.5, -0.1, 46.31),
            (48.85826, 2.294501, 44.94),
            (-33.86, 151.21, 21.18),
            (89.9, 10.0, 15.05),
            (-89.9, -170.0, -30.13),
            (0.0, 180.0, 21.30),
            (0.0, -180.0, 21.30),
            (-90.0, 0.0, -30.10),
            (90.0, 0.0, 14.90),
        ] {
            let n = undulation(lat, lon)?;
            assert!(
                (n - installer).abs() < 0.006,
                "{lat}, {lon}: {n} m, the installer {installer} m"
            );
        }
        assert!(undulation(91.0, 0.0).is_err());
        assert!(undulation(f64::NAN, 0.0).is_err());
        Ok(())
    }
}
