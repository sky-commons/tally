//! `tally-mlat-calibrate <subset dir> [options]`: the native MLAT's calibration over a LocaRDS
//! subset (the crate documentation says what it does and measures).

use std::path::PathBuf;
use std::process::ExitCode;

use tally_mlat_calibrate::locards::Subset;
use tally_mlat_calibrate::mapping::Reply;
use tally_mlat_calibrate::run::Finals;
use tally_mlat_calibrate::score::TruthModel;
use tally_mlat_calibrate::{Outcome, Settings, run};

const USAGE: &str = "usage: tally-mlat-calibrate <subset dir> [--withhold N] [--reply df4|df11] \
                     [--nacp N] [--good-sensors] [--unverified-precision M] [--start S] [--duration S] [--threads N] [--samples FILE]";

fn parse() -> Result<(PathBuf, Settings), String> {
    let mut settings = Settings::default();
    let mut dir = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--withhold" => {
                settings.withhold_one_in = value("--withhold")?.parse().map_err(|_| USAGE)?;
            }
            "--reply" => {
                settings.reply = match value("--reply")?.as_str() {
                    "df4" => Reply::Df4,
                    "df11" => Reply::Df11,
                    _ => return Err(USAGE.to_owned()),
                };
            }
            "--nacp" => settings.nacp = Some(value("--nacp")?.parse().map_err(|_| USAGE)?),
            "--good-sensors" => settings.good_sensors_only = true,
            "--unverified-precision" => {
                settings.unverified_precision_m = value("--unverified-precision")?
                    .parse()
                    .map_err(|_| USAGE)?;
            }
            "--start" => settings.start_s = value("--start")?.parse().map_err(|_| USAGE)?,
            "--duration" => {
                settings.duration_s = value("--duration")?.parse().map_err(|_| USAGE)?
            }
            "--threads" => settings.threads = value("--threads")?.parse().map_err(|_| USAGE)?,
            "--samples" => settings.samples = Some(PathBuf::from(value("--samples")?)),
            "-h" | "--help" => return Err(USAGE.to_owned()),
            other if dir.is_none() && !other.starts_with('-') => dir = Some(PathBuf::from(other)),
            _ => return Err(USAGE.to_owned()),
        }
    }
    Ok((dir.ok_or(USAGE)?, settings))
}

fn print_finals(name: &str, finals: &Finals, model: &TruthModel) {
    println!("{name}:");
    println!("  overall: {}", finals.overall.summary(model));
    println!(
        "  LocaRDS-verified aircraft: {}",
        finals.trusted.summary(model)
    );
    let bands = ["below 6 km", "6 to 9 km", "9 km and up"];
    for (band, slice) in bands.iter().zip(&finals.bands) {
        println!("  {band}: {}", slice.summary(model));
    }
    let counts = ["3 receptions", "4", "5 or 6", "7 to 9", "10 or more"];
    for (count, slice) in counts.iter().zip(&finals.receivers) {
        println!("  {count}: {}", slice.summary(model));
    }
    for (level, slice) in finals.levels.iter().enumerate() {
        println!("  tile level {level}: {}", slice.summary(model));
    }
    let clocks = ["every clock GNSS", "some GNSS", "no GNSS"];
    for (clock, slice) in clocks.iter().zip(&finals.clocks) {
        println!("  {clock}: {}", slice.summary(model));
    }
}

fn print(settings: &Settings, outcome: &Outcome) {
    println!("settings: {settings:?}");
    println!(
        "sensors {} ({} GNSS); rows {}; receptions {}; withheld aircraft {}, transmissions {}",
        outcome.sensors_described,
        outcome.sensors_gnss,
        outcome.rows_read,
        outcome.receptions,
        outcome.withheld_aircraft,
        outcome.withheld_transmissions
    );
    let window = &outcome.window;
    println!(
        "engine: windows {}, fits {}, unfitted {} ({:?}), transmissions {}, solved {}, unsolved \
         {}, rejected {}, models {}, fit time {:.0} s, solve time {:.0} s",
        window.windows,
        window.fits,
        window.unfitted,
        window.unfitted_reason,
        window.transmissions,
        window.solved,
        window.unsolved,
        window.rejected,
        outcome.models,
        window.fit_time.as_secs_f64(),
        window.solve_time.as_secs_f64()
    );
    println!("provisional engine: {:?}", outcome.provisional);
    println!(
        "solved: {} of {} eligible (aircraft, bin) pairs ({:.3}); {} finals of at most {} \
         transmissions ({:.3}); {} solutions of no withheld transmission",
        outcome.solved_bins,
        outcome.eligible_bins,
        outcome.solved_bins as f64 / outcome.eligible_bins.max(1) as f64,
        outcome.finals.overall.horizontal.total,
        outcome.eligible_transmissions,
        outcome.finals.overall.horizontal.total as f64
            / outcome.eligible_transmissions.max(1) as f64,
        outcome.unknown_solutions
    );
    let model = &outcome.truth_model;
    println!(
        "reference: {} fixes from verified Radarcapes alone, chi-square per degree of freedom \
         median {:.2}, against the raw truth {}; the truth's own error: lag {:+.1} m along the \
         track, {:.1} m along, {:.1} m across (from {} with a velocity); the reference against \
         the truth model {}",
        outcome.reference_fixes,
        outcome.reference_chi2_per_dof,
        outcome.reference_raw,
        model.lag_m,
        model.along_sd_m,
        model.cross_sd_m,
        model.samples,
        outcome.reference_against,
    );
    print_finals("final positions", &outcome.finals, model);
    print_finals("provisional positions", &outcome.provisionals, model);
}

fn main() -> ExitCode {
    let (dir, settings) = match parse() {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let subset = match Subset::find(&dir) {
        Ok(subset) => subset,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let started = std::time::Instant::now();
    let outcome = run(&subset, &settings, &mut |line| {
        eprintln!("[{:>6.0} s] {line}", started.elapsed().as_secs_f64());
    });
    match outcome {
        Ok(outcome) => {
            print(&settings, &outcome);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
