//! The engine's command line. Which relays it reads, which regions it covers and which
//! mlat-server it bridges to are its operator's choice, and nothing on the network changes them.

use std::path::PathBuf;
use std::time::Duration;

use tally_wire::{PublicKey, Region, RelayAddress};

const USAGE: &str = "\
usage: tally-mlat --key FILE --relay HOST:PORT=KEY --server HOST:PORT [options]
       tally-mlat keygen --key FILE   create the key file if it is missing, print its public key

  --key FILE             this engine's identity: it signs every position the engine publishes
  --relay HOST:PORT=KEY  a relay to read raw batches from and publish positions to; repeatable
  --server HOST:PORT     the mlat-server's client port (wiedehopf/mlat-server, unmodified)
  --region CELL          an H3 cell (decimal, or hex as H3 writes it) whose receivers this engine
                         covers; repeatable, at most 64; none means every receiver the relays
                         carry
  --delay MS             how long after a reception is heard it is replayed to the server, so
                         every receiver's copy arrives together (default 2000)
  --max-receivers N      mlat-server sessions held at once, one per receiver; up to four times as
                         many beyond it wait, and a place goes to the most active (default 1000)
";

/// Regions one subscription may name (the protocol's limit): a relay ends a session that
/// subscribes to more with `Goodbye { Protocol }` and a day's wait, so more is refused here,
/// before any relay is dialled.
pub use tally_wire::record::MAX_REGIONS;

pub enum Command {
    Keygen(PathBuf),
    Run(Box<Config>),
    Done,
}

#[derive(Debug)]
pub struct Config {
    pub key_file: PathBuf,
    pub relays: Vec<RelayAddress>,
    pub server: String,
    pub regions: Vec<Region>,
    pub delay: Duration,
    pub max_receivers: usize,
}

pub fn parse(args: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut args = args.peekable();
    let keygen = args.peek().map(String::as_str) == Some("keygen");
    if keygen {
        args.next();
    }
    let mut key_file = None;
    let mut relays = Vec::new();
    let mut server = None;
    let mut regions = Vec::new();
    let mut delay = Duration::from_millis(2_000);
    let mut max_receivers = crate::engine::DEFAULT_MAX_RECEIVERS;
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--key" => key_file = Some(PathBuf::from(value()?)),
            "--relay" => relays.push(parse_relay(&value()?)?),
            "--server" => server = Some(value()?),
            "--region" => regions.push(parse_region(&value()?)?),
            "--delay" => {
                let text = value()?;
                let ms: u64 = text
                    .parse()
                    .map_err(|_| format!("--delay: {text} is not a number"))?;
                delay = Duration::from_millis(ms);
            }
            "--max-receivers" => {
                let text = value()?;
                max_receivers = text
                    .parse()
                    .ok()
                    .filter(|count| *count > 0)
                    .ok_or_else(|| format!("--max-receivers: {text} is not a positive number"))?;
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(Command::Done);
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let key_file = key_file.ok_or_else(|| format!("--key is required\n{USAGE}"))?;
    if keygen {
        return Ok(Command::Keygen(key_file));
    }
    if relays.is_empty() {
        return Err(format!("at least one --relay is required\n{USAGE}"));
    }
    let server = server.ok_or_else(|| format!("--server is required\n{USAGE}"))?;
    // The same cell named twice is one region, and counts once against the relays' limit.
    let mut distinct = Vec::with_capacity(regions.len());
    for region in regions {
        if !distinct.contains(&region) {
            distinct.push(region);
        }
    }
    let regions = distinct;
    if regions.len() > MAX_REGIONS {
        return Err(format!(
            "--region: {} regions named, and a relay serves at most {MAX_REGIONS} per engine \
             (it would end the session); run one engine per {MAX_REGIONS} regions, or name \
             coarser cells",
            regions.len()
        ));
    }
    Ok(Command::Run(Box::new(Config {
        key_file,
        relays,
        server,
        regions,
        delay,
        max_receivers,
    })))
}

pub fn parse_relay(text: &str) -> Result<RelayAddress, String> {
    // A base64 key may end in `=`, and an address never holds one: split at the first.
    let (address, key) = text
        .split_once('=')
        .ok_or_else(|| format!("{text}: expected HOST:PORT=KEY"))?;
    let key = PublicKey::from_base64(key).map_err(|error| format!("{text}: {error}"))?;
    Ok(RelayAddress {
        key,
        address: address.to_owned(),
    })
}

/// An H3 cell as its 64-bit number: decimal, `0x` hex, or bare hex as H3's own tools print it.
pub fn parse_region(text: &str) -> Result<Region, String> {
    let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
    let candidates = match hex {
        Some(hex) => vec![u64::from_str_radix(hex, 16).ok()],
        None => vec![text.parse().ok(), u64::from_str_radix(text, 16).ok()],
    };
    candidates
        .into_iter()
        .flatten()
        .find_map(|number| Region::from_u64(number).ok())
        .ok_or_else(|| format!("--region: {text} is not an H3 cell"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tally_wire::Location;

    fn args(text: &str) -> impl Iterator<Item = String> {
        text.split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn a_region_is_read_in_any_of_the_ways_h3_numbers_are_written() -> Result<(), String> {
        let region = Region::containing(
            &Location {
                lat_e7: 374_400_000,
                lon_e7: -1_221_400_000,
                alt_m: 0,
                precision_m: 0,
            },
            3,
        )
        .map_err(|error| error.to_string())?;
        let number = region.as_u64();
        for text in [
            number.to_string(),
            format!("{number:x}"),
            format!("0x{number:x}"),
        ] {
            assert_eq!(parse_region(&text)?, region, "{text}");
        }
        assert!(parse_region("12").is_err());
        Ok(())
    }

    #[test]
    fn the_engine_needs_a_relay_and_a_server() -> Result<(), String> {
        let key = tally_wire::Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        assert!(parse(args("--key k --server s:1")).is_err());
        let Command::Run(config) = parse(args(&format!(
            "--key k --relay r:1={key} --server s:1 --delay 500"
        )))?
        else {
            return Err("not a run".to_owned());
        };
        assert_eq!(config.delay, Duration::from_millis(500));
        assert_eq!(config.max_receivers, crate::engine::DEFAULT_MAX_RECEIVERS);
        let Command::Run(config) = parse(args(&format!(
            "--key k --relay r:1={key} --server s:1 --max-receivers 20"
        )))?
        else {
            return Err("not a run".to_owned());
        };
        assert_eq!(config.max_receivers, 20);
        assert!(
            parse(args(&format!(
                "--key k --relay r:1={key} --server s:1 --max-receivers 0"
            )))
            .is_err()
        );
        assert!(matches!(parse(args("keygen --key k"))?, Command::Keygen(_)));
        Ok(())
    }

    #[test]
    fn more_regions_than_a_relay_serves_are_refused_before_any_relay_is_dialled()
    -> Result<(), String> {
        let key = tally_wire::Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        // Two degrees of longitude apart along the tenth parallel: every cell differs.
        let cells = (0..=MAX_REGIONS)
            .map(|step| {
                let step = i32::try_from(step).map_err(|error| error.to_string())?;
                Region::containing(
                    &Location {
                        lat_e7: 100_000_000,
                        lon_e7: -1_700_000_000 + step * 20_000_000,
                        alt_m: 0,
                        precision_m: 0,
                    },
                    3,
                )
                .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let line = |cells: &[Region]| {
            let mut line = format!("--key k --relay r:1={key} --server s:1");
            for cell in cells {
                line.push_str(&format!(" --region {}", cell.as_u64()));
            }
            line
        };
        assert!(
            cells
                .iter()
                .enumerate()
                .all(|(at, cell)| !cells[..at].contains(cell)),
            "the cells must differ"
        );
        let error = parse(args(&line(&cells)))
            .err()
            .ok_or("65 regions were accepted")?;
        assert!(error.contains("at most 64"), "{error}");
        // Exactly the limit is fine, and a cell named twice counts once.
        let mut at_limit = cells[..MAX_REGIONS].to_vec();
        at_limit.push(cells[0]);
        let Command::Run(config) = parse(args(&line(&at_limit)))? else {
            return Err("not a run".to_owned());
        };
        assert_eq!(config.regions, cells[..MAX_REGIONS]);
        Ok(())
    }
}
