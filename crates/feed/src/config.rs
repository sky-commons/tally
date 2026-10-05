//! The feeder's command line. Everything a feeder does is decided here, by its owner, or by the
//! fixed rules in this binary: nothing on the network can reconfigure it (RFC-0166 §3.5).

use std::path::PathBuf;

use tally_wire::{Clock, Location, PublicKey, RelayAddress};

/// Relays shipped in the binary, as `HOST:PORT=KEY`, known like any `--relay`. Before the public
/// release this lists relays run by several independent operators, never one: a single built-in
/// seed is a party that can steer every new feeder (RFC-0166 §3.5, §3.7). It is only a starting
/// point; the feeder learns relays from relays and keeps what it learned.
pub const SEEDS: &[&str] = &[];

const USAGE: &str = "\
usage: tally-feed --key FILE [options]
       tally-feed init --key FILE      create the key file if it is missing, print its public key

  --key FILE             this receiver's identity (keep it: it is the antenna's name forever)
  --source HOST:PORT     readsb's BEAST output (default 127.0.0.1:30005)
  --uat HOST:PORT        dump978-fa's raw output, for 978 MHz UAT (none by default; it is
                         usually 127.0.0.1:30978)
  --relay HOST:PORT=KEY  a relay to know of; repeatable
  --home HOST:PORT=KEY   a relay always in the set (your own, if you run one)
  --relays N             how many relays to publish to (default 4)
  --state DIR            where learned relays and the anchor are kept (default /var/lib/tally-feed)
  --lat DEG --lon DEG --alt M
                         the antenna's position, published exactly unless --precision says
                         otherwise (MLAT needs it exact)
  --precision M          how far the published position may be from the antenna (default 0)
  --clock NAME           the receiver's clock: dump1090 (RTL-SDR, the default), beast,
                         radarcape_12mhz, radarcape_gps
  --ceiling BYTES        the most this feeder sends each relay per second (default 64000)
";

pub enum Command {
    Init(PathBuf),
    Run(Box<Config>),
    Done,
}

#[derive(Debug)]
pub struct Config {
    pub key_file: PathBuf,
    pub source: String,
    pub uat: Option<String>,
    pub relays: Vec<RelayAddress>,
    pub home: Option<RelayAddress>,
    pub relay_count: usize,
    pub state_dir: PathBuf,
    pub location: Option<Location>,
    pub clock: Clock,
    pub ceiling: u32,
}

pub fn parse(args: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut args = args.peekable();
    let init = args.peek().map(String::as_str) == Some("init");
    if init {
        args.next();
    }
    let mut key_file = None;
    let mut config = Config {
        key_file: PathBuf::new(),
        source: "127.0.0.1:30005".to_owned(),
        uat: None,
        relays: Vec::new(),
        home: None,
        relay_count: 4,
        state_dir: PathBuf::from("/var/lib/tally-feed"),
        location: None,
        clock: Clock::Dump1090,
        ceiling: 64_000,
    };
    let (mut lat, mut lon, mut alt, mut precision) = (None, None, None, 0u32);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--key" => key_file = Some(PathBuf::from(value()?)),
            "--source" => config.source = value()?,
            "--uat" => config.uat = Some(value()?),
            "--relay" => config.relays.push(parse_relay(&value()?)?),
            "--home" => config.home = Some(parse_relay(&value()?)?),
            "--relays" => config.relay_count = number(&flag, &value()?)?,
            "--state" => config.state_dir = PathBuf::from(value()?),
            "--lat" => lat = Some(degrees(&flag, &value()?, 90.0)?),
            "--lon" => lon = Some(degrees(&flag, &value()?, 180.0)?),
            "--alt" => alt = Some(number(&flag, &value()?)?),
            "--precision" => precision = number(&flag, &value()?)?,
            "--clock" => {
                let name = value()?;
                config.clock =
                    Clock::from_name(&name).ok_or_else(|| format!("unknown clock {name}"))?;
            }
            "--ceiling" => config.ceiling = number(&flag, &value()?)?,
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(Command::Done);
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let key_file = key_file.ok_or_else(|| format!("--key is required\n{USAGE}"))?;
    if init {
        return Ok(Command::Init(key_file));
    }
    config.key_file = key_file;
    for seed in SEEDS {
        config.relays.push(parse_relay(seed)?);
    }
    config.location = match (lat, lon) {
        (Some(lat_e7), Some(lon_e7)) => Some(Location {
            lat_e7,
            lon_e7,
            alt_m: alt.unwrap_or(0),
            precision_m: precision,
        }),
        (None, None) => None,
        _ => return Err("--lat and --lon go together".to_owned()),
    };
    if config.relay_count == 0 {
        return Err("--relays must be at least 1".to_owned());
    }
    Ok(Command::Run(Box::new(config)))
}

pub fn parse_relay(text: &str) -> Result<RelayAddress, String> {
    let (address, key) = text
        .split_once('=')
        .ok_or_else(|| format!("{text}: expected HOST:PORT=KEY"))?;
    let key = PublicKey::from_base64(key).map_err(|error| format!("{text}: {error}"))?;
    Ok(RelayAddress {
        key,
        address: address.to_owned(),
    })
}

fn number<T: std::str::FromStr>(flag: &str, text: &str) -> Result<T, String> {
    text.parse()
        .map_err(|_| format!("{flag}: {text} is not a number"))
}

/// Degrees to the wire's degrees times 10^7, exactly as entered.
fn degrees(flag: &str, text: &str, limit: f64) -> Result<i32, String> {
    let value: f64 = number(flag, text)?;
    if !(-limit..=limit).contains(&value) {
        return Err(format!("{flag}: {text} is out of range"));
    }
    Ok((value * 1e7).round() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<Config, String> {
        match parse(args.iter().map(|arg| (*arg).to_owned()))? {
            Command::Run(config) => Ok(*config),
            _ => Err("not a run".to_owned()),
        }
    }

    #[test]
    fn every_seed_is_a_relay_address() -> Result<(), String> {
        for seed in SEEDS {
            parse_relay(seed)?;
        }
        Ok(())
    }

    #[test]
    fn seeds_join_the_relays_the_owner_named() -> Result<(), String> {
        let config = run(&["--key", "k"])?;
        assert_eq!(config.relays.len(), SEEDS.len());
        Ok(())
    }

    #[test]
    fn uat_is_off_unless_named() -> Result<(), String> {
        assert_eq!(run(&["--key", "k"])?.uat, None);
        let config = run(&["--key", "k", "--uat", "127.0.0.1:30978"])?;
        assert_eq!(config.uat.as_deref(), Some("127.0.0.1:30978"));
        Ok(())
    }
}

#[cfg(test)]
mod relay_address_tests {
    use super::*;

    #[test]
    fn a_relay_key_ending_in_padding_parses() -> Result<(), String> {
        let key = tally_wire::Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let text = format!("relay.example:10900={key}");
        assert!(
            text.ends_with('='),
            "a 32-byte key in base64 ends in padding"
        );
        let relay = parse_relay(&text)?;
        assert_eq!(
            (relay.address.as_str(), relay.key),
            ("relay.example:10900", key)
        );
        Ok(())
    }
}
