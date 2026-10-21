//! The feeder's command line. Everything a feeder does is decided here, by its owner, or by the
//! fixed rules in this binary: nothing on the network can reconfigure it (RFC-0171 §3.5).

use std::path::PathBuf;

use tally_wire::{Clock, Location, PublicKey, RelayAddress};

/// The relays shipped in the binary, known like any `--relay`: the release's seed list,
/// packaging/seeds, compiled in, so the binary, the image built from it and the `seeds` file the
/// installer reads are one list. Its format is the installer's (one `HOST:PORT=KEY OPERATOR` a
/// line, `#` comments); the feeder reads the first field. Until it names relays of several
/// independent operators, a single operator can steer every new feeder (RFC-0171 §3.5, §3.7). It
/// is only a starting point; the feeder learns relays from relays and keeps what it learned.
pub const SEEDS: &str = include_str!("../../../packaging/seeds");

/// The relays `SEEDS` names.
pub fn seeds() -> Result<Vec<RelayAddress>, String> {
    SEEDS
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(before, _)| before))
        .filter_map(|line| line.split_whitespace().next())
        .map(parse_relay)
        .collect()
}

/// The environment variables a container is configured by, in the idiom of the sdr-enthusiasts
/// images (ultrafeeder and the feeders beside it), each used only where its flag is not given:
/// a flag always wins.
///
/// - `BEASTHOST`, `BEASTPORT` (default 30005): `--source BEASTHOST:BEASTPORT`.
/// - `LAT` or `READSB_LAT`, `LONG` or `READSB_LON`: `--lat`, `--lon`.
/// - `ALT` or `READSB_ALT`: `--alt`, a bare number or with `m` or `ft` (`15m`, `45ft`), as
///   ultrafeeder takes it and hands it to mlat-client.
/// - `TALLY_KEY`: the identity's text, as `--key-env TALLY_KEY`.
/// - `TALLY_STATE`: `--state`.
///
/// An empty variable is an unset one, as a compose file's `${UNSET}` makes it.
pub const ENVIRONMENT: &[&str] = &[
    "BEASTHOST",
    "BEASTPORT",
    "LAT",
    "READSB_LAT",
    "LONG",
    "READSB_LON",
    "ALT",
    "READSB_ALT",
    "TALLY_KEY",
    "TALLY_STATE",
];

/// The variable a key held in the environment is read from when no flag names one.
pub const KEY_VARIABLE: &str = "TALLY_KEY";

/// The key file's name in the state directory when no flag and no `TALLY_KEY` names the key.
pub const KEPT_KEY: &str = "key";

const USAGE: &str = "\
usage: tally-feed [--key FILE | --key-env NAME] [options]
       tally-feed init --key FILE      create the key file if it is missing, print its public key
       tally-feed new-key              print a new identity's secret (line 1, the text a key file
                                       holds) and its public key (line 2), writing no file
       tally-feed health [--state DIR] say whether the feeder running with this state directory
                                       is publishing to a relay and reading its decoder (exit 0)
                                       or not (exit 1), from the status file it keeps there

  --key FILE             this receiver's identity (keep it: it is the antenna's name forever)
  --key-env NAME         the same identity, read from the environment variable NAME instead of a
                         file (the text a key file holds, as `new-key` prints it), for a host that
                         keeps secrets in its own configuration, such as a container's.
                         With neither, the key is the file `key` in the state directory, made
                         on the first run if it is missing (TALLY_KEY in the environment, when
                         set, is used as --key-env TALLY_KEY instead)
  --source HOST:PORT     readsb's BEAST output (default 127.0.0.1:30005)
  --uat HOST:PORT        dump978-fa's raw output, for 978 MHz UAT (none by default; it is
                         usually 127.0.0.1:30978)
  --acars HOST:PORT      acars_router's JSON output over TCP, which takes the ACARS, VDL2 and
                         HFDL decoders' (15550 ACARS, 15555 VDL2, 15556 HFDL); repeatable, none
                         by default. Only each message's aircraft, content and time are published
  --acars-ceiling BYTES  the most of --ceiling these messages take a second (default 8000),
                         so ADS-B always keeps the rest; less than --ceiling, which is
                         then at least 16394 bytes (the longest message)
  --relay HOST:PORT=KEY  a relay to consider; repeatable. Measured and ranked like every relay the
                         feeder knows: the feeder sends to the two nearest healthy relays on
                         different networks, chosen with every feeder of its area (RFC-0174)
  --state DIR            where learned relays and relays found swallowing are kept
                         (default /var/lib/tally-feed)
  --lat DEG --lon DEG --alt ALT
                         the antenna's position, sent exactly only to Tally relays (MLAT
                         needs it exact); ALT is the height as mlat-client takes it, a bare
                         number or with a unit: 34, 34m, 112ft (feet are converted to the
                         nearest metre). No client is sent it: public surfaces (the map,
                         station pages, the API) show only its public cell, about 5 km across
  --precision M          expert only: round the position to a grid of M-metre cells before
                         anything is signed or sent, so not even relay operators see the exact
                         one (latitude to the nearest M metres from the equator, longitude to
                         the nearest M metres from the prime meridian at the cell's latitude;
                         altitude kept; within M of the antenna). Default 0, exact. Above 30 m
                         the MLAT solver leaves the receiver out entirely: it still feeds ADS-B
                         but contributes nothing to MLAT
  --clock NAME           the receiver's clock: dump1090 (RTL-SDR, the default), beast,
                         radarcape_12mhz, radarcape_gps
  --ceiling BYTES        the most this feeder sends each relay per second (default 64000)

The environment configures what no flag does, as an sdr-enthusiasts container is configured:
BEASTHOST and BEASTPORT (default 30005) for --source, LAT (or READSB_LAT), LONG (or READSB_LON)
and ALT (or READSB_ALT) for the position, TALLY_KEY and TALLY_STATE. A flag always wins;
--precision is a flag only.
";

pub enum Command {
    Init(PathBuf),
    NewKey,
    /// `health`: judge the status file in this state directory (`health::check`).
    Health(PathBuf),
    Run(Box<Config>),
    Done,
}

/// Where the receiver's identity is read from: exactly one of `--key` and `--key-env`. Either holds
/// the same text, the identity's secret in base64 as `init` writes it and `new-key` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    File(PathBuf),
    /// The name of an environment variable, never its value: the secret is read where it is used
    /// (`crate::load`), so a printed `Config` cannot show it.
    Env(String),
    /// A key file the feeder keeps itself, made on the first run if it is missing: what a feeder
    /// named no key runs with, `KEPT_KEY` in its state directory. A container's volume holds it.
    Kept(PathBuf),
}

#[derive(Debug)]
pub struct Config {
    pub key: Key,
    pub source: String,
    pub uat: Option<String>,
    /// The ACARS-family decoders' JSON outputs (`--acars`, `crate::acars`).
    pub acars: Vec<String>,
    /// The most of `ceiling` their messages take a second (`--acars-ceiling`).
    pub acars_ceiling: u32,
    /// The relays the owner named with `--relay`: candidates, never pinned (RFC-0174 §2.2).
    pub relays: Vec<RelayAddress>,
    /// The relays shipped in the binary (`SEEDS`).
    pub seeds: Vec<RelayAddress>,
    pub state_dir: PathBuf,
    pub location: Option<Location>,
    pub clock: Clock,
    pub ceiling: u32,
    /// The local address its relay sessions connect from; `None` (always, from the command line)
    /// is the system's choice. A load harness sets one for each simulated feeder.
    pub source_address: Option<std::net::IpAddr>,
    /// The DEFLATE level its batches are compressed at; `None` (always, from the command line) is
    /// the wire's own. A load harness lowers it so thousands of feeders fit the cores one reader
    /// has: level 2 compresses a batch of 860 receptions within 2% of level 6's size in a quarter
    /// of the time.
    pub deflate_level: Option<u8>,
}

/// The command line alone, as if the environment held none of `ENVIRONMENT`.
pub fn parse(args: impl Iterator<Item = String>) -> Result<Command, String> {
    parse_with(args, &|_| None)
}

/// The command line, with `env` (a variable's value by name) for what no flag gives
/// (`ENVIRONMENT`).
pub fn parse_with(
    args: impl Iterator<Item = String>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Command, String> {
    let env = |name: &str| env(name).filter(|value| !value.trim().is_empty());
    let mut args = args.peekable();
    if args.peek().map(String::as_str) == Some("new-key") {
        args.next();
        return match args.next() {
            None => Ok(Command::NewKey),
            Some(extra) => Err(format!("new-key takes no arguments, not {extra}\n{USAGE}")),
        };
    }
    if args.peek().map(String::as_str) == Some("health") {
        args.next();
        let mut state = env("TALLY_STATE").map(PathBuf::from);
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--state" => {
                    state = Some(PathBuf::from(args.next().ok_or("--state needs a value")?));
                }
                other => return Err(format!("health takes --state DIR, not {other}\n{USAGE}")),
            }
        }
        return Ok(Command::Health(
            state.unwrap_or_else(|| PathBuf::from(DEFAULT_STATE)),
        ));
    }
    let init = args.peek().map(String::as_str) == Some("init");
    if init {
        args.next();
    }
    let (mut key_file, mut key_env) = (None, None);
    let mut config = Config {
        key: Key::File(PathBuf::new()),
        source: "127.0.0.1:30005".to_owned(),
        uat: None,
        acars: Vec::new(),
        acars_ceiling: crate::source::DEFAULT_ACARS_CEILING,
        relays: Vec::new(),
        seeds: Vec::new(),
        state_dir: PathBuf::from(DEFAULT_STATE),
        location: None,
        clock: Clock::Dump1090,
        ceiling: 64_000,
        source_address: None,
        deflate_level: None,
    };
    let (mut lat, mut lon, mut alt, mut precision) = (None, None, None, None);
    let (mut source, mut state) = (false, false);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--key" => key_file = Some(PathBuf::from(value()?)),
            "--key-env" => key_env = Some(value()?),
            "--source" => {
                config.source = value()?;
                source = true;
            }
            "--uat" => config.uat = Some(value()?),
            "--acars" => config.acars.push(value()?),
            "--acars-ceiling" => config.acars_ceiling = number(&flag, &value()?)?,
            "--relay" => config.relays.push(parse_relay(&value()?)?),
            // Retired with the home, anchor and random slots (RFC-0174 §2.2), and refused, so no
            // command line goes on saying what the feeder no longer does.
            "--home" | "--relays" => return Err(retired(&flag)),
            "--state" => {
                config.state_dir = PathBuf::from(value()?);
                state = true;
            }
            "--lat" => lat = Some(degrees(&flag, &value()?, 90.0)?),
            "--lon" => lon = Some(degrees(&flag, &value()?, 180.0)?),
            "--alt" => alt = Some(altitude(&flag, &value()?)?),
            "--precision" => precision = Some(number(&flag, &value()?)?),
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
    if config.acars_ceiling == 0 {
        return Err(
            "--acars-ceiling 0 would publish no message; leave out --acars to publish none"
                .to_owned(),
        );
    }
    if !config.acars.is_empty() && (config.ceiling as usize) < crate::source::LONGEST_ACARS {
        return Err(format!(
            "--ceiling {} is less than the longest ACARS message ({} bytes), which it could never \
             send: raise it, or leave out --acars",
            config.ceiling,
            crate::source::LONGEST_ACARS
        ));
    }
    if !config.acars.is_empty() && config.acars_ceiling >= config.ceiling {
        return Err(format!(
            "--acars-ceiling {} leaves ADS-B nothing of --ceiling {}: give it less",
            config.acars_ceiling, config.ceiling
        ));
    }
    if init {
        // `init` makes a key file; a key held in the environment is made with `new-key`.
        if key_env.is_some() {
            return Err(format!(
                "init writes a key file and takes --key FILE; make a key for --key-env with \
                 new-key\n{USAGE}"
            ));
        }
        let key_file = key_file.ok_or_else(|| format!("--key is required\n{USAGE}"))?;
        return Ok(Command::Init(key_file));
    }
    // What no flag gave, from the environment.
    if !source && let Some(host) = env("BEASTHOST") {
        let port = env("BEASTPORT").unwrap_or_else(|| "30005".to_owned());
        config.source = format!("{}:{}", host.trim(), port.trim());
    }
    if !state && let Some(dir) = env("TALLY_STATE") {
        config.state_dir = PathBuf::from(dir);
    }
    let either = |one: &str, other: &str| {
        env(one)
            .map(|value| (one.to_owned(), value))
            .or_else(|| env(other).map(|value| (other.to_owned(), value)))
    };
    if lat.is_none()
        && let Some((name, text)) = either("LAT", "READSB_LAT")
    {
        lat = Some(degrees(&name, text.trim(), 90.0)?);
    }
    if lon.is_none()
        && let Some((name, text)) = either("LONG", "READSB_LON")
    {
        lon = Some(degrees(&name, text.trim(), 180.0)?);
    }
    if alt.is_none()
        && let Some((name, text)) = either("ALT", "READSB_ALT")
    {
        alt = Some(altitude(&name, &text)?);
    }
    if key_file.is_none() && key_env.is_none() && env(KEY_VARIABLE).is_some() {
        key_env = Some(KEY_VARIABLE.to_owned());
    }
    config.key = match (key_file, key_env) {
        (Some(file), None) => Key::File(file),
        (None, Some(name)) if name.is_empty() => {
            return Err("--key-env needs a variable name".to_owned());
        }
        (None, Some(name)) => Key::Env(name),
        (None, None) => Key::Kept(config.state_dir.join(KEPT_KEY)),
        (Some(_), Some(_)) => {
            return Err("--key and --key-env both name the identity: give one".to_owned());
        }
    };
    config.seeds = seeds()?;
    config.location = match (lat, lon) {
        (Some(lat_e7), Some(lon_e7)) => Some(Location {
            lat_e7,
            lon_e7,
            alt_m: alt.unwrap_or(0),
            precision_m: precision.unwrap_or(0),
        }),
        (None, None) => None,
        _ => return Err("--lat and --lon (LAT and LONG) go together".to_owned()),
    };
    Ok(Command::Run(Box::new(config)))
}

/// Why a retired flag is refused, and what replaces it.
fn retired(flag: &str) -> String {
    let instead = if flag == "--home" {
        "a home relay is a candidate like any other: name it with --relay HOST:PORT=KEY"
    } else {
        "a feeder always sends to two relays: remove it"
    };
    format!("{flag} was retired with the home, anchor and random slots (RFC-0174 §2.2); {instead}")
}

/// Where a feeder keeps its state unless `--state` says otherwise.
pub const DEFAULT_STATE: &str = "/var/lib/tally-feed";

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

/// An altitude to whole metres: a bare number or `<n>m` is metres, `<n>ft` is feet, each rounded
/// to the nearest metre (mlat-client's `--alt` format, so one value serves both).
fn altitude(flag: &str, text: &str) -> Result<i32, String> {
    let (number_text, metres_per_unit) = match text.trim() {
        feet if feet.ends_with("ft") => (&feet[..feet.len() - 2], 0.3048),
        metres if metres.ends_with('m') => (&metres[..metres.len() - 1], 1.0),
        metres => (metres, 1.0),
    };
    let value: f64 = number_text
        .trim()
        .parse()
        .map_err(|_| format!("{flag}: {text} is not an altitude (34, 34m or 112ft)"))?;
    let metres = (value * metres_per_unit).round();
    if !metres.is_finite() || metres < f64::from(i32::MIN) || metres > f64::from(i32::MAX) {
        return Err(format!("{flag}: {text} is out of range"));
    }
    Ok(metres as i32)
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
    fn the_release_seed_list_is_compiled_in_and_every_line_is_a_relay() -> Result<(), String> {
        let seeds = seeds()?;
        assert!(!seeds.is_empty(), "packaging/seeds names no relay");
        let lines = SEEDS
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .count();
        assert_eq!(seeds.len(), lines);
        Ok(())
    }

    #[test]
    fn seeds_join_the_relays_the_owner_named() -> Result<(), String> {
        let config = run(&["--key", "k"])?;
        assert_eq!((config.relays.len(), config.seeds), (0, seeds()?));
        Ok(())
    }

    fn with_env(args: &[&str], vars: &[(&str, &str)]) -> Result<Config, String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let env = move |name: &str| {
            vars.iter()
                .find(|(each, _)| each == name)
                .map(|(_, value)| value.clone())
        };
        match parse_with(args.iter().map(|arg| (*arg).to_owned()), &env)? {
            Command::Run(config) => Ok(*config),
            _ => Err("not a run".to_owned()),
        }
    }

    #[test]
    fn a_container_is_one_environment_block() -> Result<(), String> {
        let config = with_env(
            &[],
            &[
                ("BEASTHOST", "ultrafeeder"),
                ("LAT", "33.9425361"),
                ("LONG", "-118.4080749"),
                ("ALT", "45ft"),
                ("PRECISION", "500"),
            ],
        )?;
        // Rounding is a flag, never the environment's.
        assert_eq!(config.source, "ultrafeeder:30005");
        assert_eq!(
            config.location,
            Some(Location {
                lat_e7: 339_425_361,
                lon_e7: -1_184_080_749,
                alt_m: 14,
                precision_m: 0,
            })
        );
        assert_eq!(
            config.key,
            Key::Kept(PathBuf::from("/var/lib/tally-feed/key"))
        );
        let config = with_env(
            &[],
            &[
                ("BEASTHOST", "readsb"),
                ("BEASTPORT", "30105"),
                ("READSB_LAT", "51.5"),
                ("READSB_LON", "-0.12"),
                ("READSB_ALT", "15m"),
                ("TALLY_KEY", "secret"),
                ("TALLY_STATE", "/data"),
            ],
        )?;
        assert_eq!(config.source, "readsb:30105");
        let location = config.location.ok_or("no location")?;
        assert_eq!((location.alt_m, location.precision_m), (15, 0));
        assert_eq!(config.key, Key::Env("TALLY_KEY".to_owned()));
        assert_eq!(config.state_dir, PathBuf::from("/data"));
        Ok(())
    }

    #[test]
    fn a_flag_wins_over_the_environment_and_empty_is_unset() -> Result<(), String> {
        let config = with_env(
            &[
                "--source",
                "127.0.0.1:30005",
                "--lat",
                "1",
                "--lon",
                "2",
                "--alt",
                "3",
                "--precision",
                "20",
                "--key",
                "/etc/tally/key",
                "--state",
                "/s",
            ],
            &[
                ("BEASTHOST", "ultrafeeder"),
                ("LAT", "33.9"),
                ("LONG", "-118.4"),
                ("ALT", "45ft"),
                ("TALLY_KEY", "secret"),
                ("TALLY_STATE", "/data"),
            ],
        )?;
        assert_eq!(config.source, "127.0.0.1:30005");
        assert_eq!(
            config.location,
            Some(Location {
                lat_e7: 10_000_000,
                lon_e7: 20_000_000,
                alt_m: 3,
                precision_m: 20,
            })
        );
        assert_eq!(config.key, Key::File(PathBuf::from("/etc/tally/key")));
        assert_eq!(config.state_dir, PathBuf::from("/s"));
        let config = with_env(
            &[],
            &[
                ("BEASTHOST", " "),
                ("LAT", ""),
                ("LONG", ""),
                ("TALLY_KEY", ""),
            ],
        )?;
        assert_eq!(
            (config.source.as_str(), config.location, &config.key),
            (
                "127.0.0.1:30005",
                None,
                &Key::Kept(PathBuf::from("/var/lib/tally-feed/key"))
            )
        );
        Ok(())
    }

    #[test]
    fn a_bad_environment_value_is_refused_by_name() {
        for (name, value) in [("LAT", "north"), ("ALT", "m"), ("LONG", "east")] {
            let mut vars = vec![("LAT", "33.9"), ("LONG", "-118.4")];
            vars.retain(|(each, _)| *each != name);
            vars.push((name, value));
            assert!(
                with_env(&[], &vars).is_err_and(|why| why.starts_with(name)),
                "{name}={value} was taken"
            );
        }
        assert!(with_env(&[], &[("LAT", "33.9")]).is_err_and(|why| why.contains("go together")));
    }

    #[test]
    fn health_reads_the_state_directory() -> Result<(), String> {
        let parsed = |args: &[&str], vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect();
            parse_with(
                args.iter().map(|arg| (*arg).to_owned()),
                &move |name: &str| {
                    vars.iter()
                        .find(|(each, _)| each == name)
                        .map(|(_, value)| value.clone())
                },
            )
        };
        assert!(
            matches!(parsed(&["health"], &[])?, Command::Health(dir) if dir == std::path::Path::new(DEFAULT_STATE))
        );
        assert!(
            matches!(parsed(&["health", "--state", "/s"], &[("TALLY_STATE", "/e")])?, Command::Health(dir) if dir == std::path::Path::new("/s"))
        );
        assert!(
            matches!(parsed(&["health"], &[("TALLY_STATE", "/e")])?, Command::Health(dir) if dir == std::path::Path::new("/e"))
        );
        assert!(parsed(&["health", "--key", "k"], &[]).is_err());
        Ok(())
    }

    fn alt(text: &str) -> Result<i32, String> {
        run(&[
            "--key", "k", "--lat", "33.9", "--lon", "-118.4", "--alt", text,
        ])?
        .location
        .map(|location| location.alt_m)
        .ok_or_else(|| "no location".to_owned())
    }

    #[test]
    fn alt_takes_metres_bare_or_suffixed_and_feet() -> Result<(), String> {
        assert_eq!(alt("34")?, 34);
        assert_eq!(alt("34m")?, 34);
        assert_eq!(alt("-12m")?, -12);
        assert_eq!(alt("34.6")?, 35);
        // 112 ft is 34.1376 m; 100 ft is 30.48 m.
        assert_eq!(alt("112ft")?, 34);
        assert_eq!(alt("100ft")?, 30);
        assert_eq!(alt("-50ft")?, -15);
        for bad in [
            "",
            "m",
            "ft",
            "34 metres",
            "34M",
            "34feet",
            "nan",
            "infm",
            "1e10",
        ] {
            assert!(alt(bad).is_err(), "{bad} was taken");
        }
        Ok(())
    }

    #[test]
    fn the_retired_home_and_relay_count_are_refused() -> Result<(), String> {
        let key = tally_wire::Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let home = format!("home.example:10900={key}");
        for args in [
            vec!["--key", "k", "--home", home.as_str()],
            vec!["--key", "k", "--relays", "1"],
        ] {
            let refused = run(&args).err().ok_or("a retired flag was taken")?;
            assert!(refused.contains("retired"), "{refused}");
        }
        assert!(run(&["--key", "k", "--home", &home]).is_err_and(|why| why.contains("--relay")));
        Ok(())
    }

    #[test]
    fn the_key_is_a_file_or_an_environment_variable() -> Result<(), String> {
        assert_eq!(
            run(&["--key", "/etc/tally/key"])?.key,
            Key::File(PathBuf::from("/etc/tally/key"))
        );
        assert_eq!(
            run(&["--key-env", "TALLY_KEY"])?.key,
            Key::Env("TALLY_KEY".to_owned())
        );
        Ok(())
    }

    #[test]
    fn at_most_one_key_and_none_is_the_kept_one() {
        assert!(
            run(&["--state", "/s"])
                .is_ok_and(|config| config.key == Key::Kept(PathBuf::from("/s/key")))
        );
        assert!(
            run(&["--key", "k", "--key-env", "TALLY_KEY"]).is_err_and(|why| why.contains("one"))
        );
        assert!(run(&["--key-env", ""]).is_err());
        assert!(run(&["--key-env"]).is_err_and(|why| why.contains("needs a value")));
    }

    #[test]
    fn new_key_takes_nothing_and_init_takes_a_file() -> Result<(), String> {
        let parsed = |args: &[&str]| parse(args.iter().map(|arg| (*arg).to_owned()));
        assert!(matches!(parsed(&["new-key"])?, Command::NewKey));
        assert!(parsed(&["new-key", "--key", "k"]).is_err());
        assert!(
            matches!(parsed(&["init", "--key", "k"])?, Command::Init(path) if path == std::path::Path::new("k"))
        );
        assert!(
            parsed(&["init", "--key-env", "TALLY_KEY"]).is_err_and(|why| why.contains("new-key"))
        );
        Ok(())
    }

    #[test]
    fn uat_is_off_unless_named() -> Result<(), String> {
        assert_eq!(run(&["--key", "k"])?.uat, None);
        let config = run(&["--key", "k", "--uat", "127.0.0.1:30978"])?;
        assert_eq!(config.uat.as_deref(), Some("127.0.0.1:30978"));
        Ok(())
    }

    #[test]
    fn acars_is_off_unless_named_and_keeps_adsb_its_share() -> Result<(), String> {
        let config = run(&["--key", "k"])?;
        assert!(config.acars.is_empty());
        assert_eq!(config.acars_ceiling, crate::source::DEFAULT_ACARS_CEILING);
        let config = run(&[
            "--key",
            "k",
            "--acars",
            "127.0.0.1:15550",
            "--acars",
            "127.0.0.1:15555",
            "--acars-ceiling",
            "2000",
        ])?;
        assert_eq!(config.acars, ["127.0.0.1:15550", "127.0.0.1:15555"]);
        assert_eq!(config.acars_ceiling, 2000);
        let starving = [
            "--key",
            "k",
            "--acars",
            "a:1",
            "--ceiling",
            "20000",
            "--acars-ceiling",
            "20000",
        ];
        assert!(run(&starving).is_err_and(|why| why.contains("--acars-ceiling")));
        let short = ["--key", "k", "--acars", "a:1", "--ceiling", "16000"];
        assert!(run(&short).is_err_and(|why| why.contains("longest ACARS message")));
        assert!(USAGE.contains(&format!("at least {} bytes", crate::source::LONGEST_ACARS)));
        let off = ["--key", "k", "--acars", "a:1", "--acars-ceiling", "0"];
        assert!(run(&off).is_err_and(|why| why.contains("--acars-ceiling 0")));
        // With no ACARS source, a low --ceiling is no conflict.
        assert_eq!(run(&["--key", "k", "--ceiling", "4000"])?.ceiling, 4000);
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
