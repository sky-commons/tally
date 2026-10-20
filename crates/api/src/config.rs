//! The API's command line. Everything it is told comes from its operator, here, and everything a
//! start checks before it opens a socket (`Config::prepare`), which `tally-api check` runs alone.

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::{HeaderName, Uri};

use tally_wire::{Identity, RelayAddress};

use crate::Settings;

const USAGE: &str = "\
usage: tally-api --relay-stats URL --readsb URL [options]
       tally-api check --relay-stats URL --readsb URL [options]
                         refuse what a start would refuse, without starting: the same
                         arguments, read and checked as a start reads and checks them (the
                         key file's format, when it can read the file; the --routes
                         directory), with no socket opened and nothing read from the
                         network, then print the settings (listen, relay-stats, readsb,
                         allow-origins, client-ip-header, rate, burst, max-requests,
                         max-connections, refresh-secs, relays, linked-relay, key,
                         mlat-max-age-secs, routes), one `name value` a line, and exit 0

  --relay-stats URL      the relay's stats listener (its --stats-listen), such as
                         http://127.0.0.1:10901
  --readsb URL           readsb's API port (its --net-api-port), such as http://127.0.0.1:30152
  --listen ADDR          where the API serves HTTP, an IP and port (default 127.0.0.1:10902)
  --allow-origin ORIGIN  an origin CORS allows, such as the site that draws the API; repeatable
                         (default none: no other site's page may read the API)
  --client-ip-header NAME
                         read each client's address from this header (such as CF-Connecting-IP)
                         instead of the connection's; set it only behind a proxy that sets it
  --rate N               requests a second each client may make (default 20)
  --burst N              requests a client may make at once (default 40)
  --max-requests N       requests handled at once; beyond it one is answered 503 (default 256)
  --max-connections N    connections held at once; beyond it a new one is closed (default 4096)
  --refresh-secs N       how often the relay's stations and readsb's count are read (default 5)
  --relay HOST:PORT=KEY  a relay to read MLAT positions, clock models and its signed feeder
                         figures from; repeatable, and relays may overlap (none serves no MLAT
                         and no feeder figures)
  --key FILE             this client's key (base64, as a relay's --key); without it a fresh key
                         each run, which no relay can vouch for
  --linked-relay HOST:PORT=KEY
                         the relay that vouches for this client's key (its --client KEY): read
                         from like any --relay, and the firehose credential it signs is presented
                         to every relay read, which serves it on that relay's credit (RFC-0174
                         §2.1); needs --key. Without it every relay serves the free tier
  --mlat-max-age-secs N  the oldest MLAT position served (default 60)
  --routes DIR           a checkout of VRS standing data (its routes/ and airports/ CSV files),
                         which the operator keeps current; read at start and again whenever its
                         files change (default none: the routes answer 404)
";

/// What the command line asks for.
#[derive(Debug)]
pub enum Command {
    /// Start the API.
    Run(Config),
    /// Refuse what a start would refuse and print the settings, without starting (`check`).
    Check(Config),
    /// Nothing more: the command was fully handled (usage).
    Done,
}

impl Command {
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut args = args.peekable();
        if args.peek().map(String::as_str) != Some("check") {
            return Ok(Config::from_args(args)?.map_or(Self::Done, Self::Run));
        }
        args.next();
        Ok(Config::from_args(args)?.map_or(Self::Done, Self::Check))
    }
}

#[derive(Debug)]
pub struct Config {
    pub listen: SocketAddr,
    /// Everything the API is told, the linked relay (`--linked-relay`) among its MLAT relays.
    pub settings: Settings,
    /// This client's key file (`--key`), read by `prepare`.
    pub key_file: Option<String>,
}

/// How `prepare` reads the key file. A start reads it; a check reads it where it can, since a key
/// is an operator's secret, not its configuration, and a deploy's check may run without it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keys {
    Read,
    WhereReadable,
}

/// Where this client's identity came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// The key file's, read and well formed.
    File(String),
    /// None was named: a fresh key, which no relay vouches for.
    Fresh,
    /// A check could not read the file (and why); a throwaway key stands in for it.
    Unread(String, String),
}

/// A start's configuration, checked: everything a start needs before it binds its listener and
/// reads its upstreams. Made only from files on this host, never from the network.
pub struct Prepared {
    pub listen: SocketAddr,
    pub settings: Settings,
    pub identity: Identity,
    pub key: Key,
}

impl Config {
    /// `None` when the command was fully handled (usage).
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut listen = "127.0.0.1:10902".to_owned();
        let mut relay_stats = None;
        let mut readsb = None;
        let mut settings = Settings::new("", "");
        let mut origins = Vec::new();
        let mut key_file = None;
        let mut linked_relay: Option<RelayAddress> = None;
        let mut args = args.peekable();
        while let Some(flag) = args.next() {
            let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--listen" => listen = value()?,
                "--relay-stats" => relay_stats = Some(http_url(&flag, value()?)?),
                "--readsb" => readsb = Some(http_url(&flag, value()?)?),
                "--allow-origin" => origins.push(value()?),
                "--client-ip-header" => {
                    let name = value()?;
                    settings.client_ip_header = Some(
                        HeaderName::try_from(name.as_str())
                            .map_err(|error| format!("{name}: {error}"))?,
                    );
                }
                "--rate" => settings.rate = positive(&flag, &value()?)?,
                "--burst" => settings.burst = positive(&flag, &value()?)?,
                "--max-requests" => settings.max_requests = count(&flag, &value()?)?,
                "--max-connections" => settings.max_connections = count(&flag, &value()?)?,
                "--refresh-secs" => {
                    settings.refresh = Duration::from_secs(count(&flag, &value()?)? as u64);
                }
                "--relay" => settings.mlat.relays.push(RelayAddress::parse(&value()?)?),
                "--key" => key_file = Some(value()?),
                "--linked-relay" => {
                    if linked_relay.is_some() {
                        return Err(format!("--linked-relay is given once\n{USAGE}"));
                    }
                    linked_relay = Some(RelayAddress::parse(&value()?)?);
                }
                "--routes" => settings.routes = Some(value()?.into()),
                "--mlat-max-age-secs" => {
                    settings.mlat.max_age = Duration::from_secs(count(&flag, &value()?)? as u64);
                }
                "-h" | "--help" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                other => return Err(format!("unknown argument {other}\n{USAGE}")),
            }
        }
        // An address by number: a name would be resolved, which is the network's to answer.
        let listen = listen
            .parse::<SocketAddr>()
            .map_err(|error| format!("--listen {listen}: {error} (an IP and port)"))?;
        settings.relay_stats = relay_stats.ok_or(format!("--relay-stats is required\n{USAGE}"))?;
        settings.readsb = readsb.ok_or(format!("--readsb is required\n{USAGE}"))?;
        settings.allow_origins = origins;
        if let Some(linked) = &linked_relay {
            // A credential binds a key: one minted fresh each run is one no relay vouches for.
            if key_file.is_none() {
                return Err(format!("--linked-relay needs --key\n{USAGE}"));
            }
            if !settings.mlat.relays.contains(linked) {
                settings.mlat.relays.push(linked.clone());
            }
        }
        settings.mlat.linked = linked_relay;
        Ok(Some(Self {
            listen,
            settings,
            key_file,
        }))
    }

    /// Everything a start checks before it opens a socket, each refusal included: the key file
    /// (`keys` says whether one this host cannot read is refused) and the `--routes` directory,
    /// read as the routes read it (`vrs::fingerprint`). It reads files and nothing else: it is
    /// not async and is handed no runtime, so it can neither bind nor dial. A start runs it and
    /// then serves; `tally-api check` runs it alone, so a check refuses what a start refuses.
    pub fn prepare(self, keys: Keys) -> Result<Prepared, String> {
        let fresh = || Identity::generate().map_err(|error| error.to_string());
        let (identity, key) = match self.key_file {
            None => (fresh()?, Key::Fresh),
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(text) => (
                    Identity::from_base64(text.trim())
                        .map_err(|error| format!("--key {path}: {error}"))?,
                    Key::File(path),
                ),
                Err(error) if keys == Keys::WhereReadable => {
                    (fresh()?, Key::Unread(path, error.to_string()))
                }
                Err(error) => return Err(format!("--key {path}: {error}")),
            },
        };
        if let Some(dir) = &self.settings.routes {
            crate::vrs::fingerprint(dir)
                .map_err(|error| format!("--routes {}: {error}", dir.display()))?;
        }
        Ok(Prepared {
            listen: self.listen,
            settings: self.settings,
            identity,
            key,
        })
    }
}

impl Prepared {
    /// The settings, one `name value` a line, as `tally-api check` prints them.
    pub fn summary(&self) -> String {
        let settings = &self.settings;
        let none = || "none".to_owned();
        let relay = |relay: &RelayAddress| format!("{}={}", relay.address, relay.key.to_base64());
        let mut lines = vec![
            ("listen", self.listen.to_string()),
            ("relay-stats", settings.relay_stats.clone()),
            ("readsb", settings.readsb.clone()),
            (
                "allow-origins",
                if settings.allow_origins.is_empty() {
                    none()
                } else {
                    settings.allow_origins.join(",")
                },
            ),
            (
                "client-ip-header",
                settings
                    .client_ip_header
                    .as_ref()
                    .map_or_else(none, |name| name.as_str().to_owned()),
            ),
            ("rate", settings.rate.to_string()),
            ("burst", settings.burst.to_string()),
            ("max-requests", settings.max_requests.to_string()),
            ("max-connections", settings.max_connections.to_string()),
            ("refresh-secs", settings.refresh.as_secs().to_string()),
            ("relays", settings.mlat.relays.len().to_string()),
        ];
        for each in &settings.mlat.relays {
            lines.push(("relay", relay(each)));
        }
        lines.extend([
            (
                "linked-relay",
                settings.mlat.linked.as_ref().map_or_else(none, relay),
            ),
            (
                "key",
                match &self.key {
                    Key::File(path) => format!("{path} {}", self.identity.public().to_base64()),
                    Key::Fresh => "fresh".to_owned(),
                    Key::Unread(path, why) => format!("{path} unread ({why})"),
                },
            ),
            (
                "mlat-max-age-secs",
                settings.mlat.max_age.as_secs().to_string(),
            ),
            (
                "routes",
                settings
                    .routes
                    .as_ref()
                    .map_or_else(none, |dir| dir.display().to_string()),
            ),
        ]);
        lines
            .into_iter()
            .map(|(name, value)| format!("{name} {value}\n"))
            .collect()
    }
}

/// A base URL the upstream reads over plain HTTP (`upstream::Upstream`): absolute, `http`.
fn http_url(flag: &str, text: String) -> Result<String, String> {
    let uri = text
        .parse::<Uri>()
        .map_err(|error| format!("{flag} {text}: {error}"))?;
    if uri.scheme_str() != Some("http") || uri.authority().is_none() {
        return Err(format!("{flag} {text}: expected http://HOST:PORT"));
    }
    Ok(text)
}

fn positive(flag: &str, text: &str) -> Result<f64, String> {
    text.parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| format!("{flag} needs a positive number"))
}

fn count(flag: &str, text: &str) -> Result<usize, String> {
    text.parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{flag} needs a whole number above zero"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_REQUESTS, limit};

    const RELAY_STATS: &str = "http://127.0.0.1:10901";
    const READSB: &str = "http://127.0.0.1:30152";

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::from_args(args.iter().map(|arg| (*arg).to_owned()))?.ok_or("no config".to_owned())
    }

    #[test]
    fn the_upstreams_are_required_and_the_rest_default() -> Result<(), String> {
        assert!(parse(&["--readsb", "http://127.0.0.1:30152"]).is_err());
        let config = parse(&[
            "--relay-stats",
            "http://127.0.0.1:10901",
            "--readsb",
            "http://127.0.0.1:30152",
        ])?;
        let settings = &config.settings;
        assert_eq!(config.listen.to_string(), "127.0.0.1:10902");
        assert!(settings.allow_origins.is_empty());
        assert_eq!(
            (settings.rate, settings.burst),
            (limit::DEFAULT_RATE, limit::DEFAULT_BURST)
        );
        assert_eq!(
            (settings.max_requests, settings.max_connections),
            (DEFAULT_MAX_REQUESTS, DEFAULT_MAX_CONNECTIONS)
        );
        assert!(settings.client_ip_header.is_none());
        assert!(settings.routes.is_none());
        let config = parse(&[
            "--relay-stats",
            RELAY_STATS,
            "--readsb",
            READSB,
            "--routes",
            "/var/lib/tally/standing-data",
        ])?;
        assert_eq!(
            config.settings.routes,
            Some("/var/lib/tally/standing-data".into())
        );
        Ok(())
    }

    #[test]
    fn origins_are_the_operators_and_repeat() -> Result<(), String> {
        let config = parse(&[
            "--relay-stats",
            RELAY_STATS,
            "--readsb",
            READSB,
            "--allow-origin",
            "https://a.example",
            "--allow-origin",
            "https://b.example",
            "--client-ip-header",
            "CF-Connecting-IP",
            "--rate",
            "5",
        ])?;
        assert_eq!(
            config.settings.allow_origins,
            ["https://a.example", "https://b.example"]
        );
        assert_eq!(
            config
                .settings
                .client_ip_header
                .as_ref()
                .map(HeaderName::as_str),
            Some("cf-connecting-ip")
        );
        assert!(
            parse(&[
                "--relay-stats",
                RELAY_STATS,
                "--readsb",
                READSB,
                "--rate",
                "0"
            ])
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn mlat_relays_repeat_and_age_are_the_operators() -> Result<(), String> {
        let key = tally_wire::Identity::from_seed([3; 32])
            .public()
            .to_base64();
        let bare = parse(&["--relay-stats", RELAY_STATS, "--readsb", READSB])?;
        assert!(bare.settings.mlat.relays.is_empty());
        let one = format!("10.0.0.1:10900={key}");
        let two = format!("10.0.0.2:10900={key}");
        let config = parse(&[
            "--relay-stats",
            RELAY_STATS,
            "--readsb",
            READSB,
            "--relay",
            &one,
            "--relay",
            &two,
            "--mlat-max-age-secs",
            "30",
        ])?;
        let mlat = &config.settings.mlat;
        assert_eq!(mlat.relays.len(), 2);
        assert_eq!(mlat.relays[1].address, "10.0.0.2:10900");
        assert_eq!(mlat.max_age, Duration::from_secs(30));
        assert!(
            parse(&[
                "--relay-stats",
                RELAY_STATS,
                "--readsb",
                READSB,
                "--relay",
                "nokey"
            ])
            .is_err()
        );
        // Raw is relay-only (wire version 3): a client has none to merge from.
        assert!(
            parse(&[
                "--relay-stats",
                RELAY_STATS,
                "--readsb",
                READSB,
                "--mlat-raw"
            ])
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_linked_relay_is_read_from_and_needs_a_key() -> Result<(), String> {
        let key = tally_wire::Identity::from_seed([5; 32])
            .public()
            .to_base64();
        let linked = format!("10.0.0.9:10900={key}");
        assert!(
            parse(&[
                "--relay-stats",
                RELAY_STATS,
                "--readsb",
                READSB,
                "--linked-relay",
                &linked
            ])
            .is_err()
        );
        let config = parse(&[
            "--relay-stats",
            RELAY_STATS,
            "--readsb",
            READSB,
            "--key",
            "/etc/tally/api.key",
            "--linked-relay",
            &linked,
        ])?;
        assert_eq!(config.key_file.as_deref(), Some("/etc/tally/api.key"));
        let named = config.settings.mlat.linked.ok_or("no linked relay")?;
        assert_eq!(named.address, "10.0.0.9:10900");
        assert_eq!(config.settings.mlat.relays, [named]);
        // Named twice: refused, as a client is linked to one relay.
        assert!(
            parse(&[
                "--relay-stats",
                RELAY_STATS,
                "--readsb",
                READSB,
                "--key",
                "k",
                "--linked-relay",
                &linked,
                "--linked-relay",
                &linked,
            ])
            .is_err()
        );
        Ok(())
    }

    /// A file of this test's own under the temporary directory, removed when dropped.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            Self(
                std::env::temp_dir()
                    .join(format!("tally-api-config-{}-{name}", std::process::id())),
            )
        }

        fn text(&self) -> String {
            self.0.display().to_string()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn prepared(args: &[&str], keys: Keys) -> Result<Prepared, String> {
        let mut all = vec!["--relay-stats", RELAY_STATS, "--readsb", READSB];
        all.extend_from_slice(args);
        parse(&all)?.prepare(keys)
    }

    #[test]
    fn check_is_a_command_over_the_starts_arguments() -> Result<(), String> {
        let args = ["check", "--relay-stats", RELAY_STATS, "--readsb", READSB];
        let command = Command::from_args(args.iter().map(|arg| (*arg).to_owned()))?;
        assert!(matches!(command, Command::Check(_)));
        let command = Command::from_args(args[1..].iter().map(|arg| (*arg).to_owned()))?;
        assert!(matches!(command, Command::Run(_)));
        // The start's refusal, word for word.
        let checked = Command::from_args(
            [
                "check",
                "--relay-stats",
                RELAY_STATS,
                "--readsb",
                READSB,
                "--mlat-raw",
            ]
            .iter()
            .map(|arg| (*arg).to_owned()),
        )
        .err();
        let started = parse(&[
            "--relay-stats",
            RELAY_STATS,
            "--readsb",
            READSB,
            "--mlat-raw",
        ])
        .err();
        assert!(
            checked
                .as_deref()
                .is_some_and(|error| error.starts_with("unknown argument --mlat-raw"))
        );
        assert_eq!(checked, started);
        Ok(())
    }

    #[test]
    fn addresses_and_urls_are_read_by_number_and_scheme() {
        assert!(prepared(&["--listen", "0.0.0.0:10902"], Keys::Read).is_ok());
        assert!(prepared(&["--listen", "[::1]:10902"], Keys::Read).is_ok());
        // A name is the network's to resolve; a port is required.
        assert!(prepared(&["--listen", "localhost:10902"], Keys::Read).is_err());
        assert!(prepared(&["--listen", "127.0.0.1"], Keys::Read).is_err());
        for (flag, url) in [
            ("--readsb", "127.0.0.1:30152"),
            ("--readsb", "https://127.0.0.1:30152"),
            ("--relay-stats", "not a url"),
        ] {
            let mut args = vec!["--relay-stats", RELAY_STATS, "--readsb", READSB];
            args.extend([flag, url]);
            assert!(parse(&args).is_err(), "{flag} {url} was accepted");
        }
        assert!(prepared(&["--client-ip-header", "CF Connecting IP"], Keys::Read).is_err());
    }

    #[test]
    fn the_key_files_format_is_checked_and_its_absence_only_by_a_start() -> Result<(), String> {
        let named = Identity::from_seed([9; 32]);
        let good = Scratch::new("good.key");
        std::fs::write(&good.0, format!("{}\n", named.to_base64())).map_err(|e| e.to_string())?;
        for keys in [Keys::Read, Keys::WhereReadable] {
            let read = prepared(&["--key", &good.text()], keys)?;
            assert_eq!(read.identity.public(), named.public());
            assert_eq!(read.key, Key::File(good.text()));
        }
        let fresh = prepared(&[], Keys::Read)?;
        assert_eq!(fresh.key, Key::Fresh);
        assert_ne!(fresh.identity.public(), named.public());
        let bad = Scratch::new("bad.key");
        std::fs::write(&bad.0, "not a key\n").map_err(|e| e.to_string())?;
        for keys in [Keys::Read, Keys::WhereReadable] {
            let refused = prepared(&["--key", &bad.text()], keys).err();
            assert!(
                refused.is_some_and(|error| error.starts_with(&format!("--key {}", bad.text())))
            );
        }
        let missing = Scratch::new("missing.key");
        assert!(prepared(&["--key", &missing.text()], Keys::Read).is_err());
        let unread = prepared(&["--key", &missing.text()], Keys::WhereReadable)?;
        assert!(matches!(unread.key, Key::Unread(path, _) if path == missing.text()));
        Ok(())
    }

    #[test]
    fn the_routes_directory_is_read_as_the_routes_read_it() -> Result<(), String> {
        let missing = Scratch::new("no-routes");
        let refused = prepared(&["--routes", &missing.text()], Keys::Read).err();
        assert!(
            refused.is_some_and(|error| error.starts_with(&format!("--routes {}", missing.text())))
        );
        let dir = Scratch::new("routes");
        for sub in ["routes", "airports"] {
            std::fs::create_dir_all(dir.0.join(sub)).map_err(|e| e.to_string())?;
        }
        let read = prepared(&["--routes", &dir.text()], Keys::Read)?;
        assert!(read.summary().contains(&format!("routes {}\n", dir.text())));
        Ok(())
    }

    #[test]
    fn the_summary_says_every_setting() -> Result<(), String> {
        let summary = prepared(&[], Keys::Read)?.summary();
        let names: Vec<&str> = summary
            .lines()
            .filter_map(|line| line.split_once(' ').map(|(name, _)| name))
            .collect();
        assert_eq!(
            names,
            [
                "listen",
                "relay-stats",
                "readsb",
                "allow-origins",
                "client-ip-header",
                "rate",
                "burst",
                "max-requests",
                "max-connections",
                "refresh-secs",
                "relays",
                "linked-relay",
                "key",
                "mlat-max-age-secs",
                "routes",
            ]
        );
        for name in names {
            assert!(USAGE.contains(name), "the help does not name {name}");
        }
        assert!(summary.contains("listen 127.0.0.1:10902\n"));
        assert!(summary.contains("key fresh\n"));
        Ok(())
    }

    #[test]
    fn the_help_states_the_defaults_the_code_uses() {
        for stated in [
            format!("(default {})", limit::DEFAULT_RATE),
            format!("(default {})", limit::DEFAULT_BURST),
            format!("(default {DEFAULT_MAX_REQUESTS})"),
            format!("(default {DEFAULT_MAX_CONNECTIONS})"),
            format!("(default {})", crate::snapshot::DEFAULT_REFRESH.as_secs()),
            "(default none: no other site's page may read the API)".to_owned(),
            format!("(default {})", crate::mlat::DEFAULT_MAX_AGE.as_secs()),
            "(default none: the routes answer 404)".to_owned(),
        ] {
            assert!(USAGE.contains(&stated), "the help does not say {stated}");
        }
    }
}
