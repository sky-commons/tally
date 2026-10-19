//! The API's command line. Everything it is told comes from its operator, here.

use std::time::Duration;

use axum::http::HeaderName;

use tally_wire::RelayAddress;

use crate::Settings;

const USAGE: &str = "\
usage: tally-api --relay-stats URL --readsb URL [options]

  --relay-stats URL      the relay's stats listener (its --stats-listen), such as
                         http://127.0.0.1:10901
  --readsb URL           readsb's API port (its --net-api-port), such as http://127.0.0.1:30152
  --listen ADDR          where the API serves HTTP (default 127.0.0.1:10902)
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
  --relay HOST:PORT=KEY  a relay to read MLAT positions, clock models and raw from; repeatable,
                         and relays may overlap (none serves no MLAT and no feeder figures)
  --mlat-raw             merge from the raw too: verify every clock model from it, solve two
                         relays' incomparable solutions over their union (MLAT is a relay's
                         duty), and give receivers standing (without it no feeder is ranked on a
                         leaderboard)
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

#[derive(Debug)]
pub struct Config {
    pub listen: String,
    pub settings: Settings,
    /// This client's key file (`--key`).
    pub key_file: Option<String>,
    /// The relay that vouches for this client (`--linked-relay`), also among `settings`' relays.
    pub linked_relay: Option<RelayAddress>,
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
                "--relay-stats" => relay_stats = Some(value()?),
                "--readsb" => readsb = Some(value()?),
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
                "--mlat-raw" => settings.mlat.raw = true,
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
        Ok(Some(Self {
            listen,
            settings,
            key_file,
            linked_relay,
        }))
    }
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
        assert_eq!(config.listen, "127.0.0.1:10902");
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
            "r",
            "--readsb",
            "s",
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
            "r",
            "--readsb",
            "s",
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
        assert!(parse(&["--relay-stats", "r", "--readsb", "s", "--rate", "0"]).is_err());
        Ok(())
    }

    #[test]
    fn mlat_relays_repeat_and_raw_and_age_are_the_operators() -> Result<(), String> {
        let key = tally_wire::Identity::from_seed([3; 32])
            .public()
            .to_base64();
        let bare = parse(&["--relay-stats", "r", "--readsb", "s"])?;
        assert!(bare.settings.mlat.relays.is_empty() && !bare.settings.mlat.raw);
        let one = format!("10.0.0.1:10900={key}");
        let two = format!("10.0.0.2:10900={key}");
        let config = parse(&[
            "--relay-stats",
            "r",
            "--readsb",
            "s",
            "--relay",
            &one,
            "--relay",
            &two,
            "--mlat-raw",
            "--mlat-max-age-secs",
            "30",
        ])?;
        let mlat = &config.settings.mlat;
        assert_eq!(mlat.relays.len(), 2);
        assert_eq!(mlat.relays[1].address, "10.0.0.2:10900");
        assert!(mlat.raw);
        assert_eq!(mlat.max_age, Duration::from_secs(30));
        assert!(parse(&["--relay-stats", "r", "--readsb", "s", "--relay", "nokey"]).is_err());
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
                "r",
                "--readsb",
                "s",
                "--linked-relay",
                &linked
            ])
            .is_err()
        );
        let config = parse(&[
            "--relay-stats",
            "r",
            "--readsb",
            "s",
            "--key",
            "/etc/tally/api.key",
            "--linked-relay",
            &linked,
        ])?;
        assert_eq!(config.key_file.as_deref(), Some("/etc/tally/api.key"));
        let named = config.linked_relay.ok_or("no linked relay")?;
        assert_eq!(named.address, "10.0.0.9:10900");
        assert_eq!(config.settings.mlat.relays, [named]);
        // Named twice: refused, as a client is linked to one relay.
        assert!(
            parse(&[
                "--relay-stats",
                "r",
                "--readsb",
                "s",
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
