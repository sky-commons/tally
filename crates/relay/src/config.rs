//! The relay's command line. Everything a relay is told comes from its operator, here.

use tally_wire::{Identity, PublicKey, RelayAddress};

use crate::hub::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS_PER_ADDRESS, DEFAULT_MAX_DEDUP_BYTES,
    DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
};

const USAGE: &str = "\
usage: tally-relay --key FILE [--key FILE]... [options]
       tally-relay keygen          print a new key file to stdout and its public key to stderr

  --key FILE             this relay's key; repeat during a rotation, newest first
  --listen ADDR          where feeders, subscribers and relays connect (default 0.0.0.0:10900)
  --beast-out ADDR       serve plain BEAST of every reception here, for a local decoder
                         (bind it to loopback: it is unauthenticated)
  --upstream HOST:PORT=KEY
                         a parent relay to exchange batches with; repeatable
  --advertise HOST:PORT=KEY
                         another relay to offer feeders and turned-away subscribers as a hint,
                         beside the upstreams; repeatable
  --accept-relay KEY     a relay allowed to dial in as one (it may forward anyone's batches and
                         is not held to the subscriber cap); repeatable. Any other key claiming
                         to be a relay is refused
  --max-subscribers N    subscribers served before new ones are turned away (default 64)
  --max-connections N    connections held at once; beyond it a new one is closed before its
                         handshake (default 2048)
  --max-connections-per-address N
                         connections held at once from one IPv4 address or IPv6 /64; beyond
                         it a new one from there is closed before its handshake (default 16)
  --max-feeder-bytes-per-sec N
                         the most one connection that dialled in may send a second, with a
                         burst of the larger of N and 192 KiB; beyond it the connection is told
                         the relay is full and dropped (default 262144). Feeders are told
                         this, less framing, as their rate limit
  --max-dedup-bytes N    the most the deduplicated stream holds of messages being compared;
                         beyond it new messages are forwarded raw only (default 268435456)
";

#[derive(Clone, Debug)]
pub struct Upstream {
    pub address: String,
    pub key: PublicKey,
}

#[derive(Debug)]
pub struct Config {
    pub key_files: Vec<String>,
    pub listen: String,
    pub beast_out: Option<String>,
    pub upstreams: Vec<Upstream>,
    pub advertise: Vec<RelayAddress>,
    pub accept_relays: Vec<PublicKey>,
    pub max_subscribers: usize,
    pub max_connections: usize,
    pub max_connections_per_address: usize,
    pub max_feeder_bytes_per_sec: u64,
    pub max_dedup_bytes: usize,
}

impl Config {
    /// `None` when the command was fully handled (usage, keygen).
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut config = Self {
            key_files: Vec::new(),
            listen: "0.0.0.0:10900".to_owned(),
            beast_out: None,
            upstreams: Vec::new(),
            advertise: Vec::new(),
            accept_relays: Vec::new(),
            max_subscribers: 64,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
            max_feeder_bytes_per_sec: DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            max_dedup_bytes: DEFAULT_MAX_DEDUP_BYTES,
        };
        let mut args = args.peekable();
        if args.peek().map(String::as_str) == Some("keygen") {
            let identity = Identity::generate().map_err(|error| error.to_string())?;
            println!("{}", identity.to_base64());
            eprintln!("public key: {}", identity.public());
            return Ok(None);
        }
        while let Some(flag) = args.next() {
            let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
            match flag.as_str() {
                "--key" => config.key_files.push(value()?),
                "--listen" => config.listen = value()?,
                "--beast-out" => config.beast_out = Some(value()?),
                "--upstream" => config.upstreams.push(parse_upstream(&value()?)?),
                "--advertise" => {
                    let Upstream { address, key } = parse_upstream(&value()?)?;
                    config.advertise.push(RelayAddress { key, address });
                }
                "--accept-relay" => {
                    let text = value()?;
                    let key = PublicKey::from_base64(&text)
                        .map_err(|error| format!("{text}: {error}"))?;
                    config.accept_relays.push(key);
                }
                "--max-connections" => {
                    config.max_connections = value()?
                        .parse()
                        .map_err(|_| "--max-connections needs a number".to_owned())?;
                }
                "--max-connections-per-address" => {
                    config.max_connections_per_address = value()?
                        .parse()
                        .map_err(|_| "--max-connections-per-address needs a number".to_owned())?;
                }
                "--max-dedup-bytes" => {
                    config.max_dedup_bytes = value()?
                        .parse()
                        .map_err(|_| "--max-dedup-bytes needs a number".to_owned())?;
                }
                "--max-feeder-bytes-per-sec" => {
                    config.max_feeder_bytes_per_sec = value()?
                        .parse()
                        .map_err(|_| "--max-feeder-bytes-per-sec needs a number".to_owned())?;
                }
                "--max-subscribers" => {
                    config.max_subscribers = value()?
                        .parse()
                        .map_err(|_| "--max-subscribers needs a number".to_owned())?;
                }
                "-h" | "--help" => {
                    print!("{USAGE}");
                    return Ok(None);
                }
                other => return Err(format!("unknown argument {other}\n{USAGE}")),
            }
        }
        if config.key_files.is_empty() {
            return Err(format!("--key is required\n{USAGE}"));
        }
        // A relay list carries a one-byte count.
        if config.hints().len() > usize::from(u8::MAX) {
            return Err("at most 255 advertised relays and upstreams together".to_owned());
        }
        Ok(Some(config))
    }

    /// The relays offered as hints (RFC-0166 §3.7): those advertised, then the upstreams.
    pub fn hints(&self) -> Vec<RelayAddress> {
        let upstreams = self.upstreams.iter().map(|upstream| RelayAddress {
            key: upstream.key,
            address: upstream.address.clone(),
        });
        let mut hints: Vec<RelayAddress> = Vec::new();
        for hint in self.advertise.iter().cloned().chain(upstreams) {
            if !hints.iter().any(|known| known.key == hint.key) {
                hints.push(hint);
            }
        }
        hints
    }

    pub fn identities(&self) -> Result<Vec<Identity>, String> {
        self.key_files
            .iter()
            .map(|path| {
                let text =
                    std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))?;
                Identity::from_base64(&text).map_err(|error| format!("{path}: {error}"))
            })
            .collect()
    }
}

pub fn parse_upstream(text: &str) -> Result<Upstream, String> {
    let (address, key) = text
        .split_once('=')
        .ok_or_else(|| format!("{text}: expected HOST:PORT=KEY"))?;
    let key = PublicKey::from_base64(key).map_err(|error| format!("{text}: {error}"))?;
    Ok(Upstream {
        address: address.to_owned(),
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_upstream_key_ending_in_padding_parses() -> Result<(), String> {
        let key = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let upstream = parse_upstream(&format!("parent.example:10900={key}"))?;
        assert_eq!(
            (upstream.address.as_str(), upstream.key),
            ("parent.example:10900", key)
        );
        Ok(())
    }

    #[test]
    fn relays_are_accepted_by_key_and_the_ceilings_default() -> Result<(), String> {
        let key = Identity::generate()
            .map_err(|error| error.to_string())?
            .public();
        let args = ["--key", "k", "--accept-relay", &key.to_base64()];
        let config =
            Config::from_args(args.iter().map(|arg| (*arg).to_owned()))?.ok_or("no config")?;
        assert_eq!(config.accept_relays, vec![key]);
        assert_eq!(
            (
                config.max_connections,
                config.max_connections_per_address,
                config.max_feeder_bytes_per_sec,
                config.max_dedup_bytes,
            ),
            (2048, 16, 262_144, 256 * 1024 * 1024)
        );
        Ok(())
    }

    #[test]
    fn the_help_states_the_defaults_and_the_burst_floor_the_code_uses() {
        let floor = format!("{} KiB", crate::ceiling::MIN_BURST / 1024);
        for stated in [
            floor,
            format!("(default {DEFAULT_MAX_CONNECTIONS})"),
            format!("(default {DEFAULT_MAX_CONNECTIONS_PER_ADDRESS})"),
            format!("(default {DEFAULT_MAX_FEEDER_BYTES_PER_SEC})"),
            format!("(default {DEFAULT_MAX_DEDUP_BYTES})"),
        ] {
            assert!(USAGE.contains(&stated), "the help does not say {stated}");
        }
    }
}
