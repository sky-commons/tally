//! The relay's command line. Everything a relay is told comes from its operator, here.

use tally_wire::{Identity, PublicKey, Region, RelayAddress};

use crate::egress::Cap;

use crate::hub::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS_PER_ADDRESS, DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
    DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
};
use crate::ingest::Threads;

const USAGE: &str = "\
usage: tally-relay --key FILE [--key FILE]... --max-upload RATE [options]
       tally-relay keygen          print a new key file to stdout and its public key to stderr

  --key FILE             this relay's key; repeat during a rotation, newest first
  --max-upload RATE      required: the most this relay sends a second to billed peers, in
                         kbit/s, Mbit/s, Gbit/s, kB/s, MB/s, GB/s, KiB/s, MiB/s or GiB/s
                         (decimal, as hosts state them, but for the KiB family), e.g.
                         10Mbit/s. It bounds the bill: the relay never sends more than this
                         rate times the seconds in a month, so 10Mbit/s is
                         at most about 3.35 TB in 31 days. Under the cap control goes first,
                         then positions and clock models, then raw to relay links and
                         engines, then the rest they are sent, then plain subscribers, each
                         class fairly among its peers; once a send has waited past 2 s, a
                         waiting peer is shed, plain subscribers first and the heaviest
                         first. A new feeder is turned away while the cap cannot carry what
                         it would have to forward. Loopback peers are neither counted nor
                         capped. 0 (with a unit) sends nothing billed at all
  --listen ADDR          where feeders, subscribers and relays connect (default 0.0.0.0:10900)
  --beast-out ADDR       serve plain BEAST of every reception here, for a local decoder
                         (bind it to loopback: it is unauthenticated)
  --stats-listen ADDR    serve each receiver's traffic as JSON here (GET /stations,
                         GET /stations/KEY), and the cap and what it carries (GET /egress),
                         for tally-api (bind it to loopback: it is unauthenticated)
  --upstream HOST:PORT=KEY
                         a relay to link with for the directory (offers and queries, never
                         data: that travels the sharing groups); repeatable
  --advertise HOST:PORT=KEY
                         a relay to offer feeders and turned-away subscribers as a hint, beside
                         the upstreams; repeatable. List this relay itself, under its own key and
                         the address others reach it at: its offers (ProviderOffer) carry that
                         address, and without it the relay signs no offer, so no relay can verify
                         it, choose it to solve an area's MLAT, or send it an area's raw
  --accept-relay KEY     a relay allowed to dial in for the directory before this one has
                         verified its offer; repeatable. A relay whose offer this one verified
                         may dial in as a sharing member; any other key claiming to be a relay is
                         refused
  --client KEY           a client this relay vouches for: each of its sessions here is signed a
                         firehose credential and this relay's evidence, which it presents to
                         every relay it reads (RFC-0174 §2.1); repeatable
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
                         this, less framing, as their rate limit. Every connection that
                         dialled in is held to it (a feeder, a subscriber, an engine, a probe)
                         but a relay, held to the next
  --max-member-bytes-per-sec N
                         the same for a relay (a sharing member, or a directory link, which
                         becomes one once its offer is verified): the most one may send a
                         second, with a burst of the larger of
                         N and 192 KiB; about twice a whole-world MLAT relay's clock models
                         and final and provisional positions (default 8388608)
  --memory BYTES         the most memory this relay may use, in bytes or with K, M, G or T
                         (binary: 16G is 16 GiB). Every feeder's share of every store (batches,
                         MLAT raw, deduplication, subscriber queues, delivery tags, connection
                         buffers) is reserved when it is admitted, and a feeder beyond what this
                         holds is turned away at its Hello: no spare slot (default: the relay's
                         cgroup limit, else the host's memory)
  --ingest-threads N     threads that verify, admit and decode feeders' batches (default: a
                         quarter of the cores)
  --message-threads N    threads that deduplicate receptions (default: an eighth of the cores)
  --area CELL            an area this relay takes (an H3 cell, hex or decimal): it shares it
                         and, with relay duties on, may solve its MLAT (RFC-0174 §2.1);
                         repeatable
  --network ASN          the autonomous system this relay is on, declared in its signed
                         replies and offers so feeders pick two relays on different networks
                         (default 0, not said)
  --mlat-threads N       threads for the MLAT this relay runs for the areas it is chosen to
                         solve (default: every core; 0 runs none)
  --world                gather the live world product: one fix per aircraft per second from
                         every area's positions this relay receives, each second sealed 4 s
                         after it ends, MLAT aircraft by their provisional fixes (RFC-0174 §2.11).
                         The world is every area: the --area cells must cover the globe (the 122
                         resolution 0 cells do), or the relay refuses to start rather than sign a
                         part of the world as the whole
  --world-precise        gather the precise world product: the same rule over final MLAT fixes,
                         each second sealed 90 s after it ends, once its finals can have come;
                         the same --area rule as --world
  --no-relay-duties      take no feeders, run no MLAT and seed nothing: only share the areas
                         taken (RFC-0174 §2.1: the duties are on by default, sharing is required)
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
    pub stats_listen: Option<String>,
    pub upstreams: Vec<Upstream>,
    pub advertise: Vec<RelayAddress>,
    pub accept_relays: Vec<PublicKey>,
    /// The clients this relay vouches for (`--client`).
    pub clients: Vec<PublicKey>,
    pub max_subscribers: usize,
    pub max_connections: usize,
    pub max_connections_per_address: usize,
    pub max_feeder_bytes_per_sec: u64,
    pub max_member_bytes_per_sec: u64,
    /// Bytes the relay may use: the admission budget (`budget`).
    pub memory: usize,
    pub threads: Threads,
    pub max_upload: Cap,
    /// The areas taken (RFC-0174 §2.1).
    pub areas: Vec<Region>,
    /// The autonomous system declared (0: not said).
    pub network: u32,
    /// Threads for the hosted MLAT; 0 runs none. Every core unless told.
    pub mlat_threads: usize,
    /// Gathers the live world product, and the precise one.
    pub world: bool,
    pub world_precise: bool,
    /// Accepting feeders, running MLAT and seeding: on unless turned off.
    pub relay_duties: bool,
}

/// Why `--max-upload` is required, and a safe value to start from.
const CAP_REQUIRED: &str = "\
--max-upload is required: a relay sends every subscriber what it asks for, and what a relay sends
is what its host bills. Name the most this relay may send a second, which bounds the bill: it can
never send more than that rate times the seconds in a month. For example --max-upload 6Mbit/s is
at most about 2.01 TB in 31 days, which leaves about 1 TB of a $12 Lightsail plan's 3 TB for what
feeders send in, which counts toward it too (AWS bills $0.09 a GB of the excess out). tally/README.md,
\"What a relay costs\", prices common hosts.";

impl Config {
    /// `None` when the command was fully handled (usage, keygen).
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut config = Self {
            key_files: Vec::new(),
            listen: "0.0.0.0:10900".to_owned(),
            beast_out: None,
            stats_listen: None,
            upstreams: Vec::new(),
            advertise: Vec::new(),
            accept_relays: Vec::new(),
            clients: Vec::new(),
            max_subscribers: 64,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
            max_feeder_bytes_per_sec: DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            max_member_bytes_per_sec: DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
            memory: crate::budget::memory_available(),
            threads: Threads::from_cores(),
            max_upload: Cap::NONE,
            areas: Vec::new(),
            network: 0,
            mlat_threads: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
            world: false,
            world_precise: false,
            relay_duties: true,
        };
        let mut max_upload = None;
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
                "--max-upload" => max_upload = Some(Cap::parse(&value()?)?),
                "--listen" => config.listen = value()?,
                "--beast-out" => config.beast_out = Some(value()?),
                "--stats-listen" => config.stats_listen = Some(value()?),
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
                "--client" => {
                    let text = value()?;
                    let key = PublicKey::from_base64(&text)
                        .map_err(|error| format!("--client {text}: {error}"))?;
                    config.clients.push(key);
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
                "--memory" => config.memory = parse_bytes(&value()?)?,
                "--ingest-threads" => {
                    config.threads.ingest = value()?
                        .parse()
                        .map_err(|_| "--ingest-threads needs a number".to_owned())?;
                }
                "--message-threads" => {
                    config.threads.message = value()?
                        .parse()
                        .map_err(|_| "--message-threads needs a number".to_owned())?;
                }
                "--max-feeder-bytes-per-sec" => {
                    config.max_feeder_bytes_per_sec = value()?
                        .parse()
                        .map_err(|_| "--max-feeder-bytes-per-sec needs a number".to_owned())?;
                }
                "--max-member-bytes-per-sec" => {
                    config.max_member_bytes_per_sec = value()?
                        .parse()
                        .map_err(|_| "--max-member-bytes-per-sec needs a number".to_owned())?;
                }
                "--max-subscribers" => {
                    config.max_subscribers = value()?
                        .parse()
                        .map_err(|_| "--max-subscribers needs a number".to_owned())?;
                }
                "--area" => config.areas.push(parse_area(&value()?)?),
                "--network" => {
                    config.network = value()?
                        .parse()
                        .map_err(|_| "--network needs an AS number".to_owned())?;
                }
                "--mlat-threads" => {
                    config.mlat_threads = value()?
                        .parse()
                        .map_err(|_| "--mlat-threads needs a number".to_owned())?;
                }
                "--no-relay-duties" => config.relay_duties = false,
                "--world" => config.world = true,
                "--world-precise" => config.world_precise = true,
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
        config.max_upload = max_upload.ok_or(CAP_REQUIRED)?;
        if (config.world || config.world_precise) && !covers_the_world(&config.areas) {
            return Err(WORLD_NEEDS_EVERY_AREA.to_owned());
        }
        // A relay list carries a one-byte count.
        if config.hints().len() > usize::from(u8::MAX) {
            return Err("at most 255 advertised relays and upstreams together".to_owned());
        }
        Ok(Some(config))
    }

    /// The relays offered as hints (RFC-0171 §3.7): those advertised, then the upstreams.
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

/// Why `--world` and `--world-precise` need every area taken.
const WORLD_NEEDS_EVERY_AREA: &str = "\
--world and --world-precise sign one fix per aircraft for the whole world (RFC-0174 §2.11), and a
relay gathers every area's positions by taking every area: its sharing groups bring it each one.
The --area cells named do not cover the globe, so the product would be a part of the world signed
as the whole. Take every area (the 122 resolution 0 cells cover it), or leave the world products
to a relay that does.";

/// An H3 cell as its 64-bit number: decimal, `0x` hex, or bare hex as H3's own tools print it.
/// Bytes, as a number or with a binary K, M, G or T after it.
pub fn parse_bytes(text: &str) -> Result<usize, String> {
    let text = text.trim();
    let (number, shift) = match text.chars().last() {
        Some('K' | 'k') => (&text[..text.len() - 1], 10),
        Some('M' | 'm') => (&text[..text.len() - 1], 20),
        Some('G' | 'g') => (&text[..text.len() - 1], 30),
        Some('T' | 't') => (&text[..text.len() - 1], 40),
        _ => (text, 0),
    };
    number
        .parse::<usize>()
        .ok()
        .and_then(|number| number.checked_mul(1 << shift))
        .ok_or_else(|| format!("--memory {text}: expected bytes, or a number with K, M, G or T"))
}

pub fn parse_area(text: &str) -> Result<Region, String> {
    let hex = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
    let candidates = match hex {
        Some(hex) => vec![u64::from_str_radix(hex, 16).ok()],
        None => vec![text.parse().ok(), u64::from_str_radix(text, 16).ok()],
    };
    candidates
        .into_iter()
        .flatten()
        .find_map(|number| Region::from_u64(number).ok())
        .ok_or_else(|| format!("--area: {text} is not an H3 cell"))
}

/// The 122 resolution 0 cells: H3's base cells, each the index with mode 1, resolution 0, its
/// base cell number, and every digit unused (7).
fn base_cells() -> Vec<Region> {
    (0..122u64)
        .filter_map(|base| Region::from_u64(0x0800_1fff_ffff_ffff | (base << 45)).ok())
        .collect()
}

/// Whether `areas` cover the globe: every area (`rendezvous::AREA_RESOLUTION`) lies in one of
/// them.
pub fn covers_the_world(areas: &[Region]) -> bool {
    let taken: std::collections::HashSet<u64> = areas
        .iter()
        .filter_map(|region| tally_wire::rendezvous::areas_of(*region).ok())
        .flatten()
        .map(Region::as_u64)
        .collect();
    let bases = base_cells();
    bases.len() == 122
        && bases.into_iter().all(|base| {
            tally_wire::rendezvous::areas_of(base)
                .is_ok_and(|every| every.iter().all(|area| taken.contains(&area.as_u64())))
        })
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
    use crate::egress;

    fn config(args: &[&str]) -> Result<Config, String> {
        Config::from_args(args.iter().map(|arg| (*arg).to_owned()))?.ok_or("no config".to_owned())
    }

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
        let config = config(&[
            "--key",
            "k",
            "--max-upload",
            "10Mbit/s",
            "--accept-relay",
            &key.to_base64(),
        ])?;
        assert_eq!(config.accept_relays, vec![key]);
        assert!(config.clients.is_empty());
        assert_eq!(config.stats_listen, None);
        assert_eq!(
            (
                config.max_connections,
                config.max_connections_per_address,
                config.max_feeder_bytes_per_sec,
                config.max_member_bytes_per_sec,
            ),
            (2048, 16, 262_144, 8_388_608)
        );
        assert_eq!(config.memory, crate::budget::memory_available());
        Ok(())
    }

    #[test]
    fn the_help_states_the_defaults_and_the_rules_the_code_uses() {
        let floor = format!("{} KiB", crate::ceiling::MIN_BURST / 1024);
        let ten = egress::decimal(Cap::bytes_per_sec(1_250_000).most_a_month());
        for stated in [
            floor,
            format!("(default {DEFAULT_MAX_CONNECTIONS})"),
            format!("(default {DEFAULT_MAX_CONNECTIONS_PER_ADDRESS})"),
            format!("(default {DEFAULT_MAX_FEEDER_BYTES_PER_SEC})"),
            format!("(default {DEFAULT_MAX_MEMBER_BYTES_PER_SEC})"),
            format!("past {} s", egress::SHED_AFTER.as_secs()),
            format!("10Mbit/s is\n                         at most about {ten}"),
        ] {
            assert!(USAGE.contains(&stated), "the help does not say {stated}");
        }
    }

    #[test]
    fn an_area_is_read_in_any_of_the_ways_h3_numbers_are_written() -> Result<(), String> {
        let region = Region::containing(
            &tally_wire::Location {
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
            assert_eq!(parse_area(&text)?, region, "{text}");
        }
        assert!(parse_area("12").is_err());
        Ok(())
    }

    /// A world product is the whole world: a relay told to gather one with only some areas taken
    /// refuses to start, and one taking every base cell (or every area under them) starts.
    #[test]
    fn a_world_product_needs_every_area_taken() -> Result<(), String> {
        let bases: Vec<String> = base_cells()
            .iter()
            .map(|cell| format!("{:x}", cell.as_u64()))
            .collect();
        assert_eq!(bases.len(), 122);
        let mut every = vec!["--key", "k", "--max-upload", "10Mbit/s"];
        for base in &bases {
            every.extend(["--area", base]);
        }
        for flag in ["--world", "--world-precise"] {
            let mut args = every.clone();
            args.push(flag);
            assert!(config(&args).is_ok(), "{flag} with every area");
            // One base cell short.
            let mut short = vec!["--key", "k", "--max-upload", "10Mbit/s", flag];
            for base in &bases[1..] {
                short.extend(["--area", base]);
            }
            let refused = config(&short).err().unwrap_or_default();
            assert!(refused.contains("do not cover the globe"), "{refused}");
            // One area.
            let one = config(&[
                "--key",
                "k",
                "--max-upload",
                "10Mbit/s",
                "--area",
                &bases[0],
                flag,
            ]);
            assert!(one.is_err());
        }
        // A relay that gathers no world product takes what areas it likes.
        assert!(
            config(&[
                "--key",
                "k",
                "--max-upload",
                "10Mbit/s",
                "--area",
                &bases[0]
            ])
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn the_advertise_help_says_a_relay_lists_itself_to_offer_mlat() {
        let advertise = USAGE
            .split("--advertise")
            .nth(1)
            .and_then(|rest| rest.split("\n  --").next())
            .unwrap_or_default();
        assert!(advertise.contains("List this relay itself"), "{advertise}");
        assert!(advertise.contains("MLAT"), "{advertise}");
    }

    #[test]
    fn a_client_is_vouched_for_by_key_and_repeatably() -> Result<(), String> {
        let a = Identity::from_seed([1; 32]).public();
        let b = Identity::from_seed([2; 32]).public();
        let config = config(&[
            "--key",
            "k",
            "--max-upload",
            "10Mbit/s",
            "--client",
            &a.to_base64(),
            "--client",
            &b.to_base64(),
        ])?;
        assert_eq!(config.clients, vec![a, b]);
        assert!(
            super::tests::config(&["--key", "k", "--max-upload", "1MB/s", "--client", "x"])
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn memory_is_read_in_bytes_or_binary_units_and_threads_by_flag() -> Result<(), String> {
        assert_eq!(parse_bytes("4096")?, 4096);
        assert_eq!(parse_bytes("16G")?, 16 << 30);
        assert_eq!(parse_bytes("512M")?, 512 << 20);
        assert!(parse_bytes("lots").is_err());
        let config = config(&[
            "--key",
            "relay.key",
            "--max-upload",
            "10Mbit/s",
            "--memory",
            "8G",
            "--ingest-threads",
            "3",
            "--message-threads",
            "2",
        ])?;
        assert_eq!(config.memory, 8 << 30);
        assert_eq!(
            config.threads,
            Threads {
                ingest: 3,
                message: 2
            }
        );
        Ok(())
    }

    #[test]
    fn the_stats_listener_is_named_by_flag() -> Result<(), String> {
        let config = config(&[
            "--key",
            "k",
            "--max-upload",
            "10Mbit/s",
            "--stats-listen",
            "127.0.0.1:10901",
        ])?;
        assert_eq!(config.stats_listen.as_deref(), Some("127.0.0.1:10901"));
        Ok(())
    }

    #[test]
    fn a_relay_without_an_upload_cap_refuses_to_start_and_says_why() -> Result<(), String> {
        let refused = config(&["--key", "k"]).err().unwrap_or_default();
        assert!(refused.contains("--max-upload is required"), "{refused}");
        assert!(refused.contains("What a relay costs"), "{refused}");
        // The safe example it names is what it says, and inside the plan it names.
        let safe = Cap::parse("6Mbit/s")?;
        let bound = egress::decimal(safe.most_a_month());
        assert!(
            refused.contains(&format!("--max-upload 6Mbit/s is\nat most about {bound}")),
            "{refused}"
        );
        // Inside the plan with the terabyte it says it leaves for what comes in.
        assert!(safe.most_a_month() + 990_000_000_000 <= 3_000_000_000_000);
        Ok(())
    }

    #[test]
    fn the_cap_is_read_once_and_a_wrong_one_refuses_the_start() -> Result<(), String> {
        let config = config(&["--key", "k", "--max-upload", "2MB/s"])?;
        assert_eq!(config.max_upload, Cap::bytes_per_sec(2_000_000));
        let none = super::tests::config(&["--key", "k", "--max-upload", "0Mbit/s"])?;
        assert!(none.max_upload.is_none());
        for wrong in ["10Mbps", "3TB/month", "fast"] {
            assert!(
                super::tests::config(&["--key", "k", "--max-upload", wrong]).is_err(),
                "{wrong} was accepted"
            );
        }
        // Every monthly flag is gone.
        for gone in ["--egress-budget", "--budget-period-start", "--state"] {
            assert!(
                super::tests::config(&["--key", "k", "--max-upload", "1MB/s", gone, "x"]).is_err(),
                "{gone} was accepted"
            );
        }
        Ok(())
    }
}
