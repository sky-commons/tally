//! The relay's command line. Everything a relay is told comes from its operator, here.

use tally_wire::{Identity, PublicKey, Region, RelayAddress};

use crate::egress::Cap;

use crate::hub::{
    DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS_PER_ADDRESS, DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
    DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
};

/// Subscribers served before new ones are turned away, unless `--max-subscribers` says.
const DEFAULT_MAX_SUBSCRIBERS: usize = 64;

const USAGE: &str = "\
usage: tally-relay --key FILE [--key FILE]... --max-upload RATE [options]
       tally-relay keygen          print a new key file to stdout and its public key to stderr
       tally-relay check [--memory-limit BYTES] [--cores N] --key FILE ... [options]
                                   refuse what a start would refuse, without starting: the same
                                   arguments, read and checked as a start reads and checks them
                                   (but for the key files, which it does not read, and the
                                   sockets, which it does not open), then print the plan
                                   (memory, base, oversize, connections, connection-buffers,
                                   per-feeder, feeders, memory-feeders, cores, core-feeders,
                                   ingest-threads, message-threads, seal-threads,
                                   mlat-threads, members,
                                   per-member, member-feeders, member-rate-pool, member-pool,
                                   member-links, planned, headroom, limit) and exit 0.
                                   --memory-limit is the memory the relay will run in (the
                                   lesser of its cgroup's limits: a unit's MemoryHigh and
                                   MemoryMax, a container's limits.memory), as it would find it
                                   there (default: this host's, as a start here would find it);
                                   --cores the cores it will run on (its CPU affinity and its
                                   cgroup's quota: a unit's CPUQuota, a container's limits.cpu,
                                   rounded down, at least 1; default: this host's)

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
  --max-connections N    connections held at once that have no place of their role's own (not
                         yet identified, probes, engines, directory links, dials that only
                         send); beyond it a new one is closed before its handshake
                         (default 2048). A feeder, a subscriber and a member session give
                         their place up for their own role's. Every connection's Noise buffers (256 KiB)
                         are planned in the memory budget: a feeder's in its reservation, and
                         these, the member sessions' and the subscribers' before any feeder
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
                         the same for the relays that send this one data (its sharing members,
                         a directory link once its offer is verified, its own one-hop raw
                         links): the most they may send a second all together, each waiting
                         its turn past it, and the most one alone may, with a burst of the
                         larger of N and 192 KiB (default 1048576). Planned once, apart from
                         the feeders', as the feeders it is worth (N over 8 KiB/s) in every
                         store, so a whole-world relay sharing its clock models and final and
                         provisional positions (about 4.2 MB/s) raises it, with the memory to
                         match. The member sessions are not chosen: they are as many as the
                         areas taken let other relays open (each area's cell, its ancestors and
                         the cells under it, 32 relays a cell, and with MLAT their raw links),
                         at most --max-connections, each carving its own ingest allowance; the
                         relay refuses to start when its memory cannot hold them and one feeder
  --memory BYTES         the most memory this relay may use, in bytes or with K, M, G or T
                         (binary: 16G is 16 GiB). Every feeder's share of every store (batches,
                         MLAT raw, deduplication, subscriber queues, delivery tags, connection
                         buffers) is reserved when it is admitted, and a feeder beyond what this
                         holds is turned away at its Hello: no spare slot (default: the memory
                         the relay runs in, the lesser of its cgroup's memory.high and
                         memory.max, else the host's memory, less 64 MiB of headroom for what
                         no store charges). Never above that: the kernel would throttle or kill
                         the relay before its budget turned a feeder away. The feeders admitted
                         are also no more than the cores it runs on (its CPU affinity and its
                         cgroup's quota) carry beside its members' rate, each stage at most
                         50% busy and, where it hosts MLAT, MLAT's steps in the cores left, and
                         each stage's threads, and MLAT's, follow what it admits
  --area CELL            an area this relay takes (an H3 cell, hex or decimal): it shares it
                         and, with relay duties on, may solve its MLAT (RFC-0174 §2.1);
                         repeatable
  --network ASN          the autonomous system this relay is on, declared in its signed
                         replies and offers so feeders pick two relays on different networks
                         (default 0, not said)
  --no-mlat              run no MLAT for the areas this relay is chosen to solve. By default
                         it does, on the cores its stages leave and below their priority,
                         shedding what it falls behind on rather than delaying raw; hosting it
                         costs each feeder memory and cores, so the same relay admits fewer
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
    /// The memory the relay runs in: the lesser of its cgroup's limits, else the host's
    /// (`budget::memory_available`), or what `check` is told it will be (`--memory-limit`).
    /// `memory` is never above it less `budget::HEADROOM_BYTES`.
    pub memory_limit: usize,
    /// The cores the relay runs on (`cores::cores_available`), or what `check` is told it will
    /// have (`--cores`): the feeders they carry bound the ceiling, and the stages' threads follow
    /// what is admitted (`cores`).
    pub cores: usize,
    pub max_upload: Cap,
    /// The areas taken (RFC-0174 §2.1).
    pub areas: Vec<Region>,
    /// The autonomous system declared (0: not said).
    pub network: u32,
    /// Hosts MLAT for the areas it is chosen to solve: on unless `--no-mlat`. Its threads are the
    /// plan's (`Budget::mlat_threads`), never an operator's.
    pub mlat: bool,
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

/// What the command line asks for.
#[derive(Debug)]
pub enum Command {
    /// Start a relay.
    Run(Config),
    /// Refuse what a start would refuse and print the plan, without starting (`check`).
    Check(Config),
    /// Nothing more: the command was fully handled (usage, keygen).
    Done,
}

impl Command {
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut args = args.peekable();
        if args.peek().map(String::as_str) != Some("check") {
            return Ok(Config::from_args(args)?.map_or(Self::Done, Self::Run));
        }
        args.next();
        let mut memory_limit = None;
        let mut cores = None;
        loop {
            match args.peek().map(String::as_str) {
                Some("--memory-limit") => {
                    args.next();
                    let text = args.next().ok_or("--memory-limit needs a value")?;
                    memory_limit = Some(
                        parse_bytes(&text).map_err(|error| format!("--memory-limit {error}"))?,
                    );
                }
                Some("--cores") => {
                    args.next();
                    let count = args
                        .next()
                        .and_then(|text| text.parse::<usize>().ok())
                        .filter(|count| *count > 0)
                        .ok_or("--cores needs a number of cores, at least 1")?;
                    cores = Some(count);
                }
                _ => break,
            }
        }
        let host = Host {
            memory_limit: memory_limit.unwrap_or_else(crate::budget::memory_available),
            cores: cores.unwrap_or_else(crate::cores::cores_available),
        };
        Ok(Config::parse(args, host)?.map_or(Self::Done, Self::Check))
    }
}

/// What the relay runs in: the memory (`budget::memory_available`) and the cores
/// (`cores::cores_available`) this host gives it, or what `check` is told it will have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Host {
    pub memory_limit: usize,
    pub cores: usize,
}

impl Host {
    /// This host as a start here finds it.
    pub fn this() -> Self {
        Self {
            memory_limit: crate::budget::memory_available(),
            cores: crate::cores::cores_available(),
        }
    }
}

impl Config {
    /// `None` when the command was fully handled (usage, keygen). The relay's memory limit and
    /// cores are what this host gives it ([`Host::this`]).
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut args = args.peekable();
        if args.peek().map(String::as_str) == Some("keygen") {
            let identity = Identity::generate().map_err(|error| error.to_string())?;
            println!("{}", identity.to_base64());
            eprintln!("public key: {}", identity.public());
            return Ok(None);
        }
        Self::parse(args, Host::this())
    }

    /// The relay's flags, for a relay that runs on `host`: every refusal a start makes of its
    /// arguments. `None` when the command was fully handled (usage).
    pub fn parse(args: impl Iterator<Item = String>, host: Host) -> Result<Option<Self>, String> {
        let Host {
            memory_limit,
            cores,
        } = host;
        let mut config = Self {
            key_files: Vec::new(),
            listen: "0.0.0.0:10900".to_owned(),
            beast_out: None,
            stats_listen: None,
            upstreams: Vec::new(),
            advertise: Vec::new(),
            accept_relays: Vec::new(),
            clients: Vec::new(),
            max_subscribers: DEFAULT_MAX_SUBSCRIBERS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
            max_feeder_bytes_per_sec: DEFAULT_MAX_FEEDER_BYTES_PER_SEC,
            max_member_bytes_per_sec: DEFAULT_MAX_MEMBER_BYTES_PER_SEC,
            memory: crate::budget::budget_within(memory_limit),
            memory_limit,
            cores,
            max_upload: Cap::NONE,
            areas: Vec::new(),
            network: 0,
            mlat: true,
            world: false,
            world_precise: false,
            relay_duties: true,
        };
        let mut max_upload = None;
        let mut args = args;
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
                "--memory" => {
                    config.memory =
                        parse_bytes(&value()?).map_err(|error| format!("--memory {error}"))?;
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
                "--no-mlat" => config.mlat = false,
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
        let most = crate::budget::budget_within(config.memory_limit);
        if config.memory > most {
            return Err(format!(
                "--memory {} is above the {most} bytes this relay may plan: the {} bytes it runs \
                 in (the lesser of its cgroup's limits, else the host's memory) less {} of \
                 headroom for what no store charges. Past it the kernel would throttle or kill \
                 the relay before its budget turned a feeder away; give it at most that, or \
                 raise the limit (the unit's MemoryHigh and MemoryMax, the container's \
                 limits.memory)",
                config.memory,
                config.memory_limit,
                crate::budget::HEADROOM_BYTES,
            ));
        }
        if (config.world || config.world_precise) && !covers_the_world(&config.areas) {
            return Err(WORLD_NEEDS_EVERY_AREA.to_owned());
        }
        // Every region taken is offered, or the relay does not start.
        crate::directory::offerable(&config.areas).map_err(|error| format!("--area: {error}"))?;
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
        .ok_or_else(|| format!("{text}: expected bytes, or a number with K, M, G or T"))
}

/// An H3 cell as its 64-bit number: decimal, `0x` hex, or bare hex as H3's own tools print it.
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

/// Whether `areas` cover the globe: every area (`rendezvous::AREA_RESOLUTION`) lies in one of
/// them (a region finer than an area counts its area taken, as `rendezvous::areas_of` does).
/// Region by region: the areas they name, at their fewest, are the base cells.
pub fn covers_the_world(areas: &[Region]) -> bool {
    let named: tally_wire::Regions = areas
        .iter()
        .filter_map(|region| {
            region.ancestor(
                region
                    .resolution()
                    .min(tally_wire::rendezvous::AREA_RESOLUTION),
            )
        })
        .collect();
    named == tally_wire::Regions::world()
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

    /// A host of a terabyte, whatever runs the test.
    const LIMIT: usize = 1 << 40;

    /// That host, on 16 cores.
    const HOST: Host = Host {
        memory_limit: LIMIT,
        cores: 16,
    };

    fn config(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|arg| (*arg).to_owned()), HOST)?.ok_or("no config".to_owned())
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
            (2048, 16, 262_144, 1_048_576)
        );
        assert_eq!(config.memory, LIMIT - crate::budget::HEADROOM_BYTES);
        Ok(())
    }

    #[test]
    fn the_help_states_the_defaults_and_the_rules_the_code_uses() {
        let floor = format!("{} KiB", crate::ceiling::MIN_BURST / 1024);
        let ten = egress::decimal(Cap::bytes_per_sec(1_250_000).most_a_month());
        for stated in [
            floor,
            format!("(default {DEFAULT_MAX_SUBSCRIBERS})"),
            format!("(default {DEFAULT_MAX_CONNECTIONS})"),
            format!(
                "Noise buffers ({} KiB)",
                crate::ingest::BUFFERS_PER_CONNECTION.div_ceil(1024)
            ),
            format!("{} relays a cell", crate::directory::OFFERS_PER_CELL),
            format!("(default {DEFAULT_MAX_CONNECTIONS_PER_ADDRESS})"),
            format!("(default {DEFAULT_MAX_FEEDER_BYTES_PER_SEC})"),
            format!("(default {DEFAULT_MAX_MEMBER_BYTES_PER_SEC})"),
            format!(
                "less {} MiB of headroom",
                crate::budget::HEADROOM_BYTES >> 20
            ),
            format!(
                "(N over {} KiB/s)",
                crate::budget::PLANNED_BYTES_PER_SEC / 1024
            ),
            format!("past {} s", egress::SHED_AFTER.as_secs()),
            format!(
                "at most\n                         {}% busy",
                crate::cores::BUSY_PERCENT
            ),
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

    /// The 122 resolution 0 cells: H3's base cells.
    fn base_cells() -> Vec<Region> {
        tally_wire::Regions::world().cells().to_vec()
    }

    /// Every region taken is offered: a relay whose regions, at their fewest, are more cells than
    /// its peers hold offers of one key refuses to start, and says how many; the same places
    /// named by fewer cells start.
    #[test]
    fn a_relay_refuses_areas_it_could_not_offer_whole() -> Result<(), String> {
        let base = *base_cells().first().ok_or("no base cell")?;
        // Every other area under one base cell: no two siblings merge, so they stay that many.
        let scattered: Vec<String> = tally_wire::rendezvous::areas_of(base)
            .map_err(|error| error.to_string())?
            .into_iter()
            .step_by(2)
            .map(|cell| format!("{:x}", cell.as_u64()))
            .collect();
        assert!(scattered.len() < crate::directory::OFFERS_PER_KEY);
        let mut args = vec!["--key", "k", "--max-upload", "10Mbit/s"];
        let some: Vec<&str> = scattered.iter().map(String::as_str).collect();
        for area in &some {
            args.extend(["--area", area]);
        }
        assert!(config(&args).is_ok());
        // The other half of a second base cell's areas too: past the bound, refused.
        let second = *base_cells().get(1).ok_or("no second base cell")?;
        let more: Vec<String> = tally_wire::rendezvous::areas_of(second)
            .map_err(|error| error.to_string())?
            .into_iter()
            .step_by(2)
            .map(|cell| format!("{:x}", cell.as_u64()))
            .collect();
        for area in &more {
            args.extend(["--area", area.as_str()]);
        }
        let refused = config(&args)
            .err()
            .ok_or("started with areas it cannot offer")?;
        assert!(refused.contains("cells at their fewest"), "{refused}");
        // The same two base cells named whole: two cells, started.
        let whole = [
            format!("{:x}", base.as_u64()),
            format!("{:x}", second.as_u64()),
        ];
        let mut args = vec!["--key", "k", "--max-upload", "10Mbit/s"];
        for cell in &whole {
            args.extend(["--area", cell.as_str()]);
        }
        assert!(config(&args).is_ok());
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
    fn memory_is_read_in_bytes_or_binary_units_and_no_thread_count_by_flag() -> Result<(), String> {
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
        ])?;
        assert_eq!(config.memory, 8 << 30);
        assert_eq!(config.cores, 16);
        // Never above the memory the relay runs in: the kernel would kill it first.
        let over = Config::parse(
            ["--key", "k", "--max-upload", "1MB/s", "--memory", "2G"]
                .map(str::to_owned)
                .into_iter(),
            Host {
                memory_limit: 1 << 30,
                cores: 1,
            },
        )
        .err()
        .unwrap_or_default();
        assert!(
            over.contains("is above the 1006632960 bytes this relay may plan"),
            "{over}"
        );
        // The headroom is kept whatever --memory says: all of the limit is refused too.
        let all = Config::parse(
            ["--key", "k", "--max-upload", "1MB/s", "--memory", "1G"]
                .map(str::to_owned)
                .into_iter(),
            Host {
                memory_limit: 1 << 30,
                cores: 1,
            },
        );
        assert!(all.is_err());
        // The member sessions follow the areas; no operator picks them.
        assert!(
            super::tests::config(&["--key", "k", "--max-upload", "1MB/s", "--max-members", "3"])
                .is_err()
        );
        // The stages' threads follow the load admitted (`cores`): no operator picks them.
        for flag in ["--ingest-threads", "--message-threads"] {
            assert!(
                super::tests::config(&["--key", "k", "--max-upload", "1MB/s", flag, "4"]).is_err(),
                "{flag}"
            );
        }
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
