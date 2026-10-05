//! The relay's command line. Everything a relay is told comes from its operator, here.

use tally_wire::{Identity, PublicKey};

const USAGE: &str = "\
usage: tally-relay --key FILE [--key FILE]... [options]
       tally-relay keygen          print a new key file to stdout and its public key to stderr

  --key FILE             this relay's key; repeat during a rotation, newest first
  --listen ADDR          where feeders, subscribers and relays connect (default 0.0.0.0:10900)
  --beast-out ADDR       serve plain BEAST of every reception here, for a local decoder
                         (bind it to loopback: it is unauthenticated)
  --upstream HOST:PORT=KEY
                         a parent relay to exchange batches with; repeatable
  --max-subscribers N    subscribers served before new ones are turned away (default 64)
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
    pub max_subscribers: usize,
}

impl Config {
    /// `None` when the command was fully handled (usage, keygen).
    pub fn from_args(args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut config = Self {
            key_files: Vec::new(),
            listen: "0.0.0.0:10900".to_owned(),
            beast_out: None,
            upstreams: Vec::new(),
            max_subscribers: 64,
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
        Ok(Some(config))
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
        .rsplit_once('=')
        .ok_or_else(|| format!("{text}: expected HOST:PORT=KEY"))?;
    let key = PublicKey::from_base64(key).map_err(|error| format!("{text}: {error}"))?;
    Ok(Upstream {
        address: address.to_owned(),
        key,
    })
}
