//! `tally-feed`: the feeder's command line (RFC-0171 §3.5).

use tally_feed::config::{self, Command};
use tally_feed::{health, privilege};

fn main() {
    let env = |name: &str| std::env::var(name).ok();
    let result = config::parse_with(std::env::args().skip(1), &env).and_then(|command| {
        // A container's root becomes its unprivileged user before anything is read or written,
        // and before the runtime starts a thread (`privilege`).
        let run_as = env(privilege::RUN_AS);
        match &command {
            Command::Run(config) => privilege::become_user(run_as.as_deref(), &config.state_dir)?,
            Command::Init(path) => {
                if let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    privilege::become_user(run_as.as_deref(), parent)?;
                }
            }
            Command::NewKey | Command::Health(_) | Command::Done => {}
        }
        execute(command)
    });
    if let Err(error) = result {
        eprintln!("tally-feed: {error}");
        std::process::exit(1);
    }
}

fn execute(command: Command) -> Result<(), String> {
    match command {
        Command::Init(path) => tally_feed::init(&path),
        Command::NewKey => tally_feed::new_key().map(|(secret, public)| {
            println!("{secret}\n{public}");
        }),
        Command::Health(state_dir) => {
            let verdict = health::check(&state_dir)?;
            println!("{verdict}");
            Ok(())
        }
        Command::Run(config) => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?
            .block_on(tally_feed::run(*config)),
        Command::Done => Ok(()),
    }
}
