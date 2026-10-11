//! `tally-feed`: the feeder's command line (RFC-0171 §3.5).

use tally_feed::config::{self, Command};

#[tokio::main]
async fn main() {
    let result = match config::parse(std::env::args().skip(1)) {
        Ok(Command::Init(path)) => tally_feed::init(&path),
        Ok(Command::NewKey) => tally_feed::new_key().map(|(secret, public)| {
            println!("{secret}\n{public}");
        }),
        Ok(Command::Run(config)) => tally_feed::run(*config).await,
        Ok(Command::Done) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("tally-feed: {error}");
        std::process::exit(1);
    }
}
