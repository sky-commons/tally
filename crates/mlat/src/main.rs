//! `tally-mlat`: the MLAT engine's command line (RFC-0166 §3.8).

use tally_mlat::config::{self, Command};

#[tokio::main]
async fn main() {
    let result = match config::parse(std::env::args().skip(1)) {
        Ok(Command::Keygen(path)) => tally_mlat::keygen(&path),
        Ok(Command::Run(config)) => tally_mlat::run(*config).await,
        Ok(Command::Done) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("tally-mlat: {error}");
        std::process::exit(1);
    }
}
