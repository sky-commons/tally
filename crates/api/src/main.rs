//! `tally-api`: the Tally API's command line (RFC-0173 §2.5).

use tally_api::config::{Command, Keys, Prepared};
use tokio::net::TcpListener;

fn main() {
    if let Err(error) = run() {
        eprintln!("tally-api: {error}");
        std::process::exit(1);
    }
}

/// A start and a check run the same `Config::prepare`, before any runtime exists. A check then
/// prints the settings, one `name value` a line, and builds none, so it cannot open a socket.
fn run() -> Result<(), String> {
    match Command::from_args(std::env::args().skip(1))? {
        Command::Done => Ok(()),
        Command::Check(config) => {
            print!("{}", config.prepare(Keys::WhereReadable)?.summary());
            Ok(())
        }
        Command::Run(config) => {
            let prepared = config.prepare(Keys::Read)?;
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("runtime: {error}"))?
                .block_on(serve(prepared))
        }
    }
}

async fn serve(prepared: Prepared) -> Result<(), String> {
    let listener = TcpListener::bind(prepared.listen)
        .await
        .map_err(|error| format!("listen {}: {error}", prepared.listen))?;
    eprintln!("tally-api: listening on {}", prepared.listen);
    tally_api::serve(listener, prepared.settings, prepared.identity).await
}
