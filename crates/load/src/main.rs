//! `tally-load`: one relay, many real feeders, one subscriber, and what it measured.

#[tokio::main]
async fn main() {
    let config = match tally_load::config::parse(std::env::args().skip(1)) {
        Ok(Some(config)) => config,
        Ok(None) => return,
        Err(error) => {
            eprintln!("tally-load: {error}");
            std::process::exit(2);
        }
    };
    match tally_load::run(config).await {
        Ok(table) => {
            println!("{table}");
            // The feeders and the client run until the process ends.
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("tally-load: {error}");
            std::process::exit(1);
        }
    }
}
