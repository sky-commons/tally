//! `tally-load`: one relay, many real feeders, one subscriber, and what it measured.

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        // The feeders run on these threads, below the instruments (`tally_load::lower_priority`).
        .on_thread_start(tally_load::lower_priority)
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("tally-load: runtime: {error}");
            std::process::exit(1);
        }
    };
    let config = match tally_load::config::parse(std::env::args().skip(1)) {
        Ok(Some(config)) => config,
        Ok(None) => return,
        Err(error) => {
            eprintln!("tally-load: {error}");
            std::process::exit(2);
        }
    };
    match runtime.block_on(tally_load::run(config)) {
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
