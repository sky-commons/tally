//! `tally-acars-collect`: the map image's ACARS collector (packaging/map/entrypoint.sh).

use std::path::Path;

use tally_acars_collect::{Collector, DEFAULT_DAY_MAX, check_address, run, sort_day};

const USAGE: &str = "usage:
  tally-acars-collect collect --from HOST:PORT --history DIR [--day-max BYTES] [--ready FILE]
      read a relay's --acars-out into DIR/YYYY/MM/DD/acars.jsonl, copies merged, at most
      BYTES a day (default 268435456), writing what each day missed to acars.gaps beside it;
      FILE is made once what was missed since the last run is marked
  tally-acars-collect sort FILE --scratch DIR
      sort a day's acars.jsonl in place by each message's own time, keeping only published
      lines, each once, its runs in DIR (emptied first, removed after; on FILE's volume)";

fn main() {
    if let Err(error) = command(std::env::args().skip(1).collect()) {
        eprintln!("tally-acars-collect: {error}\n{USAGE}");
        std::process::exit(2);
    }
}

fn command(args: Vec<String>) -> Result<(), String> {
    match args.split_first() {
        Some((verb, rest)) if verb == "collect" => {
            let (from, history, day_max, ready) = collect_args(rest)?;
            run(
                &from,
                &mut Collector::new(history, day_max),
                ready.as_deref().map(Path::new),
            )
            .map_err(|error| format!("{from}: {error}"))
        }
        Some((verb, [file, flag, scratch])) if verb == "sort" && flag == "--scratch" => {
            let sorted = sort_day(Path::new(file), Path::new(scratch))
                .map_err(|error| format!("{file}: {error}"))?;
            if sorted.dropped + sorted.repeated > 0 {
                eprintln!(
                    "tally-acars-collect: {file}: {} lines not published and {} written twice \
                     dropped",
                    sorted.dropped, sorted.repeated
                );
            }
            Ok(())
        }
        _ => Err("a command is collect or sort".to_owned()),
    }
}

type CollectArgs = (String, String, u64, Option<String>);

fn collect_args(args: &[String]) -> Result<CollectArgs, String> {
    let (mut from, mut history, mut day_max, mut ready) = (None, None, DEFAULT_DAY_MAX, None);
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?
            .clone();
        match flag.as_str() {
            "--from" => {
                check_address(&value)?;
                from = Some(value);
            }
            "--history" => history = Some(value),
            "--ready" => ready = Some(value),
            "--day-max" => {
                day_max = value
                    .parse()
                    .ok()
                    .filter(|bytes| *bytes > 0)
                    .ok_or_else(|| format!("--day-max {value} is not a positive byte count"))?;
            }
            _ => return Err(format!("{flag} is not a flag")),
        }
    }
    Ok((
        from.ok_or("collect needs --from")?,
        history.ok_or("collect needs --history")?,
        day_max,
        ready,
    ))
}
