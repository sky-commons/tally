//! The public relay's plan against what it is resident (RFC-0181, "Sizing", "The relay's own
//! base"): the relay built beside this test, started with the public relay's deployed arguments
//! (`infra/kubernetes/tally/relay.yaml` in flightlines: hosting MLAT, listening on every address,
//! serving beast-out to one client, advertising itself under its own key, vouching for a client
//! key, the 122 resolution-0 areas and its caps), and again gathering the world product
//! (`--world`), with `--memory` exactly what each load needs
//! (`tally-load --relay-fit`), and `N` simulated feeders, for N of 0, 8, 32 and 128. Its judging
//! clock is bounded by a ClockBound segment the harness keeps synchronised (`--clock-bound`), so
//! it judges and works. Each run passes only if every feeder is held, the relay did its work
//! (its clock judged every record, it signed products, its own strike tables filled, MLAT stepped,
//! took raw in, tried its clock fits and stayed within its plan, standing forgot none for room;
//! what MLAT published is reported, not held, since a run's timing moves it,
//! `tally_load::relay::MlatWorked`), what the allocator serves
//! beyond every store's charge stays within the measured base and its margin, and its peak
//! resident memory stays within its plan: the most its base and stores were charged, and the
//! memory fitted to the load, each with the headroom kept below it (`tally_load::run`).
//!
//! A measurement, not a test of the code: it takes minutes, runs real sockets and the MLAT
//! simulator, and reads this host's memory, so it is tagged `manual` and never in the verdict.
//! Run it optimised, printing each load's table:
//! `bazel test -c opt //crates/load:public_relay --test_output=all --test_arg=--nocapture`.

#![allow(
    clippy::disallowed_methods,
    reason = "a measurement's scripted readings"
)]

/// The public relay's areas: every resolution-0 cell, `8001fffffffffff` to `80f3fffffffffff`
/// (an H3 index's base cell is its bits 45 to 51). Before, the first was a nibble too wide
/// (`8001ffffffffffff`, no H3 cell), so the relay refused to start and nothing was measured.
fn areas() -> Vec<String> {
    (0..122u64)
        .map(|base| format!("{:x}", 0x0800_1fff_ffff_ffff_u64 + (base << 45)))
        .collect()
}

/// The areas are the 122 resolution-0 cells the public relay takes, as its deploy names them.
#[test]
fn the_areas_are_the_public_relays_resolution_0_cells() {
    let areas = areas();
    assert_eq!(areas.len(), 122);
    assert_eq!(areas.first().map(String::as_str), Some("8001fffffffffff"));
    assert_eq!(areas.get(1).map(String::as_str), Some("8003fffffffffff"));
    assert_eq!(areas.last().map(String::as_str), Some("80f3fffffffffff"));
}

/// A free port on loopback, for the relay's beast-out (deployed at `127.0.0.1:30105`, which
/// another process on this host may hold).
fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| error.to_string())
}

/// `tally-load`'s arguments for `feeders` feeders against the public relay's deployed shape,
/// gathering the world products (`world`) or not. The harness's own `--advertise` is the deploy's:
/// one offer, under the relay's own key, at the address its feeders reach it by.
fn args(feeders: usize, state: &std::path::Path, world: bool) -> Result<Vec<String>, String> {
    let mut args: Vec<String> = [
        "--relay-mlat",
        "--relay-fit",
        "--relay-listen",
        "0.0.0.0:0",
        "--max-upload",
        "6Mbit/s",
        "--ramp",
        "10",
        "--warmup",
        "40",
        "--duration",
        "60",
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect();
    // The relay is fitted to the run's feeders (`--feeders`, the whole run's), and `--no-feeders`
    // only starts none here: without `--feeders 0` the idle run was fitted to the default 20,000
    // and refused as more than the host holds.
    args.extend(["--feeders".to_owned(), feeders.to_string()]);
    if feeders == 0 {
        args.push("--no-feeders".to_owned());
    }
    args.extend(["--state-dir".to_owned(), state.display().to_string()]);
    // The API, vouched for: any key stands in for the deploy's.
    let client = tally_wire::Identity::from_seed([0xa9; 32])
        .public()
        .to_base64();
    let beast_out = format!("127.0.0.1:{}", free_port()?);
    let mut relay_args = vec![
        "--beast-out",
        beast_out.as_str(),
        "--client",
        client.as_str(),
    ];
    if world {
        relay_args.push("--world");
    }
    for relay_arg in relay_args.into_iter().chain([
        "--max-beast-clients",
        "1",
        "--network",
        "16509",
        "--max-member-bytes-per-sec",
        "65536",
        "--max-connections",
        "32",
        "--max-subscribers",
        "16",
    ]) {
        args.extend(["--relay-arg".to_owned(), relay_arg.to_owned()]);
    }
    for area in areas() {
        args.extend([
            "--relay-arg".to_owned(),
            "--area".to_owned(),
            "--relay-arg".to_owned(),
            area,
        ]);
    }
    Ok(args)
}

/// The deployed public relay at each load.
#[test]
fn the_public_relay_is_resident_within_its_plan_at_each_load() -> Result<(), String> {
    at_each_load(false)
}

/// The public relay gathering the world product (`--world`) at each load.
#[test]
fn the_public_relay_gathering_the_world_is_resident_within_its_plan_at_each_load()
-> Result<(), String> {
    at_each_load(true)
}

fn at_each_load(world: bool) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let root = std::env::var_os("TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    for feeders in [0usize, 8, 32, 128] {
        let state = root.join(format!(
            "public-relay-{feeders}{}",
            if world { "-world" } else { "" }
        ));
        let config = tally_load::config::parse(args(feeders, &state, world)?.into_iter())?
            .ok_or("no configuration")?;
        let table = runtime.block_on(tally_load::run(config))?;
        println!(
            "{feeders} feeders{}:\n{table}",
            if world { ", gathering the world" } else { "" }
        );
        let held = table
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("relay: feeders")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|held| held.parse::<usize>().ok())
            })
            .ok_or("no feeders line")?;
        assert_eq!(held, feeders, "{feeders} feeders: {held} held");
    }
    Ok(())
}
