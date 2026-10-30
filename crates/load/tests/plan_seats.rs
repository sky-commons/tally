//! The world relay's MLAT seats against what its load settles at (RFC-0181 §10, "MLAT in the
//! cores"): the relay built beside this test, started with the world relay's plan
//! (`crates/relay/tests/world-relay.txt`: 16 cores, its memory, `--max-connections 1024`, hosting
//! MLAT) on this host's first 16 cores, the harness on the rest, and 2,000 simulated feeders
//! sending the measured mix (`tally_load::traffic`), more than the seats it plans, so its seats
//! are what its own steps carry: its governor cuts them to what a step runs within its budget
//! (`mlat_host`, Overload). It passes if the seats it settled at are within 15% of the seats its
//! plan printed (`cores::mlat_planned_per_feeder`), and its steps, in proportion at the planned
//! seats, ran within 15% of the share of the governor's target a relay alone's steps run on
//! average (`mlat_host::STEP_TARGET_MS`, what the plan fills MLAT's threads to,
//! `cores::MLAT_BUSY_PERCENT`, times `cores::mlat_step_per_feeder` of a seat's cost): the seats can never pass the plan's, so the steps' time is the
//! other side, a plan that seats too few running its steps well short of the target. So the plan
//! predicts the load test, whose costs it was measured from.
//!
//! A measurement, not a test of the code: it takes minutes, runs real sockets and the MLAT
//! simulator over 17 cores at least, so it is tagged `manual` and never in the verdict (Bazel's
//! size rules: a large test is 15 minutes at most). Run it optimised on a host of 32 cores:
//! `bazel test -c opt //crates/load:plan_seats --test_output=all --test_arg=--nocapture`.

#![allow(
    clippy::disallowed_methods,
    reason = "a measurement's scripted readings"
)]

/// The world relay's cores (`world-relay.txt`'s `cores`).
const CORES: usize = 16;
/// Its memory (`world-relay.txt`'s `memory`: what `--memory-limit 32G` leaves it).
const MEMORY: &str = "31608274944";
/// The feeders: more than the world relay's planned seats, so the seats bind.
const FEEDERS: usize = 2_000;
/// How far the settled seats may be from the planned, either way, as a share.
const WITHIN_PERCENT: u64 = 15;

/// The seats the load settled at are within 15% of the seats the plan printed.
#[test]
fn the_world_relays_load_settles_within_15_percent_of_its_planned_seats() -> Result<(), String> {
    let root = std::env::var_os("TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let mut args: Vec<String> = [
        "--relay-mlat",
        "--relay-cores",
        &CORES.to_string(),
        "--feeders",
        &FEEDERS.to_string(),
        "--ramp",
        "60",
        "--warmup",
        "60",
        "--duration",
        "120",
        "--state-dir",
        &root.join("plan-seats").display().to_string(),
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect();
    for relay_arg in [
        "--memory",
        MEMORY,
        "--max-connections",
        "1024",
        "--max-connections-per-address",
        "1024",
    ] {
        args.extend(["--relay-arg".to_owned(), relay_arg.to_owned()]);
    }
    let config = tally_load::config::parse(args.into_iter())?.ok_or("no configuration")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let table = runtime.block_on(tally_load::run(config))?;
    println!("{FEEDERS} feeders on {CORES} cores:\n{table}");
    let (settled, planned) = table
        .lines()
        .find_map(|line| {
            let mut words = line
                .trim()
                .strip_prefix("relay: MLAT seats")?
                .split_whitespace();
            let settled = words.next()?.parse::<u64>().ok()?;
            let planned = words.nth(2)?.parse::<u64>().ok()?;
            Some((settled, planned))
        })
        .ok_or("no MLAT seats line")?;
    let ran_ms = table
        .lines()
        .find_map(|line| {
            line.split("its steps ran ")
                .nth(1)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .ok_or("no steps' time")?;
    let target_ms = tally_relay::mlat_host::STEP_TARGET_MS;
    assert!(planned > 0, "the plan printed no seat");
    assert!(
        settled.abs_diff(planned) * 100 <= planned * WITHIN_PERCENT,
        "the load settled at {settled} seats, the plan printed {planned}: more than \
         {WITHIN_PERCENT}% apart, so `cores::mlat_per_feeder` is not what a seat costs this host"
    );
    // Its steps at the planned seats, from what they ran at the seats settled, in proportion: a
    // step's cost has a part that is not the seats', so this is the most they would run. Held to
    // the target's share a step of a relay alone runs (`cores::mlat_step_per_feeder`: no
    // neighbour's model to verify, and its publishing on the duties thread). Before (2026-10-27),
    // to the whole target, which a relay alone's steps reach only when the seats' other parts
    // are planned too low.
    let at_planned_ms = ran_ms * planned / settled.max(1);
    let step_ms = target_ms * tally_relay::cores::mlat_step_per_feeder() as u64
        / tally_relay::cores::mlat_per_feeder(true) as u64;
    assert!(
        at_planned_ms.abs_diff(step_ms) * 100 <= step_ms * WITHIN_PERCENT,
        "at {settled} seats its steps ran {ran_ms} ms on average, {at_planned_ms} ms at the \
         {planned} planned, where a step of a relay alone at the governor's target ({target_ms} \
         ms) runs {step_ms} ms: more than {WITHIN_PERCENT}% apart, so the plan's seats are not \
         what the cores carry at the target"
    );
    Ok(())
}
