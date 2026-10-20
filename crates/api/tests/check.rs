//! `tally-api check`: a deploy's arguments are checked by the API itself, along the path a start
//! takes (`Config::prepare`), so a deploy's own test asks the binary rather than copying its rules.
//! Run against the built binary, which the build names (`TALLY_API_BIN`, a runfiles path);
//! `cargo test` finds it itself.

use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;

use tally_wire::Identity;

type Result<T = ()> = std::result::Result<T, String>;

fn binary() -> Result<PathBuf> {
    std::env::var_os("TALLY_API_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_tally-api").map(PathBuf::from))
        .ok_or_else(|| "TALLY_API_BIN names the API (set by the build)".to_owned())
}

/// What a run said: whether it exited 0, its stdout and its stderr.
struct Ran {
    accepted: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Result<Ran> {
    let output = Command::new(binary()?)
        .args(args)
        .output()
        .map_err(|error| format!("tally-api: {error}"))?;
    Ok(Ran {
        accepted: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// `tally-api check ARGS`, and the start's own refusal of the same ARGS.
fn checked_and_started(args: &[&str]) -> Result<(Ran, Ran)> {
    let checked = run(&[&["check"], args].concat())?;
    let started = run(args)?;
    Ok((checked, started))
}

const UPSTREAMS: [&str; 4] = [
    "--relay-stats",
    "http://127.0.0.1:10901",
    "--readsb",
    "http://127.0.0.1:30152",
];

#[test]
fn a_deploys_arguments_pass_and_the_settings_are_printed() -> Result {
    let key = Identity::from_seed([4; 32]).public().to_base64();
    let relay = format!("10.0.0.1:10900={key}");
    let mut args = vec!["check"];
    args.extend(UPSTREAMS);
    args.extend([
        "--listen",
        "0.0.0.0:10902",
        "--relay",
        &relay,
        "--client-ip-header",
        "CF-Connecting-IP",
        "--allow-origin",
        "https://map.example",
    ]);
    let ran = run(&args)?;
    assert!(ran.accepted, "refused: {}", ran.stderr);
    for line in [
        "listen 0.0.0.0:10902",
        "readsb http://127.0.0.1:30152",
        "client-ip-header cf-connecting-ip",
        "allow-origins https://map.example",
        "relays 1",
        &format!("relay {relay}"),
        "key fresh",
        "routes none",
    ] {
        assert!(
            ran.stdout.lines().any(|printed| printed == line),
            "no `{line}` in:\n{}",
            ran.stdout
        );
    }
    Ok(())
}

/// An argument the binary no longer has (`--mlat-raw`, gone in v0.5.0) is refused by the check
/// with the very message a start refuses it with.
#[test]
fn an_unknown_argument_is_refused_as_a_start_refuses_it() -> Result {
    let args = [&UPSTREAMS[..], &["--mlat-raw"]].concat();
    let (checked, started) = checked_and_started(&args)?;
    assert!(!checked.accepted && !started.accepted);
    assert!(
        checked
            .stderr
            .starts_with("tally-api: unknown argument --mlat-raw\n"),
        "{}",
        checked.stderr
    );
    assert_eq!(checked.stderr, started.stderr);
    Ok(())
}

#[test]
fn a_missing_routes_directory_is_refused_as_a_start_refuses_it() -> Result {
    let dir = std::env::temp_dir()
        .join(format!("tally-api-check-{}-no-routes", std::process::id()))
        .display()
        .to_string();
    let args = [&UPSTREAMS[..], &["--routes", &dir]].concat();
    let (checked, started) = checked_and_started(&args)?;
    assert!(!checked.accepted && !started.accepted);
    assert!(
        checked
            .stderr
            .starts_with(&format!("tally-api: --routes {dir}: ")),
        "{}",
        checked.stderr
    );
    assert_eq!(checked.stderr, started.stderr);
    Ok(())
}

/// A check binds nothing and dials nothing: told to listen where this test already listens, and to
/// read every upstream and relay from there, it passes (a bind would find the address taken, as
/// the start does) and nothing connects to it.
#[test]
fn a_check_opens_no_socket_and_reads_no_network() -> Result {
    let taken = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    taken
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let address = taken.local_addr().map_err(|error| error.to_string())?;
    let url = format!("http://{address}");
    let key = Identity::from_seed([6; 32]).public().to_base64();
    let relay = format!("{address}={key}");
    let listen = address.to_string();
    let args = [
        "--relay-stats",
        &url,
        "--readsb",
        &url,
        "--relay",
        &relay,
        "--listen",
        &listen,
    ];
    let checked = run(&[&["check"], &args[..]].concat())?;
    assert!(checked.accepted, "refused: {}", checked.stderr);
    match taken.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok((_, peer)) => return Err(format!("the check connected from {peer}")),
        Err(error) => return Err(error.to_string()),
    }
    // The same arguments started: the bind is the start's, and finds the address taken.
    let started = run(&args)?;
    assert!(!started.accepted);
    assert!(
        started
            .stderr
            .starts_with(&format!("tally-api: listen {address}: ")),
        "{}",
        started.stderr
    );
    Ok(())
}
