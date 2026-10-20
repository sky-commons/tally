//! A Tally relay (RFC-0171 §3.6, RFC-0174): accepts feeders, clients and other relays on one
//! port, checks every signature, forwards each batch and each relay's positions once, signs its
//! own deduplicated stream, and serves plain BEAST on loopback for a local decoder. There is no
//! separate MLAT engine: the relay runs MLAT itself (`mlat_host`, one program, RFC-0174 §2.1).
//! Its RFC-0174 duties (`network`) take areas and share them in striped groups, answer probes and
//! delivery checks, hold the provider directory, run MLAT for the areas it is chosen for, gate
//! clients by credit, and build the regional and world products: the world product decodes
//! aircraft positions from the receptions it gathers, so a relay that builds it reads aircraft as
//! well as frames.

pub mod admission;
pub mod bounded;
pub mod budget;
pub mod ceiling;
pub mod config;
pub mod consistency;
pub mod cores;
pub mod credit;
pub mod deduplicated;
pub mod delivery;
pub mod directory;
pub mod egress;
pub mod exchange;
pub mod fanout;
pub mod figures;
pub mod hub;
pub mod ingest;
pub mod link;
pub mod listeners;
pub mod mlat_host;
pub mod network;
pub mod os;
pub mod outbound;
pub mod parts;
pub mod peers;
pub mod products;
pub mod seal;
pub mod selection;
pub mod sharing;
pub mod shed;
pub mod sockets;
pub mod standing;
pub mod stations;
pub mod stats;
pub mod subscription;

use std::sync::Arc;

use tally_wire::Identity;
use tokio::net::TcpListener;

use crate::hub::Hub;

/// Makes every panic, on any thread of the process (a stage's, a connection's task, the hosted
/// engine's, a pool worker's), end it once it is reported, before anything unwinds: a part that
/// stopped would hold its epochs open, its charges taken and its locks poisoned while the rest ran
/// on as if it were whole, and nothing else would say so. The process's supervisor restarts it (the
/// unit's `Restart=always`, the pod's restart policy). The relay's program sets it first thing
/// (`main`), so every build of the binary (Cargo's, Bazel's) has it and no runtime that catches a
/// task's panic (as tokio does) can keep the relay running without the part that panicked; it is
/// the one mechanism (tests/panic.rs holds it to that). The library sets no hook of its own: its
/// only other users are tests, where a panic is a test's failure to report, not a process to end.
pub fn abort_on_any_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        eprintln!(
            "tally-relay: a thread panicked; ending the relay rather than running without it"
        );
        std::process::abort();
    }));
}

/// Accepts connections on `listener` up to the hub's connection caps, the relay's and each source
/// address's (beyond either, a connection is closed before its handshake), each counted and capped
/// from its first byte (`egress::Socket`); and signs its own records (its products, the
/// deduplicated stream among them, and its network records) with the newest key (`identities[0]`),
/// for as long as the relay runs. The relay's cap counts only the connections that hold no place
/// of their role's own (`hub::Connection::general`): a connection gives its place up once it is a
/// feeder, a subscriber or a member, each bounded by its own cap and told when that is full, so a
/// relay full of feeders still answers a member's handshake (`link::inbound`).
///
/// Its accepts are a [`listeners::Acceptor`]'s (`listen` on `GET /listeners`): each connection
/// counted while it is open, and a run of failed accepts waited out; it returns only when its
/// listener has accepted nothing for `listeners::STARVED_AFTER`, which ends the relay.
pub async fn serve(
    listener: TcpListener,
    identities: Vec<Identity>,
    hub: Arc<Hub>,
) -> listeners::Starved {
    if let Some(newest) = identities.first() {
        hub.network().adopt_identity(newest.clone());
    }
    network::start(Arc::clone(&hub), tokio::runtime::Handle::current());
    let identities = Arc::new(identities);
    // A feeder's kernel buffers until its handshake names its role (`sockets`).
    let mut acceptor = listeners::Acceptor::new(
        listener,
        hub.listeners().gauge("listen"),
        Arc::clone(hub.egress()),
        sockets::Role::Feeder,
    );
    loop {
        let (stream, peer) = match acceptor.next().await {
            Ok(accepted) => accepted,
            Err(starved) => return starved,
        };
        let Some(connection) = hub.connection(peer.ip()) else {
            acceptor.refuse(stream);
            continue;
        };
        let identities = Arc::clone(&identities);
        let hub = Arc::clone(&hub);
        tokio::spawn(async move {
            if let Err(error) = link::inbound(stream, &identities, hub, connection).await {
                eprintln!("tally-relay: {peer}: {error}");
            }
        });
    }
}

/// The guard every unit-test target of this crate runs beside its own module's tests.
#[cfg(test)]
mod targets {
    use std::collections::BTreeSet;

    /// The module filters of the build's unit-test targets (`crates/relay/BUILD.bazel`,
    /// `_UNIT_TEST_MODULES`, each `<module>::`), which the build hands the test binary when it
    /// compiles it. None under Cargo, which runs every test of the binary at once and so selects
    /// none by filter.
    const FILTERS: Option<&str> = option_env!("RELAY_TEST_FILTERS");

    /// This guard's name, the filter every target passes beside its own so that it runs too.
    const GUARD: &str = "every_test_has_one_target";

    /// A target selects its tests by filter, a substring of each test's path, and libtest runs no
    /// test at all, green, for a filter nothing matches. So every target runs this beside its own:
    /// every test this binary has, as libtest lists them (the binary asked for its own list), is
    /// matched by exactly one target's filter, the way libtest matches it, and every filter matches
    /// a test. A module added without its target, a filter that also matches another module's tests
    /// (`os::` would match a `pos::`), or a target whose module has gone, fails every target.
    #[test]
    fn every_test_has_one_target() -> Result<(), String> {
        let Some(filters) = FILTERS else {
            // Under Cargo every test here runs in this one binary: there is no target to miss one.
            return Ok(());
        };
        let filters: BTreeSet<&str> = filters.split_whitespace().collect();
        let exe = std::env::current_exe().map_err(|error| error.to_string())?;
        let listed = std::process::Command::new(&exe)
            .args(["--list", "--format", "terse"])
            .output()
            .map_err(|error| error.to_string())?;
        if !listed.status.success() {
            return Err(format!("{} --list: {}", exe.display(), listed.status));
        }
        let listed = String::from_utf8(listed.stdout).map_err(|error| error.to_string())?;
        let tests: Vec<&str> = listed
            .lines()
            .filter_map(|line| line.strip_suffix(": test"))
            .collect();
        let mut wrong = Vec::new();
        for test in &tests {
            let matched: Vec<&str> = filters
                .iter()
                .copied()
                .filter(|filter| test.contains(filter))
                .collect();
            let guard = *test == format!("targets::{GUARD}");
            // The guard runs in every target, so it is no target's, and no other test may share
            // its filter.
            let want = if guard { 0 } else { 1 };
            if matched.len() != want || (!guard && test.contains(GUARD)) {
                wrong.push(format!("{test}: matched by {matched:?}"));
            }
        }
        for filter in &filters {
            if !tests.iter().any(|test| test.contains(filter)) {
                wrong.push(format!("{filter}: matches no test"));
            }
        }
        if !wrong.is_empty() {
            return Err(format!(
                "every test here is one target's (crates/relay/BUILD.bazel, _UNIT_TEST_MODULES):\n{}",
                wrong.join("\n")
            ));
        }
        // And the filters this run was asked for are a target's.
        for arg in std::env::args().skip(1) {
            if !arg.starts_with('-') && arg != GUARD && !filters.contains(arg.as_str()) {
                return Err(format!("asked for {arg}, which no target names"));
            }
        }
        Ok(())
    }
}
