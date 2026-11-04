//! The upgrade gate (RFC-0203 §4): the build fails if a release cannot upgrade the installs before
//! it by itself, since no release may need the owner's hands.
//!
//! Each case starts from an install made by an earlier installer: the published `install.sh` of
//! each release vendored in `tests/previous` (the release workflow checks they are byte for byte
//! what those releases published, the newest the release before the tag), and the installer under
//! test itself. The owner has added a flag of their own and chosen about automatic updates. It
//! then upgrades the way that receiver would: through the earlier release's own updater
//! (`update.sh`) when it had one and automatic updates are on, else by the owner running the new
//! `install.sh` again, the only path a release from before the updater (v0.7.1 and earlier) has.
//! The release it upgrades to is the build under test: this `install.sh`, `update.sh`, units and
//! the real `tally-feed`.
//!
//! After it, the receiver runs the new feeder, which starts with the arguments the upgrade left
//! (its log names the receiver by the key it had), the key is the one it had, and the location,
//! the owner's flag and their choice about automatic updates are as they were. The altitude is
//! exactly the one the earlier install wrote, though the receiver's adsb.im setup gives the same
//! place another one, above sea level, which an install converts (v0.7.5): no upgrade moves it.

mod sandbox;

use std::path::PathBuf;

use sandbox::{RELAY_KEY, Result, Sandbox, installer, io, path_of, succeeded, updater};

/// An install to start from: its name, its `install.sh` and its `update.sh` if it had one.
struct Previous {
    name: String,
    installer: PathBuf,
    updater: Option<PathBuf>,
}

/// The vendored releases (`TALLY_PREVIOUS`, every file under tests/previous) and the build under
/// test as installed.
fn previous() -> Result<Vec<Previous>> {
    let files = std::env::var("TALLY_PREVIOUS")
        .map_err(|_| "TALLY_PREVIOUS lists tests/previous (set by the build)".to_owned())?;
    let mut releases: Vec<Previous> = Vec::new();
    for file in files.split_whitespace() {
        let path = io(std::fs::canonicalize(file))?;
        let release = path
            .parent()
            .and_then(|dir| dir.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| format!("{file} is not in a release's directory"))?;
        let index = match releases.iter().position(|known| known.name == release) {
            Some(index) => index,
            None => {
                releases.push(Previous {
                    name: release,
                    installer: PathBuf::new(),
                    updater: None,
                });
                releases.len() - 1
            }
        };
        match path.file_name().and_then(|name| name.to_str()) {
            Some("install.sh") => releases[index].installer = path,
            Some("update.sh") => releases[index].updater = Some(path),
            _ => {
                return Err(format!(
                    "{file}: tests/previous holds install.sh and update.sh"
                ));
            }
        }
    }
    if let Some(missing) = releases
        .iter()
        .find(|release| release.installer.as_os_str().is_empty())
    {
        return Err(format!("tests/previous/{} has no install.sh", missing.name));
    }
    if releases.is_empty() {
        return Err("tests/previous vendors no release".to_owned());
    }
    releases.push(Previous {
        name: "this build".to_owned(),
        installer: installer()?,
        updater: Some(updater()?),
    });
    Ok(releases)
}

const LOCATION: &[(&str, &str)] = &[
    ("TALLY_LAT", "51.5"),
    ("TALLY_LON", "-0.1"),
    ("TALLY_ALT", "20"),
];

const PUBLISHING: &str = "tally-feed: reading 127.0.0.1:30005\ntally-feed: publishing to relay.example:10900 (version 4)\n";

const TIMER_ENABLED: &str = "enabled-tally-feed-update.timer";

/// The tag the build under test is released as when an updater upgrades to it: newer than any
/// release vendored.
const NEXT: &str = "v99.0.0";

/// A key made by the real feeder: its secret (what a key file holds) and its public half.
fn real_key() -> Result<(String, String)> {
    let output = io(std::process::Command::new(path_of("TALLY_FEED")?)
        .arg("new-key")
        .output())?;
    let text = succeeded(output)?;
    let mut lines = text.lines();
    match (lines.next(), lines.next()) {
        (Some(secret), Some(public)) => Ok((secret.to_owned(), public.to_owned())),
        _ => Err(format!("new-key printed {text}")),
    }
}

/// Publishes the build under test in `release/` as `tag`, as the release workflow does: the real
/// feeder, this installer as that tag, the updater, the units and a seed list, signed on `tag`.
fn release_this_build(sandbox: &Sandbox, tag: &str) -> Result {
    let script = io(std::fs::read_to_string(installer()?))?;
    let current = script
        .lines()
        .find(|line| line.starts_with("VERSION=\""))
        .ok_or("the installer names no VERSION")?
        .to_owned();
    sandbox.file(
        "release/install.sh",
        &script.replacen(&current, &format!("VERSION=\"{tag}\""), 1),
    )?;
    sandbox.copy(&path_of("TALLY_FEED")?, "release/tally-feed-x86_64-linux")?;
    sandbox.copy(&updater()?, "release/update.sh")?;
    sandbox.geoid()?;
    for unit in [
        "tally-feed.service",
        "tally-feed-update.service",
        "tally-feed-update.timer",
    ] {
        sandbox.copy(
            &path_of(&format!("TALLY_UNIT_{}", unit.replace(['-', '.'], "_")))?,
            &format!("release/{unit}"),
        )?;
    }
    sandbox.file(
        "release/seeds",
        &format!("relay.example:10900={RELAY_KEY} Example Operator\n"),
    )?;
    succeeded(sandbox.run(&format!("sign_release {tag}"), &[])?)?;
    sandbox.file("latest", tag)
}

/// The installer under test's own VERSION.
fn this_version(sandbox: &Sandbox) -> Result<String> {
    sandbox.ok("printf %s \"$VERSION\"", &[])
}

/// Installs `from` with automatic updates `on` or off, adds the owner's flag, and upgrades to the
/// build under test the way that receiver would; then checks the receiver.
fn upgrade(from: &Previous, on: bool) -> Result {
    let case = format!(
        "{} with automatic updates {}",
        from.name,
        if on { "on" } else { "off" }
    );
    let sandbox = Sandbox::new(&format!("upgrade-{}-{on}", from.name.replace(' ', "-")))?;
    let (secret, public) = real_key()?;
    sandbox.file("journal", PUBLISHING)?;
    sandbox.file(
        "seeds",
        &format!("relay.example:10900={RELAY_KEY} Example Operator\n"),
    )?;

    // The earlier release, with a stand-in feeder that makes the real key (its file format is the
    // network's for good).
    sandbox.file(
        "release/tally-feed-x86_64-linux",
        &format!(
            "#!/bin/sh\n[ \"$1\" = init ] && {{ [ -f \"$3\" ] || printf '%s\\n' '{secret}' > \"$3\"; echo '{public}'; }}\nexit 0\n"
        ),
    )?;
    for (unit, text) in [
        ("tally-feed.service", "[Service]\n"),
        ("tally-feed-update.service", "[Service]\n"),
        ("tally-feed-update.timer", "[Timer]\n"),
    ] {
        sandbox.file(&format!("release/{unit}"), text)?;
    }
    // Published since v0.7.4; an earlier installer never reads it.
    sandbox.geoid()?;
    match &from.updater {
        Some(updater) => sandbox.copy(updater, "release/update.sh")?,
        None => sandbox.file("release/update.sh", "#!/bin/sh\n")?,
    }
    let seeds = sandbox.dir.join("seeds").display().to_string();
    let mut env: Vec<(&str, &str)> = LOCATION.to_vec();
    env.extend([
        ("TALLY_RELEASE", "https://release.example/previous"),
        ("TALLY_SEEDS", seeds.as_str()),
    ]);
    if !on {
        env.push(("TALLY_AUTO_UPDATE", "0"));
    }
    let out =
        succeeded(sandbox.run_with(&from.installer, "sign_release \"$VERSION\"\nmain", &env)?)
            .map_err(|error| format!("{case}: the earlier install: {error}"))?;
    let defaults = "root/etc/default/tally-feed";
    let written = sandbox.read(defaults)?.replace(
        "TALLY_FEED_EXTRA=\"\"",
        "TALLY_FEED_EXTRA=\"--clock beast\"",
    );
    if !written.contains("TALLY_FEED_EXTRA=\"--clock beast\"") {
        return Err(format!("{case}: no TALLY_FEED_EXTRA in {written}\n{out}"));
    }
    sandbox.file(defaults, &written)?;
    // The altitude the earlier install wrote, which every upgrade keeps.
    let alt = written
        .lines()
        .find(|line| line.starts_with("TALLY_FEED_ARGS="))
        .and_then(|line| line.split(" --alt ").nth(1))
        .map(|rest| rest.trim_end_matches('"').to_owned())
        .ok_or_else(|| format!("{case}: no --alt in {written}"))?;
    // The receiver's adsb.im setup names the same place and its own altitude, above sea level.
    sandbox.file(
        "root/opt/adsb/config/.env",
        "FEEDER_LAT=51.5\nFEEDER_LONG=-0.1\nFEEDER_ALT_M=31\n",
    )?;
    let had_updater = sandbox.exists("root/usr/local/lib/tally/update");
    let enabled_before = sandbox.exists(TIMER_ENABLED);

    // The upgrade.
    let new_release = [("TALLY_RELEASE", "https://release.example/next")];
    let log = match (&from.updater, enabled_before) {
        (Some(updater), true) => {
            release_this_build(&sandbox, NEXT)?;
            succeeded(sandbox.update_with(updater, "main", &new_release)?)
                .map_err(|error| format!("{case}: its updater: {error}"))?
        }
        _ => {
            let version = this_version(&sandbox)?;
            release_this_build(&sandbox, &version)?;
            succeeded(sandbox.run("main", &new_release)?)
                .map_err(|error| format!("{case}: the owner's rerun: {error}"))?
        }
    };

    // The receiver runs the build under test's feeder, with the key it had.
    let feeder = io(std::fs::read(path_of("TALLY_FEED")?))?;
    if io(std::fs::read(
        sandbox.dir.join("root/usr/local/bin/tally-feed"),
    ))? != feeder
    {
        return Err(format!("{case}: the feeder is not the new one\n{log}"));
    }
    let key = sandbox.ok("\"$BIN\" init --key \"$KEY\"", &[])?;
    if key.trim() != public {
        return Err(format!("{case}: the key is now {key}, not {public}"));
    }
    // Its settings: the location, the owner's flag, one block.
    let written = sandbox.read(defaults)?;
    for kept in [
        format!("--lat 51.5 --lon -0.1 --alt {alt}\""),
        "TALLY_FEED_EXTRA=\"--clock beast\"".to_owned(),
    ] {
        if !written.contains(&kept) {
            return Err(format!("{case}: {kept} is gone from {written}"));
        }
    }
    if written.matches("# BEGIN install.sh").count() != 1 {
        return Err(format!("{case}: {written}"));
    }
    // The owner's choice: an install from before the updater had none to make, so it is on.
    let want = on || !had_updater;
    if sandbox.exists(TIMER_ENABLED) != want {
        return Err(format!(
            "{case}: automatic updates are {} after the upgrade\n{log}",
            if want { "off" } else { "on" }
        ));
    }
    // And the new feeder starts with the arguments the upgrade left: still running after a few
    // seconds (no decoder or relay answers here, which it keeps trying), having named the
    // receiver by its key.
    let started = sandbox.ok(
        r#"
args="$(value_of "$DEFAULTS" TALLY_FEED_ARGS)"
extra="$(value_of "$DEFAULTS" TALLY_FEED_EXTRA)"
status=0
# shellcheck disable=SC2086
timeout 5 "$BIN" --key "$KEY" --state "$T/feeder-state" $args $extra 2>"$T/feeder.log" >/dev/null || status=$?
printf 'status %s\n' "$status"
cat "$T/feeder.log"
"#,
        &[],
    )?;
    if !started.starts_with("status 124\n")
        || !started.contains(&format!("tally-feed: receiver {public}"))
    {
        return Err(format!("{case}: the new feeder did not start: {started}"));
    }
    Ok(())
}

#[test]
fn every_earlier_install_upgrades_to_this_build_by_itself() -> Result {
    let mut failures = Vec::new();
    for from in previous()? {
        for on in [true, false] {
            if let Err(error) = upgrade(&from, on) {
                failures.push(error);
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n\n"))
    }
}
