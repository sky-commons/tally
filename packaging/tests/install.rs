//! `install.sh`, run with no network and no root. The first two tests run it whole as an owner
//! would before a release pipeline exists (RFC-0180 phase 1): nothing writes the release's address
//! into the script or publishes a seed list beside it, so the documented install stops, saying how
//! to go on, before it asks for root and with nothing installed.
//!
//! The rest source the script into the sandbox (`sandbox`). Each test is one behaviour: a rerun's
//! location winning over the last one's and keeping the owner's own flags, each location source,
//! the altitude it will not guess, the build the userland (not the kernel) runs, the container
//! route, the wait for "publishing", each file's signature, automatic updates on by default and
//! the owner's choice kept, uninstalling with and without the key; and the updater (`update.sh`,
//! RFC-0203): nothing installed from a release whose signature fails, never an older release, an
//! opted-out receiver left alone, and the old files back when the new release does not start.

mod sandbox;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

use sandbox::{
    INSTALL, PUBLIC, RELAY_KEY, Result, Sandbox, borrowed, install_env, installer, io, succeeded,
    updater,
};

/// The installer's refusal (its stderr) run with `env` and `path` first on its PATH; an error if
/// it did not stop.
fn refusal(env: &[(&str, &str)], path: Option<&Path>) -> Result<String> {
    let mut command = Command::new("bash");
    command
        .arg(installer()?)
        .env_remove("TALLY_RELEASE")
        .env_remove("TALLY_SEEDS");
    for (name, value) in env {
        command.env(name, value);
    }
    if let Some(path) = path {
        let inherited = std::env::var("PATH").unwrap_or_default();
        command.env("PATH", format!("{}:{inherited}", path.display()));
    }
    let output = io(command.output())?;
    if output.status.success() {
        return Err("the installer ran to its end".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// It says how to pass both, through sudo, and that nothing was installed: never that it needs
/// root first.
fn says_how_to_pass_them(refusal: &str) -> Result {
    for needed in [
        "sudo TALLY_RELEASE=",
        "TALLY_SEEDS=",
        "Nothing was installed",
    ] {
        if !refusal.contains(needed) {
            return Err(format!("the refusal does not say {needed:?}: {refusal}"));
        }
    }
    if refusal.contains("run as root") {
        return Err(format!(
            "it asked for root before saying what to pass: {refusal}"
        ));
    }
    Ok(())
}

#[test]
fn an_installer_naming_no_release_says_how_to_pass_one_and_the_seeds() -> Result {
    let refusal = refusal(&[], None)?;
    assert!(refusal.contains("names no release"), "{refusal}");
    says_how_to_pass_them(&refusal)
}

#[test]
fn a_release_publishing_no_seed_list_says_how_to_pass_one() -> Result {
    let stub = std::env::temp_dir().join(format!("tally-install-{}", std::process::id()));
    std::fs::create_dir_all(&stub).map_err(|error| error.to_string())?;
    let curl = stub.join("curl");
    // curl's exit for an HTTP error (404), as for a release with no `seeds`.
    std::fs::write(&curl, "#!/bin/sh\nexit 22\n").map_err(|error| error.to_string())?;
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| error.to_string())?;
    let refusal = refusal(
        &[("TALLY_RELEASE", "https://release.example/tally/v0.1.0")],
        Some(&stub),
    )?;
    assert!(
        refusal.contains("https://release.example/tally/v0.1.0/seeds"),
        "{refusal}"
    );
    says_how_to_pass_them(&refusal)
}

#[test]
fn a_rerun_rewrites_its_own_block_and_keeps_the_owners_flags() -> Result {
    let sandbox = Sandbox::new("rerun")?;
    sandbox.release()?;
    sandbox.file(
        "journal",
        "tally-feed: reading 127.0.0.1:30005\ntally-feed: publishing to relay.example:10900 (version 1)\n",
    )?;
    let first = install_env(
        &sandbox,
        &[
            ("TALLY_LAT", "51.5"),
            ("TALLY_LON", "-0.1"),
            ("TALLY_ALT", "20"),
        ],
    );
    sandbox.ok(INSTALL, &borrowed(&first))?;
    // The owner adds a flag of their own, and a setting of their own below it.
    let defaults = "root/etc/default/tally-feed";
    let written = sandbox.read(defaults)?.replace(
        "TALLY_FEED_EXTRA=\"\"",
        "TALLY_FEED_EXTRA=\"--clock beast\"\nOWN=1",
    );
    sandbox.file(defaults, &written)?;

    let second = install_env(
        &sandbox,
        &[
            ("TALLY_LAT", "48.25"),
            ("TALLY_LON", "11.5"),
            ("TALLY_ALT", "500"),
        ],
    );
    sandbox.ok(INSTALL, &borrowed(&second))?;
    let written = sandbox.read(defaults)?;
    assert!(
        written.contains("--lat 48.25 --lon 11.5 --alt 546\""),
        "{written}"
    );
    assert!(!written.contains("51.5"), "{written}");
    assert!(
        written.contains("TALLY_FEED_EXTRA=\"--clock beast\"\nOWN=1"),
        "{written}"
    );
    assert_eq!(
        written.matches("# BEGIN install.sh").count(),
        1,
        "{written}"
    );
    assert_eq!(written.matches("TALLY_FEED_ARGS=").count(), 1, "{written}");

    // A third run naming nothing keeps the location the second named.
    let third = install_env(&sandbox, &[]);
    sandbox.ok(INSTALL, &borrowed(&third))?;
    let written = sandbox.read(defaults)?;
    assert!(
        written.contains("--lat 48.25 --lon 11.5 --alt 546\""),
        "{written}"
    );
    Ok(())
}

#[test]
fn an_older_installs_file_keeps_the_owners_flags_in_extra() -> Result {
    let sandbox = Sandbox::new("legacy")?;
    sandbox.release()?;
    sandbox.file(
        "journal",
        "tally-feed: publishing to relay.example:10900 (version 1)\n",
    )?;
    sandbox.file(
        "root/etc/default/tally-feed",
        &format!(
            "# Written by install.sh.\nTALLY_FEED_ARGS=\"--relay relay.example:10900={RELAY_KEY} --lat 1.5 --lon 2.5 --alt 7 --clock beast --relay mine.example:1={RELAY_KEY} --uat 127.0.0.1:30978\"\n"
        ),
    )?;
    let env = install_env(&sandbox, &[]);
    let out = sandbox.ok(INSTALL, &borrowed(&env))?;
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains(&format!(
            "TALLY_FEED_EXTRA=\"--clock beast --relay mine.example:1={RELAY_KEY}\""
        )),
        "{written}"
    );
    // Its location is the earlier install's.
    assert!(
        written.contains("--lat 1.5 --lon 2.5 --alt 7\""),
        "{written}"
    );
    assert!(out.contains("earlier install"), "{out}");
    Ok(())
}

#[test]
fn the_location_is_read_from_each_receivers_configuration() -> Result {
    let cases: &[(&str, &str, &str)] = &[
        (
            "root/opt/adsb/config/.env",
            "FEEDER_LAT=51.4775\nFEEDER_LONG=-0.4614\nFEEDER_ALT_M=25\n",
            "51.4775 -0.4614 25|",
        ),
        (
            "root/etc/default/readsb",
            "DECODER_OPTIONS=\"--lat 40.1 --lon -75.2 --max-range 450\"\n",
            "40.1 -75.2 |",
        ),
        (
            "root/var/cache/piaware/location.env",
            "PIAWARE_LAT=\"33.9\"\nPIAWARE_LON=\"-118.4\"\nPIAWARE_DUMP1090_LOCATION_OPTIONS=\"--lat 33.9 --lon -118.4\"\n",
            "33.9 -118.4 |",
        ),
        (
            "root/etc/default/dump1090-fa",
            "RECEIVER_LAT=35.1\nRECEIVER_LON=139.7\n",
            "35.1 139.7 |",
        ),
        (
            "root/etc/default/adsbfi",
            "LATITUDE=60.2\nLONGITUDE=24.9\nALTITUDE=400ft\n",
            "60.2 24.9 122|",
        ),
    ];
    for (path, text, want) in cases {
        let sandbox = Sandbox::new("source")?;
        sandbox.file(path, text)?;
        let found = sandbox.located(&[])?;
        assert!(found.starts_with(want), "{path}: {found}");
        let name = path.rsplit('/').next().unwrap_or_default();
        assert!(
            found.contains(name),
            "{path} is not named as the source: {found}"
        );
    }
    Ok(())
}

#[test]
fn a_running_ultrafeeder_containers_location_is_read() -> Result {
    let sandbox = Sandbox::new("ultrafeeder")?;
    sandbox.file(
        "docker-ps",
        "ultrafeeder ghcr.io/sdr-enthusiasts/docker-adsb-ultrafeeder:latest\n",
    )?;
    sandbox.file(
        "docker-inspect",
        "TZ=UTC\nLAT=47.6\nLONG=-122.3\nALT=120m\n",
    )?;
    let found = sandbox.located(&[])?;
    assert!(
        found.starts_with("47.6 -122.3 120|the ultrafeeder container"),
        "{found}"
    );
    Ok(())
}

#[test]
fn the_environment_wins_and_an_altitude_may_come_from_another_source() -> Result {
    let sandbox = Sandbox::new("order")?;
    sandbox.file(
        "root/opt/adsb/config/.env",
        "FEEDER_LAT=51.4775\nFEEDER_LONG=-0.4614\nFEEDER_ALT_M=0\n",
    )?;
    sandbox.file("root/etc/default/adsbexchange", "ALTITUDE=30m\n")?;
    let found = sandbox.located(&[("TALLY_LAT", "10.5"), ("TALLY_LON", "20.5")])?;
    // adsb.im's 0 is an unset altitude, so the feed client's is taken.
    assert!(found.starts_with("10.5 20.5 30|TALLY_LAT"), "{found}");
    assert!(
        found.ends_with("adsbexchange (LATITUDE, LONGITUDE, ALTITUDE)"),
        "{found}"
    );
    Ok(())
}

#[test]
fn with_no_altitude_and_no_terminal_it_stops_naming_tally_alt() -> Result {
    let sandbox = Sandbox::new("noalt")?;
    sandbox.file(
        "root/etc/default/readsb",
        "RECEIVER_OPTIONS=\"--lat 40.1 --lon -75.2\"\n",
    )?;
    let refusal = sandbox.stopped("discover_location ask", &[])?;
    for needed in ["no altitude", "TALLY_ALT=", "Nothing was installed"] {
        assert!(refusal.contains(needed), "{needed:?}: {refusal}");
    }
    // An adsb.im altitude of 0 is no altitude either.
    let sandbox = Sandbox::new("zeroalt")?;
    sandbox.file(
        "root/opt/adsb/config/.env",
        "FEEDER_LAT=51.4775\nFEEDER_LONG=-0.4614\nFEEDER_ALT_M=0\n",
    )?;
    let refusal = sandbox.stopped("discover_location ask", &[])?;
    assert!(refusal.contains("TALLY_ALT="), "{refusal}");
    // On a terminal it asks instead.
    let asked = sandbox.ok(
        "have_tty() { :; }\nask() { echo 150ft; }\ndiscover_location ask\necho \"$alt|$alt_from\"",
        &[],
    )?;
    assert!(asked.ends_with("46|the terminal\n"), "{asked}");
    Ok(())
}

#[test]
fn the_build_follows_the_userland_not_the_kernel() -> Result {
    // (dpkg's answer or none, uname -m, getconf LONG_BIT) and the build, or the refusal.
    let cases: &[(Option<&str>, &str, &str, &str)] = &[
        (Some("amd64"), "x86_64", "64", "x86_64"),
        (Some("arm64"), "aarch64", "64", "aarch64"),
        // Raspberry Pi OS 32-bit on a Pi 4's 64-bit kernel.
        (Some("armhf"), "aarch64", "64", "armv7"),
        (None, "aarch64", "32", "armv7"),
        (None, "aarch64", "64", "aarch64"),
        (
            Some("armhf"),
            "armv6l",
            "32",
            "stop: 32-bit systems are not supported yet",
        ),
        (Some("i386"), "x86_64", "32", "stop: 32-bit systems are not"),
    ];
    for (dpkg, uname, bits, want) in cases {
        let sandbox = Sandbox::new("arch")?;
        match dpkg {
            Some(answer) => sandbox.file("dpkg", &format!("{answer}\n"))?,
            None => sandbox.stub("dpkg", "#!/bin/sh\nexit 1\n")?,
        }
        sandbox.file("uname", &format!("{uname}\n"))?;
        sandbox.file("getconf", &format!("{bits}\n"))?;
        let output = sandbox.run("detect_arch\necho \"$ARCH\"", &[])?;
        let got = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        } else {
            format!("stop: {}", String::from_utf8_lossy(&output.stderr))
        };
        let wanted = want.strip_prefix("stop: ").unwrap_or(want);
        assert!(
            got.contains(wanted) && got.starts_with("stop: ") == want.starts_with("stop: "),
            "{dpkg:?} {uname} {bits}: {got}"
        );
    }
    Ok(())
}

#[test]
fn a_32_bit_system_is_refused_when_the_release_has_no_32_bit_build() -> Result {
    let sandbox = Sandbox::new("armv7")?;
    let env = [("TALLY_RELEASE", "https://release.example/r")];
    let refusal = sandbox.stopped(
        "release=$TALLY_RELEASE\nARCH=armv7\nrequire_published_arch",
        &env,
    )?;
    assert!(
        refusal.contains("32-bit systems are not supported yet"),
        "{refusal}"
    );
    // Once the release publishes one, it is the build installed.
    sandbox.file("release/tally-feed-armv7-linux.sha256", "0\n")?;
    sandbox.ok(
        "release=$TALLY_RELEASE\nARCH=armv7\nrequire_published_arch",
        &env,
    )?;
    Ok(())
}

#[test]
fn an_install_waits_for_publishing_and_prints_the_station_page() -> Result {
    let sandbox = Sandbox::new("install")?;
    sandbox.release()?;
    sandbox.file(
        "journal",
        "tally-feed: receiver x\ntally-feed: reading 127.0.0.1:30005\ntally-feed: publishing to relay.example:10900 (version 1)\n",
    )?;
    let env = install_env(
        &sandbox,
        &[
            ("TALLY_LAT", "51.5"),
            ("TALLY_LON", "-0.1"),
            ("TALLY_ALT", "20"),
        ],
    );
    let output = sandbox.run(
        &format!("listening() {{ [[ $2 == 30005 ]]; }}\n{INSTALL}"),
        &borrowed(&env),
    )?;
    let err = String::from_utf8_lossy(&output.stderr).into_owned();
    let out = succeeded(output)?;
    assert!(out.contains("installed and publishing"), "{out}");
    assert!(
        out.contains(
            "https://tally.skycommons.org/feeders/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_8\n"
        ),
        "{out}"
    );
    // Exact to the relays alone, and only the public cell anywhere else, said in one line, once,
    // beside the location it found and before anything is installed; no flag for it.
    let said = format!("{err}{out}")
        .matches("Your exact location goes only to Tally relays, for MLAT. Nothing a data user reads contains it; public maps show only the ~6 km area.")
        .count();
    assert_eq!(said, 1, "{err}{out}");
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains(&format!(
            "TALLY_FEED_ARGS=\"--relay relay.example:10900={RELAY_KEY} --lat 51.5 --lon -0.1 --alt 66\""
        )),
        "{written}"
    );
    assert!(sandbox.exists("root/usr/local/bin/tally-feed"));
    Ok(())
}

#[test]
fn an_install_names_each_acars_router_output_it_finds_and_adds_none() -> Result {
    let sandbox = Sandbox::new("acars")?;
    sandbox.release()?;
    sandbox.file(
        "journal",
        "tally-feed: receiver x\ntally-feed: publishing to relay.example:10900 (version 1)\n",
    )?;
    let env = install_env(
        &sandbox,
        &[
            ("TALLY_LAT", "51.5"),
            ("TALLY_LON", "-0.1"),
            ("TALLY_ALT", "20"),
        ],
    );
    let out = sandbox.ok(
        &format!("listening() {{ [[ $2 == 30005 || $2 == 15555 || $2 == 15556 ]]; }}\n{INSTALL}"),
        &borrowed(&env),
    )?;
    // Publishing message text is the owner's choice: the run says the flag, and writes none.
    for port in [15555, 15556] {
        assert!(
            out.contains(&format!("add --acars 127.0.0.1:{port} to TALLY_FEED_EXTRA")),
            "{out}"
        );
    }
    assert!(!out.contains("15550"), "{out}");
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains(&format!(
            "TALLY_FEED_ARGS=\"--relay relay.example:10900={RELAY_KEY} --lat 51.5 --lon -0.1 --alt 66\""
        )),
        "{written}"
    );
    assert!(!written.contains("--acars"), "{written}");
    Ok(())
}

#[test]
fn a_feeder_that_never_publishes_is_not_called_installed() -> Result {
    let sandbox = Sandbox::new("silent")?;
    sandbox.release()?;
    sandbox.file("journal", "tally-feed: receiver x\n")?;
    let env = install_env(
        &sandbox,
        &[
            ("TALLY_LAT", "51.5"),
            ("TALLY_LON", "-0.1"),
            ("TALLY_ALT", "20"),
        ],
    );
    let output = sandbox.run(INSTALL, &borrowed(&env))?;
    let (out, err) = (
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(!output.status.success(), "{out}");
    assert!(!out.contains("installed and publishing"), "{out}");
    for needed in [
        "has not reached a relay",
        "the journal tail",
        "journalctl -u tally-feed -f",
    ] {
        assert!(err.contains(needed), "{needed:?}: {err}");
    }
    // A unit that did not stay up is called that.
    sandbox.file("inactive", "")?;
    let output = sandbox.run(INSTALL, &borrowed(&env))?;
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("did not start"), "{err}");
    Ok(())
}

#[test]
fn an_ultrafeeder_container_with_no_host_beast_gets_the_compose_route() -> Result {
    let sandbox = Sandbox::new("route")?;
    sandbox.release()?;
    sandbox.file(
        "docker-ps",
        "ultrafeeder ghcr.io/sdr-enthusiasts/docker-adsb-ultrafeeder:latest\n",
    )?;
    sandbox.file("docker-inspect", "LAT=47.6\nLONG=-122.3\nALT=120m\n")?;
    let env = install_env(&sandbox, &[]);
    let out = sandbox.ok(INSTALL, &borrowed(&env))?;
    for needed in [
        "Nothing was installed",
        "image: ghcr.io/sky-commons/tally-feed:0",
        "docker compose pull && docker compose up -d",
        "- BEASTHOST=ultrafeeder",
        "- LAT=47.6",
        "- LONG=-122.3",
        "- ALT_MSL=120m",
        "Your exact location goes only to Tally relays, for MLAT.",
    ] {
        assert!(out.contains(needed), "{needed:?}: {out}");
    }
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    assert!(!sandbox.exists("root/etc/default/tally-feed"));
    Ok(())
}

#[test]
fn uninstall_keeps_the_key_and_purge_deletes_it() -> Result {
    let sandbox = Sandbox::new("uninstall")?;
    for path in [
        "root/usr/local/bin/tally-feed",
        "root/etc/default/tally-feed",
        "root/etc/systemd/system/tally-feed.service",
        "root/etc/systemd/system/tally-feed-update.service",
        "root/etc/systemd/system/tally-feed-update.timer",
        "root/usr/local/lib/tally/update",
        "root/usr/local/lib/tally/installed",
        "root/etc/tally/key",
        "root/var/lib/private/tally-feed/relays",
    ] {
        sandbox.file(path, "")?;
    }
    let out = sandbox.ok("main --uninstall", &[])?;
    assert!(out.contains("kept"), "{out}");
    assert!(sandbox.exists("root/etc/tally/key"));
    for gone in [
        "root/usr/local/bin/tally-feed",
        "root/etc/default/tally-feed",
        "root/etc/systemd/system/tally-feed.service",
        "root/etc/systemd/system/tally-feed-update.service",
        "root/etc/systemd/system/tally-feed-update.timer",
        "root/usr/local/lib/tally",
        "root/var/lib/private/tally-feed",
    ] {
        assert!(!sandbox.exists(gone), "{gone} is still there");
    }
    let calls = sandbox.read("systemctl.log")?;
    for call in [
        "disable --now tally-feed.service",
        "disable --now tally-feed-update.timer",
        // Its Persistent= stamp under /var/lib/systemd/timers goes with it.
        "clean --what=state tally-feed-update.timer",
    ] {
        assert!(calls.contains(call), "{call}: {calls}");
    }

    // With no terminal to type delete on, the key goes only when TALLY_PURGE_KEY=yes says so.
    let refusal = sandbox.stopped("main --uninstall --purge", &[])?;
    assert!(
        refusal.contains("TALLY_PURGE_KEY=yes") && refusal.contains("Nothing was removed"),
        "{refusal}"
    );
    assert!(sandbox.exists("root/etc/tally/key"));
    let output = sandbox.run("main --uninstall --purge", &[("TALLY_PURGE_KEY", "yes")])?;
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{err}");
    assert!(err.contains("gone for good"), "{err}");
    assert!(!sandbox.exists("root/etc/tally/key"));
    assert!(!sandbox.exists("root/etc/tally"));

    let refusal = sandbox.stopped("main --uninstall --everything", &[])?;
    assert!(refusal.contains("usage"), "{refusal}");
    Ok(())
}

/// The journal of a feeder that reads its decoder and publishes.
const PUBLISHING: &str = "tally-feed: reading 127.0.0.1:30005\ntally-feed: publishing to relay.example:10900 (version 4)\n";

const LOCATION: &[(&str, &str)] = &[
    ("TALLY_LAT", "51.5"),
    ("TALLY_LON", "-0.1"),
    ("TALLY_ALT", "20"),
];

const TIMER_ENABLED: &str = "enabled-tally-feed-update.timer";

/// Installs the release `sandbox.release()` makes with the installer under test, with `extra` in
/// the environment and `args` to `main`; its stdout.
fn install(sandbox: &Sandbox, extra: &[(&str, &str)], args: &str) -> Result<String> {
    let mut env = LOCATION.to_vec();
    env.extend_from_slice(extra);
    let env = install_env(sandbox, &env);
    sandbox.ok(
        &INSTALL.replace("main", &format!("main {args}")),
        &borrowed(&env),
    )
}

#[test]
fn automatic_updates_are_on_by_default_and_the_install_says_how_to_turn_them_off() -> Result {
    let sandbox = Sandbox::new("auto-on")?;
    sandbox.release()?;
    sandbox.file("journal", PUBLISHING)?;
    let out = install(&sandbox, &[], "")?;
    assert!(sandbox.exists(TIMER_ENABLED), "{out}");
    for needed in [
        "Automatic updates are on (the default)",
        "sudo systemctl disable --now tally-feed-update.timer",
        "TALLY_AUTO_UPDATE=0",
    ] {
        assert!(out.contains(needed), "{needed:?}: {out}");
    }
    for installed in [
        "root/usr/local/lib/tally/update",
        "root/etc/systemd/system/tally-feed-update.service",
        "root/etc/systemd/system/tally-feed-update.timer",
    ] {
        assert!(sandbox.exists(installed), "{installed}");
    }
    let version = sandbox.ok("printf %s \"$VERSION\"", &[])?;
    assert_eq!(
        sandbox.read("root/usr/local/lib/tally/installed")?,
        format!("{version}\n")
    );
    // Every file it installed was checked against the release workflow's signature on its tag.
    let checked = sandbox.log("cosign.log");
    for name in [
        "tally-feed-x86_64-linux",
        "tally-feed.service",
        "tally-feed-update.service",
        "tally-feed-update.timer",
        "update.sh",
    ] {
        assert!(
            checked.contains(&format!("/{name} --bundle")),
            "{name}: {checked}"
        );
    }
    assert!(
        checked.contains(&format!(
            "--certificate-identity https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/{version} "
        )),
        "{checked}"
    );
    Ok(())
}

#[test]
fn the_owners_choice_about_automatic_updates_survives_a_rerun() -> Result {
    let sandbox = Sandbox::new("auto-choice")?;
    sandbox.release()?;
    sandbox.file("journal", PUBLISHING)?;
    let out = install(&sandbox, &[("TALLY_AUTO_UPDATE", "0")], "")?;
    assert!(!sandbox.exists(TIMER_ENABLED));
    assert!(
        out.contains("Automatic updates are off (you said so)"),
        "{out}"
    );
    assert!(
        out.contains("sudo systemctl enable --now tally-feed-update.timer"),
        "{out}"
    );
    // A rerun naming nothing keeps them off.
    let out = install(&sandbox, &[], "")?;
    assert!(!sandbox.exists(TIMER_ENABLED));
    assert!(
        out.contains("Automatic updates are off (the earlier install)"),
        "{out}"
    );
    // The owner turns them on with systemctl, and a rerun keeps that.
    sandbox.file(TIMER_ENABLED, "")?;
    let out = install(&sandbox, &[], "")?;
    assert!(sandbox.exists(TIMER_ENABLED));
    assert!(
        out.contains("Automatic updates are on (the earlier install)"),
        "{out}"
    );
    // And off again the same way, which a rerun keeps too.
    io(std::fs::remove_file(sandbox.dir.join(TIMER_ENABLED)))?;
    install(&sandbox, &[], "")?;
    assert!(!sandbox.exists(TIMER_ENABLED));

    // The flag says the same as TALLY_AUTO_UPDATE=0, and a word it does not know is refused.
    let fresh = Sandbox::new("auto-flag")?;
    fresh.release()?;
    fresh.file("journal", PUBLISHING)?;
    let out = install(&fresh, &[], "--no-auto-update")?;
    assert!(!fresh.exists(TIMER_ENABLED), "{out}");
    let env = install_env(&fresh, &[("TALLY_AUTO_UPDATE", "maybe")]);
    let refusal = fresh.stopped(INSTALL, &borrowed(&env))?;
    assert!(refusal.contains("TALLY_AUTO_UPDATE is 1 or 0"), "{refusal}");
    Ok(())
}

#[test]
fn a_release_file_whose_signature_fails_is_not_installed() -> Result {
    // Signed on another tag than the installer's: the workflow signed some other release.
    let sandbox = Sandbox::new("unsigned")?;
    sandbox.release()?;
    sandbox.file("journal", PUBLISHING)?;
    let env = install_env(&sandbox, LOCATION);
    let refusal = sandbox.stopped("sign_release v0.0.1\nmain", &borrowed(&env))?;
    assert!(
        refusal.contains("is not signed by the release workflow"),
        "{refusal}"
    );
    assert!(refusal.contains("nothing was installed"), "{refusal}");
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    assert!(!sandbox.exists("root/etc/default/tally-feed"));

    // Changed after it was signed, with a sha256 to match: the sha256 is no signature.
    let sandbox = Sandbox::new("tampered")?;
    sandbox.release()?;
    let refusal = sandbox.stopped(
        "sign_release \"$VERSION\"\necho 'echo owned' >> \"$T/release/tally-feed-x86_64-linux\"\nsha256sum \"$T/release/tally-feed-x86_64-linux\" > \"$T/release/tally-feed-x86_64-linux.sha256\"\nmain",
        &borrowed(&env),
    )?;
    assert!(
        refusal.contains("tally-feed-x86_64-linux is not signed"),
        "{refusal}"
    );
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    Ok(())
}

/// The fake feeder of a newer release: the same `init`, a different file.
const NEW_FEEDER: &str = "#!/bin/sh\n# the newer release\n[ \"$1\" = init ] && touch \"$3\" && echo 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+/8='\nexit 0\n";

/// A receiver installed by the installer under test (automatic updates as `extra` says), with the
/// owner's own flag, and a newer release `tag` published: the installer under test as that tag,
/// a new feeder, signed as `signed_on` (the tag, unless a test forges it). Returns the old feeder.
fn installed_then_released(
    sandbox: &Sandbox,
    extra: &[(&str, &str)],
    tag: &str,
    signed_on: &str,
) -> Result<String> {
    sandbox.release()?;
    sandbox.file("journal", PUBLISHING)?;
    install(sandbox, extra, "")?;
    let defaults = "root/etc/default/tally-feed";
    let written = sandbox.read(defaults)?.replace(
        "TALLY_FEED_EXTRA=\"\"",
        "TALLY_FEED_EXTRA=\"--clock beast\"",
    );
    sandbox.file(defaults, &written)?;
    let old = sandbox.read("root/usr/local/bin/tally-feed")?;

    let script = std::fs::read_to_string(installer()?).map_err(|error| error.to_string())?;
    let current = script
        .lines()
        .find(|line| line.starts_with("VERSION=\""))
        .ok_or("the installer names no VERSION")?
        .to_owned();
    sandbox.file(
        "release/install.sh",
        &script.replacen(&current, &format!("VERSION=\"{tag}\""), 1),
    )?;
    sandbox.file("release/tally-feed-x86_64-linux", NEW_FEEDER)?;
    sandbox.file(
        "release/seeds",
        &format!("relay.example:10900={RELAY_KEY} Example Operator\n"),
    )?;
    sandbox.ok(&format!("sign_release {signed_on}"), &[])?;
    sandbox.file("latest", tag)?;
    io(std::fs::remove_file(sandbox.dir.join("systemctl.log")))?;
    Ok(old)
}

/// The updater run as the timer runs it: its log (stdout) and whether it succeeded.
fn update(sandbox: &Sandbox) -> Result<(bool, String)> {
    let output = sandbox.update_with(
        &updater()?,
        "main",
        &[("TALLY_RELEASE", "https://release.example/new")],
    )?;
    Ok((
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    ))
}

#[test]
fn an_update_installs_a_newer_signed_release_and_keeps_the_owners_settings() -> Result {
    let sandbox = Sandbox::new("update")?;
    installed_then_released(&sandbox, &[], "v99.0.0", "v99.0.0")?;
    let (ok, log) = update(&sandbox)?;
    assert!(ok, "{log}");
    assert!(log.contains("to v99.0.0"), "{log}");
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, NEW_FEEDER);
    assert_eq!(
        sandbox.read("root/usr/local/lib/tally/installed")?,
        "v99.0.0\n"
    );
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains("TALLY_FEED_EXTRA=\"--clock beast\""),
        "{written}"
    );
    assert!(
        written.contains("--lat 51.5 --lon -0.1 --alt 66\""),
        "{written}"
    );
    assert!(sandbox.exists(TIMER_ENABLED));
    assert!(sandbox.exists("root/etc/tally/key"));
    // Run again, there is nothing newer.
    let (ok, log) = update(&sandbox)?;
    assert!(
        ok && log.contains("up to date: v99.0.0 is installed"),
        "{log}"
    );
    Ok(())
}

#[test]
fn an_update_whose_signature_fails_installs_nothing() -> Result {
    // Signed, but by a release run on another tag than the one it claims to be.
    let sandbox = Sandbox::new("update-forged")?;
    let old = installed_then_released(&sandbox, &[], "v99.0.0", "v98.0.0")?;
    let (ok, log) = update(&sandbox)?;
    assert!(!ok, "{log}");
    assert!(log.contains("REFUSED v99.0.0"), "{log}");
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, old);
    assert!(!sandbox.log("systemctl.log").contains("restart"));

    // Its install.sh changed after it was signed.
    let sandbox = Sandbox::new("update-tampered")?;
    let old = installed_then_released(&sandbox, &[], "v99.0.0", "v99.0.0")?;
    let tampered = sandbox.read("release/install.sh")? + "\necho owned\n";
    sandbox.file("release/install.sh", &tampered)?;
    let (ok, log) = update(&sandbox)?;
    assert!(!ok && log.contains("REFUSED v99.0.0"), "{log}");
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, old);
    assert!(!sandbox.log("systemctl.log").contains("restart"));
    Ok(())
}

#[test]
fn an_update_never_installs_an_older_release_or_the_same_one() -> Result {
    let sandbox = Sandbox::new("update-older")?;
    let old = installed_then_released(&sandbox, &[], "v0.0.1", "v0.0.1")?;
    let (ok, log) = update(&sandbox)?;
    assert!(ok && log.contains("an update never goes back"), "{log}");
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, old);
    assert!(
        !sandbox.log("curl.log").contains("/download/"),
        "{}",
        sandbox.log("curl.log")
    );

    let version = sandbox.ok("printf %s \"$VERSION\"", &[])?;
    sandbox.file("latest", &version)?;
    let (ok, log) = update(&sandbox)?;
    assert!(ok && log.contains("up to date"), "{log}");
    assert!(!sandbox.log("curl.log").contains("/download/"));
    Ok(())
}

#[test]
fn an_opted_out_receiver_is_not_updated() -> Result {
    let sandbox = Sandbox::new("update-off")?;
    let old = installed_then_released(
        &sandbox,
        &[("TALLY_AUTO_UPDATE", "0")],
        "v99.0.0",
        "v99.0.0",
    )?;
    io(std::fs::remove_file(sandbox.dir.join("curl.log")))?;
    let (ok, log) = update(&sandbox)?;
    assert!(ok && log.contains("automatic updates are off"), "{log}");
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, old);
    // It did not even ask for the latest release.
    assert_eq!(sandbox.log("curl.log"), "");
    Ok(())
}

#[test]
fn a_release_that_does_not_start_is_rolled_back() -> Result {
    let sandbox = Sandbox::new("update-rollback")?;
    let old = installed_then_released(&sandbox, &[], "v99.0.0", "v99.0.0")?;
    let defaults = sandbox.read("root/etc/default/tally-feed")?;
    let version = sandbox.read("root/usr/local/lib/tally/installed")?;
    // The new feeder starts but never publishes.
    sandbox.file("journal", "tally-feed: receiver x\n")?;
    let (ok, log) = update(&sandbox)?;
    assert!(!ok, "{log}");
    assert!(
        log.contains("ROLLED BACK v99.0.0: its install.sh failed"),
        "{log}"
    );
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, old);
    assert_eq!(sandbox.read("root/etc/default/tally-feed")?, defaults);
    assert_eq!(sandbox.read("root/usr/local/lib/tally/installed")?, version);
    assert!(sandbox.exists("root/etc/tally/key"));
    // The old feeder was restarted after the new one was.
    let calls = sandbox.log("systemctl.log");
    assert!(
        calls.trim_end().ends_with("restart tally-feed.service"),
        "{calls}"
    );

    // A feeder that is not running once its installer is done is rolled back the same way.
    let sandbox = Sandbox::new("update-dead")?;
    let old = installed_then_released(&sandbox, &[], "v99.0.0", "v99.0.0")?;
    sandbox.stub(
        "systemctl",
        &sandbox::STUBS
            .iter()
            .find(|(name, _)| *name == "systemctl")
            .map(|(_, script)| script.replace(
                "is-active) [ ! -f \"$TEST_DIR/inactive\" ] ;;",
                "is-active) [ ! -f \"$TEST_DIR/root/usr/local/bin/tally-feed\" ] || ! grep -q newer \"$TEST_DIR/root/usr/local/bin/tally-feed\" || [ -n \"$IN_INSTALLER\" ] ;;",
            ))
            .ok_or("no systemctl stub")?,
    )?;
    let output = sandbox.update_with(
        &updater()?,
        "run_installer() { IN_INSTALLER=1 TALLY_INSTALLER=\"$1\" bash -c \"$TALLY_PRELUDE\"$'\\n''main --upgrade'; }\nmain",
        &[("TALLY_RELEASE", "https://release.example/new")],
    )?;
    let log = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "{log}");
    assert!(log.contains("tally-feed is not running after it"), "{log}");
    assert_eq!(sandbox.read("root/usr/local/bin/tally-feed")?, old);
    Ok(())
}

// Locating from an address (RFC-0204). The address of a public landmark (San Francisco's City
// Hall), the answers each service gave for it on 2026-11-03, and the Eiffel Tower for an address
// outside the US.

const ADDRESS: &str = "1 Dr Carlton B Goodlett Pl, San Francisco, CA 94102";
const CENSUS: &str = r#"{"result":{"input":{"address":{"address":"1 Dr Carlton B Goodlett Pl, San Francisco, CA 94102"}},"addressMatches":[{"coordinates":{"x":-122.41831039539,"y":37.778536095745},"matchedAddress":"1 DR CARLTON P GOODLETT PL, SAN FRANCISCO, CA, 94102"}]}}"#;
const CENSUS_NONE: &str = r#"{"result":{"input":{"address":{"address":"x"}},"addressMatches":[]}}"#;
const NOMINATIM: &str = r#"[{"place_id":319846272,"licence":"Data © OpenStreetMap contributors, ODbL 1.0. http://osm.org/copyright","lat":"37.7792929","lon":"-122.4192601","display_name":"San Francisco City Hall, 1, Dr. Carlton B. Goodlett Place","address":{"city":"San Francisco","country":"United States","country_code":"us"}}]"#;
const NOMINATIM_PARIS: &str = r#"[{"lat":"48.8582599","lon":"2.2945006","display_name":"Tour Eiffel","address":{"country":"France","country_code":"fr"}}]"#;
const EPQS: &str = r#"{"location":{"x":-122.4183,"y":37.7785,"spatialReference":{"wkid":4326}},"locationId":0,"value":"18.678731918","rasterId":72150,"resolution":1}"#;
const OPEN_METEO: &str = r#"{"elevation":[36.0]}"#;

/// A sandbox with the services answering `answers` (`service/NAME`), the release made with its
/// geoid grid beside it, and the stub `ask` answering the lines of `typed` in turn (logging each
/// question in `asked.log`).
fn locating(name: &str, answers: &[(&str, &str)], typed: &[&str]) -> Result<Sandbox> {
    let sandbox = Sandbox::new(name)?;
    sandbox.release()?;
    sandbox.file(
        "journal",
        "tally-feed: reading 127.0.0.1:30005\ntally-feed: publishing to relay.example:10900 (version 4)\n",
    )?;
    for (service, answer) in answers {
        sandbox.file(&format!("service/{service}"), answer)?;
    }
    sandbox.file("typed", &format!("{}\n", typed.join("\n")))?;
    Ok(sandbox)
}

/// `body` after a terminal is made up: `have_tty` true, and `ask` answering `typed` in turn.
const ON_A_TERMINAL: &str = r#"
have_tty() { true; }
ask() {
  local n
  n=$(($(cat "$T/asked" 2>/dev/null || echo 0) + 1))
  echo "$n" > "$T/asked"
  printf '%s\n' "$1" >> "$T/asked.log"
  sed -n "${n}p" "$T/typed"
}
"#;

/// Every file the install wrote or a stub logged, but what the location services were asked
/// (`services.log`): none of them may hold the address.
fn holds_no_address(sandbox: &Sandbox, output: &str) -> Result {
    let words = ["Carlton", "Goodlett", "Carlton%20B"];
    let mut files = vec![output.to_owned()];
    for name in [
        "curl-args.log",
        "curl.log",
        "systemctl.log",
        "cosign.log",
        "root/etc/default/tally-feed",
    ] {
        files.push(sandbox.log(name));
    }
    for (text, word) in files
        .iter()
        .flat_map(|text| words.iter().map(move |word| (text, word)))
    {
        if text.contains(word) {
            return Err(format!("{word:?} was kept or shown: {text}"));
        }
    }
    Ok(())
}

/// TALLY_ADDRESS, no terminal: the Census geocoder places it (OpenStreetMap is its check, 119 m
/// off, which is said), USGS gives the ground, the release's geoid grid turns ground and antenna
/// into height above the ellipsoid, and only the coordinates are kept. The address went to the
/// geocoders and nowhere else: not on curl's command line, not to the elevation service, not into
/// any file or anything printed. The geoid grid's signature is checked with the release's.
#[test]
fn an_address_is_located_and_only_its_coordinates_are_kept() -> Result {
    let sandbox = locating(
        "locate-us",
        &[("census", CENSUS), ("nominatim", NOMINATIM), ("epqs", EPQS)],
        &[],
    )?;
    let env = install_env(
        &sandbox,
        &[("TALLY_ADDRESS", ADDRESS), ("TALLY_ANTENNA", "roof")],
    );
    let output = sandbox.ok(INSTALL, &borrowed(&env))?;
    let written = sandbox.read("root/etc/default/tally-feed")?;
    // 18.7 m of ground, 8 m of roof, and the geoid's -32.5 m there.
    assert!(
        written.contains("--lat 37.778536 --lon -122.418310 --alt -6\""),
        "{written}"
    );
    for said in [
        "never to Tally",
        "place it 119 m apart",
        "https://www.openstreetmap.org/?mlat=37.778536&mlon=-122.418310",
        "OpenStreetMap contributors",
        "USGS 3DEP",
        "8 m above it (TALLY_ANTENNA)",
    ] {
        assert!(output.contains(said), "it did not say {said:?}: {output}");
    }
    let asked = sandbox.log("services.log");
    let geocoders: Vec<&str> = asked
        .lines()
        .filter(|url| url.contains("Carlton%20B%20Goodlett"))
        .collect();
    assert_eq!(geocoders.len(), 2, "{asked}");
    assert!(geocoders[0].starts_with("https://geocoding.geo.census.gov/"));
    assert!(geocoders[1].starts_with("https://nominatim.openstreetmap.org/"));
    assert!(
        asked.contains("https://epqs.nationalmap.gov/v1/json?x=-122.418310&y=37.778536"),
        "{asked}"
    );
    holds_no_address(&sandbox, &output)?;
    assert!(
        sandbox.log("cosign.log").contains("geoid.txt.gz"),
        "the geoid grid's signature was not checked"
    );
    Ok(())
}

/// An address outside the US: the Census geocoder matches nothing, OpenStreetMap places it, and
/// the ground comes from Open-Meteo, never from USGS.
#[test]
fn an_address_outside_the_us_is_placed_by_openstreetmap_and_open_meteo() -> Result {
    let sandbox = locating(
        "locate-fr",
        &[
            ("census", CENSUS_NONE),
            ("nominatim", NOMINATIM_PARIS),
            ("open-meteo", OPEN_METEO),
        ],
        &[],
    )?;
    let env = install_env(
        &sandbox,
        &[
            (
                "TALLY_ADDRESS",
                "Champ de Mars, 5 Av. Anatole France, Paris",
            ),
            ("TALLY_ANTENNA", "5"),
        ],
    );
    let output = sandbox.ok(INSTALL, &borrowed(&env))?;
    let written = sandbox.read("root/etc/default/tally-feed")?;
    // 36 m of ground, 5 m of antenna, and the geoid's 44.6 m there.
    assert!(
        written.contains("--lat 48.858260 --lon 2.294501 --alt 86\""),
        "{written}"
    );
    assert!(output.contains("Copernicus DEM, by Open-Meteo"), "{output}");
    assert!(!sandbox.log("services.log").contains("epqs"));
    Ok(())
}

/// A lookup that fails with no terminal stops, saying why and naming the coordinates to pass
/// instead, with nothing installed; and an address given beside coordinates is refused.
#[test]
fn a_failed_lookup_stops_with_nothing_installed() -> Result {
    let sandbox = locating("locate-fails", &[("census", CENSUS_NONE)], &[])?;
    let env = install_env(&sandbox, &[("TALLY_ADDRESS", ADDRESS)]);
    let refusal = sandbox.stopped(INSTALL, &borrowed(&env))?;
    for said in [
        "neither the US Census geocoder nor OpenStreetMap found that address",
        "TALLY_LAT=",
        "Nothing was installed",
    ] {
        assert!(refusal.contains(said), "{refusal}");
    }
    assert!(!sandbox.exists("root/etc/default/tally-feed"));
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    holds_no_address(&sandbox, &refusal)?;
    let both = install_env(
        &sandbox,
        &[
            ("TALLY_ADDRESS", ADDRESS),
            ("TALLY_LAT", "37.7"),
            ("TALLY_LON", "-122.4"),
        ],
    );
    let refusal = sandbox.stopped(INSTALL, &borrowed(&both))?;
    assert!(refusal.contains("give one"), "{refusal}");
    Ok(())
}

/// On a terminal with no location found anywhere, the address is asked for first, the place
/// shown and confirmed, the antenna's height asked as one question, and readsb, which has no
/// location of its own, set too once the owner says yes, its old file kept.
#[test]
fn on_a_terminal_the_address_is_asked_and_readsb_offered_the_place() -> Result {
    let sandbox = locating(
        "locate-tty",
        &[("census", CENSUS), ("nominatim", NOMINATIM), ("epqs", EPQS)],
        &[ADDRESS, "y", "2", "y"],
    )?;
    let readsb = "# readsb configuration\nRECEIVER_OPTIONS=\"--net-only\"\nDECODER_OPTIONS=\"--max-range 500\"\nNET_OPTIONS=\"--net\"\n";
    sandbox.file("root/etc/default/readsb", readsb)?;
    let env = install_env(&sandbox, &[]);
    let output = sandbox.ok(&format!("{ON_A_TERMINAL}\n{INSTALL}"), &borrowed(&env))?;
    let asked = sandbox.log("asked.log");
    let questions: Vec<&str> = asked.lines().collect();
    assert_eq!(questions.len(), 4, "{asked}");
    assert!(questions[0].contains("street address"), "{asked}");
    assert!(
        questions[1].contains("Is that the antenna's place?"),
        "{asked}"
    );
    assert!(questions[2].contains("How high is the antenna?"), "{asked}");
    assert!(questions[3].contains("readsb has no location"), "{asked}");
    let written = sandbox.read("root/etc/default/tally-feed")?;
    // Upstairs: 5 m.
    assert!(
        written.contains("--lat 37.778536 --lon -122.418310 --alt -9\""),
        "{written}"
    );
    let readsb_now = sandbox.read("root/etc/default/readsb")?;
    assert!(
        readsb_now
            .contains("DECODER_OPTIONS=\"--max-range 500 --lat 37.778536 --lon -122.418310\""),
        "{readsb_now}"
    );
    let kept: Vec<_> = io(std::fs::read_dir(sandbox.dir.join("root/etc/default")))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("readsb.tally-backup.")
        })
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(io(std::fs::read_to_string(kept[0].path()))?, readsb);
    holds_no_address(&sandbox, &output)
}

/// An owner who says the place shown is not right is asked for the coordinates instead, and
/// readsb, which has its own location, is never offered or touched.
#[test]
fn a_place_the_owner_rejects_falls_back_to_the_coordinates() -> Result {
    let sandbox = locating(
        "locate-rejected",
        &[("census", CENSUS), ("nominatim", NOMINATIM), ("epqs", EPQS)],
        &["n", "37.7", "-122.4", "30"],
    )?;
    let readsb = "DECODER_OPTIONS=\"--lat 37.7 --lon -122.4\"\n";
    sandbox.file("root/etc/default/readsb", readsb)?;
    let env = install_env(&sandbox, &[("TALLY_ADDRESS", ADDRESS)]);
    sandbox.ok(&format!("{ON_A_TERMINAL}\n{INSTALL}"), &borrowed(&env))?;
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains("--lat 37.7 --lon -122.4 --alt -3\""),
        "{written}"
    );
    assert_eq!(sandbox.read("root/etc/default/readsb")?, readsb);
    assert!(!sandbox.log("asked.log").contains("readsb"));
    Ok(())
}

/// An automatic update never locates, whatever the environment says: it keeps the location the
/// install has and asks no service.
#[test]
fn an_upgrade_never_locates() -> Result {
    let sandbox = locating(
        "locate-upgrade",
        &[("census", CENSUS), ("nominatim", NOMINATIM), ("epqs", EPQS)],
        &[],
    )?;
    let first = install_env(
        &sandbox,
        &[
            ("TALLY_LAT", "51.5"),
            ("TALLY_LON", "-0.1"),
            ("TALLY_ALT", "20"),
        ],
    );
    sandbox.ok(INSTALL, &borrowed(&first))?;
    let again = install_env(&sandbox, &[("TALLY_ADDRESS", ADDRESS)]);
    sandbox.ok(
        &INSTALL.replace("main", "main --upgrade"),
        &borrowed(&again),
    )?;
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains("--lat 51.5 --lon -0.1 --alt 66\""),
        "{written}"
    );
    assert_eq!(sandbox.log("services.log"), "");
    Ok(())
}

/// The geoid grid the release ships (EGM2008, packaging/geoid) against NGS's GEOID18 at points
/// across the US (the NGS API, `model=14`, 2026-11-03): within 2 m everywhere, GEOID18's datum
/// (NAD83, NAVD88) included, and within 0.6 m in the West.
#[test]
fn the_geoid_grid_agrees_with_geoid18() -> Result {
    let sandbox = Sandbox::new("geoid")?;
    let geoid = sandbox::path_of("TALLY_GEOID")?;
    for (lat, lon, geoid18, within) in [
        (37.77, -122.42, -32.541, 0.6),
        (33.94, -118.40, -35.943, 0.6),
        (40.76, -111.89, -16.825, 0.6),
        (39.74, -104.99, -17.113, 0.6),
        (41.88, -87.63, -33.597, 0.6),
        (47.61, -122.33, -23.695, 2.0),
        (25.76, -80.19, -25.541, 2.0),
    ] {
        let n: f64 = sandbox
            .ok(&format!("geoid_of {lat} {lon} < {}", geoid.display()), &[])?
            .trim()
            .parse()
            .map_err(|error| format!("{error}"))?;
        assert!(
            (n - geoid18).abs() <= within,
            "{lat}, {lon}: the grid says {n} m, GEOID18 {geoid18} m"
        );
    }
    Ok(())
}

// The altitude's datum. Every altitude an owner types or a receiver's setup holds is above sea
// level (adsb.im's FEEDER_ALT_M is "Altitude above mean sealevel"); the feeder's --alt is above the
// WGS84 ellipsoid. The installer converts with the release's geoid grid, and keeps what an earlier
// run wrote exactly.

const ADSBIM: &str = "FEEDER_LAT=51.4775\nFEEDER_LONG=-0.4614\nFEEDER_ALT_M=25\n";

/// As `install`, with only `extra` of the location variables.
fn install_naming(sandbox: &Sandbox, extra: &[(&str, &str)], args: &str) -> Result<String> {
    let env = install_env(sandbox, extra);
    sandbox.ok(
        &INSTALL.replace("main", &format!("main {args}")),
        &borrowed(&env),
    )
}

/// adsb.im's 25 m above sea level at Heathrow is 25 m plus the geoid's 46.68 m there above the
/// ellipsoid: the block holds 72 and says how it was found.
#[test]
fn a_sea_level_altitude_is_turned_into_height_above_the_ellipsoid() -> Result {
    let sandbox = Sandbox::new("datum")?;
    sandbox.release()?;
    sandbox.file("journal", PUBLISHING)?;
    sandbox.file("root/opt/adsb/config/.env", ADSBIM)?;
    let out = install_naming(&sandbox, &[], "")?;
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains("--lat 51.4775 --lon -0.4614 --alt 72\""),
        "{written}"
    );
    for said in [&written, &out] {
        assert!(
            said.contains("25 m above sea level, and the geoid there, 46.68 m (EGM2008): metres above the WGS84 ellipsoid"),
            "{said}"
        );
    }
    // The grid it read is checked against its signature with the rest of the release.
    assert!(out.contains("geoid.txt.gz"), "{out}");
    Ok(())
}

/// A rerun, and an automatic update, keep the altitude the earlier run wrote, exactly, while the
/// location is the same: a sea-level source read again does not move it, and the block goes on
/// saying where it came from. What the owner names (TALLY_ALT), or a new location, replaces it.
#[test]
fn a_rerun_keeps_the_saved_altitude_until_the_owner_names_another() -> Result {
    let sandbox = Sandbox::new("keep-alt")?;
    sandbox.release()?;
    sandbox.file("journal", PUBLISHING)?;
    let defaults = "root/etc/default/tally-feed";
    // What v0.7.4 wrote from adsb.im: its sea-level 25, as it was, taken as above the ellipsoid.
    sandbox.file(
        defaults,
        &format!(
            "# BEGIN install.sh: rewritten on every run of install.sh\n# Location from /opt/adsb/config/.env (FEEDER_LAT, FEEDER_LONG, FEEDER_ALT_M), altitude from /opt/adsb/config/.env (FEEDER_LAT, FEEDER_LONG, FEEDER_ALT_M).\nTALLY_FEED_ARGS=\"--relay relay.example:10900={RELAY_KEY} --lat 51.4775 --lon -0.4614 --alt 25\"\n# END install.sh\nTALLY_FEED_EXTRA=\"\"\n"
        ),
    )?;
    sandbox.file("root/opt/adsb/config/.env", ADSBIM)?;
    for args in ["", "--upgrade"] {
        let out = install_naming(&sandbox, &[], args)?;
        let written = sandbox.read(defaults)?;
        assert!(
            written.contains("--lat 51.4775 --lon -0.4614 --alt 25\""),
            "{args}: {written}"
        );
        assert!(
            written.contains("altitude from the earlier install, which had it from /opt/adsb/config/.env (FEEDER_LAT, FEEDER_LONG, FEEDER_ALT_M)."),
            "{args}: {written}"
        );
        // It says how to have it converted, and converts nothing by itself.
        assert!(
            out.contains("run this again with TALLY_ALT=25"),
            "{args}: {out}"
        );
    }
    // The owner names it: converted.
    install_naming(&sandbox, &[("TALLY_ALT", "25")], "")?;
    let written = sandbox.read(defaults)?;
    assert!(written.contains("--alt 72\""), "{written}");
    // Converted once, it is kept from then on, and said to be above the ellipsoid already.
    let out = install_naming(&sandbox, &[], "--upgrade")?;
    let written = sandbox.read(defaults)?;
    assert!(written.contains("--alt 72\""), "{written}");
    assert!(!out.contains("run this again with TALLY_ALT"), "{out}");
    assert!(
        written.contains("which had it from TALLY_ALT, 25 m above sea level, and the geoid there, 46.68 m (EGM2008): metres above the WGS84 ellipsoid."),
        "{written}"
    );
    // A new place is a new altitude: adsb.im's, converted there.
    sandbox.file(
        "root/opt/adsb/config/.env",
        "FEEDER_LAT=37.778536\nFEEDER_LONG=-122.41831\nFEEDER_ALT_M=16\n",
    )?;
    install_naming(&sandbox, &[], "")?;
    let written = sandbox.read(defaults)?;
    assert!(
        written.contains("--lat 37.778536 --lon -122.41831 --alt -17\""),
        "{written}"
    );
    Ok(())
}

/// Every message that asks for an altitude asks for the height above sea level.
#[test]
fn the_altitude_asked_for_is_above_sea_level() -> Result {
    let sandbox = Sandbox::new("ask-msl")?;
    let env = [("TALLY_LAT", "51.5"), ("TALLY_LON", "-0.1")];
    let refusal = sandbox.stopped("discover_location ask", &env)?;
    assert!(
        refusal.contains("TALLY_ALT=25") && refusal.contains("height above sea level"),
        "{refusal}"
    );
    let asked = sandbox.ok(
        "have_tty() { :; }\nask() { echo \"$1\" >> \"$T/asked.log\"; echo 20; }\ndiscover_location ask\necho \"$alt|$alt_datum\"",
        &env,
    )?;
    assert!(asked.ends_with("20|sea\n"), "{asked}");
    assert!(
        sandbox
            .log("asked.log")
            .contains("Antenna altitude above sea level"),
        "{}",
        sandbox.log("asked.log")
    );
    Ok(())
}

/// A feeder that keeps crashing (Restart=always counts it active between its restarts) is called
/// that, at once, with its error; LoadCredential's failure under systemd in a container gets a
/// pointer to the container image. The key and the station page are printed all the same, and
/// only this run's log is shown.
#[test]
fn a_crashing_feeder_is_said_to_crash_with_its_error() -> Result {
    let sandbox = Sandbox::new("crash")?;
    sandbox.release()?;
    sandbox.file(
        "journal",
        "tally-feed: /run/credentials/tally-feed.service/key: Permission denied (os error 13)\n",
    )?;
    sandbox.file("show-NRestarts", "2\n")?;
    sandbox.file("show-SubState", "auto-restart\n")?;
    sandbox.file("show-ExecMainStatus", "1\n")?;
    let env = install_env(&sandbox, LOCATION);
    let output = sandbox.run(INSTALL, &borrowed(&env))?;
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{err}");
    for needed in [
        "tally-feed keeps crashing: it exited with status 1",
        "  tally-feed: /run/credentials/tally-feed.service/key: Permission denied (os error 13)",
        "inside a container",
        "#run-it-as-a-container",
        PUBLIC,
        "https://tally.skycommons.org/feeders/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_8",
    ] {
        assert!(err.contains(needed), "{needed:?}: {err}");
    }
    assert!(!err.contains("has not reached a relay"), "{err}");
    let journal = sandbox.log("journalctl.log");
    assert!(
        journal
            .lines()
            .all(|call| call.contains("--since @") || call.contains("_SYSTEMD_INVOCATION_ID=")),
        "{journal}"
    );
    Ok(())
}

/// A feeder that runs but reaches no relay is installed: its key and station page are printed,
/// and readsb's location, which the owner said yes to, is set all the same.
#[test]
fn a_feeder_reaching_no_relay_still_gets_its_key_page_and_readsb_location() -> Result {
    let sandbox = locating(
        "locate-unreached",
        &[("census", CENSUS), ("nominatim", NOMINATIM), ("epqs", EPQS)],
        &[ADDRESS, "y", "2", "y"],
    )?;
    sandbox.file(
        "journal",
        "tally-feed: reading 127.0.0.1:30005\ntally-feed: could not reach relay relay.example:10900: Connection refused (os error 111).\n",
    )?;
    let readsb = "DECODER_OPTIONS=\"--max-range 500\"\n";
    sandbox.file("root/etc/default/readsb", readsb)?;
    let env = install_env(&sandbox, &[]);
    let output = sandbox.run(&format!("{ON_A_TERMINAL}\n{INSTALL}"), &borrowed(&env))?;
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{err}");
    for needed in [
        "has not reached a relay",
        PUBLIC,
        "https://tally.skycommons.org/feeders/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_8",
    ] {
        assert!(err.contains(needed), "{needed:?}: {err}");
    }
    let readsb_now = sandbox.read("root/etc/default/readsb")?;
    assert!(
        readsb_now
            .contains("DECODER_OPTIONS=\"--max-range 500 --lat 37.778536 --lon -122.418310\""),
        "{readsb_now}"
    );
    Ok(())
}
