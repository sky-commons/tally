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

use sandbox::{INSTALL, RELAY_KEY, Result, Sandbox, borrowed, install_env, installer, io, updater};

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
        written.contains("--lat 48.25 --lon 11.5 --alt 500\""),
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
        written.contains("--lat 48.25 --lon 11.5 --alt 500\""),
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
    let out = sandbox.ok(
        &format!("listening() {{ [[ $2 == 30005 ]]; }}\n{INSTALL}"),
        &borrowed(&env),
    )?;
    assert!(out.contains("installed and publishing"), "{out}");
    assert!(
        out.contains(
            "https://tally.flightlines.ai/en/station/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-_8/"
        ),
        "{out}"
    );
    // Exact to the relays alone, and only the public cell anywhere else, said in one line; no
    // flag for it.
    assert!(
        out.contains("Your exact location goes only to Tally relays, for MLAT. Nothing a data user reads contains it; public maps show only the ~5 km area."),
        "{out}"
    );
    let written = sandbox.read("root/etc/default/tally-feed")?;
    assert!(
        written.contains(&format!(
            "TALLY_FEED_ARGS=\"--relay relay.example:10900={RELAY_KEY} --lat 51.5 --lon -0.1 --alt 20\""
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
            "TALLY_FEED_ARGS=\"--relay relay.example:10900={RELAY_KEY} --lat 51.5 --lon -0.1 --alt 20\""
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
        "- BEASTHOST=ultrafeeder",
        "- LAT=47.6",
        "- LONG=-122.3",
        "- ALT=120m",
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
    ] {
        assert!(calls.contains(call), "{call}: {calls}");
    }

    let output = sandbox.run("main --uninstall --purge", &[])?;
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
        written.contains("--lat 51.5 --lon -0.1 --alt 20\""),
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
