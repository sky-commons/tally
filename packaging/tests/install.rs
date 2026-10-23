//! `install.sh`, run with no network and no root. The first two tests run it whole as an owner
//! would before a release pipeline exists (RFC-0180 phase 1): nothing writes the release's address
//! into the script or publishes a seed list beside it, so the documented install stops, saying how
//! to go on, before it asks for root and with nothing installed.
//!
//! The rest source the script (it runs `main` only when run, not sourced) into a sandbox: every
//! path it reads or writes moved under a temporary directory, the commands it calls (`curl`,
//! `systemctl`, `journalctl`, `docker`, `dpkg`, `uname`, `getconf`, `chown`) stubbed on `PATH`,
//! and no terminal. Each test is one behaviour: a rerun's location winning over the last one's and
//! keeping the owner's own flags, each location source, the altitude it will not guess, the build
//! the userland (not the kernel) runs, the container route, the wait for "publishing", and
//! uninstalling with and without the key.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type Result<T = ()> = std::result::Result<T, String>;

fn installer() -> Result<PathBuf> {
    let path = std::env::var_os("TALLY_INSTALLER")
        .map(PathBuf::from)
        .ok_or_else(|| "TALLY_INSTALLER names install.sh (set by the build)".to_owned())?;
    std::fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))
}

fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

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

/// A relay key: 32 bytes of base64.
const RELAY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// The receiver's public key the fake `tally-feed init` prints, with both of the characters
/// base64url replaces.
const PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+/8=";

/// The sourced installer's paths and the parts that touch the machine, moved into `$T`.
const PRELUDE: &str = r#"
set -euo pipefail
source "$TALLY_INSTALLER"
T="$TEST_DIR"
R="$T/root"
BIN="$R/usr/local/bin/tally-feed"
KEY="$R/etc/tally/key"
DEFAULTS="$R/etc/default/tally-feed"
UNIT="$R/etc/systemd/system/tally-feed.service"
STATE="$R/var/lib/tally-feed"
STATE_PRIVATE="$R/var/lib/private/tally-feed"
ADSBIM_ENVS=("$R/opt/adsb/config/.env")
READSB_DEFAULTS="$R/etc/default/readsb"
PIAWARE_ENV="$R/var/cache/piaware/location.env"
DUMP1090_DEFAULTS="$R/etc/default/dump1090-fa"
FEED_CLIENT_DEFAULTS=("$R/etc/default/adsbexchange" "$R/etc/default/adsbfi")
WAIT_SECONDS=1
LOCK_RETRY_SECONDS=0
mkdir -p "$R/usr/local/bin" "$R/etc/default" "$R/etc/systemd/system" "$T/work"
work="$T/work"
require_root() { :; }
have_tty() { false; }
readsb_arguments() { :; }
listening() { false; }
"#;

/// The stubs every sandbox has: no docker container, an amd64 Debian, systemd 247 whose service
/// is always active, a journal (`$T/journal`) for the service's start, and a `curl` serving the
/// files of `$T/release`.
const STUBS: &[(&str, &str)] = &[
    (
        "docker",
        "#!/bin/sh\n[ -f \"$TEST_DIR/docker-$1\" ] && cat \"$TEST_DIR/docker-$1\"\nexit 0\n",
    ),
    (
        "dpkg",
        "#!/bin/sh\ncat \"$TEST_DIR/dpkg\" 2>/dev/null || echo amd64\n",
    ),
    (
        "uname",
        "#!/bin/sh\ncat \"$TEST_DIR/uname\" 2>/dev/null || echo x86_64\n",
    ),
    (
        "getconf",
        "#!/bin/sh\ncat \"$TEST_DIR/getconf\" 2>/dev/null || echo 64\n",
    ),
    ("chown", "#!/bin/sh\nexit 0\n"),
    // Debian's package database: what `$TEST_DIR/packages` names is installed, nothing else.
    (
        "dpkg-query",
        "#!/bin/sh\nfor last; do :; done\ngrep -qx \"$last\" \"$TEST_DIR/packages\" 2>/dev/null && echo 'install ok installed'\nexit 0\n",
    ),
    // apt-get, logged; failing when `$TEST_DIR/apt-fails` is there, an install failing when
    // `$TEST_DIR/install-fails` is, and an update failing as apt 2.8 does on the lists' lock
    // another apt holds as many times as `$TEST_DIR/lists-locked` says.
    (
        "apt-get",
        "#!/bin/sh\necho \"$*\" >> \"$TEST_DIR/apt.log\"\n[ ! -f \"$TEST_DIR/apt-fails\" ] || exit 100\ncase \"$*\" in\n  *install*) [ ! -f \"$TEST_DIR/install-fails\" ] || exit 100 ;;\n  update)\n    locked=\"$(cat \"$TEST_DIR/lists-locked\" 2>/dev/null || echo 0)\"\n    if [ \"$locked\" -gt 0 ]; then\n      echo $((locked - 1)) > \"$TEST_DIR/lists-locked\"\n      echo 'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)' >&2\n      exit 100\n    fi ;;\nesac\n",
    ),
    // systemd: the feeder's unit active unless `$TEST_DIR/inactive` is there, and of every
    // other unit only those `$TEST_DIR/active` names (`is-active` is true when any asked is).
    (
        "systemctl",
        "#!/bin/sh\necho \"$*\" >> \"$TEST_DIR/systemctl.log\"\ncase \"$1\" in\n  --version) echo 'systemd 247 (247.3-7+deb11u4)' ;;\n  show) echo 0123456789abcdef ;;\n  is-active)\n    shift\n    [ \"$1\" = --quiet ] && shift\n    for unit; do\n      case \"$unit\" in\n        tally-feed*) [ ! -f \"$TEST_DIR/inactive\" ] && exit 0 ;;\n        *) grep -qx \"$unit\" \"$TEST_DIR/active\" 2>/dev/null && exit 0 ;;\n      esac\n    done\n    exit 1 ;;\nesac\n",
    ),
    (
        "journalctl",
        "#!/bin/sh\ncase \"$*\" in\n  *_SYSTEMD_INVOCATION_ID=*) cat \"$TEST_DIR/journal\" 2>/dev/null ;;\n  *) echo 'the journal tail' ;;\nesac\nexit 0\n",
    ),
    (
        "curl",
        "#!/bin/sh\nout=''\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=\"$2\"; shift; done\nname=\"${1##*/}\"\n[ -f \"$TEST_DIR/release/$name\" ] || exit 22\ncp \"$TEST_DIR/release/$name\" \"$out\"\n",
    ),
];

/// A temporary directory holding the stubs, the files a test puts in the machine (under `root`),
/// and what the installer wrote; removed when dropped.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(format!("tally-{name}-{}", std::process::id()));
        if dir.exists() {
            io(std::fs::remove_dir_all(&dir))?;
        }
        io(std::fs::create_dir_all(dir.join("stub")))?;
        let sandbox = Self { dir };
        for (name, script) in STUBS {
            sandbox.stub(name, script)?;
        }
        Ok(sandbox)
    }

    /// Writes `text` at `path` under the sandbox, making its directories.
    fn file(&self, path: &str, text: &str) -> Result {
        let path = self.dir.join(path);
        if let Some(parent) = path.parent() {
            io(std::fs::create_dir_all(parent))?;
        }
        io(std::fs::write(path, text))
    }

    fn stub(&self, name: &str, script: &str) -> Result {
        let path = self.dir.join("stub").join(name);
        io(std::fs::write(&path, script))?;
        io(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o755),
        ))
    }

    fn read(&self, path: &str) -> Result<String> {
        io(std::fs::read_to_string(self.dir.join(path)))
    }

    fn exists(&self, path: &str) -> bool {
        self.dir.join(path).exists()
    }

    /// Runs `body` after the prelude, with only `env` of the TALLY_ variables set.
    fn run(&self, body: &str, env: &[(&str, &str)]) -> Result<Output> {
        let inherited = std::env::var("PATH").unwrap_or_default();
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(format!("{PRELUDE}\n{body}"))
            .env_clear()
            .env(
                "PATH",
                format!("{}:{inherited}", self.dir.join("stub").display()),
            )
            .env("TALLY_INSTALLER", installer()?)
            .env("TEST_DIR", &self.dir);
        for (name, value) in env {
            command.env(name, value);
        }
        io(command.output())
    }

    /// `body`'s stdout; an error carrying its stderr if it failed.
    fn ok(&self, body: &str, env: &[(&str, &str)]) -> Result<String> {
        let output = self.run(body, env)?;
        if !output.status.success() {
            return Err(format!(
                "it failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// `body`'s stderr, which must have stopped it.
    fn stopped(&self, body: &str, env: &[(&str, &str)]) -> Result<String> {
        let output = self.run(body, env)?;
        if output.status.success() {
            return Err(format!(
                "it did not stop: {}",
                String::from_utf8_lossy(&output.stdout)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stderr).into_owned())
    }

    /// The location found, as `LAT LON ALT|WHERE THE LOCATION CAME FROM|WHERE THE ALTITUDE DID`.
    fn located(&self, env: &[(&str, &str)]) -> Result<String> {
        let out = self.ok(
            "discover_location quiet\nprintf '%s %s %s|%s|%s' \"$lat\" \"$lon\" \"$alt\" \"$lat_from\" \"$alt_from\"",
            env,
        )?;
        Ok(out.lines().last().unwrap_or_default().to_owned())
    }

    /// A release in `release/` (a fake `tally-feed`, the unit, each with its sha256) and a seed
    /// list, as an install reads them.
    fn release(&self) -> Result {
        self.file(
            "release/tally-feed-x86_64-linux",
            &format!("#!/bin/sh\n[ \"$1\" = init ] && touch \"$3\" && echo '{PUBLIC}'\nexit 0\n"),
        )?;
        self.file("release/tally-feed.service", "[Service]\n")?;
        self.file(
            "seeds",
            &format!("relay.example:10900={RELAY_KEY} Example Operator\n"),
        )
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The whole install, as `main` runs it, with the release's checksums made first.
const INSTALL: &str = r#"
for f in "$T"/release/*; do sha256sum "$f" > "$f.sha256"; done
main
"#;

fn install_env<'a>(sandbox: &Sandbox, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, String)> {
    let mut env = vec![
        ("TALLY_RELEASE", "https://release.example/r".to_owned()),
        (
            "TALLY_SEEDS",
            sandbox.dir.join("seeds").display().to_string(),
        ),
    ];
    env.extend(
        extra
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    env
}

fn borrowed<'a>(env: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
    env.iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
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
    // A host keeping time with neither chrony nor ntpd gets chrony: the package lists updated
    // first, the install waiting for another's lock rather than failing at once (the update
    // ignores that option and is tried again instead).
    let apt = sandbox.read("apt.log")?;
    let lines: Vec<&str> = apt.lines().collect();
    assert_eq!(
        lines,
        ["update", "-o DPkg::Lock::Timeout=120 install -y chrony"],
        "{apt}"
    );
    assert!(out.contains("installing chrony"), "{out}");
    assert!(out.contains("it replaces systemd-timesyncd"), "{out}");
    Ok(())
}

/// The environment of an install with its location given, so it asks nothing.
fn located_env(sandbox: &Sandbox) -> Vec<(&'static str, String)> {
    install_env(
        sandbox,
        &[
            ("TALLY_LAT", "51.5"),
            ("TALLY_LON", "-0.1"),
            ("TALLY_ALT", "20"),
        ],
    )
}

/// A body that runs on a host with neither `dpkg-query` nor `apt-get` (Fedora, Arch, Alpine with
/// systemd): `command -v` finds neither, as on such a host.
const NOT_DEBIAN: &str = r#"
command() {
  if [[ $1 == -v && ( $2 == dpkg-query || $2 == apt-get ) ]]; then return 1; fi
  builtin command "$@"
}
dpkg-query() { echo "asked dpkg-query" >&2; exit 97; }
apt-get() { echo "asked apt-get" >&2; exit 97; }
"#;

/// RFC-0171 §3.6: the feeder trusts its host's clock by the kernel's error bound, which is true
/// only under chrony or ntpd (systemd-timesyncd keeps none), so an install leaves the host running
/// one of the two. One whose systemd runs chrony or ntpd under any of the distributions' names is
/// left as it is; one (on Debian) with chrony or ntpd (`ntp`, or `ntpsec`) installed and stopped
/// has it started and enabled; one with neither gets chrony from apt; one keeping time with
/// OpenNTPD, which chrony's package would remove, is stopped before anything is installed; and
/// when apt cannot install chrony, the install stops before the feeder is installed.
#[test]
fn an_install_leaves_the_host_keeping_time_with_chrony_or_ntpd() -> Result {
    for (packages, active, installs, starts) in [
        ("chrony", "", false, Some("chrony")),
        ("ntp", "", false, Some("ntp")),
        ("ntpsec", "", false, Some("ntpsec")),
        ("chrony", "chrony", false, None),
        ("", "chrony", false, None),
        ("", "chronyd", false, None),
        ("", "ntpd", false, None),
        ("", "ntpsec", false, None),
        ("", "systemd-timesyncd", true, None),
        ("", "", true, None),
    ] {
        let sandbox = Sandbox::new("time")?;
        sandbox.release()?;
        sandbox.file("packages", &format!("{packages}\n"))?;
        sandbox.file("active", &format!("{active}\n"))?;
        sandbox.file(
            "journal",
            "tally-feed: publishing to relay.example:10900 (version 1)\n",
        )?;
        let env = located_env(&sandbox);
        let out = sandbox.ok(INSTALL, &borrowed(&env))?;
        let apt = sandbox.read("apt.log").unwrap_or_default();
        assert_eq!(
            apt.contains("install -y chrony"),
            installs,
            "{packages:?} {active:?}: {apt}"
        );
        let calls = sandbox.read("systemctl.log")?;
        let started: Vec<&str> = calls
            .lines()
            .filter_map(|line| line.strip_prefix("enable --now "))
            .collect();
        assert_eq!(
            started,
            starts.into_iter().collect::<Vec<_>>(),
            "{packages:?} {active:?}: {calls}"
        );
        if let Some(unit) = starts {
            assert!(out.contains(&format!("starting {unit}")), "{out}");
        }
    }
    for (packages, active) in [("openntpd", ""), ("", "openntpd")] {
        let sandbox = Sandbox::new("time-openntpd")?;
        sandbox.release()?;
        sandbox.file("packages", &format!("{packages}\n"))?;
        sandbox.file("active", &format!("{active}\n"))?;
        let env = located_env(&sandbox);
        let refusal = sandbox.stopped(INSTALL, &borrowed(&env))?;
        assert!(refusal.contains("OpenNTPD"), "{refusal}");
        assert!(refusal.contains("replaces systemd-timesyncd"), "{refusal}");
        assert!(!sandbox.exists("apt.log"));
        assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    }
    let sandbox = Sandbox::new("time-fails")?;
    sandbox.release()?;
    sandbox.file("apt-fails", "")?;
    let env = located_env(&sandbox);
    let refusal = sandbox.stopped(INSTALL, &borrowed(&env))?;
    assert!(
        refusal.contains("could not update the package lists"),
        "{refusal}"
    );
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    // A failure that is not the lists' lock is not tried again.
    assert_eq!(sandbox.read("apt.log")?.lines().count(), 1);
    let sandbox = Sandbox::new("time-install-fails")?;
    sandbox.release()?;
    sandbox.file("install-fails", "")?;
    let env = located_env(&sandbox);
    let refusal = sandbox.stopped(INSTALL, &borrowed(&env))?;
    assert!(refusal.contains("could not install chrony"), "{refusal}");
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    Ok(())
}

/// `apt-get update` fails at once on the package lists' lock another apt holds, whatever
/// DPkg::Lock::Timeout says (apt 2.8), so the install tries it again while that is the failure,
/// LOCK_TRIES times, then stops before anything is installed.
#[test]
fn an_update_waits_out_another_apt_holding_the_package_lists() -> Result {
    let sandbox = Sandbox::new("time-locked")?;
    sandbox.release()?;
    sandbox.file("lists-locked", "3\n")?;
    sandbox.file(
        "journal",
        "tally-feed: publishing to relay.example:10900 (version 1)\n",
    )?;
    let env = located_env(&sandbox);
    let out = sandbox.ok(INSTALL, &borrowed(&env))?;
    assert!(out.contains("installed and publishing"), "{out}");
    let apt = sandbox.read("apt.log")?;
    let lines: Vec<&str> = apt.lines().collect();
    assert_eq!(
        lines,
        [
            "update",
            "update",
            "update",
            "update",
            "-o DPkg::Lock::Timeout=120 install -y chrony"
        ],
        "{apt}"
    );
    let sandbox = Sandbox::new("time-locked-for-good")?;
    sandbox.release()?;
    sandbox.file("lists-locked", "1000\n")?;
    let env = located_env(&sandbox);
    let refusal = sandbox.stopped(INSTALL, &borrowed(&env))?;
    assert!(
        refusal.contains("could not update the package lists"),
        "{refusal}"
    );
    assert_eq!(sandbox.read("apt.log")?.lines().count(), 24);
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
    Ok(())
}

/// A host with no Debian package database (no `dpkg-query`, no `apt-get`) is asked of systemd:
/// one running chronyd or ntpd is installed on, asking neither tool, and one running neither
/// is stopped before anything is installed, told to install chrony. Before, the install asked
/// only `dpkg-query`, and refused every host that is not Debian's, whatever kept its time.
#[test]
fn a_host_with_no_package_database_is_asked_of_systemd() -> Result {
    for active in ["chronyd", "ntpd"] {
        let sandbox = Sandbox::new("time-systemd")?;
        sandbox.release()?;
        sandbox.file("active", &format!("{active}\n"))?;
        sandbox.file(
            "journal",
            "tally-feed: publishing to relay.example:10900 (version 1)\n",
        )?;
        let env = located_env(&sandbox);
        let out = sandbox.ok(&format!("{NOT_DEBIAN}\n{INSTALL}"), &borrowed(&env))?;
        assert!(out.contains("installed and publishing"), "{active}: {out}");
        assert!(sandbox.exists("root/usr/local/bin/tally-feed"));
    }
    let sandbox = Sandbox::new("time-none")?;
    sandbox.release()?;
    let env = located_env(&sandbox);
    let refusal = sandbox.stopped(&format!("{NOT_DEBIAN}\n{INSTALL}"), &borrowed(&env))?;
    assert!(refusal.contains("neither chrony nor ntpd"), "{refusal}");
    assert!(
        refusal.contains("it replaces systemd-timesyncd"),
        "{refusal}"
    );
    assert!(!refusal.contains("asked"), "{refusal}");
    assert!(!sandbox.exists("root/usr/local/bin/tally-feed"));
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
    // The container trusts the host's clock: a host keeping time with neither chrony nor ntpd
    // is told to install chrony; one that keeps it is told nothing of it.
    assert!(out.contains("Install chrony on the host"), "{out}");
    sandbox.file("packages", "chrony\n")?;
    let stopped = sandbox.ok(INSTALL, &borrowed(&env))?;
    assert!(
        stopped.contains("chrony installed and not running")
            && stopped.contains("systemctl enable --now chrony"),
        "{stopped}"
    );
    sandbox.file("active", "chrony\n")?;
    let kept = sandbox.ok(INSTALL, &borrowed(&env))?;
    assert!(!kept.contains("chrony"), "{kept}");
    Ok(())
}

#[test]
fn uninstall_keeps_the_key_and_purge_deletes_it() -> Result {
    let sandbox = Sandbox::new("uninstall")?;
    for path in [
        "root/usr/local/bin/tally-feed",
        "root/etc/default/tally-feed",
        "root/etc/systemd/system/tally-feed.service",
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
        "root/var/lib/private/tally-feed",
    ] {
        assert!(!sandbox.exists(gone), "{gone} is still there");
    }
    let calls = sandbox.read("systemctl.log")?;
    assert!(
        calls.contains("disable --now tally-feed.service"),
        "{calls}"
    );

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
