//! The sandbox the installer's and the updater's tests run in: `install.sh` and `update.sh` sourced
//! (each runs `main` only when run, not sourced) with every path they read or write moved under a
//! temporary directory, the commands they call (`curl`, `systemctl`, `systemd-run`, `journalctl`,
//! `cosign`, `docker`, `dpkg`, `uname`, `getconf`, `chown`, `flock`) stubbed on `PATH`, and no
//! terminal.
//!
//! The stub `cosign` stands for the release workflow's signatures: a release file's bundle "signs"
//! it when it names the tag the check pins and the file's sha256 (`sign_release`), so a file
//! changed after signing, or signed on another tag, is refused as cosign would refuse it.
#![allow(dead_code, reason = "each test crate uses its own part of the sandbox")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output};

pub type Result<T = ()> = std::result::Result<T, String>;

pub fn installer() -> Result<PathBuf> {
    path_of("TALLY_INSTALLER")
}

pub fn updater() -> Result<PathBuf> {
    path_of("TALLY_UPDATER")
}

/// The file the build names in the environment variable `name`.
pub fn path_of(name: &str) -> Result<PathBuf> {
    let path = std::env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} names a file (set by the build)"))?;
    std::fs::canonicalize(&path).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|error| error.to_string())
}

/// A relay key: 32 bytes of base64.
pub const RELAY_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// The receiver's public key the fake `tally-feed init` prints, with both of the characters
/// base64url replaces.
pub const PUBLIC: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+/8=";

/// The sourced installer's paths and the parts that touch the machine, moved into `$T`. It names
/// only what every installer it is given has (an earlier release's too, in the upgrade test), and
/// sets the updater's paths, which an installer before them simply never reads.
pub const PRELUDE: &str = r#"
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
LIB="$R/usr/local/lib/tally"
COSIGN="$T/stub/cosign"
UPDATER="$LIB/update"
INSTALLED="$LIB/installed"
UPDATE_UNIT="$R/etc/systemd/system/tally-feed-update.service"
UPDATE_TIMER="$R/etc/systemd/system/tally-feed-update.timer"
WAIT_SECONDS=1
UPGRADE_WAIT_SECONDS=1
mkdir -p "$R/usr/local/bin" "$R/etc/default" "$R/etc/systemd/system" "$T/work"
work="$T/work"
require_root() { :; }
have_tty() { false; }
readsb_arguments() { :; }
listening() { false; }
install_cosign() { :; }
"#;

/// The sourced updater's paths, moved into `$T` as `PRELUDE` moves the installer's; the installer
/// it runs is sourced under `PRELUDE` too (`$TALLY_PRELUDE`).
pub const UPDATE_PRELUDE: &str = r#"
set -euo pipefail
source "$TALLY_UPDATER"
T="$TEST_DIR"
R="$T/root"
LIB="$R/usr/local/lib/tally"
COSIGN="$T/stub/cosign"
INSTALLED="$LIB/installed"
WORK="$T/update-work"
LOCK="$T/update.lock"
REPLACED=(
  "$R/usr/local/bin/tally-feed"
  "$R/etc/default/tally-feed"
  "$R/etc/systemd/system/tally-feed.service"
  "$R/etc/systemd/system/tally-feed-update.service"
  "$R/etc/systemd/system/tally-feed-update.timer"
  "$LIB/update"
  "$LIB/installed"
)
run_installer() {
  TALLY_INSTALLER="$1" bash -c "$TALLY_PRELUDE"$'\n''main --upgrade'
}
"#;

/// Signs every file of `$T/release` as the release workflow does on the tag TAG: its `.sha256`
/// and its `.sigstore.json`, which the stub `cosign` takes for the workflow's signature on TAG.
pub const SIGN: &str = r#"
sign_release() {
  local f
  for f in "$T"/release/*; do
    case "$f" in *.sha256 | *.sigstore.json) continue ;; esac
    sha256sum "$f" > "$f.sha256"
    printf 'signed refs/tags/%s\n%s\n' "$1" "$(sha256sum < "$f" | cut -d' ' -f1)" > "$f.sigstore.json"
  done
}
"#;

/// The stubs every sandbox has: no docker container, an amd64 Debian, systemd 247 whose service
/// is always active and which keeps which units are enabled (`$T/enabled-UNIT`), a journal
/// (`$T/journal`) for the service's start, a `curl` serving the files of `$T/release` and
/// `$T/latest` as the latest release's tag (and the location services' answers in `$T/service`,
/// logging what it was asked in `services.log` and its arguments in `curl-args.log`), and a
/// `cosign` that takes a bundle `SIGN` wrote.
pub const STUBS: &[(&str, &str)] = &[
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
    ("flock", "#!/bin/sh\nexit 0\n"),
    (
        "systemctl",
        r#"#!/bin/sh
echo "$*" >> "$TEST_DIR/systemctl.log"
case "$1" in
  --version) echo 'systemd 247 (247.3-7+deb11u4)' ;;
  show) echo 0123456789abcdef ;;
  is-active) [ ! -f "$TEST_DIR/inactive" ] ;;
  is-enabled)
    shift
    [ "$1" = --quiet ] && shift
    [ -f "$TEST_DIR/enabled-$1" ]
    ;;
  enable | disable)
    verb="$1"
    shift
    for unit in "$@"; do
      [ "$unit" = --now ] && continue
      if [ "$verb" = enable ]; then touch "$TEST_DIR/enabled-$unit"; else rm -f "$TEST_DIR/enabled-$unit"; fi
    done
    ;;
esac
"#,
    ),
    (
        "systemd-run",
        "#!/bin/sh\nwhile [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
    ),
    (
        "journalctl",
        "#!/bin/sh\ncase \"$*\" in\n  *_SYSTEMD_INVOCATION_ID=*) cat \"$TEST_DIR/journal\" 2>/dev/null ;;\n  *) echo 'the journal tail' ;;\nesac\nexit 0\n",
    ),
    (
        "curl",
        r#"#!/bin/sh
echo "$*" >> "$TEST_DIR/curl-args.log"
out='' config=''
while [ $# -gt 1 ]; do
  case "$1" in
    -o) out="$2"; shift ;;
    -w | -A) shift ;;
    -K) config="$2" ;;
  esac
  shift
done
# A URL read from standard input (`-K -`, as the installer asks the location services): answered
# from $TEST_DIR/service/NAME, by the service it names.
if [ "$config" = - ]; then
  url="$(sed -n 's/^url = "\(.*\)"$/\1/p')"
  echo "$url" >> "$TEST_DIR/services.log"
  case "$url" in
    https://geocoding.geo.census.gov/*) name=census ;;
    https://nominatim.openstreetmap.org/*) name=nominatim ;;
    https://epqs.nationalmap.gov/*) name=epqs ;;
    https://api.open-meteo.com/*) name=open-meteo ;;
    *) exit 22 ;;
  esac
  [ -f "$TEST_DIR/service/$name" ] || exit 22
  exec cat "$TEST_DIR/service/$name"
fi
echo "$1" >> "$TEST_DIR/curl.log"
case "$1" in
  */releases/latest)
    [ -f "$TEST_DIR/latest" ] || exit 22
    printf 'https://github.com/sky-commons/tally/releases/tag/%s' "$(cat "$TEST_DIR/latest")"
    exit 0
    ;;
esac
name="${1##*/}"
[ -f "$TEST_DIR/release/$name" ] || exit 22
if [ -n "$out" ]; then cp "$TEST_DIR/release/$name" "$out"; else cat "$TEST_DIR/release/$name"; fi
"#,
    ),
    (
        "cosign",
        r#"#!/bin/sh
echo "$*" >> "$TEST_DIR/cosign.log"
file="$2" bundle='' ref=''
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) bundle="$2" ;;
    --certificate-github-workflow-ref) ref="$2" ;;
  esac
  shift
done
[ -f "$bundle" ] && [ "$(sed -n 1p "$bundle")" = "signed $ref" ] &&
  [ "$(sed -n 2p "$bundle")" = "$(sha256sum < "$file" | cut -d' ' -f1)" ]
"#,
    ),
];

/// A temporary directory holding the stubs, the files a test puts in the machine (under `root`),
/// and what the installer wrote; removed when dropped.
pub struct Sandbox {
    pub dir: PathBuf,
}

impl Sandbox {
    pub fn new(name: &str) -> Result<Self> {
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
    pub fn file(&self, path: &str, text: &str) -> Result {
        let path = self.dir.join(path);
        if let Some(parent) = path.parent() {
            io(std::fs::create_dir_all(parent))?;
        }
        io(std::fs::write(path, text))
    }

    /// Copies the file `from` to `path` under the sandbox, executable.
    pub fn copy(&self, from: &std::path::Path, path: &str) -> Result {
        let to = self.dir.join(path);
        if let Some(parent) = to.parent() {
            io(std::fs::create_dir_all(parent))?;
        }
        io(std::fs::copy(from, &to))?;
        io(std::fs::set_permissions(
            &to,
            std::fs::Permissions::from_mode(0o755),
        ))
    }

    pub fn stub(&self, name: &str, script: &str) -> Result {
        let path = self.dir.join("stub").join(name);
        io(std::fs::write(&path, script))?;
        io(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o755),
        ))
    }

    pub fn read(&self, path: &str) -> Result<String> {
        io(std::fs::read_to_string(self.dir.join(path)))
    }

    /// What a stub logged (`curl.log`, `systemctl.log`, `cosign.log`), empty if nothing.
    pub fn log(&self, name: &str) -> String {
        self.read(name).unwrap_or_default()
    }

    pub fn exists(&self, path: &str) -> bool {
        self.dir.join(path).exists()
    }

    /// Runs `body` after the installer's prelude with `installer` sourced, with only `env` of the
    /// TALLY_ variables set.
    pub fn run_with(
        &self,
        installer: &std::path::Path,
        body: &str,
        env: &[(&str, &str)],
    ) -> Result<Output> {
        self.bash(
            &format!("{PRELUDE}\n{SIGN}\n{body}"),
            &[("TALLY_INSTALLER", installer)],
            env,
        )
    }

    /// Runs `body` after the installer's prelude, with only `env` of the TALLY_ variables set.
    pub fn run(&self, body: &str, env: &[(&str, &str)]) -> Result<Output> {
        self.run_with(&installer()?, body, env)
    }

    /// Runs `body` after the updater's prelude with `updater` sourced; the installer it runs is
    /// sourced under the installer's prelude.
    pub fn update_with(
        &self,
        updater: &std::path::Path,
        body: &str,
        env: &[(&str, &str)],
    ) -> Result<Output> {
        self.bash(
            &format!("{UPDATE_PRELUDE}\n{body}"),
            &[("TALLY_UPDATER", updater)],
            env,
        )
    }

    fn bash(
        &self,
        script: &str,
        files: &[(&str, &std::path::Path)],
        env: &[(&str, &str)],
    ) -> Result<Output> {
        let inherited = std::env::var("PATH").unwrap_or_default();
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(script)
            .env_clear()
            .env(
                "PATH",
                format!("{}:{inherited}", self.dir.join("stub").display()),
            )
            .env("TALLY_PRELUDE", format!("{PRELUDE}\n{SIGN}"))
            .env("TALLY_INSTALLER", installer()?)
            .env("TEST_DIR", &self.dir);
        for (name, path) in files {
            command.env(name, path);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        io(command.output())
    }

    /// `body`'s stdout; an error carrying its stderr if it failed.
    pub fn ok(&self, body: &str, env: &[(&str, &str)]) -> Result<String> {
        succeeded(self.run(body, env)?)
    }

    /// `body`'s stderr, which must have stopped it.
    pub fn stopped(&self, body: &str, env: &[(&str, &str)]) -> Result<String> {
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
    pub fn located(&self, env: &[(&str, &str)]) -> Result<String> {
        let out = self.ok(
            "discover_location quiet\nprintf '%s %s %s|%s|%s' \"$lat\" \"$lon\" \"$alt\" \"$lat_from\" \"$alt_from\"",
            env,
        )?;
        Ok(out.lines().last().unwrap_or_default().to_owned())
    }

    /// A release in `release/` (a fake `tally-feed`, the units and the updater) and a seed list,
    /// as an install reads them; `INSTALL` signs it.
    pub fn release(&self) -> Result {
        self.file(
            "release/tally-feed-x86_64-linux",
            &format!("#!/bin/sh\n[ \"$1\" = init ] && touch \"$3\" && echo '{PUBLIC}'\nexit 0\n"),
        )?;
        self.file("release/tally-feed.service", "[Service]\n")?;
        self.file("release/tally-feed-update.service", "[Service]\n")?;
        self.file("release/tally-feed-update.timer", "[Timer]\n")?;
        self.file("release/update.sh", "#!/bin/sh\n")?;
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

/// The output's stdout; an error carrying its stderr if it failed.
pub fn succeeded(output: Output) -> Result<String> {
    if !output.status.success() {
        return Err(format!(
            "it failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The whole install, as `main` runs it, with the release signed first on the installer's own
/// tag.
pub const INSTALL: &str = r#"
sign_release "$VERSION"
main
"#;

pub fn install_env<'a>(sandbox: &Sandbox, extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, String)> {
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

pub fn borrowed<'a>(env: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
    env.iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}
