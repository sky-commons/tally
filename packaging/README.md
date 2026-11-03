# Packaging

How Tally's binaries are installed on a Linux box with systemd (247 or later: Debian bullseye,
Raspberry Pi OS Bullseye and anything newer).

- `install.sh` installs a feeder on a receiver. Download it, read it if you like, and run it:

  ```sh
  curl -fsSL https://github.com/sky-commons/tally/releases/latest/download/install.sh -o /tmp/tally-install.sh
  sudo bash /tmp/tally-install.sh
  ```

  (`curl ... | sudo bash` works too.) It installs from the release its publisher published (the
  publisher writes the release's address into the script as it publishes it, `PUBLISHED_RELEASE`;
  `TALLY_RELEASE` overrides it), and in order:

  - **Build:** picks `tally-feed` by the userland (`dpkg --print-architecture`, else `uname -m`
    and `getconf LONG_BIT`), not the kernel, so 32-bit Raspberry Pi OS on a Pi 4 or 5's 64-bit
    kernel gets `tally-feed-armv7-linux`. A 32-bit system the release has no build for (ARMv6, a
    Pi 1 or the first Pi Zero; 32-bit x86) is refused with "32-bit systems are not supported yet".
    Each download is checked against the `.sha256` published beside it, which guards a broken
    download, and against its cosign signature bundle (`.sigstore.json`), which must be the
    release workflow's on this release's own tag ("Automatic updates", below). cosign itself is
    downloaded from sigstore/cosign's release and checked against the sha256 the script pins.
    Nothing of the release is installed until every file of it is checked.
  - **Decoders:** readsb's BEAST output on `127.0.0.1:30005`, and dump978-fa's raw output on
    `127.0.0.1:30978` (added as `--uat`). acars_router's ACARS, VDL2 and HFDL outputs on
    `127.0.0.1:15550`, `15555` and `15556` are never added: message text can carry personal data,
    so publishing it is the owner's choice, and the run prints the `--acars` to put in
    `TALLY_FEED_EXTRA` for each it finds. Where nothing answers on
    30005 but an ultrafeeder container runs, the decoder's output is inside docker and a host
    install would feed nothing, so it installs nothing and prints the compose service to add
    instead ("Run it as a container", below), filled in with the container's name and location.
  - **Location**, the first found, each printed with where it came from: `TALLY_LAT`, `TALLY_LON`
    and `TALLY_ALT` (metres, or `15m` or `45ft`); adsb.im's `/opt/adsb/config/.env`
    (`FEEDER_LAT`, `FEEDER_LONG`, `FEEDER_ALT_M`); readsb's `--lat` and `--lon`
    (`/etc/default/readsb`, or a running readsb); PiAware's `/var/cache/piaware/location.env`;
    `RECEIVER_LAT` and `RECEIVER_LON` in `/etc/default/dump1090-fa`; `LATITUDE`, `LONGITUDE` and
    `ALTITUDE` in `/etc/default/{adsbexchange,adsbfi,airplanes,adsblol}`; a running ultrafeeder
    container's `LAT`, `LONG` and `ALT` (when docker is installed); and what an earlier run wrote.
    The altitude may come from a later source than the position. It is never guessed: a found 0
    counts as unset (only `TALLY_ALT=0` says 0), and with none found it is asked for on the
    terminal, or, with no terminal, the install stops naming `TALLY_ALT`, having installed
    nothing. A position found nowhere is handled the same way.
  - **Who sees the location:** it asks nothing and passes no flag for it. The feed carries the
    exact location only to Tally relays, as MLAT needs, in a record relays never pass to a client.
    Nothing a data user reads (the API, the streams, the stats) contains it: the receiver's public
    description names only its public cell, about 6 km across, which is all a public map shows.
    The installer says so in one line.
  - **Relays:** from a seed list, the release's `seeds` or the file `TALLY_SEEDS` names, one
    `HOST:PORT=KEY OPERATOR` a line. It stops before installing anything if the list names no
    relay or an entry names no operator (`install.sh --check-seeds FILE` reads a list the same
    way, installing nothing).
  - **Key:** makes `/etc/tally/key` if missing (root, mode 600), and keeps it on every rerun.
  - **`/etc/default/tally-feed`:** the block between its `# BEGIN install.sh` and
    `# END install.sh` lines is the installer's, rewritten on every run with the relays, the
    location and the UAT source as `TALLY_FEED_ARGS`, so a rerun with a new `TALLY_LAT`,
    `TALLY_LON` or `TALLY_ALT` wins. The owner's own flags go in `TALLY_FEED_EXTRA`, below it,
    which every run keeps, as it keeps any other line outside the block; they come after the
    block's, so the owner's `--lat` beats the found one. A file an older `install.sh` wrote is
    rewritten the same way, every flag in it the installer does not own moved into
    `TALLY_FEED_EXTRA`.
  - **Start:** starts the service and waits up to 20 s for it to be active and log
    `tally-feed: publishing to RELAY`. Only then does it say it is installed, print the public key
    and the station page, `https://tally.skycommons.org/feeders/<key>` (the key as base64url
    without padding), and exit 0. Otherwise it prints the journal's tail and what to do next, and
    exits 1; the feeder keeps trying on its own.

  - **Automatic updates:** installs the updater, and turns it on unless `TALLY_AUTO_UPDATE=0` or
    `--no-auto-update` says otherwise, or an earlier install left it off. It ends by saying which,
    and how to change it ("Automatic updates", below).

  Run again, it upgrades the binary and keeps the key and the owner's choice about updates.
  `install.sh --uninstall` stops the feeder and its updater and removes their units, the binary,
  the updater and cosign (`/usr/local/lib/tally`), what the feeder learned and
  `/etc/default/tally-feed`, keeping the key, so installing again is the same station; `install.sh --uninstall --purge` deletes the key as well, after saying that
  the station's identity is then gone for good (on a terminal it asks you to type `delete`).
- `systemd/tally-feed.service` runs the feeder as a dynamic user with no listening socket, at most
  64 MB and 20% of one CPU. The key reaches it through `LoadCredential`, so it stays root's; the
  service reads it from `${CREDENTIALS_DIRECTORY}`, which systemd 247 sets (the `%d` specifier for
  it is 248's). `SocketBindDeny=` is 249's: an older systemd skips it with a warning. The
  arguments are `TALLY_FEED_ARGS` then `TALLY_FEED_EXTRA` in `/etc/default/tally-feed`.
- `systemd/tally-relay.service` runs a relay the same way, with its key at `/etc/tally/relay.key`
  (`tally-relay keygen > /etc/tally/relay.key`) and its arguments as `TALLY_RELAY_ARGS` in
  `/etc/default/tally-relay`. Its upload cap is `TALLY_RELAY_MAX_UPLOAD` there too; the unit's
  default, `2Mbit/s` (at most about 670 GB in 31 days), is deliberately small, and the operator
  sets it for the host's plan (`../README.md`, "What a relay costs"): the bill can never exceed the
  cap times the seconds in a month, so `10Mbit/s` is at most about 3.35 TB. The cap keeps no state.

**Until a release pipeline exists** (RFC-0180 phase 1), nothing writes `PUBLISHED_RELEASE` into
`install.sh` or publishes a `seeds` beside it, so the plain install stops before installing
anything and says how to go on. Name the release and the seed list yourself: the release is any
HTTPS directory holding the files below, and the seed list a local file in the format above
(check it first with `bash install.sh --check-seeds FILE`). `sudo` passes the `NAME=value` words
before `bash` into the script's environment:

```sh
curl -fsSL https://example.org/tally/v0.1.0/install.sh -o /tmp/tally-install.sh
sudo TALLY_RELEASE=https://example.org/tally/v0.1.0 TALLY_SEEDS=/home/pi/seeds bash /tmp/tally-install.sh
```

The installer's tests (`//packaging:install_test`, `tests/install.rs`) source it and the updater
into a sandbox with their paths moved and the commands they call stubbed (`tests/sandbox`), and
check each behaviour above. `//packaging:upgrade_test` (`tests/upgrade.rs`) is the gate that no
release needs the owner's hands (RFC-0203 §4). It upgrades installs made by the published
installers of earlier releases (`tests/previous`) and by this build to this build's real feeder,
and checks that the feeder starts with the key, the settings and the choice about updates it had.

A release therefore carries `install.sh`, `tally-feed-x86_64-linux`, `tally-feed-aarch64-linux`,
`tally-feed-armv7-linux` (32-bit ARM hard-float: 32-bit Raspberry Pi OS on a Pi 2 or later, and
the PiAware image; not ARMv6, so not a Pi 1 or the first Pi Zero), `tally-feed.service`,
`update.sh`, `tally-feed-update.service`, `tally-feed-update.timer` and `seeds`, each with a
`.sha256` whose first field is the file's hash and a `.sigstore.json`, the release workflow's
cosign signature bundle. The seed list is the
publisher's configuration, not this repository's: each publisher ships the relays it starts
feeders from, each naming its operator, and checks its list with `--check-seeds`. The feeder
compiles the same file in (`crates/feed`, `config::SEEDS`), so a feeder started with no
`--relay` starts from the release's seeds. The binaries are built against the pinned Debian
bullseye sysroots (`bazel build -c opt --platforms=//platforms:linux_aarch64
//crates/feed:tally-feed`, or `linux_armv7`), so they need only glibc 2.25 or newer and no C++
runtime: any Raspberry Pi OS from Buster on, and any current Linux.

## Automatic updates

`install.sh` installs the updater (RFC-0203): `/usr/local/lib/tally/update` (`update.sh`), run by
`tally-feed-update.service` from `tally-feed-update.timer`. The timer runs once a day, at a time
of its own for each receiver (`RandomizedDelaySec=23h`, `FixedRandomDelay=yes`), and at boot if
the receiver was off at that time. On each run it:

- reads the latest release's tag (where `releases/latest` leads) and stops with `up to date`
  unless it is newer than the version the last install recorded (`/usr/local/lib/tally/installed`).
  It never installs an older release;
- downloads that release's `install.sh` with its `.sigstore.json`, and stops with `REFUSED`,
  installing nothing, unless `cosign verify-blob` finds it signed with the certificate identity
  `https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/<that tag>`
  (exact), the issuer `https://token.actions.githubusercontent.com`, and the workflow's
  repository, trigger (`push`) and ref (the tag), and unless it says it is that version. The
  cosign is the one the last install put at `/usr/local/lib/tally/cosign`, pinned by its sha256.
  The identity is written in the installed updater. Nothing from the new release is trusted, and
  nothing downloaded is run, before that check;
- copies every file an install may replace, then runs the checked `install.sh --upgrade`. It
  checks the release's other files the same way, asks nothing, rewrites what the release needs,
  restarts the feeder and waits 90 s for it to publish;
- if the installer fails, or the feeder is not running after it, puts every copied file back,
  restarts the old feeder, and logs `ROLLED BACK` with the reason. It tries again at the next run.

curl and cosign run as a throwaway unprivileged user, a transient unit with `DynamicUser=yes`,
no capabilities, and no write access outside a private `/tmp`. Root writes only what they fetched,
and runs only the installer they checked. Its log is `journalctl -u tally-feed-update`. The
version a feeder runs is in its signed description (`software`), which a station's stats show.

**Off:** `sudo systemctl disable --now tally-feed-update.timer`, or `TALLY_AUTO_UPDATE=0` (or
`--no-auto-update`) when installing. While the timer is disabled the updater does nothing, even
when started by hand, and a rerun of `install.sh` keeps it off. `sudo systemctl enable --now
tally-feed-update.timer` turns it back on. `sudo systemctl start tally-feed-update.service` runs
a check now.

Only this standalone install updates itself. A container (below, and adsb.im) follows its image
tag through its host's own updates.

## Run it as a container

A host that runs each feeder as a container, such as adsb.im or an sdr-enthusiasts compose file
(amd64, arm64 and 32-bit arm/v7), runs the release's image: `ghcr.io/sky-commons/tally-feed:0`
follows every 0.x release, and `:vX.Y.Z` (or the `@sha256:` digest `tally-feed-image.txt` names)
pins one (`container/Dockerfile`). It is the same `tally-feed` binary the release publishes, on
distroless with no shell, and it is configured the way the sdr-enthusiasts images are, by one
block of environment variables. Beside ultrafeeder, with adsb.im's location variables:

```yaml
  tally-feed:
    image: ghcr.io/sky-commons/tally-feed:0
    container_name: tally-feed
    restart: unless-stopped
    environment:
      - BEASTHOST=ultrafeeder
      - LAT=${FEEDER_LAT}
      - LONG=${FEEDER_LONG}
      - ALT=${FEEDER_ALT_M}m
    volumes:
      - /opt/adsb/tally-feed:/var/lib/tally-feed
```

That is all of it: no key to make or paste, and no relay to name.

- **Decoder:** `BEASTHOST`, and `BEASTPORT` (default 30005), name readsb's BEAST output, here
  ultrafeeder's on the compose network, so port 30005 need not be published on the host.
- **Location:** `LAT` and `LONG` (or `READSB_LAT` and `READSB_LON`) in degrees, and `ALT` (or
  `READSB_ALT`) as ultrafeeder takes it, `15m` or `45ft` (a bare number is metres). Only Tally
  relays get the position exactly, as MLAT needs; nothing a data user reads contains it, and public
  surfaces (the map, station pages, the API) show only its public cell, about 6 km across. An
  empty variable counts as unset, so a missing
  `${FEEDER_ALT_M}` leaves `ALT=m`, which the feeder refuses by name rather than guessing 0 m.
- **Identity:** on the first run the feeder makes its key in the volume
  (`/var/lib/tally-feed/key`), and every start logs the receiver's public key and its station page,
  `https://tally.skycommons.org/feeders/<key>` (`docker logs tally-feed`). Keep the volume: the
  key is the antenna's name for good. A host that keeps secrets in its own configuration sets
  `TALLY_KEY` to the first line of `docker run --rm ghcr.io/sky-commons/tally-feed:0 new-key`
  instead, and then no key file is made.
- **Relays:** the release's seed list is compiled into the binary; the feeder learns more from
  relays and keeps them in the volume.
- **Health:** the image's `HEALTHCHECK` (`tally-feed health`) is healthy only while a relay
  session is up (within two minutes) and the decoder is sending (within five minutes; readsb sends
  a heartbeat every minute), from a status file the feeder rewrites every ten seconds in the
  volume. `docker ps` shows it. When no relay has been reachable for ten minutes the log says so
  once, and once more when one is reachable again.
- **Volume and user:** the feeder starts as root only to make the volume nonroot's (65532), so a
  bind-mounted directory Docker created as root works with no `chown`, and then runs as nonroot.
  A named volume works the same. A compose `user:` skips the handover (then the directory must be
  writable by that user).
- **Flags:** a `command:` list is `tally-feed`'s own flags and wins over the environment, for
  example `[--uat, dump978:30978]` for a 978 MHz UAT decoder, `[--acars, acars_router:15555]` for
  acars_router's VDL2 output, or `--relay HOST:PORT=KEY` to add a
  relay. `TALLY_STATE` moves the state directory (`--state`); the health check reads it too.
- **Rounding, experts only:** `--precision M` (a flag, never an environment variable) rounds the
  position to an M-metre grid before anything is signed or sent, so not even relay operators see
  the exact one. A receiver declaring more than 30 m (the MLAT solver's `MAX_SITE_PRECISION_M`) is
  left out of MLAT entirely: it still feeds ADS-B but contributes nothing to MLAT.

The image is signed by the release workflow on its tag, like the binaries, and `:0` names the
same digest as the release it last followed, so the same signature covers it; check it before
pinning it:

```sh
cosign verify ghcr.io/sky-commons/tally-feed:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/sky-commons/tally-feed:vX.Y.Z --repo sky-commons/tally
```
