# Packaging

How Tally's binaries are installed on a Linux box with systemd (248 or later).

- `install.sh` installs a feeder on a receiver:
  `curl -fsSL <release>/install.sh | sudo bash`, from the release its publisher published (the
  publisher writes the release's address into the script as it publishes it, `PUBLISHED_RELEASE`;
  `TALLY_RELEASE` overrides it). It downloads `tally-feed` for x86_64 or aarch64 and the feeder's unit from the release, each
  checked against the `.sha256` published beside it; finds readsb's BEAST output (`127.0.0.1:30005`)
  and dump978-fa's raw output (`127.0.0.1:30978`, added as `--uat`); reads the antenna's location
  from `TALLY_LAT`, `TALLY_LON`, `TALLY_ALT`, or an adsb.im / ultrafeeder `.env`, or
  `/etc/default/readsb`; takes the relays to start from from a seed list, the release's `seeds` or
  the file `TALLY_SEEDS` names, one `HOST:PORT=KEY OPERATOR` a line, and stops before installing
  anything if the list names no relay or an entry names no operator (`install.sh --check-seeds
FILE` reads a list the same way, installing nothing);
  makes `/etc/tally/key` if missing (root, mode 600); writes
  `/etc/default/tally-feed` if missing, with those relays as `--relay` flags, each beside its operator; and starts the service. Run again, it upgrades the binary
  and keeps the key and the defaults file. It installs no updater: the feeder never updates itself
  (RFC-0171 §3.5). The checksum guards a broken download, not a compromised release.
- `systemd/tally-feed.service` runs the feeder as a dynamic user with no listening socket, at most
  64 MB and 20% of one CPU. The key reaches it through `LoadCredential`, so it stays root's. The
  owner's arguments are `TALLY_FEED_ARGS` in `/etc/default/tally-feed`.
- `systemd/tally-relay.service` runs a relay the same way, with its key at `/etc/tally/relay.key`
  (`tally-relay keygen > /etc/tally/relay.key`) and its arguments as `TALLY_RELAY_ARGS` in
  `/etc/default/tally-relay`. Its upload cap is `TALLY_RELAY_MAX_UPLOAD` there too; the unit's
  default, `2Mbit/s` (at most about 670 GB in 31 days), is deliberately small, and the operator
  sets it for the host's plan (`../README.md`, "What a relay costs"): the bill can never exceed the
  cap times the seconds in a month, so `10Mbit/s` is at most about 3.35 TB. The cap keeps no state.

**Until a release pipeline exists** (RFC-0180 phase 1), nothing writes `PUBLISHED_RELEASE` into
`install.sh` or publishes a `seeds` beside it, so the plain `curl | sudo bash` stops before
installing anything and says how to go on. Name the release and the seed list yourself: the
release is any HTTPS directory holding the files below, and the seed list a local file in the
format above (check it first with `bash install.sh --check-seeds FILE`). `sudo` passes the
`NAME=value` words before `bash` into the script's environment:

```sh
curl -fsSL https://example.org/tally/v0.1.0/install.sh |
  sudo TALLY_RELEASE=https://example.org/tally/v0.1.0 TALLY_SEEDS=/home/pi/seeds bash
```

A release therefore carries `install.sh`, `tally-feed-x86_64-linux`, `tally-feed-aarch64-linux`,
`tally-feed.service` and `seeds`, each with a `.sha256` whose first field is the file's hash. The
seed list is the publisher's configuration, not this repository's: each publisher ships the relays
it starts feeders from, each naming its operator, and checks its list with `--check-seeds`. The binaries are
built against the pinned Debian bullseye sysroot (`bazel build -c opt
--platforms=//platforms:linux_aarch64 //crates/feed:tally-feed`), so they need only glibc 2.25 or
newer and no C++ runtime: any Raspberry Pi OS from Buster on, and any current Linux.

## Run it as a container

A host that runs each feeder as a container, such as adsb.im (docker compose, amd64 and arm64),
runs the release's image, `ghcr.io/sky-commons/tally-feed:<tag>`
(`container/Dockerfile`): the same `tally-feed` binary the release publishes, on distroless with no
shell, its entrypoint the binary, so the service's `command` is the feeder's arguments. It runs as
nonroot (65532) and keeps what it learns in `/var/lib/tally-feed`, a volume. The identity is an
environment variable (`--key-env`) rather than a file, so the host keeps it in its own
configuration. Make one once, and keep its first line as the secret; the second is the receiver's
public key, its name:

```sh
docker run --rm ghcr.io/sky-commons/tally-feed:vX.Y.Z new-key
```

Then, beside the decoder (here adsb.im's `ultrafeeder`, whose BEAST output is port 30005), with a
`--relay` for each `HOST:PORT=KEY` line of the release's `seeds`:

```yaml
services:
  tally-feed:
    image: ghcr.io/sky-commons/tally-feed:vX.Y.Z # or @sha256:..., as tally-feed-image.txt names it
    restart: unless-stopped
    environment:
      TALLY_KEY: ${TALLY_KEY} # new-key's first line
    command:
      - --key-env
      - TALLY_KEY
      - --source
      - ultrafeeder:30005
      - --relay
      - HOST:PORT=KEY
      - --lat
      - ${FEEDER_LAT}
      - --lon
      - ${FEEDER_LONG}
      - --alt
      - ${FEEDER_ALT_M}m
    volumes:
      - tally-feed:/var/lib/tally-feed
volumes:
  tally-feed:
```

A 978 MHz UAT decoder adds `--uat dump978:30978`. Every flag is `tally-feed --help`'s. The image
is signed by the release workflow on its tag, like the binaries; check it before pinning it:

```sh
cosign verify ghcr.io/sky-commons/tally-feed:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/sky-commons/tally-feed:vX.Y.Z --repo sky-commons/tally
```
