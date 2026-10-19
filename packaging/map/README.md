# The map

`ghcr.io/sky-commons/tally-map` is a full aircraft map of everything a relay hears, for a relay
operator to run beside the relay (RFC-0187 §1). It is the standard tools, unmodified: readsb
decodes the relay's `--beast-out`, tar1090 draws the map, and nginx serves both. The same readsb
answers `tally-api --readsb`, so one decoder serves the map and the API.

What it gives: search, filters, aircraft details (registration, type, military and interesting
flags from the database below), trails, the table, layers, any aircraft's track by date, replay
and the heatmap, all from the relay's own data.

## Run it

The relay's `--beast-out` is plain, unauthenticated BEAST bound to loopback, so the map shares the
relay host's network. Beside a relay started with `--beast-out 127.0.0.1:30105`:

```sh
docker run -d --name tally-map --restart unless-stopped --network host --stop-timeout 30 \
  -e TALLY_MAP_API=https://api.example.org \
  -v tally-map:/var/globe_history --tmpfs /run/readsb:uid=100,gid=65534 \
  ghcr.io/sky-commons/tally-map:vX.Y.Z
```

`--stop-timeout 30` gives readsb time to write its state on the way down. `/run/readsb` is where
readsb rewrites its live JSON every second; a tmpfs (memory, owned by the image's user, uid 100)
keeps those writes off the disk. The map is then at `http://HOST:8080/`. Put it behind the host's TLS proxy to publish it.

The relay and the API run from the release's binaries (the top-level README, "Run a relay" and
"Run the API"); there is no image of either yet. With compose, the map beside them on the same
host:

```yaml
services:
  tally-map:
    image: ghcr.io/sky-commons/tally-map:vX.Y.Z # or @sha256:..., as tally-map-image.txt names it
    restart: unless-stopped
    network_mode: host # the relay's --beast-out and readsb's API are on loopback
    stop_grace_period: 30s # readsb writes its state on the way down
    environment:
      TALLY_MAP_BEAST: 127.0.0.1:30105 # tally-relay --beast-out 127.0.0.1:30105
      TALLY_MAP_API: https://api.example.org # tally-api, for routes
    volumes:
      - tally-map:/var/globe_history
    tmpfs:
      - /run/readsb:uid=100,gid=65534 # readsb's live JSON, rewritten every second, in memory
volumes:
  tally-map:
```

```sh
tally-relay --key /etc/tally/relay.key --max-upload 6Mbit/s \
  --listen 0.0.0.0:10900 --beast-out 127.0.0.1:30105 --stats-listen 127.0.0.1:10901
tally-api --relay-stats http://127.0.0.1:10901 --readsb http://127.0.0.1:30152 \
  --relay 127.0.0.1:10900=<relay key> --mlat-raw --listen 127.0.0.1:10902
```

The image is signed by the release workflow on its tag, like the binaries; check it before pinning
it:

```sh
cosign verify ghcr.io/sky-commons/tally-map:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/sky-commons/tally-map:vX.Y.Z --repo sky-commons/tally
```

## Settings

| Variable                 | Default           | What it is                                                                                                                                       |
| ------------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `TALLY_MAP_BEAST`        | `127.0.0.1:30105` | The relay's `--beast-out`, `HOST:PORT` (or readsb's `HOST,PORT`). readsb dials it and redials every 5 s while it is down.                        |
| `TALLY_MAP_TITLE`        | `Tally`           | The page's title.                                                                                                                                |
| `TALLY_MAP_API`          | unset             | The `tally-api` origin (`https://host[:port]`, no path). The map asks it for routes at `/api/0/routeset`. Unset, routes are off.                 |
| `TALLY_MAP_READSB_API`   | `127.0.0.1:30152` | Where readsb's query API listens, which `tally-api --readsb http://127.0.0.1:30152` reads. Keep it on loopback: it is unauthenticated.           |
| `TALLY_MAP_JSON_EVERY`   | `1`               | Seconds between readsb's writes of its JSON and its API's updates. `tally-api`'s streams want `0.2` (the top-level README, "Run the API").       |
| `TALLY_MAP_HISTORY_DAYS` | `8`               | Days of globe history kept (below). A day older is deleted once it is archived, never before; the map's history and heatmap reach back this far. |
| `TALLY_MAP_IPV6`         | on with IPv6      | `on` or `off`: nginx also listens on `[::]:8080`. On by default where the container has IPv6 (`/proc/net/if_inet6`), off where it has none.      |

## Ports and storage

- `8080`: the map. `/` is tar1090, `/data/` readsb's JSON (`aircraft.json`, `receiver.json`, the
  globe tiles and traces, open to any origin), `/globe_history/` the history, `/archive/` the daily
  archives (below).
- `127.0.0.1:30152` (`TALLY_MAP_READSB_API`): readsb's query API, for `tally-api`.
- `/var/globe_history`, a volume: each day's traces, the heatmap, the daily archives (in
  `archive`), and readsb's state (traces across a restart, in `internal_state`, never served). The
  archiver deletes each date's history (`YYYY/MM/DD`) once it is older than
  `TALLY_MAP_HISTORY_DAYS` (default 8) and archived, so the volume holds about that many days of
  history plus the archives. A named
  volume is created owned by the image's user (`readsb`); a bind-mounted directory must be
  writable by that user's uid (`docker run --rm --entrypoint id ghcr.io/sky-commons/tally-map:vX.Y.Z`).

Its three processes (readsb, nginx and the archiver below) run as `readsb`, not root. If any
exits, the others are stopped and the container exits with a failure, so the restart policy
brings them back together.

## The daily archives

For the open data releases (RFC-0187 §3), the image packs each finished UTC day of the globe
history into one file a release job can fetch, so nothing that publishes needs a credential on
the relay's host:

- readsb writes a day's traces until 00:55 UTC the next day and compresses them at 00:56, so
  shortly after 01:15 UTC (the archiver looks every 5 minutes) yesterday's
  `/var/globe_history/YYYY/MM/DD` becomes `/var/globe_history/archive/YYYY-MM-DD.tar`: a plain tar
  of that day's tree, rooted at `.`, as adsb.lol's globe_history releases are (readsb's trace and
  heatmap files inside, each already compressed, so the tar is not), with `ATTRIBUTION` (the data's
  licence, the ODbL, and the aircraft database's, below) and `LICENSE-aircraft-database` added at
  its root. Beside it, `YYYY-MM-DD.tar.sha256`, `sha256sum`'s line for it.
- A day whose 00:55 UTC the container's readsb did not run through (it started after) may lack
  its last traces, so it is archived as `YYYY-MM-DD.partial.tar` (and `.partial.tar.sha256`)
  instead: still useful, never mistaken for a whole day. A day a stopped container missed is
  packed, as partial, when it next runs, as long as its history is still on the volume.
- Each file is written under a temporary name and renamed, the `.sha256` first and then the tar,
  so a tar is never there without its checksum.
- The newest 7 are kept; older ones are deleted. A day's history is deleted only once it is
  archived and older than `TALLY_MAP_HISTORY_DAYS`.
- nginx serves them at `/archive/`: the directory listing (cached a minute) names the days on hand,
  and each `.tar` and `.sha256` is cached two weeks, since it never changes once named.

```sh
curl -s http://HOST:8080/archive/                    # the days on hand
curl -sO http://HOST:8080/archive/2026-10-18.tar
curl -s http://HOST:8080/archive/2026-10-18.tar.sha256 | sha256sum -c
```

The disk this takes: the archives are a second copy of the last 7 days' history, so the volume
holds `TALLY_MAP_HISTORY_DAYS` days of what readsb writes (8 by default) plus 7 days more. A day is roughly the relay's traffic in traces: a relay's region is megabytes to a few
hundred megabytes a day, and the whole world about 3 GB a day (adsb.lol's daily releases), so a
whole-world map needs about 45 GB at the defaults.

## What is in it, and their licences

All of it unmodified, each from a pinned source (`Dockerfile` names every pin):

- **tar1090**, GPL-2.0-or-later, [github.com/wiedehopf/tar1090](https://github.com/wiedehopf/tar1090)
  at commit `958e60e583c4e435de1b46526bf5392fe05728ad` (version 3.14.1824), checked by the
  tarball's sha256, installed as its own `install.sh` installs it. Its `LICENSE` and the source's
  address are in `/usr/local/share/tar1090`.
- **readsb**, Debian 13's package `readsb` version `3.14.1630+git20240609.adc080d-1`, built from
  [github.com/adsbfi/readsb](https://github.com/adsbfi/readsb) (a fork of
  [wiedehopf's readsb](https://github.com/wiedehopf/readsb)); licensed BSD-2-Clause or
  GPL-2.0-or-later or GPL-3.0-or-later (`/usr/share/doc/readsb/copyright` in the image). Its
  source, the exact source package this binary was built from, kept for good by Debian's snapshot
  archive: [snapshot.debian.org/package/readsb/3.14.1630+git20240609.adc080d-1](https://snapshot.debian.org/package/readsb/3.14.1630%2Bgit20240609.adc080d-1/).
- **nginx** `1.26.3-3+deb13u9` and **tini** `0.19.0-3+b8`, Debian 13's packages (BSD-2-Clause;
  MIT). Every Debian package comes from snapshot.debian.org as it was at `20261005T000000Z`
  (`DEBIAN_SNAPSHOT` in the `Dockerfile`, with its security updates), so each stays installable at
  its version.
- **The aircraft database**: [Mictronics' aircraft database](https://github.com/Mictronics/aircraft-database)
  at commit `e7ff3f1474334b3f00d50a6661ef1c16754721a5` (2026-10-18), under the
  [Open Data Commons Attribution License](https://opendatacommons.org/licenses/by/1-0/) (ODC-By
  1.0), which lets anyone share and adapt it with attribution: _aircraft data from the Mictronics
  aircraft database, mictronics.de, ODC-By 1.0_. The map's page credits it (tar1090's
  `imageConfigText`, "Aircraft data: Mictronics aircraft database, ODC-By 1.0", linking to its
  repository), its licence is served beside the browser database (`/db-*/LICENSE.txt`) and is in
  the image at `/usr/local/share/tally-map/LICENSE-aircraft-database`, and each daily archive
  names it in its `ATTRIBUTION`. `aircraft_db.py` converts it at build
  time into readsb's `--db-file` and tar1090's browser database; the columns it fills are the
  address, registration, ICAO type code, the military and interesting flags, and the type's
  description. No open source carries the PIA and LADD flags, the year built or the owner, so
  those columns are empty. readsb marks the military address blocks as military itself.
- **Airport positions** (the map's "jump to airport"): [OurAirports](https://ourairports.com/data/)
  ([github.com/davidmegginson/ourairports-data](https://github.com/davidmegginson/ourairports-data)
  at commit `b529623d2a0b09a9be78d37fc7a7a5e1e16e3451`), public domain (The Unlicense).

tar1090 usually ships [tar1090-db](https://github.com/wiedehopf/tar1090-db), which this image does
not: neither it nor what it merges in (an ADS-B Exchange download among them) states a licence
that lets anyone redistribute it.
