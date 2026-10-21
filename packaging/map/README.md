# The map

`ghcr.io/sky-commons/tally-map` is a full aircraft map of everything a relay hears, for a relay
operator to run beside the relay (RFC-0187 §1). It is the standard tools, unmodified: readsb
decodes the relay's `--beast-out`, tar1090 draws the map, and nginx serves both. The same readsb
answers `tally-api --readsb`, so one decoder serves the map and the API.

What it gives: search, filters, aircraft details (registration, type, military and interesting
flags from the database below), trails, the table, layers, any aircraft's track by date, replay
and the heatmap, all from the relay's own data.

It also answers adsb.lol's short links and gives a link to an aircraft a preview card, its name and
a picture of the map where it is (below, "Short links and previews").

What it never shows is a receiver (docs/relay-operators.md: a receiver's site reaches only
relays). It is a relay-side tool, on the relay's host, but everything it reads is what a client
may hold: the relay's `--beast-out` gives each reception's message alone, with no receiver's
counter or signal level, which against the aircraft positions anyone reads would place the
receiver. Its readsb is given no location, so `receiver.json` names none, no range outline is
written and no aircraft carries a distance or direction from one; tar1090 is set to draw no site
marker, range rings or range outline. Do not give readsb a location, or feed it from anything
else.

## Run it

The relay's `--beast-out` is plain, unauthenticated BEAST bound to loopback, so the map shares the
relay host's network. Beside a relay started with `--beast-out 127.0.0.1:30105`:

```sh
docker run -d --name tally-map --restart unless-stopped --network host --stop-timeout 30 \
  -e TALLY_MAP_MAX_UPLOAD=2Mbit/s -e TALLY_MAP_API=https://api.example.org \
  -v tally-map:/var/globe_history --tmpfs /run/readsb:uid=100,gid=65534 \
  ghcr.io/sky-commons/tally-map:vX.Y.Z
```

`--stop-timeout 30` gives readsb time to write its state on the way down. `/run/readsb` is where
readsb rewrites its live JSON every second; a tmpfs (memory, owned by the image's user, uid 100)
keeps those writes off the disk. `TALLY_MAP_MAX_UPLOAD` is required: the most the map sends a
second (below, "What it sends"). The map is then at `http://HOST:8080/`. Put it behind the host's
TLS proxy to publish it.

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
      TALLY_MAP_ACARS: 127.0.0.1:30106 # tally-relay --acars-out 127.0.0.1:30106, for the archives
      TALLY_MAP_API: https://api.example.org # tally-api, for routes
      TALLY_MAP_MAX_UPLOAD: 2Mbit/s # the most the map sends a second, all visitors together
    volumes:
      - tally-map:/var/globe_history
    tmpfs:
      - /run/readsb:uid=100,gid=65534 # readsb's live JSON, rewritten every second, in memory
volumes:
  tally-map:
```

```sh
tally-relay --key /etc/tally/relay.key --max-upload 6Mbit/s \
  --listen 0.0.0.0:10900 --beast-out 127.0.0.1:30105 --acars-out 127.0.0.1:30106 \
  --stats-listen 127.0.0.1:10901
tally-api --relay-stats http://127.0.0.1:10901 --readsb http://127.0.0.1:30152 \
  --relay 127.0.0.1:10900=<relay key> --listen 127.0.0.1:10902
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

| Variable                       | Default           | What it is                                                                                                                                       |
| ------------------------------ | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `TALLY_MAP_BEAST`              | `127.0.0.1:30105` | The relay's `--beast-out`, `HOST:PORT` (or readsb's `HOST,PORT`). readsb dials it and redials every 5 s while it is down.                        |
| `TALLY_MAP_ACARS`              | unset             | The relay's `--acars-out`, `HOST:PORT`: each ACARS, VDL2 and HFDL message, copies merged, filed into its UTC day's archive (below). Unset, none. |
| `TALLY_MAP_ACARS_DAY_MAX`      | `268435456`       | The most bytes of ACARS lines kept for one day; past it the rest of the day's are dropped. As it is packed, it takes three times that on disk.   |
| `TALLY_MAP_TITLE`              | `Tally`           | The page's title, and the site a preview names.                                                                                                  |
| `TALLY_MAP_API`                | unset             | The `tally-api` origin (`https://host[:port]`, no path). The map asks it for routes at `/api/0/routeset`. Unset, routes are off.                 |
| `TALLY_MAP_URL`                | unset             | The map's public origin (`https://host[:port]`), which a preview's links name in full. Unset, `https://` and the host asked for.                 |
| `TALLY_MAP_TILES`              | OpenStreetMap     | The tile server the previews' pictures are drawn from (`https://host[:port]`, tiles at `/{z}/{x}/{y}.png`). Unset, `https://tile.openstreetmap.org`.|
| `TALLY_MAP_READSB_API`         | `127.0.0.1:30152` | Where readsb's query API listens, which `tally-api --readsb http://127.0.0.1:30152` reads. Keep it on loopback: it is unauthenticated.           |
| `TALLY_MAP_JSON_EVERY`         | `1`               | Seconds between readsb's writes of its JSON and its API's updates. `tally-api`'s streams want `0.2` (the top-level README, "Run the API").       |
| `TALLY_MAP_HISTORY_DAYS`       | `8`               | Days of globe history kept (below). A day older is deleted once it is archived, never before; the map's history and heatmap reach back this far. |
| `TALLY_MAP_IPV6`               | on with IPv6      | `on` or `off`: nginx also listens on `[::]:8080`. On by default where the container has IPv6 (`/proc/net/if_inet6`), off where it has none.      |
| `TALLY_MAP_MAX_UPLOAD`         | required          | The most nginx sends a second, every visitor together: a rate as `tally-relay --max-upload` takes it (`2Mbit/s`, `250kB/s`, `1MiB/s`). Below.    |
| `TALLY_MAP_CLIENT_IP_HEADER`   | unset             | The header a proxy in front names each visitor in (`CF-Connecting-IP` behind Cloudflare). Unset, a visitor is the address it connects from.      |
| `TALLY_MAP_TRUSTED_PROXIES`    | unset             | The proxies whose header is believed: CIDRs or addresses, separated by commas or spaces. Set exactly when `TALLY_MAP_CLIENT_IP_HEADER` is.       |
| `TALLY_MAP_ARCHIVE_PUBLIC`     | `on`              | `on` or `off`: `/archive/` is open to anyone. Off, it answers 404 to any request without the token below.                                        |
| `TALLY_MAP_ARCHIVE_TOKEN_FILE` | unset             | A file holding that token (one line of at least 32 letters, digits, `_` or `-`: `openssl rand -hex 32`), readable by uid 100. Required when off. |

## What it sends

Everything the map sends is bounded by one figure, `TALLY_MAP_MAX_UPLOAD`, the ceiling: the map
sends no more than that a second, whatever its visitors ask, so its month is at most the ceiling
times 2,678,400 (the seconds in 31 days), plus a second's burst on each response. `2Mbit/s` is at
most 670 GB in 31 days. It takes the same units as the relay's `--max-upload` (bits a second as
links are stated, bytes a second, or the binary units), so the two caps of one host add up in the
same terms against its plan: on the top-level README's Lightsail example, the relay's `6Mbit/s` and
the map's `2Mbit/s` are at most 2.68 TB of the plan's 3 TB, leaving about 0.3 TB for what comes in.

nginx has no shared budget of bytes. It can hold one response to a rate (`limit_rate`) and a group
of responses to a number at once (`limit_conn`). So the image puts every response in one of three
classes, each a number of slots at a rate, and derives every slot's rate from the ceiling at start
(rounded down, and printed in the container's log):

| Class   | Serves                             | Share of the ceiling | Slots, all visitors | A slot's rate | One visitor at once |
| ------- | ---------------------------------- | -------------------- | ------------------- | ------------- | ------------------- |
| live    | `/data/`, and the page's own files | half                 | 8                   | ceiling / 16  | 4 (of `/data/`)     |
| history | `/globe_history/`                  | a quarter            | 4                   | ceiling / 16  | 2                   |
| archive | `/archive/`                        | a quarter            | 2                   | ceiling / 8   | 1                   |

The slots times the rates add up to the ceiling, so all of them together cannot send more. At
`2Mbit/s` (250,000 bytes a second), a live or history response goes at 15,625 bytes a second and an
archive at 31,250; at `8Mbit/s`, four times that. The cost of a hard ceiling is that a response
keeps to its slot's rate even when the other slots are idle.

A request that finds its class's slots taken, or its visitor's share of them, is answered `503`; a
visitor asking more than 20 requests a second over `/data/`, `/globe_history/`, `/archive/`, the
page itself (`/` and `index.html`, which may ask readsb for a link's preview, below) and the
previews' pictures, with 40 more queued, is answered `429`, a figure of what one map page asks, not
of bytes, so it does not move with the ceiling. Each says when to come back in `Retry-After` (1 s
for the page and `/data/`, 5 s for the history, 60 s for an archive). The page itself and the
pictures are held to a visitor's share of the live slots too, 4, as `/data/` is. The page's other
files have no per-visitor limit, since a browser asks for them all at once and one refused breaks
the page; they are fixed, and a caching proxy keeps them two weeks (`Cache-Control`), so few reach
the map. A request refused before it is served (a limit's answer, a closed archive's 404) is an
error page of a couple of hundred bytes, no larger than the request.

**Who a visitor is.** Behind a proxy every request comes from the proxy's address, so every
visitor would share one visitor's limits. `TALLY_MAP_CLIENT_IP_HEADER` names the header the proxy
puts the visitor's address in, and `TALLY_MAP_TRUSTED_PROXIES` the proxies believed (nginx's
`realip`): a request from anywhere else is the address it comes from, whatever header it carries.
Behind a Cloudflare tunnel, `cloudflared` on the same host connects from loopback:

```sh
-e TALLY_MAP_CLIENT_IP_HEADER=CF-Connecting-IP -e TALLY_MAP_TRUSTED_PROXIES=127.0.0.1,::1
```

A visitor is one address; an IPv6 visitor holding a whole /64 can be many, but no more than the
ceiling between them.

**Closing the archive.** A release job needs the archives; nobody else need fetch them from the
map's public name. With `TALLY_MAP_ARCHIVE_PUBLIC=off`, `/archive/` answers 404 (cached by nobody)
unless the request carries `Authorization: Bearer TOKEN`, the token in
`TALLY_MAP_ARCHIVE_TOKEN_FILE`, and what it serves is `Cache-Control: private`, so no shared cache
keeps it for another visitor:

```sh
openssl rand -hex 32 > archive-token && chmod 644 archive-token
docker run ... -e TALLY_MAP_ARCHIVE_PUBLIC=off -e TALLY_MAP_ARCHIVE_TOKEN_FILE=/run/secrets/archive-token \
  -v "$PWD/archive-token:/run/secrets/archive-token:ro" ...
curl -sO -H "Authorization: Bearer $(cat archive-token)" https://map.example.org/archive/2026-10-18.tar
```

nginx compares the token as a regular expression does, not in constant time; a token of 64 random
characters leaves its timing nothing worth telling.

## Short links and previews

The map answers adsb.lol's short links, each a redirect to tar1090's own query, with or without a
trailing slash, and with the link's own query carried on after it (`/a1b2c3?zoom=9` goes to
`/?icao=a1b2c3&zoom=9`):

| Link                    | Goes to                     |
| ----------------------- | --------------------------- |
| `/<hex>`                | `/?icao=<hex>`              |
| `/<registration>`       | `/?reg=<registration>`      |
| `/<lat>,<lon>[,<zoom>]` | `/?lat=..&lon=..[&zoom=..]` |

A hex is six hex digits, or tar1090's `~` and six for an address that is not ICAO's; a
registration 3 to 8 letters, digits and one hyphen, with a letter; a place a latitude to 90, a
longitude to 180 and a zoom to 20. Any other path that is not one of the page's own files is the
map's not-found page, which links back to the site. The site's short links
(`tally.skycommons.org/<hex>`) hand off to these, so the rules are the map's alone.

A chat app or a social site reads a link's Open Graph tags to draw its card, and does not run the
page's JavaScript. So when the page is asked for one aircraft (`?icao=`, or `?reg=`, which every
aircraft short link goes to), nginx asks readsb's query API for it (`preview.lua`, nginx's Lua
module) and puts its tags in the page's head:

- the title, its callsign, registration and type, each it has (`RYR4AB · EI-EFZ · BOEING 737-800`);
- the description, its altitude and speed (`36,000 ft · 452 kt`), or `Not heard right now`;
- the picture (`summary_large_image`, 1200 by 630): the map around where readsb hears it now, with
  one marker on it, at `/preview/<hex>/<lat>,<lon>.jpg`, the position rounded to 0.01 degrees; or,
  for an aircraft readsb does not place, the site's card (`/card.jpg`);
- `og:url`, the link itself, from `TALLY_MAP_URL`.

The card shows the aircraft's position, which the map shows anyone. It shows nothing of a
receiver: readsb here has none, and none of the fields readsb writes of its own (`r_dst`, `r_dir`,
`rssi`) is read.

The picture is drawn by `preview.py` with komoot's [staticmap](https://github.com/komoot/staticmap)
over OpenStreetMap's standard tiles (`tile.openstreetmap.org`, or the server `TALLY_MAP_TILES`
names, which serves the same tiles), the layer tar1090 draws by default, credited in the picture ("©
OpenStreetMap contributors") as [OpenStreetMap's tile
policy](https://operations.osmfoundation.org/policies/tiles/) asks. The policy asks a client to name
itself, to cache, and to keep its use light: nginx fetches every tile for it, naming the image in
its User-Agent, keeps each as long as OpenStreetMap's headers say and at least a week, fetches one
tile once however many ask (`proxy_cache_lock`), and asks no more than 10 tiles a second. A picture
draws only near where readsb hears the aircraft now (within a degree), so nobody can have the map
draw anywhere else; anything it cannot draw is answered the site's card.

What a preview costs:

- **The page asked for an aircraft:** one question of readsb on loopback, answered within 250 ms to
  connect and 250 ms to answer, or the page is served with its tags but no aircraft. While it waits
  it holds one of the live class's 8 slots, and a visitor holds at most 4 of them at once and asks
  at most 20 pages a second (40 more queued); so the worst a visitor can do is hold half the live
  slots for half a second at a time.
- **A picture:** drawn at most once a minute for one aircraft at one rounded position (nginx's
  cache), one at a time with two waiting; one that waits past 10 s, or is refused, is the site's
  card. A drawing takes about a second and about 75 MB of memory at its peak, and `preview.py` may
  take no more than 768 MiB of address space. About twenty tiles a drawing, each fetched once a
  week at most. A picture is about 75 KB, the card 25 KB, both sent in the page's class.
- **Disk:** the cached pictures at most 32 MB and the tiles at most 128 MB, in the container's own
  `/var/cache/tally-map` (gone with the container, and filled again as they are asked for).

The image is 253 MB unpacked (69 MB to pull); the previews are 86 MB of it (Python, Pillow and
requests for the pictures, nginx's Lua module for the tags), 21 MB of the pull.

## Ports and storage

- `8080`: the map. `/` is tar1090 (with the short links, the previews' pictures at `/preview/` and
  the site's card at `/card.jpg`, above), `/data/` readsb's JSON (`aircraft.json`, `receiver.json`,
  the globe tiles and traces, open to any origin), `/globe_history/` the history, `/archive/` the
  daily archives (below).
- `127.0.0.1:30152` (`TALLY_MAP_READSB_API`): readsb's query API, for `tally-api` and the
  previews.
- `/var/cache/tally-map`, the container's own: the previews' pictures and OpenStreetMap's tiles
  (above, "Short links and previews"), at most 160 MB.
- `/var/globe_history`, a volume: each day's traces, the heatmap, the daily archives (in
  `archive`), and readsb's state (traces across a restart, in `internal_state`, never served). The
  archiver deletes each date's history (`YYYY/MM/DD`) once it is older than
  `TALLY_MAP_HISTORY_DAYS` (default 8) and archived, so the volume holds about that many days of
  history plus the archives. A named
  volume is created owned by the image's user (`readsb`); a bind-mounted directory must be
  writable by that user's uid (`docker run --rm --entrypoint id ghcr.io/sky-commons/tally-map:vX.Y.Z`).

Its processes (readsb, nginx, the archiver and the ACARS collector below) run as `readsb`, not
root. If any exits, the others are stopped and the container exits with a failure, so the restart policy
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
- With `TALLY_MAP_ACARS` set, the collector (`tally-acars-collect`, crates/acars-collect) reads
  the relay's `--acars-out`, where every line is one ACARS message in the wire's one flat schema
  (`tally_wire::acars`: the aircraft's address, registration and flight, the ground station, the
  message's label, sublabel, block, number, mode and acknowledgement, its text and
  its time to the second, each spelled as libacars spells it; no decoder's frame tree or libacars
  decode, which differ by decoder, version and setting). Every receiver's copy of a message is
  the same line but for its time (RFC-0187 §3 says where it is not: a message reassembled by one
  receiver and not another), so the collector holds each message 30 s
  from its first copy's arrival, counts every copy that comes meanwhile, and writes it once, timed
  at the median of the copies' seconds (with an even count, the floor of the mean of the middle
  two), so no one receiver's clock shows; the earliest second would always be the slowest
  clock's. A copy that comes after its message is written is dropped and counted for the next
  5 minutes. It files each message into the UTC day of its own time, `YYYY/MM/DD/acars.jsonl` (no
  `acars.*` file is served at `/globe_history/`), dropping one more than 5 minutes from its
  arrival, and never writes a day from 01:10 UTC the next or once it is packed (its lines are
  dropped and counted in the log); a line a crash cut short is cut off when the file is next
  opened. What a day missed goes in its `acars.gaps`, one `FROM TO WHY` a line in Unix seconds,
  written as a gap opens (`TO` is `-`) and again once it closes: `down` while the relay was not
  read (from the last time it was, which the collector keeps in `archive/.acars-read` about once a
  minute, never later than the oldest message it holds, and as it stops, until it connects again; at start, before the archiver runs, over every
  day still on the volume and not packed), `write` from the first line it could not write to the
  next it could, `full` while new messages were dropped because 8 MiB of them were already held,
  `skew` while messages came timed more than 5 minutes from their arrival (a clock is wrong),
  `cap` once the day reached `TALLY_MAP_ACARS_DAY_MAX`; a gap never closed ran to the day's end.
  A `down` or `skew` gap is in every day a message arriving in it may be filed in, from 5 minutes
  before it to 5 minutes after, so a gap just past midnight is the day before's too. The
  archiver sorts the day by each message's own time, keeping only lines in the schema and a
  message once in any 5 minutes (its earliest line: a restart can write one twice), and
  compresses it into that day's tar as `acars.jsonl.gz` (written under a temporary name and
  renamed before the `.jsonl` is removed, so a day holding both is a pack cut short, and its
  `.jsonl` is packed again); a day with an `acars.gaps` is packed as partial, the file with it.
- **What ACARS costs:** the collector holds at most 8 MiB of messages waiting for their copies and
  65,536 written messages' keys (`tally_acars_collect::COLLECT_MEMORY`, about 12.5 MiB, its
  bookkeeping measured), and peaked at 14.0 MiB resident with both full. The sort is an external
  merge, its runs in `archive/.sorting` on the volume (never served), and holds at most 16.7 MiB
  (`tally_acars_collect::SORT_MEMORY`: a run, three line buffers, its read and write buffers, and
  the keys of the last 5 minutes' messages, at most 65,536) whatever the day's size (a 120 MB day
  peaked at 13.5 MiB resident, and 17.5 MiB with 65,536 keys held); so ACARS adds about 32 MiB to
  the container's memory, both processes included. On disk, a day's file is at most
  `TALLY_MAP_ACARS_DAY_MAX`, and three times that while it is sorted (the file, the runs, and the
  run they merge into).
- A day whose 00:55 UTC the container's readsb did not run through (it started after) may lack
  its last traces, so it is archived as `YYYY-MM-DD.partial.tar` (and `.partial.tar.sha256`)
  instead: still useful, never mistaken for a whole day. A day a stopped container missed is
  packed, as partial, when it next runs, as long as its history is still on the volume.
- Each file is written under a temporary name and renamed, the `.sha256` first and then the tar,
  so a tar is never there without its checksum.
- The newest 7 are kept; older ones are deleted. A day's history is deleted only once it is
  archived and older than `TALLY_MAP_HISTORY_DAYS`.
- nginx serves them at `/archive/`: the directory listing (cached a minute) names the days on hand,
  and each `.tar` and `.sha256` is cached two weeks, since it never changes once named. Two are
  sent at once, one to a visitor, each at an eighth of the ceiling (above, "What it sends"), and
  `TALLY_MAP_ARCHIVE_PUBLIC=off` keeps them to a release job holding the token.

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
- **nginx** `1.26.3-3+deb13u9`, its Lua module `libnginx-mod-http-lua` `1:0.10.28-2` (with LuaJIT,
  lua-resty-core, lua-resty-lrucache and the NDK), **lua-cjson** `2.1.0+dfsg-2.2+b2` and **tini**
  `0.19.0-3+b8`, Debian 13's packages (BSD-2-Clause; BSD-2-Clause, MIT and BSD-3-Clause; MIT;
  MIT). Every Debian package comes from snapshot.debian.org as it was at `20261005T000000Z`
  (`DEBIAN_SNAPSHOT` in the `Dockerfile`, with its security updates), so each stays installable at
  its version.
- **Python 3**, **Pillow** `11.1.0-5+deb13u4`, **requests** `2.32.3+dfsg-5+deb13u1` and
  **ca-certificates** `20250419`, Debian 13's packages (PSF-2.0; MIT-CMU; Apache-2.0; MPL-2.0), and
  **staticmap** 0.5.7, [komoot/staticmap](https://github.com/komoot/staticmap), Apache-2.0, the
  wheel PyPI publishes, checked by its sha256, unmodified (its licence in
  `/usr/local/lib/tally-map/LICENSE-staticmap`).
- **The previews' maps**: OpenStreetMap's standard tiles, fetched as they are asked for, not
  shipped; map data © OpenStreetMap contributors, under the ODbL, credited in every picture.
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
