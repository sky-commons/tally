# RFC-0187: Parity with the open aggregators

Status: accepted, in progress (2026-10-19)

## Why

A feeder chooses where to send its data by what it gets back. adsb.lol, the largest community
aggregator, gives a full map, aircraft details, history, an ADS-B Exchange-compatible API, routes,
an "am I feeding" check and daily open data. Tally gives a map of dots, a leaderboard and a station
page. Tally's difference (no single operator, data signed at the antenna, relays anyone runs) only
counts once a feeder loses nothing by choosing it.

adsb.lol is open source (github.com/adsblol), and nearly all of it is the standard tools run as a
service: readsb (the decoder), tar1090 (the map) and mlat-server, plus a small API (BSD-3) and daily
GitHub releases. The inventory, read from its repositories on 2026-10-19:

| They offer | Built from | Here |
| --- | --- | --- |
| Map: search, filters, details, trails, table, layers | tar1090 over readsb | §1 |
| Registration, type, military / PIA / LADD flags | readsb `--db-file` | §1 |
| Any aircraft's track by date, replay, heatmap | readsb globe history, tar1090 | §1 |
| ADS-B Exchange v2 API (`/v2/hex`, `/v2/callsign`, `/v2/point`, ...) | their API over readsb's query port | §2 |
| Routes, checked against the aircraft's position | VRS standing-data (CC0) | §2 |
| "Am I feeding" by the visitor's IP; a map of one feeder's aircraft | their API | §2 |
| MLAT sync map and per-feeder sync figures | mlat-server, sync map (MIT) | §3 |
| Daily history and ACARS releases | readsb globe history; a collector | §3 |
| Link previews, short URLs, status page, hardware guide | nginx Lua, Playwright, Upptime | §3 |

Where Tally is already ahead: leaderboards, signed provenance, relays anyone can run.

## §1 The map bundle

Tally's release publishes a second image, `ghcr.io/sky-commons/tally-map`, built and signed like
`tally-feed`'s: readsb (Debian's wiedehopf build) with the aircraft database, tar1090 at a pinned
commit, and nginx. It is one more thing a relay operator runs, not a Flightlines service:

- readsb is net-only and reads the relay's `--beast-out` (`TALLY_MAP_BEAST`, default
  `127.0.0.1:30105`). It writes the globe index, the globe history (a volume at
  `/var/globe_history`) and the heatmap, and serves its query API on `127.0.0.1:30152`, which
  `tally-api --readsb` reads. One readsb serves the map and the API.
- nginx serves tar1090 on `:8080`, with readsb's JSON at `/data/` and history at `/globe_history/`.
- tar1090's config is written at start from the environment: the page's title, and
  `TALLY_MAP_API`, the `tally-api` origin its routes are asked of (§2).
- The aircraft database is a file baked into the image at release, from a source whose licence
  lets anyone redistribute it (CC0, public domain, ODbL or CC BY). The image's README names it.

tar1090 is GPL-2.0+ and readsb GPL-3.0+: the image carries their sources' URLs and commits, and
neither is modified.

## §2 The API catches up

`tally-api` gains, beside `/v1`:

- **`/v2/...`, ADS-B Exchange-compatible**, the paths and answers adsb.lol's `api_v2.py` serves:
  `/v2/hex/{hex}` (`/v2/icao/`), `/v2/callsign/{cs}`, `/v2/registration/{reg}` (`/v2/reg/`),
  `/v2/type/{type}`, `/v2/squawk/{sq}` (`/v2/sqk/`), `/v2/mil`, `/v2/ladd`, `/v2/pia`,
  `/v2/point/{lat}/{lon}/{radius}` (`/v2/lat/{lat}/lon/{lon}/dist/{radius}`, radius at most 250 nm)
  and `/v2/closest/{lat}/{lon}/{radius}`. Each is one query of readsb's API port.
- **Routes:** `POST /api/0/routeset` (the shape tar1090's `routeApiUrl` asks) and
  `GET /api/0/route/{callsign}/{lat}/{lon}`, from VRS standing-data (CC0, refreshed daily), with
  adsb.lol's plausibility check against where the aircraft is.
- **`GET /v1/me`:** the stations whose newest session came from the asking client's address (the
  relay's `/stations` names each session's address, on its loopback stats port only). Nothing but
  the asker's own stations is ever answered.

## §3 Everything else

- **MLAT health:** each station's MLAT figures (peers it is synchronised with, clock error) on its
  page and a network sync map, from the clock models relays already sign.
- **Open data releases:** each day's readsb history as a GitHub release of the Sky Commons
  organisation, under ODbL.
- **ACARS, VDL2 and HFDL:** `tally-feed --acars HOST:PORT` publishes a local decoder's JSON lines in
  its signed batches, as `--uat` does, and they join the daily release.
- **Previews and short URLs** (`/<hex>`, `/<registration>`), a status page and a hardware guide on
  the site.

## Rollout

1. The map bundle in a release; the public relay runs it (map at `tally-map.skycommons.org`).
2. `/v2`, routes and `/v1/me` in a release; the site's "am I feeding" and the map's routes.
3. §3, each in its own change.
