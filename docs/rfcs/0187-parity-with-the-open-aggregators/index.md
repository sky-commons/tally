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
- It places no receiver (RFC-0171 §3.5, amended 2026-10-19: a receiver's site reaches only
  relays). `--beast-out` gives each reception's message alone, no receiver's counter or signal
  level; readsb is given no location, so it names no site and gives no aircraft a distance or
  direction from one; tar1090 draws no site marker, range rings or range outline. The `/v2`
  answers (§2) drop readsb's `r_dst`, `r_dir` and `rssi` whatever readsb `--readsb` names.
- What the map sends is bounded by a ceiling its operator states, `TALLY_MAP_MAX_UPLOAD`, in the
  relay's `--max-upload` units, since a relay host's plan is billed for both (the reference
  deployment is a Lightsail node whose whole plan is 3 TB a month). nginx has no shared budget of
  bytes, only a rate per response and a count of responses at once, so every response is in one
  class (the live JSON and the page; the history; the archives), each class a zone keyed on a
  constant holding it to a number of slots at a rate derived from the ceiling, and the classes'
  slots times rates add up to the ceiling. Each visitor is also held to its share of slots and to
  a request rate, keyed on its own address: behind a proxy, the address the proxy's header names
  (`TALLY_MAP_CLIENT_IP_HEADER`), believed only from the proxies named
  (`TALLY_MAP_TRUSTED_PROXIES`). A refusal is `429` or `503` with `Retry-After`. The image's
  README gives the figures.
- The aircraft database is a file baked into the image at release, from a source whose licence
  lets anyone redistribute it (CC0, public domain, ODbL, CC BY, or ODC-By 1.0, the Open Data
  Commons Attribution License, the database counterpart of CC BY). The image's README names it.
  The source is Mictronics' aircraft database (github.com/Mictronics/aircraft-database, ODC-By
  1.0), at a pinned commit; the map credits it on its page, serves its licence beside it, and
  names it in each daily archive. Rejected:
  - tar1090-db, tar1090's usual database: it states no licence, and merges an ADS-B Exchange
    download that states none either.
  - The OpenSky Network's aircraft database: its terms license non-profit research, education
    and government use only, which no open release can carry.
  - The FAA's releasable aircraft file: public domain, but it covers only US-registered aircraft.

tar1090 is GPL-2.0+ and readsb GPL-3.0+: the image carries their sources' URLs and commits, and
neither is modified.

## §2 The API catches up

`tally-api` gains, beside `/v1`:

- **`/v2/...`, ADS-B Exchange-compatible**, the paths and answers adsb.lol's `api_v2.py` serves:
  `/v2/hex/{hex}` (`/v2/icao/`), `/v2/callsign/{cs}`, `/v2/registration/{reg}` (`/v2/reg/`),
  `/v2/type/{type}`, `/v2/squawk/{sq}` (`/v2/sqk/`), `/v2/mil`, `/v2/ladd`, `/v2/pia`,
  `/v2/point/{lat}/{lon}/{radius}` (`/v2/lat/{lat}/lon/{lon}/dist/{radius}`, radius at most 250 nm)
  and `/v2/closest/{lat}/{lon}/{radius}`. Each is one query of readsb's API port, served as
  readsb answers it less what it says of its own receiver (`r_dst`, `r_dir`, `rssi`), which with
  the aircraft's position would place that receiver.
- **Routes:** `POST /api/0/routeset` (the shape tar1090's `routeApiUrl` asks) and
  `GET /api/0/route/{callsign}/{lat}/{lon}`, from VRS standing-data (CC0, refreshed daily), each
  judged against where the aircraft is. The judgment keeps adsb.lol's threshold (50 nm or a fifth
  of the leg, whichever is more) and its rounding (three decimals), but measures the real distance
  from the aircraft to the great-circle leg (an end, or the cross-track foot between them). Its
  check cannot be ported as written: `calc_plausible` tests the tuple `_plausible_sync` returns,
  which is always true, so every route reads plausible, and the distance it compares is not a
  distance from the leg, so an aircraft arriving at the second airport fails it. The legs are the
  route's own, code after code; a leg with an airport the data does not hold is skipped, never
  bridged, and a route with no known leg is judged `null`. A callsign is at most eight characters
  and a routeset body at most 16 KiB.
- **`GET /v1/me`:** the asking client's own stations, and nothing else, ever. A station is the
  asker's while a session of it is connected to the relay from the asker's host: an IPv4 address
  exactly, or an IPv6 /64 (a dual-stack home feeds and browses from different addresses of one
  /64), an IPv4 address written as IPv6 the same as itself. Only a connected session has an
  address: once it ends the relay drops it, since a dynamic address may be reassigned to a
  stranger. A client whose address is not known (behind the proxy, a missing or unparseable
  client header, never the proxy's own address), or is loopback or unspecified, is answered none.
  The relay's `/stations` names each connected session's address, and its stats port is loopback
  only by refusal: `--stats-listen` on any other address stops the relay at start. It answers
  keys and traffic, never where a station is.

## §3 Everything else

- **MLAT health:** each station's MLAT figures (peers it is synchronised with, clock error) on its
  page and a network sync map, from the clock models relays already sign.
- **Open data releases:** each day's readsb history as a GitHub release of the Sky Commons
  organisation, under ODbL. The map image packs each UTC day D into one tar at
  `/archive/YYYY-MM-DD.tar` (its `.sha256` written first), with an ATTRIBUTION file naming the
  ODbL and the aircraft database's ODC-By source. readsb writes D's traces until 00:55 UTC on
  D+1 and compresses them at 00:56, so D is packed from 01:15 UTC on D+1; a day whose 00:55 UTC
  readsb was not running through (the container started after it) is packed as
  `YYYY-MM-DD.partial.tar`, since its last traces may be missing, and a release marks it so.
  The image keeps the newest 7 archives, and deletes a day's history once it is older than
  `TALLY_MAP_HISTORY_DAYS` (default 8) and packed, never before. The archives are sent within the
  map's ceiling (§1), two at once and one to a visitor; `TALLY_MAP_ARCHIVE_PUBLIC=off` answers 404
  to a request without the bearer token in `TALLY_MAP_ARCHIVE_TOKEN_FILE`, so an operator can keep
  them off its public name while its release job still fetches them.
- **ACARS, VDL2 and HFDL:** `tally-feed --acars HOST:PORT` publishes a local decoder's JSON lines in
  its signed batches, as `--uat` does, and they join the daily release. The decoders' JSON goes
  out over UDP or ZeroMQ (acarsdec only UDP), so the way in is acars_router, which takes it and
  serves one JSON object a line over TCP (`AR_SERVE_TCP_ACARS` 15550, `_VDLM2` 15555, `_HFDL`
  15556); `--acars` is repeatable. Message text can carry personal data, and some jurisdictions
  restrict disclosing intercepted content (in the UK, the Wireless Telegraphy Act 2006 s48), so it
  is opt-in: the installer prints the flag and never adds it.

  **What is published.** The privacy rule: no published field is finer than a receiver's public cell
  or names a receiver, and nothing carries reception timing below a second, or signal. So the
  station, signal, frequency, channel and error counts are dropped and the time is cut to the whole
  second, as every client form drops a receiver's signal and BEAST counter. What a decoder, its
  version and settings leave different in a receiver's copies is not a privacy defect: grouping one
  receiver's lines by those differences reveals at most its VHF or HF coverage, the ground stations
  and aircraft in its radio range, which is coarser than the public cell already published. Merging
  every receiver's copies into one message is data quality. What a line is has one rule,
  `tally_wire::acars::project`: one fixed, flat schema for all three decoders (`t`, `kind`, `icao`,
  `reg`, `flight`, `gs`, `label`, `sublabel`, `block`, `msgnum`, `mode`, `ack`, `text`, each only if
  the decoder gave it, mapped from each decoder's own fields), every field spelled as libacars
  spells it (a registration without dots or dashes, an ACK `^` and a NAK `!`, the sublabel and MFI
  left in the text and the sublabel read from it by libacars' one rule, a message number and flight
  on a downlink block alone, no broadcast address `FFFFFF`), written canonically (keys sorted, no
  spacing, strings escaped one way); no key twice; at most 16 KiB. vdlm2dec's lines are VDL2, its
  ground station's address `gs`. HFDL carries no aircraft address: dumphfdl takes it from its own
  cache of logons, not from the message, so two receivers' copies would differ by it. The decoders'
  own trees (dumpvdl2's AVLC, dumphfdl's LPDU and SPDU, libacars' decodes) are not published: they
  differ by decoder, version and configuration, so copies would not merge. A frame that carries no
  ACARS message (an XID, X.25 or CPDLC without ACARS, an HFDL logon or performance report, an SPDU),
  and one its decoder says is damaged or partial (libacars' `err` or `crc_ok` false, a block with
  more to follow by libacars' `more` or acarsdec's and vdlm2dec's `end`, an acarsdec `assstat` other
  than `complete` or `skipped`), is dropped, counted. The feeder publishes a decoder's line as its
  projection, and the relay's `--acars-out` and the collector take only a line the schema writes
  byte for byte (`tally_wire::acars::line`).

  **How it travels.** The feeder holds the messages, in the reader before they queue beside BEAST,
  to `--acars-ceiling` (8000 bytes a second) of `--ceiling` and to 256 of the queue's places, one
  share for every `--acars`, so ADS-B keeps the rest. Each message is an observation of a new
  format (`'J'`), signed in a batch of its own format (`BATCH_FORMAT_ACARS`, 3: format 2's layout,
  `'J'` and nothing else, and `'J'` in no other), in one chain with the receiver's other batches.
  A relay that predates format 3 forwards such a batch raw, as it forwards any batch format it
  does not read, and never reads one into its products, so the wire's version does not move. A
  relay refuses a batch of a format it reads that does not decode (`'J'` relabelled as format 2
  among them) rather than forward it raw. A relay that reads it forwards it raw as signed, but
  `'J'` is in none of its products (`format::in_products`): not the deduplicated stream, not the
  regional product, not a receiver's figures, and so no client's stream; it leaves a relay only
  by `--acars-out` (loopback, beside `--beast-out`), every receiver's copy as its line.

  **The archive.** The map image's `tally-acars-collect` (`TALLY_MAP_ACARS`) merges the copies,
  which are the same line but for `t`: each message is held 30 s from its first copy and written
  once, timed at the median of its copies' seconds (with an even count the floor of the mean of the
  middle two; one clock off cannot move it, where the earliest would always be the slowest clock's),
  and a copy after that is dropped for 5 minutes. It files each message by the UTC day of its own
  time (within 5 minutes of its arrival) into `YYYY/MM/DD/acars.jsonl`, never into a day from 01:10
  the next or once packed, and writes what a day missed to `acars.gaps`, including the time it was
  stopped (it keeps its last read time on the volume, never later than the oldest message it still
  holds, so a crash's gap covers what it held), messages dropped while its room to hold them was
  full, and messages timed more than 5 minutes from their arrival; a gap of arrivals is in every day
  a message arriving in it may be filed in, 5 minutes either side. At pack time the day is sorted by
  message time in bounded memory (an external merge, under 17 MiB whatever the day's size), so no
  receiver's batch stays together, each message kept once in any 5 minutes (its earliest line: a
  restart can write one twice), and goes into that day's tar as `acars.jsonl.gz`; a day with gaps
  packs as partial.

  **What the merge cannot do.** A message of several blocks is one message only where every receiver
  reassembled it alike. No block with more to follow is published, nor one acarsdec is still
  reassembling, so a receiver whose decoder reassembles publishes the message once, whole, on its
  last block. One whose decoder does not reassemble (vdlm2dec, or acarsdec, dumpvdl2 or dumphfdl run
  without it), or whose reassembly missed a block or timed out, publishes the last block's own text
  alone, which libacars cannot tell from a whole message: that copy is another line, and the blocks
  before it are lost. Two messages that are the same line but for `t` are one copy key: squitters
  (`SQ`) and empty acknowledgements (`_d`) that repeat with nothing that differs are merged into one
  within 30 s, and a repeat within 5 minutes after it is written is dropped as a late copy. A feeder
  signs whatever lines it likes: the archive says what was published, never that an aircraft sent
  it, and a fabricated message is attributable at a relay to the receiver that signed it, not in the
  archive, which names no receiver.
- **Short links and previews.** The map's nginx answers adsb.lol's short links (`/<hex>`,
  `/<registration>`, `/<lat>,<lon>[,<zoom>]`) as redirects to tar1090's own query, and the site's
  short links hand off to them, so the rules are the map's alone; a path that is none is the map's
  not-found page, back to the site. A page asked for one aircraft (`?icao=`, `?reg=`) carries Open
  Graph tags from readsb's answer for it, as adsb.lol's `inject_meta.lua` writes them, with
  Debian's nginx Lua module: its callsign, registration and type, its altitude and speed, and a
  picture of the map at its position with one marker on it. The aircraft's position is public (the
  map shows it to anyone), so it may be in the card; nothing of a receiver is, neither a site nor
  readsb's receiver fields (`r_dst`, `r_dir`, `rssi`). GitHub Pages serves one `404.html` for every
  path the site has not prerendered, so a crawler reading `tally.skycommons.org/<hex>` learns
  nothing of the aircraft: the link that previews is the map's (`tally-map.skycommons.org/<hex>`,
  or any `?icao=` link tar1090 copies).
- **The picture is a static map render, not a screenshot.** adsb.lol screenshots tar1090 with
  Playwright over a headless Chromium. In the map image that is Debian's `chromium-headless-shell`,
  528 MB installed against the image's 167 MB, a browser of 100 MB or more for each render on a
  relay's host, and a driver of our own to wait for the map's tiles (Chromium's own `--screenshot`
  left them half drawn). Instead the image draws the picture with komoot's staticmap over Pillow
  (Python, 86 MB with the tags' Lua module), over OpenStreetMap's standard tiles, the layer tar1090
  draws by default, credited in the picture. It keeps OpenStreetMap's tile policy: nginx fetches
  and caches every tile, names the image in its User-Agent and asks at most 10 tiles a second. A
  picture is cached a minute for an aircraft at a position rounded to 0.01 degrees, drawn one at a
  time, and only near where readsb hears the aircraft; anything else is the site's card, a fixed
  picture in the image. An operator on a small host turns the pictures off with
  `TALLY_MAP_PREVIEWS=off`: the renderer does not run, and every preview's picture is the card.
- A status page and a hardware guide on the site.

## Rollout

1. The map bundle in a release; the public relay runs it (map at `tally-map.skycommons.org`).
2. `/v2`, routes and `/v1/me` in a release; the site's "am I feeding" and the map's routes.
3. §3, each in its own change.
