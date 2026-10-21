# Tally

An open network for ADS-B receivers. Your receiver publishes what it hears once, and anyone may
run a relay or use the data. Nobody owns the network, including us.

Pilots say "tally" on the radio when they have the traffic in sight. That is what this does,
together.

**Status: early.** Releases are signed and public
([releases](https://github.com/sky-commons/tally/releases)), one public relay runs
(`relay.tally.flightlines.ai`, by Flightlines, the only operator in the seed list so far), and the
first receivers feed it. The map and each station's numbers are at https://tally.flightlines.ai.

## How it works

- **The feeder** (`tally-feed`) runs beside readsb on your receiver. It reads readsb's BEAST output
  (port 30005) as one more client, signs what your antenna heard about once a second, and sends it
  to the two nearest healthy relays on different networks, measured by round-trip time and chosen
  the same way by every feeder of its area, so an area's receivers land on the same relays and
  multilateration works. It checks now and then that what it sent arrived (asking relays of its
  area to prove they hold it), moves away from a relay that swallows its data, changes nothing
  about your other feeds, opens no port, and takes no orders from the network.
- **Relays** (`tally-relay`) are one program anyone may run. A relay takes the areas its operator
  names and shares them with every other relay that takes them, each forwarding its slice of the
  area's striped sharing trees; it checks every signature and never changes or repackages your
  data, so anyone downstream can verify it came from your receiver. With its duties on (the
  default) it also accepts feeders and computes their aircraft's positions by multilateration
  (MLAT) for the areas it is chosen to solve, two or three relays an area. It serves two products:
  everything for an area (the regional product), and one position per aircraft per second for the
  world.
- **Clients** read. A client never shares: it reads the free small tier with nothing but a
  connection, or more on the credit of a relay it is linked to (a short-lived credential the relay
  signs, checked against the relay's signed evidence of what it contributes).
- **Your receiver's identity is a key** it generates at install. No account, no signup. It names
  your antenna on every relay, forever, and no operator can take it away.

## Run a feeder

On a receiver that runs readsb (a Raspberry Pi image, adsb.im, a plain Debian box), the release's
installer does all of it: it downloads `tally-feed` for the machine, checks its sha256, finds the
decoders and the location, makes the key, and starts the service.

```sh
curl -fsSL https://github.com/sky-commons/tally/releases/latest/download/install.sh -o /tmp/tally-install.sh
sudo bash /tmp/tally-install.sh
```

It ends by printing your station's page, which says whether it is feeding. Run it again to upgrade
or to change the location; `--uninstall` removes it and keeps the key (`--uninstall --purge` deletes
the key too).

As a container (`ghcr.io/sky-commons/tally-feed`, signed like the binaries), see
[packaging/README.md](packaging/README.md). By hand:

```sh
tally-feed init --key /etc/tally/key            # once: creates the key, prints its public half
tally-feed --key /etc/tally/key --lat 37.41 --lon -122.10 --alt 12   # the release's relays are built in
```

Your receiver's exact location (with its altitude) goes only to relays, because multilateration
(locating aircraft that do not broadcast a position) needs it exact. It is never in anything a
client reads: maps, the API, station pages and every other client see only its public cell, the
H3 cell of about 36 km² (about 6 km across) that holds it, which the feeder works out itself.
Anyone may run a relay, so the operators of the relays your receiver reaches do hold the exact
location; the network's rules forbid them to republish it
([docs/relay-operators.md](docs/relay-operators.md)). Before this release it was not kept from
clients: tally-feed 0.3.0 and earlier put it in a description sent to raw subscribers, and the
v0.3.0 API served exact coordinates, so treat it as already known to anyone who read the feed
then (the same page, "What was exposed before this change"). `--precision <metres>` rounds it on
the receiver, for experts: above 30 m the receiver takes no part in multilateration.

If the receiver also runs dump978-fa for 978 MHz UAT, `--uat 127.0.0.1:30978` publishes its raw
output too, in the same signed batches.

`--acars HOST:PORT` publishes ACARS, VDL2 and HFDL messages the same way, from acars_router's TCP
outputs (`--acars 127.0.0.1:15550` for ACARS, `15555` for VDL2, `15556` for HFDL; repeat the flag
for each): acarsdec, dumpvdl2 and dumphfdl only send their JSON over UDP or ZeroMQ, and acars_router
takes it and serves it one line a message. Only the ACARS message is published, in one flat schema
whatever the decoder (`tally_wire::acars`): the aircraft's address, registration and flight, the
ground station, the label, sublabel, block, message number, mode, acknowledgement, the text, and the
time to the whole second (a receiver's clock readings finer than that help place it, as a BEAST
counter does), each spelled as libacars spells it whichever decoder wrote it (HFDL without the
aircraft's address, which dumphfdl takes from its own logon cache). Nothing of a decoder's own frame
trees or libacars' decodes is published: they differ by decoder, version and setting, so copies
would not merge. Everything of the receiver (its station, signal, frequency and decoder counters) is
dropped. A frame that carries no ACARS message (a VDL2 XID, an HFDL logon or ground station's SPDU),
a message its decoder says is damaged, and a block with more of its message to follow or still being
reassembled are counted and not published; a message with no time of its own is skipped. The
messages travel in batches of their own format, which a relay older than this forwards without
reading. A message two receivers hear is published by both, and the archive keeps it once: the map's
collector merges the copies, which are the same line but for their times, timed at the median of
their seconds. Message text can carry personal data, and some jurisdictions restrict disclosing
intercepted content (in the UK, the Wireless Telegraphy Act 2006 s48), so nothing is published
unless the owner names `--acars`. The messages take at most `--acars-ceiling` bytes a second (8000
by default) of `--ceiling`, so ADS-B always keeps the rest; a decoder's line over 64 KiB is skipped,
and so is a message over 16 KiB once published. They join the relay's daily open data release
(packaging/map/README.md).

`--ceiling` caps what the feeder sends each relay per second (64 KB by default). Over the cap,
receptions are dropped and counted, never buffered.

## Run a relay

```sh
tally-relay keygen > /etc/tally/relay.key
tally-relay --key /etc/tally/relay.key --max-upload 6Mbit/s \
  --listen 0.0.0.0:10900 --beast-out 127.0.0.1:30105
```

`--max-upload` is required: the most the relay sends a second to billed peers (see "What a relay
costs" below). It needs no state and no calendar: a restart cannot reset it, and it never runs
out.

`--beast-out` serves every reception as plain BEAST for a local decoder such as readsb, the one a
public map and `tally-api` read (below). Each frame is the reception's message alone: its counter
and signal level are zero, since a receiver's counters and signal levels against the aircraft
positions anyone reads place it, and those are relay-only. It is unauthenticated and never
counted against the cap, so it binds loopback only: the relay refuses to start on any other
address.

`--acars-out 127.0.0.1:30106` serves every ACARS, VDL2 and HFDL message its feeders publish as one
JSON line each, as acars_router's TCP outputs are (all three kinds on one port), for the map
image's daily archives. A line that is not exactly what a feeder publishes (`tally_wire::acars`) is
never written. Copies from receivers that heard one message are each served; the map's
collector merges them. ACARS is in no product: no subscriber's stream, regional product or
receiver's figures carry it.
Loopback only, as `--beast-out`.

`--stats-listen 127.0.0.1:10901` serves what the relay knows of each receiver's traffic as JSON
(`GET /stations`, `GET /stations/KEY` with the key as base64url): sessions, first and last seen,
batches, sequence gaps, observations, messages a second, the public cell and software its
description declares (never the exact location or altitude), and the `address` its connected
session came from. It is unauthenticated too, and names where each feeder feeds from, so it binds
loopback only: the relay refuses to start on any other address (`0.0.0.0`, a public one, or a
name). Anything a relay publishes (`tally-api`, a website, a map) shows a receiver's public cell
and nothing finer, and the exact locations a relay holds for multilateration are never
republished: the network's rules for relay operators, and the condition for a release's seed list,
are in [docs/relay-operators.md](docs/relay-operators.md).

`--area CELL` names an area the relay takes (an H3 cell, hex or decimal; repeatable). It shares
what it takes with every relay that takes the same area, and offers it, signed, to the network.
`--advertise HOST:PORT=KEY` with the relay's own key says where it answers, which its offers
carry: a relay that does not list itself signs no offer, so no other relay can verify it, choose it
to solve an area's MLAT, or pass it an area's raw. An offer names the address by number (an IP and
port), which puts it in its network group for every relay alike: a host name given here is
resolved by the relay, and the IP it resolved to is what it signs (nothing is signed before it
first resolves). `--network ASN` declares the autonomous system it is on, so feeders choose two relays on
different networks. The duties of a full relay are on by default: it accepts feeders, runs MLAT
for the areas it is chosen to solve (on the cores its other work leaves, below its priority, so
MLAT that falls behind sheds rather than delaying raw; `--no-mlat` runs none), and seeds its feeders' data into their areas' sharing groups. `--no-relay-duties` turns all
three off, for a relay that only shares the areas it takes (a host behind NAT, or one with no
cores to spare). `--world` gathers the live world product from every area's positions it receives
(one fix per aircraft per second, sealed about 4 seconds after the second, MLAT by its provisional
fix), and `--world-precise` the precise one (the same rule sealed about 90 seconds after the
second, once final MLAT fixes can arrive, MLAT by its final fix only). A relay receives an area's
positions by taking it, so a world relay takes every area: with either flag the `--area` cells
must cover the globe (the 122 resolution 0 cells do), and a relay told otherwise refuses to start
rather than sign part of the world as the whole. A client subscribes to each product separately.

Relays link in two ways. A directory link (`--upstream HOST:PORT=KEY` dials one; `--accept-relay
KEY` lets a key dial in) carries only the directory: signed offers and queries, the evidence
bundles offers are ranked by, probes, delivery checks and have-summaries. Every record of data moves over member links, which a relay dials to
the members of its areas' sharing groups (relays whose signed offers it verified, by a handshake
at the address each names), and over the one-hop raw links its MLAT keeps. So to join the network
a relay needs one directory link to a relay already in it; the rest it learns from offers. Each feeder is held to
`--max-feeder-bytes-per-sec` (256 KiB/s by default, told to the feeder in advance), as is every
other connection that dials in but a relay's. The relays that send it data (the members of its
groups, and its own one-hop raw links) share `--max-member-bytes-per-sec` all together, and the
relay plans memory for every member session its areas let other relays open, which nobody picks.
Connections in and out are capped overall (`--max-connections`), and those dialling in per
address (`--max-connections-per-address`). `tally-relay --help` lists the rest.

`tally-relay check ARGS...` refuses what a start with the same arguments would refuse, without
starting (it reads no key file and opens no socket), and prints the relay's memory plan, one
`name value` a line; a deploy's tests run it over the arguments it passes, so an argument the
binary no longer takes fails there rather than at the next start.

## What a relay costs

Taking data in costs a relay only its server. What it sends out is billed by most hosts, and a
subscriber asks for as much as it likes: one whole-world deduplicated subscriber (about 30 Mbps)
is about 10 TB a month. So every relay names a speed cap, `--max-upload`, and keeps to it whatever
its peers ask. The cap bounds the bill: the relay can never send more than the cap times the
seconds in a month (plus one second's burst). 10 Mbit/s is at most about 3.24 TB in a 30-day month
and 3.35 TB in a 31-day one. A cap never goes dark: when more is asked for than it carries,
lower-priority traffic goes slower, and nobody's data stops reaching the network because the month
is nearly over.

- Every byte it writes to a peer counts, handshakes and heartbeats included. Peers on loopback
  (a local readsb on `--beast-out`, `tally-api` on `--stats-listen`) are neither counted nor capped:
  those bytes never leave the host.
- What goes first is fixed, highest first: control (handshakes, rate limits, heartbeats, goodbyes,
  which always have a small reserve of their own); positions and clock models; raw batches to
  relay links and engines; the rest that relay links and engines are sent; provisional positions,
  when there are any; and last, plain subscribers. A class gets only what the classes above it
  leave, and peers in one class share it fairly.
- Once a send has waited 2 s for the cap, a waiting peer is dropped every quarter second until
  what is asked for fits: from the lowest class anyone is waiting in, the one asking the most. A
  plain subscriber is therefore always dropped before a relay link or an engine, which forward
  what they are sent.
- A new feeder is accepted only while the cap has room for what it would have to forward (about
  100 kbps to each relay link and engine); past that it is redirected to the relay's hints, so the
  relay never takes in data it cannot deliver.

`GET /egress` on `--stats-listen` reports the cap, the most it lets out in a month, the bytes sent
(billed and loopback), the headroom left, each class's rate, demand, waiting sends and queued
bytes, the peers dropped from each, and the feeders turned away.

| Host                          | What the plan includes                | Beyond it        | A cap to start from                                                                           |
| ----------------------------- | ------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------- |
| AWS Lightsail, $12 a month    | 3 TB a month, in and out together     | $0.09 a GB out   | `--max-upload 6Mbit/s` (at most 2.01 TB out in 31 days, leaving about 1 TB for what comes in) |
| Hetzner dedicated root server | a 1 Gbit uplink, unlimited traffic    | nothing          | `--max-upload 1Gbit/s` (the uplink itself)                                                    |
| A home connection             | your ISP's monthly cap, if it has one | your ISP's terms | the ISP's cap divided by 2,678,400 (the seconds in 31 days), and less than your upload speed  |

Sources: [Lightsail pricing](https://aws.amazon.com/lightsail/pricing/) ("$0.09 USD/GB" beyond a
plan's allowance; the $12 plan includes 3 TB) and the [Lightsail FAQ](https://aws.amazon.com/lightsail/faq/)
("Both data transfer IN and data transfer OUT of your instance count toward your data transfer
allowance"; only the excess out is billed), so what feeders send a relay uses the same allowance as
what it sends;
[Hetzner traffic](https://docs.hetzner.com/robot/general/traffic/) ("All root servers have a dedicated 1 GBit uplink by default and with it unlimited traffic").
Prices change: read your own plan before you set the cap.

## Run the API

`tally-api` serves public, read-only JSON beside a relay: aircraft in a viewport (from a readsb fed
by the relay's `--beast-out`, through readsb's own API port, with the network's MLAT positions
merged in), network totals, each station's stats (from the relay's `--stats-listen`), and each
feeder's figures and the area leaderboards; and, as adsb.lol serves them, the ADS-B
Exchange-compatible `/v2` and routes (RFC-0187 §2).

```sh
tally-api --relay-stats http://127.0.0.1:10901 --readsb http://127.0.0.1:30152 \
  --relay 127.0.0.1:10900=<relay key> --routes /var/lib/tally/standing-data \
  --listen 127.0.0.1:10902 --client-ip-header CF-Connecting-IP
```

`--routes DIR` is a checkout of [VRS standing data](https://github.com/vradarserver/standing-data)
(CC0), its `routes/` and `airports/` CSV files, which the operator keeps current (daily, say, with
`git -C DIR pull`); the API reads it at start and again whenever its files change. Fetch it
once with `git clone --depth 1 --filter=blob:none --sparse https://github.com/vradarserver/standing-data DIR && git -C DIR sparse-checkout set routes airports`.
Without it the routes answer `404`.

`--relay` (repeatable) is where the API reads the network's MLAT positions, its world products
and the relays' feeder figures. Without it the aircraft carry readsb's positions alone, and no
feeder has figures. The API is a client of the relay like any other: it is sent tagged positions
(each checked by the relay that sent it) and clock models with no receiver sites, and no raw
(`--mlat-raw`, which read raw, is gone). Each relay computes the figures of the receivers it
hosts or carries, standing and MLAT help among them, and signs them (`FeederFigures`, RFC-0174
§2.12); the API serves the newest its `--relay`s signed, and ranks only receivers their relay
says have standing.

- `GET /v1/aircraft?west=&south=&east=&north=` (degrees, at most 60 each way); add `&feed=precise`
  for the precise world product, about a minute and a half behind, with every MLAT position final
  (the answer's `feed` says which was served, and its `now_ms` is that product's own second). With
  no recent precise product to serve (none has come from the relays, or the newest is older than
  the age limit beyond its own delay) it answers `503` with `{"error":"precise_unavailable"}`,
  never an empty sky. Each aircraft's `position_at_ms` is when its position was heard (readsb's
  `seen_pos`; for MLAT, the transmission's time), which a client projects from, and
  `last_heard_at_ms` when any message was; `position_source` is `adsb`, `mlat` (Tally MLAT), `adsr`,
  `tisb` or `other`, from readsb's `type`; an MLAT aircraft's speed and track are derived from its
  last two fixes. `sent_at_ms` says when the answer was sent, so a client can measure its clock's
  offset from the API's
- `GET /v1/aircraft/stream?west=&south=&east=&north=` (the same query): Server-Sent Events, never
  cached (RFC-0184). Each `aircraft` event's data is an `AircraftUpdate`: the first `full` (every
  aircraft in the box), then at most every 250 ms the aircraft that changed and the `gone`
  addresses, and a comment every 15 s while nothing changes. One read of readsb (every 200 ms,
  while any stream is open) serves every stream; an address holds at most 4 open streams (a fifth
  is answered `429`). With `&feed=precise` each new second of the precise product is sent whole.
  Run readsb with `--write-json-every 0.2` so its answer is as fresh as the stream's
- `GET /v1/network`: receivers, their message rate, and `aircraft` (readsb's positioned aircraft
  and those only Tally MLAT places) with `aircraft_by_source` summing to it
- `GET /v1/stations/KEY` (the key as base64url without padding), `GET /v1/stations/KEY/stats`
- `GET /v1/leaderboards`, `GET /v1/leaderboards/AREA`: every area with a feeder, its `receivers`
  beside the `ranked` among them, and an area's feeders without standing as `unranked`
- `GET /v1/me`: "am I feeding": the stations connected now from the asking client's host (its
  IPv4 address, or its IPv6 /64, as `--client-ip-header` names it; none when the header is missing,
  or the address is loopback), each `key`, `online`, `messages_per_sec` and
  `last_seen_at_ms`; never another's, never cached
- `GET /v2/hex/HEX` (`/v2/icao/`), `/v2/callsign/CS`, `/v2/registration/REG` (`/v2/reg/`),
  `/v2/type/TYPE`, `/v2/squawk/SQ` (`/v2/sqk/`), `/v2/mil`, `/v2/ladd`, `/v2/pia`,
  `/v2/point/LAT/LON/NM` (`/v2/lat/LAT/lon/LON/dist/NM`, at most 250 nm) and
  `/v2/closest/LAT/LON/NM`: ADS-B Exchange's v2 answer (`ac`, `msg`, `now`, `total`, `ctime`,
  `ptime`), each one query of readsb's API port served as readsb writes it; a value may be a
  comma-separated list, and a malformed one is `400`
- `POST /api/0/routeset` (tar1090's `routeApiUrl`: `{"planes":[{"callsign","lat","lng"}]}`, at
  most 100) and `GET /api/0/route/CALLSIGN/LAT/LON`: adsb.lol's route shape, `plausible` when the
  aircraft is near a leg's great circle

The JSON is declared once, in `crates/api-types` (`tally-api-types`, serde only), which a client
in Rust can depend on rather than restate; `crates/api-types/testdata` holds one answer of each
endpoint exactly as the API writes it. Every time field says what it is: an instant is `*_at_ms`
(Unix milliseconds on the API's clock, beside the answer's `now_ms`, so a client ages it against
`now_ms`, or by its own clock through the offset `sent_at_ms` gives it), and a span is `*_for_ms`.

Each client is rate limited (`--rate`, `--burst`), and CORS allows `--allow-origin` (repeatable; no origin unless named),
answering a preflight for `GET` and `POST` with the `accept`, `content-type` and `traceparent`
request headers and exposing `Retry-After`; a map whose routes come from this API names its origin
here. `tally-api --help` lists the rest.

`tally-api check ARGS...` is the same for the API: it reads and checks the arguments as a start
does (every argument known, `--listen` an IP and port, the upstreams `http://` URLs, header names
valid, the `--key` file well formed when it can read it, the `--routes` directory readable), opens
no socket and reads nothing from the network, then prints the settings, one `name value` a line,
and exits 0; otherwise it exits 1 with the message a start would print.

Behind Cloudflare (or any proxy), every request arrives from the proxy's address, so the rate limit
would hold every visitor to one bucket. `--client-ip-header CF-Connecting-IP` reads each client's
address from the header Cloudflare sets instead. Set it only when every request comes through that
proxy: a client that reaches the API directly could otherwise name any address it likes.

## Run the map

The release's second image, `ghcr.io/sky-commons/tally-map`, is a full aircraft map of what a relay
hears (tar1090 over readsb, with an open aircraft database), for a relay operator to run beside
the relay. Its readsb reads the relay's `--beast-out` and serves the query API `tally-api --readsb`
reads, so one decoder serves the map and the API. It also packs each day's history into one
archive for the open data releases. How to run it, its settings and its licences:
[packaging/map/README.md](packaging/map/README.md).

## Build

```sh
cargo build --release      # or: bazel build //...
cargo test                 # or: bazel test //...
cargo test --release -p tally-relay --test mlat_host
```

The last runs the network test (`crates/relay/tests/mlat_host.rs`): three relays, simulated
feeders and a client, in real time for about three minutes. A debug build cannot keep up with the
clock, so `cargo test` skips it and it runs only optimised; Bazel builds it optimised itself and
gives it the four cores it needs (`crates/relay/BUILD.bazel`).

Pure Rust, no C toolchain, so it cross-compiles to a Raspberry Pi.

## Licences

- Code: MIT or Apache-2.0, at your option.
- Data: feeders dedicate their receptions under CC0. What relays publish downstream is under the
  ODbL, so nobody can take the data private.
