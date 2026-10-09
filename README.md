# Tally

An open network for ADS-B receivers. Your receiver publishes what it hears once, and anyone may
run a relay or use the data. Nobody owns the network, including us.

Pilots say "tally" on the radio when they have the traffic in sight. That is what this does,
together.

**Status: pre-release.** The protocol, the feeder and the relay work end to end in tests. Nothing
is deployed for the public yet.

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

```sh
tally-feed init --key /etc/tally/key            # once: creates the key, prints its public half
tally-feed --key /etc/tally/key \
  --relay relay.example.org:10900=<relay key> \
  --lat 37.41 --lon -122.10 --alt 12
```

Your receiver's location is published as you enter it, because multilateration (locating aircraft
that do not broadcast a position) needs it exact. Pass `--precision <metres>` to say you rounded it;
you then contribute less to multilateration.

If the receiver also runs dump978-fa for 978 MHz UAT, `--uat 127.0.0.1:30978` publishes its raw
output too, in the same signed batches.

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

`--beast-out` serves every reception as plain BEAST for a local decoder such as readsb. It is
unauthenticated: bind it to loopback.

`--stats-listen 127.0.0.1:10901` serves what the relay knows of each receiver's traffic as JSON
(`GET /stations`, `GET /stations/KEY` with the key as base64url): sessions, first and last seen,
batches, sequence gaps, observations, messages a second, and the location and software its
description declares. It is unauthenticated too: bind it to loopback.

`--area CELL` names an area the relay takes (an H3 cell, hex or decimal; repeatable). It shares
what it takes with every relay that takes the same area, and offers it, signed, to the network.
`--advertise HOST:PORT=KEY` with the relay's own key says where it answers, which its offers
carry: a relay that does not list itself signs no offer, so no other relay can verify it, choose it
to solve an area's MLAT, or pass it an area's raw. `--network ASN` declares the autonomous system it is on, so feeders choose two relays on
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
feeder's figures and the area leaderboards.

```sh
tally-api --relay-stats http://127.0.0.1:10901 --readsb http://127.0.0.1:30152 \
  --relay 127.0.0.1:10900=<relay key> --mlat-raw \
  --listen 127.0.0.1:10902 --client-ip-header CF-Connecting-IP
```

`--relay` (repeatable) is where the API reads the network's MLAT positions and its world products.
Feeder figures and leaderboards need both it and `--mlat-raw`: a receiver ranks only with standing,
and standing is settled against the raw messages the API reads with `--mlat-raw`. Without them those
endpoints answer `503`, and the aircraft carry readsb's positions alone. Without `--mlat-raw` no
receiver is credited with MLAT help either: a final position credits a receiver only when the
merge accepted it and the receiver's own signed raw holds the reception it cites. The feeder
figures (uptime, message rate, aircraft, range, coverage, MLAT help) are the API's, computed from
public signed records; no relay computes them.

- `GET /v1/aircraft?west=&south=&east=&north=` (degrees, at most 60 each way); add `&feed=precise`
  for the precise world product, about a minute and a half behind, with every MLAT position final
  (the answer's `feed` says which was served, and its `now_ms` is that product's own second). With
  no recent precise product to serve (none has come from the relays, or the newest is older than
  the age limit beyond its own delay) it answers `503` with `{"error":"precise_unavailable"}`,
  never an empty sky
- `GET /v1/network`
- `GET /v1/stations/KEY` (the key as base64url without padding), `GET /v1/stations/KEY/stats`
- `GET /v1/leaderboards`, `GET /v1/leaderboards/AREA`

The JSON is declared once, in `crates/api-types` (`tally-api-types`, serde only), which a client
in Rust can depend on rather than restate; `crates/api-types/testdata` holds one answer of each
endpoint exactly as the API writes it. Every time field says what it is: an instant is `*_at_ms`
(Unix milliseconds on the API's clock, beside the answer's `now_ms`, so a client ages it against
`now_ms` and never against its own clock), and a span is `*_for_ms`.

Each client is rate limited (`--rate`, `--burst`), and CORS allows `--allow-origin` (repeatable; no origin unless named),
answering a preflight for `GET` with the `accept` and `traceparent` request headers and exposing
`Retry-After`. `tally-api --help` lists the rest.

Behind Cloudflare (or any proxy), every request arrives from the proxy's address, so the rate limit
would hold every visitor to one bucket. `--client-ip-header CF-Connecting-IP` reads each client's
address from the header Cloudflare sets instead. Set it only when every request comes through that
proxy: a client that reaches the API directly could otherwise name any address it likes.

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
