# Rules for relay operators

These are the network's rules for anyone who runs a Tally relay. Following them is the condition
for being listed in a release's seed list (`packaging/seeds`), the relays a new feeder starts from.
That listing is the only lever the project has: it cannot stop anyone from running a relay, and it
does not try to.

## Receiver sites

A feeder signs its receiver's exact site (latitude, longitude and altitude), because MLAT needs it:
solving a position from arrival times needs each receiver's place to a few metres (RFC-0171 §3.5,
§8.3).

**The exact site goes only to relays, and is never in anything a client reads** (founder,
2026-10-19; RFC-0171 §3.3, §3.6, §6). The feeder sends it in a record of its own (`ReceiverSite`),
only to relays that speak wire version 3, and relays pass it only to other version 3 relays and
their MLAT. A client (a subscriber on the free tier or on a relay's credit, the HTTP API, the stats
endpoint, a map, any product) is sent the receiver's **public cell** instead: the H3 resolution 6
cell that holds the site, about 36 km² (about 6 km across), which the feeder computes itself. No
client form carries the site, its altitude, or what a site can be worked out from (raw counters,
full clock models, positions that name a receiver's receptions); the relay's client links are
typed so that they cannot hold one.

Be clear about what that promises. Anyone may run a relay, so a receiver's exact site is shared
with the operator of every relay it reaches that way: the relays its feeder sends to, and the
relays of its area that they share raw with. The promise is that the site is never published and
never readable by a client. It is not that the site is secret from a determined person who runs a
relay. These rules are what bind a relay operator who holds one.

One thing a client can still learn, by design: an area's deduplicated stream carries every message
its receivers heard (with no counters and no receiver named). In an area with a single receiver,
every message is that receiver's, so the stream shows its reception pattern (which aircraft it
heard, when, how strongly). That bounds its site only to about its public cell, which is already
public.

### The rules

- **Never republish an exact site.** Not on a website, an open API, a map, a download, a shared
  log or dump, or a feed to another network. Use it for MLAT and nothing else.
- **A public surface shows the public cell, nothing finer.** "Public" is anything shown to people
  who are not the feeder: a station page, a list of stations, a coverage or receiver map, a
  leaderboard. A figure that places a receiver (its area, its range) is computed from the public
  cell, not the site. Never show altitude.
- **Keep the site off client links.** The software does (below). A change to it, or a program of
  your own over the feed, that puts a site or anything finer than the public cell where a client can
  read it breaks this rule.
- **You are the controller of the sites you hold.** A receiver's exact site is personal data under
  the GDPR (RFC-0171 §6). A relay that receives sites holds them for MLAT, answers for them under
  its own law, and keeps a simple objection process: a receiver's owner who asks is answered,
  without first being made to prove ownership.

### What the software does by default

- `tally-relay` sends sites (`ReceiverSite`, and an old feeder's description with the site inside)
  only on links to relays and their MLAT that negotiated wire version 3. Everything else it sends a
  client is of a type that has no room for a site. It matches a client's regions against each
  receiver's public cell and clamps any finer region to its resolution 6 cell, so a client cannot
  learn a site from which receivers' traffic it is sent. It refuses a receiver's site and
  description when the description's public cell does not hold the site.
- `tally-relay --stats-listen` shows each receiver's public cell, never its site or altitude, and
  refuses to bind anything but loopback.
- `tally-api`, the open API a relay operator runs beside the relay (and the site at
  tally.flightlines.ai reads), places every receiver by its public cell and shows no altitude. It
  reads no site.
- `tally-feed` publishes only to relays that speak wire version 3, and sends its site only to them.
- `tally-relay --beast-out` serves every reception's message as plain BEAST, with no receiver's
  counter or signal level: those, against the aircraft positions anyone reads, solve a site, so
  they stay relay-only. It is what a local readsb decodes for the map (`tally-map`) and
  `tally-api`. It is unauthenticated, so it refuses to bind anything but loopback.
- `tally-feed --acars` signs an ACARS, VDL2 or HFDL message only in one flat schema
  (`tally_wire::acars`: the aircraft, the ground station, the message's own fields and text) and
  its time to the whole second; the station, its signal, frequency, decoder counters, clock past
  the second and the decoders' frame trees are dropped. `tally-relay --acars-out` serves each line
  as signed only when it is exactly that, loopback only, as `--beast-out`, and no other product
  carries it. They travel in batches of their own format, which an older relay forwards without
  reading, so none reaches its products.
- `tally-map` gives its readsb no location and draws no site marker, range rings or range
  outline, and `tally-api`'s `/v2` drops what readsb says of its own receiver (distance,
  direction, signal level), whatever readsb it reads. Do not give a public map's readsb a
  location, or feed it from anything but `--beast-out`.

An operator who builds their own website, map or API over the feed shows the public cell the same
way, and never anything finer.

## What was exposed before this change

The network did not keep sites from clients before 2026-10-19, and what went out then cannot be
called back:

- Up to tally-feed 0.3.0, the exact site was a field of the receiver's one signed description,
  which went to every subscriber of raw, into credit evidence bundles, and onto every relay's stats
  endpoint. Descriptions already sent to subscribers are in their hands, and anyone who kept them
  holds those sites.
- The v0.3.0 API served exact coordinates.
- Up to v0.4.2, `--beast-out` gave a local readsb each reception's counter and signal level, so
  `tally-map` and the API's `/v2` published readsb's per-aircraft signal level (`rssi`), which
  against the aircraft's position ranges the receiver that heard it.
- Raw counters, full clock models and positions that named each reception's receiver were sent to
  clients, and with the aircraft positions anyone reads they let a determined client work a site
  out to metres.
- A feeder of 0.3.0 or earlier still signs its site into its description. A version 3 relay keeps
  that description to other version 3 relays, but a relay still running 0.3.0 that such a feeder
  reaches passes it to its subscribers. Upgrading the feeder stops it at the source. tally-feed 0.3.0 sends the exact
  location beside its precision setting and rounds nothing, so on 0.3.0 the only way to keep an
  exact place out of the feed is to enter a rounded one, at a cost to MLAT.

An owner who wants their receiver's site out of the network for good can move nothing back; the
honest answer is to upgrade, and to treat the site as already known to anyone who read the feed
before.

## What this rule cannot bind

Be clear about the limit. Feeders dedicate their receptions to the public domain under CC0, and
what relays publish downstream is under the ODbL (README "Licences", RFC-0171 §8.2). Neither
licence requires anyone to keep a site private, and CC0 waives every right a licence could hold
back. This rule is a condition of the seed list, not a term of the data's licence; it binds only
operators who want to be listed, and the project can enforce it only by leaving a relay out of the
list. Whoever republishes a site is answerable for it under their own law; neither licence changes
that.
