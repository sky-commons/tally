# RFC-0171: Tally, where a receiver publishes once and nobody owns the network

- Status: **accepted 2026-10-05; the wire crate is built, the feeder and relay are next.** Founder
  direction, the same day, after §1's probe found adsb.lol's raw stream off for every client and
  its re-api failing one query in three: "I need this data, badly, ADSB.lol is both too small for
  me and i have to rely on its infra"; "if a network like im describing existed, my problems would
  not exist anymore". Named Tally that day (the pilot's call for traffic in sight), published as
  `flightlines/tally`.
- The design was pressure-tested the same day by five independent critics (signing and MLAT, relay
  discovery, a feeder frozen for five years, proof of antenna, and legal and privacy research).
  §9 records what each changed. The founder ruled on the four calls they raised (§8).
- Extends RFC-0119 (the feeder and the firehose): the boxes, the master, the consumer readsb and
  the JVM-never-sees-BEAST rule are kept whole. What changes is where the consumer readsb drinks
  from. Composes with RFC-0031 (surveillance) and RFC-0087 (observation storage), untouched.
- **Amended 2026-10-19 (founder): a receiver's exact site is relay-only.** Aircraft receptions stay
  open; a receiver's exact site (latitude, longitude, altitude, and anything a site can be derived
  from) goes only to relays, which need it for MLAT, and never into anything a client reads. Anyone
  may run a relay, so the promise is "never published, never readable by a client", not "secret
  from someone who runs a relay". It changes §3.1, §3.3 (wire version 3, in one release), §3.4, §3.5, §3.6, §3.8, §3.8.1, §3.8.2, §6, §7 and §8.3, and RFC-0174 §2.1, §2.5,
  §2.8, §2.10, §2.11 and §2.12; each place says so. It was pressure-tested by critics who found ten
  ways a client could read or derive a site from v0.3.0 (§9, item 6).

## §0 The answer, in one line

A receiver signs its raw receptions and publishes them once, outbound, to a few relays that anyone
may run; relays pass the signed batches on untouched and serve clients; MLAT is computed by
relays, which anyone may run; Flightlines is client number one and our own boxes are feeder
number one, so from the first relay we depend on nobody's infrastructure but ours, and every
receiver anyone adds afterwards is coverage for every client at once.

## §1 Why: the only whole-world terrestrial source we had is gone, and it was never ours

Verified on anvil (the master, the feeder IP RFC-0119 §3.1 entitles) on 2026-10-05:

- **The raw stream is off for everyone.** `out.adsb.lol` ports 1365 (BEAST) and 1366 (MLAT,
  SBS) time out on all six of adsb.lol's ingest addresses, IPv4 and IPv6, from our feeder IP and
  identically from a non-feeder IP (the build Mac). The same hosts answer on 443, 1337, 1338,
  30004 and 30005, so the path is up and only the stream ports are dropped. On 2026-08-13 a
  non-feeder was REFUSED (`probe-firehose-entitlement.sh`'s header), so the upstream behaviour
  has changed since, and a timeout no longer distinguishes an outage from a revocation.
- **It is not our entitlement.** re-api, gated by the same feeder-IP rule, answers our IPv4
  (`?all_with_pos`: 200, 12,526 aircraft, 0.9 s), and our feed is healthy
  (`flightlines-feeder-readsb@box-01` holds 185.233.105.52:30004, 76 aircraft with position).
- **How long it has been off is not established.** RFC-0119 §12 says "dead upstream since Aug
  2025 (abandoned by the project, community-confirmed)" without a source. Against it: the docs
  moved the stream from 1337/1338 to 1365/1366 on 2025-06-20 and still advertise it, and
  `hut8/soar` wired a proxy to `out.adsb.lol:1365` on 2025-12-14. Our consumer has failed
  99,000 times since its restart on 2026-09-17 (RFC-0126 §8.6 saw 7,400 by 2026-08-22).
- **What we run on instead is weakening.** re-api fails about one query in three here (503,
  "upstream connect error", or a 5 s timeout) and refuses us over IPv6 (403, since we feed over
  IPv4 only). Other feeders have had re-api 403s since 2026-08-28 (`adsblol/feed#22`), the
  project's Zulip is invite-only, and its maintainer wrote on 2026-09-19: "this is a hobby project
  provided as-is. there are no guarantees of availability, api access, uptime, response times,
  support, contactability, or continued availability of any particular service", with a
  commercial offering mentioned as possible.

The alternatives were surveyed in RFC-0126 §8.6 and have not improved: airplanes.live is
permission-gated (403, "contact us"), adsb.fi's contributor data is non-commercial without an
arrangement, and FlightAware and ADS-B Exchange are closed commercial products. Every open
terrestrial network today is one operator's servers holding one operator's feeder list. When the
operator's stream stops, every client stops, and the feeders, who own the antennas, have no
way to send their data anywhere else without reconfiguring each box by hand.

Coverage is the second problem and this RFC does not pretend to solve it on day one. Slice 1 buys
independence (our data, our relay, our decoder), with exactly our own receivers' coverage. The
network exists so that coverage, once added by anyone, is added for everyone: §10's later steps
are where it grows.

## §2 Capability survey (who already owns what)

| Capability                               | Owner today                                             | This RFC                                                        |
| ---------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------- |
| Receiving RF, decoding to BEAST          | readsb on each box (RFC-0119 §3.2)                      | Unchanged. Tally never touches RF.                              |
| Box to master transport                  | stunnel TLS-PSK, one service per box (RFC-0119 §3.2)    | Unchanged.                                                      |
| Feeding adsb.lol                         | per-box readsb and mlat-client on the master            | Unchanged. Tally is additive, never instead.                    |
| Decoding the world, current state        | the consumer readsb, out of process (RFC-0119 §3.3)     | Unchanged. Its connector moves to our own relay's BEAST output. |
| Live query and history                   | `LiveStateQueryPort`, surveillance BC, RFC-0087 storage | Unchanged. The JVM still never sees BEAST.                      |
| Publishing receptions to other operators | nobody (each aggregator's ingest is its own)            | NEW: `tally/`, this RFC.                                        |

No second decoder publishes aircraft state, no second store, and no second identity authority over
people: a Tally identity is an antenna's or a server's key, never a Flightlines account.

## §3 Decisions

### §3.1 The unit is a signed batch of raw receptions, and nobody repacks it

One aircraft transmission heard by four receivers is four receptions, and Tally carries all four:
the differences between their arrival times are what MLAT is. A reception (`Observation`) is the
receiver decoder's frame unchanged: a format, the raw 48-bit counter, the signal level, the bytes.
Counters are never calibrated before a relay's MLAT, by anyone.

A feeder signs about a second of its receptions as one `Batch`: its key, a random boot id, a
sequence number within the boot, a counter epoch (bumped whenever the receiver's counter may have
restarted, so counters from before and after never meet), its wall clock (checked by its relay,
§3.6), the count of receptions its own rate ceiling dropped, the hash of its previous batch, the
receptions, and an Ed25519 signature. Relays forward batches byte for byte. Consequences, each the reason for one field:

- Any relay downstream can prove a receiver published exactly what arrived; a relay can drop a batch
  but cannot alter or invent one. (Raw batches go only to relays since 2026-10-19, §3.6: their
  counters, with the published aircraft positions, would give a client the receiver's site.)
- A sequence gap is data some hop did not deliver, and `dropped` separates the feeder's own choice
  from a relay's.
- The hash chain means a receiver cannot sign two histories for two relays.
- A batch's identity is its hash, so the same batch arriving via several relays collapses exactly.

Compressing receptions into multi-receiver bundles inside relays was proposed and killed (§7): it
saves only the repeated message bytes and destroys the per-receiver proof.

### §3.2 One Ed25519 key is the identity, and the Noise key is derived from it

A feeder generates an Ed25519 key at install and keeps it on the box. It signs batches and the
receiver's own description, and the X25519 key Noise authenticates is derived from it (libsodium's
`sk_to_curve25519`), so one key names the antenna everywhere, forever. No account, no signup, no
operator issues it, so none can revoke it; a relay refusing a key is that relay's choice alone.

### §3.3 The transport: Noise IK behind a plaintext preamble, versions negotiated

Every hop is `Noise_IK_25519_ChaChaPoly_BLAKE2s` over TCP (the `snow` crate, pure Rust, so the
feeder cross-compiles to a Pi with no C toolchain). Before the handshake the initiator sends a
16-byte preamble: `TALY`, a preamble version, a handshake id, two reserved bytes, and an 8-byte
hint naming which of the responder's keys it dials. The preamble is the Noise prologue, so it
cannot be altered unnoticed, and it is what lets the handshake change later and a relay hold an
old and a new key while it rotates. The initiator's first handshake message carries its Ed25519
key, checked against the X25519 key the handshake proved.

Then `Hello{min_version, max_version, role}` and `Welcome{version}` (or `Goodbye{reason,
retry_after}`). **A relay answers every wire version a feeder ever shipped, forever**: that is a
protocol invariant, the SMTP EHLO and NTP rule, because installed feeders do not update. Every
step has a deadline (15 s to `Welcome`).

**The minimum wire version is 2** (decided 2026-10-07, `tally_wire::record::MIN_VERSION`).
Version 1 is retired before any feeder beyond Flightlines' own ran it (adsb.im ships version 2,
RFC-0174 §5), so the forever rule starts at 2: a responder answers a `Hello` whose highest version
is 1 with `Goodbye{Version}`, and no code path keeps version 1 working (a feeder compresses every
batch that compression shrinks, and probes expect a signed echo reply from every relay). Version 2
also widens `Streams` to two bytes, so products after the eighth have bits.

**Wire version 3 means "this peer keeps receiver sites off client links"** (decided 2026-10-19,
founder; `tally_wire::record::SITES_VERSION`, `carries_sites`). A site-bearing record (§3.4: a
`ReceiverSite`, or a `ReceiverInfo` of format 1) is sent only on a link that negotiated version 3
or later with the role relay or engine. Every other link is a client link and is never sent one: a
subscriber's, a feeder's, a probe's. A relay or engine link at version 2 is refused outright, since
a version 2 relay does not know it must keep sites from its own subscribers. A feeder sends its
`ReceiverSite`, and publishes at all, only to a relay that welcomed version 3. Version 3 adds
only non-critical records (§3.4), so a version 2 build skips them.

**There is no migration window.** When version 3 was decided the network was Flightlines' own
relay and feeders, so it moves at once, in one release:

- **A relay or engine link is accepted only at version 3 or above** (feeders, subscribers and
  probes keep the minimum of 2, under the forever rule above). The least is per role
  (`tally_wire::least_version`) and held at the handshake by both ends: a relay or engine says 3
  as its `Hello`'s least, and a responder answers a relay or engine `Hello` below 3 with
  `Goodbye{Version}`. The relay's egress has no column for an older relay link (`Column::of`
  refuses it), so no relay that might pass a site to a client is ever sent one, and a version 2
  peer that is not a relay is a client.
- **A feeder publishes only to relays that welcome version 3.** It sends a format 2 description,
  with its public cell, and a `ReceiverSite` (§3.5); a relay that welcomes only version 2 is not
  one it publishes to.
- **Relays** read both description formats, hold sites, refuse a site and a description of one key
  whose public cell does not hold the site (§3.6), send clients only what cannot carry a site
  (§3.6, "What a client may be sent"), and forward an older feeder's format 1 description byte for
  byte only to relay and engine peers.
- **The MLAT specification moves to version 6** with it: client clock models that name no
  receiver, tagged positions, and a model's inputs hash over site ids rather than sites (§3.8.1,
  "What a client is sent of MLAT").

**The roles** a `Hello` names: feeder, subscriber, relay, engine (another relay's MLAT taking raw
one hop, RFC-0174 §2.3; it publishes nothing), and **probe**. A probe is a
measurement session (RFC-0174 §2.2's round-trip probing and delivery check): it may send only
`Echo` and `DeliveryQuery` (`Role::may_send`; a query also carries the feeder's tag keys for the
member, RFC-0181 §7), is answered, and is never admitted as a feeder or
a subscriber, so measuring a relay takes none of its feeder slots and is sent none of its streams.
A probe that sends a delivery query of the retired form is ended with `Goodbye{Retired}`; one that
sends anything else, with `Goodbye{Protocol}`. A full relay still answers a probe.

### §3.4 Records, and the rules that let them change without the feeder

`tally/crates/wire` is the only code that encodes or decodes Tally, and every binary uses it. A
record is a kind byte, a two-byte length, a body; a Noise message carries whole records.

| Kind | Record         | Meaning                                                                         |
| ---- | -------------- | ------------------------------------------------------------------------------- |
| 0x01 | `Hello`        | the versions the initiator speaks, and its role (feeder, subscriber, relay, engine, probe) |
| 0x02 | `Welcome`      | the version both speak from here on                                             |
| 0x03 | `Batch`        | a receiver's signed receptions (§3.1)                                           |
| 0x04 | `ReceiverInfo` | a receiver's signed self-description: format 2 (2026-10-19) its public cell (H3 resolution 6), clock class, software, relays, and no site; format 1, from older feeders, its exact location, and relay-only (§3.5) |
| 0x05 | `Heartbeat`    | liveness                                                                        |
| 0x06 | `Redirect`     | "leave me", with relays as hints the feeder may ignore (§3.7)                   |
| 0x07 | `RelayList`    | relays this relay knows of, as hints                                            |
| 0x08 | `RateLimit`    | the most a relay wants; a feeder may go lower, never above its owner's ceiling; and the relay's clock, which a feeder signs its batches by (§3.6) |
| 0x09 | `Goodbye`      | the relay is closing, and how long to wait                                      |
| 0x0a | `Subscribe`    | the streams a subscriber wants, and its regions by receiver location; a client's matched by public cell, clamped to resolution 6 (§3.6) |
| 0x0b | `RelayBatch`   | a relay's own deduplicated stream, signed under its own domain (§3.6)           |
| 0x0c | `Positions`    | a relay's signed solutions, each naming its observation set (§3.8.1)          |
| 0x0d | `ClockModel`   | a relay's signed, content-addressed clock model manifest for one tile and window (§3.8.1) |
| 0x0e | `FaultProof`   | two signed solutions of one inputs that disagree, or two signed models of one inputs that differ; checked before forwarding |
| 0x0f | `ClockModelPart` | one part of a clock model too large for its manifest, checked against it (§3.8.1) |
| 0x10 | `Provisional`  | a relay's signed provisional solutions (`Positions` format 4), superseded by final ones; only to subscribers that asked (`PROVISIONAL`, §3.8.1) |
| 0x11 to 0x23 | RFC-0174's records | echo, delivery check, provider directory, sharing groups, credit, the regional and the two world products, parity and bundle index (RFC-0174 §2.10); transport version 2, the minimum. 0x13 and 0x14 are retired (the first delivery check), read as retired and never written; the delivery check is 0x22 and 0x23 (RFC-0181 §7) |
| 0x25 | `ReceiverSite` | a receiver's signed exact site (issued time, location with altitude, clock class), under its own signing domain `"tally receiver site"`; relay-only, sent only on version 3 relay and engine links (§3.3, §3.5) |
| 0x26 | `ClientClockModel` | a relay's signed clock model as a client may hold it, of one fixed size: signer, boot, sequence, issued time, spec version, the full model's id and inputs hash, and the window; no member, no site, no offsets (§3.8.1) |
| 0x27 | `ClientRegionalBatch` | a relay's signed deduplicated receptions for one area as a client may hold them: each reception's format and bytes, the batch's wall clock, and no counters or signal levels (a signal set against public positions ranges a lone receiver; §3.6) |

Kinds 0x25 to 0x27 came with wire version 3 (2026-10-19) and are non-critical, so a version 2 build
skips them. Two formats came with them: `ReceiverInfo` format 2 (above) and `Positions` formats 5
and 6, final and provisional, which name each reception by a 16-byte tag in place of its receiver,
epoch and counter (§3.8.1).

The extension rules, which are what a frozen feeder relies on:

- An unknown kind is skipped, unless its high bit (0x80) marks it critical, which ends the session
  cleanly. New records are therefore non-critical unless ignoring them would be wrong.
- A body may carry bytes after the fields a reader knows; they are ignored, so fields are appended.
- An enum value a reader does not know is kept as `Other`, never an error. The exception is
  evidence: a delivery answer's possession kind a reader does not know is an error, never read
  as a proof.
- A record whose meaning changes takes a new kind, and a signed one a new format; its old kind is
  retired, never reused. The appended-field rule cannot carry a change of meaning: a reader that
  ignores the new bytes reads the old meaning into them. The delivery check's two forms are the
  case (RFC-0181 §7).
- Every record body has one check of what makes it well formed (ranges ascending and exact,
  spans bounded, a position on the globe, one product where one is named), and the codec runs it
  on every encode and every decode (`tally_wire::Check`), so no value that breaks it is written or
  read.
- A signed form (batch, receiver info) keeps the same prefix in every format version (format byte,
  key, and for a batch its boot id and sequence) and ends with the signature over everything
  before it, so a relay can verify, route and deduplicate a format it does not otherwise read.
- An `Observation`'s format is BEAST's own type byte for 1090 MHz; 978 MHz UAT takes a new value
  and needs no new record, and relays forward formats they do not know.
- A compressed batch (format 2, RFC-0174 §2.2) states the length its receptions inflate to, and
  that length is at most 8 times its DEFLATE stream (`tally_wire::batch::MAX_INFLATION`) and at
  most 1 MiB. Every reader refuses a stated length past either before it inflates anything, and
  stops inflating at the stated length, so a relay's work on a batch is at most 8 times its wire
  bytes; a writer whose batch would be denser writes it plain (format 1), so no honest batch is
  refused. Why 8: the densest batch of honest 1090 MHz receptions the encoder makes is about 5
  times (one aircraft's identical Mode-S short replies at a steady counter and signal level; real
  extended squitters are about 1.5), because no receiver hears two receptions at one counter
  value. Only zero-filled UAT uplinks go past it, and they lose only their compression. A relay
  charges a batch by its inflated bytes and its receptions, never by its wire bytes alone
  (`Batch::inflated_len`, `Batch::receptions_at_most`, `Decoded::receptions`).

### §3.5 The feeder: what version 1 is, and what it must never do

`tally-feed` connects to the local readsb's BEAST output (port 30005, which every feeder stack
exposes) as one more client and publishes. It changes no readsb flag and no other feed.

What the decoder keeps out, because it is not this receiver's reception: positions an MLAT server
sent back (readsb re-emits them with the counter `0xFF004D4C4154`), and a stream that names more
than one receiver in `0xe3` receiver-id frames (an aggregate; the feeder refuses to publish it
under one key).

A second, optional source is 978 MHz UAT from dump978-fa's raw output (port 30978), where most
small US aircraft below 18,000 ft broadcast. Its receptions go into the same signed chain as
1090's (formats `D` and `U`, timestamped with dump978's wall clock in microseconds), and a UAT
reconnect does not start a new 1090 counter epoch.

Version 1 carries, and freezes:

- the signed, numbered, chained batches of §3.1 and a signed `ReceiverInfo` listing the relays it
  chose (so a relay's standing can be counted later, under any rule, from what receivers said);
- a configurable relay set, default four: one long-term anchor kept across restarts, one relay the
  owner pins (a "home relay", how a production user points its own feeders at itself), and the
  rest chosen at random from relays it has learned of (§3.7);
- obeying `Redirect`, `RateLimit` and `Goodbye`, with exponential backoff and jitter that a relay
  can lengthen and never shorten, so a relay restart is not 20,000 boxes reconnecting at once;
- during an outage, retrying the anchor rather than rushing to fresh relays, the classic eclipse
  path, within fixed bounds: a random slot gives up a relay it has not reached (no session got to
  `Welcome`) for an hour, the anchor after seven days (when it was last reached is kept with it,
  across restarts), and the home relay never;
- every send with a deadline (30 s), and a session that ends at once on its reader's failure
  even while a send is pending, so a relay that wedges cannot hold a slot;
- relays a relay suggests weighed as one source each when it picks (capped per source and in
  total), and never two relays on the same host, so one relay's hints cannot fill its set;
- the owner's ceiling enforced once, in the batcher; a relay that asks for less (`RateLimit`) is
  sent fewer batches, alone;
- a hard upload ceiling (a token bucket that drops, never a buffer), counted in each batch;
- the owner's location exactly as entered, with a precision field the owner may set to round it
  (§8.3), a periodic wall-clock sample and its clock class. Since 2026-10-19 the exact location
  goes only to relays (below).

**The site goes only to relays** (amended 2026-10-19, founder). Up to tally-feed 0.3.0 the exact
location was a field of the one description (`ReceiverInfo` format 1), and that description went
everywhere: to every raw subscriber, into evidence bundles, onto the stats endpoint and the API. A
feeder now signs two records, together, with one issued time:

- a **`ReceiverInfo` of format 2**: issued time, the **public cell** (the H3 resolution 6 cell
  holding the site, about 36 km², which the feeder computes; a finer cell is refused on signing
  and on reading), clock class, software and relays. No location and no altitude. It travels
  everywhere a description travels, clients included;
- a **`ReceiverSite`**: issued time, the exact location with altitude, and the clock class, under
  its own signing domain, so it can never verify as a description. It is sent only on a session
  whose relay welcomed wire version 3 (§3.3).

A relay that welcomes only version 2 is not published to at all (§3.3). When the location
changes, it reissues both with one issued time. A description from an older feeder (format 1, the site inside) is still read: relays
forward it byte for byte only to version 3 relay and engine peers, and a client is sent no
description for that receiver.

It must never carry: a remote kill switch, remote configuration or command push, self-update (it
updates through the owner's package manager, if ever), a single built-in seed or signer, any check
that fails on an old date (a Pi without a clock battery boots in 1970), a disk buffer (it wears SD
cards and replays stale data), or a listening port.

### §3.6 The relay: verify, forward, serve, and decide nothing about aircraft

`tally-relay` accepts feeders, subscribers and other relays on one port. It checks each batch's
signature, drops duplicates by hash, and forwards. It decodes no frame. It serves three streams:

1. **Regional raw:** batches routed by the receiver's declared cell, for relays' MLAT. Routing is
   by where the receiver is, never by decoded aircraft position. Relay-only since 2026-10-19 (below):
   it was also for research, but a receiver's counters and the aircraft positions everyone can read
   give its site to metres.
2. **Deduplicated:** one copy of each Mode-S message (byte-identical within a short window), for
   most clients, signed by the relay as its own claim. It is about 30 Mbps for the whole world at
   20,000 receivers, against roughly 1 to 2 Gbps of raw receptions. A client gets it with no
   counters (`ClientRegionalBatch`, below).
3. **MLAT results:** positions published by relays' MLAT (§3.8), signed by the relay; a client gets
   them tagged (§3.8.1).

A subscriber chooses with `Subscribe { streams, regions }`, which it may send at any time and which
replaces the last one; before any, a relay link gets raw batches for the whole world (a client is
never sent raw, below). Regions are H3 cells of any resolution (`wire::region`, the one place that
says whether a receiver is inside one), matched on a relay link against the receiver's newest
signed site and on a client link against its public cell (below); a receiver with no location
reaches only whole-world subscriptions. In wire version 1 the deduplicated stream is whole-world
only: it mixes every receiver, so it is not cut by region. A relay derives its own deduplicated
stream and never forwards another relay's; positions travel between relays like batches, verified
and forwarded once by hash.

**What a client may be sent is a type** (amended 2026-10-19, founder). A client is every peer that
is not a relay or engine on a version 3 link (§3.3): free-tier, credited, vouched and linked
subscribers, feeders, probes, and everything built on them (the HTTP API, the stats endpoint, any
product). The client column of the egress table carries `tally_wire::ClientRecord`, never `Record`,
and `ClientRecord` has no variant for a relay-only record; where one wire type has both forms, the
variant holds a wrapper whose only constructor refuses the relay-only form. Conversion is one
`TryFrom`, which names every relay-only record and hands back what it refuses, so egress counts it
and a new record kind does not compile until someone classifies it. It is never a filter in a
subscription's `wants`.

| Relay-only                                   | Why                                                    | A client gets                       |
| -------------------------------------------- | ------------------------------------------------------ | ----------------------------------- |
| `ReceiverSite`, `ReceiverInfo` format 1      | the exact site                                         | `ReceiverInfo` format 2             |
| `Batch`, `RelayBatch`, `RegionalBatch`       | counters: reverse MLAT, ranging by clock line          | `ClientRegionalBatch` (no counters) |
| `Positions`, `Provisional` formats 3 and 4   | receiver, epoch and counter of every reception         | formats 5 and 6 (tags, §3.8.1)      |
| `ClockModel`, `ClockModelPart`               | every member's site, and the clock offsets             | `ClientClockModel`                  |
| a `FaultProof` of raw-form records or models | it carries the records above                           | a format 1 proof of tagged records  |
| an `EvidenceBundle` holding a site           | it carries the site                                    | a bundle by reference (RFC-0174 §2.1) |

What follows from it:

- **The relay holds the site and the description apart, and checks the pair.** Per receiver it
  keeps the newest `ReceiverSite` and the newest description, and refuses a pair whose public cell
  does not hold the site, so the cell a client sees is the cell the site is in.
- **Routing.** The hub keeps each receiver's exact point for relay links, and matches a client's
  regions against the receiver's public cell. A client region finer than resolution 6 is clamped
  to its resolution 6 ancestor, so 64 regions can no longer descend to about a square metre and
  learn a site from which receivers' traffic arrives. A receiver's area is the resolution 3
  parent of its public cell (`tally_wire::site::SHARING_AREA_RESOLUTION`,
  `rendezvous::area_of_cell`): the feeder picks its relays by it and relays group and route its
  data by it, so nothing a feeder's choices reveal is finer than its public cell.
- **`--beast-out` serves each reception's message alone.** Its plain BEAST frames carry no
  counter and no signal level (`tally_wire::ClientObsView`), so it is a client's form of the
  receptions: a public map or API decoded from it (RFC-0187's `tally-map`, `tally-api`) can
  place no receiver. It is unauthenticated and uncapped, so it refuses to bind anything but
  loopback.
- **The stats endpoint** (`--stats-listen`) shows each receiver's public cell, never its site or
  altitude, and refuses to bind anything but loopback.
- **Altitude** is in no client form: the site is the only record that carries it.

How relays divide the work is RFC-0174's shape, which replaces the regional and top relay tree
first described here: one kind of relay; each feeder sending to the two nearest healthy relays on
different networks (RFC-0174 §2.2); each area's MLAT done by two or three relays chosen by a shared
rule, the others passing raw to them one hop (§2.3); and every stream spreading per area through
striped sharing trees, its sources sending a fixed few copies and each relay forwarding its slice
(§2.5). What stands of this section's contract: `Subscribe` by streams and H3 regions as above; a
relay that cannot carry a peer answers `Redirect` to its hints and never waits for a slow one; a
free tier capped per client and in total, with firehose access on a linked relay's credit (RFC-0174
§2.1); and the upload cap and priorities below. Taking data in costs a relay only its server; what
it sends out is its own to cap.

As built (2026-10-07), one `tally-relay` binary does all of it: `--area CELL` (repeatable) names
the areas it takes, `--advertise HOST:PORT=KEY` where it answers, `--network ASN` the network it
is on; MLAT runs in-process (on the threads the cores' plan leaves it, RFC-0181 §10, "The cores";
`--no-mlat` for none) for the areas it is chosen to solve; `--no-relay-duties` turns off accepting feeders, MLAT and seeding
for a relay that only shares; `--world` and `--world-precise` gather the two world products
(RFC-0174 §2.11). A relay whose signed offer it verified may connect to exchange its sharing
group's records without being named by `--accept-relay`.

**The upload cap and its priorities are part of a relay's contract** (decided 2026-10-06, replacing
the monthly egress budget built earlier that day; `tally/crates/relay/src/egress.rs`). A monthly
budget makes a relay go dark near the end of its month: its feeders' data then reaches nobody, and
a delivery check cannot tell it from a relay that swallows data. A speed cap bounds the bill just as
hard and never goes dark; it only sends lower-priority traffic slower.

- `--max-upload RATE` is required (`kbit/s`, `Mbit/s`, `Gbit/s`, `kB/s`, `MB/s`, `GB/s`, decimal as
  hosts state them, or `KiB/s`, `MiB/s`, `GiB/s`); the relay refuses to start without it, naming
  `6Mbit/s` (at most 2.01 TB out in 31 days, leaving about 1 TB of a $12 Lightsail plan's 3 TB for
  what feeders send in, since both directions count) and saying that the bill can never exceed the
  cap times the seconds in a month. `0` with a unit sends nothing billed,
  and a hub built in code with no cap sends nothing billed. There is no period, no state file and
  nothing to reset on a restart.
- Every byte written to a peer passes one place, the socket (`egress::Socket`): handshakes, rate
  limits, heartbeats, goodbyes, redirects and records, on every role's connection, upstream links,
  beast-out and the stats listener. A connection cannot be served without one. The cap fills one
  token bucket (a second of the cap, at least 64 KiB) and a billed socket writes only what the
  bucket paid for, so over any window `t` the relay sends at most the bucket plus the cap times `t`.
  Bytes to a loopback peer are counted apart and never capped, because no bill counts them; any
  other address, private ones included, is billed.
- Each record is classified once, as its link gathers it, into a fixed class, and the classes are
  strict priorities, highest first:
  1. **Control** (handshakes, `RateLimit`, `RelayList`, heartbeats, `Goodbye`, `Redirect`): never
     queued; it is what a socket writes beyond its grants, and it alone may draw the bottom 2% of
     the bucket (at least 4 KiB), so it always gets through.
  2. **Positions** and clock models (with their parts) and fault proofs to a relay link or an
     MLAT link: what this relay's MLAT originates and the final positions and models it forwards.
  3. **Raw** batches, with the receiver descriptions they travel with, to a relay link or an
     MLAT link: the border raw MLAT needs.
  4. **Forwarded**: the rest a peer that forwards is sent (the deduplicated stream).
  5. **Provisional** positions (`Provisional`, §3.8.1) to a relay link: below the final
     positions and the raw they are solved from, since a final one follows each.
  6. **Taker**: everything a plain subscriber or a beast-out client is sent.

  A data send waits for a grant from the bucket; a class is granted nothing while a higher one
  waits, so lower classes get what higher ones leave. Within a class, grants go by start-time fair
  queuing per peer, 16 KiB at a time.
- Once a grant has waited 2 s, one waiting peer is shed every 250 ms: from the lowest class anyone
  waits in, the one asking the most of it (bytes asked for, averaged over ten seconds). Plain
  subscribers are the lowest class, so a relay link or an MLAT link is never shed while a plain
  subscriber waits. (A critic found that the budget's rule, the subscriber with the most bytes
  sent, picked the one forwarding to everyone else.) A shed peer is sent `Redirect` to the
  relay's hints, or `Goodbye { Full }` if it knows none, retrying after ten minutes.
- A new feeder is accepted only while the cap's headroom (the cap less what control and classes 2
  to 4 ask for, with each admitted feeder holding at least its commitment) covers what it commits
  the relay to forward: 100 kbps (§5's per-feeder upload) to each billed relay link and MLAT link, or
  the feeders' average share of the raw asked for if more. Past that it is answered the same way,
  before anything it sent is taken in: the relay never accepts data it cannot deliver. With no
  billed relay link or MLAT link, a feeder commits the relay to nothing.
- `GET /egress` on `--stats-listen` reports the cap and the most it lets out in a month, the bytes
  sent (billed and loopback), the headroom, and per class the rate granted, the rate asked for,
  the sends waiting and their queued bytes, and the peers shed; and the feeders admitted and
  turned away.

A slow subscriber is dropped, never waited for: per subscriber a bounded queue, and a full queue
disconnects it (readsb's keep-latest rule, RFC-0119 §3.3).

What a relay holds is bounded, and what it trusts is narrow, because keys cost nothing to make:

- A peer may open a session as a relay only if this relay holds a live offer of its key, verified
  by a handshake at the address the offer names (a sharing member: its groups' records, and raw as
  an engine), or the operator accepted its key with `--accept-relay` (a directory link: the
  directory only); any other key is refused and asked to return after one re-signing of offers
  (60 s). One function decides it (`Hub::relay_trust`), at the session's start and while it runs.
  Intake ceilings are per role, decided by the role the handshake established and never by key:
  relays are held to `--max-member-bytes-per-sec` (8 MiB/s by default); every other inbound peer,
  an engine included (it publishes nothing), to a feeder's (`--max-feeder-bytes-per-sec`, 256 KiB/s
  by default). Feeders are told theirs as a `RateLimit`. Connections are capped
  (`--max-connections`).
- A relay reads two clocks, as TrueTime does on stock Linux. The wall clock is read in one place
  (`clock::RelayClock`), and the kernel's word on it in one place both ends share
  (`tally_wire::kernel_clock`); Clippy's `disallowed-methods` refuses `SystemTime::now`,
  `SystemTime::elapsed`, `UNIX_EPOCH.elapsed`, `libc::clock_gettime`, `libc::gettimeofday`,
  `libc::time`, `libc::adjtimex` and `libc::clock_adjtime` anywhere else (`clippy.toml`). The
  monotonic clock is std's `Instant`, read wherever a duration is timed: it is never compared
  across machines, and no reading of it can be wrong in a way another site's could not. `J` judges everything compared
  across machines: the usability windows, a feeder's clock, directory offers, manifests and
  receipts. It is the host's wall clock as its time daemon (chrony or ntpd, below) keeps it, with
  the kernel's error bound read by `adjtimex(2)` with no modes set (`STA_UNSYNC`, `maxerror`). `M`,
  the monotonic clock, drives epochs, ticks, the hosted MLAT's steps, paces and every duration. A
  stamp carries both. The relay never disciplines a clock of its own: the time daemon does. A step
  of `J` is seen exactly, as a change of `J - M` (which only a step moves), and ends nothing: it is
  counted (`clock_steps`) and the relay states its new clock to every feeder session. Until the
  kernel first reports the clock synchronised, and whenever its error bound (`maxerror`, which the
  kernel grows by 500 ppm a second from the last sync, so a clock that loses sync is judged on it
  and not on `STA_UNSYNC`) is past `E` = 7.5 s (`tally_wire::budget::E`), the relay states its
  error as unbounded and judges nothing by its clock. A kernel that will not answer the read (a
  seccomp filter, `ProtectClock=`) gives no bound at all, and the relay refuses to start, as
  `tally-relay check` does. The systemd units leave `ProtectClock=` off (it filters `adjtimex`
  whole), allow every system call the read may be after `~@privileged` (`adjtimex`,
  `clock_adjtime`, `clock_adjtime64`: `tally_wire::kernel_clock::SYSCALLS`, to which a test holds
  each unit) and fail a refused call with `EPERM` rather than killing the process; the empty
  `CapabilityBoundingSet` keeps `CAP_SYS_TIME` out, so the clock still cannot be set from them, and
  the relay orders itself after `chrony-wait.service` and `time-sync.target`. That target holds a
  start back only while a wait service is enabled (under ntpd, `ntpsec-wait.service` or
  `systemd-time-wait-sync.service`; neither is by default), so the ordering is no guarantee: what
  holds is the kernel's word, read at every judgement, as above.
  **The time daemon must be chrony or ntpd.** `E` is judged against `maxerror`, so `maxerror` must
  bound the clock against true time. chrony and ntpd set it to their root distance (the server's
  own distance from its reference plus half the round trip). systemd-timesyncd sets it to 0 at
  every adjustment (`src/timesync/timesyncd-manager.c`, `manager_adjust_clock`: `ADJ_MAXERROR` in
  the modes, the field left 0), so the bound it leaves counts only the kernel's 500 ppm a second
  since its last poll, never the server's error or the measurement's: a relay under it could judge
  by a clock seconds off while it reads milliseconds. Nothing stock tells that bound from a good
  chrony's (both are small with `STA_UNSYNC` clear), so neither end refuses it at run time and
  neither detects the daemon: one function, `tally_wire::kernel_clock::bound_ms`, is the only
  reader of the kernel's answer for the relay, the feeder and the API, and it takes the bound as
  the kernel states it (synced, or synced once, and within `E`). **Known gap:** under timesyncd
  that bound understates the clock's error and Tally cannot tell. The requirement is stated in
  the packaged units, the README and here, as the stock answer is. It is the feeder's too, for the
  same reason: a feeder trusts its host's clock only by the same bound (`tally_feed`'s
  `host_error_ms`), so the feeder's unit is ordered after the same two waits, the installer
  installs chrony from the system's packages when the host has neither chrony nor ntpd (Debian's
  package replaces timesyncd) and starts one installed and stopped, and the README's feeder
  section says so.
- Two predicates decide what a relay does with a record, each a pure function of its signed bytes
  and the relay's `J`; no verdict travels with a copy. **Possession** (held, sent down the stripe,
  receipted, its deliverer credited, its audit tags) never consults a clock: **nobody refuses a
  link over a clock**. No relay refuses, drops or ends a session for a clock, no feeder withholds
  a batch or replaces a relay for one, and nobody files a shortfall or withholds credit over
  usability. A clock decides usability alone, judged by each hop's own clock once, when a copy
  first arrives there (below). **Usability** decides whether a record
  reaches the products, subscribers or the hosted MLAT. Every window and tolerance it judges by
  is derived from one error budget (`tally_wire::budget`, the table below), in which each source
  of error is named once:
  - a feeder's batch where it publishes (`strikes::feeder_clock`, `strikes::Window::FEEDER`),
    however far ahead or behind, is possessed and passed on, and charged to its feeder's rate and
    share and its receiver's ceiling like any other, so a flood signed far off is bounded by the
    same budgets as one signed now. It is usable if `-F <= J - t <= F + B + LAG` (91 s behind,
    `budget::FEEDER_BEHIND`; a feeder signs at the low end of its reference, up to `LAG` below true
    time). Signed
    more than `F` ahead of `J` (a Pi that never synced, a host set by hand, or this relay's own
    clock stepped back), it is held unused at this hop and counted against nobody
    (`ahead_records`, and `unjudged_records`), as is every batch while `J` is not judging; its
    peers judge their copies by their own clocks. Older than that, it is held unused and counted
    against its receiver (`late_batches`, the stations report and `GET /v1/stations/{key}`). Either
    way off, its feeder is told the relay's clock again at its next heartbeat (`RateLimit`'s
    `clock_ms`), and its session goes on. A batch held unused is never taken into a strike table,
    so it pins no table's memory or floor;
  - any other copy of it, a peer's or one rebuilt (`strikes::Window::PEER`), is usable if
    `J - t <= U_p = F + B + LAG - K` (76 s) and `t - J <= S = F + K` (25 s), and not already taken.

  **The error budget** (`tally_wire::budget`). Each source of time error is named once, and every
  window and tolerance a relay or a feeder judges a signed time by is a `const` derivation from
  them, beside its reason and under compile-time assertions. Nothing outside the module can make a
  `Tolerance` or a `Window` (their constructors are private to it), so no file writes a time
  tolerance from a literal: a new one is a new derivation there. Three rounds of review found a
  window derived by hand that left out one error (the selection's low-end lag, the wrong term in
  the blame allowance); one budget is how that class ends.

  | term | value | what it absorbs |
  | --- | --- | --- |
  | `E` | 7.5 s | a judging relay's clock (or a synced host's bound) against true time |
  | `U_m` | 1 s | a feeder's measurement of one relay's clock (half a round trip, and drift at 500 ppm) |
  | `δ` (`TRANSIT`) | 1 s | one way between a feeder and a relay, either direction |
  | `P` (`ANCHOR_PERIOD`) | 1 s | how often a relay signs a new anchor |
  | `ANCHOR_HELD` = `2P` | 2 s | how long a feeder signs by an anchor after it first heard it |
  | `F` | 10 s | a feeder's signed time ahead of its relay; `F >= E + U_m + δ` |
  | `B` | 64 s | how long a feeder may hold a batch, gathered to sent: `ANCHOR_WAIT + BACKLOG_DRAIN` |
  | `ANCHOR_WAIT` = `B - BACKLOG_DRAIN` | 62 s | how long a feeder holds a batch for an anchor before it signs it with none |
  | `BACKLOG_DRAIN` = `SEAL_PERIOD + CEILING_BURST` | 2 s | what a released backlog adds to a batch's way out: one seal's wait, and the burst its session's pace lets through at the ceiling |
  | `REPAIR_TRANSIT` | 2 s | a repaired copy's way to the member that asked |
  | `K` = `2E` | 15 s | two judging relays' clocks apart |
  | `LAG` (`SELECTION_LAG`) = `2(E + U_m)` | 17 s | the widest trusted reference, so how far below true time its low end, where the feeder signs, may be |
  | `ANCHOR_AGE` = `P + δ + 2P` | 4 s | an honest anchor's age as a batch is signed by it |
  | `ANCHOR_ABOVE_REFERENCE` = `E` | 7.5 s | an honest anchor above its reference's high end (the reference holds true time) |
  | `ANCHOR_BELOW_REFERENCE` = `E + P + δ` | 9.5 s | an honest anchor below its reference's low end, as it is heard |
  | `FEEDER_BEHIND` = `F + B + LAG` | 91 s | a feeder's batch at its origin: its lag, its hold, and `E + δ <= F` |
  | `FEEDER_AHEAD` = `F` | 10 s | the same, ahead |
  | `PEER_BEHIND` (`U_p`) = `FEEDER_BEHIND - K` | 76 s | any other copy: too old at its origin is too old at every relay within `K` |
  | `PEER_AHEAD` (`S`) = `F + K` | 25 s | any other copy, ahead |
  | `W_a` (`ANCHOR_BEHIND`) = `FEEDER_BEHIND + E + P + δ + 2P` | 102.5 s | a batch's oldest known anchor behind a hop |
  | `ANCHOR_AHEAD` = `LAG + 2E` | 32 s | the same, ahead |
  | `OWN_ANCHOR_OLDEST` = `ANCHOR_AGE + B + δ`, drifted at 500 ppm | 69.035 s | the oldest an honest batch's own anchor is where it is published, by the origin's raw monotonic clock |
  | `MLAT_BATCHING` | 2 s | a receiver's last raw of a bin, gathered and on its way |
  | `MLAT_AHEAD` = `E` | 7.5 s | how far past a batch's judging time a hosted MLAT bin may begin |
  | `MLAT_SETTLE` = `MLAT_BATCHING + E + 2U_m` | 11.5 s | how long after a bin ends the hosted MLAT takes it |
  | `MLAT_SOLVE` | 80 s | a final fix's way out of its engine after its window settles (the engine's design) |
  | `FINAL_FIX_ARRIVED` = `MLAT_SOLVE + MLAT_SETTLE + K + REPAIR_TRANSIT` | 108.5 s | when a final fix has surely arrived, wherever it is read |
  | `RESTATE_BEYOND` = `F / 2` | 5 s | how far a feeder's signed time may be from its relay's clock before the relay restates its clock |
  | `FALLBACK_FLOOR` = `S + K` | 40 s | a strike table's floor with no state |
  | `RECEIPT_AHEAD` = `K` | 15 s | a credit receipt's issued time ahead of a relay (issued by another judging relay's clock, so at most `K` apart) |
  | `PRODUCT_AHEAD` = `K` | 15 s | a precise MLAT second ahead of the API's clock |
  | `ACARS_MESSAGE_SKEW` | 300 s | exempt: an ACARS message's own time is an aircraft's or a ground station's, set by no clock of ours |

  Every comparison of a signed time against a clock goes through the module: a `Tolerance`'s
  `ahead`, `past`, `apart` or `covers`, or a `Window`'s `holds` (`Window::FEEDER`, `PEER`,
  `ANCHOR`, `FIGURES` for a batch the feeder figures count, `FIGURES_POSITIONS` for a final MLAT
  position they count, `relay_signed`, `proofs`, `figures`). A regional batch is judged by the
  relay-signed window alone (it was judged a second way, 10 s ahead at most, after the hub had
  taken it as new, so one `K` ahead was lost); a directory offer, a credit receipt, a feeder
  figure at the API and a world fix by a `Tolerance` (the last by `S`, where a literal 2 s
  dropped an engine's fixes a few seconds ahead). What the module does not hold is no clock's error
  but a choice of how old a thing may be served or counted on one machine's own clock: a
  product's age at the API, a station's "online", the world product's history before its first
  seal, a fan-out queue's lag.

  The relay-signed windows (`Window::relay_signed`, `Window::proofs`, `Window::figures`) are
  derived there the same way from an engine's lag and a group's horizon. A property test holds the
  budget end to end (`hub::the_error_budget_holds_end_to_end_for_honest_feeders`): every batch is
  made by the feeder's own code (`RelayClocks`, `Batcher::seal`, its hold for a first anchor) and
  every honest anchor issued by its relay's own hub (`Hub::anchor`, which remembers its issue), by
  four relays whose clocks stay within `E` of true time: one at `-E`, one at `E`, one a daemon
  slews by 5 s over 69 s, one stepped by `E` either way halfway through each case; configured and
  hinted, a hinted liar whose anchor sits at the bottom of the band an honest one may, hosts
  synced, unsynced or hours off, held up to `B` and on its way up to `δ`, members releasing copies
  later at the edge of a member's window, at the signed time or hours on, to hops that never saw
  them; half the cases with every error at one edge of its range or the other. Its oracle is the
  world, not the budget: it reads only the world's own figures (`E`, `U_m`, `δ`, `B`, a member's
  first copy within 50 s, two minutes of freshness), so a window derived too tight or too loose
  fails it. For every honest case it asserts the feeder is never blamed, whatever its origin's
  clock did; with a trusted reference every honest anchor is carried, the batch is used at its
  origin when it arrives within `B + δ` of being gathered and at a member within 50 s; a batch its
  origin used is used by a member that knows only honest anchors of it within 50 s; and no batch
  is used more than two minutes after it was signed in true time where the hop knows an honest
  anchor of it. Liveness is lost only in the stated residual. It fails with `W_a` at 100, 92 or 88
  s, and a mutant of each term of the budget fails it or a test at that term's edge.
  A feeder's batch is usable at a hop only by the **freshness anchors** in its signed bytes
  (`tally_wire::Anchor`, `anchors`), the pattern of TLS 1.3's 0-RTT tickets (RFC 8446 §8.3, a
  ticket's age bounded by the server's own issue time) and of Roughtime's nonces. A hop's own
  evidence cannot say when a batch was made (one whose first copy arrives at the batch's signed
  time has none), so the proof travels in the batch.
  - **The threat they answer**: relays that would make an honest feeder's data look fresher than
    it is (a member that holds a reception and releases it later as live). A malicious feeder is
    out of their scope: it can fabricate receptions at real time anyway, so a far-ahead or late
    release of its own adds it nothing. That is the untrusted-feeder problem, which MLAT and
    consensus answer; a test pins it as out of scope. No standing or credit gates an anchor.
  - A relay signs an anchor, its key and its `J` (`Anchor { relay, j_ms, sig }` over the domain
    `tally/anchor/v1`), about once every `P` = 1 s (`budget::ANCHOR_PERIOD`), through its signer
    and so only while its clock is judging, and states its newest to every feeder session in its
    greeting and each period after (`Record::Anchor`, kind 0x2a). A relay whose budget cannot
    hold its anchor cache refuses to start.
  - A feeder keeps each session's anchor heard last (the same anchor stated again is not heard
    anew, so its age counts from when it was first heard) and signs by one at most `2P` after it
    first heard it (`budget::ANCHOR_HELD`), so an honest anchor is at most `3P + δ` = 4 s old as
    a batch is signed by it (`budget::ANCHOR_AGE`: up to `P` at its relay, `δ` on its way, `2P`
    held). It carries one anchor a relay, in the anchored formats (`batch::format::ANCHORED`), at
    most `batch::MAX_ANCHORS` = 2, and filters them only against a **trusted reference**, never
    against its raw clock (anchors matter exactly when that clock is wrong, and a filter by it
    would keep the lie that matches it and drop the honest anchor) (`source::RelayClocks::anchors`):
    - With a reference its operator trusts (a selection of its configured relays, NTP's rule, or
      its host while the kernel reports it synced to its own configured servers), it carries only
      anchors that **agree with that reference** as an honest relay's must, judged against the
      reference's whole interval `[lo, hi]` as the anchor was heard, never a point of it (the
      reference holds true time somewhere inside it, and the feeder signs at its low end): at most
      `E` above `hi` (`budget::ANCHOR_ABOVE_REFERENCE`, the relay's own error) and `E + P + δ` =
      9.5 s below `lo` (`budget::ANCHOR_BELOW_REFERENCE`, the relay's error, the anchor's age as
      stated and its transit; `budget::anchor_outside`). One that disagrees is left out and its
      health says "relay X's anchor disagrees with your reference by N s". A lying relay its
      operator did not configure can then neither make its batches unusable nor make stale ones
      look fresh. If none agrees, it carries none: there is no nearest-anchor fallback.
    - With no trusted reference (no configured majority, and its host unsynced), it carries
      every session's newest anchor unfiltered, and the hop takes the oldest it knows. Safety
      wins: a lying relay can then make that feeder's batches unusable (a loss of liveness,
      counted against nobody and shown on its health), never make stale ones look fresh.
    - When there are more anchors than slots, the oldest reading always takes one and the last
      heard the rest. A feeder holds two sessions, and its sessions are at most
      `batch::MAX_ANCHORS` (asserted at compile time, `selection::DESTINATIONS`), so each relay it
      publishes to finds its own anchor in the batch unless the trusted reference left it out.

    Before its first anchor it holds its batches in order within its backlog and drops none; one
    that waited `ANCHOR_WAIT` (62 s) is signed with none, and counted (`unanchored`). When an
    anchor comes, the backlog is released at the next seal and each session sends it at the
    ceiling, its pace waiting for tokens and never skipping a batch; a session at least as fast as
    the ceiling sends the oldest released batch within `BACKLOG_DRAIN`, so it leaves within `B` and
    lands within `FEEDER_BEHIND` (a compile-time assertion in `tally_wire::budget`). Batches a
    session was too slow for (a relay that stated a rate below the feeder's) are lost to it and
    counted in the feeder's health (`lagged`). While it carries no
    anchor past a relay's grace, its health says "carrying no anchor for N s, data unusable at
    every relay (M batches signed unanchored)".
  - A hop judges only the anchors it can check: of a relay it knows (its own key, a relay whose
    live offer it holds, or one its operator accepted: `Hub::relay_trust`) whose signature
    verifies. An unknown or forged anchor is no evidence and changes nothing; with none it can
    check, the batch is unanchored (`unanchored_records`). Otherwise the **oldest** of them, `A`,
    must be within `Window::ANCHOR`: `J - A.j_ms <= W_a` (102.5 s) and `A.j_ms - J <=
    ANCHOR_AHEAD` (32 s). This is
    besides the window of its signed time `t`, never instead of it. The oldest decides, so a known
    relay's lie can only make a batch less usable: one in the future is outweighed by an honest
    one, and an old one only ages it. The ahead bound, `LAG + 2E` = 32 s
    (`budget::ANCHOR_AHEAD`), is the most an anchor an honest feeder carries can be ahead of an
    honest hop: one a feeder with a trusted reference carries reads at most `E` above the
    reference's high end, which is at most `LAG` above true time, and the hop is at most `E`
    behind it; an honest relay's own anchor is within `E` of true time. A batch unusable by its anchors (stale, ahead or unanchored) is still
    possessed and passed on, receipted and credited, and **blamed on nobody**: it is counted
    relay-wide (`late_records`, `ahead_records`, `unanchored_records`), never in its receiver's
    `late_batches`, so a lying relay's anchor never blames an honest feeder. The judgment is a
    pure function of the signed bytes and `J`, so it needs no state and survives any restart,
    with or without a state directory.
  - **What is blamed on a receiver** (`late_batches`) is one thing only: a batch too old by its
    own signed time `t` where its feeder published it, and only once, when it is first judged
    there. A relay keeps each receiver's last boot judged and the highest sequence of that boot
    judged from its feeder (`stations::Stations::first_judged`); a feeder sends in order, so a repeat (a
    resend, an audit's owed batch) is at or below it and is judged as ever and counted
    relay-wide, but blamed on nobody (a batch first seen out of order is not blamed, which only
    undercounts; one boot is held, so a repeat of an earlier boot's batch after a later boot's
    was judged is judged anew, and may be blamed again, the one case it overcounts). Nor is a feeder blamed for the time it held a batch waiting for its first
    anchor, nor for its origin's clock: a batch too old by `t` is blamed only when **this relay's
    own anchor** in it is older than `OWN_ANCHOR_OLDEST` too (`strikes::blame`). The
    origin issued that anchor and remembers when, by its **raw monotonic clock**
    (`CLOCK_MONOTONIC_RAW`, `RelayClock::raw`), in a ring of its recent issues sized for the
    allowance (`anchors::OWN_ISSUES`, `Anchors::issued_by`), so the anchor's age is measured
    exactly, `Raw_now - Raw_issue`, never by `J` nor by `M`, which a daemon may slew (chrony at up to 83,333 ppm)
    or step within `E` meanwhile; the raw clock's own rate is off true by at most 500 ppm, counted
    in. An honest batch reaches its origin at most `ANCHOR_AGE + B + δ` = 69 s after that anchor
    was issued (stated up to `P` after its signing, `δ` to the feeder, held up to `2P`, then the
    batch held up to `B` and `δ` on its way), so no term for the clocks is needed. The origin knows
    its own anchor's truth (it signed and timed it), so no other relay's anchor moves the blame,
    and a batch is blamed the same whatever else it carries. A held batch carries the origin's
    anchor newer than its `t`, so its hold is not counted; one sent at once is blamed as by `t`, or
    later; one without the origin's anchor is blamed by `t` alone. One whose anchor has left the
    ring is aged from the newest issue the ring let go, which it was issued no later than, so its
    age is never overstated. And for `OWN_ANCHOR_OLDEST` after a run's first issue (a restart),
    the origin cannot tell an earlier run's anchor from none, so it blames nothing
    (`strikes::OwnAnchor::Unknowable`). A batch below a strike table's floor is late
    by this relay's clock, not its feeder's, and blamed on nobody.
  - `W_a` = `FEEDER_BEHIND + E + P + δ + 2P` = 102.5 s (`budget::ANCHOR_BEHIND`, asserted at
    compile time): `J - A.j_ms = (J - t) + (t - A.j_ms)`. The first is at most `FEEDER_BEHIND`
    wherever `t` is usable. The second, for a feeder with a trusted reference: it signs at the
    reference's low end as it signs, and carries only anchors at most `E + P + δ` below that low
    end as it stood when each was heard, at most `2P` before (`RelayClocks::anchors` judges each
    against the reference now, shifted back by the time since it was heard); an honest relay's
    anchor is within the same bound by its own road (its relay up to `E` behind true time, the
    anchor up to `ANCHOR_AGE` old, the feeder never ahead of true time). So no batch of a feeder
    with a trusted reference whose `t` a hop may use is ever stale there by an anchor it carries.
    Without a reference nothing ties its signed time to its anchors (its clock may be hours off),
    so that claim is not made for it: its batches are judged by both windows, and the guarantee
    below still holds. A test holds the worst an honest feeder meets, built from the world's
    figures alone (its reference `2(E + U_m)` below true time, a band-bottom anchor heard `2P`
    before, sent `B` after signing and `δ` on its way to an origin `E` ahead: 101 s, used), and
    the window's edge to the millisecond.
  - **The guarantee**: for an honest feeder, as long as one honest anchor it carries is known at
    the hop, every batch used at an honest hop was made no earlier than `J - W_a` by that hop's
    clock (in true time, within `W_a + 2E` = 117.5 s).

    **What that staleness costs the products.** Neither the live map nor MLAT takes old data for
    new. The live world product gathers fixes by their own transmit second and seals each second
    `WORLD_SETTLE_MS` after it ends: a fix of a second already sealed is late (`world_late`) and
    dropped, counted, never drawn as current, and a fix older than the history before the first
    seal is out of its window. The hosted MLAT bins raw by its signed time and takes each bin
    `MLAT_SETTLE` after it ends by the relay's judging clock: raw of a bin already taken is late
    (`observations_late`), counted and lost to MLAT alone, never solved as current; the solver
    never sees it. So a batch used up to `W_a + 2E` after it was made can only be late for them:
    the worst-case staleness costs liveness of those products, never their truth.

    **The hosted MLAT's bins** are judged by the relay's judging clock (`Stamp::judging`, carried in
    each decode as `Decoded::judge_ms`), never by its monotonic clock aligned to it once at start:
    a bin may begin at most `MLAT_AHEAD` = `E` past a batch's judging time (an honest feeder signs
    at or below true time, the relay at most `E` behind it), and is taken `MLAT_SETTLE` = 11.5 s
    after it ends by that clock (its batching and way, and an honest feeder whose selection holds
    this relay signs at most this relay's stated error and twice its measurement below its
    clock). The steps run on the monotonic clock and settle by the judging time of the step: the
    products publish one (monotonic, judging) pair with their watermark (`tally_wire::clocks::
    Moment`), and every step reads both from it, so the same stamped trace gives the same bytes.
    The two are distinct types (`Mono`, `Judged`, and `Raw` beside them): a signed or grid time is
    compared with a clock only through `tally_wire::budget`, whose every comparison takes a
    `Judged`, a span measured on one clock is a `Span` of that clock and moves no other's reading,
    no reading has a default, and none is made from a number but as one a reader took, given back
    (`recorded`, which Clippy refuses outside replays and tests). So handing a monotonic reading
    to a comparison with a signed or grid time, or moving one clock's reading by another's span,
    does not compile: `tally_wire::clocks`'s and `tally_wire::budget`'s compile-fail examples
    (`//crates/wire:wire_doc_test`) hold each such line. Each shard's lateness is the batch's own two readings, so a step
    of the host's clock moves the bins with it and offsets nothing. A window step's final fixes are
    refused and counted once `FINAL_FIX_LEAVES` (`MLAT_SETTLE + MLAT_SOLVE`) has passed since the
    start of the earliest bin it solves (the earliest a transmission in it can be), by the judging
    clock, so `FINAL_FIX_ARRIVED` holds of every fix published; its clock models are published all
    the same, since provisional solving already carries them, and a step already past that bound
    when its turn comes is not solved at all (`MlatReport::window_steps_passed`).
    The residual: a feeder whose reference leaves this relay out may sign up to `LAG` and `E` more
    below it, and its raw past the settling is late for MLAT, counted and blamed on nobody. It is
    left out for seat cost: covering it would reserve every seat's open raw over a span `LAG + E`
    longer, and the world relay's seats (`tally/crates/relay/tests/world-relay.txt`, RFC-0181) have
    no such margin over their 2,000 floor; its raw lands bins away from its peers' receptions of
    the same transmissions, so MLAT pairs little of it anyway. A seat's open raw is reserved over the bin,
    the settling, the seals that may fall behind and `MLAT_AHEAD`: 29 s of its ceiling, where it
    was 13 s before these were derived (RFC-0181's tables). **The residual**, stated exactly and pinned by a test
    built on the feeder's own `RelayClocks`:
    - with a trusted reference, its configured sources lying (operator trust): they set the
      reference, the honest anchors disagree with it and are left out;
    - without one, every relay it anchors with lying, since those can sign a reading of any time.

    **Liveness**: with a trusted reference, every batch whose `t` a hop may use is used there if
    the hop knows an anchor it carries: at its origin every batch sent within `B` of being gathered,
    at a member every first copy within 50 s of it. Without one, a single lying relay among its sessions can
    make that feeder's batches unusable wherever the liar is known, counted against nobody; its
    operator fixes it by configuring a relay or syncing its host. A property test over feeders
    hours and days off, with and without a configured selection, beside a colluding and a lying
    relay, holds both per case.
  - The only state is a cache of anchors verified here (`anchors::Anchors`, 4,096 slots, fixed and
    allocated once, `Store::Anchors`), so a hop checks a relay's anchor once and not for every
    batch. A miss costs one signature check; correctness never depends on it.
  - **A required upgrade.** A batch in a format older than the anchored ones (a feeder from before
    them) is possessed and passed on, and never usable: relays upgrade first (they read both), then
    feeders.
  `U_p + K == FEEDER_BEHIND` is asserted at compile time: a copy too old where it was published is too old
  at every relay within `K` of that one, so nothing travels with a copy to say so. The
  relay-signed kinds keep windows derived the same way (`strikes::Window::relay_signed`: an engine's lag, the horizon and a
  second, the transit and `K`, 43 s behind, `K` ahead; fault proofs, `Window::proofs`, 122 s behind,
  `S` ahead; feeder figures, the relay-signed window stretched by their hour), and possession
  never uses them. A record whose time cannot be read is malformed (no format leaves it out),
  counted as `unreadable_times` and refused as one that fails its signature is: that is the bytes,
  not a clock. A member's manifest never makes a copy usable: a replay of an archive is too old
  however fresh the manifest listing it.
- A usable record is used once, judged by a strike register (RFC 8446 §8.2, as QUIC keeps one,
  RFC 9001 §9.2; Kerberos's replay cache, RFC 4120 §3.2.3; `strikes`), never by its place in a
  stream: `t` is its author's signed time (a feeder's `wall_ms`; an engine's `issued_ms`; the time
  a relay signed a regional batch, its client form or bundle index; the newer of a fault proof's
  two records). Each table (the raw batches of each ingest shard, positions, provisional positions,
  clock models, fault proofs, feeder figures, and what is passed on by hash) remembers each record
  it used as an 8-byte fingerprint keyed by the state directory's key (`strike.key`; with no
  state directory, a secret of the process), in a generation for each
  bucket of a second (a minute for figures) that `t` names, until the bucket holding the longest
  any copy is usable after `t` has passed (91 s for a batch, about 117 s of life at the most
  counted from a copy signed `S` ahead). Each table keeps a monotone forgetting floor, the highest `t` it
  may have forgotten: dropping a generation raises it to the most that generation could hold. A
  record is new if `t` is above the floor, it is usable, and its fingerprint is not held. So a step
  of the clock either way, or a glitch, makes nothing new twice and needs no restart. A new record
  is mistaken for a copy with probability the generation's fingerprints over 2^64, about one in
  650 relay-years at the most a relay admits (`strikes`'s module doc says why eight bytes).
- A restart forwards nothing it forwarded before (`durable`). Each table keeps on disk a lease
  `H` of the newest `t` it may use: `H = t + L` (`L` = 2 s, `durable::LEASE_MS`) is written and
  synced before the first record past the last `H` is used, and a background renewer moves it on
  once a record lands within `L/2` of it (standard lease renewal), so a take seldom waits on a
  sync. A restarted table's floor is `H`, and the higher of `H` and the fallback floor only when `H`
  is past `S + L` ahead of the synced clock (below). Tables of few records whose `t` lies long before they are
  sent (feeder figures, fault proofs) keep their fingerprints themselves: a checkpoint, and a log
  each use is appended to and synced before it is used, folded into a new checkpoint once it
  outgrows the table. A regional batch a peer sent is taken into what is passed on by hash before
  the products use it, so its lease covers it and a crash never has it merged twice. A graceful
  stop (SIGTERM: every session told goodbye, then exit 0) takes nothing more, then dumps every
  table's fingerprints and floor beside each lease's bound, so a deploy is not deaf for a window.
  A run whose clock never synced writes no dump: its tables never began, so it has no floor of its
  own to state. A resumed table's floor is the dump's, but never below what a lease proves on its
  own (the bound of a lease another run wrote, which the dump's run never moved): no file lowers a
  floor a lease proves.
  With no state, every table starts at `J + S + K` (`budget::FALLBACK_FLOOR`, with `L < S`
  asserted): the old process may have used records `S` ahead of its clock, which may have been `K`
  ahead of this one's. The cost is that long with nothing new used here; possession still flows,
  so nobody is blamed.
- Every file in the state directory has one format, written as a stock checkpoint is (a file
  beside it, synced, renamed over it, the directory synced): a magic and format version, its kind
  (lease, dump, table checkpoint, log), the name of its key (a keyed hash of a constant under the
  directory's key), its layout (for a table's checkpoint and log, the table's name and windows:
  how long it keeps a record, its bucket and its ring; for a dump, every table's and the ingest
  shards' count; for a lease, its name alone, since its bound is a signed time whose meaning no
  window changes), the run that wrote
  it, its body, and a keyed code (SipHash-2-4 under the directory's key) over all of it; a log's
  records carry a code each, and a checkpoint names the generation of the log it begins. A file
  missing, torn, of another version, key or layout, or whose code does not match, is not trusted,
  and its table starts at the fallback floor, never at none; so does a checkpoint whose log is
  missing, not trusted or of another generation (the log held what was used since). A key file
  that is cut or changed is replaced by a fresh key, so every file under the old one is refused
  and every table starts at the fallback floor; the relay does not crash for it.
- One process writes a state directory: it holds an exclusive `flock` on its `lock` file for its
  whole life and refuses to start without it, as PostgreSQL and etcd do. On Kubernetes the
  relay's deployment replaces its pod with the `Recreate` strategy, so the old pod has let go of
  the volume before the new one starts. A dump is consumed once: it is read back only when every lease
  holds what it was written beside, and only after it is renamed to a consumed name and the
  directory synced; one that cannot be is not read, and the leases' floors stand.
- Nothing is derived from the wall clock until it is synced (`clock::RelayClock::judging`).
  Until then no table has a floor and none judges anything: every record a feeder or a peer sends
  is held, possession only (its group holds it, its receipts and credit flow), counted unjudged
  (`unjudged_records`), never used and never blamed on anyone; and the relay signs nothing (products, feeder figures, engine records). Once it is synced every
  table begins at its lease's bound when the lease is there and trusted (the bound covers every
  record the run before used, so it is the floor even below the fallback), and at the fallback
  floor from the synced clock when it is not. A run takes records up to `S` ahead of its clock and
  its bound is `L` past the newest it took, so a bound up to `S + L` ahead is a quick restart's. A
  bound further ahead of the synced clock was left by a run whose clock ran ahead, and that run may
  have used records up to it, so the floor is the higher of it and the fallback: no restart ever
  uses a record again, with no exception. The cost is a relay that uses nothing new until the clock passes the
  bound, bounded by how far ahead the bad time source was; it says so loudly at start, with how
  long until it clears, and counts it (`leases_ahead`, `lease_ahead_until_ms`). A clock that loses sync after the start is
  judged on the kernel's error bound, which grows from the last sync: the relay keeps judging and
  signing while that bound is within `E`, and stops (holds, signs nothing, refuses no one for
  clock) once it passes it, until the clock is synced again. Every relay signature goes through
  one seam (`signer::Signer`), which lends the key for one call only while the clock is judging,
  so a new signer cannot skip the gate. The types hold it, not a convention: the key (`Identity`)
  is not `Clone`, the relay moves its newest into its one `Signer`, and what a signing is lent
  (`Signing`) cannot be kept past the call; the transport handshake, which states no time, is the
  one use apart, by a key that cannot sign (`NoiseKey`). The wire crate's doc tests hold each
  refusal as a compile-fail check. The state directory is the unit's `StateDirectory=tally-relay` or `--state-dir` (on
  Kubernetes, a small persistent volume with one writer), and must never be restored from a
  backup: an old lease is a floor too low.
- The memory is planned and closed when full. Each class of deliverer (the feeders, the peers,
  the relay's own; `strikes::Class`) has a store of its own (`Store::FeederStrikes`,
  `Store::PeerStrikes`, `Store::OwnStrikes`) and its own ring of generations in every table, so
  whatever one class holds, and however its sets grow, never takes another's room. Each entry is
  planned at 32 bytes, its set's peak (a set doubled past three quarters full holds its old slots
  beside its new while it grows, and one generation may hold every entry of its class), over the
  longest an entry lives: a peer's copy 117 s, a feeder's 102 s, the relay's own records 44 s
  (`strikes::Usable`). Before any feeder (`Plan::strike_tables_bytes`, one part for each class):
  each class's ring in every table it takes in, its table of places, and the records the relay
  signs whatever its load. For each planned feeder: its records a second in the feeders' store,
  and the relay's own for its worth of load and the feeder figures held for it in the relay's own.
  Each entry is charged to the share of whoever delivered it: every feeder's receiver its fair
  part of the feeders' joint share, the peers together at the members' rate and their places (one
  for each session on a link, since any may send a fault proof), and the relay itself at its own
  records. A deliverer's place is charged to its kind's joint share as entries
  (`strikes::FEEDER_PLACE_ENTRIES`, `strikes::PEER_PLACE_ENTRIES`), so feeders churning fresh
  keys, each a place of its own, fill only the feeders' share; each kind's joint share is planned
  in its store twice, as a holder below its fair part is taken while another floods (and never past
  twice: one past its kind's share is taken only while its kind holds less than twice it). The
  fingerprints a restart reads back (a dump, a table's checkpoint and log) are charged to their
  class's store and counted in their class's share as one restored holder
  (`strikes::Deliverer::Restored`, never past the class's share), so every class's store holds
  only what its share allows, with no exception; one with no room raises the floor past its
  generation instead. Entries leave a share only once every table has dropped them (the relay's
  sweep of every table, then the shares'), never as one table passes them. A share or a store full lets the record go unused (counted, `strikes_full`): it is
  still possessed, so its deliverer is credited and no honest member is reported short for
  another's flood.
- How long a relay keeps what it possesses is kept on `M`, never on `J`: a sharing group's pieces
  and parity, what it forgets and refuses, its answered repairs, its ticks, repairs and
  anti-entropy (`sharing::Now`: a group is driven by both clocks, and production code cannot hand
  it one alone), the delivery tags a feeder's audit is answered from, and every deadline on what
  it remembers of other relays: an ask's membership, a demotion, a full member's route-around and
  an idle member link. Each of those is a `sharing::MonoDeadline`, which only `Now::after` makes
  from the monotonic side, so no deadline can be put on `J`. `J` is used only to
  compare signed seconds (a manifest's, a receipt's, a shortfall's, a sender's). So a step of `J`
  either way keeps nothing past its plan: a store planned on the window never overfills, every
  batch is seeded and tagged, and no honest relay fails an audit for the step.
- A feeder's limits (its share of what is shed, its receiver's ceiling) apply to every batch of it
  that is not refused, before it is seeded, usable or not, so a batch too old to use costs its
  sender as much as a fresh one.
- A relay states its clock and its error in its greeting's `RateLimit` (`clock_ms`, `error_ms`,
  appended; a reader that predates them ignores them), and again on a step or when a feeder's
  batches drift. Heartbeats carry the sender's time and echo the other side's
  (`Record::TimedHeartbeat`, NTP's four timestamps, non-critical), so a feeder knows each sample's
  uncertainty `u = RTT/2 + ρ·age` (ρ = 500 ppm, `budget::DRIFT_PPM`; the age on the raw
  monotonic clock, `CLOCK_MONOTONIC_RAW`, which no time daemon slews) and discards any with
  `u > U_m` = 1 s (`budget::U_M`); an old relay's `u` is its handshake's round trip, for the
  greeting's statement only. A later restatement (a `RateLimit` on a step or on drift) is no
  sample, since its round trip is unknown: it drops the session's sample and asks for an echo, and
  the echo's round trip is its uncertainty. The feeder selects as NTP does (RFC 5905 §11.2.1,
  Marzullo, with the differences below; `source::RelayClocks`), and as
  in NTP its clock sources are only the ones it was configured with: the configured relays (the
  ones its owner named with `--relay` and the release's seeds), heard through a session with one
  or a probe of it, and the host while its kernel reports it synced within `E` (within that
  bound). An unsynced host is no source, as NTP never votes an undisciplined local clock: it is
  read as it is only when nothing is selected. Nothing else is a source: a relay a hint named is
  never one, whether the feeder holds a session with it or probed it, so no number of relays found
  through hints, and no number of fresh keys, changes what is selected. A configured relay is one
  source however it is heard (its session and a probe of it: its tightest interval), a session
  that ends drops its sample, and a relay that states an error past `E` (an unsynced relay states
  its error unbounded) is ignored. It selects the span of the points more than half the sources'
  intervals cover (no point so covered: nothing is selected), which must hold a configured relay
  (a synced host alone selects nothing), and signs at `T`, its low end. While honest sources are
  a strict majority, true time is covered by more than half and lies in the span, so `T` is never
  ahead of true time; any two points of the span share an interval, so the span is never wider
  than one interval (`LAG`), and majority points apart are one span, never a tie. Against RFC
  5905's `clock_select`: the RFC tries `f = 0, 1, ...` falsetickers while `f < n/2`, takes the
  span of the points `n - f` intervals cover, and accepts the first `f` whose midpoint rule passes;
  this span is the RFC's at the largest `f` it allows (`ceil(n/2) - 1`) with no midpoint rule, so
  it contains the RFC's selection whenever the RFC selects one. The region the most intervals
  cover is not taken: with honest (-8.5 s, 8.5 s) twice and (-1 s, 1 s) and two agreeing liars at
  (6 s, 22 s), four meet at (6 s, 8.5 s), ahead of true time, while three cover (-1 s, 8.5 s),
  which is what this selects and what RFC 5905 selects at `f = 2`. The midpoint rule is not taken
  either: two honest relays at `-E` and `E`, each stating `E`, meet only at their edges, their
  midpoints outside, and the rule would select nothing of them. The price is a wider span when
  sources agree, so `T` lags true time by up to `LAG`, which every window allows for. A majority of fewer than three is still selected, as NTP's intersection needs no
  least number (ntpd's `minsane` and chrony's `minsources` are 1 by default), so a feeder with one
  seed and an unsynced host signs by the seed. While a configured relay is unheard it is polled
  for its clock alone, never with discovery's round, every 30 s at first, doubling each poll it
  does not answer up to the round's five minutes (`relays::ClockPolls`, NTP's poll interval).
  With no configured majority, as in NTP (no system peer; a minority never steers the clock), it
  signs at the low end of its host's interval (its clock less the kernel's bound, never ahead of
  true time) while its kernel reports it synced, else by the offset the last
  selection of configured sources made (NTP's holdover, never kept from anything else), else by
  the host's clock as read; and the feeder's health says "no configured clock source reachable,
  host unsynced" while that lasts past a relay's grace (`health`). Every time the feeder signs or
  judges by (its batches, its `ReceiverInfo`, the directory offers and announcements it signs,
  its delivery checks, its ledger) is read from this one selected clock, never the host's clock
  as read, so a host an hour off signs nothing an hour off while a majority is selected. A
  session's first `ReceiverInfo` is signed before that session's relay is heard, by the
  selection as it stands then.

  What is selected decides only the time a batch is signed at. **No clock decides what a feeder
  sends**: every batch goes to every session it is routed to, however old or however far ahead,
  and the relay alone judges whether it can use it, holding what it cannot use as possession
  (above). So a Pi whose clock is an hour off still delivers everything, and an unsynced relay
  still receives everything. A session measures its own relay's clock (`θ_i` within `u_i`, by its
  echo or by the clock its greeting stated) for one thing only: its health reports how far the
  signing clock is outside each relay's interval ("your clock disagrees with relay X by N s",
  `source::RelayClocks::disagreements`), so an owner sees a wrong clock, theirs or a relay's.
  `F >= E + U_m + δ` (δ = 1 s, `budget::TRANSIT`), so a batch signed by a selected clock arrives
  usable, and the selection's width `LAG` = `2E + 2U_m` (17 s), which its low end may lag true
  time by, is in every window behind (the budget above). **No clock
  decides a relay's fate**: a feeder replaces a relay only when the delivery audit finds it
  swallowing batches (§3.5) or when it does not answer. A session that reached its relay and
  ended before `HEALTHY_SESSION`, for any reason, or that ended while its relay was audited
  (dodging the audit), is held against the relay only if a session to another relay that was up
  when it ended is still up `ENDED_TOGETHER` later (a heartbeat and a dial's timeout,
  `relays::Ends`): when every live session ends together, the feeder's own network failed and no
  relay is blamed, as a probe round that heard nothing blames none. Two held in a row replace the
  relay (`relays::SHORT_IN_A_ROW`), and a healthy session clears the run. A dial that never
  reaches the relay (an honest relay restarting refuses connections) is held against nobody; a
  relay that stops answering is replaced by the rounds, which count it silent
  (`selection::FAILED_ROUNDS`). A session whose relay the audit found swallowing is never counted
  healthy, however long it was up. A relay whose clock is wrong still possesses and passes on
  everything it is sent, so nothing is lost by keeping it, and a selection that flips mid-session
  blames no one. A relay replaced hands what an audit still owed it to the relays in its place
  (`relays::Ledger::hand_owed`; with none in its place the list stays where it was), and a session
  that ends before it has sent what it was owed owes the rest again. What is owed a relay is
  bounded (`relays::OWED_KEPT`, four audits' worth, the oldest let go), so a relay that keeps
  failing owes little. No current relay ends a session with `Goodbye{Clock}`; one that does is
  treated as one that said `Retry`: dialled again after at least the minute's retry
  (`batch::CLOCK_RETRY_SECS`), and replaced as any other once two sessions in a row end short.
- Receiver descriptions and sites are capped and forget the receiver least recently active; a subscription names at
  most 64 regions, a client's each clamped to resolution 6 (above); a `Subscribe` sent with `Hello` decides the first byte a subscriber receives.
- A relay signs its deduplicated stream under its own signature domain, so a relay's batch can
  never verify as a receiver's.

### §3.7 Discovery is peer to peer, and the feeder holds the rules

There are no directory authorities. The founder rejected them (organisations go inactive, and a
keeper set is a party that can be captured); §7 records the alternatives considered.

- Relays tell feeders of other relays (`RelayList`, `Redirect` hints). A feeder caches what it
  learns on disk.
- A new feeder starts from several independent sources: its own cache, seed hostnames run by
  different people, and whatever relays its owner names.
- The feeder chooses by its own rules (§3.5): anchor, home, random from what it knows, distinct
  networks. A redirect only ever means "leave me".

The stronger defences the critics designed (counting relay standing by map cell rather than by key,
an eligibility bar instead of a ranking, commit-before-reveal fingerprints, signed delivery
receipts from clients) live in relays and clients, which update. They wait until an attack
appears (§8.1). The feeder already carries what they need: signed, numbered, chained batches and
signed relay choices.

### §3.8 MLAT is a relay's own computation, kept apart from forwarding

Clock sync needs decoded ADS-B positions, and its state is pairwise, so it is not a relay's job
(a relay that tracked clocks would be a second decoder) and no single relay can own a receiver's
clock. A relay's MLAT is a subscriber: it takes a region's raw batches, decodes privately for
clock sync (the mlat-server method: pairs of receivers related through aircraft with known
positions), solves, and publishes signed positions with their uncertainty and the observation
identities used.

- Relays cover overlapping regions (at least one reception radius, about 400 km), and a receiver
  belongs to every relay whose region covers it.
- An observation's identity is receiver key, counter epoch, raw counter and message hash, the same
  whichever relay delivered it, and relays deduplicate on it before solving. A client never sees
  it: it sees a reception tag in its place (§3.8.1).
- Relays never exchange calibrated times, pairwise time differences or pre-solved positions as
  solver inputs. Pairwise differences share their reference receiver's noise and overstate
  certainty; calibrated times from two relays make one reception look like two.
- A receiver's clock error is shared by everything it hears, so a solver models it as one bias per
  receiver, never as independent noise per observation.
- Clients trust a target confirmed by receivers in separate places more than one heard once.

#### §3.8.1 Merging MLAT across unbounded relays (decided 2026-10-06)

Several relays per region, without bound, is the healthy state, so results
from many relays must combine exactly, in any order, idempotently, with no coordinator. Two
adversarial critics (estimation theory; distributed systems) and a survey of production systems
(mlat-server at adsb.lol and FlightAware, OpenSky, air-traffic wide-area multilateration and
ARTAS) were put to the open question on 2026-10-06; all three arrived at the same shape, and it is
this:

- **The only exactly mergeable object is the set of signed raw observations.** It is a grow-only
  set keyed by observation identity (receiver key, counter epoch, raw counter, message hash);
  merge is union, which is commutative, associative, idempotent and verifiable. §3.1 already
  builds it. No summary of observations is ever added to another: an information-form sum is not
  idempotent, is exact only at one linearization point, double counts receiver clocks shared
  across summaries, is larger than raw per transmission (2.5 to 12 times, measured in the
  critique), and is an unverifiable claim by whoever computed it. Proposed and killed (§7).
- **A position is a cached view, never an input.** Every published solution names the exact
  observation set it used, the clock model it used, and the solver specification's version, and is
  a deterministic function of the three; the model is a deterministic function of its own input
  set. Clients merge solutions of one transmission by their full input set (the observation set
  and the model's input set together): the same set is a duplicate; a superset wins; incomparable
  sets are never averaged or fused, and any relay holding both publishes the solution over their
  union (every relay of the area holds the raw, so the union is always computable there; a client,
  which holds no raw since 2026-10-19, compares tag sets, below).
- **Completeness is local by construction.** Relay regions overlap their neighbours by at least
  one reception radius, so a relay whose region holds an aircraft receives every receiver that
  could have heard it; border solutions from two relays therefore start from the same inputs, and
  the superset rule settles any late arrival.
- **Clock models are shared evidence, not private state, and belong to a canonical tile.** The
  world is cut into fixed cubes in integer ECEF millimetres at four levels (edges of 50, 100, 200
  and 400 km); a tile's footprint is the cube and one reception radius about it, and its members
  are at most 48 of the receivers inside it, chosen by farthest point from the cube's centre so
  they spread. An aircraft is assigned the tile containing the lower median of its hearers'
  sites, at the level whose members hold the most of its hearers, ties to the smaller level.
  Every choice is integer arithmetic over signed sites and raw, so the assignment is
  canonical: any relay computes the same tile from the same raw, and a model names
  its tile. A window is decided by the raw's own signed wall clocks, never by when anything
  arrived. Clock sync within the tile is a least-squares fit of each member's offset as a
  continuous piecewise-linear function on 5 s knots aligned to the tile's reference clock (the
  gauge, chosen by rule: a GNSS-disciplined receiver first, else the lowest key), with an
  integrated random-walk prior, fed by ADS-B positions as references (at most sixteen aircraft a
  tile, ranked by hash; each reference aircraft's position a variable; its GNSS error is nearly
  constant over a minute, so each aircraft has one position bias, east, north and up, with the
  prior its declared accuracy gives, and each message only a few metres of its own), and the
  gauge's own rate one parameter more, seen through the sync ranges, so a free-running gauge's
  frequency error does not scale every time difference under the model. Undeclared clock jumps
  are found against a robust noise estimate (the median absolute consecutive difference, never
  the fit's own residual spread, which a jump inflates); a clock that jumps more than the rule
  allows is dropped from the tile, and the model says so, rather than the fit failing. Its size
  is bounded by the tile however dense the region, and its normal equations are banded in time,
  so a fit costs about the same at 100 receivers as at 1,000. A relay publishes each as a
  signed `ClockModel`: content-addressed, in fixed point, citing its tile and input set by hash
  and count, and carrying no covariance (whoever solves under it forms that once from the cited
  raw at the published estimate).
- **What is solved.** A target is an aircraft with no ADS-B position in the window (what MLAT is
  for) or one of a hash-chosen sample of the ADS-B aircraft (one in sixteen, so calibration is
  measured on live traffic); at most five of a target's transmissions a bin are solved, by hash
  rank, about one a second.
- **Uncertainty is honest.** A published covariance includes the clock component, computed from
  the joint clock covariance (not per-receiver variances added as if independent, the defect in
  mlat-server's clock normalisation), and names its clock model, so a tracker can tell which fixes
  share clock error. A tile's model is a fit to a canonical subset of the data, and that is not
  automatically conservative: a fit to less data has a wider posterior only when the model is
  right, and leaving data out can hide what would have shown the model wrong. What keeps it honest
  is that the subset is chosen without looking at the residuals (by hash and position, never by
  fit), and that its coverage is measured, by level, altitude band and hearers outside the tile,
  never assumed. The published covariance is the fit's, inflated by 1.1 and floored at 5 m a
  side, for what the simulator cannot show (unmodelled multipath, site survey error, clock
  behaviour beyond its mix); a fix wider than 1.5 km is not published.
- **Any relay verifies; anyone checks signatures and fault proofs; the rule is optimality, not
  bytes.** (Amended 2026-10-19, founder: this read "anyone can check a relay", which needed raw and
  sites in every client's hands. Verifying against raw needs the sites and the counters, so only a
  relay, which holds both, does it; a client checks signatures, content addresses and format 1
  fault proofs, which need neither.) Verifying a model is
  rebuilding its tile's members and input set from raw and checking the citation exactly, then
  forming its normal equations once at its estimate: the Gauss-Newton step there must be within
  tolerance of zero under the robust weights the estimate itself gives, its noise within
  tolerance of what its residuals say, and no residual may step where no jump is declared.
  Verifying a solution is recomputing its canonical assignment from its addressed citation (the
  aircraft must belong to the cited tile), then residuals and a chi-square test against the cited
  raw and the model, linear in the observations; omission is checked against the spec's
  deterministic outlier rule. The chi-square limit is one function on both sides: the statistical
  quantile (zero with no redundancy) widened by what the wire's rounding of position and time can
  add, and an engine publishes a solution only after running the verifier on it as published,
  every one (as built 2026-10-07: checking every solution costs 20% more solving time, measured on
  the 4,000-receiver world benchmark, about half a percent of a stride's compute). A fault is a signed model or solution that fails verification on
  its own cited raw: any relay holding that raw shows it, and a client drops the relay on its own
  authority. The one fault provable with no raw at all is two signed solutions of one
  observation set, model and spec version that disagree beyond tolerance (the fault proof's
  format 1), final or provisional alike: a provisional solution is verified the same way with
  its model carried past its knots (below, *Provisional positions*). Byte identity is a property of the reference implementation (two copies holding the same raw
  publish the same bytes, tested with a golden), not of the protocol: an independent
  implementation that reaches an optimum within tolerance is honest. Clients merge by the hash
  of a model's inputs, never its bytes. The discrete decisions (windows, tiles, members,
  assignment, grouping receptions into a transmission, thinning, outlier gating) are integer
  arithmetic on raw counters, signed wall clocks and fixed-point models, so independent
  implementations agree on them exactly.

**What a client is sent of MLAT** (amended 2026-10-19, founder). A raw-form solution names each
reception by receiver, epoch and counter, and a full clock model carries every member's site and
its clock offsets; with the aircraft positions anyone reads, an hour of either gives a receiver's
site to metres by reverse MLAT. So both stay on relay links, and a client gets these instead:

- **A site id, relay-side.** `SiteId` is BLAKE2s-256 over `"tally site id" 0x00` and the
  site-bearing record's signed bytes, signature included. It names a receiver's site for as long
  as that record stands; a full model's scope and inputs hash use it in place of the site. A
  client is never sent one.
- **A reception key, never sent.** `ReceptionKey` is BLAKE2s-256 over `"tally reception key"
  0x00` and the same signed bytes: a second derivation that no wire ever carries, so a relay holding
  the site record derives it and a client cannot.
- **Tagged positions** (`Positions` formats 5 and 6, final and provisional; format 6 travels as
  `Provisional` like format 4). Format 3's and 4's layout with no receiver table, each reception a
  `ReceptionTag`: the first 16 bytes of BLAKE2s-256 over `"tally reception tag" 0x00`, the reception
  key current when the reception was heard, the counter epoch, the 48-bit counter, the message's
  length and the message. Why a key no client can compute, and not the site id first proposed:
  the site id was then to be published in client clock models, and a tag keyed by a public value
  over a 48-bit counter is a search of 2^48 (hours on one GPU) from the counter itself. A key that
  no wire carries holds whatever else a client learns. A relay rematches tags against its own raw. A
  client merges by tag sets exactly as by observation sets: the same set is a duplicate, a superset
  wins, anything else is incomparable.
- **Client clock models** (`ClientClockModel`, kind 0x26), one fixed size: the signer, the full
  model's boot and sequence, issued time, specification version, the full model's id (what
  solutions cite), its inputs hash (what clients match models by) and the window. It names no
  receiver: no key, no site id, no entry per member, no site, no `site_mm`, no offsets. Why not
  even the members: a tile's members are chosen by their exact sites (a sphere about the tile's
  centre, then farthest point), so the tiles a receiver belongs to, over time, narrow its site to a
  fraction of its public cell. Membership is relay-only, like the site. The inputs hash covers site
  ids, not sites (specification version 6, §3.3), and a client compares it, never recomputes it.
- **Fault proofs** of format 1 over two tagged records, which a client checks with nothing else, as
  before. A format 2 proof carries two full models and stays between relays; a tagged record and a
  raw-form one of the same transmission are never a fault.

The merge's raw mode is gone (`tally-merge`, and `tally-api --mlat-raw`): no client holds raw to
resolve or verify with.

The mlat-server bridge (`tally-mlat` as first built) could not take part: mlat-server's clock sync
is private and stateful, so its outputs could be neither deduplicated nor verified. It is replaced
by a native, deterministic MLAT: `tally/crates/mlat-solver` (the pure mathematics: the clock
model, the per-transmission solver with its altitude pseudo-measurement, the robust rule, the
verifier, how a model and a solution are published, and a simulator of aircraft, receivers and
drifting clocks that tests them; its crate documentation is the specification), and `tally-mlat`
over it. As built:

- A relay's MLAT subscribes to its regions' raw stream on every relay its operator names, and holds
  each signed observation once, by identity (of copies, the earliest signed wall clock), so relays
  that overlap add nothing but availability. It holds only receivers whose newest signed
  site (a `ReceiverSite`, or an older feeder's format 1 description; never a format 2 one, which
  has none) places them in its regions with a clock and location precision the specification
  accepts, and only Mode S receptions.
- It holds raw compactly and bounded by bytes (48 GiB by default; a held reception is a 24 byte
  record over an interned message), and refuses at ingest what no rule could use: anything but
  a Mode S reply or an ADS-B position. Each 5 s bin is thinned canonically when it is sealed (its
  window's signed wall clocks have passed, plus a settling time): per receiver at most 32 sync
  events, the targets' receptions all kept, and one aircraft in sixteen kept whole by hash for
  calibration, so every relay and verifier that seals the same raw keeps the same records.
- Its work is per (tile, window). Windows run on a stride of eight bins (40 s): a window is
  eleven bins before its last and one after (65 s), and solves the eight bins since the last
  stride. Every target heard in the window is assigned its tile, each tile with a target is
  fitted once (one fit for every aircraft in it) and checked, and its targets' transmissions are
  solved, each read back from its wire form; one tile in sixteen (by hash) is checked again by the
  model verifier as any outsider would. A model or a solution that fails is dropped and counted.
  The work is spread over threads, cut and put back in tile and address order, so any number of
  threads publishes the same bytes. A relay fits a tile only when its regions cover the tile's
  whole footprint; it publishes nothing for a tile it covers in part, which a neighbour covers.
- It publishes, per tile and stride, the model's parts (none when it fits its manifest, the
  normal case: a model is a few kilobytes, about 6 KB at 30 members), its manifest, then the
  positions citing it. The manifest frames the specification's bytes rather than restating them,
  and carries the hash of the model's inputs, which is what a client matches models by.
- The specification is version 5. Version 5 dates a free-running gauge's origin by the least
  bound every cited reception of its clock gives (each was heard at or before its batch's wall
  clock), not by its anchor batch's wall clock alone, which dated every transmission under such a
  gauge up to a second late; rejects a sync message any receiver heard more than once in the
  window, judged before any tile thins, since its receptions cannot be told apart; and starts the
  fit robustly, so an event mixing two copies of a message costs the event, not the fit (RFC-0181
  sweep 6, H-d and F8). Version 4 had version 3's tile models, addressed citation and dropped
  clocks, and from the calibration over real receivers below: a clock that declares GNSS
  discipline is fitted as it behaves, a clock nothing places is dropped rather than failing its
  tile, and the last jump scan is at the published estimate a verifier scans; version 2 added the
  gauge's rate and the reference aircraft's position biases, version 1 had neither. A
  model or solution names its version, and two relays agree exactly only under the same one.
  Each version is a derivation, so the same raw gives each a different model: a verifier judges
  only its own version (`tally_mlat_solver::judges`), and a model or solution of another is
  unjudged, counted on its signature alone, never failed, so relays part-way through an upgrade
  convict nobody. A fault proof of any version is still judged, by the tolerance the wire sets
  for it (`tally_wire::Tolerance::for_spec`, the same for every version so far).
  From version 3 two signed models of one inputs that differ are not a fault (optimality is
  within tolerance, so honest relays may differ in the last bits); a proof of that form is
  refused.
- A `Positions` transmit time is in Unix picoseconds: model time is whole picoseconds, and
  rounding to the nanosecond moves a well-observed solution past the verifier's optimality bound.
  Model time zero is UTC when the tile's gauge is GNSS-disciplined, and otherwise the gauge's
  signed batch wall clock. `Positions` is format 3: each solution carries its addressed citation
  (the hash and count of what its canonical assignment was computed from).
- The same raw, delivered in any order and any number of times, and two relays that both cover
  a tile's footprint, publish byte-identical models and identical solutions for that tile (the
  reference implementation's property; the protocol asks only optimality within tolerance).
- A model of any size can still be published: one signed manifest and, when the model does not
  fit it, unsigned content-addressed parts (`ClockModelPart`). The model's encoding is cut into
  fixed 60 KiB parts; the manifest carries the relay's header, the spec version, the inputs hash,
  the model's length and BLAKE2s-256 of each part, and its id is the hash of its signed content,
  so it covers every part; a manifest is at most half a record, so two fit one fault proof. A part
  names its model's id. A relay sends the parts, then the manifest, then the positions that
  cite it. A relay forwards both under the clock model stream: it holds parts until their
  manifest arrives (at most 30 s and 64 MiB, the model least recently active forgotten first),
  then forwards those the manifest lists, in index order, ahead of it, and drops the rest; a
  listed part that arrives after its manifest is forwarded once. A client reassembles the
  model, checking every part against the manifest, before it decodes it.
- A relay's MLAT is held to an intake ceiling of its own (§3.6), told to it as a `RateLimit`, and
  paces what it publishes to it. The default, 8 MiB/s, is sized from what the MLAT publishes:
  in the end-to-end tests, 10 receivers and 14 aircraft publish 163 KB of models and 154 KB of
  positions for 906 solutions over 5 bins, and 30 receivers 6 KB a model and 360 bytes a
  solution. A model grows with its members (about 270 bytes a receiver at 13 knots, so 13 KB at the
  48 most), and a solution with the receptions it cites (12 bytes each). A dense region of 300
  aircraft, each heard by more than 48 receivers, is then about 3.9 MB of models and 2.8 MB of
  positions (5,100 solutions of some 40 receptions) a 5 s bin, 1.3 MB/s. The whole world on one
  node is about 1.2 MB/s of models (3,800 a 40 s stride), 1.0 MB/s of final positions (2,800
  solutions a second) and 2.0 MB/s of provisional ones (one a target a second, 5,400 targets,
  some 370 bytes each: measured, a provisional record is no smaller per solution than a final
  one, and there are as many), 4.2 MB/s; the default is about twice that. What an MLAT link at its ceiling costs a relay is bandwidth, not memory: what it sends
  passes through the fan-out ring and the parts table, both bounded, and goes out again to every
  subscriber of positions or clock models, a slow one dropped. MLAT links count against the
  subscriber cap, so an operator sizes that cap and the MLAT ceiling to the host's link.
- What the whole world costs one relay is set by the tile, the stride, the targets and the
  reception rate, and measured in release by the simulator at 20,000 receivers (about 5,400
  targets a window, on 3,800 tiles; `world_scale_one_node`, re-measured 2026-10-08 for RFC-0181).
  At the real rate, about 320 wanted receptions a second a receiver (a real receiver hears about
  600 a second, 60% of them wanted; the simulator comes nearest with every receiver in reach
  hearing every transmission), 41 cores keep up: 1,300 core-seconds of fits (a tile fit 0.35 s a
  core) and 300 of solving, every solution verified, a 40 s stride, on 32 threads. One window (20
  bins, 100 s) holds 289 million observations after thinning (145 a receiver a second of the 324
  wanted), 8.7 GB at 30 bytes an observation with the index, every byte counted as allocated;
  sealing a bin of the whole world (65 million receptions) takes 2.0 s on 32 threads, at most 13
  cores more. The first measurement, at a rate an eighth of the real one (39 wanted a receiver a
  second), gave 29 cores and 1.6 GB a window (46 million observations at 35 bytes; the 70 million
  it once named were held over the 30 bins of its run, not the 20 of a window), and that figure is
  superseded: the fits barely change with the rate, since a tile's events are capped, but the
  solves and the raw grow with it. Indexing a window takes 40 ms and assigning every target 0.8 s
  on 32 threads. A tile's
  fit plus its folded calibration takes 71, 95 and 107 ms at 100, 300 and 1,000 receivers, and an
  outside verifier checks it in 23 to 34 ms. Each choice that sets this was measured, and the
  trade is stated:
  - *Stride 8.* Fits a solved bin cost 21.4, 11.0, 5.7 and 2.9 at stride 1, 2, 4 and 8 (0.86,
    0.45, 0.24 and 0.13 s), at the same coverage (0.958 to 0.963), for a final position 14.5,
    17, 22 and 32 s late on average; at the first measurement's rate the world needed 34 cores
    at stride 4 and 27 at 8 (41 at 8 at the real rate). The cost
    of the eighth is latency: a final MLAT position arrives 7 to 47 s after it was heard.
  - *Sixteen sync aircraft a tile.* At 8, 16, 32 and every one, coverage is 0.964, 0.946, 0.949
    and 0.953 and the median error 52.6, 36.1, 33.6 and 36.1 m, for 20, 31, 45 and 49 s of fits
    over the busy scenario; 16 buys most of the accuracy for two thirds of the cost of 32.
  - *Warm starts are not used.* Starting a fit from the previous stride's model cut a fit
    started at the bound from 55 to 8 ms, but from a real previous stride it took 94 ms against
    62 ms cold, so the relay starts cold.
- The simulator's calibration holds under a realistic clock mix (a third of receivers at 50 to
  100 ns, a third at 250 ns, a third dump1090-class at 500 ns) and each aircraft's GNSS error
  drawn once from its NACp: with the published floor and inflation stripped, the truth is inside
  the 95% ellipsoid for 0.953 overall and 0.952 for Mode S only over forty scenarios, 0.945,
  0.961, 0.955 and 0.951 at the four tile levels, 0.959, 0.944 and 0.955 by altitude band, and
  0.950 for transmissions whose hearers lie outside their tile, for a median horizontal error of
  31.5 m; the published ellipsoid covers 0.979 (version 3: 0.950, 0.949, 0.938 to 0.957, 0.939
  to 0.956, 0.948, 31.4 m and 0.979). All clocks at 80, 250 or 500 ns give 0.940 to
  0.942. Fixes are jointly calibrated: two aircraft under one model cover 0.965 jointly, one
  aircraft's consecutive fixes 0.956, their clock correlation 0.002 to 0.005; gluing two tiles'
  fixes as if independent gives 0.87 to 0.90, the overconfidence the model id exists to show. An
  aircraft crossing from one tile to the next moves its published fix by a median 0.004 and a
  95th percentile 0.034 squared sigmas. With 500 ns on every receiver and one bad clock stepping
  5 to 10 µs every 2 s, 77 tiles fit, the bad clock is dropped where the jump rule finds it (7
  tiles) and coverage is 0.943 with no false jump. Every clock 30 ppm fast with a free-running
  gauge, the fit measures the gauge's rate (16 of 16 within three sigmas) and covers 0.945
  against 0.961 with a GNSS gauge. Receivers that declare GNSS and are not what they declare
  (one stamping 120.6 µs late throughout, one with 300 µs of jitter, beside an honest one) cost
  no fit and cover 0.953; one that declares GNSS and whose counter is noise at a millisecond
  costs no fit and no honest clock and covers 0.965. Taking each message's GNSS error as independent, as the first version did, gave 0.933
  against 0.938 with the bias, and 0.916 against 0.939 when every reference aircraft is NACp 8.
- **Calibrated over real receivers** (§10, step 7; measured 2026-10-08,
  `tally/crates/mlat-calibrate`, whose crate documentation states the method). The data is
  OpenSky's LocaRDS (Strohmeier et al., Sensors 2021; Zenodo 10.5281/zenodo.4739276, CC BY-SA
  4.0, `fetch.sh` downloads and checks it): one hour of Europe (subset 2, 460 MB zipped), 6.5
  million ADS-B positions heard by 317 crowdsourced sensors with each sensor's own nanosecond
  timestamp, its declared site, and the decoded position. Each reception becomes what a feeder
  would publish: GNSS sensors' stamps (read from the hour: 54, on one UTC scale) become Radarcape
  GPS counters, the rest 12 MHz counts (exactly the dump1090 counts OpenSky converted); one
  aircraft in eight (359) is withheld, every report of it sent as a DF4 reply with its pressure
  altitude, so it is an MLAT target; the rest are DF17 positions that sync the clocks. The
  engine a relay hosts (`tally_mlat::engine`, relay settings, every solution through the
  verifier) is driven on a virtual clock, and what it publishes is scored against the withheld
  reports. It does not test decoding real bytes, real reply rates, or operational status
  (LocaRDS has none; the type code's containment radius stands in).
  - *The truth is itself off by about as much as a fix.* A textbook solver over the receptions
    of LocaRDS-verified GNSS Radarcapes alone, needing no clock model, whose residuals fit 70 ns
    (median chi-square per degree of freedom 0.63 over 214,000 fixes), covers the reported
    position 0.47 of the time: an ADS-B report lags its aircraft a median 32 m along the track
    and scatters beyond its NACp. Against the raw truth every fix looks overconfident (finals
    cover 0.54 horizontally, 0.82 across the track alone; median horizontal error 121 m against a
    median claimed sigma of 69 m, the error leaning 39 m along the track). So the truth is
    widened by what that reference needs to cover 95% (the lag taken off, then 118 m along the
    track and 39 m across, with which the reference covers 0.947), and a fix is judged by
    whether it does as well. This says within a few points, not to the third decimal.
  - *Solver defects it found, fixed (version 4).* Over real receivers a declaration of GNSS
    discipline is not a measurement: GRX1090s stamp 120.6 µs after Radarcapes (a long message's
    end, not its start), one Radarcape declaring GPS runs 0.7 s off and drifting 0.09 ppm, and
    three stamp with hundreds of microseconds of jitter. Version 3 held every disciplined clock
    to the gauge's stamps (100 ns, rates to 0.001 ppm) and took it at 30 ns until estimated, and
    let a clock no weighted reception placed leave its normal equations singular: 5,166 of 10,260
    tile fits over the hour failed. Version 4 fits a declared-GNSS clock as any clock (its
    discipline shows only as its timebase's curvature), starts every clock at 500 ns, drops a
    clock nothing places (one receiver costs the tile that receiver, never the tile), and scans
    the published estimate for jumps last. Over the same hour the failed fits fall to the 1,559
    with no sync event, the (aircraft, bin) pairs with a final position rise from 0.22 to 0.48 of
    those heard by three receivers (52,353 to 122,514 final positions), the median horizontal
    error falls from 135 to 121 m, and coverage against the truth model is unchanged (0.894 to
    0.895). The simulator moves within its noise (above).
  - *What it measures, version 4, final positions with the floor and inflation stripped, against
    the truth model:* 0.895 overall (0.906 published); 0.912, 0.879 and 0.892 below 6 km, 6 to 9
    km and above; 0.885, 0.884, 0.912, 0.906 and 0.902 with 3, 4, 5 or 6, 7 to 9 and 10 or more
    receptions; 0.884, 0.931, 0.886 and 0.914 at the four tile levels; 0.927 when every receiver
    used is GNSS, 0.904 when some are and 0.864 when none is. Over the 45 sensors LocaRDS verified
    alone (all GNSS) it is 0.941 (0.947 published), and for the aircraft whose ADS-B LocaRDS
    verified, 0.938 over every sensor and 0.966 over the verified ones. As DF11 replies (no
    altitude) it is 0.917. Declaring every unverified site to 20 m changes nothing (0.893).
  - *So:* where the receivers and the truth are what they say, the published covariance is
    honest (0.94 to 0.97 against a truth that can only say so to a few points). The shortfall
    with every receiver is in fixes from unverified free-running receivers and from 3 or 4
    receptions, where nothing is redundant enough to catch a wrong site or a misbehaving
    counter; LocaRDS cannot tell those apart from a fault of the 12 MHz noise model, because it
    verifies no dump1090 sensor. The floor and inflation are left as they are: the calibration
    does not show a uniform overconfidence for them to correct, and widening every fix for the
    sake of unverified inputs would hide them. Owed: the same calibration over our own receivers
    with surveyed sites (§10 step 7), and over a dataset whose free-running receivers are
    verified.
- An exactly determined transmission (three receptions and the altitude) generally has two
  roots that both fit perfectly; the solver also starts it from a ring about the receivers, and
  refuses it when a second fit as good lies outside the first's 10^-6 ellipsoid (one such DF4,
  published before this rule, was 52 km out at 101 m sigma).
- **Provisional positions** (decided 2026-10-06, RFC-0174 §2.4): a final position comes 7 to 47 s
  after its transmission, so the MLAT also solves each target's transmissions about a second
  after they are heard and publishes them as `Provisional` records (kind 0x10; `Positions`
  format 4, format 3's layout with no addressed citation), which only a subscriber that set
  `Streams::PROVISIONAL` (16) is sent; a relay forwards them in a stream sequenced apart from
  final positions, below them in its egress classes. As built (`tally/crates/mlat/src/provisional.rs`,
  the solver's crate documentation § Provisional solutions):
  - *What and when*: the replies of a target (no ADS-B position heard in the last 65 s, or in its
    bin's calibration sample), solved once 1.1 s has passed since the first of a transmission's
    receptions arrived (a feeder seals a batch once a second, so receptions arrive spread over
    that second by the receivers' phases; mlat-server's 0.9 s is for clients that stream), at
    most one an aircraft a second.
  - *Under what*: the newest published model of the tile whose members are the most of the
    receivers heard, carried past its knots along each clock's last interval, at most 90 s (a
    spec constant covering the longest a tile's newest model is behind a reception: the stride and
    the window's last bins, 45 s at stride 8, its settling, 11.5 s, the ripening, 15 s, how far a
    reception runs ahead, 7.5 s, and a bin of rounding, 84 s in all, asserted at compile time;
    beyond it the model maps nothing). The clock covariance grows by the curvature prior's integrated random walk over
    the carry, a stated formula, and the error floor, inflation and 1.5 km cap are a final
    position's. A provisional is a deterministic function of its model, its receptions and the
    spec, so it is verified as a final one is (the model carried, against the receptions it was
    solved from), and the fault proof that holds finals holds it: two signed solutions of one
    observation set, model and spec, provisional or final, that disagree beyond tolerance.
  - *Measured* (the simulator, feeders sealing at phases of their own and paths of 40 to 250 ms):
    published a median 1.34 s after the transmission, 1.65 s at the 95th percentile, 3.0 s at
    most (an aircraft's first, waiting for a model). Calibration with the floor and inflation
    stripped: 0.940 carried up to 20 s, 0.947 from 20 to 45 s, 0.975 from 45 to 90 s, 0.956 of
    5,076 overall (0.982 published), for median horizontal errors of 124, 237 and 468 m. The carry
    costs precision, not honesty. Over real receivers (above; version 4, the same hour and truth
    model): 0.929 of 139,600 (0.936 published), 0.962 over the verified sensors alone and 0.959
    for the verified aircraft, for a median horizontal error of 151 m (version 3: 0.913 of
    111,955, 174 m).
- The client merge rule is implemented once, `tally/crates/merge` (`tally-merge`), for every
  client; `tally-api` is the first. It reads positions, clock models (reassembled part by part
  against their manifests), fault proofs and, until 2026-10-19, optionally raw, from any number of
  relays (a client now reads tagged positions, client clock models and tagged fault proofs only;
  what that changes is said in each item below), and holds
  per aircraft its latest transmissions (eight), each with the fix kept and up to four
  alternatives:
  - *One transmission, only on evidence*: two solutions are of one transmission when they name
    one aircraft with the same message bytes and either share a reception, or are tied through a
    clock model: a receiver one cites is a clock of the other's model, which maps that reception
    to its own model time, and less the range from the other's position that is the other's
    transmit time within 2 µs (every such receiver agreeing). A receiver in both with no reception
    in common heard two transmissions; a solution tied to two held transmissions joins neither.
    Nothing else joins: not transmit times, which two models state on origins that agree only as
    well as their gauges' wall clocks (0.9 s apart in the simulator, so a time window splits true
    matches), and not the bytes, which a Mode S reply (DF4, 5, 11, 20, 21, most of what MLAT
    solves) repeats exactly milliseconds apart to another interrogator, so a time window also
    joins false ones, which no chi-square sees since each side fits itself. What is lost: two
    relays whose solutions share no reception and no receiver of either's model are never
    merged; the aircraft's track holds both as separate transmissions and serves the latest.
    Since 2026-10-19 a client joins two solutions only on a shared tag: the tie through a clock
    model needs a reception's counter and the model's offsets, and a client holds neither.
  - *The full input set* is the observation set and the cited model's inputs hash; its identity is
    BLAKE2s-256 over `"tally merge input set" 0x00`, the set's hash and the inputs hash. The same
    set is a duplicate (dropped; its signer joins the fix's relays). Under the same model inputs a
    superset of observations wins and a subset is dropped. Anything else is incomparable.
  - *Incomparable, holding the raw* of every cited observation: the client finds the
    aircraft's canonical tile from its raw, fits that tile's model, solves the transmission and
    verifies it as a relay would; that fix stands above the ones it was solved from. Since
    2026-10-19 only a relay holds raw, so a client always takes the tie rule below; a relay that
    holds both solves their union and publishes it.
  - *Incomparable, without the raw, the tie rule*: the fix with the greater weight (observations
    cited plus the model citation's input count, so a superset under one model always ranks
    first), then the lowest input set hash, is kept; the other is recorded as an alternative.
    Both are functions of the solution alone, so every client holding the same solutions keeps
    the same one, in any order.
  - *Checked before it counts*: the cited model is held, whole and signed, decodes under its spec
    version, and its manifest's inputs hash is the hash of what the decoded model is a function
    of; the solution cites only the tile's members and reads back as a claim under it. Without
    raw that is all (signatures and content addresses only), and the fix says so. When the
    client's own raw rebuilds the tile's members and inputs and the solution's addressed
    citation exactly, and the canonical assignment puts the aircraft in the cited tile, the model
    is verified by the model verifier once and every solution under it by the solution verifier;
    a failure is dropped. A client whose raw does not reproduce a citation does not hold that
    model's raw and falls back to the signature check. Since 2026-10-19 no client holds raw, so
    every client's check is the signature check, and the check against raw is a relay's. Models are matched by the hash of their
    inputs, never by their bytes, so two honest relays' models of one inputs that differ in the
    last bits are the same evidence.
  - *Fault proofs*: a checked proof marks the relays it names faulted; what stood on their word
    alone is dropped (a transmission keeps its best remaining fix), their models are forgotten,
    and nothing they sign later counts.
  - *Provisional fixes*: checked as a final solution is without raw (signatures and content
    addresses: the raw a model was fitted from cannot reach receptions newer than its window),
    held apart from the final transmissions, at most two a signer an aircraft a second of transmit
    time and 128 an aircraft. A provisional ranks below every final fix: what is served is the
    latest final fix, unless a provisional one is later by transmit time. A final fix of the same
    transmission (the evidence rule above) supersedes it, and one arriving after that final is not
    held; a final fix of the aircraft within 2 s that puts it inside a 0.999 gate (both horizontal
    covariances, and 300 m/s of motion over the time between them plus a second for the models'
    origins) confirms it. Retraction needs no message: a client learns it by the deadline rule,
    one neither superseded nor confirmed 108.5 s after it arrived (by the client's clock; a final
    leaves its engine within 91.5 s of its transmission, `tally_wire::budget::FINAL_FIX_LEAVES`,
    and 108.5 s is the one bound every party waits on, `tally_wire::products::FINAL_FIX_ARRIVED_MS`)
    is retracted, forgotten, and
    counted against its signers. Measured over a live MLAT and its own finals, 1,109 provisionals:
    382 superseded, 726 confirmed, 1 retracted.
  - *Bounded*: aircraft, models, solutions waiting for their model, faulted keys, resolved fits,
    provisional fixes and raw are each capped, least recently active forgotten first (the relay's
    table), raw also by bin as the client's clock moves on.

  `tally-api` subscribes with `--relay` to final and provisional positions (`--mlat-raw`, which
  read raw, is gone since 2026-10-19), and serves an aircraft's merged MLAT position when readsb holds no ADS-B position for
  it, stating `position_source` (`adsb` or `mlat`) and, for MLAT, the horizontal sigma, the check
  it passed (`model`, `signature` or `resolved`; with no raw, `signature`, §3.8.2) and its `kind`
  (`final`, or `provisional` while later than every final fix).

#### §3.8.2 Who checks a position

Verification is delegated, not universal. No one checks every fix against raw, and nothing here
needs anyone to; each fix is checked by whoever is placed to, and says which check it passed.

- **The relay that signs it.** A relay's MLAT verifies every solution it signs as any checker
  would, from the raw it holds (`publish::solve_published`, every one; one that fails is dropped
  and counted). It does not verify its own clock model: that is for others.
- **The other relays holding the area.** Every relay that covers an area's tiles holds the same raw
  (§3.8.1) and computes the same positions to the same bytes. Two signatures over the same inputs
  that disagree are a fault proof (`FaultProof`), which anyone checks with the two signed records
  alone, no raw needed, and which travels to every reader of positions (to a client, of two tagged
  records, §3.8.1).
- **A client holding raw** (the API with `--mlat-raw`) checked a fix itself: the model by the model
  verifier and the solution by the solution verifier. Since 2026-10-19 no client holds raw (§3.6),
  so this check is a relay's alone.
- **A client** relies on the signatures and content addresses: the solution and the
  model it cites are signed, whole, and agree with each other. The API reports which of these each
  fix passed (`MlatCheck`: `model`, `signature`, or `resolved` when it solved the fix itself from
  two engines' raw). Both `model` and `resolved` need raw, so since 2026-10-19 a client's fixes
  pass `signature`, and the cross-check below is what tells a client more.

**The weak spot.** An area that one relay holds, or that only one operator's relays hold, has no
independent check: nobody else computes its positions, so no disagreement can be signed, and a
client has only that operator's word. Several keys prove nothing here, since one
operator can run any number.

**The rule (decided 2026-10-08).** A fix counts as cross-checked only when at least two relays of
different operators signed the same solution of the same inputs: agreeing signatures (two
solutions of one inputs hash within the verifier's tolerance, which merge as one, §3.8.1) from
signers whose declared networks differ (`ProviderOffer::network`, the same proxy for independence
the delivery check uses, RFC-0174 §2.2). The API reports, per fix, the count of independent
agreeing signers beside `MlatCheck`, so a client can require two and a map can mark a fix that has
one. Nothing is refused for having one: a lone relay's fixes are served, counted as one. The
directory aims to place at least two relays of different operators on every area (RFC-0174 §2.9),
and the count is how a client sees where it has not yet.

Open, to build: the merge already joins a duplicate's signer to the fix's relays (§3.8.1, "the
full input set"); what is left is resolving each signer to its offer's network, counting the
distinct networks, the count on `GET /v1/aircraft` (`tally_api_types::Mlat`), and the same count in
the world products' fixes once more than one relay signs them.

### §3.9 Our own use, and the production rule

We run our own relays (on our hardware), and our boxes' feeders pin them as home. The
consumer readsb's connector moves from `out.adsb.lol` to our relay's plain BEAST output on
loopback. **The production rule, for us and anyone: consume Tally through a relay you run, not
someone else's.** A competitor can then degrade only the feeders it carries, and the multi-relay
rule covers those. RFC-0119 §3.7's closure holds: the consumer readsb feeds nothing, and Tally's
received stream is never re-published as if our receivers heard it.

### §3.10 Where the code lives, and the mirror

**Superseded by RFC-0180 (Tally stands alone).** Tally leaves the monorepo for its own repository,
`sky-commons/tally`, with its history extracted; the Copybara mirror below stops, and nothing is mirrored
in either direction. The text below is kept as what was built.

`tally/` is a self-contained Cargo workspace with its own Bazel module file: it references
nothing outside itself and builds with `cargo` or Bazel alone. In the monorepo, the root module
includes `//:tally.MODULE.bazel` (its crate repository, `tally_crates`), and the nested
`tally/MODULE.bazel` is the module file the public repository uses (Bazel ignores a nested one).
Copybara (pinned by hash, `//tools/mirror:copybara`) publishes `tally/` to
`github.com/flightlines/tally` on every push to main that touches it
(`.github/workflows/tally-mirror.yml`, `tools/mirror/tally/export.sh`): it moves `tally/` to the
root, rewrites `//tally` to `//`, and squashes each export into one commit that names only the
source revision, since monorepo commit messages describe other projects too. The mirror's own
check is the proof of self-containment: it builds and tests the exported tree standalone, with no
monorepo and no build service, before anything is pushed. Bringing outside pull requests back is a
second Copybara workflow, added when the repository goes public. The repository is private until the feeder and
relay work, then public. Code is MIT or Apache-2.0.

## §4 What Tally guarantees, and what it does not

A batch is a claim by a key. Tally guarantees attribution and integrity: what arrives is exactly
what a receiver signed. It does not guarantee completeness or truth. A relay can drop data (the
multi-relay rule and sequence gaps bound and expose it); a receiver with a real antenna can report
lies (corroboration across separate receivers bounds it, and an area covered by one receiver
cannot be checked without outside data). A well-funded attacker can make some feeders' data go
missing for a while before it is caught. That is accepted (§8.1).

The residuals two adversarial sweeps left on purpose, each bounded and none able to forge data:
one operator running relays under many host names passes the feeder's distinct-host rule (it
compares names, not networks, since a feeder resolves nothing it need not); each hostile relay a
feeder reaches counts as one more source in its pick, so reaching many dilutes the honest share;
throwaway keys that keep publishing real-looking batches can occupy relay intake and an MLAT
relay's receiver slots, within the per-address, per-feeder and per-MLAT caps; and because a
feeder may publish only its own batches, replaying another receiver's old batch into a relay
needs a peer that relay's operator accepted (an accepted relay or an upstream link), and then
succeeds only once that relay has forgotten the stream, which it does least recently active
first, so a receiver that keeps publishing is the last a flood can push out. The stronger
defences of §3.7 (standing by map cell, delivery receipts) are the answer if any becomes an
attack, and the feeder already carries what they need. RFC-0119 §4's ceiling on what
Flightlines trusts ADS-B to mean is unchanged.

## §5 Bandwidth and cost

Measured on 2026-10-06 (step 5): box-01, near KLAX, at night, uploads 7.9 KB/s (about 64 kbps,
4.8 MB in 607 s, counted by systemd's IP accounting on the relay) for 73 aircraft with position,
signing and framing included. Below, the network-wide figures are still estimates from that
per-feeder rate.

A feeder uploads about 50 to 100 kbps to each of its relays. At 20,000 receivers, raw receptions are about
1 to 2 Gbps in total, the deduplicated world about 30 Mbps, MLAT results about 1 Mbps. One relay on
a 1 Gbps server serves about 25 whole-world deduplicated clients or hundreds of regional ones; a
whole-world client costs about $10 a month in metered bandwidth. Our cost at that scale is
roughly $200 to $700 a month on budget hosting; today it is one server.

## §6 Legal and privacy (researched 2026-10-05; sources in §9)

- Receiving and relaying ADS-B is lawful in the US (18 USC 2511(2)(g)(ii); 47 USC 605). UK and
  German secrecy laws plausibly exclude a broadcast to all, and no feeder has been prosecuted in
  either. China seized receivers in 2021. Tally recruits only through adsb.im (§8.4).
- LADD binds FAA data-feed subscribers by contract, not relays of radio receptions. Filtering is a
  client option, not a network duty.
- An exact receiver location is personal data under GDPR. It was published exactly by default, with
  that said plainly at install, and the owner may round it (§8.3). **Amended 2026-10-19 (founder):
  it is no longer published.** The exact site goes only to relays, which need it for MLAT (§3.3,
  §3.5), and is never in anything a client reads (§3.6); public surfaces show the receiver's public
  cell, an H3 resolution 6 cell of about 36 km². Every relay operator that receives a site is a
  controller of that exact site under the GDPR, for MLAT, bound by the network's rules for relay
  operators (`docs/relay-operators.md`: never republish it, show only the public cell, keep an
  objection process). Anyone may run a relay, so the honest promise is "never published and never
  readable by a client", not "secret from whoever runs a relay".
- **What was exposed before 2026-10-19.** Up to tally-feed and tally-relay 0.3.0 the exact site was
  in the one signed description, sent to every raw subscriber and carried in evidence bundles; the
  v0.3.0 API served exact coordinates; and raw counters, full clock models and raw-form positions
  let a determined client derive a site. Descriptions already sent to subscribers cannot be called
  back. Owners are told so (`docs/relay-operators.md`, "What was exposed before").
- **What still narrows a site, by design.** A client's deduplicated stream for an area
  (`ClientRegionalBatch`) carries every message the area's receivers heard, without counters or
  receivers. In an area with a single receiver, every message in it is that receiver's, so the
  stream shows that receiver's reception pattern: which aircraft it heard, when, and how strongly.
  That bounds the site only to about its public cell, the precision the public cell already
  states, so it is accepted; an owner in a lone area should know it.
- Sweden's IMY reprimanded Flightradar24 (2025) for demanding proof of ownership before honouring
  removal requests; publication itself was a legitimate interest. A Tally relay that runs MLAT or
  archives is a GDPR controller and keeps a simple objection process.
- Feeders dedicate their receptions under CC0; what Tally publishes downstream is ODbL, so nobody
  can take the data private (§8.2).

## §7 What is killed

- **A Flightlines-only ingest.** One more aggregator holding one more feeder list: the shape §1
  says failed us.
- **Relays compressing receptions into multi-receiver bundles.** Small saving; destroys the
  per-receiver proof (critic 1).
- **Shipping pairwise time differences or calibrated times between relays.** Overstates
  certainty (critic 1).
- **Directory authorities ("keepers"), staking, and social vouching.** Keepers go inactive and are
  a party to capture (founder); staking is Helium's failure; vouching is free for colluders.
- **Ranking relays by popularity.** Snowballs and rewards defection (critic 4).
- **Exact version matching and "unknown kind is an error".** Either one disconnects every frozen
  feeder the day a relay upgrades (critic 3).
- **A remote kill switch, config push or self-update in the feeder.** The single point of control
  this network exists to remove.
- **Re-publishing adsb.lol's aggregate into Tally.** Their data, their licence, and a feedback loop.
- **Adding MLAT summaries** (partitioned information-form sums, merged by addition): not
  idempotent, exact only at one linearization point, double counts shared receiver clocks, larger
  than raw, and unverifiable (§3.8.1).
- **Bridging to mlat-server:** its private clock state makes its positions unmergeable and
  unverifiable (§3.8.1).
- **A broker in the middle (MQTT, NATS, Kafka).** Durable buffers with worse semantics than drop
  the slow client, and a dependency a stranger must run.
- **Sites, raw counters and full clock models to clients** (2026-10-19). Any one of them gives a
  receiver's home to a client (§3.6, §3.8.1).
- **Keeping sites from clients with a filter.** A rule in a subscription's `wants` is one forgotten
  branch from a leak; a client's egress is a type that cannot hold a site (§3.6).
- **Keying reception tags by the site id.** As first designed the site id was public in client
  clock models, so its tags would fall to a 2^48 search; the key is one no wire carries (§3.8.1).
- **Naming a model's members to clients.** Tile membership is chosen by exact site, so it narrows
  a site below its public cell over time (§3.8.1).

## §8 Founder rulings (2026-10-05)

1. **Attacks are bounded, not prevented, and the defences wait until an attack appears.** "We can
   always address issues as they arise." The exception is the feeder, which cannot be fixed later:
   it carries the hooks (§3.5, §3.7).
2. **Licence:** CC0 in, ODbL out.
3. **Receiver location is exact by default.** Any relay's MLAT needs it, and rounding for some and
   not others would need a trusted party. The installer says the location is public; the owner may
   round it and contribute less to MLAT.
   **Reversed in part 2026-10-19 (founder): relays are now the trusted party for exact sites.** The
   location stays exact by default, because MLAT needs it, but it is no longer public: it goes to
   relays and to nothing a client reads (§3.5, §3.6). This ruling had refused a trusted party; it
   now names one, every relay, because the alternative left every receiver's home readable by any
   client, and a client is anyone. Relays are not a closed set (anyone may run one), so what the
   trust buys is that a site is never published and never sent to a client, and what binds an
   operator is the rules for relay operators. The installer says that the exact location goes to
   relays only and public pages show its public cell; the owner may still round it and contribute
   less to MLAT.
4. **Recruitment is through adsb.im only.** Outside that, no recruiting.

## §9 Provenance: what each critic changed

1. **Signing and MLAT:** batches are the unit and are never repacked; Ed25519 identity; MLAT in
   relays with overlapping MLAT regions; observation identity; no pairwise differences; drop
   MLAT echoes and merged streams; counter epochs.
2. **Relay discovery:** a Sybil flood beats "delivered data over time" because the data is public;
   redirects mean only "leave me"; anchors; distinct networks. (Its threshold-of-keepers
   recommendation was overruled, §8.)
3. **The frozen feeder:** the preamble, version ranges, skip-unknown with a critical bit,
   appendable bodies, open enums, control records, generic observation formats, timeouts, and the
   must-never list.
4. **Proof of antenna:** one real antenna can pose as many, and public data lets a receiver be
   synthesised, so standing must count places not keys, be a bar not a ranking, and reward unique
   contribution; four relays per feeder with a home relay; no rush to fresh relays during an
   outage.
5. **Legal and privacy research:** §6, with sources: 18 USC 2511 and 47 USC 605; UK Wireless
   Telegraphy Act s.48; German TDDDG §5 and §27; faa.gov/pilots/ladd; IMY decision DI-2021-3397;
   adsb.lol's privacy and licence pages; the ODbL 1.0 text.
6. **Site privacy (2026-10-19):** critics found ten ways a client of v0.3.0 could read or derive a
   receiver's site: the description, full clock models, routing by a point cell at any resolution,
   counters in positions, counters in the regional product, raw batches, exact altitude, the API's
   pin grid crossing the protocol's cells, the merge's raw mode, and a stats endpoint that bound
   anywhere. The design critic's shape was adopted (format 2 descriptions and a separate site
   record, wire version 3, a client egress typed so it cannot hold a site, tags, client clock
   models, the public cell as the one cell clients see); the reception key in place of the site
   id as the tags' key was the wire writer's, accepted the same day.

## §10 Build steps

1. **The wire crate.** Done: records, signed batches and receiver info, the Noise transport with
   preamble and version negotiation, the BEAST decoder, backoff; 29 host tests.
2. **Bazel and the mirror.** `tally.MODULE.bazel`, BUILD files in the core's idiom, the standalone
   module file, Copybara to a private `flightlines/tally` with the export built and tested before
   each push.
3. **The relay.** Built: accept, verify, deduplicate by hash, forward once (never back to where a
   batch came from), parent links, bounded fan-out that drops a slow subscriber, the subscriber
   cap, loopback BEAST. Still owed: regional routing by receiver cell, the deduplicated stream,
   MLAT results, redirects at the tree cap.
4. **The feeder.** Built: publish from readsb's BEAST port with the ceiling, signed chained
   batches, counter epochs, MLAT echoes and merged streams kept out, the home, anchor and random
   slots, the relay cache, backoff, and the control records. End-to-end tests over loopback
   sockets (`//crates/relay:end_to_end`): a stand-in readsb's frames reach a subscriber
   signed and unchanged and the loopback BEAST output decoded and unchanged; a feeder publishing
   another receiver's batch is cut off and nothing in that name is forwarded; a batch arriving by
   two relays is forwarded once; a stalled subscriber is dropped while another keeps every batch.
5. **On our hardware.** Done 2026-10-06: `infra/prod-host/tally` installed on the master (our relay
   on loopback, the box-01 feeder, the consumer readsb moved to the relay's output, the egress
   policy loaded for the first time, after making it reloadable and letting mlat-client read its
   own box). The consumer, dark since `out.adsb.lol` went off, holds the same 73 positioned
   aircraft as box-01's own readsb; the adsb.lol feed and MLAT stayed connected throughout. The
   server does not read Tally yet: production reads re-api, and switching it is a server change
   that waits for the deploy freeze to lift.
6. **Public launch.** Built: aarch64 and x86_64 binaries against the pinned sysroot (glibc 2.25 or
   newer, no C++ runtime; the aarch64 build is checked as an ELF but has not yet run on a Pi), the
   systemd units and the one-line installer (`tally/packaging`). Owed: a public relay on a host
   with a public address, seeds from more than one operator, release builds published to
   `flightlines/tally`, and the adsb.im pull request.
7. **Streams, MLAT and 978 MHz.** Built: subscriptions by region, the relay-signed deduplicated
   stream, relays publishing positions, peer exchange and redirects at capacity; `tally-mlat`
   as the native MLAT over `tally-mlat-solver` (§3.8.1), tested end to end over two real
   relays with the simulator's receivers as feeders and every published solution verified by a
   subscriber; the feeder's 978 MHz input from dump978-fa, in the same signed chain as 1090.
   Calibrated over real receivers offline (§3.8.1, `tally-mlat-calibrate` over OpenSky's LocaRDS,
   2026-10-08): it found and fixed three solver defects (specification version 4), and with
   receivers and truth that are what they say the published covariance covers 0.94 to 0.97,
   0.895 with every crowdsourced receiver. Owed: a run with our own real receivers, surveyed,
   and the same calibration over them.
   Then **the Bridge as a receiver** (its own RFC).
8. **Sites relay-only** (2026-10-19), in one release with no migration window (§3.3): the wire
   records and the typed client egress, relay and engine links at version 3 only (the minimum
   for those roles is 3 from this release; relays and feeders move together), feeders that
   publish only to version 3 relays, and the MLAT specification's version 6.
