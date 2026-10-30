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
- **Amended 2026-10-24 (founder): MLAT in seconds.** One class of MLAT fix, solved about 1.1 s
  after its transmission's first reception arrives, under a clock model refit every second over a
  trailing window of what had arrived; the windowed final fixes, the provisional ones and the
  precise world product are retired at wire version 4. It reverses §3.8.1's "a window is decided
  by the raw's own signed wall clocks, never by when anything arrived". It changes §3.3, §3.4,
  §3.6, §3.8.1, §3.8.2, §7 and §10, and RFC-0174 §1, §2.3, §2.4, §2.10, §2.11 and §2.12, and
  RFC-0181's hosted MLAT and its sizing; each place says so.

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

**Wire version 4 means "one MLAT fix class"** (decided 2026-10-24, founder; `tally_wire::record::FIXES_VERSION`,
§3.8.1 "Amended 2026-10-24 (founder): MLAT in seconds"). A fix is `Positions` format 7 (raw,
relay-only) or 8 (tagged, a client's), naming the receptions it considered and which it used, and
nothing is provisional or final. It retires, with their bytes never reused: the `Provisional` kind
(0x10) and its stream bit (`PROVISIONAL`, 16), the precise world product (`WorldPrecise`, 0x21) and
its bit (`WORLD_PRECISE`, 128), `Positions` formats 1 to 6, and `ClientClockModel` format 1 (a
window's bins). How a reader takes a retired form follows the session's version: from a peer of
version 4 or later it is a breach of the protocol; from one below it is dropped without a fault and
not forwarded, and a retired stream bit in a `Subscribe` is ignored. The least version a relay or
engine link may agree stays 3, so a version 3 relay is still linked while the network moves; it
simply sends nothing of MLAT a version 4 relay keeps. The protocol is pre-release, so this is one
release, as version 3 was, and the clients that read MLAT (`tally-merge`, `tally-api` and the
client core's reads) move with it, pinned together. The MLAT specification moves to version 7
(version 8 since 2026-10-26, §3.8.1).

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
| 0x0c | `Positions`    | a relay's signed MLAT fixes, each naming the receptions it considered and which of them it used (formats 7 and 8 since version 4, §3.8.1) |
| 0x0d | `ClockModel`   | a relay's signed, content-addressed clock model manifest for one area and trailing window (§3.8.1) |
| 0x0e | `FaultProof`   | two signed solutions of one inputs that disagree, or two signed models of one inputs that differ; checked before forwarding |
| 0x0f | `ClockModelPart` | one part of a clock model too large for its manifest, checked against it (§3.8.1) |
| 0x10 | retired        | `Provisional`, provisional MLAT solutions (`Positions` formats 4 and 6), retired at version 4 (2026-10-24, §3.8.1): never written; from a version 3 peer dropped without a fault and not forwarded, from a version 4 peer a breach; the byte is never reused |
| 0x11 to 0x23 | RFC-0174's records | echo, delivery check, provider directory, sharing groups, credit, the regional and the world products, parity and bundle index (RFC-0174 §2.10); transport version 2, the minimum. 0x13 and 0x14 are retired (the first delivery check), read as retired and never written; the delivery check is 0x22 and 0x23 (RFC-0181 §7). 0x21, the precise world product, is retired at version 4 as 0x10 is |
| 0x25 | `ReceiverSite` | a receiver's signed exact site (issued time, location with altitude, clock class), under its own signing domain `"tally receiver site"`; relay-only, sent only on version 3 relay and engine links (§3.3, §3.5) |
| 0x26 | `ClientClockModel` | a relay's signed clock model as a client may hold it, of one fixed size: signer, boot, sequence, issued time, spec version, the full model's id and inputs hash, and its trailing window (edge and span; format 2 since version 4); no member, no site, no offsets (§3.8.1) |
| 0x27 | `ClientRegionalBatch` | a relay's signed deduplicated receptions for one area as a client may hold them: each reception's format and bytes, the batch's wall clock, and no counters or signal levels (a signal set against public positions ranges a lone receiver; §3.6) |

Kinds 0x25 to 0x27 came with wire version 3 (2026-10-19) and are non-critical, so a version 2 build
skips them. Two formats came with them: `ReceiverInfo` format 2 (above) and tagged `Positions`,
which name each reception by a 16-byte tag in place of its receiver, epoch and counter (§3.8.1).
Wire version 4 (2026-10-24, §3.3) has one kind of MLAT fix: `Positions` format 7 (raw, relay-only)
and format 8 (tagged, what a client is sent) replace formats 3 to 6, and `ClientClockModel` format
2 names its trailing window by its edge and span in place of format 1's bins.

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
| `Positions` format 7                         | receiver, epoch and counter of every reception         | format 8 (tags, §3.8.1)             |
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
for a relay that only shares; `--world` gathers the world product (RFC-0174 §2.11; the precise
world product and its `--world-precise` were retired with wire version 4, 2026-10-24, §3.8.1). A relay whose signed offer it verified may connect to exchange its sharing
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
     MLAT link: what this relay's MLAT originates and the positions and models it forwards.
  3. **Raw** batches, with the receiver descriptions they travel with, to a relay link or an
     MLAT link: the border raw MLAT needs.
  4. **Forwarded**: the rest a peer that forwards is sent (the deduplicated stream).
  5. **Taker**: everything a plain subscriber or a beast-out client is sent.

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
  relays are held to `--max-member-bytes-per-sec`, one rate every member shares (1 MiB/s by
  default, `hub::DEFAULT_MAX_MEMBER_BYTES_PER_SEC`; 8 MiB/s each before 2026-10-08, which planned
  every member a feeder budget of its own); every other inbound peer,
  an engine included (it publishes nothing), to a feeder's (`--max-feeder-bytes-per-sec`, 256 KiB/s
  by default). Feeders are told theirs as a `RateLimit`. Connections are capped
  (`--max-connections`).
- A relay reads two clocks, as TrueTime does: the host's wall clock, and a bound on its error
  that a per-host daemon publishes, which is what Google's TrueTime and AWS ClockBound both do.
  The wall clock is read in one place (`clock::RelayClock`), and its bound in one place every end
  shares (`tally_wire::clock_bound`: the one reader of the bound and the one judgement of it, for
  the relay, the feeder and the API); Clippy's `disallowed-methods` refuses `SystemTime::now`,
  `SystemTime::elapsed`, `UNIX_EPOCH.elapsed`, `libc::clock_gettime`, `libc::gettimeofday` and
  `libc::time` anywhere else, and `libc::adjtimex` and `libc::clock_adjtime` everywhere
  (`clippy.toml`). The monotonic clock is std's `Instant`, read wherever a duration is timed: it
  is never compared across machines, and no reading of it can be wrong in a way another site's
  could not. `J` judges everything compared across machines: the usability windows, a feeder's
  clock, directory offers, manifests and receipts. It is the host's wall clock as chrony keeps
  it, with the bound **AWS ClockBound 2.x** publishes in shared memory (`/var/run/clockbound/shm0`),
  read through its own Rust client (`clock-bound-client` 2.0.3) at every judgement: a memory read,
  the bound grown by ClockBound's drift rate since its sample. `M`, the monotonic clock, drives
  epochs, ticks, the hosted MLAT's steps, paces and every duration. A stamp carries both. The relay
  never disciplines a clock of its own: the time daemon does. A step of `J` is seen exactly, as a
  change of `J - M` (which only a step moves), and ends nothing: it is counted (`clock_steps`) and
  the relay states its new clock to every feeder session. The relay judges only while ClockBound
  says `Synchronized` and the half-width of its interval is within `E` = 7.5 s less what
  ClockBound's word may leave unsaid, 418 ms (`tally_wire::budget::CLOCK_BOUND_MARGIN`: `J`'s
  truncation to the millisecond and the worst residual gap below), so 7,082 ms, and a judging
  clock is within `E` of true time even across those gaps. The segment missing or unreadable, or `Unknown`, `FreeRunning`,
  `Disrupted`, or a bound past `E`, states the relay's error as unbounded and judges nothing by its
  clock; each such read is counted by why and the last stated (`/memory`, `clock_bound`). A relay
  starts whatever ClockBound says, and its unit is ordered after `clockbound.service` and never
  pulls it in.
  **The kernel's bound is not read.** `adjtimex`'s `maxerror` is not a bound by itself: the kernel
  cannot tell which daemon wrote it (systemd-timesyncd sets it to 0 at every adjustment,
  `src/timesync/timesyncd-manager.c`, `manager_adjust_clock`); a chronyd killed mid-slew leaves the
  tick biased by up to 83,333 ppm while the kernel grows `maxerror` at 500 ppm; and a suspend or a
  VM's restore is not aged at all. So the units filter every clock call (`ProtectClock=yes`), allow
  only VMClock among devices (`DevicePolicy=closed`, `DeviceAllow=/dev/vmclock0 r`, no
  `PrivateDevices=`, which would hide it), give the process a private `/dev/shm`
  (`TemporaryFileSystem=/dev/shm`, which `PrivateDevices=` gave it), and a test holds each to that
  (`tally_wire::clock_bound::unit_faults`).
  **What a relay host runs** (ClockBound's README): chrony with `maxclockerror 50` (chrony's own 1
  ppm is an estimate, not a bound) and `rtcsync`; ClockBound 2.x with `--max-drift-rate 50`, which
  must match; and VMClock where the hypervisor offers it, readable by all as ClockBound's own
  unit makes it (`chmod a+r /dev/vmclock0`), else ClockBound with
  `--disable-clock-disruption-support`.
  **What ClockBound says when chronyd dies** (its source, `clock-bound-d` and `clock-bound-shm`
  2.0.3): it polls chronyd every 100 ms with a 1 s timeout; a poll that fails writes
  `FreeRunning` while its last synchronised sample is under 5 s old and `Unknown` after
  (`CHRONY_RESTART_GRACE_PERIOD`), keeping that sample's bound, which the client grows by
  `--max-drift-rate` from the sample's time. So the status leaves `Synchronized` within about 0.1 s
  of chronyd exiting, or about 1.1 s if it hangs. A chronyd that runs on with its sources lost
  still says synchronised, and ClockBound writes `FreeRunning` once chrony's last clock update is
  older than eight of its polling intervals; until then the bound is chrony's root dispersion,
  which grows by `maxclockerror`. ClockBound itself stopped leaves its segment `Synchronized` to a
  client for 5 s after its last sample, then `FreeRunning`, then `Unknown` after 1,000 s.
  **Residual gaps**, stated as the stock answer is: the bound is only as honest as chrony's root
  distance and ClockBound's drift rate; between chronyd dying mid-slew and ClockBound's next poll
  the status still says `Synchronized` while the tick runs at up to 83,333 ppm against a bound
  growing at 50 (about 8 ms unaccounted when chronyd exits, up to about 92 ms while it hangs, and
  up to about 417 ms when ClockBound stops with it, its segment read `Synchronized` for 5 s after
  its last sample; the margin above covers the worst, so these cost judging time and not truth); a
  leap smear (a smearing server, or `leapsecmode slew`) moves the clock off UTC by up to half a
  second with no bound that says so; a suspend or a VM's restore without VMClock is seen only at
  chronyd's next measurement; and a host without ClockBound never judges as a relay or the API.
  **A known upstream defect:** ClockBound's daemon, restarted, wipes its segment in place
  (`clock-bound-shm` 2.0.3, `ShmWriter::wipe`, `File::create` truncating the file a reader has
  mapped), so a reader that reads between the truncation and the rewrite takes `SIGBUS`. The
  process dies and its unit's `Restart=always` brings it back, judging nothing until ClockBound
  says `Synchronized` again; the fix proposed upstream is to write the new segment to a file
  beside it and rename it over the old, so a mapping never loses its pages. The vendor's reader
  also prints a line to stderr at each open of a segment of a version it does not support, so a
  reader opens such a segment again only once its file changes
  (`tally_wire::clock_bound::Reader`).
  The feeder reads the same bound (`tally_feed`'s `host_error_ms`) and never needs it: its host's
  clock is a source and a reference only while ClockBound says `Synchronized` within `E`, and
  without it the feeder signs by its configured relays (its unit is ordered after
  `clockbound.service` and pulls nothing in). So the installer manages no time daemon: it
  installs no ClockBound and no chrony, and the README's feeder section says so.
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
    late, and counted against its receiver (`late_batches`, the stations report and
    `GET /v1/stations/{key}`) only when this relay's own anchor in it is older than an honest
    batch's can be too (below). Either
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
  | `MLAT_BATCHING` | 2 s | a receiver's raw of a moment, gathered and on its way |
  | `MLAT_AHEAD` = `E` | 7.5 s | how far above the judging clock it arrives by a reception of the hosted MLAT may be signed and still be held |
  | `SIGNED_LAG` = `MLAT_BATCHING + E + 2U_m` | 11.5 s | how far below the judging clock an honest receiver's raw of a moment may be signed and still be in when the hosted MLAT looks for it |
  | `FIX_SETTLE` | 1.1 s | how long after a transmission's first reception arrives the engine weighs it (the engine's design) |
  | `ARRIVED_SLICE` | 1 s | the slices the engine seals what has arrived in (the engine's design) |
  | `MODEL_KNOT` | 5 s | a clock model's knot spacing (the solver's design) |
  | `REFIT_EVERY` | 2 s | how often an area's pair model is refit, at the edges of one grid every relay shares (the engine's design) |
  | `FIT_LAG` = `MLAT_BATCHING` | 2 s | how far a model's trailing edge trails the clock its refit runs at, so two relays holding the same raw fit the same inputs at the same edge (the engine's design) |
  | `TRAILING_WINDOW` | 15 s | the sync raw a trailing-window model is fitted over, at least three knots (the solver's design; §3.8.1) |
  | `FIX_SOLVE` | 4 s | an MLAT fix's way out of its engine, its first reception in (the engine's design) |
  | `FIX_LEAVES` = `SIGNED_LAG + FIX_SOLVE` | 15.5 s | when a fix has been offered where it was heard: the feeder path |
  | `FIX_ARRIVED` = `FIX_LEAVES + K + REPAIR_TRANSIT` | 32.5 s | when a fix has surely arrived wherever it is read: the peer path, the world's settle and when a fix's standing settles |
  | `MAX_CARRY` = `2 REFIT_EVERY + FIT_LAG + MLAT_AHEAD + FIX_SETTLE` | 14.6 s | the most a fix's transmit time may be past the trailing edge of the models it is solved under, a hard bound |
  | `RESTATE_BEYOND` = `F / 2` | 5 s | how far a feeder's signed time may be from its relay's clock before the relay restates its clock |
  | `FALLBACK_FLOOR` = `S + K` | 40 s | a strike table's floor with no state |
  | `RECEIPT_AHEAD` = `K` | 15 s | a credit receipt's issued time ahead of a relay (issued by another judging relay's clock, so at most `K` apart) |
  | `PRODUCT_AHEAD` = `K` | 15 s | a world second's seal (`(s + 1) * 1000 + FIX_ARRIVED`) ahead of the API's clock |
  | `ACARS_MESSAGE_SKEW` | 300 s | exempt: an ACARS message's own time is an aircraft's or a ground station's, set by no clock of ours |

  Every comparison of a signed time against a clock goes through the module: a `Tolerance`'s
  `ahead`, `past`, `apart` or `covers`, or a `Window`'s `holds` (`Window::FEEDER`, `PEER`,
  `ANCHOR`, `FIGURES` for a batch the feeder figures count, `FIGURES_POSITIONS` for an MLAT
  fix they count, `relay_signed`, `proofs`, `figures`). A regional batch is judged by the
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
      its host while its ClockBound reports it synchronised within `E`), it carries only
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
      counted against nobody and shown on its health), and makes a stale one look fresh only at
      a hop that can check no honest anchor the batch carries (while it can check one, the
      oldest decides).
    - When there are more anchors than slots, the oldest reading always takes one and the last
      heard the rest. A feeder holds two sessions, and its sessions are at most
      `batch::MAX_ANCHORS` (asserted at compile time, `selection::DESTINATIONS`), so a batch has
      room for the anchor of each relay it is published to. It need not carry it: a reconnect's
      backlog signed while its session had heard only another relay's anchor, a batch sent to a
      relay other than the ones it was anchored by, the trusted reference leaving that relay's
      anchor out, or a relay with no signer, which issues none. So a relay never blames a batch
      for carrying none of its own anchors (below).

    Before its first anchor it holds its batches in order within its backlog and drops none; one
    that waited `ANCHOR_WAIT` (62 s) is signed with none, and counted (`unanchored`). It holds
    each as its receptions' wire bytes, encoded and compressed as it will sign them
    (`tally_wire::EncodedBatch`), never as their decoded receptions, so a hold costs about what
    the ceiling gathers over `B`; and it refuses a `--ceiling` whose hold, with the channel to its
    sessions full and its runtime beside it, would not fit the 64 MB its unit runs it in
    (`tally_feed::source::CEILING_MOST`), which the kernel would otherwise kill, losing the
    backlog. When an
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
    was judged is judged anew, and may be blamed again, the one case it overcounts). What it
    keeps is its receiver's row of the stations table, which is bounded (`Bounded`, oldest
    active first): a row a churn of other receivers pushed out loses its last judged with it, so
    a repeat that comes after is judged anew and may be blamed again, the other case it
    overcounts; a receiver that keeps publishing keeps its row. Nor is a feeder blamed for the time it held a batch waiting for its first
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
    later. One without the origin's anchor is never blamed, however old its `t`
    (`strikes::OwnAnchor::Absent`): an honest feeder sends such batches (a reconnect's backlog
    anchored by another relay alone, its batches anchored elsewhere while this relay's `J`
    stepped ahead, an origin with no signer), so `t` alone proves nothing against it. One whose
    anchor has left the ring is aged from the newest issue the ring let go, which it was issued no
    later than, and one of the origin's earlier run from this run's first issue, before which it
    was issued, so its age is never overstated (within `OWN_ANCHOR_OLDEST` of a restart no age can
    blame anyone). The age runs to when the batch reached the origin's process, never to when the
    origin got to it: a link reads its socket only between records, so while one is paced or
    waits for its admission what the feeder sends waits in the kernel's buffers, and a message
    read with its bytes already waiting is dated to the last moment the link found its socket
    empty, after which every byte of it came (`link::Drained`; TCP keeps the order). The origin's
    own pacing, admission or queueing never ages a batch, however long. A batch below a strike
    table's floor is late by this relay's clock, not its feeder's, and blamed on nobody.
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
    new. The world product gathers fixes by their own transmit second and seals each second
    `FIX_ARRIVED` after it ends (`WORLD_SETTLE_MS`, once every honest fix of it has surely
    arrived, whatever relay heard it): a fix of a second already sealed is late (`world_late`) and
    dropped, counted, never drawn as current, and a fix older than the history before the first
    seal is out of its window. The hosted MLAT holds raw as it arrived (§3.8.1, as amended
    2026-10-24) and refuses a batch signed more than `SIGNED_LAG`, the trailing window and a step
    below the relay's judging clock as it arrives (`arrived::HELD_MS`): it is older than every
    window a model could cite, and late (counted and lost to MLAT alone, never solved as current;
    the solver never sees it). So a batch used up to `W_a + 2E` after it was made can only be late
    for them: the worst-case staleness costs liveness of those products, never their truth.

    **The hosted MLAT's clock** is the relay's judging clock (`Stamp::judging`, carried in each
    decode as `Decoded::judge_ms`), never its monotonic clock aligned to it once at start: a batch
    may be signed at most `MLAT_AHEAD` = `E` past its arrival by that clock (an honest feeder
    signs at or below true time, the relay at most `E` behind it), and at most `SIGNED_LAG` =
    11.5 s below it while it is still in time for the fix it is a reception of (its batching and
    way, and an honest feeder whose selection holds this relay signs at most this relay's stated
    error and twice its measurement below its clock). The steps run on the monotonic clock and
    read the judging time of the step: the products publish one (monotonic, judging) pair with
    their watermark (`tally_wire::clocks::Moment`), and every step reads both from it, so the same
    stamped trace gives the same bytes.
    The two are distinct types (`Mono`, `Judged`, and `Raw` beside them): a signed or grid time is
    compared with a clock only through `tally_wire::budget`, whose every comparison takes a
    `Judged`, a span measured on one clock is a `Span` of that clock and moves no other's reading,
    no reading has a default, and none is made from a number but as one a reader took, given back
    (`recorded`, which Clippy refuses outside replays and tests). So handing a monotonic reading
    to a comparison with a signed or grid time, or moving one clock's reading by another's span,
    does not compile: `tally_wire::clocks`'s and `tally_wire::budget`'s compile-fail examples
    (`//crates/wire:wire_doc_test`) hold each such line. Each shard's lateness is the batch's own
    two readings, so a step of the host's clock moves the slices with it and offsets nothing. A
    step's fixes leave within `FIX_SOLVE` of their transmission's first reception arriving, and a
    fix that would leave past `FIX_LEAVES` after its transmission is not solved, counted, so
    `FIX_ARRIVED` holds of every fix published.
    The residual: a feeder whose reference leaves this relay out may sign up to `LAG` and `E` more
    below it, and its raw past `SIGNED_LAG` is late for MLAT, counted and blamed on nobody. It is
    left out for seat cost: covering it would hold every seat's raw over a span `LAG + E`
    longer, and the world relay's seats (`tally/crates/relay/tests/world-relay.txt`, RFC-0181) have
    no such margin over their 2,000 floor; its raw lands seconds away from its peers' receptions of
    the same transmissions, so MLAT pairs little of it anyway. A seat's raw is held over the
    trailing window, `SIGNED_LAG` and a step (`arrived::HELD_MS`) at the mean kept rate, in one
    pool for the relay (RFC-0181, "Sizing"). **The residual**, stated exactly and pinned by a test
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
  second, the transit and `K`, 32 s behind, `K` ahead; fault proofs, `Window::proofs`, 122 s behind,
  `S` ahead; feeder figures, the relay-signed window stretched by their hour), and possession
  never uses them. A record whose time cannot be read is malformed (no format leaves it out),
  counted as `unreadable_times` and refused as one that fails its signature is: that is the bytes,
  not a clock. A member's manifest never makes a copy usable: a replay of an archive is too old
  however fresh the manifest listing it.
- A usable record is used once, judged by a strike register (RFC 8446 §8.2, as QUIC keeps one,
  RFC 9001 §9.2; Kerberos's replay cache, RFC 4120 §3.2.3; `strikes`), never by its place in a
  stream: `t` is its author's signed time (a feeder's `wall_ms`; an engine's `issued_ms`; the time
  a relay signed a regional batch, its client form or bundle index; the newer of a fault proof's
  two records). Each table (the raw batches of each ingest shard, positions,
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
  (`unjudged_records`), never used and never blamed on anyone; and the relay signs nothing (products, feeder figures, engine records) but its answer to a probe, which states no time (`EchoReply::answer`, its `issued_ms` 0: the answer decides it, a judging reading's while the signer's clock judges and 0 while it does not, and takes no number, so no code holding the key gets a time signed through it): a feeder chooses only a relay whose answer verifies, so a relay that cannot judge is still chosen, admitted and fed. Once it is synced every
  table begins at its lease's bound when the lease is there and trusted (the bound covers every
  record the run before used, so it is the floor even below the fallback), and at the fallback
  floor from the synced clock when it is not. A run takes records up to `S` ahead of its clock and
  its bound is `L` past the newest it took, so a bound up to `S + L` ahead is a quick restart's. A
  bound further ahead of the synced clock was left by a run whose clock ran ahead, and that run may
  have used records up to it, so the floor is the higher of it and the fallback: no restart ever
  uses a record again, with no exception. The cost is a relay that uses nothing new until the clock passes the
  bound, bounded by how far ahead the bad time source was; it says so loudly at start, with how
  long until it clears, and counts it (`leases_ahead`, `lease_ahead_until_ms`). A clock that loses sync after the start is
  judged on ClockBound's word, read at every judgement: the relay keeps judging and signing while
  it says `Synchronized` within `E`, and stops (holds, signs nothing, refuses no one for clock)
  once it says anything else, until it says so again. Every relay signature goes through
  one seam (`signer::Signer`), which lends the key for one call only while the clock is judging,
  so a new signer cannot skip the gate. The types hold it, not a convention: the key (`Identity`)
  is not `Clone`, the relay moves its newest into its one `Signer`, and what a signing is lent
  (`Signing`) cannot be kept past the call. Two uses are apart from the clock: the transport
  handshake, which states no time, by a key that cannot sign (`NoiseKey`), and the answer to a
  probe, signed by a lending the wire crate keeps to itself (`Signer::untimed`), which states 0
  for its time whenever the signer's clock does not judge. The wire crate's doc tests hold each
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
  another's flood. The one exception is a record of the relay's own making (a bundle index, a
  regional batch it signed, its feeder figures): its own store is never evicted, so one past it is
  refused there and counted, and goes out all the same, unremembered (`Hub::publish_own`), since
  only this relay holds it and no member could repair it.
- How long a relay keeps what it possesses is kept on `M`, never on `J`: a sharing group's pieces
  and parity, what it forgets and refuses, its answered repairs, its ticks, repairs and
  anti-entropy (`sharing::Now`: a group is driven by both clocks, and production code cannot hand
  it one alone), the delivery tags a feeder's audit is answered from, and every deadline on what
  it remembers of other relays: an ask's membership, a demotion, a full member's route-around
  (at both ends of the refusal) and an idle member link. A receipt window's end is a signed time,
  read on `J` while it judges; from when `J` first passes it, its receipts and its judgment fall
  due on `M` (RFC-0174 §2.5), and its senders and credit are let go with that judgment, never on
  a clock of their own. The same holds outside the groups: the directory's own re-signing and
  evidence bundling, its dial timeouts and change waits, a credit corroboration (taken only while
  `J` judges), a withdrawal's quiet period and a fan-out item's age are on `M`; an offer's or a
  bundle's expiry, a signed time, is judged on `J` and not at all while it does not judge (the
  record is counted and its signer's next one taken). Each of those is a `sharing::MonoDeadline`, which only `Now::after` makes
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
  or a probe of it, and the host while its ClockBound reports it synchronised within `E` (within that
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
  signs at the low end of its host's interval (its clock less ClockBound's bound, never ahead of
  true time) while its ClockBound reports it synchronised, else by the offset the last
  selection of configured sources made (NTP's holdover, never kept from anything else: the
  selected interval widened by the raw clock's drift at 500 ppm as it ages and dropped once wider
  than `SELECTION_LAG`, `budget::held_over`, so it is never ahead of true time nor further behind
  than a live selection), else by the host's clock as read; and the feeder's health says "no configured clock source reachable,
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
- **A position is a cached view, never an input.** Every published fix names the receptions it
  considered (every reception of its transmission that had arrived when it was solved) and the
  subset of them it used (what the deterministic outlier rule keeps of the considered set), the
  clock model it used, and the solver specification's version, and is a deterministic function of
  its used set, its model and the version; the model is a deterministic function of its own input
  set. Clients merge fixes of one transmission by their full input set (the considered set and the
  model's input set together): the same set is a duplicate; a superset that agrees with the
  smaller fix wins, and one that disagrees wins only when a relay holding its raw verified it and
  its receivers carry more standing (RFC-0174 §2.12; since 2026-10-24, below); incomparable sets
  are never averaged or fused, and any relay holding both publishes the fix over their union
  (every relay of the area holds the raw, so the union is always computable there; a client,
  which holds no raw since 2026-10-19, compares tag sets, below).
- **Completeness is local by construction.** Relay regions overlap their neighbours by at least
  one reception radius, so a relay whose region holds an aircraft receives every receiver that
  could have heard it; border solutions from two relays therefore start from the same inputs, and
  the superset rule settles any late arrival.
- **Clock models are shared evidence, not private state, and belong to an area** (specification
  version 8, 2026-10-26; the crate documentation of `tally/crates/mlat-solver` is the
  specification). The unit of fitting, publishing and citing is the RFC-0174 area, an H3 cell at
  resolution 3 (`AREA_RESOLUTION`). Which pairs of receivers exist is decided by their site records
  alone: each usable receiver keeps its 40 nearest usable receivers within 600 km
  (`PAIR_NEIGHBOURS`, `PAIR_BASELINE_MM`), by exact integer distance between millimetre sites, and
  two receivers are a pair when either keeps the other. An area's members are its own receivers and
  every receiver one of them keeps; its model publishes the pairs with an end in the area, so a pair
  whose ends lie in two areas is published by both, each fitting it from the same raw. Every choice
  is integer arithmetic over signed site records, so any relay computes the same areas, members and
  pairs, and a model names its area. A model's inputs are what had arrived when it was fitted
  (since 2026-10-24, below): its members' sync raw signed in its trailing window, from the batches
  each member's frontier names. This is mlat-server's shape (a clock pairing for each two receivers
  that hear the same aircraft, a fix normalised over the pairings among its hearers), made bounded
  and verifiable. Each pair's clock difference is fitted from the events both its ends heard, every
  ADS-B aircraft a reference (`REFERENCE_KEEP`), as a continuous piecewise-linear function on 5 s
  knots under a curvature prior, robust (Huber passes, then a cutoff until the inliers settle); a
  jump is a clock's when its pairs agree on its time; and every clock's noise and rate are the
  fixed point of the pairs fitted under them, the gauge's rate included, so a free-running gauge's
  frequency error does not scale every time difference. A fit costs a neighbourhood, never a
  region's joint system: a receiver is in at most its own pairs and its neighbours'. A relay
  publishes each model as a signed `ClockModel`: content-addressed, in fixed point, citing its
  area, its trailing window (edge and span) and its input set by hash, count and each member's
  frontier (the receiver's boot and the last batch sequence it cites). Specification versions 1 to
  7 fitted one joint model per canonical tile instead; version 8 is the pairs alone.
- **What is solved.** A target is an aircraft with no ADS-B position heard within the 65 s before
  (what MLAT is for) or one of a hash-chosen sample of the ADS-B aircraft (one in sixteen, so
  calibration is measured on live traffic). Of a target, one transmission is solved in each 700 ms
  slot (mlat-server's `RESOLVE_BACKOFF`, by a rule of the transmissions alone: the slot's
  transmission heard by the most receivers the models locate), and again only when its considered
  set grows. A transmission heard by more than 32 receivers is solved from 32 chosen by their sites
  alone (`HEARERS_MOST`, the knee of accuracy against cost at world density: from mlat-server's 15
  to 24 to 32 to no cap the median horizontal error is 35.0, 27.6, 25.1 and 21.8 m and the fixes
  cost 2.207, 2.271, 2.285 and 2.451 ms a feeder-second, the 95th percentile no better past 32).
  The fix cites one verified model of each area its used hearers are in, all at one edge.
- **Uncertainty is honest.** A published covariance includes the clock component, propagated
  jointly through the pairs among the fix's hearers (not per-receiver variances added as if
  independent, the defect in mlat-server's clock normalisation), and names the models it cites, so
  a tracker can tell which fixes share clock error. Each clock's noise and the robust weights are
  estimated from the window itself, so they can be understated; what keeps the covariance honest
  is that what is kept is chosen without looking at the residuals (by hash threshold and site,
  never by fit), and that its coverage is measured, never assumed (below). The published
  covariance is the fit's, inflated by 1.1 and floored at 5 m a side, for what the simulator cannot
  show (unmodelled multipath, site survey error, clock behaviour beyond its mix); a fix wider than
  1.5 km is not published. Every fix is solved past its models' trailing edge, by at most
  `MAX_CARRY` (14.6 s, a hard bound; a fix carried further is not solved, counted), and its clock
  component grows with the carry by each pair's process noise (a rate and a phase random walk),
  a stated formula.
- **Any relay verifies; anyone checks signatures and fault proofs; the rule is optimality, not
  bytes.** (Amended 2026-10-19, founder: this read "anyone can check a relay", which needed raw and
  sites in every client's hands. Verifying against raw needs the sites and the counters, so only a
  relay, which holds both, does it; a client checks signatures, content addresses and format 1
  fault proofs, which need neither.) Verifying a model is
  rebuilding its area's members and pairs from the site records and its inputs from the batches
  its frontiers cite, and checking the citation exactly (a holder missing a batch at or below a
  frontier cannot rebuild them and says so, unjudged, never a failure), then checking each pair
  at its published knots: its Gauss-Newton step within tolerance of zero over the inliers those
  knots choose, its jumps the rounds' answer, and every clock's noise and rate within tolerance
  of the fixed point of the pairs under them. Verifying a fix reads only the verified models it
  lists and its own receptions: the models must be exactly one of each area its used hearers are
  in, all at one edge; its considered receptions must regroup to one transmission whole, its used
  ones be of the receivers the cap chooses, and normalise on the timeline those models give; then
  residuals and a chi-square test at the claimed position, linear in the observations, and the
  claimed covariance recomputed; omission is checked against
  the spec's deterministic outlier rule within the considered set alone, so an engine that solved
  before a reception arrived is never convicted for leaving it out. The chi-square limit is one
  function on both sides: the statistical
  quantile (zero with no redundancy) widened by what the wire's rounding of position and time can
  add, and an engine publishes a fix only after running the verifier on it as published,
  every one (as built 2026-10-07: checking every solution costs 20% more solving time, measured on
  the 4,000-receiver world benchmark, about half a percent of the windowed engine's compute then). A fault is a signed model or fix that fails verification on
  its own cited raw: any relay holding that raw shows it, and a client drops the relay on its own
  authority. The one fault provable with no raw at all is two signed fixes of one used set, model
  and spec version that disagree beyond tolerance (the fault proof's format 1). Byte identity is a
  property of the reference implementation (two copies that hold the same batches when they refit
  and solve publish the same bytes, tested with a golden), not of the protocol: an independent
  implementation that reaches an optimum within tolerance is honest. Clients merge by the hash
  of a model's inputs, never its bytes. The discrete decisions (trailing windows, frontiers,
  areas, members, the pair network, the models a fix cites, grouping receptions into a
  transmission, the cap, the thresholds, outlier gating) are integer arithmetic on raw counters, batch sequences, signed wall clocks and
  fixed-point models, so independent implementations agree on them exactly.

**Amended 2026-10-24 (founder): MLAT in seconds.** There is one class of MLAT fix, solved about
1.1 s after its transmission's first reception arrives, from the receptions that had arrived, under
pair clock models refit every two seconds over a trailing window of what had arrived. The windowed final
fixes and the provisional fixes beside them are gone, and so is the precise world product that
waited for the finals.

*Why.* A final fix waited for its window: a window step solved eight 5 s bins at once and fell due
one bin after the last of them, once that bin had settled, so a final fix left its engine within
91.5 s of its transmission and had surely arrived anywhere within 108.5 s: it reached its readers
80 to 110 s after it was heard. Everything that held a fix or its raw held it that long: the relay's sealed bins and
open raw, the provisional queue, its notes and orphans, the engine's published queue, standing's
hand-off and its 108.5 s settling, the positions checks' twins at twice a transmission's rate (a
final and a provisional). A hosted MLAT receiver (a seat) cost 49.4 MB of planned memory, and the
world relay could not seat its 2,000 floor. mlat-server, which every production MLAT network runs
(wiedehopf's fork at adsb.lol), publishes a position 0.9 s after it is heard (`MLAT_DELAY`) under a
clock pairing it keeps current, and the provisional path already showed the same here (published a
median 1.34 s after the transmission, 1.65 s at the 95th percentile, in the simulator) at the cost
of a model carried up to 90 s (a median horizontal error of 124 m carried up to 20 s, 468 m from
45 to 90 s). Three critics (estimation, verification, memory) were put to the open question and
converged on this shape: keep the model current instead of carrying an old one, and give up the
final.

*What it decides.*

- **One fix class.** A transmission is due `FIX_SETTLE` (1.1 s) after its first reception reached
  the engine's relay, and is solved from every reception of it that had arrived by then, its
  considered set. A reception that arrives later makes a bigger considered set, solved again at a
  later step and published again, once: at the first step after the transmission's raw has come
  (`MLAT_BATCHING`, 2 s, after its first reception arrived) or as its set closes, whichever is
  first (amended 2026-10-26: before, only as its set closed, `JOIN_MS` after the set's first
  arrival, and a Mode S reply's set holds every repeat of its bytes over that, so every
  transmission of the sets an engine opened together was solved again at one step every 11.5 s);
  the merge's superset rule takes the bigger one, so nothing waits
  for the slowest receiver and nothing supersedes a fix by class. A fix leaves its engine within
  `FIX_SOLVE` (4 s) of its first reception arriving, so within `FIX_LEAVES` (15.5 s) of its
  transmission by its relay's judging clock, and has surely arrived wherever it is read within
  `FIX_ARRIVED` (32.5 s) (§3.6's budget).
- **A trailing-window model, refit every two seconds.** Each area is refit every `REFIT_EVERY`
  (2 s), at the edges of one grid every relay shares (the newest multiple of `REFIT_EVERY` at least
  `FIT_LAG`, 2 s, below the engine's clock, by when every honest receiver's raw of the edge has
  arrived), over its members' sync raw signed in the `TRAILING_WINDOW` (15 s) before the edge,
  warm from its previous model (each pair sought from its last knots; a cold fit lands on the same
  bytes). Its fixes are solved every second under the newest edge's models, so neighbouring areas'
  models, fitted by other relays, share the edge a fix citing several of them needs. A fix is
  solved at most `MAX_CARRY` (14.6 s) past its models' edge, never 90 s.
- **What had arrived, cited exactly.** A model's input set is what had arrived by its edge, cited
  by hash, count and a per-member frontier (its boot and the last batch sequence it cites, each
  member's batches cited as one contiguous run), never "every reception whose signed wall clock is
  in the window", which would force every holder to wait out the slowest feeder. Because the edge
  trails the clock by `FIT_LAG`, two relays holding the same batches fit the same inputs at the
  same edge whatever their paths' delays; a feeder whose signed clock lags the relay's by more may
  be cited differently by two relays, never wrongly. Two relays' models of one area may then
  differ honestly; they are matched by inputs hash, and fixes under different models are
  incomparable sets, never averaged, as the merge rule already says. A relay holding the cited
  batches rebuilds the inputs and verifies the model; one missing a batch at or below a frontier
  answers unjudged, never a failure.
- **Thresholds, not top-k.** Every canonical selection is a hash threshold: the reference aircraft
  (`REFERENCE_KEEP`, every aircraft heard with ADS-B), a busy batch's sync receptions (each kept at
  the rate `min(1, REFERENCE_EVENTS_PER_BATCH / c)`, 32 of `c`) and its replies when over
  `REPLIES_PER_BATCH` (`KEPT_KEEP`), each a function of one batch or one message alone. So what a
  holder of a subset of the raw keeps is exactly what a holder of a superset keeps, restricted,
  and a model over less is a strict subset of one over more. A hard cap on what is held stays, as
  a refusal by the relay-wide pool, never as trimming by rank. At world density a refit's median
  area holds 1,248 sync events over 61 clocks (`pairwise_path_sweep`, below).
- **Considered and used.** A fix names the receptions it considered and the subset it used (the
  outlier rule applied to the considered set). The verifier's omission check runs only within the
  considered set, so an honest engine that solved before a reception arrived is never convicted
  for leaving out what it never had.
- **The superset rule, with verification and standing.** A superset that agrees with a consistent
  smaller fix wins, as before. One that disagrees supersedes the smaller only when a relay holding
  its raw verified it and its receivers carry strictly more standing (RFC-0174 §2.12); the smaller
  is then refused and counts as evidence against what it used. Otherwise the superset is
  contested, kept as evidence, and the smaller stands. Before, every disagreeing superset was
  contested, and with fixes published a second after they are heard, a relay could freeze an
  honest bigger fix out with a fast, favourable subset. A relay verifies a disagreeing superset
  lazily, capped per engine a second (`VERIFY_PER_ENGINE_PER_SEC`, 32; past it refused,
  counted), so asking for verification is no
  way to spend a relay's cores.
- **Standing settles at the fix's arrival bound.** A transmission's fixes are settled against
  their answer `FIX_ARRIVED` (32.5 s) after its signed transmit time, by the keeper's clock, where
  it was `FINAL_FIX_ARRIVED` (108.5 s). `E` is unchanged.
- **Twins with no buffer.** An engine publishes each step's records back to back on one link: the
  models, then each fix record raw (format 7) and at once its tagged twin (format 8). A relay pairs
  a tagged record with the raw record its own link brought last, one record a link, and checks
  every fix of it before a client is sent it, where it held every raw solution for the hub's wait
  for a model.
- **What a seat costs follows.** A relay holds a seat's raw over the trailing window,
  `SIGNED_LAG` and a step, at the mean kept rate in one relay-wide pool (every receiver still held
  to its own ceiling), and nothing waits for a window: the provisional queue, notes, orphans, the
  engine's published queue and standing's hand-off are gone, and a model's fixed parts are an
  area's, not a seat's (RFC-0181, "Sizing"). A seat is planned at about 2.6 MB (`per-seat` in
  `tally/crates/relay/tests/world-relay.txt`, held equal to `tally-relay check`), where it was
  49.4 MB; the aim was 1 to 3 MB.
- **Retired at wire version 4** (§3.3): the `Provisional` kind and its stream, the precise world
  product and its stream, `Positions` formats 1 to 6, and the client clock model's window bins.
  The API's `feed=precise` and an MLAT position's `kind` go with them: there is one kind of fix.
  The specification is version 8 (2026-10-26): the pair models of areas above, where version 7
  (2026-10-24, never released) fitted its trailing window with the joint model per tile.

*What it reverses.* This section read "A window is decided by the raw's own signed wall clocks,
never by when anything arrived." That rule is reversed: a model's inputs are decided by what had
arrived by its edge, named exactly by its frontiers, because the rule it replaces could be kept
only by waiting until every honest receiver's raw of a window had surely come, which is the 80 to
110 s this amendment exists to remove. What the old rule bought, that every relay holding an area
fits the same model, is kept for every feeder on its relay's clock by `FIT_LAG`: two holders of the
same batches, one given them in another order, with copies and up to 200 ms more delay each,
publish the same model bytes for every area at every edge both fitted
(`the_same_batches_in_any_order_and_copies_publish_the_same_models`). A feeder lagging by more
than `FIT_LAG` is where relays part, and the superset rule, the frontiers and the unjudged answer
are what keep that honest.

*The window* (`TRAILING_WINDOW`, 15 s): long against the fit's time constant (about 12 s) and at
least three knots (`MODEL_KNOT`, asserted), so a pair fits its rate. What it gives over the pair
path's scenarios is measured by `tally_mlat_solver`'s `pairwise_path_sweep` (each scenario 120 s,
the default mix over three seeds, one bad clock jumping, every clock 30 ppm fast with a
free-running gauge, and world density, 120 receivers in 12 areas, over 60 s), at the window chosen
and the two longer ones, each run over the same raw:

| W | Scenario | Fixes | Coverage | Horizontal p50, p95 | Refit median: clocks, events | ms a refit, read and fit | Refit cost, ms a feeder-second | Jump found, false jumps |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 15 s | Default mix | 3,053 | 0.944 | 59.0 m, 291.5 m | 10, 245 | 0.3, 0.2 | 0.212 | (none), 0 |
| 15 s | One clock jumping | 2,660 | 0.952 | 95.8 m, 608.2 m | 10, 245 | 0.3, 0.3 | 0.246 | 41 models, 0 |
| 15 s | 30 ppm, free gauge | 3,034 | 0.961 | 71.9 m, 467.4 m | 10, 244 | 0.3, 0.2 | 0.220 | (none), 0 |
| 15 s | World density | 11,270 | 0.948 | 24.4 m, 151.4 m | 61, 1,248 | 3.9, 11.7 | 0.886 | (none), 0 |
| 20 s | Default mix | 3,052 | 0.901 | 60.0 m, 297.1 m | 10, 324 | 0.4, 0.2 | 0.264 | (none), 0 |
| 20 s | One clock jumping | 2,667 | 0.931 | 95.2 m, 581.1 m | 10, 326 | 0.4, 0.3 | 0.313 | 53 models, 0 |
| 20 s | 30 ppm, free gauge | 3,046 | 0.918 | 71.6 m, 472.5 m | 10, 324 | 0.4, 0.3 | 0.275 | (none), 0 |
| 20 s | World density | 11,282 | 0.946 | 24.3 m, 152.0 m | 61, 1,636 | 5.1, 12.0 | 1.124 | (none), 0 |
| 25 s | Default mix | 3,049 | 0.908 | 60.0 m, 293.9 m | 10, 403 | 0.5, 0.3 | 0.331 | (none), 0 |
| 25 s | One clock jumping | 2,675 | 0.916 | 96.7 m, 620.2 m | 10, 405 | 0.5, 0.4 | 0.387 | 65 models, 0 |
| 25 s | 30 ppm, free gauge | 3,045 | 0.926 | 71.0 m, 463.3 m | 10, 404 | 0.5, 0.3 | 0.345 | (none), 0 |
| 25 s | World density | 11,275 | 0.948 | 24.3 m, 151.8 m | 61, 2,019 | 7.1, 12.6 | 1.450 | (none), 0 |

Every model passed its verifier and every sampled fix the cold verifier, at every window and in
every scenario (`pairwise_path_sweep`, release build, 2026-10-26; three seeds of each scene but
world density, which is one; the default mix's scenes are 10 receivers each, a model's area
holding a receiver or two). The 15 s rows were measured again once each clock's white noise was
weighed by its own degrees of freedom (`pair::white_estimate`, below); the 20 and 25 s rows are
from before it, when the 15 s rows read 0.920, 0.928, 0.912 and 0.945. A longer window buys
nothing the sweep can see: coverage moves within 0.03 either way and not in one direction, the
median error within a metre, and no window declares a false jump, while a refit's events grow
with the window and its cost with them (at world density 1.124 and 1.450 ms a feeder-second at 20
and 25 s against 0.851 at 15, all before the noise's degrees of freedom). So `TRAILING_WINDOW` is
15 s, the shortest that holds three knots. Coverage sits inside the 95% band in every scene: 0.944
to 0.961 in the sparse scenes, where a fix has few hearers and an area's model a receiver or two,
and 0.948 at world density. Before, the sparse scenes sat at 0.91 to 0.93: a clock's white noise,
estimated from the scatter of a handful of pairs, was read as if known, and a fix's stated
covariance understated its error. Each clock's estimate now carries its own degrees of freedom
(its variance squared over that variance's own variance in the noise system) and is widened by
`dof / (dof - 2)`, the Student-t predictive rule, with no fewer than `pair::WHITE_DOF_LEAST` (4);
a clock many pairs inform is left almost as it was, so world density moved by 0.003. By the
receivers a fix used, every band of 50 fixes or more holds 0.92 to 0.98; the smaller ones (3 to
41 fixes each) read 0.75 to 1.00, world density's at four and five used 0.895 of 19 and 0.854 of
41. The per-commit check holds the default mix
to 0.92 to 0.98 (`pairwise_path_is_calibrated_and_verifies`). The joint tile model's finals had a median error of
31.5 m over the calibration mix and the carried provisionals 124 to 468 m.

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
- **Tagged positions** (`Positions` format 8, since wire version 4; formats 5 and 6 before it).
  Format 7's layout with no receiver table, each considered reception a
  `ReceptionTag`: the first 16 bytes of BLAKE2s-256 over `"tally reception tag" 0x00`, the reception
  key current when the reception was heard, the counter epoch, the 48-bit counter, the message's
  length and the message. Why a key no client can compute, and not the site id first proposed:
  the site id was then to be published in client clock models, and a tag keyed by a public value
  over a 48-bit counter is a search of 2^48 (hours on one GPU) from the counter itself. A key that
  no wire carries holds whatever else a client learns. A relay rematches tags against its own raw. A
  client merges by tag sets exactly as by observation sets: the same set is a duplicate, a superset
  wins by the superset rule (above), anything else is incomparable.
- **Client clock models** (`ClientClockModel`, kind 0x26), one fixed size: the signer, the full
  model's boot and sequence, issued time, specification version, the full model's id (what
  solutions cite), its inputs hash (what clients match models by) and its trailing window, by its
  edge and span (format 2, since wire version 4; format 1 named a window's bins). It names no
  receiver: no key, no site id, no entry per member, no site, no `site_mm`, no offsets. Why not
  even the members: an area's members are chosen by their exact sites (every receiver among an
  area receiver's 40 nearest within 600 km, by exact distance), so the models a receiver is a
  member of, over time, narrow its site to a fraction of its public cell. Membership is relay-only, like the site. The inputs hash covers site
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
- It holds raw as it arrived, in one pool for every receiver bounded by bytes (relay-wide, sized
  at the mean kept rate, every receiver still held to its own ceiling), in one-second slices of
  signed wall clock: a held reception is 16 bytes over its slice's interned messages, each
  receiver's batches a contiguous frontier. It refuses at ingest what no rule could use (anything
  but a Mode S reply, an ADS-B airborne position with an altitude, or an operational status with a
  NACp), and keeps of each batch what its hash thresholds keep: a reference aircraft's sync events
  (thinned to about `REFERENCE_EVENTS_PER_BATCH` only when the batch carries more), the targets'
  replies (thinned by `KEPT_KEEP` only over `REPLIES_PER_BATCH`), and one aircraft in sixteen whole by hash for calibration. What
  one batch keeps is decided by that batch alone, so every relay and verifier holding the same
  batches keeps the same receptions, in whatever order they came. (Until 2026-10-24 each 5 s bin
  was thinned when it was sealed, at most 32 sync events a receiver by rank, and raw was held for
  the windows' 100 s.)
- Its work is one step a second (as amended 2026-10-24). A step seals what has arrived; refits each
  area it owns once each `REFIT_EVERY`, at the grid's edge `FIT_LAG` below the step's clock, warm
  from its previous model (every owned area with a receiver taking part, bounded by its areas and
  their members, never by demand); takes every transmission whose first reception arrived 1.1 s
  before (its considered set), when the area most of its hearers are in is one it owns; keeps one
  an aircraft a 700 ms slot; solves each under the models of the areas its hearers are in (its own
  and its neighbours', which their relays publish and it verifies over the raw it holds the first
  time a fix cites one), reads it back from its wire form and verifies it as any outsider would. A
  model or a fix that fails is dropped and counted. The work is spread over threads, cut and put
  back in area and address order, so any number of threads publishes the same bytes. A relay
  holds each owned area's border band (every cell that could hold a receiver within 600 km of the
  area, `tally_mlat::area`), so it holds every member's raw.
- It publishes, each step and back to back, each new model's parts (none when it fits its
  manifest, the normal case) and its manifest, then the fixes citing it, each record raw and at
  once tagged; a pair model is about 967 bytes a clock. The manifest frames the
  specification's bytes rather than restating them, and carries the hash of the model's inputs,
  which is what a client matches models by.
- The specification is version 8 (2026-10-26): an area's pair model is fitted over a trailing
  window of what had arrived, cited by frontiers, and every fix names what it considered and what
  it used and cites one model of each of its used hearers' areas. Version 7 (2026-10-24, never
  released) fitted the trailing window with version 6's tile model.
  Version 6 (2026-10-19) named each member's site record by its site id. Version 5 dates a free-running gauge's origin by the least
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
  A fix's timeline is dated by its reference clock: a GNSS-disciplined one by its reading on the
  UTC day its batch's wall clock is in, a free-running one by its model's `heard_ns` (the latest
  its lowest count in the window can have been heard) and its nominal time since, so a
  reception's own batch wall clock never moves a free-running fix. `Positions` is format 7 (since
  wire version 4): each fix names the models it cites (by id, ascending), the receptions it considered (two-byte count) and a mask of which it used, so the used set
  is a subset by construction. Formats 3 to 6 (each fix's addressed citation, and the provisional
  formats) are retired.
- The same batches, arriving in any order and any number of times, and two relays that both hold
  an area's border band and the same batches by an edge, publish byte-identical models and
  identical fixes for that area (the reference implementation's property; the protocol asks only
  optimality within tolerance).
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
- What a relay's MLAT publishes reaches its neighbours over their member sessions (§3.6), so it is
  held to the rate their members share, `--max-member-bytes-per-sec`: 1 MiB/s by default, planned
  once as the 128 feeders it is worth (`hub::DEFAULT_MAX_MEMBER_BYTES_PER_SEC`), which an operator
  hosting MLAT for many seats raises, with the memory to match (amended 2026-10-26: this read 8
  MiB/s, the per-member default `hub` replaced on 2026-10-08 with one shared rate, so a relay with
  many members no longer planned each a budget of its own). It is sized from what the MLAT publishes: in the
  end-to-end tests, 10 receivers and 14 aircraft publish 163 KB of models and 154 KB of positions
  for 906 solutions over 5 bins, and 30 receivers 6 KB a model and 360 bytes a solution (measured on
  the windowed engine). A pair model grows with its members and their pairs (about 967 bytes a
  clock at world density, each clock keeping 40 neighbours), and a fix with the receptions it
  considers (12 bytes each, and a bit of the used mask). Since 2026-10-24 an area's model is
  published as often as it is refit, every two seconds, where a tile's was once a 40 s stride, and
  each transmission is published once as a fix (again only when a bigger considered set is solved),
  where it was a final and a provisional: at world density a model is 967 bytes a clock and a
  receiver a member of 5.84 areas' models, refit every 2 s, so about 2.8 KB of models a hosted
  receiver a second (`pairwise_path_sweep`), some 5.6 MB/s for 2,000 seats before any position
  (1,309 bytes a clock and 7.6 MB/s before the wire named a clock and a pair's clocks by their
  index in the model, with two-byte counts, and carried the variances and kappas in single
  precision, 2026-10-26: the verifier's tolerances are far coarser than single precision's, and
  the producer derives its rate system from the rounded values, so the model it signs is the one
  it fitted). Its positions are 2.6 fixes a seat a second at world density, each of about 30
  receptions considered, planned at most `consistency::POSITIONS_BYTES_PER_SEAT_PER_SEC` a seat
  (the windowed engine's world on one node was about 1.2 MB/s of models, 1.0 MB/s of final
  positions and 2.0 MB/s of provisional ones, 4.2 MB/s). Measured by `tally-load` at 2,000 feeders
  on 16 cores with the measured mix (2026-10-26, 780 seats settled), a seat publishes 5.4 KB of
  models and 2.05 KB of positions, raw and tagged, a second: 7.5 KB together, so the 1 MiB/s
  default carries about 140 seats, the world relay's planned seats (`tally-relay check`, RFC-0181
  "What it admits") about 5 MB/s, and 2,000 seats about 15 MB/s. The members' rate is a resource
  the operator states, as the memory and the cores are, for the members' raw; their products are
  paced apart, at what the seats hosted bring, so the seats never wait on a rate an operator sized
  for raw and raising them plans no more raw ingest (amended 2026-10-27:
  `budget::Plan::member_products_bytes_per_sec`, `ingest::MemberPace`; before, the products spent
  the members' rate and the plan bounded the seats by it, `Bound::Members`, 125 at the default). A model is published only once a
  fix cites it (`Step::models`), and only the models a fix cites are verified. The raw and tagged
  twins of each fix share no bytes on the wire: each is a record signed whole, forwarded byte for
  byte, and a fault proof is two records standing alone, so a twin that named the other's bytes
  would be a new wire version. What an MLAT link at its ceiling costs a
  relay is bandwidth, not memory: what it sends passes through the fan-out ring and the parts table,
  both bounded, and goes out again to every subscriber of positions or clock models, a slow one
  dropped. MLAT links count against the subscriber cap, so an operator sizes that cap and the MLAT
  ceiling to the host's link.
- What the whole world costs is set by the receivers' pairs, the refits, the targets and the
  reception rate, and is planned per seat, never measured on one node: no one relay carries the
  world (RFC-0174 §2.3). The plan is `tally_relay::cores` and `tally-relay check`, from the pair
  sweep's world density (`pairwise_path_sweep`, 120 receivers and 180 aircraft over 150 km, every
  receiver keeping its full 40 neighbours, in 12 areas, 60 s, release build): a refit's median area 61 clocks and 1,248 sync events, 3.9 ms reading its window and 11.7 ms fitting it; refitting 0.872 ms of a core a feeder-second, verifying the neighbours' models a relay's fixes cite 0.387, solving 0.682 (`tally_relay::cores` plans the same; the table's run read 0.886 refitting, as the sweep's timings move by about 2% from run to run), so about 39 cores were the world's 20,000 receivers on one relay; 155 receptions kept a feeder-second, and 2.6 fixes published from 3.2 transmissions solved a feeder-second, each considering 30 receptions (`backoff::Published::MEASURED`, which the sweep fails past). The
  raw held is the trailing window, `SIGNED_LAG` and a step of thinned raw, in the relay-wide pool
  at the mean kept rate (150 kept receptions a seat a second over `arrived::HELD_MS`, 32.5 s, about 273 kB a seat of the 0.90 MB its `Arrived` store plans). Measured for the windowed engine (2026-10-08, for RFC-0181),
  before the amendment: 41 cores kept up with the world on one node, 1,300 core-seconds of joint
  tile fits and 300 of solving a 40 s stride, and one 100 s window held 8.7 GB of raw. The trades
  that engine made are superseded: its stride of eight bins bought cores with latency (a final
  position 7 to 47 s after it was heard), which a refit every two seconds over a short window does
  not need; its sixteen reference aircraft a tile were a top-k, replaced by the `REFERENCE_KEEP`
  threshold; and it started every fit cold, where a pair refit two seconds after the last starts
  from the last knots.
- The simulator's calibration of the pair path (version 8, 2026-10-26, `pairwise_path_sweep`; the
  per-commit check is `pairwise_path_is_calibrated_and_verifies`, held to 0.92 to 0.98 over the
  default mix): at the 15 s window, over three seeds of the default mix (120 s each, 10 receivers a seed),
  coverage 0.944 of 3,053 fixes, a median horizontal error of 59.0 m and a 95th percentile of
  291.5 m; with one receiver's counter stepping once and another's every 2 s, 0.952 and 95.8 m
  (the jump declared in 41 models, no false jump); with every clock 30 ppm fast and a free-running
  gauge, 0.961 and 71.9 m; at world density (120 receivers in 12 areas, 60 s), 0.948 of 11,270
  fixes, 24.4 m and 151.4 m, a fix citing 8.04 areas' models whose pairs hold 0.983 of the
  network's pairs among its used hearers. Every model passed its verifier and every sampled fix
  the cold verifier. Every scene sits inside the 95% band, each clock's white noise weighed by its
  own degrees of freedom (0.91 to 0.93 in the sparse scenes before, 2026-10-26). The joint tile model's calibration (version 5, measured before the
  amendment) is the comparison: with the published floor and inflation stripped, the truth was
  inside the 95% ellipsoid for 0.953 overall over forty scenarios of a realistic clock mix, for a
  median horizontal error of 31.5 m, and the published ellipsoid covered 0.979.
- **Calibrated over real receivers** (§10, step 7; measured 2026-10-08 on the windowed engine,
  version 4, `tally/crates/mlat-calibrate`, whose crate documentation states the method; the same
  hour through the version 8 engine: against the truth model, 0.954 overall (0.959 published) and 0.970 over the 45 sensors LocaRDS verified (0.973), a fix for 0.798 of the eligible (aircraft, 0.7 s slot) pairs (311,365 fixes), and a median horizontal error of 85.2 m (80.1 m over the verified sensors), measured 2026-10-26 on four threads, where version 4 gave 0.895, 0.941 and 121 m). The data is
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
- The client merge rule is implemented once, `tally/crates/merge` (`tally-merge`), for every
  client; `tally-api` is the first. It reads positions, clock models (reassembled part by part
  against their manifests), fault proofs and, until 2026-10-19, optionally raw, from any number of
  relays (a client now reads tagged positions, client clock models and tagged fault proofs only;
  what that changes is said in each item below), and holds
  per aircraft its latest transmissions (eight), each with the fix kept and up to four
  alternatives:
  - *One transmission, only on evidence*: two solutions are of one transmission when they name
    one aircraft with the same message bytes and either their considered sets share a reception, or are tied through a
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
  - *The full input set* is the considered set and the cited model's inputs hash; its identity is
    BLAKE2s-256 over `"tally merge input set" 0x00`, the set's hash and the inputs hash. The same
    set is a duplicate (dropped; its signer joins the fix's relays). A fix over a superset of a
    smaller one's considered set is the ordinary case since 2026-10-24: an engine publishes a fix
    as soon as it can solve one and again when more receptions of the transmission arrive. One
    that agrees with the smaller within the smaller's covariance (RFC-0174 §2.12) supersedes it,
    and under the same model inputs drops it. One that disagrees supersedes only when a holder of
    its raw verified it and its receivers carry more standing; a client holds neither, so for it a
    disagreeing superset is unjudged and stays contested, kept as evidence while the smaller
    stands, and the API says so (`contested`). A client trusts the relay's consistency gate for
    the rest: a relay forwards no fix that disagrees with its own receptions (§3.8.2). Anything
    else is incomparable.
  - *Incomparable*: until 2026-10-19 a client holding the raw of every cited observation solved
    the transmission itself. Only a relay holds raw now: a relay that holds both solves their
    union and publishes it, and a client takes the tie rule.
  - *Incomparable, the tie rule*: the fix with the greater weight (the tags it used), then the
    lowest input set hash, is kept; the other is recorded as an alternative. Both are functions of
    the fix alone, so every client holding the same fixes keeps the same one, in any order.
  - *Checked before it counts*: the record verifies under its engine's key; the model summary it
    cites is held, signed by the same engine and of the specification the record names; and the
    fix's message names its aircraft. That is all a client can check (signatures and content
    addresses), and the fix says so; until 2026-10-19 a client whose own raw rebuilt the tile's
    members and inputs verified the model and every fix under it, and since then the check
    against raw is a relay's. Models are matched by the hash of their inputs, never by their
    bytes, so two honest relays' models of one inputs that differ in the last bits are the same
    evidence.
  - *Fault proofs*: a checked proof marks the relays it names faulted; what stood on their word
    alone is dropped (a transmission keeps its best remaining fix, and a superset the dropped fix
    refused is judged again without it), their models are forgotten, and nothing they sign later
    counts. A verdict that comes late moves the answer once and never back.
  - *Bounded*: tracks, models, fixes waiting for their model and faulted keys are each capped by
    count, least recently active forgotten first (the relay's table).

  `tally-api` subscribes with `--relay` to positions and clock models (`--mlat-raw`, which
  read raw, is gone since 2026-10-19), and serves an aircraft's merged MLAT position when readsb
  holds no ADS-B position for it, its newest fix, a few seconds after it was heard: it states
  `position_source` (`adsb` or `mlat`) and, for MLAT, the horizontal sigma, the check it passed
  (`model`, `signature` or `resolved`; with no raw, `signature`, §3.8.2), its confidence
  (`unconfirmed` at a client, which holds no standing) and whether a bigger fix contested it. Its
  `kind` (`final` or `provisional`) is gone with wire version 4.

#### §3.8.2 Who checks a position

Verification is delegated, not universal. No one checks every fix against raw, and nothing here
needs anyone to; each fix is checked by whoever is placed to, and says which check it passed.

- **The relay that signs it.** A relay's MLAT verifies every fix it signs as any checker
  would, from the raw it considered (`publish::solve_fix`, then the verifier again over what it
  considered, every one; one that fails is dropped and counted). It does not verify its own clock
  model: that is for others.
- **The relays that forward it to a client.** A relay sends a client a tagged fix only after
  pairing it with its raw twin, the record its engine's link brought just before it, and finding
  every fix under its model and consistent with its own receptions (`tally_relay::consistency`,
  RFC-0174 §2.12); one that fails is sent to no one, and one it cannot check goes to relays alone.
  A disagreeing superset is verified lazily, by a relay holding its raw, capped per engine a
  second (`VERIFY_PER_ENGINE_PER_SEC`, 32; RFC-0174 §2.12).
- **The other relays holding the area.** Every relay that holds an area's border band receives the same
  raw (§3.8.1), and computes the same positions to the same bytes from the batches that had
  arrived when it refit and solved: since 2026-10-24 two relays agree on a model's inputs only when
  the same batches had arrived at both, and otherwise publish incomparable models, each verifiable
  from the batches its frontiers cite. Two signatures over the same inputs that disagree are a
  fault proof (`FaultProof`), which anyone checks with the two signed records
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
one. Nothing is refused for having one: a lone relay's fixes are served, counted as one. Since
2026-10-24 a model's inputs are what had arrived at its relay by its edge, which trails the clock
by `FIT_LAG`, so two relays sign one inputs hash whenever the same batches had reached both by
then: given the same batches in another order, with copies and up to 200 ms more delay each, two
holders publish the same model bytes for every area at every edge both fitted
(`tally_mlat_solver`'s `the_same_batches_in_any_order_and_copies_publish_the_same_models`); only a
feeder lagging its relay's clock by more than `FIT_LAG` parts them. The directory aims to place at least two relays of different operators on every area (RFC-0174 §2.9),
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
- **Naming a model's members to clients.** An area's membership is chosen by exact site, so it narrows
  a site below its public cell over time (§3.8.1).
- **Final MLAT fixes over settled windows, and provisional ones beside them** (2026-10-24). A
  window decided by signed wall clocks had to wait for every honest receiver's raw of it, so a
  final fix reached its readers 80 to 110 s after it was heard and every table that held it or
  its raw held it that long (49.4 MB a hosted receiver); the provisional fix that covered the wait
  was solved under a model carried up to 90 s. One fix class, solved a second after it is heard
  under a model refit every second over what had arrived, replaces both (§3.8.1).
- **The precise world product** (2026-10-24). It was the world sealed once the finals had surely
  arrived, 108.5 s after its second; with no finals there is nothing for it to wait for (RFC-0174
  §2.11).

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
7. **MLAT in seconds (2026-10-24):** three critics put to why a final fix took 80 to 110 s and a
   seat 49.4 MB. Estimation: refit a trailing window every second, warm, and solve under the newest
   model, never a carried one. Verification: a model's inputs are what had arrived, cited by
   frontiers; every canonical selection a hash threshold; a fix names what it considered and what
   it used, and omission is judged only inside the considered set; a disagreeing superset wins
   only verified and with more standing, or an early subset freezes the honest bigger fix out;
   twins paired back to back. Memory: a model's fixed parts per area, one relay-wide pool of kept
   raw at the mean, raw charged after thinning, and everything that waited for a window gone.

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
9. **MLAT in seconds** (2026-10-24), in one release with no migration window (§3.3, §3.8.1): wire
   version 4 (positions formats 7 and 8, the provisional kind, the precise world product and their
   streams retired), the MLAT specification's version 8 (an area's pair models over a trailing
   window, cited by frontiers, thresholds for every canonical selection, considered and used sets,
   fixes citing one model of each used hearer's area), the engine's one step a second, the relay's
   hosted MLAT and its stores re-planned, standing settling at `FIX_ARRIVED`, twins paired with no
   buffer, and the merge, the API and the client core's reads moved together. Measured: the window
   of 15 s chosen by `pairwise_path_sweep` (refit 0.851 ms a feeder-second at 15 s, coverage within
   0.03 at 20 and 25 s); a coverage of 0.948 and a median of 24.4 m at world density, 0.944 to
   0.961 and 59 to 96 m in the sparse scenes (0.91 to 0.93 before each clock's white noise carried
   its degrees of freedom); LocaRDS 0.954 over the hour (0.970 on its good sensors);
   `tally-relay check`'s floors pass with about 2.6 MB a seat and 2,022 seats, bound by cores
   (they fail since the load test's costs were planned: 489 seats, RFC-0181 "MLAT in the cores").
