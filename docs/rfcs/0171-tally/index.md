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
restarted, so counters from before and after never meet), its wall clock, the count of receptions
its own rate ceiling dropped, the hash of its previous batch, the receptions, and an Ed25519
signature. Relays forward batches byte for byte. Consequences, each the reason for one field:

- Anyone downstream can prove a receiver published exactly what arrived; a relay can drop a batch
  but cannot alter or invent one.
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

**The roles** a `Hello` names: feeder, subscriber, relay, engine (another relay's MLAT taking raw
one hop, RFC-0174 §2.3; it publishes nothing), and **probe**. A probe is a
measurement session (RFC-0174 §2.2's round-trip probing and delivery check): it may send only
`Echo` and `DeliveryQuery` (`Role::may_send`), is answered, and is never admitted as a feeder or
a subscriber, so measuring a relay takes none of its feeder slots and is sent none of its streams.
A probe that sends anything else is ended with `Goodbye{Protocol}`. A full relay still answers a
probe.

### §3.4 Records, and the rules that let them change without the feeder

`tally/crates/wire` is the only code that encodes or decodes Tally, and every binary uses it. A
record is a kind byte, a two-byte length, a body; a Noise message carries whole records.

| Kind | Record         | Meaning                                                                         |
| ---- | -------------- | ------------------------------------------------------------------------------- |
| 0x01 | `Hello`        | the versions the initiator speaks, and its role (feeder, subscriber, relay, engine, probe) |
| 0x02 | `Welcome`      | the version both speak from here on                                             |
| 0x03 | `Batch`        | a receiver's signed receptions (§3.1)                                           |
| 0x04 | `ReceiverInfo` | a receiver's signed self-description: location, clock class, software, relays  |
| 0x05 | `Heartbeat`    | liveness                                                                        |
| 0x06 | `Redirect`     | "leave me", with relays as hints the feeder may ignore (§3.7)                   |
| 0x07 | `RelayList`    | relays this relay knows of, as hints                                            |
| 0x08 | `RateLimit`    | the most a relay wants; a feeder may go lower, never above its owner's ceiling |
| 0x09 | `Goodbye`      | the relay is closing, and how long to wait                                      |
| 0x0a | `Subscribe`    | the streams a subscriber wants, and its regions by receiver location (§3.6)     |
| 0x0b | `RelayBatch`   | a relay's own deduplicated stream, signed under its own domain (§3.6)           |
| 0x0c | `Positions`    | a relay's signed solutions, each naming its observation set (§3.8.1)          |
| 0x0d | `ClockModel`   | a relay's signed, content-addressed clock model manifest for one tile and window (§3.8.1) |
| 0x0e | `FaultProof`   | two signed solutions of one inputs that disagree, or two signed models of one inputs that differ; checked before forwarding |
| 0x0f | `ClockModelPart` | one part of a clock model too large for its manifest, checked against it (§3.8.1) |
| 0x10 | `Provisional`  | a relay's signed provisional solutions (`Positions` format 4), superseded by final ones; only to subscribers that asked (`PROVISIONAL`, §3.8.1) |
| 0x11 to 0x21 | RFC-0174's records | echo, delivery check, provider directory, sharing groups, credit, the regional and the two world products, parity and bundle index (RFC-0174 §2.10); transport version 2, the minimum |

The extension rules, which are what a frozen feeder relies on:

- An unknown kind is skipped, unless its high bit (0x80) marks it critical, which ends the session
  cleanly. New records are therefore non-critical unless ignoring them would be wrong.
- A body may carry bytes after the fields a reader knows; they are ignored, so fields are appended.
- An enum value a reader does not know is kept as `Other`, never an error. The exception is
  evidence: a delivery answer's possession tag a reader does not know is an error, never read as
  a proof.
- Every record body has one check of what makes it well formed (ranges ascending and exact,
  spans bounded, a position on the globe, one product where one is named), and the codec runs it
  on every encode and every decode (`tally_wire::Check`), so no value that breaks it is written or
  read.
- A signed form (batch, receiver info) keeps the same prefix in every format version (format byte,
  key, and for a batch its boot id and sequence) and ends with the signature over everything
  before it, so a relay can verify, route and deduplicate a format it does not otherwise read.
- An `Observation`'s format is BEAST's own type byte for 1090 MHz; 978 MHz UAT takes a new value
  and needs no new record, and relays forward formats they do not know.

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
  (§8.3), a periodic wall-clock sample and its clock class.

It must never carry: a remote kill switch, remote configuration or command push, self-update (it
updates through the owner's package manager, if ever), a single built-in seed or signer, any check
that fails on an old date (a Pi without a clock battery boots in 1970), a disk buffer (it wears SD
cards and replays stale data), or a listening port.

### §3.6 The relay: verify, forward, serve, and decide nothing about aircraft

`tally-relay` accepts feeders, subscribers and other relays on one port. It checks each batch's
signature, drops duplicates by hash, and forwards. It decodes no frame. It serves three streams:

1. **Regional raw:** batches routed by the receiver's declared cell, for relays' MLAT and research.
   Routing is by where the receiver is, never by decoded aircraft position.
2. **Deduplicated:** one copy of each Mode-S message (byte-identical within a short window), for
   most clients, signed by the relay as its own claim. It is about 30 Mbps for the whole world at
   20,000 receivers, against roughly 1 to 2 Gbps of raw receptions.
3. **MLAT results:** positions published by relays' MLAT (§3.8), signed by the relay.

A subscriber chooses with `Subscribe { streams, regions }`, which it may send at any time and which
replaces the last one; before any, it gets raw batches for the whole world. Regions are H3 cells of
any resolution (`wire::region`, the one place that says whether a receiver is inside one), matched
against the location in the receiver's newest signed `ReceiverInfo`; a receiver with no location
reaches only whole-world subscriptions. In wire version 1 the deduplicated stream is whole-world
only: it mixes every receiver, so it is not cut by region. A relay derives its own deduplicated
stream and never forwards another relay's; positions travel between relays like batches, verified
and forwarded once by hash.

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
is on; MLAT runs in-process on `--mlat-threads` threads (every core by default, 0 for none) for
the areas it is chosen to solve; `--no-relay-duties` turns off accepting feeders, MLAT and seeding
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
  `8Mbit/s` (at most 2.67 TB in 31 days, inside a $12 Lightsail plan's 3 TB) and saying that the
  bill can never exceed the cap times the seconds in a month. `0` with a unit sends nothing billed,
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
- A batch is forwarded once: new by hash, and with a sequence above the highest already forwarded
  for that receiver's boot, less a small reorder allowance, so a signed batch replayed after its
  hash is forgotten is still refused. Positions follow the same rule per MLAT boot. The table of
  streams is capped and forgets the least recently active (a stream's activity is a forwarded
  batch), so a flood of new streams pushes out its own oldest first.
- Receiver descriptions are capped and forget the receiver least recently active; a subscription names at
  most 64 regions; a `Subscribe` sent with `Hello` decides the first byte a subscriber receives.
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
  whichever relay delivered it, and relays deduplicate on it before solving.
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
  union (raw is public, so the union is always computable).
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
  Every choice is integer arithmetic over signed descriptions and raw, so the assignment is
  canonical: any relay or verifier computes the same tile from the same raw, and a model names
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
- **Anyone can check a relay, and the rule is optimality, not bytes.** Verifying a model is
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
  its own cited raw: anyone holding that raw shows it, and a client drops the relay on its own
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
  description places them in its regions with a clock and location precision the specification
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
- The specification is version 4 (version 3's tile models, addressed citation and dropped clocks,
  and from the calibration over real receivers below: a clock that declares GNSS discipline is
  fitted as it behaves, a clock nothing places is dropped rather than failing its tile, and the
  last jump scan is at the published estimate a verifier scans; version 2 added the gauge's rate
  and the reference aircraft's position biases, version 1 had neither). A
  model or solution names its version, and two relays agree exactly only under the same one.
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
- What the whole world costs one relay is set by the tile, the stride and the targets, and
  measured in release by the simulator at 20,000 receivers (about 5,400 targets a window, on
  3,800 tiles): 27 cores keep up (a tile fit 0.28 s a core, 1,050 core-seconds of fits and 22 of
  solving a 40 s stride, on 32 threads) and the raw for one window is 1.6 GB (118 million
  receptions made a minute, 70 million held after thinning, 34 bytes an observation with the
  index). Indexing a window takes 43 ms and assigning every target 0.4 s on 32 threads. A tile's
  fit plus its folded calibration takes 71, 95 and 107 ms at 100, 300 and 1,000 receivers, and an
  outside verifier checks it in 23 to 34 ms. Each choice that sets this was measured, and the
  trade is stated:
  - *Stride 8.* Fits a solved bin cost 21.4, 11.0, 5.7 and 2.9 at stride 1, 2, 4 and 8 (0.86,
    0.45, 0.24 and 0.13 s), at the same coverage (0.958 to 0.963), for a final position 14.5,
    17, 22 and 32 s late on average; the world needs 34 cores at stride 4 and 27 at 8. The cost
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
    receivers heard, carried past its knots along each clock's last interval, at most 90 s (the
    longest a final model is behind at stride 8 on a world-scale node; beyond it the model maps
    nothing). The clock covariance grows by the curvature prior's integrated random walk over
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
  against their manifests), fault proofs and, optionally, raw from any number of relays, and holds
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
  - *The full input set* is the observation set and the cited model's inputs hash; its identity is
    BLAKE2s-256 over `"tally merge input set" 0x00`, the set's hash and the inputs hash. The same
    set is a duplicate (dropped; its signer joins the fix's relays). Under the same model inputs a
    superset of observations wins and a subset is dropped. Anything else is incomparable.
  - *Incomparable, holding the raw* of every cited observation: the client finds the
    aircraft's canonical tile from its raw, fits that tile's model, solves the transmission and
    verifies it as a relay would; that fix stands above the ones it was solved from.
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
    model's raw and falls back to the signature check. Models are matched by the hash of their
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
    one neither superseded nor confirmed 90 s after it arrived (by the client's clock; a final
    comes at most about 82 s after its transmission at world scale, and 90 s is the one bound
    every party waits on, `tally_wire::products::FINAL_FIX_ARRIVED_MS`) is retracted, forgotten, and
    counted against its signers. Measured over a live MLAT and its own finals, 1,109 provisionals:
    382 superseded, 726 confirmed, 1 retracted.
  - *Bounded*: aircraft, models, solutions waiting for their model, faulted keys, resolved fits,
    provisional fixes and raw are each capped, least recently active forgotten first (the relay's
    table), raw also by bin as the client's clock moves on.

  `tally-api` subscribes with `--relay` (and `--mlat-raw` for the raw) to final and provisional
  positions, and serves an aircraft's merged MLAT position when readsb holds no ADS-B position for
  it, stating `position_source` (`adsb` or `mlat`) and, for MLAT, the horizontal sigma, the check
  it passed (`model`, `signature` or `resolved`) and its `kind` (`final`, or `provisional` while
  later than every final fix).

### §3.9 Our own use, and the production rule

We run our own relays (on our hardware), and our boxes' feeders pin them as home. The
consumer readsb's connector moves from `out.adsb.lol` to our relay's plain BEAST output on
loopback. **The production rule, for us and anyone: consume Tally through a relay you run, not
someone else's.** A competitor can then degrade only the feeders it carries, and the multi-relay
rule covers those. RFC-0119 §3.7's closure holds: the consumer readsb feeds nothing, and Tally's
received stream is never re-published as if our receivers heard it.

### §3.10 Where the code lives, and the mirror

`tally/` is a self-contained Cargo workspace with its own Bazel module file: it references
nothing outside itself and builds with `cargo` or Bazel alone. In the monorepo, the root module
includes `//tally:tally.MODULE.bazel` (its crate repository, `tally_crates`), and the nested
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
- An exact receiver location is personal data under GDPR. It is published exactly by default, with
  that said plainly at install, and the owner may round it (§8.3).
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

## §8 Founder rulings (2026-10-05)

1. **Attacks are bounded, not prevented, and the defences wait until an attack appears.** "We can
   always address issues as they arise." The exception is the feeder, which cannot be fixed later:
   it carries the hooks (§3.5, §3.7).
2. **Licence:** CC0 in, ODbL out.
3. **Receiver location is exact by default.** Any relay's MLAT needs it, and rounding for some and
   not others would need a trusted party. The installer says the location is public; the owner may
   round it and contribute less to MLAT.
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
   sockets (`//tally/crates/relay:end_to_end`): a stand-in readsb's frames reach a subscriber
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
