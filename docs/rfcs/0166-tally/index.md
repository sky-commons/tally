# RFC-0166: Tally, where a receiver publishes once and nobody owns the network

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
may run; relays pass the signed batches on untouched and serve consumers; MLAT is computed by
separate engines anyone may run; Flightlines is consumer number one and our own boxes are feeder
number one, so from the first relay we depend on nobody's infrastructure but ours, and every
receiver anyone adds afterwards is coverage for every consumer at once.

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
operator's stream stops, every consumer stops, and the feeders, who own the antennas, have no
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
Counters are never calibrated before an MLAT engine, by anyone.

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

### §3.4 Records, and the rules that let them change without the feeder

`tally/crates/wire` is the only code that encodes or decodes Tally, and every binary uses it. A
record is a kind byte, a two-byte length, a body; a Noise message carries whole records.

| Kind | Record         | Meaning                                                                         |
| ---- | -------------- | ------------------------------------------------------------------------------- |
| 0x01 | `Hello`        | the versions the initiator speaks, and its role (feeder, subscriber, relay)     |
| 0x02 | `Welcome`      | the version both speak from here on                                             |
| 0x03 | `Batch`        | a receiver's signed receptions (§3.1)                                           |
| 0x04 | `ReceiverInfo` | a receiver's signed self-description: location, clock class, software, relays  |
| 0x05 | `Heartbeat`    | liveness                                                                        |
| 0x06 | `Redirect`     | "leave me", with relays as hints the feeder may ignore (§3.7)                   |
| 0x07 | `RelayList`    | relays this relay knows of, as hints                                            |
| 0x08 | `RateLimit`    | the most a relay wants; a feeder may go lower, never above its owner's ceiling |
| 0x09 | `Goodbye`      | the relay is closing, and how long to wait                                      |

The extension rules, which are what a frozen feeder relies on:

- An unknown kind is skipped, unless its high bit (0x80) marks it critical, which ends the session
  cleanly. New records are therefore non-critical unless ignoring them would be wrong.
- A body may carry bytes after the fields a reader knows; they are ignored, so fields are appended.
- An enum value a reader does not know is kept as `Other`, never an error.
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

1. **Regional raw:** batches routed by the receiver's declared cell, for MLAT engines and research.
   Routing is by where the receiver is, never by decoded aircraft position.
2. **Deduplicated:** one copy of each Mode-S message (byte-identical within a short window), for
   most consumers, signed by the relay as its own claim. It is about 30 Mbps for the whole world at
   20,000 receivers, against roughly 1 to 2 Gbps of raw receptions.
3. **MLAT results:** positions published by MLAT engines (§3.8), signed by the engine.

A subscriber chooses with `Subscribe { streams, regions }`, which it may send at any time and which
replaces the last one; before any, it gets raw batches for the whole world. Regions are H3 cells of
any resolution (`wire::region`, the one place that says whether a receiver is inside one), matched
against the location in the receiver's newest signed `ReceiverInfo`; a receiver with no location
reaches only whole-world subscriptions. In wire version 1 the deduplicated stream is whole-world
only: it mixes every receiver, so it is not cut by region. A relay derives its own deduplicated
stream and never forwards another relay's; positions travel between relays like batches, verified
and forwarded once by hash.

Relays form a tree: regional relays pass their region up to a few top relays that hold the world,
and a whole-world consumer subscribes once to a top relay. Each relay caps how many full-world
downstreams it serves; beyond the cap it redirects, so a heavy consumer runs its own relay and
carries its own load. A free tier is capped per consumer and in total. Taking data in costs a relay
only its server; what it sends out is its own budget to set.

A slow subscriber is dropped, never waited for: per subscriber a bounded queue, and a full queue
disconnects it (readsb's keep-latest rule, RFC-0119 §3.3).

What a relay holds is bounded, and what it trusts is narrow, because keys cost nothing to make:

- A peer may claim the relay role only if the operator accepted its key (`--accept-relay`);
  any other key claiming it is refused. Accepted relays carry whole regions and are not held to
  a feeder's intake ceiling; every other inbound peer is (`--max-feeder-bytes-per-sec`, 256 KiB/s
  by default), and connections are capped (`--max-connections`).
- A batch is forwarded once: new by hash, and with a sequence above the highest already forwarded
  for that receiver's boot, less a small reorder allowance, so a signed batch replayed after its
  hash is forgotten is still refused. Positions follow the same rule per engine boot. The table of
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
receipts from consumers) live in relays and consumers, which update. They wait until an attack
appears (§8.1). The feeder already carries what they need: signed, numbered, chained batches and
signed relay choices.

### §3.8 MLAT is computed by separate engines, never inside relays

Clock sync needs decoded ADS-B positions, and its state is pairwise, so it is not a relay's job
(a relay that tracked clocks would be a second decoder) and no single relay can own a receiver's
clock. An MLAT engine is a subscriber: it takes a region's raw batches, decodes privately for
clock sync (the mlat-server method: pairs of receivers related through aircraft with known
positions), solves, and publishes signed positions with their uncertainty and the observation
identities used.

- Engines cover overlapping regions (at least one reception radius, about 400 km), and a receiver
  belongs to every engine whose region covers it.
- An observation's identity is receiver key, counter epoch, raw counter and message hash, the same
  whichever relay delivered it, and engines deduplicate on it before solving.
- Engines never exchange calibrated times, pairwise time differences or pre-solved positions as
  solver inputs. Pairwise differences share their reference receiver's noise and overstate
  certainty; calibrated times from two engines make one reception look like two.
- A receiver's clock error is shared by everything it hears, so a solver models it as one bias per
  receiver, never as independent noise per observation.
- Consumers trust a target confirmed by receivers in separate places more than one heard once.

The first engine, `tally-mlat`, runs no solver of its own. It bridges Tally to an unmodified
mlat-server (wiedehopf's, the one the open aggregators run) by speaking mlat-client's protocol to
it on behalf of each receiver in its regions: one session per receiver with an exact location and
a known clock, the handshake mlat-client sends, the sync and mlat messages mlat-client's selection
logic would send, and the positions the server returns on those sessions, signed as `Positions`
and published back through the relay. Because Tally delivers a receiver's receptions in batches
of about a second and the server groups copies of one message only within 0.9 s, the engine replays
every receiver on one timeline, a fixed delay (2 s by default) behind each reception's estimated
time. Whether that grouping holds across many real receivers, and what delay it needs, only a run
against a real server shows.

### §3.9 Our own use, and the production rule

We run our own relays (top relays, on our hardware), and our boxes' feeders pin them as home. The
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
engine's receiver slots, within the per-address, per-feeder and per-engine caps; and because a
feeder may publish only its own batches, replaying another receiver's old batch into a relay
needs a peer that relay's operator accepted (an accepted relay or an upstream link), and then
succeeds only once that relay has forgotten the stream, which it does least recently active
first, so a receiver that keeps publishing is the last a flood can push out. The stronger
defences of §3.7 (standing by map cell, delivery receipts) are the answer if any becomes an
attack, and the feeder already carries what they need. RFC-0119 §4's ceiling on what
Flightlines trusts ADS-B to mean is unchanged.

## §5 Bandwidth and cost (estimates until step 4 measures them)

A feeder uploads about 50 kbps to each of its relays. At 20,000 receivers, raw receptions are about
1 to 2 Gbps in total, the deduplicated world about 30 Mbps, MLAT results about 1 Mbps. One relay on
a 1 Gbps server serves about 25 whole-world deduplicated consumers or hundreds of regional ones; a
whole-world consumer costs about $10 a month in metered bandwidth. Our cost at that scale is
roughly $200 to $700 a month on budget hosting; today it is one server.

## §6 Legal and privacy (researched 2026-10-05; sources in §9)

- Receiving and relaying ADS-B is lawful in the US (18 USC 2511(2)(g)(ii); 47 USC 605). UK and
  German secrecy laws plausibly exclude a broadcast to all, and no feeder has been prosecuted in
  either. China seized receivers in 2021. Tally recruits only through adsb.im (§8.4).
- LADD binds FAA data-feed subscribers by contract, not relays of radio receptions. Filtering is a
  consumer option, not a network duty.
- An exact receiver location is personal data under GDPR. It is published exactly by default, with
  that said plainly at install, and the owner may round it (§8.3).
- Sweden's IMY reprimanded Flightradar24 (2025) for demanding proof of ownership before honouring
  removal requests; publication itself was a legitimate interest. A Tally node that runs MLAT or
  archives is a GDPR controller and keeps a simple objection process.
- Feeders dedicate their receptions under CC0; what Tally publishes downstream is ODbL, so nobody
  can take the data private (§8.2).

## §7 What is killed

- **A Flightlines-only ingest.** One more aggregator holding one more feeder list: the shape §1
  says failed us.
- **Relays compressing receptions into multi-receiver bundles.** Small saving; destroys the
  per-receiver proof (critic 1).
- **Shipping pairwise time differences or calibrated times between engines.** Overstates
  certainty (critic 1).
- **Directory authorities ("keepers"), staking, and social vouching.** Keepers go inactive and are
  a party to capture (founder); staking is Helium's failure; vouching is free for colluders.
- **Ranking relays by popularity.** Snowballs and rewards defection (critic 4).
- **Exact version matching and "unknown kind is an error".** Either one disconnects every frozen
  feeder the day a relay upgrades (critic 3).
- **A remote kill switch, config push or self-update in the feeder.** The single point of control
  this network exists to remove.
- **Re-publishing adsb.lol's aggregate into Tally.** Their data, their licence, and a feedback loop.
- **A broker in the middle (MQTT, NATS, Kafka).** Durable buffers with worse semantics than drop
  the slow consumer, and a dependency a stranger must run.

## §8 Founder rulings (2026-10-05)

1. **Attacks are bounded, not prevented, and the defences wait until an attack appears.** "We can
   always address issues as they arise." The exception is the feeder, which cannot be fixed later:
   it carries the hooks (§3.5, §3.7).
2. **Licence:** CC0 in, ODbL out.
3. **Receiver location is exact by default.** Any MLAT engine needs it, and rounding for some and
   not others would need a trusted party. The installer says the location is public; the owner may
   round it and contribute less to MLAT.
4. **Recruitment is through adsb.im only.** Outside that, no recruiting.

## §9 Provenance: what each critic changed

1. **Signing and MLAT:** batches are the unit and are never repacked; Ed25519 identity; MLAT in
   separate engines with overlapping regions; observation identity; no pairwise differences; drop
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
5. **On our hardware.** `infra/prod-host/tally`: our relay on loopback, one feeder per box in the
   feeder roster, the consumer readsb moved to the relay's output, every Tally process on
   loopback by the egress policy. Verified by the consumer's own counters; bandwidth measured.
6. **Public launch.** Built: aarch64 and x86_64 binaries against the pinned sysroot (glibc 2.25 or
   newer, no C++ runtime; the aarch64 build is checked as an ELF but has not yet run on a Pi), the
   systemd units and the one-line installer (`tally/packaging`). Owed: a public relay on a host
   with a public address, seeds from more than one operator, release builds published to
   `flightlines/tally`, and the adsb.im pull request.
7. **Streams, engines and 978 MHz.** Built: subscriptions by region, the relay-signed deduplicated
   stream, engines publishing positions, peer exchange and redirects at capacity; `tally-mlat`
   over mlat-server; the feeder's 978 MHz input from dump978-fa, in the same signed chain as
   1090. Owed: a run against a real mlat-server with real receivers. Then **the Bridge as a
   receiver** (its own RFC).
