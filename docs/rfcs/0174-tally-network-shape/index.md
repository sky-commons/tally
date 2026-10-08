# RFC-0174: The Tally network's shape, where every relay is one kind and raw stays near home

- Status: **accepted 2026-10-06 (founder); built 2026-10-07** (§5 steps 1 to 7, in one change on
  the RFC-0171 and RFC-0173 branch; what was built differently from the first text is said where
  it is, marked "as built"). Founder direction, the same day, in conversation: there is one kind of
  relay, not regional relays and separate MLAT operators; the relay and its MLAT ship as one program,
  relay duties on by default and not mandatory (sharing is the requirement); a feeder sends to
  the two nearest healthy relays on different networks; MLAT runs where the raw is; the data spreads
  by area, the way BitTorrent spreads a file; fast provisional MLAT positions are approved for
  cockpit traffic; honouring LADD and PIA is the displayer's duty, not the network's. The critics'
  corrections the same day (the round-trip band and the per-area capacity-weighted pick, k MLAT
  relays an area, striped sharing trees as a forwarding duty, proofs of possession in the delivery
  check, the agreeing-superset merge rule) are folded into §2.
- Two independent critics (estimation theory, and distributed systems with a Monte Carlo of relay
  choice) were put to the open question of how MLAT combines across relays; §3 records what they
  killed.
- Builds on RFC-0171 (Tally): the signed batch (§3.1), the transport and its versions (§3.3), the
  extension rules (§3.4), the upload speed cap and its priorities (§3.6), and the deterministic, verifiable MLAT and
  merge rule (§3.8.1) are kept whole. What changes is who runs what, where a feeder sends, and how
  data reaches whoever wants it. RFC-0173 (Tally on the web) is a client of the result.

**Three words** (founder, 2026-10-06). This RFC, RFC-0171 and the site use exactly three words for
the network's roles. A **feeder** is a receiver that sends what it hears: a radio receiver at
someone's home and the small program that timestamps, signs and sends its receptions. A **relay**
is the one Tally server program: it collects feeders' data, computes positions (MLAT is a relay's
job) and shares with other relays; every duty in the network is a relay's. A **client** is anything
that reads Tally data (a website, an app, a map). A client never shares; its access is either the
free small tier or the credit of the relay it is linked to, so a company that wants the firehose
runs a relay and its clients read on that relay's credit (§2.1). "Node", "engine" and "consumer"
are not used for these roles. Two names in code are not roles: `tally-mlat` is the MLAT library
every relay links, and `Engine` is the wire role a relay's MLAT dials with to take raw one hop.

## §0 The answer, in one line

Every relay is the same program: it takes the areas it wants and shares what it takes; a feeder
sends to the two nearest healthy relays on different networks, nearest meaning inside a round-trip
band and then a shared per-area pick weighted by spare capacity; each area's MLAT is done by two or
three relays chosen by a shared rule, the others passing raw to them one hop; raw travels at most a
hop, only positions travel far, and everything spreads per area through striped sharing trees in
which forwarding one's slice is the duty of taking the area, under each relay's upload speed cap.

## §1 Where things stand (verified 2026-10-06)

- **A feeder multi-homes at random.** `tally/crates/feed/src/relays.rs` publishes every batch to
  `--relays` relays (default 4): a home relay the owner pins, an anchor kept across restarts and
  given up after seven days unreachable, and random slots chosen from up to 512 learned relays,
  given up after an hour. The feeder speaks wire version 1 (`MIN_VERSION = MAX_VERSION = 1`).
- **That scatters an area's receivers.** The distributed-systems critic's Monte Carlo: 200 relays,
  a transmission heard by 10 receivers, each receiver on its own random relays. Under 1% of
  transmissions had any one relay holding 4 receptions, the least MLAT can solve. No relay sees
  enough of an area to sync its clocks or fix an aircraft, so MLAT today works only because our
  own boxes all pin our relay.
- **RFC-0171 §3.6 described two classes,** regional relays feeding a few top relays, and separate
  MLAT programs (§3.8) subscribing to regions, without saying who runs a top relay or an MLAT
  program, or why. It now points here.
- **Every relay carries a required upload speed cap** (`--max-upload`, RFC-0171 §3.6,
  `tally/crates/relay/src/egress.rs`): one token bucket at the cap, strict priority classes
  (control, then positions and clock models, then raw to relay and MLAT links, then forwarded data,
  then provisional positions, then plain subscribers), and new feeders admitted only while the cap
  can carry what they commit the relay to forward. No bill can exceed the cap times the seconds in a
  month, and a relay never goes dark. It replaced the monthly egress budget built earlier the same
  day.
- **Final MLAT positions arrive 7 to 47 s late, 32 s on average.** A window solves eight bins at
  once and is solved once it has ended and settled (RFC-0171 §3.8.1: one bin after the last it
  solves, 2 s settling, then the fits); the stride is what lets one relay carry the world (§2.3).
  **Provisional ones arrive a median 1.34 s after the transmission** (95th percentile 1.65 s,
  in the simulator), built (§2.4).
- **A feeder uploads about 8 KB/s** (box-01, near KLAX, 7.9 KB/s measured 2026-10-06), about 21 GB
  a month.

## §2 Decisions

### §2.1 One role: a relay takes an area, shares it, and does its work

There is no regional relay, top relay or separate MLAT operator. A relay names the areas it wants, takes
them, shares them with whoever else wants them (§2.5), and, when it accepts feeders, runs MLAT for
them (§2.3). Whoever wants Georgia at scale runs a relay that takes Georgia.

Why: a class with no reason to exist is a class nobody runs. Whoever wants an area already pays to
receive it; making the same relay share it adds a bounded share of egress (its speed cap bounds it), and
turns everyone who reads at scale into capacity. The network then grows where demand is, with no one asked to
run infrastructure for others' sake.

**One program, relay duties on by default** (founder, 2026-10-06). The relay and its MLAT ship as
one program (`tally-relay` and `tally-mlat` as one binary and one deployment), with the relay
duties on unless the operator turns them off: accepting feeders, running MLAT for them, and
seeding their data to the area's sharing groups.

- **Accepting feeders is not mandatory; sharing is.** The requirement on every relay is §2.5's:
  a relay that takes an area forwards its slice of that area's sharing trees. Accepting feeders,
  running an area's MLAT and seeding fresh data are what earn a relay's clients firehose credit
  (below), so running a full relay is the easiest way to earn it, never the only one.
- **Why it is not mandatory.** Accepting feeders needs a publicly reachable port, which NAT,
  corporate firewalls and metered hosts deny. It costs MLAT CPU, and a hobby site that wants Georgia
  positions should not need cores. And a relay forced on someone who does not maintain it hurts
  feeders more than no relay: the delivery check (§2.2) catches it, but every catch is a feeder
  moving, which is churn.
- **Why bundle them.** Everyone who reads at scale runs a relay somewhere. With the duties on by default, each
  one becomes a nearby destination for the feeders around it (§2.2), and coverage spreads by itself
  as relays arrive.

**Firehose access is earned by a linked relay, on signed, portable evidence (founder,
2026-10-06).** A client never shares. Its access is either the free small tier (positions for an
area, with nothing but a connection) or the credit of the relay it is linked to: a client that
wants firehose-scale streams (raw, or positions beyond a small area) presents a credential signed
by a relay's key, "this client belongs to relay R", with an expiry, beside R's evidence. The
evidence is signed records anyone can check without a history of their own: the feeders' own signed
descriptions naming R as one of their relays, signed receipts from the members of R's sharing
trees for the stripe slices R delivered to them (§2.5). R's answers to delivery checks are not
evidence: they are R's word about itself, checkable only by a holder of the same batch, so a relay
with no feeders and no children earns nothing however many it gives. Any relay a client reaches checks the bundle and serves it in proportion to what the
evidence shows, so the credit travels with the client and no peer has to have watched R itself, and
no central score exists. A relay that hosts no feeders and forwards nothing has no evidence and
earns its clients nothing. Why: whoever wants a firehose is a business doing something with it, not
a hobbyist, so standing up a working relay is a fair price; and it solves the cold start, because
the network gains a relay exactly when it gains a serious client. A linked key rather than one
bundled process, so a relay can sit near its feeders while its clients run elsewhere, and one relay
can vouch for several clients.

- **Weighing.** A bundle is weighed record by record: a record that does not verify, is dated more
  than a minute ahead of the weigher's clock, or does not name R is skipped and the rest counts;
  the bundle's own signature and date are refused whole. A hosted feeder earns what seeding it
  costs (one copy plus parity, §2.5).
- **Vouching.** R's operator names the clients it vouches for (`tally-relay --client KEY`). On each
  of their sessions R signs a fresh 15-minute credential for every product, renewed every 10
  minutes, with its newest bundle. The client (`tally-api --key FILE --linked-relay
  HOST:PORT=KEY`) presents both before its `Subscribe` to every relay it reads, and accepts a pair
  only from its linked relay.

### §2.2 A feeder sends to two relays: the nearest healthy pair, on different networks

- **Two destinations.** A feeder publishes every batch to two relays at once, on different
  networks (different autonomous systems, as each relay's address and signed description say), so
  one outage or one dishonest relay cannot silence it. Both are chosen by the rule below; when one
  fails, refuses or redirects, the next relay in the same ranking takes its place.
- **Near is a band, measured, never claimed.** The feeder measures round-trip time to candidates
  (a small echo record, §2.10, median of several probes, repeated every few minutes, and at the
  reconnect backoff's pace while it holds no relay at all, so a feeder that boots beside its relay
  publishes as soon as the relay listens). A relay's
  advertised location only orders which relays to probe first, never where to send: a location is a
  claim anyone can fake, and a round-trip time cannot be faked downward. A few random known relays
  are probed every round as well, so a lying location cannot hide a close relay. The candidates are
  the healthy relays inside the band: the closest measured time plus half again, or plus 10 ms,
  whichever is larger.
- **Inside the band, one shared pick per area.** The feeder ranks the band's relays by weighted
  rendezvous hashing over its area (the H3 cell of its signed location at the area resolution) and
  each relay's key, weighted by the spare feeder capacity the relay declares in its signed
  description. Every feeder of an area that sees the same band computes the same ranking, so an
  area's feeders land on the same few relays without coordinating, which is what MLAT needs (§2.3),
  and load spreads by declared capacity rather than by who is a millisecond closer. The second
  destination is the highest-ranked relay on a network other than the first's.
- **Full relays redirect.** A relay whose cap cannot carry a new feeder's commitment answers
  `Redirect` before taking anything in (RFC-0171 §3.6); the feeder takes the next in its ranking.
  A redirect means only "leave me".
- **Hysteresis on the choice.** A feeder keeps its two relays while they stay healthy and inside
  the band. A relay that newly outranks one of them displaces it only after holding that rank and
  the band for three rounds in a row, and a relay leaves the band only after three rounds outside
  it. Near-equal times and a flapping newcomer therefore do not move an area's feeders back and
  forth, which would churn sessions and split them. A held relay the feeder's own probes fail to
  reach two rounds in a row is dropped, whatever its offer still says. A dead session fails over
  sooner: about 12 s when the host refuses the connection, about 2.5 min when it vanishes silently.
- **Delivery check, by proof and by majority.** Every key period (five minutes) the feeder gives
  every member of its area's sharing group (§2.5) that it may ask a tag key of that member's own:
  the key in force and the next, signed by the feeder, carried in a `DeliveryQuery` over a `Probe`
  session, on that schedule whether or not an audit runs. A member holding a key for a feeder tags
  each of its batches as it arrives (a keyed BLAKE2s of the key and the batch's signed bytes, 16
  bytes, with the key's id), keeps the tag five minutes (`TAG_WINDOW_MS`, the one window both sides
  use), and lets the bytes go (RFC-0181 §7). Every few minutes the feeder audits one of its two
  relays at a time: the next few batches go to that relay alone, and it asks several keyed members,
  on distinct networks, for their tags of those batches, named by boot and sequence, within the
  window; the answer is signed by the member's key and names the query's fresh nonce. The feeder
  keeps the audited batches' bytes and every key it gave, and recomputes each tag, so a proof binds
  the exact batch; a tag counts only under a key that was in force when the batch was sent, so one
  under an old key (a replay) proves nothing. A batch counts as delivered when a majority of the
  networks that said anything of it prove it. A sequence a member leaves out is no vote (a relay
  leaves out batches it took in with no key for their feeder, refused past its bound, or let go,
  and says nothing until it has watched a whole window); only a signed "not seen" counts against. An audit whose relay's session ends before the verdict says
  nothing of that relay. When the audit ends, any audited batch the audited relay was not written
  goes to the other relay, so an audit never costs the network a batch. No audit runs when the
  area has no members to ask. A relay whose batches
  fail that majority is switched away from and remembered as one that swallows (avoided for days,
  saved across restarts); one member's word alone convicts no one. The sample is a few tags, so
  the check costs bytes, not a stream, and the members learn nothing they do not already hold.
- **What happens to the slots.** The home, anchor and random slots go. An owner's `--relay` and the
  seeds join the candidates and are measured and ranked like any other. A production user that
  wants its own feeders' data gets it by taking their area (§2.1, §2.5), not by pinning. The cache
  of learned relays, the backoff, `RateLimit` and `Goodbye` are kept; `--home` and `--relays` are
  refused.
- **Why two, and why not at random.** Random multi-homing defended against one relay dropping a
  feeder's data, at the price of making MLAT impossible: it scattered an area's receivers across
  relays so no relay held enough of them (§1, under 1% of transmissions). One closest relay made
  MLAT possible but let one relay silence a feeder. Two relays from one shared per-area ranking keep
  an area's receivers together and keep every feeder heard through any single failure.
- **Ships as feeder protocol version 2, the minimum** (as built, 2026-10-07). Version 1 is
  retired before any feeder beyond Flightlines' own ran it, so a relay refuses a version 1
  `Hello` with `Goodbye{Version}` and RFC-0171 §3.3's forever rule starts at 2. A feeder's
  round-trip probes and delivery checks are `Probe` sessions (RFC-0171 §3.3), which take no feeder
  slot. A relay at capacity says so in its signed reply (no spare slot), and a relay already
  carrying the feeder keeps it however full. Target:
  v2 ships with adsb.im.
- **Distinct networks is one rule** (`tally_wire::rendezvous::distinct_networks`): two relays are
  on distinct networks only when the networks they declare differ AND the addresses the judging
  party observed them at are in different prefixes (/24 for IPv4, /48 for IPv6). A declaration is
  a claim anyone can make; an address alone misses one operator's two prefixes. Unknown on either
  side is never distinct. The feeder's two destinations and the members a delivery check asks are
  both chosen by it.

### §2.3 MLAT runs where the raw is, by two or three relays an area

Each area's MLAT (the RFC-0171 §3.8.1 engine: one shared clock model per canonical tile, the
reference implementation deterministic, every model and solution verifiable) is done by k relays,
two or three: the first of the relays offering MLAT cores for it (in their signed `ProviderOffer`,
§2.6), ranked first by contribution tier (the same tier the directory ranks offers by, §2.6) and
within a tier by weighted rendezvous hashing over the area and their keys, weighted by the cores
they offer (counted up to 64). Where no relay has shown a witness the cores decide alone, and a key
with no witness never displaces one that has. Every relay computes the same choice from the same
offers and evidence. A chosen relay takes the area's raw plus a
border band (as built: every cell within about 573 km of the area, plus the area's own radius;
the first text said one reception radius, about 400 km, which is a tile's radius alone, and a
band that narrow would leave every top-level tile unpublished, because a relay publishes a tile
only when it holds its whole footprint, which reaches half the tile cube's diagonal further; one
definition, `tally_mlat::area::border_band`, serves both the raw a relay asks for and the
receivers its MLAT lets take part); every other relay holding feeders of the area
passes their raw to the chosen ones, one hop, over the region-cut raw subscription
(`Subscribe { streams: RAW, regions }`, matched against the receiver's signed location). When a
chosen relay fails or withdraws its offer, the next in the ranking takes the area.

An `Engine` session is another relay's MLAT taking an area's raw one hop. It is accepted only from
a key whose offer the relay verified, granted raw only within the border band of the areas that key
solves by the ranking, never counted against the subscriber cap, and it publishes nothing: its
positions travel the sharing groups. It is granted the raw regions it asks for that lie within
the border band of the areas it is an MLAT relay for, and is held to a feeder's intake ceiling.

- Neighbours that cover a tile's whole footprint and hold the same raw publish the same model and
  solutions (byte-identical from the reference implementation; the protocol asks only that each be an
  optimum within the verifier's tolerance, and clients merge by inputs hash), which collapse.
  A relay publishes a tile only if its area covers the tile's whole footprint. Two or three solve
  each area so that one failure or one dishonest relay neither stops nor decides its positions;
  overlap costs compute, never correctness.
- What one relay costs, measured (RFC-0171 §3.8.1, the world-scale benchmark, re-measured at the
  real reception rate for RFC-0181): the whole world's MLAT, 20,000 receivers clustered as the US
  and Europe's are, about 320 wanted receptions a second each and about 5,400 targets a window,
  takes 41 cores to keep up (3,800 tile fits a 40 s stride, 0.35 s each, and the solves, on 32
  threads) and holds 8.7 GB of raw for a window (30 bytes an observation, index included), about
  12 GB with the open bins and the bins standing settles in. What a relay reserves for it is a bound,
  not that mean: `held::Rates::cost` reserves about 1.1 MB a receiver (open raw at five times the
  mean rate, and 25 sealed bins of thinned raw), 22.5 GB at 20,000 (RFC-0181 §5). One 32-core relay no longer carries the whole world; a 32-core relay carries about
  three quarters of it, and a 16-core relay about a third. (The 27 cores and 1.6 GB first
  measured were at an eighth of the real rate.)
- Raw travels at most a hop, never worldwide. Only positions travel far.
- Why here: clock sync needs every receiver that heard an aircraft in one place, and the raw is
  already at the relay its feeders chose. Moving the computation to the data is cheaper than any
  shape that moves the data or a summary of it (§3).

### §2.4 Fast MLAT: provisional positions now, the verified one after

Approved by the founder on 2026-10-06, and built (RFC-0171 §3.8.1, *Provisional positions*).
Beside the final positions (7 to 47 s late, 32 s on average), a relay publishes provisional
positions solved against the latest clock model of the transmission's tile carried forward: a
median 1.34 s after the transmission (1.65 s at the 95th percentile; 1.1 s of that is waiting for
the receptions, which a feeder's once-a-second batches spread over a second), a wider uncertainty
that says so (the clock covariance grown by the random-walk prior over the carry, at most 90 s;
calibrated in the simulator at 0.956, median error 123 m carried up to 20 s and 458 m from 45 to
90 s), at most one per aircraft per second. The final verified position follows and supersedes
it.

- A provisional position is its own stream, a `Streams` bit (`PROVISIONAL`, 16), in a record kind
  of its own (`Provisional`, 0x10, a `Positions` of format 4), so a subscriber that does not ask
  for it pays nothing and a reader that does not know it skips it. Subscribed, it about doubles the positions
  stream: there are as many provisionals as final solutions (one a target a second each), and a
  provisional record is no smaller per solution (measured, about 370 bytes); a whole-world relay
  publishes some 2 MB/s of them.
- A provisional position names the model it carried; how far is a function of the model and its
  receptions, so it is checkable against raw like any solution, and the same fault proof holds it.
  The merge rule ranks it below every final fix: superseded by a final fix of the same
  transmission, confirmed by a final fix of the aircraft near it in time, and retracted by a
  deadline rule (90 s, the client's clock, `tally_wire::products::FINAL_FIX_ARRIVED_MS`) when neither came; a client needs no message to learn
  it.
- Why: cockpit traffic awareness. At 150 kt an aircraft covers two and a half miles in 32 s; a
  target drawn where it was half a minute ago is drawn in the wrong place.

### §2.5 Distribution by area, like BitTorrent: sharing is a forwarding duty

Per area (an H3 cell) there is one sharing group per stream kind (raw; positions; provisional
positions; clock models): the relays that take that area.

- **Fixed seeding.** The relays that hold an area's feeders send each stream into the group once,
  cut into its data stripes, each to its stripe's seed, with a parity stripe beside them that
  rebuilds any one lost stripe: one copy and a third in all, however many want it. A popular area
  therefore does not raise its sources' egress.
- **Striped trees.** Each stream is cut into a few stripes (by record hash), and each stripe has
  its own forwarding tree over the group, ordered by rendezvous hashing over (area, stripe, relay).
  Each relay forwards its slice, the stripes in which it is an interior member, to its few children,
  and is a leaf in the others, so the forwarding load is spread across the group and no member
  carries a whole stream for everyone (the SplitStream shape).
- **A duty, not a score.** Taking an area is agreeing to forward one's slice of it. Children see a
  missing stripe at once; a member that does not forward is reported by the children it starves,
  each with the signed receipts it holds, and is dropped from the trees, so it receives the area only
  from the free tier. There is no byte ratio to game: a relay cannot earn membership by trading
  data back and forth with a friend, because membership is kept only by forwarding the slice the
  shared ordering assigned it.
- **Receipts are evidence.** A child signs a receipt for each stripe slice it received, which is
  what a relay's firehose credit is made of (§2.1).
- **The cap stays the ceiling.** A relay whose upload cap is full serves its priority classes in
  order (RFC-0171 §3.6) and, if it cannot carry its slice, says so by withdrawing from the stripe;
  the ordering's next member takes it. The cap bounds every bill, whatever the group asks. It
  withdraws a region it takes, one at a time and at most every 30 s, when its egress sheds a peer
  that forwards. The order is fixed by a rendezvous score over (region, relay key). Its offers for
  a withdrawn region say no stripes, so it is a leaf in every tree there. It takes the
  last-withdrawn region back after 10 minutes with no such shed.
- **Who is in a tree.** The trees are laid out over the members whose verified offers cover the
  area. A relay that only asked for stripes may send the group's records but is in no tree. Repair
  is answered only to a tree member that is not demoted, and its data is sent only over a member
  link, through the upload cap; a directory link is sent only the directory. A manifest is taken
  only from a member of the group, at most 8 per origin per second, and none for a second more
  than 60 s ahead of the reader's clock. A parity is checked against its manifest when used; a
  false one is dropped and a later one taken.
- **A relay's members are bounded** (as built, 2026-10-08). A relay holds at most the member
  sessions (sessions that bring another relay's data in: a member's link sending it what its
  groups address it, and its own one-hop raw links) its memory plan admits: every one its areas
  could bring, at most its connection cap (RFC-0181 §9). Nothing bounds how many relays share a
  group with one taking coarse areas (the 122 base cells reach every offer held, up to 16,384), so
  past its plan it turns a member's link away with a `Goodbye` of reason `Full`, the reason a full
  relay already gives a feeder; no new reason, so no reader needs a new version. The relay turned
  away takes it as "this provider is full" for every area and product it sends that member, never
  as a fault: for the wait the `Goodbye` names (60 s), doubled each time it is turned away again
  within the wait after the last (at most 30 minutes), it neither dials that member nor addresses
  it, and what the trees would have had it send that member goes to the next members by the trees'
  own order instead: down a stripe, to the full member's children there (and in place of one full
  too, to its children); a manifest, to those beneath it in every stripe; what was for it alone (a
  receipt, a have-summary, an ask) nowhere. The trees are not changed, so every relay still lays
  out the same ones and the area's data still reaches every member but the full one, which repairs
  what it lacks once it has room. A relay hosting MLAT takes a raw link's place in its own pool
  before it dials it, so it never dials a link it would turn away itself.
- **Relay links carry the directory; data moves over member links** (as built). A relay links to
  another relay in two ways. A directory link (`--upstream` dials one, `--accept-relay` lets a key
  dial in) carries the directory and nothing else: signed offers and queries, echoes, delivery
  checks and have-summaries; a record of data on it is not taken. Every record of data one relay
  passes another travels in an area's group (raw, positions, provisional positions, clock models,
  and the regional product's batches; a fault proof with what it is about) over member links, the
  sessions a relay dials to its groups' members, whose offers it verified by a handshake at the
  address each names; and an MLAT relay takes raw over its one-hop raw links (§2.3). So a relay
  joins with one directory link to any relay in the network and learns the rest from offers, and
  no link is a second, unstriped path for the data.
- **A member hears what a record depends on first** (as built). Records reach a member by
  address, striped over several trees, so nothing orders them the way one session does. Each
  member link therefore carries, before a record, what it depends on that the link has not yet
  carried: a batch's receiver's newest description, a clock model's parts just before its manifest
  (parts are in no group of their own), and every model a positions record cites. A relay that
  cannot place a receiver can neither solve its receptions nor pass its batches on, a manifest
  without its parts is no model, and a solution whose model has not come cannot be checked.
  What reaches a relay by another way (rebuilt from parity, or over a link that died between a
  record and what it depends on) still waits for it: the relay sends positions to its readers
  only after the models they cite (10 s at most), and its MLAT holds a batch whose receiver it
  has not had described yet until the description comes (60 s at most). A relay forwards each
  record once, so one turned away there would be lost for good.

### §2.6 The area tree is fixed; its providers are emergent

The tree is the H3 hierarchy: everyone agrees which cells compose which parent. Anyone who has
gathered every cell under a parent may offer the parent as a bundle, so a reader of a state, a
country or the world subscribes to one provider instead of hundreds of cells. Every level should
have several providers. Records inside a bundle keep their origin signatures, so bundling adds no
trust: a bundle is checked record by record exactly as its cells would be.

**The provider directory** (what relay offers which cell), as designed here:

- A relay announces a `ProviderOffer`: its key, its address, the cell, the stream kinds, and an
  expiry, signed by its key. It re-signs every minute while it serves, and an offer lives at most
  three minutes from its signing whatever it claims (one re-signing, a minute of clock skew and a
  minute to spread), so a dead relay leaves every relay's ranking within three minutes, for all
  alike. With relay duties off, a relay's offers do not include raw.
- Relays gossip offers the way they gossip `RelayList`, keep each until it expires, and hold at most
  32 offers per cell, at most 4 from one network. Within a cell, offers are held and answered by
  contribution tier first, then by rendezvous rank over (cell, key), never by arrival, so any two
  relays that hold the same evidence and offers lay out the same trees. The bounds on a flood (a
  network's offers anywhere, a key's, the directory's) are kept by rank too: a newcomer to a full
  one displaces the offer under it lowest by tier, then deepest in its own cell's ranking, or is
  refused. A held offer takes a change at most every ten seconds per key and cell (the newest
  waiting its turn), so a peer re-signing changes in a loop costs its readers what an honest
  relay's changes do. The tier is the bit length
  of the number of distinct networks whose relays, verified in the directory, signed receipts for
  what the relay delivered (§2.1's evidence, weighed by the one weigher); the relay's own network,
  feeder descriptions and claimed rates do not count, because feeder keys are free and one network
  could sign itself any rate. Keys are free too, so a ground key with no evidence ranks below every
  relay with evidence. Relays gossip their evidence bundles beside their offers. A relay asks any relay with `ProviderQuery { cell, streams }`
  and gets the offers it holds for that cell and its ancestors.
- An offer is a hint, never a promise. A reader tries several providers, keeps those that deliver
  valid, fresh, complete data for the cell (the same accounting as §2.5), and drops the rest on its
  own authority. A provider is ranked by what it delivered to this reader, never by what it
  claims. A provider that turns a relay away as full (`Goodbye` `Full`: it holds every member it
  plans, §2.5) is skipped for that relay for the wait it names, doubled on each refusal after, and
  the next provider by the same order takes its place; it is not demoted for it, and it is tried
  again once the wait has passed.

### §2.7 Blocked aircraft (LADD and PIA) are the displayer's duty

The protocol carries what receivers hear. Honouring LADD and PIA is the duty of whoever displays
the data; the Flightlines apps filter their own display. The founder's call (2026-10-06), and
consistent with RFC-0171 §6 (LADD binds FAA data-feed subscribers by contract, not relays of radio
receptions).

### §2.8 Costs, sourced

Prices: AWS Lightsail outbound is $0.09/GB beyond the plan's allowance (the $12 plan includes 3 TB;
aws.amazon.com/lightsail/pricing). Hetzner dedicated: "All root servers have a dedicated 1 GBit
uplink by default and with it unlimited traffic" (docs.hetzner.com/robot/general/traffic). The
feeder rate is measured (§1); everything else below is an estimate from it.

| User (estimates)            | Traffic a month        | Cost a month                                     |
| --------------------------- | ---------------------- | ------------------------------------------------ |
| Georgia positions           | well inside 3 TB       | about $12 (one Lightsail plan)                   |
| A region's raw client     | about 2 TB in, 2 TB out | about $100 on AWS (1 TB over), or flat-rate      |
| World positions             | about 4 TB in, 4 TB out | about $370 metered on AWS, about $45 flat-rate   |

Lightsail's 3 TB allowance counts traffic in both directions, though only outbound overage is
billed: so a relay taking 4 TB in has spent its allowance before it sends anything, and every byte it
sends is billed. That is why world positions cost about $370 there: 4 TB out at $90 a TB.

FlightAware Firehose (the founder's figure: $1,000 to $2,000 a month) is processed positions and
events, so it compares with world positions, not with raw. Every relay's required upload speed cap
bounds any bill whatever its peers ask.

### §2.9 Bootstrap

In the early days Flightlines runs the main relays (the public relay of RFC-0173 §2.6 first), cheap
under their caps, and takes every area so the first feeders have somewhere close to send. As other
relays take areas, they become closer for their feeders and the groups of §2.5 carry the rest.

### §2.10 New records

Non-critical kinds (RFC-0171 §3.4), all built, transport version 2, which is both `MIN_VERSION`
and `MAX_VERSION`: version 1 is retired, and a `Hello` whose highest version is 1 is answered with
`Goodbye{Version}`. Version 2's `Streams` is two bytes. A reader that does not know one of these
kinds skips it:

| Kind | Record | What it is |
| --- | --- | --- |
| 0x10 | `Provisional` | A provisional MLAT position (§2.4), with the `PROVISIONAL` bit on `Streams` (16). |
| 0x11, 0x12 | `Echo`, `EchoReply` | Round-trip measurement: a nonce; the reply signed, with the relay's spare capacity and network. |
| 0x13, 0x14 | retired | The first delivery check, a proof of possession over the feeder's nonce. Read as retired and never written; a relay answers an old query with `Goodbye{Retired}` (RFC-0181 §7). |
| 0x15, 0x16 | `ProviderOffer`, `ProviderQuery` | The directory (§2.6): cells, stripes, MLAT cores, address and network, signed. |
| 0x17 to 0x1a | `StripeAssignment`, `PieceManifest`, `HaveSummary`, `StripeReceipt` | Sharing groups (§2.5). |
| 0x1b, 0x1c | `FirehoseCredential`, `EvidenceBundle` | Credit (§2.1): the credential, and feeders' descriptions and children's receipts. |
| 0x1d | `WorldPositions` | The live world product (§2.11), the `WORLD` bit (64). |
| 0x1e | `RegionalBatch` | The regional product's deduplicated receptions, the `REGIONAL` bit (32). |
| 0x1f | `Parity` | A stripe's XOR parity slice, chunked under the body limit (§2.5), unsigned. |
| 0x20 | `BundleIndex` | A parent cell's bundle for one second: its children's digests, signed (§2.6). |
| 0x21 | `WorldPrecise` | The precise world product (§2.11), the `WORLD_PRECISE` bit (128). |
| 0x22, 0x23 | `DeliveryQuery`, `DeliveryAnswer` | The feeder's signed grant of tag keys to the member asked, and, in an audit, a nonce and a few batches named by boot and sequence; per batch, the member's tag made on arrival and its key's id, or "not seen", signed, answer format 2 (§2.2, RFC-0181 §7). Kinds of their own, not 0x13 and 0x14 read differently, so no build reads one form as the other. |

A batch may be compressed (format 2, raw DEFLATE, inflating at most 1 MiB and at most 8 times its
compressed stream, RFC-0171 §3.4); a feeder compresses whenever it shrinks the batch within that
rule, since every version 2 reader inflates it.

### §2.11 Two products: regional and world

- **Regional:** everything for one area, raw included (raw, positions, provisional positions and
  clock models), read from the area's sharing group. For researchers, local apps and the relays
  that cover the area.
- **World:** one position per aircraft per second, everywhere, thinned by one deterministic rule
  (`tally_wire::products::world_choice`) and offered at the top of the area tree (§2.6) by any
  relay that has gathered every area's positions (by taking every area: its groups bring it each
  area's positions and regional batches; a relay with `--world` or `--world-precise` refuses to
  start unless its areas cover the globe). As built (founder, 2026-10-07), in two feeds, each
  opt-in on the relay (`--world`, `--world-precise`), each its own record stream and `Streams` bit,
  shared, priced and served as separate products:
  - **World live** (`WorldPositions`, `WORLD`): sealed about 4 s after its second, an MLAT
    aircraft by its provisional fix until the final one arrives.
  - **World precise** (`WorldPrecise`, `WORLD_PRECISE`): the same rule sealed about 90 s after its
    second, once final fixes can arrive, an MLAT aircraft by its final fix only; ADS-B unchanged.
  - Each fix carries its pressure altitude and its MLAT flag, and names its origin by an index into
    a per-record origin table (each entry the origin record's hash and the key that signed it, so
    the choice rule's last ties, by source key and then record hash, are decided from the record
    alone; the measurement below predates the key, which adds 32 bytes an origin, not a fix).
    `world_choice` is a total order (transmit time, final over provisional, input set, source key,
    origin hash, index), so the fix chosen is the same in any arrival order. Measured over a synthetic world of 17,400 aircraft: 87.5 bytes a fix
    live (1.52 MB/s, 3.94 TB a month) and 89.9 bytes a fix precise. A relay rebuilds its world from
    the positions it receives; the sharing groups carry the areas, not the world records.
  - tally-api serves both (`/v1/aircraft?...&feed=precise`; its answer names the feed served and,
    for the precise feed, is as of the product's own second), and the site's map offers the choice
    (Live, or Precise, delayed), forwarded to the client core's reads. With no recent precise
    product, tally-api answers `503 {"error":"precise_unavailable"}` and the map says so.

### §2.12 Receiver standing, and a bigger answer wins only if it agrees

- **Receiver standing.** Every client and relay can compute, from public signed data alone, how
  well each receiver's receptions agree with the solutions that cite it (its residuals against
  verified fixes, by tile and over time). A receiver whose receptions keep agreeing gains weight;
  one that keeps disagreeing loses it. Standing ranks answers (below); it never decides what a
  solver includes. A solver leaves out only a reception that does not fit, by the specification's
  outlier rule, which the verifier applies the same way (it refuses a solution that omits a
  reception that fits), so a fake receiver either fits and changes nothing or does not and is left
  out. Standing is a function of the public record, read when a transmission's solutions are
  decided (never fixed when a solution arrives), and a transmission is settled
  `FINAL_FIX_ARRIVED_MS` after its transmit time; so every party that reads the same record
  computes the same standing and the same ranking, and a new key starts with none.
- **A bigger answer wins only if it agrees.** RFC-0171 §3.8.1's merge rule prefers the solution
  over the larger input set, and that preference holds only when the larger solution agrees with
  the smaller within the smaller's uncertainty (a chi-square test of the difference). A superset
  that disagrees is not a better answer but a sign that something in the added inputs is wrong: the
  smaller fix stands, both are kept as evidence, and the added receptions' standing pays for it. So
  a relay cannot override an honest fix by padding it with bad receptions.
- **Feeder figures and leaderboards are a client's, never the network's.** No relay computes,
  stores or vouches for a feeder's uptime, message rate, planes heard, range, unique coverage or
  MLAT help, and nothing in the protocol ranks feeders. tally.flightlines.ai, one client run by
  Flightlines, offers station pages and per-area leaderboards (`tally-api`, `GET
  /v1/stations/{key}/stats` and `/v1/leaderboards`), computed from the public signed records any
  client reads (receivers' batches and descriptions, and the final positions that cite their
  receptions), ranking by unique coverage and MLAT help, never raw message counts, and ranking
  only receivers with standing. MLAT help is credited only for fixes the API's merge accepted and
  receptions in the receiver's own signed raw, and a station's row comes only from its batches. Anyone reading the same records computes the same figures, and
  anyone may run boards of their own (founder, 2026-10-07).

## §3 What is killed, and why

1. **Relays share only position distributions, and readers multiply them.** Overconfident, because
   the leaves share receivers and sync data under multi-homing; a duplicate reception cannot be
   removed from an information matrix once added; and the linearisation is biased beyond 1 sigma
   when the aircraft is outside the receivers' hull, which is routine.
2. **Relays share corrected-time leaves for every transmission.** Correct only with split
   covariance intersection, gauge tie tables, and altitude applied exactly once; it still loses
   clock sync across relays and a degree of freedom per extra relay; and it costs more bytes than
   raw in dense regions (about 4 MB/s against about 2.4 MB/s of raw for one dense region).
3. **All relays gossip all raw.** Every relay holds the whole world's raw, the cost §2.3 exists to
   avoid.
4. **One designated responsible relay per area.** It needs a directory and is a single point of
   failure, and it is unnecessary: deterministic outputs let any number of relays cover an area and
   agree byte for byte.
5. **Multi-homing feeders to random relays** (today's slots, for MLAT purposes): it scatters an
   area's receivers so no relay can solve (§1, §2.2).
6. **One closest relay per feeder.** It made MLAT possible but let one relay silence a feeder, and
   it piled an area onto whichever relay was a millisecond closer (§2.2).
7. **Reciprocity as a byte ratio.** Two relays trading fresh data back and forth earn priority they
   never give the group, and "about what it downloads" cannot be measured by any one peer. Sharing
   is a forwarding duty in striped trees instead (§2.5).
8. **A monthly egress budget.** It goes dark near the end of its month, and a dark relay is
   indistinguishable from one that swallows data. A speed cap bounds the bill as hard and never goes
   dark (RFC-0171 §3.6).
9. **Choosing a relay by its claimed location.** A claim can be faked; round-trip time cannot be
   faked downward.
10. **Standalone MLAT engines publishing to relays.** MLAT is a relay's duty (§2.1); another
    relay's MLAT takes raw one hop and publishes nothing over that session (§2.3).
11. **A solver gating receivers by standing.** The verifier refuses a solution that omits a
    reception that fits, so a gate one solver applied alone would publish solutions every client
    refutes; the outlier rule already leaves out what does not fit (§2.12).
12. **Delivery answers as credit.** A relay's proofs of possession are its word about itself
    (§2.1).

## §4 Open questions, for the critics

1. **The provider directory and its abuse:** offer floods under many keys, offers for cells a relay
   does not hold, false MLAT capacity to win areas, and whether per-key and per-cell caps plus
   delivery-ranked choice and the k-of-ranking rule are enough.
2. **Bootstrap:** how the network moves from Flightlines running the main relays to many operators
   without a step where feeders crowd one relay.
3. **Declared capacity:** how a relay that declares more spare capacity than it has is caught
   before its redirects and failed delivery checks move its feeders.

## §5 Build steps

Steps 1 to 7 are built (2026-10-07); step 8 is adsb.im's. In order:

1. **The wire records** of §2.10, version 2 in `tally/crates/wire`, and relays answering echo and
   delivery queries.
2. **The v2 feeder:** round-trip probing, the band, the per-area weighted rendezvous pick of two
   relays on distinct networks with hysteresis and failover, the proof-and-majority delivery check
   and its saved memory of swallowing relays, the slots retired. (Version 1 since retired:
   version 2 is the minimum.)
3. **One program:** the relay and its MLAT as one binary with relay duties on by default and
   a switch to turn them off, taking areas, the per-area choice of k MLAT relays, and the one-hop
   raw to them over the region-cut subscription.
4. **Provisional positions** and the `PROVISIONAL` stream bit. Built (RFC-0171 §3.8.1).
5. **Sharing groups:** fixed seeding, striped forwarding trees, signed stripe receipts, dropping a
   member that does not forward, under the speed cap.
6. **The provider directory**, parent bundles and the world product (§2.11).
7. **Firehose credentials** and their evidence bundles (§2.1), and **receiver standing** with the
   agreeing-superset merge rule (§2.12).
8. **adsb.im ships the v2 feeder.**
