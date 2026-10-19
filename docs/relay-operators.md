# Rules for relay operators

These are the network's rules for anyone who runs a Tally relay. Following them is the condition
for being listed in a release's seed list (`packaging/seeds`), the relays a new feeder starts from.
That listing is the only lever the project has: it cannot stop anyone from running a relay, and it
does not try to.

## Receiver locations

A feeder signs its receiver's exact location into its own description, because MLAT needs it:
solving a position from arrival times needs each receiver's place to a few metres (RFC-0171 §3.5,
§8.3). That exact location travels inside the feed, in the signed records relays carry to one
another and to the clients they serve, and it is for MLAT.

**A relay that publishes receiver locations on a public surface (a website, an open API, a map,
a download) MUST publish them blurred to about 5 km, never exact.** "Public" is anything shown to
people who are not the feeder: a station page, a list of stations, a coverage or receiver map, a
leaderboard. A figure that places a receiver (its area, its range) is computed from the blurred
location, not the exact one.

The blur must be deterministic: the same receiver gets the same blurred location on every read.
Fresh random jitter on each request does not count, because averaging many reads recovers the
exact place.

### What the software does by default

- `tally-api`, the open API a relay operator runs beside the relay (and the site at
  tally.flightlines.ai reads), serves every receiver location blurred. Each one is pinned inside
  the 0.05 degree cell (about 5.6 km tall and as wide) that holds the declared place, at an offset
  the receiver's key fixes, the same on every read, the way wiedehopf's mlat-server blurs its public
  receiver pins. The key is public, so the offset can be undone; what is left is the cell, about
  5 km, and nothing finer. The API holds no exact location after reading it, and its area and range
  figures are computed from the pin (`crates/api/src/privacy.rs`).
- `tally-relay --stats-listen` serves exact locations, for `tally-api` to read. It is
  unauthenticated and is not a public surface: bind it to loopback, as the README says. Exposing it
  publicly breaks this rule.

An operator who builds their own website, map or API over the feed must blur the same way.

### What this rule cannot bind

Be clear about the limit. Feeders dedicate their receptions to the public domain under CC0, and
what relays publish downstream is under the ODbL (README "Licences", RFC-0171 §8.2). The exact
location is inside the signed descriptions that travel with the feed, and anyone who runs a relay,
or reads raw through one, receives it. CC0 waives every right a licence could hold back, so a
reuser of the feed may legally republish exact locations, and the ODbL's share-alike terms do not
require blurring either. This rule is a condition of the seed list, not a term of the data's
licence; it binds only operators who want to be listed, and the project can enforce it only by
leaving a relay out of the list.

So a feeder should treat its exact location as reachable by anyone who reads the feed, as the
installer says. A receiver's exact location is personal data under the GDPR (RFC-0171 §6), and
whoever republishes it is answerable for that under their own law; neither licence changes that.
The feeder's precision setting is meant to let an owner round the location it signs, at a cost to
MLAT (RFC-0171 §8.3); tally-feed 0.3.0 sends the exact location beside that setting and rounds
nothing, so until a release fixes that, the only way to keep an exact place out of the feed is to
enter a rounded one.
