# RFC-0184: The live feed is pushed, and every position says when it was heard

Status: accepted, in progress (2026-10-12)

## Why

The public API's live feed is how anyone sees that Tally is live. Measured on 2026-10-12 against
`tally-api.flightlines.ai`, a position reached a browser about 2.2 s after the radio message on
average and up to 4.6 s, then waited up to 2 s more for the next poll:

| Stage | Delay |
| --- | --- |
| Feeder seals a batch (`SEAL_EVERY`) | 0 to 1000 ms |
| readsb rebuilds its answer (`--write-json-every 1`) | 0 to 1000 ms |
| API and tunnel, per request | 240 to 570 ms |
| Edge cache (`max-age=2`) | 0 to 2000 ms |
| Client poll | every 2 s |

Worse, `last_heard_at_ms` was readsb's `seen` (the last message of any kind), so a velocity or
altitude message made an old position look new: 27% of updates of moving aircraft re-stamped an
unchanged position, and a client projecting from it pulled the aircraft back (225 m typical,
6.3 km at worst). Every position was labelled `adsb` whatever readsb said, and an MLAT position
had no speed or track, so a client could not move it between fixes.

## What changes

1. **Every position carries its own time.** `Aircraft::position_at_ms` is readsb's `seen_pos` (for
   MLAT, the transmission's time); `last_heard_at_ms` stays the last message of any kind. A client
   projects from `position_at_ms` only.
2. **Every answer says when it was sent.** `sent_at_ms` on `AircraftResponse` and on each stream
   event, so a client measures its clock offset (the least receipt-minus-sent it has seen) and
   ages a position by its own clock, with transit, cache and queueing counted rather than hidden.
3. **The source is readsb's own.** `PositionSource` is `adsb`, `mlat` (Tally MLAT), `adsr`, `tisb`
   or `other`, from readsb's `type`. `Network::aircraft_by_source` counts them, and `aircraft`
   now includes the aircraft only MLAT places.
4. **An MLAT aircraft moves.** The API derives its ground speed and track from its last two fixes
   of the same aircraft (at least 1 s and at most 60 s apart, both standing), so a client can
   project it like any other.
5. **The live feed is pushed.** `GET /v1/aircraft/stream` (same query as `/v1/aircraft`) answers
   Server-Sent Events: an `aircraft` event whose data is an `AircraftUpdate`, `full` first, then
   the changed aircraft and the `gone` addresses at most every 250 ms, and a comment every 15 s
   while nothing changes (the edge closes an idle stream at about 100 s). The API reads readsb
   once per tick for every open stream (one read shared, not one per viewer), streams sit outside
   the request timeout and the in-flight limit, and one address holds at most 4 open streams. It
   is `Cache-Control: no-store`. `/v1/aircraft` stays, for clients that poll.
6. **Faster upstream.** The feeder seals at most every 250 ms (it already seals early at 48 KiB),
   and the API's readsb writes its answer every 200 ms. A batch's fixed cost is 172 bytes and one
   Ed25519 verification, so four a second per feeder is 688 bytes a second and four
   verifications: the relay's memory plan charges receptions, not batches, and is unchanged.

## What a client gets

From radio to the API's answer: about 125 ms (seal) plus 100 ms (readsb) plus transit on
average, under half a second. The stream adds no cache and no poll. A client that renders at
display rate, projects each position from `position_at_ms` and blends corrections (rather than
snapping) shows the network as it is heard.

## Cost

A stream cannot be cached, so the API's egress grows with viewers: about 50 aircraft changing
four times a second is under 10 KB/s per viewer, and changes only are sent. The per-address cap
and the shared read keep a crowd from costing more than its bandwidth.
