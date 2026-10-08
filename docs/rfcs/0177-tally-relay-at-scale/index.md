# RFC-0177: One relay carries 20,000 feeders

- Status: accepted (founder requirement 2026-10-07: one relay, one client, 20,000 feeders)
- Builds on: RFC-0171, RFC-0174


Requirement (founder): one relay, one client, 20,000 feeders. Per feeder ~600 receptions/s, ~8 KB/s,
one signed DEFLATE batch a second: 20k batches/s, 12M receptions/s, ~165 MB/s of batches.

Measured on main (tally-load, commit b3e3571809 on branch tally-load):
- 200 feeders: fine. 1,000: no loss, p99 217 ms, RSS 1.9 GiB climbing.
- 10,000: the client is cut repeatedly ("goodbye Full", fan-out ring 4096 records = 0.2 s), receives
  nothing; relay 4 GiB, 2.9 cores (lock-bound, not CPU-bound).
- Real-path microbenchmark: ingest flat at ~9k batches/s from 4 to 16 threads.

## Why (verified file:line, tally/crates)
- Everything per batch runs inline in the connection task (relay/src/link.rs:1083-1093 ->
  hub.rs:986-1024 -> network.rs:266-273) through ~7 process-wide std mutexes held in async tasks
  and global atomics touched per reception (hub.rs:408-420, products.rs:329-345, standing.rs:93).
- `products.tick` seals (Ed25519 + CPR) under the products lock for 285 ms (products.rs:476-630),
  blocking Tokio workers, so heartbeats and egress stall: the latency tail.
- Each batch is inflated/decoded 3-4 times (hub.rs:990, products.rs:340, standing.rs:90, mlat
  engine.rs:339-345 which also re-verifies the signature), `Batch` is a Vec<u8> (wire/src/batch.rs:149)
  cloned ~4 times, `Observation.data` a Vec<u8> per reception: ~50M allocations/s at 20k.
- Two dedups with the same job (hub.rs:386 Deduplicator, products.rs:511 offer_copy).
- Stores each keep their own copy with their own window and silent or wrong drops: standing Held
  1 GiB/120 s, drops silently (standing.rs:34,94); delivery 64 MiB = 0.4 s vs a ~52 s ask horizon
  (delivery.rs:30, feed/src/delivery_check.rs:68-72), so every audit is void; sharing member
  256 MiB (sharing/member.rs:68-70); MLAT engine MAX_RECEIVERS 16,384 < 20,000 (mlat/src/engine.rs:43).
- Held's byte accounting undercounts (mlat-solver/src/held.rs:259-264), seal is one single-threaded
  sort under a lock (held.rs:322-342).
- Per-connection Noise buffers ~200-320 KiB zeroed each (wire/src/noise.rs:288,329-330).
- Feeder keeps 512 whole sent batches though 4 are audited (feed/src/relays.rs:65,626-636).

## The shape

1. **Decode once.** `Batch` bytes become shared (`bytes::Bytes`). Ingest produces one immutable
   `Decoded` (receiver, boot, seq, wall, epoch, `stamp_ms` = ingest clock, `ingest_seq`, inflated
   `plain: Bytes`, `obs: Box<[ObsRef]>` with offsets into `plain` and ONE keyed 128-bit fingerprint per
   reception, the receiver's resolved place). Every consumer (hub stream, products, standing/MLAT,
   delivery, fan-out, BEAST out) takes `Arc<Decoded>`; nobody inflates, verifies or allocates per
   reception again. The relay-hosted MLAT engine never re-verifies.
2. **Ingest stage on a dedicated CPU pool**, not Tokio workers. Connection tasks do I/O only, with a
   credit of k=2 batches in flight per connection; out of credit, stop reading the socket (TCP
   pushes back; the feeder's signed `dropped` records its own loss). Workers: verify (Ed25519 batch
   verification), hash, admit (per-receiver sequence/dedup, owned by receiver shard), inflate, decode.
3. **Keyed exchanges, owned shards, no locks on the per-reception path.** Fixed logical shard count
   (e.g. 256) mapped onto threads; bounded queues per (producer, shard), carrying
   `(Arc<Decoded>, index ranges)` per batch, not per reception. Keys are uniform hashes only, never
   geography, so a dense area cannot make a hot shard:
   - `message` shard by fingerprint: the ONE dedup (hub stream + per-area first-heard), two
     generations swapped per window for O(1) expiry.
   - `raw` shard by receiver: open Held fragments, station counters.
   - `world`/`provisional` shard by ICAO address.
4. **Seal by watermark, off the hot path.** Ingest workers send `Tick(stamp)` down every queue; a
   shard closes epoch e when the minimum watermark passes it, by swapping its open buffer; frozen
   buffers go to a sealer pool. No lock is held across a seal. Regional products merge copies per area
   across message shards, sort canonically, sequence in cell order, sign. MLAT bins:
   `Bin::seal_from(fragments)` byte-equal to `Bin::seal` of one Held. World seals at
   watermark + WORLD_SETTLE_MS. Geography appears only here.

   As built: one sealer thread decides and a pool works. Each epoch's areas are cut into records that
   fit (`RegionalBatch::fits`, decided without signing; the sequence is a fixed-width field), the
   records are numbered in cell order by the one thread, then signed and their ADS-B fixes derived on
   as many threads as the message exchange has, and applied in sequence order by the one thread.
   Measured at 20,000 feeders before the pool: the single sealer thread held a whole core and fell
   behind (deriving the regional batches' ADS-B fixes was 70% of it, `to_observation` 20%, signing
   9%); after, the sealer thread is at 0.1 to 0.3 of a core.
5. **One Held per relay**, sealed bins `Arc`, shared by the MLAT engine and standing (standing reads
   sealed bins; raw later than settle is missing for both, consistently). Held stores open records per
   receiver (per-receiver sorts in parallel at seal), chunked storage (no doubling copies), byte
   accounting of what is really allocated. Standing is scoped to the areas this relay holds raw for and
   answers "unknown" outside them (decided: a relay cannot hold world raw, and relays are regional).
6. **One batch byte store**: shared `Bytes` keyed by (receiver, boot, seq); others hold handles.
   Window = the sharing repair horizon derived from sharing's own constants (~12-15 s), not 60 s.
   As built: the sharing member is that store. A group holds a batch as the `Batch` itself
   (`sharing::member::Piece`), so its bytes are the one allocation the hub, products and fan-out
   already hold a handle to; parity is built from and rebuilt into the same pieces. The horizon is
   `HORIZON_MS` = the receipt window (5 s) + its grace (4 s) + the judgment (2 s) + the repair delay
   (1.5 s) = 12.5 s, held as 13 whole seconds. The capacity is sized by time,
   `held_bytes_for(bytes_per_second)` = the admitted inflow over the horizon (default 20,000 x
   8 KiB/s, about 2 GiB; `Sharing::set_held_capacity` for the budget), and a record that would
   pass it is refused whole and counted (`Stats::refused`), never the oldest dropped to make room.
7. **Delivery proofs as tags made on arrival** (protocol change, v2 not yet shipped; decided): each
   round the feeder gives every member it may ask its own key k_m over the signed Probe session
   (current and next key overlapping, rotated); on arrival a member stores H(k_m || batch bytes)
   truncated to 16 B. Proof still needs the bytes and binds the exact batch; keys are per feeder, not
   per audit, so nothing reveals when an audit runs. Window W = 5 min, one shared constant. Feeder keeps
   (boot, seq, relay bitmask) for the window plus bytes only for audited/withheld ones.

   As built (`tally_wire::delivery`, `tally-relay`'s `delivery`, `tally-feed`'s `delivery_check`):
   - **The grant.** `TagKeys`, signed by the feeder, names the member, the key in force (its id is
     the key period, `wall_ms / KEY_PERIOD_MS`, five minutes) and the next, and how long until the
     next takes over by the member's clock. It rides in a `DeliveryQuery` (so a `Probe` session
     still sends only `Echo` and `DeliveryQuery`), every minute to any member of the area not yet
     given the current period's key, and again with every audit question. Signed, because the
     query is not: a key from anyone else would make every tag that member makes fail and void the
     feeder's audits. A member takes it only for a feeder of an area it takes, only addressed to
     itself, and never older than the keys it holds.
   - **The tag.** BLAKE2s-256 over a domain, k_m and the batch's signed bytes, first 16 bytes, with
     the key's id: `delivery_tag`. A member keeps an entry of 40 bytes (sequence, arrival, key id,
     tag) per batch for W, tagged or not, sharded by receiver under a process-secret hash. 20,000
     feeders at one batch a second: 6 M entries, 240 MB (`PER_FEEDER_BYTES` = 12 KB), bound at
     `TAGS_HELD` = 8 Mi entries (320 MiB); past it a batch is refused whole, counted, and never
     denied.
   - **The verdict.** The feeder recomputes the tag from its copy of the audited batch and the key
     it gave that member, and takes it only under a key in force when it sent the batch (its period
     or one either side, `tag_keys_for`). It keeps keys for the two periods before the current, so
     a tag under an older key (a replay, or a key a member kept past its rotation) proves nothing.
     It asks only about batches sent within `ASK_WITHIN_MS` (W less the longest ask), so the tag is
     still held. Majority and votes are unchanged: a network votes on a batch when a member of it
     proved it or signed "not seen".
   - **"Not seen" only when known.** A member says "not seen" only after it has watched for a whole
     window (since its first call: a restarted relay denies nothing for W) and holds no entry for
     the batch at or above its stream's horizon. A batch that came while it held no key for the
     feeder has an entry and no tag, and is left out, as is one refused or let go.
   - **The feeder's ledger.** Per batch first written within the window: (boot, sequence, first
     written, wall clock, a 16-bit relay mask over a slot table), 48 bytes, at most 1,024; a batch
     one of whose relays could not be named is never taken as the audited relay's alone. Bytes
     only of the latest audit's batches and of what an audit withheld or owes. At RFC-0177's 8 KB
     a second: before, 512 whole batches, about 4 MiB; after, about 13 KB of marks over the window
     plus 32 KB of audited bytes (at most 80 KB with the 1,024-mark cap).

   Why the alternatives fail:
   - **Holding whole batches for the window** (as before, `HELD_BYTES` 64 MiB): an audit asks up to
     W after sending, so the store must hold W of every feeder's bytes: 20,000 x 8 KB/s x 300 s is
     about 48 GB, and even the shortest useful window (the ~52 s an ask takes today) is ~8 GB. At
     64 MiB the store held 0.4 s, so every audit was void.
   - **A proof over the batch hash alone** (keyed hash of the nonce and the batch hash, so members
     could drop the bytes): every member already holds every batch hash, from the piece manifests
     its group floods, so a member that never received the batch (or a relay that swallowed it and
     forwarded only manifests) answers correctly. The tag must be over the bytes, and the key must be
     there when the bytes are, which is on arrival.
   - **Announcing the audit** (telling members ahead which batches to keep): a member that colludes
     with the audited relay tells it which batches matter; it delivers those and swallows the rest.
     Keys handed out on a schedule of their own, per member, say nothing of when an audit runs or
     what it covers.
   - **Keys that never rotate**: a member that once held a key can tag bytes it obtains at any
     later time; rotation bounds that to the batch's own period and its neighbours.
8. **Fan-out**: replace the 4096-record broadcast with a router keyed by subscription cell into
   per-subscriber queues bounded in BYTES and TIME (L = 2 s of inbound); a full queue disconnects with a
   Goodbye that says "fell behind" (not "full"). Fed per receiver shard: per-receiver order holds,
   description before first batch.
9. **Capacity is admission, never a silent drop inside a store.** Each store's per-feeder bytes are
   reserved when a feeder is admitted, in the same headroom check RFC-0171 uses for egress; the feeder
   ceiling is derived from RAM and those formulas; Hello beyond it is refused ("no spare slot"). MLAT
   receiver limit comes from the same F (>= 20,000). Any leftover overflow is counted, published, and
   refused whole (a whole receiver, bin, area or second), never partially in an interleaving-dependent
   way. `Added.dropped` is never discarded.

   As built (`tally-relay`'s `budget`): every store and every queue whose size grows with what feeders
   send is a `Store`, with a per-feeder cost over its own window, reserved at admission: the batch
   byte store, `Held`, the fingerprints (as if every reception were new, with the tables' room to
   double), the fan-out, the delivery tags, the ingest stage's credit, the epochs' decoded batches
   between ingest and the sealer (`seal::EPOCHS_HELD`, 3 epochs), and what the products hold until
   the hub takes it (`products::OUTBOX_EPOCHS`, 2). Each store has a gauge whose limit is its share
   at the ceiling, charged for what the store really holds and released when it lets go (a decoded
   batch by `Decoded::footprint`, a record by `Record::encoded_len`, the one size of either). What
   a full gauge does is the store's policy: the ingest stage waits (the connection's socket unread);
   an epoch past its share is refused whole by the message thread that holds it, and the sealer
   counts it; the products refuse an epoch's records or stream whole, and a peer's record alone; the
   fan-out lets go the subscriber holding most until the item fits. A sharing member reserves the
   feeders its ingest ceiling is worth (`--max-member-bytes-per-sec` over a planned feeder's rate)
   for as long as it is a member. A relay whose memory admits no feeder refuses to start
   (`Budget::check`), and the deployed units are held to the budget by a test
   (`//tally/crates/relay:deployed`). The gauges are served on `GET /memory`.

   Why (measured 2026-10-08, 20,000 feeders on one 32-core host): the relay's resident memory grew
   about 330 MB/s, unbounded, to 18 GB in 160 s. It was decoded batches: the sealer's queue was
   bounded by count (4,096 commands), and each command was a whole epoch's part from one message
   thread, so the queue could hold some 500 seconds of every batch; the one sealer thread could not
   keep up, and 2.2 M decoded batches (18.6 GB) waited in it. With the gauges and the sealer pool:
   2.3 GB resident at 20,000 feeders, flat.

10. **Overload policy (decided)**: back-pressure for raw, delivery and fan-out; whole-epoch refusal,
    counted, for derived products.
11. **Connection buffers from a shared pool**, not zeroed 64 KiB per connection. As built
    (`tally_wire::noise::Buffer`): a session's reader and writer hold no buffer between messages.
    A message's frame, its plaintext and the records packed into it are written in buffers taken
    from one process-wide pool while that message is in hand, and given back after; the pool keeps
    at most `POOL_IDLE` (256) idle, 16 MiB. Per connection idle: before, two zeroed 64 KiB buffers
    and a writer plaintext that fills to 64 KiB, about 192 KiB resident, plus a fresh frame
    allocation per message; after, the two halves (under 1 KiB) and the transport state, with
    buffers only for messages in flight.

## Invariants the tests hold
1. Thread-count independence: same stamped trace at 1, 2, 8, 32 threads gives byte-identical MLAT
   models, positions, provisionals, world/precise parts, standing, regional record sequence.
2. No consumer reads a clock: decisions use `stamp_ms`; injected queue delays change nothing.
3. MLAT/world output unchanged under permutation and duplication between two watermarks.
4. `Bin::seal_from(fragments)` byte-equal to `Bin::seal` for any split by receiver.
5. Dedup across shards exact: a message via k receivers on k workers is gathered once per window.
6. Per (receiver, boot) admitted order to every subscriber; description first.
7. Loss only at named places, counted per epoch, whole.
8. RSS within the admission budget at 20k for 10 minutes; per-store byte accounting tests.
9. No lock across a seal: ingest p99 flat with a sealer slowed to 1 s.
10. Throughput scales ~linearly with cores; 20k feeders sustain 20k batches/s at target p99 in tally-load.

## Sizing at 20k (critics' estimate; measured below)
~12-13 GB RAM (batch store ~2.4 GB, Held ~8 GB, dedup ~0.6 GB, fan-out ~0.33 GB, buffers ~0.3 GB) and
~35-40 cores (27 MLAT fits, 8-10 verify/inflate/ingest/dedup).

Measured (2026-10-08, `tally-load`, 20,000 feeders, the relay alone on 10 cores, `--memory 14G`, no
hosted MLAT): 586 kB reserved a feeder (the fingerprints' worst case is 178 kB of it), so 14 GiB
admits 23,781; 6.3 cores mean, 7.4 peak; 2.3 GB resident, flat. The feeders and the client ran as
their own processes on other cores: run in one process beside the relay, 20,000 simulated feeders
take some 19 cores and starve the client's one read task, which then falls behind and is let go.
