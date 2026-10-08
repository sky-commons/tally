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
5. **One Held per relay**, sealed bins `Arc`, shared by the MLAT engine and standing (standing reads
   sealed bins; raw later than settle is missing for both, consistently). Held stores open records per
   receiver (per-receiver sorts in parallel at seal), chunked storage (no doubling copies), byte
   accounting of what is really allocated. Standing is scoped to the areas this relay holds raw for and
   answers "unknown" outside them (decided: a relay cannot hold world raw, and relays are regional).
6. **One batch byte store**: shared `Bytes` keyed by (receiver, boot, seq); others hold handles.
   Window = the sharing repair horizon derived from sharing's own constants (~12-15 s), not 60 s.
7. **Delivery proofs as tags made on arrival** (protocol change, v2 not yet shipped; decided): each
   round the feeder gives every member it may ask its own key k_m over the signed Probe session
   (current and next key overlapping, rotated); on arrival a member stores H(k_m || batch bytes)
   truncated to 16 B. Proof still needs the bytes and binds the exact batch; keys are per feeder, not
   per audit, so nothing reveals when an audit runs. Window W = 5 min, one shared constant. Feeder keeps
   (boot, seq, relay bitmask) for 512 batches plus bytes only for audited/withheld ones.
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
10. **Overload policy (decided)**: back-pressure for raw, delivery and fan-out; whole-epoch refusal,
    counted, for derived products.
11. **Connection buffers from a shared pool**, not zeroed 64 KiB per connection.

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

## Sizing at 20k (critics' estimate, to be measured)
~12-13 GB RAM (batch store ~2.4 GB, Held ~8 GB, dedup ~0.6 GB, fan-out ~0.33 GB, buffers ~0.3 GB) and
~35-40 cores (27 MLAT fits, 8-10 verify/inflate/ingest/dedup).
