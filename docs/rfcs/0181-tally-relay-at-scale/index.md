# RFC-0181: One relay carries 20,000 feeders

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
   reception). Every consumer (hub stream, products, standing/MLAT, delivery, fan-out, BEAST out) takes
   `Arc<Decoded>`; nobody inflates or verifies again. The relay-hosted MLAT engine never re-verifies.

   As built (`tally_wire::Decoded`): there is no place field. A receiver's place is held, with its
   admission and station counters, by the ingest worker that owns its raw shard (`exchange`, the raw
   exchange), and a stage that places a reception reads it there. The signer's key is decompressed
   once, when the batch is read (`Batch::from_bytes`), and kept; there is no call that checks a key
   and decompresses it again. The regional products are signed from the receptions where their batches
   hold them (`RegionalBatch::sign_draft`, one encoder for a borrowed or an owned reception), so a
   regional record copies nothing, and so is the relay's deduplicated stream
   (`Batch::sign_relay_draft`): the sealer signs each epoch's stream in its pool while it still holds
   the epoch's batches (§4), so no kept reception is ever copied out of its batch.
2. **Ingest stage on a dedicated CPU pool**, not Tokio workers. Connection tasks do I/O only, each
   within an allowance of bytes in flight carved for it when it is admitted (`ingest::Allowance`,
   from `Store::Ingest`); with its allowance held, it stops reading the socket (TCP pushes back; the
   feeder's signed `dropped` records its own loss). Workers: verify, hash, admit (per-receiver
   sequence/dedup, owned by receiver shard), inflate, decode.

   As built: the allowance is counted in bytes as a batch is charged (`ingest::charge_of`: signed,
   inflated and referenced), never in batches, so a peer sending 64 KiB batches holds no more than
   one sending 8 KiB ones. A feeder's is `ingest::FEEDER_ALLOWANCE`, `CREDIT` (2) planned batches'
   charge, which its reservation planned (`PerFeeder::ingest`); a member session's is the same, from
   the members' pool (`Plan::per_member`), since what it forwards arrives as feeders' batches. A
   batch larger than its connection's whole allowance waits until the connection holds nothing and
   takes the rest from one oversize room shared by every connection (`ingest::OVERSIZE_BYTES`, 64
   MiB), planned in the budget beside the base (`Plan::oversize`). The charge travels with the batch
   until the next store holds its bytes, so the allowance is released only then.

   As built: a charge borrows only its own bytes of the carve (`ingest::Lent`): while the
   connection is open they go back to its carve when the charge is let go, and once it has ended
   they go back to `Store::Ingest`; the rest of the carve goes back the moment the connection ends.
   So whatever still holds a decode after its connection (orphans for 3 s, a subscriber's queue,
   the notes, the exchange's held parts) holds the bytes it is charged and no more. Before, every
   charge held the whole carve (some 68 KB for a feeder) until the last of them was let go: after
   a network blip at the ceiling every reconnect was turned away for want of room for its
   allowance until the old carves drained, and a peer reconnecting in a loop could force it.

   As built: a connection's records are paced as well as its bytes (`ingest::RecordPace`, R-N12).
   A record costs an ingest worker a strict verification whatever its size, so the allowance in
   bytes bounds how many records wait at once (`RECORDS_IN_FLIGHT`) but not how many a second: a
   feeder sending tiny batches within its 256 KiB/s was some 870 verifications a second, and a few
   dozen such feeders took every worker. A feeder's records a second are its byte ceiling over
   `RECORD_BYTES` (32 KiB: eight at the default, where an honest feeder sends at most five), a
   member session's are the feeders the members' shared rate is worth at
   `MEMBER_RECORDS_PER_FEEDER` (4) each, shared by every member session. Past its pace the read
   loop waits before it takes the next record, its socket unread, as it does with its allowance
   held: the sender is slowed, never refused. The cores plan it (§10, "The cores"): each record
   costs `INGEST_NANOS_PER_RECORD` (30 us, measured 24 to 25 us to verify, hash and decode a tiny
   batch), and a feeder's ingest load is the more of its planned receptions and its records a
   second at that cost (`cores::Source`), so the ingest threads and the feeders the cores carry
   follow `--max-feeder-bytes-per-sec`.

   As built: a connection that overruns its byte ceiling is ended with `Reason::OverCeiling`, the
   sender's abuse; `Reason::Full` says only this relay's capacity, at a member's admission. Only a
   `Full` excuses the relay told so from its shortfalls (a dialler routes around a full provider).
   Before, an overrun was told `Full` too, so a hostile parent that overran each child's ceiling
   delivered nothing, was excused as full, and its children's own children reported them short.

   As built: each signature is verified strictly, one at a time, never by Ed25519 batch
   verification. A batch equation accepts some signatures strict verification refuses (a torsion
   component in `R` passes it one time in eight), and every reader of a relay's stream verifies
   strictly, so a relay that verified in batches could be made to forward what its readers reject.
   What batching would have saved is mostly the key's decompression, and that is done once per batch
   (§1).
3. **Keyed exchanges, owned shards, no locks on the per-reception path.** Fixed logical shard count
   (256) mapped onto threads; bounded queues carrying `(Arc<Decoded>, index ranges)` per batch, not
   per reception. Keys are uniform hashes only, never geography, so a dense area cannot make a hot
   shard:
   - `message` shard by fingerprint: the ONE dedup (hub stream + per-area first-heard), generations
     swapped per epoch for O(1) expiry.
   - `raw` shard by receiver: open Held fragments, station counters.
   - `world`/`provisional` shard by ICAO address.

   As built: the two keys a peer chooses, a receiver's key and an aircraft's address, are hashed
   under a secret of the relay's process (`FingerprintKey::process`, each in its own domain listed
   once in `tally_wire::decoded::keyed`), so no feeder can grind keys or report addresses that land
   in one shard and evict the honest entries there. The per-receiver tables that remember streams
   (the hub's sequence windows, delivery's tags) hold at most four boots a receiver
   (`BOOTS_PER_AUTHOR`), so a feeder churning boot ids forgets only its own streams.

   As built (`exchange`): one bounded queue per thread, shared by every producer that sends to it
   (`QUEUE_SLICES` slices per producer), not one per (producer, shard): a producer sends each thread
   one slice per batch covering every shard that thread owns, so a queue per shard would multiply the
   sends by the shards a thread owns and buy no ordering the watermark does not already give. A
   producer that finds a queue full waits, its batches' charges still held against their connections'
   allowances, so those connections' sockets stay unread: the back-pressure raw meets (§10).

   The dedup window changed with the epochs, and is now stated (`DEDUP_WINDOW_MS`, 2 s): a copy of
   a message stamped up to 2 s after the copy kept is never kept again. The deduplication before the
   stages held two 2 s generations (a copy was caught 2 to 4 s after the first); the first cut of the
   exchange held one 1 s epoch and the one before, so a copy a feeder's network or a relay's queue
   held back a second or more was kept again (at 20,000 feeders the stream carried 77,000 receptions a
   second where 42,000 were messages). It holds `DEDUP_GENERATIONS` = 3 one-second generations, each
   reserved at admission as if every reception were new.

   Batches are ordered canonically: by stamp, then by the batch itself (receiver, boot, sequence;
   `seal::canonical`), never by `ingest_seq`, the order the workers happened to take them in. Which
   copy of a message is kept, and so the stream's and the regional products' bytes, follows the
   stamps and the batches alone.
4. **Seal by watermark, off the hot path.** Ingest workers send `Tick(stamp)` down every queue; a
   shard closes epoch e when the minimum watermark passes it, by swapping its open buffer; frozen
   buffers go to a sealer pool. No lock is held across a seal. Regional products merge copies per area
   across message shards, sort canonically, sequence in cell order, sign. MLAT bins:
   `Bin::seal_from(fragments)` byte-equal to `Bin::seal` of one Held. World seals at
   watermark + WORLD_SETTLE_MS. Geography appears only here.

   As built: one sealer thread decides and a pool works. Each epoch's areas are cut into records that
   fit (`RegionalBatch::fits`, decided without signing; the sequence is a fixed-width field), the
   records are numbered in cell order by the one thread, then signed and their ADS-B fixes derived on
   as many threads as the load planned needs (§10, "The cores"), and applied in sequence order by
   the one thread.
   The deduplicated stream is signed in the same pool, one job beside the areas' cuts: its hash chain
   makes its batches one sequence, so one job signs them all in canonical order
   (`deduplicated::Stream::sign`), each batch timed the epoch's end as the regional records are, and
   its batches go out first among the epoch's records. Before this it was gathered as owned copies
   for a signer that ran once a second on the wall clock; now the same stamped batches sign the same
   stream bytes on any number of threads, as the regional products' do.
   Records that are not epochs (positions, clock models, peers' world and regional records) wait in
   a queue of their own (`products::Records`), and the peers' regional batches to forward beside
   it, held by a store of their own, `Store::Records`, planned per feeder
   (`products::records_per_feeder`) apart from what the sealer signs (`Store::Products`); the count
   it once kept beside a gauge, `RECORDS_HELD`, is gone (§9). So a flood of peers' records fills
   their own share and refuses records, counted, never an epoch: before, both waited on the
   products' one gauge, and a flood made the sealer refuse whole epochs of its own outputs. Before sealing an epoch or advancing the watermark the sealer
   takes in every record stamped before it, sorted by stamp then hash; a record handed in later is
   stamped no earlier than what was already taken. A slice that reaches its thread after its epoch
   closed is dropped and counted (`receptions_late`), never merged into a later epoch.

   The hosted MLAT steps on the same watermark: once per `STEP_MS` grid point the products'
   watermark passes, in order. Its raw is late by its stamp (raw stamped at or after the step that
   takes its bin is late, whenever it arrived), and never ahead of it: raw of a bin that begins more
   than `held::AHEAD_MS` (1 s) past its batch's stamp is refused and counted, so no bin opens that
   the steps never reach (a receiver stamping its batches in the future once held its open raw for
   ever and filled the store every honest receiver's is charged to). Every way into a holder of
   raw takes the stamp, so every holder refuses the same raw ahead of it: before, only a holder
   built to close by the stamp checked, and the reference engine (`tally_mlat::replay`) kept raw
   the hosted one refused. Provisional solving weighs a
   step's notes in content order. What batches tell provisional solving is held until the step that
   weighs it has read it, charged to its own store (`Store::Notes`) before it is held.

   A receiver's description is stamped too, by the watermark when the relay keeps it (never before
   one the host was asked with), and takes effect at the step after its stamp, applied as the
   watermark passes that step, before anything of the step runs, in the order of the descriptions'
   stamps and keys, of each receiver only the newest it signed for that step
   (`intake::taking_effect`, by `issued_ms` then bytes, the reference drive's rule too): the host
   holds one description a receiver a step, charged, so a receiver re-signing in a loop holds one,
   and an older description never applies after a newer one. A batch is taken as its receiver
   stood when its step interval began: one stamped in an interval whose descriptions are not yet
   applied waits until they are; one of a receiver not described waits for its description
   (`intake::Orphans`, one for every raw shard, let go by the steps after `intake::ORPHAN_MS`, 3 s)
   and is taken as the last thing of the interval before the step that applies it: its notes
   weighed at that step, its raw judged ahead or late by its own stamp, as the reference engine
   judges it (before, by the stamp of the step that took it, so a feeder 1 to 4 s fast had raw the
   reference refused kept by the host). Both wait in `Store::Orphans`, split whole in two shares
   (`mlat_host::Room`): the batches waiting for a description that has not come, held by rank (the
   best drawn receivers of those that came, a seat's share each, its oldest going first), so who
   is held never depends on arrival and the share is never charged past; and what waits for a
   step's descriptions, batches and descriptions, over `mlat_host::WAITING_MS` (the epochs held
   ahead of the watermark and a step), which only a host behind on its watermark passes, held the
   same way (`mlat_host::WaitingRoom`: a seat's share each, the best drawn receivers of those that
   came), its excess let go and counted (`waiting_dropped`). Before, both were charged to one gauge
   in arrival order, and then what waits for a step's descriptions was one pool refused batch by
   batch as they came, so which batch a full store dropped was thread timing. A receiver that stops taking part keeps its raw in the
   bins the steps already due take, and is forgotten in every sealed bin at its step, a bin still
   being sealed then included once it is held (before, a seal in flight when the receiver left kept
   it), every receiver one change let go forgotten together, each bin re-sealed once for all of
   them, bin by bin, each charged to `Held` before it is built (one there is no room to re-seal is
   forgotten whole, its records counted refused); a window step fits with the sites its step's
   descriptions left. Before,
   a description took effect when it arrived, before or after a window step, so a seat that changed
   midway made different bytes by thread timing; `staged_mlat` now holds the bytes with a receiver
   described again midway and one described first midway, with delays inside every stage, and the
   reference drive (`tally_mlat::replay`) applies descriptions the same way. As built, a relay
   stamps a description by its products' watermark when the hub keeps it; a description the hub
   kept is not routed through the ingest stage's stamps, so how the same trace's descriptions fall
   against its batches depends on that watermark when the hub kept them.

   Every step the watermark passes is sealed in its turn, whatever the window steps are doing;
   window steps and provisional steps run apart, each kind one at a time and in order: a window
   step's fits take seconds, and a provisional step waiting behind them came too late for the live
   world. MLAT's work runs on three runners started with the host (seals and forgets, window
   steps, provisional steps), each a thread for the host's life at its priority below the stages,
   so no piece of it ever needs a thread it may not get (before, a step whose thread could not be
   spawned ran on the engine's thread, ungated and at the stages' priority); a runner that could
   not be lowered as far as planned, a relay already at nice 19 among them, is counted
   (`priority_unset`). The engine's thread itself does nothing that takes long and wakes for a
   message alone, and for the network task's ask only when the watermark passed a step no ask
   handed it yet and an engine runs (before, every ask woke it, ten times a second, areas or none);
   it never takes an address shard (before, dropping an engine cleared them there, waiting on a
   provisional step's every pass; now the provisional runner lets them go after the step it runs).
   Once a step's seal is held, a window step is queued if a window falls due at it
   (`Engine::falls_due`, about once a stride, 40 s) and started unless one runs, and what no window
   still to be solved needs is forgotten by the step's stamp (`Engine::forget_by`), every step
   alike, before the next seal reads the room it has, so the room a seal has, and which receivers
   it refuses, is the stamps' alone. Before, a step's seal waited for the window step before it, so
   every step a window step ran past queued as a window step and those past the limit were shed
   (about six a window step, at 11 to 14 s a window step), and only a window step that ran forgot
   raw, so two relays of one area sealed different receivers out of the same bin by how long their
   window steps ran. A window step is prepared as of the step its window fell due at, however long
   it waited, and nothing a window step queued or running has still to solve is forgotten
   (`forget_by`'s floor, the first bin of its earliest window): a host whose window steps start when
   their window falls due and finish within the grace the forgetting leaves them (about 23 s)
   forgets exactly what the engine in line does. What a seal refuses is counted when it finishes,
   and what the shards refused as they take a step's bins, then (before, both waited in the engine
   for its next window step, and went with it when it was dropped). A provisional step carries
   exactly the models of the windows that fell due `engine::MODELS_RIPEN_MS` (15 s) before it, each
   ripening by its own window's due step however late it was solved, in line and hosted alike, and
   is shed at its turn, counted (`provisional_models_late`, and `provisional_steps_shed`), if one of
   them has not been solved: it never runs with other models, so every provisional step a host runs
   makes the reference's bytes however long its window steps ran or waited (before, a window step
   put off for want of the `Engine` store was counted done, its windows solved at the next step's
   and their models ripened by it). The ripening covers a window step on the planned threads (9 to
   11 s, "MLAT in the cores") and the seals a host may fall behind, so a host within its plan never
   sheds one so; and a model is carried 90 s past its window and refitted every stride (40 s), so
   fifteen seconds of it are not missed. Before, the ripening was 5 s, shorter than a planned window
   step, and a provisional step whose models had not reported started without them and adopted them
   at whichever step came after they reported, so which models a step used, and the provisional
   bytes of two relays of one area, were thread timing's; before that, a provisional step waited
   for them, and a window step running past about four seconds shed every provisional step behind
   it. `staged_mlat` holds the bytes with every window step that solves held while the watermark
   runs ten steps past it, nothing shed. Each kind waits for the one before it up to its own limit:
   `mlat_host::STEPS_BEHIND` (4) window steps (steps a window fell due at) waiting not started, past
   which the oldest is shed, its windows the next one's, and `mlat_host::PROVISIONAL_BEHIND` (0)
   provisional steps the watermark passed not started, so a provisional step starts at its turn
   or, if the one before it still runs then, is shed whole and counted (§9, §10). That is what the
   live world's seal allows: a transmission's provisional is weighed by the step after it is due,
   at most `provisional::WAITING_MS` (3.1 s: settling 1.1 s, kept past it 1 s while too few
   receivers have come, and the step) after its first reception's stamp, and its step's run and
   its records' way to the relay that gathers the world are budgeted at
   `mlat_host::PROVISIONAL_PUBLISH_MS` (0.9 s), within `products::WORLD_SETTLE_MS` (4 s), checked at
   compile time, and held by the stamps: a step's records taken once the watermark is that far past
   the step are refused whole, counted (`provisional_steps_late`, its state applied all the same,
   so the steps after it make the reference's bytes). Before, nothing held it, and a step running
   0.9 to 1 s missed the world second unseen; then it was held by the wall clock from the step's
   turn to its run's end, which left out the watermark's lag and the wait to be taken, and made a
   test's verdict its machine's speed. Before, one step of waiting was allowed and the settling's
   second was left out, about 5.1 s at worst. The way from the transmission to its first
   reception's stamp (the feeder's batching and link) is not in it and is the world product's to
   allow for. So the steps MLAT is behind by are bounded and so is what it holds while it is:
   `INTERVALS_HELD` (3) step intervals of a feeder's decoded batches and notes at `NOTES_HEADROOM`
   (four times) the planned rate, each interval bounded by its share of the store so a host that
   sheds nothing never fills it, and its open raw over the settle, the seals it may fall behind and
   `AHEAD_MS` (`OPEN_MS`, 7 s, and 1 s ahead; past it the shards refuse raw, counted).

   **A panic in hosted MLAT (decided 2026-10-09, sweep 5, N7).** It ends the relay, as a panic in
   any other part does (`abort_on_any_panic`), not isolated and restarted: MLAT's state (the sealed
   bins standing reads, the address shards, the steps in hand) is shared with the rest of the
   relay through locks and charges a panic would leave poisoned or held, and a part restarted
   beside them would run on with them as if whole, which is what the relay's hook exists to
   refuse. The engine's thread and every runner hold a guard that ends the process when its
   thread unwinds (`mlat_host::EndOnUnwind`), so a host built apart from the relay's program, which
   sets no hook (a test's), is held to the same; a worker's panic inside a step is its step's
   (`gate::on_threads` re-raises it on the runner, never swallows it). Before, a runner's panic left
   no report, and MLAT stalled for good, silently.

   Measured at 20,000 feeders before the pool: the single sealer thread held a whole core and fell
   behind (deriving the regional batches' ADS-B fixes was 70% of it, `to_observation` 20%, signing
   9%); after, the sealer thread is at 0.1 to 0.3 of a core.
5. **One Held per relay**, sealed bins `Arc`, shared by the MLAT engine and standing (standing reads
   sealed bins; raw later than settle is missing for both, consistently). Held stores open records per
   receiver (per-receiver sorts in parallel at seal), chunked storage (no doubling copies), byte
   accounting of what is really allocated. Standing is scoped to the areas this relay holds raw for and
   answers "unknown" outside them (decided: a relay cannot hold world raw, and relays are regional).

   Held's size, one figure (it replaces the critics' "~8 GB" in the sizing below, and agrees with
   RFC-0174 §2.11): what a relay hosting MLAT holds of raw at 20,000 feeders, measured, is 8.7 GB for
   a canonical window (30 bytes an observation, index included) and about 12 GB with the open bins and
   the bins standing settles in. What it reserves is more, because the reservation is a bound, not a
   mean (`held::Rates::MEASURED.cost(SETTLE_MS)`): a receiver's open raw at its ceiling (1,800 wanted
   receptions a second, five times the mean) over a bin and the settle, 7 s, about 0.35 MB with its
   bins' fixed cost, plus its thinned raw (150 kept a second) over the 25 sealed bins a holder keeps
   (`SEALED_BINS_HELD`), 0.75 MB: about 1.1 MB a receiver, 22.5 GB at 20,000. The critics' 8 GB was
   the window's raw alone. As built the two halves are two stores, each charged before it holds a
   byte: sealed raw is `Store::Held` (0.75 MB a receiver), checked on each whole bin as it is sealed
   and charged as it is inserted; open raw is `Store::Open`, over the settle and the steps MLAT may
   fall behind (`mlat_host::OPEN_MS`, 7 s) and the second a bin may open ahead of its batch's stamp
   (`held::AHEAD_MS`): 0.69 MB a receiver at its ceiling, charged by each raw
   shard as it grows (`held::Open::add_decoded_taking` asks for every byte before it allocates it;
   one refused refuses the batch's raw of the bin, counted).
6. **One batch byte store**: shared `Bytes` keyed by (receiver, boot, seq); others hold handles.
   Window = the sharing repair horizon derived from sharing's own constants (~12-15 s), not 60 s.
   As built: the sharing member is that store. A group holds a batch as the `Batch` itself
   (`sharing::member::Piece`), so its bytes are the one allocation the hub, products and fan-out
   already hold a handle to; parity is built from and rebuilt into the same pieces. The horizon is
   `HORIZON_MS` = the receipt window (5 s) + its grace (4 s) + the judgment (2 s) + the repair delay
   (1.5 s) = 12.5 s, held as 13 whole seconds. The store is held by its gauge alone
   (`budget::Store::Batches`, `Sharing::charge_to`): every record and parity a group holds, and
   every parity being reassembled from its chunks, is charged before it is held and released as it
   is let go, so the gauge reads what the store holds; one that would pass the gauge's limit (the
   store's share of the budget, planned as a feeder's bytes over the horizon and as much again for
   their parities: a parity is as long as its manifest's longest stripe slice, a third of the
   records in a busy area and all of them in one with a record a second, so at most its records'
   bytes and `parity::OVERHEAD`) is refused whole and counted (`Stats::refused`, the gauge's own
   count), never the oldest dropped to make room. Before (2026-10-08) the member held
   its own capacity beside the budget (`held_bytes_for`, `set_held_capacity`) and charged no gauge,
   its parities were held uncounted, and reassembling parities had a 64 MiB bound of their own; so
   `/memory` read the store at 0 while it held 340 MB of records at 5,000 feeders, and some 250 MB
   of parities beside them that nothing counted. Measured since (2026-10-08, 5,000 feeders, MLAT
   off, the relay on cores 0-9 and the harness on 10-31): the gauge read exactly the store's own
   count at every sample, 596 MB at steady state (records and parities, 618 MB at its peak) of its
   2.44 GB limit, none refused; the delivery tags' gauge likewise read exactly what they held, 11.1
   MB at the end of the run, of its 137 MB limit.
7. **Delivery proofs as tags made on arrival** (protocol change, v2 not yet shipped; decided): each
   round the feeder gives every member it may ask its own key k_m over the signed Probe session
   (current and next key overlapping, rotated); on arrival a member stores H(k_m || batch bytes)
   truncated to 16 B. Proof still needs the bytes and binds the exact batch; keys are per feeder, not
   per audit, so nothing reveals when an audit runs. Window W = 5 min, one shared constant. Feeder keeps
   (boot, seq, relay bitmask) for the window plus bytes only for audited/withheld ones.

   As built (`tally_wire::delivery`, `tally-relay`'s `delivery`, `tally-feed`'s `delivery_check`):
   - **Not the old form read differently.** The proof of possession this replaces travelled under
     record kinds 0x13 and 0x14, and its answer was a format 1 `DeliveryAnswer` whose `Proved` entry
     was a 32-byte proof under the same entry tag byte. Read by the other build, either form parses
     as the other's fields and means nothing. So the tagged check has kinds of its own
     (`KIND_DELIVERY_QUERY` 0x22, `KIND_DELIVERY_ANSWER` 0x23), which a build that predates them
     skips as unknown (they are not critical, RFC-0171 §3.4), and its answer is format 2, whose
     reader refuses format 1 and which a format 1 reader refuses (an old answer carried in an
     `EvidenceBundle` included). A relay reads 0x13 and 0x14 as retired (`Record::Retired`, nothing
     of the body read, never written) and answers an old feeder's query with a `Goodbye` of reason
     `Retired`, which the old feeder takes as no answer from that member, never as evidence. Old
     feeders' audits therefore find no answer at new relays until they update; nothing counts that
     against a relay, and nothing is misread.
   - **The grant.** `TagKeys`, signed by the feeder, names the member, the key in force (its id is
     the key period, `wall_ms / KEY_PERIOD_MS`, five minutes) and the next, and how long until the
     next takes over by the member's clock. It rides in a `DeliveryQuery` (so a `Probe` session
     still sends only `Echo` and `DeliveryQuery`), every minute to any member drawn for the period
     not yet given its key, and again with every audit question. The members given keys are at most
     `KEYED_MEMBERS` (16), drawn at random from every member the feeder may ask afresh each key
     period, and a member not drawn has its keys dropped, so whoever reached the feeder first (a set
     of Sybils after a restart) judges for one period at most. Signed, because the query is not: a
     key from anyone else would make every tag that member makes fail and void the feeder's audits.
     A member takes it only for a feeder of an area it takes that fed it a batch within the window
     (so fresh keys that never fed cost it nothing), only addressed to itself, and never older than
     the keys it holds.
   - **The tag.** BLAKE2s-256 over a domain, k_m and the batch's signed bytes, first 16 bytes, with
     the key's id: `delivery_tag`. A member keeps an entry of 40 bytes (sequence, arrival, key id,
     tag) per batch for W, tagged or not, only for a receiver of the areas it takes (the relay's own
     regions decide, as for the answer's "takes the area"), sharded by receiver under a
     process-secret hash, each stream kept in sequence order so a query's batches are found by
     binary search. 20,000 feeders at one batch a second: 6 M entries, 240 MB (`PER_FEEDER_BYTES` =
     12 KB), bound per receiver at `ENTRIES_PER_RECEIVER` (twice a feeder's rate over W, so one
     receiver fills only its own share) and in all by the store's gauge (`budget::Store::Delivery`,
     `Delivery::charge_to`), which each entry's 40 bytes are charged to before it is held and
     released from as it is let go; past either a batch is refused whole, counted, and never
     denied. Before (2026-10-08) the store held its own count beside the budget (`TAGS_HELD`,
     8 Mi entries, `set_capacity`) and charged no gauge, so `/memory` read it at 0 while it held
     16 MB at 5,000 feeders. A session is answered a few
     queries at once and one more a second.
   - **The verdict.** The feeder recomputes the tag from its copy of the audited batch and the key
     it gave that member, and takes it only under a key in force when it sent the batch (its period
     or one either side, `tag_keys_for`). It keeps keys for the two periods before the current, so
     a tag under an older key (a replay, or a key a member kept past its rotation) proves nothing.
     It asks only about batches sent within `ASK_WITHIN_MS` (W less the longest ask), so the tag is
     still held. Majority and votes are unchanged: a network votes on a batch when a member of it
     proved it or signed "not seen".
   - **"Not seen" only when known.** A member says "not seen" only after it has watched the
     receiver for a whole window (since its first batch here: a restarted relay, or a receiver only
     now in its areas, is denied nothing for W; a receiver it does not watch, nothing ever) and
     holds no entry for the batch at or above its stream's horizon. A batch that came while it held no key for the
     feeder has an entry and no tag, and is left out, as is one refused or let go.
   - **The feeder's ledger.** Per batch first written within the window: (boot, sequence, first
     written, wall clock, a 16-bit relay mask over a slot table), 48 bytes, at most 1,024; a batch
     one of whose relays could not be named is never taken as the audited relay's alone. Bytes
     only of the latest audit's batches and of what an audit withheld or owes. At RFC-0181's 8 KB
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
   description before first batch. Fan-out never pushes back on the producers: a subscriber that
   cannot keep up is let go, so one slow reader never slows ingest for every feeder. When an item
   would pass the fan-out's budget, the subscriber holding most is let go the same way, and the next,
   until it fits. A relay's directory link is the one exception: what it is sent is held whole
   elsewhere, so it is sent that again (a resync) instead.
9. **Capacity is admission, never a silent drop inside a store.** Each store's per-feeder bytes are
   reserved when a feeder is admitted, in the same headroom check RFC-0171 uses for egress; the feeder
   ceiling is derived from RAM and those formulas; Hello beyond it is refused ("no spare slot"). MLAT
   receiver limit comes from the same F (>= 20,000). Any leftover overflow is counted, published, and
   refused whole (a whole receiver, bin, area or second), never partially in an interleaving-dependent
   way. `Added.dropped` is never discarded.

   As built (`tally-relay`'s `budget`): every store and every queue whose size grows with what feeders
   send is a `Store`, with a per-feeder cost over its own window, reserved at admission: the batch
   byte store, `Held`, the fingerprints (as if every reception were new, with the tables' room to
   double), the fan-out, the delivery tags, a connection's ingest allowance (`FEEDER_ALLOWANCE`) and
   its Noise buffers, reading and writing (`BUFFERS_PER_CONNECTION`, every other connection's from
   room the plan sizes to the connections the caps allow, `Plan::connection_buffers`), the epochs'
   decoded batches between ingest and the sealer and each reception's place in their decisions
   (`seal::EPOCHS_HELD`, 3 epochs; `exchange::DECISION_BYTES_PER_RECEPTION`), and what the products hold until
   the hub takes it (`products::OUTBOX_EPOCHS`, 2: the signed records only, every reception as an
   encoded observation in two of them, its stream's batch and its area's regional batch: 48 bytes a
   reception, where the owned copy the stream used to hold was planned at 54 alone); and, where the
   relay hosts MLAT, its sealed raw (`Held`), its open raw (`Open`), what batches told provisional
   solving (`Notes`, `mlat_host::notes_per_feeder`: the intervals held at `NOTES_HEADROOM`, the one
   figure a step's count is bounded by too, so the bytes a step admits are what the store holds;
   before, the count allowed four times the planned rate and the bytes covered one), the batches
   waiting for their receiver's description or a step's descriptions, and the descriptions waiting
   for their step (`Orphans`, `mlat_host::orphans_per_feeder`, before charged to `Notes` with
   nothing reserved and let go only when another came, then charged with no share for what waits
   for a step) and the engine's own
   tables (`Engine`: the receptions waiting for provisional solving, `Capacity::waiting`, 1,116 a
   seat at `provisional::WAITING_BYTES`, and a window step's working set,
   `SOLVE_BYTES_PER_RECEIVER`, 192 KiB a seat, reserved while it runs); and the records that wait
   for the sealer apart from the epochs (`Records`, §4). What sharing addresses to members waits
   in its outbox charged to the batch byte store, planned there as a network tick of a feeder's
   records and parity to each child of its stripe trees, and keeps that charge in the member
   link's queue until written, beside the link's own share (`peers::WAITING_PER_LINK_BYTES`, 256 KiB)
   taken from room planned for every member session (`Plan::member_links`), so nothing a queue to
   a member holds is outside a plan line. Each store has a gauge whose limit is its share
   at the ceiling, charged for what the store really holds and released when it lets go (a decoded
   batch by `Decoded::footprint`, a record by `Record::encoded_len`, the one size of either). A
   charge is taken before the bytes are held: there is no way to charge a gauge past its limit
   (`Gauge::force`, which charged whatever the limit for bytes already allocated, is gone; hosted
   MLAT's notes and raw were charged that way and held ten times their share when MLAT fell behind,
   "Sizing"). What a full gauge does is the store's policy: the ingest stage waits (the connection's socket unread);
   an epoch past its share is refused whole by the message thread that holds it, and the sealer
   counts it; the products refuse an epoch's records (its stream's batches among them) whole, and a
   peer's record alone; the
   fan-out lets go the subscriber holding most until the item fits, and lets go those it was for if
   it never does; hosted MLAT refuses a step's notes whole (past its count or its share of
   `Notes`, by the trace), a batch's open raw of its bin, raw ahead of its stamp, a sealed bin
   whole, a batch's replies to provisional solving whole and a batch waiting for a description
   `Orphans` cannot hold, each counted, and sheds whole steps it falls behind on (§10). A member is a
   session over which another relay's data comes in: a relay whose offer this one verified dialling
   it, or this relay's own one-hop raw link (a link this relay dials only to send a member what is
   addressed to it, or to an upstream for the directory, brings no data in and is none). The
   members share one rate, `--max-member-bytes-per-sec` all together (by default 1 MiB/s; a
   whole-world relay sharing its products, about 4.2 MB/s, raises it with the memory to match),
   held by one pace each waits its turn on (`ceiling::Pace`) and planned once as the feeders it is
   worth (128 at the default), and each member session carves its own ingest allowance from a pool
   sized at start for every member session the protocol lets the relay's areas bring
   (`budget::members_for`: an area's groups are the relays offering its cell or an ancestor's, at
   most `OFFERS_PER_CELL` a cell, so a relay taking region `r` may be dialled by whoever offers a
   cell above `r`, `r` itself or a cell under it down to the area's resolution, at most
   `OFFERS_HELD`, and hosting MLAT it dials each of them for raw once per `MAX_REGIONS` cells of its
   border band; never more than `--max-connections`, under which every session in or out holds a
   place, `Hub::dialled`), for as long as each is a member (`Plan::with_members`,
   `Budget::reserve_member`): feeders never take the members' room, a relay full of feeders still
   takes its members, and no operator picks a member count. The plan is the bound, not the
   protocol's ceiling (RFC-0174 §2.5, "A relay's members are bounded"): a relay taking coarse areas
   shares groups with up to `OFFERS_HELD` (16,384) relays and its connections cap what it plans,
   so past the sessions planned a member is turned away with `Reason::Full`, counted
   (`members_refused`), and the relay turned away routes what it would have sent this one to the
   next members of the area's trees (`peers::Peers::refused_full`, `sharing::member`'s `route`),
   dialling it again only once its wait (60 s, doubled on each refusal after, at most 30 min) has
   passed. A raw link takes its place in this relay's own pool before it is dialled, so a relay
   never dials a link it would turn away itself. The budget is
   `--memory`, by default the memory the relay runs in (the lesser of its cgroup's `memory.high` and
   `memory.max`, its own and its ancestors', else the host's) less `budget::HEADROOM_BYTES` (64 MiB,
   what no store charges: the allocator's unreturned pages, stacks, the kernel's socket buffers);
   `--memory` above that is refused. Before any feeder the budget plans, each on its own line: the
   base, the oversize room (`Plan::oversize`), the Noise buffers of every connection but a feeder's,
   which a feeder's reservation holds (`Plan::connection_buffers`: those under
   `--max-connections`, the member sessions and the subscribers, each role by its own cap), the members' pool (their shared rate's feeders' worth less the buffers
   and allowances, and each member session's allowance), and what waits for the links it dials
   to its members (`Plan::member_links`, a link's share for each member session), and the rest the
   plan lists (`Plan::before_feeders_parts`: the one list the budget sums and `check` prints, each
   part on its line and their sum as `before-feeders`, so a room planned is a line printed and no
   deploy check sums a list of its own). A relay whose budget cannot hold these and
   one feeder refuses to start (`Budget::check`). `tally-relay check` makes every refusal a start
   makes, along the start's own path, and prints the memory plan (the member sessions, each one's
   share, their rate's feeders and pool, the headroom); the packaged unit is held to it by
   `//tally/crates/relay:check`, with no area and with a base cell taken, and an operator holds its
   own deploy to it the same way (ours: `//infra/tally:relay_config_test`, which also holds that a
   relay taking areas plans their members and one taking none plans none). The gauges are served on
   `GET /memory`, beside the decoded batches alive and those some store's charge covers
   (`Budget::decoded_held`): a charge cannot pass its gauge's limit, so the one way past the budget
   is a holder no gauge charges, and that is what the two read together show. Beside them it
   serves the batch store's own count of what the sharing groups hold (`batches_held`, records and
   parities), read against `Store::Batches`, and the delivery tags' (`delivery_held`); the parities
   being reassembled are in neither, but under `parity_assembly`, the gauge of their own room
   (`Plan::parity_assembly`), which counts them itself. Each store charges
   a decode it holds with a charge that covers it (`Charge::cover`, kept through a split and an
   absorb), and the covers count each decode once however many stores hold it
   (`budget::Covered`), so the comparison is exact to the batch: one decode held where no gauge
   sees it shows, and the flood test leaks exactly one in the middle of a flood to prove it.
   Before, the stores' gauges were summed: every connection's allowance carved and idle counted,
   and a decode in the epochs and a subscriber's queue counted twice, about a megabyte of slack
   under a flood, inside which dozens of leaked batches went unseen.

   Why the pool (2026-10-08): members once reserved from the feeders' room, as 1,024 feeders at the
   then default 8 MiB/s. 576 MiB admitted 107 feeders and 2 GiB some 640, so every sharing member was
   refused full and cross-relay sharing and MLAT raw never flowed; the checks asked only that one
   feeder fit, and the budget was all of `memory.max` with no headroom and ignored `MemoryHigh`, so
   no check could fail. The pool then held `--max-members` (default 1) members, each the feeders its
   own ceiling was worth, and counted every session with a verified relay as one, this relay's own
   one-hop raw links and its dials to send included: with the default a second relay's raw link was
   turned away ("no spare member slot"), so a network of more than two relays shared and solved
   nothing until its tests raised the count to 32. Members now are what the areas bring, and their
   rate is planned once.

   Why (measured 2026-10-08, 20,000 feeders on one 32-core host): the relay's resident memory grew
   about 330 MB/s, unbounded, to 18 GB in 160 s. It was decoded batches: the sealer's queue was
   bounded by count (4,096 commands), and each command was a whole epoch's part from one message
   thread, so the queue could hold some 500 seconds of every batch; the one sealer thread could not
   keep up, and 2.2 M decoded batches (18.6 GB) waited in it. With the gauges and the sealer pool:
   3.1 GB resident at 20,000 feeders, flat (Sizing, below).

10. **Overload policy (decided)**: back-pressure for raw; whole-epoch refusal, counted, for derived
    products; refusal whole, counted, for delivery tags (a batch past the store's gauge is never tagged and
    never denied, §7); disconnection for fan-out (§8); for hosted MLAT that cannot keep up, whole
    steps shed, counted. MLAT never pushes back on ingest and never grows: every step's bins are
    taken as the watermark passes it and sealed in their turn; while more than `STEPS_BEHIND` window
    steps (steps a window fell due at) wait not started, the oldest is shed (counted,
    `steps_shed`), its windows the next one's, which solves every window due as one that ran late
    would; while the watermark has passed more than `PROVISIONAL_BEHIND` (none) provisional steps
    that have not started, the oldest is shed, its provisional solving let go (every batch whose
    notes it held counted, `MlatReport::shed`, the step counted, `provisional_steps_shed`); a
    provisional step whose models (the windows that fell due `MODELS_RIPEN_MS` before it) have not
    all been solved at its turn is shed the same way, counted (`provisional_models_late`), never
    started with other models; and one whose records are taken past its publish slot, by the
    stamps, has them refused whole, counted (`provisional_steps_late`). What is lost is
    provisional positions, never a window. A host within those limits of the watermark sheds
    nothing, so the
    same stamped trace still makes the same bytes; one further behind is shed by how far behind it
    is, which no trace decides. Before, a step shed only while no seal was in flight, so a slow seal
    let the steps queued behind it grow without bound; and a provisional step waited for the window
    step before it, so a provisional position could wait five steps and a seal, past the live
    world's seal. Changed from "back-pressure for delivery and
    fan-out" as built: back-pressure from either would let one slow subscriber, or a full tag store,
    stall ingest for every feeder, and both have a loss that is counted and told (a "fell behind"
    Goodbye, a batch left out of the audit) where back-pressure's is everyone's.

    **The cores (decided 2026-10-09).** Back-pressure for raw is the right loss only while the
    stages can carry what the relay admitted; when they cannot, it is every feeder's latency, all
    the time. So the cores are admission, as the memory is (§9): a relay plans no more feeders than
    its cores carry, and each stage's threads follow the load it plans to admit, never a fixed
    share of the host (`cores`). The load is the feeders admitted and the feeders the members'
    shared rate is worth (`Budget::load`), each at the planned rate; a stage's threads are that
    load's receptions over what one thread of the stage was measured to sustain, at
    `cores::BUSY_PERCENT` (50%) busy, at least one and at most the cores (`cores::threads_for`):
    the ingest workers, the message threads and the sealer's pool each by their own figure
    (`ingest::Threads`, whose `seal` the sealer's pool now takes instead of the message threads'
    count). The ingest workers' figure is the more of a source's planned receptions and its
    records a second at `ingest::INGEST_NANOS_PER_RECORD` (30 us) each (`cores::Source`, §2): a
    feeder's are its byte ceiling's (eight at the default 256 KiB/s, 240 us, some 1.8 times a
    planned batch's 133 us), a members' feeder's worth its `MEMBER_RECORDS_PER_FEEDER` (four, 120
    us, below its receptions), so a relay whose feeders may send tiny batches up to their pace has
    the ingest threads for it, and `check` prints `feeder-records`. The same records may instead be
    answered on the async runtime (an echo's reply signed, a delivery query's answered, a fault
    proof's two records verified), so the runtime is planned for every one of them beside a
    feeder's session (`cores::RUNTIME_NANOS_PER_RECORD`, 60 us, R4 of sweep 5), and the cores hold
    each source's records once, at the dearer of the two (`cores::spent_per_feeder`): one pace holds
    them all, so a record is taken by one or the other, never both. Before, the runtime was planned
    for a feeder's session alone (83 us of a core a second), while its eight records a second
    answered there cost some 480 us. The feeders the cores carry are every stage's work and the async runtime's together in
    that share of the cores (`cores::feeders_carried`), the members' rate taken first; the ceiling
    is the fewer of those and the feeders the memory holds (`Budget::ceiling`), so a Hello past
    either is refused ("no spare slot") and every store's share follows the same ceiling. A relay
    whose cores carry no feeder beside its members' rate refuses to start (`Budget::check`). Of the
    two ways a relay could meet cores too few for its memory (refuse to start, or admit what the
    cores carry), it admits what they carry: a relay given more memory than its cores can use is a
    smaller relay, not a broken one, and the memory already works that way. The cores are what the
    process may run on (its affinity and its cgroup's quota, `std::thread::available_parallelism`);
    `tally-relay check --cores N` is told a deploy's (every check of ours states it, from the unit's
    `CPUQuota=` or the container's `limits.cpu`, so the plan printed is the deploy's and never the
    build worker's; the master's unit runs on `CPUQuota=200%`), and prints `cores`, `core-feeders`,
    `memory-feeders` and each stage's threads beside the memory plan. `--ingest-threads` and
    `--message-threads` are gone: no operator picks a stage's threads.

    **A feeder's receptions are paced (decided 2026-10-09).** The cores are planned at the mean, 600
    receptions a second a feeder (`budget::PLANNED_RECEPTIONS_PER_SEC`), and each feeder's connection
    is held to 1,800 receptions a second (`ingest::FEEDER_RECEPTIONS_PER_SEC`): the one ceiling MLAT's
    raw holder already held a receiver to (`tally_mlat_solver::held::Rates::MEASURED`,
    `ceiling_per_s`), one constant and not two, so a feeder let in at its pace is never refused there
    for its rate. It is enforced in the read loop of each feeder's connection (`link::Paces`), by the
    count each batch states (`Batch::receptions`: the first four bytes of its observations, inflated
    alone for a compressed batch, which is exactly what a decode reads), the way the connection's
    records already are: over the pace the loop waits before it takes the batch, its socket unread,
    so TCP holds the feeder back and nothing is refused or counted lost (one mechanism for records
    and receptions). Before, a feeder's receptions were bounded only by its bytes, some 15,000 a
    second at 17 bytes each within 256 KiB/s: one connection could cost the stages 25 planned
    feeders'.

    **Every session's records are paced by its role, and planned (R4 of sweep 5).** A record costs
    the relay a signature checked or made whatever its bytes (`cores::RUNTIME_NANOS_PER_RECORD`, 60
    us), so each role's records are paced at what that role legitimately sends (`ingest`'s
    `RolePace`s, each with its reason; `link::Paces` picks the pace of what the sender is when each
    record is read):

    | Session | Pace | Why |
    | ------- | ---- | --- |
    | Feeder | its byte ceiling over 32 KiB (8 a second at 256 KiB/s) | a batch a second, early only at 48 KiB |
    | Member sessions | one pace all share, the members' rate's feeders at 4 records a second each | what a member forwards is feeders' batches and descriptions |
    | Directory links | one pace all share, whoever dialled, 546 a second | twice the directory's bound (`OFFERS_HELD`) re-signed once a minute: offers, and the queries, echoes and evidence beside them |
    | Subscriber | 12 a minute, 136 at once | a heartbeat every 30 s, a `Subscribe` when its regions change; its burst holds a credential and its evidence with every signature inside it |
    | Engine (raw one hop) | 6 a minute, 8 at once | a heartbeat every 30 s and a `Subscribe` when its band changes |
    | Probe | 6 a minute, 8 at once | a round of five echoes or one delivery query, then it hangs up |

    A shared pace is fair: each link waits for its own token in order, so of `k` links sending at
    once each is let in once in `k`, and one flooding link takes its turn and no more. Work a record
    brings beyond its token is owed to the pace it was taken by and paid before the connection's next
    record: every signature `credit::check` verifies inside an evidence bundle is a token
    (`RecordPace::owe`), a bundle being one record on the wire and up to 129 signatures. The cores
    plan every session at its pace before any feeder (`cores::Sessions`, `cores::feeders_carried`):
    each connection under `--max-connections` at the dearest pace among them (6 a minute), each
    subscriber at 12, and the directory's shared pace once, each record at 60 us, at `BUSY_PERCENT`;
    `tally-relay check` prints `general-sessions`, `subscriber-sessions` and
    `session-records-per-minute`. The packaged unit on one core, with the default caps (2,048
    connections, 64 subscribers, 45,824 records a minute), carries 274 feeders. Before, every role
    but a relay's was paced at a feeder's eight a second and each relay session at the members' whole
    rate on its own, and none of it was planned: the 2,048 connections the cap allows could send
    16,384 records a second, about a core the plan never held, and an evidence bundle's signatures
    were one token.

    **MLAT in the cores (decided 2026-10-09).** A relay that hosts MLAT plans its engine in the same
    cores. The stages keep their half-busy share for raw; MLAT's steps get what is left. Each
    hosted feeder costs MLAT its measured figure, `cores::MLAT_WINDOW_NANOS_PER_FEEDER` (seals,
    window steps and the engine's thread, 0.70 ms of a core a second) and
    `cores::MLAT_PROVISIONAL_NANOS_PER_FEEDER` (0.41 ms), planned at `cores::MLAT_BUSY_PERCENT`
    (100%: MLAT runs below the stages, so the half of their share they leave idle is MLAT's too
    whenever they do not need it, and what MLAT cannot do in time it sheds). The load the cores
    carry is the most whose stages' share and MLAT's fit the cores together
    (`cores::load_carried`), so admission with MLAT on is bounded so both fit, and MLAT's threads
    are the cores the stages' share leaves for the load admitted, rounded up
    (`cores::mlat_threads_for`, `Budget::mlat_threads`), which at the ceiling hold its cost. All of
    them, not only its average need, because its work is not even: a window step's comes at once
    every 40 s or so, and a provisional step runs only once the window steps `MODELS_RIPEN_MS`
    (15 s) before it have reported. On the three threads its average cost needs at 2,000 feeders, a
    window step took 19 and 24 s and 15 and 20 provisional steps a minute started without its
    models (then 5 s); on the seven the plan gives it, 9 to 11 s and 10 to 14, which the ripening
    now covers. Those threads are every kind of MLAT work's together: seals, window steps, forgets
    and provisional steps each hold one of them while they work (`tally_mlat_solver::gate`), so the
    three kinds at once never work on more than the plan gave (before, each kind spread over all of
    them, up to three times the plan), provisional work let in first, between two items of the
    others'. Every MLAT step runs below the stages' priority (`mlat_host::Urgency`): provisional
    steps 5 nice steps below the relay's own, seals, window steps and forgets 10 below, the threads
    they spread over inheriting it, so on a relay short of cores it is MLAT that waits and sheds
    whole steps, counted (`steps_shed`, `provisional_steps_shed`, beside the steps it ran, `steps`
    and `provisional_steps`), never raw that is delayed. Below the relay's own whatever it was
    started at: before, nice 5 and 10 were set outright, so a relay started at nice 5 or more ran
    MLAT level with its stages; a thread whose priority cannot be lowered is counted
    (`priority_unset`). Nice orders the relay's threads among themselves and no further: under a
    CPU quota (the public relay's 1,500m) every thread of the process draws on the one quota, and
    MLAT's share of it is what the plan sizes its threads by (`Budget::mlat_threads` over the cores
    the quota gives). No step holds a lock a stage or the engine's thread waits on while it works:
    an address shard's inbox, which the ingest workers hand notes to, is apart from the state a
    provisional step weighs, and the step only swaps it out (`Shared::due`); the charge of the
    receptions waiting is locked only to grow it and to settle it, never across a step's passes
    (before, held across them, the engine's thread dropping an engine waited on a provisional
    step). The engine's own thread, which does nothing long and takes the raw shards' locks, stays
    at the stages' priority; idle, it never wakes (before, ten times a second), and a provisional
    step with nothing to weigh is done on it, on no thread. A window step's working set stays
    charged until its outcome is applied, so a finished window waiting for the engine's thread is
    never outside every store.
    `--mlat-threads` is gone: no operator can need a thread count the plan does not size, and its
    one other use, turning MLAT off, is `--no-mlat`. `tally-relay check` prints `mlat-threads`.

    Why (measured 2026-10-09, 2,000 feeders hosting MLAT on cores 0-9): `--mlat-threads`
    defaulted to every core the relay saw, its window steps spread over all of them beside the
    stages, and its provisional steps ran at the stages' priority, so nothing kept a core for raw.
    Given two threads, MLAT took both whole (1.99 cores) and still fell behind, and raw's p99 was
    220 ms; given eight, 162 ms. With MLAT planned and below the stages, 52 to 68 ms. The figures
    and the runs are in "Sizing", "What the cores carry".

    Why (measured 2026-10-09, 5,000 feeders, about 3 M receptions a second, the relay on cores 0-9):
    the stages took a quarter of the cores for ingest and an eighth for the message exchange, so
    ten cores ran one message thread. It was 66% busy on average and saturated at each epoch's
    close; its queue filled, the ingest workers waited on it, and raw's p99 was 0.6 to 1.2 s, and
    different run to run. Two message threads at 28% each gave 41 ms. The figures each stage is
    sized by, and the runs after, are in "Sizing", "What the cores carry".
11. **Connection buffers from a shared pool**, not zeroed 64 KiB per connection. As built
    (`tally_wire::noise::Buffer`): a session's reader and writer hold no buffer between messages.
    A message's frame, its plaintext and the records packed into it are written in buffers taken
    from one process-wide pool while that message is in hand, and given back after; the pool keeps
    at most `POOL_IDLE` (256) idle, 16 MiB. Per connection idle: before, two zeroed 64 KiB buffers
    and a writer plaintext that fills to 64 KiB, about 192 KiB resident, plus a fresh frame
    allocation per message; after, the two halves (under 1 KiB) and the transport state, with
    buffers only for messages in flight.

    A buffer given back is zeroed over every byte any holder wrote before the pool keeps it, so no
    session's plaintext outlives its message in memory: a buffer's bytes are reached only through
    calls that record the most it was written (`space`, `append`), and only that much is zeroed, so
    a message costs the zeroing of what it used, never 64 KiB. A writer measures each record before
    it writes it (`Record::encoded_len`) and seals the message first when the record would not fit,
    so a buffer never grows past a message and the 16 MiB bound holds whatever passed through.

## Invariants the tests hold
1. Thread-count independence: same stamped trace at 1, 2, 8, 32 threads gives byte-identical MLAT
   models, positions, provisionals, world/precise parts, standing, regional record sequence.
2. No consumer reads a clock: decisions use `stamp_ms`; injected queue delays change nothing,
   for hosted MLAT while it is within its limits of the watermark (`PROVISIONAL_BEHIND`,
   `STEPS_BEHIND`; past them it sheds whole steps, counted, §10; `staged_mlat` holds the bytes with
   delays inside that, descriptions midway included, and `mlat_host`'s tests hold the shedding,
   no window step shed while a seal or a window step is held shut past many steps, every
   provisional step past the ripening shed at its turn, every store within its limit, and the
   sealed bins the reference's at the same step while a window step runs long). The tests that run relays hosting MLAT over sockets (the relay's
   `tests/mlat_host.rs`, the API's end to end) step their relays' ingest clock a step at a time
   (`mlat_host::stepping`), only once every relay has been offered what was fed and has stepped
   and published, never past the wall clock, and assert in stamps: a provisional record is published
   within `WORLD_SETTLE_MS` of its newest transmission, and every one published before its
   second's seal is in the live world for that second. How fast on the wall clock is a bed's to
   measure (`tally-load --streams provisional`), not a test's.
3. MLAT/world output unchanged under permutation and duplication between two watermarks.
4. `Bin::seal_from(fragments)` byte-equal to `Bin::seal` for any split by receiver.
5. Dedup across shards exact: a message via k receivers on k workers is gathered once per window.
6. Per (receiver, boot) admitted order to every subscriber; description first.
7. Loss only at named places, counted per epoch, whole.
8. RSS within the admission budget at 20k for 10 minutes; per-store byte accounting tests: under a
   flood and with a stage stalled, every decoded batch alive is charged by the store holding it,
   read at the same instant (`tests/flood.rs`, which first shows it sees a holder no gauge charges).
9. No lock across a seal: ingest p99 flat with a sealer slowed to 1 s.
10. Throughput scales ~linearly with cores; 20k feeders sustain 20k batches/s at target p99 in tally-load.

## Sizing at 20k

The critics' estimate, before anything was built: ~12-13 GB RAM (batch store ~2.4 GB, Held ~8 GB,
dedup ~0.6 GB, fan-out ~0.33 GB, buffers ~0.3 GB) and ~35-40 cores (27 MLAT fits, 8-10
verify/inflate/ingest/dedup). Held is about 12 GB resident and 22.5 GB reserved (§5); the rest is
what follows.

Measured (2026-10-08, `tally-load`, the relay alone on its own cores, `--memory 14G`, no hosted
MLAT), resident memory at three loads:

| Feeders | Resident  |
| ------- | --------- |
| 1,000   | 502 MiB   |
| 5,000   | 1,469 MiB |
| 20,000  | 3.1 GB    |

At 20,000 the relay held about 7 cores and its memory stayed flat.

The feeders and the client ran as their own processes on other cores: run in one process beside the
relay, 20,000 simulated feeders take some 19 cores and starve the client's one read task, which then
falls behind and is let go. An earlier run the same day, before the dedup window was widened to
three generations (§3), measured 2.3 GB and 6.3 cores mean (7.4 peak), with 586 kB reserved a
feeder (the fingerprints' worst case 178 kB of it).

**The relay's own base.** Between 1,000 and 5,000 feeders the relay grows 247 KiB a feeder; between
5,000 and 20,000, about 100 KiB. What a feeder adds falls as feeders are added, so the line through
the 1,000 and 5,000 points meets zero feeders at or above the true base: 502 MiB less 1,000 x 247 KiB
is 260 MiB. The relay's own base, with no hosted MLAT, is at most 260 MiB, the 16 MiB Noise pool
and the runtime's threads included. `budget::BASE_BYTES` was planned at 1 GiB and 16 MiB, four
times that, and with it a relay given 1 GiB, or the public relay's 640 MiB, admitted no feeder and
refused to start (`Budget::check`). It is 272 MiB: 256 MiB and the pool's 16 MiB
(`noise::POOL_IDLE x MAX_MESSAGE`), above the measured 260 MiB, and safe at any load because each
feeder's reservation (`PerFeeder::planned`, `per-feeder` in `tally-relay check`'s plan) is above the
247 KiB the relay measured adding, which `budget`'s tests hold against the measured figure
(`budget::MEASURED_GROWTH_PER_FEEDER`) rather than a size stated here.

**What hosting MLAT costs** (measured 2026-10-08, `tally-load` built `-c opt`, the relay on cores
0-9 and the harness on 10-31, the relay started by hand with `--memory 14G --mlat-threads 4`, two
areas taken, `801ffffffffffff` and `8027fffffffffff`, the cells at the centres of the simulation's
two clusters, and itself advertised so it is chosen to solve them; resident memory at the end of a
60 s ramp, 30 s warm-up and 60 s measured, with the same relay with `--mlat-threads 0` beside it):

| Feeders           | MLAT off  | MLAT on    | On less off | `Notes` held (its limit 829 MiB) |
| ----------------- | --------- | ---------- | ----------- | -------------------------------- |
| none (idle, 10 s) | 17.3 MiB  | 19.8 MiB   | 2.5 MiB     | 0                                |
| 500               | 416 MiB   | 1,981 MiB  | 1,565 MiB   | 4 MiB (peak 369)                 |
| 2,000             | 1,140 MiB | 8,201 MiB  | 7,061 MiB   | 2,451 MiB                        |
| 5,000             | 2,209 MiB | 17,070 MiB | 14,861 MiB  | 5,270 MiB (peak 8,727)           |

A line through the MLAT runs (least squares) is 843 MiB and 3.30 MiB a feeder, and through their
differences from the runs without it 569 MiB and 2.90 MiB a feeder; through the 500 and 2,000
points alone it meets zero feeders below zero. None of these intercepts is a base: what MLAT holds
grows faster than any line where the engine falls behind, and is still rising at the end of each
run. Its base is what it holds before any feeder, 2.5 MiB, and `budget::MLAT_BASE_BYTES` is 8 MiB
(4 MiB for that, and the 4 MiB bound on the signed records not yet taken,
`mlat_host::PUBLISHED_BYTES`), in the relay's base (`budget::Plan::base`) when it hosts MLAT.

What those runs showed was that MLAT's memory was not held to the budget. At 5,000 feeders the
relay was 17 GB resident under a 14 GiB `--memory`. Its notes to provisional solving were charged
by force (`Gauge::force`, since deleted): one step interval's notes were bounded by count, but
nothing bounded how many intervals waited for a step that was behind, so with four threads the
`Notes` store held six times its share at 2,000 feeders and ten at its peak at 5,000, keeping 4.9 GB
of decoded batches alive. `Held` was charged by force too, and its open bins grew with the steps
MLAT was behind. The public relay's shape (`infra/kubernetes/tally/relay.yaml`: `--memory 576M`,
`--mlat-threads 1`, its then ceiling of 167 feeders, two areas, 300 s measured) was 712 MiB resident
and still rising, past its 640 MiB limit: `Held` peaked at 211 MiB of its 179 and `Notes` at 66 of
its 18.

**Where the rest went** (measured the same day, the relay built with an allocator that tags each
allocation by the stage that made it, 500 feeders): what was allocated and live was the stores and
the base, and the engine's tables beyond them were small (provisional solving's state about 35 MiB,
70 KiB a feeder; a window step's working set at most 79 MiB while it ran, 160 KiB a feeder). The
gigabyte above the stores was two things. First, lag: while a window step ran (18 s at 500 feeders
on a loaded host), the steps queued behind it held their notes' decoded batches (`tell` peaking at
215 MiB, the batches it pinned at 500 MiB more), their open raw, and, once read at once, their
provisional receptions (peaking at 525 MiB). Second, the allocator: a window step's work is spread
over threads it starts (`window::parallel`), each served by one of glibc's arenas, which keep what
they freed for their own reuse, so resident memory was about twice what was live (2,094 MiB
resident with 900 MiB live; with `MALLOC_ARENA_MAX=2`, 1,711 MiB).

As built since: every store is charged before it holds a byte (§9), the steps MLAT may be behind
are bounded and the oldest shed past them (§4, §10), the engine's own tables that grow with its
receivers are a store (`Engine`), and after each window step the host handed the allocator's free
pages back (`malloc_trim`; removed since, "MLAT and the allocator" below). A feeder then (the first sweep) reserved
2.89 MB where MLAT is hosted (0.67 MB without it): sealed raw 0.75 MB, open raw 0.64 MB, notes
0.39 MB, the engine's tables 0.45 MB; the base was 280 MiB (`BASE_BYTES`, `MLAT_BASE_BYTES`: 4 MiB and the signed records'
4 MiB bound). Measured (2026-10-08, the same harness, the relay on cores 0-9, two areas, four MLAT
threads and `--memory` exactly what the feeders' reservations need, `Budget::memory_for`; the
deployed shape with one thread and 576 MiB, 300 s; the host shared with other work at a load of 45
to 50):

| Feeders          | `--memory` | Resident, peak | Resident, end | Steps shed | Every store within its limit |
| ---------------- | ---------- | -------------- | ------------- | ---------- | ---------------------------- |
| 107 (576 MiB, 1) | 576 MiB    | 398 MiB        | 348 MiB       | 0          | yes                          |
| 500              | 1,659 MiB  | 1,449 MiB      | 1,182 MiB     | 32         | yes                          |
| 2,000            | 5,798 MiB  | 4,754 MiB      | 4,249 MiB     | 71         | yes                          |
| 5,000            | 14,076 MiB | 7,139 MiB      | 5,665 MiB     | 82         | yes                          |

Four threads on that host did not keep up with the window steps at 500 feeders and more (a window
step took 17 to 60 s), so MLAT shed whole steps, counted, and stayed within its stores; at the
deployed shape it kept up and shed nothing. 576 MiB then admitted 107 MLAT feeders, not 167.

Since (the second sweep, 2026-10-08), what hosting MLAT reserves a feeder is sealed raw 0.75 MB,
open raw 0.69 MB (the second a bin may open ahead of its stamp), notes 0.73 MB (sized from the
same four times the planned rate their count is bounded by, over the four intervals a host that
sheds nothing holds), the batches waiting for a description 0.13 MB (a store of their own) and the
engine's tables 0.45 MB: 2.75 MB of MLAT stores, 0.52 MB more than before, so a given memory
admits fewer MLAT feeders. The runs above were not repeated with it.

**What the cores carry** (measured 2026-10-09, `tally-load` built `-c opt`, the relay on cores 0-9
and the harness on 10-31, two areas, `--memory 24G`, a 60 s ramp, 30 s warm-up and 60 s measured;
each stage's threads' CPU over the measured minute from `/proc/<pid>/task/*/stat`, beside what the
subscriber read). Each stage was run at more than one thread count, and its figure is the least a
thread sustained:

| Stage                      | Runs (receptions a second: threads, the stage's cores)       | Per thread, sized by        |
| -------------------------- | ------------------------------------------------------------ | --------------------------- |
| Ingest                     | 3.05 M: 2, 0.594; 3.02 M: 4, 0.636; 4.61 M: 4, 1.018          | 4.5 M (221 ns), 7,500 batches |
| Ingest, MLAT raw held      | 1.21 M: 2, 0.352                                             | 3.4 M (290 ns), 5,700 batches |
| Message exchange           | 3.05 M: 1, 0.660; 3.02 M: 2, 0.557 and 4, 0.468; 4.61 M: 4, 0.620 | 4.6 M (216 ns), 7,600 batches |
| Sealer and its pool        | 3.02 M: 1, 0.517; 2, 0.506; 4, 0.538; 4.61 M: 4, 0.492        | 5.6 M (178 ns), 9,300 batches |
| Sealer, MLAT raw held      | 1.21 M: 2, 0.370                                             | 3.2 M (305 ns)              |
| Async runtime (10 workers) | 5,000 feeders: 0.404 to 0.412; 6,742: 0.516                  | 12,000 feeders a core       |
| Async runtime, raw held    | 2,000 feeders: 0.243                                         | 8,000 feeders a core        |
| MLAT window steps          | 500 feeders: 0.27 + seals 0.058 + engine 0.008; 2,000: 0.96 + 0.21 + 0.085 | 0.70 ms a feeder |
| MLAT provisional steps     | 500 feeders: 0.14 to 0.20; 2,000: 0.72 to 0.80               | 0.41 ms a feeder            |

The message exchange costs less a reception the more threads it has (a thread's shards fit its
caches), and the slice each batch sends each thread cost nothing measurable beside its receptions,
so it is sized by its one-thread figure. The part of the seal no helper takes (gathering each epoch,
numbering its records, applying them) was 0.144 to 0.164 of a core at 3.02 M receptions a second and
0.144 at 4.61 M: it follows the epochs and the areas, not the receptions, so it bounds no feeder
count.

**What ten cores carry is the relay's to say, not this document's** (N15 of sweep 5). The feeders
the cores admit and each stage's threads follow from the figures above, each record a source may
send (`cores::Source::records_nanos`, at the dearer of an ingest worker's 30 us and the runtime's
60 us, `cores::RUNTIME_NANOS_PER_RECORD`: a record answered on the runtime, an echo's reply signed or
a fault proof's two records verified, costs it up to two signatures checked, measured 26.8 to
28.1 us each), and whatever else the plan holds. They are `tally/crates/relay/tests/cores-10.txt`:
`tally-relay check`'s cores lines for ten cores, the harness's two areas and memory to spare,
hosting MLAT and not, which the `check` test (`the_cores_figures_the_rfc_quotes_are_the_relays_own`)
prints and holds equal to what the relay plans, so a figure here can no more drift from the code
than the file can. Before, this paragraph said ten cores admitted 10,879 without MLAT and 4,129
hosting it, from before a record's cost was planned, while the relay planned 3,917 hosting it; with
every record planned wherever it is answered (R4 of sweep 5), it plans fewer again, and the file
says how many: with every session beside the feeders planned at its role's pace too (§10,
"Every session's records are paced by its role"; the file's `general-sessions`,
`subscriber-sessions` and `session-records-per-minute`), 2,874 hosting MLAT and 5,188 without.

Three runs back to back at 5,000 feeders, MLAT off, the plan's threads (three ingest, three message,
three seal), the same harness and host as above:

| Run | Raw p50 | Raw p99 | Raw max | Ingest (3) | Message (3) | Sealer and helpers (1 + 2) | Runtime | Relay  |
| --- | ------- | ------- | ------- | ---------- | ----------- | -------------------------- | ------- | ------ |
| 1   | 1 ms    | 69 ms   | 127 ms  | 0.640      | 0.511       | 0.277 + 0.246              | 0.411   | 2.10   |
| 2   | 1 ms    | 68 ms   | 117 ms  | 0.637      | 0.481       | 0.280 + 0.251              | 0.410   | 2.07   |
| 3   | 1 ms    | 92 ms   | 127 ms  | 0.674      | 0.527       | 0.293 + 0.260              | 0.434   | 2.20   |

(cores over the measured minute; every thread of a stage within 0.03 of the others, the busiest
0.23.) Each run read 5,000 batches and 3.02 M receptions a second with nothing lost, and the relay
admitted all 5,000. Before, with one message thread and two ingest workers, the same runs' raw p99
was 266, 275, 1,067 and 587 ms.

**Hosted MLAT in the same cores** (§10, "MLAT in the cores"). Its figures were measured with the
relay built `-c opt` and each MLAT step thread, and every thread it spread its work over, adding
its own run time (`/proc/thread-self/schedstat`) to its kind's count as it ended (a probe built for
the measurement, not in the relay), the relay on cores 0-9 with eight MLAT threads so no provisional
step was shed. A window step comes about every 40 s and costs seconds of every thread it has, so it
is taken whole: 10.0 and 11.0 cores-seconds at 500 feeders, 39.4 at 2,000. Each figure is the most a
feeder cost over the runs (`cores::MLAT_WINDOW_NANOS_PER_FEEDER`,
`cores::MLAT_PROVISIONAL_NANOS_PER_FEEDER`), planned at 100% of what the stages leave
(`cores::MLAT_BUSY_PERCENT`). Hosting MLAT, a planned feeder costs MLAT 1.11 ms of a core a second
beside what it costs the stages with its raw held; the feeders ten cores admit hosting it, and the
threads they run (MLAT's among them), are `tally/crates/relay/tests/cores-10.txt`'s "hosting MLAT"
lines, as above.

Three runs back to back at 2,000 feeders hosting MLAT, the plan's threads (one ingest, one
message, one seal, seven MLAT), `--memory 14G`, the same harness and host (cores over the measured
minute; MLAT's by its probe, its window steps over the minute holding two of them):

| Run | Raw p50 | Raw p99 | Raw max | Ingest | Message | Sealer and helper | Runtime | MLAT engine | Window steps and seals | Provisional steps | Window steps run, shed | Provisional steps run, shed |
| --- | ------- | ------- | ------- | ------ | ------- | ----------------- | ------- | ----------- | ---------------------- | ----------------- | ---------------------- | --------------------------- |
| 1   | 2 ms    | 68 ms   | 104 ms  | 0.292  | 0.200   | 0.364             | 0.245   | 0.085       | 1.189 + 0.204          | 0.676             | 2, 10                  | 60, 0                       |
| 2   | 2 ms    | 52 ms   | 107 ms  | 0.291  | 0.214   | 0.372             | 0.251   | 0.093       | 1.143 + 0.207          | 0.748             | 2, 11                  | 60, 0                       |
| 3   | 2 ms    | 58 ms   | 111 ms  | 0.291  | 0.203   | 0.369             | 0.250   | 0.091       | 1.176 + 0.205          | 0.672             | 2, 14                  | 60, 0                       |

Each run read 2,000 batches and 1.21 M receptions a second with nothing lost; resident memory peaked
at 4.1 to 4.3 GB. Every provisional step ran. A window step took 9 to 11 s, so the empty steps the
watermark passed behind it were shed into the next (`steps_shed`, no window lost) and as many
provisional steps started without its models (`provisional_models_late`, then: the ripening was
5 s; it is 15 s since, sweep 4). Before, the same 2,000
feeders with MLAT on two threads at the old defaults gave raw a p99 of 220 ms (max 284), and on
eight 162 ms (max 282).

**MLAT and the allocator** (2026-10-09, sweep 5). With the harness's clocks continuous across its
loops, MLAT solved some twelve times what it had, and at 2,000 feeders hosting MLAT raw's p99 rose
from 77 ms to 880 ms, a subscriber fell behind, and no stage thread waited on the run queue
(`/proc/<tid>/schedstat`: every stage under 4% of its run time waiting). The cause was the engine's
thread calling `malloc_trim(0)` after each window step: glibc walks every arena with that arena's
lock held, returning each free page, so every ingest worker, message thread and runtime worker that
allocated in an arena meanwhile waited for it, for seconds after a large step. MLAT ran below the
stages and its trim stopped them. Holding large blocks to their own mappings instead
(`M_MMAP_THRESHOLD` fixed at 128 KiB) moved the wait to the address space's lock (each free an
unmapping by a thread at nice 10) and slowed the window steps by half. Nothing now returns the
allocator's free pages on MLAT's behalf: it reuses them. Runs (2,000 feeders, MLAT on,
`--memory 16G`, three minutes measured with provisional positions read; relay on cores 0-9, harness
on 10-31):

| Build | Raw p99 per run (max) | Window steps measured | Resident peak |
| ----- | --------------------- | --------------------- | ------------- |
| `malloc_trim` after each window step | 2,456 ms (4,080), 440 (1,460), 64 (163) | 1, 5, 1 | 4.1 to 4.4 GB |
| 128 KiB mapping threshold, no trim | 67 ms (140), 1,846 (3,581) | 2, 2 | 6.4 to 6.7 GB |
| Neither | 64 ms (130), 33 (81), 56 (106), 29 (124) | 4, 4, 4, 4 | 5.0 to 5.1 GB |

Resident memory without the trim is what the arenas keep for reuse beside what the stores hold, a
fifth more at this load and well inside the plan's 16 GB.

**The deployed budgets** are `tally-relay check`'s to state, not this document's: the numbers move
with every store's plan, and a figure copied here is wrong the next time one does. Before any feeder
a relay plans its base (with MLAT's where it hosts MLAT), the oversize room
(`ingest::OVERSIZE_BYTES`), the Noise buffers of every connection but a feeder's its caps allow
(`ingest::BUFFERS_PER_CONNECTION` each), its members' pool and every other part the plan lists, each
on its own line of the plan and summed as `before-feeders`; a feeder then reserves `per-feeder`, and the budget keeps `headroom` below the memory it runs in. `bazel
test //tally/crates/relay:check //infra/tally:relay_config_test --test_output=all` prints the plan
of the packaged unit (as packaged, and with a base cell taken) and of each relay Flightlines
deploys, and holds each to its limit. Every new line of the plan cost the public relay feeders it
had been admitting without room for them (2026-10-08, as each landed): 107 before the members'
pool, 75 with it, 31 once the connections' buffers, the oversize room and a feeder's allowance in
bytes were planned, 27 once every member session its areas bring was, 25 once the batch byte store
planned the parities it holds beside its records (§6). Its caps were then set to admit 40 at least
(`relay.yaml`, THE CAPS); 34 once MLAT's sealed raw was reserved at the kept ceiling every receiver
is held to (`held::KEPT_CEILING_PER_S`, 300 a second) rather than its mean (2026-10-09, sweep 5 H-b),
so its limit was raised from 640 to 672 MiB, which admits 41 and still fits the node's 1,194 MiB
beside readsb and the API (`relay.yaml`, THE FIT).

**What the areas cost at rest.** Taking the 122 resolution-0 areas once cost 530 MiB and a whole
core with no feeder at all. As built: idle work follows activity, not the areas taken (`sharing`,
`directory`); the MLAT choice, the hosted engine's scope, standing's and an engine grant's band are
held as the fewest cells that cover them (`tally_wire::Regions`, membership by ancestor), so the
world is 122 cells and never its 41,162 areas; a band is found from its areas' edge
(`tally_mlat::area::Band`), and the world has none. A relay's own offers are the cells it takes at
their fewest, every one: a cap of 64 offers a key once cut the public relay to its first 64 cells,
so it offered and solved MLAT for about half the world. The cap is now a network group's
(`OFFERS_PER_KEY` = `OFFERS_PER_GROUP`, 256, at least the 122 base cells) and a relay whose areas
need more cells refuses to start (`directory::offerable`). Measured (2026-10-08, release build, the
deployed args): idle on four cores, 9.2 MiB resident and 0.3% of a core over 60 s (9.5 MiB and 0.4%
again once its 128 member sessions were planned, on a host at load 60); under
`tally-load` with 200 feeders offered and 107 admitted, 300 s, 391 MiB at its peak and 0.18 cores
mean, MLAT shedding nothing. It fits its 672 MiB limit.
