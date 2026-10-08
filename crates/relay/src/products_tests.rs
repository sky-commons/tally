//! The products' tests (RFC-0174 §2.11): the world product chosen alike by every relay from the
//! same records, each fix checkable against the record it cites, ADS-B and MLAT aircraft both in
//! it, one fix an aircraft a second; the regional product one copy of each message per area,
//! forwarded unchanged within the area's relays and cut by cell; and what both cost a second.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use tally_mlat_solver::modes::{self, LatLon};
use tally_wire::batch::{Hash, format};
use tally_wire::positions::{AddressedCitation, EnuCovariance, Solution, TransmitTime};
use tally_wire::rendezvous::area_of;
use tally_wire::{
    Batch, BatchContent, Clock, ClockModel, ClockModelContent, Decoded, Identity, Location,
    Observation, ObservationSet, Positions, PublicKey, ReceiverInfo, Reception, Record, Region,
    RegionalBatch, RegionalBatchContent, SolutionsContent, Streams, WireError, WorldPositions,
};

use super::{FORWARD_HELD, Products, WAITING_MS, WORLD_SETTLE_MS, check_fix, regional_fixes};
use crate::exchange::MessageExchange;
use crate::fanout::Filter;
use crate::hub::{Hub, Item};
use crate::ingest::Stamp;
use crate::network::{Asker, AskerRole};
use crate::subscription::Subscription;

/// The watermark passes `now`, with `relay` (when given) the products' key: what they signed.
fn tick(products: &Products, relay: Option<&Identity>, now: u64) -> Vec<Record> {
    if let Some(relay) = relay {
        products.adopt_identity(relay);
    }
    products.advance(now);
    products.tick(None)
}

/// Products fed as a relay feeds them: each batch's receptions through the message exchange's one
/// deduplication (inline: one shard thread, one producer), each epoch sealed as the watermark
/// passes it.
struct Staged {
    products: Arc<Products>,
    exchange: MessageExchange,
}

impl Staged {
    fn new(relay: &Identity) -> Self {
        let products = Arc::new(Products::new());
        products.adopt_identity(relay);
        let exchange =
            MessageExchange::inline(products.sink(), crate::exchange::Gauges::unlimited());
        Self { products, exchange }
    }

    /// A receiver's batch, decoded and stamped: into its area's regional product, if any.
    fn feed(&self, batch: &Arc<Decoded>) {
        let area = self.products.area_for(&batch.receiver());
        self.exchange
            .route(0, batch, area, crate::ingest::InFlight::free());
        self.exchange.tick(0, stamp(batch.stamp_ms()));
    }

    /// The watermark passes `now`: what the epochs before it sealed.
    fn tick(&self, now: u64) -> Vec<Record> {
        self.exchange.tick(0, stamp(now));
        self.products.tick(None)
    }
}

fn stamp(stamp_ms: u64) -> Stamp {
    Stamp {
        stamp_ms,
        ingest_seq: 0,
    }
}

/// 2026-10-04T00:00:00Z.
const BASE_MS: u64 = 1_791_244_800_000;

type Result<T> = std::result::Result<T, String>;

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn relay_asker(key: PublicKey) -> Asker {
    Asker {
        role: AskerRole::Relay,
        key,
        source: 7,
        loopback: false,
    }
}

/// When second `second`'s seal has come.
fn sealed_at(second: u64) -> u64 {
    (second + 1) * 1_000 + WORLD_SETTLE_MS
}

fn place(lat: f64, lon: f64) -> Location {
    Location {
        lat_e7: (lat * 1e7) as i32,
        lon_e7: (lon * 1e7) as i32,
        alt_m: 100,
        precision_m: 10,
    }
}

/// A DF17 airborne position (type code 11, barometric; or 20, GNSS height) at `position`.
fn airborne(address: u32, position: LatLon, odd: bool, gnss: bool) -> Vec<u8> {
    let (lat_cpr, lon_cpr) = modes::cpr_encode(position, odd);
    let (type_code, alt_field) = if gnss {
        (20, 10_000)
    } else {
        let ac13 = modes::encode_ac13_q(35_000).unwrap_or(0);
        (11, modes::ac13_to_ac12(ac13))
    };
    let me = modes::encode_airborne_position(type_code, alt_field, odd, lat_cpr, lon_cpr);
    let mut body = vec![
        (17 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    body.extend_from_slice(&me);
    modes::with_parity(&body, 0)
}

/// A DF11 all-call reply: what an MLAT target sends.
fn all_call(address: u32) -> Vec<u8> {
    let body = [
        (11 << 3) | 5,
        (address >> 16) as u8,
        (address >> 8) as u8,
        address as u8,
    ];
    modes::with_parity(&body, 0)
}

fn long(data: Vec<u8>, timestamp: u64) -> Observation {
    Observation {
        format: format::MODE_S_LONG,
        timestamp,
        signal: 40,
        data,
    }
}

/// Aircraft `n`'s position at second `second`: spread over the area about Atlanta, moving.
fn position_of(n: u32, second: u64) -> LatLon {
    LatLon {
        lat_deg: 33.0 + f64::from(n % 40) * 0.02 + (second % 100) as f64 * 1e-3,
        lon_deg: -84.6 + f64::from((n & 0xfff) / 40) * 0.02,
    }
}

/// One second of an area's ADS-B: each aircraft's even then odd position.
fn adsb_second(addresses: &[u32], second: u64, gnss: bool) -> Vec<Observation> {
    addresses
        .iter()
        .flat_map(|address| {
            let at = position_of(*address, second);
            [
                long(airborne(*address, at, false, gnss), u64::from(*address)),
                long(airborne(*address, at, true, gnss), u64::from(*address) + 1),
            ]
        })
        .collect()
}

fn regional(
    origin: &Identity,
    cell: Region,
    sequence: u64,
    wall_ms: u64,
    observations: Vec<Observation>,
) -> Result<RegionalBatch> {
    RegionalBatch::sign(
        origin,
        &RegionalBatchContent {
            cell,
            boot_id: 9,
            sequence,
            wall_ms,
            observations,
        },
    )
    .map_err(err)
}

/// An MLAT engine's model and a record of solutions under it, one per address at `ms`.
struct Mlat {
    engine: Identity,
    model: ClockModel,
    receivers: Vec<PublicKey>,
}

impl Mlat {
    fn new() -> Result<Self> {
        let engine = Identity::generate().map_err(err)?;
        let model = ClockModel::sign(
            &engine,
            &ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: BASE_MS,
                spec_version: 3,
                inputs: [0x5a; 32],
                model: vec![1, 2, 3, 4],
            },
        )
        .map_err(err)?
        .manifest;
        let receivers = (0..4)
            .map(|_| Identity::generate().map(|identity| identity.public()))
            .collect::<std::result::Result<_, _>>()
            .map_err(err)?;
        Ok(Self {
            engine,
            model,
            receivers,
        })
    }

    fn inputs_of(&self) -> impl Fn(&Hash) -> Option<Hash> + '_ {
        |id| (*id == self.model.id()).then_some([0x5a; 32])
    }

    fn solutions(
        &self,
        addresses: &[u32],
        ms: u64,
        sub_ms_ps: u32,
        provisional: bool,
        sequence: u64,
    ) -> Result<Positions> {
        let solutions = addresses
            .iter()
            .map(|address| {
                let receptions = self
                    .receivers
                    .iter()
                    .map(|receiver| Reception {
                        receiver: *receiver,
                        epoch: 0,
                        counter: (ms % 1_000_000) * 12_000 + u64::from(*address),
                    })
                    .collect();
                Ok(Solution {
                    address: *address,
                    transmitted: TransmitTime::new(ms, sub_ms_ps)?,
                    lat_e7: 337_000_000 + *address as i32,
                    lon_e7: -843_000_000,
                    alt_hae_mm: Some(9_000_000),
                    covariance: EnuCovariance {
                        xx: 900.0,
                        xy: 10.0,
                        xz: 0.0,
                        yy: 900.0,
                        yz: 0.0,
                        zz: 2_500.0,
                    },
                    clock_model: self.model.id(),
                    addressed: if provisional {
                        AddressedCitation::default()
                    } else {
                        AddressedCitation {
                            hash: [3; 32],
                            count: 4,
                        }
                    },
                    observations: ObservationSet::new(all_call(*address), receptions)?,
                })
            })
            .collect::<std::result::Result<Vec<_>, WireError>>()
            .map_err(err)?;
        let content = SolutionsContent {
            boot_id: 1,
            sequence,
            issued_ms: ms,
            spec_version: 3,
            solutions,
        };
        if provisional {
            Positions::sign_provisional(&self.engine, &content)
        } else {
            Positions::sign_solutions(&self.engine, &content)
        }
        .map_err(err)
    }
}

/// The records a world gatherer is shown in `world_inputs`, and the reader's index of them.
struct Inputs {
    regional: Vec<RegionalBatch>,
    positions: Vec<Positions>,
    mlat: Mlat,
    adsb: Vec<u32>,
    targets: Vec<u32>,
}

/// Two seconds of one area: ADS-B aircraft heard by two origins (each signing its own regional
/// batches, overlapping), and MLAT targets with a provisional and a final fix each second.
fn world_inputs(second: u64) -> Result<Inputs> {
    let cell = area_of(&place(33.7, -84.4)).map_err(err)?;
    let adsb: Vec<u32> = (0x00a0_0000..0x00a0_0000 + 60).collect();
    let targets: Vec<u32> = (0x00b0_0000..0x00b0_0000 + 12).collect();
    let mut regional_batches = Vec::new();
    for (n, origin) in [Identity::generate(), Identity::generate()]
        .into_iter()
        .enumerate()
    {
        let origin = origin.map_err(err)?;
        for offset in 0..2 {
            let at = second + offset;
            // The two origins seal at different milliseconds of the same second.
            let wall_ms = at * 1_000 + 300 + 200 * n as u64;
            // The second origin hears only half the aircraft.
            let heard = if n == 0 { &adsb[..] } else { &adsb[..30] };
            regional_batches.push(regional(
                &origin,
                cell,
                offset,
                wall_ms,
                adsb_second(heard, at, n == 1),
            )?);
        }
    }
    let mlat = Mlat::new()?;
    let mut positions = Vec::new();
    for offset in 0..2 {
        let ms = (second + offset) * 1_000;
        positions.push(mlat.solutions(&targets, ms + 100, 5, false, offset * 2)?);
        positions.push(mlat.solutions(&targets, ms + 900, 7, true, offset * 2 + 1)?);
        // A second provisional of the first half, earlier in the second: never the newest.
        positions.push(mlat.solutions(&targets[..6], ms + 50, 0, true, 100 + offset)?);
    }
    Ok(Inputs {
        regional: regional_batches,
        positions,
        mlat,
        adsb,
        targets,
    })
}

/// A gatherer shown `inputs` in the order `order` gives, ticked past both seconds' seals: what
/// it publishes.
fn gather(inputs: &Inputs, second: u64, reversed: bool) -> Result<(Identity, Vec<WorldPositions>)> {
    let relay = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?.public();
    let products = Products::new();
    products.set_world(true);
    let now = second * 1_000 + 1_500;
    let mut shown: Vec<Record> = inputs
        .regional
        .iter()
        .cloned()
        .map(Record::RegionalBatch)
        .chain(inputs.positions.iter().cloned().map(Record::Positions))
        .collect();
    if reversed {
        shown.reverse();
    } else {
        // The model first, so nothing waits for it.
        products.clock_model(&inputs.mlat.model, now);
    }
    for record in shown {
        match record {
            Record::RegionalBatch(batch) => {
                products.regional_from(&relay_asker(peer), batch, now);
            }
            Record::Positions(positions) => products.positions(&positions, now),
            _ => {}
        }
    }
    if reversed {
        // The model last (stamped after them, records are taken in by stamp): every solution
        // waited for it.
        products.clock_model(&inputs.mlat.model, now + 1);
    }
    let mut out = Vec::new();
    for record in tick(&products, Some(&relay), sealed_at(second + 1)) {
        if let Record::WorldPositions(world) = record {
            out.push(world);
        }
    }
    Ok((relay, out))
}

/// A signed record's body: its bytes without the signer's key and the signature.
fn body(world: &WorldPositions) -> Vec<u8> {
    let bytes = world.as_bytes();
    bytes[1 + 32..bytes.len() - 64].to_vec()
}

#[test]
fn two_relays_shown_the_same_records_choose_the_same_world_byte_for_byte() -> Result<()> {
    let second = BASE_MS / 1_000;
    let inputs = world_inputs(second)?;
    let (first_relay, first) = gather(&inputs, second, false)?;
    let (second_relay, other) = gather(&inputs, second, true)?;
    assert_ne!(first_relay.public(), second_relay.public());
    assert_eq!(first.len(), 2, "one part for each of the two seconds");
    assert_eq!(
        first.iter().map(body).collect::<Vec<_>>(),
        other.iter().map(body).collect::<Vec<_>>()
    );
    for world in first.iter().chain(&other) {
        world.verify().map_err(err)?;
    }
    Ok(())
}

#[test]
fn every_world_fix_checks_against_the_record_it_cites() -> Result<()> {
    let second = BASE_MS / 1_000;
    let inputs = world_inputs(second)?;
    let (_, world) = gather(&inputs, second, false)?;
    // What a reader subscribed to the area's regional and positions streams holds, by hash.
    let fetched: HashMap<Hash, Record> = inputs
        .regional
        .iter()
        .map(|batch| (batch.hash(), Record::RegionalBatch(batch.clone())))
        .chain(inputs.positions.iter().map(|positions| {
            let record = if positions.is_provisional() {
                Record::Provisional(positions.clone())
            } else {
                Record::Positions(positions.clone())
            };
            (positions.hash(), record)
        }))
        .collect();
    let mut checked = 0;
    for part in &world {
        for fix in part.content().map_err(err)?.fixes {
            let origin = fetched
                .get(&fix.origin)
                .ok_or("a world fix cites a record the reader cannot fetch")?;
            check_fix(&fix, origin, inputs.mlat.inputs_of()).map_err(err)?;
            // A fix moved by one unit no longer checks; nor one citing another record.
            let moved = tally_wire::WorldFix {
                lat_e7: fix.lat_e7 + 1,
                ..fix
            };
            assert!(check_fix(&moved, origin, inputs.mlat.inputs_of()).is_err());
            let elsewhere = fetched
                .values()
                .find(|record| match record {
                    Record::RegionalBatch(batch) => batch.hash() != fix.origin,
                    _ => false,
                })
                .ok_or("no other record")?;
            assert!(check_fix(&fix, elsewhere, inputs.mlat.inputs_of()).is_err());
            checked += 1;
        }
    }
    assert_eq!(checked, 2 * (inputs.adsb.len() + inputs.targets.len()));
    Ok(())
}

#[test]
fn adsb_and_mlat_aircraft_are_both_in_the_world_and_the_rule_picks_as_the_merge_rule_serves()
-> Result<()> {
    let second = BASE_MS / 1_000;
    let inputs = world_inputs(second)?;
    let (_, world) = gather(&inputs, second, false)?;
    let mut by_second: BTreeMap<u64, BTreeMap<u32, tally_wire::WorldFix>> = BTreeMap::new();
    for part in &world {
        let content = part.content().map_err(err)?;
        for fix in content.fixes {
            by_second
                .entry(content.second)
                .or_default()
                .insert(fix.address, fix);
        }
    }
    assert_eq!(by_second.len(), 2);
    for (at, fixes) in &by_second {
        for address in &inputs.adsb {
            let fix = fixes.get(address).ok_or("an ADS-B aircraft is missing")?;
            assert!(!fix.provisional);
            // Decoded where it was: within a metre or two of CPR's resolution.
            let truth = position_of(*address, *at);
            assert!((f64::from(fix.lat_e7) / 1e7 - truth.lat_deg).abs() < 1e-4);
            assert!((f64::from(fix.lon_e7) / 1e7 - truth.lon_deg).abs() < 1e-4);
            if *address < inputs.adsb[30] {
                // Heard by both origins: the later origin's batch (its signed wall clock is
                // the newer), which decodes the GNSS height.
                assert_eq!(fix.transmitted.unix_ms, at * 1_000 + 500);
                assert!(fix.alt_hae_mm.is_some());
            } else {
                assert_eq!(fix.transmitted.unix_ms, at * 1_000 + 300);
                assert_eq!(
                    fix.alt_hae_mm, None,
                    "a barometric altitude is not a height"
                );
            }
        }
        for address in &inputs.targets {
            let fix = fixes.get(address).ok_or("an MLAT target is missing")?;
            // The provisional at .900 is later than the final at .100: the merge rule serves it.
            assert!(fix.provisional);
            assert_eq!(fix.transmitted.unix_ms, at * 1_000 + 900);
        }
    }
    Ok(())
}

#[test]
fn no_aircraft_has_two_fixes_in_one_second_and_a_late_fix_is_dropped() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?.public();
    let origin = Identity::generate().map_err(err)?;
    let cell = area_of(&place(33.7, -84.4)).map_err(err)?;
    let products = Products::new();
    products.set_world(true);
    let mlat = Mlat::new()?;
    products.clock_model(&mlat.model, BASE_MS);
    let first = BASE_MS / 1_000;
    let addresses: Vec<u32> = (1..=20).collect();
    let mut published = Vec::new();
    let mut sequence = 0;
    // Ten seconds, each with four regional batches and three provisional records per aircraft,
    // ticked every 250 ms as the relay is.
    for step in 0..60 {
        let now = BASE_MS + step * 250;
        if step < 40 {
            let at = now / 1_000;
            products.regional_from(
                &relay_asker(peer),
                regional(
                    &origin,
                    cell,
                    sequence,
                    now,
                    adsb_second(&addresses, at, false),
                )?,
                now,
            );
            sequence += 1;
            for (n, offset) in [10, 400, 800].into_iter().enumerate() {
                let record = mlat.solutions(
                    &[0x00c0_0001, 0x00c0_0002],
                    at * 1_000 + offset,
                    0,
                    true,
                    sequence * 4 + n as u64,
                )?;
                products.positions(&record, now);
            }
        }
        for record in tick(&products, Some(&relay), now) {
            if let Record::WorldPositions(world) = record {
                published.push(world.content().map_err(err)?);
            }
        }
    }
    let mut seen = BTreeSet::new();
    for content in &published {
        for fix in &content.fixes {
            assert_eq!(fix.transmitted.unix_ms / 1_000, content.second);
            assert!(
                seen.insert((content.second, fix.address)),
                "two fixes for one aircraft in one second"
            );
        }
    }
    let seconds: BTreeSet<u64> = published.iter().map(|content| content.second).collect();
    assert_eq!(seconds, (first..first + 10).collect());
    assert_eq!(seen.len(), 10 * (addresses.len() + 2));
    // A fix for a second already sealed is late, and changes nothing published.
    let late = mlat.solutions(&[0x00c0_0003], first * 1_000 + 500, 0, false, 9_999)?;
    products.positions(&late, BASE_MS + 15_000);
    // Taken in once the watermark passes its stamp.
    let after = tick(&products, Some(&relay), BASE_MS + 15_250);
    assert_eq!(products.report().world_late, 1);
    assert!(
        !after
            .iter()
            .any(|record| matches!(record, Record::WorldPositions(_)))
    );
    Ok(())
}

/// A feeder's description naming `relays`, at `location`.
fn described(
    identity: &Identity,
    location: Location,
    relays: Vec<PublicKey>,
) -> Result<ReceiverInfo> {
    ReceiverInfo::sign(
        identity,
        &tally_wire::batch::ReceiverInfoContent {
            issued_ms: BASE_MS,
            location: Some(location),
            clock: Clock::Dump1090,
            software: "test".to_owned(),
            relays,
        },
    )
    .map_err(err)
}

/// A feeder's batch, taken in at `stamp_ms`, the `ingest_seq`th.
fn feeder_batch(
    identity: &Identity,
    sequence: u64,
    observations: Vec<Observation>,
    (stamp_ms, ingest_seq): (u64, u64),
) -> Result<Arc<Decoded>> {
    let batch = Batch::sign(
        identity,
        &BatchContent {
            boot_id: 1,
            sequence,
            counter_epoch: 0,
            wall_ms: BASE_MS,
            dropped: 0,
            previous: [0; 32],
            observations,
        },
    )
    .map_err(err)?;
    Decoded::from_verified(batch, stamp_ms, ingest_seq)
        .map_err(|undecodable| err(undecodable.error))
}

#[test]
fn the_regional_product_holds_one_copy_of_each_message_per_area_signed_as_origin() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let staged = Staged::new(&relay);
    let products = &staged.products;
    let atlanta = place(33.7, -84.4);
    let chicago = place(41.9, -87.6);
    let shared: Vec<Observation> = adsb_second(&[0x00a0_0001, 0x00a0_0002, 0x00a0_0003], 0, false);
    let mut feeders = Vec::new();
    for n in 0..10u64 {
        let feeder = Identity::generate().map_err(err)?;
        let location = if n < 8 { atlanta } else { chicago };
        // One Atlanta feeder chose other relays: not this relay's to originate.
        let relays = if n == 7 {
            vec![Identity::generate().map_err(err)?.public()]
        } else {
            vec![relay.public()]
        };
        products.described(&described(&feeder, location, relays)?);
        feeders.push(feeder);
    }
    for (n, feeder) in feeders.iter().enumerate() {
        let mut observations: Vec<Observation> = shared
            .iter()
            .map(|copy| Observation {
                // Each receiver's own counter and signal: the message is what is the same.
                timestamp: copy.timestamp + n as u64 * 1_000,
                signal: n as u8,
                ..copy.clone()
            })
            .collect();
        observations.push(long(all_call(0x00f0_0000 + n as u32), 1));
        let batch = feeder_batch(feeder, 0, observations, (BASE_MS + 100, n as u64))?;
        staged.feed(&batch);
    }
    let out = staged.tick(BASE_MS + 1_000);
    let batches: Vec<RegionalBatchContent> = out
        .iter()
        .filter_map(|record| match record {
            Record::RegionalBatch(batch) => Some(batch),
            _ => None,
        })
        .map(|batch| {
            batch.verify()?;
            assert_eq!(batch.signer()?, relay.public());
            batch.content()
        })
        .collect::<std::result::Result<_, _>>()
        .map_err(err)?;
    let cells: BTreeMap<u64, &RegionalBatchContent> = batches
        .iter()
        .map(|content| (content.cell.as_u64(), content))
        .collect();
    assert_eq!(cells.len(), 2, "one stream per area");
    let atlanta_cell = area_of(&atlanta).map_err(err)?;
    let chicago_cell = area_of(&chicago).map_err(err)?;
    for (cell, feeders_heard) in [(atlanta_cell, 0..7u32), (chicago_cell, 8..10u32)] {
        let content = cells.get(&cell.as_u64()).ok_or("an area has no batch")?;
        let mut messages: Vec<&[u8]> = content
            .observations
            .iter()
            .map(|copy| copy.data.as_slice())
            .collect();
        let count = messages.len();
        messages.sort();
        messages.dedup();
        assert_eq!(messages.len(), count, "a message twice in one area");
        // The shared messages once, and each feeder's own reply.
        assert_eq!(count, shared.len() + feeders_heard.len());
        let feeder_seven = all_call(0x00f0_0007);
        assert!(!messages.contains(&feeder_seven.as_slice()));
    }
    // Heard again within the window (the next epoch): nothing new to sign. After it: once more.
    let again = feeder_batch(&feeders[0], 1, shared.clone(), (BASE_MS + 1_500, 10))?;
    staged.feed(&again);
    assert!(staged.tick(BASE_MS + 2_000).is_empty());
    let later = feeder_batch(&feeders[0], 2, shared.clone(), (BASE_MS + 4_000, 11))?;
    staged.feed(&later);
    let out = staged.tick(BASE_MS + 5_000);
    // The epoch's deduplicated stream first, then its one area's regional batch.
    assert_eq!(out.len(), 2);
    match &out[0] {
        Record::RelayBatch(batch) => {
            batch.verify_as_relay().map_err(err)?;
            assert_eq!(
                batch.content().map_err(err)?.observations.len(),
                shared.len()
            );
        }
        _ => return Err("not the deduplicated stream".to_owned()),
    }
    // The regional stream's sequence runs on from the first two.
    match &out[1] {
        Record::RegionalBatch(batch) => assert_eq!(batch.content().map_err(err)?.sequence, 2),
        _ => return Err("not a regional batch".to_owned()),
    }
    Ok(())
}

#[test]
fn a_peer_regional_batch_is_forwarded_once_unchanged_within_the_areas_taken() -> Result<()> {
    let origin = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?.public();
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let chicago = area_of(&place(41.9, -87.6)).map_err(err)?;
    let products = Products::new();
    products.set_taken(vec![atlanta]);
    let now = BASE_MS + 100;
    let taken = regional(&origin, atlanta, 0, BASE_MS, adsb_second(&[1, 2], 0, false))?;
    let not_taken = regional(&origin, chicago, 1, BASE_MS, adsb_second(&[3], 0, false))?;
    let stale = regional(
        &origin,
        atlanta,
        2,
        BASE_MS - 120_000,
        adsb_second(&[4], 0, false),
    )?;
    let mut forged_bytes = taken.as_bytes().to_vec();
    let last = forged_bytes.len() - 1;
    forged_bytes[last] ^= 1;
    let forged = RegionalBatch::from_bytes(forged_bytes).map_err(err)?;
    let client = Asker {
        role: AskerRole::Client,
        ..relay_asker(peer)
    };
    for (asker, batch) in [
        (client, taken.clone()),
        (relay_asker(peer), forged),
        (relay_asker(peer), taken.clone()),
        (relay_asker(peer), taken.clone()),
        (relay_asker(peer), not_taken),
        (relay_asker(peer), stale),
    ] {
        assert!(products.regional_from(&asker, batch, now).is_empty());
    }
    // The sealer takes them in once the watermark passes their stamp.
    products.advance(now + 1);
    let out = products.take_forward();
    let came_on = relay_asker(peer).source;
    assert_eq!(out, vec![(came_on, taken.clone())]);
    assert_eq!(products.report().regional_forwarded, 1);
    assert_eq!(products.report().regional_stale, 1);
    // Heard back from another peer: already forwarded.
    products.regional_from(&relay_asker(peer), taken, now + 50);
    products.advance(now + 51);
    assert!(products.take_forward().is_empty());
    Ok(())
}

#[test]
fn the_products_are_routed_by_their_stream_bits_and_the_regional_by_its_cell() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let chicago = area_of(&place(41.9, -87.6)).map_err(err)?;
    let batch = regional(&relay, atlanta, 0, BASE_MS, adsb_second(&[1], 0, false))?;
    // The hub routes the relay's own regional batch by the cell it signed.
    let hub = Hub::new(4);
    let listener = hub.listen(u64::MAX, Filter::Everything);
    hub.publish_own(Record::RegionalBatch(batch.clone()));
    let item = listener.try_recv().ok_or("nothing routed")?;
    assert_eq!(item.cell, Some(atlanta));
    let world = super::world_parts(
        &relay,
        BASE_MS / 1_000,
        regional_fixes(&batch).map_err(err)?,
    )
    .pop()
    .ok_or("no world part")?;
    let world_item = Item {
        source: 0,
        record: Arc::new(Record::WorldPositions(world)),
        cell: None,
        points: None,
        decoded: None,
        stamp_ms: 0,
    };
    let wants = |streams: Streams, regions: Vec<Region>, item: &Item| {
        Subscription { streams, regions }.wants(item)
    };
    assert!(wants(Streams::REGIONAL, vec![atlanta], &item));
    assert!(wants(Streams::REGIONAL, Vec::new(), &item));
    assert!(!wants(Streams::REGIONAL, vec![chicago], &item));
    assert!(!wants(
        Streams::RAW.with(Streams::POSITIONS),
        vec![atlanta],
        &item
    ));
    assert!(!wants(Streams::WORLD, Vec::new(), &item));
    assert!(wants(Streams::WORLD, Vec::new(), &world_item));
    assert!(wants(Streams::WORLD, vec![chicago], &world_item));
    assert!(!wants(
        Streams::REGIONAL.with(Streams::POSITIONS),
        Vec::new(),
        &world_item
    ));
    assert!(!crate::subscription::directory_wants(&item));
    assert!(!crate::subscription::directory_wants(&world_item));
    Ok(())
}

#[test]
fn a_regional_batch_yields_one_fix_an_aircraft_decoded_from_a_pair_in_it() -> Result<()> {
    let origin = Identity::generate().map_err(err)?;
    let cell = area_of(&place(33.7, -84.4)).map_err(err)?;
    let at = position_of(5, 0);
    let mut observations = vec![
        // A lone odd position before any even one: no pair yet.
        long(airborne(5, at, true, false), 0),
        long(airborne(5, at, false, false), 1),
        long(all_call(5), 2),
        long(airborne(5, at, true, false), 3),
        // An aircraft heard only in one parity: no fix.
        long(airborne(6, at, false, false), 4),
    ];
    // A damaged message is no position.
    let mut damaged = airborne(7, at, false, false);
    damaged[6] ^= 0x10;
    observations.push(long(damaged, 5));
    observations.push(long(airborne(7, at, true, false), 6));
    let batch = regional(&origin, cell, 0, BASE_MS, observations)?;
    let fixes = regional_fixes(&batch).map_err(err)?;
    assert_eq!(fixes.len(), 1);
    assert_eq!(fixes[0].address, 5);
    // The newest position in the record, paired with the even one before it.
    assert_eq!(fixes[0].origin_index, 3);
    assert_eq!(fixes[0].origin, batch.hash());
    assert_eq!(
        fixes[0].transmitted,
        TransmitTime::new(BASE_MS, 0).map_err(err)?
    );
    Ok(())
}

/// Bytes on the wire (the record framed) of `records`.
fn wire_bytes<'a>(records: impl IntoIterator<Item = &'a Record>) -> Result<usize> {
    let mut total = 0;
    for record in records {
        let mut out = Vec::new();
        record.encode(&mut out).map_err(err)?;
        total += out.len();
    }
    Ok(total)
}

/// Seconds in a 30-day month, for TB a month.
const MONTH_S: f64 = 30.0 * 86_400.0;

/// What the products cost a second, measured through the relay's own paths: a busy area as an
/// origin signs it, and the world as a gatherer publishes it. Run with `--nocapture` to read it.
#[test]
fn what_a_busy_area_and_the_world_cost_a_second() -> Result<()> {
    // A busy area: 300 aircraft, each a second two positions, a velocity, an identification
    // every five seconds (long) and four Mode S replies (short), heard by 30 feeders each.
    const AIRCRAFT: u32 = 300;
    const FEEDERS: usize = 30;
    const SECONDS: u64 = 5;
    let relay = Identity::generate().map_err(err)?;
    let staged = Staged::new(&relay);
    let products = &staged.products;
    let location = place(33.7, -84.4);
    let feeders: Vec<Identity> = (0..FEEDERS)
        .map(|_| Identity::generate())
        .collect::<std::result::Result<_, _>>()
        .map_err(err)?;
    for feeder in &feeders {
        products.described(&described(feeder, location, vec![relay.public()])?);
    }
    let addresses: Vec<u32> = (0x00a1_0000..0x00a1_0000 + AIRCRAFT).collect();
    let mut regional_records = Vec::new();
    for second in 0..SECONDS {
        let at = BASE_MS / 1_000 + second;
        let mut heard = adsb_second(&addresses, at, false);
        for address in &addresses {
            // A velocity (TC 19) and, every fifth second, an identification (TC 4), as bytes.
            let mut body = vec![(17 << 3) | 5, (address >> 16) as u8, (address >> 8) as u8];
            body.push(*address as u8);
            body.extend_from_slice(&[19 << 3 | 1, 0, (at % 256) as u8, 0, 0, 0, 0]);
            heard.push(long(modes::with_parity(&body, 0), 0));
            if at % 5 == u64::from(*address % 5) {
                body[4] = 4 << 3;
                heard.push(long(modes::with_parity(&body, 0), 0));
            }
            for reply in 0..4u8 {
                let body = [4 << 3, 0, reply, (at % 256) as u8];
                heard.push(Observation {
                    format: format::MODE_S_SHORT,
                    timestamp: 0,
                    signal: 30,
                    data: modes::with_parity(&body, *address),
                });
            }
        }
        let unique = heard.len();
        for (n, feeder) in feeders.iter().enumerate() {
            let batch = feeder_batch(feeder, second, heard.clone(), (at * 1_000 + n as u64, 0))?;
            staged.feed(&batch);
        }
        let sealed: Vec<Record> = staged
            .tick((at + 1) * 1_000)
            .into_iter()
            .filter(|record| matches!(record, Record::RegionalBatch(_)))
            .collect();
        let copies: usize = sealed
            .iter()
            .map(|record| match record {
                Record::RegionalBatch(batch) => batch
                    .content()
                    .map_or(0, |content| content.observations.len()),
                _ => 0,
            })
            .sum();
        assert_eq!(
            copies, unique,
            "one copy of each message heard by {FEEDERS} feeders"
        );
        regional_records.extend(sealed);
    }
    let regional_per_s = wire_bytes(&regional_records)? as f64 / SECONDS as f64;

    // The world: 12,000 ADS-B aircraft (regional batches from every area) and 5,400 MLAT targets
    // (provisional and final records), gathered over five seconds.
    const WORLD_ADSB: u32 = 12_000;
    const WORLD_TARGETS: u32 = 5_400;
    let gatherer = Products::new();
    gatherer.set_world(true);
    let peer = Identity::generate().map_err(err)?.public();
    let origin = Identity::generate().map_err(err)?;
    let mlat = Mlat::new()?;
    gatherer.clock_model(&mlat.model, BASE_MS);
    // Running already: what was due before is sealed, so a final fix 30 s late is late.
    tick(&gatherer, Some(&relay), BASE_MS - 500);
    let cell = area_of(&location).map_err(err)?;
    let adsb: Vec<u32> = (0x0040_0000..0x0040_0000 + WORLD_ADSB).collect();
    let targets: Vec<u32> = (0x0080_0000..0x0080_0000 + WORLD_TARGETS).collect();
    let mut world = Vec::new();
    let mut sequence = 0;
    for second in 0..SECONDS + 6 {
        let at = BASE_MS / 1_000 + second;
        let now = at * 1_000 + 500;
        if second < SECONDS {
            for chunk in adsb.chunks(1_000) {
                let batch = regional(&origin, cell, sequence, now, adsb_second(chunk, at, false))?;
                sequence += 1;
                gatherer.regional_from(&relay_asker(peer), batch, now);
            }
            for (n, chunk) in targets.chunks(100).enumerate() {
                let n = n as u64;
                gatherer.positions(
                    &mlat.solutions(chunk, at * 1_000 + 200, 0, true, sequence * 1_000 + 2 * n)?,
                    now,
                );
                gatherer.positions(
                    &mlat.solutions(
                        chunk,
                        at * 1_000 - 30_000,
                        0,
                        false,
                        sequence * 1_000 + 2 * n + 1,
                    )?,
                    now,
                );
            }
        }
        world.extend(
            tick(&gatherer, Some(&relay), now)
                .into_iter()
                .filter(|record| matches!(record, Record::WorldPositions(_))),
        );
    }
    let fixes: usize = world
        .iter()
        .map(|record| match record {
            Record::WorldPositions(world) => {
                world.content().map_or(0, |content| content.fixes.len())
            }
            _ => 0,
        })
        .sum();
    assert_eq!(
        fixes,
        SECONDS as usize * (WORLD_ADSB + WORLD_TARGETS) as usize
    );
    let world_per_s = wire_bytes(&world)? as f64 / SECONDS as f64;
    let per_fix = wire_bytes(&world)? as f64 / fixes as f64;
    eprintln!(
        "regional product, busy area ({AIRCRAFT} aircraft, {FEEDERS} feeders each): \
         {:.1} KB/s, {:.3} TB/month",
        regional_per_s / 1e3,
        regional_per_s * MONTH_S / 1e12
    );
    eprintln!(
        "world product ({WORLD_ADSB} ADS-B + {WORLD_TARGETS} MLAT aircraft): {:.2} MB/s, \
         {:.2} TB/month, {per_fix:.1} bytes a fix",
        world_per_s / 1e6,
        world_per_s * MONTH_S / 1e12
    );
    // One fix an aircraft a second, and a fix is about 88 bytes: its time within the record's
    // second and its origin as an index into the record's table of origins.
    assert!((80.0..100.0).contains(&per_fix));
    Ok(())
}

/// The two world products (RFC-0174 §2.11), each opt-in: the live one seals a second
/// `WORLD_SETTLE_MS` after it ends and draws an MLAT aircraft by its provisional fix; the precise
/// one seals `WORLD_PRECISE_SETTLE_MS` after it ends and takes only final fixes, ADS-B as the live
/// one. Each is its own record, under its own signing domain, and costs what the live one does.
#[test]
fn the_precise_world_waits_for_finals_and_takes_no_provisional() -> Result<()> {
    let second = BASE_MS / 1_000;
    let inputs = world_inputs(second)?;
    let relay = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?.public();
    let products = Products::new();
    products.set_world(true);
    products.set_world_precise(true);
    let now = second * 1_000 + 1_500;
    products.clock_model(&inputs.mlat.model, now);
    for batch in &inputs.regional {
        products.regional_from(&relay_asker(peer), batch.clone(), now);
    }
    for positions in &inputs.positions {
        products.positions(positions, now);
    }
    let live_at = sealed_at(second + 1);
    let early = tick(&products, Some(&relay), live_at);
    assert!(early.iter().any(|r| matches!(r, Record::WorldPositions(_))));
    assert!(!early.iter().any(|r| matches!(r, Record::WorldPrecise(_))));
    // Not before its seal: (second + 2) * 1000 + WORLD_PRECISE_SETTLE_MS for both seconds.
    let before = (second + 1) * 1_000 + super::WORLD_PRECISE_SETTLE_MS - 1;
    assert!(
        !tick(&products, Some(&relay), before)
            .iter()
            .any(|r| matches!(r, Record::WorldPrecise(_)))
    );
    let sealed = tick(
        &products,
        Some(&relay),
        (second + 2) * 1_000 + super::WORLD_PRECISE_SETTLE_MS,
    );
    let mut precise = Vec::new();
    let mut bytes = 0;
    for record in &sealed {
        if let Record::WorldPrecise(world) = record {
            world.verify().map_err(err)?;
            // Its own domain: a precise record is no live one.
            let as_live = WorldPositions::from_bytes(world.as_bytes().to_vec()).map_err(err)?;
            assert!(as_live.verify().is_err());
            bytes += world.as_bytes().len();
            precise.extend(world.content().map_err(err)?.fixes);
        }
    }
    assert!(!precise.is_empty());
    assert!(precise.iter().all(|fix| !fix.provisional));
    for address in &inputs.targets {
        // The final at .100 of each second, never the later provisional.
        assert!(
            precise
                .iter()
                .filter(|fix| fix.address == *address)
                .all(|fix| fix.transmitted.unix_ms % 1_000 == 100)
        );
    }
    let per_fix = bytes as f64 / precise.len() as f64;
    eprintln!(
        "precise world: {} fixes in {bytes} bytes, {per_fix:.1} bytes a fix",
        precise.len()
    );
    assert_eq!(
        crate::credit::cost(tally_wire::Streams::WORLD_PRECISE, &[]),
        crate::credit::cost(tally_wire::Streams::WORLD, &[])
    );
    Ok(())
}

/// Nothing the products let go is let go silently (every drop counted by why, and served on
/// `--stats-listen`): a world fix outside the window the relay holds, positions whose model never
/// came, an epoch a message thread's part of was lost (refused whole, every product of it), and
/// peers' regional batches beyond what waits to be forwarded.
#[test]
fn every_drop_is_counted_by_why() -> Result<()> {
    let products = Products::new();
    products.set_world(true);
    let mlat = Mlat::new()?;
    // A fix a minute ahead of the relay's clock, under a model it holds: outside the window.
    products.clock_model(&mlat.model, BASE_MS);
    let ahead = mlat.solutions(&[0x00c0_0001], BASE_MS + 60_000, 0, true, 1)?;
    products.positions(&ahead, BASE_MS);
    products.advance(BASE_MS + 1);
    assert_eq!(products.report().world_out_of_window, 1);
    // Positions under a model never shown: they wait, then expire, counted.
    let other = Mlat::new()?;
    let waiting = other.solutions(&[0x00c0_0002], BASE_MS, 0, false, 2)?;
    products.positions(&waiting, BASE_MS);
    // Handed in after the watermark passed `BASE_MS + 1`, it is stamped there, never earlier, so
    // it waits from then: still waiting a full `WAITING_MS` later, expired just after.
    let stamped = BASE_MS + 1;
    tick(&products, None, stamped + WAITING_MS);
    assert_eq!(products.report().positions_waiting_expired, 0);
    tick(&products, None, stamped + WAITING_MS + 1);
    assert_eq!(products.report().positions_waiting_expired, 1);
    // An epoch gathered from two message threads, one of whose parts was lost: refused whole.
    let refusing = Arc::new(Products::with_boot(1, 2));
    let part = |epoch, thread, seq| crate::exchange::Frozen {
        thread,
        seq,
        epoch: Some(epoch),
        closed_before: epoch + 1,
        ..crate::exchange::Frozen::default()
    };
    let sink = refusing.sink();
    // Thread 1's part of epoch 6 (its second message) never came.
    for (epoch, thread, seq) in [(5, 0, 0), (5, 1, 0), (6, 0, 1), (7, 0, 2), (7, 1, 2)] {
        assert!(sink(part(epoch, thread, seq)).is_ok());
    }
    assert_eq!(refusing.report().epochs_refused, 1);
    // Peers' regional batches past what waits to be forwarded.
    let origin = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?.public();
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    products.set_taken(vec![atlanta]);
    // Past the watermark already taken (a record is never stamped before it).
    let now = stamped + WAITING_MS + 2;
    for sequence in 0..=FORWARD_HELD as u64 {
        let batch = regional(&origin, atlanta, sequence, now - 100, Vec::new())?;
        products.regional_from(&relay_asker(peer), batch, now);
    }
    products.advance(now + 1);
    assert_eq!(products.report().regional_forward_full, 1);
    assert_eq!(products.take_forward().len(), FORWARD_HELD);
    Ok(())
}

/// RFC-0181 §10 and invariant 1 for the records that are not epochs: they wait in a queue of their
/// own, so a peer flooding them is refused (counted) and never costs this relay an epoch; and a
/// world candidate is in time or late by its stamp against the watermark that seals its second,
/// never by when it was handled: two candidates handed in together, before that watermark is
/// reached, one stamped before it and one at it, are the first in time and the second late.
#[test]
fn records_wait_apart_from_the_epochs_and_are_taken_in_by_stamp() -> Result<()> {
    // The flood: more records than wait, stamped far ahead so none is taken in.
    let products = Arc::new(Products::with_boot(1, 1));
    products.on_thread(1, None)?;
    let mlat = Mlat::new()?;
    let flood = mlat.solutions(&[0x00c0_0001], BASE_MS, 0, true, 1)?;
    for _ in 0..super::RECORDS_HELD + 10 {
        products.positions(&flood, BASE_MS + 1_000_000);
    }
    let sink = products.sink();
    for closed_before in 1..=100 {
        let marker = crate::exchange::Frozen {
            closed_before,
            ..crate::exchange::Frozen::default()
        };
        assert!(
            sink(marker).is_ok(),
            "an epoch's word refused behind a flood of records"
        );
    }
    let started = std::time::Instant::now();
    while products.watermark_ms() < 100 * crate::seal::EPOCH_MS {
        if started.elapsed() > std::time::Duration::from_secs(60) {
            return Err("the sealer never took the epochs".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let report = products.report();
    assert_eq!((report.records_refused, report.epochs_refused), (10, 0));

    // By stamp: second `s` seals once the watermark reaches `(s + 1) s + WORLD_SETTLE_MS`.
    let relay = Identity::generate().map_err(err)?;
    let products = Products::new();
    products.set_world(true);
    let mlat = Mlat::new()?;
    let second = BASE_MS / 1_000;
    let seals = sealed_at(second);
    products.clock_model(&mlat.model, BASE_MS);
    let in_time = mlat.solutions(&[0x00c0_0001], BASE_MS + 100, 0, true, 1)?;
    let late = mlat.solutions(&[0x00c0_0002], BASE_MS + 200, 0, true, 2)?;
    products.positions(&late, seals);
    products.positions(&in_time, seals - 1);
    let mut addresses = Vec::new();
    for now in [seals, seals + 1] {
        for record in tick(&products, Some(&relay), now) {
            if let Record::WorldPositions(world) = record {
                let content = world.content().map_err(err)?;
                addresses.extend(
                    content
                        .fixes
                        .iter()
                        .map(|fix| (content.second, fix.address)),
                );
            }
        }
    }
    assert_eq!(addresses, vec![(second, 0x00c0_0001)]);
    assert_eq!(products.report().world_late, 1);
    Ok(())
}
