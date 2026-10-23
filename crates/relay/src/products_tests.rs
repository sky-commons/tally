//! The products' tests (RFC-0174 §2.11): the world product chosen alike by every relay from the
//! same records, each fix checkable against the record it cites, ADS-B and MLAT aircraft both in
//! it, one fix an aircraft a second; the regional product one copy of each message per area,
//! forwarded unchanged within the area's relays and cut by cell; and what both cost a second.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use tally_wire::clocks::recorded::aligned;

use tally_mlat_solver::modes::{self, LatLon};
use tally_wire::batch::{Hash, format};
use tally_wire::positions::{AddressedCitation, EnuCovariance, Solution, TransmitTime};
use tally_wire::rendezvous::area_of;
use tally_wire::{
    BatchContent, Clock, ClockModel, ClockModelContent, Decoded, Identity, Location, Observation,
    ObservationSet, Positions, PublicKey, ReceiverInfo, Reception, Record, Region, RegionalBatch,
    RegionalBatchContent, SolutionsContent, Streams, WireError, WorldPositions,
};

use super::{FORWARD_HELD, Products, WAITING_MS, WORLD_SETTLE_MS, check_fix, regional_fixes};
use crate::exchange::MessageExchange;
use crate::fanout::Filter;
use crate::hub::{Hub, Item};
use crate::ingest::Stamp;
use crate::network::{Asker, AskerRole};
use crate::sharing::groups::GroupKey;
use crate::subscription::Subscription;

/// The watermark passes `now`, with `relay` (when given) the products' key: what they signed.
fn tick(products: &Products, relay: Option<&Identity>, now: u64) -> Vec<Record> {
    if let Some(relay) = relay {
        products.adopt_identity(crate::signer::twin(relay));
    }
    products.advance(stamp(now));
    products.tick()
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
        Self::signed_by(&crate::signer::synced(crate::signer::twin(relay)))
    }

    /// As `new`, signing by `signer`.
    fn signed_by(signer: &crate::signer::Signer) -> Self {
        let products = Arc::new(Products::new());
        products.adopt_signer(signer);
        let exchange =
            MessageExchange::inline(products.sink(), crate::exchange::Gauges::unlimited());
        Self { products, exchange }
    }

    /// A receiver's batch, decoded and stamped: into its area's regional product, if any.
    fn feed(&self, batch: &Arc<Decoded>) {
        let area = self.products.area_for(&batch.receiver());
        self.exchange
            .route(0, batch, area, stamp(batch.stamp_ms()).raw());
        self.exchange.tick(0, stamp(batch.stamp_ms()));
    }

    /// The watermark passes `now`: what the epochs before it sealed.
    fn tick(&self, now: u64) -> Vec<Record> {
        self.exchange.tick(0, stamp(now));
        self.products.tick()
    }
}

fn stamp(stamp_ms: u64) -> Stamp {
    Stamp::recorded(stamp_ms, 0, stamp_ms, stamp_ms, true)
}

/// 2026-10-04T00:00:00Z.
const BASE_MS: u64 = 1_791_244_800_000;

/// The session a test's peer records are handed in by (the hub's id of its connection).
const PEER: u64 = 7;

type Result<T> = std::result::Result<T, String>;

/// A regional batch checked, as its intake checks it before the products take it in.
fn verified(batch: RegionalBatch) -> Result<crate::products::Verified> {
    crate::products::Verified::of(batch)
        .ok_or_else(|| "a regional batch that does not verify".into())
}

fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn relay_asker(key: PublicKey) -> Asker {
    Asker {
        role: AskerRole::Relay,
        key,
        source: PEER,
        loopback: false,
        address: None,
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
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
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
        products.clock_model(&inputs.mlat.model, PEER, stamp(now));
    }
    for record in shown {
        match record {
            Record::RegionalBatch(batch) => {
                products.regional_from(&relay_asker(peer), verified(batch)?, stamp(now));
            }
            Record::Positions(positions) => products.positions(&positions, PEER, stamp(now)),
            _ => {}
        }
    }
    if reversed {
        // The model last (stamped after them, records are taken in by stamp): every solution
        // waited for it.
        products.clock_model(&inputs.mlat.model, PEER, stamp(now + 1));
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

/// The watermark is published with the judging clock at it, read off the tick the sealer took
/// (`Stamp::judging`), as one pair: a host whose judging clock stands a minute ahead of its
/// monotonic one publishes each watermark a minute ahead on the judging side, whatever the live
/// clock reads as it is asked, so the same stamped trace steps the hosted MLAT alike. Before,
/// the judging time was read beside the watermark in a separate read of the live offset.
#[test]
fn the_watermark_is_published_with_the_judging_clock_of_its_tick() -> Result<()> {
    let products = Arc::new(Products::new());
    let sink = products.sink();
    let ahead = 60_000;
    for closed_before in 1..=3 {
        let end = closed_before * crate::seal::EPOCH_MS;
        let marker = crate::exchange::Frozen {
            closed_before,
            judged: Some(Stamp::recorded(end, 0, end + ahead, end, true)),
            ..crate::exchange::Frozen::default()
        };
        sink(marker).map_err(|_| "an epoch's word refused".to_owned())?;
        let started = std::time::Instant::now();
        while products.watermark_ms() < end {
            if started.elapsed() > std::time::Duration::from_secs(60) {
                return Err("the sealer never took the epoch".to_owned());
            }
            std::thread::yield_now();
        }
        let watermark = products.watermark().judging_at().ok_or("not judging")?;
        assert_eq!(
            watermark.judged().ms(),
            watermark.mono().ms() + ahead,
            "{watermark:?}"
        );
    }
    Ok(())
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
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
    products.set_world(true);
    let mlat = Mlat::new()?;
    products.clock_model(&mlat.model, PEER, stamp(BASE_MS));
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
                verified(regional(
                    &origin,
                    cell,
                    sequence,
                    now,
                    adsb_second(&addresses, at, false),
                )?)?,
                stamp(now),
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
                products.positions(&record, PEER, stamp(now));
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
    products.positions(&late, PEER, stamp(BASE_MS + 15_000));
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
    let batch = crate::anchors::anchored(
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
    Decoded::from_verified(batch, aligned(stamp_ms), ingest_seq)
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
        products.described(&described(&feeder, location, relays)?, Some(location));
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
    // The epoch's deduplicated stream first, then its one area's regional batch and its client
    // form: the same receptions, counters stripped, signed by the same origin.
    assert_eq!(out.len(), 3);
    match (&out[1], &out[2]) {
        (Record::RegionalBatch(regional), Record::ClientRegionalBatch(client)) => {
            let regional = regional.content().map_err(err)?;
            assert_eq!(client.content().map_err(err)?, regional.for_clients());
        }
        _ => return Err("no client form after the regional batch".to_owned()),
    }
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

/// An ACARS-family message a feeder publishes is in none of the products: not the deduplicated
/// stream, not the regional product, and so no client form of any record a client is sent. It
/// leaves the relay by `--acars-out` alone (`link::LocalOutput::Acars`). A relay that predates it
/// put every reception of a batch it read into its products; it reads only batch formats 1 and 2,
/// and the message travels in neither.
/// RFC-0171 §3.6: nothing the relay signs is signed by a clock not synced, since a product's
/// time is that clock's. While the relay's clock is unsynced (`signer::Signer::with`), an epoch
/// seals to nothing signed, counted (`unsynced_seals`); once it is synced the next epoch is signed
/// as ever. Before, the products signed whatever the clock read.
#[test]
fn nothing_is_signed_while_the_relays_clock_is_unsynced() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let clock = crate::clock::RelayClock::scripted(Arc::new(|| BASE_MS));
    let staged = Staged::signed_by(&crate::signer::on(
        crate::signer::twin(&relay),
        clock.clone(),
    ));
    let products = &staged.products;
    let atlanta = place(33.7, -84.4);
    let feeder = Identity::generate().map_err(err)?;
    products.described(
        &described(&feeder, atlanta, vec![relay.public()])?,
        Some(atlanta),
    );
    let signed = |out: &[Record]| {
        out.iter()
            .filter(|record| matches!(record, Record::RegionalBatch(_) | Record::RelayBatch(_)))
            .count()
    };
    clock.set_error(None);
    let first = feeder_batch(
        &feeder,
        0,
        adsb_second(&[0x00a0_0001], 0, false),
        (BASE_MS + 100, 0),
    )?;
    staged.feed(&first);
    let out = staged.tick(BASE_MS + 1_000);
    assert_eq!(signed(&out), 0, "signed while unsynced");
    assert!(products.report().unsynced_seals >= 1);
    clock.set_error(Some(5));
    let second = feeder_batch(
        &feeder,
        1,
        adsb_second(&[0x00a0_0002], 1, false),
        (BASE_MS + 1_100, 1),
    )?;
    staged.feed(&second);
    let out = staged.tick(BASE_MS + 2_000);
    assert!(signed(&out) >= 1, "nothing signed once synced");
    Ok(())
}

#[test]
fn no_product_and_no_client_carries_an_acars_message() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let staged = Staged::new(&relay);
    let feeder = Identity::generate().map_err(err)?;
    let atlanta = place(33.7, -84.4);
    staged.products.described(
        &described(&feeder, atlanta, vec![relay.public()])?,
        Some(atlanta),
    );
    let acars = br#"{"kind":"acars","label":"H1","t":1791244800,"text":"HELLO"}"#;
    let message = Observation {
        format: format::ACARS_JSON,
        timestamp: 5,
        signal: 0,
        data: acars.to_vec(),
    };
    let lines = feeder_batch(&feeder, 1, vec![message], (BASE_MS + 100, 1))?;
    let older = [
        tally_wire::batch::BATCH_FORMAT,
        tally_wire::batch::BATCH_FORMAT_DEFLATE,
    ];
    assert!(!older.contains(&lines.batch().format()));
    let adsb = adsb_second(&[0x00a0_0001], 0, false);
    staged.feed(&feeder_batch(&feeder, 0, adsb, (BASE_MS + 100, 0))?);
    staged.feed(&lines);
    let out = staged.tick(BASE_MS + 1_000);
    let kinds: Vec<u8> = out.iter().map(Record::kind).collect();
    assert!(
        out.iter()
            .any(|record| matches!(record, Record::ClientRegionalBatch(_))),
        "{kinds:?}"
    );
    for record in &out {
        let mut bytes = Vec::new();
        record.encode(&mut bytes).map_err(err)?;
        assert!(
            !bytes.windows(acars.len()).any(|at| at == acars),
            "kind {} carries the message",
            record.kind()
        );
        if let Some(client) = crate::outbound::client_form(record) {
            let mut bytes = Vec::new();
            Record::from((*client).clone())
                .encode(&mut bytes)
                .map_err(err)?;
            assert!(!bytes.windows(acars.len()).any(|at| at == acars));
        }
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
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
    products.set_taken(vec![atlanta]);
    let now = BASE_MS + 100;
    let taken = regional(&origin, atlanta, 0, BASE_MS, adsb_second(&[1, 2], 0, false))?;
    let not_taken = regional(&origin, chicago, 1, BASE_MS, adsb_second(&[3], 0, false))?;
    let mut forged_bytes = taken.as_bytes().to_vec();
    let last = forged_bytes.len() - 1;
    forged_bytes[last] ^= 1;
    let forged = RegionalBatch::from_bytes(forged_bytes).map_err(err)?;
    // A forged one never reaches the products: only a checked one can (`products::Verified`).
    assert!(crate::products::Verified::of(forged).is_none());
    let client = Asker {
        role: AskerRole::Client,
        ..relay_asker(peer)
    };
    for (asker, batch) in [
        (client, taken.clone()),
        (relay_asker(peer), taken.clone()),
        (relay_asker(peer), taken.clone()),
        (relay_asker(peer), not_taken),
    ] {
        products.regional_from(&asker, verified(batch)?, stamp(now));
    }
    // The sealer takes them in once the watermark passes their stamp.
    products.advance(stamp(now + 1));
    let out = products.take_forward();
    let came_on = relay_asker(peer).source;
    assert_eq!(
        out,
        vec![(
            came_on,
            crate::strikes::Deliverer::Peer(peer),
            taken.clone()
        )]
    );
    assert_eq!(products.report().regional_forwarded, 1);
    // Heard back from another peer: already forwarded.
    products.regional_from(&relay_asker(peer), verified(taken)?, stamp(now + 50));
    products.advance(stamp(now + 51));
    assert!(products.take_forward().is_empty());
    Ok(())
}

#[test]
fn the_products_are_routed_by_their_stream_bits_and_the_regional_by_its_cell() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let chicago = area_of(&place(41.9, -87.6)).map_err(err)?;
    let batch = regional(&relay, atlanta, 0, BASE_MS, adsb_second(&[1], 0, false))?;
    // The hub routes the relay's own regional batch by the cell it signed, by a clock at its
    // signing (a record outside the window of time is not forwarded, `strikes`).
    let hub = Hub::clocked(4, Arc::new(|| BASE_MS), crate::sharing::Deadlines::RELAY);
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
        client: None,
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
        products.described(
            &described(feeder, location, vec![relay.public()])?,
            Some(location),
        );
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
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = gatherer.member(PEER);
    gatherer.set_world(true);
    let peer = Identity::generate().map_err(err)?.public();
    let origin = Identity::generate().map_err(err)?;
    let mlat = Mlat::new()?;
    gatherer.clock_model(&mlat.model, PEER, stamp(BASE_MS));
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
                gatherer.regional_from(&relay_asker(peer), verified(batch)?, stamp(now));
            }
            for (n, chunk) in targets.chunks(100).enumerate() {
                let n = n as u64;
                gatherer.positions(
                    &mlat.solutions(chunk, at * 1_000 + 200, 0, true, sequence * 1_000 + 2 * n)?,
                    PEER,
                    stamp(now),
                );
                gatherer.positions(
                    &mlat.solutions(
                        chunk,
                        at * 1_000 - 30_000,
                        0,
                        false,
                        sequence * 1_000 + 2 * n + 1,
                    )?,
                    PEER,
                    stamp(now),
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
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
    products.set_world(true);
    products.set_world_precise(true);
    let now = second * 1_000 + 1_500;
    products.clock_model(&inputs.mlat.model, PEER, stamp(now));
    for batch in &inputs.regional {
        products.regional_from(&relay_asker(peer), verified(batch.clone())?, stamp(now));
    }
    for positions in &inputs.positions {
        products.positions(positions, PEER, stamp(now));
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

/// A world fix is judged ahead by the error budget (`tally_wire::budget::PEER_AHEAD`): its
/// transmit time is the signed time of the receptions it was solved from, which a relay uses up to
/// `S` ahead of its clock, so a fix 15 s ahead (`K`, another relay's engine's clock) is held and one
/// past `S` is not. Before, a bound of the products' own (2 s) dropped every fix of an engine whose
/// clock was a few seconds ahead of this relay's.
#[test]
fn a_world_fix_is_judged_ahead_by_the_budget() -> Result<()> {
    let products = Products::new();
    let _member = products.member(PEER);
    products.set_world(true);
    let mlat = Mlat::new()?;
    products.clock_model(&mlat.model, PEER, stamp(BASE_MS));
    let within = mlat.solutions(
        &[0x00c0_0001],
        BASE_MS
            + tally_wire::budget::K
                .span::<tally_wire::clocks::Judged>()
                .ms(),
        0,
        true,
        1,
    )?;
    products.positions(&within, PEER, stamp(BASE_MS));
    products.advance(stamp(BASE_MS + 1));
    assert_eq!(products.report().world_out_of_window, 0);
    let past = mlat.solutions(
        &[0x00c0_0002],
        BASE_MS
            + tally_wire::budget::PEER_AHEAD
                .span::<tally_wire::clocks::Judged>()
                .ms()
            + 1_000,
        0,
        true,
        2,
    )?;
    products.positions(&past, PEER, stamp(BASE_MS + 1));
    products.advance(stamp(BASE_MS + 2));
    assert_eq!(products.report().world_out_of_window, 1);
    Ok(())
}

/// A relay that starts unsynced and then steps its judging clock forward hours judges the world
/// by the judging reading of each input's stamp, one clock for every product input: its
/// monotonic clock stands three hours behind the true time it stepped to, and the fixes it was
/// shown while it did not judge are judged by nothing. Before, a world fix was judged against the
/// stamp's monotonic reading, so every fix of a relay whose two clocks stood apart fell outside
/// the window and the world it signed was empty.
#[test]
fn a_relay_that_starts_unsynced_and_steps_forward_hours_judges_the_world_by_its_judging_clock()
-> Result<()> {
    const BEHIND: u64 = 3 * 3_600_000;
    let at = |true_ms: u64, judging: bool| {
        let judged = if judging { true_ms } else { true_ms - BEHIND };
        Stamp::recorded(true_ms - BEHIND, 0, judged, true_ms - BEHIND, judging)
    };
    let second = BASE_MS / 1_000;
    let inputs = world_inputs(second)?;
    let relay = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?.public();
    let products = Products::new();
    products.adopt_identity(crate::signer::twin(&relay));
    let _member = products.member(PEER);
    products.set_world(true);
    // Unsynced: shown the inputs, it holds none of them.
    let early = second * 1_000 - 60_000;
    products.clock_model(&inputs.mlat.model, PEER, at(early, false));
    for positions in &inputs.positions {
        products.positions(positions, PEER, at(early, false));
    }
    products.advance(at(early + 1, false));
    assert!(products.tick().is_empty());
    let unsynced = products.report();
    assert!(unsynced.world_unjudged > 0);
    assert_eq!(unsynced.world_out_of_window, 0);
    // Synced, the judging clock stepped hours forward: the same inputs are judged by it.
    let now = second * 1_000 + 1_500;
    for batch in &inputs.regional {
        products.regional_from(&relay_asker(peer), verified(batch.clone())?, at(now, true));
    }
    for positions in &inputs.positions {
        products.positions(positions, PEER, at(now, true));
    }
    products.advance(at(sealed_at(second + 1), true));
    let mut fixes = Vec::new();
    for record in products.tick() {
        if let Record::WorldPositions(world) = record {
            fixes.extend(world.content().map_err(err)?.fixes);
        }
    }
    let report = products.report();
    assert_eq!(report.world_out_of_window, 0);
    assert_eq!(report.world_late, 0);
    for address in inputs.targets.iter().chain(&inputs.adsb) {
        assert!(fixes.iter().any(|fix| fix.address == *address));
    }
    Ok(())
}

/// Nothing the products let go is let go silently (every drop counted by why, and served on
/// `--stats-listen`): a world fix outside the window the relay holds, positions whose model never
/// came, an epoch a message thread's part of was lost (refused whole, every product of it), and
/// peers' regional batches beyond what waits to be forwarded.
#[test]
fn every_drop_is_counted_by_why() -> Result<()> {
    let products = Products::new();
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
    products.set_world(true);
    let mlat = Mlat::new()?;
    // A fix a minute ahead of the relay's clock, under a model it holds: outside the window.
    products.clock_model(&mlat.model, PEER, stamp(BASE_MS));
    let ahead = mlat.solutions(&[0x00c0_0001], BASE_MS + 60_000, 0, true, 1)?;
    products.positions(&ahead, PEER, stamp(BASE_MS));
    products.advance(stamp(BASE_MS + 1));
    assert_eq!(products.report().world_out_of_window, 1);
    // Positions under a model never shown: they wait, then expire, counted.
    let other = Mlat::new()?;
    let waiting = other.solutions(&[0x00c0_0002], BASE_MS, 0, false, 2)?;
    products.positions(&waiting, PEER, stamp(BASE_MS));
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
        products.regional_from(&relay_asker(peer), verified(batch)?, stamp(now));
    }
    products.advance(stamp(now + 1));
    assert_eq!(products.report().regional_forward_full, 1);
    assert_eq!(products.take_forward().len(), FORWARD_HELD);
    Ok(())
}

/// A budget of one feeder whose products' outputs take `products` bytes and whose records waiting
/// take `records`.
fn products_budget(products: usize, records: usize) -> crate::budget::Budget {
    let per_feeder = crate::budget::PerFeeder {
        products,
        records,
        ..crate::budget::PerFeeder::default()
    };
    crate::budget::Budget::new(per_feeder.total(), per_feeder)
}

/// RFC-0181 §10 and invariant 1 for the records that are not epochs: they wait in a queue of their
/// own, held by a share of their own (`Store::Records`), so a peer flooding them is refused
/// (counted) once that share is full and never costs this relay an epoch, neither its place in the
/// sealer's queue nor the room its outputs take (`Store::Products`); and a
/// world candidate is in time or late by its stamp against the watermark that seals its second,
/// never by when it was handled: two candidates handed in together, before that watermark is
/// reached, one stamped before it and one at it, are the first in time and the second late.
#[test]
fn records_wait_apart_from_the_epochs_and_are_taken_in_by_stamp() -> Result<()> {
    use crate::budget::Store;
    // The flood: more records than their share holds, stamped far ahead so none is taken in.
    let products = Arc::new(Products::with_boot(1, 1));
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
    products.on_thread(
        crate::ingest::Threads {
            ingest: 1,
            message: 1,
            seal: 1,
        },
        None,
    )?;
    let mlat = Mlat::new()?;
    let flood = mlat.solutions(&[0x00c0_0001], BASE_MS, 0, true, 1)?;
    const HELD: usize = 1_000;
    let len = flood.as_bytes().len();
    let budget = products_budget(1 << 20, HELD * len);
    let gauge = budget.gauge(Store::Records);
    products.charge_to(&budget);
    // One member floods, the only one admitted: it fills its own part of the share
    // (`RecordsRoom`), half the peers' (the other is this relay's own rebuilding's), no more.
    let fits = super::session_part(super::peers_part(HELD * len), 2) / len;
    for _ in 0..fits + 10 {
        products.positions(&flood, PEER, stamp(BASE_MS + 1_000_000));
    }
    // Each record's own bytes in its part, and the queue's slots, outside any part, what they
    // allocate.
    let slots = products
        .shared
        .records
        .lock()
        .map(|records| {
            assert_eq!(records.pending.len(), fits);
            records.pending.bytes()
        })
        .map_err(|_| "poisoned")?;
    assert_eq!(gauge.held(), fits * len + slots);
    let sink = products.sink();
    for closed_before in 1..=100 {
        // Each word carries the tick its thread closed by, as every thread's word does: the
        // watermark is a reading of both clocks, and none stands before a tick.
        let marker = crate::exchange::Frozen {
            closed_before,
            judged: Some(stamp(0)),
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

    // By stamp: second `s` seals once the watermark reaches `(s + 1) s + WORLD_SETTLE_MS`. And
    // with the records' share full of a flood, the world second still seals and goes out: its
    // outputs take their own room.
    let relay = Identity::generate().map_err(err)?;
    let products = Products::new();
    // The peer that hands these in is a member admitted, as one is on its first data.
    let _member = products.member(PEER);
    products.set_world(true);
    let mlat = Mlat::new()?;
    let second = BASE_MS / 1_000;
    let seals = sealed_at(second);
    let in_time = mlat.solutions(&[0x00c0_0001], BASE_MS + 100, 0, true, 1)?;
    let late = mlat.solutions(&[0x00c0_0002], BASE_MS + 200, 0, true, 2)?;
    let wanted = mlat.model.as_bytes().len() + in_time.as_bytes().len() + late.as_bytes().len();
    let limit = wanted + HELD * len;
    let budget = products_budget(64 * 1024, limit);
    products.charge_to(&budget);
    products.clock_model(&mlat.model, PEER, stamp(BASE_MS));
    products.positions(&late, PEER, stamp(seals));
    products.positions(&in_time, PEER, stamp(seals - 1));
    // The flood comes from another member than the engine's records: it fills a part of its
    // own, a third of the peers' with two members admitted beside this relay's own rebuilding.
    const FLOODER: u64 = PEER + 1;
    let _flooder = products.member(FLOODER);
    let fits = super::session_part(super::peers_part(limit), 3) / len;
    for _ in 0..fits + 10 {
        products.positions(&flood, FLOODER, stamp(BASE_MS + 1_000_000));
    }
    assert_eq!(products.report().records_refused, 10);
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
    assert_eq!(products.report().epochs_refused, 0);
    Ok(())
}

/// The records the products are handed are charged to
/// the session that handed them in, never to the key that signed them, so what is taken never
/// depends on what came first or on how many keys a peer signs with. One session forwarding
/// records signed by many throwaway keys (more than the old eight parts) fills only its own part,
/// the peers' share divided by the sessions open; so every honest session open beside it, more of
/// them than the old parts too, has its record taken, flood first or last, and this relay's own
/// MLAT positions are taken from a part no peer's records may take. Charged by signer, the flood's
/// keys took every part between them and the honest sessions were refused.
#[test]
fn own_output_and_each_session_have_a_part_of_the_records_share_whatever_came_first() -> Result<()>
{
    use crate::budget::Store;
    const HOSTILE: u64 = 100;
    const HONEST: u64 = 12;
    let own = Mlat::new()?;
    let throwaway: Vec<Mlat> = (0..16).map(|_| Mlat::new()).collect::<Result<_>>()?;
    let honest: Vec<Mlat> = (0..HONEST).map(|_| Mlat::new()).collect::<Result<_>>()?;
    let one =
        |mlat: &Mlat, sequence: u64| mlat.solutions(&[0x00c0_0001], BASE_MS, 0, true, sequence);
    let len = one(&own, 0)?.as_bytes().len();
    // A share of two hundred records; every record is stamped far ahead, so none is taken in.
    let limit = 200 * len;
    let ahead = BASE_MS + 1_000_000;
    // The hostile session floods (before the honest sessions and this relay hand theirs in, or
    // after): the records refused from the honest sessions and from this relay, and what the
    // share holds. Every session is open from the start, as a peer's is from its handshake.
    let run = |flood_first: bool| -> Result<(u64, u64, usize)> {
        let products = Products::new();
        products.adopt_identity(crate::signer::twin(&own.engine));
        let budget = products_budget(1 << 20, limit);
        products.charge_to(&budget);
        let _hostile = products.member(HOSTILE);
        let _honest: Vec<_> = (1..=HONEST)
            .map(|session| products.member(session))
            .collect();
        let flood = || -> Result<()> {
            for key in &throwaway {
                for sequence in 0..200 {
                    products.positions(&one(key, sequence)?, HOSTILE, stamp(ahead));
                }
            }
            Ok(())
        };
        let refused = || products.report().records_refused;
        if flood_first {
            flood()?;
        }
        let before = refused();
        for (session, mlat) in (1..=HONEST).zip(&honest) {
            products.positions(&one(mlat, 0)?, session, stamp(ahead));
        }
        let honest_refused = refused() - before;
        let before = refused();
        for sequence in 0..20 {
            products.positions(&one(&own, sequence)?, HOSTILE, stamp(ahead));
        }
        let own_refused = refused() - before;
        if !flood_first {
            flood()?;
        }
        Ok((
            honest_refused,
            own_refused,
            budget.gauge(Store::Records).held(),
        ))
    };
    for flood_first in [true, false] {
        let (honest_refused, own_refused, held) = run(flood_first)?;
        assert_eq!(
            (honest_refused, own_refused),
            (0, 0),
            "a session flooding by {} keys (first: {flood_first}) cost an honest session or this \
             relay its records",
            throwaway.len()
        );
        assert!(held <= limit, "the share held {held} of {limit} bytes");
    }
    Ok(())
}

/// The peers' share is divided by the sessions open, so a session that leaves gives
/// its part back to those that stay, and one that joins takes its part from them.
#[test]
fn a_session_leaving_gives_its_part_to_those_open() -> Result<()> {
    let mlat = Mlat::new()?;
    let one = |sequence: u64| mlat.solutions(&[0x00c0_0001], BASE_MS, 0, true, sequence);
    let len = one(0)?.as_bytes().len();
    let limit = 200 * len;
    let ahead = BASE_MS + 1_000_000;
    let products = Products::new();
    products.charge_to(&products_budget(1 << 20, limit));
    let peers = super::peers_part(limit);
    let taken = |session: u64, records: u64, first: u64| -> Result<u64> {
        let before = products.report().records_refused;
        for sequence in first..first + records {
            products.positions(&one(sequence)?, session, stamp(ahead));
        }
        Ok(records - (products.report().records_refused - before))
    };
    let _first = products.member(1);
    let second = products.member(2);
    let third = (super::session_part(peers, 3) / len) as u64;
    assert_eq!(taken(1, 1_000, 0)?, third);
    drop(second);
    let half = (super::session_part(peers, 2) / len) as u64;
    assert_eq!(taken(1, 1_000, 1_000)?, half - third);
    Ok(())
}

/// Only a session admitted as a member has a part of the records' share, so the
/// sessions that divide it are the members that send records, bounded as the members are. Two
/// thousand and forty-eight sessions that are no member (directory links and engines, each opened
/// as every session is, `Network::joined`) leave the one member admitted the part it would have
/// alone; a record one of them hands in is refused, having no part; and a member's part ends with
/// its admission. When every relay and engine session had a part, each member's bound was the
/// peers' share over 2,049.
#[test]
fn only_a_member_admitted_divides_the_records_share() -> Result<()> {
    use crate::budget::{Budget, Plan};
    let network = crate::network::Network::new(
        crate::sharing::Deadlines::RELAY,
        crate::clock::RelayClock::system(),
    );
    let mlat = Mlat::new()?;
    let one = |sequence: u64| mlat.solutions(&[0x00c0_0001], BASE_MS, 0, true, sequence);
    let len = one(0)?.as_bytes().len();
    let limit = 200 * len;
    let ahead = BASE_MS + 1_000_000;
    network.products.charge_to(&products_budget(1 << 20, limit));
    let stranger = Identity::generate().map_err(err)?.public();
    const OTHERS: u64 = 2_048;
    for source in 100..100 + OTHERS {
        network.joined(&Asker {
            role: if source % 2 == 0 {
                AskerRole::Relay
            } else {
                AskerRole::Engine
            },
            key: stranger,
            source,
            loopback: false,
            address: None,
        });
    }
    let plan = Plan::planned(false).with_members(1, crate::hub::DEFAULT_MAX_MEMBER_BYTES_PER_SEC);
    let members = Budget::of_memory(Budget::memory_for(1, plan), plan);
    const MEMBER: u64 = 1;
    let membership =
        network.admit_member(MEMBER, members.reserve_member().ok_or("no member's place")?);
    let taken = |source: u64, records: u64, first: u64| -> Result<u64> {
        let before = network.products.report().records_refused;
        for sequence in first..first + records {
            network.on_positions(&one(sequence)?, source, crate::ingest::Stamp::at(ahead, 0));
        }
        Ok(records - (network.products.report().records_refused - before))
    };
    // Its part beside this relay's own rebuilding's, as if no other session were open.
    let alone = (super::session_part(super::peers_part(limit), 2) / len) as u64;
    assert!(alone > 1);
    assert_eq!(taken(MEMBER, 2 * alone, 0)?, alone);
    // A directory link and an engine have no part.
    assert_eq!(taken(100, 1, 10_000)?, 0);
    assert_eq!(taken(101, 1, 10_001)?, 0);
    // Its admission ended: its part with it, and its reservation is the members' again.
    drop(membership);
    assert_eq!(taken(MEMBER, 1, 20_000)?, 0);
    assert!(members.reserve_member().is_some());
    Ok(())
}

/// A site whose own area (`area_of`) is not its public cell's parent: where H3's cells do not nest
/// exactly, along an area's edge. Found by walking a line across one; there is always one.
fn straddling() -> Result<Location> {
    for step in 0..20_000 {
        let site = place(33.0 + f64::from(step) * 0.000_5, -84.4);
        let public = Region::public_cell(&site).map_err(err)?;
        let parent = tally_wire::rendezvous::area_of_public(public).ok_or("no parent")?;
        if area_of(&site).map_err(err)? != parent {
            return Ok(site);
        }
    }
    Err("no site off its public cell's area along the line".to_owned())
}

/// A receiver's area is its public cell's parent at `AREA_RESOLUTION`, never the area its site
/// lies in: its regional product and its raw's sharing group are both its public cell's area, so
/// neither tells a client which side of an area's edge the receiver sits inside its public cell.
#[test]
fn a_receivers_area_is_its_public_cells_parent_never_its_sites() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let staged = Staged::new(&relay);
    let site = straddling()?;
    let public = Region::public_cell(&site).map_err(err)?;
    let parent = tally_wire::rendezvous::area_of_public(public).ok_or("no parent")?;
    assert_ne!(area_of(&site).map_err(err)?, parent);
    let feeder = Identity::generate().map_err(err)?;
    staged
        .products
        .described(&described(&feeder, site, vec![relay.public()])?, Some(site));
    assert_eq!(staged.products.area_for(&feeder.public()), Some(parent));
    let batch = feeder_batch(&feeder, 0, Vec::new(), (BASE_MS, 0))?;
    let record = Record::Batch(batch.batch().clone());
    assert_eq!(
        crate::sharing::group_of(&record, Some(public)),
        Some((parent, Streams::RAW))
    );
    Ok(())
}

/// What a regional test hub needs to tell a rebuilt record from this relay's own: a hub taking
/// `area` with its key, its sharing member made by a tick, and a control showing a record this
/// relay originates is held in its group (so a record that is not held was not seeded).
fn seeding_hub(relay: &Identity, origin: &Identity, area: Region) -> Result<(Arc<Hub>, usize)> {
    let hub = Arc::new(Hub::new(4, crate::sharing::Deadlines::RELAY).taking(vec![area]));
    hub.network().adopt_identity(crate::signer::twin(relay));
    let now = now_ms();
    let _ = hub.network().tick(&hub, now);
    let control = regional(origin, area, 99, now, adsb_second(&[9], 0, false))?;
    hub.network()
        .originate(&hub, &Record::RegionalBatch(control), now);
    let seeded = hub.network().sharing.held().0;
    if seeded == 0 {
        return Err("a regional batch this relay originated was not held in its group".into());
    }
    Ok((hub, seeded))
}

/// The regional group of `area`: where these tests' regional batches are shared, and rebuilt.
fn regional_group(area: Region) -> GroupKey {
    GroupKey::new(area, tally_wire::Streams::REGIONAL)
}

/// `record` rebuilt from parity in `hub`'s `group` (its relay `relay` a member, with two others),
/// and the handle the member's tick hands out with it, as the duties take it.
fn rebuilt_in(
    hub: &Arc<Hub>,
    relay: &Identity,
    group: GroupKey,
    record: &Record,
) -> Result<crate::sharing::Rebuilt> {
    let signer = Identity::generate().map_err(err)?;
    let parity_from = Identity::generate().map_err(err)?.public();
    let members = [relay.public(), signer.public(), parity_from];
    let now = now_ms();
    let sharing = &hub.network().sharing;
    sharing.fill_for_rebuild(
        group,
        &members,
        (&signer, parity_from),
        std::slice::from_ref(record),
        now / 1000 - 2,
        now,
    )?;
    sharing
        .tick_member_for_test(now)
        .into_iter()
        .find(|(_, rebuilt)| rebuilt == record)
        .map(|(handle, _)| handle)
        .ok_or_else(|| "the record was not rebuilt".into())
}

/// Where `group` has `handle`'s record: (held, originated as this relay's own, refused).
fn group_state(hub: &Hub, handle: crate::sharing::Rebuilt) -> (bool, bool, bool) {
    let (group, hash) = (handle.group(), handle.hash());
    hub.network()
        .sharing
        .member_for_test(|member| {
            (
                member.holds(group, &hash),
                member.originated(group, &hash),
                member.has_refused(group, &hash),
            )
        })
        .unwrap_or_default()
}

/// A regional batch the sharing group rebuilt from parity is taken in as a member's is
/// (`Hub::take_rebuilt`, `Network::take_regional`): to the products, which forward it once,
/// unchanged, as from this relay's rebuilding (`RELAY_ITSELF`), held in the group that rebuilt it
/// and never seeded into it as this relay's own. Before, the duties published it straight into the
/// fan-out and seeded it as their own (`Network::tick`'s originate of its own regional batches), so
/// the relay claimed another's record as its origin, and the products never saw it.
#[test]
fn a_regional_batch_rebuilt_from_parity_is_forwarded_once_and_never_seeded_as_this_relays()
-> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let origin = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let (hub, _) = seeding_hub(&relay, &origin, atlanta)?;
    let listener = hub.listen(u64::MAX, Filter::Everything);
    let now = now_ms();
    let rebuilt = regional(&origin, atlanta, 0, now, adsb_second(&[1, 2], 0, false))?;
    let record = Record::RegionalBatch(rebuilt.clone());
    let handle = rebuilt_in(&hub, &relay, regional_group(atlanta), &record)?;
    hub.take_rebuilt(handle, record.clone());
    assert_eq!(
        group_state(&hub, handle),
        (true, false, false),
        "a rebuilt regional batch: (held, seeded as this relay's own, refused)"
    );
    assert!(
        listener.try_recv().is_none(),
        "published before the products took it in"
    );
    hub.network()
        .products
        .advance(stamp(hub.clock().mono().ms() + 1));
    let forwarded = hub.network().products.take_forward();
    assert_eq!(
        forwarded,
        vec![(
            crate::hub::RELAY_ITSELF,
            crate::strikes::Deliverer::Relay,
            rebuilt.clone()
        )]
    );
    for (source, _, regional) in forwarded {
        hub.forward_taken(source, Record::RegionalBatch(regional));
    }
    // Taken in again (a member's copy after): not forwarded again.
    hub.take_rebuilt(handle, record.clone());
    hub.network()
        .products
        .advance(stamp(hub.clock().mono().ms() + 1));
    assert!(hub.network().products.take_forward().is_empty());
    let mut reached = 0;
    while let Some(item) = listener.try_recv() {
        if *item.record == record {
            reached += 1;
        }
    }
    assert_eq!(reached, 1, "the fan-out had it {reached} times");
    assert_eq!(hub.memory_report().rebuilt_refused, 0);
    Ok(())
}

/// RFC-0171 §3.6: what a member passes on (its client regional batches, its bundle indexes, the
/// regional batches the products forward for it) is charged to the member's share, never the
/// relay's own (`Asker::deliverer`, `Hub::publish_as`). So a member flooding fresh client regional
/// batches fills its own share and no more, and this relay's own regional batch and a regional
/// batch it rebuilt from parity are still taken and forwarded. Before, every record passed on by
/// hash was charged to the relay's share, and the flood had the relay's own products let go.
#[test]
fn a_member_flooding_client_regional_batches_leaves_the_relays_own_share_whole() -> Result<()> {
    use crate::strikes::{Deliverer, Entries};
    let relay = Identity::generate().map_err(err)?;
    let origin = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let (hub, _) = seeding_hub(&relay, &origin, atlanta)?;
    let share = 8;
    hub.set_shares_for_test(Entries {
        feeder: share,
        feeders: share,
        peer: share,
        // One flooding peer's place beside its share, as the peers' share is planned.
        peers: share + crate::strikes::PEER_PLACE_ENTRIES,
        relay: share,
    });
    let flood = Identity::generate().map_err(err)?;
    let asker = relay_asker(flood.public());
    let now = now_ms();
    for sequence in 0..(2 * share as u64) {
        let content = regional(&flood, atlanta, sequence, now, adsb_second(&[1], 0, false))?
            .content()
            .map_err(err)?
            .for_clients();
        let client = tally_wire::ClientRegionalBatch::sign(&flood, &content).map_err(err)?;
        let _ =
            hub.network()
                .take_regional(&hub, &asker, Record::ClientRegionalBatch(client), |_| {});
    }
    assert_eq!(hub.held_by_for_test(Deliverer::Peer(flood.public())), share);
    assert_eq!(hub.memory_report().strikes_full, share as u64);
    assert_eq!(hub.held_by_for_test(Deliverer::Relay), 0);
    let listener = hub.listen(u64::MAX, Filter::Everything);
    // This relay's own regional batch.
    let own = regional(&relay, atlanta, 0, now, adsb_second(&[2], 0, false))?;
    hub.publish_own(Record::RegionalBatch(own.clone()));
    // And one it rebuilt from parity, forwarded once the products take it in.
    let rebuilt = regional(&origin, atlanta, 1, now, adsb_second(&[3], 0, false))?;
    let record = Record::RegionalBatch(rebuilt.clone());
    let handle = rebuilt_in(&hub, &relay, regional_group(atlanta), &record)?;
    hub.take_rebuilt(handle, record.clone());
    hub.network()
        .products
        .advance(stamp(hub.clock().mono().ms() + 1));
    for (source, _, regional) in hub.network().products.take_forward() {
        hub.forward_taken(source, Record::RegionalBatch(regional));
    }
    let mut reached = Vec::new();
    while let Some(item) = listener.try_recv() {
        if let Record::RegionalBatch(regional) = &*item.record {
            reached.push(regional.clone());
        }
    }
    assert_eq!(reached, vec![own, rebuilt], "the relay's own were let go");
    assert_eq!(hub.memory_report().strikes_full, share as u64);
    Ok(())
}

/// A regional batch judged by what is passed on before its group holds it: one there is no room
/// to take in ([`crate::strikes::Verdict::Full`]) is let go, never held as had, whether a peer
/// sent it or this relay rebuilt it from parity, so its group asks for it again. Before, it was
/// held in its group first and judged after, so a full relay marked as had what it never took
/// in, and no repair asked for it again.
#[test]
fn a_regional_batch_there_is_no_room_for_is_let_go_never_held_as_had() -> Result<()> {
    use crate::strikes::Entries;
    let relay = Identity::generate().map_err(err)?;
    let origin = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let (hub, _) = seeding_hub(&relay, &origin, atlanta)?;
    hub.set_shares_for_test(Entries {
        feeder: 0,
        feeders: 0,
        peer: 0,
        peers: crate::strikes::PEER_PLACE_ENTRIES,
        relay: 0,
    });
    let now = now_ms();
    // A peer's.
    let peer = Identity::generate().map_err(err)?;
    let theirs = regional(&peer, atlanta, 1, now, adsb_second(&[4], 0, false))?;
    let shared = std::cell::Cell::new(false);
    assert_eq!(
        hub.network().take_regional(
            &hub,
            &relay_asker(peer.public()),
            Record::RegionalBatch(theirs),
            |_| shared.set(true)
        ),
        crate::network::Regional::Full
    );
    assert!(!shared.get(), "held in its group as had");
    // One rebuilt from parity.
    let rebuilt = regional(&origin, atlanta, 2, now, adsb_second(&[5], 0, false))?;
    let record = Record::RegionalBatch(rebuilt);
    let handle = rebuilt_in(&hub, &relay, regional_group(atlanta), &record)?;
    hub.take_rebuilt(handle, record);
    assert_eq!(
        group_state(&hub, handle),
        (false, false, false),
        "a rebuilt regional batch with no room: (held, seeded as this relay's own, refused)"
    );
    assert_eq!(hub.memory_report().strikes_full, 2);
    hub.network()
        .products
        .advance(stamp(hub.clock().mono().ms() + 1));
    assert!(hub.network().products.take_forward().is_empty());
    Ok(())
}

/// RFC-0171 §3.6, a crash: a peer's regional batch the products used (its fixes offered to the
/// world) is taken into what is passed on by hash first, so the lease covers it before it is
/// used, and a relay restarted after a crash, whose products remember nothing, never uses it
/// again: late. Before, only the copy the products forwarded was taken in, after they had used
/// it, so a crash left the lease below it and the restarted relay merged it into the world twice.
#[test]
fn a_peers_regional_batch_the_products_used_is_never_used_again_after_a_crash() -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    let relay = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let scratch = crate::durable::tests::Scratch::new("regional-crash");
    let base = now_ms();
    let clock = Arc::new(AtomicU64::new(base));
    let start = |dir: Arc<crate::durable::StateDir>| -> Result<Arc<Hub>> {
        let reading = Arc::clone(&clock);
        let hub = Hub::clocked(
            4,
            Arc::new(move || reading.load(Ordering::Relaxed)),
            crate::sharing::Deadlines::RELAY,
        )
        .durable(crate::durable::Durable::Dir(dir))
        .map_err(err)?
        .taking(vec![atlanta]);
        let hub = Arc::new(hub);
        hub.network().adopt_identity(crate::signer::twin(&relay));
        Ok(hub)
    };
    let hub = start(scratch.dir().map_err(err)?)?;
    // An earlier record passed on by hash moves the lease to just past it.
    let first = base
        + tally_wire::budget::FALLBACK_FLOOR
            .span::<tally_wire::clocks::Judged>()
            .ms()
        + 1_000;
    clock.store(first, Ordering::Relaxed);
    let own = regional(&relay, atlanta, 0, first, adsb_second(&[2], 0, false))?;
    hub.publish_own(Record::RegionalBatch(own));
    // A peer's, ten seconds on, which the products use.
    let later = first + 10_000;
    clock.store(later, Ordering::Relaxed);
    let theirs = Record::RegionalBatch(regional(
        &peer,
        atlanta,
        1,
        later,
        adsb_second(&[3], 0, false),
    )?);
    let asker = relay_asker(peer.public());
    assert_eq!(
        hub.network()
            .take_regional(&hub, &asker, theirs.clone(), |_| {}),
        crate::network::Regional::Passed
    );
    // A crash: no stop, no dump; the directory opened again by a new process.
    drop(hub);
    clock.store(later + 1_000, Ordering::Relaxed);
    let restarted = start(scratch.dir().map_err(err)?)?;
    assert_eq!(
        restarted
            .network()
            .take_regional(&restarted, &asker, theirs, |_| {}),
        crate::network::Regional::Late,
        "used again after a crash"
    );
    Ok(())
}

/// A client regional batch's freshness is judged by the relay's one window for what relays sign
/// (`Hub::in_window`, `tally_wire::budget::Window::relay_signed`, RFC-0171 §3.6), and no second
/// way: one signed a second past its behind edge reaches no client; one signed five seconds
/// before does, and so does one signed 15 s ahead, `K` from its signer's clock. Before, a second
/// bound of the products' own (10 s ahead) kept the last from every client.
#[test]
fn a_client_regional_batch_is_judged_fresh_by_the_relays_clock() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let origin = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let hub = Arc::new(Hub::new(4, crate::sharing::Deadlines::RELAY).taking(vec![atlanta]));
    hub.network().adopt_identity(crate::signer::twin(&relay));
    let listener = hub.listen(u64::MAX, Filter::Everything);
    let asker = relay_asker(Identity::generate().map_err(err)?.public());
    let now = hub.now().ms();
    let client = |sequence: u64, wall_ms: u64| -> Result<Record> {
        let content = regional(
            &origin,
            atlanta,
            sequence,
            wall_ms,
            adsb_second(&[1], 0, false),
        )?
        .content()
        .map_err(err)?
        .for_clients();
        Ok(Record::ClientRegionalBatch(
            tally_wire::ClientRegionalBatch::sign(&origin, &content).map_err(err)?,
        ))
    };
    let window = crate::strikes::relay_signed(crate::sharing::Deadlines::RELAY);
    let stale = client(
        0,
        now - window
            .behind_span()
            .span::<tally_wire::clocks::Judged>()
            .ms()
            - 1_000,
    )?;
    let fresh = client(1, now - 5_000)?;
    let ahead = client(
        2,
        now + tally_wire::budget::K
            .span::<tally_wire::clocks::Judged>()
            .ms(),
    )?;
    for record in [stale, fresh.clone(), ahead.clone()] {
        let _ = hub.network().take_regional(&hub, &asker, record, |_| {});
    }
    let mut reached = Vec::new();
    while let Some(item) = listener.try_recv() {
        if matches!(&*item.record, Record::ClientRegionalBatch(_)) {
            reached.push((*item.record).clone());
        }
    }
    assert_eq!(reached, vec![fresh, ahead]);
    Ok(())
}

/// A peer's regional batch signed 15 s ahead of this relay, `K` from its signer's clock, is inside
/// the relay's one window for what relays sign, so it enters the products and is forwarded where
/// its cell is taken. Before, the products judged it a second way (10 s ahead at most), after the
/// hub had taken it into what is passed on as new, so it was lost for good.
#[test]
fn a_regional_batch_ahead_within_k_enters_the_products() -> Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};
    let relay = Identity::generate().map_err(err)?;
    let peer = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let start = now_ms();
    let clock = Arc::new(AtomicU64::new(start));
    let reading = Arc::clone(&clock);
    let hub = Arc::new(
        Hub::clocked(
            4,
            Arc::new(move || reading.load(Ordering::Relaxed)),
            crate::sharing::Deadlines::RELAY,
        )
        .taking(vec![atlanta]),
    );
    hub.network().adopt_identity(crate::signer::twin(&relay));
    // Past the floor a relay started with no state keeps (`FALLBACK_FLOOR`).
    let base = start
        + tally_wire::budget::FALLBACK_FLOOR
            .span::<tally_wire::clocks::Judged>()
            .ms()
        + 1_000;
    clock.store(base, Ordering::Relaxed);
    let ahead = regional(
        &peer,
        atlanta,
        0,
        base + tally_wire::budget::K
            .span::<tally_wire::clocks::Judged>()
            .ms(),
        adsb_second(&[5], 0, false),
    )?;
    let asker = relay_asker(peer.public());
    // The peer a member admitted, as one is on its first data; the area taken, as a tick sets it.
    let _member = hub.network().products.member(PEER);
    hub.network().products.set_taken(vec![atlanta]);
    assert_eq!(
        hub.network()
            .take_regional(&hub, &asker, Record::RegionalBatch(ahead.clone()), |_| {}),
        crate::network::Regional::Passed
    );
    hub.network().products.advance(stamp(base + 1));
    let forwarded: Vec<RegionalBatch> = hub
        .network()
        .products
        .take_forward()
        .into_iter()
        .map(|(_, _, batch)| batch)
        .collect();
    assert_eq!(forwarded, vec![ahead]);
    Ok(())
}

/// The client form of a regional batch, rebuilt from parity, is taken in as a member's is: checked,
/// and forwarded to this relay's clients once while fresh, held in the group that rebuilt it and
/// never seeded into it as this relay's own (before, the duties seeded it as theirs). One that does
/// not verify is refused in its group, counted, and reaches no one.
#[test]
fn a_client_regional_batch_rebuilt_from_parity_reaches_clients_once_and_is_never_seeded()
-> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let origin = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let (hub, _) = seeding_hub(&relay, &origin, atlanta)?;
    let listener = hub.listen(u64::MAX, Filter::Everything);
    let now = now_ms();
    let content = regional(&origin, atlanta, 0, now, adsb_second(&[1, 2], 0, false))?
        .content()
        .map_err(err)?
        .for_clients();
    let client = tally_wire::ClientRegionalBatch::sign(&origin, &content).map_err(err)?;
    let mut forged_bytes = client.as_bytes().to_vec();
    let last = forged_bytes.len() - 1;
    forged_bytes[last] ^= 1;
    let forged = Record::ClientRegionalBatch(
        tally_wire::ClientRegionalBatch::from_bytes(forged_bytes).map_err(err)?,
    );
    let client = Record::ClientRegionalBatch(client);
    let forged_handle = rebuilt_in(&hub, &relay, regional_group(atlanta), &forged)?;
    hub.take_rebuilt(forged_handle, forged);
    let handle = rebuilt_in(&hub, &relay, regional_group(atlanta), &client)?;
    hub.take_rebuilt(handle, client.clone());
    hub.take_rebuilt(handle, client.clone());
    assert_eq!(
        group_state(&hub, handle),
        (true, false, false),
        "a rebuilt client regional batch: (held, seeded as this relay's own, refused)"
    );
    assert_eq!(
        group_state(&hub, forged_handle),
        (false, false, true),
        "a forged rebuilt client regional batch: (held, seeded as this relay's own, refused)"
    );
    let mut reached = 0;
    while let Some(item) = listener.try_recv() {
        if matches!(&*item.record, Record::ClientRegionalBatch(_)) {
            assert_eq!(*item.record, client);
            reached += 1;
        }
    }
    assert_eq!(reached, 1, "the fan-out had it {reached} times");
    assert_eq!(hub.memory_report().rebuilt_refused, 1);
    Ok(())
}

/// A regional batch a member sent that does not verify is refused in its group, as any piece its
/// relay refuses is: counted as had, so no repair asks for it again and it is never pushed on.
/// Before, it was dropped and nothing told the group, which went on lacking it. A relay that is no
/// member of the group adds nothing to it, not even a refusal (as `Network::from_peer` takes no
/// piece from one): before, its forgeries each left an entry in the group, uncharged.
#[test]
fn a_members_regional_batch_that_does_not_verify_is_refused_in_its_group() -> Result<()> {
    let relay = Identity::generate().map_err(err)?;
    let origin = Identity::generate().map_err(err)?;
    let atlanta = area_of(&place(33.7, -84.4)).map_err(err)?;
    let (hub, _) = seeding_hub(&relay, &origin, atlanta)?;
    let group = regional_group(atlanta);
    let member = Identity::generate().map_err(err)?.public();
    let stranger = Identity::generate().map_err(err)?.public();
    hub.network()
        .sharing
        .groups
        .set_offers(group, &std::collections::BTreeMap::from([(member, false)]));
    let now = now_ms();
    let refused = |sequence: u64, from: PublicKey| -> Result<bool> {
        let taken = regional(
            &origin,
            atlanta,
            sequence,
            now,
            adsb_second(&[1, 2], 0, false),
        )?;
        let mut forged_bytes = taken.as_bytes().to_vec();
        let last = forged_bytes.len() - 1;
        forged_bytes[last] ^= 1;
        let forged = Record::RegionalBatch(RegionalBatch::from_bytes(forged_bytes).map_err(err)?);
        let hash = crate::sharing::member::Piece::of(&forged)
            .and_then(|piece| piece.hash())
            .ok_or("no hash")?;
        let _ = hub
            .network()
            .handle(&hub, &relay_asker(from), forged, now, None);
        hub.network()
            .sharing
            .member_for_test(|member| member.has_refused(group, &hash))
            .ok_or_else(|| "no member".into())
    };
    assert!(
        refused(1, member)?,
        "a member's forged regional batch was not refused in its group"
    );
    assert!(
        !refused(2, stranger)?,
        "a stranger's forged regional batch left a refusal in the group"
    );
    Ok(())
}

/// RFC-0181 "Memory is charged once": the records waiting for the sealer are charged what they
/// allocate, each record's own bytes in its sender's part and the queue's slots outside any part,
/// read from an allocator counting this thread's bytes as a peer's records come and are refused;
/// and the queue gives its slots back once they are taken in. Before, a record was charged its
/// encoded length and the queue's slots, grown by doubling, nothing.
#[test]
fn the_records_waiting_for_the_sealer_are_charged_what_they_allocate() -> Result<()> {
    use crate::budget::Store;
    use tally_counting::Counting;
    let products = Products::with_boot(1, 1);
    let _member = products.member(PEER);
    let mlat = Mlat::new()?;
    let records: Vec<_> = (0..40u32)
        .map(|n| mlat.solutions(&[0x00c0_0001 + n], BASE_MS, 0, true, u64::from(n) + 1))
        .collect::<Result<_>>()?;
    let len = records[0].as_bytes().len();
    let budget = products_budget(1 << 20, 400 * len);
    let gauge = budget.gauge(Store::Records);
    products.charge_to(&budget);
    let base = Counting::live();
    for round in 0..600usize {
        products.positions(
            &records[round % records.len()],
            PEER,
            stamp(BASE_MS + 1_000_000),
        );
        let live = Counting::since(base);
        assert!(
            live >= 0 && live as usize == gauge.held(),
            "{live} allocated, {} charged, round {round}",
            gauge.held()
        );
    }
    assert!(
        products.report().records_refused > 0,
        "the share was never full"
    );
    let held = gauge.held();
    assert!(held > 0);
    // Taken in by the sealer (it waits for nothing here but the watermark): the queue is empty
    // and gives back its slots.
    if let Ok(mut waiting) = products.shared.records.lock() {
        drop(waiting.pending.take());
        waiting.settle();
    }
    assert_eq!(gauge.held(), 0);
    assert_eq!(Counting::since(base), 0);
    Ok(())
}

/// RFC-0181 "Memory is charged once": positions waiting for the model they cite are charged what
/// their tree and lists allocate, a new model's place in the tree with its list, before either
/// grows. Before, a new model's place was charged nothing.
#[test]
fn the_positions_waiting_for_their_models_are_charged_what_their_tree_allocates() -> Result<()> {
    let products = Products::new();
    let _member = products.member(PEER);
    products.set_world(true);
    let models = (0..30).map(|_| Mlat::new()).collect::<Result<Vec<_>>>()?;
    for (n, mlat) in models.iter().enumerate() {
        let waiting = mlat.solutions(&[0x00c0_0002 + n as u32], BASE_MS, 0, false, n as u64 + 1)?;
        products.positions(&waiting, PEER, stamp(BASE_MS));
        tick(&products, None, BASE_MS + 1 + n as u64);
        let sealer = products.sealer.read().map_err(|_| "poisoned")?;
        let super::Sealer::Inline(sealing) = &*sealer else {
            return Err("the sealer runs inline here".into());
        };
        let sealing = sealing.lock().map_err(|_| "poisoned")?;
        assert_eq!(
            sealing.waiting.len(),
            n + 1,
            "every one waits for its own model"
        );
        assert_eq!(sealing.waiting_charge.bytes(), sealing.waiting_bytes());
    }
    Ok(())
}

/// The relay's clock now, as a relay started now reads it: what a test signs its records by.
fn now_ms() -> u64 {
    crate::clock::RelayClock::system().judged().ms()
}

/// RFC-0171 §3.6: a sealer asks its signer's clock again in each signing job (`Signer::with`),
/// not once for the epoch. A clock that judged when the epoch began to seal and stopped before
/// its jobs ran signs nothing of it: the stream's copies and the area's are counted unsigned,
/// never signed by a clock no longer synced. Here the clock judges for the sealer's two asks
/// before its jobs (`count_unsynced`, `signer`) and for nothing after.
#[test]
fn a_clock_that_stops_judging_while_an_epoch_seals_signs_none_of_it() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let asked = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&asked);
    let signer = tally_wire::Signer::new(
        Identity::from_seed([71; 32]),
        Arc::new(move || counting.fetch_add(1, Ordering::SeqCst) < 2),
    );
    let mut sealing =
        crate::products::Sealing::new((1, 2), 1, Arc::new(crate::products::Shared::default()));
    sealing.signer = Some(signer);
    let feeder = Identity::from_seed([72; 32]);
    let batch = feeder_batch(
        &feeder,
        0,
        adsb_second(&[0x00a0_0001, 0x00a0_0002], 0, false),
        (BASE_MS + 100, 0),
    )?;
    let copies = || {
        (0..batch.observations().len() as u32)
            .map(|index| crate::seal::Kept {
                decoded: Arc::clone(&batch),
                index,
            })
            .collect::<Vec<_>>()
    };
    let area = tally_wire::rendezvous::area_of(&place(33.7, -84.4)).map_err(err)?;
    let mut areas = BTreeMap::new();
    areas.insert(area.as_u64(), (area, copies()));
    let stream = copies();
    let held = stream.len() as u64;
    let (streamed, regional) = sealing.seal_copies(Some(stamp(BASE_MS + 1_000)), stream, areas);
    assert!(
        streamed.is_empty(),
        "the stream signed by a clock no longer judging"
    );
    assert!(
        regional.is_empty(),
        "an area signed by a clock no longer judging"
    );
    let report = &sealing.report;
    // The seal began under a judging clock (no seal was skipped), and each job asked again.
    assert_eq!(report.unsynced_seals, 0);
    assert!(asked.load(Ordering::SeqCst) > 2, "no job asked the clock");
    assert_eq!(
        (report.stream_unsigned, report.regional_unsigned),
        (held, held)
    );
    assert_eq!((report.stream_oversized, report.regional_oversized), (0, 0));
    Ok(())
}
