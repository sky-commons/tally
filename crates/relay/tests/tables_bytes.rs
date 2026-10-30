//! The tables that grow with what the relay is sent cost no more than the stores they are charged
//! to (RFC-0181 "Memory is charged once"): the products' remembered tables at their caps
//! (`products::REMEMBERED_BYTES`, `budget::Store::Remembered`), a world gatherer's fixes and
//! seconds (`products::WORLD_FIX_BYTES`, `budget::Store::World`), standing's tables
//! (`standing::Caps::planned_bytes`, `budget::Store::Standing`) and the relay's decoded clock
//! models (`models::planned_bytes`, its own engine's by its seats' areas refit every refit and
//! the members' by their pace, `budget::Store::Models`), each fed past its caps and filled to the
//! honest worst case its plan is derived from. And the measured lines those plans are drawn from:
//! what an area's model holds for each of its receivers, decoded over its wire bytes, and its
//! memos (`an_areas_model_is_within_its_bytes_per_receiver`).
//! Measured by an allocator that counts every byte asked of it, in one test so nothing else in
//! the binary allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tally_mlat::engine::{Capacity, Engine, Settings};
use tally_mlat::intake::SiteRecord;
use tally_mlat::replay::{replay, scenario};
use tally_relay::bounded::Bounded;
use tally_relay::models::{Cited, Decoded, Model, Models};
use tally_relay::products::{
    DERIVED_REMEMBERED, MODELS_REMEMBERED, REGIONAL_REMEMBERED, REMEMBERED_BYTES, WORLD_FIX_BYTES,
    WORLD_SECOND_BYTES, WORLD_SECONDS_ROOT_BYTES,
};
use tally_relay::standing::{Standing, StandingReport};
use tally_wire::batch::Hash;
use tally_wire::clocks::recorded::judged;
use tally_wire::{EnuCovariance, Identity, Record, TransmitTime, WorldFix};

#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

/// What a thread of the table's own takes beside its tables (its handle, its name, its closure):
/// standing's thread, started inside the measurement.
const THREAD_BYTES: usize = 16 << 10;

/// What standing's tables hold by their own count (`StandingReport`): the book's transmissions,
/// its receivers and settled receptions at their most, and the verifications counted this second.
fn counted(caps: &tally_relay::standing::Caps, report: &StandingReport) -> usize {
    tally_mlat_solver::standing::BookCaps {
        pending_bytes: report.pending_bytes,
        ..caps.book
    }
    .planned_bytes::<Cited>()
}

fn peak_of(run: impl FnOnce()) -> usize {
    let mark = tally_counting::CountingAll::peak_base();
    run();
    usize::try_from(tally_counting::CountingAll::peak_since(mark)).unwrap_or(usize::MAX)
}

fn hash(n: u64) -> Hash {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&n.to_be_bytes());
    hash
}

/// What a reference engine published: the site records it placed its receivers by, its records
/// each with when it was published, and each owned area's memos' bytes when it ended
/// (`Engine::area_caches`).
type Published = (
    Vec<SiteRecord>,
    Vec<(u64, Record)>,
    Vec<(tally_wire::Region, usize)>,
);

/// The reference simulation's records as they reach an engine: its receivers' raw and site
/// records, each with when it arrived.
fn delivered() -> Result<Vec<(u64, Record)>, String> {
    let mut simulation = tally_mlat_solver::sim::run(&scenario(23, 120.0));
    tally_mlat_solver::sim::arrived_records(&mut simulation, 5).map_err(|error| error.to_string())
}

/// A dense scene: 81 receivers and 100 aircraft over 80 km, so each receiver keeps its full
/// `tally_mlat_solver::pair::PAIR_NEIGHBOURS` (40) as its pairs' other ends, the most pairs a
/// receiver brings a step (41 receivers measured 209,618 bytes a seat, 81 212,816: it saturates).
fn dense() -> Result<Vec<(u64, Record)>, String> {
    let mut simulation = tally_mlat_solver::sim::run(&tally_mlat_solver::sim::Scenario {
        duration_s: 30.0,
        receivers: 81,
        adsb_aircraft: 80,
        modes_aircraft: 20,
        spread_m: 80_000.0,
        reception_probability: 0.5,
        ..tally_mlat_solver::sim::Scenario::new(29)
    });
    tally_mlat_solver::sim::arrived_records(&mut simulation, 5).map_err(|error| error.to_string())
}

/// The most one step's working set takes for each receiver taking part, over the reference
/// simulation stepped a second at a time on one thread (`mlat_host::STEP_BYTES_PER_SEAT`, what
/// the relay reserves in the `Engine` store while a step runs): what the step allocated at its
/// height above what the engine held before it, less what it left held after (its tables' growth
/// and the records it published, each charged to its own store, `Arrived`, `Models` and
/// `mlat_host::PUBLISHED_BYTES_PER_SEAT`). On one thread, so the measurement is the same on every
/// run; the threads a relay steps on each hold one item of the step's lists at a time beside it.
fn step_bytes_per_seat(delivered: &[(u64, Record)]) -> Result<usize, String> {
    use tally_counting::CountingAll;
    use tally_mlat::engine::STEP_MS;
    use tally_wire::clocks::recorded::aligned;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 10_000;
    let first = delivered.first().map(|(at, _)| *at).ok_or("no raw")?;
    let mut engine = Engine::new(
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            threads: 1,
            capacity: Capacity::default(),
        },
    );
    let signer = tally_wire::Signer::new(Identity::from_seed([4; 32]), Arc::new(|| true));
    let (mut next, mut most) = (0, 0);
    let mut now = (first / STEP_MS + 1) * STEP_MS;
    let mut descriptions: Vec<(u64, SiteRecord)> = Vec::new();
    while now <= until {
        while let Some((at, record)) = delivered.get(next).filter(|(at, _)| *at < now) {
            match SiteRecord::of(record) {
                Some(site) => descriptions.push((*at, site)),
                None if matches!(record, Record::ReceiverInfo(_)) => {}
                None => {
                    engine.ingest_record(record, aligned(*at))?;
                }
            }
            next += 1;
        }
        for (at, site) in tally_mlat::intake::taking_effect(descriptions.drain(..)) {
            engine.ingest_record(&site.record(), aligned(at))?;
        }
        let seats = engine.taking_part();
        let before = CountingAll::peak_base();
        let step = engine.step(aligned(now), &signer);
        let height = CountingAll::peak_since(before);
        let left = CountingAll::since(before);
        drop(step);
        let working = usize::try_from(height - left.max(0)).unwrap_or(0);
        if seats > 0 {
            most = most.max(working.div_ceil(seats));
        }
        now += STEP_MS;
    }
    Ok(most)
}

/// What a reference engine publishes over a simulation, a step a second: clock models (manifests
/// and parts) and positions, raw and tagged, each with the step that published it, and the site
/// records its receivers were placed by.
fn published(delivered: &[(u64, Record)]) -> Result<Published, String> {
    let until = delivered.last().map_or(0, |(at, _)| *at) + 10_000;
    let mut engine = Engine::new(
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            threads: 2,
            capacity: Capacity::default(),
        },
    );
    let signer = tally_wire::Signer::new(Identity::from_seed([4; 32]), Arc::new(|| true));
    let sites = delivered
        .iter()
        .filter_map(|(_, record)| SiteRecord::of(record))
        .collect();
    let steps = replay(&mut engine, delivered, &signer, until)?;
    let records = steps
        .into_iter()
        .flat_map(|(at, step)| step.records().into_iter().map(move |record| (at, record)))
        .collect();
    Ok((sites, records, engine.area_caches()))
}

/// Every model `records` publish, as a member sends it, with when it was published.
fn models_of(
    records: &[(u64, Record)],
) -> Result<Vec<(u64, tally_wire::ClockModel, tally_wire::ClockModelContent)>, String> {
    records
        .iter()
        .filter_map(|(at, record)| match record {
            Record::ClockModel(manifest) => Some((*at, manifest)),
            _ => None,
        })
        .map(|(at, manifest)| {
            let content = manifest.content(&[]).map_err(|error| error.to_string())?;
            Ok((at, manifest.clone(), content))
        })
        .collect()
}

/// The areas `records` hold models of: what a relay hosting their MLAT holds.
fn areas_of(records: &[(u64, Record)]) -> tally_wire::Regions {
    tally_wire::Regions::new(records.iter().filter_map(|(_, record)| {
        let Record::ClockModel(manifest) = record else {
            return None;
        };
        let content = manifest.content(&[]).ok()?;
        tally_mlat_solver::publish::area_of(&content.model).ok()
    }))
}

fn world_fix(address: u32, transmitted_ms: u64) -> WorldFix {
    WorldFix {
        address,
        transmitted: TransmitTime {
            unix_ms: transmitted_ms,
            sub_ms_ps: 0,
        },
        lat_e7: 337_000_000,
        lon_e7: -844_000_000,
        alt_hae_mm: Some(10_000_000),
        pressure_altitude_ft: None,
        covariance: EnuCovariance {
            xx: 900.0,
            xy: 0.0,
            xz: 0.0,
            yy: 900.0,
            yz: 0.0,
            zz: 2_500.0,
        },
        mlat: true,
        input_set: [1; 32],
        considered: 2,
        source: Identity::from_seed([73; 32]).public(),
        origin: [2; 32],
        origin_index: 0,
    }
}

/// A pool of receivers' keys, made once.
fn keys(count: usize) -> Vec<tally_wire::PublicKey> {
    let mut keys: Vec<tally_wire::PublicKey> = (0..count)
        .map(|n| {
            let mut seed = [7u8; 32];
            seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
            Identity::from_seed(seed).public()
        })
        .collect();
    keys.sort();
    keys
}

/// `model` as another engine's: the same model refit at `edge_ms`, its input count `variant`
/// (so each is a model of its own, with an id of its own), and with `place` its area moved there
/// (every receiver of its area put at `place`, so the moved model holds what it held), encoded and
/// decoded as a relay holds one a member sent.
fn variant(model: &Decoded, place: Option<(f64, f64)>, edge_ms: u64, variant: u32) -> Decoded {
    let mut model = model.prepared.model.clone();
    if let Some((lat, lon)) = place {
        let mut to = None;
        for site in &mut model.scope {
            if tally_mlat_solver::area::of(site) == Some(model.area) {
                site.location.lat_e7 = (lat * 1e7) as i32;
                site.location.lon_e7 = (lon * 1e7) as i32;
                to = tally_mlat_solver::area::of(site);
            }
        }
        model.area = to.unwrap_or_else(|| panic!("a model of no receiver of its area"));
    }
    model.trailing = tally_mlat_solver::scope::Trailing::at(edge_ms);
    model.input.count = variant;
    let fitted = Decoded::fitted(model).unwrap_or_else(|| panic!("a variant encodes"));
    Decoded::decoded(fitted.bytes.clone()).unwrap_or_else(|| panic!("a variant decodes"))
}

/// The `n`th of distinct places over the globe, two and a half degrees of latitude and 3.6 of
/// longitude apart within 60 degrees of the equator (at least 200 km, where an area is about
/// 110 km across): one area for each of an engine's models of one edge. Where they are does not
/// matter to the store, which holds every area here.
fn place_n(n: usize) -> (f64, f64) {
    let (row, column) = (n / 100, n % 100);
    assert!(row < 48, "{n} areas");
    (-60.0 + row as f64 * 2.5, -178.0 + column as f64 * 3.6)
}

/// A wire fix of a long Mode S message whose address is the fix's, citing `receptions` (all used),
/// under the model `model`.
fn wire_fix(receptions: Vec<tally_wire::Reception>, model: Hash, at_ms: u64) -> tally_wire::Fix {
    let mut message = vec![0x8d; tally_wire::modes::LONG];
    message[1..4].copy_from_slice(&[0xab, 0xcd, 0xef]);
    let set =
        tally_wire::ObservationSet::new(message, receptions).unwrap_or_else(|_| panic!("a set"));
    tally_wire::Fix {
        address: 0x00ab_cdef,
        transmitted: TransmitTime {
            unix_ms: at_ms,
            sub_ms_ps: 0,
        },
        lat_e7: 337_000_000,
        lon_e7: -844_000_000,
        alt_hae_mm: Some(10_000_000),
        covariance: EnuCovariance {
            xx: 900.0,
            xy: 0.0,
            xz: 0.0,
            yy: 900.0,
            yz: 0.0,
            zz: 2_500.0,
        },
        models: vec![model],
        sets: tally_wire::FixSets::new(set.clone(), set).unwrap_or_else(|_| panic!("its sets")),
    }
}

/// [`RECEPTIONS_PER_FIX`] receptions of transmission `n`, each a different receiver of `keys`.
fn receptions_of(n: usize, keys: &[tally_wire::PublicKey]) -> Vec<tally_wire::Reception> {
    (0..RECEPTIONS_PER_FIX)
        .map(|at| tally_wire::Reception {
            receiver: keys[(n * RECEPTIONS_PER_FIX + at) % keys.len()],
            epoch: 1,
            counter: (n * 64 + at) as u64,
        })
        .collect()
}

/// What `run` leaves allocated.
fn held_by<T>(run: impl FnOnce() -> T) -> (usize, T) {
    let base = tally_counting::CountingAll::live();
    let value = run();
    let held = usize::try_from(tally_counting::CountingAll::since(base)).unwrap_or(usize::MAX);
    (held, value)
}

/// The slack the derived plans keep above what the honest worst case they are derived from
/// allocates: the trees planned at their least full nodes (`footprint::btree_planned`).
const DERIVED_SLACK_PERCENT: usize = 150;
/// The book's slack: each engine's share is planned as though it alone solved every transmission
/// (`standing::Caps::of`), so its room holds every transmission's entries and receptions once for
/// each engine, where the honest worst case, every engine solving each, holds them once and each
/// engine's fix beside them. That ratio, from the plan's own entries, and the trees' slack
/// ([`DERIVED_SLACK_PERCENT`]) on it.
fn book_slack_percent() -> usize {
    use tally_relay::standing::{
        ENGINE_HELD_BYTES, ENGINES_PER_TRANSMISSION, RECEPTION_HELD_BYTES,
    };
    let fix = tally_mlat_solver::standing::transmission_bytes_most::<Cited>(1, 0)
        - tally_mlat_solver::standing::transmission_bytes_most::<Cited>(0, 0);
    let alone = ENGINE_HELD_BYTES + RECEPTIONS_PER_FIX * RECEPTION_HELD_BYTES;
    let every = ENGINE_HELD_BYTES
        + (ENGINES_PER_TRANSMISSION - 1) * fix
        + RECEPTIONS_PER_FIX * RECEPTION_HELD_BYTES;
    (ENGINES_PER_TRANSMISSION * alone * DERIVED_SLACK_PERCENT).div_ceil(every)
}

/// The receptions each fix the book is filled with considers: the mean of the fixes published
/// (`standing::PUBLISHED`), rounded down so the receptions filled stay within those planned.
const RECEPTIONS_PER_FIX: usize = tally_relay::standing::PUBLISHED.considered_per_ks
    / tally_relay::standing::PUBLISHED.published_per_ks;
/// The seats the book is filled for: each transmission cites one reception of each, so the
/// receivers the book keeps are its seats'.
const SEATS: usize = RECEPTIONS_PER_FIX;

/// The judging clock the models below are held at: each model refitted at an edge no later than
/// it, and inside the hold of each (`models::HELD_PAST_EDGE_MS` past its edge).
const MODELS_NOW_MS: u64 = 100_000;

/// `model` as a member sends it: its manifest signed by `engine`, its encoding inline or in its
/// parts, and the content the hub joins from it.
fn sent(
    model: &Decoded,
    engine: &Identity,
) -> Result<(tally_wire::ClockModel, tally_wire::ClockModelContent), String> {
    let signed = tally_wire::ClockModel::sign(
        engine,
        &tally_wire::ClockModelContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 1_000,
            spec_version: model.prepared.model.spec,
            inputs: model.inputs,
            model: model.bytes.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    let content = signed
        .manifest
        .content(&signed.parts)
        .map_err(|error| error.to_string())?;
    Ok((signed.manifest, content))
}

/// What a member's model spent of the members' pace at least, as the store reads it: its manifest,
/// which carries its encoding inline or lists the parts that do.
fn wire_of(manifest: &tally_wire::ClockModel, content: &tally_wire::ClockModelContent) -> usize {
    manifest.as_bytes().len().max(content.model.len())
}

/// The measured lines' steps: what each measurement is rounded up to.
const BYTES_STEP: usize = 1 << 10;
const PERCENT_STEP: usize = 10;

/// The lines the models' plans are drawn from, measured at the reference world (`published`):
/// what an area's model holds for each of its receivers (`models::MODEL_BYTES_PER_RECEIVER`, its
/// `held_bytes` over its area's receivers, `models::area_receivers`), what it holds over what it
/// took on the wire (`models::DECODED_PER_WIRE_PERCENT`), and what an owned area's memos hold for
/// each (`mlat_host::AREA_CACHE_BYTES_PER_RECEIVER`, `Engine::area_caches`), each the most of
/// them rounded up. Every model is decoded as a relay decodes one a member sent and admitted to
/// one store as they come: what the store allocates is no more than it charges. And each model's
/// records (its manifest, parts and client summary, as the hosted engine publishes them) are no
/// more than it holds (the newest step's in flight, `models::BYTES_PER_SEAT`), and its prepared
/// lists within their plan (`standing::model_bytes_most`). Returns the model of the most bytes a
/// receiver and the one of the most held over its wire bytes.
fn an_areas_model_is_within_its_bytes_per_receiver(
    records: &[(u64, Record)],
    caches: &[(tally_wire::Region, usize)],
) -> Result<(Decoded, Decoded), String> {
    use tally_relay::mlat_host::AREA_CACHE_BYTES_PER_RECEIVER;
    use tally_relay::models::{
        DECODED_PER_WIRE_PERCENT, MODEL_BYTES_PER_RECEIVER, area_receivers, held_bytes,
    };
    let sent = models_of(records)?;
    assert!(sent.len() > 10, "{} models", sent.len());
    let mut per_receiver: Option<(usize, Decoded)> = None;
    let mut per_wire: Option<(usize, Decoded)> = None;
    let mut receivers_of: BTreeMap<tally_wire::Region, usize> = BTreeMap::new();
    let mut charged = 0;
    for (_, manifest, content) in &sent {
        let decoded =
            Decoded::decoded(content.model.clone()).ok_or("a model that does not decode")?;
        let bytes = held_bytes(&decoded);
        charged += bytes;
        let receivers = area_receivers(&decoded).max(1);
        receivers_of.insert(decoded.area(), receivers);
        let each = bytes.div_ceil(receivers);
        let percent = (bytes * 100).div_ceil(wire_of(manifest, content));
        let prepared = &decoded.prepared.model;
        assert!(
            decoded.prepared.bytes()
                <= tally_mlat_solver::standing::model_bytes_most(
                    prepared.clocks.len(),
                    prepared.pairs.len()
                ),
            "{} clocks, {} pairs",
            prepared.clocks.len(),
            prepared.pairs.len()
        );
        let signer = Identity::from_seed([9; 32]);
        let published = records_by(&decoded, &signer)?;
        let client = tally_mlat_solver::publish::client_model(
            &signer,
            prepared,
            decoded.id(),
            decoded.inputs,
            (1, 0, 1_000),
        )
        .map_err(|error| error.to_string())?;
        let wire: usize = published
            .iter()
            .chain([&Record::ClientClockModel(client)])
            .map(Record::encoded_len)
            .sum();
        assert!(wire <= bytes, "{wire} on the wire, {bytes} held");
        if per_receiver.as_ref().is_none_or(|(most, _)| each > *most) {
            per_receiver = Some((each, variant(&decoded, None, decoded.edge_ms(), 0)));
        }
        if per_wire.as_ref().is_none_or(|(most, _)| percent > *most) {
            per_wire = Some((percent, variant(&decoded, None, decoded.edge_ms(), 0)));
        }
    }
    let cache = caches
        .iter()
        .map(|(area, bytes)| bytes.div_ceil(receivers_of.get(area).copied().unwrap_or(1)))
        .max()
        .ok_or("no area's memos")?;
    let (each, per_receiver) = per_receiver.ok_or("no model")?;
    let (percent, per_wire) = per_wire.ok_or("no model")?;
    println!(
        "worst: an area's model holds {each} a receiver ({MODEL_BYTES_PER_RECEIVER} planned), \
         {percent}% of its wire bytes ({DECODED_PER_WIRE_PERCENT}% planned), its memos {cache} a \
         receiver ({AREA_CACHE_BYTES_PER_RECEIVER} planned)"
    );
    // Admitted as members send them, by the clock of the records as they come.
    let store = Models::new();
    let (allocated, admitted) = held_by(|| {
        sent.iter()
            .map(|(at, manifest, content)| store.admit(manifest, content, |_, _| true, judged(*at)))
            .collect::<Vec<_>>()
    });
    for model in &admitted {
        model.as_ref().map_err(|why| format!("{why:?}"))?;
    }
    assert!(
        allocated <= charged,
        "the models: {allocated} allocated, {charged} charged"
    );
    drop(admitted);
    assert_eq!(
        (
            MODEL_BYTES_PER_RECEIVER,
            DECODED_PER_WIRE_PERCENT,
            AREA_CACHE_BYTES_PER_RECEIVER
        ),
        (
            each.div_ceil(BYTES_STEP) * BYTES_STEP,
            percent.div_ceil(PERCENT_STEP) * PERCENT_STEP,
            cache.div_ceil(BYTES_STEP) * BYTES_STEP
        ),
        "each line is the most measured, rounded up"
    );
    Ok((per_receiver, per_wire))
}

/// `model`'s records as the hosted engine publishes them, signed by `signer`.
fn records_by(model: &Decoded, signer: &Identity) -> Result<Vec<Record>, String> {
    let signed = tally_wire::ClockModel::sign(
        signer,
        &tally_wire::ClockModelContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 1_000,
            spec_version: model.prepared.model.spec,
            inputs: model.inputs,
            model: model.bytes.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(signed.records())
}

/// The edges at which an area's models are held at the judging clock `now_ms`: each a refit
/// apart on the refit grid, the newest the last at or before `now_ms`, each not yet let go
/// (`models::HELD_PAST_EDGE_MS` past it).
fn held_edges(now_ms: u64) -> Vec<u64> {
    use tally_relay::models::{HELD_PAST_EDGE_MS, REFIT_MS};
    let newest = now_ms / REFIT_MS * REFIT_MS;
    (0..)
        .map(|n| newest.saturating_sub(n * REFIT_MS))
        .take_while(|edge| edge + HELD_PAST_EDGE_MS > now_ms)
        .collect()
}

/// The decoded models' store filled to the honest worst case its rooms are derived from
/// (`models::Rooms::of`), both sources at once: its own engine's, its seats' areas (each of the
/// receivers of `own`, the model of the most bytes a receiver) refit at every edge the hold keeps
/// (`held_edges`); and the members', every model their pace can deliver within the hold and its
/// least burst, of the model of the most held over its wire bytes (`wire`). Nothing is refused,
/// and the plan (`models::planned_bytes`) covers what the store allocates within the stated slack.
fn models_at_their_worst(own: &Decoded, wire: &Decoded) -> Result<(), String> {
    use tally_relay::budget::{Gauge, PLANNED_CHARGED_BYTES_PER_SEC, Store};
    use tally_relay::models::{MEMBER_SECONDS, Rooms, Sizing, area_receivers, planned_bytes};
    let seats = 1_000;
    let sizing = Sizing {
        seats,
        members_bytes_per_sec: PLANNED_CHARGED_BYTES_PER_SEC,
    };
    let rooms = Rooms::of(sizing);
    let planned = planned_bytes(sizing);
    let own_engine = Identity::from_seed([4; 32]).public();
    let areas = seats / area_receivers(own).max(1);
    let edges = held_edges(MODELS_NOW_MS);
    // Each made inside the measurement, as the engine's own is made where it is held.
    let slots: Vec<(u64, usize)> = edges
        .iter()
        .flat_map(|edge| (0..areas).map(move |area| (*edge, area)))
        .collect();
    let own_count = slots.len();
    // The members': their pace over the hold and its least burst, in models of the worst shape,
    // each of an area of its own at the newest edge, signed by one engine.
    let paced =
        PLANNED_CHARGED_BYTES_PER_SEC * MEMBER_SECONDS + tally_relay::ceiling::MIN_BURST as usize;
    let member = Identity::from_seed([77; 32]);
    let mut members = Vec::new();
    let mut spent = 0;
    for n in 0.. {
        let model = variant(wire, Some(place_n(areas + n)), edges[0], 2);
        let (manifest, content) = sent(&model, &member)?;
        let bytes = wire_of(&manifest, &content);
        if spent + bytes > paced {
            break;
        }
        spent += bytes;
        members.push((manifest, content));
    }
    assert!(members.len() > 10, "{} members' models", members.len());
    let (held, store) = held_by(|| -> Result<Models, String> {
        let store = Models::new();
        store.size_for(sizing, Gauge::new(Store::Models, planned));
        for (n, (edge, area)) in slots.into_iter().enumerate() {
            let model = variant(own, Some(place_n(area)), edge, 1);
            store
                .insert_own(Arc::new(model), own_engine, judged(MODELS_NOW_MS))
                .map_err(|why| format!("own model {n}: {why:?}"))?;
        }
        for (n, (manifest, content)) in members.iter().enumerate() {
            store
                .admit(manifest, content, |_, _| true, judged(MODELS_NOW_MS))
                .map_err(|why| format!("member's model {n}: {why:?}"))?;
        }
        Ok(store)
    });
    let store = store?;
    let report = store.report();
    assert_eq!(report.held, own_count + members.len(), "{report:?}");
    assert!(
        report.own_bytes <= rooms.own && report.members_bytes <= rooms.members,
        "{report:?}, {rooms:?}"
    );
    println!(
        "worst: models, {seats} seats' own {} of {} and the members' {} of {} ({spent} paced \
         bytes), {held} held, {planned} planned",
        report.own_bytes, rooms.own, report.members_bytes, rooms.members
    );
    assert!(held <= planned, "{held} held, {planned} planned");
    assert!(
        planned * 100 <= held * DERIVED_SLACK_PERCENT,
        "{held} held, {planned} planned"
    );
    Ok(())
}

/// A model of each of an area's engines, held in `store`, as the book's fixes cite them: `model`,
/// each engine's its own.
fn engines_held(store: &Models, model: &Decoded) -> Result<Vec<Model>, String> {
    let edge = held_edges(MODELS_NOW_MS)[0];
    (0..tally_relay::standing::ENGINES_PER_TRANSMISSION)
        .map(|engine| {
            store
                .insert_own(
                    Arc::new(variant(model, None, edge, 10 + engine as u32)),
                    Identity::from_seed([200 + engine as u8; 32]).public(),
                    judged(MODELS_NOW_MS),
                )
                .map_err(|why| format!("{why:?}"))
        })
        .collect()
}

/// A fix of transmission `n` (its receptions `receptions`) by engine `engine`, under `model`.
fn solved_of(
    n: usize,
    engine: usize,
    receptions: &[tally_wire::Reception],
    model: &Model,
) -> tally_mlat_solver::standing::Solved<Cited> {
    let wire = wire_fix(receptions.to_vec(), model.id(), 1_000_000 + n as u64);
    let signer = Identity::from_seed([200 + engine as u8; 32]).public();
    tally_mlat_solver::standing::Solved {
        issued_ms: 1_000_000 + n as u64,
        claimed: tally_mlat_solver::standing::Claimed::of(&wire),
        considered: wire.considered().clone(),
        used: wire.used().clone(),
        model: Cited::new(vec![model.clone()], signer).unwrap_or_else(|| panic!("one model")),
        weight: 3,
        identity: hash((n * 8 + engine) as u64),
    }
}

/// Standing filled to the honest worst case its seats bring (`standing::Caps::of`): the book holds
/// every transmission over its hold (`standing::PENDING_SECONDS`, the arrival bound
/// `FIX_ARRIVED`), each fixed by every engine of its area, and each engine alone within its share.
/// Nothing is refused, and the plan covers what it allocates within the stated slack. And the one
/// positions record standing reads at a time takes decoded no more than `standing::DECODED_BYTES`.
fn standing_at_its_worst(model: &Decoded) -> Result<(), String> {
    use tally_mlat_solver::standing::{Book, BookCaps};
    use tally_relay::standing::{
        BYTES_PER_SEAT, Caps, DECODED_BYTES, FIXED_BYTES, PENDING_SECONDS, PUBLISHED,
    };
    let one = Caps::of(1);
    println!(
        "worst: standing per seat {BYTES_PER_SEAT} (book {}), fixed {FIXED_BYTES}",
        one.book.planned_bytes::<Cited>() - Caps::of(0).book.planned_bytes::<Cited>(),
    );
    println!(
        "worst: book entries: transmission held by one engine {}, a reception {}, a fix {}",
        tally_relay::standing::ENGINE_HELD_BYTES,
        tally_relay::standing::RECEPTION_HELD_BYTES,
        tally_mlat_solver::standing::transmission_bytes_most::<Cited>(1, 0)
            - tally_mlat_solver::standing::transmission_bytes_most::<Cited>(0, 0),
    );
    let caps = Caps::of(SEATS);
    let pool = keys(SEATS);
    let store = Models::new();
    let engines = engines_held(&store, model)?;
    // Each seat's share of the fixes published over the hold, each of the mean receptions.
    let transmissions = SEATS * PUBLISHED.published_per_ks * PENDING_SECONDS / 1_000;
    // The book at rest holds no settled reception and no receiver's standing yet: their entries
    // are planned apart, each at its most.
    let pending = BookCaps {
        settled: 0,
        ..caps.book
    }
    .planned_bytes::<Cited>();
    for alone in [false, true] {
        let (held, book) = held_by(|| {
            let mut book = Book::<Cited>::new(caps.book);
            for n in 0..transmissions {
                let receptions = receptions_of(n, &pool);
                for (engine, model) in engines.iter().enumerate() {
                    if alone && engine > 0 {
                        continue;
                    }
                    let added = book.add(solved_of(n, engine, &receptions, model));
                    assert_eq!(added, Ok(()), "transmission {n}, engine {engine}");
                }
            }
            book
        });
        assert_eq!(book.counts().refused(), 0, "{:?}", book.counts());
        assert_eq!(book.pending(), transmissions);
        let shape = if alone {
            "one engine alone"
        } else {
            "every engine"
        };
        println!("worst: standing book, {shape}, {held} held, {pending} planned");
        assert!(
            held <= pending,
            "the book, {shape}: {held} held, {pending} planned"
        );
        if !alone {
            let slack = book_slack_percent();
            assert!(
                pending * 100 <= held * slack,
                "the book: {held} held, {pending} planned, {slack}% slack"
            );
        }
    }

    // The largest positions records decoded: the most receptions a fix may cite, all of
    // receivers the record names once, and the most fixes of the fewest.
    let signer = Identity::from_seed([9; 32]);
    let receivers = keys(tally_mlat_solver::standing::RECEPTIONS_MOST);
    let mut most_decoded = 0;
    for per in [1, tally_mlat_solver::standing::RECEPTIONS_MOST] {
        let many: Vec<tally_wire::Fix> = (0..20_000)
            .map(|n| {
                let receptions = (0..per)
                    .map(|at| tally_wire::Reception {
                        receiver: receivers[at],
                        epoch: 1,
                        counter: (n * 64 + at) as u64,
                    })
                    .collect();
                wire_fix(receptions, hash(1), 1_000 + n as u64)
            })
            .collect();
        let fits = tally_wire::Positions::fitting_fixes(&many);
        let record = tally_wire::Positions::sign_fix(
            &signer,
            &tally_wire::FixesContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1_000,
                spec_version: tally_mlat_solver::SPEC_VERSION,
                fixes: many[..fits].to_vec(),
            },
        )
        .map_err(|error| error.to_string())?;
        drop(many);
        let peak = peak_of(|| {
            let _ = record.fixes();
        });
        println!(
            "worst: a positions record of {fits} fixes of {per} decoded {peak}, {DECODED_BYTES} planned"
        );
        assert!(
            peak <= DECODED_BYTES,
            "{fits} fixes of {per}: {peak} decoded, {DECODED_BYTES} planned"
        );
        most_decoded = most_decoded.max(peak);
    }
    assert!(
        DECODED_BYTES * 100 <= most_decoded * DERIVED_SLACK_PERCENT,
        "{most_decoded} decoded at most, {DECODED_BYTES} planned"
    );
    Ok(())
}

#[test]
fn the_tables_the_relay_is_sent_into_allocate_no_more_than_they_are_charged() -> Result<(), String>
{
    // The products' remembered tables, each churned past its cap by twice it (so each makes its
    // table of slots anew, beside the old one, the worst instant its plan holds).
    let peak = peak_of(|| {
        let mut regional = Bounded::<Hash, ()>::new(REGIONAL_REMEMBERED);
        let mut models = Bounded::<Hash, Hash>::new(MODELS_REMEMBERED);
        let mut derived = Bounded::<(Hash, u16), u64>::new(DERIVED_REMEMBERED);
        for n in 0..(2 * REGIONAL_REMEMBERED + 2) as u64 {
            regional.insert(hash(n), ());
        }
        for n in 0..(2 * MODELS_REMEMBERED + 2) as u64 {
            models.insert(hash(n), hash(n + 1));
        }
        for n in 0..(2 * DERIVED_REMEMBERED + 2) as u64 {
            derived.insert((hash(n), 1), n);
        }
        assert_eq!(regional.len(), REGIONAL_REMEMBERED);
        assert_eq!(models.len(), MODELS_REMEMBERED);
        assert_eq!(derived.len(), DERIVED_REMEMBERED);
    });
    assert!(
        peak <= REMEMBERED_BYTES,
        "the remembered tables: {peak} at the peak, {REMEMBERED_BYTES} charged"
    );

    // A world gatherer's fixes, by second and by aircraft, as charged fix by fix.
    for (seconds, per_second) in [(1usize, 1usize), (3, 100), (40, 1_000), (200, 37)] {
        let fixes: Vec<(u64, WorldFix)> = (0..seconds as u64)
            .flat_map(|second| {
                (0..per_second as u32)
                    .map(move |address| (second, world_fix(address, second * 1_000)))
            })
            .collect();
        let charged =
            WORLD_SECONDS_ROOT_BYTES + seconds * WORLD_SECOND_BYTES + fixes.len() * WORLD_FIX_BYTES;
        let peak = peak_of(|| {
            let mut held: BTreeMap<u64, BTreeMap<u32, WorldFix>> = BTreeMap::new();
            for (second, fix) in &fixes {
                held.entry(*second).or_default().insert(fix.address, *fix);
            }
            assert_eq!(held.len(), seconds);
        });
        assert!(
            peak <= charged,
            "{seconds} seconds of {per_second} fixes: {peak} at the peak, {charged} charged"
        );
    }

    let delivered = delivered()?;
    // A step's working set (`mlat_host::STEP_BYTES_PER_SEAT`), measured on the reference
    // simulation and on a dense one whose every receiver keeps all the others as its pairs' other
    // ends: the most of it a seat, rounded up.
    let step = step_bytes_per_seat(&delivered)?.max(step_bytes_per_seat(&dense()?)?);
    println!(
        "worst: a step's working set {step} a seat ({} planned)",
        tally_relay::mlat_host::STEP_BYTES_PER_SEAT
    );
    assert_eq!(
        tally_relay::mlat_host::STEP_BYTES_PER_SEAT,
        step.div_ceil(BYTES_STEP) * BYTES_STEP,
        "a step's working set is the most measured, rounded up"
    );
    let (_, records, caches) = published(&delivered)?;
    // The lines the models' plans are drawn from first: every plan below stands on them.
    let (per_receiver, per_wire) =
        an_areas_model_is_within_its_bytes_per_receiver(&records, &caches)?;
    let areas = areas_of(&records);
    assert!(!areas.is_empty(), "no model's area");
    // Standing keeps the band of its areas beside its tables: the relay's configuration, built
    // once at its start and so in its measured base (`budget::MEASURED_IDLE_BYTES`), not a table.
    let band = held_by(|| tally_mlat::area::Band::of(&areas)).0;
    // Every model the engine published, held in the relay's store as the hub admits it whole
    // before the positions citing it are sent, each by the clock of its record: the store is
    // charged apart (`Store::Models`), so it is filled before standing is measured.
    let models = Arc::new(Models::new());
    models.set_areas(&areas);
    for (at, manifest, content) in models_of(&records)? {
        let admitted = models.admit(&manifest, &content, |_, _| true, judged(at));
        assert!(admitted.is_ok(), "{admitted:?}");
    }

    // Standing, its book small enough that what the engine published passes its room.
    let caps = tally_relay::standing::Caps {
        book: tally_mlat_solver::standing::BookCaps {
            pending_bytes: 8 << 10,
            source_share: 8 << 10,
            receivers: 256,
            settled: 16,
        },
    };
    let mut measured = None;
    let base = tally_counting::CountingAll::live();
    let peak = peak_of(|| {
        let standing = Arc::new(Standing::with_models(Arc::clone(&models)));
        standing.set_areas(&areas);
        let gauge = tally_relay::budget::Gauge::unlimited(tally_relay::budget::Store::Standing);
        if !standing.size_to(caps, &gauge) || Standing::start(&standing, None).is_err() {
            return;
        }
        let (mut rest, mut uncounted) = (0, 0);
        for (at, record) in &records {
            match record {
                Record::Positions(positions) if !positions.is_tagged() => {
                    standing.positions(positions, judged(*at));
                }
                _ => continue,
            }
            // One record at a time, settled before the next, so the book fills as it would.
            assert!(standing.wait_idle(Duration::from_secs(120)), "never idle");
            let live =
                usize::try_from(tally_counting::CountingAll::since(base)).unwrap_or(usize::MAX);
            rest = rest.max(live);
            let report = standing.report();
            uncounted = uncounted.max(live.saturating_sub(counted(&caps, &report)));
        }
        measured = Some((standing.report(), rest, uncounted));
    });
    let (report, rest, uncounted) = measured.ok_or("standing did not start")?;
    assert!(models.report().held > 2, "{:?}", models.report());
    let planned = caps.planned_bytes();
    // At its worst instant, a record decoded in hand beside its tables.
    assert!(
        peak <= planned + THREAD_BYTES + band,
        "standing: {peak} at the peak, {planned} planned: {report:?}"
    );
    // At rest, no record in hand: its tables alone, within their rooms, and never more than they
    // count (`counted`), whatever they hold.
    let tables = planned - tally_relay::standing::DECODED_BYTES;
    assert!(
        rest <= tables + THREAD_BYTES + band,
        "standing at rest: {rest} held, its tables {tables}: {report:?}"
    );
    assert!(
        uncounted <= THREAD_BYTES + band,
        "standing at rest held {uncounted} more than its tables count: {report:?}"
    );
    // Not vacuous: it took fixes in under the models held, and refused past its rooms.
    assert!(report.taken > 0 && report.pending_bytes > 0, "{report:?}");
    assert_eq!(
        (report.unmodelled, report.outside, report.unsolved),
        (0, 0, 0),
        "{report:?}"
    );
    assert!(report.forgotten > 0, "no room was reached: {report:?}");

    models_at_their_worst(&per_receiver, &per_wire)?;
    standing_at_its_worst(&per_receiver)?;
    Ok(())
}
