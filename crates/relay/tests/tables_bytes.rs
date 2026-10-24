//! The tables that grow with what the relay is sent cost no more than the stores they are charged
//! to (RFC-0181 "Memory is charged once"): the products' remembered tables at their caps
//! (`products::REMEMBERED_BYTES`, `budget::Store::Remembered`), a world gatherer's fixes and
//! seconds (`products::WORLD_FIX_BYTES`, `budget::Store::World`), standing's tables
//! (`standing::Caps::planned_bytes`, `budget::Store::Standing`) and the relay's decoded clock
//! models (`models::planned_bytes`, its own engine's per seat and the members' by their pace,
//! `budget::Store::Models`), each fed past its caps and filled to the honest worst case its plan
//! is derived from.
//! Measured by an allocator that counts every byte asked of it, in one test so nothing else in
//! the binary allocates while it measures.

#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tally_mlat::engine::{Capacity, Engine, Settings};
use tally_mlat::intake::SiteRecord;
use tally_mlat::replay::{arrivals, replay, scenario};
use tally_relay::bounded::Bounded;
use tally_relay::models::{Model, Models};
use tally_relay::products::{
    DERIVED_REMEMBERED, MODELS_REMEMBERED, REGIONAL_REMEMBERED, REMEMBERED_BYTES, WORLD_FIX_BYTES,
    WORLD_SECOND_BYTES, WORLD_SECONDS_ROOT_BYTES,
};
use tally_relay::standing::{Sized, Standing, StandingReport};
use tally_wire::batch::Hash;
use tally_wire::clocks::recorded::judged;
use tally_wire::{EnuCovariance, Identity, Record, TransmitTime, WorldFix};

#[global_allocator]
static GLOBAL: tally_counting::CountingAll = tally_counting::CountingAll;

/// What a thread of the table's own takes beside its tables (its handle, its name, its closure):
/// standing's thread, started inside the measurement.
const THREAD_BYTES: usize = 16 << 10;

/// What standing's tables hold by their own count (`StandingReport`): the hand-off's slots and
/// what its solutions hold, and the book's transmissions, its receivers and settled receptions at
/// their most.
fn counted(caps: &tally_relay::standing::Caps, report: &StandingReport) -> usize {
    tally_wire::footprint::vec::<tally_mlat_solver::standing::Solved<Model>>(caps.handed.count)
        + report.handed_bytes
        + tally_mlat_solver::standing::BookCaps {
            pending_bytes: report.pending_bytes,
            ..caps.book
        }
        .planned_bytes::<Model>()
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

/// What a reference engine published: the site records it placed its receivers by, and its records
/// each with when it was published.
type Published = (Vec<SiteRecord>, Vec<(u64, Record)>);

/// What a reference engine publishes over a simulation: clock models (manifests and parts) and
/// positions, raw and tagged, final and provisional, each with when it was published, and the
/// site records its receivers were placed by.
fn published() -> Result<Published, String> {
    let mut simulation = tally_mlat_solver::sim::run(&scenario(23, 120.0));
    let delivered = arrivals(&mut simulation, 5)?;
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = Engine::new(
        tally_wire::Signer::new(Identity::from_seed([4; 32]), Arc::new(|| true)),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, 1_000>(),
            threads: 2,
            capacity: Capacity::default(),
        },
    );
    let sites = delivered
        .iter()
        .filter_map(|(_, record)| SiteRecord::of(record))
        .collect();
    Ok((sites, replay(&mut engine, &delivered, 100, until)?))
}

/// The areas that own the tiles `records` hold models of: what a relay hosting their MLAT holds.
fn areas_of(records: &[(u64, Record)]) -> tally_wire::Regions {
    tally_wire::Regions::new(records.iter().filter_map(|(_, record)| {
        let Record::ClockModel(manifest) = record else {
            return None;
        };
        let content = manifest.content(&[]).ok()?;
        let model =
            tally_mlat_solver::publish::decode(&content.model, content.spec_version).ok()?;
        tally_wire::Region::containing(
            &tally_mlat::area::centre(model.tile),
            tally_wire::rendezvous::AREA_RESOLUTION,
        )
        .ok()
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
        provisional: false,
        mlat: true,
        input_set: [1; 32],
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

/// A model of `members` at the most the plan allows each list (`standing::model_bytes_most`): a
/// piece for each member and one for each jump, every piece at `KNOTS_MOST` knots, every bias,
/// jump and dropped clock, as an engine would encode it (`publish::encode`).
fn worst_model(members: &[tally_wire::PublicKey], tile: u64) -> tally_mlat_solver::ClockModel {
    shaped(
        members,
        Shape {
            knots: tally_mlat_solver::standing::KNOTS_MOST,
            biases: tally_mlat_solver::standing::BIASES_MOST,
            jumps: tally_mlat_solver::sync::MAX_JUMPS,
            dropped: true,
        },
        tile,
    )
}

/// The lists a model of [`shaped`] holds beside its members: each piece's knots, the biases, the
/// jumps (each a piece more), and whether each clock is dropped too.
#[derive(Clone, Copy, Debug)]
struct Shape {
    knots: usize,
    biases: usize,
    jumps: usize,
    dropped: bool,
}

/// A model of `members` (each a piece) of tile `tile` and `shape`'s lists, as an engine would
/// encode it, decoded.
fn shaped(
    members: &[tally_wire::PublicKey],
    shape: Shape,
    tile: u64,
) -> tally_mlat_solver::ClockModel {
    use tally_mlat_solver::clock::{Bias, BiasKind, ClockKey, ClockPiece, Jump, Timebase};
    let Shape {
        knots,
        biases,
        jumps,
        dropped,
    } = shape;
    let scope = members
        .iter()
        .map(|receiver| tally_mlat_solver::obs::Site {
            receiver: *receiver,
            clock: tally_wire::Clock::Beast,
            location: tally_wire::Location {
                lat_e7: 337_000_000,
                lon_e7: -844_000_000,
                alt_m: 300,
                precision_m: 10,
            },
            id: tally_wire::SiteId(*receiver.as_bytes()),
        })
        .collect::<Vec<_>>();
    let mut keys: Vec<ClockKey> = members
        .iter()
        .map(|receiver| ClockKey {
            receiver: *receiver,
            epoch: 1,
            piece: 0,
        })
        .collect();
    keys.extend((1..=jumps).map(|piece| ClockKey {
        receiver: members[0],
        epoch: 1,
        piece: piece as u16,
    }));
    keys.sort();
    let gauge = keys[0];
    let pieces = keys
        .iter()
        .map(|key| ClockPiece {
            key: *key,
            timebase: Timebase::Mhz12,
            begins: None,
            ends: None,
            site_mm: [1, 2, 3],
            site_sigma_mm: 1_000,
            noise_ps: 50_000,
            base: 0,
            first: 0,
            offsets_ps: (0..knots as i64)
                .map(|knot| if *key == gauge { 0 } else { knot + 1 })
                .collect(),
        })
        .collect();
    let kinds = [
        BiasKind::East,
        BiasKind::North,
        BiasKind::Barometric,
        BiasKind::GnssHeight,
    ];
    let biases = (0..biases)
        .map(|n| Bias {
            address: (n / 4) as u32,
            kind: kinds[n % 4],
            mm: 10,
        })
        .collect();
    let jumps = (0..jumps)
        .map(|n| Jump {
            receiver: members[0],
            epoch: 1,
            at: n as i64,
            step_ps: 1_000,
        })
        .collect();
    let dropped = if dropped {
        keys.iter()
            .map(|key| (key.receiver, key.epoch + u32::from(key.piece)))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    let model = tally_mlat_solver::ClockModel {
        spec: tally_mlat_solver::SPEC_VERSION,
        tile: tally_mlat_solver::tile::Tile {
            level: 0,
            cube: [tile as i64, 0, 0],
        },
        window: tally_mlat_solver::scope::Window { first: 0, last: 12 },
        scope,
        input: tally_mlat_solver::scope::Citation {
            hash: hash(tile),
            count: 3,
        },
        gauge,
        origin_unix_ns: 0,
        gauge_rate: 0,
        pieces,
        biases,
        jumps,
        dropped,
    };
    // Decoded from its encoding, so every list has the capacity a relay's decoding gives it.
    let bytes = tally_mlat_solver::publish::encode(&model)
        .unwrap_or_else(|error| panic!("{members:?}: {error:?}", members = members.len()));
    tally_mlat_solver::publish::decode(&bytes, tally_mlat_solver::SPEC_VERSION)
        .unwrap_or_else(|error| panic!("{members:?}: {error:?}", members = members.len()))
}

/// A wire solution citing `receptions`, under the model `model`.
fn wire_solution(
    receptions: Vec<tally_wire::Reception>,
    model: Hash,
    at_ms: u64,
) -> tally_wire::Solution {
    tally_wire::Solution {
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
        clock_model: model,
        addressed: tally_wire::AddressedCitation {
            hash: hash(at_ms),
            count: 9,
        },
        observations: tally_wire::ObservationSet::new(
            vec![0x8d; tally_relay::standing::MESSAGE_BYTES],
            receptions,
        )
        .unwrap_or_else(|_| panic!("a set")),
    }
}

/// `CITED_LEAST` receptions of transmission `n`, each a different receiver of `keys`.
fn receptions_of(n: usize, keys: &[tally_wire::PublicKey]) -> Vec<tally_wire::Reception> {
    (0..tally_relay::standing::CITED_LEAST)
        .map(|at| tally_wire::Reception {
            receiver: keys[(n * tally_relay::standing::CITED_LEAST + at) % keys.len()],
            epoch: 1,
            counter: (n * 8 + at) as u64,
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
/// each engine, where the honest worst case, every engine solving each, holds them once.
const BOOK_SLACK_PERCENT: usize = 250;

/// The seats the book and the hand-off are filled for: each transmission cites one reception of
/// each, so the receivers the book keeps are its seats'.
const SEATS: usize = tally_relay::standing::CITED_LEAST;

/// The judging clock the models below are held at: past the last bin of their windows (`shaped`'s,
/// and the few after it a slot holds), and inside the hold of each (`models::HOLD_MS`).
const MODELS_NOW_MS: u64 = 60_000;

/// `model` as a member sends it: its manifest signed by `engine`, its encoding inline, and the
/// content the hub joins from it.
fn sent(
    model: &tally_mlat_solver::ClockModel,
    engine: &Identity,
) -> Result<(tally_wire::ClockModel, tally_wire::ClockModelContent), String> {
    let encoded =
        tally_mlat_solver::publish::encode(model).map_err(|error| format!("{error:?}"))?;
    let signed = tally_wire::ClockModel::sign(
        engine,
        &tally_wire::ClockModelContent {
            boot_id: 1,
            sequence: 0,
            issued_ms: 1_000,
            spec_version: tally_mlat_solver::SPEC_VERSION,
            inputs: tally_mlat_solver::publish::inputs_id(model),
            model: encoded,
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

/// The members' models' decoded bytes over their wire bytes (`models::DECODED_PER_WIRE_PERCENT`),
/// measured by the counting allocator at every shape an engine fits: from the fewest members a
/// published model has to the most a tile has, each piece at the fewest knots a piece has (two) or
/// the most, the biases, the jumps and the dropped clocks none or all. Each shape is admitted as a
/// member sends it, many at once so the store's trees grow as they do held: what they allocate is
/// no more than they are charged (`models::held_bytes`), and the charge no more than the ratio
/// allows. The ratio is the most of them, rounded up: the worst honest shape. Returns that shape.
fn decoded_per_wire() -> Result<(usize, Shape), String> {
    use tally_relay::models::{DECODED_PER_WIRE_PERCENT, MODEL_MEMBERS_LEAST, held_bytes};
    const EACH: usize = 32;
    let pool = keys(tally_mlat_solver::tile::MEMBERS_MAX);
    let engine = Identity::from_seed([31; 32]);
    let mut worst: Option<(usize, usize, Shape)> = None;
    let mut most_allocated = 0;
    for members in [
        MODEL_MEMBERS_LEAST,
        4,
        8,
        16,
        tally_mlat_solver::tile::MEMBERS_MAX,
    ] {
        for knots in [2, tally_mlat_solver::standing::KNOTS_MOST] {
            for (biases, jumps, dropped) in [
                (0, 0, false),
                (tally_mlat_solver::standing::BIASES_MOST, 0, false),
                (0, tally_mlat_solver::sync::MAX_JUMPS, false),
                (0, 0, true),
                (
                    tally_mlat_solver::standing::BIASES_MOST,
                    tally_mlat_solver::sync::MAX_JUMPS,
                    true,
                ),
            ] {
                let shape = Shape {
                    knots,
                    biases,
                    jumps,
                    dropped,
                };
                let models: Vec<_> = (0..EACH)
                    .map(|n| {
                        let model = shaped(&pool[..members], shape, 10_000 + n as u64);
                        let (manifest, content) = sent(&model, &engine)?;
                        Ok((held_bytes(&model), manifest, content))
                    })
                    .collect::<Result<_, String>>()?;
                let store = Models::new();
                let (allocated, admitted) = held_by(|| {
                    models
                        .iter()
                        .map(|(_, manifest, content)| {
                            store.admit(manifest, content, |_, _| true, judged(MODELS_NOW_MS))
                        })
                        .collect::<Vec<_>>()
                });
                for model in &admitted {
                    model
                        .as_ref()
                        .map_err(|why| format!("{members} members, {shape:?}: {why:?}"))?;
                }
                let (charged, wire): (usize, usize) = models
                    .iter()
                    .map(|(bytes, manifest, content)| (*bytes, wire_of(manifest, content)))
                    .fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
                assert!(
                    allocated <= charged,
                    "{members} members, {shape:?}: {allocated} allocated, {charged} charged"
                );
                most_allocated = most_allocated.max((allocated * 100).div_ceil(wire));
                let percent = (charged * 100).div_ceil(wire);
                if worst.is_none_or(|(most, _, _)| percent > most) {
                    worst = Some((percent, members, shape));
                }
            }
        }
    }
    let (percent, members, shape) = worst.ok_or("no shape")?;
    println!(
        "worst: models decoded per wire, {percent}% charged and {most_allocated}% allocated at \
         most, at {members} members {shape:?}; {DECODED_PER_WIRE_PERCENT}% planned"
    );
    assert_eq!(
        DECODED_PER_WIRE_PERCENT, percent,
        "the ratio is the most an engine's shapes are charged"
    );
    Ok((members, shape))
}

/// The decoded models' store filled to the honest worst case its rooms are derived from
/// (`models::Rooms::of`), both sources at once: its own engine's, every seat a member of
/// `models::OWN_MEMBERSHIPS_PER_SEAT` models in each window a slot holds, each model of the fewest
/// members a published model has (the most models for the memberships), each list at its most; and
/// the members', every model their pace can deliver within the hold, at the shape whose decoded
/// bytes weigh most against its wire bytes. Nothing is refused, and the plan
/// (`models::planned_bytes`) covers what the store allocates within the stated slack. And a model's
/// records, as the hosted engine queues them, take no more than the model decoded (the newest
/// window's records in flight, `models::BYTES_PER_SEAT`).
fn models_at_their_worst() -> Result<(), String> {
    use tally_relay::budget::{Gauge, PLANNED_CHARGED_BYTES_PER_SEC, Store};
    use tally_relay::models::{
        MEMBER_SECONDS, MODEL_MEMBERS_LEAST, MODEL_WINDOWS, OWN_MEMBERSHIPS_PER_SEAT, Rooms,
        Sizing, held_bytes, planned_bytes,
    };
    let (worst_members, worst_shape) = decoded_per_wire()?;
    let members_max = tally_mlat_solver::tile::MEMBERS_MAX;
    // The seats each own model has as members: each a membership of every seat.
    let seats = MODEL_MEMBERS_LEAST;
    let sizing = Sizing {
        seats,
        members_bytes_per_sec: PLANNED_CHARGED_BYTES_PER_SEC,
    };
    let rooms = Rooms::of(sizing);
    let planned = planned_bytes(sizing);
    let pool = keys(members_max.max(seats));
    let own_engine = pool[0];
    // Its own: each window a slot holds, every tile a seat is a member of.
    let mut own = Vec::new();
    for window in 0..MODEL_WINDOWS as i64 {
        for tile in 0..OWN_MEMBERSHIPS_PER_SEAT {
            let mut model = worst_model(&pool[..seats], tile as u64);
            model.window.first += window;
            model.window.last += window;
            own.push(model);
        }
    }
    // The members': their pace over the hold and its least burst, in models of the worst shape,
    // each signed by an engine of its own.
    let paced =
        PLANNED_CHARGED_BYTES_PER_SEC * MEMBER_SECONDS + tally_relay::ceiling::MIN_BURST as usize;
    let mut members = Vec::new();
    let mut wire = 0;
    for n in 0.. {
        let model = shaped(&pool[..worst_members], worst_shape, 100_000 + n);
        let (manifest, content) = sent(&model, &Identity::from_seed([77; 32]))?;
        let bytes = wire_of(&manifest, &content);
        if wire + bytes > paced {
            break;
        }
        wire += bytes;
        members.push((manifest, content));
    }
    assert!(members.len() > 100, "{} members' models", members.len());
    let (held, store) = held_by(|| -> Result<Models, String> {
        let store = Models::new();
        store.size_for(sizing, Gauge::new(Store::Models, planned));
        for (n, model) in own.into_iter().enumerate() {
            store
                .insert_own(
                    hash(n as u64),
                    Arc::new(model),
                    own_engine,
                    judged(MODELS_NOW_MS),
                )
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
    assert_eq!(
        report.held,
        MODEL_WINDOWS * OWN_MEMBERSHIPS_PER_SEAT + members.len(),
        "{report:?}"
    );
    assert!(
        report.own_bytes <= rooms.own && report.members_bytes <= rooms.members,
        "{report:?}, {rooms:?}"
    );
    println!(
        "worst: models, {seats} seats' own {} of {} and the members' {} of {} ({wire} paced \
         bytes), {held} held, {planned} planned",
        report.own_bytes, rooms.own, report.members_bytes, rooms.members
    );
    assert!(held <= planned, "{held} held, {planned} planned");
    assert!(
        planned * 100 <= held * DERIVED_SLACK_PERCENT,
        "{held} held, {planned} planned"
    );
    // Every model a tile may have: inline, so none waits for parts; its records no larger than
    // it decoded, so a window's in flight is a window's held at most; and its most exactly the
    // line the plan shares per member.
    let signer = Identity::from_seed([9; 32]);
    for members in 1..=members_max {
        let model = worst_model(&pool[..members], 1);
        let encoded =
            tally_mlat_solver::publish::encode(&model).map_err(|error| error.to_string())?;
        assert!(
            encoded.len() <= tally_wire::clock_model::MAX_INLINE_LEN,
            "{} bytes",
            encoded.len()
        );
        let signed = tally_wire::ClockModel::sign(
            &signer,
            &tally_wire::ClockModelContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1_000,
                spec_version: tally_mlat_solver::SPEC_VERSION,
                inputs: hash(3),
                model: encoded,
            },
        )
        .map_err(|error| error.to_string())?;
        assert!(signed.parts.is_empty());
        let client = tally_wire::ClientClockModel::sign(
            &signer,
            &tally_mlat_solver::publish::client_model(
                &model,
                signed.manifest.id(),
                hash(3),
                (1, 0, 1_000),
            ),
        )
        .map_err(|error| error.to_string())?;
        let records: usize = signed
            .records()
            .iter()
            .chain([&Record::ClientClockModel(client)])
            .map(Record::encoded_len)
            .sum();
        let bytes = held_bytes(&model);
        assert!(
            records <= bytes,
            "{members} members: {records} on the wire, {bytes} held"
        );
        assert!(
            tally_mlat_solver::standing::model_bytes(&model)
                <= tally_mlat_solver::standing::model_bytes_most(members),
            "{members} members"
        );
    }
    Ok(())
}

/// A model of each of an area's engines, held in `store`, as the book's solutions cite them.
fn engines_held(store: &Models, pool: &[tally_wire::PublicKey]) -> Result<Vec<Model>, String> {
    (0..tally_relay::standing::ENGINES_PER_TRANSMISSION)
        .map(|engine| {
            store
                .insert_own(
                    hash(500 + engine as u64),
                    Arc::new(worst_model(pool, 500 + engine as u64)),
                    Identity::from_seed([200 + engine as u8; 32]).public(),
                    judged(MODELS_NOW_MS),
                )
                .map_err(|why| format!("{why:?}"))
        })
        .collect()
}

/// A solution of transmission `n` (its receptions `receptions`) by the engine of `model`.
fn solved_of(
    n: usize,
    engine: usize,
    receptions: &[tally_wire::Reception],
    model: &Model,
    provisional: bool,
) -> tally_mlat_solver::standing::Solved<Model> {
    let wire = wire_solution(receptions.to_vec(), model.id(), 1_000_000 + n as u64);
    tally_mlat_solver::standing::Solved {
        provisional,
        issued_ms: 1_000_000 + n as u64,
        claimed: tally_mlat_solver::standing::Claimed::of(&wire),
        observations: wire.observations,
        model: model.clone(),
        weight: 3,
        identity: hash((n * 8 + engine) as u64),
        consistent: provisional.then_some(true),
    }
}

/// Standing filled to the honest worst case its seats bring (`standing::Caps::of`): the book holds
/// every transmission over its hold, each solved by every engine of its area as a final and a
/// provisional, and each engine alone within its share; the hand-off a step's solutions. Nothing is
/// refused, and the plan covers what each allocates within the stated slack. And the one positions
/// record standing reads at a time takes decoded no more than `standing::DECODED_BYTES`.
fn standing_at_its_worst() -> Result<(), String> {
    use tally_mlat_solver::standing::{Book, BookCaps};
    use tally_relay::standing::{
        BYTES_PER_SEAT, Caps, DECODED_BYTES, ENGINES_PER_TRANSMISSION, FIXED_BYTES, HANDED_SECONDS,
        PENDING_SECONDS, TRANSMISSIONS_PER_SEAT_PER_SEC,
    };
    let one = Caps::of(1);
    println!(
        "worst: standing per seat {BYTES_PER_SEAT} (book {}, hand-off {}), fixed {FIXED_BYTES}",
        one.book.planned_bytes::<Model>() - Caps::of(0).book.planned_bytes::<Model>(),
        tally_wire::footprint::vec::<tally_mlat_solver::standing::Solved<Model>>(one.handed.count)
            + one.handed.room,
    );
    println!(
        "worst: book entries: transmission held by one engine {}, a reception {}, a final {}, a provisional {}",
        tally_relay::standing::ENGINE_HELD_BYTES,
        tally_relay::standing::RECEPTION_HELD_BYTES,
        tally_mlat_solver::standing::transmission_bytes_most::<Model>(1, 0, 0)
            - tally_mlat_solver::standing::transmission_bytes_most::<Model>(0, 0, 0),
        tally_mlat_solver::standing::transmission_bytes_most::<Model>(0, 1, 0)
            - tally_mlat_solver::standing::transmission_bytes_most::<Model>(0, 0, 0),
    );
    let caps = Caps::of(SEATS);
    let pool = keys(SEATS);
    let store = Models::new();
    let engines = engines_held(&store, &pool)?;
    let transmissions = SEATS * TRANSMISSIONS_PER_SEAT_PER_SEC * PENDING_SECONDS;
    // The book at rest holds no settled reception and no receiver's standing yet: their entries
    // are planned apart, each at its most.
    let pending = BookCaps {
        settled: 0,
        ..caps.book
    }
    .planned_bytes::<Model>();
    for alone in [false, true] {
        let (held, book) = held_by(|| {
            let mut book = Book::<Model>::new(caps.book);
            for n in 0..transmissions {
                let receptions = receptions_of(n, &pool);
                for (engine, model) in engines.iter().enumerate() {
                    if alone && engine > 0 {
                        continue;
                    }
                    for provisional in [false, true] {
                        let added = book.add(solved_of(n, engine, &receptions, model, provisional));
                        assert_eq!(added, Ok(()), "transmission {n}, engine {engine}");
                    }
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
            assert!(
                pending * 100 <= held * BOOK_SLACK_PERCENT,
                "the book: {held} held, {pending} planned"
            );
        }
    }

    // The hand-off: a step's finals and a second's provisionals of every engine, in the list made
    // once at its length.
    let step = SEATS * TRANSMISSIONS_PER_SEAT_PER_SEC * ENGINES_PER_TRANSMISSION * HANDED_SECONDS;
    assert_eq!(step, caps.handed.count);
    let (held, handed) = held_by(|| {
        let mut handed = std::collections::VecDeque::with_capacity(caps.handed.count);
        for n in 0..step {
            let engine = n % engines.len();
            handed.push_back(solved_of(
                n,
                engine,
                &receptions_of(n, &pool),
                &engines[engine],
                n % 2 == 0,
            ));
        }
        handed
    });
    assert_eq!(handed.capacity(), caps.handed.count);
    let planned =
        tally_wire::footprint::vec::<tally_mlat_solver::standing::Solved<Model>>(caps.handed.count)
            + caps.handed.room;
    println!("worst: standing hand-off {held} held, {planned} planned");
    assert!(
        held <= planned,
        "the hand-off: {held} held, {planned} planned"
    );
    assert!(
        planned * 100 <= held * DERIVED_SLACK_PERCENT,
        "the hand-off: {held} held, {planned} planned"
    );
    drop(handed);

    // The largest positions records decoded: the most receptions a solution may cite, all of
    // receivers the record names once, and the most solutions of the fewest.
    let signer = Identity::from_seed([9; 32]);
    let receivers = keys(tally_mlat_solver::tile::MEMBERS_MAX);
    let mut most_decoded = 0;
    for per in [1, tally_mlat_solver::tile::MEMBERS_MAX] {
        let many: Vec<tally_wire::Solution> = (0..20_000)
            .map(|n| {
                let receptions = (0..per)
                    .map(|at| tally_wire::Reception {
                        receiver: receivers[at],
                        epoch: 1,
                        counter: (n * 64 + at) as u64,
                    })
                    .collect();
                wire_solution(receptions, hash(1), 1_000 + n as u64)
            })
            .collect();
        let fits = tally_wire::Positions::fitting(&many);
        let record = tally_wire::Positions::sign_solutions(
            &signer,
            &tally_wire::SolutionsContent {
                boot_id: 1,
                sequence: 0,
                issued_ms: 1_000,
                spec_version: tally_mlat_solver::SPEC_VERSION,
                solutions: many[..fits].to_vec(),
            },
        )
        .map_err(|error| error.to_string())?;
        drop(many);
        let peak = peak_of(|| {
            let _ = record.solutions();
        });
        println!(
            "worst: a positions record of {fits} solutions of {per} decoded {peak}, {DECODED_BYTES} planned"
        );
        assert!(
            peak <= DECODED_BYTES,
            "{fits} solutions of {per}: {peak} decoded, {DECODED_BYTES} planned"
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

    let (_, records) = published()?;
    let areas = areas_of(&records);
    assert!(!areas.is_empty(), "no model's area");
    // Standing keeps the band of its areas beside its tables: the relay's configuration, built
    // once at its start and so in its measured base (`budget::MEASURED_IDLE_BYTES`), not a table.
    let band = held_by(|| tally_mlat::area::Band::of(&areas)).0;
    // Every model the engine published, held in the relay's store as the hub admits it whole,
    // before the positions citing it are sent: the store is charged apart (`Store::Models`).
    let models = Arc::new(Models::new());
    models.set_areas(&areas);
    for (at, record) in &records {
        if let Record::ClockModel(manifest) = record {
            let content = manifest.content(&[]).map_err(|error| error.to_string())?;
            models
                .admit(manifest, &content, |_, _| true, judged(*at))
                .map_err(|why| format!("{why:?}"))?;
        }
    }
    assert!(models.report().held > 2, "{:?}", models.report());

    // Standing, its book small enough that what the engine published passes it; its hand-off holds
    // the largest record's solutions.
    let caps = tally_relay::standing::Caps {
        handed: Sized {
            count: 4_096,
            room: 1 << 20,
        },
        book: tally_mlat_solver::standing::BookCaps {
            pending_bytes: 32 << 10,
            source_share: 32 << 10,
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
                Record::Positions(positions) | Record::Provisional(positions)
                    if !positions.is_tagged() =>
                {
                    standing.positions(positions, judged(*at));
                }
                _ => continue,
            }
            // One record at a time, so the hand-off refuses none and the book fills.
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
    let planned = caps.planned_bytes();
    // At its worst instant, a record decoded in hand beside its tables.
    assert!(
        peak <= planned + THREAD_BYTES + band,
        "standing: {peak} at the peak, {planned} planned: {report:?}"
    );
    // At rest, no record in hand and the hand-off empty: its tables alone, within their rooms,
    // and never more than they count (`counted`), whatever they hold.
    let tables = planned - tally_relay::standing::DECODED_BYTES;
    assert!(
        rest <= tables + THREAD_BYTES + band,
        "standing at rest: {rest} held, its tables {tables}: {report:?}"
    );
    assert!(
        uncounted <= THREAD_BYTES + band,
        "standing at rest held {uncounted} more than its tables count: {report:?}"
    );
    // Not vacuous: it took solutions in under the models held, and refused past its rooms.
    assert!(report.taken > 0 && report.pending_bytes > 0, "{report:?}");
    assert_eq!((report.unmodelled, report.refused), (0, 0), "{report:?}");
    assert!(report.forgotten > 0, "no room was reached: {report:?}");

    models_at_their_worst()?;
    standing_at_its_worst()?;
    Ok(())
}
