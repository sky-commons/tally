//! A client's positions pass only when the relay paired them with their raw twin and checked every
//! fix, by the records its model names, and a lie in one never passes.
#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use super::*;
use crate::models::Models;
use tally_mlat::engine::{Capacity, Engine, Settings, Step};
use tally_mlat::replay::{replay, scenario};
use tally_mlat_solver::sim;
use tally_wire::{Identity, ReceiverSite, ReceiverSiteContent, Record};

/// The engine's key in these tests.
const ENGINE_SEED: [u8; 32] = [4; 32];

/// What a reference engine publishes over a short simulation, step by step, and the site records
/// it placed its receivers by.
#[allow(
    clippy::disallowed_methods,
    reason = "a reference engine's signer, on a clock that always judges"
)]
fn published() -> Result<(Vec<Step>, Vec<SiteRecord>), String> {
    let mut simulation = sim::run(&scenario(23, 40.0));
    let delivered = sim::arrived_records(&mut simulation, 5).map_err(|error| error.to_string())?;
    let sites: Vec<SiteRecord> = delivered
        .iter()
        .filter_map(|(_, record)| SiteRecord::of(record))
        .collect();
    let until = delivered.last().map_or(0, |(at, _)| *at) + 10_000;
    let mut engine = Engine::new(
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            threads: 2,
            capacity: Capacity::default(),
        },
    );
    let signer = tally_wire::Signer::new(
        Identity::from_seed(ENGINE_SEED),
        std::sync::Arc::new(|| true),
    );
    let steps = replay(&mut engine, &delivered, &signer, until)?
        .into_iter()
        .map(|(_, step)| step)
        .collect();
    Ok((steps, sites))
}

/// Every record the steps published, in the order sent.
fn records(steps: &[Step]) -> Vec<Record> {
    steps.iter().flat_map(Step::records).collect()
}

/// Every model the steps published, held in `models` as the relay holds its own engine's
/// (`Models::insert_own`).
fn hold_models(models: &Models, steps: &[Step]) {
    let engine = Identity::from_seed(ENGINE_SEED).public();
    for step in steps {
        for model in &step.models {
            let _ = models.insert_own(
                Arc::clone(&model.model),
                engine,
                tally_wire::clocks::recorded::judged(model.edge_ms),
            );
        }
    }
}

/// Checks over `models` for a handful of links.
fn checks_of(models: &Arc<Models>) -> Consistency {
    Consistency::with_caps(
        Arc::clone(models),
        Caps::of(Sizing {
            receivers: 64,
            links: 4,
        }),
    )
}

/// The steps' fix records as pairs, raw then tagged, as the engine sent them.
fn pairs(steps: &[Step]) -> Vec<(Positions, Positions)> {
    steps
        .iter()
        .flat_map(|step| step.fixes.iter())
        .map(|fix| (fix.raw.clone(), fix.tagged.clone()))
        .collect()
}

/// The checks with every model and site held, as a relay forwarding the engine's records holds
/// them.
fn holding(steps: &[Step], sites: &[SiteRecord]) -> Consistency {
    let models = Arc::new(Models::new());
    hold_models(&models, steps);
    let checks = checks_of(&models);
    for site in sites {
        checks.site(site);
    }
    checks
}

/// Every tagged record of an honest engine passes once its raw twin came before it on the same
/// link, and a raw record is never a client's.
#[test]
fn an_honest_engines_client_forms_pass_and_a_raw_record_is_never_a_clients() -> Result<(), String> {
    let (steps, sites) = published()?;
    let checks = holding(&steps, &sites);
    let pairs = pairs(&steps);
    assert!(!pairs.is_empty(), "the engine published no fixes");
    for (raw, tagged) in &pairs {
        checks.raw(raw, 1);
        assert_eq!(checks.check(tagged, 1), Verdict::Passes);
        // Asked again (a record that waited for its model), it still pairs.
        assert_eq!(checks.check(tagged, 1), Verdict::Passes);
        assert_eq!(checks.check(raw, 1), Verdict::Fails);
    }
    assert_eq!(checks.report().held, pairs.len() as u64);
    Ok(())
}

/// How far north a lie moves a fix, in 1e-7 degrees: four times the distance its receptions may
/// still agree with (`standing::AGREE_Z` of its own stated uncertainty, the covariance's trace
/// twice, `standing::reception_zs`), and 2 km at least, which is far past any clock's noise. A fix of weak geometry states kilometres of
/// height uncertainty, and a lie inside what it states is no lie its receptions can show.
fn far_off(covariance: &tally_wire::EnuCovariance) -> i32 {
    const METRES_PER_E7_DEGREE: f64 = 111_320.0 / 1e7;
    let trace = f64::from(covariance.xx) + f64::from(covariance.yy) + f64::from(covariance.zz);
    let agrees_m = tally_mlat_solver::standing::AGREE_Z * (2.0 * trace).sqrt();
    let metres = (4.0 * agrees_m).max(2_000.0);
    (metres / METRES_PER_E7_DEGREE).ceil() as i32
}

/// A fix that claims a place its own receptions do not put the aircraft at (moved far past what
/// it states it may be off by, [`far_off`], raw and tagged re-signed alike by an engine of its
/// own) fails: a client never takes it, so it never refuses an honest bigger one. So does a tagged
/// record that is not its raw's twin.
#[test]
fn a_fix_its_own_receptions_disagree_with_fails() -> Result<(), String> {
    let (steps, sites) = published()?;
    let checks = holding(&steps, &sites);
    let (raw, tagged) = pairs(&steps).into_iter().next().ok_or("no fixes")?;
    let text = |error: tally_wire::WireError| error.to_string();
    let liar = Identity::from_seed([66; 32]);
    let mut lying_raw = raw.fixes().map_err(text)?;
    lying_raw.fixes.truncate(1);
    let off = far_off(&lying_raw.fixes[0].covariance);
    lying_raw.fixes[0].lat_e7 += off;
    let mut lying_tagged = tagged.tagged_fixes().map_err(text)?;
    lying_tagged.fixes.truncate(1);
    lying_tagged.fixes[0].lat_e7 += off;
    checks.raw(&Positions::sign_fix(&liar, &lying_raw).map_err(text)?, 2);
    assert_eq!(
        checks.check(
            &Positions::sign_tagged_fix(&liar, &lying_tagged).map_err(text)?,
            2
        ),
        Verdict::Fails
    );
    // The honest raw, and a tagged record moved off it: not its twin.
    checks.raw(&raw, 3);
    let mut moved = tagged.tagged_fixes().map_err(text)?;
    moved.fixes[0].lat_e7 += 180_000;
    let engine = Identity::from_seed(ENGINE_SEED);
    assert_eq!(
        checks.check(
            &Positions::sign_tagged_fix(&engine, &moved).map_err(text)?,
            3
        ),
        Verdict::Fails
    );
    Ok(())
}

/// What the relay cannot check is not passed: no raw twin on its link (none, or another link's),
/// no model, or no site the model names.
#[test]
fn what_cannot_be_checked_is_unknown() -> Result<(), String> {
    let (steps, sites) = published()?;
    let (raw, tagged) = pairs(&steps).into_iter().next().ok_or("no fixes")?;
    let checks = holding(&steps, &sites);
    assert_eq!(checks.check(&tagged, 1), Verdict::Unknown, "no twin held");
    checks.raw(&raw, 2);
    assert_eq!(checks.check(&tagged, 1), Verdict::Unknown, "another link's");
    let unmodelled = Consistency::new(Arc::new(Models::new()));
    for site in &sites {
        unmodelled.site(site);
    }
    unmodelled.raw(&raw, 1);
    assert_eq!(unmodelled.check(&tagged, 1), Verdict::Unknown, "no model");
    // Everything but the sites: the tags cannot be made.
    let unsited = holding(&steps, &[]);
    unsited.raw(&raw, 1);
    assert_eq!(unsited.check(&tagged, 1), Verdict::Unknown, "no site");
    Ok(())
}

/// A receiver that re-signs its site mid-window (same place, newer record) still pairs: its tags
/// are keyed by the record the model's scope names, by its site id, not by its newest. Keyed by
/// the newest, nothing would.
#[test]
fn a_site_re_signed_mid_window_still_pairs() -> Result<(), String> {
    let (steps, sites) = published()?;
    let checks = holding(&steps, &sites);
    let mut resigned = Vec::new();
    let simulation = sim::run(&scenario(23, 40.0));
    for feed in simulation.feeds().map_err(|e| e.to_string())? {
        let content = feed.site.content().map_err(|e| e.to_string())?;
        let newer = ReceiverSite::sign(
            &feed.identity,
            &ReceiverSiteContent {
                issued_ms: content.issued_ms + 1,
                ..content
            },
        )
        .map_err(|e| e.to_string())?;
        resigned.push(SiteRecord::Site(newer));
    }
    for site in &resigned {
        checks.site(site);
    }
    let (raw, tagged) = pairs(&steps).into_iter().next().ok_or("no fixes")?;
    checks.raw(&raw, 1);
    assert_eq!(checks.check(&tagged, 1), Verdict::Passes);
    // Keyed by each receiver's newest record instead, the tags are not the client's.
    let newest = |receiver: &PublicKey| {
        resigned
            .iter()
            .find(|site| site.receiver().ok() == Some(*receiver))
            .map(SiteRecord::reception_key)
    };
    let fix = &raw.fixes().map_err(|e| e.to_string())?.fixes[0];
    let client = &tagged.tagged_fixes().map_err(|e| e.to_string())?.fixes[0];
    assert_ne!(fix.tagged(newest).ok().as_ref(), Some(client));
    Ok(())
}

/// A link holds one raw record, its last: the next takes its place, one that ends lets its own
/// go, and more links than planned let the least recently active go, counted. Never more than the
/// caps' records are held.
#[test]
fn a_link_holds_its_last_raw_record_alone() -> Result<(), String> {
    let (steps, sites) = published()?;
    let checks = holding(&steps, &sites);
    let pairs = pairs(&steps);
    let [(first_raw, first_tagged), (second_raw, second_tagged), ..] = pairs.as_slice() else {
        return Err("fewer than two fix records".to_owned());
    };
    checks.raw(first_raw, 1);
    checks.raw(second_raw, 1);
    assert_eq!(checks.check(first_tagged, 1), Verdict::Unknown);
    assert_eq!(checks.check(second_tagged, 1), Verdict::Passes);
    checks.forget(1);
    assert_eq!(checks.check(second_tagged, 1), Verdict::Unknown);
    let caps = checks.caps();
    for link in 0..(caps.links as u64 + 3) {
        checks.raw(first_raw, 100 + link);
    }
    let report = checks.report();
    assert_eq!(report.evicted, 3, "{report:?}");
    assert!(
        report.bytes <= caps.links * RECORD_HELD_MOST,
        "{report:?} {caps:?}"
    );
    Ok(())
}

/// The sites are sized from the receiver figure and the twins from the links alone, one record a
/// link: a receiver of the figure costs the twins nothing, and no seat or rate does either. Each
/// is charged whole to its store; a store that cannot hold its tables is charged nothing and the
/// relay does not start. The figures are linear as the budget plans them (`FIXED_BYTES`,
/// `BYTES_PER_RECEIVER`, `twins_fixed_bytes`), never short of the tables' own plan.
#[test]
fn the_checks_are_sized_from_what_drives_them_and_charged_whole() {
    for receivers in [0, 1, 7, 100, 4_096, 100_000, 1 << 20] {
        assert!(
            planned_bytes(receivers) <= FIXED_BYTES + receivers * BYTES_PER_RECEIVER,
            "{receivers} receivers"
        );
    }
    for links in [0, 1, 7, 64, 513] {
        let caps = Caps::of(Sizing {
            receivers: 0,
            links,
        });
        assert_eq!(
            caps.twins_bytes(),
            Caps::of(Sizing {
                receivers: 1 << 20,
                links,
            })
            .twins_bytes(),
            "the twins follow no receiver"
        );
        assert_eq!(caps.twins_bytes(), twins_fixed_bytes(links));
        assert!(caps.links > links, "a link that ended beside its successor");
        assert!(caps.twins_bytes() >= caps.links * RECORD_HELD_MOST + WORKING_BYTES);
    }
    let checks = Consistency::new(Arc::new(Models::new()));
    assert!(checks.charged_in_full().is_err(), "charged before sized");
    let sites = crate::budget::Gauge::new(crate::budget::Store::Consistency, usize::MAX);
    let twins = crate::budget::Gauge::new(crate::budget::Store::Twins, usize::MAX);
    let sized = Sizing {
        receivers: 1_000,
        links: 10,
    };
    assert!(checks.size_for(sized, &sites, &twins));
    assert_eq!(sites.held(), planned_bytes(1_000));
    assert_eq!(twins.held(), Caps::of(sized).twins_bytes());
    assert!(checks.charged_in_full().is_ok());
    let short = crate::budget::Gauge::new(
        crate::budget::Store::Twins,
        Caps::of(sized).twins_bytes() - 1,
    );
    assert!(!checks.size_for(sized, &sites, &short));
    assert_eq!(
        (sites.held(), twins.held()),
        (0, 0),
        "what it held is given back"
    );
    assert!(checks.charged_in_full().is_err());
}

/// The positions pace a seat is planned at is one kind of fix at the seat's measured share of
/// the fixes published and the receptions they considered, raw and tagged, for every fix its
/// engine publishes of a transmission (its fast fix and its complete one): no factor for a second
/// kind, and no transmission planned that one an aircraft a slot does not solve.
#[test]
fn a_seats_positions_are_every_fix_of_each_transmission_raw_and_tagged() {
    let published = tally_mlat_solver::backoff::Published::MEASURED;
    let per_ks = crate::standing::FIXES_PER_TRANSMISSION
        * (published.published_per_ks * 2 * SOLUTION_WIRE_MOST
            + published.considered_per_ks * (RAW_RECEPTION_WIRE_MOST + TAGGED_RECEPTION_WIRE_MOST));
    assert_eq!(POSITIONS_BYTES_PER_SEAT_PER_SEC, per_ks.div_ceil(1_000));
}

/// Through the hub: a client's listener is given every honest client form, checked, and never the
/// lie, which no one is sent; raw positions reach relays and never a client.
#[test]
fn the_hub_sends_a_client_only_what_passed() -> Result<(), String> {
    use crate::fanout::Filter;
    use crate::hub::Hub;
    use crate::subscription::Subscription;
    use tally_wire::Streams;
    let (steps, sites) = published()?;
    let records = records(&steps);
    // By the clock the engine signed them at, moved to each record's signing as it is sent, as a
    // relay's own engine's records leave in time: a record outside the window of time is not
    // forwarded (`strikes`), and the run is longer than the window.
    let issued_of = |record: &Record| match record {
        Record::Positions(positions) => positions.issued_ms().ok(),
        Record::ClockModel(model) => model.issued_ms().ok(),
        _ => None,
    };
    let first = records.iter().find_map(issued_of).ok_or("no records")?;
    let now = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(first));
    // Its engine's areas taken (those its models are of): the store holds models there.
    let mut areas: Vec<tally_wire::Region> = steps
        .iter()
        .flat_map(|step| step.models.iter())
        .map(|model| model.area)
        .collect();
    areas.sort_unstable_by_key(|area| area.as_u64());
    areas.dedup();
    let clock = std::sync::Arc::clone(&now);
    let hub = Hub::clocked(
        8,
        std::sync::Arc::new(move || clock.load(std::sync::atomic::Ordering::SeqCst)),
        crate::sharing::Deadlines::RELAY,
    )
    .taking(areas);
    let client = hub.listen(
        1,
        Filter::Client(
            Subscription {
                streams: Streams::POSITIONS,
                regions: Vec::new(),
            }
            .for_client(),
        ),
    );
    let relay = hub.listen(2, Filter::Everything);
    // Its engine taken as its area's: the store holds its models, in rooms a test's (the hub's
    // plan hosts no MLAT, so its own engine's room is none).
    hub.network()
        .clock_models
        .set_rooms(crate::models::Rooms::UNSIZED);
    hold_models(&hub.network().clock_models, &steps);
    for site in &sites {
        hub.network().consistency.site(site);
    }
    let mut honest = 0;
    let mut lie: Option<Positions> = None;
    // Read as they are sent, as a client and a relay read them, by the clock that moves.
    let mut to_client: Vec<Positions> = Vec::new();
    let mut to_relay: Vec<Positions> = Vec::new();
    let read =
        |to_client: &mut Vec<Positions>, to_relay: &mut Vec<Positions>| -> Result<(), String> {
            while let Some(item) = client.try_recv() {
                let client = item.client.as_ref().ok_or("an item with no client form")?;
                match &*client.record {
                    tally_wire::ClientRecord::Positions(positions) => {
                        to_client.push(positions.get().clone());
                    }
                    other => return Err(format!("a client was sent kind {}", other.kind())),
                }
            }
            while let Some(item) = relay.try_recv() {
                if let Record::Positions(positions) = &*item.record {
                    to_relay.push(positions.clone());
                }
            }
            Ok(())
        };
    for record in &records {
        if let Some(issued) = issued_of(record) {
            now.fetch_max(issued, std::sync::atomic::Ordering::SeqCst);
        }
        hub.publish_own(record.clone());
        if let Record::Positions(positions) = record
            && positions.is_tagged()
        {
            honest += 1;
            // The first tagged record's lie, sent by its engine right after it, on the link whose
            // last raw record is its twin's: paired (the same sequence, just after the raw), and
            // not the twin's tagged form.
            if lie.is_none() {
                let mut content = positions.tagged_fixes().map_err(|e| e.to_string())?;
                content.fixes[0].lat_e7 += 180_000;
                let one = Positions::sign_tagged_fix(&Identity::from_seed(ENGINE_SEED), &content)
                    .map_err(|e| e.to_string())?;
                hub.publish_own(Record::Positions(one.clone()));
                lie = Some(one);
            }
        }
        read(&mut to_client, &mut to_relay)?;
    }
    let lie = lie.ok_or("no client forms")?;
    for positions in &to_client {
        assert!(positions.is_tagged());
        assert_ne!(positions.hash(), lie.hash());
    }
    assert_eq!(
        to_client.len(),
        honest,
        "{:?} {:?}",
        hub.network().consistency.report(),
        hub.network().clock_models.report()
    );
    let mut raw = 0;
    for positions in &to_relay {
        assert_ne!(positions.hash(), lie.hash(), "the lie was passed on");
        raw += usize::from(!positions.is_tagged());
    }
    assert!(raw > 0);
    assert_eq!(hub.network().consistency.refused(), 1);
    Ok(())
}

/// Whichever order a receiver's site and its description reach the hub (a site that comes first
/// waits for the description it pairs with, as one carried by another relay's link may), the site
/// the hub adopts is one the checks hold: every adopted site reaches them by the one path
/// (`Network::on_info`). Before, a site adopted when its description came was never held, so no
/// client was sent a position from a relay whose sites came first.
#[test]
fn a_site_the_hub_adopts_is_held_whichever_came_first() -> Result<(), String> {
    use crate::hub::Hub;
    use tally_wire::{Location, PublicInfoContent, ReceiverInfo, Region};
    let text = |error: tally_wire::WireError| error.to_string();
    for site_first in [true, false] {
        let hub = Hub::new(8, crate::sharing::Deadlines::RELAY);
        let identity = Identity::from_seed([9; 32]);
        let location = Location {
            lat_e7: 374_400_000,
            lon_e7: -1_221_400_000,
            alt_m: 20,
            precision_m: 0,
        };
        let info = ReceiverInfo::sign_public(
            &identity,
            &PublicInfoContent {
                issued_ms: 5,
                cell: Some(Region::public_cell(&location).map_err(text)?),
                clock: tally_wire::Clock::Dump1090,
                software: "test".to_owned(),
                relays: Vec::new(),
            },
        )
        .map_err(text)?;
        let site = ReceiverSite::sign(
            &identity,
            &ReceiverSiteContent {
                issued_ms: 5,
                location,
                clock: tally_wire::Clock::Dump1090,
            },
        )
        .map_err(text)?;
        let describe = || hub.publish_info(1, info.clone(), identity.public(), 5, None, true);
        if site_first {
            hub.publish_site(1, site.clone());
            describe();
        } else {
            describe();
            hub.publish_site(1, site.clone());
        }
        assert_eq!(
            hub.network()
                .consistency
                .inner()
                .sites
                .get(&site.site_id())
                .copied(),
            Some(site.reception_key()),
            "the site {} its description was not held",
            if site_first { "before" } else { "after" }
        );
    }
    Ok(())
}
