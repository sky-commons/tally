//! A client's positions pass only when the relay rematched and checked every solution, by the
//! records its model names, and a lie in one never passes.
#![allow(clippy::disallowed_methods, reason = "a test's scripted readings")]

use super::*;
use crate::models::Models;
use tally_mlat::engine::{Capacity, Engine, Settings};
use tally_mlat::replay::{arrivals, replay, scenario};
use tally_mlat_solver::sim;
use tally_wire::{Identity, ReceiverSite, ReceiverSiteContent, Record};

/// What a reference engine publishes over a short simulation, and the site records it placed its
/// receivers by.
#[allow(
    clippy::disallowed_methods,
    reason = "a reference engine's signer, on a clock that always judges"
)]
fn published() -> Result<(Vec<Record>, Vec<SiteRecord>), String> {
    let mut simulation = sim::run(&scenario(23, 40.0));
    let delivered = arrivals(&mut simulation, 5)?;
    let sites: Vec<SiteRecord> = delivered
        .iter()
        .filter_map(|(_, record)| SiteRecord::of(record))
        .collect();
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = Engine::new(
        tally_wire::Signer::new(Identity::from_seed([4; 32]), std::sync::Arc::new(|| true)),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle: tally_wire::budget::policy::<_, 1_000>(),
            threads: 2,
            capacity: Capacity::default(),
        },
    );
    let records = replay(&mut engine, &delivered, 100, until)?
        .into_iter()
        .map(|(_, record)| record)
        .collect();
    Ok((records, sites))
}

/// Every model `records` carry, admitted whole to `models` as the hub admits one
/// (`Network::admit_model`), its engine taken as its area's.
#[allow(
    clippy::disallowed_methods,
    reason = "a reading as each model's engine publishes it"
)]
fn admit_models(models: &Models, records: &[Record]) {
    let parts: Vec<tally_wire::ClockModelPart> = records
        .iter()
        .filter_map(|record| match record {
            Record::ClockModelPart(part) => Some(part.clone()),
            _ => None,
        })
        .collect();
    for record in records {
        if let Record::ClockModel(manifest) = record {
            let listed: Vec<tally_wire::ClockModelPart> = parts
                .iter()
                .filter(|part| part.model().ok() == Some(manifest.id()))
                .cloned()
                .collect();
            if let Ok(content) = manifest.content(&listed)
                && let Ok(model) =
                    tally_mlat_solver::publish::decode(&content.model, content.spec_version)
            {
                // As its engine publishes it: once its window's last bin is past.
                let published =
                    (model.window.last.max(0) as u64 + 1) * tally_mlat_solver::scope::GRID_MS;
                let _ = models.admit(
                    manifest,
                    &content,
                    |_, _| true,
                    tally_wire::clocks::recorded::judged(published),
                );
            }
        }
    }
}

/// Checks over `models` with room for every raw record a short simulation publishes.
fn roomy(models: &Arc<Models>) -> Consistency {
    Consistency::with_caps(
        Arc::clone(models),
        Caps::of(Sizing {
            receivers: 64,
            members: 4,
            members_bytes_per_sec: 1 << 20,
            own_bytes_per_sec: 1 << 20,
        }),
    )
}

/// The monotonic reading `ms`.
#[allow(clippy::disallowed_methods, reason = "a test's scripted readings")]
fn at(ms: u64) -> Mono {
    tally_wire::clocks::recorded::mono(ms)
}

/// Everything but the client forms handed in, as a relay forwarding them would: sites, the models
/// admitted to the relay's store, raw positions (a member's, every solution wanted). The client
/// forms, in order.
fn fed(records: &[Record], sites: &[SiteRecord]) -> (Consistency, Vec<Positions>) {
    let models = Arc::new(Models::new());
    admit_models(&models, records);
    let checks = roomy(&models);
    for site in sites {
        checks.site(site);
    }
    let mut tagged = Vec::new();
    for record in records {
        if let Record::Positions(positions) | Record::Provisional(positions) = record {
            if positions.is_tagged() {
                tagged.push(positions.clone());
            } else {
                checks.raw(positions, (1, Class::Members), at(0), |_| true);
            }
        }
    }
    (checks, tagged)
}

#[test]
fn an_honest_engines_client_forms_pass_and_a_raw_record_is_never_a_clients() -> Result<(), String> {
    let (records, sites) = published()?;
    let (checks, tagged) = fed(&records, &sites);
    let finals = tagged.iter().filter(|one| !one.is_provisional()).count();
    assert!(finals > 0, "the engine published no final positions");
    for positions in &tagged {
        assert_eq!(checks.check(positions), Verdict::Passes);
    }
    let raw = records
        .iter()
        .find_map(|record| match record {
            Record::Positions(positions) if !positions.is_tagged() => Some(positions),
            _ => None,
        })
        .ok_or("no raw positions")?;
    assert_eq!(checks.check(raw), Verdict::Fails);
    Ok(())
}

/// A solution that claims a place its own receptions do not put the aircraft at (moved 2 km,
/// re-signed by an engine of its own) fails: a client never takes it, so it never refuses an
/// honest bigger one.
#[test]
fn a_solution_its_own_receptions_disagree_with_fails() -> Result<(), String> {
    let (records, sites) = published()?;
    let (checks, tagged) = fed(&records, &sites);
    let honest = tagged
        .iter()
        .find(|one| !one.is_provisional())
        .ok_or("no final positions")?;
    let mut content = honest.tagged_solutions().map_err(|e| e.to_string())?;
    content.solutions.truncate(1);
    content.solutions[0].lat_e7 += 180_000;
    let liar = Identity::from_seed([66; 32]);
    let lying = Positions::sign_tagged(&liar, &content).map_err(|e| e.to_string())?;
    assert_eq!(checks.check(&lying), Verdict::Fails);
    Ok(())
}

/// What the relay cannot check is not passed: no raw twin, no model, or no site the model names.
#[test]
fn what_cannot_be_checked_is_unknown() -> Result<(), String> {
    let (records, sites) = published()?;
    let (_, tagged) = fed(&records, &sites);
    let one = tagged.first().ok_or("no client forms")?;
    assert_eq!(
        Consistency::new(Arc::new(Models::new())).check(one),
        Verdict::Unknown
    );
    // Everything but the sites: the tags cannot be rematched.
    let (unsited, _) = fed(&records, &[]);
    assert_eq!(unsited.check(one), Verdict::Unknown);
    Ok(())
}

/// A receiver that re-signs its site mid-window (same place, newer record) still rematches: its
/// tags are keyed by the record the model's scope names, by its site id, not by its newest. Keyed
/// by the newest, nothing would.
#[test]
fn a_site_re_signed_mid_window_still_rematches() -> Result<(), String> {
    let (records, sites) = published()?;
    let (checks, tagged) = fed(&records, &sites);
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
    let one = tagged
        .iter()
        .find(|one| !one.is_provisional())
        .ok_or("no final positions")?;
    assert_eq!(checks.check(one), Verdict::Passes);
    // Keyed by each receiver's newest record instead, the tags match nothing.
    let solution = &one.tagged_solutions().map_err(|e| e.to_string())?.solutions[0];
    let key = checks.fingerprint(
        &solution.clock_model,
        solution.address,
        solution.transmitted,
    );
    let receptions = {
        let inner = checks.inner();
        let twin = inner.twins.get(&key).ok_or("no twin")?;
        twin.raw.solutions().map_err(|e| e.to_string())?.solutions[usize::from(twin.index)]
            .observations
            .receptions()
            .to_vec()
    };
    let newest = |receiver: &PublicKey| {
        resigned
            .iter()
            .find(|site| site.receiver().ok() == Some(*receiver))
            .map(SiteRecord::reception_key)
    };
    assert!(publish::rematch(solution, receptions, newest).is_none());
    Ok(())
}

/// Through the hub: a client's listener is given every honest client form, checked, and never the
/// lie, which no one is sent; raw positions reach relays and never a client.
#[test]
fn the_hub_sends_a_client_only_what_passed() -> Result<(), String> {
    use crate::fanout::Filter;
    use crate::hub::Hub;
    use crate::subscription::Subscription;
    use tally_wire::Streams;
    let (records, sites) = published()?;
    // By the clock the engine signed them at: a record outside the window of time is not
    // forwarded (`strikes`).
    let issued = records
        .iter()
        .filter_map(|record| match record {
            Record::Positions(positions) | Record::Provisional(positions) => {
                positions.issued_ms().ok()
            }
            Record::ClockModel(model) => model.issued_ms().ok(),
            _ => None,
        })
        .max()
        .ok_or("no records")?;
    // Its engine's areas taken (those its models' tiles are in): the store holds models there, and
    // the members the areas bring are the room the twins are held in.
    let parts: Vec<tally_wire::ClockModelPart> = records
        .iter()
        .filter_map(|record| match record {
            Record::ClockModelPart(part) => Some(part.clone()),
            _ => None,
        })
        .collect();
    let mut areas: Vec<tally_wire::Region> = records
        .iter()
        .filter_map(|record| match record {
            Record::ClockModel(manifest) => {
                let listed: Vec<tally_wire::ClockModelPart> = parts
                    .iter()
                    .filter(|part| part.model().ok() == Some(manifest.id()))
                    .cloned()
                    .collect();
                manifest.content(&listed).ok()
            }
            _ => None,
        })
        .filter_map(|content| tally_mlat_solver::publish::tile_of(&content.model).ok())
        .filter_map(|tile| {
            tally_wire::Region::containing(
                &tally_mlat::area::centre(tile),
                tally_wire::rendezvous::AREA_RESOLUTION,
            )
            .ok()
        })
        .collect();
    areas.sort_unstable_by_key(|area| area.as_u64());
    areas.dedup();
    let hub = Hub::clocked(
        8,
        std::sync::Arc::new(move || issued),
        crate::sharing::Deadlines::RELAY,
    )
    .taking(areas);
    let client = hub.listen(
        1,
        Filter::Client(
            Subscription {
                streams: Streams::POSITIONS.with(Streams::PROVISIONAL),
                regions: Vec::new(),
            }
            .for_client(),
        ),
    );
    let relay = hub.listen(2, Filter::Everything);
    // Its engine taken as its area's: the store holds its models (`Network::admit_model`).
    admit_models(&hub.network().clock_models, &records);
    for site in &sites {
        hub.network().consistency.site(site);
    }
    let mut honest = 0;
    let mut lie = None;
    for record in &records {
        if let Record::Positions(positions) = record
            && positions.is_tagged()
        {
            honest += 1;
            if lie.is_none() {
                let mut content = positions.tagged_solutions().map_err(|e| e.to_string())?;
                content.solutions.truncate(1);
                content.solutions[0].lat_e7 += 180_000;
                lie = Some(
                    Positions::sign_tagged(&Identity::from_seed([66; 32]), &content)
                        .map_err(|e| e.to_string())?,
                );
            }
        }
        if !matches!(record, Record::Provisional(_)) {
            hub.publish_own(record.clone());
        }
    }
    let lie = lie.ok_or("no client forms")?;
    hub.publish_own(Record::Positions(lie.clone()));
    let mut to_client = 0;
    while let Some(item) = client.try_recv() {
        let client = item.client.as_ref().ok_or("an item with no client form")?;
        match &*client.record {
            tally_wire::ClientRecord::Positions(positions) => {
                assert!(positions.get().is_tagged());
                assert_ne!(positions.get().hash(), lie.hash());
                to_client += 1;
            }
            other => return Err(format!("a client was sent kind {}", other.kind())),
        }
    }
    assert_eq!(
        to_client,
        honest,
        "{:?} {:?}",
        hub.network().consistency.report(),
        hub.network().clock_models.report()
    );
    let mut raw = 0;
    while let Some(item) = relay.try_recv() {
        if let Record::Positions(positions) = &*item.record {
            assert_ne!(positions.hash(), lie.hash(), "the lie was passed on");
            raw += usize::from(!positions.is_tagged());
        }
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

/// The sites are sized from the receiver figure and the twins from what drives them, the MLAT
/// records a second the relay admits (its own engine's at its seats, the members' at their pace)
/// over the hold: a receiver of the figure costs the twins nothing. Each is charged whole to its
/// store; a store that cannot hold its tables is charged nothing and the relay does not start.
/// The figures are linear as the budget plans them (`FIXED_BYTES`, `BYTES_PER_RECEIVER`,
/// `twins_fixed_bytes`, `TWIN_BYTES_PER_SEAT`, `TWIN_BYTES_PER_MEMBER_FEEDER`), never short of the
/// tables' own plan. Before, every twin was planned per receiver of the figure, though the checks
/// see every raw record the members and the engine forward, worldwide.
#[test]
fn the_checks_are_sized_from_what_drives_them_and_charged_whole() {
    for receivers in [0, 1, 7, 100, 4_096, 100_000, 1 << 20] {
        assert!(
            planned_bytes(receivers) <= FIXED_BYTES + receivers * BYTES_PER_RECEIVER,
            "{receivers} receivers"
        );
    }
    let sizing = |receivers: usize, seats: usize, member_feeders: usize| Sizing {
        receivers,
        members: 16,
        members_bytes_per_sec: member_feeders * crate::budget::PLANNED_CHARGED_BYTES_PER_SEC,
        own_bytes_per_sec: seats * OWN_RAW_BYTES_PER_SEAT_PER_SEC,
    };
    for (seats, member_feeders) in [(0, 1), (1, 0), (7, 3), (4_096, 125), (100_000, 1)] {
        let caps = Caps::of(sizing(0, seats, member_feeders));
        assert_eq!(
            caps.twins_bytes(),
            Caps::of(sizing(1 << 20, seats, member_feeders)).twins_bytes(),
            "the twins follow no receiver"
        );
        assert!(
            caps.twins_bytes()
                <= twins_fixed_bytes(16)
                    + seats * TWIN_BYTES_PER_SEAT
                    + member_feeders * TWIN_BYTES_PER_MEMBER_FEEDER,
            "{seats} seats, {member_feeders} member feeders"
        );
        // Little's law: each room holds its rate's records over the hold, as held.
        let s = sizing(0, seats, member_feeders);
        assert!(caps.own.bytes >= s.own_bytes_per_sec * TWIN_SECONDS);
        assert!(caps.members.bytes >= s.members_bytes_per_sec * TWIN_SECONDS);
    }
    let checks = Consistency::new(Arc::new(Models::new()));
    assert!(checks.charged_in_full().is_err(), "charged before sized");
    let sites = crate::budget::Gauge::new(crate::budget::Store::Consistency, usize::MAX);
    let twins = crate::budget::Gauge::new(crate::budget::Store::Twins, usize::MAX);
    let sized = sizing(1_000, 10, 2);
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

/// A raw record of `raw`'s solutions, each moved `by` milliseconds later and re-signed: as many
/// new solutions as it held, citing the same models.
fn moved(raw: &Positions, by: u64) -> Result<Positions, String> {
    let mut content = raw.solutions().map_err(|e| e.to_string())?;
    for solution in &mut content.solutions {
        solution.transmitted.unix_ms += by;
    }
    content.sequence += by;
    Positions::sign_solutions(&Identity::from_seed([77; 32]), &content).map_err(|e| e.to_string())
}

/// The twins kept for a client's sake only: a raw solution whose model the store does not hold
/// (none of the relay's areas, or not come) or that no client's subscription covers is not held,
/// counted, and its tagged twin is unknown, so it goes to relays alone.
#[test]
fn only_a_solution_that_can_be_checked_for_a_client_is_held() -> Result<(), String> {
    let (records, sites) = published()?;
    let models = Arc::new(Models::new());
    let raws: Vec<&Positions> = records
        .iter()
        .filter_map(|record| match record {
            Record::Positions(positions) | Record::Provisional(positions)
                if !positions.is_tagged() =>
            {
                Some(positions)
            }
            _ => None,
        })
        .collect();
    let solutions: usize = raws
        .iter()
        .map(|raw| raw.solutions().map_or(0, |content| content.solutions.len()))
        .sum();
    // No model held: nothing is.
    let unmodelled = roomy(&models);
    for raw in &raws {
        unmodelled.raw(raw, (1, Class::Members), at(0), |_| true);
    }
    let report = unmodelled.report();
    assert_eq!((report.held, report.unwanted), (0, solutions as u64));
    // Modelled, and no client wants it: nothing is either.
    admit_models(&models, &records);
    let unwanted = roomy(&models);
    for site in &sites {
        unwanted.site(site);
    }
    for raw in &raws {
        unwanted.raw(raw, (1, Class::Members), at(0), |_| false);
    }
    assert_eq!(unwanted.report().held, 0);
    let one = records
        .iter()
        .find_map(|record| match record {
            Record::Positions(positions) if positions.is_tagged() => Some(positions),
            _ => None,
        })
        .ok_or("no client forms")?;
    assert_eq!(unwanted.check(one), Verdict::Unknown);
    // Both: every one is.
    let (wanted, _) = fed(&records, &sites);
    assert_eq!(wanted.report().held, solutions as u64);
    assert_eq!(wanted.check(one), Verdict::Passes);
    Ok(())
}

/// A member source past its even share of the members' room is refused and counted, and what
/// another holds is never let go for it: the honest member's twins still check, and it still holds
/// new ones. The relay's own engine's room is its own. A twin goes only when its hold is over.
#[test]
fn a_member_past_its_share_is_refused_counted_and_evicts_nothing() -> Result<(), String> {
    let (records, sites) = published()?;
    let models = Arc::new(Models::new());
    admit_models(&models, &records);
    let raws: Vec<&Positions> = records
        .iter()
        .filter_map(|record| match record {
            Record::Positions(positions) if !positions.is_tagged() => Some(positions),
            _ => None,
        })
        .collect();
    let honest_bytes: usize = raws
        .iter()
        .map(|raw| RECORD_HELD_EXTRA + raw.as_bytes().len())
        .sum();
    // Room for the honest member's records twice over: its share, half, holds them all.
    let caps = Caps {
        sites: 1_024,
        own: RoomCaps::of(1 << 20),
        members: RoomCaps {
            bytes: 2 * honest_bytes,
            twins: 1 << 20,
        },
        sources: 4,
    };
    let checks = Consistency::with_caps(Arc::clone(&models), caps);
    for site in &sites {
        checks.site(site);
    }
    for raw in &raws {
        checks.raw(raw, (1, Class::Members), at(0), |_| true);
    }
    let honest = checks.report().held;
    assert!(honest > 0);
    // Another member floods: held to its share, the rest refused and counted.
    let mut flooded = 0;
    for by in 1..=40u64 {
        for raw in &raws {
            checks.raw(&moved(raw, by * 1_000)?, (2, Class::Members), at(0), |_| {
                true
            });
            flooded += raw.solutions().map_or(0, |content| content.solutions.len()) as u64;
        }
    }
    let report = checks.report();
    assert!(report.over_share > 0, "{report:?}");
    assert_eq!(report.full, 0, "{report:?}");
    assert_eq!(
        report.held + report.over_share,
        honest + flooded,
        "{report:?}"
    );
    {
        let inner = checks.inner();
        let held = inner.sources.get(&2).map_or(0, |held| held.bytes);
        assert!(held <= caps.members.bytes / 2, "{held}");
        assert_eq!(
            inner.sources.get(&1).map(|held| held.bytes),
            Some(honest_bytes)
        );
    }
    // The honest member's client forms still check: nothing of it was let go.
    for record in &records {
        if let Record::Positions(positions) = record
            && positions.is_tagged()
        {
            assert_eq!(checks.check(positions), Verdict::Passes);
        }
    }
    // The relay's own engine is not the members': its room is free whatever they hold.
    let own = moved(raws[0], 900_000)?;
    checks.raw(&own, (0, Class::Own), at(0), |_| true);
    assert!(checks.report().held > report.held);
    // Their hold over, every twin goes, and the room with them.
    checks.raw(
        &moved(raws[0], 950_000)?,
        (1, Class::Members),
        at(TWIN_MS),
        |_| true,
    );
    let inner = checks.inner();
    assert_eq!(inner.own.bytes, 0);
    assert_eq!(inner.sources.get(&2), None);
    assert_eq!(
        inner.members.bytes,
        RECORD_HELD_EXTRA + raws[0].as_bytes().len()
    );
    Ok(())
}
