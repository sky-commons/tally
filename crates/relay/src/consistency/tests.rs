//! A client's positions pass only when the relay rematched and checked every solution, by the
//! records its model names, and a lie in one never passes.

use super::*;
use tally_mlat::engine::{Capacity, Engine, Settings};
use tally_mlat::replay::{arrivals, replay, scenario};
use tally_mlat_solver::sim;
use tally_wire::{Identity, ReceiverSite, ReceiverSiteContent, Record};

/// What a reference engine publishes over a short simulation, and the site records it placed its
/// receivers by.
fn published() -> Result<(Vec<Record>, Vec<SiteRecord>), String> {
    let mut simulation = sim::run(&scenario(23, 40.0));
    let delivered = arrivals(&mut simulation, 5)?;
    let sites: Vec<SiteRecord> = delivered
        .iter()
        .filter_map(|(_, record)| SiteRecord::of(record))
        .collect();
    let until = delivered.last().map_or(0, |(at, _)| *at) + 60_000;
    let mut engine = Engine::new(
        Identity::from_seed([4; 32]),
        0xb007,
        Settings {
            regions: tally_wire::Regions::default(),
            settle_ms: 1_000,
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

/// Everything but the client forms handed in, as a relay forwarding them would: sites, models,
/// raw positions. The client forms, in order.
fn fed(records: &[Record], sites: &[SiteRecord]) -> (Consistency, Vec<Positions>) {
    let checks = Consistency::new();
    for site in sites {
        checks.site(site);
    }
    let mut tagged = Vec::new();
    for record in records {
        match record {
            Record::ClockModel(_) | Record::ClockModelPart(_) => checks.model(record),
            Record::Positions(positions) | Record::Provisional(positions) => {
                if positions.is_tagged() {
                    tagged.push(positions.clone());
                } else {
                    checks.raw(positions);
                }
            }
            _ => {}
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
    assert_eq!(Consistency::new().check(one), Verdict::Unknown);
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
    let receptions = checks
        .inner()
        .twins
        .get(&(solution.clock_model, solution.address, solution.transmitted))
        .cloned()
        .ok_or("no twin")?;
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
    let hub = Hub::new(8, crate::sharing::Deadlines::RELAY);
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
    assert_eq!(to_client, honest);
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
