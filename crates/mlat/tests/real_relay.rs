//! The engine against a real relay (`tally_relay::serve`): a receiver publishes its description
//! and batches to the relay as a feeder, the engine subscribes to the relay's raw stream and
//! bridges to `support`'s stand-in mlat-server, and a plain subscriber to the relay's positions
//! stream receives what the engine solved, signed by the engine's own key; and an engine started
//! again with the same key is a new boot whose positions the relay forwards too.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tally_relay::hub::Hub;
use tally_wire::noise;
use tally_wire::{
    Identity, Positions, PublicKey, Reader, Record, Region, RelayAddress, Role, Streams,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use support::{Result, WAIT, batch, location, receiver_info, text};

type Subscriber = Reader<TcpStream>;

/// A real relay with a positions subscriber and a receiver publishing to it as a feeder: the
/// relay's address and key, and the subscriber's reading half.
async fn relay_with_feeder(receiver: &Identity) -> Result<(RelayAddress, Subscriber)> {
    let relay_identity = Identity::generate().map_err(text)?;
    let relay_key = relay_identity.public();
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let relay_address = listener.local_addr().map_err(text)?;
    tokio::spawn(tally_relay::serve(
        listener,
        vec![relay_identity],
        Arc::new(Hub::new(8)),
    ));

    // A plain subscriber that wants only positions.
    let stream = TcpStream::connect(relay_address).await.map_err(text)?;
    let mut subscriber = noise::connect(
        stream,
        &Identity::generate().map_err(text)?,
        &relay_key,
        Role::Subscriber,
    )
    .await
    .map_err(text)?;
    subscriber
        .writer
        .send(&[Record::Subscribe {
            streams: Streams::POSITIONS,
            regions: Vec::new(),
        }])
        .await
        .map_err(text)?;
    // The writing half stays open for as long as the subscriber reads.
    tokio::spawn(async move {
        let writer = subscriber.writer;
        std::future::pending::<()>().await;
        drop(writer);
    });

    // The receiver, publishing as a feeder: its description, then a batch every quarter second.
    let stream = TcpStream::connect(relay_address).await.map_err(text)?;
    let mut feeder = noise::connect(stream, receiver, &relay_key, Role::Feeder)
        .await
        .map_err(text)?;
    feeder
        .writer
        .send(&[Record::ReceiverInfo(receiver_info(receiver)?)])
        .await
        .map_err(text)?;
    tokio::spawn({
        let receiver = receiver.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            for k in 0.. {
                tick.tick().await;
                let Ok(batch) = batch(&receiver, k) else {
                    return;
                };
                if feeder.writer.send(&[Record::Batch(batch)]).await.is_err() {
                    return;
                }
            }
        }
    });
    Ok((
        RelayAddress {
            key: relay_key,
            address: relay_address.to_string(),
        },
        subscriber.reader,
    ))
}

/// The next positions the subscriber receives.
async fn next_positions(subscriber: &mut Subscriber) -> Result<Positions> {
    timeout(WAIT, async {
        loop {
            let mut got = Vec::new();
            subscriber.recv(&mut got).await.map_err(text)?;
            for record in got {
                match record {
                    Record::Positions(signed) => return Ok::<_, String>(signed),
                    Record::Batch(_) | Record::ReceiverInfo(_) => {
                        return Err("a positions-only subscriber got raw records".to_owned());
                    }
                    _ => {}
                }
            }
        }
    })
    .await
    .map_err(|_| "no positions reached the relay's subscriber".to_owned())?
}

/// Starts the stand-in mlat-server, waits until it heard the receiver, and checks what it heard.
async fn solve_with(
    start: impl FnOnce(std::net::SocketAddr) -> Result<(PublicKey, support::Running)>,
    receiver: &Identity,
) -> Result<(PublicKey, support::Running)> {
    let (server, mut heard) = support::start_server().await?;
    let started = start(server)?;
    let heard = timeout(WAIT, heard.recv())
        .await
        .map_err(|_| "the server heard no sync and mlat message".to_owned())?
        .ok_or_else(|| "the server task ended".to_owned())??;
    support::check_heard(&heard, receiver)?;
    Ok(started)
}

#[tokio::test]
async fn positions_the_engine_solves_reach_a_real_relays_positions_subscribers() -> Result {
    let receiver = Identity::generate().map_err(text)?;
    let (relay, mut subscriber) = relay_with_feeder(&receiver).await?;
    let region = Region::containing(&location(), 3).map_err(text)?;
    let mut dir = None;
    let (engine, _running) = solve_with(
        |server| {
            let (engine, made, running) = support::start_engine(relay, server, region)?;
            dir = Some(made);
            Ok((engine, running))
        },
        &receiver,
    )
    .await?;
    let signed = next_positions(&mut subscriber).await?;
    support::check_positions(&signed, engine)?;
    if let Some(dir) = dir {
        let _ = std::fs::remove_dir_all(dir);
    }
    Ok(())
}

#[tokio::test]
async fn an_engine_restarted_with_the_same_key_is_a_new_boot_the_relay_forwards() -> Result {
    let receiver = Identity::generate().map_err(text)?;
    let (relay, mut subscriber) = relay_with_feeder(&receiver).await?;
    let region = Region::containing(&location(), 3).map_err(text)?;
    let mut dir = None;
    let (engine, running) = solve_with(
        |server| {
            let (engine, made, running) = support::start_engine(relay.clone(), server, region)?;
            dir = Some(made);
            Ok((engine, running))
        },
        &receiver,
    )
    .await?;
    let dir = dir.ok_or_else(|| "no key directory".to_owned())?;
    let first = next_positions(&mut subscriber).await?;
    support::check_positions(&first, engine)?;

    // The process ends, and starts again from the same key file: its sequence starts at 0 again.
    running.abort();
    let _ = running.await;
    let (again, _running) = solve_with(
        |server| support::start_engine_in(&dir, relay, server, region),
        &receiver,
    )
    .await?;
    assert_eq!(again, engine);
    let second = next_positions(&mut subscriber).await?;
    support::check_positions(&second, engine)?;
    assert_ne!(second.boot_id(), first.boot_id());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}
