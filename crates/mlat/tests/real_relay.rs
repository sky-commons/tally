//! The engine against a real relay (`tally_relay::serve`): a receiver publishes its description
//! and batches to the relay as a feeder, the engine subscribes to the relay's raw stream and
//! bridges to `support`'s stand-in mlat-server, and a plain subscriber to the relay's positions
//! stream receives what the engine solved, signed by the engine's own key.

mod support;

use std::sync::Arc;
use std::time::Duration;

use tally_relay::hub::Hub;
use tally_wire::noise;
use tally_wire::{Identity, Positions, Record, Region, RelayAddress, Role, Streams};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use support::{Result, WAIT, batch, location, receiver_info, text};

#[tokio::test]
async fn positions_the_engine_solves_reach_a_real_relays_positions_subscribers() -> Result {
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

    // The receiver, publishing as a feeder: its description, then a batch every quarter second.
    let receiver = Identity::generate().map_err(text)?;
    let stream = TcpStream::connect(relay_address).await.map_err(text)?;
    let mut feeder = noise::connect(stream, &receiver, &relay_key, Role::Feeder)
        .await
        .map_err(text)?;
    feeder
        .writer
        .send(&[Record::ReceiverInfo(receiver_info(&receiver)?)])
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

    let region = Region::containing(&location(), 3).map_err(text)?;
    let (server, mut heard) = support::start_server().await?;
    let (engine, dir) = support::start_engine(
        RelayAddress {
            key: relay_key,
            address: relay_address.to_string(),
        },
        server,
        region,
    )?;

    let heard = timeout(WAIT, heard.recv())
        .await
        .map_err(|_| "the server heard no sync and mlat message".to_owned())?
        .ok_or_else(|| "the server task ended".to_owned())??;
    support::check_heard(&heard, &receiver)?;

    let signed: Positions = timeout(WAIT, async {
        loop {
            let mut got = Vec::new();
            subscriber.reader.recv(&mut got).await.map_err(text)?;
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
    .map_err(|_| "no positions reached the relay's subscriber".to_owned())??;
    support::check_positions(&signed, engine)?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}
