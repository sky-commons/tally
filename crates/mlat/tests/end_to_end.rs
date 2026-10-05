//! The engine end to end over real sockets against a stand-in relay: it serves one receiver's
//! signed batches to an `Engine` subscriber, checks the subscription that came with its Hello, and takes the engine's
//! positions back. The stand-in mlat-server is `support`'s.

mod support;

use std::time::Duration;

use tally_wire::noise;
use tally_wire::{Identity, Record, Region, RelayAddress, Role, Streams};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;

use support::{Result, WAIT, batch, location, receiver_info, text};

/// The stand-in relay: checks the engine's subscription, then serves the receiver's description
/// and a batch every quarter second, and hands back the first `Positions` the engine publishes.
async fn relay(
    listener: TcpListener,
    identity: Identity,
    region: Region,
    receiver: Identity,
    positions: oneshot::Sender<Result<tally_wire::Positions>>,
) {
    let outcome = async {
        let (stream, _) = listener.accept().await.map_err(text)?;
        let accepted = noise::accept(stream, &[identity]).await.map_err(text)?;
        if accepted.role != Role::Engine {
            return Err(format!("connected as {:?}", accepted.role));
        }
        // The subscription comes in the same message as the engine's Hello.
        let mut session = accepted.session;
        match accepted.first.first() {
            Some(Record::Subscribe { streams, regions })
                if *streams == Streams::RAW && *regions == vec![region] => {}
            other => return Err(format!("expected the engine's subscription, got {other:?}")),
        }
        let info = receiver_info(&receiver)?;
        let mut writer = session.writer;
        writer
            .send(&[Record::ReceiverInfo(info)])
            .await
            .map_err(text)?;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            for k in 0.. {
                tick.tick().await;
                let Ok(batch) = batch(&receiver, k) else {
                    return;
                };
                if writer.send(&[Record::Batch(batch)]).await.is_err() {
                    return;
                }
            }
        });
        loop {
            let mut got = Vec::new();
            session.reader.recv(&mut got).await.map_err(text)?;
            for record in got {
                if let Record::Positions(signed) = record {
                    return Ok(signed);
                }
            }
        }
    }
    .await;
    let _ = positions.send(outcome);
}

#[tokio::test]
async fn a_receivers_messages_reach_mlat_server_as_mlat_client_sends_them_and_results_come_back_signed()
-> Result {
    let receiver = Identity::generate().map_err(text)?;
    let relay_identity = Identity::generate().map_err(text)?;
    let region = Region::containing(&location(), 3).map_err(text)?;
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.map_err(text)?;
    let relay_address = relay_listener.local_addr().map_err(text)?;
    let (positions_out, positions) = oneshot::channel();
    tokio::spawn(relay(
        relay_listener,
        relay_identity.clone(),
        region,
        receiver.clone(),
        positions_out,
    ));
    let (server, mut heard) = support::start_server().await?;
    let (engine, dir, _running) = support::start_engine(
        RelayAddress {
            key: relay_identity.public(),
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
    let signed = timeout(WAIT, positions)
        .await
        .map_err(|_| "no positions reached the relay".to_owned())?
        .map_err(text)??;
    support::check_positions(&signed, engine)?;
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}
