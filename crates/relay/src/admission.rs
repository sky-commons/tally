//! Capacity (RFC-0174 §2.2, RFC-0171 §3.6): what this relay declares spare, signed in every
//! `EchoReply` and `ProviderOffer`, and the network it says it is on. A feeder ranks relays by the
//! spare feeder capacity they declare, so what is declared must be what the relay then does: the
//! slots declared and the feeder taken are decided by one rule (`egress`'s), and with relay duties
//! off the relay declares none and takes none. A relay that declares more is caught by its
//! redirects and failed delivery checks (§4.3); this file is where it is kept honest.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tally_wire::{Echo, EchoReply, EchoReplyContent, Headroom, Identity};

use crate::egress::{Admitted, Egress};
use crate::hub::Hub;

pub struct Admission {
    network: AtomicU32,
    duties: AtomicBool,
}

impl Default for Admission {
    fn default() -> Self {
        Self::new()
    }
}

impl Admission {
    pub fn new() -> Self {
        Self {
            network: AtomicU32::new(0),
            duties: AtomicBool::new(true),
        }
    }

    /// The operator's: the network declared, and whether relay duties (feeders, MLAT, seeding)
    /// are on.
    pub fn configure(&self, network: u32, duties: bool) {
        self.network.store(network, Ordering::Relaxed);
        self.duties.store(duties, Ordering::Relaxed);
    }

    /// Whether relay duties are on: off, the relay takes no feeders (RFC-0174 §2.1).
    pub fn duties(&self) -> bool {
        self.duties.load(Ordering::Relaxed)
    }

    /// What the relay has spare now: the feeders it would still take ([`Admission::admit`]'s
    /// rule), the cap less what it is committed to send, and the MLAT cores it offers. With relay
    /// duties off, no feeder slots and no cores: it takes neither feeders nor MLAT.
    pub fn headroom(&self, hub: &Hub) -> Headroom {
        let duties = self.duties();
        let pace_headroom_bytes_per_sec = hub.egress().report().headroom_bytes_per_sec;
        let mlat_cores = if duties {
            hub.network().mlat().map_or(0, |mlat| mlat.cores())
        } else {
            0
        };
        Headroom {
            feeder_slots: if duties {
                feeder_slots(hub.egress())
            } else {
                0
            },
            pace_headroom_bytes_per_sec,
            mlat_cores,
        }
    }

    /// Takes a feeder, or not: with duties off never, else exactly while the upload cap can carry
    /// what it commits the relay to forward (`Egress::admit_feeder`). `None` is turned away, before
    /// anything it sent is taken in.
    pub fn admit(&self, hub: &Hub) -> Option<Admitted> {
        if !self.duties() {
            return None;
        }
        hub.egress().admit_feeder()
    }

    /// The autonomous system the relay is on, as its operator configured it (0: not said).
    pub fn network(&self) -> u32 {
        self.network.load(Ordering::Relaxed)
    }

    /// The signed answer to a probe: at once, before anything else the link does.
    pub fn echo(
        &self,
        hub: &Hub,
        identity: Option<&Identity>,
        echo: Echo,
        now_ms: u64,
    ) -> Option<EchoReply> {
        let content = EchoReplyContent {
            nonce: echo.nonce,
            issued_ms: now_ms,
            network: self.network(),
            headroom: self.headroom(hub),
        };
        EchoReply::sign(identity?, &content).ok()
    }
}

/// The feeders `egress` would take now, one after another, by the rule `Egress::admit_feeder`
/// applies (`Egress::feeder_slots`), never a copy of its arithmetic.
fn feeder_slots(egress: &Arc<Egress>) -> u32 {
    egress.feeder_slots()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::Cap;

    #[test]
    fn with_duties_off_nothing_is_declared_and_no_feeder_is_taken() -> Result<(), String> {
        let hub =
            Hub::new(8, crate::sharing::Deadlines::RELAY).max_upload(Cap::bytes_per_sec(1_000_000));
        let admission = &hub.network().admission;
        admission.configure(64_512, false);
        let identity = Identity::generate().map_err(|error| error.to_string())?;
        let reply = admission
            .echo(&hub, Some(&identity), Echo { nonce: 3 }, 9)
            .ok_or("no reply")?;
        reply.verify().map_err(|error| error.to_string())?;
        let content = reply.content().map_err(|error| error.to_string())?;
        assert_eq!(content.nonce, 3);
        assert_eq!(content.network, 64_512);
        assert_eq!(content.headroom.feeder_slots, 0);
        assert_eq!(content.headroom.mlat_cores, 0);
        assert!(admission.admit(&hub).is_none(), "declared none, takes none");
        // Duties on: the egress decides, and with nothing committed it takes the feeder.
        admission.configure(64_512, true);
        assert!(admission.admit(&hub).is_some());
        Ok(())
    }
}
