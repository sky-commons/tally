//! A client's positions are checked here, because a client cannot check them (wire version 3).
//!
//! A client is sent each solution tagged (`tally_wire::TaggedSolution`): its receptions as tags, no
//! counters, and no clock model it could map a counter through. So it cannot tell whether a
//! solution agrees with its own receptions under its own model (`standing::consistent`), and the
//! merge rule needs that: only a consistent solution refuses a superset that disagrees with it, so
//! a lying smaller solution a client took on trust would refuse an honest bigger one.
//!
//! A relay holds what the check needs: the full clock models (relay-only), the raw twin of every
//! tagged solution (an engine publishes both forms, the raw first), and the site-bearing records
//! the tags are made under. So before a tagged record reaches a client link, the relay rematches
//! each of its solutions to the receptions of its raw twin (`publish::rematch`), each receiver's
//! tag keyed by the site-bearing record the model's scope names (by its site id, never the
//! receiver's current record, so a site re-signed mid-window still rematches), and passes the
//! record only when every solution is under its model and consistent with its own receptions
//! (`standing::under`, `standing::consistent`). A record it cannot check (a model, a twin or a
//! site it does not hold) waits with the positions awaiting their models (`Hub::forward_positions`)
//! and is then dropped, counted: a client is never sent what no relay checked.
//!
//! Memory is bounded by count: sites, decoded models and twins each, least recently used
//! forgotten first.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tally_mlat::intake::SiteRecord;
use tally_mlat_solver::ClockModel as Model;
use tally_mlat_solver::Reach;
use tally_mlat_solver::publish;
use tally_mlat_solver::standing::{Claimed, consistent, under};
use tally_wire::batch::Hash;
use tally_wire::clock_model::Assembler;
use tally_wire::{ClockModel, Positions, PublicKey, Reception, ReceptionKey, SiteId, TransmitTime};

use crate::bounded::Bounded;

/// Site-bearing records' reception keys held, by site id.
pub const MAX_SITES: usize = 65_536;
/// Decoded clock models held.
pub const MAX_MODELS: usize = 1_024;
/// Bytes of clock model parts waiting for their manifest.
pub const MAX_MODEL_BYTES: usize = 16 << 20;
/// Raw solutions whose receptions are held for their tagged twins.
pub const MAX_TWINS: usize = 262_144;

/// A raw solution's identity for its tagged twin: its model, aircraft and transmit time.
type TwinKey = (Hash, u32, TransmitTime);

struct HeldModel {
    spec: u16,
    model: Arc<Model>,
}

struct Inner {
    sites: Bounded<SiteId, ReceptionKey>,
    assembler: Assembler,
    models: Bounded<Hash, HeldModel>,
    twins: Bounded<TwinKey, Vec<Reception>>,
}

/// What a tagged record's check says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every solution rematched and consistent: a client may be sent it.
    Passes,
    /// A solution rematched and is not under its model or not consistent with its receptions: it
    /// is never sent.
    Fails,
    /// Something the check needs is not held (yet).
    Unknown,
}

/// The checks of client positions (module docs).
pub struct Consistency {
    inner: Mutex<Inner>,
    refused: AtomicU64,
}

impl Default for Consistency {
    fn default() -> Self {
        Self::new()
    }
}

impl Consistency {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                sites: Bounded::new(MAX_SITES),
                assembler: Assembler::new(MAX_MODEL_BYTES, MAX_MODELS),
                models: Bounded::new(MAX_MODELS),
                twins: Bounded::new(MAX_TWINS),
            }),
            refused: AtomicU64::new(0),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Tagged records never sent to a client: they failed, or could not be checked in time.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Counts a tagged record not sent (`refused`).
    pub fn refuse(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    /// A site-bearing record the relay took: its key, by its id, for the models that name it.
    pub fn site(&self, record: &SiteRecord) {
        self.inner()
            .sites
            .insert_active(record.site_id(), record.reception_key());
    }

    /// A clock model manifest or part the relay forwarded: decoded once whole, held when it is a
    /// function of what it says.
    pub fn model(&self, record: &tally_wire::Record) {
        let mut inner = self.inner();
        let done = match record {
            tally_wire::Record::ClockModel(manifest) => {
                inner.assembler.manifest(manifest.clone()).ok().flatten()
            }
            tally_wire::Record::ClockModelPart(part) => inner.assembler.part(part.clone()),
            _ => None,
        };
        if let Some((manifest, content)) = done {
            hold(&mut inner, &manifest, &content);
        }
    }

    /// A raw positions record the relay forwarded: each solution's receptions, for its twin.
    pub fn raw(&self, positions: &Positions) {
        if positions.is_tagged() {
            return;
        }
        let Ok(content) = positions.solutions() else {
            return;
        };
        let mut inner = self.inner();
        for solution in content.solutions {
            inner.twins.insert_active(
                (solution.clock_model, solution.address, solution.transmitted),
                solution.observations.receptions().to_vec(),
            );
        }
    }

    /// Whether a client may be sent `positions` (module docs). A raw record is never a client's:
    /// it fails.
    pub fn check(&self, positions: &Positions) -> Verdict {
        if !positions.is_tagged() {
            return Verdict::Fails;
        }
        let Ok(content) = positions.tagged_solutions() else {
            return Verdict::Fails;
        };
        let reach = if positions.is_provisional() {
            Reach::Carried
        } else {
            Reach::Window
        };
        let inner = self.inner();
        let mut verdict = Verdict::Passes;
        for tagged in &content.solutions {
            let Some(held) = inner.models.get(&tagged.clock_model) else {
                verdict = Verdict::Unknown;
                continue;
            };
            if held.spec != content.spec_version {
                return Verdict::Fails;
            }
            let model = Arc::clone(&held.model);
            let Some(receptions) = inner
                .twins
                .get(&(tagged.clock_model, tagged.address, tagged.transmitted))
                .cloned()
            else {
                verdict = Verdict::Unknown;
                continue;
            };
            // Each receiver's key is the record its model's scope names, by site id.
            let key_of = |receiver: &PublicKey| -> Option<ReceptionKey> {
                let site = model.scope.iter().find(|site| site.receiver == *receiver)?;
                inner.sites.get(&site.id).copied()
            };
            let Some(raw) = publish::rematch(tagged, receptions, key_of) else {
                verdict = Verdict::Unknown;
                continue;
            };
            if !under(&model, &raw, content.spec_version)
                || !consistent(&model, reach, &raw.observations, &Claimed::of(&raw))
            {
                return Verdict::Fails;
            }
        }
        verdict
    }
}

/// Holds a whole model, decoded, when it is the function of the inputs it names.
fn hold(inner: &mut Inner, manifest: &ClockModel, content: &tally_wire::ClockModelContent) {
    let Ok(decoded) = publish::decode(&content.model, content.spec_version) else {
        return;
    };
    if publish::inputs_id(&decoded) != content.inputs {
        return;
    }
    inner.models.insert_active(
        manifest.id(),
        HeldModel {
            spec: content.spec_version,
            model: Arc::new(decoded),
        },
    );
}

#[cfg(test)]
mod tests;
