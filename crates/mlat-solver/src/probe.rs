//! RFC-0198 slice 1's refit probe (#40): built only with `--cfg tally_refit_probe` (Bazel
//! `--config=refit-probe`), never in a release. It times each phase of a refit, classifies each
//! block rebuilt, and times what slice 3's ceiling would pay in its place (the oracle): reads of
//! only the seconds whose read span changed, point formation and exact-key runs of only those
//! seconds, pooling by a merge of runs then an insertion pass in version 8's order (checked against
//! the sort on a sample of builds), and a cold shadow refit of one area-edge in 64 (checked against
//! the warm one). Counters accumulate process-wide; when `TALLY_REFIT_PROBE` names a file they are
//! written there as JSON at most once a second, with the host's last memory breakdown.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        /// One counter: a phase's nanoseconds, or a count.
        #[derive(Clone, Copy, Debug)]
        #[allow(non_camel_case_types, reason = "named as the JSON it writes")]
        pub enum P { $($name),* }
        const NAMES: &[&str] = &[$(stringify!($name)),*];
    };
}

counters!(
    // Baseline phases, nanoseconds.
    gather_ns,
    reader_ns,
    clocks_ns,
    digests_ns,
    formation_ns,
    copy_ns,
    sort_ns,
    line_ns,
    residuals_ns,
    mad_ns,
    steps_ns,
    sums_ns,
    blocks_gather_ns,
    settle_ns,
    passes_ns,
    // The oracle's own work, nanoseconds.
    oracle_formation_ns,
    oracle_runsort_ns,
    oracle_merge_ns,
    shadow_ns,
    // Counts.
    refits,
    receptions_read,
    receptions_reread,
    seconds_read,
    seconds_reread,
    builds_first,
    builds_read_after,
    builds_late,
    blocks_reused,
    pair_blocks_rebuilt,
    pair_blocks_unchanged,
    order_checks,
    order_mismatches,
    shadow_runs,
    shadow_mismatches,
    shadow_failed,
);

static COUNTS: [AtomicU64; NAMES.len()] = [const { AtomicU64::new(0) }; NAMES.len()];

thread_local! {
    /// Set while this thread runs a shadow refit: its phases are the shadow's, not the baseline's.
    static SHADOWING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// This thread's nanoseconds in block builds (their phases and the oracle's pooling): what a
    /// timer around settling, which rebuilds cut blocks, takes out of its own.
    static NESTED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// This thread's nanoseconds in block builds so far (`NESTED`).
pub fn nested() -> u64 {
    NESTED.with(std::cell::Cell::get)
}

/// Runs `work` as a shadow refit: no baseline or oracle counter moves while it runs.
pub fn shadowing<T>(work: impl FnOnce() -> T) -> T {
    SHADOWING.with(|flag| flag.set(true));
    let out = work();
    SHADOWING.with(|flag| flag.set(false));
    out
}
static MEMORY: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());
static LAST: Mutex<Option<Instant>> = Mutex::new(None);

/// Adds `value` to `counter`.
pub fn add(counter: P, value: u64) {
    if SHADOWING.with(std::cell::Cell::get) {
        return;
    }
    if matches!(
        counter,
        P::formation_ns
            | P::copy_ns
            | P::sort_ns
            | P::line_ns
            | P::residuals_ns
            | P::mad_ns
            | P::steps_ns
            | P::sums_ns
            | P::oracle_runsort_ns
            | P::oracle_merge_ns
    ) {
        NESTED.with(|nested| nested.set(nested.get().saturating_add(value)));
    }
    COUNTS[counter as usize].fetch_add(value, Relaxed);
}

/// Adds the nanoseconds since `started` to `counter`, and returns them.
pub fn since(counter: P, started: Instant) -> u64 {
    let ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    add(counter, ns);
    ns
}

/// Adds to a shadow counter, which moves while shadowing too.
pub fn add_shadow(counter: P, value: u64) {
    COUNTS[counter as usize].fetch_add(value, Relaxed);
}

/// The present value of `counter`.
pub fn get(counter: P) -> u64 {
    COUNTS[counter as usize].load(Relaxed)
}

/// Every counter, by name.
pub fn snapshot() -> Vec<(&'static str, u64)> {
    NAMES
        .iter()
        .zip(&COUNTS)
        .map(|(name, count)| (*name, count.load(Relaxed)))
        .collect()
}

/// The host's memory breakdown, written with the counters.
pub fn set_memory(parts: Vec<(String, u64)>) {
    if let Ok(mut held) = MEMORY.lock() {
        *held = parts;
    }
}

/// Whether the area-edge `(area, edge_ms)` is one the shadow refits cold: one in 64, by a hash of
/// both, so every relay and run picks the same.
pub fn shadow_due(area: u64, edge_ms: u64) -> bool {
    let mut z = area ^ edge_ms.rotate_left(32) ^ 0x9e37_79b9_7f4a_7c15;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (z ^ (z >> 31)).is_multiple_of(64)
}

/// Writes the counters to `TALLY_REFIT_PROBE` if a second has passed since the last write.
pub fn dump_if_due() {
    let Ok(path) = std::env::var("TALLY_REFIT_PROBE") else {
        return;
    };
    {
        let Ok(mut last) = LAST.lock() else { return };
        if last.is_some_and(|at| at.elapsed().as_millis() < 1000) {
            return;
        }
        *last = Some(Instant::now());
    }
    let mut out = String::from("{");
    for (name, value) in snapshot() {
        out.push_str(&format!("\"{name}\":{value},"));
    }
    out.push_str("\"memory\":{");
    if let Ok(memory) = MEMORY.lock() {
        let parts: Vec<String> = memory
            .iter()
            .map(|(name, bytes)| format!("\"{name}\":{bytes}"))
            .collect();
        out.push_str(&parts.join(","));
    }
    out.push_str("}}");
    let temporary = format!("{path}.tmp");
    if std::fs::write(&temporary, out).is_ok() {
        let _ = std::fs::rename(&temporary, &path);
    }
}
