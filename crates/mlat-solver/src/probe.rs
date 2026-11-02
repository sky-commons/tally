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
    // The per-pair oracle (RFC-0198 slice 1's follow-up): a block rebuilt only when its pair's
    // pooled points changed. Its digest's cost, its builds' cost (each build alone, its formation
    // and the slice 1 oracle's pooling taken out), the cut blocks settling rebuilds, and counts.
    perpair_digest_ns,
    perpair_build_ns,
    cut_build_ns,
    perpair_rebuilt,
    perpair_reused,
    perpair_digest_misses,
    perpair_digest_false,
    // Why a second is read again (RFC-0198 slice 1's second follow-up): each changed second's
    // class, each re-read second's cause (its own class, else its nearest changed neighbour's),
    // by seconds and by receptions; the receptions added, removed and moved; how late an added
    // one is behind the last update's end; and whether a re-read second's formed points changed.
    chg_new,
    chg_dropped,
    chg_moved,
    chg_late_sync,
    chg_late_status,
    chg_removed_sync,
    chg_removed_status,
    chg_both,
    chg_wall,
    rr_sec_new,
    rr_sec_dropped,
    rr_sec_moved,
    rr_sec_late_sync,
    rr_sec_late_status,
    rr_sec_removed_sync,
    rr_sec_removed_status,
    rr_sec_both,
    rr_sec_wall,
    rr_rx_new,
    rr_rx_dropped,
    rr_rx_moved,
    rr_rx_late_sync,
    rr_rx_late_status,
    rr_rx_removed_sync,
    rr_rx_removed_status,
    rr_rx_both,
    rr_rx_wall,
    rx_added_sync,
    rx_added_status,
    rx_removed_sync,
    rx_removed_status,
    // Of the sync receptions added and removed, those whose message one receiver alone heard.
    rx_added_sync_solo,
    rx_removed_sync_solo,
    rx_moved,
    late_receivers,
    late_seconds,
    late_age_0_2,
    late_age_2_4,
    late_age_4_8,
    late_age_8_16,
    late_age_16_20,
    late_age_20_up,
    removed_age_0_2,
    removed_age_2_4,
    removed_age_4_8,
    removed_age_8_16,
    removed_age_16_20,
    removed_age_20_up,
    rr_formed_seconds,
    rr_formed_identical,
    rr_formed_rx,
    rr_formed_identical_rx,
    oracle_formation_changed_ns,
    // A digest over each second's sync receptions alone (status left out): its re-read set, what
    // forming that set costs, and how often a second it skips had its formed points change.
    receptions_reread_sync,
    oracle_formation_sync_ns,
    status_only_formed,
    status_only_points_changed,
    rx_reread_changed,
);

static COUNTS: [AtomicU64; NAMES.len()] = [const { AtomicU64::new(0) }; NAMES.len()];

thread_local! {
    /// Set while this thread runs a shadow refit: its phases are the shadow's, not the baseline's.
    static SHADOWING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// This thread's nanoseconds in block builds (their phases and the oracle's pooling): what a
    /// timer around settling, which rebuilds cut blocks, takes out of its own.
    static NESTED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// This thread's own share of every counter, for a timer that takes nested work out.
    static LOCAL: [std::cell::Cell<u64>; NAMES.len()] =
        const { [const { std::cell::Cell::new(0) }; NAMES.len()] };
}

/// This thread's own total of `counter` so far.
pub fn local(counter: P) -> u64 {
    LOCAL.with(|local| local[counter as usize].get())
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
    LOCAL.with(|local| {
        let cell = &local[counter as usize];
        cell.set(cell.get().saturating_add(value));
    });
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
