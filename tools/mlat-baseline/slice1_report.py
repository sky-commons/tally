"""RFC-0198 slice 1 (#40): one relay run's go ratio. From the probe's counters at the two ends of
the measured window: the baseline refit (gather, reads, builds, settling, passes) and the oracle's
(slice 3's ceiling: the reads of only the seconds whose read span changed, formation of only those,
exact-key runs merged then put in version 8's order, the rest as now, and the cold shadow at one
area-edge in 64), each in ms a seat-second, and their ratio; with the run's acceptance figures.
usage: slice1_report.py SAMPLE_JSON (sample_probe.py's), or a PROBE line's counters as JSON."""
import json, sys

d = json.load(open(sys.argv[1]))
if "a" in d:
    a, b = d["a"]["probe"], d["b"]["probe"]
    delta = {k: b[k] - a[k] for k in b if isinstance(b[k], int)}
    seats = sum(d["seats"]) / max(1, len(d["seats"]))
    window = d["b"]["at"] - d["a"]["at"]
    ma, mb = d["a"]["mlat"], d["b"]["mlat"]
    accept = {
        "arrived_over": mb["arrived_over"] - ma["arrived_over"],
        "unfitted": mb["steps_total"]["unfitted"] - ma["steps_total"]["unfitted"],
        "steps_collapsed": mb["steps_collapsed"] - ma["steps_collapsed"],
        "fits": mb["steps_total"]["fits"] - ma["steps_total"]["fits"],
        "fit_ms_steps": mb["steps_total"]["fit_ms"] - ma["steps_total"]["fit_ms"],
        "relay_cores": (d["b"]["relay_ticks"] - d["a"]["relay_ticks"]) / d["ticks_per_sec"] / window,
        "busy_cores_all": (d["b"]["busy"] - d["a"]["busy"]) / d["ticks_per_sec"] / window,
        "harness_cores": (d["b"].get("harness_ticks", 0) - d["a"].get("harness_ticks", 0)) / d["ticks_per_sec"] / window,
        "load_b": d["b"]["load"],
        "seats_mean": seats, "seats_min": min(d["seats"] or [0]), "load_a": d["a"]["load"],
        "memory": d["b"]["probe"].get("memory"),
    }
else:
    delta, seats, window, accept = d, None, None, {}

reads = ["gather_ns", "reader_ns", "clocks_ns", "digests_ns"]
builds = ["formation_ns", "copy_ns", "sort_ns", "line_ns", "residuals_ns", "mad_ns", "steps_ns", "sums_ns"]
rest = ["blocks_gather_ns", "settle_ns", "passes_ns"]
kept = ["line_ns", "residuals_ns", "mad_ns", "steps_ns", "sums_ns"]
f = delta["receptions_reread"] / max(1, delta["receptions_read"])
base = sum(delta[k] for k in reads + builds + rest)
oracle_parts = {
    "reads": sum(delta[k] for k in reads) * f,
    "formation": delta["oracle_formation_ns"],
    "runs_and_merge": delta["oracle_runsort_ns"] + delta["oracle_merge_ns"],
    "kept_build_phases": sum(delta[k] for k in kept),
    "rest": sum(delta[k] for k in rest),
    "shadow_cold": delta["shadow_ns"],
}
oracle = sum(oracle_parts.values())
out = {
    "refits": delta["refits"],
    "reread_fraction": round(f, 4),
    "baseline_ms_a_refit": round(base / 1e6 / max(1, delta["refits"]), 3),
    "oracle_ms_a_refit": round(oracle / 1e6 / max(1, delta["refits"]), 3),
    "ratio": round(oracle / max(1, base), 4),
    "ratio_without_shadow": round((oracle - delta["shadow_ns"]) / max(1, base), 4),
    "shadow_cold_over_warm": round(delta["shadow_ns"] / max(1, delta["shadow_runs"]) / (base / max(1, delta["refits"])), 3) if delta["shadow_runs"] else None,
    "phases_ms_a_refit": {k: round(delta[k] / 1e6 / max(1, delta["refits"]), 3) for k in reads + builds + rest},
    "oracle_ms_a_refit_by_part": {k: round(v / 1e6 / max(1, delta["refits"]), 3) for k, v in oracle_parts.items()},
    "rebuilds": {k: delta[k] for k in ("builds_first", "builds_read_after", "builds_late", "blocks_reused", "pair_blocks_rebuilt", "pair_blocks_unchanged")},
    "checks": {k: delta[k] for k in ("order_checks", "order_mismatches", "shadow_runs", "shadow_mismatches", "shadow_failed")},
}
if seats:
    out["baseline_ms_a_seat_second"] = round(base / 1e6 / window / seats, 3)
    out["oracle_ms_a_seat_second"] = round(oracle / 1e6 / window / seats, 3)
if accept:
    accept["other_users_cores"] = round(accept["busy_cores_all"] - accept["relay_cores"] - accept["harness_cores"], 2)
out["accept"] = accept
print(json.dumps(out, indent=1))
