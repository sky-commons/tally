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
        "seats_mean": seats, "other_relays_max": d.get("other_relays_max"), "seats_min": min(d["seats"] or [0]), "load_a": d["a"]["load"],
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
# The per-pair oracle (slice 1's follow-up): the same reads and formation, each pair's digest, the
# builds of only the pairs whose digest changed, the cut blocks settling rebuilds, the rest, and the
# cold shadow. Present only in a probe built with it.
perpair_parts = None
if "perpair_build_ns" in delta:
    perpair_parts = {
        "reads": oracle_parts["reads"],
        "formation": delta["oracle_formation_ns"],
        "digest": delta["perpair_digest_ns"],
        "changed_builds": delta["perpair_build_ns"],
        "cut_builds": delta["cut_build_ns"],
        "rest": oracle_parts["rest"],
        "shadow_cold": delta["shadow_ns"],
    }
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
if perpair_parts is not None:
    perpair = sum(perpair_parts.values())
    out["perpair"] = {
        "ratio": round(perpair / max(1, base), 4),
        "ratio_without_shadow": round((perpair - delta["shadow_ns"]) / max(1, base), 4),
        "ms_a_refit": round(perpair / 1e6 / max(1, delta["refits"]), 3),
        "ms_a_refit_by_part": {k: round(v / 1e6 / max(1, delta["refits"]), 3) for k, v in perpair_parts.items()},
        "pair_blocks": {k: delta[k] for k in ("perpair_rebuilt", "perpair_reused", "perpair_digest_misses", "perpair_digest_false")},
    }
    if seats:
        out["perpair"]["ms_a_seat_second"] = round(perpair / 1e6 / window / seats, 3)
if "rr_sec_new" in delta:
    causes = ["new", "dropped", "moved", "late_sync", "late_status", "removed_sync", "removed_status", "both", "wall"]
    sec_total = sum(delta[f"rr_sec_{c}"] for c in causes)
    rx_total = sum(delta[f"rr_rx_{c}"] for c in causes)
    f_changed = delta["rx_reread_changed"] / max(1, delta["receptions_read"])
    formed_parts = None
    if perpair_parts is not None:
        # The ceiling of reading and forming only the re-read seconds whose formed points changed
        # (an oracle: which those are is known only once they are formed), with per-pair builds.
        formed_parts = dict(perpair_parts)
        formed_parts["reads"] = sum(delta[k] for k in reads) * f_changed
        formed_parts["formation"] = delta["oracle_formation_changed_ns"]
    out["reread"] = {
        "cause_by_seconds": {c: round(delta[f"rr_sec_{c}"] / max(1, sec_total), 4) for c in causes},
        "cause_by_receptions": {c: round(delta[f"rr_rx_{c}"] / max(1, rx_total), 4) for c in causes},
        "changed_seconds": {c: delta[f"chg_{c}"] for c in causes},
        "receptions_added": {"sync": delta["rx_added_sync"], "status": delta["rx_added_status"]}, "receptions_removed": {"sync": delta["rx_removed_sync"], "status": delta["rx_removed_status"]}, "sync_solo": {"added": delta.get("rx_added_sync_solo"), "removed": delta.get("rx_removed_sync_solo")}, "receptions_moved": delta["rx_moved"],
        "late_seconds": delta["late_seconds"],
        "late_receivers_a_second": round(delta["late_receivers"] / max(1, delta["late_seconds"]), 2),
        "late_age_behind_last_edge_s": {k: delta[f"late_age_{k}"] for k in ("0_2", "2_4", "4_8", "8_16", "16_20", "20_up")},
        "removed_age_behind_last_edge_s": {k: delta[f"removed_age_{k}"] for k in ("0_2", "2_4", "4_8", "8_16", "16_20", "20_up")},
        "formed_identical_by_seconds": round(delta["rr_formed_identical"] / max(1, delta["rr_formed_seconds"]), 4),
        "formed_identical_by_receptions": round(delta["rr_formed_identical_rx"] / max(1, delta["rr_formed_rx"]), 4),
        "reread_fraction_points_changed": round(f_changed, 4),
    }
    if perpair_parts is not None and "receptions_reread_sync" in delta:
        f_sync = delta["receptions_reread_sync"] / max(1, delta["receptions_read"])
        sync_parts = dict(perpair_parts)
        sync_parts["reads"] = sum(delta[k] for k in reads) * f_sync
        sync_parts["formation"] = delta["oracle_formation_sync_ns"]
        out["reread"]["sync_digest"] = {
            "reread_fraction": round(f_sync, 4),
            "ratio": round(sum(sync_parts.values()) / max(1, base), 4),
            "ms_a_refit_by_part": {k: round(v / 1e6 / max(1, delta["refits"]), 3) for k, v in sync_parts.items()},
            "status_only_seconds_formed": delta["status_only_formed"],
            "status_only_points_changed": delta["status_only_points_changed"],
        }
    if formed_parts is not None:
        total = sum(formed_parts.values())
        out["reread"]["ceiling_ratio"] = round(total / max(1, base), 4)
        out["reread"]["ceiling_ms_a_refit_by_part"] = {k: round(v / 1e6 / max(1, delta["refits"]), 3) for k, v in formed_parts.items()}
if seats:
    out["baseline_ms_a_seat_second"] = round(base / 1e6 / window / seats, 3)
    out["oracle_ms_a_seat_second"] = round(oracle / 1e6 / window / seats, 3)
if accept:
    accept["other_users_cores"] = round(accept["busy_cores_all"] - accept["relay_cores"] - accept["harness_cores"], 2)
out["accept"] = accept
print(json.dumps(out, indent=1))
