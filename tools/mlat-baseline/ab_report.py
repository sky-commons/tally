"""RFC-0198 Appendix C: one same-run A/B run's verdict (abrun.sh): the prototype's refit time over
the engine's on the same area-edges, both orders, the prototype's phases, the checks, the seats
and loads, and each path's instructions by call path (perf).
usage: ab_report.py RUN_DIR"""
import json, os, subprocess, sys

d = sys.argv[1]
s = json.load(open(f"{d}/sample.json"))
a, b = s["a"].get("probe") or {}, s["b"].get("probe") or {}
delta = {k: v - a.get(k, 0) for k, v in b.items() if isinstance(v, (int, float))}
refits = max(1, delta.get("ab_refits", 0))
ms = lambda k: round(delta.get(k, 0) / 1e6 / refits, 3)
ma, mb = s["a"]["mlat"], s["b"]["mlat"]
out = {
    "refits": delta.get("ab_refits", 0),
    "engine_first": delta.get("ab_engine_first", 0),
    "engine_ms_a_refit": ms("ab_engine_ns"),
    "engine_gather_ms_a_refit": ms("ab_engine_gather_ns"),
    "proto_ms_a_refit": ms("ab_proto_ns"),
    "ratio": round(delta.get("ab_proto_ns", 0) / max(1, delta.get("ab_engine_ns", 0)), 4),
    "proto_phases_ms_a_refit": {k: ms(k) for k in ("proto_gather_ns", "proto_store_ns",
        "proto_digest_ns", "proto_formation_ns", "proto_build_ns", "proto_window_ns")},
    "proto_fit_ms_a_refit": round(ms("ab_proto_ns") - sum(ms(k) for k in ("proto_gather_ns", "proto_store_ns",
        "proto_digest_ns", "proto_formation_ns", "proto_build_ns", "proto_window_ns")), 3),
    "engine_phases_ms_a_refit": {"gather": ms("ab_engine_gather_ns"), **{k: ms(k) for k in ("reader_ns",
        "clocks_ns", "digests_ns", "formation_ns", "blocks_gather_ns")}},
    "engine_builds_and_fit_ms_a_refit": round(ms("ab_engine_ns") - ms("ab_engine_gather_ns") - sum(ms(k) for k in (
        "reader_ns", "clocks_ns", "digests_ns", "formation_ns", "blocks_gather_ns")), 3),
    "models_same": delta.get("ab_same", 0), "models_mismatched": delta.get("ab_mismatches", 0),
    "shadow_runs": delta.get("shadow_runs", 0), "shadow_mismatches": delta.get("shadow_mismatches", 0),
    "shadow_failed_alike": delta.get("shadow_failed", 0),
    "changes_a_refit": round(delta.get("proto_changes", 0) / refits), "touched_a_refit": round(delta.get("proto_touched", 0) / refits),
    "parts_new_a_refit": round(delta.get("proto_parts_new", 0) / refits), "parts_gone_a_refit": round(delta.get("proto_parts_gone", 0) / refits),
    "resets": delta.get("proto_resets", 0),
    "formed": delta.get("proto_formed", 0), "formed_held": delta.get("proto_formed_held", 0),
    "blocks_built": delta.get("proto_blocks_built", 0), "blocks_held": delta.get("proto_blocks_held", 0),
    "proto_bytes_an_area": round(delta.get("proto_bytes", 0) / max(1, delta.get("proto_bytes_samples", 0))),
    "seats_min": min(s["seats"] or [0]), "seats_max": max(s["seats"] or [0]),
    "seat_cap": mb.get("seat_cap"),
    "arrived_over": mb.get("arrived_over", 0) - ma.get("arrived_over", 0),
    "unfitted": mb["steps_total"].get("unfitted", 0) - ma["steps_total"].get("unfitted", 0),
    "steps_collapsed": mb.get("steps_collapsed", 0) - ma.get("steps_collapsed", 0),
    "other_relays_max": s.get("other_relays_max"),
    "loads": open(f"{d}/loads").read().split("\n")[:2],
}
memory = s["b"].get("memory") or {}
seats = max(1, sum(s["seats"]) / max(1, len(s["seats"])))
probe_b = s["b"].get("probe") or {}
out["memory_a_seat"] = {k: round(probe_b[k] / seats) for k in ("memos_blocks", "memos_read", "memos_network") if isinstance(probe_b.get(k), int)}
out["stores"] = {st["store"]: {"held": st["held"], "limit": st["limit"], "refused": st["refused"]} for st in (memory.get("stores") or []) if st.get("store") in ("arrived", "engine", "inbox")}
perf = f"{d}/perf.data"
if os.path.exists(perf):
    rep = subprocess.run(["sudo", "-n", "perf", "report", "-i", perf, "--children", "--sort", "symbol",
        "--stdio", "-g", "none"], capture_output=True, text=True).stdout
    share = {}
    for line in rep.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].endswith("%") and parts[2] == "[.]":
            share[parts[3]] = max(share.get(parts[3], 0.0), float(parts[0][:-1]))
    pick = lambda name: share.get(name, 0.0)
    both = pick("tally_mlat::fix::proto_refit")
    proto = pick("tally_mlat_solver::pair::proto::fit_proto")
    shadow = pick("tally_mlat::fix::shadow_now")
    engine = both - proto - shadow
    out["instructions_share_percent"] = {
        "both_paths": both, "engine": round(engine, 2), "proto": proto, "shadow": shadow,
        "engine_gather": pick("tally_mlat_solver::arrived::Arrived::area_inputs_over"),
        "proto_gather": pick("tally_mlat_solver::arrived::proto::Gather::update"),
        "proto_apply": pick("tally_mlat_solver::pair::proto::Proto::apply"),
        "proto_window_clocks": pick("tally_mlat_solver::pair::proto::Proto::window_clocks"),
        "proto_form": pick("tally_mlat_solver::pair::proto::Proto::form"),
    }
    out["instructions_ratio"] = round(proto / engine, 4) if engine > 0 else None
json.dump(out, open(f"{d}/ab.json", "w"), indent=1)
print(json.dumps(out))
