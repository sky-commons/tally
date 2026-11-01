"""RFC-0198 baseline: each configuration's runs across repeat directories (runs/<RUN>/<config>),
as mean, least and most, with each run's foreign CPU. usage: summarize.py RUNS_DIR PREFIX..."""
import glob, json, os, sys

root, prefixes = sys.argv[1], sys.argv[2:]
rows = {}
for prefix in prefixes:
    for d in sorted(glob.glob(os.path.join(root, prefix + "*"))):
        for config in sorted(os.listdir(d)):
            path = os.path.join(d, config)
            if not os.path.isdir(path) or not os.path.exists(os.path.join(path, "sample.json")):
                continue
            r = {"run": os.path.basename(d)}
            for f in ("sample", "eval", "sync"):
                try:
                    v = json.load(open(os.path.join(path, f + ".json")))
                    r.update(v.get("result", v))
                except (OSError, ValueError):
                    pass
            rows.setdefault(config, []).append(r)

def stat(values):
    values = [v for v in values if isinstance(v, (int, float))]
    if not values:
        return None
    return {"mean": round(sum(values) / len(values), 4), "least": min(values), "most": max(values), "n": len(values)}

out = {}
for config, runs in rows.items():
    keys = ["server_cores", "relay_cores", "seats_mean", "modes_fixes_per_s", "solved_fraction",
            "h_on_track_p50", "h_on_track_p95", "bad_sync_clients", "foreign_cores", "busy_cores_all"]
    out[config] = {k: stat([r.get(k) for r in runs]) for k in keys if stat([r.get(k) for r in runs])}
    out[config]["runs"] = [r["run"] for r in runs]
print(json.dumps(out, indent=1))
