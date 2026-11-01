"""Summarises mlat-server's sync.json and clients.json snapshots (RFC-0198 baseline)."""
import json, statistics, sys
d = sys.argv[1]
s = json.load(open(d + "/sync.json")); c = json.load(open(d + "/clients.json"))
pairs = [(a, b, p) for a, v in s.items() for b, p in v["peers"].items() if a < b]
out = {"receivers_in_sync": len(s), "pairs": len(pairs)}
if pairs:
    errs = sorted(p[1] for a, b, p in pairs)
    q = lambda f: errs[int(f * (len(errs) - 1))]
    out.update(err_us_p10=q(0.1), err_us_p50=q(0.5), err_us_p90=q(0.9),
               n_median=statistics.median(p[0] for a, b, p in pairs),
               jumped=sum(1 for a, b, p in pairs if p[4]),
               outlier_pct_median=statistics.median(p[5] for a, b, p in pairs),
               # mlat-server's own "good pair" reading (coordinator: not jumped, outliers <= 35%,
               # error within 1.2 us once n > 10, 1.8 us once n > 3, 2.4 us always)
               good=sum(1 for a, b, p in pairs if not (p[4] or p[5] > 35 or (p[0] > 10 and p[1] > 1.2) or (p[0] > 3 and p[1] > 1.8) or p[1] > 2.4)),
               pairs_per_receiver=2 * len(pairs) / max(1, len(s)))
bad = [v.get("bad_sync_timeout", 0) for v in c.values()]
out["clients"] = len(c); out["bad_sync_clients"] = sum(1 for x in bad if x > 0)
print(json.dumps(out))
