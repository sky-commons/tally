"""RFC-0181 §10's cost a seat (`crates/relay/src/cores.rs`, MLAT_*_NANOS_PER_FEEDER): a tally-load
run's relay sampled at two instants of its measured window, each thread's CPU and /mlat's step
totals, and its seats every second; then each part in ns a seat-second.
usage: sample_cost.py FIRST_S SECOND_S OUT MATCH (seconds after this starts; MATCH picks the relay
whose command line holds it, its run's state directory)
       sample_cost.py --report OUT..."""
import json, os, sys, time, urllib.request

# The duties thread's CPU at the same feeders not hosting MLAT (cores.rs, MLAT_PUBLISH).
DUTIES_WITHOUT_MLAT = 0.028


def report(path):
    d = json.load(open(path))
    a, b, tck = d["a"], d["b"], d["ticks_per_sec"]
    window = b["at"] - a["at"]
    seats = sum(d["seats"]) / max(1, len(d["seats"]))
    named = lambda s, name: sum(t for n, t in s["threads"].values() if n == name)
    both = set(a["threads"]) & set(b["threads"])
    others = sum(b["threads"][t][1] - a["threads"][t][1] for t in both if b["threads"][t][0] != "tally-relay")
    cores = lambda ticks: ticks / tck / window
    step = cores(b["process_ticks"] - a["process_ticks"] - others)
    ta, tb = a["mlat"]["steps_total"], b["mlat"]["steps_total"]
    fit = (tb["fit_ms"] - ta["fit_ms"]) / 1000 / window
    solve = (tb["solve_ms"] - ta["solve_ms"]) / 1000 / window
    host = cores(named(b, "tally-mlat") - named(a, "tally-mlat"))
    duties = cores(named(b, "tally-duties") - named(a, "tally-duties"))
    per = lambda c: round(c / seats * 1e9)
    refits = (tb["refits"] - ta["refits"]) / window if "refits" in tb else None
    return {
        "seats_mean": round(seats, 1), "seats_min": min(d["seats"] or [0]), "window_s": round(window, 1),
        "other_relays_max": d.get("other_relays_max"),
        "refit": per(fit), "solve": per(solve), "host": per(host), "rest": per(step - fit - solve),
        "publish": per(duties - DUTIES_WITHOUT_MLAT),
        "refits_a_second": refits and round(refits, 2),
        "ms_a_refit": refits and round(fit * 1000 / refits, 2),
        "relay_cores": round(cores(b["process_ticks"] - a["process_ticks"]), 3),
        "arrived_over": b["mlat"].get("arrived_over", 0) - a["mlat"].get("arrived_over", 0),
        "steps_collapsed": b["mlat"].get("steps_collapsed", 0) - a["mlat"].get("steps_collapsed", 0),
        "load": [a["load"], b["load"]],
    }


if sys.argv[1] == "--report":
    for path in sys.argv[2:]:
        print(path, json.dumps(report(path)))
    sys.exit(0)

first, second, out, match = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3], sys.argv[4].encode()
tck = os.sysconf("SC_CLK_TCK")
start = time.time()


def relay():
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
            except OSError:
                continue
            if cmd and cmd[0].endswith(b"tally-relay") and b"--stats-listen" in cmd and any(match in c for c in cmd):
                return int(p), [c.decode() for c in cmd]
    return None, None


pid = None
while pid is None and time.time() - start < 180:
    pid, cmd = relay()
    time.sleep(1)
stats = cmd[cmd.index("--stats-listen") + 1]


def get(path):
    try:
        return json.load(urllib.request.urlopen(f"http://{stats}/{path}", timeout=5))
    except Exception:
        return None


def sample():
    threads = {}
    for t in os.listdir(f"/proc/{pid}/task"):
        try:
            name = open(f"/proc/{pid}/task/{t}/comm").read().strip()
            f = open(f"/proc/{pid}/task/{t}/stat").read().rsplit(")", 1)[1].split()
            threads[t] = (name, int(f[11]) + int(f[12]))
        except OSError:
            pass
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return {"at": time.time(), "threads": threads, "process_ticks": int(f[11]) + int(f[12]),
            "mlat": get("mlat"), "load": open("/proc/loadavg").read().split()[:3]}


def other_relays():
    count = 0
    for p in os.listdir("/proc"):
        if p.isdigit() and int(p) != pid:
            try:
                c = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
            except OSError:
                continue
            if c and c[0].endswith(b"tally-relay"):
                count += 1
    return count


time.sleep(max(0, start + first - time.time()))
a = sample()
seats, others = [], []
while time.time() < start + second:
    others.append(other_relays())
    m = get("mlat")
    if m:
        seats.append(m.get("seats_taken", 0))
    time.sleep(1)
b = sample()
json.dump({"a": a, "b": b, "seats": seats, "other_relays_max": max(others or [0]), "ticks_per_sec": tck}, open(out, "w"))
print(out, json.dumps(report(out)))
