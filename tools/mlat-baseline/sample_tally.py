"""RFC-0198 baseline: a tally-load run's relay process CPU and seats over its measured window.
usage: sample_tally.py FIRST_S SECOND_S OUT (seconds after this starts, as measure.sh's sampler)."""
import json, os, sys, time, urllib.request

first, second, out = float(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
tck = os.sysconf("SC_CLK_TCK")
start = time.time()

def relay():
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
            except OSError:
                continue
            if cmd and cmd[0].endswith(b"tally-relay") and b"--stats-listen" in cmd:
                return int(p), [c.decode() for c in cmd]
    return None, None

pid = None
while pid is None and time.time() - start < 120:
    pid, cmd = relay(); time.sleep(1)
stats = cmd[cmd.index("--stats-listen") + 1]

def ticks():
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])

def cpu_total():
    v = list(map(int, open("/proc/stat").readline().split()[1:]))
    return sum(v) - v[3] - v[4]

def mlat():
    try:
        return json.load(urllib.request.urlopen(f"http://{stats}/mlat", timeout=5))
    except Exception:
        return None

time.sleep(max(0, start + first - time.time()))
a = {"at": time.time(), "relay": ticks(), "busy": cpu_total(), "mlat": mlat(), "load": open("/proc/loadavg").read().split()[:3]}
seats = []
while time.time() < start + second:
    m = mlat()
    if m:
        seats.append(m.get("seats_taken", 0))
    time.sleep(1)
b = {"at": time.time(), "relay": ticks(), "busy": cpu_total(), "mlat": mlat(), "load": open("/proc/loadavg").read().split()[:3]}
dt = b["at"] - a["at"]
res = {"window_s": dt, "relay_cores": (b["relay"] - a["relay"]) / tck / dt,
       "busy_cores_all": (b["busy"] - a["busy"]) / tck / dt,
       "seats_mean": sum(seats) / len(seats) if seats else 0, "seats_min": min(seats) if seats else 0,
       "load_a": a["load"], "load_b": b["load"]}
if a["mlat"] and b["mlat"]:
    for k in ("fit_ms", "solve_ms", "refits", "solved", "positions", "due", "transmissions"):
        res[k] = b["mlat"]["steps_total"][k] - a["mlat"]["steps_total"][k]
json.dump({"result": res, "a_mlat": a["mlat"], "b_mlat": b["mlat"]}, open(out, "w"))
print(json.dumps(res))
