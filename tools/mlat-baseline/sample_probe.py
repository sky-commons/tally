"""RFC-0198 slice 1 (#40): a probe-built relay's refit counters (TALLY_REFIT_PROBE), /mlat and its
CPU at two instants of a tally-load run's measured window, and its seats every second.
usage: sample_probe.py PROBE_FILE FIRST_S SECOND_S OUT (seconds after this starts)."""
import json, os, sys, time, urllib.request

probe, first, second, out = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
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
while pid is None and time.time() - start < 180:
    pid, cmd = relay()
    time.sleep(1)
stats = cmd[cmd.index("--stats-listen") + 1]

def get(path):
    try:
        return json.load(urllib.request.urlopen(f"http://{stats}/{path}", timeout=5))
    except Exception:
        return None

def harness():
    total = 0
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                cmd = open(f"/proc/{p}/cmdline", "rb").read().split(b"\0")
                if cmd and cmd[0].endswith(b"tally-load"):
                    f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
                    total += int(f[11]) + int(f[12])
            except OSError:
                continue
    return total

def sample():
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    v = list(map(int, open("/proc/stat").readline().split()[1:]))
    try:
        p = json.load(open(probe))
    except (OSError, ValueError):
        p = None
    return {"at": time.time(), "relay_ticks": int(f[11]) + int(f[12]), "harness_ticks": harness(), "busy": sum(v) - v[3] - v[4],
            "mlat": get("mlat"), "memory": get("memory"), "probe": p,
            "load": open("/proc/loadavg").read().split()[:3]}

time.sleep(max(0, start + first - time.time()))
a = sample()
seats = []
while time.time() < start + second:
    m = get("mlat")
    if m:
        seats.append(m.get("seats_taken", 0))
    time.sleep(1)
b = sample()
json.dump({"a": a, "b": b, "seats": seats, "ticks_per_sec": tck}, open(out, "w"))
print("sampled", out)
