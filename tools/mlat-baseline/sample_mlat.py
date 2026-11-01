"""RFC-0198 baseline: samples mlat-server's CPU over the emulator's measured window.
usage: sample_mlat.py SERVER_PID RUN_DIR FIRST_S SECOND_S (seconds after the emulator's t0)."""
import json, os, re, shutil, sys, time

pid, d, first, second = int(sys.argv[1]), sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
tck = os.sysconf("SC_CLK_TCK")

def proc_ticks(p):
    f = open(f"/proc/{p}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])

def emu_pid():
    for p in os.listdir("/proc"):
        if p.isdigit():
            try:
                if open(f"/proc/{p}/comm").read().strip() == "mlat-emu":
                    return int(p)
            except OSError:
                pass

def cpu_total():
    f = open("/proc/stat").readline().split()[1:]
    v = list(map(int, f))
    return sum(v) - v[3] - v[4], sum(v)  # busy, all (ticks, every CPU)

t0 = None
while t0 is None:
    try:
        m = re.search(r"t0_unix_ms=(\d+)", open(d + "/emu.log").read())
        if m:
            t0 = int(m.group(1)) / 1000
    except OSError:
        pass
    time.sleep(0.5)

def sample():
    e = emu_pid()
    return {"at": time.time(), "server": proc_ticks(pid), "emu": proc_ticks(e) if e else 0, "cpu": cpu_total(),
            "load": open("/proc/loadavg").read().split()[:3]}

time.sleep(max(0, t0 + first - time.time()))
a = sample()
time.sleep(max(0, t0 + second - 12 - time.time()))
os.makedirs(d + "/snap", exist_ok=True)
for name in ("sync.json", "clients.json", "aircraft.json"):
    try:
        shutil.copy(d + "/work/" + name, d + "/snap/" + name)
    except OSError:
        pass
time.sleep(max(0, t0 + second - time.time()))
b = sample()
dt = b["at"] - a["at"]
busy = (b["cpu"][0] - a["cpu"][0]) / tck
own = (b["server"] - a["server"] + b["emu"] - a["emu"]) / tck
out = {"t0": t0, "window_s": dt, "server_cores": (b["server"] - a["server"]) / tck / dt,
       "emu_cores": (b["emu"] - a["emu"]) / tck / dt, "foreign_cores": (busy - own) / dt,
       "load_a": a["load"], "load_b": b["load"]}
json.dump(out, open(d + "/sample.json", "w"))
print(json.dumps(out))
