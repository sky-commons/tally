#!/bin/bash
# RFC-0198 Appendix C, the held-read prototype's same-run A/B: tally-load at the world relay's plan
# (2,000 feeders, 16 cores, its memory) against a probe-built relay that refits every area-edge
# both ways (`TALLY_REFIT_PROTO`), the relay on cores 0-15, never beside another tally-load (load
# from anything else accepted, and recorded at each end). Its counters and /mlat are sampled over
# the measured window (sample_cost.py), and its instructions by call path for 60 s inside it
# (`perf record`, unwound by DWARF). BIN holds tally-load and tally-relay.
# usage: BIN=dir OUT=dir RUN=n abrun.sh
set -u
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
D=$OUT/run-$RUN; rm -rf "$D"; mkdir -p "$D/state"
start=$(date +%s)
while pgrep -x tally-load > /dev/null; do
  if [ $(( $(date +%s) - start )) -gt 2700 ]; then echo "another tally-load for 45 min: stopping"; exit 3; fi
  sleep 30
done
echo "$(date -u +%FT%TZ) A/B run $RUN load-start $(cut -d' ' -f1-3 /proc/loadavg)" | tee "$D/loads"
export TALLY_REFIT_PROTO=1 TALLY_REFIT_PROBE=$D/probe.json SAMPLE_PROBE=$D/probe.json
python3 "$SCRIPTS/sample_cost.py" 130 230 "$D/sample.json" "$D/state" > "$D/sample.out" 2>&1 &
S=$!
(
  sleep 145
  pid=$(pgrep -f -- "--state-dir $D/state" | head -1)
  for p in $(pgrep -x tally-relay); do
    if tr '\0' ' ' < /proc/$p/cmdline | grep -q -- "$D/state"; then pid=$p; fi
  done
  sudo -n perf record -e instructions:u --call-graph dwarf,16384 -c 5000003 -p "$pid" -o "$D/perf.data" -- sleep 40 > "$D/perf.out" 2>&1
) &
P=$!
TALLY_RELAY=$BIN/tally-relay "$BIN/tally-load" --relay-bin "$BIN/tally-relay" --relay-mlat --relay-cores 16 \
  --feeders "${FEEDERS:-2000}" --ramp 60 --warmup 60 --duration 120 --state-dir "$D/state" \
  --relay-arg --memory --relay-arg "${MEMORY:-31608274944}" --relay-arg --max-connections --relay-arg 1024 \
  --relay-arg --max-connections-per-address --relay-arg 1024 > "$D/load.log" 2>&1
wait $S $P
echo "$(date -u +%FT%TZ) A/B run $RUN load-end $(cut -d' ' -f1-3 /proc/loadavg)" | tee -a "$D/loads"
python3 "$SCRIPTS/ab_report.py" "$D"
