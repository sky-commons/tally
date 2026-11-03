#!/bin/bash
# RFC-0181 §10's cost a seat, measured as `cores.rs` states it: tally-load at the world relay's plan
# (2,000 feeders, 16 cores, its memory), the relay on cores 0-15, an optimised build without the
# probe, never beside another tally-load; its threads' CPU and /mlat's step totals sampled over
# the measured window (sample_cost.py). BIN holds tally-load and tally-relay; OUT/run-N gets each.
# With PROTO=1 the relay refits by the probe's held-read prototype (a probe-built BIN,
# `TALLY_REFIT_PROTO`), its counters written to OUT/run-N/probe.json and sampled with the rest.
# usage: BIN=dir OUT=dir RUN=n [PROTO=1] cost.sh
set -u
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
D=$OUT/run-$RUN; rm -rf "$D"; mkdir -p "$D/state"
while pgrep -x tally-load > /dev/null; do sleep 30; done
echo "$(date -u +%FT%TZ) cost run $RUN of $BIN (load $(cut -d' ' -f1-3 /proc/loadavg))"
if [ "${PROTO:-0}" = 1 ]; then
  export TALLY_REFIT_PROTO=1 TALLY_REFIT_PROBE=$D/probe.json SAMPLE_PROBE=$D/probe.json
fi
python3 "$SCRIPTS/sample_cost.py" 130 230 "$D/sample.json" "$D/state" > "$D/sample.out" 2>&1 &
S=$!
TALLY_RELAY=$BIN/tally-relay "$BIN/tally-load" --relay-bin "$BIN/tally-relay" --relay-mlat --relay-cores 16 \
  --feeders 2000 --ramp 60 --warmup 60 --duration 120 --state-dir "$D/state" \
  --relay-arg --memory --relay-arg "${MEMORY:-31608274944}" --relay-arg --max-connections --relay-arg 1024 \
  --relay-arg --max-connections-per-address --relay-arg 1024 > "$D/load.log" 2>&1
wait $S
cat "$D/sample.out"
