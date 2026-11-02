#!/bin/bash
# RFC-0198 slice 1 (#40): the refit oracle on the relay. tally-load at the world relay's plan
# (2,000 feeders, 16 cores) with a probe-built relay (`--config=refit-probe`), given memory
# headroom above the plan's (40 GiB against 29.4), on a quiet host, REPEATS times. Each run's
# probe counters and /mlat are sampled over the measured window (sample_probe.py) and judged by
# slice1_report.py: baseline refit against the oracle's, in the same run.
set -u
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
TREE=${TALLY_TREE:-$(git -C "$SCRIPTS" rev-parse --show-toplevel)}
OUT=${OUT:-$HOME/refit-slice1/runs}; mkdir -p "$OUT"
BIN=$(readlink -f "$TREE/bazel-bin")
TL=$BIN/crates/load/tally-load; RELAY=$BIN/crates/relay/tally-relay
MEMORY=${MEMORY:-42949672960}
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$OUT/slice1.log"; }
quiet() { local q=0; while [ $q -lt 3 ]; do
    l=$(cut -d' ' -f1 /proc/loadavg); if awk -v l="$l" 'BEGIN{exit !(l<3)}'; then q=$((q+1)); else q=0; fi; sleep 60; done; }
for r in $(seq 1 "${REPEATS:-3}"); do
  [ "${QUIET:-1}" = 1 ] && quiet
  D=$OUT/relay-r$r; rm -rf "$D"; mkdir -p "$D/state"
  log "relay run $r (load $(cut -d' ' -f1-3 /proc/loadavg))"
  python3 "$SCRIPTS/sample_probe.py" "$D/probe.json" 130 230 "$D/sample.json" > "$D/sample.out" 2>&1 &
  S=$!
  TALLY_REFIT_PROBE=$D/probe.json TALLY_RELAY=$RELAY "$TL" --relay-bin "$RELAY" --relay-mlat --relay-cores 16 --feeders 2000 \
    --ramp 60 --warmup 60 --duration 120 --state-dir "$D/state" \
    --relay-arg --memory --relay-arg "$MEMORY" --relay-arg --max-connections --relay-arg 1024 \
    --relay-arg --max-connections-per-address --relay-arg 1024 > "$D/load.log" 2>&1
  wait $S
  log "relay run $r: $(python3 "$SCRIPTS/slice1_report.py" "$D/sample.json" | tr '\n' ' ')"
  sleep "${GAP_S:-120}"
done
