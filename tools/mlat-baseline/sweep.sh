#!/bin/bash
# RFC-0198 baseline: mlat-server (wiedehopf c2d35b7, one core) under N emulated mlat-clients, and
# Tally on the same scene at matching N, on a quiet host.
#
# Once: `setup.sh` (mlat-server, its venv and its patches into $MLAT_BASELINE), and in the Tally
# tree `git apply tools/mlat-baseline/patches/tally-fix-dump.diff` (the relay writes every fix it
# publishes to TALLY_RELAY_FIXES_CSV) then
# `bazel build -c opt //tools/mlat-baseline:mlat-emu //crates/load:tally-load //crates/relay:tally-relay`.
# Then e.g. `RUN=r1 MLAT_NS="250 500" TALLY_NS="250" sweep.sh`. Pinning: mlat-server on CPU 15,
# the emulator on 0-11,16-27 (a 16-core, 32-thread host; change to suit).
set -u
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
B=${MLAT_BASELINE:-$HOME/mlat-baseline}
TREE=${TALLY_TREE:-$(git -C "$SCRIPTS" rev-parse --show-toplevel)}
OUT=$B/runs/${RUN:-$(date -u +%Y%m%dT%H%MZ)}; mkdir -p $OUT
BIN=$(readlink -f $TREE/bazel-bin)
EMU=$BIN/tools/mlat-baseline/mlat-emu; TL=$BIN/crates/load/tally-load; RELAY=$BIN/crates/relay/tally-relay
MLAT_NS=${MLAT_NS:-"250 500 1000 2000 4000"}; TALLY_NS=${TALLY_NS:-"250 500 1000"}
log() { echo "$(date -u +%FT%TZ) $*" | tee -a $OUT/sweep.log; }
quiet() { # load under 3 for three minutes in a row
  local q=0; while [ $q -lt 3 ]; do
    l=$(cut -d' ' -f1 /proc/loadavg); if awk -v l=$l 'BEGIN{exit !(l<3)}'; then q=$((q+1)); else q=0; fi; sleep 60; done
  log "quiet (load $(cut -d' ' -f1-3 /proc/loadavg))"; }
settle() { # between runs: two minutes, then load under 4
  sleep 120; while awk -v l=$(cut -d' ' -f1 /proc/loadavg) 'BEGIN{exit !(l>=4)}'; do sleep 30; done; }
run_mlat() {
  local N=$1 A=${2:-9000} D=$OUT/mlat${TAG:-}-$1; [ ${2:-9000} != 9000 ] && D=$OUT/mlat-$1-a$2; mkdir -p $D/work
  local W=8; [ $N -gt 500 ] && W=24
  log "mlat-server N=$N aircraft=$A"
  ( ulimit -n 65536; OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 exec taskset -c 15 $B/venv/bin/python ${SERVER:-$B/mlat-server}/mlat-server --client-listen 127.0.0.1:40147 --work-dir $D/work --write-csv $D/work/results.csv --status-interval 15 > $D/server.log 2>&1 ) &
  local SP=$!; sleep 3
  python3 $SCRIPTS/sample_mlat.py $SP $D 90 210 > $D/sample.out 2>&1 &
  local SAMP=$!
  ( ulimit -n 65536; exec taskset -c 0-11,16-27 $EMU run --server 127.0.0.1:40147 --feeders $N --aircraft $A --seconds 220 --workers $W ) > $D/emu.json 2> $D/emu.log
  wait $SAMP; kill $SP; wait $SP 2>/dev/null
  awk -F, '{print $2","$1","$5","$6}' $D/work/results.csv > $D/fixes.csv
  local WS=$(python3 -c "import json;print(json.load(open('$D/emu.json'))['world_seconds'])")
  local T0=$(python3 -c "import json;print(json.load(open('$D/emu.json'))['t0_unix_ms'])")
  taskset -c 0-11,16-27 $EMU eval --feeders $N --aircraft $A --world-seconds $WS --fixes $D/fixes.csv --t0-unix-ms $T0 --from 91 --to 211 > $D/eval.json 2> $D/eval.log
  python3 $SCRIPTS/syncstat.py $D/snap > $D/sync.json 2>&1
  log "mlat-server N=$N: $(cat $D/sample.json) $(cat $D/eval.json) $(cat $D/sync.json)"
}
run_tally() {
  local N=$1 MODE=$2 D=$OUT/tally-$1-$2; mkdir -p $D/state
  local M=""; [ $MODE = on ] && M="--relay-mlat"
  log "tally N=$N mlat=$MODE"
  python3 $SCRIPTS/sample_tally.py 130 230 $D/sample.json > $D/sample.out 2>&1 &
  local SAMP=$!
  TALLY_RELAY_FIXES_CSV=$D/fixes.csv TALLY_RELAY=$RELAY $TL --relay-bin $RELAY $M --relay-cores 16 --feeders $N --ramp 60 --warmup 60 --duration 120 --state-dir $D/state --streams positions \
    --relay-arg --memory --relay-arg 31608274944 --relay-arg --max-connections --relay-arg 1024 --relay-arg --max-connections-per-address --relay-arg 1024 > $D/load.log 2>&1
  wait $SAMP
  if [ $MODE = on ]; then
    local START=$(grep -o 'TALLY-LOAD-START unix_ms=[0-9]*' $D/load.log | cut -d= -f2)
    local SECS=$(grep -o '[0-9]* s forward in time' $D/load.log | head -1 | cut -d' ' -f1)
    $EMU eval --feeders $N --world-seconds $((SECS + 3)) --fixes $D/fixes.csv --t0-unix-ms $START --from 121 --to 241 > $D/eval.json 2> $D/eval.log
  fi
  log "tally N=$N mlat=$MODE: $(cat $D/sample.out | tail -1) $(cat $D/eval.json 2>/dev/null)"
}
[ "${NOQUIET:-}" = 1 ] || quiet
for N in $MLAT_NS; do run_mlat $N; settle; done
for N in ${SENS_NS:-1000}; do run_mlat $N 4900; settle; done
for N in $TALLY_NS; do run_tally $N on; settle; run_tally $N off; settle; done
log done
