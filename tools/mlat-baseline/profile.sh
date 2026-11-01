#!/bin/bash
# RFC-0198 baseline: mlat-server's own per-function CPU split (MLAT_CPU_PROFILE=1, mlat/profile.py)
# at N=250, the largest N one core carried; a separate run, since the wrappers cost a little.
set -u
B=${MLAT_BASELINE:-$HOME/mlat-baseline}
TREE=${TALLY_TREE:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}
D=$B/runs/${RUN:-sweep1}/profile-250; mkdir -p $D/work
EMU=$(readlink -f $TREE/bazel-bin)/tools/mlat-baseline/mlat-emu
while awk -v l=$(cut -d' ' -f1 /proc/loadavg) 'BEGIN{exit !(l>=4)}'; do sleep 30; done
( ulimit -n 65536; MLAT_CPU_PROFILE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 exec taskset -c 15 $B/venv/bin/python $B/mlat-server/mlat-server --client-listen 127.0.0.1:40147 --work-dir $D/work --write-csv $D/work/results.csv > $D/server.log 2>&1 ) &
SP=$!; sleep 3
( ulimit -n 65536; exec taskset -c 0-11,16-27 $EMU run --server 127.0.0.1:40147 --feeders 250 --seconds 250 --workers 8 ) > $D/emu.json 2> $D/emu.log
cp $D/work/cpuprofile.txt $D/cpuprofile.txt
kill $SP; wait $SP 2>/dev/null
echo done
