#!/bin/bash
# RFC-0198 baseline repeats on a quiet host: mlat-server as shipped and with its bad-sync drop
# patched out (a sensitivity bound), three times each at 250 and 500, then Tally at 250 again.
B=${MLAT_BASELINE:-$HOME/mlat-baseline}; cd "$(dirname "$0")"
for r in 1 2 3; do
  RUN=quiet-r$r MLAT_NS="250 500" SENS_NS=" " TALLY_NS=" " NOQUIET=$([ $r = 1 ] && echo 0 || echo 1) ./sweep.sh
  RUN=quiet-r$r TAG=-nobad SERVER=$B/mlat-server-nobadsync MLAT_NS="250 500" SENS_NS=" " TALLY_NS=" " NOQUIET=1 ./sweep.sh
done
RUN=quiet-r1 MLAT_NS=" " SENS_NS=" " TALLY_NS="250" NOQUIET=1 ./sweep.sh
echo repeats-done
