#!/bin/bash
# RFC-0198: what the world relay plans (`tally-relay check`, its arguments in
# crates/relay/tests/world-relay.txt) with each case's per-seat MLAT costs put into cores.rs.
# Each argument line: NAME REFIT VERIFY SOLVE HOST REST PUBLISH (nanoseconds a seat-second). It
# restores cores.rs afterwards; run it in a clean tree. Needs a relay key file (KEY).
set -u
TREE=${TALLY_TREE:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}; cd "$TREE" || exit 2
KEY=${KEY:?a relay key file}
b() { ${BAZEL:-bazel} "$@"; }
F=crates/relay/src/cores.rs; O=$(mktemp); cp $F $O; trap 'cp $O $F' EXIT
run() {
  cp $O $F
  sed -i "s/^pub const MLAT_REFIT_NANOS_PER_FEEDER: usize = .*/pub const MLAT_REFIT_NANOS_PER_FEEDER: usize = $2;/; s/^pub const MLAT_VERIFY_NANOS_PER_FEEDER: usize = .*/pub const MLAT_VERIFY_NANOS_PER_FEEDER: usize = $3;/; s/^pub const MLAT_SOLVE_NANOS_PER_FEEDER: usize = .*/pub const MLAT_SOLVE_NANOS_PER_FEEDER: usize = $4;/; s/^pub const MLAT_HOST_NANOS_PER_FEEDER: usize = .*/pub const MLAT_HOST_NANOS_PER_FEEDER: usize = $5;/; s/^pub const MLAT_STEP_REST_NANOS_PER_FEEDER: usize = .*/pub const MLAT_STEP_REST_NANOS_PER_FEEDER: usize = $6;/; s/^pub const MLAT_PUBLISH_NANOS_PER_FEEDER: usize = .*/pub const MLAT_PUBLISH_NANOS_PER_FEEDER: usize = $7;/" $F
  b build --lockfile_mode=error //crates/relay:tally-relay >/dev/null 2>&1 || { echo "$1 build failed"; return; }
  R=$(b cquery --output=files //crates/relay:tally-relay 2>/dev/null)
  echo "== $*"
  $R check --memory-limit 32G --cores 16 --key $KEY --max-upload 10Gbit/s --max-connections 1024 --max-connections-per-address 1024 --area 801ffffffffffff 2>&1 | grep -E "^(mlat-seats|mlat-seats-by-memory|mlat-seats-by-cores) "
}
# The third revision's cases (RFC-0198 §5): slice 3's endpoints with the shadow check every 64th
# or every 16th refit, and the go threshold.
while read -r line; do [ -n "$line" ] && run $line; done <<'CASES'
today 5040000 387000 628000 320000 1240000 484000
s3-low-shadow64 2250000 387000 628000 320000 1240000 484000
s3-high-shadow64 3310000 387000 628000 320000 1240000 484000
s3-low-shadow16 2480000 387000 628000 320000 1240000 484000
s3-high-shadow16 3550000 387000 628000 320000 1240000 484000
go-threshold-3.0 3000000 387000 628000 320000 1240000 484000
CASES
