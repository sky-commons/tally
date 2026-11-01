#!/bin/bash
# RFC-0198 baseline: wiedehopf/mlat-server at the commit measured, its venv, and the patches the
# baseline ran with, into $MLAT_BASELINE (default ~/mlat-baseline): `mlat-server` with
# patches/mlat-server.diff (CSV kept whole and at six decimals, propagation at c), and
# `mlat-server-nobadsync` with patches/mlat-server-bad-sync-kept.diff on top (the sensitivity
# bound: the mlat messages of receivers in bad-sync timeout kept). Needs uv and a C compiler.
set -eu
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
B=${MLAT_BASELINE:-$HOME/mlat-baseline}; mkdir -p "$B"; cd "$B"
[ -d mlat-server ] || git clone -q https://github.com/wiedehopf/mlat-server.git
git -C mlat-server checkout -q c2d35b747f58dec086f7675ffd0f8287645a2614
git -C mlat-server apply "$SCRIPTS/patches/mlat-server.diff"
uv venv -q -p 3.12 venv
. venv/bin/activate
uv pip install -q numpy scipy cython ujson uvloop pykalman python-graph-core "setuptools<70"
(cd mlat-server && python setup.py build_ext --inplace > /dev/null)
rm -rf mlat-server-nobadsync && cp -r mlat-server mlat-server-nobadsync
git -C mlat-server-nobadsync apply "$SCRIPTS/patches/mlat-server-bad-sync-kept.diff"
echo "ready in $B"
