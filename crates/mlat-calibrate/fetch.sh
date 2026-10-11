#!/usr/bin/env bash
# Fetches one LocaRDS subset (Zenodo 10.5281/zenodo.4739276, CC BY-SA 4.0) for the MLAT
# calibration, checks it against the hashes below and unzips it beside itself:
#
#   tally/crates/mlat-calibrate/fetch.sh /data/johnny/datasets/locards 2
#   bazel run -c opt //crates/mlat-calibrate:tally-mlat-calibrate -- \
#       /data/johnny/datasets/locards/subset_2
#
# Nothing of the dataset is committed. Subset 1 was held back for the competition in the first
# Zenodo version (4298999); this version's subset 1 is complete, and its hashes differ.
set -euo pipefail

dir="${1:?usage: fetch.sh <directory> [subset 1-8]}"
subset="${2:-2}"

# Zenodo's MD5 for each subset (what the record publishes), and the SHA-256 measured here.
declare -A md5=(
  [1]=ca2e163f437ff8b9dfaef64bed871ff3
  [2]=9e40dcb90cad589e9d7f3ffc2a1af753
  [3]=950319a9b6791f3111bf4cb01a510846
  [4]=2d1a788ee8fca8550e8bb758b11824c5
  [5]=8cbd3f3af5f341e0dd65baad9066f05a
  [6]=bbea4a6e777d35d2bd5c1f54394586b6
  [7]=e312d2e974173220ee4d0887374ec0c7
  [8]=45413ab8ee02db6dc43f75e5bebcadd7
)
declare -A sha256=(
  [2]=104cabdd6e91917079bb308e5ed0d4a7e493ea697a0bcd6631f880ce7aa86a80
)

[[ -n "${md5[$subset]:-}" ]] || {
  echo "no subset $subset" >&2
  exit 2
}
mkdir -p "$dir"
zip="$dir/subset_$subset.zip"
if [[ ! -f "$zip" ]]; then
  curl -fL --retry 3 -o "$zip.part" \
    "https://zenodo.org/api/records/4739276/files/subset_$subset.zip/content"
  mv "$zip.part" "$zip"
fi
echo "${md5[$subset]}  $zip" | md5sum -c -
if [[ -n "${sha256[$subset]:-}" ]]; then
  echo "${sha256[$subset]}  $zip" | sha256sum -c -
fi
unzip -o -q "$zip" -d "$dir"
echo "$dir/subset_$subset"
