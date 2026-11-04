#!/usr/bin/env bash
# Installs the Tally feeder on a receiver (RFC-0171 §3.5). Download it, read it if you like, and
# run it:
#
#   curl -fsSL https://github.com/sky-commons/tally/releases/latest/download/install.sh -o /tmp/tally-install.sh
#   sudo bash /tmp/tally-install.sh
#
# (`curl -fsSL .../install.sh | sudo bash` works too: everything runs only once the whole script
# has arrived, and what it must ask, it asks on the terminal either way.)
#
# It downloads tally-feed for this machine and checks its sha256 and its signature (below), finds
# the receiver's decoders and location, makes the receiver's key if there is none, starts
# tally-feed.service, waits until it publishes, and prints the station's page. It changes no readsb
# or dump978 setting (but readsb's location, when it has none, and only when the owner says yes:
# below) and no other feed. A rerun upgrades the binary and keeps the key, the location
# found before, the owner's own flags and the owner's choice about automatic updates.
#
# Automatic updates (RFC-0203) are on unless the owner says otherwise: TALLY_AUTO_UPDATE=0 (or
# --no-auto-update) installs with them off, and `systemctl disable --now tally-feed-update.timer`
# turns them off later, which every rerun keeps. tally-feed-update.timer runs
# /usr/local/lib/tally/update about once a day, at a time of its own for each receiver: it installs
# a newer release only when this release's cosign (pinned below by its sha256) finds it signed by
# this repository's release workflow on that release's own tag, never an older release, and puts
# the old files back when the new feeder does not start. The feeder itself never updates itself
# and takes no orders from the network (RFC-0171 §3.5): the updater is this script's, asks only
# GitHub for the latest release, and the owner can turn it off.
#
# Every file of a release this script installs is checked twice: against the .sha256 beside it
# (a broken download) and against its cosign signature bundle, .sigstore.json (a release someone
# other than the release workflow made), with the certificate identity pinned to
# https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/VERSION. What reads
# the network and parses what it brought (curl, cosign) runs as a throwaway unprivileged user of its
# own (a transient systemd unit with DynamicUser=); root only writes what they fetched to files and
# installs it once it is checked.
#
# /etc/default/tally-feed is shared. The block between its BEGIN and END lines is this script's,
# rewritten on every run, so a rerun with a new TALLY_LAT, TALLY_LON or TALLY_ALT
# wins. The owner's own flags go in TALLY_FEED_EXTRA, below the block, which
# every run keeps as it is.
#
# The location is the first found of: TALLY_LAT, TALLY_LON and TALLY_ALT (metres, or with m or
# ft); adsb.im's /opt/adsb/config/.env; readsb's arguments (/etc/default/readsb, or a running
# readsb); PiAware's /var/cache/piaware/location.env; dump1090-fa's /etc/default/dump1090-fa; the
# feed clients of adsbexchange, adsb.fi, airplanes.live and adsb.lol (/etc/default/<name>); a
# running ultrafeeder container's LAT, LONG and ALT; and what an earlier run of this script wrote.
# The altitude is never assumed: when no source holds one, it is asked for on the terminal, and
# with no terminal the install stops naming TALLY_ALT.
#
# Or it finds the location from an address (RFC-0204): with --locate, with TALLY_ADDRESS="...", or
# when no source holds one and the owner gives an address on the terminal. The address is geocoded
# by the US Census geocoder (US addresses) and OpenStreetMap's Nominatim (elsewhere, and as the
# Census match's check); the point's ground elevation comes from USGS EPQS (the US) or Open-Meteo
# (elsewhere); the antenna's height above the ground is one question (TALLY_ANTENNA=window,
# upstairs, roof or metres); and the geoid height that turns it into height above the WGS84
# ellipsoid comes from geoid.txt.gz, an EGM2008 grid published and signed with the release. The
# address goes only to those services, never to Tally; it is never printed, logged or stored (it
# reaches curl on its standard input, not on a command line), and only the coordinates are kept.
# Interactively the owner confirms the place (an OpenStreetMap link to it is shown), and is offered
# to set readsb's --lat and --lon too when readsb has none (with a backup). Any lookup that fails
# falls back to the questions above. An automatic update (--upgrade) never locates.
#
# The exact location goes only to Tally relays, inside the feed, for multilateration (MLAT). The
# feed signs it in a record relays keep to themselves; what any data user reads (the API, the
# streams, the stats) names only the antenna's public cell, about 6 km across, which is all a
# public map shows. It asks nothing about it and passes no flag for it.
#
# Where nothing answers on 127.0.0.1:30005 but an ultrafeeder container runs, the decoder's output
# is inside docker and a host install would feed nothing: it installs nothing and prints the
# compose service to add instead.
#
# Until a release pipeline publishes Tally's releases (RFC-0180 phase 1), nothing writes the
# release's address into this script (PUBLISHED_RELEASE) or publishes a seed list beside it, so an
# install names both itself:
#
#   sudo TALLY_RELEASE=<release> TALLY_SEEDS=/path/to/seeds bash /tmp/tally-install.sh
#
# The relays it starts from are a seed list: the release's own (`seeds`, published beside this
# script with its .sha256), or the file TALLY_SEEDS names. A seed list is configuration, never this
# script's: whoever publishes a release ships the relays it starts feeders from, and anyone (an
# image builder, a distribution, an operator) can ship their own. Each line is one relay and the
# operator who runs it:
#
#   HOST:PORT=KEY  OPERATOR
#
# the key a relay's 32-byte base64 public key, the operator its name as the feeder's owner should
# read it; blank lines and lines starting with # are skipped. An entry that names no operator is
# refused: an owner is told whose relays their receiver will publish to. They are written into
# /etc/default/tally-feed as --relay flags, each beside its operator; from there tally-feed learns
# more relays from relays (RFC-0174 §2.2).
#
#   install.sh --check-seeds FILE
#
# reads FILE as this script reads a seed list and prints each relay and its operator, or refuses it
# saying why; it installs nothing and needs no root.
#
#   install.sh --locate              finds the location from the antenna's street address (as
#                                    TALLY_ADDRESS, which needs no terminal), whatever was found
#                                    before
#   install.sh --no-auto-update      installs with automatic updates off (as TALLY_AUTO_UPDATE=0)
#   install.sh --upgrade             what the updater runs: no questions, no container route, and a
#                                    longer wait for the new feeder to publish
#   install.sh --uninstall           stops tally-feed and its updater and removes its units, binary,
#                                    what it learned and /etc/default/tally-feed; keeps the key, so a
#                                    later install is the same station
#   install.sh --uninstall --purge   the same, and deletes the key: the station's identity is gone
#                                    for good
set -euo pipefail

VERSION="v0.7.4"
# Where this release is published, whose `tally-feed` binaries, unit and seed list this script
# installs. The source names no publisher: the publisher writes its release's address here when it
# publishes it, and TALLY_RELEASE overrides it.
PUBLISHED_RELEASE="https://github.com/sky-commons/tally/releases/download/v0.7.4"
# What any public map shows of the location: the feeder's public cell (H3 resolution 6).
PUBLIC_AREA="~6 km"
BIN=/usr/local/bin/tally-feed
KEY=/etc/tally/key
DEFAULTS=/etc/default/tally-feed
UNIT=/etc/systemd/system/tally-feed.service
# What the feeder learned (the relays it knows): its StateDirectory, which for a DynamicUser
# systemd keeps under /var/lib/private and links from /var/lib.
STATE=/var/lib/tally-feed
STATE_PRIVATE=/var/lib/private/tally-feed
# The unit's LoadCredential= and $CREDENTIALS_DIRECTORY need this systemd or later (Debian
# bullseye has 247).
SYSTEMD_AT_LEAST=247
# A station's page, by its public key as base64url without padding.
STATION_PAGE=https://tally.skycommons.org/feeders
ISSUES=https://github.com/sky-commons/tally/issues
IMAGE=ghcr.io/sky-commons/tally-feed
# How long a started feeder has to say it is publishing before the install calls it failed; an
# automatic update (--upgrade) waits longer before it calls the new release failed and rolls back.
WAIT_SECONDS=20
UPGRADE_WAIT_SECONDS=90

# Who signs a release: this repository's release workflow, run on the release's own tag (cosign
# keyless, .github/workflows/release.yml), its certificate issued for GitHub Actions' token.
SIGNER_REPOSITORY=sky-commons/tally
SIGNER_ISSUER=https://token.actions.githubusercontent.com
# The cosign that checks the signatures, pinned by version and by each build's sha256 (from its
# release's cosign_checksums.txt). It is the trust anchor an automatic update checks the next
# release with, so moving it is a change to this script, itself signed.
COSIGN_VERSION=v2.6.5
COSIGN_SHA256_X86_64=c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644
COSIGN_SHA256_AARCH64=426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7
COSIGN_SHA256_ARMV7=5eeda8f80117783b03dcbaa7f74d0aeb52bd42218fa509274a0bf4c030802331
# The updater's files: cosign, the updater, the version installed, and its units.
LIB=/usr/local/lib/tally
COSIGN=$LIB/cosign
UPDATER=$LIB/update
INSTALLED=$LIB/installed
UPDATE_UNIT=/etc/systemd/system/tally-feed-update.service
UPDATE_TIMER=/etc/systemd/system/tally-feed-update.timer
TIMER=tally-feed-update.timer
# Where root's work directory goes: not /tmp, which the unprivileged units have one of their own of,
# so that they can read what root fetched.
WORK_ROOT=/var/cache

# Where receivers keep their location, read in this order (none is ever sourced: each is someone
# else's code).
ADSBIM_ENVS=(/opt/adsb/config/.env /opt/adsb/.env)
READSB_DEFAULTS=/etc/default/readsb
PIAWARE_ENV=/var/cache/piaware/location.env
DUMP1090_DEFAULTS=/etc/default/dump1090-fa
FEED_CLIENT_DEFAULTS=(/etc/default/adsbexchange /etc/default/adsbfi /etc/default/airplanes /etc/default/adsblol)

# What locating from an address asks (RFC-0204), and only then: the address goes to the geocoders
# alone, and the point they find to the elevation services; nothing goes to Tally.
CENSUS_GEOCODER=https://geocoding.geo.census.gov/geocoder/locations/onelineaddress
NOMINATIM=https://nominatim.openstreetmap.org/search
USGS_EPQS=https://epqs.nationalmap.gov/v1/json
OPEN_METEO_ELEVATION=https://api.open-meteo.com/v1/elevation
# Nominatim's usage policy asks for a User-Agent naming the application and a contact; it is asked
# once a run, well within its one request a second.
USER_AGENT="tally-install/$VERSION (+https://github.com/sky-commons/tally/issues)"
# The release's geoid grid (EGM2008, packaging/geoid), gzipped: N, the geoid's height above the
# WGS84 ellipsoid, to within 2 m on land.
GEOID=geoid.txt.gz
# Two geocoders placing an address further apart than this, metres, are shown as disagreeing.
AGREE_METRES=50
# The antenna's height above the ground, metres, by the answer to the one question asked.
ANTENNA_WINDOW=2
ANTENNA_UPSTAIRS=5
ANTENNA_ROOF=8

# The block of /etc/default/tally-feed this script owns.
MARK_BEGIN="# BEGIN install.sh: rewritten on every run of install.sh"
MARK_END="# END install.sh"
# The flags the block holds; anything else an older install.sh wrote into TALLY_FEED_ARGS is the
# owner's, and moves to TALLY_FEED_EXTRA.
OWNED_FLAGS=(--relay --lat --lon --alt --uat)
UAT=127.0.0.1:30978
# acars_router's TCP outputs, one a kind (AR_SERVE_TCP_ACARS, _VDLM2, _HFDL). Never added: message
# text is the owner's to publish (README.md, "--acars"), so a run says the flag to add instead.
ACARS=(127.0.0.1:15550 127.0.0.1:15555 127.0.0.1:15556)

say() { printf 'tally: %s\n' "$*"; }
stop() {
  printf 'tally: %s\n' "$*" >&2
  exit 1
}

# Runs COMMAND... as a throwaway unprivileged user (a transient unit with DynamicUser=, which can
# write nothing but a /tmp of its own and holds no capability), its standard output the caller's.
# Root runs curl and cosign this way; anyone else is unprivileged already.
unprivileged() {
  if [[ $EUID -ne 0 ]]; then
    "$@"
    return
  fi
  systemd-run --quiet --wait --pipe --collect -p Type=exec -p DynamicUser=yes \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateDevices=yes -p NoNewPrivileges=yes \
    -p CapabilityBoundingSet= -p 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
    -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes \
    --setenv=HOME=/tmp -- "$@"
}

# Downloads URL into FILE, as an unprivileged user; root only writes what it is handed.
fetch() {
  unprivileged curl -fsSL --proto '=https' --tlsv1.2 --retry 3 "$1" </dev/null >"$2"
}

sha256_of() {
  sha256sum "$1" | awk '{ print $1 }'
}

# Downloads NAME from the release with NAME.sha256 and NAME.sigstore.json beside it, into the work
# directory, and stops if NAME and its sha256 disagree. A NAME that cannot be downloaded stops saying
# WHY, if given. Its signature is checked once cosign is here (signed).
fetch_verified() {
  local name="$1"
  fetch "$release/$name" "$work/$name" || stop "${2:-could not download $release/$name}"
  fetch "$release/$name.sha256" "$work/$name.sha256" ||
    stop "could not download $release/$name.sha256"
  local expected
  expected="$(awk 'NR == 1 { print $1 }' "$work/$name.sha256")"
  if [[ -z $expected || $expected != "$(sha256_of "$work/$name")" ]]; then
    stop "$name does not match its sha256; nothing was installed"
  fi
  fetched+=("$name")
}

# Is FILE signed (FILE.sigstore.json beside it) by the release workflow of SIGNER_REPOSITORY run
# on the tag TAG? Checked by COSIGN as an unprivileged user.
signed_by_release() {
  local file="$1" tag="$2"
  unprivileged "$COSIGN" verify-blob "$file" --bundle "$file.sigstore.json" \
    --certificate-identity "https://github.com/$SIGNER_REPOSITORY/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer "$SIGNER_ISSUER" \
    --certificate-github-workflow-repository "$SIGNER_REPOSITORY" \
    --certificate-github-workflow-trigger push \
    --certificate-github-workflow-ref "refs/tags/$tag" </dev/null >/dev/null 2>&1
}

# Stops, having installed nothing of the release, unless every file fetched_verified fetched is
# signed by the release workflow on this release's tag, VERSION.
signed() {
  local name
  for name in "${fetched[@]}"; do
    fetch "$release/$name.sigstore.json" "$work/$name.sigstore.json" ||
      stop "could not download $release/$name.sigstore.json, $name's signature; nothing was installed"
    signed_by_release "$work/$name" "$VERSION" ||
      stop "$name is not signed by the release workflow of $SIGNER_REPOSITORY on the tag $VERSION (cosign verify-blob refused it); nothing was installed"
  done
  say "checked the signatures of ${fetched[*]}: the release workflow of $SIGNER_REPOSITORY on $VERSION"
}

# Installs SOURCE at TARGET with MODE in one rename, so nothing ever runs or reads half a file.
place() {
  local mode="$1" source="$2" target="$3"
  install -m "$mode" "$source" "$target.tally-new"
  mv -f "$target.tally-new" "$target"
}

# cosign's build for ARCH and its pinned sha256, as `NAME SHA256`.
cosign_build() {
  case "$ARCH" in
    x86_64) printf 'cosign-linux-amd64 %s' "$COSIGN_SHA256_X86_64" ;;
    aarch64) printf 'cosign-linux-arm64 %s' "$COSIGN_SHA256_AARCH64" ;;
    armv7) printf 'cosign-linux-arm %s' "$COSIGN_SHA256_ARMV7" ;;
  esac
}

# Puts the pinned cosign at COSIGN unless it is there already, checked by its sha256 before it is
# ever run.
install_cosign() {
  local name want
  read -r name want <<<"$(cosign_build)"
  if [[ -x $COSIGN && $(sha256_of "$COSIGN") == "$want" ]]; then
    return 0
  fi
  say "downloading cosign $COSIGN_VERSION, which checks the release's signatures"
  fetch "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/$name" "$work/cosign" ||
    stop "could not download cosign $COSIGN_VERSION ($name); nothing was installed"
  [[ $(sha256_of "$work/cosign") == "$want" ]] ||
    stop "cosign $COSIGN_VERSION ($name) does not match the sha256 this script pins; nothing was installed"
  install -d -m 0755 "$LIB"
  place 0755 "$work/cosign" "$COSIGN"
}

# Settles auto_update (1 or 0) and auto_update_from: --no-auto-update or TALLY_AUTO_UPDATE if
# given; else what an earlier install left (its timer enabled or not, which is how the owner turns
# it off); else on.
settle_auto_update() {
  local value="${TALLY_AUTO_UPDATE:-}"
  [[ -n $no_auto_update ]] && value=0
  case "${value,,}" in
    0 | no | off | false) auto_update=0 auto_update_from="you said so" ;;
    1 | yes | on | true) auto_update=1 auto_update_from="you said so" ;;
    "")
      if [[ -f $UPDATE_TIMER ]]; then
        auto_update=0
        systemctl is-enabled --quiet "$TIMER" 2>/dev/null && auto_update=1
        auto_update_from="the earlier install"
      else
        auto_update=1 auto_update_from="the default"
      fi
      ;;
    *) stop "TALLY_AUTO_UPDATE is 1 or 0, not $value; nothing was installed" ;;
  esac
}

# The lines that say whether automatic updates are on and how to change that.
auto_update_lines() {
  if [[ $auto_update == 1 ]]; then
    printf 'Automatic updates are on (%s): about once a day %s installs a newer release, only when
' "$auto_update_from" "$TIMER"
    printf 'it is signed by the release workflow of %s, never an older one, and puts the old one back
' "$SIGNER_REPOSITORY"
    printf 'if it does not start (journalctl -u tally-feed-update). To turn them off:
'
    printf '  sudo systemctl disable --now %s
' "$TIMER"
    printf 'or install with TALLY_AUTO_UPDATE=0. Running this script again keeps your choice.
'
  else
    printf 'Automatic updates are off (%s). To turn them on:
' "$auto_update_from"
    printf '  sudo systemctl enable --now %s
' "$TIMER"
    printf 'or install with TALLY_AUTO_UPDATE=1. Running this script again keeps your choice.
'
  fi
}

# Is anything listening on HOST PORT? bash's /dev/tcp, with a deadline. Only ever called with this
# script's own constants.
listening() {
  timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

require_root() {
  [[ $EUID -eq 0 ]] || stop "run as root: $(run_again "")"
}

# How to run this script again as root with the NAME=value words VARS, as sudo passes them in.
# Piped into bash it has no file of its own, so it says how to download it first.
run_again() {
  local self="${BASH_SOURCE[0]:-}"
  if [[ -z $self ]]; then
    printf 'curl -fsSL %s/install.sh -o /tmp/tally-install.sh && sudo %sbash /tmp/tally-install.sh' \
      "${release:-https://github.com/sky-commons/tally/releases/latest/download}" "${1:+$1 }"
  else
    printf 'sudo %sbash %s' "${1:+$1 }" "$self"
  fi
}

# Is there a terminal to ask on? With `curl | sudo bash` stdin is the script, so the questions go to
# /dev/tty, which exists only with a controlling terminal.
have_tty() {
  (exec </dev/tty) 2>/dev/null
}

# The owner's answer to PROMPT, from the terminal.
ask() {
  local answer=""
  printf '%s ' "$1" >/dev/tty
  IFS= read -r answer </dev/tty || true
  printf '%s' "$answer"
}

# The last NAME=value in FILE (- for stdin), unquoted, without sourcing the file.
value_of() {
  local file="$1" name="$2"
  [[ $file == - || -r $file ]] || return 0
  awk -v name="$name" '
    {
      line = $0
      sub(/^[ \t]*(export[ \t]+)?/, "", line)
      if (index(line, name "=") == 1) {
        value = substr(line, length(name) + 2)
        sub(/[ \t]+#.*$/, "", value)
        gsub(/^["'\'']|["'\'']$/, "", value)
        found = value
      }
    }
    END { if (found != "") print found }
  ' "$file"
}

# The value after FLAG (`--lat 1.5` or `--lat=1.5`, a number with an optional unit) in the text on
# stdin, the last one given.
flag_value() {
  grep -oE -- "${1}[ =]+-?[0-9]+(\.[0-9]+)?(m|ft)?" | tail -n 1 |
    grep -oE -- '-?[0-9]+(\.[0-9]+)?(m|ft)?$' || true
}

# The same, in FILE, as readsb-set-location writes it into /etc/default/readsb.
flag_in() {
  [[ -r $1 ]] || return 0
  flag_value "$2" <"$1"
}

# HOST:PORT=KEY, the key a 32-byte base64 public key.
is_relay() {
  [[ $1 =~ ^[^=[:space:]]+:[0-9]+=[A-Za-z0-9+/]{43}=$ ]]
}

# Reads the seed list FILE into seed_relays and seed_operators, one relay and its operator each,
# and stops, installing nothing, at the first entry that is not HOST:PORT=KEY followed by an
# operator, or when the list names no relay.
read_seeds() {
  local file="$1" number=0 line relay operator
  seed_relays=() seed_operators=()
  [[ -r $file ]] || stop "the seed list $file cannot be read; nothing was installed"
  while IFS= read -r line || [[ -n $line ]]; do
    number=$((number + 1))
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z $line || $line == \#* ]] && continue
    relay="${line%%[[:space:]]*}"
    operator="${line#"$relay"}"
    operator="${operator#"${operator%%[![:space:]]*}"}"
    operator="${operator%"${operator##*[![:space:]]}"}"
    is_relay "$relay" ||
      stop "$file line $number: $relay is not HOST:PORT=KEY; nothing was installed"
    [[ -n $operator ]] ||
      stop "$file line $number: $relay names no operator (HOST:PORT=KEY OPERATOR); nothing was installed"
    seed_relays+=("$relay")
    seed_operators+=("$operator")
  done <"$file"
  [[ ${#seed_relays[@]} -gt 0 ]] ||
    stop "the seed list $file names no relay to publish to; nothing was installed"
}

is_number() {
  [[ $1 =~ ^-?[0-9]+(\.[0-9]+)?$ ]]
}

# Is NUMBER within -LIMIT..LIMIT?
within() {
  is_number "$1" && awk -v value="$1" -v limit="$2" 'BEGIN { exit !(value >= -limit && value <= limit) }'
}

# Metres, whole, from "12", "12m", "12.5 m" or "40ft".
metres() {
  local text="${1// /}"
  local scale=1
  case "$text" in
    *ft) text="${text%ft}" scale=0.3048 ;;
    *m) text="${text%m}" ;;
  esac
  is_number "$text" && awk -v value="$text" -v scale="$scale" 'BEGIN { printf "%.0f", value * scale }'
}

# KEY (standard base64, as the key file and `tally-feed init` print it) as a station page's address
# carries it: base64url without padding.
base64url() {
  local key="${1//+/-}"
  key="${key//\//_}"
  printf '%s' "${key%%=*}"
}

# The first running container whose image is ultrafeeder's, by name; nothing if none or no docker.
ultrafeeder_container() {
  command -v docker >/dev/null || return 0
  timeout 5 docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null |
    awk '$2 ~ /ultrafeeder/ { print $1; exit }' || true
}

# The arguments of every running readsb, one a line (a containerised one's too: its process is the
# host's).
readsb_arguments() {
  command -v pgrep >/dev/null || return 0
  local pid
  for pid in $(pgrep -x readsb 2>/dev/null || true); do
    tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true
    printf '\n'
  done
}

# The TALLY_FEED_ARGS an earlier run wrote.
previous_arguments() {
  value_of "$DEFAULTS" TALLY_FEED_ARGS
}

# Each location source sets cand_lat, cand_lon and cand_alt (any may be empty) and cand_from, which
# names where they were read (cand_alt_from, if set, names where the altitude was).
from_env() {
  if [[ -n ${TALLY_LAT:-} || -n ${TALLY_LON:-} ]] && [[ -z ${TALLY_LAT:-} || -z ${TALLY_LON:-} ]]; then
    stop "TALLY_LAT and TALLY_LON go together; nothing was installed"
  fi
  cand_lat="${TALLY_LAT:-}" cand_lon="${TALLY_LON:-}" cand_alt="${TALLY_ALT:-}"
  cand_from="TALLY_LAT and TALLY_LON" cand_alt_from="TALLY_ALT"
}

from_adsbim() {
  local env
  for env in "${ADSBIM_ENVS[@]}"; do
    [[ -r $env ]] || continue
    cand_lat="$(value_of "$env" FEEDER_LAT)" cand_lon="$(value_of "$env" FEEDER_LONG)"
    cand_alt="$(value_of "$env" FEEDER_ALT_M)" cand_from="$env (FEEDER_LAT, FEEDER_LONG, FEEDER_ALT_M)"
    [[ -n $cand_lat ]] && return 0
    cand_lat="$(value_of "$env" READSB_LAT)" cand_lon="$(value_of "$env" READSB_LON)"
    cand_alt="$(value_of "$env" READSB_ALT)" cand_from="$env (READSB_LAT, READSB_LON, READSB_ALT)"
    [[ -n $cand_lat ]] && return 0
  done
  return 0
}

from_readsb() {
  cand_from="$READSB_DEFAULTS"
  cand_lat="$(value_of "$READSB_DEFAULTS" READSB_LAT)" cand_lon="$(value_of "$READSB_DEFAULTS" READSB_LON)"
  cand_alt="$(value_of "$READSB_DEFAULTS" READSB_ALT)"
  [[ -n $cand_lat ]] && return 0
  cand_lat="$(flag_in "$READSB_DEFAULTS" --lat)" cand_lon="$(flag_in "$READSB_DEFAULTS" --lon)"
  [[ -n $cand_lat ]] && return 0
  local running
  running="$(readsb_arguments)"
  [[ -n $running ]] || return 0
  cand_lat="$(flag_value --lat <<<"$running")" cand_lon="$(flag_value --lon <<<"$running")"
  cand_from="the running readsb's --lat and --lon"
}

from_piaware() {
  cand_lat="$(value_of "$PIAWARE_ENV" PIAWARE_LAT)" cand_lon="$(value_of "$PIAWARE_ENV" PIAWARE_LON)"
  cand_from="$PIAWARE_ENV"
}

from_dump1090() {
  cand_lat="$(value_of "$DUMP1090_DEFAULTS" RECEIVER_LAT)" cand_lon="$(value_of "$DUMP1090_DEFAULTS" RECEIVER_LON)"
  cand_from="$DUMP1090_DEFAULTS (RECEIVER_LAT, RECEIVER_LON)"
}

# A feed client's file holds LATITUDE, LONGITUDE and ALTITUDE. The first that holds anything
# answers; a later one may still give the altitude the first lacks (consider reads each).
from_feed_clients() {
  local file
  for file in "${FEED_CLIENT_DEFAULTS[@]}"; do
    [[ -r $file ]] || continue
    cand_lat="$(value_of "$file" LATITUDE)" cand_lon="$(value_of "$file" LONGITUDE)"
    cand_alt="$(value_of "$file" ALTITUDE)" cand_from="$file (LATITUDE, LONGITUDE, ALTITUDE)"
    consider
  done
  cand_lat="" cand_lon="" cand_alt=""
}

from_ultrafeeder() {
  local name env
  name="$(ultrafeeder_container)"
  [[ -n $name ]] || return 0
  env="$(timeout 5 docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$name" 2>/dev/null || true)"
  cand_lat="$(value_of - LAT <<<"$env")" cand_lon="$(value_of - LONG <<<"$env")"
  cand_alt="$(value_of - ALT <<<"$env")" cand_from="the $name container's LAT, LONG and ALT"
  if [[ -z $cand_lat ]]; then
    cand_lat="$(value_of - READSB_LAT <<<"$env")" cand_lon="$(value_of - READSB_LON <<<"$env")"
    cand_from="the $name container's READSB_LAT and READSB_LON"
  fi
}

from_previous() {
  local args
  args="$(previous_arguments)"
  [[ -n $args ]] || return 0
  cand_lat="$(flag_value --lat <<<"$args")" cand_lon="$(flag_value --lon <<<"$args")"
  cand_alt="$(flag_value --alt <<<"$args")" cand_from="the earlier install ($DEFAULTS)"
}

# Takes the candidate's location if none is settled yet and its altitude likewise. A discovered
# altitude of 0 is taken for "not set", as an unset one often reads; only TALLY_ALT can say 0.
consider() {
  if [[ -z $lat && -n $cand_lat && -n $cand_lon ]]; then
    if within "$cand_lat" 90 && within "$cand_lon" 180; then
      lat="$cand_lat" lon="$cand_lon" lat_from="$cand_from"
    else
      say "ignoring an unreadable location from $cand_from ($cand_lat, $cand_lon)"
    fi
  fi
  if [[ -z $alt && -n $cand_alt ]]; then
    local m from="${cand_alt_from:-$cand_from}"
    m="$(metres "$cand_alt")" || m=""
    if [[ -z $m ]]; then
      say "ignoring an unreadable altitude from $from ($cand_alt)"
    elif [[ $m == 0 && $from != TALLY_ALT ]]; then
      say "ignoring the altitude 0 in $from: it is what an unset altitude reads as"
    else
      alt="$m" alt_from="$from"
    fi
  fi
}

# The text on stdin with every byte but A-Z a-z 0-9 . _ ~ - written as %XX, for a URL's query.
urlencode() {
  local LC_ALL=C text char out="" i
  text="$(cat)"
  for ((i = 0; i < ${#text}; i++)); do
    char="${text:i:1}"
    case "$char" in
      [A-Za-z0-9._~-]) out+="$char" ;;
      *) out+="$(printf '%%%02X' "'$char")" ;;
    esac
  done
  printf '%s' "$out"
}

# Asks URL (whose query may hold the address) and writes the answer to FILE, as an unprivileged
# user. The URL reaches curl on its standard input, never on a command line, so no process list,
# journal line or shell history holds the address.
ask_service() {
  printf 'url = "%s"\n' "$1" |
    unprivileged curl -fsS --proto '=https' --tlsv1.2 --max-time 20 --retry 2 -A "$USER_AGENT" -K - >"$2" 2>/dev/null
}

# The first match's "LAT LON" in a Census geocoder answer on stdin.
census_point() {
  awk '
    { text = text $0 }
    END {
      if (!match(text, /"coordinates" *: *\{ *"x" *: *-?[0-9]+(\.[0-9]+)? *, *"y" *: *-?[0-9]+(\.[0-9]+)?/)) exit
      found = substr(text, RSTART, RLENGTH)
      sub(/.*"x" *: */, "", found)
      x = found; sub(/ *,.*/, "", x)
      y = found; sub(/.*: */, "", y)
      print y, x
    }'
}

# The first match's "LAT LON CC" (its country code, - for none) in a Nominatim answer on stdin.
nominatim_point() {
  awk '
    { text = text $0 }
    END {
      if (match(text, /"lat" *: *"-?[0-9]+(\.[0-9]+)?"/)) { lat = substr(text, RSTART, RLENGTH); sub(/.*: *"/, "", lat); sub(/"/, "", lat) }
      if (match(text, /"lon" *: *"-?[0-9]+(\.[0-9]+)?"/)) { lon = substr(text, RSTART, RLENGTH); sub(/.*: *"/, "", lon); sub(/"/, "", lon) }
      if (match(text, /"country_code" *: *"[a-z][a-z]"/)) { cc = substr(text, RSTART, RLENGTH); sub(/.*: *"/, "", cc); sub(/"/, "", cc) }
      if (lat != "" && lon != "") print lat, lon, (cc == "" ? "-" : cc)
    }'
}

# The ground's elevation, metres, in a USGS EPQS answer on stdin (a value it has no data for, as
# outside the US, is none).
epqs_metres() {
  awk '
    { text = text $0 }
    END {
      if (!match(text, /"value" *: *"?-?[0-9]+(\.[0-9]+)?/)) exit
      value = substr(text, RSTART, RLENGTH); sub(/.*: *"?/, "", value)
      if (value + 0 > -500 && value + 0 < 9000) print value
    }'
}

# The ground's elevation, metres, in an Open-Meteo elevation answer on stdin.
open_meteo_metres() {
  awk '
    { text = text $0 }
    END {
      if (!match(text, /"elevation" *: *\[ *-?[0-9]+(\.[0-9]+)?/)) exit
      value = substr(text, RSTART, RLENGTH); sub(/.*\[ */, "", value)
      if (value + 0 > -500 && value + 0 < 9000) print value
    }'
}

# Metres between LAT1 LON1 and LAT2 LON2 (haversine), whole.
metres_between() {
  awk -v a="$1" -v b="$2" -v c="$3" -v d="$4" 'BEGIN {
    r = 3.14159265358979 / 180
    h = sin((c - a) * r / 2) ^ 2 + cos(a * r) * cos(c * r) * sin((d - b) * r / 2) ^ 2
    printf "%.0f", 2 * 6371008.8 * atan2(sqrt(h), sqrt(1 - h))
  }'
}

# N, the geoid's height above the WGS84 ellipsoid at LAT LON, metres, from the EGM2008 grid on
# stdin (packaging/geoid: a global 2 degree grid with finer patches on land, read by bicubic
# interpolation, within 2 m of EGM2008 on land).
geoid_of() {
  awk -v lat="$1" -v lon="$2" '
/^# levels / { for (k = 3; k <= NF; k++) { nl++; Ls[nl] = $k } next }
/^#/ { next }
$1 == "A" { for (k = 0; k < $5; k++) cell[$3 + 0, $4 + k] = $2; next }
NF >= 4 {
  c = $3 + 0; v = $4 + 0; g[$1, $2 + 0, c] = v
  for (k = 5; k <= NF; k++) { v += $k; c++; g[$1, $2 + 0, c] = v }
}
function key(s, r, c) {
  if (r < 0) { r = -r; c += C / 2 } else if (r > R - 1) { r = 2 * (R - 1) - r; c += C / 2 }
  c = c % C; if (c < 0) c += C
  return s SUBSEP r SUBSEP c
}
function w(t, k) {
  if (k == 0) return ((-0.5 * t + 1) * t - 0.5) * t
  if (k == 1) return (1.5 * t - 2.5) * t * t + 1
  if (k == 2) return ((-1.5 * t + 2) * t + 0.5) * t
  return (0.5 * t - 0.5) * t * t
}
END {
  if (nl < 1) { print "geoid.awk: no levels line in the grid" > "/dev/stderr"; exit 2 }
  num = "^[-+]?([0-9]+[.]?[0-9]*|[.][0-9]+)$"
  if (lat !~ num || lon !~ num || lat + 0 > 90 || lat + 0 < -90) {
    print "geoid.awk: usage: awk -v lat=-90..90 -v lon=DEG -f geoid.awk geoid.txt" > "/dev/stderr"; exit 2
  }
  s = Ls[1]; sp = s / 60; CB = int(360 / sp + 0.5)
  bi = int((90 - lat) / sp); if (bi > 180 / sp - 1) bi = int(180 / sp + 0.5) - 1
  x = (lon + 180) / sp; x -= CB * int(x / CB); if (x < 0) x += CB
  bj = int(x); if (bj >= CB) bj = 0
  if ((bi, bj) in cell) s = cell[bi, bj]
  sp = s / 60; R = int(180 / sp + 0.5) + 1; C = int(360 / sp + 0.5)
  y = (90 - lat) / sp; i0 = int(y); if (i0 > R - 2) i0 = R - 2; fy = y - i0
  x = (lon + 180) / sp; x -= C * int(x / C); if (x < 0) x += C
  j0 = int(x); fx = x - j0
  for (a = 0; a < 4; a++) for (b = 0; b < 4; b++) {
    kk = key(s, i0 - 1 + a, j0 - 1 + b)
    if (!(kk in g)) { print "geoid.awk: grid file lacks node " kk > "/dev/stderr"; exit 2 }
    q[a, b] = g[kk]
  }
  n = 0
  for (a = 0; a < 4; a++) { t = 0; for (b = 0; b < 4; b++) t += w(fx, b) * q[a, b]; n += w(fy, a) * t }
  printf "%.2f\n", n / 10
}'
}

# The antenna's height above the ground, metres: TALLY_ANTENNA (window, upstairs, roof or metres),
# else asked on the terminal, else a window's. Sets antenna and antenna_from.
antenna_height() {
  local answer="${TALLY_ANTENNA:-}" from="TALLY_ANTENNA"
  if [[ -z $answer ]] && have_tty; then
    answer="$(ask "How high is the antenna? 1) by a window or on the ground floor (about ${ANTENNA_WINDOW} m), 2) upstairs (about ${ANTENNA_UPSTAIRS} m), 3) on the roof (about ${ANTENNA_ROOF} m), or its height above the ground in metres:")"
    from="your answer"
  fi
  case "${answer,,}" in
    1 | window | ground | "") antenna=$ANTENNA_WINDOW ;;
    2 | upstairs) antenna=$ANTENNA_UPSTAIRS ;;
    3 | roof) antenna=$ANTENNA_ROOF ;;
    *)
      antenna="$(metres "$answer")" || antenna=""
      if [[ -z $antenna ]] || ! within "$antenna" 1000; then
        say "ignoring the antenna height $answer; taking a window's, ${ANTENNA_WINDOW} m"
        antenna=$ANTENNA_WINDOW
      fi
      ;;
  esac
  if [[ -z $answer ]]; then
    from="assumed: name it with TALLY_ANTENNA=window, upstairs, roof or metres"
  fi
  antenna_from="$from"
}

# The one line that says where an address goes.
address_line() {
  printf 'The address goes only to the US Census geocoder and OpenStreetMap, and the place they find to USGS or Open-Meteo for its elevation; never to Tally. It is not stored: only the coordinates are.'
}

# Finds the location from ADDRESS (RFC-0204): sets lat and lon (and lat_from), and alt (and
# alt_from) unless one is settled already. False, saying why in `why`, when no geocoder finds it or
# the owner says it is not right; a location found with no elevation leaves alt for the questions.
locate_address() {
  local address="$1" query census="" osm="" cc="-" olat olon apart us="" ground="" ground_from=""
  local n answer geoid_sha
  why=""
  say "$(address_line)"
  query="$(printf '%s' "$address" | urlencode)"
  if ask_service "$CENSUS_GEOCODER?address=$query&benchmark=Public_AR_Current&format=json" "$work/census"; then
    census="$(census_point <"$work/census")"
  fi
  if ask_service "$NOMINATIM?q=$query&format=jsonv2&limit=1&addressdetails=1" "$work/nominatim"; then
    osm="$(nominatim_point <"$work/nominatim")"
  fi
  # Their answers repeat the address: gone at once.
  rm -f "$work/census" "$work/nominatim"
  if [[ -n $census ]]; then
    read -r lat lon <<<"$census"
    lat_from="the US Census geocoder" us=1
    if [[ -n $osm ]]; then
      read -r olat olon cc <<<"$osm"
      apart="$(metres_between "$lat" "$lon" "$olat" "$olon")"
      if ((apart > AGREE_METRES)); then
        say "the US Census geocoder and OpenStreetMap place it $apart m apart: using the Census geocoder's. Check it on the map below."
      else
        say "the US Census geocoder and OpenStreetMap agree, to $apart m"
      fi
    fi
  elif [[ -n $osm ]]; then
    read -r lat lon cc <<<"$osm"
    lat_from="OpenStreetMap Nominatim"
    [[ $cc == us ]] && us=1
  else
    why="neither the US Census geocoder nor OpenStreetMap found that address"
    lat="" lon=""
    return 1
  fi
  [[ -n $osm ]] && say "geocoding by OpenStreetMap Nominatim; data (c) OpenStreetMap contributors, ODbL 1.0 (https://osm.org/copyright)"
  lat="$(awk -v x="$lat" 'BEGIN { printf "%.6f", x }')"
  lon="$(awk -v x="$lon" 'BEGIN { printf "%.6f", x }')"
  if ! within "$lat" 90 || ! within "$lon" 180; then
    why="the geocoder gave an unreadable place"
    lat="" lon=""
    return 1
  fi
  say "found $lat, $lon from $lat_from: https://www.openstreetmap.org/?mlat=$lat&mlon=$lon#map=18/$lat/$lon"
  if have_tty; then
    answer="$(ask "Is that the antenna's place? [Y/n]")"
    if [[ ${answer,,} == n || ${answer,,} == no ]]; then
      why="you said that is not the place"
      lat="" lon=""
      return 1
    fi
  fi
  located_by_address=1
  [[ -z $alt ]] || return 0
  if [[ -n $us ]] && ask_service "$USGS_EPQS?x=$lon&y=$lat&units=Meters&wkid=4326&includeDate=false" "$work/elevation"; then
    ground="$(epqs_metres <"$work/elevation")" ground_from="USGS 3DEP"
  fi
  if [[ -z $ground ]] && ask_service "$OPEN_METEO_ELEVATION?latitude=$lat&longitude=$lon" "$work/elevation"; then
    ground="$(open_meteo_metres <"$work/elevation")" ground_from="Copernicus DEM, by Open-Meteo"
  fi
  if [[ -z $ground ]]; then
    say "no elevation service answered for $lat, $lon; the altitude is asked for instead"
    return 0
  fi
  # The geoid grid, checked against its sha256 here and against its signature with the release's
  # other files (`signed`), before anything is installed.
  if ! command -v gzip >/dev/null || ! fetch "$release/$GEOID" "$work/$GEOID" ||
    ! fetch "$release/$GEOID.sha256" "$work/$GEOID.sha256"; then
    say "could not read the release's geoid grid ($GEOID); the altitude is asked for instead"
    return 0
  fi
  geoid_sha="$(awk 'NR == 1 { print $1 }' "$work/$GEOID.sha256")"
  if [[ -z $geoid_sha || $geoid_sha != "$(sha256_of "$work/$GEOID")" ]] ||
    ! n="$(gzip -dc "$work/$GEOID" | geoid_of "$lat" "$lon")" || [[ -z $n ]]; then
    say "the release's geoid grid ($GEOID) does not match its sha256; the altitude is asked for instead"
    return 0
  fi
  fetched+=("$GEOID")
  antenna_height
  alt="$(awk -v g="$ground" -v a="$antenna" -v n="$n" 'BEGIN { printf "%.0f", g + a + n }')"
  alt_from="the ground, $(awk -v g="$ground" 'BEGIN { printf "%.1f", g }') m ($ground_from), the antenna, $antenna m above it ($antenna_from), and the geoid, $n m (EGM2008): metres above the WGS84 ellipsoid"
}

# When the location came from an address and readsb has none of its own, offers (on the terminal
# only) to set readsb's --lat and --lon in /etc/default/readsb too. Sets readsb_location when the
# owner says yes; nothing is changed until the feeder is installed (`set_readsb_location`).
offer_readsb_location() {
  readsb_location=""
  [[ -n ${located_by_address:-} && -f $READSB_DEFAULTS ]] || return 0
  have_tty || return 0
  [[ -z $(value_of "$READSB_DEFAULTS" READSB_LAT) && -z $(flag_in "$READSB_DEFAULTS" --lat) ]] || return 0
  # Only a layout this script can edit for sure: DECODER_OPTIONS="..." on one line.
  grep -qE '^DECODER_OPTIONS="[^"]*"[[:space:]]*$' "$READSB_DEFAULTS" || return 0
  local answer
  answer="$(ask "readsb has no location of its own. Set --lat $lat --lon $lon in $READSB_DEFAULTS too (the old file is kept beside it)? [y/N]")"
  [[ ${answer,,} == y || ${answer,,} == yes ]] && readsb_location=1
  return 0
}

# Sets readsb's --lat and --lon when the owner said so (`offer_readsb_location`), keeping the old
# file beside it, and restarts readsb if it runs.
set_readsb_location() {
  [[ -n ${readsb_location:-} ]] || return 0
  local backup tmp
  backup="$READSB_DEFAULTS.tally-backup.$(date +%Y%m%d%H%M%S)"
  cp -p "$READSB_DEFAULTS" "$backup"
  tmp="$(mktemp "$READSB_DEFAULTS.XXXXXX")"
  awk -v add="--lat $lat --lon $lon" '
    !done && /^DECODER_OPTIONS="[^"]*"[[:space:]]*$/ {
      value = $0
      sub(/^DECODER_OPTIONS="/, "", value)
      sub(/"[[:space:]]*$/, "", value)
      print "DECODER_OPTIONS=\"" (value == "" ? "" : value " ") add "\""
      done = 1
      next
    }
    { print }
  ' "$READSB_DEFAULTS" >"$tmp"
  chmod --reference="$READSB_DEFAULTS" "$tmp" 2>/dev/null || chmod 0644 "$tmp"
  mv -f "$tmp" "$READSB_DEFAULTS"
  if systemctl is-active --quiet readsb.service 2>/dev/null; then
    systemctl restart readsb.service || true
  fi
  say "set readsb's location in $READSB_DEFAULTS; the old file is $backup"
}

# Settles lat, lon and alt (whole metres), and lat_from and alt_from, from the sources in order.
# With MODE ask, what none holds is asked for on the terminal, or the install stops; with MODE
# quiet, it stays empty. With MODE ask and an address to locate from (TALLY_ADDRESS, or --locate),
# the location is the address's (only TALLY_ALT is still read), and when no source holds one an
# address is asked for first.
discover_location() {
  local mode="$1" source address="" sources=(env adsbim readsb piaware dump1090 feed_clients ultrafeeder previous)
  lat="" lon="" alt="" lat_from="" alt_from="" located_by_address=""
  local locating=""
  if [[ $mode == ask && ( -n ${TALLY_ADDRESS:-} || -n ${locate:-} ) ]]; then
    if [[ -n ${TALLY_LAT:-} || -n ${TALLY_LON:-} ]]; then
      stop "TALLY_ADDRESS (or --locate) and TALLY_LAT and TALLY_LON each give the location: give one; nothing was installed"
    fi
    locating=1 address="${TALLY_ADDRESS:-}" sources=(env)
  fi
  for source in "${sources[@]}"; do
    cand_lat="" cand_lon="" cand_alt="" cand_from="" cand_alt_from=""
    "from_$source"
    consider
  done
  [[ $mode == ask ]] || return 0

  if [[ -z $lat && -z $locating ]] && have_tty; then
    say "found no receiver location; multilateration needs the antenna's own."
    address="$(ask "The antenna's street address (or press Enter to type its coordinates instead):")"
    [[ -n $address ]] && locating=1
  elif [[ -n $locating && -z $address ]]; then
    have_tty || stop "--locate asks for the antenna's address on the terminal, and there is none: name it with $(run_again 'TALLY_ADDRESS="..."'). Nothing was installed."
    address="$(ask "The antenna's street address:")"
  fi
  if [[ -n $locating ]] && ! locate_address "$address"; then
    have_tty || stop "could not find the location from the address: $why. Name it instead and run this again: $(run_again "TALLY_LAT=51.4775 TALLY_LON=-0.4614 TALLY_ALT=25") (TALLY_ALT in metres above the WGS84 ellipsoid). Nothing was installed."
    say "could not find the location from the address: $why. Type the coordinates instead."
  fi
  address=""

  if [[ -z $lat ]]; then
    have_tty || stop "found no receiver location (in TALLY_LAT and TALLY_LON, adsb.im, readsb, PiAware, dump1090-fa, a feed client or an ultrafeeder container). Name it and run this again: $(run_again "TALLY_LAT=51.4775 TALLY_LON=-0.4614 TALLY_ALT=25") (TALLY_ALT in metres, or with ft). Nothing was installed."
    say "found no receiver location; multilateration needs the antenna's own."
    until within "$lat" 90; do lat="$(ask "Antenna latitude, decimal degrees (e.g. 51.4775):")"; done
    until within "$lon" 180; do lon="$(ask "Antenna longitude, decimal degrees, west negative (e.g. -0.4614):")"; done
    lat_from="the terminal"
  fi
  if [[ -z $alt ]]; then
    have_tty || stop "found the location ($lat, $lon from $lat_from) but no altitude, and multilateration needs a real one. Name it and run this again: $(run_again TALLY_ALT=25) (metres above the WGS84 ellipsoid, or with ft; sea level is what most setups give). Nothing was installed."
    local answer=""
    until [[ -n $alt ]]; do
      answer="$(ask "Antenna altitude, metres above the WGS84 ellipsoid (or e.g. 80ft):")"
      alt="$(metres "$answer")" || alt=""
    done
    alt_from="the terminal"
  fi
}

# The one line that says who sees the location. Nothing is asked: the feed always carries it
# exactly to relays, which multilateration needs, and no client is ever sent it.
privacy_line() {
  printf 'Your exact location goes only to Tally relays, for MLAT. Nothing a data user reads contains it; public maps show only the %s area.' "$PUBLIC_AREA"
}

# This machine's build of tally-feed, by its userland (a 32-bit Raspberry Pi OS on a 64-bit kernel
# reports aarch64 from uname -m, but runs only 32-bit programs). Sets ARCH.
detect_arch() {
  local userland="" machine bits=""
  machine="$(uname -m)"
  if command -v dpkg >/dev/null; then
    userland="$(dpkg --print-architecture 2>/dev/null || true)"
  fi
  if [[ -z $userland ]]; then
    bits="$(getconf LONG_BIT 2>/dev/null || true)"
    userland="$machine"
    if [[ $bits == 32 ]]; then
      case "$machine" in
        aarch64 | arm64 | armv8*) userland=armhf ;;
        x86_64 | amd64) userland=i386 ;;
      esac
    fi
  fi
  case "$userland" in
    amd64 | x86_64) ARCH=x86_64 ;;
    arm64 | aarch64) ARCH=aarch64 ;;
    armhf | armv7l | armv8l)
      # armhf on a Pi Zero or Pi 1 is an ARMv6 CPU, which an ARMv7 build cannot run.
      if [[ $machine == armv6* ]]; then
        stop "this is a 32-bit ARMv6 system (a Raspberry Pi Zero or 1): 32-bit systems are not supported yet. Nothing was installed."
      fi
      ARCH=armv7
      ;;
    *) stop "this is a $userland system ($machine): only 64-bit x86_64 and aarch64 are supported yet, and 32-bit systems are not. Nothing was installed." ;;
  esac
}

# Stops unless this release publishes ARCH's build: a 32-bit one it may not.
require_published_arch() {
  [[ $ARCH != armv7 ]] && return 0
  fetch "$release/tally-feed-$ARCH-linux.sha256" "$work/probe" 2>/dev/null ||
    stop "this is a 32-bit ARM system, and this release has no 32-bit build (tally-feed-$ARCH-linux): 32-bit systems are not supported yet. Nothing was installed."
}

# WHY, and how to pass the release and the seed list by hand. Until a release pipeline publishes
# Tally's releases (RFC-0180 phase 1), nothing writes PUBLISHED_RELEASE into this script or
# publishes a `seeds` beside it, so an install names both itself. sudo passes a NAME=value given
# before the command into its environment.
how_to_pass() {
  printf '%s. Until a release pipeline publishes them, name the release (a directory holding tally-feed-x86_64-linux, tally-feed-aarch64-linux and tally-feed.service, each with its .sha256 and its .sigstore.json, as the release workflow signs them) and a seed list file (one HOST:PORT=KEY OPERATOR a line) yourself:\n  sudo TALLY_RELEASE=RELEASE TALLY_SEEDS=/path/to/seeds bash /tmp/tally-install.sh\nNothing was installed.' "$1"
}

# Prints the compose service that feeds from the ultrafeeder container NAME, configured as
# packaging/README.md ("Run it as a container") says, with the location found (or placeholders),
# and installs nothing.
container_route() {
  local name="$1" volume=./tally-feed
  [[ -d ${ADSBIM_ENVS[0]%/*} ]] && volume=/opt/adsb/tally-feed
  say "nothing answers on 127.0.0.1:30005 here, but the container $name (ultrafeeder) is running:"
  say "its BEAST output is inside docker, so a feeder on the host would feed nothing."
  say "Run tally-feed as a container beside it instead. Nothing was installed."
  printf '\nAdd this service to the compose file that runs %s, then run docker compose up -d:\n\n' "$name"
  printf '  tally-feed:\n'
  printf '    image: %s:0\n' "$IMAGE"
  printf '    container_name: tally-feed\n'
  printf '    restart: unless-stopped\n'
  printf '    environment:\n'
  printf '      - BEASTHOST=%s\n' "$name"
  printf '      - LAT=%s\n' "${lat:-LATITUDE}"
  printf '      - LONG=%s\n' "${lon:-LONGITUDE}"
  printf '      - ALT=%s\n' "${alt:+${alt}m}"
  printf '    volumes:\n'
  printf '      - %s:/var/lib/tally-feed\n\n' "$volume"
  if [[ -n $lat ]]; then
    printf 'The location is %s, %s, from %s. ' "$lat" "$lon" "$lat_from"
  else
    printf 'No location was found: fill in LATITUDE and LONGITUDE (degrees). '
  fi
  if [[ -n $alt ]]; then
    printf 'The altitude is %s m, from %s.\n' "$alt" "$alt_from"
  else
    printf 'No altitude was found: fill in ALT=, the antenna'\''s, as 15m or 45ft (MLAT needs a real one).\n'
  fi
  printf '%s\n' "$(privacy_line)"
  printf 'The feeder makes its key in that volume (keep it: it is the station'\''s name for good), and\n'
  printf 'docker logs tally-feed shows its public key and station page. More, in "Run it as a container":\n'
  printf '  https://github.com/sky-commons/tally/blob/main/packaging/README.md#run-it-as-a-container\n'
}

# Writes /etc/default/tally-feed with ARGS as the block this script owns. A file with the block
# keeps everything outside it; an older install.sh's file (TALLY_FEED_ARGS alone) keeps every flag
# of it this script does not own, moved into TALLY_FEED_EXTRA, and every other setting line.
write_defaults() {
  local managed="$*" block tmp
  block="$work/block"
  {
    printf '%s\n' "$MARK_BEGIN"
    printf '# with what it found: run it again to change them (TALLY_LAT, TALLY_LON, TALLY_ALT).\n'
    printf '# Location from %s, altitude from %s.\n' "$lat_from" "$alt_from"
    printf '# The relays come from the seed list %s, each run by:\n' "$seeds_from"
    local n
    for n in "${!seed_relays[@]}"; do
      printf '#   %s  %s\n' "${seed_relays[n]%%=*}" "${seed_operators[n]}"
    done
    printf 'TALLY_FEED_ARGS="%s"\n' "$managed"
    printf '%s\n' "$MARK_END"
  } >"$block"
  tmp="$(mktemp "$DEFAULTS.XXXXXX")"
  if [[ -f $DEFAULTS ]] && grep -qxF "$MARK_BEGIN" "$DEFAULTS" && grep -qxF "$MARK_END" "$DEFAULTS"; then
    awk -v begin="$MARK_BEGIN" -v end="$MARK_END" -v block="$block" '
      $0 == begin { while ((getline line < block) > 0) print line; skipping = 1; next }
      $0 == end && skipping { skipping = 0; next }
      !skipping { print }
    ' "$DEFAULTS" >"$tmp"
    grep -q '^TALLY_FEED_EXTRA=' "$tmp" || printf 'TALLY_FEED_EXTRA=""\n' >>"$tmp"
  else
    local extra=""
    if [[ -f $DEFAULTS ]]; then
      extra="$(legacy_extra "$(previous_arguments)")"
      say "moving the flags of your own in $DEFAULTS into TALLY_FEED_EXTRA: ${extra:-none}"
    fi
    {
      printf '# Arguments for tally-feed, read by tally-feed.service; tally-feed --help lists them.\n'
      printf '# install.sh owns the block between its BEGIN and END lines and rewrites it on every run.\n'
      printf '# Your own flags go in TALLY_FEED_EXTRA, which it keeps. They come after the block'\''s, so\n'
      printf '# for a flag given once (--lat, --alt) yours wins over what it found.\n'
      cat "$block"
      printf 'TALLY_FEED_EXTRA="%s"\n' "$extra"
      if [[ -f $DEFAULTS ]]; then
        grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*(export[[:space:]]+)?TALLY_FEED_ARGS=' "$DEFAULTS" || true
      fi
    } >"$tmp"
  fi
  chmod 0644 "$tmp"
  mv -f "$tmp" "$DEFAULTS"
  local own
  own="$(value_of "$DEFAULTS" TALLY_FEED_EXTRA)"
  if grep -qE -- '--(lat|lon|alt)([ =]|$)' <<<"$own"; then
    say "note: TALLY_FEED_EXTRA in $DEFAULTS sets $(grep -oE -- '--(lat|lon|alt)' <<<"$own" | sort -u | tr '\n' ' ')itself, which wins over what this script found"
  fi
}

# The flags of an older install.sh's TALLY_FEED_ARGS that are the owner's: every flag this script
# does not own, a --relay the seed list does not name, a --uat other than the local dump978.
legacy_extra() {
  local -a words out=()
  read -ra words <<<"$1"
  local i=0 word flag value owned seed
  while ((i < ${#words[@]})); do
    word="${words[i]}"
    flag="${word%%=*}" value=""
    owned=""
    for seed in "${OWNED_FLAGS[@]}"; do [[ $flag == "$seed" ]] && owned=1; done
    if [[ -z $owned ]]; then
      out+=("$word")
      i=$((i + 1))
      continue
    fi
    if [[ $word == *=* && $flag != "$word" ]]; then
      value="${word#*=}"
      i=$((i + 1))
    else
      value="${words[i + 1]:-}"
      i=$((i + 2))
    fi
    case "$flag" in
      --relay)
        local seeded=""
        for seed in "${seed_relays[@]}"; do [[ $value == "$seed" ]] && seeded=1; done
        [[ -n $seeded ]] || out+=(--relay "$value")
        ;;
      --uat) [[ $value == "$UAT" ]] || out+=(--uat "$value") ;;
    esac
  done
  printf '%s' "${out[*]}"
}

# Waits up to WAIT_SECONDS for the started feeder to be active and say it is publishing (its
# "tally-feed: publishing to RELAY" line), reading only this start's journal. Sets log.
wait_until_publishing() {
  local deadline=$((SECONDS + WAIT_SECONDS)) invocation
  log=""
  while :; do
    if systemctl is-active --quiet tally-feed.service; then
      invocation="$(systemctl show -p InvocationID --value tally-feed.service 2>/dev/null || true)"
      if [[ -n $invocation ]]; then
        log="$(journalctl -q --no-pager -o cat "_SYSTEMD_INVOCATION_ID=$invocation" 2>/dev/null || true)"
        grep -q '^tally-feed: publishing to ' <<<"$log" && return 0
      fi
    fi
    ((SECONDS < deadline)) || return 1
    sleep 1
  done
}

uninstall() {
  local purge="$1" public="" answer
  require_root
  command -v systemctl >/dev/null || stop "systemctl is required"
  if [[ -n $purge && -f $KEY ]]; then
    [[ -x $BIN ]] && public="$("$BIN" init --key "$KEY" 2>/dev/null || true)"
    printf 'tally: --purge deletes %s, this receiver'\''s identity%s.\n' "$KEY" "${public:+ ($public)}" >&2
    printf 'tally: It is gone for good: no one can restore it, and a new install is a new station with\n' >&2
    printf 'tally: none of this one'\''s history. Without --purge the key is kept.\n' >&2
    if have_tty; then
      answer="$(ask "Type delete to delete it:")"
      [[ $answer == delete ]] || stop "nothing was removed"
    fi
  fi
  if [[ -f $UPDATE_TIMER ]]; then
    systemctl disable --now "$TIMER" >/dev/null 2>&1 || true
  fi
  if [[ -f $UNIT ]]; then
    systemctl disable --now tally-feed.service >/dev/null 2>&1 || true
  fi
  rm -f -- "$UNIT" "$UPDATE_UNIT" "$UPDATE_TIMER"
  rm -rf -- "$STATE_PRIVATE" "$STATE" "$LIB"
  systemctl daemon-reload
  systemctl reset-failed tally-feed.service tally-feed-update.service >/dev/null 2>&1 || true
  rm -f -- "$BIN" "$DEFAULTS"
  say "removed tally-feed.service, its updater ($TIMER, $LIB), $BIN, $DEFAULTS and what it learned ($STATE)"
  if [[ -n $purge ]]; then
    rm -f -- "$KEY"
    rmdir -- "${KEY%/*}" 2>/dev/null || true
    say "deleted $KEY: this receiver's identity is gone"
  elif [[ -f $KEY ]]; then
    say "kept $KEY, this receiver's identity: installing again is the same station (--uninstall --purge deletes it)"
  fi
}

# Everything runs from here, once the whole script has arrived: a download cut short runs nothing.
main() {
  case "${1:-}" in
    --check-seeds)
      [[ $# -eq 2 ]] || stop "usage: install.sh --check-seeds FILE"
      read_seeds "$2"
      local n
      for n in "${!seed_relays[@]}"; do
        printf '%s\t%s\n' "${seed_relays[n]}" "${seed_operators[n]}"
      done
      return 0
      ;;
    --uninstall)
      case "$*" in
        --uninstall) uninstall "" ;;
        "--uninstall --purge") uninstall purge ;;
        *) stop "usage: install.sh --uninstall [--purge]" ;;
      esac
      return 0
      ;;
  esac
  no_auto_update="" upgrade="" locate=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-auto-update) no_auto_update=1 ;;
      --upgrade) upgrade=1 ;;
      --locate) locate=1 ;;
      *) stop "unknown argument $1 (install.sh takes none, --locate, --no-auto-update, --upgrade, --uninstall [--purge] or --check-seeds FILE)" ;;
    esac
    shift
  done
  # An automatic update asks nothing (it has no one to ask), never locates (it keeps the location
  # the install has), and gives the new feeder longer.
  if [[ -n $upgrade ]]; then
    have_tty() { false; }
    WAIT_SECONDS=$UPGRADE_WAIT_SECONDS
    locate=""
    unset TALLY_ADDRESS
  fi
  umask 022

  # Where it installs from and the relays it starts from are settled first, before root is asked
  # for: neither needs it, and an owner told what to pass is told before anything else.
  release="${TALLY_RELEASE:-$PUBLISHED_RELEASE}"
  release="${release%/}"
  if [[ -z $release ]]; then
    stop "$(how_to_pass "this install.sh names no release to install from")"
  fi
  for tool in curl sha256sum timeout awk; do
    command -v "$tool" >/dev/null || stop "$tool is required"
  done
  # Root's work directory is readable by the unprivileged cosign that checks what is in it.
  if [[ $EUID -eq 0 ]]; then
    work="$(mktemp -d "$WORK_ROOT/tally-install.XXXXXX")"
    chmod 0755 "$work"
  else
    work="$(mktemp -d)"
  fi
  trap 'rm -rf "$work"' EXIT
  fetched=()

  # A feeder that knows no relay publishes nothing, so this is settled before anything is installed.
  if [[ -n ${TALLY_SEEDS:-} ]]; then
    seeds="$TALLY_SEEDS" seeds_from="$TALLY_SEEDS"
  else
    fetch_verified seeds "$(how_to_pass "could not download the seed list $release/seeds")"
    seeds="$work/seeds" seeds_from="$release/seeds"
  fi
  read_seeds "$seeds"

  require_root
  for tool in systemctl systemd-run; do
    command -v "$tool" >/dev/null || stop "$tool is required"
  done
  settle_auto_update

  detect_arch
  require_published_arch

  systemd_version="$(systemctl --version | awk 'NR == 1 { print $2 }')"
  systemd_version="${systemd_version%%[!0-9]*}"
  if [[ -z $systemd_version || $systemd_version -lt $SYSTEMD_AT_LEAST ]]; then
    stop "systemd $SYSTEMD_AT_LEAST or later is required (this system has ${systemd_version:-unknown}). Nothing was installed."
  fi

  local beast="" container
  if listening 127.0.0.1 30005; then
    beast=1
  elif [[ -z $upgrade ]]; then
    container="$(ultrafeeder_container)"
    if [[ -n $container ]]; then
      discover_location quiet
      container_route "$container"
      return 0
    fi
  fi

  # Every question is asked, and every refusal made, before anything is installed.
  discover_location ask
  offer_readsb_location
  say "location $lat, $lon from $lat_from"
  say "altitude $alt m from $alt_from"
  say "$(privacy_line)"

  say "downloading tally-feed $VERSION for $ARCH"
  fetch_verified "tally-feed-$ARCH-linux"
  fetch_verified "tally-feed.service"
  fetch_verified "tally-feed-update.service"
  fetch_verified "tally-feed-update.timer"
  fetch_verified "update.sh"
  # Nothing of the release is installed or run before every file of it is checked.
  install_cosign
  signed

  args=()
  for n in "${!seed_relays[@]}"; do
    say "starting from ${seed_relays[n]%%=*}, run by ${seed_operators[n]}"
    args+=(--relay "${seed_relays[n]}")
  done
  if [[ -n $beast ]]; then
    say "found BEAST (1090 MHz) on 127.0.0.1:30005"
  else
    say "nothing on 127.0.0.1:30005 yet; tally-feed will keep trying it (readsb's BEAST output)"
  fi
  if listening 127.0.0.1 30978; then
    say "found dump978 (978 MHz UAT) on $UAT"
    args+=(--uat "$UAT")
  fi
  for acars in "${ACARS[@]}"; do
    if listening 127.0.0.1 "${acars##*:}"; then
      say "found acars_router (ACARS, VDL2 or HFDL) on $acars; to publish its messages, which can carry personal data, add --acars $acars to TALLY_FEED_EXTRA in $DEFAULTS"
    fi
  done
  args+=(--lat "$lat" --lon "$lon" --alt "$alt")

  place 0755 "$work/tally-feed-$ARCH-linux" "$BIN"
  install -d -m 0755 "${KEY%/*}"
  if [[ ! -f $KEY ]]; then
    say "making this receiver's key, $KEY (keep it: it is the antenna's name forever)"
  fi
  public="$(umask 077 && "$BIN" init --key "$KEY")"
  chown root:root "$KEY"
  chmod 0600 "$KEY"

  write_defaults "${args[@]}"

  place 0644 "$work/tally-feed.service" "$UNIT"
  # The updater is installed either way, so turning it on later is one systemctl.
  install -d -m 0755 "$LIB"
  place 0755 "$work/update.sh" "$UPDATER"
  place 0644 "$work/tally-feed-update.service" "$UPDATE_UNIT"
  place 0644 "$work/tally-feed-update.timer" "$UPDATE_TIMER"
  printf '%s\n' "$VERSION" >"$work/installed"
  place 0644 "$work/installed" "$INSTALLED"
  systemctl daemon-reload
  systemctl enable tally-feed.service >/dev/null
  if [[ $auto_update == 1 ]]; then
    systemctl enable --now "$TIMER" >/dev/null 2>&1
  else
    systemctl disable --now "$TIMER" >/dev/null 2>&1 || true
  fi
  systemctl restart tally-feed.service

  say "started tally-feed; waiting up to ${WAIT_SECONDS} s for it to publish"
  if ! wait_until_publishing; then
    printf '\n' >&2
    if systemctl is-active --quiet tally-feed.service; then
      say "tally-feed is running but has not reached a relay in ${WAIT_SECONDS} s. Its log:" >&2
    else
      say "tally-feed did not start. Its log:" >&2
    fi
    journalctl -u tally-feed.service -n 30 --no-pager >&2 || true
    printf '\nNext: tally-feed keeps trying on its own. Watch it with journalctl -u tally-feed -f; it is\n' >&2
    printf 'feeding once it says "publishing to". If it never does, the lines above say why (a\n' >&2
    printf 'firewall blocking outbound TCP to %s, say). Fix that and run this again,\n' "${seed_relays[*]%%=*}" >&2
    printf 'or open an issue with those lines: %s\n\n' "$ISSUES" >&2
    auto_update_lines >&2
    exit 1
  fi
  if ! grep -q '^tally-feed: reading ' <<<"$log"; then
    say "note: it has not read 127.0.0.1:30005 yet, so it has nothing to publish until readsb (or"
    say "dump1090-fa) serves BEAST there; it keeps trying"
  fi
  set_readsb_location

  printf '\ntally-feed %s is installed and publishing (systemctl status tally-feed; journalctl -u tally-feed).\n' \
    "$VERSION"
  printf "\nThis receiver's public key, its name on the network:\n\n  %s\n" "$public"
  printf "\nIts station page, once the network holds its first receptions:\n\n  %s/%s\n\n" "$STATION_PAGE" "$(base64url "$public")"
  printf "What it publishes, in open data anyone can read: every reception this receiver's decoders\n"
  printf 'report, signed with that key.\n%s\n' "$(privacy_line)"
  printf 'To change the location, run this again with --locate (it asks for the address), or with\n'
  printf 'TALLY_LAT, TALLY_LON and TALLY_ALT.\n\n'
  auto_update_lines
}

# Run, unless sourced (the installer's tests source it to call its parts). Piped into bash,
# BASH_SOURCE is empty.
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
