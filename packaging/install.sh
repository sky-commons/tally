#!/usr/bin/env bash
# Installs the Tally feeder on a receiver (RFC-0171 §3.5):
#
#   curl -fsSL <release>/install.sh | sudo bash
#
# Until a release pipeline publishes Tally's releases (RFC-0180 phase 1), nothing writes the
# release's address into this script (PUBLISHED_RELEASE) or publishes a seed list beside it, so an
# install names both itself:
#
#   curl -fsSL <release>/install.sh | sudo TALLY_RELEASE=<release> TALLY_SEEDS=/path/to/seeds bash
#
# It downloads tally-feed for this machine and checks its sha256, finds the receiver's decoders and
# location, makes the receiver's key if there is none, and starts tally-feed.service. It changes no
# readsb or dump978 setting and no other feed. Running it again upgrades the binary and keeps the
# key and /etc/default/tally-feed as they are.
#
# It installs no updater and no timer: tally-feed never updates itself. A newer version is this
# script again, run by the owner.
#
# The location comes from TALLY_LAT, TALLY_LON and TALLY_ALT (metres) if set, else from readsb's or
# an ultrafeeder / adsb.im configuration. It is published exactly unless TALLY_PRECISION (metres)
# is set, or --precision is added to /etc/default/tally-feed afterwards.
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
set -euo pipefail

VERSION="v0.2.0"
# Where this release is published, whose `tally-feed` binaries, unit and seed list this script
# installs. The source names no publisher: the publisher writes its release's address here when it
# publishes it, and TALLY_RELEASE overrides it.
PUBLISHED_RELEASE=""
BIN=/usr/local/bin/tally-feed
KEY=/etc/tally/key
DEFAULTS=/etc/default/tally-feed
UNIT=/etc/systemd/system/tally-feed.service
# The unit's LoadCredential and %d need this systemd or later.
SYSTEMD_AT_LEAST=248

say() { printf 'tally: %s\n' "$*"; }
stop() {
  printf 'tally: %s\n' "$*" >&2
  exit 1
}

fetch() {
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1"
}

# Downloads NAME from the release with NAME.sha256 beside it, into the work directory, and stops if
# they disagree. A NAME that cannot be downloaded stops saying WHY, if given.
fetch_verified() {
  local name="$1"
  fetch "$release/$name" "$work/$name" || stop "${2:-could not download $release/$name}"
  fetch "$release/$name.sha256" "$work/$name.sha256" ||
    stop "could not download $release/$name.sha256"
  local expected actual
  expected="$(awk 'NR == 1 { print $1 }' "$work/$name.sha256")"
  actual="$(sha256sum "$work/$name" | awk '{ print $1 }')"
  if [[ -z $expected || $expected != "$actual" ]]; then
    stop "$name does not match its sha256; nothing was installed"
  fi
}

# Is anything listening on HOST PORT? bash's /dev/tcp, with a deadline. Only ever called with this
# script's own constants.
listening() {
  timeout 2 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

# The last NAME=value in FILE, unquoted, without sourcing the file (it is someone else's code).
value_of() {
  local file="$1" name="$2"
  [[ -r $file ]] || return 0
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

# The value after FLAG (`--lat 1.5` or `--lat=1.5`) anywhere in FILE, as readsb-set-location writes
# it into /etc/default/readsb.
flag_in() {
  local file="$1" flag="$2"
  [[ -r $file ]] || return 0
  grep -oE -- "${flag}[ =]+-?[0-9]+(\.[0-9]+)?" "$file" | tail -n 1 |
    grep -oE -- '-?[0-9]+(\.[0-9]+)?$' || true
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

# WHY, and how to pass the release and the seed list by hand. Until a release pipeline publishes
# Tally's releases (RFC-0180 phase 1), nothing writes PUBLISHED_RELEASE into this script or
# publishes a `seeds` beside it, so an install names both itself. sudo passes a NAME=value given
# before the command into its environment.
how_to_pass() {
  printf '%s. Until a release pipeline publishes them, name the release (a directory holding tally-feed-x86_64-linux, tally-feed-aarch64-linux and tally-feed.service, each with its .sha256) and a seed list file (one HOST:PORT=KEY OPERATOR a line) yourself:\n  curl -fsSL RELEASE/install.sh | sudo TALLY_RELEASE=RELEASE TALLY_SEEDS=/path/to/seeds bash\nNothing was installed.' "$1"
}

# Everything runs from here, once the whole script has arrived: a download cut short runs nothing.
main() {
  if [[ ${1:-} == --check-seeds ]]; then
    [[ $# -eq 2 ]] || stop "usage: install.sh --check-seeds FILE"
    read_seeds "$2"
    local n
    for n in "${!seed_relays[@]}"; do
      printf '%s\t%s\n' "${seed_relays[n]}" "${seed_operators[n]}"
    done
    return 0
  fi
  [[ $# -eq 0 ]] || stop "unknown argument $1 (install.sh takes none, or --check-seeds FILE)"

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
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  # A feeder that knows no relay publishes nothing, so this is settled before anything is installed.
  if [[ -n ${TALLY_SEEDS:-} ]]; then
    seeds="$TALLY_SEEDS" seeds_from="$TALLY_SEEDS"
  else
    fetch_verified seeds "$(how_to_pass "could not download the seed list $release/seeds")"
    seeds="$work/seeds" seeds_from="$release/seeds"
  fi
  read_seeds "$seeds"

  if [[ $EUID -ne 0 ]]; then
    stop "run as root (curl ... | sudo bash)"
  fi
  command -v systemctl >/dev/null || stop "systemctl is required"

  case "$(uname -m)" in
    x86_64 | amd64) ARCH=x86_64 ;;
    aarch64 | arm64) ARCH=aarch64 ;;
    *) stop "no tally-feed build for $(uname -m): a 64-bit x86_64 or aarch64 system is required" ;;
  esac

  systemd_version="$(systemctl --version | awk 'NR == 1 { print $2 }')"
  systemd_version="${systemd_version%%[!0-9]*}"
  if [[ -z $systemd_version || $systemd_version -lt $SYSTEMD_AT_LEAST ]]; then
    stop "systemd $SYSTEMD_AT_LEAST or later is required (this system has ${systemd_version:-unknown})"
  fi

  say "downloading tally-feed $VERSION for $ARCH"
  fetch_verified "tally-feed-$ARCH-linux"
  fetch_verified "tally-feed.service"
  install -m 0755 "$work/tally-feed-$ARCH-linux" "$BIN"

  args=()
  for n in "${!seed_relays[@]}"; do
    say "starting from ${seed_relays[n]%%=*}, run by ${seed_operators[n]}"
    args+=(--relay "${seed_relays[n]}")
  done
  if listening 127.0.0.1 30005; then
    say "found BEAST (1090 MHz) on 127.0.0.1:30005"
  else
    say "nothing on 127.0.0.1:30005 yet; tally-feed will keep trying it (readsb's BEAST output)"
  fi
  if listening 127.0.0.1 30978; then
    say "found dump978 (978 MHz UAT) on 127.0.0.1:30978"
    args+=(--uat 127.0.0.1:30978)
  fi

  lat="${TALLY_LAT:-}" lon="${TALLY_LON:-}" alt="${TALLY_ALT:-}" from="TALLY_LAT and TALLY_LON"
  if [[ -z $lat || -z $lon ]]; then
    lat="" lon="" alt="" from=""
    for env in /opt/adsb/config/.env /opt/adsb/.env; do
      if [[ -z $lat ]]; then
        lat="$(value_of "$env" FEEDER_LAT)" lon="$(value_of "$env" FEEDER_LONG)"
        alt="$(value_of "$env" FEEDER_ALT_M)" from="$env"
      fi
      if [[ -z $lat ]]; then
        lat="$(value_of "$env" READSB_LAT)" lon="$(value_of "$env" READSB_LON)"
        alt="$(value_of "$env" READSB_ALT)" from="$env"
      fi
    done
    if [[ -z $lat ]]; then
      lat="$(value_of /etc/default/readsb READSB_LAT)" lon="$(value_of /etc/default/readsb READSB_LON)"
      alt="$(value_of /etc/default/readsb READSB_ALT)" from=/etc/default/readsb
    fi
    if [[ -z $lat ]]; then
      lat="$(flag_in /etc/default/readsb --lat)" lon="$(flag_in /etc/default/readsb --lon)"
      alt="" from=/etc/default/readsb
    fi
  fi
  if [[ -n $lat || -n $lon ]] && { ! is_number "$lat" || ! is_number "$lon"; }; then
    say "ignoring an unreadable location from $from ($lat, $lon)"
    lat="" lon=""
  fi
  if [[ -n $lat && -n $lon ]]; then
    args+=(--lat "$lat" --lon "$lon")
    if [[ -n $alt ]]; then
      alt_m="$(metres "$alt")" || alt_m=""
      if [[ -n $alt_m ]]; then
        args+=(--alt "$alt_m")
      else
        say "ignoring an unreadable altitude from $from ($alt)"
      fi
    fi
    if [[ -n ${TALLY_PRECISION:-} ]]; then
      [[ $TALLY_PRECISION =~ ^[0-9]+$ ]] || stop "TALLY_PRECISION must be whole metres"
      args+=(--precision "$TALLY_PRECISION")
    fi
    say "location $lat, $lon from $from"
  else
    say "no receiver location found; set TALLY_LAT, TALLY_LON and TALLY_ALT and run this again, or"
    say "add --lat, --lon and --alt to $DEFAULTS (multilateration needs it)"
  fi

  install -d -m 0755 /etc/tally
  if [[ ! -f $KEY ]]; then
    say "making this receiver's key, $KEY (keep it: it is the antenna's name forever)"
  fi
  public="$(umask 077 && "$BIN" init --key "$KEY")"
  chown root:root "$KEY"
  chmod 0600 "$KEY"

  if [[ -f $DEFAULTS ]]; then
    say "keeping $DEFAULTS as it is (found here: ${args[*]:-nothing to add})"
    if ! grep -qE -- '--(relay|home)[ =]' "$DEFAULTS"; then
      say "$DEFAULTS names no relay, so tally-feed publishes only to relays it learned before;"
      say "add --relay HOST:PORT=KEY to it, or remove it and run this again"
    fi
  else
    {
      printf '# Arguments for tally-feed, read by tally-feed.service; tally-feed --help lists them.\n'
      printf '# Written by install.sh. The location here is published exactly as written unless\n'
      printf '# --precision M says how many metres it may be off by.\n'
      printf '# --relay HOST:PORT=KEY names a relay to start from; it learns more from relays.\n'
      printf '# The relays below came from the seed list %s, each run by:\n' "$seeds_from"
      for n in "${!seed_relays[@]}"; do
        printf '#   %s  %s\n' "${seed_relays[n]%%=*}" "${seed_operators[n]}"
      done
      printf 'TALLY_FEED_ARGS="%s"\n' "${args[*]}"
    } >"$DEFAULTS"
    chmod 0644 "$DEFAULTS"
  fi

  install -m 0644 "$work/tally-feed.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable tally-feed.service >/dev/null
  systemctl restart tally-feed.service

  precision="$(grep -oE -- '--precision[ =]+[0-9]+' "$DEFAULTS" | grep -oE '[0-9]+$' || true)"
  printf '\ntally-feed %s is running (systemctl status tally-feed; journalctl -u tally-feed).\n' \
    "$VERSION"
  printf "\nThis receiver's public key, its name on the network:\n\n  %s\n\n" "$public"
  printf "What it publishes: every reception this receiver's decoders report, signed with that\n"
  printf 'key, and the location in %s. Anyone can read both.\n' "$DEFAULTS"
  if [[ -n $precision && $precision != 0 ]]; then
    printf 'The location is published rounded to within %s metres, as --precision says.\n' "$precision"
  else
    printf 'The location is published EXACTLY as entered. Add --precision <metres> to %s\n' "$DEFAULTS"
    printf 'and restart tally-feed to round it (you then contribute less to multilateration).\n'
  fi
}

main "$@"
