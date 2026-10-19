#!/bin/bash
# The map image's entrypoint (RFC-0187 §1; packaging/map/README.md): readsb, net-only, decoding the
# relay's --beast-out; nginx serving tar1090 over readsb's output on :8080; and the archiver, which
# packs each finished UTC day of the globe history into one tar for the open data releases
# (RFC-0187 §3). All three run as this image's user; if any exits, the others are stopped and the
# container exits with a failure, so the host's restart policy brings them back together.
#
# Environment:
#   TALLY_MAP_BEAST       the relay's --beast-out, HOST:PORT or HOST,PORT (default 127.0.0.1:30105)
#   TALLY_MAP_TITLE       the page's title (default Tally)
#   TALLY_MAP_API         the tally-api origin routes are asked of, https://host[:port]; unset,
#                         routes are off
#   TALLY_MAP_READSB_API  where readsb's query API listens, ADDRESS:PORT (default 127.0.0.1:30152)
#   TALLY_MAP_JSON_EVERY  seconds between readsb's JSON writes and API updates (default 1)
#   TALLY_MAP_HISTORY_DAYS  days of globe history kept, once each is archived (default 8)
#   TALLY_MAP_IPV6        on or off: nginx also listens on [::]:8080 (default on where the
#                         container has IPv6, /proc/net/if_inet6)
set -euo pipefail

fail() {
	echo "tally-map: $*" >&2
	exit 64
}

# Each finished UTC day's globe history, /var/globe_history/YYYY/MM/DD, as one plain tar of that
# day's tree (as adsb.lol's globe_history releases are: readsb's trace and heatmap files inside,
# already compressed), with ATTRIBUTION and LICENSE-aircraft-database added at its root, at
# /var/globe_history/archive/YYYY-MM-DD.tar and its .sha256 beside it.
#
# readsb writes day D's traces until 00:55 UTC on D+1 and compresses them at 00:56, so D is packed
# from 01:15 UTC on D+1. If readsb has not run since before 00:55 UTC on D+1 (the container
# started later), D may lack its last traces: it is still packed, as YYYY-MM-DD.partial.tar, so
# nobody takes it for a whole day. Every day on the volume not yet packed is packed when its time
# has come, so a day a stopped container missed is packed when it next runs, and partial.
#
# The .sha256 is written first and the tar after, each under a temporary name and renamed; then
# the day is recorded as packed (archive/.packed/YYYY-MM-DD), and only that record makes it
# complete. The newest ARCHIVE_KEEP archives are kept, and a day's history is deleted once it is
# older than TALLY_MAP_HISTORY_DAYS and packed, never before.
ARCHIVE_KEEP=7
GLOBE_HISTORY=/var/globe_history
ARCHIVE="$GLOBE_HISTORY/archive"
PACKED="$ARCHIVE/.packed"

# The UTC midnight starting the day YYYY-MM-DD, in seconds since the epoch; fails on anything else.
day_start() {
	[[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] && date -u -d "$1 00:00:00" +%s 2>/dev/null
}

# archive_day DAY WHOLE: packs DAY's history; WHOLE is 1 for a whole day, 0 for a partial one.
archive_day() {
	local day="$1" whole="$2" dir name tmp sum
	dir="$GLOBE_HISTORY/${day//-//}"
	name="$day.tar"
	((whole)) || name="$day.partial.tar"
	tmp="$ARCHIVE/$name.tmp"
	tar -cf "$tmp" -C "$dir" . -C /usr/local/share/tally-map ./ATTRIBUTION ./LICENSE-aircraft-database &&
		sum="$(sha256sum <"$tmp" | cut -d' ' -f1)" &&
		printf '%s  %s\n' "$sum" "$name" >"$ARCHIVE/$name.sha256.tmp" &&
		mv "$ARCHIVE/$name.sha256.tmp" "$ARCHIVE/$name.sha256" &&
		mv "$tmp" "$ARCHIVE/$name" &&
		: >"$PACKED/$day" &&
		echo "tally-map: archived $day as $name ($(du -h "$ARCHIVE/$name" | cut -f1))" >&2
}

# archive_pass NOW READSB_STARTED HISTORY_DAYS: one pass of the archiver at NOW (seconds since the
# epoch), for a readsb running since READSB_STARTED, keeping HISTORY_DAYS days of history. The
# archiver runs it every 5 minutes; a test runs it once with any clock.
archive_pass() {
	local now="$1" started="$2" history_days="$3"
	local dir day start next oldest i archives
	mkdir -p "$PACKED"
	rm -f "$ARCHIVE"/*.tmp
	oldest=$(($(day_start "$(date -u -d "@$now" +%F)") - history_days * 86400))
	while IFS= read -r dir; do
		day="${dir#"$GLOBE_HISTORY"/}"
		day="${day//\//-}"
		start="$(day_start "$day")" || continue
		next=$((start + 86400))
		if [[ ! -e "$PACKED/$day" ]] && ((now >= next + 4500)); then
			# 4500 s is 01:15, 3300 s 00:55.
			archive_day "$day" "$((started < next + 3300))" ||
				echo "tally-map: could not archive $day" >&2
		fi
		if [[ -e "$PACKED/$day" ]] && ((start < oldest)); then
			rm -rf "$dir" && rm -f "$PACKED/$day" &&
				rmdir --ignore-fail-on-non-empty "${dir%/*}" "${dir%/*/*}" &&
				echo "tally-map: deleted $day's history, older than $history_days days" >&2
		fi
	done < <(find "$GLOBE_HISTORY" -mindepth 3 -maxdepth 3 -type d \
		-regex "$GLOBE_HISTORY/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]" | sort)
	mapfile -t archives < <(find "$ARCHIVE" -maxdepth 1 -type f \
		\( -name '????-??-??.tar' -o -name '????-??-??.partial.tar' \) -printf '%f\n' | sort)
	for ((i = 0; i < ${#archives[@]} - ARCHIVE_KEEP; i++)); do
		rm -f "$ARCHIVE/${archives[i]}" "$ARCHIVE/${archives[i]}.sha256"
	done
}

archiver() {
	set +e
	while true; do
		archive_pass "$(date -u +%s)" "$readsb_started" "$history_days"
		sleep 300
	done
}

# One pass of the archiver with any clock, then exit, for a test or by hand:
#   tally-map archive-pass NOW READSB_STARTED HISTORY_DAYS     (times in seconds since the epoch)
if [[ "${1:-}" == archive-pass ]]; then
	[[ $# == 4 && "$2" =~ ^[0-9]+$ && "$3" =~ ^[0-9]+$ && "$4" =~ ^[0-9]*[1-9][0-9]*$ ]] ||
		fail "archive-pass takes NOW READSB_STARTED HISTORY_DAYS, each a whole number, HISTORY_DAYS at least 1"
	archive_pass "$2" "$3" "$4"
	exit
fi

# HOST:PORT, [IPV6]:PORT or HOST,PORT, as readsb's connector wants it: HOST,PORT.
beast="${TALLY_MAP_BEAST:-127.0.0.1:30105}"
if [[ "$beast" == *,* ]]; then
	beast_host="${beast%,*}"
	beast_port="${beast##*,}"
else
	beast_host="${beast%:*}"
	beast_port="${beast##*:}"
	[[ "$beast" == *:* ]] || beast_port=""
fi
beast_host="${beast_host#[}"
beast_host="${beast_host%]}"
[[ -n "$beast_host" && "$beast_port" =~ ^[0-9]+$ ]] ||
	fail "TALLY_MAP_BEAST is '$beast'; it names the relay's --beast-out as HOST:PORT"

readsb_api="${TALLY_MAP_READSB_API:-127.0.0.1:30152}"
api_address="${readsb_api%:*}"
api_port="${readsb_api##*:}"
[[ "$readsb_api" == *:* && -n "$api_address" && "$api_port" =~ ^[0-9]+$ ]] ||
	fail "TALLY_MAP_READSB_API is '$readsb_api'; it is ADDRESS:PORT"
api_address="${api_address#[}"
api_address="${api_address%]}"

json_every="${TALLY_MAP_JSON_EVERY:-1}"
[[ "$json_every" =~ ^[0-9]+(\.[0-9]+)?$ ]] ||
	fail "TALLY_MAP_JSON_EVERY is '$json_every'; it is a number of seconds"

history_days="${TALLY_MAP_HISTORY_DAYS:-8}"
[[ "$history_days" =~ ^[0-9]*[1-9][0-9]*$ ]] ||
	fail "TALLY_MAP_HISTORY_DAYS is '$history_days'; it is a whole number of days, at least 1"
history_days=$((10#$history_days))

# nginx's IPv6 listener, its own file the config includes: on where the kernel gives the container
# IPv6, since nginx refuses to start on an address family it cannot bind.
ipv6="${TALLY_MAP_IPV6:-}"
if [[ -z "$ipv6" ]]; then
	ipv6=off
	[[ ! -e /proc/net/if_inet6 ]] || ipv6=on
fi
case "$ipv6" in
on) echo "listen [::]:8080 default_server;" >/run/tally-map/listen-ipv6.conf ;;
off) : >/run/tally-map/listen-ipv6.conf ;;
*) fail "TALLY_MAP_IPV6 is '$ipv6'; it is on or off" ;;
esac

# A JavaScript string literal of $1: backslashes and quotes escaped, and no control character,
# which could end the literal or the line.
js_string() {
	local s="$1"
	[[ "$s" != *[[:cntrl:]]* ]] || fail "$2 holds a control character"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	printf '"%s"' "$s"
}

# tar1090's settings: config.js is read after its defaults.js and assigns over them.
title="${TALLY_MAP_TITLE:-Tally}"
api="${TALLY_MAP_API:-}"
api="${api%/}"
{
	echo "// Written by the tally-map image at start, from its environment."
	echo "PageName = $(js_string "$title" TALLY_MAP_TITLE);"
	# The aircraft database's attribution, which its licence (ODC-By 1.0) asks of every page that
	# shows it; its licence is served beside it, at /db-*/LICENSE.txt.
	echo 'imageConfigText = "Aircraft data: Mictronics aircraft database, ODC-By 1.0";'
	echo 'imageConfigLink = "https://github.com/Mictronics/aircraft-database";'
	if [[ -n "$api" ]]; then
		[[ "$api" =~ ^https?://[^/[:space:]]+$ ]] ||
			fail "TALLY_MAP_API is '$api'; it is the tally-api origin, such as https://api.example.org"
		echo "routeApiUrl = $(js_string "$api/api/0/routeset" TALLY_MAP_API);"
		echo "useRouteAPI = true;"
	else
		echo 'routeApiUrl = "";'
		echo "useRouteAPI = false;"
	fi
} >/run/tally-map/config.js.new
mv /run/tally-map/config.js.new /run/tally-map/config.js

mkdir -p /run/readsb /var/globe_history/internal_state /var/globe_history/archive
[[ -w /var/globe_history ]] ||
	fail "/var/globe_history is not writable by uid $(id -u); give the volume to it (README.md)"

# The processes started so far, by pid. The trap is set before the first starts, so a signal that
# comes while they start stops those already running and starts no more.
declare -A names=()
stop() {
	((${#names[@]} == 0)) || kill -TERM "${!names[@]}" 2>/dev/null || true
}
stopping=""
trap 'stopping=1; stop' TERM INT

# When this readsb started: a day whose 00:55 UTC came before it may lack its last traces (the
# archiver above).
readsb_started="$(date -u +%s)"
readsb \
	--net-only \
	--quiet \
	--net-connector "$beast_host,$beast_port,beast_in" \
	--net-connector-delay 5 \
	--net-bind-address "$api_address" \
	--net-api-port "$api_port" \
	--db-file /usr/local/share/tally-map/aircraft.csv.gz \
	--db-file-lt \
	--write-json /run/readsb \
	--write-json-every "$json_every" \
	--write-json-globe-index \
	--json-trace-interval 15 \
	--write-globe-history /var/globe_history \
	--write-state /var/globe_history/internal_state \
	--heatmap 30 &
names[$!]=readsb

if [[ -z "$stopping" ]]; then
	nginx -e stderr -c /etc/tally-map/nginx.conf -g 'daemon off;' &
	names[$!]=nginx
fi
if [[ -z "$stopping" ]]; then
	archiver &
	names[$!]=archiver
fi
if [[ -n "$stopping" ]]; then
	stop
fi

# The first of them to exit, or a signal, ends the wait.
status=0
wait -n "${!names[@]}" || status=$?
if [[ -z "$stopping" ]]; then
	for pid in "${!names[@]}"; do
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "tally-map: ${names[$pid]} exited ($status); stopping" >&2
		fi
	done
fi
stop
wait "${!names[@]}" 2>/dev/null || true

if [[ -n "$stopping" ]]; then
	exit 0
fi
# A process that exits by itself is a failure, whatever its status.
((status != 0)) || status=1
exit "$status"
