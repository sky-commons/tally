#!/bin/bash
# The map image's entrypoint (RFC-0187 §1; packaging/map/README.md): readsb, net-only, decoding the
# relay's --beast-out; nginx serving tar1090 over readsb's output on :8080; the archiver, which
# packs each finished UTC day of the globe history into one tar for the open data releases
# (RFC-0187 §3); preview.py, which draws a link's picture (RFC-0187 §3); and, where TALLY_MAP_ACARS
# is set, the ACARS collector, which files the relay's --acars-out lines into the same days. All
# run as this image's user; if any exits, the others are stopped and the container exits with a
# failure, so the host's restart policy brings them back together.
#
# Environment:
#   TALLY_MAP_BEAST       the relay's --beast-out, HOST:PORT or HOST,PORT (default 127.0.0.1:30105)
#   TALLY_MAP_ACARS       the relay's --acars-out, HOST:PORT; unset, no ACARS is collected
#   TALLY_MAP_ACARS_DAY_MAX  the most bytes of ACARS lines kept for one day (default 268435456)
#   TALLY_MAP_TITLE       the page's title, and the site a preview names (default Tally)
#   TALLY_MAP_API         the tally-api origin routes are asked of, https://host[:port]; unset,
#                         routes are off
#   TALLY_MAP_TILES       the tile server previews' pictures are drawn from, https://host[:port]
#                         (default https://tile.openstreetmap.org, OpenStreetMap's own)
#   TALLY_MAP_URL         the map's public origin, https://host[:port], which a link's preview
#                         names its page and picture by; unset, https:// and the host asked for
#   TALLY_MAP_READSB_API  where readsb's query API listens, ADDRESS:PORT (default 127.0.0.1:30152)
#   TALLY_MAP_JSON_EVERY  seconds between readsb's JSON writes and API updates (default 1)
#   TALLY_MAP_HISTORY_DAYS  days of globe history kept, once each is archived (default 8)
#   TALLY_MAP_IPV6        on or off: nginx also listens on [::]:8080 (default on where the
#                         container has IPv6, /proc/net/if_inet6)
#   TALLY_MAP_MAX_UPLOAD  required: the most nginx sends a second, all clients together, as
#                         tally-relay's --max-upload takes it (6Mbit/s, 500kB/s, 1MiB/s)
#   TALLY_MAP_CLIENT_IP_HEADER  the header a trusted proxy names the client in (CF-Connecting-IP);
#                         unset, each client is the address it connects from
#   TALLY_MAP_TRUSTED_PROXIES  the proxies whose header is believed, CIDRs or addresses separated
#                         by commas or spaces; set exactly when TALLY_MAP_CLIENT_IP_HEADER is
#   TALLY_MAP_ARCHIVE_PUBLIC  on or off: /archive/ is open to anyone (default on); off, only to a
#                         request carrying the token
#   TALLY_MAP_ARCHIVE_TOKEN_FILE  a file holding that token, required when the archive is off
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
# A day's ACARS lines (the collector, below) are its acars.jsonl, sorted by each message's own time
# (in bounded memory, its runs in archive/.sorting, which nothing serves; a pass first removes any
# a stopped one left) and compressed to acars.jsonl.gz as the day is packed: nothing writes to it
# then, since the collector files each message by the UTC day of its own time, held to five
# minutes of its arrival, and writes no day from 01:10 UTC the next. A day the collector missed any
# of (its acars.gaps says when and why) is packed as partial too, its acars.gaps with it. The .gz is
# written under a temporary name (a pass first removes any a stopped one left) and renamed, and only
# then is the .jsonl removed, so a day holding both is a pack cut short: the .jsonl is the day's,
# and it is packed again.
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
	((whole)) && [[ ! -e "$dir/acars.gaps" ]] || name="$day.partial.tar"
	tmp="$ARCHIVE/$name.tmp"
	if [[ -e "$dir/acars.jsonl" ]]; then
		# A pack stopped between the .gz's rename and the .jsonl's removal left both: the .jsonl
		# is whole, so it is packed again.
		rm -f "$dir/acars.jsonl.gz"
		# The .gz is on the disk, and its name in the directory, before the .jsonl goes.
		tally-acars-collect sort "$dir/acars.jsonl" --scratch "$ARCHIVE/.sorting" &&
			gzip -n -c "$dir/acars.jsonl" >"$dir/acars.jsonl.gz.tmp" &&
			sync "$dir/acars.jsonl.gz.tmp" &&
			mv "$dir/acars.jsonl.gz.tmp" "$dir/acars.jsonl.gz" &&
			sync "$dir" &&
			rm "$dir/acars.jsonl" || return
	fi
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
	rm -f "$ARCHIVE"/*.tmp \
		"$GLOBE_HISTORY"/[0-9][0-9][0-9][0-9]/[0-9][0-9]/[0-9][0-9]/acars.jsonl.gz.tmp
	rm -rf "$ARCHIVE/.sorting"
	oldest=$(($(day_start "$(date -u -d "@$now" +%F)") - history_days * 86400))
	while IFS= read -r dir; do
		day="${dir#"$GLOBE_HISTORY"/}"
		day="${day//\//-}"
		start="$(day_start "$day")" || continue
		next=$((start + 86400))
		if [[ ! -e "$PACKED/$day" ]] && ((now >= next + 4500)); then
			# 4500 s is 01:15 (tally_acars_collect::PACKED_FROM, which packaging/tests/map_archive.rs
			# holds this to), 3300 s 00:55.
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

# The relay's --acars-out, HOST:PORT or [IPV6]:PORT; unset, no collector runs.
acars="${TALLY_MAP_ACARS:-}"
[[ -z "$acars" || "$acars" =~ ^(\[[0-9A-Fa-f:.]+\]|[^]:[]+):[0-9]+$ ]] ||
	fail "TALLY_MAP_ACARS is '$acars'; it names the relay's --acars-out as HOST:PORT"
acars_day_max="${TALLY_MAP_ACARS_DAY_MAX:-268435456}"
[[ "$acars_day_max" =~ ^0*[1-9][0-9]{0,14}$ ]] ||
	fail "TALLY_MAP_ACARS_DAY_MAX is '$acars_day_max'; it is a whole number of bytes, at least 1"
acars_day_max=$((10#$acars_day_max))

readsb_api="${TALLY_MAP_READSB_API:-127.0.0.1:30152}"
api_address="${readsb_api%:*}"
api_port="${readsb_api##*:}"
[[ "$readsb_api" == *:* && -n "$api_address" && "$api_port" =~ ^[0-9]+$ ]] ||
	fail "TALLY_MAP_READSB_API is '$readsb_api'; it is ADDRESS:PORT"
api_address="${api_address#[}"
api_address="${api_address%]}"

# Where nginx asks readsb's query API for a link's preview (preview.lua): the address it listens
# on, or loopback when it listens on every address.
case "$api_address" in
0.0.0.0) api_reach="127.0.0.1" ;;
:: | 0:0:0:0:0:0:0:0) api_reach="[::1]" ;;
*:*) api_reach="[$api_address]" ;;
*) api_reach="$api_address" ;;
esac
[[ "$api_reach" =~ ^[][0-9A-Za-z.:-]+$ ]] ||
	fail "TALLY_MAP_READSB_API is '$readsb_api'; it is ADDRESS:PORT"
echo "upstream readsb_api { server $api_reach:$api_port; }" >/run/tally-map/readsb.conf

public_url="${TALLY_MAP_URL:-}"
public_url="${public_url%/}"
[[ -z "$public_url" || "$public_url" =~ ^https?://[][A-Za-z0-9.:-]+$ ]] ||
	fail "TALLY_MAP_URL is '$public_url'; it is the map's public origin, such as https://map.example.org"
export TALLY_MAP_URL="$public_url"

# The tile server nginx fetches the pictures' tiles from (nginx.conf): OpenStreetMap's, tar1090's
# default layer, unless the operator names another serving the same tiles at /{z}/{x}/{y}.png.
tiles="${TALLY_MAP_TILES:-https://tile.openstreetmap.org}"
tiles="${tiles%/}"
[[ "$tiles" =~ ^https?://([][A-Za-z0-9.:-]+)$ ]] ||
	fail "TALLY_MAP_TILES is '$tiles'; it is a tile server's origin, such as https://tile.openstreetmap.org"
cat >/run/tally-map/tiles.conf <<EOF
set \$tile_origin "$tiles";
set \$tile_host "${BASH_REMATCH[1]}";
EOF

# The nameservers nginx looks up the tile server's name with, at each fetch (nginx.conf): the
# container's own. With none, no tile is fetched and every picture is the site's card.
resolvers=""
while read -r keyword address _; do
	[[ "$keyword" == nameserver ]] || continue
	address="${address%%%*}"
	if [[ "$address" =~ ^[0-9.]+$ ]]; then
		resolvers+=" $address"
	elif [[ "$address" =~ ^[0-9A-Fa-f:]+$ ]]; then
		resolvers+=" [$address]"
	fi
done </etc/resolv.conf
if [[ -n "$resolvers" ]]; then
	echo "resolver$resolvers valid=300s;" >/run/tally-map/resolver.conf
else
	echo "tally-map: /etc/resolv.conf names no nameserver; previews will have no map" >&2
	: >/run/tally-map/resolver.conf
fi

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

# rate_bytes RATE: RATE in bytes a second, as tally-relay's --max-upload reads it: 6Mbit/s, 2MB/s,
# 500kbit/s, 1.5Gbit/s, or the binary KiB/s, MiB/s and GiB/s; kB, MB, GB and the bit units are
# decimal, as hosts and links state them. Rounded down, so it never reads more than was stated.
rate_bytes() {
	local whole fraction unit scale divisor=1000
	[[ "$1" =~ ^([0-9]{1,6})(\.([0-9]{1,3}))?(kbit|Mbit|Gbit|kB|KB|MB|GB|KiB|MiB|GiB)/s$ ]] ||
		return 1
	whole="${BASH_REMATCH[1]}"
	fraction="${BASH_REMATCH[3]}000"
	fraction="${fraction:0:3}"
	unit="${BASH_REMATCH[4]}"
	case "$unit" in
	kbit) scale=1000 divisor=8000 ;;
	Mbit) scale=1000000 divisor=8000 ;;
	Gbit) scale=1000000000 divisor=8000 ;;
	kB | KB) scale=1000 ;;
	MB) scale=1000000 ;;
	GB) scale=1000000000 ;;
	KiB) scale=1024 ;;
	MiB) scale=1048576 ;;
	GiB) scale=1073741824 ;;
	esac
	echo $(((10#$whole * 1000 + 10#$fraction) * scale / divisor))
}

# What nginx sends is bounded by one figure the operator states, TALLY_MAP_MAX_UPLOAD, the ceiling.
# nginx has no shared budget of bytes: limit_rate holds one response to a rate, and limit_conn
# holds a zone to a number of responses at once. So every response nginx sends is in one class
# below, and each class is a zone keyed on a constant (every client together) holding it to its
# slots, each response sent at the class's rate: a class sends at most slots x rate, and the
# classes' shares add up to the ceiling, so all of them together never send more than the ceiling
# (plus each response's first second, which nginx's limit_rate lets out at once). The rates are
# rounded down. The cost of a hard ceiling is that a response is held to its slot's rate even
# when the others are idle.
#
#   class    serves                 share  slots  a slot's rate  one client at once
#   live     /data/, and the page   8/16   8      ceiling/16     4 (of /data/)
#   history  /globe_history/        4/16   4      ceiling/16     2
#   archive  /archive/              4/16   2      ceiling/8      1
#
# The page's files (tar1090's own) have no per-client limit, since a browser asks for them all at
# once and one refused breaks the page; they are fixed, cacheable for two weeks, and share the live
# class's slots. The page itself (/ and index.html, which may ask readsb for a link's preview) and
# the previews' pictures are held to a client's 4 of them, as /data/ is. Every client is also held
# to 20 requests a second over /data/, /globe_history/, /archive/, the page itself and the
# pictures, with 40 more queued (nginx.conf's client_req): what one map page asks, not a figure of
# bytes, so it does not move with the ceiling.
max_upload="${TALLY_MAP_MAX_UPLOAD:-}"
[[ -n "$max_upload" ]] ||
	fail "TALLY_MAP_MAX_UPLOAD is unset; it is the most the map sends a second, as tally-relay's --max-upload takes it (README.md)"
ceiling="$(rate_bytes "$max_upload")" ||
	fail "TALLY_MAP_MAX_UPLOAD is '$max_upload'; it is a rate such as 6Mbit/s or 500kB/s (kbit, Mbit, Gbit, kB, MB, GB, KiB, MiB or GiB, a second)"
live_slots=8 history_slots=4 archive_slots=2
live_rate=$((ceiling * 8 / 16 / live_slots))
history_rate=$((ceiling * 4 / 16 / history_slots))
archive_rate=$((ceiling * 4 / 16 / archive_slots))
# limit_rate 0 is no limit at all, so a rate that rounds to nothing is refused, never written.
((live_rate > 0 && history_rate > 0 && archive_rate > 0)) ||
	fail "TALLY_MAP_MAX_UPLOAD is '$max_upload'; it is too small to share, at least 16 bytes a second"
echo "tally-map: sending at most $ceiling bytes a second: live ${live_slots}x$live_rate," \
	"history ${history_slots}x$history_rate, archive ${archive_slots}x$archive_rate" >&2

# Who a client is: the address it connects from, or, from a trusted proxy, the address its header
# names (nginx's realip). A client reaching nginx directly cannot name itself, since the header is
# read only from the proxies named.
client_header="${TALLY_MAP_CLIENT_IP_HEADER:-}"
trusted="${TALLY_MAP_TRUSTED_PROXIES:-}"
realip=""
if [[ -n "$client_header" || -n "$trusted" ]]; then
	[[ "$client_header" =~ ^[A-Za-z0-9-]+$ ]] ||
		fail "TALLY_MAP_CLIENT_IP_HEADER is '$client_header'; it is a header name, such as CF-Connecting-IP, set with TALLY_MAP_TRUSTED_PROXIES"
	read -r -a proxies <<<"${trusted//,/ }"
	((${#proxies[@]} > 0)) ||
		fail "TALLY_MAP_TRUSTED_PROXIES is unset; it names the proxies whose $client_header is believed"
	for proxy in "${proxies[@]}"; do
		[[ "$proxy" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] ||
			fail "TALLY_MAP_TRUSTED_PROXIES holds '$proxy'; it is a list of CIDRs or addresses"
		realip+="set_real_ip_from $proxy;"$'\n'
	done
	realip+="real_ip_header $client_header;"
fi

# The archive's gate. Open, anyone may fetch it, and shared caches may keep it. Closed, a request
# is answered 404 unless it carries `Authorization: Bearer TOKEN`, and the answers are private, so
# no shared cache keeps one for another client. nginx compares the token as a regular expression
# does, not in constant time; the token is long and random, so what its timing could tell is
# nothing a client can act on.
archive_public="${TALLY_MAP_ARCHIVE_PUBLIC:-on}"
token_file="${TALLY_MAP_ARCHIVE_TOKEN_FILE:-}"
case "$archive_public" in
on)
	[[ -z "$token_file" ]] ||
		fail "TALLY_MAP_ARCHIVE_TOKEN_FILE is set but the archive is public; set TALLY_MAP_ARCHIVE_PUBLIC=off to close it"
	archive_gate="map \$host \$archive_token_ok { default 1; }"
	archive_scope=public
	;;
off)
	[[ -n "$token_file" ]] ||
		fail "TALLY_MAP_ARCHIVE_PUBLIC is off; TALLY_MAP_ARCHIVE_TOKEN_FILE names the file holding the token that opens it"
	[[ -r "$token_file" ]] || fail "TALLY_MAP_ARCHIVE_TOKEN_FILE $token_file is not readable by uid $(id -u)"
	token="$(<"$token_file")"
	[[ "$token" =~ ^[A-Za-z0-9_-]{32,}$ ]] ||
		fail "TALLY_MAP_ARCHIVE_TOKEN_FILE holds no token: one line of at least 32 letters, digits, _ or - (openssl rand -hex 32)"
	archive_gate="map \$http_authorization \$archive_token_ok { default 0; \"~^Bearer $token\$\" 1; }"
	archive_scope=private
	;;
*) fail "TALLY_MAP_ARCHIVE_PUBLIC is '$archive_public'; it is on or off" ;;
esac

# The limits, as nginx.conf includes them: the zones, who a client is and the archive's gate in
# the http block, and each class's limits in the locations it serves. The token is in the gate,
# so the file is the image user's alone.
(
	umask 077
	cat >/run/tally-map/limits.conf.new <<-EOF
		# Written by the tally-map image at start, from its environment (entrypoint.sh).
		map \$host \$everyone { default all; }
		limit_conn_zone \$everyone zone=live:1m;
		limit_conn_zone \$everyone zone=history:1m;
		limit_conn_zone \$everyone zone=archive:1m;
		limit_conn_zone \$binary_remote_addr zone=client_live:10m;
		limit_conn_zone \$binary_remote_addr zone=client_history:10m;
		limit_conn_zone \$binary_remote_addr zone=client_archive:10m;
		limit_req_zone \$binary_remote_addr zone=client_req:10m rate=20r/s;
		$realip
		$archive_gate
		map \$host \$archive_scope { default $archive_scope; }
	EOF
	mv /run/tally-map/limits.conf.new /run/tally-map/limits.conf
)
cat >/run/tally-map/class-page.conf <<EOF
limit_conn live $live_slots;
limit_rate $live_rate;
EOF
cat >/run/tally-map/class-live.conf <<EOF
limit_conn live $live_slots;
limit_conn client_live 4;
limit_req zone=client_req burst=40;
limit_rate $live_rate;
EOF
cat >/run/tally-map/class-history.conf <<EOF
limit_conn history $history_slots;
limit_conn client_history 2;
limit_req zone=client_req burst=40;
limit_rate $history_rate;
EOF
cat >/run/tally-map/class-archive.conf <<EOF
limit_conn archive $archive_slots;
limit_conn client_archive 1;
limit_req zone=client_req burst=40;
limit_rate $archive_rate;
EOF

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
	# No receiver is placed on the map (docs/relay-operators.md): readsb below is given no
	# location, so receiver.json names none and no aircraft carries a distance from one; and
	# tar1090 draws no site marker, range rings or range outline even if one were named.
	echo 'SiteShow = false;'
	echo 'SiteCircles = false;'
	echo 'actual_range_show = false;'
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

# readsb has no receiver location (no --lat or --lon): it decodes a network, not one
# receiver, and what it writes is served publicly, so it names no site, writes no range
# outline and gives no aircraft a distance or direction from one. What it reads is the relay's
# --beast-out, each frame's message alone, with no receiver's counter or signal level.
#
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
	rm -f /run/tally-map/tiles.sock
	nginx -e stderr -c /etc/tally-map/nginx.conf -g 'daemon off;' &
	names[$!]=nginx
fi
if [[ -z "$stopping" && -n "$acars" ]]; then
	# tally-acars-collect (crates/acars-collect): merges the copies of each message on the relay's
	# --acars-out and files it into the UTC day of its own time,
	# /var/globe_history/YYYY/MM/DD/acars.jsonl, at most TALLY_MAP_ACARS_DAY_MAX bytes a day, writing
	# what each day missed to its acars.gaps. Before the archiver, which waits until it has marked
	# what it missed while stopped, so no day is packed without its gap.
	rm -f /run/tally-map/acars.ready
	tally-acars-collect collect --from "$acars" --history "$GLOBE_HISTORY" \
		--day-max "$acars_day_max" --ready /run/tally-map/acars.ready &
	names[$!]=acars
	acars_pid=$!
	while [[ -z "$stopping" && ! -e /run/tally-map/acars.ready ]] &&
		kill -0 "$acars_pid" 2>/dev/null; do
		sleep 0.1
	done
fi
if [[ -z "$stopping" ]]; then
	archiver &
	names[$!]=archiver
fi
# A socket left by a container stopped short would refuse the new one. preview.py imports
# staticmap from its own directory, the image's.
if [[ -z "$stopping" ]]; then
	rm -f /run/tally-map/preview.sock
	python3 -E -s /usr/local/lib/tally-map/preview.py serve /run/tally-map/preview.sock \
		/run/tally-map/tiles.sock "$api_reach:$api_port" &
	names[$!]=preview
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
