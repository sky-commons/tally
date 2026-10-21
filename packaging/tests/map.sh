#!/bin/bash
# The map image's test (packaging/map; RFC-0187 §1 and §3): builds the image, runs it fed by
# map_feed.py (two aircraft over a stand-in --beast-out, inside the container), and checks what a
# visitor and a link's preview get over HTTP. It needs Docker, so it runs in CI's map job
# (.github/workflows/ci.yml), not under Bazel, whose tests have no Docker.
#
#   packaging/tests/map.sh            build the image from packaging/map, then test it
#   packaging/tests/map.sh IMAGE      test an image already built
#
# The image's one program of ours, tally-acars-collect, comes from the build context `dist`, as the
# release's signed binary does (release.yml): here Bazel builds it for this machine first.
#
# It fetches nothing from outside: the pictures' tiles come from map_tiles.py, a stand-in tile
# server in the container (TALLY_MAP_TILES), and one check reads that the image's default is
# OpenStreetMap's own.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
image="${1:-}"
if [[ -z "$image" ]]; then
	image=tally-map-test:local
	dist="$(mktemp -d)"
	case "$(uname -m)" in
	x86_64) arch=x86_64 docker_arch=amd64 ;;
	aarch64 | arm64) arch=aarch64 docker_arch=arm64 ;;
	*) echo "map.sh: no map image for $(uname -m)" >&2 && exit 1 ;;
	esac
	# From the workspace, wherever this runs from: cquery names the binary relative to it.
	root="$(cd "$here/../.." && pwd)"
	(cd "$root" && bazel build -c opt --lockfile_mode=error //crates/acars-collect:tally-acars-collect)
	install -m 0755 "$root/$(cd "$root" && bazel cquery -c opt --output=files \
		//crates/acars-collect:tally-acars-collect 2>/dev/null)" "$dist/tally-acars-collect-$arch-linux"
	docker build -q --platform "linux/$docker_arch" --build-context "dist=$dist" -t "$image" \
		"$here/../map" >/dev/null
	rm -rf "$dist"
fi

name="tally-map-test-$$"
scratch="$(mktemp -d)"
cleanup() {
	docker rm -f "$name" "tally-map-test-default-$$" "tally-map-test-off-$$" >/dev/null 2>&1 || true
	rm -rf "$scratch"
}
trap cleanup EXIT

failures=0
pass() { echo "ok: $*"; }
fail() {
	echo "FAILED: $*" >&2
	failures=$((failures + 1))
}
# expect WHAT HAYSTACK NEEDLE: HAYSTACK holds NEEDLE.
expect() {
	if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1: no '$3' in: ${2:0:400}"; fi
}
refuse() {
	if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1: '$3' in: ${2:0:400}"; fi
}

docker run -d --name "$name" -p 127.0.0.1::8080 \
	-e TALLY_MAP_MAX_UPLOAD=80Mbit/s -e TALLY_MAP_IPV6=off \
	-e TALLY_MAP_URL=https://map.example.org -e 'TALLY_MAP_TITLE=Tally & co' \
	-e TALLY_MAP_TILES=http://127.0.0.1:8089 "$image" >/dev/null
docker cp "$here/map_feed.py" "$name:/tmp/map_feed.py"
docker cp "$here/map_tiles.py" "$name:/tmp/map_tiles.py"
docker exec -d "$name" python3 -I /tmp/map_feed.py
docker exec -d "$name" python3 -I /tmp/map_tiles.py
map="http://$(docker port "$name" 8080/tcp | head -1)"

get() { curl -s --max-time 30 "$map$1"; }
# status PATH: the status code and Location of PATH, unfollowed.
status() { curl -s --max-time 30 -o /dev/null -w '%{http_code} %header{location}' "$map$1"; }

# readsb redials the feed every 5 s and needs two positions to place an aircraft.
for _ in $(seq 60); do
	page="$(get '/?icao=a32806' || true)"
	[[ "$page" == *'/preview/a32806/'* ]] && break
	sleep 1
done

# A link to an aircraft readsb hears: its tags, and its picture at its position.
expect "title" "$page" '<meta property="og:title" content="TALLY1 · N302PA · PIPER PA-44 Seminole">'
expect "description" "$page" '<meta property="og:description" content="3,000 ft">'
expect "site" "$page" '<meta property="og:site_name" content="Tally &amp; co">'
expect "url" "$page" '<meta property="og:url" content="https://map.example.org/?icao=a32806">'
expect "picture" "$page" '<meta property="og:image" content="https://map.example.org/preview/a32806/37.62,-122.38.jpg">'
expect "large card" "$page" '<meta name="twitter:card" content="summary_large_image">'
expect "the page itself" "$page" '</html>'
tags="$(grep -o '<meta [^>]*>' <<<"$page" | grep -E 'og:|twitter:')"
for field in r_dst r_dir rssi; do refuse "no $field in the tags" "$tags" "$field"; done
page="$(get '/?reg=n302pa')"
expect "by registration" "$page" '<meta property="og:url" content="https://map.example.org/?reg=N302PA">'
expect "by registration, its picture" "$page" '/preview/a32806/37.62,-122.38.jpg'
page="$(get '/?icao=ae0001')"
expect "36,000 ft" "$page" '<meta property="og:description" content="36,000 ft">'

# One readsb does not hear: the site's card.
page="$(get '/?icao=c0ffee')"
expect "unheard" "$page" '<meta property="og:description" content="Not heard right now">'
expect "unheard, the card" "$page" '<meta property="og:image" content="https://map.example.org/card.jpg">'
page="$(get '/?icao=~a32806')"
expect "a ~hex" "$page" '<meta property="og:title" content="~A32806">'

# No aircraft asked: the page as it is, its validators kept.
headers="$(curl -s -D - -o "$scratch/plain" "$map/")"
refuse "no tags without an aircraft" "$(cat "$scratch/plain")" 'og:'
expect "the plain page keeps its ETag" "$headers" 'ETag:'

# The pictures.
curl -s -D "$scratch/card.h" -o "$scratch/card.jpg" "$map/card.jpg"
expect "the card is a JPEG" "$(head -c 3 "$scratch/card.jpg" | od -An -tx1)" 'ff d8 ff'
expect "the card is kept long" "$(cat "$scratch/card.h")" 'max-age=1209600'
curl -s --max-time 60 -D "$scratch/drawn.h" -o "$scratch/drawn.jpg" "$map/preview/a32806/37.62,-122.38.jpg"
expect "the picture is a JPEG" "$(head -c 3 "$scratch/drawn.jpg" | od -An -tx1)" 'ff d8 ff'
expect "the picture is kept a minute" "$(cat "$scratch/drawn.h")" 'max-age=60'
if cmp -s "$scratch/drawn.jpg" "$scratch/card.jpg"; then
	fail "the picture is drawn (it is the card)"
else
	pass "the picture is drawn"
fi
tiles="$(docker exec "$name" cat /tmp/map_tiles.log 2>/dev/null || true)"
expect "its tiles, from the tile server named" "$tiles" '/7/'
expect "its tiles, asked by name" "$tiles" 'tally-map (link previews; +https://github.com/sky-commons/tally)'
count="$(wc -l <<<"$tiles")"
curl -s -o /dev/null "$map/preview/a32806/37.61,-122.38.jpg"
again="$(docker exec "$name" cat /tmp/map_tiles.log | wc -l)"
if ((again == count)); then pass "a tile is fetched once, then cached"; else fail "tiles fetched again: $count, then $again"; fi
curl -s -o "$scratch/far.jpg" "$map/preview/a32806/10.00,10.00.jpg"
if cmp -s "$scratch/far.jpg" "$scratch/card.jpg"; then pass "far from the aircraft, the card"; else fail "far from the aircraft, the card"; fi
curl -s -o "$scratch/none.jpg" "$map/preview/c0ffee/37.62,-122.38.jpg"
if cmp -s "$scratch/none.jpg" "$scratch/card.jpg"; then pass "unheard, the card"; else fail "unheard, the card"; fi
expect "any other picture is the map's 404" "$(status '/preview/a32806/37.6,-122.38.jpg')" '404'

# The short links, their own query carried on, with or without a trailing slash.
expect "hex" "$(status /a32806)" '302 /?icao=a32806'
expect "hex, a trailing slash" "$(status /A32806/)" '302 /?icao=A32806'
expect "~hex" "$(status /~a32806)" '302 /?icao=~a32806'
expect "hex, its query" "$(status '/a32806?zoom=9')" '302 /?icao=a32806&zoom=9'
expect "registration" "$(status /N302PA)" '302 /?reg=N302PA'
expect "registration, a hyphen" "$(status /ei-efz/)" '302 /?reg=ei-efz'
expect "place" "$(status /51.5,-0.12)" '302 /?lat=51.5&lon=-0.12'
expect "place, zoom" "$(status /51.5,-0.12,9)" '302 /?lat=51.5&lon=-0.12&zoom=9'
expect "latitude past 90" "$(status /91,0)" '404'
expect "longitude past 180" "$(status /51.5,181)" '404'
expect "zoom past 20" "$(status /51.5,0,21)" '404'
expect "a page's own file" "$(status /config.js)" '200'
expect "anything else" "$(status /nope.x)" '404'
page="$(get /nope.x)"
expect "the not-found page" "$page" '<h1>Nothing here</h1>'
expect "the not-found page, back to the site" "$page" 'https://tally.skycommons.org/'

# A day's ACARS files and the sort's runs are in the archive alone: no path of /globe_history/ or
# /archive/ serves them, while the day's other files are served.
docker exec "$name" sh -c 'd=/var/globe_history/2026/10/20 && mkdir -p "$d" /var/globe_history/archive/.sorting &&
	for f in acars.jsonl acars.jsonl.gz acars.gaps acars.jsonl.sorting probe.txt; do echo x >"$d/$f"; done &&
	echo x >/var/globe_history/archive/.sorting/run-1'
expect "a day's other files" "$(status /globe_history/2026/10/20/probe.txt)" '200'
for file in acars.jsonl acars.jsonl.gz acars.gaps acars.jsonl.sorting; do
	expect "no $file at /globe_history/" "$(status "/globe_history/2026/10/20/$file")" '404'
done
expect "no sort run at /archive/" "$(status /archive/.sorting/run-1)" '404'
expect "no sort run at /globe_history/" "$(status /globe_history/archive/.sorting/run-1)" '404'
refuse "the listing names no sort run" "$(get /archive/)" '.sorting'
docker exec "$name" sh -c 'echo 1 >/var/globe_history/archive/.acars-read'
expect "no ACARS read time at /archive/" "$(status /archive/.acars-read)" '404'

# readsb taking connections and never answering: the page, its tags without an aircraft; and
# one visitor's previews waiting on it hold no more than its share of the page's slots, so
# another's page files are still served.
docker exec -d "$name" python3 -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 9))
s.listen(64)
held = []
while True:
    held.append(s.accept()[0])'
docker exec "$name" sh -c 'echo "upstream readsb_api { server 127.0.0.1:9; }" >/run/tally-map/readsb.conf && nginx -e stderr -c /etc/tally-map/nginx.conf -s reload' 2>/dev/null
sleep 2
page="$(get '/?icao=a32806')"
expect "readsb silent, the page" "$page" '<meta property="og:description" content="On the map">'
for i in 1 2 3 4 5 6 7 8; do
	curl -s -o /dev/null -w '%{http_code}\n' "$map/?icao=a3280$i" >"$scratch/many.$i" &
done
sleep 0.1
expect "the page's files, while one visitor's previews wait" "$(status /config.js)" '200'
wait
expect "a visitor's previews past its share" "$(cat "$scratch"/many.*)" '503'

# Unset, the tiles are OpenStreetMap's own.
default="tally-map-test-default-$$"
# With TALLY_MAP_ACARS naming a relay that is not there, the collector marks today as missed from
# its start, before the archiver runs, and as it stops keeps when it last read the relay.
docker run -d --name "$default" -e TALLY_MAP_MAX_UPLOAD=8Mbit/s -e TALLY_MAP_IPV6=off \
	-e TALLY_MAP_ACARS=127.0.0.1:9 "$image" >/dev/null
for _ in $(seq 100); do
	docker exec "$default" test -e /run/tally-map/acars.ready 2>/dev/null && break
	sleep 0.1
done
expect "the default tile server is OpenStreetMap's" "$(docker exec "$default" cat /run/tally-map/tiles.conf)" \
	'tile_origin "https://tile.openstreetmap.org";'
expect "the collector is ready" "$(docker exec "$default" ls /run/tally-map)" 'acars.ready'
# Today as the container's clock has it, which is what the collector files by.
today="$(docker exec "$default" date -u +%Y/%m/%d)"
midnight="$(docker exec "$default" sh -c 'echo $(($(date -u +%s) / 86400 * 86400))')"
expect "today is missed from its start" "$(docker exec "$default" cat "/var/globe_history/$today/acars.gaps")" \
	"$midnight - down"
docker stop -t 20 "$default" >/dev/null
refuse "the collector was not killed" "$(docker inspect -f '{{.State.ExitCode}}' "$default")" '137'
docker cp "$default:/var/globe_history/archive/.acars-read" "$scratch/acars-read"
# It never reached the relay, so it last read it, for all it knows, at the start of today.
expect "the last read time is kept" "$(cat "$scratch/acars-read")" "$midnight"
docker rm -f "$default" >/dev/null

# With the pictures off: no preview.py, no /preview/, no tiles, and the site's card as a preview's
# picture; TALLY_MAP_TILES, here not an origin at all, is not read.
off="tally-map-test-off-$$"
docker run -d --name "$off" -p 127.0.0.1::8080 -e TALLY_MAP_MAX_UPLOAD=8Mbit/s -e TALLY_MAP_IPV6=off \
	-e TALLY_MAP_URL=https://map.example.org -e TALLY_MAP_PREVIEWS=off -e TALLY_MAP_TILES=nonsense \
	"$image" >/dev/null
docker cp "$here/map_feed.py" "$off:/tmp/map_feed.py"
docker exec -d "$off" python3 -I /tmp/map_feed.py
map="http://$(docker port "$off" 8080/tcp | head -1)"
for _ in $(seq 60); do
	page="$(get '/?icao=a32806' || true)"
	[[ "$page" == *'og:title" content="TALLY1 · N302PA · PIPER PA-44 Seminole"'* &&
		"$page" == *'og:description" content="3,000 ft"'* ]] && break
	sleep 1
done
expect "no pictures, the title" "$page" '<meta property="og:title" content="TALLY1 · N302PA · PIPER PA-44 Seminole">'
expect "no pictures, the description" "$page" '<meta property="og:description" content="3,000 ft">'
expect "no pictures, the url" "$page" '<meta property="og:url" content="https://map.example.org/?icao=a32806">'
expect "no pictures, the card" "$page" '<meta property="og:image" content="https://map.example.org/card.jpg">'
refuse "no pictures, no picture's path" "$page" '/preview/'
expect "no pictures, the card is served" "$(status /card.jpg)" '200'
expect "no pictures, the short link" "$(status /a32806)" '302 /?icao=a32806'
expect "no pictures, /preview/ is the map's 404" "$(status '/preview/a32806/37.62,-122.38.jpg')" '404'
expect "no pictures, the not-found page" "$(get '/preview/a32806/37.62,-122.38.jpg')" '<h1>Nothing here</h1>'
refuse "no pictures, no preview.py" "$(docker exec "$off" sh -c 'cat /proc/[0-9]*/cmdline | tr "\0" " "')" 'preview.py'
refuse "no pictures, no preview socket" "$(docker exec "$off" ls /run/tally-map)" 'preview.sock'
tile="$(docker exec "$off" python3 -I -c 'import http.client, socket
c = http.client.HTTPConnection("localhost")
c.sock = socket.socket(socket.AF_UNIX)
c.sock.connect("/run/tally-map/tiles.sock")
c.request("GET", "/7/20/49.png")
print(c.getresponse().status)')"
expect "no pictures, the tile server fetches nothing" "$tile" '404'
expect "no pictures, still running" "$(docker inspect -f '{{.State.Running}}' "$off")" 'true'
docker rm -f "$off" >/dev/null

# Anything but on or off is refused, as the other switches are.
bad=0
docker run --rm -e TALLY_MAP_MAX_UPLOAD=8Mbit/s -e TALLY_MAP_IPV6=off -e TALLY_MAP_PREVIEWS=yes \
	"$image" >/dev/null 2>"$scratch/bad" || bad=$?
if ((bad == 64)); then pass "TALLY_MAP_PREVIEWS=yes exits 64"; else fail "TALLY_MAP_PREVIEWS=yes exits $bad"; fi
expect "TALLY_MAP_PREVIEWS=yes, why" "$(cat "$scratch/bad")" "TALLY_MAP_PREVIEWS is 'yes'; it is on or off"

if ((failures > 0)); then
	echo "$failures failed" >&2
	exit 1
fi
echo "all passed"
