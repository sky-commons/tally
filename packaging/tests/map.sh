#!/bin/bash
# The map image's test (packaging/map; RFC-0187 §1 and §3): builds the image, runs it fed by
# map_feed.py (two aircraft over a stand-in --beast-out, inside the container), and checks what a
# visitor and a link's preview get over HTTP. It needs Docker, so it runs in CI's map job
# (.github/workflows/ci.yml), not under Bazel, whose tests have no Docker.
#
#   packaging/tests/map.sh            build the image from packaging/map, then test it
#   packaging/tests/map.sh IMAGE      test an image already built
#
# It fetches nothing from outside: the pictures' tiles come from map_tiles.py, a stand-in tile
# server in the container (TALLY_MAP_TILES), and one check reads that the image's default is
# OpenStreetMap's own.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
image="${1:-}"
if [[ -z "$image" ]]; then
	image=tally-map-test:local
	docker build -q -t "$image" "$here/../map" >/dev/null
fi

name="tally-map-test-$$"
scratch="$(mktemp -d)"
cleanup() {
	docker rm -f "$name" >/dev/null 2>&1 || true
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
docker run -d --name "$default" -e TALLY_MAP_MAX_UPLOAD=8Mbit/s -e TALLY_MAP_IPV6=off "$image" >/dev/null
sleep 2
expect "the default tile server is OpenStreetMap's" "$(docker exec "$default" cat /run/tally-map/tiles.conf)" \
	'tile_origin "https://tile.openstreetmap.org";'
docker rm -f "$default" >/dev/null

if ((failures > 0)); then
	echo "$failures failed" >&2
	exit 1
fi
echo "all passed"
