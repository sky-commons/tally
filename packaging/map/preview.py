# A link's picture (RFC-0187 §3; README.md, "Short links and previews"): the map around one
# aircraft's position with one marker on it, drawn by komoot's staticmap (Apache-2.0) over
# OpenStreetMap's tiles, which nginx fetches and caches (nginx.conf, the tile server). nginx sends it
# GET /preview/<hex>/<lat>,<lon>.jpg, the position preview.lua put in the page, rounded to 0.01
# degrees; it caches each answer a minute, and this server draws one at a time with two more
# waiting, so at most one map is in memory.
#
# It draws only a position near where readsb hears the aircraft now (within MAX_DRIFT), so nobody can
# have it draw anywhere they like; anything else is 404, and nginx answers the site's card instead.
# The aircraft's position is public (the map shows it to anyone); readsb has no receiver, and
# nothing of one is read here.
#
#   preview.py serve SOCKET TILE_SOCKET READSB_API   the server, on a Unix socket
#   preview.py card FILE                             the site's card, at build
import http.client
import json
import re
import resource
import socket
import socketserver
import sys
from http.server import BaseHTTPRequestHandler
from io import BytesIO

from PIL import Image, ImageDraw, ImageFont
from staticmap import CircleMarker, StaticMap

WIDTH, HEIGHT = 1200, 630
ZOOM = 7
QUALITY = 80
MAX_DRIFT = 1.0
# The most address space the server may take: a map takes about 75 MB at its peak, and its four
# tile threads' stacks and allocator arenas reserve far more than they use. Past it a picture fails
# (and is answered the site's card) rather than the host running short.
ADDRESS_SPACE = 768 * 1024 * 1024
SKY = "#0b8ab8"
CREDIT = "© OpenStreetMap contributors"
PATH = re.compile(r"^/preview/(~?[0-9a-f]{6})/(-?\d{1,2}\.\d{2}),(-?\d{1,3}\.\d{2})\.jpg$")


class UnixConnection(http.client.HTTPConnection):
    """HTTP over a Unix socket: nginx's tile server."""

    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Map(StaticMap):
    """staticmap's map, its tiles asked of nginx's cache rather than of the tile server."""

    def __init__(self, tiles):
        super().__init__(WIDTH, HEIGHT, url_template="/{z}/{x}/{y}.png", tile_request_timeout=10)
        self.tiles = tiles

    def get(self, url, **kwargs):
        connection = UnixConnection(self.tiles, 10)
        try:
            connection.request("GET", url)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()


def heard(readsb, hex):
    """Where readsb hears `hex` now, (lat, lon), or None."""
    host, _, port = readsb.rpartition(":")
    connection = http.client.HTTPConnection(host.strip("[]"), int(port), timeout=1)
    try:
        connection.request("GET", f"/?find_hex={hex}&jv2")
        response = connection.getresponse()
        if response.status != 200:
            return None
        aircraft = json.loads(response.read()).get("ac") or []
    except (OSError, ValueError):
        return None
    finally:
        connection.close()
    for each in aircraft:
        lat, lon = each.get("lat"), each.get("lon")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            return lat, lon
    return None


def font(size):
    return ImageFont.load_default(size)


def credit(image):
    """The tiles' attribution, as OpenStreetMap's tile policy asks of every image drawn from them."""
    draw = ImageDraw.Draw(image, "RGBA")
    face = font(16)
    left, top, right, bottom = draw.textbbox((0, 0), CREDIT, font=face)
    x, y = WIDTH - (right - left) - 12, HEIGHT - (bottom - top) - 10
    draw.rectangle((x - 6, y - 5, WIDTH, HEIGHT), fill=(255, 255, 255, 200))
    draw.text((x - left, y - top), CREDIT, font=face, fill=(51, 51, 51))


def picture(tiles, lat, lon):
    drawn = Map(tiles)
    drawn.add_marker(CircleMarker((lon, lat), "white", 30))
    drawn.add_marker(CircleMarker((lon, lat), SKY, 20))
    image = drawn.render(zoom=ZOOM, center=(lon, lat))
    credit(image)
    return jpeg(image)


def jpeg(image):
    out = BytesIO()
    image.convert("RGB").save(out, "JPEG", quality=QUALITY, optimize=True)
    return out.getvalue()


def card():
    """The site's card: Tally's mark and name, for a link with no aircraft to draw."""
    image = Image.new("RGB", (WIDTH, HEIGHT), "#111113")
    draw = ImageDraw.Draw(image)
    x, y, r = 300, HEIGHT // 2, 120
    draw.ellipse((x - r, y - r, x + r, y + r), fill=SKY)
    ring = r * 9 // 15
    draw.ellipse((x - ring, y - ring, x + ring, y + ring), outline="white", width=16)
    dot = r * 3 // 15
    draw.ellipse((x - dot, y - dot, x + dot, y + dot), fill="white")
    draw.text((480, y - 20), "Tally", font=font(150), fill="white", anchor="ls")
    draw.text((486, y + 60), "Live aircraft map", font=font(48), fill="#b0b4ba", anchor="ls")
    return jpeg(image)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        match = PATH.match(self.path)
        if not match:
            return self.answer(404)
        hex, lat, lon = match.group(1), float(match.group(2)), float(match.group(3))
        now = heard(self.server.readsb, hex)
        if now is None or abs(now[0] - lat) > MAX_DRIFT or abs(now[1] - lon) > MAX_DRIFT:
            return self.answer(404)
        try:
            body = picture(self.server.tiles, lat, lon)
        except Exception as error:  # a tile that never came, not an image, or memory
            print(f"tally-map: could not draw {hex}: {error}", file=sys.stderr)
            return self.answer(502)
        self.answer(200, body)

    def answer(self, status, body=b""):
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "image/jpeg")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def address_string(self):
        return "nginx"

    def log_message(self, format, *args):
        pass


class Server(socketserver.UnixStreamServer):
    """One request at a time, two more waiting: one map in memory at most."""

    request_queue_size = 2

    def __init__(self, path, tiles, readsb):
        super().__init__(path, Handler)
        self.tiles = tiles
        self.readsb = readsb


def main(argv):
    if len(argv) == 5 and argv[1] == "serve":
        resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE, ADDRESS_SPACE))
        Server(argv[2], argv[3], argv[4]).serve_forever()
    elif len(argv) == 3 and argv[1] == "card":
        with open(argv[2], "wb") as out:
            out.write(card())
    else:
        sys.exit("usage: preview.py serve SOCKET TILE_SOCKET READSB_API | card FILE")


if __name__ == "__main__":
    main(sys.argv)
