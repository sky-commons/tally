# A tile server for the map image's test (map.sh), so the test fetches nothing from
# OpenStreetMap: on 127.0.0.1:8089, one fixed 256-pixel PNG for any /{z}/{x}/{y}.png, and 404 for
# anything else. Each tile asked for is written to /tmp/map_tiles.log with the User-Agent that asked.
import io
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

from PIL import Image

out = io.BytesIO()
Image.new("RGB", (256, 256), (170, 211, 223)).save(out, "PNG")
TILE = out.getvalue()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not re.fullmatch(r"/\d+/\d+/\d+\.png", self.path):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        with open("/tmp/map_tiles.log", "a") as log:
            log.write(f"{self.path} {self.headers.get('User-Agent')}\n")
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(TILE)))
        self.end_headers()
        self.wfile.write(TILE)

    def log_message(self, format, *args):
        pass


HTTPServer(("127.0.0.1", 8089), Handler).serve_forever()
