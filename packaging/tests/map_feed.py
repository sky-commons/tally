# A relay's --beast-out for the map image's test (map.sh): a BEAST server on 127.0.0.1:30105 that
# sends, five times a second until it is stopped, ADS-B messages of two aircraft, each its
# identification and an even and an odd airborne position (so readsb decodes where it is):
#
#   a32806  TALLY1  at 37.62, -122.38, 3,000 ft
#   ae0001  MIL1    at 51.47, -0.45, 36,000 ft
import math
import socket
import time

AIRCRAFT = [(0xA32806, "TALLY1", 37.62, -122.38, 3000), (0xAE0001, "MIL1", 51.47, -0.45, 36000)]
POLY = 0xFFF409
CHARS = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"


def crc(message):
    r = 0
    for byte in message:
        r ^= byte << 16
        for _ in range(8):
            r <<= 1
            if r & 0x1000000:
                r ^= POLY
    return r & 0xFFFFFF


def extended(address, me):
    message = bytes([0x8D]) + address.to_bytes(3, "big") + me.to_bytes(7, "big")
    return message + crc(message).to_bytes(3, "big")


def identification(address, callsign):
    me = 4 << 51
    for i, c in enumerate(callsign.ljust(8)):
        me |= CHARS.index(c) << (42 - 6 * i)
    return extended(address, me)


def nl(lat):
    """The number of longitude zones at a latitude (DO-260B's NL)."""
    if abs(lat) >= 87:
        return 1
    a = 1 - math.cos(math.pi / 30)
    return math.floor(2 * math.pi / math.acos(1 - a / math.cos(math.pi / 180 * lat) ** 2))


def position(address, lat, lon, altitude, odd):
    """An airborne position (type code 11) in compact position reporting, even or odd."""
    dlat = 360 / (60 - odd)
    yz = math.floor(2**17 * (lat % dlat) / dlat + 0.5)
    rlat = dlat * (yz / 2**17 + math.floor(lat / dlat))
    dlon = 360 / max(nl(rlat) - odd, 1)
    xz = math.floor(2**17 * (lon % dlon) / dlon + 0.5)
    n = (altitude + 1000) // 25
    alt = ((n & 0x7F0) << 1) | 0x10 | (n & 0xF)
    me = 11 << 51 | alt << 36 | odd << 34 | (yz % 2**17) << 17 | (xz % 2**17)
    return extended(address, me)


def beast(message):
    frame = bytes([0x33]) + b"\x00" * 6 + b"\x80" + message
    return b"\x1a" + frame.replace(b"\x1a", b"\x1a\x1a")


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 30105))
server.listen(1)
while True:
    connection, _ = server.accept()
    try:
        while True:
            for address, callsign, lat, lon, altitude in AIRCRAFT:
                connection.sendall(
                    beast(identification(address, callsign))
                    + beast(position(address, lat, lon, altitude, 0))
                    + beast(position(address, lat, lon, altitude, 1))
                )
            time.sleep(0.2)
    except OSError:
        connection.close()
