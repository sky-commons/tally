#!/usr/bin/env python3
"""Builds the map image's aircraft database from open sources (packaging/map/README.md).

Reads Mictronics' aircraft database exports (ODC Attribution License) and OurAirports' airports
(public domain), and writes the two forms the map reads:

- readsb's --db-file, a gzipped CSV of one line per aircraft, `;` separated, each line ending in
  `;` (readsb's aircraft.c, updateDetails):

      icao;registration;type code;flags;description;year;owner;

  icao is six upper-case hex digits and the file is sorted by it. flags is a string of 0 and 1,
  one character a flag, in readsb's dbFlags order: military, interesting, PIA, LADD. Mictronics
  carries the first two; no open source carries PIA or LADD, so they are never set here. readsb
  also marks the military address blocks as military itself. description is the type's long name
  (Mictronics' ICAO type list), or the aircraft's own description where the type is a generic
  one (a glider, a balloon, a drone, ...) or unknown. year and owner are empty: no source here
  carries them.

- tar1090's browser database (the directory tar1090's index.html names as databaseFolder), each
  file gzipped as tar1090 serves it (nginx.conf, the db-*.js location):
    <prefix>.js            aircraft by address, {rest of address: [reg, type, flags, description]},
                           split by the next hex digit (a "children" list) past BLOCK_LIMIT entries
    files.js               the names of those blocks
    regIcao.js             {registration without dashes: address}
    icao_aircraft_types2.js {type code: [long name, ICAO description, wake category]}
    operators.js           {ICAO operator code: {"n": name, "c": country, "r": radio callsign}}
    airport-coords.js      {ICAO or IATA code: [lat, lon]}
    ranges.js              {"military": []}; the live map takes military from readsb

Usage: aircraft_db.py MICTRONICS_OLD_DIR MICTRONICS_NEW_DIR AIRPORTS_CSV OUT_DIR
  MICTRONICS_OLD_DIR  indexedDB_old.zip unpacked (aircrafts.json, operators.json)
  MICTRONICS_NEW_DIR  indexedDB.zip unpacked (types.json, [long name, description, wake])
  AIRPORTS_CSV        OurAirports' airports.csv
  OUT_DIR             gets aircraft.csv.gz and db/

Every output is a function of the inputs alone (sorted keys, gzip with no name or time), so one
pinned input makes one image.
"""

import csv
import gzip
import json
import re
import sys
from pathlib import Path

# tar1090-db's block size: a block past this many entries splits by the next digit.
BLOCK_LIMIT = 24576

# Type codes that name a kind of aircraft, not a model, where the aircraft's own description says
# more than the type list's long name (tar1090-db's toJson.py, useLongName).
GENERIC_TYPES = {
    "ZZZZ", "SHIP", "BALL", "GLID", "ULAC", "GYRO", "UHEL", "TWR", "GND", "PARA", "DRON", "EMER",
    "SERV",
}

ADDRESS = re.compile(r"^[0-9A-F]{6}$")


def clean(value):
    """A field as readsb's CSV can hold it: no separator, no line break, no surrounding space."""
    if value is None:
        return ""
    text = str(value)
    text = text.replace(";", ",").replace("\r", " ").replace("\n", " ").replace("\\", "")
    return text.strip()


def write_gzip(path, data):
    with open(path, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as out:
            out.write(data)


def write_json_gzip(path, obj):
    text = json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    write_gzip(path, text.encode("utf-8"))


def load_aircraft(old_dir, types):
    with open(old_dir / "aircrafts.json", encoding="utf-8") as f:
        raw = json.load(f)
    aircraft = {}
    for key, entry in raw.items():
        address = key.strip().upper()
        if not ADDRESS.match(address):
            continue
        reg = clean(entry.get("r"))
        type_code = clean(entry.get("t")).upper()
        flags = clean(entry.get("f"))
        flags = "".join("1" if c == "1" else "0" for c in flags[:2]).ljust(2, "0")
        description = clean(entry.get("d"))
        known = types.get(type_code)
        if type_code not in GENERIC_TYPES and known and clean(known[0]):
            description = clean(known[0])
        aircraft[address] = (reg, type_code, flags, description)
    return aircraft


def write_readsb_csv(path, aircraft):
    lines = []
    for address in sorted(aircraft):
        reg, type_code, flags, description = aircraft[address]
        lines.append(f"{address};{reg};{type_code};{flags};{description};;;\n")
    write_gzip(path, "".join(lines).encode("utf-8"))


def write_blocks(db_dir, aircraft):
    blocks = {f"{i:X}": {} for i in range(16)}
    for address, (reg, type_code, flags, description) in aircraft.items():
        blocks[address[0]][address[1:]] = [reg or None, type_code or None, flags, description or None]

    written = []
    queue = sorted(blocks)
    while queue:
        prefix = queue.pop(0)
        entries = blocks[prefix]
        if len(entries) > BLOCK_LIMIT:
            children = {}
            for rest, value in entries.items():
                children.setdefault(prefix + rest[0], {})[rest[1:]] = value
            entries = {"children": sorted(children)}
            for child in sorted(children):
                blocks[child] = children[child]
                queue.append(child)
        write_json_gzip(db_dir / f"{prefix}.js", entries)
        written.append(prefix)
    write_json_gzip(db_dir / "files.js", sorted(written))


def write_airports(path, airports_csv):
    with open(airports_csv, encoding="utf-8", newline="") as f:
        rows = [row for row in csv.DictReader(f) if row.get("latitude_deg") and row.get("longitude_deg")]
    coords = {}

    def place(code, row):
        coords[code] = [round(float(row["latitude_deg"]), 4), round(float(row["longitude_deg"]), 4)]

    # ICAO codes first, without the numbered ones (small fields, as tar1090-db leaves out); an
    # IATA code, the one a traveller types, then takes its key over.
    for row in rows:
        code = row.get("icao_code", "").strip().upper()
        if code and not re.search(r"\d", code):
            place(code, row)
    for row in rows:
        code = row.get("iata_code", "").strip().upper()
        if code:
            place(code, row)
    write_json_gzip(path, coords)


def main(argv):
    if len(argv) != 5:
        sys.stderr.write(__doc__)
        return 2
    old_dir, new_dir, airports_csv, out_dir = (Path(a) for a in argv[1:])
    db_dir = out_dir / "db"
    db_dir.mkdir(parents=True, exist_ok=True)

    with open(new_dir / "types.json", encoding="utf-8") as f:
        types = {k.strip().upper(): v for k, v in json.load(f).items()}
    with open(old_dir / "operators.json", encoding="utf-8") as f:
        operators = json.load(f)

    aircraft = load_aircraft(old_dir, types)
    if len(aircraft) < 100000:
        sys.stderr.write(f"only {len(aircraft)} aircraft read; the source is not what it was\n")
        return 1

    write_readsb_csv(out_dir / "aircraft.csv.gz", aircraft)
    write_blocks(db_dir, aircraft)
    write_json_gzip(db_dir / "regIcao.js", {r.replace("-", ""): a for a, (r, *_rest) in aircraft.items() if r})
    write_json_gzip(db_dir / "icao_aircraft_types2.js", types)
    write_json_gzip(db_dir / "operators.js", operators)
    write_json_gzip(db_dir / "ranges.js", {"military": []})
    write_airports(db_dir / "airport-coords.js", airports_csv)

    print(f"{len(aircraft)} aircraft, {len(types)} types, {len(operators)} operators")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
