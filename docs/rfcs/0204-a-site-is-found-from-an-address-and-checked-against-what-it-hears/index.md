# RFC-0204: A site is found from an address, and checked against what it hears

- Status: proposed, for this review (2026-11-03)
- Amends: RFC-0181 §9 (who takes part in an area's MLAT: one more reason a receiver takes none)
- Founder direction, 2026-11-03: build an easier location setup for feeders (hobbyists know neither
  their coordinates nor their height above the ellipsoid), and a check on the relay that flags a
  receiver whose site does not fit what it hears.

## §0 The decision

Two parts, each small:

- **The installer finds the site from an address** (§2). `install.sh --locate`, or
  `TALLY_ADDRESS="..."`, geocodes an address on the owner's own box, looks up the ground's
  elevation, asks how high the antenna is, and turns that into height above the WGS84 ellipsoid
  with a geoid grid that ships with the release. Tally never sees the address.
- **The relay checks the site against the aircraft the receiver itself decodes** (§3). A
  receiver whose claimed site cannot be where it hears from is held out of MLAT (its data still
  feeds the map), and its station page says "location looks wrong by about N km", with a hint to
  rerun `install.sh --locate`.

## §1 Why

MLAT needs each antenna's position to within about 10 m, and its height above the WGS84 ellipsoid
(`--alt`; `install.sh` asks for it). Hobbyists do not know either. Our own home receiver,
tally-pi, ran for days with a guessed location 45 km off, and nothing noticed. It was fixed by
hand: the Census geocoder and OSM Nominatim for the coordinates (they agreed to about 5 m), USGS
EPQS for the ground (NAVD88), plus the antenna's height, less the GEOID18 geoid height. §2 makes
that the installer's work. §3 makes the network notice when it was not done, or was done wrong.

## §2 The installer finds the site

**When.** Interactively, when no source holds a location (the questions today ask for decimal
degrees), or when the owner passes `--locate`: it asks for an address first and falls back to
coordinates. Non-interactively, `TALLY_ADDRESS`. `TALLY_LAT` and `TALLY_LON` still win; given
both, the install stops and says to give one. An automatic update (`--upgrade`) never locates: it
asks nothing and keeps the location the install has, as today.

**Geocoding.** The US Census geocoder first (US addresses only; it matches nothing elsewhere),
then OSM Nominatim: as the check on a Census match, or alone for an address outside the US.
Nominatim's usage policy is kept: a User-Agent naming the installer and the repository's issues
as contact, at most one request a second, and the attribution printed with the result. Two matches
more than 50 m apart are shown as such and the Census one is used.

**Elevation.** USGS EPQS (3DEP, NAVD88) where the Census matched, Open-Meteo's elevation API
(Copernicus DEM GLO-90, EGM2008 heights) elsewhere or when EPQS answers nothing.

**Height above the ellipsoid.** The ground's height, plus the antenna's height above the ground
(one question: by a window or on the ground floor, about 2 m; upstairs, about 5 m; on the roof,
about 8 m; or a number; or `TALLY_ANTENNA=window|upstairs|roof|<metres>`), plus the geoid
height N at the site. N comes from `geoid.txt`, a global EGM2008 grid published with each release
like every other file, with its `.sha256` and its signature (RFC-0203 §3), read with awk. No
service is asked for it. (Its accuracy against NGS GEOID18 is in the PR that adds it.)

**Shown and confirmed.** The result is shown as coordinates, the ground, the antenna and the
ellipsoid height, with an OpenStreetMap link to the point; interactively the owner confirms it.
`TALLY_ALT` given with an address overrides the altitude found.

**Readsb.** When readsb is installed and has no location of its own, the owner is offered (asked,
interactively only) to set `--lat` and `--lon` in `/etc/default/readsb` too, with a backup beside
it. Readsb is never changed without that answer.

**Privacy.** One line says that the address goes only to the Census geocoder or OpenStreetMap
and to the elevation service, never to Tally. The address is never printed, logged or stored:
it reaches curl on its standard input, not on a command line a process list or the journal shows,
and only the coordinates are kept, in `/etc/default/tally-feed`, as today.

**Failure.** Any lookup that fails (no match, no answer, a malformed reply) says so and falls
back to today's questions; non-interactively the install stops naming `TALLY_LAT`, `TALLY_LON` and
`TALLY_ALT`. All of it happens before anything is installed, so nothing half-installs.

**Upgrades.** Nothing migrates: the location is kept as before, and `//packaging:upgrade_test`
holds every earlier install to that. `geoid.txt.gz` is fetched only when locating.

## §3 The relay checks the site

**Signal.** A relay already decodes each receiver's own airborne positions (a global CPR decode
of an even and an odd position it heard, `figures`). For each receiver with a site, it keeps what
those positions say around the claimed site, for the last 12 to 24 hours by the batches' own signed
clocks: a grid of 5 km cells within 100 km, and bins by compass sector and distance beyond. Each
cell holds a count, the lowest altitude heard and 16 bits of which aircraft; nothing is kept of
when or exactly where. About 13 KiB a receiver, charged in its figures row.

**The judgment** (every 10 minutes), three tests a correct site passes by a wide margin:

- *Horizon.* Positions farther than the radio horizon of an aircraft at their altitude and an
  antenna 100 m above the claimed altitude (with 10% and 20 km to spare) cannot be heard from the
  claimed site. Enough of them (three bins, three aircraft, 5% of what it hears past 100 km) make
  the site wrong. This catches errors of about a hundred kilometres and more for any receiver.
- The other two apply only to a site *outside* what the receiver hears: every position, near or
  far, within four of its eight compass sectors. A receiver that hears all round its site, however
  far off the nearest traffic, is never found wrong by them.
- *Near field.* A receiver hears the aircraft close to it on every side, whatever its antenna: one
  within 25 km is tens of decibels louder than one at the edge of its range. So a correct site is
  surrounded by positions within 25 km in at least 5 of 8 compass sectors. A site is wrong when it
  has positions in at most 3, the nearest are at least 15 km away, and a place at least 25 km off
  is surrounded on 7 sectors by at least 8 aircraft. This catches an error larger than the
  receiver's reach: a few tens of kilometres for the quiet indoor setups most hobbyists start with.
- *Nothing near.* Nothing heard within 60 km, from 60 positions or more: the site is about as far
  off as the typical position. This catches a quiet receiver whose site is too far off for its
  near field to land in the grid (a mistyped degree).
- Anything else is *unjudged*, never wrong: too little heard (under 15 aircraft), or a receiver
  that hears no traffic near its site and nowhere surrounded either.

A busy receiver that hears 300 km all round and is 45 km off is surrounded at the claimed site too,
and is not caught; nor is one off by less than its own reach. Only signal strength could tell
those, and that is left for later (§6).

**Held wrong** after three judgments in a row (half an hour), taken back after three that are not
wrong, and at once when the receiver signs a site more than a kilometre from the one judged
(what was kept starts over).

**Out of MLAT.** A receiver held wrong takes no part in MLAT, as a receiver that declared no
site takes none (`Intake::set_misplaced`): its seat goes to the next ranked, its raw is let go
from the engine. Its batches still reach the map, the products and every other duty. This amends
RFC-0181 §9: taking part was the receiver's own signed word alone. The check is this relay's own
judgment, so two relays holding one area can disagree about a receiver while what each heard of
it differs (one restarted). They solve the same bytes again once they agree. That costs only the
corroboration of fixes using that receiver, whose site is wrong anyway.

**Said.** `GET /stations` (loopback) gives each receiver a `location_check`: `fits`, `unjudged`,
or `wrong` with `off_km`, the distance to the place the near field found (or how far past the
horizon) in steps of 5 km. tally-api serves it on `GET /v1/stations/{key}`; the station page shows
"location looks wrong by about N km" and how to fix it. The place the relay thinks the receiver is
at, and which way it is off, are never said: a distance in 5 km steps from a site the public sees
only as its cell narrows nothing to finer than the cell.

## §4 What it does not do

- It never changes a feeder's configuration: the owner reruns the installer.
- It never rejects a receiver: a wrong site only keeps it out of MLAT (RFC-0203 §5's rule for
  feeders that cannot be used for MLAT).
- It does not judge the altitude: an altitude error of tens of metres is below what aircraft
  positions can show.

## §5 Tests

- `siting::tests`: simulated skies about as dense as the Bay Area's, and receivers of every kind
  (quiet indoor, a window, a rooftop to the horizon, hills blocking one side, one with no traffic
  near it): no correct site is ever held wrong; a quiet receiver 45 km off (tally-pi's first
  site, 37.66, −121.87), 50 km off in every direction, and 120 to 300 km off is; a rooftop 350 km
  off is past the horizon.
- `hub::tests`: a receiver fed through the relay with a site in London and positions 330 km off is
  reported wrong after three judgments, and its batches are still forwarded.
- `intake::tests`: a receiver held wrong takes no part, its seat goes to the next, and it comes
  back on its own site.
- The PR records the check on real receptions: tally-pi now (correct), tally-pi's receptions
  against its old guessed site, and KLAX-1 after the deploy.
- `//packaging:install_test` holds the installer's lookups (stubbed services), the privacy rules
  (the address on no command line and in no file) and the fallbacks; `//packaging:upgrade_test`
  holds the earlier installs.

## §6 Open questions

- Signal strength. The receptions carry it, and the strongest come from the nearest aircraft
  whatever the antenna, which would also catch a busy receiver tens of kilometres off. Decoders
  scale it differently and some send none, so it needs measuring on more receivers first.
- Whether to tell the owner directly (the feeder could log the relay's verdict). Today only the
  station page says it.

## §7 Amendment, 2026-11-04 (v0.7.5): every altitude given is above sea level

A fresh-eyes walkthrough found the datum mixed. `--alt` is the height above the WGS84 ellipsoid
(mlat-client's too), but everything a hobbyist or their setup gives is above sea level: adsb.im's
`FEEDER_ALT_M` is "Altitude above mean sealevel", ultrafeeder's `ALT` and `READSB_ALT` are entered
the same way, and the installer passed them through, about 30 m off in California and 46 m in
London. Decided:

- **The installer** takes every altitude typed (`TALLY_ALT`, the terminal) or read from a setup as
  above sea level, and adds N from `geoid.txt.gz` (now fetched whenever it converts, and signed
  with the release as before). The block records the converted value and says so ("16 m above
  sea level, and the geoid there, -32.53 m (EGM2008): metres above the WGS84 ellipsoid").
- **Upgrades still migrate nothing.** What an earlier run wrote is kept exactly, by every rerun
  and automatic update, while the location is the one it was written for and no `TALLY_ALT` or
  address names another; its provenance line is carried along. A pre-v0.7.5 value from a
  sea-level source is left as it was, with a note saying how to convert it (`TALLY_ALT=` the
  same value): converting it unasked would move a working receiver's altitude by itself.
  `//packaging:upgrade_test` holds this with an adsb.im setup on the box naming another altitude.
- **The container** keeps `ALT` (and `READSB_ALT`) as it was, above the ellipsoid as mlat-client
  takes it, since running containers follow `:0`; `ALT_MSL` (and `--alt-msl`) is new, converted by
  the same grid compiled into `tally-feed`, and the documented snippet uses
  `ALT_MSL=${FEEDER_ALT_M}m`. An expert's known ellipsoidal height stays `--alt`.
