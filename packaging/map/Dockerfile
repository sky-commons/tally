# The map bundle (RFC-0187 §1; packaging/map/README.md): readsb, tar1090 and nginx, which a relay
# operator runs beside a relay to serve a full map of what the relay's --beast-out carries, and
# readsb's query API, which tally-api --readsb reads. The release builds it for linux/amd64 and
# linux/arm64 on its tag and pushes it as ghcr.io/sky-commons/tally-map:<tag>, signed like
# tally-feed's image.
#
#   docker buildx build --platform linux/amd64,linux/arm64 --build-context dist=dist \
#     -f packaging/map/Dockerfile packaging/map
#
# The one program of ours in it, tally-acars-collect (crates/acars-collect), is never built here:
# it comes from the build context `dist`, a directory holding tally-acars-collect-ARCH-linux. The
# release passes its own dist/, the signed binaries; packaging/tests/map.sh one Bazel just built.
#
# Every input is pinned: the Debian base by digest, Debian's packages by a snapshot of the archive
# (and of its security updates) at one date and readsb, nginx, its Lua module, lua-cjson and tini
# by version in it, tar1090 by commit and the tarball's sha256, and the aircraft database's sources
# by commit and sha256.

# Debian 13 (trixie), slim, pinned by the digest of its multi-arch index
# (`docker buildx imagetools inspect debian:trixie-slim`, 2026-10-05); the tag says which image the
# digest is.
ARG DEBIAN=debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# tar1090 (GPL-2.0-or-later), github.com/wiedehopf/tar1090, unmodified, at this commit (its
# version file says 3.14.1824).
ARG TAR1090_COMMIT=958e60e583c4e435de1b46526bf5392fe05728ad
ARG TAR1090_SHA256=d4445a067097aad64a5178ea0c96233bd9a5293e6f6914460eaee446db3384ab

# Mictronics' aircraft database (ODC Attribution License, ODC-By 1.0),
# github.com/Mictronics/aircraft-database, at this commit (its update of 2026-10-18,
# dbversion 527).
ARG MICTRONICS_COMMIT=e7ff3f1474334b3f00d50a6661ef1c16754721a5
ARG MICTRONICS_OLD_SHA256=bf0a9135b4915503930f7c6432cb25ce82cc5daa3e20cdfcd2ab5daeee77ed09
ARG MICTRONICS_NEW_SHA256=49d5c4cd5f3d89a4cba2e0cf3018e43d5f1caf9e851a2050175693a64b748a43

# OurAirports' airports (public domain, The Unlicense), github.com/davidmegginson/ourairports-data,
# at this commit (2026-10-16).
ARG OURAIRPORTS_COMMIT=b529623d2a0b09a9be78d37fc7a7a5e1e16e3451
ARG OURAIRPORTS_SHA256=0499dbd88de2fc735ac5c09f59796ccc3af544e17ffda807f793c0c6fe6c3d75

# readsb as Debian 13 packages it (source package readsb, from github.com/adsbfi/readsb, a
# fork of wiedehopf's readsb; GPL-3.0-or-later among its options, see its copyright file).
ARG READSB_VERSION=3.14.1630+git20240609.adc080d-1
ARG NGINX_VERSION=1.26.3-3+deb13u9
ARG TINI_VERSION=0.19.0-3+b8
# nginx's Lua module and Lua's JSON, Debian 13's packages, for the link previews (preview.lua).
ARG NGINX_LUA_VERSION=1:0.10.28-2
ARG LUA_CJSON_VERSION=2.1.0+dfsg-2.2+b2
# Their pictures (preview.py): Pillow and requests, which staticmap draws with, Debian 13's, and
# the certificates nginx checks OpenStreetMap's tile server by.
ARG PYTHON_PIL_VERSION=11.1.0-5+deb13u4
ARG PYTHON_REQUESTS_VERSION=2.32.3+dfsg-5+deb13u1
ARG CA_CERTIFICATES_VERSION=20250419

# komoot's staticmap (Apache-2.0), github.com/komoot/staticmap, the wheel PyPI publishes of 0.5.7,
# unmodified.
ARG STATICMAP_VERSION=0.5.7
ARG STATICMAP_SHA256=f4ffc40ee4502b92e91045e0df85a46a2fd68483b4e7e404a6b545fd7396ea01

# Debian's archive and its security updates as snapshot.debian.org kept them at this instant, so
# every package above stays installable at its version after Debian moves on. A snapshot's
# Release files are past their Valid-Until, which is expected of a snapshot and nothing else.
ARG DEBIAN_SNAPSHOT=20261005T000000Z

# Docker names the architecture amd64 or arm64, the release x86_64 or aarch64: a stage each, and
# `FROM collect-${TARGETARCH}` picks one (packaging/container/Dockerfile says why).
ARG TARGETARCH

FROM scratch AS collect-amd64
COPY --from=dist tally-acars-collect-x86_64-linux /tally-acars-collect

FROM scratch AS collect-arm64
COPY --from=dist tally-acars-collect-aarch64-linux /tally-acars-collect

FROM collect-${TARGETARCH} AS collect

# The web root and the database are the same bytes for every platform, so they are made once,
# on the build's own platform, with no emulation.
FROM --platform=$BUILDPLATFORM ${DEBIAN} AS web
ARG DEBIAN_SNAPSHOT
ARG TAR1090_COMMIT
ARG TAR1090_SHA256
ARG MICTRONICS_COMMIT
ARG MICTRONICS_OLD_SHA256
ARG MICTRONICS_NEW_SHA256
ARG OURAIRPORTS_COMMIT
ARG OURAIRPORTS_SHA256
COPY --chmod=0755 debian-snapshot.sh /usr/local/bin/debian-snapshot
RUN debian-snapshot "$DEBIAN_SNAPSHOT" \
  && apt-get update \
  && apt-get install -y --no-install-recommends python3 \
  && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:${TAR1090_SHA256} \
  https://github.com/wiedehopf/tar1090/archive/${TAR1090_COMMIT}.tar.gz /src/tar1090.tar.gz
ADD --checksum=sha256:${MICTRONICS_OLD_SHA256} \
  https://raw.githubusercontent.com/Mictronics/aircraft-database/${MICTRONICS_COMMIT}/indexedDB_old.zip /src/indexedDB_old.zip
ADD --checksum=sha256:${MICTRONICS_NEW_SHA256} \
  https://raw.githubusercontent.com/Mictronics/aircraft-database/${MICTRONICS_COMMIT}/indexedDB.zip /src/indexedDB.zip
ADD --checksum=sha256:${OURAIRPORTS_SHA256} \
  https://raw.githubusercontent.com/davidmegginson/ourairports-data/${OURAIRPORTS_COMMIT}/airports.csv /src/airports.csv
COPY aircraft_db.py /usr/local/bin/aircraft_db.py
COPY ATTRIBUTION.in /src/ATTRIBUTION.in

# The database: readsb's aircraft.csv.gz and tar1090's browser database, from the sources above
# (aircraft_db.py says how), its licence, and the ATTRIBUTION file the archiver puts in each day's
# archive (entrypoint.sh).
RUN set -eu; \
  mkdir -p /src/mic-old /src/mic-new /out; \
  python3 -I -m zipfile -e /src/indexedDB_old.zip /src/mic-old; \
  python3 -I -m zipfile -e /src/indexedDB.zip /src/mic-new; \
  cmp /src/mic-old/LICENSE /src/mic-new/LICENSE; \
  python3 -I /usr/local/bin/aircraft_db.py /src/mic-old /src/mic-new /src/airports.csv /out; \
  cp /src/mic-old/LICENSE /out/LICENSE-aircraft-database; \
  sed -e "s/@MICTRONICS_COMMIT@/$MICTRONICS_COMMIT/" /src/ATTRIBUTION.in > /out/ATTRIBUTION; \
  ! grep -q @ /out/ATTRIBUTION

# tar1090's html, installed as its install.sh installs it for one instance: the database in
# db-<version> named in index.html (with the database's licence beside it, as LICENSE.txt), version.json, the version in the page, the cache-busting
# renames (its own cachebust.sh), and the source's LICENSE and README beside it. Nothing of
# tar1090's is changed but what install.sh itself changes.
RUN set -eu; \
  mkdir -p /src/tar1090; \
  tar -xzf /src/tar1090.tar.gz -C /src/tar1090 --strip-components=1; \
  cd /src/tar1090; \
  version="$(cat version)"; \
  db="mictronics-$(printf %.7s "$MICTRONICS_COMMIT")"; \
  html=/usr/local/share/tar1090/html; \
  mkdir -p "$html"; \
  cp -r -T html "$html"; \
  cp -r -T /out/db "$html/db-$db"; \
  cp /out/LICENSE-aircraft-database "$html/db-$db/LICENSE.txt"; \
  sed -i -e "s/let databaseFolder = .*;/let databaseFolder = \"db-$db\";/" "$html/index.html"; \
  grep -q "let databaseFolder = \"db-$db\";" "$html/index.html"; \
  printf '{ "tar1090Version": "%s", "databaseVersion": "%s" }\n' "$version" "$db" > "$html/version.json"; \
  rm -f "$html/config.js"; \
  cd "$html"; \
  sed -i -e 's/id="webinterface_version">/\0'"($version)/" index.html; \
  bash /src/tar1090/cachebust.sh /src/tar1090/cachebust.list "$html"; \
  cp /src/tar1090/LICENSE /src/tar1090/README.md /usr/local/share/tar1090/; \
  printf 'https://github.com/wiedehopf/tar1090/tree/%s\n' "$TAR1090_COMMIT" > /usr/local/share/tar1090/SOURCE

FROM ${DEBIAN}
ARG DEBIAN_SNAPSHOT
ARG READSB_VERSION
ARG NGINX_VERSION
ARG TINI_VERSION
ARG NGINX_LUA_VERSION
ARG LUA_CJSON_VERSION
ARG PYTHON_PIL_VERSION
ARG PYTHON_REQUESTS_VERSION
ARG CA_CERTIFICATES_VERSION
ARG STATICMAP_VERSION
ARG STATICMAP_SHA256
ARG TAR1090_COMMIT
ARG MICTRONICS_COMMIT
ARG OURAIRPORTS_COMMIT

# readsb's package makes the system user readsb, which runs both processes. tini is PID 1 and
# hands signals to the entrypoint, which stops both.
COPY --chmod=0755 debian-snapshot.sh /usr/local/bin/debian-snapshot
RUN debian-snapshot "$DEBIAN_SNAPSHOT" \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    "readsb=${READSB_VERSION}" "nginx=${NGINX_VERSION}" "tini=${TINI_VERSION}" \
    "libnginx-mod-http-lua=${NGINX_LUA_VERSION}" "lua-cjson=${LUA_CJSON_VERSION}" \
    "python3-pil=${PYTHON_PIL_VERSION}" "python3-requests=${PYTHON_REQUESTS_VERSION}" \
    "ca-certificates=${CA_CERTIFICATES_VERSION}" \
  && rm -rf /var/lib/apt/lists/* /etc/nginx/sites-enabled/* /usr/local/bin/debian-snapshot \
  && install -d -o readsb /run/readsb /run/tally-map /var/globe_history /var/globe_history/archive \
    /var/cache/tally-map

COPY --from=web /usr/local/share/tar1090 /usr/local/share/tar1090
COPY --from=web /out/aircraft.csv.gz /out/LICENSE-aircraft-database /out/ATTRIBUTION /usr/local/share/tally-map/
COPY nginx.conf /etc/tally-map/nginx.conf
COPY preview.lua 404.html /usr/local/share/tally-map/
COPY preview.py /usr/local/lib/tally-map/preview.py

# staticmap beside preview.py, which imports it, and its licence beside it; then the site's card,
# drawn by preview.py once, here.
ADD --checksum=sha256:${STATICMAP_SHA256} \
  https://files.pythonhosted.org/packages/39/69/6f6c04591cced82a807b4b1e71e892ca7dc40c96d337ec6bd00f7be7035d/staticmap-${STATICMAP_VERSION}-py3-none-any.whl /tmp/staticmap.whl
RUN set -eu; \
  python3 -I -m zipfile -e /tmp/staticmap.whl /tmp/staticmap; \
  cp -r /tmp/staticmap/staticmap /usr/local/lib/tally-map/staticmap; \
  rm -f /usr/local/lib/tally-map/staticmap/tests.py; \
  cp "/tmp/staticmap/staticmap-${STATICMAP_VERSION}.dist-info/LICENSE.txt" /usr/local/lib/tally-map/LICENSE-staticmap; \
  rm -rf /tmp/staticmap /tmp/staticmap.whl; \
  python3 -E -s /usr/local/lib/tally-map/preview.py card /usr/local/share/tally-map/card.jpg
COPY --chmod=0755 entrypoint.sh /usr/local/bin/tally-map
COPY --from=collect --chmod=0755 /tally-acars-collect /usr/local/bin/tally-acars-collect
COPY README.md /usr/local/share/tally-map/README.md

LABEL org.opencontainers.image.source="https://github.com/sky-commons/tally" \
  org.opencontainers.image.description="tar1090 and readsb over a Tally relay's --beast-out" \
  org.opencontainers.image.licenses="GPL-2.0-or-later AND GPL-3.0-or-later" \
  org.skycommons.tally.tar1090="https://github.com/wiedehopf/tar1090/tree/${TAR1090_COMMIT}" \
  org.skycommons.tally.readsb="https://snapshot.debian.org/package/readsb/${READSB_VERSION}/" \
  org.skycommons.tally.aircraft-database="https://github.com/Mictronics/aircraft-database/tree/${MICTRONICS_COMMIT} (ODC-By-1.0)" \
  org.skycommons.tally.staticmap="https://pypi.org/project/staticmap/${STATICMAP_VERSION}/ (Apache-2.0)" \
  org.skycommons.tally.airports="https://github.com/davidmegginson/ourairports-data/tree/${OURAIRPORTS_COMMIT} (Unlicense)"

# The globe history, the heatmap and the daily archives, kept across restarts and upgrades;
# readsb's own state (its traces across a restart) is in internal_state under it. A new named
# volume starts as a copy of this directory, owned by readsb.
VOLUME ["/var/globe_history"]
EXPOSE 8080

USER readsb
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/tally-map"]
