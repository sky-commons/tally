#!/bin/sh
# Installs Debian packages, each at the exact version the Dockerfile pins, from snapshot.debian.org
# as it was at one instant (Dockerfile, DEBIAN_SNAPSHOT): Debian 13's suites, its updates and its
# security updates, in place of the base image's live mirrors; and checks that what it installed,
# the pins and every package they pulled in, is LOCK, to the version.
#
#   debian-install 20261105T000000Z debian-map.lock readsb=3.14.1630+git20240609.adc080d-1 ...
#
# snapshot.debian.org is one service and is sometimes down for hours (503 "No healthy backends",
# 504s), so apt retries each file with a growing delay and asks it for one file at a time; and if
# the install from the snapshot fails even so, it is made from Debian's own mirrors
# (deb.debian.org's trixie and trixie-updates, security.debian.org's trixie-security), of every
# package in LOCK at its version there. That installs the identical packages or fails: a mirror
# carries only a suite's current versions, so while any package in LOCK has since been superseded,
# the snapshot alone has it and the build waits for the snapshot.
#
# Plain http, as the base image's own sources are: apt checks every file against the Release file,
# which Debian's archive key signs, from the base image's keyring, the same for both. A snapshot's
# Release is past its Valid-Until by design, so that one check is off for the snapshot alone.
#
# The image is left with the snapshot's sources, whichever installed, and without apt's lists or
# this file's apt settings.
set -eu
export LC_ALL=C
usage() {
	echo "debian-install: $1; usage: debian-install YYYYMMDDTHHMMSSZ LOCK PACKAGE=VERSION..." >&2
	exit 64
}
case "${1:-}" in
[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
*) usage "'${1:-}' is not a snapshot instant" ;;
esac
instant="$1"
lock="${2:-}"
[ -f "$lock" ] || usage "no lock file '$lock'"
shift 2
[ $# -gt 0 ] || usage "no packages"
locked="$(grep -v '^#' "$lock" | grep . | sort)"
for pin in "$@"; do
	printf '%s\n' "$locked" | grep -qxF "$pin" || usage "$pin is not in $lock"
done

conf=/etc/apt/apt.conf.d/80debian-install
# One file at a time, each retried with a delay that doubles up to MAXIMUM seconds: RETRIES and
# MAXIMUM are the snapshot's (10, 300: a file can wait out some 13 minutes of 503s and 504s), and
# the mirrors' (6, 60).
apt_conf() {
	cat >"$conf" <<CONF
Acquire::Retries "$1";
Acquire::Retries::Delay "true";
Acquire::Retries::Delay::Maximum "$2";
Acquire::http::Timeout "60";
Acquire::Queue-Mode "access";
Acquire::http::Pipeline-Depth "1";
APT::Update::Error-Mode "any";
CONF
}

snapshot() {
	cat >/etc/apt/sources.list.d/debian.sources <<SOURCES
Types: deb
URIs: http://snapshot.debian.org/archive/debian/$instant
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/$instant
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
SOURCES
}

mirrors() {
	cat >/etc/apt/sources.list.d/debian.sources <<SOURCES
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
SOURCES
}

install_from() {
	rm -rf /var/lib/apt/lists/*
	apt-get update && apt-get install -y --no-install-recommends "$@"
}

installed() { dpkg-query -W -f '${db:Status-Status} ${Package}=${Version}\n' | sed -n 's/^installed //p' | sort; }

before="$(installed)"
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
snapshot
apt_conf 10 300
if ! install_from "$@"; then
	echo "debian-install: snapshot.debian.org/$instant failed; $lock from Debian's mirrors" >&2
	mirrors
	apt_conf 6 60
	# shellcheck disable=SC2086 # one word per package=version
	install_from $locked
	# What the pins pulled in, marked so, as the snapshot's install marks it.
	for entry in $locked; do
		printf '%s\n' "$@" | grep -qxF "$entry" || printf '%s\n' "${entry%%=*}"
	done | xargs -r apt-mark auto >/dev/null
	snapshot
fi
rm -rf /var/lib/apt/lists/* "$conf"

work="$(mktemp -d)"
printf '%s\n' "$before" >"$work/before"
installed >"$work/after"
printf '%s\n' "$locked" >"$work/lock"
comm -13 "$work/before" "$work/after" >"$work/new"
if ! cmp -s "$work/lock" "$work/new"; then
	echo "debian-install: what was installed is not $lock (< $lock, > installed):" >&2
	diff "$work/lock" "$work/new" >&2 || true
	echo "debian-install: if the pins or DEBIAN_SNAPSHOT moved, this is the new $lock:" >&2
	cat "$work/new" >&2
	rm -rf "$work"
	exit 1
fi
rm -rf "$work"
