#!/bin/sh
# Points apt at snapshot.debian.org as it was at one instant (Dockerfile, DEBIAN_SNAPSHOT): Debian
# 13's suites, its updates and its security updates, in place of the base image's live mirrors.
# Plain http, as the base image's own sources are: apt checks every file against the Release
# file, which Debian's archive key signs. A snapshot's Release is past its Valid-Until by design,
# so that one check is off.
#
#   debian-snapshot 20261005T000000Z
set -eu
case "${1:-}" in
[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;;
*)
	echo "debian-snapshot: '${1:-}' is not a snapshot instant, YYYYMMDDTHHMMSSZ" >&2
	exit 64
	;;
esac
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
cat >/etc/apt/sources.list.d/debian.sources <<SOURCES
Types: deb
URIs: http://snapshot.debian.org/archive/debian/$1
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/$1
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
Check-Valid-Until: no
SOURCES
