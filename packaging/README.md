# Packaging

How Tally's binaries are installed on a Linux box with systemd (248 or later).

- `install.sh` installs a feeder on a receiver:
  `curl -fsSL https://github.com/flightlines/tally/releases/download/<version>/install.sh | sudo bash`.
  It downloads `tally-feed` for x86_64 or aarch64 and the feeder's unit from the release, each
  checked against the `.sha256` published beside it; finds readsb's BEAST output (`127.0.0.1:30005`)
  and dump978-fa's raw output (`127.0.0.1:30978`, added as `--uat`); reads the antenna's location
  from `TALLY_LAT`, `TALLY_LON`, `TALLY_ALT`, or an adsb.im / ultrafeeder `.env`, or
  `/etc/default/readsb`; takes the relays to start from from `RELAYS` at the top of the script
  (filled at release) or `TALLY_RELAYS`, and stops before installing anything if both are empty;
  makes `/etc/tally/key` if missing (root, mode 600); writes
  `/etc/default/tally-feed` if missing, with those relays as `--relay` flags; and starts the service. Run again, it upgrades the binary
  and keeps the key and the defaults file. It installs no updater: the feeder never updates itself
  (RFC-0166 §3.5). The checksum guards a broken download, not a compromised release.
- `systemd/tally-feed.service` runs the feeder as a dynamic user with no listening socket, at most
  64 MB and 20% of one CPU. The key reaches it through `LoadCredential`, so it stays root's. The
  owner's arguments are `TALLY_FEED_ARGS` in `/etc/default/tally-feed`.
- `systemd/tally-relay.service` runs a relay the same way, with its key at `/etc/tally/relay.key`
  (`tally-relay keygen > /etc/tally/relay.key`) and its arguments as `TALLY_RELAY_ARGS` in
  `/etc/default/tally-relay`.

A release therefore carries `install.sh`, `tally-feed-x86_64-linux`, `tally-feed-aarch64-linux` and
`tally-feed.service`, each with a `.sha256` whose first field is the file's hash. The binaries are
built against the pinned Debian bullseye sysroot (`bazel build -c opt
--platforms=//platforms:linux_aarch64 //crates/feed:tally-feed`), so they need only glibc 2.25 or
newer and no C++ runtime: any Raspberry Pi OS from Buster on, and any current Linux.
