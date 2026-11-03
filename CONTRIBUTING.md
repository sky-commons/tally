# Contributing

Build and test as the README's "Build" says (`bazel test //...` runs everything CI runs). Designs
are RFCs in `docs/rfcs`. Releases follow [docs/releasing.md](docs/releasing.md).

## Two rules every change keeps (RFC-0203)

Feeders update themselves, unattended, to every newer signed release, and many are never touched
by their owner again. So:

- **No release needs the owner's hands.** Every change to a feeder's configuration, key or state
  is made by the release itself: by the new `tally-feed` when it starts, or by `install.sh`. One
  example is `install.sh` rewriting the block of `/etc/default/tally-feed` between its BEGIN and
  END lines. A release never asks an owner to edit a file, run a command or reinstall, and there is
  no "skip this release" marker for the updater. `//packaging:upgrade_test` fails the build if a
  release cannot upgrade the installs of the releases before it (`packaging/tests/previous`) and
  its own by itself. When a change breaks it, change the release so it migrates. Never change the
  test so it expects the owner to.
- **Relays accept every feeder wire version ever released**, by default and with no time limit
  (today 2 to 4, `tally_wire::record::MIN_VERSION`). There are two exceptions, each decided case
  by case: a version with a proven security flaw, or one proven to poison data (wrong timestamps
  or positions, say). Even then a relay downgrades that version and does not reject it. It stops
  using that feeder's data for MLAT and verified outputs, keeps it on the map where that is still
  safe, and the feeder's station page says why and that an update fixes it.
  `a_feeder_of_the_oldest_wire_version_is_welcomed_and_reaches_the_map`
  (`crates/relay/tests/end_to_end.rs`) holds a relay to the oldest version. Raising
  `MIN_VERSION` breaks this rule.
