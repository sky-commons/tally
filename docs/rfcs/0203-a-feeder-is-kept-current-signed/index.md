# RFC-0203: A feeder is kept current, signed

- Status: proposed, for this review (2026-11-03)
- Amends: RFC-0171 §3.5 ("it must never carry ... self-update") and §7 ("a remote kill switch,
  config push or self-update in the feeder")
- Founder direction, 2026-11-03: "an opt in opt out auto update with the default being opt in";
  then, the same day: no release may ever need a manual step, migrations are the release's own,
  and relays accept every feeder wire version ever released.

## §0 The decision

A standalone feeder (the one `install.sh` installs) updates itself to each newer release unless
its owner turns that off. The update runs only what this repository's release workflow signed on
the release's own tag, checked against a trust anchor the previous install left on the box. It
never installs an older release, and it puts the old feeder back if the new one does not start.

Two rules make that safe to leave unattended:

- **No release needs the owner's hands** (§4). A release makes every change to the owner's files
  itself, and a test fails the build if a release cannot upgrade the installs before it.
- **Relays accept every feeder wire version ever released, for good** (§5). A receiver that
  missed updates, or whose owner turned them off, still feeds.

## §1 Why

Today a feeder upgrades only when its owner reruns `install.sh`. With two receivers, both ours,
that was enough. We are about to invite outside hobbyists to run feeders, and most will install
once and never come back. Upgrades have stranded feeders before: since v0.7.0 a relay uses no
batch without a freshness anchor (RFC-0171 §3.6), so the two outside 0.5.2 feeders kept connecting
and stopped reaching the map, until we found and upgraded both by hand (README, "Upgrade
required").

RFC-0171 §3.5 ruled out self-update to keep any single party from controlling the network's
receivers. Automatic updates do give the release signer that reach: a compromised release reaches
every feeder that updates. This RFC accepts that cost and bounds it. The feeder binary still never
updates itself and still takes no orders from the network. The updater is a separate part of the
install that the owner can see and turn off. It asks only GitHub for the latest release and
installs only what the release workflow signed (§3).

## §2 The mechanism

`install.sh` installs `/usr/local/lib/tally/update` (`packaging/update.sh`),
`tally-feed-update.service` and `tally-feed-update.timer`.

- **When.** Once a day (`OnCalendar=daily`), at a time of its own for each receiver within the
  day (`RandomizedDelaySec=23h` with `FixedRandomDelay=yes`), so a release reaches the fleet
  over about a day. It also runs at boot if the receiver was off when its time came
  (`Persistent=true`).
- **What.** It reads the latest release's tag from `releases/latest`. If that tag is not newer than
  the version `install.sh` recorded in `/usr/local/lib/tally/installed`, it logs `up to date` and
  stops. It never installs an older release, nor the same one again.
- **Check.** It downloads that release's `install.sh` and `install.sh.sigstore.json` and checks
  the signature (§3). If the check fails, it installs nothing, logs `REFUSED`, and exits non-zero.
- **Install.** It runs the checked `install.sh --upgrade`. That installer checks every other file
  it installs the same way (the binary, the units, the updater, the seed list), rewrites what the
  new release needs rewritten, replaces each file in one rename, restarts the feeder, and waits
  90 s for it to log `publishing to`.
- **Roll back.** Before the installer runs, the updater copies every file an install may replace.
  If the installer fails, or the feeder is not running afterwards, it puts those files back,
  restarts the old feeder, logs `ROLLED BACK` with the reason, and tries again the next day. The
  key (`/etc/tally/key`), what the feeder learned (`/var/lib/tally-feed`) and the owner's lines
  in `/etc/default/tally-feed` are never lost.
- **Opting out.** `TALLY_AUTO_UPDATE=0` or `--no-auto-update` installs with the timer disabled.
  `sudo systemctl disable --now tally-feed-update.timer` turns it off later. The timer is the one
  switch: the updater does nothing while it is disabled, even when started by hand, and a rerun of
  `install.sh` reads the timer and keeps the owner's choice. Every install ends by saying whether
  automatic updates are on and how to turn them off.
- **Visible.** The updater logs to journald (`journalctl -u tally-feed-update`). The feeder's
  signed description already carries its software version (`ReceiverInfo.software`, e.g.
  `tally-feed 0.7.2`), which the relay's stats and the API's `GET /v1/stations/KEY` (`software`)
  serve, so a station's page can show which release it runs. Nothing new is reported.

## §3 Trust: what a release must prove

The release workflow already signs every file it publishes with cosign keyless signing (a
`.sigstore.json` bundle beside each file, next to its `.sha256`). The certificate in each bundle
is issued by Sigstore's Fulcio for the workflow's GitHub Actions identity token, and the signature
is logged in Rekor.

The updater accepts a file only if `cosign verify-blob` with that bundle succeeds with all of:

- `--certificate-identity https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/vX.Y.Z`:
  exact, not a pattern, where `vX.Y.Z` is the tag being installed. A signature made for one release
  cannot be passed off as another's.
- `--certificate-oidc-issuer https://token.actions.githubusercontent.com`
- `--certificate-github-workflow-repository sky-commons/tally`,
  `--certificate-github-workflow-trigger push` and
  `--certificate-github-workflow-ref refs/tags/vX.Y.Z`.

Then the signed `install.sh` must also say `VERSION="vX.Y.Z"`.

**The trust anchor is on the box before the new release arrives.** It is three things the previous
install left there:

- the identity above, written in the installed updater;
- the cosign binary at `/usr/local/lib/tally/cosign`, which the installer downloaded from
  sigstore/cosign's release and checked against a sha256 pinned in `install.sh`
  (`COSIGN_VERSION`, now v2.6.5);
- Sigstore's TUF root, which is built into that cosign. cosign uses it to fetch and check the
  current Fulcio and Rekor keys, so a key rotation by Sigstore does not strand anyone.

None of this comes from the release being checked. A new release can move the cosign pin or the
identity, but only through its own `install.sh`, which the old anchor has already checked.

The `.sha256` beside a file still catches a broken download. On its own it proves nothing about
who made the release, since it comes from the same place as the file.

**Least privilege.** `curl` and `cosign` handle untrusted bytes: everything from the network,
and the bundles. They run as a throwaway unprivileged user, in a transient unit with
`DynamicUser=yes`, no capabilities, and no write access outside a private `/tmp`. Root only writes
what they fetched to root-owned files and then runs the installer whose signature they checked.
The update service itself runs as root, because installing is root's work. It is confined only as
much as an installer can bear: if a later installer needed more than the running unit allows, the
update would fail, roll back and fail again every day, which is the stranded fleet this RFC exists
to prevent.

**What this does not stop.** Anyone who can run the release workflow on a `v*` tag of this
repository can ship to every updating feeder. That includes a maintainer, a stolen maintainer
token, or a compromised action the workflow pins. This is the cost §1 accepts. The workflow pins
every action by commit, and a tag push is public and logged in Rekor. An owner who does not accept
the risk turns updates off.

**Cost.** cosign is about 150 MB on disk (145 to 155 MB by architecture). It is downloaded once,
and again only when the pin moves.

## §4 No release needs the owner's hands

The updater installs every newer release whose signature checks out. There is no "manual step
needed, skip this one" marker, because nobody would take the step and those feeders would be lost.
Instead:

- **Migrations run automatically.** Any change to the configuration, the key or the state is made
  by the new release itself, either in the new binary at start or in `install.sh`. One example is
  `install.sh` rewriting the BEGIN/END block of `/etc/default/tally-feed` and moving an older
  install's flags into `TALLY_FEED_EXTRA`. A release may never ask the owner to edit a file, run a
  command or reinstall.
- **The upgrade test is a gate.** `//packaging:upgrade_test` (`packaging/tests/upgrade.rs`) runs
  in every CI run and in the release workflow's tests. It starts from installs made by earlier
  installers: the published `install.sh` of each release kept in `packaging/tests/previous` (now
  v0.7.0, i.e. N−2, and v0.7.1, i.e. N−1), plus this build's own. Each install has an owner's flag
  and an owner's choice about automatic updates, on and off. Each upgrades the way that receiver
  would: through the earlier release's own updater when it had one and updates are on, otherwise
  by the owner's rerun (the only path a release from before the updater has). The test then checks
  that the receiver runs the build's real `tally-feed`, that it starts with the arguments the
  upgrade left and names the same key, that the location and the owner's flag are kept, and that
  the choice about updates is kept.
- **The gate starts where receivers are.** Before the release workflow runs its tests, it checks
  that each vendored `install.sh` (and `update.sh`, from v0.7.2 on) is byte for byte what that
  release published, and that the newest one is the release just before the tag. A release
  therefore cannot be tagged until the release before it has been vendored (docs/releasing.md).

## §5 Old feeders keep working: full backwards compatibility

- **Relays keep accepting every feeder wire version ever released**, by default and with no time
  limit. Today that is versions 2 to 4: v0.1.0 to v0.4.2 speak only 2, v0.5.0 to v0.6.1 speak 2
  and 3, and v0.7.x speak 2 to 4. Version 1 was retired before any feeder outside Flightlines ran
  it (`tally_wire::record::MIN_VERSION`), so no relay reads it. The protocol's extension rules
  (RFC-0171 §3.4) already exist for this.
- **There are only two exceptions, each decided case by case:** a version with a proven security
  flaw, or one proven to poison data (for example wrong timestamps or positions).
- **Even then, a relay downgrades the version and does not reject it.** It stops using that
  feeder's data for MLAT and for verified outputs, but keeps it on the map where that is still
  safe. The feeder's station page says why and says that an update fixes it.
- **The test.** `a_feeder_of_the_oldest_wire_version_is_welcomed_and_reaches_the_map`
  (`crates/relay/tests/end_to_end.rs`) dials a relay as a version 2 feeder, through
  `tally_wire::noise::connect_speaking`, checks that the session is agreed at version 2, and checks
  that the feeder's receptions reach the relay's BEAST output, which the map's readsb reads.

**An exception already in force, and a gap.** Since v0.7.0 a relay uses no batch without a
freshness anchor (RFC-0171 §3.6), and feeders before v0.7.0 sign none. They are welcomed and
their batches are forwarded, but none of their data reaches the map, MLAT or subscribers. That is
stricter than the downgrade above, because their data is off the map too, and their station page
does not say why. The test above signs its batch with an anchor, as every v0.7 feeder does; a
batch as v0.6.1 and earlier sent it would not reach the map. Two questions are open (§8): whether
unanchored data may be shown on the map, and the station page notice.

## §6 Scope

Only the standalone install, the one `install.sh` makes.

- **adsb.im and other containers are out of scope.** A container host follows `ghcr.io/sky-commons/tally-feed:0`,
  or a digest it pins, through its own update mechanism. adsb.im's feeder updates replace the whole
  stack. KLAX-1, which runs Tally inside a forked adsb.im image, is unchanged by this RFC.
- **Installs before v0.7.2 have no updater.** Their owners rerun `install.sh` once, and from then
  on they update themselves. Our own standalone receiver, tally-pi, is upgraded by hand with v0.7.2.

## §7 What changes in RFC-0171

§3.5's list of what the feeder must never carry keeps the remote kill switch, remote configuration
or command push, and a single built-in seed. "Self-update (it updates through the owner's package
manager, if ever)" becomes: the feeder binary never updates itself; the install's updater (this
RFC) does, signed, opt-out, and it takes nothing from the network but the latest signed release.
§7's killed list is amended to match.

## §8 Open questions

- How a relay downgrades a version under §5's exceptions, and how the station page says so. Today
  the only case is the pre-anchor one (§5), which a relay handles by using none of that data.
- Whether to make the cosign download lighter (a smaller verifier for Sigstore bundles), if 150 MB
  proves a problem on small cards.
