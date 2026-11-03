#!/usr/bin/env bash
# The Tally feeder's automatic update (RFC-0203), run by tally-feed-update.timer about once a day.
# install.sh installs it as /usr/local/lib/tally/update, with cosign beside it and the version it
# installed in /usr/local/lib/tally/installed.
#
# It asks GitHub for the latest release of sky-commons/tally, and installs it only when:
#
# - it is newer than the installed version: never an older one, nor the same one again;
# - its install.sh is signed by this repository's release workflow run on that release's own tag
#   (cosign keyless: the certificate names
#   https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/vX.Y.Z, issued for
#   GitHub Actions' token), checked by the cosign the last install put here. That cosign is pinned
#   by its sha256 in the install.sh that installed it, and the identity is pinned here: nothing the
#   new release says is trusted before its signature is checked, and nothing downloaded is run
#   before then.
#
# Then it runs that install.sh with --upgrade, which checks every file it installs the same way,
# makes whatever change the new release needs to the owner's files itself (a release never asks
# for the owner's hands, RFC-0203 §3), restarts the feeder and waits for it to publish. If the
# installer fails, or the feeder is not running after it, every file it may have replaced is put
# back, the old feeder restarted, and the journal says so. The key and what the feeder learned are
# never touched.
#
# What reads the network and what parses what it brought (curl, cosign) runs as a throwaway
# unprivileged user, a transient unit with DynamicUser=; root writes what they fetched to files
# and runs the checked installer.
#
# It does nothing while tally-feed-update.timer is disabled, even when started by hand: that timer
# is the owner's switch (sudo systemctl disable --now tally-feed-update.timer), which every rerun
# of install.sh keeps.
set -euo pipefail

SIGNER_REPOSITORY=sky-commons/tally
SIGNER_ISSUER=https://token.actions.githubusercontent.com
RELEASES="https://github.com/$SIGNER_REPOSITORY/releases"
LIB=/usr/local/lib/tally
COSIGN=$LIB/cosign
INSTALLED=$LIB/installed
WORK=/var/cache/tally-feed-update
LOCK=/run/tally-feed-update.lock
TIMER=tally-feed-update.timer
FEEDER=tally-feed.service
# Every file an install may replace, put back when the new release does not start.
REPLACED=(
  /usr/local/bin/tally-feed
  /etc/default/tally-feed
  /etc/systemd/system/tally-feed.service
  /etc/systemd/system/tally-feed-update.service
  /etc/systemd/system/tally-feed-update.timer
  "$LIB/update"
  "$LIB/cosign"
  "$LIB/installed"
)

log() {
  printf 'tally-feed-update: %s\n' "$*"
}

# As install.sh's: COMMAND... as a throwaway unprivileged user, its standard output the caller's.
unprivileged() {
  if [[ $EUID -ne 0 ]]; then
    "$@"
    return
  fi
  systemd-run --quiet --wait --pipe --collect -p Type=exec -p DynamicUser=yes \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateDevices=yes -p NoNewPrivileges=yes \
    -p CapabilityBoundingSet= -p 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' \
    -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes \
    --setenv=HOME=/tmp -- "$@"
}

fetch() {
  unprivileged curl -fsSL --proto '=https' --tlsv1.2 --retry 3 "$1" </dev/null >"$2"
}

# Is FILE signed (FILE.sigstore.json beside it) by the release workflow of SIGNER_REPOSITORY run
# on the tag TAG?
signed_by_release() {
  local file="$1" tag="$2"
  unprivileged "$COSIGN" verify-blob "$file" --bundle "$file.sigstore.json" \
    --certificate-identity "https://github.com/$SIGNER_REPOSITORY/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer "$SIGNER_ISSUER" \
    --certificate-github-workflow-repository "$SIGNER_REPOSITORY" \
    --certificate-github-workflow-trigger push \
    --certificate-github-workflow-ref "refs/tags/$tag" </dev/null >/dev/null 2>&1
}

# vX.Y.Z, each a number.
is_version() {
  [[ $1 =~ ^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$ ]]
}

# Is version A newer than version B?
newer() {
  local a b i
  IFS=. read -ra a <<<"${1#v}"
  IFS=. read -ra b <<<"${2#v}"
  for i in 0 1 2; do
    ((10#${a[i]} == 10#${b[i]})) && continue
    ((10#${a[i]} > 10#${b[i]}))
    return
  done
  return 1
}

# The version installed, as install.sh wrote it.
installed_version() {
  local version=""
  [[ -r $INSTALLED ]] && version="$(head -n 1 "$INSTALLED")"
  is_version "$version" || return 1
  printf '%s' "$version"
}

# The latest release's tag: where GitHub's releases/latest leads.
latest_release() {
  local url tag
  url="$(unprivileged curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o /dev/null \
    -w '%{url_effective}' "$RELEASES/latest" </dev/null)" || return 1
  [[ $url == "$RELEASES/tag/"* ]] || return 1
  tag="${url#"$RELEASES/tag/"}"
  is_version "$tag" || return 1
  printf '%s' "$tag"
}

# Copies every file in REPLACED that exists into WORK/backup, and lists what was there.
back_up() {
  local i
  rm -rf "$WORK/backup"
  install -d -m 0700 "$WORK/backup"
  : >"$WORK/backup/list"
  for i in "${!REPLACED[@]}"; do
    if [[ -e ${REPLACED[i]} ]]; then
      cp -a -- "${REPLACED[i]}" "$WORK/backup/$i"
      printf 'kept %s\n' "$i" >>"$WORK/backup/list"
    else
      printf 'absent %s\n' "$i" >>"$WORK/backup/list"
    fi
  done
}

# Puts back every file back_up saw, each in one rename, removes those it did not, and restarts the
# old feeder.
roll_back() {
  local what i target
  while read -r what i; do
    target="${REPLACED[i]}"
    if [[ $what == kept ]]; then
      cp -a -- "$WORK/backup/$i" "$target.tally-old"
      mv -f -- "$target.tally-old" "$target"
    else
      rm -f -- "$target"
    fi
  done <"$WORK/backup/list"
  systemctl daemon-reload
  systemctl restart "$FEEDER" || true
}

# Runs the checked installer INSTALLER of the new release, as an automatic update.
run_installer() {
  bash "$1" --upgrade
}

main() {
  [[ $# -eq 0 ]] || {
    log "takes no arguments"
    return 2
  }
  if ! systemctl is-enabled --quiet "$TIMER" 2>/dev/null; then
    log "automatic updates are off ($TIMER is disabled; sudo systemctl enable --now $TIMER turns them on): nothing done"
    return 0
  fi
  install -d -m 0755 "$WORK"
  exec 9>"$LOCK"
  flock -n 9 || {
    log "another update is running"
    return 0
  }

  local installed latest
  if ! installed="$(installed_version)"; then
    log "$INSTALLED names no version; taking any signed release as newer"
    installed=v0.0.0
  fi
  if ! latest="$(latest_release)"; then
    log "could not read the latest release from $RELEASES/latest; nothing done, trying again at the next run"
    return 1
  fi
  if [[ $latest == "$installed" ]]; then
    log "up to date: $installed is installed, the latest release"
    return 0
  fi
  if ! newer "$latest" "$installed"; then
    log "up to date: $installed is installed, newer than the latest release $latest, and an update never goes back"
    return 0
  fi

  log "$latest is newer than $installed; checking its signature"
  local dir="$WORK/$latest"
  rm -rf -- "$dir"
  install -d -m 0755 "$dir"
  if ! fetch "$RELEASES/download/$latest/install.sh" "$dir/install.sh" ||
    ! fetch "$RELEASES/download/$latest/install.sh.sigstore.json" "$dir/install.sh.sigstore.json"; then
    log "could not download $latest's install.sh and its signature; nothing installed, trying again at the next run"
    return 1
  fi
  if ! signed_by_release "$dir/install.sh" "$latest"; then
    log "REFUSED $latest: its install.sh is not signed by the release workflow of $SIGNER_REPOSITORY on the tag $latest; nothing installed"
    return 1
  fi
  local version
  version="$(sed -n 's/^VERSION="\(.*\)"$/\1/p' "$dir/install.sh")"
  if [[ $version != "$latest" ]]; then
    log "REFUSED $latest: its signed install.sh installs ${version:-no version}; nothing installed"
    return 1
  fi

  log "installing $latest over $installed"
  back_up
  local failed=""
  run_installer "$dir/install.sh" || failed="its install.sh failed"
  if [[ -z $failed ]] && ! systemctl is-active --quiet "$FEEDER"; then
    failed="tally-feed is not running after it"
  fi
  if [[ -n $failed ]]; then
    roll_back
    log "ROLLED BACK $latest: $failed, so $installed is back (its files restored, tally-feed restarted); trying again at the next run"
    return 1
  fi
  rm -rf -- "$WORK/backup" "$dir"
  log "updated $installed to $latest"
}

# Run, unless sourced (the installer's tests source it to call its parts).
if [[ -z ${BASH_SOURCE[0]:-} || ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
