# Releasing

A release is a tag `vX.Y.Z` on main. The release workflow (`.github/workflows/release.yml`) builds
and tests it, signs every file with cosign keyless on that tag, and publishes the GitHub release
and the images. Feeders with automatic updates on install it within about a day (RFC-0203). So a
release must upgrade every earlier install by itself ([CONTRIBUTING.md](../CONTRIBUTING.md), "Two
rules every change keeps").

1. **The version PR.** Move the version in its three places: `Cargo.toml`
   (`[workspace.package]`), `build/version.bzl` and `packaging/install.sh` (`VERSION`). Also update
   `Cargo.lock` and the two hashes `MODULE.bazel.lock` records for them (#47 is one). In the same
   PR, vendor the release before this one for the upgrade gate: put its published `install.sh`, and
   its `update.sh` from v0.7.2 on, in `packaging/tests/previous/vPREVIOUS/`, byte for byte as the
   release serves them (`gh release download vPREVIOUS --pattern install.sh --pattern update.sh`).
   Keep the one before it as well (N−2), and drop older ones. Say in the PR what changed for feeders
   and relays and what migrates itself.
2. **Merge it** (squash) once CI passes. `//packaging:upgrade_test` is part of CI's `bazel test
   //...`.
3. **Tag the merge commit and push the tag:** `git tag vX.Y.Z <merge sha> && git push origin
   vX.Y.Z`. Before its tests, the workflow checks that the version in all three places is the tag,
   and that each vendored release in `packaging/tests/previous` is what that release published,
   with the release before the tag among them. Then the upgrade gate runs again as part of its
   tests.
4. **Check what it published.** Every file has a `.sha256` and a `.sigstore.json`. Check one of
   them the way the updater does:

   ```sh
   gh release download vX.Y.Z --pattern 'install.sh*'
   cosign verify-blob install.sh --bundle install.sh.sigstore.json \
     --certificate-identity https://github.com/sky-commons/tally/.github/workflows/release.yml@refs/tags/vX.Y.Z \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-github-workflow-repository sky-commons/tally \
     --certificate-github-workflow-trigger push --certificate-github-workflow-ref refs/tags/vX.Y.Z
   ```

A test that fails on the tag can be rerun (`gh run rerun --failed`). A release that is wrong is
fixed by a newer one. Updaters never go back, so never move or delete a published tag.
