"""The version every crate's Bazel targets build with (`CARGO_PKG_VERSION`).

Cargo.toml's `[workspace.package]` version says the same for Cargo, and the release refuses a tag
that either disagrees with (.github/workflows/release.yml), so a release names one version in
three places that cannot drift: this file, Cargo.toml and packaging/install.sh.
"""

VERSION = "0.4.1"
