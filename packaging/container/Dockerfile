# The feeder as a container (RFC-0180 §4), for a host that runs each aggregator's feeder as one,
# such as adsb.im. The release builds it for linux/amd64 and linux/arm64 from the binaries it has
# just built, tested and signed (the build context is the release's dist/), so the image holds the
# same bytes the release's tally-feed-<arch>-linux files are. Nothing is compiled here, and there
# is no RUN: an arm64 image builds on an amd64 runner with no emulation.
#
# The arguments are the feeder's own (`tally-feed --help`); the entrypoint is the binary, with no
# shell. The identity comes from the environment (`--key-env NAME`), made with `new-key`
# (packaging/README.md, "Run it as a container").
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f packaging/container/Dockerfile dist

# Docker names the platform's architecture amd64 or arm64; the release names its binaries x86_64
# and aarch64. Distroless has no shell to map one to the other, so each architecture is a stage
# and `FROM bin-${TARGETARCH}` picks one. BuildKit builds only the stage it picks, so a build for
# one platform needs only that platform's binary in the context.
ARG TARGETARCH

FROM scratch AS bin-amd64
COPY tally-feed-x86_64-linux /tally-feed

FROM scratch AS bin-arm64
COPY tally-feed-aarch64-linux /tally-feed

FROM bin-${TARGETARCH} AS bin

# The binary is linked dynamically against glibc, built against the pinned Debian bullseye sysroot
# (glibc 2.25 or newer, packaging/README.md), and needs nothing else of the system: distroless cc
# on Debian 12 has glibc 2.36 and libgcc, and no shell or package manager. Pinned by the digest of
# its multi-arch index (`docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot`),
# so every build of a release starts from the same base; the tag says which image the digest is.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

COPY --from=bin --chmod=0755 /tally-feed /usr/local/bin/tally-feed

# Where the feeder keeps the relays it learned and the ones it found swallowing (`--state`'s
# default), owned by nonroot (65532), the user it runs as. A volume, so what it learned outlives
# the container: a new named volume starts as a copy of this directory, ownership included.
COPY --chown=65532:65532 <<KEEP /var/lib/tally-feed/.keep
KEEP
VOLUME ["/var/lib/tally-feed"]

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tally-feed"]
