# The feeder as a container (RFC-0180 §4), for a host that runs each aggregator's feeder as one,
# such as adsb.im or an sdr-enthusiasts compose file. The release builds it for linux/amd64,
# linux/arm64 and linux/arm/v7 from the binaries it has just built, tested and signed (the build
# context is the release's dist/), so the image holds the same bytes the release's
# tally-feed-<arch>-linux files are. Nothing is compiled here, and there is no RUN: an arm image
# builds on an amd64 runner with no emulation.
#
# It is configured as the sdr-enthusiasts images are, by one block of environment variables
# (BEASTHOST, LAT, LONG, ALT; `tally-feed --help` lists them all), and any
# `command:` is the feeder's own flags, which win over the environment. The relays to start from
# are compiled into the binary (packaging/seeds). The identity is made on the first run in the
# volume, /var/lib/tally-feed/key, and the log names it and its station page; TALLY_KEY (the
# text `new-key` prints on its first line) is used instead when it is set.
#
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
#     -f packaging/container/Dockerfile dist

# Docker names the platform's architecture amd64, arm64 or arm; the release names its binaries
# x86_64, aarch64 and armv7. Distroless has no shell to map one to the other, so each architecture
# is a stage and `FROM bin-${TARGETARCH}` picks one. BuildKit builds only the stage it picks, so a
# build for one platform needs only that platform's binary in the context.
ARG TARGETARCH

FROM scratch AS bin-amd64
COPY tally-feed-x86_64-linux /tally-feed

FROM scratch AS bin-arm64
COPY tally-feed-aarch64-linux /tally-feed

FROM scratch AS bin-arm
COPY tally-feed-armv7-linux /tally-feed

FROM bin-${TARGETARCH} AS bin

# The binary is linked dynamically against glibc, built against the pinned Debian bullseye sysroot
# (glibc 2.25 or newer, packaging/README.md), and needs nothing else of the system: distroless cc
# on Debian 12 has glibc 2.36 and libgcc, and no shell or package manager. Pinned by the digest of
# its multi-arch index (`docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot`;
# it holds linux/amd64, linux/arm64/v8 and linux/arm/v7), so every build of a release starts from
# the same base; the tag says which image the digest is.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

COPY --from=bin --chmod=0755 /tally-feed /usr/local/bin/tally-feed

# Where the feeder keeps its key, the relays it learned, the ones it found swallowing and its
# status (`--state`'s default). A volume, so all of it outlives the container: a named volume or a
# bind-mounted host directory (`/opt/adsb/tally-feed:/var/lib/tally-feed`) alike.
COPY --chown=65532:65532 <<KEEP /var/lib/tally-feed/.keep
KEEP
VOLUME ["/var/lib/tally-feed"]

# The feeder starts as root only to make the volume nonroot's (65532), which a directory Docker
# created for a bind mount is not, and then becomes nonroot for good before it reads or writes
# anything (crates/feed/src/privilege.rs). A compose file's `user:` starts it as that user instead,
# and then nothing changes hands.
USER 0:0
ENV TALLY_RUN_AS=65532:65532

# Healthy is publishing to a relay (a session up within two minutes) and reading the decoder
# (bytes within five minutes; readsb sends a heartbeat every minute), from the status file the
# running feeder rewrites every ten seconds in its state directory (`tally-feed health`). The start
# period covers a first boot's wait for the decoder and the relays.
HEALTHCHECK --interval=60s --timeout=10s --start-period=5m --retries=3 \
  CMD ["/usr/local/bin/tally-feed", "health"]

ENTRYPOINT ["/usr/local/bin/tally-feed"]
