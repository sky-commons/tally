# Tally

An open network for ADS-B receivers. Your receiver publishes what it hears once, and anyone may
run a relay or use the data. Nobody owns the network, including us.

Pilots say "tally" on the radio when they have the traffic in sight. That is what this does,
together.

**Status: pre-release.** The protocol, the feeder and the relay work end to end in tests. Nothing
is deployed for the public yet.

## How it works

- **The feeder** (`tally-feed`) runs beside readsb on your receiver. It reads readsb's BEAST output
  (port 30005) as one more client, signs what your antenna heard about once a second, and sends it
  to a few relays. It changes nothing about your other feeds, opens no port, and takes no orders
  from the network.
- **Relays** (`tally-relay`) are servers anyone may run. They check every batch's signature, pass
  each one on once, and serve consumers. They never change or repackage your data, so anyone
  downstream can verify it came from your receiver.
- **Your receiver's identity is a key** it generates at install. No account, no signup. It names
  your antenna on every relay, forever, and no operator can take it away.

## Run a feeder

```sh
tally-feed init --key /etc/tally/key            # once: creates the key, prints its public half
tally-feed --key /etc/tally/key \
  --relay relay.example.org:10900=<relay key> \
  --lat 37.41 --lon -122.10 --alt 12
```

Your receiver's location is published as you enter it, because multilateration (locating aircraft
that do not broadcast a position) needs it exact. Pass `--precision <metres>` to say you rounded it;
you then contribute less to multilateration.

If the receiver also runs dump978-fa for 978 MHz UAT, `--uat 127.0.0.1:30978` publishes its raw
output too, in the same signed batches.

`--ceiling` caps what the feeder sends each relay per second (64 KB by default). Over the cap,
receptions are dropped and counted, never buffered.

## Run a relay

```sh
tally-relay keygen > /etc/tally/relay.key
tally-relay --key /etc/tally/relay.key --listen 0.0.0.0:10900 --beast-out 127.0.0.1:30105
```

`--beast-out` serves every reception as plain BEAST for a local decoder such as readsb. It is
unauthenticated: bind it to loopback.

## Build

```sh
cargo build --release      # or: bazel build //...
cargo test                 # or: bazel test //...
```

Pure Rust, no C toolchain, so it cross-compiles to a Raspberry Pi.

## Licences

- Code: MIT or Apache-2.0, at your option.
- Data: feeders dedicate their receptions under CC0. What relays publish downstream is under the
  ODbL, so nobody can take the data private.
