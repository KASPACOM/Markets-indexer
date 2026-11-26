# Markets Indexer

Independent Kaspa TN10 covenant and KCC20 V2 indexer. This repository owns the
six Rust crates, PostgreSQL migrations, decoder assets and snapshot/archive tools.
The extraction preserves the reviewed runtime behavior and API coverage limits.

## Verify locally

Install Docker Engine with Compose, then run:

```sh
bash scripts/verify.sh
```

This builds a PostgreSQL 16 Python test runner, creates a uniquely named Compose
project, runs the 25 coordination/snapshot/archive tests, and removes only that
project's containers, network and volumes. No live database or node is used.

For the full Rust suite as well, install Rust 1.95.0, pkg-config, OpenSSL headers
and PostgreSQL client tools, then run `bash scripts/verify.sh full`. This builds
Rust on your machine and can use substantial disk and CPU. Hosted CI runs the
full suite, PostgreSQL 15/16 checks and the release-image smoke independently.

Fixtures and mock-node tests prove offline behavior. They do not prove live
TN10 parity, full historical coverage or deployment readiness.

## Build the runtime image

```sh
docker build -f Dockerfile.shadow-v2 \
  --build-arg SHADOW_DECODER_REVISION="$(cat decoder-compatibility.txt)" \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  -t markets-indexer:local .
docker run --rm markets-indexer:local --help
docker run --rm --entrypoint covenant-tools-api markets-indexer:local --help
```

The image contains `tn10-shadow-indexer` and `covenant-tools-api`. Legacy crates
and commands remain in source for compatibility and regression testing; wallet
settlement scripts, frontends and live deployment configuration are excluded.
No registry publication or deployment runs in this repository's workflows.

Read [the runtime runbook](docs/architecture/tn10-shadow-v2.md),
[upstream provenance](UPSTREAM.md), [test coverage](docs/testing.md), and
[the extraction plan](docs/plans/independent-v2.md).

## Remaining live gates

A reviewed real TN10 seed inventory, compact historical retention, wider API
coverage, measured load/parity, parallel DEV operation and cutover remain open.
The example configuration deliberately contains no live database or node URL.
