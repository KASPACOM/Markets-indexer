# Independent V2 extraction

Import the tested V2 implementation from KASPACOM/kaspa-covenants commit
`2306f23cd3bacff4ead8d78477563697579a6057`. Markets-indexer owns its copied
code, dependencies, tests and future releases. There is no runtime dependency
on the original private repository.

## Scope

- Preserve all six Rust crates, migration bytes, protocol fixtures and embedded assets.
- Preserve the command names, SHADOW_* configuration, database markers, API
  coverage restrictions, recovery fences and archive formats.
- Record upstream provenance and imported hashes. Keep the decoder compatibility
  revision separate from the new repository's source revision.
- Provide an isolated PostgreSQL 16 Compose test environment and one verification command.
- Verify PostgreSQL 15/16, imported Rust regressions, V2 recovery/replay/API
  behavior and both runtime binaries in an independently built image.
- Split review into proposal, implementation and test PRs. Leave the original
  source PRs open as references.

## Acceptance

A clean clone builds and tests without a sibling repository or private upstream
credentials. CI runs against the reviewed revision. Local checks use only
owned disposable databases. Independent review has no unresolved blockers.

## Next phase

Real TN10 seed inventory, compact historical retention, full API coverage,
measured load/parity, parallel DEV operation and consumer cutover remain open.
This extraction does not deploy or publish a release image.
