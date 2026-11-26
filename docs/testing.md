# Verification coverage

`bash scripts/verify.sh` runs PostgreSQL 16 coordination, snapshot and archive
tests in an isolated Compose project. `bash scripts/verify.sh full` also runs
the imported Rust suites. The full mode requires the host Rust toolchain and
PostgreSQL client. Both modes clean up their own Compose resources on exit.

Hosted verification has these jobs:

- PostgreSQL 15 and 16: 12 coordination, 9 snapshot, 4 archive tests.
- Targeted Rust: actual persistence/reorg, bounded intake, source admission and
  identity, restart/replay, supported HTTP parity and rejected coverage,
  API concurrency admission and deadline release.
- Regression matrix: general workspace, DB unit/doc/examples, two DB integration
  shards, crawler, release writer recovery, release crawl budget and large-family lookup.
- General suite also runs the recovery-audit Python tests and ignored projector
  interruption regressions against its disposable migrated database.
- Local Compose command on a clean hosted clone.
- Release image build plus both packaged binary help commands. No image is pushed.

Every job uploads its tested SHA. Job logs contain test counts and failures.
Imported `#[ignore]` annotations stay unchanged. Release budget, active-output
ordering and projector tests have explicit jobs that opt into their named ignores.
Other upstream ignored tests and runtime fixture-availability skips remain
visible in their source/logs; they are not claimed as executed coverage.

The provenance check retains byte identity for imported code, migration checksums
and fixtures. Changes to imported files require a reviewed entry in
`extraction-changes.json`; `upstream-files.json` stays the historical source hash.
The decoder compatibility pin must be reviewed separately when decoder behavior changes.

Offline tests use synthetic state, mock nodes and retained historical fixtures.
Real seed inventory, live parity/load, full API coverage, compact retention,
DEV deployment and consumer cutover are separate gates.
