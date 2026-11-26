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
Existing capture-only tests remain ignored: `captured_full_window_paired_benchmark`
requires TN10_CONSOLIDATION_FIXTURE, and
`captured_window_matches_reference_and_reuses_verified_baseline` requires
TN10_GENESIS_CAPTURE. Live wRPC/REST smoke tests require TN10_WRPC_TEST_URL or
TN10_REST_TEST_URL and remain out of this offline suite. Tests for retired
protocol profiles retain their upstream ignore annotations. These are not
claimed as executed coverage.

Full local verification reserves 127.0.0.1:55439 because the existing uncertain-
commit fault proxy asserts that port. If occupied, Docker refuses the bind;
the runner never attaches to another database. PostgreSQL-only mode uses a
random loopback port.

The provenance check retains byte identity for imported code, migration checksums
and fixtures. Changes to imported files require a reviewed entry in
`extraction-changes.json`; `upstream-files.json` stays the historical source hash.
The decoder compatibility pin must be reviewed separately when decoder behavior changes.

Offline tests use synthetic state, mock nodes and retained historical fixtures.
Real seed inventory, live parity/load, full API coverage, compact retention,
DEV deployment and consumer cutover are separate gates.
