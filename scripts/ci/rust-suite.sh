#!/usr/bin/env bash
set -euo pipefail
: "${DATABASE_URL:?Use a disposable test PostgreSQL server}"
export SHADOW_DECODER_REVISION
SHADOW_DECODER_REVISION=$(cat decoder-compatibility.txt)
case "${1:?suite required}" in
  general)
    python3 -m unittest discover -s scripts/tests -p 'test_tn10_recovery_audit.py' -v
    cargo test --workspace --locked --exclude tn12-indexer-db --exclude tn12-indexer-crawl
    cargo check --locked -p tn12-indexer-db --example bench_tn10_writer_budget
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c 'CREATE DATABASE projector_reconnect_ci'
    export TEST_PROJECTOR_DATABASE_URL="${DATABASE_URL%/postgres}/projector_reconnect_ci"
    trap 'psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "DROP DATABASE projector_reconnect_ci WITH (FORCE)"' EXIT
    DATABASE_URL="$TEST_PROJECTOR_DATABASE_URL" cargo run --locked -p tn12-indexer-cli --bin tn12-indexer -- kcc20-projector --migrate --max-iterations 1
    cargo test --locked -p tn12-indexer-cli --bin tn12-indexer projector_tests -- --ignored --test-threads=1
    ;;
  db-unit)
    cargo test --locked -p tn12-indexer-db --lib --bins --examples
    cargo test --locked -p tn12-indexer-db --doc ;;
  db-integration-heavy|db-integration-other)
    python3 scripts/ci/run_db_integrations.py "${1#db-integration-}" ;;
  crawl) cargo test --locked -p tn12-indexer-crawl ;;
  recovery-db) cargo test --locked --release -p tn12-indexer-db --lib budget_regression -- --ignored --test-threads=1 ;;
  recovery-crawl) cargo test --locked --release -p tn12-indexer-crawl --lib tip_budget_partial_prefix -- --ignored --test-threads=1 ;;
  active-output-order) cargo test --locked --release -p tn12-indexer-db --test active_output_order large_family_lookup_500000_outputs -- --ignored --test-threads=1 ;;
  *) exit 2 ;;
esac
