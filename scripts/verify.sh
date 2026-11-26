#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-postgres}
case "$mode" in postgres|full) ;; *) echo "Usage: bash scripts/verify.sh [postgres|full]" >&2; exit 2;; esac
project="markets-verify-$(date +%s)-$$"
compose=(docker compose --project-name "$project" --file compose.verify.yml)
cleanup() { "${compose[@]}" down --volumes --remove-orphans; }
trap cleanup EXIT
"${compose[@]}" up --detach --wait postgres
"${compose[@]}" run --build --rm tests
if [[ "$mode" == full ]]; then
  port=$("${compose[@]}" port postgres 5432)
  export DATABASE_URL="postgresql://markets_test:markets_test@${port}/postgres"
  export SHADOW_DECODER_REVISION
  SHADOW_DECODER_REVISION=$(cat decoder-compatibility.txt)
  export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
  for suite in general db-unit db-integration-heavy db-integration-other crawl recovery-db recovery-crawl active-output-order; do
    bash scripts/ci/rust-suite.sh "$suite"
  done
fi
