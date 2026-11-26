# Parallel DEV seed and parity

The extraction is merged into `develop` at
`0c572ebd41a06e63ff9ead39c0891262217bc440`.
[Post-merge verification passed](https://github.com/KASPACOM/Markets-indexer/actions/runs/45911545216).
The next phase uses a dedicated DEV PostgreSQL instance and Markets-indexer
image. Consumer cutover follows separate parity and load evidence.

## Source preflight

Read-only inspection of DEV found:

- `tn10_indexer_dev` occupies 818 GB as reported by `pg_size_pretty`.
  `covenant_actions` accounts for 615 GB and `covenant_utxos` for 186 GB.
- All 149 source migrations completed. Their SQL and the decoder/vendor inputs
  have no Git diff between deployed source revision
  `4e0dc2573c3a8289c71905ef1d5e7338d36f1225` and compatibility revision
  `2306f23cd3bacff4ead8d78477563697579a6057`.
- The configured node health reports version 2.1.0, synced, UTXO indexed, on
  `kaspa-testnet-10`. Direct V2 wRPC source admission still has to pass.
- `chain_wrpc_live_cursor` stores a blue score without a hash. The exact score
  may have no row in `blocks`. A bounded REST virtual-chain lookup resolved an
  observed score to a hash, but this is not a seed checkpoint proof.

These observations are a preflight sample, not a frozen source inventory.
Recheck them at seed capture. Preserve the actual source image revision and the
separately reviewed decoder compatibility revision in evidence.

## Storage decision

The current seed contract retains all historical action evidence. It does not
implement a seven-day retention window. A full copy needs dedicated storage
sized for the database, WAL, growth and seed workspace. The logical exporter
also performs full evidence digest queries, so do not start its large sorts on
the live writer as a routine smoke test.

Choose either a temporary full-size DEV copy or a reviewed compact dependency
closure. The choice is pending. No new database or seed has been provisioned by
this preparation change. An EBS clone alone would not satisfy the current V2
seed-import contract; it needs a reviewed adoption path or a validated logical
export/import from the frozen copy.

## Execution gates

1. Provision an isolated DEV database, credentials and storage after sizing.
   Keep existing canonical and standby databases intact. Use a new instance UUID.
2. Capture a consistent source view, every required table, active UTXOs of every
   age, protocol evidence and migration identity. Confirm no incomplete write
   intent. Resolve and verify the exact committed VSPC hash, score and timestamp;
   never substitute a later tip or `MAX(blue_score)`.
3. Produce and validate the seed using the reviewed import contract. Initialization
   and import retain writer guards and leave readiness and source validation false.
4. Run the pinned image against TN10. Verify source identity and acceptance
   evidence, finish the first fenced cycle and inspect readiness and checkpoint.
5. Compare every retained active UTXO and required projection baseline at the
   frozen seed boundary. Then run sampled HTTP comparisons during live following.
6. Measure lag, catch-up rate, reorg handling, RSS, WAL, database growth, API latency
   and restart behavior. Keep the 5-second lag and 2-minute restart targets
   provisional until measured. Expand route coverage only with its own evidence.

## Image and sampled HTTP tooling

The `DEV runtime image artifact` workflow builds the runtime with separate source
and decoder labels, smoke-tests both binaries and exports a checksummed Docker
archive. It does not push an image or deploy. Verify the archive checksum and
labels before publishing its immutable image to the DEV registry.

`scripts/dev/compare_api.py` makes three sequential reads per path: source,
target, source. A changed source is inconclusive. Equal HTTP errors, redirects
and malformed JSON cannot count as parity. JSON object key order is ignored;
array order, balances, timestamps and all other response values are preserved.
Evidence records hashes, statuses, generation headers and durations, without
response bodies. Use credential-free endpoints and paths.

```bash
python3 -m unittest discover -s scripts/tests -p test_dev_parity.py -v

# Replace with a reviewed sample of deployed, supported current-state routes.
# Use nonempty examples across protocol families, including long-lived UTXOs.
python3 scripts/dev/compare_api.py \
  --source https://tn10-indexer.kaspa.com \
  --target http://127.0.0.1:18080 \
  --paths /private/reviewed-parity-paths.json \
  --output /private/dev-parity.json
```

The paths file is a JSON array of at most 32 unique relative paths. Each response
is capped at 2 MiB; socket operations time out after five seconds. The target URL
above assumes a port-forward to the isolated DEV API. It is not an existing
deployment. Each fetch runs in a child process that is killed after five seconds,
including DNS resolution and slow streaming reads. Query parameters are limited
to numeric `limit`, `offset`, `from` and `to`; `limit` is capped at 100.
Exit status is 0 for all samples matched, 1 for a mismatch, and 2 for an
inconclusive/unavailable run. Configuration errors also exit nonzero.

Sampled three-read equality cannot prove a common database checkpoint or detect
source changes that revert between reads. Health routes have different V1/V2
contracts and are checked separately. A matching sample is not full-state,
historical, throughput or cutover certification.
