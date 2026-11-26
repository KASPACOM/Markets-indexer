# TN10 shadow indexer V2

The shadow executable follows node acceptance into a dedicated database. V1
consumers and deployments stay unchanged. Run each release with its own database
instance UUID and image. The source and target database URLs have no defaults.

## Components

`tn10-shadow-indexer` uses a bounded direct Borsh wRPC connection to poll
`getVirtualChainFromBlock` from the committed hash. Pulling from a durable hash
provides reconnect and catch-up without an unbounded notification relay. The
current adapter uses the original RPC method supported by the pinned node SDK;
V2 RPC capability is not assumed. The node supplies acceptance order and removed
hashes. `DurableJoin` verifies selected-parent continuity and resolves accepted
bodies from bounded block and merge-set fetches.

A complete bounded plan is committed before state changes. Each ordered step
calls the existing `PgPersister` effects or rollback implementation. Actual state
writes, preimages and the step cursor share a transaction. Accepted and removed
events are retained separately as append-only history. Reacceptance reuses the
existing output identity.

Projection work runs after all ingestion steps. Every public-table mutation has
a database trigger that locks and checks the permanent epoch and active plan.
A stale projector is fenced even when its implementation starts its own
transactions. Required consumers are fixed on plan creation. Verification and
consumer completion occur under the coordination lock; publication seals the
revision and release publishes readiness. A crash after seal resumes release.

The API admits at most half its database pool (capped at four requests) before
taking a read fence, reserving connections for handler queries. Excess reads
return 503 without queueing. A ten-second request deadline releases stalled
read fences. The API holds a coordination share lock for the entire handler. Writers cannot
change state while a handler reads multiple pooled connections. Recovery reads
return 503. POST routes are disabled. Existing read handlers retain their response
shapes, with generation and history-coverage headers. Explicit `from` requests
before the seed boundary and unverified transaction lookups return 409.
The initial current-state route allowlist covers active UTXO reads and template
metadata. KCC20 activity/candles require an explicit `from` within coverage.
Other historical or mixed aggregate routes return 409, including unbounded
`/events`, address events and covenant actions. Their existing response contracts
need a separate coverage/parity proof before enabling them; a missing `from`
never means complete history.

## Resource boundaries

| Resource | Current bound |
| --- | --- |
| RPC frame/message | 8 MiB |
| Source fetch per cycle | 64 MiB, 256 blocks |
| Join cache | 32 MiB, existing conservative object accounting |
| Prepared effects | Existing 16 MiB join bound |
| Serialized plan | 32 MiB in source adapter, 64 MiB database/replay maximum |
| One evidence/preimage row | 8 MiB |
| Retained journal/evidence accounting | 20 GiB default, configurable database control |
| Writer connections | 4 |
| SQL statement / lock waits | 30 seconds / 5 seconds, narrower existing phase limits apply |
| Reconnect delay | Exponential, capped at 30 seconds |

A bound stops the cycle and retains progress. It never skips to the current tip.
Added blocks are processed in bounded prefixes (`--batch-blocks`, default 8,
maximum 16), then the next request resumes from that prefix hash. A node response
that itself exceeds the frame cap or a reorg beyond 128 removals stops for an
operator-reviewed recovery window or reseed.
Logical retained-byte accounting is not a physical disk quota. Measure RSS, WAL,
indexes and filesystem usage before setting deployment limits.

## Initialize and seed

Build the isolated image with a pinned decoder identity:

```bash
docker build -f Dockerfile.shadow-v2 \
  --build-arg SHADOW_DECODER_REVISION="$REVIEWED_DECODER_REVISION" \
  -t tn10-shadow-v2:local .
```

`REVIEWED_DECODER_REVISION` must match the seed's decoder identity. It identifies
the reviewed decoder compatibility revision, separately from the V2 image commit.
Do not relabel incompatible source state to pass this check. Live runs, replay
and the shadow API require the compiled pin; status remains available for diagnosis.
Source genesis must equal the TN10 genesis in the pinned node SDK.

Set `SHADOW_DATABASE_URL`, `SHADOW_INSTANCE_ID` (a new UUID), and
`SHADOW_WRPC_URL` in the runtime environment. The database must be dedicated and
empty. Initialization refuses any existing public or V2 tables.

```bash
tn10-shadow-indexer init
python scripts/shadow-v2/snapshot.py seed-export \
  --inventory /private/reviewed-seed-inventory.json --output /private/seed
python scripts/shadow-v2/snapshot.py seed-import \
  --instance-id "$SHADOW_INSTANCE_ID" --expected-source-id "$REVIEWED_SOURCE_ID" --input /private/seed
tn10-shadow-indexer run --once
tn10-shadow-indexer run
```

The export reads `SHADOW_SEED_SOURCE_DSN`. Import reads `SHADOW_DATABASE_URL`.
The Python tools require `scripts/shadow-v2/requirements.txt` and PostgreSQL
client tools matching the server major (or `SHADOW_PG_BIN` pointing to them). Source export uses one read-only repeatable-read snapshot.

The inventory is an explicit JSON contract:

```json
{
  "network": "testnet-10",
  "decoder_revision": "exact-source-revision",
  "source_identity_query": "SELECT network, genesis_hash, decoder_revision, source_id FROM reviewed_source_identity",
  "checkpoint_query": "SELECT exact_hash, exact_score, exact_time FROM reviewed_checkpoint_view",
  "evidence_contract": "Describe retained scripts, witnesses, payloads and previous outputs.",
  "assertions": ["SELECT source_ready AND evidence_complete FROM reviewed_seed_readiness"],
  "tables": {
    "blocks": {"query": "SELECT * FROM reviewed_required_blocks", "retention": "current-closure", "purpose": "Dependency closure and checkpoint"},
    "covenants": {"query": "SELECT * FROM covenants", "retention": "full", "purpose": "Protocol identity and current metadata"},
    "covenant_utxos": {"query": "SELECT * FROM covenant_utxos WHERE status='active'", "retention": "current-closure", "purpose": "Every active indexed output, regardless of age"}
  }
}
```

This example is a contract shape, not an executable production inventory.
The abbreviated table list above will be rejected. Every public table must be
listed, including protocol state, projection dependencies and evidence. Only
`blocks` and `covenant_utxos` may use `current-closure`; every other table requires
`full` retention and an independent source multiset digest verified after import.
This deliberately retains action/evidence dependencies until a narrower closure
has its own proof. Source identity comes from a reviewed database query in the
same snapshot, not the inventory's label. Import requires its expected source ID.
Include all active protocol state, projection baseline dependencies and required
covenant evidence in dependency order. The checkpoint query must identify the
state's committed hash, not `MAX(blue_score)` or a later node tip. The exporter
independently hashes every active UTXO and import rejects any omission. Column
shapes, file hashes, row counts and foreign keys must match. Initialization installs writer guards before the database is usable. Seed import
replaces data and restores all guards within one transaction; it cannot overwrite
an active target. Import leaves readiness false. The first live cycle checks the
checkpoint hash and score against the configured, synced TN10 node, runs
projections and publishes through the normal fenced plan, even if the node has
no new blocks. A durable source-validation flag is committed with that first
plan; replay cannot activate an imported seed. Backups preserve this verified
activation, allowing offline replay after restore. A seed identity is provenance, not a substitute for that node check.

The existing projectors derive some totals from historical actions. A seed
inventory must preserve the evidence needed for those totals or explicitly limit
those API contracts to covered history. Copying summary tables alone does not
prove that later refreshes preserve lifetime totals. An actual TN10 inventory and
route parity run are required before consumer cutover.

## Serve the shadow API

```bash
covenant-tools-api --database-url "$SHADOW_DATABASE_URL" \
  --shadow-instance-id "$SHADOW_INSTANCE_ID" --bind 127.0.0.1:8082
```

Do not set payment, source-observer, fixture, migration or historical database
options on this process. The API refuses those combinations. `/health/live` and
`/readyz` report serving readiness; `/health/history` reports incomplete historical
coverage. `/metrics` exposes generation, epoch, revision and retained evidence
bytes. `tn10-shadow-indexer status` prints the durable plan and cursor.

## Snapshot, archive and replay

A backup exports a single database snapshot, its generation/checkpoint, the active
UTXO digest and decoder revision. It does not compare against a later live view.
Snapshots and archive files contain evidence bytes; hashes alone are insufficient.

```bash
python scripts/shadow-v2/snapshot.py backup \
  --decoder-revision "$DECODER_REVISION" --output /private/backup
python scripts/shadow-v2/archive.py export --after-plan "$BASE_COMPLETED_PLAN" \
  --decoder-revision "$DECODER_REVISION" --output /private/archive
# Point SHADOW_DATABASE_URL at an empty restoration database first.
python scripts/shadow-v2/snapshot.py restore \
  --decoder-revision "$DECODER_REVISION" --input /private/backup
python scripts/shadow-v2/archive.py replay \
  --decoder-revision "$DECODER_REVISION" --input /private/archive
```

Archive export streams completed plans in order and retains undo records in
separate files. Replay checks checksums, network and checkpoint continuity, then
uses the pinned Rust binary without a node connection. A receipt identifies the
exact replayed file; equal block hashes alone do not prove a replay completed.
No automatic deletion or pruning is enabled. A reorg that crosses the seed
checkpoint stops for a verified reseed.

## Validation gates

The test PR runs the coordination suite on PostgreSQL 15 and 16, synthetic Rust
persistence/reorg parity, bounded wire decoding, API fencing and snapshot/restore
checks. These are separate from source-node capability checks, measured sustained
load, current-state seed parity and live API parity. Record the tested commit,
commands, results and uncovered gates before any deployment decision.
