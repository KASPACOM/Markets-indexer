use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

const KCC20_PROJECTOR_LOCK_KEY: i64 = 0x544e31324b433230;

#[derive(Parser, Debug)]
#[command(name = "covenant-tools")]
#[command(about = "KaspaCom covenant scanner and maintenance CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Apply database migrations and required indexes as the sole migration owner.
    Migrate {
        /// Explicitly retire duplicate non-unique action index prefixes after validation.
        #[arg(long)]
        retire_action_prefix_indexes: bool,
        /// Postgres connection URL.
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
    },
    /// Print a starter watch-list config.
    SampleConfig,
    /// Print a fixture RPC response for local testing.
    SampleRpcResponse,
    /// Poll watched covenant addresses and update the local store.
    Sync {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        store: PathBuf,
        /// Read UTXOs from a fixture JSON instead of a live RPC.
        #[arg(long)]
        fixture_rpc: Option<PathBuf>,
    },
    /// List indexed UTXOs.
    List {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        contract: Option<String>,
        #[arg(long)]
        active_only: bool,
    },
    /// Show one watched contract and its indexed UTXOs.
    Show {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        contract: String,
    },
    /// Print the full store as pretty JSON.
    ExportJson {
        #[arg(long)]
        store: PathBuf,
    },
    /// Replay one or more captured REST transactions through the indexer
    /// engine and print the emitted covenant events as JSON. Use this to
    /// verify the data pipeline against known on-chain fixtures
    /// (see `fixtures/timelock-live/`).
    Replay {
        /// Path to a captured REST transaction JSON file. Repeatable; files are
        /// processed in the order given.
        #[arg(long = "fixture", num_args = 1.., required_unless_present = "fixture_dir")]
        fixtures: Vec<PathBuf>,
        /// Directory of captured REST transaction JSON files. Each `.json`
        /// inside is processed in lexicographic order.
        #[arg(long = "fixture-dir")]
        fixture_dir: Option<PathBuf>,
    },
    /// Probe one captured batch of 1-16 independent generic transactions.
    /// Writes require --apply; never advances a scanner cursor or runs migrations.
    GuardedGenericProbe {
        #[arg(long)]
        fixture: PathBuf,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Fetch a single transaction from the configured REST API and run it through
    /// the engine + Postgres persister (if --database-url is set).
    Ingest {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Transaction ids to fetch. Repeatable.
        #[arg(long = "txid", num_args = 1.., required = true)]
        txids: Vec<String>,
        /// Postgres connection URL. If set, txs are persisted to the DB.
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: Option<String>,
        /// Run sqlx migrations at startup.
        #[arg(long, default_value_t = false)]
        migrate: bool,
    },
    /// Reconcile only the accepted TN10 KCOM transactions named by proof receipts.
    /// Fetch and validate the entire ordered allowlist before any write.
    ReconcileKcomCampaign {
        /// Full campaign receipts in dependency order. Repeat for linked campaigns.
        #[arg(long = "receipt", num_args = 1.., required = true)]
        receipts: Vec<PathBuf>,
        #[arg(long, default_value = "https://tn10-node.kaspa.com/rest")]
        rest: String,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Persist the verified transactions. Omit for a read-only preview.
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Read one resumable page of output identity inconsistencies.
    InventoryOutputIdentities {
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 256)]
        page_size: i64,
    },
    /// Preview or apply bounded, source-verified output identity corrections.
    RepairOutputIdentities {
        #[arg(long, default_value = "https://tn10-node.kaspa.com/rest")]
        rest: String,
        #[arg(long = "txid", num_args = 1.., required = true)]
        txids: Vec<String>,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Verify and optionally fill null genesis states for up to 16 exact txids.
    /// Uses accepted REST evidence and never overwrites a decoded state.
    RepairGenesisStates {
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        #[arg(long = "txid", num_args = 1.., required = true)]
        txids: Vec<String>,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Verify and optionally repair controller state for up to 16 accepted
    /// Replay one retained transaction after decoder support is deployed.
    /// Requires matching current source acceptance; default is a read-only preview.
    ReplayDeferredDecode {
        #[arg(long)] rest: String,
        #[arg(long)] txid: String,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)] database_url: String,
        #[arg(long, default_value_t = false)] apply: bool,
    },
    /// wrapper action transactions. Default is a read-only preview.
    RepairWrapperActions {
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        #[arg(long = "txid", num_args = 1.., required = true)]
        txids: Vec<String>,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Use stored reveal classification when TN10 REST has pruned the transaction.
        #[arg(long, default_value_t = false)]
        indexed_evidence: bool,
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Live mode: poll REST `/addresses/{addr}/full-transactions` for one
    /// or more covenant addresses, ingesting new accepted txs into Postgres.
    /// Auto-discovers further P2SH addresses as new covenants appear.
    Watch {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Covenant addresses to watch. Repeatable; further addresses are
        /// auto-discovered from P2SH outputs of seen transactions.
        #[arg(long = "address", num_args = 1..)]
        addresses: Vec<String>,
        /// Postgres connection URL (required for the live mode).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations at startup.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 10)]
        poll_secs: u64,
        /// Per-address tx fetch limit per poll.
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },
    /// Live mode: join Kaspa wRPC `blockAdded` transaction bodies with
    /// `virtualChainChanged` acceptance events and persist covenant txs.
    WrpcWatch {
        /// Deprecated compatibility option. REST gap repair runs in `tip-follow`.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Kaspa wRPC Borsh URL.
        #[arg(long)]
        wrpc_url: String,
        /// Kaspa network id used by the wRPC client.
        #[arg(long, default_value = "testnet-10")]
        network_id: String,
        /// Postgres connection URL (required for live mode).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations at startup.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Deprecated compatibility option; accepted but ignored.
        #[arg(
            long,
            env = "WRPC_FETCH_CONCURRENCY",
            default_value_t = 32,
            hide = true
        )]
        fetch_concurrency: usize,
        /// Maximum transaction bodies and block headers retained for stream joins.
        #[arg(long, env = "WRPC_CACHE_CAPACITY", default_value_t = 100_000)]
        cache_capacity: usize,
        /// Dedicated wRPC progress cursor; never share a repair scanner cursor.
        #[arg(
            long,
            env = "WRPC_CURSOR_KEY",
            default_value = "chain_wrpc_live_cursor"
        )]
        cursor_key: String,
    },
    /// Re-run the decoder registry against every covenant currently
    /// `template_name IS NULL` that has at least one spend on record.
    /// Idempotent. Run after adding new template decoders so historical
    /// covenants pick up their classifications without a full re-scan.
    Reclassify {
        /// Chain REST base URL (used to fetch spend txs for the redeem
        /// script reveal).
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Stop after this many covenants. 0 = unlimited.
        #[arg(long, default_value_t = 0)]
        limit: u32,
        /// Concurrent REST transaction fetches.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Retry each REST transaction fetch this many times after the first
        /// attempt fails.
        #[arg(long, default_value_t = 0)]
        retries: u32,
        /// Base retry delay in milliseconds. Backoff is linear per attempt.
        #[arg(long, default_value_t = 500)]
        retry_delay_ms: u64,
    },
    /// For every covenant currently `template_name IS NULL`, walk that
    /// covenant address's full-transactions feed and persist each tx. Catches
    /// covenants whose spend tx the scanner missed (pre-PR-#24 spend-only
    /// filter bug, or watcher seeded without their address). Persist is
    /// idempotent so already-seen deploys are a no-op.
    AutoDiscoverSpends {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Stop after this many covenants. 0 = unlimited.
        #[arg(long, default_value_t = 0)]
        limit: u32,
        /// Max txs fetched per covenant address per pass.
        #[arg(long, default_value_t = 50)]
        per_address_limit: u32,
        /// Concurrent address transaction feed fetches. Keep this low for
        /// public chain REST endpoints to avoid cascading request timeouts.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Retry each address transaction feed fetch this many times after the
        /// first attempt fails.
        #[arg(long, default_value_t = 0)]
        retries: u32,
        /// Base retry delay in milliseconds. Backoff is linear per attempt.
        #[arg(long, default_value_t = 500)]
        retry_delay_ms: u64,
    },
    /// Backfill wallet-supplied deployment claims from genesis tx payloads for
    /// historical rows that were discovered through scanner paths without a
    /// payload.
    RepairPayloadClaims {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Stop after this many covenants. 0 = unlimited.
        #[arg(long, default_value_t = 0)]
        limit: u32,
        /// Concurrent REST transaction fetches. Keep this low for public chain REST
        /// endpoints to avoid cascading request timeouts.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Retry each REST transaction fetch this many times after the first
        /// attempt fails.
        #[arg(long, default_value_t = 3)]
        retries: u32,
        /// Base retry delay in milliseconds. Backoff is linear per attempt.
        #[arg(long, default_value_t = 500)]
        retry_delay_ms: u64,
    },
    /// Recompute native KIP-20 covenant ids for historical rows that were
    /// keyed by script_hash because REST omitted output covenant bindings.
    /// Defaults to dry-run; take a DB backup before running with --apply.
    RepairNativeCovenantIds {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Stop after this many fallback-keyed covenants. 0 = unlimited.
        #[arg(long, default_value_t = 0)]
        limit: u32,
        /// Concurrent REST transaction fetches.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Retry each REST transaction fetch this many times after the first
        /// attempt fails.
        #[arg(long, default_value_t = 3)]
        retries: u32,
        /// Base retry delay in milliseconds. Backoff is linear per attempt.
        #[arg(long, default_value_t = 500)]
        retry_delay_ms: u64,
        /// Actually rekey rows. Omit for dry-run.
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Repair historical KCC20 active UTXO state and rebuild holder rows for
    /// one canonical token id. This replaces the one-off SQL used during the
    /// KIP-20 migration.
    RepairKcc20Holders {
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Canonical KIP-20 token/covenant id.
        #[arg(long)]
        token_id: String,
        /// Active output P2SH script hash to map to --token-id. Repeatable.
        #[arg(long = "script-hash")]
        script_hashes: Vec<String>,
        /// Active output state as
        /// scriptHash:owner:ownerScheme:amount:isMintAuthority.
        /// Repeatable.
        #[arg(long = "state")]
        states: Vec<String>,
        /// Replace existing state values instead of only filling missing state.
        #[arg(long, default_value_t = false)]
        overwrite_states: bool,
        /// Holder last_change_ms. Defaults to current wall-clock time.
        #[arg(long)]
        last_change_ms: Option<i64>,
        /// Report the changes that would be made, then roll back.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Revert one or more removed chain blocks from Postgres and rewind the
    /// chain-scan cursor to the lowest reverted blue score. This is the same
    /// rollback path the future wRPC virtual-chain listener will call.
    RevertBlocks {
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Removed chain block hashes to revert. Repeatable.
        #[arg(long = "block-hash", num_args = 1.., required = true)]
        block_hashes: Vec<String>,
    },
    /// Verify and optionally reconcile canonical transaction acceptance.
    ReconcileAcceptingBlock {
        #[arg(long)]
        rest: String,
        #[arg(long)]
        old_hash: String,
        #[arg(long)]
        new_hash: String,
        #[arg(long)]
        transaction_id: String,
        /// Omit for equivalent-block source verification only. With a DB,
        /// preview executes the repair and rolls it back; splits require a DB.
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: Option<String>,
        /// Apply the verified reference update. Default is preview only.
        #[arg(long, requires = "database_url")]
        apply: bool,
    },
    /// Run one API payment settlement policy sweep. The sweep claims
    /// settlable channels and disables threshold-hit channels that cannot
    /// currently be settled.
    ApiPaymentSettlementSweep {
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations before the sweep.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Current wall-clock override in milliseconds. Defaults to now.
        #[arg(long)]
        now_ms: Option<i64>,
        /// Claim/disable when unsettled spend reaches this amount. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        min_unsettled_sompi: i64,
        /// Claim/disable when latest voucher sequence reaches this value. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        min_unsettled_sequences: i64,
        /// Claim/disable when the latest accepted voucher is this old. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        max_voucher_age_ms: i64,
        /// Claim/disable channels this close to refundAfterMs. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        refund_safety_margin_ms: i64,
        /// Maximum channels to touch in one sweep.
        #[arg(long, default_value_t = 100)]
        limit: i64,
        /// Only report candidates; do not mutate channel or authorization state.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Repeat the sweep forever at this interval. Omit for a single sweep.
        #[arg(long)]
        interval_secs: Option<u64>,
        /// Stop after this many iterations when --interval-secs is set. Mostly
        /// useful for supervised smoke tests.
        #[arg(long)]
        max_iterations: Option<u64>,
    },
    /// Disable API payment channels whose open transaction was never indexed
    /// before the activation timeout.
    ApiPaymentOpeningReconcile {
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations before the reconciliation.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Current wall-clock override in milliseconds. Defaults to now.
        #[arg(long)]
        now_ms: Option<i64>,
        /// Disable opening channels older than this age.
        #[arg(long, default_value_t = 900_000)]
        max_opening_age_ms: i64,
        /// Maximum channels to touch in one pass.
        #[arg(long, default_value_t = 100)]
        limit: i64,
        /// Only report candidates; do not mutate channel state.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Repeat the reconciliation forever at this interval. Omit for a single pass.
        #[arg(long)]
        interval_secs: Option<u64>,
        /// Stop after this many iterations when --interval-secs is set.
        #[arg(long)]
        max_iterations: Option<u64>,
    },
    /// Claim API payment settlement authorizations and submit their stored
    /// wallet-lab settlement artifacts through the provider wallet.
    ApiPaymentSettlementBroadcast {
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations before the broadcaster.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Current wall-clock override in milliseconds. Defaults to now.
        #[arg(long)]
        now_ms: Option<i64>,
        /// Claim when unsettled spend reaches this amount. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        min_unsettled_sompi: i64,
        /// Claim when latest voucher sequence reaches this value. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        min_unsettled_sequences: i64,
        /// Claim when the latest accepted voucher is this old. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        max_voucher_age_ms: i64,
        /// Claim channels this close to refundAfterMs. 0 disables this trigger.
        #[arg(long, default_value_t = 0)]
        refund_safety_margin_ms: i64,
        /// Maximum channels to touch in one pass.
        #[arg(long, default_value_t = 100)]
        limit: i64,
        /// Only report candidates; do not claim or submit.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Provider wallet JSON path used by wallet-lab to add the provider signature.
        #[arg(long, env = "API_PAYMENT_PROVIDER_WALLET_PATH")]
        provider_wallet_path: Option<PathBuf>,
        /// Kaspa wRPC Borsh URL used for submit.
        #[arg(
            long,
            env = "KASPA_WRPC_URL",
            default_value = "ws://tn10-node.kaspa.com:17210"
        )]
        wrpc_url: String,
        /// Kaspa network id.
        #[arg(long, env = "API_PAYMENT_NETWORK_ID", default_value = "testnet-10")]
        network_id: String,
        /// Node.js executable.
        #[arg(long, default_value = "node")]
        node_bin: PathBuf,
        /// wallet-lab settlement submit script.
        #[arg(
            long,
            default_value = "wallet-lab/scripts/api-payments/api-channel-settle.mjs"
        )]
        settle_script: PathBuf,
        /// Repeat the broadcaster forever at this interval. Omit for a single pass.
        #[arg(long)]
        interval_secs: Option<u64>,
        /// Stop after this many iterations when --interval-secs is set.
        #[arg(long)]
        max_iterations: Option<u64>,
        /// Exit non-zero when a claimed settlement submission is rejected.
        #[arg(
            long,
            env = "API_PAYMENT_BROADCAST_FAIL_ON_REJECTED",
            default_value_t = false
        )]
        fail_on_rejected: bool,
    },
    /// covenant output, and persist it. Discovers covenants without a seed
    /// address — meant to run alongside the address-based `watch` mode.
    Scan {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// Postgres connection URL (required).
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations at startup.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Starting blue score when no cursor is present in DB.
        #[arg(long, default_value_t = 0)]
        from_blue_score: u64,
        /// Start at current chain tip minus this window when no cursor is present.
        #[arg(long, env = "SCAN_FROM_TIP_WINDOW")]
        from_tip_window: Option<u64>,
        /// Cursor key in indexer_state. Use a distinct key for parallel scanners.
        #[arg(long, env = "SCAN_CURSOR_KEY", default_value = "chain_scan_cursor")]
        cursor_key: String,
        /// Blocks per REST page.
        #[arg(long, default_value_t = 50)]
        batch_size: u32,
        /// Sleep (s) when the chain tip is reached.
        #[arg(long, default_value_t = 15)]
        idle_secs: u64,
        /// Concurrent REST fetches used to hydrate missing transaction payloads.
        #[arg(long, env = "SCAN_HYDRATE_CONCURRENCY", default_value_t = 8)]
        hydrate_concurrency: usize,
        /// Concurrent REST fetches used to backfill missing P2SH prevouts.
        #[arg(long, env = "SCAN_PREVOUT_CONCURRENCY", default_value_t = 8)]
        prevout_concurrency: usize,
    },
    /// Replay one bounded historical REST window without changing any cursor.
    ReplayWindow {
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Start score, aligned to batch-size.
        #[arg(long)]
        blue_score: u64,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=100))]
        batch_size: u32,
    },
    /// Follow canonical REST windows and durably repair every gap after restart.
    TipFollow {
        /// Chain REST base URL.
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        /// REST source to use after the durable cursor crosses a verified overlap.
        #[arg(long, requires = "switch_blue_score")]
        next_rest: Option<String>,
        /// Settled 100-score boundary shared by both REST sources.
        #[arg(long, requires = "next_rest")]
        switch_blue_score: Option<u64>,
        /// Postgres connection URL.
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations at startup.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Freshness cursor key. Keep separate from repair cursors.
        #[arg(
            long,
            env = "TIP_FOLLOW_CURSOR_KEY",
            default_value = "chain_realtime_tip_cursor"
        )]
        cursor_key: String,
        /// Blue-score width per REST window.
        #[arg(long, env = "TIP_FOLLOW_BATCH_SIZE", default_value_t = 10)]
        batch_size: u32,
        /// Number of recent windows retained for reorg detection.
        #[arg(long, env = "TIP_FOLLOW_OVERLAP_WINDOWS", default_value_t = 2)]
        overlap_windows: u32,
        /// Maximum sequential REST windows repaired in one pass.
        #[arg(long, env = "TIP_FOLLOW_MAX_CATCHUP_WINDOWS", default_value_t = 1_000)]
        max_catchup_windows: u32,
        /// Delay between tip snapshots in milliseconds.
        #[arg(long, env = "TIP_FOLLOW_POLL_MS", default_value_t = 500)]
        poll_ms: u64,
        /// Revisit one settled REST window per near-tip pass across this many scores.
        #[arg(
            long,
            env = "TIP_FOLLOW_SETTLED_RECHECK_SPAN_SCORES",
            default_value_t = 0
        )]
        settled_recheck_span_scores: u64,
        /// Keep rechecks this far behind the current REST tip.
        #[arg(
            long,
            env = "TIP_FOLLOW_SETTLED_RECHECK_MIN_AGE_SCORES",
            default_value_t = 0
        )]
        settled_recheck_min_age_scores: u64,
        /// Prefetch complete 100-score REST pages after sparse historical windows.
        #[arg(long, env = "TIP_FOLLOW_ADAPTIVE_PREFETCH", default_value_t = false)]
        adaptive_prefetch: bool,
        /// Concurrent ten-score REST windows to fetch before ordered writes.
        #[arg(long, env = "TIP_FOLLOW_WINDOW_FETCH_CONCURRENCY", default_value_t = 1)]
        window_fetch_concurrency: usize,
        /// Allow bounded, double-checked canonical reconciliation at the live tip.
        #[arg(
            long,
            env = "TIP_FOLLOW_RECENT_ACCEPTANCE_RECONCILIATION",
            default_value_t = false
        )]
        recent_acceptance_reconciliation: bool,
        /// Concurrent REST fetches used to hydrate transaction payloads.
        #[arg(long, env = "SCAN_HYDRATE_CONCURRENCY", default_value_t = 8)]
        hydrate_concurrency: usize,
        /// Concurrent REST fetches used to backfill missing P2SH prevouts.
        #[arg(long, env = "SCAN_PREVOUT_CONCURRENCY", default_value_t = 8)]
        prevout_concurrency: usize,
    },
    /// Recheck settled REST windows already covered by the history cursor.
    SettledRecheck {
        #[arg(long, default_value = "https://api-tn10.kaspa.org")]
        rest: String,
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value = "chain_realtime_tip_cursor")]
        cursor_key: String,
        #[arg(long, default_value_t = 20_000)]
        span_scores: u64,
        #[arg(long, default_value_t = 1_000)]
        min_age_scores: u64,
        #[arg(long, default_value_t = 1_000)]
        poll_ms: u64,
        #[arg(long, env = "SCAN_HYDRATE_CONCURRENCY", default_value_t = 8)]
        hydrate_concurrency: usize,
        #[arg(long, env = "SCAN_PREVOUT_CONCURRENCY", default_value_t = 8)]
        prevout_concurrency: usize,
    },
    /// Build and verify the derived active-output ordering in resumable 500-row pages.
    ActiveOutputOrderBackfill {
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value_t = 100)]
        pause_ms: u64,
    },
    /// Resume the bounded KCC20 owner-action history backfill.
    Kcc20OwnerActionBackfill {
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        #[arg(long, default_value_t = 500)]
        batch_size: i64,
        #[arg(long, default_value_t = 100)]
        pause_ms: u64,
        /// Keep watching for targeted rescans after the current backfill completes.
        #[arg(long, default_value_t = false)]
        follow: bool,
        /// Poll interval when following a completed backfill.
        #[arg(long, default_value_t = 1_000)]
        idle_ms: u64,
    },
    /// Refresh derived KCC20 market/token-page read models outside the scanner writer path.
    Kcc20Projector {
        /// Postgres connection URL.
        #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
        database_url: String,
        /// Run sqlx migrations at startup.
        #[arg(long, default_value_t = false)]
        migrate: bool,
        /// Recovery poll interval when no projection notification arrives.
        #[arg(long, env = "KCC20_PROJECTOR_IDLE_SECS", default_value_t = 5)]
        idle_secs: u64,
        /// Maximum distinct activity transaction IDs processed per pass.
        #[arg(
            long,
            env = "KCC20_PROJECTOR_ACTIVITY_MAX_TXIDS_PER_PASS",
            default_value_t = 500
        )]
        activity_max_txids_per_pass: i64,
        /// Statement timeout for activity-feed projection refreshes.
        #[arg(
            long,
            env = "KCC20_PROJECTOR_ACTIVITY_STATEMENT_TIMEOUT",
            default_value = "10s"
        )]
        activity_statement_timeout: String,
        /// Allow activity-feed full rebuilds from the projector.
        #[arg(
            long,
            env = "KCC20_PROJECTOR_FULL_REFRESH_ENABLED",
            default_value_t = false
        )]
        full_refresh_enabled: bool,
        /// Stop after this many projection passes. Omit to run forever.
        #[arg(long)]
        max_iterations: Option<u64>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Migrate {
            database_url,
            retire_action_prefix_indexes,
        } => run_async(run_migrate(database_url, retire_action_prefix_indexes)),
        Command::SampleConfig => print_json(&sample_config()),
        Command::SampleRpcResponse => print_json(&sample_rpc_response()),
        Command::Sync {
            config,
            store,
            fixture_rpc,
        } => {
            let config = read_json::<IndexerConfig>(&config)?;
            validate_config(&config)?;
            let now_ms = now_ms()?;
            let source: Box<dyn UtxoSource> = match fixture_rpc {
                Some(path) => Box::new(FixtureSource::from_file(&path)?),
                None => Box::new(HttpRpcSource::new(config.rpc_url.clone())),
            };

            let mut state = read_store_or_default(&store)?;
            sync_once(&config, &mut state, source.as_ref(), now_ms)?;
            write_json(&store, &state)?;
            println!(
                "synced {} watched contract(s), {} indexed utxo(s)",
                state.contracts.len(),
                state.utxos.len()
            );
            Ok(())
        }
        Command::List {
            store,
            contract,
            active_only,
        } => {
            let state = read_json::<IndexStore>(&store)?;
            let mut rows = state.utxos;
            rows.sort_by(|a, b| {
                a.contract_id
                    .cmp(&b.contract_id)
                    .then(a.outpoint.txid.cmp(&b.outpoint.txid))
                    .then(a.outpoint.vout.cmp(&b.outpoint.vout))
            });
            for row in rows {
                if contract.as_deref().is_some_and(|id| id != row.contract_id) {
                    continue;
                }
                if active_only && row.status != UtxoStatus::Active {
                    continue;
                }
                println!(
                    "{} {}:{} {} {} covenant_id={}",
                    row.contract_id,
                    row.outpoint.txid,
                    row.outpoint.vout,
                    row.amount_sompi,
                    row.status,
                    row.covenant_id.as_deref().unwrap_or("null")
                );
            }
            Ok(())
        }
        Command::Show { store, contract } => {
            let state = read_json::<IndexStore>(&store)?;
            let report = build_contract_report(&state, &contract)
                .with_context(|| format!("contract not found in store: {contract}"))?;
            print_json(&report)
        }
        Command::ExportJson { store } => {
            let state = read_json::<IndexStore>(&store)?;
            print_json(&state)
        }
        Command::Replay {
            fixtures,
            fixture_dir,
        } => run_replay(fixtures, fixture_dir),
        Command::GuardedGenericProbe {
            fixture,
            database_url,
            apply,
        } => run_async(run_guarded_generic_probe(fixture, database_url, apply)),
        Command::Ingest {
            rest,
            txids,
            database_url,
            migrate,
        } => run_async(run_ingest(rest, txids, database_url, migrate)),
        Command::ReconcileKcomCampaign { receipts, rest, database_url, apply } =>
            run_async(run_reconcile_kcom_campaign(receipts, rest, database_url, apply)),
        Command::InventoryOutputIdentities { database_url, after, page_size } => run_async(async move {
            let pool=tn12_indexer_db::connect(&database_url).await?;
            print_json(&tn12_indexer_db::persist::identity::inventory(&pool,after.as_deref(),page_size).await?)
        }),
        Command::RepairOutputIdentities { rest, txids, database_url, apply } =>
            run_async(run_repair_output_identities(rest, txids, database_url, apply)),
        Command::RepairGenesisStates {
            rest,
            txids,
            database_url,
            apply,
        } => run_async(run_repair_genesis_states(rest, txids, database_url, apply)),
        Command::ReplayDeferredDecode { rest,txid,database_url,apply } =>
            run_async(run_replay_deferred_decode(rest,txid,database_url,apply)),
        Command::RepairWrapperActions {
            rest,
            txids,
            database_url,
            indexed_evidence,
            apply,
        } => run_async(run_repair_wrapper_actions(
            rest,
            txids,
            database_url,
            indexed_evidence,
            apply,
        )),
        Command::Watch {
            rest,
            addresses,
            database_url,
            migrate,
            poll_secs,
            limit,
        } => run_async(run_watch(
            rest,
            addresses,
            database_url,
            migrate,
            poll_secs,
            limit,
        )),
        Command::WrpcWatch {
            rest,
            wrpc_url,
            network_id,
            database_url,
            migrate,
            fetch_concurrency,
            cache_capacity,
            cursor_key,
        } => run_async(run_wrpc_watch(
            rest,
            wrpc_url,
            network_id,
            database_url,
            migrate,
            fetch_concurrency,
            cache_capacity,
            cursor_key,
        )),
        Command::Scan {
            rest,
            database_url,
            migrate,
            from_blue_score,
            from_tip_window,
            cursor_key,
            batch_size,
            idle_secs,
            hydrate_concurrency,
            prevout_concurrency,
        } => run_async(run_scan(
            rest,
            database_url,
            migrate,
            from_blue_score,
            from_tip_window,
            cursor_key,
            batch_size,
            idle_secs,
            hydrate_concurrency,
            prevout_concurrency,
        )),
        Command::ReplayWindow {
            rest,
            database_url,
            blue_score,
            batch_size,
        } => run_async(run_replay_window(
            rest,
            database_url,
            blue_score,
            batch_size,
        )),
        Command::TipFollow {
            rest,
            next_rest,
            switch_blue_score,
            database_url,
            migrate,
            cursor_key,
            batch_size,
            overlap_windows,
            max_catchup_windows,
            poll_ms,
            settled_recheck_span_scores,
            settled_recheck_min_age_scores,
            adaptive_prefetch,
            window_fetch_concurrency,
            recent_acceptance_reconciliation,
            hydrate_concurrency,
            prevout_concurrency,
        } => run_async(run_tip_follow(
            rest,
            next_rest,
            switch_blue_score,
            database_url,
            migrate,
            cursor_key,
            batch_size,
            overlap_windows,
            max_catchup_windows,
            poll_ms,
            settled_recheck_span_scores,
            settled_recheck_min_age_scores,
            adaptive_prefetch,
            window_fetch_concurrency,
            recent_acceptance_reconciliation,
            hydrate_concurrency,
            prevout_concurrency,
        )),
        Command::SettledRecheck {
            rest,
            database_url,
            cursor_key,
            span_scores,
            min_age_scores,
            poll_ms,
            hydrate_concurrency,
            prevout_concurrency,
        } => run_async(run_settled_recheck(
            rest, database_url, cursor_key, span_scores, min_age_scores,
            poll_ms, hydrate_concurrency, prevout_concurrency,
        )),
        Command::ActiveOutputOrderBackfill { database_url, pause_ms } => run_async(async move {
            let pool = tn12_indexer_db::connect(&database_url).await?;
            loop {
                let mut tx = pool.begin().await?;
                sqlx::query("SET LOCAL statement_timeout='2s'").execute(&mut *tx).await?;
                let state: serde_json::Value = sqlx::query_scalar("SELECT active_output_order_backfill_step()")
                    .fetch_one(&mut *tx).await?;
                tx.commit().await?;
                tracing::info!(
                    phase = %state["phase"],
                    processed_rows = %state["processed_rows"],
                    "active output ordering backfill"
                );
                if state["phase"] == "ready" { break; }
                tokio::time::sleep(std::time::Duration::from_millis(pause_ms.max(10))).await;
            }
            Ok(())
        }),
        Command::Kcc20OwnerActionBackfill {
            database_url,
            batch_size,
            pause_ms,
            follow,
            idle_ms,
        } => run_async(run_kcc20_owner_action_backfill(
            database_url,
            batch_size,
            pause_ms,
            follow,
            idle_ms,
        )),
        Command::Kcc20Projector {
            database_url,
            migrate,
            idle_secs,
            activity_max_txids_per_pass,
            activity_statement_timeout,
            full_refresh_enabled,
            max_iterations,
        } => run_async(run_kcc20_projector(
            database_url,
            migrate,
            idle_secs,
            activity_max_txids_per_pass,
            activity_statement_timeout,
            full_refresh_enabled,
            max_iterations,
        )),
        Command::Reclassify {
            rest,
            database_url,
            limit,
            concurrency,
            retries,
            retry_delay_ms,
        } => run_async(run_reclassify(
            rest,
            database_url,
            limit,
            concurrency,
            retries,
            retry_delay_ms,
        )),
        Command::AutoDiscoverSpends {
            rest,
            database_url,
            limit,
            per_address_limit,
            concurrency,
            retries,
            retry_delay_ms,
        } => run_async(run_auto_discover_spends(
            rest,
            database_url,
            limit,
            per_address_limit,
            concurrency,
            retries,
            retry_delay_ms,
        )),
        Command::RepairPayloadClaims {
            rest,
            database_url,
            limit,
            concurrency,
            retries,
            retry_delay_ms,
        } => run_async(run_repair_payload_claims(
            rest,
            database_url,
            limit,
            concurrency,
            retries,
            retry_delay_ms,
        )),
        Command::RepairNativeCovenantIds {
            rest,
            database_url,
            limit,
            concurrency,
            retries,
            retry_delay_ms,
            apply,
        } => run_async(run_repair_native_covenant_ids(
            rest,
            database_url,
            limit,
            concurrency,
            retries,
            retry_delay_ms,
            apply,
        )),
        Command::RepairKcc20Holders {
            database_url,
            token_id,
            script_hashes,
            states,
            overwrite_states,
            last_change_ms,
            dry_run,
        } => run_async(run_repair_kcc20_holders(
            database_url,
            token_id,
            script_hashes,
            states,
            overwrite_states,
            last_change_ms,
            dry_run,
        )),
        Command::RevertBlocks {
            database_url,
            block_hashes,
        } => run_async(run_revert_blocks(database_url, block_hashes)),
        Command::ReconcileAcceptingBlock {
            rest,
            old_hash,
            new_hash,
            transaction_id,
            database_url,
            apply,
        } => run_async(run_reconcile_accepting_block(
            rest,
            old_hash,
            new_hash,
            transaction_id,
            database_url,
            apply,
        )),
        Command::ApiPaymentSettlementSweep {
            database_url,
            migrate,
            now_ms,
            min_unsettled_sompi,
            min_unsettled_sequences,
            max_voucher_age_ms,
            refund_safety_margin_ms,
            limit,
            dry_run,
            interval_secs,
            max_iterations,
        } => run_async(run_api_payment_settlement_sweep(
            database_url,
            migrate,
            now_ms,
            min_unsettled_sompi,
            min_unsettled_sequences,
            max_voucher_age_ms,
            refund_safety_margin_ms,
            limit,
            dry_run,
            interval_secs,
            max_iterations,
        )),
        Command::ApiPaymentOpeningReconcile {
            database_url,
            migrate,
            now_ms,
            max_opening_age_ms,
            limit,
            dry_run,
            interval_secs,
            max_iterations,
        } => run_async(run_api_payment_opening_reconcile(
            database_url,
            migrate,
            now_ms,
            max_opening_age_ms,
            limit,
            dry_run,
            interval_secs,
            max_iterations,
        )),
        Command::ApiPaymentSettlementBroadcast {
            database_url,
            migrate,
            now_ms,
            min_unsettled_sompi,
            min_unsettled_sequences,
            max_voucher_age_ms,
            refund_safety_margin_ms,
            limit,
            dry_run,
            provider_wallet_path,
            wrpc_url,
            network_id,
            node_bin,
            settle_script,
            interval_secs,
            max_iterations,
            fail_on_rejected,
        } => run_async(run_api_payment_settlement_broadcast(
            database_url,
            migrate,
            now_ms,
            min_unsettled_sompi,
            min_unsettled_sequences,
            max_voucher_age_ms,
            refund_safety_margin_ms,
            limit,
            dry_run,
            provider_wallet_path,
            wrpc_url,
            network_id,
            node_bin,
            settle_script,
            interval_secs,
            max_iterations,
            fail_on_rejected,
        )),
    }
}

async fn run_migrate(database_url: String, retire_action_prefix_indexes: bool) -> Result<()> {
    use tn12_indexer_db::{connect, migrate as db_migrate};

    let pool = connect(&database_url).await?;
    if retire_action_prefix_indexes {
        tn12_indexer_db::migrate_retiring_action_prefix_indexes(&pool).await
    } else {
        db_migrate(&pool).await
    }
}

async fn run_api_payment_settlement_sweep(
    database_url: String,
    migrate: bool,
    now_ms_override: Option<i64>,
    min_unsettled_sompi: i64,
    min_unsettled_sequences: i64,
    max_voucher_age_ms: i64,
    refund_safety_margin_ms: i64,
    limit: i64,
    dry_run: bool,
    interval_secs: Option<u64>,
    max_iterations: Option<u64>,
) -> Result<()> {
    use tn12_indexer_db::{api_payments, connect, migrate as db_migrate};

    if matches!(interval_secs, Some(0)) {
        bail!("--interval-secs must be greater than zero");
    }
    if max_iterations.is_some() && interval_secs.is_none() {
        bail!("--max-iterations requires --interval-secs");
    }

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }

    let mut iteration = 0u64;
    loop {
        iteration += 1;
        let now_ms = match now_ms_override {
            Some(value) => value,
            None => now_ms()?.try_into()?,
        };
        let policy = api_payments::ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi,
            min_unsettled_sequences,
            max_voucher_age_ms,
            refund_safety_margin_ms,
            limit,
        };
        let mut report = run_api_payment_settlement_sweep_once(&pool, policy, dry_run).await?;
        if interval_secs.is_some() {
            report["worker"] = json!(true);
            report["iteration"] = json!(iteration);
            report["maxIterations"] = json!(max_iterations);
        }
        let candidate_count = json_i64_field(&report, "candidateCount");
        let claimed_count = json_i64_field(&report, "claimedCount");
        let disabled_count = json_i64_field(&report, "disabledCount");
        tracing::info!(
            target: "api_payment_settlement",
            worker = interval_secs.is_some(),
            iteration,
            dry_run,
            now_ms = %report.get("nowMs").and_then(|value| value.as_str()).unwrap_or(""),
            candidate_count = ?candidate_count,
            claimed_count = ?claimed_count,
            disabled_count = ?disabled_count,
            "API payment settlement sweep completed"
        );
        if disabled_count.is_some_and(|count| count > 0) {
            tracing::warn!(
                target: "api_payment_settlement",
                iteration,
                disabled_count,
                "API payment settlement sweep disabled channels"
            );
        }
        print_json(&report)?;

        let Some(interval_secs) = interval_secs else {
            return Ok(());
        };
        if max_iterations.is_some_and(|max| iteration >= max) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

async fn run_api_payment_opening_reconcile(
    database_url: String,
    migrate: bool,
    now_ms_override: Option<i64>,
    max_opening_age_ms: i64,
    limit: i64,
    dry_run: bool,
    interval_secs: Option<u64>,
    max_iterations: Option<u64>,
) -> Result<()> {
    use tn12_indexer_db::{api_payments, connect, migrate as db_migrate};

    if matches!(interval_secs, Some(0)) {
        bail!("--interval-secs must be greater than zero");
    }
    if max_iterations.is_some() && interval_secs.is_none() {
        bail!("--max-iterations requires --interval-secs");
    }
    if max_opening_age_ms <= 0 {
        bail!("--max-opening-age-ms must be greater than zero");
    }

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }

    let mut iteration = 0u64;
    loop {
        iteration += 1;
        let now_ms = match now_ms_override {
            Some(value) => value,
            None => now_ms()?.try_into()?,
        };
        let policy = api_payments::ApiPaymentOpeningReconciliationPolicy {
            now_ms,
            max_opening_age_ms,
            limit,
        };
        let mut report = run_api_payment_opening_reconcile_once(&pool, policy, dry_run).await?;
        if interval_secs.is_some() {
            report["worker"] = json!(true);
            report["iteration"] = json!(iteration);
            report["maxIterations"] = json!(max_iterations);
        }
        let candidate_count = json_i64_field(&report, "candidateCount");
        let disabled_count = json_i64_field(&report, "disabledCount");
        tracing::info!(
            target: "api_payments",
            worker = interval_secs.is_some(),
            iteration,
            dry_run,
            now_ms = %report.get("nowMs").and_then(|value| value.as_str()).unwrap_or(""),
            candidate_count = ?candidate_count,
            disabled_count = ?disabled_count,
            "API payment opening reconciliation completed"
        );
        print_json(&report)?;

        let Some(interval_secs) = interval_secs else {
            return Ok(());
        };
        if max_iterations.is_some_and(|max| iteration >= max) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_api_payment_settlement_broadcast(
    database_url: String,
    migrate: bool,
    now_ms_override: Option<i64>,
    min_unsettled_sompi: i64,
    min_unsettled_sequences: i64,
    max_voucher_age_ms: i64,
    refund_safety_margin_ms: i64,
    limit: i64,
    dry_run: bool,
    provider_wallet_path: Option<PathBuf>,
    wrpc_url: String,
    network_id: String,
    node_bin: PathBuf,
    settle_script: PathBuf,
    interval_secs: Option<u64>,
    max_iterations: Option<u64>,
    fail_on_rejected: bool,
) -> Result<()> {
    use tn12_indexer_db::{api_payments, connect, migrate as db_migrate};

    if matches!(interval_secs, Some(0)) {
        bail!("--interval-secs must be greater than zero");
    }
    if max_iterations.is_some() && interval_secs.is_none() {
        bail!("--max-iterations requires --interval-secs");
    }
    if !dry_run && provider_wallet_path.is_none() {
        bail!("--provider-wallet-path or API_PAYMENT_PROVIDER_WALLET_PATH is required without --dry-run");
    }

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }

    let mut iteration = 0u64;
    loop {
        iteration += 1;
        let now_ms = match now_ms_override {
            Some(value) => value,
            None => now_ms()?.try_into()?,
        };
        let policy = api_payments::ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi,
            min_unsettled_sequences,
            max_voucher_age_ms,
            refund_safety_margin_ms,
            limit,
        };
        let mut report = run_api_payment_settlement_broadcast_once(
            &pool,
            policy,
            dry_run,
            provider_wallet_path.as_deref(),
            &wrpc_url,
            &network_id,
            &node_bin,
            &settle_script,
        )
        .await?;
        if interval_secs.is_some() {
            report["worker"] = json!(true);
            report["iteration"] = json!(iteration);
            report["maxIterations"] = json!(max_iterations);
        }
        let submitted_count = json_i64_field(&report, "submittedCount");
        let rejected_count = json_i64_field(&report, "rejectedCount");
        tracing::info!(
            target: "api_payment_settlement",
            worker = interval_secs.is_some(),
            iteration,
            dry_run,
            submitted_count = ?submitted_count,
            rejected_count = ?rejected_count,
            "API payment settlement broadcaster completed"
        );
        if rejected_count.is_some_and(|count| count > 0) {
            tracing::warn!(
                target: "api_payment_settlement",
                iteration,
                rejected_count,
                "API payment settlement broadcaster rejected failed submissions"
            );
        }
        print_json(&report)?;
        if fail_on_rejected && rejected_count.is_some_and(|count| count > 0) {
            bail!(
                "API payment settlement broadcaster rejected {} submitted settlement(s)",
                rejected_count.unwrap_or_default()
            );
        }

        let Some(interval_secs) = interval_secs else {
            return Ok(());
        };
        if max_iterations.is_some_and(|max| iteration >= max) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_api_payment_settlement_broadcast_once(
    pool: &tn12_indexer_db::PgPool,
    policy: tn12_indexer_db::api_payments::ApiPaymentSettlementCandidatePolicy,
    dry_run: bool,
    provider_wallet_path: Option<&Path>,
    wrpc_url: &str,
    network_id: &str,
    node_bin: &Path,
    settle_script: &Path,
) -> Result<Value> {
    use tn12_indexer_db::api_payments;

    let now_ms = policy.now_ms;
    if dry_run {
        let candidates = api_payments::api_payment_settlement_candidates(pool, policy).await?;
        return Ok(json!({
            "dryRun": true,
            "nowMs": now_ms.to_string(),
            "candidateCount": candidates.len(),
            "candidates": candidates.iter().map(|row| json!({
                "channelId": row.channel_id,
                "networkId": row.network_id,
                "reason": row.reason,
                "spentSompi": row.spent_sompi.to_string(),
                "latestSequence": row.latest_sequence.to_string(),
                "refundAfterMs": row.refund_after_ms.map(|value| value.to_string()),
                "latestAuthorizationSequence": row.latest_authorization_sequence.map(|value| value.to_string()),
                "latestAuthorizationStatus": row.latest_authorization_status,
                "latestAuthorizationExpiresAtMs": row.latest_authorization_expires_at_ms.map(|value| value.to_string()),
                "latestAuthorizationSettlementTxid": row.latest_authorization_settlement_txid,
            })).collect::<Vec<_>>()
        }));
    }

    let provider_wallet_path = provider_wallet_path
        .context("--provider-wallet-path or API_PAYMENT_PROVIDER_WALLET_PATH is required")?;
    let claimed =
        api_payments::claim_api_payment_settlement_authorizations(pool, policy.clone()).await?;
    let disabled =
        api_payments::disable_api_payment_channels_missing_settlement_authorization(pool, policy)
            .await?;
    let mut broadcasts = Vec::new();
    let mut submitted_count = 0usize;
    let mut rejected_count = 0usize;

    for row in claimed.iter() {
        let Some(artifact_json) = row.settlement_artifact_json.as_ref() else {
            rejected_count += 1;
            let rejection = api_payments::reject_api_payment_submitted_settlement(
                pool,
                &row.settlement_txid,
                now_ms,
            )
            .await?;
            broadcasts.push(json!({
                "channelId": row.channel_id,
                "settlementTxid": row.settlement_txid,
                "status": "rejected",
                "failure": "missing_settlement_artifact_json",
                "rejection": rejection.map(|row| json!({
                    "channelStatus": row.channel_status,
                    "authorizationStatus": row.authorization_status,
                    "rejectedAtMs": row.rejected_at_ms.to_string(),
                })),
            }));
            continue;
        };

        let artifact_path = write_settlement_artifact_temp(&row.channel_id, now_ms, artifact_json)?;
        let output = ProcessCommand::new(node_bin)
            .arg(settle_script)
            .arg("--settlement-artifact")
            .arg(&artifact_path)
            .arg("--provider-wallet-path")
            .arg(provider_wallet_path)
            .arg("--wrpc-url")
            .arg(wrpc_url)
            .arg("--network")
            .arg(network_id)
            .arg("--submit")
            .output()
            .with_context(|| {
                format!(
                    "run settlement submitter {}",
                    settle_script.to_string_lossy()
                )
            })?;

        if output.status.success() {
            submitted_count += 1;
            broadcasts.push(json!({
                "channelId": row.channel_id,
                "settlementTxid": row.settlement_txid,
                "status": "submitted",
                "artifactPath": artifact_path.display().to_string(),
                "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            }));
            continue;
        }

        rejected_count += 1;
        let rejection = api_payments::reject_api_payment_submitted_settlement(
            pool,
            &row.settlement_txid,
            now_ms,
        )
        .await?;
        broadcasts.push(json!({
            "channelId": row.channel_id,
            "settlementTxid": row.settlement_txid,
            "status": "rejected",
            "artifactPath": artifact_path.display().to_string(),
            "exitStatus": output.status.code(),
            "stdout": String::from_utf8_lossy(&output.stdout).trim(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim(),
            "rejection": rejection.map(|row| json!({
                "channelStatus": row.channel_status,
                "authorizationStatus": row.authorization_status,
                "rejectedAtMs": row.rejected_at_ms.to_string(),
            })),
        }));
    }

    Ok(json!({
        "dryRun": false,
        "nowMs": now_ms.to_string(),
        "claimedCount": claimed.len(),
        "disabledCount": disabled.len(),
        "submittedCount": submitted_count,
        "rejectedCount": rejected_count,
        "broadcasts": broadcasts,
        "disabled": disabled.iter().map(|row| json!({
            "channelId": row.channel_id,
            "networkId": row.network_id,
            "reason": row.reason,
            "spentSompi": row.spent_sompi.to_string(),
            "latestSequence": row.latest_sequence.to_string(),
            "disabledAtMs": row.disabled_at_ms.to_string(),
            "latestAuthorizationSequence": row.latest_authorization_sequence.map(|value| value.to_string()),
            "latestAuthorizationStatus": row.latest_authorization_status,
            "latestAuthorizationExpiresAtMs": row.latest_authorization_expires_at_ms.map(|value| value.to_string()),
        })).collect::<Vec<_>>()
    }))
}

fn write_settlement_artifact_temp(
    channel_id: &str,
    now_ms: i64,
    artifact_json: &Value,
) -> Result<PathBuf> {
    let safe_channel_id = channel_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect::<String>();
    let path = std::env::temp_dir().join(format!(
        "api-payment-settlement-{safe_channel_id}-{}-{now_ms}.json",
        std::process::id()
    ));
    fs::write(&path, serde_json::to_vec_pretty(artifact_json)?)
        .with_context(|| format!("write settlement artifact {}", path.display()))?;
    Ok(path)
}

async fn run_api_payment_opening_reconcile_once(
    pool: &tn12_indexer_db::PgPool,
    policy: tn12_indexer_db::api_payments::ApiPaymentOpeningReconciliationPolicy,
    dry_run: bool,
) -> Result<Value> {
    use tn12_indexer_db::api_payments;

    let now_ms = policy.now_ms;
    let rows = if dry_run {
        api_payments::api_payment_stale_opening_channels(pool, policy).await?
    } else {
        api_payments::disable_api_payment_stale_opening_channels(pool, policy).await?
    };

    Ok(json!({
        "dryRun": dry_run,
        "nowMs": now_ms.to_string(),
        "candidateCount": if dry_run { rows.len() } else { 0 },
        "disabledCount": if dry_run { 0 } else { rows.len() },
        "channels": rows.iter().map(|row| json!({
            "channelId": row.channel_id,
            "networkId": row.network_id,
            "reason": row.reason,
            "spentSompi": row.spent_sompi.to_string(),
            "latestSequence": row.latest_sequence.to_string(),
            "disabledAtMs": row.disabled_at_ms.to_string(),
        })).collect::<Vec<_>>()
    }))
}

async fn run_api_payment_settlement_sweep_once(
    pool: &tn12_indexer_db::PgPool,
    policy: tn12_indexer_db::api_payments::ApiPaymentSettlementCandidatePolicy,
    dry_run: bool,
) -> Result<Value> {
    use tn12_indexer_db::api_payments;

    let now_ms = policy.now_ms;
    if dry_run {
        let candidates = api_payments::api_payment_settlement_candidates(pool, policy).await?;
        return Ok(json!({
            "dryRun": true,
            "nowMs": now_ms.to_string(),
            "candidateCount": candidates.len(),
            "candidates": candidates.iter().map(|row| json!({
                "channelId": row.channel_id,
                "networkId": row.network_id,
                "reason": row.reason,
                "spentSompi": row.spent_sompi.to_string(),
                "latestSequence": row.latest_sequence.to_string(),
                "refundAfterMs": row.refund_after_ms.map(|value| value.to_string()),
                "latestAuthorizationSequence": row.latest_authorization_sequence.map(|value| value.to_string()),
                "latestAuthorizationStatus": row.latest_authorization_status,
                "latestAuthorizationExpiresAtMs": row.latest_authorization_expires_at_ms.map(|value| value.to_string()),
                "latestAuthorizationSettlementTxid": row.latest_authorization_settlement_txid,
            })).collect::<Vec<_>>()
        }));
    }

    let claimed =
        api_payments::claim_api_payment_settlement_authorizations(pool, policy.clone()).await?;
    let disabled =
        api_payments::disable_api_payment_channels_missing_settlement_authorization(pool, policy)
            .await?;

    Ok(json!({
        "dryRun": false,
        "nowMs": now_ms.to_string(),
        "claimedCount": claimed.len(),
        "disabledCount": disabled.len(),
        "claimed": claimed.iter().map(|row| json!({
            "channelId": row.channel_id,
            "networkId": row.network_id,
            "reason": row.reason,
            "sequence": row.sequence.to_string(),
            "totalSpentSompi": row.total_spent_sompi.to_string(),
            "providerAmountSompi": row.provider_amount_sompi.to_string(),
            "payerRefundSompi": row.payer_refund_sompi.to_string(),
            "settlementFeeSompi": row.settlement_fee_sompi.to_string(),
            "settlementTxid": row.settlement_txid,
            "settlementTemplateHash": row.settlement_template_hash,
            "metadataHash": row.metadata_hash,
            "settlementArtifactSchema": row.settlement_artifact_schema,
            "hasUnsignedSettlementTemplate": row.unsigned_settlement_template.is_some(),
            "hasSettlementArtifactJson": row.settlement_artifact_json.is_some(),
            "refundAfterMs": row.refund_after_ms.to_string(),
            "expiresAtMs": row.expires_at_ms.to_string(),
            "claimedAtMs": row.claimed_at_ms.to_string(),
        })).collect::<Vec<_>>(),
        "disabled": disabled.iter().map(|row| json!({
            "channelId": row.channel_id,
            "networkId": row.network_id,
            "reason": row.reason,
            "spentSompi": row.spent_sompi.to_string(),
            "latestSequence": row.latest_sequence.to_string(),
            "disabledAtMs": row.disabled_at_ms.to_string(),
            "latestAuthorizationSequence": row.latest_authorization_sequence.map(|value| value.to_string()),
            "latestAuthorizationStatus": row.latest_authorization_status,
            "latestAuthorizationExpiresAtMs": row.latest_authorization_expires_at_ms.map(|value| value.to_string()),
        })).collect::<Vec<_>>()
    }))
}

fn json_i64_field(value: &Value, field: &str) -> Option<i64> {
    let number = value.get(field)?;
    number
        .as_i64()
        .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
}

async fn run_repair_kcc20_holders(
    database_url: String,
    token_id: String,
    script_hashes: Vec<String>,
    states: Vec<String>,
    overwrite_states: bool,
    last_change_ms: Option<i64>,
    dry_run: bool,
) -> Result<()> {
    use tn12_indexer_db::{connect, repo};

    let pool = connect(&database_url).await?;
    let token_id_bytes = parse_32_byte_hex(&token_id, "token-id")?;
    let script_hash_bytes = script_hashes
        .iter()
        .map(|value| parse_32_byte_hex(value, "script-hash"))
        .collect::<Result<Vec<_>>>()?;
    let state_specs = states
        .iter()
        .map(|value| parse_kcc20_repair_state(value))
        .collect::<Result<Vec<_>>>()?;
    let last_change_ms = match last_change_ms {
        Some(value) => value,
        None => now_ms()?.try_into()?,
    };

    let result = repo::repair_kcc20_holders(
        &pool,
        &token_id_bytes,
        &script_hash_bytes,
        &state_specs,
        last_change_ms,
        overwrite_states,
        dry_run,
    )
    .await?;

    print_json(&result)
}

async fn run_revert_blocks(database_url: String, block_hashes: Vec<String>) -> Result<()> {
    use std::sync::Arc;
    use tn12_indexer_crawl::{PgCursorStore, ReorgHandler};
    use tn12_indexer_db::{connect, PgPersister};

    let pool = connect(&database_url).await?;
    let persister = Arc::new(PgPersister::new(pool.clone()));
    let cursor = Box::new(PgCursorStore::new(pool));
    let handler = ReorgHandler::new(persister, cursor);
    let stats = handler.handle_removed_block_hashes(&block_hashes).await?;

    print_json(&json!({
        "requestedBlocks": stats.requested_blocks,
        "unknownBlocks": stats.unknown_blocks,
        "minRevertedBlueScore": stats.min_reverted_blue_score,
        "blocksRemoved": stats.blocks_removed,
        "covenantsRemoved": stats.covenants_removed,
        "utxosCreatedRemoved": stats.utxos_created_removed,
        "utxosReactivated": stats.utxos_reactivated,
        "actionsRemoved": stats.actions_removed,
        "covenantsUnclassified": stats.covenants_unclassified,
    }))
}

async fn run_reconcile_accepting_block(
    rest: String,
    old_hash: String,
    new_hash: String,
    transaction_id: String,
    database_url: Option<String>,
    apply: bool,
) -> Result<()> {
    use tn12_indexer_db::persist::AcceptanceConflict;
    use tn12_indexer_db::{connect, PgPersister};
    let pool = match database_url {
        Some(url) => Some(connect(&url).await?),
        None => None,
    };
    let client = tn12_indexer_crawl::RestClient::new(rest)?;
    let conflict = AcceptanceConflict {
        transaction_id,
        persisted_hash: old_hash,
        incoming_hash: new_hash,
    };
    let proof = match client.verify_canonical_block_replacement(&conflict).await {
        Ok(proof) => proof,
        Err(error)
            if error
                .downcast_ref::<tn12_indexer_db::persist::NonEquivalentBlockEvidence>()
                .is_some() =>
        {
            let pool =
                pool.context("a split acceptance proof requires the complete database cohort")?;
            let writer = PgPersister::new(pool).with_bounded_writer_lock_wait();
            let cohort = writer
                .historical_acceptance_cohort(&[hex::decode(&conflict.persisted_hash)?])
                .await?;
            let proof = client
                .verify_historical_acceptance_map(cohort, &conflict)
                .await?;
            let stats = if apply {
                tn12_indexer_crawl::rest_replay_fence::for_acceptance_map(&writer,&client,&proof).await?
                    .reconcile_historical_acceptance_map(&proof).await?
            } else {
                writer.preview_historical_acceptance_map(&proof).await?
            };
            let target_blocks: std::collections::BTreeSet<_> = proof
                .source()
                .targets()
                .iter()
                .map(|t| hex::encode(&t.target_hash))
                .collect();
            return print_json(
                &json!({"kind":"historical_acceptance_map","sourceVerified":true,"databaseChecked":true,"applied":apply,
                "proofHash":hex::encode(proof.proof_hash()),"oldHash":conflict.persisted_hash,"targetBlocks":target_blocks,
                "transactions":proof.source().targets().len(),"references":stats}),
            );
        }
        Err(error) => return Err(error),
    };
    let stats = match pool {
        Some(pool) => {
            let writer = PgPersister::new(pool).with_bounded_writer_lock_wait();
            Some(if apply {
                tn12_indexer_crawl::rest_replay_fence::for_replacement(&writer,&client,&proof).await?
                    .reconcile_accepting_block(&proof).await?
            } else {
                writer
                    .preview_accepting_block_reconciliation(&proof)
                    .await?
            })
        }
        None => {
            anyhow::ensure!(!apply, "database URL is required for apply");
            None
        }
    };
    print_json(
        &json!({"sourceVerified":true,"databaseChecked":stats.is_some(),"applied":apply,
        "oldHash":conflict.persisted_hash,"newHash":conflict.incoming_hash,"references":stats}),
    )
}

async fn run_reclassify(
    rest: String,
    database_url: String,
    limit: u32,
    concurrency: usize,
    retries: u32,
    retry_delay_ms: u64,
) -> Result<()> {
    use std::sync::Arc;
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, repo, PgPersister};
    use tokio::task::JoinSet;

    let pool = connect(&database_url).await?;
    let persister = Arc::new(PgPersister::new(pool.clone()));
    let client = RestClient::new(rest)?;
    let concurrency = concurrency.max(1);
    let retry_delay = Duration::from_millis(retry_delay_ms);

    let unclassified = repo::unclassified_covenants_with_spends(&pool, limit).await?;
    tracing::info!(
        target: "reclassify",
        "candidates: {}, concurrency={}, retries={}, retry_delay_ms={}",
        unclassified.len(),
        concurrency,
        retries,
        retry_delay_ms
    );

    let mut classified = 0u64;
    let mut unmatched = 0u64;
    let mut fetch_failed = 0u64;
    let mut processed = 0usize;
    let mut fetch_error_samples = 0u8;
    let mut no_input_samples = 0u8;

    for chunk in unclassified.chunks(concurrency) {
        let mut tasks = JoinSet::new();
        for row in chunk.iter().cloned() {
            let client = client.clone();
            tasks.spawn(async move {
                let tx = fetch_rest_transaction(
                    client,
                    row.spend_txid_hex.clone(),
                    retries,
                    retry_delay,
                )
                .await?;
                Ok::<_, anyhow::Error>((row, tx))
            });
        }

        while let Some(joined) = tasks.join_next().await {
            processed += 1;
            let (row, tx) = match joined {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    fetch_failed += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(target: "reclassify", "fetch failed: {e:#}");
                    } else {
                        tracing::debug!(target: "reclassify", "fetch failed: {e:#}");
                    }
                    continue;
                }
                Err(e) => {
                    fetch_failed += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(target: "reclassify", "fetch task failed: {e:#}");
                    } else {
                        tracing::debug!(target: "reclassify", "fetch task failed: {e:#}");
                    }
                    continue;
                }
            };

            // The spend input that consumed THIS covenant UTXO. Multi-input
            // transactions can include wallet funding, KCC20 state, and sale
            // escrow inputs, so use the outpoint captured when the action was
            // first persisted.
            let target_id_hex = hex::encode(&row.covenant_id);
            let candidate_input = match (
                row.spent_outpoint_hash.as_deref(),
                row.spent_outpoint_index.as_deref(),
            ) {
                (Some(hash), Some(index)) => tx.inputs.iter().find(|i| {
                    i.previous_outpoint_hash.eq_ignore_ascii_case(hash)
                        && i.previous_outpoint_index == index
                }),
                _ => None,
            }
            .or_else(|| tx.inputs.iter().find(|i| !i.signature_script.is_empty()))
            .or_else(|| tx.inputs.first());
            let Some(input) = candidate_input else {
                if no_input_samples < 5 {
                    no_input_samples += 1;
                    tracing::warn!(target: "reclassify", "{} has no inputs", row.spend_txid_hex);
                } else {
                    tracing::debug!(target: "reclassify", "{} has no inputs", row.spend_txid_hex);
                }
                unmatched += 1;
                continue;
            };
            tracing::debug!(
                target: "reclassify",
                "{} selected input {}:{} sig_hex_len={}",
                &target_id_hex[..16],
                input.previous_outpoint_hash,
                input.previous_outpoint_index,
                input.signature_script.len()
            );

            match persister
                .reclassify_covenant(
                    row.action_id,
                    &row.covenant_id,
                    &row.spend_txid,
                    &input.signature_script,
                )
                .await?
            {
                Some(name) => {
                    classified += 1;
                    tracing::info!(target: "reclassify", "{} -> {}", &target_id_hex[..16], name);
                }
                None => unmatched += 1,
            }
        }

        tracing::info!(
            target: "reclassify",
            "progress {}/{}: classified={} unmatched={} fetch_failed={}",
            processed,
            unclassified.len(),
            classified,
            unmatched,
            fetch_failed
        );
    }
    tracing::info!(target: "reclassify",
        "done: candidates={} classified={} unmatched={} fetch_failed={}",
        unclassified.len(), classified, unmatched, fetch_failed
    );
    Ok(())
}

async fn fetch_rest_transaction(
    client: tn12_indexer_crawl::RestClient,
    txid: String,
    retries: u32,
    retry_delay: Duration,
) -> Result<tn12_indexer_core::RestTransaction> {
    let mut failed_attempts = 0;
    loop {
        match client.get_transaction(&txid).await {
            Ok(tx) => return Ok(tx),
            Err(e) if failed_attempts < retries => {
                failed_attempts += 1;
                tracing::debug!(
                    target: "rest-fetch",
                    "fetch {txid} failed attempt {}/{}: {e:#}",
                    failed_attempts,
                    retries + 1
                );
                tokio::time::sleep(retry_delay.saturating_mul(failed_attempts)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("fetch {txid} after {} attempts", failed_attempts + 1)
                });
            }
        }
    }
}

async fn run_auto_discover_spends(
    rest: String,
    database_url: String,
    limit: u32,
    per_address_limit: u32,
    concurrency: usize,
    retries: u32,
    retry_delay_ms: u64,
) -> Result<()> {
    use anyhow::Context;
    use std::sync::Arc;
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, repo, Persister, PgPersister};
    use tokio::task::JoinSet;

    let pool = connect(&database_url).await?;
    let persister = Arc::new(PgPersister::new(pool.clone()));
    let client = RestClient::new(rest)?;
    let concurrency = concurrency.max(1);
    let retry_delay = Duration::from_millis(retry_delay_ms);

    // Pull unclassified covenants newest first. Newest matters because the
    // pre-PR-#24 scanner had been running for ~25h before the fix landed, so
    // the spends it missed are the recent ones; older covenants tend to be
    // long-spent and reclassify-able.
    let row_limit: i64 = if limit == 0 { 1_000_000 } else { limit as i64 };
    let rows = repo::unclassified_covenant_addresses(&pool, row_limit).await?;

    let total = rows.len();
    tracing::info!(
        target: "auto-discover",
        "candidates: {total}, concurrency={concurrency}, retries={retries}, retry_delay_ms={retry_delay_ms}"
    );

    let mut walked = 0u64;
    let mut classified = 0u64;
    let mut fetch_errors = 0u64;
    let mut persist_errors = 0u64;
    let mut processed = 0usize;
    let mut fetch_error_samples = 0u8;
    let mut persist_error_samples = 0u8;

    for chunk in rows.chunks(concurrency) {
        let mut tasks = JoinSet::new();
        for (covenant_id, address) in chunk.iter().cloned() {
            let client = client.clone();
            let retry_delay = retry_delay;
            tasks.spawn(async move {
                let txs = fetch_address_full_transactions(
                    client,
                    address.clone(),
                    per_address_limit,
                    retries,
                    retry_delay,
                )
                .await?;
                Ok::<_, anyhow::Error>((covenant_id, address, txs))
            });
        }

        while let Some(joined) = tasks.join_next().await {
            processed += 1;
            let (covenant_id, address, txs) = match joined {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    fetch_errors += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(target: "auto-discover", "{e:#}");
                    } else {
                        tracing::debug!(target: "auto-discover", "{e:#}");
                    }
                    continue;
                }
                Err(e) => {
                    fetch_errors += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(target: "auto-discover", "fetch task failed: {e:#}");
                    } else {
                        tracing::debug!(target: "auto-discover", "fetch task failed: {e:#}");
                    }
                    continue;
                }
            };

            if !txs.is_empty() {
                walked += 1;
                for tx in &txs {
                    let result=async {
                        tn12_indexer_crawl::rest_replay_fence::for_transactions(&persister,&client,std::slice::from_ref(tx)).await?
                            .persist_tx(tx).await
                    }.await;
                    if let Err(e) = result {
                        persist_errors += 1;
                        if persist_error_samples < 5 {
                            persist_error_samples += 1;
                            tracing::warn!(target: "auto-discover",
                                "persist {} (covenant {}) failed: {e:#}",
                                tx.transaction_id, &hex::encode(&covenant_id)[..16]
                            );
                        } else {
                            tracing::debug!(target: "auto-discover",
                                "persist {} (covenant {}) failed: {e:#}",
                                tx.transaction_id, &hex::encode(&covenant_id)[..16]
                            );
                        }
                    }
                }
            }

            // Re-check classification — covenant row may now have a template.
            if repo::template_name_for(&pool, &covenant_id)
                .await
                .with_context(|| format!("checking template for {address}"))?
                .is_some()
            {
                classified += 1;
            }
        }

        tracing::info!(target: "auto-discover",
            "progress {}/{}: walked={walked} classified={classified} fetch_err={fetch_errors} persist_err={persist_errors}",
            processed, total
        );
    }

    tracing::info!(target: "auto-discover",
        "done: total={total} walked={walked} classified={classified} fetch_err={fetch_errors} persist_err={persist_errors}",
    );
    Ok(())
}

async fn fetch_address_full_transactions(
    client: tn12_indexer_crawl::RestClient,
    address: String,
    limit: u32,
    retries: u32,
    retry_delay: Duration,
) -> Result<Vec<tn12_indexer_core::RestTransaction>> {
    let mut failed_attempts = 0;
    loop {
        match client
            .get_address_full_transactions(&address, limit, 0)
            .await
        {
            Ok(txs) => return Ok(txs),
            Err(e) if failed_attempts < retries => {
                failed_attempts += 1;
                tracing::debug!(
                    target: "auto-discover",
                    "fetch {address} failed attempt {}/{}: {e:#}",
                    failed_attempts,
                    retries + 1
                );
                tokio::time::sleep(retry_delay.saturating_mul(failed_attempts)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("fetch {address} after {} attempts", failed_attempts + 1)
                });
            }
        }
    }
}

async fn run_repair_payload_claims(
    rest: String,
    database_url: String,
    limit: u32,
    concurrency: usize,
    retries: u32,
    retry_delay_ms: u64,
) -> Result<()> {
    use tn12_indexer_core::compute_genesis_covenant_id_for_output;
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{claim, connect, repo};
    use tokio::task::JoinSet;

    let pool = connect(&database_url).await?;
    let client = RestClient::new(rest)?;
    let concurrency = concurrency.max(1);
    let retry_delay = Duration::from_millis(retry_delay_ms);
    let row_limit: i64 = if limit == 0 { 1_000_000 } else { limit as i64 };
    let rows = repo::covenants_payload_claim_repair_candidates(&pool, row_limit).await?;
    let total = rows.len();
    tracing::info!(
        target: "repair-payload-claims",
        "candidates: {total}, concurrency={concurrency}, retries={retries}, retry_delay_ms={retry_delay_ms}"
    );

    let mut repaired = 0u64;
    let mut no_claim = 0u64;
    let mut fetch_errors = 0u64;
    let mut update_skipped = 0u64;
    let mut rekeyed = 0u64;
    let mut processed = 0usize;
    let mut fetch_error_samples = 0u8;

    for chunk in rows.chunks(concurrency) {
        let mut tasks = JoinSet::new();
        for row in chunk.iter().cloned() {
            let client = client.clone();
            tasks.spawn(async move {
                let tx = fetch_payload_claim_transaction(
                    client,
                    row.genesis_txid_hex.clone(),
                    retries,
                    retry_delay,
                )
                .await?;
                Ok::<_, anyhow::Error>((row, tx))
            });
        }

        while let Some(joined) = tasks.join_next().await {
            processed += 1;
            let (row, tx) = match joined {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    fetch_errors += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(target: "repair-payload-claims", "{e:#}");
                    } else {
                        tracing::debug!(target: "repair-payload-claims", "{e:#}");
                    }
                    continue;
                }
                Err(e) => {
                    fetch_errors += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(
                            target: "repair-payload-claims",
                            "fetch task failed: {e:#}"
                        );
                    } else {
                        tracing::debug!(
                            target: "repair-payload-claims",
                            "fetch task failed: {e:#}"
                        );
                    }
                    continue;
                }
            };

            let claim = tx
                .payload
                .as_deref()
                .and_then(claim::parse_payload_envelope);
            let Some(claim) = claim else {
                no_claim += 1;
                continue;
            };

            let target_covenant_id = compute_genesis_covenant_id_for_output(
                &tx,
                row.genesis_vout.try_into().unwrap_or_default(),
            )
            .and_then(|id| hex::decode(id).ok())
            .filter(|bytes| bytes.len() == 32)
            .unwrap_or_else(|| row.covenant_id.clone());
            if repo::rekey_covenant_id(&pool, &row.covenant_id, &target_covenant_id).await? {
                rekeyed += 1;
            }

            let changed =
                repo::store_payload_claim_for_covenant(&pool, &target_covenant_id, &claim).await?;
            if changed > 0 {
                repaired += changed;
                tracing::info!(
                    target: "repair-payload-claims",
                    "{} -> {} from {}",
                    row.covenant_id_hex,
                    claim.tmpl,
                    row.genesis_txid_hex
                );
            } else {
                update_skipped += 1;
            }
        }

        tracing::info!(
            target: "repair-payload-claims",
            "progress {}/{}: repaired={} rekeyed={} no_claim={} fetch_err={} skipped={}",
            processed,
            total,
            repaired,
            rekeyed,
            no_claim,
            fetch_errors,
            update_skipped
        );
    }

    if total == 0 {
        tracing::info!(
            target: "repair-payload-claims",
            "progress {}/{}: repaired={} rekeyed={} no_claim={} fetch_err={} skipped={}",
            processed,
            total,
            repaired,
            rekeyed,
            no_claim,
            fetch_errors,
            update_skipped
        );
    }

    print_json(&serde_json::json!({
        "candidates": total,
        "concurrency": concurrency,
        "retries": retries,
        "retryDelayMs": retry_delay_ms,
        "repaired": repaired,
        "noClaim": no_claim,
        "fetchErrors": fetch_errors,
        "updateSkipped": update_skipped,
        "rekeyed": rekeyed,
    }))
}

async fn run_repair_native_covenant_ids(
    rest: String,
    database_url: String,
    limit: u32,
    concurrency: usize,
    retries: u32,
    retry_delay_ms: u64,
    apply: bool,
) -> Result<()> {
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, repo};
    use tokio::task::JoinSet;

    let pool = connect(&database_url).await?;
    let client = RestClient::new(rest)?;
    let concurrency = concurrency.max(1);
    let retry_delay = Duration::from_millis(retry_delay_ms);
    let row_limit: i64 = if limit == 0 { 1_000_000 } else { limit as i64 };
    let rows = repo::covenant_id_repair_candidates(&pool, row_limit).await?;
    let total = rows.len();
    tracing::info!(
        target: "repair-native-covenant-ids",
        "candidates: {total}, concurrency={concurrency}, retries={retries}, retry_delay_ms={retry_delay_ms}, apply={apply}"
    );

    let mut would_rekey = 0u64;
    let mut rekeyed = 0u64;
    let mut same_id = 0u64;
    let mut no_native_id = 0u64;
    let mut fetch_errors = 0u64;
    let mut misclassified_deploys_deleted = 0u64;
    let mut processed = 0usize;
    let mut fetch_error_samples = 0u8;

    for chunk in rows.chunks(concurrency) {
        let mut tasks = JoinSet::new();
        for row in chunk.iter().cloned() {
            let client = client.clone();
            tasks.spawn(async move {
                let tx = fetch_transaction_with_retries(
                    client,
                    row.genesis_txid_hex.clone(),
                    retries,
                    retry_delay,
                )
                .await?;
                Ok::<_, anyhow::Error>((row, tx))
            });
        }

        while let Some(joined) = tasks.join_next().await {
            processed += 1;
            let (row, tx) = match joined {
                Ok(Ok(result)) => result,
                Ok(Err(e)) => {
                    fetch_errors += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(target: "repair-native-covenant-ids", "{e:#}");
                    } else {
                        tracing::debug!(target: "repair-native-covenant-ids", "{e:#}");
                    }
                    continue;
                }
                Err(e) => {
                    fetch_errors += 1;
                    if fetch_error_samples < 5 {
                        fetch_error_samples += 1;
                        tracing::warn!(
                            target: "repair-native-covenant-ids",
                            "fetch task failed: {e:#}"
                        );
                    } else {
                        tracing::debug!(
                            target: "repair-native-covenant-ids",
                            "fetch task failed: {e:#}"
                        );
                    }
                    continue;
                }
            };

            let target_covenant_id = derive_native_covenant_id_repair_target(
                &pool,
                client.clone(),
                tx,
                row.genesis_vout,
                retries,
                retry_delay,
            )
            .await?;
            let Some(target_covenant_id) = target_covenant_id else {
                no_native_id += 1;
                continue;
            };
            if target_covenant_id == row.covenant_id {
                same_id += 1;
                continue;
            }

            if apply {
                if repo::rekey_covenant_id(&pool, &row.covenant_id, &target_covenant_id).await? {
                    rekeyed += 1;
                    tracing::info!(
                        target: "repair-native-covenant-ids",
                        "{} -> {} from {}:{}",
                        row.covenant_id_hex,
                        hex::encode(&target_covenant_id),
                        row.genesis_txid_hex,
                        row.genesis_vout
                    );
                }
            } else {
                would_rekey += 1;
            }
        }

        tracing::info!(
            target: "repair-native-covenant-ids",
            "progress {}/{}: would_rekey={} rekeyed={} same_id={} no_native_id={} fetch_err={}",
            processed,
            total,
            would_rekey,
            rekeyed,
            same_id,
            no_native_id,
            fetch_errors
        );
    }

    if total == 0 {
        tracing::info!(
            target: "repair-native-covenant-ids",
            "progress {}/{}: would_rekey={} rekeyed={} same_id={} no_native_id={} fetch_err={}",
            processed,
            total,
            would_rekey,
            rekeyed,
            same_id,
            no_native_id,
            fetch_errors
        );
    }

    if apply {
        misclassified_deploys_deleted =
            repo::delete_misclassified_continuation_deploy_actions(&pool).await?;
        if misclassified_deploys_deleted > 0 {
            tracing::info!(
                target: "repair-native-covenant-ids",
                "deleted {misclassified_deploys_deleted} misclassified deploy action(s)"
            );
        }
    }

    print_json(&serde_json::json!({
        "candidates": total,
        "concurrency": concurrency,
        "retries": retries,
        "retryDelayMs": retry_delay_ms,
        "apply": apply,
        "wouldRekey": would_rekey,
        "rekeyed": rekeyed,
        "sameId": same_id,
        "noNativeId": no_native_id,
        "fetchErrors": fetch_errors,
        "misclassifiedDeploysDeleted": misclassified_deploys_deleted,
    }))
}

async fn fetch_payload_claim_transaction(
    client: tn12_indexer_crawl::RestClient,
    txid: String,
    retries: u32,
    retry_delay: Duration,
) -> Result<tn12_indexer_core::RestTransaction> {
    fetch_transaction_with_retries(client, txid, retries, retry_delay).await
}

async fn derive_native_covenant_id_repair_target(
    pool: &tn12_indexer_db::PgPool,
    client: tn12_indexer_crawl::RestClient,
    tx: tn12_indexer_core::RestTransaction,
    genesis_vout: i32,
    retries: u32,
    retry_delay: Duration,
) -> Result<Option<Vec<u8>>> {
    use tn12_indexer_core::compute_genesis_covenant_id_for_output;
    use tn12_indexer_db::repo;

    let mut current_tx = tx;
    let mut current_vout = genesis_vout;
    let mut seen = HashSet::new();

    for _ in 0..16 {
        let marker = format!("{}:{}", current_tx.transaction_id, current_vout);
        if !seen.insert(marker) {
            return Ok(None);
        }

        let mut parents = Vec::new();
        let mut seen_parents = HashSet::new();
        for input in &current_tx.inputs {
            let Ok(prev_vout) = input.previous_outpoint_index.parse::<i32>() else {
                continue;
            };
            if let Some(parent) =
                repo::covenant_identity_for_outpoint(pool, &input.previous_outpoint_hash, prev_vout)
                    .await?
            {
                if seen_parents.insert(parent.covenant_id_hex.clone()) {
                    parents.push(parent);
                }
            }
        }

        match parents.len() {
            1 => {
                let parent = parents.remove(0);
                if parent.canonical_covenant_id_known {
                    return Ok(Some(parent.covenant_id));
                }
                let parent_tx = fetch_transaction_with_retries(
                    client.clone(),
                    parent.genesis_txid_hex,
                    retries,
                    retry_delay,
                )
                .await
                .with_context(|| {
                    format!(
                        "fetch fallback parent {} for continuation repair",
                        parent.covenant_id_hex
                    )
                });
                let Ok(parent_tx) = parent_tx else {
                    return Ok(None);
                };
                current_vout = parent.genesis_vout;
                current_tx = parent_tx;
                continue;
            }
            n if n > 1 => return Ok(None),
            _ => {}
        }

        return Ok(compute_genesis_covenant_id_for_output(
            &current_tx,
            current_vout.try_into().unwrap_or_default(),
        )
        .and_then(|id| hex::decode(id).ok())
        .filter(|bytes| bytes.len() == 32));
    }

    Ok(None)
}

async fn fetch_transaction_with_retries(
    client: tn12_indexer_crawl::RestClient,
    txid: String,
    retries: u32,
    retry_delay: Duration,
) -> Result<tn12_indexer_core::RestTransaction> {
    let mut failed_attempts = 0;
    loop {
        match client.get_transaction(&txid).await {
            Ok(tx) => return Ok(tx),
            Err(e) if failed_attempts < retries => {
                failed_attempts += 1;
                tracing::debug!(
                    target: "fetch-transaction",
                    "fetch {txid} failed attempt {}/{}: {e:#}",
                    failed_attempts,
                    retries + 1
                );
                tokio::time::sleep(retry_delay.saturating_mul(failed_attempts)).await;
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("fetch {txid} after {} attempts", failed_attempts + 1)
                });
            }
        }
    }
}
async fn run_scan(
    rest: String,
    database_url: String,
    migrate: bool,
    from_blue_score: u64,
    from_tip_window: Option<u64>,
    cursor_key: String,
    batch_size: u32,
    idle_secs: u64,
    hydrate_concurrency: usize,
    prevout_concurrency: usize,
) -> Result<()> {
    use std::sync::Arc;
    use std::time::Duration;
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_crawl::{ChainScanner, PgCursorStore, ScannerConfig};
    use tn12_indexer_db::{connect, migrate as db_migrate, PgPersister};

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }
    let persister = Arc::new(PgPersister::new(pool.clone()));
    let cursor = Box::new(PgCursorStore::with_key(pool, cursor_key));
    let client = RestClient::new(rest)?;
    let scanner = ChainScanner::new(
        client,
        persister,
        ScannerConfig {
            from_blue_score,
            from_tip_window,
            batch_size,
            idle_interval: Duration::from_secs(idle_secs),
            hydrate_concurrency,
            prevout_concurrency,
        },
        cursor,
    );
    scanner.run_forever().await
}

fn parse_guarded_probe_fixture(bytes: &[u8]) -> Result<Vec<tn12_indexer_core::RestTransaction>> {
    anyhow::ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "probe fixture exceeds 8 MiB"
    );
    let txs: Vec<tn12_indexer_core::RestTransaction> = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        (1..=16).contains(&txs.len()),
        "probe fixture requires 1-16 transactions"
    );
    Ok(txs)
}

async fn run_guarded_generic_probe(
    fixture: PathBuf,
    database_url: String,
    apply: bool,
) -> Result<()> {
    use std::io::Read;
    use tn12_indexer_db::{connect, persist::ProbeReason, PgPersister};
    let mut bytes = Vec::new();
    std::fs::File::open(fixture)?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let txs = parse_guarded_probe_fixture(&bytes)?;
    let fixture_hash = hex::encode(tn12_indexer_core::blake2b_256(&bytes));
    if !apply {
        return print_json(&serde_json::json!({
            "apply_requested":false, "fixture_hash":fixture_hash, "transactions":txs.len(),
            "validation":"JSON and count only; source and database eligibility not checked",
        }));
    }
    let pool = match connect(&database_url).await {
        Ok(pool) => pool,
        Err(error) => {
            let outcome = tn12_indexer_db::persist::GenericProbeOutcome {
                reason: ProbeReason::DatabaseOrEvidenceError,
                confirmed_txids: vec![],
                remaining_txids: txs.iter().map(|tx| tx.transaction_id.clone()).collect(),
                uncertain_txids: vec![],
                attempts: vec![],
            };
            print_json(
                &serde_json::json!({"apply_requested":true, "fixture_hash":fixture_hash, "outcome":outcome}),
            )?;
            return Err(error.context("probe database connection failed before writes"));
        }
    };
    let outcome = PgPersister::new(pool)
        .persist_guarded_generic_probe(&txs)
        .await;
    let completed = outcome.reason == ProbeReason::Completed;
    print_json(
        &serde_json::json!({"apply_requested":true, "fixture_hash":fixture_hash, "outcome":outcome}),
    )?;
    anyhow::ensure!(completed, "probe stopped; preserve the fixture and reconcile the reported remaining or uncertain transactions before retrying");
    Ok(())
}

async fn run_replay_window(
    rest: String,
    database_url: String,
    blue_score: u64,
    batch_size: u32,
) -> Result<()> {
    use tn12_indexer_crawl::{ChainScanner, PgCursorStore, RestClient, ScannerConfig};
    use tn12_indexer_db::{connect, PgPersister};
    anyhow::ensure!(
        blue_score % u64::from(batch_size) == 0,
        "blue-score must be aligned to batch-size"
    );
    let pool = connect(&database_url).await?;
    let scanner = ChainScanner::new(
        RestClient::new(rest)?,
        std::sync::Arc::new(PgPersister::new(pool.clone()).with_bounded_writer_lock_wait()),
        ScannerConfig {
            batch_size,
            ..Default::default()
        },
        Box::new(PgCursorStore::with_key(
            pool.clone(),
            "unused_replay_window_cursor",
        )),
    )
    .with_bulk_block_hydration();
    let persisted_txs = scanner.replay_window(blue_score).await?;
    let (covenants, actions) = PgPersister::new(pool)
        .normalize_replayed_genesis(blue_score, u64::from(batch_size))
        .await?;
    tracing::info!(
        blue_score,
        persisted_txs,
        normalized_covenants = covenants,
        normalized_actions = actions,
        "replayed settled window and normalized canonical genesis"
    );
    Ok(())
}

async fn run_tip_follow(
    rest: String,
    next_rest: Option<String>,
    switch_blue_score: Option<u64>,
    database_url: String,
    migrate: bool,
    cursor_key: String,
    batch_size: u32,
    overlap_windows: u32,
    max_catchup_windows: u32,
    poll_ms: u64,
    settled_recheck_span_scores: u64,
    settled_recheck_min_age_scores: u64,
    adaptive_prefetch: bool,
    window_fetch_concurrency: usize,
    recent_acceptance_reconciliation: bool,
    hydrate_concurrency: usize,
    prevout_concurrency: usize,
) -> Result<()> {
    use std::sync::Arc;
    use std::time::Duration;
    use tn12_indexer_crawl::{ChainTipFollower, RestClient, TipFollowerConfig};
    use tn12_indexer_db::{connect, migrate as db_migrate, PgPersister};

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }
    let persister = Arc::new(PgPersister::for_tip_follow(pool.clone())?);
    let config = TipFollowerConfig {
        batch_size,
        overlap_windows,
        max_catchup_windows,
        poll_interval: Duration::from_millis(poll_ms.max(50)),
        settled_recheck_span_scores,
        settled_recheck_min_age_scores,
        hydrate_concurrency,
        prevout_concurrency,
        adaptive_prefetch,
        window_fetch_concurrency,
        recent_acceptance_reconciliation,
    };
    let initial_rest = RestClient::new(rest.clone())?;
    let initial_rest = if next_rest.is_some() {
        initial_rest.allow_degraded_snapshot()
    } else {
        initial_rest
    };
    let follower = ChainTipFollower::new(
        initial_rest,
        persister.clone(),
        pool.clone(),
        cursor_key.clone(),
        config.clone(),
    )?;
    if let (Some(next_rest), Some(boundary)) = (next_rest, switch_blue_score) {
        anyhow::ensure!(boundary % 100 == 0, "source switch score must align to 100");
        follower.run_until_blue_score(boundary).await?;
        let old = RestClient::new(rest)?.allow_degraded_snapshot();
        let next = RestClient::new(next_rest)?;
        verify_rest_source_overlap(&old, &next, boundary).await?;
        tracing::info!(
            boundary,
            "REST source overlap verified; switching replay source"
        );
        let successor = ChainTipFollower::new(next, persister, pool, cursor_key, config)?;
        successor.run_forever().await
    } else {
        follower.run_forever().await
    }
}

async fn run_settled_recheck(
    rest: String,
    database_url: String,
    cursor_key: String,
    span_scores: u64,
    min_age_scores: u64,
    poll_ms: u64,
    hydrate_concurrency: usize,
    prevout_concurrency: usize,
) -> Result<()> {
    use std::sync::Arc;
    use tn12_indexer_crawl::{ChainTipFollower, RestClient, TipFollowerConfig};
    use tn12_indexer_db::{connect, PgPersister, SettledRecheckFence};

    let pool = connect(&database_url).await?;
    let rest = RestClient::new(rest)?;
    let config = TipFollowerConfig {
        settled_recheck_span_scores: span_scores,
        settled_recheck_min_age_scores: min_age_scores,
        poll_interval: Duration::from_millis(poll_ms.max(1_000)),
        hydrate_concurrency,
        prevout_concurrency,
        ..Default::default()
    };
    anyhow::ensure!(span_scores > min_age_scores.saturating_add(100),
        "settled recheck span must exceed minimum age by one window");
    let persister = PgPersister::for_tip_follow(pool.clone())?;
    let fence = SettledRecheckFence::claim(&pool, &cursor_key).await?;
    let persister = Arc::new(persister.with_settled_recheck_fence(fence.clone()));
    ChainTipFollower::new(rest, persister, pool, cursor_key, config)?
        .with_settled_recheck_fence(fence)
        .run_settled_recheck_forever()
        .await
}

type SourceBlockIdentity = (u64, String);
type SourceTransactionIdentity = (u64, String, String, bool);

fn source_identities(
    blocks: &[tn12_indexer_core::VirtualChainBlock],
) -> (
    BTreeSet<SourceBlockIdentity>,
    BTreeSet<SourceTransactionIdentity>,
) {
    let mut block_ids = BTreeSet::new();
    let mut transaction_ids = BTreeSet::new();
    for block in blocks {
        block_ids.insert((block.blue_score, block.hash.clone()));
        for tx in &block.transactions {
            transaction_ids.insert((
                block.blue_score,
                block.hash.clone(),
                tx.transaction_id.clone(),
                tx.is_accepted,
            ));
        }
    }
    (block_ids, transaction_ids)
}

fn verify_source_overlap_pages(
    old_page: &[tn12_indexer_core::VirtualChainBlock],
    next_page: &[tn12_indexer_core::VirtualChainBlock],
    boundary: u64,
) -> Result<()> {
    anyhow::ensure!(
        !old_page.is_empty() && !next_page.is_empty(),
        "REST source overlap is empty at score {boundary}"
    );
    anyhow::ensure!(
        source_identities(old_page) == source_identities(next_page),
        "REST source block or transaction identities differ at score {boundary}"
    );
    Ok(())
}

async fn verify_rest_source_overlap(
    old: &tn12_indexer_crawl::RestClient,
    next: &tn12_indexer_crawl::RestClient,
    boundary: u64,
) -> Result<()> {
    let end = boundary.saturating_add(99);
    let (old_tip, next_tip) = tokio::try_join!(
        old.get_rest_database_blue_score(),
        next.get_rest_database_blue_score()
    )?;
    anyhow::ensure!(
        old_tip >= end && next_tip >= end,
        "REST source overlap is not complete at score {end}: old={old_tip} next={next_tip}"
    );
    let (old_page, next_page) = tokio::try_join!(
        old.get_virtual_chain(boundary, 100),
        next.get_virtual_chain(boundary, 100)
    )?;
    verify_source_overlap_pages(&old_page, &next_page, boundary)
}

// Session advisory locks must never be returned to the pool on an error or
// cancellation: the server may have acquired the lock before the response was lost.
struct ProjectorLockConnection {
    connection: sqlx::pool::PoolConnection<sqlx::Postgres>,
    safe_to_reuse: bool,
}

impl std::ops::Deref for ProjectorLockConnection {
    type Target = sqlx::PgConnection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl std::ops::DerefMut for ProjectorLockConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.connection
    }
}

impl Drop for ProjectorLockConnection {
    fn drop(&mut self) {
        if !self.safe_to_reuse {
            self.connection.close_on_drop();
        }
    }
}

async fn run_kcc20_owner_action_backfill(
    database_url: String,
    batch_size: i64,
    pause_ms: u64,
    follow: bool,
    idle_ms: u64,
) -> Result<()> {
    use tn12_indexer_db::{connect, repo};

    let pool = connect(&database_url).await?;
    repo::initialize_kcc20_owner_action_backfill(&pool).await?;
    let mut batches = 0_u64;
    let mut completed = false;
    loop {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, batch_size).await? {
            if !completed {
                tracing::info!(batches, "KCC20 owner-action source backfill complete");
                completed = true;
                batches = 0;
            }
            if !follow {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(idle_ms.max(250))).await;
            continue;
        }
        if completed {
            tracing::info!("KCC20 owner-action source backfill resumed");
            completed = false;
        }
        batches += 1;
        if batches % 100 == 0 {
            tracing::info!(batches, "KCC20 owner-action backfill progressing");
        }
        tokio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
    }
}

async fn run_kcc20_projector(
    database_url: String,
    migrate: bool,
    idle_secs: u64,
    activity_max_txids_per_pass: i64,
    activity_statement_timeout: String,
    full_refresh_enabled: bool,
    max_iterations: Option<u64>,
) -> Result<()> {
    use sqlx::postgres::PgListener;
    use std::time::{Duration, Instant};
    use tn12_indexer_db::{connect, migrate as db_migrate, repo};

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }
    let mut dirty_listener = PgListener::connect(&database_url)
        .await
        .context("connect KCC20 projector dirty listener")?;
    dirty_listener
        .listen(repo::KCC20_PROJECTION_DIRTY_CHANNEL)
        .await
        .context("listen for KCC20 projection dirty notifications")?;

    let mut iterations = 0_u64;
    let mut owner_action_initialized = false;
    loop {
        iterations += 1;
        let started = Instant::now();

        let mut skipped = false;
        // Acquisition and release belong to the same retry boundary as refresh.
        let refresh_result: Result<()> = async {
            let mut lock_conn = ProjectorLockConnection {
                connection: pool.acquire().await
                    .context("acquire KCC20 projector lock connection")?,
                safe_to_reuse: false,
            };
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(KCC20_PROJECTOR_LOCK_KEY)
                .fetch_one(&mut *lock_conn)
                .await
                .context("acquire KCC20 projector advisory lock")?;

            if acquired {
                let result = async {
                    let pass_dirty_id = repo::capture_kcc20_projection_pass_dirty_id(&mut lock_conn)
                        .await
                        .context("capture KCC20 projector pass dirty watermark")?;
                    if !owner_action_initialized {
                        repo::initialize_kcc20_owner_action_backfill(&pool)
                            .await
                            .context("initialize KCC20 owner-action backfill")?;
                        owner_action_initialized = true;
                    }
                    let activity_feed_result = refresh_kcc20_activity_projection_phase(
                        &pool,
                        iterations,
                        pass_dirty_id,
                        activity_max_txids_per_pass,
                        full_refresh_enabled,
                        activity_statement_timeout.clone(),
                    )
                    .await;
                    let owner_orders_result = refresh_kcc20_projection_phase(
                        &pool,
                        repo::kcc20_owner_orders_projection_name(),
                        iterations,
                        pass_dirty_id,
                        || repo::refresh_kcc20_owner_orders(&pool),
                    )
                    .await;
                    let market_result = if owner_orders_result.is_ok() {
                        refresh_kcc20_projection_phase(
                            &pool,
                            repo::kcc20_market_projection_name(),
                            iterations,
                            pass_dirty_id,
                            || repo::refresh_kcc20_market_summaries(&pool),
                        )
                        .await
                    } else {
                        tracing::debug!(
                            target: "kcc20_projector",
                            iteration = iterations,
                            "deferring market refresh until owner-orders projection succeeds"
                        );
                        Ok(())
                    };
                    let token_page_result = refresh_kcc20_projection_phase(
                        &pool,
                        repo::kcc20_token_page_projection_name(),
                        iterations,
                        pass_dirty_id,
                        || repo::refresh_kcc20_token_page_projections(&pool),
                    )
                    .await;
                    let owner_action_result = repo::refresh_kcc20_owner_action_history(
                        &pool,
                        pass_dirty_id,
                        activity_max_txids_per_pass,
                    )
                    .await;
                    let dependencies_ready = market_result.is_ok()
                        && token_page_result.is_ok()
                        && owner_orders_result.is_ok();
                    let owner_portfolio_result = if dependencies_ready {
                        refresh_kcc20_projection_phase(
                            &pool,
                            repo::kcc20_owner_portfolio_assets_projection_name(),
                            iterations,
                            pass_dirty_id,
                            || repo::refresh_kcc20_owner_portfolio_assets(&pool),
                        )
                        .await
                    } else {
                        tracing::debug!(
                            target: "kcc20_projector",
                            iteration = iterations,
                            projection = repo::kcc20_owner_portfolio_assets_projection_name(),
                            "deferring owner portfolio refresh until market, token-page, and owner-orders projections succeed"
                        );
                        Ok(())
                    };
                    let phases_result = market_result
                        .and(token_page_result)
                        .and(activity_feed_result)
                        .and(owner_orders_result)
                        .and(owner_action_result)
                        .and(owner_portfolio_result);
                    if phases_result.is_ok() {
                        let pruned_rows = repo::prune_kcc20_projection_dirty(&pool, 10_000)
                            .await
                            .context("prune processed KCC20 projection dirty rows")?;
                        if pruned_rows > 0 {
                            tracing::info!(
                                target: "kcc20_projector",
                                iteration = iterations,
                                pruned_rows,
                                "pruned processed KCC20 projection dirty rows"
                            );
                        }
                    }
                    phases_result
                }
                .await;
                let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
                    .bind(KCC20_PROJECTOR_LOCK_KEY)
                    .fetch_one(&mut *lock_conn)
                    .await
                    .context("release KCC20 projector advisory lock")?;
                anyhow::ensure!(released, "KCC20 projector lost projection ownership");
                lock_conn.safe_to_reuse = true;
                result
            } else {
                tracing::info!(
                    target: "kcc20_projector",
                    iteration = iterations,
                    "another KCC20 projector pass is already running"
                );
                lock_conn.safe_to_reuse = true;
                skipped = true;
                Ok(())
            }
        }
        .await;

        match refresh_result {
            Ok(()) if skipped => {}
            Ok(()) => {
                tracing::info!(
                    target: "kcc20_projector",
                    iteration = iterations,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "refreshed KCC20 read models"
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "kcc20_projector",
                    iteration = iterations,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    error = %error,
                    "KCC20 read model refresh failed"
                );
                if max_iterations == Some(iterations) {
                    return Err(error).context("refresh KCC20 read models");
                }
            }
        }

        if skipped && max_iterations.is_some_and(|max| iterations >= max) {
            anyhow::bail!("one-shot KCC20 projector could not acquire projection ownership");
        }
        if max_iterations.is_some_and(|max| iterations >= max) {
            return Ok(());
        }

        match tokio::time::timeout(Duration::from_secs(idle_secs.max(1)), dirty_listener.recv())
            .await
        {
            Ok(Ok(notification)) => tracing::debug!(
                target: "kcc20_projector",
                dirty_id = notification.payload(),
                "received KCC20 projection dirty notification"
            ),
            Ok(Err(error)) => {
                tracing::warn!(
                    target: "kcc20_projector",
                    error = %error,
                    "KCC20 projection listener disconnected; reconnecting"
                );
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    match PgListener::connect(&database_url).await {
                        Ok(mut listener) => {
                            match listener.listen(repo::KCC20_PROJECTION_DIRTY_CHANNEL).await {
                                Ok(()) => {
                                    dirty_listener = listener;
                                    break;
                                }
                                Err(error) => tracing::warn!(
                                    target: "kcc20_projector",
                                    error = %error,
                                    "failed to resume KCC20 projection dirty listener; retrying"
                                ),
                            }
                        }
                        Err(error) => tracing::warn!(
                            target: "kcc20_projector",
                            error = %error,
                            "failed to reconnect KCC20 projection dirty listener; retrying"
                        ),
                    }
                }
            }
            Err(_) => {}
        }
    }
}

async fn refresh_kcc20_projection_phase<F, Fut>(
    pool: &tn12_indexer_db::PgPool,
    projection_name: &str,
    iteration: u64,
    pass_dirty_id: i64,
    refresh: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    use tn12_indexer_db::repo;

    let target_dirty_id =
        repo::kcc20_projection_dirty_target_for_through(pool, projection_name, pass_dirty_id)
            .await
            .with_context(|| format!("check {projection_name} KCC20 projection dirty watermark"))?;
    let Some(dirty_id) = target_dirty_id else {
        tracing::debug!(
            target: "kcc20_projector",
            iteration,
            projection = projection_name,
            "KCC20 read model is clean"
        );
        return Ok(());
    };

    refresh()
        .await
        .with_context(|| format!("refresh {projection_name} KCC20 projection"))?;
    repo::mark_kcc20_projection_refreshed_for(pool, projection_name, dirty_id).await?;
    tracing::info!(
        target: "kcc20_projector",
        iteration,
        projection = projection_name,
        dirty_id,
        "advanced KCC20 projection watermark"
    );
    Ok(())
}

async fn refresh_kcc20_activity_projection_phase(
    pool: &tn12_indexer_db::PgPool,
    iteration: u64,
    pass_dirty_id: i64,
    max_distinct_txids: i64,
    full_refresh_enabled: bool,
    statement_timeout: String,
) -> Result<()> {
    use tn12_indexer_db::repo;

    let projection_name = repo::kcc20_activity_feed_projection_name();
    let target_dirty_id = repo::kcc20_activity_projection_dirty_target_for_through(
        pool,
        pass_dirty_id,
        max_distinct_txids,
    )
    .await
    .with_context(|| format!("check {projection_name} KCC20 projection dirty watermark"))?;
    let Some(dirty_id) = target_dirty_id else {
        tracing::debug!(
            target: "kcc20_projector",
            iteration,
            projection = projection_name,
            "KCC20 read model is clean"
        );
        return Ok(());
    };

    let stats = repo::refresh_kcc20_activity_feed_with_config(
        pool,
        repo::Kcc20ActivityFeedRefreshConfig::projector(
            dirty_id,
            full_refresh_enabled,
            statement_timeout,
        ),
    )
    .await
    .context("refresh activity_feed KCC20 projection")?;
    if stats.mode == repo::Kcc20ActivityFeedRefreshMode::DisabledFull {
        tracing::warn!(
            target: "kcc20_projector",
            iteration,
            projection = projection_name,
            dirty_id,
            dirty_rows = stats.dirty_rows,
            "KCC20 activity feed full refresh is disabled; leaving projection dirty"
        );
        return Ok(());
    }
    tracing::info!(
        target: "kcc20_projector",
        iteration,
        projection = projection_name,
        dirty_id,
        dirty_rows = stats.dirty_rows,
        scoped_dirty_txids = stats.scoped_dirty_txids,
        mode = ?stats.mode,
        "advanced KCC20 activity-feed projection watermark"
    );
    Ok(())
}

fn run_async<F: std::future::Future<Output = Result<()>>>(f: F) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()
        .ok();
    let rt = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    rt.block_on(f)
}

async fn run_ingest(
    rest: String,
    txids: Vec<String>,
    database_url: Option<String>,
    migrate: bool,
) -> Result<()> {
    use std::sync::Arc;
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, migrate as db_migrate, Persister, PgPersister};

    let client = RestClient::new(rest)?;
    let persister: Option<Arc<PgPersister>> = match database_url.as_deref() {
        Some(url) => {
            let pool = connect(url).await?;
            if migrate {
                db_migrate(&pool).await?;
            }
            Some(Arc::new(PgPersister::new(pool)))
        }
        None => None,
    };

    let mut summary = serde_json::Map::new();
    for txid in &txids {
        let tx = client.get_transaction(txid).await?;
        if let Some(p) = persister.as_ref() {
            let stats = tn12_indexer_crawl::rest_replay_fence::for_transactions(p,&client,std::slice::from_ref(&tx)).await?
                .persist_tx(&tx).await?;
            tracing::info!(target: "ingest", "{txid} -> {:?}", stats);
            summary.insert(
                txid.clone(),
                serde_json::json!({
                    "blocksInserted": stats.blocks_inserted,
                    "covenantsInserted": stats.covenants_inserted,
                    "utxosInserted": stats.utxos_inserted,
                    "utxosSpent": stats.utxos_spent,
                    "actionsInserted": stats.actions_inserted,
                }),
            );
        } else {
            tracing::info!(target: "ingest", "{txid} fetched (no DB)");
            summary.insert(
                txid.clone(),
                serde_json::json!({ "isAccepted": tx.is_accepted }),
            );
        }
    }
    print_json(&serde_json::Value::Object(summary))
}

#[derive(Debug)]
struct KcomReceiptTx {
    label: String,
    txid: String,
    accepting_block_hash: String,
    inputs: Vec<(String, String)>,
    outputs: Vec<(usize, String, String, Option<String>)>,
    token_id: Option<String>,
}

fn kcom_receipt_text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value.get(field).and_then(Value::as_str)
        .with_context(|| format!("KCOM receipt missing {field}"))
}

fn kcom_receipt_hex32(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "{field} must be 32-byte hex");
    Ok(())
}

fn kcom_receipt_transactions(paths: &[PathBuf]) -> Result<Vec<KcomReceiptTx>> {
    anyhow::ensure!(!paths.is_empty() && paths.len() <= 4,
        "KCOM reconciliation requires 1..=4 ordered campaign receipts");
    let mut result = Vec::new();
    let mut token_deploy: Option<(String, String, String)> = None;
    let mut graphs = BTreeSet::new();
    for path in paths {
        let receipt: Value = read_json(path)?;
        anyhow::ensure!(receipt["network"] == "testnet-10", "KCOM receipt must use TN10");
        let graph = kcom_receipt_text(&receipt, "graphId")?;
        let token = kcom_receipt_text(&receipt, "tokenId")?;
        kcom_receipt_hex32(graph, "graphId")?;
        kcom_receipt_hex32(token, "tokenId")?;
        anyhow::ensure!(graphs.insert(graph.to_owned()), "duplicate KCOM campaign graph");
        let deploy = &receipt["tokenDeploy"];
        let deploy_id = kcom_receipt_text(deploy, "txid")?;
        let deploy_block = kcom_receipt_text(deploy, "acceptingBlockHash")?;
        kcom_receipt_hex32(deploy_id, "token deployment txid")?;
        kcom_receipt_hex32(deploy_block, "token deployment accepting block")?;
        let source = (deploy_id.to_owned(), deploy_block.to_owned(), token.to_owned());
        if let Some(previous) = &token_deploy {
            anyhow::ensure!(previous == &source, "campaign receipts disagree on token deployment");
        } else {
            token_deploy = Some(source);
        }
        let rows = receipt["transactions"].as_array()
            .context("KCOM receipt transactions are missing")?;
        anyhow::ensure!(!rows.is_empty() && rows.len() <= 64,
            "KCOM receipt must contain 1..=64 transactions");
        for row in rows {
            let label = kcom_receipt_text(row, "label")?.to_owned();
            let txid = kcom_receipt_text(row, "txid")?.to_owned();
            let block = kcom_receipt_text(row, "acceptingBlockHash")?.to_owned();
            kcom_receipt_hex32(&txid, "campaign txid")?;
            kcom_receipt_hex32(&block, "campaign accepting block")?;
            anyhow::ensure!(row["acceptedRest"] == true, "unaccepted receipt transaction {txid}");
            let inputs = row["inputs"].as_array().context("KCOM receipt inputs are missing")?
                .iter().map(|item| {
                    let outpoint = kcom_receipt_text(item, "outpoint")?;
                    let (hash, index) = outpoint.split_once(':').context("invalid receipt input outpoint")?;
                    kcom_receipt_hex32(hash, "receipt input txid")?;
                    index.parse::<u32>().context("invalid receipt input index")?;
                    Ok((hash.to_owned(), index.to_owned()))
                }).collect::<Result<Vec<_>>>()?;
            let outputs = row["outputs"].as_array().context("KCOM receipt outputs are missing")?
                .iter().map(|item| {
                    let index = item["index"].as_u64().context("invalid receipt output index")? as usize;
                    let amount = kcom_receipt_text(item, "amountSompi")?.to_owned();
                    amount.parse::<u64>().context("invalid receipt output amount")?;
                    let script = kcom_receipt_text(item, "script")?.to_owned();
                    hex::decode(&script).context("invalid receipt output script")?;
                    let covenant_id = item["covenantId"].as_str().map(str::to_owned);
                    if let Some(id) = &covenant_id { kcom_receipt_hex32(id, "receipt output covenant ID")?; }
                    Ok((index, amount, script, covenant_id))
                }).collect::<Result<Vec<_>>>()?;
            result.push(KcomReceiptTx { label, txid, accepting_block_hash: block,
                inputs, outputs, token_id: None });
        }
    }
    let (token_txid, token_block, token_id) = token_deploy.context("missing token deployment")?;
    result.insert(0, KcomReceiptTx { label: "token-deploy".into(), txid: token_txid,
        accepting_block_hash: token_block, inputs: Vec::new(), outputs: Vec::new(),
        token_id: Some(token_id) });
    anyhow::ensure!(result.len() <= 129, "KCOM reconciliation allowlist is too large");
    let all = result.iter().map(|row| row.txid.as_str()).collect::<BTreeSet<_>>();
    anyhow::ensure!(all.len() == result.len(), "duplicate KCOM receipt transaction ID");
    let mut seen = BTreeSet::new();
    for row in &result {
        for (source, _) in &row.inputs {
            anyhow::ensure!(!all.contains(source.as_str()) || seen.contains(source.as_str()),
                "KCOM receipt dependency is out of order at {}", row.txid);
        }
        seen.insert(row.txid.as_str());
    }
    Ok(result)
}

fn verify_kcom_receipt_tx(expected: &KcomReceiptTx, tx: &tn12_indexer_core::RestTransaction) -> Result<()> {
    anyhow::ensure!(tx.transaction_id == expected.txid && tx.is_accepted,
        "KCOM source is not the accepted transaction {}", expected.txid);
    anyhow::ensure!(tx.accepting_block_hash.as_deref() == Some(expected.accepting_block_hash.as_str()),
        "KCOM accepting block changed for {}", expected.txid);
    if let Some(token_id) = &expected.token_id {
        anyhow::ensure!(tx.outputs.first().and_then(|out| out.canonical_covenant_id()) == Some(token_id.as_str()),
            "KCOM token deployment identity differs");
    }
    if expected.token_id.is_none() {
        anyhow::ensure!(tx.inputs.len() == expected.inputs.len(),
            "KCOM input count differs for {}", expected.txid);
    }
    for (source, index) in &expected.inputs {
        anyhow::ensure!(tx.inputs.iter().any(|input|
            input.previous_outpoint_hash == *source && input.previous_outpoint_index == *index),
            "KCOM source outpoint differs for {}", expected.txid);
    }
    anyhow::ensure!(tx.outputs.len() == expected.outputs.len() || expected.token_id.is_some(),
        "KCOM output count differs for {}", expected.txid);
    for (index, amount, script, id) in &expected.outputs {
        let out = tx.outputs.iter().find(|out| out.index == *index as u64)
            .context("KCOM receipt output is missing")?;
        anyhow::ensure!(out.amount.to_string() == *amount && out.script_public_key == *script,
            "KCOM output script or native amount differs for {}:{index}", expected.txid);
        if let Some(id) = id {
            anyhow::ensure!(out.canonical_covenant_id() == Some(id.as_str()),
                "KCOM output lineage differs for {}:{index}", expected.txid);
        }
    }
    Ok(())
}

fn verify_kcom_indexed_outputs(
    tx: &tn12_indexer_core::RestTransaction,
    indexed: &[(i32, i64, Vec<u8>)],
) -> Result<()> {
    for (vout, native, script) in indexed {
        let output = tx.outputs.iter().find(|output| output.index == *vout as u64)
            .with_context(|| format!("indexed KCOM output is absent from accepted {}:{vout}", tx.transaction_id))?;
        let accepted_script = hex::decode(&output.script_public_key)?;
        anyhow::ensure!(u64::try_from(*native)? == output.amount
            && script == &accepted_script,
            "indexed KCOM output conflicts with accepted {}:{vout}", tx.transaction_id);
    }
    Ok(())
}

async fn run_reconcile_kcom_campaign(
    receipts: Vec<PathBuf>, rest: String, database_url: String, apply: bool,
) -> Result<()> {
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, Persister, PgPersister};

    let expected = kcom_receipt_transactions(&receipts)?;
    let client = RestClient::new(rest)?;
    let mut accepted = Vec::with_capacity(expected.len());
    for row in &expected {
        let tx = client.get_transaction_with_explicit_acceptance(&row.txid).await?;
        verify_kcom_receipt_tx(row, &tx).with_context(|| format!("verify {}", row.label))?;
        accepted.push(tx);
    }
    let pool = connect(&database_url).await?;
    for tx in &accepted {
        let indexed: Vec<(i32, i64, Vec<u8>)> = sqlx::query_as(
            "SELECT vout, amount_sompi, script_pubkey FROM covenant_utxos WHERE txid=$1",
        ).bind(hex::decode(&tx.transaction_id)?).fetch_all(&pool).await?;
        verify_kcom_indexed_outputs(tx, &indexed)?;
    }
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut reports = Vec::with_capacity(expected.len());
    for (row, tx) in expected.iter().zip(&accepted) {
        let txid = hex::decode(&row.txid)?;
        let before: (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(*) FILTER (WHERE action='spend' AND entrypoint IS NOT NULL) FROM covenant_actions WHERE txid=$1",
        ).bind(&txid).fetch_one(&pool).await?;
        if apply {
            tn12_indexer_crawl::rest_replay_fence::for_transactions(&writer,&client,std::slice::from_ref(tx)).await?
                .persist_tx(tx).await.with_context(|| format!("persist {}", row.label))?;
        }
        let after: (i64, i64) = if apply {
            sqlx::query_as("SELECT count(*), count(*) FILTER (WHERE action='spend' AND entrypoint IS NOT NULL) FROM covenant_actions WHERE txid=$1")
                .bind(&txid).fetch_one(&pool).await?
        } else { before };
        reports.push(json!({"label":row.label,"txid":row.txid,
            "actionsBefore":before.0,"decodedSpendsBefore":before.1,
            "actionsAfter":after.0,"decodedSpendsAfter":after.1}));
    }
    print_json(&json!({"applied":apply,"acceptedVerified":accepted.len(),"transactions":reports}))
}

async fn run_repair_genesis_states(
    rest: String,
    txids: Vec<String>,
    database_url: String,
    apply: bool,
) -> Result<()> {
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, PgPersister};

    anyhow::ensure!(
        !txids.is_empty() && txids.len() <= 16,
        "repair requires 1..=16 exact transaction ids"
    );
    let client = RestClient::new(rest)?;
    let writer = PgPersister::new(connect(&database_url).await?);
    let mut reports = Vec::with_capacity(txids.len());
    for txid in txids {
        anyhow::ensure!(
            txid.len() == 64 && txid.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "repair txid must be 64 hex characters"
        );
        let source = client
            .get_transaction_with_explicit_acceptance(&txid)
            .await?;
        anyhow::ensure!(
            source.transaction_id.eq_ignore_ascii_case(&txid),
            "REST returned a different transaction"
        );
        reports.push(writer.repair_claimed_genesis_states(&source, apply).await?);
    }
    print_json(&serde_json::to_value(reports)?)
}

async fn run_replay_deferred_decode(rest:String,txid:String,database_url:String,apply:bool)->Result<()> {
    use tn12_indexer_db::{connect,PgPersister};
    use tn12_indexer_crawl::RestClient;
    anyhow::ensure!(txid.len()==64 && txid.bytes().all(|b|b.is_ascii_hexdigit()),"txid must be 32-byte hex");
    let pool=connect(&database_url).await?;
    let rows:Vec<(Vec<u8>,serde_json::Value)>=sqlx::query_as(
        "SELECT block_hash,raw_transaction FROM indexer_deferred_decodes WHERE txid=$1 AND status='pending' LIMIT 2")
        .bind(hex::decode(&txid)?).fetch_all(&pool).await?;
    anyhow::ensure!(rows.len()==1,"expected one pending acceptance; reconcile ambiguous acceptance first");
    let client=RestClient::new(rest)?;
    let source=client.get_transaction_with_explicit_acceptance(&txid).await?;
    anyhow::ensure!(source.is_accepted && source.transaction_id.eq_ignore_ascii_case(&txid)
        && source.accepting_block_hash.as_deref()==Some(hex::encode(&rows[0].0).as_str()),
        "source no longer proves retained acceptance; reconcile without discarding evidence");
    let retained:tn12_indexer_core::RestTransaction=serde_json::from_value(rows[0].1.clone())?;
    anyhow::ensure!(tn12_indexer_db::deferred_decode::evidence_identity(&retained)
        ==tn12_indexer_db::deferred_decode::evidence_identity(&source),"source transaction differs from retained evidence");
    client.deferred_decode_proof(&retained,"testnet-10").await?;
    if apply {
        let writer=PgPersister::new(pool).with_bounded_writer_lock_wait();
        let guarded=tn12_indexer_crawl::rest_replay_fence::for_transactions(&writer,&client,std::slice::from_ref(&retained)).await?;
        guarded.replay_deferred_tx(&retained).await?;
        let proof=client.deferred_decode_proof(&retained,"testnet-10").await?;
        writer.confirm_deferred_decode(&proof).await?;
    }
    print_json(&serde_json::json!({"txid":txid,"sourceAcceptanceMatched":true,"applied":apply,
        "scope":"one transaction; pending dependencies and decoder support checked on apply"}))
}

async fn run_repair_wrapper_actions(
    rest: String,
    txids: Vec<String>,
    database_url: String,
    indexed_evidence: bool,
    apply: bool,
) -> Result<()> {
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_db::{connect, PgPersister};

    anyhow::ensure!(
        !txids.is_empty() && txids.len() <= 16,
        "repair requires 1..=16 exact transaction ids"
    );
    let client = if indexed_evidence {
        None
    } else {
        Some(RestClient::new(rest)?)
    };
    let writer = PgPersister::new(connect(&database_url).await?);
    let mut reports = Vec::with_capacity(txids.len());
    for txid in txids {
        anyhow::ensure!(
            txid.len() == 64 && txid.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "repair txid must be 64 hex characters"
        );
        if let Some(client) = &client {
            let source = client
                .get_transaction_with_explicit_acceptance(&txid)
                .await?;
            anyhow::ensure!(
                source.transaction_id.eq_ignore_ascii_case(&txid),
                "REST returned a different transaction"
            );
            reports.push(writer.repair_wrapper_action_state(&source, apply).await?);
        } else {
            reports.push(
                writer
                    .repair_wrapper_action_from_indexed_evidence(&txid, apply)
                    .await?,
            );
        }
    }
    print_json(&serde_json::to_value(reports)?)
}

async fn run_watch(
    rest: String,
    addresses: Vec<String>,
    database_url: String,
    migrate: bool,
    poll_secs: u64,
    limit: u32,
) -> Result<()> {
    use std::sync::Arc;
    use std::time::Duration;
    use tn12_indexer_crawl::RestClient;
    use tn12_indexer_crawl::{AddressWatcher, WatcherConfig};
    use tn12_indexer_db::{connect, migrate as db_migrate, PgPersister};

    let pool = connect(&database_url).await?;
    if migrate {
        db_migrate(&pool).await?;
    }
    let persister: Arc<PgPersister> = Arc::new(PgPersister::new(pool));
    let client = RestClient::new(rest)?;
    let watcher = AddressWatcher::new(
        client,
        persister,
        WatcherConfig {
            addresses,
            poll_interval: Duration::from_secs(poll_secs),
            limit_per_poll: limit,
        },
    );
    watcher.run_forever().await
}

async fn run_wrpc_watch(
    rest: String,
    wrpc_url: String,
    network_id: String,
    database_url: String,
    migrate: bool,
    fetch_concurrency: usize,
    cache_capacity: usize,
    cursor_key: String,
) -> Result<()> {
    let pool = tn12_indexer_db::connect(&database_url).await?;
    if migrate {
        tn12_indexer_db::migrate(&pool).await?;
    }
    let runtime = tn12_indexer_crawl::live_supervisor::JournalRuntime {
        pool, rest, wrpc_url, network: network_id, cursor: cursor_key,
        cache_capacity, fetch_concurrency,
        use_journal: std::env::var("TN12_WRPC_GENERIC_BULK_PERSIST").as_deref() == Ok("1"),
    };
    tn12_indexer_crawl::live_supervisor::supervise(&runtime, std::time::Duration::from_secs(2)).await
}

fn run_replay(fixtures: Vec<PathBuf>, fixture_dir: Option<PathBuf>) -> Result<()> {
    use tn12_indexer_core::RestTransaction;
    use tn12_indexer_crawl::IndexerEngine;

    let mut paths: Vec<PathBuf> = fixtures;
    if let Some(dir) = fixture_dir {
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        entries.sort();
        paths.extend(entries);
    }
    if paths.is_empty() {
        anyhow::bail!("no fixtures supplied (use --fixture or --fixture-dir)");
    }

    let mut engine = IndexerEngine::new();
    let mut all_events = Vec::new();
    for path in &paths {
        let tx: RestTransaction =
            read_json(path).with_context(|| format!("parsing REST tx from {}", path.display()))?;
        let mut events = engine.process_tx(&tx)?;
        all_events.append(&mut events);
    }
    print_json(&serde_json::json!({
        "fixturesProcessed": paths.len(),
        "knownCovenantUtxos": engine.known_count(),
        "events": all_events,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IndexerConfig {
    rpc_url: String,
    contracts: Vec<WatchedContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WatchedContract {
    id: String,
    name: String,
    contract_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compiled_json_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    known_outpoint: Option<Outpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IndexStore {
    #[serde(default)]
    last_sync_at_ms: u64,
    #[serde(default)]
    contracts: Vec<WatchedContract>,
    #[serde(default)]
    utxos: Vec<IndexedCovenantUtxo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct IndexedCovenantUtxo {
    contract_id: String,
    address: String,
    outpoint: Outpoint,
    amount_sompi: u64,
    script_public_key: Option<String>,
    covenant_id: Option<String>,
    status: UtxoStatus,
    first_seen_at_ms: u64,
    last_seen_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
struct Outpoint {
    txid: String,
    vout: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum UtxoStatus {
    Active,
    Spent,
}

impl std::fmt::Display for UtxoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtxoStatus::Active => f.write_str("active"),
            UtxoStatus::Spent => f.write_str("spent"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcUtxo {
    address: Option<String>,
    outpoint: Outpoint,
    amount_sompi: u64,
    script_public_key: Option<String>,
    covenant_id: Option<String>,
}

trait UtxoSource {
    fn get_utxos_by_address(&self, address: &str) -> Result<Vec<RpcUtxo>>;
}

fn sync_once(
    config: &IndexerConfig,
    store: &mut IndexStore,
    source: &dyn UtxoSource,
    now_ms: u64,
) -> Result<()> {
    validate_config(config)?;
    store.contracts = config.contracts.clone();
    store.last_sync_at_ms = now_ms;

    let mut existing = BTreeMap::<(String, Outpoint), IndexedCovenantUtxo>::new();
    for utxo in store.utxos.drain(..) {
        existing.insert((utxo.contract_id.clone(), utxo.outpoint.clone()), utxo);
    }

    for contract in &config.contracts {
        let rpc_utxos = source
            .get_utxos_by_address(&contract.contract_address)
            .with_context(|| format!("polling {}", contract.contract_address))?;

        let mut current_outpoints = BTreeSet::new();
        for rpc_utxo in rpc_utxos {
            current_outpoints.insert(rpc_utxo.outpoint.clone());
            let key = (contract.id.clone(), rpc_utxo.outpoint.clone());
            let first_seen = existing
                .get(&key)
                .map(|utxo| utxo.first_seen_at_ms)
                .unwrap_or(now_ms);

            existing.insert(
                key,
                IndexedCovenantUtxo {
                    contract_id: contract.id.clone(),
                    address: rpc_utxo
                        .address
                        .unwrap_or_else(|| contract.contract_address.clone()),
                    outpoint: rpc_utxo.outpoint,
                    amount_sompi: rpc_utxo.amount_sompi,
                    script_public_key: rpc_utxo.script_public_key,
                    covenant_id: rpc_utxo.covenant_id,
                    status: UtxoStatus::Active,
                    first_seen_at_ms: first_seen,
                    last_seen_at_ms: now_ms,
                },
            );
        }

        for ((contract_id, outpoint), utxo) in existing.iter_mut() {
            if contract_id == &contract.id
                && utxo.status == UtxoStatus::Active
                && !current_outpoints.contains(outpoint)
            {
                utxo.status = UtxoStatus::Spent;
                utxo.last_seen_at_ms = now_ms;
            }
        }
    }

    store.utxos = existing.into_values().collect();
    store.utxos.sort_by(|a, b| {
        a.contract_id
            .cmp(&b.contract_id)
            .then(a.outpoint.txid.cmp(&b.outpoint.txid))
            .then(a.outpoint.vout.cmp(&b.outpoint.vout))
    });
    Ok(())
}

struct FixtureSource {
    by_address: BTreeMap<String, Vec<RpcUtxo>>,
    fallback: Vec<RpcUtxo>,
}

impl FixtureSource {
    fn from_file(path: &Path) -> Result<Self> {
        let value = read_json::<Value>(path)?;
        let mut by_address = BTreeMap::<String, Vec<RpcUtxo>>::new();
        let mut fallback = Vec::<RpcUtxo>::new();

        if let Some(map) = value.get("byAddress").and_then(Value::as_object) {
            for (address, entries) in map {
                by_address.insert(address.clone(), parse_utxo_entries(entries)?);
            }
        } else {
            fallback = parse_utxo_entries(&value)?;
        }

        Ok(Self {
            by_address,
            fallback,
        })
    }
}

impl UtxoSource for FixtureSource {
    fn get_utxos_by_address(&self, address: &str) -> Result<Vec<RpcUtxo>> {
        Ok(self
            .by_address
            .get(address)
            .cloned()
            .unwrap_or_else(|| self.fallback.clone()))
    }
}

struct HttpRpcSource {
    rpc_url: String,
}

impl HttpRpcSource {
    fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

impl UtxoSource for HttpRpcSource {
    fn get_utxos_by_address(&self, address: &str) -> Result<Vec<RpcUtxo>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "covenant-tools",
            "method": "getUtxosByAddresses",
            "params": {
                "addresses": [address]
            }
        });
        let response = http_post_json(&self.rpc_url, &body)?;
        parse_utxo_entries(&response)
    }
}

#[derive(Debug, Error)]
enum HttpError {
    #[error("only http:// RPC URLs are supported in this prototype: {0}")]
    UnsupportedUrl(String),
    #[error("RPC URL is missing a host: {0}")]
    MissingHost(String),
    #[error("RPC returned non-success status: {0}")]
    Status(String),
    #[error("RPC response is missing HTTP headers")]
    MissingHeaders,
}

fn http_post_json(url: &str, body: &Value) -> Result<Value> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = TcpStream::connect((&*host, port))
        .with_context(|| format!("connecting to {host}:{port}"))?;
    let body = serde_json::to_string(body)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or(HttpError::MissingHeaders)?;
    let status = headers.lines().next().unwrap_or_default();
    if !(status.contains(" 200 ") || status.ends_with(" 200")) {
        return Err(HttpError::Status(status.to_string()).into());
    }
    serde_json::from_str(body).context("parsing RPC JSON response")
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| HttpError::UnsupportedUrl(url.to_string()))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(HttpError::MissingHost(url.to_string()).into());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port
                .parse::<u16>()
                .with_context(|| format!("invalid RPC URL port: {port}"))?;
            (host.to_string(), port)
        }
        _ => (authority.to_string(), 80),
    };
    Ok((host, port, path))
}

fn parse_utxo_entries(value: &Value) -> Result<Vec<RpcUtxo>> {
    let entries = value
        .get("result")
        .and_then(|result| result.get("entries").or_else(|| result.get("utxos")))
        .or_else(|| value.get("result").filter(|result| result.is_array()))
        .or_else(|| value.get("entries"))
        .or_else(|| value.get("utxos"))
        .or_else(|| value.as_array().map(|_| value))
        .context("RPC/fixture JSON does not contain UTXO entries")?;

    let entries = entries
        .as_array()
        .context("UTXO entries must be a JSON array")?;
    entries.iter().map(parse_utxo_entry).collect()
}

fn parse_utxo_entry(value: &Value) -> Result<RpcUtxo> {
    let outpoint_value = value.get("outpoint").unwrap_or(value);
    let txid = string_field(outpoint_value, &["transactionId", "transaction_id", "txid"])
        .or_else(|| string_field(value, &["transactionId", "transaction_id", "txid"]))
        .context("UTXO entry is missing transaction id")?;
    let vout = u32_field(outpoint_value, &["index", "vout"])
        .or_else(|| u32_field(value, &["index", "vout"]))
        .context("UTXO entry is missing output index")?;
    let amount_sompi = u64_field(value, &["amountSompi", "amount", "value"])
        .context("UTXO entry is missing amount")?;

    Ok(RpcUtxo {
        address: string_field(value, &["address"]),
        outpoint: Outpoint { txid, vout },
        amount_sompi,
        script_public_key: script_public_key(value),
        covenant_id: string_field(value, &["covenantId", "covenant_id"]),
    })
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        value.get(*name).and_then(|field| match field {
            Value::String(text) => Some(text.clone()),
            Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    })
}

fn u64_field(value: &Value, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        value.get(*name).and_then(|field| match field {
            Value::Number(number) => number.as_u64(),
            Value::String(text) => text.parse().ok(),
            _ => None,
        })
    })
}

fn u32_field(value: &Value, names: &[&str]) -> Option<u32> {
    u64_field(value, names).and_then(|number| u32::try_from(number).ok())
}

fn script_public_key(value: &Value) -> Option<String> {
    match value
        .get("scriptPublicKey")
        .or_else(|| value.get("script_public_key"))
    {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Object(map)) => map
            .get("script")
            .or_else(|| map.get("hex"))
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractReport<'a> {
    contract: &'a WatchedContract,
    active_utxos: Vec<&'a IndexedCovenantUtxo>,
    spent_utxos: Vec<&'a IndexedCovenantUtxo>,
    active_amount_sompi: u64,
}

fn build_contract_report<'a>(
    state: &'a IndexStore,
    contract_id: &str,
) -> Option<ContractReport<'a>> {
    let contract = state.contracts.iter().find(|item| item.id == contract_id)?;
    let active_utxos = state
        .utxos
        .iter()
        .filter(|utxo| utxo.contract_id == contract_id && utxo.status == UtxoStatus::Active)
        .collect::<Vec<_>>();
    let spent_utxos = state
        .utxos
        .iter()
        .filter(|utxo| utxo.contract_id == contract_id && utxo.status == UtxoStatus::Spent)
        .collect::<Vec<_>>();
    let active_amount_sompi = active_utxos.iter().map(|utxo| utxo.amount_sompi).sum();

    Some(ContractReport {
        contract,
        active_utxos,
        spent_utxos,
        active_amount_sompi,
    })
}

fn validate_config(config: &IndexerConfig) -> Result<()> {
    if config.rpc_url.trim().is_empty() {
        anyhow::bail!("rpcUrl is required");
    }
    let mut ids = BTreeSet::new();
    for contract in &config.contracts {
        if contract.id.trim().is_empty() {
            anyhow::bail!("contract id is required");
        }
        if !ids.insert(contract.id.clone()) {
            anyhow::bail!("duplicate contract id: {}", contract.id);
        }
        if contract.contract_address.trim().is_empty() {
            anyhow::bail!("contract address is required for {}", contract.id);
        }
    }
    Ok(())
}

fn read_store_or_default(path: &Path) -> Result<IndexStore> {
    if path.exists() {
        read_json(path)
    } else {
        Ok(IndexStore::default())
    }
}

fn read_json<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&content).with_context(|| format!("parsing {}", path.display()))
}

fn write_json<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(value)?;
    fs::write(path, format!("{content}\n")).with_context(|| format!("writing {}", path.display()))
}

fn parse_32_byte_hex(value: &str, name: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(value.trim().trim_start_matches("0x"))
        .with_context(|| format!("decoding {name} hex"))?;
    anyhow::ensure!(bytes.len() == 32, "{name} must decode to 32 bytes");
    Ok(bytes)
}

fn parse_kcc20_repair_state(value: &str) -> Result<tn12_indexer_db::repo::Kcc20RepairStateSpec> {
    let parts: Vec<&str> = value.split(':').collect();
    anyhow::ensure!(
        parts.len() == 5,
        "state must be scriptHash:owner:ownerScheme:amount:isMintAuthority"
    );
    let script_hash = parse_32_byte_hex(parts[0], "state scriptHash")?;
    let owner_identifier = parse_32_byte_hex(parts[1], "state ownerIdentifier")?;
    let identifier_type: i16 = parts[2]
        .parse()
        .with_context(|| format!("parsing state ownerScheme {}", parts[2]))?;
    anyhow::ensure!(
        (0..=4).contains(&identifier_type),
        "state ownerScheme must be 0 through 4"
    );
    let amount = parts[3].to_string();
    anyhow::ensure!(
        !amount.is_empty() && amount.chars().all(|c| c.is_ascii_digit()),
        "state amount must be a decimal integer string"
    );
    let is_minter = parts[4]
        .parse()
        .with_context(|| format!("parsing state isMintAuthority {}", parts[4]))?;
    Ok(tn12_indexer_db::repo::Kcc20RepairStateSpec {
        script_hash,
        owner_identifier,
        identifier_type,
        amount,
        is_minter,
    })
}

fn print_json<T>(value: &T) -> Result<()>
where
    T: Serialize,
{
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn now_ms() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before UNIX_EPOCH")?;
    Ok(duration.as_millis().try_into()?)
}

fn sample_config() -> IndexerConfig {
    IndexerConfig {
        rpc_url: "http://127.0.0.1:16210".to_string(),
        contracts: vec![WatchedContract {
            id: "timelock-demo".to_string(),
            name: "Time Lock Vault".to_string(),
            contract_address: "kaspatest:replace-with-contract-address".to_string(),
            compiled_json_path: Some(PathBuf::from("contracts/compiled/time-lock-vault.json")),
            known_outpoint: Some(Outpoint {
                txid: "replace-with-genesis-txid".to_string(),
                vout: 0,
            }),
        }],
    }
}

fn sample_rpc_response() -> Value {
    json!({
        "byAddress": {
            "kaspatest:replace-with-contract-address": [
                {
                    "address": "kaspatest:replace-with-contract-address",
                    "outpoint": {
                        "transactionId": "replace-with-genesis-txid",
                        "index": 0
                    },
                    "amount": 100000000,
                    "scriptPublicKey": {
                        "script": "replace-with-script-public-key"
                    },
                    "covenantId": "replace-with-covenant-id-if-rpc-exposes-it"
                }
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn kcom_reconciliation_rejects_changed_acceptance_and_outputs() {
        use super::*;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let receipts = ["main", "no-long"].map(|name|
            root.join(format!("docs/evidence/kcom-claim-tn10-{name}-full-20261030.json")));
        let expected = kcom_receipt_transactions(&receipts).unwrap();
        assert_eq!(expected.len(), 62);
        let first: Vec<tn12_indexer_core::RestTransaction> = read_json(
            &root.join("fixtures/kcom-claim-tn10-live/ordered-token-and-main.json")
        ).unwrap();
        let selection = &expected[11];
        let tx = &first[11];
        verify_kcom_receipt_tx(selection, tx).unwrap();
        let mut changed_block = tx.clone();
        changed_block.accepting_block_hash = Some("ff".repeat(32));
        assert!(verify_kcom_receipt_tx(selection, &changed_block).is_err());
        let mut changed_output = tx.clone();
        changed_output.outputs[1].script_public_key = format!("aa20{}87", "ff".repeat(32));
        assert!(verify_kcom_receipt_tx(selection, &changed_output).is_err());
        let mut missing = tx.clone();
        missing.is_accepted = false;
        assert!(verify_kcom_receipt_tx(selection, &missing).is_err());

        let output = &tx.outputs[0];
        let indexed = vec![(
            output.index as i32,
            output.amount as i64,
            hex::decode(&output.script_public_key).unwrap(),
        )];
        verify_kcom_indexed_outputs(tx, &indexed).unwrap();
        let mut changed_native = indexed.clone();
        changed_native[0].1 -= 1;
        assert!(verify_kcom_indexed_outputs(tx, &changed_native).is_err());
        let mut changed_script = indexed.clone();
        changed_script[0].2[0] ^= 1;
        assert!(verify_kcom_indexed_outputs(tx, &changed_script).is_err());
        let mut absent_vout = indexed;
        absent_vout[0].0 = 999;
        assert!(verify_kcom_indexed_outputs(tx, &absent_vout).is_err());
    }

    #[test]
    fn kcom_reconciliation_rejects_out_of_order_or_duplicate_receipts() {
        use super::*;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let main = root.join("docs/evidence/kcom-claim-tn10-main-full-20261030.json");
        let no_long = root.join("docs/evidence/kcom-claim-tn10-no-long-full-20261030.json");
        assert!(kcom_receipt_transactions(&[no_long.clone(), main.clone()]).is_err());
        assert!(kcom_receipt_transactions(&[main.clone(), main.clone()]).is_err());
        let mut receipt: Value = read_json(&main).unwrap();
        receipt["transactions"].as_array_mut().unwrap().swap(0, 1);
        let changed = std::env::temp_dir().join(format!("kcom-receipt-order-{}.json", std::process::id()));
        fs::write(&changed, serde_json::to_vec(&receipt).unwrap()).unwrap();
        let result = kcom_receipt_transactions(&[changed.clone()]);
        fs::remove_file(changed).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn owner_action_backfill_follow_flags_parse() {
        use clap::Parser;
        let cli = super::Cli::try_parse_from([
            "tn12-indexer",
            "kcc20-owner-action-backfill",
            "--database-url",
            "postgres://unused",
            "--follow",
            "--idle-ms=1000",
        ])
        .unwrap();
        let super::Command::Kcc20OwnerActionBackfill {
            follow, idle_ms, ..
        } = cli.command
        else {
            panic!("wrong command");
        };
        assert!(follow);
        assert_eq!(idle_ms, 1000);
    }

    #[test]
    fn tip_follow_source_switch_requires_both_settings() {
        use clap::Parser;
        let base = [
            "tn12-indexer",
            "tip-follow",
            "--database-url",
            "postgres://unused",
        ];
        assert!(super::Cli::try_parse_from(
            base.into_iter()
                .chain(["--next-rest", "https://next.example"])
        )
        .is_err());
        assert!(super::Cli::try_parse_from(
            base.into_iter().chain(["--switch-blue-score", "574910000"])
        )
        .is_err());
        let cli = super::Cli::try_parse_from(base.into_iter().chain([
            "--next-rest",
            "https://next.example",
            "--switch-blue-score",
            "574910000",
        ]))
        .unwrap();
        match cli.command {
            super::Command::TipFollow {
                next_rest,
                switch_blue_score,
                ..
            } => {
                assert_eq!(next_rest.as_deref(), Some("https://next.example"));
                assert_eq!(switch_blue_score, Some(574910000));
            }
            _ => panic!("expected tip-follow command"),
        }
    }

    #[test]
    fn source_overlap_identity_checks_blocks_and_acceptances() {
        use tn12_indexer_core::{RestTransaction, VirtualChainBlock};
        let block = VirtualChainBlock {
            hash: "block-a".to_string(),
            blue_score: 574910000,
            daa_score: 0,
            timestamp: 0,
            transactions: vec![RestTransaction {
                transaction_id: "tx-a".to_string(),
                is_accepted: true,
                ..Default::default()
            }],
        };
        assert!(super::verify_source_overlap_pages(&[], &[block.clone()], 574910000).is_err());
        assert!(
            super::verify_source_overlap_pages(&[block.clone()], &[block.clone()], 574910000)
                .is_ok()
        );
        let mut changed = block.clone();
        changed.hash = "block-b".to_string();
        assert!(
            super::verify_source_overlap_pages(&[block.clone()], &[changed], 574910000).is_err()
        );
        let mut changed = block.clone();
        changed.transactions[0].is_accepted = false;
        assert!(super::verify_source_overlap_pages(&[block], &[changed], 574910000).is_err());
    }

    #[test]
    fn action_prefix_retirement_requires_explicit_migration_flag() {
        use clap::Parser;
        for (flag, expected) in [(false, false), (true, true)] {
            let mut args = vec![
                "tn12-indexer",
                "migrate",
                "--database-url",
                "postgres://unused",
            ];
            if flag {
                args.push("--retire-action-prefix-indexes");
            }
            let cli = super::Cli::try_parse_from(args).unwrap();
            match cli.command {
                super::Command::Migrate {
                    retire_action_prefix_indexes,
                    ..
                } => assert_eq!(retire_action_prefix_indexes, expected),
                _ => panic!("expected migrate command"),
            }
        }
    }
    #[tokio::test]
    async fn guarded_probe_dry_run_does_not_connect() {
        let path = std::env::temp_dir().join(format!(
            "tn10-probe-dry-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            serde_json::to_vec(&vec![tn12_indexer_core::RestTransaction::default()]).unwrap(),
        )
        .unwrap();
        let result =
            super::run_guarded_generic_probe(path.clone(), "not-a-database-url".into(), false)
                .await;
        std::fs::remove_file(path).unwrap();
        result.expect("dry run must not parse or connect to the database URL");
    }
    #[test]
    fn guarded_probe_fixture_has_fixed_input_bounds() {
        use tn12_indexer_core::RestTransaction;
        assert!(super::parse_guarded_probe_fixture(b"[]").is_err());
        assert!(super::parse_guarded_probe_fixture(b"{}").is_err());
        assert!(super::parse_guarded_probe_fixture(&vec![b' '; 8 * 1024 * 1024 + 1]).is_err());
        for count in [1, 16, 17] {
            let fixture = serde_json::to_vec(&vec![RestTransaction::default(); count]).unwrap();
            assert_eq!(
                super::parse_guarded_probe_fixture(&fixture).is_ok(),
                count <= 16
            );
        }
    }

    #[test]
    fn guarded_probe_cli_requires_explicit_apply() {
        use clap::Parser;
        for apply in [false, true] {
            let mut args = vec![
                "tn12-indexer",
                "guarded-generic-probe",
                "--fixture",
                "input.json",
                "--database-url",
                "postgres://localhost/test",
            ];
            if apply {
                args.push("--apply");
            }
            let cli = super::Cli::try_parse_from(args).unwrap();
            match cli.command {
                super::Command::GuardedGenericProbe { apply: parsed, .. } => {
                    assert_eq!(parsed, apply)
                }
                _ => panic!("unexpected command"),
            }
        }
    }
    #[test]
    fn database_environment_values_are_hidden_in_help() {
        use clap::CommandFactory;
        fn check(command: &clap::Command) -> usize {
            let mut checked = 0;
            for arg in command.get_arguments() {
                if arg.get_env() == Some(std::ffi::OsStr::new("DATABASE_URL")) {
                    assert!(arg.is_hide_env_values_set(), "{}", command.get_name());
                    checked += 1;
                }
            }
            checked + command.get_subcommands().map(check).sum::<usize>()
        }
        assert!(check(&super::Cli::command()) > 0);
    }

    use super::*;

    #[derive(Default)]
    struct MockSource {
        by_address: BTreeMap<String, Vec<RpcUtxo>>,
    }

    impl UtxoSource for MockSource {
        fn get_utxos_by_address(&self, address: &str) -> Result<Vec<RpcUtxo>> {
            Ok(self.by_address.get(address).cloned().unwrap_or_default())
        }
    }

    fn config() -> IndexerConfig {
        IndexerConfig {
            rpc_url: "http://127.0.0.1:16210".to_string(),
            contracts: vec![WatchedContract {
                id: "vault".to_string(),
                name: "Time Lock Vault".to_string(),
                contract_address: "kaspatest:vault".to_string(),
                compiled_json_path: None,
                known_outpoint: None,
            }],
        }
    }

    fn rpc_utxo(txid: &str, vout: u32, amount_sompi: u64) -> RpcUtxo {
        RpcUtxo {
            address: None,
            outpoint: Outpoint {
                txid: txid.to_string(),
                vout,
            },
            amount_sompi,
            script_public_key: Some("script".to_string()),
            covenant_id: Some("covenant".to_string()),
        }
    }

    #[test]
    fn sync_adds_new_active_utxo() {
        let config = config();
        let mut source = MockSource::default();
        source
            .by_address
            .insert("kaspatest:vault".to_string(), vec![rpc_utxo("tx1", 0, 42)]);

        let mut store = IndexStore::default();
        sync_once(&config, &mut store, &source, 1000).unwrap();

        assert_eq!(store.contracts, config.contracts);
        assert_eq!(store.utxos.len(), 1);
        assert_eq!(store.utxos[0].status, UtxoStatus::Active);
        assert_eq!(store.utxos[0].amount_sompi, 42);
        assert_eq!(store.utxos[0].first_seen_at_ms, 1000);
        assert_eq!(store.utxos[0].last_seen_at_ms, 1000);
    }

    #[test]
    fn sync_marks_missing_active_utxo_spent() {
        let config = config();
        let mut source = MockSource::default();
        source
            .by_address
            .insert("kaspatest:vault".to_string(), vec![rpc_utxo("tx1", 0, 42)]);

        let mut store = IndexStore::default();
        sync_once(&config, &mut store, &source, 1000).unwrap();
        source
            .by_address
            .insert("kaspatest:vault".to_string(), Vec::new());
        sync_once(&config, &mut store, &source, 2000).unwrap();

        assert_eq!(store.utxos.len(), 1);
        assert_eq!(store.utxos[0].status, UtxoStatus::Spent);
        assert_eq!(store.utxos[0].first_seen_at_ms, 1000);
        assert_eq!(store.utxos[0].last_seen_at_ms, 2000);
    }

    #[test]
    fn sync_preserves_first_seen_for_still_active_utxo() {
        let config = config();
        let mut source = MockSource::default();
        source
            .by_address
            .insert("kaspatest:vault".to_string(), vec![rpc_utxo("tx1", 0, 42)]);

        let mut store = IndexStore::default();
        sync_once(&config, &mut store, &source, 1000).unwrap();
        source
            .by_address
            .insert("kaspatest:vault".to_string(), vec![rpc_utxo("tx1", 0, 50)]);
        sync_once(&config, &mut store, &source, 3000).unwrap();

        assert_eq!(store.utxos.len(), 1);
        assert_eq!(store.utxos[0].status, UtxoStatus::Active);
        assert_eq!(store.utxos[0].amount_sompi, 50);
        assert_eq!(store.utxos[0].first_seen_at_ms, 1000);
        assert_eq!(store.utxos[0].last_seen_at_ms, 3000);
    }

    #[test]
    fn parse_accepts_kaspa_rpc_shapes() {
        let value = json!({
            "result": {
                "entries": [
                    {
                        "outpoint": {
                            "transactionId": "abc",
                            "index": 2
                        },
                        "amount": "123",
                        "scriptPublicKey": {
                            "script": "deadbeef"
                        },
                        "covenant_id": "cid"
                    }
                ]
            }
        });

        let parsed = parse_utxo_entries(&value).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].outpoint.txid, "abc");
        assert_eq!(parsed[0].outpoint.vout, 2);
        assert_eq!(parsed[0].amount_sompi, 123);
        assert_eq!(parsed[0].script_public_key.as_deref(), Some("deadbeef"));
        assert_eq!(parsed[0].covenant_id.as_deref(), Some("cid"));
    }

    #[test]
    fn report_sums_active_amount_only() {
        let mut store = IndexStore {
            contracts: config().contracts,
            ..IndexStore::default()
        };
        store.utxos.push(IndexedCovenantUtxo {
            contract_id: "vault".to_string(),
            address: "kaspatest:vault".to_string(),
            outpoint: Outpoint {
                txid: "active".to_string(),
                vout: 0,
            },
            amount_sompi: 10,
            script_public_key: None,
            covenant_id: None,
            status: UtxoStatus::Active,
            first_seen_at_ms: 1,
            last_seen_at_ms: 1,
        });
        store.utxos.push(IndexedCovenantUtxo {
            contract_id: "vault".to_string(),
            address: "kaspatest:vault".to_string(),
            outpoint: Outpoint {
                txid: "spent".to_string(),
                vout: 0,
            },
            amount_sompi: 99,
            script_public_key: None,
            covenant_id: None,
            status: UtxoStatus::Spent,
            first_seen_at_ms: 1,
            last_seen_at_ms: 2,
        });

        let report = build_contract_report(&store, "vault").unwrap();
        assert_eq!(report.active_amount_sompi, 10);
        assert_eq!(report.active_utxos.len(), 1);
        assert_eq!(report.spent_utxos.len(), 1);
    }
}

#[cfg(test)]
mod projector_tests;

async fn run_repair_output_identities(rest: String, txids: Vec<String>, database_url: String, apply: bool) -> Result<()> {
    anyhow::ensure!(!txids.is_empty() && txids.len() <= 16, "repair requires 1..=16 exact transaction ids");
    let client = tn12_indexer_crawl::RestClient::new(rest)?;
    let writer = tn12_indexer_db::PgPersister::new(tn12_indexer_db::connect(&database_url).await?);
    let mut reports = Vec::new();
    for txid in txids {
        anyhow::ensure!(txid.len()==64 && txid.bytes().all(|b| b.is_ascii_hexdigit()), "invalid transaction id");
        let source = client.get_transaction_with_explicit_acceptance(&txid).await?;
        anyhow::ensure!(source.transaction_id.eq_ignore_ascii_case(&txid), "source returned different transaction");
        let mut ancestors = Vec::new();
        let mut pending: Vec<String> = source.inputs.iter().filter(|i| source.needs_input_identity(i))
            .map(|i| i.previous_outpoint_hash.clone()).collect();
        let mut seen = std::collections::BTreeSet::new();
        seen.insert(source.transaction_id.clone());
        let mut bytes = 0usize;
        while let Some(parent_id) = pending.pop() {
            if !seen.insert(parent_id.clone()) { continue; }
            anyhow::ensure!(ancestors.len()<256, "identity proof exceeds 256 ancestors");
            let parent = client.get_transaction_with_explicit_acceptance(&parent_id).await?;
            anyhow::ensure!(parent.transaction_id.eq_ignore_ascii_case(&parent_id), "proof source returned a different parent");
            bytes += serde_json::to_vec(&parent)?.len();
            anyhow::ensure!(bytes<=16*1024*1024, "identity proof exceeds 16 MiB");
            pending.extend(parent.inputs.iter().filter(|i| parent.needs_input_identity(i)).map(|i| i.previous_outpoint_hash.clone()));
            ancestors.push(parent);
        }
        reports.extend(writer.repair_output_identities(&source, &ancestors, apply).await?);
    }
    print_json(&serde_json::to_value(reports)?)
}
