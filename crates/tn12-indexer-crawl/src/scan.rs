//! Chain-wide scanner.
//!
//! The address-based [`AddressWatcher`](crate::watch) only sees covenants
//! reachable from explicit seed addresses (plus auto-discovered P2SH outputs
//! of seen txs). To track *every* TN12 covenant — including ones nobody on
//! our team knows about yet — we walk the chain by blue score, look at every
//! tx output, and fetch the full tx whenever any output is a P2SH covenant.
//!
//! Cursor: the latest fully-processed blue score is written into the
//! `indexer_state` table under a configured cursor key. On restart, the
//! scanner resumes there. If the key is missing (fresh DB or first run),
//! `--from-blue-score` (CLI flag, default 0) is used, or a live scanner can
//! start near the current tip with `--from-tip-window`.
//!
//! P2SH detection: an output's `verboseData.scriptPublicKeyType` is
//! `"scripthash"` on Kaspa's REST API for the standard P2SH program shape
//! (`OP_BLAKE2B <32 bytes> OP_EQUAL`). We trust that label and fall back to
//! a hex-prefix check so a missing verboseData doesn't lose us coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::rpc::rest::{BlockTxMetadata, METADATA_SEARCH_BATCH_SIZE};
use crate::rpc::RestClient;
use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use sqlx::Row;
use tn12_indexer_core::VirtualChainBlock;
use tn12_indexer_db::{is_transient_persist_error, Persister};
use tokio::task::JoinSet;

const SPARSE_WINDOW_STABILIZATION_RETRIES: u8 = 2;
const MAX_FULL_BLOCK_SCORE_REQUESTS: usize = 20;
const FULL_BLOCK_LOOKBACK_SCORES: u64 = 8;
const PREVOUT_LOOKUP_BATCH_SIZE: usize = 512;

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Starting blue score when no cursor is present in DB.
    pub from_blue_score: u64,
    /// Start at `tip - window` when no cursor is present. Intended for live-tip
    /// scanners that run beside historical catch-up scanners.
    pub from_tip_window: Option<u64>,
    /// How many blocks to request per REST page.
    pub batch_size: u32,
    /// Sleep when the chain tip is reached (no new blocks).
    pub idle_interval: Duration,
    /// Concurrent REST fetches used to hydrate missing payloads and
    /// covenant bindings omitted by the virtual-chain surface.
    pub hydrate_concurrency: usize,
    /// Concurrent REST fetches used to backfill missing P2SH prevouts.
    pub prevout_concurrency: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            from_blue_score: 0,
            from_tip_window: None,
            batch_size: 50,
            idle_interval: Duration::from_secs(15),
            hydrate_concurrency: 8,
            prevout_concurrency: 8,
        }
    }
}

#[derive(Debug, Clone)]
struct ChainAcceptance {
    hash: String,
    blue_score: u64,
    timestamp: u64,
}

#[derive(Debug, Clone)]
struct CandidateTx {
    tx: tn12_indexer_core::RestTransaction,
    acceptance: ChainAcceptance,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub(crate) struct AcceptanceKey {
    pub(crate) transaction_id: String,
    pub(crate) block_hash: String,
}

impl CandidateTx {
    fn acceptance_key(&self) -> AcceptanceKey {
        AcceptanceKey {
            transaction_id: self.tx.transaction_id.clone(),
            block_hash: self.acceptance.hash.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct PrevoutBackfill {
    order: usize,
    txid: String,
    vout: i32,
}

pub struct ChainScanner<P: Persister + ?Sized> {
    rpc: RestClient,
    persister: Arc<P>,
    config: ScannerConfig,
    bulk_block_hydration: bool,
    recent_acceptance_reconciliation: bool,
    // Retain the original proof across cancellation or uncertain COMMIT until
    // a fresh locked inspection classifies the outcome.
    pending_historical_acceptance:
        tokio::sync::Mutex<Option<Arc<tn12_indexer_db::persist::HistoricalAcceptanceMapProof>>>,
    /// Read/write the resume cursor in `indexer_state`.
    cursor: Box<dyn CursorStore + Send + Sync>,
}

#[async_trait::async_trait]
pub trait CursorStore {
    fn with_pool(&self,_pool:sqlx::PgPool) -> Result<Box<dyn CursorStore + Send + Sync>> {
        anyhow::bail!("cursor cannot use the owned event session")
    }
    async fn load(&self) -> Result<Option<u64>>;
    async fn save(&self, blue_score: u64, rest_database_blue_score: Option<u64>) -> Result<()>;
}

impl<P: Persister + ?Sized> ChainScanner<P> {
    pub fn new(
        rpc: RestClient,
        persister: Arc<P>,
        config: ScannerConfig,
        cursor: Box<dyn CursorStore + Send + Sync>,
    ) -> Self {
        Self {
            rpc,
            persister,
            config,
            bulk_block_hydration: false,
            recent_acceptance_reconciliation: false,
            pending_historical_acceptance: tokio::sync::Mutex::new(None),
            cursor,
        }
    }

    /// Hydrate metadata with bounded search and full-block requests before per-tx fallback.
    pub fn with_bulk_block_hydration(mut self) -> Self {
        self.bulk_block_hydration = true;
        self
    }

    pub fn with_recent_acceptance_reconciliation(mut self) -> Self {
        self.recent_acceptance_reconciliation = true;
        self
    }

    pub async fn run_forever(&self) -> Result<()> {
        let limit = self.config.batch_size.max(1) as u64;
        let mut blue_score = match self.cursor.load().await? {
            Some(bs) => bs,
            None => match self.config.from_tip_window {
                Some(window) => {
                    let tip = self.rpc.get_rest_database_blue_score().await?;
                    let start = tip.saturating_sub(window);
                    tracing::info!(
                        target: "scanner",
                        "no cursor found; starting from REST DB tip window: rest_database_blue_score={tip} window={window} start={start}"
                    );
                    start
                }
                None => self.config.from_blue_score,
            },
        };
        // Align cursor to a multiple of limit (`/virtual-chain` contract).
        blue_score = (blue_score / limit) * limit;
        let mut sparse_window_retries = 0u8;
        tracing::info!(target: "scanner", "starting at blueScore={blue_score} (aligned to limit={limit})");
        loop {
            match self.process_batch(blue_score).await {
                Ok(Some(s)) => {
                    if s.txs_persisted > 0 || s.blocks_seen > 0 {
                        tracing::info!(
                            target: "scanner",
                            "batch: from={blue_score} blocks={} p2sh_candidates={} hydrated={} prevouts_backfilled={} persisted={} max_blue_score={}",
                            s.blocks_seen,
                            s.p2sh_candidates,
                            s.txs_hydrated,
                            s.prevouts_backfilled,
                            s.txs_persisted,
                            s.max_blue_score,
                        );
                    }
                    if should_advance_window(blue_score, limit, s.max_blue_score) {
                        blue_score += limit;
                        sparse_window_retries = 0;
                        let rest_database_blue_score = match self
                            .rpc
                            .get_rest_database_blue_score()
                            .await
                        {
                            Ok(tip) => Some(tip),
                            Err(error) => {
                                tracing::warn!(
                                    target: "scanner",
                                    "failed to sample REST DB tip after completed window: {error:#}"
                                );
                                None
                            }
                        };
                        self.cursor
                            .save(blue_score, rest_database_blue_score)
                            .await?;
                    } else {
                        let rest_database_blue_score =
                            self.rpc.get_rest_database_blue_score().await?;
                        if should_advance_window(blue_score, limit, rest_database_blue_score) {
                            if should_retry_sparse_window(
                                sparse_window_retries,
                                SPARSE_WINDOW_STABILIZATION_RETRIES,
                                blue_score,
                                limit,
                                rest_database_blue_score,
                            ) {
                                sparse_window_retries += 1;
                                tracing::info!(
                                    target: "scanner",
                                    "sparse partial window: from={blue_score} max_blue_score={} rest_database_blue_score={} window_end={}; retrying {}/{} after idle for REST stabilization",
                                    s.max_blue_score,
                                    rest_database_blue_score,
                                    window_end(blue_score, limit),
                                    sparse_window_retries,
                                    SPARSE_WINDOW_STABILIZATION_RETRIES,
                                );
                                tokio::time::sleep(self.config.idle_interval).await;
                                continue;
                            }
                            tracing::info!(
                                target: "scanner",
                                "sparse partial window: from={blue_score} max_blue_score={} rest_database_blue_score={} window_end={}; advancing",
                                s.max_blue_score,
                                rest_database_blue_score,
                                window_end(blue_score, limit),
                            );
                            blue_score += limit;
                            sparse_window_retries = 0;
                            self.cursor
                                .save(blue_score, Some(rest_database_blue_score))
                                .await?;
                        } else {
                            tracing::info!(
                                target: "scanner",
                                "REST DB window incomplete: from={blue_score} max_blue_score={} rest_database_blue_score={} window_end={}; retrying after idle",
                                s.max_blue_score,
                                rest_database_blue_score,
                                window_end(blue_score, limit),
                            );
                            tokio::time::sleep(self.config.idle_interval).await;
                        }
                    }
                }
                Ok(None) => {
                    let rest_database_blue_score = self.rpc.get_rest_database_blue_score().await?;
                    if should_advance_window(blue_score, limit, rest_database_blue_score) {
                        if should_retry_sparse_window(
                            sparse_window_retries,
                            SPARSE_WINDOW_STABILIZATION_RETRIES,
                            blue_score,
                            limit,
                            rest_database_blue_score,
                        ) {
                            sparse_window_retries += 1;
                            tracing::info!(
                                target: "scanner",
                                "empty sparse window: from={blue_score} rest_database_blue_score={} window_end={}; retrying {}/{} after idle for REST stabilization",
                                rest_database_blue_score,
                                window_end(blue_score, limit),
                                sparse_window_retries,
                                SPARSE_WINDOW_STABILIZATION_RETRIES,
                            );
                            tokio::time::sleep(self.config.idle_interval).await;
                            continue;
                        }
                        tracing::info!(
                            target: "scanner",
                            "empty sparse window: from={blue_score} rest_database_blue_score={} window_end={}; advancing",
                            rest_database_blue_score,
                            window_end(blue_score, limit),
                        );
                        blue_score += limit;
                        sparse_window_retries = 0;
                        self.cursor
                            .save(blue_score, Some(rest_database_blue_score))
                            .await?;
                    } else {
                        tracing::info!(
                            target: "scanner",
                            "REST DB has not indexed requested window yet: from={blue_score} rest_database_blue_score={} window_end={}; retrying after idle",
                            rest_database_blue_score,
                            window_end(blue_score, limit),
                        );
                        tokio::time::sleep(self.config.idle_interval).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(target: "scanner", "batch error at blueScore={blue_score}: {e:#}");
                    tokio::time::sleep(self.config.idle_interval).await;
                }
            }
        }
    }

    pub(crate) async fn rest_database_tip(&self) -> Result<u64> {
        self.rpc.get_rest_database_blue_score().await
    }

    /// Replay exactly one aligned REST window without changing a progress cursor.
    /// Used to repair previously recorded acceptances through normal persistence.
    pub async fn replay_window(&self, blue_score_gte: u64) -> Result<u64> {
        let width = self.config.batch_size as u64;
        anyhow::ensure!(
            (1..=100).contains(&width),
            "replay window width must be 1..=100"
        );
        anyhow::ensure!(
            blue_score_gte % width == 0,
            "replay window must be aligned to its width"
        );
        self.rpc.ensure_current_database_synced().await?;
        let prepared = self
            .prepare_batch(blue_score_gte)
            .await?
            .context("REST returned no blocks for requested replay window")?;
        self.rpc.ensure_current_database_synced().await?;
        let evidence=serde_json::json!({
            "windowStart":blue_score_gte,"width":width,
            "blocks":prepared.block_hashes(),
            "acceptances":prepared.acceptance_coordinates(),
            "transactions":prepared.recovery_bodies().collect::<Vec<_>>()
        });
        let stats = match self.persist_prepared(prepared).await {
            Ok(result)=>result.stats,
            Err(error)=>{
                if let Some(missing)=error.downcast_ref::<crate::rpc::rest::MissingTransaction>() {
                    let retained=MissingHistoricalWindow {
                        missing_txid:missing.txid.clone(),endpoint:missing.endpoint.clone(),evidence,
                    };
                    return Err(error.context(retained));
                }
                return Err(error);
            }
        };
        tracing::info!(
            blue_score = blue_score_gte,
            batch_size = width,
            blocks = stats.blocks_seen,
            candidates = stats.p2sh_candidates,
            persisted = stats.txs_persisted,
            "completed bounded historical replay without changing cursors"
        );
        Ok(stats.txs_persisted)
    }

    async fn process_batch(&self, blue_score_gte: u64) -> Result<Option<BatchStats>> {
        let Some(prepared) = self.prepare_batch(blue_score_gte).await? else {
            return Ok(None);
        };
        let outcome = self.persist_prepared(prepared).await?;
        Ok(Some(outcome.stats))
    }

    pub(crate) async fn prepare_batch(&self, blue_score_gte: u64) -> Result<Option<PreparedBatch>> {
        let blocks = self
            .rpc
            .get_virtual_chain(blue_score_gte, self.config.batch_size.max(1))
            .await?;
        Ok(self.prepare_blocks(blocks))
    }

    /// Recovery journals can include plain funding parents. Preserve the normal
    /// covenant filter, but replay every explicitly retained transaction too.
    pub(crate) async fn prepare_recovery_batch(
        &self,
        start: u64,
        retained: &[tn12_indexer_core::RestTransaction],
    ) -> Result<Option<PreparedBatch>> {
        let required = retained.iter().map(|tx| tx.transaction_id.clone()).collect();
        let blocks = self.rpc.get_virtual_chain(start, self.config.batch_size.max(1)).await?;
        Ok(self.prepare_blocks_requiring(blocks, &required))
    }

    pub(crate) fn prepare_blocks(&self, blocks: Vec<VirtualChainBlock>) -> Option<PreparedBatch> {
        self.prepare_blocks_requiring(blocks, &BTreeSet::new())
    }

    fn prepare_blocks_requiring(&self, blocks: Vec<VirtualChainBlock>, required: &BTreeSet<String>) -> Option<PreparedBatch> {
        if blocks.is_empty() {
            return None;
        }

        let mut stats = BatchStats {
            blocks_seen: blocks.len() as u64,
            ..Default::default()
        };

        let mut candidates = Vec::new();
        let mut block_hashes = BTreeSet::new();
        for block in &blocks {
            stats.max_blue_score = stats.max_blue_score.max(block.blue_score);
            block_hashes.insert(block.hash.clone());

            for tx in &block.transactions {
                if !has_p2sh_output(tx) && !any_p2sh_input(tx) && !required.contains(&tx.transaction_id) {
                    continue;
                }
                stats.p2sh_candidates += 1;
                let mut tx_for_persist = tx.clone();
                tx_for_persist.normalize_missing_output_indexes();
                synthesize_acceptance(&mut tx_for_persist, block);
                candidates.push(CandidateTx {
                    tx: tx_for_persist,
                    acceptance: ChainAcceptance {
                        hash: block.hash.clone(),
                        blue_score: block.blue_score,
                        timestamp: block.timestamp,
                    },
                });
            }
        }

        Some(PreparedBatch {
            dependencies: None,
            stats,
            candidates,
            block_hashes,
        })
    }

    pub(crate) async fn persist_prepared(&self, prepared: PreparedBatch) -> Result<PersistedBatch> {
        self.persist_prepared_with_metadata(prepared, None).await
    }

    /// Source-only hydration can run ahead of the ordered historical writer.
    /// The caller still reconciles the window and commits it in source order.
    pub(crate) async fn prehydrate_prepared_metadata(&self, prepared: &mut PreparedBatch) -> u128 {
        let started = Instant::now();
        self.hydrate_missing_p2sh_metadata(&mut prepared.candidates, &mut prepared.stats)
            .await;
        started.elapsed().as_millis()
    }

    /// Warm identity pages only. All results are discarded; acceptance and
    /// prevouts are still revalidated under the ordered writer's lock.
    pub(crate) async fn prefetch_prepared_identities(&self, prepared: &PreparedBatch) {
        let mut ids = Vec::with_capacity(64);
        for candidate in &prepared.candidates {
            for id in std::iter::once(&candidate.tx.transaction_id).chain(
                candidate.tx.inputs.iter().map(|input| &input.previous_outpoint_hash),
            ) {
                ids.push(id.clone());
                if ids.len() == 64 {
                    match self.persister.prefetch_identities(&ids).await {
                        Ok(true) => {}
                        Ok(false) => return,
                        Err(error) => {
                            tracing::debug!(%error, "optional identity prefetch failed; ordered validation unchanged");
                            return;
                        }
                    }
                    ids.clear();
                }
            }
        }
        if !ids.is_empty() {
            if let Err(error) = self.persister.prefetch_identities(&ids).await {
                tracing::debug!(%error, "optional identity prefetch failed; ordered validation unchanged");
            }
        }
    }

    pub(crate) async fn prepare_recovery_dependencies(&self, prepared: &mut PreparedBatch) -> Result<Vec<tn12_indexer_core::RestTransaction>> {
        self.hydrate_missing_p2sh_metadata(&mut prepared.candidates, &mut prepared.stats).await;
        let parents = self.fetch_missing_p2sh_prevouts(&prepared.candidates, &mut prepared.stats).await?;
        prepared.dependencies = Some(parents.clone());
        Ok(parents)
    }

    /// Find missing P2SH parents one source page at a time. The paged recovery
    /// frontier owns the recursive walk, so this check never accumulates the
    /// entire dependency graph in scanner memory.
    pub(crate) async fn missing_recovery_p2sh_parent_txids(
        &self,
        bodies: &[tn12_indexer_core::RestTransaction],
    ) -> Result<Vec<String>> {
        let in_page: BTreeSet<(String, i32)> = bodies
            .iter()
            .flat_map(|body| {
                body.outputs.iter().filter_map(|out| {
                    i32::try_from(out.index)
                        .ok()
                        .map(|index| (body.transaction_id.to_ascii_lowercase(), index))
                })
            })
            .collect();
        let mut external = BTreeSet::new();
        for body in bodies.iter().filter(|body| body.is_accepted) {
            for input in &body.inputs {
                if !input_spends_p2sh(input) && !body.needs_input_identity(input) {
                    continue;
                }
                let id = input.previous_outpoint_hash.to_ascii_lowercase();
                anyhow::ensure!(
                    hex::decode(&id).is_ok_and(|bytes| bytes.len() == 32),
                    "paged P2SH parent has invalid transaction ID"
                );
                let vout: i32 = input
                    .previous_outpoint_index
                    .parse()
                    .context("paged P2SH parent has invalid output index")?;
                anyhow::ensure!(vout >= 0, "paged P2SH parent has negative output index");
                if !in_page.contains(&(id.clone(), vout)) {
                    external.insert((id, vout));
                }
            }
        }
        let external: Vec<_> = external.into_iter().collect();
        let mut missing = BTreeSet::new();
        for page in external.chunks(128) {
            let existing = self.persister.existing_utxos(page).await?;
            for (id, vout) in page {
                if !existing.contains(&(id.clone(), *vout)) {
                    missing.insert(id.clone());
                }
            }
        }
        Ok(missing.into_iter().collect())
    }

    pub(crate) async fn persist_prepared_with_metadata(
        &self,
        mut prepared: PreparedBatch,
        prefetched_hydrate_ms: Option<u128>,
    ) -> Result<PersistedBatch> {
        let started = Instant::now();
        let mut stats = prepared.stats;
        let candidate_keys: BTreeSet<AcceptanceKey> = prepared.acceptance_keys();

        let local_hydrate_ms = if prefetched_hydrate_ms.is_none() && prepared.dependencies.is_none() {
            self.hydrate_missing_p2sh_metadata(&mut prepared.candidates, &mut stats)
                .await;
            started.elapsed().as_millis()
        } else {
            0
        };
        let hydrate_ms = prefetched_hydrate_ms.unwrap_or(local_hydrate_ms);
        let backfilled_prevouts = match prepared.dependencies.take() {
            Some(parents) => parents,
            None => self.fetch_missing_p2sh_prevouts(&prepared.candidates, &mut stats).await?,
        };
        let before_persist_ms = started.elapsed().as_millis();

        let mut txs_for_persist = backfilled_prevouts;
        txs_for_persist.extend(
            prepared
                .candidates
                .iter()
                .map(|candidate| candidate.tx.clone()),
        );
        // Newly fetched parents also prove whether an unknown input is funding
        // or P2SH. Supply that evidence before any identity is inferred.
        let parents: std::collections::HashMap<_,_> = txs_for_persist.iter()
            .map(|tx| {
                let mut parent = tx.clone();
                for output in &mut parent.outputs {
                    if output.transaction_id.is_empty() { output.transaction_id=parent.transaction_id.clone(); }
                }
                (parent.transaction_id.clone(),parent)
            }).collect();
        for tx in &mut txs_for_persist {
            for input in &mut tx.inputs {
                if let Some(parent) = parents.get(&input.previous_outpoint_hash) {
                    let output = crate::cached_prevout::compatible(input,parent)
                        .ok_or(crate::recovery_policy::RecoveryBlocked("parent_metadata_conflict"))?;
                    crate::cached_prevout::hydrate(input,output);
                }
            }
        }
        let txs_for_persist =
            tn12_indexer_db::persist::transactions_in_dependency_order(&txs_for_persist)?;
        let candidate_keys_by_txid: std::collections::BTreeMap<String, AcceptanceKey> = prepared
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.tx.transaction_id.clone(),
                    candidate.acceptance_key(),
                )
            })
            .collect();
        let mut persisted_acceptances = BTreeSet::new();

        {
            let mut pending = self.pending_historical_acceptance.lock().await;
            if let Some(proof) = pending.as_ref() {
                self.persister
                    .classify_historical_acceptance_outcome(proof)
                    .await?;
                *pending = None;
            }
        }
        if !txs_for_persist.is_empty() {
            let mut batch_result = if let Some(writer)=self.persister.paged_recovery_writer() {
                crate::rest_replay_fence::for_transactions(writer,&self.rpc,&txs_for_persist).await?
                    .persist_batch(&txs_for_persist).await
            } else { self.persister.persist_batch(&txs_for_persist).await };
            if let Some(conflict) = batch_result.as_ref().err().and_then(|error| {
                error.downcast_ref::<tn12_indexer_db::persist::AcceptanceConflict>()
            }) {
                let verified = if self.recent_acceptance_reconciliation {
                    self.rpc
                        .verify_recent_canonical_block_replacement(conflict)
                        .await
                } else {
                    self.rpc.verify_canonical_block_replacement(conflict).await
                };
                let reconciled=match verified {
                    Ok(proof)=>if let Some(writer)=self.persister.paged_recovery_writer() {
                        crate::rest_replay_fence::for_replacement(writer,&self.rpc,&proof).await?
                            .reconcile_accepting_block(&proof).await?
                    }else{self.persister.reconcile_accepting_block(&proof).await?},
                    Err(error) if error.downcast_ref::<tn12_indexer_db::persist::NonEquivalentBlockEvidence>().is_some()=>{
                        let mut pending=self.pending_historical_acceptance.lock().await;
                        if let Some(proof)=pending.as_ref() {
                            self.persister.classify_historical_acceptance_outcome(proof).await?;
                            *pending=None;
                        }
                        let cohort=self.persister.historical_acceptance_cohort(&[hex::decode(&conflict.persisted_hash)?]).await?;
                        let proof=Arc::new(self.rpc.verify_historical_acceptance_map(cohort,conflict).await?);
                        let guarded=if let Some(writer)=self.persister.paged_recovery_writer() {
                            Some(crate::rest_replay_fence::for_acceptance_map(writer,&self.rpc,&proof).await?)
                        }else{None};
                        *pending=Some(proof.clone());
                        let result=if let Some(writer)=guarded {
                            writer.reconcile_historical_acceptance_map(&proof).await
                        }else{self.persister.reconcile_historical_acceptance_map(&proof).await};
                        if !result.as_ref().err().is_some_and(|error|error.downcast_ref::<tn12_indexer_db::persist::HistoricalAcceptanceOutcomeUnknown>().is_some()) {
                            *pending=None;
                        }
                        result?
                    }
                    Err(error)=>return Err(error).with_context(||format!("verify historical accepting block replacement (transaction {}, old {}, new {}); retaining window for retry",conflict.transaction_id,conflict.persisted_hash,conflict.incoming_hash)),
                };
                tracing::info!(target: "scanner", transaction_id = %conflict.transaction_id,
                    old_block = %conflict.persisted_hash, new_block = %conflict.incoming_hash,
                    ?reconciled, "reconciled verified canonical acceptance references");
                // At most one repair/retry per attempt. A second conflict keeps
                // the window pending rather than expanding into serial fanout.
                batch_result = if let Some(writer)=self.persister.paged_recovery_writer() {
                    crate::rest_replay_fence::for_transactions(writer,&self.rpc,&txs_for_persist).await?
                        .persist_batch(&txs_for_persist).await
                }else{self.persister.persist_batch(&txs_for_persist).await};
            }
            match batch_result {
                Ok(_) => {
                    stats.txs_persisted += prepared.candidates.len() as u64;
                    persisted_acceptances = candidate_keys;
                }
                Err(e) => {
                    if e.is::<tn12_indexer_db::persist::StaleRestAcceptance>() {
                        return Err(e).context("source changed; retain the whole window for refetch");
                    }
                    if e.downcast_ref::<tn12_indexer_db::persist::HistoricalAcceptanceMapGuard>()
                        .is_some()
                    {
                        return Err(e)
                            .context("historical acceptance recovery required; retaining window");
                    }
                    if e.downcast_ref::<tn12_indexer_db::persist::AcceptanceEvidenceConflict>()
                        .is_some()
                    {
                        return Err(e).context("source transaction evidence conflicts; retaining window for investigation");
                    }
                    if e.downcast_ref::<tn12_indexer_db::persist::AcceptanceConflict>()
                        .is_some()
                    {
                        return Err(e).context(
                            "accepting block conflict remains; retaining window for retry",
                        );
                    }
                    if e.downcast_ref::<tn12_indexer_db::persist::GenericWriteOutcomeUnknown>()
                        .is_some()
                    {
                        return Err(e).context("generic write outcome requires whole-window reconciliation; refusing individual fallback");
                    }
                    if is_transient_persist_error(&e) {
                        tracing::warn!(
                            target: "scanner",
                            "batch persist hit transient DB pressure; retrying same window after idle without individual tx fanout: {e:#}"
                        );
                        return Err(e);
                    }
                    tracing::warn!(target: "scanner", "batch persist failed: {e:#}; retrying txs individually");
                    let candidate_txids: BTreeSet<&str> = prepared
                        .candidates
                        .iter()
                        .map(|candidate| candidate.tx.transaction_id.as_str())
                        .collect();
                    for tx in txs_for_persist.iter() {
                        let result = if let Some(writer) = self.persister.paged_recovery_writer() {
                            crate::rest_replay_fence::for_transactions(writer, &self.rpc, std::slice::from_ref(tx)).await?
                                .persist_tx(tx).await
                        } else { self.persister.persist_tx(tx).await };
                        match result {
                            Ok(_) => {
                                if candidate_txids.contains(tx.transaction_id.as_str()) {
                                    stats.txs_persisted += 1;
                                    if let Some(key) =
                                        candidate_keys_by_txid.get(tx.transaction_id.as_str())
                                    {
                                        persisted_acceptances.insert(key.clone());
                                    }
                                }
                            }
                            Err(e) => {
                                return Err(e).with_context(|| {
                                    format!(
                                        "persist {} failed; retaining window for retry",
                                        tx.transaction_id
                                    )
                                });
                            }
                        }
                    }
                }
            }
        }
        let elapsed_ms = started.elapsed().as_millis();
        if elapsed_ms >= 5_000 {
            tracing::info!(
                target: "scanner",
                elapsed_ms,
                hydrate_ms,
                prevout_ms = before_persist_ms.saturating_sub(local_hydrate_ms),
                sql_persist_ms = elapsed_ms - before_persist_ms,
                p2sh_candidates = stats.p2sh_candidates,
                hydrated_txs = stats.txs_hydrated,
                block_bodies_covered = stats.block_bodies_covered,
                prevouts_backfilled = stats.prevouts_backfilled,
                persisted_txs = stats.txs_persisted,
                "slow P2SH persistence"
            );
        }
        Ok(PersistedBatch {
            stats,
            persisted_acceptances,
            hydrate_ms,
            prevout_ms: before_persist_ms.saturating_sub(local_hydrate_ms),
            sql_persist_ms: elapsed_ms.saturating_sub(before_persist_ms),
        })
    }

    async fn hydrate_missing_p2sh_metadata(
        &self,
        candidates: &mut [CandidateTx],
        stats: &mut BatchStats,
    ) {
        let pending: Vec<(usize, String)> = candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| needs_p2sh_metadata_hydration(&candidate.tx))
            .map(|(idx, candidate)| (idx, candidate.tx.transaction_id.clone()))
            .collect();

        // Search once when individual lookups would need multiple concurrency waves.
        let covered_by_bulk = if self.bulk_block_hydration
            && pending.len() > self.config.hydrate_concurrency.max(1)
        {
            let mut covered = self.hydrate_from_search(candidates, &pending, stats).await;
            let remaining: Vec<_> = pending
                .iter()
                .filter(|(idx, _)| !covered.contains(idx))
                .cloned()
                .collect();
            if !remaining.is_empty() {
                covered.extend(
                    self.hydrate_from_full_blocks(candidates, &remaining, stats)
                        .await,
                );
            }
            covered
        } else {
            BTreeSet::new()
        };
        let pending: Vec<_> = pending
            .into_iter()
            .filter(|(idx, _)| !covered_by_bulk.contains(idx))
            .collect();

        for chunk in pending.chunks(self.config.hydrate_concurrency.max(1)) {
            let mut tasks = JoinSet::new();
            for (idx, txid) in chunk.iter().cloned() {
                let rpc = self.rpc.clone();
                tasks.spawn(async move {
                    let fetched = rpc.get_transaction(&txid).await;
                    (idx, txid, fetched)
                });
            }

            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((idx, _, Ok(full_tx))) => {
                        if merge_hydrated_p2sh_metadata(&mut candidates[idx].tx, &full_tx) {
                            stats.txs_hydrated += 1;
                        }
                    }
                    Ok((_, txid, Err(e))) => tracing::warn!(
                        target: "scanner",
                        "P2SH metadata hydration for {txid} failed: {e:#}"
                    ),
                    Err(e) => {
                        tracing::warn!(target: "scanner", "P2SH metadata hydration task failed: {e:#}")
                    }
                }
            }
        }
    }

    async fn hydrate_from_search(
        &self,
        candidates: &mut [CandidateTx],
        pending: &[(usize, String)],
        stats: &mut BatchStats,
    ) -> BTreeSet<usize> {
        let mut by_txid: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (idx, txid) in pending {
            by_txid.entry(txid.clone()).or_default().push(*idx);
        }
        let txids: Vec<_> = by_txid.keys().cloned().collect();
        let mut covered = BTreeSet::new();
        // Up to four requests at a time, each capped at 1,000 IDs and 16 MiB.
        // Only metadata fetches overlap; candidates retain acceptance order.
        let concurrency = self.config.hydrate_concurrency.clamp(1, 4);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        'search: for group in txids.chunks(METADATA_SEARCH_BATCH_SIZE * concurrency) {
            let mut tasks = JoinSet::new();
            for chunk in group.chunks(METADATA_SEARCH_BATCH_SIZE) {
                let rpc = self.rpc.clone();
                let chunk = chunk.to_vec();
                tasks.spawn(async move { rpc.search_transaction_metadata(&chunk).await });
            }
            loop {
                let joined = match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                    Ok(Some(joined)) => joined,
                    Ok(None) => break,
                    Err(_) => {
                        tracing::warn!(target: "scanner", "transaction metadata search exceeded 15s budget; using full blocks");
                        break 'search;
                    }
                };
                match joined {
                    Ok(Ok(metadata)) => {
                        for metadata in metadata {
                            let Some(indices) = by_txid.get(&metadata.transaction_id) else {
                                continue;
                            };
                            for idx in indices {
                                if let Some(changed) =
                                    merge_full_block_metadata(&mut candidates[*idx].tx, &metadata)
                                {
                                    covered.insert(*idx);
                                    if changed {
                                        stats.txs_hydrated += 1;
                                    }
                                }
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(target: "scanner", "transaction metadata search failed; using full blocks: {error:#}");
                        break 'search;
                    }
                    Err(error) => {
                        tracing::warn!(target: "scanner", "transaction metadata search task failed; using full blocks: {error:#}");
                        break 'search;
                    }
                }
            }
        }
        tracing::info!(target: "scanner", requested = pending.len(), covered = covered.len(), "bulk transaction metadata hydration");
        covered
    }

    async fn hydrate_from_full_blocks(
        &self,
        candidates: &mut [CandidateTx],
        pending: &[(usize, String)],
        stats: &mut BatchStats,
    ) -> BTreeSet<usize> {
        let mut by_txid: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut min_score = u64::MAX;
        let mut max_score = 0;
        let mut acceptance_scores = BTreeSet::new();
        for (idx, txid) in pending {
            by_txid.entry(txid.clone()).or_default().push(*idx);
            let score = candidates[*idx].acceptance.blue_score;
            min_score = min_score.min(score);
            max_score = max_score.max(score);
            acceptance_scores.insert(score);
        }
        if min_score == u64::MAX {
            return BTreeSet::new();
        }

        // Accepted transactions can originate in red DAG blocks before their
        // accepting chain block. Search the current scores first, then a
        // bounded lookback. Any unmatched transaction uses the normal lookup.
        let mut scores: Vec<u64> = if max_score.saturating_sub(min_score)
            < MAX_FULL_BLOCK_SCORE_REQUESTS as u64 - FULL_BLOCK_LOOKBACK_SCORES
        {
            (min_score..=max_score).collect()
        } else {
            acceptance_scores.into_iter().collect()
        };
        scores.truncate(MAX_FULL_BLOCK_SCORE_REQUESTS - FULL_BLOCK_LOOKBACK_SCORES as usize);
        scores.extend((min_score.saturating_sub(FULL_BLOCK_LOOKBACK_SCORES)..min_score).rev());
        let wanted_txids: Arc<BTreeSet<String>> = Arc::new(by_txid.keys().cloned().collect());
        let mut covered = BTreeSet::new();
        // Fetch a bounded number of block bodies in parallel, but apply them
        // in score order so repeated txids keep the same metadata precedence.
        let concurrency = self.config.hydrate_concurrency.clamp(1, 4);
        let mut fetched = stream::iter(scores.into_iter().map(|score| {
            let rpc = self.rpc.clone();
            let wanted_txids = wanted_txids.clone();
            async move {
                (
                    score,
                    rpc.get_block_transaction_metadata(score, &wanted_txids)
                        .await,
                )
            }
        }))
        .buffered(concurrency);
        while let Some((score, result)) = fetched.next().await {
            match result {
                Ok(metadata) => {
                    for metadata in metadata {
                        let Some(indices) = by_txid.get(&metadata.transaction_id) else {
                            continue;
                        };
                        for idx in indices {
                            if covered.contains(idx) {
                                continue;
                            }
                            if let Some(changed) =
                                merge_full_block_metadata(&mut candidates[*idx].tx, &metadata)
                            {
                                covered.insert(*idx);
                                stats.block_bodies_covered += 1;
                                if changed {
                                    stats.txs_hydrated += 1;
                                }
                            }
                        }
                    }
                }
                Err(error) => tracing::warn!(
                    target: "scanner",
                    "full block hydration at blue score {score} failed; falling back to transaction lookups: {error:#}"
                ),
            }
            if covered.len() == pending.len() {
                break;
            }
        }
        covered
    }

    async fn fetch_missing_p2sh_prevouts(
        &self, candidates: &[CandidateTx], stats: &mut BatchStats,
    ) -> Result<Vec<tn12_indexer_core::RestTransaction>> {
        let budget = Arc::new(crate::rpc::rest::ParentResponseBudget::default());
        let mut frontier = candidates.to_vec();
        let mut fetched = Vec::new();
        let mut seen = BTreeSet::new();
        let mut bytes = 0usize;
        for _ in 0..32 {
            let page = self.fetch_prevout_page(&frontier, stats, budget.clone()).await?;
            if page.is_empty() { return Ok(fetched); }
            frontier.clear();
            for tx in page {
                if !seen.insert(tx.transaction_id.clone()) { continue; }
                bytes += serde_json::to_vec(&tx)?.len();
                crate::recovery_policy::check_capacity("dependency_count", fetched.len() + 1, 256)?;
                crate::recovery_policy::check_capacity("dependency_bytes", bytes, 16 * 1024 * 1024)?;
                frontier.push(CandidateTx {
                    acceptance: ChainAcceptance {
                        hash: tx.accepting_block_hash.clone().context("parent acceptance missing")?,
                        blue_score: tx.accepting_block_blue_score.context("parent score missing")?,
                        timestamp: tx.accepting_block_time.context("parent timestamp missing")?,
                    }, tx:tx.clone(),
                });
                fetched.push(tx);
            }
            if frontier.is_empty() { return Ok(fetched); }
        }
        Err(crate::recovery_policy::RecoveryCapacity { dimension: "dependency_depth", observed: 33, limit: 32 }.into())
    }

    async fn fetch_prevout_page(
        &self,
        candidates: &[CandidateTx],
        stats: &mut BatchStats,
        budget: Arc<crate::rpc::rest::ParentResponseBudget>,
    ) -> Result<Vec<tn12_indexer_core::RestTransaction>> {
        let lookups = collect_external_p2sh_prevouts(candidates);
        let outpoints: Vec<_> = lookups
            .iter()
            .map(|lookup| (lookup.txid.clone(), lookup.vout))
            .collect();
        let mut existing = std::collections::HashSet::new();
        let mut lookup_batches = 0;
        for chunk in outpoints.chunks(PREVOUT_LOOKUP_BATCH_SIZE) {
            existing.extend(self.persister.existing_utxos(chunk).await?);
            lookup_batches += 1;
        }
        let missing: Vec<_> = lookups
            .into_iter()
            .filter(|lookup| !existing.contains(&(lookup.txid.clone(), lookup.vout)))
            .collect();
        // One REST transaction contains every output. Keep the per-outpoint DB
        // check above, then fetch each missing creator transaction only once.
        let mut scheduled_txids = BTreeSet::new();
        let pending: Vec<_> = missing
            .iter()
            .filter(|lookup| scheduled_txids.insert(lookup.txid.clone()))
            .cloned()
            .collect();
        if outpoints.len() >= PREVOUT_LOOKUP_BATCH_SIZE {
            tracing::info!(
                target: "scanner",
                requested_prevouts = outpoints.len(),
                existing_prevouts = existing.len(),
                rest_backfill_prevouts = missing.len(),
                rest_backfill_transactions = pending.len(),
                lookup_batches,
                "batched P2SH prevout presence lookup"
            );
        }

        crate::recovery_policy::check_capacity("dependency_page_count", pending.len(), 256)?;
        let mut page_bytes = 0usize;
        let mut backfilled = Vec::new();
        for chunk in pending.chunks(self.config.prevout_concurrency.clamp(1, 8)) {
            let mut tasks = JoinSet::new();
            for backfill in chunk.iter().cloned() {
                let rpc = self.rpc.clone();
                let budget = budget.clone();
                tasks.spawn(async move {
                    let tx = rpc.get_transaction_with_budget(&backfill.txid, &budget).await;
                    (backfill, tx)
                });
            }

            let mut fetched = Vec::new();
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((backfill, Ok(tx))) => {
                        page_bytes += serde_json::to_vec(&tx)?.len();
                        crate::recovery_policy::check_capacity("dependency_page_bytes", page_bytes, 16 * 1024 * 1024)?;
                        anyhow::ensure!(tx.transaction_id.eq_ignore_ascii_case(&backfill.txid)
                            && tx.outputs.iter().any(|o| o.index==backfill.vout as u64),
                            crate::recovery_policy::RecoveryBlocked("parent_output_mismatch"));
                        if !tx.is_accepted {
                            return Err(crate::live_supervisor::RecoveryPending("required parent is not currently accepted").into());
                        }
                        fetched.push((backfill.order, tx));
                    }
                    Ok((backfill, Err(e))) => {
                        return Err(e).with_context(|| format!("required prevout backfill {} failed; retain source window", backfill.txid));
                    }
                    Err(e) => return Err(e).context("required prevout backfill task failed; retain source window"),
                }
            }
            fetched.sort_by_key(|(order, _)| *order);
            for (_, tx) in fetched {
                stats.prevouts_backfilled += 1;
                backfilled.push(tx);
            }
        }

        Ok(backfilled)
    }
}

fn collect_external_p2sh_prevouts(candidates: &[CandidateTx]) -> Vec<PrevoutBackfill> {
    let candidate_outputs: BTreeSet<(String, i32)> = candidates
        .iter()
        .flat_map(|candidate| {
            candidate.tx.outputs.iter().map(|out| {
                (
                    candidate.tx.transaction_id.to_ascii_lowercase(),
                    out.index as i32,
                )
            })
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut lookups = Vec::new();
    for candidate in candidates {
        for input in &candidate.tx.inputs {
            if !input_spends_p2sh(input) && !candidate.tx.needs_input_identity(input) {
                continue;
            }
            let prev_vout: i32 = input.previous_outpoint_index.parse().unwrap_or(0);
            let key = (input.previous_outpoint_hash.to_ascii_lowercase(), prev_vout);
            if hex::decode(&key.0).is_err() {
                tracing::warn!(
                    target: "scanner",
                    txid_len = key.0.len(),
                    "skipping malformed P2SH prevout hash"
                );
                continue;
            }
            if !seen.insert(key.clone()) || candidate_outputs.contains(&key) {
                continue;
            }
            lookups.push(PrevoutBackfill {
                order: lookups.len(),
                txid: key.0,
                vout: key.1,
            });
        }
    }
    lookups
}

#[derive(Debug, thiserror::Error)]
#[error("historical source evidence unavailable for {missing_txid}")]
pub(crate) struct MissingHistoricalWindow {
    pub missing_txid: String,
    pub endpoint: String,
    pub evidence: serde_json::Value,
}

pub(crate) struct PreparedBatch {
    dependencies: Option<Vec<tn12_indexer_core::RestTransaction>>,
    stats: BatchStats,
    candidates: Vec<CandidateTx>,
    block_hashes: BTreeSet<String>,
}

impl PreparedBatch {
    pub(crate) fn acceptance_coordinates(&self) -> BTreeSet<(String, String, u64)> {
        self.candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.tx.transaction_id.clone(),
                    candidate.acceptance.hash.clone(),
                    candidate.acceptance.blue_score,
                )
            })
            .collect()
    }

    pub(crate) fn recovery_bodies(&self) -> impl Iterator<Item = &tn12_indexer_core::RestTransaction> {
        self.dependencies.iter().flatten().chain(self.candidates.iter().map(|candidate| &candidate.tx))
    }

    pub(crate) fn block_hashes(&self) -> BTreeSet<String> {
        self.block_hashes.clone()
    }

    pub(crate) fn acceptance_keys(&self) -> BTreeSet<AcceptanceKey> {
        self.candidates
            .iter()
            .map(CandidateTx::acceptance_key)
            .collect()
    }

    pub(crate) fn retain_acceptances(&mut self, allowed: &BTreeSet<AcceptanceKey>) {
        self.candidates
            .retain(|candidate| allowed.contains(&candidate.acceptance_key()));
    }

    /// A committed P2SH output proves the whole transaction was persisted in one
    /// database transaction. Check every output and every P2SH input against
    /// the exact accepting block before omitting the expensive REST hydration.
    /// Missing or inconsistent evidence leaves the candidate for normal replay.
    pub(crate) async fn already_persisted(
        &self,
        pool: &tn12_indexer_db::PgPool,
    ) -> Result<BTreeSet<AcceptanceKey>> {
        let mut txids = BTreeSet::new();
        for candidate in &self.candidates {
            if !has_p2sh_output(&candidate.tx) {
                continue;
            }
            if let Ok(txid) = hex::decode(&candidate.tx.transaction_id) {
                txids.insert(txid);
            }
            for input in candidate
                .tx
                .inputs
                .iter()
                .filter(|input| input_spends_p2sh(input))
            {
                if let Ok(txid) = hex::decode(&input.previous_outpoint_hash) {
                    txids.insert(txid);
                }
            }
        }

        type UtxoEvidence = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, i64, Vec<u8>);
        let mut rows_by_outpoint: BTreeMap<(Vec<u8>, i32), UtxoEvidence> = BTreeMap::new();
        let txids: Vec<_> = txids.into_iter().collect();
        for chunk in txids.chunks(256) {
            let rows = sqlx::query(
                "SELECT txid, vout, created_block, spent_block, spent_by_txid, amount_sompi, script_pubkey \
                 FROM covenant_utxos WHERE txid = ANY($1::bytea[])",
            )
            .bind(chunk.to_vec())
            .fetch_all(pool)
            .await?;
            for row in rows {
                rows_by_outpoint.insert(
                    (row.get("txid"), row.get("vout")),
                    (
                        row.get("created_block"),
                        row.get("spent_block"),
                        row.get("spent_by_txid"),
                        row.get("amount_sompi"),
                        row.get("script_pubkey"),
                    ),
                );
            }
        }

        let mut covered = BTreeSet::new();
        for candidate in &self.candidates {
            let tx = candidate.tx.with_normalized_missing_output_indexes();
            // Reject immutable evidence contradictions before the covered-row shortcut.
            for input in &tx.inputs {
                let (Ok(id), Ok(vout)) = (
                    hex::decode(&input.previous_outpoint_hash),
                    input.previous_outpoint_index.parse::<i32>(),
                ) else {
                    continue;
                };
                if let Some((_, _, _, amount, script)) = rows_by_outpoint.get(&(id, vout)) {
                    let amount_conflict = input
                        .previous_outpoint_amount
                        .is_some_and(|value| i64::try_from(value).ok().as_ref() != Some(amount));
                    let script_conflict = input
                        .previous_outpoint_script
                        .as_ref()
                        .is_some_and(|value| hex::decode(value).ok().as_ref() != Some(script));
                    if amount_conflict || script_conflict {
                        return Err(tn12_indexer_db::persist::AcceptanceEvidenceConflict.into());
                    }
                }
            }
            let Ok(id) = hex::decode(&tx.transaction_id) else {
                continue;
            };
            for output in &tx.outputs {
                let Ok(vout) = i32::try_from(output.index) else {
                    continue;
                };
                if let Some((_, _, _, amount, script)) = rows_by_outpoint.get(&(id.clone(), vout)) {
                    if i64::try_from(output.amount).ok().as_ref() != Some(amount)
                        || hex::decode(&output.script_public_key).ok().as_ref() != Some(script)
                    {
                        return Err(tn12_indexer_db::persist::AcceptanceEvidenceConflict.into());
                    }
                }
            }

            let Some(txid) = hex::decode(&tx.transaction_id).ok() else {
                continue;
            };
            let Some(block_hash) = hex::decode(&candidate.acceptance.hash).ok() else {
                continue;
            };
            let p2sh_outputs: Vec<_> = tx
                .outputs
                .iter()
                .filter(|out| is_p2sh_output(out))
                .collect();
            if p2sh_outputs.is_empty() {
                continue;
            }
            let outputs_covered = p2sh_outputs.iter().all(|out| {
                let (Ok(vout), Ok(amount), Ok(script)) = (
                    i32::try_from(out.index),
                    i64::try_from(out.amount),
                    hex::decode(&out.script_public_key),
                ) else {
                    return false;
                };
                rows_by_outpoint.get(&(txid.clone(), vout)).is_some_and(
                    |(created, _, _, stored_amount, stored_script)| {
                        created == &block_hash
                            && stored_amount == &amount
                            && stored_script == &script
                    },
                )
            });
            if !outputs_covered {
                continue;
            }
            let inputs_covered = tx
                .inputs
                .iter()
                .filter(|input| input_spends_p2sh(input))
                .all(|input| {
                    let (Ok(prev_txid), Ok(vout)) = (
                        hex::decode(&input.previous_outpoint_hash),
                        input.previous_outpoint_index.parse::<i32>(),
                    ) else {
                        return false;
                    };
                    rows_by_outpoint.get(&(prev_txid, vout)).is_some_and(
                        |(_, spent_block, spent_by, _, _)| {
                            spent_block.as_ref() == Some(&block_hash)
                                && spent_by.as_ref() == Some(&txid)
                        },
                    )
                });
            if inputs_covered {
                covered.insert(candidate.acceptance_key());
            }
        }
        Ok(covered)
    }
}

pub(crate) struct PersistedBatch {
    pub(crate) stats: BatchStats,
    pub(crate) persisted_acceptances: BTreeSet<AcceptanceKey>,
    pub(crate) hydrate_ms: u128,
    pub(crate) prevout_ms: u128,
    pub(crate) sql_persist_ms: u128,
}

pub(crate) fn has_p2sh_output(tx: &tn12_indexer_core::RestTransaction) -> bool {
    tx.outputs.iter().any(is_p2sh_output)
}

pub(crate) fn is_p2sh_output(out: &tn12_indexer_core::RestTxOutput) -> bool {
    matches!(out.script_public_key_type.as_deref(), Some(t) if t.eq_ignore_ascii_case("scripthash"))
        || is_p2sh_script_hex(&out.script_public_key)
}

/// Catches *spend-only* covenant transactions: an input consuming a covenant
/// UTXO produces no new P2SH output (the spender just withdraws funds back to
/// a regular address). The output-only filter misses these, leaving the
/// covenant `template_name` NULL because the decoder never sees the reveal.
///
/// Requires `resolveInputs=true` on `/virtual-chain` so each input carries
/// `previous_outpoint_script`.
fn any_p2sh_input(tx: &tn12_indexer_core::RestTransaction) -> bool {
    tx.inputs.iter().any(input_spends_p2sh)
}

fn input_spends_p2sh(inp: &tn12_indexer_core::RestTxInput) -> bool {
    inp.requires_covenant_identity()
}


fn missing_payload(tx: &tn12_indexer_core::RestTransaction) -> bool {
    tx.payload.as_deref().unwrap_or("").is_empty()
}

fn needs_p2sh_metadata_hydration(tx: &tn12_indexer_core::RestTransaction) -> bool {
    has_p2sh_output(tx)
        && (missing_payload(tx)
            || tx.outputs.iter().any(|out| {
                is_p2sh_script_hex(&out.script_public_key)
                    && (out.canonical_covenant_id().is_none()
                        || out.covenant_authorizing_input().is_none())
            }))
}

fn merge_hydrated_p2sh_metadata(
    target: &mut tn12_indexer_core::RestTransaction,
    fetched: &tn12_indexer_core::RestTransaction,
) -> bool {
    let mut changed = false;

    if missing_payload(target) {
        if let Some(payload) = fetched.payload.as_deref().filter(|p| !p.is_empty()) {
            target.payload = Some(payload.to_string());
            changed = true;
        }
    }
    if target.version == 0 && fetched.version != 0 {
        target.version = fetched.version;
        changed = true;
    }

    for target_out in &mut target.outputs {
        if !is_p2sh_script_hex(&target_out.script_public_key) {
            continue;
        }
        if target_out.canonical_covenant_id().is_some()
            && target_out.covenant_authorizing_input().is_some()
        {
            continue;
        }
        let Some(fetched_out) = fetched
            .outputs
            .iter()
            .find(|out| out.index == target_out.index)
        else {
            continue;
        };
        if target_out.covenant_id.is_none() && fetched_out.covenant_id.is_some() {
            target_out.covenant_id = fetched_out.covenant_id.clone();
            changed = true;
        }
        match (&mut target_out.covenant, &fetched_out.covenant) {
            (Some(target_binding), Some(fetched_binding)) => {
                if target_binding.covenant_id.is_none() && fetched_binding.covenant_id.is_some() {
                    target_binding.covenant_id = fetched_binding.covenant_id.clone();
                    changed = true;
                }
                if target_binding.authorizing_input.is_none()
                    && fetched_binding.authorizing_input.is_some()
                {
                    target_binding.authorizing_input = fetched_binding.authorizing_input;
                    changed = true;
                }
            }
            (None, Some(fetched_binding)) => {
                target_out.covenant = Some(fetched_binding.clone());
                changed = true;
            }
            _ => {}
        }
    }

    changed
}

/// A full block is authoritative for legacy transactions. For newer
/// transactions, require complete native bindings or use the individual REST
/// lookup, which may have a better binding source.
fn merge_full_block_metadata(
    target: &mut tn12_indexer_core::RestTransaction,
    metadata: &BlockTxMetadata,
) -> Option<bool> {
    if target.transaction_id != metadata.transaction_id
        || (target.version != 0 && target.version != metadata.version)
        || target.outputs.len() != metadata.outputs.len()
        || target
            .outputs
            .iter()
            .zip(&metadata.outputs)
            .any(|(out, full)| {
                out.amount != full.amount
                    || !out
                        .script_public_key
                        .eq_ignore_ascii_case(&full.script_public_key)
            })
    {
        return None;
    }
    if metadata.version != 0
        && target
            .outputs
            .iter()
            .zip(&metadata.outputs)
            .any(|(out, full)| {
                is_p2sh_output(out)
                    && !full.covenant.as_ref().is_some_and(|binding| {
                        binding.covenant_id.is_some() && binding.authorizing_input.is_some()
                    })
            })
    {
        return None;
    }

    let mut changed = false;
    if missing_payload(target) {
        if let Some(payload) = metadata
            .payload
            .as_deref()
            .filter(|payload| !payload.is_empty())
        {
            target.payload = Some(payload.to_string());
            changed = true;
        }
    }
    if target.version == 0 && metadata.version != 0 {
        target.version = metadata.version;
        changed = true;
    }
    for (out, full) in target.outputs.iter_mut().zip(&metadata.outputs) {
        if !is_p2sh_output(out) {
            continue;
        }
        if let Some(binding) = &full.covenant {
            if out.covenant_id.is_none() && binding.covenant_id.is_some() {
                out.covenant_id = binding.covenant_id.clone();
                changed = true;
            }
            match &mut out.covenant {
                Some(existing) => {
                    if existing.covenant_id.is_none() && binding.covenant_id.is_some() {
                        existing.covenant_id = binding.covenant_id.clone();
                        changed = true;
                    }
                    if existing.authorizing_input.is_none() && binding.authorizing_input.is_some() {
                        existing.authorizing_input = binding.authorizing_input;
                        changed = true;
                    }
                }
                None => {
                    out.covenant = Some(binding.clone());
                    changed = true;
                }
            }
        }
    }
    Some(changed)
}

/// /virtual-chain omits accepting-block fields per tx; /transactions can omit
/// them in older REST shapes. Fill missing fields from the chain block that led
/// us to this transaction so the persister has a coherent block FK.
fn synthesize_acceptance(
    tx: &mut tn12_indexer_core::RestTransaction,
    block: &tn12_indexer_core::VirtualChainBlock,
) {
    synthesize_acceptance_from(
        tx,
        &ChainAcceptance {
            hash: block.hash.clone(),
            blue_score: block.blue_score,
            timestamp: block.timestamp,
        },
    );
}

fn synthesize_acceptance_from(
    tx: &mut tn12_indexer_core::RestTransaction,
    acceptance: &ChainAcceptance,
) {
    tx.normalize_missing_output_indexes();
    tx.is_accepted = true;
    tx.accepting_block_hash
        .get_or_insert_with(|| acceptance.hash.clone());
    tx.accepting_block_blue_score
        .get_or_insert(acceptance.blue_score);
    tx.accepting_block_time.get_or_insert(acceptance.timestamp);
    if tx.block_time == 0 {
        tx.block_time = acceptance.timestamp;
    }
    if tx.block_hash.is_empty() {
        tx.block_hash = vec![acceptance.hash.clone()];
    }
}

/// P2SH script-pubkey hex check shared by output + resolved-input paths.
/// P2SH = OP_BLAKE2B (0xaa) PUSHDATA-32 (0x20) <32 bytes> OP_EQUAL (0x87) —
/// 35 bytes / 70 hex chars (or 74 with the leading 0000 script-version prefix
/// that some REST shapes include).
fn is_p2sh_script_hex(h: &str) -> bool {
    (h.len() == 70 && h.starts_with("aa20") && h.ends_with("87"))
        || (h.len() == 74 && h.starts_with("0000aa20") && h.ends_with("87"))
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct BatchStats {
    pub(crate) blocks_seen: u64,
    pub(crate) p2sh_candidates: u64,
    pub(crate) txs_hydrated: u64,
    pub(crate) block_bodies_covered: u64,
    pub(crate) prevouts_backfilled: u64,
    pub(crate) txs_persisted: u64,
    pub(crate) max_blue_score: u64,
}

fn window_end(start: u64, limit: u64) -> u64 {
    start + limit - 1
}

fn should_advance_window(start: u64, limit: u64, max_blue_score: u64) -> bool {
    max_blue_score >= window_end(start, limit)
}

fn should_retry_sparse_window(
    retries: u8,
    max_retries: u8,
    start: u64,
    limit: u64,
    tip_blue_score: u64,
) -> bool {
    let next_window_end = start
        .saturating_add(limit.saturating_mul(2))
        .saturating_sub(1);
    retries < max_retries && tip_blue_score <= next_window_end
}

#[cfg(test)]
mod filter_tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use tn12_indexer_core::{RestCovenantBinding, RestTransaction, RestTxInput, RestTxOutput};
    use tn12_indexer_db::{PersistStats, RevertStats};

    fn output(spk: &str, kind: Option<&str>) -> RestTxOutput {
        RestTxOutput {
            transaction_id: String::new(),
            index: 0,
            amount: 0,
            script_public_key: spk.into(),
            script_public_key_address: None,
            script_public_key_type: kind.map(str::to_string),
            covenant_id: None,
            covenant: None,
        }
    }

    fn input(prev_script: Option<&str>) -> RestTxInput {
        RestTxInput {
            transaction_id: String::new(),
            index: 0,
            previous_outpoint_hash: "ff".repeat(32),
            previous_outpoint_index: "0".into(),
            previous_outpoint_address: None,
            previous_outpoint_amount: None,
            previous_outpoint_script: prev_script.map(str::to_string),
            signature_script: String::new(),
            sig_op_count: "0".into(),
        }
    }

    fn input_with_address(prev_script: Option<&str>, address: Option<&str>) -> RestTxInput {
        RestTxInput {
            previous_outpoint_address: address.map(str::to_string),
            ..input(prev_script)
        }
    }

    fn tx(inputs: Vec<RestTxInput>, outputs: Vec<RestTxOutput>) -> RestTransaction {
        RestTransaction {
            transaction_id: "aa".repeat(32),
            inputs,
            outputs,
            ..Default::default()
        }
    }

    // 35-byte P2SH redeem-commitment script: OP_BLAKE2B PUSH32 <32B> OP_EQUAL.
    const P2SH_HEX: &str = "aa20c1d1a29613715893d1b98480dcbeb951c36647da8baad352b6bc932ab244a87787";

    #[test]
    fn detects_deploy_via_output() {
        let t = tx(vec![input(None)], vec![output(P2SH_HEX, None)]);
        assert!(has_p2sh_output(&t));
        assert!(!any_p2sh_input(&t));
    }

    #[test]
    fn detects_spend_via_resolved_input() {
        // Spend tx: input came from a P2SH covenant utxo; output is a normal
        // address (no P2SH). Without resolveInputs the scanner used to skip
        // this, leaving the covenant unclassified.
        let normal_out = "76a914aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88ac"; // not P2SH
        let t = tx(
            vec![input(Some(P2SH_HEX))],
            vec![output(normal_out, Some("pubkeyhash"))],
        );
        assert!(!has_p2sh_output(&t));
        assert!(any_p2sh_input(&t));
    }

    #[test]
    fn detects_spend_via_resolved_p2sh_address() {
        // Some REST responses resolve the previous output address but omit
        // previous_outpoint_script. The address is still enough to keep the
        // spend-only settlement/refund tx in the scanner candidate set.
        let normal_out = "204b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4ac";
        let t = tx(
            vec![input_with_address(
                None,
                Some("kaspatest:prl8k7x4ah2ve4nd8rhrx7707a76hhyk5up3ymsyxfkgje2q8wjdc3frfqkj0"),
            )],
            vec![output(normal_out, Some("pubkey"))],
        );
        assert!(!has_p2sh_output(&t));
        assert!(any_p2sh_input(&t));
    }

    #[test]
    fn ignores_unresolved_input() {
        // Without resolveInputs, previous_outpoint_script is None — filter
        // must not panic and must not pretend it's a covenant.
        let t = tx(vec![input(None)], vec![]);
        assert!(!any_p2sh_input(&t));
    }

    #[test]
    fn ignores_non_p2sh_input() {
        let t = tx(
            vec![input_with_address(
                Some("76a914bbbb88ac"),
                Some("kaspatest:qp93l20xyghwrwqpnp2gdl4p746wdy78aewnjv74duuet3mc2qedgfvgz42s2"),
            )],
            vec![],
        );
        assert!(!any_p2sh_input(&t));
    }

    #[test]
    fn does_not_advance_partial_tip_window() {
        assert!(!should_advance_window(457011400, 100, 457011433));
    }

    #[test]
    fn advances_complete_window() {
        assert!(should_advance_window(457011400, 100, 457011499));
        assert!(should_advance_window(457011400, 100, 457011500));
    }

    #[test]
    fn retries_sparse_window_before_advancing() {
        assert!(should_retry_sparse_window(0, 2, 457011400, 100, 457011520));
        assert!(should_retry_sparse_window(1, 2, 457011400, 100, 457011520));
        assert!(!should_retry_sparse_window(2, 2, 457011400, 100, 457011520));
    }

    #[test]
    fn does_not_retry_historical_sparse_window() {
        assert!(!should_retry_sparse_window(0, 2, 457011400, 100, 457020000));
    }

    #[test]
    fn synthesizes_missing_acceptance_fields() {
        let block = tn12_indexer_core::VirtualChainBlock {
            hash: "ab".repeat(32),
            blue_score: 123,
            daa_score: 123,
            timestamp: 456,
            transactions: vec![],
        };
        let mut t = tx(vec![], vec![]);

        synthesize_acceptance(&mut t, &block);

        assert!(t.is_accepted);
        assert_eq!(t.accepting_block_hash.as_deref(), Some(block.hash.as_str()));
        assert_eq!(t.accepting_block_blue_score, Some(123));
        assert_eq!(t.accepting_block_time, Some(456));
        assert_eq!(t.block_time, 456);
        assert_eq!(t.block_hash, vec![block.hash]);
    }

    #[test]
    fn hydrates_payload_from_full_transaction_without_losing_resolved_inputs() {
        let mut virtual_tx = tx(vec![input(Some(P2SH_HEX))], vec![output(P2SH_HEX, None)]);
        virtual_tx.payload = None;
        let original_inputs = virtual_tx.inputs.clone();

        let mut full_tx = virtual_tx.clone();
        full_tx.payload = Some("7b7d".to_string());
        full_tx.inputs.clear();

        assert!(merge_hydrated_p2sh_metadata(&mut virtual_tx, &full_tx));
        assert_eq!(virtual_tx.payload.as_deref(), Some("7b7d"));
        assert_eq!(virtual_tx.inputs.len(), original_inputs.len());
        assert_eq!(
            virtual_tx.inputs[0].previous_outpoint_script,
            original_inputs[0].previous_outpoint_script
        );
    }

    #[test]
    fn does_not_overwrite_existing_payload() {
        let mut virtual_tx = tx(vec![], vec![output(P2SH_HEX, None)]);
        virtual_tx.payload = Some("old".to_string());
        let mut full_tx = virtual_tx.clone();
        full_tx.payload = Some("new".to_string());

        assert!(!merge_hydrated_p2sh_metadata(&mut virtual_tx, &full_tx));
        assert_eq!(virtual_tx.payload.as_deref(), Some("old"));
    }

    #[test]
    fn hydrates_native_covenant_binding_from_full_transaction() {
        let mut virtual_tx = tx(vec![input(Some(P2SH_HEX))], vec![output(P2SH_HEX, None)]);
        virtual_tx.version = 0;
        let mut full_tx = virtual_tx.clone();
        full_tx.version = 1;
        full_tx.outputs[0].covenant_id =
            Some("97f666256bcea86d3a44d04265d76aec55773973eec64922d12c7bca1d8ac5d4".into());
        full_tx.outputs[0].covenant = Some(RestCovenantBinding {
            covenant_id: full_tx.outputs[0].covenant_id.clone(),
            authorizing_input: Some(0),
        });

        assert!(needs_p2sh_metadata_hydration(&virtual_tx));
        assert!(merge_hydrated_p2sh_metadata(&mut virtual_tx, &full_tx));
        assert_eq!(
            virtual_tx.outputs[0].canonical_covenant_id(),
            Some("97f666256bcea86d3a44d04265d76aec55773973eec64922d12c7bca1d8ac5d4")
        );
        assert_eq!(virtual_tx.outputs[0].covenant_authorizing_input(), Some(0));
        assert_eq!(virtual_tx.version, 1);
    }

    #[test]
    fn hydrates_partial_covenant_binding_when_authorizing_input_is_missing() {
        let mut virtual_tx = tx(vec![input(Some(P2SH_HEX))], vec![output(P2SH_HEX, None)]);
        virtual_tx.outputs[0].covenant_id =
            Some("97f666256bcea86d3a44d04265d76aec55773973eec64922d12c7bca1d8ac5d4".into());

        let mut full_tx = virtual_tx.clone();
        full_tx.outputs[0].covenant = Some(RestCovenantBinding {
            covenant_id: full_tx.outputs[0].covenant_id.clone(),
            authorizing_input: Some(0),
        });

        assert!(needs_p2sh_metadata_hydration(&virtual_tx));
        assert!(merge_hydrated_p2sh_metadata(&mut virtual_tx, &full_tx));
        assert_eq!(virtual_tx.outputs[0].covenant_authorizing_input(), Some(0));
    }

    #[test]
    fn external_prevouts_skip_same_window_nonzero_output_and_duplicates() {
        let mut producer = tx(
            vec![],
            vec![output("76a914bbbb88ac", None), output(P2SH_HEX, None)],
        );
        producer.transaction_id = "11".repeat(32);
        producer.normalize_missing_output_indexes();
        let mut same_window = input(Some(P2SH_HEX));
        same_window.previous_outpoint_hash = producer.transaction_id.clone();
        same_window.previous_outpoint_index = "1".into();
        let mut external = input(Some(P2SH_HEX));
        external.previous_outpoint_hash = "AB".repeat(32);
        let mut malformed = input(Some(P2SH_HEX));
        malformed.previous_outpoint_hash = "bad-hash".into();
        let consumer = tx(
            vec![same_window, external.clone(), external, malformed],
            vec![],
        );
        let acceptance = ChainAcceptance {
            hash: "cc".repeat(32),
            blue_score: 100,
            timestamp: 1_000,
        };
        let lookups = collect_external_p2sh_prevouts(&[
            CandidateTx {
                tx: producer,
                acceptance: acceptance.clone(),
            },
            CandidateTx {
                tx: consumer,
                acceptance,
            },
        ]);
        assert_eq!(lookups.len(), 1);
        assert_eq!(lookups[0].txid, "ab".repeat(32));
        assert_eq!(lookups[0].vout, 0);
    }

    #[derive(Default)]
    struct BatchProbe {
        lookup_sizes: Mutex<Vec<usize>>,
    }

    #[async_trait::async_trait]
    impl Persister for BatchProbe {
        async fn persist_tx(&self, _tx: &RestTransaction) -> Result<PersistStats> {
            unreachable!()
        }

        async fn revert_block(&self, _block_hash: &[u8]) -> Result<RevertStats> {
            unreachable!()
        }

        async fn has_utxo(&self, _txid_hex: &str, _vout: i32) -> Result<bool> {
            panic!("dense prevouts must use the set lookup")
        }

        async fn existing_utxos(
            &self,
            outpoints: &[(String, i32)],
        ) -> Result<HashSet<(String, i32)>> {
            self.lookup_sizes.lock().unwrap().push(outpoints.len());
            Ok(outpoints.iter().cloned().collect())
        }
    }

    struct UnusedCursor;

    #[derive(Default)]
    struct FailingIndividualProbe {
        attempts: Mutex<Vec<String>>,
        stored: Mutex<HashSet<String>>,
        failed_once: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl Persister for FailingIndividualProbe {
        async fn persist_batch(&self, _txs: &[RestTransaction]) -> Result<PersistStats> {
            anyhow::bail!("exercise individual fallback")
        }

        async fn persist_tx(&self, tx: &RestTransaction) -> Result<PersistStats> {
            self.attempts
                .lock()
                .unwrap()
                .push(tx.transaction_id.clone());
            if tx.transaction_id == "02".repeat(32)
                && !self
                    .failed_once
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                anyhow::bail!("fixture write failure");
            }
            self.stored
                .lock()
                .unwrap()
                .insert(tx.transaction_id.clone());
            Ok(PersistStats::default())
        }

        async fn revert_block(&self, _block_hash: &[u8]) -> Result<RevertStats> {
            unreachable!()
        }

        async fn has_utxo(&self, _txid_hex: &str, _vout: i32) -> Result<bool> {
            unreachable!()
        }
    }

    struct HistoricalGuardProbe;

    #[async_trait::async_trait]
    impl Persister for HistoricalGuardProbe {
        async fn persist_batch(&self, _txs: &[RestTransaction]) -> Result<PersistStats> {
            Err(tn12_indexer_db::persist::HistoricalAcceptanceMapGuard {
                reason: "canonical target lost".into(),
            }
            .into())
        }
        async fn persist_tx(&self, _tx: &RestTransaction) -> Result<PersistStats> {
            panic!("historical map guard must never fan out into individual writes")
        }
        async fn revert_block(&self, _hash: &[u8]) -> Result<RevertStats> {
            unreachable!()
        }
        async fn has_utxo(&self, _txid: &str, _vout: i32) -> Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn historical_map_guard_retains_window_without_individual_writes() {
        let scanner = ChainScanner::new(
            RestClient::new("http://127.0.0.1:1").unwrap(),
            Arc::new(HistoricalGuardProbe),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let result = scanner
            .persist_prepared(PreparedBatch {
                dependencies: None,
                stats: BatchStats::default(),
                block_hashes: BTreeSet::from(["cc".repeat(32)]),
                candidates: vec![CandidateTx {
                    tx: RestTransaction {
                        transaction_id: "01".repeat(32),
                        payload: Some("01".into()),
                        outputs: vec![RestTxOutput {
                            covenant: Some(RestCovenantBinding {
                                covenant_id: Some("dd".repeat(32)),
                                authorizing_input: Some(0),
                            }),
                            ..output(P2SH_HEX, None)
                        }],
                        ..Default::default()
                    },
                    acceptance: ChainAcceptance {
                        hash: "cc".repeat(32),
                        blue_score: 100,
                        timestamp: 1_000,
                    },
                }],
            })
            .await;
        let error = result.err().expect("guard must retain the window");
        assert!(error
            .downcast_ref::<tn12_indexer_db::persist::HistoricalAcceptanceMapGuard>()
            .is_some());
    }

    struct WriterBudgetProbe;

    #[async_trait::async_trait]
    impl Persister for WriterBudgetProbe {
        async fn persist_batch(&self, _txs: &[RestTransaction]) -> Result<PersistStats> {
            Err(tn12_indexer_db::persist::TransientPersistError::writer_budget_exceeded().into())
        }
        async fn persist_tx(&self, _tx: &RestTransaction) -> Result<PersistStats> {
            panic!("writer budget must never fan out into individual writes")
        }
        async fn revert_block(&self, _hash: &[u8]) -> Result<RevertStats> {
            unreachable!()
        }
        async fn has_utxo(&self, _txid: &str, _vout: i32) -> Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn writer_budget_retains_window_without_individual_writes() {
        let scanner = ChainScanner::new(
            RestClient::new("http://127.0.0.1:1").unwrap(),
            Arc::new(WriterBudgetProbe),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let result = scanner
            .persist_prepared(PreparedBatch {
                dependencies: None,
                stats: BatchStats::default(),
                block_hashes: BTreeSet::from(["cc".repeat(32)]),
                candidates: vec![CandidateTx {
                    tx: RestTransaction {
                        transaction_id: "01".repeat(32),
                        payload: Some("01".into()),
                        outputs: vec![RestTxOutput {
                            covenant: Some(RestCovenantBinding {
                                covenant_id: Some("dd".repeat(32)),
                                authorizing_input: Some(0),
                            }),
                            ..output(P2SH_HEX, None)
                        }],
                        ..Default::default()
                    },
                    acceptance: ChainAcceptance {
                        hash: "cc".repeat(32),
                        blue_score: 100,
                        timestamp: 1_000,
                    },
                }],
            })
            .await;
        let error = result.err().expect("guard must retain the window");
        assert_eq!(
            error
                .downcast_ref::<tn12_indexer_db::persist::TransientPersistError>()
                .unwrap()
                .kind,
            tn12_indexer_db::persist::PersistTransientKind::WriterBudgetExceeded
        );
    }

    struct UnknownGenericCommitProbe;

    #[async_trait::async_trait]
    impl Persister for UnknownGenericCommitProbe {
        async fn persist_batch(&self, _txs: &[RestTransaction]) -> Result<PersistStats> {
            Err(tn12_indexer_db::persist::GenericWriteOutcomeUnknown {
                phase: "commit",
                detail: "pool timed out after commit".into(),
            }
            .into())
        }
        async fn persist_tx(&self, _tx: &RestTransaction) -> Result<PersistStats> {
            panic!("writer budget must never fan out into individual writes")
        }
        async fn revert_block(&self, _hash: &[u8]) -> Result<RevertStats> {
            unreachable!()
        }
        async fn has_utxo(&self, _txid: &str, _vout: i32) -> Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn unknown_generic_commit_retains_window_without_individual_writes() {
        let scanner = ChainScanner::new(
            RestClient::new("http://127.0.0.1:1").unwrap(),
            Arc::new(UnknownGenericCommitProbe),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let result = scanner
            .persist_prepared(PreparedBatch {
                dependencies: None,
                stats: BatchStats::default(),
                block_hashes: BTreeSet::from(["cc".repeat(32)]),
                candidates: vec![CandidateTx {
                    tx: RestTransaction {
                        transaction_id: "01".repeat(32),
                        payload: Some("01".into()),
                        outputs: vec![RestTxOutput {
                            covenant: Some(RestCovenantBinding {
                                covenant_id: Some("dd".repeat(32)),
                                authorizing_input: Some(0),
                            }),
                            ..output(P2SH_HEX, None)
                        }],
                        ..Default::default()
                    },
                    acceptance: ChainAcceptance {
                        hash: "cc".repeat(32),
                        blue_score: 100,
                        timestamp: 1_000,
                    },
                }],
            })
            .await;
        let error = result.err().expect("guard must retain the window");
        assert!(error
            .downcast_ref::<tn12_indexer_db::persist::GenericWriteOutcomeUnknown>()
            .is_some());
        assert!(!is_transient_persist_error(&error));
    }

    #[tokio::test]
    async fn individual_persist_failure_retries_window_before_later_acceptances() {
        let persister = Arc::new(FailingIndividualProbe::default());
        let scanner = ChainScanner::new(
            RestClient::new("http://127.0.0.1:1").unwrap(),
            persister.clone(),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let prepared = || PreparedBatch {
            dependencies: None,
            stats: BatchStats {
                p2sh_candidates: 3,
                ..Default::default()
            },
            block_hashes: BTreeSet::from(["cc".repeat(32)]),
            candidates: (1..=3)
                .map(|index| CandidateTx {
                    tx: RestTransaction {
                        transaction_id: format!("{index:02x}").repeat(32),
                        payload: Some("01".into()),
                        outputs: vec![RestTxOutput {
                            covenant: Some(RestCovenantBinding {
                                covenant_id: Some("dd".repeat(32)),
                                authorizing_input: Some(0),
                            }),
                            ..output(P2SH_HEX, None)
                        }],
                        ..Default::default()
                    },
                    acceptance: ChainAcceptance {
                        hash: "cc".repeat(32),
                        blue_score: 100,
                        timestamp: 1_000,
                    },
                })
                .collect(),
        };
        let first = scanner.persist_prepared(prepared()).await;
        assert!(
            first.is_err(),
            "a partial write must not authorize cursor advancement"
        );
        assert_eq!(
            *persister.attempts.lock().unwrap(),
            vec!["01".repeat(32), "02".repeat(32)]
        );
        let retried = scanner.persist_prepared(prepared()).await.unwrap();
        assert_eq!(retried.persisted_acceptances.len(), 3);
        assert_eq!(retried.stats.txs_persisted, 3);
        assert_eq!(persister.stored.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn individual_fallback_persists_parent_before_child() {
        let persister = Arc::new(FailingIndividualProbe::default());
        let scanner = ChainScanner::new(
            RestClient::new("http://127.0.0.1:1").unwrap(),
            persister.clone(),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let candidates = ["01", "03"]
            .into_iter()
            .map(|id| CandidateTx {
                tx: RestTransaction {
                    transaction_id: id.repeat(32),
                    payload: Some("01".into()),
                    inputs: if id == "01" {
                        vec![tn12_indexer_core::RestTxInput {
                            previous_outpoint_hash: "03".repeat(32),
                            previous_outpoint_index: "0".into(),
                            previous_outpoint_script: Some(P2SH_HEX.into()),
                            ..Default::default()
                        }]
                    } else {
                        vec![]
                    },
                    outputs: vec![RestTxOutput {
                        covenant: Some(RestCovenantBinding {
                            covenant_id: Some("dd".repeat(32)),
                            authorizing_input: Some(0),
                        }),
                        ..output(P2SH_HEX, None)
                    }],
                    ..Default::default()
                },
                acceptance: ChainAcceptance {
                    hash: "cc".repeat(32),
                    blue_score: 100,
                    timestamp: 1000,
                },
            })
            .collect();
        let result = scanner
            .persist_prepared(PreparedBatch {
                dependencies: None,
                stats: BatchStats {
                    p2sh_candidates: 2,
                    ..Default::default()
                },
                candidates,
                block_hashes: BTreeSet::from(["cc".repeat(32)]),
            })
            .await
            .unwrap();
        assert_eq!(result.persisted_acceptances.len(), 2);
        assert_eq!(
            *persister.attempts.lock().unwrap(),
            vec!["03".repeat(32), "01".repeat(32)]
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn missing_parent_retains_source_evidence_and_allows_independent_replay(pool: tn12_indexer_db::PgPool) {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        use std::sync::atomic::{AtomicU16,Ordering};
        let status=Arc::new(AtomicU16::new(404));
        let server_status=status.clone();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=listener.local_addr().unwrap();
        let parent="ff".repeat(32);
        let child=RestTransaction { transaction_id:"aa".repeat(32),inputs:vec![input(Some(P2SH_HEX))],..Default::default() };
        let server=tokio::spawn(async move {
            loop {
                let (mut stream,_)=listener.accept().await.unwrap();
                let mut request=[0u8;8192];
                let read=stream.read(&mut request).await.unwrap();
                let request=String::from_utf8_lossy(&request[..read]);
                let (code,body)=if request.contains("/info/health") {
                    (200,serde_json::json!({"database":{"blueScore":5000,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}}).to_string())
                } else if request.contains("/virtual-chain") {
                    let score=if request.contains("blueScoreGte=100") {100} else {200};
                    (200,serde_json::json!([{"hash":"cc".repeat(32),"blue_score":score,"daa_score":score,"timestamp":1000,"transactions":if score==100 {vec![child.clone()]} else {vec![]}}]).to_string())
                } else {
                    assert!(request.contains(&format!("/transactions/{parent}")));
                    (server_status.load(Ordering::SeqCst),"{}".into())
                };
                let response=crate::source_observation::fresh_test_response(format!("HTTP/1.1 {code} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body));
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let writer=Arc::new(tn12_indexer_db::PgPersister::for_genesis_repair(pool.clone()));
        let scanner=ChainScanner::new(RestClient::new(format!("http://{address}")).unwrap(),writer.clone(),ScannerConfig {batch_size:100,..Default::default()},Box::new(UnusedCursor));
        let job=writer.prepare_settled_repair("fixture",100,100).await.unwrap();
        let error=scanner.replay_window(100).await.unwrap_err();
        let missing=error.downcast_ref::<MissingHistoricalWindow>().expect("404 must retain the exact failed source window");
        assert_eq!(missing.missing_txid,"ff".repeat(32));
        assert_eq!(missing.evidence["windowStart"],100);
        assert_eq!(missing.evidence["transactions"].as_array().unwrap().len(),1);
        assert!(writer.defer_missing_history("fixture","fixture",job.epoch,200,&missing.missing_txid,&missing.endpoint,&missing.evidence,&error.to_string()).await.unwrap());
        scanner.replay_window(200).await.unwrap();
        assert_eq!(tn12_indexer_db::persist::genesis::unverified::summary(&pool).await.unwrap().pending_windows,1);
        status.store(503,Ordering::SeqCst);
        let error=scanner.replay_window(100).await.unwrap_err();
        assert!(error.downcast_ref::<MissingHistoricalWindow>().is_none(),"an outage must not park arbitrary windows");
        server.abort();
    }

    #[tokio::test]
    async fn bounded_replay_rejects_invalid_window_and_never_uses_cursor() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut pages = 0;
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let read = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                let body = if request.contains("/info/health") {
                    &serde_json::json!({"database":{"blueScore":150,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}}).to_string()
                } else {
                    assert!(request.contains("blueScoreGte=100"));
                    assert!(request.contains("limit=10"));
                    pages += 1;
                    if pages == 1 {
                        "[{\"hash\":\"aa\",\"blue_score\":109,\"daa_score\":109,\"timestamp\":1000,\"transactions\":[]}]"
                    } else {
                        "[]"
                    }
                };
                stream.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body)).as_bytes()).await.unwrap();
            }
        });
        let scanner = ChainScanner::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(FailingIndividualProbe::default()),
            ScannerConfig {
                batch_size: 10,
                ..Default::default()
            },
            Box::new(UnusedCursor),
        );
        assert!(scanner
            .replay_window(101)
            .await
            .unwrap_err()
            .to_string()
            .contains("aligned"));
        scanner.replay_window(100).await.unwrap();
        assert!(scanner
            .replay_window(100)
            .await
            .unwrap_err()
            .to_string()
            .contains("no blocks"));
        server.await.unwrap();
    }

    #[async_trait::async_trait]
    impl CursorStore for UnusedCursor {
        async fn load(&self) -> Result<Option<u64>> {
            unreachable!()
        }

        async fn save(
            &self,
            _blue_score: u64,
            _rest_database_blue_score: Option<u64>,
        ) -> Result<()> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn search_hydration_batches_without_changing_acceptance_order() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let server_sizes = sizes.clone();
        let server = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            let barrier = Arc::new(tokio::sync::Barrier::new(4));
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let sizes = server_sizes.clone();
                let barrier = barrier.clone();
                workers.spawn(async move {
                    let mut request = Vec::new();
                    let header_end;
                    loop {
                        let mut chunk = [0; 4096];
                        let n = stream.read(&mut chunk).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&chunk[..n]);
                        if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                            header_end = pos + 4;
                            break;
                        }
                    }
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    assert!(headers.starts_with("POST /transactions/search?fields="));
                    let length: usize = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                    }).unwrap();
                    while request.len() < header_end + length {
                        let mut chunk = [0; 4096];
                        let n = stream.read(&mut chunk).await.unwrap();
                        assert!(n > 0);
                        request.extend_from_slice(&chunk[..n]);
                    }
                    let body: serde_json::Value = serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
                    let ids = body["transactionIds"].as_array().unwrap();
                    sizes.lock().unwrap().push(ids.len());
                    barrier.wait().await;
                    // Reverse the response and omit one result. Both are legal.
                    let rows: Vec<_> = ids.iter().rev().filter(|id| id.as_str().unwrap() != format!("{:064x}", 2_999)).map(|id| serde_json::json!({
                        "transaction_id": id, "version": 0, "payload": null,
                        "outputs": [{"index": 0, "amount": 100, "script_public_key": P2SH_HEX}]
                    })).collect();
                    let body = serde_json::to_string(&rows).unwrap();
                    let response = crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
                    if ids.len() == 1 {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                    }
                    stream.write_all(response.as_bytes()).await.unwrap();
                });
            }
            while let Some(result) = workers.join_next().await {
                result.unwrap();
            }
        });
        let scanner = ChainScanner::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(BatchProbe::default()),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let mut candidates: Vec<_> = (0..3_001)
            .rev()
            .map(|index| CandidateTx {
                tx: RestTransaction {
                    transaction_id: format!("{index:064x}"),
                    outputs: vec![RestTxOutput {
                        amount: 100,
                        ..output(P2SH_HEX, None)
                    }],
                    ..Default::default()
                },
                acceptance: ChainAcceptance {
                    hash: format!("{index:064x}"),
                    blue_score: index,
                    timestamp: 1_000,
                },
            })
            .collect();
        let pending: Vec<_> = candidates
            .iter()
            .enumerate()
            .map(|(i, candidate)| (i, candidate.tx.transaction_id.clone()))
            .collect();
        let mut stats = BatchStats::default();
        let covered = tokio::time::timeout(
            Duration::from_secs(10),
            scanner.hydrate_from_search(&mut candidates, &pending, &mut stats),
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(covered.len(), 3_000);
        assert!(covered.contains(&0)); // The delayed fourth request completed.
        assert!(!covered.contains(&1)); // Missing result remains eligible for fallback.
        assert_eq!(stats.txs_hydrated, 0); // Explicit empty payload is validated without mutation.
        let mut sizes = sizes.lock().unwrap().clone();
        sizes.sort();
        assert_eq!(sizes, vec![1, 1_000, 1_000, 1_000]);
        for (i, candidate) in candidates.iter().enumerate() {
            assert_eq!(candidate.tx.transaction_id, pending[i].1);
            assert_eq!(candidate.acceptance.blue_score, 3_000 - i as u64);
        }
    }

    #[test]
    fn bulk_metadata_requires_output_match_and_native_bindings() {
        let mut target = tx(vec![], vec![output(P2SH_HEX, None)]);
        let mut metadata = BlockTxMetadata {
            transaction_id: target.transaction_id.clone(),
            payload: None,
            version: 0,
            outputs: vec![crate::rpc::rest::BlockOutputMetadata {
                amount: target.outputs[0].amount,
                script_public_key: P2SH_HEX.into(),
                covenant: None,
            }],
        };
        assert_eq!(
            merge_full_block_metadata(&mut target, &metadata),
            Some(false)
        );
        metadata.outputs[0].amount += 1;
        assert_eq!(merge_full_block_metadata(&mut target, &metadata), None);
        metadata.outputs[0].amount -= 1;
        metadata.version = 1;
        assert_eq!(merge_full_block_metadata(&mut target, &metadata), None);
        metadata.outputs[0].covenant = Some(RestCovenantBinding {
            covenant_id: Some("native".into()),
            authorizing_input: Some(0),
        });
        assert_eq!(
            merge_full_block_metadata(&mut target, &metadata),
            Some(true)
        );
        assert_eq!(target.version, 1);
        assert_eq!(target.outputs[0].canonical_covenant_id(), Some("native"));
        metadata.version = 0;
        metadata.outputs[0].covenant = None;
        assert_eq!(merge_full_block_metadata(&mut target, &metadata), None);
    }

    #[tokio::test]
    async fn search_outage_stops_later_batches_and_bounds_total_wait() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt;
        for hang in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let server_requests = requests.clone();
            let server = tokio::spawn(async move {
                let mut held = Vec::new();
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    server_requests.fetch_add(1, Ordering::SeqCst);
                    if hang {
                        held.push(stream);
                    } else {
                        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                    }
                }
            });
            let scanner = ChainScanner::new(
                RestClient::new(format!("http://{address}")).unwrap(),
                Arc::new(BatchProbe::default()),
                ScannerConfig::default(),
                Box::new(UnusedCursor),
            );
            let mut candidates: Vec<_> = (0..4_001)
                .map(|index| CandidateTx {
                    tx: RestTransaction {
                        transaction_id: format!("{index:064x}"),
                        ..Default::default()
                    },
                    acceptance: ChainAcceptance {
                        hash: "cc".repeat(32),
                        blue_score: 100,
                        timestamp: 1_000,
                    },
                })
                .collect();
            let pending: Vec<_> = candidates
                .iter()
                .enumerate()
                .map(|(i, candidate)| (i, candidate.tx.transaction_id.clone()))
                .collect();
            let covered = tokio::time::timeout(
                Duration::from_secs(16),
                scanner.hydrate_from_search(&mut candidates, &pending, &mut BatchStats::default()),
            )
            .await
            .unwrap();
            server.abort();
            assert!(covered.is_empty());
            assert!((1..=4).contains(&requests.load(Ordering::SeqCst)));
        }
    }

    #[tokio::test]
    async fn search_failure_falls_back_to_full_blocks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0; 8192];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..pos]);
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= pos + 4 + length {
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let (status, body) = if attempt == 0 {
                    assert!(request.starts_with("POST /transactions/search?"));
                    ("503 Service Unavailable", "{}".to_string())
                } else {
                    assert!(request.starts_with("GET /blocks-from-bluescore?blueScore=100&"));
                    let transactions: Vec<_> = (0..16).map(|index| serde_json::json!({
                        "verboseData": {"transactionId": format!("{index:064x}")}, "version": 0, "payload": "",
                        "outputs": [{"amount": 0, "scriptPublicKey": {"scriptPublicKey": P2SH_HEX}}]
                    })).collect();
                    (
                        "200 OK",
                        serde_json::json!([{"transactions": transactions}]).to_string(),
                    )
                };
                let response = crate::source_observation::fresh_test_response(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()));
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let scanner = ChainScanner::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(BatchProbe::default()),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        )
        .with_bulk_block_hydration();
        let mut candidates: Vec<_> = (0..16)
            .map(|index| CandidateTx {
                tx: RestTransaction {
                    transaction_id: format!("{index:064x}"),
                    outputs: vec![output(P2SH_HEX, None)],
                    ..Default::default()
                },
                acceptance: ChainAcceptance {
                    hash: "cc".repeat(32),
                    blue_score: 100,
                    timestamp: 1_000,
                },
            })
            .collect();
        let mut stats = BatchStats::default();
        tokio::time::timeout(
            Duration::from_secs(5),
            scanner.hydrate_missing_p2sh_metadata(&mut candidates, &mut stats),
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(stats.block_bodies_covered, 16);
        assert_eq!(stats.txs_hydrated, 0);
    }

    #[tokio::test]
    async fn full_block_fallback_fetches_in_parallel_and_applies_score_order() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let txid = "ab".repeat(32);
        let response_txid = txid.clone();
        let server = tokio::spawn(async move {
            let mut streams = BTreeMap::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 2048];
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request);
                let score = if request.contains("blueScore=100") {
                    100
                } else {
                    99
                };
                streams.insert(score, stream);
            }
            for (score, payload) in [(99, "bb"), (100, "aa")] {
                let body = serde_json::json!([{"transactions": [{
                    "verboseData": {"transactionId": response_txid.as_str()},
                    "version": 0,
                    "payload": payload,
                    "outputs": [{"amount": 0, "scriptPublicKey": {"scriptPublicKey": P2SH_HEX}}]
                }]}])
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                streams
                    .get_mut(&score)
                    .unwrap()
                    .write_all(response.as_bytes())
                    .await
                    .unwrap();
                if score == 99 {
                    // The older score completes first; applying responses by
                    // completion order would choose its different payload.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        });
        let scanner = ChainScanner::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(BatchProbe::default()),
            ScannerConfig {
                hydrate_concurrency: 2,
                ..Default::default()
            },
            Box::new(UnusedCursor),
        );
        let mut candidates = vec![CandidateTx {
            tx: RestTransaction {
                transaction_id: txid.clone(),
                outputs: vec![output(P2SH_HEX, None)],
                ..Default::default()
            },
            acceptance: ChainAcceptance {
                hash: "cc".repeat(32),
                blue_score: 100,
                timestamp: 1_000,
            },
        }];
        let covered = tokio::time::timeout(
            Duration::from_secs(2),
            scanner.hydrate_from_full_blocks(
                &mut candidates,
                &[(0, txid)],
                &mut BatchStats::default(),
            ),
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(covered, BTreeSet::from([0]));
        assert_eq!(candidates[0].tx.payload.as_deref(), Some("aa"));
    }

    #[tokio::test]
    async fn dense_prevouts_use_bounded_set_lookups() {
        let persister = Arc::new(BatchProbe::default());
        let scanner = ChainScanner::new(
            RestClient::new("http://127.0.0.1:1").unwrap(),
            persister.clone(),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let candidates: Vec<_> = (0..1_025)
            .map(|index| {
                let mut previous = input(Some(P2SH_HEX));
                previous.previous_outpoint_hash = format!("{index:064x}");
                CandidateTx {
                    tx: tx(vec![previous], vec![]),
                    acceptance: ChainAcceptance {
                        hash: "cc".repeat(32),
                        blue_score: 100,
                        timestamp: 1_000,
                    },
                }
            })
            .collect();
        let backfilled = scanner
            .fetch_missing_p2sh_prevouts(&candidates, &mut BatchStats::default())
            .await
            .unwrap();
        assert!(backfilled.is_empty());
        assert_eq!(*persister.lookup_sizes.lock().unwrap(), vec![512, 512, 1]);
    }

    #[tokio::test]
    async fn two_missing_outputs_from_one_prevout_fetch_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct MissingPrevoutProbe;
        #[async_trait::async_trait]
        impl Persister for MissingPrevoutProbe {
            async fn persist_tx(&self, _tx: &RestTransaction) -> Result<PersistStats> {
                unreachable!()
            }

            async fn revert_block(&self, _block_hash: &[u8]) -> Result<RevertStats> {
                unreachable!()
            }

            async fn has_utxo(&self, _txid_hex: &str, _vout: i32) -> Result<bool> {
                Ok(false)
            }
        }

        let previous_id = "08".repeat(32);
        let mut output_one = output(P2SH_HEX, None);
        output_one.index = 1;
        let previous = RestTransaction {
            transaction_id: previous_id.clone(),
            is_accepted: true,
            accepting_block_hash: Some("bb".repeat(32)),
            accepting_block_blue_score: Some(99),
            accepting_block_time: Some(900),
            outputs: vec![output(P2SH_HEX, None), output_one],
            ..Default::default()
        };
        let body = serde_json::to_string(&previous).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                stream.read(&mut request).await.unwrap();
                server_requests.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let mut first = input(Some(P2SH_HEX));
        first.previous_outpoint_hash = previous_id.clone();
        let mut second = first.clone();
        second.previous_outpoint_index = "1".into();
        let candidate = CandidateTx {
            tx: tx(vec![first, second], vec![]),
            acceptance: ChainAcceptance {
                hash: "cc".repeat(32),
                blue_score: 574487414,
                timestamp: 1_000,
            },
        };
        let scanner = ChainScanner::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(MissingPrevoutProbe),
            ScannerConfig::default(),
            Box::new(UnusedCursor),
        );
        let backfilled = scanner
            .fetch_missing_p2sh_prevouts(&[candidate], &mut BatchStats::default())
            .await
            .unwrap();
        server.abort();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(backfilled.len(), 1);
        tn12_indexer_db::persist::transactions_in_dependency_order(&backfilled).unwrap();
    }
    #[tokio::test]
    async fn missing_or_unaccepted_parent_stops_backfill() {
        use tokio::io::{AsyncReadExt,AsyncWriteExt};
        struct Missing;
        #[async_trait::async_trait]
        impl Persister for Missing {
            async fn persist_tx(&self,_: &RestTransaction)->Result<PersistStats>{unreachable!()}
            async fn revert_block(&self,_: &[u8])->Result<RevertStats>{unreachable!()}
            async fn has_utxo(&self,_: &str,_: i32)->Result<bool>{Ok(false)}
        }
        for status in ["404 Not Found","200 OK"] {
            let id="08".repeat(32);
            let parent=RestTransaction {transaction_id:id.clone(),outputs:vec![output(P2SH_HEX,None)],..Default::default()};
            let body=serde_json::to_string(&parent).unwrap();
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address=listener.local_addr().unwrap();
            let server=tokio::spawn(async move {
                loop {
                    let (mut stream,_)=listener.accept().await.unwrap();
                    let mut buf=[0;4096];stream.read(&mut buf).await.unwrap();
                    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
            });
            let mut previous=input(Some(P2SH_HEX));previous.previous_outpoint_hash=id;
            let candidate=CandidateTx {tx:tx(vec![previous],vec![]),acceptance:ChainAcceptance{hash:"cc".repeat(32),blue_score:100,timestamp:1000}};
            let scanner=ChainScanner::new(RestClient::new(format!("http://{address}")).unwrap(),Arc::new(Missing),ScannerConfig::default(),Box::new(UnusedCursor));
            assert!(scanner.fetch_missing_p2sh_prevouts(&[candidate],&mut BatchStats::default()).await.is_err());
            server.abort();
        }
    }

}

/// Postgres-backed implementation of `CursorStore`.
pub struct PgCursorStore {
    pool: tn12_indexer_db::PgPool,
    key: String,
    fence: Option<tn12_indexer_db::persist::DurableConsumerFence>,
}

impl PgCursorStore {
    pub fn with_consumer_fence(
        mut self,
        fence: tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Self {
        self.fence = Some(fence);
        self
    }

    pub fn new(pool: tn12_indexer_db::PgPool) -> Self {
        Self::with_key(pool, "chain_scan_cursor")
    }

    pub fn with_key(pool: tn12_indexer_db::PgPool, key: impl Into<String>) -> Self {
        Self {
            pool,
            key: key.into(),
            fence: None,
        }
    }
}

#[async_trait::async_trait]
impl CursorStore for PgCursorStore {
    fn with_pool(&self,pool:sqlx::PgPool) -> Result<Box<dyn CursorStore + Send + Sync>> {
        Ok(Box::new(Self {pool,key:self.key.clone(),fence:self.fence.clone()}))
    }
    async fn load(&self) -> Result<Option<u64>> {
        let row: Option<(serde_json::Value,)> =
            sqlx::query_as("SELECT value FROM indexer_state WHERE key = $1")
                .bind(&self.key)
                .fetch_optional(&self.pool)
                .await?;
        let Some((v,)) = row else { return Ok(None) };
        let bs = v
            .get("blue_score")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| anyhow::anyhow!("{} row missing blue_score", self.key))?;
        Ok(Some(bs))
    }

    async fn save(&self, blue_score: u64, rest_database_blue_score: Option<u64>) -> Result<()> {
        let now_ms: i64 = chrono::Utc::now().timestamp_millis();
        let mut value = serde_json::json!({ "blue_score": blue_score });
        if let Some(rest_database_blue_score) = rest_database_blue_score {
            value["rest_database_blue_score"] = serde_json::json!(rest_database_blue_score);
            value["rest_database_observed_at_ms"] = serde_json::json!(now_ms);
        }
        let query = sqlx::query(
            r#"
            INSERT INTO indexer_state(key, value, updated_at_ms)
            VALUES ($1, $2, $3)
            ON CONFLICT (key) DO UPDATE
                SET value = indexer_state.value || EXCLUDED.value,
                    updated_at_ms = EXCLUDED.updated_at_ms
            "#,
        )
        .bind(&self.key)
        .bind(value)
        .bind(now_ms);
        tn12_indexer_db::persist::execute_fenced_metadata(&self.pool, self.fence.as_ref(), query)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod cursor_store_tests {
    use super::*;

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn replaced_consumer_cannot_advance_cursor_or_heartbeat(pool: tn12_indexer_db::PgPool) {
        use tn12_indexer_db::persist::DurableConsumerFence;
        crate::durable_inbox::DurableInbox::open(pool.clone(), "testnet-10:watcher".into(), 1024)
            .await
            .unwrap();
        let first = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let old = PgCursorStore::with_key(pool.clone(), "fenced_live").with_consumer_fence(first);
        old.save(100, None).await.unwrap();
        let next = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let current =
            PgCursorStore::with_key(pool.clone(), "fenced_live").with_consumer_fence(next);
        current.save(200, None).await.unwrap();
        assert!(old.save(300, Some(400)).await.is_err());
        assert_eq!(current.load().await.unwrap(), Some(200));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn cursor_save_preserves_last_observed_tip_when_probe_fails(
        pool: tn12_indexer_db::PgPool,
    ) {
        let store = PgCursorStore::with_key(pool.clone(), "test_scan_cursor");
        store.save(100, Some(150)).await.unwrap();
        store.save(110, None).await.unwrap();

        let value: serde_json::Value =
            sqlx::query_scalar("SELECT value FROM indexer_state WHERE key = 'test_scan_cursor'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(value["blue_score"], 110);
        assert_eq!(value["rest_database_blue_score"], 150);
    }
}
