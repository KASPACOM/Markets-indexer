use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tn12_indexer_core::{RestTransaction, VirtualChainBlock};
use tn12_indexer_db::Persister;
use tn12_indexer_db::SettledRecheckFence;

use crate::scan::PreparedBatch;
use crate::scan::{AcceptanceKey, BatchStats};
use crate::{ChainScanner, CursorStore, RestClient, ScannerConfig};

const SPARSE_PREFETCH_WIDTH: u64 = 100;
const SPARSE_PREFETCH_MAX_BYTES: usize = 8 * 1024 * 1024;
const SPARSE_PREFETCH_MAX_TXS: usize = 1_000;
const SPARSE_PREFETCH_MAX_PREVIOUS_CANDIDATES: u64 = 100;
const SPARSE_PREFETCH_FINALITY_MARGIN: u64 = 1_000;
const WINDOW_FETCH_FINALITY_MARGIN: u64 = 1_000;
const SETTLED_RECHECK_WIDTH: u64 = 100;

#[path = "live_recovery_impact.rs"]
mod recovery_impact;

// A separate task keeps REST reads and JSON decoding moving while the ordered
// database writer awaits its current commit. Dropping the receiver aborts work
// for future windows if the current window fails.
struct WindowFetches {
    receiver: tokio::sync::mpsc::Receiver<Result<(Option<PreparedBatch>, Option<u128>)>>,
    task: tokio::task::JoinHandle<()>,
}

impl WindowFetches {
    fn start<P: Persister + ?Sized + 'static>(
        rest: RestClient,
        scanner: Arc<ChainScanner<P>>,
        starts: Vec<u64>,
        width: u32,
        concurrency: usize,
    ) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(concurrency);
        let task = tokio::spawn(async move {
            // Keep metadata hydration to one window while REST fetches retain
            // their configured lookahead. Hydration can overlap the writer's
            // current ordered commit without multiplying source pressure.
            let hydration = Arc::new(tokio::sync::Semaphore::new(1));
            let fetches = stream::iter(starts.into_iter().map(|start| {
                let rest = rest.clone();
                let scanner = scanner.clone();
                let hydration = hydration.clone();
                async move {
                    let blocks = rest.get_virtual_chain(start, width).await?;
                    let mut prepared = scanner.prepare_blocks(blocks);
                    let hydrate_ms = if let Some(batch) = prepared.as_mut() {
                        let _permit = hydration.acquire().await?;
                        Some(scanner.prehydrate_prepared_metadata(batch).await)
                    } else {
                        None
                    };
                    if let Some(batch) = prepared.as_ref() {
                        scanner.prefetch_prepared_identities(batch).await;
                    }
                    Ok((prepared, hydrate_ms))
                }
            }))
            .buffered(concurrency);
            tokio::pin!(fetches);
            while let Some(result) = fetches.next().await {
                if sender.send(result).await.is_err() {
                    break;
                }
            }
        });
        Self { receiver, task }
    }

    async fn next(&mut self) -> Result<(Option<PreparedBatch>, Option<u128>)> {
        self.receiver
            .recv()
            .await
            .context("REST window fetcher stopped before the ordered window")?
    }
}

impl Drop for WindowFetches {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Clone)]
pub struct TipFollowerConfig {
    pub batch_size: u32,
    pub overlap_windows: u32,
    pub max_catchup_windows: u32,
    pub poll_interval: Duration,
    pub settled_recheck_span_scores: u64,
    pub settled_recheck_min_age_scores: u64,
    pub hydrate_concurrency: usize,
    pub prevout_concurrency: usize,
    pub adaptive_prefetch: bool,
    pub window_fetch_concurrency: usize,
    pub recent_acceptance_reconciliation: bool,
}

impl Default for TipFollowerConfig {
    fn default() -> Self {
        Self {
            batch_size: 10,
            overlap_windows: 2,
            max_catchup_windows: 1_000,
            poll_interval: Duration::from_millis(500),
            settled_recheck_span_scores: 0,
            settled_recheck_min_age_scores: 0,
            hydrate_concurrency: 8,
            prevout_concurrency: 8,
            adaptive_prefetch: false,
            window_fetch_concurrency: 1,
            recent_acceptance_reconciliation: false,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TipFollowerStats {
    pub rest_database_tip: u64,
    pub windows_scanned: u64,
    pub blocks_seen: u64,
    pub p2sh_candidates: u64,
    pub txs_hydrated: u64,
    pub block_bodies_covered: u64,
    pub prevouts_backfilled: u64,
    pub persisted_txs: u64,
    pub already_persisted_txs: u64,
    pub removed_blocks: u64,
}

impl TipFollowerStats {
    fn add_batch(&mut self, stats: BatchStats) {
        self.windows_scanned += 1;
        self.blocks_seen += stats.blocks_seen;
        self.p2sh_candidates += stats.p2sh_candidates;
        self.txs_hydrated += stats.txs_hydrated;
        self.block_bodies_covered += stats.block_bodies_covered;
        self.prevouts_backfilled += stats.prevouts_backfilled;
        self.persisted_txs += stats.txs_persisted;
    }
}

struct PrefetchedPage {
    start: u64,
    windows: BTreeMap<u64, Vec<VirtualChainBlock>>,
    transactions: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("historical preparation paused while canonical recovery owns writes")]
struct HistoricalPreparationPaused;

impl PrefetchedPage {
    fn contains(&self, window_start: u64) -> bool {
        window_start >= self.start
            && window_start < self.start.saturating_add(SPARSE_PREFETCH_WIDTH)
    }
}

fn split_sparse_page(start: u64, blocks: Vec<VirtualChainBlock>) -> Result<PrefetchedPage> {
    let mut windows: BTreeMap<u64, Vec<VirtualChainBlock>> = BTreeMap::new();
    let mut hashes = BTreeSet::new();
    let mut previous_score = start;
    let mut transactions = 0usize;
    for block in blocks {
        anyhow::ensure!(
            block.blue_score >= start
                && block.blue_score < start.saturating_add(SPARSE_PREFETCH_WIDTH)
                && block.blue_score >= previous_score,
            "wide REST page has an out-of-range or unordered block"
        );
        anyhow::ensure!(
            hashes.insert(block.hash.clone()),
            "wide REST page repeats a block"
        );
        previous_score = block.blue_score;
        transactions = transactions.saturating_add(block.transactions.len());
        anyhow::ensure!(
            transactions <= SPARSE_PREFETCH_MAX_TXS,
            "wide REST page exceeds sparse transaction cap"
        );
        let window_start = (block.blue_score / 10) * 10;
        windows.entry(window_start).or_default().push(block);
    }
    Ok(PrefetchedPage {
        start,
        windows,
        transactions,
    })
}

type WindowSignature = BTreeMap<String, (u64, u64, u64, BTreeMap<String, serde_json::Value>)>;

fn window_signature(blocks: &[VirtualChainBlock]) -> Result<WindowSignature> {
    let mut result = BTreeMap::new();
    for block in blocks {
        let mut transactions = BTreeMap::new();
        for tx in &block.transactions {
            anyhow::ensure!(
                transactions
                    .insert(tx.transaction_id.clone(), serde_json::to_value(tx)?)
                    .is_none(),
                "REST page repeats a transaction"
            );
        }
        anyhow::ensure!(
            result
                .insert(
                    block.hash.clone(),
                    (
                        block.blue_score,
                        block.daa_score,
                        block.timestamp,
                        transactions
                    )
                )
                .is_none(),
            "REST page repeats a block"
        );
    }
    Ok(result)
}

#[derive(Default)]
struct TipFailureTracker {
    cursor: Option<u64>,
    since: Option<Instant>,
    consecutive_failures: u64,
}

impl TipFailureTracker {
    fn record(&mut self, cursor: Option<u64>, started: Instant, now: Instant) -> u128 {
        if self.cursor != cursor {
            self.cursor = cursor;
            self.since = None;
            self.consecutive_failures = 0;
        }
        let since = *self.since.get_or_insert(started);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        now.saturating_duration_since(since).as_millis()
    }
}

pub struct ChainTipFollower<P: Persister + ?Sized> {
    scanner: Arc<ChainScanner<P>>,
    settled_scanner: Option<Arc<ChainScanner<P>>>,
    prefetch_rest: RestClient,
    persister: Arc<P>,
    store: PgTipFollowerStore,
    config: TipFollowerConfig,
    settled_recheck_fence: Option<SettledRecheckFence>,
}

impl<P: Persister + ?Sized + 'static> ChainTipFollower<P> {
    pub fn new(
        rest: RestClient,
        persister: Arc<P>,
        pool: tn12_indexer_db::PgPool,
        cursor_key: impl Into<String>,
        config: TipFollowerConfig,
    ) -> Result<Self> {
        anyhow::ensure!(
            matches!(config.batch_size, 10 | 100),
            "TN10 /virtual-chain only accepts batch sizes 10 or 100"
        );
        anyhow::ensure!(
            (1..=16).contains(&config.window_fetch_concurrency),
            "REST window fetch concurrency must be 1..=16"
        );
        anyhow::ensure!(
            !config.adaptive_prefetch || config.window_fetch_concurrency == 1,
            "wide REST prefetch and parallel window fetch cannot be enabled together"
        );
        if config.settled_recheck_span_scores > 0 {
            anyhow::ensure!(
                config.settled_recheck_span_scores
                    > config.settled_recheck_min_age_scores.saturating_add(100),
                "settled recheck span must exceed minimum age by one window"
            );
        }
        let settled_scanner = (config.settled_recheck_span_scores > 0).then(|| {
            Arc::new(
                ChainScanner::new(
                    rest.clone(),
                    persister.clone(),
                    ScannerConfig {
                        batch_size: 100,
                        hydrate_concurrency: config.hydrate_concurrency,
                        prevout_concurrency: config.prevout_concurrency,
                        ..Default::default()
                    },
                    Box::new(NoopCursor),
                )
                .with_bulk_block_hydration(),
            )
        });
        let prefetch_rest = rest.clone();
        let mut scanner = ChainScanner::new(
            rest,
            persister.clone(),
            ScannerConfig {
                batch_size: config.batch_size,
                hydrate_concurrency: config.hydrate_concurrency,
                prevout_concurrency: config.prevout_concurrency,
                ..Default::default()
            },
            Box::new(NoopCursor),
        )
        .with_bulk_block_hydration();
        if config.recent_acceptance_reconciliation {
            scanner = scanner.with_recent_acceptance_reconciliation();
        }
        Ok(Self {
            scanner: Arc::new(scanner),
            settled_scanner,
            prefetch_rest,
            persister,
            store: PgTipFollowerStore::new(pool, cursor_key),
            config,
            settled_recheck_fence: None,
        })
    }

    pub fn with_settled_recheck_fence(mut self, fence: SettledRecheckFence) -> Self {
        self.settled_recheck_fence = Some(fence);
        self
    }

    /// Re-read a durable live intent from canonical REST without advancing any
    /// normal live or historical cursor. The caller retains the intent on error.
    pub async fn recover_live_window(
        &self,
        window: &mut crate::live_recovery::LiveWriteWindow,
        journal: &dyn crate::live_recovery::LiveWriteJournal,
    ) -> Result<()> {
        window.validate()?;
        let width = self.config.batch_size.max(1) as u64;
        anyhow::ensure!(
            matches!(width, 10 | 100),
            "unsupported recovery window width"
        );
        if let Some(recorded_width) = window.window_width {
            anyhow::ensure!(u64::from(recorded_width) == width,
                "recovery window width changed; retain intent and resume with its recorded width");
        }
        while !window.unresolved_blocks.is_empty() {
            let requested:Vec<_>=window.unresolved_blocks.iter().take(32).cloned().collect();
            let blocks=self.prefetch_rest.event_block_coordinates(&requested).await?;
            anyhow::ensure!(blocks.len()==requested.len(),"incomplete event coordinate evidence");
            let mut resolved=window.clone();
            for (expected,(hash,score)) in requested.iter().zip(blocks) {
                anyhow::ensure!(hash==hex::decode(expected)?,"event block identity changed");
                resolved.observed_blocks.entry(score/width*width).or_default().insert(expected.clone());
            }
            resolved.unresolved_blocks.drain(..requested.len());
            resolved.window_width=Some(width as u32);
            resolved.validate()?;
            journal.replace(window,&resolved).await?;
            *window=resolved;
        }
        if let Some(recorded_width) = window.window_width {
            anyhow::ensure!(
                window.observed_blocks.is_empty() || u64::from(recorded_width) == width,
                "recovery window width changed; retain intent and resume with its recorded width"
            );
        } else {
            // Older journals did not persist width. Prove each stored hash lies
            // within the page we will read before treating any hash as removed.
            for (start, hashes) in &window.observed_blocks {
                let end = start
                    .checked_add(width)
                    .context("recovery range overflow")?;
                for hash in hashes {
                    let evidence = self.prefetch_rest.recovery_block_evidence(hash).await?;
                    anyhow::ensure!(evidence.blue_score >= *start && evidence.blue_score < end,
                        "legacy recovery hash outside current window; retain intent for full-range recovery");
                }
            }
        }
        if let (Some(key), Some(_writer)) =
            (journal.intent_key(), self.persister.paged_recovery_writer())
        {
            if tn12_indexer_db::persist::PagedRecoveryOwner::plan_exists(&self.store.pool, key)
                .await?
            {
                let tip = self.scanner.rest_database_tip().await?;
                return self
                    .run_paged_live_recovery(journal, window, &BTreeSet::new(), tip, width)
                    .await;
            }
        }
        let mut prior = window.observed_blocks.clone();
        for tx in &window.transactions {
            let score = tx.accepting_block_blue_score.unwrap();
            prior
                .entry(score / width * width)
                .or_default()
                .insert(tx.accepting_block_hash.clone().unwrap());
        }
        let tip = self.scanner.rest_database_tip().await?;
        let last = *prior.keys().next_back().context("empty recovery window")?;
        if tip <= window_end(last,width) {
            return Err(crate::live_supervisor::RecoveryPending("REST has not published the complete live repair window yet").into());
        }
        // Most intents have not reorged. Verify their acceptance coordinates
        // against canonical REST windows in bulk; only missing transactions
        // need individual lookups to detect a move or rejection.
        let mut prepared_by_start = BTreeMap::new();
        for start in prior.keys().copied() {
            prepared_by_start.insert(start, self.scanner.prepare_recovery_batch(start, &window.transactions).await?);
        }
        let coordinates_by_start: BTreeMap<_, _> = prepared_by_start
            .iter()
            .map(|(start, prepared)| {
                (
                    *start,
                    prepared
                        .as_ref()
                        .map(PreparedBatch::acceptance_coordinates)
                        .unwrap_or_default(),
                )
            })
            .collect();
        let mut current = window.transactions.clone();
        let mut missing = Vec::new();
        for (index, tx) in current.iter().enumerate() {
            let start = tx.accepting_block_blue_score.unwrap() / width * width;
            if !coordinates_by_start
                .get(&start)
                .is_some_and(|coordinates| contains_acceptance(coordinates, tx))
            {
                missing.push(index);
            }
        }
        let missing_txs: Vec<_> = missing
            .iter()
            .map(|&index| current[index].clone())
            .collect();
        let resolved = self.fetch_current_acceptances(&missing_txs).await?;
        for (index, tx) in missing.into_iter().zip(resolved) {
            current[index] = tx;
        }
        // An equivalent accepting-block replacement only moves references;
        // its descendants do not need to be removed and replayed. Prove that
        // narrow case before building the potentially large removal closure.
        // Keep the retained intent until the normal final replay verification.
        let stale = self.persister.stale_persisted_acceptances(&current).await?;
        let mut replacement_pairs = BTreeMap::new();
        for stored in stale {
            let source = current.iter().find(|tx| tx.transaction_id == stored.spender_txid)
                .context("stale persisted acceptance is absent from retained recovery")?;
            let incoming_hash = source.accepting_block_hash.as_ref()
                .context("accepted recovery transaction has no accepting block")?;
            replacement_pairs.entry((stored.block_hash, incoming_hash.clone()))
                .or_insert(stored.spender_txid);
        }
        if replacement_pairs.len() <= 16 {
            for ((persisted_hash, incoming_hash), transaction_id) in replacement_pairs {
                let source = current.iter().find(|tx| tx.transaction_id == transaction_id)
                    .context("stale persisted acceptance is absent from retained recovery")?;
                let conflict = tn12_indexer_db::persist::AcceptanceConflict {
                    transaction_id,
                    persisted_hash,
                    incoming_hash: incoming_hash.clone(),
                };
                match self.prefetch_rest.verify_recent_canonical_block_replacement(&conflict).await {
                    Ok(proof) => {
                        if let Some(writer)=self.persister.paged_recovery_writer() {
                            crate::rest_replay_fence::for_replacement(writer,&self.prefetch_rest,&proof).await?
                                .reconcile_accepting_block(&proof).await?;
                        } else {
                            self.persister.reconcile_accepting_block(&proof).await?;
                        }
                        let after = self.prefetch_rest
                            .get_transaction_with_explicit_acceptance(&conflict.transaction_id).await?;
                        anyhow::ensure!(after.is_accepted
                            && after.accepting_block_hash.as_deref() == Some(incoming_hash.as_str())
                            && after.accepting_block_blue_score == source.accepting_block_blue_score,
                            crate::live_supervisor::RecoveryPending(
                                "source acceptance changed after equivalent replacement"
                            ));
                    }
                    Err(error) if error.downcast_ref::<tn12_indexer_db::persist::NonEquivalentBlockEvidence>().is_some()
                        || error.downcast_ref::<crate::rpc::rest::RestStatusError>()
                            .is_some_and(|status| status.status == reqwest::StatusCode::NOT_FOUND) => {
                        // A split or REST-pruned orphan cannot establish the
                        // shortcut. Full dependency recovery below must still
                        // prove canonicality, using node evidence for orphans.
                    }
                    Err(error) => match crate::recovery_policy::classify(&error) {
                        crate::recovery_policy::Decision::Retry(reason) => {
                            return Err(error.context(crate::live_supervisor::RecoveryPending(reason)));
                        }
                        _ => return Err(error).context(
                            "canonical acceptance proof unavailable; retaining recovery intent",
                        ),
                    },
                }
            }
        }
        // A replacement spend can arrive before the removal notification for
        // the block that held the previous spender. That old block is outside
        // this intent's acceptance coordinates, so discover it from the inputs
        // before deciding which canonical source windows to replay.
        let mut affected_ids: BTreeSet<String> =
            window.affected_transaction_ids.iter().cloned().collect();
        let mut removed_roots = BTreeSet::new();
        let mut displaced_spenders = Vec::new();
        let mut displaced: Vec<_> = self.persister.conflicting_input_spends(&current).await?
            .into_iter().map(|conflict| (conflict, true)).collect();
        displaced.extend(self.persister.stale_persisted_acceptances(&current).await?
            .into_iter().map(|conflict| (conflict, false)));
        displaced.sort();
        displaced.dedup();
        for (conflict, must_be_rejected) in displaced {
            let block = self
                .prefetch_rest
                .recovery_block_evidence(&conflict.block_hash)
                .await?;
            anyhow::ensure!(
                block.hash == hex::decode(&conflict.block_hash)?
                    && block.blue_score == conflict.block_blue_score,
                "conflicting spend block disagrees with persisted identity"
            );
            if block.is_chain_block {
                return Err(crate::live_supervisor::RecoveryPending(
                    "conflicting spend block is still canonical"
                )
                .into());
            }
            let spender = self
                .prefetch_rest
                .get_transaction_with_explicit_acceptance(&conflict.spender_txid)
                .await?;
            anyhow::ensure!(
                spender.transaction_id == conflict.spender_txid,
                "conflicting spend transaction identity changed"
            );
            if must_be_rejected && spender.is_accepted {
                return Err(crate::live_supervisor::RecoveryPending(
                    "conflicting spend is still accepted"
                )
                .into());
            }
            if !must_be_rejected && (!spender.is_accepted
                || !current.iter().any(|tx| tx.transaction_id == spender.transaction_id
                    && tx.accepting_block_hash == spender.accepting_block_hash
                    && tx.accepting_block_blue_score == spender.accepting_block_blue_score)) {
                return Err(crate::live_supervisor::RecoveryPending(
                    "stored acceptance changed at source during recovery"
                ).into());
            }
            removed_roots.insert(conflict.block_hash.clone());
            displaced_spenders.push((conflict.block_hash.clone(), conflict.spender_txid));
            prior
                .entry(conflict.block_blue_score / width * width)
                .or_default()
                .insert(conflict.block_hash);
        }
        // Reorg-only intents have no retained transactions. Inspect every
        // observed block absent from its canonical page before selecting a
        // replay subset, or removing it could silently lose moved siblings.
        let mut discovered_blocks = BTreeMap::new();
        for (start, previous_blocks) in &prior {
            if tip <= window_end(*start, width) {
                return Err(crate::live_supervisor::RecoveryPending(
                    "REST has not published the complete live repair window yet"
                ).into());
            }
            let prepared = if let Some(prepared) = prepared_by_start.remove(start) {
                prepared
            } else {
                self.scanner.prepare_recovery_batch(*start, &window.transactions).await?
            };
            let canonical = prepared.as_ref().map(PreparedBatch::block_hashes).unwrap_or_default();
            discovered_blocks.insert(*start, canonical.clone());
            for hash in previous_blocks.difference(&canonical) {
                let block = self.prefetch_rest.recovery_block_evidence(hash).await?;
                anyhow::ensure!(block.hash == hex::decode(hash)?
                    && block.blue_score >= *start && block.blue_score <= window_end(*start, width),
                    "removed live block identity disagrees with source");
                if block.is_chain_block {
                    return Err(crate::live_supervisor::RecoveryPending(
                        "observed block remains canonical but is missing from source page"
                    ).into());
                }
                removed_roots.insert(hash.clone());
            }
            prepared_by_start.insert(*start, prepared);
        }
        // Include dependent blocks even when still canonical. Their outputs
        // must be removed before their parent and restored from source evidence.
        let (removal_impacts, dependency_blocks) =
            match self.discover_recovery_impacts(&removed_roots, tip, width).await {
                Ok(result) => result,
                Err(error)
                    if self.persister.paged_recovery_writer().is_some()
                        && journal.intent_key().is_some()
                        && !removed_roots.is_empty()
                        && (error.is::<tn12_indexer_db::persist::RecoveryImpactLimit>()
                            || error.downcast_ref::<crate::recovery_policy::RecoveryBlocked>()
                                .is_some_and(|blocked| matches!(blocked.0,
                                    "affected_block_limit" | "affected_transaction_limit"))) =>
                {
                    return self
                        .run_paged_live_recovery(journal, window, &removed_roots, tip, width)
                        .await;
                }
                Err(error) => return Err(error),
            };
        for (hash, id) in displaced_spenders {
            anyhow::ensure!(removal_impacts.iter().any(|impact|
                impact.block_hash == hash && impact.transaction_ids.contains(&id)),
                tn12_indexer_db::persist::RecoveryReplanRequired("displaced spender changed during discovery"));
        }
        for impact in &removal_impacts {
            affected_ids.extend(impact.transaction_ids.iter().cloned());
        }
        if affected_ids.len() > 256
            && self.persister.paged_recovery_writer().is_some()
            && journal.intent_key().is_some()
            && !removed_roots.is_empty()
        {
            return self
                .run_paged_live_recovery(journal, window, &removed_roots, tip, width)
                .await;
        }
        anyhow::ensure!(affected_ids.len() <= 256,
            crate::recovery_policy::RecoveryBlocked("affected_transaction_limit"));
        for (start, hashes) in dependency_blocks {
            prior.entry(start).or_default().extend(hashes);
        }
        let affected_requests: Vec<_> = affected_ids.iter().map(|transaction_id| RestTransaction {
            transaction_id: transaction_id.clone(),
            ..Default::default()
        }).collect();
        let affected_now = self.fetch_current_acceptances(&affected_requests).await?;
        if !affected_requests.is_empty() {
            // Earlier pages were prepared before the affected transaction IDs
            // were known. Rebuild them with the complete retained set.
            prepared_by_start.clear();
        }
        let affected_coordinates: BTreeMap<_, _> = affected_now.iter().map(|tx| (
            tx.transaction_id.clone(),
            (tx.is_accepted, tx.accepting_block_hash.clone(), tx.accepting_block_blue_score),
        )).collect();
        let mut replay_bodies = BTreeMap::new();
        for tx in current.iter().chain(&affected_now).filter(|tx| !tx.is_accepted) {
            // REST may explicitly reject a transaction without returning its
            // old body or acceptance coordinates. Keep that prior evidence in
            // the journal, separately from the current source observation.
            let previous = window.transactions.iter().chain(&window.rejected_transactions)
                .find(|body| body.transaction_id == tx.transaction_id);
            let retained = if tx.accepting_block_hash.is_none()
                && tx.accepting_block_blue_score.is_none()
                && tx.accepting_block_time.is_none()
            {
                previous.map(|body| {
                    let mut body = body.clone();
                    body.is_accepted = false;
                    body
                })
            } else { None };
            recovery_impact::retain_body(&mut replay_bodies, retained.as_ref().unwrap_or(tx))?;
        }
        for tx in affected_now {
            if let Some(existing) = current.iter_mut().find(|candidate| candidate.transaction_id == tx.transaction_id) {
                *existing = tx.clone();
            } else if tx.is_accepted {
                current.push(tx.clone());
            }
            if tx.is_accepted {
                let score = tx.accepting_block_blue_score.context("affected transaction acceptance score missing")?;
                prior.entry(score / width * width).or_default();
            }
        }
        let mut required: BTreeMap<u64, BTreeSet<AcceptanceKey>> = BTreeMap::new();
        for tx in &current {
            if tx.is_accepted {
                let score = tx
                    .accepting_block_blue_score
                    .context("repair source missing acceptance score")?;
                let hash = tx
                    .accepting_block_hash
                    .clone()
                    .context("repair source missing acceptance hash")?;
                let start = score / width * width;
                prior.entry(start).or_default();
                required.entry(start).or_default().insert(AcceptanceKey {
                    transaction_id: tx.transaction_id.clone(),
                    block_hash: hash,
                });
            }
        }
        let last = *prior.keys().next_back().context("empty recovery window")?;
        if tip <= window_end(last,width) {
            return Err(crate::live_supervisor::RecoveryPending("REST has not published the complete live repair window yet").into());
        }
        let mut updated = window.clone();
        updated.window_width = Some(width as u32);
        affected_ids.extend(current.iter().map(|tx| tx.transaction_id.clone()));
        anyhow::ensure!(affected_ids.len() <= 256,
            crate::recovery_policy::RecoveryBlocked("affected_transaction_limit"));
        updated.affected_transaction_ids = affected_ids.into_iter().collect();
        let target_txids: BTreeSet<_> = current.iter().filter(|tx| tx.is_accepted)
            .map(|tx| tx.transaction_id.clone()).collect();
        for tx in current.iter().filter(|tx| tx.is_accepted) {
            if !updated.transactions.iter().any(|original| original.transaction_id == tx.transaction_id) {
                updated.transactions.push(tx.clone());
            }
        }
        let mut validated = Vec::new();
        let mut canonical_blocks_before = BTreeMap::new();
        let mut dependency_bodies = BTreeMap::new();
        let mut dependency_bytes = 0usize;
        for (start, previous_blocks) in prior {
            let mut prepared = if let Some(prepared) = prepared_by_start.remove(&start) {
                prepared
            } else {
                self.scanner.prepare_recovery_batch(start, &updated.transactions).await?
            };
            if let Some(batch) = prepared.as_mut() {
                // The page supplies canonical block membership, but replay only
                // journaled transactions and displaced siblings. Replaying
                // unrelated page traffic can create an unbounded dependency
                // chain and block the live writer's retained intent.
                let selected: BTreeSet<_> = batch.acceptance_keys().into_iter()
                    .filter(|key| target_txids.contains(&key.transaction_id)).collect();
                batch.retain_acceptances(&selected);
                let parents = match self.scanner.prepare_recovery_dependencies(batch).await {
                    Ok(parents) => parents,
                    Err(error)
                        if error.is::<crate::recovery_policy::RecoveryCapacity>()
                            && self.persister.paged_recovery_writer().is_some()
                            && journal.intent_key().is_some()
                            && !removed_roots.is_empty() =>
                    {
                        return self
                            .run_paged_live_recovery(journal, window, &removed_roots, tip, width)
                            .await;
                    }
                    Err(error) => return Err(error),
                };
                for parent in parents {
                    let parent_score = parent.accepting_block_blue_score.context("dependency acceptance score missing")?;
                    if tip <= window_end(parent_score / width * width, width) {
                        return Err(crate::live_supervisor::RecoveryPending("dependency acceptance window is not published yet").into());
                    }
                    updated.observed_blocks.entry(parent_score / width * width).or_default()
                        .insert(parent.accepting_block_hash.clone().context("dependency acceptance hash missing")?);
                    if !updated.transactions.iter().any(|tx| tx.transaction_id == parent.transaction_id) {
                        updated.transactions.push(parent.clone());
                    }
                    if let Some(previous) = dependency_bodies.get(&parent.transaction_id) {
                        if serde_json::to_value(previous)? != serde_json::to_value(&parent)? {
                            return Err(crate::live_supervisor::RecoveryPending("dependency changed between recovery windows").into());
                        }
                    } else {
                        dependency_bytes = dependency_bytes.saturating_add(serde_json::to_vec(&parent)?.len());
                        crate::recovery_policy::check_capacity("recovery_dependency_count", dependency_bodies.len() + 1, 256)?;
                        crate::recovery_policy::check_capacity("recovery_dependency_bytes", dependency_bytes, 16 * 1024 * 1024)?;
                        dependency_bodies.insert(parent.transaction_id.clone(), parent);
                    }
                }
            }
            if let Some(batch) = &prepared {
                for tx in batch.recovery_bodies() {
                    recovery_impact::retain_body(&mut replay_bodies, tx)?;
                }
            }
            let keys = prepared
                .as_ref()
                .map(|p| p.acceptance_keys())
                .unwrap_or_default();
            let expected = required.remove(&start).unwrap_or_default();
            anyhow::ensure!(
                expected.is_subset(&keys),
                crate::live_supervisor::RecoveryPending(
                    "canonical repair page omits required accepted transactions"
                )
            );
            let current_blocks = prepared
                .as_ref()
                .map(|p| p.block_hashes())
                .unwrap_or_default();
            if discovered_blocks.get(&start).is_some_and(|discovered| discovered != &current_blocks) {
                return Err(crate::live_supervisor::RecoveryPending(
                    "canonical block membership changed after impact discovery"
                ).into());
            }
            canonical_blocks_before.insert(start, current_blocks.clone());
            updated
                .observed_blocks
                .entry(start)
                .or_default()
                .extend(previous_blocks.iter().cloned());
            updated
                .observed_blocks
                .entry(start)
                .or_default()
                .extend(current_blocks.iter().cloned());
            let removed: Vec<_> = previous_blocks
                .difference(&current_blocks)
                .cloned()
                .collect();
            validated.push((removed, prepared, expected));
        }
        // Persist every potentially written block before mutation. If replay
        // itself has an uncertain outcome or a later reorg, its blocks survive
        // restart and are reconciled on the next attempt too.
        for tx in &current {
            let captured = replay_bodies.get(&tx.transaction_id)
                .context("recovery journal lacks a required transaction body")?;
            anyhow::ensure!(captured.is_accepted == tx.is_accepted
                && (!tx.is_accepted || (captured.accepting_block_hash == tx.accepting_block_hash
                    && captured.accepting_block_blue_score == tx.accepting_block_blue_score)),
                crate::live_supervisor::RecoveryPending("acceptance changed while preparing recovery journal"));
        }
        updated.transactions = replay_bodies.values().filter(|tx| tx.is_accepted).cloned().collect();
        updated.rejected_transactions = replay_bodies.into_values().filter(|tx| !tx.is_accepted).collect();
        updated.validate()?;
        anyhow::ensure!(serde_json::to_vec(&updated)?.len() <= 32 * 1024 * 1024,
            crate::recovery_policy::RecoveryBlocked("journal_byte_limit"));
        journal.replace(window, &updated).await?;
        *window = updated;
        // Atomic dependency-ordered removals recheck the entire indexed
        // footprint under the writer lock. Changed plans retain this journal.
        self.persister.revert_recovery_blocks(&removal_impacts).await?;
        for (_, prepared, expected) in validated {
            if let Some(prepared) = prepared {
                let persisted = self.scanner.persist_prepared(prepared).await?;
                anyhow::ensure!(
                    expected.is_subset(&persisted.persisted_acceptances),
                    "canonical repair did not persist every required acceptance"
                );
            }
        }
        for parent in dependency_bodies.values() {
            let after = self.prefetch_rest.get_transaction_with_explicit_acceptance(&parent.transaction_id).await?;
            if !after.is_accepted || after.accepting_block_hash != parent.accepting_block_hash
                || after.accepting_block_blue_score != parent.accepting_block_blue_score
                || after.accepting_block_time != parent.accepting_block_time {
                return Err(crate::live_supervisor::RecoveryPending("dependency acceptance changed during recovery").into());
            }
        }
        // Recheck both original and moved-to windows after the write. A change
        // to any journaled acceptance retains the intent for another pass.
        let mut after_by_start = BTreeMap::new();
        let recheck_starts: BTreeSet<_> = window
            .transactions
            .iter()
            .chain(&current)
            .filter_map(|tx| {
                tx.accepting_block_blue_score
                    .map(|score| score / width * width)
            })
            .chain(canonical_blocks_before.keys().copied())
            .chain(dependency_bodies.values().filter_map(|parent| parent.accepting_block_blue_score.map(|score| score / width * width)))
            .collect();
        for start in recheck_starts {
            if let std::collections::btree_map::Entry::Vacant(entry) = after_by_start.entry(start) {
                entry.insert(self.scanner.prepare_recovery_batch(start, &window.transactions).await?);
            }
        }
        for (start, before) in &canonical_blocks_before {
            let after = after_by_start
                .get(start)
                .and_then(Option::as_ref)
                .map(PreparedBatch::block_hashes)
                .unwrap_or_default();
            if *before != after {
                return Err(crate::live_supervisor::RecoveryPending("canonical source changed during live recovery").into());
            }
        }
        let after_coordinates: BTreeMap<_, _> = after_by_start
            .iter()
            .map(|(start, prepared)| {
                (
                    *start,
                    prepared
                        .as_ref()
                        .map(PreparedBatch::acceptance_coordinates)
                        .unwrap_or_default(),
                )
            })
            .collect();
        for parent in dependency_bodies.values() {
            if !parent.accepting_block_blue_score
                .and_then(|score| after_coordinates.get(&(score / width * width)))
                .is_some_and(|coordinates| contains_acceptance(coordinates, parent)) {
                return Err(crate::live_supervisor::RecoveryPending("dependency omitted from canonical recovery window").into());
            }
        }
        let affected_after = self.fetch_current_acceptances(&affected_requests).await?;
        for tx in affected_after {
            let before = affected_coordinates.get(&tx.transaction_id).context("missing affected transaction observation")?;
            if before != &(tx.is_accepted, tx.accepting_block_hash, tx.accepting_block_blue_score) {
                return Err(crate::live_supervisor::RecoveryPending("affected transaction acceptance changed during recovery").into());
            }
        }
        let missing_after: Vec<_> = current
            .iter()
            .filter(|before| {
                !before
                    .accepting_block_blue_score
                    .and_then(|score| after_coordinates.get(&(score / width * width)))
                    .is_some_and(|coordinates| contains_acceptance(coordinates, before))
            })
            .cloned()
            .collect();
        let mut after_missing = self
            .fetch_current_acceptances(&missing_after)
            .await?
            .into_iter();
        for before in &current {
            let matched = before
                .accepting_block_blue_score
                .and_then(|score| after_coordinates.get(&(score / width * width)))
                .is_some_and(|coordinates| contains_acceptance(coordinates, before));
            if matched {
                continue;
            }
            let after = after_missing.next().context("missing recovery recheck")?;
            if !(after.transaction_id == before.transaction_id
                    && after.is_accepted == before.is_accepted
                    && after.accepting_block_hash == before.accepting_block_hash
                    && after.accepting_block_blue_score == before.accepting_block_blue_score) {
                return Err(crate::live_supervisor::RecoveryPending("canonical source changed during live recovery").into());
            }
        }
        Ok(())
    }

    async fn fetch_current_acceptances(
        &self,
        transactions: &[RestTransaction],
    ) -> Result<Vec<RestTransaction>> {
        let concurrency = self.config.hydrate_concurrency.clamp(1, 16);
        stream::iter(transactions.iter().map(|original| {
            let rest = self.prefetch_rest.clone();
            let expected_id = original.transaction_id.clone();
            async move {
                let tx = rest
                    .get_transaction_with_explicit_acceptance(&expected_id)
                    .await?;
                anyhow::ensure!(
                    tx.transaction_id == expected_id,
                    "repair transaction identity changed"
                );
                Ok(tx)
            }
        }))
        .buffered(concurrency)
        .try_collect()
        .await
    }

    pub async fn run_forever(&self) -> Result<()> {
        tokio::select! {
            result = self.run_catchup(None) => result,
            result = self.observe_rest_forever() => result,
        }
    }

    /// Stop after a committed cursor reaches a source-overlap boundary. The
    /// caller can then construct a follower for the next REST source using
    /// the same durable cursor and database writer.
    pub async fn run_until_blue_score(&self, boundary: u64) -> Result<()> {
        tokio::select! {
            result = self.run_catchup(Some(boundary)) => result,
            result = self.observe_rest_forever() => result,
        }
    }

    async fn observe_rest_forever(&self) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match self.scanner.rest_database_tip().await {
                Ok(tip) => {
                    let observed_at_ms = chrono::Utc::now().timestamp_millis();
                    if let Err(error) = self
                        .store
                        .record_rest_observation(tip, observed_at_ms)
                        .await
                    {
                        tracing::warn!(target: "tip-follower", "REST tip observation write failed: {error:#}");
                    }
                }
                Err(error) => {
                    tracing::warn!(target: "tip-follower", "REST tip observation failed: {error:#}")
                }
            }
        }
    }

    async fn run_catchup(&self, stop_at: Option<u64>) -> Result<()> {
        let mut state = self.store.load_state().await?;
        if let Some(boundary) = stop_at {
            anyhow::ensure!(
                state.cursor_blue_score.is_some(),
                "source handoff requires a durable replay cursor"
            );
            if state
                .cursor_blue_score
                .is_some_and(|cursor| cursor >= boundary)
            {
                return Ok(());
            }
        }
        let mut failures = TipFailureTracker::default();
        loop {
            let started = Instant::now();
            match self.run_once(&mut state).await {
                Ok(stats) => {
                    if failures.consecutive_failures > 0 {
                        tracing::info!(target: "tip-follower", event = "tip_window_retry_recovered",
                            cursor_blue_score = ?state.cursor_blue_score,
                            consecutive_failures = failures.consecutive_failures,
                            "historical scan recovered after retained-window retries");
                    }
                    failures = TipFailureTracker::default();
                    tracing::info!(
                        target: "tip-follower",
                        "tip: rest_database_tip={} windows={} blocks={} p2sh_candidates={} hydrated={} block_bodies_covered={} prevouts_backfilled={} persisted={} already_persisted={} removed_blocks={}",
                        stats.rest_database_tip,
                        stats.windows_scanned,
                        stats.blocks_seen,
                        stats.p2sh_candidates,
                        stats.txs_hydrated,
                        stats.block_bodies_covered,
                        stats.prevouts_backfilled,
                        stats.persisted_txs,
                        stats.already_persisted_txs,
                        stats.removed_blocks,
                    );
                    if stop_at.is_none()
                        && self.config.settled_recheck_span_scores > 0
                        && state.cursor_blue_score.is_some_and(|cursor| {
                            cursor.saturating_add(u64::from(self.config.batch_size) * 2)
                                >= stats.rest_database_tip
                        })
                    {
                        if let Err(error) = self.run_settled_recheck(stats.rest_database_tip, stats.rest_database_tip).await
                        {
                            tracing::warn!(
                                target: "tip-follower",
                                "settled REST recheck retained its window: {error:#}"
                            );
                        }
                    }
                    if stop_at.is_some_and(|boundary| {
                        state
                            .cursor_blue_score
                            .is_some_and(|cursor| cursor >= boundary)
                    }) {
                        return Ok(());
                    }
                }
                Err(error) if error.downcast_ref::<HistoricalPreparationPaused>().is_some() => {
                    tracing::info!(target: "tip-follower", "historical preparation paused by canonical recovery; cursor retained");
                }
                Err(error) => {
                    let retained_window_ms =
                        failures.record(state.cursor_blue_score, started, Instant::now());
                    tracing::warn!(target: "tip-follower", event = "tip_window_retained",
                        cursor_blue_score = ?state.cursor_blue_score,
                        consecutive_failures = failures.consecutive_failures,
                        retained_window_ms,
                        "tip scan failed: {error:#}");
                }
            }
            tokio::time::sleep(self.config.poll_interval.saturating_sub(started.elapsed())).await;
        }
    }

    /// Recheck indexed, settled windows even while the history cursor is
    /// catching up. The durable history cursor bounds the work; live writes
    /// still take priority through the shared database writer lock.
    pub async fn run_settled_recheck_forever(&self) -> Result<()> {
        let fence = self.settled_recheck_fence.as_ref().context("settled worker requires a fence")?;
        anyhow::ensure!(self.config.settled_recheck_span_scores > 0, "settled recheck is disabled");
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            fence.assert_current(&self.store.pool).await?;
            if self.canonical_recovery_owns_writes().await? { continue; }
            let result = async {
                self.prefetch_rest.ensure_current_database_synced().await?;
                let source_tip = self.scanner.rest_database_tip().await?;
                let Some(history_cursor) = self.store.load_cursor_blue_score().await? else {
                    return Ok(());
                };
                let Some(selection_tip) = settled_recheck_selection_tip(
                    source_tip,
                    history_cursor,
                    self.config.settled_recheck_min_age_scores,
                ) else {
                    return Ok(());
                };
                self.retry_one_deferred_decode().await?;
                self.run_settled_recheck(selection_tip, source_tip).await
            }.await;
            if let Err(error) = result {
                fence.assert_current(&self.store.pool).await?;
                tracing::warn!(target: "settled-recheck", "settled window retained: {error:#}");
            }
        }
    }

    async fn retry_one_deferred_decode(&self) -> Result<()> {
        self.check_historical_preparation().await?;
        let Some((sequence, raw)) = tn12_indexer_db::deferred_decode::claim_due(
            &self.store.pool, chrono::Utc::now().timestamp_millis(),
        ).await? else { return Ok(()); };
        let attempt = async {
            let retained: RestTransaction = serde_json::from_value(raw)?;
            self.prefetch_rest.deferred_decode_proof(&retained, "testnet-10").await?;
            let mut writer = tn12_indexer_db::PgPersister::for_genesis_repair(self.store.pool.clone());
            if let Some(fence) = &self.settled_recheck_fence {
                writer = writer.with_settled_recheck_fence(fence.clone());
            }
            let guarded = crate::rest_replay_fence::for_transactions(
                &writer, &self.prefetch_rest, std::slice::from_ref(&retained),
            ).await?;
            guarded.replay_deferred_tx(&retained).await?;
            let proof = self.prefetch_rest.deferred_decode_proof(&retained, "testnet-10").await?;
            writer.confirm_deferred_decode(&proof).await
        }.await;
        if let Err(error) = attempt {
            if let Some(fence) = &self.settled_recheck_fence { fence.assert_current(&self.store.pool).await?; }
            tn12_indexer_db::deferred_decode::record_retry_error(&self.store.pool,sequence,&format!("{error:#}")).await?;
            tracing::warn!(target: "deferred-decode", sequence, "retained decoding retry: {error:#}");
        }
        Ok(())
    }

    async fn run_settled_recheck(&self, selection_tip: u64, source_tip: u64) -> Result<()> {
        self.check_historical_preparation().await?;
        let width = SETTLED_RECHECK_WIDTH;
        let mut writer = tn12_indexer_db::PgPersister::for_genesis_repair(self.store.pool.clone());
        if let Some(fence) = &self.settled_recheck_fence {
            writer = writer.with_settled_recheck_fence(fence.clone());
        }
        let root = &self.store.cursor_key;
        let retry=writer.due_history_retry(root,selection_tip,self.config.settled_recheck_min_age_scores).await?;
        let (work_key,window,next)=if let Some((key,window))=retry {
            (key,window,window.checked_add(width).context("retry window overflow")?)
        } else {
            let scheduled:Option<i64>=sqlx::query_scalar("SELECT next_window FROM settled_history_schedule WHERE cursor_key=$1")
                .bind(root).fetch_optional(&self.store.pool).await?;
            let saved=match scheduled {Some(value)=>Some(u64::try_from(value)?),None=>self.store.load_settled_recheck_next().await?};
            let Some((window,next))=settled_recheck_window(selection_tip,width,self.config.settled_recheck_span_scores,self.config.settled_recheck_min_age_scores,saved) else {return Ok(())};
            if writer.retained_history_window(root,window,next).await? {return Ok(())}
            (root.clone(),window,next)
        };
        let key=&work_key;
        let job = writer.prepare_settled_repair(key, window, width).await?;
        if job.next_retry_at_ms > chrono::Utc::now().timestamp_millis() {
            return Ok(());
        }
        let selected_window = window;
        let window = u64::try_from(job.window_start)?;
        if !settled_job_eligible(
            selection_tip,
            self.config.settled_recheck_min_age_scores,
            window,
            width,
        ) {
            // The durable job may predate the selected cursor. Wait for both
            // history and source to cover it again after a tip regression.
            return Ok(());
        }
        let next = resumed_settled_next(selected_window, window, next, width);
        let mut reconciliation_step_failed = false;
        let result = async {
            if job.phase == "replay" {
                self.settled_scanner
                    .as_ref()
                    .context("settled recheck scanner is disabled")?
                    .replay_window(window)
                    .await
                    .with_context(|| format!("replay settled window {window}"))?;
                if !writer.acknowledge_settled_replay(key, job.epoch).await? {
                    return Ok(());
                }
            }
            let slice = Instant::now();
            while !writer.discover_settled_members(key).await? {
                if slice.elapsed() >= Duration::from_millis(250) {
                    return Ok(());
                }
                tokio::task::yield_now().await;
            }
            // Yield between commits; near-tip repair runs before the next slice.
            loop {
                let step = writer.step_settled_repair(key, next, source_tip).await;
                reconciliation_step_failed = step.is_err();
                if step? {
                    tracing::info!(target: "tip-follower", window,
                        "settled REST replay and genesis reconciliation committed");
                    break;
                }
                if slice.elapsed() >= Duration::from_millis(250)
                    || tn12_indexer_db::persist::genesis::retry_pending(&self.store.pool, key).await? {
                    break;
                }
                tokio::task::yield_now().await;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = &result {
            if let Some(missing)=error.downcast_ref::<crate::scan::MissingHistoricalWindow>() {
                if writer.defer_missing_history(root,key,job.epoch,next,&missing.missing_txid,&missing.endpoint,&missing.evidence,&format!("{error:#}")).await? {
                    tracing::warn!(target:"settled-recheck",window,missing_txid=%missing.missing_txid,
                        "historical window retained as unverified; scheduling independent work");
                    return Ok(());
                }
            }
            if reconciliation_step_failed {
                writer
                    .retain_settled_reconciliation_error(key, error)
                    .await?;
            } else {
                writer.retain_settled_error(key, error).await?;
            }
        }
        result
    }

    async fn maybe_prefetch_sparse_page(
        &self,
        start: u64,
        tip: u64,
        previous_candidates: Option<u64>,
    ) -> Option<PrefetchedPage> {
        if !self.config.adaptive_prefetch
            || self.config.batch_size != 10
            || start % SPARSE_PREFETCH_WIDTH != 0
            || tip
                < start
                    .saturating_add(SPARSE_PREFETCH_WIDTH)
                    .saturating_add(SPARSE_PREFETCH_FINALITY_MARGIN)
            || !previous_candidates
                .is_some_and(|count| count <= SPARSE_PREFETCH_MAX_PREVIOUS_CANDIDATES)
        {
            return None;
        }

        let wide = match self
            .prefetch_rest
            .get_virtual_chain_bounded(
                start,
                SPARSE_PREFETCH_WIDTH as u32,
                SPARSE_PREFETCH_MAX_BYTES,
            )
            .await
        {
            Ok(blocks) => blocks,
            Err(error) => {
                tracing::debug!(target: "tip-follower", start, "wide REST page unavailable, using ten-score windows: {error:#}");
                return None;
            }
        };
        let page = match split_sparse_page(start, wide) {
            Ok(page) => page,
            Err(error) => {
                tracing::debug!(target: "tip-follower", start, "wide REST page rejected, using ten-score windows: {error:#}");
                return None;
            }
        };
        for edge_start in [start, start + SPARSE_PREFETCH_WIDTH - 10] {
            let narrow = match self.prefetch_rest.get_virtual_chain(edge_start, 10).await {
                Ok(blocks) => blocks,
                Err(error) => {
                    tracing::debug!(target: "tip-follower", start, "wide REST edge check failed, using ten-score windows: {error:#}");
                    return None;
                }
            };
            let prefetched = page
                .windows
                .get(&edge_start)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            match (window_signature(prefetched), window_signature(&narrow)) {
                (Ok(wide), Ok(narrow)) if wide == narrow => {}
                _ => {
                    tracing::warn!(target: "tip-follower", start, edge_start, "wide REST page disagrees with ten-score edge; using ten-score windows");
                    return None;
                }
            }
        }
        tracing::info!(
            target: "tip-follower",
            start,
            transactions = page.transactions,
            "prefetched sparse REST page"
        );
        Some(page)
    }

    async fn prepare_window(
        &self,
        window_start: u64,
        tip: u64,
        previous_candidates: Option<u64>,
        prefetched: &mut Option<PrefetchedPage>,
    ) -> Result<Option<PreparedBatch>> {
        if !prefetched
            .as_ref()
            .is_some_and(|page| page.contains(window_start))
        {
            *prefetched = self
                .maybe_prefetch_sparse_page(window_start, tip, previous_candidates)
                .await;
        }
        if let Some(page) = prefetched
            .as_mut()
            .filter(|page| page.contains(window_start))
        {
            return Ok(self
                .scanner
                .prepare_blocks(page.windows.remove(&window_start).unwrap_or_default()));
        }
        self.scanner.prepare_batch(window_start).await
    }

    async fn verify_rest_removals(&self, start: u64, removed: &BTreeSet<String>) -> Result<()> {
        anyhow::ensure!(removed.len() <= self.config.batch_size as usize,
            "REST removal evidence exceeds window bound");
        // Page absence is not negative chain evidence. Complete all source reads
        // before the caller may roll back any block or commit its window/cursor.
        let verify = stream::iter(removed.iter().map(|hash| async move {
            let block = self.prefetch_rest.recovery_block_evidence(hash).await?;
            anyhow::ensure!(block.hash == hex::decode(hash)?
                && block.blue_score >= start
                && block.blue_score <= window_end(start, self.config.batch_size as u64),
                "REST removal block identity disagrees with window");
            if block.is_chain_block {
                return Err(crate::live_supervisor::RecoveryPending(
                    "REST page omitted a still-canonical block; retaining repair window"
                ).into());
            }
            Ok::<_, anyhow::Error>(())
        })).buffer_unordered(4).try_collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(2), verify).await
            .context("REST block-removal verification exceeded two seconds")??;
        Ok(())
    }

    async fn canonical_recovery_owns_writes(&self) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_plans WHERE exclusive_writes)")
            .fetch_one(&self.store.pool).await?)
    }

    async fn check_historical_preparation(&self) -> Result<()> {
        anyhow::ensure!(!self.canonical_recovery_owns_writes().await?, HistoricalPreparationPaused);
        Ok(())
    }

    async fn run_once(&self, state: &mut TipFollowerState) -> Result<TipFollowerStats> {
        self.check_historical_preparation().await?;
        let tip = self.scanner.rest_database_tip().await?;
        let window_starts = reconciliation_window_starts(
            tip,
            state.cursor_blue_score,
            self.config.batch_size.max(1) as u64,
            self.config.overlap_windows.max(1) as usize,
            self.config.max_catchup_windows.max(1) as usize,
        );
        let mut stats = TipFollowerStats {
            rest_database_tip: tip,
            ..Default::default()
        };
        let current_window_start =
            (tip / self.config.batch_size as u64) * self.config.batch_size as u64;
        let mut prefetched = None;
        let mut previous_candidates = None;
        let mut timed_windows = 0u64;
        let mut prepare_wait_ms = 0u128;
        let mut reconcile_ms = 0u128;
        let mut persist_ms_total = 0u128;
        let mut hydrate_ms_total = 0u128;
        let mut prevout_ms_total = 0u128;
        let mut sql_persist_ms_total = 0u128;
        let mut cursor_commit_ms = 0u128;
        let parallel_windows = window_starts
            .iter()
            .take_while(|start| tip.saturating_sub(**start) >= WINDOW_FETCH_FINALITY_MARGIN)
            .count();
        // Fetch settled REST windows in a separate task so decoding continues
        // while the single writer commits earlier windows. The channel and
        // buffered stream bound lookahead and preserve source order.
        let mut window_fetches = (self.config.window_fetch_concurrency > 1
            && !self.config.adaptive_prefetch
            && parallel_windows > 0)
            .then(|| {
                WindowFetches::start(
                    self.prefetch_rest.clone(),
                    self.scanner.clone(),
                    window_starts
                        .iter()
                        .copied()
                        .take(parallel_windows)
                        .collect(),
                    self.config.batch_size,
                    self.config.window_fetch_concurrency,
                )
            });

        for (index, window_start) in window_starts.iter().enumerate() {
            self.check_historical_preparation().await?;
            let window_started = Instant::now();
            let (prepared, prefetched_hydrate_ms) = if let Some(fetches) =
                window_fetches.as_mut().filter(|_| index < parallel_windows)
            {
                fetches.next().await?
            } else {
                (
                    self.prepare_window(*window_start, tip, previous_candidates, &mut prefetched)
                        .await?,
                    None,
                )
            };
            // A source can turn unhealthy after the initial tip read. Discard
            // this page before any row or cursor mutation in that case.
            self.prefetch_rest.ensure_current_database_synced().await?;
            let Some(mut prepared) = prepared else {
                if *window_start == current_window_start {
                    break;
                }
                previous_candidates = Some(0);
                let reconciliation =
                    state.reconcile(*window_start, BTreeSet::new(), BTreeSet::new());
                self.verify_rest_removals(*window_start, &reconciliation.removed_blocks).await?;
                for block_hash in &reconciliation.removed_blocks {
                    let decoded = hex::decode(block_hash)
                        .with_context(|| format!("decoding removed block hash {block_hash}"))?;
                    self.persister.revert_block(&decoded).await?;
                    stats.removed_blocks += 1;
                }
                state.commit(reconciliation.snapshot, &BTreeSet::new());
                let cursor_blue_score = window_end(*window_start, self.config.batch_size as u64);
                let retain_from = window_start.saturating_sub(
                    self.config.batch_size as u64
                        * self.config.overlap_windows.saturating_sub(1) as u64,
                );
                self.store
                    .commit_window(
                        state.windows.get(window_start),
                        cursor_blue_score,
                        retain_from,
                    )
                    .await?;
                state.cursor_blue_score = Some(cursor_blue_score);
                state.retain_from(retain_from);
                continue;
            };
            let prepare_ms = window_started.elapsed().as_millis();
            let reconciliation = state.reconcile(
                *window_start,
                prepared.block_hashes(),
                prepared.acceptance_keys(),
            );

            self.verify_rest_removals(*window_start, &reconciliation.removed_blocks).await?;
            for block_hash in &reconciliation.removed_blocks {
                let decoded = hex::decode(block_hash)
                    .with_context(|| format!("decoding removed block hash {block_hash}"))?;
                self.persister.revert_block(&decoded).await?;
                stats.removed_blocks += 1;
            }

            prepared.retain_acceptances(&reconciliation.unseen_acceptances);
            let already_persisted = prepared.already_persisted(&self.store.pool).await?;
            stats.already_persisted_txs += already_persisted.len() as u64;
            let remaining = reconciliation
                .unseen_acceptances
                .difference(&already_persisted)
                .cloned()
                .collect();
            prepared.retain_acceptances(&remaining);
            self.check_historical_preparation().await?;
            let persist_started = Instant::now();
            let before_persist_ms = persist_started.duration_since(window_started).as_millis();
            let mut persisted = self
                .scanner
                .persist_prepared_with_metadata(prepared, prefetched_hydrate_ms)
                .await?;
            self.prefetch_rest.ensure_current_database_synced().await?;
            previous_candidates = Some(persisted.stats.p2sh_candidates);
            let persist_ms = persist_started.elapsed().as_millis();
            persisted.persisted_acceptances.extend(already_persisted);
            state.commit(reconciliation.snapshot, &persisted.persisted_acceptances);
            let cursor_blue_score = if *window_start == current_window_start {
                tip
            } else {
                window_end(*window_start, self.config.batch_size as u64)
            };
            let retain_from = window_start.saturating_sub(
                self.config.batch_size as u64
                    * self.config.overlap_windows.saturating_sub(1) as u64,
            );
            self.store
                .commit_window(
                    state.windows.get(window_start),
                    cursor_blue_score,
                    retain_from,
                )
                .await?;
            state.cursor_blue_score = Some(cursor_blue_score);
            state.retain_from(retain_from);
            let elapsed_ms = window_started.elapsed().as_millis();
            timed_windows += 1;
            prepare_wait_ms += prepare_ms;
            reconcile_ms += before_persist_ms.saturating_sub(prepare_ms);
            persist_ms_total += persist_ms;
            hydrate_ms_total += persisted.hydrate_ms;
            prevout_ms_total += persisted.prevout_ms;
            sql_persist_ms_total += persisted.sql_persist_ms;
            cursor_commit_ms += elapsed_ms.saturating_sub(before_persist_ms + persist_ms);
            if timed_windows == 50 {
                tracing::info!(
                    target: "tip-follower",
                    windows = timed_windows,
                    prepare_wait_ms,
                    reconcile_ms,
                    persist_ms = persist_ms_total,
                    hydrate_ms = hydrate_ms_total,
                    prevout_ms = prevout_ms_total,
                    sql_persist_ms = sql_persist_ms_total,
                    cursor_commit_ms,
                    last_cursor_blue_score = cursor_blue_score,
                    "historical replay phase timing"
                );
                timed_windows = 0;
                prepare_wait_ms = 0;
                reconcile_ms = 0;
                persist_ms_total = 0;
                hydrate_ms_total = 0;
                prevout_ms_total = 0;
                sql_persist_ms_total = 0;
                cursor_commit_ms = 0;
            }
            if elapsed_ms >= 5_000 {
                tracing::info!(
                    target: "tip-follower",
                    window_start = *window_start,
                    elapsed_ms,
                    prepare_ms,
                    before_persist_ms,
                    persist_ms,
                    p2sh_candidates = persisted.stats.p2sh_candidates,
                    persisted_txs = persisted.stats.txs_persisted,
                    hydrated_txs = persisted.stats.txs_hydrated,
                    block_bodies_covered = persisted.stats.block_bodies_covered,
                    "slow historical window"
                );
            }
            stats.add_batch(persisted.stats);
        }
        Ok(stats)
    }
}

struct NoopCursor;

#[async_trait::async_trait]
impl CursorStore for NoopCursor {
    async fn load(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn save(&self, _blue_score: u64, _rest_database_blue_score: Option<u64>) -> Result<()> {
        Ok(())
    }
}

fn resumed_settled_next(selected: u64, retained: u64, selected_next: u64, width: u64) -> u64 {
    if selected == retained {
        selected_next
    } else {
        retained.saturating_add(width)
    }
}

#[test]
fn pending_initial_window_does_not_skip_forward_when_rolling_span_moves() {
    assert_eq!(resumed_settled_next(200, 100, 300, 100), 200);
    assert_eq!(resumed_settled_next(100, 100, 200, 100), 200);
    assert_eq!(resumed_settled_next(900, 900, 100, 100), 100);
}

fn settled_recheck_window(
    tip: u64,
    width: u64,
    span: u64,
    min_age: u64,
    saved_next: Option<u64>,
) -> Option<(u64, u64)> {
    if width == 0 || span <= min_age.saturating_add(width) {
        return None;
    }
    let first = (tip.saturating_sub(span) / width) * width;
    let end = (tip.saturating_sub(min_age) / width) * width;
    if first >= end {
        return None;
    }
    // A failed window remains pending even after it leaves the rolling span.
    // Resetting to `first` silently abandons that window as the chain advances.
    // A regressed source tip must mature again before its saved window runs.
    let window = match saved_next {
        Some(next) if next % width == 0 && next < end => next,
        Some(_) => return None,
        None => first,
    };
    let next = if window.saturating_add(width) >= end {
        first
    } else {
        window + width
    };
    Some((window, next))
}

fn settled_recheck_selection_tip(source_tip: u64, history_cursor: u64, min_age: u64) -> Option<u64> {
    const HISTORY_MARGIN: u64 = 200;
    let covered_through = history_cursor.checked_sub(HISTORY_MARGIN)?;
    let mature_through = source_tip.checked_sub(min_age)?;
    if covered_through < SETTLED_RECHECK_WIDTH || mature_through < SETTLED_RECHECK_WIDTH {
        return None;
    }
    Some(source_tip.min(covered_through.saturating_add(min_age)))
}

fn settled_job_eligible(selection_tip: u64, min_age: u64, window: u64, width: u64) -> bool {
    if width == 0 {
        return false;
    }
    let eligible_end = (selection_tip.saturating_sub(min_age) / width) * width;
    window.checked_add(width).is_some_and(|end| end <= eligible_end)
}

#[test]
fn independent_recheck_stays_behind_history_and_source() {
    let selection = settled_recheck_selection_tip(100_000, 90_000, 1_000).unwrap();
    assert_eq!(selection, 90_800);
    let (window, _) = settled_recheck_window(selection, 100, 20_000, 1_000, Some(89_600)).unwrap();
    assert_eq!(window, 89_600);
    assert!(window + 100 <= 90_000 - 200);
    assert!(settled_recheck_window(selection, 100, 20_000, 1_000, Some(89_800)).is_none());
    assert!(!settled_job_eligible(selection, 1_000, 89_800, 100));
    assert!(settled_job_eligible(selection, 1_000, 89_600, 100));
    assert!(settled_recheck_selection_tip(900, 10_000, 1_000).is_none());
    assert!(settled_recheck_selection_tip(100_000, 100, 1_000).is_none());
}

fn recent_window_starts(tip: u64, batch_size: u64, overlap_windows: usize) -> Vec<u64> {
    let batch_size = batch_size.max(1);
    let current = (tip / batch_size) * batch_size;
    let first =
        current.saturating_sub(batch_size.saturating_mul(overlap_windows.saturating_sub(1) as u64));
    (first..=current).step_by(batch_size as usize).collect()
}

fn reconciliation_window_starts(
    tip: u64,
    cursor_blue_score: Option<u64>,
    batch_size: u64,
    overlap_windows: usize,
    max_catchup_windows: usize,
) -> Vec<u64> {
    let batch_size = batch_size.max(1);
    let current = (tip / batch_size) * batch_size;
    let Some(cursor) = cursor_blue_score else {
        return recent_window_starts(tip, batch_size, overlap_windows);
    };
    let next = (cursor.saturating_add(1) / batch_size) * batch_size;
    if next < current {
        return (next..=current)
            .step_by(batch_size as usize)
            .take(max_catchup_windows.max(1))
            .collect();
    }
    recent_window_starts(tip, batch_size, overlap_windows)
}

fn contains_acceptance(
    coordinates: &BTreeSet<(String, String, u64)>,
    tx: &RestTransaction,
) -> bool {
    if !tx.is_accepted {
        return false;
    }
    match (&tx.accepting_block_hash, tx.accepting_block_blue_score) {
        (Some(hash), Some(score)) => {
            coordinates.contains(&(tx.transaction_id.clone(), hash.clone(), score))
        }
        _ => false,
    }
}

fn window_end(window_start: u64, batch_size: u64) -> u64 {
    window_start.saturating_add(batch_size.max(1).saturating_sub(1))
}

#[derive(Debug, Default)]
struct TipFollowerState {
    cursor_blue_score: Option<u64>,
    windows: BTreeMap<u64, TipWindowSnapshot>,
}

impl TipFollowerState {
    fn reconcile(
        &self,
        window_start: u64,
        block_hashes: BTreeSet<String>,
        acceptances: BTreeSet<AcceptanceKey>,
    ) -> TipReconciliation {
        let previous = self.windows.get(&window_start);
        let removed_blocks = previous
            .map(|snapshot| {
                snapshot
                    .block_hashes
                    .difference(&block_hashes)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let persisted_acceptances: BTreeSet<AcceptanceKey> = previous
            .map(|snapshot| {
                snapshot
                    .persisted_acceptances
                    .intersection(&acceptances)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let unseen_acceptances = acceptances
            .difference(&persisted_acceptances)
            .cloned()
            .collect();

        TipReconciliation {
            removed_blocks,
            unseen_acceptances,
            snapshot: TipWindowSnapshot {
                window_start,
                block_hashes,
                persisted_acceptances,
            },
        }
    }

    fn commit(
        &mut self,
        mut snapshot: TipWindowSnapshot,
        persisted_acceptances: &BTreeSet<AcceptanceKey>,
    ) {
        snapshot
            .persisted_acceptances
            .extend(persisted_acceptances.iter().cloned());
        self.windows.insert(snapshot.window_start, snapshot);
    }

    fn retain_from(&mut self, retain_from: u64) {
        self.windows
            .retain(|window_start, _| *window_start >= retain_from);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TipWindowSnapshot {
    window_start: u64,
    block_hashes: BTreeSet<String>,
    persisted_acceptances: BTreeSet<AcceptanceKey>,
}

struct PgTipFollowerStore {
    pool: tn12_indexer_db::PgPool,
    cursor_key: String,
}

impl PgTipFollowerStore {
    fn new(pool: tn12_indexer_db::PgPool, cursor_key: impl Into<String>) -> Self {
        Self {
            pool,
            cursor_key: cursor_key.into(),
        }
    }

    fn settled_recheck_key(&self) -> String {
        format!("{}:settled_recheck", self.cursor_key)
    }

    async fn load_settled_recheck_next(&self) -> Result<Option<u64>> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM indexer_state WHERE key=$1",
        )
        .bind(self.settled_recheck_key())
        .fetch_optional(&self.pool)
        .await?;
        Ok(value.and_then(|value| value.get("next_blue_score")?.as_u64()))
    }

    async fn load_cursor_blue_score(&self) -> Result<Option<u64>> {
        let value = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM indexer_state WHERE key=$1",
        ).bind(&self.cursor_key).fetch_optional(&self.pool).await?;
        Ok(value.and_then(|value| value.get("blue_score")?.as_u64()))
    }

    #[cfg(test)]
    async fn save_settled_recheck_next(&self, completed: u64, next: u64, tip: u64) -> Result<()> {
        // Called only after replay and normalization both return success. Keep
        // cumulative work with the cursor in one atomic statement. Sweep wraps
        // and successful rechecks count as work, not additional unique coverage.
        let result = sqlx::query(
            r#"INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ($1,$2,$3)
               ON CONFLICT (key) DO UPDATE SET
                 value=EXCLUDED.value || jsonb_build_object(
                   'completed_windows',coalesce((indexer_state.value->>'completed_windows')::bigint,0)+1,
                   'completed_scores',coalesce((indexer_state.value->>'completed_scores')::bigint,0)+$4::bigint),
                 updated_at_ms=EXCLUDED.updated_at_ms
               WHERE (NOT indexer_state.value ? 'completed_windows' AND NOT indexer_state.value ? 'completed_scores')
                  OR (jsonb_typeof(indexer_state.value->'completed_windows')='number'
                    AND jsonb_typeof(indexer_state.value->'completed_scores')='number'
                    AND (indexer_state.value->>'completed_windows')::bigint>=0
                    AND (indexer_state.value->>'completed_scores')::bigint>=0)"#,
        )
        .bind(self.settled_recheck_key())
        .bind(serde_json::json!({
            "last_completed_blue_score": completed,
            "next_blue_score": next,
            "source_tip_blue_score": tip,
            "completed_windows": 1,
            "completed_scores": SETTLED_RECHECK_WIDTH,
        }))
        .bind(chrono::Utc::now().timestamp_millis())
        .bind(i64::try_from(SETTLED_RECHECK_WIDTH)?)
        .execute(&self.pool)
        .await?;
        anyhow::ensure!(
            result.rows_affected() == 1,
            "invalid settled replay work counters; cursor retained"
        );
        Ok(())
    }

    async fn load_state(&self) -> Result<TipFollowerState> {
        let cursor_blue_score = sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT value FROM indexer_state WHERE key = $1",
        )
        .bind(&self.cursor_key)
        .fetch_optional(&self.pool)
        .await?
        .and_then(|value| value.get("blue_score").and_then(serde_json::Value::as_u64));
        let rows = sqlx::query(
            r#"SELECT window_start, block_hashes, persisted_acceptances
               FROM tip_follower_windows
               WHERE cursor_key = $1
               ORDER BY window_start"#,
        )
        .bind(&self.cursor_key)
        .fetch_all(&self.pool)
        .await?;
        let mut windows = BTreeMap::new();
        for row in rows {
            let window_start = row.get::<i64, _>("window_start") as u64;
            windows.insert(
                window_start,
                TipWindowSnapshot {
                    window_start,
                    block_hashes: serde_json::from_value(row.get("block_hashes"))?,
                    persisted_acceptances: serde_json::from_value(
                        row.get("persisted_acceptances"),
                    )?,
                },
            );
        }
        Ok(TipFollowerState {
            cursor_blue_score,
            windows,
        })
    }

    async fn commit_window(
        &self,
        snapshot: Option<&TipWindowSnapshot>,
        cursor_blue_score: u64,
        retain_from: u64,
    ) -> Result<()> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut tx = self.pool.begin().await?;
        if let Some(snapshot) = snapshot {
            sqlx::query(
                r#"INSERT INTO tip_follower_windows(
                       cursor_key, window_start, block_hashes, persisted_acceptances, updated_at_ms
                   ) VALUES ($1, $2, $3, $4, $5)
                   ON CONFLICT (cursor_key, window_start) DO UPDATE
                   SET block_hashes = EXCLUDED.block_hashes,
                       persisted_acceptances = EXCLUDED.persisted_acceptances,
                       updated_at_ms = EXCLUDED.updated_at_ms"#,
            )
            .bind(&self.cursor_key)
            .bind(snapshot.window_start as i64)
            .bind(serde_json::to_value(&snapshot.block_hashes)?)
            .bind(serde_json::to_value(&snapshot.persisted_acceptances)?)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            r#"INSERT INTO indexer_state(key, value, updated_at_ms)
               VALUES ($1, $2, $3)
               ON CONFLICT (key) DO UPDATE
               SET value = indexer_state.value || EXCLUDED.value,
                   updated_at_ms = EXCLUDED.updated_at_ms"#,
        )
        .bind(&self.cursor_key)
        .bind(serde_json::json!({
            "blue_score": cursor_blue_score,
        }))
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM tip_follower_windows WHERE cursor_key = $1 AND window_start < $2")
            .bind(&self.cursor_key)
            .bind(retain_from as i64)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn record_rest_observation(
        &self,
        rest_database_blue_score: u64,
        rest_observed_at_ms: i64,
    ) -> Result<()> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        sqlx::query(
            r#"INSERT INTO indexer_state(key, value, updated_at_ms)
               VALUES ($1, $2, $3)
               ON CONFLICT (key) DO UPDATE
               SET value = indexer_state.value || EXCLUDED.value"#,
        )
        .bind(&self.cursor_key)
        .bind(serde_json::json!({
            "rest_database_blue_score": rest_database_blue_score,
            "rest_database_observed_at_ms": rest_observed_at_ms,
        }))
        .bind(now_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Debug)]
struct TipReconciliation {
    removed_blocks: BTreeSet<String>,
    unseen_acceptances: BTreeSet<AcceptanceKey>,
    snapshot: TipWindowSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn virtual_block(score: u64, hash: &str, txid: &str) -> VirtualChainBlock {
        VirtualChainBlock {
            hash: hash.to_string(),
            blue_score: score,
            daa_score: score,
            timestamp: score,
            transactions: vec![tn12_indexer_core::RestTransaction {
                transaction_id: txid.to_string(),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn sparse_page_keeps_ten_score_window_boundaries() {
        let page = split_sparse_page(
            1_000,
            vec![
                virtual_block(1_001, "a", "tx-a"),
                virtual_block(1_019, "b", "tx-b"),
                virtual_block(1_099, "c", "tx-c"),
            ],
        )
        .unwrap();
        assert!(page.contains(1_000));
        assert!(page.contains(1_090));
        assert!(!page.contains(1_100));
        assert_eq!(page.transactions, 3);
        assert_eq!(
            page.windows.keys().copied().collect::<Vec<_>>(),
            vec![1_000, 1_010, 1_090]
        );
    }

    #[test]
    fn sparse_page_rejects_missing_range_or_duplicate_evidence() {
        assert!(split_sparse_page(1_000, vec![virtual_block(1_100, "a", "tx-a")]).is_err());
        assert!(split_sparse_page(
            1_000,
            vec![
                virtual_block(1_010, "a", "tx-a"),
                virtual_block(1_009, "b", "tx-b")
            ]
        )
        .is_err());
        assert!(split_sparse_page(
            1_000,
            vec![
                virtual_block(1_000, "a", "tx-a"),
                virtual_block(1_010, "a", "tx-b")
            ]
        )
        .is_err());
        let mut oversized = virtual_block(1_000, "a", "tx-a");
        oversized.transactions = (0..=SPARSE_PREFETCH_MAX_TXS)
            .map(|n| tn12_indexer_core::RestTransaction {
                transaction_id: format!("tx-{n}"),
                ..Default::default()
            })
            .collect();
        assert!(split_sparse_page(1_000, vec![oversized]).is_err());
    }

    #[test]
    fn sparse_page_edge_check_compares_full_transaction_values() {
        let first = virtual_block(1_000, "a", "tx-a");
        let mut drifted = first.clone();
        drifted.transactions[0].block_time = 42;
        assert_eq!(
            window_signature(&[first.clone()]).unwrap(),
            window_signature(&[first]).unwrap()
        );
        assert_ne!(
            window_signature(&[drifted]).unwrap(),
            window_signature(&[virtual_block(1_000, "a", "tx-a")]).unwrap()
        );
    }

    fn blocks(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    fn acceptances(values: &[(&str, &str)]) -> BTreeSet<AcceptanceKey> {
        values
            .iter()
            .map(|(transaction_id, block_hash)| AcceptanceKey {
                transaction_id: (*transaction_id).to_string(),
                block_hash: (*block_hash).to_string(),
            })
            .collect()
    }

    #[test]
    fn recent_windows_cover_the_reorg_overlap() {
        assert_eq!(
            recent_window_starts(545_000_000, 20, 2),
            vec![544_999_980, 545_000_000]
        );
        assert_eq!(
            recent_window_starts(545_200_000, 20, 2),
            vec![545_199_980, 545_200_000]
        );
    }

    #[test]
    fn settled_recheck_rotates_after_success_and_retains_an_old_pending_window() {
        assert_eq!(
            settled_recheck_window(100_000, 100, 20_000, 1_000, None),
            Some((80_000, 80_100))
        );
        assert_eq!(
            settled_recheck_window(100_000, 100, 20_000, 1_000, Some(98_900)),
            Some((98_900, 80_000))
        );
        assert_eq!(
            settled_recheck_window(100_000, 100, 20_000, 1_000, Some(70_000)),
            Some((70_000, 70_100))
        );
        assert_eq!(settled_recheck_window(100_000, 100, 0, 0, None), None);
    }

    #[test]
    fn settled_recheck_never_skips_a_failed_window_as_tip_advances() {
        for tip in [100_000, 110_000, 200_000] {
            assert_eq!(
                settled_recheck_window(tip, 100, 20_000, 1_000, Some(80_000)),
                Some((80_000, 80_100))
            );
        }
        // A tip regression or corrupt unaligned checkpoint cannot restart a sweep.
        assert_eq!(
            settled_recheck_window(80_000, 100, 20_000, 1_000, Some(80_000)),
            None
        );
        assert_eq!(
            settled_recheck_window(100_000, 100, 20_000, 1_000, Some(80_001)),
            None
        );
    }

    #[test]
    fn catchup_walks_every_window_after_a_long_outage() {
        assert_eq!(
            reconciliation_window_starts(10_050, Some(9_999), 10, 2, 1_000),
            vec![10_000, 10_010, 10_020, 10_030, 10_040, 10_050]
        );
    }

    #[test]
    fn catchup_is_bounded_without_jumping_the_cursor() {
        assert_eq!(
            reconciliation_window_starts(20_000, Some(9_999), 10, 2, 3),
            vec![10_000, 10_010, 10_020]
        );
    }

    #[test]
    fn node_supported_page_sizes_are_explicit() {
        assert!(matches!(TipFollowerConfig::default().batch_size, 10 | 100));
    }

    #[test]
    fn repeated_snapshot_skips_already_persisted_transactions() {
        let mut state = TipFollowerState::default();
        let expected = acceptances(&[("tx-a", "block-a"), ("tx-b", "block-a")]);
        let first = state.reconcile(100, blocks(&["block-a"]), expected.clone());
        assert_eq!(first.unseen_acceptances, expected.clone());
        state.commit(first.snapshot, &first.unseen_acceptances);

        let repeated = state.reconcile(100, blocks(&["block-a"]), expected);
        assert!(repeated.removed_blocks.is_empty());
        assert!(repeated.unseen_acceptances.is_empty());
    }

    #[test]
    fn changed_snapshot_reverts_removed_block_and_retries_reaccepted_tx() {
        let mut state = TipFollowerState::default();
        let first = state.reconcile(
            100,
            blocks(&["block-a"]),
            acceptances(&[("tx-a", "block-a")]),
        );
        state.commit(first.snapshot, &first.unseen_acceptances);

        let reorg = state.reconcile(
            100,
            blocks(&["block-b"]),
            acceptances(&[("tx-a", "block-b")]),
        );
        assert_eq!(reorg.removed_blocks, blocks(&["block-a"]));
        assert_eq!(
            reorg.unseen_acceptances,
            acceptances(&[("tx-a", "block-b")])
        );
    }

    #[test]
    fn empty_reorg_window_removes_every_previous_block() {
        let mut state = TipFollowerState::default();
        let first = state.reconcile(100, blocks(&["aa", "bb"]), acceptances(&[("tx-a", "aa")]));
        state.commit(first.snapshot, &first.unseen_acceptances);

        let empty = state.reconcile(100, BTreeSet::new(), BTreeSet::new());
        assert_eq!(empty.removed_blocks, blocks(&["aa", "bb"]));
        assert!(empty.unseen_acceptances.is_empty());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn settled_committed_work_survives_restart_and_sweep_wrap(pool: tn12_indexer_db::PgPool) {
        let store = PgTipFollowerStore::new(pool.clone(), "committed-work");
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ($1,$2,1)")
            .bind(store.settled_recheck_key())
            .bind(serde_json::json!({"next_blue_score": 100, "last_completed_blue_score": 0}))
            .execute(&pool)
            .await
            .unwrap();
        store
            .save_settled_recheck_next(100, 200, 1000)
            .await
            .unwrap();
        // A sweep wrap is successful repeated work, not unique covered scores.
        let restarted = PgTipFollowerStore::new(pool.clone(), "committed-work");
        restarted
            .save_settled_recheck_next(200, 100, 1100)
            .await
            .unwrap();
        let state: serde_json::Value =
            sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
                .bind(store.settled_recheck_key())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state["completed_windows"], 2);
        assert_eq!(state["completed_scores"], 200);
        assert_eq!(state["next_blue_score"], 100);

        sqlx::query("UPDATE indexer_state SET value=jsonb_set(value,'{completed_windows}',to_jsonb(9223372036854775807::bigint)) WHERE key=$1")
            .bind(store.settled_recheck_key()).execute(&pool).await.unwrap();
        assert!(restarted
            .save_settled_recheck_next(100, 200, 1200)
            .await
            .is_err());
        let after: serde_json::Value =
            sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
                .bind(store.settled_recheck_key())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after["next_blue_score"], 100);
        assert_eq!(after["completed_scores"], 200);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_state_survives_restart(pool: tn12_indexer_db::PgPool) {
        let store = PgTipFollowerStore::new(pool, "restart-test");
        let snapshot = TipWindowSnapshot {
            window_start: 100,
            block_hashes: blocks(&["block-a"]),
            persisted_acceptances: acceptances(&[("tx-a", "block-a")]),
        };
        store.commit_window(Some(&snapshot), 109, 90).await.unwrap();

        let restored = store.load_state().await.unwrap();
        assert_eq!(restored.cursor_blue_score, Some(109));
        assert_eq!(restored.windows.len(), 1);
        let repeated = restored.windows.get(&100).unwrap();
        assert_eq!(repeated.block_hashes, snapshot.block_hashes);
        assert_eq!(
            repeated.persisted_acceptances,
            snapshot.persisted_acceptances
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn rest_observation_update_does_not_advance_cursor(pool: tn12_indexer_db::PgPool) {
        let store = PgTipFollowerStore::new(pool.clone(), "observation-test");
        store.commit_window(None, 109, 90).await.unwrap();

        store.record_rest_observation(180, 234_567).await.unwrap();

        let value: serde_json::Value =
            sqlx::query_scalar("SELECT value FROM indexer_state WHERE key = $1")
                .bind("observation-test")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(value["blue_score"], serde_json::json!(109));
        assert_eq!(value["rest_database_blue_score"], serde_json::json!(180));
        assert_eq!(
            value["rest_database_observed_at_ms"],
            serde_json::json!(234_567)
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn observation_only_state_loads_without_cursor(pool: tn12_indexer_db::PgPool) {
        let store = PgTipFollowerStore::new(pool, "observation-only-test");
        store.record_rest_observation(180, 234_567).await.unwrap();

        let state = store.load_state().await.unwrap();
        assert_eq!(state.cursor_blue_score, None);
        assert!(state.windows.is_empty());
    }
}

#[cfg(test)]
#[path = "tip_commit_recovery_tests.rs"]
mod commit_recovery_tests;

#[cfg(test)]
mod retry_observation_tests {
    use super::*;

    #[test]
    fn retained_window_duration_resets_after_cursor_progress_or_success() {
        let start = Instant::now();
        let mut failures = TipFailureTracker::default();
        assert_eq!(
            failures.record(Some(99), start, start + Duration::from_secs(2)),
            2000
        );
        assert_eq!(
            failures.record(
                Some(99),
                start + Duration::from_secs(3),
                start + Duration::from_secs(5)
            ),
            5000
        );
        assert_eq!(failures.consecutive_failures, 2);
        assert_eq!(
            failures.record(
                Some(109),
                start + Duration::from_secs(6),
                start + Duration::from_secs(7)
            ),
            1000
        );
        assert_eq!(failures.consecutive_failures, 1);
        failures = TipFailureTracker::default();
        assert_eq!(
            failures.record(
                None,
                start + Duration::from_secs(8),
                start + Duration::from_secs(9)
            ),
            1000
        );
        assert_eq!(failures.consecutive_failures, 1);
    }
}

#[cfg(test)]
#[path = "live_recovery_tests.rs"]
mod live_recovery_tests;

#[cfg(test)]
#[path = "live_recovery_pg_tests.rs"]
mod live_recovery_pg_tests;

#[cfg(test)]
#[path = "rest_removal_tests.rs"]
mod rest_removal_tests;
