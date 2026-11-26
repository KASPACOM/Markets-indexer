//! Event-driven wRPC live indexer.
//!
//! `blockAdded` carries transaction bodies before the REST database publishes
//! them. `virtualChainChanged` identifies which of those transactions became
//! accepted and which selected-chain blocks were removed. The watcher joins
//! both streams in a bounded cache, persists only covenant candidates, and
//! leaves reconnect gaps to the independent REST tip follower.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures::{FutureExt, StreamExt};
use kaspa_addresses::Prefix;
use kaspa_consensus_core::tx::Transaction;
use kaspa_txscript::extract_script_pub_key_address;
use kaspa_wrpc_client::prelude::{
    BlockAddedNotification, BlockAddedScope, ChannelConnection, ChannelType, ConnectOptions,
    KaspaRpcClient, NetworkId, Notification, RpcAcceptedTransactionIds, RpcApi, RpcBlock, RpcState,
    RpcTransaction, Scope, VirtualChainChangedNotification, VirtualChainChangedScope, WrpcEncoding,
};
use tn12_indexer_core::{RestCovenantBinding, RestTransaction, RestTxInput, RestTxOutput};
use tn12_indexer_db::{is_transient_persist_error, Persister};
use tracing::Instrument;
use workflow_core::channel::Channel;

use crate::scan::{has_p2sh_output, is_p2sh_output};
use crate::{CursorStore, ReorgHandler};

#[path = "wrpc_hydration.rs"]
mod hydration;

#[cfg(test)]
#[path = "wrpc_decode_isolation_tests.rs"]
mod decode_isolation_tests;

const DEFAULT_CACHE_CAPACITY: usize = 100_000;
const ACCEPTANCE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

// These durations start inside this process, after dequeue. They do not measure
// source delivery, SDK queue time, or source-to-API latency.
fn report_wrpc_phase(phase: &'static str, elapsed: Duration, outcome: &'static str) {
    let elapsed_us = elapsed.as_micros() as u64;
    if elapsed >= Duration::from_millis(250) || outcome != "ok" {
        tracing::warn!(target: "wrpc_phase", phase, elapsed_us, outcome, "watcher phase completed");
    } else {
        tracing::debug!(target: "wrpc_phase", phase, elapsed_us, outcome, "watcher phase completed");
    }
}

struct WrpcPhaseTimer {
    phase: &'static str,
    started: Instant,
    outcome: &'static str,
}

impl Drop for WrpcPhaseTimer {
    fn drop(&mut self) {
        report_wrpc_phase(self.phase, self.started.elapsed(), self.outcome);
    }
}

async fn observe_wrpc_phase<T>(
    phase: &'static str,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let mut timer = WrpcPhaseTimer {
        phase,
        started: Instant::now(),
        outcome: "incomplete",
    };
    tracing::debug!(target: "wrpc_phase", phase, "watcher phase started");
    let result = future.await;
    timer.outcome = if result.is_ok() { "ok" } else { "error" };
    result
}

fn acceptance_heartbeat_due(
    stats: &WrpcWatcherStats,
    last_heartbeat: Option<Instant>,
    now: Instant,
) -> bool {
    stats.accepted_txids > 0
        && stats.body_cache_misses == 0
        && stats.persist_errors == 0
        && last_heartbeat.is_none_or(|at| now.duration_since(at) >= ACCEPTANCE_HEARTBEAT_INTERVAL)
}

#[derive(Debug, Clone)]
pub struct WrpcWatcherConfig {
    pub wrpc_url: String,
    pub network_id: String,
    pub cache_capacity: usize,
}

impl WrpcWatcherConfig {
    pub fn with_default_cache(wrpc_url: String, network_id: String) -> Self {
        Self {
            wrpc_url,
            network_id,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WrpcWatcherStats {
    pub notifications: u64,
    pub block_notifications: u64,
    pub removed_blocks: u64,
    pub accepted_txids: u64,
    pub cached_txs: u64,
    pub body_cache_misses: u64,
    pub candidate_txs: u64,
    pub persisted_txs: u64,
    pub persist_errors: u64,
    pub max_index_latency_ms: u64,
}

#[derive(Debug, Clone)]
struct Acceptance {
    block_hash: String,
    blue_score: u64,
    timestamp: u64,
}

#[derive(Debug)]
struct LiveTransactionCache {
    transactions: HashMap<String, RestTransaction>,
    transaction_order: VecDeque<String>,
    blocks: HashMap<String, Acceptance>,
    block_order: VecDeque<String>,
    pending: HashMap<String, String>,
    pending_order: VecDeque<String>,
    capacity: usize,
    address_prefix: Prefix,
}

impl LiveTransactionCache {
    fn new(capacity: usize, address_prefix: Prefix) -> Self {
        Self {
            transactions: HashMap::new(),
            transaction_order: VecDeque::new(),
            blocks: HashMap::new(),
            block_order: VecDeque::new(),
            pending: HashMap::new(),
            pending_order: VecDeque::new(),
            capacity: capacity.max(1),
            address_prefix,
        }
    }

    fn insert_block(&mut self, block: &RpcBlock) -> Result<Vec<RestTransaction>> {
        self.remember_block(block)?;
        Ok(self.drain_ready())
    }

    // Source preparation must never apply pending or future acceptance.
    fn remember_block(&mut self, block: &RpcBlock) -> Result<()> {
        let block_hash = block.header.hash.to_string();
        let is_new_block = self
            .blocks
            .insert(
                block_hash.clone(),
                Acceptance {
                    block_hash: block_hash.clone(),
                    blue_score: block.header.blue_score,
                    timestamp: block.header.timestamp,
                },
            )
            .is_none();
        if is_new_block {
            self.block_order.push_back(block_hash);
        }

        for rpc_tx in &block.transactions {
            let tx = rpc_transaction_to_rest(rpc_tx, block, self.address_prefix)?;
            let txid = tx.transaction_id.clone();
            if self.transactions.insert(txid.clone(), tx).is_none() {
                self.transaction_order.push_back(txid);
            }
        }
        self.prune();
        Ok(())
    }

    fn accept(&mut self, groups: &[RpcAcceptedTransactionIds]) -> Vec<RestTransaction> {
        for group in groups {
            let accepting_hash = group.accepting_block_hash.to_string();
            for txid in &group.accepted_transaction_ids {
                let txid = txid.to_string();
                if self
                    .pending
                    .insert(txid.clone(), accepting_hash.clone())
                    .is_none()
                {
                    self.pending_order.push_back(txid);
                }
            }
        }
        self.prune();
        self.drain_ready()
    }

    fn cancel_pending_acceptances(&mut self, removed_accepting_blocks: &HashSet<String>) {
        self.pending
            .retain(|_, accepting_hash| !removed_accepting_blocks.contains(accepting_hash));
        self.pending_order
            .retain(|txid| self.pending.contains_key(txid));
    }

    fn resolve_cached_prevouts(&self, tx: &mut RestTransaction) {
        for input in &mut tx.inputs {
            let Some(parent) = self.transactions.get(&input.previous_outpoint_hash) else {
                continue;
            };
            if let Some(output) = crate::cached_prevout::compatible(input, parent) {
                crate::cached_prevout::hydrate(input, output);
            }
        }
    }

    fn drain_ready(&mut self) -> Vec<RestTransaction> {
        let mut waiting = VecDeque::with_capacity(self.pending_order.len());
        let mut ready = Vec::new();
        while let Some(txid) = self.pending_order.pop_front() {
            let Some(accepting_hash) = self.pending.get(&txid) else {
                continue;
            };
            if !self.transactions.contains_key(&txid) || !self.blocks.contains_key(accepting_hash) {
                waiting.push_back(txid);
                continue;
            }
            let Some(accepting_hash) = self.pending.remove(&txid) else {
                continue;
            };
            let Some(mut tx) = self.transactions.get(&txid).cloned() else {
                continue;
            };
            let Some(acceptance) = self.blocks.get(&accepting_hash) else {
                continue;
            };
            tx.is_accepted = true;
            tx.accepting_block_hash = Some(acceptance.block_hash.clone());
            tx.accepting_block_blue_score = Some(acceptance.blue_score);
            tx.accepting_block_time = Some(acceptance.timestamp);
            self.resolve_cached_prevouts(&mut tx);
            ready.push(tx);
        }
        self.pending_order = waiting;
        ready
    }

    fn prune(&mut self) {
        while self.transaction_order.len() > self.capacity {
            if let Some(txid) = self.transaction_order.pop_front() {
                self.transactions.remove(&txid);
                // Evicting an immutable body does not resolve its acceptance.
                // Keep that obligation visible until joined or removed.
            }
        }
        while self.block_order.len() > self.capacity {
            if let Some(hash) = self.block_order.pop_front() {
                self.blocks.remove(&hash);
            }
        }
        while self.pending_order.len() > self.capacity {
            let Some(txid) = self.pending_order.pop_front() else {
                break;
            };
            self.pending.remove(&txid);
        }
    }
}

pub struct WrpcVirtualChainWatcher<P: Persister + ?Sized> {
    persister: Arc<P>,
    reorg: ReorgHandler<P>,
    live_cursor: Box<dyn CursorStore + Send + Sync>,
    acceptance_heartbeat: Box<dyn CursorStore + Send + Sync>,
    config: WrpcWatcherConfig,
    journal: Option<Arc<dyn crate::live_recovery::LiveWriteJournal>>,
    funding_metadata_source: Option<crate::RestClient>,
}

impl<P: Persister + ?Sized> WrpcVirtualChainWatcher<P> {
    pub fn new(
        persister: Arc<P>,
        reorg_cursor: Box<dyn CursorStore + Send + Sync>,
        live_cursor: Box<dyn CursorStore + Send + Sync>,
        acceptance_heartbeat: Box<dyn CursorStore + Send + Sync>,
        config: WrpcWatcherConfig,
    ) -> Self {
        let reorg = ReorgHandler::new(persister.clone(), reorg_cursor);
        Self {
            persister,
            reorg,
            live_cursor,
            acceptance_heartbeat,
            config,
            journal: None,
            funding_metadata_source: None,
        }
    }

    pub fn with_write_journal(
        mut self,
        journal: Arc<dyn crate::live_recovery::LiveWriteJournal>,
    ) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Optional preparation of immutable funding metadata before acquiring a writer lock.
    pub fn with_funding_metadata_source(mut self, source: crate::RestClient) -> Self {
        self.funding_metadata_source = Some(source);
        self
    }

    fn should_resume_ingress<T>(stopped: bool, result: &Result<T>) -> bool {
        stopped && result.is_ok()
    }

    pub async fn run_forever(&self) -> Result<()> {
        let network_id = NetworkId::from_str(&self.config.network_id)
            .with_context(|| format!("parsing network id {}", self.config.network_id))?;
        let rpc = Arc::new(KaspaRpcClient::new_with_args(
            WrpcEncoding::Borsh,
            Some(self.config.wrpc_url.as_str()),
            None,
            Some(network_id),
            None,
        )?);
        let notifications = Channel::<Notification>::unbounded();
        let rpc_ctl = rpc.rpc_ctl().multiplexer().channel();
        let notification_receiver = notifications.receiver.clone();
        let mut listener_id = None;
        let address_prefix = Prefix::from(network_id);
        let mut cache = LiveTransactionCache::new(self.config.cache_capacity, address_prefix);
        let mut live_blue_score = self.live_cursor.load().await?.unwrap_or(0);
        let mut last_acceptance_heartbeat: Option<Instant> = None;
        let watcher_started_at_ms = utc_now_ms();
        let mut event_seq = 0_u64;
        let mut last_event_finished: Option<Instant> = None;

        let result: Result<()> = async {
        rpc.connect(Some(ConnectOptions {
            block_async_connect: false,
            ..Default::default()
        }))
        .await?;
        tracing::info!(
            target: "wrpc",
            "connecting to {} on {}",
            self.config.wrpc_url,
            self.config.network_id
        );

        loop {
            futures::select_biased! {
                msg = rpc_ctl.receiver.recv().fuse() => {
                    match msg.context("wRPC control channel closed")? {
                        RpcState::Connected => {
                            if listener_id.is_none() {
                                let id = rpc.register_new_listener(ChannelConnection::new(
                                    "TN12-INDEXER",
                                    notifications.sender.clone(),
                                    ChannelType::Persistent,
                                ));
                                rpc.start_notify(id, Scope::BlockAdded(BlockAddedScope {})).await?;
                                rpc.start_notify(
                                    id,
                                    Scope::VirtualChainChanged(VirtualChainChangedScope {
                                        include_accepted_transaction_ids: true,
                                    }),
                                )
                                .await?;
                                listener_id = Some(id);
                                tracing::info!(target: "wrpc", "blockAdded and virtualChainChanged subscriptions active");
                            }
                        }
                        RpcState::Disconnected => {
                            if let Some(id) = listener_id.take() {
                                if let Err(e) = rpc.unregister_listener(id).await {
                                    tracing::debug!(target: "wrpc", "unregister listener after disconnect failed: {e:#}");
                                }
                            }
                            cache = LiveTransactionCache::new(self.config.cache_capacity, address_prefix);
                            last_acceptance_heartbeat = None;
                            tracing::warn!(target: "wrpc", "disconnected from wRPC; cache cleared and REST tip follower will repair the gap");
                        }
                    }
                }
                notification = notification_receiver.recv().fuse() => {
                    let notification = notification.context("wRPC notification channel closed")?;
                    event_seq = event_seq.wrapping_add(1);
                    let kind = match &notification {
                        Notification::BlockAdded(_) => "block_added",
                        Notification::VirtualChainChanged(_) => "virtual_chain_changed",
                        _ => "other",
                    };
                    let span = tracing::info_span!(
                        "wrpc_event", watcher_started_at_ms, event_seq, kind,
                        dequeued_at_ms = utc_now_ms(),
                        queued_notifications = notification_receiver.len(),
                        since_previous_event_completed_us = ?last_event_finished.map(|at| at.elapsed().as_micros()),
                    );
                    observe_wrpc_phase("notification", async {
                    match notification {
                        Notification::BlockAdded(block) => {
                            let result = self.handle_block_added(&mut cache, &mut live_blue_score, block).await;
                            if let Ok(stats) = &result {
                                self.record_acceptance_heartbeat(stats, live_blue_score, &mut last_acceptance_heartbeat).await;
                            }
                            match result {
                                Ok(stats) if stats.persisted_txs > 0 => tracing::info!(
                                    target: "wrpc",
                                    "block: cached={} accepted_joined={} candidates={} persisted={} persist_err={} max_index_latency_ms={}",
                                    stats.cached_txs,
                                    stats.accepted_txids,
                                    stats.candidate_txs,
                                    stats.persisted_txs,
                                    stats.persist_errors,
                                    stats.max_index_latency_ms
                                ),
                                Ok(_) => {}
                                Err(e) if self.journal.is_some() => return Err(e).context("live writer stopped; durable intent must recover before reconnect"),
                                Err(e) => tracing::warn!(target: "wrpc", "blockAdded failed: {e:#}"),
                            }
                        }
                        Notification::VirtualChainChanged(vcc) => {
                            let mut ingress_stopped = false;
                            let result = self.handle_virtual_chain_changed_with_source(&mut cache, &mut live_blue_score, vcc,
                                Some(&hydration::RpcBlocks { rpc:rpc.clone(), network:network_id }), || {
                                ingress_stopped = true;
                                let rpc = rpc.clone();
                                async move {
                                    // The SDK's relay/intake queues are also unbounded.
                                    // Stop the websocket before a DB retry can stall them.
                                    // Keep notifier services alive to drain queued removals.
                                    loop {
                                        match rpc.rpc_client().shutdown().await {
                                            Ok(()) => break,
                                            Err(error) => {
                                                tracing::warn!(target: "wrpc", "pausing notification ingress for reorg retry failed: {error:#}");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                }
                            }).await;
                            if Self::should_resume_ingress(ingress_stopped, &result) {
                                rpc.rpc_client().connect(ConnectOptions {
                                    block_async_connect: false,
                                    ..Default::default()
                                }).await?;
                            }
                            if let Ok(stats) = &result {
                                self.record_acceptance_heartbeat(stats, live_blue_score, &mut last_acceptance_heartbeat).await;
                            }
                            match result {
                                Ok(stats) if stats.removed_blocks > 0
                                    || stats.candidate_txs > 0
                                    || stats.body_cache_misses > 0 => tracing::info!(
                                    target: "wrpc",
                                    "vcc: removed={} accepted={} joined={} cache_miss={} candidates={} persisted={} persist_err={} max_index_latency_ms={}",
                                    stats.removed_blocks,
                                    stats.accepted_txids,
                                    stats.cached_txs,
                                    stats.body_cache_misses,
                                    stats.candidate_txs,
                                    stats.persisted_txs,
                                    stats.persist_errors,
                                    stats.max_index_latency_ms
                                ),
                                Ok(stats) => tracing::debug!(
                                    target: "wrpc",
                                    "vcc: accepted={} joined={}",
                                    stats.accepted_txids,
                                    stats.cached_txs
                                ),
                                Err(e) if self.journal.is_some() => return Err(e).context("live writer stopped; durable intent must recover before reconnect"),
                                Err(e) => tracing::warn!(target: "wrpc", "virtualChainChanged failed: {e:#}"),
                            }
                        }
                        other => tracing::debug!(target: "wrpc", "ignoring notification: {other:?}"),
                    }
                    Ok(())
                    }).instrument(span).await?;
                    last_event_finished = Some(Instant::now());
                }
            }
        }
        }.await;
        // A retained journal error must not leave the SDK relay/reconnect tasks
        // alive while canonical recovery waits for REST publication.
        crate::live_supervisor::stop_transport(
            async { rpc.rpc_client().shutdown().await?; Ok(()) },
            async { rpc.stop().await?; Ok(()) },
            Duration::from_secs(5),
        ).await?;
        result
    }

    async fn record_acceptance_heartbeat(
        &self,
        stats: &WrpcWatcherStats,
        live_blue_score: u64,
        last_heartbeat: &mut Option<Instant>,
    ) {
        if acceptance_heartbeat_due(stats, *last_heartbeat, Instant::now()) {
            match observe_wrpc_phase(
                "acceptance_heartbeat",
                self.acceptance_heartbeat.save(live_blue_score, None),
            )
            .await
            {
                Ok(()) => *last_heartbeat = Some(Instant::now()),
                Err(error) => {
                    tracing::warn!(target: "wrpc", "accepted-chain heartbeat write failed: {error:#}")
                }
            }
        }
    }

    async fn handle_block_added(
        &self,
        cache: &mut LiveTransactionCache,
        live_blue_score: &mut u64,
        notification: BlockAddedNotification,
    ) -> Result<WrpcWatcherStats> {
        let cached_txs = notification.block.transactions.len() as u64;
        let ready = cache.insert_block(&notification.block)?;
        let max_accepted_blue_score = max_acceptance_blue_score(&ready);
        let mut stats = WrpcWatcherStats {
            block_notifications: 1,
            accepted_txids: ready.len() as u64,
            cached_txs,
            body_cache_misses: cache.pending.len() as u64,
            ..Default::default()
        };
        self.persist_candidates(ready, &mut stats).await?;
        if stats.persist_errors == 0 && stats.body_cache_misses == 0 {
            self.advance_live_cursor(live_blue_score, max_accepted_blue_score)
                .await?;
        }
        Ok(stats)
    }

    #[cfg(test)]
    async fn handle_virtual_chain_changed<F, Fut>(
        &self,
        cache: &mut LiveTransactionCache,
        live_blue_score: &mut u64,
        notification: VirtualChainChangedNotification,
        before_reorg_retry: F,
    ) -> Result<WrpcWatcherStats>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        self.handle_virtual_chain_changed_with_source(cache, live_blue_score, notification, None, before_reorg_retry).await
    }

    async fn handle_virtual_chain_changed_with_source<F, Fut>(
        &self,
        cache: &mut LiveTransactionCache,
        live_blue_score: &mut u64,
        notification: VirtualChainChangedNotification,
        source: Option<&dyn hydration::BlockSource>,
        before_reorg_retry: F,
    ) -> Result<WrpcWatcherStats>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let removed: Vec<String> = notification
            .removed_chain_block_hashes
            .iter()
            .map(ToString::to_string)
            .collect();
        if !removed.is_empty() && self.journal.is_some() && self.persister.paged_recovery_writer().is_some() {
            return self.handle_exclusive_live_reorg(cache,live_blue_score,notification,&removed,source,before_reorg_retry).await;
        }
        cache.cancel_pending_acceptances(&removed.iter().cloned().collect());
        let accepted_count = notification
            .accepted_transaction_ids
            .iter()
            .map(|group| group.accepted_transaction_ids.len())
            .sum::<usize>();
        if !removed.is_empty() {
            let reorg = observe_wrpc_phase(
                "reorg",
                self.reorg
                    .handle_removed_block_hashes_until_applied(&removed, before_reorg_retry),
            )
            .await?;
            if let Some(reverted_blue_score) = reorg.min_reverted_blue_score {
                *live_blue_score = reverted_blue_score;
            }
            tracing::info!(
                target: "wrpc",
                "reorg: requested={} removed={} unknown={} min_blue_score={:?}",
                reorg.requested_blocks,
                reorg.blocks_removed,
                reorg.unknown_blocks,
                reorg.min_reverted_blue_score
            );
        }

        let ready = cache.accept(&notification.accepted_transaction_ids);
        let max_accepted_blue_score = max_acceptance_blue_score(&ready);
        let mut stats = WrpcWatcherStats {
            notifications: 1,
            removed_blocks: removed.len() as u64,
            accepted_txids: accepted_count as u64,
            cached_txs: ready.len() as u64,
            body_cache_misses: accepted_count.saturating_sub(ready.len()) as u64,
            ..Default::default()
        };

        self.persist_candidates(ready, &mut stats).await?;
        if stats.persist_errors == 0 && stats.body_cache_misses == 0 {
            self.advance_live_cursor(live_blue_score, max_accepted_blue_score)
                .await?;
        }
        Ok(stats)
    }

    /// Keep removal and replacement commits inside one non-reconnecting writer
    /// session. Persist the event first; a failed/cancelled operation recovers
    /// from that intent rather than retrying a partial reorg in place.
    async fn handle_exclusive_live_reorg<F,Fut>(
        &self, cache:&mut LiveTransactionCache, live_blue_score:&mut u64,
        notification:VirtualChainChangedNotification, removed:&[String], source:Option<&dyn hydration::BlockSource>, mut before_retry:F,
    ) -> Result<WrpcWatcherStats>
    where F:FnMut()->Fut, Fut:std::future::Future<Output=()> {

        use crate::live_recovery::LiveWriteWindow;
        use tn12_indexer_db::persist::CanonicalWriteLease;
        let journal=self.journal.as_ref().expect("journaled event");
        // Journal only obligations this event can apply. Unresolved older cache
        // entries remain pending and suppress freshness, but do not require an
        // otherwise complete reorg to enter canonical recovery.
        let mut hashes:BTreeSet<String>=removed.iter().cloned().chain(
            cache.pending.iter().filter(|(txid,hash)|
                cache.transactions.contains_key(*txid) && cache.blocks.contains_key(*hash))
                .map(|(_,hash)|hash.clone()))
            .chain(notification.accepted_transaction_ids.iter()
                .filter(|group|!group.accepted_transaction_ids.is_empty())
                .map(|g|g.accepting_block_hash.to_string())).collect();
        let mut raw=LiveWriteWindow {
            transactions:Vec::new(), rejected_transactions:Vec::new(), affected_transaction_ids:Vec::new(),
            observed_blocks:Default::default(), window_width:Some(100), unresolved_blocks:hashes.iter().cloned().collect(),
        };
        for (hash,block) in &cache.blocks {
            if hashes.contains(hash) {
                raw.observed_blocks.entry(block.blue_score/100*100).or_default().insert(hash.clone());
            }
        }
        raw.unresolved_blocks.retain(|hash|!cache.blocks.contains_key(hash));
        raw.validate()?;
        journal.begin(&raw).await?;
        if let Some(source)=source {
            if !hydration::current_ready(cache,&notification.accepted_transaction_ids) {
                // No canonical writes or writer lease exist yet. A timed-out
                // fetch only abandons immutable preparation; the intent stays.
                let result=tokio::time::timeout(Duration::from_millis(500),
                    hydration::hydrate(cache,&notification.accepted_transaction_ids,source)).await;
                match result {
                    Ok(Ok(()))=>{},
                    other=>tracing::warn!(target:"wrpc", outcome=?other,
                        "bounded live source preparation incomplete"),
                }
                let previous=raw.clone();
                hashes.extend(cache.pending.iter().filter(|(id,hash)|
                    cache.transactions.contains_key(*id) && cache.blocks.contains_key(*hash))
                    .map(|(_,hash)|hash.clone()));
                raw.observed_blocks.clear();
                raw.unresolved_blocks.clear();
                for hash in &hashes {
                    if let Some(block)=cache.blocks.get(hash) {
                        raw.observed_blocks.entry(block.blue_score/100*100).or_default().insert(hash.clone());
                    } else { raw.unresolved_blocks.push(hash.clone()); }
                }
                raw.validate()?;
                journal.replace(&previous,&raw).await?;
            }
        }
        cache.cancel_pending_acceptances(&removed.iter().cloned().collect());
        let accepted=notification.accepted_transaction_ids.iter().map(|g|g.accepted_transaction_ids.len()).sum::<usize>();
        let ready=cache.accept(&notification.accepted_transaction_ids);
        let max_score=max_acceptance_blue_score(&ready);
        let joined:HashSet<_>=ready.iter().filter_map(|tx|tx.accepting_block_hash.as_ref()
            .map(|hash|(tx.transaction_id.clone(),hash.clone()))).collect();
        let missing=notification.accepted_transaction_ids.iter().flat_map(|group|
            group.accepted_transaction_ids.iter().map(move |id|(id.to_string(),group.accepting_block_hash.to_string())))
            .filter(|pair|!joined.contains(pair)).count();
        let pending=cache.pending.len();
        let mut stats=WrpcWatcherStats { notifications:1,removed_blocks:removed.len() as u64,
            accepted_txids:accepted as u64,cached_txs:ready.len() as u64,
            body_cache_misses:missing.max(pending) as u64,..Default::default() };
        let candidates=self.prepare_candidates(ready,&mut stats).await?;
        let coordinates:HashMap<String,u64>=hashes.iter().filter_map(|hash|cache.blocks.get(hash)
            .map(|block|(hash.clone(),block.blue_score))).collect();
        let writer=self.persister.paged_recovery_writer().expect("postgres event");
        let lease=loop {
            match CanonicalWriteLease::acquire_for_live_event(writer).await {
                Ok(lease)=>break lease,
                Err(error) if is_transient_persist_error(&error)=>{
                    // No canonical mutation has begun. Stop unbounded SDK intake
                    // before waiting for a busy writer, retaining the raw intent.
                    before_retry().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error)=>return Err(error),
            }
        };
        lease.run(|writer| async move {
            let journal=journal.with_pool(writer.pool().clone())?;
            let reorg=self.reorg.with_writer(writer.clone(),writer.pool().clone())?;
            let live_cursor=self.live_cursor.with_pool(writer.pool().clone())?;
            let encoded:Vec<_>=hashes.iter().map(hex::decode).collect::<std::result::Result<_,_>>()?;
            let rows:Vec<(String,i64)>=sqlx::query_as("SELECT encode(hash,'hex'),blue_score FROM blocks WHERE hash=ANY($1::bytea[])")
                .bind(&encoded).fetch_all(writer.pool()).await?;
            // Most chain removals have never touched this covenant index. Do
            // not turn a cold cache miss into canonical recovery for those
            // no-effect removals. Negative evidence still commits under this
            // session before the raw journal can be replaced or completed.
            let removed_set:BTreeSet<_>=removed.iter().cloned().collect();
            let bounded=hashes.len()<=32 && candidates.len()<=32
                && serde_json::to_vec(&candidates)?.len()<=1024*1024;
            let mut no_effect=bounded && !rows.iter().any(|(hash,_)|removed_set.contains(hash));
            if no_effect {
                for hash in &removed_set {
                    let impact=writer.recovery_block_impact(hash).await?;
                    if !impact.transaction_ids.is_empty() || !impact.descendants.is_empty() {
                        no_effect=false;
                        break;
                    }
                }
            }
            if no_effect {
                reorg.handle_removed_block_hashes_once(writer.as_ref(),removed).await?;
                let prepared=if candidates.is_empty() { raw.clone() }
                    else { LiveWriteWindow::new(&candidates)? };
                if !candidates.is_empty() { journal.replace(&raw,&prepared).await?; }
                let start=Instant::now();
                writer.persist_batch(&candidates).await?;
                let elapsed=start.elapsed().as_micros() as u64;
                if let Some(sample)=record_persist_success_at(&candidates,&mut stats,utc_now_ms(),elapsed,"no_effect_reorg") {
                    log_persist_latency_sample(sample,candidates.len(),candidates.len(),0,elapsed);
                }
                if stats.body_cache_misses==0 {
                    if let Some(next)=next_forward_blue_score(*live_blue_score,max_score) {
                        live_cursor.save(next,None).await?;
                        *live_blue_score=next;
                    }
                }
                journal.complete(&prepared).await?;
                return Ok(stats);
            }
            // Unknown removals can coexist with indexed removals. Commit their
            // negative epochs before dropping their unresolvable coordinates
            // from the journal. The writer lease excludes concurrent REST.
            let mut empty_removals=BTreeSet::new();
            for hash in removed_set.iter().filter(|_|bounded) {
                if rows.iter().any(|(indexed,_)|indexed==hash) { continue; }
                let impact=writer.recovery_block_impact(hash).await?;
                if impact.transaction_ids.is_empty() && impact.descendants.is_empty() {
                    empty_removals.insert(hash.clone());
                }
            }
            if !empty_removals.is_empty() {
                let empty:Vec<_>=empty_removals.iter().cloned().collect();
                reorg.handle_removed_block_hashes_once(writer.as_ref(),&empty).await?;
            }
            let mut coordinates=coordinates;
            for (hash,score) in &rows {
                let score=u64::try_from(*score)?;
                if let Some(previous)=coordinates.insert(hash.clone(),score) {
                    anyhow::ensure!(previous==score,"event block score disagrees with indexed block");
                }
            }
            let mut window=raw.clone();
            for hash in &hashes {
                if empty_removals.contains(hash) { continue; }
                let Some(score)=coordinates.get(hash) else {
                    tracing::warn!(target:"wrpc", block_hash=%hash, current_missing=missing,
                        pending_total=pending, "event admission missing block coordinates");
                    return Err(crate::live_supervisor::RecoveryPending("live event metadata unavailable; retained before removal").into());
                };
                window.observed_blocks.entry(score/100*100).or_default().insert(hash.clone());
            }
            for blocks in window.observed_blocks.values_mut() {
                blocks.retain(|hash|!empty_removals.contains(hash));
            }
            window.observed_blocks.retain(|_,blocks|!blocks.is_empty());
            window.unresolved_blocks.clear();
            window.transactions=candidates.clone();
            let mut ids=BTreeSet::new();
            let mut defer=missing!=0 || hashes.len()>32
                || candidates.len()>32
                || serde_json::to_vec(&candidates)?.len()>1024*1024;
            if !defer {
                for (hash,_) in rows.iter().filter(|(hash,_)|removed_set.contains(hash)) {
                    match writer.recovery_block_impact(hash).await {
                        Ok(impact)=>{
                            ids.extend(impact.transaction_ids);
                            defer |= ids.len()>256 || impact.descendants.iter().any(|hash|!removed_set.contains(hash));
                        }
                        Err(error) if error.is::<tn12_indexer_db::persist::RecoveryImpactLimit>()=>defer=true,
                        Err(error)=>return Err(error),
                    }
                    if defer { break; }
                }
            }
            if ids.len()<=256 { window.affected_transaction_ids=ids.into_iter().collect(); }
            window.validate()?;
            journal.replace(&raw,&window).await?;
            if defer {
                tracing::warn!(target:"wrpc", current_missing=missing, pending_total=pending,
                    event_blocks=hashes.len(), candidates=candidates.len(),
                    affected_transactions=window.affected_transaction_ids.len(),
                    "event admission requires dependency/body recovery");
                return Err(crate::live_supervisor::RecoveryPending("live event requires complete dependency/body recovery before removal").into());
            }
            if rows.iter().any(|(hash,_)|removed_set.contains(hash)) || !candidates.is_empty() {
                sqlx::query("INSERT INTO tn10_live_event_fences(intent_key) VALUES($1)")
                    .bind(journal.intent_key().context("event journal has no key")?).execute(writer.pool()).await?;
            }
            let reorg=reorg.handle_removed_block_hashes_once(writer.as_ref(),removed).await?;
            if let Some(score)=reorg.min_reverted_blue_score { *live_blue_score=score; }
            let start=Instant::now();
            writer.persist_batch(&candidates).await?;
            let elapsed=start.elapsed().as_micros() as u64;
            if let Some(sample)=record_persist_success_at(&candidates,&mut stats,utc_now_ms(),elapsed,"exclusive_reorg") {
                log_persist_latency_sample(sample,candidates.len(),candidates.len(),0,elapsed);
            }
            if stats.body_cache_misses==0 {
                if let Some(next)=next_forward_blue_score(*live_blue_score,max_score) {
                    live_cursor.save(next,None).await?;
                    *live_blue_score=next;
                }
            }
            journal.complete(&window).await?;
            Ok(stats)
        }).await
    }

    async fn advance_live_cursor(
        &self,
        live_blue_score: &mut u64,
        candidate: Option<u64>,
    ) -> Result<()> {
        let Some(candidate) = next_forward_blue_score(*live_blue_score, candidate) else {
            return Ok(());
        };
        observe_wrpc_phase("live_cursor", self.live_cursor.save(candidate, None)).await?;
        *live_blue_score = candidate;
        Ok(())
    }

    async fn prepare_candidates(
        &self,
        txs: Vec<RestTransaction>,
        stats: &mut WrpcWatcherStats,
    ) -> Result<Vec<RestTransaction>> {
        let mut outpoints = Vec::new();
        let p2sh_outputs: BTreeSet<(String, i32)> = txs
            .iter()
            .flat_map(|tx| {
                tx.outputs
                    .iter()
                    .filter(|output| is_p2sh_output(output))
                    .map(|output| (tx.transaction_id.clone(), output.index as i32))
            })
            .collect();
        for tx in txs.iter().filter(|tx| !has_p2sh_output(tx)) {
            outpoints.extend(tx.inputs.iter().filter_map(|input| {
                input
                    .previous_outpoint_index
                    .parse::<i32>()
                    .ok()
                    .map(|vout| (input.previous_outpoint_hash.clone(), vout))
            }));
        }
        outpoints.sort();
        outpoints.dedup();
        let existing =
            observe_wrpc_phase("existing_utxos", self.persister.existing_utxos(&outpoints)).await?;
        let mut candidates: Vec<_> = txs
            .into_iter()
            .filter(|tx| is_stream_candidate(tx, &p2sh_outputs, &existing))
            .collect();
        stats.candidate_txs += candidates.len() as u64;

        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        self.prepare_funding_metadata(&mut candidates).await;
        Ok(tn12_indexer_db::persist::transactions_in_dependency_order(&candidates)?.into_owned())
    }

    async fn persist_candidates(
        &self, txs:Vec<RestTransaction>, stats:&mut WrpcWatcherStats,
    ) -> Result<()> {
        let candidates=self.prepare_candidates(txs,stats).await?;
        if candidates.is_empty() { return Ok(()); }
        let intent = if let Some(journal) = &self.journal {
            let intent = crate::live_recovery::LiveWriteWindow::new(&candidates)?;
            journal.begin(&intent).await?;
            Some(intent)
        } else {
            None
        };
        let batch_started = Instant::now();
        match observe_wrpc_phase("persist_batch", self.persister.persist_batch(&candidates)).await {
            Ok(_) => {
                if let (Some(journal), Some(intent)) = (&self.journal, &intent) {
                    journal.complete(intent).await?;
                }
                let elapsed_us = batch_started.elapsed().as_micros() as u64;
                if let Some(sample) =
                    record_persist_success_at(&candidates, stats, utc_now_ms(), elapsed_us, "batch")
                {
                    log_persist_latency_sample(
                        sample,
                        candidates.len(),
                        candidates.len(),
                        0,
                        elapsed_us,
                    );
                }
            }
            Err(e) => {
                if self.journal.is_some() {
                    return Err(e).context("durable live intent retained for canonical REST recovery; refusing fallback");
                }
                if e.downcast_ref::<tn12_indexer_db::persist::GenericWriteOutcomeUnknown>()
                    .is_some()
                {
                    return Err(e).context("generic write outcome requires whole-window reconciliation; refusing individual fallback");
                }
                if is_transient_persist_error(&e) {
                    stats.persist_errors += candidates.len() as u64;
                    tracing::warn!(
                        target: "wrpc",
                        "batch persist hit transient DB pressure; REST tip follower will retry: {e:#}"
                    );
                    return Ok(());
                }
                tracing::warn!(target: "wrpc", "batch persist failed: {e:#}; retrying txs individually");
                let mut slowest_success = None;
                let mut succeeded = 0;
                let mut failed = 0;
                for tx in candidates.iter() {
                    let individual_started = Instant::now();
                    match observe_wrpc_phase("persist_tx_fallback", self.persister.persist_tx(tx))
                        .await
                    {
                        Ok(_) => {
                            succeeded += 1;
                            let sample = record_persist_success_at(
                                std::slice::from_ref(tx),
                                stats,
                                utc_now_ms(),
                                individual_started.elapsed().as_micros() as u64,
                                "individual_fallback",
                            );
                            retain_slowest_sample(&mut slowest_success, sample);
                        }
                        Err(e) => {
                            failed += 1;
                            stats.persist_errors += 1;
                            tracing::warn!(target: "wrpc", "persist {} failed: {e:#}", tx.transaction_id);
                        }
                    }
                }
                if let Some(sample) = slowest_success {
                    log_persist_latency_sample(
                        sample,
                        candidates.len(),
                        succeeded,
                        failed,
                        batch_started.elapsed().as_micros() as u64,
                    );
                }
            }
        }
        Ok(())
    }

    async fn prepare_funding_metadata(&self, candidates: &mut [RestTransaction]) {
        let Some(source) = &self.funding_metadata_source else {
            return;
        };
        let mut unresolved = BTreeSet::new();
        for tx in candidates.iter() {
            for input in &tx.inputs {
                if input.previous_outpoint_script.is_none()
                    && input.previous_outpoint_address.is_none()
                    && tx.needs_input_identity(input)
                {
                    let Ok(index) = input.previous_outpoint_index.parse::<i32>() else {
                        continue;
                    };
                    unresolved.insert((input.previous_outpoint_hash.clone(), index));
                    // Opportunistic preparation is bounded. The journal recovery
                    // path still owns dependencies outside this small fast path.
                    if unresolved.len() > 8 {
                        return;
                    }
                }
            }
        }
        if unresolved.is_empty() {
            return;
        }
        let preparation = async {
            let outpoints: Vec<_> = unresolved.into_iter().collect();
            let existing = self.persister.existing_utxos(&outpoints).await?;
            let ids: BTreeSet<_> = outpoints
                .into_iter()
                .filter(|outpoint| !existing.contains(outpoint))
                .map(|(id, _)| id)
                .collect();
            let budget = crate::rpc::rest::ParentResponseBudget::default();
            let parents = futures::stream::iter(
                ids.iter()
                    .map(|id| async { source.get_transaction_with_budget(id, &budget).await }),
            )
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await;
            Ok::<_, anyhow::Error>(parents)
        };
        // Include the read and HTTP preparation in one wall-clock budget.
        // No writer lock or durable intent exists during these optional reads.
        let Ok(Ok(parents)) = tokio::time::timeout(Duration::from_millis(200), preparation).await
        else {
            return;
        };
        let mut hydrated = 0;
        for parent in parents
            .into_iter()
            .flatten()
            .filter(|parent| parent.is_accepted)
        {
            for tx in candidates.iter_mut() {
                for input in &mut tx.inputs {
                    if input.previous_outpoint_script.is_some()
                        || input.previous_outpoint_address.is_some()
                    {
                        continue;
                    }
                    let Some(output) = crate::cached_prevout::compatible(input, &parent) else {
                        continue;
                    };
                    // Only standard Schnorr funding inputs qualify. Covenant,
                    // malformed and unknown scripts retain the identity guard.
                    let Ok(script) = hex::decode(&output.script_public_key) else {
                        continue;
                    };
                    if script.len() != 34 || script[0] != 0x20 || script[33] != 0xac {
                        continue;
                    }
                    crate::cached_prevout::hydrate(input, output);
                    hydrated += 1;
                }
            }
        }
        if hydrated > 0 {
            tracing::info!(target: "wrpc", hydrated, "prepared funding metadata before live persistence");
        }
    }
}

fn is_stream_candidate(
    tx: &RestTransaction,
    current_p2sh_outputs: &BTreeSet<(String, i32)>,
    existing_utxos: &HashSet<(String, i32)>,
) -> bool {
    has_p2sh_output(tx)
        || tx.inputs.iter().any(|input| {
            input
                .previous_outpoint_index
                .parse::<i32>()
                .ok()
                .is_some_and(|vout| {
                    let outpoint = (input.previous_outpoint_hash.clone(), vout);
                    existing_utxos.contains(&outpoint) || current_p2sh_outputs.contains(&outpoint)
                })
        })
}

// These samples diagnose successful persist calls. They exclude SDK/network
// queues, joins and API visibility, and must not replace the block-age SLO.
#[derive(Clone, Copy, Debug)]
struct PersistLatencySample<'a> {
    tx: &'a RestTransaction,
    observed_at_ms: u64,
    block_age_ms: u64,
    persist_call_elapsed_us: u64,
    mode: &'static str,
}

fn utc_now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn max_acceptance_latency_sample(
    txs: &[RestTransaction],
    now_ms: u64,
) -> Option<(&RestTransaction, u64)> {
    txs.iter()
        .filter_map(|tx| {
            tx.accepting_block_time
                .map(|at| (tx, now_ms.saturating_sub(at)))
        })
        .max_by(|(a, age_a), (b, age_b)| {
            age_a
                .cmp(age_b)
                .then_with(|| b.transaction_id.cmp(&a.transaction_id))
        })
}

#[cfg(test)]
fn max_acceptance_latency_ms(txs: &[RestTransaction]) -> u64 {
    max_acceptance_latency_sample(txs, utc_now_ms()).map_or(0, |(_, age)| age)
}

fn record_persist_success_at<'a>(
    txs: &'a [RestTransaction],
    stats: &mut WrpcWatcherStats,
    now_ms: u64,
    persist_call_elapsed_us: u64,
    mode: &'static str,
) -> Option<PersistLatencySample<'a>> {
    stats.persisted_txs += txs.len() as u64;
    let (tx, age) = max_acceptance_latency_sample(txs, now_ms)?;
    stats.max_index_latency_ms = stats.max_index_latency_ms.max(age);
    (age >= 1_500).then_some(PersistLatencySample {
        tx,
        observed_at_ms: now_ms,
        block_age_ms: age,
        persist_call_elapsed_us,
        mode,
    })
}

fn retain_slowest_sample<'a>(
    retained: &mut Option<PersistLatencySample<'a>>,
    candidate: Option<PersistLatencySample<'a>>,
) {
    if let Some(candidate) = candidate {
        if retained.as_ref().is_none_or(|old| {
            candidate.block_age_ms > old.block_age_ms
                || (candidate.block_age_ms == old.block_age_ms
                    && candidate.tx.transaction_id < old.tx.transaction_id)
        }) {
            *retained = Some(candidate);
        }
    }
}

fn log_persist_latency_sample(
    sample: PersistLatencySample<'_>,
    batch_size: usize,
    succeeded: usize,
    failed: usize,
    attempt_group_elapsed_us: u64,
) {
    tracing::info!(target: "wrpc",
        event = "persisted_latency_sample", mode = sample.mode,
        txid = %sample.tx.transaction_id,
        accepting_block_hash = sample.tx.accepting_block_hash.as_deref(),
        accepting_block_time_ms = sample.tx.accepting_block_time,
        correlation_complete = sample.tx.accepting_block_hash.is_some()
            && sample.tx.accepting_block_time.is_some(),
        observed_at_ms = sample.observed_at_ms, block_age_ms = sample.block_age_ms,
        persist_call_elapsed_us = sample.persist_call_elapsed_us,
        attempt_group_elapsed_us, batch_size, succeeded, failed,
        "slow block-age attribution after successful persistence");
}

fn max_acceptance_blue_score(txs: &[RestTransaction]) -> Option<u64> {
    txs.iter()
        .filter_map(|tx| tx.accepting_block_blue_score)
        .max()
}

fn next_forward_blue_score(current: u64, candidate: Option<u64>) -> Option<u64> {
    candidate.filter(|candidate| *candidate > current)
}

pub(crate) fn rpc_transaction_to_rest(
    rpc_tx: &RpcTransaction,
    block: &RpcBlock,
    address_prefix: Prefix,
) -> Result<RestTransaction> {
    let transaction_id = match &rpc_tx.verbose_data {
        Some(verbose) => verbose.transaction_id.to_string(),
        None => {
            let tx: Transaction = rpc_tx
                .clone()
                .try_into()
                .context("converting RPC transaction to consensus transaction")?;
            tx.id().to_string()
        }
    };
    let block_hash = block.header.hash.to_string();
    let hash = rpc_tx
        .verbose_data
        .as_ref()
        .map(|verbose| verbose.hash.to_string())
        .unwrap_or_default();
    let mass = rpc_tx
        .verbose_data
        .as_ref()
        .map(|verbose| verbose.compute_mass)
        // Older nodes may omit verbose compute mass; storage mass is the only
        // mass value available on the base RPC transaction in that case.
        .unwrap_or(rpc_tx.storage_mass)
        .to_string();

    let inputs = rpc_tx
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| RestTxInput {
            transaction_id: transaction_id.clone(),
            index: index as u64,
            previous_outpoint_hash: input.previous_outpoint.transaction_id.to_string(),
            previous_outpoint_index: input.previous_outpoint.index.to_string(),
            previous_outpoint_address: None,
            previous_outpoint_amount: None,
            previous_outpoint_script: None,
            signature_script: hex::encode(&input.signature_script),
            sig_op_count: input.sig_op_count.to_string(),
        })
        .collect();
    let outputs = rpc_tx
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let covenant = output.covenant.map(|binding| RestCovenantBinding {
                covenant_id: Some(binding.0.covenant_id.to_string()),
                authorizing_input: Some(binding.0.authorizing_input),
            });
            RestTxOutput {
                transaction_id: transaction_id.clone(),
                index: index as u64,
                amount: output.value,
                script_public_key: hex::encode(output.script_public_key.script()),
                script_public_key_address: output
                    .verbose_data
                    .as_ref()
                    .map(|verbose| verbose.script_public_key_address.to_string())
                    .or_else(|| {
                        extract_script_pub_key_address(&output.script_public_key, address_prefix)
                            .ok()
                            .map(|address| address.to_string())
                    }),
                script_public_key_type: output
                    .verbose_data
                    .as_ref()
                    .map(|verbose| verbose.script_public_key_type.to_string())
                    .or_else(|| {
                        Some(
                            kaspa_wrpc_client::prelude::RpcScriptClass::from_script(
                                &output.script_public_key,
                            )
                            .to_string(),
                        )
                    }),
                covenant_id: covenant
                    .as_ref()
                    .and_then(|binding| binding.covenant_id.clone()),
                covenant,
            }
        })
        .collect();

    Ok(RestTransaction {
        transaction_id,
        subnetwork_id: rpc_tx.subnetwork_id.to_string(),
        hash,
        mass,
        payload: Some(hex::encode(&rpc_tx.payload)),
        block_hash: vec![block_hash],
        block_time: block.header.timestamp,
        version: rpc_tx.version as u32,
        is_accepted: false,
        accepting_block_hash: None,
        accepting_block_blue_score: None,
        accepting_block_time: None,
        inputs,
        outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn cold_unknown_removal_waits_for_body_without_recovery_or_false_cursor(pool: sqlx::PgPool) {
        use crate::live_recovery::{LiveWriteJournal, PgLiveWriteJournal};
        use tn12_indexer_db::PgPersister;
        let writer=Arc::new(PgPersister::new(pool.clone()).with_bounded_writer_lock_wait());
        let old_epoch=writer.rest_removal_revisions(&[vec![0x11;32]]).await.unwrap();
        let stale_rest=writer.with_rest_removal_guard(old_epoch);
        let journal=Arc::new(PgLiveWriteJournal::new(pool.clone(),"testnet-10","cold-event"));
        let watcher=WrpcVirtualChainWatcher::new(writer.clone(),
            Box::new(crate::PgCursorStore::with_key(pool.clone(),"cold-reorg")),
            Box::new(crate::PgCursorStore::with_key(pool.clone(),"cold-live")),
            Box::new(crate::PgCursorStore::with_key(pool.clone(),"cold-heartbeat")),
            WrpcWatcherConfig::with_default_cache("ws://unused".into(),"testnet-10".into()),
        ).with_write_journal(journal.clone());
        let mut body=serde_json::from_str::<Vec<RestTransaction>>(include_str!(
            "../../tn12-indexer-db/tests/fixtures/tn10-dense-generic-32.json"
        )).unwrap().remove(0);
        let notification=VirtualChainChangedNotification {
            removed_chain_block_hashes:Arc::new(vec!["11".repeat(32).parse().unwrap()]),
            added_chain_block_hashes:Arc::new(vec!["22".repeat(32).parse().unwrap()]),
            accepted_transaction_ids:Arc::new(vec![RpcAcceptedTransactionIds {
                accepting_block_hash:"22".repeat(32).parse().unwrap(),
                accepted_transaction_ids:vec![body.transaction_id.parse().unwrap()],
            }]),
        };
        let mut cache=LiveTransactionCache::new(64,Prefix::Testnet);
        let mut score=104;
        let stats=watcher.handle_virtual_chain_changed(&mut cache,&mut score,notification,||async {}).await.unwrap();
        assert_eq!(score,104);
        assert_eq!(stats.body_cache_misses,1);
        assert!(!acceptance_heartbeat_due(&stats,None,Instant::now()));
        assert!(journal.load().await.unwrap().is_none());
        assert_eq!(cache.pending.len(),1);
        assert!(writer.rest_removal_revisions(&[vec![0x11;32]]).await.unwrap()[&vec![0x11;32]]>0);
        body.accepting_block_hash=Some("11".repeat(32));
        body.accepting_block_blue_score=Some(105);
        let error=stale_rest.persist_tx(&body).await.unwrap_err();
        assert!(error.is::<tn12_indexer_db::persist::StaleRestAcceptance>());
        cache.transactions.insert(body.transaction_id.clone(),body.clone());
        cache.blocks.insert("22".repeat(32),Acceptance {block_hash:"22".repeat(32),blue_score:106,timestamp:1000});
        let ready=cache.drain_ready();
        assert_eq!(ready.len(),1);
        watcher.persist_candidates(ready.clone(),&mut WrpcWatcherStats::default()).await.unwrap();
        watcher.advance_live_cursor(&mut score,max_acceptance_blue_score(&ready)).await.unwrap();
        assert_eq!(score,106);
        assert!(cache.drain_ready().is_empty());
        assert!(journal.load().await.unwrap().is_none());
        let hash:Vec<u8>=sqlx::query_scalar("SELECT created_block FROM covenant_utxos WHERE txid=$1 LIMIT 1")
            .bind(hex::decode(&body.transaction_id).unwrap()).fetch_one(&pool).await.unwrap();
        assert_eq!(hash,vec![0x22u8;32]);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn journaled_live_event_commits_replacement_and_clears_read_fence(pool: sqlx::PgPool) {
        journaled_event_case(pool, false, 1, false, false, false).await;
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn journaled_live_event_cursor_failure_retains_recovery_and_read_fence(pool: sqlx::PgPool) {
        journaled_event_case(pool, true, 1, false, false, false).await;
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn oversized_live_event_retains_complete_journal_before_removal(pool: sqlx::PgPool) {
        journaled_event_case(pool, false, 33, false, false, false).await;
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn indexed_reorg_ignores_unrelated_pending_but_does_not_certify_tip(pool: sqlx::PgPool) {
        journaled_event_case(pool, false, 1, true, false, false).await;
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn indexed_reorg_with_unknown_empty_removal_commits_both_epochs(pool: sqlx::PgPool) {
        journaled_event_case(pool, false, 1, true, true, false).await;
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn journaled_live_reorg_hydrates_missing_header_before_removal(pool: sqlx::PgPool) {
        journaled_event_case(pool, false, 1, true, true, true).await;
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn unavailable_live_header_retains_journal_before_any_removal(pool: sqlx::PgPool) {
        // A zero candidate count selects the missing-source fixture path.
        journaled_event_case(pool, false, 0, false, false, true).await;
    }

    async fn journaled_event_case(pool: sqlx::PgPool, fail_cursor: bool, candidates: usize,
        unrelated_pending: bool, unknown_removal: bool, hydrate_missing: bool) {
        use crate::live_recovery::{LiveWriteJournal, PgLiveWriteJournal};
        use tn12_indexer_db::PgPersister;
        let writer = Arc::new(PgPersister::new(pool.clone()));
        let mut original: RestTransaction = serde_json::from_str::<Vec<RestTransaction>>(include_str!(
            "../../tn12-indexer-db/tests/fixtures/tn10-dense-generic-32.json"
        )).unwrap().remove(0);
        original.accepting_block_hash = Some("11".repeat(32));
        original.accepting_block_blue_score = Some(105);
        writer.persist_tx(&original).await.unwrap();
        let journal = Arc::new(PgLiveWriteJournal::new(pool.clone(), "testnet-10", "event-test"));
        let watcher = WrpcVirtualChainWatcher::new(
            writer, Box::new(crate::PgCursorStore::with_key(pool.clone(), "event-reorg")),
            Box::new(crate::PgCursorStore::with_key(pool.clone(), "event-live")),
            Box::new(crate::PgCursorStore::with_key(pool.clone(), "event-heartbeat")),
            WrpcWatcherConfig::with_default_cache("ws://unused".into(), "testnet-10".into()),
        ).with_write_journal(journal.clone());
        if fail_cursor {
            sqlx::raw_sql("CREATE FUNCTION fail_event_cursor() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN IF NEW.key='event-live' THEN RAISE EXCEPTION 'injected cursor failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_event_cursor BEFORE INSERT OR UPDATE ON indexer_state FOR EACH ROW EXECUTE FUNCTION fail_event_cursor();")
                .execute(&pool).await.unwrap();
        }
        let mut cache = LiveTransactionCache::new(64, Prefix::Testnet);
        cache.transactions.insert(original.transaction_id.clone(), original.clone());
        let mut accepted_ids = vec![original.transaction_id.parse().unwrap()];
        for id in 1..candidates {
            let mut extra = original.clone();
            extra.transaction_id = hex::encode([id as u8;32]);
            accepted_ids.push(extra.transaction_id.parse().unwrap());
            cache.transactions.insert(extra.transaction_id.clone(),extra);
        }
        for (id, score) in [(0x11u8,105), (0x22u8,106)] {
            let hash = hex::encode([id;32]);
            cache.blocks.insert(hash.clone(), Acceptance { block_hash:hash, blue_score:score, timestamp:1000 });
        }
        let notification = VirtualChainChangedNotification {
            removed_chain_block_hashes:Arc::new(vec!["11".repeat(32).parse().unwrap()]),
            added_chain_block_hashes:Arc::new(vec!["22".repeat(32).parse().unwrap()]),
            accepted_transaction_ids:Arc::new(vec![RpcAcceptedTransactionIds {
                accepting_block_hash:"22".repeat(32).parse().unwrap(),
                accepted_transaction_ids:accepted_ids,
            }]),
        };
        let mut notification=notification;
        if unrelated_pending {
            notification.added_chain_block_hashes=Arc::new(vec![
                "22".repeat(32).parse().unwrap(),"44".repeat(32).parse().unwrap()]);
            let mut groups=notification.accepted_transaction_ids.as_ref().clone();
            groups.push(RpcAcceptedTransactionIds {
                accepting_block_hash:"44".repeat(32).parse().unwrap(),
                accepted_transaction_ids:Vec::new(),
            });
            notification.accepted_transaction_ids=Arc::new(groups);
        }
        if unknown_removal {
            notification.removed_chain_block_hashes=Arc::new(vec![
                "11".repeat(32).parse().unwrap(),"33".repeat(32).parse().unwrap()]);
        }
        if unrelated_pending {
            cache.pending.insert("aa".repeat(32),"bb".repeat(32));
            cache.pending_order.push_back("aa".repeat(32));
        }
        let mut score=105;
        let start = Instant::now();
        let source=hydration::tests::FixtureSource(
            if candidates==0 {vec![]} else {vec![hydration::tests::block(0x22)]},
            std::sync::Mutex::new(vec![]));
        if hydrate_missing { cache.blocks.remove(&"22".repeat(32)); }
        let result = watcher.handle_virtual_chain_changed_with_source(&mut cache, &mut score, notification,
            hydrate_missing.then_some(&source as &dyn hydration::BlockSource), || async {}).await;
        if hydrate_missing { assert_eq!(source.1.lock().unwrap().len(),1); }
        eprintln!("journaled event elapsed={:?}, fail_cursor={fail_cursor}",start.elapsed());
        if candidates==0 {
            assert!(result.unwrap_err().is::<crate::live_supervisor::RecoveryPending>());
            let retained=journal.load().await.unwrap().unwrap();
            assert!(retained.unresolved_blocks.contains(&"22".repeat(32)));
        } else if candidates>32 {
            assert!(result.unwrap_err().is::<crate::live_supervisor::RecoveryPending>());
            assert_eq!(journal.load().await.unwrap().unwrap().transactions.len(),candidates);
        } else if fail_cursor {
            assert!(format!("{:#}", result.unwrap_err()).contains("injected cursor failure"));
            assert!(journal.load().await.unwrap().is_some());
        } else {
            let stats=result.unwrap();
            if unrelated_pending {
                assert_eq!(cache.pending.get(&"aa".repeat(32)),Some(&"bb".repeat(32)));
                assert_eq!(stats.body_cache_misses,1);
                assert!(!acceptance_heartbeat_due(&stats,None,Instant::now()));
                assert_eq!(score,105,"unresolved older acceptance must not advance live cursor");
                let saved:Option<serde_json::Value>=sqlx::query_scalar("SELECT value FROM indexer_state WHERE key='event-live'")
                    .fetch_optional(&pool).await.unwrap();
                assert!(saved.is_none());
            }
            if unknown_removal {
                let revision:i64=sqlx::query_scalar("SELECT revision FROM rest_replay_removed_blocks WHERE block_hash=$1")
                    .bind(vec![0x33u8;32]).fetch_one(&pool).await.unwrap();
                assert!(revision>0);
            }
            assert!(journal.load().await.unwrap().is_none());
        }
        let fences:i64 = sqlx::query_scalar("SELECT count(*) FROM tn10_live_event_fences").fetch_one(&pool).await.unwrap();
        assert_eq!(fences, i64::from(fail_cursor));
        let hashes:Vec<Vec<u8>> = sqlx::query_scalar("SELECT DISTINCT created_block FROM covenant_utxos WHERE txid=$1")
            .bind(hex::decode(&original.transaction_id).unwrap()).fetch_all(&pool).await.unwrap();
        assert_eq!(hashes,vec![vec![if candidates==0 || candidates>32 {0x11u8} else {0x22u8};32]]);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn captured_live_cache_bulk_matches_scalar_replay_and_reorg(pool: sqlx::PgPool) {
        use tn12_indexer_db::PgPersister;
        let mut parents: Vec<RestTransaction> =
            serde_json::from_str(include_str!("../tests/fixtures/live-oom-parents.json")).unwrap();
        let children: Vec<RestTransaction> =
            serde_json::from_str(include_str!("../tests/fixtures/live-oom-transactions.json"))
                .unwrap();
        let mut cache = LiveTransactionCache::new(100_000, Prefix::Testnet);
        let serial = PgPersister::with_network_id(pool.clone(), "testnet-10");
        for parent in &mut parents {
            parent.is_accepted = true;
            parent.accepting_block_hash = Some("bb".repeat(32));
            parent.accepting_block_blue_score = Some(1);
            parent.accepting_block_time = Some(1000);
            serial.persist_tx(parent).await.unwrap();
            cache
                .transactions
                .insert(parent.transaction_id.clone(), parent.clone());
        }
        let accepting = "aa".repeat(32);
        cache.blocks.insert(
            accepting.clone(),
            Acceptance {
                block_hash: accepting.clone(),
                blue_score: 2,
                timestamp: 2000,
            },
        );
        for child in &children {
            cache
                .transactions
                .insert(child.transaction_id.clone(), child.clone());
        }
        let ready = cache.accept(&[RpcAcceptedTransactionIds {
            accepting_block_hash: accepting.parse().unwrap(),
            accepted_transaction_ids: children
                .iter()
                .map(|t| t.transaction_id.parse().unwrap())
                .collect(),
        }]);
        assert_eq!(ready.len(), 16);
        sqlx::raw_sql("CREATE TABLE live_update_count(n BIGINT); INSERT INTO live_update_count VALUES(0);             CREATE FUNCTION count_live_updates() RETURNS TRIGGER LANGUAGE plpgsql AS $$             BEGIN UPDATE live_update_count SET n=n+1; RETURN NULL; END $$;             CREATE TRIGGER count_live_updates AFTER UPDATE ON covenant_utxos             FOR EACH STATEMENT EXECUTE FUNCTION count_live_updates();")
            .execute(&pool).await.unwrap();
        async fn snapshot(pool: &sqlx::PgPool) -> Vec<serde_json::Value> {
            let mut rows = Vec::new();
            for query in [
                "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) - 'indexed_at_ms' AS v FROM blocks t) s",
                "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM covenants t) s",
                "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM covenant_utxos t) s",
                "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) - 'id' AS v FROM covenant_actions t) s",
                "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) - 'updated_at_ms' AS v FROM covenant_summaries t) s",
            ] {
                rows.push(sqlx::query_scalar(query).fetch_one(pool).await.unwrap());
            }
            rows
        }
        let mut expected = None;
        for bulk in [false, true] {
            sqlx::query("UPDATE live_update_count SET n=0")
                .execute(&pool)
                .await
                .unwrap();
            let writer = PgPersister::with_network_id(pool.clone(), "testnet-10")
                .with_bounded_writer_lock_wait()
                .with_generic_bulk_persist(bulk)
                .with_generic_writer_budget(bulk)
                .with_generic_bulk_max_txs(16);
            writer.persist_batch(&ready).await.unwrap();
            let updates: i64 = sqlx::query_scalar("SELECT n FROM live_update_count")
                .fetch_one(&pool)
                .await
                .unwrap();
            if bulk {
                assert!(
                    updates < 16,
                    "actual cache output must use bulk writes: {updates}"
                );
            }
            let state = snapshot(&pool).await;
            if let Some(expected) = &expected {
                assert_eq!(&state, expected);
            } else {
                expected = Some(state.clone());
            }
            writer.persist_batch(&ready).await.unwrap();
            assert_eq!(snapshot(&pool).await, state, "duplicate replay");
            writer
                .revert_block(&hex::decode(&accepting).unwrap())
                .await
                .unwrap();
            let active: i64 =
                sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE status='active'")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(active, 16, "reorg restores captured parent outputs");
        }
    }

    #[test]
    fn cached_live_prevouts_leave_missing_or_conflicting_evidence_unchanged() {
        let parents: Vec<RestTransaction> =
            serde_json::from_str(include_str!("../tests/fixtures/live-oom-parents.json")).unwrap();
        let children: Vec<RestTransaction> =
            serde_json::from_str(include_str!("../tests/fixtures/live-oom-transactions.json"))
                .unwrap();
        let child = children[0].clone();
        let parent = parents
            .iter()
            .find(|p| p.transaction_id == child.inputs[0].previous_outpoint_hash)
            .unwrap();
        for case in 0..9 {
            let mut cache = LiveTransactionCache::new(100_000, Prefix::Testnet);
            let mut parent = parent.clone();
            let mut tx = child.clone();
            match case {
                0 => {} // absent or evicted parent
                1 => parent.transaction_id = "ff".repeat(32),
                2 => tx.inputs[0].previous_outpoint_index = "invalid".into(),
                3 => tx.inputs[0].previous_outpoint_index = "999999".into(),
                4 => parent.outputs[0].index = 999999,
                5 => parent.outputs[0].transaction_id = "ff".repeat(32),
                6 => tx.inputs[0].previous_outpoint_script = Some("conflicting".into()),
                7 => tx.inputs[0].previous_outpoint_amount = Some(u64::MAX),
                8 => tx.inputs[0].previous_outpoint_address = Some("conflicting".into()),
                _ => unreachable!(),
            }
            if case != 0 {
                cache
                    .transactions
                    .insert(child.inputs[0].previous_outpoint_hash.clone(), parent);
            }
            let before = serde_json::to_value(&tx).unwrap();
            cache.resolve_cached_prevouts(&mut tx);
            assert_eq!(serde_json::to_value(&tx).unwrap(), before, "case {case}");
        }
    }

    #[test]
    fn cached_live_prevouts_resolve_exact_captured_parent_bodies() {
        let parents: Vec<RestTransaction> =
            serde_json::from_str(include_str!("../tests/fixtures/live-oom-parents.json")).unwrap();
        let children: Vec<RestTransaction> =
            serde_json::from_str(include_str!("../tests/fixtures/live-oom-transactions.json"))
                .unwrap();
        let mut cache = LiveTransactionCache::new(100_000, Prefix::Testnet);
        for parent in &parents {
            cache
                .transactions
                .insert(parent.transaction_id.clone(), parent.clone());
        }
        let accepting = "aa".repeat(32);
        cache.blocks.insert(
            accepting.clone(),
            Acceptance {
                block_hash: accepting.clone(),
                blue_score: 1,
                timestamp: 1,
            },
        );
        for child in &children {
            assert!(child
                .inputs
                .iter()
                .all(|input| input.previous_outpoint_script.is_none()));
            cache
                .transactions
                .insert(child.transaction_id.clone(), child.clone());
        }
        let ready = cache.accept(&[RpcAcceptedTransactionIds {
            accepting_block_hash: accepting.parse().unwrap(),
            accepted_transaction_ids: children
                .iter()
                .map(|tx| tx.transaction_id.parse().unwrap())
                .collect(),
        }]);
        assert_eq!(ready.len(), children.len());
        for child in &ready {
            for input in &child.inputs {
                let parent = parents
                    .iter()
                    .find(|tx| tx.transaction_id == input.previous_outpoint_hash)
                    .unwrap();
                let index = input.previous_outpoint_index.parse::<u64>().unwrap();
                let output = parent
                    .outputs
                    .iter()
                    .find(|output| output.index == index)
                    .unwrap();
                assert_eq!(
                    input.previous_outpoint_script.as_deref(),
                    Some(output.script_public_key.as_str())
                );
                assert_eq!(input.previous_outpoint_amount, Some(output.amount));
                assert_eq!(
                    input.previous_outpoint_address,
                    output.script_public_key_address
                );
            }
            assert!(
                cache.transactions[&child.transaction_id]
                    .inputs
                    .iter()
                    .all(|input| input.previous_outpoint_script.is_none()),
                "immutable cached bodies stay unchanged"
            );
        }
    }

    use std::collections::BTreeMap;
    use std::sync::Mutex;
    #[derive(Clone, Default)]
    struct PhaseCapture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);
    struct PhaseFields(BTreeMap<String, String>);
    impl tracing::field::Visit for PhaseFields {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }
    }
    impl tracing::Subscriber for PhaseCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() == "wrpc_phase" {
                let mut fields = PhaseFields(BTreeMap::new());
                event.record(&mut fields);
                fields
                    .0
                    .insert("level".into(), event.metadata().level().to_string());
                self.0.lock().unwrap().push(fields.0);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    fn phase_timing_preserves_result_cancellation_and_threshold() {
        let capture = PhaseCapture::default();
        let _subscriber = tracing::subscriber::set_default(capture.clone());
        let answer = futures::executor::block_on(observe_wrpc_phase("success", async { Ok(42) }));
        assert_eq!(answer.unwrap(), 42);
        let error = futures::executor::block_on(observe_wrpc_phase::<()>("error", async {
            Err(std::io::Error::other("fixture").into())
        }))
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().to_string(),
            "fixture"
        );
        let mut pending = Box::pin(observe_wrpc_phase::<()>(
            "cancelled",
            futures::future::pending(),
        ));
        assert!(pending.as_mut().now_or_never().is_none());
        drop(pending);
        report_wrpc_phase("below", Duration::from_micros(249_999), "ok");
        report_wrpc_phase("boundary", Duration::from_millis(250), "ok");
        let events = capture.0.lock().unwrap();
        let completed: Vec<_> = events
            .iter()
            .filter(|e| e.contains_key("outcome"))
            .collect();
        assert_eq!(completed.len(), 5);
        assert_eq!(completed[0]["outcome"], "ok");
        assert_eq!(completed[1]["outcome"], "error");
        assert_eq!(completed[2]["outcome"], "incomplete");
        assert_eq!(completed[2]["level"], "WARN");
        assert_eq!(completed[3]["level"], "DEBUG");
        assert_eq!(completed[4]["level"], "WARN");
        assert_eq!(completed[4]["elapsed_us"], "250000");
    }

    #[tokio::test]
    #[ignore = "read-only live smoke; requires TN10_WRPC_TEST_URL"]
    async fn live_raw_reconnect_preserves_notification_services() {
        let url = std::env::var("TN10_WRPC_TEST_URL").expect("set the read-only wRPC endpoint");
        let rpc = KaspaRpcClient::new_with_args(
            WrpcEncoding::Borsh,
            Some(&url),
            None,
            Some(NetworkId::from_str("testnet-10").unwrap()),
            None,
        )
        .unwrap();
        let events = Channel::<Notification>::unbounded();
        let control = rpc.rpc_ctl().multiplexer().channel();
        rpc.connect(Some(ConnectOptions {
            block_async_connect: false,
            ..Default::default()
        }))
        .await
        .unwrap();
        let mut listener = None;
        for round in 0..2 {
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    match control.receiver.recv().await.unwrap() {
                        RpcState::Disconnected => {
                            if let Some(id) = listener.take() {
                                rpc.unregister_listener(id).await.unwrap();
                            }
                        }
                        RpcState::Connected => {
                            while events.receiver.try_recv().is_ok() {}
                            let id = rpc.register_new_listener(ChannelConnection::new(
                                "RECONNECT-SMOKE",
                                events.sender.clone(),
                                ChannelType::Persistent,
                            ));
                            rpc.start_notify(id, Scope::BlockAdded(BlockAddedScope {}))
                                .await
                                .unwrap();
                            listener = Some(id);
                            break;
                        }
                    }
                }
                for _ in 0..3 {
                    assert!(matches!(
                        events.receiver.recv().await.unwrap(),
                        Notification::BlockAdded(_)
                    ));
                }
            })
            .await
            .expect("fresh block notifications after connection");
            if round == 0 {
                rpc.rpc_client().shutdown().await.unwrap();
                rpc.rpc_client()
                    .connect(ConnectOptions {
                        block_async_connect: false,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
            }
        }
        if let Some(id) = listener {
            rpc.unregister_listener(id).await.unwrap();
        }
        rpc.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn paused_reorg_with_unknown_live_commit_retains_window_without_reconnect() {
        use tn12_indexer_db::{PersistStats, RevertStats};
        struct Probe(std::sync::atomic::AtomicBool);
        #[async_trait::async_trait]
        impl Persister for Probe {
            async fn persist_batch(&self, _: &[RestTransaction]) -> Result<PersistStats> {
                Err(tn12_indexer_db::persist::GenericWriteOutcomeUnknown {
                    phase: "commit",
                    detail: "injected lost acknowledgement".into(),
                }
                .into())
            }
            async fn persist_tx(&self, _: &RestTransaction) -> Result<PersistStats> {
                panic!("uncertain commit must never fall back to individual writes");
            }
            async fn revert_block(&self, _: &[u8]) -> Result<RevertStats> {
                if !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    anyhow::bail!("fixture removal retry");
                }
                Ok(RevertStats { reverted_blue_score: Some(10), blocks_removed: 1, ..Default::default() })
            }
            async fn has_utxo(&self, _: &str, _: i32) -> Result<bool> {
                Ok(false)
            }
        }
        struct Cursor;
        #[async_trait::async_trait]
        impl CursorStore for Cursor {
            async fn load(&self) -> Result<Option<u64>> {
                Ok(None)
            }
            async fn save(&self, score: u64, _: Option<u64>) -> Result<()> {
                assert_eq!(score, 10, "uncertain window cannot advance cursor or heartbeat");
                Ok(())
            }
        }
        use crate::live_recovery::{LiveWriteJournal, LiveWriteWindow};
        #[derive(Default)]
        struct Journal(Mutex<Option<LiveWriteWindow>>);
        #[async_trait::async_trait]
        impl LiveWriteJournal for Journal {
            async fn load(&self) -> Result<Option<LiveWriteWindow>> {
                Ok(self.0.lock().unwrap().clone())
            }
            async fn begin(&self, window: &LiveWriteWindow) -> Result<()> {
                *self.0.lock().unwrap() = Some(window.clone());
                Ok(())
            }
            async fn replace(&self, _: &LiveWriteWindow, _: &LiveWriteWindow) -> Result<()> {
                unreachable!()
            }
            async fn complete(&self, _: &LiveWriteWindow) -> Result<()> {
                panic!("uncertain write cannot clear durable intent");
            }
        }
        let journal = Arc::new(Journal::default());
        let watcher = WrpcVirtualChainWatcher::new(
            Arc::new(Probe(std::sync::atomic::AtomicBool::new(false))),
            Box::new(Cursor),
            Box::new(Cursor),
            Box::new(Cursor),
            WrpcWatcherConfig::with_default_cache("ws://unused".into(), "testnet-10".into()),
        )
        .with_write_journal(journal.clone());
        let mut cache = LiveTransactionCache::new(10, Prefix::Testnet);
        let txid = "11".repeat(32);
        let accepting = "22".repeat(32);
        cache.transactions.insert(
            txid.clone(),
            RestTransaction {
                transaction_id: txid.clone(),
                outputs: vec![RestTxOutput {
                    script_public_key: format!("aa20{}87", "44".repeat(32)),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        cache.blocks.insert(
            accepting.clone(),
            Acceptance {
                block_hash: accepting.clone(),
                blue_score: 11,
                timestamp: 1000,
            },
        );
        let notification = VirtualChainChangedNotification {
            removed_chain_block_hashes: Arc::new(vec!["33".repeat(32).parse().unwrap()]),
            added_chain_block_hashes: Arc::new(vec![accepting.parse().unwrap()]),
            accepted_transaction_ids: Arc::new(vec![RpcAcceptedTransactionIds {
                accepting_block_hash: accepting.parse().unwrap(),
                accepted_transaction_ids: vec![txid.parse().unwrap()],
            }]),
        };
        let mut score = 10;
        let mut paused = false;
        let result = watcher
            .handle_virtual_chain_changed(&mut cache, &mut score, notification, || { paused = true; async {} })
            .await;
        assert!(paused, "removal retry must stop ingress");
        assert!(!WrpcVirtualChainWatcher::<Probe>::should_resume_ingress(paused, &result), "uncertain commit must not reconnect before recovery");
        let error = result.unwrap_err();
        assert!(error
            .downcast_ref::<tn12_indexer_db::persist::GenericWriteOutcomeUnknown>()
            .is_some());
        assert_eq!(score, 10);
        let retained = journal
            .load()
            .await
            .unwrap()
            .expect("durable accepted window retained");
        assert_eq!(retained.transactions.len(), 1);
        assert_eq!(retained.transactions[0].transaction_id, txid);
        assert_eq!(
            retained.transactions[0].accepting_block_hash,
            Some(accepting)
        );
        assert_eq!(
            retained.transactions[0].accepting_block_blue_score,
            Some(11)
        );
    }

    #[tokio::test]
    async fn removal_retry_completes_before_same_event_additions() {
        use std::sync::Mutex;
        use tn12_indexer_db::{PersistStats, RevertStats};
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let phases = PhaseCapture::default();
        let _subscriber = tracing::subscriber::set_default(phases.clone());
        struct Probe(Arc<Mutex<Vec<String>>>);
        #[async_trait::async_trait]
        impl Persister for Probe {
            async fn persist_tx(&self, _: &RestTransaction) -> Result<PersistStats> {
                self.0.lock().unwrap().push("persist".into());
                Ok(PersistStats::default())
            }
            async fn revert_block(&self, _: &[u8]) -> Result<RevertStats> {
                let mut events = self.0.lock().unwrap();
                events.push("remove".into());
                if events.len() == 1 {
                    anyhow::bail!("fixture lock failure");
                }
                Ok(RevertStats {
                    reverted_blue_score: Some(10),
                    blocks_removed: 1,
                    ..Default::default()
                })
            }
            async fn has_utxo(&self, _: &str, _: i32) -> Result<bool> {
                unreachable!()
            }
        }
        struct Cursor(Arc<Mutex<Vec<String>>>);
        #[async_trait::async_trait]
        impl CursorStore for Cursor {
            async fn load(&self) -> Result<Option<u64>> {
                Ok(None)
            }
            async fn save(&self, score: u64, _: Option<u64>) -> Result<()> {
                self.0.lock().unwrap().push(format!("cursor:{score}"));
                Ok(())
            }
        }
        let watcher = WrpcVirtualChainWatcher::new(
            Arc::new(Probe(events.clone())),
            Box::new(Cursor(events.clone())),
            Box::new(Cursor(events.clone())),
            Box::new(Cursor(events.clone())),
            WrpcWatcherConfig::with_default_cache("ws://unused".into(), "testnet-10".into()),
        );
        let mut cache = LiveTransactionCache::new(10, Prefix::Testnet);
        let txid = "11".repeat(32);
        let accepting = "22".repeat(32);
        cache.transactions.insert(
            txid.clone(),
            RestTransaction {
                transaction_id: txid.clone(),
                outputs: vec![RestTxOutput {
                    script_public_key: format!("aa20{}87", "44".repeat(32)),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        cache.blocks.insert(
            accepting.clone(),
            Acceptance {
                block_hash: accepting.clone(),
                blue_score: 11,
                timestamp: 1_000,
            },
        );
        let notification = VirtualChainChangedNotification {
            removed_chain_block_hashes: Arc::new(vec!["33".repeat(32).parse().unwrap()]),
            added_chain_block_hashes: Arc::new(vec![accepting.parse().unwrap()]),
            accepted_transaction_ids: Arc::new(vec![RpcAcceptedTransactionIds {
                accepting_block_hash: accepting.parse().unwrap(),
                accepted_transaction_ids: vec![txid.parse().unwrap()],
            }]),
        };
        let mut score = 10;
        let stats = tokio::time::timeout(
            Duration::from_secs(5),
            watcher.handle_virtual_chain_changed(&mut cache, &mut score, notification, || {
                events.lock().unwrap().push("pause-ingress".into());
                async {}
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stats.persisted_txs, 1);
        assert_eq!(score, 11);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "remove",
                "pause-ingress",
                "remove",
                "cursor:10",
                "persist",
                "cursor:11"
            ]
        );
        watcher
            .record_acceptance_heartbeat(&stats, score, &mut None)
            .await;
        let captured = phases.0.lock().unwrap();
        let finished: Vec<_> = captured
            .iter()
            .filter(|e| e.contains_key("outcome"))
            .collect();
        assert_eq!(
            finished
                .iter()
                .map(|e| e["phase"].as_str())
                .collect::<Vec<_>>(),
            [
                "reorg",
                "existing_utxos",
                "persist_batch",
                "live_cursor",
                "acceptance_heartbeat"
            ]
        );
        assert!(finished.iter().all(|e| e["outcome"] == "ok"));
    }

    #[test]
    fn acceptance_heartbeat_requires_complete_event_and_bounded_interval() {
        let now = Instant::now();
        let complete = WrpcWatcherStats {
            accepted_txids: 1,
            ..Default::default()
        };
        assert!(acceptance_heartbeat_due(&complete, None, now));
        assert!(!acceptance_heartbeat_due(
            &complete,
            Some(now - Duration::from_secs(1)),
            now
        ));
        assert!(acceptance_heartbeat_due(
            &complete,
            Some(now - ACCEPTANCE_HEARTBEAT_INTERVAL),
            now
        ));
        assert!(!acceptance_heartbeat_due(
            &WrpcWatcherStats {
                body_cache_misses: 1,
                ..complete
            },
            None,
            now
        ));
        assert!(!acceptance_heartbeat_due(
            &WrpcWatcherStats {
                persist_errors: 1,
                ..complete
            },
            None,
            now
        ));
        assert!(!acceptance_heartbeat_due(
            &WrpcWatcherStats::default(),
            None,
            now
        ));
    }
    #[test]
    fn empty_acceptance_data_has_no_ready_transactions() {
        let mut cache = LiveTransactionCache::new(10, Prefix::Testnet);
        assert!(cache.accept(&[]).is_empty());
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn bounded_cache_evicts_bodies_without_acknowledging_pending_acceptances() {
        let mut cache = LiveTransactionCache::new(1, Prefix::Testnet);
        cache
            .transactions
            .insert("old".into(), RestTransaction::default());
        cache.transaction_order.push_back("old".into());
        cache
            .transactions
            .insert("new".into(), RestTransaction::default());
        cache.transaction_order.push_back("new".into());
        cache.pending.insert("old".into(), "block".into());
        cache.pending_order.push_back("old".into());

        cache.prune();

        assert!(!cache.transactions.contains_key("old"));
        assert!(cache.transactions.contains_key("new"));
        assert_eq!(cache.pending.get("old").map(String::as_str),Some("block"));
        assert!(cache.drain_ready().is_empty());
        assert_eq!(cache.pending_order,VecDeque::from(["old".to_owned()]));
    }

    #[test]
    fn reorg_cancels_only_pending_acceptances_from_removed_blocks() {
        let mut cache = LiveTransactionCache::new(10, Prefix::Testnet);
        cache.pending.insert("removed-tx".into(), "removed".into());
        cache.pending.insert("kept-tx".into(), "kept".into());
        cache.pending_order.push_back("removed-tx".into());
        cache.pending_order.push_back("kept-tx".into());

        cache.cancel_pending_acceptances(&HashSet::from(["removed".to_string()]));

        assert!(!cache.pending.contains_key("removed-tx"));
        assert_eq!(cache.pending_order, VecDeque::from(["kept-tx".into()]));
    }

    #[test]
    fn acceptance_waits_for_both_transaction_and_accepting_block() {
        let mut cache = LiveTransactionCache::new(10, Prefix::Testnet);
        cache.pending.insert("tx".into(), "accepting".into());
        cache.pending_order.push_back("tx".into());
        cache.transactions.insert(
            "tx".into(),
            RestTransaction {
                transaction_id: "tx".into(),
                ..Default::default()
            },
        );
        assert!(cache.drain_ready().is_empty());

        cache.blocks.insert(
            "accepting".into(),
            Acceptance {
                block_hash: "accepting".into(),
                blue_score: 42,
                timestamp: 1_234,
            },
        );
        let ready = cache.drain_ready();

        assert_eq!(ready.len(), 1);
        assert!(ready[0].is_accepted);
        assert_eq!(ready[0].accepting_block_hash.as_deref(), Some("accepting"));
        assert_eq!(ready[0].accepting_block_blue_score, Some(42));
        assert_eq!(ready[0].accepting_block_time, Some(1_234));
        let joined_stats = WrpcWatcherStats {
            block_notifications: 1,
            accepted_txids: ready.len() as u64,
            ..Default::default()
        };
        assert!(acceptance_heartbeat_due(
            &joined_stats,
            None,
            Instant::now()
        ));
    }

    #[test]
    fn partial_delayed_join_keeps_heartbeat_stale() {
        let mut cache = LiveTransactionCache::new(10, Prefix::Testnet);
        for txid in ["ready", "waiting"] {
            cache.pending.insert(txid.into(), "accepting".into());
            cache.pending_order.push_back(txid.into());
        }
        cache.blocks.insert(
            "accepting".into(),
            Acceptance {
                block_hash: "accepting".into(),
                blue_score: 42,
                timestamp: 1_234,
            },
        );
        cache.transactions.insert(
            "ready".into(),
            RestTransaction {
                transaction_id: "ready".into(),
                ..Default::default()
            },
        );
        let joined = cache.drain_ready();
        assert_eq!(joined.len(), 1);
        assert_eq!(cache.pending.len(), 1);
        let partial_stats = WrpcWatcherStats {
            block_notifications: 1,
            accepted_txids: joined.len() as u64,
            body_cache_misses: cache.pending.len() as u64,
            ..Default::default()
        };
        assert!(!acceptance_heartbeat_due(
            &partial_stats,
            None,
            Instant::now()
        ));

        cache.transactions.insert(
            "waiting".into(),
            RestTransaction {
                transaction_id: "waiting".into(),
                ..Default::default()
            },
        );
        let joined = cache.drain_ready();
        assert_eq!(joined.len(), 1);
        assert!(cache.pending.is_empty());
        let complete_stats = WrpcWatcherStats {
            block_notifications: 1,
            accepted_txids: joined.len() as u64,
            body_cache_misses: cache.pending.len() as u64,
            ..Default::default()
        };
        assert!(acceptance_heartbeat_due(
            &complete_stats,
            None,
            Instant::now()
        ));
    }

    #[test]
    fn default_cache_is_large_enough_for_stream_jitter() {
        let config = WrpcWatcherConfig::with_default_cache("ws://node".into(), "testnet-10".into());
        assert_eq!(config.cache_capacity, DEFAULT_CACHE_CAPACITY);
    }

    #[test]
    fn latency_sample_identifies_old_header_without_claiming_processing_delay() {
        let txs = vec![
            RestTransaction {
                transaction_id: "newer".into(),
                accepting_block_time: Some(9_000),
                ..Default::default()
            },
            RestTransaction {
                transaction_id: "older".into(),
                accepting_block_hash: Some("block-old".into()),
                accepting_block_time: Some(7_999),
                ..Default::default()
            },
            RestTransaction {
                transaction_id: "missing".into(),
                ..Default::default()
            },
        ];
        let (tx, age) = max_acceptance_latency_sample(&txs, 10_000).unwrap();
        assert_eq!(tx.transaction_id, "older");
        assert_eq!(tx.accepting_block_hash.as_deref(), Some("block-old"));
        assert_eq!(age, 2_001);
        let mut stats = WrpcWatcherStats {
            persisted_txs: 4,
            max_index_latency_ms: 3_000,
            ..Default::default()
        };
        record_persist_success_at(&txs, &mut stats, 10_000, 237_000, "batch");
        assert_eq!(stats.persisted_txs, 7);
        assert_eq!(stats.max_index_latency_ms, 3_000);
        assert_eq!(stats.persist_errors, 0);
    }

    #[test]
    fn latency_sample_handles_missing_future_and_tied_timestamps() {
        assert!(max_acceptance_latency_sample(&[], 10_000).is_none());
        assert!(max_acceptance_latency_sample(&[RestTransaction::default()], 10_000).is_none());
        let future = [RestTransaction {
            transaction_id: "future".into(),
            accepting_block_time: Some(u64::MAX),
            ..Default::default()
        }];
        assert_eq!(max_acceptance_latency_sample(&future, 10_000).unwrap().1, 0);
        let tied = [
            RestTransaction {
                transaction_id: "b".into(),
                accepting_block_time: Some(8_000),
                ..Default::default()
            },
            RestTransaction {
                transaction_id: "a".into(),
                accepting_block_time: Some(8_000),
                ..Default::default()
            },
        ];
        assert_eq!(
            max_acceptance_latency_sample(&tied, 10_000)
                .unwrap()
                .0
                .transaction_id,
            "a"
        );
        let mut stats = WrpcWatcherStats::default();
        record_persist_success_at(&future, &mut stats, 10_000, 5, "individual_fallback");
        assert_eq!(stats.persisted_txs, 1);
        assert_eq!(stats.max_index_latency_ms, 0);
        assert_eq!(stats.persist_errors, 0);
    }

    #[test]
    fn latency_sample_threshold_and_fallback_selection_are_exact() {
        let txs = [
            RestTransaction {
                transaction_id: "below".into(),
                accepting_block_time: Some(8_501),
                ..Default::default()
            },
            RestTransaction {
                transaction_id: "threshold".into(),
                accepting_block_time: Some(8_500),
                ..Default::default()
            },
            RestTransaction {
                transaction_id: "older".into(),
                accepting_block_time: Some(7_999),
                ..Default::default()
            },
        ];
        let mut stats = WrpcWatcherStats::default();
        assert!(record_persist_success_at(&txs[..1], &mut stats, 10_000, 1, "batch").is_none());
        let threshold = record_persist_success_at(
            &txs[1..2],
            &mut stats,
            10_000,
            237_000,
            "individual_fallback",
        )
        .unwrap();
        assert_eq!(threshold.block_age_ms, 1_500);
        assert_eq!(threshold.observed_at_ms, 10_000);
        assert_eq!(threshold.persist_call_elapsed_us, 237_000);
        assert_eq!(threshold.mode, "individual_fallback");
        let mut selected = Some(threshold);
        retain_slowest_sample(
            &mut selected,
            record_persist_success_at(&txs[2..], &mut stats, 10_000, 100, "individual_fallback"),
        );
        retain_slowest_sample(&mut selected, Some(threshold));
        retain_slowest_sample(&mut selected, None);
        assert_eq!(selected.unwrap().tx.transaction_id, "older");
        assert_eq!(stats.persisted_txs, 3);
        assert_eq!(stats.max_index_latency_ms, 2_001);
    }

    #[tokio::test]
    async fn latency_sample_preserves_real_caller_outcomes() {
        use std::collections::BTreeMap;
        use std::sync::Mutex;
        use tn12_indexer_db::{PersistStats, RevertStats};
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);
        struct Fields(BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
        }
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut fields = Fields(BTreeMap::new());
                event.record(&mut fields);
                if fields.0.get("event").map(String::as_str) == Some("persisted_latency_sample") {
                    self.0.lock().unwrap().push(fields.0);
                }
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        struct Probe {
            mode: u8,
            calls: Mutex<Vec<String>>,
        }
        #[async_trait::async_trait]
        impl Persister for Probe {
            async fn persist_batch(&self, _: &[RestTransaction]) -> Result<PersistStats> {
                self.calls.lock().unwrap().push("batch".into());
                match self.mode {
                    0 | 5 => Ok(PersistStats::default()),
                    1 => anyhow::bail!("pool timed out"),
                    2 | 4 => anyhow::bail!("ordinary batch rejection"),
                    _ => Err(tn12_indexer_db::persist::GenericWriteOutcomeUnknown {
                        phase: "commit",
                        detail: "pool timed out".into(),
                    }
                    .into()),
                }
            }
            async fn persist_tx(&self, tx: &RestTransaction) -> Result<PersistStats> {
                self.calls.lock().unwrap().push(tx.transaction_id.clone());
                if tx.transaction_id == "fail" || self.mode == 4 {
                    anyhow::bail!("individual rejection");
                }
                Ok(PersistStats::default())
            }
            async fn revert_block(&self, _: &[u8]) -> Result<RevertStats> {
                unreachable!()
            }
            async fn has_utxo(&self, _: &str, _: i32) -> Result<bool> {
                Ok(false)
            }
        }
        struct Cursor;
        #[async_trait::async_trait]
        impl CursorStore for Cursor {
            async fn load(&self) -> Result<Option<u64>> {
                Ok(None)
            }
            async fn save(&self, _: u64, _: Option<u64>) -> Result<()> {
                unreachable!()
            }
        }
        for (mode, expected_success, expected_errors, expected_calls) in [
            (0, 2, 0, 1),
            (1, 0, 2, 1),
            (2, 1, 1, 3),
            (3, 0, 0, 1),
            (4, 0, 2, 3),
            (5, 2, 0, 1),
        ] {
            let probe = Arc::new(Probe {
                mode,
                calls: Mutex::new(Vec::new()),
            });
            let watcher = WrpcVirtualChainWatcher::new(
                probe.clone(),
                Box::new(Cursor),
                Box::new(Cursor),
                Box::new(Cursor),
                WrpcWatcherConfig::with_default_cache("ws://unused".into(), "testnet-10".into()),
            );
            let txs = ["pass", "fail"].map(|id| RestTransaction {
                transaction_id: id.into(),
                accepting_block_hash: (mode != 5).then(|| "block".into()),
                accepting_block_time: Some(if id == "fail" {
                    1
                } else {
                    utc_now_ms().saturating_sub(1_600)
                }),
                outputs: vec![RestTxOutput {
                    script_public_key: format!("aa20{}87", "44".repeat(32)),
                    ..Default::default()
                }],
                ..Default::default()
            });
            let capture = Capture::default();
            let _subscriber = tracing::subscriber::set_default(capture.clone());
            let mut stats = WrpcWatcherStats::default();
            let result = watcher.persist_candidates(txs.to_vec(), &mut stats).await;
            assert_eq!(result.is_err(), mode == 3, "mode {mode}");
            assert_eq!(stats.candidate_txs, 2);
            assert_eq!(stats.persisted_txs, expected_success, "mode {mode}");
            assert_eq!(stats.persist_errors, expected_errors, "mode {mode}");
            assert_eq!(
                probe.calls.lock().unwrap().len(),
                expected_calls,
                "mode {mode}"
            );
            if mode == 2 {
                assert!(stats.max_index_latency_ms >= 1_500);
            }
            if expected_success == 0 {
                assert_eq!(stats.max_index_latency_ms, 0);
            }
            let samples = capture.0.lock().unwrap();
            assert_eq!(
                samples.len(),
                usize::from(expected_success > 0),
                "mode {mode}"
            );
            if let Some(sample) = samples.first() {
                let expected_txid = if matches!(mode, 0 | 5) {
                    "fail"
                } else {
                    "pass"
                };
                assert_eq!(sample["txid"], expected_txid);
                assert_eq!(
                    sample["mode"],
                    if matches!(mode, 0 | 5) {
                        "batch"
                    } else {
                        "individual_fallback"
                    }
                );
                assert_eq!(sample["batch_size"], "2");
                assert_eq!(sample["succeeded"], expected_success.to_string());
                assert_eq!(sample["failed"], expected_errors.to_string());
                if mode == 5 {
                    assert!(!sample.contains_key("accepting_block_hash"));
                    assert_eq!(sample["correlation_complete"], "false");
                } else {
                    assert_eq!(sample["accepting_block_hash"], "block");
                    assert_eq!(sample["correlation_complete"], "true");
                }
                let chosen = txs
                    .iter()
                    .find(|tx| tx.transaction_id == expected_txid)
                    .unwrap();
                assert_eq!(
                    sample["accepting_block_time_ms"],
                    chosen.accepting_block_time.unwrap().to_string()
                );
                let observed = sample["observed_at_ms"].parse::<u64>().unwrap();
                let age = sample["block_age_ms"].parse::<u64>().unwrap();
                assert_eq!(
                    age,
                    observed.saturating_sub(chosen.accepting_block_time.unwrap())
                );
                assert_eq!(age, stats.max_index_latency_ms);
                let call = sample["persist_call_elapsed_us"].parse::<u64>().unwrap();
                let group = sample["attempt_group_elapsed_us"].parse::<u64>().unwrap();
                assert!(group >= call);
            }
        }
    }

    #[test]
    fn future_acceptance_timestamp_does_not_underflow_latency() {
        let tx = RestTransaction {
            accepting_block_time: Some(u64::MAX),
            ..Default::default()
        };
        assert_eq!(max_acceptance_latency_ms(&[tx]), 0);
    }

    #[test]
    fn delayed_block_join_retains_acceptance_progress() {
        let txs = vec![
            RestTransaction {
                accepting_block_blue_score: Some(40),
                ..Default::default()
            },
            RestTransaction {
                accepting_block_blue_score: Some(42),
                ..Default::default()
            },
        ];

        assert_eq!(max_acceptance_blue_score(&txs), Some(42));
        assert_eq!(next_forward_blue_score(41, Some(42)), Some(42));
        assert_eq!(next_forward_blue_score(43, Some(42)), None);
    }

    #[test]
    fn same_event_spend_of_new_p2sh_output_is_a_candidate() {
        let deploy = RestTransaction {
            transaction_id: "deploy".into(),
            outputs: vec![RestTxOutput {
                index: 0,
                script_public_key_type: Some("scripthash".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let spend = RestTransaction {
            transaction_id: "spend".into(),
            inputs: vec![RestTxInput {
                previous_outpoint_hash: "deploy".into(),
                previous_outpoint_index: "0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let current_outputs = BTreeSet::from([("deploy".to_string(), 0)]);

        assert!(is_stream_candidate(
            &deploy,
            &current_outputs,
            &HashSet::new()
        ));
        assert!(is_stream_candidate(
            &spend,
            &current_outputs,
            &HashSet::new()
        ));
    }
}

#[cfg(test)]
#[path = "recovery_handoff_tests.rs"]
mod recovery_handoff_tests;

#[cfg(test)]
#[path = "live_funding_tests.rs"]
mod live_funding_tests;
