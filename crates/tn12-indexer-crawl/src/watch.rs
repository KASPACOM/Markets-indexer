//! Live address watcher.
//!
//! Polls TN12 REST `/addresses/{addr}/full-transactions` for each watched
//! covenant address and feeds new transactions through the same `Persister`
//! the replay path uses. This is the cheap "live mode" — it stays current
//! without needing the rusty-kaspa Rust crates or the wRPC client.
//!
//! Reorg story: REST exposes only `is_accepted` + `accepting_block_hash`. A
//! tx that flips from accepted → not-accepted will reappear in the poll with
//! `is_accepted=false`; the persister skips non-accepted txs, so reverted
//! txs simply stop being added. Cleaning up rows that were accepted in a
//! since-orphaned block lives with the wRPC + reorg path (Phase 1c-v2).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::rpc::RestClient;
use anyhow::Result;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{PersistStats, Persister};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct WatcherConfig {
    pub addresses: Vec<String>,
    pub poll_interval: Duration,
    pub limit_per_poll: u32,
}

#[derive(Default)]
pub struct WatchState {
    seen: HashSet<String>,
}

pub struct AddressWatcher<P: Persister + ?Sized> {
    rpc: RestClient,
    persister: Arc<P>,
    config: RwLock<WatcherConfig>,
    state: RwLock<WatchState>,
}

impl<P: Persister + ?Sized> AddressWatcher<P> {
    pub fn new(rpc: RestClient, persister: Arc<P>, config: WatcherConfig) -> Self {
        Self {
            rpc,
            persister,
            config: RwLock::new(config),
            state: RwLock::new(WatchState::default()),
        }
    }

    pub async fn add_address(&self, address: String) {
        let mut config = self.config.write().await;
        if !config.addresses.iter().any(|a| a == &address) {
            tracing::info!(target: "watcher", "+address {address}");
            config.addresses.push(address);
        }
    }

    pub async fn run_forever(&self) -> Result<()> {
        loop {
            match self.tick().await {
                Ok(stats) => {
                    if stats.txs_ingested > 0 {
                        tracing::info!(
                            target: "watcher",
                            "tick: addresses={} ingested={} persist={:?}",
                            stats.addresses_polled,
                            stats.txs_ingested,
                            stats.persist_totals
                        );
                    }
                }
                Err(e) => tracing::warn!(target: "watcher", "tick error: {e:#}"),
            }
            let interval = self.config.read().await.poll_interval;
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn tick(&self) -> Result<TickStats> {
        let (addresses, limit) = {
            let cfg = self.config.read().await;
            (cfg.addresses.clone(), cfg.limit_per_poll)
        };
        let mut stats = TickStats::default();
        for address in &addresses {
            stats.addresses_polled += 1;
            let mut txs = self
                .rpc
                .get_address_full_transactions(address, limit, 0)
                .await?;
            // REST returns newest-first; process oldest-first so a deploy
            // always precedes its spend in the same poll window.
            txs.sort_by_key(|t| t.accepting_block_time.unwrap_or(t.block_time));
            for tx in &txs {
                if !tx.is_accepted {
                    continue;
                }
                let seen = self.state.read().await;
                if seen.seen.contains(&tx.transaction_id) {
                    continue;
                }
                drop(seen);
                let result = if let Some(writer) = self.persister.paged_recovery_writer() {
                    match crate::rest_replay_fence::for_transactions(writer, &self.rpc, std::slice::from_ref(tx)).await {
                        Ok(guarded) => guarded.persist_tx(tx).await,
                        Err(error) => Err(error),
                    }
                } else { self.persister.persist_tx(tx).await };
                match result {
                    Ok(s) => {
                        self.state.write().await.seen.insert(tx.transaction_id.clone());
                        stats.txs_ingested += 1;
                        stats.persist_totals.merge(s);
                        // Auto-discover: after persisting, scan outputs for
                        // new P2SH addresses and add them to the watch list.
                        self.auto_discover_outputs(tx).await;
                    }
                    Err(e) => {
                        tracing::warn!(target: "watcher", "persist {} failed: {e:#}", tx.transaction_id);
                    }
                }
            }
        }
        Ok(stats)
    }

    async fn auto_discover_outputs(&self, tx: &RestTransaction) {
        for out in &tx.outputs {
            let Some(addr) = out.script_public_key_address.as_deref() else {
                continue;
            };
            // Heuristic: P2SH addresses on testnet start with "kaspatest:p" (Bech32
            // version byte 8). Pubkey outputs start with "kaspatest:q". Skip pubkey.
            if !addr.starts_with("kaspatest:p") {
                continue;
            }
            self.add_address(addr.to_string()).await;
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TickStats {
    pub addresses_polled: u32,
    pub txs_ingested: u32,
    pub persist_totals: PersistStatsAccum,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PersistStatsAccum {
    pub blocks_inserted: u64,
    pub covenants_inserted: u64,
    pub utxos_inserted: u64,
    pub utxos_spent: u64,
    pub actions_inserted: u64,
}

impl PersistStatsAccum {
    pub fn merge(&mut self, s: PersistStats) {
        self.blocks_inserted += s.blocks_inserted;
        self.covenants_inserted += s.covenants_inserted;
        self.utxos_inserted += s.utxos_inserted;
        self.utxos_spent += s.utxos_spent;
        self.actions_inserted += s.actions_inserted;
    }
}
