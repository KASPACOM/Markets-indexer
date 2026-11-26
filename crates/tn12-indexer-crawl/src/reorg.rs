//! Reorg helpers shared by the future wRPC listener and operational repair commands.
//!
//! wRPC `virtualChainChanged` delivers `removedChainBlockHashes`; the indexer
//! must undo those blocks before applying the added chain blocks. This module
//! keeps the rollback contract independent from the transport so it can be
//! tested and used by a one-shot CLI command today.

use std::sync::Arc;

use anyhow::{Context, Result};
use tn12_indexer_db::{Persister, RevertStats};

use crate::CursorStore;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReorgStats {
    pub requested_blocks: u64,
    pub unknown_blocks: u64,
    pub min_reverted_blue_score: Option<u64>,
    pub blocks_removed: u64,
    pub covenants_removed: u64,
    pub utxos_created_removed: u64,
    pub utxos_reactivated: u64,
    pub actions_removed: u64,
    pub covenants_unclassified: u64,
}

impl ReorgStats {
    fn add_revert(&mut self, stats: RevertStats) {
        self.blocks_removed += stats.blocks_removed;
        self.covenants_removed += stats.covenants_removed;
        self.utxos_created_removed += stats.utxos_created_removed;
        self.utxos_reactivated += stats.utxos_reactivated;
        self.actions_removed += stats.actions_removed;
        self.covenants_unclassified += stats.covenants_unclassified;

        let Some(blue_score) = stats.reverted_blue_score else {
            self.unknown_blocks += 1;
            return;
        };
        self.min_reverted_blue_score = Some(match self.min_reverted_blue_score {
            Some(current) => current.min(blue_score),
            None => blue_score,
        });
    }
}

pub struct ReorgHandler<P: Persister + ?Sized> {
    persister: Arc<P>,
    cursor: Box<dyn CursorStore + Send + Sync>,
}

impl<P: Persister + ?Sized> ReorgHandler<P> {
    pub fn new(persister: Arc<P>, cursor: Box<dyn CursorStore + Send + Sync>) -> Self {
        Self { persister, cursor }
    }

    pub fn with_writer<Q: Persister + ?Sized>(&self,writer:Arc<Q>,pool:sqlx::PgPool) -> Result<ReorgHandler<Q>> {
        Ok(ReorgHandler::new(writer,self.cursor.with_pool(pool)?))
    }

    pub async fn handle_removed_block_hashes(&self, block_hashes: &[String]) -> Result<ReorgStats> {
        self.apply_removed_blocks(
            self.persister.as_ref(),
            decode_block_hashes(block_hashes)?,
            false,
            || async {},
        )
        .await
    }

    /// Keep a live removal event pending until its rollback and cursor rewind
    /// both succeed. The caller must not process its additions or later events.
    pub async fn handle_removed_block_hashes_until_applied<F, Fut>(
        &self,
        block_hashes: &[String],
        before_retry: F,
    ) -> Result<ReorgStats>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        self.apply_removed_blocks(
            self.persister.as_ref(),
            decode_block_hashes(block_hashes)?,
            true,
            before_retry,
        )
        .await
    }

    pub async fn handle_removed_blocks<'a>(
        &self,
        block_hashes: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<ReorgStats> {
        let block_hashes: Vec<Vec<u8>> = block_hashes.into_iter().map(<[u8]>::to_vec).collect();
        self.apply_removed_blocks(self.persister.as_ref(), block_hashes, false, || async {})
            .await
    }

    pub async fn handle_removed_block_hashes_once<Q: Persister + ?Sized>(
        &self,
        writer: &Q,
        hashes: &[String],
    ) -> Result<ReorgStats> {
        self.apply_removed_blocks(writer, decode_block_hashes(hashes)?, false, || async {})
            .await
    }

    async fn apply_removed_blocks<Q: Persister + ?Sized, F, Fut>(
        &self,
        writer: &Q,
        block_hashes: Vec<Vec<u8>>,
        retry: bool,
        mut before_retry: F,
    ) -> Result<ReorgStats>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let mut stats = ReorgStats::default();
        stats.requested_blocks = block_hashes.len() as u64;

        let reverted_blocks = loop {
            match writer.revert_blocks(&block_hashes).await {
                Ok(reverted) => break reverted,
                Err(error) if retry => {
                    tracing::warn!(target: "wrpc", "reorg rollback failed; retaining removal event for retry: {error:#}");
                    before_retry().await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(error) => return Err(error),
            }
        };
        for reverted in reverted_blocks {
            stats.add_revert(reverted);
        }

        if let Some(blue_score) = stats.min_reverted_blue_score {
            // Preserve the successful rollback's score across cursor failures.
            // Repeating the rollback here would see only unknown blocks.
            loop {
                match self.cursor.save(blue_score, None).await {
                    Ok(()) => break,
                    Err(error) if retry => {
                        tracing::warn!(target: "wrpc", "reorg cursor rewind failed; retaining rollback result for retry: {error:#}");
                        before_retry().await;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        Ok(stats)
    }
}

fn decode_block_hashes(block_hashes: &[String]) -> Result<Vec<Vec<u8>>> {
    block_hashes
        .iter()
        .map(|hash| hex::decode(hash).with_context(|| format!("decoding block hash {hash}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use tn12_indexer_core::RestTransaction;

    #[derive(Clone, Default)]
    struct MemoryCursor {
        saved: Arc<Mutex<Vec<u64>>>,
    }

    #[async_trait]
    impl CursorStore for MemoryCursor {
        async fn load(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        async fn save(
            &self,
            blue_score: u64,
            _rest_database_blue_score: Option<u64>,
        ) -> Result<()> {
            self.saved.lock().unwrap().push(blue_score);
            Ok(())
        }
    }

    struct FakePersister {
        reverts: Mutex<Vec<RevertStats>>,
    }

    #[async_trait]
    impl Persister for FakePersister {
        async fn persist_tx(&self, _tx: &RestTransaction) -> Result<tn12_indexer_db::PersistStats> {
            unreachable!("reorg tests do not persist txs")
        }

        async fn revert_block(&self, _block_hash: &[u8]) -> Result<RevertStats> {
            Ok(self.reverts.lock().unwrap().remove(0))
        }

        async fn has_utxo(&self, _txid_hex: &str, _vout: i32) -> Result<bool> {
            unreachable!("reorg tests do not check utxos")
        }
    }

    #[tokio::test]
    async fn saves_cursor_to_lowest_reverted_blue_score() {
        let cursor_state = MemoryCursor::default();
        let saved = cursor_state.saved.clone();
        let cursor = Box::new(cursor_state);
        let persister = Arc::new(FakePersister {
            reverts: Mutex::new(vec![
                RevertStats {
                    reverted_blue_score: Some(200),
                    blocks_removed: 1,
                    actions_removed: 2,
                    ..Default::default()
                },
                RevertStats {
                    reverted_blue_score: Some(150),
                    blocks_removed: 1,
                    utxos_reactivated: 1,
                    ..Default::default()
                },
            ]),
        });
        let handler = ReorgHandler::new(persister, cursor);

        let stats = handler
            .handle_removed_block_hashes(&["11".repeat(32), "22".repeat(32)])
            .await
            .unwrap();

        assert_eq!(stats.requested_blocks, 2);
        assert_eq!(stats.min_reverted_blue_score, Some(150));
        assert_eq!(stats.blocks_removed, 2);
        assert_eq!(stats.actions_removed, 2);
        assert_eq!(stats.utxos_reactivated, 1);
        assert_eq!(*saved.lock().unwrap(), vec![150]);
    }

    #[tokio::test]
    async fn live_reorg_retries_removal_then_cursor_without_losing_rewind_score() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct RetryPersister(Arc<AtomicUsize>);
        #[async_trait]
        impl Persister for RetryPersister {
            async fn persist_tx(
                &self,
                _: &RestTransaction,
            ) -> Result<tn12_indexer_db::PersistStats> {
                unreachable!()
            }
            async fn revert_block(&self, _: &[u8]) -> Result<RevertStats> {
                unreachable!()
            }
            async fn has_utxo(&self, _: &str, _: i32) -> Result<bool> {
                unreachable!()
            }
            async fn revert_blocks(&self, hashes: &[Vec<u8>]) -> Result<Vec<RevertStats>> {
                assert_eq!(hashes, &[vec![0x11; 32]]);
                match self.0.fetch_add(1, Ordering::SeqCst) {
                    0 => anyhow::bail!("canceling statement due to lock timeout"),
                    1 => Ok(vec![RevertStats {
                        reverted_blue_score: Some(150),
                        blocks_removed: 1,
                        ..Default::default()
                    }]),
                    _ => panic!("cursor retry must retain the completed rollback"),
                }
            }
        }
        struct RetryCursor(Arc<AtomicUsize>);
        #[async_trait]
        impl CursorStore for RetryCursor {
            async fn load(&self) -> Result<Option<u64>> {
                unreachable!()
            }
            async fn save(&self, blue_score: u64, _: Option<u64>) -> Result<()> {
                assert_eq!(blue_score, 150);
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    anyhow::bail!("fixture cursor write failure");
                }
                Ok(())
            }
        }
        let removals = Arc::new(AtomicUsize::new(0));
        let rewinds = Arc::new(AtomicUsize::new(0));
        let handler = ReorgHandler::new(
            Arc::new(RetryPersister(removals.clone())),
            Box::new(RetryCursor(rewinds.clone())),
        );
        let stats = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handler.handle_removed_block_hashes_until_applied(&["11".repeat(32)], || async {}),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(stats.blocks_removed, 1);
        assert_eq!(stats.min_reverted_blue_score, Some(150));
        assert_eq!(removals.load(Ordering::SeqCst), 2);
        assert_eq!(rewinds.load(Ordering::SeqCst), 2);
    }
}
