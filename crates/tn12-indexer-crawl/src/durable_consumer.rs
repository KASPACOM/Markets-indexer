//! One ordered consumer step. Bootstrap and source reconciliation must establish
//! a checkpoint before this can run; no missing receipt is skipped or retried as
//! a raw reorg after an uncertain write. This is not wired to the CLI yet.
use crate::bounded_notification::decode_notification;
use crate::durable_inbox::{
    DurableCommitOutcome, DurableEventApplier, DurableInbox, InboxCheckpoint,
};
use crate::durable_join::{ContiguousEventPlan, DurableJoin};
use anyhow::{ensure, Context, Result};
use kaspa_addresses::Prefix;
use kaspa_wrpc_client::prelude::{NetworkId, Notification, VirtualChainChangedNotification};
use std::{str::FromStr, sync::Arc};
use tn12_indexer_db::persist::DurableConsumerFence;

const LOOKAHEAD_FRAMES: usize = 64;
const LOOKAHEAD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryReason {
    MissingAnchor,
    ConnectionGap,
    UncertainEffect,
    PendingCanonicalSnapshot,
    MissingBodiesOrContinuity,
}

#[derive(Debug)]
pub enum ConsumerStep {
    Idle,
    Committed {
        sequence: i64,
    },
    RecoveryRequired {
        reason: RecoveryReason,
        checkpoint: InboxCheckpoint,
    },
}

pub struct DurableConsumer {
    inbox: Arc<DurableInbox>,
    fence: DurableConsumerFence,
    applier: DurableEventApplier,
    network: String,
    prefix: Prefix,
    cache: DurableJoin,
    cache_limit: usize,
}

impl DurableConsumer {
    /// Claim a generation once at startup and pass it here. Errors must not
    /// cause a stale consumer to reclaim a newer generation automatically.
    pub fn new(
        inbox: Arc<DurableInbox>,
        fence: DurableConsumerFence,
        network: String,
        cache_limit: usize,
    ) -> Result<Self> {
        let prefix = Prefix::from(NetworkId::from_str(&network)?);
        let cache = DurableJoin::new(cache_limit)?;
        let applier = DurableEventApplier::new(inbox.clone(), fence.clone(), network.clone())?;
        Ok(Self {
            inbox,
            fence,
            applier,
            network,
            prefix,
            cache,
            cache_limit,
        })
    }

    pub fn cache_bytes(&self) -> usize {
        self.cache.charged_bytes()
    }

    /// Rebuild only cached block bodies from the bounded processed tail. Never
    /// apply historical virtual-chain effects or move a checkpoint here.
    pub async fn restore_cache(&mut self) -> Result<()> {
        let before = self.inbox.checkpoint(&self.fence).await?;
        self.cache = DurableJoin::new(self.cache_limit)?;
        let mut after = 0;
        while let Some(entry) = self.inbox.replay_tail_after(after).await? {
            ensure!(
                entry.sequence <= before.committed_sequence,
                "checkpoint advanced during cache restore"
            );
            let notification = decode_notification(&entry.payload)?;
            after = entry.sequence;
            drop(entry);
            if let Notification::BlockAdded(notification) = notification {
                self.cache
                    .remember_block(&notification.block, self.prefix)?;
            }
        }
        let current = self.inbox.checkpoint(&self.fence).await?;
        ensure!(
            current.committed_sequence == before.committed_sequence
                && current.anchor == before.anchor,
            "checkpoint changed during cache restore"
        );
        Ok(())
    }

    pub async fn step(&mut self) -> Result<ConsumerStep> {
        let checkpoint = self.inbox.checkpoint(&self.fence).await?;
        let recovery = if checkpoint.pending_recovery_snapshot {
            Some(RecoveryReason::PendingCanonicalSnapshot)
        } else if checkpoint.uncertain_effect {
            Some(RecoveryReason::UncertainEffect)
        } else if checkpoint.open_recovery_intervals != 0 {
            Some(RecoveryReason::ConnectionGap)
        } else if checkpoint.anchor.is_none() {
            Some(RecoveryReason::MissingAnchor)
        } else {
            None
        };
        if let Some(reason) = recovery {
            return Ok(ConsumerStep::RecoveryRequired { reason, checkpoint });
        }
        let anchor = checkpoint
            .anchor
            .as_ref()
            .expect("checked checkpoint anchor");
        ensure!(
            anchor.network == self.network,
            "checkpoint belongs to another network"
        );
        let Some(entry) = self.inbox.oldest().await? else {
            return Ok(ConsumerStep::Idle);
        };
        ensure!(
            entry.sequence == checkpoint.committed_sequence + 1,
            "inbox head changed or missing"
        );
        let sequence = entry.sequence;
        let notification = decode_notification(&entry.payload)?;
        drop(entry);
        match notification {
            Notification::BlockAdded(notification) => {
                self.cache
                    .remember_block(&notification.block, self.prefix)?;
                // This receipt only hydrates bodies. It cannot advance acceptance.
                self.inbox
                    .acknowledge_contiguous(sequence, anchor, anchor, &self.fence)
                    .await?;
            }
            Notification::VirtualChainChanged(notification) => {
                let mut plan =
                    self.cache
                        .prepare_contiguous_change(&self.network, anchor, &notification)?;
                if plan.is_none() {
                    plan = tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        self.hydrate_lookahead(
                            sequence,
                            checkpoint.next_sequence - 1,
                            anchor,
                            &notification,
                        ),
                    )
                    .await
                    .context("durable lookahead deadline; receipt remains pending")??;
                }
                let Some(plan) = plan else {
                    return Ok(ConsumerStep::RecoveryRequired {
                        reason: RecoveryReason::MissingBodiesOrContinuity,
                        checkpoint,
                    });
                };
                drop(notification);
                match self.applier.commit(sequence, &plan).await? {
                    DurableCommitOutcome::Committed(_) => {}
                    DurableCommitOutcome::RecoveryRequired(_) => {
                        return Ok(ConsumerStep::RecoveryRequired {
                            reason: RecoveryReason::UncertainEffect,
                            checkpoint: self.inbox.checkpoint(&self.fence).await?,
                        });
                    }
                }
            }
            _ => anyhow::bail!("unsupported durable notification"),
        }
        Ok(ConsumerStep::Committed { sequence })
    }

    async fn hydrate_lookahead(
        &mut self,
        after: i64,
        through: i64,
        anchor: &crate::durable_inbox::ChainAnchor,
        pending: &VirtualChainChangedNotification,
    ) -> Result<Option<ContiguousEventPlan>> {
        let entries = self.inbox.peek_pending_batch(
            after, through, LOOKAHEAD_FRAMES, LOOKAHEAD_BYTES, &self.fence,
        ).await?;
        for entry in entries {
            let notification = decode_notification(&entry.payload)?;
            drop(entry);
            if let Notification::BlockAdded(notification) = notification {
                self.cache
                    .remember_block(&notification.block, self.prefix)?;
                drop(notification);
                // Stop as soon as the pending event is complete. Reading extra
                // bodies could evict the ones this event needs.
                if let Some(plan) =
                    self.cache
                        .prepare_contiguous_change(&self.network, anchor, pending)?
                {
                    return Ok(Some(plan));
                }
            }
            // Future removals and acceptances have no effects here.
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_inbox::ChainAnchor;
    use kaspa_rpc_core::api::ops::RpcApiOps;
    use kaspa_wrpc_client::prelude::{
        BlockAddedNotification, RpcBlock, RpcBlockVerboseData, RpcHeader,
        VirtualChainChangedNotification,
    };
    use workflow_rpc::messages::borsh::{BorshServerMessageHeader, ServerMessageKind};
    use workflow_serializer::prelude::Serializable;

    fn hash(n: u8) -> kaspa_rpc_core::RpcHash {
        format!("{n:02x}").repeat(32).parse().unwrap()
    }
    fn block(n: u8) -> Notification {
        Notification::BlockAdded(BlockAddedNotification {
            block: Arc::new(RpcBlock {
                header: RpcHeader {
                    hash: hash(n),
                    version: 1,
                    parents_by_level: vec![vec![hash(n - 1)]],
                    hash_merkle_root: hash(0),
                    accepted_id_merkle_root: hash(0),
                    utxo_commitment: hash(0),
                    timestamp: n as u64,
                    bits: 0,
                    nonce: 0,
                    daa_score: n as u64,
                    blue_work: Default::default(),
                    blue_score: n as u64 * 10,
                    pruning_point: hash(0),
                },
                transactions: vec![],
                verbose_data: Some(RpcBlockVerboseData {
                    hash: hash(n),
                    difficulty: 0.0,
                    selected_parent_hash: hash(n - 1),
                    transaction_ids: vec![],
                    is_header_only: false,
                    blue_score: n as u64 * 10,
                    children_hashes: vec![],
                    merge_set_blues_hashes: vec![],
                    merge_set_reds_hashes: vec![],
                    is_chain_block: true,
                }),
            }),
        })
    }
    fn change(added: &[u8]) -> Notification {
        Notification::VirtualChainChanged(VirtualChainChangedNotification {
            removed_chain_block_hashes: Arc::new(vec![]),
            added_chain_block_hashes: Arc::new(added.iter().map(|n| hash(*n)).collect()),
            accepted_transaction_ids: Arc::new(vec![]),
        })
    }
    fn frame(notification: Notification) -> Vec<u8> {
        let op = match &notification {
            Notification::BlockAdded(_) => RpcApiOps::BlockAddedNotification,
            _ => RpcApiOps::VirtualChainChangedNotification,
        };
        let mut bytes = borsh::to_vec(&BorshServerMessageHeader {
            id: None::<u64>,
            kind: ServerMessageKind::Notification,
            op: Some(op),
        })
        .unwrap();
        bytes.extend(borsh::to_vec(&Serializable(notification)).unwrap());
        bytes
    }
    async fn setup(
        pool: &sqlx::PgPool,
        anchored: bool,
    ) -> (Arc<DurableInbox>, DurableConsumerFence, DurableConsumer) {
        let inbox = Arc::new(
            DurableInbox::open(pool.clone(), "testnet-10:consumer".into(), 1024 * 1024)
                .await
                .unwrap(),
        );
        if anchored {
            let anchor = ChainAnchor {
                network: "testnet-10".into(),
                block_hash: hash(1).to_string(),
                blue_score: 10,
            };
            sqlx::query(
                "UPDATE wrpc_inbox_streams SET anchor=$1 WHERE stream='testnet-10:consumer'",
            )
            .bind(serde_json::to_value(anchor).unwrap())
            .execute(pool)
            .await
            .unwrap();
        }
        let fence = DurableConsumerFence::claim(pool, "testnet-10:consumer")
            .await
            .unwrap();
        let consumer =
            DurableConsumer::new(inbox.clone(), fence.clone(), "testnet-10".into(), 8192).unwrap();
        (inbox, fence, consumer)
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn ordered_consumer_restores_bodies_without_reapplying_acceptance(pool: sqlx::PgPool) {
        let (inbox, fence, mut consumer) = setup(&pool, true).await;
        for (i, n) in [block(1), block(2), change(&[2])].into_iter().enumerate() {
            inbox
                .append(i as i64 + 1, &frame(n), i as i64)
                .await
                .unwrap();
        }
        for sequence in 1..=3 {
            assert!(
                matches!(consumer.step().await.unwrap(), ConsumerStep::Committed { sequence: s } if s == sequence)
            );
        }
        let checkpoint = inbox.checkpoint(&fence).await.unwrap();
        assert_eq!(
            checkpoint.anchor.as_ref().unwrap().block_hash,
            hash(2).to_string()
        );
        assert_eq!(checkpoint.pending_bytes, 0);
        let replacement = DurableConsumerFence::claim(&pool, "testnet-10:consumer")
            .await
            .unwrap();
        assert!(consumer.step().await.is_err());
        let mut restarted = DurableConsumer::new(
            inbox.clone(),
            replacement.clone(),
            "testnet-10".into(),
            8192,
        )
        .unwrap();
        restarted.restore_cache().await.unwrap();
        assert!(restarted.cache_bytes() <= 8192);
        assert_eq!(inbox.checkpoint(&replacement).await.unwrap(), checkpoint);
        assert!(matches!(
            restarted.step().await.unwrap(),
            ConsumerStep::Idle
        ));
        // An old raw change cannot undo the later committed anchor.
        inbox.append(4, &frame(change(&[2])), 4).await.unwrap();
        assert!(matches!(
            restarted.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::MissingBodiesOrContinuity,
                ..
            }
        ));
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 4);
        assert_eq!(
            inbox.checkpoint(&replacement).await.unwrap().anchor,
            checkpoint.anchor
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn unverified_start_and_connection_gap_leave_receipt_pending(pool: sqlx::PgPool) {
        let (inbox, _, mut consumer) = setup(&pool, false).await;
        inbox.append(1, &frame(block(1)), 1).await.unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::MissingAnchor,
                ..
            }
        ));
        inbox
            .open_recovery_interval("connection_started")
            .await
            .unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::ConnectionGap,
                ..
            }
        ));
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn missing_body_or_malformed_frame_does_not_acknowledge(pool: sqlx::PgPool) {
        let (inbox, fence, mut consumer) = setup(&pool, true).await;
        inbox.append(1, &frame(change(&[2])), 1).await.unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::MissingBodiesOrContinuity,
                ..
            }
        ));
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().committed_sequence,
            0
        );
        sqlx::query("UPDATE wrpc_inbox_entries SET payload='bad'::bytea WHERE stream='testnet-10:consumer' AND sequence=1")
            .execute(&pool).await.unwrap();
        assert!(consumer.step().await.is_err());
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().committed_sequence,
            0
        );
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn lookahead_hydrates_only_bodies_and_preserves_future_receipts(pool: sqlx::PgPool) {
        let (inbox, fence, mut consumer) = setup(&pool, true).await;
        for (i, n) in [block(1), change(&[2]), change(&[3]), block(2), block(3)]
            .into_iter()
            .enumerate()
        {
            inbox
                .append(i as i64 + 1, &frame(n), i as i64)
                .await
                .unwrap();
        }
        consumer.step().await.unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::Committed { sequence: 2 }
        ));
        assert_eq!(
            inbox
                .checkpoint(&fence)
                .await
                .unwrap()
                .anchor
                .unwrap()
                .block_hash,
            hash(2).to_string()
        );
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 3);
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::Committed { sequence: 3 }
        ));
        assert_eq!(
            inbox
                .checkpoint(&fence)
                .await
                .unwrap()
                .anchor
                .unwrap()
                .block_hash,
            hash(3).to_string()
        );
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 4);
        assert!(consumer.cache_bytes() <= 8192);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn lookahead_frame_limit_retains_the_blocked_head(pool: sqlx::PgPool) {
        let (inbox, fence, mut consumer) = setup(&pool, true).await;
        inbox.append(1, &frame(block(1)), 1).await.unwrap();
        inbox.append(2, &frame(change(&[2])), 2).await.unwrap();
        for sequence in 3..=66 {
            inbox
                .append(sequence, &frame(block(1)), sequence)
                .await
                .unwrap();
        }
        inbox.append(67, &frame(block(2)), 67).await.unwrap();
        consumer.step().await.unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::MissingBodiesOrContinuity,
                ..
            }
        ));
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 2);
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().committed_sequence,
            1
        );
        assert!(consumer.cache_bytes() <= 8192);
        assert!(inbox
            .peek_pending_after(66, 66, &fence)
            .await
            .unwrap()
            .is_none());
        DurableConsumerFence::claim(&pool, "testnet-10:consumer")
            .await
            .unwrap();
        assert!(inbox.peek_pending_after(1, 67, &fence).await.is_err());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn lookahead_byte_limit_stops_before_decoding_the_next_frame(pool: sqlx::PgPool) {
        let (inbox, fence, mut consumer) = setup(&pool, true).await;
        let producer =
            DurableInbox::open(pool.clone(), "testnet-10:consumer".into(), 20 * 1024 * 1024)
                .await
                .unwrap();
        producer.append(1, &frame(block(1)), 1).await.unwrap();
        producer.append(2, &frame(change(&[2])), 2).await.unwrap();
        producer.append(3, &frame(block(1)), 3).await.unwrap();
        producer
            .append(4, &vec![0; LOOKAHEAD_BYTES], 4)
            .await
            .unwrap();
        producer.append(5, &frame(block(2)), 5).await.unwrap();
        consumer.step().await.unwrap();
        assert!(matches!(
            consumer.step().await.unwrap(),
            ConsumerStep::RecoveryRequired {
                reason: RecoveryReason::MissingBodiesOrContinuity,
                ..
            }
        ));
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 2);
        assert_eq!(
            inbox.checkpoint(&fence).await.unwrap().committed_sequence,
            1
        );
    }
}
