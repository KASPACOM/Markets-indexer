//! The inbox checkpoint moves only when the whole effect is acknowledged.
//! A crash with an intent present requires canonical recovery before completion.
use super::{ChainAnchor, DurableInbox};
use crate::live_recovery::{LiveWriteJournal, LiveWriteWindow};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;
use tn12_indexer_db::persist::DurableConsumerFence;

pub enum EffectStart {
    /// The caller can apply the validated notification exactly once in this run.
    Fresh,
    /// The prior attempt may have committed any prefix. Recover from the source.
    RecoveryRequired(LiveWriteWindow),
}

pub struct InboxEffectJournal {
    inbox: Arc<DurableInbox>,
    sequence: i64,
    fence: DurableConsumerFence,
}

impl InboxEffectJournal {
    pub fn new(inbox: Arc<DurableInbox>, sequence: i64, fence: DurableConsumerFence) -> Self {
        Self {
            inbox,
            sequence,
            fence,
        }
    }

    pub async fn start(&self, window: &LiveWriteWindow) -> Result<EffectStart> {
        self.start_inner(window, None).await
    }

    pub(super) async fn start_contiguous(
        &self,
        window: &LiveWriteWindow,
        previous: &ChainAnchor,
    ) -> Result<EffectStart> {
        self.start_inner(window, Some(previous)).await
    }

    async fn start_inner(
        &self,
        window: &LiveWriteWindow,
        previous: Option<&ChainAnchor>,
    ) -> Result<EffectStart> {
        window.validate()?;
        let payload = serde_json::to_vec(window)?;
        let mut tx = self.inbox.pool.begin().await?;
        self.lock_head(&mut tx).await?;
        if let Some(previous) = previous {
            self.inbox
                .require_anchor(&mut tx, previous, &self.fence)
                .await?;
        }
        let old: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT payload FROM wrpc_inbox_effects WHERE stream=$1 AND sequence=$2",
        )
        .bind(&self.inbox.stream)
        .bind(self.sequence)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(old) = old {
            // Recovery may have expanded the old intent. Never replace it with
            // a reconstructed raw event, even when that reconstruction differs.
            let existing: LiveWriteWindow = serde_json::from_slice(&old)?;
            existing.validate()?;
            return Ok(EffectStart::RecoveryRequired(existing));
        }
        self.reserve(&mut tx, payload.len() as i64).await?;
        sqlx::query("INSERT INTO wrpc_inbox_effects(stream,sequence,payload,started_at_ms) VALUES($1,$2,$3,$4)")
            .bind(&self.inbox.stream).bind(self.sequence).bind(payload)
            .bind(chrono::Utc::now().timestamp_millis()).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(EffectStart::Fresh)
    }

    /// Caller has acknowledged persistence or canonical recovery for this exact
    /// intent. Deletion, capacity release, anchor and receipt checkpoint commit
    /// together. A failed/unknown commit must reload the stream before retry.
    pub async fn finish(
        &self,
        expected: &LiveWriteWindow,
        anchor: Option<&ChainAnchor>,
    ) -> Result<()> {
        self.finish_inner(expected, anchor, None).await
    }

    pub(super) async fn finish_contiguous(
        &self,
        expected: &LiveWriteWindow,
        previous: &ChainAnchor,
        next: &ChainAnchor,
    ) -> Result<()> {
        ensure!(
            previous.network == next.network,
            "checkpoint network changed"
        );
        self.finish_inner(expected, Some(next), Some(previous))
            .await
    }

    async fn finish_inner(
        &self,
        expected: &LiveWriteWindow,
        anchor: Option<&ChainAnchor>,
        previous: Option<&ChainAnchor>,
    ) -> Result<()> {
        expected.validate()?;
        let payload = serde_json::to_vec(expected)?;
        let mut tx = self.inbox.pool.begin().await?;
        self.lock_head(&mut tx).await?;
        if let Some(previous) = previous {
            self.inbox
                .require_anchor(&mut tx, previous, &self.fence)
                .await?;
        }
        let bytes: Option<i64> = sqlx::query_scalar("DELETE FROM wrpc_inbox_effects WHERE stream=$1 AND sequence=$2 AND payload=$3 RETURNING octet_length(payload)::bigint")
            .bind(&self.inbox.stream).bind(self.sequence).bind(payload).fetch_optional(&mut *tx).await?;
        ensure!(
            bytes.is_some(),
            "effect changed or missing before acknowledgement"
        );
        self.reserve(&mut tx, -bytes.unwrap()).await?;
        self.inbox
            .acknowledge_in_transaction(&mut tx, self.sequence, anchor, Some(&self.fence))
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn lock_head(&self, tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<()> {
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut **tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='2s'")
            .execute(&mut **tx)
            .await?;
        let committed: i64 = sqlx::query_scalar(
            "SELECT committed_sequence FROM wrpc_inbox_streams WHERE stream=$1 FOR UPDATE",
        )
        .bind(&self.inbox.stream)
        .fetch_one(&mut **tx)
        .await?;
        self.fence.verify_locked(tx, &self.inbox.stream).await?;
        ensure!(
            committed.checked_add(1) == Some(self.sequence),
            "effect is not the oldest pending receipt"
        );
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM wrpc_inbox_entries WHERE stream=$1 AND sequence=$2)",
        )
        .bind(&self.inbox.stream)
        .bind(self.sequence)
        .fetch_one(&mut **tx)
        .await?;
        ensure!(exists, "effect receipt is missing");
        Ok(())
    }

    async fn reserve(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        delta: i64,
    ) -> Result<()> {
        let updated = sqlx::query("UPDATE wrpc_inbox_streams SET effect_bytes=effect_bytes+$2 WHERE stream=$1 AND effect_bytes+$2>=0 AND ($2<=0 OR pending_bytes+retained_bytes+effect_bytes+$2<=$3)")
            .bind(&self.inbox.stream).bind(delta).bind(self.inbox.capacity_bytes).execute(&mut **tx).await?;
        ensure!(
            updated.rows_affected() == 1,
            "durable effect capacity exceeded; receipt retained"
        );
        Ok(())
    }
}

#[async_trait::async_trait]
impl LiveWriteJournal for InboxEffectJournal {
    async fn load(&self) -> Result<Option<LiveWriteWindow>> {
        let payload: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT payload FROM wrpc_inbox_effects WHERE stream=$1 AND sequence=$2",
        )
        .bind(&self.inbox.stream)
        .bind(self.sequence)
        .fetch_optional(&self.inbox.pool)
        .await?;
        payload
            .map(|bytes| {
                let window: LiveWriteWindow =
                    serde_json::from_slice(&bytes).context("decode durable effect")?;
                window.validate()?;
                Ok(window)
            })
            .transpose()
    }
    async fn begin(&self, _: &LiveWriteWindow) -> Result<()> {
        anyhow::bail!("use effect start and handle RecoveryRequired before applying")
    }
    async fn replace(&self, previous: &LiveWriteWindow, updated: &LiveWriteWindow) -> Result<()> {
        previous.validate()?;
        updated.validate()?;
        let old = serde_json::to_vec(previous)?;
        let new = serde_json::to_vec(updated)?;
        let mut tx = self.inbox.pool.begin().await?;
        self.lock_head(&mut tx).await?;
        self.reserve(&mut tx, new.len() as i64 - old.len() as i64)
            .await?;
        let result = sqlx::query("UPDATE wrpc_inbox_effects SET payload=$4 WHERE stream=$1 AND sequence=$2 AND payload=$3")
            .bind(&self.inbox.stream).bind(self.sequence).bind(old).bind(new).execute(&mut *tx).await?;
        ensure!(
            result.rows_affected() == 1,
            "effect changed during canonical recovery"
        );
        tx.commit().await?;
        Ok(())
    }
    async fn complete(&self, _: &LiveWriteWindow) -> Result<()> {
        anyhow::bail!("use effect finish to acknowledge its receipt and anchor atomically")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_inbox::AppendOutcome;
    use sqlx::PgPool;

    fn window() -> LiveWriteWindow {
        LiveWriteWindow {
            unresolved_blocks: Vec::new(),
            transactions: vec![],
            affected_transaction_ids: vec![],
                rejected_transactions: vec![],
            window_width: Some(10),
            observed_blocks: std::collections::BTreeMap::from([(
                100,
                std::collections::BTreeSet::from(["11".repeat(32)]),
            )]),
        }
    }
    async fn setup(pool: &PgPool, capacity: i64) -> (Arc<DurableInbox>, InboxEffectJournal) {
        let inbox = Arc::new(
            DurableInbox::open(pool.clone(), "testnet-10:effects".into(), capacity)
                .await
                .unwrap(),
        );
        inbox.append(1, b"receipt", 1).await.unwrap();
        let fence = DurableConsumerFence::claim(pool, "testnet-10:effects")
            .await
            .unwrap();
        let journal = InboxEffectJournal::new(inbox.clone(), 1, fence);
        (inbox, journal)
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn uncertain_effect_requires_recovery_and_atomic_ack(pool: PgPool) {
        let (inbox, journal) = setup(&pool, 4096).await;
        let original = window();
        assert!(matches!(
            journal.start(&original).await.unwrap(),
            EffectStart::Fresh
        ));
        assert!(inbox.acknowledge(1, None).await.is_err());
        // Simulate process loss after any prefix, including the entire DB write.
        let fence = DurableConsumerFence::claim(&pool, "testnet-10:effects")
            .await
            .unwrap();
        let resumed = InboxEffectJournal::new(inbox.clone(), 1, fence);
        assert!(matches!(
            resumed.start(&original).await.unwrap(),
            EffectStart::RecoveryRequired(_)
        ));
        assert!(journal.finish(&original, None).await.is_err());
        let mut updated = original.clone();
        updated
            .observed_blocks
            .get_mut(&100)
            .unwrap()
            .insert("22".repeat(32));
        resumed.replace(&original, &updated).await.unwrap();
        assert!(resumed.finish(&original, None).await.is_err());
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 1);
        let anchor = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "22".repeat(32),
            blue_score: 109,
        };
        resumed.finish(&updated, Some(&anchor)).await.unwrap();
        assert!(inbox.oldest().await.unwrap().is_none());
        assert!(resumed.load().await.unwrap().is_none());
        let (committed,bytes,stored):(i64,i64,serde_json::Value)=sqlx::query_as("SELECT committed_sequence,effect_bytes,anchor FROM wrpc_inbox_streams WHERE stream='testnet-10:effects'").fetch_one(&pool).await.unwrap();
        assert_eq!((committed, bytes), (1, 0));
        assert_eq!(stored, serde_json::to_value(anchor).unwrap());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn effects_share_capacity_with_raw_intake(pool: PgPool) {
        let bytes = serde_json::to_vec(&window()).unwrap().len() as i64;
        let (inbox, journal) = setup(&pool, bytes + 7).await;
        assert!(matches!(
            journal.start(&window()).await.unwrap(),
            EffectStart::Fresh
        ));
        assert_eq!(
            inbox.append(2, b"x", 2).await.unwrap(),
            AppendOutcome::CapacityReached
        );
        let mut larger = window();
        larger
            .observed_blocks
            .get_mut(&100)
            .unwrap()
            .insert("22".repeat(32));
        assert!(journal.replace(&window(), &larger).await.is_err());
        journal.finish(&window(), None).await.unwrap();
        assert_eq!(
            inbox.append(2, b"x", 2).await.unwrap(),
            AppendOutcome::Stored
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn smaller_capacity_can_drain_an_existing_effect(pool: PgPool) {
        let (_, journal) = setup(&pool, 4096).await;
        journal.start(&window()).await.unwrap();
        let smaller = Arc::new(
            DurableInbox::open(pool.clone(), "testnet-10:effects".into(), 1)
                .await
                .unwrap(),
        );
        let resumed = InboxEffectJournal::new(smaller.clone(), 1, journal.fence.clone());
        resumed.finish(&window(), None).await.unwrap();
        assert!(smaller.oldest().await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn effect_cannot_skip_receipt_or_clear_without_ack(pool: PgPool) {
        let (inbox, journal) = setup(&pool, 4096).await;
        inbox.append(2, b"later", 2).await.unwrap();
        let later = InboxEffectJournal::new(inbox.clone(), 2, journal.fence.clone());
        assert!(later.start(&window()).await.is_err());
        assert!(journal.begin(&window()).await.is_err());
        journal.start(&window()).await.unwrap();
        assert!(journal.complete(&window()).await.is_err());
        let invalid = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "bad".into(),
            blue_score: 109,
        };
        assert!(journal.finish(&window(), Some(&invalid)).await.is_err());
        assert!(journal.load().await.unwrap().is_some());
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn contiguous_start_and_finish_require_the_exact_durable_anchor(pool: PgPool) {
        let (inbox, journal) = setup(&pool, 4096).await;
        let previous = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "aa".repeat(32),
            blue_score: 99,
        };
        let next = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "11".repeat(32),
            blue_score: 109,
        };
        let intent = window();
        assert!(journal.start_contiguous(&intent, &previous).await.is_err());
        assert!(journal.load().await.unwrap().is_none());
        sqlx::query("UPDATE wrpc_inbox_streams SET anchor=$1 WHERE stream='testnet-10:effects'")
            .bind(serde_json::to_value(&previous).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            journal.start_contiguous(&intent, &previous).await.unwrap(),
            EffectStart::Fresh
        ));
        // A changed checkpoint cannot be overwritten by an older prepared proof.
        sqlx::query("UPDATE wrpc_inbox_streams SET anchor=$1 WHERE stream='testnet-10:effects'")
            .bind(serde_json::to_value(&next).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        assert!(journal
            .finish_contiguous(&intent, &previous, &next)
            .await
            .is_err());
        assert!(journal.load().await.unwrap().is_some());
        assert_eq!(inbox.oldest().await.unwrap().unwrap().sequence, 1);
        sqlx::query("UPDATE wrpc_inbox_streams SET anchor=$1 WHERE stream='testnet-10:effects'")
            .bind(serde_json::to_value(&previous).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        journal
            .finish_contiguous(&intent, &previous, &next)
            .await
            .unwrap();
        assert!(inbox.oldest().await.unwrap().is_none());
        let stored: serde_json::Value = sqlx::query_scalar(
            "SELECT anchor FROM wrpc_inbox_streams WHERE stream='testnet-10:effects'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, serde_json::to_value(&next).unwrap());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn no_effect_ack_is_fenced_and_checks_anchor_without_creating_intent(pool: PgPool) {
        let (inbox, journal) = setup(&pool, 4096).await;
        let anchor = ChainAnchor {
            network: "testnet-10".into(),
            block_hash: "aa".repeat(32),
            blue_score: 99,
        };
        assert!(inbox
            .acknowledge_contiguous(1, &anchor, &anchor, &journal.fence)
            .await
            .is_err());
        sqlx::query("UPDATE wrpc_inbox_streams SET anchor=$1 WHERE stream='testnet-10:effects'")
            .bind(serde_json::to_value(&anchor).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        let new_fence = DurableConsumerFence::claim(&pool, "testnet-10:effects")
            .await
            .unwrap();
        assert!(inbox
            .acknowledge_contiguous(1, &anchor, &anchor, &journal.fence)
            .await
            .is_err());
        assert!(inbox.oldest().await.unwrap().is_some());
        inbox
            .acknowledge_contiguous(1, &anchor, &anchor, &new_fence)
            .await
            .unwrap();
        assert!(inbox.oldest().await.unwrap().is_none());
        assert!(journal.load().await.unwrap().is_none());
    }
}
