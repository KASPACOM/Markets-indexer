//! Durable intent for the single live writer. Cleared only after acknowledged
//! persistence or a fresh canonical REST replay of every affected score window.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tn12_indexer_core::RestTransaction;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveWriteWindow {
    /// Node event hashes retained before metadata lookup or any removal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_blocks: Vec<String>,
    pub transactions: Vec<RestTransaction>,
    /// Complete rejected source bodies from recovery; accepted bodies live in
    /// `transactions`. Neither authorizes replay without fresh source evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_transactions: Vec<RestTransaction>,
    /// Indexed transactions in a removed block, including ones now rejected.
    /// Keep their IDs after a partial replay so later source changes are seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_transaction_ids: Vec<String>,
    #[serde(default)]
    pub observed_blocks: std::collections::BTreeMap<u64, std::collections::BTreeSet<String>>,
    /// Width used to collect observed_blocks. Legacy intents require per-hash
    /// score validation before assigning the current recovery width.
    #[serde(default)]
    pub window_width: Option<u32>,
}

impl LiveWriteWindow {
    pub fn new(transactions: &[RestTransaction]) -> Result<Self> {
        anyhow::ensure!(!transactions.is_empty(), "empty live write intent");
        let window = Self {
            unresolved_blocks: Vec::new(),
            transactions: transactions.to_vec(),
            rejected_transactions: Vec::new(),
            affected_transaction_ids: Vec::new(),
            observed_blocks: Default::default(),
            window_width: None,
        };
        window.validate()?;
        Ok(window)
    }

    /// Reorg-only intents carry affected score windows without transactions.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.transactions.is_empty() || !self.observed_blocks.is_empty() || !self.unresolved_blocks.is_empty(),
            "empty live recovery intent"
        );
        anyhow::ensure!(self.unresolved_blocks.len() <= 8192,"live event hash bound exceeded");
        for hash in &self.unresolved_blocks {
            anyhow::ensure!(hex::decode(hash).is_ok_and(|v|v.len()==32),"invalid unresolved event hash");
        }
        if let Some(width) = self.window_width {
            anyhow::ensure!(
                matches!(width, 10 | 100),
                "unsupported recovery window width"
            );
        }
        for hashes in self.observed_blocks.values() {
            anyhow::ensure!(!hashes.is_empty(), "empty observed block set");
            for hash in hashes {
                anyhow::ensure!(
                    hex::decode(hash).is_ok_and(|v| v.len() == 32),
                    "invalid observed block hash"
                );
            }
        }
        anyhow::ensure!(self.affected_transaction_ids.len() <= 256,
            "too many affected live recovery transactions");
        for id in &self.affected_transaction_ids {
            anyhow::ensure!(hex::decode(id).is_ok_and(|v| v.len() == 32),
                "invalid affected live recovery transaction ID");
        }
        for tx in &self.transactions {
            anyhow::ensure!(
                tx.is_accepted
                    && tx.accepting_block_blue_score.is_some()
                    && tx
                        .accepting_block_hash
                        .as_ref()
                        .is_some_and(|hash| hash.len() == 64 && hex::decode(hash).is_ok()),
                "live write intent requires complete acceptance coordinates"
            );
        }
        anyhow::ensure!(self.rejected_transactions.len() <= 256, "too many rejected recovery bodies");
        let mut ids: std::collections::BTreeSet<_> = self.transactions.iter().map(|tx| &tx.transaction_id).collect();
        for tx in &self.rejected_transactions {
            anyhow::ensure!(hex::decode(&tx.transaction_id).is_ok_and(|v| v.len()==32)
                && ids.insert(&tx.transaction_id), "invalid or duplicate rejected body identity");
            // Explicit rejection is authoritative even when REST retains the
            // previous acceptance coordinates as historical metadata.
            anyhow::ensure!(!tx.is_accepted, "accepted transaction in rejected recovery bodies");
            anyhow::ensure!(tx.accepting_block_hash.as_ref().is_none_or(|hash|
                hex::decode(hash).is_ok_and(|v| v.len() == 32)), "invalid historical rejection block");
            anyhow::ensure!(self.affected_transaction_ids.contains(&tx.transaction_id),
                "rejected transaction missing from affected recovery IDs");
        }
        // Bound serialization before allocating a second copy of the intent.
        struct Limit(usize);
        impl std::io::Write for Limit {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_sub(bytes.len())
                    .ok_or_else(|| std::io::Error::other("live recovery intent exceeds 32 MiB"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Limit(32 * 1024 * 1024), self)?;
        Ok(())
    }
}

#[async_trait::async_trait]
pub trait LiveWriteJournal: Send + Sync {
    fn with_pool(&self, _pool:sqlx::PgPool) -> Result<std::sync::Arc<dyn LiveWriteJournal>> {
        anyhow::bail!("journal cannot use the owned event session")
    }
    fn intent_key(&self) -> Option<&str> {
        None
    }
    async fn load(&self) -> Result<Option<LiveWriteWindow>>;
    async fn begin(&self, window: &LiveWriteWindow) -> Result<()>;
    async fn replace(&self, previous: &LiveWriteWindow, updated: &LiveWriteWindow) -> Result<()>;
    async fn complete(&self, window: &LiveWriteWindow) -> Result<()>;
}

pub struct PgLiveWriteJournal {
    pool: sqlx::PgPool,
    key: String,
    fence: Option<tn12_indexer_db::persist::DurableConsumerFence>,
}
impl PgLiveWriteJournal {
    pub fn with_consumer_fence(
        mut self,
        fence: tn12_indexer_db::persist::DurableConsumerFence,
    ) -> Self {
        self.fence = Some(fence);
        self
    }

    pub fn new(pool: sqlx::PgPool, network_id: &str, cursor_key: &str) -> Self {
        Self {
            pool,
            key: format!("live_write_intent:{network_id}:{cursor_key}"),
            fence: None,
        }
    }
}
#[async_trait::async_trait]
impl LiveWriteJournal for PgLiveWriteJournal {
    fn with_pool(&self,pool:sqlx::PgPool) -> Result<std::sync::Arc<dyn LiveWriteJournal>> {
        Ok(std::sync::Arc::new(Self {pool,key:self.key.clone(),fence:self.fence.clone()}))
    }
    fn intent_key(&self) -> Option<&str> {
        Some(&self.key)
    }
    async fn load(&self) -> Result<Option<LiveWriteWindow>> {
        let value: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT value FROM indexer_state WHERE key = $1")
                .bind(&self.key)
                .fetch_optional(&self.pool)
                .await?;
        value
            .map(serde_json::from_value)
            .transpose()
            .context("decode pending live write intent")
    }
    async fn begin(&self, window: &LiveWriteWindow) -> Result<()> {
        let query = sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,$3) ON CONFLICT(key) DO NOTHING")
            .bind(&self.key).bind(serde_json::to_value(window)?)
            .bind(chrono::Utc::now().timestamp_millis());
        let result = tn12_indexer_db::persist::execute_fenced_metadata(
            &self.pool,
            self.fence.as_ref(),
            query,
        )
        .await?;
        anyhow::ensure!(
            result.rows_affected() == 1,
            "pending live write intent must be reconciled before another batch"
        );
        Ok(())
    }
    async fn replace(&self, previous: &LiveWriteWindow, updated: &LiveWriteWindow) -> Result<()> {
        anyhow::ensure!(
            serde_json::to_vec(updated)?.len() <= 32 * 1024 * 1024,
            "live recovery intent exceeds 32 MiB"
        );
        let query = sqlx::query(
            "UPDATE indexer_state SET value=$3,updated_at_ms=$4 WHERE key=$1 AND value=$2",
        )
        .bind(&self.key)
        .bind(serde_json::to_value(previous)?)
        .bind(serde_json::to_value(updated)?)
        .bind(chrono::Utc::now().timestamp_millis());
        let result = tn12_indexer_db::persist::execute_fenced_metadata(
            &self.pool,
            self.fence.as_ref(),
            query,
        )
        .await?;
        anyhow::ensure!(
            result.rows_affected() == 1,
            "live recovery intent changed during recovery"
        );
        Ok(())
    }
    async fn complete(&self, window: &LiveWriteWindow) -> Result<()> {
        // The verified plan and its writer/read fence retire with this exact
        // journal. Lock the intent first, as recovery owners do, so a stale
        // acknowledgement cannot erase an active or replacement plan.
        let query = sqlx::query(
            "WITH intent AS MATERIALIZED (SELECT key,value FROM indexer_state WHERE key=$1 AND value=$2 FOR UPDATE), \
             retired AS (DELETE FROM tn10_live_recovery_plans p USING intent i \
               WHERE p.intent_key=i.key AND p.phase='complete' \
                 AND p.intent_sha256=pg_catalog.sha256(i.value::text::bytea) RETURNING p.intent_key) \
             DELETE FROM indexer_state s USING intent i WHERE s.key=i.key \
               AND (NOT EXISTS(SELECT 1 FROM tn10_live_recovery_plans p WHERE p.intent_key=i.key) \
                    OR EXISTS(SELECT 1 FROM retired r WHERE r.intent_key=i.key))"
        )
            .bind(&self.key)
            .bind(serde_json::to_value(window)?);
        let result = tn12_indexer_db::persist::execute_fenced_metadata(
            &self.pool,
            self.fence.as_ref(),
            query,
        )
        .await?;
        anyhow::ensure!(
            result.rows_affected() == 1,
            "live write intent changed or disappeared before acknowledgement"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_journal_json_round_trips_without_new_empty_field() {
        let original = LiveWriteWindow::new(&[RestTransaction {
            transaction_id: "11".repeat(32),
            is_accepted: true,
            accepting_block_hash: Some("22".repeat(32)),
            accepting_block_blue_score: Some(105),
            ..Default::default()
        }]).unwrap();
        let mut old = serde_json::to_value(&original).unwrap();
        old.as_object_mut().unwrap().remove("affected_transaction_ids");
        let decoded: LiveWriteWindow = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), old);
    }
    #[test]
    fn rejected_body_retains_old_coordinates_without_becoming_replayable() {
        let mut intent = window(105);
        let rejected = RestTransaction {
            transaction_id: "33".repeat(32),
            is_accepted: false,
            accepting_block_hash: Some("44".repeat(32)),
            accepting_block_blue_score: Some(99),
            accepting_block_time: Some(1000),
            ..Default::default()
        };
        intent.affected_transaction_ids.push(rejected.transaction_id.clone());
        intent.rejected_transactions.push(rejected);
        intent.validate().unwrap();
        let decoded: LiveWriteWindow =
            serde_json::from_value(serde_json::to_value(&intent).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded.transactions.len(), 1);
        assert!(!decoded.rejected_transactions[0].is_accepted);
        assert_eq!(decoded.rejected_transactions[0].accepting_block_blue_score, Some(99));
        assert_eq!(decoded.rejected_transactions[0].accepting_block_hash, Some("44".repeat(32)));
        intent.rejected_transactions[0].is_accepted = true;
        assert!(intent.validate().unwrap_err().to_string().contains("accepted transaction in rejected"));
        intent.rejected_transactions[0].is_accepted = false;
        intent.rejected_transactions[0].accepting_block_hash = Some("invalid".into());
        assert!(intent.validate().unwrap_err().to_string().contains("invalid historical rejection block"));
    }
    fn window(score: u64) -> LiveWriteWindow {
        LiveWriteWindow::new(&[RestTransaction {
            transaction_id: "11".repeat(32),
            is_accepted: true,
            accepting_block_hash: Some("22".repeat(32)),
            accepting_block_blue_score: Some(score),
            ..Default::default()
        }])
        .unwrap()
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn replaced_consumer_cannot_mutate_pending_write_intent(pool: sqlx::PgPool) {
        use tn12_indexer_db::persist::DurableConsumerFence;
        crate::durable_inbox::DurableInbox::open(pool.clone(), "testnet-10:watcher".into(), 1024)
            .await
            .unwrap();
        let first = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let old = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "fenced")
            .with_consumer_fence(first);
        old.begin(&window(10)).await.unwrap();
        let next = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let current =
            PgLiveWriteJournal::new(pool, "testnet-10", "fenced").with_consumer_fence(next);
        assert!(old.replace(&window(10), &window(20)).await.is_err());
        assert!(old.complete(&window(10)).await.is_err());
        assert_eq!(
            current.load().await.unwrap().unwrap().transactions[0].accepting_block_blue_score,
            Some(10)
        );
        current.replace(&window(10), &window(20)).await.unwrap();
        current.complete(&window(20)).await.unwrap();
        assert!(old.begin(&window(30)).await.is_err());
        assert!(current.load().await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn journal_survives_recreation_and_rejects_overwrite_or_wrong_ack(pool: sqlx::PgPool) {
        let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "live-test");
        assert!(journal.load().await.unwrap().is_none());
        journal.begin(&window(10)).await.unwrap();
        let restarted = PgLiveWriteJournal::new(pool, "testnet-10", "live-test");
        assert_eq!(
            restarted.load().await.unwrap().unwrap().transactions[0].accepting_block_blue_score,
            Some(10)
        );
        assert!(restarted.begin(&window(20)).await.is_err());
        assert!(restarted.complete(&window(20)).await.is_err());
        let mut updated = window(10);
        updated
            .observed_blocks
            .entry(10)
            .or_default()
            .insert("33".repeat(32));
        restarted.replace(&window(10), &updated).await.unwrap();
        assert!(restarted.replace(&window(10), &window(20)).await.is_err());
        assert!(restarted.complete(&window(10)).await.is_err());
        assert_eq!(
            restarted.load().await.unwrap().unwrap().observed_blocks,
            updated.observed_blocks
        );
        restarted.complete(&updated).await.unwrap();
        assert!(restarted.load().await.unwrap().is_none());
    }
}
