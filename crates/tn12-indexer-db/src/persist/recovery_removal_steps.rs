//! Resolve a failed removal under the writer fence before retrying or reducing
//! its granularity. The staged source evidence and original journal stay intact.
use super::paged_recovery::{decode_hash, lock_intent_and_owner};
use super::{
    recovery_impact, PagedRecoveryOwner, PgPersister, RecoveryReplanRequired, StagedRecoveryBlock,
};
use anyhow::{ensure, Result};
use sqlx::Row;

#[derive(Debug, thiserror::Error)]
#[error("canonical removal retry {attempt}/3 for block {block}: {reason}")]
pub struct RecoveryRemovalRetry {
    pub attempt: i32,
    pub block: String,
    pub reason: String,
}

pub(super) fn removal_needs_reconciliation(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let Some(error) = cause.downcast_ref::<sqlx::Error>() else { return false; };
        matches!(error, sqlx::Error::Io(_) | sqlx::Error::Tls(_) | sqlx::Error::Protocol(_))
            || error.as_database_error().and_then(|e| e.code())
                .is_some_and(|code| matches!(code.as_ref(), "57014" | "55P03"))
    })
}

impl PagedRecoveryOwner {
    /// Acquiring the same writer lock resolves any still-running transaction.
    /// A committed checkpoint wins over an error reported by its client.
    pub(super) async fn reconcile_failed_removal(
        &self,
        writer: &PgPersister,
        block: &StagedRecoveryBlock,
        error: &anyhow::Error,
    ) -> Result<()> {
        let hash = decode_hash(&block.impact.block_hash)?;
        let mut tx = writer.paged_recovery_pool().begin().await?;
        PgPersister::set_persist_query_limits(&mut tx).await?;
        writer
            .acquire_recovery_writer_lock(&mut tx, Some(self))
            .await?;
        lock_intent_and_owner(&mut tx, self).await?;
        let row = sqlx::query("SELECT transaction_ids,descendants,reverted,chunked FROM tn10_live_recovery_blocks WHERE intent_key=$1 AND block_hash=$2 FOR UPDATE")
            .bind(&self.intent_key).bind(&hash).fetch_one(&mut *tx).await?;
        if row.try_get::<bool, _>("reverted")? {
            tx.commit().await?;
            return Ok(());
        }
        if row.try_get::<bool, _>("chunked")? && !block.impact.transaction_ids.is_empty() {
            let id = decode_hash(&block.impact.transaction_ids[0])?;
            let committed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_block_items WHERE intent_key=$1 AND block_hash=$2 AND kind='transaction' AND item=$3 AND removed)")
                .bind(&self.intent_key).bind(&hash).bind(id).fetch_one(&mut *tx).await?;
            if committed {
                tx.commit().await?;
                return Ok(());
            }
        }
        let ids: Vec<String> = serde_json::from_value(row.try_get("transaction_ids")?)?;
        let children: Vec<String> = serde_json::from_value(row.try_get("descendants")?)?;
        if !row.try_get::<bool, _>("chunked")? && ids.len() > 1 {
            // Fence ordinary writers before checking that all indexed effects
            // are still covered by the already-pinned discovery evidence.
            sqlx::query(
                "UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE WHERE intent_key=$1",
            )
            .bind(&self.intent_key)
            .execute(&mut *tx)
            .await?;
            let actual = recovery_impact::load(&mut tx, &block.impact.block_hash).await?;
            ensure!(
                actual.transaction_ids.iter().all(|id| ids.contains(id))
                    && actual.descendants.iter().all(|id| children.contains(id)),
                RecoveryReplanRequired("removal footprint changed before transaction paging")
            );
            for (kind, items) in [("transaction", &ids), ("descendant", &children)] {
                sqlx::query("INSERT INTO tn10_live_recovery_block_items(intent_key,block_hash,kind,item) SELECT $1,$2,$3,decode(value,'hex') FROM jsonb_array_elements_text($4::jsonb) ON CONFLICT DO NOTHING")
                    .bind(&self.intent_key).bind(&hash).bind(kind).bind(serde_json::to_value(items)?)
                    .execute(&mut *tx).await?;
            }
            sqlx::query("UPDATE tn10_live_recovery_blocks SET chunked=TRUE,removal_failures=0 WHERE intent_key=$1 AND block_hash=$2")
                .bind(&self.intent_key).bind(&hash).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(());
        }
        let reason: String = format!("{error:#}").chars().take(2048).collect();
        let attempt: i32 = sqlx::query_scalar("UPDATE tn10_live_recovery_blocks SET removal_failures=least(removal_failures+1,3),last_removal_error=$3,last_removal_failure_at_ms=$4 WHERE intent_key=$1 AND block_hash=$2 RETURNING removal_failures")
            .bind(&self.intent_key).bind(&hash).bind(&reason).bind(chrono::Utc::now().timestamp_millis())
            .fetch_one(&mut *tx).await?;
        tx.commit().await?;
        ensure!(attempt<3, "canonical recovery blocked at smallest removal step: block {}, stage=remove, consecutiveFailures={}, cause={}",block.impact.block_hash,attempt,reason);
        Err(RecoveryRemovalRetry {
            attempt,
            block: block.impact.block_hash.clone(),
            reason,
        }
        .into())
    }
}
