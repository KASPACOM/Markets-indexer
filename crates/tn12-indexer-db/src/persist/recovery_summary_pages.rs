//! Rebuild absent/invalid baselines before removal, while the existing global
//! recovery fence protects the canonical generation. No partial totals publish.
use super::paged_recovery::{decode_hash, lock_intent_and_owner};
use super::{PagedRecoveryOwner, PgPersister, StagedRecoveryBlock};
use anyhow::{ensure, Result};

impl PagedRecoveryOwner {
    /// Returns true when a baseline was rebuilt. The caller must then return
    /// through fresh source validation before attempting canonical removal.
    pub(super) async fn prepare_removal_summaries(
        &self,
        writer: &PgPersister,
        block: &StagedRecoveryBlock,
    ) -> Result<bool> {
        let hash = decode_hash(&block.impact.block_hash)?;
        let ids: Vec<Vec<u8>> = block
            .impact
            .transaction_ids
            .iter()
            .map(|id| decode_hash(id))
            .collect::<Result<_>>()?;
        let mut rebuilt = false;
        loop {
            let mut tx = writer.paged_recovery_pool().begin().await?;
            PgPersister::set_persist_query_limits(&mut tx).await?;
            writer
                .acquire_recovery_writer_lock(&mut tx, Some(self))
                .await?;
            lock_intent_and_owner(&mut tx, self).await?;
            let reverting: bool = sqlx::query_scalar(
                "SELECT phase='revert' FROM tn10_live_recovery_plans WHERE intent_key=$1",
            )
            .bind(&self.intent_key)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(reverting, "summary rebuild requires removal phase");
            let ready: bool = sqlx::query_scalar(
                "SELECT phase='ready' FROM covenant_active_output_order_progress WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await?;
            if !ready {
                tx.commit().await?;
                return Ok(rebuilt);
            }
            let family: Option<Vec<u8>> =
                sqlx::query_scalar(include_str!("recovery_missing_summary.sql"))
                    .bind(&hash)
                    .bind(&ids)
                    .fetch_optional(&mut *tx)
                    .await?;
            let Some(family) = family else {
                tx.commit().await?;
                return Ok(rebuilt);
            };
            sqlx::query(
                "UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE WHERE intent_key=$1",
            )
            .bind(&self.intent_key)
            .execute(&mut *tx)
            .await?;
            let complete: bool = sqlx::query_scalar("SELECT recovery_summary_page($1,$2)")
                .bind(&self.intent_key)
                .bind(&family)
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            rebuilt = true;
            tokio::task::yield_now().await;
            if complete {
                return Ok(true);
            }
        }
    }
}
