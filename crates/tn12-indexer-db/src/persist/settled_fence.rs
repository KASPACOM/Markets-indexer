//! Fence a settled recheck owner across REST reads and bounded database writes.
//! A replacement increments the generation under the shared writer lock, so a
//! stale worker cannot commit another replay or reconciliation transaction.
use super::{PgPersister, PERSIST_WRITER_LOCK_KEY};
use anyhow::{ensure, Result};
use sqlx::{PgPool, Postgres, Transaction};

#[derive(Clone, Debug)]
pub struct SettledRecheckFence {
    key: String,
    generation: i64,
}

impl SettledRecheckFence {
    pub async fn claim(pool: &PgPool, cursor_key: &str) -> Result<Self> {
        ensure!(
            !cursor_key.is_empty() && cursor_key.len() <= 200,
            "invalid settled cursor key"
        );
        let key = format!("{cursor_key}:settled_recheck_owner");
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PERSIST_WRITER_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let generation: i64 = sqlx::query_scalar(
            "INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,jsonb_build_object('generation',1),$2) \
             ON CONFLICT(key) DO UPDATE SET value=jsonb_build_object('generation',(indexer_state.value->>'generation')::bigint+1),updated_at_ms=$2 \
             RETURNING (value->>'generation')::bigint"
        ).bind(&key).bind(chrono::Utc::now().timestamp_millis()).fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(Self { key, generation })
    }

    pub async fn assert_current(&self, pool: &PgPool) -> Result<()> {
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT (value->>'generation')::bigint FROM indexer_state WHERE key=$1",
        )
        .bind(&self.key)
        .fetch_optional(pool)
        .await?;
        ensure!(
            current == Some(self.generation),
            "settled recheck owner was replaced"
        );
        Ok(())
    }

    pub(super) async fn verify_locked(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        let current: Option<i64> = sqlx::query_scalar(
            "SELECT (value->>'generation')::bigint FROM indexer_state WHERE key=$1",
        )
        .bind(&self.key)
        .fetch_optional(&mut **tx)
        .await?;
        ensure!(
            current == Some(self.generation),
            "settled recheck owner was replaced"
        );
        Ok(())
    }
}

impl PgPersister {
    pub fn with_settled_recheck_fence(mut self, fence: SettledRecheckFence) -> Self {
        self.settled_recheck_fence = Some(fence);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::{PersistTransientKind, TransientPersistError};
    use std::time::Duration;

    fn writer_lock_busy(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| {
            cause
                .downcast_ref::<TransientPersistError>()
                .is_some_and(|pressure| pressure.kind == PersistTransientKind::WriterLockBusy)
        })
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn replacement_fences_old_recheck_writes(pool: PgPool) {
        let first = SettledRecheckFence::claim(&pool, "history").await.unwrap();
        let second = SettledRecheckFence::claim(&pool, "history").await.unwrap();
        assert!(first.assert_current(&pool).await.is_err());
        second.assert_current(&pool).await.unwrap();
        let old = PgPersister::for_genesis_repair(pool.clone()).with_settled_recheck_fence(first);
        let old_error = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match old.prepare_settled_repair("history", 100, 100).await {
                    Err(error) if writer_lock_busy(&error) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    result => break result,
                }
            }
        })
        .await
        .expect("old settled owner remained blocked for ten seconds")
        .expect_err("replaced settled owner prepared a replay");
        assert!(format!("{old_error:#}").contains("settled recheck owner was replaced"));
        let current = PgPersister::for_genesis_repair(pool).with_settled_recheck_fence(second);
        // Other database tests share the process-wide writer lock. Retry only
        // that transient contention; the ownership assertion must still pass.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match current.prepare_settled_repair("history", 100, 100).await {
                    Ok(_) => break,
                    Err(error) if writer_lock_busy(&error) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(error) => {
                        panic!("current settled owner could not prepare replay: {error:#}")
                    }
                }
            }
        })
        .await
        .expect("current settled owner remained blocked for ten seconds");
    }
}
