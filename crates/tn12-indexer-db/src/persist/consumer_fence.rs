//! A replacement consumer must cross the same serialization lock as every
//! covenant write. A lost lease connection alone cannot fence a pooled writer.
use anyhow::{ensure, Context, Result};
use sqlx::{PgPool, Postgres, Transaction};

use super::{PgPersister, PERSIST_WRITER_LOCK_KEY};

#[derive(Clone, Debug)]
pub struct DurableConsumerFence {
    stream: String,
    generation: i64,
}

impl DurableConsumerFence {
    /// Claim only once per consumer startup. A stale worker must exit, never
    /// reclaim automatically. The caller opens the durable stream beforehand.
    pub async fn claim(pool: &PgPool, stream: &str) -> Result<Self> {
        ensure!(
            !stream.is_empty() && stream.len() <= 256,
            "invalid consumer stream"
        );
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='1s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PERSIST_WRITER_LOCK_KEY)
            .execute(&mut *tx)
            .await?;
        let generation = sqlx::query_scalar(
            "UPDATE wrpc_inbox_streams SET consumer_generation=consumer_generation+1 WHERE stream=$1 RETURNING consumer_generation"
        ).bind(stream).fetch_one(&mut *tx).await.context("claim durable consumer generation")?;
        tx.commit().await?;
        Ok(Self {
            stream: stream.to_owned(),
            generation,
        })
    }

    /// For writes, the caller holds the global writer lock. For inbox commits,
    /// the caller holds this stream row lock. Either prevents takeover from
    /// committing between this check and the protected transaction's commit.
    pub async fn verify_locked(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        stream: &str,
    ) -> Result<()> {
        ensure!(
            self.stream == stream,
            "consumer fence belongs to another stream"
        );
        let generation: i64 = sqlx::query_scalar(
            "SELECT consumer_generation FROM wrpc_inbox_streams WHERE stream=$1",
        )
        .bind(stream)
        .fetch_one(&mut **tx)
        .await?;
        ensure!(
            generation == self.generation,
            "durable consumer generation is stale"
        );
        Ok(())
    }
}

/// Metadata writes share the stream row with takeover. The ordinary watcher
/// keeps its original single-statement path until durable intake is enabled.
pub async fn execute_fenced_metadata<'q>(
    pool: &PgPool,
    fence: Option<&DurableConsumerFence>,
    query: sqlx::query::Query<'q, Postgres, sqlx::postgres::PgArguments>,
) -> Result<sqlx::postgres::PgQueryResult> {
    let Some(fence) = fence else {
        return Ok(query.execute(pool).await?);
    };
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='350ms'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='1s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT stream FROM wrpc_inbox_streams WHERE stream=$1 FOR SHARE")
        .bind(&fence.stream)
        .fetch_one(&mut *tx)
        .await?;
    fence.verify_locked(&mut tx, &fence.stream).await?;
    let result = query.execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(result)
}

impl PgPersister {
    pub fn with_durable_consumer_fence(mut self, fence: DurableConsumerFence) -> Self {
        self.consumer_fence = Some(fence);
        self
    }

    pub(super) async fn verify_consumer_fence(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<()> {
        if let Some(session) = &self.recovery_session {
            session.verify(tx).await?;
        }
        if let Some(fence) = &self.consumer_fence {
            fence.verify_locked(tx, &fence.stream).await?;
        }
        if let Some(fence) = &self.settled_recheck_fence {
            fence.verify_locked(tx).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_stream(pool: &PgPool) {
        sqlx::query(
            "INSERT INTO wrpc_inbox_streams(stream,updated_at_ms) VALUES('testnet-10:watcher',0)",
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn replacement_fences_both_writer_lock_modes(pool: PgPool) {
        create_stream(&pool).await;
        let first = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let second = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        for wait in [false, true] {
            let mut stale =
                PgPersister::new(pool.clone()).with_durable_consumer_fence(first.clone());
            stale.wait_for_writer_lock = wait;
            let mut tx = pool.begin().await.unwrap();
            assert!(stale
                .acquire_persist_writer_lock(&mut tx)
                .await
                .unwrap_err()
                .to_string()
                .contains("stale"));
            tx.rollback().await.unwrap();
            let current =
                PgPersister::new(pool.clone()).with_durable_consumer_fence(second.clone());
            let mut tx = pool.begin().await.unwrap();
            current.acquire_persist_writer_lock(&mut tx).await.unwrap();
            tx.rollback().await.unwrap();
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn takeover_cannot_cross_an_inflight_write(pool: PgPool) {
        create_stream(&pool).await;
        let fence = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let writer = PgPersister::new(pool.clone()).with_durable_consumer_fence(fence.clone());
        let mut tx = pool.begin().await.unwrap();
        writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
        assert!(DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .is_err());
        fence
            .verify_locked(&mut tx, "testnet-10:watcher")
            .await
            .unwrap();
        assert!(fence
            .verify_locked(&mut tx, "another-stream")
            .await
            .is_err());
        tx.commit().await.unwrap();
        DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert!(writer.acquire_persist_writer_lock(&mut tx).await.is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn native_bulk_and_live_priority_preserve_consumer_fencing(pool: PgPool) {
        use crate::Persister;
        create_stream(&pool).await;
        let old = DurableConsumerFence::claim(&pool, "testnet-10:watcher")
            .await
            .unwrap();
        let build = |fence| {
            PgPersister::for_wrpc_settings(pool.clone(), "testnet-10", |key| {
                matches!(
                    key,
                    "TN12_WRPC_GENERIC_BULK_PERSIST"
                        | "TN12_WRPC_NATIVE_GENESIS_BULK"
                        | "TN12_WRITER_LIVE_PRIORITY"
                )
                .then(|| "1".to_owned())
            })
            .unwrap()
            .with_durable_consumer_fence(fence)
        };
        let stale = build(old);
        let current = build(
            DurableConsumerFence::claim(&pool, "testnet-10:watcher")
                .await
                .unwrap(),
        );
        let tx: tn12_indexer_core::RestTransaction = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-native-genesis-burst.json"
        ))
        .unwrap();
        let error = stale
            .persist_batch(std::slice::from_ref(&tx))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("stale"));
        let actions: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(actions, 0);
        current
            .persist_batch(std::slice::from_ref(&tx))
            .await
            .unwrap();
        let id: String = sqlx::query_scalar("SELECT encode(covenant_id,'hex') FROM covenants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            id,
            "73f224d972ce346285ddc0985a7034bba6889a8d7779cbdd461e0f5817e86adb"
        );
        assert!(stale
            .revert_block(&hex::decode(tx.accepting_block_hash.unwrap()).unwrap())
            .await
            .is_err());
        let remaining_actions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining_actions, 1);
    }
}
