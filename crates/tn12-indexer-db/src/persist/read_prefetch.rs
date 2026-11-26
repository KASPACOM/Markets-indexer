//! Bounded read hints for settled replay. No returned row affects persistence.
use super::PgPersister;
use anyhow::{ensure, Context, Result};
use sqlx::Acquire;
use std::time::{Duration, Instant};

// A timeout may drop BEGIN, a query, or COMMIT before protocol cleanup.
// Only a fully acknowledged read-only commit permits pool reuse.
struct PrefetchConnection {
    connection: sqlx::pool::PoolConnection<sqlx::Postgres>,
    reusable: bool,
}
impl Drop for PrefetchConnection {
    fn drop(&mut self) {
        if !self.reusable {
            self.connection.close_on_drop();
        }
    }
}

impl PgPersister {
    pub(super) async fn prefetch_identity_pages(&self, txids: &[String]) -> Result<bool> {
        let Some(readers) = &self.read_prefetch else {
            return Ok(false);
        };
        ensure!(
            txids.len() <= 64,
            "identity prefetch exceeds 64 transactions"
        );
        if txids.is_empty() {
            return Ok(false);
        }
        // Skip hints under pressure. They cannot hold up correctness or claim
        // writer ownership. The same semaphore bounds all lookahead windows.
        let Ok(_permit) = readers.try_acquire() else {
            return Ok(false);
        };
        let ids: Vec<Vec<u8>> = txids
            .iter()
            .map(|id| {
                let bytes = hex::decode(id).context("invalid prefetch transaction ID")?;
                ensure!(bytes.len() == 32, "invalid prefetch transaction ID length");
                Ok(bytes)
            })
            .collect::<Result<_>>()?;
        let started = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(1), async {
            let mut lease = PrefetchConnection {
                connection: self.pool.acquire().await?,
                reusable: false,
            };
            let mut tx = lease.connection.begin().await?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL statement_timeout = '500ms'")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL lock_timeout = '50ms'")
                .execute(&mut *tx)
                .await?;
            // LIMIT 1 bounds duplicate identities; later writes still load all
            // required rows and independently validate canonical acceptance.
            let _: i64 = sqlx::query_scalar(
                r#"
                SELECT coalesce(sum(coalesce(octet_length(u.created_block),0)
                    + coalesce(octet_length(a.block_hash),0)
                    + coalesce(octet_length(c.genesis_block),0)),0)::bigint
                FROM unnest($1::bytea[]) w(txid)
                LEFT JOIN LATERAL (SELECT created_block FROM covenant_utxos
                    WHERE txid=w.txid LIMIT 1) u ON true
                LEFT JOIN LATERAL (SELECT block_hash FROM covenant_actions
                    WHERE txid=w.txid LIMIT 1) a ON true
                LEFT JOIN LATERAL (SELECT genesis_block FROM covenants
                    WHERE genesis_txid=w.txid LIMIT 1) c ON true
            "#,
            )
            .bind(ids)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            lease.reusable = true;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("identity prefetch deadline")?;
        tracing::debug!(
            transactions = txids.len(),
            elapsed_us = started.elapsed().as_micros() as u64,
            success = result.is_ok(),
            "historical identity read prefetch"
        );
        result.map(|()| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::{Persister, PERSIST_WRITER_LOCK_KEY};
    use sqlx::PgPool;
    #[sqlx::test(migrations = "./migrations")]
    async fn hints_are_bounded_optional_and_do_not_take_writer_lock(pool: PgPool) {
        let disabled = PgPersister::new(pool.clone());
        disabled
            .prefetch_identities(&["not a txid".into()])
            .await
            .unwrap();
        let mut enabled = PgPersister::new(pool.clone());
        enabled.read_prefetch = Some(std::sync::Arc::new(tokio::sync::Semaphore::new(2)));
        let mut writer = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PERSIST_WRITER_LOCK_KEY)
            .execute(&mut *writer)
            .await
            .unwrap();
        enabled
            .prefetch_identities(&["ab".repeat(32)])
            .await
            .unwrap();
        assert!(enabled
            .prefetch_identities(&["ab".repeat(31)])
            .await
            .is_err());
        assert!(enabled
            .prefetch_identities(&vec!["ab".repeat(32); 65])
            .await
            .is_err());
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
        let first = enabled
            .read_prefetch
            .as_ref()
            .unwrap()
            .acquire()
            .await
            .unwrap();
        let second = enabled
            .read_prefetch
            .as_ref()
            .unwrap()
            .acquire()
            .await
            .unwrap();
        enabled
            .prefetch_identities(&["invalid but skipped at capacity".into()])
            .await
            .unwrap();
        drop((first, second));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn prefetch_configuration_is_explicit_and_validated(pool: PgPool) {
        let off = PgPersister::for_tip_follow_settings(pool.clone(), |_| None).unwrap();
        assert!(off.read_prefetch.is_none());
        for value in ["0", "1", "2", "true"] {
            let configured = PgPersister::for_tip_follow_settings(pool.clone(), |name| {
                (name == "TN12_HISTORY_READ_PREFETCH").then(|| value.to_string())
            });
            if value == "0" || value == "1" {
                assert_eq!(configured.unwrap().read_prefetch.is_some(), value == "1");
            } else {
                assert!(configured.is_err());
            }
        }
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn failed_prefetch_does_not_reuse_its_transaction_session(pool: PgPool) {
        let hints = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let before: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&hints)
            .await
            .unwrap();
        let mut enabled = PgPersister::new(hints.clone());
        enabled.read_prefetch = Some(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE covenant_actions IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *blocker)
            .await
            .unwrap();
        let result = enabled.prefetch_identities(&["ab".repeat(32)]).await;
        assert!(result.is_err(), "read hint should hit its lock timeout");
        blocker.rollback().await.unwrap();
        let after: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&hints)
            .await
            .unwrap();
        assert_ne!(
            before, after,
            "failed transaction session must be discarded"
        );
        let readonly: String = sqlx::query_scalar("SHOW transaction_read_only")
            .fetch_one(&hints)
            .await
            .unwrap();
        assert_eq!(readonly, "off");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn successful_prefetch_reuses_clean_session(pool: PgPool) {
        let hints = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let before: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&hints)
            .await
            .unwrap();
        let mut enabled = PgPersister::new(hints.clone());
        enabled.read_prefetch = Some(std::sync::Arc::new(tokio::sync::Semaphore::new(1)));
        assert!(enabled
            .prefetch_identities(&["ab".repeat(32)])
            .await
            .unwrap());
        let (after, readonly): (i32, String) =
            sqlx::query_as("SELECT pg_backend_pid(),current_setting('transaction_read_only')")
                .fetch_one(&hints)
                .await
                .unwrap();
        assert_eq!(before, after);
        assert_eq!(readonly, "off");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn cancelled_read_transaction_is_closed_before_pool_reuse(pool: PgPool) {
        let hints = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let before: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&hints)
            .await
            .unwrap();
        let copy = hints.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut lease = PrefetchConnection {
                connection: copy.acquire().await.unwrap(),
                reusable: false,
            };
            let mut tx = lease.connection.begin().await.unwrap();
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await
                .unwrap();
            started_tx.send(()).unwrap();
            sqlx::query("SELECT pg_sleep(10)")
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            lease.reusable = true;
        });
        started_rx.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let active: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND state='active' AND query='SELECT pg_sleep(10)')",
                ).bind(before).fetch_one(&pool).await.unwrap();
                if active { break; }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("sleep query must reach PostgreSQL before cancellation");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let (after, readonly): (i32, String) = tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query_as("SELECT pg_backend_pid(),current_setting('transaction_read_only')")
                .fetch_one(&hints),
        )
        .await
        .expect("cancelled read must not pin pool for its ten-second query")
        .unwrap();
        assert_ne!(before, after);
        assert_eq!(readonly, "off");
    }
}
