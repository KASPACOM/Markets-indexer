//! A short exclusive operation lease across several bounded write transactions.
//! Uses the existing writer lock. A replacement pool connection cannot inherit
//! the lease: every mutation checks the original backend and session nonce.
//! This does not establish canonical source evidence or acknowledge a journal.
use super::{DurableConsumerFence, PgPersister, PERSIST_WRITER_LOCK_KEY};
use anyhow::{ensure, Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const MAX_OPERATION_TIME: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub(super) struct RecoverySessionFence {
    backend: i32,
    backend_start: chrono::DateTime<chrono::Utc>,
    nonce: String,
    expires: Instant,
    bounded_operation: bool,
}

impl RecoverySessionFence {
    pub(super) async fn verify(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        ensure!(
            !self.bounded_operation || Instant::now() < self.expires,
            "canonical write operation deadline exceeded"
        );
        if !self.bounded_operation {
            sqlx::raw_sql("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'")
                .execute(&mut **tx)
                .await?;
        }
        let matches: bool = sqlx::query_scalar(
            "SELECT pg_backend_pid()=$1 AND current_setting('tn12.recovery_session',true) IS NOT DISTINCT FROM $2::text AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$3)"
        ).bind(self.backend).bind(&self.nonce).bind(self.backend_start).fetch_one(&mut **tx).await?;
        ensure!(
            matches,
            "canonical write session was replaced; retain recovery intent"
        );
        Ok(())
    }
}

/// The caller prepares source data before acquiring this lease. All ordinary
/// writers already honor its advisory lock. Partial commits remain possible on
/// failure, so the caller must retain its durable intent and recover canonically.
pub struct CanonicalWriteLease {
    writer: Arc<PgPersister>,
    pool: PgPool,
    control: PgPool,
    cleanup_runtime: tokio::runtime::Handle,
    close_started: bool,
}

impl CanonicalWriteLease {
    pub async fn acquire(
        source: &PgPool,
        network: &str,
        consumer: DurableConsumerFence,
    ) -> Result<Self> {
        let writer =
            PgPersister::for_wrpc(source.clone(), network)?.with_durable_consumer_fence(consumer);
        Self::acquire_writer(writer, true).await
    }

    /// Serialize one already-prepared live reorg across its removal/addition
    /// commits. The caller journals the whole event before the first mutation.
    /// There is no scheduling deadline; individual database operations remain bounded.
    pub async fn acquire_for_live_event(writer: &PgPersister) -> Result<Self> {
        Self::acquire_writer(writer.clone(), false).await
    }

    async fn acquire_writer(mut writer: PgPersister, bounded_operation: bool) -> Result<Self> {
        let source = writer.pool.clone();
        // Reserve a separate control connection before taking the writer lock.
        // Cleanup must not depend on availability of the caller's working pool.
        let control = PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .acquire_timeout(Duration::from_secs(1))
            .connect_with((*source.connect_options()).clone())
            .await?;
        let opened = Arc::new(AtomicBool::new(false));
        let pool = PgPoolOptions::new()
            .after_connect(move |_, _| {
                let first = !opened.swap(true, Ordering::SeqCst);
                Box::pin(async move {
                    if first {
                        Ok(())
                    } else {
                        Err(sqlx::Error::Protocol(
                            "canonical write session cannot reconnect".into(),
                        ))
                    }
                })
            })
            .max_connections(1)
            .min_connections(0)
            .max_lifetime(None)
            .idle_timeout(None)
            .acquire_timeout(Duration::from_secs(2))
            .connect_with((*source.connect_options()).clone())
            .await?;
        writer.pool = pool.clone();
        // Reentrant writes must not wait on their own live-pressure marker.
        writer.writer_priority = super::live_pressure::WriterPriority::Disabled;
        let mut connection = pool.acquire().await?;
        sqlx::raw_sql(if bounded_operation {
            "SET statement_timeout='1s'; SET idle_session_timeout='2s'"
        } else {
            "SET statement_timeout='5s'; SET lock_timeout='1s'; SET idle_session_timeout=0"
        })
        .execute(&mut *connection)
        .await?;
        let (backend, nonce, backend_start): (i32, String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT pid,set_config('tn12.recovery_session',gen_random_uuid()::text,false),backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()"
        ).fetch_one(&mut *connection).await?;
        if bounded_operation {
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                .bind(PERSIST_WRITER_LOCK_KEY)
                .fetch_one(&mut *connection)
                .await?;
            ensure!(
                acquired,
                "canonical write operation busy; retain recovery intent"
            );
        } else {
            sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(PERSIST_WRITER_LOCK_KEY)
                .execute(&mut *connection)
                .await
                .map_err(|error| {
                    super::classify_persist_sqlx_error("acquire live event lease", error)
                })?;
        }
        writer.recovery_session = Some(RecoverySessionFence {
            backend,
            backend_start,
            nonce,
            expires: Instant::now() + MAX_OPERATION_TIME,
            bounded_operation,
        });
        drop(connection);
        Ok(Self {
            writer: Arc::new(writer),
            pool,
            control,
            cleanup_runtime: tokio::runtime::Handle::current(),
            close_started: false,
        })
    }

    /// A retained clone becomes unusable when the lease closes or its physical
    /// session dies. It must never be used to retry an uncertain raw event.
    #[cfg(test)]
    fn writer(&self) -> Arc<PgPersister> {
        self.writer.clone()
    }

    /// Run only prepared canonical work. The closure must commit its proof and
    /// receipt acknowledgement through this writer's pool before returning.
    /// An error or timeout retains the durable intent for canonical recovery.
    pub async fn run<F, Fut, T>(self, action: F) -> Result<T>
    where
        F: FnOnce(Arc<PgPersister>) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let deadline = self
            .writer
            .recovery_session
            .as_ref()
            .expect("owned session")
            .expires;
        let bounded = self
            .writer
            .recovery_session
            .as_ref()
            .expect("owned session")
            .bounded_operation;
        let result = if bounded {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                action(self.writer.clone()),
            )
            .await
            .context("canonical operation deadline; retain recovery intent")
            .and_then(|r| r)
        } else {
            action(self.writer.clone()).await
        };
        let closed = self.close().await;
        match result {
            Err(error) => {
                if let Err(close_error) = closed {
                    tracing::warn!(%close_error, "canonical session close failed after operation error");
                }
                Err(error)
            }
            Ok(value) => {
                closed?;
                Ok(value)
            }
        }
    }

    async fn close(mut self) -> Result<()> {
        let session = self
            .writer
            .recovery_session
            .as_ref()
            .expect("owned session");
        let result = close_owned_session(
            &self.pool,
            &self.control,
            session.backend,
            session.backend_start,
        )
        .await;
        self.close_started = result.is_ok();
        result
    }
}

// Closing a TCP socket need not interrupt an executing PostgreSQL statement.
// Explicitly terminate only this dedicated backend, matching its start time to
// protect against PID reuse. The control connection never takes the writer lock.
async fn close_owned_session(
    pool: &PgPool,
    control: &PgPool,
    backend: i32,
    backend_start: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let closing = async {
        tokio::time::timeout(Duration::from_secs(3), pool.close())
            .await
            .context("canonical pool close deadline")
    };
    let terminate = async {
        let terminated: Option<bool> = tokio::time::timeout(Duration::from_secs(1),
            sqlx::query_scalar("SELECT pg_terminate_backend(pid,250) FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND datname=current_database() AND usename=current_user")
                .bind(backend).bind(backend_start).fetch_optional(control)
        ).await.context("canonical backend termination deadline")??;
        if terminated == Some(false) {
            // pool.close() runs concurrently. The session can disappear after
            // pg_stat_activity selected it but before pg_terminate_backend
            // signals it. A failed signal alone does not prove it still owns
            // the lock; require a fresh, identity-matched absence check.
            let remains: bool = tokio::time::timeout(Duration::from_secs(1), sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2 AND datname=current_database() AND usename=current_user)"
            ).bind(backend).bind(backend_start).fetch_one(control)).await
                .context("canonical backend absence check deadline")??;
            ensure!(
                !remains,
                "canonical backend did not terminate; recovery remains uncertain"
            );
        }
        Ok::<_, anyhow::Error>(())
    };
    let (closed, terminated) = tokio::join!(closing, terminate);
    // Leave the independent control pool available to Drop's retry if either
    // part of cleanup failed. Closing it first would make retry ineffective.
    closed?;
    terminated?;
    let control_closed = tokio::time::timeout(Duration::from_secs(1), control.close())
        .await
        .context("canonical control connection close deadline");
    control_closed?;
    Ok(())
}

impl Drop for CanonicalWriteLease {
    fn drop(&mut self) {
        if !self.close_started {
            let pool = self.pool.clone();
            let control = self.control.clone();
            let session = self
                .writer
                .recovery_session
                .as_ref()
                .expect("owned session");
            let (backend, started) = (session.backend, session.backend_start);
            {
                self.cleanup_runtime.spawn(async move {
                    if let Err(error) = close_owned_session(&pool, &control, backend, started).await
                    {
                        tracing::warn!(%error, "dropped canonical session cleanup incomplete");
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Persister;

    async fn fence(pool: &PgPool) -> DurableConsumerFence {
        sqlx::query("INSERT INTO wrpc_inbox_streams(stream,updated_at_ms) VALUES('lease-test',0)")
            .execute(pool)
            .await
            .unwrap();
        DurableConsumerFence::claim(pool, "lease-test")
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn live_event_survives_scheduling_deadline_and_excludes_rest_between_commits(
        pool: PgPool,
    ) {
        let ordinary = PgPersister::new(pool.clone());
        let mut lease = CanonicalWriteLease::acquire_for_live_event(&ordinary)
            .await
            .unwrap();
        Arc::get_mut(&mut lease.writer)
            .unwrap()
            .recovery_session
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        let fixture: Vec<tn12_indexer_core::RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-dense-generic-32.json"
        ))
        .unwrap();
        let tx_body = fixture[0].clone();
        let hash = hex::decode(tx_body.accepting_block_hash.as_ref().unwrap()).unwrap();
        lease
            .run(|writer| async move {
                writer.persist_tx(&tx_body).await?;
                writer.revert_block(&hash).await?;
                // Even independently refreshed REST evidence cannot interleave here.
                assert!(ordinary.persist_tx(&tx_body).await.is_err());
                writer.persist_tx(&tx_body).await?;
                Ok(())
            })
            .await
            .unwrap();
        PgPersister::new(pool)
            .persist_tx(&fixture[0])
            .await
            .unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn live_event_read_fence_survives_writer_loss_until_journal_completion(pool: PgPool) {
        sqlx::query(
            "INSERT INTO indexer_state(key,value,updated_at_ms) VALUES('live-event-test','{}',0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let before: i64 =
            sqlx::query_scalar("SELECT generation FROM tn10_recovery_read_fence WHERE singleton")
                .fetch_one(&pool)
                .await
                .unwrap();
        let lease = CanonicalWriteLease::acquire_for_live_event(&PgPersister::new(pool.clone()))
            .await
            .unwrap();
        let writer = lease.writer();
        sqlx::query("INSERT INTO tn10_live_event_fences(intent_key) VALUES('live-event-test')")
            .execute(writer.pool())
            .await
            .unwrap();
        lease.close().await.unwrap();
        let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM tn10_live_event_fences")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(retained, 1);
        let fenced: i64 =
            sqlx::query_scalar("SELECT generation FROM tn10_recovery_read_fence WHERE singleton")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(fenced, before + 1);
        sqlx::query("DELETE FROM indexer_state WHERE key='live-event-test'")
            .execute(&pool)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM tn10_live_event_fences")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 0);
        let completed: i64 =
            sqlx::query_scalar("SELECT generation FROM tn10_recovery_read_fence WHERE singleton")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(completed, fenced + 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_excludes_interleaved_writer_across_commits(pool: PgPool) {
        let consumer = fence(&pool).await;
        let ordinary = PgPersister::new(pool.clone());
        // The original per-transaction lock allows another writer after commit.
        let mut first = pool.begin().await.unwrap();
        ordinary
            .acquire_persist_writer_lock(&mut first)
            .await
            .unwrap();
        first.commit().await.unwrap();
        let mut intervening = pool.begin().await.unwrap();
        ordinary
            .acquire_persist_writer_lock(&mut intervening)
            .await
            .unwrap();
        intervening.commit().await.unwrap();

        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        for _ in 0..2 {
            let mut tx = writer.pool.begin().await.unwrap();
            writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
            tx.commit().await.unwrap();
            let mut other = pool.begin().await.unwrap();
            assert!(ordinary
                .acquire_persist_writer_lock(&mut other)
                .await
                .is_err());
            other.rollback().await.unwrap();
        }
        lease.close().await.unwrap();
        assert!(writer.pool.begin().await.is_err());
        let mut other = pool.begin().await.unwrap();
        ordinary
            .acquire_persist_writer_lock(&mut other)
            .await
            .unwrap();
        other.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_connection_loss_never_reclaims_lease(pool: PgPool) {
        let consumer = fence(&pool).await;
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        let backend = writer.recovery_session.as_ref().unwrap().backend;
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(backend)
            .execute(&pool)
            .await
            .unwrap();
        // A newly established connection has neither the original PID nor nonce.
        // Pool health checks may first return a broken-socket error; every retry
        // must still fail before mutation, including after replacement.
        for _ in 0..3 {
            if let Ok(mut tx) = writer.pool.begin().await {
                assert!(writer.acquire_persist_writer_lock(&mut tx).await.is_err());
                let _ = tx.rollback().await;
            }
        }
        lease.close().await.unwrap();
        let ordinary = PgPersister::new(pool.clone());
        let mut tx = pool.begin().await.unwrap();
        ordinary.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_real_revert_and_replay_reenter_same_lock(pool: PgPool) {
        let consumer = fence(&pool).await;
        let fixture: Vec<tn12_indexer_core::RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-dense-generic-32.json"
        ))
        .unwrap();
        let original = PgPersister::new(pool.clone());
        original.persist_tx(&fixture[0]).await.unwrap();
        let hash = hex::decode(fixture[0].accepting_block_hash.as_ref().unwrap()).unwrap();
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        writer.revert_block(&hash).await.unwrap();
        assert!(original.persist_tx(&fixture[0]).await.is_err());
        writer.persist_tx(&fixture[0]).await.unwrap();
        lease.close().await.unwrap();
        original.persist_tx(&fixture[0]).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_drop_closes_escaped_writer(pool: PgPool) {
        let consumer = fence(&pool).await;
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        drop(lease);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !writer.pool.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(writer.pool.begin().await.is_err());
        let ordinary = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
        let mut tx = pool.begin().await.unwrap();
        PgPersister::set_persist_query_limits(&mut tx)
            .await
            .unwrap();
        ordinary.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_expired_operation_cannot_write(pool: PgPool) {
        let consumer = fence(&pool).await;
        let mut lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        Arc::get_mut(&mut lease.writer)
            .unwrap()
            .recovery_session
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        let writer = lease.writer();
        let mut tx = writer.pool.begin().await.unwrap();
        assert!(writer
            .acquire_persist_writer_lock(&mut tx)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        tx.rollback().await.unwrap();
        lease.close().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_run_timeout_releases_writer(pool: PgPool) {
        let consumer = fence(&pool).await;
        let mut lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        Arc::get_mut(&mut lease.writer)
            .unwrap()
            .recovery_session
            .as_mut()
            .unwrap()
            .expires = Instant::now() + Duration::from_millis(50);
        assert!(lease
            .run(|_| async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        let ordinary = PgPersister::new(pool.clone());
        let mut tx = pool.begin().await.unwrap();
        ordinary.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_timeout_during_sql_releases_the_server_lock(pool: PgPool) {
        let consumer = fence(&pool).await;
        let mut lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        Arc::get_mut(&mut lease.writer)
            .unwrap()
            .recovery_session
            .as_mut()
            .unwrap()
            .expires = Instant::now() + Duration::from_millis(100);
        assert!(lease
            .run(|writer| async move {
                let mut tx = writer.pool.begin().await?;
                PgPersister::set_persist_query_limits(&mut tx).await?;
                writer.acquire_persist_writer_lock(&mut tx).await?;
                sqlx::query("SELECT pg_sleep(5)").execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(())
            })
            .await
            .is_err());
        let ordinary = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        ordinary.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_active_sql_cleanup_survives_closed_source_pool(pool: PgPool) {
        let consumer = fence(&pool).await;
        let probe = PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let mut lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        Arc::get_mut(&mut lease.writer)
            .unwrap()
            .recovery_session
            .as_mut()
            .unwrap()
            .expires = Instant::now() + Duration::from_millis(100);
        pool.close().await;
        assert!(lease
            .run(|writer| async move {
                let mut tx = writer.pool.begin().await?;
                PgPersister::set_persist_query_limits(&mut tx).await?;
                writer.acquire_persist_writer_lock(&mut tx).await?;
                sqlx::query("SELECT pg_sleep(5)").execute(&mut *tx).await?;
                tx.commit().await?;
                Ok(())
            })
            .await
            .is_err());
        let mut tx = probe.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        PgPersister::new(probe.clone())
            .with_bounded_writer_lock_wait()
            .acquire_persist_writer_lock(&mut tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        probe.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_drop_on_plain_thread_releases_lock(pool: PgPool) {
        let consumer = fence(&pool).await;
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        std::thread::spawn(move || drop(lease)).join().unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !writer.pool.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        PgPersister::new(pool.clone())
            .with_bounded_writer_lock_wait()
            .acquire_persist_writer_lock(&mut tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_cancel_during_close_finishes_cleanup(pool: PgPool) {
        let consumer = fence(&pool).await;
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        let control = lease.control.clone();
        let held_writer = writer.pool.acquire().await.unwrap();
        let held_control = control.acquire().await.unwrap();
        let closing = tokio::spawn(lease.close());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !writer.pool.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        closing.abort();
        assert!(closing.await.unwrap_err().is_cancelled());
        drop(held_writer);
        drop(held_control);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        PgPersister::new(pool.clone())
            .with_bounded_writer_lock_wait()
            .acquire_persist_writer_lock(&mut tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_failed_close_retries_with_open_control_pool(pool: PgPool) {
        let consumer = fence(&pool).await;
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer)
            .await
            .unwrap();
        let writer = lease.writer();
        let control = lease.control.clone();
        let held_writer = writer.pool.acquire().await.unwrap();
        let held_control = control.acquire().await.unwrap();
        assert!(lease.close().await.is_err());
        assert!(!control.is_closed());
        drop(held_writer);
        drop(held_control);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !control.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='350ms'")
            .execute(&mut *tx)
            .await
            .unwrap();
        PgPersister::new(pool.clone())
            .with_bounded_writer_lock_wait()
            .acquire_persist_writer_lock(&mut tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn recovery_session_genesis_normalization_checks_deadline_and_generation(pool: PgPool) {
        let consumer = fence(&pool).await;
        let lease = CanonicalWriteLease::acquire(&pool, "testnet-10", consumer.clone())
            .await
            .unwrap();
        sqlx::query("UPDATE wrpc_inbox_streams SET consumer_generation=consumer_generation+1 WHERE stream='lease-test'").execute(&pool).await.unwrap();
        assert!(lease
            .writer()
            .normalize_replayed_genesis(100, 10)
            .await
            .unwrap_err()
            .to_string()
            .contains("stale"));
        lease.close().await.unwrap();
        let current = DurableConsumerFence::claim(&pool, "lease-test")
            .await
            .unwrap();
        let mut lease = CanonicalWriteLease::acquire(&pool, "testnet-10", current)
            .await
            .unwrap();
        Arc::get_mut(&mut lease.writer)
            .unwrap()
            .recovery_session
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        assert!(lease
            .writer()
            .normalize_replayed_genesis(100, 10)
            .await
            .unwrap_err()
            .to_string()
            .contains("deadline"));
        lease.close().await.unwrap();
    }
}
