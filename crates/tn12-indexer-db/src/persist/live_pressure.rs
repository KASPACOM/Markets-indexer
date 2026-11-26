//! Cooperative replay backpressure. The existing advisory writer lock remains
//! the sole write serialization mechanism. A short database-clock lease asks
//! historical writers to yield before acquiring that lock during a live burst.
use super::{PgPersister, TransientPersistError};
use anyhow::{Context, Result};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::{Duration, Instant};
use tn12_indexer_core::RestTransaction;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum WriterPriority {
    #[default]
    Disabled,
    Live,
    History,
}

pub(super) fn configured(setting: Option<String>, role: WriterPriority) -> Result<WriterPriority> {
    match setting.as_deref() {
        None | Some("0") => Ok(WriterPriority::Disabled),
        Some("1") => Ok(role),
        _ => anyhow::bail!("TN12_WRITER_LIVE_PRIORITY must be 0 or 1"),
    }
}

fn congested(txs: &[RestTransaction], now_ms: u64) -> bool {
    let accepted = txs.iter().filter(|tx| tx.is_accepted).collect::<Vec<_>>();
    accepted.len() >= 16
        || accepted.iter().any(|tx| {
            tx.accepting_block_time
                .is_some_and(|at| now_ms.saturating_sub(at) >= 1_000)
        })
}

pub(super) struct LivePressure {
    pool: PgPool,
    key: String,
    owner: String,
    refreshed: Instant,
}

impl PgPersister {
    fn pressure_key(&self) -> String {
        format!("live_writer_pressure:{}:", self.network_id)
    }

    pub(super) async fn start_live_pressure(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Option<LivePressure>> {
        if self.writer_priority != WriterPriority::Live
            || !congested(txs, chrono::Utc::now().timestamp_millis().max(0) as u64)
        {
            return Ok(None);
        }
        let prefix = self.pressure_key();
        let (key, owner): (String, String) = tokio::time::timeout(Duration::from_secs(1), sqlx::query_as(
            "WITH expired AS (DELETE FROM indexer_state WHERE starts_with(key,$1) AND (value->>'expires_at_ms')::bigint<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint), lease AS (SELECT txid_current()::text AS owner) INSERT INTO indexer_state(key,value,updated_at_ms) SELECT $1||owner,jsonb_build_object('owner',owner,'expires_at_ms',floor(extract(epoch FROM clock_timestamp())*1000)::bigint+2000),floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM lease RETURNING key,value->>'owner'"
        ).bind(&prefix).fetch_one(&self.pool)).await.context("live pressure declaration deadline")??;
        tracing::info!(
            transactions = txs.len(),
            lease_ms = 2000,
            "live burst requested replay backpressure"
        );
        Ok(Some(LivePressure {
            pool: self.pool.clone(),
            key,
            owner,
            refreshed: Instant::now(),
        }))
    }

    pub(super) async fn wait_for_live_pressure(
        &self,
        conn: &mut Transaction<'_, Postgres>,
    ) -> Result<()> {
        if self.writer_priority != WriterPriority::History {
            return Ok(());
        }
        let started = Instant::now();
        let key = self.pressure_key();
        loop {
            let active: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM indexer_state WHERE starts_with(key,$1) AND (value->>'expires_at_ms')::bigint > floor(extract(epoch FROM clock_timestamp())*1000)::bigint)")
                .bind(&key).fetch_one(&mut **conn).await?;
            if !active {
                break;
            }
            if started.elapsed() >= Duration::from_secs(5) {
                tracing::info!(
                    wait_ms = started.elapsed().as_millis() as u64,
                    "replay yielding its current window to live pressure"
                );
                return Err(TransientPersistError::writer_lock_busy(
                    "live pressure; retain replay window",
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if started.elapsed() >= Duration::from_millis(25) {
            tracing::info!(
                wait_ms = started.elapsed().as_millis() as u64,
                "replay resumed after live pressure"
            );
        }
        Ok(())
    }
}

impl LivePressure {
    pub(super) async fn refresh(&mut self) -> Result<()> {
        if self.refreshed.elapsed() < Duration::from_millis(500) {
            return Ok(());
        }
        let changed = tokio::time::timeout(Duration::from_secs(1), sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,jsonb_build_object('owner',$2::text,'expires_at_ms',floor(extract(epoch FROM clock_timestamp())*1000)::bigint+2000),floor(extract(epoch FROM clock_timestamp())*1000)::bigint) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at_ms=EXCLUDED.updated_at_ms WHERE indexer_state.value->>'owner'=$2")
            .bind(&self.key).bind(&self.owner).execute(&self.pool)).await.context("live pressure refresh deadline")??;
        anyhow::ensure!(
            changed.rows_affected() == 1,
            "live pressure lease replaced; retain write intent"
        );
        self.refreshed = Instant::now();
        Ok(())
    }

    pub(super) async fn finish(self) {
        // Failure or cancellation leaves only a two-second lease. Clearing an
        // older lease must never clear another live writer's newer declaration.
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            sqlx::query("DELETE FROM indexer_state WHERE key=$1 AND value->>'owner'=$2")
                .bind(&self.key)
                .bind(&self.owner)
                .execute(&self.pool),
        )
        .await;
        if !matches!(result, Ok(Ok(_))) {
            tracing::warn!("live pressure release failed; database-clock lease will expire");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::PERSIST_WRITER_LOCK_KEY;
    fn live(pool: &PgPool) -> PgPersister {
        let mut writer = PgPersister::new(pool.clone());
        writer.writer_priority = WriterPriority::Live;
        writer
    }
    fn old_tx() -> Vec<RestTransaction> {
        vec![RestTransaction {
            is_accepted: true,
            accepting_block_time: Some(1),
            ..Default::default()
        }]
    }
    #[test]
    fn pressure_is_explicit_and_only_declared_for_congested_live_work() {
        assert!(configured(Some("true".into()), WriterPriority::Live).is_err());
        assert!(configured(None, WriterPriority::Live).unwrap() == WriterPriority::Disabled);
        let fresh = RestTransaction {
            is_accepted: true,
            accepting_block_time: Some(1000),
            ..Default::default()
        };
        assert!(!congested(&[fresh.clone()], 1500));
        assert!(congested(&[fresh.clone()], 2000));
        assert!(congested(&vec![fresh; 16], 1000));
        assert!(!congested(&vec![RestTransaction::default(); 16], 5000));
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn replay_waits_without_holding_writer_lock_and_resumes_after_release(pool: PgPool) {
        let live = live(&pool);
        let pressure = live.start_live_pressure(&old_tx()).await.unwrap().unwrap();
        let mut history = PgPersister::new(pool.clone());
        history.writer_priority = WriterPriority::History;
        let mut tx = pool.begin().await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(100),
            history.acquire_persist_writer_lock(&mut tx)
        )
        .await
        .is_err());
        let mut probe = pool.begin().await.unwrap();
        let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(PERSIST_WRITER_LOCK_KEY)
            .fetch_one(&mut *probe)
            .await
            .unwrap();
        assert!(free);
        probe.rollback().await.unwrap();
        pressure.finish().await;
        history.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn abandoned_lease_expires_and_old_owner_cannot_clear_replacement(pool: PgPool) {
        let live = live(&pool);
        let old = live.start_live_pressure(&old_tx()).await.unwrap().unwrap();
        let newer = live.start_live_pressure(&old_tx()).await.unwrap().unwrap();
        assert_ne!(old.owner, newer.owner);
        assert_ne!(old.key, newer.key);
        old.finish().await;
        let owner: String =
            sqlx::query_scalar("SELECT value->>'owner' FROM indexer_state WHERE key=$1")
                .bind(&newer.key)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(owner, newer.owner);
        let key = newer.key.clone();
        drop(newer);
        sqlx::query("UPDATE indexer_state SET value=jsonb_set(value,'{expires_at_ms}','0'::jsonb) WHERE key=$1").bind(key).execute(&pool).await.unwrap();
        let mut history = PgPersister::new(pool.clone());
        history.writer_priority = WriterPriority::History;
        let mut tx = pool.begin().await.unwrap();
        history.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn overlapping_batches_keep_independent_pressure_and_expired_active_lease_can_refresh(
        pool: PgPool,
    ) {
        let live = live(&pool);
        let mut first = live.start_live_pressure(&old_tx()).await.unwrap().unwrap();
        let second = live.start_live_pressure(&old_tx()).await.unwrap().unwrap();
        second.finish().await;
        let mut history = PgPersister::new(pool.clone());
        history.writer_priority = WriterPriority::History;
        let mut tx = pool.begin().await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(100),
            history.acquire_persist_writer_lock(&mut tx)
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        sqlx::query("UPDATE indexer_state SET value=jsonb_set(value,'{expires_at_ms}','0'::jsonb) WHERE key=$1").bind(&first.key).execute(&pool).await.unwrap();
        let third = live.start_live_pressure(&old_tx()).await.unwrap().unwrap();
        let old_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM indexer_state WHERE key=$1)")
                .bind(&first.key)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!old_exists);
        first.refreshed = Instant::now() - Duration::from_secs(1);
        first.refresh().await.unwrap();
        third.finish().await;
        let mut tx = pool.begin().await.unwrap();
        assert!(tokio::time::timeout(
            Duration::from_millis(100),
            history.acquire_persist_writer_lock(&mut tx)
        )
        .await
        .is_err());
        first.finish().await;
        history.acquire_persist_writer_lock(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();
    }
    #[tokio::test]
    async fn both_runtime_constructors_validate_priority_and_default_disabled() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for value in [None, Some("0"), Some("1")] {
            let settings = |name: &str| {
                if name == "TN12_WRITER_LIVE_PRIORITY" {
                    value.map(str::to_owned)
                } else {
                    None
                }
            };
            let live =
                PgPersister::for_wrpc_settings(pool.clone(), "testnet-10", settings).unwrap();
            let history = PgPersister::for_tip_follow_settings(pool.clone(), settings).unwrap();
            assert!(
                live.writer_priority
                    == if value == Some("1") {
                        WriterPriority::Live
                    } else {
                        WriterPriority::Disabled
                    }
            );
            assert!(
                history.writer_priority
                    == if value == Some("1") {
                        WriterPriority::History
                    } else {
                        WriterPriority::Disabled
                    }
            );
        }
        let invalid = |name: &str| (name == "TN12_WRITER_LIVE_PRIORITY").then(|| "bad".to_string());
        assert!(PgPersister::for_wrpc_settings(pool.clone(), "testnet-10", invalid).is_err());
        assert!(PgPersister::for_tip_follow_settings(pool, invalid).is_err());
    }
}
