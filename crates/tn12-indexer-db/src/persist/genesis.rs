//! Durable settled-replay phases and incremental earliest canonical output proof.
//! Every scan page and candidate correction shares writer serialization with reorgs.
use super::PgPersister;
use anyhow::{Context, Result};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::time::{Duration, Instant};

pub mod unverified;

const BUDGET: Duration = Duration::from_millis(350);

// EXISTS lets the planner prefer a sequential scan because it estimates that
// almost every pair of version columns differs. An ordered scalar lookup keeps
// the empty/past-the-last-pending case on the partial pending index too.
const HAS_PENDING_RECONCILIATION: &str = "SELECT (SELECT covenant_id FROM covenant_genesis_progress WHERE NOT baseline_complete OR applied_version<>version ORDER BY covenant_id LIMIT 1) IS NOT NULL OR EXISTS(SELECT 1 FROM settled_repair_members m JOIN covenant_genesis_progress p USING(covenant_id) WHERE m.cursor_key=$1 AND m.normalized_version IS DISTINCT FROM p.version)";

#[cfg(test)]
#[path = "genesis_pending_tests.rs"]
mod pending_tests;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct RepairJob {
    pub window_start: i64,
    pub epoch: i64,
    pub width: i32,
    pub phase: String,
    pub batch_size: i32,
    pub discovery_after: Option<Vec<u8>>,
    pub discovery_action_id: i64,
    pub consecutive_failures: i32,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub blocker: Option<serde_json::Value>,
    pub next_retry_at_ms: i64,
    pub updated_at_ms: i64,
    pub scanned_outputs: i64,
    pub normalized_covenants: i64,
    pub normalized_actions: i64,
    pub last_step_ms: i64,
    pub last_lock_held_ms: i64,
    #[sqlx(default)]
    pub remaining_families: i64,
    #[sqlx(default)]
    pub identity_corrections: i64,
    #[sqlx(default)]
    pub identity_blocked_families: i64,
}

pub async fn read_job(pool: &PgPool, key: &str) -> Result<Option<RepairJob>> {
    Ok(
        sqlx::query_as("SELECT j.*, (SELECT count(*) FROM (SELECT covenant_id FROM covenant_genesis_progress WHERE NOT baseline_complete OR applied_version<>version UNION SELECT m.covenant_id FROM settled_repair_members m JOIN covenant_genesis_progress p USING(covenant_id) WHERE m.cursor_key=j.cursor_key AND m.normalized_version IS DISTINCT FROM p.version) pending) AS remaining_families,(SELECT count(*) FROM covenant_identity_corrections) AS identity_corrections,(SELECT count(*) FROM covenant_genesis_progress WHERE blocker IS NOT NULL) AS identity_blocked_families FROM settled_repair_jobs j WHERE cursor_key=$1")
            .bind(key)
            .fetch_optional(pool)
            .await?,
    )
}

/// Cheap scheduling lookup: do not count the complete inventory on each slice.
pub async fn retry_pending(pool: &PgPool, key: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT next_retry_at_ms FROM settled_repair_jobs WHERE cursor_key=$1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await?
    .is_some_and(|retry| retry > now()))
}

impl PgPersister {
    pub fn for_genesis_repair(pool: PgPool) -> Self {
        let mut writer = Self::new(pool);
        writer.writer_priority = super::live_pressure::WriterPriority::History;
        writer
    }

    async fn begin_genesis(&self) -> Result<Transaction<'static, Postgres>> {
        let mut tx = self.pool.begin().await?;
        Self::set_persist_query_limits(&mut tx).await?;
        self.acquire_persist_writer_lock(&mut tx).await?;
        sqlx::query("SET LOCAL statement_timeout='250ms'")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Keep a pending window even if the rolling sweep moved beyond it.
    pub async fn prepare_settled_repair(
        &self,
        key: &str,
        start: u64,
        width: u64,
    ) -> Result<RepairJob> {
        anyhow::ensure!((1..=100).contains(&width), "replay width must be 1..=100");
        let start = i64::try_from(start)?;
        start
            .checked_add(width as i64)
            .context("replay window overflow")?;
        let mut tx = self.begin_genesis().await?;
        let result = tokio::time::timeout(BUDGET, async {
        sqlx::query("DELETE FROM settled_repair_members WHERE cursor_key=$1 AND EXISTS (SELECT 1 FROM settled_repair_jobs WHERE cursor_key=$1 AND phase='complete')")
            .bind(key).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO settled_repair_jobs(cursor_key,window_start,width,updated_at_ms) VALUES($1,$2,$3,$4) ON CONFLICT(cursor_key) DO UPDATE SET window_start=EXCLUDED.window_start,width=EXCLUDED.width,epoch=settled_repair_jobs.epoch+1,phase='replay',discovery_after=NULL,discovery_action_id=0,consecutive_failures=0,last_error=NULL,next_retry_at_ms=0,updated_at_ms=EXCLUDED.updated_at_ms,scanned_outputs=0,normalized_covenants=0,normalized_actions=0 WHERE settled_repair_jobs.phase='complete'")
            .bind(key).bind(start).bind(width as i32).bind(now()).execute(&mut *tx).await?;
        let job = sqlx::query_as("SELECT * FROM settled_repair_jobs WHERE cursor_key=$1")
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;
        Ok(job)
        }).await;
        finish_transaction(tx, result).await
    }

    /// A reorg during replay changes the epoch; never acknowledge that stale replay.
    pub async fn acknowledge_settled_replay(&self, key: &str, epoch: i64) -> Result<bool> {
        let mut tx = self.begin_genesis().await?;
        let result = tokio::time::timeout(BUDGET, async {
            let changed = sqlx::query("UPDATE settled_repair_jobs SET phase='discover',discovery_after=NULL,discovery_action_id=0,consecutive_failures=0,last_error=NULL,next_retry_at_ms=0,updated_at_ms=$3 WHERE cursor_key=$1 AND epoch=$2 AND phase='replay'")
                .bind(key).bind(epoch).bind(now()).execute(&mut *tx).await?.rows_affected();
            Ok(changed == 1)
        }).await;
        finish_transaction(tx, result).await
    }

    /// Discover in a read transaction without the writer lock, then validate the
    /// epoch and commit a bounded membership page under writer serialization.
    pub async fn discover_settled_members(&self, key: &str) -> Result<bool> {
        // Scheduling needs only the durable job row. The health-report query
        // also counts the global inventory, consuming the 250-ms replay slice
        // even when discovery is already finished.
        let job: RepairJob = sqlx::query_as("SELECT * FROM settled_repair_jobs WHERE cursor_key=$1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .context("missing settled job")?;
        if job.phase != "discover" {
            return Ok(job.phase == "reconcile");
        }
        let mut read = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *read)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *read)
            .await?;
        let rows = sqlx::query("WITH window_blocks AS MATERIALIZED (SELECT hash FROM blocks WHERE blue_score>=$1 AND blue_score<$1+$3::bigint AND is_chain_block AND ($2::bytea IS NULL OR hash>=$2)) SELECT b.hash,a.id,a.covenant_id FROM window_blocks b CROSS JOIN LATERAL (SELECT id,covenant_id FROM covenant_actions WHERE block_hash=b.hash AND action IN ('deploy','continuation') AND id>CASE WHEN b.hash=$2 THEN $4 ELSE 0 END ORDER BY id LIMIT 512) a ORDER BY b.hash,a.id LIMIT 512")
            .bind(job.window_start).bind(&job.discovery_after).bind(i64::from(job.width)).bind(job.discovery_action_id).fetch_all(&mut *read).await?;
        let ids: Vec<Vec<u8>> = rows
            .iter()
            .map(|r| r.get::<Vec<u8>, _>("covenant_id"))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let last_block = rows
            .last()
            .map(|r| r.get::<Vec<u8>, _>("hash"))
            .or(job.discovery_after.clone());
        let last_id = rows
            .last()
            .map(|r| r.get::<i64, _>("id"))
            .unwrap_or(job.discovery_action_id);
        read.commit().await?;
        let mut tx = self.begin_genesis().await?;
        let result=tokio::time::timeout(BUDGET,async {
            let matches:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM settled_repair_jobs WHERE cursor_key=$1 AND epoch=$2 AND phase='discover' AND discovery_after IS NOT DISTINCT FROM $3::bytea AND discovery_action_id=$4)")
                .bind(key).bind(job.epoch).bind(&job.discovery_after).bind(job.discovery_action_id).fetch_one(&mut *tx).await?;
            if !matches { return Ok(false); }
            sqlx::query("INSERT INTO covenant_genesis_progress(covenant_id) SELECT unnest($1::bytea[]) ON CONFLICT DO NOTHING").bind(&ids).execute(&mut *tx).await?;
            // Retain old members: a reorg can remove their last action in this window.
            sqlx::query("INSERT INTO settled_repair_members(cursor_key,covenant_id) SELECT $1,unnest($2::bytea[]) ON CONFLICT DO NOTHING").bind(key).bind(&ids).execute(&mut *tx).await?;
            sqlx::query("UPDATE settled_repair_jobs SET discovery_after=$2,discovery_action_id=$5,phase=CASE WHEN $3 THEN 'reconcile' ELSE 'discover' END,updated_at_ms=$4,consecutive_failures=0,last_error=NULL,next_retry_at_ms=0 WHERE cursor_key=$1")
                .bind(key).bind(last_block).bind(rows.len()<512).bind(now()).bind(last_id).execute(&mut *tx).await?;
            Ok(rows.len()<512)
        }).await;
        finish_transaction(tx, result).await
    }

    /// One page or one verified family per commit. Return true only after cursor commit.
    pub async fn step_settled_repair(&self, key: &str, next: u64, tip: u64) -> Result<bool> {
        let started = Instant::now();
        let mut tx = self.begin_genesis().await?;
        let held = Instant::now();
        let body = async {
            let job: RepairJob =
                sqlx::query_as("SELECT * FROM settled_repair_jobs WHERE cursor_key=$1 FOR UPDATE")
                    .bind(key)
                    .fetch_one(&mut *tx)
                    .await?;
            anyhow::ensure!(
                job.phase == "reconcile",
                "replay invalidated; retry canonical window"
            );
            let mut member: Option<Vec<u8>> = sqlx::query_scalar("SELECT covenant_id FROM covenant_genesis_progress WHERE (NOT baseline_complete OR applied_version<>version) AND retry_at_ms<=$1 ORDER BY covenant_id LIMIT 1")
                .bind(now()).fetch_optional(&mut *tx).await?;
            if member.is_none() {
                member=sqlx::query_scalar("SELECT m.covenant_id FROM settled_repair_members m JOIN covenant_genesis_progress p USING(covenant_id) WHERE m.cursor_key=$1 AND m.normalized_version IS DISTINCT FROM p.version AND p.retry_at_ms<=$2 ORDER BY m.covenant_id LIMIT 1")
                    .bind(key).bind(now()).fetch_optional(&mut *tx).await?;
            }
            if let Some(cid) = member {
                let (scanned, complete) = scan_page(&mut tx, &cid, job.batch_size).await?;
                let (covenants, actions) = if complete {
                    let result = Self::apply_genesis_candidate(&mut tx, &cid).await?;
                    sqlx::query("UPDATE settled_repair_members m SET normalized_version=p.version FROM covenant_genesis_progress p WHERE m.cursor_key=$1 AND m.covenant_id=$2 AND p.covenant_id=m.covenant_id")
                        .bind(key).bind(&cid).execute(&mut *tx).await?;
                    result
                } else {
                    (0, 0)
                };
                // A budget failure halves the scan page. Periodically restore
                // capacity after a fast full page so a one-row page cannot
                // persist for the rest of a large settled window.
                let raise_batch = !complete
                    && scanned == i64::from(job.batch_size)
                    && job.batch_size < 64
                    && (job.attempts + 1) % 8 == 0
                    && held.elapsed() < BUDGET / 2;
                sqlx::query("UPDATE settled_repair_jobs SET scanned_outputs=scanned_outputs+$2,normalized_covenants=normalized_covenants+$3,normalized_actions=normalized_actions+$4,consecutive_failures=0,last_error=NULL,next_retry_at_ms=0,updated_at_ms=$5,attempts=attempts+1,last_step_ms=$6,last_lock_held_ms=$7,batch_size=CASE WHEN $8 THEN LEAST(batch_size*2,64) ELSE batch_size END WHERE cursor_key=$1")
                    .bind(key).bind(scanned).bind(covenants as i64).bind(actions as i64).bind(now())
                    .bind(started.elapsed().as_millis() as i64).bind(held.elapsed().as_millis() as i64)
                    .bind(raise_batch)
                    .execute(&mut *tx).await?;
                Ok(false)
            } else {
                // A delayed blocked family still prevents cursor completion.
                let pending: bool = sqlx::query_scalar(HAS_PENDING_RECONCILIATION)
                    .bind(key).fetch_one(&mut *tx).await?;
                if pending {
                    sqlx::query("UPDATE settled_repair_jobs SET next_retry_at_ms=COALESCE((SELECT min(retry_at_ms) FROM covenant_genesis_progress WHERE blocker IS NOT NULL AND retry_at_ms>$2),$2+1000) WHERE cursor_key=$1")
                        .bind(key).bind(now()).execute(&mut *tx).await?;
                    return Ok(false);
                }
                // Cursor and completion commit together. A crash cannot double count.
                let width: i32 =
                    sqlx::query_scalar("SELECT width FROM settled_repair_jobs WHERE cursor_key=$1")
                        .bind(key)
                        .fetch_one(&mut *tx)
                        .await?;
                let changed = sqlx::query(r#"INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,$3)
                    ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value || jsonb_build_object(
                      'completed_windows',coalesce((indexer_state.value->>'completed_windows')::bigint,0)+1,
                      'completed_scores',coalesce((indexer_state.value->>'completed_scores')::bigint,0)+$4::bigint),updated_at_ms=EXCLUDED.updated_at_ms
                    WHERE (NOT indexer_state.value ? 'completed_windows' AND NOT indexer_state.value ? 'completed_scores')
                    OR (jsonb_typeof(indexer_state.value->'completed_windows')='number' AND jsonb_typeof(indexer_state.value->'completed_scores')='number'
                        AND (indexer_state.value->>'completed_windows')::bigint>=0 AND (indexer_state.value->>'completed_scores')::bigint>=0)"#)
                    .bind(format!("{key}:settled_recheck"))
                    .bind(serde_json::json!({"last_completed_blue_score":job.window_start,"next_blue_score":next,"source_tip_blue_score":tip,"completed_windows":1,"completed_scores":width}))
                    .bind(now()).bind(i64::from(width)).execute(&mut *tx).await?.rows_affected();
                anyhow::ensure!(
                    changed == 1,
                    "invalid settled replay work counters; cursor retained"
                );
                // Deferred jobs retain their own completion record. Only the
                // forward lane changes its scheduling cursor.
                sqlx::query("INSERT INTO settled_history_schedule(cursor_key,next_window) SELECT $1,$2 WHERE NOT EXISTS(SELECT 1 FROM settled_history_unverified WHERE job_key=$1) ON CONFLICT(cursor_key) DO UPDATE SET next_window=EXCLUDED.next_window")
                    .bind(key).bind(i64::try_from(next)?).execute(&mut *tx).await?;
                sqlx::query("UPDATE settled_repair_jobs SET phase='complete',blocker=NULL,updated_at_ms=$2,last_error=NULL,next_retry_at_ms=0,consecutive_failures=0 WHERE cursor_key=$1")
                    .bind(key).bind(now()).execute(&mut *tx).await?;
                Ok(true)
            }
        };
        let result: Result<bool> = match tokio::time::timeout(BUDGET, body).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!(
                "genesis reconciliation exceeded 350-ms writer budget"
            )),
        };
        match result {
            Ok(done) => {
                tx.commit().await?;
                Ok(done)
            }
            Err(error) => {
                tx.rollback()
                    .await
                    .context("rollback genesis reconciliation")?;
                Err(error)
            }
        }
    }

    pub async fn retain_settled_error(&self, key: &str, error: &anyhow::Error) -> Result<()> {
        self.retain_settled_error_for_stage(key, error, false).await
    }

    pub async fn retain_settled_reconciliation_error(
        &self,
        key: &str,
        error: &anyhow::Error,
    ) -> Result<()> {
        self.retain_settled_error_for_stage(key, error, true).await
    }

    async fn retain_settled_error_for_stage(
        &self,
        key: &str,
        error: &anyhow::Error,
        reconciliation_step_failed: bool,
    ) -> Result<()> {
        let message = format!("{error:#}");
        // A replaced worker must not overwrite the active owner's error or
        // retry state after its replay write was fenced.
        if self.settled_recheck_fence.is_some() {
            let mut tx = self.begin_genesis().await?;
            if let Some(blocked) = error.downcast_ref::<super::identity::GenesisIdentityBlocked>() {
                sqlx::query("UPDATE covenant_genesis_progress SET blocker=$2,retry_at_ms=$3 WHERE covenant_id=$1 AND version=$4")
                    .bind(hex::decode(&blocked.family_id)?).bind(blocked.details()).bind(now()+60_000).bind(blocked.version).execute(&mut *tx).await?;
                sqlx::query("UPDATE settled_repair_jobs SET blocker=$2,last_error=$3,attempts=attempts+1,consecutive_failures=least(consecutive_failures+1,30),next_retry_at_ms=0 WHERE cursor_key=$1 AND phase<>'complete'")
                    .bind(key).bind(blocked.details()).bind(&message).execute(&mut *tx).await?;
            } else {
                let budget = reconciliation_step_failed
                    && (message.contains("timeout") || message.contains("budget"));
                sqlx::query("UPDATE settled_repair_jobs SET last_error=$2,consecutive_failures=least(consecutive_failures+1,30),attempts=attempts+1,next_retry_at_ms=$3+least(60000,1000*(1::bigint<<least(consecutive_failures,6))),batch_size=CASE WHEN $4 AND phase='reconcile' THEN greatest(1,batch_size/2) ELSE batch_size END WHERE cursor_key=$1 AND phase<>'complete'")
                    .bind(key).bind(message.chars().take(1024).collect::<String>()).bind(now()).bind(budget)
                    .execute(&mut *tx).await?;
            }
            tx.commit().await?;
            return Ok(());
        }
        if let Some(blocked) = error.downcast_ref::<super::identity::GenesisIdentityBlocked>() {
            let mut tx = self.pool.begin().await?;
            sqlx::query("UPDATE covenant_genesis_progress SET blocker=$2,retry_at_ms=$3 WHERE covenant_id=$1 AND version=$4")
                .bind(hex::decode(&blocked.family_id)?).bind(blocked.details()).bind(now()+60_000).bind(blocked.version).execute(&mut *tx).await?;
            sqlx::query("UPDATE settled_repair_jobs SET blocker=$2,last_error=$3,attempts=attempts+1,consecutive_failures=least(consecutive_failures+1,30),next_retry_at_ms=0 WHERE cursor_key=$1 AND phase<>'complete'")
                .bind(key).bind(blocked.details()).bind(&message).execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(());
        }
        let budget = reconciliation_step_failed
            && (message.contains("timeout") || message.contains("budget"));
        sqlx::query("UPDATE settled_repair_jobs SET last_error=$2,consecutive_failures=least(consecutive_failures+1,30),attempts=attempts+1,next_retry_at_ms=$3+least(60000,1000*(1::bigint<<least(consecutive_failures,6))),batch_size=CASE WHEN $4 AND phase='reconcile' THEN greatest(1,batch_size/2) ELSE batch_size END WHERE cursor_key=$1 AND phase<>'complete'")
            .bind(key).bind(message.chars().take(1024).collect::<String>()).bind(now()).bind(budget)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub(super) async fn normalize_genesis_window(
        &self,
        start: u64,
        width: u64,
    ) -> Result<(u64, u64)> {
        anyhow::ensure!((1..=100).contains(&width), "replay width must be 1..=100");
        let mut tx = self.begin_genesis().await?;
        let ids: Vec<Vec<u8>> = sqlx::query_scalar("SELECT DISTINCT a.covenant_id FROM blocks b JOIN covenant_actions a ON a.block_hash=b.hash WHERE b.blue_score>=$1 AND b.blue_score<$2 AND b.is_chain_block AND a.action IN ('deploy','continuation')")
            .bind(i64::try_from(start)?).bind(i64::try_from(start.checked_add(width).context("window overflow")?)?).fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let mut result = (0, 0);
        for cid in ids {
            loop {
                let mut tx = self.begin_genesis().await?;
                let step = async {
                    sqlx::query("INSERT INTO covenant_genesis_progress(covenant_id) VALUES($1) ON CONFLICT DO NOTHING").bind(&cid).execute(&mut *tx).await?;
                    let (_, complete) = scan_page(&mut tx, &cid, 512).await?;
                    let changed = if complete {
                        Self::apply_genesis_candidate(&mut tx, &cid).await?
                    } else {
                        (0, 0)
                    };
                    Ok::<_, anyhow::Error>((complete, changed))
                };
                let outcome = tokio::time::timeout(BUDGET, step).await;
                match outcome {
                    Ok(Ok((done, changed))) => {
                        tx.commit().await?;
                        result.0 += changed.0;
                        result.1 += changed.1;
                        if done {
                            break;
                        }
                    }
                    other => {
                        tx.rollback().await?;
                        return Err(match other {
                            Ok(Err(e)) => e,
                            _ => anyhow::anyhow!("genesis reconciliation exceeded writer budget"),
                        });
                    }
                }
                tokio::task::yield_now().await;
            }
        }
        Ok(result)
    }
}

async fn scan_page(
    tx: &mut Transaction<'_, Postgres>,
    cid: &[u8],
    batch: i32,
) -> Result<(i64, bool)> {
    let state = sqlx::query("SELECT scan_txid,scan_vout,baseline_complete FROM covenant_genesis_progress WHERE covenant_id=$1 FOR UPDATE")
        .bind(cid).fetch_one(&mut **tx).await?;
    if state.get::<bool, _>("baseline_complete") {
        return Ok((0, true));
    }
    let after: Option<Vec<u8>> = state.get("scan_txid");
    let after_vout: Option<i32> = state.get("scan_vout");
    // Separate first-page and continuation predicates so both use the ordered index.
    let predicate = if after.is_some() {
        "AND (u.txid,u.vout)>($3,$4)"
    } else {
        "AND $3::bytea IS NULL AND $4::integer IS NULL"
    };
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("WITH page AS MATERIALIZED (SELECT txid,vout,created_block FROM covenant_utxos u WHERE covenant_id=$1 {predicate} ORDER BY txid,vout LIMIT $2) SELECT p.*,b.blue_score,b.timestamp_ms,b.is_chain_block FROM page p LEFT JOIN blocks b ON b.hash=p.created_block ORDER BY p.txid,p.vout")))
        .bind(cid).bind(i64::from(batch)).bind(after).bind(after_vout).fetch_all(&mut **tx).await?;
    let best = rows
        .iter()
        .filter(|r| r.get::<Option<bool>, _>("is_chain_block") == Some(true))
        .min_by_key(|r| {
            (
                r.get::<i64, _>("blue_score"),
                r.get::<i32, _>("vout"),
                r.get::<Vec<u8>, _>("txid"),
            )
        });
    if let Some(best) = best {
        sqlx::query("SELECT tn10_genesis_offer($1,$2,$3,$4)")
            .bind(cid)
            .bind(best.get::<Vec<u8>, _>("txid"))
            .bind(best.get::<i32, _>("vout"))
            .bind(best.get::<Vec<u8>, _>("created_block"))
            .execute(&mut **tx)
            .await?;
    }
    let complete = rows.len() < batch as usize;
    if let Some(last) = rows.last() {
        sqlx::query("UPDATE covenant_genesis_progress SET scan_txid=$2,scan_vout=$3,scanned_outputs=scanned_outputs+$4,baseline_complete=$5 WHERE covenant_id=$1")
            .bind(cid).bind(last.get::<Vec<u8>,_>("txid")).bind(last.get::<i32,_>("vout"))
            .bind(rows.len() as i64).bind(complete).execute(&mut **tx).await?;
    } else {
        sqlx::query(
            "UPDATE covenant_genesis_progress SET baseline_complete=TRUE WHERE covenant_id=$1",
        )
        .bind(cid)
        .execute(&mut **tx)
        .await?;
    }
    Ok((rows.len() as i64, complete))
}
fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn finish_transaction<T>(
    tx: Transaction<'_, Postgres>,
    result: std::result::Result<Result<T>, tokio::time::error::Elapsed>,
) -> Result<T> {
    match result {
        Ok(Ok(value)) => {
            tx.commit().await?;
            Ok(value)
        }
        other => {
            tx.rollback()
                .await
                .context("rollback genesis transaction")?;
            Err(match other {
                Ok(Err(error)) => error,
                _ => anyhow::anyhow!("genesis reconciliation exceeded 350-ms writer budget"),
            })
        }
    }
}
