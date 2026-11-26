//! Durable missing-source windows. Never count parking as verified progress.
use super::*;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Window {
    pub window_start: i64,
    pub width: i32,
    pub missing_txid: String,
    pub source_endpoint: String,
    pub first_missing_at_ms: i64,
    pub next_retry_at_ms: i64,
    pub attempts: i64,
}
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub pending_windows: i64,
    pub retained_bytes: i64,
    pub windows: Vec<Window>,
    pub truncated: bool,
}
pub async fn summary(pool: &PgPool) -> Result<Summary> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let (pending_windows,retained_bytes):(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE j.phase<>'complete'),coalesce(sum(q.evidence_bytes),0)::bigint FROM settled_history_unverified q JOIN settled_repair_jobs j ON j.cursor_key=q.job_key")
        .fetch_one(&mut *tx).await?;
    let windows=sqlx::query_as("SELECT q.window_start,q.width,q.missing_txid,q.source_endpoint,q.first_missing_at_ms,q.next_retry_at_ms,q.attempts FROM settled_history_unverified q JOIN settled_repair_jobs j ON j.cursor_key=q.job_key WHERE j.phase<>'complete' ORDER BY q.window_start,q.job_key LIMIT 100")
        .fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(Summary {
        pending_windows,
        retained_bytes,
        windows,
        truncated: pending_windows > 100,
    })
}

impl PgPersister {
    /// Park only the exact failed replay epoch, retaining its job and members.
    /// An uncertain commit is safe to retry: an already-moved original job no
    /// longer matches, so it cannot advance scheduling twice.
    pub async fn defer_missing_history(
        &self,
        root: &str,
        key: &str,
        epoch: i64,
        next: u64,
        missing_txid: &str,
        endpoint: &str,
        evidence: &serde_json::Value,
        error: &str,
    ) -> Result<bool> {
        let bytes = serde_json::to_vec(evidence)?.len();
        anyhow::ensure!(
            bytes <= 16 * 1024 * 1024,
            "history evidence exceeds durable per-window limit"
        );
        let mut tx = self.begin_genesis().await?;
        let job:Option<RepairJob>=sqlx::query_as("SELECT * FROM settled_repair_jobs WHERE cursor_key=$1 AND epoch=$2 AND phase='replay' FOR UPDATE")
            .bind(key).bind(epoch).fetch_optional(&mut *tx).await?;
        let Some(job) = job else {
            tx.rollback().await?;
            return Ok(false);
        };
        let existing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM settled_history_unverified WHERE job_key=$1 AND cursor_key=$2)")
            .bind(key).bind(root).fetch_one(&mut *tx).await?;
        if existing {
            // Preserve the first source evidence; retries always fetch current
            // canonical data and never use this snapshot as acceptance proof.
            sqlx::query("UPDATE settled_history_unverified SET missing_txid=$2,last_missing_at_ms=$3,next_retry_at_ms=$3+900000,attempts=attempts+1,last_error=$4 WHERE job_key=$1")
                .bind(key).bind(missing_txid).bind(now()).bind(error.chars().take(1024).collect::<String>()).execute(&mut *tx).await?;
        } else {
            anyhow::ensure!(key == root, "unknown historical retry namespace");
            let (count,total):(i64,i64)=sqlx::query_as("SELECT count(*),coalesce(sum(evidence_bytes),0)::bigint FROM settled_history_unverified")
                .fetch_one(&mut *tx).await?;
            anyhow::ensure!(
                count < 10000 && total + bytes as i64 <= 1024 * 1024 * 1024,
                "history evidence capacity exhausted; retain current window"
            );
            let suffix: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(&mut *tx)
                .await?;
            let parked = format!("{root}:unverified:{suffix}");
            sqlx::query("UPDATE settled_repair_jobs SET cursor_key=$2,last_error=$3,next_retry_at_ms=$4+900000 WHERE cursor_key=$1")
                .bind(key).bind(&parked).bind(error.chars().take(1024).collect::<String>()).bind(now()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO settled_history_unverified(job_key,cursor_key,window_start,width,missing_txid,source_endpoint,source_evidence,evidence_bytes,first_missing_at_ms,last_missing_at_ms,next_retry_at_ms,last_error) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9+900000,$10)")
                .bind(parked).bind(root).bind(job.window_start).bind(job.width).bind(missing_txid).bind(endpoint).bind(evidence).bind(bytes as i64).bind(now()).bind(error.chars().take(1024).collect::<String>()).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO settled_history_schedule(cursor_key,next_window) VALUES($1,$2) ON CONFLICT(cursor_key) DO UPDATE SET next_window=EXCLUDED.next_window")
                .bind(root).bind(i64::try_from(next)?).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    /// At most one retained-window attempt per minute across restarts. Other
    /// ticks serve forward work, even when many missing windows are overdue.
    pub async fn due_history_retry(
        &self,
        root: &str,
        selection_tip: u64,
        min_age: u64,
    ) -> Result<Option<(String, u64)>> {
        let mut tx = self.begin_genesis().await?;
        // Poll leases exclude stopped cursor roots from dispatch. Among active
        // roots, the least recently served root gets the next global slot.
        sqlx::query("UPDATE settled_history_schedule SET last_poll_at_ms=$2 WHERE cursor_key=$1")
            .bind(root)
            .bind(now())
            .execute(&mut *tx)
            .await?;
        let row:Option<(String,i64)>=sqlx::query_as("WITH next AS MATERIALIZED (SELECT q.job_key,q.window_start,q.cursor_key FROM settled_history_unverified q JOIN settled_repair_jobs j ON j.cursor_key=q.job_key JOIN settled_history_schedule s ON s.cursor_key=q.cursor_key CROSS JOIN settled_history_retry_gate g WHERE j.phase<>'complete' AND q.next_retry_at_ms<=$2 AND j.next_retry_at_ms<=$2 AND g.last_retry_at_ms<=$2-60000 AND s.last_poll_at_ms>=$2-120000 AND q.window_start+q.width<=$3 ORDER BY s.last_retry_at_ms,q.next_retry_at_ms,q.job_key LIMIT 1) SELECT job_key,window_start FROM next WHERE cursor_key=$1")
            .bind(root).bind(now()).bind(i64::try_from(selection_tip.saturating_sub(min_age))?).fetch_optional(&mut *tx).await?;
        if let Some((key, _)) = &row {
            sqlx::query(
                "UPDATE settled_history_schedule SET last_retry_at_ms=$2 WHERE cursor_key=$1",
            )
            .bind(root)
            .bind(now())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE settled_history_retry_gate SET last_retry_at_ms=$1 WHERE singleton",
            )
            .bind(now())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE settled_history_unverified SET next_retry_at_ms=$2+60000 WHERE job_key=$1",
            )
            .bind(key)
            .bind(now())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        row.map(|(k, w)| Ok((k, u64::try_from(w)?))).transpose()
    }

    /// Rolling sweeps may revisit a retained hole. Keep its existing job and
    /// schedule independent work; do not manufacture a second obligation.
    pub async fn retained_history_window(
        &self,
        root: &str,
        window: u64,
        next: u64,
    ) -> Result<bool> {
        let mut tx = self.begin_genesis().await?;
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM settled_history_unverified q JOIN settled_repair_jobs j ON j.cursor_key=q.job_key WHERE q.cursor_key=$1 AND q.window_start=$2 AND j.phase<>'complete') AND NOT EXISTS(SELECT 1 FROM settled_repair_jobs WHERE cursor_key=$1 AND phase<>'complete')")
            .bind(root).bind(i64::try_from(window)?).fetch_one(&mut *tx).await?;
        if exists {
            sqlx::query("INSERT INTO settled_history_schedule(cursor_key,next_window) VALUES($1,$2) ON CONFLICT(cursor_key) DO UPDATE SET next_window=EXCLUDED.next_window")
                .bind(root).bind(i64::try_from(next)?).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(exists)
    }
}

#[cfg(test)]
#[path = "unverified_tests.rs"]
mod tests;
