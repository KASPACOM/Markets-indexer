//! Observe successful settled replay separately from the advancing tip cursor.
use anyhow::{Context, Result};
use serde::Serialize;
use sqlx::PgPool;
use std::fmt::Write;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SettledRecheck {
    pub next_blue_score: u64,
    pub last_completed_blue_score: u64,
    pub updated_at_ms: i64,
    pub age_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconciliation: Option<tn12_indexer_db::persist::genesis::RepairJob>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_windows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_scores: Option<u64>,
}

impl SettledRecheck {
    fn progress_age_ms(&self) -> Option<i64> {
        let age = self.age_ms?;
        let now = self.updated_at_ms.saturating_add(age);
        Some(
            self.reconciliation
                .as_ref()
                .filter(|job| job.phase != "complete")
                .and_then(|job| now.checked_sub(job.updated_at_ms).filter(|age| *age >= 0))
                .map_or(age, |progress_age| age.min(progress_age)),
        )
    }

    pub fn stalled(&self) -> bool {
        self.progress_age_ms().is_none_or(|age| age > 300_000)
    }

    pub fn write_metrics(&self, output: &mut String) {
        if let Some(age) = self.progress_age_ms() {
            let _ = writeln!(
                output,
                "tn10_indexer_settled_recheck_progress_age_seconds {}",
                age as f64 / 1000.0
            );
        }
        if let Some(job) = &self.reconciliation {
            let _ = writeln!(output, "tn10_indexer_identity_corrected_outputs_total {}", job.identity_corrections);
            let _ = writeln!(output, "tn10_indexer_identity_blocked_families {}", job.identity_blocked_families);
            let reason = job.blocker.as_ref().and_then(|b| b.get("reason")).and_then(|r| r.as_str());
            for known in ["inconsistent_identity", "missing_dependency_evidence", "canonical_removal_requires_proof"] {
                let _ = writeln!(output, "tn10_indexer_settled_identity_blocked{{reason=\"{known}\"}} {}", u8::from(reason==Some(known)));
            }
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_remaining_families {}",
                job.remaining_families
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_next_retry_timestamp_seconds {}",
                job.next_retry_at_ms as f64 / 1000.0
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_attempts {}",
                job.attempts
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_scanned_outputs {}",
                job.scanned_outputs
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_failures {}",
                job.consecutive_failures
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_step_seconds {}",
                job.last_step_ms as f64 / 1000.0
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_lock_held_seconds {}",
                job.last_lock_held_ms as f64 / 1000.0
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_progress_timestamp_seconds {}",
                job.updated_at_ms as f64 / 1000.0
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_reconciliation_phase{{phase=\"{}\"}} 1",
                job.phase
            );
        }
        if let Some(age) = self.age_ms {
            let _ = writeln!(
                output,
                "tn10_indexer_settled_recheck_cursor_age_seconds {}",
                age as f64 / 1000.0
            );
        }
        let _ = writeln!(
            output,
            "tn10_indexer_settled_recheck_next_blue_score {}",
            self.next_blue_score
        );
        if let (Some(windows), Some(scores)) = (self.completed_windows, self.completed_scores) {
            let _ = writeln!(
                output,
                "tn10_indexer_settled_recheck_completed_windows_total {windows}"
            );
            let _ = writeln!(
                output,
                "tn10_indexer_settled_recheck_completed_scores_total {scores}"
            );
        }
    }
}

/// The worker may only touch complete windows behind both the durable history
/// cursor and a mature source tip. Keep this in sync with the crawler bound.
pub(crate) fn eligible(next: u64, history_cursor: i64, source_tip: i64) -> bool {
    let Some(covered) = history_cursor.checked_sub(200) else { return false; };
    let Some(mature) = source_tip.checked_sub(1_000) else { return false; };
    next.checked_add(100)
        .and_then(|end| i64::try_from(end).ok())
        .is_some_and(|end| end <= covered.min(mature))
}

#[test]
fn eligibility_requires_a_complete_indexed_mature_window() {
    assert!(eligible(89_600, 90_000, 100_000));
    assert!(!eligible(89_800, 90_000, 100_000));
    assert!(!eligible(89_600, 90_000, 90_500));
}

pub(crate) async fn read(pool: &PgPool, now_ms: i64) -> Result<Option<SettledRecheck>> {
    let row: Option<(serde_json::Value, i64)> = sqlx::query_as(
        "SELECT value, updated_at_ms FROM indexer_state WHERE key = 'chain_realtime_tip_cursor:settled_recheck'",
    ).fetch_optional(pool).await?;
    let reconciliation =
        tn12_indexer_db::persist::genesis::read_job(pool, "chain_realtime_tip_cursor").await?;
    row.map(|(value, updated_at_ms)| {
        let counters = match (
            value.get("completed_windows"),
            value.get("completed_scores"),
        ) {
            (None, None) => None,
            (Some(windows), Some(scores)) => Some((
                windows
                    .as_u64()
                    .context("invalid settled replay completed windows")?,
                scores
                    .as_u64()
                    .context("invalid settled replay completed scores")?,
            )),
            _ => anyhow::bail!("incomplete settled replay work counters"),
        };
        Ok(SettledRecheck {
            reconciliation,
            next_blue_score: value["next_blue_score"]
                .as_u64()
                .context("invalid settled replay next score")?,
            last_completed_blue_score: value["last_completed_blue_score"]
                .as_u64()
                .context("invalid settled replay completed score")?,
            updated_at_ms,
            age_ms: now_ms.checked_sub(updated_at_ms).filter(|age| *age >= 0),
            completed_windows: counters.map(|v| v.0),
            completed_scores: counters.map(|v| v.1),
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn settled_work_counters_are_optional_for_legacy_but_never_fabricated(pool: PgPool) {
        let base = serde_json::json!({"next_blue_score": 100, "last_completed_blue_score": 0});
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('chain_realtime_tip_cursor:settled_recheck',$1,1000)")
            .bind(&base).execute(&pool).await.unwrap();
        let mut text = String::new();
        read(&pool, 2000)
            .await
            .unwrap()
            .unwrap()
            .write_metrics(&mut text);
        assert!(!text.contains("completed_scores_total"));
        let mut value = base.clone();
        value["completed_windows"] = serde_json::json!(3);
        value["completed_scores"] = serde_json::json!(300);
        sqlx::query("UPDATE indexer_state SET value=$1")
            .bind(&value)
            .execute(&pool)
            .await
            .unwrap();
        text.clear();
        read(&pool, 2000)
            .await
            .unwrap()
            .unwrap()
            .write_metrics(&mut text);
        assert!(text.contains("tn10_indexer_settled_recheck_completed_scores_total 300\n"));
        assert!(text.contains("tn10_indexer_settled_recheck_completed_windows_total 3\n"));
        for bad in [
            serde_json::json!(-1),
            serde_json::json!("300"),
            serde_json::Value::Null,
        ] {
            value["completed_scores"] = bad;
            sqlx::query("UPDATE indexer_state SET value=$1")
                .bind(&value)
                .execute(&pool)
                .await
                .unwrap();
            assert!(read(&pool, 2000).await.is_err());
        }
        value = base;
        value["completed_windows"] = serde_json::json!(3);
        sqlx::query("UPDATE indexer_state SET value=$1")
            .bind(&value)
            .execute(&pool)
            .await
            .unwrap();
        assert!(read(&pool, 2000).await.is_err());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn missing_or_invalid_settled_progress_never_becomes_a_fresh_observation(pool: PgPool) {
        assert!(read(&pool, 500_000).await.unwrap().is_none());
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('chain_realtime_tip_cursor:settled_recheck','{}',1000)")
            .execute(&pool).await.unwrap();
        assert!(read(&pool, 500_000).await.is_err());
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn stalled_settled_progress_remains_visible_while_tip_cursor_advances(pool: PgPool) {
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('chain_realtime_tip_cursor:settled_recheck',$1,1000),('chain_realtime_tip_cursor','{}',500000)")
            .bind(serde_json::json!({"next_blue_score": 80000, "last_completed_blue_score": 79900}))
            .execute(&pool).await.unwrap();
        let progress = read(&pool, 500_000).await.unwrap().unwrap();
        assert!(progress.stalled());
        assert_eq!(progress.age_ms, Some(499_000));
        let mut metrics = String::new();
        progress.write_metrics(&mut metrics);
        assert!(metrics.contains("tn10_indexer_settled_recheck_cursor_age_seconds 499\n"));
        assert!(metrics.contains("tn10_indexer_settled_recheck_next_blue_score 80000\n"));
        assert!(!read(&pool, 301_000).await.unwrap().unwrap().stalled());
        let future = read(&pool, 999).await.unwrap().unwrap();
        assert!(future.stalled());
        let mut metrics = String::new();
        future.write_metrics(&mut metrics);
        assert!(!metrics.contains("cursor_age_seconds"));
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn committed_pages_keep_progress_fresh_but_retries_do_not(pool: PgPool) {
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES ('chain_realtime_tip_cursor:settled_recheck',$1,1000)")
            .bind(serde_json::json!({"next_blue_score":100,"last_completed_blue_score":0})).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO settled_repair_jobs(cursor_key,window_start,width,phase,updated_at_ms,scanned_outputs) VALUES('chain_realtime_tip_cursor',100,100,'reconcile',499000,512)")
            .execute(&pool).await.unwrap();
        let progress = read(&pool, 500000).await.unwrap().unwrap();
        assert!(!progress.stalled());
        assert_eq!(progress.age_ms, Some(499000));
        let mut metrics = String::new();
        progress.write_metrics(&mut metrics);
        assert!(metrics.contains("tn10_indexer_settled_recheck_progress_age_seconds 1\n"));
        assert!(metrics.contains("tn10_indexer_settled_recheck_cursor_age_seconds 499\n"));
        let writer = tn12_indexer_db::PgPersister::new(pool.clone());
        writer
            .retain_settled_error("chain_realtime_tip_cursor", &anyhow::anyhow!("timeout"))
            .await
            .unwrap();
        let stale = read(&pool, 900000).await.unwrap().unwrap();
        assert!(stale.stalled());
        assert!(stale
            .reconciliation
            .unwrap()
            .last_error
            .unwrap()
            .contains("timeout"));
        // A future timestamp cannot provide freshness evidence.
        sqlx::query("UPDATE settled_repair_jobs SET updated_at_ms=1000000")
            .execute(&pool)
            .await
            .unwrap();
        assert!(read(&pool, 900000).await.unwrap().unwrap().stalled());
    }
}
