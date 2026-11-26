//! Recovery obligations are independent of a fresh watcher heartbeat.
use anyhow::Result;
use serde::Serialize;
use sqlx::{PgPool, Row};

const LIVE_IN_FLIGHT_INTENT_GRACE_MS: i64 = 2_000;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PagedRecoveryProgress {
    pub intent_key: String,
    pub phase: String,
    pub discovered_blocks: i64,
    pub reverted_blocks: i64,
    pub remaining_blocks: i64,
    pub pending_discovery_blocks: i64,
    pub pending_discovery_transactions: i64,
    pub staged_transactions: i64,
    pub replayed_transactions: i64,
    pub remaining_transactions: i64,
    pub updated_at_ms: i64,
    pub last_committed_step_at_ms: Option<i64>,
    pub last_committed_checkpoint: Option<String>,
    pub removal_blocker: Option<serde_json::Value>,
    pub last_durable_progress_at_ms: Option<i64>,
    pub last_durable_checkpoint: Option<String>,
    pub canonical_pause_started_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryHealth {
    pub pending_intents: i64,
    pub oldest_pending_intent_age_ms: Option<i64>,
    pub oldest_uncommitted_intent_age_ms: Option<i64>,
    pub canonical_pause_age_ms: Option<i64>,
    pub open_intervals: i64,
    pub pending_snapshots: i64,
    pub pending_effects: i64,
    pub oldest_pending_effect_age_ms: Option<i64>,
    pub pending_bytes: i64,
    pub states: Vec<serde_json::Value>,
    pub paged_recovery: Vec<PagedRecoveryProgress>,
}
impl RecoveryHealth {
    pub fn write_progress_metrics(&self, output: &mut String, now: i64) {
        use std::fmt::Write;
        let sum = |field: &str| {
            self.states
                .iter()
                .map(|s| s[field].as_u64().unwrap_or(0))
                .sum::<u64>()
        };
        let _ = writeln!(output,"# TYPE tn10_indexer_recovery_attempts_total counter\ntn10_indexer_recovery_attempts_total {}",sum("attempts"));
        let _ = writeln!(
            output,
            "# TYPE tn10_indexer_recovery_outcomes_total counter"
        );
        for (label, field) in [
            ("completed", "completedTotal"),
            ("retry", "retryTotal"),
            ("blocked", "blockedTotal"),
            ("terminal", "terminalTotal"),
            ("handoff", "handoffTotal"),
        ] {
            let _ = writeln!(
                output,
                "tn10_indexer_recovery_outcomes_total{{outcome=\"{label}\"}} {}",
                sum(field)
            );
        }
        let _ = writeln!(
            output,
            "# TYPE tn10_indexer_recovery_duration_seconds histogram"
        );
        for bound in [1, 2, 5, 10, 30, 60, 120, 300, 600] {
            let count: u64 = self
                .states
                .iter()
                .map(|s| {
                    s["durationBuckets"][bound.to_string()]
                        .as_u64()
                        .unwrap_or(0)
                })
                .sum();
            let _ = writeln!(
                output,
                "tn10_indexer_recovery_duration_seconds_bucket{{le=\"{bound}\"}} {count}"
            );
        }
        let count = sum("completedTotal");
        let duration: f64 = self
            .states
            .iter()
            .map(|s| s["durationSumSeconds"].as_f64().unwrap_or(0.0))
            .sum();
        let _ = writeln!(output,"tn10_indexer_recovery_duration_seconds_bucket{{le=\"+Inf\"}} {count}\ntn10_indexer_recovery_duration_seconds_count {count}\ntn10_indexer_recovery_duration_seconds_sum {duration}");
        let age = if self.clear() {
            0
        } else {
            self.states
                .iter()
                .filter(|s| s["phase"] != "watching")
                .filter(|s| {
                    !self.paged_recovery.iter().any(|p| {
                        s["journalKey"].as_str() == Some(p.intent_key.as_str())
                            || s["activeIncident"]["journalKey"].as_str()
                                == Some(p.intent_key.as_str())
                    })
                })
                .filter_map(|s| {
                    let start = s["pendingSinceMs"]
                        .as_i64()
                        .or_else(|| s["phaseStartedAtMs"].as_i64())?;
                    let committed = s["lastCommittedProgressAtMs"]
                        .as_i64()
                        .unwrap_or(start)
                        .max(start);
                    Some(now.saturating_sub(committed).max(0))
                })
                .max()
                .unwrap_or(0)
                .max(
                    self.oldest_uncommitted_intent_age_ms
                        .or(self.oldest_pending_intent_age_ms)
                        .unwrap_or(0),
                )
                .max(self.oldest_pending_effect_age_ms.unwrap_or(0))
        };
        let _ = writeln!(output,"# TYPE tn10_indexer_recovery_no_progress_age_seconds gauge\ntn10_indexer_recovery_no_progress_age_seconds {}",age as f64 / 1000.0);
        let _ = writeln!(output,"# TYPE tn10_indexer_canonical_pause_age_seconds gauge\ntn10_indexer_canonical_pause_age_seconds {}",self.canonical_pause_age_ms.unwrap_or(0) as f64 / 1000.0);
        let active = self
            .states
            .iter()
            .filter(|state| state["activeIncident"].is_object())
            .count();
        let action_required = self
            .states
            .iter()
            .filter(|state| matches!(state["phase"].as_str(), Some("blocked" | "stopped")))
            .count();
        let _ = writeln!(output,
            "# TYPE tn10_indexer_recovery_incidents_active gauge\ntn10_indexer_recovery_incidents_active {active}\n# TYPE tn10_indexer_recovery_action_required gauge\ntn10_indexer_recovery_action_required {action_required}");
    }

    pub fn clear(&self) -> bool {
        // Certification is independent of latency and alerting budgets. A fresh
        // obligation is still outstanding; its age is diagnostic only.
        self.pending_intents == 0 && self.other_obligations_clear()
    }

    pub fn alert_healthy(&self) -> bool {
        // This is a non-certifying paging signal. A brief in-flight intent is
        // normal during writes, but /health/live and live_ok stay fail-closed.
        // An old or undated intent still signals failed recovery here.
        (self.pending_intents == 0
            || (self.pending_intents > 0
                && self
                    .oldest_pending_intent_age_ms
                    .is_some_and(|age| age < LIVE_IN_FLIGHT_INTENT_GRACE_MS)))
            && self.other_obligations_clear()
    }

    fn other_obligations_clear(&self) -> bool {
        self.open_intervals == 0
            && self.pending_snapshots == 0
            && self.pending_effects == 0
            && self.pending_bytes == 0
            && self.states.iter().all(|s| s["phase"] == "watching")
    }
}

pub(crate) async fn read(pool: &PgPool, network: &str, now: i64) -> Result<RecoveryHealth> {
    let (pending_intents, oldest): (i64, Option<i64>) = sqlx::query_as(
        "SELECT count(*),min(created_at_ms) FROM indexer_state WHERE starts_with(key,$1)",
    )
    .bind(format!("live_write_intent:{network}:"))
    .fetch_one(pool)
    .await?;
    let (open_intervals, pending_snapshots, pending_effects, pending_bytes): (i64,i64,i64,i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM wrpc_recovery_intervals WHERE starts_with(stream,$1) AND verified_at_ms IS NULL), (SELECT count(*) FROM wrpc_recovery_snapshots WHERE starts_with(stream,$1)), (SELECT count(*) FROM wrpc_inbox_effects WHERE starts_with(stream,$1)), (SELECT coalesce(sum(pending_bytes),0)::bigint FROM wrpc_inbox_streams WHERE starts_with(stream,$1))"
    ).bind(format!("{network}:")).fetch_one(pool).await?;
    let effect_started: Option<i64> = sqlx::query_scalar(
        "SELECT min(started_at_ms) FROM wrpc_inbox_effects WHERE starts_with(stream,$1)",
    )
    .bind(format!("{network}:"))
    .fetch_one(pool)
    .await?;
    let states = sqlx::query_scalar(
        "SELECT value || jsonb_build_object('journalKey', 'live_write_intent:' || substr(key,length('live_recovery_state:')+1)) FROM indexer_state WHERE starts_with(key,$1) ORDER BY key",
    )
    .bind(format!("live_recovery_state:{network}:"))
    .fetch_all(pool)
    .await?;
    let paged_recovery = if sqlx::query_scalar::<_, bool>(
        "SELECT to_regclass('tn10_live_recovery_plans') IS NOT NULL",
    )
    .fetch_one(pool)
    .await?
    {
        sqlx::query(
            r#"SELECT p.intent_key,p.phase,p.discovered_blocks,p.reverted_blocks,
                      GREATEST(p.discovered_blocks-p.reverted_blocks,0)::BIGINT AS remaining_blocks,
                      (SELECT count(*) FROM tn10_live_recovery_frontier f
                       WHERE f.intent_key=p.intent_key AND NOT f.processed) AS pending_discovery_blocks,
                      (SELECT count(*) FROM tn10_live_recovery_tx_frontier f
                       WHERE f.intent_key=p.intent_key AND NOT f.processed) AS pending_discovery_transactions,
                      (SELECT count(*) FROM tn10_live_recovery_transactions t
                       WHERE t.intent_key=p.intent_key) AS staged_transactions,
                      p.replayed_transactions,
                      (SELECT count(*) FROM tn10_live_recovery_transactions t
                       WHERE t.intent_key=p.intent_key AND NOT t.replayed AND NOT t.verified_rejected) AS remaining_transactions,
                      p.updated_at_ms,p.last_committed_step_at_ms,p.last_committed_checkpoint,
                      p.last_durable_progress_at_ms,p.last_durable_checkpoint,p.canonical_pause_started_at_ms,
                      (SELECT jsonb_build_object('stage','remove','block',encode(b.block_hash,'hex'),
                          'consecutiveFailures',b.removal_failures,'lastError',b.last_removal_error,
                          'failedAtMs',b.last_removal_failure_at_ms,'actionRequired',b.removal_failures>=3)
                       FROM tn10_live_recovery_blocks b WHERE b.intent_key=p.intent_key AND b.removal_failures>0
                       ORDER BY b.last_removal_failure_at_ms DESC LIMIT 1) AS removal_blocker
               FROM tn10_live_recovery_plans p
               WHERE starts_with(p.intent_key,$1)
                 AND EXISTS (SELECT 1 FROM indexer_state i WHERE i.key=p.intent_key)
               ORDER BY p.intent_key"#,
        )
        .bind(format!("live_write_intent:{network}:"))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| PagedRecoveryProgress {
            intent_key: row.get("intent_key"),
            phase: row.get("phase"),
            discovered_blocks: row.get("discovered_blocks"),
            reverted_blocks: row.get("reverted_blocks"),
            remaining_blocks: row.get("remaining_blocks"),
            pending_discovery_blocks: row.get("pending_discovery_blocks"),
            pending_discovery_transactions: row.get("pending_discovery_transactions"),
            staged_transactions: row.get("staged_transactions"),
            replayed_transactions: row.get("replayed_transactions"),
            remaining_transactions: row.get("remaining_transactions"),
            updated_at_ms: row.get("updated_at_ms"),
            last_committed_step_at_ms: row.get("last_committed_step_at_ms"),
            last_committed_checkpoint: row.get("last_committed_checkpoint"),
            removal_blocker: row.get("removal_blocker"),
            last_durable_progress_at_ms: row.get("last_durable_progress_at_ms"),
            last_durable_checkpoint: row.get("last_durable_checkpoint"),
            canonical_pause_started_at_ms: row.get("canonical_pause_started_at_ms"),
        })
        .collect()
    } else {
        Vec::new()
    };
    let oldest_uncommitted: Option<i64> = sqlx::query_scalar(
        "SELECT min(coalesce(p.last_durable_progress_at_ms,i.created_at_ms)) FROM indexer_state i LEFT JOIN tn10_live_recovery_plans p ON p.intent_key=i.key WHERE starts_with(i.key,$1)"
    ).bind(format!("live_write_intent:{network}:")).fetch_one(pool).await?;
    let pause_started: Option<i64> = sqlx::query_scalar(
        "SELECT min(coalesce(p.canonical_pause_started_at_ms,i.created_at_ms,0)) FROM tn10_live_recovery_plans p LEFT JOIN indexer_state i ON i.key=p.intent_key WHERE p.exclusive_writes AND starts_with(p.intent_key,$1)"
    ).bind(format!("live_write_intent:{network}:")).fetch_one(pool).await?;
    Ok(RecoveryHealth {
        pending_intents,
        oldest_uncommitted_intent_age_ms: oldest_uncommitted.map(|t| now.saturating_sub(t).max(0)),
        canonical_pause_age_ms: pause_started.map(|t| now.saturating_sub(t).max(0)),
        oldest_pending_intent_age_ms: oldest.map(|t| now.saturating_sub(t).max(0)),
        open_intervals,
        pending_snapshots,
        pending_effects,
        oldest_pending_effect_age_ms: effect_started.map(|t| now.saturating_sub(t).max(0)),
        pending_bytes,
        states,
        paged_recovery,
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnverifiedRange {
    pub from_blue_score: i64,
    pub through_blue_score: i64,
    pub reason: &'static str,
}

pub(crate) fn watermark(checkpoint: Option<&serde_json::Value>) -> Option<i64> {
    let c = checkpoint?;
    if c["verified"] != true {
        return None;
    }
    c.get("verifiedThroughBlueScore")
        .or_else(|| c.get("sourceCurrentAuditedThroughBlueScore"))?
        .as_i64()
        .filter(|v| *v >= 0)
}

pub(crate) fn unverified(verified: Option<i64>, tip: Option<i64>) -> Option<Vec<UnverifiedRange>> {
    let tip = tip.filter(|t| *t >= 0)?;
    let start = verified.map_or(0, |s| s.saturating_add(1));
    Some(if start > tip {
        vec![]
    } else {
        vec![UnverifiedRange {
            from_blue_score: start,
            through_blue_score: tip,
            reason: "not_independently_verified",
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retries_do_not_hide_stalls_and_metrics_have_bounded_labels() {
        let h = RecoveryHealth {
            pending_intents: 1,
            oldest_pending_intent_age_ms: Some(400_000),
            states: vec![
                serde_json::json!({"phase":"recovering","attempts":100,"pendingSinceMs":1,"updatedAtMs":400001,"nextRetryAtMs":430001}),
            ],
            ..Default::default()
        };
        let mut text = String::new();
        h.write_progress_metrics(&mut text, 400001);
        assert!(text.contains("tn10_indexer_recovery_no_progress_age_seconds 400"));
        assert!(text.contains("tn10_indexer_recovery_attempts_total 100"));
        assert!(!text.contains("nextRetryAtMs"));
        let mut clear = String::new();
        RecoveryHealth::default().write_progress_metrics(&mut clear, 400001);
        assert!(clear.contains("tn10_indexer_recovery_no_progress_age_seconds 0"));
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn durable_steps_reset_only_their_own_stall_not_the_canonical_pause(pool: PgPool) {
        let key = "live_write_intent:testnet-10:progress";
        sqlx::query("INSERT INTO indexer_state(key,value,created_at_ms,updated_at_ms) VALUES($1,'{}',1,1),('live_recovery_state:testnet-10:progress','{\"phase\":\"recovering\",\"pendingSinceMs\":1}',1,1)")
            .bind(key).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tn10_live_recovery_plans(intent_key,intent_sha256,owner_token,lease_expires_at_ms,phase,updated_at_ms) VALUES($1,sha256('{}'::bytea),gen_random_uuid(),2,'discover',1)")
            .bind(key).execute(&pool).await.unwrap();
        sqlx::query(
            "UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE WHERE intent_key=$1",
        )
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE tn10_live_recovery_plans SET canonical_pause_started_at_ms=1 WHERE intent_key=$1")
            .bind(key).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tn10_live_recovery_frontier(intent_key,block_hash) VALUES($1,decode(repeat('aa',32),'hex'))")
            .bind(key).execute(&pool).await.unwrap();
        sqlx::query("UPDATE tn10_live_recovery_frontier SET processed=TRUE WHERE intent_key=$1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        let committed: i64 = sqlx::query_scalar(
            "SELECT last_durable_progress_at_ms FROM tn10_live_recovery_plans WHERE intent_key=$1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
        let health = read(&pool, "testnet-10", committed + 1_000).await.unwrap();
        assert_eq!(health.oldest_uncommitted_intent_age_ms, Some(1_000));
        assert_eq!(health.canonical_pause_age_ms, Some(committed + 999));
        assert!(!health.clear());
        let mut metrics = String::new();
        health.write_progress_metrics(&mut metrics, committed + 1_000);
        assert!(
            metrics.contains("tn10_indexer_recovery_no_progress_age_seconds 1\n"),
            "{metrics}"
        );
        assert!(health.paged_recovery[0]
            .last_durable_checkpoint
            .as_ref()
            .unwrap()
            .starts_with("discover-block:"));

        // Lease refresh and duplicate page processing must not reset progress.
        sqlx::query("UPDATE tn10_live_recovery_plans SET updated_at_ms=$2,lease_expires_at_ms=$2 WHERE intent_key=$1")
            .bind(key).bind(committed+50_000).execute(&pool).await.unwrap();
        sqlx::query("UPDATE tn10_live_recovery_frontier SET processed=TRUE WHERE intent_key=$1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            read(&pool, "testnet-10", committed + 60_001)
                .await
                .unwrap()
                .oldest_uncommitted_intent_age_ms,
            Some(60_001)
        );

        // A rolled-back discovery page is not committed progress.
        sqlx::query("INSERT INTO tn10_live_recovery_tx_frontier(intent_key,txid) VALUES($1,decode(repeat('bb',32),'hex'))")
            .bind(key).execute(&pool).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE tn10_live_recovery_tx_frontier SET processed=TRUE WHERE intent_key=$1")
            .bind(key)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        let health = read(&pool, "testnet-10", committed + 60_001).await.unwrap();
        assert_eq!(
            health.paged_recovery[0].last_durable_progress_at_ms,
            Some(committed)
        );
        let sequence: i64 = sqlx::query_scalar(
            "SELECT committed_step_sequence FROM tn10_live_recovery_plans WHERE intent_key=$1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            sequence, 0,
            "discovery cannot change the canonical summary generation"
        );

        // Progress on this journal cannot hide a separate unpaged obligation.
        sqlx::query("INSERT INTO indexer_state(key,value,created_at_ms,updated_at_ms) VALUES('live_write_intent:testnet-10:other','{}',$1,$1)")
            .bind(committed-100_000).execute(&pool).await.unwrap();
        let health = read(&pool, "testnet-10", committed + 1_000).await.unwrap();
        assert_eq!(health.oldest_uncommitted_intent_age_ms, Some(101_000));
        let mut metrics = String::new();
        health.write_progress_metrics(&mut metrics, committed + 1_000);
        assert!(
            metrics.contains("tn10_indexer_recovery_no_progress_age_seconds 101\n"),
            "{metrics}"
        );
    }

    #[test]
    fn blocked_incidents_are_exposed_without_error_text_metric_labels() {
        let health = RecoveryHealth {
            states: vec![serde_json::json!({
                "phase":"blocked",
                "activeIncident":{"id":"testnet-10:1","lastReason":"dependency_limit"},
                "lastError":"arbitrary transaction bytes"
            })],
            ..Default::default()
        };
        let mut metrics = String::new();
        health.write_progress_metrics(&mut metrics, 10);
        assert!(metrics.contains("tn10_indexer_recovery_incidents_active 1\n"));
        assert!(metrics.contains("tn10_indexer_recovery_action_required 1\n"));
        assert!(!metrics.contains("arbitrary transaction bytes"));
        assert!(!metrics.contains("dependency_limit"));
    }
    #[test]
    fn fresh_obligations_never_clear_recovery() {
        assert!(RecoveryHealth::default().clear());
        for age in [None, Some(0), Some(1), Some(2_000), Some(2_001)] {
            assert!(
                !RecoveryHealth {
                    pending_intents: 1,
                    oldest_pending_intent_age_ms: age,
                    ..Default::default()
                }
                .clear(),
                "pending intent with age {age:?} cannot certify recovery"
            );
            assert!(
                !RecoveryHealth {
                    pending_effects: 1,
                    oldest_pending_effect_age_ms: age,
                    ..Default::default()
                }
                .clear(),
                "pending effect with age {age:?} cannot certify recovery"
            );
        }
        for pending in [
            RecoveryHealth {
                open_intervals: 1,
                ..Default::default()
            },
            RecoveryHealth {
                pending_snapshots: 1,
                ..Default::default()
            },
            RecoveryHealth {
                pending_bytes: 1,
                ..Default::default()
            },
            RecoveryHealth {
                states: vec![serde_json::json!({"phase":"recovering"})],
                ..Default::default()
            },
        ] {
            assert!(!pending.clear());
        }
    }
    #[test]
    fn paging_signal_allows_only_fresh_in_flight_intents() {
        assert!(RecoveryHealth::default().alert_healthy());
        let fresh = RecoveryHealth {
            pending_intents: 1,
            oldest_pending_intent_age_ms: Some(300),
            states: vec![serde_json::json!({"phase":"watching"})],
            ..Default::default()
        };
        assert!(!fresh.clear());
        assert!(fresh.alert_healthy());
        assert!(RecoveryHealth {
            oldest_pending_intent_age_ms: Some(1_999),
            ..fresh.clone()
        }
        .alert_healthy());

        for age in [None, Some(2_000), Some(5_000)] {
            assert!(!RecoveryHealth {
                oldest_pending_intent_age_ms: age,
                ..fresh.clone()
            }
            .alert_healthy());
        }
        assert!(!RecoveryHealth {
            open_intervals: 1,
            ..fresh.clone()
        }
        .alert_healthy());
        assert!(!RecoveryHealth {
            states: vec![serde_json::json!({"phase":"recovering"})],
            ..fresh
        }
        .alert_healthy());
    }

    #[test]
    fn rolling_cursor_cannot_certify_a_dated_checkpoint() {
        let checkpoint =
            serde_json::json!({"verified":true,"sourceCurrentAuditedThroughBlueScore":100});
        let ranges = unverified(watermark(Some(&checkpoint)), Some(150)).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].from_blue_score, 101);
        assert_eq!(ranges[0].through_blue_score, 150);
        assert!(unverified(None, None).is_none());
        assert!(unverified(Some(150), Some(150)).unwrap().is_empty());
    }
    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn pending_journal_and_recovery_state_block_live_readiness(pool: PgPool) {
        assert!(read(&pool, "testnet-10", 100).await.unwrap().clear());
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES('live_write_intent:testnet-10:test','{}',10)").execute(&pool).await.unwrap();
        sqlx::query("UPDATE indexer_state SET created_at_ms=10,updated_at_ms=2990")
            .execute(&pool)
            .await
            .unwrap();
        let fresh = read(&pool, "testnet-10", 11).await.unwrap();
        assert_eq!(fresh.oldest_pending_intent_age_ms, Some(1));
        assert!(!fresh.clear(), "a 1ms-old journal is still outstanding");
        let h = read(&pool, "testnet-10", 3_000).await.unwrap();
        assert!(!h.clear());
        assert_eq!(h.oldest_pending_intent_age_ms, Some(2_990));
        sqlx::query("INSERT INTO tn10_live_recovery_plans(intent_key,intent_sha256,owner_token,lease_expires_at_ms,phase,discovered_blocks,reverted_blocks,updated_at_ms) VALUES('live_write_intent:testnet-10:test',sha256('{}'::bytea),gen_random_uuid(),4000,'revert',3,1,3000)")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tn10_live_recovery_frontier(intent_key,block_hash) VALUES('live_write_intent:testnet-10:test',decode(repeat('11',32),'hex'))")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO tn10_live_recovery_tx_frontier(intent_key,txid) VALUES('live_write_intent:testnet-10:test',decode(repeat('22',32),'hex'))")
            .execute(&pool).await.unwrap();
        let progress = read(&pool, "testnet-10", 3_000).await.unwrap();
        assert_eq!(progress.paged_recovery.len(), 1);
        assert_eq!(progress.paged_recovery[0].remaining_blocks, 2);
        assert_eq!(progress.paged_recovery[0].pending_discovery_blocks, 1);
        assert_eq!(progress.paged_recovery[0].pending_discovery_transactions, 1);
        assert!(read(&pool, "testnet-11", 100).await.unwrap().clear());
        sqlx::query("DELETE FROM indexer_state")
            .execute(&pool)
            .await
            .unwrap();
        assert!(read(&pool, "testnet-10", 3_000)
            .await
            .unwrap()
            .paged_recovery
            .is_empty());
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES('live_recovery_state:testnet-10:test','{\"phase\":\"recovering\"}',10)").execute(&pool).await.unwrap();
        assert!(!read(&pool, "testnet-10", 100).await.unwrap().clear());
    }
}
