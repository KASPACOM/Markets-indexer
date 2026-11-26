//! Durable, additive diagnostics. Retry activity never certifies committed work.
use anyhow::Result;
use serde_json::{json, Value};

pub struct Observation<'a> {
    pub phase: &'a str,
    pub outcome: &'a str,
    pub reason: Option<&'a str>,
    pub error: Option<&'a str>,
    pub next_retry_at_ms: Option<i64>,
}
impl<'a> Observation<'a> {
    pub fn new(phase: &'a str, outcome: &'a str) -> Self {
        Self {
            phase,
            outcome,
            reason: None,
            error: None,
            next_retry_at_ms: None,
        }
    }
}

fn increment(value: &mut Value, key: &str, delta: u64) {
    value[key] = json!(value[key].as_u64().unwrap_or(0).saturating_add(delta));
}

/// Keep an operator-sized pointer to the durable journal. The journal itself
/// remains authoritative and is never copied into the diagnostic state row.
fn summarize_journal(journal: &Value) -> Value {
    let accepted = journal["transactions"].as_array();
    let rejected = journal["rejected_transactions"].as_array();
    let mut scores = accepted
        .into_iter()
        .flatten()
        .chain(rejected.into_iter().flatten())
        .filter_map(|tx| tx["accepting_block_blue_score"].as_u64());
    let first = scores.next();
    let (first_score, last_score) = scores.fold((first, first), |(low, high), score| {
        (
            Some(low.unwrap_or(score).min(score)),
            Some(high.unwrap_or(score).max(score)),
        )
    });
    let transaction_ids: Vec<_> = accepted
        .into_iter()
        .flatten()
        .chain(rejected.into_iter().flatten())
        .filter_map(|tx| tx["transaction_id"].as_str())
        .take(8)
        .collect();
    json!({
        "acceptedCount": accepted.map_or(0, Vec::len),
        "rejectedCount": rejected.map_or(0, Vec::len),
        "affectedCount": journal["affected_transaction_ids"].as_array().map_or(0, Vec::len),
        "observedWindows": journal["observed_blocks"].as_object().map_or(0, serde_json::Map::len),
        "firstScore": first_score,
        "lastScore": last_score,
        "transactionIds": transaction_ids,
    })
}

fn incident_action(outcome: &str) -> &'static str {
    match outcome {
        "attempt" | "handoff" => "canonical_replay",
        "retry" => "retry_canonical_replay",
        "blocked" => "investigate_retained_journal",
        "terminal" => "investigate_stopped_writer",
        _ => "none",
    }
}

fn update(
    mut value: Value,
    observation: Observation<'_>,
    network: &str,
    now: i64,
    journal_since: Option<i64>,
) -> Value {
    if !value.is_object() {
        value = json!({});
    }
    if value["phase"] != observation.phase {
        value["phaseStartedAtMs"] = json!(now);
    }
    value["phase"] = json!(observation.phase);
    value["network"] = json!(network);
    value["updatedAtMs"] = json!(now);
    value["nextRetryAtMs"] = json!(observation.next_retry_at_ms);
    if let Some(reason) = observation.reason {
        value["reason"] = json!(reason);
    }
    if let Some(error) = observation.error {
        value["lastError"] = json!(error.chars().take(2048).collect::<String>());
        if observation.outcome == "handoff" {
            // Keep the initiating failure separate from later REST/replay errors.
            // This dated diagnostic is not an outstanding recovery obligation.
            value["lastHandoff"] = json!({
                "atMs": now,
                "reason": observation.reason,
                "error": value["lastError"].clone(),
            });
        }
    }
    if let Some(since) = journal_since {
        value["pendingSinceMs"] = json!(value["pendingSinceMs"]
            .as_i64()
            .map_or(since, |old| old.min(since)));
    }
    if matches!(
        observation.outcome,
        "attempt" | "handoff" | "retry" | "blocked" | "terminal"
    ) {
        if !value["activeIncident"].is_object() {
            let opened_at = value["pendingSinceMs"].as_i64().unwrap_or(now);
            value["activeIncident"] = json!({
                "id": format!("{network}:{opened_at}"),
                "openedAtMs": opened_at,
                "initialReason": observation.reason,
                "status": "investigating",
            });
        }
        let incident = &mut value["activeIncident"];
        if incident["initialReason"].is_null() && observation.reason.is_some() {
            incident["initialReason"] = json!(observation.reason);
        }
        if observation.reason.is_some() {
            incident["lastReason"] = json!(observation.reason);
        }
        if let Some(error) = observation.error {
            incident["lastError"] = json!(error.chars().take(2048).collect::<String>());
        }
        incident["lastObservedAtMs"] = json!(now);
        incident["action"] = json!(incident_action(observation.outcome));
        incident["status"] = json!(match observation.outcome {
            "blocked" => "blocked",
            "terminal" => "stopped",
            _ => "recovering",
        });
        if observation.outcome == "attempt" {
            increment(incident, "attempts", 1);
            if journal_since.is_some() {
                // A retained intent is about to be replayed again. Earlier
                // replay evidence cannot certify this new attempt.
                incident["replayEvidence"] = Value::Null;
            }
        }
    }
    if observation.outcome == "attempt" {
        increment(&mut value, "attempts", 1);
    }
    if matches!(
        observation.outcome,
        "retry" | "blocked" | "terminal" | "handoff"
    ) {
        let field = format!("{}Total", observation.outcome);
        increment(&mut value, &field, 1);
    }
    if observation.outcome == "completed" && value["activeIncident"]["status"] != "replay_committed"
    {
        if value["activeIncident"].is_object() {
            value["activeIncident"]["status"] = json!("replay_committed");
            value["activeIncident"]["lastObservedAtMs"] = json!(now);
            if let Some(journal_created_at) = journal_since {
                let incident_id = value["activeIncident"]["id"].clone();
                value["activeIncident"]["replayEvidence"] = json!({
                    "incidentId": incident_id,
                    "journalCreatedAtMs": journal_created_at,
                    "verifiedAtMs": now,
                });
            }
        }
        value["lastCommittedProgressAtMs"] = json!(now);
        increment(&mut value, "completedTotal", 1);
        let seconds = now
            .saturating_sub(value["pendingSinceMs"].as_i64().unwrap_or(now))
            .max(0) as f64
            / 1000.0;
        value["durationSumSeconds"] =
            json!(value["durationSumSeconds"].as_f64().unwrap_or(0.0) + seconds);
        if !value["durationBuckets"].is_object() {
            value["durationBuckets"] = json!({});
        }
        for bound in [1, 2, 5, 10, 30, 60, 120, 300, 600] {
            if seconds <= bound as f64 {
                increment(&mut value["durationBuckets"], &bound.to_string(), 1);
            }
        }
    }
    if observation.phase == "watching" {
        if value["activeIncident"].is_object() {
            let recovered = replay_evidence_valid(&value["activeIncident"]);
            let mut incident = value["activeIncident"].take();
            incident["status"] = json!(if recovered {
                "replay_committed"
            } else {
                "closed_unverified"
            });
            incident["closedAtMs"] = json!(now);
            value["lastIncident"] = incident;
        }
        value["reason"] = Value::Null;
        value["lastError"] = Value::Null;
        value["pendingSinceMs"] = Value::Null;
    }
    value
}

fn replay_evidence_valid(incident: &Value) -> bool {
    let evidence = &incident["replayEvidence"];
    let created = evidence["journalCreatedAtMs"].as_i64();
    let verified = evidence["verifiedAtMs"].as_i64();
    incident["id"].as_str().is_some_and(|id| !id.is_empty())
        && evidence["incidentId"] == incident["id"]
        && created.is_some()
        && created == incident["openedAtMs"].as_i64()
        && verified.is_some_and(|at| at >= created.unwrap_or(i64::MAX))
}

fn watch_is_safe(state: &Value) -> bool {
    match state["phase"].as_str() {
        None | Some("watching") => true,
        _ => replay_evidence_valid(&state["activeIncident"]),
    }
}

/// A pod restart must not turn a deleted or unverified journal into a clean
/// watcher. A retained journal is replayed before this check is called.
pub(crate) async fn ensure_watch_safe(
    pool: &sqlx::PgPool,
    network: &str,
    cursor: &str,
) -> Result<()> {
    let state: Option<Value> = sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
        .bind(format!("live_recovery_state:{network}:{cursor}"))
        .fetch_optional(pool)
        .await?;
    anyhow::ensure!(
        state.as_ref().is_none_or(watch_is_safe),
        crate::recovery_policy::RecoveryBlocked("unverified_recovery_state")
    );
    Ok(())
}

pub(crate) async fn record(
    pool: &sqlx::PgPool,
    network: &str,
    cursor: &str,
    observation: Observation<'_>,
) -> Result<()> {
    if observation.outcome == "handoff" {
        tracing::warn!(
            target: "live_recovery",
            network, cursor,
            reason = observation.reason.unwrap_or("unspecified"),
            error = observation.error.unwrap_or("").chars().take(2048).collect::<String>(),
            "live writer handed retained intent to canonical recovery"
        );
    }
    let now = chrono::Utc::now().timestamp_millis();
    let key = format!("live_recovery_state:{network}:{cursor}");
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',$2) ON CONFLICT(key) DO NOTHING")
        .bind(&key).bind(now).execute(&mut *tx).await?;
    let previous: Value =
        sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1 FOR UPDATE")
            .bind(&key)
            .fetch_one(&mut *tx)
            .await?;
    let journal: Option<(i64, Value)> =
        sqlx::query_as("SELECT created_at_ms,value FROM indexer_state WHERE key=$1")
            .bind(format!("live_write_intent:{network}:{cursor}"))
            .fetch_optional(&mut *tx)
            .await?;
    let mut value = update(
        previous,
        observation,
        network,
        now,
        journal.as_ref().map(|(since, _)| *since),
    );
    if let (Some((_, journal)), true) = (&journal, value["activeIncident"].is_object()) {
        value["activeIncident"]["journal"] = summarize_journal(journal);
        value["activeIncident"]["journalKey"] =
            json!(format!("live_write_intent:{network}:{cursor}"));
    }
    sqlx::query("UPDATE indexer_state SET value=$2,updated_at_ms=$3 WHERE key=$1")
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handoff_cause_survives_retry_errors_and_successful_recovery() {
        let handoff = Observation {
            phase: "recovering",
            outcome: "handoff",
            reason: Some("missing_parent"),
            error: Some("missing input identity"),
            next_retry_at_ms: None,
        };
        let mut v = update(json!({}), handoff, "testnet-10", 1000, Some(900));
        let first = v["lastHandoff"].clone();
        assert_eq!(first["atMs"], 1000);
        assert_eq!(first["reason"], "missing_parent");
        assert_eq!(first["error"], "missing input identity");
        v = update(
            v,
            Observation {
                phase: "recovering",
                outcome: "retry",
                reason: Some("source_pending"),
                error: Some("REST publication pending"),
                next_retry_at_ms: Some(3000),
            },
            "testnet-10",
            2000,
            Some(900),
        );
        assert_eq!(v["lastError"], "REST publication pending");
        assert_eq!(v["lastHandoff"], first);
        v = update(
            v,
            Observation::new("recovering", "completed"),
            "testnet-10",
            4000,
            None,
        );
        v = update(
            v,
            Observation::new("watching", "watching"),
            "testnet-10",
            4001,
            None,
        );
        assert!(v["lastError"].is_null());
        assert!(v["reason"].is_null());
        assert!(v["pendingSinceMs"].is_null());
        assert_eq!(v["lastHandoff"], first);
        let mut next = Observation::new("recovering", "handoff");
        next.reason = Some("acceptance_conflict");
        next.error = Some("second failure");
        v = update(v, next, "testnet-10", 5000, Some(4900));
        assert_eq!(v["lastHandoff"]["atMs"], 5000);
        assert_eq!(v["lastHandoff"]["error"], "second failure");
    }

    #[test]
    fn retries_preserve_age_and_only_commits_advance_progress() {
        let mut v = update(
            json!({}),
            Observation::new("recovering", "attempt"),
            "testnet-10",
            1000,
            Some(1),
        );
        v = update(
            v,
            Observation::new("recovering", "attempt"),
            "testnet-10",
            9000,
            Some(1),
        );
        assert_eq!(v["pendingSinceMs"], 1);
        assert_eq!(v["phaseStartedAtMs"], 1000);
        assert_eq!(v["attempts"], 2);
        assert!(v["lastCommittedProgressAtMs"].is_null());
        v = update(
            v,
            Observation::new("recovering", "completed"),
            "testnet-10",
            10001,
            None,
        );
        assert_eq!(v["lastCommittedProgressAtMs"], 10001);
        assert_eq!(v["durationBuckets"]["10"], 1);
        assert!(v["durationBuckets"]["5"].is_null());
        v = update(
            v,
            Observation::new("watching", "watching"),
            "testnet-10",
            10002,
            None,
        );
        assert!(v["pendingSinceMs"].is_null());
        assert_eq!(v["completedTotal"], 1);
    }

    #[test]
    fn one_incident_tracks_handoff_retry_and_committed_replay() {
        let mut handoff = Observation::new("recovering", "handoff");
        handoff.reason = Some("acceptance_conflict");
        handoff.error = Some("old block spent the input");
        let mut state = update(json!({}), handoff, "testnet-10", 1000, Some(900));
        let id = state["activeIncident"]["id"].clone();
        assert_eq!(
            state["activeIncident"]["initialReason"],
            "acceptance_conflict"
        );
        assert_eq!(state["activeIncident"]["action"], "canonical_replay");
        let mut retry = Observation::new("recovering", "retry");
        retry.reason = Some("source_pending");
        retry.error = Some("REST has not published the window");
        state = update(state, retry, "testnet-10", 2000, Some(900));
        assert_eq!(state["activeIncident"]["id"], id);
        assert_eq!(
            state["activeIncident"]["initialReason"],
            "acceptance_conflict"
        );
        assert_eq!(state["activeIncident"]["lastReason"], "source_pending");
        assert_eq!(state["activeIncident"]["action"], "retry_canonical_replay");
        state = update(
            state,
            Observation::new("recovering", "attempt"),
            "testnet-10",
            2500,
            Some(900),
        );
        assert_eq!(state["activeIncident"]["lastReason"], "source_pending");
        state = update(
            state,
            Observation::new("recovering", "completed"),
            "testnet-10",
            3000,
            Some(900),
        );
        assert_eq!(state["activeIncident"]["status"], "replay_committed");
        state = update(
            state,
            Observation::new("recovering", "completed"),
            "testnet-10",
            3001,
            None,
        );
        assert_eq!(state["completedTotal"], 1);
        state = update(
            state,
            Observation::new("watching", "watching"),
            "testnet-10",
            3002,
            None,
        );
        assert!(state["activeIncident"].is_null());
        assert_eq!(state["lastIncident"]["id"], id);
        assert_eq!(state["lastIncident"]["status"], "replay_committed");
        assert_eq!(state["lastIncident"]["closedAtMs"], 3002);
    }

    #[test]
    fn blocked_and_terminal_incidents_require_investigation() {
        let mut blocked = Observation::new("blocked", "blocked");
        blocked.reason = Some("dependency_limit");
        let state = update(json!({}), blocked, "testnet-10", 1000, Some(950));
        assert_eq!(state["activeIncident"]["status"], "blocked");
        assert_eq!(
            state["activeIncident"]["action"],
            "investigate_retained_journal"
        );
        let mut terminal = Observation::new("stopped", "terminal");
        terminal.reason = Some("invariant_or_ownership_failure");
        let state = update(json!({}), terminal, "testnet-10", 1000, None);
        assert_eq!(state["activeIncident"]["status"], "stopped");
        assert_eq!(
            state["activeIncident"]["action"],
            "investigate_stopped_writer"
        );
    }

    #[test]
    fn external_journal_clear_does_not_claim_automatic_recovery() {
        let blocked = Observation {
            phase: "blocked",
            outcome: "blocked",
            reason: Some("dependency_limit"),
            error: Some("too many dependencies"),
            next_retry_at_ms: None,
        };
        let state = update(json!({}), blocked, "testnet-10", 1000, Some(900));
        let state = update(
            state,
            Observation::new("watching", "watching"),
            "testnet-10",
            2000,
            None,
        );
        assert_eq!(state["lastIncident"]["status"], "closed_unverified");
    }

    #[test]
    fn restart_guard_rejects_any_unverified_recovery_state() {
        assert!(watch_is_safe(&json!({})));
        assert!(watch_is_safe(&json!({"phase":"watching"})));
        assert!(watch_is_safe(
            &json!({"phase":"recovering","activeIncident":{"id":"testnet-10:900","openedAtMs":900,"status":"replay_committed","replayEvidence":{"incidentId":"testnet-10:900","journalCreatedAtMs":900,"verifiedAtMs":1000}}})
        ));
        for phase in ["recovering", "blocked", "stopped"] {
            assert!(!watch_is_safe(
                &json!({"phase":phase,"activeIncident":{"status":"recovering"}})
            ));
        }
        assert!(!watch_is_safe(
            &json!({"phase":"blocked","activeIncident":{"status":"replay_committed"}})
        ));
        assert!(!watch_is_safe(&json!({
            "phase":"recovering",
            "activeIncident":{
                "id":"testnet-10:900","openedAtMs":900,
                "replayEvidence":{"incidentId":"different:900","journalCreatedAtMs":900,"verifiedAtMs":1000}
            }
        })));
    }

    #[test]
    fn lost_delete_ack_keeps_replay_evidence_until_the_next_real_attempt() {
        let mut state = update(
            json!({}),
            Observation::new("recovering", "attempt"),
            "testnet-10",
            1000,
            Some(900),
        );
        state = update(
            state,
            Observation::new("recovering", "completed"),
            "testnet-10",
            1100,
            Some(900),
        );
        let mut lost_ack = Observation::new("recovering", "retry");
        lost_ack.reason = Some("database_unavailable");
        state = update(state, lost_ack, "testnet-10", 1200, None);
        assert_eq!(state["activeIncident"]["status"], "recovering");
        assert_eq!(
            state["activeIncident"]["replayEvidence"]["journalCreatedAtMs"],
            900
        );
        assert!(watch_is_safe(&state));
        state = update(
            state,
            Observation::new("recovering", "attempt"),
            "testnet-10",
            1300,
            Some(900),
        );
        assert!(!watch_is_safe(&state));
        assert!(state["activeIncident"]["replayEvidence"].is_null());
    }

    #[test]
    fn journal_summary_is_bounded_and_points_to_retained_evidence() {
        let journal = json!({
            "transactions": (0..30).map(|n| json!({
                "transaction_id": format!("{n:064x}"),
                "accepting_block_blue_score": 100 + n
            })).collect::<Vec<_>>(),
            "rejected_transactions": [json!({"transaction_id": "ff".repeat(32)})],
            "affected_transaction_ids": ["aa".repeat(32)],
            "observed_blocks": {"100": ["bb".repeat(32)]}
        });
        let summary = summarize_journal(&journal);
        assert_eq!(summary["acceptedCount"], 30);
        assert_eq!(summary["rejectedCount"], 1);
        assert_eq!(summary["affectedCount"], 1);
        assert_eq!(summary["firstScore"], 100);
        assert_eq!(summary["lastScore"], 129);
        assert_eq!(summary["transactionIds"].as_array().unwrap().len(), 8);
        assert_eq!(summary["observedWindows"], 1);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn recording_an_incident_preserves_the_authoritative_journal(pool: sqlx::PgPool) {
        let journal = json!({
            "transactions": [{
                "transaction_id": "11".repeat(32),
                "accepting_block_blue_score": 123
            }],
            "observed_blocks": {"120": ["22".repeat(32)]}
        });
        let journal_key = "live_write_intent:testnet-10:incident-test";
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,$3)")
            .bind(journal_key)
            .bind(&journal)
            .bind(100_i64)
            .execute(&pool)
            .await
            .unwrap();
        let mut observation = Observation::new("recovering", "handoff");
        observation.reason = Some("acceptance_conflict");
        observation.error = Some("old acceptance moved");
        record(&pool, "testnet-10", "incident-test", observation)
            .await
            .unwrap();
        let state: Value = sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
            .bind("live_recovery_state:testnet-10:incident-test")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state["activeIncident"]["journalKey"], journal_key);
        assert_eq!(state["activeIncident"]["journal"]["acceptedCount"], 1);
        assert_eq!(state["activeIncident"]["journal"]["firstScore"], 123);
        let retained: Value = sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
            .bind(journal_key)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(retained, journal);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn a_pod_restart_cannot_resume_an_unverified_incident(pool: sqlx::PgPool) {
        let key = "live_recovery_state:testnet-10:restart-test";
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,$3)")
            .bind(key)
            .bind(json!({"phase":"stopped","activeIncident":{"status":"stopped"}}))
            .bind(100_i64)
            .execute(&pool)
            .await
            .unwrap();
        assert!(ensure_watch_safe(&pool, "testnet-10", "restart-test")
            .await
            .is_err());
        sqlx::query("UPDATE indexer_state SET value=$2 WHERE key=$1")
            .bind(key)
            .bind(json!({"phase":"recovering","activeIncident":{"id":"testnet-10:100","openedAtMs":100,"status":"replay_committed","replayEvidence":{"incidentId":"testnet-10:100","journalCreatedAtMs":100,"verifiedAtMs":200}}}))
            .execute(&pool)
            .await
            .unwrap();
        ensure_watch_safe(&pool, "testnet-10", "restart-test")
            .await
            .unwrap();
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn replay_evidence_survives_a_crash_after_journal_deletion(pool: sqlx::PgPool) {
        let journal_key = "live_write_intent:testnet-10:crash-test";
        sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,$3)")
            .bind(journal_key)
            .bind(json!({"transactions":[{"transaction_id":"11".repeat(32)}]}))
            .bind(100_i64)
            .execute(&pool)
            .await
            .unwrap();
        record(
            &pool,
            "testnet-10",
            "crash-test",
            Observation::new("recovering", "attempt"),
        )
        .await
        .unwrap();
        // JournalRuntime records this only after canonical replay and source
        // recheck return successfully, before deleting the durable intent.
        record(
            &pool,
            "testnet-10",
            "crash-test",
            Observation::new("recovering", "completed"),
        )
        .await
        .unwrap();
        sqlx::query("DELETE FROM indexer_state WHERE key=$1")
            .bind(journal_key)
            .execute(&pool)
            .await
            .unwrap();
        let mut lost_ack = Observation::new("recovering", "retry");
        lost_ack.reason = Some("database_unavailable");
        lost_ack.error = Some("journal delete committed but acknowledgement was lost");
        record(&pool, "testnet-10", "crash-test", lost_ack)
            .await
            .unwrap();
        ensure_watch_safe(&pool, "testnet-10", "crash-test")
            .await
            .unwrap();
        let state: Value = sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
            .bind("live_recovery_state:testnet-10:crash-test")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state["activeIncident"]["status"], "recovering");
        assert_eq!(
            state["activeIncident"]["replayEvidence"]["journalCreatedAtMs"],
            state["activeIncident"]["openedAtMs"]
        );
    }
}
