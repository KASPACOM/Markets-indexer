use super::*;
use crate::persist::ProbeReason;

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_freshness_rejects_each_partial_representation(pool: sqlx::PgPool) {
    let (_, txs) = seed_budget_fixture(pool.clone()).await;
    for (kind, tx) in txs.iter().take(3).enumerate() {
        let tid = hex::decode(&tx.transaction_id).unwrap();
        let parent = hex::decode(&tx.inputs[0].previous_outpoint_hash).unwrap();
        // Isolate each existence check. These deliberately partial rows must
        // stop the probe, regardless of whether ordinary replay could repair them.
        match kind {
            0 => {
                sqlx::query("INSERT INTO covenant_utxos
                    (txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status)
                    SELECT $1,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status
                    FROM covenant_utxos WHERE txid=$2")
                    .bind(&tid).bind(&parent).execute(&pool).await.unwrap();
            }
            1 => {
                sqlx::query("UPDATE covenant_actions SET txid=$1 WHERE txid=$2")
                    .bind(&tid)
                    .bind(&parent)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::query("UPDATE covenants SET genesis_txid=$1 WHERE genesis_txid=$2")
                    .bind(&tid)
                    .bind(&parent)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }
        let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        let result = PgPersister::new(pool.clone())
            .persist_guarded_generic_probe(std::slice::from_ref(tx))
            .await;
        assert_eq!(
            result.reason,
            ProbeReason::GenericIneligible,
            "representation {kind}"
        );
        assert!(result.confirmed_txids.is_empty());
        let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, after, "representation {kind}");
    }
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_freshness_rejects_spend_without_actions_or_outputs(pool: sqlx::PgPool) {
    let (writer, mut txs) = seed_budget_fixture(pool.clone()).await;
    txs[0].outputs.clear();
    writer.persist_tx(&txs[0]).await.unwrap();
    sqlx::query("DELETE FROM covenant_actions WHERE txid=$1")
        .bind(hex::decode(&txs[0].transaction_id).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    let result = writer.persist_guarded_generic_probe(&txs[..1]).await;
    assert_eq!(result.reason, ProbeReason::GenericIneligible);
    assert!(result.confirmed_txids.is_empty());
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_freshness_rechecks_after_concurrent_writer_commits(pool: sqlx::PgPool) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    sqlx::raw_sql(
        r#"
CREATE SEQUENCE test_probe_writer_started;
CREATE FUNCTION pause_probe_competitor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM nextval('test_probe_writer_started');
 PERFORM pg_advisory_xact_lock(982617::bigint);
 RETURN NULL;
END $$;
CREATE TRIGGER pause_probe_competitor AFTER INSERT ON covenant_actions
FOR EACH STATEMENT EXECUTE FUNCTION pause_probe_competitor();
"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(982617::bigint)")
        .execute(&mut *gate)
        .await
        .unwrap();
    let tx = txs[0].clone();
    let competitor = tokio::spawn(async move { writer.persist_tx(&tx).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let started: bool =
                sqlx::query_scalar("SELECT is_called FROM test_probe_writer_started")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            if started {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("competing writer must hold the writer lock");
    // The competitor's canonical rows are still uncommitted at this preflight.
    let tid = hex::decode(&txs[0].transaction_id).unwrap();
    let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1")
        .bind(&tid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(visible, 0);
    let probe_pool = pool.clone();
    let fixture = txs[..1].to_vec();
    let probe = tokio::spawn(async move {
        PgPersister::new(probe_pool)
            .persist_guarded_generic_probe(&fixture)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let queued: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted
                 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
                 AND classid=1414410546::oid AND objid=1262699314::oid)",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            if queued {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("probe must queue behind the competing writer");
    gate.commit().await.unwrap();
    competitor.await.unwrap().unwrap();
    let result = probe.await.unwrap();
    assert_eq!(result.reason, ProbeReason::GenericIneligible);
    assert!(result.confirmed_txids.is_empty());
    assert!(result.uncertain_txids.is_empty());
    assert_eq!(result.remaining_txids, vec![txs[0].transaction_id.clone()]);
    let actions: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1")
        .bind(tid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        actions, 2,
        "only the competing writer's output and spend remain"
    );
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_freshness_rejects_already_persisted_transaction(pool: sqlx::PgPool) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    writer.persist_tx(&txs[0]).await.unwrap();
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    let result = writer.persist_guarded_generic_probe(&txs[..1]).await;
    assert_eq!(result.reason, ProbeReason::GenericIneligible);
    assert!(result.confirmed_txids.is_empty());
    assert!(result.uncertain_txids.is_empty());
    assert_eq!(result.remaining_txids, vec![txs[0].transaction_id.clone()]);
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    // Ordinary replay retains its existing idempotent behavior.
    assert!(PgPersister::new(pool)
        .try_persist_generic_batch_inner(&txs[..1], false)
        .await
        .unwrap()
        .is_some());
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_acknowledged_post_write_error_has_hold_bound(pool: sqlx::PgPool) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    sqlx::raw_sql(r#"
CREATE FUNCTION fail_probe_actions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'injected post-write error'; END $$;
CREATE TRIGGER fail_probe_actions AFTER INSERT ON covenant_actions FOR EACH STATEMENT EXECUTE FUNCTION fail_probe_actions();
"#).execute(&pool).await.unwrap();
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    let result = writer.persist_guarded_generic_probe(&txs).await;
    assert_eq!(result.reason, ProbeReason::DatabaseOrEvidenceError);
    assert_eq!(result.attempts.len(), 1);
    assert_eq!(
        result.attempts[0].hold_upper_bound_us,
        Some(result.attempts[0].elapsed_us)
    );
    assert!(result.confirmed_txids.is_empty());
    assert!(result.uncertain_txids.is_empty());
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_database_ineligibility_after_split_stops(pool: sqlx::PgPool) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    sqlx::raw_sql(include_str!(
        "../../tests/fixtures/generic-writer-budget-delays.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    // Queue this transaction behind the first writer attempt. PostgreSQL's
    // advisory-lock queue places it before the retry, so eligibility changes
    // only after the budget rollback, without timing-dependent sleeps.
    let change = async {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let started: bool =
                    sqlx::query_scalar("SELECT is_called FROM test_budget_attempts")
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                if started {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            let mut update = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL statement_timeout='1s'")
                .execute(&mut *update)
                .await
                .unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(6074847039450202930::bigint)")
                .execute(&mut *update)
                .await
                .unwrap();
            sqlx::query("UPDATE covenants SET classification_status='matched'")
                .execute(&mut *update)
                .await
                .unwrap();
            update.commit().await.unwrap();
        })
        .await
        .expect("eligibility update must reach the rollback boundary");
    };
    let (result, ()) = tokio::join!(writer.persist_guarded_generic_probe(&txs), change);
    assert_eq!(result.reason, ProbeReason::GenericIneligible);
    assert_eq!(
        result.attempts.iter().map(|a| a.count).collect::<Vec<_>>(),
        vec![16, 8]
    );
    assert!(result.confirmed_txids.is_empty());
    assert_eq!(result.remaining_txids.len(), 16);
    let ids: Vec<_> = txs
        .iter()
        .map(|tx| hex::decode(&tx.transaction_id).unwrap())
        .collect();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=ANY($1::bytea[])")
            .bind(ids)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_database_ineligibility_never_uses_scalar(pool: sqlx::PgPool) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    sqlx::query("UPDATE covenants SET classification_status='matched'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(r#"
CREATE FUNCTION reject_probe_scalar() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'scalar path must not run'; END $$;
CREATE TRIGGER reject_probe_scalar BEFORE INSERT ON blocks FOR EACH STATEMENT EXECUTE FUNCTION reject_probe_scalar();
"#).execute(&pool).await.unwrap();
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    let outcome = writer.persist_guarded_generic_probe(&txs).await;
    assert_eq!(outcome.reason, ProbeReason::GenericIneligible);
    assert!(outcome.confirmed_txids.is_empty());
    assert_eq!(outcome.attempts.len(), 1);
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_invalid_fixtures_reject_before_writes(pool: sqlx::PgPool) {
    let (_, txs) = seed_budget_fixture(pool.clone()).await;
    let mut oversized = txs.clone();
    oversized.push(txs[0].clone());
    let duplicate = vec![txs[0].clone(), txs[0].clone()];
    let mut dependency = txs[..2].to_vec();
    dependency[1].inputs[0].previous_outpoint_hash = dependency[0].transaction_id.clone();
    let mut ineligible = txs.clone();
    ineligible[0].payload = Some("01".into());
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    for fixture in [vec![], oversized, duplicate, dependency, ineligible] {
        let result = PgPersister::new(pool.clone())
            .persist_guarded_generic_probe(&fixture)
            .await;
        assert_eq!(result.reason, ProbeReason::InvalidInput);
        assert!(result.attempts.is_empty());
        assert!(result.confirmed_txids.is_empty());
        assert_eq!(result.remaining_txids.len(), fixture.len());
    }
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_partial_prefix_reports_exact_commits(pool: sqlx::PgPool) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    sqlx::raw_sql(include_str!(
        "../../tests/fixtures/generic-writer-budget-delays.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(r#"
CREATE FUNCTION fail_probe_suffix() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
IF EXISTS(SELECT 1 FROM covenant_actions WHERE action='spend') THEN PERFORM pg_sleep(0.12); END IF;
RETURN NULL;
END $$;
CREATE TRIGGER z_fail_probe_suffix AFTER INSERT ON blocks FOR EACH STATEMENT EXECUTE FUNCTION fail_probe_suffix();
"#).execute(&pool).await.unwrap();
    let result = writer.persist_guarded_generic_probe(&txs).await;
    assert_eq!(result.reason, ProbeReason::BudgetExhausted);
    let ids: Vec<_> = txs.iter().map(|tx| tx.transaction_id.clone()).collect();
    assert_eq!(result.confirmed_txids, ids[..8]);
    assert_eq!(result.remaining_txids, ids[8..]);
    assert!(result.uncertain_txids.is_empty());
    assert_eq!(
        result.attempts.iter().map(|a| a.count).collect::<Vec<_>>(),
        vec![16, 8, 8, 4, 2, 1]
    );
    let stored: Vec<String> = sqlx::query_scalar("SELECT DISTINCT encode(txid,'hex') FROM covenant_actions WHERE txid=ANY($1::bytea[]) ORDER BY 1")
        .bind(ids.iter().map(|id|hex::decode(id).unwrap()).collect::<Vec<_>>())
        .fetch_all(&pool).await.unwrap();
    let mut expected = ids[..8].to_vec();
    expected.sort();
    assert_eq!(stored, expected);
    sqlx::raw_sql("DROP TRIGGER z_fail_probe_suffix ON blocks; DROP TRIGGER test_budget_blocks ON blocks; DROP TRIGGER test_budget_covenants ON covenants; DROP TRIGGER test_budget_outputs ON covenant_utxos; DROP TRIGGER test_budget_inputs ON covenant_utxos; DROP TRIGGER test_budget_actions ON covenant_actions;")
        .execute(&pool).await.unwrap();
    let repeated = PgPersister::new(pool.clone())
        .persist_guarded_generic_probe(&txs)
        .await;
    assert_eq!(repeated.reason, ProbeReason::GenericIneligible);
    assert!(repeated.confirmed_txids.is_empty());
    // A reconciled prefix is not new probe work. Only the untouched suffix can
    // be admitted to a subsequent probe; ordinary replay below still takes all.
    let complete = PgPersister::new(pool.clone())
        .persist_guarded_generic_probe(&txs[8..])
        .await;
    assert_eq!(complete.reason, ProbeReason::Completed);
    assert_eq!(complete.confirmed_txids, ids[8..]);
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    PgPersister::new(pool.clone())
        .persist_batch(&txs)
        .await
        .unwrap();
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "ordinary replay must preserve all canonical rows"
    );
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_lost_commit_ack_does_not_retry(pool: sqlx::PgPool) {
    check_lost_transaction_ack(pool, true, false, true).await;
}

#[ignore = "serial local PostgreSQL recovery CI"]
#[sqlx::test(migrations = "./migrations")]
async fn probe_lost_rollback_ack_does_not_retry(pool: sqlx::PgPool) {
    check_lost_transaction_ack(pool, true, true, true).await;
}
