use super::*;

#[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
#[sqlx::test(migrations = false)]
async fn budget_statement_timeout_classification_is_narrow(pool: sqlx::PgPool) {
    for (query, expected) in [
        ("DO $$ BEGIN RAISE SQLSTATE '57014' USING MESSAGE='canceling statement due to statement timeout'; END $$", true),
        ("DO $$ BEGIN RAISE SQLSTATE '57014' USING MESSAGE='canceling statement due to user request'; END $$", false),
        ("DO $$ BEGIN RAISE SQLSTATE '55P03' USING MESSAGE='canceling statement due to lock timeout'; END $$", false),
    ] {
        let error = anyhow::Error::new(sqlx::query(query).execute(&pool).await.unwrap_err())
            .context("query context must preserve structured cause");
        assert_eq!(is_budget_statement_timeout(&error, true), expected);
        assert!(!is_budget_statement_timeout(&error, false),
            "normal writer and stricter configured caps must not split");
    }
    assert!(!is_budget_statement_timeout(
        &anyhow::anyhow!("canceling statement due to statement timeout"),
        true
    ));
}

#[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
#[sqlx::test(migrations = "./migrations")]
async fn budget_progress_statement_timeout_splits_and_commits(pool: sqlx::PgPool) {
    let (writer, txs) = guarded_writer(pool.clone()).await;
    // The first 16-row statement exceeds the server cap; each half fits.
    // Unlike the existing aggregate-deadline fixture, no sequence of short
    // statements is needed to trigger this failure.
    sqlx::raw_sql(
        r#"
CREATE OR REPLACE FUNCTION test_budget_blocks() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM nextval('test_budget_attempts'); RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION test_budget_rows() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
SELECT count(*) INTO n FROM inserted_rows;
IF n / TG_ARGV[0]::float > 8 THEN PERFORM pg_sleep(0.15); END IF;
RETURN NULL;
END $$;
"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        writer.persist_batch(&txs),
    )
    .await
    .expect("split retries must terminate")
    .expect("server budget timeout must split and commit smaller prefixes");
    assert_eq!(result.actions_inserted, 32);
    let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM test_budget_attempts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(attempts, 3, "16 rolls back, then 8 + 8 commit");
    let ids: Vec<Vec<u8>> = txs
        .iter()
        .map(|tx| hex::decode(&tx.transaction_id).unwrap())
        .collect();
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=ANY($1::bytea[])")
            .bind(&ids)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored, 32,
        "rolled-back attempt must leave no extra actions"
    );
}

async fn guarded_writer(pool: sqlx::PgPool) -> (PgPersister, Vec<RestTransaction>) {
    let (writer, txs) = seed_budget_fixture(pool.clone()).await;
    sqlx::raw_sql(include_str!(
        "../../tests/fixtures/generic-writer-budget-delays.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    // Every successful write must use the budgeted generic connection. A
    // fallback into the ordinary scalar writer fails this assertion in SQL.
    sqlx::raw_sql(r#"
CREATE FUNCTION test_reject_scalar_writer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
IF current_setting('statement_timeout')::interval > interval '75 milliseconds' THEN
RAISE EXCEPTION 'unexpected unbudgeted scalar writer';
END IF;
RETURN NULL;
END $$;
CREATE TRIGGER a_test_reject_scalar_writer BEFORE INSERT ON blocks FOR EACH STATEMENT EXECUTE FUNCTION test_reject_scalar_writer();
"#).execute(&pool).await.unwrap();
    (
        writer
            .with_generic_bulk_persist(true)
            .with_generic_bulk_max_txs(16)
            .with_generic_writer_budget(true),
        txs,
    )
}

#[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
#[sqlx::test(migrations = "./migrations")]
async fn budget_progress_odd_tail_stays_on_generic_writer(pool: sqlx::PgPool) {
    let (writer, txs) = guarded_writer(pool.clone()).await;
    let result = writer.persist_batch(&txs[..15]).await.unwrap();
    assert_eq!(result.actions_inserted, 30);
    let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM test_budget_attempts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(attempts, 4, "15 rolls back, then 7 + 7 + 1 commit");
}

#[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
#[sqlx::test(migrations = "./migrations")]
async fn budget_progress_dependency_boundary_keeps_producer_first(pool: sqlx::PgPool) {
    let (writer, txs) = guarded_writer(pool.clone()).await;
    let parent = &txs[0];
    let mut child = parent.clone();
    child.transaction_id = "fe".repeat(32);
    child.inputs[0].previous_outpoint_hash = parent.transaction_id.clone();
    child.inputs[0].previous_outpoint_index = parent.outputs[0].index.to_string();
    child.inputs[0].previous_outpoint_amount = Some(parent.outputs[0].amount);
    child.inputs[0].previous_outpoint_script = Some(parent.outputs[0].script_public_key.clone());
    child.outputs[0].transaction_id = child.transaction_id.clone();
    child.outputs[0].amount -= 1;
    let mut reversed = vec![child.clone()];
    reversed.extend(txs);
    let result = writer.persist_batch(&reversed).await.unwrap();
    assert_eq!(result.actions_inserted, 34);
    let spender: Vec<u8> = sqlx::query_scalar(
        "SELECT spent_by_txid FROM covenant_utxos WHERE txid=decode($1,'hex') AND vout=$2",
    )
    .bind(&child.inputs[0].previous_outpoint_hash)
    .bind(
        child.inputs[0]
            .previous_outpoint_index
            .parse::<i32>()
            .unwrap(),
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(spender, hex::decode(&child.transaction_id).unwrap());
}

#[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
#[sqlx::test(migrations = "./migrations")]
async fn budget_progress_shared_outpoint_rejects_second_spender(pool: sqlx::PgPool) {
    let (writer, txs) = guarded_writer(pool.clone()).await;
    let mut competing = txs[0].clone();
    competing.transaction_id = "fe".repeat(32);
    competing.outputs[0].transaction_id = competing.transaction_id.clone();
    let error = writer
        .persist_batch(&[txs[0].clone(), competing.clone()])
        .await
        .unwrap_err();
    assert!(
        error
            .downcast_ref::<crate::persist::AcceptanceEvidenceConflict>()
            .is_some(),
        "{error:#}"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=decode($1,'hex')")
            .bind(&competing.transaction_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
#[sqlx::test(migrations = "./migrations")]
async fn budget_progress_minimum_batch_failure_is_terminal(pool: sqlx::PgPool) {
    let (writer, txs) = guarded_writer(pool.clone()).await;
    sqlx::raw_sql(
        r#"
CREATE OR REPLACE FUNCTION test_budget_rows() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_sleep(0.05); RETURN NULL; END $$;
"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        writer.persist_batch(&txs),
    )
    .await
    .expect("minimum batch must stop retrying")
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<crate::persist::TransientPersistError>()
            .unwrap()
            .kind,
        crate::persist::PersistTransientKind::WriterBudgetExceeded
    );
    let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM test_budget_attempts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(attempts, 5, "16,8,4,2,1 are the only attempts");
    let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
}
