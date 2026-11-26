use super::*;
use crate::Persister;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn exact_cohort_rejects_numeric_representation_change(pool: PgPool) {
    let fixture: Vec<tn12_indexer_core::RestTransaction> = serde_json::from_str(include_str!(
        "../../tests/fixtures/tn10-dense-generic-32.json"
    ))
    .unwrap();
    let writer = PgPersister::new(pool.clone());
    writer.persist_tx(&fixture[0]).await.unwrap();
    let old = hex::decode(fixture[0].accepting_block_hash.as_ref().unwrap()).unwrap();
    sqlx::query("UPDATE covenant_utxos SET state='{\"value\":1.00}'::jsonb WHERE created_block=$1")
        .bind(&old)
        .execute(&pool)
        .await
        .unwrap();
    let before: String =
        sqlx::query_scalar("SELECT state::text FROM covenant_utxos WHERE created_block=$1 LIMIT 1")
            .bind(&old)
            .fetch_one(&pool)
            .await
            .unwrap();
    let captured = writer
        .historical_acceptance_cohort(&[old.clone()])
        .await
        .unwrap();
    sqlx::query("UPDATE covenant_utxos SET state='{\"value\":1.0}'::jsonb WHERE created_block=$1")
        .bind(&old)
        .execute(&pool)
        .await
        .unwrap();
    let after: String =
        sqlx::query_scalar("SELECT state::text FROM covenant_utxos WHERE created_block=$1 LIMIT 1")
            .bind(&old)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(
        before, after,
        "PostgreSQL must preserve the numeric scale difference"
    );
    let normalized = writer.historical_acceptance_cohort(&[old]).await.unwrap();
    assert_eq!(
        captured.digest(),
        normalized.digest(),
        "Test must exercise normalization losing representation"
    );
    let mut tx = pool.begin().await.unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    let result = verify_cohort(
        &mut tx,
        &captured,
        tokio::time::Instant::now() + std::time::Duration::from_millis(350),
    )
    .await;
    tx.rollback().await.unwrap();
    assert!(
        result.is_err(),
        "Exact database row representation changed but guard accepted it"
    );
}

async fn fixture(pool: &PgPool) -> (PgPersister, Vec<u8>, HistoricalAcceptanceCohort) {
    let rows: Vec<tn12_indexer_core::RestTransaction> = serde_json::from_str(include_str!(
        "../../tests/fixtures/tn10-dense-generic-32.json"
    ))
    .unwrap();
    let writer = PgPersister::new(pool.clone());
    writer.persist_tx(&rows[0]).await.unwrap();
    let old = hex::decode(rows[0].accepting_block_hash.as_ref().unwrap()).unwrap();
    sqlx::query("UPDATE covenant_utxos SET state=$2 WHERE created_block=$1")
        .bind(&old)
        .bind(serde_json::json!({"nested":[null,{"text":"שלום\\\"\n"}],"number":1.0}))
        .execute(pool)
        .await
        .unwrap();
    let captured = writer
        .historical_acceptance_cohort(&[old.clone()])
        .await
        .unwrap();
    (writer, old, captured)
}

async fn check(
    pool: &PgPool,
    writer: &PgPersister,
    captured: &HistoricalAcceptanceCohort,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    writer.acquire_persist_writer_lock(&mut tx).await?;
    let result = verify_cohort(
        &mut tx,
        captured,
        tokio::time::Instant::now() + std::time::Duration::from_millis(350),
    )
    .await;
    tx.rollback().await?;
    result
}

#[sqlx::test(migrations = "./migrations")]
async fn exact_cohort_full_rows_and_metadata_fail_closed(pool: PgPool) {
    let (writer, old, captured) = fixture(&pool).await;
    check(&pool, &writer, &captured).await.unwrap();
    // Comparison metadata must never change the existing normalized proof.
    let expected_bytes = serde_json::to_vec(&(&captured.old_hashes, &captured.references)).unwrap();
    assert_eq!(captured.normalized_rows(), expected_bytes);
    assert_eq!(
        captured.digest(),
        &tn12_indexer_core::blake2b_256(&expected_bytes)
    );
    for mutation in [
        "missing_metadata",
        "duplicate",
        "missing",
        "changed",
        "kind",
        "oversize",
    ] {
        let mut bad = captured.clone();
        if mutation == "missing_metadata" {
            bad.comparison_rows = None;
        } else if mutation == "oversize" {
            bad.comparison_rows = Some("x".repeat(MAX_COMPARISON_BYTES + 1));
        } else {
            let mut values: Vec<Value> =
                serde_json::from_str(bad.comparison_rows.as_ref().unwrap()).unwrap();
            match mutation {
                "duplicate" => values.push(values[0].clone()),
                "missing" => {
                    values.pop();
                }
                "changed" => values[0]["data"] = Value::String("{}".into()),
                "kind" => values[0]["kind"] = Value::String("unknown".into()),
                _ => unreachable!(),
            }
            bad.comparison_rows = Some(serde_json::to_string(&values).unwrap());
        }
        assert!(
            check(&pool, &writer, &bad).await.is_err(),
            "accepted {mutation}"
        );
    }
    for sql in [
        "UPDATE covenant_utxos SET state=NULL WHERE created_block=$1",
        "DELETE FROM covenant_actions WHERE block_hash=$1",
        "UPDATE covenants SET address=address||'changed' WHERE genesis_block=$1",
    ] {
        let mut tx = pool.begin().await.unwrap();
        writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
        assert!(
            sqlx::query(sql)
                .bind(&old)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected()
                > 0
        );
        assert!(verify_cohort(
            &mut tx,
            &captured,
            tokio::time::Instant::now() + std::time::Duration::from_millis(350)
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        check(&pool, &writer, &captured).await.unwrap();
    }
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("ALTER TABLE covenant_utxos ADD COLUMN future_field text")
        .execute(&mut *tx)
        .await
        .unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    assert!(verify_cohort(
        &mut tx,
        &captured,
        tokio::time::Instant::now() + std::time::Duration::from_millis(350)
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    check(&pool, &writer, &captured).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn exact_cohort_all_kinds_reference_boundary(pool: PgPool) {
    sqlx::query("INSERT INTO blocks VALUES(decode(repeat('ac',32),'hex'),100,100,ARRAY[]::bytea[],100,true,100)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) VALUES(decode(repeat('bc',32),'hex'),'boundary',0,decode(repeat('cc',32),'hex'),decode(repeat('dc',32),'hex'),0,decode(repeat('ac',32),'hex'),100)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,address,amount_sompi,script_pubkey,created_block,spent_block,spent_by_txid,status) SELECT decode(lpad(to_hex(n),64,'0'),'hex'),0,'boundary',1,decode('00','hex'),decode(repeat('ac',32),'hex'),decode(repeat('ac',32),'hex'),decode(repeat('dc',32),'hex'),'spent' FROM generate_series(1,4095) n").execute(&pool).await.unwrap();
    let insert_action="INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action) VALUES(decode(repeat('bc',32),'hex'),decode(repeat('dc',32),'hex'),decode(repeat('ac',32),'hex'),100,'deploy')";
    sqlx::query(insert_action).execute(&pool).await.unwrap();
    let writer = PgPersister::new(pool.clone());
    let old = vec![0xac; 32];
    let captured = writer
        .historical_acceptance_cohort(&[old.clone()])
        .await
        .unwrap();
    assert_eq!(captured.reference_count(), 8192);
    for kind in ["created", "spent", "action", "genesis"] {
        assert!(captured.references.iter().any(|r| r.kind == kind));
    }
    check(&pool, &writer, &captured).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(
        insert_action.replace("repeat('dc'", "repeat('dd'"),
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(writer.historical_acceptance_cohort(&[old]).await.is_err());
    assert!(check(&pool, &writer, &captured).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn exact_cohort_raw_bound_and_timeout_release_writer(pool: PgPool) {
    let (writer, old, captured) = fixture(&pool).await;
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM covenant_utxos WHERE created_block=$1 FOR UPDATE")
        .bind(&old)
        .fetch_all(&mut *blocker)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    let result = verify_cohort(
        &mut tx,
        &captured,
        tokio::time::Instant::now() + std::time::Duration::from_millis(25),
    )
    .await;
    assert!(
        result.is_err(),
        "row lock must exceed the short comparison deadline"
    );
    tx.rollback().await.unwrap();
    blocker.rollback().await.unwrap();
    check(&pool, &writer, &captured).await.unwrap();
    let maps: i64 = sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_maps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(maps, 0);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE covenant_utxos SET state=jsonb_build_object('large',repeat('x',16777217)) WHERE created_block=$1").bind(&old).execute(&mut *tx).await.unwrap();
    assert!(
        read_cohort(&mut tx, &[old], false, None).await.is_err(),
        "oversized raw row must fail capture"
    );
    tx.rollback().await.unwrap();
    check(&pool, &writer, &captured).await.unwrap();
}
