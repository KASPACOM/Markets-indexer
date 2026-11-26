//! Same-score acceptance changes must not rebuild every active covenant.
use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{Persister, PgPersister};

async fn seed(pool: &PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let txs: Vec<_> = (0..512)
        .map(|i| {
            let mut tx = fixture[i % fixture.len()].clone();
            tx.transaction_id = format!("{:064x}", i + 100_000);
            tx
        })
        .collect();
    writer.persist_batch(&txs).await.unwrap();
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('ef',32),'hex'),blue_score,daa_score,parent_hashes,timestamp_ms+60,true,indexed_at_ms FROM blocks LIMIT 1;").execute(pool).await.unwrap();
}

async fn forbid_refresh(pool: &PgPool) {
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION refresh_covenant_summary(target_covenant_id BYTEA) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'full covenant rebuild forbidden'; END; $$;").execute(pool).await.unwrap();
}

async fn assert_parity(pool: &PgPool) {
    let mismatches: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM covenant_summaries s
        JOIN covenants c USING(covenant_id)
        LEFT JOIN LATERAL (
            SELECT count(*)::bigint AS n,coalesce(sum(amount_sompi),0)::bigint AS amount
            FROM covenant_utxos u WHERE u.covenant_id=s.covenant_id AND u.status='active'
        ) totals ON true
        LEFT JOIN LATERAL (
            SELECT u.txid,u.vout,u.address,u.created_block,b.blue_score
            FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block
            WHERE u.covenant_id=s.covenant_id AND u.status='active'
            ORDER BY b.blue_score DESC,u.txid DESC,u.vout DESC LIMIT 1
        ) latest ON true
        WHERE ROW(s.active_utxos,s.total_amount_sompi,s.current_address,s.latest_active_txid,
            s.latest_active_vout,s.latest_active_block,s.latest_active_blue_score)
        IS DISTINCT FROM ROW(totals.n,totals.amount,coalesce(latest.address,c.address),latest.txid,
            latest.vout,latest.created_block,latest.blue_score)
    "#,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(mismatches, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn same_score_acceptance_batch_avoids_full_summary_rebuild(pool: PgPool) {
    seed(&pool).await;
    assert_parity(&pool).await;
    forbid_refresh(&pool).await;
    let changed = sqlx::query("UPDATE covenant_utxos SET created_block=decode(repeat('ef',32),'hex') WHERE status='active'")
        .execute(&pool).await.unwrap().rows_affected();
    assert_eq!(changed, 512);
    assert_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn deferred_acceptance_refresh_only_skips_metadata_reassociation(pool: PgPool) {
    seed(&pool).await;
    forbid_refresh(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('tn12.defer_acceptance_summary_refresh','on',true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let changed = sqlx::query(
        "UPDATE covenant_utxos SET created_block=decode(repeat('ef',32),'hex') WHERE status='active'",
    )
    .execute(&mut *tx)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(changed, 512);
    let error = sqlx::query("UPDATE covenant_utxos SET amount_sompi=amount_sompi+1 WHERE txid=(SELECT txid FROM covenant_utxos LIMIT 1)")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("full covenant rebuild forbidden"));
    tx.rollback().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn same_score_acceptance_preserves_nonlatest_and_vout_ties(pool: PgPool) {
    seed(&pool).await;
    // Add a tie on both score and transaction ID; vout must break the tie.
    sqlx::raw_sql("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT u.txid,u.vout+1000,u.covenant_id,u.address,u.amount_sompi,u.script_pubkey,u.state,u.created_block,u.status FROM covenant_utxos u JOIN covenant_summaries s ON u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout LIMIT 1").execute(&pool).await.unwrap();
    let target: (Vec<u8>,i32,Vec<u8>) = sqlx::query_as("SELECT u.txid,u.vout,u.covenant_id FROM covenant_utxos u JOIN covenant_summaries s USING(covenant_id) WHERE s.latest_active_vout>=1000 AND u.txid=s.latest_active_txid AND u.vout<s.latest_active_vout LIMIT 1").fetch_one(&pool).await.unwrap();
    let before: (serde_json::Value, String) = sqlx::query_as(
        "SELECT to_jsonb(s),xmin::text FROM covenant_summaries s WHERE covenant_id=$1",
    )
    .bind(&target.2)
    .fetch_one(&pool)
    .await
    .unwrap();
    forbid_refresh(&pool).await;
    sqlx::query("UPDATE covenant_utxos SET created_block=decode(repeat('ef',32),'hex') WHERE txid=$1 AND vout=$2").bind(&target.0).bind(target.1).execute(&pool).await.unwrap();
    let after: (serde_json::Value, String) = sqlx::query_as(
        "SELECT to_jsonb(s),xmin::text FROM covenant_summaries s WHERE covenant_id=$1",
    )
    .bind(&target.2)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "nonlatest reassociation must not write the summary"
    );
    assert_parity(&pool).await;
    sqlx::query("UPDATE covenant_utxos u SET created_block=decode(repeat('ef',32),'hex') FROM covenant_summaries s WHERE u.covenant_id=$1 AND u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout AND s.covenant_id=u.covenant_id").bind(&target.2).execute(&pool).await.unwrap();
    assert_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn acceptance_summary_repairs_missing_inconsistent_and_changed_state(pool: PgPool) {
    seed(&pool).await;
    sqlx::raw_sql("CREATE TABLE test_summary_refresh_calls(n int); ALTER FUNCTION refresh_covenant_summary(bytea) RENAME TO test_original_refresh_covenant_summary; CREATE FUNCTION refresh_covenant_summary(target_covenant_id BYTEA) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN INSERT INTO test_summary_refresh_calls VALUES(1); PERFORM test_original_refresh_covenant_summary(target_covenant_id); END; $$;").execute(&pool).await.unwrap();
    let target: (Vec<u8>,i32,Vec<u8>) = sqlx::query_as("SELECT latest_active_txid,latest_active_vout,covenant_id FROM covenant_summaries WHERE active_utxos>0 LIMIT 1").fetch_one(&pool).await.unwrap();
    let cases = [
        ("missing", "DELETE FROM covenant_summaries WHERE covenant_id=$1"),
        ("bad block", "UPDATE covenant_summaries SET latest_active_block=decode(repeat('ef',32),'hex') WHERE covenant_id=$1"),
        ("bad score", "UPDATE covenant_summaries SET latest_active_blue_score=0 WHERE covenant_id=$1"),
        ("unequal score", "UPDATE blocks SET blue_score=blue_score+1 WHERE hash=decode(repeat('ef',32),'hex') AND $1::bytea IS NOT NULL"),
        ("address", "SELECT $1::bytea"),
        ("amount", "SELECT $1::bytea"),
        ("identity", "SELECT $1::bytea"),
    ];
    for (name, setup) in cases {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(setup)
            .bind(&target.2)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE covenant_utxos SET created_block=decode(repeat('ef',32),'hex'),address=CASE WHEN $3 THEN 'changed' ELSE address END,amount_sompi=amount_sompi+CASE WHEN $4 THEN 1 ELSE 0 END,vout=vout+CASE WHEN $5 THEN 2000 ELSE 0 END WHERE txid=$1 AND vout=$2").bind(&target.0).bind(target.1).bind(name=="address").bind(name=="amount").bind(name=="identity").execute(&mut *tx).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM test_summary_refresh_calls")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 1, "{name} must use full repair");
        let actual: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s WHERE covenant_id=$1",
        )
        .bind(&target.2)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT test_original_refresh_covenant_summary($1)")
            .bind(&target.2)
            .execute(&mut *tx)
            .await
            .unwrap();
        let expected: serde_json::Value = sqlx::query_scalar(
            "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s WHERE covenant_id=$1",
        )
        .bind(&target.2)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(actual, expected, "{name}: full summary parity");
        tx.rollback().await.unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_score_nonlatest_acceptance_preserves_summary_without_rebuild(pool: PgPool) {
    seed_later_winners(&pool).await;
    assert_parity(&pool).await;
    let snapshot = "SELECT jsonb_agg(jsonb_build_object('row',to_jsonb(s),'xmin',s.xmin::text) ORDER BY covenant_id) FROM covenant_summaries s";
    let before: serde_json::Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
    forbid_refresh(&pool).await;
    for target in ["ef", "fb"] {
        let changed=sqlx::query("UPDATE covenant_utxos SET created_block=decode(repeat($1,32),'hex') WHERE created_block<>decode(repeat('fa',32),'hex')")
            .bind(target).execute(&pool).await.unwrap().rows_affected();
        assert_eq!(changed, 512);
        assert_parity(&pool).await;
        let after: serde_json::Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        assert_eq!(
            before, after,
            "upward and downward nonlatest moves must not write summaries"
        );
    }
}

async fn seed_later_winners(pool: &PgPool) {
    seed(pool).await;
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fa',32),'hex'),max(blue_score)+100,0,ARRAY[]::bytea[],0,true,0 FROM blocks; INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fb',32),'hex'),min(blue_score)-1,0,ARRAY[]::bytea[],0,true,0 FROM blocks; UPDATE blocks SET blue_score=blue_score+1 WHERE hash=decode(repeat('ef',32),'hex');").execute(pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(md5(encode(s.covenant_id,'hex'))||md5(encode(s.covenant_id,'hex')),'hex'),0,u.covenant_id,u.address,u.amount_sompi,u.script_pubkey,u.state,decode(repeat('fa',32),'hex'),'active' FROM covenant_summaries s JOIN covenant_utxos u ON u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout").execute(pool).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_score_acceptance_repairs_stale_winner_and_crossing_batch(pool: PgPool) {
    seed_later_winners(&pool).await;
    sqlx::raw_sql("CREATE TABLE test_summary_refresh_calls(n int); ALTER FUNCTION refresh_covenant_summary(bytea) RENAME TO test_original_refresh_covenant_summary; CREATE FUNCTION refresh_covenant_summary(target_covenant_id BYTEA) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN INSERT INTO test_summary_refresh_calls VALUES(1); PERFORM test_original_refresh_covenant_summary(target_covenant_id); END; $$;").execute(&pool).await.unwrap();
    let target:(Vec<u8>,i32,Vec<u8>)=sqlx::query_as("SELECT txid,vout,covenant_id FROM covenant_utxos WHERE created_block<>decode(repeat('fa',32),'hex') LIMIT 1").fetch_one(&pool).await.unwrap();
    sqlx::query("UPDATE covenant_summaries SET latest_active_block=decode(repeat('ef',32),'hex') WHERE covenant_id=$1").bind(&target.2).execute(&pool).await.unwrap();
    sqlx::query("UPDATE covenant_utxos SET created_block=decode(repeat('ef',32),'hex') WHERE txid=$1 AND vout=$2").bind(&target.0).bind(target.1).execute(&pool).await.unwrap();
    let calls: i64 = sqlx::query_scalar("SELECT count(*) FROM test_summary_refresh_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(calls, 1, "a stale cached winner must use full repair");
    assert_parity(&pool).await;
    sqlx::query("TRUNCATE test_summary_refresh_calls")
        .execute(&pool)
        .await
        .unwrap();
    // AFTER row events see all changes: the previous winners move down while
    // historical rows move above them in the same statement.
    sqlx::query("UPDATE covenant_utxos SET created_block=CASE WHEN created_block=decode(repeat('fa',32),'hex') THEN decode(repeat('fb',32),'hex') ELSE decode(repeat('fa',32),'hex') END").execute(&pool).await.unwrap();
    let calls: i64 = sqlx::query_scalar("SELECT count(*) FROM test_summary_refresh_calls")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(calls > 0, "a changed winner must use full repair");
    assert_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn utxo_update_page_reserve_preserves_existing_vacuum_options(pool: PgPool) {
    let options: Vec<String> =
        sqlx::query_scalar("SELECT reloptions FROM pg_class WHERE oid='covenant_utxos'::regclass")
            .fetch_one(&pool)
            .await
            .unwrap();
    for required in [
        "fillfactor=80",
        "autovacuum_vacuum_scale_factor=0.02",
        "autovacuum_analyze_scale_factor=0.01",
        "autovacuum_vacuum_threshold=5000",
        "autovacuum_analyze_threshold=5000",
    ] {
        assert!(
            options.iter().any(|o| o == required),
            "missing option {required}: {options:?}"
        );
    }
    seed(&pool).await;
    assert_parity(&pool).await;
}
