use sqlx::PgPool;
use tn12_indexer_db::{Persister, PgPersister};

async fn seed(pool: &PgPool, count: i64) {
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
        VALUES(decode(repeat('11',32),'hex'),100,100,ARRAY[]::bytea[],1000,true,1000),
        (decode(repeat('22',32),'hex'),200,200,ARRAY[]::bytea[],2000,true,2000);
        INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms)
        VALUES(decode(repeat('44',32),'hex'),'test',0,decode(repeat('44',32),'hex'),decode(repeat('aa',32),'hex'),0,decode(repeat('11',32),'hex'),1000);")
        .execute(pool).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL tn12.defer_bulk_utxo_summaries='on'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status)
        SELECT decode(lpad(to_hex(i),64,'0'),'hex'),0,decode(repeat('44',32),'hex'),'test',1,'\\x51',decode(repeat('11',32),'hex'),'active'
        FROM generate_series(1,$1::bigint) i")
        .bind(count).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

async fn backfill(pool: &PgPool) {
    for _ in 0..4000 {
        let state: serde_json::Value =
            sqlx::query_scalar("SELECT active_output_order_backfill_step()")
                .fetch_one(pool)
                .await
                .unwrap();
        if state["phase"] == "ready" {
            return;
        }
    }
    panic!("backfill failed to complete");
}

async fn assert_parity(pool: &PgPool) {
    let differences: i64 = sqlx::query_scalar("WITH expected AS (
        SELECT u.txid,u.vout,u.covenant_id,u.created_block,b.blue_score
        FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block
        WHERE u.status='active' AND u.covenant_id IS NOT NULL
    ) SELECT count(*) FROM (
        (SELECT * FROM expected EXCEPT SELECT txid,vout,covenant_id,created_block,blue_score FROM covenant_active_output_order)
        UNION ALL
        (SELECT txid,vout,covenant_id,created_block,blue_score FROM covenant_active_output_order EXCEPT SELECT * FROM expected)
    ) delta").fetch_one(pool).await.unwrap();
    assert_eq!(differences, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn backfill_resumes_and_triggers_preserve_active_membership(pool: PgPool) {
    seed(&pool, 1001).await;
    // Simulate rows that existed before installing the maintenance trigger.
    sqlx::query("DELETE FROM covenant_active_output_order")
        .execute(&pool)
        .await
        .unwrap();
    let state: serde_json::Value = sqlx::query_scalar("SELECT active_output_order_backfill_step()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(state["processed_rows"], 500);
    assert_eq!(state["phase"], "fill");
    // Mutation behind the durable cursor must not be resurrected on resume.
    sqlx::query("UPDATE covenant_utxos SET status='spent',spent_block=decode(repeat('22',32),'hex') WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex')")
        .execute(&pool).await.unwrap();
    backfill(&pool).await;
    assert_parity(&pool).await;
    sqlx::raw_sql("UPDATE covenant_utxos SET status='active',spent_block=NULL WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex');
        UPDATE covenant_utxos SET created_block=decode(repeat('22',32),'hex') WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex');
        UPDATE blocks SET blue_score=250 WHERE hash=decode(repeat('22',32),'hex');")
        .execute(&pool).await.unwrap();
    assert_parity(&pool).await;
    let latest: (String, i64) = sqlx::query_as("SELECT encode(txid,'hex'),blue_score FROM latest_active_covenant_output(decode(repeat('44',32),'hex'))")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(latest, (format!("{:064x}", 1), 250));
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM covenant_utxos WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex')")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_parity(&pool).await;
    sqlx::query("UPDATE covenant_utxos SET covenant_id=NULL WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex')")
        .execute(&pool).await.unwrap();
    assert_parity(&pool).await;
    sqlx::query("DELETE FROM blocks WHERE hash=decode(repeat('11',32),'hex')")
        .execute(&pool)
        .await
        .unwrap();
    assert_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn source_verification_rejects_stale_ordering(pool: PgPool) {
    seed(&pool, 2).await;
    // The forward audit must prevent enabling a deliberately corrupt rank.
    sqlx::query("UPDATE covenant_active_output_order_progress SET phase='verify_source'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenant_active_output_order SET blue_score=999")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query("SELECT active_output_order_backfill_step()")
        .execute(&pool)
        .await
        .is_err());
    let phase: String =
        sqlx::query_scalar("SELECT phase FROM covenant_active_output_order_progress")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(phase, "verify_source");
}

#[sqlx::test(migrations = "./migrations")]
async fn outpoint_identity_updates_preserve_ordering_and_rollback(pool: PgPool) {
    seed(&pool, 2).await;
    backfill(&pool).await;
    sqlx::query("UPDATE covenant_utxos SET txid=decode(repeat('ff',32),'hex'),vout=4 WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex')")
        .execute(&pool).await.unwrap();
    assert_parity(&pool).await;
    let latest:(String,i32)=sqlx::query_as("SELECT encode(txid,'hex'),vout FROM latest_active_covenant_output(decode(repeat('44',32),'hex'))")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(latest,("ff".repeat(32),4));
    let mut tx=pool.begin().await.unwrap();
    sqlx::query("UPDATE covenant_utxos SET txid=decode(repeat('ee',32),'hex'),vout=5 WHERE txid=decode(repeat('ff',32),'hex')")
        .execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert_parity(&pool).await;
    let after:(String,i32)=sqlx::query_as("SELECT encode(txid,'hex'),vout FROM latest_active_covenant_output(decode(repeat('44',32),'hex'))")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(after,latest);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "large-family lookup performance gate; run in isolated release CI"]
async fn large_family_lookup_500000_outputs(pool: PgPool) {
    seed(&pool, 500_000).await;
    // Newest global blocks deliberately have no outputs in this family.
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
        SELECT decode(lpad(to_hex(i),64,'0'),'hex'),i,i,ARRAY[]::bytea[],i,true,i FROM generate_series(1000,1100) i")
        .execute(&pool).await.unwrap();
    backfill(&pool).await;
    assert_parity(&pool).await;
    sqlx::query("ANALYZE covenant_active_output_order")
        .execute(&pool)
        .await
        .unwrap();
    let plan: serde_json::Value = sqlx::query_scalar("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON)
        SELECT txid,vout,created_block,blue_score FROM covenant_active_output_order
        WHERE covenant_id=decode(repeat('44',32),'hex') ORDER BY blue_score DESC,txid DESC,vout DESC LIMIT 1")
        .fetch_one(&pool).await.unwrap();
    assert!(plan
        .to_string()
        .contains("covenant_active_output_latest_idx"));
    assert!(
        plan[0]["Execution Time"].as_f64().unwrap() < 350.0,
        "{plan}"
    );
    let latest: String = sqlx::query_scalar("SELECT encode(txid,'hex') FROM latest_active_covenant_output(decode(repeat('44',32),'hex'))")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(latest, format!("{:064x}", 500_000));
    // Remove only the newer output, leaving the large family at old scores.
    // This is the path that exhausted the live incident's removal budget.
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status)
        VALUES(decode(repeat('ff',32),'hex'),0,decode(repeat('44',32),'hex'),'new',1,'\\x51',decode(repeat('22',32),'hex'),'active')")
        .execute(&pool).await.unwrap();
    sqlx::query("SELECT refresh_covenant_summary(decode(repeat('44',32),'hex'))")
        .execute(&pool)
        .await
        .unwrap();
    let writer = PgPersister::new(pool.clone());
    let started = std::time::Instant::now();
    writer.revert_block(&[0x22; 32]).await.unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_millis(350),
        "large-family removal took {:?}",
        started.elapsed()
    );
    let summary: (i64, i64, String) = sqlx::query_as("SELECT active_utxos,total_amount_sompi,encode(latest_active_txid,'hex') FROM covenant_summaries WHERE covenant_id=decode(repeat('44',32),'hex')")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(summary, (500_000, 500_000, format!("{:064x}", 500_000)));
    assert_parity(&pool).await;
    sqlx::query("SELECT refresh_covenant_summary(decode(repeat('44',32),'hex'))")
        .execute(&pool)
        .await
        .unwrap();
    let rebuilt: (i64, i64, String) = sqlx::query_as("SELECT active_utxos,total_amount_sompi,encode(latest_active_txid,'hex') FROM covenant_summaries WHERE covenant_id=decode(repeat('44',32),'hex')")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(summary, rebuilt);
    start_summary_rebuild(&pool).await;
    let started=std::time::Instant::now();
    let mut pages=0;
    loop {
        pages+=1;
        assert!(pages<=1001,"aggregation must finish after the full active set");
        if summary_page(&pool).await { break; }
    }
    assert_eq!(pages,1001);
    assert!(started.elapsed()<std::time::Duration::from_secs(30));
    let paged:(i64,i64,String)=sqlx::query_as("SELECT active_utxos,total_amount_sompi,encode(latest_active_txid,'hex') FROM covenant_summaries WHERE covenant_id=decode(repeat('44',32),'hex')")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(summary,paged);
}

async fn start_summary_rebuild(pool:&PgPool) {
    sqlx::raw_sql("DELETE FROM covenant_summaries;
        INSERT INTO tn10_live_recovery_plans(intent_key,intent_sha256,owner_token,lease_expires_at_ms,phase,updated_at_ms,exclusive_writes)
        VALUES('summary-test',decode(repeat('11',32),'hex'),gen_random_uuid(),0,'revert',1,TRUE);")
        .execute(pool).await.unwrap();
}

async fn summary_page(pool:&PgPool)->bool {
    sqlx::query_scalar("SELECT recovery_summary_page('summary-test',decode(repeat('44',32),'hex'))")
        .fetch_one(pool).await.unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_summary_pages_resume_without_publishing_partial_totals(pool:PgPool) {
    seed(&pool,1001).await;
    backfill(&pool).await;
    start_summary_rebuild(&pool).await;
    for expected in [500_i64,1000,1001] {
        assert!(!summary_page(&pool).await);
        let scanned:i64=sqlx::query_scalar("SELECT active_count FROM tn10_recovery_summary_pages WHERE intent_key='summary-test'")
            .fetch_one(&pool).await.unwrap();
        assert_eq!(scanned,expected);
        let published:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_summaries").fetch_one(&pool).await.unwrap();
        assert_eq!(published,0,"partial counts must never become queryable");
    }
    assert!(summary_page(&pool).await);
    let counts:(i64,i64)=sqlx::query_as("SELECT active_utxos,total_amount_sompi FROM covenant_summaries").fetch_one(&pool).await.unwrap();
    assert_eq!(counts,(1001,1001));
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_generation_change_restarts_summary_aggregation(pool:PgPool) {
    seed(&pool,1001).await;
    backfill(&pool).await;
    start_summary_rebuild(&pool).await;
    assert!(!summary_page(&pool).await);
    // Use the same textual checkpoint twice. Its monotonic sequence must still
    // detect the changed canonical generation, even within one millisecond.
    sqlx::raw_sql("UPDATE tn10_live_recovery_plans SET last_committed_checkpoint='same' WHERE intent_key='summary-test';
        UPDATE tn10_live_recovery_plans SET last_committed_checkpoint='same' WHERE intent_key='summary-test';")
        .execute(&pool).await.unwrap();
    assert!(!summary_page(&pool).await);
    let state:(i64,i64)=sqlx::query_as("SELECT active_count,canonical_sequence FROM tn10_recovery_summary_pages WHERE intent_key='summary-test'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(state,(500,2));
    sqlx::query("UPDATE tn10_live_recovery_plans SET exclusive_writes=FALSE WHERE intent_key='summary-test'").execute(&pool).await.unwrap();
    assert!(sqlx::query("SELECT recovery_summary_page('summary-test',decode(repeat('44',32),'hex'))").execute(&pool).await.is_err());
    let rows:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_summaries").fetch_one(&pool).await.unwrap();
    assert_eq!(rows,0);
}

#[sqlx::test(migrations = "./migrations")]
async fn active_only_backfill_skips_spent_prefix_and_preserves_legacy_cursor(pool: PgPool) {
    seed(&pool,10001).await;
    let mut tx=pool.begin().await.unwrap();
    sqlx::query("SET LOCAL tn12.defer_bulk_utxo_summaries='on'").execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE covenant_utxos SET status='spent',spent_block=decode(repeat('22',32),'hex') WHERE txid<decode(lpad(to_hex(10001),64,'0'),'hex')")
        .execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    sqlx::query("DELETE FROM covenant_active_output_order").execute(&pool).await.unwrap();
    // A legacy page already traversed 500 spent outputs; do not reset its cursor.
    sqlx::query("UPDATE covenant_active_output_order_progress SET after_txid=decode(lpad(to_hex(500),64,'0'),'hex'),after_vout=0,processed_rows=500")
        .execute(&pool).await.unwrap();
    let state:serde_json::Value=sqlx::query_scalar("SELECT active_output_order_backfill_step()")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(state["processed_rows"],501);
    let last:String=sqlx::query_scalar("SELECT encode(after_txid,'hex') FROM covenant_active_output_order_progress")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(last,format!("{:064x}",10001));
    // A reactivation behind the old cursor remains covered by the atomic trigger.
    sqlx::query("UPDATE covenant_utxos SET status='active',spent_block=NULL WHERE txid=decode(lpad(to_hex(1),64,'0'),'hex')")
        .execute(&pool).await.unwrap();
    backfill(&pool).await;
    assert_parity(&pool).await;
    let members:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_active_output_order").fetch_one(&pool).await.unwrap();
    assert_eq!(members,2);
    let processed:i64=sqlx::query_scalar("SELECT processed_rows FROM covenant_active_output_order_progress").fetch_one(&pool).await.unwrap();
    assert!(processed<510,"spent history was traversed again");
}

#[sqlx::test(migrations = "./migrations")]
async fn active_only_backfill_migration_requires_a_valid_index(pool: PgPool) {
    sqlx::query("DROP INDEX covenant_utxos_active_outpoint_backfill_idx").execute(&pool).await.unwrap();
    let error=sqlx::raw_sql(include_str!("../migrations/20261114070100_active_only_output_backfill.sql"))
        .execute(&pool).await.unwrap_err();
    assert!(error.to_string().contains("missing or invalid"));
}

async fn interrupted_active_backfill_index(pool: &PgPool, recorded: bool) {
    seed(pool, 2).await;
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_active_outpoint_backfill_idx")
        .execute(pool).await.unwrap();
    // Failed concurrent uniqueness validation leaves the same invalid-index
    // artifact as an interrupted concurrent build, without catalog writes.
    assert!(sqlx::query("CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_active_outpoint_backfill_idx ON covenant_utxos(covenant_id)")
        .execute(pool).await.is_err());
    let valid: bool=sqlx::query_scalar("SELECT indisvalid FROM pg_index WHERE indexrelid='covenant_utxos_active_outpoint_backfill_idx'::regclass")
        .fetch_one(pool).await.unwrap();
    assert!(!valid);
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=20261114070100 OR (version=20261114070000 AND NOT $1)")
        .bind(recorded).execute(pool).await.unwrap();
    tn12_indexer_db::migrate(pool).await.unwrap();
    let ready: bool=sqlx::query_scalar("SELECT indisvalid AND indisready AND NOT indisunique FROM pg_index WHERE indexrelid='covenant_utxos_active_outpoint_backfill_idx'::regclass")
        .fetch_one(pool).await.unwrap();
    assert!(ready);
    backfill(pool).await;
    assert_parity(pool).await;
    // A second migration attempt is idempotent and preserves the checkpoint.
    tn12_indexer_db::migrate(pool).await.unwrap();
    assert_parity(pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn active_backfill_index_interruption_retries_unrecorded_migration(pool: PgPool) {
    interrupted_active_backfill_index(&pool, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn active_backfill_index_repaired_before_pending_function_migration(pool: PgPool) {
    interrupted_active_backfill_index(&pool, true).await;
}
