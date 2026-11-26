//! Compression policy changes storage only; immutable proof bytes stay exact.
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn historical_evidence_compression_preserves_bytes_and_seal(pool: PgPool) {
    let policies:Vec<(String,String)>=sqlx::query_as("SELECT attname::text,attcompression::text FROM pg_attribute WHERE attrelid='historical_acceptance_maps'::regclass AND attname IN ('window_evidence','cohort_evidence','evidence') ORDER BY attname").fetch_all(&pool).await.unwrap();
    assert_eq!(
        policies,
        vec![
            ("cohort_evidence".into(), "l".into()),
            ("evidence".into(), "".into()),
            ("window_evidence".into(), "l".into())
        ]
    );
    let window: Vec<u8> = (0..262144).map(|n| (n % 251) as u8).collect();
    let cohort: Vec<u8> = (0..131072).map(|n| (n % 239) as u8).collect();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL default_toast_compression='pglz'")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) VALUES($1,$2)")
        .bind(vec![2u8; 32])
        .bind(vec![1u8; 32])
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES($1,$2,$3,$4,101,1000)").bind(vec![1u8;32]).bind(vec![2u8;32]).bind(vec![3u8;32]).bind(vec![4u8;32]).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_maps(proof_hash,source_tip,window_start,window_end,cohort_digest,window_digest,evidence,window_evidence,cohort_evidence) VALUES($1,2000,100,110,$2,$3,'{}',$4,$5)").bind(vec![1u8;32]).bind(vec![5u8;32]).bind(vec![6u8;32]).bind(&window).bind(&cohort).execute(&mut *tx).await.unwrap();
    let stored:(Vec<u8>,Vec<u8>,String,String)=sqlx::query_as("SELECT window_evidence,cohort_evidence,pg_column_compression(window_evidence),pg_column_compression(cohort_evidence) FROM historical_acceptance_maps").fetch_one(&mut *tx).await.unwrap();
    assert_eq!(stored, (window, cohort, "lz4".into(), "lz4".into()));
    let error =
        sqlx::query("UPDATE historical_acceptance_maps SET cohort_evidence=decode('00','hex')")
            .execute(&mut *tx)
            .await
            .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
    tx.rollback().await.unwrap();
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM historical_acceptance_maps),(SELECT count(*) FROM historical_acceptance_map_sources),(SELECT count(*) FROM historical_acceptance_map_entries)").fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (0, 0, 0));
}
