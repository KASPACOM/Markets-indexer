//! Verify the actual SQLx simple-query seam before moving the repair kernel.
use sqlx::{Acquire, PgPool, Row};

#[sqlx::test(migrations = "./migrations")]
async fn fixed_batch_returns_final_stats_and_drops_staging_on_same_connection(pool: PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    for commit in [false, true] {
        let mut tx = connection.begin().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE transition_protocol_input(n bigint NOT NULL) ON COMMIT DROP; INSERT INTO transition_protocol_input VALUES(451)")
            .execute(&mut *tx).await.unwrap();
        let rows = sqlx::raw_sql("DO $kernel$ BEGIN UPDATE pg_temp.transition_protocol_input SET n=n+2; END $kernel$; SELECT n FROM pg_temp.transition_protocol_input")
            .fetch_all(&mut *tx).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<i64, _>("n"), 453);
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        let absent: bool =
            sqlx::query_scalar("SELECT to_regclass('pg_temp.transition_protocol_input') IS NULL")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
        assert!(absent, "staging survived on the same pooled connection");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn late_batch_timeout_rolls_back_writes_and_releases_writer_lock(pool: PgPool) {
    sqlx::query("CREATE TABLE transition_protocol_witness(n bigint NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    let mut connection = pool.acquire().await.unwrap();
    let mut tx = connection.begin().await.unwrap();
    sqlx::raw_sql("CREATE TEMP TABLE transition_protocol_input(n bigint) ON COMMIT DROP; SET LOCAL statement_timeout='20ms'")
        .execute(&mut *tx).await.unwrap();
    let error = sqlx::raw_sql("DO $kernel$ BEGIN PERFORM pg_advisory_xact_lock(6074847039450202930::bigint); INSERT INTO public.transition_protocol_witness VALUES(1); PERFORM pg_sleep(0.1); END $kernel$; SELECT 1 AS result")
        .fetch_all(&mut *tx).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("57014")
    );
    tx.rollback().await.unwrap();
    let absent: bool =
        sqlx::query_scalar("SELECT to_regclass('pg_temp.transition_protocol_input') IS NULL")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    assert!(absent);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.transition_protocol_witness")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let mut other = pool.begin().await.unwrap();
    let released: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(6074847039450202930::bigint)")
            .fetch_one(&mut *other)
            .await
            .unwrap();
    assert!(released);
    other.rollback().await.unwrap();
}
