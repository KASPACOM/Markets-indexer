//! Run against a disposable, migrated database with TEST_PROJECTOR_DATABASE_URL.
use super::*;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires a disposable migrated TEST_PROJECTOR_DATABASE_URL"]
async fn projector_retries_when_lock_connection_dies_during_refresh() -> Result<()> {
    interrupt_refresh(3).await??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable migrated TEST_PROJECTOR_DATABASE_URL"]
async fn projector_one_shot_reports_failed_refresh() -> Result<()> {
    let result = interrupt_refresh(1).await?;
    let error = result.expect_err("failed final pass must not report success");
    assert!(format!("{error:#}").contains("release KCC20 projector advisory lock"));
    Ok(())
}

async fn interrupt_refresh(iterations: u64) -> Result<Result<()>> {
    let url = std::env::var("TEST_PROJECTOR_DATABASE_URL")?;
    let pool = tn12_indexer_db::connect(&url).await?;
    let mut blocker = pool.begin().await?;
    sqlx::query("LOCK TABLE kcc20_projection_dirty IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let separator = if url.contains('?') { '&' } else { '?' };
    let application = format!("projector_reconnect_test_{}", std::process::id());
    let worker_url = format!("{url}{separator}application_name={application}");
    let worker = run_kcc20_projector(
        worker_url,
        false,
        1,
        500,
        "10s".into(),
        false,
        Some(iterations),
    );
    let interrupt = async {
        let wait = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let pid: Option<i32> = sqlx::query_scalar(
                    "SELECT pid FROM pg_stat_activity WHERE datname = current_database() \
                 AND application_name = $1 AND wait_event_type = 'Lock' \
                 AND query LIKE '%commit_barrier AS MATERIALIZED%' LIMIT 1",
                )
                .bind(&application)
                .fetch_optional(&pool)
                .await?;
                if let Some(pid) = pid {
                    return Ok::<_, anyhow::Error>(pid);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        let pid = match wait {
            Ok(Ok(pid)) => pid,
            other => {
                anyhow::bail!("projector did not reach refresh lock wait: {other:?}");
            }
        };
        let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&pool)
            .await?;
        assert!(terminated);
        blocker.rollback().await?;
        // The old code exits from advisory unlock. The fixed loop must complete
        // subsequent passes and preserve bounded one-shot execution.
        Ok::<_, anyhow::Error>(())
    };
    let (worker_result, interrupt_result) = tokio::time::timeout(Duration::from_secs(45), async {
        tokio::join!(worker, interrupt)
    })
    .await?;
    interrupt_result?;
    pool.close().await;
    Ok(worker_result)
}

#[tokio::test]
#[ignore = "requires a disposable TEST_PROJECTOR_DATABASE_URL"]
async fn projector_lock_guard_closes_session_on_cancel() -> Result<()> {
    let url = std::env::var("TEST_PROJECTOR_DATABASE_URL")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let mut guard = ProjectorLockConnection {
        connection: pool.acquire().await?,
        safe_to_reuse: false,
    };
    let original_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *guard)
        .await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(KCC20_PROJECTOR_LOCK_KEY)
        .execute(&mut *guard)
        .await?;
    // Dropping the future exercises cancellation, which skips explicit unlock.
    let future = async move {
        let _held_guard = guard;
        std::future::pending::<()>().await;
    };
    assert!(tokio::time::timeout(Duration::from_millis(10), future)
        .await
        .is_err());
    let mut next = pool.acquire().await?;
    let next_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *next)
        .await?;
    assert_ne!(original_pid, next_pid, "uncertain lock session was pooled");
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(KCC20_PROJECTOR_LOCK_KEY)
        .fetch_one(&mut *next)
        .await?;
    assert!(acquired, "abandoned projector lock remained held");
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(KCC20_PROJECTOR_LOCK_KEY)
        .execute(&mut *next)
        .await?;
    drop(next);
    pool.close().await;
    Ok(())
}
