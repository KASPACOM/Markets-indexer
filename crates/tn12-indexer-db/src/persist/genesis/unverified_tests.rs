use super::*;
const KEY: &str = "history-test";
fn evidence() -> serde_json::Value {
    serde_json::json!({"transactions":[{"transaction_id":"retained-child"}]})
}
async fn park(writer: &PgPersister, epoch: i64) -> bool {
    writer
        .defer_missing_history(
            KEY,
            KEY,
            epoch,
            200,
            &"11".repeat(32),
            "http://source",
            &evidence(),
            "404 parent",
        )
        .await
        .unwrap()
}
async fn finish(writer: &PgPersister, key: &str, next: u64) {
    let epoch: i64 =
        sqlx::query_scalar("SELECT epoch FROM settled_repair_jobs WHERE cursor_key=$1")
            .bind(key)
            .fetch_one(&writer.pool)
            .await
            .unwrap();
    assert!(writer.acknowledge_settled_replay(key, epoch).await.unwrap());
    assert!(writer.discover_settled_members(key).await.unwrap());
    for _ in 0..10 {
        if writer.step_settled_repair(key, next, 5000).await.unwrap() {
            return;
        }
    }
    panic!("settled fixture did not complete");
}
#[sqlx::test(migrations = "./migrations")]
async fn missing_window_retains_job_members_and_independent_work_completes(pool: PgPool) {
    let writer = PgPersister::for_genesis_repair(pool.clone());
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    sqlx::query("INSERT INTO covenant_genesis_progress(covenant_id,baseline_complete,version,applied_version) VALUES(decode(repeat('44',32),'hex'),true,0,0)").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO settled_repair_members(cursor_key,covenant_id,normalized_version) VALUES($1,decode(repeat('44',32),'hex'),0)").bind(KEY).execute(&pool).await.unwrap();
    assert!(park(&writer, job.epoch).await);
    assert!(
        !park(&writer, job.epoch).await,
        "lost commit acknowledgement must not park twice"
    );
    let (key, saved): (String, serde_json::Value) =
        sqlx::query_as("SELECT job_key,source_evidence FROM settled_history_unverified")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(saved, evidence());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM settled_repair_members WHERE cursor_key=$1"
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM indexer_state WHERE key=$1")
            .bind(format!("{KEY}:settled_recheck"))
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
        "parking cannot certify completion"
    );
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 1);
    let next = writer.prepare_settled_repair(KEY, 200, 100).await.unwrap();
    assert_eq!(next.window_start, 200);
    finish(&writer, KEY, 300).await;
    let counters: serde_json::Value =
        sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
            .bind(format!("{KEY}:settled_recheck"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(counters["completed_windows"], 1);
    assert_eq!(counters["last_completed_blue_score"], 200);
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 1);
    // A fresh process reuses the persisted schedule and retained obligation.
    let restarted = PgPersister::for_genesis_repair(pool.clone());
    sqlx::query("UPDATE settled_history_unverified SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE settled_repair_jobs SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        restarted.due_history_retry(KEY, 5000, 1000).await.unwrap(),
        Some((key.clone(), 100))
    );
    assert_eq!(
        restarted.due_history_retry(KEY, 5000, 1000).await.unwrap(),
        None,
        "retry lane must yield to forward work"
    );
    finish(&restarted, &key, 200).await;
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 0);
    // Actual canonical-block trigger reopens the repaired range.
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES(decode(repeat('33',32),'hex'),100,100,ARRAY[]::bytea[],1,true,1)")
        .execute(&pool).await.unwrap();
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 1);
    assert_eq!(
        sqlx::query_scalar::<_, serde_json::Value>(
            "SELECT source_evidence FROM settled_history_unverified"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        evidence()
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn stale_epoch_or_replaced_owner_cannot_defer_history(pool: PgPool) {
    let fence = crate::persist::SettledRecheckFence::claim(&pool, KEY)
        .await
        .unwrap();
    let writer = PgPersister::for_genesis_repair(pool.clone()).with_settled_recheck_fence(fence);
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    assert!(!park(&writer, job.epoch + 1).await);
    let _replacement = crate::persist::SettledRecheckFence::claim(&pool, KEY)
        .await
        .unwrap();
    assert!(writer
        .defer_missing_history(
            KEY,
            KEY,
            job.epoch,
            200,
            "parent",
            "source",
            &evidence(),
            "404"
        )
        .await
        .is_err());
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM settled_history_schedule")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn retained_window_deduplicates_sweep_and_capacity_does_not_advance(pool: PgPool) {
    let writer = PgPersister::for_genesis_repair(pool.clone());
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    assert!(writer
        .defer_missing_history(
            KEY,
            KEY,
            job.epoch,
            200,
            "parent",
            "source",
            &serde_json::json!("x".repeat(16 * 1024 * 1024)),
            "404"
        )
        .await
        .is_err());
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 0);
    assert!(park(&writer, job.epoch).await);
    assert!(writer.retained_history_window(KEY, 100, 200).await.unwrap());
    assert_eq!(summary(&pool).await.unwrap().pending_windows, 1);
    assert_eq!(
        writer.due_history_retry(KEY, 150, 1000).await.unwrap(),
        None,
        "unmature source cannot authorize retry"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn retries_are_limited_across_cursor_roots(pool: PgPool) {
    let writer = PgPersister::for_genesis_repair(pool.clone());
    for root in ["first", "second"] {
        let job = writer.prepare_settled_repair(root, 100, 100).await.unwrap();
        assert!(writer
            .defer_missing_history(
                root,
                root,
                job.epoch,
                200,
                "parent",
                "source",
                &evidence(),
                "404"
            )
            .await
            .unwrap());
    }
    sqlx::query("UPDATE settled_history_unverified SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE settled_repair_jobs SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(writer
        .due_history_retry("first", 5000, 1000)
        .await
        .unwrap()
        .is_some());
    assert!(writer
        .due_history_retry("second", 5000, 1000)
        .await
        .unwrap()
        .is_none());
    sqlx::query("UPDATE settled_history_retry_gate SET last_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(writer
        .due_history_retry("second", 5000, 1000)
        .await
        .unwrap()
        .is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_rotation_serves_active_roots_and_expires_stopped_roots(pool: PgPool) {
    let writer = PgPersister::for_genesis_repair(pool.clone());
    for root in ["first", "second"] {
        let job = writer.prepare_settled_repair(root, 100, 100).await.unwrap();
        writer
            .defer_missing_history(
                root,
                root,
                job.epoch,
                200,
                "parent",
                "source",
                &evidence(),
                "404",
            )
            .await
            .unwrap();
    }
    sqlx::query("UPDATE settled_history_unverified SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE settled_repair_jobs SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(writer
        .due_history_retry("first", 5000, 1000)
        .await
        .unwrap()
        .is_some());
    assert!(writer
        .due_history_retry("second", 5000, 1000)
        .await
        .unwrap()
        .is_none());
    // Simulate the next minute: the first root's persistent failure is due
    // again, but it must leave the global slot for the waiting second root.
    sqlx::query("UPDATE settled_history_retry_gate SET last_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE settled_history_unverified SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    assert!(writer
        .due_history_retry("first", 5000, 1000)
        .await
        .unwrap()
        .is_none());
    assert!(writer
        .due_history_retry("second", 5000, 1000)
        .await
        .unwrap()
        .is_some());
    sqlx::query("UPDATE settled_history_retry_gate SET last_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE settled_history_unverified SET next_retry_at_ms=0")
        .execute(&pool)
        .await
        .unwrap();
    // A retired root cannot reserve the dispatcher forever.
    sqlx::query("UPDATE settled_history_schedule SET last_poll_at_ms=0,last_retry_at_ms=0 WHERE cursor_key='first'").execute(&pool).await.unwrap();
    assert!(writer
        .due_history_retry("second", 5000, 1000)
        .await
        .unwrap()
        .is_some());
}
