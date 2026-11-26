use super::*;

const KEY: &str = "pending-regression";

async fn pending(pool: &PgPool) -> bool {
    sqlx::query_scalar(HAS_PENDING_RECONCILIATION)
        .bind(KEY)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn delayed_and_member_only_work_prevent_completion(pool: PgPool) {
    let writer = PgPersister::for_genesis_repair(pool.clone());
    writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    sqlx::query("UPDATE settled_repair_jobs SET phase='reconcile' WHERE cursor_key=$1")
        .bind(KEY)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!pending(&pool).await);
    sqlx::query("INSERT INTO covenant_genesis_progress(covenant_id,baseline_complete,version,applied_version,retry_at_ms) VALUES(decode('01','hex'),false,0,0,$1)")
        .bind(i64::MAX).execute(&pool).await.unwrap();
    assert!(
        pending(&pool).await,
        "incomplete baseline is pending even before its retry"
    );
    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    sqlx::query("UPDATE covenant_genesis_progress SET baseline_complete=true,version=1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(pending(&pool).await, "unapplied version is pending");
    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    sqlx::query("UPDATE covenant_genesis_progress SET applied_version=version")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!pending(&pool).await);
    sqlx::query(
        "INSERT INTO settled_repair_members(cursor_key,covenant_id) VALUES($1,decode('01','hex'))",
    )
    .bind(KEY)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        pending(&pool).await,
        "NULL member version must remain pending"
    );
    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    sqlx::query("UPDATE settled_repair_members SET normalized_version=0 WHERE cursor_key=$1")
        .bind(KEY)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        pending(&pool).await,
        "stale member version must remain pending"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM indexer_state WHERE key=$1")
        .bind(format!("{KEY}:settled_recheck"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "no cursor commit while an obligation remains");
    sqlx::query("UPDATE settled_repair_members SET normalized_version=1 WHERE cursor_key=$1")
        .bind(KEY)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!pending(&pool).await);
    assert!(writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    let cursor: serde_json::Value =
        sqlx::query_scalar("SELECT value FROM indexer_state WHERE key=$1")
            .bind(format!("{KEY}:settled_recheck"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursor["next_blue_score"], 200);
    assert_eq!(cursor["completed_windows"], 1);
}

fn scans_inventory(plan: &serde_json::Value) -> bool {
    match plan {
        serde_json::Value::Object(node) => {
            (node.get("Relation Name").and_then(|v| v.as_str())
                == Some("covenant_genesis_progress")
                && node.get("Node Type").and_then(|v| v.as_str()) == Some("Seq Scan"))
                || node.values().any(scans_inventory)
        }
        serde_json::Value::Array(nodes) => nodes.iter().any(scans_inventory),
        _ => false,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn completed_inventory_uses_pending_index_for_empty_and_sparse_cases(pool: PgPool) {
    sqlx::query("INSERT INTO covenant_genesis_progress(covenant_id,baseline_complete,version,applied_version) SELECT decode(lpad(to_hex(n),64,'0'),'hex'),true,n,n FROM generate_series(1,50000)n")
        .execute(&pool).await.unwrap();
    sqlx::query("ANALYZE covenant_genesis_progress")
        .execute(&pool)
        .await
        .unwrap();
    for sparse in [false, true] {
        if sparse {
            sqlx::query("UPDATE covenant_genesis_progress SET applied_version=version-1 WHERE covenant_id=decode(lpad(to_hex(50000),64,'0'),'hex')")
                .execute(&pool).await.unwrap();
        }
        assert_eq!(pending(&pool).await, sparse);
        let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (FORMAT JSON) {HAS_PENDING_RECONCILIATION}"
        )))
        .bind(KEY)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !scans_inventory(&plan),
            "completion check must not scan all completed families: {plan}"
        );
        assert!(plan
            .to_string()
            .contains("covenant_genesis_progress_pending_idx"));
    }
    // Prove this fixture detects the production regression rather than just
    // accepting either plan. Do not force planner settings in this test.
    let old: serde_json::Value = sqlx::query_scalar("EXPLAIN (FORMAT JSON) SELECT EXISTS(SELECT 1 FROM covenant_genesis_progress WHERE NOT baseline_complete OR applied_version<>version)")
        .fetch_one(&pool).await.unwrap();
    assert!(
        scans_inventory(&old),
        "fixture must expose the former planner choice"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn discovery_phase_check_does_not_read_global_inventory(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    let key = "cheap-discovery-phase";
    writer.prepare_settled_repair(key, 100, 100).await.unwrap();
    // A scheduling-only call must not wait on the global inventory. This lock
    // makes the old aggregate read deterministically block, without relying on
    // hardware-specific timings or millions of unrelated families.
    let mut inventory = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE covenant_genesis_progress IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *inventory)
        .await
        .unwrap();
    for (phase, expected) in [("replay", false), ("reconcile", true), ("complete", false)] {
        sqlx::query("UPDATE settled_repair_jobs SET phase=$2 WHERE cursor_key=$1")
            .bind(key)
            .bind(phase)
            .execute(&pool)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            writer.discover_settled_members(key),
        )
        .await;
        assert_eq!(
            result
                .expect("phase check waited on unrelated inventory")
                .unwrap(),
            expected
        );
    }
    inventory.rollback().await.unwrap();
}
