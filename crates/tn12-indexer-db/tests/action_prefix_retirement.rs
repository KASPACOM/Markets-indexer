//! Opt-in removal of duplicate action index prefixes, using real PostgreSQL.
use sqlx::PgPool;
use tn12_indexer_db::{migrate, migrate_retiring_action_prefix_indexes};

const PAIRS: &[(&str, &str)] = &[
    (
        "actions_txid_idx",
        "covenant_actions_tx_covenant_action_id_idx",
    ),
    (
        "actions_covenant_time_idx",
        "covenant_actions_covenant_time_id_idx",
    ),
];
async fn exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn assert_retired(pool: &PgPool) {
    for (old, replacement) in PAIRS {
        assert!(!exists(pool, old).await, "redundant {old} remains");
        let ready: bool = sqlx::query_scalar("SELECT indisvalid AND indisready AND indislive FROM pg_index WHERE indexrelid=to_regclass($1)")
            .bind(replacement).fetch_one(pool).await.unwrap();
        assert!(ready, "replacement {replacement} unavailable");
    }
    for unique in [
        "covenant_actions_pkey",
        "covenant_actions_deploy_vout_uniq",
        "covenant_actions_spend_outpoint_uniq",
        "covenant_actions_continuation_vout_uniq",
    ] {
        assert!(exists(pool, unique).await);
    }
}
#[sqlx::test(migrations = "./migrations")]
async fn explicit_retirement_removes_both_prefixes_and_is_idempotent(pool: PgPool) {
    migrate(&pool).await.unwrap();
    for (old, _) in PAIRS {
        assert!(exists(&pool, old).await);
    }
    migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
    assert_retired(&pool).await;
    migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
    assert_retired(&pool).await;
    migrate(&pool).await.unwrap();
    assert_retired(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_replacements_are_repaired_before_prefix_retirement(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX covenant_actions_tx_covenant_action_id_idx; DROP INDEX covenant_actions_covenant_time_id_idx")
        .execute(&pool).await.unwrap();
    migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
    assert_retired(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_second_replacement_preserves_both_prefixes(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX covenant_actions_covenant_time_id_idx; CREATE INDEX covenant_actions_covenant_time_id_idx ON covenant_actions(covenant_id,block_time_ms ASC,id DESC)")
        .execute(&pool).await.unwrap();
    let error = migrate_retiring_action_prefix_indexes(&pool)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("required exact definition"));
    for (old, _) in PAIRS {
        assert!(exists(&pool, old).await);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_second_target_preserves_both_prefixes(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX actions_covenant_time_idx; CREATE INDEX actions_covenant_time_idx ON covenant_actions(covenant_id,block_time_ms DESC) INCLUDE (id)")
        .execute(&pool).await.unwrap();
    let error = migrate_retiring_action_prefix_indexes(&pool)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("unexpected definition"));
    for (old, _) in PAIRS {
        assert!(exists(&pool, old).await);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn unique_target_is_never_retired(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX actions_txid_idx; CREATE UNIQUE INDEX actions_txid_idx ON covenant_actions(txid)")
        .execute(&pool).await.unwrap();
    let error = migrate_retiring_action_prefix_indexes(&pool)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("unexpected definition"));
    for (old, _) in PAIRS {
        assert!(exists(&pool, old).await);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn interrupted_drop_retry_repairs_replacement_then_converges(pool: PgPool) {
    migrate(&pool).await.unwrap();
    let short = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    sqlx::query("SET statement_timeout='200ms'")
        .execute(&short)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE covenant_actions IN SHARE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let error = migrate_retiring_action_prefix_indexes(&short)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("retiring redundant action prefix index"),
        "{error:#}"
    );
    blocker.rollback().await.unwrap();
    assert!(exists(&pool, "actions_txid_idx").await);
    sqlx::query("DROP INDEX covenant_actions_tx_covenant_action_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
    assert_retired(&pool).await;
    short.close().await;
}

async fn seed_actions(pool: &PgPool) {
    use tn12_indexer_core::RestTransaction;
    use tn12_indexer_db::{Persister, PgPersister};
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    PgPersister::new(pool.clone())
        .persist_batch(&fixture)
        .await
        .unwrap();
    sqlx::raw_sql(
        r#"
      INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs)
      SELECT (SELECT covenant_id FROM covenants ORDER BY covenant_id LIMIT 1),
             CASE WHEN i<=3 THEN decode(repeat('ab',32),'hex') ELSE decode(md5(i::text)||md5(i::text),'hex') END,(SELECT hash FROM blocks LIMIT 1),
             1000000+i/3,'continuation',jsonb_build_object('vout',i)
      FROM generate_series(1,3000) i;
      ANALYZE covenant_actions;
    "#,
    )
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_replacement_is_repaired_before_retirement(pool: PgPool) {
    seed_actions(&pool).await;
    sqlx::query("DROP INDEX covenant_actions_covenant_time_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query("CREATE UNIQUE INDEX CONCURRENTLY covenant_actions_covenant_time_id_idx ON covenant_actions ((1))")
        .execute(&pool).await.is_err());
    migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
    assert_retired(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn transaction_and_covenant_time_queries_preserve_rows_and_use_replacements(pool: PgPool) {
    seed_actions(&pool).await;
    let cid: Vec<u8> =
        sqlx::query_scalar("SELECT covenant_id FROM covenants ORDER BY covenant_id LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let queries = [
        ("SELECT id FROM covenant_actions WHERE txid=$1 ORDER BY id", vec![0xab;32], "covenant_actions_tx_covenant_action_id_idx"),
        ("SELECT id FROM covenant_actions WHERE covenant_id=$1 ORDER BY block_time_ms DESC,id DESC LIMIT 25", cid, "covenant_actions_covenant_time_id_idx"),
    ];
    let mut before = Vec::new();
    for (q, key, _) in &queries {
        before.push(
            sqlx::query_scalar::<_, i64>(*q)
                .bind(key)
                .fetch_all(&pool)
                .await
                .unwrap(),
        );
    }
    let digest_sql =
        "SELECT md5(string_agg(row_to_json(a)::text, ',' ORDER BY id)) FROM covenant_actions a";
    let digest_before: String = sqlx::query_scalar(digest_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
    assert_retired(&pool).await;
    let digest_after: String = sqlx::query_scalar(digest_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(digest_before, digest_after);
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET enable_seqscan=off")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("SET plan_cache_mode=force_generic_plan")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::raw_sql("PREPARE prefix_tx(bytea) AS SELECT id FROM covenant_actions WHERE txid=$1 ORDER BY id; PREPARE prefix_time(bytea) AS SELECT id FROM covenant_actions WHERE covenant_id=$1 ORDER BY block_time_ms DESC,id DESC LIMIT 25")
        .execute(&mut *conn).await.unwrap();
    sqlx::query("SELECT set_config('tn12.test_cid', encode($1::bytea, 'hex'), false)")
        .bind(&queries[1].1)
        .execute(&mut *conn)
        .await
        .unwrap();
    for ((q, key, index), expected) in queries.iter().zip(before) {
        let actual = sqlx::query_scalar::<_, i64>(*q)
            .bind(key)
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert_eq!(actual, expected);
        let execute = if *index == "covenant_actions_tx_covenant_action_id_idx" {
            "EXECUTE prefix_tx(decode(repeat('ab',32),'hex'))"
        } else {
            "EXECUTE prefix_time(decode(current_setting('tn12.test_cid'),'hex'))"
        };
        let prepared = sqlx::query_scalar::<_, i64>(execute)
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert_eq!(prepared, expected);
        let explain = if *index == "covenant_actions_tx_covenant_action_id_idx" {
            "EXPLAIN (FORMAT JSON) EXECUTE prefix_tx(decode(repeat('ab',32),'hex'))"
        } else {
            "EXPLAIN (FORMAT JSON) EXECUTE prefix_time(decode(current_setting('tn12.test_cid'),'hex'))"
        };
        let plan: serde_json::Value = sqlx::query_scalar(explain)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert!(plan.to_string().contains(index), "{plan}");
        assert!(
            plan.to_string().contains("$1"),
            "expected generic parameter plan: {plan}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn same_named_non_index_preserves_both_targets(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX actions_covenant_time_idx; CREATE VIEW actions_covenant_time_idx AS SELECT 1 AS marker")
        .execute(&pool).await.unwrap();
    let error = migrate_retiring_action_prefix_indexes(&pool)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("unexpected definition"),
        "{error:#}"
    );
    for (old, _) in PAIRS {
        assert!(exists(&pool, old).await);
    }
}

async fn wait_for_prefix_drop(pool: &PgPool) -> i32 {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let pid: Option<i32>=sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'DROP INDEX CONCURRENTLY IF EXISTS public.actions_txid_idx%' AND wait_event_type='Lock' LIMIT 1")
                .fetch_optional(pool).await.unwrap();
            if let Some(pid)=pid { return pid; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("migration must reach the blocked prefix drop")
}
async fn ownership_available(pool: &PgPool) -> bool {
    let mut conn = pool.acquire().await.unwrap();
    let key: i64 = 0x544e31325f4d4947;
    for _ in 0..100 {
        let available: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        if available {
            let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
                .bind(key)
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            assert!(released);
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    false
}
#[sqlx::test(migrations = "./migrations")]
async fn aborted_migration_cannot_return_ownership_lock_to_pool(pool: PgPool) {
    tokio::task::LocalSet::new()
        .run_until(async {
            migrate(&pool).await.unwrap();
            let owner = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with((*pool.connect_options()).clone())
                .await
                .unwrap();
            let mut blocker = pool.begin().await.unwrap();
            sqlx::query("LOCK TABLE covenant_actions IN SHARE MODE")
                .execute(&mut *blocker)
                .await
                .unwrap();
            let run_pool = owner.clone();
            let task = tokio::task::spawn_local(async move {
                migrate_retiring_action_prefix_indexes(&run_pool).await
            });
            wait_for_prefix_drop(&pool).await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            blocker.rollback().await.unwrap();
            let available = ownership_available(&pool).await;
            owner.close().await;
            assert!(
                available,
                "cancelled migration returned a session ownership lock to the pool"
            );
            migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
            assert_retired(&pool).await;
        })
        .await;
}
#[sqlx::test(migrations = "./migrations")]
async fn terminated_backend_releases_ownership_and_retry_converges(pool: PgPool) {
    tokio::task::LocalSet::new()
        .run_until(async {
            migrate(&pool).await.unwrap();
            let mut blocker = pool.begin().await.unwrap();
            sqlx::query("LOCK TABLE covenant_actions IN SHARE MODE")
                .execute(&mut *blocker)
                .await
                .unwrap();
            let run_pool = pool.clone();
            let task = tokio::task::spawn_local(async move {
                migrate_retiring_action_prefix_indexes(&run_pool).await
            });
            let pid = wait_for_prefix_drop(&pool).await;
            let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
                .bind(pid)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert!(terminated);
            blocker.rollback().await.unwrap();
            assert!(task.await.unwrap().is_err());
            assert!(ownership_available(&pool).await);
            migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
            assert_retired(&pool).await;
        })
        .await;
}
#[sqlx::test(migrations = "./migrations")]
async fn interrupted_invalid_target_is_finished_on_retry(pool: PgPool) {
    tokio::task::LocalSet::new()
        .run_until(async {
            migrate(&pool).await.unwrap();
            let mut blocker = pool.begin().await.unwrap();
            sqlx::query("SELECT id FROM covenant_actions LIMIT 1")
                .fetch_all(&mut *blocker)
                .await
                .unwrap();
            let run_pool = pool.clone();
            let task = tokio::task::spawn_local(async move {
                migrate_retiring_action_prefix_indexes(&run_pool).await
            });
            let pid = wait_for_prefix_drop(&pool).await;
            let valid: bool = sqlx::query_scalar(
                "SELECT indisvalid FROM pg_index WHERE indexrelid='actions_txid_idx'::regclass",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(
                !valid,
                "concurrent drop must have invalidated its target before waiting for old readers"
            );
            let cancelled: bool = sqlx::query_scalar("SELECT pg_cancel_backend($1)")
                .bind(pid)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert!(cancelled);
            assert!(task.await.unwrap().is_err());
            blocker.rollback().await.unwrap();
            assert!(exists(&pool, "actions_txid_idx").await);
            assert!(ownership_available(&pool).await);
            migrate_retiring_action_prefix_indexes(&pool).await.unwrap();
            assert_retired(&pool).await;
        })
        .await;
}
