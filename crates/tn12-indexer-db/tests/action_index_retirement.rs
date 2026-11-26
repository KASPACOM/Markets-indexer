//! Managed index retirement must preserve its replacement on every retry.
use sqlx::PgPool;
use tn12_indexer_db::migrate;

const REPLACEMENT: &str = "covenant_actions_tx_covenant_action_id_idx";
const REDUNDANT: &str = "covenant_actions_continuation_tx_idx";

async fn exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn assert_converged(pool: &PgPool) {
    assert!(exists(pool, REPLACEMENT).await);
    assert!(!exists(pool, REDUNDANT).await);
    let valid: bool = sqlx::query_scalar(
        "SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid=to_regclass($1)",
    )
    .bind(REPLACEMENT)
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(valid);
    for name in [
        "actions_txid_idx",
        "covenant_actions_continuation_vout_uniq",
    ] {
        assert!(exists(pool, name).await, "must preserve {name}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn direct_sql_migrations_preserve_index_until_managed_convergence(pool: PgPool) {
    assert!(exists(&pool, REDUNDANT).await);
    migrate(&pool).await.unwrap();
    assert_converged(&pool).await;
    migrate(&pool).await.unwrap();
    assert_converged(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_replacement_is_rebuilt_before_retirement(pool: PgPool) {
    sqlx::query("DROP INDEX covenant_actions_tx_covenant_action_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    migrate(&pool).await.unwrap();
    assert_converged(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn valid_wrong_replacement_preserves_redundant_index(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX covenant_actions_tx_covenant_action_id_idx; CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON covenant_actions(txid);")
        .execute(&pool).await.unwrap();
    let error = migrate(&pool).await.unwrap_err();
    assert!(format!("{error:#}").contains("required exact definition"));
    assert!(exists(&pool, REDUNDANT).await);
    sqlx::query("DROP INDEX covenant_actions_tx_covenant_action_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    migrate(&pool).await.unwrap();
    assert_converged(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unexpected_retirement_target_is_preserved(pool: PgPool) {
    sqlx::raw_sql("DROP INDEX covenant_actions_continuation_tx_idx; CREATE INDEX covenant_actions_continuation_tx_idx ON covenant_actions(txid);")
        .execute(&pool).await.unwrap();
    let error = migrate(&pool).await.unwrap_err();
    assert!(format!("{error:#}").contains("unexpected definition"));
    assert!(exists(&pool, REDUNDANT).await);
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_retirement_retry_repairs_a_subsequently_missing_replacement(pool: PgPool) {
    // Keep this fault injection at retirement, after additive index preparation.
    sqlx::raw_sql("CREATE INDEX covenant_utxos_genesis_scan_idx ON covenant_utxos(covenant_id,txid,vout) INCLUDE(created_block);
        CREATE INDEX covenant_actions_genesis_discovery_idx ON covenant_actions(block_hash,id) INCLUDE(covenant_id) WHERE action IN ('deploy','continuation');")
        .execute(&pool).await.unwrap();
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
    let error = migrate(&short).await.unwrap_err();
    assert!(format!("{error:#}").contains("retiring redundant continuation action index"));
    blocker.rollback().await.unwrap();
    assert!(exists(&pool, REDUNDANT).await);
    sqlx::query("DROP INDEX covenant_actions_tx_covenant_action_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    migrate(&pool).await.unwrap();
    assert_converged(&pool).await;
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
}

#[sqlx::test(migrations = "./migrations")]
async fn invalid_replacement_is_rebuilt_before_retirement(pool: PgPool) {
    seed_actions(&pool).await;
    sqlx::query("DROP INDEX covenant_actions_tx_covenant_action_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query("CREATE UNIQUE INDEX CONCURRENTLY covenant_actions_tx_covenant_action_id_idx ON covenant_actions ((1))")
        .execute(&pool).await.is_err());
    let valid: bool =
        sqlx::query_scalar("SELECT indisvalid FROM pg_index WHERE indexrelid=to_regclass($1)")
            .bind(REPLACEMENT)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!valid);
    migrate(&pool).await.unwrap();
    assert_converged(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn replacement_definition_guard_covers_order_predicate_opclass_and_includes(pool: PgPool) {
    for definition in [
        "CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON covenant_actions (txid,covenant_id,action,id DESC)",
        "CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON covenant_actions (txid,covenant_id,action,id) WHERE action='continuation'",
        "CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON covenant_actions (txid,covenant_id,action text_pattern_ops,id)",
        "CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON covenant_actions (txid,covenant_id,action,id) INCLUDE (block_time_ms)",
        "CREATE INDEX covenant_actions_tx_covenant_action_id_idx ON covenant_actions (txid,covenant_id,action COLLATE \"C\",id)",
    ] {
        sqlx::query("DROP INDEX covenant_actions_tx_covenant_action_id_idx")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(definition)
            .execute(&pool).await.unwrap();
        let error = migrate(&pool).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("required exact definition"),
            "{definition}: {error:#}"
        );
        assert!(exists(&pool, REDUNDANT).await);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn cached_wrapper_lifecycle_queries_keep_cross_covenant_output_order(pool: PgPool) {
    seed_actions(&pool).await;
    sqlx::raw_sql(r#"
      INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms)
      SELECT decode(repeat(lpad(to_hex(i+200),2,'0'),32),'hex'),'index-probe-'||i,0,
             decode(repeat(lpad(to_hex(i+200),2,'0'),32),'hex'),
             decode(repeat(lpad(to_hex(i+200),2,'0'),32),'hex'),0,(SELECT hash FROM blocks LIMIT 1),1
      FROM generate_series(1,4) i;
      INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,entrypoint,outputs,decoded_args)
      SELECT decode(repeat(lpad(to_hex(cid+200),2,'0'),32),'hex'),decode(repeat('ab',32),'hex'),
             (SELECT hash FROM blocks LIMIT 1),1000000,
             CASE WHEN i%5=0 THEN 'spend' ELSE 'continuation' END,
             CASE WHEN i%5=0 THEN 'wrap' ELSE NULL END,
             jsonb_build_object('vout',i,'state',jsonb_build_object('ownerIdentifier',cid||':'||i)),
             jsonb_build_object('orderbookHolderOutputIndex',3)
      FROM generate_series(1,4) cid CROSS JOIN generate_series(0,31) i ORDER BY cid,i;
      INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,entrypoint,decoded_args)
      SELECT decode(repeat('c9',32),'hex'),decode(repeat('cd',32),'hex'),(SELECT hash FROM blocks LIMIT 1),1000000,
             'spend',CASE WHEN i=1 THEN 'wrap' ELSE NULL END,jsonb_build_object('orderbookHolderOutputIndex',3)
      FROM generate_series(1,1000) i;
    "#).execute(&pool).await.unwrap();
    async fn lookup(conn: &mut sqlx::PgConnection, txid: Vec<u8>) -> Vec<(i64, Option<String>)> {
        sqlx::query_as(
            r#"
          SELECT a.id, recipient.owner_identifier FROM covenant_actions a
          LEFT JOIN LATERAL (
            SELECT cont.outputs->'state'->>'ownerIdentifier' AS owner_identifier
            FROM covenant_actions cont
            WHERE a.entrypoint IN ('wrap','unwrap') AND cont.txid=a.txid
              AND cont.action='continuation'
              AND cont.outputs->>'vout'=CASE
                WHEN a.entrypoint='wrap' THEN a.decoded_args->>'orderbookHolderOutputIndex'
                WHEN a.entrypoint='unwrap' THEN a.decoded_args->>'tokenRecipientOutputIndex'
                ELSE NULL END
            ORDER BY cont.id DESC LIMIT 1
          ) recipient ON TRUE
          WHERE a.txid=$1 AND a.entrypoint='wrap' ORDER BY a.id
        "#,
        )
        .bind(txid)
        .fetch_all(conn)
        .await
        .unwrap()
    }
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET plan_cache_mode=force_generic_plan")
        .execute(&mut *conn)
        .await
        .unwrap();
    let before = lookup(&mut conn, vec![0xab; 32]).await;
    let absent = lookup(&mut conn, vec![0xcd; 32]).await;
    assert_eq!(before.len(), 28);
    assert!(before
        .iter()
        .all(|(_, owner)| owner.as_deref() == Some("4:3")));
    assert_eq!(absent.len(), 1);
    assert_eq!(absent[0].1, None);
    migrate(&pool).await.unwrap();
    assert_eq!(lookup(&mut conn, vec![0xab; 32]).await, before);
    assert_eq!(lookup(&mut conn, vec![0xcd; 32]).await, absent);
    assert_converged(&pool).await;
}
