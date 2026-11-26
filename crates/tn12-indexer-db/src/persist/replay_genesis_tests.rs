use super::PgPersister;
use sqlx::PgPool;

async fn fixture(pool: &PgPool, existing_deploy: bool) {
    sqlx::raw_sql(
        "INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
         VALUES(decode(repeat('aa',32),'hex'),100,0,ARRAY[]::bytea[],1000,true,1000),
               (decode(repeat('bb',32),'hex'),200,0,ARRAY[]::bytea[],2000,true,2000);
         INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms)
         VALUES(decode(repeat('cc',32),'hex'),'test',0,decode(repeat('dd',32),'hex'),decode(repeat('22',32),'hex'),1,decode(repeat('bb',32),'hex'),2000);
         INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status)
         SELECT decode(repeat('11',32),'hex'),n,decode(repeat('cc',32),'hex'),'test',1,decode('aa20','hex'),decode(repeat('aa',32),'hex'),'active' FROM generate_series(0,6)n;
         INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs)
         SELECT decode(repeat('cc',32),'hex'),decode(repeat('11',32),'hex'),decode(repeat('aa',32),'hex'),1000,'continuation',jsonb_build_object('vout',n) FROM generate_series(0,6)n;",
    ).execute(pool).await.unwrap();
    if existing_deploy {
        sqlx::query("UPDATE covenant_actions SET action='deploy' WHERE outputs->>'vout'='0'")
            .execute(pool)
            .await
            .unwrap();
    }
}

async fn assert_preserved(pool: &PgPool) {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT action,outputs->>'vout' FROM covenant_actions ORDER BY outputs->>'vout'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 7);
    assert_eq!(rows[0], ("deploy".into(), "0".into()));
    for (vout, (action, output)) in rows.iter().enumerate().skip(1) {
        assert_eq!(action, "continuation");
        assert_eq!(output, &vout.to_string());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(count, 7);
    let summary: i64 = sqlx::query_scalar("SELECT action_count FROM covenant_action_summaries")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(summary, 7);
    let dirty: Vec<Option<Vec<u8>>> = sqlx::query_scalar(
        "SELECT txid FROM kcc20_projection_dirty WHERE reason='settled_replay_genesis'",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(dirty, vec![Some(vec![0x11_u8; 32])]);
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_genesis_promotes_only_the_genesis_output(pool: PgPool) {
    fixture(&pool, false).await;
    let writer = PgPersister::new(pool.clone());
    assert_eq!(
        writer.normalize_replayed_genesis(100, 100).await.unwrap(),
        (1, 1)
    );
    assert_preserved(&pool).await;
    assert_eq!(
        writer.normalize_replayed_genesis(100, 100).await.unwrap(),
        (0, 0)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_genesis_preserves_existing_deploy_and_continuations(pool: PgPool) {
    fixture(&pool, true).await;
    let writer = PgPersister::new(pool.clone());
    assert_eq!(
        writer.normalize_replayed_genesis(100, 100).await.unwrap(),
        (1, 0)
    );
    assert_preserved(&pool).await;
    assert_eq!(
        writer.normalize_replayed_genesis(100, 100).await.unwrap(),
        (0, 0)
    );
}
