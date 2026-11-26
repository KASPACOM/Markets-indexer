//! Synthetic fixture parity and atomic cursor tests on the real persistence path.
use serde_json::{json, Value};
use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{shadow, Persister, PgPersister};

async fn state(pool: &PgPool) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object('utxos',COALESCE((SELECT jsonb_agg(to_jsonb(u) ORDER BY txid,vout) FROM covenant_utxos u),'[]'::jsonb),'covenants',COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY covenant_id) FROM covenants c),'[]'::jsonb))")
        .fetch_one(pool).await.unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn shadow_effects_match_v1_and_removal_keeps_acceptance_evidence(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let mut body = fixture[0].clone();
    // Explicitly synthetic isolated genesis, not funded-chain evidence.
    body.inputs.clear();
    body.outputs.truncate(1);
    body.outputs[0].script_public_key = format!("aa20{}87", "71".repeat(32));
    body.outputs[0].script_public_key_address = None;
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&body).await.unwrap();
    let expected = state(&pool).await;
    let hash = hex::decode(body.accepting_block_hash.as_ref().unwrap()).unwrap();
    writer.revert_block(&hash).await.unwrap();
    sqlx::raw_sql(shadow::MIGRATION)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO shadow_v2.identity(network,instance_id) VALUES('testnet-10','00000000-0000-0000-0000-000000000001')").execute(&pool).await.unwrap();
    sqlx::query("UPDATE shadow_v2.control SET checkpoint_hash=$1,checkpoint_score=0,history_start_hash=$1,source_validated=true,seed_manifest='{}'").bind(vec![0u8;32]).execute(&pool).await.unwrap();
    sqlx::query("SELECT shadow_v2.install_guards()")
        .execute(&pool)
        .await
        .unwrap();
    let epoch: i64 = sqlx::query_scalar("SELECT shadow_v2.acquire('test')")
        .fetch_one(&pool)
        .await
        .unwrap();
    let steps = json!([{"kind":"apply","evidence":body}]);
    let plan: i64 = sqlx::query_scalar(
        "SELECT shadow_v2.begin_plan($1,$2,$3,10,ARRAY['ingestor','projection'],$4)",
    )
    .bind(epoch)
    .bind(vec![0u8; 32])
    .bind(&hash)
    .bind(steps)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(writer.apply_shadow_step(epoch, plan, 0).await.unwrap());
    assert!(!writer.apply_shadow_step(epoch, plan, 0).await.unwrap());
    assert_eq!(state(&pool).await, expected);
    let undo: i64 = sqlx::query_scalar("SELECT count(*) FROM shadow_v2.undo WHERE plan_id=$1")
        .bind(plan)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(undo > 0);
    for consumer in ["ingestor", "projection"] {
        sqlx::query("SELECT shadow_v2.consumer_done($1,$2,$3)")
            .bind(epoch)
            .bind(plan)
            .bind(consumer)
            .execute(&pool)
            .await
            .unwrap();
    }
    let rev: i64 = sqlx::query_scalar("SELECT revision FROM shadow_v2.control")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("SELECT shadow_v2.publish($1,$2,$3)")
        .bind(epoch)
        .bind(plan)
        .bind(rev)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("SELECT shadow_v2.release($1,$2)")
        .bind(epoch)
        .bind(plan)
        .execute(&pool)
        .await
        .unwrap();
    let epoch: i64 = sqlx::query_scalar("SELECT shadow_v2.acquire('test2')")
        .fetch_one(&pool)
        .await
        .unwrap();
    let plan: i64 = sqlx::query_scalar(
        "SELECT shadow_v2.begin_plan($1,$2,$3,0,ARRAY['ingestor','projection'],$4)",
    )
    .bind(epoch)
    .bind(&hash)
    .bind(vec![0u8; 32])
    .bind(json!([{"kind":"remove","evidence":{"hash":hex::encode(&hash)}}]))
    .fetch_one(&pool)
    .await
    .unwrap();
    writer.apply_shadow_step(epoch, plan, 0).await.unwrap();
    let active: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE status='active'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active, 0);
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM shadow_v2.acceptance_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(events, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_shadow_effect_does_not_advance_cursor(pool: PgPool) {
    sqlx::raw_sql(shadow::MIGRATION)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE shadow_v2.control SET checkpoint_hash=$1,history_start_hash=$1")
        .bind(vec![0u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    let epoch: i64 = sqlx::query_scalar("SELECT shadow_v2.acquire('test')")
        .fetch_one(&pool)
        .await
        .unwrap();
    let plan: i64 = sqlx::query_scalar(
        "SELECT shadow_v2.begin_plan($1,$2,$3,1,ARRAY['ingestor','projection'],$4)",
    )
    .bind(epoch)
    .bind(vec![0u8; 32])
    .bind(vec![1u8; 32])
    .bind(json!([{"kind":"anchor","evidence":{"hash":"invalid"}}]))
    .fetch_one(&pool)
    .await
    .unwrap();
    let writer = PgPersister::new(pool.clone());
    assert!(writer.apply_shadow_step(epoch, plan, 0).await.is_err());
    let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM shadow_v2.plans WHERE id=$1")
        .bind(plan)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cursor, 0);
}
