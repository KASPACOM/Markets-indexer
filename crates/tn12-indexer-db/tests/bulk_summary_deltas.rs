use sqlx::PgPool;
use tn12_indexer_core::{RestTransaction, RestTxInput};
use tn12_indexer_db::{Persister, PgPersister};

fn output(id: u64, cid: u64, score: u64) -> RestTransaction {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let mut tx = fixture[0].clone();
    tx.transaction_id = format!("{id:064x}");
    tx.inputs.clear();
    tx.outputs.truncate(1);
    tx.outputs[0].transaction_id = tx.transaction_id.clone();
    tx.outputs[0].index = 0;
    tx.outputs[0].amount = 100;
    tx.outputs[0].script_public_key = format!("aa20{cid:064x}87");
    tx.outputs[0].script_public_key_address = None;
    tx.accepting_block_hash = Some(format!("{:064x}", id + 1_000_000));
    tx.accepting_block_blue_score = Some(score);
    tx.accepting_block_time = Some(score * 1000);
    tx.block_time = score * 1000;
    tx
}
fn spend(id: u64, parent: &RestTransaction, score: u64) -> RestTransaction {
    let mut tx = parent.clone();
    tx.transaction_id = format!("{id:064x}");
    tx.outputs[0].transaction_id = tx.transaction_id.clone();
    tx.accepting_block_hash = Some(format!("{:064x}", id + 1_000_000));
    tx.accepting_block_blue_score = Some(score);
    tx.accepting_block_time = Some(score * 1000);
    tx.block_time = score * 1000;
    tx.inputs = vec![RestTxInput {
        previous_outpoint_hash: parent.transaction_id.clone(),
        previous_outpoint_index: "0".into(),
        previous_outpoint_amount: Some(100),
        previous_outpoint_script: Some(parent.outputs[0].script_public_key.clone()),
        signature_script: "0151".into(),
        ..Default::default()
    }];
    tx
}
async fn assert_refresh_parity(pool: &PgPool) {
    let before: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s ORDER BY covenant_id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let templates: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_template_summaries s ORDER BY template",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    sqlx::query("SELECT refresh_covenant_summary(covenant_id) FROM covenants")
        .execute(pool)
        .await
        .unwrap();
    let after: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s ORDER BY covenant_id",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(before, after);
    let after_templates: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_template_summaries s ORDER BY template",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(templates, after_templates);
}

#[sqlx::test(migrations = "./migrations")]
async fn continuation_updates_each_summary_once_and_replay_is_noop(pool: PgPool) {
    let writer = PgPersister::new(pool.clone()).with_generic_bulk_persist(true);
    let parents = (0..16)
        .map(|i| output(100 + i, 500 + i, 100))
        .collect::<Vec<_>>();
    writer.persist_batch(&parents).await.unwrap();
    sqlx::raw_sql("CREATE TABLE summary_update_audit(cid bytea); CREATE FUNCTION audit_summary_delta() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO summary_update_audit VALUES(NEW.covenant_id); RETURN NEW; END $$; CREATE TRIGGER audit_summary_delta AFTER UPDATE ON covenant_summaries FOR EACH ROW EXECUTE FUNCTION audit_summary_delta();")
        .execute(&pool).await.unwrap();
    let children = parents
        .iter()
        .enumerate()
        .map(|(i, p)| spend(200 + i as u64, p, 200))
        .collect::<Vec<_>>();
    writer.persist_batch(&children).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM summary_update_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 16, "exactly one net summary update per covenant");
    writer.persist_batch(&children).await.unwrap();
    let replay_count: i64 = sqlx::query_scalar("SELECT count(*) FROM summary_update_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(replay_count, count);
    assert_refresh_parity(&pool).await;
    for tx in &children {
        writer
            .revert_block(&hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap())
            .await
            .unwrap();
    }
    assert_refresh_parity(&pool).await;
    writer.persist_batch(&children).await.unwrap();
    assert_refresh_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn older_outputs_and_spent_maxima_keep_the_canonical_latest_pointer(pool: PgPool) {
    let writer = PgPersister::new(pool.clone()).with_generic_bulk_persist(true);
    let mut children = Vec::new();
    for case in 0..4_u64 {
        let parents = [
            output(100 + case * 10, 500 + case, 100),
            output(101 + case * 10, 500 + case, 200),
            output(102 + case * 10, 500 + case, 300),
        ];
        for p in &parents {
            writer.persist_tx(p).await.unwrap();
        }
        let (parent, score) = match case {
            0 => (&parents[0], 250),
            1 => (&parents[2], 250),
            2 => (&parents[2], 50),
            _ => (&parents[2], 400),
        };
        children.push(spend(800 + case, parent, score));
    }
    writer.persist_batch(&children).await.unwrap();
    assert_refresh_parity(&pool).await;
    let scores: Vec<i64> = sqlx::query_scalar(
        "SELECT latest_active_blue_score FROM covenant_summaries ORDER BY covenant_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(scores, vec![300, 250, 200, 400]);
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_summary_delta_rolls_back_utxos_and_actions(pool: PgPool) {
    let writer = PgPersister::new(pool.clone()).with_generic_bulk_persist(true);
    let parents = (0..4)
        .map(|i| output(100 + i, 500 + i, 100))
        .collect::<Vec<_>>();
    writer.persist_batch(&parents).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION fail_delta() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected summary failure'; END $$; CREATE TRIGGER fail_delta BEFORE UPDATE ON covenant_summaries FOR EACH ROW EXECUTE FUNCTION fail_delta();")
        .execute(&pool).await.unwrap();
    let children = parents
        .iter()
        .enumerate()
        .map(|(i, p)| spend(200 + i as u64, p, 200))
        .collect::<Vec<_>>();
    assert!(writer.persist_batch(&children).await.is_err());
    let counts: (i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM covenant_utxos),(SELECT count(*) FROM covenant_utxos WHERE status='spent')").fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (4, 0));
    sqlx::query("DROP TRIGGER fail_delta ON covenant_summaries")
        .execute(&pool)
        .await
        .unwrap();
    writer.persist_batch(&children).await.unwrap();
    assert_refresh_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_active_pointer_metadata_is_repaired_before_reusing_the_maximum(pool: PgPool) {
    let writer = PgPersister::new(pool.clone()).with_generic_bulk_persist(true);
    let mut children = Vec::new();
    for case in 0..2_u64 {
        let parents = [
            output(100 + case * 10, 500 + case, 100),
            output(101 + case * 10, 500 + case, 200),
            output(102 + case * 10, 500 + case, 300),
        ];
        for p in &parents {
            writer.persist_tx(p).await.unwrap();
        }
        children.push(spend(800 + case, &parents[case as usize * 2], 150));
    }
    // An artificially low cached maximum must not let an older new output
    // replace the actual maximum. Correct counts remain the delta invariant.
    sqlx::query("UPDATE covenant_summaries SET current_address='wrong',latest_active_block=decode(repeat('ff',32),'hex'),latest_active_blue_score=1")
        .execute(&pool).await.unwrap();
    writer.persist_batch(&children).await.unwrap();
    assert_refresh_parity(&pool).await;
    let scores: Vec<i64> = sqlx::query_scalar(
        "SELECT latest_active_blue_score FROM covenant_summaries ORDER BY covenant_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(scores, vec![300, 200]);
}

#[sqlx::test(migrations = "./migrations")]
async fn summary_delta_disables_jit_only_inside_its_transaction(pool: PgPool) {
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    sqlx::raw_sql("SET jit=on; SET jit_above_cost=0;")
        .execute(&single)
        .await
        .unwrap();
    let writer = PgPersister::new(single.clone()).with_generic_bulk_persist(true);
    let parents = (0..2)
        .map(|i| output(900 + i, 900 + i, 100))
        .collect::<Vec<_>>();
    writer.persist_batch(&parents).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION require_non_jit_summary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF current_setting('jit') <> 'off' THEN RAISE EXCEPTION 'summary compilation must be disabled'; END IF; RETURN NEW; END $$; CREATE TRIGGER require_non_jit_summary BEFORE UPDATE ON covenant_summaries FOR EACH ROW EXECUTE FUNCTION require_non_jit_summary();")
        .execute(&single).await.unwrap();
    let children = parents
        .iter()
        .enumerate()
        .map(|(i, p)| spend(950 + i as u64, p, 200))
        .collect::<Vec<_>>();
    writer.persist_batch(&children).await.unwrap();
    let setting: String = sqlx::query_scalar("SHOW jit")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(
        setting, "on",
        "JIT setting must return to the session value after commit"
    );
    sqlx::query("DROP TRIGGER require_non_jit_summary ON covenant_summaries")
        .execute(&single)
        .await
        .unwrap();
    assert_refresh_parity(&single).await;
}
