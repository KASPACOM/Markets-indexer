//! Captured TN10 consolidation spends. Parent rows are reconstructed from
//! resolved prevouts; this checks persistence semantics, not source completeness.
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use tn12_indexer_core::{RestTransaction, RestTxOutput};
use tn12_indexer_db::{Persister, PgPersister};

async fn snapshot(pool: &PgPool) -> Vec<Value> {
    let mut result = Vec::new();
    for query in [
        "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) - 'indexed_at_ms' AS v FROM blocks t) s",
        "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM covenants t) s",
        "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) AS v FROM covenant_utxos t) s",
        "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) - 'id' AS v FROM covenant_actions t) s",
        "SELECT COALESCE(jsonb_agg(v ORDER BY v::text), '[]'::jsonb) FROM (SELECT to_jsonb(t) - 'updated_at_ms' AS v FROM covenant_summaries t) s",
    ] {
        result.push(sqlx::query_scalar(query).fetch_one(pool).await.unwrap());
    }
    result
}

fn captured() -> Vec<RestTransaction> {
    serde_json::from_str(include_str!("fixtures/tn10-consolidation-2.json")).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn captured_consolidations_match_serial_replay_and_reorg(pool: PgPool) {
    compare_serial_and_bulk(pool, captured()).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn single_consolidation_uses_set_based_input_writes(pool: PgPool) {
    compare_serial_and_bulk(pool, captured()[..1].to_vec()).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn mixed_outputless_and_output_transactions_preserve_actions(pool: PgPool) {
    let mut txs = captured();
    txs[1].inputs.truncate(1);
    txs[1].outputs[0].script_public_key = format!("aa20{}87", "99".repeat(32));
    txs[1].outputs[0].script_public_key_address = Some("kaspatest:synthetic-mixed-output".into());
    compare_serial_and_bulk(pool, txs).await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires TN10_CONSOLIDATION_FIXTURE captured window path"]
async fn captured_full_window_paired_benchmark(pool: PgPool) {
    let path = std::env::var("TN10_CONSOLIDATION_FIXTURE").unwrap();
    let txs: Vec<RestTransaction> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(txs.len(), 63);
    assert_eq!(txs.iter().map(|tx| tx.inputs.len()).sum::<usize>(), 5274);
    compare_with_plan(pool, txs, &[false, true, true, false, false, true], false).await;
}

async fn compare_serial_and_bulk(pool: PgPool, txs: Vec<RestTransaction>) {
    compare_with_plan(pool, txs, &[false, true], true).await;
}

async fn compare_with_plan(
    pool: PgPool,
    txs: Vec<RestTransaction>,
    plan: &[bool],
    count_statements: bool,
) {
    let inputs = txs.iter().map(|tx| tx.inputs.len()).sum::<usize>() as u64;
    let outputs = txs
        .iter()
        .flat_map(|tx| &tx.outputs)
        .filter(|o| o.script_public_key.starts_with("aa20"))
        .count() as u64;
    let serial = PgPersister::new(pool.clone());
    let mut parents: BTreeMap<String, RestTransaction> = BTreeMap::new();
    for tx in &txs {
        for input in &tx.inputs {
            let source_id = input.previous_outpoint_hash.clone();
            let source = parents
                .entry(source_id.clone())
                .or_insert_with(|| RestTransaction {
                    transaction_id: source_id.clone(),
                    block_time: tx.accepting_block_time.unwrap() - 1,
                    is_accepted: true,
                    accepting_block_hash: Some(source_id.clone()),
                    accepting_block_blue_score: Some(tx.accepting_block_blue_score.unwrap() - 1),
                    ..Default::default()
                });
            source.outputs.push(RestTxOutput {
                transaction_id: source_id,
                index: input.previous_outpoint_index.parse().unwrap(),
                amount: input.previous_outpoint_amount.unwrap(),
                script_public_key: input.previous_outpoint_script.clone().unwrap(),
                script_public_key_address: input.previous_outpoint_address.clone(),
                ..Default::default()
            });
        }
    }
    for source in parents.values() {
        serial.persist_tx(source).await.unwrap();
    }
    sqlx::raw_sql(
        "CREATE TABLE consolidation_update_count (n BIGINT NOT NULL); \
        INSERT INTO consolidation_update_count VALUES (0); \
        CREATE FUNCTION count_consolidation_update() RETURNS TRIGGER LANGUAGE plpgsql AS $$ \
        BEGIN UPDATE consolidation_update_count SET n=n+1; RETURN NULL; END $$; \
        CREATE TRIGGER count_consolidation_update AFTER UPDATE ON covenant_utxos \
        FOR EACH STATEMENT EXECUTE FUNCTION count_consolidation_update();",
    )
    .execute(&pool)
    .await
    .unwrap();
    if !count_statements {
        // Statement counters prove batching in correctness tests but add work to
        // every serial input update. Exclude that instrumentation from timings.
        sqlx::query("ALTER TABLE covenant_utxos DISABLE TRIGGER count_consolidation_update")
            .execute(&pool)
            .await
            .unwrap();
    }
    let blocks: BTreeSet<_> = txs
        .iter()
        .map(|tx| tx.accepting_block_hash.clone().unwrap())
        .collect();
    let mut expected = None;
    for &bulk in plan {
        sqlx::query("UPDATE consolidation_update_count SET n=0")
            .execute(&pool)
            .await
            .unwrap();
        let writer = PgPersister::new(pool.clone()).with_generic_bulk_persist(bulk);
        let started = Instant::now();
        let stats = writer.persist_batch(&txs).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(stats.utxos_spent, inputs);
        assert_eq!(stats.utxos_inserted, outputs);
        assert_eq!(stats.actions_inserted, inputs + outputs);
        assert_eq!(stats.covenants_inserted, outputs);
        let statements: i64 = sqlx::query_scalar("SELECT n FROM consolidation_update_count")
            .fetch_one(&pool)
            .await
            .unwrap();
        eprintln!(
            "consolidation bulk={bulk} counted={count_statements} elapsed_us={} utxo_update_statements={statements}",
            elapsed.as_micros()
        );
        if bulk && count_statements {
            assert!(
                statements < inputs as i64,
                "consolidations fell back to scalar input writes"
            );
        }
        // IDs are generated independently on replay, but their relative order
        // is part of the action stream consumed by projections and pagination.
        for tx in &txs {
            let ordered: Vec<(String, Option<String>)> = sqlx::query_as(
                "SELECT action, inputs->'previousOutpoint'->>'hash' FROM covenant_actions \
                 WHERE txid = decode($1, 'hex') ORDER BY id",
            )
            .bind(&tx.transaction_id)
            .fetch_all(&pool)
            .await
            .unwrap();
            let mut expected_order: Vec<_> = tx
                .inputs
                .iter()
                .map(|input| {
                    (
                        "spend".to_string(),
                        Some(input.previous_outpoint_hash.clone()),
                    )
                })
                .collect();
            for output in &tx.outputs {
                if output.script_public_key.starts_with("aa20") {
                    expected_order.push(("deploy".to_string(), None));
                }
            }
            assert_eq!(ordered, expected_order);
        }
        let state = snapshot(&pool).await;
        if let Some(expected) = &expected {
            assert_eq!(&state, expected);
        } else {
            expected = Some(state.clone());
        }
        let replay = writer.persist_batch(&txs).await.unwrap();
        assert_eq!(replay.utxos_spent, 0);
        assert_eq!(replay.actions_inserted, 0);
        assert_eq!(snapshot(&pool).await, state);
        // A different spender must fail atomically and leave every table unchanged.
        let mut conflict = txs.clone();
        conflict[0].transaction_id = "ab".repeat(32);
        assert!(writer.persist_batch(&conflict).await.is_err());
        assert_eq!(snapshot(&pool).await, state);
        for block in &blocks {
            writer
                .revert_block(&hex::decode(block).unwrap())
                .await
                .unwrap();
        }
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE status='active'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(active, inputs as i64);
    }
}
