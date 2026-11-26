//! Regression coverage for replay after an accepting block leaves the chain.

use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::persist::{
    AcceptanceConflict, AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
    CanonicalBlockReplacement,
};
use tn12_indexer_db::{Persister, PgPersister};

#[sqlx::test(migrations = "./migrations")]
async fn serial_replay_does_not_silently_accept_a_different_accepting_block(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx = fixture[0].clone();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&tx).await.unwrap();

    let mut replacement = tx.clone();
    replacement.accepting_block_hash = Some("ef".repeat(32));
    let result = writer.persist_tx(&replacement).await;
    assert!(
        result.is_err(),
        "a replay must request canonical reconciliation instead of reporting success with stale accepting-block references"
    );
    let error = result.unwrap_err();
    let conflict = error
        .downcast_ref::<AcceptanceConflict>()
        .expect("typed acceptance conflict");
    assert_eq!(
        conflict.persisted_hash,
        tx.accepting_block_hash.clone().unwrap()
    );
    assert_eq!(
        conflict.incoming_hash,
        replacement.accepting_block_hash.clone().unwrap()
    );

    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT encode(created_block, 'hex') FROM covenant_utxos WHERE txid = decode($1, 'hex')",
    )
    .bind(&tx.transaction_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(!hashes.is_empty());
    assert!(hashes
        .iter()
        .all(|hash| Some(hash) == tx.accepting_block_hash.as_ref()));
}

fn proof(
    tx: &RestTransaction,
    replacement_hash: &str,
    members: Vec<Vec<u8>>,
) -> CanonicalBlockReplacement {
    proof_with_timestamp(
        tx,
        replacement_hash,
        members,
        tx.accepting_block_time.unwrap_or(tx.block_time),
    )
}

fn proof_with_timestamp(
    tx: &RestTransaction,
    replacement_hash: &str,
    members: Vec<Vec<u8>>,
    timestamp: u64,
) -> CanonicalBlockReplacement {
    let old = AcceptingBlockEvidence {
        hash: hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap(),
        is_chain_block: false,
        blue_score: tx.accepting_block_blue_score.unwrap(),
        timestamp: tx.accepting_block_time.unwrap_or(tx.block_time),
        selected_parent: vec![0x55; 32],
        parents: vec![vec![vec![0x55; 32]]],
        accepted_id_merkle_root: vec![0x66; 32],
        utxo_commitment: vec![0x77; 32],
    };
    let mut new = old.clone();
    new.hash = hex::decode(replacement_hash).unwrap();
    new.is_chain_block = true;
    new.timestamp = timestamp;
    let txid = hex::decode(&tx.transaction_id).unwrap();
    let outputs = if members.contains(&txid) {
        tx.outputs
            .iter()
            .map(|output| AcceptedOutputEvidence {
                transaction_id: txid.clone(),
                vout: output.index as i32,
                amount: output.amount,
                script: hex::decode(&output.script_public_key).unwrap(),
            })
            .collect()
    } else {
        vec![]
    };
    let inputs = if members.contains(&txid) {
        tx.inputs
            .iter()
            .map(|input| AcceptedInputEvidence {
                transaction_id: txid.clone(),
                previous_txid: hex::decode(&input.previous_outpoint_hash).unwrap(),
                previous_vout: input.previous_outpoint_index.parse().unwrap(),
                previous_amount: input.previous_outpoint_amount,
                previous_script: input
                    .previous_outpoint_script
                    .as_ref()
                    .map(|script| hex::decode(script).unwrap()),
            })
            .collect()
    } else {
        vec![]
    };
    CanonicalBlockReplacement::verify(
        old.clone(),
        new,
        old.blue_score + 1_001,
        members,
        inputs,
        outputs,
    )
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_reassociation_preserves_later_spends_and_rejects_stale_replay(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx = fixture[0].clone();
    let mut later = fixture[1].clone();
    later.accepting_block_hash = Some("de".repeat(32));
    later.accepting_block_blue_score = Some(tx.accepting_block_blue_score.unwrap() + 1);
    later.accepting_block_time = Some(tx.accepting_block_time.unwrap_or(tx.block_time) + 1000);
    later.inputs[0].previous_outpoint_hash = tx.transaction_id.clone();
    later.inputs[0].previous_outpoint_index = tx.outputs[0].index.to_string();
    later.inputs[0].previous_outpoint_amount = Some(tx.outputs[0].amount);
    later.inputs[0].previous_outpoint_script = Some(tx.outputs[0].script_public_key.clone());
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&tx).await.unwrap();
    writer.persist_tx(&later).await.unwrap();
    let snapshot_sql = "SELECT (to_jsonb(u) - 'created_block' - 'spent_block') FROM covenant_utxos u ORDER BY txid, vout";
    let before: Vec<serde_json::Value> = sqlx::query_scalar(snapshot_sql)
        .fetch_all(&pool)
        .await
        .unwrap();
    let replacement_hash = "ef".repeat(32);
    let evidence = proof_with_timestamp(
        &tx,
        &replacement_hash,
        vec![hex::decode(&tx.transaction_id).unwrap()],
        tx.accepting_block_time.unwrap_or(tx.block_time) + 60,
    );
    let stats = writer.reconcile_accepting_block(&evidence).await.unwrap();
    assert_eq!(stats.created_outputs, 1);
    assert_eq!(stats.actions, 1);
    assert_eq!(stats.covenants, 1);
    let after: Vec<serde_json::Value> = sqlx::query_scalar(snapshot_sql)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "reassociation must preserve status, amounts, script and spending transaction"
    );
    let spent: (String, String, String) = sqlx::query_as(
        "SELECT encode(created_block, 'hex'), encode(spent_block, 'hex'), status FROM covenant_utxos WHERE txid=decode($1,'hex')",
    ).bind(&tx.transaction_id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        spent,
        (
            replacement_hash.clone(),
            later.accepting_block_hash.unwrap(),
            "spent".into()
        )
    );
    let mut canonical = tx.clone();
    canonical.accepting_block_hash = Some(replacement_hash.clone());
    canonical.accepting_block_time = Some(tx.accepting_block_time.unwrap_or(tx.block_time) + 60);
    writer.persist_tx(&canonical).await.unwrap();
    assert!(
        writer
            .reconcile_accepting_block(&evidence)
            .await
            .unwrap()
            .already_reconciled
    );
    assert!(writer
        .persist_tx(&tx)
        .await
        .unwrap_err()
        .downcast_ref::<AcceptanceConflict>()
        .is_some());
    // An old removal event must not erase the durable replay guard.
    writer
        .revert_block(&hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap())
        .await
        .unwrap();
    assert!(writer
        .persist_tx(&tx)
        .await
        .unwrap_err()
        .downcast_ref::<AcceptanceConflict>()
        .is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_reassociation_rejects_incomplete_membership_atomically(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx = fixture[0].clone();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&tx).await.unwrap();
    let evidence = proof(&tx, &"ef".repeat(32), vec![vec![0x11; 32]]);
    let error = writer
        .reconcile_accepting_block(&evidence)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("outside canonical acceptance membership"));
    let recorded: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(recorded, 0);
    writer.persist_tx(&tx).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn reverting_replacement_target_allows_a_later_canonical_flip(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx = fixture[0].clone();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&tx).await.unwrap();
    let replacement = "ef".repeat(32);
    writer
        .reconcile_accepting_block(&proof(
            &tx,
            &replacement,
            vec![hex::decode(&tx.transaction_id).unwrap()],
        ))
        .await
        .unwrap();
    writer
        .revert_block(&hex::decode(&replacement).unwrap())
        .await
        .unwrap();
    let guards: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(guards, 0);
    writer.persist_tx(&tx).await.unwrap();
    let canonical: bool =
        sqlx::query_scalar("SELECT is_chain_block FROM blocks WHERE hash=decode($1,'hex')")
            .bind(tx.accepting_block_hash.unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(canonical);
}

#[sqlx::test(migrations = "./migrations")]
async fn replacement_chain_survives_intermediate_removal_and_retires_with_terminal(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let a = fixture[0].clone();
    let mut b = a.clone();
    b.accepting_block_hash = Some("ee".repeat(32));
    let c = "ef".repeat(32);
    let members = vec![hex::decode(&a.transaction_id).unwrap()];
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&a).await.unwrap();
    writer
        .reconcile_accepting_block(&proof(
            &a,
            b.accepting_block_hash.as_ref().unwrap(),
            members.clone(),
        ))
        .await
        .unwrap();
    writer
        .reconcile_accepting_block(&proof(&b, &c, members))
        .await
        .unwrap();
    writer
        .revert_block(&hex::decode(b.accepting_block_hash.as_ref().unwrap()).unwrap())
        .await
        .unwrap();
    for stale in [&a, &b] {
        let error = writer.persist_tx(stale).await.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<AcceptanceConflict>()
                .unwrap()
                .persisted_hash,
            c
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    writer
        .revert_block(&hex::decode(&c).unwrap())
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    writer.persist_tx(&a).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn reconciliation_preview_is_read_only_and_spend_reference_moves_on_apply(pool: PgPool) {
    use tn12_indexer_core::RestTxOutput;
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let mut tx = fixture[0].clone();
    let input = &tx.inputs[0];
    let source = RestTransaction {
        transaction_id: input.previous_outpoint_hash.clone(),
        is_accepted: true,
        accepting_block_hash: Some("aa".repeat(32)),
        accepting_block_blue_score: Some(tx.accepting_block_blue_score.unwrap() - 1),
        block_time: tx.block_time - 1000,
        outputs: vec![RestTxOutput {
            index: input.previous_outpoint_index.parse().unwrap(),
            amount: input.previous_outpoint_amount.unwrap(),
            script_public_key: input.previous_outpoint_script.clone().unwrap(),
            script_public_key_address: input.previous_outpoint_address.clone(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut second_source = source.clone();
    second_source.transaction_id = "bb".repeat(32);
    second_source.outputs[0].script_public_key = format!("aa20{}87", "cc".repeat(32));
    let mut second_input = tx.inputs[0].clone();
    second_input.previous_outpoint_hash = second_source.transaction_id.clone();
    second_input.previous_outpoint_script =
        Some(second_source.outputs[0].script_public_key.clone());
    tx.inputs.push(second_input);
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&source).await.unwrap();
    writer.persist_tx(&second_source).await.unwrap();
    writer.persist_tx(&tx).await.unwrap();
    let replacement = "ef".repeat(32);
    let evidence = proof(
        &tx,
        &replacement,
        vec![hex::decode(&tx.transaction_id).unwrap()],
    );
    let mut missing_input = tx.clone();
    missing_input.inputs.remove(0);
    let incomplete = proof(
        &missing_input,
        &replacement,
        vec![hex::decode(&tx.transaction_id).unwrap()],
    );
    let error = writer
        .reconcile_accepting_block(&incomplete)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("stored spend is absent"));
    sqlx::query("INSERT INTO blocks SELECT decode($1,'hex'),blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms FROM blocks LIMIT 1")
        .bind("dd".repeat(32)).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE covenant_utxos SET spent_block=decode($2,'hex') WHERE txid=decode($1,'hex')",
    )
    .bind(&source.transaction_id)
    .bind("dd".repeat(32))
    .execute(&pool)
    .await
    .unwrap();
    // The spend action must expose an omitted input even outside the block pair.
    let error = writer
        .reconcile_accepting_block(&incomplete)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("spend action conflicts"));
    let error = writer
        .reconcile_accepting_block(&evidence)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("spend action conflicts"));
    sqlx::query(
        "UPDATE covenant_utxos SET spent_block=decode($2,'hex') WHERE txid=decode($1,'hex')",
    )
    .bind(&source.transaction_id)
    .bind(tx.accepting_block_hash.as_ref().unwrap())
    .execute(&pool)
    .await
    .unwrap();
    let before: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM covenant_utxos u ORDER BY txid,vout")
            .fetch_all(&pool)
            .await
            .unwrap();
    let preview = writer
        .preview_accepting_block_reconciliation(&evidence)
        .await
        .unwrap();
    assert_eq!(preview.spent_inputs, 2);
    assert_eq!(preview.actions, 3);
    let after: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT to_jsonb(u) FROM covenant_utxos u ORDER BY txid,vout")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    let stats = writer.reconcile_accepting_block(&evidence).await.unwrap();
    assert_eq!(stats.spent_inputs, 2);
    let spend: (String,String,String) = sqlx::query_as("SELECT encode(spent_block,'hex'),encode(spent_by_txid,'hex'),status FROM covenant_utxos WHERE txid=decode($1,'hex')")
        .bind(&source.transaction_id).fetch_one(&pool).await.unwrap();
    assert_eq!(spend, (replacement, tx.transaction_id, "spent".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_reassociation_rejects_corrupt_output_and_third_block_evidence(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx = fixture[0].clone();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&tx).await.unwrap();
    let evidence = proof(
        &tx,
        &"ef".repeat(32),
        vec![hex::decode(&tx.transaction_id).unwrap()],
    );
    sqlx::query("UPDATE covenant_utxos SET amount_sompi=amount_sompi+1")
        .execute(&pool)
        .await
        .unwrap();
    let error = writer
        .reconcile_accepting_block(&evidence)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("conflicting content evidence"));
    sqlx::query("UPDATE covenant_utxos SET amount_sompi=amount_sompi-1")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO blocks SELECT decode($1,'hex'),blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms FROM blocks LIMIT 1")
        .bind("dd".repeat(32)).execute(&pool).await.unwrap();
    sqlx::query("UPDATE covenant_actions SET block_hash=decode($1,'hex')")
        .bind("dd".repeat(32))
        .execute(&pool)
        .await
        .unwrap();
    let error = writer
        .reconcile_accepting_block(&evidence)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("third block"));
}

#[sqlx::test(migrations = "./migrations")]
async fn bulk_replay_checks_action_acceptance_and_prioritizes_content_corruption(pool: PgPool) {
    use tn12_indexer_core::RestTxOutput;
    use tn12_indexer_db::persist::AcceptanceEvidenceConflict;
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let mut batch = fixture[..2].to_vec();
    let writer = PgPersister::new(pool.clone())
        .with_bounded_writer_lock_wait()
        .with_generic_bulk_persist(true);
    for tx in &batch {
        for input in &tx.inputs {
            writer
                .persist_tx(&RestTransaction {
                    transaction_id: input.previous_outpoint_hash.clone(),
                    is_accepted: true,
                    accepting_block_hash: Some("aa".repeat(32)),
                    accepting_block_blue_score: Some(100),
                    block_time: 1000,
                    outputs: vec![RestTxOutput {
                        index: input.previous_outpoint_index.parse().unwrap(),
                        amount: input.previous_outpoint_amount.unwrap(),
                        script_public_key: input.previous_outpoint_script.clone().unwrap(),
                        script_public_key_address: input.previous_outpoint_address.clone(),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .await
                .unwrap();
        }
    }
    writer.persist_batch(&batch).await.unwrap();
    let old = batch[0].accepting_block_hash.clone().unwrap();
    let new = "ef".repeat(32);
    sqlx::query("INSERT INTO blocks SELECT decode($1,'hex'),blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms FROM blocks WHERE hash=decode($2,'hex')")
        .bind(&new).bind(&old).execute(&pool).await.unwrap();
    let ids: Vec<Vec<u8>> = batch
        .iter()
        .map(|tx| hex::decode(&tx.transaction_id).unwrap())
        .collect();
    sqlx::query(
        "UPDATE covenant_utxos SET created_block=decode($2,'hex') WHERE txid=ANY($1::bytea[])",
    )
    .bind(&ids)
    .bind(&new)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE covenant_utxos SET spent_block=decode($2,'hex') WHERE spent_by_txid=ANY($1::bytea[])")
        .bind(&ids).bind(&new).execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE covenants SET genesis_block=decode($2,'hex') WHERE genesis_txid=ANY($1::bytea[])",
    )
    .bind(&ids)
    .bind(&new)
    .execute(&pool)
    .await
    .unwrap();
    for tx in &mut batch {
        tx.accepting_block_hash = Some(new.clone());
    }
    let error = writer.persist_batch(&batch).await.unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<AcceptanceConflict>()
            .unwrap()
            .persisted_hash,
        old
    );
    sqlx::query("UPDATE covenant_utxos SET amount_sompi=amount_sompi+1 WHERE txid=$1")
        .bind(&ids[0])
        .execute(&pool)
        .await
        .unwrap();
    let error = writer.persist_batch(&batch).await.unwrap_err();
    assert!(error.downcast_ref::<AcceptanceEvidenceConflict>().is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_reassociation_updates_timestamp_metadata_and_projections(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx = fixture[0].clone();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&tx).await.unwrap();
    let initial = tx.accepting_block_time.unwrap_or(tx.block_time);
    let mut previous = tx.clone();
    for (byte, timestamp) in [("ed", initial + 60), ("ef", initial - 60)] {
        let replacement = byte.repeat(32);
        let evidence = proof_with_timestamp(
            &previous,
            &replacement,
            vec![hex::decode(&tx.transaction_id).unwrap()],
            timestamp,
        );
        let preview = writer
            .preview_accepting_block_reconciliation(&evidence)
            .await
            .unwrap();
        assert_eq!(preview.actions, 1);
        let stats = writer.reconcile_accepting_block(&evidence).await.unwrap();
        assert_eq!(
            (stats.created_outputs, stats.actions, stats.covenants),
            (1, 1, 1)
        );
        let metadata: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT b.timestamp_ms, c.created_at_ms, a.block_time_ms, s.latest_action_time_ms FROM covenants c JOIN covenant_actions a USING(covenant_id) JOIN blocks b ON b.hash=c.genesis_block JOIN covenant_action_summaries s USING(covenant_id) WHERE c.genesis_txid=decode($1,'hex')"
        ).bind(&tx.transaction_id).fetch_one(&pool).await.unwrap();
        assert_eq!(
            metadata,
            (
                timestamp as i64,
                timestamp as i64,
                timestamp as i64,
                timestamp as i64
            )
        );
        let template: (i64,i64,i64) = sqlx::query_as("SELECT latest_created_at_ms,latest_action_time_ms,action_count FROM covenant_template_summaries WHERE template='Unknown'").fetch_one(&pool).await.unwrap();
        assert_eq!(template, (timestamp as i64, timestamp as i64, 1));
        let dirty: i64 = sqlx::query_scalar("SELECT count(*) FROM kcc20_projection_dirty WHERE txid=decode($1,'hex') AND reason='acceptance_reconciliation'").bind(&tx.transaction_id).fetch_one(&pool).await.unwrap();
        assert!(
            dirty > 0,
            "timestamp change must invalidate derived activity and market data"
        );
        assert!(
            writer
                .reconcile_accepting_block(&evidence)
                .await
                .unwrap()
                .already_reconciled
        );
        previous.accepting_block_hash = Some(replacement);
        previous.accepting_block_time = Some(timestamp);
        writer.persist_tx(&previous).await.unwrap();
    }
    assert!(
        writer.persist_tx(&tx).await.is_err(),
        "stale acceptance must remain rejected"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn backward_action_timestamp_batch_avoids_full_template_rebuild(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut txs = Vec::new();
    for i in 0..512 {
        let mut tx = fixture[i % fixture.len()].clone();
        tx.transaction_id = format!("{:064x}", i + 100_000);
        txs.push(tx);
    }
    writer.persist_batch(&txs).await.unwrap();
    let original = txs[0].accepting_block_time.unwrap_or(txs[0].block_time) as i64;
    sqlx::raw_sql("CREATE OR REPLACE FUNCTION refresh_covenant_template_summary(target_template TEXT) RETURNS VOID LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'full template rebuild is forbidden in timestamp batch'; END; $$;").execute(&pool).await.unwrap();
    // One statement moves many times backwards and one forwards. The statement
    // repair must observe all final action summaries, including the later action.
    sqlx::query("UPDATE covenant_actions SET block_time_ms = CASE WHEN txid=decode($1,'hex') THEN $2+60 ELSE $2-60 END")
        .bind(&txs[0].transaction_id).bind(original).execute(&pool).await.unwrap();
    let expected: (i64, i64) =
        sqlx::query_as("SELECT count(*),max(block_time_ms) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap();
    let summary: (i64,i64) = sqlx::query_as("SELECT action_count,latest_action_time_ms FROM covenant_template_summaries WHERE template='Unknown'").fetch_one(&pool).await.unwrap();
    assert_eq!(expected.0, 512);
    assert_eq!(summary, expected);
    assert_eq!(summary.1, original + 60);
    sqlx::query("UPDATE covenant_actions SET block_time_ms=$1")
        .bind(original - 120)
        .execute(&pool)
        .await
        .unwrap();
    let summary: (i64,i64) = sqlx::query_as("SELECT action_count,latest_action_time_ms FROM covenant_template_summaries WHERE template='Unknown'").fetch_one(&pool).await.unwrap();
    assert_eq!(summary, (512, original - 120));
    let mismatches: i64=sqlx::query_scalar("SELECT count(*) FROM covenant_action_summaries s WHERE s.latest_action_time_ms IS DISTINCT FROM (SELECT max(a.block_time_ms) FROM covenant_actions a WHERE a.covenant_id=s.covenant_id)").fetch_one(&pool).await.unwrap();
    assert_eq!(mismatches, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_reassociation_allows_pending_spends_then_normal_replay_completes_them(
    pool: PgPool,
) {
    exercise_pending_spend_reconciliation(pool, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn canonical_reassociation_allows_pending_spends_then_bulk_replay_completes_them(
    pool: PgPool,
) {
    exercise_pending_spend_reconciliation(pool, true).await;
}

async fn exercise_pending_spend_reconciliation(pool: PgPool, bulk: bool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let mut parent = fixture[0].clone();
    parent.accepting_block_hash = Some("ab".repeat(32));
    parent.accepting_block_blue_score = Some(parent.accepting_block_blue_score.unwrap() - 1);
    let mut child = fixture[1].clone();
    child.inputs[0].previous_outpoint_hash = parent.transaction_id.clone();
    child.inputs[0].previous_outpoint_index = parent.outputs[0].index.to_string();
    child.inputs[0].previous_outpoint_amount = Some(parent.outputs[0].amount);
    child.inputs[0].previous_outpoint_script = Some(parent.outputs[0].script_public_key.clone());
    let writer = PgPersister::new(pool.clone())
        .with_bounded_writer_lock_wait()
        .with_generic_bulk_persist(bulk);
    // Live ingestion can see a child before historical replay supplies its parent.
    writer.persist_tx(&child).await.unwrap();
    writer.persist_tx(&parent).await.unwrap();
    let state_sql = "SELECT status, encode(spent_by_txid,'hex'), encode(spent_block,'hex') FROM covenant_utxos WHERE txid=decode($1,'hex') AND vout=$2";
    let before: (String, Option<String>, Option<String>) = sqlx::query_as(state_sql)
        .bind(&parent.transaction_id)
        .bind(parent.outputs[0].index as i32)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, ("active".into(), None, None));
    let replacement = "ef".repeat(32);
    let time = child.accepting_block_time.unwrap_or(child.block_time) + 60;
    let evidence = proof_with_timestamp(
        &child,
        &replacement,
        vec![hex::decode(&child.transaction_id).unwrap()],
        time,
    );
    // Neither a malformed state nor a different spender may pass as pending.
    for (status, spender, block) in [
        ("active", Some(child.transaction_id.clone()), None),
        ("active", None, parent.accepting_block_hash.clone()),
        ("spent", None, None),
        (
            "spent",
            Some("cc".repeat(32)),
            child.accepting_block_hash.clone(),
        ),
        (
            "spent",
            Some(child.transaction_id.clone()),
            parent.accepting_block_hash.clone(),
        ),
    ] {
        sqlx::query("UPDATE covenant_utxos SET status=$2,spent_by_txid=decode($3,'hex'),spent_block=decode($4,'hex') WHERE txid=decode($1,'hex')")
            .bind(&parent.transaction_id).bind(status).bind(spender).bind(block).execute(&pool).await.unwrap();
        assert!(writer.reconcile_accepting_block(&evidence).await.is_err());
    }
    sqlx::query("UPDATE covenant_utxos SET status='active',spent_by_txid=NULL,spent_block=NULL WHERE txid=decode($1,'hex')")
        .bind(&parent.transaction_id).execute(&pool).await.unwrap();
    for (amount, script) in [
        (
            parent.outputs[0].amount + 1,
            parent.outputs[0].script_public_key.clone(),
        ),
        (parent.outputs[0].amount, "00".repeat(35)),
    ] {
        sqlx::query("UPDATE covenant_utxos SET amount_sompi=$2,script_pubkey=decode($3,'hex') WHERE txid=decode($1,'hex')")
            .bind(&parent.transaction_id).bind(amount as i64).bind(script).execute(&pool).await.unwrap();
        assert!(writer.reconcile_accepting_block(&evidence).await.is_err());
    }
    sqlx::query("UPDATE covenant_utxos SET amount_sompi=$2,script_pubkey=decode($3,'hex') WHERE txid=decode($1,'hex')")
        .bind(&parent.transaction_id).bind(parent.outputs[0].amount as i64).bind(&parent.outputs[0].script_public_key).execute(&pool).await.unwrap();
    let stale_action: i64 = sqlx::query_scalar("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,inputs) SELECT covenant_id,txid,block_hash,block_time_ms,'spend',$2 FROM covenant_actions WHERE txid=decode($1,'hex') LIMIT 1 RETURNING id")
        .bind(&child.transaction_id).bind(serde_json::json!({"previousOutpoint":{"hash":parent.transaction_id,"index":parent.outputs[0].index}})).fetch_one(&pool).await.unwrap();
    let error = writer
        .reconcile_accepting_block(&evidence)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("stored spend action conflicts"));
    sqlx::query("DELETE FROM covenant_actions WHERE id=$1")
        .bind(stale_action)
        .execute(&pool)
        .await
        .unwrap();
    let aliases: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(aliases, 0, "failed repairs must be atomic");
    let preview = writer
        .preview_accepting_block_reconciliation(&evidence)
        .await
        .unwrap();
    assert_eq!(preview.spent_inputs, 0);
    writer.reconcile_accepting_block(&evidence).await.unwrap();
    let after: (String, Option<String>, Option<String>) = sqlx::query_as(state_sql)
        .bind(&parent.transaction_id)
        .bind(parent.outputs[0].index as i32)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        after, before,
        "reassociation must leave pending spends to normal replay"
    );
    assert!(
        writer
            .reconcile_accepting_block(&evidence)
            .await
            .unwrap()
            .already_reconciled
    );
    let mut canonical = child.clone();
    canonical.accepting_block_hash = Some(replacement.clone());
    canonical.accepting_block_time = Some(time);
    if bulk {
        let mut independent = fixture[2].clone();
        independent.accepting_block_hash = Some("dc".repeat(32));
        // Its non-covenant funding needs no historical UTXO backfill.
        for input in &mut independent.inputs {
            input.previous_outpoint_script = Some("00".into());
            input.signature_script.clear();
        }
        let stats = writer
            .persist_batch(&[canonical.clone(), independent.clone()])
            .await
            .unwrap();
        assert_eq!(stats.utxos_spent, 1);
        // A bulk write changes both rows in one DB transaction. Serial fallback
        // would give the parent update and independent insert different xmins.
        let same_transaction: bool = sqlx::query_scalar("SELECT p.xmin=i.xmin FROM covenant_utxos p CROSS JOIN covenant_utxos i WHERE p.txid=decode($1,'hex') AND p.vout=$2 AND i.txid=decode($3,'hex') AND i.vout=$4")
            .bind(&parent.transaction_id).bind(parent.outputs[0].index as i32)
            .bind(&independent.transaction_id).bind(independent.outputs[0].index as i32)
            .fetch_one(&pool).await.unwrap();
        assert!(
            same_transaction,
            "the regression must exercise the bulk writer, without serial fallback"
        );
    } else {
        writer.persist_tx(&canonical).await.unwrap();
    }
    writer.persist_tx(&canonical).await.unwrap();
    let after: (String, Option<String>, Option<String>) = sqlx::query_as(state_sql)
        .bind(&parent.transaction_id)
        .bind(parent.outputs[0].index as i32)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        after,
        (
            "spent".into(),
            Some(child.transaction_id.clone()),
            Some(replacement)
        )
    );
    let actions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE txid=decode($1,'hex') AND action='spend'",
    )
    .bind(&child.transaction_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actions, 1);
    assert!(
        writer
            .reconcile_accepting_block(&evidence)
            .await
            .unwrap()
            .already_reconciled
    );
    assert!(writer.persist_tx(&child).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn replacement_rejects_target_removed_after_source_observation(pool:PgPool) {
    let fixture:Vec<RestTransaction>=serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let tx=&fixture[0];
    let writer=PgPersister::new(pool);
    writer.persist_tx(tx).await.unwrap();
    let target="ef".repeat(32);
    let proof=proof(tx,&target,vec![hex::decode(&tx.transaction_id).unwrap()]);
    let guard=writer.rest_removal_revisions(&[hex::decode(&target).unwrap()]).await.unwrap();
    writer.revert_block(&hex::decode(&target).unwrap()).await.unwrap();
    assert!(writer.with_rest_removal_guard(guard).reconcile_accepting_block(&proof).await.unwrap_err()
        .is::<tn12_indexer_db::persist::StaleRestAcceptance>());
}
