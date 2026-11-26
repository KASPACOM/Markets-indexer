//! Ledger invariants for split acceptance recovery. Full apply tests follow the
//! separate proof/persister implementation; these do not certify live repair.
use sqlx::PgPool;

async fn seed(pool: &PgPool) {
    seed_guard(pool, &vec![4; 32], &vec![5; 32], &vec![6; 32]).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_ledger_retains_source_guard_after_target_loss(pool: PgPool) {
    seed(&pool).await;
    sqlx::query(
        "UPDATE historical_acceptance_maps SET status='target_lost' WHERE status='applied'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let state: (String,i64,i64) = sqlx::query_as("SELECT status,(SELECT count(*) FROM historical_acceptance_map_sources),(SELECT count(*) FROM historical_acceptance_map_entries) FROM historical_acceptance_maps")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(state, ("target_lost".into(), 1, 1));
    assert!(
        sqlx::query("UPDATE historical_acceptance_maps SET status='applied'")
            .execute(&pool)
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_ledger_rejects_evidence_mutation_and_deletion(pool: PgPool) {
    seed(&pool).await;
    for sql in [
        "UPDATE historical_acceptance_maps SET evidence='{\"changed\":true}'",
        "UPDATE historical_acceptance_maps SET window_evidence=decode('00','hex')",
        "UPDATE historical_acceptance_maps SET cohort_evidence=decode('00','hex')",
        "UPDATE historical_acceptance_map_sources SET old_hash=decode(repeat('07',32),'hex')",
        "UPDATE historical_acceptance_map_entries SET target_score=102",
        "DELETE FROM historical_acceptance_map_entries",
        "DELETE FROM historical_acceptance_map_sources",
        "DELETE FROM historical_acceptance_maps",
        "INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) VALUES(decode(repeat('07',32),'hex'),decode(repeat('01',32),'hex'))",
        "INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES(decode(repeat('01',32),'hex'),decode(repeat('04',32),'hex'),decode(repeat('08',32),'hex'),decode(repeat('06',32),'hex'),101,1000)",
    ] {
        assert!(
            sqlx::query(sql).execute(&pool).await.is_err(),
            "mutation accepted: {sql}"
        );
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_map_entries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_ledger_rejects_ambiguous_transaction_mapping(pool: PgPool) {
    let mut conn = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) VALUES(decode(repeat('04',32),'hex'),decode(repeat('01',32),'hex')),(decode(repeat('07',32),'hex'),decode(repeat('01',32),'hex'))").execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES(decode(repeat('01',32),'hex'),decode(repeat('04',32),'hex'),decode(repeat('05',32),'hex'),decode(repeat('06',32),'hex'),101,1000)").execute(&mut *conn).await.unwrap();
    let error=sqlx::query("INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES(decode(repeat('01',32),'hex'),decode(repeat('07',32),'hex'),decode(repeat('05',32),'hex'),decode(repeat('06',32),'hex'),101,1000)").execute(&mut *conn).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23505")
    );
    conn.rollback().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_cohort_binds_full_rows_and_preserves_later_spend(pool: PgPool) {
    use tn12_indexer_db::{Persister, PgPersister};
    let fixture: Vec<tn12_indexer_core::RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone());
    writer.persist_tx(&fixture[0]).await.unwrap();
    let old = hex::decode(fixture[0].accepting_block_hash.as_ref().unwrap()).unwrap();
    let first = writer
        .historical_acceptance_cohort(&[old.clone()])
        .await
        .unwrap();
    assert!(first.reference_count() > 0);
    let repeated = writer
        .historical_acceptance_cohort(&[old.clone()])
        .await
        .unwrap();
    assert_eq!(first.digest(), repeated.digest());
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES(decode(repeat('de',32),'hex'),999999999,0,ARRAY[]::bytea[],999999999,true,0)").execute(&pool).await.unwrap();
    sqlx::query("UPDATE covenant_utxos SET status='spent',spent_block=decode(repeat('de',32),'hex'),spent_by_txid=decode(repeat('ad',32),'hex'),state='{\"preserve\":true}' WHERE created_block=$1").bind(&old).execute(&pool).await.unwrap();
    let later = writer
        .historical_acceptance_cohort(&[old.clone()])
        .await
        .unwrap();
    assert_ne!(
        first.digest(),
        later.digest(),
        "later spend and state must invalidate the original cohort"
    );
    assert_eq!(first.reference_count(), later.reference_count());
    let saved: Vec<(String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT status,encode(spent_block,'hex'),state FROM covenant_utxos WHERE created_block=$1",
    )
    .bind(&old)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(saved.iter().all(|r| r.0 == "spent"
        && r.1 == "de".repeat(32)
        && r.2 == serde_json::json!({"preserve":true})));
    assert!(writer
        .historical_acceptance_cohort(&[vec![0; 32]])
        .await
        .is_err());
    assert!(writer.historical_acceptance_cohort(&[]).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_proof_binds_split_rows_and_rejects_content_corruption(pool: PgPool) {
    exercise_historical_map(pool, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_merges_two_old_cohorts_atomically(pool: PgPool) {
    exercise_historical_map(pool, true).await;
}

async fn exercise_historical_map(pool: PgPool, merge: bool) {
    use tn12_indexer_db::persist::{
        AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
        HistoricalAcceptanceBlock, HistoricalAcceptanceMapProof, HistoricalAcceptanceWindow,
    };
    use tn12_indexer_db::{Persister, PgPersister};
    let fixture: Vec<tn12_indexer_core::RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone());
    let first = &fixture[0];
    let old = AcceptingBlockEvidence {
        hash: hex::decode(first.accepting_block_hash.as_ref().unwrap()).unwrap(),
        is_chain_block: false,
        blue_score: first.accepting_block_blue_score.unwrap(),
        timestamp: first.accepting_block_time.unwrap_or(first.block_time),
        selected_parent: vec![7; 32],
        parents: vec![vec![vec![7; 32]]],
        accepted_id_merkle_root: vec![8; 32],
        utxo_commitment: vec![9; 32],
    };
    let mut removed = vec![old.clone()];
    let mut canonical = Vec::new();
    for (n, tx) in fixture.iter().take(2).enumerate() {
        let mut tx = tx.clone();
        tx.accepting_block_hash = first.accepting_block_hash.clone();
        tx.accepting_block_blue_score = first.accepting_block_blue_score;
        tx.accepting_block_time = first.accepting_block_time;
        if merge && n == 1 {
            let mut second = old.clone();
            second.hash = vec![49; 32];
            tx.accepting_block_hash = Some(hex::encode(&second.hash));
            removed.push(second);
        }
        writer.persist_tx(&tx).await.unwrap();
        let txid = hex::decode(&tx.transaction_id).unwrap();
        let mut block = old.clone();
        block.hash = vec![50 + n as u8; 32];
        block.is_chain_block = true;
        block.blue_score += 1 + n as u64;
        block.timestamp += 100 + n as u64;
        canonical.push(HistoricalAcceptanceBlock {
            block,
            transaction_ids: vec![txid.clone()],
            inputs: tx
                .inputs
                .iter()
                .map(|i| AcceptedInputEvidence {
                    transaction_id: txid.clone(),
                    previous_txid: hex::decode(&i.previous_outpoint_hash).unwrap(),
                    previous_vout: i.previous_outpoint_index.parse().unwrap(),
                    previous_amount: i.previous_outpoint_amount,
                    previous_script: i
                        .previous_outpoint_script
                        .as_ref()
                        .map(|s| hex::decode(s).unwrap()),
                })
                .collect(),
            outputs: tx
                .outputs
                .iter()
                .map(|o| AcceptedOutputEvidence {
                    transaction_id: txid.clone(),
                    vout: o.index as i32,
                    amount: o.amount,
                    script: hex::decode(&o.script_public_key).unwrap(),
                })
                .collect(),
        });
    }
    // A descendant outside the repair window has already spent one mapped
    // output. The repair must move its creation without resurrecting it.
    let mut later = fixture[2].clone();
    later.accepting_block_hash = Some("ee".repeat(32));
    later.accepting_block_blue_score = Some(old.blue_score + 100);
    later.accepting_block_time = Some(old.timestamp + 10000);
    later.inputs[0].previous_outpoint_hash = first.transaction_id.clone();
    later.inputs[0].previous_outpoint_index = first.outputs[0].index.to_string();
    later.inputs[0].previous_outpoint_amount = Some(first.outputs[0].amount);
    later.inputs[0].previous_outpoint_script = Some(first.outputs[0].script_public_key.clone());
    writer.persist_tx(&later).await.unwrap();
    let descendant:(String,String)=sqlx::query_as("SELECT status,encode(spent_block,'hex') FROM covenant_utxos WHERE txid=decode($1,'hex') AND vout=$2").bind(&first.transaction_id).bind(first.outputs[0].index as i32).fetch_one(&pool).await.unwrap();
    assert_eq!(descendant, ("spent".into(), "ee".repeat(32)));
    sqlx::query("CREATE FUNCTION preserve_historical_map_descendant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.status='spent' AND OLD.created_block IS DISTINCT FROM NEW.created_block AND (to_jsonb(OLD)-'created_block') IS DISTINCT FROM (to_jsonb(NEW)-'created_block') THEN RAISE EXCEPTION 'historical map changed a later-spent output'; END IF; RETURN NEW; END $$").execute(&pool).await.unwrap();
    sqlx::query("CREATE TRIGGER preserve_historical_map_descendant BEFORE UPDATE ON covenant_utxos FOR EACH ROW EXECUTE FUNCTION preserve_historical_map_descendant()").execute(&pool).await.unwrap();
    if merge {
        let second = canonical.pop().unwrap();
        canonical[0].transaction_ids.extend(second.transaction_ids);
        canonical[0].inputs.extend(second.inputs);
        canonical[0].outputs.extend(second.outputs);
    }
    let old_hashes: Vec<_> = removed.iter().map(|b| b.hash.clone()).collect();
    let window = HistoricalAcceptanceWindow {
        source_tip: old.blue_score + 2000,
        start_score: old.blue_score - 1,
        end_score: old.blue_score + 10,
        removed,
        canonical,
    };
    let cohort = writer
        .historical_acceptance_cohort(&old_hashes)
        .await
        .unwrap();
    let proof =
        HistoricalAcceptanceMapProof::verify(cohort.clone(), window.clone(), window.clone())
            .unwrap();
    let snapshot_sql = r#"SELECT jsonb_build_object(
        'blocks',(SELECT jsonb_agg(to_jsonb(r) ORDER BY hash) FROM blocks r),
        'utxos',(SELECT jsonb_agg(to_jsonb(r) ORDER BY txid,vout) FROM covenant_utxos r),
        'actions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM covenant_actions r),
        'covenants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY covenant_id) FROM covenants r),
        'summaries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY covenant_id) FROM covenant_summaries r),
        'templates',(SELECT jsonb_agg(to_jsonb(r) ORDER BY template) FROM covenant_template_summaries r),
        'maps',(SELECT jsonb_agg(to_jsonb(r) ORDER BY proof_hash) FROM historical_acceptance_maps r))"#;
    let before: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let stats = writer
        .preview_historical_acceptance_map(&proof)
        .await
        .unwrap();
    eprintln!(
        "two-transaction split preview including rollback: {}us",
        started.elapsed().as_micros()
    );
    assert_eq!(
        (
            stats.created_outputs,
            stats.spent_inputs,
            stats.actions,
            stats.covenants
        ),
        (2, 0, 2, 2)
    );
    let after: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "preview must roll back targets, retags, summaries and ledger"
    );
    sqlx::query("CREATE FUNCTION slow_historical_map_action() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$").execute(&pool).await.unwrap();
    sqlx::query("CREATE TRIGGER slow_historical_map_action BEFORE UPDATE ON covenant_actions FOR EACH ROW EXECUTE FUNCTION slow_historical_map_action()").execute(&pool).await.unwrap();
    let timeout_error = writer
        .preview_historical_acceptance_map(&proof)
        .await
        .unwrap_err();
    let text = format!("{timeout_error:#}");
    assert!(
        text.contains("deadline") || text.contains("statement timeout"),
        "unexpected failure: {text}"
    );
    let after_timeout: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, after_timeout,
        "deadline failure must roll back prior UTXO retags and summaries"
    );
    let released: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(0x544e31324b434332_i64)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(released, "preview deadline must release the writer lock");
    sqlx::query("DROP TRIGGER slow_historical_map_action ON covenant_actions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION slow_historical_map_action()")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(proof.source().targets().len(), 2);
    assert_eq!(
        proof.source().targets()[0].target_hash == proof.source().targets()[1].target_hash,
        merge
    );
    let mut corrupt = window.clone();
    corrupt.canonical[0].outputs[0].amount += 1;
    assert!(
        HistoricalAcceptanceMapProof::verify(cohort.clone(), corrupt.clone(), corrupt).is_err()
    );
    let mut missing = window.clone();
    missing.canonical[0].outputs.clear();
    assert!(
        HistoricalAcceptanceMapProof::verify(cohort.clone(), missing.clone(), missing).is_err()
    );
    sqlx::query("UPDATE covenant_utxos SET state='{\"changed\":true}' WHERE created_block=$1")
        .bind(&old.hash)
        .execute(&pool)
        .await
        .unwrap();
    let changed = writer
        .historical_acceptance_cohort(&old_hashes)
        .await
        .unwrap();
    let stale_error = writer
        .preview_historical_acceptance_map(&proof)
        .await
        .unwrap_err();
    assert!(stale_error.to_string().contains("cohort changed"));
    let changed_proof =
        HistoricalAcceptanceMapProof::verify(changed, window.clone(), window.clone()).unwrap();
    assert_ne!(
        proof.proof_hash(),
        changed_proof.proof_hash(),
        "unchanged source cannot authorize a different database snapshot"
    );
    let applied = writer
        .reconcile_historical_acceptance_map(&changed_proof)
        .await
        .unwrap();
    assert_eq!(
        (applied.created_outputs, applied.actions, applied.covenants),
        (2, 2, 2)
    );
    let summary_mismatches: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM covenant_summaries s
        JOIN covenants c USING(covenant_id)
        LEFT JOIN LATERAL (
            SELECT count(*)::bigint n,coalesce(sum(amount_sompi),0)::bigint amount
            FROM covenant_utxos u WHERE u.covenant_id=s.covenant_id AND u.status='active'
        ) totals ON true
        LEFT JOIN LATERAL (
            SELECT u.txid,u.vout,u.address,u.created_block,coalesce(b.blue_score,0) blue_score
            FROM covenant_utxos u LEFT JOIN blocks b ON b.hash=u.created_block
            WHERE u.covenant_id=s.covenant_id AND u.status='active'
            ORDER BY coalesce(b.blue_score,0) DESC,u.txid DESC,u.vout DESC LIMIT 1
        ) latest ON true
        WHERE ROW(s.active_utxos,s.total_amount_sompi,s.current_address,s.latest_active_txid,
                  s.latest_active_vout,s.latest_active_block,s.latest_active_blue_score)
        IS DISTINCT FROM ROW(totals.n,totals.amount,coalesce(latest.address,c.address),latest.txid,
                             latest.vout,latest.created_block,latest.blue_score)
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(summary_mismatches, 0, "acceptance summary must match active UTXOs");
    assert!(
        writer
            .reconcile_historical_acceptance_map(&changed_proof)
            .await
            .unwrap()
            .already_reconciled
    );
    // A restarted process has no in-memory pending proof. A proof captured
    // before the earlier commit, with a new source tip, still cannot remap an
    // already sealed source cohort under a different proof identity.
    let restarted = PgPersister::new(pool.clone());
    let mut newer_window = window.clone();
    newer_window.source_tip += 1;
    let stale_after_restart = HistoricalAcceptanceMapProof::verify(
        changed_proof.cohort().clone(),
        newer_window.clone(),
        newer_window,
    )
    .unwrap();
    assert_ne!(stale_after_restart.proof_hash(), changed_proof.proof_hash());
    let restart_error = restarted
        .reconcile_historical_acceptance_map(&stale_after_restart)
        .await
        .unwrap_err();
    assert!(restart_error
        .to_string()
        .contains("source already has an immutable map"));
    assert!(
        restarted
            .historical_acceptance_cohort(&old_hashes)
            .await
            .is_err(),
        "a fresh process must not reconstruct a second repair cohort after commit"
    );
    assert_eq!(
        restarted
            .classify_historical_acceptance_outcome(&changed_proof)
            .await
            .unwrap(),
        tn12_indexer_db::persist::HistoricalAcceptanceOutcome::Applied
    );
    let source_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_map_sources")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(source_count, if merge { 2 } else { 1 });
    for target in changed_proof.source().targets() {
        let accepted: (Vec<u8>, i64, Vec<u8>, i64) = sqlx::query_as("SELECT a.block_hash,a.block_time_ms,c.genesis_block,c.created_at_ms FROM covenant_actions a JOIN covenants c ON c.genesis_txid=a.txid WHERE a.txid=$1")
            .bind(&target.transaction_id).fetch_one(&pool).await.unwrap();
        assert_eq!(
            accepted,
            (
                target.target_hash.clone(),
                target.target_time_ms as i64,
                target.target_hash.clone(),
                target.target_time_ms as i64
            )
        );
    }
}

async fn seed_guard(pool: &PgPool, old: &[u8], txid: &[u8], target: &[u8]) {
    let mut conn = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) VALUES($1,decode(repeat('01',32),'hex'))").bind(old).execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES(decode(repeat('01',32),'hex'),$1,$2,$3,101,1000)").bind(old).bind(txid).bind(target).execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_maps(proof_hash,source_tip,window_start,window_end,cohort_digest,window_digest,evidence,window_evidence,cohort_evidence) VALUES(decode(repeat('01',32),'hex'),2000,100,110,decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),'{}',convert_to('{}','UTF8'),convert_to('[]','UTF8'))").execute(&mut *conn).await.unwrap();
    conn.commit().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_guards_reject_unseen_old_source_serial_and_bulk(pool: PgPool) {
    use tn12_indexer_db::persist::HistoricalAcceptanceMapGuard;
    use tn12_indexer_db::{Persister, PgPersister};
    let mut fixture: Vec<tn12_indexer_core::RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    // Synthetic ordinary funding inputs keep this batch eligible without
    // requiring indexed covenant parents; the output/acceptance guards are real.
    for tx in &mut fixture {
        for input in &mut tx.inputs {
            input.previous_outpoint_script = Some("51".into());
            input.signature_script = String::new();
        }
    }
    let old = hex::decode(fixture[0].accepting_block_hash.as_ref().unwrap()).unwrap();
    seed_guard(&pool, &old, &vec![0x33; 32], &vec![0x44; 32]).await;
    let writer = PgPersister::new(pool.clone());
    let error = writer.persist_tx(&fixture[0]).await.unwrap_err();
    assert!(error
        .downcast_ref::<HistoricalAcceptanceMapGuard>()
        .is_some());
    // The rejected serial write queues an asynchronous SQLx rollback. Wait for
    // that lock release so this assertion exercises the bulk acceptance guard.
    let writer = writer
        .with_generic_bulk_persist(true)
        .with_bounded_writer_lock_wait();
    let error = writer.persist_batch(&fixture).await.unwrap_err();
    // An acknowledged rollback adds outcome evidence around the original cause.
    // Keep proving this fixture reached the bulk acceptance guard underneath it.
    assert!(
        error
            .chain()
            .any(|cause| cause.to_string() == "check generic batch acceptance"),
        "fixture must reach the generic bulk guard"
    );
    assert!(error
        .downcast_ref::<HistoricalAcceptanceMapGuard>()
        .is_some());
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_target_loss_follows_alias_ancestry_and_blocks_replay(pool: PgPool) {
    use tn12_indexer_db::persist::HistoricalAcceptanceMapGuard;
    use tn12_indexer_db::{Persister, PgPersister};
    let fixture: Vec<tn12_indexer_core::RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let txid = hex::decode(&fixture[0].transaction_id).unwrap();
    let target = vec![0x44; 32];
    let successor = vec![0x55; 32];
    seed_guard(&pool, &vec![0x33; 32], &txid, &target).await;
    sqlx::query("INSERT INTO canonical_block_replacements(old_hash,new_hash,evidence,source_tip) VALUES($1,$2,'{}',2000)").bind(&target).bind(&successor).execute(&pool).await.unwrap();
    let writer = PgPersister::new(pool.clone());
    writer.revert_blocks(&[target.clone()]).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM historical_acceptance_maps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "applied",
        "reverting an old alias is not loss of its live successor"
    );
    writer.revert_blocks(&[successor.clone()]).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM historical_acceptance_maps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "applied",
        "unknown target removal must not invalidate evidence"
    );
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,101,0,ARRAY[]::bytea[],1000,false,0)").bind(&successor).execute(&pool).await.unwrap();
    writer.revert_blocks(&[successor.clone()]).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM historical_acceptance_maps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "applied",
        "noncanonical target removal must not invalidate evidence"
    );
    let aliases: i64 = sqlx::query_scalar("SELECT count(*) FROM canonical_block_replacements")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(aliases, 1, "ignored removals must preserve target ancestry");
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,101,0,ARRAY[]::bytea[],1000,true,0)").bind(&successor).execute(&pool).await.unwrap();
    writer.revert_blocks(&[successor]).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM historical_acceptance_maps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "target_lost");
    let error = writer.persist_tx(&fixture[0]).await.unwrap_err();
    assert!(error
        .downcast_ref::<HistoricalAcceptanceMapGuard>()
        .is_some());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_map_sources")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_ledger_cannot_commit_unsealed_children(pool: PgPool) {
    let mut conn = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) VALUES(decode(repeat('04',32),'hex'),decode(repeat('01',32),'hex'))").execute(&mut *conn).await.unwrap();
    let error = conn.commit().await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_map_sources")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    let error=sqlx::query("INSERT INTO historical_acceptance_maps(proof_hash,source_tip,window_start,window_end,cohort_digest,window_digest,evidence,window_evidence,cohort_evidence) VALUES(decode(repeat('01',32),'hex'),2000,100,110,decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),'{}',convert_to('{}','UTF8'),convert_to('[]','UTF8'))").execute(&pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn historical_map_ledger_sealing_serializes_concurrent_append(pool: PgPool) {
    let mut owner = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_sources(old_hash,proof_hash) VALUES(decode(repeat('04',32),'hex'),decode(repeat('01',32),'hex'))").execute(&mut *owner).await.unwrap();
    sqlx::query("INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES(decode(repeat('01',32),'hex'),decode(repeat('04',32),'hex'),decode(repeat('05',32),'hex'),decode(repeat('06',32),'hex'),101,1000)").execute(&mut *owner).await.unwrap();
    let rival_pool = pool.clone();
    let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
    let rival = tokio::spawn(async move {
        let mut conn = rival_pool.acquire().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        pid_tx.send(pid).unwrap();
        sqlx::query("INSERT INTO historical_acceptance_map_entries(proof_hash,old_hash,txid,target_hash,target_score,target_time_ms) VALUES(decode(repeat('01',32),'hex'),decode(repeat('04',32),'hex'),decode(repeat('08',32),'hex'),decode(repeat('06',32),'hex'),101,1000)").execute(&mut *conn).await
    });
    let pid = pid_rx.await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let wait: Option<String> =
                sqlx::query_scalar("SELECT wait_event FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            if wait.as_deref() == Some("advisory") {
                break;
            }
            assert!(
                !rival.is_finished(),
                "concurrent append must wait for the sealing transaction"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    sqlx::query("INSERT INTO historical_acceptance_maps(proof_hash,source_tip,window_start,window_end,cohort_digest,window_digest,evidence,window_evidence,cohort_evidence) VALUES(decode(repeat('01',32),'hex'),2000,100,110,decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),'{}',convert_to('{}','UTF8'),convert_to('[]','UTF8'))").execute(&mut *owner).await.unwrap();
    owner.commit().await.unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(2), rival)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("55000")
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_map_entries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
}
