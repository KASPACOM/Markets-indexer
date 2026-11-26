//! Compare the actual batch with the previous transition, including genesis triggers.
use super::*;
use serde_json::Value;
use sqlx::{Acquire, PgPool};

#[sqlx::test(migrations = "./migrations")]
async fn comparison_jit_limit_is_transaction_local(pool: PgPool) {
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SET jit=on")
        .execute(&mut *connection)
        .await
        .unwrap();
    for commit in [false, true] {
        let mut tx = connection.begin().await.unwrap();
        set_comparison_work_limits(&mut tx).await.unwrap();
        let inside: String = sqlx::query_scalar("SHOW jit")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(inside, "off", "bounded repair must avoid JIT compilation");
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        let after: String = sqlx::query_scalar("SHOW jit")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert_eq!(after, "on", "repair setting must not leak on connection reuse");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn unbounded_repair_clears_statement_timeout(pool: PgPool) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('statement_timeout','250ms',true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    super::remaining_budget(&mut tx, None::<Instant>)
        .await
        .unwrap();
    let timeout: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(timeout, "0");
    tx.rollback().await.unwrap();
}

async fn fixture(pool: PgPool) -> (PgPersister, HistoricalAcceptanceMapProof) {
    let merge = false;

    use crate::persist::{
        AcceptedInputEvidence, AcceptedOutputEvidence, AcceptingBlockEvidence,
        HistoricalAcceptanceBlock, HistoricalAcceptanceMapProof, HistoricalAcceptanceWindow,
    };
    use crate::{Persister, PgPersister};
    let fixture: Vec<tn12_indexer_core::RestTransaction> = serde_json::from_str(include_str!(
        "../../tests/fixtures/tn10-dense-generic-32.json"
    ))
    .unwrap();
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
    (writer, proof)
}

const SNAPSHOT: &str = r#"SELECT jsonb_build_object(
 'blocks',(SELECT jsonb_agg(to_jsonb(r)-'indexed_at_ms' ORDER BY hash) FROM blocks r),
 'utxos',(SELECT jsonb_agg(to_jsonb(r) ORDER BY txid,vout) FROM covenant_utxos r),
 'actions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM covenant_actions r),
 'covenants',(SELECT jsonb_agg(to_jsonb(r) ORDER BY covenant_id) FROM covenants r),
 'summaries',(SELECT jsonb_agg(to_jsonb(r)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_summaries r),
 'action_summaries',(SELECT jsonb_agg(to_jsonb(r)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_action_summaries r),
 'snapshot_revision',(SELECT jsonb_agg(to_jsonb(r)) FROM snapshot_claim_history_revision r),
 'templates',(SELECT jsonb_agg(to_jsonb(r)-'updated_at_ms' ORDER BY template) FROM covenant_template_summaries r),
 'maps',(SELECT jsonb_agg(to_jsonb(r)-'created_at'-'status_changed_at' ORDER BY proof_hash) FROM historical_acceptance_maps r),
 'sources',(SELECT jsonb_agg(to_jsonb(r) ORDER BY old_hash) FROM historical_acceptance_map_sources r),
 'entries',(SELECT jsonb_agg(to_jsonb(r) ORDER BY old_hash,txid) FROM historical_acceptance_map_entries r),
 'dirty',(SELECT jsonb_agg(jsonb_build_object('reason',reason,'txid',txid) ORDER BY reason,txid) FROM kcc20_projection_dirty))"#;

#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_matches_reference_with_genesis_and_all_summaries(pool: PgPool) {
    let (writer, proof) = fixture(pool.clone()).await;
    let prepared = PreparedTransition::new(&proof);
    let mut connection = pool.acquire().await.unwrap();
    let before: Value = sqlx::query_scalar(SNAPSHOT)
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    let mut expected = None;
    for batch in [false, true] {
        let mut tx = connection.begin().await.unwrap();
        PgPersister::set_persist_query_limits(&mut tx)
            .await
            .unwrap();
        set_comparison_work_limits(&mut tx).await.unwrap();
        if batch {
            stage_transition(&mut tx, &proof, &prepared).await.unwrap();
        }
        writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
        let deadline = Instant::now() + Duration::from_millis(350);
        let stats = if batch {
            transition(&mut tx, &proof, &prepared, deadline)
                .await
                .unwrap()
        } else {
            super::reference::transition_reference(&mut tx, &proof, &prepared, deadline)
                .await
                .unwrap()
        };
        assert_eq!(
            (
                stats.created_outputs,
                stats.spent_inputs,
                stats.actions,
                stats.covenants
            ),
            (2, 0, 2, 2)
        );
        let state: Value = sqlx::query_scalar(SNAPSHOT)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        // This generic acceptance-map fixture contains no snapshot claim.
        // Remapping its unrelated covenant rows must leave claim pagination
        // stable, including both the epoch and numeric revision.
        assert_eq!(
            state["snapshot_revision"][0]["epoch"],
            before["snapshot_revision"][0]["epoch"]
        );
        assert_eq!(
            state["snapshot_revision"][0]["revision"],
            before["snapshot_revision"][0]["revision"]
        );
        if let Some(reference) = &expected {
            assert_eq!(&state, reference);
        } else {
            expected = Some(state);
        }
        tx.rollback().await.unwrap();
        let after: Value = sqlx::query_scalar(SNAPSHOT)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        assert_eq!(before, after);
        let clean:bool=sqlx::query_scalar("SELECT to_regclass('pg_temp.historical_transition_input') IS NULL AND to_regclass('pg_temp.historical_transition_mapping') IS NULL AND to_regclass('pg_temp.historical_transition_result') IS NULL").fetch_one(&mut *connection).await.unwrap();
        assert!(clean);
    }
    // Commit the real batch and verify cleanup on this exact same connection.
    let mut tx = connection.begin().await.unwrap();
    PgPersister::set_persist_query_limits(&mut tx)
        .await
        .unwrap();
    stage_transition(&mut tx, &proof, &prepared).await.unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    transition(
        &mut tx,
        &proof,
        &prepared,
        Instant::now() + Duration::from_millis(350),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let clean:bool=sqlx::query_scalar("SELECT to_regclass('pg_temp.historical_transition_input') IS NULL AND to_regclass('pg_temp.historical_transition_mapping') IS NULL AND to_regclass('pg_temp.historical_transition_result') IS NULL").fetch_one(&mut *connection).await.unwrap();
    assert!(clean);
}

async fn add_newer_active_output(pool: &PgPool, old_hash: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let covenant_id: Vec<u8> = sqlx::query_scalar(
        "SELECT covenant_id FROM covenant_utxos WHERE created_block=$1 AND status='active' LIMIT 1",
    )
    .bind(old_hash)
    .fetch_one(pool)
    .await
    .unwrap();
    let newer_block: Vec<u8> = vec![0xf2; 32];
    let newer_txid: Vec<u8> = vec![0xf1; 32];
    sqlx::query(
        "INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) \
         SELECT $1,MAX(blue_score)+100,0,ARRAY[]::bytea[],MAX(timestamp_ms)+100,TRUE,0 FROM blocks",
    )
    .bind(&newer_block)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) \
         SELECT $1,0,covenant_id,address,amount_sompi,script_pubkey,state,$2,'active' \
         FROM covenant_utxos WHERE covenant_id=$3 AND status='active' LIMIT 1",
    )
    .bind(&newer_txid)
    .bind(&newer_block)
    .bind(&covenant_id)
    .execute(pool)
    .await
    .unwrap();
    (covenant_id, newer_txid)
}

#[sqlx::test(migrations = "./migrations")]
async fn older_acceptance_move_does_not_refresh_a_newer_covenant_summary(pool: PgPool) {
    let (writer, proof) = fixture(pool.clone()).await;
    let (covenant_id, newer_txid) =
        add_newer_active_output(&pool, &proof.cohort.old_hashes()[0]).await;
    let before: Value = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let latest_txid: Vec<u8> = sqlx::query_scalar(
        "SELECT latest_active_txid FROM covenant_summaries WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(latest_txid, newer_txid);

    let prepared = PreparedTransition::new(&proof);
    let mut reference_tx = pool.begin().await.unwrap();
    PgPersister::set_persist_query_limits(&mut reference_tx)
        .await
        .unwrap();
    set_comparison_work_limits(&mut reference_tx).await.unwrap();
    writer
        .acquire_persist_writer_lock(&mut reference_tx)
        .await
        .unwrap();
    super::reference::transition_reference(
        &mut reference_tx,
        &proof,
        &prepared,
        Instant::now() + Duration::from_millis(350),
    )
    .await
    .unwrap();
    let expected: Value = sqlx::query_scalar(SNAPSHOT)
        .fetch_one(&mut *reference_tx)
        .await
        .unwrap();
    reference_tx.rollback().await.unwrap();

    // The original transition rescanned every active output and updated this
    // unchanged summary. A trigger makes that unnecessary write a hard failure.
    sqlx::raw_sql(
        "CREATE TABLE test_unchanged_summary_guard(covenant_id bytea PRIMARY KEY); \
         CREATE FUNCTION forbid_unchanged_summary_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF EXISTS(SELECT 1 FROM test_unchanged_summary_guard WHERE covenant_id=NEW.covenant_id) \
         THEN RAISE EXCEPTION 'unnecessary covenant summary refresh'; END IF; RETURN NEW; END $$; \
         CREATE TRIGGER forbid_unchanged_summary_refresh BEFORE INSERT OR UPDATE ON covenant_summaries \
         FOR EACH ROW EXECUTE FUNCTION forbid_unchanged_summary_refresh()",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO test_unchanged_summary_guard VALUES($1)")
        .bind(&covenant_id)
        .execute(&pool)
        .await
        .unwrap();
    let unbounded = PgPersister::for_tip_follow_settings(pool.clone(), |name| {
        (name == "TN12_HISTORY_ACCEPTANCE_HOLD_BUDGET_MS").then(|| "0".to_owned())
    })
    .unwrap();
    unbounded
        .reconcile_historical_acceptance_map(&proof)
    .await
    .unwrap();

    let after: Value = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after, before);
    let actual: Value = sqlx::query_scalar(SNAPSHOT).fetch_one(&pool).await.unwrap();
    assert_eq!(actual, expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_latest_score_requires_full_acceptance_summary_refresh(pool: PgPool) {
    let (writer, proof) = fixture(pool.clone()).await;
    let (covenant_id, newer_txid) =
        add_newer_active_output(&pool, &proof.cohort.old_hashes()[0]).await;
    let latest_txid: Vec<u8> = sqlx::query_scalar(
        "SELECT latest_active_txid FROM covenant_summaries WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(latest_txid, newer_txid);
    let actual_score: i64 = sqlx::query_scalar(
        "SELECT b.blue_score FROM covenant_summaries s JOIN blocks b \
         ON b.hash=s.latest_active_block WHERE s.covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE covenant_summaries SET latest_active_blue_score=$2 WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .bind(actual_score + 10_000)
    .execute(&pool)
    .await
    .unwrap();

    let prepared = PreparedTransition::new(&proof);
    let mut reference_tx = pool.begin().await.unwrap();
    PgPersister::set_persist_query_limits(&mut reference_tx)
        .await
        .unwrap();
    set_comparison_work_limits(&mut reference_tx).await.unwrap();
    writer
        .acquire_persist_writer_lock(&mut reference_tx)
        .await
        .unwrap();
    super::reference::transition_reference(
        &mut reference_tx,
        &proof,
        &prepared,
        Instant::now() + Duration::from_millis(350),
    )
    .await
    .unwrap();
    let expected: Value = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&mut *reference_tx)
    .await
    .unwrap();
    reference_tx.rollback().await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    PgPersister::set_persist_query_limits(&mut tx)
        .await
        .unwrap();
    stage_transition(&mut tx, &proof, &prepared).await.unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    transition(
        &mut tx,
        &proof,
        &prepared,
        Instant::now() + Duration::from_millis(350),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let repaired_score: i64 = sqlx::query_scalar(
        "SELECT latest_active_blue_score FROM covenant_summaries WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(repaired_score, actual_score + 10_000);
    let actual: Value = sqlx::query_scalar(
        "SELECT to_jsonb(s)-'updated_at_ms' FROM covenant_summaries s WHERE covenant_id=$1",
    )
    .bind(&covenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(actual, expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_rechecks_after_staging_and_external_writer(pool: PgPool) {
    staged_mutation(
        pool,
        "UPDATE covenant_utxos SET amount_sompi=amount_sompi+1 WHERE txid=$1",
    )
    .await;
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_rechecks_deleted_row_after_staging(pool: PgPool) {
    staged_mutation(pool, "DELETE FROM covenant_actions WHERE txid=$1").await;
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_rechecks_added_row_after_staging(pool: PgPool) {
    staged_mutation(pool, "INSERT INTO covenant_actions SELECT (jsonb_populate_record(NULL::covenant_actions,to_jsonb(a)||jsonb_build_object('id',nextval(pg_get_serial_sequence('covenant_actions','id')),'txid',decode(repeat('ab',32),'hex')))).* FROM covenant_actions a WHERE txid=$1 LIMIT 1").await;
}

async fn staged_mutation(pool: PgPool, mutation: &str) {
    let (writer, proof) = fixture(pool.clone()).await;
    let prepared = PreparedTransition::new(&proof);
    let mut tx = pool.begin().await.unwrap();
    PgPersister::set_persist_query_limits(&mut tx)
        .await
        .unwrap();
    stage_transition(&mut tx, &proof, &prepared).await.unwrap();
    let mut other = pool.begin().await.unwrap();
    writer
        .acquire_persist_writer_lock(&mut other)
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(mutation))
        .bind(&prepared.ids[0])
        .execute(&mut *other)
        .await
        .unwrap();
    other.commit().await.unwrap();
    let external: Value = sqlx::query_scalar(SNAPSHOT).fetch_one(&pool).await.unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    let error = transition(
        &mut tx,
        &proof,
        &prepared,
        Instant::now() + Duration::from_millis(350),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("cohort changed"), "{error:#}");
    tx.rollback().await.unwrap();
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM historical_acceptance_maps)+(SELECT count(*) FROM historical_acceptance_map_sources)+(SELECT count(*) FROM historical_acceptance_map_entries)").fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);
    let after: Value = sqlx::query_scalar(SNAPSHOT).fetch_one(&pool).await.unwrap();
    assert_eq!(external, after);
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_late_seal_timeout_is_atomic(pool: PgPool) {
    let (writer, proof) = fixture(pool.clone()).await;
    sqlx::raw_sql("CREATE SEQUENCE public.batch_seal_reached; CREATE FUNCTION public.slow_batch_seal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.batch_seal_reached'); PERFORM pg_sleep(0.5); RETURN NEW; END $$; CREATE TRIGGER slow_batch_seal BEFORE INSERT ON public.historical_acceptance_maps FOR EACH ROW EXECUTE FUNCTION public.slow_batch_seal()")
        .execute(&pool).await.unwrap();
    let before: Value = sqlx::query_scalar(SNAPSHOT).fetch_one(&pool).await.unwrap();
    let error = writer
        .preview_historical_acceptance_map(&proof)
        .await
        .unwrap_err();
    let error = format!("{error:#}");
    assert!(
        error.contains("deadline") || error.contains("statement timeout"),
        "{error}"
    );
    let reached: bool = sqlx::query_scalar("SELECT is_called FROM public.batch_seal_reached")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(reached, "timeout test must reach the final parent seal");
    let after: Value = sqlx::query_scalar(SNAPSHOT).fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
    let mut tx = pool.begin().await.unwrap();
    let released: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(6074847039450202930::bigint)")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(released);
    tx.rollback().await.unwrap();
}

// Drop PostgreSQL's real COMMIT acknowledgement after the server sends it.
// The ordinary persister must enter its automatic uncertain-commit recovery.
#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_recovers_automatic_lost_commit_ack(pool: PgPool) {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (writer, proof) = fixture(pool.clone()).await;
    let options = (*pool.connect_options()).clone();
    assert!(matches!(options.get_host(), "127.0.0.1" | "localhost"));
    let destination = (options.get_host().to_owned(), options.get_port());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let armed = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let armed_server = armed.clone();
    let dropped_server = dropped.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (client, _) = listener.accept().await.unwrap();
            let destination = destination.clone();
            let armed = armed_server.clone();
            let dropped = dropped_server.clone();
            connections.spawn(async move {
                let backend = tokio::net::TcpStream::connect(destination).await.unwrap();
                client.set_nodelay(true).unwrap();
                backend.set_nodelay(true).unwrap();
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = backend.into_split();
                let upstream = async {
                    let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
                };
                let downstream = async {
                    loop {
                        let mut header = [0u8; 5];
                        if server_read.read_exact(&mut header).await.is_err() {
                            break;
                        }
                        let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
                        if !(4..=16 * 1024 * 1024).contains(&length) {
                            break;
                        }
                        let mut payload = vec![0; length - 4];
                        if server_read.read_exact(&mut payload).await.is_err() {
                            break;
                        }
                        if header[0] == b'C'
                            && payload == b"COMMIT\0"
                            && armed.swap(false, Ordering::SeqCst)
                        {
                            dropped.store(true, Ordering::SeqCst);
                            break;
                        }
                        if client_write.write_all(&header).await.is_err()
                            || client_write.write_all(&payload).await.is_err()
                        {
                            break;
                        }
                    }
                };
                tokio::select! {_=upstream=>{},_=downstream=>{}}
            });
        }
    });
    let proxy_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            options
                .host("127.0.0.1")
                .port(port)
                .ssl_mode(sqlx::postgres::PgSslMode::Disable),
        )
        .await
        .unwrap();
    armed.store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        PgPersister::new(proxy_pool.clone()).reconcile_historical_acceptance_map(&proof),
    )
    .await;
    proxy_pool.close().await;
    server.abort();
    let _ = server.await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "proxy did not withhold the actual commit acknowledgement"
    );
    let stats = result.unwrap().unwrap();
    assert!(
        stats.already_reconciled,
        "automatic recovery was not reached"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM historical_acceptance_maps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(
        writer
            .reconcile_historical_acceptance_map(&proof)
            .await
            .unwrap()
            .already_reconciled
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn batch_transition_tokio_cancellation_rolls_back_finished_server_batch(pool: PgPool) {
    let (writer, proof) = fixture(pool.clone()).await;
    sqlx::raw_sql("CREATE SEQUENCE public.batch_cancel_reached; CREATE FUNCTION public.pause_batch_seal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('public.batch_cancel_reached'); PERFORM pg_sleep(0.15); RETURN NEW; END $$; CREATE TRIGGER pause_batch_seal BEFORE INSERT ON public.historical_acceptance_maps FOR EACH ROW EXECUTE FUNCTION public.pause_batch_seal()")
        .execute(&pool).await.unwrap();
    let before: Value = sqlx::query_scalar(SNAPSHOT).fetch_one(&pool).await.unwrap();
    let prepared = PreparedTransition::new(&proof);
    let mut connection = pool.acquire().await.unwrap();
    let mut tx = connection.begin().await.unwrap();
    PgPersister::set_persist_query_limits(&mut tx)
        .await
        .unwrap();
    stage_transition(&mut tx, &proof, &prepared).await.unwrap();
    writer.acquire_persist_writer_lock(&mut tx).await.unwrap();
    // Keep the server deadline later than the client deadline to select the
    // Tokio cancellation branch deterministically, then drain and roll back.
    sqlx::query("SET LOCAL statement_timeout='300ms'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let cancellation_started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_millis(30),
        super::batch::execute(&mut tx, &proof),
    )
    .await;
    let cancellation_elapsed = cancellation_started.elapsed();
    eprintln!("client cancellation observed after {cancellation_elapsed:?}");
    assert!(
        cancellation_elapsed < Duration::from_millis(200),
        "client cancellation must precede the 300ms server timeout: {cancellation_elapsed:?}"
    );
    assert!(
        result.is_err(),
        "expected client timeout before PostgreSQL's deadline"
    );
    tx.rollback().await.unwrap();
    let reached: bool = sqlx::query_scalar("SELECT is_called FROM public.batch_cancel_reached")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert!(reached);
    let after: Value = sqlx::query_scalar(SNAPSHOT)
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(before, after);
    let clean:bool=sqlx::query_scalar("SELECT to_regclass('pg_temp.historical_transition_input') IS NULL AND to_regclass('pg_temp.historical_transition_mapping') IS NULL AND to_regclass('pg_temp.historical_transition_result') IS NULL").fetch_one(&mut *connection).await.unwrap();
    assert!(clean);
    let mut other = pool.begin().await.unwrap();
    let released: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(6074847039450202930::bigint)")
            .fetch_one(&mut *other)
            .await
            .unwrap();
    assert!(released);
    other.rollback().await.unwrap();
}
