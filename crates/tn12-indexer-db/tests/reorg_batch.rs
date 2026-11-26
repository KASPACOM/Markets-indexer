//! Reorgs recount affected summaries without per-output summary writes.
use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{repo, Persister, PgPersister};

async fn assert_parity(pool: &PgPool) {
    let mismatches: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM covenant_summaries s
        JOIN covenants c USING(covenant_id)
        LEFT JOIN LATERAL (
            SELECT count(*)::bigint AS n,coalesce(sum(amount_sompi),0)::bigint AS amount
            FROM covenant_utxos u WHERE u.covenant_id=s.covenant_id AND u.status='active'
        ) totals ON true
        LEFT JOIN LATERAL (
            SELECT u.txid,u.vout,u.address,u.created_block,b.blue_score
            FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block
            WHERE u.covenant_id=s.covenant_id AND u.status='active'
            ORDER BY b.blue_score DESC,u.txid DESC,u.vout DESC LIMIT 1
        ) latest ON true
        WHERE ROW(s.active_utxos,s.total_amount_sompi,s.current_address,s.latest_active_txid,
            s.latest_active_vout,s.latest_active_block,s.latest_active_blue_score)
        IS DISTINCT FROM ROW(totals.n,totals.amount,coalesce(latest.address,c.address),latest.txid,
            latest.vout,latest.created_block,latest.blue_score)
    "#,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(mismatches, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn set_based_reorg_recount_matches_full_refresh_for_recent_old_and_missing_summaries(
    pool: PgPool,
) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut txs = Vec::new();
    for i in 0..12 {
        let mut tx = fixture[0].clone();
        tx.transaction_id = format!("{:064x}", i + 800_000);
        tx.inputs.clear();
        tx.outputs.truncate(1);
        tx.outputs[0].transaction_id = tx.transaction_id.clone();
        tx.outputs[0].script_public_key = format!("aa20{:064x}87", i + 900_000);
        tx.outputs[0].script_public_key_address = None;
        txs.push(tx);
    }
    writer.persist_batch(&txs).await.unwrap();
    let ids: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT covenant_id FROM covenants ORDER BY covenant_id")
            .fetch_all(&pool)
            .await
            .unwrap();
    for older_than_recent_window in [false, true] {
        let mut conn = pool.begin().await.unwrap();
        if older_than_recent_window {
            sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(md5(i::text)||md5(i::text),'hex'),(SELECT max(blue_score) FROM blocks)+i,0,ARRAY[]::bytea[],0,true,0 FROM generate_series(1,100) i;")
                .execute(&mut *conn).await.unwrap();
        }
        // Cover missing summaries, invalid pointers, negative/zero counters,
        // and valid pointers whose deliberately wrong counters must be repaired.
        sqlx::query("DELETE FROM covenant_summaries WHERE covenant_id=ANY($1::bytea[])")
            .bind(&ids[..2])
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("UPDATE covenant_summaries SET latest_active_txid=NULL,latest_active_vout=NULL WHERE covenant_id=ANY($1::bytea[])")
            .bind(&ids[2..6]).execute(&mut *conn).await.unwrap();
        sqlx::query("UPDATE covenant_summaries SET active_utxos=0 WHERE covenant_id=$1")
            .bind(&ids[3])
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("UPDATE covenant_summaries SET active_utxos=-1 WHERE covenant_id=$1")
            .bind(&ids[4])
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("UPDATE covenant_summaries SET active_utxos=17 WHERE covenant_id=$1")
            .bind(&ids[8])
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE summary_before ON COMMIT DROP AS SELECT * FROM covenant_summaries;",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        let mut affected = ids.clone();
        affected.push(vec![0xff; 32]); // Deleted/unknown covenant.
        affected.push(ids[2].clone()); // Duplicate input.
        sqlx::query("SELECT refresh_covenant_summary(covenant_id) FROM unnest($1::bytea[]) AS affected(covenant_id)")
            .bind(&affected).execute(&mut *conn).await.unwrap();
        let snapshot =
            "SELECT jsonb_agg(to_jsonb(s) ORDER BY covenant_id) FROM covenant_summaries s";
        let expected: serde_json::Value = sqlx::query_scalar(snapshot)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        sqlx::raw_sql("TRUNCATE covenant_summaries; INSERT INTO covenant_summaries SELECT * FROM summary_before;")
            .execute(&mut *conn).await.unwrap();
        sqlx::query(include_str!("../src/persist/finalize_reorg_summaries.sql"))
            .bind(&affected)
            .execute(&mut *conn)
            .await
            .unwrap();
        let actual: serde_json::Value = sqlx::query_scalar(snapshot)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(actual, expected, "old-window={older_than_recent_window}");
        conn.rollback().await.unwrap();
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_one_thousand_covenant_spends_preserves_summary_parity(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let mut txs = Vec::new();
    for i in 0..1000 {
        let mut tx = fixture[0].clone();
        tx.transaction_id = format!("{:064x}", i + 500_000);
        tx.inputs.clear();
        tx.outputs.truncate(1);
        tx.outputs[0].transaction_id = tx.transaction_id.clone();
        tx.outputs[0].script_public_key = format!("aa20{:064x}87", i + 700_000);
        tx.outputs[0].script_public_key_address = None;
        txs.push(tx);
    }
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_batch(&txs).await.unwrap();
    // Sixteen existing outputs per covenant, then one spend/continuation per
    // covenant in the reverted block. This exercises reactivation, summary
    // finalization and address normalization through the real persister.
    sqlx::raw_sql("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(md5(encode(txid,'hex')||i::text)||md5(encode(txid,'hex')||i::text),'hex'),0,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status FROM covenant_utxos CROSS JOIN generate_series(1,15) i;").execute(&pool).await.unwrap();
    // Count writes at the real summary boundary, so a regression to one
    // summary update per output fails without relying on wall-clock timing.
    sqlx::raw_sql("CREATE TABLE reorg_summary_writes(covenant_id bytea); CREATE FUNCTION count_reorg_summary_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO reorg_summary_writes VALUES (NEW.covenant_id); RETURN NEW; END $$; CREATE TRIGGER count_reorg_summary_write AFTER INSERT OR UPDATE ON covenant_summaries FOR EACH ROW EXECUTE FUNCTION count_reorg_summary_write();")
        .execute(&pool).await.unwrap();
    for iteration in 0..3 {
        sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fa',32),'hex'),max(blue_score)+100,0,ARRAY[]::bytea[],0,true,0 FROM blocks; INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(md5(encode(s.covenant_id,'hex'))||md5(encode(s.covenant_id,'hex')),'hex'),0,u.covenant_id,u.address,u.amount_sompi,u.script_pubkey,u.state,decode(repeat('fa',32),'hex'),'active' FROM covenant_summaries s JOIN covenant_utxos u ON u.txid=s.latest_active_txid AND u.vout=s.latest_active_vout; UPDATE covenant_utxos u SET status='spent',spent_block=decode(repeat('fa',32),'hex'),spent_by_txid=decode(md5(encode(u.covenant_id,'hex'))||md5(encode(u.covenant_id,'hex')),'hex') WHERE (u.txid,u.vout) IN (SELECT DISTINCT ON (covenant_id) txid,vout FROM covenant_utxos WHERE created_block<>decode(repeat('fa',32),'hex') ORDER BY covenant_id,txid DESC,vout DESC);").execute(&pool).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_summaries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1000);
        assert_parity(&pool).await;
        sqlx::query("TRUNCATE reorg_summary_writes")
            .execute(&pool)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let stats = writer.revert_block(&[0xfa; 32]).await.unwrap();
        let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM reorg_summary_writes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            writes, 1000,
            "one final summary write per affected covenant"
        );
        eprintln!(
            "actual reorg of 1000 covenant spends (iteration {iteration}): {:?}",
            started.elapsed()
        );
        assert_eq!(stats.utxos_created_removed, 1000);
        assert_eq!(stats.utxos_reactivated, 1000);
        assert_parity(&pool).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn batched_reorg_reads_current_address_without_rewriting_history(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut parent = fixture[0].clone();
    parent.inputs.clear();
    parent.outputs.truncate(1);
    writer.persist_tx(&parent).await.unwrap();
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fa',32),'hex'),max(blue_score)+100,0,ARRAY[]::bytea[],0,true,0 FROM blocks; INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(repeat('fb',32),'hex'),0,covenant_id,'new address',amount_sompi,script_pubkey,state,decode(repeat('fa',32),'hex'),'active' FROM covenant_utxos; UPDATE covenant_utxos SET status='spent',spent_block=decode(repeat('fa',32),'hex'),spent_by_txid=decode(repeat('fb',32),'hex') WHERE txid<>decode(repeat('fb',32),'hex'); UPDATE covenant_actions SET outputs=jsonb_build_object('address','stale address');").execute(&pool).await.unwrap();
    // A failure after UTXO mutation must roll back the entire removal,
    // including the transaction-local trigger setting.
    let snapshot_sql = "SELECT jsonb_build_object('blocks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY hash) FROM blocks t),'utxos',(SELECT jsonb_agg(to_jsonb(t) ORDER BY txid,vout) FROM covenant_utxos t),'actions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM covenant_actions t),'summaries',(SELECT jsonb_agg(to_jsonb(t) ORDER BY covenant_id) FROM covenant_summaries t),'templates',(SELECT jsonb_agg(to_jsonb(t) ORDER BY template) FROM covenant_template_summaries t))";
    let before: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_reorg_summary() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected reorg summary failure'; END $$; CREATE TRIGGER reject_reorg_summary BEFORE UPDATE ON covenant_summaries FOR EACH ROW EXECUTE FUNCTION reject_reorg_summary();")
        .execute(&pool).await.unwrap();
    let error = writer.revert_block(&[0xfa; 32]).await.unwrap_err();
    assert!(format!("{error:#}").contains("injected reorg summary failure"));
    let after: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "failed summary recount must roll back the reorg"
    );
    sqlx::query("DROP TRIGGER reject_reorg_summary ON covenant_summaries")
        .execute(&pool)
        .await
        .unwrap();
    let stats = writer.revert_block(&[0xfa; 32]).await.unwrap();
    assert_eq!(stats.utxos_reactivated, 1);
    assert_parity(&pool).await;
    let rows: Vec<(String, String, String)> = sqlx::query_as("SELECT encode(a.covenant_id,'hex'),a.outputs->>'address',s.current_address FROM covenant_actions a JOIN covenant_summaries s USING(covenant_id) WHERE s.active_utxos=1").fetch_all(&pool).await.unwrap();
    assert!(!rows.is_empty());
    for (covenant_id, historic_address, current_address) in rows {
        assert_ne!(historic_address, current_address);
        assert!(repo::actions_by_address(&pool, &historic_address, 20)
            .await
            .unwrap()
            .is_empty());
        let visible = repo::actions_for_covenant(&pool, &covenant_id, 20, 0, false, None, &[])
            .await
            .unwrap();
        assert!(!visible.is_empty());
        assert!(visible
            .iter()
            .all(|action| action.address == current_address));
        assert!(visible.iter().all(|action| {
            action
                .outputs
                .as_ref()
                .and_then(|value| value.get("address"))
                .and_then(|value| value.as_str())
                == Some(current_address.as_str())
        }));
        let current = repo::actions_by_address(&pool, &current_address, 20)
            .await
            .unwrap();
        assert!(!current.is_empty());
        assert!(current
            .iter()
            .all(|action| action.address == current_address));
        assert!(current.iter().all(|action| {
            action
                .outputs
                .as_ref()
                .and_then(|value| value.get("address"))
                .and_then(|value| value.as_str())
                == Some(current_address.as_str())
        }));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_large_family_uses_changed_rows_and_preserves_exact_summary(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut tx = fixture[0].clone();
    tx.inputs.clear();
    tx.outputs.truncate(1);
    writer.persist_tx(&tx).await.unwrap();
    // Benchmark the actual reorg path with a large existing family.
    sqlx::raw_sql("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(md5(i::text)||md5(i::text),'hex'),0,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status FROM covenant_utxos CROSS JOIN generate_series(1,20000) i; ANALYZE covenant_utxos;")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fa',32),'hex'),max(blue_score)+100,0,ARRAY[]::bytea[],0,true,0 FROM blocks; INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(repeat('fb',32),'hex'),0,u.covenant_id,u.address,u.amount_sompi,u.script_pubkey,u.state,decode(repeat('fa',32),'hex'),'active' FROM covenant_utxos u LIMIT 1;")
        .execute(&pool).await.unwrap();
    // Keep the large historical block outside the bounded recent lookup,
    // with one surviving recent output and the removed latest output.
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(md5('recent'||i::text)||md5('recent'||i::text),'hex'),(SELECT max(blue_score) FROM blocks)-i,0,ARRAY[]::bytea[],0,true,0 FROM generate_series(1,80) i; INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(repeat('fc',32),'hex'),0,u.covenant_id,u.address,u.amount_sompi,u.script_pubkey,u.state,decode(md5('recent1')||md5('recent1'),'hex'),'active' FROM covenant_utxos u LIMIT 1;")
        .execute(&pool).await.unwrap();
    let ids: Vec<Vec<u8>> = sqlx::query_scalar("SELECT covenant_id FROM covenants")
        .fetch_all(&pool)
        .await
        .unwrap();
    let mut expected = None;
    for use_delta in [false, true, false, true] {
        let mut conn = pool.begin().await.unwrap();
        sqlx::raw_sql("SET LOCAL jit=off; SET LOCAL tn12.defer_reorg_utxo_summaries='on';")
            .execute(&mut *conn)
            .await
            .unwrap();
        let changes: serde_json::Value = sqlx::query_scalar(
            "SELECT jsonb_agg(jsonb_build_object('cid',encode(covenant_id,'hex'),'count_delta',-1,'amount_delta',-amount_sompi,'txid',encode(txid,'hex'),'vout',vout,'address',address,'block',encode(created_block,'hex'))) FROM covenant_utxos WHERE created_block=decode(repeat('fa',32),'hex')"
        ).fetch_one(&mut *conn).await.unwrap();
        sqlx::query("DELETE FROM covenant_utxos WHERE created_block=decode(repeat('fa',32),'hex')")
            .execute(&mut *conn)
            .await
            .unwrap();
        let began = std::time::Instant::now();
        if use_delta {
            sqlx::query(include_str!(
                "../src/persist/finalize_reorg_summary_deltas.sql"
            ))
            .bind(&changes)
            .bind(Vec::<Vec<u8>>::new())
            .execute(&mut *conn)
            .await
            .unwrap();
        } else {
            sqlx::query(include_str!("../src/persist/finalize_reorg_summaries.sql"))
                .bind(&ids)
                .execute(&mut *conn)
                .await
                .unwrap();
        }
        eprintln!(
            "same-window summary delta={use_delta}: {:?}",
            began.elapsed()
        );
        let actual: serde_json::Value = sqlx::query_scalar("SELECT jsonb_agg(to_jsonb(s)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_summaries s")
            .fetch_one(&mut *conn).await.unwrap();
        if let Some(expected) = &expected {
            assert_eq!(&actual, expected);
        } else {
            expected = Some(actual);
        }
        conn.rollback().await.unwrap();
    }
    let started = std::time::Instant::now();
    writer.revert_block(&[0xfa; 32]).await.unwrap();
    eprintln!("large-family removal: {:?}", started.elapsed());
    assert_parity(&pool).await;
    let n: i64 = sqlx::query_scalar("SELECT active_utxos FROM covenant_summaries LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 20002);
    writer.revert_block(&[0xfa; 32]).await.unwrap();
    assert_parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_deltas_cover_same_block_spends_missing_baselines_and_score_ties(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut tx = fixture[0].clone();
    tx.inputs.clear();
    tx.outputs.truncate(1);
    writer.persist_tx(&tx).await.unwrap();
    // More than 64 blocks tie at the cutoff. A surviving output at that
    // score must beat the reactivated older output even if its block lies
    // past the first 64 rows. Both before and after use the full oracle.
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(md5('tie'||i::text)||md5('tie'||i::text),'hex'),(SELECT max(blue_score) FROM blocks)+10,0,ARRAY[]::bytea[],0,true,0 FROM generate_series(1,100) i;")
        .execute(&pool).await.unwrap();
    for baseline in ["valid", "missing", "stale_spent"] {
        sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fa',32),'hex'),max(blue_score)+1,0,ARRAY[]::bytea[],0,true,0 FROM blocks; INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(repeat('fb',32),'hex'),0,covenant_id,'removed',7,script_pubkey,state,decode(repeat('fa',32),'hex'),'active' FROM covenant_utxos LIMIT 1; INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) SELECT decode(repeat('fc',32),'hex'),0,covenant_id,'tie winner',11,script_pubkey,state,decode(md5('tie100')||md5('tie100'),'hex'),'active' FROM covenant_utxos LIMIT 1 ON CONFLICT DO NOTHING; UPDATE covenant_utxos SET status='spent',spent_block=decode(repeat('fa',32),'hex'),spent_by_txid=decode(repeat('fd',32),'hex') WHERE txid<>decode(repeat('fc',32),'hex');")
            .execute(&pool).await.unwrap();
        assert_parity(&pool).await;
        if baseline == "missing" {
            sqlx::query("DELETE FROM covenant_summaries")
                .execute(&pool)
                .await
                .unwrap();
        }
        if baseline == "stale_spent" {
            sqlx::query("UPDATE covenant_summaries s SET latest_active_txid=u.txid,latest_active_vout=u.vout,latest_active_block=u.created_block,latest_active_blue_score=b.blue_score,current_address=u.address FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE u.covenant_id=s.covenant_id AND u.created_block=decode(repeat('fa',32),'hex')")
                .execute(&pool).await.unwrap();
        }
        writer.revert_block(&[0xfa; 32]).await.unwrap();
        assert_parity(&pool).await;
        let address: String =
            sqlx::query_scalar("SELECT current_address FROM covenant_summaries LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(address, "tie winner");
        writer.revert_block(&[0xfa; 32]).await.unwrap();
        assert_parity(&pool).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_removing_last_active_output_clears_latest_without_deleting_family(pool: PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut tx = fixture[0].clone();
    tx.inputs.clear();
    tx.outputs.truncate(1);
    writer.persist_tx(&tx).await.unwrap();
    sqlx::raw_sql("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) SELECT decode(repeat('fa',32),'hex'),max(blue_score)+1,0,ARRAY[]::bytea[],0,true,0 FROM blocks; UPDATE covenant_utxos SET created_block=decode(repeat('fa',32),'hex');")
        .execute(&pool).await.unwrap();
    assert_parity(&pool).await;
    writer.revert_block(&[0xfa; 32]).await.unwrap();
    assert_parity(&pool).await;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_summaries WHERE active_utxos=0 AND total_amount_sompi=0 AND latest_active_txid IS NULL AND latest_active_vout IS NULL AND latest_active_block IS NULL AND latest_active_blue_score IS NULL")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}
