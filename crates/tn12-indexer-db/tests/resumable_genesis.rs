use sqlx::{PgPool, Row};
use tn12_indexer_db::{persist::genesis::read_job, PgPersister};
const KEY: &str = "test_tip";

async fn fixture(pool: &PgPool, count: i32) {
    sqlx::raw_sql("CREATE INDEX covenant_utxos_genesis_scan_idx ON covenant_utxos(covenant_id,txid,vout) INCLUDE(created_block);
      CREATE INDEX covenant_actions_genesis_discovery_idx ON covenant_actions(block_hash,id) INCLUDE(covenant_id) WHERE action IN ('deploy','continuation');
      INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
      VALUES(decode('aa','hex'),100,0,ARRAY[]::bytea[],1000,true,1000),(decode('bb','hex'),200,0,ARRAY[]::bytea[],2000,true,2000);
      INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms)
      VALUES(decode('cc','hex'),'test',0,decode('dd','hex'),decode('ffff','hex'),0,decode('bb','hex'),2000);")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status)
      SELECT decode(lpad(to_hex(n),8,'0'),'hex'),0,decode('cc','hex'),'test',1,decode('aa20','hex'),decode('aa','hex'),'active' FROM generate_series(1,$1)n")
        .bind(count).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs) VALUES(decode('cc','hex'),decode('00000001','hex'),decode('aa','hex'),1000,'continuation','{\"vout\":0}')")
        .execute(pool).await.unwrap();
}
async fn start(pool: &PgPool) -> PgPersister {
    let writer = PgPersister::new(pool.clone());
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    assert!(writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap());
    assert!(writer.discover_settled_members(KEY).await.unwrap());
    writer
}
async fn finish(writer: &PgPersister) {
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    if job.phase == "replay" {
        writer
            .acknowledge_settled_replay(KEY, job.epoch)
            .await
            .unwrap();
    }
    while !writer.discover_settled_members(KEY).await.unwrap() {}
    for _ in 0..20 {
        if writer.step_settled_repair(KEY, 200, 500).await.unwrap() {
            return;
        }
    }
    panic!("reconciliation did not complete");
}
async fn genesis(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT encode(genesis_txid,'hex') FROM covenants WHERE covenant_id=decode('cc','hex')",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn pages_resume_after_restart_without_replay_or_early_cursor_commit(pool: PgPool) {
    fixture(&pool, 1100).await;
    let writer = start(&pool).await;
    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    let job = read_job(&pool, KEY).await.unwrap().unwrap();
    assert_eq!(job.scanned_outputs, 512);
    assert_eq!(genesis(&pool).await, "ffff");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM indexer_state WHERE key='test_tip:settled_recheck'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    drop(writer);
    let writer = PgPersister::new(pool.clone());
    let resumed = writer
        .prepare_settled_repair(KEY, 99900, 100)
        .await
        .unwrap();
    assert_eq!(resumed.window_start, 100);
    assert_eq!(resumed.phase, "reconcile");
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000001");
    assert_eq!(
        read_job(&pool, KEY).await.unwrap().unwrap().scanned_outputs,
        1100
    );
    let cursor: serde_json::Value =
        sqlx::query_scalar("SELECT value FROM indexer_state WHERE key='test_tip:settled_recheck'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursor["completed_windows"], 1);
    assert!(writer.step_settled_repair(KEY, 200, 500).await.is_err());
    let again: serde_json::Value =
        sqlx::query_scalar("SELECT value FROM indexer_state WHERE key='test_tip:settled_recheck'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursor, again);
}

#[sqlx::test(migrations = "./migrations")]
async fn inserts_behind_checkpoint_and_after_baseline_are_not_missed(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    writer.step_settled_repair(KEY, 200, 500).await.unwrap();
    sqlx::query("INSERT INTO covenant_utxos SELECT decode('00000000','hex'),vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,spent_block,spent_by_txid,status FROM covenant_utxos LIMIT 1").execute(&pool).await.unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000000");
    // A later sweep uses the verified candidate without reading the family again.
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap();
    finish(&writer).await;
    assert_eq!(
        read_job(&pool, KEY).await.unwrap().unwrap().scanned_outputs,
        0
    );
    // An output arriving after the baseline can still replace the candidate.
    sqlx::query("INSERT INTO covenant_utxos SELECT decode('00','hex'),vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,spent_block,spent_by_txid,status FROM covenant_utxos LIMIT 1").execute(&pool).await.unwrap();
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00");
}

#[sqlx::test(migrations = "./migrations")]
async fn removing_candidate_invalidates_proof_and_reorg_invalidates_replay_epoch(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    writer.step_settled_repair(KEY, 200, 500).await.unwrap();
    sqlx::query("DELETE FROM covenant_utxos WHERE txid=decode('00000001','hex')")
        .execute(&pool)
        .await
        .unwrap();
    let row =
        sqlx::query("SELECT baseline_complete,scan_txid,best_txid FROM covenant_genesis_progress")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!row.get::<bool, _>("baseline_complete"));
    assert!(row.get::<Option<Vec<u8>>, _>("scan_txid").is_none());
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000002");
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    sqlx::query("UPDATE blocks SET is_chain_block=false WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(!writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap());
    assert!(writer.step_settled_repair(KEY, 200, 500).await.is_err());
    sqlx::query("UPDATE blocks SET is_chain_block=true WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    let resumed = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    assert!(resumed.epoch > job.epoch);
    writer
        .acknowledge_settled_replay(KEY, resumed.epoch)
        .await
        .unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000002");
}

#[sqlx::test(migrations = "./migrations")]
async fn failure_backoff_is_durable_and_bounded_and_resets_on_progress(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    for n in 0..9 {
        let before = chrono::Utc::now().timestamp_millis();
        writer
            .retain_settled_reconciliation_error(KEY, &anyhow::anyhow!("statement timeout"))
            .await
            .unwrap();
        let job = read_job(&pool, KEY).await.unwrap().unwrap();
        let expected = (1000_i64 << n.min(6)).min(60000);
        assert!(job.next_retry_at_ms >= before + expected);
        assert!(job.next_retry_at_ms <= chrono::Utc::now().timestamp_millis() + expected);
        assert_eq!(job.batch_size, (512 >> n + 1).max(1));
    }
    writer.step_settled_repair(KEY, 200, 500).await.unwrap();
    let job = read_job(&pool, KEY).await.unwrap().unwrap();
    assert_eq!(job.consecutive_failures, 0);
    assert_eq!(job.next_retry_at_ms, 0);
    assert!(job.last_error.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn source_timeout_does_not_shrink_reconciliation_pages(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    writer
        .retain_settled_error(KEY, &anyhow::anyhow!("REST source timeout"))
        .await
        .unwrap();
    assert_eq!(read_job(&pool, KEY).await.unwrap().unwrap().batch_size, 512);
}

#[sqlx::test(migrations = "./migrations")]
async fn successful_reconciliation_recovers_from_one_output_batches(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    sqlx::query("UPDATE settled_repair_jobs SET batch_size=1,attempts=7 WHERE cursor_key=$1")
        .bind(KEY)
        .execute(&pool)
        .await
        .unwrap();

    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    let job = read_job(&pool, KEY).await.unwrap().unwrap();
    assert_eq!(job.scanned_outputs, 1);
    assert_eq!(
        job.batch_size, 2,
        "successful pages must restore scan capacity"
    );
    assert_eq!(job.last_error, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn successful_reconciliation_does_not_reduce_large_pages(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    sqlx::query("UPDATE settled_repair_jobs SET attempts=7 WHERE cursor_key=$1")
        .bind(KEY)
        .execute(&pool)
        .await
        .unwrap();

    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    let job = read_job(&pool, KEY).await.unwrap().unwrap();
    assert_eq!(job.scanned_outputs, 512);
    assert_eq!(job.batch_size, 512);
}

#[sqlx::test(migrations = "./migrations")]
async fn block_score_change_updates_candidate_and_rolled_back_insert_leaves_no_progress(
    pool: PgPool,
) {
    fixture(&pool, 2).await;
    let writer = start(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO covenant_utxos SELECT decode('00','hex'),vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,spent_block,spent_by_txid,status FROM covenant_utxos LIMIT 1").execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000001");
    sqlx::query("INSERT INTO covenant_utxos SELECT decode('ff','hex'),vout,covenant_id,address,amount_sompi,script_pubkey,state,decode('bb','hex'),spent_block,spent_by_txid,status FROM covenant_utxos LIMIT 1").execute(&pool).await.unwrap();
    sqlx::query("UPDATE blocks SET blue_score=50 WHERE hash=decode('bb','hex')")
        .execute(&pool)
        .await
        .unwrap();
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "ff");
}

#[sqlx::test(migrations = "./migrations")]
async fn timeout_rolls_back_page_and_releases_writer_lock(pool: PgPool) {
    fixture(&pool, 600).await;
    let writer = start(&pool).await;
    sqlx::raw_sql("CREATE FUNCTION delay_genesis_page() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$; CREATE TRIGGER delay_genesis_page BEFORE UPDATE ON covenant_genesis_progress FOR EACH ROW EXECUTE FUNCTION delay_genesis_page();").execute(&pool).await.unwrap();
    let started = std::time::Instant::now();
    assert!(writer.step_settled_repair(KEY, 200, 500).await.is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    let scanned: i64 = sqlx::query_scalar("SELECT scanned_outputs FROM covenant_genesis_progress")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(scanned, 0);
    assert_eq!(genesis(&pool).await, "ffff");
    // This takes the same writer lock on a fresh transaction after rollback.
    writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    sqlx::query("DROP TRIGGER delay_genesis_page ON covenant_genesis_progress")
        .execute(&pool)
        .await
        .unwrap();
    finish(&writer).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn candidate_identity_move_and_block_activation_are_observed(pool: PgPool) {
    fixture(&pool, 2).await;
    let writer = start(&pool).await;
    finish(&writer).await;
    sqlx::raw_sql("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) SELECT decode('ee','hex'),'other',0,decode('ff','hex'),genesis_txid,genesis_vout,genesis_block,created_at_ms FROM covenants LIMIT 1;
      INSERT INTO covenant_genesis_progress(covenant_id,baseline_complete) VALUES(decode('ee','hex'),true);
      UPDATE covenant_utxos SET covenant_id=decode('ee','hex') WHERE txid=decode('00000001','hex');")
        .execute(&pool).await.unwrap();
    let old_complete:bool=sqlx::query_scalar("SELECT baseline_complete FROM covenant_genesis_progress WHERE covenant_id=decode('cc','hex')").fetch_one(&pool).await.unwrap();
    assert!(!old_complete);
    let moved:String=sqlx::query_scalar("SELECT encode(best_txid,'hex') FROM covenant_genesis_progress WHERE covenant_id=decode('ee','hex')").fetch_one(&pool).await.unwrap();
    assert_eq!(moved, "00000001");
    sqlx::query("UPDATE blocks SET is_chain_block=false WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap();
    while !writer.discover_settled_members(KEY).await.unwrap() {}
    assert!(writer.step_settled_repair(KEY, 200, 500).await.is_err());
    sqlx::query("UPDATE blocks SET is_chain_block=true WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    let candidate:String=sqlx::query_scalar("SELECT encode(best_txid,'hex') FROM covenant_genesis_progress WHERE covenant_id=decode('cc','hex')").fetch_one(&pool).await.unwrap();
    assert_eq!(candidate, "00000002");
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000002");
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_between_family_commit_and_cursor_commit_requires_replay(pool: PgPool) {
    fixture(&pool, 2).await;
    let writer = start(&pool).await;
    assert!(!writer.step_settled_repair(KEY, 200, 500).await.unwrap());
    assert_eq!(genesis(&pool).await, "00000001");
    sqlx::query("UPDATE blocks SET is_chain_block=false WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(writer.step_settled_repair(KEY, 200, 500).await.is_err());
    assert_eq!(read_job(&pool, KEY).await.unwrap().unwrap().phase, "replay");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM indexer_state WHERE key='test_tip:settled_recheck'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "requires TN10_GENESIS_CAPTURE containing captured window families"]
async fn captured_window_matches_reference_and_reuses_verified_baseline(pool: PgPool) {
    use std::io::Read;
    let path = std::env::var("TN10_GENESIS_CAPTURE").unwrap();
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("CREATE TABLE genesis_capture (data JSONB NOT NULL)")
        .execute(&mut *conn)
        .await
        .unwrap();
    let mut copy = conn
        .copy_in_raw("COPY genesis_capture(data) FROM STDIN")
        .await
        .unwrap();
    let mut file = std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        copy.send(&buffer[..n]).await.unwrap();
    }
    copy.finish().await.unwrap();
    // Only seed unrelated summaries through their existing bulk deferral path.
    // Genesis maintenance remains enabled; this benchmark measures reconciliation.
    sqlx::raw_sql("SET tn12.defer_bulk_utxo_summaries='on'; SET tn12.defer_acceptance_summary_refresh='on'; INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
      SELECT decode(data->>'hash','hex'),(data->>'blue_score')::bigint,0,ARRAY[]::bytea[],(data->>'timestamp_ms')::bigint,(data->>'is_chain_block')::boolean,0 FROM genesis_capture WHERE data->>'type'='block';
      INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms)
      SELECT DISTINCT ON(data->>'covenant_id') decode(data->>'covenant_id','hex'),'captured',0,decode(data->>'covenant_id','hex'),decode(data->>'txid','hex'),(data->>'vout')::integer,decode(data->>'created_block','hex'),b.timestamp_ms FROM genesis_capture JOIN blocks b ON b.hash=decode(data->>'created_block','hex') WHERE data->>'type'='output' ORDER BY data->>'covenant_id',b.blue_score DESC;
      INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,created_block,status)
      SELECT decode(data->>'txid','hex'),(data->>'vout')::integer,decode(data->>'covenant_id','hex'),'captured',1,decode('aa20','hex'),decode(data->>'created_block','hex'),'active' FROM genesis_capture WHERE data->>'type'='output';
      CREATE INDEX covenant_utxos_genesis_scan_idx ON covenant_utxos(covenant_id,txid,vout) INCLUDE(created_block);
      CREATE INDEX covenant_actions_genesis_discovery_idx ON covenant_actions(block_hash,id) INCLUDE(covenant_id) WHERE action IN ('deploy','continuation');
      INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs)
      SELECT u.covenant_id,u.txid,u.created_block,b.timestamp_ms,'continuation',jsonb_build_object('vout',u.vout)
      FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE b.blue_score>=586430900 AND b.blue_score<586431000 AND b.is_chain_block;
      ANALYZE covenant_utxos; ANALYZE blocks;")
        .execute(&mut *conn).await.unwrap();
    drop(conn);
    let expected:Vec<(Vec<u8>,Vec<u8>,i32)>=sqlx::query_as("SELECT DISTINCT ON(u.covenant_id) u.covenant_id,u.txid,u.vout FROM covenant_utxos u JOIN blocks b ON b.hash=u.created_block WHERE b.is_chain_block ORDER BY u.covenant_id,b.blue_score,u.vout,u.txid")
        .fetch_all(&pool).await.unwrap();
    let writer = PgPersister::new(pool.clone());
    for pass in 0..2 {
        let job = writer
            .prepare_settled_repair(KEY, 586430900, 100)
            .await
            .unwrap();
        writer
            .acknowledge_settled_replay(KEY, job.epoch)
            .await
            .unwrap();
        while !writer.discover_settled_members(KEY).await.unwrap() {}
        let started = std::time::Instant::now();
        let mut steps = 0;
        let mut max_step = std::time::Duration::ZERO;
        loop {
            let step = std::time::Instant::now();
            let done = writer
                .step_settled_repair(KEY, 586431000, 586632000)
                .await
                .unwrap();
            max_step = max_step.max(step.elapsed());
            steps += 1;
            if done {
                break;
            }
            assert!(steps < 20000, "unbounded reconciliation");
        }
        let observed: Vec<(Vec<u8>, Vec<u8>, i32)> = sqlx::query_as(
            "SELECT covenant_id,genesis_txid,genesis_vout FROM covenants ORDER BY covenant_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(observed, expected);
        let job = read_job(&pool, KEY).await.unwrap().unwrap();
        println!("GENESIS_CAPTURE pass={pass} families={} scanned={} steps={steps} elapsed_ms={} max_step_ms={}",expected.len(),job.scanned_outputs,started.elapsed().as_millis(),max_step.as_millis());
        if pass == 1 {
            assert_eq!(job.scanned_outputs, 0);
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn permanent_reorg_preserves_members_when_last_window_action_disappears(pool: PgPool) {
    fixture(&pool, 2).await;
    sqlx::query("INSERT INTO covenant_utxos SELECT decode('ff','hex'),vout,covenant_id,address,amount_sompi,script_pubkey,state,decode('bb','hex'),spent_block,spent_by_txid,status FROM covenant_utxos LIMIT 1").execute(&pool).await.unwrap();
    let writer = start(&pool).await;
    writer.step_settled_repair(KEY, 200, 500).await.unwrap();
    sqlx::query("UPDATE blocks SET is_chain_block=false WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM covenant_actions WHERE block_hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "ff");
    let members: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM settled_repair_members WHERE cursor_key='test_tip'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(members, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn older_candidate_change_is_repaired_after_original_window_members_are_retired(
    pool: PgPool,
) {
    fixture(&pool, 2).await;
    sqlx::query("INSERT INTO covenant_utxos SELECT decode('ff','hex'),vout,covenant_id,address,amount_sompi,script_pubkey,state,decode('bb','hex'),spent_block,spent_by_txid,status FROM covenant_utxos LIMIT 1").execute(&pool).await.unwrap();
    let writer = start(&pool).await;
    finish(&writer).await;
    let next = writer.prepare_settled_repair(KEY, 300, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, next.epoch)
        .await
        .unwrap();
    assert!(writer.discover_settled_members(KEY).await.unwrap());
    let members: i64 = sqlx::query_scalar("SELECT count(*) FROM settled_repair_members")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(members, 0);
    sqlx::query("UPDATE blocks SET is_chain_block=false WHERE hash=decode('aa','hex')")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        read_job(&pool, KEY).await.unwrap().unwrap().phase,
        "reconcile"
    );
    assert_eq!(
        read_job(&pool, KEY)
            .await
            .unwrap()
            .unwrap()
            .remaining_families,
        1
    );
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "ff");
    let dirty:i64=sqlx::query_scalar("SELECT count(*) FROM kcc20_projection_dirty WHERE txid=decode('ff','hex') AND reason='settled_replay_genesis'").fetch_one(&pool).await.unwrap();
    assert!(dirty > 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn discovery_pages_actions_even_when_many_actions_share_one_family(pool: PgPool) {
    fixture(&pool, 1100).await;
    sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs) SELECT covenant_id,txid,created_block,1000,'continuation',jsonb_build_object('vout',vout) FROM covenant_utxos WHERE txid<>decode('00000001','hex')").execute(&pool).await.unwrap();
    let writer = PgPersister::new(pool.clone());
    let job = writer.prepare_settled_repair(KEY, 100, 100).await.unwrap();
    writer
        .acknowledge_settled_replay(KEY, job.epoch)
        .await
        .unwrap();
    assert!(!writer.discover_settled_members(KEY).await.unwrap());
    let first = read_job(&pool, KEY).await.unwrap().unwrap();
    assert_eq!(first.discovery_action_id, 512);
    assert_eq!(first.phase, "discover");
    drop(writer);
    let writer = PgPersister::new(pool.clone());
    assert!(!writer.discover_settled_members(KEY).await.unwrap());
    assert_eq!(
        read_job(&pool, KEY)
            .await
            .unwrap()
            .unwrap()
            .discovery_action_id,
        1024
    );
    assert!(writer.discover_settled_members(KEY).await.unwrap());
    finish(&writer).await;
    assert_eq!(genesis(&pool).await, "00000001");
}
