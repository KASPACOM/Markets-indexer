//! Timestamp reassociation must maintain summaries once per affected group.
use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{Persister, PgPersister};

async fn seed(pool: &PgPool) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    let txs: Vec<_> = (0..512)
        .map(|i| {
            let mut tx = fixture[i % fixture.len()].clone();
            tx.transaction_id = format!("{:064x}", i + 100_000);
            tx
        })
        .collect();
    PgPersister::new(pool.clone())
        .with_bounded_writer_lock_wait()
        .persist_batch(&txs)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE test_summary_writes(kind text); CREATE FUNCTION test_count_summary_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO test_summary_writes VALUES(TG_ARGV[0]); RETURN NEW; END; $$; CREATE TRIGGER test_action_writes AFTER UPDATE ON covenant_action_summaries FOR EACH ROW EXECUTE FUNCTION test_count_summary_write('action'); CREATE TRIGGER test_template_writes AFTER UPDATE ON covenant_template_summaries FOR EACH ROW EXECUTE FUNCTION test_count_summary_write('template');").execute(pool).await.unwrap();
}

async fn parity(pool: &PgPool) {
    let bad:i64=sqlx::query_scalar("SELECT count(*) FROM covenants c LEFT JOIN covenant_action_summaries s USING(covenant_id) WHERE ROW(s.action_count,s.latest_action_time_ms) IS DISTINCT FROM (SELECT ROW(count(*),max(block_time_ms)) FROM covenant_actions a WHERE a.covenant_id=c.covenant_id)").fetch_one(pool).await.unwrap();
    assert_eq!(bad, 0);
    let actual:(i64,i64)=sqlx::query_as("SELECT action_count,latest_action_time_ms FROM covenant_template_summaries WHERE template='Unknown'").fetch_one(pool).await.unwrap();
    let expected: (i64, i64) =
        sqlx::query_as("SELECT count(*),max(block_time_ms) FROM covenant_actions")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(actual, expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn action_insert_batch_updates_summaries_once_per_group(pool: PgPool) {
    seed(&pool).await;
    sqlx::query("TRUNCATE test_summary_writes")
        .execute(&pool)
        .await
        .unwrap();
    let inserted: Vec<Vec<u8>> = sqlx::query_scalar(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint,
            inputs, outputs, decoded_args)
           SELECT covenant_id, decode(lpad(to_hex(id + 1000000), 64, '0'), 'hex'),
                  block_hash, block_time_ms + 100, action, entrypoint,
                  inputs, outputs, decoded_args
           FROM covenant_actions WHERE id IN
               (SELECT id FROM covenant_actions ORDER BY id LIMIT 100)
           ORDER BY id ON CONFLICT DO NOTHING
           RETURNING covenant_id"#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(inserted.len(), 100);
    parity(&pool).await;
    let template_writes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM test_summary_writes WHERE kind='template'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        template_writes, 1,
        "one template update for the insert statement"
    );
    let action_writes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM test_summary_writes WHERE kind='action'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let affected = inserted
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(action_writes, affected.len() as i64);

    sqlx::query("TRUNCATE test_summary_writes")
        .execute(&pool)
        .await
        .unwrap();
    let duplicates = sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint,
            inputs, outputs, decoded_args)
           SELECT covenant_id, txid, block_hash, block_time_ms, action,
                  entrypoint, inputs, outputs, decoded_args
           FROM covenant_actions WHERE id IN
               (SELECT id FROM covenant_actions ORDER BY id LIMIT 100)
           ON CONFLICT DO NOTHING"#,
    )
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(duplicates, 0);
    let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM test_summary_writes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(writes, 0, "conflict replay must not update summaries");
    parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn action_insert_batch_handles_templates_new_summary_and_partial_replay(pool: PgPool) {
    seed(&pool).await;
    let ids: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT covenant_id FROM covenants ORDER BY covenant_id LIMIT 2")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(ids.len(), 2);
    for (id, name) in ids.iter().zip(["BatchA", "BatchB"]) {
        sqlx::query("UPDATE covenants SET template_name=$2 WHERE covenant_id=$1")
            .bind(id)
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
    }
    let fresh_id = vec![0xcdu8; 32];
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id,address,script_version,script_hash,template_name,
            genesis_txid,genesis_vout,genesis_block,created_at_ms,constructor_args)
           SELECT $1,address,script_version,$1,'BatchC',$2,genesis_vout,
                  genesis_block,created_at_ms,constructor_args
           FROM covenants WHERE covenant_id=$3"#,
    )
    .bind(&fresh_id)
    .bind(vec![0xdcu8; 32])
    .bind(&ids[0])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM covenant_action_summaries WHERE covenant_id=$1")
        .bind(&fresh_id)
        .execute(&pool)
        .await
        .unwrap();
    let block: Vec<u8> = sqlx::query_scalar("SELECT hash FROM blocks LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("TRUNCATE test_summary_writes")
        .execute(&pool)
        .await
        .unwrap();
    let inserted: Vec<Vec<u8>> = sqlx::query_scalar(
        r#"INSERT INTO covenant_actions
           (covenant_id,txid,block_hash,block_time_ms,action,inputs,outputs)
           SELECT cid,decode(lpad(to_hex(2000000 + ord),64,'0'),'hex'),
                  $4,100 + ord,'deploy',NULL,'{"vout":0}'::jsonb
           FROM (VALUES ($1::bytea,1),($2::bytea,2),($3::bytea,3)) AS wanted(cid,ord)
           UNION ALL
           SELECT covenant_id,txid,block_hash,block_time_ms,action,inputs,outputs
           FROM (SELECT covenant_id,txid,block_hash,block_time_ms,action,inputs,outputs
                 FROM covenant_actions WHERE action='deploy' ORDER BY id LIMIT 1) duplicate
           ON CONFLICT DO NOTHING RETURNING covenant_id"#,
    )
    .bind(&ids[0])
    .bind(&ids[1])
    .bind(&fresh_id)
    .bind(block)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        inserted.len(),
        3,
        "only the new rows should reach summaries"
    );
    let fresh_summary: (i64, i64) = sqlx::query_as(
        "SELECT action_count,latest_action_time_ms FROM covenant_action_summaries WHERE covenant_id=$1",
    )
    .bind(&fresh_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fresh_summary, (1, 103));
    let bad_actions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_action_summaries s WHERE ROW(s.action_count,s.latest_action_time_ms) IS DISTINCT FROM (SELECT ROW(count(*),max(a.block_time_ms)) FROM covenant_actions a WHERE a.covenant_id=s.covenant_id)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bad_actions, 0);
    let bad_templates: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_template_summaries s WHERE ROW(s.action_count,s.latest_action_time_ms) IS DISTINCT FROM (SELECT ROW(count(*),max(a.block_time_ms)) FROM covenant_actions a JOIN covenants c USING(covenant_id) WHERE COALESCE(c.template_name,c.claimed_template,'Unknown')=s.template)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(bad_templates, 0);
    let template_writes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM test_summary_writes WHERE kind='template'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(template_writes, 3, "one update per affected template");
}

#[sqlx::test(migrations = "./migrations")]
async fn timestamp_batch_updates_each_summary_once(pool: PgPool) {
    seed(&pool).await;
    sqlx::query("UPDATE covenant_actions SET block_time_ms=block_time_ms+100")
        .execute(&pool)
        .await
        .unwrap();
    parity(&pool).await;
    let action_writes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM test_summary_writes WHERE kind='action'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let affected: i64 =
        sqlx::query_scalar("SELECT count(DISTINCT covenant_id) FROM covenant_actions")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        action_writes, affected,
        "one action summary update per covenant"
    );
    let writes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM test_summary_writes WHERE kind='template'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(writes, 1, "one template write for the entire forward batch");
    sqlx::query("TRUNCATE test_summary_writes")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenant_actions SET block_time_ms=block_time_ms")
        .execute(&pool)
        .await
        .unwrap();
    let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM test_summary_writes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(writes, 0, "unchanged timestamps must not write summaries");
    sqlx::query("UPDATE covenant_actions SET block_time_ms=block_time_ms+CASE WHEN id%2=0 THEN 200 ELSE -200 END").execute(&pool).await.unwrap();
    parity(&pool).await;
    let writes: i64 =
        sqlx::query_scalar("SELECT count(*) FROM test_summary_writes WHERE kind='template'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        writes, 1,
        "mixed directions must converge in one template write"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn nonlatest_timestamp_batch_preserves_summary_rows(pool: PgPool) {
    seed(&pool).await;
    sqlx::raw_sql("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,inputs,outputs) SELECT DISTINCT ON(covenant_id) covenant_id,decode(repeat('ab',32),'hex'),block_hash,block_time_ms+10000,action,inputs,outputs FROM covenant_actions ORDER BY covenant_id,id; TRUNCATE test_summary_writes;").execute(&pool).await.unwrap();
    sqlx::query("UPDATE covenant_actions SET block_time_ms=block_time_ms+CASE WHEN id%2=0 THEN 10 ELSE -10 END WHERE txid<>decode(repeat('ab',32),'hex')").execute(&pool).await.unwrap();
    parity(&pool).await;
    let writes: i64 = sqlx::query_scalar("SELECT count(*) FROM test_summary_writes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        writes, 0,
        "nonlatest timestamp changes must not rewrite unchanged summaries"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn timestamp_batch_repairs_missing_and_stale_latest_summaries(pool: PgPool) {
    seed(&pool).await;
    sqlx::raw_sql("DELETE FROM covenant_action_summaries; DELETE FROM covenant_template_summaries; UPDATE covenant_actions SET block_time_ms=block_time_ms-100;").execute(&pool).await.unwrap();
    parity(&pool).await;
    sqlx::raw_sql("UPDATE covenant_action_summaries SET latest_action_time_ms=latest_action_time_ms+100000; UPDATE covenant_template_summaries SET latest_action_time_ms=latest_action_time_ms+100000; UPDATE covenant_actions SET block_time_ms=block_time_ms+10;").execute(&pool).await.unwrap();
    parity(&pool).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn timestamp_batch_handles_multiple_templates_and_covenant_moves(pool: PgPool) {
    seed(&pool).await;
    let covenants: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT covenant_id FROM covenants ORDER BY covenant_id LIMIT 2")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(covenants.len(), 2);
    sqlx::query("UPDATE covenants SET template_name='BatchA' WHERE covenant_id=$1")
        .bind(&covenants[0])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET template_name='BatchB' WHERE covenant_id=$1")
        .bind(&covenants[1])
        .execute(&pool)
        .await
        .unwrap();
    // The same statement moves one covenant reference and retimestamps other rows.
    let moved: i64 =
        sqlx::query_scalar("SELECT min(id) FROM covenant_actions WHERE covenant_id=$1")
            .bind(&covenants[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE covenant_actions SET covenant_id=CASE WHEN id=$1 THEN $2 ELSE covenant_id END,block_time_ms=block_time_ms+CASE WHEN id%2=0 THEN 50 ELSE -50 END").bind(moved).bind(&covenants[1]).execute(&pool).await.unwrap();
    let bad:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_action_summaries s WHERE ROW(s.action_count,s.latest_action_time_ms) IS DISTINCT FROM (SELECT ROW(count(*),max(block_time_ms)) FROM covenant_actions a WHERE a.covenant_id=s.covenant_id)").fetch_one(&pool).await.unwrap();
    assert_eq!(bad, 0);
    let bad:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_template_summaries s WHERE ROW(s.action_count,s.latest_action_time_ms) IS DISTINCT FROM (SELECT ROW(count(*),max(a.block_time_ms)) FROM covenant_actions a JOIN covenants c USING(covenant_id) WHERE COALESCE(c.template_name,c.claimed_template,'Unknown')=s.template)").fetch_one(&pool).await.unwrap();
    assert_eq!(bad, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn timestamp_batch_serializes_with_opposite_covenant_moves(pool: PgPool) {
    seed(&pool).await;
    let covenants: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT covenant_id FROM covenants ORDER BY covenant_id LIMIT 2")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(covenants.len(), 2);
    for direction in [0, 1] {
        let from = covenants[direction].clone();
        let to = covenants[1 - direction].clone();
        // Match the persister protocol: every writer takes this transaction lock
        // before touching action rows or summary rows.
        let mut owner = pool.begin().await.unwrap();
        sqlx::raw_sql("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='3s'; SELECT pg_advisory_xact_lock(6074847039450202930::bigint);").execute(&mut *owner).await.unwrap();
        sqlx::query(
            "UPDATE covenant_actions SET block_time_ms=block_time_ms+1 WHERE covenant_id=ANY($1)",
        )
        .bind(&covenants)
        .execute(&mut *owner)
        .await
        .unwrap();
        let rival_pool = pool.clone();
        let (pid_tx, pid_rx) = tokio::sync::oneshot::channel();
        let rival = tokio::spawn(async move {
            let mut tx = rival_pool.begin().await.unwrap();
            sqlx::raw_sql("SET LOCAL lock_timeout='2s'; SET LOCAL statement_timeout='3s';")
                .execute(&mut *tx)
                .await
                .unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            pid_tx.send(pid).unwrap();
            sqlx::query("SELECT pg_advisory_xact_lock(6074847039450202930::bigint)")
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query("UPDATE covenant_actions SET covenant_id=$1,block_time_ms=block_time_ms-2 WHERE id=(SELECT min(id) FROM covenant_actions WHERE covenant_id=$2)").bind(to).bind(from).execute(&mut *tx).await.unwrap();
            tx.commit().await.unwrap();
        });
        let pid = pid_rx.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
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
                assert!(!rival.is_finished());
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        owner.commit().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), rival)
            .await
            .unwrap()
            .unwrap();
        parity(&pool).await;
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn timestamp_batch_recomputes_a_partially_invalidated_latest(pool: PgPool) {
    seed(&pool).await;
    // One later action per covenant stays outside the first timestamp batch.
    sqlx::raw_sql("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,inputs,outputs) SELECT DISTINCT ON(covenant_id) covenant_id,decode(repeat('ac',32),'hex'),block_hash,block_time_ms+10000,action,inputs,outputs FROM covenant_actions ORDER BY covenant_id,id;").execute(&pool).await.unwrap();
    // Only the later rows move backwards. Their cached maxima are invalidated;
    // the exact fallback must find the untouched older actions.
    sqlx::query("UPDATE covenant_actions SET block_time_ms=block_time_ms-20000 WHERE txid=decode(repeat('ac',32),'hex')").execute(&pool).await.unwrap();
    parity(&pool).await;
    // A partial batch can also become the maximum without reading old actions.
    sqlx::query("UPDATE covenant_actions SET block_time_ms=block_time_ms+30000 WHERE txid=decode(repeat('ac',32),'hex')").execute(&pool).await.unwrap();
    parity(&pool).await;
}
