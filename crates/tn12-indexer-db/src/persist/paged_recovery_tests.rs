use super::*;
use crate::Persister;
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};

fn block(hash: &str, descendant: &str) -> StagedRecoveryBlock {
    StagedRecoveryBlock {
        impact: RecoveryBlockImpact {
            block_hash: hash.repeat(32),
            transaction_ids: vec!["33".repeat(32)],
            descendants: vec![descendant.repeat(32)],
        },
        blue_score: 100,
        source_is_chain_block: false,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn discovery_page_and_frontier_resume_under_new_owner(pool: PgPool) {
    let key = "live_write_intent:testnet-10:test";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,1)")
        .bind(key)
        .bind(serde_json::json!({"transactions": [{"transaction_id": "11"}]}))
        .execute(&pool)
        .await
        .unwrap();
    let first = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    assert_eq!(first.roots(&pool).await.unwrap(), vec!["11".repeat(32)]);
    assert_eq!(
        first.pending_blocks(&pool).await.unwrap(),
        vec!["11".repeat(32)]
    );
    first
        .stage_blocks(&pool, &[block("11", "22")])
        .await
        .unwrap();
    first
        .enqueue_transactions(&pool, &["aa".repeat(32)])
        .await
        .unwrap();
    assert_eq!(
        first.pending_transactions(&pool).await.unwrap(),
        vec!["33".repeat(32), "aa".repeat(32)]
    );
    assert_eq!(
        first.pending_blocks(&pool).await.unwrap(),
        vec!["22".repeat(32)]
    );
    assert!(PagedRecoveryOwner::claim(&pool, key, &[]).await.is_err());

    sqlx::query("UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key=$1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let second = PagedRecoveryOwner::claim(&pool, key, &[]).await.unwrap();
    assert_eq!(second.roots(&pool).await.unwrap(), vec!["11".repeat(32)]);
    assert_eq!(second.generation, first.generation + 1);
    assert!(first
        .stage_blocks(&pool, &[block("22", "44")])
        .await
        .is_err());
    second
        .stage_blocks(&pool, &[block("22", "44")])
        .await
        .unwrap();
    second
        .stage_blocks(&pool, &[block("22", "44")])
        .await
        .unwrap();
    assert_eq!(
        second.pending_blocks(&pool).await.unwrap(),
        vec!["44".repeat(32)]
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT discovered_blocks FROM tn10_live_recovery_plans WHERE intent_key=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn changed_intent_or_block_evidence_stops_discovery(pool: PgPool) {
    let key = "live_write_intent:testnet-10:changed";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,1)")
        .bind(key)
        .bind(serde_json::json!({"transactions": []}))
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    owner
        .stage_blocks(&pool, &[block("11", "22")])
        .await
        .unwrap();
    let mut conflict = block("11", "44");
    conflict.blue_score = 101;
    assert!(owner.stage_blocks(&pool, &[conflict]).await.is_err());
    sqlx::query("UPDATE indexer_state SET value=$2 WHERE key=$1")
        .bind(key)
        .bind(serde_json::json!({"transactions": [{"transaction_id": "22"}]}))
        .execute(&pool)
        .await
        .unwrap();
    assert!(owner.pending_blocks(&pool).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn reordered_discovery_evidence_is_idempotent(pool: PgPool) {
    let key = "live_write_intent:testnet-10:reordered";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,1)")
        .bind(key)
        .bind(serde_json::json!({"transactions": []}))
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    let first = StagedRecoveryBlock {
        impact: RecoveryBlockImpact {
            block_hash: "11".repeat(32),
            transaction_ids: vec!["bb".repeat(32), "aa".repeat(32)],
            descendants: vec!["33".repeat(32), "22".repeat(32)],
        },
        blue_score: 100,
        source_is_chain_block: false,
    };
    owner.stage_blocks(&pool, &[first.clone()]).await.unwrap();
    let mut reordered = first;
    reordered.impact.transaction_ids.reverse();
    reordered.impact.transaction_ids[0] = reordered.impact.transaction_ids[0].to_uppercase();
    reordered.impact.descendants.reverse();
    owner.stage_blocks(&pool, &[reordered]).await.unwrap();
    assert_eq!(
        owner.pending_blocks(&pool).await.unwrap(),
        vec!["22".repeat(32), "33".repeat(32)]
    );
    let discovered: i64 = sqlx::query_scalar(
        "SELECT discovered_blocks FROM tn10_live_recovery_plans WHERE intent_key=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(discovered, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn discovery_resumes_a_footprint_larger_than_the_live_window_limit(pool: PgPool) {
    let key = "live_write_intent:testnet-10:large-discovery";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,1)")
        .bind(key)
        .bind(serde_json::json!({"transactions": [{"transaction_id": "root"}]}))
        .execute(&pool)
        .await
        .unwrap();
    let first =
        PagedRecoveryOwner::claim(&pool, key, &[hex::encode(1_u32.to_be_bytes().repeat(8))])
            .await
            .unwrap();
    // Each of the 257 indexed blocks owns one distinct transaction. The
    // complete dependency closure exceeds the ordinary 256-ID journal limit.
    for start in (1_u16..=257).step_by(MAX_PAGE_BLOCKS) {
        let end = (start + MAX_PAGE_BLOCKS as u16).min(258);
        let page = (start..end)
            .map(|number| StagedRecoveryBlock {
                impact: RecoveryBlockImpact {
                    block_hash: hex::encode((number as u32).to_be_bytes().repeat(8)),
                    transaction_ids: vec![hex::encode(
                        (number as u32 + 1000).to_be_bytes().repeat(8),
                    )],
                    descendants: if number < 257 {
                        vec![hex::encode((number as u32 + 1).to_be_bytes().repeat(8))]
                    } else {
                        Vec::new()
                    },
                },
                blue_score: i64::from(number),
                source_is_chain_block: false,
            })
            .collect::<Vec<_>>();
        first.stage_blocks(&pool, &page).await.unwrap();
        let bodies = (start..end)
            .map(|number| {
                let transaction_id = hex::encode((number as u32 + 1000).to_be_bytes().repeat(8));
                RestTransaction {
                    transaction_id: transaction_id.clone(),
                    is_accepted: true,
                    accepting_block_hash: Some(hex::encode(
                        (number as u32).to_be_bytes().repeat(8),
                    )),
                    accepting_block_blue_score: Some(u64::from(number)),
                    accepting_block_time: Some(1000),
                    outputs: vec![RestTxOutput {
                        transaction_id,
                        index: 0,
                        amount: 1,
                        script_public_key: format!("aa20{}87", "44".repeat(32)),
                        ..Default::default()
                    }],
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();
        first.stage_transactions(&pool, &bodies).await.unwrap();
    }
    assert!(first.pending_blocks(&pool).await.unwrap().is_empty());
    assert!(first.pending_transactions(&pool).await.unwrap().is_empty());
    sqlx::query("UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key=$1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let resumed = PagedRecoveryOwner::claim(&pool, key, &[]).await.unwrap();
    resumed.finish_discovery(&pool).await.unwrap();
    let ready = resumed.ready_removals(&pool).await.unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].blue_score, 257);
    let discovered: i64 = sqlx::query_scalar(
        "SELECT discovered_blocks FROM tn10_live_recovery_plans WHERE intent_key=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(discovered, 257);
}

fn accepted(txid: u8, block: u8, score: u64, parent: Option<u8>) -> RestTransaction {
    let script = format!("aa20{}87", "44".repeat(32));
    RestTransaction {
        transaction_id: hex::encode([txid; 32]),
        is_accepted: true,
        accepting_block_hash: Some(hex::encode([block; 32])),
        accepting_block_blue_score: Some(score),
        accepting_block_time: Some(1000),
        inputs: parent
            .into_iter()
            .map(|parent| RestTxInput {
                previous_outpoint_hash: hex::encode([parent; 32]),
                previous_outpoint_index: "0".into(),
                previous_outpoint_script: Some(script.clone()),
                previous_outpoint_amount: Some(1),
                ..Default::default()
            })
            .collect(),
        outputs: vec![RestTxOutput {
            transaction_id: hex::encode([txid; 32]),
            index: 0,
            amount: 1,
            script_public_key: script,
            ..Default::default()
        }],
        ..Default::default()
    }
}

// Delay the checkpoint after removal SQL has run: cancellation here used to
// roll back all useful work and make the next owner repeat the same block.
#[sqlx::test(migrations = "./migrations")]
async fn slow_removal_commits_once_without_wall_clock_cancellation(pool: PgPool) {
    let (writer, owner, page) = removal_timeout_fixture(&pool).await;
    sqlx::raw_sql(
        "CREATE FUNCTION delay_recovery_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.reverted_blocks > OLD.reverted_blocks THEN
             IF current_setting('statement_timeout')='0' OR current_setting('lock_timeout')='0' THEN
               RAISE EXCEPTION 'database safety timeouts must remain enabled';
             END IF;
             PERFORM pg_sleep(0.45);
           END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER delay_recovery_checkpoint BEFORE UPDATE ON tn10_live_recovery_plans
         FOR EACH ROW EXECUTE FUNCTION delay_recovery_checkpoint();",
    ).execute(&pool).await.unwrap();
    let started = std::time::Instant::now();
    owner.revert_one(&writer, &page).await.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(450));
    assert!(!writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    owner.revert_one(&writer, &page).await.unwrap();
    let checkpoint: (i64, bool) = sqlx::query_as(
        "SELECT p.reverted_blocks,b.reverted FROM tn10_live_recovery_plans p
         JOIN tn10_live_recovery_blocks b USING(intent_key) WHERE p.intent_key=$1",
    ).bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
    assert_eq!(checkpoint, (1, true), "retry must not remove or count twice");
    assert!(owner.ready_removals(&pool).await.unwrap().is_empty());
    assert!(sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM indexer_state WHERE key=$1)")
        .bind(&owner.intent_key).fetch_one(&pool).await.unwrap(), "removal cannot acknowledge the journal");
}

#[sqlx::test(migrations = "./migrations")]
async fn database_cancellation_preserves_removal_and_checkpoint_for_retry(pool: PgPool) {
    let (writer, owner, page) = removal_timeout_fixture(&pool).await;
    sqlx::raw_sql(
        "CREATE FUNCTION cancel_recovery_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF NEW.reverted_blocks > OLD.reverted_blocks THEN
             RAISE EXCEPTION USING ERRCODE='57014', MESSAGE='injected database statement cancellation';
           END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER cancel_recovery_checkpoint BEFORE UPDATE ON tn10_live_recovery_plans
         FOR EACH ROW EXECUTE FUNCTION cancel_recovery_checkpoint();",
    ).execute(&pool).await.unwrap();
    let error = owner.revert_one(&writer, &page).await.unwrap_err();
    assert!(format!("{error:#}").contains("injected database statement cancellation"));
    assert!(writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    let checkpoint: (i64, bool) = sqlx::query_as(
        "SELECT p.reverted_blocks,b.reverted FROM tn10_live_recovery_plans p
         JOIN tn10_live_recovery_blocks b USING(intent_key) WHERE p.intent_key=$1",
    ).bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
    assert_eq!(checkpoint, (0, false));
    sqlx::query("DROP TRIGGER cancel_recovery_checkpoint ON tn10_live_recovery_plans")
        .execute(&pool).await.unwrap();
    owner.revert_one(&writer, &page).await.unwrap();
    assert!(!writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
}

async fn removal_timeout_fixture(pool: &PgPool) -> (PgPersister, PagedRecoveryOwner, StagedRecoveryBlock) {
    let writer = PgPersister::new(pool.clone());
    let body = accepted(0xaa, 0x11, 106, None);
    writer.persist_tx(&body).await.unwrap();
    let key = "live_write_intent:testnet-10:removal-timeout";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key).execute(pool).await.unwrap();
    let owner = PagedRecoveryOwner::claim(pool, key, &["11".repeat(32)]).await.unwrap();
    let page = StagedRecoveryBlock {
        impact: writer.recovery_block_impact(&"11".repeat(32)).await.unwrap(),
        blue_score: 106,
        source_is_chain_block: false,
    };
    owner.stage_blocks(pool, &[page.clone()]).await.unwrap();
    owner.stage_transactions(pool, &[body]).await.unwrap();
    owner.finish_discovery(pool).await.unwrap();
    (writer, owner, page)
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_baseline_rebuild_yields_before_canonical_removal(pool:PgPool) {
    let (writer,owner,page)=removal_timeout_fixture(&pool).await;
    for _ in 0..10 {
        let state:serde_json::Value=sqlx::query_scalar("SELECT active_output_order_backfill_step()")
            .fetch_one(&pool).await.unwrap();
        if state["phase"]=="ready" { break; }
    }
    sqlx::query("DELETE FROM covenant_summaries").execute(&pool).await.unwrap();
    owner.revert_one(&writer,&page).await.unwrap();
    assert!(writer.has_utxo(&"aa".repeat(32),0).await.unwrap(),"return for fresh source validation after rebuild");
    let state:(i64,String)=sqlx::query_as("SELECT reverted_blocks,last_committed_checkpoint FROM tn10_live_recovery_plans WHERE intent_key=$1")
        .bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
    assert_eq!(state.0,0);
    assert!(state.1.starts_with("summary:"));
    owner.revert_one(&writer,&page).await.unwrap();
    assert!(!writer.has_utxo(&"aa".repeat(32),0).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn timed_out_block_resumes_as_transaction_pages_under_same_owner(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    let bodies = [accepted(0xaa, 0x11, 106, None), accepted(0xbb, 0x11, 106, None)];
    for body in &bodies { writer.persist_tx(body).await.unwrap(); }
    let key = "live_write_intent:testnet-10:page-removal";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key).execute(&pool).await.unwrap();
    let owner = PagedRecoveryOwner::claim(&pool,key,&["11".repeat(32)]).await.unwrap();
    let page = StagedRecoveryBlock {
        impact: writer.recovery_block_impact(&"11".repeat(32)).await.unwrap(),
        blue_score:106, source_is_chain_block:false,
    };
    owner.stage_blocks(&pool,&[page.clone()]).await.unwrap();
    owner.stage_transactions(&pool,&bodies).await.unwrap();
    owner.finish_discovery(&pool).await.unwrap();
    // Simulate a statement whose work exceeds its DB budget only when the
    // whole block is removed. The same transaction-sized operation succeeds.
    sqlx::raw_sql("CREATE FUNCTION reject_wide_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF (SELECT count(*) FROM removed_outputs)>1 THEN
            RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='wide removal exceeded database budget';
        END IF; RETURN NULL; END $$;
        CREATE TRIGGER reject_wide_removal AFTER DELETE ON covenant_utxos
        REFERENCING OLD TABLE AS removed_outputs FOR EACH STATEMENT EXECUTE FUNCTION reject_wide_removal();")
        .execute(&pool).await.unwrap();
    owner.revert_one(&writer,&page).await.unwrap();
    assert!(writer.has_utxo(&"aa".repeat(32),0).await.unwrap());
    assert!(writer.has_utxo(&"bb".repeat(32),0).await.unwrap());
    let state:(bool,i64,Option<i64>)=sqlx::query_as("SELECT exclusive_writes,reverted_blocks,last_committed_step_at_ms FROM tn10_live_recovery_plans WHERE intent_key=$1")
        .bind(key).fetch_one(&pool).await.unwrap();
    assert_eq!(state,(true,0,None),"conversion is not canonical progress");
    // A crash after conversion must leave a durable transaction frontier.
    sqlx::query("UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key=$1")
        .bind(key).execute(&pool).await.unwrap();
    let resumed = PagedRecoveryOwner::claim(&pool,key,&[]).await.unwrap();
    assert!(owner.revert_one(&writer,&page).await.is_err(),"expired owner stays fenced");
    for _ in 0..3 {
        let next=resumed.ready_removals(&pool).await.unwrap();
        assert_eq!(next.len(),1);
        assert!(next[0].impact.transaction_ids.len()<=1);
        resumed.revert_one(&writer,&next[0]).await.unwrap();
    }
    assert!(resumed.ready_removals(&pool).await.unwrap().is_empty());
    let state:(i64,Option<String>)=sqlx::query_as("SELECT reverted_blocks,last_committed_checkpoint FROM tn10_live_recovery_plans WHERE intent_key=$1")
        .bind(key).fetch_one(&pool).await.unwrap();
    assert_eq!(state,(1,Some(format!("remove-block:{}","11".repeat(32)))));
    assert!(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM indexer_state WHERE key=$1)")
        .bind(key).fetch_one(&pool).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn three_smallest_step_failures_are_durable_and_heartbeats_are_not_progress(pool: PgPool) {
    let (writer,owner,page)=removal_timeout_fixture(&pool).await;
    sqlx::raw_sql("CREATE FUNCTION cancel_smallest_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='smallest removal cannot finish'; END $$;
        CREATE TRIGGER cancel_smallest_removal BEFORE DELETE ON covenant_utxos
        FOR EACH ROW EXECUTE FUNCTION cancel_smallest_removal();")
        .execute(&pool).await.unwrap();
    for attempt in 1..=3 {
        let error=owner.revert_one(&writer,&page).await.unwrap_err();
        if attempt<3 { assert_eq!(error.downcast_ref::<super::super::RecoveryRemovalRetry>().unwrap().attempt,attempt); }
        else { assert!(error.to_string().contains("blocked at smallest removal step")); }
        owner.heartbeat(&pool).await.unwrap();
        let state:(i32,Option<i64>,i64)=sqlx::query_as("SELECT b.removal_failures,p.last_committed_step_at_ms,p.reverted_blocks FROM tn10_live_recovery_plans p JOIN tn10_live_recovery_blocks b USING(intent_key) WHERE p.intent_key=$1")
            .bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
        assert_eq!(state,(attempt,None,0));
        assert!(writer.has_utxo(&"aa".repeat(32),0).await.unwrap());
    }
    sqlx::query("DROP TRIGGER cancel_smallest_removal ON covenant_utxos").execute(&pool).await.unwrap();
    owner.revert_one(&writer,&page).await.unwrap();
    let failures:i32=sqlx::query_scalar("SELECT removal_failures FROM tn10_live_recovery_blocks WHERE intent_key=$1")
        .bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
    assert_eq!(failures,0,"successful checkpoint clears failures");
}

#[sqlx::test(migrations = "./migrations")]
async fn lost_removal_response_reconciles_committed_checkpoint(pool: PgPool) {
    let (writer,owner,page)=removal_timeout_fixture(&pool).await;
    owner.revert_one(&writer,&page).await.unwrap();
    let checkpoint:Option<i64>=sqlx::query_scalar("SELECT last_committed_step_at_ms FROM tn10_live_recovery_plans WHERE intent_key=$1")
        .bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
    assert!(checkpoint.is_some());
    owner.reconcile_failed_removal(&writer,&page,&anyhow::anyhow!("lost commit response")).await.unwrap();
    owner.heartbeat(&pool).await.unwrap();
    let state:(i64,Option<i64>)=sqlx::query_as("SELECT reverted_blocks,last_committed_step_at_ms FROM tn10_live_recovery_plans WHERE intent_key=$1")
        .bind(&owner.intent_key).fetch_one(&pool).await.unwrap();
    assert_eq!(state,(1,checkpoint),"reconciliation and heartbeat must not fabricate progress");
}

#[sqlx::test(migrations = "./migrations")]
async fn leaf_removal_and_checkpoint_commit_together(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    writer
        .persist_tx(&accepted(0xaa, 0x11, 106, None))
        .await
        .unwrap();
    writer
        .persist_tx(&accepted(0xbb, 0x22, 125, Some(0xaa)))
        .await
        .unwrap();
    let key = "live_write_intent:testnet-10:ordered";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,$2,1)")
        .bind(key)
        .bind(serde_json::json!({"transactions": [{"transaction_id": "aa"}]}))
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    let parent = StagedRecoveryBlock {
        impact: writer
            .recovery_block_impact(&"11".repeat(32))
            .await
            .unwrap(),
        blue_score: 106,
        source_is_chain_block: false,
    };
    owner.stage_blocks(&pool, &[parent.clone()]).await.unwrap();
    let child = StagedRecoveryBlock {
        impact: writer
            .recovery_block_impact(&"22".repeat(32))
            .await
            .unwrap(),
        blue_score: 125,
        source_is_chain_block: true,
    };
    owner.stage_blocks(&pool, &[child.clone()]).await.unwrap();
    assert!(owner.finish_discovery(&pool).await.is_err());
    let parent_body = accepted(0xaa, 0x11, 106, None);
    let child_body = accepted(0xbb, 0x22, 125, Some(0xaa));
    owner
        .stage_transactions(&pool, &[parent_body.clone(), child_body.clone()])
        .await
        .unwrap();
    let mut observed_again = parent_body.clone();
    observed_again.block_hash.push("99".repeat(32));
    owner
        .stage_transactions(&pool, &[observed_again])
        .await
        .unwrap();
    let mut changed_body = parent_body.clone();
    changed_body.outputs[0].amount = 2;
    assert!(owner
        .stage_transactions(&pool, &[changed_body])
        .await
        .is_err());
    owner.finish_discovery(&pool).await.unwrap();
    assert_eq!(
        owner.ready_removals(&pool).await.unwrap()[0]
            .impact
            .block_hash,
        child.impact.block_hash
    );
    assert!(owner.revert_one(&writer, &parent).await.is_err());
    assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    owner.revert_one(&writer, &child).await.unwrap();
    assert!(!writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    assert_eq!(
        owner.ready_removals(&pool).await.unwrap()[0]
            .impact
            .block_hash,
        parent.impact.block_hash
    );
    owner.revert_one(&writer, &parent).await.unwrap();
    assert!(!writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    // An uncertain commit response can be retried after inspecting the saved
    // checkpoint; a committed removal is a no-op.
    owner.revert_one(&writer, &child).await.unwrap();
    let checkpoint: (i64, i64) = sqlx::query_as(
        "SELECT discovered_blocks,reverted_blocks FROM tn10_live_recovery_plans WHERE intent_key=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(checkpoint, (2, 2));
    assert!(owner.ready_removals(&pool).await.unwrap().is_empty());
    assert!(owner.finish_replay(&pool).await.is_err());
    owner.finish_removal(&pool).await.unwrap();
    assert_eq!(
        replay_ready(&owner, &pool).await.unwrap()[0].transaction_id,
        parent_body.transaction_id
    );
    writer
        .replay_paged_recovery_tx(&owner, &parent_body)
        .await
        .unwrap();
    assert_eq!(
        replay_ready(&owner, &pool).await.unwrap()[0].transaction_id,
        child_body.transaction_id
    );
    writer
        .replay_paged_recovery_tx(&owner, &child_body)
        .await
        .unwrap();
    assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    assert!(replay_ready(&owner, &pool).await.unwrap().is_empty());
    writer
        .replay_paged_recovery_tx(&owner, &child_body)
        .await
        .unwrap();
    let replayed: i64 = sqlx::query_scalar(
        "SELECT replayed_transactions FROM tn10_live_recovery_plans WHERE intent_key=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replayed, 2);
    owner.finish_replay(&pool).await.unwrap();
    assert_eq!(
        owner.verification_blocks(&pool, None).await.unwrap().len(),
        2
    );
    assert_eq!(
        owner
            .verification_transactions(&pool, None)
            .await
            .unwrap()
            .len(),
        2
    );
    owner.mark_complete(&pool).await.unwrap();
    assert_eq!(owner.phase(&pool).await.unwrap(), "complete");
    assert_eq!(
        owner
            .verification_transactions(&pool, None)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn single_block_pages_fence_writers_and_resume_after_owner_loss(pool: PgPool) {
    exercise_single_block_pages(pool, 258).await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "release-mode writer budget regression"]
async fn single_block_budget_regression_2048_transactions(pool: PgPool) {
    exercise_single_block_pages(pool, 2048).await;
}

async fn exercise_single_block_pages(pool: PgPool, count: u64) {
    let writer = PgPersister::new(pool.clone());
    let old_hash = format!("{:064x}", 1000);
    let mut bodies = Vec::new();
    for n in 1..=count {
        let id = format!("{n:064x}");
        let tx = RestTransaction {
            transaction_id: id.clone(),
            is_accepted: true,
            accepting_block_hash: Some(old_hash.clone()),
            accepting_block_blue_score: Some(100),
            accepting_block_time: Some(1000),
            outputs: vec![RestTxOutput {
                transaction_id: id.clone(),
                index: 0,
                amount: 1,
                script_public_key: format!("aa20{id}87"),
                ..Default::default()
            }],
            ..Default::default()
        };
        writer.persist_tx(&tx).await.unwrap();
        let mut canonical = tx;
        canonical.accepting_block_hash = Some(format!("{:064x}", 1001));
        canonical.accepting_block_blue_score = Some(99);
        bodies.push(canonical);
    }
    assert!(writer
        .recovery_block_impact(&old_hash)
        .await
        .unwrap_err()
        .is::<super::recovery_impact::RecoveryImpactLimit>());
    let key = "live_write_intent:testnet-10:single-block-pages";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &[old_hash.clone()])
        .await
        .unwrap();
    owner
        .stage_chunked_block(&writer, &old_hash, 100, false)
        .await
        .unwrap();
    let staged: i64 = sqlx::query_scalar("SELECT count(*) FROM tn10_live_recovery_block_items WHERE intent_key=$1 AND kind='transaction'")
        .bind(key).fetch_one(&pool).await.unwrap();
    assert_eq!(staged, count as i64);
    assert!(
        writer.persist_tx(&bodies[0]).await.is_err(),
        "independent repair must not race a partial block"
    );
    for page in bodies.chunks(32) {
        owner.stage_transactions(&pool, page).await.unwrap();
    }
    owner.finish_discovery(&pool).await.unwrap();
    let page = owner.ready_removals(&pool).await.unwrap().remove(0);
    assert_eq!(page.impact.transaction_ids.len(), 1);
    owner.revert_one(&writer, &page).await.unwrap();
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        remaining,
        count as i64 - 1,
        "one page removes one transaction's effects"
    );
    // A committed page must not be applied twice after a lost response.
    assert!(owner.revert_one(&writer, &page).await.is_err());
    sqlx::query("UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key=$1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let replacement = PagedRecoveryOwner::claim(&pool, key, &[]).await.unwrap();
    assert!(owner.ready_removals(&pool).await.is_err());
    assert!(writer.persist_tx(&bodies[0]).await.is_err());
    let mut pages = 0;
    loop {
        let ready = replacement.ready_removals(&pool).await.unwrap();
        if ready.is_empty() {
            break;
        }
        for next in ready {
            assert!(next.impact.transaction_ids.len() <= 1);
            replacement.revert_one(&writer, &next).await.unwrap();
            pages += 1;
        }
    }
    assert_eq!(
        pages, count,
        "remaining transactions and one final block checkpoint"
    );
    replacement.finish_removal(&pool).await.unwrap();
    for body in &bodies {
        writer
            .replay_paged_recovery_tx(&replacement, body)
            .await
            .unwrap();
    }
    replacement.finish_replay(&pool).await.unwrap();
    let effects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE created_block=$1")
            .bind(hex::decode(format!("{:064x}", 1001)).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(effects, count as i64);
    let retained: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM indexer_state WHERE key=$1)")
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        retained,
        "checkpoint completion must never acknowledge the live journal"
    );
    assert!(writer.persist_tx(&bodies[0]).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn chunked_same_block_spender_precedes_genesis_and_preserves_summaries(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    let hash = "aa".repeat(32);
    let root_id = "01".repeat(32);
    let child_id = "ff".repeat(32);
    let script = format!("aa20{root_id}87");
    let root = RestTransaction {
        transaction_id: root_id.clone(),
        is_accepted: true,
        accepting_block_hash: Some(hash.clone()),
        accepting_block_blue_score: Some(100),
        accepting_block_time: Some(1000),
        outputs: vec![RestTxOutput {
            transaction_id: root_id.clone(),
            index: 0,
            amount: 10,
            script_public_key: script.clone(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let child = RestTransaction {
        transaction_id: child_id.clone(),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: root_id.clone(),
            previous_outpoint_index: "0".into(),
            previous_outpoint_script: Some(script.clone()),
            previous_outpoint_amount: Some(10),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: child_id.clone(),
            index: 0,
            amount: 10,
            script_public_key: script,
            ..Default::default()
        }],
        ..root.clone()
    };
    writer.persist_tx(&root).await.unwrap();
    writer.persist_tx(&child).await.unwrap();
    let snapshot = "SELECT jsonb_agg(jsonb_build_array(encode(covenant_id,'hex'),active_utxos,total_amount_sompi,encode(latest_active_txid,'hex')) ORDER BY covenant_id) FROM covenant_summaries";
    let before: serde_json::Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
    let key = "live_write_intent:testnet-10:same-block";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &[hash.clone()])
        .await
        .unwrap();
    owner
        .stage_chunked_block(&writer, &hash, 100, false)
        .await
        .unwrap();
    let mut canonical = vec![root, child];
    for tx in &mut canonical {
        tx.accepting_block_hash = Some("bb".repeat(32));
        tx.accepting_block_blue_score = Some(99);
    }
    owner.stage_transactions(&pool, &canonical).await.unwrap();
    owner.finish_discovery(&pool).await.unwrap();
    let first = owner.ready_removals(&pool).await.unwrap().remove(0);
    assert_eq!(first.impact.transaction_ids, vec![child_id]);
    owner.revert_one(&writer, &first).await.unwrap();
    let active: (i64, i64) =
        sqlx::query_as("SELECT active_utxos,total_amount_sompi::bigint FROM covenant_summaries")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        active,
        (1, 10),
        "removing a same-block spend reactivates its parent before the next page"
    );
    let parent = owner.ready_removals(&pool).await.unwrap().remove(0);
    assert_eq!(parent.impact.transaction_ids, vec![root_id]);
    owner.revert_one(&writer, &parent).await.unwrap();
    let final_page = owner.ready_removals(&pool).await.unwrap().remove(0);
    assert!(final_page.impact.transaction_ids.is_empty());
    owner.revert_one(&writer, &final_page).await.unwrap();
    owner.finish_removal(&pool).await.unwrap();
    for tx in &canonical {
        writer.replay_paged_recovery_tx(&owner, tx).await.unwrap();
    }
    let after: serde_json::Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
    assert_eq!(before, after);
}

#[sqlx::test(migrations = "./migrations")]
async fn footprint_growth_reopens_discovery_without_removing_effects(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    let parent = accepted(0xaa, 0x11, 106, None);
    writer.persist_tx(&parent).await.unwrap();
    let stale = StagedRecoveryBlock {
        impact: writer
            .recovery_block_impact(&"11".repeat(32))
            .await
            .unwrap(),
        blue_score: 106,
        source_is_chain_block: false,
    };
    // A repair write lands after the footprint read, before the recovery fence.
    let child = accepted(0xbb, 0x22, 125, Some(0xaa));
    writer.persist_tx(&child).await.unwrap();
    let key = "live_write_intent:testnet-10:expanded-descendant";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    owner.stage_blocks(&pool, &[stale.clone()]).await.unwrap();
    owner
        .stage_transactions(&pool, &[parent.clone()])
        .await
        .unwrap();
    owner.finish_discovery(&pool).await.unwrap();
    assert!(owner.revert_one(&writer, &stale).await.is_err());
    let phase: String =
        sqlx::query_scalar("SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1")
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        phase, "discover",
        "retry must discover the new child, not repeat the frozen plan"
    );
    assert!(writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    assert!(
        owner.heartbeat(&pool).await.is_err(),
        "expansion releases only its own fenced lease"
    );
    assert!(
        writer
            .persist_tx(&accepted(0xcc, 0x33, 130, Some(0xbb)))
            .await
            .is_err(),
        "ordinary writes must not expand the closure between owners"
    );
    assert!(!writer.has_utxo(&"cc".repeat(32), 0).await.unwrap());
    let resumed = PagedRecoveryOwner::claim(&pool, key, &[]).await.unwrap();
    assert_eq!(
        resumed.pending_blocks(&pool).await.unwrap(),
        vec!["22".repeat(32)]
    );
    assert!(resumed.finish_discovery(&pool).await.is_err());
    let discovered = StagedRecoveryBlock {
        impact: writer
            .recovery_block_impact(&"22".repeat(32))
            .await
            .unwrap(),
        blue_score: 125,
        source_is_chain_block: true,
    };
    resumed.stage_blocks(&pool, &[discovered]).await.unwrap();
    assert!(
        resumed.finish_discovery(&pool).await.is_err(),
        "new source bodies are still required"
    );
    resumed
        .stage_transactions(&pool, &[child.clone()])
        .await
        .unwrap();
    resumed.finish_discovery(&pool).await.unwrap();
    let leaf = resumed.ready_removals(&pool).await.unwrap().remove(0);
    assert_eq!(leaf.impact.block_hash, "22".repeat(32));
    resumed.revert_one(&writer, &leaf).await.unwrap();
    let root = resumed.ready_removals(&pool).await.unwrap().remove(0);
    resumed.revert_one(&writer, &root).await.unwrap();
    resumed.finish_removal(&pool).await.unwrap();
    writer
        .replay_paged_recovery_tx(&resumed, &parent)
        .await
        .unwrap();
    writer
        .replay_paged_recovery_tx(&resumed, &child)
        .await
        .unwrap();
    resumed.finish_replay(&pool).await.unwrap();
    let intent_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM indexer_state WHERE key=$1)")
            .bind(key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        intent_exists,
        "only the supervisor may acknowledge the retained journal"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn footprint_growth_requires_new_transaction_source_before_retry(pool: PgPool) {
    let writer = PgPersister::new(pool.clone());
    let first = accepted(0xaa, 0x11, 106, None);
    writer.persist_tx(&first).await.unwrap();
    let stale = StagedRecoveryBlock {
        impact: writer
            .recovery_block_impact(&"11".repeat(32))
            .await
            .unwrap(),
        blue_score: 106,
        source_is_chain_block: false,
    };
    let second = accepted(0xbb, 0x11, 106, None);
    writer.persist_tx(&second).await.unwrap();
    let key = "live_write_intent:testnet-10:expanded-transactions";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    owner.stage_blocks(&pool, &[stale.clone()]).await.unwrap();
    owner.stage_transactions(&pool, &[first]).await.unwrap();
    owner.finish_discovery(&pool).await.unwrap();
    assert!(owner.revert_one(&writer, &stale).await.is_err());
    let resumed = PagedRecoveryOwner::claim(&pool, key, &[]).await.unwrap();
    assert_eq!(
        resumed.pending_transactions(&pool).await.unwrap(),
        vec!["bb".repeat(32)]
    );
    assert!(resumed.finish_discovery(&pool).await.is_err());
    assert!(writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    resumed.stage_transactions(&pool, &[second]).await.unwrap();
    resumed.finish_discovery(&pool).await.unwrap();
    let page = resumed.ready_removals(&pool).await.unwrap().remove(0);
    assert_eq!(page.impact.transaction_ids.len(), 2);
    resumed.revert_one(&writer, &page).await.unwrap();
}

// Tests that exercise whole recovery can explicitly drive bounded preparation.
pub(super) async fn replay_ready(owner: &PagedRecoveryOwner, pool: &PgPool) -> Result<Vec<RestTransaction>> {
    loop {
        match owner.pending_replay(pool).await? {
            RecoveryReplayPage::Preparing => tokio::task::yield_now().await,
            RecoveryReplayPage::Ready(rows) => return Ok(rows),
        }
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn journal_digest_backfills_existing_large_intent_and_tracks_updates(pool: PgPool) {
    let key = "live_write_intent:testnet-10:digest";
    // Simulate an existing retained journal before the additive migration.
    sqlx::query("ALTER TABLE indexer_state DROP COLUMN value_sha256")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,jsonb_build_object('padding',repeat('x',4194304)),1)")
        .bind(key).execute(&pool).await.unwrap();
    let mut migration = pool.begin().await.unwrap();
    sqlx::raw_sql(include_str!("../../migrations/20261114080000_recovery_intent_digest.sql"))
        .execute(&mut *migration).await.unwrap();
    migration.commit().await.unwrap();
    let identical: bool = sqlx::query_scalar("SELECT value_sha256=pg_catalog.sha256(value::text::bytea) FROM indexer_state WHERE key=$1")
        .bind(key).fetch_one(&pool).await.unwrap();
    assert!(identical);
    let owner = PagedRecoveryOwner::claim(&pool,key,&["11".repeat(32)]).await.unwrap();
    owner.heartbeat(&pool).await.unwrap();
    assert!(sqlx::query("UPDATE indexer_state SET value_sha256=decode(repeat('00',32),'hex') WHERE key=$1")
        .bind(key).execute(&pool).await.is_err(),"caller must not forge the generated fingerprint");
    let mut rollback = pool.begin().await.unwrap();
    sqlx::query("UPDATE indexer_state SET value='{}'::jsonb WHERE key=$1")
        .bind(key).execute(&mut *rollback).await.unwrap();
    rollback.rollback().await.unwrap();
    owner.heartbeat(&pool).await.unwrap();
    sqlx::query("UPDATE indexer_state SET value='{}'::jsonb WHERE key=$1")
        .bind(key).execute(&pool).await.unwrap();
    assert!(owner.heartbeat(&pool).await.is_err(),"committed journal change must still fence the old owner");
}

#[sqlx::test(migrations = "./migrations")]
async fn cached_journal_digest_preserves_shared_lock_fence(pool: PgPool) {
    let key = "live_write_intent:testnet-10:digest-lock";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(key).execute(&pool).await.unwrap();
    let owner = PagedRecoveryOwner::claim(&pool,key,&["11".repeat(32)]).await.unwrap();
    let mut step = pool.begin().await.unwrap();
    lock_intent_and_owner(&mut step,&owner).await.unwrap();
    let mut other = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='50ms'").execute(&mut *other).await.unwrap();
    let error = sqlx::query("UPDATE indexer_state SET value='[]'::jsonb WHERE key=$1")
        .bind(key).execute(&mut *other).await.unwrap_err();
    assert_eq!(error.as_database_error().and_then(|e|e.code()).as_deref(),Some("55P03"));
    other.rollback().await.unwrap();
    step.commit().await.unwrap();
    sqlx::query("DELETE FROM indexer_state WHERE key=$1").bind(key).execute(&pool).await.unwrap();
    assert!(owner.heartbeat(&pool).await.is_err(),"deleted journal must fence the old owner");
}
