use super::tests::replay_ready;
use super::*;
use tn12_indexer_core::RestTxInput;

async fn fixture(pool: &PgPool) -> PagedRecoveryOwner {
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES('ready-test','{}',1)")
        .execute(pool)
        .await
        .unwrap();
    let owner = PagedRecoveryOwner::claim(pool, "ready-test", &[])
        .await
        .unwrap();
    sqlx::query("UPDATE tn10_live_recovery_plans SET phase='replay' WHERE intent_key=$1")
        .bind(&owner.intent_key)
        .execute(pool)
        .await
        .unwrap();
    owner
}
async fn add(pool: &PgPool, id: u64, parents: &[u64], accepted: bool) {
    let body = RestTransaction {
        transaction_id: format!("{id:064x}"),
        is_accepted: accepted,
        inputs: parents
            .iter()
            .map(|p| RestTxInput {
                previous_outpoint_hash: format!("{p:064x}"),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    sqlx::query("INSERT INTO tn10_live_recovery_transactions(intent_key,txid,source_body,source_sha256) VALUES('ready-test',$1,$2,decode(repeat('ab',32),'hex'))")
        .bind(decode_hash(&body.transaction_id).unwrap()).bind(serde_json::to_value(body).unwrap()).execute(pool).await.unwrap();
}
async fn checkpoint(pool: &PgPool, id: u64) {
    sqlx::query("UPDATE tn10_live_recovery_transactions SET replayed=TRUE WHERE intent_key='ready-test' AND txid=$1")
        .bind(decode_hash(&format!("{id:064x}")).unwrap()).execute(pool).await.unwrap();
}
async fn count(pool: &PgPool, predicate: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM tn10_live_recovery_transactions WHERE intent_key='ready-test' AND CASE $1::text WHEN 'replay_blockers IS NOT NULL' THEN replay_blockers IS NOT NULL WHEN 'replay_blockers=1' THEN replay_blockers=1 WHEN 'NOT replayed AND replay_blockers=0' THEN NOT replayed AND replay_blockers=0 WHEN 'replayed' THEN replayed ELSE FALSE END")
        .bind(predicate).fetch_one(pool).await.unwrap()
}
async fn reclaim(pool: &PgPool) -> PagedRecoveryOwner {
    sqlx::query(
        "UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key='ready-test'",
    )
    .execute(pool)
    .await
    .unwrap();
    PagedRecoveryOwner::claim(pool, "ready-test", &[])
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_ready_resumes_initialization_and_fanout_after_uncertain_commit(pool: PgPool) {
    let owner = fixture(&pool).await;
    add(&pool, 1000, &[], true).await;
    for id in 1..=300 {
        add(&pool, id, &[1000, 1000, 9999], true).await;
    }
    assert!(owner.prepare_replay_page(&pool).await.unwrap());
    assert_eq!(count(&pool, "replay_blockers IS NOT NULL").await, 32);
    let next = reclaim(&pool).await;
    assert!(owner.prepare_replay_page(&pool).await.is_err());
    assert_eq!(
        replay_ready(&next, &pool).await.unwrap()[0].transaction_id,
        format!("{:064x}", 1000)
    );
    // Rollback must undo both the checkpoint and the release journal.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE tn10_live_recovery_transactions SET replayed=TRUE WHERE intent_key='ready-test' AND txid=decode(lpad(to_hex(1000),64,'0'),'hex')")
        .execute(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert!(!next.release_replay_page(&pool).await.unwrap());
    assert_eq!(count(&pool, "replay_blockers=1").await, 300);
    checkpoint(&pool, 1000).await;
    checkpoint(&pool, 1000).await; // lost commit response, retry is harmless
    assert_eq!(count(&pool, "replay_blockers=1").await, 300);
    assert!(next.release_replay_page(&pool).await.unwrap());
    assert_eq!(count(&pool, "replay_blockers=1").await, 268);
    let resumed = reclaim(&pool).await;
    let ready = match resumed.pending_replay(&pool).await.unwrap() {
        RecoveryReplayPage::Ready(rows) => rows,
        RecoveryReplayPage::Preparing => panic!("released children should already be ready"),
    };
    assert_eq!(ready.len(), 32);
    assert_eq!(ready[0].transaction_id, format!("{:064x}", 1));
    assert_eq!(count(&pool, "NOT replayed AND replay_blockers=0").await,64);
    assert_eq!(count(&pool, "replay_blockers=1").await,236);
    while resumed.release_replay_page(&pool).await.unwrap() {}
    assert_eq!(count(&pool, "NOT replayed AND replay_blockers=0").await,300);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM tn10_recovery_replay_edges WHERE intent_key='ready-test'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        600
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_ready_preserves_a_chain_above_256_transactions(pool: PgPool) {
    let owner = fixture(&pool).await;
    for id in 1..=300 {
        let parents=if id==1 { vec![] } else { vec![id-1] };
        add(&pool,id,&parents,true).await;
    }
    for id in 1..=300 {
        let ready = replay_ready(&owner, &pool).await.unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].transaction_id, format!("{id:064x}"));
        checkpoint(&pool, id).await;
    }
    assert!(replay_ready(&owner, &pool).await.unwrap().is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_ready_cycles_and_rejected_staged_parents_fail_closed(pool: PgPool) {
    let owner = fixture(&pool).await;
    add(&pool, 1, &[2], true).await;
    add(&pool, 2, &[1], true).await;
    add(&pool, 3, &[], false).await;
    add(&pool, 4, &[3], true).await;
    assert!(owner
        .pending_replay(&pool)
        .await
        .unwrap_err()
        .to_string()
        .contains("dependencies cannot advance"));
    assert_eq!(count(&pool, "replayed").await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_ready_migration_resumes_old_binary_commits_before_initialization(pool: PgPool) {
    let owner = fixture(&pool).await;
    add(&pool, 1, &[], true).await;
    add(&pool, 2, &[], true).await;
    add(&pool, 3, &[1, 2], true).await;
    checkpoint(&pool, 1).await;
    // Initialization excludes the already committed parent; release must not
    // decrement again and incorrectly unblock the still-dependent child.
    let ready = replay_ready(&owner, &pool).await.unwrap();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].transaction_id, format!("{:064x}", 2));
    assert_eq!(count(&pool, "replay_blockers=1").await, 1);
    checkpoint(&pool, 2).await;
    assert_eq!(
        replay_ready(&owner, &pool).await.unwrap()[0].transaction_id,
        format!("{:064x}", 3)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn replay_selection_returns_preparing_after_one_initialization_page(pool: PgPool) {
    let owner = fixture(&pool).await;
    add(&pool, 1000, &[], true).await;
    for id in 1..=300 {
        add(&pool, id, &[1000], true).await;
    }
    assert!(matches!(
        owner.pending_replay(&pool).await.unwrap(),
        RecoveryReplayPage::Preparing
    ));
    assert_eq!(count(&pool, "replay_blockers IS NOT NULL").await, 32);
    let checkpoint:(Option<i64>,Option<String>)=sqlx::query_as("SELECT last_durable_progress_at_ms,last_durable_checkpoint FROM tn10_live_recovery_plans WHERE intent_key='ready-test'").fetch_one(&pool).await.unwrap();
    assert!(checkpoint.0.is_some());
    assert_eq!(checkpoint.1.as_deref(), Some("replay-prepare-page"));
    let next = reclaim(&pool).await;
    assert!(matches!(
        next.pending_replay(&pool).await.unwrap(),
        RecoveryReplayPage::Preparing
    ));
    assert_eq!(count(&pool, "replay_blockers IS NOT NULL").await, 64);
}

#[sqlx::test(migrations = "./migrations")]
async fn one_release_page_batches_independent_chains_and_leaf_cleanup(pool: PgPool) {
    let owner=fixture(&pool).await;
    for id in 1..=32 { add(&pool,id,&[],true).await; add(&pool,id+100,&[id],true).await; }
    while owner.prepare_replay_page(&pool).await.unwrap() {}
    for id in 1..=32 { checkpoint(&pool,id).await; }
    assert!(owner.release_replay_page(&pool).await.unwrap());
    assert_eq!(count(&pool,"NOT replayed AND replay_blockers=0").await,32);
    assert!(owner.release_replay_page(&pool).await.unwrap()); // clear all exhausted cursors
    assert!(!owner.release_replay_page(&pool).await.unwrap());
    for id in 101..=132 { checkpoint(&pool,id).await; }
    assert!(owner.release_replay_page(&pool).await.unwrap()); // 32 leaves, no edge scans
    assert!(!owner.release_replay_page(&pool).await.unwrap());
}
