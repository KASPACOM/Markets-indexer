use super::*;
use crate::Persister;
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};

fn transaction(txid: u8, block: u8, score: u64, parent: Option<u8>) -> RestTransaction {
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

async fn fixture(pool: &sqlx::PgPool) -> (PgPersister, Vec<RecoveryBlockImpact>) {
    let writer = PgPersister::new(pool.clone());
    writer
        .persist_tx(&transaction(0xaa, 0x11, 106, None))
        .await
        .unwrap();
    writer
        .persist_tx(&transaction(0xbb, 0x22, 125, Some(0xaa)))
        .await
        .unwrap();
    let child = writer
        .recovery_block_impact(&"22".repeat(32))
        .await
        .unwrap();
    let parent = writer
        .recovery_block_impact(&"11".repeat(32))
        .await
        .unwrap();
    assert!(parent.descendants.contains(&"22".repeat(32)));
    (writer, vec![child, parent])
}

async fn remove(writer: &PgPersister, impacts: &[RecoveryBlockImpact]) -> Result<Vec<RevertStats>> {
    let hashes = impacts
        .iter()
        .map(|i| hex::decode(&i.block_hash).unwrap())
        .collect::<Vec<_>>();
    // Test transaction semantics independently of hosted-runner wall-clock load.
    writer
        .revert_blocks_locked_checked(&hashes, Some(impacts))
        .await
}

#[sqlx::test(migrations = "./migrations")]
async fn slow_atomic_removal_finishes_without_wall_clock_cancellation(pool: sqlx::PgPool) {
    let writer = PgPersister::new(pool.clone());
    writer
        .persist_tx(&transaction(0xaa, 0x11, 106, None))
        .await
        .unwrap();
    let impact = writer.recovery_block_impact(&"11".repeat(32)).await.unwrap();
    let journal = "live_write_intent:testnet-10:slow-atomic-removal";
    sqlx::query("INSERT INTO indexer_state(key,value,updated_at_ms) VALUES($1,'{}',1)")
        .bind(journal)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE FUNCTION delay_atomic_recovery_removal() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF OLD.hash = decode(repeat('11',32),'hex') THEN
             PERFORM pg_sleep(0.45);
           END IF;
           RETURN OLD;
         END $$;
         CREATE TRIGGER delay_atomic_recovery_removal BEFORE DELETE ON blocks
         FOR EACH ROW EXECUTE FUNCTION delay_atomic_recovery_removal();",
    )
    .execute(&pool)
    .await
    .unwrap();

    let started = std::time::Instant::now();
    let stats = writer.remove_recovery_impact(&[impact]).await.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(450));
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].blocks_removed, 1);
    assert!(!writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM indexer_state WHERE key=$1)",
    )
    .bind(journal)
    .fetch_one(&pool)
    .await
    .unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn dependent_spend_is_recovered_without_erasing_its_final_acceptance(pool: sqlx::PgPool) {
    let (writer, impacts) = fixture(&pool).await;
    let old = writer
        .indexed_block_transaction_ids(&"11".repeat(32))
        .await
        .unwrap_err();
    assert!(old.to_string().contains("indexed descendant spends"));
    remove(&writer, &impacts).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_utxos")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    // Replaying the journal after removal (including a restart here) recreates
    // the parent at its new acceptance and the still-canonical child spend.
    writer
        .persist_tx(&transaction(0xaa, 0x33, 105, None))
        .await
        .unwrap();
    writer
        .persist_tx(&transaction(0xbb, 0x22, 125, Some(0xaa)))
        .await
        .unwrap();
    writer
        .persist_tx(&transaction(0xbb, 0x22, 125, Some(0xaa)))
        .await
        .unwrap();
    let parent: (Vec<u8>, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT created_block,status,spent_by_txid FROM covenant_utxos WHERE txid=$1 AND vout=0",
    )
    .bind(vec![0xaau8; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        parent,
        (vec![0x33; 32], "spent".into(), Some(vec![0xbb; 32]))
    );
    let child: (Vec<u8>, String) =
        sqlx::query_as("SELECT created_block,status FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(vec![0xbbu8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(child, (vec![0x22; 32], "active".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_descendant_is_rejected_before_any_removal(pool: sqlx::PgPool) {
    let (writer, impacts) = fixture(&pool).await;
    assert!(remove(&writer, &impacts[1..])
        .await
        .unwrap_err()
        .is::<RecoveryReplanRequired>());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_utxos")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn new_descendant_after_discovery_retains_the_whole_footprint(pool: sqlx::PgPool) {
    let (writer, impacts) = fixture(&pool).await;
    writer
        .persist_tx(&transaction(0xcc, 0x44, 135, Some(0xbb)))
        .await
        .unwrap();
    assert!(remove(&writer, &impacts)
        .await
        .unwrap_err()
        .is::<RecoveryReplanRequired>());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_utxos")
            .fetch_one(&pool)
            .await
            .unwrap(),
        3
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn new_sibling_after_discovery_is_not_silently_removed(pool: sqlx::PgPool) {
    let (writer, impacts) = fixture(&pool).await;
    writer
        .persist_tx(&transaction(0xdd, 0x22, 125, None))
        .await
        .unwrap();
    assert!(remove(&writer, &impacts)
        .await
        .unwrap_err()
        .is::<RecoveryReplanRequired>());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_utxos")
            .fetch_one(&pool)
            .await
            .unwrap(),
        3
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn genesis_fk_cascade_is_included_even_without_a_spend_edge(pool: sqlx::PgPool) {
    let (writer, _) = fixture(&pool).await;
    sqlx::query("UPDATE covenant_utxos SET status='active',spent_block=NULL,spent_by_txid=NULL WHERE txid=$1")
        .bind(vec![0xaau8;32]).execute(&pool).await.unwrap();
    let impact = writer
        .recovery_block_impact(&"11".repeat(32))
        .await
        .unwrap();
    assert!(impact.descendants.contains(&"22".repeat(32)));
}

#[sqlx::test(migrations = "./migrations")]
async fn action_only_genesis_descendant_still_requires_ordered_removal(pool: sqlx::PgPool) {
    let (writer, _) = fixture(&pool).await;
    sqlx::query("UPDATE covenant_utxos SET status='active',spent_block=NULL,spent_by_txid=NULL WHERE txid=$1")
        .bind(vec![0xaau8;32]).execute(&pool).await.unwrap();
    sqlx::query("DELETE FROM covenant_utxos WHERE txid=$1")
        .bind(vec![0xbbu8;32]).execute(&pool).await.unwrap();
    let parent = writer.recovery_block_impact(&"11".repeat(32)).await.unwrap();
    assert_eq!(parent.descendants, vec!["22".repeat(32)]);
    assert!(remove(&writer, &[parent]).await.unwrap_err().is::<RecoveryReplanRequired>());
    assert!(writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn absent_recovery_root_does_not_include_other_covenants(pool: sqlx::PgPool) {
    let (writer, _) = fixture(&pool).await;
    let absent = writer.recovery_block_impact(&"99".repeat(32)).await.unwrap();
    assert!(absent.transaction_ids.is_empty());
    assert!(absent.descendants.is_empty());
    remove(&writer, &[absent]).await.unwrap();
    assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    let parent = writer.recovery_block_impact(&"11".repeat(32)).await.unwrap();
    assert_eq!(parent.descendants, vec!["22".repeat(32)]);
}
