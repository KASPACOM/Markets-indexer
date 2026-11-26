//! Accepted TN10 lifecycle replay and reorg checks in an isolated SQLx database.
use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{Persister, PgPersister};
#[sqlx::test(migrations = "./migrations")]
async fn accepted_vesting_replay_closure_and_reorg(pool: PgPool) {
    // The accepted vesting transactions spend canonical KCC20 outputs. Replay
    // their accepted parents first so identity inference never guesses the
    // lineage of a missing P2SH source.
    let parents: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/kcom-vesting/accepted-parents.json")).unwrap();
    let writer = PgPersister::new(pool.clone());
    for tx in &parents {
        assert!(tx.is_accepted);
        writer.persist_tx(tx).await.unwrap();
    }
    for raw in [
        include_str!("fixtures/kcom-vesting/alice-short.json"),
        include_str!("fixtures/kcom-vesting/alice-medium.json"),
        include_str!("fixtures/kcom-vesting/alice-long.json"),
    ] {
        let txs: Vec<RestTransaction> = serde_json::from_str(raw).unwrap();
        let id = hex::decode(txs[0].outputs[0].canonical_covenant_id().unwrap()).unwrap();
        writer.persist_tx(&txs[0]).await.unwrap();
        let initial_status: String =
            sqlx::query_scalar("SELECT classification_status FROM covenants WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(initial_status, "unrevealed");
        for tx in &txs[1..] {
            writer.persist_tx(tx).await.unwrap();
        }
        let classification: (String, String) = sqlx::query_as(
            "SELECT template_name,classification_status FROM covenants WHERE covenant_id=$1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(classification, ("KCOMVesting".into(), "matched".into()));
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active, 0);
        let states:Vec<serde_json::Value>=sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND state IS NOT NULL ORDER BY vout").bind(&id).fetch_all(&pool).await.unwrap();
        assert!(
            states.iter().any(|s| s["released"] == "100"),
            "continuation state missing: {states:?}"
        );
        let actions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        for tx in &txs {
            writer.persist_tx(tx).await.unwrap();
        }
        let replay_actions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(actions, replay_actions);
        let last = txs.last().unwrap();
        writer
            .revert_block(&hex::decode(last.accepting_block_hash.as_ref().unwrap()).unwrap())
            .await
            .unwrap();
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active, 1, "final reorg must restore position");
        let restored: serde_json::Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let expected = if txs.len() == 5 { "137" } else { "100" };
        assert_eq!(restored["released"], expected);

        writer.persist_tx(last).await.unwrap();
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active, 0);
        let final_actions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(actions, final_actions);
    }
}
