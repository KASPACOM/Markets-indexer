use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{Persister, PgPersister};

async fn seed_parents(pool: &PgPool) -> PgPersister {
    let writer = PgPersister::new(pool.clone());
    for json in [
        include_str!("fixtures/snapshot-start-tn10/parent-0.json"),
        include_str!("fixtures/snapshot-start-tn10/parent-1.json"),
    ] {
        let tx: RestTransaction = serde_json::from_str(json).unwrap();
        writer.persist_tx(&tx).await.unwrap();
    }
    writer
}

fn start_fixture() -> RestTransaction {
    serde_json::from_str(include_str!("fixtures/snapshot-start-tn10/start.json")).unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_start_persists_genesis_and_controller_successor(pool: PgPool) {
    let writer = seed_parents(&pool).await;
    let tx = start_fixture();
    writer.persist_tx(&tx).await.unwrap();
    let state: serde_json::Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid = decode($1, 'hex') AND vout = 1",
    )
    .bind(&tx.transaction_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        state["tokenId"],
        "584b5120436111b6a77cf4e81c1cfaf310068613b9e031199c5bbbb824621a62"
    );
    assert_eq!(state["claimsProcessed"], "0");
    let reserve: serde_json::Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid = decode($1, 'hex') AND vout = 0",
    )
    .bind(&tx.transaction_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        reserve["owner"],
        "211eedb8f452c6bfb236ba148b3380da874f3b9a1a1fdbfe06d06d64a255e387"
    );
    assert_eq!(reserve["amount"], state["remainingAmount"]);
    writer.persist_tx(&tx).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_start_rejects_unverified_outputs_and_rolls_back(pool: PgPool) {
    let writer = seed_parents(&pool).await;
    let original: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/snapshot-start-tn10/start.json")).unwrap();
    for case in [
        "missing",
        "duplicate",
        "extra",
        "wrong_authorizer",
        "wrong_genesis",
    ] {
        let mut value = original.clone();
        match case {
            "missing" => {
                value["outputs"].as_array_mut().unwrap().remove(1);
            }
            "duplicate" | "extra" => {
                let mut output = value["outputs"][1].clone();
                output["index"] = serde_json::json!(3);
                if case == "extra" {
                    output["covenant_id"] = serde_json::json!("ff".repeat(32));
                }
                value["outputs"].as_array_mut().unwrap().push(output);
            }
            "wrong_authorizer" => {
                value["outputs"][1]["covenant_authorizing_input"] = serde_json::json!(0)
            }
            "wrong_genesis" => {
                value["outputs"][0]["covenant_id"] = serde_json::json!("ff".repeat(32))
            }
            _ => unreachable!(),
        }
        let tx: RestTransaction = serde_json::from_value(value).unwrap();
        assert!(writer.persist_tx(&tx).await.is_err(), "accepted {case}");
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE txid = decode($1, 'hex')",
        )
        .bind(&tx.transaction_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 0, "partial output state for {case}");
    }
    // Every rejected variant rolled back the parent spends as well.
    writer.persist_tx(&start_fixture()).await.unwrap();
}
