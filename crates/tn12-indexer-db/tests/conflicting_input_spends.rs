use tn12_indexer_core::{RestTransaction, RestTxInput};
use tn12_indexer_db::{persist::PersistedInputSpend, Persister, PgPersister, PgPool};

#[sqlx::test(migrations = "./migrations")]
async fn recovery_finds_only_different_persisted_spenders(pool: PgPool) {
    sqlx::raw_sql(
        "INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
         VALUES (decode(repeat('aa',32),'hex'),100,0,ARRAY[]::bytea[],1000,true,1000),
                (decode(repeat('66',32),'hex'),106,0,ARRAY[]::bytea[],1060,true,1060);
         INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,
                                    state,created_block,spent_block,spent_by_txid,status)
         VALUES (decode(repeat('88',32),'hex'),0,NULL,'test',1,decode('51','hex'),NULL,
                 decode(repeat('aa',32),'hex'),decode(repeat('66',32),'hex'),
                 decode(repeat('77',32),'hex'),'spent');",
    )
    .execute(&pool)
    .await
    .unwrap();

    let writer = PgPersister::new(pool.clone());
    assert_eq!(writer.indexed_block_transaction_ids(&"66".repeat(32)).await.unwrap(),
        vec!["77".repeat(32)]);
    let moved = RestTransaction {
        transaction_id: "88".repeat(32),
        is_accepted: true,
        accepting_block_hash: Some("22".repeat(32)),
        ..Default::default()
    };
    assert_eq!(writer.stale_persisted_acceptances(&[moved.clone()]).await.unwrap(),
        vec![PersistedInputSpend {
            spender_txid: "88".repeat(32),
            block_hash: "aa".repeat(32),
            block_blue_score: 100,
        }]);
    let same_block = RestTransaction { accepting_block_hash: Some("aa".repeat(32)), ..moved };
    assert!(writer.stale_persisted_acceptances(&[same_block]).await.unwrap().is_empty());
    let incoming = RestTransaction {
        transaction_id: "11".repeat(32),
        is_accepted: true,
        inputs: vec![RestTxInput {
            previous_outpoint_hash: "88".repeat(32),
            previous_outpoint_index: "0".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        writer.conflicting_input_spends(&[incoming.clone()]).await.unwrap(),
        vec![PersistedInputSpend {
            spender_txid: "77".repeat(32),
            block_hash: "66".repeat(32),
            block_blue_score: 106,
        }]
    );

    let same_spender = RestTransaction {
        transaction_id: "77".repeat(32),
        ..incoming.clone()
    };
    assert!(writer.conflicting_input_spends(&[same_spender]).await.unwrap().is_empty());
    let rejected = RestTransaction {
        is_accepted: false,
        ..incoming.clone()
    };
    assert!(writer.conflicting_input_spends(&[rejected]).await.unwrap().is_empty());
    sqlx::query(
        "UPDATE covenant_utxos SET status='active',spent_block=NULL,spent_by_txid=NULL
         WHERE txid=decode(repeat('88',32),'hex') AND vout=0",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(writer.conflicting_input_spends(&[incoming]).await.unwrap().is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn removed_block_with_indexed_descendant_fails_closed(pool: PgPool) {
    sqlx::raw_sql(
        "INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms)
         VALUES (decode(repeat('66',32),'hex'),106,0,ARRAY[]::bytea[],1060,true,1060),
                (decode(repeat('aa',32),'hex'),110,0,ARRAY[]::bytea[],1100,true,1100);
         INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,
                                    state,created_block,spent_block,spent_by_txid,status)
         VALUES (decode(repeat('88',32),'hex'),0,NULL,'test',1,decode('51','hex'),NULL,
                 decode(repeat('66',32),'hex'),decode(repeat('aa',32),'hex'),
                 decode(repeat('77',32),'hex'),'spent');",
    )
    .execute(&pool).await.unwrap();
    let writer = PgPersister::new(pool);
    assert!(writer.indexed_block_transaction_ids(&"66".repeat(32)).await.is_err());
}
