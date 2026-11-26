use sqlx::PgPool;
use tn12_indexer_db::repo::kcc20_fee_receipts_page;

const MARKET: &str = "0202020202020202020202020202020202020202020202020202020202020202";

#[sqlx::test(migrations = "./migrations")]
async fn fee_receipt_page_tracks_only_active_entitlements_and_fails_on_bad_value(pool: PgPool) {
    let block = vec![1u8; 32];
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,1,1,ARRAY[]::bytea[],1,true,1)")
        .bind(&block).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms) VALUES(decode($1,'hex'),'fee-market',0,decode($1,'hex'),decode(repeat('02',32),'hex'),0,$2,1)")
        .bind(MARKET).bind(&block).execute(&pool).await.unwrap();
    let spk = [vec![0xaa, 0x20], vec![3; 32], vec![0x87]].concat();
    for (id, p, c, status) in [(4u8, 50_000_000, 50_000_000, "active"),
        (5, 100_000_000, 50_000_000, "active"),
        (6, 50_000_000, 50_000_000, "spent")]
    {
        let state = serde_json::json!({
            "roleName": "receipt", "market": MARKET,
            "protocol_amount": p.to_string(), "creator_amount": c.to_string(),
        });
        sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) VALUES($1,0,decode($2,'hex'),'fee-receipt',$3,decode($4,'hex'),$5,$6,$7)")
            .bind(vec![id; 32]).bind(MARKET).bind(p + c).bind(hex::encode(&spk))
            .bind(state).bind(&block).bind(status).execute(&pool).await.unwrap();
    }
    let first = kcc20_fee_receipts_page(&pool, MARKET, 1, 0).await.unwrap();
    assert_eq!(first.total_count, 2);
    assert_eq!(first.protocol_claimable_sompi, "150000000");
    assert_eq!(first.creator_claimable_sompi, "100000000");
    assert_eq!(first.receipts.len(), 1);
    assert_eq!(first.receipts[0].txid_hex, "04".repeat(32));
    let second = kcc20_fee_receipts_page(&pool, MARKET, 1, 1).await.unwrap();
    assert_eq!(second.receipts[0].txid_hex, "05".repeat(32));
    sqlx::query("UPDATE covenant_utxos SET amount_sompi=amount_sompi-1 WHERE txid=$1")
        .bind(vec![5u8; 32]).execute(&pool).await.unwrap();
    assert!(kcc20_fee_receipts_page(&pool, MARKET, 10, 0).await.is_err());
}
