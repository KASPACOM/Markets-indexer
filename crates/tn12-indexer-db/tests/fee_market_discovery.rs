use sqlx::PgPool;
use tn12_indexer_db::repo::kcc20_fee_markets_by_canonical;

const TOKEN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const TICKET: &str = "3333333333333333333333333333333333333333333333333333333333333333";

#[sqlx::test(migrations = "./migrations")]
async fn fee_market_discovery_rejects_labels_without_exact_wrapper_script(pool: PgPool) {
    let block = vec![1u8; 32];
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,1,1,ARRAY[]::bytea[],1,true,1)")
        .bind(&block)
        .execute(&pool)
        .await
        .unwrap();

    // An active output alone cannot authenticate a wallet-declared template.
    for (suffix, template, constructor_token, claimed, claimed_token, verified) in [
        ("04", Some("KCC20WrapperFeeV1"), TOKEN, None, TOKEN, false),
        (
            "08",
            Some("KCC20WrapperFeeArgentV2"),
            TOKEN,
            None,
            TOKEN,
            false,
        ),
        (
            "05",
            None,
            OTHER_TOKEN,
            Some("KCC20WrapperFeeV1"),
            TOKEN,
            false,
        ),
        (
            "06",
            None,
            OTHER_TOKEN,
            Some("KCC20WrapperFeeArgentV1"),
            TOKEN,
            true,
        ),
        (
            "07",
            Some("KCC20WrapperFeeV1"),
            OTHER_TOKEN,
            Some("KCC20WrapperFeeV1"),
            TOKEN,
            false,
        ),
    ] {
        let market = suffix.repeat(32);
        sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms,template_name,constructor_args,claimed_template,claimed_args,claim_verified) VALUES(decode($1,'hex'),'fee-wrapper',0,decode($1,'hex'),decode($1,'hex'),0,$2,1,$3,$4,$5,$6,$7)")
            .bind(&market)
            .bind(&block)
            .bind(template)
            .bind(serde_json::json!({"canonicalTokenId": constructor_token}))
            .bind(claimed)
            .bind(serde_json::json!({"canonicalTokenId": claimed_token}))
            .bind(verified)
            .execute(&pool)
            .await
            .unwrap();
        let state = serde_json::json!({
            "canonicalTokenId": TOKEN,
            "authenticatedMarketId": market,
            "feePolicyVersion": 1,
            "enabled": true,
            "feeTicketId": TICKET,
        });
        sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) VALUES(decode($1,'hex'),0,decode($1,'hex'),'fee-wrapper',50000000,decode($1,'hex'),$2,$3,'active')")
            .bind(&market)
            .bind(state)
            .bind(&block)
            .execute(&pool)
            .await
            .unwrap();
    }

    let rows = kcc20_fee_markets_by_canonical(&pool, TOKEN).await.unwrap();
    let ids: Vec<String> = rows.into_iter().map(|row| row.market_id_hex).collect();
    assert!(
        ids.is_empty(),
        "labels and claimed state cannot authenticate a different script"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_market_discovery_uses_live_wrapper_not_lineage_label(pool: PgPool) {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/fee-wrapper-argent-v2-active.json")).unwrap();
    let market = fixture["marketId"].as_str().unwrap();
    let token = fixture["tokenId"].as_str().unwrap();
    let state = &fixture["state"];
    let block = vec![1u8; 32];
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,1,1,ARRAY[]::bytea[],1,true,1)")
        .bind(&block).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms,template_name,constructor_args) VALUES(decode($1,'hex'),'wrapper',0,decode($1,'hex'),decode($1,'hex'),0,$2,1,'KCC20OrderbookFeeHolderV1',$3)")
        .bind(market).bind(&block).bind(serde_json::json!({"canonicalTokenId": token}))
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) VALUES(decode($1,'hex'),0,decode($1,'hex'),'wrapper',50000000,decode($2,'hex'),$3,$4,'active')")
        .bind(market).bind(fixture["scriptPubkeyHex"].as_str().unwrap()).bind(state).bind(&block)
        .execute(&pool).await.unwrap();
    for label in [
        Some("KCC20OrderbookFeeHolderV1"),
        Some("KCC20FeeEscrowV1"),
        None,
    ] {
        sqlx::query("UPDATE covenants SET template_name=$1")
            .bind(label)
            .execute(&pool)
            .await
            .unwrap();
        let rows = kcc20_fee_markets_by_canonical(&pool, token).await.unwrap();
        assert_eq!(
            rows.len(),
            1,
            "verified wrapper remains discoverable under {label:?}"
        );
        assert_eq!(rows[0].market_id_hex, market);
    }
    for field in ["canonicalTokenId", "authenticatedMarketId", "feeTicketId"] {
        let mut wrong = state.clone();
        wrong[field] = serde_json::json!("ff".repeat(32));
        sqlx::query("UPDATE covenant_utxos SET state=$1")
            .bind(wrong)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            kcc20_fee_markets_by_canonical(&pool, token)
                .await
                .unwrap()
                .is_empty(),
            "reject wrong {field}"
        );
    }
    sqlx::query("UPDATE covenant_utxos SET state=$1, script_pubkey=decode('aa20' || repeat('ff',32) || '87','hex')")
        .bind(state).execute(&pool).await.unwrap();
    assert!(kcc20_fee_markets_by_canonical(&pool, token)
        .await
        .unwrap()
        .is_empty());
    sqlx::query("UPDATE covenant_utxos SET script_pubkey=decode($1,'hex'), status='spent'")
        .bind(fixture["scriptPubkeyHex"].as_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    assert!(kcc20_fee_markets_by_canonical(&pool, token)
        .await
        .unwrap()
        .is_empty());
}

// Captured DEV GHOAD wrapper state. The metadata claim deliberately stays
// unverified: market authentication must not promote token identity verification.
#[sqlx::test(migrations = "./migrations")]
async fn fee_wrapper_supply_uses_authenticated_p2sh_reserves_and_survives_reorg(pool: PgPool) {
    use tn12_indexer_db::repo::{kcc20_token_summary, refresh_kcc20_token_summaries};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/fee-wrapper-native-v2-ghoad-active.json"
    ))
    .unwrap();
    let market = fixture["marketId"].as_str().unwrap();
    let token = fixture["tokenId"].as_str().unwrap();
    let script = fixture["scriptPubkeyHex"].as_str().unwrap();
    let reserve_owner = &script[4..68];
    let block = vec![1u8; 32];
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES($1,100,100,ARRAY[]::bytea[],1,true,1)")
        .bind(&block).execute(&pool).await.unwrap();
    for (id, template) in [(token, "KCC20"), (market, "KCC20OrderbookFeeHolderV1")] {
        sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,genesis_txid,genesis_vout,genesis_block,created_at_ms,template_name,claim_verified) VALUES(decode($1,'hex'),'fixture',0,decode($1,'hex'),decode($1,'hex'),0,$2,1,$3,false)")
            .bind(id).bind(&block).bind(template).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO covenant_utxos(txid,vout,covenant_id,address,amount_sompi,script_pubkey,state,created_block,status) VALUES(decode($1,'hex'),0,decode($1,'hex'),'wrapper',100000000,decode($2,'hex'),$3,$4,'active')")
        .bind(market).bind(script).bind(&fixture["state"]).bind(&block)
        .execute(&pool).await.unwrap();
    // Six wrapped tokens, a large unrelated snapshot shard, an unrelated P2SH
    // balance, and an equal-byte owner under the wrong authority scheme.
    for (id, owner, scheme, amount) in [
        (token, reserve_owner.to_owned(), 3i16, "600000000"),
        (token, "77".repeat(32), 4, "399999510228446924"),
        (token, "88".repeat(32), 3, "19"),
        (token, reserve_owner.to_owned(), 0, "23"),
        (market, "99".repeat(32), 0, "600000000"),
    ] {
        sqlx::query("INSERT INTO kcc20_holders(covenant_id,owner_identifier,identifier_type,amount_total,utxo_count,is_minter,last_change_ms) VALUES(decode($1,'hex'),decode($2,'hex'),$3,$4::TEXT::NUMERIC,1,false,1)")
            .bind(id).bind(owner).bind(scheme).bind(amount).execute(&pool).await.unwrap();
    }
    for _ in 0..2 {
        refresh_kcc20_token_summaries(&pool).await.unwrap();
        let row = kcc20_token_summary(&pool, token).await.unwrap().unwrap();
        assert_eq!(row.wrapper_id_hex.as_deref(), Some(market));
        assert_eq!(row.wrapper_reserve_supply, "600000000");
        assert_eq!(row.orderbook_tradeable_supply, "600000000");
        assert_eq!(row.holder_supply, "399999510828446966");
        let verified: bool = sqlx::query_scalar(
            "SELECT claim_verified FROM covenants WHERE covenant_id=decode($1,'hex')",
        )
        .bind(token)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!verified);
    }
    // A stale legacy label for the same authenticated market cannot double-count.
    sqlx::query("INSERT INTO kcc20_wrapper_summaries(wrapper_id,canonical_token_id,refreshed_at_ms) VALUES(decode($1,'hex'),decode($2,'hex'),1)")
        .bind(market).bind(token).execute(&pool).await.unwrap();
    refresh_kcc20_token_summaries(&pool).await.unwrap();
    let same_market = kcc20_token_summary(&pool, token).await.unwrap().unwrap();
    assert_eq!(same_market.wrapper_reserve_supply, "600000000");
    assert_eq!(same_market.orderbook_tradeable_supply, "600000000");
    sqlx::query("DELETE FROM kcc20_wrapper_summaries")
        .execute(&pool)
        .await
        .unwrap();

    // Both refreshers take a snapshot while queued behind the same lock.
    // The second must retry its whole snapshot after the first commits.
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('tn12:kcc20_token_summaries_refresh', 0))",
    )
    .execute(&mut *blocker)
    .await
    .unwrap();
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first = tokio::spawn(async move { refresh_kcc20_token_summaries(&first_pool).await });
    let second = tokio::spawn(async move { refresh_kcc20_token_summaries(&second_pool).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())")
                .fetch_one(&mut *blocker).await.unwrap();
            if waiting >= 2 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("both refreshers must wait behind the lock");
    blocker.commit().await.unwrap();
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();

    // Wrapped supply is independently measured, not copied from reserve supply.
    sqlx::query(
        "UPDATE kcc20_holders SET amount_total=400000000 WHERE covenant_id=decode($1,'hex')",
    )
    .bind(market)
    .execute(&pool)
    .await
    .unwrap();
    refresh_kcc20_token_summaries(&pool).await.unwrap();
    let row = kcc20_token_summary(&pool, token).await.unwrap().unwrap();
    assert_eq!(row.wrapper_reserve_supply, "600000000");
    assert_eq!(row.orderbook_tradeable_supply, "400000000");

    // Reorg removes the authenticated controller. A rebuild cannot retain it.
    sqlx::query("UPDATE covenant_utxos SET status='spent'")
        .execute(&pool)
        .await
        .unwrap();
    refresh_kcc20_token_summaries(&pool).await.unwrap();
    let row = kcc20_token_summary(&pool, token).await.unwrap().unwrap();
    assert!(row.wrapper_id_hex.is_none());
    assert_eq!(row.wrapper_reserve_supply, "0");
    assert_eq!(row.orderbook_tradeable_supply, "0");
    sqlx::query("UPDATE covenant_utxos SET status='active'")
        .execute(&pool)
        .await
        .unwrap();
    refresh_kcc20_token_summaries(&pool).await.unwrap();
    assert_eq!(
        kcc20_token_summary(&pool, token)
            .await
            .unwrap()
            .unwrap()
            .wrapper_reserve_supply,
        "600000000"
    );

    // A competing legacy market does not win by balance or lexicographic order.
    sqlx::query("INSERT INTO kcc20_wrapper_summaries(wrapper_id,canonical_token_id,refreshed_at_ms) VALUES(decode($1,'hex'),decode($2,'hex'),1)")
        .bind("ab".repeat(32)).bind(token).execute(&pool).await.unwrap();
    refresh_kcc20_token_summaries(&pool).await.unwrap();
    assert!(kcc20_token_summary(&pool, token)
        .await
        .unwrap()
        .unwrap()
        .wrapper_id_hex
        .is_none());
}
