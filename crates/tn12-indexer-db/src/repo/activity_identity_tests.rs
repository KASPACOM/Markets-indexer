use super::*;
use serde_json::json;

async fn seed(pool: &PgPool) {
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES(decode(repeat('aa',32),'hex'),1,1,ARRAY[]::bytea[],100,true,100)")
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO covenants(covenant_id,address,script_version,script_hash,template_name,genesis_txid,genesis_vout,genesis_block,created_at_ms,classification_kind,classification_status) VALUES(decode(repeat('bb',32),'hex'),'kaspatest:identity',0,decode(repeat('bb',32),'hex'),'KCC20',decode(repeat('cc',32),'hex'),0,decode(repeat('aa',32),'hex'),100,'covenant','matched')")
        .execute(pool).await.unwrap();
}

async fn lanes(pool: &PgPool) {
    sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,entrypoint,decoded_args) VALUES(decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),decode(repeat('aa',32),'hex'),100,'spend','set_public_mint_active','{}')").execute(pool).await.unwrap();
    for index in 0..35 {
        sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,outputs) VALUES(decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),decode(repeat('aa',32),'hex'),100,'continuation',$1)")
            .bind(json!({"vout": index, "state":{"owner":"ee".repeat(32),"ownerScheme":0,"amount":"0","isMintAuthority":true,"publicMintActive":true}}))
            .execute(pool).await.unwrap();
    }
}

async fn refresh(pool: &PgPool) {
    sqlx::query("INSERT INTO kcc20_projection_dirty(reason,txid,created_at_ms) VALUES('activity_identity_test',decode(repeat('cc',32),'hex'),100)").execute(pool).await.unwrap();
    refresh_kcc20_activity_feed(pool).await.unwrap();
}

fn ids(rows: &[Kcc20ActivityRow]) -> Vec<Option<String>> {
    rows.iter().map(|row| row.event_id.clone()).collect()
}

#[sqlx::test(migrations = "./migrations")]
async fn lane_identity_survives_paging_refresh_replay_and_raw_fallback(pool: PgPool) {
    seed(&pool).await;
    lanes(&pool).await;
    let token = "bb".repeat(32);
    let filters = Kcc20ActivityFilter::default();
    let raw = kcc20_activity_raw(&pool, &token, &filters, 100, 0)
        .await
        .unwrap();
    assert_eq!(raw.len(), 35);
    assert!(raw.iter().all(|row| row.event_id.is_some()));
    let distinct: std::collections::HashSet<_> = ids(&raw).into_iter().collect();
    assert_eq!(distinct.len(), 35);
    refresh(&pool).await;
    let mut pages = Vec::new();
    for offset in [0, 10, 20, 30, 40] {
        let page = kcc20_activity(&pool, &token, 10, offset).await.unwrap();
        assert_eq!(
            page.len(),
            if offset < 30 {
                10
            } else if offset == 30 {
                5
            } else {
                0
            }
        );
        pages.extend(page);
    }
    assert_eq!(ids(&pages), ids(&raw));
    let without_owner =
        kcc20_activity_feed_rows_without_owner_hydration(&pool, &vec![0xbb; 32], &filters, 100, 0)
            .await
            .unwrap();
    assert_eq!(
        without_owner
            .into_iter()
            .map(kcc20_activity_row_from_pg)
            .map(|row| row.event_id)
            .collect::<Vec<_>>(),
        ids(&raw)
    );
    sqlx::query("DELETE FROM kcc20_activity_feed")
        .execute(&pool)
        .await
        .unwrap();
    refresh(&pool).await;
    assert_eq!(
        ids(&kcc20_activity(&pool, &token, 100, 0).await.unwrap()),
        ids(&raw)
    );
    // Replay changes serial IDs; public identity is still the same chain event.
    sqlx::query("DELETE FROM covenant_actions")
        .execute(&pool)
        .await
        .unwrap();
    refresh(&pool).await;
    assert!(kcc20_activity(&pool, &token, 100, 0)
        .await
        .unwrap()
        .is_empty());
    lanes(&pool).await;
    sqlx::query("INSERT INTO blocks(hash,blue_score,daa_score,parent_hashes,timestamp_ms,is_chain_block,indexed_at_ms) VALUES(decode(repeat('ab',32),'hex'),2,2,ARRAY[]::bytea[],200,true,200)").execute(&pool).await.unwrap();
    sqlx::query(
        "UPDATE covenant_actions SET block_time_ms = 200, block_hash=decode(repeat('ab',32),'hex')",
    )
    .execute(&pool)
    .await
    .unwrap();
    refresh(&pool).await;
    assert_eq!(
        ids(&kcc20_activity(&pool, &token, 100, 0).await.unwrap()),
        ids(&raw)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn output_fill_and_missing_coordinate_identities(pool: PgPool) {
    let txid = vec![0xcc; 32];
    for index in 0..3 {
        let output: Option<String> =
            sqlx::query_scalar("SELECT kcc20_activity_event_id($1,'continuation',NULL,$2)")
                .bind(&txid)
                .bind(json!({"vout":index}))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            output,
            Some(format!("kcc20:{}:output:{index}", hex::encode(&txid)))
        );
        let fill: Option<String> = sqlx::query_scalar("SELECT kcc20_activity_fill_event_id($1,$2)")
            .bind(&txid)
            .bind(index.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            fill,
            Some(format!("kcc20:{}:fee-fill:{index}", hex::encode(&txid)))
        );
    }
    let spend: Option<String> =
        sqlx::query_scalar("SELECT kcc20_activity_event_id($1,'spend',$2,NULL)")
            .bind(&txid)
            .bind(json!({"previousOutpoint":{"hash":"DD".repeat(32),"index":2}}))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        spend,
        Some(format!(
            "kcc20:{}:input:{}:2",
            hex::encode(&txid),
            "dd".repeat(32)
        ))
    );
    for inputs in [
        json!(null),
        json!({"previousOutpoint":{"hash":"bad","index":0}}),
        json!({"previousOutpoint":{"hash":"dd".repeat(32),"index":-1}}),
    ] {
        let id: Option<String> =
            sqlx::query_scalar("SELECT kcc20_activity_event_id($1,'spend',$2,NULL)")
                .bind(&txid)
                .bind(inputs)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(id, None);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn grouped_fill_identity_matches_raw_and_projection(pool: PgPool) {
    seed(&pool).await;
    sqlx::query("UPDATE covenants SET template_name='KCC20Orderbook'")
        .execute(&pool)
        .await
        .unwrap();
    let token = "bb".repeat(32);
    let fills: Vec<_> = (0..3)
        .map(|index| {
            json!({
                "canonicalTokenId": token, "side":"buy", "maker":"ee".repeat(32),
                "taker":"ff".repeat(32), "makerScheme":0, "takerScheme":0,
                "amount":"10", "unitPriceSompi":"100", "priceSompi":"1000",
                "inputIndex":index, "orderId":format!("{}:{index}","dd".repeat(32))
            })
        })
        .collect();
    sqlx::query("INSERT INTO covenant_actions(covenant_id,txid,block_hash,block_time_ms,action,entrypoint,decoded_args) VALUES(decode(repeat('bb',32),'hex'),decode(repeat('cc',32),'hex'),decode(repeat('aa',32),'hex'),100,'spend','buyAsks',$1)")
        .bind(json!({"feePolicyVersion":"1","feePolicy":{},"feeTrades":fills}))
        .execute(&pool).await.unwrap();
    let filters = Kcc20ActivityFilter {
        kind: Some("trade".into()),
        ..Default::default()
    };
    let raw = kcc20_activity_raw(&pool, &token, &filters, 10, 0)
        .await
        .unwrap();
    assert_eq!(raw.len(), 3);
    assert_eq!(
        ids(&raw)
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    refresh(&pool).await;
    assert_eq!(
        ids(&kcc20_activity_filtered(&pool, &token, &filters, 10, 0)
            .await
            .unwrap()),
        ids(&raw)
    );
}
