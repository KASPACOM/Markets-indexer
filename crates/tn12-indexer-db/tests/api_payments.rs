use std::{collections::BTreeMap, sync::Arc, time::Instant};

use sqlx::{PgPool, Row};
use tn12_indexer_core::{
    blake2b_256, ApiPaymentChannelCloseRequest, ApiPaymentMethod, ApiPaymentSettlementArtifact,
    ApiPaymentSettlementAuthorization, ApiPaymentVoucher,
    API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1, API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1,
    API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1, API_PAYMENT_VOUCHER_SCHEMA_V1,
};
use tn12_indexer_db::api_payments::{
    accept_api_payment_voucher, api_direct_payment_proof_by_txid, api_payment_channel_by_id,
    api_payment_channel_tx_status_by_txid, api_payment_pricing_routes, api_payment_receipt_by_id,
    api_payment_settlement_candidates, api_payment_stale_opening_channels,
    apply_indexed_api_payment_channel_continuation, apply_indexed_api_payment_channel_refund,
    apply_indexed_api_payment_channel_settlement, claim_api_payment_settlement_authorizations,
    disable_api_payment_channels_missing_settlement_authorization,
    disable_api_payment_stale_opening_channels, insert_api_payment_channel,
    insert_api_payment_settlement_authorization, latest_api_payment_settlement_authorization,
    record_api_payment_usage_event, reject_api_payment_submitted_settlement,
    request_api_payment_channel_close, submit_api_direct_payment_proof,
    update_api_direct_payment_proof_status, upsert_indexed_api_payment_channel_open,
    ApiDirectPaymentProofStatusUpdate, ApiPaymentOpeningReconciliationPolicy,
    ApiPaymentSettlementCandidatePolicy, ApiPaymentVoucherAcceptance,
    IndexedApiPaymentChannelContinuation, IndexedApiPaymentChannelOpen,
    IndexedApiPaymentChannelRefund, IndexedApiPaymentChannelSettlement, NewApiDirectPaymentProof,
    NewApiPaymentChannel, NewApiPaymentChannelCloseRequest, NewApiPaymentSettlementAuthorization,
    NewApiPaymentUsageEvent,
};
use tokio::sync::Barrier;

fn channel(channel_id: &str, status: &str) -> NewApiPaymentChannel {
    NewApiPaymentChannel {
        channel_id: channel_id.to_string(),
        network_id: "testnet-10".to_string(),
        payer_identifier: "api-key-hash-1".to_string(),
        payer_pubkey: "aa".repeat(32),
        provider_pubkey: "bb".repeat(32),
        provider_identifier: Some("kaspacom-api".to_string()),
        scope: Some("indexer-api".to_string()),
        deposit_sompi: 5_000,
        reserve_sompi: 1_000,
        status: status.to_string(),
        open_txid_hex: Some("11".repeat(32)),
        refund_after_daa: Some(123_456),
        pricing_policy_id: Some("dev-indexer".to_string()),
        indexed_at_ms: Some(1_780_000_000_000),
        now_ms: 1_780_000_001_000,
    }
}

fn voucher(channel_id: &str, sequence: u64, total_spent_sompi: u64) -> ApiPaymentVoucher {
    ApiPaymentVoucher {
        schema: API_PAYMENT_VOUCHER_SCHEMA_V1.to_string(),
        method: ApiPaymentMethod::KaspaChannel,
        network_id: "testnet-10".to_string(),
        channel_id: channel_id.to_string(),
        payer_pubkey: "aa".repeat(32),
        provider_pubkey: "bb".repeat(32),
        sequence,
        total_spent_sompi,
        incremental_amount_sompi: 500,
        request_hash: format!("{sequence:064x}"),
        pricing_id: "kcc20.markets.v1".to_string(),
        route: "GET /kcc20/markets".to_string(),
        issued_at_ms: 1_780_000_001_000,
        expires_at_ms: 1_780_000_061_000,
        nonce: format!("nonce-{sequence}"),
        signature: "00".repeat(64),
    }
}

fn acceptance(sequence: u64) -> ApiPaymentVoucherAcceptance {
    ApiPaymentVoucherAcceptance {
        credential_hash_hex: format!("{:064x}", sequence + 100),
        accepted_at_ms: 1_780_000_002_000 + sequence as i64,
        served_status: Some(200),
    }
}

fn acceptance_at(tag: u64, accepted_at_ms: i64) -> ApiPaymentVoucherAcceptance {
    ApiPaymentVoucherAcceptance {
        credential_hash_hex: format!("{tag:064x}"),
        accepted_at_ms,
        served_status: Some(200),
    }
}

fn direct_proof(challenge_id: &str, txid_hex: &str) -> NewApiDirectPaymentProof {
    NewApiDirectPaymentProof {
        challenge_id: challenge_id.to_string(),
        network_id: "testnet-10".to_string(),
        txid_hex: txid_hex.to_string(),
        payer_identifier: Some("payer-1".to_string()),
        recipient_address: "kaspatest:qdirectrecipient".to_string(),
        amount_sompi: 777,
        pricing_id: "kcc20.discovery.v1".to_string(),
        route: "GET /kcc20/discovery".to_string(),
        request_hash: "11".repeat(32),
        status: "submitted".to_string(),
        failure_reason: None,
        raw_status_snapshot: None,
        submitted_at_ms: 1_780_000_010_000,
        verified_at_ms: None,
        indexed_at_ms: None,
    }
}

fn settlement_authorization(
    channel_id: &str,
    sequence: u64,
) -> NewApiPaymentSettlementAuthorization {
    NewApiPaymentSettlementAuthorization {
        authorization: ApiPaymentSettlementAuthorization {
            schema: API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: channel_id.to_string(),
            payer_pubkey: "aa".repeat(32),
            provider_pubkey: "bb".repeat(32),
            sequence,
            total_spent_sompi: 1_000 + sequence,
            provider_amount_sompi: 1_000 + sequence,
            payer_refund_sompi: 4_000 - sequence,
            settlement_fee_sompi: 0,
            settlement_txid: format!("{:064x}", sequence + 500),
            settlement_template_hash: format!("{:064x}", sequence + 600),
            refund_after_ms: 1_780_000_120_000,
            issued_at_ms: 1_780_000_010_000,
            expires_at_ms: 1_780_000_090_000,
            payer_settlement_signature: "41".repeat(65),
        },
        settlement_artifact: None,
        status: "available".to_string(),
        created_at_ms: 1_780_000_020_000 + sequence as i64,
    }
}

fn settlement_authorization_for_spend(
    channel_id: &str,
    sequence: u64,
    total_spent_sompi: u64,
) -> NewApiPaymentSettlementAuthorization {
    let mut new = settlement_authorization(channel_id, sequence);
    new.authorization.total_spent_sompi = total_spent_sompi;
    new.authorization.provider_amount_sompi = total_spent_sompi;
    new.authorization.payer_refund_sompi = 5_000 - total_spent_sompi;
    new
}

fn close_request(channel_id: &str) -> NewApiPaymentChannelCloseRequest {
    NewApiPaymentChannelCloseRequest {
        request: ApiPaymentChannelCloseRequest {
            schema: API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: channel_id.to_string(),
            payer_pubkey: "aa".repeat(32),
            provider_pubkey: "bb".repeat(32),
            requested_at_ms: 1_780_000_020_000,
            expires_at_ms: 1_780_000_080_000,
            nonce: format!("close-{channel_id}"),
            reason: Some("wallet-close".to_string()),
            signature: "77".repeat(64),
        },
        credential_hash_hex: "55".repeat(32),
        status: "requested".to_string(),
        created_at_ms: 1_780_000_020_000,
    }
}

async fn close_request_status(pool: &PgPool, channel_id: &str) -> String {
    sqlx::query_scalar::<_, String>(
        "SELECT status FROM api_payment_channel_close_requests WHERE channel_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(channel_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn settlement_authorization_with_artifact(
    channel_id: &str,
    sequence: u64,
    total_spent_sompi: u64,
) -> NewApiPaymentSettlementAuthorization {
    let mut new = settlement_authorization_for_spend(channel_id, sequence, total_spent_sompi);
    let unsigned_settlement_template =
        serde_json::json!({ "transaction": format!("unsigned-settlement-template-{sequence}") });
    new.authorization.settlement_template_hash = hex::encode(blake2b_256(
        serde_json::to_string(&unsigned_settlement_template)
            .unwrap()
            .as_bytes(),
    ));
    let metadata_digest = new.authorization.metadata_digest_hex();
    let mut extra = BTreeMap::new();
    extra.insert(
        "channelTxid".to_string(),
        serde_json::json!("11".repeat(32)),
    );
    extra.insert("channelVout".to_string(), serde_json::json!(0));
    extra.insert("contractScript".to_string(), serde_json::json!([1, 2, 3]));
    new.settlement_artifact = Some(ApiPaymentSettlementArtifact {
        schema: API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1.to_string(),
        contract: "ApiPaymentChannel".to_string(),
        network: new.authorization.network_id.clone(),
        channel_id: new.authorization.channel_id.clone(),
        authorization: new.authorization.clone(),
        metadata_digest,
        unsigned_settlement_template,
        extra,
    });
    new
}

fn indexed_open(channel_id: &str) -> IndexedApiPaymentChannelOpen {
    IndexedApiPaymentChannelOpen {
        channel_id: channel_id.to_string(),
        network_id: "testnet-10".to_string(),
        payer_pubkey: "aa".repeat(32),
        provider_pubkey: "bb".repeat(32),
        provider_payout_pubkey: "cc".repeat(32),
        voucher_domain_hash: "44".repeat(32),
        deposit_sompi: 100_000_000,
        reserve_sompi: 50_000_000,
        max_spend_sompi: 50_000_000,
        refund_after_ms: 1_780_001_200_000,
        close_after_ms: 0,
        open_txid_hex: "11".repeat(32),
        indexed_at_ms: 1_780_000_100_000,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn inserts_api_payment_channel(pool: PgPool) {
    let row = insert_api_payment_channel(&pool, channel("chan-insert", "usable"))
        .await
        .unwrap();

    assert_eq!(row.channel_id, "chan-insert");
    assert_eq!(row.network_id, "testnet-10");
    assert_eq!(row.deposit_sompi, 5_000);
    assert_eq!(row.reserve_sompi, 1_000);
    assert_eq!(row.spent_sompi, 0);
    assert_eq!(row.latest_sequence, 0);
    assert_eq!(row.status, "usable");
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_usable_channel_without_indexed_open_evidence(pool: PgPool) {
    let mut missing_open = channel("chan-usable-missing-open", "usable");
    missing_open.open_txid_hex = None;
    let err = insert_api_payment_channel(&pool, missing_open)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("usable API payment channels require indexed open evidence"),
        "{err}"
    );

    let mut missing_indexed_at = channel("chan-usable-missing-indexed", "usable");
    missing_indexed_at.indexed_at_ms = None;
    let err = insert_api_payment_channel(&pool, missing_indexed_at)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("usable API payment channels require indexed open evidence"),
        "{err}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn seeds_default_api_payment_pricing_catalog(pool: PgPool) {
    let rows = api_payment_pricing_routes(&pool, 1_780_000_001_000)
        .await
        .unwrap();

    let discovery = rows
        .iter()
        .find(|row| row.pricing_id == "api-payment.proof.kcc20-discovery.v1")
        .unwrap();
    assert_eq!(discovery.method, "GET");
    assert_eq!(discovery.path_pattern, "/payments/proof/kcc20-discovery");
    assert_eq!(discovery.base_sompi, 50_000_000);
    assert_eq!(discovery.per_row_sompi, 0);
    assert_eq!(discovery.max_limit, Some(100));
    assert!(discovery.enabled);

    let body_echo = rows
        .iter()
        .find(|row| row.pricing_id == "api-payment.proof.body-echo.v1")
        .unwrap();
    assert_eq!(body_echo.method, "POST");
    assert_eq!(body_echo.path_pattern, "/payments/proof/body-echo");
    assert_eq!(body_echo.base_sompi, 50_000_000);
    assert_eq!(body_echo.per_row_sompi, 0);
    assert_eq!(body_echo.max_limit, Some(100));
    assert!(body_echo.enabled);
}

#[sqlx::test(migrations = "./migrations")]
async fn api_payment_pricing_lookup_uses_active_time_index(pool: PgPool) {
    let now_ms = 1_780_000_001_000_i64;
    sqlx::query(
        r#"
        INSERT INTO api_payment_pricing (
            pricing_id, method, path_pattern, base_sompi, per_row_sompi,
            max_limit, enabled, effective_from_ms, effective_to_ms
        )
        SELECT
            'cold.future.' || gs::TEXT,
            'GET',
            '/cold/future/' || gs::TEXT,
            1,
            0,
            NULL::BIGINT,
            TRUE,
            $1::BIGINT + 1000000 + gs,
            NULL::BIGINT
        FROM generate_series(1, 1500) AS gs
        UNION ALL
        SELECT
            'cold.expired.' || gs::TEXT,
            'GET',
            '/cold/expired/' || gs::TEXT,
            1,
            0,
            NULL::BIGINT,
            TRUE,
            $1::BIGINT - 2000000 - gs,
            $1::BIGINT - 1000000 - gs
        FROM generate_series(1, 1500) AS gs
        "#,
    )
    .bind(now_ms)
    .execute(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        r#"
        EXPLAIN
        SELECT pricing_id, method, path_pattern, base_sompi, per_row_sompi,
               max_limit, enabled, effective_from_ms, effective_to_ms
        FROM api_payment_pricing
        WHERE effective_from_ms <= $1
          AND (effective_to_ms IS NULL OR effective_to_ms > $1)
        ORDER BY method ASC, path_pattern ASC, pricing_id ASC
        "#,
    )
    .bind(now_ms)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    let plan_text = plan.join("\n");
    assert!(
        plan_text.contains("api_payment_pricing_active_time_idx"),
        "pricing lookup did not use active-time index:\n{plan_text}"
    );

    let started = Instant::now();
    let rows = api_payment_pricing_routes(&pool, now_ms).await.unwrap();
    let elapsed = started.elapsed();
    let pricing_ids: Vec<_> = rows.iter().map(|row| row.pricing_id.as_str()).collect();
    assert_eq!(
        pricing_ids,
        vec![
            "api-payment.proof.kcc20-discovery.v1",
            "api-payment.proof.body-echo.v1"
        ]
    );
    assert!(
        elapsed.as_millis() < 500,
        "cold pricing lookup exceeded latency gate: {elapsed:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn projects_indexed_api_payment_channel_open(pool: PgPool) {
    let row = upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-index-open"))
        .await
        .unwrap();

    assert_eq!(row.channel_id, "chan-index-open");
    assert_eq!(row.status, "usable");
    assert_eq!(row.deposit_sompi, 100_000_000);
    assert_eq!(row.reserve_sompi, 50_000_000);

    let projected = sqlx::query(
        r#"
        SELECT provider_payout_pubkey, encode(voucher_domain_hash, 'hex') AS voucher_domain_hash,
               refund_after_ms, max_spend_sompi, encode(open_txid, 'hex') AS open_txid,
               encode(current_txid, 'hex') AS current_txid, current_vout
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind("chan-index-open")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(
        projected.get::<String, _>("provider_payout_pubkey"),
        "cc".repeat(32)
    );
    assert_eq!(
        projected.get::<String, _>("voucher_domain_hash"),
        "44".repeat(32)
    );
    assert_eq!(
        projected.get::<i64, _>("refund_after_ms"),
        1_780_001_200_000
    );
    assert_eq!(projected.get::<i64, _>("max_spend_sompi"), 50_000_000);
    assert_eq!(projected.get::<String, _>("open_txid"), "11".repeat(32));
    assert_eq!(projected.get::<String, _>("current_txid"), "11".repeat(32));
    assert_eq!(projected.get::<i32, _>("current_vout"), 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn projects_indexed_api_payment_channel_continuation(pool: PgPool) {
    upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-index-continue"))
        .await
        .unwrap();

    let row = apply_indexed_api_payment_channel_continuation(
        &pool,
        IndexedApiPaymentChannelContinuation {
            channel_id: "chan-index-continue".to_string(),
            txid_hex: "44".repeat(32),
            vout: 0,
            deposit_sompi: 150_000_000,
            max_spend_sompi: 100_000_000,
            refund_after_ms: 1_780_004_800_000,
            indexed_at_ms: 1_780_000_250_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row.status, "usable");
    assert_eq!(row.deposit_sompi, 150_000_000);
    assert_eq!(row.refund_after_ms, Some(1_780_004_800_000));

    let projected = sqlx::query(
        r#"
        SELECT deposit_sompi, max_spend_sompi, refund_after_ms,
               encode(open_txid, 'hex') AS open_txid,
               encode(current_txid, 'hex') AS current_txid,
               current_vout
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind("chan-index-continue")
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(projected.get::<i64, _>("deposit_sompi"), 150_000_000);
    assert_eq!(projected.get::<i64, _>("max_spend_sompi"), 100_000_000);
    assert_eq!(
        projected.get::<i64, _>("refund_after_ms"),
        1_780_004_800_000
    );
    assert_eq!(projected.get::<String, _>("open_txid"), "11".repeat(32));
    assert_eq!(projected.get::<String, _>("current_txid"), "44".repeat(32));
    assert_eq!(projected.get::<i32, _>("current_vout"), 0);

    let status = api_payment_channel_tx_status_by_txid(&pool, &"44".repeat(32))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.kind, "continuation");
    assert_eq!(status.channel_id, "chan-index-continue");
    assert_eq!(status.channel_status, "usable");

    let open_status = api_payment_channel_tx_status_by_txid(&pool, &"11".repeat(32))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(open_status.kind, "open");
}

#[sqlx::test(migrations = "./migrations")]
async fn projects_indexed_api_payment_channel_settlement(pool: PgPool) {
    upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-index-settle"))
        .await
        .unwrap();

    let row = apply_indexed_api_payment_channel_settlement(
        &pool,
        IndexedApiPaymentChannelSettlement {
            channel_id: "chan-index-settle".to_string(),
            txid_hex: "22".repeat(32),
            settled_total_sompi: 50_000_000,
            provider_amount_sompi: 50_000_000,
            payer_refund_sompi: 46_000_000,
            indexed_at_ms: 1_780_000_200_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row.status, "settled");
    assert_eq!(row.spent_sompi, 50_000_000);

    let settlement = sqlx::query(
        r#"
        SELECT channel_id, settled_total_sompi, provider_amount_sompi,
               payer_refund_sompi, indexer_status
        FROM api_payment_settlements
        WHERE txid = decode($1, 'hex')
        "#,
    )
    .bind("22".repeat(32))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        settlement.get::<String, _>("channel_id"),
        "chan-index-settle"
    );
    assert_eq!(settlement.get::<i64, _>("settled_total_sompi"), 50_000_000);
    assert_eq!(
        settlement.get::<i64, _>("provider_amount_sompi"),
        50_000_000
    );
    assert_eq!(settlement.get::<i64, _>("payer_refund_sompi"), 46_000_000);
    assert_eq!(settlement.get::<String, _>("indexer_status"), "indexed");
}

#[sqlx::test(migrations = "./migrations")]
async fn indexed_api_payment_channel_settlement_replay_updates_channel_id(pool: PgPool) {
    upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-fallback-settle"))
        .await
        .unwrap();
    upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-canonical-settle"))
        .await
        .unwrap();

    apply_indexed_api_payment_channel_settlement(
        &pool,
        IndexedApiPaymentChannelSettlement {
            channel_id: "chan-fallback-settle".to_string(),
            txid_hex: "77".repeat(32),
            settled_total_sompi: 40_000_000,
            provider_amount_sompi: 40_000_000,
            payer_refund_sompi: 56_000_000,
            indexed_at_ms: 1_780_000_200_000,
        },
    )
    .await
    .unwrap()
    .unwrap();
    apply_indexed_api_payment_channel_settlement(
        &pool,
        IndexedApiPaymentChannelSettlement {
            channel_id: "chan-canonical-settle".to_string(),
            txid_hex: "77".repeat(32),
            settled_total_sompi: 50_000_000,
            provider_amount_sompi: 50_000_000,
            payer_refund_sompi: 46_000_000,
            indexed_at_ms: 1_780_000_300_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    let settlement = api_payment_channel_tx_status_by_txid(&pool, &"77".repeat(32))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(settlement.kind, "settlement");
    assert_eq!(settlement.channel_id, "chan-canonical-settle");
    assert_eq!(settlement.settled_total_sompi, Some(50_000_000));
    assert_eq!(settlement.provider_amount_sompi, Some(50_000_000));
    assert_eq!(settlement.payer_refund_sompi, Some(46_000_000));
}

#[sqlx::test(migrations = "./migrations")]
async fn projects_indexed_api_payment_channel_refund(pool: PgPool) {
    upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-index-refund"))
        .await
        .unwrap();

    let row = apply_indexed_api_payment_channel_refund(
        &pool,
        IndexedApiPaymentChannelRefund {
            channel_id: "chan-index-refund".to_string(),
            txid_hex: "33".repeat(32),
            indexed_at_ms: 1_780_000_300_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row.status, "refunded");

    let refund_txid: String = sqlx::query_scalar(
        "SELECT encode(refund_txid, 'hex') FROM api_payment_channels WHERE channel_id = $1",
    )
    .bind("chan-index-refund")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(refund_txid, "33".repeat(32));
}

#[sqlx::test(migrations = "./migrations")]
async fn refund_tx_status_prefers_canonical_continuation_channel(pool: PgPool) {
    let mut fallback_open = indexed_open("chan-fallback-refund");
    fallback_open.open_txid_hex = "44".repeat(32);
    fallback_open.indexed_at_ms = 1_780_000_300_000;
    upsert_indexed_api_payment_channel_open(&pool, fallback_open)
        .await
        .unwrap();

    upsert_indexed_api_payment_channel_open(&pool, indexed_open("chan-canonical-refund"))
        .await
        .unwrap();
    apply_indexed_api_payment_channel_continuation(
        &pool,
        IndexedApiPaymentChannelContinuation {
            channel_id: "chan-canonical-refund".to_string(),
            txid_hex: "44".repeat(32),
            vout: 0,
            deposit_sompi: 150_000_000,
            max_spend_sompi: 100_000_000,
            refund_after_ms: 1_780_004_800_000,
            indexed_at_ms: 1_780_000_300_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    for channel_id in ["chan-fallback-refund", "chan-canonical-refund"] {
        apply_indexed_api_payment_channel_refund(
            &pool,
            IndexedApiPaymentChannelRefund {
                channel_id: channel_id.to_string(),
                txid_hex: "55".repeat(32),
                indexed_at_ms: 1_780_000_400_000,
            },
        )
        .await
        .unwrap()
        .unwrap();
    }

    let refund = api_payment_channel_tx_status_by_txid(&pool, &"55".repeat(32))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refund.kind, "refund");
    assert_eq!(refund.channel_id, "chan-canonical-refund");
    assert_eq!(refund.channel_status, "refunded");
}

#[sqlx::test(migrations = "./migrations")]
async fn accepts_voucher_and_advances_channel(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-accept", "usable"))
        .await
        .unwrap();

    let accepted =
        accept_api_payment_voucher(&pool, &voucher("chan-accept", 1, 1_000), acceptance(1))
            .await
            .unwrap()
            .unwrap();

    assert_eq!(accepted.spent_sompi, 1_000);
    assert_eq!(accepted.latest_sequence, 1);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM api_payment_vouchers WHERE channel_id = $1")
            .bind("chan-accept")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn records_and_reads_payment_receipt_usage(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-receipt", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(&pool, &voucher("chan-receipt", 1, 1_000), acceptance(1))
        .await
        .unwrap()
        .unwrap();

    let row = record_api_payment_usage_event(
        &pool,
        NewApiPaymentUsageEvent {
            request_id: "req-receipt-1".to_string(),
            channel_id: Some("chan-receipt".to_string()),
            wallet_or_api_key_hash_hex: None,
            route: "GET /kcc20/markets".to_string(),
            pricing_id: "kcc20.markets.v1".to_string(),
            amount_sompi: 500,
            voucher_sequence: Some(1),
            receipt_id: format!("apr_{}", "12".repeat(32)),
            response_status: Some(200),
            duration_ms: Some(42),
            created_at_ms: 1_780_000_003_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row.receipt_id, format!("apr_{}", "12".repeat(32)));
    assert_eq!(row.channel_id.as_deref(), Some("chan-receipt"));
    assert_eq!(row.amount_sompi, 500);
    assert_eq!(row.voucher_sequence, Some(1));
    assert_eq!(row.response_status, Some(200));
    assert_eq!(row.duration_ms, Some(42));
    assert_eq!(row.voucher_total_spent_sompi, Some(1_000));
    assert_eq!(row.voucher_request_hash, Some(format!("{:064x}", 1)));
    assert_eq!(row.voucher_accepted_at_ms, Some(1_780_000_002_001));
    assert_eq!(row.channel_status.as_deref(), Some("usable"));
    assert_eq!(row.channel_spent_sompi, Some(1_000));
    assert_eq!(row.channel_latest_sequence, Some(1));

    let fetched = api_payment_receipt_by_id(&pool, &row.receipt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched, row);

    let duplicate = record_api_payment_usage_event(
        &pool,
        NewApiPaymentUsageEvent {
            request_id: "req-receipt-1".to_string(),
            channel_id: Some("chan-receipt".to_string()),
            wallet_or_api_key_hash_hex: None,
            route: "GET /kcc20/markets".to_string(),
            pricing_id: "kcc20.markets.v1".to_string(),
            amount_sompi: 500,
            voucher_sequence: Some(1),
            receipt_id: format!("apr_{}", "13".repeat(32)),
            response_status: Some(200),
            duration_ms: Some(1),
            created_at_ms: 1_780_000_003_100,
        },
    )
    .await
    .unwrap();
    assert!(duplicate.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn accepts_only_one_concurrent_voucher_for_same_sequence(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-concurrent", "usable"))
        .await
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);

    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        accept_api_payment_voucher(
            &first_pool,
            &voucher("chan-concurrent", 1, 3_000),
            acceptance(1),
        )
        .await
        .unwrap()
    });

    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        accept_api_payment_voucher(
            &second_pool,
            &voucher("chan-concurrent", 1, 3_000),
            acceptance(2),
        )
        .await
        .unwrap()
    });

    let first = first.await.unwrap();
    let second = second.await.unwrap();
    assert_eq!(
        usize::from(first.is_some()) + usize::from(second.is_some()),
        1
    );

    let channel = api_payment_channel_by_id(&pool, "chan-concurrent")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.spent_sompi, 3_000);
    assert_eq!(channel.latest_sequence, 1);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM api_payment_vouchers WHERE channel_id = $1")
            .bind("chan-concurrent")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn accepts_only_one_concurrent_conflicting_voucher_for_same_sequence(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-conflict", "usable"))
        .await
        .unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_barrier = Arc::clone(&barrier);
    let second_barrier = Arc::clone(&barrier);

    let first = tokio::spawn(async move {
        first_barrier.wait().await;
        accept_api_payment_voucher(
            &first_pool,
            &voucher("chan-conflict", 1, 2_000),
            acceptance(10),
        )
        .await
        .unwrap()
    });

    let second = tokio::spawn(async move {
        second_barrier.wait().await;
        accept_api_payment_voucher(
            &second_pool,
            &voucher("chan-conflict", 1, 3_000),
            acceptance(20),
        )
        .await
        .unwrap()
    });

    let first = first.await.unwrap();
    let second = second.await.unwrap();
    assert_eq!(
        usize::from(first.is_some()) + usize::from(second.is_some()),
        1
    );

    let accepted = first.or(second).unwrap();
    assert_eq!(accepted.latest_sequence, 1);
    assert!(
        [2_000, 3_000].contains(&accepted.spent_sompi),
        "unexpected accepted total {}",
        accepted.spent_sompi
    );

    let channel = api_payment_channel_by_id(&pool, "chan-conflict")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.latest_sequence, 1);
    assert_eq!(channel.spent_sompi, accepted.spent_sompi);

    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT sequence, total_spent_sompi FROM api_payment_vouchers WHERE channel_id = $1",
    )
    .bind("chan-conflict")
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows, vec![(1, accepted.spent_sompi)]);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_stale_non_increasing_and_overspend_vouchers(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-reject", "usable"))
        .await
        .unwrap();

    assert!(
        accept_api_payment_voucher(&pool, &voucher("chan-reject", 1, 1_000), acceptance(1))
            .await
            .unwrap()
            .is_some()
    );

    assert!(
        accept_api_payment_voucher(&pool, &voucher("chan-reject", 1, 2_000), acceptance(2))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        accept_api_payment_voucher(&pool, &voucher("chan-reject", 2, 1_000), acceptance(3))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        accept_api_payment_voucher(&pool, &voucher("chan-reject", 2, 4_001), acceptance(4))
            .await
            .unwrap()
            .is_none()
    );

    let accepted =
        accept_api_payment_voucher(&pool, &voucher("chan-reject", 2, 1_500), acceptance(5))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(accepted.spent_sompi, 1_500);
    assert_eq!(accepted.latest_sequence, 2);

    let channel = api_payment_channel_by_id(&pool, "chan-reject")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.spent_sompi, 1_500);
    assert_eq!(channel.latest_sequence, 2);

    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM api_payment_vouchers WHERE channel_id = $1")
            .bind("chan-reject")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_vouchers_for_non_usable_channels(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-disabled", "disabled"))
        .await
        .unwrap();

    let accepted =
        accept_api_payment_voucher(&pool, &voucher("chan-disabled", 1, 1_000), acceptance(1))
            .await
            .unwrap();

    assert!(accepted.is_none());

    let row = sqlx::query(
        "SELECT spent_sompi, latest_sequence FROM api_payment_channels WHERE channel_id = $1",
    )
    .bind("chan-disabled")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("spent_sompi"), 0);
    assert_eq!(row.get::<i64, _>("latest_sequence"), 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn disables_opening_channels_that_miss_indexed_activation(pool: PgPool) {
    let now_ms = 1_780_000_100_000_i64;
    let mut missing_txid = channel("chan-open-missing-txid", "opening");
    missing_txid.open_txid_hex = None;
    missing_txid.indexed_at_ms = None;
    missing_txid.now_ms = now_ms - 2_000;
    insert_api_payment_channel(&pool, missing_txid)
        .await
        .unwrap();

    let mut missing_indexed_open = channel("chan-open-not-indexed", "opening");
    missing_indexed_open.indexed_at_ms = None;
    missing_indexed_open.now_ms = now_ms - 1_500;
    insert_api_payment_channel(&pool, missing_indexed_open)
        .await
        .unwrap();

    let mut fresh_open = channel("chan-open-fresh", "opening");
    fresh_open.indexed_at_ms = None;
    fresh_open.now_ms = now_ms - 100;
    insert_api_payment_channel(&pool, fresh_open).await.unwrap();

    insert_api_payment_channel(&pool, channel("chan-already-usable", "usable"))
        .await
        .unwrap();

    let policy = ApiPaymentOpeningReconciliationPolicy {
        now_ms,
        max_opening_age_ms: 1_000,
        limit: 100,
    };
    let candidates = api_payment_stale_opening_channels(&pool, policy.clone())
        .await
        .unwrap();
    let candidate_ids: Vec<_> = candidates
        .iter()
        .map(|row| (row.channel_id.as_str(), row.reason.as_str()))
        .collect();
    assert_eq!(
        candidate_ids,
        vec![
            ("chan-open-missing-txid", "open_txid_missing"),
            ("chan-open-not-indexed", "open_not_indexed"),
        ]
    );

    let disabled = disable_api_payment_stale_opening_channels(&pool, policy)
        .await
        .unwrap();
    let disabled_ids: Vec<_> = disabled
        .iter()
        .map(|row| (row.channel_id.as_str(), row.reason.as_str()))
        .collect();
    assert_eq!(disabled_ids, candidate_ids);

    for channel_id in ["chan-open-missing-txid", "chan-open-not-indexed"] {
        let row = api_payment_channel_by_id(&pool, channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "disabled");
    }
    let fresh = api_payment_channel_by_id(&pool, "chan-open-fresh")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh.status, "opening");
    let usable = api_payment_channel_by_id(&pool, "chan-already-usable")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usable.status, "usable");

    let second = disable_api_payment_stale_opening_channels(
        &pool,
        ApiPaymentOpeningReconciliationPolicy {
            now_ms: now_ms + 1,
            max_opening_age_ms: 1_000,
            limit: 100,
        },
    )
    .await
    .unwrap();
    assert!(second.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn inserts_and_reads_latest_settlement_authorization(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-settle-auth", "usable"))
        .await
        .unwrap();

    let first = insert_api_payment_settlement_authorization(
        &pool,
        settlement_authorization("chan-settle-auth", 1),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(first.channel_id, "chan-settle-auth");
    assert_eq!(first.sequence, 1);
    assert_eq!(first.total_spent_sompi, 1_001);
    assert_eq!(first.provider_amount_sompi, 1_001);
    assert_eq!(first.payer_refund_sompi, 3_999);
    assert_eq!(first.settlement_fee_sompi, 0);
    assert_eq!(first.status, "available");
    assert_eq!(first.metadata_hash.len(), 64);

    insert_api_payment_settlement_authorization(
        &pool,
        settlement_authorization("chan-settle-auth", 2),
    )
    .await
    .unwrap()
    .unwrap();

    let latest = latest_api_payment_settlement_authorization(&pool, "chan-settle-auth")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.sequence, 2);
    assert_eq!(latest.total_spent_sompi, 1_002);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_settlement_authorization_expiring_after_refund_window(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-expiry-bound", "usable"))
        .await
        .unwrap();

    let mut expired_at_refund = settlement_authorization("chan-expiry-bound", 1);
    expired_at_refund.authorization.expires_at_ms = expired_at_refund.authorization.refund_after_ms;
    let err = insert_api_payment_settlement_authorization(&pool, expired_at_refund)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("settlement authorization expires at or after refund window"),
        "{err}"
    );

    let mut expired_after_refund = settlement_authorization("chan-expiry-bound", 1);
    expired_after_refund.authorization.expires_at_ms =
        expired_after_refund.authorization.refund_after_ms + 1;
    let err = insert_api_payment_settlement_authorization(&pool, expired_after_refund)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("settlement authorization expires at or after refund window"),
        "{err}"
    );
    assert!(
        latest_api_payment_settlement_authorization(&pool, "chan-expiry-bound")
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn stores_and_claims_settlement_artifact_template(pool: PgPool) {
    let now_ms = 1_780_000_060_000;
    insert_api_payment_channel(&pool, channel("chan-settle-artifact", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-settle-artifact", 1, 2_500),
        acceptance_at(601, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    let new = settlement_authorization_with_artifact("chan-settle-artifact", 1, 2_500);
    let template = new
        .settlement_artifact
        .as_ref()
        .unwrap()
        .unsigned_settlement_template
        .clone();
    let template_json = serde_json::to_string(&template).unwrap();
    let inserted = insert_api_payment_settlement_authorization(&pool, new)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        inserted.settlement_artifact_schema.as_deref(),
        Some(API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1)
    );
    assert_eq!(
        inserted.unsigned_settlement_template.as_deref(),
        Some(template_json.as_str())
    );
    assert_eq!(
        inserted
            .settlement_artifact_json
            .as_ref()
            .and_then(|value| value.get("contractScript"))
            .cloned(),
        Some(serde_json::json!([1, 2, 3]))
    );

    let latest = latest_api_payment_settlement_authorization(&pool, "chan-settle-artifact")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        latest.settlement_artifact_schema.as_deref(),
        Some(API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1)
    );
    assert_eq!(
        latest.unsigned_settlement_template.as_deref(),
        Some(template_json.as_str())
    );
    assert_eq!(
        latest
            .settlement_artifact_json
            .as_ref()
            .and_then(|value| value.get("channelTxid"))
            .cloned(),
        Some(serde_json::json!("11".repeat(32)))
    );

    let claims = claim_api_payment_settlement_authorizations(
        &pool,
        ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi: 2_000,
            min_unsettled_sequences: 0,
            max_voucher_age_ms: 0,
            refund_safety_margin_ms: 0,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        claims[0].settlement_artifact_schema.as_deref(),
        Some(API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1)
    );
    assert_eq!(
        claims[0].unsigned_settlement_template.as_deref(),
        Some(template_json.as_str())
    );
    assert_eq!(
        claims[0]
            .settlement_artifact_json
            .as_ref()
            .and_then(|value| value.get("contractScript"))
            .cloned(),
        Some(serde_json::json!([1, 2, 3]))
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn close_request_marks_channel_and_claims_latest_authorization(pool: PgPool) {
    let now_ms = 1_780_000_060_000;
    insert_api_payment_channel(&pool, channel("chan-close-request", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-close-request", 1, 2_500),
        acceptance_at(701, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    insert_api_payment_settlement_authorization(
        &pool,
        settlement_authorization_for_spend("chan-close-request", 1, 2_500),
    )
    .await
    .unwrap()
    .unwrap();

    let closed = request_api_payment_channel_close(&pool, close_request("chan-close-request"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed.status, "close_requested");
    assert_eq!(closed.spent_sompi, 2_500);

    let candidates = api_payment_settlement_candidates(
        &pool,
        ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi: 0,
            min_unsettled_sequences: 0,
            max_voucher_age_ms: 0,
            refund_safety_margin_ms: 0,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].channel_id, "chan-close-request");
    assert_eq!(candidates[0].reason, "close_requested");

    let claimed = claim_api_payment_settlement_authorizations(
        &pool,
        ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi: 0,
            min_unsettled_sequences: 0,
            max_voucher_age_ms: 0,
            refund_safety_margin_ms: 0,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].channel_id, "chan-close-request");
    assert_eq!(claimed[0].reason, "close_requested");

    let channel = api_payment_channel_by_id(&pool, "chan-close-request")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.status, "settlement_pending");
    let auth = latest_api_payment_settlement_authorization(&pool, "chan-close-request")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.status, "submitted");
    assert_eq!(
        close_request_status(&pool, "chan-close-request").await,
        "claimed"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn close_request_without_spend_or_usable_channel_is_not_queued(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-close-empty", "usable"))
        .await
        .unwrap();
    assert!(
        request_api_payment_channel_close(&pool, close_request("chan-close-empty"))
            .await
            .unwrap()
            .is_none()
    );

    insert_api_payment_channel(&pool, channel("chan-close-disabled", "disabled"))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE api_payment_channels SET spent_sompi = 2500, latest_sequence = 1 WHERE channel_id = $1",
    )
    .bind("chan-close-disabled")
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        request_api_payment_channel_close(&pool, close_request("chan-close-disabled"))
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_settlement_authorization_replays(pool: PgPool) {
    insert_api_payment_channel(&pool, channel("chan-settle-replay", "usable"))
        .await
        .unwrap();

    let original = settlement_authorization("chan-settle-replay", 1);
    assert!(
        insert_api_payment_settlement_authorization(&pool, original.clone())
            .await
            .unwrap()
            .is_some()
    );

    assert!(insert_api_payment_settlement_authorization(&pool, original)
        .await
        .unwrap()
        .is_none());

    let mut same_txid = settlement_authorization("chan-settle-replay", 2);
    same_txid.authorization.settlement_txid = format!("{:064x}", 501);
    assert!(
        insert_api_payment_settlement_authorization(&pool, same_txid)
            .await
            .unwrap()
            .is_none()
    );

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM api_payment_settlement_authorizations WHERE channel_id = $1",
    )
    .bind("chan-settle-replay")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn lists_settlement_candidates_by_thresholds_and_refund_margin(pool: PgPool) {
    let now_ms = 1_780_000_050_000;

    insert_api_payment_channel(&pool, channel("chan-candidate-amount", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-candidate-amount", 1, 2_500),
        acceptance_at(201, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    insert_api_payment_settlement_authorization(
        &pool,
        settlement_authorization("chan-candidate-amount", 1),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-candidate-sequence", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-candidate-sequence", 3, 1_500),
        acceptance_at(202, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-candidate-age", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-candidate-age", 1, 1_500),
        acceptance_at(203, now_ms - 20_000),
    )
    .await
    .unwrap()
    .unwrap();

    let mut expiring = indexed_open("chan-candidate-expiring");
    expiring.refund_after_ms = now_ms + 10_000;
    upsert_indexed_api_payment_channel_open(&pool, expiring)
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-candidate-expiring", 1, 1_000),
        acceptance_at(204, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-candidate-fresh", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-candidate-fresh", 1, 500),
        acceptance_at(205, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    let rows = api_payment_settlement_candidates(
        &pool,
        ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi: 2_000,
            min_unsettled_sequences: 3,
            max_voucher_age_ms: 10_000,
            refund_safety_margin_ms: 20_000,
            limit: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].channel_id, "chan-candidate-expiring");
    assert_eq!(rows[0].reason, "refund_window");

    let amount = rows
        .iter()
        .find(|row| row.channel_id == "chan-candidate-amount")
        .unwrap();
    assert_eq!(amount.reason, "unsettled_sompi");
    assert_eq!(amount.spent_sompi, 2_500);
    assert_eq!(amount.latest_authorization_sequence, Some(1));
    assert_eq!(
        amount.latest_authorization_status.as_deref(),
        Some("available")
    );

    let sequence = rows
        .iter()
        .find(|row| row.channel_id == "chan-candidate-sequence")
        .unwrap();
    assert_eq!(sequence.reason, "unsettled_sequence");
    assert_eq!(sequence.latest_authorization_sequence, None);

    let age = rows
        .iter()
        .find(|row| row.channel_id == "chan-candidate-age")
        .unwrap();
    assert_eq!(age.reason, "voucher_age");

    assert!(rows
        .iter()
        .all(|row| row.channel_id != "chan-candidate-fresh"));
}

#[sqlx::test(migrations = "./migrations")]
async fn claims_available_settlement_authorizations_for_worker(pool: PgPool) {
    let now_ms = 1_780_000_050_000;
    let policy = ApiPaymentSettlementCandidatePolicy {
        now_ms,
        min_unsettled_sompi: 2_000,
        min_unsettled_sequences: 0,
        max_voucher_age_ms: 0,
        refund_safety_margin_ms: 0,
        limit: 10,
    };

    insert_api_payment_channel(&pool, channel("chan-claim", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-claim", 1, 2_500),
        acceptance_at(501, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    insert_api_payment_settlement_authorization(
        &pool,
        settlement_authorization_for_spend("chan-claim", 1, 2_500),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-no-claim", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-no-claim", 1, 2_500),
        acceptance_at(502, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-stale-claim", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-stale-claim", 1, 2_500),
        acceptance_at(503, now_ms - 2_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut stale_claim_auth = settlement_authorization_for_spend("chan-stale-claim", 1, 2_500);
    stale_claim_auth.authorization.settlement_txid = "91".repeat(32);
    stale_claim_auth.authorization.settlement_template_hash = "92".repeat(32);
    insert_api_payment_settlement_authorization(&pool, stale_claim_auth)
        .await
        .unwrap()
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-stale-claim", 2, 3_000),
        acceptance_at(504, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    let claims = claim_api_payment_settlement_authorizations(&pool, policy.clone())
        .await
        .unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].channel_id, "chan-claim");
    assert_eq!(claims[0].reason, "unsettled_sompi");
    assert_eq!(claims[0].sequence, 1);
    assert_eq!(claims[0].settlement_txid, format!("{:064x}", 501));
    assert_eq!(claims[0].claimed_at_ms, now_ms);

    let claimed_channel = api_payment_channel_by_id(&pool, "chan-claim")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claimed_channel.status, "settlement_pending");
    assert_eq!(claimed_channel.updated_at_ms, now_ms);
    assert!(accept_api_payment_voucher(
        &pool,
        &voucher("chan-claim", 2, 3_000),
        acceptance_at(503, now_ms + 1),
    )
    .await
    .unwrap()
    .is_none());

    let auth = latest_api_payment_settlement_authorization(&pool, "chan-claim")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.status, "submitted");
    assert_eq!(auth.updated_at_ms, now_ms);

    let no_claim = api_payment_channel_by_id(&pool, "chan-no-claim")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(no_claim.status, "usable");
    let stale_claim = api_payment_channel_by_id(&pool, "chan-stale-claim")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale_claim.status, "usable");

    let second = claim_api_payment_settlement_authorizations(&pool, policy)
        .await
        .unwrap();
    assert!(second.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn indexed_settlement_marks_submitted_authorization_spent(pool: PgPool) {
    let now_ms = 1_780_000_050_000;
    let settlement_txid = "22".repeat(32);

    insert_api_payment_channel(&pool, channel("chan-claim-indexed", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-claim-indexed", 1, 2_500),
        acceptance_at(601, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut auth = settlement_authorization_for_spend("chan-claim-indexed", 1, 2_500);
    auth.authorization.settlement_txid = settlement_txid.clone();
    insert_api_payment_settlement_authorization(&pool, auth)
        .await
        .unwrap()
        .unwrap();

    let claims = claim_api_payment_settlement_authorizations(
        &pool,
        ApiPaymentSettlementCandidatePolicy {
            now_ms,
            min_unsettled_sompi: 2_000,
            min_unsettled_sequences: 0,
            max_voucher_age_ms: 0,
            refund_safety_margin_ms: 0,
            limit: 10,
        },
    )
    .await
    .unwrap();
    assert_eq!(claims.len(), 1);

    apply_indexed_api_payment_channel_settlement(
        &pool,
        IndexedApiPaymentChannelSettlement {
            channel_id: "chan-claim-indexed".to_string(),
            txid_hex: settlement_txid,
            settled_total_sompi: 2_500,
            provider_amount_sompi: 2_500,
            payer_refund_sompi: 2_500,
            indexed_at_ms: now_ms + 5_000,
        },
    )
    .await
    .unwrap()
    .unwrap();

    let channel = api_payment_channel_by_id(&pool, "chan-claim-indexed")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.status, "settled");

    let auth = latest_api_payment_settlement_authorization(&pool, "chan-claim-indexed")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.status, "spent");
    assert_eq!(auth.updated_at_ms, now_ms + 5_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejected_submitted_settlement_disables_channel(pool: PgPool) {
    let now_ms = 1_780_000_050_000;
    let settlement_txid = "33".repeat(32);

    insert_api_payment_channel(&pool, channel("chan-claim-reject", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-claim-reject", 1, 2_500),
        acceptance_at(701, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut auth = settlement_authorization_for_spend("chan-claim-reject", 1, 2_500);
    auth.authorization.settlement_txid = settlement_txid.clone();
    insert_api_payment_settlement_authorization(&pool, auth)
        .await
        .unwrap()
        .unwrap();
    request_api_payment_channel_close(&pool, close_request("chan-claim-reject"))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        claim_api_payment_settlement_authorizations(
            &pool,
            ApiPaymentSettlementCandidatePolicy {
                now_ms,
                min_unsettled_sompi: 2_000,
                min_unsettled_sequences: 0,
                max_voucher_age_ms: 0,
                refund_safety_margin_ms: 0,
                limit: 10,
            },
        )
        .await
        .unwrap()
        .len(),
        1
    );
    assert_eq!(
        close_request_status(&pool, "chan-claim-reject").await,
        "claimed"
    );

    let rejected = reject_api_payment_submitted_settlement(&pool, &settlement_txid, now_ms + 2_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected.channel_id, "chan-claim-reject");
    assert_eq!(rejected.channel_status, "disabled");
    assert_eq!(rejected.authorization_status, "rejected");

    let rejected_channel = api_payment_channel_by_id(&pool, "chan-claim-reject")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected_channel.status, "disabled");
    assert!(accept_api_payment_voucher(
        &pool,
        &voucher("chan-claim-reject", 2, 3_000),
        acceptance_at(702, now_ms + 3_000),
    )
    .await
    .unwrap()
    .is_none());

    let auth = latest_api_payment_settlement_authorization(&pool, "chan-claim-reject")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.status, "rejected");
    assert_eq!(auth.updated_at_ms, now_ms + 2_000);
    assert_eq!(
        close_request_status(&pool, "chan-claim-reject").await,
        "rejected"
    );

    assert!(
        reject_api_payment_submitted_settlement(&pool, &settlement_txid, now_ms + 4_000)
            .await
            .unwrap()
            .is_none()
    );

    let usable_txid = "34".repeat(32);
    insert_api_payment_channel(&pool, channel("chan-usable-reject", "usable"))
        .await
        .unwrap();
    let mut usable_auth = settlement_authorization("chan-usable-reject", 2);
    usable_auth.status = "submitted".to_string();
    usable_auth.authorization.settlement_txid = usable_txid.clone();
    insert_api_payment_settlement_authorization(&pool, usable_auth)
        .await
        .unwrap()
        .unwrap();

    let rejected = reject_api_payment_submitted_settlement(&pool, &usable_txid, now_ms + 5_000)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected.channel_id, "chan-usable-reject");
    assert_eq!(rejected.channel_status, "disabled");

    let channel = api_payment_channel_by_id(&pool, "chan-usable-reject")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(channel.status, "disabled");
}

#[sqlx::test(migrations = "./migrations")]
async fn disables_settlement_candidates_without_available_authorization(pool: PgPool) {
    let now_ms = 1_780_000_050_000;
    let policy = ApiPaymentSettlementCandidatePolicy {
        now_ms,
        min_unsettled_sompi: 2_000,
        min_unsettled_sequences: 0,
        max_voucher_age_ms: 0,
        refund_safety_margin_ms: 0,
        limit: 10,
    };

    insert_api_payment_channel(&pool, channel("chan-safe-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-safe-auth", 1, 2_500),
        acceptance_at(301, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    insert_api_payment_settlement_authorization(
        &pool,
        settlement_authorization_for_spend("chan-safe-auth", 1, 2_500),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-missing-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-missing-auth", 1, 2_500),
        acceptance_at(302, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-close-missing-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-close-missing-auth", 1, 2_500),
        acceptance_at(309, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    request_api_payment_channel_close(&pool, close_request("chan-close-missing-auth"))
        .await
        .unwrap()
        .unwrap();

    insert_api_payment_channel(&pool, channel("chan-stale-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-stale-auth", 1, 2_500),
        acceptance_at(305, now_ms - 2_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut stale_auth = settlement_authorization_for_spend("chan-stale-auth", 1, 2_500);
    stale_auth.authorization.settlement_txid = "93".repeat(32);
    stale_auth.authorization.settlement_template_hash = "94".repeat(32);
    insert_api_payment_settlement_authorization(&pool, stale_auth)
        .await
        .unwrap()
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-stale-auth", 2, 3_000),
        acceptance_at(306, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();

    insert_api_payment_channel(&pool, channel("chan-bad-math-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-bad-math-auth", 1, 2_500),
        acceptance_at(307, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut bad_math_auth = settlement_authorization_for_spend("chan-bad-math-auth", 1, 2_500);
    bad_math_auth.authorization.settlement_txid = "95".repeat(32);
    bad_math_auth.authorization.settlement_template_hash = "96".repeat(32);
    bad_math_auth.authorization.payer_refund_sompi -= 1;
    insert_api_payment_settlement_authorization(&pool, bad_math_auth)
        .await
        .unwrap()
        .unwrap();

    insert_api_payment_channel(&pool, channel("chan-expired-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-expired-auth", 1, 2_500),
        acceptance_at(303, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut expired = settlement_authorization("chan-expired-auth", 2);
    expired.authorization.expires_at_ms = (now_ms - 1) as u64;
    insert_api_payment_settlement_authorization(&pool, expired)
        .await
        .unwrap()
        .unwrap();

    insert_api_payment_channel(&pool, channel("chan-rejected-auth", "usable"))
        .await
        .unwrap();
    accept_api_payment_voucher(
        &pool,
        &voucher("chan-rejected-auth", 1, 2_500),
        acceptance_at(304, now_ms - 1_000),
    )
    .await
    .unwrap()
    .unwrap();
    let mut rejected = settlement_authorization("chan-rejected-auth", 3);
    rejected.status = "rejected".to_string();
    insert_api_payment_settlement_authorization(&pool, rejected)
        .await
        .unwrap()
        .unwrap();

    let disabled =
        disable_api_payment_channels_missing_settlement_authorization(&pool, policy.clone())
            .await
            .unwrap();
    let disabled_ids: Vec<_> = disabled.iter().map(|row| row.channel_id.as_str()).collect();
    assert_eq!(disabled_ids.len(), 6);
    assert!(disabled_ids.contains(&"chan-missing-auth"));
    assert!(disabled_ids.contains(&"chan-close-missing-auth"));
    assert!(disabled_ids.contains(&"chan-stale-auth"));
    assert!(disabled_ids.contains(&"chan-bad-math-auth"));
    assert!(disabled_ids.contains(&"chan-expired-auth"));
    assert!(disabled_ids.contains(&"chan-rejected-auth"));
    assert!(!disabled_ids.contains(&"chan-safe-auth"));

    let safe = api_payment_channel_by_id(&pool, "chan-safe-auth")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(safe.status, "usable");

    for channel_id in [
        "chan-missing-auth",
        "chan-close-missing-auth",
        "chan-stale-auth",
        "chan-bad-math-auth",
        "chan-expired-auth",
        "chan-rejected-auth",
    ] {
        let row = api_payment_channel_by_id(&pool, channel_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "disabled");
        assert_eq!(row.updated_at_ms, now_ms);
        assert!(accept_api_payment_voucher(
            &pool,
            &voucher(channel_id, 2, 3_000),
            acceptance_at(400, now_ms + 1),
        )
        .await
        .unwrap()
        .is_none());
    }
    assert_eq!(
        close_request_status(&pool, "chan-close-missing-auth").await,
        "rejected"
    );

    let second = disable_api_payment_channels_missing_settlement_authorization(&pool, policy)
        .await
        .unwrap();
    assert!(second.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn submits_direct_payment_proof_and_reads_by_txid(pool: PgPool) {
    let txid = "44".repeat(32);
    let row = submit_api_direct_payment_proof(&pool, direct_proof("ch_direct_1", &txid))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(row.challenge_id, "ch_direct_1");
    assert_eq!(row.txid_hex, txid);
    assert_eq!(row.status, "submitted");
    assert_eq!(row.amount_sompi, 777);

    let found = api_direct_payment_proof_by_txid(&pool, &txid)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found, row);
}

#[sqlx::test(migrations = "./migrations")]
async fn rejects_direct_payment_replay_by_txid_or_challenge(pool: PgPool) {
    let first_txid = "45".repeat(32);
    let second_txid = "46".repeat(32);

    assert!(
        submit_api_direct_payment_proof(&pool, direct_proof("ch_direct_replay", &first_txid))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        submit_api_direct_payment_proof(&pool, direct_proof("ch_direct_other", &first_txid))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        submit_api_direct_payment_proof(&pool, direct_proof("ch_direct_replay", &second_txid))
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn updates_direct_payment_proof_status(pool: PgPool) {
    let txid = "47".repeat(32);
    submit_api_direct_payment_proof(&pool, direct_proof("ch_direct_update", &txid))
        .await
        .unwrap()
        .unwrap();

    let row = update_api_direct_payment_proof_status(
        &pool,
        ApiDirectPaymentProofStatusUpdate {
            txid_hex: txid.clone(),
            status: "accepted".to_string(),
            failure_reason: None,
            raw_status_snapshot: Some(serde_json::json!({
                "isAccepted": true,
                "payloadMatches": true,
                "outputMatches": true
            })),
            verified_at_ms: 1_780_000_020_000,
            indexed_at_ms: Some(1_780_000_020_000),
        },
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(row.txid_hex, txid);
    assert_eq!(row.status, "accepted");
    assert_eq!(row.verified_at_ms, Some(1_780_000_020_000));
    assert_eq!(row.indexed_at_ms, Some(1_780_000_020_000));
    assert_eq!(
        row.raw_status_snapshot
            .unwrap()
            .get("payloadMatches")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
}
