use crate::PgPool;
use anyhow::{ensure, Result};
use serde_json::Value;
use sqlx::{Executor, Postgres, Row};
use tn12_indexer_core::{
    ApiPaymentChannelCloseRequest, ApiPaymentSettlementArtifact, ApiPaymentSettlementAuthorization,
    ApiPaymentVoucher,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiPaymentChannel {
    pub channel_id: String,
    pub network_id: String,
    pub payer_identifier: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub provider_identifier: Option<String>,
    pub scope: Option<String>,
    pub deposit_sompi: i64,
    pub reserve_sompi: i64,
    pub status: String,
    pub open_txid_hex: Option<String>,
    pub refund_after_daa: Option<i64>,
    pub pricing_policy_id: Option<String>,
    pub indexed_at_ms: Option<i64>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentPricingRouteRow {
    pub pricing_id: String,
    pub method: String,
    pub path_pattern: String,
    pub base_sompi: i64,
    pub per_row_sompi: i64,
    pub max_limit: Option<i64>,
    pub enabled: bool,
    pub effective_from_ms: i64,
    pub effective_to_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentChannelRow {
    pub channel_id: String,
    pub network_id: String,
    pub payer_identifier: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub deposit_sompi: i64,
    pub reserve_sompi: i64,
    pub spent_sompi: i64,
    pub latest_sequence: i64,
    pub status: String,
    pub refund_after_ms: Option<i64>,
    pub close_after_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentChannelStatusRow {
    pub channel_id: String,
    pub network_id: String,
    pub payer_identifier: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub provider_payout_pubkey: Option<String>,
    pub voucher_domain_hash: Option<String>,
    pub deposit_sompi: i64,
    pub reserve_sompi: i64,
    pub spent_sompi: i64,
    pub latest_sequence: i64,
    pub status: String,
    pub open_txid: Option<String>,
    pub current_txid: Option<String>,
    pub current_vout: Option<i32>,
    pub settlement_txid: Option<String>,
    pub refund_txid: Option<String>,
    pub refund_after_ms: Option<i64>,
    pub close_after_ms: i64,
    pub max_spend_sompi: Option<i64>,
    pub indexed_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentChannelTxStatusRow {
    pub txid_hex: String,
    pub kind: String,
    pub channel_id: String,
    pub network_id: String,
    pub channel_status: String,
    pub settled_sequence: Option<i64>,
    pub settled_total_sompi: Option<i64>,
    pub provider_amount_sompi: Option<i64>,
    pub payer_refund_sompi: Option<i64>,
    pub indexer_status: Option<String>,
    pub created_at_ms: Option<i64>,
    pub indexed_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentVoucherAcceptance {
    pub credential_hash_hex: String,
    pub accepted_at_ms: i64,
    pub served_status: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiPaymentUsageEvent {
    pub request_id: String,
    pub channel_id: Option<String>,
    pub wallet_or_api_key_hash_hex: Option<String>,
    pub route: String,
    pub pricing_id: String,
    pub amount_sompi: i64,
    pub voucher_sequence: Option<i64>,
    pub receipt_id: String,
    pub response_status: Option<i32>,
    pub duration_ms: Option<i64>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentReceiptRow {
    pub id: i64,
    pub request_id: String,
    pub receipt_id: String,
    pub channel_id: Option<String>,
    pub route: String,
    pub pricing_id: String,
    pub amount_sompi: i64,
    pub voucher_sequence: Option<i64>,
    pub response_status: Option<i32>,
    pub duration_ms: Option<i64>,
    pub created_at_ms: i64,
    pub voucher_total_spent_sompi: Option<i64>,
    pub voucher_request_hash: Option<String>,
    pub voucher_accepted_at_ms: Option<i64>,
    pub channel_status: Option<String>,
    pub channel_spent_sompi: Option<i64>,
    pub channel_latest_sequence: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentSettlementCandidatePolicy {
    pub now_ms: i64,
    pub min_unsettled_sompi: i64,
    pub min_unsettled_sequences: i64,
    pub max_voucher_age_ms: i64,
    pub refund_safety_margin_ms: i64,
    pub limit: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentOpeningReconciliationPolicy {
    pub now_ms: i64,
    pub max_opening_age_ms: i64,
    pub limit: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentSettlementCandidateRow {
    pub channel_id: String,
    pub network_id: String,
    pub spent_sompi: i64,
    pub deposit_sompi: i64,
    pub reserve_sompi: i64,
    pub latest_sequence: i64,
    pub refund_after_ms: Option<i64>,
    pub updated_at_ms: i64,
    pub reason: String,
    pub latest_authorization_sequence: Option<i64>,
    pub latest_authorization_status: Option<String>,
    pub latest_authorization_expires_at_ms: Option<i64>,
    pub latest_authorization_settlement_txid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentDisabledChannelRow {
    pub channel_id: String,
    pub network_id: String,
    pub spent_sompi: i64,
    pub latest_sequence: i64,
    pub reason: String,
    pub disabled_at_ms: i64,
    pub latest_authorization_sequence: Option<i64>,
    pub latest_authorization_status: Option<String>,
    pub latest_authorization_expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentSettlementClaimRow {
    pub channel_id: String,
    pub network_id: String,
    pub reason: String,
    pub sequence: i64,
    pub total_spent_sompi: i64,
    pub provider_amount_sompi: i64,
    pub payer_refund_sompi: i64,
    pub settlement_fee_sompi: i64,
    pub settlement_txid: String,
    pub settlement_template_hash: String,
    pub metadata_hash: String,
    pub payer_settlement_signature: String,
    pub settlement_artifact_schema: Option<String>,
    pub unsigned_settlement_template: Option<String>,
    pub settlement_artifact_json: Option<Value>,
    pub refund_after_ms: i64,
    pub expires_at_ms: i64,
    pub claimed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentSettlementRejectionRow {
    pub channel_id: String,
    pub network_id: String,
    pub sequence: i64,
    pub settlement_txid: String,
    pub rejected_at_ms: i64,
    pub channel_status: String,
    pub authorization_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiPaymentChannelCloseRequest {
    pub request: ApiPaymentChannelCloseRequest,
    pub credential_hash_hex: String,
    pub status: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiPaymentSettlementAuthorization {
    pub authorization: ApiPaymentSettlementAuthorization,
    pub settlement_artifact: Option<ApiPaymentSettlementArtifact>,
    pub status: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPaymentSettlementAuthorizationRow {
    pub id: i64,
    pub channel_id: String,
    pub sequence: i64,
    pub total_spent_sompi: i64,
    pub provider_amount_sompi: i64,
    pub payer_refund_sompi: i64,
    pub settlement_fee_sompi: i64,
    pub settlement_txid: String,
    pub settlement_template_hash: String,
    pub metadata_hash: String,
    pub payer_settlement_signature: String,
    pub settlement_artifact_schema: Option<String>,
    pub unsigned_settlement_template: Option<String>,
    pub settlement_artifact_json: Option<Value>,
    pub refund_after_ms: i64,
    pub expires_at_ms: i64,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedApiPaymentChannelOpen {
    pub channel_id: String,
    pub network_id: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub provider_payout_pubkey: String,
    pub voucher_domain_hash: String,
    pub deposit_sompi: i64,
    pub reserve_sompi: i64,
    pub max_spend_sompi: i64,
    pub refund_after_ms: i64,
    pub close_after_ms: i64,
    pub open_txid_hex: String,
    pub indexed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedApiPaymentChannelSettlement {
    pub channel_id: String,
    pub txid_hex: String,
    pub settled_total_sompi: i64,
    pub provider_amount_sompi: i64,
    pub payer_refund_sompi: i64,
    pub indexed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedApiPaymentChannelContinuation {
    pub channel_id: String,
    pub txid_hex: String,
    pub vout: i32,
    pub deposit_sompi: i64,
    pub max_spend_sompi: i64,
    pub refund_after_ms: i64,
    pub indexed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedApiPaymentChannelCloseRequested {
    pub channel_id: String,
    pub txid_hex: String,
    pub vout: i32,
    pub deposit_sompi: i64,
    pub close_after_ms: i64,
    pub indexed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedApiPaymentChannelRefund {
    pub channel_id: String,
    pub txid_hex: String,
    pub indexed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiDirectPaymentProof {
    pub challenge_id: String,
    pub network_id: String,
    pub txid_hex: String,
    pub payer_identifier: Option<String>,
    pub recipient_address: String,
    pub amount_sompi: i64,
    pub pricing_id: String,
    pub route: String,
    pub request_hash: String,
    pub status: String,
    pub failure_reason: Option<String>,
    pub raw_status_snapshot: Option<Value>,
    pub submitted_at_ms: i64,
    pub verified_at_ms: Option<i64>,
    pub indexed_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiDirectPaymentProofRow {
    pub id: i64,
    pub challenge_id: String,
    pub network_id: String,
    pub txid_hex: String,
    pub payer_identifier: Option<String>,
    pub recipient_address: String,
    pub amount_sompi: i64,
    pub pricing_id: String,
    pub route: String,
    pub request_hash: String,
    pub status: String,
    pub failure_reason: Option<String>,
    pub raw_status_snapshot: Option<Value>,
    pub submitted_at_ms: i64,
    pub verified_at_ms: Option<i64>,
    pub indexed_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiDirectPaymentProofStatusUpdate {
    pub txid_hex: String,
    pub status: String,
    pub failure_reason: Option<String>,
    pub raw_status_snapshot: Option<Value>,
    pub verified_at_ms: i64,
    pub indexed_at_ms: Option<i64>,
}

pub async fn insert_api_payment_channel(
    pool: &PgPool,
    channel: NewApiPaymentChannel,
) -> Result<ApiPaymentChannelRow> {
    if channel.status == "usable" {
        ensure!(
            channel.open_txid_hex.is_some() && channel.indexed_at_ms.is_some(),
            "usable API payment channels require indexed open evidence"
        );
    }

    let row = sqlx::query(
        r#"
        INSERT INTO api_payment_channels (
            channel_id, network_id, payer_identifier, payer_pubkey,
            provider_pubkey, provider_identifier, scope, deposit_sompi,
            reserve_sompi, spent_sompi, latest_sequence, status, open_txid,
            refund_after_daa, pricing_policy_id, indexed_at_ms, created_at_ms,
            updated_at_ms, refund_after_ms, close_after_ms
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 0, $10,
            CASE WHEN $11::TEXT IS NULL THEN NULL ELSE decode($11, 'hex') END,
            $12, $13, $14, $15, $15,
            CASE WHEN $12 >= 500000000000 THEN $12 ELSE NULL END,
            0
        )
        RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                  provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                  latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        "#,
    )
    .bind(&channel.channel_id)
    .bind(&channel.network_id)
    .bind(&channel.payer_identifier)
    .bind(&channel.payer_pubkey)
    .bind(&channel.provider_pubkey)
    .bind(&channel.provider_identifier)
    .bind(&channel.scope)
    .bind(channel.deposit_sompi)
    .bind(channel.reserve_sompi)
    .bind(&channel.status)
    .bind(&channel.open_txid_hex)
    .bind(channel.refund_after_daa)
    .bind(&channel.pricing_policy_id)
    .bind(channel.indexed_at_ms)
    .bind(channel.now_ms)
    .fetch_one(pool)
    .await?;

    Ok(channel_row(row))
}

pub async fn api_payment_pricing_routes(
    pool: &PgPool,
    now_ms: i64,
) -> Result<Vec<ApiPaymentPricingRouteRow>> {
    let rows = sqlx::query(
        r#"
        SELECT pricing_id, method, path_pattern, base_sompi, per_row_sompi,
               max_limit, enabled, effective_from_ms, effective_to_ms
        FROM api_payment_pricing
        WHERE effective_from_ms <= $1
          AND (effective_to_ms IS NULL OR effective_to_ms > $1)
        ORDER BY method ASC, path_pattern ASC, pricing_id ASC
        "#,
    )
    .bind(now_ms)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(pricing_route_row).collect())
}

pub async fn api_payment_channel_by_id(
    pool: &PgPool,
    channel_id: &str,
) -> Result<Option<ApiPaymentChannelRow>> {
    let row = sqlx::query(
        r#"
        SELECT channel_id, network_id, payer_identifier, payer_pubkey,
               provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
               latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind(channel_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(channel_row))
}

pub async fn api_payment_channel_status_by_id(
    pool: &PgPool,
    channel_id: &str,
) -> Result<Option<ApiPaymentChannelStatusRow>> {
    let row = sqlx::query(
        r#"
        SELECT channel_id, network_id, payer_identifier, payer_pubkey,
               provider_pubkey, provider_payout_pubkey,
               encode(voucher_domain_hash, 'hex') AS voucher_domain_hash,
               deposit_sompi, reserve_sompi, spent_sompi,
               latest_sequence, status, encode(open_txid, 'hex') AS open_txid,
               encode(current_txid, 'hex') AS current_txid,
               current_vout,
               encode(settlement_txid, 'hex') AS settlement_txid,
               encode(refund_txid, 'hex') AS refund_txid,
               refund_after_ms, close_after_ms, max_spend_sompi, indexed_at_ms, updated_at_ms
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind(channel_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(channel_status_row))
}

pub async fn api_payment_channel_tx_status_by_txid(
    pool: &PgPool,
    txid_hex: &str,
) -> Result<Option<ApiPaymentChannelTxStatusRow>> {
    let row = sqlx::query(
        r#"
        WITH requested AS (
            SELECT decode($1, 'hex') AS txid
        ),
        settlement_rows AS (
            SELECT encode(s.txid, 'hex') AS txid_hex,
                   1::INT AS priority,
                   CASE
                       WHEN c.current_txid IS NOT NULL
                        AND c.current_txid IS DISTINCT FROM c.open_txid THEN 0
                       ELSE 1
                   END AS replay_rank,
                   'settlement'::TEXT AS kind,
                   s.channel_id,
                   c.network_id,
                   c.status AS channel_status,
                   s.settled_sequence,
                   s.settled_total_sompi,
                   s.provider_amount_sompi,
                   s.payer_refund_sompi,
                   s.indexer_status,
                   s.created_at_ms,
                   s.indexed_at_ms,
                   c.updated_at_ms
            FROM api_payment_settlements s
            JOIN api_payment_channels c ON c.channel_id = s.channel_id
            JOIN requested r ON r.txid = s.txid
        ),
        refund_rows AS (
            SELECT encode(c.refund_txid, 'hex') AS txid_hex,
                   2::INT AS priority,
                   CASE
                       WHEN c.current_txid IS NOT NULL
                        AND c.current_txid IS DISTINCT FROM c.open_txid THEN 0
                       ELSE 1
                   END AS replay_rank,
                   'refund'::TEXT AS kind,
                   c.channel_id,
                   c.network_id,
                   c.status AS channel_status,
                   NULL::BIGINT AS settled_sequence,
                   NULL::BIGINT AS settled_total_sompi,
                   NULL::BIGINT AS provider_amount_sompi,
                   NULL::BIGINT AS payer_refund_sompi,
                   'indexed'::TEXT AS indexer_status,
                   NULL::BIGINT AS created_at_ms,
                   c.indexed_at_ms,
                   c.updated_at_ms
            FROM api_payment_channels c
            JOIN requested r ON r.txid = c.refund_txid
        ),
        fallback_settlement_rows AS (
            SELECT encode(c.settlement_txid, 'hex') AS txid_hex,
                   3::INT AS priority,
                   CASE
                       WHEN c.current_txid IS NOT NULL
                        AND c.current_txid IS DISTINCT FROM c.open_txid THEN 0
                       ELSE 1
                   END AS replay_rank,
                   'settlement'::TEXT AS kind,
                   c.channel_id,
                   c.network_id,
                   c.status AS channel_status,
                   c.latest_sequence AS settled_sequence,
                   c.spent_sompi AS settled_total_sompi,
                   c.spent_sompi AS provider_amount_sompi,
                   GREATEST(c.deposit_sompi - c.spent_sompi, 0)::BIGINT AS payer_refund_sompi,
                   'indexed'::TEXT AS indexer_status,
                   NULL::BIGINT AS created_at_ms,
                   c.indexed_at_ms,
                   c.updated_at_ms
            FROM api_payment_channels c
            JOIN requested r ON r.txid = c.settlement_txid
            WHERE NOT EXISTS (SELECT 1 FROM settlement_rows)
        ),
        continuation_rows AS (
            SELECT encode(c.current_txid, 'hex') AS txid_hex,
                   4::INT AS priority,
                   CASE
                       WHEN c.current_txid IS NOT NULL
                        AND c.current_txid IS DISTINCT FROM c.open_txid THEN 0
                       ELSE 1
                   END AS replay_rank,
                   'continuation'::TEXT AS kind,
                   c.channel_id,
                   c.network_id,
                   c.status AS channel_status,
                   NULL::BIGINT AS settled_sequence,
                   NULL::BIGINT AS settled_total_sompi,
                   NULL::BIGINT AS provider_amount_sompi,
                   NULL::BIGINT AS payer_refund_sompi,
                   'indexed'::TEXT AS indexer_status,
                   NULL::BIGINT AS created_at_ms,
                   c.indexed_at_ms,
                   c.updated_at_ms
            FROM api_payment_channels c
            JOIN requested r ON r.txid = c.current_txid
            WHERE c.current_txid IS NOT NULL
              AND c.current_txid IS DISTINCT FROM c.open_txid
        ),
        open_rows AS (
            SELECT encode(c.open_txid, 'hex') AS txid_hex,
                   5::INT AS priority,
                   1::INT AS replay_rank,
                   'open'::TEXT AS kind,
                   c.channel_id,
                   c.network_id,
                   c.status AS channel_status,
                   NULL::BIGINT AS settled_sequence,
                   NULL::BIGINT AS settled_total_sompi,
                   NULL::BIGINT AS provider_amount_sompi,
                   NULL::BIGINT AS payer_refund_sompi,
                   'indexed'::TEXT AS indexer_status,
                   NULL::BIGINT AS created_at_ms,
                   c.indexed_at_ms,
                   c.updated_at_ms
            FROM api_payment_channels c
            JOIN requested r ON r.txid = c.open_txid
        ),
        combined AS (
            SELECT * FROM settlement_rows
            UNION ALL
            SELECT * FROM refund_rows
            UNION ALL
            SELECT * FROM fallback_settlement_rows
            UNION ALL
            SELECT * FROM continuation_rows
            UNION ALL
            SELECT * FROM open_rows
        )
        SELECT txid_hex, kind, channel_id, network_id, channel_status,
               settled_sequence, settled_total_sompi, provider_amount_sompi,
               payer_refund_sompi, indexer_status, created_at_ms, indexed_at_ms,
               updated_at_ms
        FROM combined
        ORDER BY priority, replay_rank, updated_at_ms DESC, channel_id ASC
        LIMIT 1
        "#,
    )
    .bind(txid_hex)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(channel_tx_status_row))
}

pub async fn upsert_indexed_api_payment_channel_open<'e, E>(
    executor: E,
    channel: IndexedApiPaymentChannelOpen,
) -> Result<ApiPaymentChannelRow>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        INSERT INTO api_payment_channels (
            channel_id, network_id, payer_identifier, payer_pubkey,
            provider_pubkey, provider_identifier, scope, deposit_sompi,
            reserve_sompi, spent_sompi, latest_sequence, status, open_txid,
            refund_after_daa, pricing_policy_id, indexed_at_ms, created_at_ms,
            updated_at_ms, provider_payout_pubkey, voucher_domain_hash,
            refund_after_ms, max_spend_sompi, close_after_ms, current_txid, current_vout
        )
        VALUES (
            $1, $2, $3, $3, $4, $4, NULL, $5, $6, 0, 0, 'usable',
            decode($7, 'hex'), $8, NULL, $9, $9, $9, $10, decode($11, 'hex'),
            $8, $12, $13, decode($7, 'hex'), 0
        )
        ON CONFLICT (channel_id) DO UPDATE
        SET network_id = EXCLUDED.network_id,
            payer_pubkey = EXCLUDED.payer_pubkey,
            provider_pubkey = EXCLUDED.provider_pubkey,
            deposit_sompi = EXCLUDED.deposit_sompi,
            reserve_sompi = EXCLUDED.reserve_sompi,
            open_txid = COALESCE(api_payment_channels.open_txid, EXCLUDED.open_txid),
            refund_after_daa = COALESCE(api_payment_channels.refund_after_daa, EXCLUDED.refund_after_daa),
            indexed_at_ms = GREATEST(COALESCE(api_payment_channels.indexed_at_ms, 0), EXCLUDED.indexed_at_ms),
            updated_at_ms = GREATEST(api_payment_channels.updated_at_ms, EXCLUDED.updated_at_ms),
            provider_payout_pubkey = EXCLUDED.provider_payout_pubkey,
            voucher_domain_hash = EXCLUDED.voucher_domain_hash,
            refund_after_ms = EXCLUDED.refund_after_ms,
            max_spend_sompi = EXCLUDED.max_spend_sompi,
            close_after_ms = EXCLUDED.close_after_ms,
            current_txid = COALESCE(api_payment_channels.current_txid, EXCLUDED.current_txid),
            current_vout = COALESCE(api_payment_channels.current_vout, EXCLUDED.current_vout),
            status = CASE
                WHEN api_payment_channels.status IN ('opening', 'usable') THEN 'usable'
                ELSE api_payment_channels.status
            END
        RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                  provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                  latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        "#,
    )
    .bind(&channel.channel_id)
    .bind(&channel.network_id)
    .bind(&channel.payer_pubkey)
    .bind(&channel.provider_pubkey)
    .bind(channel.deposit_sompi)
    .bind(channel.reserve_sompi)
    .bind(&channel.open_txid_hex)
    .bind(channel.refund_after_ms)
    .bind(channel.indexed_at_ms)
    .bind(&channel.provider_payout_pubkey)
    .bind(&channel.voucher_domain_hash)
    .bind(channel.max_spend_sompi)
    .bind(channel.close_after_ms)
    .fetch_one(executor)
    .await?;

    Ok(channel_row(row))
}

pub async fn apply_indexed_api_payment_channel_continuation<'e, E>(
    executor: E,
    continuation: IndexedApiPaymentChannelContinuation,
) -> Result<Option<ApiPaymentChannelRow>>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        UPDATE api_payment_channels
        SET deposit_sompi = $4,
            max_spend_sompi = $5,
            refund_after_ms = $6,
            close_after_ms = 0,
            current_txid = decode($2, 'hex'),
            current_vout = $3,
            indexed_at_ms = GREATEST(COALESCE(indexed_at_ms, 0), $7),
            updated_at_ms = GREATEST(updated_at_ms, $7),
            status = CASE
                WHEN status IN ('opening', 'usable') THEN 'usable'
                ELSE status
            END
        WHERE channel_id = $1
        RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                  provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                  latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        "#,
    )
    .bind(&continuation.channel_id)
    .bind(&continuation.txid_hex)
    .bind(continuation.vout)
    .bind(continuation.deposit_sompi)
    .bind(continuation.max_spend_sompi)
    .bind(continuation.refund_after_ms)
    .bind(continuation.indexed_at_ms)
    .fetch_optional(executor)
    .await?;

    Ok(row.map(channel_row))
}

pub async fn apply_indexed_api_payment_channel_close_requested<'e, E>(
    executor: E,
    close: IndexedApiPaymentChannelCloseRequested,
) -> Result<Option<ApiPaymentChannelRow>>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        UPDATE api_payment_channels
        SET deposit_sompi = $4,
            close_after_ms = $5,
            current_txid = decode($2, 'hex'),
            current_vout = $3,
            indexed_at_ms = GREATEST(COALESCE(indexed_at_ms, 0), $6),
            updated_at_ms = GREATEST(updated_at_ms, $6),
            status = CASE
                WHEN status IN ('opening', 'usable', 'close_requested') THEN 'close_requested'
                ELSE status
            END
        WHERE channel_id = $1
        RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                  provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                  latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        "#,
    )
    .bind(&close.channel_id)
    .bind(&close.txid_hex)
    .bind(close.vout)
    .bind(close.deposit_sompi)
    .bind(close.close_after_ms)
    .bind(close.indexed_at_ms)
    .fetch_optional(executor)
    .await?;

    Ok(row.map(channel_row))
}

pub async fn apply_indexed_api_payment_channel_settlement<'e, E>(
    executor: E,
    settlement: IndexedApiPaymentChannelSettlement,
) -> Result<Option<ApiPaymentChannelRow>>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        WITH updated AS (
            UPDATE api_payment_channels
            SET spent_sompi = GREATEST(spent_sompi, $3),
                status = CASE
                    WHEN status = 'disabled' THEN status
                    ELSE 'settled'
                END,
                settlement_txid = decode($2, 'hex'),
                indexed_at_ms = GREATEST(COALESCE(indexed_at_ms, 0), $6),
                updated_at_ms = GREATEST(updated_at_ms, $6)
            WHERE channel_id = $1
            RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                      provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                      latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        ),
        inserted AS (
            INSERT INTO api_payment_settlements (
                txid, channel_id, settled_sequence, settled_total_sompi,
                provider_amount_sompi, payer_refund_sompi, indexer_status,
                created_at_ms, indexed_at_ms
            )
            SELECT decode($2, 'hex'), channel_id, latest_sequence, $3, $4, $5,
                   'indexed', $6, $6
            FROM updated
            ON CONFLICT (txid) DO UPDATE
            SET channel_id = EXCLUDED.channel_id,
                settled_sequence = EXCLUDED.settled_sequence,
                settled_total_sompi = EXCLUDED.settled_total_sompi,
                provider_amount_sompi = EXCLUDED.provider_amount_sompi,
                payer_refund_sompi = EXCLUDED.payer_refund_sompi,
                indexer_status = EXCLUDED.indexer_status,
                indexed_at_ms = GREATEST(api_payment_settlements.indexed_at_ms, EXCLUDED.indexed_at_ms)
        ),
        finalized_authorization AS (
            UPDATE api_payment_settlement_authorizations
            SET status = 'spent',
                updated_at_ms = GREATEST(updated_at_ms, $6)
            WHERE settlement_txid = decode($2, 'hex')
              AND status IN ('available', 'submitted')
        )
        SELECT * FROM updated
        "#,
    )
    .bind(&settlement.channel_id)
    .bind(&settlement.txid_hex)
    .bind(settlement.settled_total_sompi)
    .bind(settlement.provider_amount_sompi)
    .bind(settlement.payer_refund_sompi)
    .bind(settlement.indexed_at_ms)
    .fetch_optional(executor)
    .await?;

    Ok(row.map(channel_row))
}

pub async fn apply_indexed_api_payment_channel_refund<'e, E>(
    executor: E,
    refund: IndexedApiPaymentChannelRefund,
) -> Result<Option<ApiPaymentChannelRow>>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        UPDATE api_payment_channels
        SET status = 'refunded',
            refund_txid = decode($2, 'hex'),
            indexed_at_ms = GREATEST(COALESCE(indexed_at_ms, 0), $3),
            updated_at_ms = GREATEST(updated_at_ms, $3)
        WHERE channel_id = $1
        RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                  provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                  latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        "#,
    )
    .bind(&refund.channel_id)
    .bind(&refund.txid_hex)
    .bind(refund.indexed_at_ms)
    .fetch_optional(executor)
    .await?;

    Ok(row.map(channel_row))
}

pub async fn accept_api_payment_voucher(
    pool: &PgPool,
    voucher: &ApiPaymentVoucher,
    acceptance: ApiPaymentVoucherAcceptance,
) -> Result<Option<ApiPaymentChannelRow>> {
    let mut tx = pool.begin().await?;

    let updated = sqlx::query(
        r#"
        UPDATE api_payment_channels
        SET spent_sompi = $2,
            latest_sequence = $3,
            updated_at_ms = $4
        WHERE channel_id = $1
          AND status = 'usable'
          AND $3 > latest_sequence
          AND $2 > spent_sompi
          AND $2 <= deposit_sompi - reserve_sompi
        RETURNING channel_id, network_id, payer_identifier, payer_pubkey,
                  provider_pubkey, deposit_sompi, reserve_sompi, spent_sompi,
                  latest_sequence, status, refund_after_ms, close_after_ms, updated_at_ms
        "#,
    )
    .bind(&voucher.channel_id)
    .bind(voucher.total_spent_sompi as i64)
    .bind(voucher.sequence as i64)
    .bind(acceptance.accepted_at_ms)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(updated) = updated else {
        tx.rollback().await?;
        return Ok(None);
    };

    sqlx::query(
        r#"
        INSERT INTO api_payment_vouchers (
            channel_id, sequence, total_spent_sompi, incremental_amount_sompi,
            pricing_id, request_hash, route, credential_hash, signature,
            accepted_at_ms, served_status
        )
        VALUES (
            $1, $2, $3, $4, $5, decode($6, 'hex'), $7, decode($8, 'hex'),
            $9, $10, $11
        )
        "#,
    )
    .bind(&voucher.channel_id)
    .bind(voucher.sequence as i64)
    .bind(voucher.total_spent_sompi as i64)
    .bind(voucher.incremental_amount_sompi as i64)
    .bind(&voucher.pricing_id)
    .bind(&voucher.request_hash)
    .bind(&voucher.route)
    .bind(&acceptance.credential_hash_hex)
    .bind(&voucher.signature)
    .bind(acceptance.accepted_at_ms)
    .bind(acceptance.served_status)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(channel_row(updated)))
}

pub async fn record_api_payment_usage_event(
    pool: &PgPool,
    event: NewApiPaymentUsageEvent,
) -> Result<Option<ApiPaymentReceiptRow>> {
    let inserted = sqlx::query(
        r#"
        INSERT INTO api_payment_usage_events (
            request_id, channel_id, wallet_or_api_key_hash, route, pricing_id,
            amount_sompi, voucher_sequence, receipt_id, response_status,
            duration_ms, created_at_ms
        )
        VALUES (
            $1, $2, CASE WHEN $3 IS NULL THEN NULL ELSE decode($3, 'hex') END,
            $4, $5, $6, $7, $8, $9, $10, $11
        )
        ON CONFLICT (request_id) DO NOTHING
        RETURNING receipt_id
        "#,
    )
    .bind(&event.request_id)
    .bind(&event.channel_id)
    .bind(&event.wallet_or_api_key_hash_hex)
    .bind(&event.route)
    .bind(&event.pricing_id)
    .bind(event.amount_sompi)
    .bind(event.voucher_sequence)
    .bind(&event.receipt_id)
    .bind(event.response_status)
    .bind(event.duration_ms)
    .bind(event.created_at_ms)
    .fetch_optional(pool)
    .await?;

    if inserted.is_none() {
        return Ok(None);
    }
    api_payment_receipt_by_id(pool, &event.receipt_id).await
}

pub async fn api_payment_receipt_by_id(
    pool: &PgPool,
    receipt_id: &str,
) -> Result<Option<ApiPaymentReceiptRow>> {
    let row = sqlx::query(
        r#"
        SELECT e.id,
               e.request_id,
               e.receipt_id,
               e.channel_id,
               e.route,
               e.pricing_id,
               e.amount_sompi,
               e.voucher_sequence,
               e.response_status,
               e.duration_ms,
               e.created_at_ms,
               v.total_spent_sompi AS voucher_total_spent_sompi,
               encode(v.request_hash, 'hex') AS voucher_request_hash,
               v.accepted_at_ms AS voucher_accepted_at_ms,
               c.status AS channel_status,
               c.spent_sompi AS channel_spent_sompi,
               c.latest_sequence AS channel_latest_sequence
        FROM api_payment_usage_events e
        LEFT JOIN api_payment_vouchers v
          ON v.channel_id = e.channel_id
         AND v.sequence = e.voucher_sequence
        LEFT JOIN api_payment_channels c
          ON c.channel_id = e.channel_id
        WHERE e.receipt_id = $1
        "#,
    )
    .bind(receipt_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(payment_receipt_row))
}

pub async fn insert_api_payment_settlement_authorization(
    pool: &PgPool,
    new: NewApiPaymentSettlementAuthorization,
) -> Result<Option<ApiPaymentSettlementAuthorizationRow>> {
    let auth = new.authorization;
    ensure!(
        auth.expires_at_ms < auth.refund_after_ms,
        "settlement authorization expires at or after refund window"
    );
    if let Some(artifact) = new.settlement_artifact.as_ref() {
        artifact.validate_static()?;
        ensure!(
            artifact.authorization == auth,
            "settlement artifact authorization does not match stored authorization"
        );
    }
    let metadata_hash = auth.metadata_digest_hex();
    let settlement_artifact_schema = new
        .settlement_artifact
        .as_ref()
        .map(|artifact| artifact.schema.as_str());
    let unsigned_settlement_template = new
        .settlement_artifact
        .as_ref()
        .map(|artifact| serde_json::to_string(&artifact.unsigned_settlement_template))
        .transpose()?;
    let settlement_artifact_json = new
        .settlement_artifact
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    let row = sqlx::query(
        r#"
        INSERT INTO api_payment_settlement_authorizations (
            channel_id, sequence, total_spent_sompi, provider_amount_sompi,
            payer_refund_sompi, settlement_fee_sompi, settlement_txid,
            settlement_template_hash, metadata_hash, payer_settlement_signature,
            settlement_artifact_schema, unsigned_settlement_template,
            settlement_artifact_json, refund_after_ms, expires_at_ms, status,
            created_at_ms, updated_at_ms
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, decode($7, 'hex'), decode($8, 'hex'),
            decode($9, 'hex'), $10, $11, $12, $13, $14, $15, $16, $17, $17
        )
        ON CONFLICT DO NOTHING
        RETURNING id, channel_id, sequence, total_spent_sompi,
                  provider_amount_sompi, payer_refund_sompi,
                  settlement_fee_sompi, encode(settlement_txid, 'hex') AS settlement_txid,
                  encode(settlement_template_hash, 'hex') AS settlement_template_hash,
                  encode(metadata_hash, 'hex') AS metadata_hash,
                  payer_settlement_signature, settlement_artifact_schema,
                  unsigned_settlement_template, settlement_artifact_json,
                  refund_after_ms, expires_at_ms, status, created_at_ms,
                  updated_at_ms
        "#,
    )
    .bind(&auth.channel_id)
    .bind(auth.sequence as i64)
    .bind(auth.total_spent_sompi as i64)
    .bind(auth.provider_amount_sompi as i64)
    .bind(auth.payer_refund_sompi as i64)
    .bind(auth.settlement_fee_sompi as i64)
    .bind(&auth.settlement_txid)
    .bind(&auth.settlement_template_hash)
    .bind(&metadata_hash)
    .bind(&auth.payer_settlement_signature)
    .bind(settlement_artifact_schema)
    .bind(unsigned_settlement_template.as_deref())
    .bind(settlement_artifact_json)
    .bind(auth.refund_after_ms as i64)
    .bind(auth.expires_at_ms as i64)
    .bind(&new.status)
    .bind(new.created_at_ms)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(settlement_authorization_row))
}

pub async fn latest_api_payment_settlement_authorization(
    pool: &PgPool,
    channel_id: &str,
) -> Result<Option<ApiPaymentSettlementAuthorizationRow>> {
    let row = sqlx::query(
        r#"
        SELECT id, channel_id, sequence, total_spent_sompi,
               provider_amount_sompi, payer_refund_sompi,
               settlement_fee_sompi, encode(settlement_txid, 'hex') AS settlement_txid,
               encode(settlement_template_hash, 'hex') AS settlement_template_hash,
               encode(metadata_hash, 'hex') AS metadata_hash,
               payer_settlement_signature, settlement_artifact_schema,
               unsigned_settlement_template, settlement_artifact_json,
               refund_after_ms, expires_at_ms, status, created_at_ms,
               updated_at_ms
        FROM api_payment_settlement_authorizations
        WHERE channel_id = $1
        ORDER BY sequence DESC, id DESC
        LIMIT 1
        "#,
    )
    .bind(channel_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(settlement_authorization_row))
}

pub async fn request_api_payment_channel_close(
    pool: &PgPool,
    new: NewApiPaymentChannelCloseRequest,
) -> Result<Option<ApiPaymentChannelStatusRow>> {
    ensure!(
        new.request.expires_at_ms > new.request.requested_at_ms,
        "close request expires before or at request time"
    );
    let queued = sqlx::query_scalar::<_, bool>(
        r#"
        WITH candidate AS (
            SELECT channel_id
            FROM api_payment_channels
            WHERE channel_id = $1
              AND status IN ('usable', 'close_requested')
              AND spent_sompi > 0
            FOR UPDATE
        ),
        inserted_request AS (
            INSERT INTO api_payment_channel_close_requests (
                channel_id, credential_hash, payer_pubkey, provider_pubkey,
                requested_at_ms, expires_at_ms, nonce, reason, signature,
                status, created_at_ms, updated_at_ms
            )
            SELECT $1, decode($2, 'hex'), $3, $4, $5, $6, $7, $8, $9,
                   $10, $11, $11
            FROM candidate
            ON CONFLICT (credential_hash) DO NOTHING
            RETURNING channel_id
        ),
        updated_channel AS (
            UPDATE api_payment_channels c
            SET status = 'close_requested',
                updated_at_ms = GREATEST(c.updated_at_ms, $11::BIGINT)
            FROM candidate
            WHERE c.channel_id = candidate.channel_id
              AND c.status = 'usable'
            RETURNING c.channel_id
        )
        SELECT EXISTS (SELECT 1 FROM candidate)
        "#,
    )
    .bind(&new.request.channel_id)
    .bind(&new.credential_hash_hex)
    .bind(&new.request.payer_pubkey)
    .bind(&new.request.provider_pubkey)
    .bind(new.request.requested_at_ms as i64)
    .bind(new.request.expires_at_ms as i64)
    .bind(&new.request.nonce)
    .bind(&new.request.reason)
    .bind(&new.request.signature)
    .bind(&new.status)
    .bind(new.created_at_ms)
    .fetch_one(pool)
    .await?;

    if !queued {
        return Ok(None);
    }

    api_payment_channel_status_by_id(pool, &new.request.channel_id).await
}

pub async fn api_payment_settlement_candidates(
    pool: &PgPool,
    policy: ApiPaymentSettlementCandidatePolicy,
) -> Result<Vec<ApiPaymentSettlementCandidateRow>> {
    let limit = policy.limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"
        WITH latest_auth AS (
            SELECT DISTINCT ON (channel_id)
                   channel_id,
                   sequence,
                   status,
                   expires_at_ms,
                   encode(settlement_txid, 'hex') AS settlement_txid
            FROM api_payment_settlement_authorizations
            ORDER BY channel_id, sequence DESC, id DESC
        )
        SELECT c.channel_id,
               c.network_id,
               c.spent_sompi,
               c.deposit_sompi,
               c.reserve_sompi,
               c.latest_sequence,
               c.refund_after_ms,
               c.updated_at_ms,
               CASE
                   WHEN c.status = 'close_requested'
                        THEN 'close_requested'
                   WHEN $5::BIGINT > 0
                    AND c.refund_after_ms IS NOT NULL
                    AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT
                        THEN 'refund_window'
                   WHEN $2::BIGINT > 0
                    AND c.spent_sompi >= $2::BIGINT
                        THEN 'unsettled_sompi'
                   WHEN $3::BIGINT > 0
                    AND c.latest_sequence >= $3::BIGINT
                        THEN 'unsettled_sequence'
                   ELSE 'voucher_age'
               END AS reason,
               latest_auth.sequence AS latest_authorization_sequence,
               latest_auth.status AS latest_authorization_status,
               latest_auth.expires_at_ms AS latest_authorization_expires_at_ms,
               latest_auth.settlement_txid AS latest_authorization_settlement_txid
        FROM api_payment_channels c
        LEFT JOIN latest_auth ON latest_auth.channel_id = c.channel_id
        WHERE c.status IN ('usable', 'close_requested')
          AND c.spent_sompi > 0
          AND (
              c.status = 'close_requested'
           OR ($5::BIGINT > 0
               AND c.refund_after_ms IS NOT NULL
               AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT)
           OR ($2::BIGINT > 0 AND c.spent_sompi >= $2::BIGINT)
           OR ($3::BIGINT > 0 AND c.latest_sequence >= $3::BIGINT)
           OR ($4::BIGINT > 0 AND c.updated_at_ms <= $1::BIGINT - $4::BIGINT)
          )
        ORDER BY
            CASE
                WHEN c.status = 'close_requested'
                    THEN 0
                WHEN $5::BIGINT > 0
                 AND c.refund_after_ms IS NOT NULL
                 AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT
                    THEN 1
                WHEN $2::BIGINT > 0 AND c.spent_sompi >= $2::BIGINT
                    THEN 2
                WHEN $3::BIGINT > 0 AND c.latest_sequence >= $3::BIGINT
                    THEN 3
                ELSE 3
            END,
            c.refund_after_ms ASC NULLS LAST,
            c.spent_sompi DESC,
            c.latest_sequence DESC,
            c.updated_at_ms ASC,
            c.channel_id ASC
        LIMIT $6
        "#,
    )
    .bind(policy.now_ms)
    .bind(policy.min_unsettled_sompi)
    .bind(policy.min_unsettled_sequences)
    .bind(policy.max_voucher_age_ms)
    .bind(policy.refund_safety_margin_ms)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(settlement_candidate_row).collect())
}

pub async fn api_payment_stale_opening_channels(
    pool: &PgPool,
    policy: ApiPaymentOpeningReconciliationPolicy,
) -> Result<Vec<ApiPaymentDisabledChannelRow>> {
    ensure!(
        policy.max_opening_age_ms > 0,
        "max opening age must be positive"
    );
    let limit = policy.limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"
        SELECT channel_id,
               network_id,
               spent_sompi,
               latest_sequence,
               CASE
                   WHEN open_txid IS NULL THEN 'open_txid_missing'
                   ELSE 'open_not_indexed'
               END AS reason,
               $1::BIGINT AS disabled_at_ms,
               NULL::BIGINT AS latest_authorization_sequence,
               NULL::TEXT AS latest_authorization_status,
               NULL::BIGINT AS latest_authorization_expires_at_ms
        FROM api_payment_channels
        WHERE status = 'opening'
          AND created_at_ms <= $1::BIGINT - $2::BIGINT
        ORDER BY created_at_ms ASC, channel_id ASC
        LIMIT $3
        "#,
    )
    .bind(policy.now_ms)
    .bind(policy.max_opening_age_ms)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(disabled_channel_row).collect())
}

pub async fn disable_api_payment_stale_opening_channels(
    pool: &PgPool,
    policy: ApiPaymentOpeningReconciliationPolicy,
) -> Result<Vec<ApiPaymentDisabledChannelRow>> {
    ensure!(
        policy.max_opening_age_ms > 0,
        "max opening age must be positive"
    );
    let limit = policy.limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"
        WITH candidates AS (
            SELECT channel_id,
                   network_id,
                   spent_sompi,
                   latest_sequence,
                   CASE
                       WHEN open_txid IS NULL THEN 'open_txid_missing'
                       ELSE 'open_not_indexed'
                   END AS reason
            FROM api_payment_channels
            WHERE status = 'opening'
              AND created_at_ms <= $1::BIGINT - $2::BIGINT
            ORDER BY created_at_ms ASC, channel_id ASC
            LIMIT $3
            FOR UPDATE SKIP LOCKED
        ),
        updated AS (
            UPDATE api_payment_channels c
            SET status = 'disabled',
                updated_at_ms = GREATEST(c.updated_at_ms, $1::BIGINT)
            FROM candidates
            WHERE c.channel_id = candidates.channel_id
              AND c.status = 'opening'
            RETURNING c.channel_id,
                      c.network_id,
                      c.spent_sompi,
                      c.latest_sequence,
                      candidates.reason,
                      c.updated_at_ms AS disabled_at_ms,
                      NULL::BIGINT AS latest_authorization_sequence,
                      NULL::TEXT AS latest_authorization_status,
                      NULL::BIGINT AS latest_authorization_expires_at_ms
        )
        SELECT * FROM updated
        ORDER BY disabled_at_ms ASC, channel_id ASC
        "#,
    )
    .bind(policy.now_ms)
    .bind(policy.max_opening_age_ms)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(disabled_channel_row).collect())
}

pub async fn disable_api_payment_channels_missing_settlement_authorization(
    pool: &PgPool,
    policy: ApiPaymentSettlementCandidatePolicy,
) -> Result<Vec<ApiPaymentDisabledChannelRow>> {
    let limit = policy.limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"
        WITH latest_auth AS (
            SELECT DISTINCT ON (channel_id)
                   channel_id,
                   sequence,
                   total_spent_sompi,
                   provider_amount_sompi,
                   payer_refund_sompi,
                   settlement_fee_sompi,
                   refund_after_ms,
                   status,
                   expires_at_ms
            FROM api_payment_settlement_authorizations
            ORDER BY channel_id, sequence DESC, id DESC
        ),
        candidates AS (
            SELECT c.channel_id,
                   c.network_id,
                   c.spent_sompi,
                   c.latest_sequence,
                   c.updated_at_ms,
                   CASE
                       WHEN c.status = 'close_requested'
                            THEN 'close_requested'
                       WHEN $5::BIGINT > 0
                        AND c.refund_after_ms IS NOT NULL
                        AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT
                            THEN 'refund_window'
                       WHEN $2::BIGINT > 0
                        AND c.spent_sompi >= $2::BIGINT
                            THEN 'unsettled_sompi'
                       WHEN $3::BIGINT > 0
                        AND c.latest_sequence >= $3::BIGINT
                            THEN 'unsettled_sequence'
                       ELSE 'voucher_age'
                   END AS reason,
                   latest_auth.sequence AS latest_authorization_sequence,
                   latest_auth.status AS latest_authorization_status,
                   latest_auth.expires_at_ms AS latest_authorization_expires_at_ms
            FROM api_payment_channels c
            LEFT JOIN latest_auth ON latest_auth.channel_id = c.channel_id
            WHERE c.status IN ('usable', 'close_requested')
              AND c.spent_sompi > 0
              AND (
                  c.status = 'close_requested'
               OR ($5::BIGINT > 0
                   AND c.refund_after_ms IS NOT NULL
                   AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT)
               OR ($2::BIGINT > 0 AND c.spent_sompi >= $2::BIGINT)
               OR ($3::BIGINT > 0 AND c.latest_sequence >= $3::BIGINT)
               OR ($4::BIGINT > 0 AND c.updated_at_ms <= $1::BIGINT - $4::BIGINT)
              )
              AND (
                  latest_auth.sequence IS NULL
               OR latest_auth.status <> 'available'
               OR latest_auth.expires_at_ms <= $1::BIGINT
               OR latest_auth.sequence <> c.latest_sequence
               OR latest_auth.total_spent_sompi <> c.spent_sompi
               OR latest_auth.provider_amount_sompi <> c.spent_sompi
               OR latest_auth.provider_amount_sompi
                  + latest_auth.payer_refund_sompi
                  + latest_auth.settlement_fee_sompi <> c.deposit_sompi
               OR (
                    c.refund_after_ms IS NOT NULL
                AND latest_auth.refund_after_ms <> c.refund_after_ms
               )
              )
            ORDER BY
                CASE
                    WHEN c.status = 'close_requested'
                        THEN 0
                    WHEN $5::BIGINT > 0
                     AND c.refund_after_ms IS NOT NULL
                     AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT
                        THEN 1
                    WHEN $2::BIGINT > 0 AND c.spent_sompi >= $2::BIGINT
                        THEN 2
                    WHEN $3::BIGINT > 0 AND c.latest_sequence >= $3::BIGINT
                        THEN 3
                    ELSE 3
                END,
                c.updated_at_ms ASC,
                c.channel_id ASC
            LIMIT $6
        ),
        updated AS (
            UPDATE api_payment_channels c
            SET status = 'disabled',
                updated_at_ms = GREATEST(c.updated_at_ms, $1::BIGINT)
            FROM candidates
            WHERE c.channel_id = candidates.channel_id
            RETURNING c.channel_id,
                      c.network_id,
                      c.spent_sompi,
                      c.latest_sequence,
                      candidates.reason,
                      c.updated_at_ms AS disabled_at_ms,
                      candidates.latest_authorization_sequence,
                      candidates.latest_authorization_status,
                      candidates.latest_authorization_expires_at_ms
        ),
        updated_close_requests AS (
            UPDATE api_payment_channel_close_requests r
            SET status = 'rejected',
                updated_at_ms = GREATEST(r.updated_at_ms, $1::BIGINT)
            FROM updated
            WHERE r.channel_id = updated.channel_id
              AND updated.reason = 'close_requested'
              AND r.status = 'requested'
            RETURNING r.channel_id
        )
        SELECT updated.*,
               (SELECT COUNT(*) FROM updated_close_requests) AS close_requests_updated_count
        FROM updated
        ORDER BY disabled_at_ms ASC, channel_id ASC
        "#,
    )
    .bind(policy.now_ms)
    .bind(policy.min_unsettled_sompi)
    .bind(policy.min_unsettled_sequences)
    .bind(policy.max_voucher_age_ms)
    .bind(policy.refund_safety_margin_ms)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(disabled_channel_row).collect())
}

pub async fn claim_api_payment_settlement_authorizations(
    pool: &PgPool,
    policy: ApiPaymentSettlementCandidatePolicy,
) -> Result<Vec<ApiPaymentSettlementClaimRow>> {
    let limit = policy.limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"
        WITH latest_auth AS (
            SELECT DISTINCT ON (channel_id)
                   id,
                   channel_id,
                   sequence,
                   total_spent_sompi,
                   provider_amount_sompi,
                   payer_refund_sompi,
                   settlement_fee_sompi,
                   encode(settlement_txid, 'hex') AS settlement_txid,
                   encode(settlement_template_hash, 'hex') AS settlement_template_hash,
                   encode(metadata_hash, 'hex') AS metadata_hash,
                   payer_settlement_signature,
                   settlement_artifact_schema,
                   unsigned_settlement_template,
                   settlement_artifact_json,
                   refund_after_ms,
                   expires_at_ms,
                   status
            FROM api_payment_settlement_authorizations
            ORDER BY channel_id, sequence DESC, id DESC
        ),
        candidates AS (
            SELECT c.channel_id,
                   c.network_id,
                   CASE
                       WHEN c.status = 'close_requested'
                            THEN 'close_requested'
                       WHEN $5::BIGINT > 0
                        AND c.refund_after_ms IS NOT NULL
                        AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT
                            THEN 'refund_window'
                       WHEN $2::BIGINT > 0
                        AND c.spent_sompi >= $2::BIGINT
                            THEN 'unsettled_sompi'
                       WHEN $3::BIGINT > 0
                        AND c.latest_sequence >= $3::BIGINT
                            THEN 'unsettled_sequence'
                       ELSE 'voucher_age'
                   END AS reason,
                   latest_auth.id AS authorization_id,
                   latest_auth.sequence,
                   latest_auth.total_spent_sompi,
                   latest_auth.provider_amount_sompi,
                   latest_auth.payer_refund_sompi,
                   latest_auth.settlement_fee_sompi,
                   latest_auth.settlement_txid,
                   latest_auth.settlement_template_hash,
                   latest_auth.metadata_hash,
                   latest_auth.payer_settlement_signature,
                   latest_auth.settlement_artifact_schema,
                   latest_auth.unsigned_settlement_template,
                   latest_auth.settlement_artifact_json,
                   latest_auth.refund_after_ms,
                   latest_auth.expires_at_ms
            FROM api_payment_channels c
            JOIN latest_auth ON latest_auth.channel_id = c.channel_id
            WHERE c.status IN ('usable', 'close_requested')
              AND c.spent_sompi > 0
              AND latest_auth.status = 'available'
              AND latest_auth.expires_at_ms > $1::BIGINT
              AND latest_auth.sequence = c.latest_sequence
              AND latest_auth.total_spent_sompi = c.spent_sompi
              AND latest_auth.provider_amount_sompi = c.spent_sompi
              AND latest_auth.provider_amount_sompi
                 + latest_auth.payer_refund_sompi
                 + latest_auth.settlement_fee_sompi = c.deposit_sompi
              AND (
                   c.refund_after_ms IS NULL
                OR latest_auth.refund_after_ms = c.refund_after_ms
              )
              AND (
                  c.status = 'close_requested'
               OR ($5::BIGINT > 0
                   AND c.refund_after_ms IS NOT NULL
                   AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT)
               OR ($2::BIGINT > 0 AND c.spent_sompi >= $2::BIGINT)
               OR ($3::BIGINT > 0 AND c.latest_sequence >= $3::BIGINT)
               OR ($4::BIGINT > 0 AND c.updated_at_ms <= $1::BIGINT - $4::BIGINT)
              )
            ORDER BY
                CASE
                    WHEN c.status = 'close_requested'
                        THEN 0
                    WHEN $5::BIGINT > 0
                     AND c.refund_after_ms IS NOT NULL
                     AND c.refund_after_ms <= $1::BIGINT + $5::BIGINT
                        THEN 1
                    WHEN $2::BIGINT > 0 AND c.spent_sompi >= $2::BIGINT
                        THEN 2
                    WHEN $3::BIGINT > 0 AND c.latest_sequence >= $3::BIGINT
                        THEN 3
                    ELSE 3
                END,
                c.refund_after_ms ASC NULLS LAST,
                c.spent_sompi DESC,
                c.latest_sequence DESC,
                c.updated_at_ms ASC,
                c.channel_id ASC
            LIMIT $6
            FOR UPDATE OF c SKIP LOCKED
        ),
        updated_channels AS (
            UPDATE api_payment_channels c
            SET status = 'settlement_pending',
                updated_at_ms = GREATEST(c.updated_at_ms, $1::BIGINT)
            FROM candidates
            WHERE c.channel_id = candidates.channel_id
              AND c.status IN ('usable', 'close_requested')
            RETURNING c.channel_id
        ),
        updated_authorizations AS (
            UPDATE api_payment_settlement_authorizations a
            SET status = 'submitted',
                updated_at_ms = GREATEST(a.updated_at_ms, $1::BIGINT)
            FROM candidates
            JOIN updated_channels ON updated_channels.channel_id = candidates.channel_id
            WHERE a.id = candidates.authorization_id
              AND a.status = 'available'
            RETURNING a.id
        ),
        updated_close_requests AS (
            UPDATE api_payment_channel_close_requests r
            SET status = 'claimed',
                updated_at_ms = GREATEST(r.updated_at_ms, $1::BIGINT)
            FROM candidates
            JOIN updated_channels ON updated_channels.channel_id = candidates.channel_id
            JOIN updated_authorizations ON updated_authorizations.id = candidates.authorization_id
            WHERE r.channel_id = candidates.channel_id
              AND candidates.reason = 'close_requested'
              AND r.status = 'requested'
            RETURNING r.channel_id
        )
        SELECT candidates.channel_id,
               candidates.network_id,
               candidates.reason,
               candidates.sequence,
               candidates.total_spent_sompi,
               candidates.provider_amount_sompi,
               candidates.payer_refund_sompi,
               candidates.settlement_fee_sompi,
               candidates.settlement_txid,
               candidates.settlement_template_hash,
               candidates.metadata_hash,
               candidates.payer_settlement_signature,
               candidates.settlement_artifact_schema,
               candidates.unsigned_settlement_template,
               candidates.settlement_artifact_json,
               candidates.refund_after_ms,
               candidates.expires_at_ms,
               $1::BIGINT AS claimed_at_ms,
               (SELECT COUNT(*) FROM updated_close_requests) AS close_requests_updated_count
        FROM candidates
        JOIN updated_authorizations
          ON updated_authorizations.id = candidates.authorization_id
        WHERE EXISTS (
            SELECT 1
            FROM updated_channels
            WHERE updated_channels.channel_id = candidates.channel_id
        )
        ORDER BY claimed_at_ms ASC, channel_id ASC
        "#,
    )
    .bind(policy.now_ms)
    .bind(policy.min_unsettled_sompi)
    .bind(policy.min_unsettled_sequences)
    .bind(policy.max_voucher_age_ms)
    .bind(policy.refund_safety_margin_ms)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(settlement_claim_row).collect())
}

pub async fn reject_api_payment_submitted_settlement(
    pool: &PgPool,
    settlement_txid: &str,
    rejected_at_ms: i64,
) -> Result<Option<ApiPaymentSettlementRejectionRow>> {
    let row = sqlx::query(
        r#"
        WITH rejected_auth AS (
            UPDATE api_payment_settlement_authorizations
            SET status = 'rejected',
                updated_at_ms = GREATEST(updated_at_ms, $2)
            WHERE settlement_txid = decode($1, 'hex')
              AND status = 'submitted'
            RETURNING channel_id,
                      sequence,
                      encode(settlement_txid, 'hex') AS settlement_txid,
                      status AS authorization_status
        ),
        disabled_channel AS (
            UPDATE api_payment_channels c
            SET status = 'disabled',
                updated_at_ms = GREATEST(c.updated_at_ms, $2)
            FROM rejected_auth
            WHERE c.channel_id = rejected_auth.channel_id
              AND c.status IN ('usable', 'settlement_pending')
            RETURNING c.channel_id,
                      c.network_id,
                      c.status AS channel_status
        ),
        updated_close_requests AS (
            UPDATE api_payment_channel_close_requests r
            SET status = 'rejected',
                updated_at_ms = GREATEST(r.updated_at_ms, $2)
            FROM rejected_auth
            WHERE r.channel_id = rejected_auth.channel_id
              AND r.status IN ('requested', 'claimed')
            RETURNING r.channel_id
        )
        SELECT disabled_channel.channel_id,
               disabled_channel.network_id,
               rejected_auth.sequence,
               rejected_auth.settlement_txid,
               $2::BIGINT AS rejected_at_ms,
               disabled_channel.channel_status,
               rejected_auth.authorization_status,
               (SELECT COUNT(*) FROM updated_close_requests) AS close_requests_updated_count
        FROM rejected_auth
        JOIN disabled_channel ON disabled_channel.channel_id = rejected_auth.channel_id
        "#,
    )
    .bind(settlement_txid)
    .bind(rejected_at_ms)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(settlement_rejection_row))
}

pub async fn submit_api_direct_payment_proof(
    pool: &PgPool,
    proof: NewApiDirectPaymentProof,
) -> Result<Option<ApiDirectPaymentProofRow>> {
    let row = sqlx::query(
        r#"
        INSERT INTO api_payment_direct_proofs (
            challenge_id, network_id, txid, payer_identifier, recipient_address,
            amount_sompi, pricing_id, route, request_hash, status,
            failure_reason, raw_status_snapshot, submitted_at_ms, verified_at_ms,
            indexed_at_ms
        )
        VALUES (
            $1, $2, decode($3, 'hex'), $4, $5, $6, $7, $8, decode($9, 'hex'),
            $10, $11, $12, $13, $14, $15
        )
        ON CONFLICT DO NOTHING
        RETURNING id, challenge_id, network_id, encode(txid, 'hex') AS txid_hex,
                  payer_identifier, recipient_address, amount_sompi, pricing_id,
                  route, encode(request_hash, 'hex') AS request_hash, status,
                  failure_reason, raw_status_snapshot, submitted_at_ms,
                  verified_at_ms, indexed_at_ms
        "#,
    )
    .bind(&proof.challenge_id)
    .bind(&proof.network_id)
    .bind(&proof.txid_hex)
    .bind(&proof.payer_identifier)
    .bind(&proof.recipient_address)
    .bind(proof.amount_sompi)
    .bind(&proof.pricing_id)
    .bind(&proof.route)
    .bind(&proof.request_hash)
    .bind(&proof.status)
    .bind(&proof.failure_reason)
    .bind(&proof.raw_status_snapshot)
    .bind(proof.submitted_at_ms)
    .bind(proof.verified_at_ms)
    .bind(proof.indexed_at_ms)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(direct_payment_proof_row))
}

pub async fn api_direct_payment_proof_by_txid(
    pool: &PgPool,
    txid_hex: &str,
) -> Result<Option<ApiDirectPaymentProofRow>> {
    let row = sqlx::query(
        r#"
        SELECT id, challenge_id, network_id, encode(txid, 'hex') AS txid_hex,
               payer_identifier, recipient_address, amount_sompi, pricing_id,
               route, encode(request_hash, 'hex') AS request_hash, status,
               failure_reason, raw_status_snapshot, submitted_at_ms,
               verified_at_ms, indexed_at_ms
        FROM api_payment_direct_proofs
        WHERE txid = decode($1, 'hex')
        "#,
    )
    .bind(txid_hex)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(direct_payment_proof_row))
}

pub async fn update_api_direct_payment_proof_status(
    pool: &PgPool,
    update: ApiDirectPaymentProofStatusUpdate,
) -> Result<Option<ApiDirectPaymentProofRow>> {
    let row = sqlx::query(
        r#"
        UPDATE api_payment_direct_proofs
        SET status = $2,
            failure_reason = $3,
            raw_status_snapshot = $4,
            verified_at_ms = COALESCE(verified_at_ms, $5),
            indexed_at_ms = COALESCE($6, indexed_at_ms)
        WHERE txid = decode($1, 'hex')
        RETURNING id, challenge_id, network_id, encode(txid, 'hex') AS txid_hex,
                  payer_identifier, recipient_address, amount_sompi, pricing_id,
                  route, encode(request_hash, 'hex') AS request_hash, status,
                  failure_reason, raw_status_snapshot, submitted_at_ms,
                  verified_at_ms, indexed_at_ms
        "#,
    )
    .bind(&update.txid_hex)
    .bind(&update.status)
    .bind(&update.failure_reason)
    .bind(&update.raw_status_snapshot)
    .bind(update.verified_at_ms)
    .bind(update.indexed_at_ms)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(direct_payment_proof_row))
}

fn channel_row(row: sqlx::postgres::PgRow) -> ApiPaymentChannelRow {
    ApiPaymentChannelRow {
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        payer_identifier: row.get("payer_identifier"),
        payer_pubkey: row.get("payer_pubkey"),
        provider_pubkey: row.get("provider_pubkey"),
        deposit_sompi: row.get("deposit_sompi"),
        reserve_sompi: row.get("reserve_sompi"),
        spent_sompi: row.get("spent_sompi"),
        latest_sequence: row.get("latest_sequence"),
        status: row.get("status"),
        refund_after_ms: row.get("refund_after_ms"),
        close_after_ms: row.get("close_after_ms"),
        updated_at_ms: row.get("updated_at_ms"),
    }
}

fn pricing_route_row(row: sqlx::postgres::PgRow) -> ApiPaymentPricingRouteRow {
    ApiPaymentPricingRouteRow {
        pricing_id: row.get("pricing_id"),
        method: row.get("method"),
        path_pattern: row.get("path_pattern"),
        base_sompi: row.get("base_sompi"),
        per_row_sompi: row.get("per_row_sompi"),
        max_limit: row.get("max_limit"),
        enabled: row.get("enabled"),
        effective_from_ms: row.get("effective_from_ms"),
        effective_to_ms: row.get("effective_to_ms"),
    }
}

fn channel_status_row(row: sqlx::postgres::PgRow) -> ApiPaymentChannelStatusRow {
    ApiPaymentChannelStatusRow {
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        payer_identifier: row.get("payer_identifier"),
        payer_pubkey: row.get("payer_pubkey"),
        provider_pubkey: row.get("provider_pubkey"),
        provider_payout_pubkey: row.get("provider_payout_pubkey"),
        voucher_domain_hash: row.get("voucher_domain_hash"),
        deposit_sompi: row.get("deposit_sompi"),
        reserve_sompi: row.get("reserve_sompi"),
        spent_sompi: row.get("spent_sompi"),
        latest_sequence: row.get("latest_sequence"),
        status: row.get("status"),
        open_txid: row.get("open_txid"),
        current_txid: row.get("current_txid"),
        current_vout: row.get("current_vout"),
        settlement_txid: row.get("settlement_txid"),
        refund_txid: row.get("refund_txid"),
        refund_after_ms: row.get("refund_after_ms"),
        close_after_ms: row.get("close_after_ms"),
        max_spend_sompi: row.get("max_spend_sompi"),
        indexed_at_ms: row.get("indexed_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
    }
}

fn channel_tx_status_row(row: sqlx::postgres::PgRow) -> ApiPaymentChannelTxStatusRow {
    ApiPaymentChannelTxStatusRow {
        txid_hex: row.get("txid_hex"),
        kind: row.get("kind"),
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        channel_status: row.get("channel_status"),
        settled_sequence: row.get("settled_sequence"),
        settled_total_sompi: row.get("settled_total_sompi"),
        provider_amount_sompi: row.get("provider_amount_sompi"),
        payer_refund_sompi: row.get("payer_refund_sompi"),
        indexer_status: row.get("indexer_status"),
        created_at_ms: row.get("created_at_ms"),
        indexed_at_ms: row.get("indexed_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
    }
}

fn payment_receipt_row(row: sqlx::postgres::PgRow) -> ApiPaymentReceiptRow {
    ApiPaymentReceiptRow {
        id: row.get("id"),
        request_id: row.get("request_id"),
        receipt_id: row.get("receipt_id"),
        channel_id: row.get("channel_id"),
        route: row.get("route"),
        pricing_id: row.get("pricing_id"),
        amount_sompi: row.get("amount_sompi"),
        voucher_sequence: row.get("voucher_sequence"),
        response_status: row.get("response_status"),
        duration_ms: row.get("duration_ms"),
        created_at_ms: row.get("created_at_ms"),
        voucher_total_spent_sompi: row.get("voucher_total_spent_sompi"),
        voucher_request_hash: row.get("voucher_request_hash"),
        voucher_accepted_at_ms: row.get("voucher_accepted_at_ms"),
        channel_status: row.get("channel_status"),
        channel_spent_sompi: row.get("channel_spent_sompi"),
        channel_latest_sequence: row.get("channel_latest_sequence"),
    }
}

fn direct_payment_proof_row(row: sqlx::postgres::PgRow) -> ApiDirectPaymentProofRow {
    ApiDirectPaymentProofRow {
        id: row.get("id"),
        challenge_id: row.get("challenge_id"),
        network_id: row.get("network_id"),
        txid_hex: row.get("txid_hex"),
        payer_identifier: row.get("payer_identifier"),
        recipient_address: row.get("recipient_address"),
        amount_sompi: row.get("amount_sompi"),
        pricing_id: row.get("pricing_id"),
        route: row.get("route"),
        request_hash: row.get("request_hash"),
        status: row.get("status"),
        failure_reason: row.get("failure_reason"),
        raw_status_snapshot: row.get("raw_status_snapshot"),
        submitted_at_ms: row.get("submitted_at_ms"),
        verified_at_ms: row.get("verified_at_ms"),
        indexed_at_ms: row.get("indexed_at_ms"),
    }
}

fn settlement_authorization_row(
    row: sqlx::postgres::PgRow,
) -> ApiPaymentSettlementAuthorizationRow {
    ApiPaymentSettlementAuthorizationRow {
        id: row.get("id"),
        channel_id: row.get("channel_id"),
        sequence: row.get("sequence"),
        total_spent_sompi: row.get("total_spent_sompi"),
        provider_amount_sompi: row.get("provider_amount_sompi"),
        payer_refund_sompi: row.get("payer_refund_sompi"),
        settlement_fee_sompi: row.get("settlement_fee_sompi"),
        settlement_txid: row.get("settlement_txid"),
        settlement_template_hash: row.get("settlement_template_hash"),
        metadata_hash: row.get("metadata_hash"),
        payer_settlement_signature: row.get("payer_settlement_signature"),
        settlement_artifact_schema: row.get("settlement_artifact_schema"),
        unsigned_settlement_template: row.get("unsigned_settlement_template"),
        settlement_artifact_json: row.get("settlement_artifact_json"),
        refund_after_ms: row.get("refund_after_ms"),
        expires_at_ms: row.get("expires_at_ms"),
        status: row.get("status"),
        created_at_ms: row.get("created_at_ms"),
        updated_at_ms: row.get("updated_at_ms"),
    }
}

fn settlement_candidate_row(row: sqlx::postgres::PgRow) -> ApiPaymentSettlementCandidateRow {
    ApiPaymentSettlementCandidateRow {
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        spent_sompi: row.get("spent_sompi"),
        deposit_sompi: row.get("deposit_sompi"),
        reserve_sompi: row.get("reserve_sompi"),
        latest_sequence: row.get("latest_sequence"),
        refund_after_ms: row.get("refund_after_ms"),
        updated_at_ms: row.get("updated_at_ms"),
        reason: row.get("reason"),
        latest_authorization_sequence: row.get("latest_authorization_sequence"),
        latest_authorization_status: row.get("latest_authorization_status"),
        latest_authorization_expires_at_ms: row.get("latest_authorization_expires_at_ms"),
        latest_authorization_settlement_txid: row.get("latest_authorization_settlement_txid"),
    }
}

fn disabled_channel_row(row: sqlx::postgres::PgRow) -> ApiPaymentDisabledChannelRow {
    ApiPaymentDisabledChannelRow {
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        spent_sompi: row.get("spent_sompi"),
        latest_sequence: row.get("latest_sequence"),
        reason: row.get("reason"),
        disabled_at_ms: row.get("disabled_at_ms"),
        latest_authorization_sequence: row.get("latest_authorization_sequence"),
        latest_authorization_status: row.get("latest_authorization_status"),
        latest_authorization_expires_at_ms: row.get("latest_authorization_expires_at_ms"),
    }
}

fn settlement_claim_row(row: sqlx::postgres::PgRow) -> ApiPaymentSettlementClaimRow {
    ApiPaymentSettlementClaimRow {
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        reason: row.get("reason"),
        sequence: row.get("sequence"),
        total_spent_sompi: row.get("total_spent_sompi"),
        provider_amount_sompi: row.get("provider_amount_sompi"),
        payer_refund_sompi: row.get("payer_refund_sompi"),
        settlement_fee_sompi: row.get("settlement_fee_sompi"),
        settlement_txid: row.get("settlement_txid"),
        settlement_template_hash: row.get("settlement_template_hash"),
        metadata_hash: row.get("metadata_hash"),
        payer_settlement_signature: row.get("payer_settlement_signature"),
        settlement_artifact_schema: row.get("settlement_artifact_schema"),
        unsigned_settlement_template: row.get("unsigned_settlement_template"),
        settlement_artifact_json: row.get("settlement_artifact_json"),
        refund_after_ms: row.get("refund_after_ms"),
        expires_at_ms: row.get("expires_at_ms"),
        claimed_at_ms: row.get("claimed_at_ms"),
    }
}

fn settlement_rejection_row(row: sqlx::postgres::PgRow) -> ApiPaymentSettlementRejectionRow {
    ApiPaymentSettlementRejectionRow {
        channel_id: row.get("channel_id"),
        network_id: row.get("network_id"),
        sequence: row.get("sequence"),
        settlement_txid: row.get("settlement_txid"),
        rejected_at_ms: row.get("rejected_at_ms"),
        channel_status: row.get("channel_status"),
        authorization_status: row.get("authorization_status"),
    }
}
