//! Shared primitives for KaspaCom API payment credentials.
//!
//! This module intentionally stops before backend auth, DB state, or covenant
//! settlement. It gives those layers deterministic request binding and voucher
//! payload hashing so every implementation signs the same bytes. Settlement
//! authorization is modeled separately from request vouchers because current
//! SilverScript examples verify transaction signatures, not arbitrary JSON
//! voucher messages.

use std::collections::BTreeMap;

use crate::blake2b_256;
use secp256k1::{Message, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const API_PAYMENT_VOUCHER_SCHEMA_V1: &str = "kaspa-api-payment-voucher/v1";
pub const API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1: &str =
    "kaspa-api-payment-settlement-authorization/v1";
pub const API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1: &str =
    "kaspa-api-payment-channel-settlement-artifact/v1";
pub const API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1: &str =
    "kaspa-api-payment-channel-close-request/v1";
pub const API_PAYMENT_VOUCHER_DOMAIN_V1: &str = "KaspaCom API Payment Voucher v1";
pub const API_PAYMENT_SETTLEMENT_AUTHORIZATION_DOMAIN_V1: &str =
    "KaspaCom API Payment Settlement Authorization v1";
pub const API_PAYMENT_CHANNEL_CLOSE_REQUEST_DOMAIN_V1: &str =
    "KaspaCom API Payment Channel Close Request v1";
pub const API_PAYMENT_REQUEST_DOMAIN_V1: &str = "KaspaCom API Payment Request v1";
pub const API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI: u64 = 50_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiPaymentChannelSizingPolicy {
    pub min_channel_deposit_sompi: u64,
    pub min_provider_output_sompi: u64,
    pub min_payer_refund_output_sompi: u64,
}

impl Default for ApiPaymentChannelSizingPolicy {
    fn default() -> Self {
        Self {
            min_channel_deposit_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
            min_provider_output_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
            min_payer_refund_output_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
        }
    }
}

pub fn validate_api_payment_channel_open_sizing(
    deposit_sompi: u64,
    reserve_sompi: u64,
    max_spend_sompi: u64,
    policy: ApiPaymentChannelSizingPolicy,
) -> Result<(), ApiPaymentValidationError> {
    if deposit_sompi < policy.min_channel_deposit_sompi {
        return Err(ApiPaymentValidationError::ChannelDepositBelowMinimum {
            minimum_sompi: policy.min_channel_deposit_sompi,
            actual_sompi: deposit_sompi,
        });
    }
    if reserve_sompi > deposit_sompi {
        return Err(ApiPaymentValidationError::ChannelSizingInvalid {
            deposit_sompi,
            reserve_sompi,
            max_spend_sompi,
        });
    }
    let usable_sompi = deposit_sompi.checked_sub(reserve_sompi).ok_or(
        ApiPaymentValidationError::ChannelSizingInvalid {
            deposit_sompi,
            reserve_sompi,
            max_spend_sompi,
        },
    )?;
    if max_spend_sompi == 0 || max_spend_sompi > usable_sompi {
        return Err(ApiPaymentValidationError::ChannelSizingInvalid {
            deposit_sompi,
            reserve_sompi,
            max_spend_sompi,
        });
    }
    Ok(())
}

pub fn validate_api_payment_settlement_output_sizing(
    provider_amount_sompi: u64,
    payer_refund_sompi: u64,
    policy: ApiPaymentChannelSizingPolicy,
) -> Result<(), ApiPaymentValidationError> {
    if provider_amount_sompi < policy.min_provider_output_sompi {
        return Err(ApiPaymentValidationError::ProviderOutputBelowMinimum {
            minimum_sompi: policy.min_provider_output_sompi,
            actual_sompi: provider_amount_sompi,
        });
    }
    if payer_refund_sompi > 0 && payer_refund_sompi < policy.min_payer_refund_output_sompi {
        return Err(ApiPaymentValidationError::PayerRefundBelowMinimum {
            minimum_sompi: policy.min_payer_refund_output_sompi,
            actual_sompi: payer_refund_sompi,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ApiPaymentMethod {
    KaspaDirect,
    KaspaChannel,
}

impl std::fmt::Display for ApiPaymentMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiPaymentMethod::KaspaDirect => f.write_str("kaspa-direct"),
            ApiPaymentMethod::KaspaChannel => f.write_str("kaspa-channel"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApiPaymentIntent {
    Charge,
    Session,
}

impl std::fmt::Display for ApiPaymentIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiPaymentIntent::Charge => f.write_str("charge"),
            ApiPaymentIntent::Session => f.write_str("session"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentRequestBinding {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Vec<ApiPaymentQueryParam>,
    #[serde(default)]
    pub headers: Vec<ApiPaymentHeader>,
    pub body_hash_hex: String,
}

impl ApiPaymentRequestBinding {
    pub fn canonical_digest_hex(&self) -> String {
        hex::encode(self.canonical_digest())
    }

    pub fn canonical_digest(&self) -> [u8; 32] {
        blake2b_256(self.canonical_preimage().as_bytes())
    }

    pub fn canonical_preimage(&self) -> String {
        let mut query = self.query.clone();
        query.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.value.cmp(&b.value))
                .then_with(|| a.index.cmp(&b.index))
        });

        let mut headers = self.headers.clone();
        for header in &mut headers {
            header.name = header.name.to_ascii_lowercase();
            header.value = normalize_header_value(&header.value);
        }
        headers.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.value.cmp(&b.value)));

        let mut out = String::new();
        out.push_str(API_PAYMENT_REQUEST_DOMAIN_V1);
        out.push('\n');
        out.push_str(&self.method.to_ascii_uppercase());
        out.push('\n');
        out.push_str(&self.path);
        out.push('\n');
        out.push_str("query\n");
        for param in query {
            out.push_str(&param.index.to_string());
            out.push('\t');
            out.push_str(&param.name);
            out.push('\t');
            out.push_str(&param.value);
            out.push('\n');
        }
        out.push_str("headers\n");
        for header in headers {
            out.push_str(&header.name);
            out.push('\t');
            out.push_str(&header.value);
            out.push('\n');
        }
        out.push_str("body\n");
        out.push_str(&self.body_hash_hex.to_ascii_lowercase());
        out.push('\n');
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentQueryParam {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentVoucher {
    pub schema: String,
    pub method: ApiPaymentMethod,
    pub network_id: String,
    pub channel_id: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub sequence: u64,
    pub total_spent_sompi: u64,
    pub incremental_amount_sompi: u64,
    pub request_hash: String,
    pub pricing_id: String,
    pub route: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentSettlementAuthorization {
    pub schema: String,
    pub method: ApiPaymentMethod,
    pub network_id: String,
    pub channel_id: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub sequence: u64,
    pub total_spent_sompi: u64,
    pub provider_amount_sompi: u64,
    pub payer_refund_sompi: u64,
    pub settlement_fee_sompi: u64,
    pub settlement_txid: String,
    pub settlement_template_hash: String,
    pub refund_after_ms: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Payer signature for the actual close-on-settle transaction/PSKT.
    ///
    /// This is intentionally not a signature over `metadata_digest`. The
    /// covenant can enforce a transaction signature with `checkSig`; it cannot
    /// currently enforce this JSON metadata digest directly.
    pub payer_settlement_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentChannelCloseRequest {
    pub schema: String,
    pub method: ApiPaymentMethod,
    pub network_id: String,
    pub channel_id: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentSettlementArtifact {
    pub schema: String,
    pub contract: String,
    pub network: String,
    pub channel_id: String,
    pub authorization: ApiPaymentSettlementAuthorization,
    pub metadata_digest: String,
    pub unsigned_settlement_template: Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ApiPaymentSettlementAuthorization {
    pub fn metadata_digest_hex(&self) -> String {
        hex::encode(self.metadata_digest())
    }

    pub fn metadata_digest(&self) -> [u8; 32] {
        blake2b_256(self.metadata_preimage().as_bytes())
    }

    pub fn metadata_preimage(&self) -> String {
        [
            API_PAYMENT_SETTLEMENT_AUTHORIZATION_DOMAIN_V1.to_string(),
            self.schema.clone(),
            self.method.to_string(),
            self.network_id.clone(),
            self.channel_id.clone(),
            self.payer_pubkey.to_ascii_lowercase(),
            self.provider_pubkey.to_ascii_lowercase(),
            self.sequence.to_string(),
            self.total_spent_sompi.to_string(),
            self.provider_amount_sompi.to_string(),
            self.payer_refund_sompi.to_string(),
            self.settlement_fee_sompi.to_string(),
            self.settlement_txid.to_ascii_lowercase(),
            self.settlement_template_hash.to_ascii_lowercase(),
            self.refund_after_ms.to_string(),
            self.issued_at_ms.to_string(),
            self.expires_at_ms.to_string(),
        ]
        .join("\n")
    }

    pub fn validate_static(
        &self,
        expected: ApiPaymentSettlementAuthorizationExpectation<'_>,
    ) -> Result<(), ApiPaymentValidationError> {
        if self.schema != API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1 {
            return Err(ApiPaymentValidationError::UnsupportedSettlementSchema {
                actual: self.schema.clone(),
            });
        }
        if self.method != ApiPaymentMethod::KaspaChannel {
            return Err(ApiPaymentValidationError::UnsupportedMethod {
                actual: self.method.to_string(),
            });
        }
        if self.network_id != expected.network_id {
            return Err(ApiPaymentValidationError::NetworkMismatch {
                expected: expected.network_id.to_string(),
                actual: self.network_id.clone(),
            });
        }
        if self.channel_id != expected.channel_id {
            return Err(ApiPaymentValidationError::ChannelMismatch {
                expected: expected.channel_id.to_string(),
                actual: self.channel_id.clone(),
            });
        }
        if self.payer_pubkey.to_ascii_lowercase() != expected.payer_pubkey.to_ascii_lowercase() {
            return Err(ApiPaymentValidationError::PayerPubkeyMismatch);
        }
        if self.provider_pubkey.to_ascii_lowercase()
            != expected.provider_pubkey.to_ascii_lowercase()
        {
            return Err(ApiPaymentValidationError::ProviderPubkeyMismatch);
        }
        validate_hex_len(&self.settlement_txid, 32)
            .map_err(|_| ApiPaymentValidationError::InvalidSettlementTxid)?;
        validate_hex_len(&self.settlement_template_hash, 32)
            .map_err(|_| ApiPaymentValidationError::InvalidSettlementTemplateHash)?;
        validate_hex_len(&self.payer_settlement_signature, 65)
            .map_err(|_| ApiPaymentValidationError::InvalidSettlementSignature)?;
        if self.expires_at_ms <= expected.now_ms {
            return Err(ApiPaymentValidationError::Expired {
                expires_at_ms: self.expires_at_ms,
                now_ms: expected.now_ms,
            });
        }
        if expected.now_ms >= self.refund_after_ms {
            return Err(ApiPaymentValidationError::SettlementAfterRefundWindow {
                refund_after_ms: self.refund_after_ms,
                now_ms: expected.now_ms,
            });
        }
        if self.expires_at_ms >= self.refund_after_ms {
            return Err(
                ApiPaymentValidationError::SettlementAuthorizationExpiresAfterRefundWindow {
                    expires_at_ms: self.expires_at_ms,
                    refund_after_ms: self.refund_after_ms,
                },
            );
        }
        if self.sequence <= expected.latest_sequence {
            return Err(ApiPaymentValidationError::StaleSequence {
                latest_sequence: expected.latest_sequence,
                actual_sequence: self.sequence,
            });
        }
        if self.total_spent_sompi <= expected.latest_total_spent_sompi {
            return Err(ApiPaymentValidationError::NonIncreasingSpend {
                latest_total_spent_sompi: expected.latest_total_spent_sompi,
                actual_total_spent_sompi: self.total_spent_sompi,
            });
        }
        if self.total_spent_sompi > expected.max_total_spend_sompi {
            return Err(ApiPaymentValidationError::Overspend {
                max_total_spend_sompi: expected.max_total_spend_sompi,
                actual_total_spent_sompi: self.total_spent_sompi,
            });
        }
        if self.provider_amount_sompi != self.total_spent_sompi {
            return Err(ApiPaymentValidationError::SettlementPayoutMismatch {
                expected_provider_amount_sompi: self.total_spent_sompi,
                actual_provider_amount_sompi: self.provider_amount_sompi,
            });
        }
        let expected_payer_refund = expected
            .channel_value_sompi
            .checked_sub(self.provider_amount_sompi)
            .and_then(|value| value.checked_sub(self.settlement_fee_sompi))
            .ok_or(ApiPaymentValidationError::SettlementValueMismatch {
                channel_value_sompi: expected.channel_value_sompi,
                provider_amount_sompi: self.provider_amount_sompi,
                payer_refund_sompi: self.payer_refund_sompi,
                settlement_fee_sompi: self.settlement_fee_sompi,
            })?;
        if self.settlement_fee_sompi != expected.settlement_fee_sompi
            || self.payer_refund_sompi != expected_payer_refund
        {
            return Err(ApiPaymentValidationError::SettlementValueMismatch {
                channel_value_sompi: expected.channel_value_sompi,
                provider_amount_sompi: self.provider_amount_sompi,
                payer_refund_sompi: self.payer_refund_sompi,
                settlement_fee_sompi: self.settlement_fee_sompi,
            });
        }
        if let Some(policy) = expected.sizing_policy {
            validate_api_payment_settlement_output_sizing(
                self.provider_amount_sompi,
                self.payer_refund_sompi,
                policy,
            )?;
        }
        Ok(())
    }
}

impl ApiPaymentChannelCloseRequest {
    pub fn signing_digest_hex(&self) -> String {
        hex::encode(self.signing_digest())
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b_256(self.signing_preimage().as_bytes())
    }

    pub fn signing_preimage(&self) -> String {
        [
            API_PAYMENT_CHANNEL_CLOSE_REQUEST_DOMAIN_V1.to_string(),
            self.schema.clone(),
            self.method.to_string(),
            self.network_id.clone(),
            self.channel_id.clone(),
            self.payer_pubkey.to_ascii_lowercase(),
            self.provider_pubkey.to_ascii_lowercase(),
            self.requested_at_ms.to_string(),
            self.expires_at_ms.to_string(),
            self.nonce.clone(),
            self.reason.clone().unwrap_or_default(),
        ]
        .join("\n")
    }

    pub fn validate_static(
        &self,
        expected: ApiPaymentChannelCloseRequestExpectation<'_>,
    ) -> Result<(), ApiPaymentValidationError> {
        if self.schema != API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1 {
            return Err(ApiPaymentValidationError::UnsupportedCloseRequestSchema {
                actual: self.schema.clone(),
            });
        }
        if self.method != ApiPaymentMethod::KaspaChannel {
            return Err(ApiPaymentValidationError::UnsupportedMethod {
                actual: self.method.to_string(),
            });
        }
        if self.network_id != expected.network_id {
            return Err(ApiPaymentValidationError::NetworkMismatch {
                expected: expected.network_id.to_string(),
                actual: self.network_id.clone(),
            });
        }
        if self.channel_id != expected.channel_id {
            return Err(ApiPaymentValidationError::ChannelMismatch {
                expected: expected.channel_id.to_string(),
                actual: self.channel_id.clone(),
            });
        }
        if self.payer_pubkey.to_ascii_lowercase() != expected.payer_pubkey.to_ascii_lowercase() {
            return Err(ApiPaymentValidationError::PayerPubkeyMismatch);
        }
        if self.provider_pubkey.to_ascii_lowercase()
            != expected.provider_pubkey.to_ascii_lowercase()
        {
            return Err(ApiPaymentValidationError::ProviderPubkeyMismatch);
        }
        if self.expires_at_ms <= expected.now_ms {
            return Err(ApiPaymentValidationError::Expired {
                expires_at_ms: self.expires_at_ms,
                now_ms: expected.now_ms,
            });
        }
        Ok(())
    }

    pub fn verify_payer_signature(&self) -> Result<(), ApiPaymentValidationError> {
        verify_schnorr_digest(&self.payer_pubkey, &self.signature, self.signing_digest())
    }
}

impl ApiPaymentSettlementArtifact {
    pub fn settlement_template_digest_hex(&self) -> Result<String, ApiPaymentValidationError> {
        let stable_template = stable_json(&self.unsigned_settlement_template)?;
        Ok(hex::encode(blake2b_256(stable_template.as_bytes())))
    }

    pub fn validate_static(&self) -> Result<(), ApiPaymentValidationError> {
        if self.schema != API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1 {
            return Err(
                ApiPaymentValidationError::UnsupportedSettlementArtifactSchema {
                    actual: self.schema.clone(),
                },
            );
        }
        if self.contract != "ApiPaymentChannel" {
            return Err(ApiPaymentValidationError::SettlementArtifactMismatch {
                field: "contract",
            });
        }
        if self.network != self.authorization.network_id {
            return Err(ApiPaymentValidationError::SettlementArtifactMismatch { field: "network" });
        }
        if self.channel_id != self.authorization.channel_id {
            return Err(ApiPaymentValidationError::SettlementArtifactMismatch {
                field: "channelId",
            });
        }
        if self.metadata_digest.to_ascii_lowercase()
            != self
                .authorization
                .metadata_digest_hex()
                .to_ascii_lowercase()
        {
            return Err(ApiPaymentValidationError::SettlementArtifactMetadataMismatch);
        }
        if self.settlement_template_digest_hex()?.to_ascii_lowercase()
            != self
                .authorization
                .settlement_template_hash
                .to_ascii_lowercase()
        {
            return Err(ApiPaymentValidationError::SettlementArtifactTemplateMismatch);
        }
        Ok(())
    }
}

fn stable_json(value: &Value) -> Result<String, ApiPaymentValidationError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value)
                .map_err(|_| ApiPaymentValidationError::SettlementArtifactTemplateInvalid)
        }
        Value::Array(values) => {
            let mut out = String::from("[");
            for (idx, item) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&stable_json(item)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            let mut out = String::from("{");
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key).map_err(|_| {
                        ApiPaymentValidationError::SettlementArtifactTemplateInvalid
                    })?,
                );
                out.push(':');
                out.push_str(&stable_json(&map[*key])?);
            }
            out.push('}');
            Ok(out)
        }
    }
}

impl ApiPaymentVoucher {
    pub fn signing_digest_hex(&self) -> String {
        hex::encode(self.signing_digest())
    }

    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b_256(self.signing_preimage().as_bytes())
    }

    pub fn signing_preimage(&self) -> String {
        [
            API_PAYMENT_VOUCHER_DOMAIN_V1.to_string(),
            self.schema.clone(),
            self.method.to_string(),
            self.network_id.clone(),
            self.channel_id.clone(),
            self.payer_pubkey.to_ascii_lowercase(),
            self.provider_pubkey.to_ascii_lowercase(),
            self.sequence.to_string(),
            self.total_spent_sompi.to_string(),
            self.incremental_amount_sompi.to_string(),
            self.request_hash.to_ascii_lowercase(),
            self.pricing_id.clone(),
            self.route.clone(),
            self.issued_at_ms.to_string(),
            self.expires_at_ms.to_string(),
            self.nonce.clone(),
        ]
        .join("\n")
    }

    pub fn validate_static(
        &self,
        expected: ApiPaymentVoucherExpectation<'_>,
    ) -> Result<(), ApiPaymentValidationError> {
        if self.schema != API_PAYMENT_VOUCHER_SCHEMA_V1 {
            return Err(ApiPaymentValidationError::UnsupportedSchema {
                actual: self.schema.clone(),
            });
        }
        if self.method != ApiPaymentMethod::KaspaChannel {
            return Err(ApiPaymentValidationError::UnsupportedMethod {
                actual: self.method.to_string(),
            });
        }
        if self.network_id != expected.network_id {
            return Err(ApiPaymentValidationError::NetworkMismatch {
                expected: expected.network_id.to_string(),
                actual: self.network_id.clone(),
            });
        }
        if self.channel_id != expected.channel_id {
            return Err(ApiPaymentValidationError::ChannelMismatch {
                expected: expected.channel_id.to_string(),
                actual: self.channel_id.clone(),
            });
        }
        if self.payer_pubkey.to_ascii_lowercase() != expected.payer_pubkey.to_ascii_lowercase() {
            return Err(ApiPaymentValidationError::PayerPubkeyMismatch);
        }
        if self.provider_pubkey.to_ascii_lowercase()
            != expected.provider_pubkey.to_ascii_lowercase()
        {
            return Err(ApiPaymentValidationError::ProviderPubkeyMismatch);
        }
        if self.request_hash.to_ascii_lowercase() != expected.request_hash.to_ascii_lowercase() {
            return Err(ApiPaymentValidationError::RequestHashMismatch);
        }
        if self.pricing_id != expected.pricing_id {
            return Err(ApiPaymentValidationError::PricingMismatch {
                expected: expected.pricing_id.to_string(),
                actual: self.pricing_id.clone(),
            });
        }
        if self.route != expected.route {
            return Err(ApiPaymentValidationError::RouteMismatch {
                expected: expected.route.to_string(),
                actual: self.route.clone(),
            });
        }
        if self.expires_at_ms <= expected.now_ms {
            return Err(ApiPaymentValidationError::Expired {
                expires_at_ms: self.expires_at_ms,
                now_ms: expected.now_ms,
            });
        }
        if self.incremental_amount_sompi < expected.min_incremental_amount_sompi {
            return Err(ApiPaymentValidationError::Underpaid {
                required_sompi: expected.min_incremental_amount_sompi,
                actual_sompi: self.incremental_amount_sompi,
            });
        }
        if self.sequence <= expected.latest_sequence {
            return Err(ApiPaymentValidationError::StaleSequence {
                latest_sequence: expected.latest_sequence,
                actual_sequence: self.sequence,
            });
        }
        if self.total_spent_sompi <= expected.latest_total_spent_sompi {
            return Err(ApiPaymentValidationError::NonIncreasingSpend {
                latest_total_spent_sompi: expected.latest_total_spent_sompi,
                actual_total_spent_sompi: self.total_spent_sompi,
            });
        }
        if self.total_spent_sompi > expected.max_total_spend_sompi {
            return Err(ApiPaymentValidationError::Overspend {
                max_total_spend_sompi: expected.max_total_spend_sompi,
                actual_total_spent_sompi: self.total_spent_sompi,
            });
        }
        Ok(())
    }

    pub fn verify_payer_signature(&self) -> Result<(), ApiPaymentValidationError> {
        verify_schnorr_digest(&self.payer_pubkey, &self.signature, self.signing_digest())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ApiPaymentVoucherExpectation<'a> {
    pub network_id: &'a str,
    pub channel_id: &'a str,
    pub payer_pubkey: &'a str,
    pub provider_pubkey: &'a str,
    pub request_hash: &'a str,
    pub pricing_id: &'a str,
    pub route: &'a str,
    pub now_ms: u64,
    pub min_incremental_amount_sompi: u64,
    pub latest_sequence: u64,
    pub latest_total_spent_sompi: u64,
    pub max_total_spend_sompi: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ApiPaymentSettlementAuthorizationExpectation<'a> {
    pub network_id: &'a str,
    pub channel_id: &'a str,
    pub payer_pubkey: &'a str,
    pub provider_pubkey: &'a str,
    pub now_ms: u64,
    pub latest_sequence: u64,
    pub latest_total_spent_sompi: u64,
    pub max_total_spend_sompi: u64,
    pub channel_value_sompi: u64,
    pub settlement_fee_sompi: u64,
    pub sizing_policy: Option<ApiPaymentChannelSizingPolicy>,
}

#[derive(Debug, Clone, Copy)]
pub struct ApiPaymentChannelCloseRequestExpectation<'a> {
    pub network_id: &'a str,
    pub channel_id: &'a str,
    pub payer_pubkey: &'a str,
    pub provider_pubkey: &'a str,
    pub now_ms: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiPaymentValidationError {
    #[error("unsupported payment voucher schema: {actual}")]
    UnsupportedSchema { actual: String },
    #[error("unsupported payment settlement authorization schema: {actual}")]
    UnsupportedSettlementSchema { actual: String },
    #[error("unsupported payment settlement artifact schema: {actual}")]
    UnsupportedSettlementArtifactSchema { actual: String },
    #[error("unsupported payment channel close request schema: {actual}")]
    UnsupportedCloseRequestSchema { actual: String },
    #[error("unsupported payment method: {actual}")]
    UnsupportedMethod { actual: String },
    #[error("payment network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },
    #[error("payment channel mismatch: expected {expected}, got {actual}")]
    ChannelMismatch { expected: String, actual: String },
    #[error("payment payer pubkey does not match channel state")]
    PayerPubkeyMismatch,
    #[error("payment provider pubkey does not match channel state")]
    ProviderPubkeyMismatch,
    #[error("payment request hash mismatch")]
    RequestHashMismatch,
    #[error("payment pricing mismatch: expected {expected}, got {actual}")]
    PricingMismatch { expected: String, actual: String },
    #[error("payment route mismatch: expected {expected}, got {actual}")]
    RouteMismatch { expected: String, actual: String },
    #[error("payment voucher expired at {expires_at_ms}, now {now_ms}")]
    Expired { expires_at_ms: u64, now_ms: u64 },
    #[error("payment underpaid: required {required_sompi}, got {actual_sompi}")]
    Underpaid {
        required_sompi: u64,
        actual_sompi: u64,
    },
    #[error("stale payment sequence: latest {latest_sequence}, got {actual_sequence}")]
    StaleSequence {
        latest_sequence: u64,
        actual_sequence: u64,
    },
    #[error("non-increasing payment total: latest {latest_total_spent_sompi}, got {actual_total_spent_sompi}")]
    NonIncreasingSpend {
        latest_total_spent_sompi: u64,
        actual_total_spent_sompi: u64,
    },
    #[error("payment overspend: max {max_total_spend_sompi}, got {actual_total_spent_sompi}")]
    Overspend {
        max_total_spend_sompi: u64,
        actual_total_spent_sompi: u64,
    },
    #[error("payment settlement txid is not 32-byte hex")]
    InvalidSettlementTxid,
    #[error("payment settlement template hash is not 32-byte hex")]
    InvalidSettlementTemplateHash,
    #[error("payment settlement artifact {field} does not match authorization")]
    SettlementArtifactMismatch { field: &'static str },
    #[error("payment settlement artifact metadata digest does not match authorization")]
    SettlementArtifactMetadataMismatch,
    #[error("payment settlement artifact template hash does not match authorization")]
    SettlementArtifactTemplateMismatch,
    #[error("payment settlement artifact template is not serializable")]
    SettlementArtifactTemplateInvalid,
    #[error("payment settlement signature must be a 65-byte transaction signature hex")]
    InvalidSettlementSignature,
    #[error(
        "payment settlement is at or past refund window: refund {refund_after_ms}, now {now_ms}"
    )]
    SettlementAfterRefundWindow { refund_after_ms: u64, now_ms: u64 },
    #[error("payment settlement authorization expires at or after refund window: expires {expires_at_ms}, refund {refund_after_ms}")]
    SettlementAuthorizationExpiresAfterRefundWindow {
        expires_at_ms: u64,
        refund_after_ms: u64,
    },
    #[error("payment settlement provider payout mismatch: expected {expected_provider_amount_sompi}, got {actual_provider_amount_sompi}")]
    SettlementPayoutMismatch {
        expected_provider_amount_sompi: u64,
        actual_provider_amount_sompi: u64,
    },
    #[error("payment settlement values do not close channel value {channel_value_sompi}: provider {provider_amount_sompi}, payer refund {payer_refund_sompi}, fee {settlement_fee_sompi}")]
    SettlementValueMismatch {
        channel_value_sompi: u64,
        provider_amount_sompi: u64,
        payer_refund_sompi: u64,
        settlement_fee_sompi: u64,
    },
    #[error("payment channel deposit below minimum: required {minimum_sompi}, got {actual_sompi}")]
    ChannelDepositBelowMinimum {
        minimum_sompi: u64,
        actual_sompi: u64,
    },
    #[error("payment channel sizing invalid: deposit {deposit_sompi}, reserve {reserve_sompi}, max spend {max_spend_sompi}")]
    ChannelSizingInvalid {
        deposit_sompi: u64,
        reserve_sompi: u64,
        max_spend_sompi: u64,
    },
    #[error("payment settlement provider output below minimum: required {minimum_sompi}, got {actual_sompi}")]
    ProviderOutputBelowMinimum {
        minimum_sompi: u64,
        actual_sompi: u64,
    },
    #[error("payment settlement payer refund output below minimum: required {minimum_sompi}, got {actual_sompi}")]
    PayerRefundBelowMinimum {
        minimum_sompi: u64,
        actual_sompi: u64,
    },
    #[error("payment payer pubkey is not a valid x-only secp256k1 key")]
    InvalidPayerPubkey,
    #[error("payment signature is not a valid Schnorr signature")]
    InvalidSignature,
    #[error("payment signature does not match voucher digest and payer pubkey")]
    SignatureMismatch,
}

fn verify_schnorr_digest(
    payer_pubkey: &str,
    signature: &str,
    digest: [u8; 32],
) -> Result<(), ApiPaymentValidationError> {
    let pubkey_bytes =
        hex::decode(payer_pubkey).map_err(|_| ApiPaymentValidationError::InvalidPayerPubkey)?;
    let signature_bytes =
        hex::decode(signature).map_err(|_| ApiPaymentValidationError::InvalidSignature)?;
    let pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)
        .map_err(|_| ApiPaymentValidationError::InvalidPayerPubkey)?;
    let signature = secp256k1::schnorr::Signature::from_slice(&signature_bytes)
        .map_err(|_| ApiPaymentValidationError::InvalidSignature)?;
    let message = Message::from_digest(digest);
    signature
        .verify(&message, &pubkey)
        .map_err(|_| ApiPaymentValidationError::SignatureMismatch)
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_hex_len(value: &str, expected_bytes: usize) -> Result<(), ()> {
    let expected_len = expected_bytes * 2;
    if value.len() != expected_len || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Keypair;

    const PAYER_PUBKEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PROVIDER_PUBKEY: &str =
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const OTHER_PAYER_PUBKEY: &str =
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    const OTHER_PROVIDER_PUBKEY: &str =
        "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";

    fn request_binding() -> ApiPaymentRequestBinding {
        ApiPaymentRequestBinding {
            method: "get".to_string(),
            path: "/kcc20/markets".to_string(),
            query: vec![
                ApiPaymentQueryParam {
                    name: "limit".to_string(),
                    value: "5".to_string(),
                    index: 1,
                },
                ApiPaymentQueryParam {
                    name: "sortBy".to_string(),
                    value: "totalVolumeSompi".to_string(),
                    index: 0,
                },
            ],
            headers: vec![ApiPaymentHeader {
                name: "X-Kaspa-Network".to_string(),
                value: " testnet-10 ".to_string(),
            }],
            body_hash_hex: hex::encode(blake2b_256(b"")),
        }
    }

    fn voucher(request_hash: String) -> ApiPaymentVoucher {
        ApiPaymentVoucher {
            schema: API_PAYMENT_VOUCHER_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "chan_01".to_string(),
            payer_pubkey: PAYER_PUBKEY.to_string(),
            provider_pubkey: PROVIDER_PUBKEY.to_string(),
            sequence: 2,
            total_spent_sompi: 10_000,
            incremental_amount_sompi: 1_000,
            request_hash,
            pricing_id: "kcc20.markets.v1".to_string(),
            route: "GET /kcc20/markets".to_string(),
            issued_at_ms: 1_780_000_000_000,
            expires_at_ms: 1_780_000_060_000,
            nonce: "nonce".to_string(),
            signature: "00".repeat(64),
        }
    }

    fn signed_voucher() -> ApiPaymentVoucher {
        let mut voucher = voucher(request_binding().canonical_digest_hex());
        let secret = [3u8; 32];
        let keypair = Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret).unwrap();
        voucher.payer_pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        let message = Message::from_digest(voucher.signing_digest());
        voucher.signature = hex::encode(
            secp256k1::SECP256K1
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .as_ref(),
        );
        voucher
    }

    fn close_request() -> ApiPaymentChannelCloseRequest {
        ApiPaymentChannelCloseRequest {
            schema: API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "chan_01".to_string(),
            payer_pubkey: PAYER_PUBKEY.to_string(),
            provider_pubkey: PROVIDER_PUBKEY.to_string(),
            requested_at_ms: 1_780_000_030_000,
            expires_at_ms: 1_780_000_090_000,
            nonce: "close-nonce".to_string(),
            reason: Some("wallet-close".to_string()),
            signature: "00".repeat(64),
        }
    }

    fn signed_close_request() -> ApiPaymentChannelCloseRequest {
        let mut request = close_request();
        let secret = [5u8; 32];
        let keypair = Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret).unwrap();
        request.payer_pubkey = hex::encode(keypair.x_only_public_key().0.serialize());
        let message = Message::from_digest(request.signing_digest());
        request.signature = hex::encode(
            secp256k1::SECP256K1
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .as_ref(),
        );
        request
    }

    fn expectation<'a>(request_hash: &'a str) -> ApiPaymentVoucherExpectation<'a> {
        ApiPaymentVoucherExpectation {
            network_id: "testnet-10",
            channel_id: "chan_01",
            payer_pubkey: PAYER_PUBKEY,
            provider_pubkey: PROVIDER_PUBKEY,
            request_hash,
            pricing_id: "kcc20.markets.v1",
            route: "GET /kcc20/markets",
            now_ms: 1_780_000_001_000,
            min_incremental_amount_sompi: 1_000,
            latest_sequence: 1,
            latest_total_spent_sompi: 9_000,
            max_total_spend_sompi: 50_000,
        }
    }

    fn settlement_authorization() -> ApiPaymentSettlementAuthorization {
        ApiPaymentSettlementAuthorization {
            schema: API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "chan_01".to_string(),
            payer_pubkey: PAYER_PUBKEY.to_string(),
            provider_pubkey: PROVIDER_PUBKEY.to_string(),
            sequence: 3,
            total_spent_sompi: 12_000,
            provider_amount_sompi: 12_000,
            payer_refund_sompi: 37_000,
            settlement_fee_sompi: 1_000,
            settlement_txid: "11".repeat(32),
            settlement_template_hash: "22".repeat(32),
            refund_after_ms: 1_780_000_120_000,
            issued_at_ms: 1_780_000_010_000,
            expires_at_ms: 1_780_000_090_000,
            payer_settlement_signature: "41".repeat(65),
        }
    }

    fn settlement_expectation() -> ApiPaymentSettlementAuthorizationExpectation<'static> {
        ApiPaymentSettlementAuthorizationExpectation {
            network_id: "testnet-10",
            channel_id: "chan_01",
            payer_pubkey: PAYER_PUBKEY,
            provider_pubkey: PROVIDER_PUBKEY,
            now_ms: 1_780_000_020_000,
            latest_sequence: 2,
            latest_total_spent_sompi: 10_000,
            max_total_spend_sompi: 49_000,
            channel_value_sompi: 50_000,
            settlement_fee_sompi: 1_000,
            sizing_policy: None,
        }
    }

    fn close_request_expectation<'a>(
        payer_pubkey: &'a str,
    ) -> ApiPaymentChannelCloseRequestExpectation<'a> {
        ApiPaymentChannelCloseRequestExpectation {
            network_id: "testnet-10",
            channel_id: "chan_01",
            payer_pubkey,
            provider_pubkey: PROVIDER_PUBKEY,
            now_ms: 1_780_000_040_000,
        }
    }

    #[test]
    fn request_hash_is_stable_for_query_and_header_order() {
        let a = request_binding();
        let mut b = request_binding();
        b.query.reverse();
        b.headers[0].name = "x-kaspa-network".to_string();
        b.headers[0].value = "testnet-10".to_string();
        assert_eq!(a.canonical_digest_hex(), b.canonical_digest_hex());
    }

    #[test]
    fn request_hash_changes_when_path_changes() {
        let a = request_binding();
        let mut b = request_binding();
        b.path = "/kcc20/listings".to_string();
        assert_ne!(a.canonical_digest_hex(), b.canonical_digest_hex());
    }

    #[test]
    fn request_hash_changes_when_query_value_changes() {
        let a = request_binding();
        let mut b = request_binding();
        b.query[0].value = "50".to_string();
        assert_ne!(a.canonical_digest_hex(), b.canonical_digest_hex());
    }

    #[test]
    fn request_hash_changes_when_body_hash_changes() {
        let a = request_binding();
        let mut b = request_binding();
        b.body_hash_hex = "22".repeat(32);
        assert_ne!(a.canonical_digest_hex(), b.canonical_digest_hex());
    }

    #[test]
    fn voucher_signing_digest_excludes_signature() {
        let request_hash = request_binding().canonical_digest_hex();
        let a = voucher(request_hash.clone());
        let mut b = voucher(request_hash);
        b.signature = "ff".repeat(64);
        assert_eq!(a.signing_digest_hex(), b.signing_digest_hex());
    }

    #[test]
    fn voucher_accepts_valid_payer_signature() {
        assert_eq!(signed_voucher().verify_payer_signature(), Ok(()));
    }

    #[test]
    fn voucher_rejects_signature_for_mutated_payload() {
        let mut voucher = signed_voucher();
        voucher.total_spent_sompi += 1;
        assert_eq!(
            voucher.verify_payer_signature(),
            Err(ApiPaymentValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn voucher_rejects_malformed_signature_inputs() {
        let mut voucher = signed_voucher();
        voucher.payer_pubkey = "not-hex".to_string();
        assert_eq!(
            voucher.verify_payer_signature(),
            Err(ApiPaymentValidationError::InvalidPayerPubkey)
        );

        let mut voucher = signed_voucher();
        voucher.signature = "00".to_string();
        assert_eq!(
            voucher.verify_payer_signature(),
            Err(ApiPaymentValidationError::InvalidSignature)
        );
    }

    #[test]
    fn close_request_signing_digest_excludes_signature() {
        let a = close_request();
        let mut b = close_request();
        b.signature = "ff".repeat(64);
        assert_eq!(a.signing_digest_hex(), b.signing_digest_hex());
    }

    #[test]
    fn close_request_accepts_valid_payer_signature() {
        let request = signed_close_request();
        request
            .validate_static(close_request_expectation(&request.payer_pubkey))
            .unwrap();
        assert_eq!(request.verify_payer_signature(), Ok(()));
    }

    #[test]
    fn close_request_rejects_signature_for_mutated_payload() {
        let mut request = signed_close_request();
        request.channel_id = "chan_other".to_string();
        assert_eq!(
            request.verify_payer_signature(),
            Err(ApiPaymentValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn close_request_rejects_wrong_or_expired_channel_bindings() {
        let request = close_request();
        let mut expected = close_request_expectation(PAYER_PUBKEY);
        expected.channel_id = "chan_other";
        assert_eq!(
            request.validate_static(expected).unwrap_err(),
            ApiPaymentValidationError::ChannelMismatch {
                expected: "chan_other".to_string(),
                actual: "chan_01".to_string()
            }
        );

        let mut expected = close_request_expectation(PAYER_PUBKEY);
        expected.now_ms = request.expires_at_ms;
        assert_eq!(
            request.validate_static(expected).unwrap_err(),
            ApiPaymentValidationError::Expired {
                expires_at_ms: 1_780_000_090_000,
                now_ms: 1_780_000_090_000
            }
        );
    }

    #[test]
    fn voucher_validates_expected_static_fields() {
        let request_hash = request_binding().canonical_digest_hex();
        voucher(request_hash.clone())
            .validate_static(expectation(&request_hash))
            .unwrap();
    }

    #[test]
    fn voucher_rejects_wrong_channel_pubkey_bindings() {
        let request_hash = request_binding().canonical_digest_hex();
        let mut expected = expectation(&request_hash);
        expected.network_id = "mainnet";
        assert_eq!(
            voucher(request_hash.clone())
                .validate_static(expected)
                .unwrap_err(),
            ApiPaymentValidationError::NetworkMismatch {
                expected: "mainnet".to_string(),
                actual: "testnet-10".to_string()
            }
        );

        let mut expected = expectation(&request_hash);
        expected.channel_id = "chan_other";
        assert_eq!(
            voucher(request_hash.clone())
                .validate_static(expected)
                .unwrap_err(),
            ApiPaymentValidationError::ChannelMismatch {
                expected: "chan_other".to_string(),
                actual: "chan_01".to_string()
            }
        );

        let mut expected = expectation(&request_hash);
        expected.payer_pubkey = OTHER_PAYER_PUBKEY;
        assert_eq!(
            voucher(request_hash.clone())
                .validate_static(expected)
                .unwrap_err(),
            ApiPaymentValidationError::PayerPubkeyMismatch
        );

        let mut expected = expectation(&request_hash);
        expected.provider_pubkey = OTHER_PROVIDER_PUBKEY;
        assert_eq!(
            voucher(request_hash.clone())
                .validate_static(expected)
                .unwrap_err(),
            ApiPaymentValidationError::ProviderPubkeyMismatch
        );
    }

    #[test]
    fn voucher_rejects_request_hash_replay() {
        let request_hash = request_binding().canonical_digest_hex();
        let err = voucher(request_hash)
            .validate_static(expectation(&"00".repeat(32)))
            .unwrap_err();
        assert_eq!(err, ApiPaymentValidationError::RequestHashMismatch);
    }

    #[test]
    fn voucher_rejects_stale_sequence() {
        let request_hash = request_binding().canonical_digest_hex();
        let mut expected = expectation(&request_hash);
        expected.latest_sequence = 2;
        let err = voucher(request_hash.clone())
            .validate_static(expected)
            .unwrap_err();
        assert_eq!(
            err,
            ApiPaymentValidationError::StaleSequence {
                latest_sequence: 2,
                actual_sequence: 2
            }
        );
    }

    #[test]
    fn voucher_rejects_underpayment() {
        let request_hash = request_binding().canonical_digest_hex();
        let mut expected = expectation(&request_hash);
        expected.min_incremental_amount_sompi = 1_001;
        let err = voucher(request_hash.clone())
            .validate_static(expected)
            .unwrap_err();
        assert_eq!(
            err,
            ApiPaymentValidationError::Underpaid {
                required_sompi: 1_001,
                actual_sompi: 1_000
            }
        );
    }

    #[test]
    fn voucher_rejects_overspend() {
        let request_hash = request_binding().canonical_digest_hex();
        let mut expected = expectation(&request_hash);
        expected.max_total_spend_sompi = 9_999;
        let err = voucher(request_hash.clone())
            .validate_static(expected)
            .unwrap_err();
        assert_eq!(
            err,
            ApiPaymentValidationError::Overspend {
                max_total_spend_sompi: 9_999,
                actual_total_spent_sompi: 10_000
            }
        );
    }

    #[test]
    fn settlement_authorization_metadata_digest_excludes_signature() {
        let a = settlement_authorization();
        let mut b = a.clone();
        b.payer_settlement_signature = "42".repeat(65);
        assert_eq!(a.metadata_digest_hex(), b.metadata_digest_hex());

        b.settlement_txid = "33".repeat(32);
        assert_ne!(a.metadata_digest_hex(), b.metadata_digest_hex());
    }

    #[test]
    fn settlement_authorization_digest_matches_wallet_artifact() {
        let settlement = ApiPaymentSettlementAuthorization {
            schema: API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "af3c1065efa87396d1cefe1bf41a877370e5ce04878e3c18ef1cddcc8ba571c0"
                .to_string(),
            payer_pubkey: "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
                .to_string(),
            provider_pubkey: "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
                .to_string(),
            sequence: 1,
            total_spent_sompi: 50_000_000,
            provider_amount_sompi: 50_000_000,
            payer_refund_sompi: 46_000_000,
            settlement_fee_sompi: 4_000_000,
            settlement_txid: "718ab78ecf3b25907d146b1fac35b1cf80efe3ecbc0d572a472ed54072909f72"
                .to_string(),
            settlement_template_hash:
                "ac156f3f8800d5fde4cdd7dc866d73590c014ee0c34dde8cdddd39088d504f78".to_string(),
            refund_after_ms: 1_780_510_711_398,
            issued_at_ms: 1_780_507_260_839,
            expires_at_ms: 1_780_508_160_839,
            payer_settlement_signature: "41".repeat(65),
        };

        assert_eq!(
            settlement.metadata_digest_hex(),
            "5262f860d0f5ad3c1e716fec353529b1d9fe43a9c58e237c63a0a193605365c5"
        );
    }

    fn settlement_artifact() -> ApiPaymentSettlementArtifact {
        let unsigned_settlement_template = serde_json::json!({
            "version": 1,
            "outputs": [],
            "inputs": [],
            "lockTime": 0,
        });
        let mut authorization = settlement_authorization();
        authorization.settlement_template_hash = hex::encode(blake2b_256(
            stable_json(&unsigned_settlement_template)
                .unwrap()
                .as_bytes(),
        ));
        ApiPaymentSettlementArtifact {
            schema: API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1.to_string(),
            contract: "ApiPaymentChannel".to_string(),
            network: authorization.network_id.clone(),
            channel_id: authorization.channel_id.clone(),
            metadata_digest: authorization.metadata_digest_hex(),
            authorization,
            unsigned_settlement_template,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn settlement_artifact_validates_template_and_metadata_binding() {
        settlement_artifact().validate_static().unwrap();
    }

    #[test]
    fn settlement_artifact_rejects_template_hash_mismatch() {
        let mut artifact = settlement_artifact();
        artifact.unsigned_settlement_template = serde_json::json!({});
        assert_eq!(
            artifact.validate_static().unwrap_err(),
            ApiPaymentValidationError::SettlementArtifactTemplateMismatch
        );
    }

    #[test]
    fn settlement_artifact_template_digest_uses_wallet_stable_json() {
        let artifact = settlement_artifact();
        assert_eq!(
            stable_json(&artifact.unsigned_settlement_template).unwrap(),
            r#"{"inputs":[],"lockTime":0,"outputs":[],"version":1}"#
        );
        assert_eq!(
            artifact.settlement_template_digest_hex().unwrap(),
            artifact.authorization.settlement_template_hash
        );
    }

    #[test]
    fn settlement_authorization_validates_enforceable_shape() {
        settlement_authorization()
            .validate_static(settlement_expectation())
            .unwrap();
    }

    #[test]
    fn settlement_authorization_rejects_missing_settlement_signature() {
        let mut settlement = settlement_authorization();
        settlement.payer_settlement_signature.clear();
        assert_eq!(
            settlement
                .validate_static(settlement_expectation())
                .unwrap_err(),
            ApiPaymentValidationError::InvalidSettlementSignature
        );
    }

    #[test]
    fn settlement_authorization_rejects_wrong_payout_math() {
        let mut settlement = settlement_authorization();
        settlement.provider_amount_sompi += 1;
        assert_eq!(
            settlement
                .validate_static(settlement_expectation())
                .unwrap_err(),
            ApiPaymentValidationError::SettlementPayoutMismatch {
                expected_provider_amount_sompi: 12_000,
                actual_provider_amount_sompi: 12_001
            }
        );

        let mut settlement = settlement_authorization();
        settlement.payer_refund_sompi -= 1;
        assert_eq!(
            settlement
                .validate_static(settlement_expectation())
                .unwrap_err(),
            ApiPaymentValidationError::SettlementValueMismatch {
                channel_value_sompi: 50_000,
                provider_amount_sompi: 12_000,
                payer_refund_sompi: 36_999,
                settlement_fee_sompi: 1_000
            }
        );
    }

    #[test]
    fn channel_open_sizing_rejects_tiny_or_invalid_channels() {
        let policy = ApiPaymentChannelSizingPolicy::default();

        assert_eq!(
            validate_api_payment_channel_open_sizing(49_999_999, 0, 1, policy).unwrap_err(),
            ApiPaymentValidationError::ChannelDepositBelowMinimum {
                minimum_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
                actual_sompi: 49_999_999,
            }
        );
        assert_eq!(
            validate_api_payment_channel_open_sizing(50_000_000, 60_000_000, 1, policy)
                .unwrap_err(),
            ApiPaymentValidationError::ChannelSizingInvalid {
                deposit_sompi: 50_000_000,
                reserve_sompi: 60_000_000,
                max_spend_sompi: 1,
            }
        );
        assert_eq!(
            validate_api_payment_channel_open_sizing(100_000_000, 50_000_000, 50_000_001, policy)
                .unwrap_err(),
            ApiPaymentValidationError::ChannelSizingInvalid {
                deposit_sompi: 100_000_000,
                reserve_sompi: 50_000_000,
                max_spend_sompi: 50_000_001,
            }
        );
        validate_api_payment_channel_open_sizing(100_000_000, 50_000_000, 50_000_000, policy)
            .unwrap();
    }

    #[test]
    fn settlement_output_sizing_rejects_tiny_provider_or_refund_outputs() {
        let policy = ApiPaymentChannelSizingPolicy::default();

        assert_eq!(
            validate_api_payment_settlement_output_sizing(49_999_999, 0, policy).unwrap_err(),
            ApiPaymentValidationError::ProviderOutputBelowMinimum {
                minimum_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
                actual_sompi: 49_999_999,
            }
        );
        assert_eq!(
            validate_api_payment_settlement_output_sizing(50_000_000, 49_999_999, policy)
                .unwrap_err(),
            ApiPaymentValidationError::PayerRefundBelowMinimum {
                minimum_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
                actual_sompi: 49_999_999,
            }
        );
        validate_api_payment_settlement_output_sizing(50_000_000, 0, policy).unwrap();
        validate_api_payment_settlement_output_sizing(50_000_000, 50_000_000, policy).unwrap();
    }

    #[test]
    fn settlement_authorization_applies_optional_output_sizing_policy() {
        let mut settlement = settlement_authorization();
        settlement.total_spent_sompi = 50_000_000;
        settlement.provider_amount_sompi = 50_000_000;
        settlement.payer_refund_sompi = 46_000_000;
        settlement.settlement_fee_sompi = 4_000_000;

        let mut expected = settlement_expectation();
        expected.latest_sequence = 2;
        expected.latest_total_spent_sompi = 10_000;
        expected.max_total_spend_sompi = 50_000_000;
        expected.channel_value_sompi = 100_000_000;
        expected.settlement_fee_sompi = 4_000_000;
        expected.sizing_policy = Some(ApiPaymentChannelSizingPolicy::default());

        assert_eq!(
            settlement.validate_static(expected).unwrap_err(),
            ApiPaymentValidationError::PayerRefundBelowMinimum {
                minimum_sompi: API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI,
                actual_sompi: 46_000_000,
            }
        );

        settlement.payer_refund_sompi = 50_000_000;
        expected.channel_value_sompi = 104_000_000;
        settlement.validate_static(expected).unwrap();
    }

    #[test]
    fn settlement_authorization_rejects_after_refund_window() {
        let mut expected = settlement_expectation();
        expected.now_ms = settlement_authorization().refund_after_ms;
        let mut settlement = settlement_authorization();
        settlement.expires_at_ms = expected.now_ms + 1;
        assert_eq!(
            settlement.validate_static(expected).unwrap_err(),
            ApiPaymentValidationError::SettlementAfterRefundWindow {
                refund_after_ms: 1_780_000_120_000,
                now_ms: 1_780_000_120_000
            }
        );
    }

    #[test]
    fn settlement_authorization_rejects_expiry_after_refund_window() {
        let mut settlement = settlement_authorization();
        settlement.expires_at_ms = settlement.refund_after_ms + 1;
        assert_eq!(
            settlement
                .validate_static(settlement_expectation())
                .unwrap_err(),
            ApiPaymentValidationError::SettlementAuthorizationExpiresAfterRefundWindow {
                expires_at_ms: 1_780_000_120_001,
                refund_after_ms: 1_780_000_120_000
            }
        );
    }

    #[test]
    fn settlement_authorization_rejects_expiry_at_refund_window() {
        let mut settlement = settlement_authorization();
        settlement.expires_at_ms = settlement.refund_after_ms;
        assert_eq!(
            settlement
                .validate_static(settlement_expectation())
                .unwrap_err(),
            ApiPaymentValidationError::SettlementAuthorizationExpiresAfterRefundWindow {
                expires_at_ms: 1_780_000_120_000,
                refund_after_ms: 1_780_000_120_000
            }
        );
    }

    #[test]
    fn settlement_authorization_rejects_non_monotonic_or_overspend() {
        let mut expected = settlement_expectation();
        expected.latest_sequence = 3;
        assert_eq!(
            settlement_authorization()
                .validate_static(expected)
                .unwrap_err(),
            ApiPaymentValidationError::StaleSequence {
                latest_sequence: 3,
                actual_sequence: 3
            }
        );

        let mut expected = settlement_expectation();
        expected.max_total_spend_sompi = 11_999;
        assert_eq!(
            settlement_authorization()
                .validate_static(expected)
                .unwrap_err(),
            ApiPaymentValidationError::Overspend {
                max_total_spend_sompi: 11_999,
                actual_total_spent_sompi: 12_000
            }
        );
    }
}
