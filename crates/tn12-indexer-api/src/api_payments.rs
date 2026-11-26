use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use thiserror::Error;
use tn12_indexer_core::{
    blake2b_256, ApiPaymentIntent, ApiPaymentMethod, ApiPaymentQueryParam,
    ApiPaymentRequestBinding, ApiPaymentVoucher, ApiPaymentVoucherExpectation, RestTransaction,
};
use tn12_indexer_db::api_payments::{
    accept_api_payment_voucher, api_payment_channel_by_id, ApiPaymentPricingRouteRow,
    ApiPaymentVoucherAcceptance,
};
use tn12_indexer_db::PgPool;

pub const AUTHORIZATION: &str = "authorization";
pub const PAYMENT_RECEIPT: &str = "payment-receipt";
pub const WWW_AUTHENTICATE: &str = "www-authenticate";

pub const EMPTY_BODY_HASH_HEX: &str =
    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
pub const API_PAYMENT_PROOF_DISCOVERY_PRICING_ID: &str = "api-payment.proof.kcc20-discovery.v1";
pub const API_PAYMENT_PROOF_DISCOVERY_PATH: &str = "/payments/proof/kcc20-discovery";
pub const API_PAYMENT_PROOF_DISCOVERY_ROUTE: &str = "GET /payments/proof/kcc20-discovery";
pub const API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID: &str = "api-payment.proof.body-echo.v1";
pub const API_PAYMENT_PROOF_BODY_ECHO_PATH: &str = "/payments/proof/body-echo";
pub const API_PAYMENT_PROOF_BODY_ECHO_ROUTE: &str = "POST /payments/proof/body-echo";
pub const API_PAYMENT_FREE_ROUTES: &[&str] = &[
    "GET /livez",
    "GET /readyz",
    "GET /health",
    "GET /openapi.json",
    "GET /swagger-ui",
    "GET /payments/pricing",
    "GET /payments/metrics",
    "GET /payments/debug",
    "POST /payments/challenges",
    "POST /payments/direct-proofs",
    "GET /payments/direct-proofs/{txid}",
    "POST /payments/direct-proofs/{txid}/verify",
    "GET /payments/receipts/{receiptId}",
    "GET /payments/channels/{channelId}",
    "POST /payments/channels/{channelId}/sync",
    "POST /payments/channels/{channelId}/close",
    "GET /payments/settlements/{txid}",
];
pub const DIRECT_PAYMENT_EXPIRY_MS: u64 = 10 * 60 * 1000;
pub const DIRECT_PAYMENT_PAYLOAD_PREFIX: &str = "kaspa-api-payment:v1";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentChallengeRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub raw_query: Option<String>,
    #[serde(default)]
    pub body_hash_hex: Option<String>,
    #[serde(default)]
    pub payment_method: Option<ApiPaymentMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentChallenge {
    pub id: String,
    pub method: ApiPaymentMethod,
    pub intent: ApiPaymentIntent,
    pub request: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiDirectPaymentCredential {
    pub method: ApiPaymentMethod,
    pub txid_hex: String,
    #[serde(default)]
    pub payer_identifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiPaymentCredential {
    Channel(ApiPaymentVoucher),
    Direct(ApiDirectPaymentCredential),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentReceipt {
    pub receipt_id: String,
    pub channel_id: Option<String>,
    pub voucher_sequence: Option<u64>,
    pub amount_sompi: u64,
    pub pricing_id: String,
    pub request_hash: String,
    #[serde(default, skip_serializing, skip_deserializing)]
    pub payer_identifier_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiDirectPaymentProofRequest {
    pub challenge_id: String,
    pub network_id: String,
    pub txid_hex: String,
    #[serde(default)]
    pub payer_identifier: Option<String>,
    pub recipient_address: String,
    pub amount_sompi: String,
    pub pricing_id: String,
    pub route: String,
    pub request_hash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiDirectPaymentProofResponse {
    pub receipt_id: String,
    pub challenge_id: String,
    pub txid_hex: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub amount_sompi: String,
    pub pricing_id: String,
    pub route: String,
    pub request_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at_ms: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_at_ms: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentChannelStatusResponse {
    pub channel_id: String,
    pub network_id: String,
    pub status: String,
    pub payer_identifier: String,
    pub payer_pubkey: String,
    pub provider_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_payout_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_domain_hash: Option<String>,
    pub deposit_sompi: String,
    pub reserve_sompi: String,
    pub spent_sompi: String,
    pub remaining_sompi: String,
    pub latest_sequence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_spend_sompi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_after_ms: Option<String>,
    pub close_after_ms: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_vout: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_at_ms: Option<String>,
    pub updated_at_ms: String,
    pub scanner: Value,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentChannelSyncRequest {
    pub txid_hex: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentSettlementStatusResponse {
    pub txid_hex: String,
    pub indexed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_sequence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_total_sompi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_amount_sompi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_refund_sompi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexer_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexed_at_ms: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<String>,
    pub scanner: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentReceiptStatusResponse {
    pub receipt_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    pub route: String,
    pub pricing_id: String,
    pub amount_sompi: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_sequence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<String>,
    pub created_at_ms: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_total_spent_sompi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_accepted_at_ms: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_spent_sompi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_latest_sequence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiDirectPaymentExpectation {
    pub challenge_id: String,
    pub txid_hex: String,
    pub recipient_address: String,
    pub amount_sompi: u64,
    pub request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiDirectPaymentVerification {
    pub status: String,
    pub failure_reason: Option<String>,
    pub raw_status_snapshot: Value,
}

#[derive(Debug, Clone)]
pub struct ApiPaymentRoutePolicy {
    pub challenge_id: String,
    pub network_id: String,
    pub pricing_id: String,
    pub route: String,
    pub request_hash: String,
    pub amount_sompi: u64,
    pub now_ms: u64,
    pub refund_safety_margin_ms: u64,
    pub payer_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentChallengeResponse {
    pub challenge: ApiPaymentChallenge,
    pub pricing_id: String,
    pub route: String,
    pub amount_sompi: String,
    pub request_hash: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentPolicyCatalog {
    pub enabled: bool,
    pub network_id: String,
    pub kcc20_discovery_sompi: u64,
    pub refund_safety_margin_ms: u64,
    pub direct_recipient_address: Option<String>,
    paid_routes: Vec<ApiPaymentPaidRouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentPaidRouteConfig {
    pub pricing_id: String,
    pub method: String,
    pub path: String,
    pub route: String,
    pub amount_sompi: u64,
    pub method_name: ApiPaymentMethod,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentPricingRoute {
    pub pricing_id: String,
    pub method: String,
    pub path: String,
    pub route: String,
    pub amount_sompi: String,
    pub method_name: ApiPaymentMethod,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApiPaymentPricingResponse {
    pub enabled: bool,
    pub network_id: String,
    pub methods: Vec<ApiPaymentMethod>,
    pub free_routes: Vec<String>,
    pub paid_routes: Vec<ApiPaymentPricingRoute>,
}

impl ApiPaymentPolicyCatalog {
    pub fn new(enabled: bool, network_id: impl Into<String>, kcc20_discovery_sompi: u64) -> Self {
        Self {
            enabled,
            network_id: network_id.into(),
            kcc20_discovery_sompi,
            refund_safety_margin_ms: 0,
            direct_recipient_address: None,
            paid_routes: vec![
                ApiPaymentPaidRouteConfig {
                    pricing_id: API_PAYMENT_PROOF_DISCOVERY_PRICING_ID.to_string(),
                    method: "GET".to_string(),
                    path: API_PAYMENT_PROOF_DISCOVERY_PATH.to_string(),
                    route: API_PAYMENT_PROOF_DISCOVERY_ROUTE.to_string(),
                    amount_sompi: kcc20_discovery_sompi,
                    method_name: ApiPaymentMethod::KaspaChannel,
                    enabled: kcc20_discovery_sompi > 0,
                },
                ApiPaymentPaidRouteConfig {
                    pricing_id: API_PAYMENT_PROOF_BODY_ECHO_PRICING_ID.to_string(),
                    method: "POST".to_string(),
                    path: API_PAYMENT_PROOF_BODY_ECHO_PATH.to_string(),
                    route: API_PAYMENT_PROOF_BODY_ECHO_ROUTE.to_string(),
                    amount_sompi: kcc20_discovery_sompi,
                    method_name: ApiPaymentMethod::KaspaChannel,
                    enabled: kcc20_discovery_sompi > 0,
                },
            ],
        }
    }

    pub fn with_refund_safety_margin_ms(mut self, refund_safety_margin_ms: u64) -> Self {
        self.refund_safety_margin_ms = refund_safety_margin_ms;
        self
    }

    pub fn with_direct_recipient(mut self, recipient_address: Option<String>) -> Self {
        self.direct_recipient_address = recipient_address.filter(|value| !value.trim().is_empty());
        self
    }

    pub fn with_paid_route_allowlist(mut self, routes: Option<&str>) -> Self {
        let Some(routes) = routes else {
            return self;
        };
        let allowed = parse_paid_route_allowlist(routes);
        for route in &mut self.paid_routes {
            route.enabled = route.enabled && allowed.contains(&route.route);
        }
        self
    }

    pub fn with_pricing_rows(mut self, rows: Vec<ApiPaymentPricingRouteRow>) -> Self {
        let routes: Vec<_> = rows
            .into_iter()
            .filter_map(ApiPaymentPaidRouteConfig::from_db_row)
            .collect();
        if !routes.is_empty() {
            if let Some(route) = routes
                .iter()
                .find(|route| route.pricing_id == API_PAYMENT_PROOF_DISCOVERY_PRICING_ID)
            {
                self.kcc20_discovery_sompi = route.amount_sompi;
            }
            self.paid_routes = routes;
        }
        self
    }

    pub fn pricing_response(&self) -> ApiPaymentPricingResponse {
        ApiPaymentPricingResponse {
            enabled: self.enabled,
            network_id: self.network_id.clone(),
            methods: self.supported_methods(),
            free_routes: API_PAYMENT_FREE_ROUTES
                .iter()
                .map(|route| (*route).to_string())
                .collect(),
            paid_routes: self
                .paid_routes
                .iter()
                .map(|route| route.to_pricing_route(self.enabled))
                .collect(),
        }
    }

    pub fn route_policy(
        &self,
        route: &str,
        request_hash: String,
        now_ms: u64,
    ) -> Option<ApiPaymentRoutePolicy> {
        let route = self.route_by_route(route)?;
        if !self.enabled || !route.enabled || route.amount_sompi == 0 {
            return None;
        }
        Some(ApiPaymentRoutePolicy {
            challenge_id: challenge_id(&route.pricing_id, &request_hash),
            network_id: self.network_id.clone(),
            pricing_id: route.pricing_id.clone(),
            route: route.route.clone(),
            request_hash,
            amount_sompi: route.amount_sompi,
            now_ms,
            refund_safety_margin_ms: self.refund_safety_margin_ms,
            payer_identifier: None,
        })
    }

    pub fn challenge_for_request(
        &self,
        request: &ApiPaymentChallengeRequest,
        now_ms: u64,
    ) -> Result<ApiPaymentChallengeResponse, ApiPaymentChallengeError> {
        let method = request.method.to_ascii_uppercase();
        let route = format!("{method} {}", request.path);
        let route_config = self
            .route_by_route(&route)
            .ok_or(ApiPaymentChallengeError::UnsupportedRoute)?;
        if request
            .body_hash_hex
            .as_deref()
            .is_some_and(|body_hash| !is_hex_32(body_hash))
        {
            return Err(ApiPaymentChallengeError::InvalidBodyHash);
        }
        let request_hash = get_request_hash_for_method(
            &method,
            &request.path,
            request.raw_query.as_deref(),
            request
                .body_hash_hex
                .as_deref()
                .unwrap_or(EMPTY_BODY_HASH_HEX),
        );
        match request
            .payment_method
            .clone()
            .unwrap_or(ApiPaymentMethod::KaspaChannel)
        {
            ApiPaymentMethod::KaspaChannel => {
                let Some(policy) = self.route_policy(&route, request_hash.clone(), now_ms) else {
                    return Err(ApiPaymentChallengeError::RouteNotPriced);
                };
                Ok(ApiPaymentChallengeResponse {
                    challenge: challenge_for_policy(&policy),
                    pricing_id: policy.pricing_id,
                    route: policy.route,
                    amount_sompi: policy.amount_sompi.to_string(),
                    request_hash,
                    enabled: true,
                })
            }
            ApiPaymentMethod::KaspaDirect => {
                let Some(recipient_address) = self.direct_recipient_address.as_ref() else {
                    return Err(ApiPaymentChallengeError::DirectRecipientMissing);
                };
                if !self.enabled || !route_config.enabled || route_config.amount_sompi == 0 {
                    return Err(ApiPaymentChallengeError::RouteNotPriced);
                }
                let challenge_id = direct_challenge_id(
                    &self.network_id,
                    &route_config.pricing_id,
                    &request_hash,
                    recipient_address,
                    route_config.amount_sompi,
                );
                Ok(ApiPaymentChallengeResponse {
                    challenge: ApiPaymentChallenge {
                        id: challenge_id.clone(),
                        method: ApiPaymentMethod::KaspaDirect,
                        intent: ApiPaymentIntent::Charge,
                        request: json!({
                            "networkId": self.network_id.clone(),
                            "challengeId": challenge_id,
                            "pricingId": route_config.pricing_id.clone(),
                            "route": route_config.route.clone(),
                            "requestHash": request_hash,
                            "amountSompi": route_config.amount_sompi.to_string(),
                            "recipientAddress": recipient_address,
                            "payloadHex": direct_payment_payload_hex(&challenge_id, &request_hash),
                            "expiresAtMs": now_ms.saturating_add(DIRECT_PAYMENT_EXPIRY_MS).to_string(),
                        }),
                    },
                    pricing_id: route_config.pricing_id.clone(),
                    route: route_config.route.clone(),
                    amount_sompi: route_config.amount_sompi.to_string(),
                    request_hash,
                    enabled: true,
                })
            }
        }
    }

    pub fn validate_direct_payment_proof(
        &self,
        proof: &ApiDirectPaymentProofRequest,
    ) -> Result<u64, ApiDirectPaymentProofError> {
        let Some(route) = self.route_by_pricing_id(&proof.pricing_id) else {
            return Err(ApiDirectPaymentProofError::RouteNotPriced);
        };
        if !self.enabled || !route.enabled || route.amount_sompi == 0 {
            return Err(ApiDirectPaymentProofError::RouteNotPriced);
        }
        let Some(recipient_address) = self.direct_recipient_address.as_ref() else {
            return Err(ApiDirectPaymentProofError::DirectRecipientMissing);
        };
        if proof.network_id != self.network_id {
            return Err(ApiDirectPaymentProofError::NetworkMismatch);
        }
        if proof.pricing_id != route.pricing_id || proof.route != route.route {
            return Err(ApiDirectPaymentProofError::RouteMismatch);
        }
        if proof.recipient_address != *recipient_address {
            return Err(ApiDirectPaymentProofError::RecipientMismatch);
        }
        if !is_hex_32(&proof.txid_hex) {
            return Err(ApiDirectPaymentProofError::InvalidTxid);
        }
        if !is_hex_32(&proof.request_hash) {
            return Err(ApiDirectPaymentProofError::InvalidRequestHash);
        }
        let amount_sompi = proof
            .amount_sompi
            .parse::<u64>()
            .map_err(|_| ApiDirectPaymentProofError::InvalidAmount)?;
        if amount_sompi < route.amount_sompi {
            return Err(ApiDirectPaymentProofError::Underpaid);
        }
        let expected_challenge_id = direct_challenge_id(
            &proof.network_id,
            &route.pricing_id,
            &proof.request_hash,
            recipient_address,
            route.amount_sompi,
        );
        if proof.challenge_id != expected_challenge_id {
            return Err(ApiDirectPaymentProofError::ChallengeMismatch);
        }
        Ok(amount_sompi)
    }

    pub fn direct_payment_proof_request_for_policy(
        &self,
        policy: &ApiPaymentRoutePolicy,
        credential: ApiDirectPaymentCredential,
    ) -> Result<ApiDirectPaymentProofRequest, ApiDirectPaymentProofError> {
        let Some(recipient_address) = self.direct_recipient_address.as_ref() else {
            return Err(ApiDirectPaymentProofError::DirectRecipientMissing);
        };
        if credential.method != ApiPaymentMethod::KaspaDirect {
            return Err(ApiDirectPaymentProofError::RouteMismatch);
        }
        if policy
            .payer_identifier
            .as_deref()
            .is_some_and(|expected| credential.payer_identifier.as_deref() != Some(expected))
        {
            return Err(ApiDirectPaymentProofError::PayerIdentifierMismatch);
        }
        if !is_hex_32(&credential.txid_hex) {
            return Err(ApiDirectPaymentProofError::InvalidTxid);
        }
        Ok(ApiDirectPaymentProofRequest {
            challenge_id: direct_challenge_id(
                &policy.network_id,
                &policy.pricing_id,
                &policy.request_hash,
                recipient_address,
                policy.amount_sompi,
            ),
            network_id: policy.network_id.clone(),
            txid_hex: credential.txid_hex.to_ascii_lowercase(),
            payer_identifier: credential.payer_identifier,
            recipient_address: recipient_address.clone(),
            amount_sompi: policy.amount_sompi.to_string(),
            pricing_id: policy.pricing_id.clone(),
            route: policy.route.clone(),
            request_hash: policy.request_hash.clone(),
        })
    }

    fn supported_methods(&self) -> Vec<ApiPaymentMethod> {
        let mut methods = vec![ApiPaymentMethod::KaspaChannel];
        if self.direct_recipient_address.is_some() {
            methods.push(ApiPaymentMethod::KaspaDirect);
        }
        methods
    }

    fn route_by_route(&self, route: &str) -> Option<&ApiPaymentPaidRouteConfig> {
        self.paid_routes.iter().find(|config| config.route == route)
    }

    fn route_by_pricing_id(&self, pricing_id: &str) -> Option<&ApiPaymentPaidRouteConfig> {
        self.paid_routes
            .iter()
            .find(|route| route.pricing_id == pricing_id)
    }
}

impl ApiPaymentPaidRouteConfig {
    fn from_db_row(row: ApiPaymentPricingRouteRow) -> Option<Self> {
        let amount_sompi = u64::try_from(row.base_sompi).ok()?;
        let path = row.path_pattern;
        let method = row.method.to_ascii_uppercase();
        Some(Self {
            pricing_id: row.pricing_id,
            route: format!("{method} {path}"),
            method,
            path,
            amount_sompi,
            method_name: ApiPaymentMethod::KaspaChannel,
            enabled: row.enabled,
        })
    }

    fn to_pricing_route(&self, catalog_enabled: bool) -> ApiPaymentPricingRoute {
        ApiPaymentPricingRoute {
            pricing_id: self.pricing_id.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            route: self.route.clone(),
            amount_sompi: self.amount_sompi.to_string(),
            method_name: self.method_name.clone(),
            enabled: catalog_enabled && self.enabled && self.amount_sompi > 0,
        }
    }
}

pub fn is_free_route(method: &str, path: &str) -> bool {
    let route = format!("{} {}", method.to_ascii_uppercase(), path);
    API_PAYMENT_FREE_ROUTES.contains(&route.as_str())
        || (method.eq_ignore_ascii_case("GET")
            && (path == "/swagger-ui" || path.starts_with("/swagger-ui/")))
}

fn parse_paid_route_allowlist(routes: &str) -> BTreeSet<String> {
    routes
        .split([',', '\n', ';'])
        .map(str::trim)
        .filter(|route| !route.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiPaymentChallengeError {
    #[error("payment route is not supported")]
    UnsupportedRoute,
    #[error("payment route is not currently priced")]
    RouteNotPriced,
    #[error("bodyHashHex must be 32-byte hex")]
    InvalidBodyHash,
    #[error("direct payment recipient is not configured")]
    DirectRecipientMissing,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiDirectPaymentProofError {
    #[error("payment route is not currently priced")]
    RouteNotPriced,
    #[error("direct payment recipient is not configured")]
    DirectRecipientMissing,
    #[error("direct payment network mismatch")]
    NetworkMismatch,
    #[error("direct payment route mismatch")]
    RouteMismatch,
    #[error("direct payment payer identifier mismatch")]
    PayerIdentifierMismatch,
    #[error("direct payment recipient mismatch")]
    RecipientMismatch,
    #[error("txidHex must be 32-byte hex")]
    InvalidTxid,
    #[error("requestHash must be 32-byte hex")]
    InvalidRequestHash,
    #[error("amountSompi must be a positive integer string")]
    InvalidAmount,
    #[error("direct payment amount is below the required route price")]
    Underpaid,
    #[error("direct payment challenge does not match request binding")]
    ChallengeMismatch,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiPaymentHttpError {
    #[error("payment authorization header is not valid UTF-8")]
    InvalidHeader,
    #[error("payment authorization scheme must be Payment")]
    InvalidScheme,
    #[error("payment authorization credential is missing")]
    MissingCredential,
    #[error("multiple payment authorization credentials are not allowed")]
    AmbiguousCredential,
    #[error("payment authorization credential is not valid base64url JSON")]
    MalformedCredential,
}

#[derive(Debug, Error)]
pub enum ApiPaymentGuardError {
    #[error("payment is required")]
    MissingPayment,
    #[error("payment authorization is malformed: {0}")]
    InvalidAuthorization(ApiPaymentHttpError),
    #[error("payment channel is unknown")]
    UnknownChannel,
    #[error("payment channel is not usable")]
    ChannelNotUsable,
    #[error("payment channel is inside the refund safety window")]
    ChannelRefundSafetyWindow,
    #[error("payment channel payer does not match route identity")]
    PayerIdentifierMismatch,
    #[error("payment voucher is invalid: {0}")]
    InvalidVoucher(String),
    #[error("payment voucher was not accepted")]
    VoucherNotAccepted,
    #[error("payment persistence is unavailable")]
    PersistenceUnavailable,
}

impl ApiPaymentGuardError {
    pub fn failure_code(&self) -> &'static str {
        match self {
            ApiPaymentGuardError::MissingPayment => "missing-payment",
            ApiPaymentGuardError::InvalidAuthorization(_) => "invalid-payment-authorization",
            ApiPaymentGuardError::UnknownChannel => "unknown-payment-channel",
            ApiPaymentGuardError::ChannelNotUsable => "payment-channel-not-usable",
            ApiPaymentGuardError::ChannelRefundSafetyWindow => "payment-channel-refund-window",
            ApiPaymentGuardError::PayerIdentifierMismatch => "payment-payer-mismatch",
            ApiPaymentGuardError::InvalidVoucher(_) => "invalid-payment-voucher",
            ApiPaymentGuardError::VoucherNotAccepted => "payment-voucher-not-accepted",
            ApiPaymentGuardError::PersistenceUnavailable => "payment-persistence-unavailable",
        }
    }

    pub fn into_response(self, policy: &ApiPaymentRoutePolicy) -> Response {
        match self {
            ApiPaymentGuardError::PersistenceUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "type": "https://kaspa.com/problems/payment-persistence-unavailable",
                    "title": "Payment Persistence Unavailable",
                    "status": 503
                })),
            )
                .into_response(),
            other => {
                let failure_code = other.failure_code();
                let detail = other.to_string();
                payment_required_response(
                    &challenge_for_policy(policy),
                    Some(failure_code),
                    Some(&detail),
                )
                .into_response()
            }
        }
    }
}

pub async fn authorize_api_payment(
    pool: &PgPool,
    headers: &HeaderMap,
    policy: &ApiPaymentRoutePolicy,
) -> Result<ApiPaymentReceipt, ApiPaymentGuardError> {
    let voucher = parse_payment_authorization(headers)
        .map_err(ApiPaymentGuardError::InvalidAuthorization)?
        .ok_or(ApiPaymentGuardError::MissingPayment)?;

    let channel = api_payment_channel_by_id(pool, &voucher.channel_id)
        .await
        .map_err(|_| ApiPaymentGuardError::PersistenceUnavailable)?
        .ok_or(ApiPaymentGuardError::UnknownChannel)?;
    if channel.status != "usable" {
        return Err(ApiPaymentGuardError::ChannelNotUsable);
    }
    let refund_safety_cutoff_ms = policy
        .now_ms
        .saturating_add(policy.refund_safety_margin_ms)
        .min(i64::MAX as u64) as i64;
    if channel
        .refund_after_ms
        .is_some_and(|refund_after_ms| refund_after_ms <= refund_safety_cutoff_ms)
    {
        return Err(ApiPaymentGuardError::ChannelRefundSafetyWindow);
    }
    if policy
        .payer_identifier
        .as_deref()
        .is_some_and(|expected| expected != channel.payer_identifier)
    {
        return Err(ApiPaymentGuardError::PayerIdentifierMismatch);
    }

    let max_total_spend_sompi = (channel.deposit_sompi - channel.reserve_sompi).max(0) as u64;
    voucher
        .validate_static(ApiPaymentVoucherExpectation {
            network_id: &policy.network_id,
            channel_id: &channel.channel_id,
            payer_pubkey: &channel.payer_pubkey,
            provider_pubkey: &channel.provider_pubkey,
            request_hash: &policy.request_hash,
            pricing_id: &policy.pricing_id,
            route: &policy.route,
            now_ms: policy.now_ms,
            min_incremental_amount_sompi: policy.amount_sompi,
            latest_sequence: channel.latest_sequence as u64,
            latest_total_spent_sompi: channel.spent_sompi as u64,
            max_total_spend_sompi,
        })
        .map_err(|err| ApiPaymentGuardError::InvalidVoucher(err.to_string()))?;
    voucher
        .verify_payer_signature()
        .map_err(|err| ApiPaymentGuardError::InvalidVoucher(err.to_string()))?;

    let credential_hash_hex = credential_hash_hex(&voucher)
        .map_err(|_| ApiPaymentGuardError::InvalidVoucher("voucher is not serializable".into()))?;
    let accepted = accept_api_payment_voucher(
        pool,
        &voucher,
        ApiPaymentVoucherAcceptance {
            credential_hash_hex: credential_hash_hex.clone(),
            accepted_at_ms: policy.now_ms as i64,
            served_status: Some(200),
        },
    )
    .await
    .map_err(|_| ApiPaymentGuardError::PersistenceUnavailable)?;
    if accepted.is_none() {
        return Err(ApiPaymentGuardError::VoucherNotAccepted);
    }

    Ok(ApiPaymentReceipt {
        receipt_id: format!("apr_{credential_hash_hex}"),
        channel_id: Some(voucher.channel_id),
        voucher_sequence: Some(voucher.sequence),
        amount_sompi: voucher.incremental_amount_sompi,
        pricing_id: voucher.pricing_id,
        request_hash: voucher.request_hash,
        payer_identifier_hash_hex: Some(payer_identifier_hash_hex(&channel.payer_identifier)),
    })
}

pub fn payer_identifier_hash_hex(payer_identifier: &str) -> String {
    hex::encode(blake2b_256(payer_identifier.as_bytes()))
}

pub fn payment_required_response(
    challenge: &ApiPaymentChallenge,
    failure_code: Option<&str>,
    detail: Option<&str>,
) -> (StatusCode, HeaderMap, Json<Value>) {
    let mut headers = HeaderMap::new();
    if let Ok(value) = payment_challenge_header(challenge) {
        headers.insert(WWW_AUTHENTICATE, value);
    }

    let mut body = json!({
        "type": "https://kaspa.com/problems/payment-required",
        "title": "Payment Required",
        "status": 402,
        "payment": {
            "challengeId": challenge.id,
            "method": challenge.method,
            "intent": challenge.intent
        }
    });
    if let Some(failure_code) = failure_code {
        body["failureCode"] = json!(failure_code);
    }
    if let Some(detail) = detail {
        body["detail"] = json!(detail);
    }
    (StatusCode::PAYMENT_REQUIRED, headers, Json(body))
}

pub fn payment_challenge_header(
    challenge: &ApiPaymentChallenge,
) -> serde_json::Result<HeaderValue> {
    let request = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&challenge.request)?);
    let value = format!(
        "Payment id=\"{}\", method=\"{}\", intent=\"{}\", request=\"{}\"",
        escape_header_param(&challenge.id),
        challenge.method,
        challenge.intent,
        request
    );
    Ok(HeaderValue::from_str(&value).expect("base64url payment challenge header is valid ASCII"))
}

pub fn parse_payment_authorization(
    headers: &HeaderMap,
) -> Result<Option<ApiPaymentVoucher>, ApiPaymentHttpError> {
    match parse_payment_credential(headers)? {
        Some(ApiPaymentCredential::Channel(voucher)) => Ok(Some(voucher)),
        Some(ApiPaymentCredential::Direct(_)) => Err(ApiPaymentHttpError::MalformedCredential),
        None => Ok(None),
    }
}

pub fn parse_payment_credential(
    headers: &HeaderMap,
) -> Result<Option<ApiPaymentCredential>, ApiPaymentHttpError> {
    if headers.get_all(AUTHORIZATION).iter().count() > 1 {
        return Err(ApiPaymentHttpError::AmbiguousCredential);
    }
    let Some(value) = headers.get(AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApiPaymentHttpError::InvalidHeader)?;
    let Some((scheme, credential)) = value.split_once(' ') else {
        return Err(ApiPaymentHttpError::MissingCredential);
    };
    if !scheme.eq_ignore_ascii_case("Payment") {
        return Err(ApiPaymentHttpError::InvalidScheme);
    }
    if credential.trim().is_empty() {
        return Err(ApiPaymentHttpError::MissingCredential);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(credential.trim())
        .map_err(|_| ApiPaymentHttpError::MalformedCredential)?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| ApiPaymentHttpError::MalformedCredential)?;
    if value
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method == "kaspa-direct")
    {
        let credential =
            serde_json::from_value(value).map_err(|_| ApiPaymentHttpError::MalformedCredential)?;
        return Ok(Some(ApiPaymentCredential::Direct(credential)));
    }
    let voucher =
        serde_json::from_value(value).map_err(|_| ApiPaymentHttpError::MalformedCredential)?;
    Ok(Some(ApiPaymentCredential::Channel(voucher)))
}

pub fn payment_receipt_header(receipt: &ApiPaymentReceipt) -> serde_json::Result<HeaderValue> {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(receipt)?);
    Ok(HeaderValue::from_str(&encoded).expect("base64url payment receipt header is valid ASCII"))
}

pub fn insert_payment_receipt_header(
    headers: &mut HeaderMap,
    receipt: &ApiPaymentReceipt,
) -> serde_json::Result<()> {
    headers.insert(PAYMENT_RECEIPT, payment_receipt_header(receipt)?);
    Ok(())
}

pub fn decode_payment_receipt_header(
    value: &HeaderValue,
) -> Result<ApiPaymentReceipt, ApiPaymentHttpError> {
    let value = value
        .to_str()
        .map_err(|_| ApiPaymentHttpError::InvalidHeader)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiPaymentHttpError::MalformedCredential)?;
    serde_json::from_slice(&bytes).map_err(|_| ApiPaymentHttpError::MalformedCredential)
}

pub fn get_request_hash(uri: &Uri) -> String {
    get_request_hash_for_get(uri.path(), uri.query(), EMPTY_BODY_HASH_HEX)
}

pub fn get_request_hash_for_get(
    path: &str,
    raw_query: Option<&str>,
    body_hash_hex: &str,
) -> String {
    get_request_hash_for_method("GET", path, raw_query, body_hash_hex)
}

pub fn get_request_hash_for_method(
    method: &str,
    path: &str,
    raw_query: Option<&str>,
    body_hash_hex: &str,
) -> String {
    ApiPaymentRequestBinding {
        method: method.to_ascii_uppercase(),
        path: path.to_string(),
        query: query_params(raw_query),
        headers: Vec::new(),
        body_hash_hex: body_hash_hex.to_string(),
    }
    .canonical_digest_hex()
}

pub fn direct_payment_payload_hex(challenge_id: &str, request_hash: &str) -> String {
    hex::encode(blake2b_256(
        format!("{DIRECT_PAYMENT_PAYLOAD_PREFIX}:{challenge_id}:{request_hash}").as_bytes(),
    ))
}

pub fn verify_direct_payment_transaction(
    expectation: &ApiDirectPaymentExpectation,
    tx: &RestTransaction,
) -> ApiDirectPaymentVerification {
    let expected_payload_hex =
        direct_payment_payload_hex(&expectation.challenge_id, &expectation.request_hash);
    let observed_payload_hex = tx.payload.as_deref().unwrap_or("").to_ascii_lowercase();
    let txid_matches = tx
        .transaction_id
        .eq_ignore_ascii_case(expectation.txid_hex.as_str());
    let payload_matches = observed_payload_hex == expected_payload_hex;
    let matching_output = tx.outputs.iter().find(|output| {
        output
            .script_public_key_address
            .as_deref()
            .is_some_and(|address| address == expectation.recipient_address)
            && output.amount >= expectation.amount_sompi
    });
    let output_matches = matching_output.is_some();

    let mut snapshot = json!({
        "txidHex": tx.transaction_id,
        "txidMatches": txid_matches,
        "isAccepted": tx.is_accepted,
        "acceptingBlockHash": tx.accepting_block_hash,
        "acceptingBlockBlueScore": tx.accepting_block_blue_score,
        "acceptingBlockTime": tx.accepting_block_time,
        "expectedRecipientAddress": expectation.recipient_address,
        "expectedAmountSompi": expectation.amount_sompi.to_string(),
        "expectedPayloadHex": expected_payload_hex,
        "observedPayloadHex": observed_payload_hex,
        "payloadMatches": payload_matches,
        "outputMatches": output_matches,
    });
    if let Some(output) = matching_output {
        snapshot["matchingOutput"] = json!({
            "index": output.index,
            "amountSompi": output.amount.to_string(),
            "scriptPublicKeyAddress": output.script_public_key_address,
            "scriptPublicKeyType": output.script_public_key_type,
        });
    }

    if !txid_matches {
        return ApiDirectPaymentVerification {
            status: "rejected".to_string(),
            failure_reason: Some("transaction id mismatch".to_string()),
            raw_status_snapshot: snapshot,
        };
    }
    if !payload_matches {
        return ApiDirectPaymentVerification {
            status: "rejected".to_string(),
            failure_reason: Some("payment payload does not match challenge binding".to_string()),
            raw_status_snapshot: snapshot,
        };
    }
    if !output_matches {
        return ApiDirectPaymentVerification {
            status: "rejected".to_string(),
            failure_reason: Some(
                "payment output does not satisfy recipient and amount".to_string(),
            ),
            raw_status_snapshot: snapshot,
        };
    }
    if !tx.is_accepted {
        return ApiDirectPaymentVerification {
            status: "verified".to_string(),
            failure_reason: Some("transaction is not accepted yet".to_string()),
            raw_status_snapshot: snapshot,
        };
    }

    ApiDirectPaymentVerification {
        status: "accepted".to_string(),
        failure_reason: None,
        raw_status_snapshot: snapshot,
    }
}

fn escape_header_param(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn challenge_for_policy(policy: &ApiPaymentRoutePolicy) -> ApiPaymentChallenge {
    ApiPaymentChallenge {
        id: policy.challenge_id.clone(),
        method: ApiPaymentMethod::KaspaChannel,
        intent: ApiPaymentIntent::Session,
        request: json!({
            "networkId": policy.network_id,
            "pricingId": policy.pricing_id,
            "route": policy.route,
            "requestHash": policy.request_hash,
            "amountSompi": policy.amount_sompi.to_string(),
        }),
    }
}

fn credential_hash_hex(voucher: &ApiPaymentVoucher) -> serde_json::Result<String> {
    Ok(hex::encode(blake2b_256(&serde_json::to_vec(voucher)?)))
}

fn query_params(raw_query: Option<&str>) -> Vec<ApiPaymentQueryParam> {
    raw_query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
        .enumerate()
        .map(|(index, pair)| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            ApiPaymentQueryParam {
                name: name.to_string(),
                value: value.to_string(),
                index: index as u32,
            }
        })
        .collect()
}

fn challenge_id(pricing_id: &str, request_hash: &str) -> String {
    let digest = hex::encode(blake2b_256(
        format!("{pricing_id}:{request_hash}").as_bytes(),
    ));
    format!("ch_{}", &digest[..24])
}

fn direct_challenge_id(
    network_id: &str,
    pricing_id: &str,
    request_hash: &str,
    recipient_address: &str,
    amount_sompi: u64,
) -> String {
    let digest = hex::encode(blake2b_256(
        format!(
            "direct:{network_id}:{pricing_id}:{request_hash}:{recipient_address}:{amount_sompi}"
        )
        .as_bytes(),
    ));
    format!("chd_{}", &digest[..24])
}

fn is_hex_32(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        http::Request,
        routing::get,
        Router,
    };
    use secp256k1::{Keypair, Message};
    use sqlx::PgPool;
    use tn12_indexer_core::{RestTxOutput, API_PAYMENT_VOUCHER_SCHEMA_V1};
    use tn12_indexer_db::api_payments::{insert_api_payment_channel, NewApiPaymentChannel};
    use tower::ServiceExt;

    fn challenge() -> ApiPaymentChallenge {
        ApiPaymentChallenge {
            id: "ch_123".to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            intent: ApiPaymentIntent::Session,
            request: json!({
                "networkId": "testnet-10",
                "pricingId": "kcc20.markets.v1",
                "amountSompi": "1000"
            }),
        }
    }

    fn voucher() -> ApiPaymentVoucher {
        ApiPaymentVoucher {
            schema: API_PAYMENT_VOUCHER_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "chan_01".to_string(),
            payer_pubkey: "aa".repeat(32),
            provider_pubkey: "bb".repeat(32),
            sequence: 1,
            total_spent_sompi: 1_000,
            incremental_amount_sompi: 1_000,
            request_hash: "11".repeat(32),
            pricing_id: "kcc20.markets.v1".to_string(),
            route: "GET /kcc20/markets".to_string(),
            issued_at_ms: 1,
            expires_at_ms: 2,
            nonce: "nonce".to_string(),
            signature: "00".repeat(64),
        }
    }

    fn route_policy() -> ApiPaymentRoutePolicy {
        ApiPaymentRoutePolicy {
            challenge_id: "ch_paid".to_string(),
            network_id: "testnet-10".to_string(),
            pricing_id: "paid.route.v1".to_string(),
            route: "GET /paid".to_string(),
            request_hash: "11".repeat(32),
            amount_sompi: 500,
            now_ms: 1_780_000_010_000,
            refund_safety_margin_ms: 0,
            payer_identifier: None,
        }
    }

    fn route_policy_for_payer(payer_identifier: &str) -> ApiPaymentRoutePolicy {
        let mut policy = route_policy();
        policy.payer_identifier = Some(payer_identifier.to_string());
        policy
    }

    fn route_policy_with_refund_safety_margin(
        now_ms: u64,
        refund_safety_margin_ms: u64,
    ) -> ApiPaymentRoutePolicy {
        ApiPaymentRoutePolicy {
            now_ms,
            refund_safety_margin_ms,
            ..route_policy()
        }
    }

    fn direct_expectation() -> ApiDirectPaymentExpectation {
        ApiDirectPaymentExpectation {
            challenge_id: "chd_test".to_string(),
            txid_hex: "44".repeat(32),
            recipient_address: "kaspatest:qdirectrecipient".to_string(),
            amount_sompi: 50_000_000,
            request_hash: "11".repeat(32),
        }
    }

    fn direct_payment_tx(expectation: &ApiDirectPaymentExpectation) -> RestTransaction {
        RestTransaction {
            transaction_id: expectation.txid_hex.clone(),
            payload: Some(direct_payment_payload_hex(
                &expectation.challenge_id,
                &expectation.request_hash,
            )),
            is_accepted: true,
            accepting_block_hash: Some("aa".repeat(32)),
            accepting_block_blue_score: Some(123),
            accepting_block_time: Some(1_780_000_030_000),
            outputs: vec![RestTxOutput {
                transaction_id: expectation.txid_hex.clone(),
                index: 0,
                amount: expectation.amount_sompi,
                script_public_key: "00".to_string(),
                script_public_key_address: Some(expectation.recipient_address.clone()),
                script_public_key_type: Some("pubkey".to_string()),
                covenant_id: None,
                covenant: None,
            }],
            ..Default::default()
        }
    }

    fn direct_payment_proof_request(request_hash: &str) -> ApiDirectPaymentProofRequest {
        let recipient_address = "kaspatest:qdirectrecipient".to_string();
        ApiDirectPaymentProofRequest {
            challenge_id: direct_challenge_id(
                "testnet-10",
                API_PAYMENT_PROOF_DISCOVERY_PRICING_ID,
                request_hash,
                &recipient_address,
                50_000_000,
            ),
            network_id: "testnet-10".to_string(),
            txid_hex: "66".repeat(32),
            payer_identifier: Some("api-key-hash-1".to_string()),
            recipient_address,
            amount_sompi: "50000000".to_string(),
            pricing_id: API_PAYMENT_PROOF_DISCOVERY_PRICING_ID.to_string(),
            route: API_PAYMENT_PROOF_DISCOVERY_ROUTE.to_string(),
            request_hash: request_hash.to_string(),
        }
    }

    fn signing_keypair() -> Keypair {
        Keypair::from_seckey_slice(secp256k1::SECP256K1, &[7u8; 32]).unwrap()
    }

    fn signed_route_voucher(sequence: u64, total_spent_sompi: u64) -> ApiPaymentVoucher {
        let keypair = signing_keypair();
        let mut voucher = ApiPaymentVoucher {
            schema: API_PAYMENT_VOUCHER_SCHEMA_V1.to_string(),
            method: ApiPaymentMethod::KaspaChannel,
            network_id: "testnet-10".to_string(),
            channel_id: "chan-paid".to_string(),
            payer_pubkey: hex::encode(keypair.x_only_public_key().0.serialize()),
            provider_pubkey: "bb".repeat(32),
            sequence,
            total_spent_sompi,
            incremental_amount_sompi: 500,
            request_hash: route_policy().request_hash,
            pricing_id: route_policy().pricing_id,
            route: route_policy().route,
            issued_at_ms: 1_780_000_001_000,
            expires_at_ms: 1_780_000_061_000,
            nonce: format!("nonce-{sequence}"),
            signature: String::new(),
        };
        let message = Message::from_digest(voucher.signing_digest());
        voucher.signature = hex::encode(
            secp256k1::SECP256K1
                .sign_schnorr_no_aux_rand(&message, &keypair)
                .as_ref(),
        );
        voucher
    }

    fn payment_authorization(voucher: &ApiPaymentVoucher) -> String {
        format!(
            "Payment {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(voucher).unwrap())
        )
    }

    async fn insert_paid_channel(pool: &PgPool) {
        insert_paid_channel_with_status(pool, "usable").await;
    }

    async fn insert_paid_channel_with_status(pool: &PgPool, status: &str) {
        let keypair = signing_keypair();
        insert_api_payment_channel(
            pool,
            NewApiPaymentChannel {
                channel_id: "chan-paid".to_string(),
                network_id: "testnet-10".to_string(),
                payer_identifier: "api-key-hash-1".to_string(),
                payer_pubkey: hex::encode(keypair.x_only_public_key().0.serialize()),
                provider_pubkey: "bb".repeat(32),
                provider_identifier: Some("kaspacom-api".to_string()),
                scope: Some("indexer-api".to_string()),
                deposit_sompi: 5_000,
                reserve_sompi: 1_000,
                status: status.to_string(),
                open_txid_hex: Some("22".repeat(32)),
                refund_after_daa: Some(1_780_001_200_000),
                pricing_policy_id: Some("dev-indexer".to_string()),
                indexed_at_ms: Some(1_780_000_000_000),
                now_ms: 1_780_000_001_000,
            },
        )
        .await
        .unwrap();
    }

    async fn accepted_voucher_count(pool: &PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM api_payment_vouchers WHERE channel_id = $1")
            .bind("chan-paid")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn paid_handler(State(pool): State<PgPool>, headers: HeaderMap) -> Response {
        let policy = route_policy();
        match authorize_api_payment(&pool, &headers, &policy).await {
            Ok(receipt) => {
                let mut headers = HeaderMap::new();
                insert_payment_receipt_header(&mut headers, &receipt).unwrap();
                (headers, Json(json!({"ok": true}))).into_response()
            }
            Err(err) => err.into_response(&policy),
        }
    }

    async fn paid_identity_handler(State(pool): State<PgPool>, headers: HeaderMap) -> Response {
        let policy = route_policy_for_payer("api-key-hash-2");
        match authorize_api_payment(&pool, &headers, &policy).await {
            Ok(receipt) => {
                let mut headers = HeaderMap::new();
                insert_payment_receipt_header(&mut headers, &receipt).unwrap();
                (headers, Json(json!({"ok": true}))).into_response()
            }
            Err(err) => err.into_response(&policy),
        }
    }

    async fn paid_refund_window_handler(
        State(pool): State<PgPool>,
        headers: HeaderMap,
    ) -> Response {
        let policy = route_policy_with_refund_safety_margin(1_780_001_140_000, 60_000);
        match authorize_api_payment(&pool, &headers, &policy).await {
            Ok(receipt) => {
                let mut headers = HeaderMap::new();
                insert_payment_receipt_header(&mut headers, &receipt).unwrap();
                (headers, Json(json!({"ok": true}))).into_response()
            }
            Err(err) => err.into_response(&policy),
        }
    }

    async fn paid_refund_expired_handler(
        State(pool): State<PgPool>,
        headers: HeaderMap,
    ) -> Response {
        let policy = route_policy_with_refund_safety_margin(1_780_001_200_000, 0);
        match authorize_api_payment(&pool, &headers, &policy).await {
            Ok(receipt) => {
                let mut headers = HeaderMap::new();
                insert_payment_receipt_header(&mut headers, &receipt).unwrap();
                (headers, Json(json!({"ok": true}))).into_response()
            }
            Err(err) => err.into_response(&policy),
        }
    }

    fn paid_app(pool: PgPool) -> Router {
        Router::new()
            .route("/paid", get(paid_handler))
            .route("/paid-identity", get(paid_identity_handler))
            .route("/paid-refund-window", get(paid_refund_window_handler))
            .route("/paid-refund-expired", get(paid_refund_expired_handler))
            .with_state(pool)
    }

    #[test]
    fn challenge_header_uses_payment_auth_scheme() {
        let header = payment_challenge_header(&challenge()).unwrap();
        let header = header.to_str().unwrap();
        assert!(header.starts_with("Payment "));
        assert!(header.contains("id=\"ch_123\""));
        assert!(header.contains("method=\"kaspa-channel\""));
        assert!(header.contains("intent=\"session\""));
        assert!(header.contains("request=\""));
    }

    #[test]
    fn payment_required_response_has_402_and_retry_challenge() {
        let (status, headers, Json(body)) = payment_required_response(
            &challenge(),
            Some("missing-payment"),
            Some("route requires payment"),
        );
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(headers.get(WWW_AUTHENTICATE).is_some());
        assert_eq!(body["status"], json!(402));
        assert_eq!(body["failureCode"], json!("missing-payment"));
    }

    #[test]
    fn parse_payment_authorization_returns_none_when_missing() {
        assert_eq!(
            parse_payment_authorization(&HeaderMap::new()).unwrap(),
            None
        );
    }

    #[test]
    fn parse_payment_authorization_decodes_voucher() {
        let voucher = voucher();
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&voucher).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Payment {encoded}")).unwrap(),
        );
        assert_eq!(
            parse_payment_authorization(&headers).unwrap(),
            Some(voucher)
        );
    }

    #[test]
    fn parse_payment_authorization_rejects_wrong_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert_eq!(
            parse_payment_authorization(&headers).unwrap_err(),
            ApiPaymentHttpError::InvalidScheme
        );
    }

    #[test]
    fn parse_payment_authorization_rejects_duplicate_headers() {
        let voucher = voucher();
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&voucher).unwrap());
        let mut headers = HeaderMap::new();
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Payment {encoded}")).unwrap(),
        );
        headers.append(AUTHORIZATION, HeaderValue::from_static("Payment ignored"));
        assert_eq!(
            parse_payment_authorization(&headers).unwrap_err(),
            ApiPaymentHttpError::AmbiguousCredential
        );
    }

    #[test]
    fn parse_payment_authorization_rejects_malformed_payload() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Payment !!!"));
        assert_eq!(
            parse_payment_authorization(&headers).unwrap_err(),
            ApiPaymentHttpError::MalformedCredential
        );
    }

    #[test]
    fn payment_receipt_header_round_trips() {
        let receipt = ApiPaymentReceipt {
            receipt_id: "r_1".to_string(),
            channel_id: Some("chan_01".to_string()),
            voucher_sequence: Some(7),
            amount_sompi: 1_000,
            pricing_id: "kcc20.markets.v1".to_string(),
            request_hash: "11".repeat(32),
            payer_identifier_hash_hex: None,
        };
        let header = payment_receipt_header(&receipt).unwrap();
        assert_eq!(decode_payment_receipt_header(&header).unwrap(), receipt);
    }

    #[test]
    fn insert_payment_receipt_header_uses_standard_name() {
        let receipt = ApiPaymentReceipt {
            receipt_id: "r_1".to_string(),
            channel_id: Some("chan_01".to_string()),
            voucher_sequence: Some(7),
            amount_sompi: 1_000,
            pricing_id: "kcc20.markets.v1".to_string(),
            request_hash: "11".repeat(32),
            payer_identifier_hash_hex: None,
        };
        let mut headers = HeaderMap::new();
        insert_payment_receipt_header(&mut headers, &receipt).unwrap();
        assert_eq!(
            decode_payment_receipt_header(headers.get(PAYMENT_RECEIPT).unwrap()).unwrap(),
            receipt
        );
    }

    #[test]
    fn empty_body_hash_matches_shared_blake2b_256() {
        assert_eq!(EMPTY_BODY_HASH_HEX, hex::encode(blake2b_256(b"")));
    }

    #[test]
    fn get_request_hash_binds_path_and_query_values() {
        let base = get_request_hash(&"/kcc20/discovery?limit=5".parse().unwrap());
        let changed_query = get_request_hash(&"/kcc20/discovery?limit=6".parse().unwrap());
        let changed_path = get_request_hash(&"/kcc20/markets?limit=5".parse().unwrap());
        let changed_body =
            get_request_hash_for_get("/kcc20/discovery", Some("limit=5"), &"22".repeat(32));
        assert_ne!(base, changed_query);
        assert_ne!(base, changed_path);
        assert_ne!(base, changed_body);
    }

    #[test]
    fn challenge_request_hash_binds_non_get_method() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 0).with_pricing_rows(vec![
            ApiPaymentPricingRouteRow {
                pricing_id: "post.build.v1".to_string(),
                method: "POST".to_string(),
                path_pattern: "/build".to_string(),
                base_sompi: 3_000,
                per_row_sompi: 0,
                max_limit: None,
                enabled: true,
                effective_from_ms: 0,
                effective_to_ms: None,
            },
        ]);
        let body_hash = "22".repeat(32);
        let challenge = catalog
            .challenge_for_request(
                &ApiPaymentChallengeRequest {
                    method: "POST".to_string(),
                    path: "/build".to_string(),
                    raw_query: Some("mode=fast".to_string()),
                    body_hash_hex: Some(body_hash.clone()),
                    payment_method: None,
                },
                route_policy().now_ms,
            )
            .unwrap();

        assert_eq!(challenge.route, "POST /build");
        assert_eq!(
            challenge.request_hash,
            get_request_hash_for_method("POST", "/build", Some("mode=fast"), &body_hash)
        );
        assert_ne!(
            challenge.request_hash,
            get_request_hash_for_get("/build", Some("mode=fast"), &body_hash)
        );
    }

    #[test]
    fn policy_catalog_disables_zero_price_route() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 0);
        assert!(!catalog.pricing_response().paid_routes[0].enabled);
        assert!(catalog
            .route_policy(
                API_PAYMENT_PROOF_DISCOVERY_ROUTE,
                "11".repeat(32),
                1_780_000_010_000
            )
            .is_none());
    }

    #[test]
    fn policy_catalog_empty_paid_route_allowlist_disables_route_enforcement() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 777)
            .with_paid_route_allowlist(Some(""));

        let pricing = catalog.pricing_response();
        assert_eq!(pricing.paid_routes.len(), 2);
        assert!(pricing.paid_routes.iter().all(|route| !route.enabled));
        assert!(catalog
            .route_policy(
                API_PAYMENT_PROOF_DISCOVERY_ROUTE,
                "11".repeat(32),
                1_780_000_010_000
            )
            .is_none());
    }

    #[test]
    fn policy_catalog_paid_route_allowlist_keeps_selected_route() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 777)
            .with_paid_route_allowlist(Some("GET /health, GET /payments/proof/kcc20-discovery"));

        let pricing = catalog.pricing_response();
        assert!(
            pricing
                .paid_routes
                .iter()
                .find(|route| route.route == API_PAYMENT_PROOF_DISCOVERY_ROUTE)
                .unwrap()
                .enabled
        );
        assert!(
            !pricing
                .paid_routes
                .iter()
                .find(|route| route.route == API_PAYMENT_PROOF_BODY_ECHO_ROUTE)
                .unwrap()
                .enabled
        );
        assert!(catalog
            .route_policy(
                API_PAYMENT_PROOF_DISCOVERY_ROUTE,
                "11".repeat(32),
                1_780_000_010_000
            )
            .is_some());
        assert!(catalog
            .route_policy(
                API_PAYMENT_PROOF_BODY_ECHO_ROUTE,
                "22".repeat(32),
                1_780_000_010_000
            )
            .is_none());
    }

    #[test]
    fn policy_catalog_uses_db_pricing_rows() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 0).with_pricing_rows(vec![
            ApiPaymentPricingRouteRow {
                pricing_id: API_PAYMENT_PROOF_DISCOVERY_PRICING_ID.to_string(),
                method: "GET".to_string(),
                path_pattern: API_PAYMENT_PROOF_DISCOVERY_PATH.to_string(),
                base_sompi: 1_234,
                per_row_sompi: 0,
                max_limit: Some(100),
                enabled: true,
                effective_from_ms: 0,
                effective_to_ms: None,
            },
        ]);

        let pricing = catalog.pricing_response();
        assert_eq!(pricing.paid_routes.len(), 1);
        assert_eq!(pricing.paid_routes[0].amount_sompi, "1234");
        assert!(pricing.paid_routes[0].enabled);

        let policy = catalog
            .route_policy(
                API_PAYMENT_PROOF_DISCOVERY_ROUTE,
                "11".repeat(32),
                1_780_000_010_000,
            )
            .unwrap();
        assert_eq!(policy.amount_sompi, 1_234);
    }

    #[test]
    fn free_route_allowlist_covers_operational_routes() {
        for route in API_PAYMENT_FREE_ROUTES {
            let (method, path) = route.split_once(' ').unwrap();
            assert!(is_free_route(method, path), "{route} should be free");
        }
        assert!(is_free_route("GET", "/swagger-ui/index.html"));
        assert!(!is_free_route("GET", "/kcc20/discovery"));
    }

    #[test]
    fn challenge_request_rejects_invalid_body_hash() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 500);
        let err = catalog
            .challenge_for_request(
                &ApiPaymentChallengeRequest {
                    method: "GET".to_string(),
                    path: API_PAYMENT_PROOF_DISCOVERY_PATH.to_string(),
                    raw_query: None,
                    body_hash_hex: Some("not-hex".to_string()),
                    payment_method: None,
                },
                route_policy().now_ms,
            )
            .unwrap_err();
        assert_eq!(err, ApiPaymentChallengeError::InvalidBodyHash);
    }

    #[test]
    fn direct_payment_payload_binds_challenge_and_request_hash() {
        let expectation = direct_expectation();
        assert_eq!(
            direct_payment_payload_hex(&expectation.challenge_id, &expectation.request_hash),
            hex::encode(blake2b_256(
                format!(
                    "{DIRECT_PAYMENT_PAYLOAD_PREFIX}:{}:{}",
                    expectation.challenge_id, expectation.request_hash
                )
                .as_bytes()
            ))
        );
    }

    #[test]
    fn direct_payment_proof_validation_binds_route_request_and_amount() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 50_000_000)
            .with_direct_recipient(Some("kaspatest:qdirectrecipient".to_string()));
        let request_hash = "11".repeat(32);
        let proof = direct_payment_proof_request(&request_hash);
        assert_eq!(
            catalog.validate_direct_payment_proof(&proof),
            Ok(50_000_000)
        );

        let mut wrong_request_hash = proof.clone();
        wrong_request_hash.request_hash = "22".repeat(32);
        assert_eq!(
            catalog.validate_direct_payment_proof(&wrong_request_hash),
            Err(ApiDirectPaymentProofError::ChallengeMismatch)
        );

        let mut wrong_route = proof.clone();
        wrong_route.route = "GET /kcc20/markets".to_string();
        assert_eq!(
            catalog.validate_direct_payment_proof(&wrong_route),
            Err(ApiDirectPaymentProofError::RouteMismatch)
        );

        let mut underpaid = proof.clone();
        underpaid.amount_sompi = "776".to_string();
        underpaid.challenge_id = direct_challenge_id(
            "testnet-10",
            API_PAYMENT_PROOF_DISCOVERY_PRICING_ID,
            &underpaid.request_hash,
            &underpaid.recipient_address,
            776,
        );
        assert_eq!(
            catalog.validate_direct_payment_proof(&underpaid),
            Err(ApiDirectPaymentProofError::Underpaid)
        );
    }

    #[test]
    fn direct_payment_credential_rejects_payer_identifier_mismatch() {
        let catalog = ApiPaymentPolicyCatalog::new(true, "testnet-10", 50_000_000)
            .with_direct_recipient(Some("kaspatest:qdirectrecipient".to_string()));
        let policy = route_policy_for_payer("api-key-hash-expected");

        let err = catalog
            .direct_payment_proof_request_for_policy(
                &policy,
                ApiDirectPaymentCredential {
                    method: ApiPaymentMethod::KaspaDirect,
                    txid_hex: "44".repeat(32),
                    payer_identifier: Some("api-key-hash-other".to_string()),
                },
            )
            .unwrap_err();

        assert_eq!(err, ApiDirectPaymentProofError::PayerIdentifierMismatch);
    }

    #[test]
    fn direct_payment_verifier_accepts_matching_accepted_tx() {
        let expectation = direct_expectation();
        let tx = direct_payment_tx(&expectation);

        let verified = verify_direct_payment_transaction(&expectation, &tx);

        assert_eq!(verified.status, "accepted");
        assert_eq!(verified.failure_reason, None);
        assert_eq!(verified.raw_status_snapshot["payloadMatches"], json!(true));
        assert_eq!(verified.raw_status_snapshot["outputMatches"], json!(true));
    }

    #[test]
    fn direct_payment_verifier_rejects_wrong_payload() {
        let expectation = direct_expectation();
        let mut tx = direct_payment_tx(&expectation);
        tx.payload = Some("00".repeat(8));

        let verified = verify_direct_payment_transaction(&expectation, &tx);

        assert_eq!(verified.status, "rejected");
        assert_eq!(
            verified.failure_reason.as_deref(),
            Some("payment payload does not match challenge binding")
        );
    }

    #[test]
    fn direct_payment_verifier_marks_matching_unaccepted_tx_verified_only() {
        let expectation = direct_expectation();
        let mut tx = direct_payment_tx(&expectation);
        tx.is_accepted = false;

        let verified = verify_direct_payment_transaction(&expectation, &tx);

        assert_eq!(verified.status, "verified");
        assert_eq!(
            verified.failure_reason.as_deref(),
            Some("transaction is not accepted yet")
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_challenges_then_serves_with_receipt(pool: PgPool) {
        insert_paid_channel(&pool).await;
        let app = paid_app(pool.clone());

        let missing = app
            .clone()
            .oneshot(Request::builder().uri("/paid").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(missing.headers().get(WWW_AUTHENTICATE).is_some());
        assert!(missing.headers().get(PAYMENT_RECEIPT).is_none());

        let voucher = signed_route_voucher(1, 500);
        let paid = app
            .oneshot(
                Request::builder()
                    .uri("/paid")
                    .header(AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(paid.status(), StatusCode::OK);
        let receipt =
            decode_payment_receipt_header(paid.headers().get(PAYMENT_RECEIPT).unwrap()).unwrap();
        assert_eq!(receipt.channel_id.as_deref(), Some("chan-paid"));
        assert_eq!(receipt.voucher_sequence, Some(1));
        assert_eq!(receipt.amount_sompi, 500);

        let body = to_bytes(paid.into_body(), 1024).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"ok": true})
        );
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_rejects_expired_voucher_without_serving(pool: PgPool) {
        insert_paid_channel(&pool).await;
        let mut voucher = signed_route_voucher(1, 500);
        voucher.expires_at_ms = route_policy().now_ms - 1;

        let response = paid_app(pool)
            .oneshot(
                Request::builder()
                    .uri("/paid")
                    .header(AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(PAYMENT_RECEIPT).is_none());
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["failureCode"], json!("invalid-payment-voucher"));
        assert!(body["detail"]
            .as_str()
            .unwrap()
            .contains("payment voucher expired"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_rejects_settled_or_refunded_channel_without_serving(pool: PgPool) {
        for status in ["settled", "refunded"] {
            insert_paid_channel_with_status(&pool, status).await;
            let voucher = signed_route_voucher(1, 500);

            let response = paid_app(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri("/paid")
                        .header(AUTHORIZATION, payment_authorization(&voucher))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
            assert!(response.headers().get(PAYMENT_RECEIPT).is_none());
            let body = to_bytes(response.into_body(), 2048).await.unwrap();
            let body: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["failureCode"], json!("payment-channel-not-usable"));
            assert_eq!(body["detail"], json!("payment channel is not usable"));
            assert_eq!(accepted_voucher_count(&pool).await, 0);

            sqlx::query("DELETE FROM api_payment_channels WHERE channel_id = $1")
                .bind("chan-paid")
                .execute(&pool)
                .await
                .unwrap();
        }
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_rejects_channel_inside_refund_safety_window(pool: PgPool) {
        insert_paid_channel(&pool).await;
        let voucher = signed_route_voucher(1, 500);

        let response = paid_app(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/paid-refund-window")
                    .header(AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(PAYMENT_RECEIPT).is_none());
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["failureCode"], json!("payment-channel-refund-window"));
        assert_eq!(
            body["detail"],
            json!("payment channel is inside the refund safety window")
        );
        assert_eq!(accepted_voucher_count(&pool).await, 0);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_rejects_channel_at_refund_time_even_with_zero_margin(pool: PgPool) {
        insert_paid_channel(&pool).await;
        let voucher = signed_route_voucher(1, 500);

        let response = paid_app(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/paid-refund-expired")
                    .header(AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(PAYMENT_RECEIPT).is_none());
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["failureCode"], json!("payment-channel-refund-window"));
        assert_eq!(accepted_voucher_count(&pool).await, 0);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_rejects_channel_for_wrong_payer_identity(pool: PgPool) {
        insert_paid_channel(&pool).await;
        let voucher = signed_route_voucher(1, 500);

        let response = paid_app(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/paid-identity")
                    .header(AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().get(PAYMENT_RECEIPT).is_none());
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["failureCode"], json!("payment-payer-mismatch"));
        assert_eq!(
            body["detail"],
            json!("payment channel payer does not match route identity")
        );
        assert_eq!(accepted_voucher_count(&pool).await, 0);
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn paid_route_fails_closed_when_db_unavailable(pool: PgPool) {
        let voucher = signed_route_voucher(1, 500);
        pool.close().await;

        let response = paid_app(pool)
            .oneshot(
                Request::builder()
                    .uri("/paid")
                    .header(AUTHORIZATION, payment_authorization(&voucher))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(PAYMENT_RECEIPT).is_none());
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["status"],
            json!(503)
        );
    }
}
