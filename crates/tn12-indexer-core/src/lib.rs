//! Shared types + canonical primitives for the TN12 covenant indexer.
//!
//! What lives here:
//! - `Outpoint`, `CovenantUtxo`, `KnownTemplate` — types every crate consumes.
//! - `compute_covenant_id` — Rust port of the wallet's `computeCovenantId`
//!   (Blake2b-256 keyed with `"CovenantID"` over the canonical preimage).
//!   Validated against the TypeScript implementation via golden tests in `tests/`.

pub mod api_payments;
pub mod covenant_id;
pub mod rest_types;
pub mod script;
pub mod types;

pub use api_payments::{
    validate_api_payment_channel_open_sizing, validate_api_payment_settlement_output_sizing,
    ApiPaymentChannelCloseRequest, ApiPaymentChannelCloseRequestExpectation,
    ApiPaymentChannelSizingPolicy, ApiPaymentHeader, ApiPaymentIntent, ApiPaymentMethod,
    ApiPaymentQueryParam, ApiPaymentRequestBinding, ApiPaymentSettlementArtifact,
    ApiPaymentSettlementAuthorization, ApiPaymentSettlementAuthorizationExpectation,
    ApiPaymentValidationError, ApiPaymentVoucher, ApiPaymentVoucherExpectation,
    API_PAYMENT_CHANNEL_CLOSE_REQUEST_DOMAIN_V1, API_PAYMENT_CHANNEL_CLOSE_REQUEST_SCHEMA_V1,
    API_PAYMENT_PRACTICAL_MIN_OUTPUT_SOMPI, API_PAYMENT_REQUEST_DOMAIN_V1,
    API_PAYMENT_SETTLEMENT_ARTIFACT_SCHEMA_V1, API_PAYMENT_SETTLEMENT_AUTHORIZATION_DOMAIN_V1,
    API_PAYMENT_SETTLEMENT_AUTHORIZATION_SCHEMA_V1, API_PAYMENT_VOUCHER_DOMAIN_V1,
    API_PAYMENT_VOUCHER_SCHEMA_V1,
};
pub use covenant_id::{compute_covenant_id, AuthOutput, CovenantIdError};
pub use rest_types::{
    compute_genesis_covenant_id_for_output, compute_genesis_covenant_id_for_outputs,
    compute_genesis_covenant_id_for_outputs_at_input, RestBlock, RestCovenantBinding,
    RestTransaction, RestTxInput, RestTxOutput, VirtualChainBlock,
};
pub use script::{
    blake2b_256, is_p2sh_script_pubkey, opcode_signature, p2sh_script_hash, parse_minimal_int,
    read_push, skip_one_push, template_fingerprint, ScriptReader,
};
pub use types::{CovenantUtxo, KnownTemplate, Outpoint, UtxoStatus};
