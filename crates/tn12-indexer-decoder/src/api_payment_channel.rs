//! ApiPaymentChannel covenant decoder.
//!
//! This first P4 slice provides template identity, constructor metadata, and
//! entrypoint classification for generic covenant/action rows.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, script_items, ScriptItem};
use crate::TemplateDecoder;

pub const API_PAYMENT_CHANNEL_SCRIPT_LEN: usize = 1319;
pub const API_PAYMENT_CHANNEL_V2_SCRIPT_LEN: usize = 770;
pub const API_PAYMENT_CHANNEL_V1_SCRIPT_LEN: usize = 584;
const API_PAYMENT_CHANNEL_V2_FINGERPRINT: [u8; 32] = [
    0xba, 0x0e, 0x78, 0x95, 0x70, 0x0f, 0x3d, 0xda, 0xb7, 0x48, 0xc5, 0x37, 0xd8, 0x6e, 0x86, 0x49,
    0xa5, 0xa2, 0x2c, 0xad, 0x8f, 0xe8, 0x83, 0x85, 0x66, 0xa5, 0xa4, 0x5e, 0xee, 0x34, 0x72, 0xc1,
];
const API_PAYMENT_CHANNEL_V1_FINGERPRINT: [u8; 32] = [
    0xdb, 0x17, 0x1e, 0x82, 0x42, 0x57, 0xdb, 0xe7, 0x69, 0xdb, 0xcb, 0x5d, 0x18, 0x4a, 0x9a, 0x48,
    0xa8, 0x21, 0x6c, 0x34, 0x42, 0x44, 0x0b, 0xfc, 0x13, 0x9a, 0x5d, 0x01, 0x64, 0x68, 0xea, 0x27,
];

const PAYER_RANGE: (usize, usize) = (2, 34);
const PROVIDER_RANGE: (usize, usize) = (35, 67);
const PROVIDER_PAYOUT_RANGE: (usize, usize) = (68, 100);
const VOUCHER_DOMAIN_HASH_RANGE: (usize, usize) = (101, 133);
const REFUND_AFTER_MS_RANGE: (usize, usize) = (134, 142);
const RESERVE_SOMPI_RANGE: (usize, usize) = (143, 151);
const MAX_SPEND_SOMPI_RANGE: (usize, usize) = (152, 160);
const CLOSE_AFTER_MS_RANGE: (usize, usize) = (161, 169);
const CONSTRUCTOR_RANGES: &[(usize, usize)] = &[
    PAYER_RANGE,
    PROVIDER_RANGE,
    PROVIDER_PAYOUT_RANGE,
    VOUCHER_DOMAIN_HASH_RANGE,
    REFUND_AFTER_MS_RANGE,
    RESERVE_SOMPI_RANGE,
    MAX_SPEND_SOMPI_RANGE,
    CLOSE_AFTER_MS_RANGE,
];

pub struct ApiPaymentChannelDecoder {
    fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiPaymentChannelAction {
    Settle {
        total_spent_sompi: i64,
        settlement_fee_sompi: i64,
        provider_output_index: i32,
        payer_refund_output_index: i32,
    },
    Refund {
        settlement_fee_sompi: i64,
        payer_output_index: i32,
    },
    CooperativeClose {
        provider_amount_sompi: i64,
        settlement_fee_sompi: i64,
        provider_output_index: i32,
        payer_refund_output_index: i32,
    },
    ContinueChannel {
        channel_output_index: i32,
        new_refund_after_ms: i64,
        new_max_spend_sompi: i64,
    },
    RequestRefundClose {
        settlement_fee_sompi: i64,
        channel_output_index: i32,
        final_refund_after_ms: i64,
    },
}

impl ApiPaymentChannelDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }

    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        let mut masked = script.to_vec();
        for (start, end) in CONSTRUCTOR_RANGES {
            if (*start, *end) == CLOSE_AFTER_MS_RANGE
                && script.len() != API_PAYMENT_CHANNEL_SCRIPT_LEN
            {
                continue;
            }
            if *end <= masked.len() {
                for b in masked[*start..*end].iter_mut() {
                    *b = 0;
                }
            }
        }
        blake2b_256(&masked)
    }
}

pub fn decode_action_projection(
    signature_script: &[u8],
) -> Result<Option<ApiPaymentChannelAction>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(ScriptItem::as_int) else {
        return Ok(None);
    };

    match selector {
        0 => Ok(Some(ApiPaymentChannelAction::Settle {
            total_spent_sompi: item_i64(&items, 3, "totalSpentSompi")?,
            settlement_fee_sompi: item_i64(&items, 4, "settlementFeeSompi")?,
            provider_output_index: item_i32(&items, 5, "providerOutputIndex")?,
            payer_refund_output_index: item_i32(&items, 6, "payerRefundOutputIndex")?,
        })),
        1 => Ok(Some(ApiPaymentChannelAction::Refund {
            settlement_fee_sompi: item_i64(&items, 1, "settlementFeeSompi")?,
            payer_output_index: item_i32(&items, 2, "payerOutputIndex")?,
        })),
        2 => Ok(Some(ApiPaymentChannelAction::CooperativeClose {
            provider_amount_sompi: item_i64(&items, 3, "providerAmountSompi")?,
            settlement_fee_sompi: item_i64(&items, 4, "settlementFeeSompi")?,
            provider_output_index: item_i32(&items, 5, "providerOutputIndex")?,
            payer_refund_output_index: item_i32(&items, 6, "payerRefundOutputIndex")?,
        })),
        3 => Ok(Some(ApiPaymentChannelAction::ContinueChannel {
            channel_output_index: item_i32(&items, 1, "channelOutputIndex")?,
            new_refund_after_ms: item_i64(&items, 2, "newRefundAfterMs")?,
            new_max_spend_sompi: item_i64(&items, 3, "newMaxSpendSompi")?,
        })),
        4 => Ok(Some(ApiPaymentChannelAction::RequestRefundClose {
            settlement_fee_sompi: item_i64(&items, 1, "settlementFeeSompi")?,
            channel_output_index: item_i32(&items, 2, "channelOutputIndex")?,
            final_refund_after_ms: item_i64(&items, 3, "finalRefundAfterMs")?,
        })),
        _ => Ok(None),
    }
}

fn item_i64(items: &[ScriptItem], index: usize, label: &str) -> Result<i64> {
    let value = items
        .get(index)
        .and_then(ScriptItem::as_int)
        .ok_or_else(|| anyhow!("ApiPaymentChannel sigscript item {index} is not {label}"))?;
    i64::try_from(value)
        .map_err(|_| anyhow!("ApiPaymentChannel sigscript item {index} overflows i64 {label}"))
}

fn item_i32(items: &[ScriptItem], index: usize, label: &str) -> Result<i32> {
    let value = item_i64(items, index, label)?;
    i32::try_from(value)
        .map_err(|_| anyhow!("ApiPaymentChannel sigscript item {index} overflows i32 {label}"))
}

impl TemplateDecoder for ApiPaymentChannelDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::ApiPaymentChannel
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        let fingerprint = Self::fingerprint_of_compiled_script(reveal);
        (reveal.len() == API_PAYMENT_CHANNEL_SCRIPT_LEN && fingerprint == self.fingerprint)
            || (reveal.len() == API_PAYMENT_CHANNEL_V2_SCRIPT_LEN
                && fingerprint == API_PAYMENT_CHANNEL_V2_FINGERPRINT)
            || (reveal.len() == API_PAYMENT_CHANNEL_V1_SCRIPT_LEN
                && fingerprint == API_PAYMENT_CHANNEL_V1_FINGERPRINT)
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        if payload.len() != API_PAYMENT_CHANNEL_SCRIPT_LEN
            && payload.len() != API_PAYMENT_CHANNEL_V2_SCRIPT_LEN
            && payload.len() != API_PAYMENT_CHANNEL_V1_SCRIPT_LEN
        {
            return Err(anyhow!(
                "ApiPaymentChannel reveal script is {} bytes, expected {}, {}, or {}",
                payload.len(),
                API_PAYMENT_CHANNEL_SCRIPT_LEN,
                API_PAYMENT_CHANNEL_V2_SCRIPT_LEN,
                API_PAYMENT_CHANNEL_V1_SCRIPT_LEN
            ));
        }
        Ok(json!({
            "payerPubkey": hex::encode(&payload[PAYER_RANGE.0..PAYER_RANGE.1]),
            "providerPubkey": hex::encode(&payload[PROVIDER_RANGE.0..PROVIDER_RANGE.1]),
            "providerPayoutPubkey": hex::encode(&payload[PROVIDER_PAYOUT_RANGE.0..PROVIDER_PAYOUT_RANGE.1]),
            "voucherDomainHash": hex::encode(&payload[VOUCHER_DOMAIN_HASH_RANGE.0..VOUCHER_DOMAIN_HASH_RANGE.1]),
            "refundAfterMs": parse_minimal_int(&payload[REFUND_AFTER_MS_RANGE.0..REFUND_AFTER_MS_RANGE.1]),
            "reserveSompi": parse_minimal_int(&payload[RESERVE_SOMPI_RANGE.0..RESERVE_SOMPI_RANGE.1]),
            "maxSpendSompi": parse_minimal_int(&payload[MAX_SPEND_SOMPI_RANGE.0..MAX_SPEND_SOMPI_RANGE.1]),
            "closeAfterMs": if payload.len() == API_PAYMENT_CHANNEL_SCRIPT_LEN {
                parse_minimal_int(&payload[CLOSE_AFTER_MS_RANGE.0..CLOSE_AFTER_MS_RANGE.1])
            } else {
                0
            },
        }))
    }

    fn decode_state(&self, _payload: &[u8]) -> Result<Value> {
        Ok(Value::Null)
    }

    fn decode_action_checked(&self, signature_script: &[u8]) -> Result<Option<String>> {
        self.decode_action(signature_script)
            .map(Some)
            .ok_or_else(|| anyhow!(crate::InterpretationFailure("unsupported spend action")))
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        let selector = script_items(prefix).last().and_then(ScriptItem::as_int)?;
        match selector {
            0 => Some("settle".into()),
            1 => Some("refund".into()),
            2 => Some("cooperativeClose".into()),
            3 => Some("continueChannel".into()),
            4 => Some("requestRefundClose".into()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact_script(raw: &str) -> Vec<u8> {
        let artifact: Value = serde_json::from_str(raw).unwrap();
        artifact
            .get("script")
            .or_else(|| artifact.get("bytecode"))
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect()
    }

    fn placeholder_script() -> Vec<u8> {
        artifact_script(include_str!(
            "../fixtures/api-payment-channel/ApiPaymentChannel.placeholder.json"
        ))
    }

    fn live_script() -> Vec<u8> {
        let mut script = placeholder_script();
        let pubkey =
            hex::decode("4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4")
                .unwrap();
        script[PAYER_RANGE.0..PAYER_RANGE.1].copy_from_slice(&pubkey);
        script[PROVIDER_RANGE.0..PROVIDER_RANGE.1].copy_from_slice(&pubkey);
        script[PROVIDER_PAYOUT_RANGE.0..PROVIDER_PAYOUT_RANGE.1].copy_from_slice(&pubkey);
        script[VOUCHER_DOMAIN_HASH_RANGE.0..VOUCHER_DOMAIN_HASH_RANGE.1]
            .copy_from_slice(&[0x44; 32]);
        write_i64(&mut script, REFUND_AFTER_MS_RANGE, 1_780_510_711_398);
        write_i64(&mut script, RESERVE_SOMPI_RANGE, 50_000_000);
        write_i64(&mut script, MAX_SPEND_SOMPI_RANGE, 50_000_000);
        write_i64(&mut script, CLOSE_AFTER_MS_RANGE, 0);
        script
    }

    fn write_i64(script: &mut [u8], range: (usize, usize), value: i64) {
        script[range.0..range.1].copy_from_slice(&value.to_le_bytes());
    }

    fn push(data: &[u8], out: &mut Vec<u8>) {
        assert!(data.len() <= 75);
        out.push(data.len() as u8);
        out.extend_from_slice(data);
    }

    fn push_i64(value: i64, out: &mut Vec<u8>) {
        push(&value.to_le_bytes(), out);
    }

    fn sig_script_with_selector(selector: u8) -> Vec<u8> {
        let mut script = Vec::new();
        push(&[0x41; 65], &mut script);
        push(&[0x42; 65], &mut script);
        push(&[0x44; 32], &mut script);
        script.push(selector);
        let reveal = live_script();
        script.push(0x4d);
        script.extend_from_slice(&(reveal.len() as u16).to_le_bytes());
        script.extend_from_slice(&reveal);
        script
    }

    fn settle_sig_script() -> Vec<u8> {
        let mut script = Vec::new();
        push(&[0x41; 65], &mut script);
        push(&[0x42; 65], &mut script);
        push(&[0x44; 32], &mut script);
        push_i64(50_000_000, &mut script);
        push_i64(4_000_000, &mut script);
        push_i64(0, &mut script);
        push_i64(1, &mut script);
        script.push(0x00);
        let reveal = live_script();
        script.push(0x4d);
        script.extend_from_slice(&(reveal.len() as u16).to_le_bytes());
        script.extend_from_slice(&reveal);
        script
    }

    fn continue_sig_script() -> Vec<u8> {
        let mut script = Vec::new();
        push(&[0x41; 65], &mut script);
        push_i64(0, &mut script);
        push_i64(1_780_514_311_398, &mut script);
        push_i64(150_000_000, &mut script);
        script.push(0x53);
        let reveal = live_script();
        script.push(0x4d);
        script.extend_from_slice(&(reveal.len() as u16).to_le_bytes());
        script.extend_from_slice(&reveal);
        script
    }

    fn request_refund_close_sig_script() -> Vec<u8> {
        let mut script = Vec::new();
        push(&[0x41; 65], &mut script);
        push_i64(4_000_000, &mut script);
        push_i64(0, &mut script);
        push_i64(1_780_517_911_398, &mut script);
        script.push(0x54);
        let reveal = live_script();
        script.push(0x4d);
        script.extend_from_slice(&(reveal.len() as u16).to_le_bytes());
        script.extend_from_slice(&reveal);
        script
    }

    #[test]
    fn fingerprint_matches_live_constructor_instance() {
        let placeholder = placeholder_script();
        let live = live_script();

        assert_eq!(placeholder.len(), API_PAYMENT_CHANNEL_SCRIPT_LEN);
        assert_eq!(live.len(), API_PAYMENT_CHANNEL_SCRIPT_LEN);
        assert_eq!(
            ApiPaymentChannelDecoder::fingerprint_of_compiled_script(&placeholder),
            ApiPaymentChannelDecoder::fingerprint_of_compiled_script(&live)
        );
    }

    #[test]
    fn decodes_live_constructor_values() {
        let decoder = ApiPaymentChannelDecoder::new(
            ApiPaymentChannelDecoder::fingerprint_of_compiled_script(&placeholder_script()),
        );
        let args = decoder.decode_constructor(&live_script()).unwrap();
        assert_eq!(
            args["payerPubkey"],
            "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
        );
        assert_eq!(
            args["providerPubkey"],
            "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
        );
        assert_eq!(
            args["providerPayoutPubkey"],
            "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
        );
        assert_eq!(
            args["voucherDomainHash"],
            "4444444444444444444444444444444444444444444444444444444444444444"
        );
        assert_eq!(args["refundAfterMs"], 1_780_510_711_398i64);
        assert_eq!(args["reserveSompi"], 50_000_000i64);
        assert_eq!(args["maxSpendSompi"], 50_000_000i64);
        assert_eq!(args["closeAfterMs"], 0i64);
    }

    #[test]
    fn decodes_entrypoint_selectors() {
        let decoder = ApiPaymentChannelDecoder::new(
            ApiPaymentChannelDecoder::fingerprint_of_compiled_script(&placeholder_script()),
        );

        assert_eq!(
            decoder
                .decode_action(&sig_script_with_selector(0x00))
                .as_deref(),
            Some("settle")
        );
        assert_eq!(
            decoder
                .decode_action(&sig_script_with_selector(0x51))
                .as_deref(),
            Some("refund")
        );
        assert_eq!(
            decoder
                .decode_action(&sig_script_with_selector(0x52))
                .as_deref(),
            Some("cooperativeClose")
        );
        assert_eq!(
            decoder
                .decode_action(&sig_script_with_selector(0x53))
                .as_deref(),
            Some("continueChannel")
        );
        assert_eq!(
            decoder
                .decode_action(&sig_script_with_selector(0x54))
                .as_deref(),
            Some("requestRefundClose")
        );
    }

    #[test]
    fn decodes_settle_projection_args() {
        let action = decode_action_projection(&settle_sig_script())
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            ApiPaymentChannelAction::Settle {
                total_spent_sompi: 50_000_000,
                settlement_fee_sompi: 4_000_000,
                provider_output_index: 0,
                payer_refund_output_index: 1,
            }
        );
    }

    #[test]
    fn decodes_continue_projection_args() {
        let action = decode_action_projection(&continue_sig_script())
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            ApiPaymentChannelAction::ContinueChannel {
                channel_output_index: 0,
                new_refund_after_ms: 1_780_514_311_398,
                new_max_spend_sompi: 150_000_000,
            }
        );
    }

    #[test]
    fn decodes_request_refund_close_projection_args() {
        let action = decode_action_projection(&request_refund_close_sig_script())
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            ApiPaymentChannelAction::RequestRefundClose {
                settlement_fee_sompi: 4_000_000,
                channel_output_index: 0,
                final_refund_after_ms: 1_780_517_911_398,
            }
        );
    }
}
