//! KCC20 V3 decoder.
//!
//! V3 is the token-native partial-fill orderbook candidate. It keeps one
//! covenant family for root, holder, ask, and bid states so partial fills can
//! settle by continuing the token covenant rather than trusting a standalone
//! market covenant.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{
    args_prefix_before_reveal, identifier_type_name, item_bytes_32, item_int, script_items,
};
use crate::TemplateDecoder;

pub const KCC20_V3_SCRIPT_LEN: usize = 2072;
const GENESIS_OWNER_RANGE: (usize, usize) = (2, 34);
const GENESIS_AMOUNT_RANGE: (usize, usize) = (35, 43);
const GENESIS_MODE_RANGE: (usize, usize) = (44, 52);
const GENESIS_UNIT_PRICE_RANGE: (usize, usize) = (53, 61);
const PROTOCOL_FEE_BPS: i128 = 200;
const MIN_PROTOCOL_FEE_SOMPI: i128 = 50_000_000;
const MIN_GROSS_FILL_SOMPI: i128 = 50_000_000;
const PROTOCOL_FEE_RECIPIENT: &str =
    "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01";

pub struct Kcc20V3Decoder {
    pub fingerprint: [u8; 32],
}

impl Kcc20V3Decoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }

    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        let mut masked = script.to_vec();
        for (start, end) in [
            GENESIS_OWNER_RANGE,
            GENESIS_AMOUNT_RANGE,
            GENESIS_MODE_RANGE,
            GENESIS_UNIT_PRICE_RANGE,
        ] {
            if end <= masked.len() {
                for b in masked[start..end].iter_mut() {
                    *b = 0;
                }
            }
        }
        blake2b_256(&masked)
    }
}

impl TemplateDecoder for Kcc20V3Decoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20V3
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        reveal.len() == KCC20_V3_SCRIPT_LEN
            && Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        if payload.len() != KCC20_V3_SCRIPT_LEN {
            return Err(anyhow!(
                "reveal script is {} bytes, expected {}",
                payload.len(),
                KCC20_V3_SCRIPT_LEN
            ));
        }

        decode_reveal_state_value(payload)
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        decode_state_payload(payload)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        match prefix.last().copied() {
            Some(0x00) => Some("issueFromRoot".into()),
            Some(0x51) => Some("createBidFromRoot".into()),
            Some(0x52) => Some("createAskByOwnerSig".into()),
            Some(0x53) => Some("fillAskPartial".into()),
            Some(0x54) => Some("fillBidPartial".into()),
            Some(0x55) => Some("sellIntoBidByOwnerSig".into()),
            _ => None,
        }
    }
}

pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(|i| i.as_int()) else {
        return Ok(None);
    };

    let args = match selector {
        3 => json!({
            "fillAmount": item_int(&items, 1)?.to_string(),
            "buyerOutputIndex": item_int(&items, 2)?.to_string(),
            "askOutputIndex": item_int(&items, 3)?.to_string(),
            "sellerOutputIndex": item_int(&items, 4)?.to_string(),
        }),
        4 => json!({
            "sellerInputIndex": item_int(&items, 0)?.to_string(),
            "fillAmount": item_int(&items, 1)?.to_string(),
            "buyerOutputIndex": item_int(&items, 2)?.to_string(),
            "bidOutputIndex": item_int(&items, 3)?.to_string(),
            "sellerOutputIndex": item_int(&items, 4)?.to_string(),
        }),
        5 => json!({
            "fillAmount": item_int(&items, 2)?.to_string(),
            "buyerOutputIndex": item_int(&items, 3)?.to_string(),
            "changeOutputIndex": item_int(&items, 4)?.to_string(),
        }),
        _ => return Ok(None),
    };

    Ok(Some(args))
}

#[derive(Debug, Clone)]
struct V3State {
    owner: String,
    amount: i128,
    mode: i128,
    unit_price_sompi: i128,
    fee_recipient: String,
}

pub fn decode_reveal_state_value(payload: &[u8]) -> Result<Value> {
    if payload.len() != KCC20_V3_SCRIPT_LEN {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}",
            payload.len(),
            KCC20_V3_SCRIPT_LEN
        ));
    }
    Ok(state_value(&reveal_state(payload)?))
}

pub fn decode_output_state_values(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Vec<(i32, Value)>>> {
    let input_state = reveal_state(reveal_script)?;
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(|i| i.as_int()) else {
        return Ok(None);
    };

    match selector {
        0 => {
            let token_amount = item_int(&items, 2)?;
            Ok(Some(vec![
                output(
                    item_int(&items, 3)? as i32,
                    hex::encode(item_bytes_32(&items, 1)?),
                    token_amount,
                    0,
                    0,
                    &input_state,
                ),
                output(
                    item_int(&items, 4)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - token_amount,
                    1,
                    0,
                    &input_state,
                ),
            ]))
        }
        1 => Ok(Some(vec![
            output(
                item_int(&items, 3)? as i32,
                hex::encode(item_bytes_32(&items, 0)?),
                item_int(&items, 1)?,
                3,
                item_int(&items, 2)?,
                &input_state,
            ),
            output(
                item_int(&items, 4)? as i32,
                input_state.owner.clone(),
                input_state.amount,
                1,
                0,
                &input_state,
            ),
        ])),
        2 => {
            let ask_amount = item_int(&items, 1)?;
            let mut outputs = vec![output(
                item_int(&items, 3)? as i32,
                input_state.owner.clone(),
                ask_amount,
                2,
                item_int(&items, 2)?,
                &input_state,
            )];
            if ask_amount < input_state.amount {
                outputs.push(output(
                    item_int(&items, 4)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - ask_amount,
                    0,
                    0,
                    &input_state,
                ));
            }
            Ok(Some(outputs))
        }
        3 => {
            let fill_amount = item_int(&items, 1)?;
            let mut outputs = vec![output(
                item_int(&items, 2)? as i32,
                hex::encode(item_bytes_32(&items, 0)?),
                fill_amount,
                0,
                0,
                &input_state,
            )];
            if fill_amount < input_state.amount {
                outputs.push(output(
                    item_int(&items, 3)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - fill_amount,
                    2,
                    input_state.unit_price_sompi,
                    &input_state,
                ));
            }
            Ok(Some(outputs))
        }
        4 => {
            let fill_amount = item_int(&items, 1)?;
            if fill_amount >= input_state.amount {
                return Ok(Some(Vec::new()));
            }
            Ok(Some(vec![output(
                item_int(&items, 3)? as i32,
                input_state.owner.clone(),
                input_state.amount - fill_amount,
                3,
                input_state.unit_price_sompi,
                &input_state,
            )]))
        }
        5 => {
            let fill_amount = item_int(&items, 2)?;
            let mut outputs = vec![output(
                item_int(&items, 3)? as i32,
                hex::encode(item_bytes_32(&items, 1)?),
                fill_amount,
                0,
                0,
                &input_state,
            )];
            if fill_amount < input_state.amount {
                outputs.push(output(
                    item_int(&items, 4)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - fill_amount,
                    0,
                    0,
                    &input_state,
                ));
            }
            Ok(Some(outputs))
        }
        _ => Ok(None),
    }
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() < 60 {
        return Err(anyhow!(
            "KCC20V3 state payload too short ({} bytes)",
            payload.len()
        ));
    }
    expect_len(payload, 0, 32, "owner")?;
    expect_len(payload, 33, 8, "amount")?;
    expect_len(payload, 42, 8, "mode")?;
    expect_len(payload, 51, 8, "unitPriceSompi")?;

    let state = V3State {
        owner: hex::encode(&payload[1..33]),
        amount: parse_minimal_int(&payload[34..42]),
        mode: parse_minimal_int(&payload[43..51]),
        unit_price_sompi: parse_minimal_int(&payload[52..60]),
        fee_recipient: PROTOCOL_FEE_RECIPIENT.to_string(),
    };

    Ok(state_value(&state))
}

fn reveal_state(payload: &[u8]) -> Result<V3State> {
    if payload.len() != KCC20_V3_SCRIPT_LEN {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}",
            payload.len(),
            KCC20_V3_SCRIPT_LEN
        ));
    }
    Ok(V3State {
        owner: hex::encode(&payload[GENESIS_OWNER_RANGE.0..GENESIS_OWNER_RANGE.1]),
        amount: parse_minimal_int(&payload[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1]),
        mode: parse_minimal_int(&payload[GENESIS_MODE_RANGE.0..GENESIS_MODE_RANGE.1]),
        unit_price_sompi: parse_minimal_int(
            &payload[GENESIS_UNIT_PRICE_RANGE.0..GENESIS_UNIT_PRICE_RANGE.1],
        ),
        fee_recipient: PROTOCOL_FEE_RECIPIENT.to_string(),
    })
}

fn output(
    output_index: i32,
    owner: String,
    amount: i128,
    mode: i128,
    unit_price_sompi: i128,
    input_state: &V3State,
) -> (i32, Value) {
    let state = V3State {
        owner,
        amount,
        mode,
        unit_price_sompi,
        fee_recipient: input_state.fee_recipient.clone(),
    };
    (output_index, state_value(&state))
}

fn state_value(state: &V3State) -> Value {
    json!({
        "ownerIdentifier": state.owner,
        "identifierType": 0,
        "identifierTypeName": identifier_type_name(0),
        "amount": state.amount.to_string(),
        "mode": state.mode,
        "modeName": mode_name(state.mode),
        "isMinter": state.mode == 1,
        "unitPriceSompi": state.unit_price_sompi.to_string(),
        "minGrossFillSompi": MIN_GROSS_FILL_SOMPI.to_string(),
        "minProtocolFeeSompi": MIN_PROTOCOL_FEE_SOMPI.to_string(),
        "feeRecipient": state.fee_recipient,
        "protocolFeeRecipient": state.fee_recipient,
        "feeBps": PROTOCOL_FEE_BPS,
        "protocolFeeBps": PROTOCOL_FEE_BPS,
        "stateOwner": state.owner,
        "stateOwnerType": 0,
        "stateAmount": state.amount.to_string(),
        "stateMode": state.mode,
        "marketUnitPriceSompi": state.unit_price_sompi.to_string(),
    })
}

fn expect_len(payload: &[u8], offset: usize, expected: usize, label: &str) -> Result<()> {
    let actual = payload
        .get(offset)
        .copied()
        .ok_or_else(|| anyhow!("missing KCC20V3 {label} push length"))? as usize;
    if actual != expected {
        return Err(anyhow!(
            "unexpected KCC20V3 {label} push length {actual}, expected {expected}"
        ));
    }
    Ok(())
}

fn mode_name(mode: i128) -> &'static str {
    match mode {
        0 => "holder",
        1 => "root",
        2 => "ask",
        3 => "bid",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-v3/KCC20V3.placeholder.json"
        ))
        .unwrap();
        artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect()
    }

    fn push_i64(out: &mut Vec<u8>, value: i64) {
        out.push(8);
        out.extend(value.to_le_bytes());
    }

    fn push_script(out: &mut Vec<u8>, script: &[u8]) {
        out.push(0x4d);
        out.extend((script.len() as u16).to_le_bytes());
        out.extend(script);
    }

    #[test]
    fn matches_placeholder_script() {
        let script = placeholder_script();
        let decoder = Kcc20V3Decoder::new(Kcc20V3Decoder::fingerprint_of_compiled_script(&script));
        assert!(decoder.matches_reveal_script(&script));
    }

    #[test]
    fn decodes_constructor_from_placeholder() {
        let script = placeholder_script();
        let decoder = Kcc20V3Decoder::new(Kcc20V3Decoder::fingerprint_of_compiled_script(&script));
        let v = decoder.decode_constructor(&script).unwrap();
        assert_eq!(v["stateMode"], 1);
        assert_eq!(v["stateAmount"], "1000000");
        assert_eq!(v["marketUnitPriceSompi"], "0");
        assert_eq!(v["minProtocolFeeSompi"], "50000000");
        assert_eq!(v["minGrossFillSompi"], "50000000");
        assert_eq!(v["protocolFeeBps"], 200);
    }

    #[test]
    fn decodes_state_payload() {
        let d = Kcc20V3Decoder::new([0u8; 32]);
        let owner = [0x42u8; 32];
        let mut state = Vec::new();
        state.push(32);
        state.extend(owner);
        push_i64(&mut state, 1_000);
        push_i64(&mut state, 2);
        push_i64(&mut state, 50_000_000);

        let v = d.decode_state(&state).unwrap();
        assert_eq!(v["ownerIdentifier"], hex::encode(owner));
        assert_eq!(v["amount"], "1000");
        assert_eq!(v["mode"], 2);
        assert_eq!(v["modeName"], "ask");
        assert_eq!(v["unitPriceSompi"], "50000000");
        assert_eq!(v["minProtocolFeeSompi"], "50000000");
        assert_eq!(v["minGrossFillSompi"], "50000000");
        assert_eq!(v["protocolFeeRecipient"], PROTOCOL_FEE_RECIPIENT);
        assert_eq!(v["protocolFeeBps"], 200);
    }

    #[test]
    fn decodes_v3_actions() {
        let d = Kcc20V3Decoder::new([0u8; 32]);
        assert_eq!(
            d.decode_action(&[0x00, 0x01, 0xaa]).as_deref(),
            Some("issueFromRoot")
        );
        assert_eq!(
            d.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("createBidFromRoot")
        );
        assert_eq!(
            d.decode_action(&[0x53, 0x01, 0xaa]).as_deref(),
            Some("fillAskPartial")
        );
        assert_eq!(
            d.decode_action(&[0x54, 0x01, 0xaa]).as_deref(),
            Some("fillBidPartial")
        );
        assert_eq!(d.decode_action(&[0x5a, 0x01, 0xaa]), None);
    }

    #[test]
    fn decodes_create_ask_output_states() {
        let script = placeholder_script();
        let mut sig = Vec::new();
        sig.push(64);
        sig.extend([0xaa; 64]);
        push_i64(&mut sig, 400);
        push_i64(&mut sig, 50_000_000);
        sig.push(0x00);
        sig.push(0x51);
        sig.push(0x52);
        push_script(&mut sig, &script);

        let out = decode_output_state_values(&sig, &script).unwrap().unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, 0);
        assert_eq!(out[0].1["modeName"], "ask");
        assert_eq!(out[0].1["amount"], "400");
        assert_eq!(out[0].1["unitPriceSompi"], "50000000");
        assert_eq!(out[1].0, 1);
        assert_eq!(out[1].1["modeName"], "holder");
        assert_eq!(out[1].1["amount"], "999600");
    }

    #[test]
    fn decodes_root_bid_output_states() {
        let script = placeholder_script();
        let buyer = [0x44; 32];
        let mut sig = Vec::new();
        sig.push(32);
        sig.extend(buyer);
        push_i64(&mut sig, 250);
        push_i64(&mut sig, 10_000_000);
        sig.push(0x00);
        sig.push(0x51);
        sig.push(0x51);
        push_script(&mut sig, &script);

        let out = decode_output_state_values(&sig, &script).unwrap().unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, 0);
        assert_eq!(out[0].1["ownerIdentifier"], hex::encode(buyer));
        assert_eq!(out[0].1["modeName"], "bid");
        assert_eq!(out[0].1["amount"], "250");
        assert_eq!(out[1].0, 1);
        assert_eq!(out[1].1["modeName"], "root");
    }

    #[test]
    fn decodes_partial_and_full_ask_fill_outputs() {
        let script = placeholder_script();
        let buyer = [0x55; 32];
        let mut partial = Vec::new();
        partial.push(32);
        partial.extend(buyer);
        push_i64(&mut partial, 50);
        partial.push(0x00);
        partial.push(0x51);
        partial.push(0x52);
        partial.push(0x53);
        push_script(&mut partial, &script);

        let out = decode_output_state_values(&partial, &script)
            .unwrap()
            .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, 0);
        assert_eq!(out[0].1["ownerIdentifier"], hex::encode(buyer));
        assert_eq!(out[0].1["modeName"], "holder");
        assert_eq!(out[0].1["amount"], "50");
        assert_eq!(out[1].0, 1);
        assert_eq!(out[1].1["modeName"], "ask");
        assert_eq!(out[1].1["amount"], "999950");

        let mut full = Vec::new();
        full.push(32);
        full.extend(buyer);
        push_i64(&mut full, 1_000_000);
        full.push(0x00);
        full.push(0x51);
        full.push(0x52);
        full.push(0x53);
        push_script(&mut full, &script);

        let out = decode_output_state_values(&full, &script).unwrap().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1["modeName"], "holder");
        assert_eq!(out[0].1["amount"], "1000000");
    }

    #[test]
    fn decodes_partial_and_full_bid_fill_outputs() {
        let script = placeholder_script();
        let seller = [0x66; 32];
        let mut partial = Vec::new();
        partial.push(0x51);
        push_i64(&mut partial, 50);
        partial.push(0x00);
        partial.push(0x51);
        partial.push(0x52);
        partial.push(32);
        partial.extend(seller);
        partial.push(0x54);
        push_script(&mut partial, &script);

        let out = decode_output_state_values(&partial, &script)
            .unwrap()
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 1);
        assert_eq!(out[0].1["modeName"], "bid");
        assert_eq!(out[0].1["amount"], "999950");

        let mut full = Vec::new();
        full.push(0x51);
        push_i64(&mut full, 1_000_000);
        full.push(0x00);
        full.push(0x51);
        full.push(0x52);
        full.push(32);
        full.extend(seller);
        full.push(0x54);
        push_script(&mut full, &script);

        let out = decode_output_state_values(&full, &script).unwrap().unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn decodes_sell_into_bid_holder_change_edge() {
        let script = placeholder_script();
        let buyer = [0x77; 32];
        let mut partial = Vec::new();
        partial.push(64);
        partial.extend([0xaa; 64]);
        partial.push(32);
        partial.extend(buyer);
        push_i64(&mut partial, 75);
        partial.push(0x00);
        partial.push(0x51);
        partial.push(0x55);
        push_script(&mut partial, &script);

        let out = decode_output_state_values(&partial, &script)
            .unwrap()
            .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1["ownerIdentifier"], hex::encode(buyer));
        assert_eq!(out[0].1["modeName"], "holder");
        assert_eq!(out[0].1["amount"], "75");
        assert_eq!(out[1].1["modeName"], "holder");
        assert_eq!(out[1].1["amount"], "999925");

        let mut full = Vec::new();
        full.push(64);
        full.extend([0xaa; 64]);
        full.push(32);
        full.extend(buyer);
        push_i64(&mut full, 1_000_000);
        full.push(0x00);
        full.push(0x51);
        full.push(0x55);
        push_script(&mut full, &script);

        let out = decode_output_state_values(&full, &script).unwrap().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1["ownerIdentifier"], hex::encode(buyer));
        assert_eq!(out[0].1["amount"], "1000000");
    }
}
