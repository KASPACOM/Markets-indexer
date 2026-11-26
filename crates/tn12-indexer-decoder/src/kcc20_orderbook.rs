//! KCC20 orderbook decoder.
//!
//! Wrap and unwrap supply is gated by a reserve wrapper covenant in the same
//! covenant family.

use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, item_bytes_32, item_int, script_items};
use crate::kcc20_standard::{item_tag, owner_scheme_name};
use crate::TemplateDecoder;

pub const KCC20_ORDERBOOK_SCRIPT_LEN: usize = 25496;
const GENESIS_CANONICAL_TOKEN_RANGE: (usize, usize) = (2, 34);
const GENESIS_OWNER_RANGE: (usize, usize) = (35, 67);
const GENESIS_OWNER_SCHEME_RANGE: (usize, usize) = (68, 69);
const GENESIS_AMOUNT_RANGE: (usize, usize) = (70, 78);
const GENESIS_MODE_RANGE: (usize, usize) = (79, 87);
const GENESIS_UNIT_PRICE_RANGE: (usize, usize) = (88, 96);
const GENESIS_FEE_TICKET_RANGE: (usize, usize) = (97, 129);
const GENESIS_PRICE_SCALE_RANGE: (usize, usize) = (130, 138);
const ACTION_TAGS: [[u8; 4]; 15] = [
    [0xcf, 0x72, 0x4d, 0xcc],
    [0xa1, 0x58, 0x20, 0x22],
    [0xff, 0x4d, 0x23, 0xb3],
    [0xcb, 0x10, 0x63, 0xeb],
    [0x0f, 0xce, 0x1f, 0xa4],
    [0xa4, 0x5e, 0x76, 0x80],
    [0x1b, 0xef, 0x28, 0x9d],
    [0xe4, 0x55, 0xbb, 0xad],
    [0xc2, 0x3a, 0xc7, 0x50],
    [0x78, 0x32, 0xc4, 0x82],
    [0x80, 0xc5, 0x48, 0x6d],
    [0x4b, 0xa1, 0xee, 0xf2],
    [0x5a, 0xc2, 0x7a, 0x60],
    [0xea, 0x50, 0xeb, 0x13],
    [0x9e, 0x96, 0xe5, 0xf4],
];
const ACTION_NAMES: [&str; 15] = [
    "unwrapByOwnerSig",
    "createBidFromRoot",
    "createAskByOwnerSig",
    "fillAskPartial",
    "fillBidPartial",
    "sellIntoBidByOwnerSig",
    "crossAskSide",
    "crossBidSide",
    "cancelAskByOwnerSig",
    "cancelBidByOwnerSig",
    "mergeByOwnerSig",
    "mergePeerByOwnerSig",
    "fillBidFromSellerSweep",
    "sellIntoBidsByOwnerSig",
    "sellIntoBids10ByOwnerSig",
];
const PROTOCOL_FEE_BPS: i128 = 200;
const MIN_PROTOCOL_FEE_SOMPI: i128 = 50_000_000;
const MIN_GROSS_FILL_SOMPI: i128 = 50_000_000;
const PROTOCOL_FEE_RECIPIENT: &str =
    "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01";

pub struct Kcc20OrderbookDecoder {
    fingerprint: [u8; 32],
    script_len: usize,
}

impl Kcc20OrderbookDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            fingerprint,
            script_len: KCC20_ORDERBOOK_SCRIPT_LEN,
        }
    }

    pub fn with_script_len(fingerprint: [u8; 32], script_len: usize) -> Self {
        Self {
            fingerprint,
            script_len,
        }
    }

    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        let mut masked = script.to_vec();
        for (start, end) in [
            GENESIS_CANONICAL_TOKEN_RANGE,
            GENESIS_OWNER_RANGE,
            GENESIS_OWNER_SCHEME_RANGE,
            GENESIS_AMOUNT_RANGE,
            GENESIS_MODE_RANGE,
            GENESIS_UNIT_PRICE_RANGE,
            GENESIS_FEE_TICKET_RANGE,
            GENESIS_PRICE_SCALE_RANGE,
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

impl TemplateDecoder for Kcc20OrderbookDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20Orderbook
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        reveal.len() == self.script_len
            && Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        if payload.len() != self.script_len {
            return Err(anyhow!(
                "reveal script is {} bytes, expected {}",
                payload.len(),
                self.script_len
            ));
        }
        Ok(state_value(&reveal_state(payload)?))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        decode_state_payload(payload)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let items = script_items(args_prefix_before_reveal(signature_script));
        action_index(items.last().and_then(item_tag)?).map(|index| ACTION_NAMES[index].into())
    }
}

pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(item_tag).and_then(action_index) else {
        return Ok(None);
    };

    let args = match selector {
        0 => {
            let mut args = json!({
                "wrapperInputIndex": item_int(&items, 1)?.to_string(),
                "tokenAmount": item_int(&items, 2)?.to_string(),
                "changeOutputIndex": item_int(&items, 3)?.to_string(),
            });
            if items.len() >= 6 {
                args["refundOutputIndex"] = Value::String(item_int(&items, 4)?.to_string());
            }
            args
        }
        3 => json!({
            "fillAmount": item_int(&items, 1)?.to_string(),
            "buyerOutputIndex": item_int(&items, 2)?.to_string(),
            "askOutputIndex": item_int(&items, 3)?.to_string(),
            "sellerOutputIndex": item_int(&items, 4)?.to_string(),
            "ticketInputIndex": if items.len() >= 7 { item_int(&items, 5)? } else { -1 }.to_string(),
        }),
        4 => json!({
            "sellerInputIndex": item_int(&items, 0)?.to_string(),
            "fillAmount": item_int(&items, 1)?.to_string(),
            "buyerOutputIndex": item_int(&items, 2)?.to_string(),
            "bidOutputIndex": item_int(&items, 3)?.to_string(),
            "sellerOutputIndex": item_int(&items, 4)?.to_string(),
            "ticketInputIndex": if items.len() >= 8 { item_int(&items, 6)? } else { -1 }.to_string(),
        }),
        5 => {
            let mut args = json!({
                "fillAmount": item_int(&items, 2)?.to_string(),
                "buyerOutputIndex": item_int(&items, 3)?.to_string(),
                "changeOutputIndex": item_int(&items, 4)?.to_string(),
            });
            if items.len() >= 7 {
                args["refundOutputIndex"] = Value::String(item_int(&items, 5)?.to_string());
            }
            if items.len() >= 8 {
                args["sellerOutputsEndIndex"] = Value::String(item_int(&items, 6)?.to_string());
            }
            args
        }
        6 => json!({
            "bidInputIndex": item_int(&items, 1)?.to_string(),
            "fillAmount": item_int(&items, 2)?.to_string(),
            "clearingUnitPrice": item_int(&items, 3)?.to_string(),
            "buyerOutputIndex": item_int(&items, 4)?.to_string(),
            "askOutputIndex": item_int(&items, 5)?.to_string(),
            "bidOutputIndex": item_int(&items, 6)?.to_string(),
            "sellerOutputIndex": item_int(&items, 7)?.to_string(),
            "feeOutputIndex": item_int(&items, 8)?.to_string(),
            "refundOutputIndex": item_int(&items, 9)?.to_string(),
            "ticketInputIndex": if items.len() >= 12 { item_int(&items, 10)? } else { -1 }.to_string(),
        }),
        7 => json!({
            "askInputIndex": item_int(&items, 0)?.to_string(),
            "fillAmount": item_int(&items, 1)?.to_string(),
            "clearingUnitPrice": item_int(&items, 2)?.to_string(),
            "buyerOutputIndex": item_int(&items, 3)?.to_string(),
            "askOutputIndex": item_int(&items, 4)?.to_string(),
            "bidOutputIndex": item_int(&items, 5)?.to_string(),
            "sellerOutputIndex": item_int(&items, 6)?.to_string(),
            "feeOutputIndex": item_int(&items, 7)?.to_string(),
            "refundOutputIndex": item_int(&items, 8)?.to_string(),
            "ticketInputIndex": if items.len() >= 12 { item_int(&items, 10)? } else { -1 }.to_string(),
        }),
        10 => json!({
            "mergedOutputIndex": KCC20_ORDERBOOK_MERGED_OUTPUT_INDEX.to_string(),
            "refundOutputIndex": "1",
        }),
        11 => json!({
            "primaryInputIndex": item_int(&items, 1)?.to_string(),
            "mergedAmount": item_int(&items, 2)?.to_string(),
            "mergedOutputIndex": KCC20_ORDERBOOK_MERGED_OUTPUT_INDEX.to_string(),
            "refundOutputIndex": "1",
        }),
        12 => json!({
            "sellerInputIndex": item_int(&items, 0)?.to_string(),
            "sellerAuthOutputOrdinal": item_int(&items, 1)?.to_string(),
            "fillAmount": item_int(&items, 2)?.to_string(),
            "buyerOutputIndex": item_int(&items, 3)?.to_string(),
            "bidOutputIndex": item_int(&items, 4)?.to_string(),
            "sellerOutputIndex": item_int(&items, 5)?.to_string(),
            "ticketInputIndex": if items.len() >= 9 { item_int(&items, 7)? } else { -1 }.to_string(),
        }),
        13 => {
            let mut args = Map::new();
            for index in 0..3 {
                let base = 1 + index * 3;
                args.insert(
                    format!("fillAmount{}", index),
                    Value::String(item_int(&items, base + 1)?.to_string()),
                );
                args.insert(
                    format!("buyerOutputIndex{}", index),
                    Value::String(item_int(&items, base + 2)?.to_string()),
                );
            }
            args.insert(
                "changeOutputIndex".to_string(),
                Value::String(item_int(&items, 10)?.to_string()),
            );
            if items.len() >= 13 {
                args.insert(
                    "refundOutputIndex".to_string(),
                    Value::String(item_int(&items, 11)?.to_string()),
                );
            }
            if items.len() >= 14 {
                args.insert(
                    "sellerOutputsEndIndex".to_string(),
                    Value::String(item_int(&items, 12)?.to_string()),
                );
            }
            Value::Object(args)
        }
        14 => {
            let mut args = Map::new();
            for index in 0..10 {
                let base = 1 + index * 3;
                args.insert(
                    format!("fillAmount{}", index),
                    Value::String(item_int(&items, base + 1)?.to_string()),
                );
                args.insert(
                    format!("buyerOutputIndex{}", index),
                    Value::String(item_int(&items, base + 2)?.to_string()),
                );
            }
            args.insert(
                "changeOutputIndex".to_string(),
                Value::String(item_int(&items, 31)?.to_string()),
            );
            if items.len() >= 34 {
                args.insert(
                    "refundOutputIndex".to_string(),
                    Value::String(item_int(&items, 32)?.to_string()),
                );
            }
            if items.len() >= 35 {
                args.insert(
                    "sellerOutputsEndIndex".to_string(),
                    Value::String(item_int(&items, 33)?.to_string()),
                );
            }
            Value::Object(args)
        }
        _ => return Ok(None),
    };

    Ok(Some(args))
}

#[derive(Debug, Clone)]
struct OrderbookState {
    canonical_token_id: String,
    owner: String,
    owner_scheme: u8,
    amount: i128,
    mode: i128,
    unit_price_sompi: i128,
    fee_ticket_id: String,
    price_scale: i128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderbookMergeRequest {
    pub merged_output_index: i32,
}

pub const KCC20_ORDERBOOK_MAX_MERGE_INPUTS: usize = 8;
pub const KCC20_ORDERBOOK_MERGED_OUTPUT_INDEX: i32 = 0;

fn action_index(tag: [u8; 4]) -> Option<usize> {
    ACTION_TAGS.iter().position(|candidate| *candidate == tag)
}

pub fn decode_primary_merge_request(
    signature_script: &[u8],
) -> Result<Option<OrderbookMergeRequest>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    let Some(selector) = items.last().and_then(item_tag).and_then(action_index) else {
        return Ok(None);
    };
    if selector != 10 {
        return Ok(None);
    }

    Ok(Some(OrderbookMergeRequest {
        merged_output_index: KCC20_ORDERBOOK_MERGED_OUTPUT_INDEX,
    }))
}

pub fn decode_merge_peer_primary_input(signature_script: &[u8]) -> Result<Option<usize>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    let Some(selector) = items.last().and_then(item_tag).and_then(action_index) else {
        return Ok(None);
    };
    if selector != 11 {
        return Ok(None);
    }

    Ok(Some(usize::try_from(item_int(&items, 1)?).map_err(
        |_| anyhow!("KCC20Orderbook merge primary input index is invalid"),
    )?))
}

pub fn decode_merge_output_state_value(
    primary_input_index: usize,
    primary_signature_script: &[u8],
    primary_reveal_script: &[u8],
    peer_inputs: &[(usize, Vec<u8>)],
) -> Result<Option<(i32, Value, [u8; 32])>> {
    let Some(request) = decode_primary_merge_request(primary_signature_script)? else {
        return Ok(None);
    };
    if peer_inputs.is_empty() || peer_inputs.len() >= KCC20_ORDERBOOK_MAX_MERGE_INPUTS {
        return Err(anyhow!(
            "KCC20Orderbook merge must contain between 2 and {} holder inputs",
            KCC20_ORDERBOOK_MAX_MERGE_INPUTS
        ));
    }

    let primary = reveal_state(primary_reveal_script)?;
    if !primary.is_merge_holder() {
        return Err(anyhow!("KCC20Orderbook merge inputs must be holder states"));
    }
    let mut merged_amount = primary.amount;
    for (peer_input_index, peer_reveal_script) in peer_inputs {
        if *peer_input_index == primary_input_index {
            return Err(anyhow!(
                "KCC20Orderbook merge peer cannot be the primary input"
            ));
        }
        let peer = reveal_state(peer_reveal_script)?;
        if !peer.is_merge_holder() {
            return Err(anyhow!("KCC20Orderbook merge inputs must be holder states"));
        }
        if !primary.merge_compatible_with(&peer) {
            return Err(anyhow!(
                "KCC20Orderbook merge input states are incompatible"
            ));
        }
        merged_amount = merged_amount
            .checked_add(peer.amount)
            .ok_or_else(|| anyhow!("KCC20Orderbook merged amount overflow"))?;
    }

    let (output_index, state) = output(
        &primary,
        request.merged_output_index,
        primary.owner.clone(),
        merged_amount,
        0,
        0,
        primary.fee_ticket_id.clone(),
        primary.price_scale,
    );
    let mut merged_script = primary_reveal_script.to_vec();
    let merged_amount = i64::try_from(merged_amount)
        .map_err(|_| anyhow!("KCC20Orderbook merged amount is outside i64"))?;
    merged_script[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1]
        .copy_from_slice(&merged_amount.to_le_bytes());

    Ok(Some((output_index, state, blake2b_256(&merged_script))))
}

pub fn decode_output_state_values(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Vec<(i32, Value)>>> {
    let input_state = reveal_state(reveal_script)?;
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(item_tag).and_then(action_index) else {
        return Ok(None);
    };

    match selector {
        0 => {
            let token_amount = item_int(&items, 2)?;
            if token_amount >= input_state.amount {
                return Ok(Some(Vec::new()));
            }
            Ok(Some(vec![output(
                &input_state,
                item_int(&items, 3)? as i32,
                input_state.owner.clone(),
                input_state.amount - token_amount,
                0,
                0,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )]))
        }
        1 => Ok(Some(vec![
            output(
                &input_state,
                item_int(&items, 3)? as i32,
                hex::encode(item_bytes_32(&items, 0)?),
                item_int(&items, 1)?,
                3,
                item_int(&items, 2)?,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            ),
            output(
                &input_state,
                item_int(&items, 4)? as i32,
                input_state.owner.clone(),
                input_state.amount,
                1,
                0,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            ),
        ])),
        2 => {
            let ask_amount = item_int(&items, 1)?;
            let mut outputs = vec![output(
                &input_state,
                item_int(&items, 3)? as i32,
                input_state.owner.clone(),
                ask_amount,
                2,
                item_int(&items, 2)?,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )];
            if ask_amount < input_state.amount {
                outputs.push(output(
                    &input_state,
                    item_int(&items, 4)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - ask_amount,
                    0,
                    0,
                    input_state.fee_ticket_id.clone(),
                    input_state.price_scale,
                ));
            }
            Ok(Some(outputs))
        }
        3 => {
            let fill_amount = item_int(&items, 1)?;
            let mut outputs = vec![output(
                &input_state,
                item_int(&items, 2)? as i32,
                hex::encode(item_bytes_32(&items, 0)?),
                fill_amount,
                0,
                0,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )];
            if fill_amount < input_state.amount {
                outputs.push(output(
                    &input_state,
                    item_int(&items, 3)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - fill_amount,
                    2,
                    input_state.unit_price_sompi,
                    input_state.fee_ticket_id.clone(),
                    input_state.price_scale,
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
                &input_state,
                item_int(&items, 3)? as i32,
                input_state.owner.clone(),
                input_state.amount - fill_amount,
                3,
                input_state.unit_price_sompi,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )]))
        }
        5 => {
            let fill_amount = item_int(&items, 2)?;
            let mut outputs = vec![output(
                &input_state,
                item_int(&items, 3)? as i32,
                hex::encode(item_bytes_32(&items, 1)?),
                fill_amount,
                0,
                0,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )];
            if fill_amount < input_state.amount {
                outputs.push(output(
                    &input_state,
                    item_int(&items, 4)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - fill_amount,
                    0,
                    0,
                    input_state.fee_ticket_id.clone(),
                    input_state.price_scale,
                ));
            }
            Ok(Some(outputs))
        }
        6 => {
            let fill_amount = item_int(&items, 2)?;
            let mut outputs = vec![output(
                &input_state,
                item_int(&items, 4)? as i32,
                hex::encode(item_bytes_32(&items, 0)?),
                fill_amount,
                0,
                0,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )];
            if fill_amount < input_state.amount {
                outputs.push(output(
                    &input_state,
                    item_int(&items, 5)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - fill_amount,
                    2,
                    input_state.unit_price_sompi,
                    input_state.fee_ticket_id.clone(),
                    input_state.price_scale,
                ));
            }
            Ok(Some(outputs))
        }
        7 => {
            let fill_amount = item_int(&items, 1)?;
            if fill_amount >= input_state.amount {
                return Ok(Some(Vec::new()));
            }
            Ok(Some(vec![output(
                &input_state,
                item_int(&items, 5)? as i32,
                input_state.owner.clone(),
                input_state.amount - fill_amount,
                3,
                input_state.unit_price_sompi,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )]))
        }
        8 => Ok(Some(vec![output(
            &input_state,
            item_int(&items, 1)? as i32,
            input_state.owner.clone(),
            input_state.amount,
            0,
            0,
            input_state.fee_ticket_id.clone(),
            input_state.price_scale,
        )])),
        9 => Ok(Some(Vec::new())),
        10 | 11 => Ok(None),
        12 => {
            let fill_amount = item_int(&items, 2)?;
            if fill_amount >= input_state.amount {
                return Ok(Some(Vec::new()));
            }
            Ok(Some(vec![output(
                &input_state,
                item_int(&items, 4)? as i32,
                input_state.owner.clone(),
                input_state.amount - fill_amount,
                3,
                input_state.unit_price_sompi,
                input_state.fee_ticket_id.clone(),
                input_state.price_scale,
            )]))
        }
        13 | 14 => {
            let leg_count = if selector == 13 { 3 } else { 10 };
            let mut outputs = Vec::new();
            let mut total_fill = 0;
            for index in 0..leg_count {
                let buyer_idx = 1 + index * 3;
                let fill = item_int(&items, buyer_idx + 1)?;
                let output_idx = buyer_idx + 2;
                if fill > 0 {
                    outputs.push(output(
                        &input_state,
                        item_int(&items, output_idx)? as i32,
                        hex::encode(item_bytes_32(&items, buyer_idx)?),
                        fill,
                        0,
                        0,
                        input_state.fee_ticket_id.clone(),
                        input_state.price_scale,
                    ));
                }
                total_fill += fill;
            }
            if total_fill < input_state.amount {
                outputs.push(output(
                    &input_state,
                    item_int(&items, 1 + leg_count * 3)? as i32,
                    input_state.owner.clone(),
                    input_state.amount - total_fill,
                    0,
                    0,
                    input_state.fee_ticket_id.clone(),
                    input_state.price_scale,
                ));
            }
            Ok(Some(outputs))
        }
        _ => Ok(None),
    }
}

pub fn decode_reveal_state_value(payload: &[u8]) -> Result<Value> {
    if !is_supported_reveal_len(payload.len()) {
        return Err(anyhow!(
            "reveal script is {} bytes, expected a supported KCC20Orderbook length",
            payload.len(),
        ));
    }
    Ok(state_value(&reveal_state(payload)?))
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() != 137 {
        return Err(anyhow!(
            "KCC20Orderbook state payload too short ({} bytes)",
            payload.len()
        ));
    }
    expect_len(payload, 0, 32, "canonicalTokenId")?;
    expect_len(payload, 33, 32, "owner")?;
    expect_len(payload, 66, 1, "ownerScheme")?;
    expect_len(payload, 68, 8, "amount")?;
    expect_len(payload, 77, 8, "mode")?;
    expect_len(payload, 86, 8, "unitPriceSompi")?;
    expect_len(payload, 95, 32, "feeTicketId")?;
    expect_len(payload, 128, 8, "priceScale")?;

    Ok(state_value(&OrderbookState {
        canonical_token_id: hex::encode(&payload[1..33]),
        owner: hex::encode(&payload[34..66]),
        owner_scheme: payload[67],
        amount: parse_minimal_int(&payload[69..77]),
        mode: parse_minimal_int(&payload[78..86]),
        unit_price_sompi: parse_minimal_int(&payload[87..95]),
        fee_ticket_id: hex::encode(&payload[96..128]),
        price_scale: parse_minimal_int(&payload[129..137]),
    }))
}

fn reveal_state(payload: &[u8]) -> Result<OrderbookState> {
    if !is_supported_reveal_len(payload.len()) {
        return Err(anyhow!(
            "reveal script is {} bytes, expected a supported KCC20Orderbook length",
            payload.len(),
        ));
    }
    Ok(OrderbookState {
        canonical_token_id: hex::encode(
            &payload[GENESIS_CANONICAL_TOKEN_RANGE.0..GENESIS_CANONICAL_TOKEN_RANGE.1],
        ),
        owner: hex::encode(&payload[GENESIS_OWNER_RANGE.0..GENESIS_OWNER_RANGE.1]),
        owner_scheme: payload[GENESIS_OWNER_SCHEME_RANGE.0],
        amount: parse_minimal_int(&payload[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1]),
        mode: parse_minimal_int(&payload[GENESIS_MODE_RANGE.0..GENESIS_MODE_RANGE.1]),
        unit_price_sompi: parse_minimal_int(
            &payload[GENESIS_UNIT_PRICE_RANGE.0..GENESIS_UNIT_PRICE_RANGE.1],
        ),
        fee_ticket_id: hex::encode(
            &payload[GENESIS_FEE_TICKET_RANGE.0..GENESIS_FEE_TICKET_RANGE.1],
        ),
        price_scale: parse_minimal_int(
            &payload[GENESIS_PRICE_SCALE_RANGE.0..GENESIS_PRICE_SCALE_RANGE.1],
        ),
    })
}

fn is_supported_reveal_len(script_len: usize) -> bool {
    script_len == KCC20_ORDERBOOK_SCRIPT_LEN
}

fn output(
    input_state: &OrderbookState,
    output_index: i32,
    owner: String,
    amount: i128,
    mode: i128,
    unit_price_sompi: i128,
    fee_ticket_id: String,
    price_scale: i128,
) -> (i32, Value) {
    (
        output_index,
        state_value(&OrderbookState {
            canonical_token_id: input_state.canonical_token_id.clone(),
            owner,
            owner_scheme: input_state.owner_scheme,
            amount,
            mode,
            unit_price_sompi,
            fee_ticket_id,
            price_scale,
        }),
    )
}

fn state_value(state: &OrderbookState) -> Value {
    json!({
        "canonicalTokenId": state.canonical_token_id,
        "tokenId": state.canonical_token_id,
        "owner": state.owner,
        "ownerIdentifier": state.owner,
        "ownerScheme": state.owner_scheme,
        "ownerSchemeName": owner_scheme_name(state.owner_scheme),
        "amount": state.amount.to_string(),
        "mode": state.mode,
        "modeName": mode_name(state.mode),
        "isMintAuthority": state.mode == 1,
        "isMinter": state.mode == 1,
        "unitPriceSompi": state.unit_price_sompi.to_string(),
        "feeTicketId": state.fee_ticket_id,
        "priceScale": state.price_scale.to_string(),
        "tokenDisplayScale": state.price_scale.to_string(),
        "minGrossFillSompi": MIN_GROSS_FILL_SOMPI.to_string(),
        "minProtocolFeeSompi": MIN_PROTOCOL_FEE_SOMPI.to_string(),
        "feeRecipient": PROTOCOL_FEE_RECIPIENT,
        "protocolFeeRecipient": PROTOCOL_FEE_RECIPIENT,
        "feeBps": PROTOCOL_FEE_BPS,
        "protocolFeeBps": PROTOCOL_FEE_BPS,
        "stateOwner": state.owner,
        "stateOwnerType": state.owner_scheme,
        "stateAmount": state.amount.to_string(),
        "stateMode": state.mode,
        "marketUnitPriceSompi": state.unit_price_sompi.to_string(),
        "supplyBacking": "kcc20WrapperReserve",
    })
}

impl OrderbookState {
    fn is_merge_holder(&self) -> bool {
        self.mode == 0 && self.amount > 0 && self.unit_price_sompi == 0
    }

    fn merge_compatible_with(&self, other: &Self) -> bool {
        self.canonical_token_id == other.canonical_token_id
            && self.owner == other.owner
            && self.owner_scheme == other.owner_scheme
            && self.mode == other.mode
            && self.unit_price_sompi == other.unit_price_sompi
            && self.fee_ticket_id == other.fee_ticket_id
            && self.price_scale == other.price_scale
    }
}

fn expect_len(payload: &[u8], offset: usize, expected: usize, label: &str) -> Result<()> {
    let actual = payload
        .get(offset)
        .copied()
        .ok_or_else(|| anyhow!("missing KCC20Orderbook {label} push length"))?
        as usize;
    if actual != expected {
        return Err(anyhow!(
            "unexpected KCC20Orderbook {label} push length {actual}, expected {expected}"
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
mod current_tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-orderbook/KCC20Orderbook.placeholder.json"
        ))
        .unwrap();
        artifact["bytecode"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect()
    }

    fn action_script(tag: [u8; 4]) -> Vec<u8> {
        let mut script = vec![4];
        script.extend(tag);
        script.extend([1, 0xaa]);
        script
    }

    fn push_i64(script: &mut Vec<u8>, value: i64) {
        script.push(8);
        script.extend(value.to_le_bytes());
    }

    fn push_data(script: &mut Vec<u8>, value: &[u8]) {
        script.push(value.len() as u8);
        script.extend(value);
    }

    fn fill_action_script(selector: usize, ticket_input_index: i64) -> Vec<u8> {
        let mut script = Vec::new();
        match selector {
            3 => {
                push_data(&mut script, &[0x22; 32]);
                for value in [1, 0, -1, 1, ticket_input_index] {
                    push_i64(&mut script, value);
                }
            }
            4 => {
                for value in [1, 1, 0, -1, 1] {
                    push_i64(&mut script, value);
                }
                push_data(&mut script, &[0x33; 32]);
                push_i64(&mut script, ticket_input_index);
            }
            12 => {
                for value in [1, 0, 1, 0, -1, 1] {
                    push_i64(&mut script, value);
                }
                push_data(&mut script, &[0x44; 32]);
                push_i64(&mut script, ticket_input_index);
            }
            _ => unreachable!(),
        }
        push_data(&mut script, &ACTION_TAGS[selector]);
        push_data(&mut script, &[0xaa]);
        script
    }

    #[test]
    fn current_artifact_and_all_kcc1_actions_decode() {
        let script = placeholder_script();
        assert_eq!(script.len(), KCC20_ORDERBOOK_SCRIPT_LEN);
        let decoder = Kcc20OrderbookDecoder::new(
            Kcc20OrderbookDecoder::fingerprint_of_compiled_script(&script),
        );
        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(
            decoder.decode_constructor(&script).unwrap()["ownerScheme"],
            0
        );

        for (index, tag) in ACTION_TAGS.iter().enumerate() {
            assert_eq!(
                decoder.decode_action(&action_script(*tag)).as_deref(),
                Some(ACTION_NAMES[index])
            );
        }
        assert_eq!(decoder.decode_action(&action_script([0; 4])), None);
    }

    #[test]
    fn current_direct_fill_action_args_include_fee_ticket_input() {
        for selector in [3, 4, 12] {
            let args = decode_action_args(&fill_action_script(selector, 2))
                .unwrap()
                .unwrap();
            assert_eq!(args["ticketInputIndex"], "2");
        }
    }
}
