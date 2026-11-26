//! KCC20 reserve wrapper decoder.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, item_bytes_32, item_int, script_items};
use crate::kcc20_standard::{item_tag, owner_scheme_name};
use crate::TemplateDecoder;

pub const KCC20_WRAPPER_SCRIPT_LEN: usize = 3895;
// SilverScript v1.0.0 dispatch tags. Keep these pinned to the vendored ABI;
// the v1.0.0 compiler changed both wrapper selectors from the rc1 values.
const WRAP_TAG: [u8; 4] = [0x45, 0xf3, 0x39, 0x9f];
const UNWRAP_TAG: [u8; 4] = [0xa3, 0x40, 0x3f, 0xd7];
const CANONICAL_TOKEN_RANGE: (usize, usize) = (2, 34);
const ENABLED_RANGE: (usize, usize) = (35, 36);
const PRICE_SCALE_RANGE: (usize, usize) = (37, 45);

pub struct Kcc20WrapperDecoder {
    fingerprint: [u8; 32],
    script_len: usize,
}

impl Kcc20WrapperDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            fingerprint,
            script_len: KCC20_WRAPPER_SCRIPT_LEN,
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
        for (start, end) in [CANONICAL_TOKEN_RANGE, ENABLED_RANGE, PRICE_SCALE_RANGE] {
            if end <= masked.len() {
                for b in masked[start..end].iter_mut() {
                    *b = 0;
                }
            }
        }
        blake2b_256(&masked)
    }
}

impl TemplateDecoder for Kcc20WrapperDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20Wrapper
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
        Ok(json!({
            "canonicalTokenId": hex::encode(&payload[CANONICAL_TOKEN_RANGE.0..CANONICAL_TOKEN_RANGE.1]),
            "enabled": payload[ENABLED_RANGE.0] != 0,
            "priceScale": parse_minimal_int(&payload[PRICE_SCALE_RANGE.0..PRICE_SCALE_RANGE.1]).to_string(),
            "wrappedTokenIdMode": "sameCovenantFamily",
            "reserveOwnerScheme": 4,
            "reserveOwnerSchemeName": owner_scheme_name(4),
        }))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        if payload.len() < 44 {
            return Err(anyhow!(
                "KCC20Wrapper state payload too short ({} bytes)",
                payload.len()
            ));
        }
        if payload[0] != 32 {
            return Err(anyhow!(
                "unexpected KCC20Wrapper canonicalTokenId push length"
            ));
        }
        if payload[33] != 1 {
            return Err(anyhow!("unexpected KCC20Wrapper enabled push length"));
        }
        if payload[35] != 8 {
            return Err(anyhow!("unexpected KCC20Wrapper priceScale push length"));
        }
        Ok(json!({
            "canonicalTokenId": hex::encode(&payload[1..33]),
            "enabled": parse_minimal_int(&payload[34..35]) != 0,
            "priceScale": parse_minimal_int(&payload[36..44]).to_string(),
            "wrappedTokenIdMode": "sameCovenantFamily",
        }))
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let items = script_items(args_prefix_before_reveal(signature_script));
        match items.last().and_then(item_tag) {
            Some(WRAP_TAG) => Some("wrap".into()),
            Some(UNWRAP_TAG) => Some("unwrap".into()),
            _ => None,
        }
    }
}

/// Decode the input/output linkage that the wrapper covenant validates.
///
/// Persisting these indexes lets projections distinguish the reserve movement
/// from an unrelated same-token transfer batched into the same transaction.
pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };

    let args = match tag {
        WRAP_TAG => json!({
            "tokenInputIndex": item_int(&items, 6)?.to_string(),
            "tokenLockedOutputIndex": item_int(&items, 7)?.to_string(),
            "orderbookHolderOutputIndex": item_int(&items, 8)?.to_string(),
            "wrapperOutputIndex": item_int(&items, 9)?.to_string(),
            "wrappedRecipient": hex::encode(item_bytes_32(&items, 10)?),
            "wrappedRecipientScheme": item_int(&items, 11)?.to_string(),
            "tokenAmount": item_int(&items, 12)?.to_string(),
        }),
        UNWRAP_TAG => json!({
            "wrappedInputIndex": item_int(&items, 6)?.to_string(),
            "tokenReserveInputIndex": item_int(&items, 7)?.to_string(),
            "tokenRecipientOutputIndex": item_int(&items, 8)?.to_string(),
            "tokenReserveChangeOutputIndex": item_int(&items, 9)?.to_string(),
            "wrappedChangeOutputIndex": item_int(&items, 10)?.to_string(),
            "wrapperOutputIndex": item_int(&items, 11)?.to_string(),
            "tokenRecipient": hex::encode(item_bytes_32(&items, 12)?),
            "tokenRecipientScheme": item_int(&items, 13)?.to_string(),
            "tokenAmount": item_int(&items, 14)?.to_string(),
        }),
        _ => return Ok(None),
    };

    Ok(Some(args))
}

pub fn decode_wrap_output_state_values(
    signature_script: &[u8],
    canonical_token_id_override: Option<&[u8]>,
    wrapper_covenant_id: &[u8],
) -> Result<Option<Vec<(i32, Value)>>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };
    if tag != WRAP_TAG {
        return Ok(None);
    }

    let output_index = item_int(&items, 8)? as i32;
    let wrapper_covenant_id = hex::encode(wrapper_covenant_id);
    let canonical_token_id = canonical_token_id_override
        .filter(|value| value.len() == 32)
        .map(hex::encode)
        .unwrap_or(hex::encode(item_bytes_32(&items, 0)?));
    let owner = hex::encode(item_bytes_32(&items, 24)?);
    let owner_scheme = item_int(&items, 25)?;
    let amount = item_int(&items, 26)?;
    let mode = item_int(&items, 27)?;
    let unit_price = item_int(&items, 28)?;
    let fee_ticket_id = hex::encode(item_bytes_32(&items, 29)?);
    let price_scale = item_int(&items, 30)?;
    Ok(Some(vec![(
        output_index,
        json!({
            "canonicalTokenId": canonical_token_id,
            "tokenId": canonical_token_id,
            "owner": owner,
            "ownerIdentifier": owner,
            "ownerScheme": owner_scheme,
            "ownerSchemeName": owner_scheme_name(owner_scheme as u8),
            "amount": amount.to_string(),
            "mode": mode,
            "modeName": match mode {
                0 => "holder",
                1 => "root",
                2 => "ask",
                3 => "bid",
                _ => "unknown",
            },
            "isMintAuthority": mode == 1,
            "isMinter": mode == 1,
            "unitPriceSompi": unit_price.to_string(),
            "feeTicketId": fee_ticket_id,
            "priceScale": price_scale.to_string(),
            "tokenDisplayScale": price_scale.to_string(),
            "stateOwner": owner,
            "stateOwnerType": owner_scheme,
            "stateAmount": amount.to_string(),
            "stateMode": mode,
            "marketUnitPriceSompi": unit_price.to_string(),
            "wrapperCovenantId": wrapper_covenant_id,
            "supplyBacking": "kcc20WrapperReserve",
        }),
    )]))
}

pub fn decode_wrap_token_input_index(signature_script: &[u8]) -> Result<Option<usize>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };
    if tag != WRAP_TAG {
        return Ok(None);
    }
    let input_index = item_int(&items, 6)?;
    usize::try_from(input_index)
        .map(Some)
        .map_err(|_| anyhow!("KCC20Wrapper tokenInputIndex is negative"))
}

pub fn deploy_wrapped_root_state_from_claimed_args(
    claimed_args: &Value,
    state_owner_override: Option<&str>,
) -> Result<Value> {
    let canonical_token_id = claim_hex32(claimed_args, "canonicalTokenId")
        .ok_or_else(|| anyhow!("missing KCC20Wrapper canonical token claim"))?;
    let owner = state_owner_override
        .map(str::to_ascii_lowercase)
        .or_else(|| claim_hex32(claimed_args, "stateOwner"))
        .ok_or_else(|| anyhow!("missing KCC20Wrapper wrapped root owner claim"))?;
    let amount = claim_i128(claimed_args, "wrappedRootAmount").unwrap_or(0);
    if amount < 0 {
        return Err(anyhow!(
            "KCC20Wrapper wrappedRootAmount must be non-negative"
        ));
    }
    let fee_ticket_id = claim_hex32(claimed_args, "feeTicketId")
        .or_else(|| claim_hex32(claimed_args, "protocolFeeTicketId"))
        .unwrap_or_else(|| "0".repeat(64));
    let price_scale = claim_i128(claimed_args, "priceScale")
        .or_else(|| claim_i128(claimed_args, "tokenDisplayScale"))
        .unwrap_or(100_000_000);
    if price_scale <= 0 {
        return Err(anyhow!("KCC20Wrapper priceScale must be positive"));
    }

    Ok(json!({
        "canonicalTokenId": canonical_token_id,
        "tokenId": canonical_token_id,
        "owner": owner,
        "ownerIdentifier": owner,
        "ownerScheme": 0,
        "ownerSchemeName": owner_scheme_name(0),
        "amount": amount.to_string(),
        "mode": 1,
        "modeName": "root",
        "isMintAuthority": true,
        "isMinter": true,
        "unitPriceSompi": "0",
        "feeTicketId": fee_ticket_id,
        "priceScale": price_scale.to_string(),
        "tokenDisplayScale": price_scale.to_string(),
        "stateOwner": owner,
        "stateOwnerType": 0,
        "stateAmount": amount.to_string(),
        "stateMode": 1,
        "marketUnitPriceSompi": "0",
        "supplyBacking": "kcc20WrapperReserve",
    }))
}

fn claim_value<'a>(claimed_args: &'a Value, name: &str) -> Option<&'a Value> {
    claimed_args
        .get("args")?
        .as_array()?
        .iter()
        .find(|arg| arg.get("name").and_then(Value::as_str) == Some(name))?
        .get("value")
}

fn claim_string(claimed_args: &Value, name: &str) -> Option<String> {
    claim_value(claimed_args, name).and_then(|value| match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn claim_i128(claimed_args: &Value, name: &str) -> Option<i128> {
    claim_value(claimed_args, name).and_then(|value| match value {
        Value::String(s) => s.parse::<i128>().ok(),
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().and_then(|u| i128::try_from(u).ok())),
        _ => None,
    })
}

fn claim_hex32(claimed_args: &Value, name: &str) -> Option<String> {
    claim_string(claimed_args, name).and_then(|value| {
        let value = value.trim();
        if value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            Some(value.to_ascii_lowercase())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod state_template_tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-wrapper/KCC20Wrapper.placeholder.json"
        ))
        .unwrap();
        artifact["bytecode"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect()
    }

    #[test]
    fn wrapper_template_match_ignores_fixed_width_state_values() {
        let placeholder = placeholder_script();
        assert_eq!(placeholder.len(), KCC20_WRAPPER_SCRIPT_LEN);
        let decoder = Kcc20WrapperDecoder::new(
            Kcc20WrapperDecoder::fingerprint_of_compiled_script(&placeholder),
        );
        let mut deployed = placeholder.clone();
        deployed[CANONICAL_TOKEN_RANGE.0..CANONICAL_TOKEN_RANGE.1].fill(0x42);
        deployed[ENABLED_RANGE.0] = 0;
        deployed[PRICE_SCALE_RANGE.0..PRICE_SCALE_RANGE.1].copy_from_slice(&1_i64.to_le_bytes());
        assert!(decoder.matches_reveal_script(&deployed));
        let state = decoder.decode_state(&deployed[1..45]).unwrap();
        assert_eq!(state["priceScale"], "1");
        assert_eq!(state["enabled"], false);
    }
}

#[cfg(test)]
mod current_tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-wrapper/KCC20Wrapper.placeholder.json"
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

    fn push_data(script: &mut Vec<u8>, value: &[u8]) {
        match value.len() {
            0..=75 => script.push(value.len() as u8),
            76..=255 => {
                script.push(0x4c);
                script.push(value.len() as u8);
            }
            _ => {
                script.push(0x4d);
                script.extend_from_slice(&(value.len() as u16).to_le_bytes());
            }
        }
        script.extend_from_slice(value);
    }

    fn push_int(script: &mut Vec<u8>, value: u8) {
        match value {
            0 => script.push(0x00),
            1..=16 => script.push(0x50 + value),
            _ => push_data(script, &[value]),
        }
    }

    fn push_wrapper_state(script: &mut Vec<u8>, canonical_token_id: &[u8; 32]) {
        push_data(script, canonical_token_id);
        push_int(script, 1);
        push_int(script, 1);
    }

    fn push_kcc20_state(script: &mut Vec<u8>, owner: &[u8; 32], amount: u8) {
        push_int(script, amount);
        push_data(script, owner);
        push_int(script, 0);
        push_int(script, 0);
        push_data(script, &[0; 32]);
        push_data(script, &[0x55; 32]);
    }

    fn push_orderbook_state(
        script: &mut Vec<u8>,
        canonical_token_id: &[u8; 32],
        owner: &[u8; 32],
        amount: u8,
    ) {
        push_data(script, canonical_token_id);
        push_data(script, owner);
        push_int(script, 0);
        push_int(script, amount);
        push_int(script, 0);
        push_int(script, 0);
        push_data(script, &[0x66; 32]);
        push_int(script, 1);
    }

    fn current_wrap_script() -> Vec<u8> {
        let mut script = Vec::new();
        let token_id = [0x11; 32];
        let recipient = [0x44; 32];
        push_wrapper_state(&mut script, &token_id);
        push_wrapper_state(&mut script, &token_id);
        for value in 1..=4 {
            push_int(&mut script, value);
        }
        push_data(&mut script, &recipient);
        push_int(&mut script, 0);
        push_int(&mut script, 5);
        for value in 0x70..=0x73 {
            push_data(&mut script, &[value]);
        }
        push_kcc20_state(&mut script, &[0x33; 32], 5);
        push_orderbook_state(&mut script, &token_id, &recipient, 5);
        push_data(&mut script, &WRAP_TAG);
        push_data(&mut script, &placeholder_script());
        script
    }

    fn current_unwrap_script() -> Vec<u8> {
        let mut script = Vec::new();
        let token_id = [0x11; 32];
        push_wrapper_state(&mut script, &token_id);
        push_wrapper_state(&mut script, &token_id);
        for value in 1..=6 {
            push_int(&mut script, value);
        }
        push_data(&mut script, &[0x44; 32]);
        push_int(&mut script, 0);
        push_int(&mut script, 5);
        push_data(&mut script, &UNWRAP_TAG);
        push_data(&mut script, &placeholder_script());
        script
    }

    #[test]
    fn current_artifact_and_kcc1_actions_decode() {
        let script = placeholder_script();
        assert_eq!(script.len(), KCC20_WRAPPER_SCRIPT_LEN);
        let decoder =
            Kcc20WrapperDecoder::new(Kcc20WrapperDecoder::fingerprint_of_compiled_script(&script));
        assert!(decoder.matches_reveal_script(&script));
        let constructor = decoder.decode_constructor(&script).unwrap();
        assert_eq!(constructor["reserveOwnerScheme"], 4);
        assert_eq!(
            decoder.decode_action(&action_script(WRAP_TAG)).as_deref(),
            Some("wrap")
        );
        assert_eq!(
            decoder.decode_action(&action_script(UNWRAP_TAG)).as_deref(),
            Some("unwrap")
        );
        assert_eq!(decoder.decode_action(&action_script([0; 4])), None);
    }

    #[test]
    fn dispatch_tags_match_silverscript_v1_artifact() {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-wrapper/KCC20Wrapper.placeholder.json"
        ))
        .unwrap();
        let abi = artifact["abi"].as_array().unwrap();
        let tag_for = |name: &str| {
            abi.iter()
                .find(|entry| entry["name"] == name)
                .and_then(|entry| entry["dispatch_tag"].as_str())
                .map(|tag| hex::decode(tag).unwrap())
                .unwrap()
        };

        assert_eq!(tag_for("wrap"), WRAP_TAG);
        assert_eq!(tag_for("unwrap"), UNWRAP_TAG);
    }

    #[test]
    fn current_wrap_layout_decodes_linkage_and_wrapped_holder_state() {
        let signature_script = current_wrap_script();
        let args = decode_action_args(&signature_script).unwrap().unwrap();
        assert_eq!(args["tokenInputIndex"], "1");
        assert_eq!(args["tokenLockedOutputIndex"], "2");
        assert_eq!(args["orderbookHolderOutputIndex"], "3");
        assert_eq!(args["wrapperOutputIndex"], "4");
        assert_eq!(args["wrappedRecipient"], "44".repeat(32));
        assert_eq!(args["tokenAmount"], "5");
        assert_eq!(
            decode_wrap_token_input_index(&signature_script).unwrap(),
            Some(1)
        );

        let outputs =
            decode_wrap_output_state_values(&signature_script, Some(&[0x11; 32]), &[0x22; 32])
                .unwrap()
                .unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, 3);
        assert_eq!(outputs[0].1["canonicalTokenId"], "11".repeat(32));
        assert_eq!(outputs[0].1["wrapperCovenantId"], "22".repeat(32));
        assert_eq!(outputs[0].1["owner"], "44".repeat(32));
        assert_eq!(outputs[0].1["amount"], "5");
    }

    #[test]
    fn current_unwrap_layout_decodes_linkage() {
        let args = decode_action_args(&current_unwrap_script())
            .unwrap()
            .unwrap();
        assert_eq!(args["wrappedInputIndex"], "1");
        assert_eq!(args["tokenReserveInputIndex"], "2");
        assert_eq!(args["tokenRecipientOutputIndex"], "3");
        assert_eq!(args["tokenReserveChangeOutputIndex"], "4");
        assert_eq!(args["wrappedChangeOutputIndex"], "5");
        assert_eq!(args["wrapperOutputIndex"], "6");
        assert_eq!(args["tokenRecipient"], "44".repeat(32));
        assert_eq!(args["tokenAmount"], "5");
    }
}
