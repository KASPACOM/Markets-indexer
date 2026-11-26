//! Native KAS FOMO time-vault round decoder.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, item_bytes_32, item_int, script_items};
use crate::TemplateDecoder;

pub const KASPA_FOMO_ROUND_SCRIPT_LEN: usize = 1042;
const STATE_RANGE: (usize, usize) = (1, 52);
const LAST_BUYER_RANGE: (usize, usize) = (2, 34);
const END_TIME_RANGE: (usize, usize) = (35, 43);
const TICKET_COUNT_RANGE: (usize, usize) = (44, 52);
const ROUND_SIGNER_RANGE_A: (usize, usize) = (157, 189);
const ROUND_SIGNER_RANGE_B: (usize, usize) = (465, 497);
const MARKETING_RECIPIENT_RANGE: (usize, usize) = (642, 674);
const PLATFORM_RECIPIENT_RANGE: (usize, usize) = (708, 740);

pub struct KaspaFomoRoundDecoder {
    fingerprint: [u8; 32],
}

impl KaspaFomoRoundDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }

    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        let mut masked = script.to_vec();
        for (start, end) in [
            STATE_RANGE,
            ROUND_SIGNER_RANGE_A,
            ROUND_SIGNER_RANGE_B,
            MARKETING_RECIPIENT_RANGE,
            PLATFORM_RECIPIENT_RANGE,
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

impl TemplateDecoder for KaspaFomoRoundDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::KaspaFomoRound
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        reveal.len() == KASPA_FOMO_ROUND_SCRIPT_LEN
            && Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        self.decode_state(payload)
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        decode_state_payload(payload)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        let selector = script_items(prefix).last().and_then(|i| i.as_int())?;
        match selector {
            0 => Some("buy".into()),
            1 => Some("settle".into()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct FomoRoundState {
    last_buyer: String,
    end_time_ms: i128,
    ticket_count: i128,
}

pub fn decode_reveal_state_value(payload: &[u8]) -> Result<Value> {
    Ok(state_value(&reveal_state(payload)?))
}

pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(|i| i.as_int()) else {
        return Ok(None);
    };

    match selector {
        0 => Ok(Some(json!({
            "action": "buy",
            "buyer": hex::encode(item_bytes_32(&items, 2)?),
            "proposedEndTimeMs": item_int(&items, 3)?.to_string(),
            "roundOutputIndex": item_int(&items, 4)?.to_string(),
        }))),
        1 => Ok(Some(json!({
            "action": "settle",
            "settlementFeeSompi": item_int(&items, 1)?.to_string(),
            "randomRecipients": [
                hex::encode(item_bytes_32(&items, 2)?),
                hex::encode(item_bytes_32(&items, 3)?),
                hex::encode(item_bytes_32(&items, 4)?),
                hex::encode(item_bytes_32(&items, 5)?),
                hex::encode(item_bytes_32(&items, 6)?),
                hex::encode(item_bytes_32(&items, 7)?),
            ],
        }))),
        _ => Ok(None),
    }
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
            let buyer = hex::encode(item_bytes_32(&items, 2)?);
            let proposed_end_time_ms = item_int(&items, 3)?;
            let round_output_index = item_int(&items, 4)?;
            if !(0..=i32::MAX as i128).contains(&round_output_index) {
                return Err(anyhow!(
                    "KaspaFomoRound output index {round_output_index} is out of range"
                ));
            }
            Ok(Some(vec![(
                round_output_index as i32,
                state_value(&FomoRoundState {
                    last_buyer: buyer,
                    end_time_ms: proposed_end_time_ms,
                    ticket_count: input_state.ticket_count + 1,
                }),
            )]))
        }
        1 => Ok(Some(Vec::new())),
        _ => Ok(None),
    }
}

pub fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() != KASPA_FOMO_ROUND_SCRIPT_LEN {
        return Err(anyhow!(
            "unexpected KaspaFomoRound script length {}, expected {}",
            payload.len(),
            KASPA_FOMO_ROUND_SCRIPT_LEN
        ));
    }
    if payload.get(STATE_RANGE.0).copied() != Some(32) {
        return Err(anyhow!("unexpected KaspaFomoRound lastBuyer push length"));
    }
    if payload.get(END_TIME_RANGE.0 - 1).copied() != Some(8) {
        return Err(anyhow!("unexpected KaspaFomoRound endTimeMs push length"));
    }
    if payload.get(TICKET_COUNT_RANGE.0 - 1).copied() != Some(8) {
        return Err(anyhow!("unexpected KaspaFomoRound ticketCount push length"));
    }
    Ok(state_value(&FomoRoundState {
        last_buyer: hex::encode(&payload[LAST_BUYER_RANGE.0..LAST_BUYER_RANGE.1]),
        end_time_ms: parse_minimal_int(&payload[END_TIME_RANGE.0..END_TIME_RANGE.1]),
        ticket_count: parse_minimal_int(&payload[TICKET_COUNT_RANGE.0..TICKET_COUNT_RANGE.1]),
    }))
}

fn reveal_state(payload: &[u8]) -> Result<FomoRoundState> {
    if payload.len() != KASPA_FOMO_ROUND_SCRIPT_LEN {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}",
            payload.len(),
            KASPA_FOMO_ROUND_SCRIPT_LEN
        ));
    }
    Ok(FomoRoundState {
        last_buyer: hex::encode(&payload[LAST_BUYER_RANGE.0..LAST_BUYER_RANGE.1]),
        end_time_ms: parse_minimal_int(&payload[END_TIME_RANGE.0..END_TIME_RANGE.1]),
        ticket_count: parse_minimal_int(&payload[TICKET_COUNT_RANGE.0..TICKET_COUNT_RANGE.1]),
    })
}

fn state_value(state: &FomoRoundState) -> Value {
    json!({
        "lastBuyer": state.last_buyer,
        "stateOwner": state.last_buyer,
        "endTimeMs": state.end_time_ms.to_string(),
        "ticketCount": state.ticket_count.to_string(),
        "modeName": "activeRound",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kaspa-fomo-round/KaspaFomoRound.placeholder.json"
        ))
        .unwrap();
        artifact
            .get("script")
            .or_else(|| artifact.get("bytecode"))
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect()
    }

    #[test]
    fn matches_placeholder_and_decodes_state_actions() {
        let script = placeholder_script();
        let decoder = KaspaFomoRoundDecoder::new(
            KaspaFomoRoundDecoder::fingerprint_of_compiled_script(&script),
        );

        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(decoder.name(), "KaspaFomoRound");
        assert_eq!(decoder.template(), KnownTemplate::KaspaFomoRound);

        let state = decoder.decode_state(&script).unwrap();
        assert_eq!(state["lastBuyer"], "11".repeat(32));
        assert_eq!(state["endTimeMs"], "500000000001");
        assert_eq!(state["ticketCount"], "0");

        assert_eq!(
            decoder.decode_action(&[0x00, 0x01, 0xaa]).as_deref(),
            Some("buy")
        );
        assert_eq!(
            decoder.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("settle")
        );
        assert_eq!(decoder.decode_action(&[0x52, 0x01, 0xaa]), None);
    }

    #[test]
    fn patched_state_still_matches_template() {
        let mut script = placeholder_script();
        script[LAST_BUYER_RANGE.0..LAST_BUYER_RANGE.1].fill(0x99);
        script[END_TIME_RANGE.0..END_TIME_RANGE.1]
            .copy_from_slice(&600_000_000_001_i64.to_le_bytes());
        script[TICKET_COUNT_RANGE.0..TICKET_COUNT_RANGE.1].copy_from_slice(&7_i64.to_le_bytes());

        let decoder = KaspaFomoRoundDecoder::new(
            KaspaFomoRoundDecoder::fingerprint_of_compiled_script(&placeholder_script()),
        );

        assert!(decoder.matches_reveal_script(&script));
        let state = decoder.decode_state(&script).unwrap();
        assert_eq!(state["lastBuyer"], "99".repeat(32));
        assert_eq!(state["endTimeMs"], "600000000001");
        assert_eq!(state["ticketCount"], "7");
    }

    #[test]
    fn patched_recipients_and_signer_still_match_template() {
        let mut script = placeholder_script();
        script[ROUND_SIGNER_RANGE_A.0..ROUND_SIGNER_RANGE_A.1].fill(0xdd);
        script[ROUND_SIGNER_RANGE_B.0..ROUND_SIGNER_RANGE_B.1].fill(0xdd);
        script[MARKETING_RECIPIENT_RANGE.0..MARKETING_RECIPIENT_RANGE.1].fill(0xbb);
        script[PLATFORM_RECIPIENT_RANGE.0..PLATFORM_RECIPIENT_RANGE.1].fill(0xcc);

        let decoder = KaspaFomoRoundDecoder::new(
            KaspaFomoRoundDecoder::fingerprint_of_compiled_script(&placeholder_script()),
        );

        assert!(decoder.matches_reveal_script(&script));
    }

    #[test]
    fn decodes_buy_output_state() {
        let script = placeholder_script();
        let buyer = vec![0xab; 32];
        let mut sigscript = Vec::new();
        sigscript.extend_from_slice(&[64]);
        sigscript.extend_from_slice(&[0x01; 64]);
        sigscript.extend_from_slice(&[64]);
        sigscript.extend_from_slice(&[0x02; 64]);
        sigscript.push(32);
        sigscript.extend_from_slice(&buyer);
        sigscript.push(8);
        sigscript.extend_from_slice(&600_000_000_001_i64.to_le_bytes());
        sigscript.push(0x00);
        sigscript.push(0x00);
        sigscript.push(77);
        sigscript.extend_from_slice(&(script.len() as u16).to_le_bytes());
        sigscript.extend_from_slice(&script);

        let outputs = decode_output_state_values(&sigscript, &script)
            .unwrap()
            .unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].0, 0);
        assert_eq!(outputs[0].1["lastBuyer"], "ab".repeat(32));
        assert_eq!(outputs[0].1["endTimeMs"], "600000000001");
        assert_eq!(outputs[0].1["ticketCount"], "1");

        let args = decode_action_args(&sigscript).unwrap().unwrap();
        assert_eq!(args["action"], "buy");
        assert_eq!(args["buyer"], "ab".repeat(32));
        assert_eq!(args["proposedEndTimeMs"], "600000000001");
        assert_eq!(args["roundOutputIndex"], "0");
    }

    #[test]
    fn decodes_settle_action_args() {
        let script = placeholder_script();
        let mut sigscript = Vec::new();
        sigscript.push(64);
        sigscript.extend_from_slice(&[0x01; 64]);
        sigscript.push(8);
        sigscript.extend_from_slice(&3_000_000_i64.to_le_bytes());
        for byte in 0xa0..=0xa5 {
            sigscript.push(32);
            sigscript.extend_from_slice(&[byte; 32]);
        }
        sigscript.push(0x51);
        sigscript.push(77);
        sigscript.extend_from_slice(&(script.len() as u16).to_le_bytes());
        sigscript.extend_from_slice(&script);

        let args = decode_action_args(&sigscript).unwrap().unwrap();
        assert_eq!(args["action"], "settle");
        assert_eq!(args["settlementFeeSompi"], "3000000");
        assert_eq!(args["randomRecipients"].as_array().unwrap().len(), 6);
        assert_eq!(args["randomRecipients"][0], "a0".repeat(32));
        assert_eq!(args["randomRecipients"][5], "a5".repeat(32));
    }
}
