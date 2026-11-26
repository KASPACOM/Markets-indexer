//! KCC20 vesting covenant decoder.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, item_int, script_items};
use crate::kcc20_standard::{item_tag, owner_scheme_name};
use crate::TemplateDecoder;

pub const KCC20_VESTING_SCRIPT_LEN: usize = 1348;
const STATE_RANGE: (usize, usize) = (1, 78);
const CANONICAL_TOKEN_ID_RANGE: (usize, usize) = (2, 34);
const BENEFICIARY_RANGE: (usize, usize) = (35, 67);
const BENEFICIARY_TYPE_RANGE: (usize, usize) = (68, 69);
const UNLOCK_TIME_RANGE: (usize, usize) = (70, 78);
const RELEASE_TAG: [u8; 4] = [0xf4, 0xd0, 0xa8, 0x71];

pub struct Kcc20VestingDecoder {
    fingerprint: [u8; 32],
    script_len: usize,
}

impl Kcc20VestingDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            fingerprint,
            script_len: KCC20_VESTING_SCRIPT_LEN,
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
        if STATE_RANGE.1 <= masked.len() {
            for b in masked[STATE_RANGE.0..STATE_RANGE.1].iter_mut() {
                *b = 0;
            }
        }
        blake2b_256(&masked)
    }
}

impl TemplateDecoder for Kcc20VestingDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20Vesting
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        reveal.len() == self.script_len
            && Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        Ok(state_value(&reveal_state(payload)?))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        decode_state_payload(payload)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let items = script_items(args_prefix_before_reveal(signature_script));
        match items.last().and_then(item_tag) {
            Some(RELEASE_TAG) => Some("release".into()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct VestingState {
    canonical_token_id: String,
    beneficiary: String,
    beneficiary_type: i128,
    unlock_time_ms: i128,
}

pub fn decode_reveal_state_value(payload: &[u8]) -> Result<Value> {
    Ok(state_value(&reveal_state(payload)?))
}

pub fn decode_output_state_values(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Vec<(i32, Value)>>> {
    let input_state = reveal_state(reveal_script)?;
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };

    match tag {
        RELEASE_TAG => {
            let vesting_output_index = item_int(&items, 3)?;
            if vesting_output_index < 0 {
                return Ok(Some(Vec::new()));
            }
            Ok(Some(vec![(
                vesting_output_index as i32,
                state_value(&input_state),
            )]))
        }
        _ => Ok(None),
    }
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() != 77 {
        return Err(anyhow!(
            "KCC20Vesting state payload too short ({} bytes)",
            payload.len()
        ));
    }
    expect_len(payload, 0, 32, "canonicalTokenId")?;
    expect_len(payload, 33, 32, "beneficiary")?;
    expect_len(payload, 66, 1, "beneficiaryScheme")?;
    expect_len(payload, 68, 8, "unlockTimeMs")?;

    Ok(state_value(&VestingState {
        canonical_token_id: hex::encode(&payload[1..33]),
        beneficiary: hex::encode(&payload[34..66]),
        beneficiary_type: payload[67] as i128,
        unlock_time_ms: parse_minimal_int(&payload[69..77]),
    }))
}

fn reveal_state(payload: &[u8]) -> Result<VestingState> {
    if payload.len() != KCC20_VESTING_SCRIPT_LEN {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}",
            payload.len(),
            KCC20_VESTING_SCRIPT_LEN
        ));
    }
    Ok(VestingState {
        canonical_token_id: hex::encode(
            &payload[CANONICAL_TOKEN_ID_RANGE.0..CANONICAL_TOKEN_ID_RANGE.1],
        ),
        beneficiary: hex::encode(&payload[BENEFICIARY_RANGE.0..BENEFICIARY_RANGE.1]),
        beneficiary_type: payload[BENEFICIARY_TYPE_RANGE.0] as i128,
        unlock_time_ms: parse_minimal_int(&payload[UNLOCK_TIME_RANGE.0..UNLOCK_TIME_RANGE.1]),
    })
}

fn state_value(state: &VestingState) -> Value {
    json!({
        "canonicalTokenId": state.canonical_token_id,
        "beneficiary": state.beneficiary,
        "beneficiaryScheme": state.beneficiary_type,
        "beneficiarySchemeName": owner_scheme_name(state.beneficiary_type as u8),
        "unlockTimeMs": state.unlock_time_ms.to_string(),
        "stateOwner": state.beneficiary,
        "stateOwnerType": state.beneficiary_type,
        "modeName": "vesting",
    })
}

fn expect_len(payload: &[u8], offset: usize, expected: usize, label: &str) -> Result<()> {
    let actual = payload
        .get(offset)
        .copied()
        .ok_or_else(|| anyhow!("missing KCC20Vesting {label} push length"))?
        as usize;
    if actual != expected {
        return Err(anyhow!(
            "unexpected KCC20Vesting {label} push length {actual}, expected {expected}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod current_tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-vesting/KCC20Vesting.placeholder.json"
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
    fn current_artifact_and_release_tag_decode() {
        let script = placeholder_script();
        assert_eq!(script.len(), KCC20_VESTING_SCRIPT_LEN);
        let decoder =
            Kcc20VestingDecoder::new(Kcc20VestingDecoder::fingerprint_of_compiled_script(&script));
        assert!(decoder.matches_reveal_script(&script));
        let state = decoder.decode_constructor(&script).unwrap();
        assert_eq!(state["beneficiaryScheme"], 0);
        let mut action = vec![4];
        action.extend(RELEASE_TAG);
        action.extend([1, 0xaa]);
        assert_eq!(decoder.decode_action(&action).as_deref(), Some("release"));
    }
}
