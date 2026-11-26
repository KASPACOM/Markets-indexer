//! Fixed-denomination KCC20 fee-ticket decoder.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, item_bytes_32, item_int, script_items};
use crate::kcc20_standard::{item_tag, owner_scheme_name};
use crate::TemplateDecoder;

pub const KCC20_FEE_TICKET_SCRIPT_LEN: usize = 5240;
const STATE_RANGE: (usize, usize) = (1, 87);
const OWNER_RANGE: (usize, usize) = (2, 34);
const OWNER_SCHEME_RANGE: (usize, usize) = (35, 36);
const MODE_RANGE: (usize, usize) = (37, 45);
const UTILITY_TOKEN_ID_RANGE: (usize, usize) = (46, 78);
const DENOMINATION_RANGE: (usize, usize) = (79, 87);
const CREATE_TAG: [u8; 4] = [0x1f, 0x8e, 0xd3, 0x27];
const CREATE_BATCH_TAG: [u8; 4] = [0x1a, 0xee, 0x4f, 0xd0];
const TRANSFER_TAG: [u8; 4] = [0x1e, 0xae, 0x2a, 0xda];
const BURN_TAG: [u8; 4] = [0xf0, 0xc0, 0x12, 0xc1];
const UPDATE_TAG: [u8; 4] = [0xc2, 0xfd, 0xe0, 0xf7];

pub struct Kcc20FeeTicketDecoder {
    fingerprint: [u8; 32],
    script_len: usize,
}

impl Kcc20FeeTicketDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            fingerprint,
            script_len: KCC20_FEE_TICKET_SCRIPT_LEN,
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

impl TemplateDecoder for Kcc20FeeTicketDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20FeeTicket
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
        decode_action_tag(items.last().and_then(item_tag))
    }
}

/// A deploy claim can open the initial root before its first spend reveals the
/// script. The caller must compare this commitment with the accepted output.
pub fn deploy_root_state_from_claimed_args(claimed: &Value) -> Result<([u8; 32], Value)> {
    let arg = |name: &str| -> Result<String> {
        let value = claimed
            .get("args")
            .and_then(Value::as_array)
            .and_then(|args| args.iter().find(|arg| arg.get("name").and_then(Value::as_str) == Some(name)))
            .and_then(|arg| arg.get("value"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing FeeTicket {name} deploy claim"))?;
        Ok(value.to_owned())
    };
    let owner = arg("stateOwner")?;
    let utility_token_id = arg("utilityTokenId")?;
    let owner_bytes = hex::decode(&owner)?;
    let utility_bytes = hex::decode(&utility_token_id)?;
    if owner_bytes.len() != 32 || utility_bytes.len() != 32 {
        return Err(anyhow!("FeeTicket deploy identifiers must be 32 bytes"));
    }
    let mode: i64 = arg("stateMode")?.parse()?;
    let denomination: i64 = arg("denomination")?.parse()?;
    let owner_scheme = claimed.get("args").and_then(Value::as_array)
        .and_then(|args| args.iter().find(|arg| arg.get("name").and_then(Value::as_str) == Some("stateOwnerScheme")))
        .map(|_| arg("stateOwnerScheme").and_then(|value| value.parse::<u8>().map_err(Into::into)))
        .transpose()?.unwrap_or(0);
    if mode != 1 || denomination <= 0 {
        return Err(anyhow!("FeeTicket deploy claim is not a positive-denomination root"));
    }

    // This is the same pinned artifact and state layout used by the builder.
    let artifact: Value = serde_json::from_str(include_str!(
        "../fixtures/kcc20-fee-ticket/KCC20FeeTicket.placeholder.json"
    ))?;
    let mut script = artifact["script"]
        .as_array()
        .ok_or_else(|| anyhow!("missing pinned FeeTicket script"))?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("invalid pinned FeeTicket script"))?;
    if script.len() != KCC20_FEE_TICKET_SCRIPT_LEN
        || script[1] != 32
        || script[34] != 1
        || script[36] != 8
        || script[45] != 32
        || script[78] != 8
    {
        return Err(anyhow!("unexpected pinned FeeTicket state layout"));
    }
    script[OWNER_RANGE.0..OWNER_RANGE.1].copy_from_slice(&owner_bytes);
    script[OWNER_SCHEME_RANGE.0] = owner_scheme;
    script[MODE_RANGE.0..MODE_RANGE.1].copy_from_slice(&mode.to_le_bytes());
    script[UTILITY_TOKEN_ID_RANGE.0..UTILITY_TOKEN_ID_RANGE.1].copy_from_slice(&utility_bytes);
    script[DENOMINATION_RANGE.0..DENOMINATION_RANGE.1]
        .copy_from_slice(&denomination.to_le_bytes());
    let state = state_value(&reveal_state(&script)?);
    Ok((blake2b_256(&script), state))
}

#[derive(Debug, Clone)]
struct FeeTicketState {
    owner: String,
    owner_scheme: u8,
    mode: i128,
    utility_token_id: String,
    denomination: i128,
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
        CREATE_TAG => Ok(Some(vec![
            output(
                item_int(&items, 2)? as i32,
                hex::encode(item_bytes_32(&items, 4)?),
                item_int(&items, 5)? as u8,
                2,
                input_state.utility_token_id.clone(),
                input_state.denomination,
            ),
            output(
                item_int(&items, 3)? as i32,
                input_state.owner.clone(),
                input_state.owner_scheme,
                1,
                input_state.utility_token_id,
                input_state.denomination,
            ),
        ])),
        CREATE_BATCH_TAG => {
            let first_ticket_output_index = item_int(&items, 2)? as i32;
            let root_output_index = item_int(&items, 3)? as i32;
            let quantity = item_int(&items, 4)?;
            if quantity <= 0 || quantity > 10 {
                return Err(anyhow!("invalid KCC20FeeTicket batch quantity {quantity}"));
            }
            let ticket_owner = hex::encode(item_bytes_32(&items, 5)?);
            let ticket_owner_scheme = item_int(&items, 6)? as u8;
            let mut outputs = Vec::with_capacity(quantity as usize + 1);
            for ordinal in 0..quantity {
                outputs.push(output(
                    first_ticket_output_index + ordinal as i32,
                    ticket_owner.clone(),
                    ticket_owner_scheme,
                    2,
                    input_state.utility_token_id.clone(),
                    input_state.denomination,
                ));
            }
            outputs.push(output(
                root_output_index,
                input_state.owner,
                input_state.owner_scheme,
                1,
                input_state.utility_token_id,
                input_state.denomination,
            ));
            Ok(Some(outputs))
        }
        TRANSFER_TAG => Ok(Some(vec![output(
            item_int(&items, 3)? as i32,
            hex::encode(item_bytes_32(&items, 1)?),
            item_int(&items, 2)? as u8,
            2,
            input_state.utility_token_id,
            input_state.denomination,
        )])),
        BURN_TAG => Ok(Some(Vec::new())),
        UPDATE_TAG => Ok(Some(vec![output(
            item_int(&items, 2)? as i32,
            input_state.owner,
            input_state.owner_scheme,
            1,
            input_state.utility_token_id,
            item_int(&items, 1)?,
        )])),
        _ => Ok(None),
    }
}

pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };

    let args = match tag {
        CREATE_TAG => json!({
            "utilityInputIndex": item_int(&items, 0)?.to_string(),
            "utilityChangeOutputIndex": item_int(&items, 1)?.to_string(),
            "ticketOutputIndex": item_int(&items, 2)?.to_string(),
            "rootOutputIndex": item_int(&items, 3)?.to_string(),
            "ticketOwner": hex::encode(item_bytes_32(&items, 4)?),
            "ticketOwnerScheme": item_int(&items, 5)? as u8,
            "quantity": 1,
        }),
        CREATE_BATCH_TAG => {
            let quantity = item_int(&items, 4)?;
            if quantity <= 0 || quantity > 10 {
                return Err(anyhow!("invalid KCC20FeeTicket batch quantity {quantity}"));
            }
            json!({
                "utilityInputIndex": item_int(&items, 0)?.to_string(),
                "utilityChangeOutputIndex": item_int(&items, 1)?.to_string(),
                "firstTicketOutputIndex": item_int(&items, 2)?.to_string(),
                "rootOutputIndex": item_int(&items, 3)?.to_string(),
                "quantity": quantity,
                "ticketOwner": hex::encode(item_bytes_32(&items, 5)?),
                "ticketOwnerScheme": item_int(&items, 6)? as u8,
            })
        }
        TRANSFER_TAG => {
            let recipient_owner = hex::encode(item_bytes_32(&items, 1)?);
            let recipient_owner_scheme = item_int(&items, 2)? as u8;
            json!({
                "recipientOwner": recipient_owner,
                "toOwner": recipient_owner,
                "recipientOwnerScheme": recipient_owner_scheme,
                "toOwnerScheme": recipient_owner_scheme,
                "ticketOutputIndex": item_int(&items, 3)?.to_string(),
            })
        }
        BURN_TAG => json!({
            "refundOutputIndex": item_int(&items, 1)?.to_string(),
        }),
        UPDATE_TAG => json!({
            "newDenomination": item_int(&items, 1)?.to_string(),
            "rootOutputIndex": item_int(&items, 2)?.to_string(),
        }),
        _ => return Ok(None),
    };
    Ok(Some(args))
}

fn decode_action_tag(tag: Option<[u8; 4]>) -> Option<String> {
    match tag {
        Some(CREATE_TAG) => Some("createFromUtilityBurn".into()),
        Some(CREATE_BATCH_TAG) => Some("createBatchFromUtilityBurn".into()),
        Some(TRANSFER_TAG) => Some("transferByOwnerSig".into()),
        Some(BURN_TAG) => Some("burnByOwnerSig".into()),
        Some(UPDATE_TAG) => Some("updateDenominationByOwnerSig".into()),
        _ => None,
    }
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() != 86 {
        return Err(anyhow!(
            "KCC20FeeTicket state payload too short ({} bytes)",
            payload.len()
        ));
    }
    expect_len(payload, 0, 32, "owner")?;
    expect_len(payload, 33, 1, "ownerScheme")?;
    expect_len(payload, 35, 8, "mode")?;
    expect_len(payload, 44, 32, "utilityTokenId")?;
    expect_len(payload, 77, 8, "denomination")?;

    Ok(state_value(&FeeTicketState {
        owner: hex::encode(&payload[1..33]),
        owner_scheme: payload[34],
        mode: parse_minimal_int(&payload[36..44]),
        utility_token_id: hex::encode(&payload[45..77]),
        denomination: parse_minimal_int(&payload[78..86]),
    }))
}

fn reveal_state(payload: &[u8]) -> Result<FeeTicketState> {
    if payload.len() != KCC20_FEE_TICKET_SCRIPT_LEN {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}",
            payload.len(),
            KCC20_FEE_TICKET_SCRIPT_LEN,
        ));
    }
    Ok(FeeTicketState {
        owner: hex::encode(&payload[OWNER_RANGE.0..OWNER_RANGE.1]),
        owner_scheme: payload[OWNER_SCHEME_RANGE.0],
        mode: parse_minimal_int(&payload[MODE_RANGE.0..MODE_RANGE.1]),
        utility_token_id: hex::encode(&payload[UTILITY_TOKEN_ID_RANGE.0..UTILITY_TOKEN_ID_RANGE.1]),
        denomination: parse_minimal_int(&payload[DENOMINATION_RANGE.0..DENOMINATION_RANGE.1]),
    })
}

fn output(
    output_index: i32,
    owner: String,
    owner_scheme: u8,
    mode: i128,
    utility_token_id: String,
    denomination: i128,
) -> (i32, Value) {
    (
        output_index,
        state_value(&FeeTicketState {
            owner,
            owner_scheme,
            mode,
            utility_token_id,
            denomination,
        }),
    )
}

fn state_value(state: &FeeTicketState) -> Value {
    json!({
        "owner": state.owner,
        "ownerIdentifier": state.owner,
        "stateOwner": state.owner,
        "ownerScheme": state.owner_scheme,
        "ownerSchemeName": owner_scheme_name(state.owner_scheme),
        "mode": state.mode,
        "stateMode": state.mode,
        "modeName": mode_name(state.mode),
        "utilityTokenId": state.utility_token_id,
        "denomination": state.denomination.to_string(),
        "ticketCredits": if state.mode == 2 { "1" } else { "0" },
    })
}

fn mode_name(mode: i128) -> &'static str {
    match mode {
        1 => "root",
        2 => "ticket",
        _ => "unknown",
    }
}

fn expect_len(payload: &[u8], offset: usize, expected: usize, label: &str) -> Result<()> {
    let actual = payload
        .get(offset)
        .copied()
        .ok_or_else(|| anyhow!("missing KCC20FeeTicket {label} push length"))?
        as usize;
    if actual != expected {
        return Err(anyhow!(
            "unexpected KCC20FeeTicket {label} push length {actual}, expected {expected}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod deploy_claim_tests {
    use super::*;

    #[test]
    fn reconstructed_root_matches_accepted_tn10_output() {
        let claim = json!({"args": [
            {"name": "stateOwner", "value": "51fb56d74326e9f92d4866907994cb6442791f71f2a1a2fee0d408f1cdfa28d1"},
            {"name": "stateMode", "value": "1"},
            {"name": "utilityTokenId", "value": "13ebc6ca72e7b0244074f47071de42118f66be00172544eeb1dacdb74c97ef16"},
            {"name": "denomination", "value": "550"}
        ]});
        let (hash, state) = deploy_root_state_from_claimed_args(&claim).unwrap();
        assert_eq!(hex::encode(hash), "1859baf1288eb1c87ccab00bf6374cf08c8eded7a02dd5bbf1ac41258b2d0bc5");
        assert_eq!(state["stateMode"], 1);
        assert_eq!(state["denomination"], "550");
        let mut forged = claim.clone();
        forged["args"][3]["value"] = json!("551");
        assert_ne!(deploy_root_state_from_claimed_args(&forged).unwrap().0, hash);

        let mut alternate_scheme = claim.clone();
        alternate_scheme["args"].as_array_mut().unwrap().push(json!({
            "name": "stateOwnerScheme", "value": "1"
        }));
        let (alternate_hash, alternate_state) = deploy_root_state_from_claimed_args(&alternate_scheme).unwrap();
        assert_ne!(alternate_hash, hash);
        assert_eq!(alternate_state["ownerScheme"], 1);
        alternate_scheme["args"][4]["value"] = json!("256");
        assert!(deploy_root_state_from_claimed_args(&alternate_scheme).is_err());
    }
}

#[cfg(any())]
mod legacy_tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket/KCC20FeeTicket.placeholder.json"
        ))
        .unwrap();
        artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect()
    }

    fn pre_refund_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket/KCC20FeeTicket.pre-refund.placeholder.json"
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

    fn batch_sigscript(script: &[u8], quantity: i64) -> Vec<u8> {
        let mut sigscript = Vec::new();
        push_i64(&mut sigscript, 1);
        push_i64(&mut sigscript, 12);
        push_i64(&mut sigscript, 0);
        push_i64(&mut sigscript, quantity);
        push_i64(&mut sigscript, quantity);
        sigscript.push(32);
        sigscript.extend([0x42; 32]);
        sigscript.push(1);
        sigscript.push(0xaa);
        sigscript.push(1);
        sigscript.push(0xbb);
        sigscript.push(0x51);
        push_script(&mut sigscript, script);
        sigscript
    }

    fn burn_sigscript(script: &[u8], refund_output_index: i64) -> Vec<u8> {
        let mut sigscript = Vec::new();
        sigscript.push(65);
        sigscript.extend([0x11; 65]);
        push_i64(&mut sigscript, refund_output_index);
        sigscript.push(0x53);
        push_script(&mut sigscript, script);
        sigscript
    }

    #[test]
    fn matches_placeholder_and_decodes_actions() {
        let script = placeholder_script();
        let decoder = Kcc20FeeTicketDecoder::new(
            Kcc20FeeTicketDecoder::fingerprint_of_compiled_script(&script),
        );
        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(decoder.template(), KnownTemplate::Kcc20FeeTicket);
        let state = decoder.decode_constructor(&script).unwrap();
        assert_eq!(state["modeName"], "root");
        assert_eq!(state["denomination"], "100");
        assert_eq!(
            decoder.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("createBatchFromUtilityBurn")
        );
        assert_eq!(
            decoder.decode_action(&[0x52, 0x01, 0xaa]).as_deref(),
            Some("transferByOwnerSig")
        );
        assert_eq!(
            decoder.decode_action(&[0x53, 0x01, 0xaa]).as_deref(),
            Some("burnByOwnerSig")
        );
        assert_eq!(
            decoder.decode_action(&[0x54, 0x01, 0xaa]).as_deref(),
            Some("updateDenominationByOwnerSig")
        );
    }

    #[test]
    fn decodes_pre_batch_action_selectors() {
        let decoder = Kcc20FeeTicketDecoder::with_script_len(
            [0u8; 32],
            KCC20_FEE_TICKET_PRE_BATCH_SCRIPT_LEN,
        );

        assert_eq!(
            decoder.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("transferByOwnerSig")
        );
        assert_eq!(
            decoder.decode_action(&[0x52, 0x01, 0xaa]).as_deref(),
            Some("burnByOwnerSig")
        );
        assert_eq!(
            decoder.decode_action(&[0x53, 0x01, 0xaa]).as_deref(),
            Some("updateDenominationByOwnerSig")
        );
        assert_eq!(decoder.decode_action(&[0x54, 0x01, 0xaa]), None);
    }

    #[test]
    fn decodes_pre_refund_batch_action_selectors() {
        let script = pre_refund_script();
        let decoder = Kcc20FeeTicketDecoder::with_script_len(
            Kcc20FeeTicketDecoder::fingerprint_of_compiled_script(&script),
            KCC20_FEE_TICKET_PRE_REFUND_SCRIPT_LEN,
        );

        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(
            decoder.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("createBatchFromUtilityBurn")
        );
        assert_eq!(
            decoder.decode_action(&[0x53, 0x01, 0xaa]).as_deref(),
            Some("burnByOwnerSig")
        );
    }

    #[test]
    fn decodes_every_supported_batch_size_and_rejects_out_of_range_quantities() {
        let script = placeholder_script();
        for quantity in 1..=10 {
            let outputs = decode_output_state_values(&batch_sigscript(&script, quantity), &script)
                .unwrap()
                .unwrap();
            assert_eq!(outputs.len(), quantity as usize + 1);
            assert_eq!(outputs[0].0, 0);
            assert_eq!(outputs[quantity as usize - 1].0, quantity as i32 - 1);
            assert_eq!(outputs[quantity as usize].0, quantity as i32);
            assert_eq!(outputs[0].1["modeName"], "ticket");
            assert_eq!(outputs[quantity as usize].1["modeName"], "root");
        }

        for quantity in [0, 11] {
            let error = decode_output_state_values(&batch_sigscript(&script, quantity), &script)
                .unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("invalid KCC20FeeTicket batch quantity {quantity}")));
        }
    }

    #[test]
    fn burn_with_refund_output_index_has_no_fee_ticket_state_outputs() {
        let script = placeholder_script();
        let outputs = decode_output_state_values(&burn_sigscript(&script, 2), &script)
            .unwrap()
            .unwrap();

        assert!(outputs.is_empty());
    }
}

#[cfg(test)]
mod current_tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-ticket/KCC20FeeTicket.placeholder.json"
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

    fn transfer_script(recipient: [u8; 32], output_index: i64) -> Vec<u8> {
        let mut script = vec![65];
        script.extend([0x11; 65]);
        script.push(32);
        script.extend(recipient);
        script.extend([1, 0]);
        push_i64(&mut script, output_index);
        script.push(4);
        script.extend(TRANSFER_TAG);
        script.extend([1, 0xaa]);
        script
    }

    fn batch_script(ticket_owner: [u8; 32], quantity: i64) -> Vec<u8> {
        let mut script = Vec::new();
        for value in [1, 12, 0, 10, quantity] {
            push_i64(&mut script, value);
        }
        script.push(32);
        script.extend(ticket_owner);
        script.extend([1, 0]);
        script.push(4);
        script.extend(CREATE_BATCH_TAG);
        script.extend([1, 0xaa]);
        script
    }

    #[test]
    fn current_artifact_and_kcc1_actions_decode() {
        let script = placeholder_script();
        assert_eq!(script.len(), KCC20_FEE_TICKET_SCRIPT_LEN);
        let decoder = Kcc20FeeTicketDecoder::new(
            Kcc20FeeTicketDecoder::fingerprint_of_compiled_script(&script),
        );
        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(
            decoder.decode_constructor(&script).unwrap()["ownerScheme"],
            0
        );

        for (tag, name) in [
            (CREATE_TAG, "createFromUtilityBurn"),
            (CREATE_BATCH_TAG, "createBatchFromUtilityBurn"),
            (TRANSFER_TAG, "transferByOwnerSig"),
            (BURN_TAG, "burnByOwnerSig"),
            (UPDATE_TAG, "updateDenominationByOwnerSig"),
        ] {
            assert_eq!(
                decoder.decode_action(&action_script(tag)).as_deref(),
                Some(name)
            );
        }
        assert_eq!(decoder.decode_action(&action_script([0; 4])), None);
    }

    #[test]
    fn current_transfer_action_args_include_recipient_and_output() {
        let recipient = [0x22; 32];
        let args = decode_action_args(&transfer_script(recipient, 3))
            .unwrap()
            .unwrap();

        assert_eq!(args["recipientOwner"], hex::encode(recipient));
        assert_eq!(args["toOwner"], hex::encode(recipient));
        assert_eq!(args["recipientOwnerScheme"], 0);
        assert_eq!(args["ticketOutputIndex"], "3");
    }

    #[test]
    fn current_batch_action_args_include_owner_count_and_outputs() {
        let ticket_owner = [0x33; 32];
        let args = decode_action_args(&batch_script(ticket_owner, 2))
            .unwrap()
            .unwrap();

        assert_eq!(args["ticketOwner"], hex::encode(ticket_owner));
        assert_eq!(args["ticketOwnerScheme"], 0);
        assert_eq!(args["firstTicketOutputIndex"], "0");
        assert_eq!(args["rootOutputIndex"], "10");
        assert_eq!(args["quantity"], 2);

        for quantity in [0, 11] {
            let error = decode_action_args(&batch_script(ticket_owner, quantity)).unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("invalid KCC20FeeTicket batch quantity {quantity}")));
        }
    }
}
