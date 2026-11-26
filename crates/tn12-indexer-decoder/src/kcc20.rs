//! KCC20 decoder.
//!
//! Source: KASPACOM KCC20 v1 manual transfer contract.
//!
//! ```silverscript
//! contract KCC20(byte[32] genesisPk, int genesisIdentifierType, int genesisAmount,
//!                bool genesisIsMinter) {
//!   byte[32] ownerIdentifier = genesisPk;
//!   int      identifierType   = genesisIdentifierType;
//!   int      amount           = genesisAmount;
//!   bool     isMinter         = genesisIsMinter;
//!
//!   entrypoint function transferBySig(...) { ... }
//!   entrypoint function transferAllBySig(...) { ... }
//!   entrypoint function transferByScriptHash(...) { ... }
//!   entrypoint function transferAllByScriptHash(...) { ... }
//!   entrypoint function transferByCovenant(...) { ... }
//!   entrypoint function transferAllByCovenant(...) { ... }
//! }
//! ```
//!
//! State layout per UTXO (on-chain order):
//!   1. `ownerIdentifier` — byte[32]
//!   2. `identifierType`  — i64 (0=pubkey, 1=script_hash, 2=covenant_id)
//!   3. `amount`          — i64 token amount (NOT sompi)
//!   4. `isMinter`        — bool (0x00 / 0x01)
//!
//! Public entrypoints: pubkey-owner, script-hash-owner, and covenant-owner
//! partial/full transfer.

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, read_push, KnownTemplate};

use crate::TemplateDecoder;

pub const IDENTIFIER_PUBKEY: u8 = 0x00;
pub const IDENTIFIER_SCRIPT_HASH: u8 = 0x01;
pub const IDENTIFIER_COVENANT_ID: u8 = 0x02;

pub const KCC20_SCRIPT_LEN: usize = 1089;
const GENESIS_PK_RANGE: (usize, usize) = (2, 34);
const GENESIS_IDENTIFIER_TYPE_RANGE: (usize, usize) = (35, 43);
const GENESIS_AMOUNT_RANGE: (usize, usize) = (44, 52);
const GENESIS_IS_MINTER_RANGE: (usize, usize) = (52, 54);
const GENESIS_IDENTIFIER_TYPE_PUSH_LEN_OFFSET: usize = 34;
const GENESIS_AMOUNT_PUSH_LEN_OFFSET: usize = 43;

pub struct Kcc20Decoder {
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20State {
    pub owner_identifier: String,
    pub identifier_type: u8,
    pub identifier_type_name: &'static str,
    pub amount: String,
    pub is_minter: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20OutputState {
    pub output_index: i32,
    pub state: Kcc20State,
}

impl Kcc20Decoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self { fingerprint }
    }

    /// Compute a stable template fingerprint for the vendored KCC20 artifact.
    /// KCC20 UTXO state is embedded directly in the redeem script, so every
    /// transfer output can have a different owner, identifier type, amount, and
    /// minter flag. All state-bearing constructor slots are masked; covenant
    /// shape parameters stay fixed to the vendored artifact.
    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        let mut masked = script.to_vec();
        for (start, end) in [
            GENESIS_PK_RANGE,
            GENESIS_IDENTIFIER_TYPE_RANGE,
            GENESIS_AMOUNT_RANGE,
            GENESIS_IS_MINTER_RANGE,
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

impl TemplateDecoder for Kcc20Decoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        reveal.len() == KCC20_SCRIPT_LEN
            && Self::fingerprint_of_compiled_script(reveal) == self.fingerprint
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        if payload.len() != KCC20_SCRIPT_LEN {
            return Err(anyhow!(
                "reveal script is {} bytes, expected {}",
                payload.len(),
                KCC20_SCRIPT_LEN
            ));
        }

        let genesis_pk = &payload[GENESIS_PK_RANGE.0..GENESIS_PK_RANGE.1];
        let identifier_len = payload[GENESIS_IDENTIFIER_TYPE_PUSH_LEN_OFFSET] as usize;
        if identifier_len != GENESIS_IDENTIFIER_TYPE_RANGE.1 - GENESIS_IDENTIFIER_TYPE_RANGE.0 {
            return Err(anyhow!(
                "unexpected KCC20 genesisIdentifierType push length {identifier_len}"
            ));
        }
        let identifier_bytes =
            &payload[GENESIS_IDENTIFIER_TYPE_RANGE.0..GENESIS_IDENTIFIER_TYPE_RANGE.1];
        let amount_len = payload[GENESIS_AMOUNT_PUSH_LEN_OFFSET] as usize;
        if amount_len != GENESIS_AMOUNT_RANGE.1 - GENESIS_AMOUNT_RANGE.0 {
            return Err(anyhow!(
                "unexpected KCC20 genesisAmount push length {amount_len}"
            ));
        }
        let genesis_amount_bytes = &payload[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1];
        let is_minter_push = &payload[GENESIS_IS_MINTER_RANGE.0..GENESIS_IS_MINTER_RANGE.1];

        Ok(json!({
            "genesisPk": hex::encode(genesis_pk),
            "genesisIdentifierType": parse_minimal_int(identifier_bytes),
            "genesisAmount": parse_minimal_int(genesis_amount_bytes),
            "genesisIsMinter": decode_small_push(is_minter_push) != 0,
        }))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        // State layout as encoded in the redeem script:
        // OP_DATA_32 owner | OP_DATA_8 identifierType | OP_DATA_8 amount | OP_DATA_1 isMinter.
        if payload.len() < 32 + 1 + 8 + 1 + 8 + 1 + 1 {
            return Err(anyhow!(
                "KCC20 state payload too short ({} bytes)",
                payload.len()
            ));
        }
        if payload[0] != 32 {
            return Err(anyhow!("unexpected KCC20 ownerIdentifier push length"));
        }
        let owner = &payload[1..33];
        if payload[33] != 8 {
            return Err(anyhow!("unexpected KCC20 identifierType push length"));
        }
        let identifier_type = parse_minimal_int(&payload[34..42]) as u8;
        if payload[42] != 8 {
            return Err(anyhow!("unexpected KCC20 amount push length"));
        }
        let amount_bytes = &payload[43..51];
        if payload[51] != 1 {
            return Err(anyhow!("unexpected KCC20 isMinter push length"));
        }
        let is_minter = payload[52];

        Ok(json!({
            "ownerIdentifier": hex::encode(owner),
            "identifierType": identifier_type,
            "identifierTypeName": identifier_type_name(identifier_type),
            "amount": parse_minimal_int(amount_bytes).to_string(),
            "isMinter": is_minter != 0,
        }))
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        match prefix.last().copied() {
            Some(0x00) => Some("transferBySig".into()),
            Some(0x51) => Some("transferAllBySig".into()),
            Some(0x52) => Some("transferByScriptHash".into()),
            Some(0x53) => Some("transferAllByScriptHash".into()),
            Some(0x54) => Some("transferByCovenant".into()),
            Some(0x55) => Some("transferAllByCovenant".into()),
            _ => Some("transfer".into()),
        }
    }
}

pub fn decode_reveal_state(payload: &[u8]) -> Result<Kcc20State> {
    if payload.len() != KCC20_SCRIPT_LEN {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}",
            payload.len(),
            KCC20_SCRIPT_LEN
        ));
    }

    let owner = &payload[GENESIS_PK_RANGE.0..GENESIS_PK_RANGE.1];
    let identifier_type = parse_minimal_int(
        &payload[GENESIS_IDENTIFIER_TYPE_RANGE.0..GENESIS_IDENTIFIER_TYPE_RANGE.1],
    ) as u8;
    let amount = parse_minimal_int(&payload[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1]);
    let is_minter =
        decode_small_push(&payload[GENESIS_IS_MINTER_RANGE.0..GENESIS_IS_MINTER_RANGE.1]) != 0;

    Ok(Kcc20State {
        owner_identifier: hex::encode(owner),
        identifier_type,
        identifier_type_name: identifier_type_name(identifier_type),
        amount: amount.to_string(),
        is_minter,
    })
}

pub fn decode_transfer_output_states(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Vec<Kcc20OutputState>>> {
    let input_state = decode_reveal_state(reveal_script)?;
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(ScriptItem::as_int) else {
        return Ok(None);
    };

    let (to_owner_idx, to_type_idx, amount_idx, to_output_idx, change_output_idx) = match selector {
        0 | 2 | 4 => (1, 2, Some(3), 4, Some(5)),
        1 | 3 | 5 => (1, 2, None, 3, None),
        _ => return Ok(None),
    };

    let to_owner = item_bytes_32(&items, to_owner_idx)?;
    let to_identifier_type = item_int(&items, to_type_idx)? as u8;
    let to_amount = if let Some(idx) = amount_idx {
        item_int(&items, idx)?
    } else {
        input_state
            .amount
            .parse::<i128>()
            .map_err(|e| anyhow!("invalid KCC20 input amount: {e}"))?
    };
    let to_output_index = item_int(&items, to_output_idx)? as i32;

    let mut out = vec![Kcc20OutputState {
        output_index: to_output_index,
        state: Kcc20State {
            owner_identifier: hex::encode(to_owner),
            identifier_type: to_identifier_type,
            identifier_type_name: identifier_type_name(to_identifier_type),
            amount: to_amount.to_string(),
            is_minter: false,
        },
    }];

    if let Some(idx) = change_output_idx {
        let input_amount = input_state
            .amount
            .parse::<i128>()
            .map_err(|e| anyhow!("invalid KCC20 input amount: {e}"))?;
        let change_amount = input_amount - to_amount;
        let change_output_index = item_int(&items, idx)? as i32;
        out.push(Kcc20OutputState {
            output_index: change_output_index,
            state: Kcc20State {
                owner_identifier: input_state.owner_identifier,
                identifier_type: input_state.identifier_type,
                identifier_type_name: identifier_type_name(input_state.identifier_type),
                amount: change_amount.to_string(),
                is_minter: false,
            },
        });
    }

    Ok(Some(out))
}

pub fn args_prefix_before_reveal(script: &[u8]) -> &[u8] {
    let mut cursor = script;
    let mut offset = 0usize;
    let mut last_push_start = None;
    while !cursor.is_empty() {
        if let Some((_data, rest)) = read_push(cursor) {
            last_push_start = Some(offset);
            let consumed = cursor.len() - rest.len();
            offset += consumed;
            cursor = rest;
        } else {
            offset += 1;
            cursor = &cursor[1..];
        }
    }
    &script[..last_push_start.unwrap_or(script.len())]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptItem {
    Data(Vec<u8>),
    Int(i128),
}

impl ScriptItem {
    pub fn as_int(&self) -> Option<i128> {
        match self {
            ScriptItem::Data(bytes) if bytes.len() <= 8 => Some(parse_minimal_int(bytes)),
            ScriptItem::Int(value) => Some(*value),
            _ => None,
        }
    }
}

pub fn script_items(mut script: &[u8]) -> Vec<ScriptItem> {
    let mut out = Vec::new();
    while !script.is_empty() {
        let op = script[0];
        if let Some((data, rest)) = read_push(script) {
            out.push(ScriptItem::Data(data.to_vec()));
            script = rest;
            continue;
        }
        match op {
            0x00 => out.push(ScriptItem::Int(0)),
            0x4f => out.push(ScriptItem::Int(-1)),
            0x51..=0x60 => out.push(ScriptItem::Int((op - 0x50) as i128)),
            _ => {}
        }
        script = &script[1..];
    }
    out
}

pub fn item_bytes_32(items: &[ScriptItem], index: usize) -> Result<Vec<u8>> {
    match items.get(index) {
        Some(ScriptItem::Data(bytes)) if bytes.len() == 32 => Ok(bytes.clone()),
        _ => Err(anyhow!(
            "KCC20 sigscript item {index} is not a 32-byte owner"
        )),
    }
}

/// Parse and narrow a witness integer without conflating output/identity checks.
pub fn item_integer<T>(items: &[ScriptItem], index: usize) -> Result<T>
where
    T: TryFrom<i128>,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    crate::interpretation("witness_integer", T::try_from(item_int(items, index)?).map_err(anyhow::Error::from))
}

pub fn item_int(items: &[ScriptItem], index: usize) -> Result<i128> {
    crate::interpretation("kcc20.rs:item_int", (|| {
    items
        .get(index)
        .and_then(ScriptItem::as_int)
        .ok_or_else(|| anyhow!("KCC20 sigscript item {index} is not an int"))

    })())
}

fn decode_small_push(bytes: &[u8]) -> u8 {
    match bytes {
        [0x01, value] => *value,
        [0x51, ..] => 1,
        [0x52, ..] => 2,
        [value, ..] if *value <= 16 => *value,
        _ => 0,
    }
}

pub fn identifier_type_name(t: u8) -> &'static str {
    match t {
        IDENTIFIER_PUBKEY => "pubkey",
        IDENTIFIER_SCRIPT_HASH => "scriptHash",
        IDENTIFIER_COVENANT_ID => "covenantId",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn build_state(owner: &[u8; 32], id_type: u8, amount_le: &[u8], is_minter: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(32);
        v.extend_from_slice(owner);
        v.push(8);
        v.extend_from_slice(&(id_type as i64).to_le_bytes());
        v.push(8);
        v.extend_from_slice(amount_le);
        v.resize(51, 0);
        v.push(1);
        v.push(if is_minter { 1 } else { 0 });
        v
    }

    #[test]
    fn decodes_minter_state() {
        let d = Kcc20Decoder::new([0u8; 32]);
        let owner = [0x77u8; 32];
        let state = build_state(
            &owner,
            IDENTIFIER_PUBKEY,
            &[0xe8, 0x03, 0, 0, 0, 0, 0, 0],
            true,
        ); // 1000
        let v = d.decode_state(&state).unwrap();
        assert_eq!(v["ownerIdentifier"], hex::encode(owner));
        assert_eq!(v["identifierType"], 0);
        assert_eq!(v["identifierTypeName"], "pubkey");
        assert_eq!(v["amount"], "1000");
        assert_eq!(v["isMinter"], true);
    }

    #[test]
    fn decodes_transfer_holder_state() {
        let d = Kcc20Decoder::new([0u8; 32]);
        let owner = [0x42u8; 32];
        let state = build_state(
            &owner,
            IDENTIFIER_SCRIPT_HASH,
            &[0x80, 0x96, 0x98, 0x00, 0, 0, 0, 0],
            false,
        ); // 10_000_000
        let v = d.decode_state(&state).unwrap();
        assert_eq!(v["identifierType"], 1);
        assert_eq!(v["identifierTypeName"], "scriptHash");
        assert_eq!(v["amount"], "10000000");
        assert_eq!(v["isMinter"], false);
    }

    #[test]
    fn rejects_truncated_state() {
        let d = Kcc20Decoder::new([0u8; 32]);
        assert!(d.decode_state(&[0x00; 5]).is_err());
    }

    #[test]
    fn decodes_v1_transfer_action_selectors() {
        let d = Kcc20Decoder::new([0u8; 32]);
        assert_eq!(
            d.decode_action(&[0x00, 0x01, 0xaa]).as_deref(),
            Some("transferBySig")
        );
        assert_eq!(
            d.decode_action(&[0x54, 0x01, 0xaa]).as_deref(),
            Some("transferByCovenant")
        );
        assert_eq!(
            d.decode_action(&[0x55, 0x01, 0xaa]).as_deref(),
            Some("transferAllByCovenant")
        );
    }
}
