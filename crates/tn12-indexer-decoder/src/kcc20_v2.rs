//! KCC20 V2 decoder.
//!
//! V2 keeps the compact KCC20 state layout, adds mint/burn entrypoints, and
//! treats `isMintAuthority=true` / legacy `isMinter=true` UTXOs as remaining
//! supply rather than holder balance.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{
    args_prefix_before_reveal, identifier_type_name, item_bytes_32, item_int, script_items,
    Kcc20State,
};
use crate::TemplateDecoder;

pub const KCC20_V2_LEGACY_SCRIPT_LEN: usize = 2405;
pub const KCC20_V2_PRE_PUBLIC_MINT_CONTROL_SCRIPT_LEN: usize = 8076;
pub const KCC20_V2_SCRIPT_LEN: usize = 8618;
pub const KCC20_V2_MAX_MERGE_INPUTS: usize = 8;
pub const KCC20_V2_MERGED_OUTPUT_INDEX: i32 = 0;
pub const PLATFORM_PROTOCOL_FEE_RECIPIENT: &str =
    "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01";
const GENESIS_OWNER_RANGE: (usize, usize) = (2, 34);
const GENESIS_IDENTIFIER_TYPE_RANGE: (usize, usize) = (35, 43);
const GENESIS_AMOUNT_RANGE: (usize, usize) = (44, 52);
const GENESIS_MINTER_MODE_RANGE: (usize, usize) = (53, 61);
const GENESIS_MINT_PRICE_RANGE: (usize, usize) = (62, 70);
const GENESIS_TREASURY_RANGE: (usize, usize) = (71, 103);
const GENESIS_FEE_RECIPIENT_RANGE: (usize, usize) = (104, 136);
const GENESIS_FEE_BPS_RANGE: (usize, usize) = (137, 145);
const GENESIS_TICKER_RANGE: (usize, usize) = (146, 178);
const GENESIS_NAME_RANGE: (usize, usize) = (179, 211);
const GENESIS_PRICE_SCALE_RANGE: (usize, usize) = (212, 220);
const GENESIS_IDENTIFIER_TYPE_PUSH_LEN_OFFSET: usize = 34;
const GENESIS_AMOUNT_PUSH_LEN_OFFSET: usize = 43;
const GENESIS_MINTER_MODE_PUSH_LEN_OFFSET: usize = 52;
const GENESIS_MINT_PRICE_PUSH_LEN_OFFSET: usize = 61;
const GENESIS_TREASURY_PUSH_LEN_OFFSET: usize = 70;
const GENESIS_FEE_RECIPIENT_PUSH_LEN_OFFSET: usize = 103;
const GENESIS_FEE_BPS_PUSH_LEN_OFFSET: usize = 136;
const GENESIS_TICKER_PUSH_LEN_OFFSET: usize = 145;
const GENESIS_NAME_PUSH_LEN_OFFSET: usize = 178;
const GENESIS_PRICE_SCALE_PUSH_LEN_OFFSET: usize = 211;
const DEFAULT_PRICE_SCALE: i128 = 100_000_000;

pub struct Kcc20V2Decoder {
    pub fingerprint: [u8; 32],
    script_len: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Kcc20V2OutputState {
    pub output_index: i32,
    pub state: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kcc20V2MergeRequest {
    pub merged_output_index: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Kcc20V2MergeOutput {
    pub output_index: i32,
    pub state: Value,
    pub script_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Kcc20V2DeployOutputState {
    pub role: &'static str,
    pub script: Vec<u8>,
    pub script_hash: [u8; 32],
    pub state: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Kcc20V2StateParts {
    owner_identifier: String,
    identifier_type: u8,
    amount: i128,
    minter_mode: i128,
    mint_price_sompi: String,
    treasury: String,
    fee_recipient: String,
    fee_bps: i128,
    ticker: String,
    token_name: String,
    price_scale: i128,
}

impl Kcc20V2Decoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            fingerprint,
            script_len: KCC20_V2_SCRIPT_LEN,
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
            GENESIS_OWNER_RANGE,
            GENESIS_IDENTIFIER_TYPE_RANGE,
            GENESIS_AMOUNT_RANGE,
            GENESIS_MINTER_MODE_RANGE,
            GENESIS_MINT_PRICE_RANGE,
            GENESIS_TREASURY_RANGE,
            GENESIS_FEE_BPS_RANGE,
            GENESIS_TICKER_RANGE,
            GENESIS_NAME_RANGE,
        ] {
            if end <= masked.len() {
                for b in masked[start..end].iter_mut() {
                    *b = 0;
                }
            }
        }
        if script.len() != KCC20_V2_LEGACY_SCRIPT_LEN {
            for b in masked[GENESIS_PRICE_SCALE_RANGE.0..GENESIS_PRICE_SCALE_RANGE.1].iter_mut() {
                *b = 0;
            }
        }
        blake2b_256(&masked)
    }
}

impl TemplateDecoder for Kcc20V2Decoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20V2
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

        let genesis_owner = &payload[GENESIS_OWNER_RANGE.0..GENESIS_OWNER_RANGE.1];
        let identifier_len = payload[GENESIS_IDENTIFIER_TYPE_PUSH_LEN_OFFSET] as usize;
        if identifier_len != GENESIS_IDENTIFIER_TYPE_RANGE.1 - GENESIS_IDENTIFIER_TYPE_RANGE.0 {
            return Err(anyhow!(
                "unexpected KCC20V2 stateOwnerType push length {identifier_len}"
            ));
        }
        let amount_len = payload[GENESIS_AMOUNT_PUSH_LEN_OFFSET] as usize;
        if amount_len != GENESIS_AMOUNT_RANGE.1 - GENESIS_AMOUNT_RANGE.0 {
            return Err(anyhow!(
                "unexpected KCC20V2 stateAmount push length {amount_len}"
            ));
        }
        expect_len(payload, GENESIS_MINTER_MODE_PUSH_LEN_OFFSET, 8, "mintMode")?;
        expect_len(
            payload,
            GENESIS_MINT_PRICE_PUSH_LEN_OFFSET,
            8,
            "mintPricePerTokenSompi",
        )?;
        expect_len(
            payload,
            GENESIS_TREASURY_PUSH_LEN_OFFSET,
            32,
            "treasuryRecipient",
        )?;
        expect_len(
            payload,
            GENESIS_FEE_RECIPIENT_PUSH_LEN_OFFSET,
            32,
            "protocolFeeRecipient",
        )?;
        expect_len(
            payload,
            GENESIS_FEE_BPS_PUSH_LEN_OFFSET,
            8,
            "protocolFeeBps",
        )?;
        expect_len(payload, GENESIS_TICKER_PUSH_LEN_OFFSET, 32, "tokenTicker")?;
        expect_len(payload, GENESIS_NAME_PUSH_LEN_OFFSET, 32, "tokenName")?;
        if has_price_scale(payload) {
            expect_len(
                payload,
                GENESIS_PRICE_SCALE_PUSH_LEN_OFFSET,
                8,
                "priceScale",
            )?;
        }

        Ok(json!({
            "stateOwner": hex::encode(genesis_owner),
            "stateOwnerType": parse_minimal_int(&payload[GENESIS_IDENTIFIER_TYPE_RANGE.0..GENESIS_IDENTIFIER_TYPE_RANGE.1]),
            "stateAmount": parse_minimal_int(&payload[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1]),
            "mintMode": parse_minimal_int(&payload[GENESIS_MINTER_MODE_RANGE.0..GENESIS_MINTER_MODE_RANGE.1]),
            "mintPricePerTokenSompi": parse_minimal_int(&payload[GENESIS_MINT_PRICE_RANGE.0..GENESIS_MINT_PRICE_RANGE.1]).to_string(),
            "treasuryRecipient": hex::encode(&payload[GENESIS_TREASURY_RANGE.0..GENESIS_TREASURY_RANGE.1]),
            "protocolFeeRecipient": hex::encode(&payload[GENESIS_FEE_RECIPIENT_RANGE.0..GENESIS_FEE_RECIPIENT_RANGE.1]),
            "protocolFeeBps": parse_minimal_int(&payload[GENESIS_FEE_BPS_RANGE.0..GENESIS_FEE_BPS_RANGE.1]),
            "ticker": decode_fixed_ascii(&payload[GENESIS_TICKER_RANGE.0..GENESIS_TICKER_RANGE.1]),
            "tokenName": decode_fixed_ascii(&payload[GENESIS_NAME_RANGE.0..GENESIS_NAME_RANGE.1]),
            "priceScale": reveal_price_scale(payload).to_string(),
            "tokenDisplayScale": reveal_price_scale(payload).to_string(),
        }))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        decode_state_payload(payload)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        match prefix.last().copied() {
            Some(0x00) => Some("transferByOwnerSig".into()),
            Some(0x51) => Some("transferByWitness".into()),
            Some(0x52) => Some("mintByAuthoritySig".into()),
            Some(0x53) => Some("mintPublic".into()),
            Some(0x54) => Some("burnByOwnerSig".into()),
            Some(0x55) => Some("mergeByOwnerSig".into()),
            Some(0x56) => Some("mergePeerByOwnerSig".into()),
            Some(0x57) => Some("setPublicMintActive".into()),
            _ => None,
        }
    }
}

/// Decode output indexes authorized by the active V2 input.
///
/// These fields make continuation-to-spend attribution exact when multiple
/// inputs from the same canonical token are batched in one transaction.
pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(|item| item.as_int()) else {
        return Ok(None);
    };

    let args = match selector {
        0 | 1 => json!({
            "tokenAmount": item_int(&items, 3)?.to_string(),
            "tokenOutputIndex": item_int(&items, 4)?.to_string(),
            "changeOutputIndex": item_int(&items, 5)?.to_string(),
        }),
        2 => json!({
            "tokenAmount": item_int(&items, 3)?.to_string(),
            "tokenOutputIndex": item_int(&items, 4)?.to_string(),
            "minterOutputIndex": item_int(&items, 5)?.to_string(),
        }),
        3 => json!({
            "tokenAmount": item_int(&items, 2)?.to_string(),
            "tokenOutputIndex": item_int(&items, 3)?.to_string(),
            "minterOutputIndex": item_int(&items, 4)?.to_string(),
        }),
        4 => json!({
            "tokenAmount": item_int(&items, 1)?.to_string(),
            "changeOutputIndex": item_int(&items, 2)?.to_string(),
        }),
        5 => json!({
            "mergedOutputIndex": KCC20_V2_MERGED_OUTPUT_INDEX.to_string(),
            "refundOutputIndex": "1",
        }),
        6 => json!({
            "primaryInputIndex": item_int(&items, 1)?.to_string(),
            "mergedAmount": item_int(&items, 2)?.to_string(),
            "mergedOutputIndex": KCC20_V2_MERGED_OUTPUT_INDEX.to_string(),
            "refundOutputIndex": "1",
        }),
        7 => json!({
            "active": item_int(&items, 1)? != 0,
            "minterOutputIndex": item_int(&items, 2)?.to_string(),
        }),
        _ => return Ok(None),
    };

    Ok(Some(args))
}

pub fn decode_reveal_state(payload: &[u8]) -> Result<Kcc20State> {
    Ok(decode_reveal_state_parts(payload)?.legacy_state())
}

pub fn decode_reveal_state_value(payload: &[u8]) -> Result<Value> {
    Ok(decode_reveal_state_parts(payload)?.to_value())
}

fn decode_reveal_state_parts(payload: &[u8]) -> Result<Kcc20V2StateParts> {
    if !is_supported_reveal_len(payload.len()) {
        return Err(anyhow!(
            "reveal script is {} bytes, expected {}, {}, or {}",
            payload.len(),
            KCC20_V2_LEGACY_SCRIPT_LEN,
            KCC20_V2_PRE_PUBLIC_MINT_CONTROL_SCRIPT_LEN,
            KCC20_V2_SCRIPT_LEN
        ));
    }

    let owner = &payload[GENESIS_OWNER_RANGE.0..GENESIS_OWNER_RANGE.1];
    let identifier_type = parse_minimal_int(
        &payload[GENESIS_IDENTIFIER_TYPE_RANGE.0..GENESIS_IDENTIFIER_TYPE_RANGE.1],
    ) as u8;
    let amount = parse_minimal_int(&payload[GENESIS_AMOUNT_RANGE.0..GENESIS_AMOUNT_RANGE.1]);
    let minter_mode =
        parse_minimal_int(&payload[GENESIS_MINTER_MODE_RANGE.0..GENESIS_MINTER_MODE_RANGE.1]);

    Ok(Kcc20V2StateParts {
        owner_identifier: hex::encode(owner),
        identifier_type,
        amount,
        minter_mode,
        mint_price_sompi: parse_minimal_int(
            &payload[GENESIS_MINT_PRICE_RANGE.0..GENESIS_MINT_PRICE_RANGE.1],
        )
        .to_string(),
        treasury: hex::encode(&payload[GENESIS_TREASURY_RANGE.0..GENESIS_TREASURY_RANGE.1]),
        fee_recipient: hex::encode(
            &payload[GENESIS_FEE_RECIPIENT_RANGE.0..GENESIS_FEE_RECIPIENT_RANGE.1],
        ),
        fee_bps: parse_minimal_int(&payload[GENESIS_FEE_BPS_RANGE.0..GENESIS_FEE_BPS_RANGE.1]),
        ticker: decode_fixed_ascii(&payload[GENESIS_TICKER_RANGE.0..GENESIS_TICKER_RANGE.1]),
        token_name: decode_fixed_ascii(&payload[GENESIS_NAME_RANGE.0..GENESIS_NAME_RANGE.1]),
        price_scale: reveal_price_scale(payload),
    })
}

pub fn decode_output_states(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Vec<Kcc20V2OutputState>>> {
    let input_state = decode_reveal_state_parts(reveal_script)?;
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(|i| i.as_int()) else {
        return Ok(None);
    };

    match selector {
        0 | 1 => decode_transfer_outputs(&items, &input_state, selector),
        2 => decode_mint_outputs(&items, &input_state, 1, 2, 3, 4, 5),
        3 => decode_mint_outputs(&items, &input_state, 0, 1, 2, 3, 4),
        4 => decode_burn_outputs(&items, &input_state),
        5 | 6 => Ok(None),
        7 => decode_public_mint_availability_output(&items, &input_state, reveal_script.len()),
        _ => Ok(None),
    }
}

pub fn decode_primary_merge_request(
    signature_script: &[u8],
) -> Result<Option<Kcc20V2MergeRequest>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(selector) = items.last().and_then(|i| i.as_int()) else {
        return Ok(None);
    };
    if selector != 5 {
        return Ok(None);
    }

    Ok(Some(Kcc20V2MergeRequest {
        merged_output_index: KCC20_V2_MERGED_OUTPUT_INDEX,
    }))
}

pub fn decode_merge_peer_primary_input(signature_script: &[u8]) -> Result<Option<usize>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    let Some(selector) = items.last().and_then(|item| item.as_int()) else {
        return Ok(None);
    };
    if selector != 6 {
        return Ok(None);
    }

    Ok(Some(usize::try_from(item_int(&items, 1)?).context(
        "KCC20V2 merge primary input index is negative or too large",
    )?))
}

pub fn decode_merge_output_state(
    primary_input_index: usize,
    primary_signature_script: &[u8],
    primary_reveal_script: &[u8],
    peer_inputs: &[(usize, Vec<u8>)],
) -> Result<Option<Kcc20V2MergeOutput>> {
    let Some(request) = decode_primary_merge_request(primary_signature_script)? else {
        return Ok(None);
    };
    if peer_inputs.is_empty() || peer_inputs.len() >= KCC20_V2_MAX_MERGE_INPUTS {
        return Err(anyhow!(
            "KCC20V2 merge must contain between 2 and {} holder inputs",
            KCC20_V2_MAX_MERGE_INPUTS
        ));
    }

    let primary = decode_reveal_state_parts(primary_reveal_script)?;
    if !primary.is_merge_holder() {
        return Err(anyhow!(
            "KCC20V2 merge inputs must be pubkey-owned holder states"
        ));
    }
    let mut merged_amount = primary.amount;
    for (peer_input_index, peer_reveal_script) in peer_inputs {
        if *peer_input_index == primary_input_index {
            return Err(anyhow!("KCC20V2 merge peer cannot be the primary input"));
        }
        let peer = decode_reveal_state_parts(peer_reveal_script)?;
        if !peer.is_merge_holder() {
            return Err(anyhow!(
                "KCC20V2 merge inputs must be pubkey-owned holder states"
            ));
        }
        if !primary.merge_compatible_with(&peer) {
            return Err(anyhow!("KCC20V2 merge input states are incompatible"));
        }
        merged_amount = merged_amount
            .checked_add(peer.amount)
            .ok_or_else(|| anyhow!("KCC20V2 merged amount overflow"))?;
    }

    let merged = Kcc20V2StateParts {
        amount: merged_amount,
        minter_mode: 0,
        ..primary
    };
    let merged_amount = i64::try_from(merged_amount)
        .map_err(|_| anyhow!("KCC20V2 merged amount is outside i64"))?;
    let mut merged_script = primary_reveal_script.to_vec();
    patch_range(
        &mut merged_script,
        GENESIS_AMOUNT_RANGE,
        &merged_amount.to_le_bytes(),
    );
    patch_range(
        &mut merged_script,
        GENESIS_MINTER_MODE_RANGE,
        &0_i64.to_le_bytes(),
    );
    let script_hash = blake2b_256(&merged_script);

    Ok(Some(Kcc20V2MergeOutput {
        output_index: request.merged_output_index,
        state: merged.to_value(),
        script_hash,
    }))
}

pub fn deploy_output_states_from_claimed_args(
    claimed_args: &Value,
) -> Result<Vec<Kcc20V2DeployOutputState>> {
    let max_supply = claim_i128(claimed_args, "maxSupply")
        .or_else(|| claim_i128(claimed_args, "totalSupply"))
        .ok_or_else(|| anyhow!("missing KCC20V2 maxSupply/totalSupply claim"))?;
    let premint_supply = claim_i128(claimed_args, "premintSupply").unwrap_or(0);
    let minter_mode = claim_i128(claimed_args, "mintMode")
        .ok_or_else(|| anyhow!("missing KCC20V2 mintMode claim"))?;
    let owner_identifier = claim_hex32(claimed_args, "stateOwner")
        .ok_or_else(|| anyhow!("missing KCC20V2 stateOwner claim"))?;
    let identifier_type = claim_u8(claimed_args, "stateOwnerType")
        .ok_or_else(|| anyhow!("missing/invalid KCC20V2 stateOwnerType claim"))?;
    let mint_price_sompi = claim_i128(claimed_args, "mintPricePerTokenSompi")
        .unwrap_or(0)
        .to_string();
    let treasury = claim_hex32(claimed_args, "treasuryRecipient")
        .ok_or_else(|| anyhow!("missing KCC20V2 treasuryRecipient claim"))?;
    let fee_recipient = claim_hex32(claimed_args, "protocolFeeRecipient")
        .unwrap_or_else(|| PLATFORM_PROTOCOL_FEE_RECIPIENT.to_string());
    let fee_bps = claim_i128(claimed_args, "protocolFeeBps").unwrap_or(200);
    let ticker = claim_string(claimed_args, "ticker").unwrap_or_default();
    let token_name = claim_string(claimed_args, "tokenName").unwrap_or_default();
    let price_scale = claim_price_scale(claimed_args)?;
    let public_mint_control = minter_mode == 3
        || claim_string(claimed_args, "artifactVersion").as_deref()
            == Some("public-mint-control-v1");

    if max_supply <= 0 {
        return Err(anyhow!("KCC20V2 maxSupply/totalSupply must be positive"));
    }
    if premint_supply < 0 || premint_supply > max_supply {
        return Err(anyhow!("KCC20V2 premintSupply outside maxSupply"));
    }
    if !(0..=3).contains(&minter_mode) {
        return Err(anyhow!("KCC20V2 mintMode must be 0, 1, 2, or 3"));
    }
    let template = Kcc20V2StateParts {
        owner_identifier: owner_identifier.clone(),
        identifier_type,
        amount: if minter_mode == 0 {
            max_supply
        } else {
            max_supply - premint_supply
        },
        minter_mode,
        mint_price_sompi,
        treasury,
        fee_recipient,
        fee_bps,
        ticker,
        token_name,
        price_scale,
    };

    let mut out = Vec::new();
    out.push(deploy_state("minter", &template, public_mint_control)?);

    if minter_mode != 0 && premint_supply > 0 {
        let premint_owner =
            claim_hex32(claimed_args, "premintRecipient").unwrap_or(owner_identifier);
        let premint_type =
            claim_u8(claimed_args, "premintRecipientType").unwrap_or(identifier_type);
        let premint = Kcc20V2StateParts {
            owner_identifier: premint_owner,
            identifier_type: premint_type,
            amount: premint_supply,
            minter_mode: 0,
            ..template.clone()
        };
        out.push(deploy_state("premint", &premint, public_mint_control)?);
    }

    Ok(out)
}

fn deploy_state(
    role: &'static str,
    state: &Kcc20V2StateParts,
    public_mint_control: bool,
) -> Result<Kcc20V2DeployOutputState> {
    let script = if public_mint_control {
        script_for_state(state)?
    } else {
        script_for_state_with_placeholder(state, pre_public_mint_control_placeholder_script())?
    };
    let script_hash = blake2b_256(&script);
    Ok(Kcc20V2DeployOutputState {
        role,
        script,
        script_hash,
        state: state.to_value(),
    })
}

fn decode_transfer_outputs(
    items: &[crate::kcc20::ScriptItem],
    input_state: &Kcc20V2StateParts,
    selector: i128,
) -> Result<Option<Vec<Kcc20V2OutputState>>> {
    let (to_owner_idx, to_type_idx, amount_idx, to_output_idx, change_output_idx) = match selector {
        0 | 1 => (1, 2, 3, 4, 5),
        _ => return Ok(None),
    };
    let to_amount = item_int(items, amount_idx)?;
    let input_amount = input_state.amount;
    let mut out = vec![holder_output(
        input_state,
        hex::encode(item_bytes_32(items, to_owner_idx)?),
        item_int(items, to_type_idx)? as u8,
        to_amount,
        item_int(items, to_output_idx)? as i32,
    )];

    if to_amount < input_amount {
        out.push(Kcc20V2OutputState {
            output_index: item_int(items, change_output_idx)? as i32,
            state: input_state.with_state(
                input_state.owner_identifier.clone(),
                input_state.identifier_type,
                input_amount - to_amount,
                0,
            ),
        });
    }

    Ok(Some(out))
}

fn decode_mint_outputs(
    items: &[crate::kcc20::ScriptItem],
    input_state: &Kcc20V2StateParts,
    owner_idx: usize,
    type_idx: usize,
    amount_idx: usize,
    token_output_idx: usize,
    minter_output_idx: usize,
) -> Result<Option<Vec<Kcc20V2OutputState>>> {
    let minted_amount = item_int(items, amount_idx)?;
    let input_amount = input_state.amount;
    let mut out = vec![holder_output(
        input_state,
        hex::encode(item_bytes_32(items, owner_idx)?),
        item_int(items, type_idx)? as u8,
        minted_amount,
        item_int(items, token_output_idx)? as i32,
    )];
    if minted_amount < input_amount {
        out.push(Kcc20V2OutputState {
            output_index: item_int(items, minter_output_idx)? as i32,
            state: input_state.with_state(
                input_state.owner_identifier.clone(),
                input_state.identifier_type,
                input_amount - minted_amount,
                input_state.minter_mode,
            ),
        });
    }
    Ok(Some(out))
}

fn decode_burn_outputs(
    items: &[crate::kcc20::ScriptItem],
    input_state: &Kcc20V2StateParts,
) -> Result<Option<Vec<Kcc20V2OutputState>>> {
    let burn_amount = item_int(items, 1)?;
    let input_amount = input_state.amount;
    if burn_amount >= input_amount {
        return Ok(Some(Vec::new()));
    }
    Ok(Some(vec![Kcc20V2OutputState {
        output_index: item_int(items, 2)? as i32,
        state: input_state.with_state(
            input_state.owner_identifier.clone(),
            input_state.identifier_type,
            input_amount - burn_amount,
            0,
        ),
    }]))
}

fn decode_public_mint_availability_output(
    items: &[crate::kcc20::ScriptItem],
    input_state: &Kcc20V2StateParts,
    reveal_script_len: usize,
) -> Result<Option<Vec<Kcc20V2OutputState>>> {
    if reveal_script_len != KCC20_V2_SCRIPT_LEN {
        return Err(anyhow!(
            "KCC20V2 public mint availability is unsupported by this artifact"
        ));
    }
    let active = item_int(items, 1)? != 0;
    let next_mode = match (input_state.minter_mode, active) {
        (3, true) => 2,
        (2, false) => 3,
        _ => {
            return Err(anyhow!(
                "invalid KCC20V2 public mint availability transition"
            ));
        }
    };
    Ok(Some(vec![Kcc20V2OutputState {
        output_index: item_int(items, 2)? as i32,
        state: input_state.with_state(
            input_state.owner_identifier.clone(),
            input_state.identifier_type,
            input_state.amount,
            next_mode,
        ),
    }]))
}

fn holder_output(
    template: &Kcc20V2StateParts,
    owner_identifier: String,
    identifier_type: u8,
    amount: i128,
    output_index: i32,
) -> Kcc20V2OutputState {
    Kcc20V2OutputState {
        output_index,
        state: template.with_state(owner_identifier, identifier_type, amount, 0),
    }
}

impl Kcc20V2StateParts {
    fn is_merge_holder(&self) -> bool {
        self.identifier_type == 0 && self.minter_mode == 0 && self.amount > 0
    }

    fn merge_compatible_with(&self, other: &Self) -> bool {
        self.owner_identifier == other.owner_identifier
            && self.identifier_type == other.identifier_type
            && self.mint_price_sompi == other.mint_price_sompi
            && self.treasury == other.treasury
            && self.fee_recipient == other.fee_recipient
            && self.fee_bps == other.fee_bps
            && self.ticker == other.ticker
            && self.token_name == other.token_name
            && self.price_scale == other.price_scale
    }

    fn legacy_state(&self) -> Kcc20State {
        Kcc20State {
            owner_identifier: self.owner_identifier.clone(),
            identifier_type: self.identifier_type,
            identifier_type_name: identifier_type_name(self.identifier_type),
            amount: self.amount.to_string(),
            is_minter: self.minter_mode != 0,
        }
    }

    fn to_value(&self) -> Value {
        self.with_state(
            self.owner_identifier.clone(),
            self.identifier_type,
            self.amount,
            self.minter_mode,
        )
    }

    fn with_state(
        &self,
        owner_identifier: String,
        identifier_type: u8,
        amount: i128,
        minter_mode: i128,
    ) -> Value {
        let amount = amount.to_string();
        let is_minter = minter_mode != 0;
        let public_mint_active = match minter_mode {
            2 => Some(true),
            3 => Some(false),
            _ => None,
        };
        json!({
            "ownerIdentifier": owner_identifier,
            "identifierType": identifier_type,
            "identifierTypeName": identifier_type_name(identifier_type),
            "amount": amount,
            "isMinter": is_minter,
            "minterMode": minter_mode,
            "publicMintActive": public_mint_active,
            "mintPriceSompi": self.mint_price_sompi,
            "treasury": self.treasury,
            "feeRecipient": self.fee_recipient,
            "feeBps": self.fee_bps,
            "stateOwner": owner_identifier,
            "stateOwnerType": identifier_type,
            "stateAmount": amount,
            "mintMode": minter_mode,
            "isMintAuthority": is_minter,
            "mintPricePerTokenSompi": self.mint_price_sompi,
            "treasuryRecipient": self.treasury,
            "protocolFeeRecipient": self.fee_recipient,
            "protocolFeeBps": self.fee_bps,
            "ticker": self.ticker,
            "tokenName": self.token_name,
            "priceScale": self.price_scale.to_string(),
            "tokenDisplayScale": self.price_scale.to_string(),
        })
    }
}

fn placeholder_script() -> Vec<u8> {
    let artifact: Value = serde_json::from_str(include_str!(
        "../fixtures/kcc20-v2/KCC20V2.placeholder.json"
    ))
    .expect("embedded KCC20V2 placeholder fixture is valid JSON");
    artifact["script"]
        .as_array()
        .expect("embedded KCC20V2 placeholder fixture has script array")
        .iter()
        .map(|v| v.as_u64().expect("script byte is numeric") as u8)
        .collect()
}

fn pre_public_mint_control_placeholder_script() -> Vec<u8> {
    let artifact: Value = serde_json::from_str(include_str!(
        "../fixtures/kcc20-v2/KCC20V2.pre-public-mint-control.placeholder.json"
    ))
    .expect("embedded pre-public-mint-control KCC20V2 placeholder fixture is valid JSON");
    artifact["script"]
        .as_array()
        .expect("embedded pre-public-mint-control KCC20V2 placeholder fixture has script array")
        .iter()
        .map(|v| v.as_u64().expect("script byte is numeric") as u8)
        .collect()
}

fn script_for_state(state: &Kcc20V2StateParts) -> Result<Vec<u8>> {
    script_for_state_with_placeholder(state, placeholder_script())
}

fn script_for_state_with_placeholder(
    state: &Kcc20V2StateParts,
    mut script: Vec<u8>,
) -> Result<Vec<u8>> {
    patch_range(
        &mut script,
        GENESIS_OWNER_RANGE,
        &hex32_bytes(&state.owner_identifier)?,
    );
    patch_range(
        &mut script,
        GENESIS_IDENTIFIER_TYPE_RANGE,
        &i64_le(state.identifier_type as i128)?,
    );
    patch_range(&mut script, GENESIS_AMOUNT_RANGE, &i64_le(state.amount)?);
    patch_range(
        &mut script,
        GENESIS_MINTER_MODE_RANGE,
        &i64_le(state.minter_mode)?,
    );
    patch_range(
        &mut script,
        GENESIS_MINT_PRICE_RANGE,
        &i64_le(
            state
                .mint_price_sompi
                .parse::<i128>()
                .context("KCC20V2 mint price is not an integer")?,
        )?,
    );
    patch_range(
        &mut script,
        GENESIS_TREASURY_RANGE,
        &hex32_bytes(&state.treasury)?,
    );
    patch_range(
        &mut script,
        GENESIS_FEE_RECIPIENT_RANGE,
        &hex32_bytes(&state.fee_recipient)?,
    );
    patch_range(&mut script, GENESIS_FEE_BPS_RANGE, &i64_le(state.fee_bps)?);
    patch_range(
        &mut script,
        GENESIS_TICKER_RANGE,
        &ascii_bytes32(&state.ticker),
    );
    patch_range(
        &mut script,
        GENESIS_NAME_RANGE,
        &ascii_bytes32(&state.token_name),
    );
    patch_range(
        &mut script,
        GENESIS_PRICE_SCALE_RANGE,
        &i64_le(state.price_scale)?,
    );
    Ok(script)
}

fn patch_range(script: &mut [u8], range: (usize, usize), bytes: &[u8]) {
    assert_eq!(bytes.len(), range.1 - range.0);
    script[range.0..range.1].copy_from_slice(bytes);
}

fn i64_le(value: i128) -> Result<[u8; 8]> {
    if value < i64::MIN as i128 || value > i64::MAX as i128 {
        return Err(anyhow!("KCC20V2 state integer outside i64 range"));
    }
    Ok((value as i64).to_le_bytes())
}

fn hex32_bytes(hex_value: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_value, &mut out).context("KCC20V2 state field is not 32-byte hex")?;
    Ok(out)
}

fn ascii_bytes32(value: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    let len = bytes.len().min(32);
    out[..len].copy_from_slice(&bytes[..len]);
    out
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
    claim_value(claimed_args, name).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn claim_i128(claimed_args: &Value, name: &str) -> Option<i128> {
    claim_value(claimed_args, name).and_then(|v| match v {
        Value::String(s) => s.parse::<i128>().ok(),
        Value::Number(n) => n
            .as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().and_then(|u| i128::try_from(u).ok())),
        _ => None,
    })
}

fn claim_u8(claimed_args: &Value, name: &str) -> Option<u8> {
    claim_i128(claimed_args, name).and_then(|value| u8::try_from(value).ok())
}

fn claim_price_scale(claimed_args: &Value) -> Result<i128> {
    if let Some(value) = claim_i128(claimed_args, "priceScale")
        .or_else(|| claim_i128(claimed_args, "tokenDisplayScale"))
    {
        if value > 0 {
            return Ok(value);
        }
        return Err(anyhow!(
            "KCC20V2 priceScale/tokenDisplayScale must be positive"
        ));
    }
    let decimals = claim_i128(claimed_args, "decimals").unwrap_or(8);
    if !(0..=8).contains(&decimals) {
        return Err(anyhow!("KCC20V2 decimals must be between 0 and 8"));
    }
    let mut scale = 1i128;
    for _ in 0..decimals {
        scale *= 10;
    }
    Ok(scale)
}

fn claim_hex32(claimed_args: &Value, name: &str) -> Option<String> {
    claim_string(claimed_args, name).and_then(|s| {
        let value = s.trim();
        if value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            Some(value.to_ascii_lowercase())
        } else {
            None
        }
    })
}

fn is_supported_reveal_len(len: usize) -> bool {
    len == KCC20_V2_LEGACY_SCRIPT_LEN
        || len == KCC20_V2_PRE_PUBLIC_MINT_CONTROL_SCRIPT_LEN
        || len == KCC20_V2_SCRIPT_LEN
}

fn has_price_scale(payload: &[u8]) -> bool {
    payload.len() != KCC20_V2_LEGACY_SCRIPT_LEN
}

fn reveal_price_scale(payload: &[u8]) -> i128 {
    if has_price_scale(payload) {
        parse_minimal_int(&payload[GENESIS_PRICE_SCALE_RANGE.0..GENESIS_PRICE_SCALE_RANGE.1])
    } else {
        DEFAULT_PRICE_SCALE
    }
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() < 210 {
        return Err(anyhow!(
            "KCC20V2 state payload too short ({} bytes)",
            payload.len()
        ));
    }
    if payload[0] != 32 {
        return Err(anyhow!("unexpected KCC20V2 ownerIdentifier push length"));
    }
    if payload[33] != 8 {
        return Err(anyhow!("unexpected KCC20V2 identifierType push length"));
    }
    if payload[42] != 8 {
        return Err(anyhow!("unexpected KCC20V2 amount push length"));
    }
    if payload[51] != 8 {
        return Err(anyhow!("unexpected KCC20V2 minterMode push length"));
    }
    if payload[60] != 8 {
        return Err(anyhow!("unexpected KCC20V2 mintPriceSompi push length"));
    }
    if payload[69] != 32 {
        return Err(anyhow!("unexpected KCC20V2 treasury push length"));
    }
    if payload[102] != 32 {
        return Err(anyhow!("unexpected KCC20V2 feeRecipient push length"));
    }
    if payload[135] != 8 {
        return Err(anyhow!("unexpected KCC20V2 feeBps push length"));
    }
    if payload[144] != 32 {
        return Err(anyhow!("unexpected KCC20V2 ticker push length"));
    }
    if payload[177] != 32 {
        return Err(anyhow!("unexpected KCC20V2 name push length"));
    }
    if payload.len() >= 219 && payload[210] != 8 {
        return Err(anyhow!("unexpected KCC20V2 priceScale push length"));
    }
    let identifier_type = parse_minimal_int(&payload[34..42]) as u8;
    let minter_mode = parse_minimal_int(&payload[52..60]);
    let amount = parse_minimal_int(&payload[43..51]).to_string();
    let mint_price = parse_minimal_int(&payload[61..69]).to_string();
    let treasury = hex::encode(&payload[70..102]);
    let fee_recipient = hex::encode(&payload[103..135]);
    let fee_bps = parse_minimal_int(&payload[136..144]);
    let ticker = decode_fixed_ascii(&payload[145..177]);
    let name = decode_fixed_ascii(&payload[178..210]);
    let owner = hex::encode(&payload[1..33]);
    let price_scale = if payload.len() >= 219 {
        parse_minimal_int(&payload[211..219])
    } else {
        DEFAULT_PRICE_SCALE
    };

    Ok(json!({
        "ownerIdentifier": owner,
        "identifierType": identifier_type,
        "identifierTypeName": identifier_type_name(identifier_type),
        "amount": amount,
        "isMinter": minter_mode != 0,
        "minterMode": minter_mode,
        "mintPriceSompi": mint_price,
        "treasury": treasury,
        "feeRecipient": fee_recipient,
        "feeBps": fee_bps,
        "stateOwner": owner,
        "stateOwnerType": identifier_type,
        "stateAmount": amount,
        "mintMode": minter_mode,
        "isMintAuthority": minter_mode != 0,
        "mintPricePerTokenSompi": mint_price,
        "treasuryRecipient": treasury,
        "protocolFeeRecipient": fee_recipient,
        "protocolFeeBps": fee_bps,
        "ticker": ticker,
        "tokenName": name,
        "priceScale": price_scale.to_string(),
        "tokenDisplayScale": price_scale.to_string(),
    }))
}

fn decode_fixed_ascii(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
        .trim_end()
        .to_string()
}

fn expect_len(payload: &[u8], offset: usize, expected: usize, label: &str) -> Result<()> {
    let actual = payload
        .get(offset)
        .copied()
        .ok_or_else(|| anyhow!("missing KCC20V2 {label} push length"))? as usize;
    if actual != expected {
        return Err(anyhow!(
            "unexpected KCC20V2 {label} push length {actual}, expected {expected}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::kcc20::{IDENTIFIER_COVENANT_ID, IDENTIFIER_PUBKEY, IDENTIFIER_SCRIPT_HASH};

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-v2/KCC20V2.placeholder.json"
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

    fn build_v2_state(
        owner: &[u8; 32],
        id_type: u8,
        amount: i64,
        minter_mode: i64,
        mint_price: i64,
        treasury: &[u8; 32],
        fee_recipient: &[u8; 32],
        fee_bps: i64,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(32);
        v.extend_from_slice(owner);
        push_i64(&mut v, id_type as i64);
        push_i64(&mut v, amount);
        push_i64(&mut v, minter_mode);
        push_i64(&mut v, mint_price);
        v.push(32);
        v.extend_from_slice(treasury);
        v.push(32);
        v.extend_from_slice(fee_recipient);
        push_i64(&mut v, fee_bps);
        v.push(32);
        v.extend_from_slice(b"KCOM\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        v.push(32);
        v.extend_from_slice(b"KaspaCom Utility\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        v
    }

    #[test]
    fn matches_placeholder_script() {
        let script = placeholder_script();
        let decoder = Kcc20V2Decoder::new(Kcc20V2Decoder::fingerprint_of_compiled_script(&script));
        assert!(decoder.matches_reveal_script(&script));
    }

    #[test]
    fn matches_pre_public_mint_control_placeholder_script() {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-v2/KCC20V2.pre-public-mint-control.placeholder.json"
        ))
        .unwrap();
        let script: Vec<u8> = artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect();
        let decoder = Kcc20V2Decoder::with_script_len(
            Kcc20V2Decoder::fingerprint_of_compiled_script(&script),
            script.len(),
        );
        assert_eq!(script.len(), KCC20_V2_PRE_PUBLIC_MINT_CONTROL_SCRIPT_LEN);
        assert!(decoder.matches_reveal_script(&script));
    }

    #[test]
    fn decodes_transfer_output_linkage() {
        let mut signature_script = Vec::new();
        for value in [99, 2, 0, 40, 7, 8] {
            push_i64(&mut signature_script, value);
        }
        signature_script.push(0x00);
        push_script(&mut signature_script, &[0xaa]);

        let args = decode_action_args(&signature_script).unwrap().unwrap();
        assert_eq!(args["tokenAmount"], "40");
        assert_eq!(args["tokenOutputIndex"], "7");
        assert_eq!(args["changeOutputIndex"], "8");
    }

    #[test]
    fn rejects_v2_script_with_mutated_protocol_fee_recipient() {
        let script = placeholder_script();
        let decoder = Kcc20V2Decoder::new(Kcc20V2Decoder::fingerprint_of_compiled_script(&script));

        let mut patched = script.clone();
        patched[GENESIS_FEE_RECIPIENT_RANGE.0] ^= 0xff;

        assert!(!decoder.matches_reveal_script(&patched));
    }

    #[test]
    fn decodes_constructor_from_placeholder() {
        let script = placeholder_script();
        let decoder = Kcc20V2Decoder::new(Kcc20V2Decoder::fingerprint_of_compiled_script(&script));
        let v = decoder.decode_constructor(&script).unwrap();
        assert_eq!(
            v["stateOwner"],
            "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"
        );
        assert_eq!(v["stateOwnerType"], IDENTIFIER_PUBKEY);
        assert_eq!(v["stateAmount"], 1_000_000);
        assert_eq!(v["mintMode"], 2);
        assert_eq!(v["mintPricePerTokenSompi"], "100000000");
        assert_eq!(
            v["treasuryRecipient"],
            "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"
        );
        assert_eq!(v["protocolFeeRecipient"], PLATFORM_PROTOCOL_FEE_RECIPIENT);
        assert_eq!(v["protocolFeeBps"], 200);
        assert_eq!(v["ticker"], "KCOM");
        assert_eq!(v["tokenName"], "KaspaCom Utility");
        assert_eq!(v["priceScale"], "100000000");
        assert_eq!(v["tokenDisplayScale"], "100000000");
    }

    #[test]
    fn projects_deploy_minter_and_premint_states_from_claim() {
        let owner = "11".repeat(32);
        let premint = "22".repeat(32);
        let treasury = "33".repeat(32);
        let blob = json!({
            "tmpl": "KCC20V2",
            "args": [
                {"name": "stateOwner", "type": "byte[32]", "value": owner},
                {"name": "stateOwnerType", "type": "u64", "value": "0"},
                {"name": "maxSupply", "type": "u64", "value": "1000000"},
                {"name": "premintSupply", "type": "u64", "value": "500000"},
                {"name": "premintRecipient", "type": "byte[32]", "value": premint},
                {"name": "premintRecipientType", "type": "u64", "value": "0"},
                {"name": "mintMode", "type": "u64", "value": "2"},
                {"name": "mintPricePerTokenSompi", "type": "u64", "value": "500000000"},
                {"name": "treasuryRecipient", "type": "byte[32]", "value": treasury},
                {"name": "protocolFeeBps", "type": "u64", "value": "200"},
                {"name": "ticker", "type": "string", "value": "TESTV9"},
                {"name": "tokenName", "type": "string", "value": "Test V9"}
            ]
        });

        let states = deploy_output_states_from_claimed_args(&blob).unwrap();

        assert_eq!(states.len(), 2);
        assert_eq!(states[0].role, "minter");
        assert_eq!(states[0].state["ownerIdentifier"], owner);
        assert_eq!(states[0].state["amount"], "500000");
        assert_eq!(states[0].state["isMinter"], true);
        assert_eq!(states[0].state["priceScale"], "100000000");
        assert_eq!(states[1].role, "premint");
        assert_eq!(states[1].state["ownerIdentifier"], premint);
        assert_eq!(states[1].state["amount"], "500000");
        assert_eq!(states[1].state["isMinter"], false);
        assert_eq!(states[1].state["priceScale"], "100000000");
        assert_eq!(states[0].script_hash, blake2b_256(&states[0].script));
        assert_eq!(states[1].script_hash, blake2b_256(&states[1].script));
    }

    #[test]
    fn projects_current_test26_deploy_premint_script_hash() {
        let owner = "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01";
        let blob = json!({
            "tmpl": "KCC20V2",
            "args": [
                {"name": "stateOwner", "type": "byte[32]", "value": owner},
                {"name": "stateOwnerType", "type": "u64", "value": "0"},
                {"name": "maxSupply", "type": "u64", "value": "1000000"},
                {"name": "premintSupply", "type": "u64", "value": "55555"},
                {"name": "premintRecipient", "type": "byte[32]", "value": owner},
                {"name": "premintRecipientType", "type": "u64", "value": "0"},
                {"name": "mintMode", "type": "u64", "value": "2"},
                {"name": "mintPricePerTokenSompi", "type": "u64", "value": "200000000"},
                {"name": "treasuryRecipient", "type": "byte[32]", "value": owner},
                {"name": "protocolFeeBps", "type": "u64", "value": "200"},
                {"name": "ticker", "type": "string", "value": "TEST26"},
                {"name": "tokenName", "type": "string", "value": "TEST26"}
            ]
        });

        let states = deploy_output_states_from_claimed_args(&blob).unwrap();

        assert_eq!(
            hex::encode(states[0].script_hash),
            "776149ddd9ab57626c475e5190c14ee84cdcb8483c3a71ca0c238ac00b265434"
        );
        assert_eq!(
            hex::encode(states[1].script_hash),
            "86244e1ca82f59406d2597bd2e1f04545692e029b3f67a9b17d487809b75c488"
        );
        assert_eq!(states[0].state["priceScale"], "100000000");
        assert_eq!(states[1].state["priceScale"], "100000000");
    }

    #[test]
    fn projects_fixed_supply_deploy_as_single_holder_state() {
        let owner = "11".repeat(32);
        let treasury = "33".repeat(32);
        let blob = json!({
            "tmpl": "KCC20V2",
            "args": [
                {"name": "stateOwner", "type": "byte[32]", "value": owner},
                {"name": "stateOwnerType", "type": "u64", "value": "0"},
                {"name": "totalSupply", "type": "u64", "value": "1000000"},
                {"name": "premintSupply", "type": "u64", "value": "1000000"},
                {"name": "mintMode", "type": "u64", "value": "0"},
                {"name": "mintPricePerTokenSompi", "type": "u64", "value": "0"},
                {"name": "treasuryRecipient", "type": "byte[32]", "value": treasury},
                {"name": "protocolFeeBps", "type": "u64", "value": "200"}
            ]
        });

        let states = deploy_output_states_from_claimed_args(&blob).unwrap();

        assert_eq!(states.len(), 1);
        assert_eq!(states[0].role, "minter");
        assert_eq!(states[0].state["ownerIdentifier"], owner);
        assert_eq!(states[0].state["amount"], "1000000");
        assert_eq!(states[0].state["isMinter"], false);
        assert_eq!(states[0].state["minterMode"], 0);
    }

    #[test]
    fn rejects_invalid_deploy_claim_mode_and_identifier_type() {
        let owner = "11".repeat(32);
        let treasury = "33".repeat(32);
        let mut blob = json!({
            "tmpl": "KCC20V2",
            "args": [
                {"name": "stateOwner", "type": "byte[32]", "value": owner},
                {"name": "stateOwnerType", "type": "u64", "value": "999"},
                {"name": "maxSupply", "type": "u64", "value": "1000000"},
                {"name": "premintSupply", "type": "u64", "value": "0"},
                {"name": "mintMode", "type": "u64", "value": "2"},
                {"name": "mintPricePerTokenSompi", "type": "u64", "value": "0"},
                {"name": "treasuryRecipient", "type": "byte[32]", "value": treasury}
            ]
        });

        assert!(deploy_output_states_from_claimed_args(&blob).is_err());

        blob["args"][1]["value"] = json!("0");
        blob["args"][4]["value"] = json!("99");
        assert!(deploy_output_states_from_claimed_args(&blob).is_err());
    }

    #[test]
    fn decodes_v2_state_payload_with_paid_public_minter_fields() {
        let d = Kcc20V2Decoder::new([0u8; 32]);
        let owner = [0x42u8; 32];
        let treasury = [0x77u8; 32];
        let fee_recipient = [0x99u8; 32];
        let state = build_v2_state(
            &owner,
            IDENTIFIER_COVENANT_ID,
            1_000,
            2,
            100_000_000,
            &treasury,
            &fee_recipient,
            200,
        );
        let v = d.decode_state(&state).unwrap();
        assert_eq!(v["ownerIdentifier"], hex::encode(owner));
        assert_eq!(v["identifierType"], IDENTIFIER_COVENANT_ID);
        assert_eq!(v["identifierTypeName"], "covenantId");
        assert_eq!(v["amount"], "1000");
        assert_eq!(v["isMinter"], true);
        assert_eq!(v["minterMode"], 2);
        assert_eq!(v["mintPriceSompi"], "100000000");
        assert_eq!(v["treasury"], hex::encode(treasury));
        assert_eq!(v["feeRecipient"], hex::encode(fee_recipient));
        assert_eq!(v["feeBps"], 200);
        assert_eq!(v["ticker"], "KCOM");
        assert_eq!(v["tokenName"], "KaspaCom Utility");
        assert_eq!(v["priceScale"], "100000000");
    }

    #[test]
    fn decodes_public_mint_output_states() {
        let script = placeholder_script();
        let mut sig = Vec::new();
        sig.push(32);
        sig.extend([0x42; 32]);
        push_i64(&mut sig, IDENTIFIER_PUBKEY as i64);
        push_i64(&mut sig, 100);
        sig.push(0x00);
        sig.push(0x51);
        sig.push(0x52);
        sig.push(0x52);
        sig.push(0x53);
        push_script(&mut sig, &script);

        let out = decode_output_states(&sig, &script).unwrap().unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].output_index, 0);
        assert_eq!(out[0].state["ownerIdentifier"], "42".repeat(32));
        assert_eq!(out[0].state["identifierType"], IDENTIFIER_PUBKEY);
        assert_eq!(out[0].state["amount"], "100");
        assert_eq!(out[0].state["isMinter"], false);
        assert_eq!(out[0].state["minterMode"], 0);
        assert_eq!(out[0].state["mintPriceSompi"], "100000000");
        assert_eq!(
            out[0].state["protocolFeeRecipient"],
            PLATFORM_PROTOCOL_FEE_RECIPIENT
        );
        assert_eq!(out[0].state["protocolFeeBps"], 200);
        assert_eq!(out[0].state["ticker"], "KCOM");
        assert_eq!(out[0].state["tokenName"], "KaspaCom Utility");
        assert_eq!(out[0].state["priceScale"], "100000000");
        assert_eq!(out[1].output_index, 1);
        assert_eq!(out[1].state["amount"], "999900");
        assert_eq!(out[1].state["isMinter"], true);
        assert_eq!(out[1].state["minterMode"], 2);
        assert_eq!(out[1].state["publicMintActive"], true);
        assert_eq!(out[1].state["mintPriceSompi"], "100000000");
        assert_eq!(
            out[1].state["protocolFeeRecipient"],
            PLATFORM_PROTOCOL_FEE_RECIPIENT
        );
        assert_eq!(out[1].state["priceScale"], "100000000");
    }

    #[test]
    fn decodes_public_mint_pause_output_state() {
        let script = placeholder_script();
        let mut sig = vec![65];
        sig.extend([0x11; 65]);
        sig.push(0x00);
        sig.push(0x51);
        sig.push(0x57);
        push_script(&mut sig, &script);

        let args = decode_action_args(&sig).unwrap().unwrap();
        assert_eq!(args["active"], false);
        assert_eq!(args["minterOutputIndex"], "1");

        let out = decode_output_states(&sig, &script).unwrap().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].output_index, 1);
        assert_eq!(out[0].state["amount"], "1000000");
        assert_eq!(out[0].state["minterMode"], 3);
        assert_eq!(out[0].state["publicMintActive"], false);
    }

    #[test]
    fn decodes_partial_burn_output_state() {
        let script = placeholder_script();
        let mut sig = vec![65];
        sig.extend([0x11; 65]);
        push_i64(&mut sig, 100);
        sig.push(0x00);
        sig.push(0x54);
        push_script(&mut sig, &script);

        let out = decode_output_states(&sig, &script).unwrap().unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].output_index, 0);
        assert_eq!(out[0].state["amount"], "999900");
        assert_eq!(out[0].state["isMinter"], false);
        assert_eq!(out[0].state["minterMode"], 0);
        assert_eq!(out[0].state["mintPriceSompi"], "100000000");
        assert_eq!(out[0].state["priceScale"], "100000000");
    }

    fn merge_signature(primary_input_index: Option<i64>, selector: u8, reveal: &[u8]) -> Vec<u8> {
        let mut sig = vec![65];
        sig.extend([0x11; 65]);
        if let Some(primary_input_index) = primary_input_index {
            push_i64(&mut sig, primary_input_index);
        }
        sig.push(selector);
        push_script(&mut sig, reveal);
        sig
    }

    #[test]
    fn decodes_batched_v2_holder_merge_output() {
        let mut primary_state = decode_reveal_state_parts(&placeholder_script()).unwrap();
        primary_state.amount = 1_000;
        primary_state.minter_mode = 0;
        let primary_reveal = script_for_state(&primary_state).unwrap();
        let peer_inputs = [500, 250]
            .into_iter()
            .enumerate()
            .map(|(index, amount)| {
                let peer_reveal = script_for_state(&Kcc20V2StateParts {
                    amount,
                    ..primary_state.clone()
                })
                .unwrap();
                (index + 1, peer_reveal)
            })
            .collect::<Vec<_>>();
        let primary_sig = merge_signature(None, 0x55, &primary_reveal);

        let output = decode_merge_output_state(0, &primary_sig, &primary_reveal, &peer_inputs)
            .unwrap()
            .unwrap();

        assert_eq!(output.output_index, 0);
        assert_eq!(output.state["amount"], "1750");
        assert_eq!(
            output.state["ownerIdentifier"],
            primary_state.owner_identifier
        );
        assert_eq!(output.state["minterMode"], 0);
        let mut expected_state = primary_state.clone();
        expected_state.amount = 1_750;
        assert_eq!(
            output.script_hash,
            blake2b_256(&script_for_state(&expected_state).unwrap())
        );
    }

    #[test]
    fn rejects_incompatible_duplicate_or_overflowing_v2_holder_merge() {
        let mut primary_state = decode_reveal_state_parts(&placeholder_script()).unwrap();
        primary_state.amount = 1_000;
        primary_state.minter_mode = 0;
        let primary_reveal = script_for_state(&primary_state).unwrap();
        let mut peer_state = primary_state.clone();
        peer_state.amount = 500;
        peer_state.owner_identifier = "22".repeat(32);
        let peer_reveal = script_for_state(&peer_state).unwrap();
        let primary_sig = merge_signature(None, 0x55, &primary_reveal);
        assert!(
            decode_merge_output_state(0, &primary_sig, &primary_reveal, &[(1, peer_reveal)],)
                .is_err()
        );

        let compatible_peer_reveal = script_for_state(&Kcc20V2StateParts {
            owner_identifier: primary_state.owner_identifier.clone(),
            amount: 500,
            ..primary_state.clone()
        })
        .unwrap();
        assert!(decode_merge_output_state(
            0,
            &primary_sig,
            &primary_reveal,
            &[(0, compatible_peer_reveal)],
        )
        .is_err());

        let mut max_state = primary_state.clone();
        max_state.amount = i64::MAX as i128;
        let max_reveal = script_for_state(&max_state).unwrap();
        let mut one_state = primary_state.clone();
        one_state.amount = 1;
        let one_reveal = script_for_state(&one_state).unwrap();
        let max_sig = merge_signature(None, 0x55, &max_reveal);
        assert!(decode_merge_output_state(0, &max_sig, &max_reveal, &[(1, one_reveal)],).is_err());
    }

    #[test]
    fn decodes_v2_action_selectors() {
        let d = Kcc20V2Decoder::new([0u8; 32]);
        assert_eq!(
            d.decode_action(&[0x51, 0x01, 0xaa]).as_deref(),
            Some("transferByWitness")
        );
        assert_eq!(
            d.decode_action(&[0x52, 0x01, 0xaa]).as_deref(),
            Some("mintByAuthoritySig")
        );
        assert_eq!(
            d.decode_action(&[0x54, 0x01, 0xaa]).as_deref(),
            Some("burnByOwnerSig")
        );
        assert_eq!(
            d.decode_action(&[0x55, 0x01, 0xaa]).as_deref(),
            Some("mergeByOwnerSig")
        );
        assert_eq!(
            d.decode_action(&[0x56, 0x01, 0xaa]).as_deref(),
            Some("mergePeerByOwnerSig")
        );
        assert_eq!(
            d.decode_action(&[0x57, 0x01, 0xaa]).as_deref(),
            Some("setPublicMintActive")
        );
    }

    #[test]
    fn identifier_constants_stay_stable() {
        assert_eq!(IDENTIFIER_PUBKEY, 0);
        assert_eq!(IDENTIFIER_SCRIPT_HASH, 1);
        assert_eq!(IDENTIFIER_COVENANT_ID, 2);
    }
}
