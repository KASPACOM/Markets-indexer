//! KCC-0001/KCC-0002/KCC-0020 decoder for the universal KCC20 program.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, script_items, ScriptItem};
use crate::TemplateDecoder;

pub const KCC20_STATE_START: usize = 1;
pub const KCC20_STATE_LEN: usize = 112;
const MAX_KCC20_AMOUNT: i128 = i64::MAX as i128;
const MAX_WIDE_KCC20_SUPPLY: i128 = (1_i128 << 126) - 1;
pub const TRANSFER_TAG: [u8; 4] = [0x79, 0xc7, 0x1c, 0x23];
pub const TRANSFER_DELEGATOR_TAG: [u8; 4] = [0xfd, 0x3e, 0xf1, 0x4a];
pub const MINT_BY_OWNER_TAG: [u8; 4] = [0xd8, 0xfa, 0x65, 0x08];
pub const MINT_PUBLIC_TAG: [u8; 4] = [0xe7, 0xe1, 0x85, 0x05];
pub const BURN_TAG: [u8; 4] = [0x47, 0x79, 0x51, 0x66];
pub const SET_PUBLIC_MINT_ACTIVE_TAG: [u8; 4] = [0x51, 0x90, 0x76, 0x35];

pub struct Kcc20StandardDecoder {
    pub template_hash: [u8; 32],
    profile: crate::token_profiles::TokenProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kcc20StandardState {
    pub amount: String,
    pub owner: String,
    pub owner_scheme: u8,
    pub owner_scheme_name: &'static str,
    pub borrow_scheme: u8,
    pub borrow_scheme_name: &'static str,
    pub borrow_guard: String,
    pub extension_commitment: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Kcc20DeployOutputState {
    pub role: &'static str,
    pub script_hash: [u8; 32],
    pub state: Value,
}

impl Kcc20StandardDecoder {
    pub fn new(template_hash: [u8; 32]) -> Self {
        let profile = crate::token_profiles::bundled_profiles()
            .iter()
            .find(|p| hex::encode(template_hash) == p.template_hash)
            .expect("native KCC20 template must be in the bundled registry")
            .clone();
        Self {
            template_hash,
            profile,
        }
    }

    pub fn from_profile(profile: crate::token_profiles::TokenProfile) -> Result<Self> {
        let template_hash = hex::decode(&profile.template_hash)?
            .try_into()
            .map_err(|_| anyhow!("invalid profile template hash"))?;
        Ok(Self {
            template_hash,
            profile,
        })
    }

    pub fn template_hash_of_compiled_script(script: &[u8]) -> Result<[u8; 32]> {
        if script.len() < KCC20_STATE_START + KCC20_STATE_LEN {
            return Err(anyhow!(
                "KCC20 script is too short for canonical state layout"
            ));
        }
        let prefix = &script[..KCC20_STATE_START];
        let suffix = &script[KCC20_STATE_START + KCC20_STATE_LEN..];
        let mut preimage = Vec::with_capacity(16 + prefix.len() + suffix.len());
        preimage.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
        preimage.extend_from_slice(prefix);
        preimage.extend_from_slice(&(suffix.len() as u64).to_le_bytes());
        preimage.extend_from_slice(suffix);
        Ok(*blake3::hash(&preimage).as_bytes())
    }
}

impl TemplateDecoder for Kcc20StandardDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20
    }

    fn script_hash(&self) -> [u8; 32] {
        self.template_hash
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        reveal.len() == self.profile.script_length
            && crate::token_profiles::template_hash(reveal, self.profile.state_layout.start)
                .is_ok_and(|hash| hash == self.template_hash)
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        if !self.matches_reveal_script(payload) {
            return Err(anyhow!("KCC20 reveal does not match profile"));
        }
        let start = self.profile.state_layout.start;
        let state = decode_state_payload(&payload[start..start + KCC20_STATE_LEN])?;
        Ok(json!({
            "standard": "KCC20",
            "state": state,
            "templateHash": hex::encode(self.template_hash),
            "profileId": self.profile.id,
            "decimals": self.profile.display_decimals,
            "standardRevision": self.profile.standard_revision,
        }))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        Ok(serde_json::to_value(decode_state_payload(payload)?)?)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let tag = action_tag(signature_script)?;
        if hex::encode(tag) == self.profile.transfer_tag {
            return Some("transfer".into());
        }
        if hex::encode(tag) == self.profile.delegator_tag {
            return Some("transfer_delegator".into());
        }
        if self.profile.native_extensions {
            action_name(tag).map(str::to_owned)
        } else {
            None
        }
    }
}

pub fn decode_reveal_state(payload: &[u8]) -> Result<Kcc20StandardState> {
    let profile = crate::token_profiles::profile_for_reveal(payload)
        .ok_or_else(|| anyhow!("unknown KCC20 reveal template"))?;
    let start = profile.state_layout.start;
    decode_state_payload(&payload[start..start + KCC20_STATE_LEN])
}

pub fn decode_state_payload(payload: &[u8]) -> Result<Kcc20StandardState> {
    if payload.len() != KCC20_STATE_LEN {
        return Err(anyhow!(
            "KCC20 state is {} bytes, expected {}",
            payload.len(),
            KCC20_STATE_LEN
        ));
    }
    expect_push(payload, 0, 8, "amount")?;
    expect_push(payload, 9, 32, "owner")?;
    expect_push(payload, 42, 1, "owner_scheme")?;
    expect_push(payload, 44, 1, "borrow_scheme")?;
    expect_push(payload, 46, 32, "borrow_guard")?;
    expect_push(payload, 79, 32, "extension_commitment")?;

    let owner_scheme = payload[43];
    let borrow_scheme = payload[45];
    Ok(Kcc20StandardState {
        amount: parse_minimal_int(&payload[1..9]).to_string(),
        owner: hex::encode(&payload[10..42]),
        owner_scheme,
        owner_scheme_name: owner_scheme_name(owner_scheme),
        borrow_scheme,
        borrow_scheme_name: borrow_scheme_name(borrow_scheme),
        borrow_guard: hex::encode(&payload[47..79]),
        extension_commitment: hex::encode(&payload[80..112]),
    })
}

pub fn deploy_output_states_from_claimed_args(
    claimed_args: &Value,
) -> Result<Vec<Kcc20DeployOutputState>> {
    let creator = claim_hex32(claimed_args, "creator")
        .ok_or_else(|| anyhow!("missing KCC20 creator claim"))?;
    let max_supply = decode_supply_claim(claimed_args, "maxSupply")
        .ok_or_else(|| anyhow!("missing KCC20 maxSupply claim"))?;
    let premint_supply = decode_supply_claim(claimed_args, "premintSupply").unwrap_or(0);
    let mint_policy = claim_u8(claimed_args, "mintPolicy")
        .ok_or_else(|| anyhow!("missing KCC20 mintPolicy claim"))?;
    let display_scale = claim_i128(claimed_args, "displayScale")
        .ok_or_else(|| anyhow!("missing KCC20 displayScale claim"))?;
    let mint_lane_count = claim_i128(claimed_args, "mintLaneCount").unwrap_or(1);
    let mint_price_sompi = claim_i128(claimed_args, "mintPriceSompi").unwrap_or(0);
    let treasury = claim_hex32(claimed_args, "treasury")
        .ok_or_else(|| anyhow!("missing KCC20 treasury claim"))?;
    let protocol_fee_recipient = claim_hex32(claimed_args, "protocolFeeRecipient")
        .ok_or_else(|| anyhow!("missing KCC20 protocolFeeRecipient claim"))?;
    let protocol_fee_bps = claim_i128(claimed_args, "protocolFeeBps").unwrap_or(200);
    let ticker = ascii_bytes32(&claim_string(claimed_args, "ticker").unwrap_or_default());
    let name = ascii_bytes32(&claim_string(claimed_args, "name").unwrap_or_default());
    if max_supply <= 0
        || max_supply > MAX_WIDE_KCC20_SUPPLY
        || !is_valid_display_scale(display_scale)
    {
        return Err(anyhow!("KCC20 maxSupply or displayScale is invalid"));
    }
    if !(1..=10).contains(&mint_lane_count) {
        return Err(anyhow!("KCC20 mintLaneCount must be 1..10"));
    }
    if premint_supply < 0 || premint_supply > max_supply {
        return Err(anyhow!("KCC20 premintSupply is outside maxSupply"));
    }
    if mint_policy > 2 {
        return Err(anyhow!("KCC20 mintPolicy must be 0, 1, or 2"));
    }
    if mint_policy != 0 && max_supply > MAX_KCC20_AMOUNT {
        return Err(anyhow!(
            "mintable KCC20 maxSupply must fit one signed 64-bit amount"
        ));
    }
    if mint_price_sompi < 0 || !(0..=10_000).contains(&protocol_fee_bps) {
        return Err(anyhow!("KCC20 mint price or protocol fee is invalid"));
    }

    let creator_bytes = hex32(&creator)?;
    let zero = [0u8; 32];
    let mut extension = MintExtension {
        kind: if max_supply > MAX_KCC20_AMOUNT { 2 } else { 1 },
        creator: creator_bytes.to_vec(),
        ticker: ticker.to_vec(),
        name: name.to_vec(),
        display_scale,
        max_supply,
        mint_lane_count,
        mint_policy,
        mint_price_sompi,
        treasury: hex32(&treasury)?.to_vec(),
        protocol_fee_recipient: hex32(&protocol_fee_recipient)?.to_vec(),
        protocol_fee_bps,
        remaining_supply: max_supply - premint_supply,
        public_mint_active: false,
        holder_extension_commitment: Vec::new(),
    };
    let holder_extension_commitment = extension.holder_commitment();
    if let Some(claimed_commitment) = claim_hex32(claimed_args, "holderExtensionCommitment") {
        if hex32(&claimed_commitment)? != holder_extension_commitment {
            return Err(anyhow!(
                "KCC20 holder extension commitment does not match immutable metadata"
            ));
        }
    }
    extension.holder_extension_commitment = holder_extension_commitment.to_vec();
    let mut outputs = Vec::new();
    if mint_policy == 0 {
        if premint_supply != max_supply {
            return Err(anyhow!("fixed KCC20 deploy must premint maxSupply"));
        }
        if let Some(reserves) = claim_value(claimed_args, "snapshotReserves") {
            return snapshot_reserve_outputs(reserves, max_supply, holder_extension_commitment);
        }
        if max_supply > MAX_KCC20_AMOUNT {
            return Err(anyhow!("wide fixed KCC20 deploy requires snapshotReserves"));
        }
        let holder_owner =
            claim_hex32(claimed_args, "premintRecipient").unwrap_or_else(|| creator.clone());
        let holder_scheme = claim_u8(claimed_args, "premintOwnerScheme").unwrap_or(0);
        let state = Kcc20StandardState {
            amount: max_supply.to_string(),
            owner: holder_owner,
            owner_scheme: holder_scheme,
            owner_scheme_name: owner_scheme_name(holder_scheme),
            borrow_scheme: 0,
            borrow_scheme_name: borrow_scheme_name(0),
            borrow_guard: hex::encode(zero),
            extension_commitment: hex::encode(holder_extension_commitment),
        };
        outputs.push(deploy_output("holder", &state)?);
        return Ok(outputs);
    }

    let remaining_supply = max_supply - premint_supply;
    if remaining_supply <= 0 {
        return Err(anyhow!("mintable KCC20 deploy must leave remaining supply"));
    }
    extension.remaining_supply = remaining_supply;
    let lane_supplies = split_supply(remaining_supply, mint_lane_count)?;
    for (index, lane_supply) in lane_supplies.into_iter().enumerate() {
        let minter_state = Kcc20StandardState {
            amount: "0".to_string(),
            owner: creator.clone(),
            owner_scheme: 0,
            owner_scheme_name: owner_scheme_name(0),
            borrow_scheme: 0,
            borrow_scheme_name: borrow_scheme_name(0),
            borrow_guard: hex::encode(zero),
            extension_commitment: hex::encode(extension.commitment(lane_supply, false)),
        };
        let mut minter = serde_json::to_value(&minter_state)?;
        merge_object(
            &mut minter,
            json!({
                "isMintAuthority": true,
                "remainingSupply": lane_supply.to_string(),
                "publicMintActive": false,
                "mintPolicy": mint_policy,
                "mintLane": index + 1,
                "mintLaneCount": mint_lane_count,
                "extension": extension.value_with(lane_supply, false),
            }),
        );
        outputs.push(deploy_output_value("minter", minter)?);
    }

    if premint_supply > 0 {
        let holder_owner =
            claim_hex32(claimed_args, "premintRecipient").unwrap_or_else(|| creator.clone());
        let holder_scheme = claim_u8(claimed_args, "premintOwnerScheme").unwrap_or(0);
        let state = Kcc20StandardState {
            amount: premint_supply.to_string(),
            owner: holder_owner,
            owner_scheme: holder_scheme,
            owner_scheme_name: owner_scheme_name(holder_scheme),
            borrow_scheme: 0,
            borrow_scheme_name: borrow_scheme_name(0),
            borrow_guard: hex::encode(zero),
            extension_commitment: hex::encode(holder_extension_commitment),
        };
        outputs.push(deploy_output("premint", &state)?);
    }
    Ok(outputs)
}

/// Decode only the entrypoints reviewed for the revealed implementation.
pub fn decode_action_args_for_reveal(
    signature_script: &[u8],
    reveal: &[u8],
) -> Result<Option<Value>> {
    let Some(profile) = crate::token_profiles::profile_for_reveal(reveal) else {
        return Ok(None);
    };
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };
    if hex::encode(tag) == profile.transfer_tag {
        let states = decode_state_record_arrays_with_limit(&items, 0, profile.max_token_outputs)?;
        if states.len() > profile.max_token_outputs {
            return Err(anyhow!("KCC20 state array exceeds approved profile bound"));
        }
        return Ok(Some(json!({ "nextStates": states })));
    }
    if profile.native_extensions {
        return decode_action_args(signature_script);
    }
    // Custom mint, burn and metadata entrypoints are intentionally opaque.
    Ok(None)
}

pub fn decode_action_args(signature_script: &[u8]) -> Result<Option<Value>> {
    let prefix = args_prefix_before_reveal(signature_script);
    let items = script_items(prefix);
    let Some(tag) = items.last().and_then(item_tag) else {
        return Ok(None);
    };

    let args = if tag == TRANSFER_TAG {
        json!({ "nextStates": decode_state_record_arrays(&items, 0)? })
    } else if tag == BURN_TAG {
        json!({
            "nextStates": decode_state_record_arrays(&items, 0)?,
            "burnAmount": item_int(&items, 6)?.to_string(),
        })
    } else if tag == MINT_BY_OWNER_TAG {
        let extension = decode_mint_extension(&items, 0)?;
        json!({
            "extension": extension.value(),
            "extensionCommitment": hex::encode(extension.commitment(extension.remaining_supply, extension.public_mint_active)),
            "tokenAmount": item_int(&items, 20)?.to_string(),
            "tokenOutputIndex": item_int(&items, 21)?.to_string(),
            "minterOutputIndex": item_int(&items, 22)?.to_string(),
            "treasuryOutputIndex": item_int(&items, 23)?.to_string(),
            "feeOutputIndex": item_int(&items, 24)?.to_string(),
            "outputStates": decode_mint_output_states(&items, &extension, 16, 17, 18, 19, 20, 21, 22)?,
        })
    } else if tag == MINT_PUBLIC_TAG {
        let extension = decode_mint_extension(&items, 0)?;
        json!({
            "extension": extension.value(),
            "extensionCommitment": hex::encode(extension.commitment(extension.remaining_supply, extension.public_mint_active)),
            "tokenAmount": item_int(&items, 19)?.to_string(),
            "tokenOutputIndex": item_int(&items, 20)?.to_string(),
            "minterOutputIndex": item_int(&items, 21)?.to_string(),
            "treasuryOutputIndex": item_int(&items, 22)?.to_string(),
            "feeOutputIndex": item_int(&items, 23)?.to_string(),
            "outputStates": decode_mint_output_states(&items, &extension, 15, 16, 17, 18, 19, 20, 21)?,
        })
    } else if tag == SET_PUBLIC_MINT_ACTIVE_TAG {
        let extension = decode_mint_extension(&items, 0)?;
        let active = item_int(&items, 16)? != 0;
        let next_extension = extension.value_with(extension.remaining_supply, active);
        json!({
            "extension": extension.value(),
            "extensionCommitment": hex::encode(extension.commitment(extension.remaining_supply, extension.public_mint_active)),
            "active": active,
            "minterOutputIndex": item_int(&items, 17)?.to_string(),
            "nextExtensionCommitment": hex::encode(extension.commitment(extension.remaining_supply, active)),
            "outputStates": [{
                "outputIndex": item_int(&items, 17)?.to_string(),
                "state": {
                    "amount": "0",
                    "owner": hex::encode(&extension.creator),
                    "ownerScheme": 0,
                    "borrowScheme": 0,
                    "borrowGuard": "00".repeat(32),
                    "extensionCommitment": hex::encode(extension.commitment(extension.remaining_supply, active)),
                    "isMintAuthority": true,
                    "mintPolicy": extension.mint_policy,
                    "remainingSupply": extension.remaining_supply.to_string(),
                    "publicMintActive": active,
                    "extension": next_extension,
                }
            }],
        })
    } else if tag == TRANSFER_DELEGATOR_TAG {
        return Ok(None);
    } else {
        return Ok(None);
    };
    Ok(Some(args))
}

#[derive(Debug, Clone)]
struct MintExtension {
    kind: u8,
    creator: Vec<u8>,
    ticker: Vec<u8>,
    name: Vec<u8>,
    display_scale: i128,
    max_supply: i128,
    mint_lane_count: i128,
    mint_policy: u8,
    mint_price_sompi: i128,
    treasury: Vec<u8>,
    protocol_fee_recipient: Vec<u8>,
    protocol_fee_bps: i128,
    remaining_supply: i128,
    public_mint_active: bool,
    holder_extension_commitment: Vec<u8>,
}

impl MintExtension {
    fn holder_commitment(&self) -> [u8; 32] {
        let mut payload = Vec::with_capacity(251);
        payload.extend_from_slice(if self.kind == 2 {
            b"KASPACOM/KCC20/HOLDER/V2"
        } else {
            b"KASPACOM/KCC20/HOLDER/V1"
        });
        payload.push(self.kind);
        payload.extend_from_slice(&self.creator);
        payload.extend_from_slice(&self.ticker);
        payload.extend_from_slice(&self.name);
        payload.extend_from_slice(&script_i64_payload(self.display_scale));
        if self.kind == 2 {
            let (high, low) = wide_amount_limbs(self.max_supply);
            payload.extend_from_slice(&script_i64_payload(high));
            payload.extend_from_slice(&script_i64_payload(low));
        } else {
            payload.extend_from_slice(&script_i64_payload(self.max_supply));
        }
        payload.extend_from_slice(&script_i64_payload(self.mint_lane_count));
        payload.push(self.mint_policy);
        payload.extend_from_slice(&script_i64_payload(self.mint_price_sompi));
        payload.extend_from_slice(&self.treasury);
        payload.extend_from_slice(&self.protocol_fee_recipient);
        payload.extend_from_slice(&script_i64_payload(self.protocol_fee_bps));
        *blake3::hash(&payload).as_bytes()
    }

    fn value(&self) -> Value {
        json!({
            "kind": self.kind,
            "creator": hex::encode(&self.creator),
            "ticker": decode_fixed_ascii(&self.ticker),
            "name": decode_fixed_ascii(&self.name),
            "displayScale": self.display_scale.to_string(),
            "maxSupply": self.max_supply.to_string(),
            "mintLaneCount": self.mint_lane_count,
            "mintPolicy": self.mint_policy,
            "mintPriceSompi": self.mint_price_sompi.to_string(),
            "treasury": hex::encode(&self.treasury),
            "protocolFeeRecipient": hex::encode(&self.protocol_fee_recipient),
            "protocolFeeBps": self.protocol_fee_bps.to_string(),
            "remainingSupply": self.remaining_supply.to_string(),
            "publicMintActive": self.public_mint_active,
            "holderExtensionCommitment": hex::encode(&self.holder_extension_commitment),
        })
    }

    fn commitment(&self, remaining_supply: i128, public_mint_active: bool) -> [u8; 32] {
        let mut payload = Vec::with_capacity(235);
        payload.push(self.kind);
        payload.extend_from_slice(&self.creator);
        payload.extend_from_slice(&self.ticker);
        payload.extend_from_slice(&self.name);
        payload.extend_from_slice(&script_i64_payload(self.display_scale));
        payload.extend_from_slice(&script_i64_payload(self.max_supply));
        payload.extend_from_slice(&script_i64_payload(self.mint_lane_count));
        payload.push(self.mint_policy);
        payload.extend_from_slice(&script_i64_payload(self.mint_price_sompi));
        payload.extend_from_slice(&self.treasury);
        payload.extend_from_slice(&self.protocol_fee_recipient);
        payload.extend_from_slice(&script_i64_payload(self.protocol_fee_bps));
        payload.extend_from_slice(&script_i64_payload(remaining_supply));
        payload.push(u8::from(public_mint_active));
        payload.extend_from_slice(&self.holder_extension_commitment);
        *blake3::hash(&payload).as_bytes()
    }

    fn value_with(&self, remaining_supply: i128, public_mint_active: bool) -> Value {
        let mut value = self.value();
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "remainingSupply".to_string(),
                Value::String(remaining_supply.to_string()),
            );
            object.insert(
                "publicMintActive".to_string(),
                Value::Bool(public_mint_active),
            );
        }
        value
    }
}

fn decode_mint_extension(items: &[ScriptItem], start: usize) -> Result<MintExtension> {
    Ok(MintExtension {
        kind: item_u8(items, start)?,
        creator: item_fixed_data(items, start + 1, 32, "creator")?.to_vec(),
        ticker: item_fixed_data(items, start + 2, 32, "ticker")?.to_vec(),
        name: item_fixed_data(items, start + 3, 32, "name")?.to_vec(),
        display_scale: item_int(items, start + 4)?,
        max_supply: item_int(items, start + 5)?,
        mint_lane_count: item_int(items, start + 6)?,
        mint_policy: item_u8(items, start + 7)?,
        mint_price_sompi: item_int(items, start + 8)?,
        treasury: item_fixed_data(items, start + 9, 32, "treasury")?.to_vec(),
        protocol_fee_recipient: item_fixed_data(items, start + 10, 32, "protocol fee recipient")?
            .to_vec(),
        protocol_fee_bps: item_int(items, start + 11)?,
        remaining_supply: item_int(items, start + 12)?,
        public_mint_active: item_int(items, start + 13)? != 0,
        holder_extension_commitment: item_fixed_data(
            items,
            start + 14,
            32,
            "holder extension commitment",
        )?
        .to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_mint_output_states(
    items: &[ScriptItem],
    extension: &MintExtension,
    owner_index: usize,
    owner_scheme_index: usize,
    borrow_scheme_index: usize,
    borrow_guard_index: usize,
    amount_index: usize,
    token_output_index: usize,
    minter_output_index: usize,
) -> Result<Vec<Value>> {
    let amount = item_int(items, amount_index)?;
    let token_index = item_int(items, token_output_index)?;
    let mut outputs = vec![json!({
        "outputIndex": token_index.to_string(),
        "state": {
            "amount": amount.to_string(),
            "owner": hex::encode(item_fixed_data(items, owner_index, 32, "recipient owner")?),
            "ownerScheme": item_u8(items, owner_scheme_index)?,
            "borrowScheme": item_u8(items, borrow_scheme_index)?,
            "borrowGuard": hex::encode(item_fixed_data(items, borrow_guard_index, 32, "recipient borrow guard")?),
            "extensionCommitment": hex::encode(&extension.holder_extension_commitment),
        }
    })];
    let remaining = extension.remaining_supply - amount;
    if remaining > 0 {
        let next_extension = extension.value_with(remaining, extension.public_mint_active);
        outputs.push(json!({
            "outputIndex": item_int(items, minter_output_index)?.to_string(),
            "state": {
                "amount": "0",
                "owner": hex::encode(&extension.creator),
                "ownerScheme": 0,
                "borrowScheme": 0,
                "borrowGuard": "00".repeat(32),
                "extensionCommitment": hex::encode(extension.commitment(remaining, extension.public_mint_active)),
                "isMintAuthority": true,
                "mintPolicy": extension.mint_policy,
                "remainingSupply": remaining.to_string(),
                "publicMintActive": extension.public_mint_active,
                "extension": next_extension,
            }
        }));
    }
    Ok(outputs)
}

pub fn action_tag(signature_script: &[u8]) -> Option<[u8; 4]> {
    let prefix = args_prefix_before_reveal(signature_script);
    script_items(prefix).last().and_then(item_tag)
}

fn action_name(tag: [u8; 4]) -> Option<&'static str> {
    match tag {
        TRANSFER_TAG => Some("transfer"),
        TRANSFER_DELEGATOR_TAG => Some("transfer_delegator"),
        MINT_BY_OWNER_TAG => Some("mint_by_owner"),
        MINT_PUBLIC_TAG => Some("mint_public"),
        BURN_TAG => Some("burn"),
        SET_PUBLIC_MINT_ACTIVE_TAG => Some("set_public_mint_active"),
        _ => None,
    }
}

pub fn item_tag(item: &ScriptItem) -> Option<[u8; 4]> {
    match item {
        ScriptItem::Data(bytes) if bytes.len() == 4 => bytes.as_slice().try_into().ok(),
        _ => None,
    }
}

fn decode_state_record_arrays(items: &[ScriptItem], start: usize) -> Result<Vec<Value>> {
    decode_state_record_arrays_with_limit(items, start, 8)
}

fn decode_state_record_arrays_with_limit(
    items: &[ScriptItem],
    start: usize,
    limit: usize,
) -> Result<Vec<Value>> {
    let amounts = item_data(items, start)?;
    if amounts.len() % 8 != 0 {
        return Err(anyhow!("KCC20 amount array is not a multiple of 8 bytes"));
    }
    let count = amounts.len() / 8;
    if count > limit {
        return Err(anyhow!("KCC20 state array exceeds profile bound"));
    }
    let owners = fixed_record_bytes(items, start + 1, count, 32, "owner")?;
    let owner_schemes = fixed_record_bytes(items, start + 2, count, 1, "owner_scheme")?;
    let borrow_schemes = fixed_record_bytes(items, start + 3, count, 1, "borrow_scheme")?;
    let borrow_guards = fixed_record_bytes(items, start + 4, count, 32, "borrow_guard")?;
    let extensions = fixed_record_bytes(items, start + 5, count, 32, "extension_commitment")?;

    Ok((0..count)
        .map(|index| {
            let amount = parse_minimal_int(&amounts[index * 8..(index + 1) * 8]);
            json!({
                "amount": amount.to_string(),
                "owner": hex::encode(&owners[index * 32..(index + 1) * 32]),
                "ownerScheme": owner_schemes[index],
                "ownerSchemeName": owner_scheme_name(owner_schemes[index]),
                "borrowScheme": borrow_schemes[index],
                "borrowSchemeName": borrow_scheme_name(borrow_schemes[index]),
                "borrowGuard": hex::encode(&borrow_guards[index * 32..(index + 1) * 32]),
                "extensionCommitment": hex::encode(&extensions[index * 32..(index + 1) * 32]),
            })
        })
        .collect())
}

fn fixed_record_bytes<'a>(
    items: &'a [ScriptItem],
    index: usize,
    count: usize,
    width: usize,
    label: &str,
) -> Result<Cow<'a, [u8]>> {
    let bytes = item_data(items, index)?;
    if bytes.len() != count * width {
        return Err(anyhow!(
            "KCC20 {label} array has invalid byte length {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn item_data(items: &[ScriptItem], index: usize) -> Result<Cow<'_, [u8]>> {
    match items.get(index) {
        Some(ScriptItem::Data(bytes)) => Ok(Cow::Borrowed(bytes)),
        Some(ScriptItem::Int(value)) => Ok(Cow::Owned(minimal_script_num_payload(*value))),
        _ => Err(anyhow!("KCC20 sigscript item {index} is not byte data")),
    }
}

fn minimal_script_num_payload(value: i128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude > 0 {
        bytes.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0 });
    } else if negative {
        *bytes.last_mut().expect("non-zero script number") |= 0x80;
    }
    bytes
}

fn item_int(items: &[ScriptItem], index: usize) -> Result<i128> {
    items
        .get(index)
        .and_then(ScriptItem::as_int)
        .ok_or_else(|| anyhow!("KCC20 sigscript item {index} is not an int"))
}

fn item_u8(items: &[ScriptItem], index: usize) -> Result<u8> {
    let value = item_int(items, index)?;
    u8::try_from(value).map_err(|_| anyhow!("KCC20 sigscript item {index} is not a byte"))
}

fn item_fixed_data<'a>(
    items: &'a [ScriptItem],
    index: usize,
    width: usize,
    label: &str,
) -> Result<Cow<'a, [u8]>> {
    let bytes = item_data(items, index)?;
    if bytes.len() != width {
        return Err(anyhow!("KCC20 {label} must be {width} bytes"));
    }
    Ok(bytes)
}

fn expect_push(payload: &[u8], offset: usize, expected: u8, label: &str) -> Result<()> {
    if payload.get(offset).copied() != Some(expected) {
        return Err(anyhow!("KCC20 {label} push is not OP_DATA_{expected}"));
    }
    Ok(())
}

#[cfg(test)]
fn signed_i64_payload(value: i64) -> [u8; 8] {
    script_i64_payload(i128::from(value))
}

fn script_i64_payload(value: i128) -> [u8; 8] {
    debug_assert!(value >= -9_223_372_036_854_775_807 && value <= 9_223_372_036_854_775_807);
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut output = [0u8; 8];
    for byte in &mut output {
        *byte = (magnitude & 0xff) as u8;
        magnitude >>= 8;
    }
    if negative {
        output[7] |= 0x80;
    }
    output
}

fn is_valid_display_scale(value: i128) -> bool {
    matches!(
        value,
        1 | 10 | 100 | 1_000 | 10_000 | 100_000 | 1_000_000 | 10_000_000 | 100_000_000
    )
}

fn split_supply(remaining: i128, lane_count: i128) -> Result<Vec<i128>> {
    if !(1..=10).contains(&lane_count) || remaining < lane_count {
        return Err(anyhow!(
            "KCC20 remaining supply cannot be split across mint lanes"
        ));
    }
    let base = remaining / lane_count;
    let remainder = remaining % lane_count;
    Ok((0..lane_count)
        .map(|index| base + if index < remainder { 1 } else { 0 })
        .collect())
}

fn wide_amount_limbs(value: i128) -> (i128, i128) {
    let base = 1_i128 << 63;
    (value / base, value % base)
}

fn snapshot_reserve_outputs(
    reserves: &Value,
    max_supply: i128,
    holder_extension_commitment: [u8; 32],
) -> Result<Vec<Kcc20DeployOutputState>> {
    let reserves = reserves
        .as_array()
        .ok_or_else(|| anyhow!("KCC20 snapshotReserves must be an array"))?;
    if reserves.is_empty() || reserves.len() > 8 {
        return Err(anyhow!("KCC20 snapshotReserves must contain 1..8 reserves"));
    }

    let zero = [0u8; 32];
    let mut total = 0_i128;
    let mut outputs = Vec::with_capacity(reserves.len());
    for (index, reserve) in reserves.iter().enumerate() {
        let shard_index = json_i128(reserve.get("shardIndex"))
            .ok_or_else(|| anyhow!("KCC20 snapshot reserve shardIndex is missing"))?;
        if shard_index != index as i128 {
            return Err(anyhow!(
                "KCC20 snapshot reserve shardIndex must be contiguous from zero"
            ));
        }
        let amount = json_i128(reserve.get("amount"))
            .ok_or_else(|| anyhow!("KCC20 snapshot reserve amount is missing"))?;
        if !(1..=MAX_KCC20_AMOUNT).contains(&amount) {
            return Err(anyhow!(
                "KCC20 snapshot reserve amount is outside signed 64-bit range"
            ));
        }
        total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow!("KCC20 snapshot reserve total overflows"))?;
        let owner = reserve
            .get("owner")
            .and_then(Value::as_str)
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .map(str::to_ascii_lowercase)
            .ok_or_else(|| anyhow!("KCC20 snapshot reserve owner is invalid"))?;
        let owner_scheme = json_i128(reserve.get("ownerScheme"))
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| anyhow!("KCC20 snapshot reserve ownerScheme is invalid"))?;
        if owner_scheme != 4 {
            return Err(anyhow!(
                "KCC20 snapshot reserve ownerScheme must be covenant-id"
            ));
        }
        let state = Kcc20StandardState {
            amount: amount.to_string(),
            owner,
            owner_scheme,
            owner_scheme_name: owner_scheme_name(owner_scheme),
            borrow_scheme: 0,
            borrow_scheme_name: borrow_scheme_name(0),
            borrow_guard: hex::encode(zero),
            extension_commitment: hex::encode(holder_extension_commitment),
        };
        outputs.push(deploy_output("reserve", &state)?);
    }
    if total != max_supply {
        return Err(anyhow!("KCC20 snapshot reserves do not conserve maxSupply"));
    }
    Ok(outputs)
}

fn decode_fixed_ascii(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn deploy_output(role: &'static str, state: &Kcc20StandardState) -> Result<Kcc20DeployOutputState> {
    deploy_output_value(role, serde_json::to_value(state)?)
}

fn deploy_output_value(role: &'static str, state: Value) -> Result<Kcc20DeployOutputState> {
    let script = script_for_state_value(&state)?;
    Ok(Kcc20DeployOutputState {
        role,
        script_hash: blake2b_256(&script),
        state,
    })
}

pub fn script_for_state_value(state: &Value) -> Result<Vec<u8>> {
    script_for_state_value_with_reveal(state, &placeholder_script())
}

/// Rebuild a KCC20 script from an authenticated template witness and decoded state.
pub fn script_for_state_value_with_template_parts(
    state: &Value,
    prefix: &[u8],
    suffix: &[u8],
) -> Result<Vec<u8>> {
    let native = script_for_state_value(state)?;
    let mut script = Vec::with_capacity(prefix.len() + KCC20_STATE_LEN + suffix.len());
    script.extend_from_slice(prefix);
    script.extend_from_slice(&native[KCC20_STATE_START..KCC20_STATE_START + KCC20_STATE_LEN]);
    script.extend_from_slice(suffix);
    Ok(script)
}

/// Preserve the authenticated implementation while replacing only its reviewed state range.
pub fn script_for_state_value_with_reveal(state: &Value, reveal: &[u8]) -> Result<Vec<u8>> {
    let profile = crate::token_profiles::profile_for_reveal(reveal)
        .ok_or_else(|| anyhow!("unknown KCC20 reveal template"))?;
    let start = profile.state_layout.start;
    let mut script = reveal.to_vec();
    let amount =
        json_i128(state.get("amount")).ok_or_else(|| anyhow!("KCC20 state amount is missing"))?;
    if amount < 0 || amount > i64::MAX as i128 {
        return Err(anyhow!("KCC20 holder amount outside signed 64-bit range"));
    }
    let owner = state
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("KCC20 state owner is missing"))?;
    let owner_scheme = json_i128(state.get("ownerScheme"))
        .ok_or_else(|| anyhow!("KCC20 owner scheme is missing"))?;
    let borrow_scheme = json_i128(state.get("borrowScheme"))
        .ok_or_else(|| anyhow!("KCC20 borrow scheme is missing"))?;
    let borrow_guard = state
        .get("borrowGuard")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("KCC20 borrow guard is missing"))?;
    let extension = state
        .get("extensionCommitment")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("KCC20 extension commitment is missing"))?;

    script[start + 1..start + 9].copy_from_slice(&script_i64_payload(amount));
    script[start + 10..start + 42].copy_from_slice(&hex32(owner)?);
    script[start + 43] =
        u8::try_from(owner_scheme).map_err(|_| anyhow!("invalid KCC20 owner scheme"))?;
    script[start + 45] =
        u8::try_from(borrow_scheme).map_err(|_| anyhow!("invalid KCC20 borrow scheme"))?;
    script[start + 47..start + 79].copy_from_slice(&hex32(borrow_guard)?);
    script[start + 80..start + 112].copy_from_slice(&hex32(extension)?);
    Ok(script)
}

fn placeholder_script() -> Vec<u8> {
    let artifact: Value =
        serde_json::from_str(include_str!("../fixtures/kcc20/KCC20.placeholder.json"))
            .expect("embedded KCC20 artifact JSON");
    artifact["script"]
        .as_array()
        .expect("embedded KCC20 artifact script")
        .iter()
        .map(|value| value.as_u64().expect("KCC20 script byte") as u8)
        .collect()
}

fn ascii_bytes32(value: &str) -> [u8; 32] {
    let mut output = [0u8; 32];
    let bytes = value.as_bytes();
    let length = bytes.len().min(output.len());
    output[..length].copy_from_slice(&bytes[..length]);
    output
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    let mut output = [0u8; 32];
    hex::decode_to_slice(value, &mut output).context("KCC20 field is not 32-byte hex")?;
    Ok(output)
}

fn claim_argument<'a>(claimed_args: &'a Value, name: &str) -> Option<&'a Value> {
    let mut matches = claimed_args
        .get("args")?
        .as_array()?
        .iter()
        .filter(|arg| arg.get("name").and_then(Value::as_str) == Some(name));
    let argument = matches.next()?;
    matches.next().is_none().then_some(argument)
}

fn claim_value<'a>(claimed_args: &'a Value, name: &str) -> Option<&'a Value> {
    claim_argument(claimed_args, name)?.get("value")
}

fn claim_string(claimed_args: &Value, name: &str) -> Option<String> {
    match claim_value(claimed_args, name)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn claim_i128(claimed_args: &Value, name: &str) -> Option<i128> {
    json_i128(claim_value(claimed_args, name))
}

/// Decode the KCC20 supply wire representation.
///
/// Ordinary supplies remain one signed-64-bit scalar. Wide fixed supplies use
/// two non-negative signed-64-bit limbs in base 2^63. The explicit `u64[2]`
/// type keeps an unrelated JSON array from being interpreted as token supply.
pub fn decode_supply_claim(claimed_args: &Value, name: &str) -> Option<i128> {
    let argument = claim_argument(claimed_args, name)?;
    match argument.get("value")? {
        Value::Array(limbs) => {
            if argument.get("type").and_then(Value::as_str) != Some("u64[2]")
                || limbs.len() != 2
            {
                return None;
            }
            let high = canonical_wide_limb(&limbs[0])?;
            let low = canonical_wide_limb(&limbs[1])?;
            if high == 0 {
                return None;
            }
            let amount = high.checked_mul(1_i128 << 63)?.checked_add(low)?;
            (amount > MAX_KCC20_AMOUNT && amount <= MAX_WIDE_KCC20_SUPPLY).then_some(amount)
        }
        value => {
            let amount = json_i128(Some(value))?;
            (0..=MAX_KCC20_AMOUNT).contains(&amount).then_some(amount)
        }
    }
}

fn canonical_wide_limb(value: &Value) -> Option<i128> {
    let Value::String(value) = value else {
        return None;
    };
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    let limb = value.parse::<i128>().ok()?;
    (0..=MAX_KCC20_AMOUNT).contains(&limb).then_some(limb)
}

fn claim_u8(claimed_args: &Value, name: &str) -> Option<u8> {
    claim_i128(claimed_args, name).and_then(|value| u8::try_from(value).ok())
}

fn claim_hex32(claimed_args: &Value, name: &str) -> Option<String> {
    claim_string(claimed_args, name)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(|value| value.to_ascii_lowercase())
}

fn json_i128(value: Option<&Value>) -> Option<i128> {
    match value? {
        Value::String(value) => value.parse().ok(),
        Value::Number(value) => value
            .as_i64()
            .map(i128::from)
            .or_else(|| value.as_u64().map(i128::from)),
        _ => None,
    }
}

fn merge_object(target: &mut Value, source: Value) {
    let (Some(target), Some(source)) = (target.as_object_mut(), source.as_object()) else {
        return;
    };
    target.extend(source.clone());
}

pub fn owner_scheme_name(value: u8) -> &'static str {
    match value {
        0 => "p2pk-schnorr/v1",
        1 => "p2pkh-schnorr/v1",
        2 => "p2pkh-ecdsa/v1",
        3 => "p2sh/v1",
        4 => "covenant-id/v1",
        _ => "unknown",
    }
}

pub fn borrow_scheme_name(value: u8) -> &'static str {
    match value {
        0 => "disabled/v1",
        1 => "amount-threshold/v1",
        2 => "schnorr-signature/v1",
        3 => "hash-chain/v1",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder_script() -> Vec<u8> {
        let artifact: Value =
            serde_json::from_str(include_str!("../fixtures/kcc20/KCC20.placeholder.json"))
                .expect("KCC20 artifact JSON");
        artifact["script"]
            .as_array()
            .expect("script array")
            .iter()
            .map(|value| value.as_u64().expect("script byte") as u8)
            .collect()
    }

    #[test]
    fn placeholder_matches_universal_template_and_decodes_state() {
        let script = placeholder_script();
        assert_eq!(
            script.len(),
            crate::token_profiles::profile_for_reveal(&script)
                .unwrap()
                .script_length
        );
        let hash = Kcc20StandardDecoder::template_hash_of_compiled_script(&script).unwrap();
        let decoder = Kcc20StandardDecoder::new(hash);
        assert!(decoder.matches_reveal_script(&script));
        let state = decode_reveal_state(&script).unwrap();
        assert_eq!(state.amount, "0");
        assert_eq!(state.owner_scheme, 0);
        assert_eq!(state.borrow_scheme, 0);
    }

    #[test]
    fn state_changes_preserve_template_hash() {
        let mut script = placeholder_script();
        let expected = Kcc20StandardDecoder::template_hash_of_compiled_script(&script).unwrap();
        script[KCC20_STATE_START + 1] = 42;
        script[KCC20_STATE_START + 10] = 0xaa;
        assert_eq!(
            Kcc20StandardDecoder::template_hash_of_compiled_script(&script).unwrap(),
            expected
        );
    }

    #[test]
    fn dispatch_tags_are_decoded_as_exact_four_byte_values() {
        for (tag, expected) in [
            (TRANSFER_TAG, "transfer"),
            (TRANSFER_DELEGATOR_TAG, "transfer_delegator"),
            (MINT_BY_OWNER_TAG, "mint_by_owner"),
            (MINT_PUBLIC_TAG, "mint_public"),
            (BURN_TAG, "burn"),
            (SET_PUBLIC_MINT_ACTIVE_TAG, "set_public_mint_active"),
        ] {
            assert_eq!(action_name(tag), Some(expected));
        }
        assert_eq!(action_name([0, 0, 0, 0]), None);
    }

    #[test]
    fn deploy_claim_reconstructs_paused_minter_and_premint_outputs() {
        let owner = "11".repeat(32);
        let claim = json!({
            "tmpl": "KCC20",
            "args": [
                {"name": "creator", "value": owner},
                {"name": "maxSupply", "value": "1000"},
                {"name": "premintSupply", "value": "100"},
                {"name": "premintRecipient", "value": "22".repeat(32)},
                {"name": "premintOwnerScheme", "value": "0"},
                {"name": "mintPolicy", "value": "2"},
                {"name": "mintLaneCount", "value": "10"},
                {"name": "displayScale", "value": "100"},
                {"name": "mintPriceSompi", "value": "0"},
                {"name": "treasury", "value": "33".repeat(32)},
                {"name": "protocolFeeRecipient", "value": "44".repeat(32)},
                {"name": "protocolFeeBps", "value": "200"},
                {"name": "ticker", "value": "TEST"},
                {"name": "name", "value": "Test Token"}
            ]
        });
        let outputs = deploy_output_states_from_claimed_args(&claim).unwrap();
        assert_eq!(outputs.len(), 11);
        assert_eq!(outputs[0].role, "minter");
        assert_eq!(outputs[0].state["amount"], "0");
        assert_eq!(outputs[0].state["remainingSupply"], "90");
        assert_eq!(outputs[0].state["mintLaneCount"], 10);
        assert_eq!(outputs[9].state["remainingSupply"], "90");
        assert_eq!(outputs[10].role, "premint");
        assert_eq!(outputs[10].state["amount"], "100");
        assert_ne!(outputs[0].script_hash, outputs[10].script_hash);
    }

    #[test]
    fn deploy_claim_accepts_all_supported_decimal_scales_and_rejects_nine() {
        let owner = "11".repeat(32);
        let mut claim = json!({
            "args": [
                {"name": "creator", "value": owner},
                {"name": "maxSupply", "value": "1000"},
                {"name": "premintSupply", "value": "1000"},
                {"name": "mintPolicy", "value": "0"},
                {"name": "displayScale", "value": "1"},
                {"name": "mintPriceSompi", "value": "0"},
                {"name": "treasury", "value": "22".repeat(32)},
                {"name": "protocolFeeRecipient", "value": "33".repeat(32)},
                {"name": "ticker", "value": "TEST"},
                {"name": "name", "value": "Test Token"}
            ]
        });

        for decimals in 0..=8 {
            claim["args"][4]["value"] = json!(10_i128.pow(decimals));
            assert!(deploy_output_states_from_claimed_args(&claim).is_ok());
        }

        claim["args"][4]["value"] = json!(1_000_000_000_i128);
        assert!(deploy_output_states_from_claimed_args(&claim)
            .unwrap_err()
            .to_string()
            .contains("displayScale is invalid"));
    }

    #[test]
    fn wide_fixed_supply_reconstructs_bounded_snapshot_reserves() {
        let envelope: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20/nacho-wide-deployment-payload.v1.json"
        ))
        .unwrap();
        let mut claim = envelope["tn10"].clone();
        let expected_commitment =
            "bd2bc17e17e2a7a6fdc4a557c80fa441760a8ce31f4d09a394bed240f7f9a6e3";

        let outputs = deploy_output_states_from_claimed_args(&claim).unwrap();
        assert_eq!(outputs.len(), 5);
        assert!(outputs.iter().all(|output| output.role == "reserve"));
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.state["amount"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "6155259898638223950",
                "5951866420246839519",
                "5757775773333178726",
                "5919898242175782749",
                "4915199665605975056",
            ]
        );
        assert!(outputs.iter().all(|output| {
            output.state["extensionCommitment"] == expected_commitment
        }));

        claim["args"][17]["value"][0]["amount"] = json!("9223372036854775808");
        assert!(deploy_output_states_from_claimed_args(&claim)
            .unwrap_err()
            .to_string()
            .contains("outside signed 64-bit range"));
    }

    #[test]
    fn wide_supply_claim_requires_the_canonical_two_limb_wire_shape() {
        let envelope: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20/nacho-wide-deployment-payload.v1.json"
        ))
        .unwrap();
        let claim = envelope["tn10"].clone();
        assert_eq!(
            decode_supply_claim(&claim, "maxSupply"),
            Some(28_700_000_000_000_000_000)
        );

        let mut oversized_scalar = claim.clone();
        oversized_scalar["args"][1]["type"] = json!("u64");
        oversized_scalar["args"][1]["value"] = json!("28700000000000000000");
        assert_eq!(decode_supply_claim(&oversized_scalar, "maxSupply"), None);

        let mut wrong_type = claim.clone();
        wrong_type["args"][1]["type"] = json!("u64[3]");
        assert_eq!(decode_supply_claim(&wrong_type, "maxSupply"), None);

        let mut leading_zero = claim.clone();
        leading_zero["args"][1]["value"][0] = json!("03");
        assert_eq!(decode_supply_claim(&leading_zero, "maxSupply"), None);

        let mut numeric_limb = claim.clone();
        numeric_limb["args"][1]["value"][0] = json!(3);
        assert_eq!(decode_supply_claim(&numeric_limb, "maxSupply"), None);

        let mut zero_high_limb = claim.clone();
        zero_high_limb["args"][1]["value"][0] = json!("0");
        assert_eq!(decode_supply_claim(&zero_high_limb, "maxSupply"), None);

        let mut oversized_limb = claim.clone();
        oversized_limb["args"][1]["value"][1] = json!("9223372036854775808");
        assert_eq!(decode_supply_claim(&oversized_limb, "maxSupply"), None);

        let mut duplicate = claim;
        let duplicate_max_supply = duplicate["args"][1].clone();
        duplicate["args"]
            .as_array_mut()
            .unwrap()
            .push(duplicate_max_supply);
        assert_eq!(decode_supply_claim(&duplicate, "maxSupply"), None);
    }

    #[test]
    fn holder_commitment_binds_all_immutable_token_metadata() {
        let base = MintExtension {
            kind: 1,
            creator: vec![0x11; 32],
            ticker: ascii_bytes32("TEST").to_vec(),
            name: ascii_bytes32("Test Token").to_vec(),
            display_scale: 100,
            max_supply: 1000,
            mint_lane_count: 1,
            mint_policy: 2,
            mint_price_sompi: 10,
            treasury: vec![0x22; 32],
            protocol_fee_recipient: vec![0x33; 32],
            protocol_fee_bps: 200,
            remaining_supply: 900,
            public_mint_active: false,
            holder_extension_commitment: Vec::new(),
        };
        let expected = base.holder_commitment();

        let mut changed = base.clone();
        changed.ticker = ascii_bytes32("FAKE").to_vec();
        assert_ne!(changed.holder_commitment(), expected);
        changed = base.clone();
        changed.max_supply += 1;
        assert_ne!(changed.holder_commitment(), expected);
        changed = base.clone();
        changed.treasury[0] ^= 1;
        assert_ne!(changed.holder_commitment(), expected);
    }

    #[test]
    fn deploy_claim_rejects_a_supplied_holder_commitment_for_other_metadata() {
        let owner = "11".repeat(32);
        let claim = json!({
            "args": [
                {"name": "creator", "value": owner},
                {"name": "maxSupply", "value": "1000"},
                {"name": "premintSupply", "value": "0"},
                {"name": "mintPolicy", "value": "2"},
                {"name": "displayScale", "value": "100"},
                {"name": "mintPriceSompi", "value": "0"},
                {"name": "treasury", "value": "22".repeat(32)},
                {"name": "protocolFeeRecipient", "value": "33".repeat(32)},
                {"name": "protocolFeeBps", "value": "200"},
                {"name": "ticker", "value": "TEST"},
                {"name": "name", "value": "Test Token"},
                {"name": "holderExtensionCommitment", "value": "44".repeat(32)}
            ]
        });

        assert!(deploy_output_states_from_claimed_args(&claim)
            .unwrap_err()
            .to_string()
            .contains("does not match immutable metadata"));
    }

    #[test]
    fn public_mint_tag_decodes_extension_and_successor_states() {
        let script = placeholder_script();
        let owner = [0x11; 32];
        let holder_extension = MintExtension {
            kind: 1,
            creator: owner.to_vec(),
            ticker: ascii_bytes32("TEST").to_vec(),
            name: ascii_bytes32("Test Token").to_vec(),
            display_scale: 100,
            max_supply: 1000,
            mint_lane_count: 1,
            mint_policy: 2,
            mint_price_sompi: 0,
            treasury: vec![0x33; 32],
            protocol_fee_recipient: vec![0x44; 32],
            protocol_fee_bps: 200,
            remaining_supply: 1000,
            public_mint_active: true,
            holder_extension_commitment: Vec::new(),
        }
        .holder_commitment();
        let mut sigscript = Vec::new();
        push_int(&mut sigscript, 1);
        push_data(&mut sigscript, &owner);
        push_data(&mut sigscript, &ascii_bytes32("TEST"));
        push_data(&mut sigscript, &ascii_bytes32("Test Token"));
        push_int(&mut sigscript, 100);
        push_int(&mut sigscript, 1000);
        push_int(&mut sigscript, 1);
        push_int(&mut sigscript, 2);
        push_int(&mut sigscript, 0);
        push_data(&mut sigscript, &[0x33; 32]);
        push_data(&mut sigscript, &[0x44; 32]);
        push_int(&mut sigscript, 200);
        push_int(&mut sigscript, 1000);
        push_int(&mut sigscript, 1);
        push_data(&mut sigscript, &holder_extension);
        push_data(&mut sigscript, &[0x22; 32]);
        push_int(&mut sigscript, 0);
        push_int(&mut sigscript, 0);
        push_data(&mut sigscript, &[0; 32]);
        push_int(&mut sigscript, 100);
        push_int(&mut sigscript, 0);
        push_int(&mut sigscript, 1);
        push_int(&mut sigscript, 2);
        push_int(&mut sigscript, 3);
        push_data(&mut sigscript, &MINT_PUBLIC_TAG);
        push_data(&mut sigscript, &script);

        let decoder = Kcc20StandardDecoder::new(
            Kcc20StandardDecoder::template_hash_of_compiled_script(&script).unwrap(),
        );
        assert_eq!(
            decoder.decode_action(&sigscript).as_deref(),
            Some("mint_public")
        );
        let args = decode_action_args(&sigscript).unwrap().unwrap();
        assert_eq!(args["extension"]["publicMintActive"], true);
        assert_eq!(args["tokenAmount"], "100");
        assert_eq!(args["outputStates"][0]["state"]["amount"], "100");
        assert_eq!(args["outputStates"][1]["state"]["remainingSupply"], "900");
    }

    #[test]
    fn state_record_arrays_decode_minimal_owner_and_borrow_scheme_pushes() {
        let reveal = placeholder_script();
        for count in 1..=8 {
            for owner_scheme in 0..=4 {
                for borrow_scheme in 0..=3 {
                    let mut sigscript = Vec::new();
                    let mut amounts = Vec::new();
                    let mut owners = Vec::new();
                    let mut borrow_guards = Vec::new();
                    let mut extensions = Vec::new();
                    for ordinal in 0..count {
                        amounts.extend(signed_i64_payload((ordinal + 1) as i64));
                        owners.extend([0x20 + ordinal as u8; 32]);
                        borrow_guards.extend([0x40 + ordinal as u8; 32]);
                        extensions.extend([0x60 + ordinal as u8; 32]);
                    }
                    push_data(&mut sigscript, &amounts);
                    push_data(&mut sigscript, &owners);
                    push_record_byte_group(&mut sigscript, owner_scheme, count);
                    push_record_byte_group(&mut sigscript, borrow_scheme, count);
                    push_data(&mut sigscript, &borrow_guards);
                    push_data(&mut sigscript, &extensions);
                    push_data(&mut sigscript, &[0; 66]);
                    push_data(&mut sigscript, &TRANSFER_TAG);
                    push_data(&mut sigscript, &reveal);

                    let args = decode_action_args(&sigscript).unwrap().unwrap();
                    assert_eq!(args["nextStates"].as_array().unwrap().len(), count);
                    assert_eq!(args["nextStates"][0]["ownerScheme"], owner_scheme);
                    assert_eq!(args["nextStates"][0]["borrowScheme"], borrow_scheme);
                }
            }
        }
    }

    #[test]
    fn empty_state_record_arrays_decode_for_full_burns() {
        let reveal = placeholder_script();
        let mut sigscript = Vec::new();
        for _ in 0..6 {
            push_data(&mut sigscript, &[]);
        }
        push_int(&mut sigscript, 25);
        push_data(&mut sigscript, &[0; 66]);
        push_data(&mut sigscript, &BURN_TAG);
        push_data(&mut sigscript, &reveal);

        let args = decode_action_args(&sigscript).unwrap().unwrap();
        assert_eq!(args["nextStates"], json!([]));
        assert_eq!(args["burnAmount"], "25");
    }

    fn push_record_byte_group(script: &mut Vec<u8>, value: i64, count: usize) {
        if count == 1 && value != 0 {
            push_int(script, value);
        } else {
            push_data(script, &vec![value as u8; count]);
        }
    }

    fn push_int(script: &mut Vec<u8>, value: i64) {
        match value {
            0 => script.push(0x00),
            1..=16 => script.push(0x50 + value as u8),
            _ => {
                let mut bytes = Vec::new();
                let mut magnitude = value.unsigned_abs();
                while magnitude > 0 {
                    bytes.push((magnitude & 0xff) as u8);
                    magnitude >>= 8;
                }
                if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
                    bytes.push(0);
                }
                if value < 0 {
                    *bytes.last_mut().unwrap() |= 0x80;
                }
                push_data(script, &bytes);
            }
        }
    }

    fn push_data(script: &mut Vec<u8>, bytes: &[u8]) {
        if bytes.len() <= 75 {
            script.push(bytes.len() as u8);
        } else if bytes.len() <= u8::MAX as usize {
            script.extend([0x4c, bytes.len() as u8]);
        } else {
            script.push(0x4d);
            script.extend((bytes.len() as u16).to_le_bytes());
        }
        script.extend(bytes);
    }
}
