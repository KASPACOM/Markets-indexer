//! Decoder for the immutable signerless KRC20-to-KCC20 snapshot bootstrap.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, script_items, ScriptItem};
use crate::kcc20_standard::item_tag;
use crate::TemplateDecoder;

pub const SNAPSHOT_BOOTSTRAP_SCRIPT_LEN: usize = 35_913;
pub const SNAPSHOT_BOOTSTRAP_STATE_START: usize = 1;
pub const SNAPSHOT_BOOTSTRAP_STATE_LEN: usize = 414;
const LEGACY_SNAPSHOT_BOOTSTRAP_SCRIPT_LEN: usize = 33_718;
const LEGACY_SNAPSHOT_BOOTSTRAP_STATE_LEN: usize = 405;
// Authenticated template hash used by the accepted TN10 snapshot-start fixture.
pub(crate) const LEGACY_SNAPSHOT_BOOTSTRAP_TEMPLATE_HASH: [u8; 32] = [
    0x4e, 0x6b, 0xe0, 0xd4, 0xd6, 0x65, 0x11, 0x58, 0x92, 0x5e, 0x95, 0x2e, 0xbb, 0x28, 0x4b, 0x90,
    0x68, 0x30, 0x89, 0x27, 0x01, 0xc9, 0x85, 0x8d, 0x87, 0x9a, 0xcd, 0xb6, 0xe3, 0xce, 0x6b, 0xae,
];
const START_TAG: [u8; 4] = [0xe2, 0x8b, 0x43, 0x38];
const OWNER_COVENANT_ID: i128 = 4;
const MIN_CELL_SOMPI: i128 = 50_000_000;
const LOCK_TIME_THRESHOLD: i128 = 500_000_000_000;
const MAX_SHARDS: usize = 8;

pub struct Kcc20SnapshotBootstrapDecoder {
    template_hash: [u8; 32],
}

impl Kcc20SnapshotBootstrapDecoder {
    pub fn new(template_hash: [u8; 32]) -> Self {
        Self { template_hash }
    }

    pub fn template_hash_of_compiled_script(script: &[u8]) -> Result<[u8; 32]> {
        let state_len = state_len_for_script(script.len())?;
        let prefix = &script[..SNAPSHOT_BOOTSTRAP_STATE_START];
        let suffix = &script[SNAPSHOT_BOOTSTRAP_STATE_START + state_len..];
        Ok(template_hash(prefix, suffix))
    }
}

impl TemplateDecoder for Kcc20SnapshotBootstrapDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20SnapshotBootstrap
    }

    fn script_hash(&self) -> [u8; 32] {
        self.template_hash
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        Self::template_hash_of_compiled_script(reveal).is_ok_and(|hash| hash == self.template_hash)
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        let state = decode_reveal_state(payload)?;
        validate_state(&state)?;
        Ok(json!({
            "standard": "KCC20SnapshotBootstrap",
            "templateHash": hex::encode(self.template_hash),
            "state": state,
        }))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        let state = decode_state_payload(payload)?;
        validate_state(&state)?;
        Ok(state)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        (action_tag(signature_script) == Some(START_TAG)).then(|| "start".into())
    }
}

pub fn decode_bootstrap_action(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Value>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    if items.last().and_then(item_tag) != Some(START_TAG) {
        return Ok(None);
    }
    if items.len() != 35 {
        return Err(anyhow!(
            "snapshot start action has {} items, expected 35",
            items.len()
        ));
    }

    let state = decode_reveal_state(reveal_script)?;
    validate_state(&state)?;
    validate_template_items(
        &state,
        &items,
        30,
        31,
        "kcc20TemplatePrefixLen",
        "kcc20TemplateSuffixLen",
        "kcc20TemplateHash",
    )?;
    validate_template_items(
        &state,
        &items,
        32,
        33,
        "controllerTemplatePrefixLen",
        "controllerTemplateSuffixLen",
        "controllerTemplateHash",
    )?;

    let count = usize::try_from(json_i128(&state, "shardCount")?)?;
    let controllers = decode_controller_arrays(&items, count)?;
    let reserves = decode_reserve_arrays(&items, count)?;
    validate_start_plan(&state, &controllers, &reserves)?;

    let projection_schema = if has_wide_supply(&state)? {
        "kcc20-snapshot-bootstrap-start/v3"
    } else {
        "kcc20-snapshot-bootstrap-start/v2"
    };
    Ok(Some(json!({
        "projectionSchema": projection_schema,
        "action": "start",
        "terminal": true,
        "bootstrapSuccessor": Value::Null,
        "migrationId": state["migrationId"],
        "manifestCommitment": state["manifestCommitment"],
        "holderExtensionCommitment": state["holderExtensionCommitment"],
        "tokenId": state["expectedTokenId"],
        "totalSupply": state["totalSupply"],
        "kcc20TemplateHash": state["kcc20TemplateHash"],
        "reserveCellKas": state["reserveCellKas"],
        "claimNotBeforeDaaScore": state["claimNotBeforeDaaScore"],
        "shardCount": state["shardCount"],
        "peerPlanCommitment": state["peerPlanCommitment"],
        "startPlanCommitment": state["startPlanCommitment"],
        "controllers": controllers,
        "reserves": reserves,
    })))
}

/// Return the KCC20 template witness after authenticating it against bootstrap state.
pub fn decode_bootstrap_kcc20_template_parts(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    if items.last().and_then(item_tag) != Some(START_TAG) {
        return Ok(None);
    }
    if items.len() != 35 {
        return Err(anyhow!(
            "snapshot start action has {} items, expected 35",
            items.len()
        ));
    }
    let state = decode_reveal_state(reveal_script)?;
    validate_state(&state)?;
    validate_template_items(
        &state,
        &items,
        30,
        31,
        "kcc20TemplatePrefixLen",
        "kcc20TemplateSuffixLen",
        "kcc20TemplateHash",
    )?;
    Ok(Some((item_data(&items, 30)?, item_data(&items, 31)?)))
}

fn decode_controller_arrays(items: &[ScriptItem], count: usize) -> Result<Value> {
    let widths = [
        32_usize, 32, 32, 32, 32, 32, 32, 32, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 32, 8, 8,
    ];
    for (index, width) in widths.into_iter().enumerate() {
        if item_data(items, index)?.len() != count * width {
            return Err(anyhow!(
                "snapshot start controller field {index} has an inconsistent array length"
            ));
        }
    }
    Ok(Value::Array(
        (0..count)
            .map(|index| {
                Ok(json!({
                    "migrationId": array_hex32(items, 0, index)?,
                    "tokenId": array_hex32(items, 1, index)?,
                    "holderExtensionCommitment": array_hex32(items, 2, index)?,
                    "manifestCommitment": array_hex32(items, 3, index)?,
                    "snapshotContext": array_hex32(items, 4, index)?,
                    "kcc20TemplateHash": array_hex32(items, 5, index)?,
                    "bootstrapTemplateHash": array_hex32(items, 6, index)?,
                    "deploymentGuardCommitment": array_hex32(items, 7, index)?,
                    "claimNotBeforeDaaScore": array_int(items, 8, index)?,
                    "shardIndex": array_int(items, 9, index)?,
                    "globalIndexStart": array_int(items, 10, index)?,
                    "holderCount": array_int(items, 11, index)?,
                    "treeDepth": array_int(items, 12, index)?,
                    "kcc20TemplatePrefixLen": array_int(items, 13, index)?,
                    "kcc20TemplateSuffixLen": array_int(items, 14, index)?,
                    "bootstrapTemplatePrefixLen": array_int(items, 15, index)?,
                    "bootstrapTemplateSuffixLen": array_int(items, 16, index)?,
                    "shardCount": array_int(items, 17, index)?,
                    "controllerCellKas": array_int(items, 18, index)?,
                    "reserveCellKas": array_int(items, 19, index)?,
                    "recipientMinCellKas": array_int(items, 20, index)?,
                    "remainingRoot": array_hex32(items, 21, index)?,
                    "remainingAmount": array_int(items, 22, index)?,
                    "claimsProcessed": array_int(items, 23, index)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn decode_reserve_arrays(items: &[ScriptItem], count: usize) -> Result<Value> {
    let offset = 24;
    let widths = [8_usize, 32, 1, 1, 32, 32];
    for (field, width) in widths.into_iter().enumerate() {
        if item_data(items, offset + field)?.len() != count * width {
            return Err(anyhow!(
                "snapshot start reserve field {field} has an inconsistent array length"
            ));
        }
    }
    Ok(Value::Array(
        (0..count)
            .map(|index| {
                Ok(json!({
                    "shardIndex": index.to_string(),
                    "amount": array_int(items, offset, index)?,
                    "owner": array_hex32(items, offset + 1, index)?,
                    "ownerScheme": array_byte(items, offset + 2, index)?.to_string(),
                    "borrowScheme": array_byte(items, offset + 3, index)?.to_string(),
                    "borrowGuard": array_hex32(items, offset + 4, index)?,
                    "extensionCommitment": array_hex32(items, offset + 5, index)?,
                }))
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn validate_start_plan(state: &Value, controllers: &Value, reserves: &Value) -> Result<()> {
    (|| -> Result<()> {
    let controllers = controllers
        .as_array()
        .ok_or_else(|| anyhow!("snapshot start controllers are not an array"))?;
    let reserves = reserves
        .as_array()
        .ok_or_else(|| anyhow!("snapshot start reserves are not an array"))?;
    if controllers.len() != reserves.len()
        || controllers.is_empty()
        || controllers.len() > MAX_SHARDS
    {
        return Err(anyhow!("snapshot start shard arrays are inconsistent"));
    }

    let migration = decode_hex32(state, "migrationId")?;
    let manifest = decode_hex32(state, "manifestCommitment")?;
    let extension = decode_hex32(state, "holderExtensionCommitment")?;
    let token = decode_hex32(state, "expectedTokenId")?;
    let mut peer_plan = vec![0x21];
    peer_plan.extend_from_slice(&migration);
    peer_plan.extend_from_slice(&manifest);
    peer_plan.extend_from_slice(&le_i64(controllers.len() as i128)?);
    let mut start_plan = vec![0x22];
    start_plan.extend_from_slice(&migration);
    start_plan.extend_from_slice(&manifest);
    start_plan.extend_from_slice(&extension);
    start_plan.extend_from_slice(&token);
    if has_wide_supply(state)? {
        start_plan.extend_from_slice(&le_i64(json_i128(state, "totalSupplyHigh")?)?);
        start_plan.extend_from_slice(&le_i64(json_i128(state, "totalSupplyLow")?)?);
    } else {
        start_plan.extend_from_slice(&le_i64(json_i128(state, "totalSupply")?)?);
    }
    start_plan.extend_from_slice(&le_i64(json_i128(state, "claimNotBeforeDaaScore")?)?);
    start_plan.extend_from_slice(&le_i64(controllers.len() as i128)?);

    let mut total = 0_i128;
    let zero = "00".repeat(32);
    for (index, (controller, reserve)) in controllers.iter().zip(reserves).enumerate() {
        let amount = json_i128(controller, "remainingAmount")?;
        if controller["migrationId"] != state["migrationId"]
            || controller["tokenId"] != state["expectedTokenId"]
            || controller["holderExtensionCommitment"] != state["holderExtensionCommitment"]
            || controller["manifestCommitment"] != state["manifestCommitment"]
            || controller["kcc20TemplateHash"] != state["kcc20TemplateHash"]
            || controller["bootstrapTemplateHash"] != state["bootstrapTemplateHash"]
            || json_i128(controller, "bootstrapTemplatePrefixLen")?
                != json_i128(state, "bootstrapTemplatePrefixLen")?
            || json_i128(controller, "bootstrapTemplateSuffixLen")?
                != json_i128(state, "bootstrapTemplateSuffixLen")?
            || json_i128(controller, "claimNotBeforeDaaScore")?
                != json_i128(state, "claimNotBeforeDaaScore")?
            || json_i128(controller, "shardIndex")? != i128::try_from(index)?
            || json_i128(controller, "shardCount")? != i128::try_from(controllers.len())?
            || json_i128(controller, "controllerCellKas")? != json_i128(state, "controllerCellKas")?
            || json_i128(controller, "reserveCellKas")? != json_i128(state, "reserveCellKas")?
            || json_i128(controller, "claimsProcessed")? != 0
            || json_i128(reserve, "amount")? != amount
            || reserve["ownerScheme"] != OWNER_COVENANT_ID.to_string()
            || reserve["borrowScheme"] != "0"
            || reserve["borrowGuard"] != zero
            || reserve["extensionCommitment"] != state["holderExtensionCommitment"]
        {
            return Err(anyhow!("snapshot start shard {index} is inconsistent"));
        }
        if index == 0 {
            if controller["deploymentGuardCommitment"] != state["peerPlanCommitment"] {
                return Err(anyhow!("snapshot start shard-zero guard is inconsistent"));
            }
        } else if controller["deploymentGuardCommitment"] != zero {
            return Err(anyhow!(
                "snapshot start peer controller has a deployment guard"
            ));
        }
        total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow!("snapshot start allocation overflows"))?;

        let mut shard = le_i64(index as i128)?.to_vec();
        shard.extend_from_slice(&decode_hex32(reserve, "owner")?);
        shard.extend_from_slice(&decode_hex32(controller, "remainingRoot")?);
        shard.extend_from_slice(&le_i64(amount)?);
        shard.extend_from_slice(&le_i64(json_i128(controller, "globalIndexStart")?)?);
        shard.extend_from_slice(&le_i64(json_i128(controller, "holderCount")?)?);
        shard.extend_from_slice(&le_i64(json_i128(controller, "treeDepth")?)?);
        shard.extend_from_slice(&decode_hex32(controller, "snapshotContext")?);
        start_plan.extend_from_slice(&shard);
        if index > 0 {
            peer_plan.extend_from_slice(&shard);
        }
    }

    if total != json_i128(state, "totalSupply")?
        || hex::encode(blake2b_256(&peer_plan)) != state["peerPlanCommitment"]
        || hex::encode(blake2b_256(&start_plan)) != state["startPlanCommitment"]
    {
        return Err(anyhow!("snapshot start plan commitment is inconsistent"));
    }
    Ok(())

    })().map_err(|error| error.context(crate::IntegrityFailure("snapshot_validate_start_plan")))
}

fn validate_template_items(
    state: &Value,
    items: &[ScriptItem],
    prefix_item: usize,
    suffix_item: usize,
    prefix_key: &str,
    suffix_key: &str,
    hash_key: &str,
) -> Result<()> {
    (|| -> Result<()> {
    let prefix = item_data(items, prefix_item)?;
    let suffix = item_data(items, suffix_item)?;
    if i128::try_from(prefix.len())? != json_i128(state, prefix_key)?
        || i128::try_from(suffix.len())? != json_i128(state, suffix_key)?
        || template_hash(&prefix, &suffix) != decode_hex32(state, hash_key)?
    {
        return Err(anyhow!(
            "snapshot start template fingerprint is inconsistent"
        ));
    }
    Ok(())

    })().map_err(|error| error.context(crate::IntegrityFailure("snapshot_validate_template_items")))
}

fn validate_state(state: &Value) -> Result<()> {
    (|| -> Result<()> {
    for key in [
        "migrationId",
        "manifestCommitment",
        "holderExtensionCommitment",
        "expectedTokenId",
        "kcc20TemplateHash",
        "controllerTemplateHash",
        "bootstrapTemplateHash",
        "peerPlanCommitment",
        "startPlanCommitment",
    ] {
        if decode_hex32(state, key)? == [0_u8; 32] {
            return Err(anyhow!("snapshot bootstrap {key} is zero"));
        }
    }
    let shard_count = json_i128(state, "shardCount")?;
    let supply_is_invalid = if has_wide_supply(state)? {
        (json_i128(state, "totalSupplyHigh")? == 0 && json_i128(state, "totalSupplyLow")? == 0)
            || json_i128(state, "totalSupplyHigh")? < 0
            || json_i128(state, "totalSupplyLow")? < 0
    } else {
        json_i128(state, "totalSupply")? <= 0
    };
    if supply_is_invalid
        || !(1..LOCK_TIME_THRESHOLD).contains(&json_i128(state, "claimNotBeforeDaaScore")?)
        || json_i128(state, "kcc20TemplatePrefixLen")? <= 0
        || json_i128(state, "kcc20TemplateSuffixLen")? <= 0
        || json_i128(state, "controllerTemplatePrefixLen")? <= 0
        || json_i128(state, "controllerTemplateSuffixLen")? <= 0
        || json_i128(state, "bootstrapTemplatePrefixLen")? <= 0
        || json_i128(state, "bootstrapTemplateSuffixLen")? <= 0
        || json_i128(state, "reserveCellKas")? < MIN_CELL_SOMPI
        || json_i128(state, "controllerCellKas")? < MIN_CELL_SOMPI
        || json_i128(state, "bootstrapCellKas")? < MIN_CELL_SOMPI
        || !(1..=MAX_SHARDS as i128).contains(&shard_count)
    {
        return Err(anyhow!("snapshot bootstrap configuration is invalid"));
    }
    Ok(())

    })().map_err(|error| error.context(crate::IntegrityFailure("snapshot_validate_state")))
}

fn decode_reveal_state(payload: &[u8]) -> Result<Value> {
    let state_len = state_len_for_script(payload.len())?;
    decode_state_payload(
        &payload[SNAPSHOT_BOOTSTRAP_STATE_START..SNAPSHOT_BOOTSTRAP_STATE_START + state_len],
    )
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if !matches!(
        payload.len(),
        SNAPSHOT_BOOTSTRAP_STATE_LEN | LEGACY_SNAPSHOT_BOOTSTRAP_STATE_LEN
    ) {
        return Err(anyhow!(
            "snapshot bootstrap state is {} bytes, expected {} or {}",
            payload.len(),
            LEGACY_SNAPSHOT_BOOTSTRAP_STATE_LEN,
            SNAPSHOT_BOOTSTRAP_STATE_LEN,
        ));
    }
    let fixed = |marker: usize, start: usize, end: usize, label: &str| -> Result<String> {
        if payload[marker] != 32 {
            return Err(anyhow!("snapshot bootstrap {label} push is not OP_DATA_32"));
        }
        Ok(hex::encode(&payload[start..end]))
    };
    let int = |marker: usize, start: usize, end: usize, label: &str| -> Result<String> {
        if payload[marker] != 8 {
            return Err(anyhow!("snapshot bootstrap {label} push is not OP_DATA_8"));
        }
        Ok(parse_minimal_int(&payload[start..end]).to_string())
    };
    if payload.len() == LEGACY_SNAPSHOT_BOOTSTRAP_STATE_LEN {
        return Ok(json!({
            "migrationId": fixed(0, 1, 33, "migrationId")?,
            "manifestCommitment": fixed(33, 34, 66, "manifestCommitment")?,
            "holderExtensionCommitment": fixed(66, 67, 99, "holderExtensionCommitment")?,
            "totalSupply": int(99, 100, 108, "totalSupply")?,
            "claimNotBeforeDaaScore": int(108, 109, 117, "claimNotBeforeDaaScore")?,
            "expectedTokenId": fixed(117, 118, 150, "expectedTokenId")?,
            "kcc20TemplateHash": fixed(150, 151, 183, "kcc20TemplateHash")?,
            "kcc20TemplatePrefixLen": int(183, 184, 192, "kcc20TemplatePrefixLen")?,
            "kcc20TemplateSuffixLen": int(192, 193, 201, "kcc20TemplateSuffixLen")?,
            "controllerTemplateHash": fixed(201, 202, 234, "controllerTemplateHash")?,
            "controllerTemplatePrefixLen": int(234, 235, 243, "controllerTemplatePrefixLen")?,
            "controllerTemplateSuffixLen": int(243, 244, 252, "controllerTemplateSuffixLen")?,
            "bootstrapTemplateHash": fixed(252, 253, 285, "bootstrapTemplateHash")?,
            "bootstrapTemplatePrefixLen": int(285, 286, 294, "bootstrapTemplatePrefixLen")?,
            "bootstrapTemplateSuffixLen": int(294, 295, 303, "bootstrapTemplateSuffixLen")?,
            "reserveCellKas": int(303, 304, 312, "reserveCellKas")?,
            "controllerCellKas": int(312, 313, 321, "controllerCellKas")?,
            "bootstrapCellKas": int(321, 322, 330, "bootstrapCellKas")?,
            "shardCount": int(330, 331, 339, "shardCount")?,
            "peerPlanCommitment": fixed(339, 340, 372, "peerPlanCommitment")?,
            "startPlanCommitment": fixed(372, 373, 405, "startPlanCommitment")?,
        }));
    }

    let total_supply_high = int(99, 100, 108, "totalSupplyHigh")?;
    let total_supply_low = int(108, 109, 117, "totalSupplyLow")?;
    let total_supply = wide_supply(&total_supply_high, &total_supply_low)?;
    Ok(json!({
        "migrationId": fixed(0, 1, 33, "migrationId")?,
        "manifestCommitment": fixed(33, 34, 66, "manifestCommitment")?,
        "holderExtensionCommitment": fixed(66, 67, 99, "holderExtensionCommitment")?,
        "totalSupplyHigh": total_supply_high,
        "totalSupplyLow": total_supply_low,
        "totalSupply": total_supply,
        "claimNotBeforeDaaScore": int(117, 118, 126, "claimNotBeforeDaaScore")?,
        "expectedTokenId": fixed(126, 127, 159, "expectedTokenId")?,
        "kcc20TemplateHash": fixed(159, 160, 192, "kcc20TemplateHash")?,
        "kcc20TemplatePrefixLen": int(192, 193, 201, "kcc20TemplatePrefixLen")?,
        "kcc20TemplateSuffixLen": int(201, 202, 210, "kcc20TemplateSuffixLen")?,
        "controllerTemplateHash": fixed(210, 211, 243, "controllerTemplateHash")?,
        "controllerTemplatePrefixLen": int(243, 244, 252, "controllerTemplatePrefixLen")?,
        "controllerTemplateSuffixLen": int(252, 253, 261, "controllerTemplateSuffixLen")?,
        "bootstrapTemplateHash": fixed(261, 262, 294, "bootstrapTemplateHash")?,
        "bootstrapTemplatePrefixLen": int(294, 295, 303, "bootstrapTemplatePrefixLen")?,
        "bootstrapTemplateSuffixLen": int(303, 304, 312, "bootstrapTemplateSuffixLen")?,
        "reserveCellKas": int(312, 313, 321, "reserveCellKas")?,
        "controllerCellKas": int(321, 322, 330, "controllerCellKas")?,
        "bootstrapCellKas": int(330, 331, 339, "bootstrapCellKas")?,
        "shardCount": int(339, 340, 348, "shardCount")?,
        "peerPlanCommitment": fixed(348, 349, 381, "peerPlanCommitment")?,
        "startPlanCommitment": fixed(381, 382, 414, "startPlanCommitment")?,
    }))
}

fn state_len_for_script(script_len: usize) -> Result<usize> {
    match script_len {
        LEGACY_SNAPSHOT_BOOTSTRAP_SCRIPT_LEN => Ok(LEGACY_SNAPSHOT_BOOTSTRAP_STATE_LEN),
        SNAPSHOT_BOOTSTRAP_SCRIPT_LEN => Ok(SNAPSHOT_BOOTSTRAP_STATE_LEN),
        _ => Err(anyhow!(
            "snapshot bootstrap reveal script is {script_len} bytes, expected {} or {}",
            LEGACY_SNAPSHOT_BOOTSTRAP_SCRIPT_LEN,
            SNAPSHOT_BOOTSTRAP_SCRIPT_LEN,
        )),
    }
}

fn has_wide_supply(state: &Value) -> Result<bool> {
    match (state.get("totalSupplyHigh"), state.get("totalSupplyLow")) {
        (Some(_), Some(_)) => Ok(true),
        (None, None) => Ok(false),
        _ => Err(anyhow!("snapshot bootstrap supply limbs are incomplete")),
    }
}

fn wide_supply(high: &str, low: &str) -> Result<String> {
    let high = high.parse::<i128>()?;
    let low = low.parse::<i128>()?;
    if high < 0 || low < 0 {
        return Err(anyhow!("snapshot bootstrap supply limb is negative"));
    }
    high.checked_mul(1_i128 << 63)
        .and_then(|value| value.checked_add(low))
        .map(|value| value.to_string())
        .ok_or_else(|| anyhow!("snapshot bootstrap supply limbs overflow"))
}

fn action_tag(signature_script: &[u8]) -> Option<[u8; 4]> {
    script_items(args_prefix_before_reveal(signature_script))
        .last()
        .and_then(item_tag)
}

fn item_data(items: &[ScriptItem], index: usize) -> Result<Vec<u8>> {
    match items.get(index) {
        Some(ScriptItem::Data(bytes)) => Ok(bytes.clone()),
        // ScriptBuilder emits one-byte values 0..=16 using their canonical
        // small-integer opcodes. These items still represent the original
        // byte-array value and must decode identically to a direct data push.
        Some(ScriptItem::Int(value)) if (0..=16).contains(value) => Ok(vec![u8::try_from(*value)?]),
        _ => Err(anyhow!("bootstrap sigscript item {index} is not byte data")),
    }
}

fn array_hex32(items: &[ScriptItem], field: usize, index: usize) -> Result<String> {
    let data = item_data(items, field)?;
    let start = index
        .checked_mul(32)
        .ok_or_else(|| anyhow!("snapshot array offset overflows"))?;
    Ok(hex::encode(data.get(start..start + 32).ok_or_else(
        || anyhow!("snapshot array field is truncated"),
    )?))
}

fn array_int(items: &[ScriptItem], field: usize, index: usize) -> Result<String> {
    let data = item_data(items, field)?;
    let start = index
        .checked_mul(8)
        .ok_or_else(|| anyhow!("snapshot array offset overflows"))?;
    Ok(parse_minimal_int(
        data.get(start..start + 8)
            .ok_or_else(|| anyhow!("snapshot integer array field is truncated"))?,
    )
    .to_string())
}

fn array_byte(items: &[ScriptItem], field: usize, index: usize) -> Result<u8> {
    item_data(items, field)?
        .get(index)
        .copied()
        .ok_or_else(|| anyhow!("snapshot byte array field is truncated"))
}

fn json_i128(value: &Value, key: &str) -> Result<i128> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("snapshot state is missing {key}"))?
        .parse()
        .map_err(Into::into)
}

fn decode_hex32(value: &Value, key: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("snapshot state is missing {key}"))?,
    )?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("snapshot state {key} is not 32 bytes"))
}

fn le_i64(value: i128) -> Result<[u8; 8]> {
    let value = i64::try_from(value)?;
    if value < 0 {
        return Err(anyhow!("snapshot plan integer is negative"));
    }
    Ok(value.to_le_bytes())
}

fn template_hash(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(16 + prefix.len() + suffix.len());
    preimage.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
    preimage.extend_from_slice(prefix);
    preimage.extend_from_slice(&(suffix.len() as u64).to_le_bytes());
    preimage.extend_from_slice(suffix);
    *blake3::hash(&preimage).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_data(script: &mut Vec<u8>, data: &[u8]) {
        if data.len() <= 75 {
            script.push(data.len() as u8);
        } else if data.len() <= u8::MAX as usize {
            script.extend_from_slice(&[0x4c, data.len() as u8]);
        } else {
            script.push(0x4d);
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        script.extend_from_slice(data);
    }

    fn artifact_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-snapshot-bootstrap/KCC20SnapshotBootstrap.placeholder.json"
        ))
        .expect("embedded snapshot bootstrap artifact");
        artifact["script"]
            .as_array()
            .expect("script array")
            .iter()
            .map(|value| value.as_u64().expect("script byte") as u8)
            .collect()
    }

    fn artifact_parts(raw: &str) -> (Vec<u8>, Vec<u8>) {
        let artifact: Value = serde_json::from_str(raw).expect("embedded contract artifact");
        let script = artifact["script"]
            .as_array()
            .expect("script array")
            .iter()
            .map(|value| value.as_u64().expect("script byte") as u8)
            .collect::<Vec<_>>();
        let start = artifact["state_layout"]["start"]
            .as_u64()
            .expect("state start") as usize;
        let len = artifact["state_layout"]["len"]
            .as_u64()
            .expect("state length") as usize;
        (script[..start].to_vec(), script[start + len..].to_vec())
    }

    fn append_i64(target: &mut Vec<u8>, value: i64) {
        target.extend_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn constructor_validation_cannot_be_downgraded_to_pending_decoding() {
        let mut reveal = artifact_script();
        // Preserve the executable and field framing; invalidate the committed shard count.
        reveal[SNAPSHOT_BOOTSTRAP_STATE_START + 340..SNAPSHOT_BOOTSTRAP_STATE_START + 348].fill(0);
        let hash = Kcc20SnapshotBootstrapDecoder::template_hash_of_compiled_script(&reveal).unwrap();
        let decoder = Kcc20SnapshotBootstrapDecoder::new(hash);
        let error = crate::interpretation("constructor", decoder.decode_constructor(&reveal)).unwrap_err();
        assert!(error.downcast_ref::<crate::IntegrityFailure>().is_some());
        assert!(error.downcast_ref::<crate::InterpretationFailure>().is_none());
    }

    #[test]
    fn decodes_immutable_signerless_state() {
        let script = artifact_script();
        assert_eq!(script.len(), SNAPSHOT_BOOTSTRAP_SCRIPT_LEN);
        let hash = Kcc20SnapshotBootstrapDecoder::template_hash_of_compiled_script(&script)
            .expect("template hash");
        let decoder = Kcc20SnapshotBootstrapDecoder::new(hash);
        assert!(decoder.matches_reveal_script(&script));
        let decoded = decoder.decode_constructor(&script).expect("constructor");
        assert_eq!(decoded["state"]["totalSupply"], "1000");
        assert_eq!(decoded["state"]["expectedTokenId"], "11".repeat(32));
        assert!(decoded["state"].get("approvalKey").is_none());
        assert!(decoded["state"].get("phase").is_none());
        let mut changed_state = script.clone();
        changed_state[SNAPSHOT_BOOTSTRAP_STATE_START + 104] ^= 1;
        assert!(decoder.matches_reveal_script(&changed_state));
        let mut changed_program = script;
        changed_program[SNAPSHOT_BOOTSTRAP_STATE_START + SNAPSHOT_BOOTSTRAP_STATE_LEN] ^= 1;
        assert!(!decoder.matches_reveal_script(&changed_program));
    }

    #[test]
    fn resolves_only_start() {
        let script = artifact_script();
        let hash = Kcc20SnapshotBootstrapDecoder::template_hash_of_compiled_script(&script)
            .expect("template hash");
        let decoder = Kcc20SnapshotBootstrapDecoder::new(hash);
        let mut signature_script = Vec::new();
        push_data(&mut signature_script, &START_TAG);
        push_data(&mut signature_script, &script);
        assert_eq!(
            decoder.decode_action(&signature_script).as_deref(),
            Some("start")
        );

        let mut removed = Vec::new();
        push_data(&mut removed, &[0x29, 0x14, 0x3f, 0x1f]);
        push_data(&mut removed, &script);
        assert_eq!(decoder.decode_action(&removed), None);
    }

    #[test]
    fn decodes_canonical_small_integer_byte_arrays() {
        let items = [ScriptItem::Int(OWNER_COVENANT_ID), ScriptItem::Int(0)];
        assert_eq!(item_data(&items, 0).unwrap(), vec![4]);
        assert_eq!(item_data(&items, 1).unwrap(), vec![0]);
        assert_eq!(array_byte(&items, 0, 0).unwrap(), 4);
        assert_eq!(array_byte(&items, 1, 0).unwrap(), 0);
    }

    #[test]
    fn decodes_and_validates_complete_signerless_start_projection() {
        let mut reveal = artifact_script();
        let initial = decode_reveal_state(&reveal).expect("bootstrap state");
        let migration = decode_hex32(&initial, "migrationId").unwrap();
        let manifest = decode_hex32(&initial, "manifestCommitment").unwrap();
        let extension = decode_hex32(&initial, "holderExtensionCommitment").unwrap();
        let token = decode_hex32(&initial, "expectedTokenId").unwrap();
        let kcc20_hash = decode_hex32(&initial, "kcc20TemplateHash").unwrap();
        let bootstrap_hash = decode_hex32(&initial, "bootstrapTemplateHash").unwrap();
        let controller_ids = [[0x61_u8; 32], [0x62_u8; 32]];
        let roots = [[0x71_u8; 32], [0x72_u8; 32]];
        let contexts = [[0x81_u8; 32], [0x82_u8; 32]];
        let amounts = [400_i64, 600_i64];
        let global_starts = [0_i64, 1_i64];

        let mut peer_preimage = vec![0x21];
        peer_preimage.extend_from_slice(&migration);
        peer_preimage.extend_from_slice(&manifest);
        peer_preimage.extend_from_slice(&2_i64.to_le_bytes());
        peer_preimage.extend_from_slice(&1_i64.to_le_bytes());
        peer_preimage.extend_from_slice(&controller_ids[1]);
        peer_preimage.extend_from_slice(&roots[1]);
        peer_preimage.extend_from_slice(&amounts[1].to_le_bytes());
        peer_preimage.extend_from_slice(&global_starts[1].to_le_bytes());
        peer_preimage.extend_from_slice(&1_i64.to_le_bytes());
        peer_preimage.extend_from_slice(&1_i64.to_le_bytes());
        peer_preimage.extend_from_slice(&contexts[1]);
        let peer = blake2b_256(&peer_preimage);

        let mut start_preimage = vec![0x22];
        start_preimage.extend_from_slice(&migration);
        start_preimage.extend_from_slice(&manifest);
        start_preimage.extend_from_slice(&extension);
        start_preimage.extend_from_slice(&token);
        start_preimage.extend_from_slice(&0_i64.to_le_bytes());
        start_preimage.extend_from_slice(&1_000_i64.to_le_bytes());
        start_preimage.extend_from_slice(&100_i64.to_le_bytes());
        start_preimage.extend_from_slice(&2_i64.to_le_bytes());
        for index in 0..2 {
            start_preimage.extend_from_slice(&(index as i64).to_le_bytes());
            start_preimage.extend_from_slice(&controller_ids[index]);
            start_preimage.extend_from_slice(&roots[index]);
            start_preimage.extend_from_slice(&amounts[index].to_le_bytes());
            start_preimage.extend_from_slice(&global_starts[index].to_le_bytes());
            start_preimage.extend_from_slice(&1_i64.to_le_bytes());
            start_preimage.extend_from_slice(&1_i64.to_le_bytes());
            start_preimage.extend_from_slice(&contexts[index]);
        }
        let start = blake2b_256(&start_preimage);
        reveal[SNAPSHOT_BOOTSTRAP_STATE_START + 349..SNAPSHOT_BOOTSTRAP_STATE_START + 381]
            .copy_from_slice(&peer);
        reveal[SNAPSHOT_BOOTSTRAP_STATE_START + 382..SNAPSHOT_BOOTSTRAP_STATE_START + 414]
            .copy_from_slice(&start);
        let state = decode_reveal_state(&reveal).expect("patched bootstrap state");

        let mut controller_fields = vec![Vec::new(); 24];
        for index in 0..2 {
            controller_fields[0].extend_from_slice(&migration);
            controller_fields[1].extend_from_slice(&token);
            controller_fields[2].extend_from_slice(&extension);
            controller_fields[3].extend_from_slice(&manifest);
            controller_fields[4].extend_from_slice(&contexts[index]);
            controller_fields[5].extend_from_slice(&kcc20_hash);
            controller_fields[6].extend_from_slice(&bootstrap_hash);
            controller_fields[7].extend_from_slice(if index == 0 { &peer } else { &[0_u8; 32] });
            append_i64(&mut controller_fields[8], 100);
            append_i64(&mut controller_fields[9], index as i64);
            append_i64(&mut controller_fields[10], global_starts[index]);
            append_i64(&mut controller_fields[11], 1);
            append_i64(&mut controller_fields[12], 1);
            append_i64(
                &mut controller_fields[13],
                json_i128(&state, "kcc20TemplatePrefixLen").unwrap() as i64,
            );
            append_i64(
                &mut controller_fields[14],
                json_i128(&state, "kcc20TemplateSuffixLen").unwrap() as i64,
            );
            append_i64(
                &mut controller_fields[15],
                json_i128(&state, "bootstrapTemplatePrefixLen").unwrap() as i64,
            );
            append_i64(
                &mut controller_fields[16],
                json_i128(&state, "bootstrapTemplateSuffixLen").unwrap() as i64,
            );
            append_i64(&mut controller_fields[17], 2);
            append_i64(&mut controller_fields[18], 50_000_000);
            append_i64(&mut controller_fields[19], 50_000_000);
            append_i64(&mut controller_fields[20], 50_000_000);
            controller_fields[21].extend_from_slice(&roots[index]);
            append_i64(&mut controller_fields[22], amounts[index]);
            append_i64(&mut controller_fields[23], 0);
        }

        let mut reserve_fields = vec![Vec::new(); 6];
        for index in 0..2 {
            append_i64(&mut reserve_fields[0], amounts[index]);
            reserve_fields[1].extend_from_slice(&controller_ids[index]);
            reserve_fields[2].push(OWNER_COVENANT_ID as u8);
            reserve_fields[3].push(0);
            reserve_fields[4].extend_from_slice(&[0_u8; 32]);
            reserve_fields[5].extend_from_slice(&extension);
        }

        let (kcc20_prefix, kcc20_suffix) =
            artifact_parts(include_str!("../fixtures/kcc20/KCC20.placeholder.json"));
        let (controller_prefix, controller_suffix) = artifact_parts(include_str!(
            "../fixtures/kcc20-snapshot-controller/KCC20SnapshotController.placeholder.json"
        ));
        let mut signature_script = Vec::new();
        for field in controller_fields.iter().chain(&reserve_fields) {
            push_data(&mut signature_script, field);
        }
        for field in [
            kcc20_prefix,
            kcc20_suffix,
            controller_prefix,
            controller_suffix,
        ] {
            push_data(&mut signature_script, &field);
        }
        push_data(&mut signature_script, &START_TAG);
        push_data(&mut signature_script, &reveal);

        let projection = decode_bootstrap_action(&signature_script, &reveal)
            .expect("decode start")
            .expect("start projection");
        assert_eq!(projection["action"], "start");
        assert_eq!(projection["tokenId"], hex::encode(token));
        assert_eq!(projection["controllers"].as_array().unwrap().len(), 2);
        assert_eq!(projection["reserves"].as_array().unwrap().len(), 2);
    }
}
