//! KRC20-to-KCC20 snapshot shard-controller decoder.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, KnownTemplate};

use crate::kcc20::{args_prefix_before_reveal, item_bytes_32, item_int, script_items, ScriptItem};
use crate::kcc20_standard::{item_tag, owner_scheme_name};
use crate::TemplateDecoder;

pub const SNAPSHOT_CONTROLLER_SCRIPT_LEN: usize = 15_028;
pub const SNAPSHOT_CONTROLLER_STATE_START: usize = 1;
pub const SNAPSHOT_CONTROLLER_STATE_LEN: usize = 432;
const LEGACY_SNAPSHOT_CONTROLLER_SCRIPT_LEN: usize = 15_297;
const PRE_COMPACT_START_SNAPSHOT_CONTROLLER_SCRIPT_LEN: usize = 15_350;
// Authenticated template hash used by the accepted TN10 snapshot-start fixture.
pub(crate) const LEGACY_SNAPSHOT_CONTROLLER_TEMPLATE_HASH: [u8; 32] = [
    0x26, 0x6c, 0x92, 0x83, 0xb9, 0x68, 0xaf, 0x50, 0x56, 0xb4, 0xe0, 0x79, 0x15, 0x92, 0xcd, 0x42,
    0x80, 0xd5, 0x19, 0x64, 0x2c, 0x5d, 0x34, 0xab, 0x81, 0x18, 0xfe, 0x01, 0xb6, 0xda, 0x08, 0x31,
];
// Template deployed before the start witness stopped duplicating the complete
// KCC20 reserve state and template already authenticated by the bootstrap.
pub(crate) const PRE_COMPACT_START_SNAPSHOT_CONTROLLER_TEMPLATE_HASH: [u8; 32] = [
    0x75, 0x03, 0xe1, 0x04, 0x03, 0x57, 0xc4, 0x72, 0xa4, 0xb6, 0x9e, 0x16, 0x9b, 0xc3, 0xc2, 0xd2,
    0x06, 0x1f, 0xa5, 0x55, 0x89, 0x68, 0xe9, 0x24, 0x62, 0xa2, 0x44, 0x33, 0xc3, 0x27, 0xa1, 0x03,
];
const START_TAG: [u8; 4] = [0x7d, 0xd2, 0x1b, 0x19];
const CLAIM_TAG: [u8; 4] = [0x70, 0x66, 0x55, 0x0d];
const OWNER_P2PK_SCHNORR: i128 = 0;
const OWNER_P2SH: i128 = 3;
const OWNER_COVENANT_ID: i128 = 4;
const LOCK_TIME_THRESHOLD: i128 = 500_000_000_000;
const MIN_KCC20_CELL_SOMPI: i128 = 50_000_000;

pub struct Kcc20SnapshotControllerDecoder {
    template_hash: [u8; 32],
}

impl Kcc20SnapshotControllerDecoder {
    pub fn new(template_hash: [u8; 32]) -> Self {
        Self { template_hash }
    }

    pub fn template_hash_of_compiled_script(script: &[u8]) -> Result<[u8; 32]> {
        if !matches!(
            script.len(),
            LEGACY_SNAPSHOT_CONTROLLER_SCRIPT_LEN
                | PRE_COMPACT_START_SNAPSHOT_CONTROLLER_SCRIPT_LEN
                | SNAPSHOT_CONTROLLER_SCRIPT_LEN
        ) {
            return Err(anyhow!(
                "snapshot controller reveal script is {} bytes, expected {}, {}, or {}",
                script.len(),
                LEGACY_SNAPSHOT_CONTROLLER_SCRIPT_LEN,
                PRE_COMPACT_START_SNAPSHOT_CONTROLLER_SCRIPT_LEN,
                SNAPSHOT_CONTROLLER_SCRIPT_LEN,
            ));
        }
        let prefix = &script[..SNAPSHOT_CONTROLLER_STATE_START];
        let suffix = &script[SNAPSHOT_CONTROLLER_STATE_START + SNAPSHOT_CONTROLLER_STATE_LEN..];
        let mut preimage = Vec::with_capacity(16 + prefix.len() + suffix.len());
        preimage.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
        preimage.extend_from_slice(prefix);
        preimage.extend_from_slice(&(suffix.len() as u64).to_le_bytes());
        preimage.extend_from_slice(suffix);
        Ok(*blake3::hash(&preimage).as_bytes())
    }
}

impl TemplateDecoder for Kcc20SnapshotControllerDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::Kcc20SnapshotController
    }

    fn script_hash(&self) -> [u8; 32] {
        self.template_hash
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        Self::template_hash_of_compiled_script(reveal).is_ok_and(|hash| hash == self.template_hash)
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        let state = decode_reveal_state(payload)?;
        Ok(json!({
            "standard": "KCC20SnapshotController",
            "codec": "kasmelt-snapshot-v2/blake2b256/sharded-full-claim",
            "templateHash": hex::encode(self.template_hash),
            "state": state,
        }))
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        decode_state_payload(payload)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let items = script_items(args_prefix_before_reveal(signature_script));
        match items.last().and_then(item_tag) {
            Some(START_TAG) => Some("start".into()),
            Some(CLAIM_TAG) => Some("claim".into()),
            _ => None,
        }
    }
}

pub fn decode_claim_action(signature_script: &[u8]) -> Result<Option<Value>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    if items.last().and_then(item_tag) != Some(CLAIM_TAG) {
        return Ok(None);
    }
    let owner_scheme = item_int(&items, 2)?;
    let reserve_amount = item_int(&items, 7)?;
    let recipient_amount = item_int(&items, 13)?;
    Ok(Some(json!({
        "globalIndex": item_int(&items, 0)?.to_string(),
        "shardLeafIndex": item_int(&items, 1)?.to_string(),
        "ownerScheme": owner_scheme.to_string(),
        "ownerSchemeName": u8::try_from(owner_scheme).ok().map(owner_scheme_name),
        "owner": hex::encode(item_bytes_32(&items, 3)?),
        "claimAmount": item_int(&items, 5)?.to_string(),
        "successorReserveAmount": reserve_amount.to_string(),
        "recipientAmount": recipient_amount.to_string(),
        "recipient": hex::encode(item_bytes_32(&items, 14)?),
        "recipientOwnerScheme": item_int(&items, 15)?.to_string(),
        "holderExtensionCommitment": hex::encode(item_bytes_32(&items, 18)?),
    })))
}

fn decode_start_transition(items: &[ScriptItem], reveal_script: &[u8]) -> Result<Option<Value>> {
    if items.len() != 36 {
        return Err(anyhow!(
            "snapshot controller start has {} items, expected 36",
            items.len()
        ));
    }
    let previous = decode_reveal_state(reveal_script)?;
    validate_prestart_state(&previous)?;
    let next = controller_state_from_items(items, 0)?;
    validate_state_configuration(&next)?;
    for key in [
        "migrationId",
        "holderExtensionCommitment",
        "manifestCommitment",
        "snapshotContext",
        "kcc20TemplateHash",
        "bootstrapTemplateHash",
        "deploymentGuardCommitment",
        "claimNotBeforeDaaScore",
        "shardIndex",
        "globalIndexStart",
        "holderCount",
        "treeDepth",
        "kcc20TemplatePrefixLen",
        "kcc20TemplateSuffixLen",
        "bootstrapTemplatePrefixLen",
        "bootstrapTemplateSuffixLen",
        "shardCount",
        "controllerCellKas",
        "reserveCellKas",
        "recipientMinCellKas",
        "remainingRoot",
        "remainingAmount",
        "claimsProcessed",
    ] {
        if previous[key] != next[key] {
            return Err(anyhow!("snapshot controller start changes field {key}"));
        }
    }
    let token_id = decode_hex32(&next, "tokenId")?;
    if token_id == [0_u8; 32] {
        return Err(anyhow!("snapshot controller start token id is zero"));
    }

    let reserve = kcc20_state_from_items(items, 27)?;
    if json_i128(&reserve, "amount")? != json_i128(&next, "remainingAmount")?
        || decode_hex32(&reserve, "owner")? == [0_u8; 32]
        || json_i128(&reserve, "ownerScheme")? != OWNER_COVENANT_ID
        || json_i128(&reserve, "borrowScheme")? != 0
        || decode_hex32(&reserve, "borrowGuard")? != [0_u8; 32]
        || reserve["extensionCommitment"] != next["holderExtensionCommitment"]
    {
        return Err(anyhow!("snapshot controller start reserve is inconsistent"));
    }
    validate_kcc20_template_items(&previous, items, 33, 34)?;

    Ok(Some(json!({
        "projectionSchema": "kcc20-snapshot-controller-start/v2",
        "action": "start",
        "migrationId": next["migrationId"],
        "manifestCommitment": next["manifestCommitment"],
        "tokenId": next["tokenId"],
        "shardIndex": next["shardIndex"],
        "bootstrapInputIndex": item_int(items, 24)?.to_string(),
        "reserveOutputIndex": item_int(items, 25)?.to_string(),
        "controllerOutputIndex": item_int(items, 26)?.to_string(),
        "reserve": reserve,
        "terminal": false,
        "nextState": next,
    })))
}

pub fn decode_claim_transition(
    signature_script: &[u8],
    reveal_script: &[u8],
) -> Result<Option<Value>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    if items.last().and_then(item_tag) == Some(START_TAG) {
        return decode_start_transition(&items, reveal_script);
    }
    let Some(mut action) = decode_claim_action(signature_script)? else {
        return Ok(None);
    };
    let state = decode_reveal_state(reveal_script)?;
    validate_state_configuration(&state)?;
    let siblings = item_data(&items, 6)?;
    let depth = json_i128(&state, "treeDepth")?;
    if depth < 1 || depth > 32 || siblings.len() != usize::try_from(depth)? * 32 {
        return Err(anyhow!(
            "snapshot claim proof length does not match tree depth"
        ));
    }
    let global_index = item_int(&items, 0)?;
    let shard_leaf_index = item_int(&items, 1)?;
    let owner_scheme_value = item_int(&items, 2)?;
    if ![OWNER_P2PK_SCHNORR, OWNER_P2SH].contains(&owner_scheme_value) {
        return Err(anyhow!("snapshot claim owner scheme is unsupported"));
    }
    let owner_scheme = u8::try_from(owner_scheme_value)?;
    let owner = item_bytes_32(&items, 3)?;
    let claim_amount = item_int(&items, 5)?;
    let global_index_start = json_i128(&state, "globalIndexStart")?;
    let holder_count = json_i128(&state, "holderCount")?;
    if shard_leaf_index < 0 || shard_leaf_index >= holder_count {
        return Err(anyhow!("snapshot claim leaf index is outside the shard"));
    }
    if global_index_start.checked_add(shard_leaf_index) != Some(global_index) {
        return Err(anyhow!(
            "snapshot claim global index does not match the shard"
        ));
    }
    let context = decode_hex32(&state, "snapshotContext")?;
    let previous_root = decode_hex32(&state, "remainingRoot")?;
    let old_leaf = entitlement_leaf(&context, global_index, owner_scheme, &owner, claim_amount)?;
    if fold(old_leaf, &siblings, shard_leaf_index)? != previous_root {
        return Err(anyhow!("snapshot claim proof does not match current root"));
    }
    let next_root = fold(
        claimed_leaf(&context, global_index)?,
        &siblings,
        shard_leaf_index,
    )?;
    let remaining_before = json_i128(&state, "remainingAmount")?;
    if claim_amount <= 0 || claim_amount > remaining_before {
        return Err(anyhow!("snapshot claim amount is outside the reserve"));
    }
    let remaining_after = remaining_before
        .checked_sub(claim_amount)
        .ok_or_else(|| anyhow!("snapshot remaining amount underflow"))?;
    let claims_before = json_i128(&state, "claimsProcessed")?;
    let claims_after = claims_before
        .checked_add(1)
        .ok_or_else(|| anyhow!("snapshot claim count overflow"))?;
    let terminal = remaining_after == 0;
    if terminal != (claims_after == holder_count) {
        return Err(anyhow!("snapshot terminal amount and claim count disagree"));
    }

    let expected_extension = decode_hex32(&state, "holderExtensionCommitment")?;
    let zero = vec![0_u8; 32];
    let reserve_amount = item_int(&items, 7)?;
    let reserve_owner = item_bytes_32(&items, 8)?;
    let reserve_owner_scheme = item_int(&items, 9)?;
    let reserve_borrow_scheme = item_int(&items, 10)?;
    let reserve_borrow_guard = item_bytes_32(&items, 11)?;
    let reserve_extension = item_bytes_32(&items, 12)?;
    if terminal {
        if reserve_amount != 0
            || reserve_owner != zero
            || reserve_owner_scheme != OWNER_P2PK_SCHNORR
            || reserve_borrow_scheme != 0
            || reserve_borrow_guard != zero
            || reserve_extension != zero
        {
            return Err(anyhow!("snapshot terminal reserve state is not empty"));
        }
    } else if reserve_amount != remaining_after
        || reserve_owner == zero
        || reserve_owner_scheme != OWNER_COVENANT_ID
        || reserve_borrow_scheme != 0
        || reserve_borrow_guard != zero
        || reserve_extension != expected_extension
    {
        return Err(anyhow!("snapshot successor reserve state is inconsistent"));
    }

    let recipient_amount = item_int(&items, 13)?;
    let recipient_owner = item_bytes_32(&items, 14)?;
    let recipient_owner_scheme = item_int(&items, 15)?;
    let recipient_borrow_scheme = item_int(&items, 16)?;
    let recipient_borrow_guard = item_bytes_32(&items, 17)?;
    let recipient_extension = item_bytes_32(&items, 18)?;
    if recipient_amount != claim_amount
        || recipient_owner != owner
        || recipient_owner_scheme != owner_scheme_value
        || recipient_borrow_scheme != 0
        || recipient_borrow_guard != zero
        || recipient_extension != expected_extension
    {
        return Err(anyhow!("snapshot recipient state is inconsistent"));
    }

    let template_prefix = item_data(&items, 19)?;
    let template_suffix = item_data(&items, 20)?;
    let expected_prefix_len = usize::try_from(json_i128(&state, "kcc20TemplatePrefixLen")?)?;
    let expected_suffix_len = usize::try_from(json_i128(&state, "kcc20TemplateSuffixLen")?)?;
    let expected_template_hash = decode_hex32(&state, "kcc20TemplateHash")?;
    if template_prefix.len() != expected_prefix_len
        || template_suffix.len() != expected_suffix_len
        || template_hash(&template_prefix, &template_suffix) != expected_template_hash
    {
        return Err(anyhow!(
            "snapshot KCC20 template fingerprint is inconsistent"
        ));
    }

    let next_state = if terminal {
        Value::Null
    } else {
        let mut next = state.clone();
        let object = next
            .as_object_mut()
            .ok_or_else(|| anyhow!("snapshot controller state is not an object"))?;
        object.insert(
            "remainingRoot".into(),
            Value::String(hex::encode(&next_root)),
        );
        object.insert(
            "remainingAmount".into(),
            Value::String(remaining_after.to_string()),
        );
        object.insert(
            "claimsProcessed".into(),
            Value::String(claims_after.to_string()),
        );
        next
    };
    let object = action
        .as_object_mut()
        .ok_or_else(|| anyhow!("snapshot claim projection is not an object"))?;
    object.insert(
        "projectionSchema".into(),
        Value::String("kcc20-snapshot-claim/v1".into()),
    );
    object.insert("tokenId".into(), state["tokenId"].clone());
    object.insert(
        "manifestCommitment".into(),
        state["manifestCommitment"].clone(),
    );
    object.insert("snapshotContext".into(), state["snapshotContext"].clone());
    object.insert("shardIndex".into(), state["shardIndex"].clone());
    object.insert("holderCount".into(), state["holderCount"].clone());
    object.insert(
        "previousRoot".into(),
        Value::String(hex::encode(previous_root)),
    );
    object.insert("nextRoot".into(), Value::String(hex::encode(next_root)));
    object.insert(
        "remainingBefore".into(),
        Value::String(remaining_before.to_string()),
    );
    object.insert(
        "remainingAfter".into(),
        Value::String(remaining_after.to_string()),
    );
    object.insert(
        "claimsProcessedBefore".into(),
        Value::String(claims_before.to_string()),
    );
    object.insert(
        "claimsProcessedAfter".into(),
        Value::String(claims_after.to_string()),
    );
    object.insert("terminal".into(), Value::Bool(terminal));
    object.insert("nextState".into(), next_state);
    Ok(Some(action))
}

pub fn decode_reveal_state_value(payload: &[u8]) -> Result<Value> {
    decode_reveal_state(payload)
}

fn item_data(items: &[ScriptItem], index: usize) -> Result<Vec<u8>> {
    match items.get(index) {
        Some(ScriptItem::Data(bytes)) => Ok(bytes.clone()),
        _ => Err(anyhow!("snapshot sigscript item {index} is not byte data")),
    }
}

fn controller_state_from_items(items: &[ScriptItem], offset: usize) -> Result<Value> {
    Ok(json!({
        "migrationId": hex::encode(item_bytes_32(items, offset)?),
        "tokenId": hex::encode(item_bytes_32(items, offset + 1)?),
        "holderExtensionCommitment": hex::encode(item_bytes_32(items, offset + 2)?),
        "manifestCommitment": hex::encode(item_bytes_32(items, offset + 3)?),
        "snapshotContext": hex::encode(item_bytes_32(items, offset + 4)?),
        "kcc20TemplateHash": hex::encode(item_bytes_32(items, offset + 5)?),
        "bootstrapTemplateHash": hex::encode(item_bytes_32(items, offset + 6)?),
        "deploymentGuardCommitment": hex::encode(item_bytes_32(items, offset + 7)?),
        "claimNotBeforeDaaScore": item_int(items, offset + 8)?.to_string(),
        "shardIndex": item_int(items, offset + 9)?.to_string(),
        "globalIndexStart": item_int(items, offset + 10)?.to_string(),
        "holderCount": item_int(items, offset + 11)?.to_string(),
        "treeDepth": item_int(items, offset + 12)?.to_string(),
        "kcc20TemplatePrefixLen": item_int(items, offset + 13)?.to_string(),
        "kcc20TemplateSuffixLen": item_int(items, offset + 14)?.to_string(),
        "bootstrapTemplatePrefixLen": item_int(items, offset + 15)?.to_string(),
        "bootstrapTemplateSuffixLen": item_int(items, offset + 16)?.to_string(),
        "shardCount": item_int(items, offset + 17)?.to_string(),
        "controllerCellKas": item_int(items, offset + 18)?.to_string(),
        "reserveCellKas": item_int(items, offset + 19)?.to_string(),
        "recipientMinCellKas": item_int(items, offset + 20)?.to_string(),
        "remainingRoot": hex::encode(item_bytes_32(items, offset + 21)?),
        "remainingAmount": item_int(items, offset + 22)?.to_string(),
        "claimsProcessed": item_int(items, offset + 23)?.to_string(),
    }))
}

fn kcc20_state_from_items(items: &[ScriptItem], offset: usize) -> Result<Value> {
    Ok(json!({
        "amount": item_int(items, offset)?.to_string(),
        "owner": hex::encode(item_bytes_32(items, offset + 1)?),
        "ownerScheme": item_int(items, offset + 2)?.to_string(),
        "borrowScheme": item_int(items, offset + 3)?.to_string(),
        "borrowGuard": hex::encode(item_bytes_32(items, offset + 4)?),
        "extensionCommitment": hex::encode(item_bytes_32(items, offset + 5)?),
    }))
}

fn validate_kcc20_template_items(
    state: &Value,
    items: &[ScriptItem],
    prefix_index: usize,
    suffix_index: usize,
) -> Result<()> {
    let prefix = item_data(items, prefix_index)?;
    let suffix = item_data(items, suffix_index)?;
    if prefix.len() != usize::try_from(json_i128(state, "kcc20TemplatePrefixLen")?)?
        || suffix.len() != usize::try_from(json_i128(state, "kcc20TemplateSuffixLen")?)?
        || template_hash(&prefix, &suffix) != decode_hex32(state, "kcc20TemplateHash")?
    {
        return Err(anyhow!(
            "snapshot KCC20 template fingerprint is inconsistent"
        ));
    }
    Ok(())
}

fn json_i128(value: &Value, key: &str) -> Result<i128> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("snapshot state is missing {key}"))?
        .parse()
        .map_err(Into::into)
}

fn validate_state_configuration(state: &Value) -> Result<()> {
    validate_controller_state(state, true)
}

fn validate_prestart_state(state: &Value) -> Result<()> {
    validate_controller_state(state, false)
}

fn validate_controller_state(state: &Value, initialized: bool) -> Result<()> {
    for key in [
        "migrationId",
        "holderExtensionCommitment",
        "manifestCommitment",
        "snapshotContext",
        "kcc20TemplateHash",
        "bootstrapTemplateHash",
        "remainingRoot",
    ] {
        if decode_hex32(state, key)? == [0_u8; 32] {
            return Err(anyhow!("snapshot controller {key} is zero"));
        }
    }
    let token_id = decode_hex32(state, "tokenId")?;
    if initialized != (token_id != [0_u8; 32]) {
        return Err(anyhow!(
            "snapshot controller token initialization state is invalid"
        ));
    }

    let claim_not_before = json_i128(state, "claimNotBeforeDaaScore")?;
    let shard_index = json_i128(state, "shardIndex")?;
    let shard_count = json_i128(state, "shardCount")?;
    let guard = decode_hex32(state, "deploymentGuardCommitment")?;
    let global_index_start = json_i128(state, "globalIndexStart")?;
    let holder_count = json_i128(state, "holderCount")?;
    let tree_depth = json_i128(state, "treeDepth")?;
    let prefix_len = json_i128(state, "kcc20TemplatePrefixLen")?;
    let suffix_len = json_i128(state, "kcc20TemplateSuffixLen")?;
    let bootstrap_prefix_len = json_i128(state, "bootstrapTemplatePrefixLen")?;
    let bootstrap_suffix_len = json_i128(state, "bootstrapTemplateSuffixLen")?;
    let controller_cell_kas = json_i128(state, "controllerCellKas")?;
    let reserve_cell_kas = json_i128(state, "reserveCellKas")?;
    let recipient_min_cell_kas = json_i128(state, "recipientMinCellKas")?;
    let remaining_amount = json_i128(state, "remainingAmount")?;
    let claims_processed = json_i128(state, "claimsProcessed")?;
    let last_global_index = global_index_start
        .checked_add(holder_count.saturating_sub(1))
        .ok_or_else(|| anyhow!("snapshot controller global range overflows"))?;
    let combined_cell_kas = controller_cell_kas
        .checked_add(reserve_cell_kas)
        .ok_or_else(|| anyhow!("snapshot controller cell KAS overflows"))?;
    let tree_width = 1_i128
        .checked_shl(u32::try_from(tree_depth).unwrap_or(u32::MAX))
        .unwrap_or(0);
    if claim_not_before <= 0
        || claim_not_before >= LOCK_TIME_THRESHOLD
        || shard_index < 0
        || !(1..=8).contains(&shard_count)
        || shard_index >= shard_count
        || (shard_index == 0 && guard == [0_u8; 32])
        || (shard_index > 0 && guard != [0_u8; 32])
        || global_index_start < 0
        || holder_count <= 0
        || last_global_index > i64::MAX as i128
        || !(1..=32).contains(&tree_depth)
        || holder_count > tree_width
        || prefix_len <= 0
        || suffix_len <= 0
        || bootstrap_prefix_len <= 0
        || bootstrap_suffix_len <= 0
        || prefix_len
            .checked_add(suffix_len)
            .is_none_or(|total| total > i64::MAX as i128)
        || bootstrap_prefix_len
            .checked_add(bootstrap_suffix_len)
            .is_none_or(|total| total > i64::MAX as i128)
        || remaining_amount <= 0
        || claims_processed < 0
        || claims_processed >= holder_count
        || (!initialized && claims_processed != 0)
        || controller_cell_kas < MIN_KCC20_CELL_SOMPI
        || reserve_cell_kas < MIN_KCC20_CELL_SOMPI
        || recipient_min_cell_kas < MIN_KCC20_CELL_SOMPI
        || combined_cell_kas > i64::MAX as i128
        || combined_cell_kas < recipient_min_cell_kas
    {
        return Err(anyhow!(
            "snapshot controller state configuration is invalid"
        ));
    }
    Ok(())
}
fn decode_hex32(value: &Value, key: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(
        value
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("snapshot state is missing {key}"))?,
    )?;
    if bytes.len() != 32 {
        return Err(anyhow!("snapshot state {key} is not 32 bytes"));
    }
    Ok(bytes)
}

fn snapshot_hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut data = Vec::new();
    for part in parts {
        data.extend_from_slice(part);
    }
    blake2b_256(&data).to_vec()
}

fn template_hash(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(16 + prefix.len() + suffix.len());
    preimage.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
    preimage.extend_from_slice(prefix);
    preimage.extend_from_slice(&(suffix.len() as u64).to_le_bytes());
    preimage.extend_from_slice(suffix);
    blake3::hash(&preimage).as_bytes().to_vec()
}

fn le_i64(value: i128) -> Result<[u8; 8]> {
    let value = i64::try_from(value)?;
    if value < 0 {
        return Err(anyhow!("snapshot Merkle integer is negative"));
    }
    Ok(value.to_le_bytes())
}

fn entitlement_leaf(
    context: &[u8],
    global_index: i128,
    owner_scheme: u8,
    owner: &[u8],
    amount: i128,
) -> Result<Vec<u8>> {
    let global = le_i64(global_index)?;
    let amount = le_i64(amount)?;
    Ok(snapshot_hash(&[
        &[0x10],
        context,
        &global,
        &[owner_scheme],
        owner,
        &amount,
    ]))
}

fn claimed_leaf(context: &[u8], global_index: i128) -> Result<Vec<u8>> {
    let global = le_i64(global_index)?;
    Ok(snapshot_hash(&[&[0x12], context, &global]))
}

fn fold(mut node: Vec<u8>, siblings: &[u8], mut leaf_index: i128) -> Result<Vec<u8>> {
    if leaf_index < 0 {
        return Err(anyhow!("snapshot leaf index is negative"));
    }
    for sibling in siblings.chunks_exact(32) {
        node = if leaf_index % 2 == 0 {
            snapshot_hash(&[&[0x11], &node, sibling])
        } else {
            snapshot_hash(&[&[0x11], sibling, &node])
        };
        leaf_index /= 2;
    }
    Ok(node)
}

fn decode_reveal_state(payload: &[u8]) -> Result<Value> {
    if !matches!(
        payload.len(),
        LEGACY_SNAPSHOT_CONTROLLER_SCRIPT_LEN
            | PRE_COMPACT_START_SNAPSHOT_CONTROLLER_SCRIPT_LEN
            | SNAPSHOT_CONTROLLER_SCRIPT_LEN
    ) {
        return Err(anyhow!(
            "snapshot controller reveal script is {} bytes, expected {}, {}, or {}",
            payload.len(),
            LEGACY_SNAPSHOT_CONTROLLER_SCRIPT_LEN,
            PRE_COMPACT_START_SNAPSHOT_CONTROLLER_SCRIPT_LEN,
            SNAPSHOT_CONTROLLER_SCRIPT_LEN
        ));
    }
    decode_state_payload(
        &payload[SNAPSHOT_CONTROLLER_STATE_START
            ..SNAPSHOT_CONTROLLER_STATE_START + SNAPSHOT_CONTROLLER_STATE_LEN],
    )
}

fn decode_state_payload(payload: &[u8]) -> Result<Value> {
    if payload.len() != SNAPSHOT_CONTROLLER_STATE_LEN {
        return Err(anyhow!(
            "snapshot controller state is {} bytes, expected {}",
            payload.len(),
            SNAPSHOT_CONTROLLER_STATE_LEN
        ));
    }
    let fixed = |marker: usize, start: usize, end: usize, label: &str| -> Result<String> {
        if payload[marker] != 32 {
            return Err(anyhow!(
                "snapshot controller {label} push is not OP_DATA_32"
            ));
        }
        Ok(hex::encode(&payload[start..end]))
    };
    let int = |marker: usize, start: usize, end: usize, label: &str| -> Result<String> {
        if payload[marker] != 8 {
            return Err(anyhow!("snapshot controller {label} push is not OP_DATA_8"));
        }
        Ok(parse_minimal_int(&payload[start..end]).to_string())
    };
    Ok(json!({
        "migrationId": fixed(0, 1, 33, "migrationId")?,
        "tokenId": fixed(33, 34, 66, "tokenId")?,
        "holderExtensionCommitment": fixed(66, 67, 99, "holderExtensionCommitment")?,
        "manifestCommitment": fixed(99, 100, 132, "manifestCommitment")?,
        "snapshotContext": fixed(132, 133, 165, "snapshotContext")?,
        "kcc20TemplateHash": fixed(165, 166, 198, "kcc20TemplateHash")?,
        "bootstrapTemplateHash": fixed(198, 199, 231, "bootstrapTemplateHash")?,
        "deploymentGuardCommitment": fixed(231, 232, 264, "deploymentGuardCommitment")?,
        "claimNotBeforeDaaScore": int(264, 265, 273, "claimNotBeforeDaaScore")?,
        "shardIndex": int(273, 274, 282, "shardIndex")?,
        "globalIndexStart": int(282, 283, 291, "globalIndexStart")?,
        "holderCount": int(291, 292, 300, "holderCount")?,
        "treeDepth": int(300, 301, 309, "treeDepth")?,
        "kcc20TemplatePrefixLen": int(309, 310, 318, "kcc20TemplatePrefixLen")?,
        "kcc20TemplateSuffixLen": int(318, 319, 327, "kcc20TemplateSuffixLen")?,
        "bootstrapTemplatePrefixLen": int(327, 328, 336, "bootstrapTemplatePrefixLen")?,
        "bootstrapTemplateSuffixLen": int(336, 337, 345, "bootstrapTemplateSuffixLen")?,
        "shardCount": int(345, 346, 354, "shardCount")?,
        "controllerCellKas": int(354, 355, 363, "controllerCellKas")?,
        "reserveCellKas": int(363, 364, 372, "reserveCellKas")?,
        "recipientMinCellKas": int(372, 373, 381, "recipientMinCellKas")?,
        "remainingRoot": fixed(381, 382, 414, "remainingRoot")?,
        "remainingAmount": int(414, 415, 423, "remainingAmount")?,
        "claimsProcessed": int(423, 424, 432, "claimsProcessed")?,
    }))
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

    fn push_int(script: &mut Vec<u8>, value: i64) {
        script.push(8);
        script.extend_from_slice(&value.to_le_bytes());
    }

    fn artifact_script() -> Vec<u8> {
        let artifact: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-snapshot-controller/KCC20SnapshotController.placeholder.json"
        ))
        .expect("embedded snapshot controller artifact");
        artifact["script"]
            .as_array()
            .expect("script array")
            .iter()
            .map(|value| value.as_u64().expect("script byte") as u8)
            .collect()
    }

    fn kcc20_template_parts() -> (Vec<u8>, Vec<u8>) {
        let artifact: Value =
            serde_json::from_str(include_str!("../fixtures/kcc20/KCC20.placeholder.json"))
                .expect("embedded KCC20 artifact");
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

    fn claim_sigscript(
        reserve_amount: i64,
        recipient_owner: u8,
        extension: u8,
        template_prefix: &[u8],
        template_suffix: &[u8],
    ) -> Vec<u8> {
        let mut sigscript = Vec::new();
        push_int(&mut sigscript, 1);
        push_int(&mut sigscript, 1);
        push_int(&mut sigscript, 3);
        push_data(&mut sigscript, &[0xaa; 32]);
        push_data(&mut sigscript, &[2]);
        push_int(&mut sigscript, 75);
        push_data(&mut sigscript, &[0xbb; 32]);
        for (amount, owner, scheme) in [
            (reserve_amount, 0xcc, OWNER_COVENANT_ID as i64),
            (75, recipient_owner, OWNER_P2SH as i64),
        ] {
            push_int(&mut sigscript, amount);
            push_data(&mut sigscript, &[owner; 32]);
            push_int(&mut sigscript, scheme);
            push_int(&mut sigscript, 0);
            push_data(&mut sigscript, &[0; 32]);
            push_data(&mut sigscript, &[extension; 32]);
        }
        push_data(&mut sigscript, template_prefix);
        push_data(&mut sigscript, template_suffix);
        push_data(&mut sigscript, &CLAIM_TAG);
        push_data(&mut sigscript, &[0x51]);
        sigscript
    }

    fn terminal_claim_sigscript(template_prefix: &[u8], template_suffix: &[u8]) -> Vec<u8> {
        let mut sigscript = Vec::new();
        push_int(&mut sigscript, 1);
        push_int(&mut sigscript, 1);
        push_int(&mut sigscript, 3);
        push_data(&mut sigscript, &[0xaa; 32]);
        push_data(&mut sigscript, &[2]);
        push_int(&mut sigscript, 75);
        push_data(&mut sigscript, &[0xbb; 32]);
        for (amount, owner, scheme, extension) in [
            (0, 0x00, OWNER_P2PK_SCHNORR as i64, 0x00),
            (75, 0xaa, OWNER_P2SH as i64, 0x33),
        ] {
            push_int(&mut sigscript, amount);
            push_data(&mut sigscript, &[owner; 32]);
            push_int(&mut sigscript, scheme);
            push_int(&mut sigscript, 0);
            push_data(&mut sigscript, &[0; 32]);
            push_data(&mut sigscript, &[extension; 32]);
        }
        push_data(&mut sigscript, template_prefix);
        push_data(&mut sigscript, template_suffix);
        push_data(&mut sigscript, &CLAIM_TAG);
        push_data(&mut sigscript, &[0x51]);
        sigscript
    }

    fn patch_i64_state(script: &mut [u8], payload_offset: usize, value: i64) {
        let start = SNAPSHOT_CONTROLLER_STATE_START + payload_offset;
        script[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn hex_value(value: &Value, key: &str) -> Vec<u8> {
        hex::decode(value[key].as_str().expect("hex string")).expect("valid hex")
    }

    fn int_value(value: &Value, key: &str) -> i128 {
        value[key]
            .as_str()
            .expect("integer string")
            .parse()
            .unwrap()
    }

    fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
        assert!(bytes.len() <= 75);
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }

    fn push_i64(out: &mut Vec<u8>, value: i128) {
        push_bytes(out, &le_i64(value).expect("i64 vector value"));
    }

    fn controller_state_commitment(state: &Value) -> String {
        let mut encoded = Vec::new();
        for key in [
            "migrationId",
            "tokenId",
            "holderExtensionCommitment",
            "manifestCommitment",
            "snapshotContext",
            "kcc20TemplateHash",
            "bootstrapTemplateHash",
            "deploymentGuardCommitment",
        ] {
            push_bytes(&mut encoded, &hex_value(state, key));
        }
        for key in [
            "claimNotBeforeDaaScore",
            "shardIndex",
            "globalIndexStart",
            "holderCount",
            "treeDepth",
            "kcc20TemplatePrefixLen",
            "kcc20TemplateSuffixLen",
            "bootstrapTemplatePrefixLen",
            "bootstrapTemplateSuffixLen",
            "shardCount",
            "controllerCellKas",
            "reserveCellKas",
            "recipientMinCellKas",
        ] {
            push_i64(&mut encoded, int_value(state, key));
        }
        push_bytes(&mut encoded, &hex_value(state, "remainingRoot"));
        push_i64(&mut encoded, int_value(state, "remainingAmount"));
        push_i64(&mut encoded, int_value(state, "claimsProcessed"));
        hex::encode(snapshot_hash(&[
            b"kcc20-snapshot-controller-state/v2",
            &encoded,
        ]))
    }

    #[test]
    fn matches_wallet_codec_vectors() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../fixtures/kcc20-snapshot-controller/codec-vectors.v1.json"
        ))
        .expect("snapshot codec vectors");
        assert_eq!(fixture["schema"], "kaspacom-snapshot-codec-vectors/v1");
        assert_eq!(
            fixture["codec"],
            "kasmelt-snapshot-v2/blake2b256/sharded-full-claim"
        );
        let case = &fixture["cases"][0];
        let context = hex_value(case, "context");
        let holders = case["holders"].as_array().expect("holders");
        let holder_a = &holders[0];
        let holder_b = &holders[1];
        let owner_a = hex_value(holder_a, "owner");
        let owner_b = hex_value(holder_b, "owner");
        let leaf_a = entitlement_leaf(
            &context,
            int_value(holder_a, "globalIndex"),
            int_value(holder_a, "ownerScheme") as u8,
            &owner_a,
            int_value(holder_a, "amount"),
        )
        .expect("leaf A");
        let leaf_b = entitlement_leaf(
            &context,
            int_value(holder_b, "globalIndex"),
            int_value(holder_b, "ownerScheme") as u8,
            &owner_b,
            int_value(holder_b, "amount"),
        )
        .expect("leaf B");
        let pad2 = snapshot_hash(&[&[0x13], &context, &le_i64(2).unwrap(), &le_i64(2).unwrap()]);
        let pad3 = snapshot_hash(&[&[0x13], &context, &le_i64(2).unwrap(), &le_i64(3).unwrap()]);
        let left = snapshot_hash(&[&[0x11], &leaf_a, &leaf_b]);
        let right = snapshot_hash(&[&[0x11], &pad2, &pad3]);
        let root_before = snapshot_hash(&[&[0x11], &left, &right]);
        let claimed_b = claimed_leaf(&context, int_value(holder_b, "globalIndex")).unwrap();
        let mut siblings = Vec::new();
        siblings.extend_from_slice(&leaf_a);
        siblings.extend_from_slice(&right);
        let root_after = fold(
            claimed_b.clone(),
            &siblings,
            int_value(&case["proof"], "claimShardLeafIndex"),
        )
        .expect("folded proof");

        let hashes = &case["hashes"];
        assert_eq!(hex::encode(&leaf_a), hashes["entitlementA"]);
        assert_eq!(hex::encode(&leaf_b), hashes["entitlementB"]);
        assert_eq!(hex::encode(&claimed_b), hashes["claimedB"]);
        assert_eq!(hex::encode(&pad2), hashes["padding2"]);
        assert_eq!(hex::encode(&pad3), hashes["padding3"]);
        assert_eq!(hex::encode(&left), hashes["branchLeft"]);
        assert_eq!(hex::encode(&right), hashes["branchRight"]);
        assert_eq!(hex::encode(&root_before), hashes["rootBefore"]);
        assert_eq!(hex::encode(&root_after), hashes["rootAfter"]);

        let preimages = &case["preimages"];
        assert_eq!(
            hex::encode(
                [
                    &[0x10][..],
                    &context,
                    &le_i64(int_value(holder_a, "globalIndex")).unwrap(),
                    &[int_value(holder_a, "ownerScheme") as u8],
                    &owner_a,
                    &le_i64(int_value(holder_a, "amount")).unwrap(),
                ]
                .concat()
            ),
            preimages["entitlementA"]
        );
        assert_eq!(
            hex::encode(
                [
                    &[0x12][..],
                    &context,
                    &le_i64(int_value(holder_b, "globalIndex")).unwrap(),
                ]
                .concat()
            ),
            preimages["claimedB"]
        );
        assert_eq!(
            hex::encode([&[0x11][..], &left, &right].concat()),
            preimages["rootBefore"]
        );
        assert_eq!(
            controller_state_commitment(&case["controllerState"]),
            case["controllerStateCommitment"]
        );
    }

    #[test]
    fn decodes_uninitialized_controller_state() {
        let script = artifact_script();
        let hash = Kcc20SnapshotControllerDecoder::template_hash_of_compiled_script(&script)
            .expect("template hash");
        let decoder = Kcc20SnapshotControllerDecoder::new(hash);
        assert!(decoder.matches_reveal_script(&script));
        let mut another_shard = script.clone();
        another_shard[274] ^= 1;
        another_shard[283] ^= 2;
        assert!(decoder.matches_reveal_script(&another_shard));
        let state = decoder
            .decode_constructor(&script)
            .expect("controller state");
        assert_eq!(state["state"]["remainingAmount"], "1000");
        assert_eq!(state["state"]["claimNotBeforeDaaScore"], "100");
        assert_eq!(state["state"]["holderCount"], "2");
        assert_eq!(state["state"]["treeDepth"], "1");
        assert_eq!(state["state"]["claimsProcessed"], "0");
        assert_eq!(state["state"]["tokenId"], "00".repeat(32));
        assert_eq!(state["state"]["migrationId"], "10".repeat(32));
    }

    #[test]
    fn rejects_foreign_template_and_malformed_state() {
        let script = artifact_script();
        let hash = Kcc20SnapshotControllerDecoder::template_hash_of_compiled_script(&script)
            .expect("template hash");
        let decoder = Kcc20SnapshotControllerDecoder::new(hash);
        let mut foreign = script.clone();
        *foreign.last_mut().expect("script byte") ^= 1;
        assert!(!decoder.matches_reveal_script(&foreign));
        assert!(decoder
            .decode_state(&vec![0; SNAPSHOT_CONTROLLER_STATE_LEN])
            .is_err());
    }

    #[test]
    fn decodes_claim_projection_fields() {
        let (template_prefix, template_suffix) = kcc20_template_parts();
        let sigscript = claim_sigscript(925, 0xaa, 0x33, &template_prefix, &template_suffix);
        let action = decode_claim_action(&sigscript)
            .expect("valid claim")
            .expect("claim action");
        assert_eq!(action["globalIndex"], "1");
        assert_eq!(action["claimAmount"], "75");
        assert_eq!(action["successorReserveAmount"], "925");
        assert_eq!(action["recipient"], hex::encode([0xaa; 32]));

        let mut reveal = artifact_script();
        // The controller artifact predates the current KCC20 fixture. Patch
        // its constructor state just as a deployment builder does so this
        // transition test also covers template-version independence.
        let current_template_hash = template_hash(&template_prefix, &template_suffix);
        reveal[SNAPSHOT_CONTROLLER_STATE_START + 166..SNAPSHOT_CONTROLLER_STATE_START + 198]
            .copy_from_slice(&current_template_hash);
        patch_i64_state(&mut reveal, 310, template_prefix.len() as i64);
        patch_i64_state(&mut reveal, 319, template_suffix.len() as i64);
        let context = [0x55; 32];
        let leaf = entitlement_leaf(&context, 1, 3, &[0xaa; 32], 75).unwrap();
        let root = fold(leaf, &[0xbb; 32], 1).unwrap();
        reveal[SNAPSHOT_CONTROLLER_STATE_START + 382..SNAPSHOT_CONTROLLER_STATE_START + 414]
            .copy_from_slice(&root);
        // Claims operate only after signerless start has initialized the exact token id.
        reveal[SNAPSHOT_CONTROLLER_STATE_START + 34..SNAPSHOT_CONTROLLER_STATE_START + 66]
            .copy_from_slice(&[0x11; 32]);
        let transition = decode_claim_transition(&sigscript, &reveal)
            .expect("valid transition")
            .expect("claim transition");
        assert_eq!(transition["remainingBefore"], "1000");
        assert_eq!(transition["remainingAfter"], "925");
        assert_eq!(transition["claimsProcessedAfter"], "1");
        assert_eq!(transition["terminal"], false);
        assert_eq!(transition["nextState"]["remainingAmount"], "925");

        let wrong_recipient = claim_sigscript(925, 0xab, 0x33, &template_prefix, &template_suffix);
        assert!(decode_claim_transition(&wrong_recipient, &reveal)
            .unwrap_err()
            .to_string()
            .contains("recipient state is inconsistent"));
        let wrong_reserve = claim_sigscript(924, 0xaa, 0x33, &template_prefix, &template_suffix);
        assert!(decode_claim_transition(&wrong_reserve, &reveal)
            .unwrap_err()
            .to_string()
            .contains("successor reserve state is inconsistent"));
        let wrong_extension = claim_sigscript(925, 0xaa, 0x34, &template_prefix, &template_suffix);
        assert!(decode_claim_transition(&wrong_extension, &reveal)
            .unwrap_err()
            .to_string()
            .contains("successor reserve state is inconsistent"));
        let wrong_template = claim_sigscript(925, 0xaa, 0x33, &[0x6a], &template_suffix);
        let integrity_error = decode_claim_transition(&wrong_template, &reveal).unwrap_err();
        assert!(integrity_error.to_string().contains("template fingerprint is inconsistent"));
        assert!(integrity_error.downcast_ref::<crate::InterpretationFailure>().is_none());

        let terminal_sigscript = terminal_claim_sigscript(&template_prefix, &template_suffix);
        let mut terminal_reveal = reveal.clone();
        patch_i64_state(&mut terminal_reveal, 415, 75);
        patch_i64_state(&mut terminal_reveal, 424, 1);
        let terminal = decode_claim_transition(&terminal_sigscript, &terminal_reveal)
            .expect("valid terminal transition")
            .expect("terminal claim transition");
        assert_eq!(terminal["remainingBefore"], "75");
        assert_eq!(terminal["remainingAfter"], "0");
        assert_eq!(terminal["successorReserveAmount"], "0");
        assert_eq!(terminal["claimsProcessedBefore"], "1");
        assert_eq!(terminal["claimsProcessedAfter"], "2");
        assert_eq!(terminal["terminal"], true);
        assert_eq!(terminal["nextState"], Value::Null);
    }
}
