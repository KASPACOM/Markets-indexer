//! Exact artifact decoders for the versioned fee protocol.
//!
//! The state span may change between market instances. Everything outside that
//! span must match the pinned artifact byte for byte before we label a reveal.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};
use tn12_indexer_core::{
    blake2b_256, parse_minimal_int, read_push, KnownTemplate, RestTransaction,
};

use crate::kcc20::{args_prefix_before_reveal, item_int, script_items, ScriptItem};
use crate::TemplateDecoder;

struct StateField {
    name: String,
    kind: String,
    fixed_len: Option<usize>,
}

pub struct Kcc20FeeV1Decoder {
    template: KnownTemplate,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    state_len: usize,
    template_hash: [u8; 32],
    fields: Vec<StateField>,
    entries: BTreeMap<[u8; 4], String>,
    #[cfg(test)]
    placeholder: Vec<u8>,
}

impl Kcc20FeeV1Decoder {
    fn from_artifact(template: KnownTemplate, raw: &str) -> Result<Self> {
        let artifact: Value = serde_json::from_str(raw)?;
        let name = crate::template_name(template);
        let contract = artifact["contracts"]
            .get(name)
            .ok_or_else(|| anyhow!("missing {name} in fee artifact"))?;
        let compiled = &contract["compiled"];
        let script: Vec<u8> = serde_json::from_value(compiled["bytecode"].clone())?;
        let offset = compiled["state_span"]["offset"]
            .as_u64()
            .context("fee artifact state offset")? as usize;
        let state_len = compiled["state_span"]["len"]
            .as_u64()
            .context("fee artifact state length")? as usize;
        let end = offset
            .checked_add(state_len)
            .context("fee state overflow")?;
        if state_len == 0 || end > script.len() {
            bail!("invalid fee artifact state span");
        }
        let prefix = script[..offset].to_vec();
        let suffix = script[end..].to_vec();
        let mut hash = blake3::Hasher::new();
        hash.update(&(prefix.len() as u64).to_le_bytes());
        hash.update(&prefix);
        hash.update(&(suffix.len() as u64).to_le_bytes());
        hash.update(&suffix);
        let template_hash = *hash.finalize().as_bytes();
        let declared: Vec<u8> = serde_json::from_value(compiled["template_hash"].clone())?;
        if declared.as_slice() != template_hash {
            bail!("fee artifact template hash mismatch for {name}");
        }

        let fields = contract["runtime_state"]["fields"]
            .as_array()
            .context("fee artifact runtime state fields")?
            .iter()
            .map(|field| -> Result<StateField> {
                Ok(StateField {
                    name: field["name"]
                        .as_str()
                        .context("fee state field name")?
                        .to_owned(),
                    kind: field["type"]["kind"]
                        .as_str()
                        .context("fee state field kind")?
                        .to_owned(),
                    fixed_len: field["type"]["len"].as_u64().map(|n| n as usize),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if fields.is_empty()
            || fields.iter().map(|f| &f.name).collect::<HashSet<_>>().len() != fields.len()
        {
            bail!("invalid fee artifact state fields for {name}");
        }
        let mut entries = BTreeMap::new();
        for (entry, value) in contract["entries"]
            .as_object()
            .context("fee artifact entries")?
        {
            let bytes = hex::decode(value["dispatch_tag"].as_str().context("fee entry tag")?)?;
            let tag: [u8; 4] = bytes
                .try_into()
                .map_err(|_| anyhow!("invalid fee entry tag"))?;
            if entries.insert(tag, entry.clone()).is_some() {
                bail!("duplicate fee entry tag for {name}");
            }
        }
        if entries.is_empty() {
            bail!("fee artifact has no entries for {name}");
        }
        let decoder = Self {
            template,
            prefix,
            suffix,
            state_len,
            template_hash,
            fields,
            entries,
            #[cfg(test)]
            placeholder: script.clone(),
        };
        decoder.decode_constructor(&script)?;
        Ok(decoder)
    }

    fn state_bytes<'a>(&self, reveal: &'a [u8]) -> Result<&'a [u8]> {
        if !self.exact_template(reveal) {
            bail!("fee reveal does not match pinned {} artifact", self.name());
        }
        Ok(&reveal[self.prefix.len()..self.prefix.len() + self.state_len])
    }

    fn exact_template(&self, reveal: &[u8]) -> bool {
        reveal.len() == self.prefix.len() + self.state_len + self.suffix.len()
            && reveal.starts_with(&self.prefix)
            && reveal.ends_with(&self.suffix)
    }

    fn script_for_state(&self, state: &Value) -> Result<Vec<u8>> {
        let mut script = self.prefix.clone();
        for field in &self.fields {
            let value = state
                .get(&field.name)
                .context("missing fee receipt field")?;
            let bytes = match field.kind.as_str() {
                "fixed_bytes" => {
                    let bytes = hex::decode(value.as_str().context("fee field must be hex")?)?;
                    if Some(bytes.len()) != field.fixed_len {
                        bail!("incorrect fee field width");
                    }
                    bytes
                }
                "int" => {
                    let number = value
                        .as_str()
                        .context("fee integer must be decimal")?
                        .parse::<i64>()?;
                    if number < 0 {
                        bail!("negative fee integer");
                    }
                    number.to_le_bytes().to_vec()
                }
                "byte" => vec![u8::try_from(
                    value.as_u64().context("fee byte must be numeric")?,
                )?],
                "bool" => vec![u8::from(
                    value.as_bool().context("fee bool must be boolean")?,
                )],
                _ => bail!("unsupported fee field type"),
            };
            match bytes.len() {
                1..=75 => script.push(bytes.len() as u8),
                76..=255 => script.extend([0x4c, bytes.len() as u8]),
                256..=65535 => {
                    script.push(0x4d);
                    script.extend((bytes.len() as u16).to_le_bytes());
                }
                _ => bail!("unsupported fee field width"),
            }
            script.extend(bytes);
        }
        script.extend(&self.suffix);
        Ok(script)
    }

    fn decode_fields(&self, mut state: &[u8]) -> Result<Value> {
    crate::interpretation("kcc20_fee_v1.rs:decode_fields", (|| {
        if state.len() != self.state_len {
            bail!("invalid {} state length", self.name());
        }
        let mut result = Map::new();
        for field in &self.fields {
            let (bytes, rest) = read_push(state)
                .ok_or_else(|| anyhow!("invalid state push for {}.{}", self.name(), field.name))?;
            let expected = match field.kind.as_str() {
                "int" => 8,
                "byte" | "bool" => 1,
                "fixed_bytes" => field.fixed_len.context("missing fixed byte length")?,
                _ => bail!("unsupported state field {}.{}", self.name(), field.name),
            };
            if bytes.len() != expected || !canonical_push(state, expected) {
                bail!(
                    "noncanonical state value for {}.{}",
                    self.name(),
                    field.name
                );
            }
            let value = match field.kind.as_str() {
                "fixed_bytes" => Value::String(hex::encode(bytes)),
                "int" if parse_minimal_int(bytes) >= 0 => {
                    Value::String(parse_minimal_int(bytes).to_string())
                }
                "byte" => Value::from(bytes[0]),
                "bool" if bytes[0] <= 1 => Value::Bool(bytes[0] == 1),
                _ => bail!("invalid state value for {}.{}", self.name(), field.name),
            };
            result.insert(field.name.clone(), value);
            state = rest;
        }
        if !state.is_empty() {
            bail!("extra state bytes in {} reveal", self.name());
        }
        self.validate_semantics(&mut result).map_err(|error| error.context(crate::IntegrityFailure("fee_state_commitments")))?;
        Ok(Value::Object(result))

    })())
}

    fn validate_semantics(&self, state: &mut Map<String, Value>) -> Result<()> {
        let zero = hex::encode([0; 32]);
        if matches!(
            self.template,
            KnownTemplate::Kcc20FeeEscrowV1 | KnownTemplate::Kcc20FeeRecipientV1
        ) {
            let self_hash = hex::encode(self.template_hash);
            if state.get("self_template").and_then(Value::as_str) != Some(self_hash.as_str())
                || number(state, "self_prefix")? != self.prefix.len() as u64
                || number(state, "self_suffix")? != self.suffix.len() as u64
            {
                bail!("fee receipt/account self-template anchor mismatch");
            }
            let role = number(state, "role")?;
            let protocol = number(state, "protocol_amount")?;
            let creator = number(state, "creator_amount")?;
            if role > 2
                || state["token"] == zero
                || protocol
                    .checked_add(creator)
                    .is_none_or(|sum| sum > i64::MAX as u64)
            {
                bail!("invalid fee role or entitlement total");
            }
            if role == 0 {
                if self.template != KnownTemplate::Kcc20FeeEscrowV1
                    || state["market"] == zero
                    || state["policy"] == zero
                    || protocol + creator == 0
                    || (protocol != 0 && protocol < 50_000_000)
                    || (creator != 0 && creator < 50_000_000)
                    || state["protocol_account"] == zero
                    || state["protocol_account"] == state["creator_account"]
                    || (creator > 0 && state["creator_account"] == zero)
                    || state["owner"] != zero
                    || number(state, "owner_scheme")? != 0
                    || state["guard_template"] != zero
                    || number(state, "guard_prefix")? != 0
                    || number(state, "guard_suffix")? != 0
                {
                    bail!("invalid fee receipt state");
                }
            } else if role == 1 {
                let scheme = number(state, "owner_scheme")?;
                let guard_is_zero = state["guard_template"] == zero;
                let prefix = number(state, "guard_prefix")?;
                let suffix = number(state, "guard_suffix")?;
                let unbound = state["market"] == zero && state["policy"] == zero;
                if self.template != KnownTemplate::Kcc20FeeEscrowV1
                    || (state["market"] == zero) != (state["policy"] == zero)
                    || protocol != 0
                    || creator != 0
                    || state["owner"] == zero
                    || scheme > 4
                    || state["protocol_account"] != zero
                    || state["creator_account"] != zero
                    || (unbound && (scheme != 0 || state["action_hash"] != zero))
                    || match scheme {
                        0..=2 => !guard_is_zero || prefix != 0 || suffix != 0,
                        3 => guard_is_zero || prefix != 0 || suffix != 0,
                        4 => guard_is_zero || prefix == 0 || suffix == 0,
                        _ => true,
                    }
                {
                    bail!("invalid fee account state");
                }
                state.insert(
                    "bindingStatus".to_owned(),
                    Value::String(if unbound { "unbound" } else { "bound" }.to_owned()),
                );
            } else if self.template != KnownTemplate::Kcc20FeeRecipientV1
                || state["market"] == zero
                || state["policy"] == zero
                || protocol != 0
                || creator != 0
                || state["owner"] == zero
                || number(state, "owner_scheme")? != 0
            {
                bail!("invalid fee recipient state");
            }
            state.insert(
                "roleName".to_owned(),
                Value::String(
                    match role {
                        0 => "receipt",
                        1 => "account",
                        _ => "recipient",
                    }
                    .to_owned(),
                ),
            );
            return Ok(());
        }

        let policy = hex::decode(
            state
                .get("feePolicy")
                .and_then(Value::as_str)
                .context("missing fee policy")?,
        )?;
        let reference = pinned_policy();
        if policy.len() != 361 || policy[0] != 1 || policy[73..] != reference[73..] {
            bail!("unsupported fee policy or template set");
        }
        let bps = u64::from_le_bytes(policy[1..9].try_into()?);
        if bps > 500
            || policy[9..41] == [0; 32]
            || policy[9..41] == policy[41..73]
            || (bps == 0) != (policy[41..73] == [0; 32])
        {
            bail!("invalid fee policy rate or accounts");
        }
        if number(state, "priceScale")? == 0 {
            bail!("invalid fee market price scale");
        }
        let role_tuple_offset = match self.template {
            KnownTemplate::Kcc20FeeRootV1 => Some((121, 1)),
            KnownTemplate::Kcc20FeeHolderV1 => Some((169, 0)),
            KnownTemplate::Kcc20FeeAskV1 => Some((217, 2)),
            KnownTemplate::Kcc20FeeBidV1 => Some((265, 3)),
            _ => None,
        };
        if let Some((offset, mode)) = role_tuple_offset {
            let mut tuple = self.template_hash.to_vec();
            tuple.extend((self.prefix.len() as u64).to_le_bytes());
            tuple.extend((self.suffix.len() as u64).to_le_bytes());
            if &policy[offset..offset + 48] != tuple.as_slice() || number(state, "mode")? != mode {
                bail!("fee market role does not match its policy template");
            }
            let amount = number(state, "amount")?;
            let price = number(state, "unitPrice")?;
            if number(state, "owner_scheme")? > 4
                || (mode != 1 && state["owner"] == zero)
                || state["canonicalTokenId"] == zero
                || state["wrapper_spk_hash"] == zero
                || (mode == 1 && price != 0)
                || (mode == 0 && (amount == 0 || price != 0))
                || ((mode == 2 || mode == 3) && (amount == 0 || price == 0))
                || (mode != 1 && state["payout_script_hash"] == zero)
            {
                bail!("invalid fee market role state");
            }
            // Shared holder balances use the standard KCC-2 spelling. Keep
            // the artifact field intact for script reconstruction.
            let owner_scheme = number(state, "owner_scheme")?;
            state.insert("ownerScheme".to_owned(), Value::from(owner_scheme));
        }
        state.insert("feePolicyVersion".to_owned(), Value::from(1));
        state.insert("creatorFeeBps".to_owned(), Value::from(bps));
        Ok(())
    }
}

fn witness_bytes(items: &[ScriptItem], index: usize) -> Result<&[u8]> {
    crate::interpretation("kcc20_fee_v1.rs:witness_bytes", (|| {
    match items.get(index) {
        Some(ScriptItem::Data(bytes)) => Ok(bytes.as_slice()),
        _ => bail!("fee witness item {index} must be bytes"),
    }

    })())
}

// A zero-fee trade has no receipt output and requires empty template bytes.
// OP_0 is parsed as Int(0), even when it represents an empty byte-array argument.
fn grouped_receipt_templates_match(
    items: &[ScriptItem],
    fee_output_at: usize,
    fee_vector_at: usize,
    prefix_at: usize,
) -> bool {
    let empty = |index| match items.get(index) {
        Some(ScriptItem::Int(0)) => true,
        Some(ScriptItem::Data(bytes)) => bytes.is_empty(),
        _ => false,
    };
    match item_int(items, fee_output_at) {
        Ok(index) if index < 0 => {
            empty(prefix_at)
                && empty(prefix_at + 1)
                && witness_bytes(items, fee_vector_at)
                    .is_ok_and(|fees| !fees.is_empty() && fees.iter().all(|byte| *byte == 0))
        }
        Ok(_) => {
            let receipt = receipt_decoder();
            witness_bytes(items, prefix_at).is_ok_and(|bytes| bytes == receipt.prefix.as_slice())
                && witness_bytes(items, prefix_at + 1)
                    .is_ok_and(|bytes| bytes == receipt.suffix.as_slice())
        }
        Err(_) => false,
    }
}

fn receipt_decoder() -> &'static Kcc20FeeV1Decoder {
    static DECODER: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    DECODER.get_or_init(|| {
        Kcc20FeeV1Decoder::from_artifact(
            KnownTemplate::Kcc20FeeEscrowV1,
            include_str!("../fixtures/kcc20-fee-escrow-v1/KCC20FeeEscrowV1.placeholder.json"),
        )
        .expect("pinned fee receipt artifact")
    })
}

fn recipient_decoder() -> &'static Kcc20FeeV1Decoder {
    static DECODER: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    DECODER.get_or_init(|| Kcc20FeeV1Decoder::from_artifact(
        KnownTemplate::Kcc20FeeRecipientV1,
        include_str!("../fixtures/kcc20-fee-recipient-v1/KCC20FeeRecipientV1.placeholder.json"),
    ).expect("pinned fee recipient artifact"))
}

#[derive(Clone, Copy, Debug)]
pub enum FeeMarketWrapperVersion {
    NativeV1,
    NativeV2,
    ArgentV1,
    ArgentV2,
}

impl FeeMarketWrapperVersion {
    pub fn from_template_name(name: &str) -> Option<Self> {
        match name {
            "KCC20WrapperFeeV1" => Some(Self::NativeV1),
            "KCC20WrapperFeeV2" => Some(Self::NativeV2),
            "KCC20WrapperFeeArgentV1" => Some(Self::ArgentV1),
            "KCC20WrapperFeeArgentV2" => Some(Self::ArgentV2),
            _ => None,
        }
    }
}

fn wrapper_decoder(version: FeeMarketWrapperVersion) -> &'static Kcc20FeeV1Decoder {
    static NATIVE: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    static NATIVE_V2: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    static ARGENT_V1: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    static ARGENT_V2: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    let (cell, template, raw) = match version {
        FeeMarketWrapperVersion::NativeV1 => (&NATIVE, KnownTemplate::Kcc20FeeWrapperV1,
            include_str!("../fixtures/kcc20-wrapper-fee-v1/KCC20WrapperFeeV1.placeholder.json")),
        FeeMarketWrapperVersion::NativeV2 => (&NATIVE_V2, KnownTemplate::Kcc20FeeWrapperV2,
            include_str!("../fixtures/kcc20-wrapper-fee-v2/KCC20WrapperFeeV2.placeholder.json")),
        FeeMarketWrapperVersion::ArgentV1 => (&ARGENT_V1, KnownTemplate::Kcc20FeeWrapperArgentV1,
            include_str!("../fixtures/kcc20-wrapper-fee-argent-v1/KCC20WrapperFeeArgentV1.placeholder.json")),
        FeeMarketWrapperVersion::ArgentV2 => (&ARGENT_V2, KnownTemplate::Kcc20FeeWrapperArgentV2,
            include_str!("../fixtures/kcc20-wrapper-fee-argent-v2/KCC20WrapperFeeArgentV2.placeholder.json")),
    };
    cell.get_or_init(|| Kcc20FeeV1Decoder::from_artifact(template, raw)
        .expect("pinned fee wrapper artifact"))
}

/// Authenticate the active wrapper role independently of lineage-wide metadata.
/// A market lineage also contains holders, orders and receipts; its first known
/// template need not be the wrapper. Reconstruct the pinned script from the
/// supplied state and require the exact P2SH commitment from the stored UTXO.
pub fn fee_market_wrapper_matches_script_pubkey(state: &Value, script_pubkey: &[u8]) -> bool {
    fee_market_wrapper_template(state, script_pubkey).is_some()
}

/// Version is derived from the authenticated script, never an unverified label.
pub fn fee_market_wrapper_template(state: &Value, script_pubkey: &[u8]) -> Option<&'static str> {
    [
        FeeMarketWrapperVersion::NativeV1,
        FeeMarketWrapperVersion::NativeV2,
        FeeMarketWrapperVersion::ArgentV1,
        FeeMarketWrapperVersion::ArgentV2,
    ]
    .into_iter()
    .find_map(|version| {
        let matches = wrapper_decoder(version)
            .script_for_state(state)
            .is_ok_and(|script| {
                let expected = [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat();
                script_pubkey == expected
            });
        matches.then_some(match version {
            FeeMarketWrapperVersion::NativeV1 => "KCC20WrapperFeeV1",
            FeeMarketWrapperVersion::NativeV2 => "KCC20WrapperFeeV2",
            FeeMarketWrapperVersion::ArgentV1 => "KCC20WrapperFeeArgentV1",
            FeeMarketWrapperVersion::ArgentV2 => "KCC20WrapperFeeArgentV2",
        })
    })
}

fn root_decoder() -> &'static Kcc20FeeV1Decoder {
    static DECODER: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    DECODER.get_or_init(|| {
        Kcc20FeeV1Decoder::from_artifact(
            KnownTemplate::Kcc20FeeRootV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-root-v1/KCC20OrderbookFeeRootV1.placeholder.json"
            ),
        )
        .expect("pinned fee root artifact")
    })
}

fn holder_decoder() -> &'static Kcc20FeeV1Decoder {
    static DECODER: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    DECODER.get_or_init(|| {
        Kcc20FeeV1Decoder::from_artifact(
            KnownTemplate::Kcc20FeeHolderV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-holder-v1/KCC20OrderbookFeeHolderV1.placeholder.json"
            ),
        )
        .expect("pinned fee holder artifact")
    })
}

fn ask_decoder() -> &'static Kcc20FeeV1Decoder {
    static DECODER: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    DECODER.get_or_init(|| {
        Kcc20FeeV1Decoder::from_artifact(
            KnownTemplate::Kcc20FeeAskV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-ask-v1/KCC20OrderbookFeeAskV1.placeholder.json"
            ),
        )
        .expect("pinned fee ask artifact")
    })
}

fn bid_decoder() -> &'static Kcc20FeeV1Decoder {
    static DECODER: OnceLock<Kcc20FeeV1Decoder> = OnceLock::new();
    DECODER.get_or_init(|| {
        Kcc20FeeV1Decoder::from_artifact(
            KnownTemplate::Kcc20FeeBidV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-bid-v1/KCC20OrderbookFeeBidV1.placeholder.json"
            ),
        )
        .expect("pinned fee bid artifact")
    })
}

fn verified_market_output(
    tx: &RestTransaction,
    input_index: usize,
    output_index: usize,
    market_id: &[u8],
    script: &[u8],
) -> Result<()> {
    let output = tx
        .outputs
        .get(output_index)
        .context("missing fee market output")?;
    let expected_spk = [vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat();
    if hex::decode(&output.script_public_key)? != expected_spk
        || output
            .canonical_covenant_id()
            .is_some_and(|id| id != hex::encode(market_id))
        || output
            .covenant_authorizing_input()
            .is_some_and(|n| usize::from(n) != input_index)
    {
        bail!("fee market successor script or lineage mismatch");
    }
    Ok(())
}

/// A merge has one holder continuation and refunds the other holder deposits.
/// The source may omit input amounts, so check the refund value when it supplies
/// them and always check the payout script committed by the holder states.
pub fn fee_market_merge_holders_output(
    tx: &RestTransaction,
    input_indexes: &[usize],
    states: &[Value],
    market_id: &[u8],
) -> Result<(i32, Value)> {
    if market_id.len() != 32 || !(2..=3).contains(&input_indexes.len()) || input_indexes.len() != states.len() {
        bail!("fee holder merge requires two or three matching inputs");
    }
    let first = states.first().context("missing fee holder merge leader")?;
    if first["mode"] != "0" {
        bail!("fee holder merge leader is not active");
    }
    let mut total = 0i64;
    for (index, state) in input_indexes.iter().zip(states) {
        if tx.inputs.get(*index).is_none() || state["mode"] != "0" {
            bail!("fee holder merge input is missing or inactive");
        }
        let mut compatible = state.clone();
        compatible["amount"] = first["amount"].clone();
        if &compatible != first {
            bail!("fee holder merge inputs have incompatible state");
        }
        let amount = state["amount"]
            .as_str()
            .context("missing fee holder merge amount")?
            .parse::<i64>()?;
        if amount <= 0 {
            bail!("fee holder merge amount must be positive");
        }
        total = total.checked_add(amount).context("fee holder merge amount overflow")?;
    }
    let mut merged = first.clone();
    merged["amount"] = Value::String(total.to_string());
    let script = holder_decoder().script_for_state(&merged)?;
    verified_market_output(tx, input_indexes[0], 0, market_id, &script)?;
    if tx.outputs[0].amount != 50_000_000 {
        bail!("fee holder merge continuation must retain the exact deposit");
    }
    let refund = tx.outputs.get(1).context("missing fee holder merge refund")?;
    let refund_spk = hex::decode(&refund.script_public_key)?;
    let mut serialized = vec![0xe3, 0, 0];
    serialized.extend((refund_spk.len() as u64).to_le_bytes());
    serialized.extend(refund_spk);
    if first["payout_script_hash"] != blake3::hash(&serialized).to_hex().to_string() {
        bail!("fee holder merge refund has wrong payout script");
    }
    let input_values: Option<Vec<u64>> = input_indexes
        .iter()
        .map(|index| tx.inputs[*index].previous_outpoint_amount)
        .collect();
    if let Some(values) = input_values {
        let deposits = values.into_iter().try_fold(0u64, |sum, value| sum.checked_add(value))
            .context("fee holder merge deposit overflow")?;
        if deposits < 50_000_000 || refund.amount != deposits - 50_000_000 {
            bail!("fee holder merge refund does not return the exact deposits");
        }
    }
    Ok((0, merged))
}

/// Project the unchanged wrapper and the optional remaining holder after an
/// accepted unwrap. The holder witness names its wrapper input and change or
/// refund output; the wrapper continuation has one exact pinned script.
pub fn fee_market_unwrap_outputs(
    tx: &RestTransaction,
    holder_input: usize,
    holder_witness: &[u8],
    holder_state: &Value,
    wrapper_input: usize,
    wrapper_state: &Value,
    market_id: &[u8],
    wrapper_version: FeeMarketWrapperVersion,
) -> Result<Vec<(i32, Value)>> {
    if market_id.len() != 32 || holder_input == wrapper_input || holder_state["mode"] != "0"
        || holder_state["canonicalTokenId"] != wrapper_state["canonicalTokenId"]
        || holder_state["feePolicy"] != wrapper_state["feePolicy"]
    {
        bail!("fee market unwrap source mismatch");
    }
    let items = script_items(args_prefix_before_reveal(holder_witness));
    let declared_wrapper = usize::try_from(item_int(&items, 1)?)?;
    let amount = i64::try_from(item_int(&items, 2)?)?;
    let change = item_int(&items, 3)?;
    let refund = item_int(&items, 4)?;
    let current_amount = holder_state["amount"]
        .as_str().context("missing fee unwrap holder amount")?.parse::<i64>()?;
    if declared_wrapper != wrapper_input || amount <= 0 || amount > current_amount {
        bail!("invalid fee market unwrap witness");
    }
    let wrapper = wrapper_decoder(wrapper_version);
    let wrapper_script = wrapper.script_for_state(wrapper_state)?;
    if holder_state["wrapper_spk_hash"] != hex::encode(blake2b_256(&wrapper_script)) {
        bail!("fee market unwrap holder is bound to another wrapper");
    }
    let expected_wrapper_spk = [vec![0xaa, 0x20], blake2b_256(&wrapper_script).to_vec(), vec![0x87]].concat();
    let wrapper_indexes = tx.outputs.iter().enumerate()
        .filter_map(|(index, output)| {
            (hex::decode(&output.script_public_key).ok().as_deref() == Some(expected_wrapper_spk.as_slice()))
                .then_some(index)
        }).collect::<Vec<_>>();
    if wrapper_indexes.len() != 1 {
        bail!("fee market unwrap has no unique wrapper continuation");
    }
    let wrapper_index = wrapper_indexes[0];
    verified_market_output(tx, wrapper_input, wrapper_index, market_id, &wrapper_script)?;
    if let Some(principal) = tx.inputs.get(wrapper_input).and_then(|input| input.previous_outpoint_amount) {
        if tx.outputs[wrapper_index].amount != principal {
            bail!("fee market unwrap changes wrapper principal");
        }
    }
    let mut outputs = vec![(i32::try_from(wrapper_index)?, wrapper.decode_constructor(&wrapper_script)?)];
    if amount < current_amount {
        if refund >= 0 {
            bail!("partial fee market unwrap cannot refund holder deposit");
        }
        let change_index = usize::try_from(change)?;
        if change_index == wrapper_index {
            bail!("fee market unwrap holder change overlaps wrapper");
        }
        let mut remaining = holder_state.clone();
        remaining["amount"] = Value::String((current_amount - amount).to_string());
        let holder_script = holder_decoder().script_for_state(&remaining)?;
        verified_market_output(tx, holder_input, change_index, market_id, &holder_script)?;
        if let Some(principal) = tx.inputs.get(holder_input).and_then(|input| input.previous_outpoint_amount) {
            if tx.outputs[change_index].amount != principal {
                bail!("fee market unwrap changes holder deposit");
            }
        }
        outputs.push((i32::try_from(change_index)?, holder_decoder().decode_constructor(&holder_script)?));
    } else {
        if change >= 0 {
            bail!("full fee market unwrap cannot retain holder change");
        }
        let refund_index = usize::try_from(refund)?;
        let refund_output = tx.outputs.get(refund_index).context("missing fee unwrap holder refund")?;
        let refund_spk = hex::decode(&refund_output.script_public_key)?;
        let mut serialized = vec![0xe3, 0, 0];
        serialized.extend((refund_spk.len() as u64).to_le_bytes());
        serialized.extend(refund_spk);
        if holder_state["payout_script_hash"] != blake3::hash(&serialized).to_hex().to_string() {
            bail!("fee market unwrap holder refund has wrong payout script");
        }
        if let Some(principal) = tx.inputs.get(holder_input).and_then(|input| input.previous_outpoint_amount) {
            if refund_output.amount != principal {
                bail!("fee market unwrap holder deposit refund mismatch");
            }
        }
    }
    Ok(outputs)
}

/// Recover the exact ask and optional holder change from an accepted createAsk.
/// The holder witness must carry the pinned ask template, and each successor
/// must match the script and market lineage authorized by that holder input.
pub fn fee_market_create_ask_outputs(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    market_id: &[u8],
) -> Result<Vec<(i32, Value)>> {
    let current_fields = current
        .as_object()
        .context("createAsk source state is not an object")?;
    if number(current_fields, "mode")? != 0 {
        bail!("createAsk must spend a fee market holder");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let ask = ask_decoder();
    let candidates = (0..items.len().saturating_sub(7))
        .filter(|&start| {
            witness_bytes(&items, start + 6).is_ok_and(|bytes| bytes == ask.prefix.as_slice())
                && witness_bytes(&items, start + 7)
                    .is_ok_and(|bytes| bytes == ask.suffix.as_slice())
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(anyhow!("createAsk witness has no unique pinned ask template").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let start = candidates[0];
    let ask_amount = item_int(&items, start + 1)?;
    let ask_price = item_int(&items, start + 2)?;
    let payout = witness_bytes(&items, start + 3)?;
    let ask_index = usize::try_from(item_int(&items, start + 4)?)?;
    let change = item_int(&items, start + 5)?;
    let holder_amount = number(current_fields, "amount")?;
    if ask_amount <= 0
        || ask_price <= 0
        || payout.len() != 32
        || payout.iter().all(|byte| *byte == 0)
        || u64::try_from(ask_amount)? > holder_amount
    {
        bail!("invalid createAsk amount, price or payout");
    }
    let ask_state = serde_json::json!({
        "canonicalTokenId": current["canonicalTokenId"],
        "owner": current["owner"], "owner_scheme": current["owner_scheme"],
        "amount": ask_amount.to_string(), "mode": "2", "unitPrice": ask_price.to_string(),
        "feeTicketId": current["feeTicketId"], "priceScale": current["priceScale"],
        "feePolicy": current["feePolicy"],
        "payout_script_hash": hex::encode(payout),
        "wrapper_spk_hash": current["wrapper_spk_hash"],
    });
    let ask_script = ask.script_for_state(&ask_state)?;
    verified_market_output(tx, input_index, ask_index, market_id, &ask_script)?;
    if let Some(principal) = tx
        .inputs
        .get(input_index)
        .and_then(|input| input.previous_outpoint_amount)
    {
        if tx.outputs[ask_index].amount != principal {
            bail!("createAsk changes the ask deposit");
        }
    }
    let mut outputs = vec![(
        i32::try_from(ask_index)?,
        ask.decode_constructor(&ask_script)?,
    )];
    if u64::try_from(ask_amount)? < holder_amount {
        let change_index = usize::try_from(change)?;
        if change_index == ask_index
            || tx
                .outputs
                .get(change_index)
                .is_none_or(|output| output.amount < 50_000_000)
        {
            bail!("invalid createAsk holder change deposit");
        }
        let mut holder_state = current.clone();
        holder_state["amount"] =
            Value::String((holder_amount - u64::try_from(ask_amount)?).to_string());
        let holder_script = holder_decoder().script_for_state(&holder_state)?;
        verified_market_output(tx, input_index, change_index, market_id, &holder_script)?;
        outputs.push((
            i32::try_from(change_index)?,
            holder_decoder().decode_constructor(&holder_script)?,
        ));
    } else if change >= 0 {
        bail!("full createAsk has an unexpected holder change");
    }
    Ok(outputs)
}

/// Return an ask's full token amount to a holder after an owner-authorized
/// cancellation. The accepted witness commits to the pinned holder role.
pub fn fee_market_cancel_ask_output(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    market_id: &[u8],
) -> Result<(i32, Value)> {
    let fields = current.as_object().context("cancelAsk source state is not an object")?;
    if number(fields, "mode")? != 2 {
        bail!("cancelAsk must spend a fee market ask");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let holder = holder_decoder();
    let candidates = (0..items.len().saturating_sub(3))
        .filter(|&start| {
            witness_bytes(&items, start + 2).is_ok_and(|bytes| bytes == holder.prefix.as_slice())
                && witness_bytes(&items, start + 3).is_ok_and(|bytes| bytes == holder.suffix.as_slice())
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(anyhow!("cancelAsk witness has no unique pinned holder template").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let output_index = usize::try_from(item_int(&items, candidates[0] + 1)?)?;
    let mut holder_state = current.clone();
    holder_state["mode"] = Value::String("0".into());
    holder_state["unitPrice"] = Value::String("0".into());
    let holder_script = holder.script_for_state(&holder_state)?;
    verified_market_output(tx, input_index, output_index, market_id, &holder_script)?;
    if let Some(principal) = tx.inputs.get(input_index).and_then(|input| input.previous_outpoint_amount) {
        if tx.outputs[output_index].amount != principal {
            bail!("cancelAsk changes the returned holder deposit");
        }
    }
    Ok((i32::try_from(output_index)?, holder.decode_constructor(&holder_script)?))
}

/// Recover a bid and continuing root from an accepted root createBid spend.
/// The bid locks the exact gross KAS plus its fixed 2 KAS order deposit.
pub fn fee_market_create_bid_outputs(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    market_id: &[u8],
) -> Result<[(i32, Value); 2]> {
    let fields = current.as_object().context("createBid source state is not an object")?;
    if number(fields, "mode")? != 1 {
        bail!("createBid must spend a fee market root");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let bid = bid_decoder();
    let candidates = (0..items.len().saturating_sub(8))
        .filter(|&start| {
            witness_bytes(&items, start + 7).is_ok_and(|bytes| bytes == bid.prefix.as_slice())
                && witness_bytes(&items, start + 8).is_ok_and(|bytes| bytes == bid.suffix.as_slice())
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(anyhow!("createBid witness has no unique pinned bid template").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let start = candidates[0];
    let buyer = witness_bytes(&items, start)?;
    let scheme = u8::try_from(item_int(&items, start + 1)?)?;
    let payout = witness_bytes(&items, start + 2)?;
    let amount = u64::try_from(item_int(&items, start + 3)?)?;
    let price = u64::try_from(item_int(&items, start + 4)?)?;
    let bid_index = usize::try_from(item_int(&items, start + 5)?)?;
    let root_index = usize::try_from(item_int(&items, start + 6)?)?;
    let scale = number(fields, "priceScale")?;
    if buyer.len() != 32 || buyer.iter().all(|byte| *byte == 0)
        || payout.len() != 32 || payout.iter().all(|byte| *byte == 0)
        || scheme > 4 || amount == 0 || price == 0 || scale == 0
        || bid_index == root_index
    {
        bail!("invalid createBid owner, amount, price or outputs");
    }
    let product = u128::from(amount).checked_mul(u128::from(price))
        .context("createBid gross overflows")?;
    if product % u128::from(scale) != 0 {
        bail!("createBid gross is not exact at the market price scale");
    }
    let gross = product / u128::from(scale);
    if gross < 50_000_000 || gross > i64::MAX as u128 - 200_000_000 {
        bail!("createBid gross is outside contract range");
    }
    let bid_state = serde_json::json!({
        "canonicalTokenId": current["canonicalTokenId"],
        "owner": hex::encode(buyer), "owner_scheme": scheme,
        "amount": amount.to_string(), "mode": "3", "unitPrice": price.to_string(),
        "feeTicketId": current["feeTicketId"], "priceScale": current["priceScale"],
        "feePolicy": current["feePolicy"],
        "payout_script_hash": hex::encode(payout),
        "wrapper_spk_hash": current["wrapper_spk_hash"],
    });
    let bid_script = bid.script_for_state(&bid_state)?;
    let root = root_decoder();
    let root_script = root.script_for_state(current)?;
    verified_market_output(tx, input_index, bid_index, market_id, &bid_script)?;
    verified_market_output(tx, input_index, root_index, market_id, &root_script)?;
    if u128::from(tx.outputs[bid_index].amount) != gross + 200_000_000 {
        bail!("createBid locks the wrong gross or order deposit");
    }
    if let Some(principal) = tx.inputs.get(input_index).and_then(|input| input.previous_outpoint_amount) {
        if tx.outputs[root_index].amount != principal {
            bail!("createBid changes root principal");
        }
    }
    Ok([
        (i32::try_from(bid_index)?, bid.decode_constructor(&bid_script)?),
        (i32::try_from(root_index)?, root.decode_constructor(&root_script)?),
    ])
}

/// Recover the buyer holders, optional bid continuations, and seller change
/// from an accepted holder-led sale. The source states and every successor
/// script are checked against the pinned market artifacts.
pub fn fee_market_sell_into_bids_outputs(
    tx: &RestTransaction,
    leader_input_index: usize,
    signature_script: &[u8],
    seller: &Value,
    bid_sources: &[(usize, Value)],
    market_id: &[u8],
) -> Result<Vec<(i32, Value)>> {
    if bid_sources.is_empty() || bid_sources.len() > 10 {
        bail!("sellIntoBids has an unsupported number of bid sources");
    }
    let seller_fields = seller.as_object().context("sellIntoBids seller state is not an object")?;
    if number(seller_fields, "mode")? != 0 {
        bail!("sellIntoBids leader must be a holder");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let candidates = (0..items.len().saturating_sub(10))
        .filter(|&start| {
            let count = item_int(&items, start + 1).ok();
            let legs = witness_bytes(&items, start + 2).ok();
            let fees = witness_bytes(&items, start + 3).ok();
            count == Some(bid_sources.len() as i128)
                && legs.is_some_and(|v| v.len() == bid_sources.len() * 32)
                && fees.is_some_and(|v| v.len() == bid_sources.len() * 16)
                && grouped_receipt_templates_match(&items, start + 5, start + 3, start + 9)
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(anyhow!("sellIntoBids witness has no unique fee vector and receipt template").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let start = candidates[0];
    let legs = witness_bytes(&items, start + 2)?;
    let change_index = item_int(&items, start + 6)?;
    let refund_index = item_int(&items, start + 7)?;
    let mut projected = Vec::new();
    let mut used_outputs = HashSet::new();
    let mut sold = 0u64;
    let mut last_seller_index = None;
    for (slot, (bid_input_index, bid)) in bid_sources.iter().enumerate() {
        if *bid_input_index <= leader_input_index
            || (slot > 0 && *bid_input_index <= bid_sources[slot - 1].0)
        {
            bail!("sellIntoBids sources are not in market input order");
        }
        let fields = bid.as_object().context("sellIntoBids bid state is not an object")?;
        if number(fields, "mode")? != 3
            || bid["canonicalTokenId"] != seller["canonicalTokenId"]
            || bid["feePolicy"] != seller["feePolicy"]
            || bid["feeTicketId"] != seller["feeTicketId"]
            || bid["priceScale"] != seller["priceScale"]
            || bid["wrapper_spk_hash"] != seller["wrapper_spk_hash"]
        {
            bail!("sellIntoBids source bid disagrees with the seller market");
        }
        let base = slot * 32;
        let leg_int = |offset: usize| -> Result<i64> {
            Ok(i64::from_le_bytes(legs[base + offset..base + offset + 8].try_into()?))
        };
        let fill = u64::try_from(leg_int(0)?)?;
        let buyer_index = usize::try_from(leg_int(8)?)?;
        let continuation = leg_int(16)?;
        let seller_index = usize::try_from(leg_int(24)?)?;
        let bid_amount = number(fields, "amount")?;
        if fill == 0 || fill > bid_amount
            || buyer_index >= seller_index
            || last_seller_index.is_some_and(|previous| buyer_index <= previous)
            || !used_outputs.insert(buyer_index)
        {
            bail!("sellIntoBids has an invalid fill or buyer output");
        }
        let buyer_state = serde_json::json!({
            "canonicalTokenId": bid["canonicalTokenId"],
            "owner": bid["owner"], "owner_scheme": bid["owner_scheme"],
            "amount": fill.to_string(), "mode": "0", "unitPrice": "0",
            "feeTicketId": bid["feeTicketId"], "priceScale": bid["priceScale"],
            "feePolicy": bid["feePolicy"],
            "payout_script_hash": bid["payout_script_hash"],
            "wrapper_spk_hash": bid["wrapper_spk_hash"],
        });
        let holder = holder_decoder();
        let buyer_script = holder.script_for_state(&buyer_state)?;
        verified_market_output(tx, leader_input_index, buyer_index, market_id, &buyer_script)?;
        projected.push((i32::try_from(buyer_index)?, holder.decode_constructor(&buyer_script)?));
        let scale = number(fields, "priceScale")?;
        let gross_product = u128::from(fill).checked_mul(u128::from(number(fields, "unitPrice")?))
            .context("sellIntoBids gross overflows")?;
        if scale == 0 || gross_product % u128::from(scale) != 0 {
            bail!("sellIntoBids gross is not exact");
        }
        let gross = gross_product / u128::from(scale);
        if fill < bid_amount {
            let continuation_index = usize::try_from(continuation)?;
            if continuation_index != buyer_index + 1 || seller_index != buyer_index + 2
                || !used_outputs.insert(continuation_index)
            {
                bail!("sellIntoBids has an invalid partial bid continuation");
            }
            let mut next_bid = bid.clone();
            next_bid["amount"] = Value::String((bid_amount - fill).to_string());
            let bid_template = bid_decoder();
            let bid_script = bid_template.script_for_state(&next_bid)?;
            verified_market_output(tx, *bid_input_index, continuation_index, market_id, &bid_script)?;
            projected.push((i32::try_from(continuation_index)?, bid_template.decode_constructor(&bid_script)?));
            if let Some(principal) = tx.inputs.get(*bid_input_index).and_then(|input| input.previous_outpoint_amount) {
                let original_product = u128::from(bid_amount) * u128::from(number(fields, "unitPrice")?);
                let remaining_product = u128::from(bid_amount - fill) * u128::from(number(fields, "unitPrice")?);
                if original_product % u128::from(scale) != 0 || remaining_product % u128::from(scale) != 0 {
                    bail!("sellIntoBids bid gross is not exact");
                }
                let deposit = u128::from(principal).checked_sub(original_product / u128::from(scale))
                    .context("sellIntoBids bid deposit underflows")?;
                if u128::from(tx.outputs[continuation_index].amount) != remaining_product / u128::from(scale) + deposit {
                    bail!("sellIntoBids changes bid deposit");
                }
            }
        } else if continuation != 0 || seller_index != buyer_index + 1 {
            bail!("sellIntoBids has an invalid final bid output");
        } else if let Some(principal) = tx.inputs.get(*bid_input_index).and_then(|input| input.previous_outpoint_amount) {
            if u128::from(tx.outputs[buyer_index].amount) + gross != u128::from(principal) {
                bail!("sellIntoBids does not return the final bid deposit");
            }
        }
        sold = sold.checked_add(fill).context("sellIntoBids sold amount overflows")?;
        last_seller_index = Some(seller_index);
    }
    let seller_amount = number(seller_fields, "amount")?;
    if sold > seller_amount {
        bail!("sellIntoBids exceeds seller holdings");
    }
    if sold < seller_amount {
        let change_index = usize::try_from(change_index)?;
        if refund_index >= 0 || change_index != last_seller_index.unwrap() + 1 {
            bail!("sellIntoBids has an invalid seller change index");
        }
        let mut change = seller.clone();
        change["amount"] = Value::String((seller_amount - sold).to_string());
        let holder = holder_decoder();
        let script = holder.script_for_state(&change)?;
        verified_market_output(tx, leader_input_index, change_index, market_id, &script)?;
        if let Some(principal) = tx.inputs.get(leader_input_index).and_then(|input| input.previous_outpoint_amount) {
            if tx.outputs[change_index].amount != principal {
                bail!("sellIntoBids changes seller holder deposit");
            }
        }
        projected.push((i32::try_from(change_index)?, holder.decode_constructor(&script)?));
    } else if change_index >= 0 || refund_index < 0 {
        bail!("sellIntoBids is missing the final seller deposit refund");
    }
    Ok(projected)
}

/// Recover every buyer holder and optional remaining ask in a grouped buy.
/// Each leg is checked against its authenticated spent ask state, the pinned
/// successor script, and the authorizing input's market lineage.
pub fn fee_market_buy_asks_outputs(
    tx: &RestTransaction,
    leader_input_index: usize,
    signature_script: &[u8],
    ask_sources: &[(usize, Value)],
    market_id: &[u8],
) -> Result<Vec<(i32, Value)>> {
    let Some((first_input_index, first_ask)) = ask_sources.first() else {
        bail!("buyAsks has no authenticated ask sources");
    };
    if *first_input_index != leader_input_index {
        bail!("buyAsks leader is not the first market input");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let holder = holder_decoder();
    let candidates = (0..items.len().saturating_sub(12))
        .filter(|&start| {
            grouped_receipt_templates_match(&items, start + 7, start + 5, start + 9)
                && witness_bytes(&items, start + 11)
                    .is_ok_and(|bytes| bytes == holder.prefix.as_slice())
                && witness_bytes(&items, start + 12)
                    .is_ok_and(|bytes| bytes == holder.suffix.as_slice())
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(anyhow!("buyAsks witness has no unique pinned successor templates").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let start = candidates[0];
    let buyer = witness_bytes(&items, start)?;
    let buyer_scheme = u8::try_from(item_int(&items, start + 1)?)?;
    let payout = witness_bytes(&items, start + 2)?;
    let fill_count = item_int(&items, start + 3)?;
    let legs = witness_bytes(&items, start + 4)?;
    let fee_vector = witness_bytes(&items, start + 5)?;
    if buyer.len() != 32
        || buyer.iter().all(|byte| *byte == 0)
        || buyer_scheme > 4
        || payout.len() != 32
        || payout.iter().all(|byte| *byte == 0)
        || fill_count < 1
        || fill_count > 16
        || usize::try_from(fill_count)? != ask_sources.len()
        || legs.len() != ask_sources.len() * 32
        || fee_vector.len() != ask_sources.len() * 16
    {
        return Err(anyhow!("invalid or unsupported buyAsks witness").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let mut outputs = Vec::new();
    let mut used_outputs = HashSet::new();
    let mut last_seller_index = None;
    for (slot, (input_index, current)) in ask_sources.iter().enumerate() {
        if slot > 0 && *input_index <= ask_sources[slot - 1].0 {
            bail!("buyAsks source inputs are not in market order");
        }
        let fields = current
            .as_object()
            .context("buyAsks source state is not an object")?;
        if number(fields, "mode")? != 2
            || current["canonicalTokenId"] != first_ask["canonicalTokenId"]
            || current["feePolicy"] != first_ask["feePolicy"]
            || current["feeTicketId"] != first_ask["feeTicketId"]
            || current["priceScale"] != first_ask["priceScale"]
            || current["wrapper_spk_hash"] != first_ask["wrapper_spk_hash"]
        {
            bail!("buyAsks source asks disagree on market policy or role");
        }
        let base = slot * 32;
        let leg_int = |offset: usize| -> Result<i64> {
            Ok(i64::from_le_bytes(
                legs[base + offset..base + offset + 8].try_into()?,
            ))
        };
        let fill = leg_int(0)?;
        let holder_index = usize::try_from(leg_int(8)?)?;
        let continuation = leg_int(16)?;
        let seller_index = usize::try_from(leg_int(24)?)?;
        let ask_amount = number(fields, "amount")?;
        if fill <= 0
            || u64::try_from(fill)? > ask_amount
            || holder_index >= seller_index
            || last_seller_index.is_some_and(|previous| holder_index <= previous)
            || tx
                .outputs
                .get(holder_index)
                .is_none_or(|output| output.amount < 50_000_000)
            || !used_outputs.insert(holder_index)
        {
            bail!("invalid buyAsks fill or holder output");
        }
        let holder_state = serde_json::json!({
            "canonicalTokenId": current["canonicalTokenId"],
            "owner": hex::encode(buyer), "owner_scheme": buyer_scheme,
            "amount": fill.to_string(), "mode": "0", "unitPrice": "0",
            "feeTicketId": current["feeTicketId"], "priceScale": current["priceScale"],
            "feePolicy": current["feePolicy"],
            "payout_script_hash": hex::encode(payout),
            "wrapper_spk_hash": current["wrapper_spk_hash"],
        });
        let holder_script = holder.script_for_state(&holder_state)?;
        verified_market_output(tx, *input_index, holder_index, market_id, &holder_script)?;
        outputs.push((
            i32::try_from(holder_index)?,
            holder.decode_constructor(&holder_script)?,
        ));
        if u64::try_from(fill)? < ask_amount {
            let continuation_index = usize::try_from(continuation)?;
            if continuation_index != holder_index + 1
                || seller_index != holder_index + 2
                || !used_outputs.insert(continuation_index)
            {
                bail!("invalid buyAsks ask continuation index");
            }
            let mut ask_state = current.clone();
            ask_state["amount"] = Value::String((ask_amount - u64::try_from(fill)?).to_string());
            let ask_script = ask_decoder().script_for_state(&ask_state)?;
            verified_market_output(tx, *input_index, continuation_index, market_id, &ask_script)?;
            if let Some(principal) = tx
                .inputs
                .get(*input_index)
                .and_then(|input| input.previous_outpoint_amount)
            {
                if tx.outputs[continuation_index].amount != principal {
                    bail!("buyAsks changes the remaining ask deposit");
                }
            }
            outputs.push((
                i32::try_from(continuation_index)?,
                ask_decoder().decode_constructor(&ask_script)?,
            ));
        } else if continuation != 0 || seller_index != holder_index + 1 {
            bail!("final buyAsks has an invalid seller output");
        }
        last_seller_index = Some(seller_index);
    }
    Ok(outputs)
}

/// Recover buyer tokens and both order continuations from an accepted cross.
/// The caller supplies the complete, ordered authenticated market input set.
pub fn fee_market_cross_outputs(
    tx: &RestTransaction,
    signature_script: &[u8],
    sources: &[(usize, Value)],
    market_id: &[u8],
) -> Result<Vec<(i32, Value)>> {
    if sources.len() != 2 || sources[0].0 >= sources[1].0 || market_id.len() != 32 {
        bail!("cross requires exactly two ordered market inputs");
    }
    let (ask_index, ask) = &sources[0];
    let (bid_index, bid) = &sources[1];
    let ask_fields = ask.as_object().context("cross ask state")?;
    let bid_fields = bid.as_object().context("cross bid state")?;
    if number(ask_fields, "mode")? != 2 || number(bid_fields, "mode")? != 3 {
        bail!("cross source roles are not ask then bid");
    }
    for field in ["canonicalTokenId", "feePolicy", "feeTicketId", "priceScale", "wrapper_spk_hash"] {
        if ask[field] != bid[field] { bail!("cross source policies disagree"); }
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    for (offset, decoder) in [(9, receipt_decoder()), (11, holder_decoder()), (13, bid_decoder())] {
        if witness_bytes(&items, offset)? != decoder.prefix || witness_bytes(&items, offset + 1)? != decoder.suffix {
            bail!("cross successor templates differ from pinned artifacts");
        }
    }
    let fill = u64::try_from(item_int(&items, 2)?)?;
    let ask_amount = number(ask_fields, "amount")?;
    let bid_amount = number(bid_fields, "amount")?;
    if fill == 0 || fill > ask_amount || fill > bid_amount {
        bail!("cross fill exceeds order amounts");
    }
    let ask_remaining = ask_amount - fill;
    let bid_remaining = bid_amount - fill;
    let holder_index = usize::try_from(item_int(&items, 3)?)?;
    let ask_output = item_int(&items, 4)?;
    let bid_output = item_int(&items, 5)?;
    let seller_output = item_int(&items, 6)?;
    if holder_index != 0
        || (ask_remaining > 0 && ask_output != 1)
        || (ask_remaining == 0 && ask_output >= 0)
        || (bid_remaining > 0 && bid_output != 1 + i128::from(ask_remaining > 0))
        || (bid_remaining == 0 && bid_output >= 0)
        || seller_output != 1 + i128::from(ask_remaining > 0) + i128::from(bid_remaining > 0)
    { bail!("cross output ordering mismatch"); }
    let verify_successor = |input: usize, output: usize, script: &[u8]| -> Result<()> {
        verified_market_output(tx, input, output, market_id, script)?;
        let output = &tx.outputs[output];
        let market_hex = hex::encode(market_id);
        if output.canonical_covenant_id() != Some(market_hex.as_str())
            || output.covenant_authorizing_input().map(usize::from) != Some(input) {
            bail!("cross successor requires explicit matching lineage and authorizer");
        }
        Ok(())
    };
    let ask_principal = tx.inputs.get(*ask_index).and_then(|i| i.previous_outpoint_amount)
        .context("cross needs authenticated ask principal")?;
    let bid_principal = tx.inputs.get(*bid_index).and_then(|i| i.previous_outpoint_amount)
        .context("cross needs authenticated bid principal")?;
    let mut holder_state = bid.clone();
    holder_state["amount"] = Value::String(fill.to_string());
    holder_state["mode"] = Value::String("0".into());
    holder_state["unitPrice"] = Value::String("0".into());
    let holder = holder_decoder();
    let script = holder.script_for_state(&holder_state)?;
    verify_successor(*ask_index, holder_index, &script)?;
    if tx.outputs[holder_index].amount < 50_000_000 { bail!("cross buyer holder principal too small"); }
    let mut outputs = vec![(i32::try_from(holder_index)?, holder.decode_constructor(&script)?)];
    if ask_remaining > 0 {
        let index = usize::try_from(ask_output)?;
        let mut state = ask.clone(); state["amount"] = Value::String(ask_remaining.to_string());
        let decoder = ask_decoder(); let script = decoder.script_for_state(&state)?;
        verify_successor(*ask_index, index, &script)?;
        if tx.outputs[index].amount != ask_principal {
            bail!("cross changed ask continuation principal");
        }
        outputs.push((i32::try_from(index)?, decoder.decode_constructor(&script)?));
    }
    let price_scale = number(bid_fields, "priceScale")?;
    let bid_price = number(bid_fields, "unitPrice")?;
    if price_scale == 0 || bid_price < number(ask_fields, "unitPrice")? { bail!("cross prices disagree"); }
    let gross = |amount: u64| -> Result<u64> {
        let value = u128::from(amount) * u128::from(bid_price);
        if value % u128::from(price_scale) != 0 { bail!("cross fractional bid value"); }
        Ok(u64::try_from(value / u128::from(price_scale))?)
    };
    let deposit = bid_principal.checked_sub(gross(bid_amount)?).context("cross bid missing principal")?;
    if deposit < 50_000_000 { bail!("cross bid principal too small"); }
    let ask_value = u128::from(fill) * u128::from(number(ask_fields, "unitPrice")?);
    if ask_value % u128::from(price_scale) != 0 { bail!("cross fractional ask value"); }
    let ask_gross = u64::try_from(ask_value / u128::from(price_scale))?;
    let check_payout = |index: usize, amount: u64, state: &Value| -> Result<()> {
        let output = tx.outputs.get(index).context("missing cross payout")?;
        let script = hex::decode(&output.script_public_key)?;
        let mut serialized = vec![0xe3, 0, 0];
        serialized.extend((script.len() as u64).to_le_bytes());
        serialized.extend(script);
        if output.amount != amount || state["payout_script_hash"] != blake3::hash(&serialized).to_hex().to_string() {
            bail!("cross payout amount or script mismatch");
        }
        Ok(())
    };
    check_payout(usize::try_from(seller_output)?,
        ask_gross.checked_add(if ask_remaining == 0 { ask_principal } else { 0 }).context("cross seller payout overflow")?, ask)?;
    let surplus = gross(fill)?.checked_sub(ask_gross).context("cross negative buyer surplus")?;
    let surplus_index = item_int(&items, 8)?;
    if surplus > 0 {
        if surplus_index != seller_output + 2 { bail!("cross buyer surplus ordering mismatch"); }
        check_payout(usize::try_from(surplus_index)?, surplus, bid)?;
    } else if surplus_index >= 0 { bail!("cross unexpected buyer surplus output"); }
    if bid_remaining > 0 {
        let index = usize::try_from(bid_output)?;
        let mut state = bid.clone(); state["amount"] = Value::String(bid_remaining.to_string());
        let decoder = bid_decoder(); let script = decoder.script_for_state(&state)?;
        verify_successor(*bid_index, index, &script)?;
        if tx.outputs[index].amount != gross(bid_remaining)?.checked_add(deposit).context("cross bid value overflow")? {
            bail!("cross changed bid continuation principal");
        }
        outputs.push((i32::try_from(index)?, decoder.decode_constructor(&script)?));
    } else if tx.outputs[holder_index].amount != deposit {
        bail!("cross final buyer holder lost bid principal");
    }
    Ok(outputs)
}

pub fn fee_market_buy_ask_outputs(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    market_id: &[u8],
) -> Result<Vec<(i32, Value)>> {
    fee_market_buy_asks_outputs(
        tx,
        input_index,
        signature_script,
        &[(input_index, current.clone())],
        market_id,
    )
}

/// Recover the holder and wrapper outputs produced by an accepted fee-market
/// wrap. The wrapper witness commits to the exact holder template and state.
pub fn fee_market_wrap_outputs(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    market_id: &[u8],
    wrapper_version: FeeMarketWrapperVersion,
) -> Result<[(i32, Value); 2]> {
    if current["enabled"] != Value::Bool(true)
        || current["authenticatedMarketId"] != Value::String(hex::encode(market_id))
    {
        bail!("fee market wrap requires the bound wrapper");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let holder = holder_decoder();
    let candidates = (0..items.len().saturating_sub(8))
        .filter(|&start| {
            item_int(&items, start).is_ok()
                && item_int(&items, start + 1).is_ok()
                && item_int(&items, start + 2).is_ok()
                && witness_bytes(&items, start + 7).is_ok_and(|bytes| bytes == holder.prefix.as_slice())
                && witness_bytes(&items, start + 8).is_ok_and(|bytes| bytes == holder.suffix.as_slice())
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(anyhow!("fee market wrap witness has no unique holder template").context(crate::InterpretationFailure("fee_witness_layout")));
    }
    let start = candidates[0];
    let reserve_index = usize::try_from(item_int(&items, start)?)?;
    let holder_index = usize::try_from(item_int(&items, start + 1)?)?;
    let wrapper_index = usize::try_from(item_int(&items, start + 2)?)?;
    if reserve_index >= holder_index || holder_index >= wrapper_index {
        bail!("invalid fee market wrap output order");
    }
    let owner = witness_bytes(&items, start + 3)?;
    let scheme = u8::try_from(item_int(&items, start + 4)?)?;
    let payout = witness_bytes(&items, start + 5)?;
    let amount = item_int(&items, start + 6)?;
    if owner.len() != 32 || payout.len() != 32 || scheme > 4 || amount <= 0 {
        bail!("invalid fee market wrap recipient or amount");
    }
    let wrapper = wrapper_decoder(wrapper_version);
    let wrapper_script = wrapper.script_for_state(current)?;
    let wrapper_hash = blake2b_256(&wrapper_script);
    let holder_state = serde_json::json!({
        "canonicalTokenId": current["canonicalTokenId"],
        "owner": hex::encode(owner), "owner_scheme": scheme,
        "amount": amount.to_string(), "mode": "0", "unitPrice": "0",
        "feeTicketId": current["feeTicketId"],
        "priceScale": current["priceScale"],
        "feePolicy": current["feePolicy"],
        "payout_script_hash": hex::encode(payout),
        "wrapper_spk_hash": hex::encode(wrapper_hash),
    });
    let holder_script = holder.script_for_state(&holder_state)?;
    for (index, script) in [(holder_index, &holder_script), (wrapper_index, &wrapper_script)] {
        let output = tx.outputs.get(index).context("missing fee market wrap output")?;
        let expected_spk = [vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat();
        if hex::decode(&output.script_public_key)? != expected_spk
            || output.canonical_covenant_id().is_some_and(|id| id != hex::encode(market_id))
            || output.covenant_authorizing_input().is_some_and(|n| usize::from(n) != input_index)
        {
            bail!("fee market wrap output script or lineage mismatch");
        }
    }
    if tx.outputs[holder_index].amount < 50_000_000 {
        bail!("fee market holder deposit is below 0.5 KAS");
    }
    if let Some(principal) = tx.inputs.get(input_index)
        .and_then(|input| input.previous_outpoint_amount)
    {
        if tx.outputs[wrapper_index].amount != principal {
            bail!("fee market wrap changes wrapper principal");
        }
    }
    Ok([
        (i32::try_from(holder_index)?, holder.decode_constructor(&holder_script)?),
        (i32::try_from(wrapper_index)?, wrapper.decode_constructor(&wrapper_script)?),
    ])
}

/// Recover the two fee-market outputs from an accepted wrapper binding.
/// Both output scripts must match pinned artifacts and continue the spent
/// wrapper's lineage; an unspent output alone is not enough evidence.
pub fn fee_market_binding_outputs(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    market_id: &[u8],
    wrapper_version: FeeMarketWrapperVersion,
) -> Result<[(i32, Value); 2]> {
    if market_id.len() != 32
        || current["enabled"] != false
        || current["authenticatedMarketId"] != hex::encode([0; 32])
    {
        bail!("fee market binding requires an unbound wrapper");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let wrapper_index = i32::try_from(item_int(&items, 0)?)?;
    let root_index = i32::try_from(item_int(&items, 1)?)?;
    if wrapper_index < 0 || root_index <= wrapper_index {
        bail!("invalid fee market binding output order");
    }
    let wrapper = wrapper_decoder(wrapper_version);
    let root = root_decoder();
    if witness_bytes(&items, 2)? != root.prefix || witness_bytes(&items, 3)? != root.suffix {
        bail!("fee market root witness uses a different template");
    }
    let owner = witness_bytes(&items, 4)?;
    let scheme = u8::try_from(item_int(&items, 5)?)?;
    let payout = witness_bytes(&items, 6)?;
    let bound_hash = witness_bytes(&items, 7)?;
    if owner.len() != 32 || payout.len() != 32 || bound_hash.len() != 32 {
        bail!("invalid fee market binding witness fields");
    }
    let mut bound = current.clone();
    bound["enabled"] = Value::Bool(true);
    bound["authenticatedMarketId"] = Value::String(hex::encode(market_id));
    let wrapper_script = wrapper.script_for_state(&bound)?;
    let bound_hash_actual = blake2b_256(&wrapper_script);
    if bound_hash != bound_hash_actual {
        bail!("fee market bound wrapper hash mismatch");
    }
    let bound = wrapper.decode_constructor(&wrapper_script)?;
    let root_state = serde_json::json!({
        "canonicalTokenId": current["canonicalTokenId"],
        "owner": hex::encode(owner),
        "owner_scheme": scheme,
        "amount": "0",
        "mode": "1",
        "unitPrice": "0",
        "feeTicketId": current["feeTicketId"],
        "priceScale": current["priceScale"],
        "feePolicy": current["feePolicy"],
        "payout_script_hash": hex::encode(payout),
        "wrapper_spk_hash": hex::encode(bound_hash),
    });
    let root_script = root.script_for_state(&root_state)?;
    let root_state = root.decode_constructor(&root_script)?;
    for (index, script) in [(wrapper_index, &wrapper_script), (root_index, &root_script)] {
        let output = tx
            .outputs
            .get(usize::try_from(index)?)
            .context("missing fee market binding output")?;
        let expected_spk = [vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat();
        if hex::decode(&output.script_public_key)? != expected_spk
            || output
                .canonical_covenant_id()
                .is_some_and(|id| id != hex::encode(market_id))
            || output
                .covenant_authorizing_input()
                .is_some_and(|n| usize::from(n) != input_index)
        {
            bail!("fee market binding output script or lineage mismatch");
        }
    }
    if let Some(amount) = tx
        .inputs
        .get(input_index)
        .and_then(|input| input.previous_outpoint_amount)
    {
        if tx.outputs[usize::try_from(wrapper_index)?].amount != amount {
            bail!("fee market binding changes wrapper principal");
        }
    }
    if tx.outputs[usize::try_from(root_index)?].amount == 0 {
        bail!("fee market root has no principal");
    }
    Ok([(wrapper_index, bound), (root_index, root_state)])
}

fn witness_state(items: &[ScriptItem], start: usize, decoder: &Kcc20FeeV1Decoder) -> Result<Value> {
    crate::interpretation("fee_account_witness", (|| {
    let mut state = Map::new();
    for (offset, field) in decoder.fields.iter().enumerate() {
        let index = start + offset;
        let value = match field.kind.as_str() {
            "fixed_bytes" => {
                let bytes = witness_bytes(items, index)?;
                if Some(bytes.len()) != field.fixed_len {
                    bail!("invalid fee account witness field width");
                }
                Value::String(hex::encode(bytes))
            }
            "int" => Value::String(i64::try_from(item_int(items, index)?)?.to_string()),
            "byte" => {
                // PushMinimal encodes byte values 1..16 as OP_1..OP_16.
                // These put the same one-byte value on the VM stack as a data
                // push. OP_0 puts an empty vector there, not the byte 0x00.
                let byte = match items.get(index) {
                    Some(ScriptItem::Data(bytes)) if bytes.len() == 1 => bytes[0],
                    Some(ScriptItem::Int(value @ 1..=16)) => *value as u8,
                    Some(ScriptItem::Int(-1)) => 0x81,
                    _ => bail!("invalid fee account witness byte at {index}"),
                };
                Value::from(byte)
            }
            _ => bail!("unsupported fee account witness field"),
        };
        state.insert(field.name.clone(), value);
    }
    Ok(Value::Object(state))
    })())
}

/// Recover a fee account's exact successor from its authenticated spend.
/// Binding and authority updates are accepted only when the successor script
/// matches the pinned artifact and the transaction output.
pub fn fee_account_output_state(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    entrypoint: &str,
    current: &Value,
) -> Result<Option<(i32, Value)>> {
    let receipt = receipt_decoder();
    if current["roleName"] != "account" {
        return Ok(None);
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let (output_index, next) = match entrypoint {
        "bindMarket" => {
            let mut next = current.clone();
            next["market"] = Value::String(hex::encode(witness_bytes(&items, 0)?));
            next["policy"] = Value::String(hex::encode(witness_bytes(&items, 1)?));
            (i32::try_from(item_int(&items, 3)?)?, next)
        }
        "authorize" => {
            let action = item_int(&items, 0)?;
            if action != 1 && action != 2 {
                bail!("invalid fee account action");
            }
            let next = witness_state(&items, 1, receipt)?;
            (
                i32::try_from(item_int(&items, 1 + receipt.fields.len())?)?,
                next,
            )
        }
        _ => return Ok(None),
    };
    if output_index < 0 {
        bail!("fee account successor index is negative");
    }
    let script = receipt.script_for_state(&next)?;
    let decoded = receipt.decode_constructor(&script)?;
    if decoded["roleName"] != "account" {
        bail!("fee account successor changes role");
    }
    let output = tx
        .outputs
        .get(usize::try_from(output_index)?)
        .context("missing fee account successor")?;
    let expected_spk = [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat();
    if hex::decode(&output.script_public_key)? != expected_spk {
        bail!("fee account successor script mismatch");
    }
    if let Some(amount) = tx
        .inputs
        .get(input_index)
        .and_then(|input| input.previous_outpoint_amount)
    {
        if output.amount != amount {
            bail!("fee account successor value mismatch");
        }
    }
    Ok(Some((output_index, decoded)))
}

pub struct FeeClaimProjection {
    pub remainder: Option<(i32, Value)>,
    pub account_output_index: i32,
    pub account_commitment: String,
    pub expected_account_id: String,
    pub token_id: String,
    pub policy_id: String,
    pub claimed_sompi: i64,
    pub creator_side: bool,
}

/// Preserve the independent recipient's authenticated continuation after a
/// joint account action. Consensus verifies its signature and the account's
/// approval commitment; this projection checks the exact continuing output.
pub fn fee_recipient_output_state(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    current: &Value,
    recipient_id: &[u8],
) -> Result<(i32, Value)> {
    let recipient = recipient_decoder();
    anyhow::ensure!(current["roleName"] == "recipient", "not a fee recipient");
    let items = script_items(args_prefix_before_reveal(signature_script));
    let next = witness_state(&items, 1, recipient)?;
    let output_index = usize::try_from(item_int(&items, 1 + recipient.fields.len())?)?;
    for field in &recipient.fields {
        if field.name != "action_hash" {
            anyhow::ensure!(next[&field.name] == current[&field.name], "recipient changes {}", field.name);
        }
    }
    anyhow::ensure!(next["action_hash"].as_str().is_some_and(|v| v != "00".repeat(32)), "recipient approval is empty");
    let script = recipient.script_for_state(&next)?;
    let decoded = recipient.decode_constructor(&script)?;
    let output = tx.outputs.get(output_index).context("missing fee recipient successor")?;
    let expected_spk = [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat();
    anyhow::ensure!(hex::decode(&output.script_public_key)? == expected_spk, "fee recipient successor script mismatch");
    let principal = tx.inputs.get(input_index).and_then(|i| i.previous_outpoint_amount)
        .context("fee recipient principal must be hydrated")?;
    anyhow::ensure!(output.amount == principal, "fee recipient successor value mismatch");
    anyhow::ensure!(output.canonical_covenant_id() == Some(hex::encode(recipient_id).as_str()), "fee recipient successor lineage mismatch");
    anyhow::ensure!(output.covenant_authorizing_input() == Some(u16::try_from(input_index)?), "fee recipient successor authority mismatch");
    anyhow::ensure!(tx.outputs.iter().filter(|o| o.covenant_authorizing_input() == Some(input_index as u16)).count() == 1,
        "fee recipient must have exactly one authorized output");
    Ok((i32::try_from(output_index)?, decoded))
}

/// Validate a complete accepted claim and recover its remaining entitlement.
/// All selected receipt inputs must have authenticated states from their reveals.
pub fn fee_claim_output_state(
    tx: &RestTransaction,
    signature_script: &[u8],
    market_id: &[u8],
    receipts: &[(usize, Value)],
) -> Result<FeeClaimProjection> {
    if market_id.len() != 32 || receipts.is_empty() || receipts.len() > 5 {
        bail!("invalid fee claim receipt group");
    }
    let items = script_items(args_prefix_before_reveal(signature_script));
    let creator_side = item_int(&items, 0)? == 1;
    if !creator_side && item_int(&items, 0)? != 0 {
        bail!("invalid fee claim side");
    }
    let account_index = usize::try_from(item_int(&items, 1)?)?;
    let account_output_index = i32::try_from(item_int(&items, 2)?)?;
    let payout_index = usize::try_from(item_int(&items, 3)?)?;
    let payout_script = witness_bytes(&items, 4)?;
    let remainder_index = i32::try_from(item_int(&items, 5)?)?;
    let first = &receipts[0].1;
    if first["roleName"] != "receipt" || first["market"] != hex::encode(market_id) {
        bail!("claim leader is not a receipt in this market");
    }
    let mut protocol = 0i64;
    let mut creator = 0i64;
    let mut receipt_hash = [0u8; 32];
    for (index, state) in receipts {
        if state["roleName"] != "receipt"
            || state["token"] != first["token"]
            || state["market"] != first["market"]
            || state["policy"] != first["policy"]
            || state["protocol_account"] != first["protocol_account"]
            || state["creator_account"] != first["creator_account"]
        {
            bail!("claim mixes receipt identities");
        }
        let p = state["protocol_amount"]
            .as_str()
            .context("protocol amount")?
            .parse::<i64>()?;
        let c = state["creator_amount"]
            .as_str()
            .context("creator amount")?
            .parse::<i64>()?;
        if p < 0 || c < 0 || (if creator_side { c } else { p }) == 0 {
            bail!("receipt lacks claimant share");
        }
        let receipt_value = p.checked_add(c).context("receipt value overflow")?;
        let input = tx
            .inputs
            .get(*index)
            .context("missing claimed receipt input")?;
        if input
            .previous_outpoint_amount
            .is_some_and(|amount| amount != receipt_value as u64)
        {
            bail!("claimed receipt value disagrees with state");
        }
        protocol = protocol.checked_add(p).context("protocol claim overflow")?;
        creator = creator.checked_add(c).context("creator claim overflow")?;
        let mut preimage = Vec::with_capacity(72);
        preimage.extend(receipt_hash);
        preimage.extend(hex::decode(&input.previous_outpoint_hash)?);
        preimage.extend(input.previous_outpoint_index.parse::<i64>()?.to_le_bytes());
        receipt_hash.copy_from_slice(blake3::hash(&preimage).as_bytes());
    }
    let claimed = if creator_side { creator } else { protocol };
    let retained = if creator_side { protocol } else { creator };
    let payout = tx
        .outputs
        .get(payout_index)
        .context("missing claim payout")?;
    if payout_script.len() < 3 || payout_script[..2] != [0, 0]
        || payout.amount != claimed as u64
        || hex::decode(&payout.script_public_key)? != payout_script[2..]
    {
        bail!("claim payout disagrees with selected entitlement");
    }
    let account_input = tx
        .inputs
        .get(account_index)
        .context("missing claim account input")?;
    let mut binding = Vec::with_capacity(250);
    binding.push(0xf1);
    binding.extend(hex::decode(first["token"].as_str().context("fee token")?)?);
    binding.extend(market_id);
    binding.extend(hex::decode(
        first["policy"].as_str().context("fee policy")?,
    )?);
    binding.extend(receipt_hash);
    binding.extend(hex::decode(&account_input.previous_outpoint_hash)?);
    binding.extend(
        account_input
            .previous_outpoint_index
            .parse::<i64>()?
            .to_le_bytes(),
    );
    binding.extend((if creator_side { 1i64 } else { 0 }).to_le_bytes());
    binding.extend(claimed.to_le_bytes());
    binding.extend(retained.to_le_bytes());
    binding.extend(blake3::hash(payout_script).as_bytes());
    let account_commitment = blake3::hash(&binding).to_hex().to_string();
    let expected_account_id = first[if creator_side {
        "creator_account"
    } else {
        "protocol_account"
    }]
    .as_str()
    .context("claim account identity")?
    .to_owned();
    let remainder = if retained == 0 {
        if remainder_index != -1 {
            bail!("empty claim must omit remainder");
        }
        None
    } else {
        if remainder_index < 0 {
            bail!("claim dropped opposing entitlement");
        }
        let mut next = first.clone();
        next["protocol_amount"] =
            Value::String((if creator_side { protocol } else { 0 }).to_string());
        next["creator_amount"] =
            Value::String((if creator_side { 0 } else { creator }).to_string());
        next["action_hash"] = Value::String(hex::encode([0; 32]));
        let decoder = receipt_decoder();
        let script = decoder.script_for_state(&next)?;
        let output = tx
            .outputs
            .get(usize::try_from(remainder_index)?)
            .context("missing claim remainder")?;
        let expected_spk = [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat();
        if output.amount != retained as u64
            || hex::decode(&output.script_public_key)? != expected_spk
        {
            bail!("claim remainder loses opposing entitlement");
        }
        Some((remainder_index, decoder.decode_constructor(&script)?))
    };
    Ok(FeeClaimProjection {
        remainder,
        account_output_index,
        account_commitment,
        expected_account_id,
        token_id: first["token"]
            .as_str()
            .context("claim token identity")?
            .to_owned(),
        policy_id: first["policy"]
            .as_str()
            .context("claim policy identity")?
            .to_owned(),
        claimed_sompi: claimed,
        creator_side,
    })
}

/// Recover a receipt from a consensus-accepted grouped trade's authenticated
/// leader witness. The output script and KAS value must match the derived state.
pub fn grouped_receipt_output_state(
    tx: &RestTransaction,
    signature_script: &[u8],
    entrypoint: &str,
    leader_state: &Value,
    market_id: &[u8],
    market_input_indices: &[usize],
) -> Result<Option<(i32, Value)>> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    let (count_at, vector_at, ticket_at, output_at, prefix_at, taker) = match entrypoint {
        "sellIntoBids" => (
            1,
            Some(3),
            4,
            5,
            9,
            hex::decode(leader_state["owner"].as_str().context("seller owner")?)?,
        ),
        "buyAsks" => (3, Some(5), 6, 7, 9, witness_bytes(&items, 0)?.to_vec()),
        "crossWithBid" => (
            2,
            None,
            usize::MAX,
            7,
            9,
            witness_bytes(&items, 0)?.to_vec(),
        ),
        _ => return Ok(None),
    };
    if market_id.len() != 32 || taker.len() != 32 {
        bail!("invalid market or taker identity");
    }
    let fill_count = if entrypoint == "crossWithBid" {
        1
    } else {
        usize::try_from(item_int(&items, count_at)?)?
    };
    let max_fills = match entrypoint {
        "sellIntoBids" => 10,
        "buyAsks" => 16,
        _ => 1,
    };
    if fill_count == 0 || fill_count > max_fills {
        bail!("fee group exceeds contract fill limit");
    }
    let expected_inputs = match entrypoint {
        "sellIntoBids" => fill_count + 1,
        "buyAsks" => fill_count,
        _ => 2,
    };
    if fill_count == 0
        || market_input_indices.len() != expected_inputs
        || market_input_indices.first().copied().is_none()
    {
        bail!("fee group market input set is incomplete");
    }
    let ticket_index = if ticket_at == usize::MAX {
        -1
    } else {
        item_int(&items, ticket_at)?
    };
    let output_index = i32::try_from(item_int(&items, output_at)?)?;
    if output_index < 0 {
        return Ok(None);
    }
    let receipt = receipt_decoder();
    if witness_bytes(&items, prefix_at)? != receipt.prefix
        || witness_bytes(&items, prefix_at + 1)? != receipt.suffix
    {
        bail!("fee receipt witness does not use pinned artifact");
    }
    let token = hex::decode(
        leader_state["canonicalTokenId"]
            .as_str()
            .context("fee token")?,
    )?;
    let ticket_id = hex::decode(
        leader_state["feeTicketId"]
            .as_str()
            .context("fee ticket root")?,
    )?;
    let policy = hex::decode(leader_state["feePolicy"].as_str().context("fee policy")?)?;
    if token.len() != 32 || ticket_id.len() != 32 || policy.len() != 361 {
        bail!("invalid fee policy identity");
    }
    let price_scale = leader_state["priceScale"]
        .as_str()
        .context("fee price scale")?
        .parse::<i64>()?;
    if price_scale <= 0 {
        bail!("invalid fee price scale");
    }
    let mut policy_preimage = Vec::with_capacity(32 + 32 + 8 + 361);
    policy_preimage.extend(&token);
    policy_preimage.extend(&ticket_id);
    policy_preimage.extend(price_scale.to_le_bytes());
    policy_preimage.extend(&policy);
    let policy_id = blake3::hash(&policy_preimage);
    let vector = match vector_at {
        Some(index) => witness_bytes(&items, index)?.to_vec(),
        None => {
            let fill = i64::try_from(item_int(&items, 2)?)?;
            let unit_price = leader_state["unitPrice"]
                .as_str()
                .context("ask price")?
                .parse::<i64>()?;
            let gross = (i128::from(fill) * i128::from(unit_price)) / i128::from(price_scale);
            let gross = i64::try_from(gross)?;
            let percentage =
                |bps: i64| (i128::from(gross) * i128::from(bps) / 10_000).max(50_000_000) as i64;
            let creator_bps = i64::from_le_bytes(policy[1..9].try_into()?);
            let mut bytes = percentage(100).to_le_bytes().to_vec();
            bytes.extend(
                (if creator_bps == 0 {
                    0
                } else {
                    percentage(creator_bps)
                })
                .to_le_bytes(),
            );
            bytes
        }
    };
    if vector.len() != fill_count * 16 {
        bail!("fee vector length does not match fills");
    }
    let mut protocol = 0i64;
    let mut creator = 0i64;
    for pair in vector.chunks_exact(16) {
        let p = i64::from_le_bytes(pair[..8].try_into()?);
        let c = i64::from_le_bytes(pair[8..].try_into()?);
        if p < 0 || c < 0 {
            bail!("negative fee vector amount");
        }
        protocol = protocol.checked_add(p).context("protocol fee overflow")?;
        creator = creator.checked_add(c).context("creator fee overflow")?;
    }
    let total = protocol
        .checked_add(creator)
        .context("receipt value overflow")?;
    if total == 0 {
        return Ok(None);
    }
    let mut input_bytes = vec![0xe1];
    input_bytes.extend(i64::try_from(market_input_indices.len())?.to_le_bytes());
    for &index in market_input_indices {
        let input = tx.inputs.get(index).context("missing market input")?;
        input_bytes.extend(hex::decode(&input.previous_outpoint_hash)?);
        input_bytes.extend(input.previous_outpoint_index.parse::<i64>()?.to_le_bytes());
    }
    let mut ticket_bytes = vec![0; 40];
    if ticket_index >= 0 {
        let input = tx
            .inputs
            .get(usize::try_from(ticket_index)?)
            .context("missing ticket input")?;
        ticket_bytes[..32].copy_from_slice(&hex::decode(&input.previous_outpoint_hash)?);
        ticket_bytes[32..]
            .copy_from_slice(&input.previous_outpoint_index.parse::<i64>()?.to_le_bytes());
    }
    let mut group = vec![0xe2];
    group.extend(&token);
    group.extend(market_id);
    group.extend(policy_id.as_bytes());
    group.extend(&taker);
    group.extend(ticket_bytes);
    group.extend(blake3::hash(&input_bytes).as_bytes());
    group.extend(&vector);
    let zero = hex::encode([0; 32]);
    let state = serde_json::json!({
        "role": "0", "token": hex::encode(&token), "market": hex::encode(market_id),
        "policy": policy_id.to_hex().to_string(),
        "protocol_account": hex::encode(&policy[9..41]),
        "creator_account": hex::encode(&policy[41..73]),
        "protocol_amount": protocol.to_string(), "creator_amount": creator.to_string(),
        "owner": zero, "owner_scheme": 0, "guard_template": zero,
        "guard_prefix": "0", "guard_suffix": "0",
        "action_hash": blake3::hash(&group).to_hex().to_string(),
        "self_template": hex::encode(receipt.template_hash),
        "self_prefix": receipt.prefix.len().to_string(),
        "self_suffix": receipt.suffix.len().to_string(),
    });
    let script = receipt.script_for_state(&state)?;
    let output = tx
        .outputs
        .get(usize::try_from(output_index)?)
        .context("missing receipt output")?;
    let expected_spk = [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat();
    if output.amount != total as u64 || hex::decode(&output.script_public_key)? != expected_spk {
        bail!("fee receipt output does not match committed script or value");
    }
    Ok(Some((output_index, receipt.decode_constructor(&script)?)))
}

fn canonical_push(state: &[u8], size: usize) -> bool {
    match size {
        1..=75 => state.first().copied() == Some(size as u8),
        76..=255 => state.starts_with(&[0x4c, size as u8]),
        256..=65535 => state.starts_with(&[0x4d, size as u8, (size >> 8) as u8]),
        _ => false,
    }
}

fn number(state: &Map<String, Value>, field: &str) -> Result<u64> {
    let value = state.get(field).context("missing fee numeric field")?;
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    value
        .as_str()
        .context("fee field is not numeric")?
        .parse()
        .map_err(Into::into)
}

fn pinned_policy() -> &'static Vec<u8> {
    static POLICY: OnceLock<Vec<u8>> = OnceLock::new();
    POLICY.get_or_init(|| {
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../wallet-lab/vendor/kcc20-fee-policy-v1/manifest.json"
        ))
        .expect("pinned fee policy manifest");
        hex::decode(manifest["policyHex"].as_str().expect("pinned policy hex"))
            .expect("pinned policy bytes")
    })
}

impl TemplateDecoder for Kcc20FeeV1Decoder {
    fn template(&self) -> KnownTemplate {
        self.template
    }
    fn script_hash(&self) -> [u8; 32] {
        self.template_hash
    }
    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        self.exact_template(reveal)
            && self
                .decode_fields(&reveal[self.prefix.len()..self.prefix.len() + self.state_len])
                .is_ok()
    }
    fn decode_constructor(&self, reveal: &[u8]) -> Result<Value> {
        self.decode_fields(self.state_bytes(reveal)?)
    }
    fn decode_state(&self, state: &[u8]) -> Result<Value> {
        self.decode_fields(state)
    }
    fn decode_action_checked(&self, signature_script: &[u8]) -> Result<Option<String>> {
        self.decode_action(signature_script)
            .map(Some)
            .ok_or_else(|| anyhow!(crate::InterpretationFailure("unsupported spend action")))
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let prefix = args_prefix_before_reveal(signature_script);
        let ScriptItem::Data(bytes) = script_items(prefix).last()?.clone() else {
            return None;
        };
        let tag: [u8; 4] = bytes.as_slice().try_into().ok()?;
        self.entries.get(&tag).cloned()
    }
}

pub fn bundled_decoders() -> Vec<Kcc20FeeV1Decoder> {
    let artifacts = [
        (
            KnownTemplate::Kcc20FeeEscrowV1,
            include_str!("../fixtures/kcc20-fee-escrow-v1/KCC20FeeEscrowV1.placeholder.json"),
        ),
        (
            KnownTemplate::Kcc20FeeRecipientV1,
            include_str!("../fixtures/kcc20-fee-recipient-v1/KCC20FeeRecipientV1.placeholder.json"),
        ),
        (
            KnownTemplate::Kcc20FeeRootV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-root-v1/KCC20OrderbookFeeRootV1.placeholder.json"
            ),
        ),
        (
            KnownTemplate::Kcc20FeeHolderV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-holder-v1/KCC20OrderbookFeeHolderV1.placeholder.json"
            ),
        ),
        (
            KnownTemplate::Kcc20FeeAskV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-ask-v1/KCC20OrderbookFeeAskV1.placeholder.json"
            ),
        ),
        (
            KnownTemplate::Kcc20FeeBidV1,
            include_str!(
                "../fixtures/kcc20-orderbook-fee-bid-v1/KCC20OrderbookFeeBidV1.placeholder.json"
            ),
        ),
        (
            KnownTemplate::Kcc20FeeWrapperV1,
            include_str!("../fixtures/kcc20-wrapper-fee-v1/KCC20WrapperFeeV1.placeholder.json"),
        ),
        (
            KnownTemplate::Kcc20FeeWrapperV2,
            include_str!("../fixtures/kcc20-wrapper-fee-v2/KCC20WrapperFeeV2.placeholder.json"),
        ),
        (
            KnownTemplate::Kcc20FeeWrapperArgentV1,
            include_str!(
                "../fixtures/kcc20-wrapper-fee-argent-v1/KCC20WrapperFeeArgentV1.placeholder.json"
            ),
        ),
        (
            KnownTemplate::Kcc20FeeWrapperArgentV2,
            include_str!("../fixtures/kcc20-wrapper-fee-argent-v2/KCC20WrapperFeeArgentV2.placeholder.json"),
        ),
    ];
    artifacts
        .into_iter()
        .map(|(kind, raw)| {
            Kcc20FeeV1Decoder::from_artifact(kind, raw).expect("invalid pinned KCC20 fee artifact")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tn12_indexer_core::{RestTxInput, RestTxOutput};

    fn push(bytes: &[u8], script: &mut Vec<u8>) {
        match bytes.len() {
            0 => script.push(0),
            1..=75 => script.push(bytes.len() as u8),
            76..=255 => script.extend([0x4c, bytes.len() as u8]),
            _ => {
                script.push(0x4d);
                script.extend((bytes.len() as u16).to_le_bytes());
            }
        }
        script.extend(bytes);
    }

    #[test]
    fn holder_merge_projects_sum_and_rejects_wrong_refund_or_state() {
        let market = [3u8; 32];
        let payout_spk = vec![0x51];
        let mut serialized = vec![0xe3, 0, 0];
        serialized.extend((payout_spk.len() as u64).to_le_bytes());
        serialized.extend(&payout_spk);
        let payout_hash = blake3::hash(&serialized).to_hex().to_string();
        let source = serde_json::json!({
            "canonicalTokenId": "01".repeat(32), "owner": "04".repeat(32),
            "owner_scheme": 0, "amount": "5", "mode": "0", "unitPrice": "0",
            "feeTicketId": "02".repeat(32), "priceScale": "1",
            "feePolicy": hex::encode(pinned_policy()),
            "payout_script_hash": payout_hash, "wrapper_spk_hash": "06".repeat(32),
        });
        let source = holder_decoder().decode_constructor(
            &holder_decoder().script_for_state(&source).unwrap(),
        ).unwrap();
        let mut second = source.clone();
        second["amount"] = Value::String("3".into());
        let mut merged = source.clone();
        merged["amount"] = Value::String("8".into());
        let merged_script = holder_decoder().script_for_state(&merged).unwrap();
        let merged_spk = [vec![0xaa, 0x20], blake2b_256(&merged_script).to_vec(), vec![0x87]].concat();
        let mut tx = RestTransaction {
            inputs: vec![
                RestTxInput { previous_outpoint_amount: Some(50_000_000), ..Default::default() },
                RestTxInput { previous_outpoint_amount: Some(50_000_000), ..Default::default() },
            ],
            outputs: vec![
                RestTxOutput { amount: 50_000_000, script_public_key: hex::encode(merged_spk), covenant_id: Some(hex::encode(market)), ..Default::default() },
                RestTxOutput { amount: 50_000_000, script_public_key: hex::encode(&payout_spk), ..Default::default() },
            ],
            ..Default::default()
        };
        let states = vec![source.clone(), second.clone()];
        assert_eq!(
            fee_market_merge_holders_output(&tx, &[0, 1], &states, &market).unwrap().1["amount"],
            "8"
        );
        tx.outputs[1].amount -= 1;
        assert!(fee_market_merge_holders_output(&tx, &[0, 1], &states, &market).is_err());
        tx.outputs[1].amount += 1;
        tx.inputs[0].previous_outpoint_amount = None;
        tx.inputs[1].previous_outpoint_amount = None;
        assert_eq!(
            fee_market_merge_holders_output(&tx, &[0, 1], &states, &market).unwrap().1["amount"],
            "8"
        );
        tx.outputs[1].script_public_key = "52".into();
        assert!(fee_market_merge_holders_output(&tx, &[0, 1], &states, &market).is_err());
        tx.outputs[1].script_public_key = "51".into();
        second["owner"] = Value::String("05".repeat(32));
        assert!(fee_market_merge_holders_output(&tx, &[0, 1], &[source, second], &market).is_err());
    }

    #[test]
    fn grouped_trade_projects_the_exact_active_receipt_and_rejects_diversion() {
        let receipt = receipt_decoder();
        let policy = pinned_policy();
        let state = serde_json::json!({
            "role": "0", "token": "01".repeat(32), "market": "02".repeat(32),
            "policy": "84a7d4615074426dd9545e8171aa8624b19844583026f793793c37c03475cafb",
            "protocol_account": hex::encode(&policy[9..41]),
            "creator_account": hex::encode(&policy[41..73]),
            "protocol_amount": "50000000", "creator_amount": "50000000",
            "owner": "00".repeat(32), "owner_scheme": 0,
            "guard_template": "00".repeat(32), "guard_prefix": "0", "guard_suffix": "0",
            "action_hash": "33849829ec78a466300b9bf2ad60a920fa69cdf428ea85d847724dfab65ebd71",
            "self_template": hex::encode(receipt.template_hash),
            "self_prefix": receipt.prefix.len().to_string(),
            "self_suffix": receipt.suffix.len().to_string(),
        });
        let script = receipt.script_for_state(&state).unwrap();
        let mut witness = Vec::new();
        push(&[9; 64], &mut witness);
        witness.push(0x51); // one fill
        push(&[0; 32], &mut witness); // leg data
        let mut vector = 50_000_000i64.to_le_bytes().to_vec();
        vector.extend(50_000_000i64.to_le_bytes());
        push(&vector, &mut witness);
        witness.push(0x4f); // no ticket
        witness.push(0x00); // fee output 0
        witness.push(0x4f); // no change
        witness.push(0x51); // refund 1
        witness.push(0x4f); // no ticket refund
        push(&receipt.prefix, &mut witness);
        push(&receipt.suffix, &mut witness);
        push(&[1; 4], &mut witness); // dispatch tag
        push(&[2; 4], &mut witness); // reveal
        let input = |id: u8, index: u32| RestTxInput {
            previous_outpoint_hash: hex::encode([id; 32]),
            previous_outpoint_index: index.to_string(),
            ..Default::default()
        };
        let mut tx = RestTransaction {
            inputs: vec![input(7, 0), input(8, 2)],
            outputs: vec![RestTxOutput {
                amount: 100_000_000,
                script_public_key: hex::encode(
                    [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        };
        let leader = serde_json::json!({
            "canonicalTokenId": "01".repeat(32), "owner": "04".repeat(32),
            "feeTicketId": "00".repeat(32), "feePolicy": hex::encode(policy),
            "priceScale": "1",
        });
        let projected =
            grouped_receipt_output_state(&tx, &witness, "sellIntoBids", &leader, &[2; 32], &[0, 1])
                .unwrap()
                .unwrap();
        assert_eq!(projected.0, 0);
        assert_eq!(projected.1["action_hash"], state["action_hash"]);
        assert_eq!(projected.1["protocol_amount"], "50000000");
        tx.outputs[0].amount -= 1;
        assert!(grouped_receipt_output_state(
            &tx,
            &witness,
            "sellIntoBids",
            &leader,
            &[2; 32],
            &[0, 1],
        )
        .is_err());

        let receipt_output = RestTxOutput {
            amount: 100_000_000,
            script_public_key: hex::encode(
                [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat(),
            ),
            ..Default::default()
        };
        tx.outputs = vec![RestTxOutput::default(); 7];
        tx.outputs.push(receipt_output);
        let mut cross = Vec::new();
        push(&[4; 32], &mut cross); // matcher
        cross.push(0x52); // funding input 2
        cross.push(0x51); // fill one token
        cross.extend([0x00, 0x4f, 0x4f, 0x56, 0x57, 0x4f]);
        push(&receipt.prefix, &mut cross);
        push(&receipt.suffix, &mut cross);
        for _ in 0..4 {
            cross.push(0x00);
        } // role-template arguments
        push(&[1; 4], &mut cross);
        push(&[2; 4], &mut cross);
        let mut cross_leader = leader.clone();
        cross_leader["unitPrice"] = Value::String("100000000".into());
        let crossed = grouped_receipt_output_state(
            &tx,
            &cross,
            "crossWithBid",
            &cross_leader,
            &[2; 32],
            &[0, 1],
        )
        .unwrap()
        .unwrap();
        assert_eq!(crossed.0, 7);
        assert_eq!(crossed.1["action_hash"], state["action_hash"]);

        let mut buy_state = state.clone();
        buy_state["action_hash"] = Value::String(
            "9cc55a706dac8a5e939c8a21bb11cc03d7da7adcd9a63b82f5c38215dbb49a11".into(),
        );
        let buy_script = receipt.script_for_state(&buy_state).unwrap();
        tx.inputs.truncate(1);
        tx.outputs = vec![RestTxOutput {
            amount: 100_000_000,
            script_public_key: hex::encode(
                [
                    vec![0xaa, 0x20],
                    blake2b_256(&buy_script).to_vec(),
                    vec![0x87],
                ]
                .concat(),
            ),
            ..Default::default()
        }];
        let mut buy = Vec::new();
        push(&[4; 32], &mut buy); // buyer
        buy.push(0x00); // owner scheme
        push(&[9; 32], &mut buy); // payout hash
        buy.push(0x51); // one ask
        push(&[0; 32], &mut buy); // leg data
        push(&vector, &mut buy);
        buy.extend([0x4f, 0x00, 0x4f]); // no ticket, fee output 0, no refund
        push(&receipt.prefix, &mut buy);
        push(&receipt.suffix, &mut buy);
        buy.extend([0x00, 0x00]); // holder template arguments
        push(&[1; 4], &mut buy);
        push(&[2; 4], &mut buy);
        let bought = grouped_receipt_output_state(&tx, &buy, "buyAsks", &leader, &[2; 32], &[0])
            .unwrap()
            .unwrap();
        assert_eq!(bought.1["action_hash"], buy_state["action_hash"]);

        let mut sweep_state = state.clone();
        sweep_state["protocol_amount"] = Value::String("500000000".into());
        sweep_state["creator_amount"] = Value::String("500000000".into());
        sweep_state["action_hash"] = Value::String(
            "3fdaac37cd212fdb6de0c89bbf7b334111a5ce5a9abe97dfcff4417e488bc9a6".into(),
        );
        let sweep_script = receipt.script_for_state(&sweep_state).unwrap();
        tx.inputs = (70..81).map(|id| input(id, 0)).collect();
        tx.outputs = vec![RestTxOutput {
            amount: 1_000_000_000,
            script_public_key: hex::encode(
                [
                    vec![0xaa, 0x20],
                    blake2b_256(&sweep_script).to_vec(),
                    vec![0x87],
                ]
                .concat(),
            ),
            ..Default::default()
        }];
        let mut sweep = Vec::new();
        push(&[9; 64], &mut sweep);
        sweep.push(0x5a); // ten fills
        push(&[0; 320], &mut sweep);
        push(&vector.repeat(10), &mut sweep);
        sweep.extend([0x4f, 0x00, 0x4f, 0x51, 0x4f]);
        push(&receipt.prefix, &mut sweep);
        push(&receipt.suffix, &mut sweep);
        push(&[1; 4], &mut sweep);
        push(&[2; 4], &mut sweep);
        let indices = (0..11).collect::<Vec<_>>();
        let swept =
            grouped_receipt_output_state(&tx, &sweep, "sellIntoBids", &leader, &[2; 32], &indices)
                .unwrap()
                .unwrap();
        assert_eq!(swept.1["action_hash"], sweep_state["action_hash"]);
    }

    fn set_field(script: &mut [u8], decoder: &Kcc20FeeV1Decoder, name: &str, value: &[u8]) {
        let mut offset = decoder.prefix.len();
        let end = offset + decoder.state_len;
        for field in &decoder.fields {
            let remaining = &script[offset..end];
            let (data, rest) = read_push(remaining).unwrap();
            let consumed = remaining.len() - rest.len();
            if field.name == name {
                let length = data.len();
                assert_eq!(length, value.len());
                let payload_start = offset + consumed - length;
                script[payload_start..payload_start + length].copy_from_slice(value);
                return;
            }
            offset += consumed;
        }
        panic!("missing fee state field {name}");
    }

    fn decoder(kind: KnownTemplate) -> Kcc20FeeV1Decoder {
        bundled_decoders()
            .into_iter()
            .find(|d| d.template == kind)
            .unwrap()
    }

    #[test]
    fn wrapper_binding_projects_only_exact_pinned_successors() {
        for wrapper_version in [FeeMarketWrapperVersion::NativeV1, FeeMarketWrapperVersion::NativeV2, FeeMarketWrapperVersion::ArgentV1, FeeMarketWrapperVersion::ArgentV2] {
            let wrapper = wrapper_decoder(wrapper_version);
            let root = root_decoder();
            let mut genesis = wrapper.placeholder.clone();
            set_field(&mut genesis, wrapper, "canonicalTokenId", &[1; 32]);
            set_field(&mut genesis, wrapper, "enabled", &[0]);
            set_field(&mut genesis, wrapper, "priceScale", &1i64.to_le_bytes());
            set_field(&mut genesis, wrapper, "feeTicketId", &[2; 32]);
            set_field(&mut genesis, wrapper, "feePolicy", &pinned_policy());
            set_field(&mut genesis, wrapper, "authenticatedMarketId", &[0; 32]);
            let current = wrapper.decode_constructor(&genesis).unwrap();
            let market = [3; 32];
            let mut bound = current.clone();
            bound["enabled"] = Value::Bool(true);
            bound["authenticatedMarketId"] = Value::String(hex::encode(market));
            let bound_script = wrapper.script_for_state(&bound).unwrap();
            let bound_hash = blake2b_256(&bound_script);
            let spk = [vec![0xaa, 0x20], bound_hash.to_vec(), vec![0x87]].concat();
            assert!(fee_market_wrapper_matches_script_pubkey(&bound, &spk));
            let expected_template = match wrapper_version {
                FeeMarketWrapperVersion::NativeV1 => "KCC20WrapperFeeV1",
                FeeMarketWrapperVersion::NativeV2 => "KCC20WrapperFeeV2",
                FeeMarketWrapperVersion::ArgentV1 => "KCC20WrapperFeeArgentV1",
                FeeMarketWrapperVersion::ArgentV2 => "KCC20WrapperFeeArgentV2",
            };
            assert_eq!(fee_market_wrapper_template(&bound, &spk), Some(expected_template));
            let mut wrong = bound.clone();
            wrong["feeTicketId"] = Value::String("ff".repeat(32));
            assert!(!fee_market_wrapper_matches_script_pubkey(&wrong, &spk));
            assert_eq!(fee_market_wrapper_template(&wrong, &spk), None);
            assert!(!fee_market_wrapper_matches_script_pubkey(&bound, &[0; 35]));
            let root_state = serde_json::json!({
                "canonicalTokenId": current["canonicalTokenId"],
                "owner": "04".repeat(32), "owner_scheme": 0,
                "amount": "0", "mode": "1", "unitPrice": "0",
                "feeTicketId": current["feeTicketId"],
                "priceScale": current["priceScale"],
                "feePolicy": current["feePolicy"],
                "payout_script_hash": "05".repeat(32),
                "wrapper_spk_hash": hex::encode(bound_hash),
            });
            let root_script = root.script_for_state(&root_state).unwrap();
            let spk = |script: &[u8]| {
                hex::encode([vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat())
            };
            let mut tx = RestTransaction {
                inputs: vec![RestTxInput {
                    previous_outpoint_amount: Some(50_000_000),
                    ..Default::default()
                }],
                outputs: vec![
                    RestTxOutput {
                        amount: 50_000_000,
                        script_public_key: spk(&bound_script),
                        covenant_id: Some(hex::encode(market)),
                        ..Default::default()
                    },
                    RestTxOutput {
                        amount: 50_000_000,
                        script_public_key: spk(&root_script),
                        covenant_id: Some(hex::encode(market)),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            };
            let mut witness = vec![0x00, 0x51];
            push(&root.prefix, &mut witness);
            push(&root.suffix, &mut witness);
            push(&[4; 32], &mut witness);
            witness.push(0x00);
            push(&[5; 32], &mut witness);
            push(&bound_hash, &mut witness);
            push(&genesis, &mut witness);
            let projected =
                fee_market_binding_outputs(&tx, 0, &witness, &current, &market, wrapper_version).unwrap();
            assert_eq!(projected[0].1["authenticatedMarketId"], hex::encode(market));
            assert_eq!(projected[1].1["wrapper_spk_hash"], hex::encode(bound_hash));
            tx.outputs[0].covenant_id = None;
            tx.outputs[1].covenant_id = None;
            assert!(fee_market_binding_outputs(&tx, 0, &witness, &current, &market, wrapper_version).is_ok());
            tx.outputs[0].covenant_id = Some(hex::encode(market));
            tx.outputs[1].covenant_id = Some(hex::encode(market));
            tx.outputs[1].script_public_key = spk(&genesis);
            assert!(
                fee_market_binding_outputs(&tx, 0, &witness, &current, &market, wrapper_version).is_err()
            );
            tx.outputs[1].script_public_key = spk(&root_script);
            tx.outputs[1].covenant_id = Some(hex::encode([6; 32]));
            assert!(
                fee_market_binding_outputs(&tx, 0, &witness, &current, &market, wrapper_version).is_err()
            );
        }
    }

    #[test]
    fn wrapper_wrap_projects_exact_holder_and_wrapper_successors() {
        for wrapper_version in [FeeMarketWrapperVersion::NativeV1, FeeMarketWrapperVersion::NativeV2, FeeMarketWrapperVersion::ArgentV1, FeeMarketWrapperVersion::ArgentV2] {
        let wrapper = wrapper_decoder(wrapper_version);
        let holder = holder_decoder();
        let market = [3; 32];
        let mut genesis = wrapper.placeholder.clone();
        set_field(&mut genesis, wrapper, "canonicalTokenId", &[1; 32]);
        set_field(&mut genesis, wrapper, "enabled", &[1]);
        set_field(&mut genesis, wrapper, "priceScale", &1i64.to_le_bytes());
        set_field(&mut genesis, wrapper, "feeTicketId", &[2; 32]);
        set_field(&mut genesis, wrapper, "feePolicy", &pinned_policy());
        set_field(&mut genesis, wrapper, "authenticatedMarketId", &market);
        let current = wrapper.decode_constructor(&genesis).unwrap();
        let holder_state = serde_json::json!({
            "canonicalTokenId": current["canonicalTokenId"],
            "owner": "04".repeat(32), "owner_scheme": 0,
            "amount": "10", "mode": "0", "unitPrice": "0",
            "feeTicketId": current["feeTicketId"],
            "priceScale": current["priceScale"],
            "feePolicy": current["feePolicy"],
            "payout_script_hash": "05".repeat(32),
            "wrapper_spk_hash": hex::encode(blake2b_256(&genesis)),
        });
        let holder_script = holder.script_for_state(&holder_state).unwrap();
        let spk = |script: &[u8]| {
            hex::encode([vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat())
        };
        let mut tx = RestTransaction {
            inputs: vec![RestTxInput {
                previous_outpoint_amount: Some(50_000_000),
                ..Default::default()
            }],
            outputs: vec![
                RestTxOutput::default(),
                RestTxOutput { amount: 50_000_000, script_public_key: spk(&holder_script),
                    covenant_id: Some(hex::encode(market)), ..Default::default() },
                RestTxOutput { amount: 50_000_000, script_public_key: spk(&genesis),
                    covenant_id: Some(hex::encode(market)), ..Default::default() },
            ],
            ..Default::default()
        };
        let mut witness = vec![0x00, 0x51, 0x52];
        push(&[4; 32], &mut witness);
        push(&[0], &mut witness);
        push(&[5; 32], &mut witness);
        push(&10i64.to_le_bytes(), &mut witness);
        push(&holder.prefix, &mut witness);
        push(&holder.suffix, &mut witness);
        push(&genesis, &mut witness);
        let projected = fee_market_wrap_outputs(&tx, 0, &witness, &current, &market, wrapper_version).unwrap();
        assert_eq!(projected[0].0, 1);
        assert_eq!(projected[0].1["amount"], "10");
        assert_eq!(projected[1].0, 2);
        assert_eq!(projected[1].1["authenticatedMarketId"], hex::encode(market));
        let mut prefixed_witness = Vec::new();
        push(&[1; 32], &mut prefixed_witness);
        push(&[1], &mut prefixed_witness);
        prefixed_witness.extend(&witness);
        assert!(fee_market_wrap_outputs(&tx, 0, &prefixed_witness, &current, &market, wrapper_version).is_ok());
        tx.outputs[1].script_public_key = spk(&genesis);
        assert!(fee_market_wrap_outputs(&tx, 0, &witness, &current, &market, wrapper_version).is_err());
        tx.outputs[1].script_public_key = spk(&holder_script);
        tx.outputs[1].amount = 1;
        assert!(fee_market_wrap_outputs(&tx, 0, &witness, &current, &market, wrapper_version).is_err());
        }
    }

    #[test]
    fn fee_market_unwrap_projects_remaining_holder_and_wrapper() {
        for wrapper_version in [FeeMarketWrapperVersion::NativeV1, FeeMarketWrapperVersion::NativeV2, FeeMarketWrapperVersion::ArgentV1, FeeMarketWrapperVersion::ArgentV2] {
        let wrapper = wrapper_decoder(wrapper_version);
        let holder = holder_decoder();
        let market = [3; 32];
        let mut wrapper_script = wrapper.placeholder.clone();
        set_field(&mut wrapper_script, wrapper, "canonicalTokenId", &[1; 32]);
        set_field(&mut wrapper_script, wrapper, "enabled", &[1]);
        set_field(&mut wrapper_script, wrapper, "priceScale", &1i64.to_le_bytes());
        set_field(&mut wrapper_script, wrapper, "feeTicketId", &[2; 32]);
        set_field(&mut wrapper_script, wrapper, "feePolicy", &pinned_policy());
        set_field(&mut wrapper_script, wrapper, "authenticatedMarketId", &market);
        let wrapper_state = wrapper.decode_constructor(&wrapper_script).unwrap();
        let refund_spk = vec![0x51];
        let mut serialized = vec![0xe3, 0, 0];
        serialized.extend((refund_spk.len() as u64).to_le_bytes());
        serialized.extend(&refund_spk);
        let holder_state = serde_json::json!({
            "canonicalTokenId": wrapper_state["canonicalTokenId"],
            "owner": "04".repeat(32), "owner_scheme": 0,
            "amount": "10", "mode": "0", "unitPrice": "0",
            "feeTicketId": wrapper_state["feeTicketId"],
            "priceScale": wrapper_state["priceScale"],
            "feePolicy": wrapper_state["feePolicy"],
            "payout_script_hash": blake3::hash(&serialized).to_hex().to_string(),
            "wrapper_spk_hash": hex::encode(blake2b_256(&wrapper_script)),
        });
        let holder_state = holder.decode_constructor(&holder.script_for_state(&holder_state).unwrap()).unwrap();
        let mut remaining = holder_state.clone();
        remaining["amount"] = Value::String("5".into());
        let remaining_script = holder.script_for_state(&remaining).unwrap();
        let spk = |script: &[u8]| hex::encode(
            [vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat()
        );
        let mut tx = RestTransaction {
            inputs: vec![
                RestTxInput { previous_outpoint_amount: Some(50_000_000), ..Default::default() },
                RestTxInput::default(),
                RestTxInput { previous_outpoint_amount: Some(50_000_000), ..Default::default() },
            ],
            outputs: vec![
                RestTxOutput::default(), RestTxOutput::default(),
                RestTxOutput { amount: 50_000_000, script_public_key: spk(&remaining_script),
                    covenant_id: Some(hex::encode(market)), ..Default::default() },
                RestTxOutput { amount: 50_000_000, script_public_key: spk(&wrapper_script),
                    covenant_id: Some(hex::encode(market)), ..Default::default() },
            ],
            ..Default::default()
        };
        let mut witness = Vec::new();
        push(&[9; 64], &mut witness);
        witness.extend([0x52, 0x55, 0x52, 0x4f]);
        push(&[1; 4], &mut witness);
        push(&holder.script_for_state(&holder_state).unwrap(), &mut witness);
        let projected = fee_market_unwrap_outputs(&tx, 0, &witness, &holder_state, 2,
            &wrapper_state, &market, wrapper_version).unwrap();
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[0].0, 3);
        assert_eq!(projected[1].0, 2);
        assert_eq!(projected[1].1["amount"], "5");
        tx.outputs[2].script_public_key = spk(&wrapper_script);
        assert!(fee_market_unwrap_outputs(&tx, 0, &witness, &holder_state, 2,
            &wrapper_state, &market, wrapper_version).is_err());
        tx.outputs[2].script_public_key = spk(&remaining_script);

        tx.outputs[1] = RestTxOutput { amount: 50_000_000,
            script_public_key: hex::encode(&refund_spk), ..Default::default() };
        tx.outputs.remove(2);
        let mut full = Vec::new();
        push(&[9; 64], &mut full);
        full.extend([0x52, 0x5a, 0x4f, 0x51]);
        push(&[1; 4], &mut full);
        push(&holder.script_for_state(&holder_state).unwrap(), &mut full);
        let projected = fee_market_unwrap_outputs(&tx, 0, &full, &holder_state, 2,
            &wrapper_state, &market, wrapper_version).unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].0, 2);
        }
    }

    #[test]
    fn fee_market_create_ask_and_buy_project_only_exact_successors() {
        let holder = holder_decoder();
        let ask = ask_decoder();
        let receipt = receipt_decoder();
        let market = [3; 32];
        let holder_state = serde_json::json!({
            "canonicalTokenId": "01".repeat(32), "owner": "04".repeat(32),
            "owner_scheme": 0, "amount": "10", "mode": "0", "unitPrice": "0",
            "feeTicketId": "02".repeat(32), "priceScale": "1",
            "feePolicy": hex::encode(pinned_policy()),
            "payout_script_hash": "05".repeat(32), "wrapper_spk_hash": "06".repeat(32),
        });
        let holder_script = holder.script_for_state(&holder_state).unwrap();
        let current = holder.decode_constructor(&holder_script).unwrap();
        let mut ask_state = current.clone();
        ask_state["amount"] = Value::String("5".into());
        ask_state["mode"] = Value::String("2".into());
        ask_state["unitPrice"] = Value::String("100000000".into());
        ask_state["payout_script_hash"] = Value::String("07".repeat(32));
        let ask_script = ask.script_for_state(&ask_state).unwrap();
        let mut change_state = current.clone();
        change_state["amount"] = Value::String("5".into());
        let change_script = holder.script_for_state(&change_state).unwrap();
        let spk = |script: &[u8]| {
            hex::encode([vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat())
        };
        let mut tx = RestTransaction {
            inputs: vec![RestTxInput {
                previous_outpoint_amount: Some(50_000_000),
                ..Default::default()
            }],
            outputs: vec![
                RestTxOutput {
                    amount: 50_000_000,
                    script_public_key: spk(&ask_script),
                    covenant_id: Some(hex::encode(market)),
                    ..Default::default()
                },
                RestTxOutput {
                    amount: 50_000_000,
                    script_public_key: spk(&change_script),
                    covenant_id: Some(hex::encode(market)),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut create = Vec::new();
        push(&[9; 64], &mut create);
        push(&5i64.to_le_bytes(), &mut create);
        push(&100_000_000i64.to_le_bytes(), &mut create);
        push(&[7; 32], &mut create);
        create.extend([0x00, 0x51]);
        push(&ask.prefix, &mut create);
        push(&ask.suffix, &mut create);
        push(&[1; 4], &mut create);
        push(&holder_script, &mut create);
        let created = fee_market_create_ask_outputs(&tx, 0, &create, &current, &market).unwrap();
        assert_eq!(
            created.iter().map(|(vout, _)| *vout).collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert_eq!(created[0].1["amount"], "5");
        assert_eq!(created[1].1["amount"], "5");
        tx.outputs[0].script_public_key = spk(&holder_script);
        assert!(fee_market_create_ask_outputs(&tx, 0, &create, &current, &market).is_err());

        let mut cancelled_state = created[0].1.clone();
        cancelled_state["mode"] = Value::String("0".into());
        cancelled_state["unitPrice"] = Value::String("0".into());
        let cancelled_script = holder.script_for_state(&cancelled_state).unwrap();
        let mut cancel_tx = RestTransaction {
            inputs: vec![RestTxInput { previous_outpoint_amount: Some(50_000_000), ..Default::default() }],
            outputs: vec![RestTxOutput { amount: 50_000_000,
                script_public_key: spk(&cancelled_script),
                covenant_id: Some(hex::encode(market)), ..Default::default() }],
            ..Default::default()
        };
        let mut cancel = Vec::new();
        push(&[9; 64], &mut cancel);
        cancel.push(0x00);
        push(&holder.prefix, &mut cancel);
        push(&holder.suffix, &mut cancel);
        push(&[1; 4], &mut cancel);
        push(&ask_script, &mut cancel);
        let (_, cancelled) = fee_market_cancel_ask_output(&cancel_tx, 0,
            &cancel, &created[0].1, &market).unwrap();
        assert_eq!(cancelled["amount"], "5");
        assert_eq!(cancelled["mode"], "0");
        cancel_tx.outputs[0].amount -= 1;
        assert!(fee_market_cancel_ask_output(&cancel_tx, 0,
            &cancel, &created[0].1, &market).is_err());

        let mut buyer_state = created[0].1.clone();
        buyer_state["owner"] = Value::String("08".repeat(32));
        buyer_state["mode"] = Value::String("0".into());
        buyer_state["unitPrice"] = Value::String("0".into());
        buyer_state["payout_script_hash"] = Value::String("09".repeat(32));
        let buyer_script = holder.script_for_state(&buyer_state).unwrap();
        let mut trade = RestTransaction {
            inputs: vec![RestTxInput {
                previous_outpoint_amount: Some(50_000_000),
                ..Default::default()
            }],
            outputs: vec![
                RestTxOutput {
                    amount: 50_000_000,
                    script_public_key: spk(&buyer_script),
                    covenant_id: Some(hex::encode(market)),
                    ..Default::default()
                },
                RestTxOutput::default(),
                RestTxOutput::default(),
            ],
            ..Default::default()
        };
        let mut buy = Vec::new();
        push(&[8; 32], &mut buy);
        push(&[0], &mut buy);
        push(&[9; 32], &mut buy);
        buy.push(0x51);
        let mut legs = Vec::new();
        for value in [5i64, 0, 0, 1] {
            legs.extend(value.to_le_bytes());
        }
        push(&legs, &mut buy);
        push(&[0; 16], &mut buy);
        buy.extend([0x4f, 0x52, 0x4f]);
        push(&receipt.prefix, &mut buy);
        push(&receipt.suffix, &mut buy);
        push(&holder.prefix, &mut buy);
        push(&holder.suffix, &mut buy);
        push(&[1; 4], &mut buy);
        push(&ask_script, &mut buy);
        let bought = fee_market_buy_ask_outputs(&trade, 0, &buy, &created[0].1, &market).unwrap();
        assert_eq!(bought.len(), 1);
        assert_eq!(bought[0].1["amount"], "5");
        trade.outputs[0].covenant_id = Some(hex::encode([4; 32]));
        assert!(fee_market_buy_ask_outputs(&trade, 0, &buy, &created[0].1, &market).is_err());

        let mut partial_source = created[0].1.clone();
        partial_source["amount"] = Value::String("10".into());
        let partial_source_script = ask.script_for_state(&partial_source).unwrap();
        let mut remaining = partial_source.clone();
        remaining["amount"] = Value::String("5".into());
        let remaining_script = ask.script_for_state(&remaining).unwrap();
        trade.outputs[0].covenant_id = Some(hex::encode(market));
        trade.outputs[1] = RestTxOutput { amount: 50_000_000,
            script_public_key: spk(&remaining_script),
            covenant_id: Some(hex::encode(market)), ..Default::default() };
        let mut partial_buy = Vec::new();
        push(&[8; 32], &mut partial_buy);
        push(&[0], &mut partial_buy);
        push(&[9; 32], &mut partial_buy);
        partial_buy.push(0x51);
        let mut partial_leg = Vec::new();
        for value in [5i64, 0, 1, 2] { partial_leg.extend(value.to_le_bytes()); }
        push(&partial_leg, &mut partial_buy);
        push(&[0; 16], &mut partial_buy);
        partial_buy.extend([0x4f, 0x53, 0x4f]);
        push(&receipt.prefix, &mut partial_buy);
        push(&receipt.suffix, &mut partial_buy);
        push(&holder.prefix, &mut partial_buy);
        push(&holder.suffix, &mut partial_buy);
        push(&[1; 4], &mut partial_buy);
        push(&partial_source_script, &mut partial_buy);
        let projected = fee_market_buy_ask_outputs(&trade, 0, &partial_buy,
            &partial_source, &market).unwrap();
        assert_eq!(projected.iter().map(|(vout, _)| *vout).collect::<Vec<_>>(), vec![0, 1]);
        assert_eq!(projected[1].1["amount"], "5");
        trade.outputs[1].amount -= 1;
        assert!(fee_market_buy_ask_outputs(&trade, 0, &partial_buy,
            &partial_source, &market).is_err());
    }

    fn fee_test_witness(items: &[ScriptItem]) -> Vec<u8> {
        let mut witness = Vec::new();
        for item in items {
            match item {
                ScriptItem::Data(bytes) => push(bytes, &mut witness),
                ScriptItem::Int(-1) => witness.push(0x4f),
                ScriptItem::Int(0) => witness.push(0x00),
                ScriptItem::Int(value @ 1..=16) => witness.push(0x50 + *value as u8),
                _ => panic!("unsupported test integer"),
            }
        }
        witness
    }

    #[test]
    fn fee_market_live_zero_fee_buy_projects_authenticated_holder() {
        // Accepted TN10 purchase that stalled both ingestion workers on 2026-11-23.
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-zero-buy.json"
        )).unwrap();
        assert!(tx.is_accepted);
        let witness = hex::decode(&tx.inputs[0].signature_script).unwrap();
        let items = script_items(&witness);
        let ScriptItem::Data(reveal) = items.last().unwrap() else { panic!("missing reveal") };
        let source = ask_decoder().decode_constructor(reveal).unwrap();
        let market = hex::decode(tx.outputs[0].canonical_covenant_id().unwrap()).unwrap();
        let projected = fee_market_buy_asks_outputs(
            &tx, 0, &witness, &[(0, source.clone())], &market,
        ).unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].0, 0);
        assert_eq!(projected[0].1["amount"], "2000000000");
        assert_eq!(projected[0].1["mode"], "0");
        let ScriptItem::Data(buyer) = &items[0] else { panic!("missing buyer") };
        assert_eq!(projected[0].1["owner"], hex::encode(buyer));
        assert!(grouped_receipt_output_state(
            &tx, &witness, "buyAsks", &source, &market, &[0],
        ).unwrap().is_none());

        // Missing receipts cannot hide fees, and paid trades still need pinned templates.
        for (index, value) in [
            (5, ScriptItem::Data([vec![1], vec![0; 15]].concat())),
            (7, ScriptItem::Int(2)),
            (9, ScriptItem::Data(vec![0])),
            (12, ScriptItem::Data(vec![1])),
        ] {
            let mut invalid = items.clone();
            invalid[index] = value;
            assert!(fee_market_buy_asks_outputs(
                &tx, 0, &fee_test_witness(&invalid), &[(0, source.clone())], &market,
            ).is_err());
        }

        let mut wrong = tx.clone();
        wrong.outputs[0].script_public_key = "aa20".to_owned() + &"00".repeat(32) + "87";
        assert!(fee_market_buy_asks_outputs(&wrong, 0, &witness, &[(0, source.clone())], &market).is_err());
        let mut wrong = tx.clone();
        wrong.outputs[0].covenant.as_mut().unwrap().authorizing_input = Some(1);
        assert!(fee_market_buy_asks_outputs(&wrong, 0, &witness, &[(0, source)], &market).is_err());
    }

    #[test]
    fn fee_market_two_ask_buy_requires_each_source_and_lineage() {
        let holder = holder_decoder();
        let ask = ask_decoder();
        let receipt = receipt_decoder();
        let market = [3; 32];
        let source = serde_json::json!({
            "canonicalTokenId": "01".repeat(32), "owner": "04".repeat(32),
            "owner_scheme": 0, "amount": "5", "mode": "2", "unitPrice": "100000000",
            "feeTicketId": "02".repeat(32), "priceScale": "1",
            "feePolicy": hex::encode(pinned_policy()),
            "payout_script_hash": "07".repeat(32), "wrapper_spk_hash": "06".repeat(32),
        });
        let first_script = ask.script_for_state(&source).unwrap();
        let first = ask.decode_constructor(&first_script).unwrap();
        let mut second = first.clone();
        second["owner"] = Value::String("0a".repeat(32));
        second["payout_script_hash"] = Value::String("0b".repeat(32));
        let second_script = ask.script_for_state(&second).unwrap();
        let second = ask.decode_constructor(&second_script).unwrap();
        let mut buyer_state = first.clone();
        buyer_state["owner"] = Value::String("08".repeat(32));
        buyer_state["mode"] = Value::String("0".into());
        buyer_state["unitPrice"] = Value::String("0".into());
        buyer_state["payout_script_hash"] = Value::String("09".repeat(32));
        let buyer_script = holder.script_for_state(&buyer_state).unwrap();
        let spk = |script: &[u8]| {
            hex::encode([vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat())
        };
        let output = |authorizer| RestTxOutput {
            amount: 50_000_000,
            script_public_key: spk(&buyer_script),
            covenant: Some(tn12_indexer_core::RestCovenantBinding {
                covenant_id: Some(hex::encode(market)),
                authorizing_input: Some(authorizer),
            }),
            ..Default::default()
        };
        let mut tx = RestTransaction {
            inputs: vec![RestTxInput::default(), RestTxInput::default()],
            outputs: vec![
                output(0),
                RestTxOutput::default(),
                output(1),
                RestTxOutput::default(),
            ],
            ..Default::default()
        };
        let mut witness = Vec::new();
        push(&[8; 32], &mut witness);
        push(&[0], &mut witness);
        push(&[9; 32], &mut witness);
        witness.push(0x52);
        let mut legs = Vec::new();
        for value in [5i64, 0, 0, 1, 5, 2, 0, 3] {
            legs.extend(value.to_le_bytes());
        }
        push(&legs, &mut witness);
        push(&[0; 32], &mut witness);
        witness.extend([0x4f, 0x54, 0x4f]);
        push(&receipt.prefix, &mut witness);
        push(&receipt.suffix, &mut witness);
        push(&holder.prefix, &mut witness);
        push(&holder.suffix, &mut witness);
        push(&[1; 4], &mut witness);
        push(&first_script, &mut witness);
        let sources = vec![(0, first.clone()), (1, second.clone())];
        let outputs = fee_market_buy_asks_outputs(&tx, 0, &witness, &sources, &market).unwrap();
        assert_eq!(
            outputs.iter().map(|(vout, _)| *vout).collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(outputs[0].1["amount"], "5");
        assert!(fee_market_buy_asks_outputs(&tx, 0, &witness, &sources[..1], &market).is_err());
        tx.outputs[2].covenant.as_mut().unwrap().authorizing_input = Some(0);
        assert!(fee_market_buy_asks_outputs(&tx, 0, &witness, &sources, &market).is_err());
        tx.outputs[2].covenant.as_mut().unwrap().authorizing_input = Some(1);
        let mut wrong_source = sources.clone();
        wrong_source[1].1["feePolicy"] = Value::String("00".repeat(361));
        assert!(fee_market_buy_asks_outputs(&tx, 0, &witness, &wrong_source, &market).is_err());
    }

    #[test]
    fn fee_market_three_bid_sale_projects_buyer_holders() {
        let market = [3; 32];
        let holder = holder_decoder();
        let receipt = receipt_decoder();
        let seller = serde_json::json!({
            "canonicalTokenId": "01".repeat(32), "owner": "04".repeat(32),
            "owner_scheme": 0, "amount": "15", "mode": "0", "unitPrice": "0",
            "feeTicketId": "02".repeat(32), "priceScale": "1",
            "feePolicy": hex::encode(pinned_policy()),
            "payout_script_hash": "07".repeat(32), "wrapper_spk_hash": "06".repeat(32),
        });
        let mut bids = Vec::new();
        let mut outputs = Vec::new();
        let spk = |script: &[u8]| {
            hex::encode([vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat())
        };
        for slot in 0..3usize {
            let mut bid = seller.clone();
            bid["owner"] = Value::String(format!("{:02x}", slot + 8).repeat(32));
            bid["mode"] = Value::String("3".into());
            bid["amount"] = Value::String("5".into());
            bid["unitPrice"] = Value::String("100000000".into());
            bid["payout_script_hash"] = Value::String(format!("{:02x}", slot + 12).repeat(32));
            let mut buyer = bid.clone();
            buyer["mode"] = Value::String("0".into());
            buyer["unitPrice"] = Value::String("0".into());
            let buyer_script = holder.script_for_state(&buyer).unwrap();
            outputs.push(RestTxOutput {
                amount: 200_000_000, script_public_key: spk(&buyer_script),
                covenant: Some(tn12_indexer_core::RestCovenantBinding {
                    covenant_id: Some(hex::encode(market)), authorizing_input: Some(0),
                }), ..Default::default()
            });
            outputs.push(RestTxOutput { amount: 450_000_000, ..Default::default() });
            bids.push((slot + 1, bid));
        }
        outputs.push(RestTxOutput { amount: 150_000_000, ..Default::default() });
        outputs.push(RestTxOutput { amount: 50_000_000, ..Default::default() });
        let tx = RestTransaction {
            inputs: [vec![RestTxInput { previous_outpoint_amount: Some(50_000_000),
                ..Default::default() }],
                vec![RestTxInput { previous_outpoint_amount: Some(700_000_000),
                    ..Default::default() }; 3]].concat(),
            outputs, ..Default::default()
        };
        let mut witness = Vec::new();
        witness.push(0x00); // Owner witness is supplied by the signed transaction.
        witness.push(0x53); // Three fills.
        let mut legs = Vec::new();
        for slot in 0..3i64 {
            for value in [5, slot * 2, 0, slot * 2 + 1] {
                legs.extend(value.to_le_bytes());
            }
        }
        push(&legs, &mut witness);
        push(&[0; 48], &mut witness);
        witness.extend([0x4f, 0x56, 0x4f, 0x57, 0x4f]);
        push(&receipt.prefix, &mut witness);
        push(&receipt.suffix, &mut witness);
        push(&[1; 4], &mut witness);
        let projected = fee_market_sell_into_bids_outputs(
            &tx, 0, &witness, &seller, &bids, &market,
        ).unwrap();
        assert_eq!(projected.iter().map(|(vout, _)| *vout).collect::<Vec<_>>(), vec![0, 2, 4]);
        assert!(projected.iter().all(|(_, state)| state["mode"] == "0" && state["amount"] == "5"));
        let mut zero_fee = script_items(&witness);
        zero_fee[5] = ScriptItem::Int(-1);
        zero_fee[9] = ScriptItem::Int(0);
        zero_fee[10] = ScriptItem::Int(0);
        let zero_fee_projected = fee_market_sell_into_bids_outputs(
            &tx, 0, &fee_test_witness(&zero_fee), &seller, &bids, &market,
        ).unwrap();
        assert_eq!(zero_fee_projected, projected);
        zero_fee[3] = ScriptItem::Data(vec![1; 48]);
        assert!(fee_market_sell_into_bids_outputs(
            &tx, 0, &fee_test_witness(&zero_fee), &seller, &bids, &market,
        ).is_err());
        let mut wrong = tx.clone();
        wrong.outputs[2].covenant.as_mut().unwrap().authorizing_input = Some(2);
        assert!(fee_market_sell_into_bids_outputs(&wrong, 0, &witness, &seller, &bids, &market).is_err());
        let mut wrong_bid = bids.clone();
        wrong_bid[1].1["feePolicy"] = Value::String("00".into());
        assert!(fee_market_sell_into_bids_outputs(&tx, 0, &witness, &seller, &wrong_bid, &market).is_err());
    }

    #[test]
    fn fee_market_create_bid_projects_exact_locked_value_and_root() {
        let root = root_decoder();
        let bid = bid_decoder();
        let market = [3; 32];
        let root_state = serde_json::json!({
            "canonicalTokenId": "01".repeat(32), "owner": "04".repeat(32),
            "owner_scheme": 0, "amount": "0", "mode": "1", "unitPrice": "0",
            "feeTicketId": "02".repeat(32), "priceScale": "1",
            "feePolicy": hex::encode(pinned_policy()),
            "payout_script_hash": "05".repeat(32), "wrapper_spk_hash": "06".repeat(32),
        });
        let root_script = root.script_for_state(&root_state).unwrap();
        let current = root.decode_constructor(&root_script).unwrap();
        let mut bid_state = current.clone();
        bid_state["owner"] = Value::String("08".repeat(32));
        bid_state["amount"] = Value::String("5".into());
        bid_state["mode"] = Value::String("3".into());
        bid_state["unitPrice"] = Value::String("100000000".into());
        bid_state["payout_script_hash"] = Value::String("09".repeat(32));
        let bid_script = bid.script_for_state(&bid_state).unwrap();
        let spk = |script: &[u8]| {
            hex::encode([vec![0xaa, 0x20], blake2b_256(script).to_vec(), vec![0x87]].concat())
        };
        let mut tx = RestTransaction {
            inputs: vec![RestTxInput { previous_outpoint_amount: Some(50_000_000), ..Default::default() }],
            outputs: vec![
                RestTxOutput { amount: 700_000_000, script_public_key: spk(&bid_script),
                    covenant_id: Some(hex::encode(market)), ..Default::default() },
                RestTxOutput { amount: 50_000_000, script_public_key: spk(&root_script),
                    covenant_id: Some(hex::encode(market)), ..Default::default() },
            ], ..Default::default()
        };
        let mut witness = Vec::new();
        push(&[8; 32], &mut witness);
        push(&[0], &mut witness);
        push(&[9; 32], &mut witness);
        push(&5i64.to_le_bytes(), &mut witness);
        push(&100_000_000i64.to_le_bytes(), &mut witness);
        witness.extend([0x00, 0x51]);
        push(&bid.prefix, &mut witness);
        push(&bid.suffix, &mut witness);
        push(&[1; 4], &mut witness);
        push(&root_script, &mut witness);
        let outputs = fee_market_create_bid_outputs(&tx, 0, &witness, &current, &market).unwrap();
        assert_eq!(outputs[0].1["amount"], "5");
        assert_eq!(outputs[0].1["mode"], "3");
        assert_eq!(outputs[1].1["mode"], "1");
        tx.outputs[0].amount -= 1;
        assert!(fee_market_create_bid_outputs(&tx, 0, &witness, &current, &market).is_err());
    }

    #[test]
    fn signed_cross_projects_final_and_partial_successors() {
        for raw in [
            include_str!("../fixtures/kcc20-fee-escrow-v1/signed-cross-2-2.json"),
            include_str!("../fixtures/kcc20-fee-escrow-v1/signed-cross-3-2.json"),
            include_str!("../fixtures/kcc20-fee-escrow-v1/signed-cross-2-3.json"),
        ] {
            let fixture: Value = serde_json::from_str(raw).unwrap();
            let tx: RestTransaction = serde_json::from_value(fixture["transaction"].clone()).unwrap();
            let market = hex::decode(fixture["marketId"].as_str().unwrap()).unwrap();
            let sources = vec![(0, fixture["ask"].clone()), (1, fixture["bid"].clone())];
            let witness = hex::decode(&tx.inputs[0].signature_script).unwrap();
            let outputs = fee_market_cross_outputs(&tx, &witness, &sources, &market).unwrap();
            assert_eq!(outputs[0].0, 0);
            assert_eq!(outputs[0].1["owner"], fixture["bid"]["owner"]);
            assert_eq!(outputs[0].1["amount"], "2");
            assert_eq!(outputs[0].1["mode"], "0");
            assert_eq!(outputs[0].1["ownerScheme"], fixture["bid"]["owner_scheme"]);
            let ask_remaining = fixture["ask"]["amount"] == "3";
            let bid_remaining = fixture["bid"]["amount"] == "3";
            assert_eq!(outputs.len(), 1 + usize::from(ask_remaining) + usize::from(bid_remaining));
            if outputs.len() == 2 {
                assert_eq!(outputs[1].1["amount"], "1");
                assert_eq!(outputs[1].1["mode"], if ask_remaining { "2" } else { "3" });
            }
            assert!(grouped_receipt_output_state(&tx, &witness, "crossWithBid", &sources[0].1, &market, &[0, 1]).unwrap().is_some());
            let mut wrong = tx.clone();
            wrong.outputs[0].script_public_key = "51".into();
            assert!(fee_market_cross_outputs(&wrong, &witness, &sources, &market).is_err());
            let mut wrong_principal = tx.clone();
            wrong_principal.outputs[if bid_remaining || ask_remaining { 1 } else { 0 }].amount -= 1;
            assert!(fee_market_cross_outputs(&wrong_principal, &witness, &sources, &market).is_err());
            assert!(fee_market_cross_outputs(&tx, &witness, &sources[..1], &market).is_err());
            let items = script_items(args_prefix_before_reveal(&witness));
            for slot in [6, 8] {
                let index = usize::try_from(item_int(&items, slot).unwrap()).unwrap();
                let mut underpaid = tx.clone(); underpaid.outputs[index].amount -= 1;
                assert!(fee_market_cross_outputs(&underpaid, &witness, &sources, &market).is_err());
                let mut diverted = tx.clone(); diverted.outputs[index].script_public_key = "51".into();
                assert!(fee_market_cross_outputs(&diverted, &witness, &sources, &market).is_err());
            }
            for (index, _) in &outputs {
                let mut missing = tx.clone();
                missing.outputs[*index as usize].covenant = None;
                missing.outputs[*index as usize].covenant_id = None;
                assert!(fee_market_cross_outputs(&missing, &witness, &sources, &market).is_err());
                let mut no_authorizer = tx.clone();
                no_authorizer.outputs[*index as usize].covenant.as_mut().unwrap().authorizing_input = None;
                assert!(fee_market_cross_outputs(&no_authorizer, &witness, &sources, &market).is_err());
                let mut wrong_market = tx.clone();
                wrong_market.outputs[*index as usize].covenant_id = Some("ff".repeat(32));
                assert!(fee_market_cross_outputs(&wrong_market, &witness, &sources, &market).is_err());
                let mut wrong = tx.clone();
                wrong.outputs[*index as usize].covenant.as_mut().unwrap().authorizing_input = Some(7);
                assert!(fee_market_cross_outputs(&wrong, &witness, &sources, &market).is_err());
            }
            let mut missing_principal = tx.clone(); missing_principal.inputs[0].previous_outpoint_amount = None;
            assert!(fee_market_cross_outputs(&missing_principal, &witness, &sources, &market).is_err());
        }
    }

    #[test]
    fn funded_matcher_cross_projects_holder_partial_ask_and_receipt() {
        // Accepted TN10 transaction, with parent amounts/scripts hydrated from
        // their accepted source transactions, as persistence does at runtime.
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-escrow-v1/tn10-matcher-cross.json"
        )).unwrap();
        assert!(tx.is_accepted);
        let market = hex::decode("0dc2ae4759c105ae4478e3fdb5642d01daca99d63b096b26f71708cc114e47be").unwrap();
        let sources = [KnownTemplate::Kcc20FeeAskV1, KnownTemplate::Kcc20FeeBidV1]
            .into_iter().enumerate().map(|(index, role)| {
                let witness = hex::decode(&tx.inputs[index].signature_script).unwrap();
                let items = script_items(&witness);
                let Some(ScriptItem::Data(reveal)) = items.last() else { panic!("missing reveal") };
                (index, decoder(role).decode_constructor(reveal).unwrap())
            }).collect::<Vec<_>>();
        let witness = hex::decode(&tx.inputs[0].signature_script).unwrap();
        let outputs = fee_market_cross_outputs(&tx, &witness, &sources, &market).unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].0, 0);
        assert_eq!(outputs[0].1["mode"], "0");
        assert_eq!(outputs[0].1["amount"], "1");
        assert_eq!(outputs[0].1["owner"], sources[1].1["owner"]);
        assert_eq!(outputs[1].0, 1);
        assert_eq!(outputs[1].1["mode"], "2");
        assert_eq!(outputs[1].1["amount"], "1");
        assert_eq!(outputs[1].1["owner"], sources[0].1["owner"]);
        let (receipt_index, receipt) = grouped_receipt_output_state(
            &tx, &witness, "crossWithBid", &sources[0].1, &market, &[0, 1]
        ).unwrap().unwrap();
        assert_eq!(receipt_index, 3);
        assert_eq!(receipt["protocol_amount"], "50000000");
        assert_eq!(receipt["creator_amount"], "50000000");
    }

    #[test]
    fn signed_recipient_claims_and_rotation_preserve_exact_continuations() {
        for raw in [
            include_str!("../fixtures/kcc20-fee-escrow-v1/recipient-creator-1-true.json"),
            include_str!("../fixtures/kcc20-fee-escrow-v1/recipient-protocol-5-true.json"),
            include_str!("../fixtures/kcc20-fee-escrow-v1/recipient-rotation-back.json"),
        ] {
            let fixture: Value = serde_json::from_str(raw).unwrap();
            let tx: RestTransaction = serde_json::from_value(fixture["transaction"].clone()).unwrap();
            let index = fixture["recipientInputIndex"].as_u64().unwrap() as usize;
            let id = hex::decode(fixture["recipientId"].as_str().unwrap()).unwrap();
            let witness = hex::decode(&tx.inputs[index].signature_script).unwrap();
            let items = script_items(&witness);
            let Some(ScriptItem::Data(reveal)) = items.last() else { panic!("missing recipient reveal") };
            let current = recipient_decoder().decode_constructor(reveal).unwrap();
            let (out, next) = fee_recipient_output_state(&tx,index,&witness,&current,&id).unwrap();
            assert_eq!(next["roleName"], "recipient");
            assert_eq!(next["owner"],current["owner"]);
            assert_ne!(next["action_hash"],current["action_hash"]);
            for mutation in 0..5 {
                let mut bad = tx.clone();
                match mutation {
                    0 => bad.outputs[out as usize].amount -= 1,
                    1 => bad.outputs[out as usize].script_public_key = "51".into(),
                    2 => bad.outputs[out as usize].covenant.as_mut().unwrap().authorizing_input = Some(0),
                    3 => bad.outputs[out as usize].covenant_id = Some("ff".repeat(32)),
                    _ => bad.inputs[index].previous_outpoint_amount = None,
                }
                assert!(fee_recipient_output_state(&bad,index,&witness,&current,&id).is_err(), "mutation {mutation}");
            }
        }
    }

    #[test]
    fn funded_hash_authority_rotation_projects_accepted_successor() {
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-escrow-v1/tn10-rotate-schnorr-hash.json"
        )).unwrap();
        let witness = hex::decode(&tx.inputs[0].signature_script).unwrap();
        let items = script_items(&witness);
        let Some(ScriptItem::Data(reveal)) = items.last() else { panic!("missing reveal") };
        let current = receipt_decoder().decode_constructor(reveal).unwrap();
        assert_eq!(current["owner_scheme"], 0);
        let (index, next) = fee_account_output_state(&tx, 0, &witness, "authorize", &current)
            .unwrap().unwrap();
        assert_eq!(index, 0);
        assert_eq!(next["owner_scheme"], 1);
        assert_eq!(next["owner"], blake3::hash(&hex::decode(current["owner"].as_str().unwrap()).unwrap()).to_hex().to_string());
        assert_eq!(next["market"], current["market"]);
        assert_eq!(next["policy"], current["policy"]);
        let mut wrong_value = tx.clone();
        // The REST fixture omits parent amounts. Persistence hydrates this
        // account's 50,000,000-sompi parent (d4f2665b..:1) before projection.
        wrong_value.inputs[0].previous_outpoint_amount = Some(50_000_000);
        wrong_value.outputs[0].amount -= 1;
        assert!(fee_account_output_state(&wrong_value, 0, &witness, "authorize", &current).is_err());
        let mut wrong_script = tx.clone();
        wrong_script.outputs[0].script_public_key = "51".to_owned();
        assert!(fee_account_output_state(&wrong_script, 0, &witness, "authorize", &current).is_err());
    }

    #[test]
    fn account_byte_witness_accepts_stack_equivalent_small_pushes_only() {
        let tx: RestTransaction = serde_json::from_str(include_str!(
            "../fixtures/kcc20-fee-escrow-v1/tn10-rotate-schnorr-hash.json"
        )).unwrap();
        let witness = hex::decode(&tx.inputs[0].signature_script).unwrap();
        let mut items = script_items(args_prefix_before_reveal(&witness));
        let decoder = receipt_decoder();
        let owner_index = 1 + decoder.fields.iter().position(|f| f.name == "owner_scheme").unwrap();
        for value in 1..=16u8 {
            items[owner_index] = ScriptItem::Int(i128::from(value));
            let minimal = witness_state(&items, 1, decoder).unwrap();
            items[owner_index] = ScriptItem::Data(vec![value]);
            assert_eq!(minimal, witness_state(&items, 1, decoder).unwrap());
        }
        items[owner_index] = ScriptItem::Int(-1);
        assert_eq!(witness_state(&items, 1, decoder).unwrap()["owner_scheme"], 129);
        items[owner_index] = ScriptItem::Data(vec![0]);
        assert_eq!(witness_state(&items, 1, decoder).unwrap()["owner_scheme"], 0);
        for invalid in [ScriptItem::Int(0), ScriptItem::Int(17), ScriptItem::Data(vec![]), ScriptItem::Data(vec![1, 0])] {
            items[owner_index] = invalid;
            assert!(witness_state(&items, 1, decoder).is_err());
        }
    }

    #[test]
    fn account_binding_and_authorization_project_only_exact_successors() {
        let receipt = receipt_decoder();
        let mut account = receipt.placeholder.clone();
        set_field(&mut account, receipt, "role", &1i64.to_le_bytes());
        for field in ["market", "policy", "protocol_account", "creator_account"] {
            set_field(&mut account, receipt, field, &[0; 32]);
        }
        for field in ["protocol_amount", "creator_amount"] {
            set_field(&mut account, receipt, field, &0i64.to_le_bytes());
        }
        set_field(&mut account, receipt, "owner", &[9; 32]);
        set_field(&mut account, receipt, "action_hash", &[0; 32]);
        let current = receipt.decode_constructor(&account).unwrap();
        let mut bound = current.clone();
        bound["market"] = Value::String("02".repeat(32));
        bound["policy"] = Value::String("03".repeat(32));
        let bound_script = receipt.script_for_state(&bound).unwrap();
        let mut tx = RestTransaction {
            inputs: vec![RestTxInput {
                previous_outpoint_amount: Some(50_000_000),
                ..Default::default()
            }],
            outputs: vec![RestTxOutput {
                amount: 50_000_000,
                script_public_key: hex::encode(
                    [
                        vec![0xaa, 0x20],
                        blake2b_256(&bound_script).to_vec(),
                        vec![0x87],
                    ]
                    .concat(),
                ),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut bind = Vec::new();
        push(&[2; 32], &mut bind);
        push(&[3; 32], &mut bind);
        push(&[4; 65], &mut bind);
        bind.push(0x00); // successor 0
        push(&[1; 4], &mut bind);
        push(&account, &mut bind);
        let projected = fee_account_output_state(&tx, 0, &bind, "bindMarket", &current)
            .unwrap()
            .unwrap();
        assert_eq!(projected.1["bindingStatus"], "bound");

        let mut approved = projected.1.clone();
        approved["action_hash"] = Value::String("05".repeat(32));
        let approved_script = receipt.script_for_state(&approved).unwrap();
        tx.outputs[0].script_public_key = hex::encode(
            [
                vec![0xaa, 0x20],
                blake2b_256(&approved_script).to_vec(),
                vec![0x87],
            ]
            .concat(),
        );
        let mut authorize = vec![0x51]; // action 1
        for field in &receipt.fields {
            let value = &approved[&field.name];
            let bytes = match field.kind.as_str() {
                "fixed_bytes" => hex::decode(value.as_str().unwrap()).unwrap(),
                "int" => value
                    .as_str()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap()
                    .to_le_bytes()
                    .to_vec(),
                "byte" => vec![value.as_u64().unwrap() as u8],
                _ => unreachable!(),
            };
            push(&bytes, &mut authorize);
        }
        authorize.push(0x00); // successor output 0
        push(&[4; 65], &mut authorize); // authority witness
        authorize.extend([0x4f, 0x4f]); // no guard input or output
        push(&[1; 4], &mut authorize); // remaining arguments are not read
        push(&account, &mut authorize);
        let approved_state =
            fee_account_output_state(&tx, 0, &authorize, "authorize", &projected.1)
                .unwrap()
                .unwrap();
        assert_eq!(approved_state.1["action_hash"], "05".repeat(32));
        tx.outputs[0].amount -= 1;
        assert!(fee_account_output_state(&tx, 0, &authorize, "authorize", &projected.1).is_err());
    }

    #[test]
    fn claim_projection_preserves_the_other_share_and_matches_builder_commitment() {
        let receipt = receipt_decoder();
        let current = receipt.decode_constructor(&receipt.placeholder).unwrap();
        let mut remaining = current.clone();
        remaining["protocol_amount"] = Value::String("0".into());
        remaining["creator_amount"] = Value::String("100000000".into());
        remaining["action_hash"] = Value::String("00".repeat(32));
        let script = receipt.script_for_state(&remaining).unwrap();
        let mut witness = vec![0x00, 0x52, 0x00, 0x51];
        push(&[0, 0, 0x51], &mut witness);
        witness.push(0x52);
        push(&[1; 4], &mut witness);
        push(&receipt.placeholder, &mut witness);
        let input = |id: u8, index: u32| RestTxInput {
            previous_outpoint_hash: hex::encode([id; 32]),
            previous_outpoint_index: index.to_string(),
            previous_outpoint_amount: Some(100_000_000),
            ..Default::default()
        };
        let mut tx = RestTransaction {
            inputs: vec![input(7, 0), input(8, 1), input(9, 0)],
            outputs: vec![
                RestTxOutput::default(),
                RestTxOutput {
                    amount: 100_000_000,
                    script_public_key: "51".into(),
                    ..Default::default()
                },
                RestTxOutput {
                    amount: 100_000_000,
                    script_public_key: hex::encode(
                        [vec![0xaa, 0x20], blake2b_256(&script).to_vec(), vec![0x87]].concat(),
                    ),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let selected = vec![(0, current.clone()), (1, current)];
        let claim = fee_claim_output_state(&tx, &witness, &[2; 32], &selected).unwrap();
        assert_eq!(claim.claimed_sompi, 100_000_000);
        assert!(!claim.creator_side);
        assert_eq!(claim.account_output_index, 0);
        assert_eq!(
            claim.account_commitment,
            "ce114ba9fef75b9582155c61cf8fe906ba651cb0b86e3850bd1e8a7a07278312"
        );
        assert_eq!(claim.remainder.unwrap().1["creator_amount"], "100000000");
        tx.outputs[2].amount -= 1;
        assert!(fee_claim_output_state(&tx, &witness, &[2; 32], &selected).is_err());
        let mut overflowing = selected[0].1.clone();
        overflowing["protocol_amount"] = Value::String(i64::MAX.to_string());
        overflowing["creator_amount"] = Value::String("1".into());
        assert!(fee_claim_output_state(&tx, &witness, &[2; 32], &[(0, overflowing)]).is_err());
    }

    #[test]
    fn pinned_fee_artifacts_match_only_their_exact_script_templates() {
        for decoder in bundled_decoders() {
            let mut script = decoder.placeholder.clone();
            assert!(decoder.matches_reveal_script(&script));
            script[0] ^= 1;
            assert!(!decoder.matches_reveal_script(&script));
            assert!(decoder.decode_constructor(&script).is_err());
        }
    }

    #[test]
    fn a_valid_template_with_a_bad_policy_is_not_classified() {
        let decoder = decoder(KnownTemplate::Kcc20FeeAskV1);
        let mut script = decoder.placeholder.clone();
        let offset = script
            .windows(361)
            .position(|window| window == pinned_policy().as_slice())
            .unwrap();
        script[offset] = 2;
        assert!(decoder.exact_template(&script));
        assert!(!decoder.matches_reveal_script(&script));
    }

    #[test]
    fn bootstrap_account_is_classified_but_wrong_role_and_guard_are_rejected() {
        let escrow = decoder(KnownTemplate::Kcc20FeeEscrowV1);
        let mut account = escrow.placeholder.clone();
        set_field(&mut account, &escrow, "role", &1i64.to_le_bytes());
        for field in ["market", "policy", "protocol_account", "creator_account"] {
            set_field(&mut account, &escrow, field, &[0; 32]);
        }
        for field in ["protocol_amount", "creator_amount"] {
            set_field(&mut account, &escrow, field, &0i64.to_le_bytes());
        }
        set_field(&mut account, &escrow, "owner", &[9; 32]);
        assert_eq!(
            escrow.decode_constructor(&account).unwrap()["bindingStatus"],
            "unbound"
        );

        let mut wrong_role = escrow.placeholder.clone();
        set_field(&mut wrong_role, &escrow, "role", &2i64.to_le_bytes());
        assert!(!escrow.matches_reveal_script(&wrong_role));
        let recipient = decoder(KnownTemplate::Kcc20FeeRecipientV1);
        let mut wrong_recipient = recipient.placeholder.clone();
        set_field(
            &mut wrong_recipient,
            &recipient,
            "role",
            &1i64.to_le_bytes(),
        );
        assert!(!recipient.matches_reveal_script(&wrong_recipient));
        let mut wrong_scheme = recipient.placeholder.clone();
        set_field(&mut wrong_scheme, &recipient, "owner_scheme", &[4]);
        assert!(!recipient.matches_reveal_script(&wrong_scheme));

        let mut guard = account.clone();
        set_field(&mut guard, &escrow, "market", &[2; 32]);
        set_field(&mut guard, &escrow, "policy", &[3; 32]);
        set_field(&mut guard, &escrow, "owner_scheme", &[3]);
        assert!(!escrow.matches_reveal_script(&guard));
        set_field(&mut guard, &escrow, "guard_template", &[7; 32]);
        assert!(escrow.matches_reveal_script(&guard));
        set_field(&mut guard, &escrow, "owner_scheme", &[4]);
        assert!(!escrow.matches_reveal_script(&guard));
        set_field(&mut guard, &escrow, "guard_prefix", &1i64.to_le_bytes());
        set_field(&mut guard, &escrow, "guard_suffix", &1i64.to_le_bytes());
        assert!(escrow.matches_reveal_script(&guard));
    }

    #[test]
    fn market_roles_reject_unspendable_amounts_and_prices() {
        for (kind, field, value) in [
            (KnownTemplate::Kcc20FeeHolderV1, "amount", 0i64),
            (KnownTemplate::Kcc20FeeAskV1, "amount", 0),
            (KnownTemplate::Kcc20FeeBidV1, "unitPrice", 0),
            (KnownTemplate::Kcc20FeeRootV1, "unitPrice", 1),
        ] {
            let decoder = decoder(kind);
            let mut script = decoder.placeholder.clone();
            set_field(&mut script, &decoder, field, &value.to_le_bytes());
            assert!(
                !decoder.matches_reveal_script(&script),
                "{} accepted invalid {field}",
                decoder.name()
            );
        }
        let root = decoder(KnownTemplate::Kcc20FeeRootV1);
        let mut zero_owner_root = root.placeholder.clone();
        set_field(&mut zero_owner_root, &root, "owner", &[0; 32]);
        assert!(root.matches_reveal_script(&zero_owner_root));
    }

    #[test]
    fn escrow_entry_tag_comes_from_the_pinned_abi() {
        let decoder = bundled_decoders()
            .into_iter()
            .find(|d| d.template == KnownTemplate::Kcc20FeeEscrowV1)
            .unwrap();
        let tag = decoder
            .entries
            .iter()
            .find(|(_, name)| name == &"claim")
            .unwrap()
            .0;
        let mut sigscript = vec![4];
        sigscript.extend(tag);
        sigscript.extend([1, 0xaa]);
        assert_eq!(decoder.decode_action(&sigscript).as_deref(), Some("claim"));
    }
}
