use serde::{Deserialize, Serialize};

use crate::{compute_covenant_id, AuthOutput};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestTxInput {
    // `transaction_id` / `index` are owner-tx-relative — only the address
    // history endpoint sets them. Per-tx queries and `/virtual-chain` omit
    // them, so we accept synthetic defaults.
    #[serde(default)]
    pub transaction_id: String,
    #[serde(default)]
    pub index: u64,
    #[serde(default)]
    pub previous_outpoint_hash: String,
    #[serde(default, deserialize_with = "stringy_or_int_default")]
    pub previous_outpoint_index: String,
    #[serde(default)]
    pub previous_outpoint_address: Option<String>,
    #[serde(default)]
    pub previous_outpoint_amount: Option<u64>,
    #[serde(default)]
    pub previous_outpoint_script: Option<String>,
    #[serde(default)]
    pub signature_script: String,
    #[serde(default, deserialize_with = "stringy_or_int_default")]
    pub sig_op_count: String,
}

impl RestTxInput {
    /// Source script or address evidence that an input needs covenant lineage.
    /// Kept shared so scalar, bulk and scanner paths cannot disagree.
    pub fn requires_covenant_identity(&self) -> bool {
        self.previous_outpoint_script.as_deref().is_some_and(|s| {
            hex::decode(s.strip_prefix("0000").unwrap_or(s))
                .ok()
                .is_some_and(|bytes| crate::is_p2sh_script_pubkey(&bytes))
        }) || self
            .previous_outpoint_address
            .as_deref()
            .and_then(|a| a.split_once(':'))
            .is_some_and(|(_, p)| p.starts_with('p'))
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RestTxOutput {
    #[serde(default)]
    pub transaction_id: String,
    #[serde(default)]
    pub index: u64,
    pub amount: u64,
    pub script_public_key: String,
    #[serde(default)]
    pub script_public_key_address: Option<String>,
    #[serde(default)]
    pub script_public_key_type: Option<String>,
    #[serde(default, alias = "covenantId")]
    pub covenant_id: Option<String>,
    #[serde(default)]
    pub covenant: Option<RestCovenantBinding>,
}

#[derive(Debug, Deserialize)]
struct RestTxOutputWire {
    #[serde(default)]
    transaction_id: String,
    #[serde(default)]
    index: u64,
    amount: u64,
    script_public_key: String,
    #[serde(default)]
    script_public_key_address: Option<String>,
    #[serde(default)]
    script_public_key_type: Option<String>,
    #[serde(default, alias = "covenantId")]
    covenant_id: Option<String>,
    #[serde(
        default,
        alias = "covenantAuthorizingInput",
        alias = "authorizingInput"
    )]
    covenant_authorizing_input: Option<u16>,
    #[serde(default)]
    covenant: Option<RestCovenantBinding>,
}

impl<'de> Deserialize<'de> for RestTxOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RestTxOutputWire::deserialize(deserializer)?;
        let mut covenant = wire.covenant;
        if wire.covenant_id.is_some() || wire.covenant_authorizing_input.is_some() {
            match covenant.as_mut() {
                Some(binding) => {
                    if binding.covenant_id.is_none() {
                        binding.covenant_id = wire.covenant_id.clone();
                    }
                    if binding.authorizing_input.is_none() {
                        binding.authorizing_input = wire.covenant_authorizing_input;
                    }
                }
                None => {
                    covenant = Some(RestCovenantBinding {
                        covenant_id: wire.covenant_id.clone(),
                        authorizing_input: wire.covenant_authorizing_input,
                    });
                }
            }
        }
        Ok(Self {
            transaction_id: wire.transaction_id,
            index: wire.index,
            amount: wire.amount,
            script_public_key: wire.script_public_key,
            script_public_key_address: wire.script_public_key_address,
            script_public_key_type: wire.script_public_key_type,
            covenant_id: wire.covenant_id,
            covenant,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestCovenantBinding {
    #[serde(default, alias = "covenantId")]
    pub covenant_id: Option<String>,
    #[serde(default, alias = "authorizingInput")]
    pub authorizing_input: Option<u16>,
}

impl RestTxOutput {
    pub fn canonical_covenant_id(&self) -> Option<&str> {
        self.covenant_id
            .as_deref()
            .or_else(|| self.covenant.as_ref()?.covenant_id.as_deref())
    }

    pub fn covenant_authorizing_input(&self) -> Option<u16> {
        self.covenant.as_ref()?.authorizing_input
    }
}

/// Compute the KIP-20 genesis covenant id for one output when the REST surface
/// does not expose the native `covenantId` field.
///
/// Wallet-lab deploys use `populateGenesisCovenants([GenesisCovenantGroup(0,
/// [output_index])])`, so the canonical id is derived from input 0's previous
/// outpoint plus the authorized output. Callers should only use this for known
/// genesis deploy outputs; continuation outputs need the binding exposed by RPC
/// or inferred from the spent covenant input.
pub fn compute_genesis_covenant_id_for_output(
    tx: &RestTransaction,
    output_index: u64,
) -> Option<String> {
    compute_genesis_covenant_id_for_outputs(tx, &[output_index])
}

/// Compute the KIP-20 genesis covenant id for a genesis covenant group.
///
/// Grouped deploys, such as KCC20 minter + premint holder outputs, authorize
/// several outputs from the same input and therefore share one canonical
/// covenant id. The output order must match the order passed to
/// `GenesisCovenantGroup` by the wallet.
pub fn compute_genesis_covenant_id_for_outputs(
    tx: &RestTransaction,
    output_indexes: &[u64],
) -> Option<String> {
    compute_genesis_covenant_id_for_outputs_at_input(tx, 0, output_indexes)
}

/// Compute the KIP-20 genesis covenant id for a genesis group authorized by
/// an explicit transaction input. Snapshot start uses controller input 1 as
/// the token family's immutable genesis outpoint, rather than funding input 0.
pub fn compute_genesis_covenant_id_for_outputs_at_input(
    tx: &RestTransaction,
    authorizing_input: usize,
    output_indexes: &[u64],
) -> Option<String> {
    if tx.version == 0 {
        return None;
    }
    let input = tx.inputs.get(authorizing_input)?;
    let previous_index = input.previous_outpoint_index.parse::<u32>().ok()?;
    let mut auth_outputs = Vec::with_capacity(output_indexes.len());
    for output_index in output_indexes {
        let out = tx.outputs.iter().find(|out| out.index == *output_index)?;
        let script_bytes = hex::decode(&out.script_public_key).ok()?;
        auth_outputs.push(AuthOutput {
            index: out.index as u32,
            value: out.amount,
            script_version: 0,
            script_bytes,
        });
    }

    compute_covenant_id(&input.previous_outpoint_hash, previous_index, &auth_outputs).ok()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RestTransaction {
    pub transaction_id: String,
    // Address-history + per-tx endpoints set these. /virtual-chain omits
    // them, so we accept defaults and synthesise where the persister needs
    // a value (see scan.rs).
    #[serde(default)]
    pub subnetwork_id: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default, deserialize_with = "stringy_or_int_default")]
    pub mass: String,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub block_hash: Vec<String>,
    #[serde(default)]
    pub block_time: u64,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub is_accepted: bool,
    #[serde(default)]
    pub accepting_block_hash: Option<String>,
    #[serde(default)]
    pub accepting_block_blue_score: Option<u64>,
    #[serde(default)]
    pub accepting_block_time: Option<u64>,
    #[serde(default, deserialize_with = "vec_or_null_default")]
    pub inputs: Vec<RestTxInput>,
    #[serde(default, deserialize_with = "vec_or_null_default")]
    pub outputs: Vec<RestTxOutput>,
}

impl RestTransaction {
    /// Source metadata can be hydrated differently across REST endpoints.
    /// Pin transaction bytes and canonical acceptance, excluding observational
    /// block lists, address strings, and hydrated previous-output fields.
    pub fn recovery_identity(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.transaction_id,
            "version": self.version,
            "subnetwork": self.subnetwork_id,
            "payload": self.payload.as_deref().unwrap_or(""),
            "accepted": self.is_accepted,
            "block": self.accepting_block_hash,
            "score": self.accepting_block_blue_score,
            "time": self.accepting_block_time,
            "inputs": self.inputs.iter().map(|input| (
                &input.previous_outpoint_hash,
                &input.previous_outpoint_index,
                &input.signature_script,
                &input.sig_op_count,
            )).collect::<Vec<_>>(),
            "outputs": self.outputs.iter().map(|output| (
                output.index,
                output.amount,
                &output.script_public_key,
                &output.covenant_id,
                &output.covenant,
            )).collect::<Vec<_>>(),
        })
    }

    /// Native output inference depends on input ownership. Legacy version-zero
    /// outputs use their script hash independently of the input's family.
    pub fn needs_input_identity(&self, input: &RestTxInput) -> bool {
        self.version != 0
            && self.outputs.iter().any(|o| {
                hex::decode(&o.script_public_key)
                    .ok()
                    .is_some_and(|s| crate::is_p2sh_script_pubkey(&s))
            })
            && (input.requires_covenant_identity()
                || (input.previous_outpoint_script.is_none()
                    && input.previous_outpoint_address.is_none()
                    && self.outputs.iter().any(|o| {
                        o.canonical_covenant_id().is_none()
                            && hex::decode(&o.script_public_key)
                                .ok()
                                .is_some_and(|s| crate::is_p2sh_script_pubkey(&s))
                    })))
    }

    pub fn normalize_missing_output_indexes(&mut self) {
        let mut seen = std::collections::BTreeSet::new();
        let has_duplicate = self.outputs.iter().any(|out| !seen.insert(out.index));
        if !has_duplicate {
            return;
        }
        for (idx, out) in self.outputs.iter_mut().enumerate() {
            out.index = idx as u64;
        }
    }

    pub fn with_normalized_missing_output_indexes(&self) -> Self {
        let mut tx = self.clone();
        tx.normalize_missing_output_indexes();
        tx
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestBlock {
    pub hash: String,
    #[serde(default)]
    pub blue_score: u64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub transactions: Vec<RestTransaction>,
}

// ----- /virtual-chain shape -----
//
// Each item is a *chain* block; `transactions[]` are the accepted txs in
// that block with inputs + outputs inline. No `verboseData` envelope (the
// /blocks-from-bluescore one had it; this endpoint flattens).

#[derive(Debug, Clone, Deserialize)]
pub struct VirtualChainBlock {
    pub hash: String,
    pub blue_score: u64,
    #[serde(default)]
    pub daa_score: u64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub transactions: Vec<RestTransaction>,
}

/// Accept a JSON number or string, hand back a decimal `String`. `/virtual-chain`
/// returns ints for `previous_outpoint_index` / `sig_op_count` whereas the
/// address-history endpoint returns strings.
fn stringy_or_int_default<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Either {
        S(String),
        N(i64),
    }
    match Option::<Either>::deserialize(d)? {
        Some(Either::S(s)) => Ok(s),
        Some(Either::N(n)) => Ok(n.to_string()),
        None => Ok(String::new()),
    }
}

fn vec_or_null_default<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::{RestTransaction, RestTxOutput};

    #[test]
    fn reads_top_level_camel_case_covenant_id() {
        let out: RestTxOutput = serde_json::from_value(serde_json::json!({
            "index": 0,
            "amount": 1,
            "script_public_key": "aa20",
            "covenantId": "11"
        }))
        .unwrap();
        assert_eq!(out.canonical_covenant_id(), Some("11"));
    }

    #[test]
    fn reads_nested_covenant_binding_id() {
        let out: RestTxOutput = serde_json::from_value(serde_json::json!({
            "index": 0,
            "amount": 1,
            "script_public_key": "aa20",
            "covenant": {"covenantId": "22", "authorizingInput": 0}
        }))
        .unwrap();
        assert_eq!(out.canonical_covenant_id(), Some("22"));
    }

    #[test]
    fn reads_top_level_snake_case_covenant_binding() {
        let out: RestTxOutput = serde_json::from_value(serde_json::json!({
            "index": 0,
            "amount": 1,
            "script_public_key": "aa20",
            "covenant_id": "33",
            "covenant_authorizing_input": 0
        }))
        .unwrap();
        assert_eq!(out.canonical_covenant_id(), Some("33"));
        assert_eq!(out.covenant_authorizing_input(), Some(0));
        assert_eq!(
            out.covenant
                .as_ref()
                .and_then(|binding| binding.covenant_id.as_deref()),
            Some("33")
        );
    }

    #[test]
    fn computes_genesis_covenant_id_when_rest_omits_binding() {
        let tx = serde_json::from_value(serde_json::json!({
            "transaction_id": "536d2b5459bbd9a742ffcee2e3b2d422830e94b7bbe45098b554e46bde6d2e8b",
            "version": 1,
            "inputs": [{
                "previous_outpoint_hash": "40c367458fd0790267e3a90098ffbb4fba7800f64a53134a33d9315a9789ed1f",
                "previous_outpoint_index": "1"
            }],
            "outputs": [{
                "index": 0,
                "amount": 100000000,
                "script_public_key": "aa20b808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d87"
            }]
        }))
        .unwrap();

        assert_eq!(
            super::compute_genesis_covenant_id_for_output(&tx, 0).as_deref(),
            Some("884c13695a8bef0023ab743ed43102a4832bdaaceb8a27a48589bef0906b25f5")
        );
    }

    #[test]
    fn computes_grouped_genesis_covenant_id() {
        let tx = serde_json::from_value(serde_json::json!({
            "transaction_id": "536d2b5459bbd9a742ffcee2e3b2d422830e94b7bbe45098b554e46bde6d2e8b",
            "version": 1,
            "inputs": [{
                "previous_outpoint_hash": "40c367458fd0790267e3a90098ffbb4fba7800f64a53134a33d9315a9789ed1f",
                "previous_outpoint_index": "1"
            }],
            "outputs": [{
                "index": 0,
                "amount": 100000000,
                "script_public_key": "aa20b808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d87"
            }, {
                "index": 2,
                "amount": 100000000,
                "script_public_key": "aa20c808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d87"
            }]
        }))
        .unwrap();

        let single = super::compute_genesis_covenant_id_for_output(&tx, 0).unwrap();
        let grouped = super::compute_genesis_covenant_id_for_outputs(&tx, &[0, 2]).unwrap();
        assert_ne!(single, grouped);
        assert_eq!(grouped.len(), 64);
    }

    #[test]
    fn computes_grouped_genesis_covenant_id_from_explicit_input() {
        let tx = serde_json::from_value(serde_json::json!({
            "transaction_id": "536d2b5459bbd9a742ffcee2e3b2d422830e94b7bbe45098b554e46bde6d2e8b",
            "version": 1,
            "inputs": [{
                "previous_outpoint_hash": "10c367458fd0790267e3a90098ffbb4fba7800f64a53134a33d9315a9789ed1f",
                "previous_outpoint_index": "0"
            }, {
                "previous_outpoint_hash": "40c367458fd0790267e3a90098ffbb4fba7800f64a53134a33d9315a9789ed1f",
                "previous_outpoint_index": "1"
            }],
            "outputs": [{
                "index": 0,
                "amount": 100000000,
                "script_public_key": "aa20b808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d87"
            }, {
                "index": 1,
                "amount": 100000000,
                "script_public_key": "aa20c808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d87"
            }]
        }))
        .unwrap();

        let funding = super::compute_genesis_covenant_id_for_outputs(&tx, &[0, 1]).unwrap();
        let controller =
            super::compute_genesis_covenant_id_for_outputs_at_input(&tx, 1, &[0, 1]).unwrap();
        assert_ne!(funding, controller);
        assert_eq!(controller.len(), 64);
    }

    #[test]
    fn normalizes_duplicate_output_indexes_from_virtual_chain() {
        let mut tx: RestTransaction = serde_json::from_value(serde_json::json!({
            "transaction_id": "5c358ee77c2888cce46d8cfac280e1e15746994becd6770b59771f56bc5ef07c",
            "outputs": [
                {"index": 0, "amount": 1, "script_public_key": "aa20"},
                {"index": 0, "amount": 2, "script_public_key": "aa20"},
                {"index": 0, "amount": 3, "script_public_key": "aa20"}
            ]
        }))
        .unwrap();

        tx.normalize_missing_output_indexes();
        assert_eq!(
            tx.outputs.iter().map(|out| out.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn treats_null_inputs_and_outputs_as_empty_lists() {
        let tx: RestTransaction = serde_json::from_value(serde_json::json!({
            "transaction_id": "5c358ee77c2888cce46d8cfac280e1e15746994becd6770b59771f56bc5ef07c",
            "inputs": null,
            "outputs": null
        }))
        .unwrap();

        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }
    #[test]
    fn native_identity_requires_parent_or_explicit_funding_evidence() {
        let mut tx = RestTransaction {
            version: 1,
            outputs: vec![super::RestTxOutput {
                script_public_key: format!("aa20{}87", "11".repeat(32)),
                ..Default::default()
            }],
            ..Default::default()
        };
        let unknown = super::RestTxInput::default();
        assert!(tx.needs_input_identity(&unknown));
        let funding = super::RestTxInput {
            previous_outpoint_script: Some(format!("20{}ac", "22".repeat(32))),
            ..Default::default()
        };
        assert!(!tx.needs_input_identity(&funding));
        let p2sh = super::RestTxInput {
            previous_outpoint_script: Some(format!("0000aa20{}87", "33".repeat(32))),
            ..Default::default()
        };
        assert!(tx.needs_input_identity(&p2sh));
        tx.outputs[0].covenant_id = Some("44".repeat(32));
        assert!(!tx.needs_input_identity(&unknown));
        assert!(tx.needs_input_identity(&p2sh));
        tx.version = 0;
        assert!(!tx.needs_input_identity(&p2sh));
    }
}
