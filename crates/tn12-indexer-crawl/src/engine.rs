use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tn12_indexer_core::{is_p2sh_script_pubkey, p2sh_script_hash};
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};
use tn12_indexer_decoder::{default_registry, registry::DecoderRegistry, TemplateDecoder};

/// Per-UTXO record of what the indexer knows about a covenant output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownCovenant {
    pub txid: String,
    pub vout: u32,
    pub address: String,
    pub script_hash_hex: String,
    pub amount_sompi: u64,
    /// covenantId from rusty-kaspa rc.3 RPC, or computed via
    /// `tn12-indexer-core::compute_covenant_id`. None when neither path applied.
    pub covenant_id: Option<String>,
    pub template: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum EventKind {
    Deploy {
        address: String,
        script_hash_hex: String,
        amount_sompi: u64,
        template: Option<String>,
        constructor: Option<serde_json::Value>,
    },
    Spend {
        address: String,
        script_hash_hex: String,
        amount_sompi: u64,
        entrypoint: Option<String>,
        template: Option<String>,
    },
    Continuation {
        address: String,
        script_hash_hex: String,
        amount_sompi: u64,
        template: Option<String>,
        state: Option<serde_json::Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantEvent {
    pub txid: String,
    pub block_time_ms: u64,
    pub vout: Option<u32>,
    pub event: EventKind,
}

pub struct IndexerEngine {
    /// Currently-active covenant UTXOs, keyed by `(txid, vout)`. Drops on spend.
    known: HashMap<(String, u32), KnownCovenant>,
    /// Sticky per-`script_hash` metadata that survives spends (we still want to
    /// surface the covenant's bech32 address even after every UTXO is spent).
    address_by_script_hash: HashMap<[u8; 32], String>,
    /// Template decoders consulted at spend time (linear scan).
    decoders: DecoderRegistry,
    /// Captured reveal scripts from observed spends, keyed by script_hash, so
    /// continuations + later deploys can be matched template-wise.
    reveal_scripts: HashMap<[u8; 32], Vec<u8>>,
    /// Once a spend has revealed the redeem script, we know its template for
    /// any future deploy/continuation that lands at the same P2SH script_hash.
    template_by_script_hash: HashMap<[u8; 32], &'static str>,
    /// Per (script_hash) decoded constructor args, computed once at first
    /// spend and cached for later events that touch the same instance.
    constructor_by_script_hash: HashMap<[u8; 32], serde_json::Value>,
}

impl IndexerEngine {
    /// Construct with the default decoder set (TimeLockVault today).
    pub fn new() -> Self {
        Self::with_decoders(default_registry())
    }

    /// Construct with a caller-supplied decoder set (useful for tests).
    pub fn with_decoders(decoders: DecoderRegistry) -> Self {
        Self {
            known: HashMap::new(),
            address_by_script_hash: HashMap::new(),
            decoders,
            reveal_scripts: HashMap::new(),
            template_by_script_hash: HashMap::new(),
            constructor_by_script_hash: HashMap::new(),
        }
    }

    pub fn register_decoder(&mut self, d: Arc<dyn TemplateDecoder>) {
        self.decoders.register(d);
    }

    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    pub fn process_tx(&mut self, tx: &RestTransaction) -> Result<Vec<CovenantEvent>> {
        if !tx.is_accepted {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();

        for inp in &tx.inputs {
            if let Some(ev) = self.handle_input(tx, inp)? {
                events.push(ev);
            }
        }

        for out in &tx.outputs {
            if let Some(ev) = self.handle_output(tx, out)? {
                events.push(ev);
            }
        }

        Ok(events)
    }

    fn handle_input(
        &mut self,
        tx: &RestTransaction,
        inp: &RestTxInput,
    ) -> Result<Option<CovenantEvent>> {
        let prev_vout: u32 = inp.previous_outpoint_index.parse().unwrap_or(0);
        let key = (inp.previous_outpoint_hash.clone(), prev_vout);
        let Some(known) = self.known.remove(&key) else {
            return Ok(None);
        };

        let sig_script = hex::decode(&inp.signature_script).unwrap_or_default();
        let reveal_bytes = extract_last_push(&sig_script);

        let mut script_hash = [0u8; 32];
        let _ = hex::decode_to_slice(&known.script_hash_hex, &mut script_hash);

        // Resolve template against the reveal script (one-shot per
        // script_hash). Cache constructor args at the same time.
        let mut resolved_template: Option<&'static str> =
            self.template_by_script_hash.get(&script_hash).copied();
        let mut entrypoint = None;

        if let Some(reveal) = reveal_bytes.as_ref() {
            self.reveal_scripts
                .insert(tn12_indexer_core::blake2b_256(reveal), reveal.clone());

            if resolved_template.is_none() {
                if let Some(decoder) = self.decoders.find_for_reveal(reveal) {
                    let name: &'static str = decoder.name();
                    self.template_by_script_hash.insert(script_hash, name);
                    if let Ok(args) = decoder.decode_constructor(reveal) {
                        self.constructor_by_script_hash.insert(script_hash, args);
                    }
                    resolved_template = Some(name);
                }
            }

            if let Some(decoder) = self.decoders.find_for_reveal(reveal) {
                entrypoint = decoder.decode_action(&sig_script);
            }
        }

        Ok(Some(CovenantEvent {
            txid: tx.transaction_id.clone(),
            block_time_ms: tx.block_time,
            vout: None,
            event: EventKind::Spend {
                address: known.address,
                script_hash_hex: known.script_hash_hex,
                amount_sompi: known.amount_sompi,
                entrypoint,
                template: resolved_template.map(String::from),
            },
        }))
    }

    fn handle_output(
        &mut self,
        tx: &RestTransaction,
        out: &RestTxOutput,
    ) -> Result<Option<CovenantEvent>> {
        let spk = hex::decode(&out.script_public_key).unwrap_or_default();
        if !is_p2sh_script_pubkey(&spk) {
            return Ok(None);
        }
        let Some(script_hash) = p2sh_script_hash(&spk) else {
            return Ok(None);
        };
        let script_hash_hex = hex::encode(script_hash);
        let address = out
            .script_public_key_address
            .clone()
            .unwrap_or_else(|| script_hash_hex.clone());

        // Continuation vs first deploy: if we've already cached a template for
        // this script_hash (via a prior spend), this output is a continuation.
        let template_name_static = self.template_by_script_hash.get(&script_hash).copied();
        let template_name: Option<String> = template_name_static.map(String::from);
        let is_continuation =
            template_name_static.is_some() || self.reveal_scripts.contains_key(&script_hash);
        let constructor = self.constructor_by_script_hash.get(&script_hash).cloned();

        self.known.insert(
            (tx.transaction_id.clone(), out.index as u32),
            KnownCovenant {
                txid: tx.transaction_id.clone(),
                vout: out.index as u32,
                address: address.clone(),
                script_hash_hex: script_hash_hex.clone(),
                amount_sompi: out.amount,
                covenant_id: None,
                template: template_name_static,
            },
        );
        self.address_by_script_hash
            .insert(script_hash, address.clone());

        let event = if is_continuation {
            EventKind::Continuation {
                address,
                script_hash_hex,
                amount_sompi: out.amount,
                template: template_name,
                state: None,
            }
        } else {
            EventKind::Deploy {
                address,
                script_hash_hex,
                amount_sompi: out.amount,
                template: template_name,
                constructor,
            }
        };

        Ok(Some(CovenantEvent {
            txid: tx.transaction_id.clone(),
            block_time_ms: tx.block_time,
            vout: Some(out.index as u32),
            event,
        }))
    }
}

impl Default for IndexerEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// A point-in-time view of the engine's in-memory state, used by the HTTP API
/// to render JSON without holding the engine lock during serialization.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineSnapshot {
    pub covenants: Vec<CovenantSummary>,
    pub utxos: Vec<KnownCovenant>,
    pub events: Vec<CovenantEvent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantSummary {
    pub script_hash_hex: String,
    pub address: String,
    pub template: Option<&'static str>,
    pub constructor: Option<serde_json::Value>,
    pub active_utxos: usize,
    pub total_amount_sompi: u64,
}

impl IndexerEngine {
    /// Build a serializable snapshot from the engine's accumulated state.
    /// `events` must be the chronologically-ordered list the caller has been
    /// receiving from `process_tx`.
    pub fn snapshot(&self, events: &[CovenantEvent]) -> EngineSnapshot {
        let mut by_hash: HashMap<String, CovenantSummary> = HashMap::new();
        for u in self.known.values() {
            let entry =
                by_hash
                    .entry(u.script_hash_hex.clone())
                    .or_insert_with(|| CovenantSummary {
                        script_hash_hex: u.script_hash_hex.clone(),
                        address: u.address.clone(),
                        template: None,
                        constructor: None,
                        active_utxos: 0,
                        total_amount_sompi: 0,
                    });
            entry.active_utxos += 1;
            entry.total_amount_sompi = entry.total_amount_sompi.saturating_add(u.amount_sompi);
            if entry.template.is_none() {
                entry.template = u.template;
            }
        }
        // Backfill template + constructor + address from the engine's caches
        // so covenants whose deploy preceded the spend still surface fully
        // (including covenants whose every UTXO has been spent).
        let mut all_script_hashes: std::collections::BTreeSet<[u8; 32]> =
            std::collections::BTreeSet::new();
        all_script_hashes.extend(self.template_by_script_hash.keys().copied());
        all_script_hashes.extend(self.address_by_script_hash.keys().copied());
        for sh in &all_script_hashes {
            let hex_sh = hex::encode(sh);
            let entry = by_hash
                .entry(hex_sh.clone())
                .or_insert_with(|| CovenantSummary {
                    script_hash_hex: hex_sh,
                    address: String::new(),
                    template: None,
                    constructor: None,
                    active_utxos: 0,
                    total_amount_sompi: 0,
                });
            if entry.address.is_empty() {
                if let Some(addr) = self.address_by_script_hash.get(sh) {
                    entry.address = addr.clone();
                }
            }
            if let Some(name) = self.template_by_script_hash.get(sh) {
                entry.template = Some(*name);
            }
            if let Some(ctor) = self.constructor_by_script_hash.get(sh) {
                entry.constructor = Some(ctor.clone());
            }
        }

        let mut covenants: Vec<CovenantSummary> = by_hash.into_values().collect();
        covenants.sort_by(|a, b| a.script_hash_hex.cmp(&b.script_hash_hex));

        // Patch each event with the late-resolved template / constructor so the
        // deploy event no longer shows null after the spend revealed its
        // template. We rewrite the cloned event list — the engine's own event
        // log is whatever the caller stored.
        let patched_events: Vec<CovenantEvent> = events
            .iter()
            .cloned()
            .map(|mut ev| {
                let sh_hex = match &ev.event {
                    EventKind::Deploy {
                        script_hash_hex, ..
                    }
                    | EventKind::Spend {
                        script_hash_hex, ..
                    }
                    | EventKind::Continuation {
                        script_hash_hex, ..
                    } => script_hash_hex.clone(),
                };
                let mut sh = [0u8; 32];
                if hex::decode_to_slice(&sh_hex, &mut sh).is_err() {
                    return ev;
                }
                let template = self.template_by_script_hash.get(&sh).copied();
                let ctor = self.constructor_by_script_hash.get(&sh).cloned();
                match &mut ev.event {
                    EventKind::Deploy {
                        template: t,
                        constructor,
                        ..
                    } => {
                        if t.is_none() {
                            *t = template.map(String::from);
                        }
                        if constructor.is_none() {
                            *constructor = ctor;
                        }
                    }
                    EventKind::Spend { template: t, .. } => {
                        if t.is_none() {
                            *t = template.map(String::from);
                        }
                    }
                    EventKind::Continuation { template: t, .. } => {
                        if t.is_none() {
                            *t = template.map(String::from);
                        }
                    }
                }
                ev
            })
            .collect();

        EngineSnapshot {
            covenants,
            utxos: self.known.values().cloned().collect(),
            events: patched_events,
        }
    }
}

/// Extract the last data push from a script byte sequence. Returns the
/// trailing push payload, or None if no push parses cleanly.
fn extract_last_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = script;
    let mut last: Option<Vec<u8>> = None;
    while !cursor.is_empty() {
        match tn12_indexer_core::read_push(cursor) {
            Some((data, rest)) => {
                last = Some(data.to_vec());
                cursor = rest;
            }
            None => {
                // Skip one byte (non-push opcode) and continue scanning.
                cursor = &cursor[1..];
            }
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replays_both_accepted_tn10_claim_campaigns_in_receipt_order() {
        let first: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../../fixtures/kcom-claim-tn10-live/ordered-token-and-main.json"
        ))
        .unwrap();
        let second: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../../fixtures/kcom-claim-tn10-live/ordered-no-long.json"
        ))
        .unwrap();
        let main: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/evidence/kcom-claim-tn10-main-full-20261030.json"
        ))
        .unwrap();
        let no_long: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/evidence/kcom-claim-tn10-no-long-full-20261030.json"
        ))
        .unwrap();
        assert_eq!((first.len(), second.len()), (33, 29));
        assert_eq!(first[0].transaction_id, "d4b096c30da55ba81bffaf49dbcac369544e75fb82e387e3cd81d3dacba6524c");

        let mut engine = IndexerEngine::new();
        engine.process_tx(&first[0]).unwrap();
        for (receipt, transactions) in [(&main, &first[1..]), (&no_long, &second[..])] {
            let expected = receipt["transactions"].as_array().unwrap();
            assert_eq!(expected.len(), transactions.len());
            for (tx, proof) in transactions.iter().zip(expected) {
                let label = proof["label"].as_str().unwrap();
                assert_eq!(tx.transaction_id, proof["txid"], "{label}");
                assert_eq!(tx.accepting_block_hash.as_deref(), proof["acceptingBlockHash"].as_str(), "{label}");
                assert!(tx.is_accepted, "{label}");
                for output in proof["outputs"].as_array().unwrap() {
                    let actual = &tx.outputs[output["index"].as_u64().unwrap() as usize];
                    assert_eq!(actual.amount.to_string(), output["amountSompi"], "{label}");
                    assert_eq!(actual.script_public_key, output["script"], "{label}");
                }
                let events = engine.process_tx(tx).unwrap();
                let required: Option<(&str, &str)> = match label.split(':').next().unwrap() {
                    "initialize" => Some(("KCOMInitialize", "initialize")),
                    "transfer-to-graph" => Some(("KCC20", "transfer")),
                    "fund-vault" => Some(("KCOMVault", "fund")),
                    "open" => Some(("KCOMVault", "open")),
                    "create-shard" => Some(("KCOMFactory", "create_shard")),
                    "finish-initialization" => Some(("KCOMFactory", "finish_initialization")),
                    "select" => Some(("KCOMClaimShard", "select")),
                    "close-shard" => Some(("KCOMClaimShard", "close")),
                    "collect" => Some(("KCOMSettlement", "collect")),
                    "settle" => Some(("KCOMSettlement", "settle")),
                    "finish-settlement" => Some(("KCOMSettlement", "finish_settlement")),
                    "seal" => Some(("KCOMVault", "seal")),
                    "activate" => Some(("KCOMVault", "activate_")),
                    "recover" => Some(("KCOMVault", "recover_")),
                    "release" => Some(("KCOMVesting", "release")),
                    _ => None,
                };
                if label == "deploy-initializer" {
                    assert!(events.iter().any(|event| matches!(
                        &event.event,
                        EventKind::Deploy { template: None, .. }
                    )), "initializer must start unrevealed");
                }
                if let Some((template, entrypoint)) = required {
                    assert!(events.iter().any(|event| matches!(
                        &event.event,
                        EventKind::Spend {
                            template: Some(actual_template),
                            entrypoint: Some(actual_entrypoint),
                            ..
                        } if actual_template == template && actual_entrypoint.starts_with(entrypoint)
                    )), "{label} {} was not classified as {template}.{entrypoint}: {events:?}", tx.transaction_id);
                }
            }
        }
    }

    #[test]
    fn recognizes_accepted_tn10_claim_selection_after_shard_creation() {
        let created: RestTransaction = serde_json::from_str(include_str!(
            "../../../fixtures/kcom-claim-tn10-live/create-shard-2.json"
        ))
        .expect("accepted TN10 shard creation fixture parses");
        let selected: RestTransaction = serde_json::from_str(include_str!(
            "../../../fixtures/kcom-claim-tn10-live/select-alice.json"
        ))
        .expect("accepted TN10 selection fixture parses");
        let mut engine = IndexerEngine::new();
        engine.process_tx(&created).unwrap();
        let events = engine.process_tx(&selected).unwrap();
        assert!(
            events.iter().any(|event| matches!(
                &event.event,
                EventKind::Spend {
                    template: Some(template),
                    entrypoint: Some(entrypoint),
                    ..
                } if template == "KCOMClaimShard" && entrypoint == "select"
            )),
            "accepted selection must reveal the shard and its entrypoint: {events:?}"
        );
    }

    fn load_fixture(name: &str) -> RestTransaction {
        let raw = std::fs::read_to_string(format!(
            "{}/../../fixtures/timelock-live/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("fixture exists");
        serde_json::from_str(&raw).expect("fixture parses")
    }

    #[test]
    fn replays_timelock_create_then_redeem() {
        let create = load_fixture("create.json");
        let redeem = load_fixture("redeem.json");

        let mut engine = IndexerEngine::new();
        let ev_create = engine.process_tx(&create).unwrap();
        let ev_redeem = engine.process_tx(&redeem).unwrap();

        // Create tx should emit exactly one Deploy event for the P2SH output.
        assert_eq!(
            ev_create.len(),
            1,
            "expected 1 deploy event, got: {ev_create:?}"
        );
        match &ev_create[0].event {
            EventKind::Deploy {
                address,
                amount_sompi,
                ..
            } => {
                assert_eq!(
                    address,
                    "kaspatest:pqgl3yjv0ur3sc6vdp9fd7k2elwr3xvsw0cvuuxq6s5mvnyft9htjz5dsxj7l"
                );
                assert_eq!(*amount_sompi, 15_000_000_000);
            }
            other => panic!("expected Deploy, got {other:?}"),
        }

        // Redeem tx spends that UTXO → one Spend event.
        assert_eq!(
            ev_redeem.len(),
            1,
            "expected 1 spend event, got: {ev_redeem:?}"
        );
        match &ev_redeem[0].event {
            EventKind::Spend {
                address,
                amount_sompi,
                ..
            } => {
                assert_eq!(
                    address,
                    "kaspatest:pqgl3yjv0ur3sc6vdp9fd7k2elwr3xvsw0cvuuxq6s5mvnyft9htjz5dsxj7l"
                );
                assert_eq!(*amount_sompi, 15_000_000_000);
            }
            other => panic!("expected Spend, got {other:?}"),
        }
    }
}
