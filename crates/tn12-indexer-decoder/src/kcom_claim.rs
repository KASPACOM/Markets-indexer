//! ABI-pinned first-spend classification for the KCOM initializer and campaign actors.
//! Successor state inference and campaign graph projections are separate gates.
use crate::{
    kcc20::{args_prefix_before_reveal, item_int, script_items, ScriptItem},
    kcc20_standard::{self, item_tag},
    kcom_vesting, kcom_profile::{self, Profile}, TemplateDecoder,
};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::sync::OnceLock;
use tn12_indexer_core::{
    blake2b_256, compute_genesis_covenant_id_for_outputs_at_input, p2sh_script_hash,
    parse_minimal_int, KnownTemplate, RestTransaction,
};

const ABI_SOURCE: &str = include_str!(
    "../../../wallet-lab/vendor/kcom-claim-capabilities/campaign-entitlements/program-abi.json"
);
const INITIALIZE_ABI_SOURCE: &str = include_str!(
    "../../../wallet-lab/vendor/kcom-claim-capabilities/campaign-entitlements-open/program-abi.json"
);

fn abi() -> &'static Value {
    static ABI: OnceLock<Value> = OnceLock::new();
    ABI.get_or_init(|| serde_json::from_str(ABI_SOURCE).expect("reviewed Argent claim ABI"))
}

fn initialize_abi() -> &'static Value {
    static ABI: OnceLock<Value> = OnceLock::new();
    ABI.get_or_init(|| serde_json::from_str(INITIALIZE_ABI_SOURCE).expect("reviewed Argent initializer ABI"))
}

fn abi_for(template: KnownTemplate) -> &'static Value {
    abi_for_profile(template, Profile::Production)
}

fn abi_for_profile(template: KnownTemplate, profile: Profile) -> &'static Value {
    if profile == Profile::ConfigurableV2 {
        kcom_profile::configurable_abi(template == KnownTemplate::KcomInitialize)
    } else if profile == Profile::FastTn10 {
        kcom_profile::fast_abi(template == KnownTemplate::KcomInitialize)
    } else if template == KnownTemplate::KcomInitialize {
        initialize_abi()
    } else {
        abi()
    }
}

#[cfg(test)]
mod campaign_successor_tests {
    use super::*;

    const OPEN_VECTOR: &str = include_str!("../fixtures/kcom-claim-open-vectors.json");
    const FUND_VECTOR: &str = include_str!("../fixtures/kcom-claim-fund-vectors.json");

    fn vector() -> Value {
        serde_json::from_str(include_str!("../fixtures/kcom-claim-factory-vectors.json")).unwrap()
    }

    fn source_state(vector: &Value) -> Map<String, Value> {
        let mut state = vector["factoryState"].as_object().unwrap().clone();
        assert_eq!(
            vector["graphArtifactId"],
            "531a05b1c137c2141c71618366fbd8d52a30fe5834667bcf07495914fea875ae"
        );
        for (field, hash) in vector["generatedTemplateHashes"].as_object().unwrap() {
            state.insert(field.clone(), hash.clone());
        }
        state
    }

    #[test]
    fn activation_reconstructs_both_builder_positions_and_reserves() {
        let fixture = vector();
        let activation = &fixture["activationVectors"];
        let graph_id = hex::decode(activation["graphId"].as_str().unwrap()).unwrap();
        let token_id = hex::decode(activation["tokenId"].as_str().unwrap()).unwrap();
        for name in ["first", "last"] {
            let v = &activation[name];
            let inputs = v["inputs"].as_array().unwrap().iter().enumerate().map(|(index, input)| {
                let (source, witness, amount) = match index {
                    0 => ("vaultSourceScript", "vaultWitness", 600_000_000),
                    1 => ("entitlementSourceScript", "entitlementWitness", 100_000_000),
                    2 => ("tokenSourceScript", "tokenWitness", if name == "first" {200_000_000} else {100_000_000}),
                    _ => ("", "", 100_000_000),
                };
                json!({
                    "previous_outpoint_hash": input["transactionId"],
                    "previous_outpoint_index": input["index"],
                    "previous_outpoint_script": if index < 3 {Value::String(format!("aa20{}87", hex::encode(blake2b_256(&hex::decode(v[source].as_str().unwrap()).unwrap()))))} else {Value::Null},
                    "previous_outpoint_amount": amount,
                    "signature_script": if index < 3 {v[witness].clone()} else {json!("")},
                })
            }).collect::<Vec<_>>();
            let outputs = v["outputs"].as_array().unwrap().iter().enumerate().map(|(index, out)| json!({
                "index": index, "amount": out["valueSompi"].as_str().unwrap().parse::<u64>().unwrap(),
                "script_public_key": out["scriptPublicKeyHex"],
                "covenant_id": out["covenantId"],
                "covenant_authorizing_input": if index < 2 {0} else {2},
            })).collect::<Vec<_>>();
            let tx: RestTransaction = serde_json::from_value(json!({
                "transaction_id": "ab".repeat(32), "version": 1,
                "is_accepted": true, "accepting_block_hash": "cd".repeat(32),
                "inputs": inputs, "outputs": outputs,
            }))
            .unwrap();
            let reveals = [
                "vaultSourceScript",
                "entitlementSourceScript",
                "tokenSourceScript",
            ]
            .map(|field| hex::decode(v[field].as_str().unwrap()).unwrap());
            let (vault, position_id, position) = decode_activation_successors(
                &tx,
                0,
                1,
                2,
                &graph_id,
                &token_id,
                &reveals[0],
                &reveals[1],
                &reveals[2],
            )
            .unwrap();
            assert_eq!(hex::encode(position_id), v["positionId"]);
            assert_eq!(
                vault[0].1["activated_raw"],
                if name == "first" { "276" } else { "996" }
            );
            assert_eq!(position.1["released"], "0");
            assert_eq!(position.1["total"], v["allocationRaw"]);

            for mutation in [
                "position",
                "reserve",
                "native",
                "lineage",
                "extra",
                "extra_position",
                "rebound",
            ] {
                let mut forged = tx.clone();
                match mutation {
                    "position" => forged.outputs[1]
                        .script_public_key
                        .replace_range(8..10, "ff"),
                    "reserve" => forged.outputs[2]
                        .script_public_key
                        .replace_range(8..10, "ff"),
                    "native" => forged.outputs[1].amount -= 1,
                    "lineage" => forged.outputs[1].covenant_id = Some("ff".repeat(32)),
                    "extra" => {
                        let mut extra = forged.outputs[2].clone();
                        extra.index = 8;
                        forged.outputs.push(extra);
                    }
                    "extra_position" => {
                        let mut extra = forged.outputs[1].clone();
                        extra.index = 8;
                        forged.outputs.push(extra);
                    }
                    "rebound" => {
                        forged.outputs[1]
                            .covenant
                            .as_mut()
                            .unwrap()
                            .authorizing_input = Some(2)
                    }
                    _ => unreachable!(),
                }
                assert!(
                    decode_activation_successors(
                        &forged,
                        0,
                        1,
                        2,
                        &graph_id,
                        &token_id,
                        &reveals[0],
                        &reveals[1],
                        &reveals[2],
                    )
                    .is_err(),
                    "{name} {mutation}"
                );
            }
        }
    }

    #[test]
    fn configurable_engine_transactions_reconstruct_initializer_and_activation() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../fixtures/kcom-configurable-engine.json"
        )).unwrap();
        assert_eq!(fixture["evidence"], "synthetic-local-engine-only");
        let graph_id = hex::decode(fixture["graphId"].as_str().unwrap()).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let tx: RestTransaction = serde_json::from_value(case["transaction"].clone()).unwrap();
            let signature = |i: usize| hex::decode(&tx.inputs[i].signature_script).unwrap();
            let reveal = |i: usize| {
                let sig = signature(i);
                let items = script_items(&sig);
                witness_bytes(&items, items.len() - 1).unwrap()
            };
            if case["operation"] == "initialize" {
                let reveal = reveal(0);
                let source = [vec![0xaa, 0x20], blake2b_256(&reveal).to_vec(), vec![0x87]].concat();
                let amount = fixture["initializerValueSompi"].as_str().unwrap().parse().unwrap();
                let (id, states) = decode_initialize_successors(
                    &tx, 0, &signature(0), &reveal, &source, amount,
                ).unwrap();
                assert_eq!(id, graph_id);
                assert_eq!(states.len(), 2);
                for (_, state) in states {
                    assert_eq!(state["artifactProfile"], "kcom-configurable-v2");
                }
                let mut forged = tx.clone();
                forged.outputs[1].script_public_key.replace_range(8..10, "ff");
                assert!(decode_initialize_successors(
                    &forged, 0, &signature(0), &reveal, &source, amount,
                ).is_err());
            } else {
                let reveals = [reveal(0), reveal(1), reveal(2)];
                let state = KcomClaimDecoder::new(KnownTemplate::KcomVault)
                    .decode_constructor(&reveals[0]).unwrap();
                let token_id = hex::decode(state["token_id"].as_str().unwrap()).unwrap();
                let decode = |transaction: &RestTransaction| decode_activation_successors(
                    transaction, 0, 1, 2, &graph_id, &token_id,
                    &reveals[0], &reveals[1], &reveals[2],
                );
                let (vault, _, position) = decode(&tx).unwrap();
                assert_eq!(position.1["artifactProfile"], "kcom-configurable-v2");
                assert_eq!(position.1["period_ms"], "60000");
                assert_eq!(position.1["total"], case["allocationRaw"]);
                assert_eq!(position.1["released"], "0");
                assert_eq!(vault.len(), 1);
                if case["operation"] == "activate-final" {
                    assert_eq!(vault[0].1["activated_raw"], vault[0].1["liability_raw"]);
                }
                for mutation in ["position", "amount", "source", "extra"] {
                    let mut forged = tx.clone();
                    let index = position.0 as usize;
                    match mutation {
                        "position" => forged.outputs[index].script_public_key.replace_range(8..10, "ff"),
                        "amount" => forged.outputs[index].amount -= 1,
                        "source" => forged.inputs[0].previous_outpoint_amount = None,
                        "extra" => {
                            let mut extra = forged.outputs[index].clone();
                            extra.index = 99;
                            forged.outputs.push(extra);
                        },
                        _ => unreachable!(),
                    }
                    assert!(decode(&forged).is_err(), "{mutation}");
                }
            }
        }
    }

    #[test]
    fn recovery_reconstructs_both_signed_builder_variants() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../fixtures/kcom-claim-recovery-vectors.json"
        )).unwrap();
        assert_eq!(fixture["builderCommit"],
            "c2f79f173d13a051a3efc462d1361cd8b062456b");
        assert_eq!(fixture["argentCommit"],
            "9a9f4b107116d0b259fae629f200fa3b663e7e9d");
        assert_eq!(fixture["engineSha256"],
            "fb1782be8c4499ad9d18dc11a0fdac85fe553ae22c1a0b8dd6bc023f46f7c2c1");
        for case in fixture["cases"].as_array().unwrap() {
            let partial = case["variant"] == "partial";
            let action = if partial { "recover_partial" } else { "recover_final" };
            let tag = abi()["contracts"]["KCOMVault"]["entries"][action]["dispatch_tag"]
                .as_str().unwrap();
            let vault_reveal = hex::decode(case["vaultRevealHex"].as_str().unwrap()).unwrap();
            let token_reveal = hex::decode(case["tokenRevealHex"].as_str().unwrap()).unwrap();
            let mut witness = vec![4];
            witness.extend(hex::decode(tag).unwrap());
            witness.push(0x4d);
            witness.extend(u16::try_from(vault_reveal.len()).unwrap().to_le_bytes());
            witness.extend(&vault_reveal);
            let inputs = case["inputs"].as_array().unwrap().iter().enumerate()
                .map(|(index, input)| json!({
                    "previous_outpoint_hash": input["transactionId"],
                    "previous_outpoint_index": input["index"],
                    "previous_outpoint_amount": input["amountSompi"].as_str().unwrap()
                        .parse::<u64>().unwrap(),
                    "previous_outpoint_script": input["scriptPublicKeyHex"],
                    "signature_script": if index == 0 {hex::encode(&witness)} else {String::new()},
                })).collect::<Vec<_>>();
            let outputs = case["outputs"].as_array().unwrap().iter().map(|output| json!({
                "index": output["index"],
                "amount": output["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
                "script_public_key": output["scriptPublicKeyHex"],
                "covenant_id": output["covenantId"],
                "covenant_authorizing_input": output["authorizingInput"],
            })).collect::<Vec<_>>();
            let tx: RestTransaction = serde_json::from_value(json!({
                "transaction_id": case["localTransactionId"],
                "version": 1, "is_accepted": true,
                "accepting_block_hash": "cd".repeat(32),
                "inputs": inputs, "outputs": outputs,
            })).unwrap();
            let graph_id = hex::decode(case["graphId"].as_str().unwrap()).unwrap();
            let token_id = hex::decode(case["tokenId"].as_str().unwrap()).unwrap();
            let recovered = decode_recovery_successor(&tx, 0, 1,
                &graph_id, &token_id, &vault_reveal, &token_reveal).unwrap();
            assert_eq!(recovered.0.0, 0);
            assert_eq!(recovered.0.1["recovered"], true);
            assert_eq!(recovered.0.1["liability_raw"], case["vaultState"]["liability_raw"]);
            assert_eq!(recovered.1.len(), if partial { 2 } else { 1 });
            assert_eq!(recovered.1[0].1["amount"], case["surplusRaw"]);
            if partial {
                assert_eq!(recovered.1[1].1["amount"], case["remainingLiabilityRaw"]);
            }
            for mutation in ["vault_script", "treasury_script", "native", "token_native", "lineage",
                "rebound", "source", "extra"] {
                let mut forged = tx.clone();
                match mutation {
                    "vault_script" => forged.outputs[0].script_public_key.replace_range(8..10, "ff"),
                    "treasury_script" => forged.outputs[1].script_public_key.replace_range(8..10, "ff"),
                    "native" => forged.outputs[0].amount -= 1,
                    "token_native" => forged.outputs[1].amount -= 1,
                    "lineage" => forged.outputs[1].covenant_id = Some("ff".repeat(32)),
                    "rebound" => forged.outputs[1].covenant.as_mut().unwrap()
                        .authorizing_input = Some(0),
                    "source" => forged.inputs[1].previous_outpoint_script = Some("aa20".to_owned() + &"ff".repeat(32) + "87"),
                    "extra" => {
                        let mut extra = forged.outputs[1].clone();
                        extra.index = 8;
                        forged.outputs.push(extra);
                    }
                    _ => unreachable!(),
                }
                assert!(decode_recovery_successor(&forged, 0, 1,
                    &graph_id, &token_id, &vault_reveal, &token_reveal).is_err(),
                    "{} {mutation}", case["variant"]);
            }
            if partial {
                let mut forged = tx.clone();
                forged.outputs[2].script_public_key.replace_range(8..10, "ff");
                assert!(decode_recovery_successor(&forged, 0, 1,
                    &graph_id, &token_id, &vault_reveal, &token_reveal).is_err());
            }
        }
    }

    fn spend(
        reveal: &[u8],
        actor: &str,
        action: &str,
        graph: &str,
        scripts: &[String],
    ) -> (RestTransaction, Vec<u8>) {
        let tag = abi()["contracts"][actor]["entries"][action]["dispatch_tag"]
            .as_str()
            .unwrap();
        let mut signature = vec![4];
        signature.extend(hex::decode(tag).unwrap());
        signature.push(0x4d);
        signature.extend(u16::try_from(reveal.len()).unwrap().to_le_bytes());
        signature.extend(reveal);
        let tx = serde_json::from_value(json!({
            "transaction_id": "11".repeat(32),
            "version": 1,
            "is_accepted": true,
            "accepting_block_hash": "22".repeat(32),
            "accepting_block_blue_score": 1,
            "accepting_block_time": 1790000000000u64,
            "inputs": [{
                "previous_outpoint_hash": "33".repeat(32),
                "previous_outpoint_index": "0",
                "previous_outpoint_script": format!("aa20{}87", hex::encode(blake2b_256(reveal))),
                "signature_script": hex::encode(&signature)
            }],
            "outputs": scripts.iter().enumerate().map(|(index, script)| json!({
                "index": index,
                "amount": 100000000,
                "script_public_key": script,
                "covenant_authorizing_input": 0,
                "covenant_id": graph
            })).collect::<Vec<_>>()
        }))
        .unwrap();
        (tx, signature)
    }

    #[test]
    fn opening_authenticates_both_builder_sources_and_the_unrevealed_vault() {
        let fixture: Value = serde_json::from_str(OPEN_VECTOR).unwrap();
        assert_eq!(fixture["builderCommit"], "c2f79f173d13a051a3efc462d1361cd8b062456b");
        assert_eq!(fixture["engineSha256"],
            "fb1782be8c4499ad9d18dc11a0fdac85fe553ae22c1a0b8dd6bc023f46f7c2c1");
        let case = &fixture["case"];
        let graph = hex::decode(case["graphId"].as_str().unwrap()).unwrap();
        let factory = hex::decode(case["factoryRevealHex"].as_str().unwrap()).unwrap();
        let vault = hex::decode(case["vaultRevealHex"].as_str().unwrap()).unwrap();
        let witness = |actor: &str, reveal: &[u8]| {
            let tag = abi()["contracts"][actor]["entries"]["open"]["dispatch_tag"]
                .as_str().unwrap();
            let mut bytes = vec![4];
            bytes.extend(hex::decode(tag).unwrap());
            bytes.push(0x4d);
            bytes.extend(u16::try_from(reveal.len()).unwrap().to_le_bytes());
            bytes.extend(reveal);
            hex::encode(bytes)
        };
        let reveals = [&factory, &vault];
        let actors = ["KCOMFactory", "KCOMVault"];
        let inputs = case["inputs"].as_array().unwrap().iter().enumerate().map(|(index, input)| json!({
            "previous_outpoint_hash": input["transactionId"],
            "previous_outpoint_index": input["index"],
            "previous_outpoint_amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "previous_outpoint_script": input["scriptPublicKeyHex"],
            "signature_script": witness(actors[index], reveals[index]),
        })).collect::<Vec<_>>();
        let outputs = case["outputs"].as_array().unwrap().iter().map(|output| json!({
            "index": output["index"],
            "amount": output["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "script_public_key": output["scriptPublicKeyHex"],
            "covenant_id": output["covenantId"],
            "covenant_authorizing_input": output["authorizingInput"],
        })).collect::<Vec<_>>();
        let tx: RestTransaction = serde_json::from_value(json!({
            "transaction_id": case["localTransactionId"], "version": 1,
            "is_accepted": true, "accepting_block_hash": "cd".repeat(32),
            "inputs": inputs, "outputs": outputs,
        })).unwrap();
        let opened = decode_vault_open_successor(&tx, 0, 1, &graph, &factory, &vault).unwrap();
        assert_eq!(opened.0, 1);
        assert_eq!(opened.1["opened"], true);
        assert_eq!(opened.1["treasury"],
            KcomClaimDecoder::new(KnownTemplate::KcomVault).decode_constructor(&vault).unwrap()["treasury"]);

        for mutation in ["source", "vault_script", "factory_script", "native", "lineage", "rebound", "extra"] {
            let mut bad = tx.clone();
            match mutation {
                "source" => bad.inputs[1].previous_outpoint_script = Some(format!("aa20{}87", "ff".repeat(32))),
                "vault_script" => bad.outputs[1].script_public_key.replace_range(8..10, "ff"),
                "factory_script" => bad.outputs[0].script_public_key.replace_range(8..10, "ff"),
                "native" => bad.outputs[1].amount -= 1,
                "lineage" => bad.outputs[1].covenant_id = Some("ff".repeat(32)),
                "rebound" => bad.outputs[1].covenant.as_mut().unwrap().authorizing_input = Some(1),
                "extra" => { let mut extra = bad.outputs[1].clone(); extra.index = 8; bad.outputs.push(extra); }
                _ => unreachable!(),
            }
            assert!(decode_vault_open_successor(&bad, 0, 1, &graph, &factory, &vault).is_err(),
                "{mutation}");
        }
        let mut changed = KcomClaimDecoder::new(KnownTemplate::KcomVault)
            .decode_constructor(&vault).unwrap().as_object().unwrap().clone();
        changed.insert("budget_raw".into(), json!("999"));
        let changed_reveal = encoded_script(KnownTemplate::KcomVault, &changed).unwrap();
        let mut bad = tx.clone();
        bad.inputs[1].previous_outpoint_script = Some(format!("aa20{}87",
            hex::encode(blake2b_256(&changed_reveal))));
        bad.inputs[1].signature_script = witness("KCOMVault", &changed_reveal);
        assert!(decode_vault_open_successor(&bad, 0, 1, &graph, &factory, &changed_reveal).is_err());
    }

    #[test]
    fn funding_authenticates_graph_token_and_unrevealed_reserves() {
        let fixture: Value = serde_json::from_str(FUND_VECTOR).unwrap();
        assert_eq!(fixture["builderCommit"], "c2f79f173d13a051a3efc462d1361cd8b062456b");
        assert_eq!(fixture["engineSha256"],
            "fb1782be8c4499ad9d18dc11a0fdac85fe553ae22c1a0b8dd6bc023f46f7c2c1");
        let case = &fixture["case"];
        let graph = hex::decode(case["graphId"].as_str().unwrap()).unwrap();
        let token = hex::decode(case["tokenId"].as_str().unwrap()).unwrap();
        let vault_reveal = hex::decode(case["vaultRevealHex"].as_str().unwrap()).unwrap();
        let token_reveal = hex::decode(case["tokenRevealHex"].as_str().unwrap()).unwrap();
        let tag = abi()["contracts"]["KCOMVault"]["entries"]["fund"]["dispatch_tag"]
            .as_str().unwrap();
        let mut vault_witness = vec![4];
        vault_witness.extend(hex::decode(tag).unwrap());
        vault_witness.push(0x4d);
        vault_witness.extend(u16::try_from(vault_reveal.len()).unwrap().to_le_bytes());
        vault_witness.extend(&vault_reveal);
        let inputs = case["inputs"].as_array().unwrap().iter().enumerate().map(|(index, input)| json!({
            "previous_outpoint_hash": input["transactionId"],
            "previous_outpoint_index": input["index"],
            "previous_outpoint_amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "previous_outpoint_script": input["scriptPublicKeyHex"],
            "signature_script": if index == 0 {hex::encode(&vault_witness)} else {String::new()},
        })).collect::<Vec<_>>();
        let mut outputs = case["outputs"].as_array().unwrap().iter().map(|output| json!({
            "index": output["index"],
            "amount": output["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "script_public_key": output["scriptPublicKeyHex"],
            "covenant_id": output["covenantId"],
            "covenant_authorizing_input": output["authorizingInput"],
        })).collect::<Vec<_>>();
        outputs.push(json!({"index": 2, "amount": 940000000,
            "script_public_key": format!("20{}ac", "11".repeat(32))}));
        let tx: RestTransaction = serde_json::from_value(json!({
            "transaction_id": case["localTransactionId"], "version": 1,
            "is_accepted": true, "accepting_block_hash": "cd".repeat(32),
            "inputs": inputs, "outputs": outputs,
        })).unwrap();
        let (vault, token_state) = decode_vault_fund_successors(&tx, 0, 1,
            &graph, &token, &vault_reveal, &token_reveal).unwrap();
        assert_eq!(vault.1["funded"], true);
        assert_eq!(token_state.1["amount"], "1000");
        for mutation in ["source", "vault", "token", "kas", "lineage", "rebound", "extra"] {
            let mut bad = tx.clone();
            match mutation {
                "source" => bad.inputs[1].previous_outpoint_script = Some(format!("aa20{}87", "ff".repeat(32))),
                "vault" => bad.outputs[0].script_public_key.replace_range(8..10, "ff"),
                "token" => bad.outputs[1].script_public_key.replace_range(8..10, "ff"),
                "kas" => bad.outputs[1].amount -= 1,
                "lineage" => bad.outputs[1].covenant_id = Some("ff".repeat(32)),
                "rebound" => bad.outputs[1].covenant.as_mut().unwrap().authorizing_input = Some(0),
                "extra" => {let mut extra = bad.outputs[1].clone(); extra.index = 8; bad.outputs.push(extra);}
                _ => unreachable!(),
            }
            assert!(decode_vault_fund_successors(&bad, 0, 1,
                &graph, &token, &vault_reveal, &token_reveal).is_err(), "{mutation}");
        }
    }

    #[test]
    fn factory_outputs_match_independent_shared_builder_vectors() {
        let vector = vector();
        assert_eq!(
            vector["builderCommit"],
            "c2f79f173d13a051a3efc462d1361cd8b062456b"
        );
        assert_eq!(
            vector["sourceFixtureSha256"],
            "93f8fe414d86cf228de058e3008401562fd6accd158ba28e27610cc58c63fc33"
        );
        let graph = vector["graphId"].as_str().unwrap();
        let state = source_state(&vector);
        let mut unopened = state.clone();
        unopened.insert("opened".into(), json!(false));
        let opening_reveal = encoded_script(KnownTemplate::KcomFactory, &unopened).unwrap();
        let opening_scripts = vector["openOutputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let (opening_tx, opening_signature) = spend(
            &opening_reveal,
            "KCOMFactory",
            "open",
            graph,
            &opening_scripts,
        );
        let opened = decode_factory_successors(
            &opening_tx,
            0,
            &hex::decode(graph).unwrap(),
            &opening_signature,
            &opening_reveal,
        )
        .unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].1["opened"], true);
        let mut bad_open = opening_tx.clone();
        bad_open.outputs[0]
            .script_public_key
            .replace_range(8..10, "ff");
        assert!(decode_factory_successors(
            &bad_open,
            0,
            &hex::decode(graph).unwrap(),
            &opening_signature,
            &opening_reveal,
        )
        .is_err());

        let reveal = encoded_script(KnownTemplate::KcomFactory, &state).unwrap();
        let scripts = vector["firstCreateShardOutputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let (tx, signature) = spend(&reveal, "KCOMFactory", "create_shard", graph, &scripts);
        let successors =
            decode_factory_successors(&tx, 0, &hex::decode(graph).unwrap(), &signature, &reveal)
                .unwrap();
        assert_eq!(successors.len(), 2);
        assert_eq!(successors[0].1["next_shard"], "1");
        assert_eq!(successors[1].1["shard"], "0");
        assert_eq!(successors[1].1["closed"], false);

        for mutation in ["script", "lineage", "extra", "reordered"] {
            let mut bad = tx.clone();
            match mutation {
                "script" => bad.outputs[1].script_public_key.replace_range(8..10, "ff"),
                "lineage" => bad.outputs[1].covenant_id = Some("44".repeat(32)),
                "extra" => bad.outputs.push(bad.outputs[1].clone()),
                "reordered" => bad.outputs.swap(0, 1),
                _ => unreachable!(),
            }
            assert!(
                decode_factory_successors(
                    &bad,
                    0,
                    &hex::decode(graph).unwrap(),
                    &signature,
                    &reveal,
                )
                .is_err(),
                "{mutation}"
            );
        }

        let mut final_state = state;
        final_state.insert(
            "next_shard".into(),
            vector["factoryState"]["shard_count"].clone(),
        );
        let reveal = encoded_script(KnownTemplate::KcomFactory, &final_state).unwrap();
        let script = vector["finishInitializationOutput"]
            .as_str()
            .unwrap()
            .to_owned();
        let (tx, signature) = spend(
            &reveal,
            "KCOMFactory",
            "finish_initialization",
            graph,
            &[script],
        );
        let successors =
            decode_factory_successors(&tx, 0, &hex::decode(graph).unwrap(), &signature, &reveal)
                .unwrap();
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0].1["modeName"], "KCOMSettlement");
        assert_eq!(successors[0].1["settled_count"], "0");
    }

    #[test]
    fn shard_close_matches_shared_builder_and_rejects_mutations() {
        let vector = vector();
        let graph = vector["graphId"].as_str().unwrap();
        let graph_id = hex::decode(graph).unwrap();
        let reveal = hex::decode(vector["initialShardScript"].as_str().unwrap()).unwrap();
        let closed_script = vector["closedShardOutput"].as_str().unwrap().to_owned();
        let (tx, signature) = spend(&reveal, "KCOMClaimShard", "close", graph, &[closed_script]);
        let successors = decode_shard_successors(&tx, 0, &graph_id, &signature, &reveal).unwrap();
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0].1["closed"], true);
        assert_eq!(successors[0].1["shard"], "0");
        for mutation in ["script", "lineage", "extra"] {
            let mut bad = tx.clone();
            match mutation {
                "script" => bad.outputs[0].script_public_key.replace_range(8..10, "ff"),
                "lineage" => bad.outputs[0].covenant_id = Some("44".repeat(32)),
                "extra" => bad.outputs.push(bad.outputs[0].clone()),
                _ => unreachable!(),
            }
            assert!(
                decode_shard_successors(&bad, 0, &graph_id, &signature, &reveal).is_err(),
                "{mutation}"
            );
        }
        let mut closed_state = KcomClaimDecoder::new(KnownTemplate::KcomClaimShard)
            .decode_constructor(&reveal)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        closed_state.insert("closed".into(), json!(true));
        let closed_reveal = encoded_script(KnownTemplate::KcomClaimShard, &closed_state).unwrap();
        let (collect, collect_signature) =
            spend(&closed_reveal, "KCOMClaimShard", "collect", graph, &[]);
        assert!(decode_shard_successors(
            &collect,
            0,
            &graph_id,
            &collect_signature,
            &closed_reveal,
        )
        .unwrap()
        .is_empty());
        let (bad_collect, bad_signature) = spend(
            &closed_reveal,
            "KCOMClaimShard",
            "collect",
            graph,
            &[vector["closedShardOutput"].as_str().unwrap().to_owned()],
        );
        assert!(decode_shard_successors(
            &bad_collect,
            0,
            &graph_id,
            &bad_signature,
            &closed_reveal,
        )
        .is_err());
    }

    fn push_data(script: &mut Vec<u8>, bytes: &[u8]) {
        match bytes.len() {
            0 => script.push(0),
            1..=75 => script.push(bytes.len() as u8),
            76..=255 => script.extend([0x4c, bytes.len() as u8]),
            _ => {
                script.push(0x4d);
                script.extend(u16::try_from(bytes.len()).unwrap().to_le_bytes());
            }
        }
        script.extend(bytes);
    }

    fn selection_witness(selection: &Value) -> Vec<u8> {
        let args = &selection["args"];
        let mut witness = Vec::new();
        let mut signature = [0u8; 65];
        signature[64] = 1;
        push_data(&mut witness, &signature);
        push_data(
            &mut witness,
            &hex::decode(args["key"].as_str().unwrap()).unwrap(),
        );
        for name in ["index", "weight", "tier"] {
            push_data(&mut witness, &args[name].as_i64().unwrap().to_le_bytes());
        }
        push_data(&mut witness, &[args["scheme"].as_u64().unwrap() as u8]);
        for name in ["beneficiary", "membershipProof", "unusedProof"] {
            push_data(
                &mut witness,
                &hex::decode(args[name].as_str().unwrap()).unwrap(),
            );
        }
        for name in ["depth", "route"] {
            push_data(&mut witness, &args[name].as_i64().unwrap().to_le_bytes());
        }
        let parts = &selection["commitmentTemplateParts"];
        for name in ["prefix", "suffix"] {
            push_data(
                &mut witness,
                &hex::decode(parts[name].as_str().unwrap()).unwrap(),
            );
        }
        let tag = abi()["contracts"]["KCOMClaimShard"]["entries"]["select"]["dispatch_tag"]
            .as_str()
            .unwrap();
        push_data(&mut witness, &hex::decode(tag).unwrap());
        push_data(
            &mut witness,
            &hex::decode(selection["sourceScript"].as_str().unwrap()).unwrap(),
        );
        witness
    }

    #[test]
    fn shard_selection_proofs_and_redirected_commitment_match_builder() {
        let vector = vector();
        assert_eq!(
            vector["selectionSourceSha256"],
            "63df28dd387ec61427d0b04b28c9e21a498a1eecf48ac6c6e170d9296e2de407"
        );
        let selection = &vector["selection"];
        let graph = vector["graphId"].as_str().unwrap();
        let graph_id = hex::decode(graph).unwrap();
        let reveal = hex::decode(selection["sourceScript"].as_str().unwrap()).unwrap();
        let scripts = selection["outputScripts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|script| script.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        let (mut tx, _) = spend(&reveal, "KCOMClaimShard", "select", graph, &scripts);
        let signature = selection_witness(selection);
        tx.inputs[0].signature_script = hex::encode(&signature);
        let successors = decode_shard_successors(&tx, 0, &graph_id, &signature, &reveal).unwrap();
        let builder_witness =
            hex::decode(selection["signedBuilderWitness"].as_str().unwrap()).unwrap();
        assert_eq!(
            decode_shard_successors(&tx, 0, &graph_id, &builder_witness, &reveal).unwrap(),
            successors
        );
        assert_eq!(successors.len(), 2);
        for name in [
            "used_root",
            "selected_count",
            "all_weight",
            "boosted_weight",
            "long_weight",
        ] {
            assert_eq!(
                successors[0].1[name], selection["afterState"][name],
                "{name}"
            );
        }
        assert_eq!(successors[1].1["modeName"], "KCOMClaimCommitment");
        assert_eq!(
            successors[1].1["beneficiary"],
            selection["args"]["beneficiary"]
        );
        assert_eq!(successors[1].1["tier"], "3");
        assert_eq!(
            successors[1].1["identity"],
            selection["commitmentState"]["identity"]
        );
        let action = decode_selection_action_details(&builder_witness, &reveal).unwrap();
        assert_eq!(action["leafIndex"], selection["args"]["index"]);
        assert_eq!(action["originalAuthority"],
            selection["commitmentState"]["original_authority"]);
        assert_eq!(action["usedRootBefore"], selection["beforeState"]["used_root"]);
        assert_eq!(action["usedRootAfter"], selection["afterState"]["used_root"]);
        assert_eq!(action["selectionDigest"],
            "098b874ff5e22633809b8dbe2c56bb52c68da66638efd4e5c54e9f39bd8896ab");

        for mutation in ["membershipProof", "unusedProof", "beneficiary", "tier"] {
            let mut altered = selection.clone();
            let original = &selection["args"][mutation];
            altered["args"][mutation] = if mutation == "tier" {
                json!(2)
            } else {
                let mut value = original.as_str().unwrap().to_owned();
                value.replace_range(0..2, "ff");
                json!(value)
            };
            let bad = selection_witness(&altered);
            assert!(
                decode_shard_successors(&tx, 0, &graph_id, &bad, &reveal).is_err(),
                "{mutation}"
            );
            if mutation == "membershipProof" || mutation == "unusedProof" {
                assert!(decode_selection_action_details(&bad, &reveal).is_err(),
                    "selection details accepted {mutation}");
            }
        }
        let mut bad_output = tx.clone();
        bad_output.outputs[1]
            .script_public_key
            .replace_range(8..10, "ff");
        assert!(decode_shard_successors(&bad_output, 0, &graph_id, &signature, &reveal).is_err());
        let mut stale = selection["beforeState"].as_object().unwrap().clone();
        stale.insert(
            "used_root".into(),
            selection["afterState"]["used_root"].clone(),
        );
        for (field, hash) in vector["generatedTemplateHashes"].as_object().unwrap() {
            if field == "gen__kcom_claim_commitment_template"
                || field == "gen__kcom_settlement_template"
            {
                stale.insert(field.clone(), hash.clone());
            }
        }
        let stale_reveal = encoded_script(KnownTemplate::KcomClaimShard, &stale).unwrap();
        assert!(decode_shard_successors(&tx, 0, &graph_id, &signature, &stale_reveal).is_err());
    }

    #[test]
    fn settlement_finish_matches_shared_builder_output() {
        let vector = vector();
        let finish = &vector["settlementFinish"];
        assert_eq!(
            finish["sourceFixtureSha256"],
            "93f8fe414d86cf228de058e3008401562fd6accd158ba28e27610cc58c63fc33"
        );
        let graph = vector["graphId"].as_str().unwrap();
        let before = finish["beforeState"].as_object().unwrap();
        let reveal = encoded_script(KnownTemplate::KcomSettlement, before).unwrap();
        assert_eq!(hex::encode(&reveal), finish["sourceScript"]);
        let output = finish["outputScript"].as_str().unwrap().to_owned();
        let (tx, witness) = spend(
            &reveal,
            "KCOMSettlement",
            "finish_settlement",
            graph,
            &[output],
        );
        let successors =
            decode_settlement_successors(&tx, 0, &hex::decode(graph).unwrap(), &witness, &reveal)
                .unwrap();
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0].1["settlement_complete"], true);
        assert_eq!(successors[0].1["liability_raw"], before["liability_raw"]);

        let mut forged = tx.clone();
        forged.outputs[0]
            .script_public_key
            .replace_range(8..10, "ff");
        assert!(decode_settlement_successors(
            &forged,
            0,
            &hex::decode(graph).unwrap(),
            &witness,
            &reveal
        )
        .is_err());
        let mut wrong_total = before.clone();
        wrong_total.insert("settled_count".into(), json!("3"));
        let invalid_reveal = encoded_script(KnownTemplate::KcomSettlement, &wrong_total).unwrap();
        assert!(decode_settlement_successors(
            &tx,
            0,
            &hex::decode(graph).unwrap(),
            &witness,
            &invalid_reveal
        )
        .is_err());
    }

    #[test]
    fn vault_seal_matches_both_shared_builder_sources() {
        let vector = vector();
        let seal = &vector["vaultSeal"];
        assert_eq!(
            seal["sourceFixtureSha256"],
            "93f8fe414d86cf228de058e3008401562fd6accd158ba28e27610cc58c63fc33"
        );
        let graph = vector["graphId"].as_str().unwrap();
        let graph_id = hex::decode(graph).unwrap();
        let vault_reveal = hex::decode(seal["vaultSourceScript"].as_str().unwrap()).unwrap();
        let collector_reveal =
            hex::decode(seal["collectorSourceScript"].as_str().unwrap()).unwrap();
        let (mut tx, _) = spend(
            &vault_reveal,
            "KCOMVault",
            "seal",
            graph,
            &[seal["outputScript"].as_str().unwrap().to_owned()],
        );
        let (_, collector_witness) = spend(&collector_reveal, "KCOMSettlement", "seal", graph, &[]);
        tx.inputs[0].previous_outpoint_amount = Some(100_000_000);
        tx.inputs.push(
            serde_json::from_value(json!({
                "previous_outpoint_hash": "44".repeat(32),
                "previous_outpoint_index": "0",
                "previous_outpoint_amount": 500_000_000,
                "previous_outpoint_script": format!("aa20{}87", hex::encode(blake2b_256(&collector_reveal))),
                "signature_script": hex::encode(&collector_witness)
            }))
            .unwrap(),
        );
        tx.outputs[0].amount = 600_000_000;
        let successor =
            decode_vault_seal_successor(&tx, 0, 1, &graph_id, &vault_reveal, &collector_reveal)
                .unwrap();
        assert_eq!(successor.0, 0);
        assert_eq!(successor.1["modeName"], "KCOMVault");
        assert_eq!(successor.1["settled"], true);
        assert_eq!(successor.1["liability_raw"], seal["liabilityRaw"]);

        let mut diverted = tx.clone();
        diverted.outputs[0].amount -= 1;
        assert!(decode_vault_seal_successor(
            &diverted,
            0,
            1,
            &graph_id,
            &vault_reveal,
            &collector_reveal
        )
        .unwrap_err()
        .to_string()
        .contains("native KAS"));
        let mut forged = tx.clone();
        forged.outputs[0]
            .script_public_key
            .replace_range(8..10, "ff");
        assert!(decode_vault_seal_successor(
            &forged,
            0,
            1,
            &graph_id,
            &vault_reveal,
            &collector_reveal
        )
        .unwrap_err()
        .to_string()
        .contains("forged sealed vault script"));
        let mut extra = tx.clone();
        let mut rebound = extra.outputs[0].clone();
        rebound.index = 1;
        rebound.covenant.as_mut().unwrap().authorizing_input = Some(2);
        extra.outputs.push(rebound);
        assert!(decode_vault_seal_successor(
            &extra,
            0,
            1,
            &graph_id,
            &vault_reveal,
            &collector_reveal
        )
        .unwrap_err()
        .to_string()
        .contains("extra graph output"));
        let mut wrong_terms = KcomClaimDecoder::new(KnownTemplate::KcomSettlement)
            .decode_constructor(&collector_reveal)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        wrong_terms.insert("terms_hash".into(), json!("ff".repeat(32)));
        let wrong_reveal = encoded_script(KnownTemplate::KcomSettlement, &wrong_terms).unwrap();
        let mut mismatched = tx.clone();
        mismatched.inputs[1].previous_outpoint_script =
            Some(format!("aa20{}87", hex::encode(blake2b_256(&wrong_reveal))));
        assert!(decode_vault_seal_successor(
            &mismatched,
            0,
            1,
            &graph_id,
            &vault_reveal,
            &wrong_reveal
        )
        .unwrap_err()
        .to_string()
        .contains("seal terms differ"));
    }

    #[test]
    fn closed_shard_collection_matches_shared_builder_output() {
        let vector = vector();
        let collection = &vector["collection"];
        let graph = vector["graphId"].as_str().unwrap();
        let graph_id = hex::decode(graph).unwrap();
        let collector_reveal =
            hex::decode(collection["collectorSourceScript"].as_str().unwrap()).unwrap();
        let shard_reveal = hex::decode(collection["shardSourceScript"].as_str().unwrap()).unwrap();
        let collector_spk = format!("aa20{}87", hex::encode(blake2b_256(&collector_reveal)));
        let shard_spk = format!("aa20{}87", hex::encode(blake2b_256(&shard_reveal)));
        let tx: RestTransaction = serde_json::from_value(json!({
            "transaction_id": "aa".repeat(32),
            "version": 1,
            "is_accepted": true,
            "inputs": [
                {"previous_outpoint_hash":"bb".repeat(32),"previous_outpoint_index":"0",
                    "previous_outpoint_script":collector_spk,"previous_outpoint_amount":100000000,
                    "signature_script":collection["leaderWitness"]},
                {"previous_outpoint_hash":"cc".repeat(32),"previous_outpoint_index":"0",
                    "previous_outpoint_script":shard_spk,"previous_outpoint_amount":100000000,
                    "signature_script":collection["shardWitness"]}
            ],
            "outputs": [{"index":0,"amount":200000000,"script_public_key":collection["outputScript"],
                "covenant_authorizing_input":0,"covenant_id":graph}]
        })).unwrap();
        let successor = decode_settlement_collect_successor(
            &tx,
            0,
            1,
            &graph_id,
            &collector_reveal,
            &shard_reveal,
        )
        .unwrap();
        assert_eq!(successor.1["modeName"], "KCOMSettlement");
        assert_eq!(successor.1["next_shard"], "1");
        assert_eq!(successor.1["selected_count"], "1");
        assert_eq!(successor.1["all_weight"], "27");
        assert_eq!(successor.1["collection_complete"], true);
        let mut diverted = tx.clone();
        diverted.outputs[0].amount -= 1;
        assert!(decode_settlement_collect_successor(
            &diverted,
            0,
            1,
            &graph_id,
            &collector_reveal,
            &shard_reveal,
        )
        .unwrap_err()
        .to_string()
        .contains("collected native KAS"));
        let mut forged = tx.clone();
        forged.outputs[0]
            .script_public_key
            .replace_range(8..10, "ff");
        assert!(decode_settlement_collect_successor(
            &forged,
            0,
            1,
            &graph_id,
            &collector_reveal,
            &shard_reveal,
        )
        .unwrap_err()
        .to_string()
        .contains("forged collected settlement script"));
        let mut used = KcomClaimDecoder::new(KnownTemplate::KcomSettlement)
            .decode_constructor(&collector_reveal)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        used.insert("summaries_root".into(), json!("ff".repeat(32)));
        let stale_reveal = encoded_script(KnownTemplate::KcomSettlement, &used).unwrap();
        let mut stale = tx.clone();
        stale.inputs[0].previous_outpoint_script =
            Some(format!("aa20{}87", hex::encode(blake2b_256(&stale_reveal))));
        assert!(decode_settlement_collect_successor(
            &stale,
            0,
            1,
            &graph_id,
            &stale_reveal,
            &shard_reveal,
        )
        .unwrap_err()
        .to_string()
        .contains("summary slot"));
    }

    #[test]
    fn selected_commitment_settlement_matches_shared_builder_entitlement() {
        let vector = vector();
        let step = &vector["settlementStep"];
        assert_eq!(
            step["sourceFixtureSha256"],
            "df54c5f7495b02699bb536a88e70d3dd2a5afad17f9a9bb31cfd119a8d8f2191"
        );
        let graph = vector["graphId"].as_str().unwrap();
        let graph_id = hex::decode(graph).unwrap();
        let collector_reveal =
            hex::decode(step["collectorSourceScript"].as_str().unwrap()).unwrap();
        let commitment_reveal =
            hex::decode(step["commitmentSourceScript"].as_str().unwrap()).unwrap();
        let scripts = step["outputScripts"].as_array().unwrap();
        let tx: RestTransaction = serde_json::from_value(json!({
            "transaction_id":"aa".repeat(32),"version":1,"is_accepted":true,
            "inputs":[
                {"previous_outpoint_hash":"bb".repeat(32),"previous_outpoint_index":"0",
                    "previous_outpoint_amount":100000000,
                    "previous_outpoint_script":format!("aa20{}87",hex::encode(blake2b_256(&collector_reveal))),
                    "signature_script":step["leaderWitness"]},
                {"previous_outpoint_hash":"cc".repeat(32),"previous_outpoint_index":"0",
                    "previous_outpoint_amount":100000000,
                    "previous_outpoint_script":format!("aa20{}87",hex::encode(blake2b_256(&commitment_reveal))),
                    "signature_script":step["delegateWitness"]}
            ],
            "outputs":scripts.iter().enumerate().map(|(index, script)| json!({
                "index":index,"amount":100000000,"script_public_key":script,
                "covenant_authorizing_input":0,"covenant_id":graph
            })).collect::<Vec<_>>()
        })).unwrap();
        let successors = decode_settlement_claim_successors(
            &tx,
            0,
            1,
            &graph_id,
            &collector_reveal,
            &commitment_reveal,
        )
        .unwrap();
        assert_eq!(successors.len(), 2);
        assert_eq!(
            successors[0].1["settled_count"],
            step["nextState"]["settled_count"]
        );
        assert_eq!(
            successors[0].1["liability_raw"],
            step["nextState"]["liability_raw"]
        );
        assert_eq!(successors[1].1["modeName"], "KCOMEntitlement");
        assert_eq!(successors[1].1["total"], step["step"]["totalRaw"]);
        assert_eq!(
            successors[1].1["beneficiary"],
            step["entitlementState"]["beneficiary"]
        );
        let mut diverted = tx.clone();
        diverted.outputs[1].amount -= 1;
        assert!(decode_settlement_claim_successors(
            &diverted,
            0,
            1,
            &graph_id,
            &collector_reveal,
            &commitment_reveal,
        )
        .unwrap_err()
        .to_string()
        .contains("diverts native KAS"));
        let mut forged = tx.clone();
        forged.outputs[1]
            .script_public_key
            .replace_range(8..10, "ff");
        assert!(decode_settlement_claim_successors(
            &forged,
            0,
            1,
            &graph_id,
            &collector_reveal,
            &commitment_reveal,
        )
        .unwrap_err()
        .to_string()
        .contains("forged settlement successor script"));
        let mut wrong = KcomClaimDecoder::new(KnownTemplate::KcomSettlement)
            .decode_constructor(&collector_reveal)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        wrong.insert("summaries_root".into(), json!("ff".repeat(32)));
        let wrong_reveal = encoded_script(KnownTemplate::KcomSettlement, &wrong).unwrap();
        let mut altered = tx.clone();
        altered.inputs[0].previous_outpoint_script =
            Some(format!("aa20{}87", hex::encode(blake2b_256(&wrong_reveal))));
        assert!(decode_settlement_claim_successors(
            &altered,
            0,
            1,
            &graph_id,
            &wrong_reveal,
            &commitment_reveal,
        )
        .unwrap_err()
        .to_string()
        .contains("summary proof differs"));
    }
}

pub struct KcomClaimDecoder {
    template: KnownTemplate,
    #[cfg(test)]
    state_span: (usize, usize),
    template_hash: [u8; 32],
}

impl KcomClaimDecoder {
    pub fn new(template: KnownTemplate) -> Self {
        assert!(matches!(
            template,
            KnownTemplate::KcomInitialize
                | KnownTemplate::KcomFactory
                | KnownTemplate::KcomVault
                | KnownTemplate::KcomClaimShard
                | KnownTemplate::KcomSettlement
                | KnownTemplate::KcomClaimCommitment
                | KnownTemplate::KcomEntitlement
        ));
        let contract = &abi_for(template)["contracts"][crate::template_name(template)];
        let script: Vec<u8> = contract["compiled"]["bytecode"]
            .as_array()
            .expect("reviewed compiled bytecode")
            .iter()
            .map(|byte| byte.as_u64().expect("byte") as u8)
            .collect();
        let span = &contract["compiled"]["state_span"];
        let start = span["offset"].as_u64().expect("state offset") as usize;
        let len = span["len"].as_u64().expect("state length") as usize;
        let end = start.checked_add(len).expect("reviewed state span");
        assert!(end <= script.len(), "reviewed state span exceeds script");
        let mut masked = script.clone();
        masked[start..end].fill(0);
        Self {
            template,
            #[cfg(test)]
            state_span: (start, len),
            template_hash: blake2b_256(&masked),
        }
    }

    fn contract(&self) -> &'static Value {
        &abi_for(self.template)["contracts"][self.name()]
    }

    #[cfg(test)]
    fn compiled_script(&self) -> Vec<u8> {
        let script: Vec<u8> = self.contract()["compiled"]["bytecode"]
            .as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
        let (start, len) = self.span();
        let mut state = self.decode_payload(&script[start..start + len]).unwrap();
        for (field, actor) in [
            ("gen__kcom_claim_shard_template", "KCOMClaimShard"),
            ("gen__kcom_settlement_template", "KCOMSettlement"),
            ("gen__kcom_factory_template", "KCOMFactory"),
            ("gen__kcom_vault_template", "KCOMVault"),
            ("gen__kcom_claim_commitment_template", "KCOMClaimCommitment"),
            ("gen__kcom_entitlement_template", "KCOMEntitlement"),
        ] {
            if state.get(field).is_some() {
                let hash: Vec<u8> = abi_for(KnownTemplate::KcomFactory)["contracts"][actor]
                    ["compiled"]["template_hash"].as_array().unwrap()
                    .iter().map(|b| b.as_u64().unwrap() as u8).collect();
                state[field] = json!(hex::encode(hash));
            }
        }
        encoded_script(self.template, state.as_object().unwrap()).unwrap()
    }

    #[cfg(test)]
    fn span(&self) -> (usize, usize) {
        self.state_span
    }

    fn matched_profile(&self, script: &[u8]) -> Option<Profile> {
        for profile in Profile::ALL {
            let contract = &abi_for_profile(self.template, profile)["contracts"][self.name()];
            let bytes = contract["compiled"]["bytecode"].as_array()?;
            let span = &contract["compiled"]["state_span"];
            let start = span["offset"].as_u64()? as usize;
            let len = span["len"].as_u64()? as usize;
            if script.len() != bytes.len() || start.checked_add(len)? > script.len() {
                continue;
            }
            // Match executable bytes exactly, including the selected timing constants.
            if script[..start].iter().zip(&bytes[..start]).any(|(a,b)| Some(u64::from(*a)) != b.as_u64())
                || script[start+len..].iter().zip(&bytes[start+len..]).any(|(a,b)| Some(u64::from(*a)) != b.as_u64()) {
                continue;
            }
            let state = self.decode_payload(&script[start..start+len]).ok()?;
            let graph = abi_for_profile(KnownTemplate::KcomFactory, profile);
            // Shared factory code must select its ABI from authenticated generated
            // template commitments. An unsupported family stays unknown to the indexer.
            let compatible = [
                ("gen__kcom_claim_shard_template", "KCOMClaimShard"),
                ("gen__kcom_settlement_template", "KCOMSettlement"),
                ("gen__kcom_factory_template", "KCOMFactory"),
                ("gen__kcom_vault_template", "KCOMVault"),
                ("gen__kcom_claim_commitment_template", "KCOMClaimCommitment"),
                ("gen__kcom_entitlement_template", "KCOMEntitlement"),
            ].iter().all(|(field, actor)| {
                let Some(value) = state.get(*field) else { return true; };
                let expected: Option<Vec<u8>> = graph["contracts"][*actor]["compiled"]["template_hash"]
                    .as_array().map(|bytes| bytes.iter().map(|b| b.as_u64().and_then(|v| u8::try_from(v).ok())).collect()).flatten();
                expected.is_some_and(|hash| value.as_str() == Some(hex::encode(hash).as_str()))
            });
            if compatible { return Some(profile); }
        }
        None
    }

    fn decode_payload(&self, mut bytes: &[u8]) -> Result<Value> {
        let mut state = Map::new();
        for field in self.contract()["runtime_state"]["fields"]
            .as_array()
            .expect("reviewed runtime fields")
        {
            let kind = field["type"]["kind"].as_str().expect("field kind");
            let width = match kind {
                "fixed_bytes" => field["type"]["len"].as_u64().expect("fixed width") as usize,
                "int" => 8,
                "byte" | "bool" => 1,
                _ => return Err(anyhow!("unsupported campaign ABI type")),
            };
            ensure!(
                bytes.len() > width && bytes[0] as usize == width,
                "noncanonical campaign state field"
            );
            let value = &bytes[1..1 + width];
            let decoded = match kind {
                "int" => json!(parse_minimal_int(value).to_string()),
                "byte" => json!(value[0]),
                "bool" => {
                    ensure!(value[0] <= 1, "noncanonical campaign boolean");
                    json!(value[0] == 1)
                }
                _ => json!(hex::encode(value)),
            };
            state.insert(field["name"].as_str().expect("field name").into(), decoded);
            bytes = &bytes[width + 1..];
        }
        ensure!(bytes.is_empty(), "trailing campaign state bytes");
        let mut result = Value::Object(state);
        result["campaignId"] = result["campaign"].clone();
        result["canonicalTokenId"] = result["token_id"].clone();
        result["modeName"] = json!(self.name());
        if result.get("beneficiary").is_some() {
            result["stateOwner"] = result["beneficiary"].clone();
            result["stateOwnerType"] = result["beneficiary_scheme"].clone();
        }
        Ok(result)
    }
}

fn same_artifact_profile(left: &Map<String, Value>, right: &Map<String, Value>) -> Result<()> {
    ensure!(Profile::from_state(left)? == Profile::from_state(right)?,
        "campaign actor artifact profiles differ");
    Ok(())
}

fn encoded_script(template: KnownTemplate, state: &Map<String, Value>) -> Result<Vec<u8>> {
    let decoder = KcomClaimDecoder::new(template);
    let profile = Profile::from_state(state)?;
    let contract = &abi_for_profile(template, profile)["contracts"][decoder.name()];
    let mut script: Vec<u8> = contract["compiled"]["bytecode"].as_array().context("compiled campaign bytes")?
        .iter().map(|b| b.as_u64().expect("compiled byte") as u8).collect();
    let span = &contract["compiled"]["state_span"];
    let (start, len) = (span["offset"].as_u64().context("state offset")? as usize,
        span["len"].as_u64().context("state len")? as usize);
    let mut offset = start;
    for field in decoder.contract()["runtime_state"]["fields"]
        .as_array()
        .context("campaign runtime fields")?
    {
        let name = field["name"].as_str().context("campaign field name")?;
        let value = state.get(name).with_context(|| format!("missing {name}"))?;
        let bytes = match field["type"]["kind"].as_str() {
            Some("fixed_bytes") => hex::decode(value.as_str().context("campaign bytes")?)?,
            Some("int") => value
                .as_str()
                .context("campaign integer")?
                .parse::<i64>()?
                .to_le_bytes()
                .to_vec(),
            Some("byte") => vec![u8::try_from(value.as_u64().context("campaign byte")?)?],
            Some("bool") => vec![u8::from(value.as_bool().context("campaign boolean")?)],
            _ => return Err(anyhow!("unsupported campaign ABI type")),
        };
        ensure!(
            offset + bytes.len() < start + len && script[offset] == u8::try_from(bytes.len())?,
            "campaign state encoding differs from ABI"
        );
        script[offset + 1..offset + 1 + bytes.len()].copy_from_slice(&bytes);
        offset += bytes.len() + 1;
    }
    ensure!(
        offset == start + len,
        "campaign state span differs from ABI"
    );
    ensure!(
        decoder.matches_reveal_script(&script),
        "campaign template changed"
    );
    Ok(script)
}

fn copy_fields(source: &Map<String, Value>, names: &[&str]) -> Result<Map<String, Value>> {
    let mut result = Map::new();
    if let Some(profile) = source.get("artifactProfile") {
        result.insert("artifactProfile".into(), profile.clone());
    }
    for name in names {
        result.insert(
            (*name).into(),
            source
                .get(*name)
                .with_context(|| format!("missing {name}"))?
                .clone(),
        );
    }
    Ok(result)
}

/// Reconstruct the two graph genesis cells from an accepted initializer spend.
/// Their scripts are visible before either actor reveals its own code.
pub fn decode_initialize_successors(
    tx: &RestTransaction,
    input_index: usize,
    signature_script: &[u8],
    reveal: &[u8],
    source_script: &[u8],
    source_amount: u64,
) -> Result<(Vec<u8>, Vec<(i32, Value)>)> {
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomInitialize);
    ensure!(decoder.decode_action(signature_script).as_deref() == Some("initialize"),
        "initializer action differs from reviewed ABI");
    tx.inputs.get(input_index).context("missing initializer input")?;
    ensure!(p2sh_script_hash(source_script) == Some(blake2b_256(reveal)),
        "initializer reveal differs from indexed source");
    let initial = decoder.decode_constructor(reveal)?;
    let initial = initial.as_object().context("initializer state")?;
    let items = script_items(args_prefix_before_reveal(signature_script));
    let configurable = Profile::from_state(initial)? == Profile::ConfigurableV2;
    ensure!(items.len() == if configurable { 24 } else { 12 }, "initializer witness differs from reviewed ABI");
    let terms = witness_bytes(&items, 4)?;
    ensure!(terms.len() == (if configurable { 373 } else { 277 })
        && hex::encode(blake3::hash(&terms).as_bytes())
            == initial["terms_hash"].as_str().unwrap_or(""),
        "initializer terms digest differs");

    let graph_id = compute_genesis_covenant_id_for_outputs_at_input(tx, input_index, &[0, 1])
        .context("initializer graph covenant ID is not derivable")?;
    let graph = hex::decode(&graph_id)?;
    ensure!(source_amount > 100_000_000, "initializer KAS is too small");
    ensure!(tx.outputs.iter().filter(|out|
        out.covenant_authorizing_input() == Some(u16::try_from(input_index).unwrap_or(u16::MAX))
    ).count() == 2, "initializer creates extra bound outputs");

    let mut state = initial.clone();
    for (name, template) in [
        ("gen__kcom_claim_shard_template", KnownTemplate::KcomClaimShard),
        ("gen__kcom_settlement_template", KnownTemplate::KcomSettlement),
        ("gen__kcom_factory_template", KnownTemplate::KcomFactory),
        ("gen__kcom_vault_template", KnownTemplate::KcomVault),
        ("gen__kcom_claim_commitment_template", KnownTemplate::KcomClaimCommitment),
        ("gen__kcom_entitlement_template", KnownTemplate::KcomEntitlement),
    ] {
        let hash = abi_for_profile(template, Profile::from_state(initial)?)["contracts"][crate::template_name(template)]["compiled"]["template_hash"]
            .as_array().context("reviewed generated template hash missing")?
            .iter().map(|byte| -> Result<u8> {
                Ok(u8::try_from(byte.as_u64().context("template hash byte")?)?)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(hash.len() == 32, "generated template hash width differs");
        state.insert(name.into(), json!(hex::encode(hash)));
    }
    state.insert("next_shard".into(), json!("0"));
    state.insert("opened".into(), json!(false));
    state.insert("extension".into(), json!(hex::encode(&terms[132..164])));
    state.insert("treasury_scheme".into(), json!(terms[212]));
    state.insert("treasury".into(), json!(hex::encode(&terms[213..245])));
    for name in ["funded", "settled", "recovered"] {
        state.insert(name.into(), json!(false));
    }
    for name in ["liability_raw", "activated_raw"] {
        state.insert(name.into(), json!("0"));
    }
    let mut outputs = Vec::with_capacity(2);
    for (index, template, amount) in [
        (0, KnownTemplate::KcomFactory, source_amount - 100_000_000),
        (1, KnownTemplate::KcomVault, 100_000_000),
    ] {
        let output = tx.outputs.iter().find(|out| out.index == index)
            .context("initializer graph output missing")?;
        ensure!(output.amount == amount
            && output.covenant_authorizing_input() == Some(u16::try_from(input_index)?)
            && output.canonical_covenant_id() == Some(graph_id.as_str()),
            "initializer graph output amount or lineage differs");
        let script = encoded_script(template, &state)?;
        ensure!(p2sh_script_hash(&hex::decode(&output.script_public_key)?)
            == Some(blake2b_256(&script)),
            "initializer graph output script differs from approved state");
        outputs.push((i32::try_from(index)?, KcomClaimDecoder::new(template).decode_constructor(&script)?));
    }
    Ok((graph, outputs))
}

/// Infer only factory-created outputs whose complete scripts follow from the revealed factory
/// state. Other campaign transitions still require separately authenticated inference.
pub fn decode_factory_successors(
    tx: &RestTransaction,
    input_index: usize,
    covenant_id: &[u8],
    signature_script: &[u8],
    reveal: &[u8],
) -> Result<Vec<(i32, Value)>> {
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomFactory);
    let state = decoder.decode_constructor(reveal)?;
    let state = state.as_object().context("factory state")?;
    let action = decoder
        .decode_action(signature_script)
        .context(crate::InterpretationFailure("unknown factory action"))?;
    let input_index = u16::try_from(input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(input_index))
        .collect::<Vec<_>>();
    let mut successors = Vec::new();
    let generated_commitment = "gen__kcom_claim_commitment_template";
    let generated_settlement = "gen__kcom_settlement_template";
    let common = [
        "campaign",
        "terms_hash",
        "token_id",
        "budget_raw",
        "manifest_total",
        "eligibility_root",
        "leaf_count",
        "shard_count",
        "first",
        "second",
        "third",
        "opens_ms",
        "closes_ms",
        "tge_ms",
    ];
    let expected = match action.as_str() {
        "open" => {
            ensure!(authorized.len() == 2, "factory open needs two outputs");
            ensure!(
                state["opened"] == false && state["next_shard"] == "0",
                "factory is not ready to open"
            );
            let mut factory = state.clone();
            factory.insert("opened".into(), json!(true));
            // The vault's extension and treasury are committed by its own input, not by
            // the factory state. Only the factory successor can be reconstructed here.
            vec![(KnownTemplate::KcomFactory, factory)]
        }
        "create_shard" => {
            ensure!(authorized.len() == 2, "factory create needs two outputs");
            let next = state["next_shard"]
                .as_str()
                .context("next shard")?
                .parse::<i64>()?;
            let count = state["shard_count"]
                .as_str()
                .context("shard count")?
                .parse::<i64>()?;
            ensure!(
                state["opened"] == true && next >= 0 && next < count,
                "factory cannot create shard"
            );
            let mut factory = state.clone();
            factory.insert(
                "next_shard".into(),
                json!(next.checked_add(1).context("shard overflow")?.to_string()),
            );
            let mut shard = copy_fields(state, &common)?;
            for name in [generated_commitment, generated_settlement] {
                shard.insert(name.into(), state[name].clone());
            }
            shard.insert("used_root".into(), state["empty_used_root"].clone());
            for name in [
                "selected_count",
                "all_weight",
                "boosted_weight",
                "long_weight",
            ] {
                shard.insert(name.into(), json!("0"));
            }
            shard.insert("shard".into(), json!(next.to_string()));
            shard.insert("closed".into(), json!(false));
            vec![
                (KnownTemplate::KcomFactory, factory),
                (KnownTemplate::KcomClaimShard, shard),
            ]
        }
        "finish_initialization" => {
            ensure!(authorized.len() == 1, "factory finish needs one output");
            ensure!(
                state["opened"] == true && state["next_shard"] == state["shard_count"],
                "factory shards are incomplete"
            );
            let mut collector = copy_fields(state, &common)?;
            for name in [
                generated_commitment,
                "gen__kcom_claim_shard_template",
                "gen__kcom_entitlement_template",
                "gen__kcom_vault_template",
            ] {
                collector.insert(name.into(), state[name].clone());
            }
            collector.insert(
                "summaries_root".into(),
                state["empty_summaries_root"].clone(),
            );
            for name in [
                "next_shard",
                "selected_count",
                "all_weight",
                "boosted_weight",
                "long_weight",
                "settled_count",
                "liability_raw",
            ] {
                collector.insert(name.into(), json!("0"));
            }
            collector.insert("collection_complete".into(), json!(false));
            collector.insert("settlement_complete".into(), json!(false));
            vec![(KnownTemplate::KcomSettlement, collector)]
        }
        _ => return Err(anyhow!(crate::InterpretationFailure("unsupported factory action"))),
    };
    for ((template, next_state), output) in expected.into_iter().zip(authorized) {
        let id = output
            .canonical_covenant_id()
            .context("missing campaign successor ID")?;
        ensure!(
            hex::decode(id)? == covenant_id,
            "wrong campaign successor lineage"
        );
        let script = encoded_script(template, &next_state)?;
        let spk = hex::decode(&output.script_public_key)?;
        ensure!(
            p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
            "forged {} successor script: expected {}, observed {}",
            KcomClaimDecoder::new(template).name(),
            hex::encode(blake2b_256(&script)),
            p2sh_script_hash(&spk).map(hex::encode).unwrap_or_default(),
        );
        let state = KcomClaimDecoder::new(template).decode_constructor(&script)?;
        successors.push((i32::try_from(output.index)?, state));
    }
    Ok(successors)
}

/// Opening spends the factory and its separately funded vault. The factory reveal alone cannot
/// determine the vault's extension or treasury, so both authenticated source scripts are needed.
pub fn decode_vault_open_successor(
    tx: &RestTransaction,
    factory_input_index: usize,
    vault_input_index: usize,
    covenant_id: &[u8],
    factory_reveal: &[u8],
    vault_reveal: &[u8],
) -> Result<(i32, Value)> {
    ensure!(factory_input_index < vault_input_index, "factory must lead vault in open");
    let factory_input = tx.inputs.get(factory_input_index).context("missing factory input")?;
    let vault_input = tx.inputs.get(vault_input_index).context("missing vault input")?;
    let factory_decoder = KcomClaimDecoder::new(KnownTemplate::KcomFactory);
    let vault_decoder = KcomClaimDecoder::new(KnownTemplate::KcomVault);
    for (input, reveal, decoder) in [
        (factory_input, factory_reveal, &factory_decoder),
        (vault_input, vault_reveal, &vault_decoder),
    ] {
        let signature = hex::decode(&input.signature_script)?;
        ensure!(decoder.decode_action(&signature).as_deref() == Some("open"),
            "opening requires both graph actors");
        let script_hex = input.previous_outpoint_script.as_deref()
            .context("opening source script is missing")?;
        let script = hex::decode(script_hex.strip_prefix("0000").unwrap_or(script_hex))?;
        ensure!(p2sh_script_hash(&script) == Some(blake2b_256(reveal)),
            "opening reveal differs from authenticated source script");
    }
    let factory = factory_decoder.decode_constructor(factory_reveal)?;
    let vault = vault_decoder.decode_constructor(vault_reveal)?;
    let factory = factory.as_object().context("factory state")?;
    let vault = vault.as_object().context("vault state")?;
    same_artifact_profile(factory, vault)?;
    ensure!(factory["opened"] == false && factory["next_shard"] == "0"
        && vault["funded"] == true && vault["opened"] == false
        && vault["settled"] == false && vault["recovered"] == false
        && vault["liability_raw"] == "0" && vault["activated_raw"] == "0",
        "campaign actors are not ready to open");
    for name in ["campaign", "terms_hash", "token_id", "budget_raw", "tge_ms",
        "first", "second", "third"] {
        ensure!(factory[name] == vault[name], "opening terms differ at {name}");
    }
    let family_outputs = tx.outputs.iter().filter(|output| {
        output.canonical_covenant_id()
            .and_then(|id| hex::decode(id).ok())
            .is_some_and(|id| id == covenant_id)
    }).collect::<Vec<_>>();
    ensure!(family_outputs.len() == 2, "opening needs exactly two graph outputs");
    let factory_authorizer = u16::try_from(factory_input_index)?;
    let vault_authorizer = u16::try_from(vault_input_index)?;
    ensure!(tx.outputs.iter().filter(|output|
        output.covenant_authorizing_input() == Some(factory_authorizer)).count() == 2,
        "opening created an extra factory-authorized output");
    for (index, input) in [(0, factory_input), (1, vault_input)] {
        let output = family_outputs[index];
        ensure!(output.index == index as u64
            && output.covenant_authorizing_input() == Some(factory_authorizer)
            && output.canonical_covenant_id()
                .and_then(|id| hex::decode(id).ok()).is_some_and(|id| id == covenant_id),
            "opening output order or lineage differs");
        let source_amount = input.previous_outpoint_amount.context("opening source amount is missing")?;
        ensure!(output.amount == source_amount, "opening changed native KAS");
    }
    ensure!(tx.outputs.iter().all(|output|
        output.covenant_authorizing_input() != Some(vault_authorizer)),
        "opening created a vault-authorized output");
    let mut next_factory = factory.clone();
    next_factory.insert("opened".into(), json!(true));
    let factory_script = encoded_script(KnownTemplate::KcomFactory, &next_factory)?;
    let factory_spk = hex::decode(&family_outputs[0].script_public_key)?;
    ensure!(p2sh_script_hash(&factory_spk) == Some(blake2b_256(&factory_script)),
        "forged opened factory script");
    let mut next = vault.clone();
    next.insert("opened".into(), json!(true));
    let script = encoded_script(KnownTemplate::KcomVault, &next)?;
    let output = family_outputs[1];
    let spk = hex::decode(&output.script_public_key)?;
    ensure!(p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
        "forged opened vault script");
    Ok((i32::try_from(output.index)?, vault_decoder.decode_constructor(&script)?))
}

/// Funding locks the configured canonical token reserve to its still-unopened graph vault.
/// Both source scripts and native amounts must be obtained from indexed UTXOs by the caller.
pub fn decode_vault_fund_successors(
    tx: &RestTransaction,
    vault_input_index: usize,
    token_input_index: usize,
    graph_id: &[u8],
    token_id: &[u8],
    vault_reveal: &[u8],
    token_reveal: &[u8],
) -> Result<((i32, Value), (i32, Value))> {
    ensure!(vault_input_index < token_input_index, "vault must lead token in funding");
    ensure!(graph_id.len() == 32 && token_id.len() == 32, "invalid funding ID");
    let vault_input = tx.inputs.get(vault_input_index).context("missing funding vault")?;
    let token_input = tx.inputs.get(token_input_index).context("missing funding token")?;
    for (input, reveal) in [(vault_input, vault_reveal), (token_input, token_reveal)] {
        let spk = input.previous_outpoint_script.as_deref()
            .context("indexed funding source script missing")?;
        let spk = hex::decode(spk.strip_prefix("0000").unwrap_or(spk))?;
        ensure!(p2sh_script_hash(&spk) == Some(blake2b_256(reveal)),
            "funding reveal differs from indexed source");
        ensure!(input.previous_outpoint_amount.is_some(), "indexed funding source KAS missing");
    }
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomVault);
    let signature = hex::decode(&vault_input.signature_script)?;
    ensure!(decoder.decode_action(&signature).as_deref() == Some("fund"),
        "wrong vault funding action");
    let vault = decoder.decode_constructor(vault_reveal)?;
    let vault = vault.as_object().context("vault state")?;
    let budget = vault["budget_raw"].as_str().context("vault budget")?.parse::<i64>()?;
    ensure!(vault["funded"] == false && vault["opened"] == false
        && vault["settled"] == false && vault["recovered"] == false
        && vault["liability_raw"] == "0" && vault["activated_raw"] == "0"
        && budget > 0 && budget <= 10_000_000_000_000_000,
        "vault is not ready for funding");
    ensure!(hex::decode(vault["token_id"].as_str().context("vault token ID")?)? == token_id,
        "funding token ID differs");
    let token = kcc20_standard::decode_reveal_state(token_reveal)?;
    ensure!(hex::encode(
        kcc20_standard::Kcc20StandardDecoder::template_hash_of_compiled_script(token_reveal)?
    ) == "5d6cacdf57c734536fcb8a9c833f0318671226727ec77c503a98fc5be59f9e29",
        "funding token template differs from canonical KCC20");
    ensure!(token.amount.parse::<i64>()? == budget
        && token.owner_scheme == 4 && token.owner == hex::encode(graph_id)
        && token.borrow_scheme == 0 && token.borrow_guard == "00".repeat(32)
        && token.extension_commitment == vault["extension"],
        "funding token is not the configured graph reserve");
    ensure!(tx.outputs.len() == 3, "funding output count differs");
    let vault_out = &tx.outputs[0];
    let token_out = &tx.outputs[1];
    ensure!(vault_out.index == 0
        && vault_out.covenant_authorizing_input() == Some(u16::try_from(vault_input_index)?)
        && vault_out.canonical_covenant_id()
            .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(graph_id))
        && vault_out.amount == vault_input.previous_outpoint_amount.context("vault KAS")?,
        "funded vault output changes lineage or native KAS");
    let mut next = vault.clone();
    next.insert("funded".into(), json!(true));
    let vault_script = encoded_script(KnownTemplate::KcomVault, &next)?;
    ensure!(p2sh_script_hash(&hex::decode(&vault_out.script_public_key)?)
        == Some(blake2b_256(&vault_script)), "forged funded vault script");
    ensure!(token_out.index == 1
        && token_out.covenant_authorizing_input() == Some(u16::try_from(token_input_index)?)
        && token_out.canonical_covenant_id()
            .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(token_id))
        && token_out.amount == token_input.previous_outpoint_amount.context("token KAS")?,
        "funded token output changes lineage or native KAS");
    let token_state = json!({
        "amount": budget.to_string(), "owner": hex::encode(graph_id),
        "ownerScheme": 4, "borrowScheme": 0, "borrowGuard": "00".repeat(32),
        "extensionCommitment": vault["extension"],
    });
    let token_script = kcc20_standard::script_for_state_value_with_reveal(&token_state, token_reveal)?;
    ensure!(p2sh_script_hash(&hex::decode(&token_out.script_public_key)?)
        == Some(blake2b_256(&token_script)), "forged funded token script");
    ensure!(tx.outputs[2].canonical_covenant_id().is_none(),
        "funding sponsor change adds a covenant output");
    Ok(((i32::try_from(vault_out.index)?, decoder.decode_constructor(&vault_script)?),
        (i32::try_from(token_out.index)?, token_state)))
}

fn campaign_digest(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("kcom.claim.{domain}/v1\0").as_bytes());
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn witness_bytes(items: &[ScriptItem], index: usize) -> Result<Vec<u8>> {
    crate::interpretation("kcom_claim.rs:witness_bytes", (|| {
    match items.get(index) {
        Some(ScriptItem::Data(bytes)) => Ok(bytes.clone()),
        Some(ScriptItem::Int(0)) => Ok(Vec::new()),
        _ => Err(anyhow!("invalid selection witness item {index}")),
    }

    })())
}

fn fold_campaign_proof(
    mut leaf: [u8; 32],
    mut index: u32,
    proof: &[u8],
    domain: &str,
) -> Result<[u8; 32]> {
    ensure!(proof.len() % 32 == 0, "invalid campaign proof width");
    for sibling in proof.chunks_exact(32) {
        leaf = if index & 1 == 0 {
            campaign_digest(domain, &[&leaf, sibling])
        } else {
            campaign_digest(domain, &[sibling, &leaf])
        };
        index >>= 1;
    }
    Ok(leaf)
}

fn selection_states(
    state: &Map<String, Value>,
    signature_script: &[u8],
) -> Result<(Map<String, Value>, Map<String, Value>)> {
    let items = script_items(args_prefix_before_reveal(signature_script));
    ensure!(items.len() == 14, "selection witness differs from ABI");
    let signature = witness_bytes(&items, 0)?;
    ensure!(signature.len() == 65, "invalid selection signature width");
    let authority = witness_bytes(&items, 1)?;
    ensure!(authority.len() == 32, "invalid selection authority width");
    let index = crate::kcc20::item_integer::<u32>(&items, 2)?;
    let weight = crate::kcc20::item_integer::<u64>(&items, 3)?;
    let tier = crate::kcc20::item_integer::<u8>(&items, 4)?;
    let scheme = crate::kcc20::item_integer::<u8>(&items, 5)?;
    let beneficiary = witness_bytes(&items, 6)?;
    ensure!(beneficiary.len() == 32, "invalid beneficiary width");
    let membership = witness_bytes(&items, 7)?;
    let unused = witness_bytes(&items, 8)?;
    let depth = crate::kcc20::item_integer::<usize>(&items, 9)?;
    let route = crate::kcc20::item_integer::<u32>(&items, 10)?;
    let leaf_count = state["leaf_count"]
        .as_str()
        .context("leaf count")?
        .parse::<u32>()?;
    let shard_count = state["shard_count"]
        .as_str()
        .context("shard count")?
        .parse::<u32>()?;
    let shard = state["shard"].as_str().context("shard")?.parse::<u32>()?;
    let mut expected_depth = 0usize;
    let mut width = 1u32;
    while width < leaf_count {
        width = width.checked_mul(2).context("leaf tree overflow")?;
        expected_depth += 1;
    }
    ensure!(
        !leaf_count.eq(&0)
            && leaf_count <= 1_048_576
            && index < leaf_count
            && depth == expected_depth
            && depth <= 20
            && membership.len() == depth * 32
            && unused.len() == depth * 32,
        "invalid selection proof shape"
    );
    ensure!(
        state["closed"] == false
            && shard_count > 0
            && shard < shard_count
            && weight > 0
            && weight <= 2_000_000_000_000_000
            && (1..=3).contains(&tier)
            && scheme <= 4,
        "invalid shard selection terms"
    );
    let campaign = hex::decode(state["campaign"].as_str().context("campaign")?)?;
    let eligibility_root = hex::decode(
        state["eligibility_root"]
            .as_str()
            .context("eligibility root")?,
    )?;
    let used_root = hex::decode(state["used_root"].as_str().context("used root")?)?;
    ensure!(
        campaign.len() == 32 && eligibility_root.len() == 32 && used_root.len() == 32,
        "invalid selection root width"
    );
    let index_bytes = index.to_le_bytes();
    let weight_bytes = weight.to_le_bytes();
    let eligible = campaign_digest(
        "eligibility.leaf",
        &[&campaign, &index_bytes, &[0], &authority, &weight_bytes],
    );
    ensure!(
        fold_campaign_proof(eligible, index, &membership, "eligibility.node")?
            == eligibility_root.as_slice(),
        "selection membership proof differs from root"
    );
    let empty = campaign_digest("used.empty", &[&campaign, &index_bytes]);
    ensure!(
        fold_campaign_proof(empty, index, &unused, "used.node")? == used_root.as_slice(),
        "selection slot has already been used"
    );
    let identity = campaign_digest("nullifier", &[&campaign, &[0], &authority]);
    ensure!(
        u32::from_le_bytes(identity[..4].try_into()?) == route && route % shard_count == shard,
        "selection routes to another shard"
    );
    let selection = campaign_digest(
        "selection",
        &[
            &campaign,
            &eligibility_root,
            &identity,
            &[tier, scheme],
            &beneficiary,
        ],
    );
    let used = campaign_digest("used.leaf", &[&campaign, &index_bytes, &selection]);
    let next_root = fold_campaign_proof(used, index, &unused, "used.node")?;
    let prior = |name: &str| -> Result<i64> {
        Ok(state[name]
            .as_str()
            .with_context(|| format!("missing {name}"))?
            .parse::<i64>()?)
    };
    let manifest_total = prior("manifest_total")?;
    let weight = i64::try_from(weight)?;
    let selected = prior("selected_count")?
        .checked_add(1)
        .context("selected overflow")?;
    let all = prior("all_weight")?
        .checked_add(weight)
        .context("weight overflow")?;
    let boosted = prior("boosted_weight")?
        .checked_add(if tier >= 2 { weight } else { 0 })
        .context("boosted overflow")?;
    let long = prior("long_weight")?
        .checked_add(if tier == 3 { weight } else { 0 })
        .context("long overflow")?;
    ensure!(
        selected <= i64::from(leaf_count)
            && all <= manifest_total
            && boosted <= all
            && long <= boosted,
        "selection exceeds frozen totals"
    );
    let mut next = state.clone();
    next.insert("used_root".into(), json!(hex::encode(next_root)));
    for (name, value) in [
        ("selected_count", selected),
        ("all_weight", all),
        ("boosted_weight", boosted),
        ("long_weight", long),
    ] {
        next.insert(name.into(), json!(value.to_string()));
    }
    let mut commitment = copy_fields(
        state,
        &[
            "gen__kcom_settlement_template",
            "campaign",
            "terms_hash",
            "token_id",
            "tge_ms",
            "budget_raw",
            "manifest_total",
            "eligibility_root",
            "leaf_count",
            "shard",
            "shard_count",
        ],
    )?;
    for (name, value) in [
        ("index", json!(index.to_string())),
        ("original_authority", json!(hex::encode(authority))),
        ("identity", json!(hex::encode(identity))),
        ("weight", json!(weight.to_string())),
        ("tier", json!(tier.to_string())),
        ("beneficiary_scheme", json!(scheme)),
        ("beneficiary", json!(hex::encode(beneficiary))),
    ] {
        commitment.insert(name.into(), value);
    }
    Ok((next, commitment))
}

/// Public projection of a selection after its accepted transaction and exact successor scripts
/// have been verified by `decode_shard_successors`. The authorization signature and Merkle
/// witness remain in the accepted transaction.
pub fn decode_selection_action_details(signature_script: &[u8], reveal: &[u8]) -> Result<Value> {
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomClaimShard);
    ensure!(decoder.decode_action(signature_script).as_deref() == Some("select"),
        "selection action is required");
    let state = decoder.decode_constructor(reveal)?;
    let state = state.as_object().context("selection shard state")?;
    let (next, commitment) = selection_states(state, signature_script)?;
    let campaign = hex::decode(state["campaign"].as_str().context("campaign")?)?;
    let root = hex::decode(state["eligibility_root"].as_str().context("eligibility root")?)?;
    let identity = hex::decode(commitment["identity"].as_str().context("selection identity")?)?;
    let tier = commitment["tier"].as_str().context("selection tier")?.parse::<u8>()?;
    let scheme = u8::try_from(commitment["beneficiary_scheme"].as_u64()
        .context("beneficiary scheme")?)?;
    let beneficiary = hex::decode(commitment["beneficiary"].as_str()
        .context("beneficiary")?)?;
    let digest = campaign_digest("selection", &[
        &campaign, &root, &identity, &[tier, scheme], &beneficiary,
    ]);
    Ok(json!({
        "leafIndex": commitment["index"].as_str().context("leaf index")?.parse::<u32>()?,
        "shard": state["shard"],
        "originalAuthority": commitment["original_authority"],
        "selectionDigest": hex::encode(digest),
        "usedRootBefore": state["used_root"],
        "usedRootAfter": next["used_root"],
    }))
}

/// Selection reconstructs the shard and commitment from verified proofs; closing fixes one
/// script-hash-verified successor, and collection consumes the shard without a successor.
pub fn decode_shard_successors(
    tx: &RestTransaction,
    input_index: usize,
    covenant_id: &[u8],
    signature_script: &[u8],
    reveal: &[u8],
) -> Result<Vec<(i32, Value)>> {
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomClaimShard);
    let state = decoder.decode_constructor(reveal)?;
    let state = state.as_object().context("claim shard state")?;
    let action = decoder
        .decode_action(signature_script)
        .context(crate::InterpretationFailure("unknown shard action"))?;
    let input_index = u16::try_from(input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(input_index))
        .collect::<Vec<_>>();
    if action == "select" {
        ensure!(authorized.len() == 2, "selection needs two outputs");
        let (next, commitment) = selection_states(state, signature_script)?;
        let mut successors = Vec::new();
        for ((template, next_state), output) in [
            (KnownTemplate::KcomClaimShard, next),
            (KnownTemplate::KcomClaimCommitment, commitment),
        ]
        .into_iter()
        .zip(authorized)
        {
            let id = output
                .canonical_covenant_id()
                .context("missing selection successor ID")?;
            ensure!(hex::decode(id)? == covenant_id, "wrong selection lineage");
            let script = encoded_script(template, &next_state)?;
            let spk = hex::decode(&output.script_public_key)?;
            ensure!(
                p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
                "forged selection successor script"
            );
            successors.push((
                i32::try_from(output.index)?,
                KcomClaimDecoder::new(template).decode_constructor(&script)?,
            ));
        }
        return Ok(successors);
    }
    if action == "collect" {
        ensure!(authorized.is_empty(), "collected shard has a successor");
        return Ok(vec![]);
    }
    ensure!(action == "close", crate::InterpretationFailure("unsupported shard action"));
    ensure!(authorized.len() == 1, "shard close needs one output");
    ensure!(state["closed"] == false, "shard already closed");
    let output = authorized[0];
    let id = output
        .canonical_covenant_id()
        .context("missing closed shard covenant ID")?;
    ensure!(
        hex::decode(id)? == covenant_id,
        "wrong closed shard lineage"
    );
    let mut next_state = state.clone();
    next_state.insert("closed".into(), json!(true));
    let script = encoded_script(KnownTemplate::KcomClaimShard, &next_state)?;
    let spk = hex::decode(&output.script_public_key)?;
    ensure!(
        p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
        "forged closed shard script"
    );
    Ok(vec![(
        i32::try_from(output.index)?,
        decoder.decode_constructor(&script)?,
    )])
}

/// Infer the finalized collector before its next spend. Collection and per-claim settlement
/// require proof-derived state; sealing consumes the collector without its own successor.
pub fn decode_settlement_successors(
    tx: &RestTransaction,
    input_index: usize,
    covenant_id: &[u8],
    signature_script: &[u8],
    reveal: &[u8],
) -> Result<Vec<(i32, Value)>> {
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomSettlement);
    let state = decoder.decode_constructor(reveal)?;
    let state = state.as_object().context("settlement state")?;
    let action = decoder
        .decode_action(signature_script)
        .context(crate::InterpretationFailure("unknown settlement action"))?;
    let input_index = u16::try_from(input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(input_index))
        .collect::<Vec<_>>();
    match action.as_str() {
        "collect" | "settle" => Ok(vec![]),
        "seal" => {
            ensure!(authorized.is_empty(), "sealed collector has a successor");
            Ok(vec![])
        }
        "finish_settlement" => {
            ensure!(authorized.len() == 1, "settlement finish needs one output");
            let number = |name: &str| -> Result<i64> {
                Ok(state[name]
                    .as_str()
                    .with_context(|| format!("missing {name}"))?
                    .parse::<i64>()?)
            };
            let budget = number("budget_raw")?;
            let leaf_count = number("leaf_count")?;
            let selected = number("selected_count")?;
            let liability = number("liability_raw")?;
            ensure!(
                state["collection_complete"] == true
                    && state["settlement_complete"] == false
                    && number("next_shard")? == number("shard_count")?
                    && selected >= 0
                    && selected <= leaf_count
                    && number("settled_count")? == selected
                    && liability >= 0
                    && liability <= budget,
                "collector is not ready to finish settlement"
            );
            let output = authorized[0];
            let id = output
                .canonical_covenant_id()
                .context("missing finalized collector covenant ID")?;
            ensure!(hex::decode(id)? == covenant_id, "wrong collector lineage");
            let mut next = state.clone();
            next.insert("settlement_complete".into(), json!(true));
            let script = encoded_script(KnownTemplate::KcomSettlement, &next)?;
            let spk = hex::decode(&output.script_public_key)?;
            ensure!(
                p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
                "forged finalized collector script"
            );
            Ok(vec![(
                i32::try_from(output.index)?,
                decoder.decode_constructor(&script)?,
            )])
        }
        _ => Err(anyhow!(crate::InterpretationFailure("unsupported settlement action"))),
    }
}

/// Seal consumes a finalized collector and fixes one vault continuation. The caller must
/// authenticate both spent inputs as members of the same campaign covenant lineage.
pub fn decode_vault_seal_successor(
    tx: &RestTransaction,
    vault_input_index: usize,
    collector_input_index: usize,
    covenant_id: &[u8],
    vault_reveal: &[u8],
    collector_reveal: &[u8],
) -> Result<(i32, Value)> {
    ensure!(
        vault_input_index < collector_input_index,
        "vault must lead collector in seal"
    );
    let vault_input = tx
        .inputs
        .get(vault_input_index)
        .context("missing vault input")?;
    let collector_input = tx
        .inputs
        .get(collector_input_index)
        .context("missing collector input")?;
    let vault_signature = hex::decode(&vault_input.signature_script)?;
    let collector_signature = hex::decode(&collector_input.signature_script)?;
    let vault_decoder = KcomClaimDecoder::new(KnownTemplate::KcomVault);
    let collector_decoder = KcomClaimDecoder::new(KnownTemplate::KcomSettlement);
    ensure!(
        vault_decoder.decode_action(&vault_signature).as_deref() == Some("seal")
            && collector_decoder
                .decode_action(&collector_signature)
                .as_deref()
                == Some("seal"),
        "seal requires both graph actors"
    );
    for (input, reveal) in [
        (vault_input, vault_reveal),
        (collector_input, collector_reveal),
    ] {
        if let Some(script_hex) = &input.previous_outpoint_script {
            let script = hex::decode(script_hex.strip_prefix("0000").unwrap_or(script_hex))?;
            ensure!(
                p2sh_script_hash(&script) == Some(blake2b_256(reveal)),
                "seal input reveal differs from source script"
            );
        }
    }
    let vault = vault_decoder.decode_constructor(vault_reveal)?;
    let collector = collector_decoder.decode_constructor(collector_reveal)?;
    let vault = vault.as_object().context("vault state")?;
    let collector = collector.as_object().context("collector state")?;
    same_artifact_profile(vault, collector)?;
    let number = |state: &Map<String, Value>, name: &str| -> Result<i64> {
        Ok(state[name]
            .as_str()
            .with_context(|| format!("missing {name}"))?
            .parse::<i64>()?)
    };
    ensure!(
        vault["funded"] == true
            && vault["opened"] == true
            && vault["settled"] == false
            && vault["recovered"] == false
            && number(vault, "liability_raw")? == 0
            && number(vault, "activated_raw")? == 0
            && collector["collection_complete"] == true
            && collector["settlement_complete"] == true
            && number(collector, "next_shard")? == number(collector, "shard_count")?
            && number(collector, "settled_count")? == number(collector, "selected_count")?,
        "campaign actors are not ready to seal"
    );
    for name in [
        "campaign",
        "terms_hash",
        "token_id",
        "tge_ms",
        "budget_raw",
        "first",
        "second",
        "third",
    ] {
        ensure!(
            vault[name] == collector[name],
            "seal terms differ at {name}"
        );
    }
    let liability = number(collector, "liability_raw")?;
    ensure!(
        liability >= 0 && liability <= number(vault, "budget_raw")?,
        "invalid sealed liability"
    );
    let vault_input_index = u16::try_from(vault_input_index)?;
    let collector_input_index = u16::try_from(collector_input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(vault_input_index))
        .collect::<Vec<_>>();
    ensure!(authorized.len() == 1, "vault seal needs one output");
    ensure!(
        tx.outputs
            .iter()
            .filter(|output| {
                output
                    .canonical_covenant_id()
                    .and_then(|id| hex::decode(id).ok())
                    .is_some_and(|id| id == covenant_id)
            })
            .count()
            == 1,
        "vault seal creates an extra graph output"
    );
    ensure!(
        tx.outputs
            .iter()
            .all(|output| output.covenant_authorizing_input() != Some(collector_input_index)),
        "sealed collector has a successor"
    );
    let output = authorized[0];
    let id = output
        .canonical_covenant_id()
        .context("missing sealed vault covenant ID")?;
    ensure!(
        hex::decode(id)? == covenant_id,
        "wrong sealed vault lineage"
    );
    if let (Some(vault_amount), Some(collector_amount)) = (
        vault_input.previous_outpoint_amount,
        collector_input.previous_outpoint_amount,
    ) {
        ensure!(
            output.amount
                == vault_amount
                    .checked_add(collector_amount)
                    .context("seal KAS overflow")?,
            "sealed vault native KAS differs from both sources"
        );
    }
    let mut next = vault.clone();
    next.insert("settled".into(), json!(true));
    next.insert("liability_raw".into(), json!(liability.to_string()));
    let script = encoded_script(KnownTemplate::KcomVault, &next)?;
    let spk = hex::decode(&output.script_public_key)?;
    ensure!(
        p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
        "forged sealed vault script"
    );
    Ok((
        i32::try_from(output.index)?,
        vault_decoder.decode_constructor(&script)?,
    ))
}

/// Collect one closed shard into the authenticated summaries root. The caller must verify both
/// spent inputs belong to the same graph and supply their indexed native KAS amounts.
pub fn decode_settlement_collect_successor(
    tx: &RestTransaction,
    collector_input_index: usize,
    shard_input_index: usize,
    covenant_id: &[u8],
    collector_reveal: &[u8],
    shard_reveal: &[u8],
) -> Result<(i32, Value)> {
    ensure!(
        collector_input_index < shard_input_index,
        "collector must lead shard"
    );
    let collector_input = tx
        .inputs
        .get(collector_input_index)
        .context("missing collector input")?;
    let shard_input = tx
        .inputs
        .get(shard_input_index)
        .context("missing shard input")?;
    let collector_signature = hex::decode(&collector_input.signature_script)?;
    let shard_signature = hex::decode(&shard_input.signature_script)?;
    let collector_decoder = KcomClaimDecoder::new(KnownTemplate::KcomSettlement);
    let shard_decoder = KcomClaimDecoder::new(KnownTemplate::KcomClaimShard);
    ensure!(
        collector_decoder
            .decode_action(&collector_signature)
            .as_deref()
            == Some("collect")
            && shard_decoder.decode_action(&shard_signature).as_deref() == Some("collect"),
        "collection requires both graph actors"
    );
    for (input, reveal) in [
        (collector_input, collector_reveal),
        (shard_input, shard_reveal),
    ] {
        if let Some(script_hex) = &input.previous_outpoint_script {
            let script = hex::decode(script_hex.strip_prefix("0000").unwrap_or(script_hex))?;
            ensure!(
                p2sh_script_hash(&script) == Some(blake2b_256(reveal)),
                "collection input reveal differs from source script"
            );
        }
    }
    let collector = collector_decoder.decode_constructor(collector_reveal)?;
    let shard = shard_decoder.decode_constructor(shard_reveal)?;
    let collector = collector.as_object().context("collector state")?;
    let shard = shard.as_object().context("closed shard state")?;
    let number = |state: &Map<String, Value>, name: &str| -> Result<i64> {
        Ok(state[name]
            .as_str()
            .with_context(|| format!("missing {name}"))?
            .parse::<i64>()?)
    };
    let count = number(collector, "shard_count")?;
    let index = number(collector, "next_shard")?;
    ensure!(
        collector["collection_complete"] == false
            && collector["settlement_complete"] == false
            && number(collector, "settled_count")? == 0
            && number(collector, "liability_raw")? == 0
            && count > 0
            && count <= 1_048_576
            && index >= 0
            && index < count
            && shard["closed"] == true
            && number(shard, "shard")? == index
            && number(shard, "shard_count")? == count,
        "collector and shard are not ready for collection"
    );
    for name in [
        "campaign",
        "terms_hash",
        "token_id",
        "budget_raw",
        "manifest_total",
        "eligibility_root",
        "leaf_count",
        "first",
        "second",
        "third",
        "opens_ms",
        "closes_ms",
        "tge_ms",
    ] {
        ensure!(
            collector[name] == shard[name],
            "collection terms differ at {name}"
        );
    }
    let opens = number(collector, "opens_ms")?;
    let closes = number(collector, "closes_ms")?;
    let profile = Profile::from_state(collector)?;
    ensure!(profile == Profile::from_state(shard)?, "collection artifact profiles differ");
    let claim_window_ms = match profile {
        Profile::Production => 2_592_000_000,
        Profile::FastTn10 => 3_600_000,
        Profile::ConfigurableV2 => {
            let duration = closes.checked_sub(opens).context("close underflow")?;
            ensure!((1..=31_622_400_000).contains(&duration), "invalid configurable selection window");
            duration
        },
    };
    ensure!(
        opens >= 500_000_000_000
            && closes <= 9_223_372_034_262_775_807
            && closes == opens.checked_add(claim_window_ms).context("close overflow")?,
        "invalid frozen close time"
    );
    let budget = number(collector, "budget_raw")?;
    let manifest_total = number(collector, "manifest_total")?;
    let leaf_count = number(collector, "leaf_count")?;
    let selected_before = number(collector, "selected_count")?;
    let all_before = number(collector, "all_weight")?;
    let boosted_before = number(collector, "boosted_weight")?;
    let long_before = number(collector, "long_weight")?;
    ensure!(
        (budget == 10_000_000_000_000_000 || (10..=20_000).contains(&budget) && budget % 10 == 0)
            && manifest_total > 0
            && manifest_total <= budget / 5
            && (1..=1_048_576).contains(&leaf_count)
            && selected_before >= 0
            && selected_before <= leaf_count
            && all_before >= 0
            && all_before <= manifest_total
            && boosted_before >= 0
            && boosted_before <= all_before
            && long_before >= 0
            && long_before <= boosted_before,
        "invalid collector participation totals"
    );
    let items = script_items(args_prefix_before_reveal(&collector_signature));
    ensure!(items.len() == 5, "collection witness differs from ABI");
    let proof = witness_bytes(&items, 0)?;
    let depth = crate::kcc20::item_integer::<usize>(&items, 1)?;
    ensure!(
        depth <= 20
            && proof.len() == depth * 32
            && 1i64
                .checked_shl(u32::try_from(depth)?)
                .context("summary depth overflow")?
                == count,
        "invalid summary proof shape"
    );
    let index = u32::try_from(index)?;
    let campaign = hex::decode(collector["campaign"].as_str().context("campaign")?)?;
    let used_root = hex::decode(shard["used_root"].as_str().context("shard used root")?)?;
    let root = hex::decode(
        collector["summaries_root"]
            .as_str()
            .context("summaries root")?,
    )?;
    ensure!(
        campaign.len() == 32 && used_root.len() == 32 && root.len() == 32,
        "invalid collection hash width"
    );
    let index_bytes = index.to_le_bytes();
    let empty = campaign_digest("summary.empty", &[&campaign, &index_bytes]);
    ensure!(
        fold_campaign_proof(empty, index, &proof, "summary.node")? == root.as_slice(),
        "collection summary slot has already been used"
    );
    let shard_selected = number(shard, "selected_count")?;
    let shard_all = number(shard, "all_weight")?;
    let shard_boosted = number(shard, "boosted_weight")?;
    let shard_long = number(shard, "long_weight")?;
    ensure!(
        shard_selected >= 0
            && shard_selected <= number(collector, "leaf_count")?
            && shard_all >= 0
            && shard_all <= 2_000_000_000_000_000
            && shard_boosted >= 0
            && shard_boosted <= shard_all
            && shard_long >= 0
            && shard_long <= shard_boosted,
        "invalid closed shard totals"
    );
    let summary = campaign_digest(
        "summary.leaf",
        &[
            &campaign,
            &index_bytes,
            &used_root,
            &u64::try_from(shard_selected)?.to_le_bytes(),
            &u64::try_from(shard_all)?.to_le_bytes(),
            &u64::try_from(shard_boosted)?.to_le_bytes(),
            &u64::try_from(shard_long)?.to_le_bytes(),
        ],
    );
    let new_root = fold_campaign_proof(summary, index, &proof, "summary.node")?;
    let mut next = collector.clone();
    next.insert("summaries_root".into(), json!(hex::encode(new_root)));
    next.insert(
        "next_shard".into(),
        json!((i64::from(index) + 1).to_string()),
    );
    for name in [
        "selected_count",
        "all_weight",
        "boosted_weight",
        "long_weight",
    ] {
        let sum = number(collector, name)?
            .checked_add(number(shard, name)?)
            .with_context(|| format!("{name} overflow"))?;
        next.insert(name.into(), json!(sum.to_string()));
    }
    ensure!(
        number(&next, "selected_count")? <= number(collector, "leaf_count")?
            && number(&next, "all_weight")? <= number(collector, "manifest_total")?
            && number(&next, "long_weight")? <= number(&next, "boosted_weight")?
            && number(&next, "boosted_weight")? <= number(&next, "all_weight")?,
        "collection exceeds frozen participation totals"
    );
    next.insert(
        "collection_complete".into(),
        json!(i64::from(index) + 1 == count),
    );
    let collector_input_index = u16::try_from(collector_input_index)?;
    let shard_input_index = u16::try_from(shard_input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|output| output.covenant_authorizing_input() == Some(collector_input_index))
        .collect::<Vec<_>>();
    ensure!(
        authorized.len() == 1,
        "collection needs one collector output"
    );
    ensure!(
        tx.outputs
            .iter()
            .all(|output| output.covenant_authorizing_input() != Some(shard_input_index)),
        "collected shard has a successor"
    );
    ensure!(
        tx.outputs
            .iter()
            .filter(|output| output
                .canonical_covenant_id()
                .and_then(|id| hex::decode(id).ok())
                .is_some_and(|id| id == covenant_id))
            .count()
            == 1,
        "collection creates an extra graph output"
    );
    let output = authorized[0];
    let id = output
        .canonical_covenant_id()
        .context("missing collected successor ID")?;
    ensure!(hex::decode(id)? == covenant_id, "wrong collection lineage");
    if let (Some(collector_amount), Some(shard_amount)) = (
        collector_input.previous_outpoint_amount,
        shard_input.previous_outpoint_amount,
    ) {
        ensure!(
            output.amount
                == collector_amount
                    .checked_add(shard_amount)
                    .context("collection KAS overflow")?,
            "collected native KAS differs from both sources"
        );
    }
    let script = encoded_script(KnownTemplate::KcomSettlement, &next)?;
    let spk = hex::decode(&output.script_public_key)?;
    ensure!(
        p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
        "forged collected settlement script"
    );
    Ok((
        i32::try_from(output.index)?,
        collector_decoder.decode_constructor(&script)?,
    ))
}

/// Settle one selected commitment from authenticated shard-summary and used-slot proofs.
/// The caller must verify both spent inputs belong to the same graph and supply indexed KAS.
pub fn decode_settlement_claim_successors(
    tx: &RestTransaction,
    collector_input_index: usize,
    commitment_input_index: usize,
    covenant_id: &[u8],
    collector_reveal: &[u8],
    commitment_reveal: &[u8],
) -> Result<Vec<(i32, Value)>> {
    ensure!(
        collector_input_index < commitment_input_index,
        "collector must lead commitment"
    );
    let collector_input = tx
        .inputs
        .get(collector_input_index)
        .context("missing collector input")?;
    let commitment_input = tx
        .inputs
        .get(commitment_input_index)
        .context("missing commitment input")?;
    let collector_signature = hex::decode(&collector_input.signature_script)?;
    let commitment_signature = hex::decode(&commitment_input.signature_script)?;
    let collector_decoder = KcomClaimDecoder::new(KnownTemplate::KcomSettlement);
    let commitment_decoder = KcomClaimDecoder::new(KnownTemplate::KcomClaimCommitment);
    ensure!(
        collector_decoder
            .decode_action(&collector_signature)
            .as_deref()
            == Some("settle")
            && commitment_decoder
                .decode_action(&commitment_signature)
                .as_deref()
                == Some("settle"),
        "settlement requires collector and commitment"
    );
    for (input, reveal) in [
        (collector_input, collector_reveal),
        (commitment_input, commitment_reveal),
    ] {
        if let Some(script_hex) = &input.previous_outpoint_script {
            let script = hex::decode(script_hex.strip_prefix("0000").unwrap_or(script_hex))?;
            ensure!(
                p2sh_script_hash(&script) == Some(blake2b_256(reveal)),
                "settlement input reveal differs from source script"
            );
        }
    }
    let collector = collector_decoder.decode_constructor(collector_reveal)?;
    let commitment = commitment_decoder.decode_constructor(commitment_reveal)?;
    let collector = collector.as_object().context("collector state")?;
    let commitment = commitment.as_object().context("commitment state")?;
    same_artifact_profile(collector, commitment)?;
    let number = |state: &Map<String, Value>, name: &str| -> Result<i64> {
        Ok(state[name]
            .as_str()
            .with_context(|| format!("missing {name}"))?
            .parse::<i64>()?)
    };
    let budget = number(collector, "budget_raw")?;
    let manifest = number(collector, "manifest_total")?;
    let leaf_count = number(collector, "leaf_count")?;
    let shard_count = number(collector, "shard_count")?;
    let selected = number(collector, "selected_count")?;
    let settled = number(collector, "settled_count")?;
    let all = number(collector, "all_weight")?;
    let boosted = number(collector, "boosted_weight")?;
    let long = number(collector, "long_weight")?;
    let liability = number(collector, "liability_raw")?;
    let weight = number(commitment, "weight")?;
    let tier = u8::try_from(number(commitment, "tier")?)?;
    let scheme = u8::try_from(
        commitment["beneficiary_scheme"]
            .as_u64()
            .context("beneficiary scheme")?,
    )?;
    let claim_index = u32::try_from(number(commitment, "index")?)?;
    let claim_shard = u32::try_from(number(commitment, "shard")?)?;
    ensure!(
        collector["collection_complete"] == true
            && collector["settlement_complete"] == false
            && shard_count > 0
            && shard_count <= 1_048_576
            && number(collector, "next_shard")? == shard_count
            && leaf_count > 0
            && leaf_count <= 1_048_576
            && selected > 0
            && selected <= leaf_count
            && settled >= 0
            && settled < selected
            && (budget == 10_000_000_000_000_000
                || ((10..=20_000).contains(&budget) && budget % 10 == 0))
            && manifest > 0
            && manifest <= budget / 5
            && all > 0
            && all <= manifest
            && boosted >= 0
            && boosted <= all
            && long >= 0
            && long <= boosted
            && liability >= 0
            && liability <= budget
            && weight > 0
            && weight <= all
            && (1..=3).contains(&tier)
            && scheme <= 4
            && i64::from(claim_index) < leaf_count
            && i64::from(claim_shard) < shard_count
            && number(commitment, "shard_count")? == shard_count,
        "collector and selected commitment are not ready to settle"
    );
    for name in [
        "campaign",
        "terms_hash",
        "token_id",
        "budget_raw",
        "manifest_total",
        "eligibility_root",
        "leaf_count",
        "tge_ms",
        "shard_count",
    ] {
        ensure!(
            collector[name] == commitment[name],
            "settlement terms differ at {name}"
        );
    }
    let items = script_items(args_prefix_before_reveal(&collector_signature));
    ensure!(items.len() == 14, "settlement witness differs from ABI");
    let final_used_root = witness_bytes(&items, 0)?;
    let summary_selected = crate::kcc20::item_integer::<i64>(&items, 1)?;
    let summary_all = crate::kcc20::item_integer::<i64>(&items, 2)?;
    let summary_boosted = crate::kcc20::item_integer::<i64>(&items, 3)?;
    let summary_long = crate::kcc20::item_integer::<i64>(&items, 4)?;
    let summary_proof = witness_bytes(&items, 5)?;
    let summary_depth = crate::kcc20::item_integer::<usize>(&items, 6)?;
    let used_proof = witness_bytes(&items, 7)?;
    let used_depth = crate::kcc20::item_integer::<usize>(&items, 8)?;
    ensure!(
        final_used_root.len() == 32
            && summary_selected > 0
            && summary_selected <= selected
            && summary_all >= weight
            && summary_all <= all
            && summary_boosted >= 0
            && summary_boosted <= summary_all
            && summary_long >= 0
            && summary_long <= summary_boosted
            && summary_depth <= 20
            && summary_proof.len() == summary_depth * 32
            && used_depth <= 20
            && used_proof.len() == used_depth * 32
            && 1i64
                .checked_shl(u32::try_from(summary_depth)?)
                .context("summary depth overflow")?
                == shard_count,
        "invalid settlement proof shape or shard totals"
    );
    let mut expected_used_width = 1i64;
    let mut expected_used_depth = 0usize;
    while expected_used_width < leaf_count {
        expected_used_width = expected_used_width
            .checked_mul(2)
            .context("used tree overflow")?;
        expected_used_depth += 1;
    }
    ensure!(
        used_depth == expected_used_depth,
        "invalid used proof depth"
    );
    let campaign = hex::decode(collector["campaign"].as_str().context("campaign")?)?;
    let eligibility_root = hex::decode(
        collector["eligibility_root"]
            .as_str()
            .context("eligibility root")?,
    )?;
    let summaries_root = hex::decode(
        collector["summaries_root"]
            .as_str()
            .context("summaries root")?,
    )?;
    let identity = hex::decode(commitment["identity"].as_str().context("claim identity")?)?;
    let authority = hex::decode(
        commitment["original_authority"]
            .as_str()
            .context("original authority")?,
    )?;
    let beneficiary = hex::decode(commitment["beneficiary"].as_str().context("beneficiary")?)?;
    ensure!(
        [
            &campaign,
            &eligibility_root,
            &summaries_root,
            &identity,
            &authority,
            &beneficiary
        ]
        .iter()
        .all(|bytes| bytes.len() == 32),
        "invalid settlement identity or root width"
    );
    ensure!(
        identity == campaign_digest("nullifier", &[&campaign, &[0], &authority]),
        "commitment identity differs from authority"
    );
    let summary = campaign_digest(
        "summary.leaf",
        &[
            &campaign,
            &claim_shard.to_le_bytes(),
            &final_used_root,
            &u64::try_from(summary_selected)?.to_le_bytes(),
            &u64::try_from(summary_all)?.to_le_bytes(),
            &u64::try_from(summary_boosted)?.to_le_bytes(),
            &u64::try_from(summary_long)?.to_le_bytes(),
        ],
    );
    ensure!(
        fold_campaign_proof(summary, claim_shard, &summary_proof, "summary.node")?
            == summaries_root.as_slice(),
        "settlement summary proof differs from root"
    );
    let selection = campaign_digest(
        "selection",
        &[
            &campaign,
            &eligibility_root,
            &identity,
            &[tier, scheme],
            &beneficiary,
        ],
    );
    let used = campaign_digest(
        "used.leaf",
        &[&campaign, &claim_index.to_le_bytes(), &selection],
    );
    ensure!(
        fold_campaign_proof(used, claim_index, &used_proof, "used.node")?
            == final_used_root.as_slice(),
        "settlement used proof differs from root"
    );
    let ratio = |pool: i64, denominator: i64| -> Result<i64> {
        ensure!(
            pool >= 0
                && denominator > 0
                && denominator <= 2_000_000_000_000_000
                && weight <= denominator,
            "invalid settlement denominator"
        );
        let product = i128::from(pool)
            .checked_mul(i128::from(weight))
            .context("allocation overflow")?;
        Ok(i64::try_from(product / i128::from(denominator))?)
    };
    let mut total = weight;
    if tier >= 2 {
        total = total
            .checked_add(ratio((budget / 10) * 3, boosted)?)
            .context("medium allocation overflow")?;
    }
    if tier == 3 {
        total = total
            .checked_add(ratio(budget / 2, long)?)
            .context("long allocation overflow")?;
        total = total
            .checked_add(ratio(manifest - all, long)?)
            .context("unclaimed allocation overflow")?;
    }
    ensure!(
        total > 0 && total <= budget && liability <= budget - total,
        "settlement allocation exceeds budget"
    );
    let mut next = collector.clone();
    next.insert(
        "settled_count".into(),
        json!(settled
            .checked_add(1)
            .context("settled overflow")?
            .to_string()),
    );
    next.insert(
        "liability_raw".into(),
        json!(liability
            .checked_add(total)
            .context("liability overflow")?
            .to_string()),
    );
    let mut entitlement = copy_fields(
        collector,
        &[
            "gen__kcom_vault_template",
            "campaign",
            "terms_hash",
            "token_id",
            "tge_ms",
            "budget_raw",
            "manifest_total",
            "eligibility_root",
        ],
    )?;
    for name in [
        "index",
        "original_authority",
        "beneficiary",
        "beneficiary_scheme",
        "tier",
    ] {
        entitlement.insert(name.into(), commitment[name].clone());
    }
    entitlement.insert("total".into(), json!(total.to_string()));
    let collector_input_index = u16::try_from(collector_input_index)?;
    let commitment_input_index = u16::try_from(commitment_input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|out| out.covenant_authorizing_input() == Some(collector_input_index))
        .collect::<Vec<_>>();
    ensure!(
        authorized.len() == 2,
        "settlement needs collector and entitlement outputs"
    );
    ensure!(
        tx.outputs
            .iter()
            .all(|out| out.covenant_authorizing_input() != Some(commitment_input_index)),
        "settled commitment has a successor"
    );
    ensure!(
        tx.outputs
            .iter()
            .filter(|out| out
                .canonical_covenant_id()
                .and_then(|id| hex::decode(id).ok())
                .is_some_and(|id| id == covenant_id))
            .count()
            == 2,
        "settlement creates an extra graph output"
    );
    let expected = [
        (
            KnownTemplate::KcomSettlement,
            next,
            collector_input.previous_outpoint_amount,
        ),
        (
            KnownTemplate::KcomEntitlement,
            entitlement,
            commitment_input.previous_outpoint_amount,
        ),
    ];
    let mut successors = Vec::new();
    for ((template, state, source_amount), output) in expected.into_iter().zip(authorized) {
        let id = output
            .canonical_covenant_id()
            .context("missing settlement output lineage")?;
        ensure!(hex::decode(id)? == covenant_id, "wrong settlement lineage");
        if let Some(amount) = source_amount {
            ensure!(output.amount == amount, "settlement diverts native KAS");
        }
        let script = encoded_script(template, &state)?;
        let spk = hex::decode(&output.script_public_key)?;
        ensure!(
            p2sh_script_hash(&spk) == Some(blake2b_256(&script)),
            "forged settlement successor script"
        );
        successors.push((
            i32::try_from(output.index)?,
            KcomClaimDecoder::new(template).decode_constructor(&script)?,
        ));
    }
    Ok(successors)
}

/// Independently reconstruct a settled claim's activation outputs from accepted inputs.
/// Source KAS amounts must come from indexed UTXOs, not an untrusted REST hint.
pub fn decode_activation_successors(
    tx: &RestTransaction,
    vault_input_index: usize,
    entitlement_input_index: usize,
    token_input_index: usize,
    graph_id: &[u8],
    token_id: &[u8],
    vault_reveal: &[u8],
    entitlement_reveal: &[u8],
    token_reveal: &[u8],
) -> Result<(Vec<(i32, Value)>, Vec<u8>, (i32, Value))> {
    ensure!(
        vault_input_index < entitlement_input_index,
        "vault must lead entitlement"
    );
    ensure!(
        token_input_index != vault_input_index && token_input_index != entitlement_input_index,
        "activation needs a separate token input"
    );
    ensure!(
        graph_id.len() == 32 && token_id.len() == 32,
        "invalid activation covenant ID"
    );
    let vault_input = tx
        .inputs
        .get(vault_input_index)
        .context("missing vault input")?;
    let entitlement_input = tx
        .inputs
        .get(entitlement_input_index)
        .context("missing entitlement input")?;
    let token_input = tx
        .inputs
        .get(token_input_index)
        .context("missing token input")?;
    for (input, reveal) in [
        (vault_input, vault_reveal),
        (entitlement_input, entitlement_reveal),
        (token_input, token_reveal),
    ] {
        let source_spk = input
            .previous_outpoint_script
            .as_ref()
            .context("activation source script missing")?;
        let source_spk = hex::decode(source_spk.strip_prefix("0000").unwrap_or(source_spk))?;
        ensure!(
            p2sh_script_hash(&source_spk) == Some(blake2b_256(reveal)),
            "activation reveal differs from spent source"
        );
        ensure!(
            input.previous_outpoint_amount.is_some(),
            "indexed activation source KAS missing"
        );
    }
    let vault_decoder = KcomClaimDecoder::new(KnownTemplate::KcomVault);
    let entitlement_decoder = KcomClaimDecoder::new(KnownTemplate::KcomEntitlement);
    let vault_sig = hex::decode(&vault_input.signature_script)?;
    let entitlement_sig = hex::decode(&entitlement_input.signature_script)?;
    let action = vault_decoder
        .decode_action(&vault_sig)
        .context(crate::InterpretationFailure("unknown activation action"))?;
    ensure!(
        action == "activate_partial" || action == "activate_final",
        "wrong vault activation action"
    );
    ensure!(
        entitlement_decoder
            .decode_action(&entitlement_sig)
            .as_deref()
            == Some(action.as_str()),
        "wrong entitlement activation action"
    );
    let vault = vault_decoder.decode_constructor(vault_reveal)?;
    let entitlement = entitlement_decoder.decode_constructor(entitlement_reveal)?;
    let vault = vault.as_object().context("vault state")?;
    let entitlement = entitlement.as_object().context("entitlement state")?;
    same_artifact_profile(vault, entitlement)?;
    for key in ["campaign", "terms_hash", "token_id", "tge_ms", "budget_raw"] {
        ensure!(
            vault[key] == entitlement[key],
            "activation terms differ at {key}"
        );
    }
    ensure!(
        hex::decode(vault["token_id"].as_str().context("vault token")?)? == token_id,
        "activation token ID differs"
    );
    ensure!(
        vault["funded"] == true && vault["opened"] == true && vault["settled"] == true,
        "vault not settled"
    );
    let number = |state: &Map<String, Value>, key: &str| -> Result<i64> {
        Ok(state[key]
            .as_str()
            .with_context(|| format!("missing {key}"))?
            .parse::<i64>()?)
    };
    let budget = number(vault, "budget_raw")?;
    let liability = number(vault, "liability_raw")?;
    let activated = number(vault, "activated_raw")?;
    let total = number(entitlement, "total")?;
    ensure!(
        budget > 0
            && liability >= 0
            && liability <= budget
            && activated >= 0
            && activated < liability
            && total > 0
            && total <= liability - activated,
        "invalid activation liability"
    );
    let available = if vault["recovered"] == true {
        liability - activated
    } else {
        budget - activated
    };
    let partial = action == "activate_partial";
    ensure!(
        if partial {
            total < available
        } else {
            total == available && total == liability - activated
        },
        "activation action differs from reserve"
    );
    let tier = number(entitlement, "tier")?;
    let scheme = entitlement["beneficiary_scheme"]
        .as_u64()
        .context("beneficiary scheme")?;
    ensure!(
        (1..=3).contains(&tier) && scheme <= 4,
        "invalid vesting beneficiary or tier"
    );
    let beneficiary = entitlement["beneficiary"].as_str().context("beneficiary")?;
    ensure!(
        hex::decode(beneficiary)?.len() == 32,
        "invalid beneficiary width"
    );
    let token = kcc20_standard::decode_reveal_state(token_reveal)?;
    ensure!(
        hex::encode(
            kcc20_standard::Kcc20StandardDecoder::template_hash_of_compiled_script(token_reveal)?
        ) == "5d6cacdf57c734536fcb8a9c833f0318671226727ec77c503a98fc5be59f9e29",
        "activation token template differs from canonical KCC20"
    );
    ensure!(
        token.amount.parse::<i64>()? == available
            && token.owner_scheme == 4
            && token.owner == hex::encode(graph_id)
            && token.borrow_scheme == 0
            && token.borrow_guard == "00".repeat(32)
            && token.extension_commitment == vault["extension"],
        "invalid activation token reserve"
    );

    let configurable = Profile::from_state(vault)? == Profile::ConfigurableV2;
    let extra_args = if configurable { 5 } else { 0 };
    let items = script_items(args_prefix_before_reveal(&vault_sig));
    ensure!(
        items.len() == (if partial { 11 } else { 10 }) + extra_args,
        "activation witness differs from ABI"
    );
    ensure!(
        crate::kcc20::item_integer::<usize>(&items, 0)? == token_input_index,
        "activation token input differs"
    );
    let position_reserve_index = crate::kcc20::item_integer::<u64>(&items, 1)?;
    let vault_reserve_index = if partial {
        Some(crate::kcc20::item_integer::<u64>(&items, 2)?)
    } else {
        None
    };
    let position_index = crate::kcc20::item_integer::<u64>(&items, (if partial { 9 } else { 8 }) + extra_args)?;
    let output = |index: u64| {
        tx.outputs
            .iter()
            .find(|out| out.index == index)
            .with_context(|| format!("missing activation output {index}"))
    };
    let vault_output = tx
        .outputs
        .iter()
        .filter(|out| {
            out.canonical_covenant_id()
                .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(graph_id))
        })
        .collect::<Vec<_>>();
    ensure!(
        vault_output.len() == 1
            && vault_output[0].covenant_authorizing_input()
                == Some(u16::try_from(vault_input_index)?),
        "activation graph successor differs"
    );
    let vault_output = vault_output[0];
    ensure!(
        vault_output.amount == vault_input.previous_outpoint_amount.context("vault KAS")?,
        "activation diverts vault KAS"
    );
    let mut next_vault = vault.clone();
    next_vault.insert(
        "activated_raw".into(),
        json!((activated + total).to_string()),
    );
    let next_script = encoded_script(KnownTemplate::KcomVault, &next_vault)?;
    ensure!(
        p2sh_script_hash(&hex::decode(&vault_output.script_public_key)?)
            == Some(blake2b_256(&next_script)),
        "forged activated vault script"
    );

    let position_output = output(position_index)?;
    let position_id =
        compute_genesis_covenant_id_for_outputs_at_input(tx, vault_input_index, &[position_index])
            .context("cannot derive vesting position ID")?;
    let position_id = hex::decode(position_id)?;
    ensure!(
        position_output
            .canonical_covenant_id()
            .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(position_id.as_slice())),
        "activation position lineage differs"
    );
    ensure!(
        position_output.covenant_authorizing_input() == Some(u16::try_from(vault_input_index)?)
            && tx
                .outputs
                .iter()
                .filter(|out| out
                    .canonical_covenant_id()
                    .is_some_and(
                        |id| hex::decode(id).ok().as_deref() == Some(position_id.as_slice())
                    ))
                .count()
                == 1,
        "activation creates an extra or rebound vesting position"
    );
    ensure!(
        position_output.amount
            == entitlement_input
                .previous_outpoint_amount
                .context("entitlement KAS")?,
        "activation diverts entitlement KAS"
    );
    let mut position = json!({
        "token_id": hex::encode(token_id), "beneficiary": beneficiary,
        "beneficiary_scheme": scheme, "extension": vault["extension"],
        "total": total.to_string(), "released": "0", "tier": tier.to_string(),
        "tge_ms": vault["tge_ms"], "token_prefix_len": "1", "token_suffix_len": "25264",
        "token_template_hash": "5d6cacdf57c734536fcb8a9c833f0318671226727ec77c503a98fc5be59f9e29"
    });
    if configurable {
        let terms_index = if partial { 5 } else { 4 };
        let terms = witness_bytes(&items, terms_index)?;
        ensure!(terms.len() == 373 && &terms[..20] == b"kcom.claim.terms/v3\0"
            && hex::encode(blake3::hash(&terms).as_bytes()) == vault["terms_hash"].as_str().unwrap_or(""),
            "activation schedule commitment differs");
        let offset = 277 + usize::try_from(tier - 1)? * 32;
        for (n, name) in ["period_ms", "first_period", "period_count", "tge_bps"].iter().enumerate() {
            let value = crate::kcc20::item_integer::<i64>(&items, terms_index + 1 + n)?;
            let expected = i64::from_le_bytes(terms[offset+n*8..offset+(n+1)*8].try_into()?);
            ensure!(value == expected, "activation schedule witness differs");
            position[*name] = json!(value.to_string());
        }
    }
    Profile::from_state(vault)?.annotate(&mut position);
    let position_script = kcom_vesting::script_for_state_value(&position)?;
    ensure!(
        p2sh_script_hash(&hex::decode(&position_output.script_public_key)?)
            == Some(blake2b_256(&position_script)),
        "forged activated position script"
    );
    let token_outputs = tx
        .outputs
        .iter()
        .filter(|out| {
            out.canonical_covenant_id()
                .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(token_id))
        })
        .collect::<Vec<_>>();
    ensure!(
        token_outputs.len() == if partial { 2 } else { 1 },
        "activation token output count differs"
    );
    let position_reserve = output(position_reserve_index)?;
    ensure!(
        token_outputs[0].index == position_reserve_index
            && position_reserve.covenant_authorizing_input()
                == Some(u16::try_from(token_input_index)?),
        "activation position reserve order differs"
    );
    let reserve_state = |amount: i64, owner: &[u8]| {
        json!({
            "amount": amount.to_string(), "owner": hex::encode(owner), "ownerScheme": 4,
            "borrowScheme": 0, "borrowGuard": "00".repeat(32),
            "extensionCommitment": vault["extension"]
        })
    };
    let check_reserve = |index: u64, state: &Value| -> Result<()> {
        let out = output(index)?;
        ensure!(
            out.amount >= 100_000_000,
            "activation reserve lacks native KAS"
        );
        let script = kcc20_standard::script_for_state_value_with_reveal(state, token_reveal)?;
        ensure!(
            p2sh_script_hash(&hex::decode(&out.script_public_key)?) == Some(blake2b_256(&script)),
            "forged activation token reserve"
        );
        Ok(())
    };
    check_reserve(position_reserve_index, &reserve_state(total, &position_id))?;
    if let Some(index) = vault_reserve_index {
        let remaining = output(index)?;
        ensure!(
            token_outputs[1].index == index
                && remaining.covenant_authorizing_input()
                    == Some(u16::try_from(token_input_index)?),
            "activation vault reserve order differs"
        );
        check_reserve(index, &reserve_state(available - total, graph_id))?;
        ensure!(
            position_reserve
                .amount
                .checked_add(remaining.amount)
                .context("activation KAS overflow")?
                >= token_input.previous_outpoint_amount.context("token KAS")?,
            "activation diverts reserve KAS"
        );
    } else {
        ensure!(
            position_reserve.amount == token_input.previous_outpoint_amount.context("token KAS")?,
            "activation diverts final reserve KAS"
        );
    }
    let next_vault = vault_decoder.decode_constructor(&next_script)?;
    let position = kcom_vesting::decode_reveal_state_value(&position_script)?;
    Ok((
        vec![(i32::try_from(vault_output.index)?, next_vault)],
        position_id,
        (i32::try_from(position_index)?, position),
    ))
}

/// Recover only the proven surplus from a settled vault. Both spent source amounts and
/// scripts must be loaded from indexed UTXOs before calling this function.
pub fn decode_recovery_successor(
    tx: &RestTransaction,
    vault_input_index: usize,
    token_input_index: usize,
    graph_id: &[u8],
    token_id: &[u8],
    vault_reveal: &[u8],
    token_reveal: &[u8],
) -> Result<((i32, Value), Vec<(i32, Value)>)> {
    ensure!(vault_input_index != token_input_index, "recovery sources alias");
    ensure!(graph_id.len() == 32 && token_id.len() == 32, "invalid recovery ID");
    let vault_input = tx.inputs.get(vault_input_index).context("missing recovery vault")?;
    let token_input = tx.inputs.get(token_input_index).context("missing recovery token")?;
    for (input, reveal) in [(vault_input, vault_reveal), (token_input, token_reveal)] {
        let spk = input.previous_outpoint_script.as_ref()
            .context("indexed recovery source script missing")?;
        let spk = hex::decode(spk.strip_prefix("0000").unwrap_or(spk))?;
        ensure!(p2sh_script_hash(&spk) == Some(blake2b_256(reveal)),
            "recovery reveal differs from indexed source");
        ensure!(input.previous_outpoint_amount.is_some(),
            "indexed recovery source KAS missing");
    }
    let decoder = KcomClaimDecoder::new(KnownTemplate::KcomVault);
    let signature = hex::decode(&vault_input.signature_script)?;
    let action = decoder.decode_action(&signature).context(crate::InterpretationFailure("unknown recovery action"))?;
    ensure!(action == "recover_partial" || action == "recover_final",
        "wrong vault recovery action");
    let state = decoder.decode_constructor(vault_reveal)?;
    let state = state.as_object().context("recovery vault state")?;
    let number = |key: &str| -> Result<i64> {
        Ok(state[key].as_str().with_context(|| format!("missing {key}"))?.parse()?)
    };
    let budget = number("budget_raw")?;
    let liability = number("liability_raw")?;
    let activated = number("activated_raw")?;
    ensure!(state["funded"] == true && state["opened"] == true
        && state["settled"] == true && state["recovered"] == false
        && budget > 0 && budget <= 10_000_000_000_000_000
        && liability >= 0 && liability < budget
        && activated >= 0 && activated <= liability,
        "vault has no proven recovery surplus");
    let remaining = liability - activated;
    let partial = remaining > 0;
    ensure!(action == if partial { "recover_partial" } else { "recover_final" },
        "recovery action differs from beneficiary liability");
    ensure!(hex::decode(state["token_id"].as_str().context("vault token ID")?)? == token_id,
        "recovery token ID differs");
    let treasury = hex::decode(state["treasury"].as_str().context("frozen treasury")?)?;
    let treasury_scheme = state["treasury_scheme"].as_u64()
        .context("frozen treasury scheme")?;
    ensure!(treasury.len() == 32 && treasury_scheme <= 4,
        "invalid frozen treasury");
    let token = kcc20_standard::decode_reveal_state(token_reveal)?;
    ensure!(hex::encode(
        kcc20_standard::Kcc20StandardDecoder::template_hash_of_compiled_script(token_reveal)?
    ) == "5d6cacdf57c734536fcb8a9c833f0318671226727ec77c503a98fc5be59f9e29",
        "recovery token template differs from canonical KCC20");
    ensure!(token.amount.parse::<i64>()? == budget - activated
        && token.owner_scheme == 4 && token.owner == hex::encode(graph_id)
        && token.borrow_scheme == 0 && token.borrow_guard == "00".repeat(32)
        && token.extension_commitment == state["extension"],
        "recovery source does not cover beneficiary liability and surplus");
    ensure!(tx.outputs.len() == if partial { 4 } else { 3 },
        "recovery output count differs");
    let vault_out = &tx.outputs[0];
    ensure!(vault_out.index == 0
        && vault_out.covenant_authorizing_input() == Some(u16::try_from(vault_input_index)?)
        && vault_out.canonical_covenant_id()
            .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(graph_id))
        && vault_out.amount == vault_input.previous_outpoint_amount.context("vault KAS")?,
        "recovery vault output changes lineage or native KAS");
    let mut next = state.clone();
    next.insert("recovered".into(), json!(true));
    let script = encoded_script(KnownTemplate::KcomVault, &next)?;
    ensure!(p2sh_script_hash(&hex::decode(&vault_out.script_public_key)?)
        == Some(blake2b_256(&script)), "forged recovered vault script");
    let extension = state["extension"].as_str().context("vault extension")?;
    let token_state = |amount: i64, owner: &[u8], scheme: u64| json!({
        "amount": amount.to_string(), "owner": hex::encode(owner),
        "ownerScheme": scheme, "borrowScheme": 0,
        "borrowGuard": "00".repeat(32), "extensionCommitment": extension,
    });
    let mut token_successors = Vec::new();
    for (index, expected) in [(1, token_state(budget - liability, &treasury, treasury_scheme)),
        (2, token_state(remaining, graph_id, 4))].into_iter().take(if partial { 2 } else { 1 }) {
        let out = &tx.outputs[index];
        ensure!(out.index == index as u64
            && out.covenant_authorizing_input() == Some(u16::try_from(token_input_index)?)
            && out.canonical_covenant_id()
                .is_some_and(|id| hex::decode(id).ok().as_deref() == Some(token_id))
            && out.amount >= 100_000_000,
            "recovery token output changes lineage or native reserve");
        let token_script = kcc20_standard::script_for_state_value_with_reveal(&expected, token_reveal)?;
        ensure!(p2sh_script_hash(&hex::decode(&out.script_public_key)?)
            == Some(blake2b_256(&token_script)), "forged recovery token output");
        token_successors.push((i32::try_from(index)?, expected));
    }
    let token_kas = token_input.previous_outpoint_amount.context("token KAS")?;
    let output_kas = tx.outputs[1].amount
        .checked_add(if partial { tx.outputs[2].amount } else { 0 })
        .context("recovery native KAS overflow")?;
    ensure!(output_kas >= token_kas, "recovery diverts token reserve KAS");
    let change = tx.outputs.last().context("recovery sponsor change")?;
    ensure!(change.canonical_covenant_id().is_none(),
        "recovery adds a rebound covenant output");
    Ok(((i32::try_from(vault_out.index)?, decoder.decode_constructor(&script)?),
        token_successors))
}

impl TemplateDecoder for KcomClaimDecoder {
    fn template(&self) -> KnownTemplate {
        self.template
    }

    fn script_hash(&self) -> [u8; 32] {
        self.template_hash
    }

    fn matches_reveal_script(&self, script: &[u8]) -> bool {
        self.matched_profile(script).is_some()
    }

    fn unsupported_reveal_reason(&self, script: &[u8]) -> Option<&'static str> {
        if self.matched_profile(script).is_some() { return None; }
        for profile in Profile::ALL {
            let contract=&abi_for_profile(self.template,profile)["contracts"][self.name()];
            let bytes=contract["compiled"]["bytecode"].as_array()?;
            let span=&contract["compiled"]["state_span"];
            let start=span["offset"].as_u64()? as usize;
            let end=start.checked_add(span["len"].as_u64()? as usize)?;
            if script.len()!=bytes.len() || end>script.len() { continue; }
            if script[..start].iter().zip(&bytes[..start]).all(|(a,b)|Some(u64::from(*a))==b.as_u64())
                && script[end..].iter().zip(&bytes[end..]).all(|(a,b)|Some(u64::from(*a))==b.as_u64())
                && self.decode_payload(&script[start..end]).is_ok() {
                return Some("unsupported_committed_template_family");
            }
        }
        None
    }

    fn decode_constructor(&self, script: &[u8]) -> Result<Value> {
        let profile = self.matched_profile(script).context("campaign actor template mismatch")?;
        let span = &abi_for_profile(self.template, profile)["contracts"][self.name()]["compiled"]["state_span"];
        let (start, len) = (span["offset"].as_u64().context("state offset")? as usize,
            span["len"].as_u64().context("state len")? as usize);
        let mut state = self.decode_payload(&script[start..start + len])?;
        profile.annotate(&mut state);
        Ok(state)
    }

    fn decode_state(&self, payload: &[u8]) -> Result<Value> {
        self.decode_payload(payload)
    }

    fn decode_action_checked(&self, signature_script: &[u8]) -> Result<Option<String>> {
        self.decode_action(signature_script)
            .map(Some)
            .ok_or_else(|| anyhow!(crate::InterpretationFailure("unsupported spend action")))
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let items = script_items(args_prefix_before_reveal(signature_script));
        let tag = hex::encode(item_tag(items.last()?)?);
        let all_items = script_items(signature_script);
        let profile = match all_items.last()? {
            ScriptItem::Data(reveal) => self.matched_profile(reveal)?,
            _ => return None,
        };
        abi_for_profile(self.template, profile)["contracts"][self.name()]["entries"]
            .as_object()?.iter().find_map(|(name, entry)| {
                (entry["dispatch_tag"].as_str()? == tag).then(|| name.clone())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const TEMPLATES: [KnownTemplate; 6] = [
        KnownTemplate::KcomFactory,
        KnownTemplate::KcomVault,
        KnownTemplate::KcomClaimShard,
        KnownTemplate::KcomSettlement,
        KnownTemplate::KcomClaimCommitment,
        KnownTemplate::KcomEntitlement,
    ];

    #[test]
    fn initializer_abi_and_first_spend_are_pinned() {
        assert_eq!(
            hex::encode(Sha256::digest(INITIALIZE_ABI_SOURCE.as_bytes())),
            "faaf91ad0af7b83910e2e7ebb9c8d9935d8add5594a5967cdfe9a739f1990ca2"
        );
        let decoder = KcomClaimDecoder::new(KnownTemplate::KcomInitialize);
        let script = decoder.compiled_script();
        assert!(decoder.matches_reveal_script(&script));
        assert_eq!(crate::default_registry().find_for_reveal(&script).unwrap().template(),
            KnownTemplate::KcomInitialize);
        let state = decoder.decode_constructor(&script).unwrap();
        assert_eq!(state["modeName"], "KCOMInitialize");
        assert_eq!(state["campaignId"], state["campaign"]);
        let tag = decoder.contract()["entries"]["initialize"]["dispatch_tag"].as_str().unwrap();
        let mut signature = [vec![4], hex::decode(tag).unwrap()].concat();
        signature.push(0x4e);
        signature.extend((script.len() as u32).to_le_bytes());
        signature.extend(&script);
        assert_eq!(decoder.decode_action(&signature).as_deref(), Some("initialize"));
    }

    #[test]
    fn accepted_tn10_initializer_reconstructs_unrevealed_graph_outputs() {
        let transactions: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../../fixtures/kcom-claim-tn10-live/ordered-token-and-main.json"
        )).unwrap();
        let deployment = &transactions[1];
        let initialization = &transactions[2];
        let source_script = hex::decode(&deployment.outputs[0].script_public_key).unwrap();
        let signature = hex::decode(&initialization.inputs[0].signature_script).unwrap();
        let items = script_items(&signature);
        let reveal = witness_bytes(&items, items.len() - 1).unwrap();
        let (graph, states) = decode_initialize_successors(
            initialization, 0, &signature, &reveal, &source_script,
            deployment.outputs[0].amount,
        ).unwrap();
        assert_eq!(hex::encode(graph),
            "9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447");
        assert_eq!(states.iter().map(|(vout, state)| (*vout, state["modeName"].as_str().unwrap()))
            .collect::<Vec<_>>(), vec![(0, "KCOMFactory"), (1, "KCOMVault")]);
        let mut forged = initialization.clone();
        forged.outputs[1].script_public_key.replace_range(8..10, "ff");
        assert!(decode_initialize_successors(
            &forged, 0, &signature, &reveal, &source_script, deployment.outputs[0].amount,
        ).is_err());
        assert!(decode_initialize_successors(
            initialization, 0, &signature, &reveal, &source_script, deployment.outputs[0].amount - 1,
        ).is_err());
    }

    #[test]
    fn abi_and_six_actor_templates_are_pinned() {
        assert_eq!(
            hex::encode(Sha256::digest(ABI_SOURCE.as_bytes())),
            "d2a65313b146e047eb0add80a80bfbf325ae7d74f4f3d78cafe9fa970ad1fd9c"
        );
        let registry = crate::default_registry();
        let mut hashes = std::collections::HashSet::new();
        for template in TEMPLATES {
            let decoder = KcomClaimDecoder::new(template);
            let script = decoder.compiled_script();
            assert!(hashes.insert(decoder.script_hash()));
            assert!(decoder.matches_reveal_script(&script));
            assert_eq!(
                registry.find_for_reveal(&script).unwrap().template(),
                template
            );
            let state = decoder.decode_constructor(&script).unwrap();
            assert_eq!(state["modeName"], decoder.name());
            assert_eq!(state["campaignId"], state["campaign"]);
            assert_eq!(state["canonicalTokenId"], state["token_id"]);
            let (start, len) = decoder.span();
            let raw: Vec<u8> = decoder.contract()["compiled"]["bytecode"].as_array().unwrap()
                .iter().map(|b| b.as_u64().unwrap() as u8).collect();
            if decoder.contract()["runtime_state"]["fields"][0]["name"].as_str().unwrap().starts_with("gen__") {
                assert!(!decoder.matches_reveal_script(&raw), "zero generated commitments must fail closed");
            }
            let mut changed_state = script.clone();
            let mut campaign_offset = start;
            for field in decoder.contract()["runtime_state"]["fields"].as_array().unwrap() {
                if field["name"] == "campaign" { break; }
                campaign_offset += 1 + usize::from(script[campaign_offset]);
            }
            changed_state[campaign_offset + 1] ^= 1;
            assert!(decoder.matches_reveal_script(&changed_state));
            if decoder.contract()["runtime_state"]["fields"][0]["name"].as_str().unwrap().starts_with("gen__") {
                let mut unsupported_family = script.clone();
                unsupported_family[start + 1] ^= 1;
                assert!(!decoder.matches_reveal_script(&unsupported_family));
                assert_eq!(decoder.unsupported_reveal_reason(&unsupported_family),Some("unsupported_committed_template_family"));
            }
            assert_ne!(decoder.decode_constructor(&changed_state).unwrap(), state);
            let mut changed_code = script.clone();
            changed_code[start + len] ^= 1;
            assert!(!decoder.matches_reveal_script(&changed_code));
            assert!(decoder.decode_constructor(&changed_code).is_err());
            assert!(decoder.unsupported_reveal_reason(&changed_code).is_none());
            assert!(decoder.unsupported_reveal_reason(&script).is_none());
        }
    }

    #[test]
    fn strict_field_encoding_and_compiler_dispatch() {
        for template in TEMPLATES {
            let decoder = KcomClaimDecoder::new(template);
            let script = decoder.compiled_script();
            let (start, len) = decoder.span();
            let mut payload = script[start..start + len].to_vec();
            payload[0] = 31;
            assert!(decoder.decode_state(&payload).is_err());
            let (name, entry) = decoder.contract()["entries"]
                .as_object()
                .unwrap()
                .iter()
                .next()
                .unwrap();
            let tag = hex::decode(entry["dispatch_tag"].as_str().unwrap()).unwrap();
            let mut signature_script = vec![4];
            signature_script.extend(tag);
            signature_script.push(0x4e);
            signature_script.extend((script.len() as u32).to_le_bytes());
            signature_script.extend(&script);
            assert_eq!(
                decoder.decode_action(&signature_script).as_deref(),
                Some(name.as_str())
            );
            signature_script[1] ^= 1;
            assert_eq!(decoder.decode_action(&signature_script), None);
        }
    }
}

#[cfg(test)]
mod fast_tn10_tests {
    use super::*;
    #[test]
    fn multi_actor_profiles_must_match() {
        let production = Map::new();
        let mut fast = Map::new();
        fast.insert("artifactProfile".into(), json!(Profile::FAST_NAME));
        assert!(same_artifact_profile(&production, &production).is_ok());
        assert!(same_artifact_profile(&fast, &fast).is_ok());
        assert!(same_artifact_profile(&production, &fast).is_err());
        assert!(same_artifact_profile(&fast, &production).is_err());
    }


    #[test]
    fn accepted_fast_factory_shard_and_forged_successor() {
        let txs: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../../fixtures/kcom-fast-tn10-live/ordered-fast.json"
        )).unwrap();
        let tx = txs.iter().find(|tx| tx.transaction_id ==
            "ae4fd75778fb512e3ebb4cd418f192fb5166d446efd5056de19e9e62deea618a").unwrap();
        let sig = hex::decode(&tx.inputs[0].signature_script).unwrap();
        let items = script_items(&sig);
        let ScriptItem::Data(reveal) = items.last().unwrap() else { panic!("missing reveal") };
        let graph = hex::decode("e8418ea75b7a547d51ee4cd4dd3d83d55da623713d933c31e86369636c3b7942").unwrap();
        let successors = decode_factory_successors(tx, 0, &graph, &sig, reveal).unwrap();
        assert_eq!(successors.len(), 2);
        assert_eq!(successors[1].1["modeName"], "KCOMClaimShard");
        assert_eq!(successors[1].1["artifactProfile"], Profile::FAST_NAME);
        assert_eq!(successors[1].1["shard"], "0");
        let mut forged = tx.clone();
        forged.outputs[1].script_public_key = format!("aa20{}87", "ff".repeat(32));
        assert!(decode_factory_successors(&forged, 0, &graph, &sig, reveal)
            .unwrap_err().to_string().contains("forged KCOMClaimShard successor script"));
    }

    #[test]
    fn timing_profiles_keep_the_same_state_schema_and_dispatch() {
        for template in [KnownTemplate::KcomInitialize, KnownTemplate::KcomFactory,
            KnownTemplate::KcomVault, KnownTemplate::KcomClaimShard,
            KnownTemplate::KcomSettlement, KnownTemplate::KcomClaimCommitment,
            KnownTemplate::KcomEntitlement] {
            let name = crate::template_name(template);
            let prod = &abi_for(template)["contracts"][name];
            let fast = &abi_for_profile(template, Profile::FastTn10)["contracts"][name];
            assert_eq!(prod["runtime_state"], fast["runtime_state"], "{name} state schema");
            assert_eq!(prod["compiled"]["state_span"], fast["compiled"]["state_span"], "{name} span");
            for (name, entry) in prod["entries"].as_object().unwrap() {
                assert_eq!(entry["dispatch_tag"], fast["entries"][name]["dispatch_tag"]);
            }
        }
    }
}
