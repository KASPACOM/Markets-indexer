//! Argent KCOM vesting decoding from the compiler-owned Program ABI.
use crate::{
    kcc20::{args_prefix_before_reveal, item_int, script_items},
    kcc20_standard::item_tag,
    kcom_profile::{self, Profile}, TemplateDecoder,
};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::OnceLock;
use tn12_indexer_core::{
    blake2b_256, p2sh_script_hash, parse_minimal_int, KnownTemplate, RestTransaction,
};
fn abi() -> &'static Value {
    static ABI: OnceLock<Value> = OnceLock::new();
    ABI.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../fixtures/kcom-vesting/KCOMVesting.program-abi.json"
        ))
        .expect("compiler ABI fixture")
    })
}
fn contract() -> &'static Value {
    contract_for(Profile::Production)
}
fn contract_for(profile: Profile) -> &'static Value {
    let abi = if profile == Profile::ConfigurableV2 { kcom_profile::configurable_vesting_abi() } else if profile == Profile::FastTn10 { kcom_profile::fast_vesting_abi() } else { abi() };
    &abi["contracts"]["KCOMVesting"]
}
fn matched_profile(s: &[u8]) -> Option<Profile> {
    Profile::ALL.into_iter().find(|profile| {
        let c = contract_for(*profile);
        let bytes = c["compiled"]["bytecode"].as_array().expect("pinned bytecode");
        let (start, len) = span_for(*profile);
        s.len() == bytes.len() && start + len <= s.len()
            && s[..start].iter().zip(&bytes[..start]).all(|(a,b)| Some(u64::from(*a)) == b.as_u64())
            && s[start+len..].iter().zip(&bytes[start+len..]).all(|(a,b)| Some(u64::from(*a)) == b.as_u64())
    })
}
fn script() -> Vec<u8> {
    contract()["compiled"]["bytecode"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect()
}
fn span() -> (usize, usize) {
    span_for(Profile::Production)
}
fn span_for(profile: Profile) -> (usize, usize) {
    let s = &contract_for(profile)["compiled"]["state_span"];
    (
        s["offset"].as_u64().unwrap() as usize,
        s["len"].as_u64().unwrap() as usize,
    )
}
fn fingerprint(s: &[u8]) -> [u8; 32] {
    let (mut masked, (start, len)) = (s.to_vec(), span());
    if start + len <= masked.len() {
        masked[start..start + len].fill(0);
    }
    blake2b_256(&masked)
}
#[derive(Default)]
pub struct KcomVestingDecoder;
impl TemplateDecoder for KcomVestingDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::KcomVesting
    }
    fn script_hash(&self) -> [u8; 32] {
        fingerprint(&script())
    }
    fn matches_reveal_script(&self, s: &[u8]) -> bool {
        matched_profile(s).is_some()
    }
    fn decode_constructor(&self, s: &[u8]) -> Result<Value> {
        decode_reveal_state_value(s)
    }
    fn decode_state(&self, s: &[u8]) -> Result<Value> {
        decode_payload(s)
    }
    fn decode_action_checked(&self, signature_script: &[u8]) -> Result<Option<String>> {
        self.decode_action(signature_script)
            .map(Some)
            .ok_or_else(|| anyhow!(crate::InterpretationFailure("unsupported spend action")))
    }

    fn decode_action(&self, s: &[u8]) -> Option<String> {
        let items = script_items(args_prefix_before_reveal(s));
        let tag = item_tag(items.last()?)?;
        for name in ["release", "finish"] {
            if hex::encode(tag) == contract()["entries"][name]["dispatch_tag"].as_str()? {
                return Some(name.into());
            }
        }
        None
    }
}
fn decode_payload(bytes: &[u8]) -> Result<Value> {
    decode_payload_for(bytes, Profile::Production)
}
fn decode_payload_for(mut bytes: &[u8], profile: Profile) -> Result<Value> {
    let mut out = serde_json::Map::new();
    for f in contract_for(profile)["runtime_state"]["fields"].as_array().unwrap() {
        let t = &f["type"];
        let kind = t["kind"].as_str().unwrap();
        let width = match kind {
            "fixed_bytes" => t["len"].as_u64().unwrap() as usize,
            "byte" => 1,
            "int" => 8,
            _ => return Err(anyhow!("unsupported ABI type")),
        };
        ensure!(
            bytes.len() > width && bytes[0] as usize == width,
            "noncanonical explicit state field"
        );
        let value = &bytes[1..1 + width];
        out.insert(
            f["name"].as_str().unwrap().into(),
            match kind {
                "int" => json!(parse_minimal_int(value).to_string()),
                "byte" => json!(value[0]),
                _ => json!(hex::encode(value)),
            },
        );
        bytes = &bytes[width + 1..];
    }
    ensure!(bytes.is_empty(), "trailing state bytes");
    let mut value = Value::Object(out);
    value["canonicalTokenId"] = value["token_id"].clone();
    value["stateOwner"] = value["beneficiary"].clone();
    value["stateOwnerType"] = value["beneficiary_scheme"].clone();
    value["modeName"] = json!("kcom-vesting");
    Ok(value)
}
pub fn decode_reveal_state_value(s: &[u8]) -> Result<Value> {
    let profile = matched_profile(s).context("vesting template mismatch")?;
    let (start, len) = span_for(profile);
    let mut state = decode_payload_for(&s[start..start + len], profile)?;
    profile.annotate(&mut state);
    Ok(state)
}
/// Reconstruct the reviewed vesting script from its ABI state without changing executable bytes.
pub fn script_for_state_value(state: &Value) -> Result<Vec<u8>> {
    let profile = Profile::from_state(state.as_object().context("vesting state")?)?;
    let selected_contract = contract_for(profile);
    let mut script: Vec<u8> = selected_contract["compiled"]["bytecode"].as_array().context("vesting bytes")?
        .iter().map(|b| b.as_u64().expect("compiled byte") as u8).collect();
    let (start, len) = span_for(profile);
    let mut offset = start;
    for field in selected_contract["runtime_state"]["fields"]
        .as_array()
        .context("vesting fields")?
    {
        let name = field["name"].as_str().context("vesting field name")?;
        let ty = &field["type"];
        let bytes = match ty["kind"].as_str().context("vesting field kind")? {
            "fixed_bytes" => {
                let bytes = hex::decode(
                    state[name]
                        .as_str()
                        .with_context(|| format!("missing {name}"))?,
                )?;
                ensure!(
                    bytes.len() == ty["len"].as_u64().context("vesting byte width")? as usize,
                    "invalid {name} width"
                );
                bytes
            }
            "byte" => vec![u8::try_from(
                state[name]
                    .as_u64()
                    .with_context(|| format!("missing {name}"))?,
            )?],
            "int" => state[name]
                .as_str()
                .with_context(|| format!("missing {name}"))?
                .parse::<i64>()?
                .to_le_bytes()
                .to_vec(),
            _ => return Err(anyhow!("unsupported vesting ABI field {name}")),
        };
        ensure!(
            script.get(offset).copied() == Some(bytes.len() as u8),
            "vesting ABI state layout differs at {name}"
        );
        script[offset + 1..offset + 1 + bytes.len()].copy_from_slice(&bytes);
        offset += 1 + bytes.len();
    }
    ensure!(offset == start + len, "vesting state span differs from ABI");
    decode_reveal_state_value(&script)?;
    Ok(script)
}
/// Accepted-chain successor inference verifies the exact reconstructed output hash and lineage.
pub fn decode_successors(
    tx: &RestTransaction,
    input_index: usize,
    covenant_id: &[u8],
    sig: &[u8],
    reveal: &[u8],
) -> Result<Vec<(i32, Value)>> {
    let state = decode_reveal_state_value(reveal)?;
    let action = KcomVestingDecoder
        .decode_action(sig)
        .context(crate::InterpretationFailure("unknown vesting action"))?;
    let authorizing_input = u16::try_from(input_index)?;
    let authorized = tx
        .outputs
        .iter()
        .filter(|o| o.covenant_authorizing_input() == Some(authorizing_input))
        .collect::<Vec<_>>();
    if action == "finish" {
        ensure!(authorized.is_empty(), "finish has a position successor");
        return Ok(vec![]);
    }
    ensure!(
        authorized.len() == 1,
        "release needs exactly one position successor"
    );
    let output = authorized[0];
    let id = output
        .canonical_covenant_id()
        .context("missing successor covenant ID")?;
    ensure!(hex::decode(id)? == covenant_id, "wrong successor lineage");
    let items = script_items(args_prefix_before_reveal(sig));
    let amount = item_int(&items, 1)?;
    ensure!(amount > 0, "release amount must be positive");
    let prior = state["released"]
        .as_str()
        .context("released")?
        .parse::<i64>()?;
    let amount = i64::try_from(amount)?;
    let next = prior.checked_add(amount).context("released overflow")?;
    let total = state["total"].as_str().context("total")?.parse::<i64>()?;
    ensure!(next < total, "release must continue a nonempty position");
    let mut next_script = reveal.to_vec();
    let profile = matched_profile(reveal).context("vesting template mismatch")?;
    let (start, _) = span_for(profile);
    let mut offset = start;
    for f in contract_for(profile)["runtime_state"]["fields"].as_array().unwrap() {
        let width = next_script[offset] as usize;
        if f["name"] == "released" {
            next_script[offset + 1..offset + 1 + width].copy_from_slice(&next.to_le_bytes());
            break;
        }
        offset += width + 1;
    }
    let spk = hex::decode(&output.script_public_key)?;
    ensure!(
        p2sh_script_hash(&spk) == Some(blake2b_256(&next_script)),
        "forged vesting successor script"
    );
    Ok(vec![(
        i32::try_from(output.index)?,
        decode_reveal_state_value(&next_script)?,
    )])
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fast_vesting_preserves_schema_and_authenticates_profile() {
        let prod = contract_for(Profile::Production);
        let fast = contract_for(Profile::FastTn10);
        assert_eq!(prod["runtime_state"], fast["runtime_state"]);
        assert_eq!(prod["compiled"]["state_span"], fast["compiled"]["state_span"]);
        for (name, entry) in prod["entries"].as_object().unwrap() {
            assert_eq!(entry["dispatch_tag"], fast["entries"][name]["dispatch_tag"]);
        }
        let bytes: Vec<u8> = fast["compiled"]["bytecode"].as_array().unwrap()
            .iter().map(|b| b.as_u64().unwrap() as u8).collect();
        let state = decode_reveal_state_value(&bytes).unwrap();
        assert_eq!(state["artifactProfile"], Profile::FAST_NAME);
        assert_eq!(script_for_state_value(&state).unwrap(), bytes);
        let mut swapped = state.clone();
        swapped.as_object_mut().unwrap().remove("artifactProfile");
        assert_ne!(script_for_state_value(&swapped).unwrap(), bytes);
        let mut forged = bytes.clone();
        let (start, len) = span_for(Profile::FastTn10);
        forged[start + len] ^= 1;
        assert!(decode_reveal_state_value(&forged).is_err());
    }

    #[test]
    fn campaign_activation_position_matches_both_builder_vectors() {
        let fixture: Value =
            serde_json::from_str(include_str!("../fixtures/kcom-claim-factory-vectors.json"))
                .unwrap();
        let activation = &fixture["activationVectors"];
        assert_eq!(
            activation["sourceFixtureSha256"],
            "93f8fe414d86cf228de058e3008401562fd6accd158ba28e27610cc58c63fc33"
        );
        for name in ["first", "last"] {
            let vector = &activation[name];
            let entitlement = &vector["entitlementState"];
            let state = json!({
                "token_id": activation["tokenId"],
                "beneficiary": entitlement["beneficiary"],
                "beneficiary_scheme": entitlement["beneficiary_scheme"],
                "extension": activation["extension"],
                "total": vector["allocationRaw"],
                "released": "0",
                "tier": entitlement["tier"],
                "tge_ms": entitlement["tge_ms"],
                "token_prefix_len": "1",
                "token_suffix_len": "25264",
                "token_template_hash": "5d6cacdf57c734536fcb8a9c833f0318671226727ec77c503a98fc5be59f9e29"
            });
            let script = script_for_state_value(&state).unwrap();
            let spk = format!("aa20{}87", hex::encode(blake2b_256(&script)));
            assert_eq!(spk, vector["outputs"][1]["scriptPublicKeyHex"], "{name}");
            assert_eq!(
                decode_reveal_state_value(&script).unwrap()["total"],
                vector["allocationRaw"]
            );
        }
    }
    #[test]
    fn authenticated_template_and_fields() {
        let mut s = script();
        assert!(KcomVestingDecoder.matches_reveal_script(&s));
        let v = decode_reveal_state_value(&s).unwrap();
        assert!(v.get("released").is_some());
        let last = s.len() - 1;
        s[last] ^= 1;
        assert!(!KcomVestingDecoder.matches_reveal_script(&s));
        assert!(decode_reveal_state_value(&s).is_err());
    }
    #[test]
    fn state_encoding_rejects_wrong_push_width() {
        let s = script();
        let (start, len) = span();
        let mut p = s[start..start + len].to_vec();
        p[0] = 31;
        assert!(decode_payload(&p).is_err());
    }
    #[test]
    fn accepted_tn10_partial_and_final_and_mutations() {
        for (raw, expected) in [
            (
                include_str!("../fixtures/kcom-vesting/tn10-partial.json"),
                1,
            ),
            (include_str!("../fixtures/kcom-vesting/tn10-final.json"), 0),
        ] {
            let tx: RestTransaction = serde_json::from_str(raw).unwrap();
            assert!(tx.is_accepted);
            let sig = hex::decode(&tx.inputs[0].signature_script).unwrap();
            let reveal = match script_items(&sig).last().unwrap() {
                crate::kcc20::ScriptItem::Data(data) => data.clone(),
                _ => panic!("missing reveal"),
            };
            let id =
                hex::decode("85993bebe31f14f88d26a686c457213cc4d748b18a9bf8bbfcaeae64191dd128")
                    .unwrap();
            let outputs = decode_successors(&tx, 0, &id, &sig, &reveal).unwrap();
            assert_eq!(outputs.len(), expected);
            assert!(decode_successors(&tx, usize::MAX, &id, &sig, &reveal).is_err());
            if expected == 1 {
                assert_eq!(outputs[0].1["released"], "1000");
                let mut bad = tx.clone();
                bad.outputs[2].script_public_key = "00".into();
                assert!(decode_successors(&bad, 0, &id, &sig, &reveal).is_err());
                assert!(decode_successors(&tx, 0, &[0u8; 32], &sig, &reveal).is_err());
                bad = tx.clone();
                bad.outputs.push(bad.outputs[2].clone());
                assert!(decode_successors(&bad, 0, &id, &sig, &reveal).is_err());
                assert_eq!(
                    decode_successors(&tx, 0, &id, &sig, &reveal).unwrap(),
                    outputs
                );
            }
        }
    }
}

#[cfg(test)]
mod configurable_tests {
    use super::*;
    #[test]
    fn configurable_fields_round_trip_and_modified_code_fails() {
        let contract = contract_for(Profile::ConfigurableV2);
        let script: Vec<u8> = contract["compiled"]["bytecode"].as_array().unwrap()
            .iter().map(|b| b.as_u64().unwrap() as u8).collect();
        let mut state = decode_reveal_state_value(&script).unwrap();
        assert_eq!(state["artifactProfile"], Profile::CONFIGURABLE_NAME);
        for (field,value) in [("period_ms","60000"),("first_period","10"),("period_count","36"),("tge_bps","0")] {
            state[field] = json!(value);
        }
        let rebuilt = script_for_state_value(&state).unwrap();
        assert_eq!(decode_reveal_state_value(&rebuilt).unwrap(),state);
        let mut forged = rebuilt.clone();
        let i = forged.len()-1;
        forged[i] ^= 1;
        assert!(decode_reveal_state_value(&forged).is_err());
        state["artifactProfile"] = json!("kcom-fast-tn10-60s-v1");
        assert_ne!(script_for_state_value(&state).unwrap(),rebuilt);
    }
}
