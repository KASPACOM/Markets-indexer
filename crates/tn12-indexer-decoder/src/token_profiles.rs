//! Bundled token templates, authenticated independently of token metadata.
use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::OnceLock;

pub const STANDARD_REVISION: &str = "3fbec524abfbc20e87652eb938db218f8c17db17";
const REGISTRY: &str = include_str!("../../../wallet-lab/vendor/token-profiles/registry.json");
const DIGEST: &str = include_str!("../../../wallet-lab/vendor/token-profiles/registry.sha256");

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenProfile {
    pub id: String,
    pub template_hash: String,
    pub script_length: usize,
    pub state_layout: StateLayout,
    pub standard_revision: String,
    pub native_extensions: bool,
    pub transfer_tag: String,
    pub delegator_tag: String,
    pub wrapper: Option<WrapperProfile>,
    pub display_decimals: Option<u8>,
    pub max_token_inputs: usize,
    pub max_token_outputs: usize,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrapperProfile {
    pub fingerprint: String,
    pub script_length: usize,
    pub token_template_hash: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct StateLayout {
    pub start: usize,
    pub len: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Registry {
    schema: String,
    standard_revision: String,
    profiles: Vec<TokenProfile>,
}

pub fn parse_registry(raw: &str, digest: &str) -> Result<Vec<TokenProfile>> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let canonical = serde_json::to_vec(&value)?;
    if hex::encode(Sha256::digest(canonical)) != digest.trim() {
        bail!("KCC20 token profile registry digest mismatch");
    }
    let registry: Registry = serde_json::from_value(value)?;
    if registry.schema != "kcc20-token-profiles/v2"
        || registry.standard_revision != STANDARD_REVISION
    {
        bail!("unsupported KCC20 token profile registry");
    }
    let mut ids = HashSet::new();
    let mut hashes = HashSet::new();
    for p in &registry.profiles {
        if !ids.insert(p.id.clone())
            || !hashes.insert(p.template_hash.clone())
            || hex::decode(&p.template_hash)?.len() != 32
            || p.max_token_inputs == 0
            || p.max_token_inputs > 255
            || p.max_token_outputs == 0
            || p.max_token_outputs > 255
            || p.state_layout.len != 112
            || p.state_layout
                .start
                .checked_add(112)
                .is_none_or(|end| end > p.script_length)
            || p.standard_revision != STANDARD_REVISION
            || hex::decode(&p.transfer_tag)?.len() != 4
            || hex::decode(&p.delegator_tag)?.len() != 4
        {
            bail!("invalid or duplicate KCC20 token profile");
        }
        if let Some(w) = &p.wrapper {
            if w.token_template_hash != p.template_hash
                || hex::decode(&w.fingerprint)?.len() != 32
                || w.script_length <= 45
            {
                bail!("invalid wrapper profile binding");
            }
        }
    }
    Ok(registry.profiles)
}

pub fn bundled_profiles() -> &'static [TokenProfile] {
    static PROFILES: OnceLock<Vec<TokenProfile>> = OnceLock::new();
    PROFILES
        .get_or_init(|| parse_registry(REGISTRY, DIGEST).expect("invalid bundled token profiles"))
}

pub fn template_hash(script: &[u8], state_start: usize) -> Result<[u8; 32]> {
    let end = state_start
        .checked_add(112)
        .ok_or_else(|| anyhow!("state range overflow"))?;
    if end > script.len() {
        bail!("state range outside script");
    }
    let (prefix, suffix) = (&script[..state_start], &script[end..]);
    let mut hash = blake3::Hasher::new();
    hash.update(&(prefix.len() as u64).to_le_bytes());
    hash.update(prefix);
    hash.update(&(suffix.len() as u64).to_le_bytes());
    hash.update(suffix);
    Ok(*hash.finalize().as_bytes())
}

pub fn profile_for_reveal(script: &[u8]) -> Option<&'static TokenProfile> {
    bundled_profiles().iter().find(|p| {
        script.len() == p.script_length
            && template_hash(script, p.state_layout.start)
                .is_ok_and(|hash| hex::encode(hash) == p.template_hash)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_manifest_and_rejects_tampering() {
        assert!(!parse_registry(REGISTRY, DIGEST).unwrap().is_empty());
        assert!(parse_registry(
            &REGISTRY.replace("kcc20-token-profiles/v2", "invalid"),
            DIGEST
        )
        .is_err());
    }
    #[test]
    fn identifies_current_artifact_without_fixed_script_length() {
        let script = crate::kcc20_compiled_placeholder();
        let p = profile_for_reveal(&script).unwrap();
        assert_eq!(p.standard_revision, STANDARD_REVISION);
        let mut altered = script.clone();
        let end = altered.len() - 1;
        altered[end] ^= 1;
        assert!(profile_for_reveal(&altered).is_none());
    }
    #[test]
    fn distinct_profile_decodes_a_different_length_and_state_offset() {
        use crate::TemplateDecoder;
        let mut script = crate::kcc20_compiled_placeholder();
        script.insert(0, 0x61); // Distinct test template.
        assert!(profile_for_reveal(&script).is_none());
        let mut profile = bundled_profiles()[0].clone();
        profile.id = "offline-distinct-template".into();
        profile.state_layout.start += 1;
        profile.script_length = script.len();
        profile.template_hash =
            hex::encode(template_hash(&script, profile.state_layout.start).unwrap());
        profile.native_extensions = false;
        let decoder = crate::kcc20_standard::Kcc20StandardDecoder::from_profile(profile).unwrap();
        assert!(decoder.matches_reveal_script(&script));
        let state = decoder.decode_constructor(&script).unwrap();
        assert_eq!(state["profileId"], "offline-distinct-template");
        assert!(state["state"]["amount"].is_string());
        assert!(!decoder.matches_reveal_script(&crate::kcc20_compiled_placeholder()));
    }
    #[test]
    fn independent_argent_profile_has_its_own_state_offset_and_boundaries() {
        use crate::TemplateDecoder;
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../../wallet-lab/vendor/token-profiles/ArgentKCC20.reference.json"
        ))
        .unwrap();
        let script: Vec<u8> = artifact["script"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect();
        let profile = bundled_profiles()
            .iter()
            .find(|p| p.id == "argent-reference-kcc20-v1")
            .unwrap();
        assert_ne!(profile.state_layout.start, 1);
        assert!(crate::default_registry().find_for_reveal(&script).is_some());
        let decoder =
            crate::kcc20_standard::Kcc20StandardDecoder::from_profile(profile.clone()).unwrap();
        assert!(decoder.matches_reveal_script(&script));
        let decoded = decoder.decode_constructor(&script).unwrap();
        assert_eq!(decoded["state"]["amount"], "0");
    }
}
