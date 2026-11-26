//! Parser + validator for the `tn10`/`tn12` deployment-envelope written into
//! `tx.payload` by wallets that opt in to the claimed-constructor-params
//! feature. See migrations/20260514000000_claimed_params.sql for the schema
//! columns and the wallet-side rationale.
//!
//! Schema (v1):
//!
//! ```json
//! {
//!   "tn10": {
//!     "v": 1,
//!     "tmpl": "MultiSigVault",
//!     "args": [
//!       {"name":"signer1","type":"address","value":"kaspatest:..."},
//!       {"name":"signer2","type":"address","value":"kaspatest:..."},
//!       {"name":"signer3","type":"address","value":"kaspatest:..."}
//!     ],
//!     "meta": { "label": "...", "tags": ["..."] }   // optional
//!   }
//! }
//! ```
//!
//! Backward compat: any tx whose payload is empty, non-UTF-8, non-JSON, or
//! missing a recognised network key returns `None` here and the persister
//! silently skips the claim. Wallets that don't opt in keep behaving as before.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One declared constructor argument. `type` is loose on purpose — the
/// canonical set lives in the docs (`address` / `pubkey` / `int` / `blueScore`
/// / `bool` / `bytes`) but we don't enforce it here; the spend-time
/// verifier compares against decoded values regardless of declared type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedArg {
    pub name: String,
    #[serde(rename = "type")]
    pub arg_type: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedDeployment {
    /// Schema version. Currently 1; bumps when the envelope shape changes
    /// in a non-additive way.
    pub v: u32,
    /// Template name as the wallet labels it. Free-form to permit future
    /// templates without an indexer-side enum bump; we only enforce that
    /// it's non-empty.
    pub tmpl: String,
    pub args: Vec<ClaimedArg>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub meta: Option<ClaimedMeta>,
}

#[derive(Debug, Clone, Deserialize)]
struct Envelope {
    tn10: Option<ClaimedDeployment>,
    tn12: Option<ClaimedDeployment>,
}

/// Parse a transaction's `payload` hex string into a `ClaimedDeployment`
/// if it carries a recognisable TN10/TN12 envelope. Returns `None` for any of:
///   - empty / non-hex / non-UTF-8 payload
///   - JSON parse failure
///   - missing recognised network key
///   - schema version other than `v == 1`
///   - empty `tmpl` field
///
/// We never error here: a malformed payload simply means "no claim". The
/// scanner is too hot a path to bubble parser noise back as a tx-level
/// failure.
pub fn parse_payload_envelope(payload_hex: &str) -> Option<ClaimedDeployment> {
    if payload_hex.is_empty() {
        return None;
    }
    let bytes = hex::decode(payload_hex).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let env: Envelope = serde_json::from_str(text).ok()?;
    let claim = env.tn10.or(env.tn12)?;
    if claim.v != 1 || claim.tmpl.is_empty() {
        return None;
    }
    Some(claim)
}

/// Serialize a `ClaimedDeployment` into a JSON `Value` shaped for the
/// `covenants.claimed_args` column — `{"tmpl": "...", "args": [...], "meta":
/// {...}}`. We keep `tmpl` denormalised inside this blob too so consumers
/// reading the JSONB column directly don't have to join with
/// `claimed_template`.
pub fn claimed_args_jsonb(c: &ClaimedDeployment) -> Value {
    let mut o = serde_json::Map::new();
    o.insert("tmpl".into(), Value::String(c.tmpl.clone()));
    o.insert(
        "args".into(),
        Value::Array(
            c.args
                .iter()
                .map(|a| serde_json::to_value(a).unwrap_or(Value::Null))
                .collect(),
        ),
    );
    if let Some(meta) = &c.meta {
        if let Ok(m) = serde_json::to_value(meta) {
            o.insert("meta".into(), m);
        }
    }
    Value::Object(o)
}

/// Cross-check the wallet's claimed args against what the decoder pulled
/// out of the spend's reveal script. Returns `true` iff every claimed
/// `address`/`pubkey` arg appears as a 32-byte hex pubkey *somewhere* in
/// `decoded_args`. Other arg types (int/bool/blueScore) are not yet
/// extractable from compiled SilverScript reveals, so we don't penalise
/// their mismatch — we just require the address set to line up, which is
/// the bit that materially identifies a covenant.
///
/// This is intentionally permissive (subset, not exact) to handle templates
/// that bake extra constants beyond the claimed args (timelock values,
/// arity selectors). Lying wallets that change pubkey identities still get
/// caught: an aggregator MuSig pubkey for `{pk1,pk2}` won't match a claim
/// of `pk3`.
pub fn matches_decoded(claimed: &ClaimedDeployment, decoded: &Value) -> bool {
    // Collect every 32-byte hex string we can spot inside `decoded`.
    let mut decoded_hexes = Vec::<String>::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => {
                if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                    out.push(s.to_ascii_lowercase());
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::Object(m) => m.values().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    walk(decoded, &mut decoded_hexes);
    if decoded_hexes.is_empty() {
        // Nothing extractable on the decoded side — can't verify, but also
        // can't disprove. Default to false; the verifier will then leave
        // claim_verified=false and let consumers see both views.
        return false;
    }

    // For every claimed address/pubkey arg, require some decoded hex to
    // contain it (we don't do bech32→pubkey here; treat the claim as opaque
    // and look for any hex collision).
    let claimed_idents: Vec<String> = claimed
        .args
        .iter()
        .filter(|a| matches!(a.arg_type.as_str(), "address" | "pubkey"))
        .filter_map(|a| a.value.as_str().map(|s| s.to_ascii_lowercase()))
        .collect();
    if claimed_idents.is_empty() {
        return false;
    }
    claimed_idents.iter().all(|ci| {
        decoded_hexes
            .iter()
            .any(|h| ci.contains(h) || h.contains(ci))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload_hex_for(json: &str) -> String {
        hex::encode(json.as_bytes())
    }

    #[test]
    fn parses_valid_envelope() {
        let hex = payload_hex_for(
            r#"{"tn10":{"v":1,"tmpl":"MultiSigVault","args":[
                {"name":"signer1","type":"address","value":"kaspatest:qpdzgy"},
                {"name":"signer2","type":"address","value":"kaspatest:qqvy0kf7"},
                {"name":"signer3","type":"address","value":"kaspatest:qqnvk0l3"}
            ]}}"#,
        );
        let c = parse_payload_envelope(&hex).expect("valid envelope");
        assert_eq!(c.tmpl, "MultiSigVault");
        assert_eq!(c.args.len(), 3);
        assert_eq!(c.args[0].arg_type, "address");
    }

    #[test]
    fn parses_legacy_tn12_envelope() {
        let hex = payload_hex_for(r#"{"tn12":{"v":1,"tmpl":"Escrow","args":[]}}"#);
        let c = parse_payload_envelope(&hex).expect("legacy envelope");
        assert_eq!(c.tmpl, "Escrow");
    }

    #[test]
    fn rejects_wrong_version() {
        let hex = payload_hex_for(r#"{"tn12":{"v":2,"tmpl":"X","args":[]}}"#);
        assert!(parse_payload_envelope(&hex).is_none());
    }

    #[test]
    fn rejects_missing_tmpl() {
        let hex = payload_hex_for(r#"{"tn12":{"v":1,"tmpl":"","args":[]}}"#);
        assert!(parse_payload_envelope(&hex).is_none());
    }

    #[test]
    fn rejects_non_tn12_payload() {
        // Some other dApp's payload — must not be mistaken for ours.
        let hex = payload_hex_for(r#"{"unrelated":{"foo":1}}"#);
        assert!(parse_payload_envelope(&hex).is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_payload_envelope("").is_none());
        assert!(parse_payload_envelope("nothex!").is_none());
        assert!(parse_payload_envelope("ffeedd").is_none()); // not valid UTF-8 JSON
    }

    #[test]
    fn matches_when_addresses_match() {
        // A claim where the "address" value is itself a 32-byte hex pubkey
        // hash. Realistic case: wallet writes the bech32 address but the
        // verifier passes after a future address-to-pubkey-hash mapper —
        // we don't have that yet, so this test exercises the easy path.
        let claimed = ClaimedDeployment {
            v: 1,
            tmpl: "MultiSigVault".into(),
            args: vec![ClaimedArg {
                name: "signer1".into(),
                arg_type: "pubkey".into(),
                value: Value::String(
                    "1847d93e2254d109f8dc3bd4f90d59673d36fe259825b665c659476df20e9a86".into(),
                ),
            }],
            meta: None,
        };
        let decoded = serde_json::json!({
            "pubkeys": ["1847d93e2254d109f8dc3bd4f90d59673d36fe259825b665c659476df20e9a86"]
        });
        assert!(matches_decoded(&claimed, &decoded));
    }

    #[test]
    fn mismatches_when_pubkeys_differ() {
        let claimed = ClaimedDeployment {
            v: 1,
            tmpl: "MultiSigVault".into(),
            args: vec![ClaimedArg {
                name: "signer1".into(),
                arg_type: "pubkey".into(),
                value: Value::String("a".repeat(64)),
            }],
            meta: None,
        };
        let decoded = serde_json::json!({"pubkeys": ["b".repeat(64)]});
        assert!(!matches_decoded(&claimed, &decoded));
    }

    #[test]
    fn jsonb_round_trip() {
        let c = ClaimedDeployment {
            v: 1,
            tmpl: "EscrowWithArbiter".into(),
            args: vec![ClaimedArg {
                name: "buyer".into(),
                arg_type: "address".into(),
                value: Value::String("kaspatest:qq".into()),
            }],
            meta: Some(ClaimedMeta {
                label: Some("Q2 pilot".into()),
                description: None,
                tags: Some(vec!["pilot".into()]),
            }),
        };
        let blob = claimed_args_jsonb(&c);
        assert_eq!(blob["tmpl"], "EscrowWithArbiter");
        assert_eq!(blob["args"][0]["name"], "buyer");
        assert_eq!(blob["meta"]["label"], "Q2 pilot");
    }
}
