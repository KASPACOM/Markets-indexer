//! Golden tests for `compute_covenant_id`.
//!
//! Vectors at `tests/golden/golden.json` are produced by `generate.mjs`,
//! which calls `@noble/hashes/blake2b` with the exact same preimage layout as
//! `covenant-sdk/src/covenant.ts:265`. If a vector ever disagrees, the Rust
//! port has drifted from the TS canonical and needs to be fixed.

use serde::Deserialize;
use tn12_indexer_core::{compute_covenant_id, AuthOutput};

#[derive(Debug, Deserialize)]
struct AuthOutputJson {
    index: u32,
    value: String,
    #[serde(rename = "scriptVersion")]
    script_version: u16,
    #[serde(rename = "scriptBytes")]
    script_bytes: String,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    txid: String,
    index: u32,
    #[serde(rename = "authOutputs")]
    auth_outputs: Vec<AuthOutputJson>,
    expected: String,
}

#[test]
fn matches_ts_implementation() {
    let raw = include_str!("golden/golden.json");
    let vectors: Vec<Vector> = serde_json::from_str(raw).expect("golden.json parse");
    assert!(!vectors.is_empty(), "no golden vectors loaded");

    for v in &vectors {
        let auth: Vec<AuthOutput> = v
            .auth_outputs
            .iter()
            .map(|a| AuthOutput {
                index: a.index,
                value: a.value.parse().expect("value u64"),
                script_version: a.script_version,
                script_bytes: hex::decode(&a.script_bytes).expect("script bytes hex"),
            })
            .collect();

        let got = compute_covenant_id(&v.txid, v.index, &auth).expect("hash");
        assert_eq!(
            got, v.expected,
            "mismatch on vector '{}': got {} expected {}",
            v.name, got, v.expected
        );
    }
}
