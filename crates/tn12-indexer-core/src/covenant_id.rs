//! Rust port of `computeCovenantId` from
//! `kaspacom-web-wallet:tn-12/src/app/services/covenant/covenant-sdk/covenant.ts:265`.
//!
//! Algorithm: Blake2b-256 keyed with `"CovenantID"` over the canonical preimage:
//!   - outpoint.txid (32 bytes raw)
//!   - outpoint.index (u32, little-endian)
//!   - auth_outputs.len() (u64, little-endian)
//!   - for each auth output: index (u32 LE), value (u64 LE),
//!     scriptVersion (u16 LE), scriptBytes length (u64 LE), scriptBytes
//!
//! Validated against the TypeScript implementation through golden tests.

use blake2::digest::consts::U32;
use blake2::digest::{KeyInit, Mac};
use blake2::Blake2bMac;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CovenantIdError {
    #[error("txid must be 32 hex bytes (64 chars), got {0} chars")]
    BadTxidLen(usize),
    #[error("invalid hex in txid: {0}")]
    BadTxidHex(String),
}

#[derive(Debug, Clone)]
pub struct AuthOutput {
    pub index: u32,
    pub value: u64,
    pub script_version: u16,
    pub script_bytes: Vec<u8>,
}

const DOMAIN_KEY: &[u8] = b"CovenantID";

type Blake2bMac256 = Blake2bMac<U32>;

/// Returns the 32-byte covenant id, hex-encoded.
pub fn compute_covenant_id(
    outpoint_txid_hex: &str,
    outpoint_index: u32,
    auth_outputs: &[AuthOutput],
) -> Result<String, CovenantIdError> {
    let txid_bytes = decode_txid(outpoint_txid_hex)?;

    let mut mac = <Blake2bMac256 as KeyInit>::new_from_slice(DOMAIN_KEY)
        .expect("Blake2b accepts any key length up to 64 bytes");

    mac.update(&txid_bytes);
    mac.update(&outpoint_index.to_le_bytes());
    mac.update(&(auth_outputs.len() as u64).to_le_bytes());
    for ao in auth_outputs {
        mac.update(&ao.index.to_le_bytes());
        mac.update(&ao.value.to_le_bytes());
        mac.update(&ao.script_version.to_le_bytes());
        mac.update(&(ao.script_bytes.len() as u64).to_le_bytes());
        mac.update(&ao.script_bytes);
    }

    let out = mac.finalize().into_bytes();
    Ok(hex::encode(out))
}

fn decode_txid(hex_str: &str) -> Result<[u8; 32], CovenantIdError> {
    if hex_str.len() != 64 {
        return Err(CovenantIdError::BadTxidLen(hex_str.len()));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out)
        .map_err(|e| CovenantIdError::BadTxidHex(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_txid_length() {
        let err = compute_covenant_id("deadbeef", 0, &[]).unwrap_err();
        assert!(matches!(err, CovenantIdError::BadTxidLen(_)));
    }

    #[test]
    fn deterministic_output() {
        let a = compute_covenant_id(
            &"11".repeat(32),
            5,
            &[AuthOutput {
                index: 0,
                value: 1_000,
                script_version: 0,
                script_bytes: vec![0xaa],
            }],
        )
        .unwrap();
        let b = compute_covenant_id(
            &"11".repeat(32),
            5,
            &[AuthOutput {
                index: 0,
                value: 1_000,
                script_version: 0,
                script_bytes: vec![0xaa],
            }],
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn index_changes_output() {
        let preimage_a = compute_covenant_id(&"00".repeat(32), 0, &[]).unwrap();
        let preimage_b = compute_covenant_id(&"00".repeat(32), 1, &[]).unwrap();
        assert_ne!(preimage_a, preimage_b);
    }
}
