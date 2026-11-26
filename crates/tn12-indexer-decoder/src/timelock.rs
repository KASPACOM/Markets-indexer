//! TimeLockVault decoder.
//!
//! On-chain shape, proven by `kaspacom-web-wallet` PR #173 + `fixtures/timelock-live/`:
//!
//!   * Deploy: single P2SH output `OP_BLAKE2B 0x20 <script_hash> OP_EQUAL`,
//!     funded by the deployer; tx payload is null.
//!   * Spend: tx version=1, one input whose `signature_script` is
//!     `OP_PUSH65 <sig||sighash> <selector> OP_PUSHDATA1 <len> <reveal_script>`.
//!     The reveal script is the compiled SilverScript bytecode with three
//!     constructor pushes filled in (owner pubkey 32B, recovery pubkey 32B,
//!     timeout 6B little-endian).
//!
//! Entrypoint inference:
//!   * selector `0x00` (OP_0) → `spend` (owner withdraws).
//!   * selector `0x51` (OP_1) → `recover` (recovery key after timeout).
//!
//! Template detection: hash the reveal script after zeroing the constructor
//! placeholder ranges. The fingerprint is stable across deploys.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use tn12_indexer_core::{blake2b_256, parse_minimal_int, skip_one_push, KnownTemplate};

use crate::TemplateDecoder;

/// Compiled TimeLockVault bytecode length (TN12, kaspacom-web-wallet `tn-12`).
pub const TIMELOCK_SCRIPT_LEN: usize = 103;

/// Byte ranges (inclusive start, exclusive end) of the constructor pushes
/// inside the compiled TimeLockVault script.
// Layout (offsets in compiled bytecode):
//   bytes  0..8   header `76 00 9c 63 75 00 79 20`
//   bytes  8..40  owner pubkey (PUSH32 data)
//   bytes 40..53  mid `ac 69 75 51 67 76 51 9c 63 75 00 79 20`
//   bytes 53..85  recovery pubkey (PUSH32 data)
//   bytes 85..88  mid `ac 69 06`
//   bytes 88..94  timeout (PUSH6 data, little-endian millis)
//   bytes 94..103 trailing `b0 75 51 67 75 00 69 68 68`
const CONSTRUCTOR_RANGES: &[(usize, usize)] = &[(8, 40), (53, 85), (88, 94)];

/// Blake2b-256 of the TimeLockVault compiled bytecode with the three constructor
/// regions zeroed. Computed once in tests/`timelock_fingerprint.rs` (and in
/// `decoders::known_templates()`); kept here as a constant so registration is
/// trivial.
pub const TIMELOCK_FINGERPRINT: [u8; 32] =
    hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000");
// NOTE: the all-zero placeholder is replaced at decoder registration time via
// `TimeLockVaultDecoder::fingerprint_of_compiled_script`. We keep a constant
// here only as a convenient default for callers that supply the hash.

pub struct TimeLockVaultDecoder {
    pub script_hash: [u8; 32],
    pub fingerprint: [u8; 32],
}

impl TimeLockVaultDecoder {
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            script_hash: fingerprint,
            fingerprint,
        }
    }

    /// Compute the template fingerprint from a compiled script (constructor
    /// regions zeroed before hashing).
    pub fn fingerprint_of_compiled_script(script: &[u8]) -> [u8; 32] {
        let mut masked = script.to_vec();
        for (start, end) in CONSTRUCTOR_RANGES {
            if *end <= masked.len() {
                for b in masked[*start..*end].iter_mut() {
                    *b = 0;
                }
            }
        }
        blake2b_256(&masked)
    }

    fn match_inner(&self, reveal_script: &[u8]) -> bool {
        if reveal_script.len() != TIMELOCK_SCRIPT_LEN {
            return false;
        }
        let masked_hash = Self::fingerprint_of_compiled_script(reveal_script);
        masked_hash == self.fingerprint
    }

    /// Extract `(owner, recovery, timeout_bytes)` from a reveal script in
    /// fixed byte positions, skipping the OP_PUSH prefix bytes.
    fn extract_args(reveal: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
        if reveal.len() != TIMELOCK_SCRIPT_LEN {
            return Err(anyhow!(
                "reveal script is {} bytes, expected {}",
                reveal.len(),
                TIMELOCK_SCRIPT_LEN
            ));
        }
        Ok((&reveal[8..40], &reveal[53..85], &reveal[88..94]))
    }
}

impl TemplateDecoder for TimeLockVaultDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::TimeLockVault
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        self.match_inner(reveal)
    }

    fn decode_constructor(&self, payload: &[u8]) -> Result<Value> {
        let (owner, recovery, timeout_bytes) = Self::extract_args(payload)?;
        Ok(json!({
            "owner": hex::encode(owner),
            "recovery": hex::encode(recovery),
            "timeoutMs": parse_minimal_int(timeout_bytes),
        }))
    }

    fn decode_state(&self, _payload: &[u8]) -> Result<Value> {
        // TimeLockVault has no mutable state beyond the constructor args.
        Ok(Value::Null)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        let after_sig = skip_one_push(signature_script)?;
        match after_sig.first()? {
            0x00 => Some("spend".into()),
            0x51 => Some("recover".into()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timelock_compiled() -> Vec<u8> {
        // bytes from kaspacom-web-wallet src/assets/covenant-templates/time-lock-vault.json
        hex::decode("76009c6375007920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ac6975516776519c63750079202726cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fcac69060010a5d4e800b07551677500696868").unwrap_or_default()
    }

    #[test]
    fn fingerprint_is_stable_across_constructor_args() {
        let template_bytes = hex::decode("76009c6375007920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ac6975516776519c63750079\
2026cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fcac69060010a5d4e800b07551677500696868").unwrap_or_default();
        let _ = template_bytes; // not used directly; just demonstrating shape
                                // Build an instance with random constructor args and verify the
                                // fingerprint matches the all-placeholder script.
        let placeholder = hex::decode(
            "76009c6375007920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9\
ac6975516776519c637500\
7920bbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9cac\
69060010a5d4e800b07551677500696868",
        )
        .unwrap();
        let placeholder_fp = TimeLockVaultDecoder::fingerprint_of_compiled_script(&placeholder);

        let real_reveal = hex::decode(
            "76009c637500792026cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fcac\
6975516776519c63750079201847d93e2254d109f8dc3bd4f90d59673d36fe259825b665c659476df20e9a86ac\
69060066ab6bdc00b07551677500696868",
        )
        .unwrap();
        let real_fp = TimeLockVaultDecoder::fingerprint_of_compiled_script(&real_reveal);

        assert_eq!(
            placeholder_fp,
            real_fp,
            "fingerprint diverged: placeholder={} real={}",
            hex::encode(placeholder_fp),
            hex::encode(real_fp)
        );
        assert_eq!(real_reveal.len(), TIMELOCK_SCRIPT_LEN);
    }

    #[test]
    fn decodes_constructor_args_from_live_reveal() {
        // Reveal script from fixtures/timelock-live/redeem.json (after stripping
        // sig + selector + PUSHDATA1 header).
        let reveal = hex::decode(
            "76009c637500792026cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fcac\
6975516776519c63750079201847d93e2254d109f8dc3bd4f90d59673d36fe259825b665c659476df20e9a86ac\
69060066ab6bdc00b07551677500696868",
        )
        .unwrap();
        let fp = TimeLockVaultDecoder::fingerprint_of_compiled_script(&reveal);
        let d = TimeLockVaultDecoder::new(fp);
        let v = d.decode_constructor(&reveal).unwrap();
        assert_eq!(
            v["owner"],
            "26cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fc"
        );
        assert_eq!(
            v["recovery"],
            "1847d93e2254d109f8dc3bd4f90d59673d36fe259825b665c659476df20e9a86"
        );
        assert!(v["timeoutMs"].is_number());
    }

    #[test]
    fn infers_spend_entrypoint() {
        let mut s = vec![0x41];
        s.extend(std::iter::repeat(0).take(65));
        s.push(0x00); // OP_0 = spend
        let d = TimeLockVaultDecoder::new([0; 32]);
        assert_eq!(d.decode_action(&s).as_deref(), Some("spend"));
    }

    #[test]
    fn infers_recover_entrypoint() {
        let mut s = vec![0x41];
        s.extend(std::iter::repeat(0).take(65));
        s.push(0x51); // OP_1 = recover
        let d = TimeLockVaultDecoder::new([0; 32]);
        assert_eq!(d.decode_action(&s).as_deref(), Some("recover"));
    }
}
