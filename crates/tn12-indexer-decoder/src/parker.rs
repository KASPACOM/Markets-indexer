//! Decoders for Parker's TN12 covenant prototype templates
//! (DelayedRecoveryVault, AssurancePledge, Escrow, EscrowExpired).
//!
//! Source: github.com/parker2017code/tn12-covenant-vault-demo (vendored at
//! the historical Parker prototype. The compiled `.script` arrays from each
//! `artifacts/<Template>.json` are baked into this module as hex constants.
//!
//! Identity strategy: each decoder fingerprints templates by the
//! length-invariant `template_fingerprint` (Blake2b-256 of the opcode-only
//! signature). Constructor extraction is intentionally *not* implemented in v1
//! — Parker's contracts pack each parameter into several push slots throughout
//! the bytecode, and parsing them generically needs an AST walker we haven't
//! added yet. The action/entrypoint mapping covers what the explorer needs
//! today.

use anyhow::Result;
use serde_json::Value;
use tn12_indexer_core::{skip_one_push, template_fingerprint, KnownTemplate};

use crate::TemplateDecoder;

/// Compiled bytecode for each template (placeholder values intact). These hex
/// strings come straight from Parker's `artifacts/<Template>.json` `script`
/// arrays.
const DELAYED_RECOVERY_VAULT_HEX: &str = "6b6c76009c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac690453c7fd69b000c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975516776519c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac6900c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e87697551677500696868";

const ASSURANCE_PLEDGE_HEX: &str = "6b6c76009c637500c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e8769516776519c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac690453c7fd69b000c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e87697551677500696868";

const ESCROW_HEX: &str = "6b6c76009c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac6900c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975516776519c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac690453c7fd69b000c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975516776529c63757820d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac697620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac6900c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975755167750069686868";

const ESCROW_EXPIRED_HEX: &str = "6b6c76009c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac6900c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975516776519c63757620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac6903907351b000c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975516776529c63757820d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac697620d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5ac6900c2b9be028813949c6900c320d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5030000207c7e01ac7e876975755167750069686868";

/// Build a `(template, fingerprint, compiled_bytes)` triple. `decode!` does
/// the hex parse once at construction.
fn build_decoder(template: KnownTemplate, hex_str: &str) -> ParkerDecoder {
    let bytes = hex::decode(hex_str).expect("compile-time hex literal");
    let fingerprint = template_fingerprint(&bytes);
    let canonical_len = bytes.len();
    ParkerDecoder {
        template,
        fingerprint,
        canonical_len,
        _compiled: bytes,
    }
}

pub fn delayed_recovery_vault() -> ParkerDecoder {
    build_decoder(
        KnownTemplate::DelayedRecoveryVault,
        DELAYED_RECOVERY_VAULT_HEX,
    )
}
pub fn assurance_pledge() -> ParkerDecoder {
    build_decoder(KnownTemplate::AssurancePledge, ASSURANCE_PLEDGE_HEX)
}
pub fn escrow() -> ParkerDecoder {
    build_decoder(KnownTemplate::Escrow, ESCROW_HEX)
}
pub fn escrow_expired() -> ParkerDecoder {
    build_decoder(KnownTemplate::EscrowExpired, ESCROW_EXPIRED_HEX)
}

pub struct ParkerDecoder {
    template: KnownTemplate,
    fingerprint: [u8; 32],
    /// Canonical compiled length. Used to disambiguate templates that share
    /// a fingerprint but differ in baked-in int-literal push size (notably
    /// Escrow 351 vs EscrowExpired 350 — they only differ in the
    /// refundTime literal width).
    canonical_len: usize,
    _compiled: Vec<u8>,
}

impl TemplateDecoder for ParkerDecoder {
    fn template(&self) -> KnownTemplate {
        self.template
    }

    fn name(&self) -> &'static str {
        match self.template {
            KnownTemplate::DelayedRecoveryVault => "DelayedRecoveryVault",
            KnownTemplate::AssurancePledge => "AssurancePledge",
            KnownTemplate::Escrow => "Escrow",
            KnownTemplate::EscrowExpired => "EscrowExpired",
            _ => "Unknown",
        }
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        // Fingerprint match is necessary but not sufficient: the opcode-only
        // signature normalises push sizes, so Escrow (351 B) and
        // EscrowExpired (350 B) collide. Pin to exact compiled length so
        // they classify separately.
        template_fingerprint(reveal) == self.fingerprint && reveal.len() == self.canonical_len
    }

    fn decode_constructor(&self, _payload: &[u8]) -> Result<Value> {
        // Generic constructor extraction is deferred — see module doc.
        Ok(Value::Null)
    }

    fn decode_state(&self, _payload: &[u8]) -> Result<Value> {
        Ok(Value::Null)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        // The signature_script for a P2SH covenant spend looks like:
        //   [0..K sig pushes] [selector byte] [PUSHDATA1 redeem-script]
        // where K depends on the entrypoint's arity:
        //   * AssurancePledge.release      → K=0
        //   * everything else with 1 sig   → K=1
        //   * Escrow.cancel (buyerSig+sellerSig) → K=2
        //
        // We try each plausible K (smallest first) and return the first
        // selector that maps to a known entrypoint for this template.
        let candidates = [
            (0u8, Some(signature_script)),
            (1, skip_one_push(signature_script)),
            (2, skip_one_push(signature_script).and_then(skip_one_push)),
        ];

        for (k, slice_opt) in candidates {
            let Some(slice) = slice_opt else { continue };
            let Some(&selector) = slice.first() else {
                continue;
            };
            let resolved = match (self.template, selector, k) {
                // DelayedRecoveryVault: 0x00 = withdraw, 0x51 = recover.
                (KnownTemplate::DelayedRecoveryVault, 0x00, 1) => Some("withdraw"),
                (KnownTemplate::DelayedRecoveryVault, 0x51, 1) => Some("recover"),
                // AssurancePledge: 0x00 = release (no sig), 0x51 = refund.
                (KnownTemplate::AssurancePledge, 0x00, 0) => Some("release"),
                (KnownTemplate::AssurancePledge, 0x51, 1) => Some("refund"),
                // Escrow / EscrowExpired: 0x00 = release (1 sig),
                // 0x51 = refund (1 sig), 0x52 = cancel (2 sigs).
                (KnownTemplate::Escrow | KnownTemplate::EscrowExpired, 0x00, 1) => Some("release"),
                (KnownTemplate::Escrow | KnownTemplate::EscrowExpired, 0x51, 1) => Some("refund"),
                (KnownTemplate::Escrow | KnownTemplate::EscrowExpired, 0x52, 2) => Some("cancel"),
                _ => None,
            };
            if let Some(name) = resolved {
                return Some(name.into());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_decoder_has_a_distinct_fingerprint_or_length() {
        let v = delayed_recovery_vault();
        let p = assurance_pledge();
        let e = escrow();
        let ee = escrow_expired();
        assert_ne!(v.fingerprint, p.fingerprint);
        assert_ne!(v.fingerprint, e.fingerprint);
        assert_ne!(p.fingerprint, e.fingerprint);
        // Escrow and EscrowExpired share a fingerprint (the opcode-only
        // signature normalises push sizes) but differ in compiled length,
        // so `matches_reveal_script` now disambiguates them via length.
        assert_eq!(e.fingerprint, ee.fingerprint);
        assert_ne!(e.canonical_len, ee.canonical_len);
    }

    #[test]
    fn escrow_and_escrow_expired_classify_separately() {
        let e = escrow();
        let ee = escrow_expired();
        let e_bytes = hex::decode(ESCROW_HEX).unwrap();
        let ee_bytes = hex::decode(ESCROW_EXPIRED_HEX).unwrap();
        assert!(e.matches_reveal_script(&e_bytes));
        assert!(!e.matches_reveal_script(&ee_bytes));
        assert!(ee.matches_reveal_script(&ee_bytes));
        assert!(!ee.matches_reveal_script(&e_bytes));
    }

    #[test]
    fn fingerprint_stable_under_pubkey_swap() {
        // Swap the placeholder pubkey for a different 32-byte value and
        // confirm the fingerprint stays the same.
        let mut altered = hex::decode(DELAYED_RECOVERY_VAULT_HEX).unwrap();
        let placeholder =
            hex::decode("d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5")
                .unwrap();
        let real = hex::decode("26cb3ff1d2275f7d5b9d960a6f5ec437bf15dfc099dacb199e8d35e8151562fc")
            .unwrap();
        let mut i = 0;
        while i + 32 <= altered.len() {
            if altered[i..i + 32] == placeholder[..] {
                altered[i..i + 32].copy_from_slice(&real);
                i += 32;
            } else {
                i += 1;
            }
        }
        let d = delayed_recovery_vault();
        assert!(d.matches_reveal_script(&altered));
    }
}
