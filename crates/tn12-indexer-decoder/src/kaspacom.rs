//! Decoders for KASPACOM-authored covenant templates shipped through the
//! wallet flows.
//!
//! These are distinct from Parker's vendored prototype (decoded in
//! `parker.rs`). The legacy spend-tested catalog from
//! `kaspacom-web-wallet:tn-12` commit `c39e4140` remains registered for
//! historical rows, and the PR #359 wallet-contract variants are registered
//! beside it:
//!
//!   DeadManSwitch         keepAlive / changeHeir / topUp / claim
//!   EscrowWithArbiter     release / refund / arbitrate / topUp
//!   MultiSigVault         spend12 / spend13 / spend23 / topUp
//!   TimeLockVault         spend / changeRecovery / recover / topUp
//!     (variant of the wallet PR #173 vault; if its opcode fingerprint
//!     collides with the legacy `TimeLockVaultDecoder` in `timelock.rs`
//!     the registry's first-match wins — both have the same template
//!     name so consumers don't see a difference)
//!
//! Identity strategy matches `parker.rs`: opcode-normalised Blake2b
//! fingerprint. The legacy decoders keep exact length gating; the PR #359
//! variants do not, because wallet-supplied constructor ints can legitimately
//! change byte width while preserving the same template opcode signature.
//!
//! Constructor extraction is intentionally minimal in v1 (returns
//! `Value::Null`). Generic extraction would need an AST walker.
//! Action/entrypoint resolution is what the indexer's API and the
//! explorer frontend rely on today — that's the part we implement.

use anyhow::Result;
use serde_json::Value;
use tn12_indexer_core::{read_push, template_fingerprint, KnownTemplate};

use crate::TemplateDecoder;

// ─── Compiled scripts (placeholders intact) ──────────────────────────────
//
// Pulled byte-for-byte from
//   kaspacom-web-wallet:tn-12/src/assets/covenant-templates/<name>.json
// commit c39e4140. Each is the `script` field's array, hex-encoded.

const LEGACY_DEAD_MANS_SWITCH_HEX: &str = "76009c6375007920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ac6900c2b9be02e80394a26975516776519c6375007920cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebac69060010a5d4e800b07551677500696868";

const LEGACY_ESCROW_WITH_ARBITER_HEX: &str = "76009c6375517920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ac69007920bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9daac6900c320bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da030000207c7e01ac7e87697575516776519c6375007920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ac69060010a5d4e800b000c320aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9030000207c7e01ac7e876975516776529c63755279aa20cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaeb876951795379ac6900c251799c6951c2b9be52799402e803949c697575755167750069686868";

const LEGACY_MULTI_SIG_VAULT_HEX: &str = "76009c6375517920cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebac69007920dddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcac697575516776519c6375517920cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebac69007920eeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0dac697575516776529c6375517920dddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcac69007920eeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0dac6975755167750069686868";

const LEGACY_TIME_LOCK_VAULT_DEV_HEX: &str = "76009c6375007920aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9ac6975516776519c6375007920bbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9cac69060010a5d4e800b07551677500696868";

const WALLET_DEAD_MANS_SWITCH_JSON: &str =
    include_str!("../fixtures/wallet-contracts/DeadManSwitch.placeholder.json");
const WALLET_ESCROW_WITH_ARBITER_JSON: &str =
    include_str!("../fixtures/wallet-contracts/EscrowWithArbiter.placeholder.json");
const WALLET_MULTI_SIG_VAULT_JSON: &str =
    include_str!("../fixtures/wallet-contracts/MultiSigVault.placeholder.json");
const WALLET_TIME_LOCK_VAULT_JSON: &str =
    include_str!("../fixtures/wallet-contracts/TimeLockVault.placeholder.json");

// ─── Builders ─────────────────────────────────────────────────────────────

pub fn dead_mans_switch() -> KaspacomDecoder {
    build_decoder_from_hex(
        KnownTemplate::DeadManSwitch,
        KaspacomVariant::LegacyC39e4140,
        LEGACY_DEAD_MANS_SWITCH_HEX,
        true,
    )
}

pub fn dead_mans_switch_wallet_pr359() -> KaspacomDecoder {
    build_decoder_from_artifact(
        KnownTemplate::DeadManSwitch,
        KaspacomVariant::WalletPr359,
        WALLET_DEAD_MANS_SWITCH_JSON,
        false,
    )
}

pub fn escrow_with_arbiter() -> KaspacomDecoder {
    build_decoder_from_hex(
        KnownTemplate::EscrowWithArbiter,
        KaspacomVariant::LegacyC39e4140,
        LEGACY_ESCROW_WITH_ARBITER_HEX,
        true,
    )
}

pub fn escrow_with_arbiter_wallet_pr359() -> KaspacomDecoder {
    build_decoder_from_artifact(
        KnownTemplate::EscrowWithArbiter,
        KaspacomVariant::WalletPr359,
        WALLET_ESCROW_WITH_ARBITER_JSON,
        false,
    )
}

pub fn multi_sig_vault() -> KaspacomDecoder {
    build_decoder_from_hex(
        KnownTemplate::MultiSigVault,
        KaspacomVariant::LegacyC39e4140,
        LEGACY_MULTI_SIG_VAULT_HEX,
        true,
    )
}

pub fn multi_sig_vault_wallet_pr359() -> KaspacomDecoder {
    build_decoder_from_artifact(
        KnownTemplate::MultiSigVault,
        KaspacomVariant::WalletPr359,
        WALLET_MULTI_SIG_VAULT_JSON,
        false,
    )
}

pub fn time_lock_vault_dev() -> KaspacomDecoder {
    build_decoder_from_hex(
        KnownTemplate::TimeLockVault,
        KaspacomVariant::LegacyC39e4140,
        LEGACY_TIME_LOCK_VAULT_DEV_HEX,
        true,
    )
}

pub fn time_lock_vault_wallet_pr359() -> KaspacomDecoder {
    build_decoder_from_artifact(
        KnownTemplate::TimeLockVault,
        KaspacomVariant::WalletPr359,
        WALLET_TIME_LOCK_VAULT_JSON,
        false,
    )
}

fn build_decoder_from_hex(
    template: KnownTemplate,
    variant: KaspacomVariant,
    hex_str: &str,
    strict_len: bool,
) -> KaspacomDecoder {
    let bytes = hex::decode(hex_str).expect("compile-time hex literal");
    build_decoder(template, variant, bytes, strict_len)
}

fn build_decoder_from_artifact(
    template: KnownTemplate,
    variant: KaspacomVariant,
    artifact_json: &str,
    strict_len: bool,
) -> KaspacomDecoder {
    build_decoder(
        template,
        variant,
        artifact_script(artifact_json),
        strict_len,
    )
}

fn build_decoder(
    template: KnownTemplate,
    variant: KaspacomVariant,
    bytes: Vec<u8>,
    strict_len: bool,
) -> KaspacomDecoder {
    let fingerprint = template_fingerprint(&bytes);
    let canonical_len = strict_len.then_some(bytes.len());
    KaspacomDecoder {
        template,
        variant,
        fingerprint,
        canonical_len,
        _compiled: bytes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KaspacomVariant {
    LegacyC39e4140,
    WalletPr359,
}

pub struct KaspacomDecoder {
    template: KnownTemplate,
    variant: KaspacomVariant,
    fingerprint: [u8; 32],
    /// Legacy variants keep exact compiled length gating. Current wallet
    /// variants intentionally do not: constructor ints can change push width.
    canonical_len: Option<usize>,
    _compiled: Vec<u8>,
}

impl TemplateDecoder for KaspacomDecoder {
    fn template(&self) -> KnownTemplate {
        self.template
    }

    fn name(&self) -> &'static str {
        match self.template {
            KnownTemplate::DeadManSwitch => "DeadManSwitch",
            KnownTemplate::EscrowWithArbiter => "EscrowWithArbiter",
            KnownTemplate::MultiSigVault => "MultiSigVault",
            KnownTemplate::TimeLockVault => "TimeLockVault",
            _ => "Unknown",
        }
    }

    fn script_hash(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        template_fingerprint(reveal) == self.fingerprint
            && self
                .canonical_len
                .map(|canonical_len| reveal.len() == canonical_len)
                .unwrap_or(true)
    }

    fn decode_constructor(&self, _payload: &[u8]) -> Result<Value> {
        // Same v1 stance as parker.rs — push-slot extraction without an
        // AST walker is too brittle. The covenant rows still capture
        // script_hash + address + template_name; constructor JSON lands later.
        Ok(Value::Null)
    }

    fn decode_state(&self, _payload: &[u8]) -> Result<Value> {
        Ok(Value::Null)
    }

    fn decode_action(&self, signature_script: &[u8]) -> Option<String> {
        // sig_script for a P2SH covenant spend is:
        //   [K param pushes] [selector byte push] [PUSHDATA1 redeem script]
        //
        // K depends on the entrypoint's arity (see ABI per template).
        // The selector convention from SilverScript is:
        //   1st AST function -> 0x00 (OP_FALSE)
        //   2nd              -> 0x51 (OP_1)
        //   3rd              -> 0x52 (OP_2)
        //   ...
        // We peek the first byte after K pushes and map to the entrypoint.
        for k in 0..=3 {
            let Some(selector) = selector_after_args(signature_script, k) else {
                continue;
            };
            let resolved = match (self.template, self.variant, selector, k) {
                // Legacy DeadManSwitch — keepAlive(sig) / claim(sig)
                (KnownTemplate::DeadManSwitch, KaspacomVariant::LegacyC39e4140, 0x00, 1) => {
                    Some("keepAlive")
                }
                (KnownTemplate::DeadManSwitch, KaspacomVariant::LegacyC39e4140, 0x51, 1) => {
                    Some("claim")
                }

                // PR #359 DeadManSwitch:
                //   keepAlive(sig, int) / changeHeir(sig, pubkey) / topUp() / claim(sig)
                (KnownTemplate::DeadManSwitch, KaspacomVariant::WalletPr359, 0x00, 2) => {
                    Some("keepAlive")
                }
                (KnownTemplate::DeadManSwitch, KaspacomVariant::WalletPr359, 0x51, 2) => {
                    Some("changeHeir")
                }
                (KnownTemplate::DeadManSwitch, KaspacomVariant::WalletPr359, 0x52, 0) => {
                    Some("topUp")
                }
                (KnownTemplate::DeadManSwitch, KaspacomVariant::WalletPr359, 0x53, 1) => {
                    Some("claim")
                }

                // EscrowWithArbiter:
                //   release (idx 0) — buyerSig + sellerSig          (K=2, 0x00)
                //   refund  (idx 1) — single sig                    (K=1, 0x51)
                //   arbitrate (idx 2) — pubkey + sig + int          (K=3, 0x52)
                (
                    KnownTemplate::EscrowWithArbiter,
                    KaspacomVariant::LegacyC39e4140 | KaspacomVariant::WalletPr359,
                    0x00,
                    2,
                ) => Some("release"),
                (
                    KnownTemplate::EscrowWithArbiter,
                    KaspacomVariant::LegacyC39e4140 | KaspacomVariant::WalletPr359,
                    0x51,
                    1,
                ) => Some("refund"),
                (
                    KnownTemplate::EscrowWithArbiter,
                    KaspacomVariant::LegacyC39e4140 | KaspacomVariant::WalletPr359,
                    0x52,
                    3,
                ) => Some("arbitrate"),
                (KnownTemplate::EscrowWithArbiter, KaspacomVariant::WalletPr359, 0x53, 0) => {
                    Some("topUp")
                }

                // MultiSigVault — every entrypoint is 2 sigs:
                //   spend12 (idx 0) -> 0x00
                //   spend13 (idx 1) -> 0x51
                //   spend23 (idx 2) -> 0x52
                (
                    KnownTemplate::MultiSigVault,
                    KaspacomVariant::LegacyC39e4140 | KaspacomVariant::WalletPr359,
                    0x00,
                    2,
                ) => Some("spend12"),
                (
                    KnownTemplate::MultiSigVault,
                    KaspacomVariant::LegacyC39e4140 | KaspacomVariant::WalletPr359,
                    0x51,
                    2,
                ) => Some("spend13"),
                (
                    KnownTemplate::MultiSigVault,
                    KaspacomVariant::LegacyC39e4140 | KaspacomVariant::WalletPr359,
                    0x52,
                    2,
                ) => Some("spend23"),
                (KnownTemplate::MultiSigVault, KaspacomVariant::WalletPr359, 0x53, 0) => {
                    Some("topUp")
                }

                // TimeLockVault legacy/dev variant — both 1 sig:
                //   spend   (idx 0) -> 0x00
                //   recover (idx 1) -> 0x51
                (KnownTemplate::TimeLockVault, KaspacomVariant::LegacyC39e4140, 0x00, 1) => {
                    Some("spend")
                }
                (KnownTemplate::TimeLockVault, KaspacomVariant::LegacyC39e4140, 0x51, 1) => {
                    Some("recover")
                }

                // TimeLockVault wallet variant:
                //   spend          (idx 0) -> 0x00
                //   changeRecovery (idx 1) -> 0x51
                //   recover        (idx 2) -> 0x52
                //   topUp          (idx 3) -> 0x53
                (KnownTemplate::TimeLockVault, KaspacomVariant::WalletPr359, 0x00, 1) => {
                    Some("spend")
                }
                (KnownTemplate::TimeLockVault, KaspacomVariant::WalletPr359, 0x51, 2) => {
                    Some("changeRecovery")
                }
                (KnownTemplate::TimeLockVault, KaspacomVariant::WalletPr359, 0x52, 1) => {
                    Some("recover")
                }
                (KnownTemplate::TimeLockVault, KaspacomVariant::WalletPr359, 0x53, 0) => {
                    Some("topUp")
                }

                _ => None,
            };
            if let Some(name) = resolved {
                return Some(name.into());
            }
        }
        None
    }
}

fn selector_after_args(signature_script: &[u8], arg_count: usize) -> Option<u8> {
    let mut rest = signature_script;
    for _ in 0..arg_count {
        rest = skip_one_script_arg(rest)?;
    }
    rest.first().copied()
}

fn skip_one_script_arg(script: &[u8]) -> Option<&[u8]> {
    if let Some((_, rest)) = read_push(script) {
        return Some(rest);
    }
    match script.first().copied()? {
        // OP_0, OP_1NEGATE, OP_1..OP_16 can encode small int/bool args.
        0x00 | 0x4f | 0x51..=0x60 => Some(&script[1..]),
        _ => None,
    }
}

fn artifact_script(artifact_json: &str) -> Vec<u8> {
    let artifact: Value =
        serde_json::from_str(artifact_json).expect("wallet contract fixture JSON valid");
    artifact
        .get("script")
        .or_else(|| artifact.get("bytecode"))
        .and_then(Value::as_array)
        .expect("wallet contract fixture has script or bytecode array")
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .expect("wallet contract script byte")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_decoder_classifies_its_own_compiled_script() {
        for (decoder, bytes) in [
            (
                dead_mans_switch(),
                hex::decode(LEGACY_DEAD_MANS_SWITCH_HEX).unwrap(),
            ),
            (
                escrow_with_arbiter(),
                hex::decode(LEGACY_ESCROW_WITH_ARBITER_HEX).unwrap(),
            ),
            (
                multi_sig_vault(),
                hex::decode(LEGACY_MULTI_SIG_VAULT_HEX).unwrap(),
            ),
            (
                time_lock_vault_dev(),
                hex::decode(LEGACY_TIME_LOCK_VAULT_DEV_HEX).unwrap(),
            ),
            (
                dead_mans_switch_wallet_pr359(),
                artifact_script(WALLET_DEAD_MANS_SWITCH_JSON),
            ),
            (
                escrow_with_arbiter_wallet_pr359(),
                artifact_script(WALLET_ESCROW_WITH_ARBITER_JSON),
            ),
            (
                multi_sig_vault_wallet_pr359(),
                artifact_script(WALLET_MULTI_SIG_VAULT_JSON),
            ),
            (
                time_lock_vault_wallet_pr359(),
                artifact_script(WALLET_TIME_LOCK_VAULT_JSON),
            ),
        ] {
            assert!(
                decoder.matches_reveal_script(&bytes),
                "decoder {:?} failed to match its own compiled script",
                decoder.template,
            );
        }
    }

    #[test]
    fn fingerprints_are_distinct_within_kaspacom_family() {
        let all = [
            dead_mans_switch().fingerprint,
            escrow_with_arbiter().fingerprint,
            multi_sig_vault().fingerprint,
            time_lock_vault_dev().fingerprint,
            dead_mans_switch_wallet_pr359().fingerprint,
            escrow_with_arbiter_wallet_pr359().fingerprint,
            multi_sig_vault_wallet_pr359().fingerprint,
            time_lock_vault_wallet_pr359().fingerprint,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "decoders {i} and {j} share a fingerprint — add a length disambiguator"
                );
            }
        }
    }

    #[test]
    fn wallet_pr359_actions_decode_every_entrypoint() {
        let dms = dead_mans_switch_wallet_pr359();
        assert_eq!(action(&dms, &[Arg::Sig, Arg::Int], 0x00), "keepAlive");
        assert_eq!(action(&dms, &[Arg::Sig, Arg::Pubkey], 0x51), "changeHeir");
        assert_eq!(action(&dms, &[], 0x52), "topUp");
        assert_eq!(action(&dms, &[Arg::Sig], 0x53), "claim");

        let escrow = escrow_with_arbiter_wallet_pr359();
        assert_eq!(action(&escrow, &[Arg::Sig, Arg::Sig], 0x00), "release");
        assert_eq!(action(&escrow, &[Arg::Sig], 0x51), "refund");
        assert_eq!(
            action(&escrow, &[Arg::Pubkey, Arg::Sig, Arg::SmallInt], 0x52),
            "arbitrate"
        );
        assert_eq!(action(&escrow, &[], 0x53), "topUp");

        let multi = multi_sig_vault_wallet_pr359();
        assert_eq!(action(&multi, &[Arg::Sig, Arg::Sig], 0x00), "spend12");
        assert_eq!(action(&multi, &[Arg::Sig, Arg::Sig], 0x51), "spend13");
        assert_eq!(action(&multi, &[Arg::Sig, Arg::Sig], 0x52), "spend23");
        assert_eq!(action(&multi, &[], 0x53), "topUp");

        let timelock = time_lock_vault_wallet_pr359();
        assert_eq!(action(&timelock, &[Arg::Sig], 0x00), "spend");
        assert_eq!(
            action(&timelock, &[Arg::Sig, Arg::Pubkey], 0x51),
            "changeRecovery"
        );
        assert_eq!(action(&timelock, &[Arg::Sig], 0x52), "recover");
        assert_eq!(action(&timelock, &[], 0x53), "topUp");
    }

    #[test]
    fn legacy_actions_still_decode() {
        assert_eq!(action(&dead_mans_switch(), &[Arg::Sig], 0x00), "keepAlive");
        assert_eq!(action(&dead_mans_switch(), &[Arg::Sig], 0x51), "claim");
        assert_eq!(
            action(
                &escrow_with_arbiter(),
                &[Arg::Pubkey, Arg::Sig, Arg::SmallInt],
                0x52
            ),
            "arbitrate"
        );
    }

    #[derive(Clone, Copy)]
    enum Arg {
        Sig,
        Pubkey,
        Int,
        SmallInt,
    }

    fn action(decoder: &KaspacomDecoder, args: &[Arg], selector: u8) -> String {
        decoder
            .decode_action(&sigscript(args, selector))
            .expect("entrypoint decodes")
    }

    fn sigscript(args: &[Arg], selector: u8) -> Vec<u8> {
        let mut out = Vec::new();
        for arg in args {
            match arg {
                Arg::Sig => push(&mut out, &[0x11; 65]),
                Arg::Pubkey => push(&mut out, &[0x22; 32]),
                Arg::Int => push(&mut out, &[0x00, 0x10, 0xa5, 0xd4, 0xe8, 0x00]),
                Arg::SmallInt => out.push(0x51),
            }
        }
        out.push(selector);
        out
    }

    fn push(out: &mut Vec<u8>, bytes: &[u8]) {
        out.push(u8::try_from(bytes.len()).unwrap());
        out.extend_from_slice(bytes);
    }
}
