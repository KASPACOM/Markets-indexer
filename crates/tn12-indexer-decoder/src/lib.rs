//! Template-aware decoders for covenant state + entrypoints.
//!
//! Phase 3 fills in `TimeLockVaultDecoder`; Phase 4 fills in `Kcc20Decoder`.
//! Both implement the `TemplateDecoder` trait so the crawler can resolve
//! `script_hash -> Box<dyn TemplateDecoder>` at runtime.

use anyhow::Result;
use serde_json::Value;
use tn12_indexer_core::KnownTemplate;

/// An application payload could not be interpreted. Only parsing/unsupported
/// semantics may carry this marker; authentication and canonical checks must not.
#[derive(Debug)]
pub struct InterpretationFailure(pub &'static str);
impl std::fmt::Display for InterpretationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "application interpretation failed at {}", self.0)
    }
}
impl std::error::Error for InterpretationFailure {}

/// Authentication or protocol commitments disagree. Never defer as parsing.
#[derive(Debug)]
pub struct IntegrityFailure(pub &'static str);
impl std::fmt::Display for IntegrityFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f,"integrity failure at {}",self.0) }
}
impl std::error::Error for IntegrityFailure {}

/// Apply only to pure application parsing, never SQL or source authentication.
pub fn interpretation<T>(stage: &'static str, result: Result<T>) -> Result<T> {
    result.map_err(|error| {
        if error.downcast_ref::<IntegrityFailure>().is_some() { error }
        else { error.context(InterpretationFailure(stage)) }
    })
}

/// Stable fingerprint for retrying retained work after a decoder deployment.
pub fn revision() -> &'static str {
    static REVISION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    REVISION.get_or_init(|| {
        let mut hash = blake3::Hasher::new();
        hash.update(include_bytes!("lib.rs"));
        hash.update(include_bytes!("api_payment_channel.rs"));
        hash.update(include_bytes!("inscriptions.rs"));
        hash.update(include_bytes!("kaspa_fomo_round.rs"));
        hash.update(include_bytes!("kaspacom.rs"));
        hash.update(include_bytes!("kcc20.rs"));
        hash.update(include_bytes!("kcc20_fee_contracts.rs"));
        hash.update(include_bytes!("kcc20_fee_ticket.rs"));
        hash.update(include_bytes!("kcc20_fee_v1.rs"));
        hash.update(include_bytes!("kcc20_orderbook.rs"));
        hash.update(include_bytes!("kcc20_sale.rs"));
        hash.update(include_bytes!("kcc20_snapshot_bootstrap.rs"));
        hash.update(include_bytes!("kcc20_snapshot_controller.rs"));
        hash.update(include_bytes!("kcc20_standard.rs"));
        hash.update(include_bytes!("kcc20_v2.rs"));
        hash.update(include_bytes!("kcc20_v3.rs"));
        hash.update(include_bytes!("kcc20_vesting.rs"));
        hash.update(include_bytes!("kcc20_wrapper.rs"));
        hash.update(include_bytes!("kcom_claim.rs"));
        hash.update(include_bytes!("kcom_profile.rs"));
        hash.update(include_bytes!("kcom_vesting.rs"));
        hash.update(include_bytes!("parker.rs"));
        hash.update(include_bytes!("timelock.rs"));
        hash.update(include_bytes!("token_profiles.rs"));
        hash.finalize().to_hex().to_string()
    }).as_str()
}

pub mod api_payment_channel;
pub mod inscriptions;
pub mod kaspa_fomo_round;
pub mod kaspacom;
pub mod kcc20;
pub mod kcc20_fee_contracts;
pub mod kcc20_fee_ticket;
pub mod kcc20_fee_v1;
pub mod kcc20_orderbook;
pub mod kcc20_sale;
pub mod kcc20_snapshot_bootstrap;
pub mod kcc20_snapshot_controller;
pub mod kcc20_standard;
pub mod kcc20_v2;
pub mod kcc20_v3;
pub mod kcc20_vesting;
pub mod kcc20_wrapper;
pub mod kcom_claim;
mod kcom_profile;
pub mod kcom_vesting;
pub mod parker;
pub mod timelock;
pub mod token_profiles;

pub use api_payment_channel::ApiPaymentChannelDecoder;
pub use inscriptions::{detect_inscription_from_reveal, Inscription, InscriptionProtocol};
pub use kaspa_fomo_round::KaspaFomoRoundDecoder;
pub use kaspacom::KaspacomDecoder;
pub use kcc20::Kcc20Decoder;
pub use kcc20_fee_ticket::Kcc20FeeTicketDecoder;
pub use kcc20_orderbook::Kcc20OrderbookDecoder;
pub use kcc20_sale::Kcc20SaleDecoder;
pub use kcc20_snapshot_bootstrap::Kcc20SnapshotBootstrapDecoder;
pub use kcc20_snapshot_controller::Kcc20SnapshotControllerDecoder;
pub use kcc20_standard::Kcc20StandardDecoder;
pub use kcc20_v2::Kcc20V2Decoder;
pub use kcc20_v3::Kcc20V3Decoder;
pub use kcc20_vesting::Kcc20VestingDecoder;
pub use kcc20_wrapper::Kcc20WrapperDecoder;
pub use parker::ParkerDecoder;
pub use timelock::TimeLockVaultDecoder;

pub fn template_name(t: KnownTemplate) -> &'static str {
    match t {
        KnownTemplate::TimeLockVault => "TimeLockVault",
        KnownTemplate::Kcc20 => "KCC20",
        KnownTemplate::Kcc20V2 => "KCC20V2",
        KnownTemplate::Kcc20V3 => "KCC20V3",
        KnownTemplate::Kcc20Orderbook => "KCC20Orderbook",
        KnownTemplate::Kcc20Wrapper => "KCC20Wrapper",
        KnownTemplate::Kcc20FeeEscrowV1 => "KCC20FeeEscrowV1",
        KnownTemplate::Kcc20FeeRecipientV1 => "KCC20FeeRecipientV1",
        KnownTemplate::Kcc20FeeRootV1 => "KCC20OrderbookFeeRootV1",
        KnownTemplate::Kcc20FeeHolderV1 => "KCC20OrderbookFeeHolderV1",
        KnownTemplate::Kcc20FeeAskV1 => "KCC20OrderbookFeeAskV1",
        KnownTemplate::Kcc20FeeBidV1 => "KCC20OrderbookFeeBidV1",
        KnownTemplate::Kcc20FeeWrapperV1 => "KCC20WrapperFeeV1",
        KnownTemplate::Kcc20FeeWrapperV2 => "KCC20WrapperFeeV2",
        KnownTemplate::Kcc20FeeWrapperArgentV1 => "KCC20WrapperFeeArgentV1",
        KnownTemplate::Kcc20FeeWrapperArgentV2 => "KCC20WrapperFeeArgentV2",
        KnownTemplate::Kcc20SnapshotBootstrap => "KCC20SnapshotBootstrap",
        KnownTemplate::Kcc20SnapshotController => "KCC20SnapshotController",
        KnownTemplate::Kcc20FeeTicket => "KCC20FeeTicket",
        KnownTemplate::Kcc20Vesting => "KCC20Vesting",
        KnownTemplate::KcomVesting => "KCOMVesting",
        KnownTemplate::KcomInitialize => "KCOMInitialize",
        KnownTemplate::KcomFactory => "KCOMFactory",
        KnownTemplate::KcomVault => "KCOMVault",
        KnownTemplate::KcomClaimShard => "KCOMClaimShard",
        KnownTemplate::KcomSettlement => "KCOMSettlement",
        KnownTemplate::KcomClaimCommitment => "KCOMClaimCommitment",
        KnownTemplate::KcomEntitlement => "KCOMEntitlement",
        KnownTemplate::Kcc20Sale => "KCC20Sale",
        KnownTemplate::Kcc20SaleV2 => "KCC20SaleV2",
        KnownTemplate::Kcc20BuyOrder => "KCC20BuyOrder",
        KnownTemplate::ApiPaymentChannel => "ApiPaymentChannel",
        KnownTemplate::KaspaFomoRound => "KaspaFomoRound",
        KnownTemplate::DelayedRecoveryVault => "DelayedRecoveryVault",
        KnownTemplate::AssurancePledge => "AssurancePledge",
        KnownTemplate::Escrow => "Escrow",
        KnownTemplate::EscrowExpired => "EscrowExpired",
        KnownTemplate::DeadManSwitch => "DeadManSwitch",
        KnownTemplate::EscrowWithArbiter => "EscrowWithArbiter",
        KnownTemplate::MultiSigVault => "MultiSigVault",
    }
}

pub trait TemplateDecoder: Send + Sync {
    fn template(&self) -> KnownTemplate;
    fn name(&self) -> &'static str {
        template_name(self.template())
    }
    fn script_hash(&self) -> [u8; 32];
    /// Returns `true` iff the reveal script (from a P2SH spend) is an instance
    /// of this template. Implementations typically mask out the constructor
    /// byte ranges, hash the result, and compare to a known fingerprint.
    fn matches_reveal_script(&self, reveal: &[u8]) -> bool;
    /// Recognized executable with an unsupported committed contract family.
    /// This is not an authentication failure and must never assert decoded state.
    fn unsupported_reveal_reason(&self, _reveal: &[u8]) -> Option<&'static str> {
        None
    }
    fn decode_constructor(&self, payload: &[u8]) -> Result<Value>;
    fn decode_state(&self, payload: &[u8]) -> Result<Value>;
    fn decode_action(&self, signature_script: &[u8]) -> Option<String>;
    /// Optional actions remain valid by default. Decoders with exhaustive spend
    /// dispatch override this to retain unknown actions as pending interpretation.
    fn decode_action_checked(&self, signature_script: &[u8]) -> Result<Option<String>> {
        Ok(self.decode_action(signature_script))
    }

}

pub mod registry {
    use super::TemplateDecoder;
    use std::sync::Arc;

    /// Holds registered template decoders. Lookup is linear (we expect very
    /// few templates in v1: TimeLockVault, KCC20, eventually MultiSig + Escrow).
    #[derive(Default, Clone)]
    pub struct DecoderRegistry {
        decoders: Vec<Arc<dyn TemplateDecoder>>,
    }

    impl DecoderRegistry {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn register(&mut self, decoder: Arc<dyn TemplateDecoder>) {
            self.decoders.push(decoder);
        }

        pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn TemplateDecoder>> {
            self.decoders.iter()
        }

        pub fn find_for_reveal(&self, reveal: &[u8]) -> Option<&Arc<dyn TemplateDecoder>> {
            self.decoders
                .iter()
                .find(|d| d.matches_reveal_script(reveal))
        }
    }
}

/// Build the default decoder set used by the CLI / API.
/// Registers every template we recognise on TN12 today:
///   * TimeLockVault — wallet PR #173 placeholder fingerprint.
///   * Parker prototype: DelayedRecoveryVault / AssurancePledge / Escrow /
///     EscrowExpired (from the historical Parker prototype).
///   * KASPACOM dev branch: DeadManSwitch / EscrowWithArbiter /
///     MultiSigVault / TimeLockVault-dev (from
///     `kaspacom-web-wallet:tn-12/src/assets/covenant-templates/`).
pub fn default_registry() -> registry::DecoderRegistry {
    use std::sync::Arc;
    let mut reg = registry::DecoderRegistry::new();
    for decoder in kcc20_fee_v1::bundled_decoders() {
        reg.register(Arc::new(decoder));
    }
    let fingerprint = timelock::TimeLockVaultDecoder::fingerprint_of_compiled_script(
        &timelock_compiled_placeholder(),
    );
    reg.register(Arc::new(timelock::TimeLockVaultDecoder::new(fingerprint)));
    reg.register(Arc::new(parker::delayed_recovery_vault()));
    reg.register(Arc::new(parker::assurance_pledge()));
    reg.register(Arc::new(parker::escrow()));
    reg.register(Arc::new(parker::escrow_expired()));
    reg.register(Arc::new(kaspacom::dead_mans_switch()));
    reg.register(Arc::new(kaspacom::escrow_with_arbiter()));
    reg.register(Arc::new(kaspacom::multi_sig_vault()));
    reg.register(Arc::new(kaspacom::time_lock_vault_dev()));
    reg.register(Arc::new(kaspacom::dead_mans_switch_wallet_pr359()));
    reg.register(Arc::new(kaspacom::escrow_with_arbiter_wallet_pr359()));
    reg.register(Arc::new(kaspacom::multi_sig_vault_wallet_pr359()));
    reg.register(Arc::new(kaspacom::time_lock_vault_wallet_pr359()));
    let kcc20_script = kcc20_compiled_placeholder();
    reg.register(Arc::new(kcc20_standard::Kcc20StandardDecoder::new(
        kcc20_standard::Kcc20StandardDecoder::template_hash_of_compiled_script(&kcc20_script)
            .expect("KCC20 placeholder has canonical state layout"),
    )));
    for profile in token_profiles::bundled_profiles()
        .iter()
        .filter(|p| !p.native_extensions)
    {
        reg.register(Arc::new(
            kcc20_standard::Kcc20StandardDecoder::from_profile(profile.clone())
                .expect("validated KCC20 profile"),
        ));
    }
    reg.register(Arc::new(kcc20_orderbook::Kcc20OrderbookDecoder::new(
        kcc20_orderbook::Kcc20OrderbookDecoder::fingerprint_of_compiled_script(
            &kcc20_orderbook_compiled_placeholder(),
        ),
    )));
    reg.register(Arc::new(kcc20_wrapper::Kcc20WrapperDecoder::new(
        kcc20_wrapper::Kcc20WrapperDecoder::fingerprint_of_compiled_script(
            &kcc20_wrapper_compiled_placeholder(),
        ),
    )));
    for profile in token_profiles::bundled_profiles()
        .iter()
        .filter(|p| !p.native_extensions)
    {
        if let Some(wrapper) = &profile.wrapper {
            let fingerprint: [u8; 32] = hex::decode(&wrapper.fingerprint)
                .expect("validated wrapper fingerprint")
                .try_into()
                .expect("32-byte fingerprint");
            reg.register(Arc::new(Kcc20WrapperDecoder::with_script_len(
                fingerprint,
                wrapper.script_length,
            )));
        }
    }
    let snapshot_bootstrap_script = kcc20_snapshot_bootstrap_compiled_placeholder();
    reg.register(Arc::new(
        kcc20_snapshot_bootstrap::Kcc20SnapshotBootstrapDecoder::new(
            kcc20_snapshot_bootstrap::Kcc20SnapshotBootstrapDecoder::template_hash_of_compiled_script(
                &snapshot_bootstrap_script,
            )
            .expect("snapshot bootstrap placeholder has canonical state layout"),
        ),
    ));
    reg.register(Arc::new(
        kcc20_snapshot_bootstrap::Kcc20SnapshotBootstrapDecoder::new(
            kcc20_snapshot_bootstrap::LEGACY_SNAPSHOT_BOOTSTRAP_TEMPLATE_HASH,
        ),
    ));
    let snapshot_controller_script = kcc20_snapshot_controller_compiled_placeholder();
    reg.register(Arc::new(
        kcc20_snapshot_controller::Kcc20SnapshotControllerDecoder::new(
            kcc20_snapshot_controller::Kcc20SnapshotControllerDecoder::template_hash_of_compiled_script(
                &snapshot_controller_script,
            )
            .expect("snapshot controller placeholder has canonical state layout"),
        ),
    ));
    reg.register(Arc::new(
        kcc20_snapshot_controller::Kcc20SnapshotControllerDecoder::new(
            kcc20_snapshot_controller::LEGACY_SNAPSHOT_CONTROLLER_TEMPLATE_HASH,
        ),
    ));
    reg.register(Arc::new(
        kcc20_snapshot_controller::Kcc20SnapshotControllerDecoder::new(
            kcc20_snapshot_controller::PRE_COMPACT_START_SNAPSHOT_CONTROLLER_TEMPLATE_HASH,
        ),
    ));
    reg.register(Arc::new(kcc20_fee_ticket::Kcc20FeeTicketDecoder::new(
        kcc20_fee_ticket::Kcc20FeeTicketDecoder::fingerprint_of_compiled_script(
            &kcc20_fee_ticket_compiled_placeholder(),
        ),
    )));
    reg.register(Arc::new(kcom_vesting::KcomVestingDecoder));
    for template in [
        KnownTemplate::KcomInitialize,
        KnownTemplate::KcomFactory,
        KnownTemplate::KcomVault,
        KnownTemplate::KcomClaimShard,
        KnownTemplate::KcomSettlement,
        KnownTemplate::KcomClaimCommitment,
        KnownTemplate::KcomEntitlement,
    ] {
        reg.register(Arc::new(kcom_claim::KcomClaimDecoder::new(template)));
    }
    reg.register(Arc::new(kcc20_vesting::Kcc20VestingDecoder::new(
        kcc20_vesting::Kcc20VestingDecoder::fingerprint_of_compiled_script(
            &kcc20_vesting_compiled_placeholder(),
        ),
    )));
    reg.register(Arc::new(
        api_payment_channel::ApiPaymentChannelDecoder::new(
            api_payment_channel::ApiPaymentChannelDecoder::fingerprint_of_compiled_script(
                &api_payment_channel_compiled_placeholder(),
            ),
        ),
    ));
    reg.register(Arc::new(kaspa_fomo_round::KaspaFomoRoundDecoder::new(
        kaspa_fomo_round::KaspaFomoRoundDecoder::fingerprint_of_compiled_script(
            &kaspa_fomo_round_compiled_placeholder(),
        ),
    )));
    reg
}

/// The 103-byte compiled TimeLockVault placeholder script. Source:
/// `kaspacom-web-wallet:tn-12/src/assets/covenant-templates/time-lock-vault.json`
/// `script` field, byte-for-byte.
fn timelock_compiled_placeholder() -> Vec<u8> {
    hex::decode(
        "76009c6375007920\
aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9\
ac6975516776519c63750079\
20\
bbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c\
ac6906\
0010a5d4e800\
b07551677500696868",
    )
    .expect("compile-time hex literal valid")
}

fn kcc20_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!("../fixtures/kcc20/KCC20.placeholder.json"))
}

fn api_payment_channel_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/api-payment-channel/ApiPaymentChannel.placeholder.json"
    ))
}

fn kcc20_orderbook_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kcc20-orderbook/KCC20Orderbook.placeholder.json"
    ))
}

fn kcc20_wrapper_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kcc20-wrapper/KCC20Wrapper.placeholder.json"
    ))
}

fn kcc20_snapshot_controller_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kcc20-snapshot-controller/KCC20SnapshotController.placeholder.json"
    ))
}

fn kcc20_snapshot_bootstrap_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kcc20-snapshot-bootstrap/KCC20SnapshotBootstrap.placeholder.json"
    ))
}

fn kcc20_fee_ticket_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kcc20-fee-ticket/KCC20FeeTicket.placeholder.json"
    ))
}

fn kcc20_vesting_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kcc20-vesting/KCC20Vesting.placeholder.json"
    ))
}

fn kaspa_fomo_round_compiled_placeholder() -> Vec<u8> {
    artifact_script_bytes(include_str!(
        "../fixtures/kaspa-fomo-round/KaspaFomoRound.placeholder.json"
    ))
}

fn artifact_script_bytes(raw: &str) -> Vec<u8> {
    let artifact: Value = serde_json::from_str(raw).expect("placeholder artifact JSON valid");
    artifact
        .get("bytecode")
        .or_else(|| artifact.get("script"))
        .expect("placeholder artifact has bytecode")
        .as_array()
        .expect("placeholder artifact bytecode is an array")
        .iter()
        .map(|v| {
            v.as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .expect("script byte")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_matches_current_kcc20_and_auxiliary_templates() {
        let reg = default_registry();
        for script in [
            kcc20_compiled_placeholder(),
            kcc20_orderbook_compiled_placeholder(),
            kcc20_wrapper_compiled_placeholder(),
            kcc20_snapshot_bootstrap_compiled_placeholder(),
            kcc20_fee_ticket_compiled_placeholder(),
            kcc20_vesting_compiled_placeholder(),
            kaspa_fomo_round_compiled_placeholder(),
        ] {
            assert!(reg.find_for_reveal(&script).is_some());
        }
    }

    #[test]
    fn default_registry_rejects_retired_kcc20_artifacts() {
        let reg = default_registry();
        for raw in [
            include_str!("../fixtures/kcc20-v2/KCC20V2.placeholder.json"),
            include_str!("../fixtures/kcc20-v2/KCC20V2.pre-public-mint-control.placeholder.json"),
            include_str!("../fixtures/kcc20-v3/KCC20V3.placeholder.json"),
            include_str!("../fixtures/kcc20-sale/KCC20Sale.placeholder.json"),
            include_str!("../fixtures/kcc20-sale-v2/KCC20SaleV2.placeholder.json"),
            include_str!("../fixtures/kcc20-buy-order/KCC20BuyOrder.placeholder.json"),
        ] {
            assert!(reg.find_for_reveal(&artifact_script_bytes(raw)).is_none());
        }
    }

    #[test]
    fn kcc20_template_hash_matches_kcc1_framed_blake3() {
        let script = kcc20_compiled_placeholder();
        let expected =
            kcc20_standard::Kcc20StandardDecoder::template_hash_of_compiled_script(&script)
                .expect("KCC20 template hash");
        assert_eq!(
            hex::encode(expected),
            "5d6cacdf57c734536fcb8a9c833f0318671226727ec77c503a98fc5be59f9e29"
        );
    }

    #[test]
    fn active_kcc20_fixtures_are_pinned_to_silverscript_v1() {
        let expected_commit = "3ed973335b59269293564805cc2c58a14595ec03";
        let expected_tree = "2a30f522768d9b4cae6fe30014326c689a25bd41";
        let expected_asset = "silverc-linux-x86_64.tar.gz";
        let expected_asset_sha256 =
            "058ffa17a390526f27280752f864b1bd680217cded14dfc5b7fd168d7e943fb5";

        for raw in [
            include_str!("../fixtures/kcc20/KCC20.placeholder.json"),
            include_str!("../fixtures/kcc20-orderbook/KCC20Orderbook.placeholder.json"),
            include_str!("../fixtures/kcc20-wrapper/KCC20Wrapper.placeholder.json"),
            include_str!("../fixtures/kcc20-fee-ticket/KCC20FeeTicket.placeholder.json"),
            include_str!("../fixtures/kcc20-vesting/KCC20Vesting.placeholder.json"),
        ] {
            let artifact: Value = serde_json::from_str(raw).expect("artifact JSON");
            let generation = artifact
                .get("generation")
                .expect("artifact generation metadata");
            assert_eq!(generation["silverscript_tag"], "v1.0.0");
            assert_eq!(generation["silverscript_commit"], expected_commit);
            assert_eq!(generation["silverscript_tree"], expected_tree);
            assert_eq!(generation["silverscript_abi_schema"], 1);
            match generation["compiler_build"].as_str() {
                Some("verified-source") => {
                    assert!(generation.get("silverscript_release_asset").is_none())
                }
                Some("verified-release") => {
                    assert_eq!(generation["silverscript_release_asset"], expected_asset);
                    assert_eq!(
                        generation["silverscript_release_asset_sha256"],
                        expected_asset_sha256
                    );
                }
                _ => panic!("artifact compiler provenance is missing"),
            }
        }
    }
}
