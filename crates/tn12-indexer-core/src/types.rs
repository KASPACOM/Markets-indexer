use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Outpoint {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UtxoStatus {
    Active,
    Spent,
}

impl std::fmt::Display for UtxoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtxoStatus::Active => f.write_str("active"),
            UtxoStatus::Spent => f.write_str("spent"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CovenantUtxo {
    pub covenant_id: Option<String>,
    pub address: String,
    pub outpoint: Outpoint,
    pub amount_sompi: u64,
    pub script_public_key: Option<String>,
    pub status: UtxoStatus,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum KnownTemplate {
    TimeLockVault,
    Kcc20,
    Kcc20V2,
    Kcc20V3,
    Kcc20Orderbook,
    Kcc20Wrapper,
    Kcc20FeeEscrowV1,
    Kcc20FeeRecipientV1,
    Kcc20FeeRootV1,
    Kcc20FeeHolderV1,
    Kcc20FeeAskV1,
    Kcc20FeeBidV1,
    Kcc20FeeWrapperV1,
    Kcc20FeeWrapperV2,
    Kcc20FeeWrapperArgentV1,
    Kcc20FeeWrapperArgentV2,
    Kcc20SnapshotBootstrap,
    Kcc20SnapshotController,
    Kcc20FeeTicket,
    Kcc20Vesting,
    KcomVesting,
    KcomInitialize,
    KcomFactory,
    KcomVault,
    KcomClaimShard,
    KcomSettlement,
    KcomClaimCommitment,
    KcomEntitlement,
    Kcc20Sale,
    Kcc20SaleV2,
    Kcc20BuyOrder,
    ApiPaymentChannel,
    KaspaFomoRound,
    // Parker prototype set:
    DelayedRecoveryVault,
    AssurancePledge,
    Escrow,
    EscrowExpired,
    // KASPACOM dev-branch set (`kaspacom-web-wallet:tn-12/.../covenant-templates/`):
    DeadManSwitch,
    EscrowWithArbiter,
    MultiSigVault,
}
