//! One recovery decision for failures raised by watching and by replay.
use std::time::Duration;
use tn12_indexer_db::persist::{self, identity};

#[derive(Debug, thiserror::Error)]
#[error("recovery blocked: {0}")]
pub(crate) struct RecoveryBlocked(pub &'static str);

/// A work ceiling can become satisfiable after another writer fills dependencies.
/// Reassessment never changes the ceiling or grants authority to reconnect.
#[derive(Debug, thiserror::Error)]
#[error("recovery capacity exceeded: {dimension} observed={observed} limit={limit}")]
pub(crate) struct RecoveryCapacity {
    pub dimension: &'static str,
    pub observed: usize,
    pub limit: usize,
}

pub(crate) fn check_capacity(dimension: &'static str, observed: usize, limit: usize) -> anyhow::Result<()> {
    anyhow::ensure!(observed <= limit, RecoveryCapacity { dimension, observed, limit });
    Ok(())
}

pub(crate) fn reassessment_delay(attempt: u32) -> Duration {
    Duration::from_secs(60u64.saturating_mul(1u64 << attempt.saturating_sub(1).min(3)).min(300))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Retry(&'static str),
    Reassess(&'static str),
    Blocked(&'static str),
    Terminal(&'static str),
}
impl Decision {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Retry(r) | Self::Reassess(r) | Self::Blocked(r) | Self::Terminal(r) => r,
        }
    }
}

pub(crate) fn classify(error: &anyhow::Error) -> Decision {
    use crate::live_supervisor::{RecoveryPending, TransportCleanupFailed};
    if error.is::<TransportCleanupFailed>() {
        return Decision::Terminal("transport_cleanup_failed");
    }
    if let Some(e) = error.downcast_ref::<RecoveryCapacity>() {
        return Decision::Reassess(e.dimension);
    }
    if let Some(e) = error.downcast_ref::<RecoveryBlocked>() {
        return Decision::Blocked(e.0);
    }
    if error.is::<identity::GenesisIdentityBlocked>()
        || error.is::<persist::AcceptanceEvidenceConflict>()
    {
        return Decision::Blocked("contradictory_identity");
    }
    if error.is::<identity::MissingIdentityDependency>() {
        return Decision::Retry("missing_parent");
    }
    if error.is::<persist::StaleRestAcceptance>() {
        return Decision::Retry("canonical_evidence_changed");
    }
    if error.is::<persist::AcceptanceWindowPending>() {
        return Decision::Retry("immature_acceptance");
    }
    if error.is::<persist::AcceptanceEvidenceChanged>() {
        return Decision::Retry("canonical_evidence_changed");
    }
    if error.is::<persist::RecoveryImpactLimit>() {
        return Decision::Reassess("affected_transaction_limit");
    }
    if error.is::<persist::RecoveryReplanRequired>() {
        return Decision::Retry("recovery_footprint_changed");
    }
    if error.is::<RecoveryPending>() {
        return Decision::Retry("source_pending");
    }
    if error.is::<persist::AcceptanceConflict>() {
        return Decision::Retry("acceptance_conflict");
    }
    if error.is::<persist::GenericWriteOutcomeUnknown>()
        || error.is::<persist::HistoricalAcceptanceOutcomeUnknown>()
    {
        return Decision::Retry("unknown_commit");
    }
    if persist::is_transient_persist_error(error) {
        return Decision::Retry("database_unavailable");
    }
    let status = error
        .downcast_ref::<crate::rpc::rest::RestStatusError>()
        .map(|e| e.status)
        .or_else(|| {
            error
                .downcast_ref::<reqwest::Error>()
                .and_then(|e| e.status())
        });
    if let Some(status) = status {
        if crate::rpc::rest::retryable_status(status) {
            return Decision::Retry("source_unavailable");
        }
        return Decision::Blocked("source_request_rejected");
    }
    if error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|e| e.is_timeout() || e.is_connect())
    {
        return Decision::Retry("source_unavailable");
    }
    // Unknown invariant/ownership failures must never authorize reconnection.
    Decision::Terminal("invariant_or_ownership_failure")
}

pub(crate) fn delay(base: Duration, attempt: u32, entropy: u64) -> Duration {
    let millis = base
        .as_millis()
        .saturating_mul(1u128 << attempt.saturating_sub(1).min(4))
        .min(30_000);
    // Bounded jitter, capped at thirty seconds even at the maximum backoff.
    Duration::from_millis((millis * (80 + entropy % 41) as u128 / 100).min(30_000) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_errors_preserve_retry_block_and_terminal_boundaries() {
        assert_eq!(classify(&persist::RecoveryReplanRequired("changed descendant").into()),
            Decision::Retry("recovery_footprint_changed"));
        assert_eq!(classify(&persist::RecoveryImpactLimit.into()),
            Decision::Reassess("affected_transaction_limit"));

        let missing = anyhow::Error::new(identity::MissingIdentityDependency {
            txid: "11".repeat(32),
            vout: 1,
        })
        .context("live writer stopped");
        assert_eq!(classify(&missing), Decision::Retry("missing_parent"));
        assert_eq!(
            classify(
                &persist::AcceptanceWindowPending {
                    source_tip: 100,
                    required_tip: 1100
                }
                .into()
            ),
            Decision::Retry("immature_acceptance")
        );
        assert_eq!(
            classify(&RecoveryBlocked("dependency_limit").into()),
            Decision::Blocked("dependency_limit")
        );
        assert_eq!(
            classify(&crate::live_supervisor::TransportCleanupFailed.into()),
            Decision::Terminal("transport_cleanup_failed")
        );
        assert!(matches!(
            classify(&anyhow::anyhow!("durable consumer generation is stale")),
            Decision::Terminal(_)
        ));
    }
    #[test]
    fn exponential_retry_is_bounded() {
        for (n, expected) in [
            (1, 2000),
            (2, 4000),
            (3, 8000),
            (4, 16000),
            (5, 30000),
            (100, 30000),
        ] {
            assert_eq!(delay(Duration::from_secs(2), n, 20).as_millis(), expected);
            assert!(delay(Duration::from_secs(2), n, u64::MAX) <= Duration::from_secs(30));
        }
        assert_eq!(delay(Duration::ZERO, 1, 0), Duration::ZERO);
    }
}
