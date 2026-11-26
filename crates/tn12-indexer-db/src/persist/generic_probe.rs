//! A finite diagnostic write with no path to ordinary scalar persistence.
use std::{future::Future, time::Instant};

use anyhow::Result;
use serde::Serialize;
use tn12_indexer_core::RestTransaction;

use super::{GenericBatchStats, PgPersister};
use crate::persist::{GenericWriteOutcomeUnknown, PersistTransientKind, TransientPersistError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeReason {
    Completed,
    InvalidInput,
    GenericIneligible,
    /// An individual attempt rolled back; the coordinator may reduce its cap.
    BudgetExceeded,
    BudgetExhausted,
    DatabaseOrEvidenceError,
    UnknownOutcome,
    HoldLimitExceeded,
}

#[derive(Debug, Serialize)]
pub struct GenericProbeAttempt {
    pub offset: usize,
    pub count: usize,
    pub elapsed_us: u128,
    pub lock_wait_us: Option<u128>,
    pub lock_held_us: Option<u128>,
    pub hold_upper_bound_us: Option<u128>,
    pub reason: ProbeReason,
}

#[derive(Debug, Serialize)]
pub struct GenericProbeOutcome {
    pub reason: ProbeReason,
    pub confirmed_txids: Vec<String>,
    pub remaining_txids: Vec<String>,
    pub uncertain_txids: Vec<String>,
    pub attempts: Vec<GenericProbeAttempt>,
}

impl PgPersister {
    /// Persist at most 16 independent generic transactions, in the supplied order.
    /// Consumes this writer so forced probe settings cannot affect another caller.
    /// Caller must retain the fixture and reconcile any uncertain attempt before
    /// retrying. No scanner cursor or migration is touched.
    pub async fn persist_guarded_generic_probe(
        mut self,
        txs: &[RestTransaction],
    ) -> GenericProbeOutcome {
        let ids: Vec<String> = txs.iter().map(|tx| tx.transaction_id.clone()).collect();
        if txs.is_empty()
            || txs.len() > 16
            || txs
                .iter()
                .any(|tx| super::prepare(tx, &self.decoders).is_none())
            || super::independent_prefix_len(txs, &self.decoders) != txs.len()
        {
            return GenericProbeOutcome {
                reason: ProbeReason::InvalidInput,
                confirmed_txids: vec![],
                remaining_txids: ids,
                uncertain_txids: vec![],
                attempts: vec![],
            };
        }
        self.wait_for_writer_lock = true;
        coordinate(ids, |start, count| {
            self.try_persist_generic_batch_with_fence(&txs[start..start + count], true, true)
        })
        .await
    }
}

async fn coordinate<F, Fut>(ids: Vec<String>, mut write: F) -> GenericProbeOutcome
where
    F: FnMut(usize, usize) -> Fut,
    Fut: Future<Output = Result<Option<GenericBatchStats>>>,
{
    let mut result = GenericProbeOutcome {
        reason: ProbeReason::Completed,
        confirmed_txids: vec![],
        remaining_txids: ids.clone(),
        uncertain_txids: vec![],
        attempts: vec![],
    };
    let mut offset = 0;
    let mut cap = ids.len();
    let mut splits = 0;
    while offset < ids.len() {
        let count = cap.min(ids.len() - offset);
        let started = Instant::now();
        let written = write(offset, count).await;
        let elapsed_us = started.elapsed().as_micros();
        let mut attempt = GenericProbeAttempt {
            offset,
            count,
            elapsed_us,
            lock_wait_us: None,
            lock_held_us: None,
            hold_upper_bound_us: None,
            reason: ProbeReason::Completed,
        };
        match written {
            Ok(Some(stats)) => {
                attempt.lock_wait_us = Some(stats.lock_wait_us);
                attempt.lock_held_us = Some(stats.lock_held_us);
                attempt.hold_upper_bound_us = Some(stats.lock_held_us);
                result
                    .confirmed_txids
                    .extend_from_slice(&ids[offset..offset + count]);
                offset += count;
                if stats.lock_held_us > 400_000 {
                    attempt.reason = ProbeReason::HoldLimitExceeded;
                }
            }
            Ok(None) => {
                // None is returned before a transaction starts, or after an
                // acknowledged rollback. Entire-call timing is conservative.
                attempt.hold_upper_bound_us = Some(elapsed_us);
                attempt.reason = ProbeReason::GenericIneligible;
            }
            Err(error) => {
                if error.downcast_ref::<GenericWriteOutcomeUnknown>().is_some() {
                    result
                        .uncertain_txids
                        .extend_from_slice(&ids[offset..offset + count]);
                    attempt.reason = ProbeReason::UnknownOutcome;
                } else if error
                    .downcast_ref::<TransientPersistError>()
                    .is_some_and(|e| e.kind == PersistTransientKind::WriterBudgetExceeded)
                {
                    // This marker is exposed only after rollback acknowledgement.
                    attempt.hold_upper_bound_us = Some(elapsed_us);
                    attempt.reason = if elapsed_us > 400_000 {
                        ProbeReason::HoldLimitExceeded
                    } else {
                        ProbeReason::BudgetExceeded
                    };
                } else {
                    // Setup and lock-acquisition errors occur outside the
                    // acknowledged rollback branch; never invent their bound.
                    if error
                        .downcast_ref::<super::GenericRollbackAcknowledged>()
                        .is_some()
                    {
                        attempt.hold_upper_bound_us = Some(elapsed_us);
                    }
                    attempt.reason = ProbeReason::DatabaseOrEvidenceError;
                }
            }
        }
        let reason = attempt.reason;
        result.attempts.push(attempt);
        if reason == ProbeReason::BudgetExceeded && count > 1 && splits < 4 {
            cap = count / 2;
            splits += 1;
            continue;
        }
        if reason != ProbeReason::Completed {
            result.reason = if reason == ProbeReason::BudgetExceeded {
                ProbeReason::BudgetExhausted
            } else {
                reason
            };
            break;
        }
    }
    result.remaining_txids = ids[offset..].to_vec();
    result
}

#[cfg(test)]
#[path = "generic_probe_tests.rs"]
mod tests;
