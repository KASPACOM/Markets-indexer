use super::*;

fn ids() -> Vec<String> {
    (0..16).map(|i| format!("{i:064x}")).collect()
}

fn committed() -> Result<Option<GenericBatchStats>> {
    Ok(Some(GenericBatchStats {
        stats: crate::persist::PersistStats::default(),
        lock_wait_us: 10,
        lock_held_us: 20,
    }))
}

#[tokio::test]
async fn probe_error_bound_requires_rollback_acknowledgement() {
    for acknowledged in [false, true] {
        let result = coordinate(ids(), |_, _| {
            let error = anyhow::anyhow!("injected setup or write failure");
            std::future::ready(Err(if acknowledged {
                error.context(super::super::GenericRollbackAcknowledged)
            } else {
                error
            }))
        })
        .await;
        assert_eq!(result.reason, ProbeReason::DatabaseOrEvidenceError);
        assert_eq!(result.attempts.len(), 1);
        assert_eq!(
            result.attempts[0].hold_upper_bound_us.is_some(),
            acknowledged
        );
        assert!(result.confirmed_txids.is_empty());
    }
}

#[tokio::test]
async fn probe_initial_ineligibility_stops_without_scalar_path() {
    let result = coordinate(ids(), |_, _| std::future::ready(Ok(None))).await;
    assert_eq!(result.reason, ProbeReason::GenericIneligible);
    assert!(result.confirmed_txids.is_empty());
    assert_eq!(result.remaining_txids, ids());
    assert_eq!(result.attempts.len(), 1);
}

#[tokio::test]
async fn probe_split_then_ineligible_preserves_all_input() {
    let result = coordinate(ids(), |_, count| {
        std::future::ready(if count == 16 {
            Err(crate::persist::TransientPersistError::writer_budget_exceeded().into())
        } else {
            Ok(None)
        })
    })
    .await;
    assert_eq!(result.reason, ProbeReason::GenericIneligible);
    assert!(result.confirmed_txids.is_empty());
    assert_eq!(result.remaining_txids, ids());
    assert_eq!(
        result.attempts.iter().map(|a| a.count).collect::<Vec<_>>(),
        vec![16, 8]
    );
}

#[tokio::test]
async fn probe_partial_prefix_and_unknown_attempt_are_distinct() {
    let result = coordinate(ids(), |start, count| {
        std::future::ready(if count == 16 {
            Err(crate::persist::TransientPersistError::writer_budget_exceeded().into())
        } else if start == 0 {
            committed()
        } else {
            Err(crate::persist::GenericWriteOutcomeUnknown {
                phase: "commit",
                detail: "injected".into(),
            }
            .into())
        })
    })
    .await;
    assert_eq!(result.reason, ProbeReason::UnknownOutcome);
    assert_eq!(result.confirmed_txids, ids()[..8]);
    assert_eq!(result.remaining_txids, ids()[8..]);
    assert_eq!(result.uncertain_txids, ids()[8..]);
    assert_eq!(result.attempts.len(), 3);
    assert!(result.attempts[2].hold_upper_bound_us.is_none());
}

#[tokio::test]
async fn probe_minimum_failure_terminates() {
    let result = coordinate(ids(), |_, _| {
        std::future::ready(Err(
            crate::persist::TransientPersistError::writer_budget_exceeded().into(),
        ))
    })
    .await;
    assert_eq!(result.reason, ProbeReason::BudgetExhausted);
    assert_eq!(
        result.attempts.iter().map(|a| a.count).collect::<Vec<_>>(),
        vec![16, 8, 4, 2, 1]
    );
    assert!(result.confirmed_txids.is_empty());
}

#[tokio::test]
async fn probe_successful_split_keeps_order_and_cap() {
    let result = coordinate(ids(), |_, count| {
        std::future::ready(if count == 16 {
            Err(crate::persist::TransientPersistError::writer_budget_exceeded().into())
        } else {
            committed()
        })
    })
    .await;
    assert_eq!(result.reason, ProbeReason::Completed);
    assert_eq!(result.confirmed_txids, ids());
    assert!(result.remaining_txids.is_empty());
    assert_eq!(
        result.attempts.iter().map(|a| a.count).collect::<Vec<_>>(),
        vec![16, 8, 8]
    );
}

#[tokio::test]
async fn probe_hold_limit_stops_after_confirmed_commit() {
    let result = coordinate(ids(), |_, _| {
        std::future::ready(Ok(Some(GenericBatchStats {
            stats: crate::persist::PersistStats::default(),
            lock_wait_us: 0,
            lock_held_us: 400001,
        })))
    })
    .await;
    assert_eq!(result.reason, ProbeReason::HoldLimitExceeded);
    assert_eq!(result.confirmed_txids, ids());
    assert!(result.uncertain_txids.is_empty());
    assert_eq!(result.attempts.len(), 1);
}
