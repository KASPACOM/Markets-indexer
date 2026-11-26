//! Own the transition between live notifications and canonical journal recovery.
//! The transport must be stopped before returning from `watch`.
use anyhow::Result;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[error("canonical recovery pending: {0}")]
pub struct RecoveryPending(pub &'static str);

#[derive(Debug, thiserror::Error)]
#[error("transport teardown was not confirmed; refusing in-process reconnect")]
pub(crate) struct TransportCleanupFailed;

#[cfg(test)]
pub(crate) fn retry_recovery(error: &anyhow::Error) -> bool {
    matches!(
        crate::recovery_policy::classify(error),
        crate::recovery_policy::Decision::Retry(_) | crate::recovery_policy::Decision::Reassess(_)
    )
}

pub(crate) async fn stop_transport<A, B>(shutdown: A, stop: B, limit: Duration) -> Result<()>
where
    A: std::future::Future<Output = Result<()>>,
    B: std::future::Future<Output = Result<()>>,
{
    let shutdown_ok = matches!(tokio::time::timeout(limit, shutdown).await, Ok(Ok(())));
    // Always attempt notifier/control shutdown, even when socket shutdown fails.
    let stop_ok = matches!(tokio::time::timeout(limit, stop).await, Ok(Ok(())));
    if !shutdown_ok || !stop_ok {
        return Err(TransportCleanupFailed.into());
    }
    Ok(())
}

#[async_trait::async_trait(?Send)]
pub trait LiveRuntime: Send + Sync {
    async fn pending(&self) -> Result<bool>;
    async fn recover(&self) -> Result<()>;
    async fn ensure_watch_safe(&self) -> Result<()> {
        Ok(())
    }
    async fn watch(&self) -> Result<()>;
    async fn state(&self, phase: &str, error: Option<&str>) -> Result<()>;
    async fn observe(&self, observation: crate::recovery_state::Observation<'_>) -> Result<()> {
        self.state(observation.phase, observation.error).await
    }
}

pub async fn supervise(runtime: &impl LiveRuntime, retry: Duration) -> Result<()> {
    use crate::recovery_policy::{classify, delay, Decision};
    use crate::recovery_state::Observation;
    let mut failures = 0u32;
    loop {
        while runtime.pending().await? {
            runtime
                .observe(Observation::new("recovering", "attempt"))
                .await?;
            match runtime.recover().await {
                Ok(()) => {
                    failures = 0;
                    runtime
                        .observe(Observation::new("recovering", "completed"))
                        .await?;
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    let decision = classify(&error);
                    let message = format!("{error:#}");
                    match decision {
                        Decision::Retry(reason) => {
                            let now = chrono::Utc::now().timestamp_millis();
                            let wait = delay(retry, failures, now as u64);
                            runtime
                                .observe(Observation {
                                    phase: "recovering",
                                    outcome: "retry",
                                    reason: Some(reason),
                                    error: Some(&message),
                                    next_retry_at_ms: Some(
                                        now.saturating_add(wait.as_millis() as i64),
                                    ),
                                })
                                .await?;
                            tokio::time::sleep(wait).await;
                        }
                        Decision::Reassess(reason) => {
                            let wait = crate::recovery_policy::reassessment_delay(failures);
                            runtime.observe(Observation {
                                phase: "blocked",
                                outcome: "blocked",
                                reason: Some(reason),
                                error: Some(&message),
                                next_retry_at_ms: Some(chrono::Utc::now().timestamp_millis()
                                    .saturating_add(wait.as_millis() as i64)),
                            }).await?;
                            tokio::time::sleep(wait).await;
                            // A vanished intent is not proof of completed replay.
                            // Only recover() may verify it and authorize watching.
                            if !runtime.pending().await? {
                                return Err(error);
                            }
                        }
                        Decision::Blocked(reason) => {
                            runtime
                                .observe(Observation {
                                    phase: "blocked",
                                    outcome: "blocked",
                                    reason: Some(reason),
                                    error: Some(&message),
                                    next_retry_at_ms: None,
                                })
                                .await?;
                            // An operator may resolve the retained intent. Never
                            // enlarge limits or reconnect while it still exists.
                            while runtime.pending().await? {
                                tokio::time::sleep(Duration::from_secs(30)).await;
                            }
                            return Err(error);
                        }
                        Decision::Terminal(reason) => {
                            runtime
                                .observe(Observation {
                                    phase: "stopped",
                                    outcome: "terminal",
                                    reason: Some(reason),
                                    error: Some(&message),
                                    next_retry_at_ms: None,
                                })
                                .await?;
                            return Err(error);
                        }
                    }
                }
            }
        }
        if let Err(error) = runtime.ensure_watch_safe().await {
            if let Some(blocked) = error.downcast_ref::<crate::recovery_policy::RecoveryBlocked>() {
                let message = format!("{error:#}");
                runtime
                    .observe(Observation {
                        phase: "blocked",
                        outcome: "blocked",
                        reason: Some(blocked.0),
                        error: Some(&message),
                        next_retry_at_ms: None,
                    })
                    .await?;
            }
            return Err(error);
        }
        runtime
            .observe(Observation::new("watching", "watching"))
            .await?;
        match runtime.watch().await {
            Ok(()) => return Ok(()),
            Err(error) => {
                let decision = classify(&error);
                let message = format!("{error:#}");
                // A stopped transport and retained intent are mandatory before
                // either retrying or waiting for operator intervention.
                if matches!(decision, Decision::Terminal(_)) || !runtime.pending().await? {
                    runtime
                        .observe(Observation {
                            phase: "stopped",
                            outcome: "terminal",
                            reason: Some(decision.reason()),
                            error: Some(&message),
                            next_retry_at_ms: None,
                        })
                        .await?;
                    return Err(error);
                }
                let blocked = matches!(decision, Decision::Blocked(_));
                runtime
                    .observe(Observation {
                        phase: if blocked { "blocked" } else { "recovering" },
                        outcome: if blocked { "blocked" } else { "handoff" },
                        reason: Some(decision.reason()),
                        error: Some(&message),
                        next_retry_at_ms: None,
                    })
                    .await?;
                if blocked {
                    while runtime.pending().await? {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                    return Err(error);
                }
            }
        }
    }
}

/// Adapter for the deployed journal path, retained during durable-intake rollout.
pub struct JournalRuntime {
    pub pool: sqlx::PgPool,
    pub rest: String,
    pub wrpc_url: String,
    pub network: String,
    pub cursor: String,
    pub cache_capacity: usize,
    pub fetch_concurrency: usize,
    pub use_journal: bool,
}

impl JournalRuntime {
    fn journal(&self) -> std::sync::Arc<crate::live_recovery::PgLiveWriteJournal> {
        std::sync::Arc::new(crate::live_recovery::PgLiveWriteJournal::new(
            self.pool.clone(),
            &self.network,
            &self.cursor,
        ))
    }
}

#[async_trait::async_trait(?Send)]
impl LiveRuntime for JournalRuntime {
    async fn pending(&self) -> Result<bool> {
        use crate::live_recovery::LiveWriteJournal;
        Ok(self.journal().load().await?.is_some())
    }

    async fn recover(&self) -> Result<()> {
        use crate::live_recovery::LiveWriteJournal;
        let journal = self.journal();
        let Some(mut window) = journal.load().await? else {
            return Err(
                crate::recovery_policy::RecoveryBlocked("journal_missing_before_recovery").into(),
            );
        };
        let recovery = crate::ChainTipFollower::new(
            crate::RestClient::new(self.rest.clone())?,
            std::sync::Arc::new(
                tn12_indexer_db::PgPersister::for_wrpc(self.pool.clone(), self.network.clone())?
                    .with_startup_recovery_acceptance_budget(),
            ),
            self.pool.clone(),
            format!("{}:recovery", self.cursor),
            crate::TipFollowerConfig {
                batch_size: window.window_width.unwrap_or(crate::TipFollowerConfig::default().batch_size),
                hydrate_concurrency: self.fetch_concurrency.max(1),
                prevout_concurrency: self.fetch_concurrency.max(1),
                recent_acceptance_reconciliation: true,
                ..Default::default()
            },
        )?;
        recovery
            .recover_live_window(&mut window, journal.as_ref())
            .await?;
        // Persist the verified replay before deleting its journal. A crash
        // between deletion and the supervisor's observation must still leave
        // durable evidence that watching may resume.
        self.observe(crate::recovery_state::Observation::new(
            "recovering",
            "completed",
        ))
        .await?;
        journal.complete(&window).await
    }

    async fn ensure_watch_safe(&self) -> Result<()> {
        crate::recovery_state::ensure_watch_safe(&self.pool, &self.network, &self.cursor).await
    }

    async fn watch(&self) -> Result<()> {
        let watcher = crate::WrpcVirtualChainWatcher::new(
            std::sync::Arc::new(tn12_indexer_db::PgPersister::for_wrpc(
                self.pool.clone(),
                self.network.clone(),
            )?),
            Box::new(crate::PgCursorStore::with_key(
                self.pool.clone(),
                self.cursor.clone(),
            )),
            Box::new(crate::PgCursorStore::with_key(
                self.pool.clone(),
                self.cursor.clone(),
            )),
            Box::new(crate::PgCursorStore::with_key(
                self.pool.clone(),
                "chain_wrpc_acceptance_heartbeat",
            )),
            crate::WrpcWatcherConfig {
                wrpc_url: self.wrpc_url.clone(),
                network_id: self.network.clone(),
                cache_capacity: self.cache_capacity,
            },
        );
        let watcher = if self.use_journal {
            watcher
                .with_write_journal(self.journal())
                .with_funding_metadata_source(crate::RestClient::new(self.rest.clone())?)
        } else {
            watcher
        };
        watcher.run_forever().await
    }

    async fn state(&self, phase: &str, error: Option<&str>) -> Result<()> {
        self.observe(crate::recovery_state::Observation {
            phase,
            outcome: "state",
            reason: None,
            error,
            next_retry_at_ms: None,
        })
        .await
    }

    async fn observe(&self, observation: crate::recovery_state::Observation<'_>) -> Result<()> {
        crate::recovery_state::record(&self.pool, &self.network, &self.cursor, observation).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tn12_indexer_db::persist::AcceptanceConflict;

    struct Fake(Mutex<(bool, usize, usize, Vec<String>)>);
    #[async_trait::async_trait(?Send)]
    impl LiveRuntime for Fake {
        async fn pending(&self) -> Result<bool> {
            Ok(self.0.lock().unwrap().0)
        }
        async fn recover(&self) -> Result<()> {
            let mut s = self.0.lock().unwrap();
            s.2 += 1;
            s.3.push("recover".into());
            if s.2 == 1 {
                return Err(RecoveryPending("source publication is behind").into());
            }
            if s.2 == 2 {
                return Err(tn12_indexer_db::persist::GenericWriteOutcomeUnknown {
                    phase: "commit",
                    detail: "canonical repair lost its acknowledgement".into(),
                }
                .into());
            }
            s.0 = false;
            Ok(())
        }
        async fn watch(&self) -> Result<()> {
            let mut s = self.0.lock().unwrap();
            assert!(!s.0, "reconnected with an unreconciled intent");
            s.1 += 1;
            s.3.push("watch".into());
            if s.1 == 1 {
                s.0 = true;
                return Err(AcceptanceConflict {
                    transaction_id: "11".repeat(32),
                    persisted_hash:
                        "e28f4ad719b11f8c245aa6ff56d50ab4434e6e85b6741cb49ccbeea12c8858ac".into(),
                    incoming_hash:
                        "c3ac6a2d7cf18c0276595b79b1ce5f76875d554dbe795d049522108c86164b88".into(),
                }
                .into());
            }
            anyhow::bail!("injected terminal stop")
        }
        async fn state(&self, phase: &str, _: Option<&str>) -> Result<()> {
            self.0.lock().unwrap().3.push(phase.into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn shutdown_failure_still_stops_services_and_is_terminal() {
        let stopped = std::sync::atomic::AtomicBool::new(false);
        let error = stop_transport(
            async { anyhow::bail!("socket shutdown failed") },
            async {
                stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
        assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(error.downcast_ref::<TransportCleanupFailed>().is_some());
        assert!(!retry_recovery(&error));
    }
    #[tokio::test]
    async fn shutdown_timeout_still_attempts_service_stop() {
        let stopped = std::sync::atomic::AtomicBool::new(false);
        let error = stop_transport(
            std::future::pending(),
            async {
                stopped.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();
        assert!(stopped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(error.downcast_ref::<TransportCleanupFailed>().is_some());
    }
    #[tokio::test]
    async fn fatal_recovery_never_reconnects() {
        struct Fatal;
        #[async_trait::async_trait(?Send)]
        impl LiveRuntime for Fatal {
            async fn pending(&self) -> Result<bool> {
                Ok(true)
            }
            async fn recover(&self) -> Result<()> {
                anyhow::bail!("durable consumer generation is stale")
            }
            async fn watch(&self) -> Result<()> {
                panic!("fatal recovery cannot reconnect")
            }
            async fn state(&self, _: &str, _: Option<&str>) -> Result<()> {
                Ok(())
            }
        }
        let error = supervise(&Fatal, Duration::ZERO).await.unwrap_err();
        assert!(error.to_string().contains("generation is stale"));
        assert!(!retry_recovery(&anyhow::anyhow!(
            "invalid recovery window width"
        )));
    }

    #[tokio::test]
    async fn acceptance_conflict_recovers_without_process_restart_or_early_reconnect() {
        let runtime = Fake(Mutex::new((false, 0, 0, vec![])));
        let result = supervise(&runtime, Duration::ZERO).await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("injected terminal stop"));
        let s = runtime.0.lock().unwrap();
        assert_eq!((s.0, s.1, s.2), (false, 2, 3));
        assert!(s.3.iter().any(|p| p == "recovering"));
    }

    #[tokio::test]
    async fn missing_parent_from_live_watch_enters_recovery_without_restart() {
        struct MissingParent(Mutex<(bool, usize, usize)>);
        #[async_trait::async_trait(?Send)]
        impl LiveRuntime for MissingParent {
            async fn pending(&self) -> Result<bool> {
                Ok(self.0.lock().unwrap().0)
            }
            async fn recover(&self) -> Result<()> {
                let mut state = self.0.lock().unwrap();
                state.1 += 1;
                state.0 = false;
                Ok(())
            }
            async fn watch(&self) -> Result<()> {
                let mut state = self.0.lock().unwrap();
                assert!(!state.0, "must recover before reconnecting");
                state.2 += 1;
                if state.2 > 1 {
                    return Ok(());
                }
                state.0 = true;
                Err(
                    tn12_indexer_db::persist::identity::MissingIdentityDependency {
                        txid: "11".repeat(32),
                        vout: 1,
                    }
                    .into(),
                )
            }
            async fn state(&self, _: &str, _: Option<&str>) -> Result<()> {
                Ok(())
            }
        }
        let runtime = MissingParent(Mutex::new((false, 0, 0)));
        supervise(&runtime, Duration::ZERO).await.unwrap();
        assert_eq!(*runtime.0.lock().unwrap(), (false, 1, 2));
    }
    #[tokio::test]
    async fn blocked_dependency_retains_intent_without_retry_or_reconnect() {
        struct Blocked(std::sync::atomic::AtomicUsize);
        #[async_trait::async_trait(?Send)]
        impl LiveRuntime for Blocked {
            async fn pending(&self) -> Result<bool> {
                Ok(true)
            }
            async fn recover(&self) -> Result<()> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(crate::recovery_policy::RecoveryBlocked("dependency_depth_limit").into())
            }
            async fn watch(&self) -> Result<()> {
                panic!("blocked recovery must not reconnect")
            }
            async fn state(&self, _: &str, _: Option<&str>) -> Result<()> {
                Ok(())
            }
        }
        let runtime = Blocked(std::sync::atomic::AtomicUsize::new(0));
        assert!(tokio::time::timeout(
            Duration::from_millis(25),
            supervise(&runtime, Duration::ZERO)
        )
        .await
        .is_err());
        assert_eq!(runtime.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(runtime.pending().await.unwrap());
    }

    #[tokio::test]
    async fn vanished_journal_cannot_complete_replay_or_reconnect() {
        struct Vanished(std::sync::atomic::AtomicUsize);
        #[async_trait::async_trait(?Send)]
        impl LiveRuntime for Vanished {
            async fn pending(&self) -> Result<bool> {
                Ok(self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0)
            }
            async fn recover(&self) -> Result<()> {
                Err(
                    crate::recovery_policy::RecoveryBlocked("journal_missing_before_recovery")
                        .into(),
                )
            }
            async fn watch(&self) -> Result<()> {
                panic!("missing journal must never reconnect")
            }
            async fn state(&self, _: &str, _: Option<&str>) -> Result<()> {
                Ok(())
            }
        }
        let error = supervise(
            &Vanished(std::sync::atomic::AtomicUsize::new(0)),
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("journal_missing_before_recovery"));
    }

    #[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
    async fn journal_runtime_refuses_to_recover_a_missing_intent(pool: sqlx::PgPool) {
        let runtime = JournalRuntime {
            pool,
            rest: "http://unused.invalid".into(),
            wrpc_url: "ws://unused.invalid".into(),
            network: "testnet-10".into(),
            cursor: "missing-intent-test".into(),
            cache_capacity: 1,
            fetch_concurrency: 1,
            use_journal: true,
        };
        let error = runtime.recover().await.unwrap_err();
        assert!(matches!(
            crate::recovery_policy::classify(&error),
            crate::recovery_policy::Decision::Blocked("journal_missing_before_recovery")
        ));
    }

    #[tokio::test]
    async fn restart_guard_records_a_blocked_incident_before_exiting() {
        struct Guarded(Mutex<Vec<String>>);
        #[async_trait::async_trait(?Send)]
        impl LiveRuntime for Guarded {
            async fn pending(&self) -> Result<bool> {
                Ok(false)
            }
            async fn recover(&self) -> Result<()> {
                panic!("no journal to recover")
            }
            async fn ensure_watch_safe(&self) -> Result<()> {
                Err(crate::recovery_policy::RecoveryBlocked("unverified_recovery_state").into())
            }
            async fn watch(&self) -> Result<()> {
                panic!("unverified state must not reconnect")
            }
            async fn state(&self, phase: &str, _: Option<&str>) -> Result<()> {
                self.0.lock().unwrap().push(phase.into());
                Ok(())
            }
        }
        let runtime = Guarded(Mutex::new(Vec::new()));
        let error = supervise(&runtime, Duration::ZERO).await.unwrap_err();
        assert!(error.to_string().contains("unverified_recovery_state"));
        assert_eq!(*runtime.0.lock().unwrap(), vec!["blocked"]);
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::recovery_policy::{check_capacity, classify, Decision, RecoveryBlocked};
    use std::sync::Mutex;
    use tokio::time::Instant;

    struct CapacityRuntime {
        state: Mutex<(bool, Vec<Instant>, usize, Vec<i64>)>,
        failures: usize,
        vanish: bool,
    }
    #[async_trait::async_trait(?Send)]
    impl LiveRuntime for CapacityRuntime {
        async fn pending(&self) -> Result<bool> { Ok(self.state.lock().unwrap().0) }
        async fn recover(&self) -> Result<()> {
            let mut s = self.state.lock().unwrap();
            s.1.push(Instant::now());
            if s.1.len() <= self.failures {
                return check_capacity("dependency_page_count", 257, 256);
            }
            s.0 = false;
            Ok(())
        }
        async fn watch(&self) -> Result<()> {
            let mut s = self.state.lock().unwrap();
            assert!(!s.0);
            assert!(s.1.len() > self.failures, "must complete recovery before reconnecting");
            s.2 += 1;
            Ok(())
        }
        async fn state(&self, _: &str, _: Option<&str>) -> Result<()> { Ok(()) }
        async fn observe(&self, o: crate::recovery_state::Observation<'_>) -> Result<()> {
            if o.phase == "blocked" {
                let mut s = self.state.lock().unwrap();
                assert!(s.0, "capacity failure must retain intent");
                s.3.push(o.next_retry_at_ms.expect("capacity must schedule reassessment"));
                if self.vanish { s.0 = false; }
            }
            Ok(())
        }
    }
    fn runtime(failures: usize, vanish: bool) -> CapacityRuntime {
        CapacityRuntime { state: Mutex::new((true, vec![], 0, vec![])), failures, vanish }
    }

    #[tokio::test(start_paused = true)]
    async fn capacity_recovers_after_dependencies_arrive_without_restart() {
        let r = runtime(2, false);
        supervise(&r, Duration::ZERO).await.unwrap();
        let s = r.state.lock().unwrap();
        assert_eq!((s.0, s.1.len(), s.2, s.3.len()), (false, 3, 1, 2));
        assert_eq!(s.1[1].duration_since(s.1[0]), Duration::from_secs(60));
        assert_eq!(s.1[2].duration_since(s.1[1]), Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn persistent_capacity_is_paced_and_never_reconnects() {
        let r = runtime(usize::MAX, false);
        assert!(tokio::time::timeout(Duration::from_secs(1000), supervise(&r, Duration::ZERO)).await.is_err());
        let s = r.state.lock().unwrap();
        assert!(s.0);
        assert_eq!(s.2, 0);
        assert_eq!(s.1.len(), 5); // attempts at 0, 60, 180, 420, 720 seconds
        assert_eq!(s.1[4].duration_since(s.1[3]), Duration::from_secs(300));
    }

    #[tokio::test(start_paused = true)]
    async fn disappearing_journal_during_capacity_wait_does_not_reconnect() {
        let r = runtime(1, true);
        let error = supervise(&r, Duration::ZERO).await.unwrap_err();
        assert_eq!(classify(&error), Decision::Reassess("dependency_page_count"));
        let s = r.state.lock().unwrap();
        assert_eq!((s.1.len(), s.2), (1, 0));
    }

    #[test]
    fn capacity_classification_keeps_limits_and_contradictions_distinct() {
        check_capacity("dependency_count", 256, 256).unwrap();
        let error = check_capacity("dependency_count", 257, 256).unwrap_err();
        assert_eq!(classify(&error), Decision::Reassess("dependency_count"));
        assert!(error.to_string().contains("observed=257 limit=256"));
        for reason in ["parent_output_mismatch", "source_identity_mismatch", "journal_missing_before_recovery", "contradictory_identity"] {
            assert_eq!(classify(&RecoveryBlocked(reason).into()), Decision::Blocked(reason));
        }
    }
}
