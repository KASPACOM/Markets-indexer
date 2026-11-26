//! Exercise the actual live writer, durable journal, REST recovery and PostgreSQL.
use super::*;
use crate::live_recovery::{LiveWriteJournal, PgLiveWriteJournal};
use crate::live_supervisor::{supervise, JournalRuntime, LiveRuntime};
use std::sync::atomic::{AtomicUsize, Ordering};
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};
use tn12_indexer_db::PgPersister;

struct Runtime {
    recovery: JournalRuntime,
    child: RestTransaction,
    watches: AtomicUsize,
    recoveries: AtomicUsize,
    change_parent: bool,
}
#[async_trait::async_trait(?Send)]
impl LiveRuntime for Runtime {
    async fn pending(&self) -> Result<bool> {
        self.recovery.pending().await
    }
    async fn recover(&self) -> Result<()> {
        let attempt = self.recoveries.fetch_add(1, Ordering::SeqCst) + 1;
        let result = self.recovery.recover().await;
        if self.change_parent && attempt == 2 {
            assert!(result
                .as_ref()
                .unwrap_err()
                .is::<crate::live_supervisor::RecoveryPending>());
            let retained =
                PgLiveWriteJournal::new(self.recovery.pool.clone(), "testnet-10", "handoff")
                    .load()
                    .await?
                    .unwrap();
            assert_eq!(
                retained.transactions.len(),
                2,
                "original child and fetched parent must survive recovery"
            );
            assert!(retained.observed_blocks.contains_key(&90));
            assert!(retained
                .transactions
                .iter()
                .any(|tx| tx.transaction_id == "11".repeat(32)));
            // Reconstruct the journal adapter, as a process restart would.
            assert!(self.recovery.pending().await?);
        }
        result
    }
    async fn watch(&self) -> Result<()> {
        assert!(!self.pending().await?);
        if self.watches.fetch_add(1, Ordering::SeqCst) > 0 {
            return Ok(());
        }
        let pool = self.recovery.pool.clone();
        let journal = Arc::new(PgLiveWriteJournal::new(
            pool.clone(),
            "testnet-10",
            "handoff",
        ));
        let watcher = WrpcVirtualChainWatcher::new(
            Arc::new(PgPersister::new(pool.clone())),
            Box::new(crate::PgCursorStore::with_key(pool.clone(), "unused-watch")),
            Box::new(crate::PgCursorStore::with_key(pool.clone(), "unused-reorg")),
            Box::new(crate::PgCursorStore::with_key(
                pool.clone(),
                "unused-heartbeat",
            )),
            WrpcWatcherConfig {
                wrpc_url: "ws://unused".into(),
                network_id: "testnet-10".into(),
                cache_capacity: 16,
            },
        )
        .with_write_journal(journal.clone());
        let error = watcher
            .persist_candidates(vec![self.child.clone()], &mut WrpcWatcherStats::default())
            .await
            .unwrap_err();
        assert!(error.is::<tn12_indexer_db::persist::identity::MissingIdentityDependency>());
        assert!(journal.load().await?.is_some());
        Err(error)
    }
    async fn state(&self, phase: &str, error: Option<&str>) -> Result<()> {
        self.recovery.state(phase, error).await
    }
    async fn observe(&self, o: crate::recovery_state::Observation<'_>) -> Result<()> {
        self.recovery.observe(o).await
    }
}

async fn recover_missing_parent(pool: sqlx::PgPool, funding: bool, change_parent: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let p2sh = format!("aa20{}87", "33".repeat(32));
    let parent = RestTransaction {
        transaction_id: "11".repeat(32),
        is_accepted: true,
        accepting_block_hash: Some("22".repeat(32)),
        accepting_block_blue_score: Some(95),
        accepting_block_time: Some(9500),
        outputs: vec![RestTxOutput {
            transaction_id: "11".repeat(32),
            index: 0,
            amount: 1000,
            script_public_key: if funding {
                format!("20{}ac", "44".repeat(32))
            } else {
                p2sh.clone()
            },
            ..Default::default()
        }],
        ..Default::default()
    };
    let child = RestTransaction {
        transaction_id: "55".repeat(32),
        version: 1,
        is_accepted: true,
        payload: Some(String::new()),
        accepting_block_hash: Some("66".repeat(32)),
        accepting_block_blue_score: Some(105),
        accepting_block_time: Some(10500),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: parent.transaction_id.clone(),
            previous_outpoint_index: "0".into(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: "55".repeat(32),
            index: 0,
            amount: 900,
            script_public_key: p2sh,
            ..Default::default()
        }],
        ..Default::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serving_child = child.clone();
    let parent_reads = Arc::new(AtomicUsize::new(0));
    let reads = parent_reads.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 65536];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            let (status, body) = if request.contains("/info/health") {
                (
                    200,
                    serde_json::json!({"database":{"blueScore":200,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}}),
                )
            } else if request.contains(&format!("/transactions/{}?", parent.transaction_id)) {
                // A temporary missing parent must retain the original journal.
                let read = reads.fetch_add(1, Ordering::SeqCst);
                if read == 0 {
                    (404, serde_json::json!({}))
                } else if change_parent && read == 2 {
                    let mut changed = parent.clone();
                    changed.is_accepted = false;
                    (200, serde_json::to_value(changed).unwrap())
                } else {
                    (200, serde_json::to_value(&parent).unwrap())
                }
            } else if request.contains("/transactions/")
                && !request.contains("/transactions/search")
            {
                (200, serde_json::to_value(&serving_child).unwrap())
            } else if request.contains("/virtual-chain?") {
                let tx = if request.contains("blueScoreGte=90") {
                    &parent
                } else {
                    &serving_child
                };
                (
                    200,
                    serde_json::json!([{"hash":tx.accepting_block_hash,"blue_score":tx.accepting_block_blue_score,"daa_score":tx.accepting_block_blue_score,"timestamp":tx.accepting_block_time,"transactions":[tx]}]),
                )
            } else {
                (200, serde_json::json!([]))
            };
            let body = body.to_string();
            stream.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 {status} fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len())).as_bytes()).await.unwrap();
        }
    });
    let runtime = Runtime {
        recovery: JournalRuntime {
            pool: pool.clone(),
            rest: format!("http://{address}"),
            wrpc_url: "ws://unused".into(),
            network: "testnet-10".into(),
            cursor: "handoff".into(),
            cache_capacity: 16,
            fetch_concurrency: 8,
            use_journal: true,
        },
        child: child.clone(),
        watches: AtomicUsize::new(0),
        recoveries: AtomicUsize::new(0),
        change_parent,
    };
    tokio::time::timeout(Duration::from_secs(15), supervise(&runtime, Duration::ZERO))
        .await
        .unwrap()
        .unwrap();
    server.abort();
    assert_eq!(runtime.watches.load(Ordering::SeqCst), 2);
    assert_eq!(
        runtime.recoveries.load(Ordering::SeqCst),
        if change_parent { 3 } else { 2 }
    );
    assert!(!runtime.pending().await.unwrap());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE txid=decode($1,'hex')")
            .bind(&child.transaction_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let cursors: i64 =
        sqlx::query_scalar("SELECT count(*) FROM indexer_state WHERE key LIKE 'unused-%'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursors, 0);
    let state: serde_json::Value = sqlx::query_scalar(
        "SELECT value FROM indexer_state WHERE key='live_recovery_state:testnet-10:handoff'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state["phase"], "watching");
    assert_eq!(state["completedTotal"], 1);
    assert_eq!(state["attempts"], if change_parent { 3 } else { 2 });
    // Reprocessing after an acknowledged commit must preserve the same output.
    let mut hydrated = child;
    hydrated.inputs[0].previous_outpoint_script = Some(if funding {
        format!("20{}ac", "44".repeat(32))
    } else {
        format!("aa20{}87", "33".repeat(32))
    });
    PgPersister::new(pool).persist_tx(&hydrated).await.unwrap();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn live_funding_dependency_recovers_through_rest_and_postgres(pool: sqlx::PgPool) {
    recover_missing_parent(pool, true, false).await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn live_covenant_dependency_recovers_through_rest_and_postgres(pool: sqlx::PgPool) {
    recover_missing_parent(pool, false, false).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn changed_parent_after_commit_keeps_journal_until_canonical_replay(pool: sqlx::PgPool) {
    recover_missing_parent(pool, false, true).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn funding_parent_after_commit_is_replayed_even_though_not_a_covenant(pool: sqlx::PgPool) {
    recover_missing_parent(pool, true, true).await;
}

/// Exercise the real count ceiling and DB presence lookup, not an injected error.
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn capacity_reassesses_after_rest_writer_fills_exact_parent_outputs(pool: sqlx::PgPool) {
    use crate::live_recovery::LiveWriteWindow;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let script = format!("aa20{}87", "33".repeat(32));
    let parents: Vec<_> = (1..=257).map(|n| RestTransaction {
        transaction_id: format!("{n:064x}"),
        is_accepted: true,
        accepting_block_hash: Some("22".repeat(32)),
        accepting_block_blue_score: Some(95),
        accepting_block_time: Some(9500),
        outputs: vec![RestTxOutput { index: 0, amount: 1000, script_public_key: script.clone(), ..Default::default() }],
        ..Default::default()
    }).collect();
    let child = RestTransaction {
        transaction_id: "55".repeat(32),
        is_accepted: true,
        accepting_block_hash: Some("66".repeat(32)),
        accepting_block_blue_score: Some(115),
        accepting_block_time: Some(11500),
        inputs: parents.iter().map(|p| RestTxInput {
            previous_outpoint_hash: p.transaction_id.clone(),
            previous_outpoint_index: "0".into(),
            previous_outpoint_script: Some(script.clone()),
            ..Default::default()
        }).collect(),
        outputs: vec![RestTxOutput { index: 0, amount: 900, script_public_key: script, ..Default::default() }],
        ..Default::default()
    };
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "capacity-handoff");
    journal.begin(&LiveWriteWindow::new(&[child.clone()]).unwrap()).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = child.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 65536];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            let body = if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore":200,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/virtual-chain?") {
                serde_json::json!([{"hash":served.accepting_block_hash,"blue_score":115,"daa_score":115,"timestamp":11500,"transactions":[served]}])
            } else if request.contains(&format!("/transactions/{}?", served.transaction_id)) {
                serde_json::to_value(&served).unwrap()
            } else {
                assert!(!request.contains("/transactions/") || request.contains("/transactions/search"),
                    "known parent outputs must avoid recursive REST fetch");
                serde_json::json!([])
            };
            let body = body.to_string();
            stream.write_all(crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
            )).as_bytes()).await.unwrap();
        }
    });
    struct ReassessRuntime {
        inner: JournalRuntime,
        parents: Vec<RestTransaction>,
        attempts: AtomicUsize,
        watches: AtomicUsize,
    }
    #[async_trait::async_trait(?Send)]
    impl LiveRuntime for ReassessRuntime {
        async fn pending(&self) -> Result<bool> { self.inner.pending().await }
        async fn recover(&self) -> Result<()> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            self.inner.recover().await
        }
        async fn ensure_watch_safe(&self) -> Result<()> { self.inner.ensure_watch_safe().await }
        async fn watch(&self) -> Result<()> {
            assert!(!self.pending().await?);
            assert_eq!(self.attempts.load(Ordering::SeqCst), 2);
            self.inner.ensure_watch_safe().await?;
            self.watches.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn state(&self, phase: &str, error: Option<&str>) -> Result<()> { self.inner.state(phase, error).await }
        async fn observe(&self, observation: crate::recovery_state::Observation<'_>) -> Result<()> {
            let capacity = observation.reason == Some("dependency_page_count");
            self.inner.observe(observation).await?;
            if capacity {
                assert!(self.pending().await?);
                assert_eq!(self.watches.load(Ordering::SeqCst), 0);
                // Simulate independent REST repair while the live supervisor waits.
                let persister = PgPersister::new(self.inner.pool.clone());
                for parent in &self.parents { persister.persist_tx(parent).await?; }
                // Supplying parents alone cannot acknowledge the journal.
                assert!(self.pending().await?);
                assert!(self.inner.ensure_watch_safe().await.is_err());
            }
            Ok(())
        }
    }
    let runtime = ReassessRuntime {
        inner: JournalRuntime {
            pool: pool.clone(), rest: format!("http://{address}"), wrpc_url: "ws://unused".into(),
            network: "testnet-10".into(), cursor: "capacity-handoff".into(), cache_capacity: 16,
            fetch_concurrency: 8, use_journal: true,
        },
        parents, attempts: AtomicUsize::new(0), watches: AtomicUsize::new(0),
    };
    // Keep real time here: pausing Tokio also advances SQLx/HTTP deadlines.
    tokio::time::timeout(Duration::from_secs(100), supervise(&runtime, Duration::ZERO)).await.unwrap().unwrap();
    server.abort();
    assert_eq!(runtime.watches.load(Ordering::SeqCst), 1);
    assert!(journal.load().await.unwrap().is_none());
    let state: serde_json::Value = sqlx::query_scalar("SELECT value FROM indexer_state WHERE key='live_recovery_state:testnet-10:capacity-handoff'")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(state["completedTotal"], 1);
    assert_eq!(state["attempts"], 2);
    assert!(state["lastIncident"]["replayEvidence"].is_object());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE txid=decode($1,'hex')")
        .bind(&child.transaction_id).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}
