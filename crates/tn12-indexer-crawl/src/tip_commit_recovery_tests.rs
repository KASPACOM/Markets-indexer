use super::*;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};
use tn12_indexer_core::{RestTransaction, RestTxOutput};
use tn12_indexer_db::{PersistStats, PgPersister, RevertStats};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CommitThenLoseAck {
    inner: PgPersister,
    failed: AtomicBool,
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn exclusive_recovery_pauses_history_before_any_source_request(pool: tn12_indexer_db::PgPool) {
    let follower = ChainTipFollower::new(
        RestClient::new("http://127.0.0.1:1").unwrap(),
        Arc::new(PgPersister::new(pool.clone())), pool.clone(),
        "exclusive-pause-test", TipFollowerConfig::default(),
    ).unwrap();
    follower.store.commit_window(None,109,0).await.unwrap();
    sqlx::query("INSERT INTO tn10_live_recovery_plans(intent_key,intent_sha256,owner_token,lease_expires_at_ms,phase,updated_at_ms,exclusive_writes) VALUES('test-pause',decode(repeat('11',32),'hex'),gen_random_uuid(),0,'revert',1,TRUE)")
        .execute(&pool).await.unwrap();
    let mut state=follower.store.load_state().await.unwrap();
    let error=follower.run_once(&mut state).await.unwrap_err();
    assert!(error.downcast_ref::<HistoricalPreparationPaused>().is_some(),"must pause before contacting the unavailable source: {error:#}");
    let error=follower.run_settled_recheck(1000,1000).await.unwrap_err();
    assert!(error.downcast_ref::<HistoricalPreparationPaused>().is_some());
    assert_eq!(follower.store.load_state().await.unwrap().cursor_blue_score,Some(109));
    // An expired owner still fences partially applied canonical state.
    assert!(follower.canonical_recovery_owns_writes().await.unwrap());
    sqlx::query("DELETE FROM tn10_live_recovery_plans WHERE intent_key='test-pause'").execute(&pool).await.unwrap();
    follower.check_historical_preparation().await.unwrap();
}
#[async_trait::async_trait]
impl Persister for CommitThenLoseAck {
    async fn persist_batch(&self, txs: &[RestTransaction]) -> Result<PersistStats> {
        let stats = self.inner.persist_batch(txs).await?;
        if !self.failed.swap(true, Ordering::SeqCst) {
            return Err(tn12_indexer_db::persist::GenericWriteOutcomeUnknown {
                phase: "commit",
                detail: "injected after actual batch commit".into(),
            }
            .into());
        }
        Ok(stats)
    }
    async fn persist_tx(&self, _: &RestTransaction) -> Result<PersistStats> {
        panic!("uncertain batch must never fall back to individual writes")
    }
    async fn revert_block(&self, hash: &[u8]) -> Result<RevertStats> {
        self.inner.revert_block(hash).await
    }
    async fn has_utxo(&self, id: &str, vout: i32) -> Result<bool> {
        self.inner.has_utxo(id, vout).await
    }
    async fn existing_utxos(&self, points: &[(String, i32)]) -> Result<HashSet<(String, i32)>> {
        self.inner.existing_utxos(points).await
    }
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn source_handoff_requires_cursor_and_resumes_after_boundary(pool: tn12_indexer_db::PgPool) {
    let follower = ChainTipFollower::new(
        RestClient::new("http://127.0.0.1:1").unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool,
        "source-handoff-test",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let error = follower.run_until_blue_score(100).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("requires a durable replay cursor"));
    follower.store.commit_window(None, 109, 0).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), follower.run_until_blue_score(100))
        .await
        .expect("already-crossed boundary must return promptly")
        .unwrap();
    assert_eq!(
        follower.store.load_state().await.unwrap().cursor_blue_score,
        Some(109)
    );
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn source_handoff_stops_after_committing_boundary_window(pool: tn12_indexer_db::PgPool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut bytes = [0; 2048];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                let path = String::from_utf8(request).unwrap();
                let body = if path.contains("/info/health") {
                    serde_json::json!({"database":{"blueScore":109,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
                } else {
                    assert!(path.contains("blueScoreGte=100"));
                    serde_json::json!([{
                        "hash":format!("{:064x}",100),"blue_score":100,
                        "daa_score":100,"timestamp":100,"transactions":[]
                    }])
                };
                let body = serde_json::to_vec(&body).unwrap();
                socket.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            });
        }
    });
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool,
        "source-handoff-crossing-test",
        TipFollowerConfig {
            overlap_windows: 1,
            max_catchup_windows: 1,
            ..Default::default()
        },
    )
    .unwrap();
    follower.store.commit_window(None, 99, 0).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), follower.run_until_blue_score(100))
        .await
        .expect("handoff must stop after the committed window")
        .unwrap();
    server.abort();
    assert_eq!(
        follower.store.load_state().await.unwrap().cursor_blue_score,
        Some(109)
    );
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn unhealthy_source_after_page_fetch_retains_cursor(pool: tn12_indexer_db::PgPool) {
    let health_reads = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn({
        let health_reads = health_reads.clone();
        async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let size = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let path = request.split_whitespace().nth(1).unwrap();
                let (status, body) = if path.split('?').next() == Some("/info/health") {
                    if health_reads.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            "200 OK",
                            serde_json::json!({"database":{"blueScore":109,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}}),
                        )
                    } else {
                        (
                            "503 Service Unavailable",
                            serde_json::json!({"database":{"blueScore":109,"isSynced":false}}),
                        )
                    }
                } else {
                    assert!(path.contains("blueScoreGte=100"));
                    (
                        "200 OK",
                        serde_json::json!([{
                            "hash":format!("{:064x}",100),"blue_score":100,
                            "daa_score":100,"timestamp":100,"transactions":[]
                        }]),
                    )
                };
                let body = serde_json::to_vec(&body).unwrap();
                socket.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        }
    });
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool,
        "unhealthy-source-cursor-test",
        TipFollowerConfig {
            overlap_windows: 1,
            max_catchup_windows: 1,
            ..Default::default()
        },
    )
    .unwrap();
    follower.store.commit_window(None, 99, 0).await.unwrap();
    let mut state = follower.store.load_state().await.unwrap();
    assert!(follower.run_once(&mut state).await.is_err());
    assert_eq!(health_reads.load(Ordering::SeqCst), 2);
    assert_eq!(state.cursor_blue_score, Some(99));
    assert_eq!(
        follower.store.load_state().await.unwrap().cursor_blue_score,
        Some(99)
    );
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn tip_unknown_commit_retains_cursor_then_recovers_same_source_window(
    pool: tn12_indexer_db::PgPool,
) {
    check_tip_recovery(pool, false, 10).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn hundred_score_window_unknown_commit_retains_cursor_then_recovers(
    pool: tn12_indexer_db::PgPool,
) {
    check_tip_recovery(pool, false, 100).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn parallel_rest_fetch_keeps_cursor_commits_in_score_order(pool: tn12_indexer_db::PgPool) {
    let completed = Arc::new(Mutex::new(Vec::<u64>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let completed_for_server = completed.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let completed = completed_for_server.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut bytes = [0; 2048];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                let request = String::from_utf8(request).unwrap();
                let path = request.split_whitespace().nth(1).unwrap();
                let body = if path.split('?').next() == Some("/info/health") {
                    serde_json::json!({"database":{"blueScore":1129,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
                } else {
                    let start: u64 = path
                        .split("blueScoreGte=")
                        .nth(1)
                        .unwrap()
                        .split('&')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!([100, 110, 120].contains(&start));
                    tokio::time::sleep(Duration::from_millis(if start == 100 { 200 } else { 10 }))
                        .await;
                    completed.lock().unwrap().push(start);
                    serde_json::json!([{
                        "hash":format!("{:064x}", start),"blue_score":start,
                        "daa_score":start,"timestamp":start,"transactions":[]
                    }])
                };
                let body = serde_json::to_vec(&body).unwrap();
                socket.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            });
        }
    });
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "parallel-rest-order-test",
        TipFollowerConfig {
            overlap_windows: 1,
            max_catchup_windows: 3,
            window_fetch_concurrency: 3,
            ..Default::default()
        },
    )
    .unwrap();
    follower.store.commit_window(None, 99, 0).await.unwrap();
    let mut state = follower.store.load_state().await.unwrap();
    let stats = follower.run_once(&mut state).await.unwrap();
    server.abort();
    assert_eq!(stats.windows_scanned, 3);
    assert_eq!(state.cursor_blue_score, Some(129));
    assert_eq!(
        follower.store.load_state().await.unwrap().cursor_blue_score,
        Some(129)
    );
    let completed = completed.lock().unwrap();
    assert!(
        completed.iter().position(|score| *score == 110).unwrap()
            < completed.iter().position(|score| *score == 100).unwrap()
    );
}

#[tokio::test]
async fn future_windows_finish_fetching_while_ordered_writer_is_busy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut bytes = [0; 2048];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                let request = String::from_utf8(request).unwrap();
                let path = request.split_whitespace().nth(1).unwrap();
                let start: u64 = path
                    .split("blueScoreGte=")
                    .nth(1)
                    .unwrap()
                    .split('&')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(if start == 100 { 50 } else { 10 })).await;
                let body = serde_json::to_vec(&serde_json::json!([{
                    "hash":format!("{:064x}", start), "blue_score":start,
                    "daa_score":start, "timestamp":start, "transactions":[]
                }]))
                .unwrap();
                socket.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            });
        }
    });
    let rest = RestClient::new(format!("http://{address}")).unwrap();
    let pool = tn12_indexer_db::PgPool::connect_lazy("postgres://localhost/test").unwrap();
    let scanner = Arc::new(ChainScanner::new(
        rest.clone(),
        Arc::new(PgPersister::new(pool)),
        ScannerConfig::default(),
        Box::new(NoopCursor),
    ));
    let mut fetches = WindowFetches::start(rest, scanner, vec![100, 110, 120], 10, 3);
    assert!(fetches
        .next()
        .await
        .unwrap()
        .0
        .unwrap()
        .block_hashes()
        .contains(&format!("{:064x}", 100)));
    // Model a database commit by not polling the next result. Both later
    // windows must still reach the bounded channel in source order.
    tokio::time::timeout(Duration::from_secs(2), async {
        while fetches.receiver.len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(fetches
        .next()
        .await
        .unwrap()
        .0
        .unwrap()
        .block_hashes()
        .contains(&format!("{:064x}", 110)));
    assert!(fetches
        .next()
        .await
        .unwrap()
        .0
        .unwrap()
        .block_hashes()
        .contains(&format!("{:064x}", 120)));
    server.abort();
}

#[tokio::test]
async fn future_window_hydration_finishes_before_ordered_writer_receives_it() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let searches = Arc::new(AtomicUsize::new(0));
    let server_searches = searches.clone();
    let p2sh = format!("aa20{}87", "11".repeat(32));
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let searches = server_searches.clone();
            let p2sh = p2sh.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let header_end = loop {
                    let mut bytes = [0; 4096];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                    if let Some(pos) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let header = String::from_utf8_lossy(&request[..header_end]).into_owned();
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap_or(0);
                while request.len() < header_end + length {
                    let mut bytes = [0; 4096];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&bytes[..n]);
                }
                let body = if header.starts_with("GET /virtual-chain?") {
                    let start: u64 = header
                        .split("blueScoreGte=")
                        .nth(1)
                        .unwrap()
                        .split('&')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let transactions: Vec<_> = (1..=2)
                        .map(|offset| {
                            serde_json::json!({
                                "transaction_id": format!("{:064x}", start * 10 + offset),
                                "outputs": [{"index": 0, "amount": 100,
                                             "script_public_key": p2sh}]
                            })
                        })
                        .collect();
                    serde_json::json!([{"hash": format!("{:064x}", start),
                        "blue_score": start, "timestamp": start,
                        "transactions": transactions}])
                } else {
                    assert!(header.starts_with("POST /transactions/search?fields="));
                    searches.fetch_add(1, Ordering::SeqCst);
                    let request_body: serde_json::Value =
                        serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
                    serde_json::Value::Array(
                        request_body["transactionIds"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|id| {
                                serde_json::json!({
                                    "transaction_id": id, "version": 0, "payload": "abcd",
                                    "outputs": [{"index": 0, "amount": 100,
                                                 "script_public_key": p2sh}]
                                })
                            })
                            .collect(),
                    )
                };
                let body = serde_json::to_vec(&body).unwrap();
                socket
                    .write_all(
                        crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()))
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                socket.write_all(&body).await.unwrap();
            });
        }
    });
    let rest = RestClient::new(format!("http://{address}")).unwrap();
    let pool = tn12_indexer_db::PgPool::connect_lazy("postgres://localhost/test").unwrap();
    let scanner = Arc::new(
        ChainScanner::new(
            rest.clone(),
            Arc::new(PgPersister::new(pool)),
            ScannerConfig {
                hydrate_concurrency: 1,
                ..Default::default()
            },
            Box::new(NoopCursor),
        )
        .with_bulk_block_hydration(),
    );
    let mut fetches = WindowFetches::start(rest, scanner, vec![100, 110], 10, 2);
    tokio::time::timeout(Duration::from_secs(3), async {
        while fetches.receiver.len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(searches.load(Ordering::SeqCst), 2);
    for start in [100, 110] {
        let (prepared, hydrate_ms) = fetches.next().await.unwrap();
        assert!(hydrate_ms.is_some());
        assert!(prepared
            .unwrap()
            .block_hashes()
            .contains(&format!("{start:064x}")));
    }
    server.abort();
}

#[ignore = "timed writer recovery; exercised serially by the writer recovery CI step"]
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn tip_budget_partial_prefix_retains_cursor_then_recovers_same_source_window(
    pool: tn12_indexer_db::PgPool,
) {
    check_tip_recovery(pool, true, 10).await;
}

async fn check_tip_recovery(pool: tn12_indexer_db::PgPool, partial_prefix: bool, batch_size: u32) {
    let fixture: Vec<RestTransaction> = serde_json::from_str(include_str!(
        "../../tn12-indexer-db/tests/fixtures/tn10-dense-generic-32.json"
    ))
    .unwrap();
    let mut txs = fixture[..16].to_vec();
    for tx in &mut txs {
        tx.accepting_block_hash = Some("cc".repeat(32));
        tx.accepting_block_blue_score = Some(109);
        tx.accepting_block_time = Some(tx.block_time);
    }
    let writer = PgPersister::new(pool.clone())
        .with_bounded_writer_lock_wait()
        .with_generic_bulk_persist(true)
        .with_generic_bulk_max_txs(16)
        .with_generic_writer_budget(partial_prefix);
    for tx in &txs {
        for input in &tx.inputs {
            let id = input.previous_outpoint_hash.clone();
            writer
                .persist_tx(&RestTransaction {
                    transaction_id: id.clone(),
                    block_time: tx.block_time - 1,
                    version: 0,
                    is_accepted: true,
                    accepting_block_hash: Some(id.clone()),
                    accepting_block_blue_score: Some(98),
                    outputs: vec![RestTxOutput {
                        transaction_id: id,
                        index: input.previous_outpoint_index.parse().unwrap(),
                        amount: input.previous_outpoint_amount.unwrap(),
                        script_public_key: input.previous_outpoint_script.clone().unwrap(),
                        script_public_key_address: input.previous_outpoint_address.clone(),
                        ..Default::default()
                    }],
                    ..Default::default()
                })
                .await
                .unwrap();
        }
    }
    if partial_prefix {
        sqlx::raw_sql(include_str!(
            "../../tn12-indexer-db/tests/fixtures/generic-writer-budget-delays.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(r#"
CREATE TABLE test_later_prefix_failure(txid bytea NOT NULL);
CREATE FUNCTION test_later_prefix_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
IF EXISTS(SELECT 1 FROM covenant_actions n JOIN test_later_prefix_failure f USING(txid)) THEN
PERFORM pg_sleep(0.12);
END IF;
RETURN NULL;
END $$;
CREATE TRIGGER z_test_later_prefix_failure AFTER INSERT ON blocks FOR EACH STATEMENT EXECUTE FUNCTION test_later_prefix_failure();
"#).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO test_later_prefix_failure VALUES (decode($1,'hex'))")
            .bind(&txs[0].transaction_id)
            .execute(&pool)
            .await
            .unwrap();
    }
    let block_hash = "cc".repeat(32);
    let source = Arc::new(Mutex::new(serde_json::json!([{
        "hash":block_hash,"blue_score":109,"daa_score":109,"timestamp":txs[0].block_time,"transactions":txs
    }])));
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let source_copy = source.clone();
    let requests_copy = requests.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
                assert!(bytes.len() < 1_048_576);
                if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
            };
            let header = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
            let length = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while bytes.len() < header_end + length {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
            }
            let path = header
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            requests_copy.lock().unwrap().push(path.to_owned());
            let body = if path.split('?').next() == Some("/info/health") {
                serde_json::json!({"database":{"blueScore":219,"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
            } else if path.starts_with("/virtual-chain?") {
                source_copy.lock().unwrap().clone()
            } else if path.starts_with("/transactions/search?") {
                source_copy.lock().unwrap()[0]["transactions"].clone()
            } else if path.starts_with("/transactions/") {
                let id = path
                    .trim_start_matches("/transactions/")
                    .split('?')
                    .next()
                    .unwrap();
                source_copy.lock().unwrap()[0]["transactions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|tx| tx["transaction_id"] == id)
                    .unwrap()
                    .clone()
            } else {
                panic!("unexpected source request {path}")
            };
            let body = serde_json::to_vec(&body).unwrap();
            socket.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len())).as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        }
    });
    let persister = Arc::new(CommitThenLoseAck {
        inner: writer,
        failed: AtomicBool::new(partial_prefix),
    });
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        persister.clone(),
        pool.clone(),
        "commit-recovery-test",
        TipFollowerConfig {
            batch_size,
            overlap_windows: 1,
            max_catchup_windows: 1,
            window_fetch_concurrency: 3,
            ..Default::default()
        },
    )
    .unwrap();
    follower.store.commit_window(None, 99, 0).await.unwrap();
    let mut state = follower.store.load_state().await.unwrap();
    let first = tokio::time::timeout(Duration::from_secs(10), follower.run_once(&mut state))
        .await
        .unwrap()
        .unwrap_err();
    if partial_prefix {
        assert!(
            tn12_indexer_db::is_transient_persist_error(&first),
            "{first:#}"
        );
        let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM test_budget_attempts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            attempts, 6,
            "16 rolls back, first 8 commit, then server timeouts exhaust 8,4,2,1"
        );
    } else {
        assert!(
            first
                .downcast_ref::<tn12_indexer_db::persist::GenericWriteOutcomeUnknown>()
                .is_some(),
            "{first:#}"
        );
    }
    assert_eq!(state.cursor_blue_score, Some(99));
    assert_eq!(
        follower.store.load_state().await.unwrap().cursor_blue_score,
        Some(99)
    );
    let snapshot_sql="SELECT jsonb_build_object('actions',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM covenant_actions a),'utxos',(SELECT jsonb_agg(to_jsonb(u) ORDER BY txid,vout) FROM covenant_utxos u),'summaries',(SELECT jsonb_agg(to_jsonb(s) ORDER BY covenant_id) FROM covenant_action_summaries s))";
    let before: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT txid) FROM covenant_actions WHERE block_hash=decode($1,'hex')",
    )
    .bind(&block_hash)
    .fetch_one(&pool)
    .await
    .unwrap();
    if partial_prefix {
        assert!(
            count > 0 && count < 16 && (count as u64).is_power_of_two(),
            "fault must follow a committed budget-split prefix, got {count}"
        );
    } else {
        assert_eq!(count, 16, "lost acknowledgement follows the full commit");
    }
    let committed_count = count;
    // Build a fresh follower, not just a fresh in-memory cursor.
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        persister,
        pool.clone(),
        "commit-recovery-test",
        TipFollowerConfig {
            batch_size,
            overlap_windows: 1,
            max_catchup_windows: 1,
            window_fetch_concurrency: 3,
            ..Default::default()
        },
    )
    .unwrap();
    let original_source = source.lock().unwrap().clone();
    for scenario in 0..4 {
        let mut changed = original_source.clone();
        let tx = &mut changed[0]["transactions"][0];
        match scenario {
            0 => {
                tx["inputs"][0]["previous_outpoint_amount"] = serde_json::json!(
                    tx["inputs"][0]["previous_outpoint_amount"]
                        .as_u64()
                        .unwrap()
                        + 1
                )
            }
            1 => {
                tx["inputs"][0]["previous_outpoint_script"] =
                    serde_json::json!(format!("aa20{}87", "ee".repeat(32)))
            }
            2 => {
                tx["outputs"][0]["amount"] =
                    serde_json::json!(tx["outputs"][0]["amount"].as_u64().unwrap() + 1)
            }
            3 => {
                tx["outputs"][0]["script_public_key"] =
                    serde_json::json!(format!("aa20{}87", "ee".repeat(32)))
            }
            _ => unreachable!(),
        }
        *source.lock().unwrap() = changed;
        state = follower.store.load_state().await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(10), follower.run_once(&mut state))
            .await
            .unwrap()
            .err()
            .expect("changed immutable source evidence must retain cursor");
        assert!(
            error
                .downcast_ref::<tn12_indexer_db::persist::AcceptanceEvidenceConflict>()
                .is_some(),
            "scenario {scenario}: {error:#}"
        );
        assert_eq!(
            follower.store.load_state().await.unwrap().cursor_blue_score,
            Some(99)
        );
        let unchanged: serde_json::Value = sqlx::query_scalar(snapshot_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, unchanged);
    }
    *source.lock().unwrap() = original_source;
    if partial_prefix {
        sqlx::query("DELETE FROM test_later_prefix_failure")
            .execute(&pool)
            .await
            .unwrap();
    }
    // Restart from durable cursor rather than carrying an in-memory success.
    state = follower.store.load_state().await.unwrap();
    let recovered = tokio::time::timeout(Duration::from_secs(10), follower.run_once(&mut state))
        .await
        .unwrap()
        .unwrap();
    let expected_cursor = if batch_size == 100 { 199 } else { 109 };
    assert_eq!(state.cursor_blue_score, Some(expected_cursor));
    assert_eq!(
        follower.store.load_state().await.unwrap().cursor_blue_score,
        Some(expected_cursor)
    );
    assert_eq!(recovered.already_persisted_txs, committed_count as u64);
    let after: serde_json::Value = sqlx::query_scalar(snapshot_sql)
        .fetch_one(&pool)
        .await
        .unwrap();
    if !partial_prefix {
        assert_eq!(before, after);
    } else {
        let complete: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT txid) FROM covenant_actions WHERE block_hash=decode($1,'hex')",
        )
        .bind(&block_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(complete, 16);
        assert_eq!(recovered.persisted_txs, (16 - committed_count) as u64);
    }
    let windows: Vec<_> = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.starts_with("/virtual-chain?"))
        .cloned()
        .collect();
    assert_eq!(windows.len(), 6);
    assert!(windows.iter().all(|window| window == &windows[0]));
    if batch_size == 10 && !partial_prefix {
        let wide_follower = ChainTipFollower::new(
            RestClient::new(format!("http://{address}")).unwrap(),
            Arc::new(PgPersister::new(pool.clone()).with_generic_bulk_persist(true)),
            pool.clone(),
            "commit-recovery-test",
            TipFollowerConfig {
                batch_size: 100,
                overlap_windows: 1,
                max_catchup_windows: 1,
                window_fetch_concurrency: 3,
                ..Default::default()
            },
        )
        .unwrap();
        let mut state = wide_follower.store.load_state().await.unwrap();
        let widened = wide_follower.run_once(&mut state).await.unwrap();
        assert_eq!(state.cursor_blue_score, Some(199));
        assert_eq!(widened.persisted_txs, 0);
        let after_widening: serde_json::Value = sqlx::query_scalar(snapshot_sql)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(after, after_widening);
    }
    server.abort();
    eprintln!("TIP recovery partial_prefix={partial_prefix} batch_size={batch_size}: cursor99 retained, source conflicts rejected, fresh follower reused {committed_count} committed transactions and advanced cursor{expected_cursor}");
}
