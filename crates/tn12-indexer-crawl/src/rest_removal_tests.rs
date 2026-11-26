use super::*;
use tn12_indexer_core::{RestTxInput, RestTxOutput};
use tn12_indexer_db::PgPersister;

fn parent(id: u8, block: u8, score: u64) -> RestTransaction {
    RestTransaction {
        transaction_id: hex::encode([id; 32]),
        is_accepted: true,
        accepting_block_hash: Some(hex::encode([block; 32])),
        accepting_block_blue_score: Some(score),
        accepting_block_time: Some(score * 100),
        outputs: vec![RestTxOutput {
            transaction_id: hex::encode([id; 32]),
            index: 0,
            amount: 1000,
            script_public_key: format!("aa20{}87", hex::encode([id; 32])),
            ..Default::default()
        }],
        ..Default::default()
    }
}
fn child() -> RestTransaction {
    let mut tx = parent(0xbb, 0x33, 105);
    tx.version = 1;
    tx.inputs = vec![RestTxInput {
        previous_outpoint_hash: "aa".repeat(32),
        previous_outpoint_index: "0".into(),
        previous_outpoint_script: Some(format!("aa20{}87", "aa".repeat(32))),
        previous_outpoint_amount: Some(1000),
        ..Default::default()
    }];
    tx
}

async fn source(
    mode: &'static str,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let block_reads = reads.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            let block_request = request.contains("/blocks/");
            if block_request {
                block_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            let second = request.contains(&"22".repeat(32));
            let hash = if second || mode == "wrong_hash" {
                "22"
            } else {
                "11"
            }
            .repeat(32);
            let score = if mode == "wrong_score" {
                105
            } else if second {
                96
            } else {
                95
            };
            let canonical = matches!(mode, "canonical_empty" | "canonical_partial")
                || mode == "mixed" && second;
            let (status, body) = if request.contains("/info/health") {
                (
                    200,
                    serde_json::json!({"database":{"blueScore":105,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}}),
                )
            } else if block_request && mode == "missing" {
                (404, serde_json::json!({"error":"not found"}))
            } else if block_request {
                assert!(request
                    .to_ascii_lowercase()
                    .contains("cache-control: no-cache"));
                assert!(request.contains("source_observation="));
                (
                    200,
                    serde_json::json!({"header":{"blueScore":score,"timestamp":score*100,
                    "parents":[{"parentHashes":["44".repeat(32)]}],
                    "acceptedIdMerkleRoot":"55".repeat(32),"utxoCommitment":"66".repeat(32)},
                    "verboseData":{"hash":hash,"blueScore":score,"isChainBlock":canonical,
                    "selectedParentHash":"44".repeat(32)}}),
                )
            } else if mode == "canonical_partial" {
                (
                    200,
                    serde_json::json!([{"hash":"22".repeat(32),"blue_score":96,"timestamp":9600,"transactions":[]}]),
                )
            } else {
                (200, serde_json::json!([]))
            };
            let body = body.to_string();
            let age = if block_request && mode == "stale" {
                "Age: 10\r\n"
            } else {
                ""
            };
            let response = format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{age}Connection: close\r\n\r\n{body}",body.len());
            let response = crate::source_observation::fresh_test_response(response);
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (url, task, reads)
}

async fn check_window(pool: sqlx::PgPool, mode: &'static str) {
    let writer = Arc::new(PgPersister::new(pool.clone()));
    writer.persist_tx(&parent(0xaa, 0x11, 95)).await.unwrap();
    let mut hashes = BTreeSet::from(["11".repeat(32)]);
    if mode == "mixed" {
        writer.persist_tx(&parent(0xcc, 0x22, 96)).await.unwrap();
        hashes.insert("22".repeat(32));
    }
    let (url, server, reads) = source(mode).await;
    let follower = ChainTipFollower::new(
        RestClient::new(url).unwrap(),
        writer.clone(),
        pool.clone(),
        "removal-test",
        TipFollowerConfig {
            batch_size: 10,
            overlap_windows: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let snapshot = TipWindowSnapshot {
        window_start: 90,
        block_hashes: hashes.clone(),
        persisted_acceptances: BTreeSet::new(),
    };
    follower
        .store
        .commit_window(Some(&snapshot), 99, 90)
        .await
        .unwrap();
    let mut state = TipFollowerState {
        cursor_blue_score: Some(99),
        windows: BTreeMap::from([(90, snapshot)]),
    };
    let result = follower.run_once(&mut state).await;
    server.abort();
    assert!(
        reads.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "must reach block evidence verification"
    );
    if mode == "noncanonical" {
        assert_eq!(result.unwrap().removed_blocks, 1);
        assert!(!writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
        assert!(state.windows[&90].block_hashes.is_empty());
    } else {
        let error = result.unwrap_err();
        let expected = match mode {
            "canonical_empty" | "canonical_partial" | "mixed" => "still-canonical block",
            "missing" => "orphan block requires node evidence",
            "wrong_hash" => "block proof returned a different hash",
            "wrong_score" => "REST removal block identity disagrees with window",
            "stale" => "cached source health response",
            _ => unreachable!(),
        };
        assert!(
            format!("{error:#}").contains(expected),
            "unexpected error for {mode}: {error:#}"
        );
        assert_eq!(state.cursor_blue_score, Some(99));
        assert_eq!(state.windows[&90].block_hashes, hashes);
        assert!(writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
        if mode == "mixed" {
            assert!(writer.has_utxo(&"cc".repeat(32), 0).await.unwrap());
        }
        let loaded = follower.store.load_state().await.unwrap();
        assert_eq!(loaded.cursor_blue_score, Some(99));
        assert_eq!(loaded.windows[&90].block_hashes, hashes);
        writer.persist_tx(&child()).await.unwrap();
        assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    }
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn empty_rest_page_preserves_canonical_parent(pool: sqlx::PgPool) {
    check_window(pool, "canonical_empty").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn partial_rest_page_preserves_canonical_parent(pool: sqlx::PgPool) {
    check_window(pool, "canonical_partial").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn all_removals_verified_before_first_mutation(pool: sqlx::PgPool) {
    check_window(pool, "mixed").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn missing_block_evidence_preserves_parent(pool: sqlx::PgPool) {
    check_window(pool, "missing").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn mismatched_block_identity_preserves_parent(pool: sqlx::PgPool) {
    check_window(pool, "wrong_hash").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn out_of_window_block_preserves_parent(pool: sqlx::PgPool) {
    check_window(pool, "wrong_score").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn cached_block_evidence_preserves_parent(pool: sqlx::PgPool) {
    check_window(pool, "stale").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn explicit_noncanonical_block_can_be_removed(pool: sqlx::PgPool) {
    check_window(pool, "noncanonical").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn unverified_rollback_reproduces_missing_parent(pool: sqlx::PgPool) {
    let writer = PgPersister::new(pool);
    writer.persist_tx(&parent(0xaa, 0x11, 95)).await.unwrap();
    writer.revert_block(&[0x11; 32]).await.unwrap();
    let error = writer.persist_tx(&child()).await.unwrap_err();
    assert!(error.is::<tn12_indexer_db::persist::identity::MissingIdentityDependency>());
}

#[derive(Debug)]
struct NodeProof {
    canonical: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
#[async_trait::async_trait]
impl crate::rest_replay_fence::CanonicalVerifier for NodeProof {
    async fn verify(&self, blocks: &[(Vec<u8>, u64)]) -> Result<()> {
        self.calls
            .fetch_add(blocks.len(), std::sync::atomic::Ordering::SeqCst);
        anyhow::ensure!(self.canonical, "node says removed");
        Ok(())
    }
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn removed_acceptance_needs_node_proof_and_stable_revision(pool: sqlx::PgPool) {
    let writer = PgPersister::new(pool.clone());
    let tx = parent(0xaa, 0x11, 95);
    writer.revert_block(&[0x11; 32]).await.unwrap();
    let (url, server, rest_reads) = source("canonical_empty").await;
    let mut rest = RestClient::new(url).unwrap();
    rest.canonical_verifier = None;
    assert!(
        crate::rest_replay_fence::for_transactions(&writer, &rest, &[tx.clone()])
            .await
            .is_err()
    );
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    rest.canonical_verifier = Some(Arc::new(NodeProof {
        canonical: false,
        calls: calls.clone(),
    }));
    assert!(
        crate::rest_replay_fence::for_transactions(&writer, &rest, &[tx.clone()])
            .await
            .is_err(),
        "fresh-but-lagging REST must not override a node removal"
    );
    assert!(!writer.has_utxo(&tx.transaction_id, 0).await.unwrap());
    calls.store(0, std::sync::atomic::Ordering::SeqCst);
    rest.canonical_verifier = Some(Arc::new(NodeProof {
        canonical: true,
        calls: calls.clone(),
    }));
    let admitted =
        crate::rest_replay_fence::for_transactions(&writer, &rest, &vec![tx.clone(); 1000])
            .await
            .unwrap();
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one proof per distinct hash"
    );
    assert_eq!(
        rest_reads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "REST cannot renew removed hashes"
    );
    admitted.persist_tx(&tx).await.unwrap();
    writer.revert_block(&[0x11; 32]).await.unwrap();
    assert!(admitted
        .persist_tx(&tx)
        .await
        .unwrap_err()
        .is::<tn12_indexer_db::persist::StaleRestAcceptance>());
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn stale_rest_observation_cannot_interrupt_live_replacement(pool: sqlx::PgPool) {
    let writer = PgPersister::new(pool).with_bounded_writer_lock_wait();
    let old = parent(0xaa, 0x11, 95);
    writer.persist_tx(&old).await.unwrap();
    let (url, server, reads) = source("noncanonical").await;
    let rest = RestClient::new(url).unwrap();
    let stale = crate::rest_replay_fence::for_transactions(&writer, &rest, &[old.clone()])
        .await
        .unwrap();
    assert_eq!(
        reads.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "unremoved blocks need no extra network lookup"
    );
    writer.revert_block(&[0x11; 32]).await.unwrap();
    assert!(stale
        .persist_batch(&[old])
        .await
        .unwrap_err()
        .is::<tn12_indexer_db::persist::StaleRestAcceptance>());
    writer.persist_tx(&parent(0xaa, 0x22, 96)).await.unwrap();
    server.abort();
}
