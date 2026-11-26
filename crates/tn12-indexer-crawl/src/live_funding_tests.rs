//! Real writer/journal regressions for the optional funding metadata preparation.
use super::*;
use crate::live_recovery::{LiveWriteJournal, PgLiveWriteJournal};
use std::sync::atomic::{AtomicUsize, Ordering};
use tn12_indexer_db::PgPersister;

fn transactions() -> (RestTransaction, RestTransaction) {
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
            script_public_key: format!("20{}ac", "44".repeat(32)),
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
            script_public_key: format!("aa20{}87", "33".repeat(32)),
            ..Default::default()
        }],
        ..Default::default()
    };
    (parent, child)
}

async fn run(pool: sqlx::PgPool, scenario: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut parent, mut child) = transactions();
    match scenario {
        "wrong_id" => parent.transaction_id = "77".repeat(32),
        "covenant_parent" => {
            parent.outputs[0].script_public_key = format!("aa20{}87", "88".repeat(32))
        }
        "unaccepted" => parent.is_accepted = false,
        "conflicting_metadata" => child.inputs[0].previous_outpoint_amount = Some(999),
        "invalid_script" => parent.outputs[0].script_public_key = String::new(),
        "already_known" => {
            child.inputs[0].previous_outpoint_script =
                Some(parent.outputs[0].script_public_key.clone())
        }
        "too_many" => {
            for n in 1..=8 {
                child.inputs.push(RestTxInput {
                    previous_outpoint_hash: format!("{n:064x}"),
                    previous_outpoint_index: "0".into(),
                    ..Default::default()
                });
            }
        }
        _ => {}
    }
    let delayed = scenario == "timeout";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let n = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..n])
                .contains(&format!("GET /transactions/{}?", "11".repeat(32))));
            count.fetch_add(1, Ordering::SeqCst);
            if delayed {
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            let body = serde_json::to_string(&parent).unwrap();
            let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body);
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    let journal = Arc::new(PgLiveWriteJournal::new(
        pool.clone(),
        "testnet-10",
        "funding-test",
    ));
    let watcher = WrpcVirtualChainWatcher::new(
        Arc::new(PgPersister::new(pool.clone())),
        Box::new(crate::PgCursorStore::with_key(pool.clone(), "reorg")),
        Box::new(crate::PgCursorStore::with_key(pool.clone(), "live")),
        Box::new(crate::PgCursorStore::with_key(pool.clone(), "heartbeat")),
        WrpcWatcherConfig::with_default_cache("ws://unused".into(), "testnet-10".into()),
    )
    .with_write_journal(journal.clone())
    .with_funding_metadata_source(crate::RestClient::new(format!("http://{address}")).unwrap());
    let began = Instant::now();
    let result = watcher
        .persist_candidates(vec![child.clone()], &mut WrpcWatcherStats::default())
        .await;
    if matches!(scenario, "funding" | "already_known") {
        assert!(
            result.is_ok(),
            "available plain funding metadata must not force a whole live recovery: {result:?}"
        );
        assert!(journal.load().await.unwrap().is_none());
        let actions: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1")
                .bind(hex::decode(&child.transaction_id).unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(actions > 0);
    } else {
        assert!(result
            .unwrap_err()
            .is::<tn12_indexer_db::persist::identity::MissingIdentityDependency>());
        let retained = journal.load().await.unwrap().unwrap();
        assert_eq!(
            retained.transactions[0].inputs[0].previous_outpoint_script,
            None
        );
        assert_eq!(
            retained.transactions[0].inputs[0].previous_outpoint_amount,
            child.inputs[0].previous_outpoint_amount
        );
    }
    assert_eq!(
        requests.load(Ordering::SeqCst),
        usize::from(!matches!(scenario, "already_known" | "too_many"))
    );
    if delayed {
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "metadata must not stall the ordered writer"
        );
    }
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn available_funding_parent_avoids_live_recovery(pool: sqlx::PgPool) {
    run(pool, "funding").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn wrong_parent_identity_retains_journal(pool: sqlx::PgPool) {
    run(pool, "wrong_id").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn covenant_parent_still_requires_canonical_recovery(pool: sqlx::PgPool) {
    run(pool, "covenant_parent").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn unaccepted_funding_parent_retains_journal(pool: sqlx::PgPool) {
    run(pool, "unaccepted").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn funding_metadata_conflict_retains_journal(pool: sqlx::PgPool) {
    run(pool, "conflicting_metadata").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn slow_funding_source_is_bounded(pool: sqlx::PgPool) {
    run(pool, "timeout").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn invalid_funding_script_retains_journal(pool: sqlx::PgPool) {
    run(pool, "invalid_script").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn known_funding_metadata_does_not_contact_rest(pool: sqlx::PgPool) {
    run(pool, "already_known").await;
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn excessive_funding_dependencies_retain_journal_without_fetch(pool: sqlx::PgPool) {
    run(pool, "too_many").await;
}
