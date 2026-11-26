use super::*;
use crate::live_recovery::{LiveWriteJournal, LiveWriteWindow};
struct Journal {
    events: Arc<Mutex<Vec<String>>>,
    fail: bool,
    expected_block: Option<String>,
    expect_descendant: bool,
}
#[async_trait::async_trait]
impl LiveWriteJournal for Journal {
    async fn load(&self) -> Result<Option<LiveWriteWindow>> {
        unreachable!()
    }
    async fn begin(&self, _: &LiveWriteWindow) -> Result<()> {
        unreachable!()
    }
    async fn complete(&self, _: &LiveWriteWindow) -> Result<()> {
        unreachable!()
    }
    async fn replace(&self, _: &LiveWriteWindow, updated: &LiveWriteWindow) -> Result<()> {
        assert!(!updated.observed_blocks.is_empty());
        updated.validate().unwrap();
        let reloaded: LiveWriteWindow = serde_json::from_value(serde_json::to_value(updated).unwrap()).unwrap();
        reloaded.validate().unwrap();
        if self.expect_descendant {
            let bodies: Vec<_> = reloaded.transactions.iter().chain(&reloaded.rejected_transactions).collect();
            assert_eq!(bodies.iter().filter(|tx| tx.transaction_id == "11".repeat(32)).count(), 1);
            assert_eq!(bodies.iter().filter(|tx| tx.transaction_id == "99".repeat(32)).count(), 1);
            assert!(bodies.iter().all(|tx| !tx.outputs.is_empty()));
            assert!(reloaded.observed_blocks.values().any(|hashes| hashes.contains(&"33".repeat(32))));
        }
        if let Some(hash) = &self.expected_block {
            assert!(updated.observed_blocks.values().any(|blocks| blocks.contains(hash)));
        }
        self.events.lock().unwrap().push("journal".into());
        anyhow::ensure!(!self.fail, "injected journal failure");
        Ok(())
    }
}
use std::sync::Mutex;
use tn12_indexer_core::{RestTransaction, RestTxInput, RestTxOutput};
use tn12_indexer_db::{PersistStats, RevertStats};

#[derive(Default)]
struct RepairProbe(
    Arc<Mutex<Vec<String>>>,
    Option<tn12_indexer_db::persist::PersistedInputSpend>,
    bool,
    bool,
);
#[async_trait::async_trait]
impl Persister for RepairProbe {
    async fn indexed_block_transaction_ids(&self, _: &str) -> Result<Vec<String>> {
        anyhow::ensure!(!self.3, "removed block has indexed descendant spends");
        if self.2 { return Ok(vec!["11".repeat(32)]); }
        if self.1.is_none() { return Ok(Vec::new()); }
        let mut ids = vec![if self.1.as_ref().is_some_and(|conflict| conflict.spender_txid == "11".repeat(32)) {
            "11".repeat(32)
        } else {
            "77".repeat(32)
        }];
        if self.1.as_ref().is_some_and(|conflict| conflict.block_blue_score == 108) {
            ids.push("99".repeat(32));
        }
        Ok(ids)
    }
    async fn recovery_block_impact(&self, hash: &str) -> Result<tn12_indexer_db::persist::RecoveryBlockImpact> {
        use tn12_indexer_db::persist::RecoveryBlockImpact;
        if self.3 {
            return Ok(if hash == "66".repeat(32) {
                RecoveryBlockImpact { block_hash: hash.into(), transaction_ids: vec!["11".repeat(32)], descendants: vec!["33".repeat(32)] }
            } else {
                assert_eq!(hash, "33".repeat(32));
                RecoveryBlockImpact { block_hash: hash.into(), transaction_ids: vec!["99".repeat(32)], descendants: vec![] }
            });
        }
        Ok(RecoveryBlockImpact { block_hash: hash.into(), transaction_ids: self.indexed_block_transaction_ids(hash).await?, descendants: vec![] })
    }
    async fn revert_recovery_blocks(&self, impacts: &[tn12_indexer_db::persist::RecoveryBlockImpact]) -> Result<Vec<RevertStats>> {
        if self.3 { assert_eq!(impacts.iter().map(|i| i.block_hash.clone()).collect::<Vec<_>>(), vec!["33".repeat(32), "66".repeat(32)]); }
        let mut stats=Vec::new();
        for impact in impacts { stats.push(self.revert_block(&hex::decode(&impact.block_hash)?).await?); }
        Ok(stats)
    }
    async fn conflicting_input_spends(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Vec<tn12_indexer_db::persist::PersistedInputSpend>> {
        if self.1.as_ref().is_some_and(|conflict| conflict.spender_txid == "77".repeat(32)) {
            assert_eq!(txs.len(), 1);
            assert_eq!(txs[0].inputs[0].previous_outpoint_hash, "88".repeat(32));
        }
        Ok(self.1.clone().filter(|conflict| conflict.spender_txid == "77".repeat(32)).into_iter().collect())
    }
    async fn stale_persisted_acceptances(
        &self,
        _: &[RestTransaction],
    ) -> Result<Vec<tn12_indexer_db::persist::PersistedInputSpend>> {
        Ok(self.1.clone().filter(|conflict| conflict.spender_txid == "11".repeat(32)).into_iter().collect())
    }
    async fn persist_tx(&self, tx: &RestTransaction) -> Result<PersistStats> {
        self.0.lock().unwrap().push(format!(
            "persist:{}",
            tx.accepting_block_hash.as_deref().unwrap()
        ));
        Ok(PersistStats::default())
    }
    async fn revert_block(&self, hash: &[u8]) -> Result<RevertStats> {
        self.0
            .lock()
            .unwrap()
            .push(format!("revert:{}", hex::encode(hash)));
        Ok(RevertStats::default())
    }
    async fn has_utxo(&self, _: &str, _: i32) -> Result<bool> {
        Ok(false)
    }
}

async fn scenario(mode: &str) -> (Result<()>, Vec<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let original = RestTransaction {
        transaction_id: "11".repeat(32),
        is_accepted: true,
        accepting_block_hash: Some("22".repeat(32)),
        accepting_block_blue_score: Some(105),
        accepting_block_time: Some(1000),
        inputs: if mode.starts_with("competing-spend") {
            vec![RestTxInput {
                previous_outpoint_hash: "88".repeat(32),
                previous_outpoint_index: "0".into(),
                ..Default::default()
            }]
        } else {
            vec![]
        },
        outputs: vec![RestTxOutput {
            transaction_id: "11".repeat(32),
            index: 0,
            amount: 1,
            script_public_key: format!("aa20{}87", "44".repeat(32)),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut intent = LiveWriteWindow::new(&[original.clone()]).unwrap();
    if mode.starts_with("reorg-only") {
        intent.transactions.clear();
        intent.window_width = Some(if mode == "reorg-only-width-changed" {
            100
        } else {
            10
        });
        intent
            .observed_blocks
            .insert(100, BTreeSet::from(["22".repeat(32)]));
        if mode == "reorg-only-membership-change" {
            intent.observed_blocks.get_mut(&100).unwrap().insert("44".repeat(32));
        }
    }
    if mode.starts_with("legacy-width") {
        intent
            .observed_blocks
            .insert(100, BTreeSet::from(["22".repeat(32)]));
        intent.window_width = None;
    }
    let mut current = original;
    if mode == "reorg-only-moved" || mode == "reorg-only-membership-change" {
        current.accepting_block_hash = Some("33".repeat(32));
    }
    if mode == "moved" {
        current.accepting_block_hash = Some("33".repeat(32));
        current.accepting_block_blue_score = Some(125);
    }
    if mode == "rejected" {
        current.is_accepted = false;
        current.accepting_block_hash = None;
        current.accepting_block_blue_score = None;
    }
    let fail_journal = mode == "journal-failure" || mode == "descendant-journal-failure";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let omitted = mode == "omitted";
    let server_mode = mode.to_owned();
    let server = tokio::spawn(async move {
        let mode = server_mode;
        let mut lookups = 0;
        let mut virtual_reads = 0;
        let mut child_lookups = 0;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let n = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            let body = if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore": if mode == "unpublished" {108} else if mode == "descendant-unpublished" {120} else {150},"isSynced":true,"acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/blocks/") {
                assert!(mode.starts_with("legacy-width") || mode.starts_with("competing-spend")
                    || (mode == "acceptance-mismatch" || mode.starts_with("descendant")) || mode.starts_with("reorg-only")
                    || matches!(mode.as_str(), "moved" | "rejected" | "omitted" | "reaccepted"));
                let requested_old = request.contains(&"66".repeat(32));
                let child = mode.starts_with("descendant") && request.contains(&"33".repeat(32));
                let score = if child { 125 } else if requested_old && (mode == "acceptance-mismatch" || mode.starts_with("descendant")) {
                    106
                } else if mode == "legacy-width-too-small" {
                    195
                } else if mode == "reorg-only-last-score" {
                    109
                } else if mode == "competing-spend-wrong-score" {
                    107
                } else if mode == "competing-spend-later" {
                    126
                } else if mode == "competing-spend-sibling-moved" {
                    108
                } else if mode.starts_with("competing-spend") {
                    106
                } else {
                    105
                };
                let hash = if child { "33".repeat(32) } else if requested_old || mode.starts_with("competing-spend") {
                    "66".repeat(32)
                } else {
                    "22".repeat(32)
                };
                serde_json::json!({
                    "header":{"blueScore":score,"timestamp":1000,"parents":[{"parentHashes":["33".repeat(32)]}],
                        "acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":hash,"blueScore":score,
                        "isChainBlock":(child && mode != "descendant-rejected") || !(requested_old || mode.starts_with("competing-spend")
                            || mode.starts_with("reorg-only") || matches!(mode.as_str(), "moved" | "rejected" | "omitted" | "reaccepted"))
                            || mode == "competing-spend-still-canonical",
                        "selectedParentHash":"33".repeat(32)}
                })
            } else if mode.starts_with("competing-spend")
                && request.contains(&format!("/transactions/{}", "77".repeat(32)))
            {
                let mut prior = current.clone();
                prior.transaction_id = "77".repeat(32);
                prior.outputs[0].transaction_id = prior.transaction_id.clone();
                prior.is_accepted = mode == "competing-spend-still-accepted";
                if !prior.is_accepted {
                    prior.accepting_block_hash = None;
                    prior.accepting_block_blue_score = None;
                    prior.accepting_block_time = None;
                }
                serde_json::to_value(prior).unwrap()
            } else if mode == "competing-spend-sibling-moved"
                && request.contains(&format!("/transactions/{}", "99".repeat(32)))
            {
                let mut sibling = current.clone();
                sibling.transaction_id = "99".repeat(32);
                sibling.outputs[0].transaction_id = sibling.transaction_id.clone();
                sibling.accepting_block_hash = Some("33".repeat(32));
                sibling.accepting_block_blue_score = Some(125);
                serde_json::to_value(sibling).unwrap()
            } else if mode.starts_with("descendant") && request.contains(&format!("/transactions/{}", "99".repeat(32))) {
                let mut child = current.clone();
                child.transaction_id = "99".repeat(32);
                child.outputs[0].transaction_id = child.transaction_id.clone();
                child.accepting_block_hash = Some("33".repeat(32));
                child.accepting_block_blue_score = Some(125);
                child_lookups += 1;
                if mode == "descendant-rejected" {
                    child.is_accepted = false;
                    child.accepting_block_hash = None;
                    child.accepting_block_blue_score = None;
                    child.accepting_block_time = None;
                }
                if mode == "descendant-changing" && child_lookups > 1 {
                    child.accepting_block_hash = Some("55".repeat(32));
                }
                serde_json::to_value(child).unwrap()
            } else if request.contains("/transactions/") {
                lookups += 1;
                assert!(
                    mode != "bulk-only" || lookups <= 1,
                    "unexpected REST request: {request}"
                );
                let mut tx = current.clone();
                if mode == "changed" && virtual_reads > 1 {
                    tx.accepting_block_hash = Some("55".repeat(32));
                }
                if mode == "reaccepted" && lookups == 1 {
                    tx.is_accepted = false;
                }
                let mut value = serde_json::to_value(tx).unwrap();
                if mode == "implicit" {
                    value.as_object_mut().unwrap().remove("is_accepted");
                }
                value
            } else if request.contains("/virtual-chain?") {
                virtual_reads += 1;
                let start = if request.contains("blueScoreGte=120") {
                    120
                } else {
                    100
                };
                if mode.starts_with("reorg-only") {
                    if mode == "reorg-only-membership-change" {
                        let mut blocks = vec![serde_json::json!({"hash":current.accepting_block_hash,"blue_score":105,"daa_score":105,"timestamp":1000,"transactions":[current]})];
                        if virtual_reads == 1 {
                            blocks.push(serde_json::json!({"hash":"44".repeat(32),"blue_score":106,"daa_score":106,"timestamp":1000,"transactions":[]}));
                        }
                        serde_json::json!(blocks)
                    } else if mode == "reorg-only-moved" {
                        serde_json::json!([{"hash":current.accepting_block_hash,"blue_score":105,"daa_score":105,"timestamp":1000,"transactions":[current]}])
                    } else if mode == "reorg-only-changing" && virtual_reads > 1 {
                        serde_json::json!([{"hash":"55".repeat(32),"blue_score":105,"daa_score":105,"timestamp":1000,"transactions":[]}])
                    } else {
                        serde_json::json!([])
                    }
                } else if mode == "unrelated-block-change" && virtual_reads > 1 {
                    serde_json::json!([
                        {"hash":current.accepting_block_hash,"blue_score":105,"daa_score":105,"timestamp":1000,"transactions":[current]},
                        {"hash":"55".repeat(32),"blue_score":106,"daa_score":106,"timestamp":1000,"transactions":[]}
                    ])
                } else if mode == "omitted"
                    || mode == "rejected"
                    || mode == "implicit"
                    || (mode == "reaccepted" && virtual_reads == 1)
                    || (mode == "moved" && start == 100)
                    || (mode == "competing-spend-later" && start == 120)
                    || (mode == "descendant-rejected" && start == 120)
                {
                    serde_json::json!([])
                } else {
                    let mut page_tx = current.clone();
                    if (mode == "competing-spend-sibling-moved" || mode.starts_with("descendant")) && start == 120 {
                        page_tx.transaction_id = "99".repeat(32);
                        page_tx.outputs[0].transaction_id = page_tx.transaction_id.clone();
                        page_tx.accepting_block_hash = Some("33".repeat(32));
                        page_tx.accepting_block_blue_score = Some(125);
                    }
                    if mode == "changed" && virtual_reads > 1 {
                        page_tx.accepting_block_hash = Some("55".repeat(32));
                    }
                    let mut transactions = vec![page_tx.clone()];
                    if mode == "unrelated-candidates" {
                        let mut unrelated = page_tx.clone();
                        unrelated.transaction_id = "99".repeat(32);
                        unrelated.outputs[0].transaction_id = unrelated.transaction_id.clone();
                        transactions.push(unrelated);
                    }
                    serde_json::json!([{"hash":page_tx.accepting_block_hash,"blue_score":page_tx.accepting_block_blue_score,
                        "daa_score":page_tx.accepting_block_blue_score,"timestamp":1000,"transactions":transactions}])
                }
            } else {
                panic!("unexpected REST request: {request}")
            };
            let body = body.to_string();
            stream.write_all(crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body)).as_bytes()).await.unwrap();
        }
    });
    let conflict = (mode.starts_with("competing-spend") || (mode == "acceptance-mismatch" || mode.starts_with("descendant"))).then_some(
        tn12_indexer_db::persist::PersistedInputSpend {
            spender_txid: if (mode == "acceptance-mismatch" || mode.starts_with("descendant")) { "11".repeat(32) } else { "77".repeat(32) },
            block_hash: "66".repeat(32),
            block_blue_score: if mode == "competing-spend-later" { 126 } else if mode == "competing-spend-sibling-moved" { 108 } else { 106 },
        },
    );
    let probe = Arc::new(RepairProbe(Arc::new(Mutex::new(Vec::new())), conflict,
        mode == "reorg-only-moved" || mode == "reorg-only-membership-change", mode.starts_with("descendant")));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        probe.clone(),
        pool,
        "unused-repair-cursor",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let original_intent = serde_json::to_value(&intent).unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        follower.recover_live_window(
            &mut intent,
            &Journal {
                events: probe.0.clone(),
                fail: fail_journal,
                expect_descendant: mode.starts_with("descendant"),
                expected_block: if mode == "reorg-only-moved" { Some("22".repeat(32)) }
                    else { (mode.starts_with("competing-spend") || (mode == "acceptance-mismatch" || mode.starts_with("descendant"))).then(|| "66".repeat(32)) },
            },
        ),
    )
    .await
    .unwrap();
    if omitted {
        assert_eq!(serde_json::to_value(&intent).unwrap(), original_intent);
    }
    server.abort();
    let events = probe.0.lock().unwrap().clone();
    (result, events)
}

#[tokio::test]
async fn live_recovery_replays_same_acceptance_without_cursor_access() {
    let (result, events) = scenario("bulk-only").await;
    result.unwrap();
    assert_eq!(
        events,
        vec!["journal".into(), format!("persist:{}", "22".repeat(32))]
    );
}
#[tokio::test]
async fn live_recovery_does_not_replay_unrelated_page_transactions() {
    let (result, events) = scenario("unrelated-candidates").await;
    result.unwrap();
    assert_eq!(events, vec![
        "journal".to_owned(),
        format!("persist:{}", "22".repeat(32)),
    ]);
}
#[tokio::test]
async fn reorg_only_recovery_replays_indexed_transaction_in_replacement_block() {
    let (result, events) = scenario("reorg-only-moved").await;
    result.unwrap();
    assert_eq!(events, vec![
        "journal".to_owned(),
        format!("revert:{}", "22".repeat(32)),
        format!("persist:{}", "33".repeat(32)),
    ]);
}
#[tokio::test]
async fn reorg_only_recovery_accepts_removed_block_at_last_score_of_window() {
    let (result, events) = scenario("reorg-only-last-score").await;
    result.unwrap();
    assert_eq!(events, vec![
        "journal".to_owned(),
        format!("revert:{}", "22".repeat(32)),
    ]);
}
#[tokio::test]
async fn recovery_stops_before_revert_if_page_changes_after_impact_discovery() {
    let (result, events) = scenario("reorg-only-membership-change").await;
    assert!(result.is_err());
    assert!(events.is_empty());
}
#[tokio::test]
async fn live_recovery_follows_reorg_into_another_score_window() {
    let (result, events) = scenario("moved").await;
    result.unwrap();
    assert_eq!(
        events,
        vec![
            "journal".into(),
            format!("revert:{}", "22".repeat(32)),
            format!("persist:{}", "33".repeat(32))
        ]
    );
}
#[tokio::test]
async fn live_recovery_reverts_unjournaled_competing_spend_before_replay() {
    let (result, events) = scenario("competing-spend").await;
    result.unwrap();
    assert_eq!(
        events,
        vec![
            "journal".to_owned(),
            format!("revert:{}", "66".repeat(32)),
            format!("persist:{}", "22".repeat(32)),
        ]
    );
}
#[tokio::test]
async fn live_recovery_reverts_stale_accepting_block_for_same_transaction() {
    let (result, events) = scenario("acceptance-mismatch").await;
    result.unwrap();
    assert_eq!(events, vec![
        "journal".to_owned(),
        format!("revert:{}", "66".repeat(32)),
        format!("persist:{}", "22".repeat(32)),
    ]);
}
#[tokio::test]
async fn live_recovery_reverts_later_competing_window_before_earlier_replay() {
    let (result, events) = scenario("competing-spend-later").await;
    result.unwrap();
    assert_eq!(events, vec![
        "journal".to_owned(),
        format!("revert:{}", "66".repeat(32)),
        format!("persist:{}", "22".repeat(32)),
    ]);
}
#[tokio::test]
async fn live_recovery_replays_sibling_moved_to_another_window() {
    let (result, events) = scenario("competing-spend-sibling-moved").await;
    result.unwrap();
    assert_eq!(events, vec![
        "journal".to_owned(),
        format!("revert:{}", "66".repeat(32)),
        format!("persist:{}", "22".repeat(32)),
        format!("persist:{}", "33".repeat(32)),
    ]);
}
#[tokio::test]
async fn live_recovery_keeps_intent_when_competing_spend_is_not_proven_removed() {
    for mode in [
        "competing-spend-still-canonical",
        "competing-spend-still-accepted",
        "competing-spend-wrong-score",
    ] {
        let (result, events) = scenario(mode).await;
        assert!(result.is_err(), "{mode}");
        assert!(events.is_empty(), "{mode} changed database or journal");
    }
}
#[tokio::test]
async fn live_recovery_rejects_missing_or_unpublished_source_before_writes() {
    for mode in ["omitted", "unpublished", "implicit"] {
        let (result, events) = scenario(mode).await;
        assert!(result.is_err(), "{mode}");
        assert!(events.is_empty(), "{mode}");
    }
}

#[tokio::test]
async fn live_recovery_omitted_page_retries_without_restart_or_intent_loss() {
    use crate::live_supervisor::{supervise, LiveRuntime};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Runtime(AtomicUsize);
    #[async_trait::async_trait(?Send)]
    impl LiveRuntime for Runtime {
        async fn pending(&self) -> Result<bool> {
            Ok(self.0.load(Ordering::SeqCst) < 2)
        }
        async fn recover(&self) -> Result<()> {
            let attempt = self.0.fetch_add(1, Ordering::SeqCst);
            let (result, events) =
                scenario(if attempt == 0 { "omitted" } else { "bulk-only" }).await;
            if attempt == 0 {
                assert!(
                    events.is_empty(),
                    "incomplete evidence must not write or replace the intent"
                );
                assert_eq!(
                    crate::recovery_policy::classify(result.as_ref().unwrap_err()),
                    crate::recovery_policy::Decision::Retry("source_pending")
                );
            } else {
                result.as_ref().expect("complete source evidence must recover");
                assert_eq!(
                    events,
                    vec!["journal".to_owned(), format!("persist:{}", "22".repeat(32))]
                );
            }
            result
        }
        async fn watch(&self) -> Result<()> {
            assert_eq!(self.0.load(Ordering::SeqCst), 2);
            Ok(())
        }
        async fn state(&self, _: &str, _: Option<&str>) -> Result<()> {
            Ok(())
        }
    }
    let runtime = Runtime(AtomicUsize::new(0));
    tokio::time::timeout(Duration::from_secs(5), supervise(&runtime, Duration::ZERO))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runtime.0.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn live_recovery_rejects_source_changes_during_replay() {
    let (result, _) = scenario("changed").await;
    assert!(result.unwrap_err().to_string().contains("source changed"));
}

#[tokio::test]
async fn live_recovery_rejects_reacceptance_after_explicit_rejection() {
    let (result, _) = scenario("reaccepted").await;
    assert!(result.unwrap_err().to_string().contains("source changed"));
}

#[tokio::test]
async fn live_recovery_records_intent_before_mutation_and_handles_rejection() {
    let (result, events) = scenario("journal-failure").await;
    assert!(result.unwrap_err().to_string().contains("journal failure"));
    assert_eq!(events, vec!["journal"]);
    let (result, events) = scenario("rejected").await;
    result.unwrap();
    assert_eq!(
        events,
        vec!["journal".into(), format!("revert:{}", "22".repeat(32))]
    );
}

#[tokio::test]
async fn live_recovery_fetches_intent_transactions_concurrently_in_order() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let first_id = "11".repeat(32);
    let second_id = "22".repeat(32);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let both_requested = Arc::new(tokio::sync::Barrier::new(2));
    let server = tokio::spawn({
        let first_id = first_id.clone();
        let second_id = second_id.clone();
        async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let barrier = both_requested.clone();
                let first_id = first_id.clone();
                let second_id = second_id.clone();
                tokio::spawn(async move {
                    let mut request = [0; 4096];
                    let n = stream.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..n]);
                    let id = if request.contains(&first_id) {
                        first_id
                    } else {
                        assert!(request.contains(&second_id));
                        second_id
                    };
                    barrier.wait().await;
                    if id.starts_with("11") {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    let body = serde_json::to_string(&RestTransaction {
                        transaction_id: id,
                        is_accepted: false,
                        ..Default::default()
                    })
                    .unwrap();
                    stream
                        .write_all(crate::source_observation::fresh_test_response(format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )).as_bytes())
                        .await
                        .unwrap();
                });
            }
        }
    });
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    let follower = ChainTipFollower::new(
        RestClient::new(format!("http://{address}")).unwrap(),
        Arc::new(RepairProbe::default()),
        pool,
        "unused-repair-cursor",
        TipFollowerConfig {
            hydrate_concurrency: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let originals = [
        RestTransaction {
            transaction_id: first_id.clone(),
            ..Default::default()
        },
        RestTransaction {
            transaction_id: second_id.clone(),
            ..Default::default()
        },
    ];
    let fetched = tokio::time::timeout(
        Duration::from_secs(5),
        follower.fetch_current_acceptances(&originals),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(fetched[0].transaction_id, first_id);
    assert_eq!(fetched[1].transaction_id, second_id);
    server.await.unwrap();
}

#[tokio::test]
async fn live_recovery_reorg_only_intent_rechecks_its_window() {
    let (result, events) = scenario("reorg-only").await;
    result.unwrap();
    assert_eq!(
        events,
        vec!["journal".to_owned(), format!("revert:{}", "22".repeat(32))]
    );
    let (result, _) = scenario("reorg-only-changing").await;
    assert!(result.unwrap_err().to_string().contains("source changed"));
}

#[tokio::test]
async fn live_recovery_checks_unrelated_blocks_in_affected_windows() {
    let (result, _) = scenario("unrelated-block-change").await;
    assert!(result.unwrap_err().to_string().contains("source changed"));
}

#[tokio::test]
async fn live_recovery_rejects_a_smaller_restart_window_before_mutation() {
    let (result, events) = scenario("reorg-only-width-changed").await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("window width changed"));
    assert!(events.is_empty());
}

#[tokio::test]
async fn legacy_recovery_proves_each_recorded_hash_fits_the_read_window() {
    let (result, events) = scenario("legacy-width-ok").await;
    result.unwrap();
    assert_eq!(
        events,
        vec!["journal".to_owned(), format!("persist:{}", "22".repeat(32))]
    );
    let (result, events) = scenario("legacy-width-too-small").await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("outside current window"));
    assert!(events.is_empty());
}

#[tokio::test]
async fn recovery_replays_still_canonical_descendant_after_parent_acceptance_moves() {
    let (result, events) = scenario("descendant").await;
    result.unwrap();
    assert_eq!(events, vec!["journal".to_owned(), format!("revert:{}", "33".repeat(32)),
        format!("revert:{}", "66".repeat(32)), format!("persist:{}", "22".repeat(32)),
        format!("persist:{}", "33".repeat(32))]);
}

#[tokio::test]
async fn descendant_recovery_cannot_remove_anything_when_journaling_fails() {
    let (result, events) = scenario("descendant-journal-failure").await;
    assert!(result.unwrap_err().to_string().contains("journal failure"));
    assert_eq!(events, vec!["journal"]);
}

#[tokio::test]
async fn recovery_waits_for_complete_descendant_source_window_before_writing() {
    let (result, events) = scenario("descendant-unpublished").await;
    assert!(result.unwrap_err().is::<crate::live_supervisor::RecoveryPending>());
    assert!(events.is_empty());
}
#[tokio::test]
async fn recovery_retains_rejected_descendant_id_but_does_not_replay_it() {
    let (result, events) = scenario("descendant-rejected").await;
    result.unwrap();
    assert_eq!(events, vec!["journal".to_owned(), format!("revert:{}", "33".repeat(32)),
        format!("revert:{}", "66".repeat(32)), format!("persist:{}", "22".repeat(32))]);
}
#[tokio::test]
async fn changed_descendant_acceptance_prevents_recovery_acknowledgement() {
    let (result, events) = scenario("descendant-changing").await;
    assert!(result.unwrap_err().is::<crate::live_supervisor::RecoveryPending>());
    assert_eq!(events.first().map(String::as_str), Some("journal"));
    assert!(events.iter().any(|e| e.starts_with("persist:")));
}
