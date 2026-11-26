use super::*;
use crate::live_recovery::{LiveWriteJournal, LiveWriteWindow, PgLiveWriteJournal};
use tn12_indexer_core::{RestTxInput, RestTxOutput};
use tn12_indexer_db::persist::PagedRecoveryOwner;
use tn12_indexer_db::persist::{PersistedInputSpend, RecoveryBlockImpact, RecoveryReplanRequired};
use tn12_indexer_db::{PersistStats, PgPersister, RevertStats};

#[derive(Debug)]
struct FixtureNode(std::collections::BTreeMap<Vec<u8>,u64>);
#[async_trait::async_trait]
impl crate::rest_replay_fence::CanonicalVerifier for FixtureNode {
    async fn block_evidence(&self, hash: &[u8]) -> Result<tn12_indexer_db::persist::AcceptingBlockEvidence> {
        anyhow::ensure!(hash == [0x11u8;32], "unknown fixture orphan");
        Ok(tn12_indexer_db::persist::AcceptingBlockEvidence {
            hash: hash.to_vec(), is_chain_block: false, blue_score:106, timestamp:1000,
            selected_parent:vec![0x33;32], parents:vec![vec![vec![0x33;32]]],
            accepted_id_merkle_root:vec![0x44;32], utxo_commitment:vec![0x55;32],
        })
    }
    async fn verify(&self, blocks:&[(Vec<u8>,u64)]) -> Result<()> {
        for (hash,score) in blocks {
            anyhow::ensure!(self.0.get(hash)==Some(score),"fixture node rejects accepting block");
        }
        Ok(())
    }
}
fn rest_with_fixture_node(url:String, canonical:&[RestTransaction]) -> RestClient {
    let mut rest=RestClient::new(url).unwrap();
    let blocks=canonical.iter().map(|tx|(hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap(),tx.accepting_block_blue_score.unwrap())).collect();
    rest.canonical_verifier=Some(Arc::new(FixtureNode(blocks)));
    rest
}

struct CrashProbe {
    writer: PgPersister,
    legacy: bool,
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn removal_retry_revalidates_source_before_another_write(pool: sqlx::PgPool) {
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    let writer=PgPersister::new(pool.clone());
    let original=tx(0xaa,0x11,106,None);
    let moved=tx(0xaa,0x33,105,None);
    writer.persist_tx(&original).await.unwrap();
    let journal=PgLiveWriteJournal::new(pool.clone(),"testnet-10","retry-source-test");
    journal.begin(&LiveWriteWindow::new(&[original]).unwrap()).await.unwrap();
    let key=journal.intent_key().unwrap();
    let owner=PagedRecoveryOwner::claim(&pool,key,&["11".repeat(32)]).await.unwrap();
    owner.stage_blocks(&pool,&[tn12_indexer_db::persist::StagedRecoveryBlock {
        impact:writer.recovery_block_impact(&"11".repeat(32)).await.unwrap(),
        blue_score:106,source_is_chain_block:false,
    }]).await.unwrap();
    owner.stage_transactions(&pool,&[moved.clone()]).await.unwrap();
    owner.finish_discovery(&pool).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION fail_first_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION USING ERRCODE='57014',MESSAGE='injected removal cancellation'; END $$;
        CREATE TRIGGER fail_first_removal BEFORE DELETE ON covenant_utxos FOR EACH ROW EXECUTE FUNCTION fail_first_removal();")
        .execute(&pool).await.unwrap();
    let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url=format!("http://{}",listener.local_addr().unwrap());
    let observed_pool=pool.clone();
    let server=tokio::spawn(async move {
        loop {
            let (mut socket,_)=listener.accept().await.unwrap();
            let mut request=[0;8192];
            let n=socket.read(&mut request).await.unwrap();
            let request=String::from_utf8_lossy(&request[..n]);
            let body=if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore":150,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/blocks/") {
                let failed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tn10_live_recovery_blocks WHERE removal_failures>0)")
                    .fetch_one(&observed_pool).await.unwrap();
                serde_json::json!({"header":{"blueScore":106,"timestamp":1000,"parents":[],
                    "acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":"11".repeat(32),"blueScore":106,"isChainBlock":failed,
                    "selectedParentHash":"33".repeat(32)}})
            } else if request.contains("/transactions/") { serde_json::to_value(&moved).unwrap() }
            else { panic!("unexpected request: {request}") };
            let body=body.to_string();
            let response=crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let follower=ChainTipFollower::new(RestClient::new(url).unwrap(),Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),"unused-retry-source",TipFollowerConfig::default()).unwrap();
    let error=follower.remove_paged_recovery_blocks(&owner,&writer).await.unwrap_err();
    assert!(error.to_string().contains("paged source block changed before removal"),"{error:#}");
    let failures:i32=sqlx::query_scalar("SELECT removal_failures FROM tn10_live_recovery_blocks WHERE intent_key=$1")
        .bind(key).fetch_one(&pool).await.unwrap();
    assert_eq!(failures,1,"second attempt must stop at source validation");
    owner.heartbeat(&pool).await.unwrap();
    assert!(writer.has_utxo(&"aa".repeat(32),0).await.unwrap());
    assert!(journal.load().await.unwrap().is_some());
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn paged_plan_resumes_from_source_after_owner_loss(pool: sqlx::PgPool) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let writer = PgPersister::new(pool.clone());
    let original = tx(0xaa, 0x11, 106, None);
    let moved = tx(0xaa, 0x33, 105, None);
    let child = tx(0xbb, 0x22, 125, Some(0xaa));
    writer.persist_tx(&original).await.unwrap();
    writer.persist_tx(&child).await.unwrap();
    let node_canonical=vec![moved.clone(),child.clone()];

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let changed_source = Arc::new(AtomicBool::new(false));
    let server_changed = changed_source.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            let body = if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore":150,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),
                    "acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/blocks/") {
                let descendant = request.contains(&"22".repeat(32));
                let (hash, score) = if descendant {
                    ("22".repeat(32), 125)
                } else {
                    ("11".repeat(32), 106)
                };
                serde_json::json!({"header":{"blueScore":score,"timestamp":1000,"parents":[],
                    "acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":hash,"blueScore":score,"isChainBlock":descendant,
                        "selectedParentHash":"33".repeat(32)}})
            } else if request.contains("/transactions/") {
                let mut selected = if request.contains(&"bb".repeat(32)) {
                    child.clone()
                } else {
                    moved.clone()
                };
                if selected.transaction_id == moved.transaction_id
                    && server_changed.load(Ordering::SeqCst)
                {
                    selected.outputs[0].amount = 2;
                }
                serde_json::to_value(selected).unwrap()
            } else if request.contains("/virtual-chain") {
                let selected = if request.contains("blueScoreGte=120") {
                    &child
                } else {
                    &moved
                };
                serde_json::json!([{"hash":selected.accepting_block_hash,
                    "blue_score":selected.accepting_block_blue_score,
                    "daa_score":selected.accepting_block_blue_score,"timestamp":1000,
                    "transactions":[selected]}])
            } else {
                panic!("unexpected request: {request}")
            };
            let body = body.to_string();
            let response = crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            ));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "paged-resume-test");
    journal
        .begin(&LiveWriteWindow::new(&[original]).unwrap())
        .await
        .unwrap();
    let follower = ChainTipFollower::new(
        rest_with_fixture_node(url,&node_canonical),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let pending = journal.load().await.unwrap().unwrap();
    let key = journal.intent_key().unwrap();
    let first = PagedRecoveryOwner::claim(&pool, key, &["11".repeat(32)])
        .await
        .unwrap();
    follower
        .stage_paged_recovery_source(&first, &pending, 150, 10)
        .await
        .unwrap();
    assert_eq!(first.phase(&pool).await.unwrap(), "revert");
    sqlx::query("UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key=$1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    changed_source.store(true, Ordering::SeqCst);
    let mut restarted = journal.load().await.unwrap().unwrap();
    let error = follower
        .recover_live_window(&mut restarted, &journal)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("staged recovery transaction evidence changed"));
    assert!(journal.load().await.unwrap().is_some());
    changed_source.store(false, Ordering::SeqCst);
    sqlx::query("UPDATE tn10_live_recovery_plans SET lease_expires_at_ms=0 WHERE intent_key=$1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    follower
        .recover_live_window(&mut restarted, &journal)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT phase FROM tn10_live_recovery_plans WHERE intent_key=$1"
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap(),
        "complete"
    );
    assert!(writer.has_utxo(&"aa".repeat(32), 0).await.unwrap());
    assert!(writer.has_utxo(&"bb".repeat(32), 0).await.unwrap());
    assert!(journal.load().await.unwrap().is_some());
    journal.complete(&restarted).await.unwrap();
    server.abort();
}
#[async_trait::async_trait]
impl Persister for CrashProbe {
    async fn persist_tx(&self, tx: &RestTransaction) -> Result<PersistStats> {
        self.writer.persist_tx(tx).await
    }
    async fn persist_batch(&self, txs: &[RestTransaction]) -> Result<PersistStats> {
        self.writer.persist_batch(txs).await
    }
    async fn revert_block(&self, hash: &[u8]) -> Result<RevertStats> {
        self.writer.revert_block(hash).await
    }
    async fn has_utxo(&self, id: &str, vout: i32) -> Result<bool> {
        self.writer.has_utxo(id, vout).await
    }
    async fn conflicting_input_spends(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Vec<PersistedInputSpend>> {
        self.writer.conflicting_input_spends(txs).await
    }
    async fn stale_persisted_acceptances(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Vec<PersistedInputSpend>> {
        self.writer.stale_persisted_acceptances(txs).await
    }
    async fn recovery_block_impact(&self, hash: &str) -> Result<RecoveryBlockImpact> {
        if self.legacy {
            return Ok(RecoveryBlockImpact {
                block_hash: hash.into(),
                transaction_ids: self.writer.indexed_block_transaction_ids(hash).await?,
                descendants: vec![],
            });
        }
        self.writer.recovery_block_impact(hash).await
    }
    async fn revert_recovery_blocks(
        &self,
        impacts: &[RecoveryBlockImpact],
    ) -> Result<Vec<RevertStats>> {
        self.writer.revert_recovery_blocks(impacts).await?;
        Err(RecoveryReplanRequired("injected loss after committed removal").into())
    }
}
fn tx(id: u8, block: u8, score: u64, parent: Option<u8>) -> RestTransaction {
    let script = format!("aa20{}87", "44".repeat(32));
    RestTransaction {
        transaction_id: hex::encode([id; 32]),
        is_accepted: true,
        accepting_block_hash: Some(hex::encode([block; 32])),
        accepting_block_blue_score: Some(score),
        accepting_block_time: Some(1000),
        inputs: parent
            .into_iter()
            .map(|parent| RestTxInput {
                previous_outpoint_hash: hex::encode([parent; 32]),
                previous_outpoint_index: "0".into(),
                previous_outpoint_script: Some(script.clone()),
                previous_outpoint_amount: Some(1),
                ..Default::default()
            })
            .collect(),
        outputs: vec![RestTxOutput {
            transaction_id: hex::encode([id; 32]),
            index: 0,
            amount: 1,
            script_public_key: script,
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn recover_live_window_hands_257_descendant_closure_to_durable_plan(pool: sqlx::PgPool) {
    recover_large_footprint(pool, 0).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn recover_single_block_with_258_transactions(pool: sqlx::PgPool) {
    recover_large_footprint(pool, 1).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn recover_single_genesis_block_with_257_descendant_blocks(pool: sqlx::PgPool) {
    recover_large_footprint(pool, 2).await;
}

async fn recover_large_footprint(pool: sqlx::PgPool, shape: u8) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn chain_tx(id: u64, block: u64, score: u64, parent: Option<u64>) -> RestTransaction {
        let script = format!("aa20{id:064x}87");
        let transaction_id = format!("{id:064x}");
        RestTransaction {
            transaction_id: transaction_id.clone(),
            is_accepted: true,
            accepting_block_hash: Some(format!("{block:064x}")),
            accepting_block_blue_score: Some(score),
            accepting_block_time: Some(1000),
            inputs: parent
                .into_iter()
                .map(|parent| RestTxInput {
                    previous_outpoint_hash: format!("{parent:064x}"),
                    previous_outpoint_index: "0".into(),
                    previous_outpoint_script: Some(format!("aa20{parent:064x}87")),
                    previous_outpoint_amount: Some(1),
                    ..Default::default()
                })
                .collect(),
            outputs: vec![RestTxOutput {
                transaction_id,
                index: 0,
                amount: 1,
                script_public_key: script,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    let writer = PgPersister::new(pool.clone());
    let removed = chain_tx(1, 1, 106, None);
    let replacement = chain_tx(1, 2, 105, None);
    let descendants: Vec<_> = (0..257_u64)
        .map(|index| match shape {
            0 => chain_tx(index + 2, index + 3, index + 120, Some(index + 1)),
            1 => chain_tx(index + 2, 1, 106, None),
            _ => {
                let mut tx = chain_tx(index + 2, index + 3, index + 120, None);
                tx.outputs[0].script_public_key = removed.outputs[0].script_public_key.clone();
                tx
            }
        })
        .collect();
    writer.persist_tx(&removed).await.unwrap();
    for descendant in &descendants {
        writer.persist_tx(descendant).await.unwrap();
    }

    let mut canonical = Vec::with_capacity(descendants.len() + 1);
    canonical.push(replacement.clone());
    canonical.extend(descendants.iter().cloned().map(|mut tx| {
        if shape == 1 {
            tx.accepting_block_hash = replacement.accepting_block_hash.clone();
            tx.accepting_block_blue_score = replacement.accepting_block_blue_score;
        }
        tx
    }));
    if shape > 0 {
        let error = writer
            .recovery_block_impact(removed.accepting_block_hash.as_ref().unwrap())
            .await
            .unwrap_err();
        assert!(
            error.is::<tn12_indexer_db::persist::RecoveryImpactLimit>(),
            "fixture must exceed a single-block bound: {error:#}"
        );
    }
    let node_canonical = canonical.clone();
    let removed_block = removed.accepting_block_hash.clone().unwrap();
    let source_by_id: BTreeMap<_, _> = canonical
        .iter()
        .cloned()
        .map(|tx| (tx.transaction_id.clone(), tx))
        .collect();
    let mut blocks = BTreeMap::new();
    blocks.insert(removed_block.clone(), (106, false));
    for tx in &canonical {
        blocks.insert(
            tx.accepting_block_hash.clone().unwrap(),
            (tx.accepting_block_blue_score.unwrap(), true),
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            let body = if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore":500,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),
                    "acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/blocks/") {
                let (hash, (score, is_chain_block)) = blocks
                    .iter()
                    .find(|(hash, _)| request.contains(hash.as_str()))
                    .unwrap_or_else(|| panic!("unknown block request: {request}"));
                serde_json::json!({"header":{"blueScore":score,"timestamp":1000,
                    "parents":[{"parentHashes":["ff".repeat(32)]}],
                    "acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":hash,"blueScore":score,"isChainBlock":is_chain_block,
                    "selectedParentHash":"ff".repeat(32)}})
            } else if request.contains("/transactions/") {
                let (_, transaction) = source_by_id
                    .iter()
                    .find(|(id, _)| request.contains(id.as_str()))
                    .unwrap_or_else(|| panic!("unknown transaction request: {request}"));
                serde_json::to_value(transaction).unwrap()
            } else if request.contains("/virtual-chain") {
                let start: u64 = request
                    .split("blueScoreGte=")
                    .nth(1)
                    .and_then(|value| value.split('&').next())
                    .unwrap()
                    .parse()
                    .unwrap();
                let mut page = BTreeMap::<String, Vec<&RestTransaction>>::new();
                for tx in canonical.iter().filter(|tx| {
                    tx.accepting_block_blue_score
                        .is_some_and(|score| start <= score && score < start + 10)
                }) {
                    page.entry(tx.accepting_block_hash.clone().unwrap())
                        .or_default()
                        .push(tx);
                }
                serde_json::Value::Array(page.into_iter().map(|(hash, transactions)| {
                    let score = transactions[0].accepting_block_blue_score;
                    serde_json::json!({"hash":hash,"blue_score":score,"daa_score":score,"timestamp":1000,"transactions":transactions})
                }).collect())
            } else {
                panic!("unexpected request: {request}")
            };
            let body = body.to_string();
            let response = crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            ));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });

    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "paged-257-closure");
    journal
        .begin(&LiveWriteWindow::new(&[replacement]).unwrap())
        .await
        .unwrap();
    let follower = ChainTipFollower::new(
        rest_with_fixture_node(url,&node_canonical),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let mut retained = journal.load().await.unwrap().unwrap();
    follower
        .recover_live_window(&mut retained, &journal)
        .await
        .unwrap();

    let key = journal.intent_key().unwrap();
    let plan: (String, i64, i64, i64) = sqlx::query_as(
        "SELECT phase,discovered_blocks,reverted_blocks,replayed_transactions \
         FROM tn10_live_recovery_plans WHERE intent_key=$1",
    )
    .bind(key)
    .fetch_one(&pool)
    .await
    .unwrap();
    let expected_blocks = if shape == 1 { 1 } else { 258 };
    assert_eq!(
        plan,
        ("complete".into(), expected_blocks, expected_blocks, 258)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM tn10_live_recovery_blocks WHERE intent_key=$1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap(),
        expected_blocks
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM tn10_live_recovery_transactions WHERE intent_key=$1 AND replayed",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap(),
        258
    );
    let effects: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),count(*) FILTER (WHERE status='spent'),count(*) FILTER (WHERE status='active') \
         FROM covenant_utxos",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        effects,
        if shape == 0 {
            (258, 257, 1)
        } else {
            (258, 0, 258)
        }
    );
    if shape > 0 {
        let chunked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tn10_live_recovery_blocks WHERE intent_key=$1 AND chunked",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(chunked, 1);
        // Even after final verification, unrelated writers remain fenced until
        // the supervisor acknowledges the retained journal.
        assert!(writer
            .persist_tx(&chain_tx(9999, 9999, 499, None))
            .await
            .is_err());
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_utxos WHERE created_block=$1",)
            .bind(hex::decode(removed_block).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert!(journal.load().await.unwrap().is_some());
    journal.complete(&retained).await.unwrap();
    assert!(journal.load().await.unwrap().is_none());
    writer
        .persist_tx(&chain_tx(9999, 9999, 499, None))
        .await
        .unwrap();
    server.abort();
}
#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn equivalent_acceptance_recovery_moves_references_before_removal_discovery(
    pool: sqlx::PgPool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let writer = PgPersister::new(pool.clone());
    let old = tx(0xaa, 0x11, 106, None);
    let canonical = tx(0xaa, 0x33, 106, None);
    writer.persist_tx(&old).await.unwrap();
    writer
        .persist_tx(&tx(0xbb, 0x44, 116, Some(0xaa)))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let source_tx = canonical.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let path = String::from_utf8_lossy(&request[..n]);
            let path = path.split_whitespace().nth(1).unwrap().to_string();
            let body = if path.starts_with("/info/health") {
                serde_json::json!({"database":{"blueScore":150,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),
                    "acceptedTxBlockTimeDiff":0}})
            } else if path.starts_with("/blocks/") {
                let old_block = path.contains(&"11".repeat(32));
                serde_json::json!({
                    "header":{"blueScore":106,"timestamp":1000,
                        "parents":[{"parentHashes":["22".repeat(32)]}],
                        "acceptedIdMerkleRoot":"44".repeat(32),
                        "utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":if old_block { "11".repeat(32) } else { "33".repeat(32) },
                        "blueScore":106,"selectedParentHash":"22".repeat(32),
                        "isChainBlock":!old_block}
                })
            } else if path.starts_with("/transactions/") {
                serde_json::to_value(&source_tx).unwrap()
            } else if path.starts_with("/virtual-chain") {
                serde_json::json!([{"hash":"33".repeat(32),"blue_score":106,
                    "timestamp":1000,"transactions":[source_tx]}])
            } else {
                panic!("unexpected source request: {path}")
            };
            let body = body.to_string();
            let response = crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "equivalent-recovery-test");
    let mut intent = LiveWriteWindow::new(&[canonical]).unwrap();
    intent.window_width = Some(10);
    intent
        .observed_blocks
        .entry(100)
        .or_default()
        .insert("11".repeat(32));
    journal.begin(&intent).await.unwrap();
    let follower = ChainTipFollower::new(
        RestClient::new(url).unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    follower
        .recover_live_window(&mut intent, &journal)
        .await
        .unwrap();
    let block: Vec<u8> =
        sqlx::query_scalar("SELECT created_block FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(vec![0xaau8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(block, vec![0x33u8; 32]);
    let old_references: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE block_hash=$1")
            .bind(vec![0x11u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(old_references, 0);
    let replacement_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM canonical_block_replacements WHERE old_hash=$1 AND new_hash=$2",
    )
    .bind(vec![0x11u8; 32])
    .bind(vec![0x33u8; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replacement_count, 1);
    let child: (Vec<u8>, String) =
        sqlx::query_as("SELECT created_block,status FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(vec![0xbbu8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(child, (vec![0x44u8; 32], "active".into()));
    assert!(journal.load().await.unwrap().is_some());
    journal.complete(&intent).await.unwrap();
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn changing_equivalent_acceptance_proof_retains_intent_without_mutation(pool: sqlx::PgPool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let writer = PgPersister::new(pool.clone());
    let old = tx(0xaa, 0x11, 106, None);
    let canonical = tx(0xaa, 0x33, 106, None);
    writer.persist_tx(&old).await.unwrap();
    writer
        .persist_tx(&tx(0xbb, 0x44, 116, Some(0xaa)))
        .await
        .unwrap();
    let before_block: Vec<u8> =
        sqlx::query_scalar("SELECT created_block FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(vec![0xaau8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    let before_references: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE block_hash=$1")
            .bind(vec![0x11u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(before_references > 0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let source_tx = canonical.clone();
    let changed_member = tx(0xcc, 0x33, 106, None);
    let server = tokio::spawn(async move {
        let mut canonical_pages = 0;
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let path = String::from_utf8_lossy(&request[..n]);
            let path = path.split_whitespace().nth(1).unwrap().to_string();
            let body = if path.starts_with("/info/health") {
                serde_json::json!({"database":{"blueScore":150,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),
                    "acceptedTxBlockTimeDiff":0}})
            } else if path.starts_with("/blocks/") {
                let old_block = path.contains(&"11".repeat(32));
                serde_json::json!({
                    "header":{"blueScore":106,"timestamp":1000,
                        "parents":[{"parentHashes":["22".repeat(32)]}],
                        "acceptedIdMerkleRoot":"44".repeat(32),
                        "utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":if old_block { "11".repeat(32) } else { "33".repeat(32) },
                        "blueScore":106,"selectedParentHash":"22".repeat(32),
                        "isChainBlock":!old_block}
                })
            } else if path.starts_with("/transactions/") {
                serde_json::to_value(&source_tx).unwrap()
            } else if path.starts_with("/virtual-chain") {
                canonical_pages += 1;
                let transactions = if canonical_pages == 3 {
                    vec![source_tx.clone(), changed_member.clone()]
                } else {
                    vec![source_tx.clone()]
                };
                serde_json::json!([{"hash":"33".repeat(32),"blue_score":106,
                    "timestamp":1000,"transactions":transactions}])
            } else {
                panic!("unexpected source request: {path}")
            };
            let body = body.to_string();
            let response = crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "changing-proof-test");
    let mut intent = LiveWriteWindow::new(&[canonical]).unwrap();
    intent.window_width = Some(10);
    intent
        .observed_blocks
        .entry(100)
        .or_default()
        .insert("11".repeat(32));
    journal.begin(&intent).await.unwrap();
    let follower = ChainTipFollower::new(
        RestClient::new(url).unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let error = follower
        .recover_live_window(&mut intent, &journal)
        .await
        .unwrap_err();
    assert!(error.is::<crate::live_supervisor::RecoveryPending>());
    let after_block: Vec<u8> =
        sqlx::query_scalar("SELECT created_block FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(vec![0xaau8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_block, before_block);
    let after_references: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE block_hash=$1")
            .bind(vec![0x11u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_references, before_references);
    let replacement_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM canonical_block_replacements WHERE old_hash=$1 AND new_hash=$2",
    )
    .bind(vec![0x11u8; 32])
    .bind(vec![0x33u8; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replacement_count, 0);
    let retained = journal
        .load()
        .await
        .unwrap()
        .expect("recovery intent retained");
    assert_eq!(retained.transactions.len(), 1);
    assert_eq!(
        retained.transactions[0].accepting_block_hash,
        Some("33".repeat(32))
    );
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn durable_journal_recovers_descendant_after_committed_removal_and_process_loss(
    pool: sqlx::PgPool,
) {
    descendant_restart_case(pool, false).await;
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn orphan_missing_from_rest_recovers_descendants_from_node_and_retained_journal(pool: sqlx::PgPool) {
    descendant_restart_case(pool, true).await;
}

async fn descendant_restart_case(pool: sqlx::PgPool, prune_orphan: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let writer = PgPersister::new(pool.clone());
    writer.persist_tx(&tx(0xaa, 0x11, 106, None)).await.unwrap();
    let parent = tx(0xaa, 0x33, 105, None);
    let child = tx(0xbb, 0x22, 125, Some(0xaa));
    writer.persist_tx(&child).await.unwrap();
    let node_canonical=vec![parent.clone(),child.clone()];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let source_parent = parent.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            if prune_orphan && request.contains("/blocks/") && request.contains(&"11".repeat(32)) {
                socket.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                continue;
            }
            let body = if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore":150,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/blocks/") {
                let descendant = request.contains(&"22".repeat(32));
                let replacement = request.contains(&"33".repeat(32));
                let (hash, score) = if descendant {
                    ("22".repeat(32), 125)
                } else if replacement {
                    ("33".repeat(32), 105)
                } else {
                    ("11".repeat(32), 106)
                };
                serde_json::json!({"header":{"blueScore":score,"timestamp":1000,"parents":[{"parentHashes":["33".repeat(32)]}],
                    "acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":hash,"blueScore":score,"isChainBlock":descendant || replacement,"selectedParentHash":"33".repeat(32)}})
            } else if request.contains("/transactions/") {
                serde_json::to_value(if request.contains(&"bb".repeat(32)) {
                    &child
                } else {
                    &source_parent
                })
                .unwrap()
            } else if request.contains("/virtual-chain") {
                let selected = if request.contains("blueScoreGte=120") {
                    &child
                } else {
                    &source_parent
                };
                serde_json::json!([{"hash":selected.accepting_block_hash,"blue_score":selected.accepting_block_blue_score,
                    "daa_score":selected.accepting_block_blue_score,"timestamp":1000,"transactions":[selected]}])
            } else {
                panic!("unexpected request: {request}")
            };
            let body = body.to_string();
            let response=crate::source_observation::fresh_test_response(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "descendant-restart-test");
    let original = LiveWriteWindow::new(&[parent]).unwrap();
    journal.begin(&original).await.unwrap();
    // Reproduce the deployed failure through the actual DB lookup and planner.
    let legacy = ChainTipFollower::new(
        rest_with_fixture_node(url.clone(), &node_canonical),
        Arc::new(CrashProbe {
            writer: PgPersister::new(pool.clone()),
            legacy: true,
        }),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let error = legacy
        .recover_live_window(&mut original.clone(), &journal)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("indexed descendant spends"));
    let crash = ChainTipFollower::new(
        rest_with_fixture_node(url.clone(), &node_canonical),
        Arc::new(CrashProbe {
            writer: PgPersister::new(pool.clone()),
            legacy: false,
        }),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let mut pending = journal.load().await.unwrap().unwrap();
    let error = crash
        .recover_live_window(&mut pending, &journal)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("injected loss after committed removal"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM covenant_utxos")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    drop(crash);
    let restarted_journal =
        PgLiveWriteJournal::new(pool.clone(), "testnet-10", "descendant-restart-test");
    let mut retained = restarted_journal.load().await.unwrap().unwrap();
    assert_eq!(retained.transactions.len(), 2);
    assert!(retained
        .transactions
        .iter()
        .all(|tx| !tx.outputs.is_empty()));
    let restarted = ChainTipFollower::new(
        rest_with_fixture_node(url,&node_canonical),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    restarted
        .recover_live_window(&mut retained, &restarted_journal)
        .await
        .unwrap();
    assert!(restarted_journal.load().await.unwrap().is_some());
    let parent: (Vec<u8>, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT created_block,status,spent_by_txid FROM covenant_utxos WHERE txid=$1 AND vout=0",
    )
    .bind(vec![0xaau8; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        parent,
        (vec![0x33; 32], "spent".into(), Some(vec![0xbb; 32]))
    );
    let child: (Vec<u8>, String) =
        sqlx::query_as("SELECT created_block,status FROM covenant_utxos WHERE txid=$1 AND vout=0")
            .bind(vec![0xbbu8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(child, (vec![0x22; 32], "active".into()));
    restarted_journal.complete(&retained).await.unwrap();
    assert!(restarted_journal.load().await.unwrap().is_none());
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn rejected_source_retains_historical_body_and_coordinates_across_journal_reload(
    pool: sqlx::PgPool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let writer = PgPersister::new(pool.clone());
    let original = tx(0xaa, 0x22, 105, None);
    writer.persist_tx(&original).await.unwrap();
    let rejected = RestTransaction {
        transaction_id: original.transaction_id.clone(),
        is_accepted: false,
        ..Default::default()
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let original_block_hash = original.accepting_block_hash.clone().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 8192];
            let n = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..n]);
            let body = if request.contains("/info/health") {
                serde_json::json!({"database":{"blueScore":150,"isSynced":true,
                    "acceptedTxBlockTime":chrono::Utc::now().timestamp_millis(),"acceptedTxBlockTimeDiff":0}})
            } else if request.contains("/blocks/") {
                serde_json::json!({"header":{"blueScore":105,"timestamp":1000,"parents":[],
                    "acceptedIdMerkleRoot":"44".repeat(32),"utxoCommitment":"55".repeat(32)},
                    "verboseData":{"hash":original_block_hash,"blueScore":105,"isChainBlock":false,
                        "selectedParentHash":"33".repeat(32)}})
            } else if request.contains("/transactions/") {
                serde_json::to_value(&rejected).unwrap()
            } else if request.contains("/virtual-chain") {
                serde_json::json!([])
            } else {
                panic!("unexpected request: {request}")
            };
            let body = body.to_string();
            let response = crate::source_observation::fresh_test_response(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            ));
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "rejected-restart-test");
    journal
        .begin(&LiveWriteWindow::new(&[original.clone()]).unwrap())
        .await
        .unwrap();
    let recovering = ChainTipFollower::new(
        RestClient::new(url.clone()).unwrap(),
        Arc::new(CrashProbe {
            writer: PgPersister::new(pool.clone()),
            legacy: false,
        }),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    let mut pending = journal.load().await.unwrap().unwrap();
    let error = recovering
        .recover_live_window(&mut pending, &journal)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("injected loss after committed removal"));

    let restarted_journal =
        PgLiveWriteJournal::new(pool.clone(), "testnet-10", "rejected-restart-test");
    let mut retained = restarted_journal.load().await.unwrap().unwrap();
    let retained_rejection = retained
        .rejected_transactions
        .iter()
        .find(|tx| tx.transaction_id == original.transaction_id)
        .unwrap();
    assert!(!retained_rejection.is_accepted);
    assert_eq!(
        retained_rejection.accepting_block_hash,
        original.accepting_block_hash
    );
    assert_eq!(
        retained_rejection.accepting_block_blue_score,
        original.accepting_block_blue_score
    );
    assert_eq!(
        retained_rejection.accepting_block_time,
        original.accepting_block_time
    );
    assert_eq!(
        serde_json::to_value(&retained_rejection.outputs).unwrap(),
        serde_json::to_value(&original.outputs).unwrap()
    );

    let restarted = ChainTipFollower::new(
        RestClient::new(url).unwrap(),
        Arc::new(PgPersister::new(pool.clone())),
        pool.clone(),
        "unused",
        TipFollowerConfig::default(),
    )
    .unwrap();
    restarted
        .recover_live_window(&mut retained, &restarted_journal)
        .await
        .unwrap();
    let reloaded = restarted_journal.load().await.unwrap().unwrap();
    let reloaded_rejection = reloaded
        .rejected_transactions
        .iter()
        .find(|tx| tx.transaction_id == original.transaction_id)
        .unwrap();
    assert_eq!(
        reloaded_rejection.accepting_block_hash,
        original.accepting_block_hash
    );
    assert_eq!(
        reloaded_rejection.accepting_block_blue_score,
        original.accepting_block_blue_score
    );
    assert_eq!(
        reloaded_rejection.accepting_block_time,
        original.accepting_block_time
    );
    assert_eq!(
        serde_json::to_value(&reloaded_rejection.outputs).unwrap(),
        serde_json::to_value(&original.outputs).unwrap()
    );
    let outputs: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(outputs, 0);
    restarted_journal.complete(&retained).await.unwrap();
    assert!(restarted_journal.load().await.unwrap().is_none());
    server.abort();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn acknowledgement_requires_verified_matching_plan_and_releases_its_fence(
    pool: sqlx::PgPool,
) {
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "ack-plan");
    let window = LiveWriteWindow::new(&[tx(0xaa, 0x11, 106, None)]).unwrap();
    journal.begin(&window).await.unwrap();
    let key = journal.intent_key().unwrap();
    let owner = PagedRecoveryOwner::claim(&pool, key, &[]).await.unwrap();
    assert!(
        journal.complete(&window).await.is_err(),
        "an unfinished plan must retain its intent"
    );
    assert!(journal.load().await.unwrap().is_some());
    assert!(PagedRecoveryOwner::plan_exists(&pool, key).await.unwrap());
    owner.finish_discovery(&pool).await.unwrap();
    owner.finish_removal(&pool).await.unwrap();
    owner.finish_replay(&pool).await.unwrap();
    owner.mark_complete(&pool).await.unwrap();
    sqlx::query("UPDATE tn10_live_recovery_plans SET exclusive_writes=TRUE,intent_sha256=$2 WHERE intent_key=$1")
        .bind(key).bind(vec![0u8;32]).execute(&pool).await.unwrap();
    assert!(
        journal.complete(&window).await.is_err(),
        "a completed plan for another body must not be retired"
    );
    assert!(journal.load().await.unwrap().is_some());
    sqlx::query("UPDATE tn10_live_recovery_plans SET intent_sha256=(SELECT pg_catalog.sha256(value::text::bytea) FROM indexer_state WHERE key=$1) WHERE intent_key=$1")
        .bind(key).execute(&pool).await.unwrap();
    journal.complete(&window).await.unwrap();
    assert!(journal.load().await.unwrap().is_none());
    assert!(!PagedRecoveryOwner::plan_exists(&pool, key).await.unwrap());
    // Reusing the worker's journal key must not find the completed old plan.
    let next = LiveWriteWindow::new(&[tx(0xbb, 0x22, 107, None)]).unwrap();
    journal.begin(&next).await.unwrap();
    assert!(
        journal.complete(&window).await.is_err(),
        "stale acknowledgement preserves a new intent"
    );
    journal.complete(&next).await.unwrap();
}

#[sqlx::test(migrations = "../tn12-indexer-db/migrations")]
async fn unresolved_recovery_rejects_width_change_before_mutating_journal(pool: sqlx::PgPool) {
    let journal = PgLiveWriteJournal::new(pool.clone(), "testnet-10", "mixed-width-test");
    let mut intent = LiveWriteWindow::new(&[tx(0xaa, 0x11, 106, None)]).unwrap();
    intent.window_width = Some(100);
    intent.observed_blocks.clear();
    intent.observed_blocks.entry(100).or_default().insert("11".repeat(32));
    intent.unresolved_blocks.push("22".repeat(32));
    journal.begin(&intent).await.unwrap();
    let before = serde_json::to_value(&intent).unwrap();
    let follower = ChainTipFollower::new(
        RestClient::new("http://127.0.0.1:1").unwrap(),
        Arc::new(PgPersister::new(pool.clone())), pool, "unused", TipFollowerConfig::default(),
    ).unwrap();
    let error = follower.recover_live_window(&mut intent, &journal).await.unwrap_err();
    assert!(error.to_string().contains("recovery window width changed"), "{error:#}");
    assert_eq!(serde_json::to_value(&intent).unwrap(), before);
    assert_eq!(serde_json::to_value(journal.load().await.unwrap().unwrap()).unwrap(), before);
}
