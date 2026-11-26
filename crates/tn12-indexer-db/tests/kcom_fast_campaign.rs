//! Captured accepted TN10 transactions through the real persister and read models.
use serde_json::Value;
use sqlx::PgPool;
use tn12_indexer_core::RestTransaction;
use tn12_indexer_db::{repo, Persister, PgPersister};

const GRAPH: &str = "e8418ea75b7a547d51ee4cd4dd3d83d55da623713d933c31e86369636c3b7942";
const FAST: &str = include_str!("../../../fixtures/kcom-fast-tn10-live/ordered-fast.json");

#[sqlx::test(migrations = "./migrations")]
async fn accepted_fast_campaign_replay_closure_idempotency_and_reorg(pool: PgPool) {
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for fixture in [
        include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-token-and-main.json"),
        include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-no-long.json"),
        include_str!("../../../fixtures/kcom-fast-tn10-live/ordered-latest.json"),
    ] {
        let txs: Vec<RestTransaction> = serde_json::from_str(fixture).unwrap();
        for tx in txs {
            writer
                .persist_tx(&tx)
                .await
                .unwrap_or_else(|e| panic!("dependency {}: {e:#}", tx.transaction_id));
        }
    }
    let txs: Vec<RestTransaction> = serde_json::from_str(FAST).unwrap();
    assert_eq!(txs.len(), 36);
    for tx in &txs {
        writer
            .persist_tx(tx)
            .await
            .unwrap_or_else(|e| panic!("fast campaign {}: {e:#}", tx.transaction_id));
    }
    let campaign = repo::kcom_campaign(&pool, GRAPH).await.unwrap().unwrap();
    assert_eq!(campaign.lifecycle, "settled");
    assert_eq!(campaign.artifact_profile, "kcom-fast-tn10-60s-v1");
    assert!(campaign.test_only);
    assert_eq!(campaign.settled_raw, "997");
    assert_eq!(campaign.activated_raw, "997");
    assert_eq!(campaign.liability_raw, "0");
    assert_eq!(campaign.recovered_raw, "3");
    assert_eq!(campaign.reserve_raw, "0");
    let states: Vec<Value> = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
    )
    .bind(hex::decode(GRAPH).unwrap())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0]["artifactProfile"], "kcom-fast-tn10-60s-v1");
    let receipt: Value = serde_json::from_str(include_str!(
        "../../../docs/evidence/kcom-fast-tn10-full-20261102.json"
    ))
    .unwrap();
    for (role, allocation) in [("alice", "27"), ("bob", "153"), ("carol", "817")] {
        let participant = repo::kcom_participant(
            &pool,
            GRAPH,
            receipt["publicRoles"][role]["owner"].as_str().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(participant.allocation_raw.as_deref(), Some(allocation));
        assert_eq!(participant.released_raw.as_deref(), Some(allocation));
        assert_eq!(participant.remaining_raw.as_deref(), Some("0"));
    }
    for finish in receipt["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|tx| tx["positionClosed"] == true)
    {
        let position = hex::decode(finish["positionId"].as_str().unwrap()).unwrap();
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
        )
        .bind(&position)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active, 0, "final position must be closed");
        let finished: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND entrypoint='finish'",
        )
        .bind(&position)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(finished, 1);
    }
    // Legacy deployments stored a family address label and no fast profile metadata.
    // Replay must authenticate the unchanged outpoint/state and migrate only those fields.
    let original: Vec<(i64, Value, Value)> = sqlx::query_as(
        "SELECT id, inputs, decoded_args FROM covenant_actions WHERE entrypoint='open' ORDER BY id"
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(original.len(), 8);
    sqlx::query("UPDATE covenant_actions SET inputs=jsonb_set(inputs,'{address}','\"legacy-family-address\"'), decoded_args=decoded_args-'artifactProfile'-'testOnly' WHERE entrypoint='open'")
        .execute(&pool).await.unwrap();
    for fixture in [
        include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-token-and-main.json"),
        include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-no-long.json"),
        include_str!("../../../fixtures/kcom-fast-tn10-live/ordered-latest.json"), FAST,
    ] {
        for tx in serde_json::from_str::<Vec<RestTransaction>>(fixture).unwrap() {
            writer.persist_tx(&tx).await.unwrap_or_else(|e| panic!("legacy replay {}: {e:#}", tx.transaction_id));
        }
    }
    let repaired: Vec<(i64, Value, Value)> = sqlx::query_as(
        "SELECT id, inputs, decoded_args FROM covenant_actions WHERE entrypoint='open' ORDER BY id"
    ).fetch_all(&pool).await.unwrap();
    assert_eq!(repaired, original);
    let open_tx = txs.iter().find(|tx| tx.transaction_id ==
        "1bfa4a1a6a5650a79f656618c8e7b381056e74b723c3d1caf18bab0ce9253f52").unwrap();
    let (id, inputs, args) = original.iter().find(|(_,_,args)|
        args["modeName"] == "KCOMFactory" && args["artifactProfile"] == "kcom-fast-tn10-60s-v1").unwrap();
    for (column, changed) in [
        ("decoded_args", { let mut v=args.clone(); v["campaign"]=serde_json::json!("00".repeat(32)); v }),
        ("decoded_args", { let mut v=args.clone(); v["artifactProfile"]=serde_json::json!("unsupported"); v }),
        ("inputs", { let mut v=inputs.clone(); v["unexpected"]=serde_json::json!(true); v }),
    ] {
        let sql = if column == "inputs" { "UPDATE covenant_actions SET inputs=$1 WHERE id=$2" }
            else { "UPDATE covenant_actions SET decoded_args=$1 WHERE id=$2" };
        sqlx::query(sql).bind(changed).bind(id).execute(&pool).await.unwrap();
        let snapshot_sql = "SELECT jsonb_build_object(            'actions', (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM covenant_actions a WHERE txid=$1),             'utxos', (SELECT jsonb_agg(to_jsonb(u) ORDER BY txid,vout) FROM covenant_utxos u WHERE txid=$1 OR spent_by_txid=$1))";
        let open_id = hex::decode(&open_tx.transaction_id).unwrap();
        let before_rejection: Value = sqlx::query_scalar(snapshot_sql)
            .bind(&open_id).fetch_one(&pool).await.unwrap();
        let error = writer.persist_tx(open_tx).await.unwrap_err();
        assert!(format!("{error:#}").contains("KCOM spend action conflicts with accepted replay"));
        let after_rejection: Value = sqlx::query_scalar(snapshot_sql)
            .bind(&open_id).fetch_one(&pool).await.unwrap();
        assert_eq!(after_rejection, before_rejection, "rejected replay must roll back every affected action and UTXO");
        sqlx::query("UPDATE covenant_actions SET inputs=$1, decoded_args=$2 WHERE id=$3")
            .bind(inputs).bind(args).bind(id).execute(&pool).await.unwrap();
    }
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions")
        .fetch_one(&pool)
        .await
        .unwrap();
    for tx in &txs {
        writer.persist_tx(tx).await.unwrap();
    }
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    for tx in txs.iter().rev() {
        writer
            .revert_block(&hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap())
            .await
            .unwrap();
    }
    for tx in &txs {
        writer.persist_tx(tx).await.unwrap();
    }
    let replayed = repo::kcom_campaign(&pool, GRAPH).await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(replayed).unwrap(),
        serde_json::to_value(campaign).unwrap()
    );
}

/// Simulate a decoder rollout before this valid executable family is supported.
/// The source fixture is the exact accepted transaction that stalled DEV.
struct UnsupportedFactory(tn12_indexer_decoder::kcom_claim::KcomClaimDecoder);
impl tn12_indexer_decoder::TemplateDecoder for UnsupportedFactory {
    fn template(&self) -> tn12_indexer_core::KnownTemplate {
        tn12_indexer_core::KnownTemplate::KcomFactory
    }
    fn script_hash(&self) -> [u8; 32] {
        self.0.script_hash()
    }
    fn matches_reveal_script(&self, _: &[u8]) -> bool {
        false
    }
    fn unsupported_reveal_reason(&self, reveal: &[u8]) -> Option<&'static str> {
        self.0
            .matches_reveal_script(reveal)
            .then_some("unsupported_captured_family")
    }
    fn decode_constructor(&self, payload: &[u8]) -> anyhow::Result<Value> {
        self.0.decode_constructor(payload)
    }
    fn decode_state(&self, payload: &[u8]) -> anyhow::Result<Value> {
        self.0.decode_state(payload)
    }
    fn decode_action(&self, signature: &[u8]) -> Option<String> {
        self.0.decode_action(signature)
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn captured_stalling_factory_is_retained_and_later_decoded(pool: PgPool) {
    use std::sync::Arc;
    use tn12_indexer_core::KnownTemplate;
    use tn12_indexer_decoder::{
        default_registry, kcom_claim::KcomClaimDecoder, registry::DecoderRegistry,
    };
    let supported = PgPersister::new(pool.clone());
    for fixture in [
        include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-token-and-main.json"),
        include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-no-long.json"),
        include_str!("../../../fixtures/kcom-fast-tn10-live/ordered-latest.json"),
    ] {
        for tx in serde_json::from_str::<Vec<RestTransaction>>(fixture).unwrap() {
            supported.persist_tx(&tx).await.unwrap();
        }
    }
    let txs: Vec<RestTransaction> = serde_json::from_str(FAST).unwrap();
    let blocker = txs
        .iter()
        .position(|tx| {
            tx.transaction_id == "ae4fd75778fb512e3ebb4cd418f192fb5166d446efd5056de19e9e62deea618a"
        })
        .unwrap();
    for tx in &txs[..blocker] {
        supported.persist_tx(tx).await.unwrap();
    }
    let mut registry = DecoderRegistry::new();
    for decoder in default_registry().iter() {
        if decoder.template() != KnownTemplate::KcomFactory {
            registry.register(Arc::clone(decoder));
        }
    }
    registry.register(Arc::new(UnsupportedFactory(KcomClaimDecoder::new(
        KnownTemplate::KcomFactory,
    ))));
    let old = PgPersister::with_decoders(pool.clone(), registry).with_generic_bulk_persist(true);
    old.persist_tx(&txs[blocker]).await.unwrap();
    let raw: Value =
        sqlx::query_scalar("SELECT raw_transaction FROM indexer_deferred_decodes WHERE txid=$1")
            .bind(hex::decode(&txs[blocker].transaction_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(raw, serde_json::to_value(&txs[blocker]).unwrap());
    assert!(repo::kcom_campaign(&pool, GRAPH)
        .await
        .unwrap_err()
        .to_string()
        .contains("decoding incomplete"));
    assert!(old.has_utxo(&txs[blocker].transaction_id, 1).await.unwrap());
    // The entire subsequent campaign must ingest while its factory decoder is
    // unavailable, then replay in dependency order after an upgrade.
    for tx in &txs[blocker + 1..] {
        old.persist_tx(tx)
            .await
            .unwrap_or_else(|e| panic!("opaque {}: {e:#}", tx.transaction_id));
    }
    let pending_before = tn12_indexer_db::deferred_decode::summary(&pool)
        .await
        .unwrap()
        .pending;
    assert!(pending_before > 1);
    supported.replay_deferred_tx(&txs[blocker]).await.unwrap();
    assert_eq!(
        tn12_indexer_db::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        pending_before,
        "decoded effects alone must not certify source acceptance"
    );
    let mode: Option<String> = sqlx::query_scalar(
        "SELECT state->>'modeName' FROM covenant_utxos WHERE txid=$1 AND vout=1",
    )
    .bind(hex::decode(&txs[blocker].transaction_id).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mode.as_deref(), Some("KCOMClaimShard"));
    for tx in &txs[blocker..] {
        let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM indexer_deferred_decodes WHERE txid=$1 AND status='pending')")
            .bind(hex::decode(&tx.transaction_id).unwrap()).fetch_one(&pool).await.unwrap();
        if !pending {
            continue;
        }
        supported
            .replay_deferred_tx(tx)
            .await
            .unwrap_or_else(|e| panic!("replay {}: {e:#}", tx.transaction_id));
        let block = tn12_indexer_db::persist::AcceptingBlockEvidence {
            hash: hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap(),
            blue_score: tx.accepting_block_blue_score.unwrap(),
            is_chain_block: true,
            timestamp: tx.accepting_block_time.unwrap(),
            selected_parent: vec![0; 32],
            parents: vec![],
            accepted_id_merkle_root: vec![0; 32],
            utxo_commitment: vec![0; 32],
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let proof = tn12_indexer_db::deferred_decode::CanonicalDecodeProof::verify(
            tx,
            tx,
            &block,
            block.blue_score + 1000,
            now,
        )
        .unwrap();
        supported.confirm_deferred_decode(&proof).await.unwrap();
    }
    assert_eq!(
        tn12_indexer_db::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        0
    );
    let campaign = repo::kcom_campaign(&pool, GRAPH).await.unwrap().unwrap();
    assert_eq!(campaign.lifecycle, "settled");
    assert_eq!(campaign.activated_raw, "997");
    assert_eq!(campaign.recovered_raw, "3");
    assert_eq!(campaign.liability_raw, "0");
}
