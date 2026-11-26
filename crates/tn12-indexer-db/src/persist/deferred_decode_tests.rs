//! These cross the real scalar writer, batch routing, journal and reorg seams.
use super::*;
use std::sync::Arc;
use tn12_indexer_core::{RestTxInput, RestTxOutput};

struct FutureDecoder {
    supported: bool,
}
impl TemplateDecoder for FutureDecoder {
    fn template(&self) -> KnownTemplate {
        KnownTemplate::TimeLockVault
    }
    fn script_hash(&self) -> [u8; 32] {
        blake2b_256(&[0x51])
    }
    fn matches_reveal_script(&self, reveal: &[u8]) -> bool {
        self.supported && reveal == [0x51]
    }
    fn unsupported_reveal_reason(&self, reveal: &[u8]) -> Option<&'static str> {
        (!self.supported && reveal == [0x51]).then_some("unsupported_test_version")
    }
    fn decode_constructor(&self, _: &[u8]) -> Result<Value> {
        Ok(serde_json::json!({"version":2}))
    }
    fn decode_state(&self, bytes: &[u8]) -> Result<Value> {
        self.decode_constructor(bytes)
    }
    fn decode_action(&self, _: &[u8]) -> Option<String> {
        Some("spend".into())
    }
}
fn writer(pool: &PgPool, supported: bool) -> PgPersister {
    let mut registry = DecoderRegistry::new();
    registry.register(Arc::new(FutureDecoder { supported }));
    PgPersister::with_decoders(pool.clone(), registry).with_generic_bulk_persist(true)
}
fn tx(id: u8, parent: Option<u8>) -> RestTransaction {
    let script = format!("aa20{}87", hex::encode(blake2b_256(&[0x51])));
    RestTransaction {
        transaction_id: hex::encode([id; 32]),
        accepting_block_hash: Some(hex::encode([id; 32])),
        accepting_block_blue_score: Some(u64::from(id)),
        accepting_block_time: Some(1000 + u64::from(id)),
        is_accepted: true,
        inputs: parent
            .into_iter()
            .map(|p| RestTxInput {
                previous_outpoint_hash: hex::encode([p; 32]),
                previous_outpoint_index: "0".into(),
                previous_outpoint_script: Some(script.clone()),
                previous_outpoint_amount: Some(1),
                signature_script: "0151".into(),
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

fn proof(tx: &RestTransaction) -> crate::deferred_decode::CanonicalDecodeProof {
    let block = AcceptingBlockEvidence {
        hash: hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap(),
        is_chain_block: true,
        blue_score: tx.accepting_block_blue_score.unwrap(),
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
    crate::deferred_decode::CanonicalDecodeProof::verify(
        tx,
        tx,
        &block,
        block.blue_score + 1000,
        now,
    )
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn unsupported_decode_preserves_raw_data_and_unrelated_batch_progress(pool: PgPool) {
    let w = writer(&pool, false);
    w.persist_tx(&tx(1, None)).await.unwrap();
    w.persist_batch(&[tx(2, Some(1)), tx(3, None)])
        .await
        .unwrap();
    assert!(w.has_utxo(&tx(2, None).transaction_id, 0).await.unwrap());
    assert!(w.has_utxo(&tx(3, None).transaction_id, 0).await.unwrap());
    let raw: Value = sqlx::query_scalar(
        "SELECT raw_transaction FROM indexer_deferred_decodes WHERE status='pending'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(raw, serde_json::to_value(tx(2, Some(1))).unwrap());
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1")
        .bind(vec![2u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn deferred_dependencies_survive_restart_and_replay_in_order(pool: PgPool) {
    let old = writer(&pool, false);
    old.persist_tx(&tx(1, None)).await.unwrap();
    old.persist_tx(&tx(2, Some(1))).await.unwrap();
    let upgraded = writer(&pool, true);
    upgraded.persist_tx(&tx(3, Some(2))).await.unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        2
    );
    assert!(upgraded.replay_deferred_tx(&tx(3, Some(2))).await.is_err());
    upgraded.replay_deferred_tx(&tx(2, Some(1))).await.unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        2
    );
    upgraded
        .confirm_deferred_decode(&proof(&tx(2, Some(1))))
        .await
        .unwrap();
    upgraded.replay_deferred_tx(&tx(3, Some(2))).await.unwrap();
    upgraded
        .confirm_deferred_decode(&proof(&tx(3, Some(2))))
        .await
        .unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        0
    );
    upgraded.persist_tx(&tx(3, Some(2))).await.unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn deferred_reorg_preserves_evidence_but_revokes_acceptance(pool: PgPool) {
    let w = writer(&pool, false);
    w.persist_tx(&tx(1, None)).await.unwrap();
    w.persist_tx(&tx(2, Some(1))).await.unwrap();
    w.revert_block(&[2; 32]).await.unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        0
    );
    assert!(writer(&pool, true)
        .replay_deferred_tx(&tx(2, Some(1)))
        .await
        .is_err());
    let status: String = sqlx::query_scalar("SELECT status FROM indexer_deferred_decodes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "reverted");
    w.persist_tx(&tx(2, Some(1))).await.unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        1
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_parent_and_failed_journal_commit_do_not_advance(pool: PgPool) {
    let w = writer(&pool, false);
    assert!(w.persist_tx(&tx(2, Some(1))).await.is_err());
    w.persist_tx(&tx(1, None)).await.unwrap();
    sqlx::query("ALTER TABLE indexer_deferred_decodes ADD CONSTRAINT inject_failure CHECK (false)")
        .execute(&pool)
        .await
        .unwrap();
    assert!(w.persist_tx(&tx(2, Some(1))).await.is_err());
    assert!(!w.has_utxo(&tx(2, None).transaction_id, 0).await.unwrap());
    let status: String = sqlx::query_scalar("SELECT status FROM covenant_utxos WHERE txid=$1")
        .bind(vec![1u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "active");
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_between_replay_and_verification_cannot_clear_obligation(pool: PgPool) {
    let old = writer(&pool, false);
    old.persist_tx(&tx(1, None)).await.unwrap();
    old.persist_tx(&tx(2, Some(1))).await.unwrap();
    let upgraded = writer(&pool, true);
    upgraded.replay_deferred_tx(&tx(2, Some(1))).await.unwrap();
    let evidence = proof(&tx(2, Some(1)));
    upgraded.revert_block(&[2; 32]).await.unwrap();
    assert!(upgraded.confirm_deferred_decode(&evidence).await.is_err());
    let status: String = sqlx::query_scalar("SELECT status FROM indexer_deferred_decodes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "reverted");
}

#[sqlx::test(migrations = "./migrations")]
async fn capacity_failure_rolls_back_generic_effects_and_accounting(pool: PgPool) {
    let w = writer(&pool, false);
    w.persist_tx(&tx(1, None)).await.unwrap();
    sqlx::query("UPDATE indexer_deferred_decode_capacity SET byte_limit=1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(w.persist_tx(&tx(2, Some(1))).await.is_err());
    assert!(!w.has_utxo(&tx(2, None).transaction_id, 0).await.unwrap());
    let status: String = sqlx::query_scalar("SELECT status FROM covenant_utxos WHERE txid=$1")
        .bind(vec![1u8; 32])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "active");
    let summary = crate::deferred_decode::summary(&pool).await.unwrap();
    assert_eq!(summary.pending, 0);
    assert_eq!(summary.retained_bytes, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_hydration_preserves_first_evidence_and_does_not_expand_retention(pool: PgPool) {
    let w = writer(&pool, false);
    w.persist_tx(&tx(1, None)).await.unwrap();
    let original = tx(2, Some(1));
    w.persist_tx(&original).await.unwrap();
    let before = crate::deferred_decode::summary(&pool).await.unwrap();
    let mut hydrated = original.clone();
    hydrated.inputs[0].previous_outpoint_address = Some("display-only".into());
    hydrated.mass = "123".into();
    w.persist_tx(&hydrated).await.unwrap();
    let after = crate::deferred_decode::summary(&pool).await.unwrap();
    assert_eq!(before.retained_bytes, after.retained_bytes);
    assert_eq!(after.pending, 1);
    let saved: Value = sqlx::query_scalar("SELECT raw_transaction FROM indexer_deferred_decodes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(saved, serde_json::to_value(original).unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn unsupported_hint_cannot_bypass_input_authentication_or_missing_identity(pool: PgPool) {
    let w = writer(&pool, false);
    let mut parent = tx(1, None);
    parent.outputs[0].script_public_key = format!("aa20{}87", "99".repeat(32));
    w.persist_tx(&parent).await.unwrap();
    let err = w.persist_tx(&tx(2, Some(1))).await.unwrap_err();
    assert!(format!("{err:#}").contains("authenticated input"));
    let mut fake = tx(3, Some(77));
    fake.inputs[0].previous_outpoint_script = None;
    assert!(w.persist_tx(&fake).await.is_err());
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        0
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unsupported_replay_and_changed_raw_content_remain_pending(pool: PgPool) {
    let w = writer(&pool, false);
    w.persist_tx(&tx(1, None)).await.unwrap();
    w.persist_tx(&tx(2, Some(1))).await.unwrap();
    assert!(w.replay_deferred_tx(&tx(2, Some(1))).await.is_err());
    let upgraded = writer(&pool, true);
    let mut changed = tx(2, Some(1));
    changed.outputs[0].amount = 7;
    assert!(upgraded.replay_deferred_tx(&changed).await.is_err());
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        1
    );
    assert!(upgraded
        .confirm_deferred_decode(&proof(&tx(2, Some(1))))
        .await
        .is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn pending_family_does_not_capture_other_outputs_of_same_parent(pool: PgPool) {
    let w = writer(&pool, false);
    let other_script = format!("aa20{}87", hex::encode(blake2b_256(&[0x52])));
    let mut parent = tx(1, None);
    let mut other = parent.outputs[0].clone();
    other.index = 1;
    other.script_public_key = other_script.clone();
    parent.outputs.push(other);
    w.persist_tx(&parent).await.unwrap();
    w.persist_tx(&tx(2, Some(1))).await.unwrap();
    let mut independent = tx(3, Some(1));
    independent.inputs[0].previous_outpoint_index = "1".into();
    independent.inputs[0].previous_outpoint_script = Some(other_script.clone());
    independent.inputs[0].signature_script = "0152".into();
    independent.outputs[0].script_public_key = other_script;
    w.persist_batch(&[independent.clone()]).await.unwrap();
    assert_eq!(
        crate::deferred_decode::summary(&pool)
            .await
            .unwrap()
            .pending,
        1
    );
    assert!(
        crate::repo::actions_by_txid_if_decoded(&pool, &independent.transaction_id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        crate::repo::actions_by_txid_if_decoded(&pool, &tx(2, Some(1)).transaction_id)
            .await
            .unwrap()
            .is_none()
    );
}


struct BrokenParser { template: KnownTemplate, broken: bool }
impl TemplateDecoder for BrokenParser {
    fn template(&self) -> KnownTemplate { self.template }
    fn script_hash(&self) -> [u8;32] { blake2b_256(&[0x51]) }
    fn matches_reveal_script(&self, reveal: &[u8]) -> bool { reveal == [0x51] }
    fn decode_constructor(&self, _: &[u8]) -> Result<Value> {
        anyhow::ensure!(!self.broken, "fixture schema is not understood");
        Ok(serde_json::json!({"version":2}))
    }
    fn decode_state(&self, bytes: &[u8]) -> Result<Value> { self.decode_constructor(bytes) }
    fn decode_action(&self, _: &[u8]) -> Option<String> { Some("spend".into()) }
}
fn parser_writer(pool: &PgPool, template: KnownTemplate, broken: bool) -> PgPersister {
    let mut registry=DecoderRegistry::new();
    registry.register(Arc::new(BrokenParser {template,broken}));
    PgPersister::with_decoders(pool.clone(),registry).with_generic_bulk_persist(true)
}

#[sqlx::test(migrations = "./migrations")]
async fn shared_boundary_defers_multiple_decoders_and_replays_after_upgrade(pool: PgPool) {
    for (id,template) in [(10,KnownTemplate::TimeLockVault),(20,KnownTemplate::Escrow)] {
        let writer=parser_writer(&pool,template,true);
        writer.persist_tx(&tx(id,None)).await.unwrap();
        writer.persist_batch(&[tx(id+1,Some(id)),tx(id+2,None)]).await.unwrap();
        assert!(writer.has_utxo(&tx(id+2,None).transaction_id,0).await.unwrap());
        let pending:i64=sqlx::query_scalar("SELECT count(*) FROM indexer_deferred_decodes WHERE txid=$1 AND status='pending'")
            .bind(vec![id+1;32]).fetch_one(&pool).await.unwrap();
        assert_eq!(pending,1);
        let decoded:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1 AND decoded_args IS NOT NULL")
            .bind(vec![id+1;32]).fetch_one(&pool).await.unwrap();
        assert_eq!(decoded,0,"failed parser must not leave partial semantic effects");
        assert!(writer.replay_deferred_tx(&tx(id+1,Some(id))).await.is_err());
        let upgraded=parser_writer(&pool,template,false);
        upgraded.persist_tx(&tx(id+3,Some(id+1))).await.unwrap();
        assert!(upgraded.replay_deferred_tx(&tx(id+3,Some(id+1))).await.is_err());
        upgraded.replay_deferred_tx(&tx(id+1,Some(id))).await.unwrap();
        upgraded.confirm_deferred_decode(&proof(&tx(id+1,Some(id)))).await.unwrap();
        upgraded.replay_deferred_tx(&tx(id+3,Some(id+1))).await.unwrap();
        upgraded.confirm_deferred_decode(&proof(&tx(id+3,Some(id+1)))).await.unwrap();
    }
    assert_eq!(crate::deferred_decode::summary(&pool).await.unwrap().pending,0);
}

#[sqlx::test(migrations = "./migrations")]
async fn generic_parser_deferral_rolls_back_all_writes_if_retention_fails(pool: PgPool) {
    let writer=parser_writer(&pool,KnownTemplate::TimeLockVault,true);
    writer.persist_tx(&tx(1,None)).await.unwrap();
    sqlx::query("UPDATE indexer_deferred_decode_capacity SET byte_limit=1").execute(&pool).await.unwrap();
    assert!(writer.persist_tx(&tx(2,Some(1))).await.is_err());
    let status:String=sqlx::query_scalar("SELECT status FROM covenant_utxos WHERE txid=$1").bind(vec![1u8;32]).fetch_one(&pool).await.unwrap();
    assert_eq!(status,"active");
    assert!(!writer.has_utxo(&tx(2,None).transaction_id,0).await.unwrap());
    assert_eq!(crate::deferred_decode::summary(&pool).await.unwrap().pending,0);
}

#[sqlx::test(migrations = "./migrations")]
async fn sql_errors_are_never_reclassified_as_decoder_failures(pool: PgPool) {
    let writer=parser_writer(&pool,KnownTemplate::TimeLockVault,false);
    writer.persist_tx(&tx(1,None)).await.unwrap();
    sqlx::raw_sql("CREATE FUNCTION reject_decode_action() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture SQL failure'; END $$; CREATE TRIGGER reject_decode_action BEFORE INSERT ON covenant_actions FOR EACH ROW EXECUTE FUNCTION reject_decode_action();").execute(&pool).await.unwrap();
    assert!(writer.persist_tx(&tx(2,Some(1))).await.is_err());
    assert_eq!(crate::deferred_decode::summary(&pool).await.unwrap().pending,0);
    let status:String=sqlx::query_scalar("SELECT status FROM covenant_utxos WHERE txid=$1").bind(vec![1u8;32]).fetch_one(&pool).await.unwrap();
    assert_eq!(status,"active");
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_schedule_preserves_age_and_coverage_and_retries_after_upgrade(pool: PgPool) {
    let writer=parser_writer(&pool,KnownTemplate::TimeLockVault,true);
    writer.persist_tx(&tx(1,None)).await.unwrap();
    writer.persist_tx(&tx(2,Some(1))).await.unwrap();
    let before=crate::deferred_decode::summary(&pool).await.unwrap();
    let (seq,_)=crate::deferred_decode::claim_due(&pool,100).await.unwrap().unwrap();
    assert!(crate::deferred_decode::claim_due(&pool,101).await.unwrap().is_none());
    crate::deferred_decode::record_retry_error(&pool,seq,"still unsupported").await.unwrap();
    let after=crate::deferred_decode::summary(&pool).await.unwrap();
    assert_eq!(before.generation,after.generation,"scheduling must not invalidate API reads");
    assert_eq!(before.oldest_pending_at_ms,after.oldest_pending_at_ms);
    assert_eq!(before.retained_bytes,after.retained_bytes);
    assert_eq!(after.pending,1);
    sqlx::query("UPDATE indexer_deferred_decodes SET last_attempt_revision='old-decoder'").execute(&pool).await.unwrap();
    assert!(crate::deferred_decode::claim_due(&pool,102).await.unwrap().is_some());
    assert!(crate::deferred_decode::claim_due(&pool,103).await.unwrap().is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn large_generic_eligible_batch_cannot_bypass_parser_deferral(pool: PgPool) {
    let writer=parser_writer(&pool,KnownTemplate::TimeLockVault,true);
    let mut children=Vec::new();
    for id in 30..46 { writer.persist_tx(&tx(id,None)).await.unwrap(); children.push(tx(id+32,Some(id))); }
    writer.persist_batch(&children).await.unwrap();
    assert_eq!(crate::deferred_decode::summary(&pool).await.unwrap().pending,16);
}

#[test]
fn application_parser_wrapper_preserves_integrity_failures() {
    let error=anyhow::anyhow!("authenticated commitment mismatch")
        .context(tn12_indexer_decoder::IntegrityFailure("fixture"));
    let wrapped=tn12_indexer_decoder::interpretation::<()>("constructor",Err(error)).unwrap_err();
    assert!(wrapped.downcast_ref::<tn12_indexer_decoder::IntegrityFailure>().is_some());
    assert!(wrapped.downcast_ref::<tn12_indexer_decoder::InterpretationFailure>().is_none());
}

struct LaterParser;
impl TemplateDecoder for LaterParser {
    fn template(&self) -> KnownTemplate { KnownTemplate::TimeLockVault }
    fn script_hash(&self) -> [u8;32] { blake2b_256(&[0x51]) }
    fn matches_reveal_script(&self, reveal:&[u8]) -> bool { reveal == [0x51] || reveal == [0x52] }
    fn decode_constructor(&self, reveal:&[u8]) -> Result<Value> {
        anyhow::ensure!(reveal != [0x52], "second input interpretation failed");
        Ok(serde_json::json!({"version":1}))
    }
    fn decode_state(&self, bytes:&[u8]) -> Result<Value> { self.decode_constructor(bytes) }
    fn decode_action(&self,_:&[u8]) -> Option<String> { Some("spend".into()) }
}
#[sqlx::test(migrations = "./migrations")]
async fn later_input_failure_removes_earlier_classification_and_actions(pool:PgPool) {
    let mut registry=DecoderRegistry::new();registry.register(Arc::new(LaterParser));
    let writer=PgPersister::with_decoders(pool.clone(),registry);
    writer.persist_tx(&tx(1,None)).await.unwrap();
    let second_script=format!("aa20{}87",hex::encode(blake2b_256(&[0x52])));
    let mut second=tx(2,None);second.outputs[0].script_public_key=second_script.clone();
    writer.persist_tx(&second).await.unwrap();
    let mut child=tx(3,Some(1));
    child.inputs.push(RestTxInput {previous_outpoint_hash:second.transaction_id,previous_outpoint_index:"0".into(),signature_script:"0152".into(),previous_outpoint_script:Some(second_script),previous_outpoint_amount:Some(1),..Default::default()});
    writer.persist_tx(&child).await.unwrap();
    let classified:i64=sqlx::query_scalar("SELECT count(*) FROM covenants WHERE template_name IS NOT NULL").fetch_one(&pool).await.unwrap();
    assert_eq!(classified,0,"first input classification must roll back with second input failure");
    let decoded:i64=sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE txid=$1 AND decoded_args IS NOT NULL").bind(vec![3u8;32]).fetch_one(&pool).await.unwrap();
    assert_eq!(decoded,0);
    let retained:Value=sqlx::query_scalar("SELECT raw_transaction FROM indexer_deferred_decodes WHERE status='pending'").fetch_one(&pool).await.unwrap();
    assert_eq!(retained,serde_json::to_value(&child).unwrap());
}

#[test]
fn shared_witness_integer_narrowing_is_recoverable() {
    use tn12_indexer_decoder::kcc20::{item_integer, ScriptItem};
    for value in [-1, 256] {
        let error = item_integer::<u8>(&[ScriptItem::Int(value)], 0).unwrap_err();
        assert!(error.downcast_ref::<tn12_indexer_decoder::InterpretationFailure>().is_some());
    }
    assert_eq!(item_integer::<u8>(&[ScriptItem::Int(255)], 0).unwrap(), 255);
}

#[test]
fn audited_dispatchers_retain_unknown_actions() {
    use tn12_indexer_decoder::{api_payment_channel::ApiPaymentChannelDecoder, kcom_claim::KcomClaimDecoder, kcom_vesting::KcomVestingDecoder};
    let decoders: Vec<Box<dyn TemplateDecoder>> = vec![
        Box::new(ApiPaymentChannelDecoder::new([0; 32])),
        Box::new(KcomClaimDecoder::new(KnownTemplate::KcomVault)),
        Box::new(KcomVestingDecoder),
    ];
    for decoder in decoders {
        let error = decoder.decode_action_checked(&[0x01, 0x51]).unwrap_err();
        assert!(error.downcast_ref::<tn12_indexer_decoder::InterpretationFailure>().is_some());
    }
}
