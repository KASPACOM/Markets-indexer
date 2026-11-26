use super::*;
use crate::Persister;
use sqlx::PgPool;

fn captured() -> RestTransaction {
    serde_json::from_str(include_str!(
        "../../tests/fixtures/tn10-native-genesis-burst.json"
    ))
    .unwrap()
}

async fn snapshot(pool: &PgPool) -> Value {
    sqlx::query_scalar(r#"SELECT jsonb_build_object(
      'covenants',(SELECT jsonb_agg(to_jsonb(t) ORDER BY covenant_id) FROM covenants t),
      'utxos',(SELECT jsonb_agg(to_jsonb(t) ORDER BY txid,vout) FROM covenant_utxos t),
      'actions',(SELECT jsonb_agg(to_jsonb(t)-'id' ORDER BY covenant_id,txid,action) FROM covenant_actions t),
      'summaries',(SELECT jsonb_agg(to_jsonb(t)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_summaries t),
      'action_summaries',(SELECT jsonb_agg(to_jsonb(t)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_action_summaries t),
      'template_summaries',(SELECT jsonb_agg(to_jsonb(t)-'updated_at_ms' ORDER BY to_jsonb(t)::text) FROM covenant_template_summaries t)
    )"#).fetch_one(pool).await.unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn captured_native_genesis_bulk_matches_scalar_duplicate_reorg_and_restore(pool: PgPool) {
    let tx = captured();
    let scalar = PgPersister::new(pool.clone());
    scalar.persist_tx(&tx).await.unwrap();
    let expected = snapshot(&pool).await;
    let cid: String = sqlx::query_scalar("SELECT encode(covenant_id,'hex') FROM covenants")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        cid,
        "73f224d972ce346285ddc0985a7034bba6889a8d7779cbdd461e0f5817e86adb"
    );
    let block = hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap();
    scalar.revert_block(&block).await.unwrap();
    let removed = snapshot(&pool).await;
    sqlx::query("TRUNCATE covenants,blocks RESTART IDENTITY CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    let bulk = PgPersister::new(pool.clone()).with_native_genesis_bulk(true);
    for _ in 0..2 {
        assert!(bulk
            .try_persist_generic_batch(std::slice::from_ref(&tx))
            .await
            .unwrap()
            .is_some());
        assert_eq!(snapshot(&pool).await, expected);
    }
    bulk.revert_block(&block).await.unwrap();
    assert_eq!(snapshot(&pool).await, removed);
    assert!(bulk
        .try_persist_generic_batch(std::slice::from_ref(&tx))
        .await
        .unwrap()
        .is_some());
    assert_eq!(snapshot(&pool).await, expected);
}

#[sqlx::test(migrations = "./migrations")]
async fn native_genesis_is_opt_in_and_retains_acceptance_guards(pool: PgPool) {
    let tx = captured();
    let off = PgPersister::new(pool.clone());
    assert!(off
        .try_persist_generic_batch(std::slice::from_ref(&tx))
        .await
        .unwrap()
        .is_none());
    let on = off.with_native_genesis_bulk(true);
    on.try_persist_generic_batch(std::slice::from_ref(&tx))
        .await
        .unwrap()
        .unwrap();
    let baseline = snapshot(&pool).await;
    let mut moved = tx.clone();
    moved.accepting_block_hash = Some("99".repeat(32));
    assert!(on.try_persist_generic_batch(&[moved]).await.is_err());
    assert_eq!(snapshot(&pool).await, baseline);
    let mut changed = tx.clone();
    changed.outputs[0].amount += 1;
    assert!(on.try_persist_generic_batch(&[changed]).await.is_err());
    assert_eq!(snapshot(&pool).await, baseline);
    sqlx::query("UPDATE covenants SET claimed_template='KCC20'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(on.try_persist_generic_batch(&[tx]).await.unwrap().is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn native_continuation_and_legacy_rekey_require_scalar_writer(pool: PgPool) {
    let tx = captured();
    let writer = PgPersister::new(pool.clone()).with_native_genesis_bulk(true);
    // Seed the exact old script-hash identity that the scalar writer rekeys.
    let mut legacy = tx.clone();
    legacy.version = 0;
    legacy.payload = None;
    writer.persist_tx(&legacy).await.unwrap();
    assert!(writer
        .try_persist_generic_batch(std::slice::from_ref(&tx))
        .await
        .unwrap()
        .is_none());
    writer.persist_tx(&tx).await.unwrap();
    let mut continuation = tx.clone();
    continuation.transaction_id = "ac".repeat(32);
    continuation.inputs[0].previous_outpoint_hash = tx.transaction_id.clone();
    continuation.inputs[0].previous_outpoint_index = "0".into();
    // Even when the source omitted prevout metadata, DB ownership rejects the
    // genesis fast path before it can derive a replacement identity.
    assert!(writer
        .try_persist_generic_batch(&[continuation])
        .await
        .unwrap()
        .is_none());
}

#[test]
fn native_metadata_and_protocol_guards() {
    let registry = crate::persist::default_registry();
    let tx = captured();
    assert!(is_writer_candidate(&tx, &registry, true));
    assert!(!is_writer_candidate(&tx, &registry, false));
    let mut known_input = tx.clone();
    known_input.inputs[0].previous_outpoint_script = Some(tx.outputs[0].script_public_key.clone());
    assert!(!is_writer_candidate(&known_input, &registry, true));
    let mut claimed = tx.clone();
    claimed.payload = Some(hex::encode(r#"{"tn10":{"v":1,"tmpl":"KCC20","args":[]}}"#));
    assert!(crate::claim::parse_payload_envelope(claimed.payload.as_deref().unwrap()).is_some());
    assert!(!is_writer_candidate(&claimed, &registry, true));
    let mut bound = tx.clone();
    bound.outputs[0].covenant_id = Some("44".repeat(32));
    assert!(!is_writer_candidate(&bound, &registry, true));
    let artifact: Value = serde_json::from_str(include_str!(
        "../../../tn12-indexer-decoder/fixtures/kcc20/KCC20.placeholder.json"
    ))
    .unwrap();
    let reveal: Vec<u8> = serde_json::from_value(artifact["bytecode"].clone()).unwrap();
    let mut recognized = tx.clone();
    recognized.inputs[0].signature_script = hex::encode(push_reveal(&reveal));
    assert!(!is_writer_candidate(&recognized, &registry, true));
    let mut unknown_version = tx.clone();
    unknown_version.version = 2;
    assert!(!is_writer_candidate(&unknown_version, &registry, true));
    let mut extra = tx.clone();
    let mut output = tx.outputs[0].clone();
    output.index = 2;
    extra.outputs.push(output);
    assert!(!is_writer_candidate(&extra, &registry, true));
}

#[tokio::test]
async fn native_runtime_configuration_is_strict_and_requires_bulk() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .unwrap();
    for (flag, bulk, expected) in [
        (None, None, Some(false)),
        (Some("0"), None, Some(false)),
        (Some("1"), None, None),
        (Some("true"), Some("1"), None),
        (Some("1"), Some("1"), Some(true)),
    ] {
        let result = PgPersister::for_wrpc_settings(pool.clone(), "testnet-10", |key| match key {
            "TN12_WRPC_GENERIC_BULK_PERSIST" => bulk.map(str::to_owned),
            "TN12_WRPC_NATIVE_GENESIS_BULK" => flag.map(str::to_owned),
            _ => None,
        });
        if let Some(expected) = expected {
            assert_eq!(result.unwrap().native_genesis_bulk, expected);
        } else {
            assert!(result.is_err());
        }
    }
}

fn push_reveal(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x4d];
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

#[tokio::test]
async fn native_runtime_preserves_cooperative_live_priority() {
    let pool=sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://unused:unused@127.0.0.1:1/unused").unwrap();
    let writer=PgPersister::for_wrpc_settings(pool,"testnet-10",|key| {
        matches!(key,"TN12_WRPC_GENERIC_BULK_PERSIST"|"TN12_WRPC_NATIVE_GENESIS_BULK"|"TN12_WRITER_LIVE_PRIORITY").then(|| "1".to_owned())
    }).unwrap();
    assert!(writer.native_genesis_bulk);
    assert!(writer.writer_priority==crate::persist::live_pressure::WriterPriority::Live);
}
