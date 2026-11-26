//! Synthetic accepted-shape replay. This proves indexer persistence, not TN10 consensus acceptance.
use serde_json::{json, Value};
use sqlx::PgPool;
use tn12_indexer_core::{blake2b_256, RestTransaction};
use tn12_indexer_db::{repo, Persister, PgPersister};
use tn12_indexer_decoder::registry::DecoderRegistry;

const ABI: &str = include_str!(
    "../../../wallet-lab/vendor/kcom-claim-capabilities/campaign-entitlements/program-abi.json"
);
const FACTORY_VECTOR: &str =
    include_str!("../../tn12-indexer-decoder/fixtures/kcom-claim-factory-vectors.json");
const RECOVERY_VECTOR: &str =
    include_str!("../../tn12-indexer-decoder/fixtures/kcom-claim-recovery-vectors.json");
const OPEN_VECTOR: &str =
    include_str!("../../tn12-indexer-decoder/fixtures/kcom-claim-open-vectors.json");
const FUND_VECTOR: &str =
    include_str!("../../tn12-indexer-decoder/fixtures/kcom-claim-fund-vectors.json");
const TN10_FIRST: &str =
    include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-token-and-main.json");
const TN10_SECOND: &str =
    include_str!("../../../fixtures/kcom-claim-tn10-live/ordered-no-long.json");

fn accepted_campaign_transactions() -> Vec<RestTransaction> {
    let mut first: Vec<RestTransaction> = serde_json::from_str(TN10_FIRST).unwrap();
    let second: Vec<RestTransaction> = serde_json::from_str(TN10_SECOND).unwrap();
    assert_eq!((first.len(), second.len()), (33, 29));
    first.extend(second);
    first
}

fn campaign_actor_reveal(abi: &Value, name: &str) -> Vec<u8> {
    let contract = &abi["contracts"][name];
    let mut reveal: Vec<u8> = contract["compiled"]["bytecode"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as u8)
        .collect();
    let span = &contract["compiled"]["state_span"];
    let start = span["offset"].as_u64().unwrap() as usize;
    let len = span["len"].as_u64().unwrap() as usize;
    let mut offset = start;
    for field in contract["runtime_state"]["fields"].as_array().unwrap() {
        let field_len = usize::from(reveal[offset]);
        let actor = match field["name"].as_str().unwrap() {
            "gen__kcom_claim_shard_template" => Some("KCOMClaimShard"),
            "gen__kcom_settlement_template" => Some("KCOMSettlement"),
            "gen__kcom_factory_template" => Some("KCOMFactory"),
            "gen__kcom_vault_template" => Some("KCOMVault"),
            "gen__kcom_claim_commitment_template" => Some("KCOMClaimCommitment"),
            "gen__kcom_entitlement_template" => Some("KCOMEntitlement"),
            _ => None,
        };
        if let Some(actor) = actor {
            let hash: Vec<u8> = abi["contracts"][actor]["compiled"]["template_hash"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u8)
                .collect();
            assert_eq!(field_len, hash.len(), "{name} {actor} commitment width");
            reveal[offset + 1..offset + 1 + field_len].copy_from_slice(&hash);
        }
        offset += 1 + field_len;
    }
    assert_eq!(offset, start + len, "{name} state span");
    reveal
}

#[test]
fn campaign_actor_fixture_reveals_are_authenticated() {
    let abi: Value = serde_json::from_str(ABI).unwrap();
    let registry = tn12_indexer_decoder::default_registry();
    for name in [
        "KCOMSettlement",
        "KCOMClaimCommitment",
        "KCOMEntitlement",
    ] {
        let raw: Vec<u8> = abi["contracts"][name]["compiled"]["bytecode"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u8)
            .collect();
        assert!(
            registry.find_for_reveal(&raw).is_none(),
            "{name} placeholder commitments must fail closed"
        );
        let reveal = campaign_actor_reveal(&abi, name);
        assert_eq!(
            registry.find_for_reveal(&reveal).map(|decoder| decoder.name()),
            Some(name),
            "{name} authenticated fixture"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn accepted_tn10_selection_replay_repairs_existing_unknown_action(pool: PgPool) {
    let transactions = accepted_campaign_transactions();
    let graph = hex::decode("9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447").unwrap();
    let selected = &transactions[11];
    let selected_txid = hex::decode(&selected.transaction_id).unwrap();
    let selected_block = hex::decode(selected.accepting_block_hash.as_ref().unwrap()).unwrap();
    let old_writer = PgPersister::with_decoders(pool.clone(), DecoderRegistry::new());
    for tx in &transactions[..=11] {
        old_writer.persist_tx(tx).await.unwrap();
    }
    let before: (Option<String>, Option<Value>) = sqlx::query_as(
        "SELECT entrypoint, decoded_args FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND action='spend'",
    ).bind(&graph).bind(&selected_txid).fetch_one(&pool).await.unwrap();
    assert_eq!(before, (None, None));

    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for tx in &transactions[..=11] {
        writer.persist_tx(tx).await.unwrap();
    }
    let repaired: (Option<String>, Option<Value>) = sqlx::query_as(
        "SELECT entrypoint, decoded_args FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND action='spend'",
    ).bind(&graph).bind(&selected_txid).fetch_one(&pool).await.unwrap();
    assert_eq!(repaired.0.as_deref(), Some("select"));
    assert_eq!(repaired.1.as_ref().unwrap()["modeName"], "KCOMClaimShard");
    assert!(repaired.1.as_ref().unwrap()["originalAuthority"].as_str().is_some());
    let commitment: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1 AND covenant_id=$2",
    ).bind(&selected_txid).bind(&graph).fetch_one(&pool).await.unwrap();
    assert_eq!(commitment["modeName"], "KCOMClaimCommitment");

    writer.persist_tx(selected).await.unwrap();
    let action_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND action='spend'",
    ).bind(&graph).bind(&selected_txid).fetch_one(&pool).await.unwrap();
    assert_eq!(action_count, 1);
    writer.revert_block(&selected_block).await.unwrap();
    writer.persist_tx(selected).await.unwrap();
    let restored: (Option<String>, Option<Value>) = sqlx::query_as(
        "SELECT entrypoint, decoded_args FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND action='spend'",
    ).bind(&graph).bind(&selected_txid).fetch_one(&pool).await.unwrap();
    assert_eq!(restored, repaired);
}

#[sqlx::test(migrations = "./migrations")]
async fn both_accepted_tn10_campaigns_replay_without_duplicate_actions(pool: PgPool) {
    let transactions = accepted_campaign_transactions();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for tx in &transactions {
        writer.persist_tx(tx).await.unwrap_or_else(|error|
            panic!("accepted replay {} failed: {error:#}", tx.transaction_id));
    }
    let initial_graph_states: Vec<Value> = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout IN (0,1) ORDER BY vout",
    ).bind(hex::decode("5949693cade552fbfe06766b332b29a736da355bb96729d5a16702ff29533f49").unwrap())
        .fetch_all(&pool).await.unwrap();
    assert_eq!(initial_graph_states.len(), 2);
    assert_eq!(initial_graph_states[0]["modeName"], "KCOMFactory");
    assert_eq!(initial_graph_states[1]["modeName"], "KCOMVault");
    let genesis_actions: Vec<(String, String)> = sqlx::query_as(
        "SELECT action, outputs->>'vout' FROM covenant_actions WHERE txid=$1 \
         AND covenant_id=$2 AND action IN ('deploy','continuation') ORDER BY outputs->>'vout'",
    ).bind(hex::decode("5949693cade552fbfe06766b332b29a736da355bb96729d5a16702ff29533f49").unwrap())
        .bind(hex::decode("9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447").unwrap())
        .fetch_all(&pool).await.unwrap();
    assert_eq!(genesis_actions, vec![("deploy".into(), "0".into()),
        ("continuation".into(), "1".into())]);
    let unresolved: Vec<(String, String)> = sqlx::query_as(
        "SELECT encode(txid,'hex'), encode(covenant_id,'hex') FROM covenant_actions \
         WHERE txid = ANY($1) AND action='spend' AND entrypoint IS NULL",
    ).bind(transactions.iter().map(|tx| hex::decode(&tx.transaction_id).unwrap()).collect::<Vec<_>>())
        .fetch_all(&pool).await.unwrap();
    assert!(unresolved.is_empty(), "accepted campaign spends remain undecoded: {unresolved:?}");
    let first_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT encode(txid,'hex'), count(*) FROM covenant_actions WHERE txid = ANY($1) GROUP BY txid ORDER BY txid",
    ).bind(transactions.iter().map(|tx| hex::decode(&tx.transaction_id).unwrap()).collect::<Vec<_>>())
        .fetch_all(&pool).await.unwrap();
    assert!(first_counts.iter().map(|(_, count)| count).sum::<i64>() >= 61,
        "each accepted campaign transaction must leave indexed evidence");
    for tx in &transactions {
        writer.persist_tx(tx).await.unwrap();
    }
    let second_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT encode(txid,'hex'), count(*) FROM covenant_actions WHERE txid = ANY($1) GROUP BY txid ORDER BY txid",
    ).bind(transactions.iter().map(|tx| hex::decode(&tx.transaction_id).unwrap()).collect::<Vec<_>>())
        .fetch_all(&pool).await.unwrap();
    assert_eq!(second_counts, first_counts);
    for (graph_id, selected, allocated) in [
        ("9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447", 3, "997"),
        ("cb94c0e726167ed09120ddb9555f9ae359c4b1634c4998364f0b738617b0abf5", 2, "388"),
    ] {
        let graph = hex::decode(graph_id).unwrap();
        let matched: (String, String) = sqlx::query_as(
            "SELECT classification_kind, classification_status FROM covenants WHERE covenant_id=$1",
        ).bind(&graph).fetch_one(&pool).await.unwrap();
        assert_eq!(matched, ("covenant".into(), "matched".into()));
        let active_vault: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND status='active' AND state->>'modeName'='KCOMVault'",
        ).bind(&graph).fetch_one(&pool).await.unwrap();
        assert_eq!(active_vault, 1);
        let campaign = repo::kcom_campaign(&pool, graph_id).await.unwrap().unwrap();
        assert_eq!(campaign.lifecycle, "settled");
        assert_eq!(campaign.budget_raw, "1000");
        assert_eq!(campaign.settled_raw, allocated);
        assert_eq!(campaign.selected_count, selected);
        assert_eq!(campaign.settled_count, selected);
        assert_eq!(campaign.activated_raw, allocated);
        assert_eq!(campaign.liability_raw, "0");
        assert_eq!(campaign.reserve_raw, "0");
        assert_eq!(campaign.recovered_raw,
            if graph_id.starts_with("9d4d") { "3" } else { "612" });
    }
    let final_receipt: Value = serde_json::from_str(include_str!(
        "../../../docs/evidence/kcom-claim-tn10-no-long-full-20261030.json"
    )).unwrap();
    let token_id = hex::decode(final_receipt["tokenId"].as_str().unwrap()).unwrap();
    let token_rows: Vec<(String, i32, i64, Value)> = sqlx::query_as(
        "SELECT encode(txid,'hex'), vout, amount_sompi, state FROM covenant_utxos WHERE covenant_id=$1 AND status='active'",
    ).bind(&token_id).fetch_all(&pool).await.unwrap();
    let expected = final_receipt["tokenConservation"]["currentUtxos"].as_array().unwrap();
    assert_eq!(token_rows.len(), expected.len(), "canonical active token UTXO count");
    let mut indexed_total = 0u64;
    for (txid, vout, native, state) in &token_rows {
        let outpoint = format!("{txid}:{vout}");
        let proof = expected.iter().find(|entry| entry["outpoint"].as_str() == Some(outpoint.as_str()))
            .unwrap_or_else(|| panic!("unexpected indexed canonical outpoint {outpoint}"));
        assert_eq!(state["amount"], proof["amountRaw"]);
        assert_eq!(state["owner"], proof["owner"]);
        assert_eq!(state["ownerScheme"], proof["ownerScheme"]);
        assert_eq!(state["extensionCommitment"], proof["extensionCommitment"]);
        assert_eq!(native.to_string(), proof["reserveSompi"].as_str().unwrap());
        indexed_total += state["amount"].as_str().unwrap().parse::<u64>().unwrap();
    }
    assert_eq!(indexed_total.to_string(), final_receipt["tokenConservation"]["currentActiveRaw"].as_str().unwrap());
    let main_receipt: Value = serde_json::from_str(include_str!(
        "../../../docs/evidence/kcom-claim-tn10-main-full-20261030.json"
    )).unwrap();
    for proof in [&final_receipt, &main_receipt] {
        for category in ["beneficiaryReceipts", "positionReserves", "treasuryRecovery"] {
            let items = if category == "treasuryRecovery" {
                vec![proof["tokenConservation"][category].clone()]
            } else {
                proof["tokenConservation"][category].as_array().unwrap().clone()
            };
            for item in items {
                assert!(expected.iter().any(|active| active["outpoint"] == item["outpoint"]
                    && active["amountRaw"] == item["amountRaw"]
                    && active["owner"] == item["owner"]),
                    "{category} is absent from canonical active token proof");
            }
        }
    }
    let short = repo::kcom_participant(
        &pool,
        "9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447",
        "24a150dbc3a7b3a137bfcf6e8e634049cc4e47c833b1c160b1ce6b099988c1e6",
    ).await.unwrap().unwrap();
    assert_eq!(short.lifecycle, "active");
    assert_eq!(short.allocation_raw.as_deref(), Some("27"));
    assert_eq!(short.released_raw.as_deref(), Some("2"));
    assert_eq!(short.remaining_raw.as_deref(), Some("25"));
    assert_eq!(short.beneficiary,
        "33dabe26675a8e0c067eda92183400f6b3e8c9022bf41813ac3fdc9d84489012");
    assert_eq!(short.position_id.as_deref(),
        Some("fa4f0c3b2c1b3c4bfb0a809435054804056d19727647bcca056cea6379f1c265"));
    assert!(repo::kcom_participant(
        &pool,
        "9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447",
        &"00".repeat(32),
    ).await.unwrap().is_none());
    let mut reverted = std::collections::HashSet::new();
    for accepted in transactions.iter().rev() {
        let block = accepted.accepting_block_hash.as_ref().unwrap();
        if reverted.insert(block.clone()) {
            writer.revert_block(&hex::decode(block).unwrap()).await.unwrap();
        }
    }
    let after_rollback: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE txid = ANY($1)",
    ).bind(transactions.iter().map(|tx| hex::decode(&tx.transaction_id).unwrap()).collect::<Vec<_>>())
        .fetch_one(&pool).await.unwrap();
    assert_eq!(after_rollback, 0);
    for accepted in &transactions {
        writer.persist_tx(accepted).await.unwrap();
    }
    let after_reapply: Vec<(String, i64)> = sqlx::query_as(
        "SELECT encode(txid,'hex'), count(*) FROM covenant_actions WHERE txid = ANY($1) GROUP BY txid ORDER BY txid",
    ).bind(transactions.iter().map(|tx| hex::decode(&tx.transaction_id).unwrap()).collect::<Vec<_>>())
        .fetch_all(&pool).await.unwrap();
    assert_eq!(after_reapply, first_counts);
    sqlx::query(
        "DELETE FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND action='spend' AND entrypoint='select'",
    ).bind(hex::decode("9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447").unwrap())
        .bind(hex::decode("8d7b57511652e2b4290bc6b728c6908aeb5ca3cd6ea5494496b1ce47276c9606").unwrap())
        .execute(&pool).await.unwrap();
    assert!(repo::kcom_campaign(
        &pool, "9d4da3f271e742cbbee771fe0dd198e953a3cd8c148f87fc9a0bc76e7841e447",
    ).await.is_err(), "missing accepted selection history must fail closed");
}

fn transaction(value: Value) -> RestTransaction {
    serde_json::from_value(value).unwrap()
}

fn push_reveal(tag: &str, reveal: &[u8]) -> String {
    let mut signature = vec![4];
    signature.extend(hex::decode(tag).unwrap());
    signature.push(0x4d); // OP_PUSHDATA2
    signature.extend(u16::try_from(reveal.len()).unwrap().to_le_bytes());
    signature.extend(reveal);
    hex::encode(signature)
}

// Supply complete transfer arrays so this fixture reaches successor integrity
// checks. A selector-only witness now correctly becomes pending interpretation.
fn recovery_token_signature(case: &Value, reveal: &[u8]) -> String {
    let mut amounts = case["surplusRaw"].as_str().unwrap().parse::<i64>().unwrap().to_le_bytes().to_vec();
    let mut owners = hex::decode(case["vaultState"]["treasury"].as_str().unwrap()).unwrap();
    let mut schemes = vec![case["vaultState"]["treasury_scheme"].as_u64().unwrap() as u8];
    if case["variant"] == "partial" {
        amounts.extend(case["remainingLiabilityRaw"].as_str().unwrap().parse::<i64>().unwrap().to_le_bytes());
        owners.extend(hex::decode(case["graphId"].as_str().unwrap()).unwrap());
        schemes.push(4);
    }
    let count = schemes.len();
    let extension = hex::decode(case["vaultState"]["extension"].as_str().unwrap()).unwrap();
    let fields = [amounts, owners, schemes, vec![0; count], vec![0; 32 * count], extension.repeat(count)];
    let mut signature = Vec::new();
    for bytes in fields {
        signature.push(0x4d);
        signature.extend(u16::try_from(bytes.len()).unwrap().to_le_bytes());
        signature.extend(bytes);
    }
    signature.extend(hex::decode(push_reveal("79c71c23", reveal)).unwrap());
    hex::encode(signature)
}

fn opening_transactions() -> (RestTransaction, RestTransaction, Vec<u8>, Vec<u8>) {
    let vector: Value = serde_json::from_str(OPEN_VECTOR).unwrap();
    let abi: Value = serde_json::from_str(ABI).unwrap();
    let case = &vector["case"];
    let graph = hex::decode(case["graphId"].as_str().unwrap()).unwrap();
    let source_block = hex::decode("a5".repeat(32)).unwrap();
    let spend_block = hex::decode("a6".repeat(32)).unwrap();
    let source = transaction(json!({
        "transaction_id": "a4".repeat(32), "version": 1, "is_accepted": true,
        "accepting_block_hash": hex::encode(&source_block),
        "accepting_block_blue_score": 100, "accepting_block_time": 1790000000000u64,
        "inputs": [{
            "previous_outpoint_hash": "a3".repeat(32), "previous_outpoint_index": "0",
            "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
            "signature_script": "",
        }],
        "outputs": case["inputs"].as_array().unwrap().iter().enumerate().map(|(index, input)| json!({
            "index": index,
            "amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "script_public_key": input["scriptPublicKeyHex"],
            "script_public_key_address": format!("kaspatest:p{:064x}", index + 900),
            "covenant_authorizing_input": 0, "covenant_id": case["graphId"],
        })).collect::<Vec<_>>(),
    }));
    let reveals = ["factoryRevealHex", "vaultRevealHex"];
    let actors = ["KCOMFactory", "KCOMVault"];
    let spend = transaction(json!({
        "transaction_id": case["localTransactionId"], "version": 1, "is_accepted": true,
        "accepting_block_hash": hex::encode(&spend_block),
        "accepting_block_blue_score": 101, "accepting_block_time": 1790000001000u64,
        "inputs": case["inputs"].as_array().unwrap().iter().enumerate().map(|(index, input)| {
            let reveal = hex::decode(case[reveals[index]].as_str().unwrap()).unwrap();
            let tag = abi["contracts"][actors[index]]["entries"]["open"]["dispatch_tag"]
                .as_str().unwrap();
            json!({
                "previous_outpoint_hash": "a4".repeat(32), "previous_outpoint_index": index.to_string(),
                "previous_outpoint_script": input["scriptPublicKeyHex"],
                "previous_outpoint_amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
                "signature_script": push_reveal(tag, &reveal),
            })
        }).collect::<Vec<_>>(),
        "outputs": case["outputs"].as_array().unwrap().iter().map(|output| json!({
            "index": output["index"],
            "amount": output["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "script_public_key": output["scriptPublicKeyHex"],
            "script_public_key_address": format!("kaspatest:p{:064x}", output["index"].as_u64().unwrap() + 910),
            "covenant_authorizing_input": output["authorizingInput"],
            "covenant_id": output["covenantId"],
        })).collect::<Vec<_>>(),
    }));
    (source, spend, graph, spend_block)
}

#[sqlx::test(migrations = "./migrations")]
async fn opened_vault_is_inferred_before_reveal_and_restored_after_reorg(pool: PgPool) {
    let (source, spend, graph, spend_block) = opening_transactions();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&source).await.unwrap();
    let initial: Option<Value> = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1",
    ).bind(hex::decode(&source.transaction_id).unwrap()).fetch_one(&pool).await.unwrap();
    assert!(initial.is_none());
    writer.persist_tx(&spend).await.unwrap();
    let opened: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1 AND covenant_id=$2",
    ).bind(hex::decode(&spend.transaction_id).unwrap()).bind(&graph)
        .fetch_one(&pool).await.unwrap();
    assert_eq!(opened["opened"], true);
    assert_eq!(opened["funded"], true);
    assert_eq!(opened["liability_raw"], "0");
    writer.persist_tx(&spend).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_utxos WHERE txid=$1 AND covenant_id=$2 AND state IS NOT NULL",
    ).bind(hex::decode(&spend.transaction_id).unwrap()).bind(&graph)
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);
    writer.revert_block(&spend_block).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_utxos WHERE txid=$1",
    ).bind(hex::decode(&spend.transaction_id).unwrap())
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);
    writer.persist_tx(&spend).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1",
    ).bind(hex::decode(&spend.transaction_id).unwrap())
        .fetch_one(&pool).await.unwrap();
    assert_eq!(restored, opened);
}

#[sqlx::test(migrations = "./migrations")]
async fn opened_vault_rejects_forged_indexed_sources_and_outputs(pool: PgPool) {
    let (source, spend, _, _) = opening_transactions();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    writer.persist_tx(&source).await.unwrap();
    for mutation in ["source", "amount", "vault_output", "extra_graph"] {
        let mut bad = spend.clone();
        match mutation {
            "source" => bad.inputs[1].previous_outpoint_script = Some(format!("aa20{}87", "ff".repeat(32))),
            "amount" => bad.inputs[1].previous_outpoint_amount = Some(99_999_999),
            "vault_output" => bad.outputs[1].script_public_key.replace_range(8..10, "ff"),
            "extra_graph" => { let mut extra = bad.outputs[1].clone(); extra.index = 8; bad.outputs.push(extra); }
            _ => unreachable!(),
        }
        assert!(writer.persist_tx(&bad).await.is_err(), "{mutation}");
    }
    writer.persist_tx(&spend).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn funded_vault_and_token_reserve_are_inferred_before_reveal_and_reorg(pool: PgPool) {
    let fixture: Value = serde_json::from_str(FUND_VECTOR).unwrap();
    let abi: Value = serde_json::from_str(ABI).unwrap();
    let case = &fixture["case"];
    let graph = hex::decode(case["graphId"].as_str().unwrap()).unwrap();
    let token = hex::decode(case["tokenId"].as_str().unwrap()).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for (index, input) in case["inputs"].as_array().unwrap().iter().enumerate() {
        let source = transaction(json!({
            "transaction_id": input["transactionId"], "version": 1, "is_accepted": true,
            "accepting_block_hash": format!("{:064x}", 90_000 + index),
            "accepting_block_blue_score": 100 + index,
            "accepting_block_time": 1790000000000u64 + index as u64,
            "inputs": [{"previous_outpoint_hash": format!("{:064x}", 91_000 + index),
                "previous_outpoint_index": "0",
                "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
                "signature_script": ""}],
            "outputs": [{"index": 0,
                "amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
                "script_public_key": input["scriptPublicKeyHex"],
                "covenant_authorizing_input": 0,
                "covenant_id": if index == 0 {case["graphId"].clone()} else {case["tokenId"].clone()}}],
        }));
        writer.persist_tx(&source).await.unwrap();
    }
    let vault_reveal = hex::decode(case["vaultRevealHex"].as_str().unwrap()).unwrap();
    let token_reveal = hex::decode(case["tokenRevealHex"].as_str().unwrap()).unwrap();
    let vault_tag = abi["contracts"]["KCOMVault"]["entries"]["fund"]["dispatch_tag"]
        .as_str().unwrap();
    let block = hex::decode("a7".repeat(32)).unwrap();
    let spend = transaction(json!({
        "transaction_id": case["localTransactionId"], "version": 1, "is_accepted": true,
        "accepting_block_hash": hex::encode(&block), "accepting_block_blue_score": 200,
        "accepting_block_time": 1790000001000u64,
        "inputs": case["inputs"].as_array().unwrap().iter().enumerate().map(|(index, input)| json!({
            "previous_outpoint_hash": input["transactionId"],
            "previous_outpoint_index": input["index"],
            "previous_outpoint_amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "previous_outpoint_script": input["scriptPublicKeyHex"],
            "signature_script": if index == 0 {push_reveal(vault_tag, &vault_reveal)}
                else {push_reveal("00000000", &token_reveal)},
        })).collect::<Vec<_>>(),
        "outputs": case["outputs"].as_array().unwrap().iter().map(|output| json!({
            "index": output["index"],
            "amount": output["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "script_public_key": output["scriptPublicKeyHex"],
            "covenant_authorizing_input": output["authorizingInput"],
            "covenant_id": output["covenantId"],
        })).chain([json!({"index": 2, "amount": 940000000,
            "script_public_key": format!("20{}ac", "11".repeat(32))})]).collect::<Vec<_>>(),
    }));
    for mutation in ["token_source", "token_amount", "vault_output", "token_output", "rebound"] {
        let mut bad = spend.clone();
        match mutation {
            "token_source" => bad.inputs[1].previous_outpoint_script = Some(format!("aa20{}87", "ff".repeat(32))),
            "token_amount" => bad.inputs[1].previous_outpoint_amount = Some(99_999_999),
            "vault_output" => bad.outputs[0].script_public_key.replace_range(8..10, "ff"),
            "token_output" => bad.outputs[1].script_public_key.replace_range(8..10, "ff"),
            "rebound" => bad.outputs[1].covenant.as_mut().unwrap().authorizing_input = Some(0),
            _ => unreachable!(),
        }
        assert!(writer.persist_tx(&bad).await.is_err(), "{mutation}");
    }
    writer.persist_tx(&spend).await.unwrap();
    for (vout, id, field) in [(0, &graph, "funded"), (1, &token, "amount")] {
        let state: Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=$2 AND covenant_id=$3",
        ).bind(hex::decode(&spend.transaction_id).unwrap()).bind(vout).bind(id)
            .fetch_one(&pool).await.unwrap();
        assert_eq!(state[field], if vout == 0 {json!(true)} else {json!("1000")});
    }
    writer.persist_tx(&spend).await.unwrap();
    writer.revert_block(&block).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE txid=$1")
        .bind(hex::decode(&spend.transaction_id).unwrap()).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 0);
    writer.persist_tx(&spend).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1 AND covenant_id=$2",
    ).bind(hex::decode(&spend.transaction_id).unwrap()).bind(&token)
        .fetch_one(&pool).await.unwrap();
    assert_eq!(restored["amount"], "1000");
}

#[sqlx::test(migrations = "./migrations")]
async fn campaign_actors_reveal_replay_and_reorg(pool: PgPool) {
    let abi: Value = serde_json::from_str(ABI).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for (sequence, name) in [
        "KCOMSettlement",
        "KCOMClaimCommitment",
        "KCOMEntitlement",
    ]
    .iter()
    .enumerate()
    {
        let contract = &abi["contracts"][name];
        let reveal = campaign_actor_reveal(&abi, name);
        let p2sh_script = format!("aa20{}87", hex::encode(blake2b_256(&reveal)));
        let entries = contract["entries"].as_object().unwrap();
        let (action, entry) = if *name == "KCOMSettlement" {
            ("seal", &entries["seal"])
        } else {
            let (action, entry) = entries.iter().next().unwrap();
            (action.as_str(), entry)
        };
        let source_txid = format!("{:064x}", 1000 + sequence);
        let spend_txid = format!("{:064x}", 2000 + sequence);
        let covenant_id = format!("{:064x}", 3000 + sequence);
        let source_block = format!("{:064x}", 4000 + sequence);
        let spend_block = format!("{:064x}", 5000 + sequence);
        let source = transaction(json!({
            "transaction_id": source_txid,
            "version": 1,
            "is_accepted": true,
            "accepting_block_hash": source_block,
            "accepting_block_blue_score": 100 + sequence,
            "accepting_block_time": 1790000000000u64 + sequence as u64,
            "inputs": [{
                "previous_outpoint_hash": format!("{:064x}", 6000 + sequence),
                "previous_outpoint_index": "0",
                "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
                "signature_script": ""
            }],
            "outputs": [{
                "index": 0,
                "amount": 100000000,
                "script_public_key": p2sh_script,
                "script_public_key_address": format!("kaspatest:p{:064x}", sequence),
                "covenant_authorizing_input": 0,
                "covenant_id": covenant_id
            }]
        }));
        let spend = transaction(json!({
            "transaction_id": spend_txid,
            "version": 1,
            "is_accepted": true,
            "accepting_block_hash": spend_block,
            "accepting_block_blue_score": 200 + sequence,
            "accepting_block_time": 1790000001000u64 + sequence as u64,
            "inputs": [{
                "previous_outpoint_hash": source_txid,
                "previous_outpoint_index": "0",
                "previous_outpoint_script": p2sh_script,
                "signature_script": push_reveal(entry["dispatch_tag"].as_str().unwrap(), &reveal)
            }],
            "outputs": [{
                "index": 0,
                "amount": 90000000,
                "script_public_key": format!("20{}ac", "22".repeat(32))
            }]
        }));
        writer.persist_tx(&source).await.unwrap();
        let id = hex::decode(&covenant_id).unwrap();
        let before: String =
            sqlx::query_scalar("SELECT classification_status FROM covenants WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(before, "unrevealed", "{name}");
        writer.persist_tx(&spend).await.unwrap();
        let classification: (String, String) = sqlx::query_as(
            "SELECT template_name, classification_status FROM covenants WHERE covenant_id=$1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(classification, ((*name).into(), "matched".into()));
        let action_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND entrypoint=$2",
        )
        .bind(&id)
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(action_count, 1, "{name} action");
        let initial_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        writer.persist_tx(&spend).await.unwrap();
        let replay_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenant_actions WHERE covenant_id=$1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(replay_count, initial_count, "{name} idempotent replay");
        writer
            .revert_block(&hex::decode(&spend_block).unwrap())
            .await
            .unwrap();
        let reverted: (String, String) = sqlx::query_as(
            "SELECT classification_status, status FROM covenants c JOIN covenant_utxos u USING(covenant_id) WHERE c.covenant_id=$1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reverted, ("unrevealed".into(), "active".into()));
        let reverted_action_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND entrypoint=$2",
        )
        .bind(&id)
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reverted_action_count, 0, "{name} action rollback");
        writer.persist_tx(&spend).await.unwrap();
        let reapplied: (String, String) = sqlx::query_as(
            "SELECT template_name, classification_status FROM covenants WHERE covenant_id=$1",
        )
        .bind(&id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reapplied, ((*name).into(), "matched".into()), "{name} reapplication");
        let reapplied_action_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND entrypoint=$2",
        )
        .bind(&id)
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reapplied_action_count, 1, "{name} action reapplication");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn factory_shards_and_collector_are_inferred_before_reveal(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let graph = vector["graphId"].as_str().unwrap();
    let graph_bytes = hex::decode(graph).unwrap();
    let scripts = vector["sourceScripts"].as_array().unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let p2sh = |script_hex: &str| {
        format!(
            "aa20{}87",
            hex::encode(blake2b_256(&hex::decode(script_hex).unwrap()))
        )
    };
    let source_txid = format!("{:064x}", 7000);
    let source_block = format!("{:064x}", 8000);
    let source = transaction(json!({
        "transaction_id": source_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": source_block,
        "accepting_block_blue_score": 100,
        "accepting_block_time": 1790000000000u64,
        "inputs": [{
            "previous_outpoint_hash": format!("{:064x}", 9000),
            "previous_outpoint_index": "0",
            "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
            "signature_script": ""
        }],
        "outputs": [{
            "index": 0,
            "amount": 500000000,
            "script_public_key": p2sh(scripts[0].as_str().unwrap()),
            "covenant_authorizing_input": 0,
            "covenant_id": graph
        }]
    }));
    writer.persist_tx(&source).await.unwrap();

    let mut previous_txid = source_txid;
    let mut blocks = Vec::new();
    for step in 0..=4 {
        let reveal = hex::decode(scripts[step].as_str().unwrap()).unwrap();
        let action = if step == 4 {
            "finish_initialization"
        } else {
            "create_shard"
        };
        let tag = serde_json::from_str::<Value>(ABI).unwrap()["contracts"]["KCOMFactory"]
            ["entries"][action]["dispatch_tag"]
            .as_str()
            .unwrap()
            .to_owned();
        let txid = format!("{:064x}", 7100 + step);
        let block = format!("{:064x}", 8100 + step);
        let outputs = if step == 4 {
            vec![json!({
                "index": 0,
                "amount": 100000000,
                "script_public_key": vector["finishInitializationOutput"],
                "covenant_authorizing_input": 0,
                "covenant_id": graph
            })]
        } else {
            vector["createShardSequence"][step].as_array().unwrap().iter().enumerate()
                .map(|(index, script)| json!({
                    "index": index,
                    "amount": vector["createShardValuesSompi"][step][index].as_str().unwrap().parse::<u64>().unwrap(),
                    "script_public_key": script,
                    "covenant_authorizing_input": 0,
                    "covenant_id": graph
                })).collect::<Vec<_>>()
        };
        let spend = transaction(json!({
            "transaction_id": txid,
            "version": 1,
            "is_accepted": true,
            "accepting_block_hash": block,
            "accepting_block_blue_score": 200 + step,
            "accepting_block_time": 1790000001000u64 + step as u64,
            "inputs": [{
                "previous_outpoint_hash": previous_txid,
                "previous_outpoint_index": "0",
                "previous_outpoint_script": p2sh(scripts[step].as_str().unwrap()),
                "signature_script": push_reveal(&tag, &reveal)
            }],
            "outputs": outputs
        }));
        writer.persist_tx(&spend).await.unwrap();
        let expected = if step == 4 {
            "KCOMSettlement"
        } else {
            "KCOMFactory"
        };
        let state: Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
        )
        .bind(&graph_bytes)
        .bind(hex::decode(&txid).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state["modeName"], expected);
        if step < 4 {
            assert_eq!(state["next_shard"], (step + 1).to_string());
            let shard: Value = sqlx::query_scalar(
                "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=1",
            )
            .bind(&graph_bytes)
            .bind(hex::decode(&txid).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(shard["modeName"], "KCOMClaimShard");
            assert_eq!(shard["shard"], step.to_string());
        }
        blocks.push((block, spend));
        previous_txid = txid;
    }

    let shard_reveal = hex::decode(vector["initialShardScript"].as_str().unwrap()).unwrap();
    let close_tag = serde_json::from_str::<Value>(ABI).unwrap()["contracts"]["KCOMClaimShard"]
        ["entries"]["close"]["dispatch_tag"]
        .as_str()
        .unwrap()
        .to_owned();
    let close_txid = format!("{:064x}", 7200);
    let close_block = format!("{:064x}", 8200);
    let close = transaction(json!({
        "transaction_id": close_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": close_block,
        "accepting_block_blue_score": 300,
        "accepting_block_time": 1790000010000u64,
        "inputs": [{
            "previous_outpoint_hash": blocks[0].1.transaction_id,
            "previous_outpoint_index": "1",
            "previous_outpoint_script": p2sh(vector["initialShardScript"].as_str().unwrap()),
            "signature_script": push_reveal(&close_tag, &shard_reveal)
        }],
        "outputs": [{
            "index": 0,
            "amount": 100000000,
            "script_public_key": vector["closedShardOutput"],
            "covenant_authorizing_input": 0,
            "covenant_id": graph
        }]
    }));
    writer.persist_tx(&close).await.unwrap();
    let closed: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&close_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(closed["modeName"], "KCOMClaimShard");
    assert_eq!(closed["closed"], true);
    writer
        .revert_block(&hex::decode(&close_block).unwrap())
        .await
        .unwrap();
    writer.persist_tx(&close).await.unwrap();

    let (finish_block, finish_tx) = blocks.pop().unwrap();
    writer
        .revert_block(&hex::decode(&finish_block).unwrap())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&finish_tx.transaction_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    let (last_create_block, last_create_tx) = blocks.pop().unwrap();
    writer
        .revert_block(&hex::decode(&last_create_block).unwrap())
        .await
        .unwrap();
    let removed_shard: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&last_create_tx.transaction_id).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(removed_shard, 0);
    writer.persist_tx(&last_create_tx).await.unwrap();
    writer.persist_tx(&finish_tx).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&finish_tx.transaction_id).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored["modeName"], "KCOMSettlement");
}

#[sqlx::test(migrations = "./migrations")]
async fn selection_and_redirected_commitment_replay_after_reorg(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let selection = &vector["selection"];
    let graph = vector["graphId"].as_str().unwrap();
    let graph_bytes = hex::decode(graph).unwrap();
    let source_script = hex::decode(selection["sourceScript"].as_str().unwrap()).unwrap();
    let source_spk = format!("aa20{}87", hex::encode(blake2b_256(&source_script)));
    let source_txid = format!("{:064x}", 7300);
    let spend_txid = format!("{:064x}", 7301);
    let block = format!("{:064x}", 8301);
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let source = transaction(json!({
        "transaction_id": source_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": format!("{:064x}", 8300),
        "accepting_block_blue_score": 400,
        "accepting_block_time": 1790000020000u64,
        "inputs": [{
            "previous_outpoint_hash": format!("{:064x}", 9300),
            "previous_outpoint_index": "0",
            "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
            "signature_script": ""
        }],
        "outputs": [{
            "index": 0,
            "amount": 100000000,
            "script_public_key": source_spk,
            "covenant_authorizing_input": 0,
            "covenant_id": graph
        }]
    }));
    writer.persist_tx(&source).await.unwrap();
    let before: String =
        sqlx::query_scalar("SELECT classification_status FROM covenants WHERE covenant_id=$1")
            .bind(&graph_bytes)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, "unrevealed");

    let spend = transaction(json!({
        "transaction_id": spend_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": block,
        "accepting_block_blue_score": 401,
        "accepting_block_time": 1790000021000u64,
        "inputs": [{
            "previous_outpoint_hash": source_txid,
            "previous_outpoint_index": "0",
            "previous_outpoint_script": source_spk,
            "signature_script": selection["signedBuilderWitness"]
        }, {
            "previous_outpoint_hash": format!("{:064x}", 9301),
            "previous_outpoint_index": "0",
            "previous_outpoint_script": format!("20{}ac", "22".repeat(32)),
            "signature_script": ""
        }],
        "outputs": selection["outputScripts"].as_array().unwrap().iter().enumerate()
            .map(|(index, script)| json!({
                "index": index,
                "amount": 100000000,
                "script_public_key": script,
                "covenant_authorizing_input": 0,
                "covenant_id": graph
            })).collect::<Vec<_>>()
    }));
    let mut forged = spend.clone();
    forged.transaction_id = format!("{:064x}", 7302);
    forged.outputs[1]
        .script_public_key
        .replace_range(8..10, "ff");
    let forged_error = writer.persist_tx(&forged).await.unwrap_err();
    assert!(
        format!("{forged_error:#}").contains("forged selection successor script"),
        "unexpected rejection: {forged_error:#}"
    );
    writer.persist_tx(&spend).await.unwrap();
    for (vout, mode) in [(0, "KCOMClaimShard"), (1, "KCOMClaimCommitment")] {
        let state: Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=$3",
        )
        .bind(&graph_bytes)
        .bind(hex::decode(&spend_txid).unwrap())
        .bind(vout)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state["modeName"], mode);
        if vout == 1 {
            assert_eq!(state["beneficiary"], selection["args"]["beneficiary"]);
            assert_eq!(state["identity"], selection["commitmentState"]["identity"]);
            assert_eq!(state["tier"], "3");
        } else {
            assert_eq!(state["used_root"], selection["afterState"]["used_root"]);
        }
    }
    writer.persist_tx(&spend).await.unwrap();
    let selected_actions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND entrypoint='select'",
    )
    .bind(&graph_bytes)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(selected_actions, 1);
    let selection_args: Value = sqlx::query_scalar(
        "SELECT decoded_args FROM covenant_actions WHERE covenant_id=$1 AND entrypoint='select'",
    ).bind(&graph_bytes).fetch_one(&pool).await.unwrap();
    assert_eq!(selection_args["leafIndex"], selection["args"]["index"]);
    assert_eq!(selection_args["usedRootBefore"], selection["beforeState"]["used_root"]);
    assert_eq!(selection_args["usedRootAfter"], selection["afterState"]["used_root"]);
    assert_eq!(selection_args["originalAuthority"],
        selection["commitmentState"]["original_authority"]);
    assert_eq!(selection_args["selectionDigest"],
        "098b874ff5e22633809b8dbe2c56bb52c68da66638efd4e5c54e9f39bd8896ab");
    writer
        .revert_block(&hex::decode(&block).unwrap())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&spend_txid).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    writer.persist_tx(&spend).await.unwrap();
    let reapplied_args: Value = sqlx::query_scalar(
        "SELECT decoded_args FROM covenant_actions WHERE covenant_id=$1 AND entrypoint='select'",
    ).bind(&graph_bytes).fetch_one(&pool).await.unwrap();
    assert_eq!(reapplied_args, selection_args);
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=1",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored["beneficiary"], selection["args"]["beneficiary"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn finalized_collector_is_inferred_before_reveal_and_restored_after_reorg(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let finish = &vector["settlementFinish"];
    let graph = vector["graphId"].as_str().unwrap();
    let graph_bytes = hex::decode(graph).unwrap();
    let reveal = hex::decode(finish["sourceScript"].as_str().unwrap()).unwrap();
    let source_spk = format!("aa20{}87", hex::encode(blake2b_256(&reveal)));
    let source_txid = format!("{:064x}", 7400);
    let spend_txid = format!("{:064x}", 7401);
    let block = format!("{:064x}", 8401);
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let source = transaction(json!({
        "transaction_id": source_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": format!("{:064x}", 8400),
        "accepting_block_blue_score": 500,
        "accepting_block_time": 1790000030000u64,
        "inputs": [{
            "previous_outpoint_hash": format!("{:064x}", 9400),
            "previous_outpoint_index": "0",
            "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
            "signature_script": ""
        }],
        "outputs": [{
            "index": 0,
            "amount": 500000000,
            "script_public_key": source_spk,
            "covenant_authorizing_input": 0,
            "covenant_id": graph
        }]
    }));
    writer.persist_tx(&source).await.unwrap();
    let before: String =
        sqlx::query_scalar("SELECT classification_status FROM covenants WHERE covenant_id=$1")
            .bind(&graph_bytes)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, "unrevealed");

    let abi: Value = serde_json::from_str(ABI).unwrap();
    let tag = abi["contracts"]["KCOMSettlement"]["entries"]["finish_settlement"]["dispatch_tag"]
        .as_str()
        .unwrap();
    let spend = transaction(json!({
        "transaction_id": spend_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": block,
        "accepting_block_blue_score": 501,
        "accepting_block_time": 1790000031000u64,
        "inputs": [{
            "previous_outpoint_hash": source_txid,
            "previous_outpoint_index": "0",
            "previous_outpoint_script": source_spk,
            "signature_script": push_reveal(tag, &reveal)
        }],
        "outputs": [{
            "index": 0,
            "amount": 500000000,
            "script_public_key": finish["outputScript"],
            "covenant_authorizing_input": 0,
            "covenant_id": graph
        }]
    }));
    let mut forged = spend.clone();
    forged.transaction_id = format!("{:064x}", 7402);
    forged.outputs[0]
        .script_public_key
        .replace_range(8..10, "ff");
    let forged_error = writer.persist_tx(&forged).await.unwrap_err();
    assert!(
        format!("{forged_error:#}").contains("forged finalized collector script"),
        "unexpected rejection: {forged_error:#}"
    );
    writer.persist_tx(&spend).await.unwrap();
    let state: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state["modeName"], "KCOMSettlement");
    assert_eq!(state["settlement_complete"], true);
    assert_eq!(
        state["liability_raw"],
        finish["beforeState"]["liability_raw"]
    );
    writer.persist_tx(&spend).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND entrypoint='finish_settlement'",
    )
    .bind(&graph_bytes)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    writer
        .revert_block(&hex::decode(&block).unwrap())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&spend_txid).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    writer.persist_tx(&spend).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored["settlement_complete"], true);
}

#[sqlx::test(migrations = "./migrations")]
async fn sealed_vault_is_inferred_from_both_graph_inputs(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let seal = &vector["vaultSeal"];
    let graph = vector["graphId"].as_str().unwrap();
    let graph_bytes = hex::decode(graph).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut sources = Vec::new();
    for (index, field, amount) in [
        (0, "vaultSourceScript", 100_000_000u64),
        (1, "collectorSourceScript", 500_000_000u64),
    ] {
        let reveal = hex::decode(seal[field].as_str().unwrap()).unwrap();
        let script = format!("aa20{}87", hex::encode(blake2b_256(&reveal)));
        let txid = format!("{:064x}", 7500 + index);
        let source = transaction(json!({
            "transaction_id": txid,
            "version": 1,
            "is_accepted": true,
            "accepting_block_hash": format!("{:064x}", 8500 + index),
            "accepting_block_blue_score": 600 + index,
            "accepting_block_time": 1790000040000u64 + index as u64,
            "inputs": [{
                "previous_outpoint_hash": format!("{:064x}", 9500 + index),
                "previous_outpoint_index": "0",
                "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
                "signature_script": ""
            }],
            "outputs": [{
                "index": 0,
                "amount": amount,
                "script_public_key": script,
                "covenant_authorizing_input": 0,
                "covenant_id": graph
            }]
        }));
        writer.persist_tx(&source).await.unwrap();
        sources.push((txid, script, reveal, amount));
    }
    let abi: Value = serde_json::from_str(ABI).unwrap();
    let vault_tag = abi["contracts"]["KCOMVault"]["entries"]["seal"]["dispatch_tag"]
        .as_str()
        .unwrap();
    let collector_tag = abi["contracts"]["KCOMSettlement"]["entries"]["seal"]["dispatch_tag"]
        .as_str()
        .unwrap();
    let spend_txid = format!("{:064x}", 7502);
    let block = format!("{:064x}", 8502);
    let spend = transaction(json!({
        "transaction_id": spend_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": block,
        "accepting_block_blue_score": 602,
        "accepting_block_time": 1790000042000u64,
        "inputs": [
            {
                "previous_outpoint_hash": sources[0].0,
                "previous_outpoint_index": "0",
                "previous_outpoint_script": sources[0].1,
                "signature_script": push_reveal(vault_tag, &sources[0].2)
            },
            {
                "previous_outpoint_hash": sources[1].0,
                "previous_outpoint_index": "0",
                "previous_outpoint_script": sources[1].1,
                "signature_script": push_reveal(collector_tag, &sources[1].2)
            }
        ],
        "outputs": [{
            "index": 0,
            "amount": 600000000,
            "script_public_key": seal["outputScript"],
            "covenant_authorizing_input": 0,
            "covenant_id": graph
        }]
    }));
    let mut forged = spend.clone();
    forged.transaction_id = format!("{:064x}", 7503);
    forged.outputs[0]
        .script_public_key
        .replace_range(8..10, "ff");
    let error = writer.persist_tx(&forged).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("forged sealed vault script"),
        "unexpected rejection: {error:#}"
    );
    let mut diverted = spend.clone();
    diverted.transaction_id = format!("{:064x}", 7504);
    diverted.outputs[0].amount -= 1;
    let error = writer.persist_tx(&diverted).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("sealed vault native KAS differs"),
        "unexpected rejection: {error:#}"
    );
    writer.persist_tx(&spend).await.unwrap();
    let state: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state["modeName"], "KCOMVault");
    assert_eq!(state["settled"], true);
    assert_eq!(state["liability_raw"], seal["liabilityRaw"]);
    writer.persist_tx(&spend).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND entrypoint='seal'",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
    writer
        .revert_block(&hex::decode(&block).unwrap())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&spend_txid).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    writer.persist_tx(&spend).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored["liability_raw"], seal["liabilityRaw"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn recovered_vault_is_inferred_from_indexed_token_and_reorgs(pool: PgPool) {
    let vectors: Value = serde_json::from_str(RECOVERY_VECTOR).unwrap();
    let abi: Value = serde_json::from_str(ABI).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for (case_index, case) in vectors["cases"].as_array().unwrap().iter().enumerate() {
        let graph = case["graphId"].as_str().unwrap();
        let token = case["tokenId"].as_str().unwrap();
        let graph_bytes = hex::decode(graph).unwrap();
        let action = if case["variant"] == "partial" {
            "recover_partial"
        } else {
            "recover_final"
        };
        let tag = abi["contracts"]["KCOMVault"]["entries"][action]["dispatch_tag"]
            .as_str().unwrap();
        let vault_reveal = hex::decode(case["vaultRevealHex"].as_str().unwrap()).unwrap();
        let token_reveal = hex::decode(case["tokenRevealHex"].as_str().unwrap()).unwrap();
        let mut sources = Vec::new();
        for (index, input) in case["inputs"].as_array().unwrap().iter().take(2).enumerate() {
            let txid = format!("{:064x}", 7800 + case_index * 10 + index);
            let block = format!("{:064x}", 8800 + case_index * 10 + index);
            let source = transaction(json!({
                "transaction_id": txid, "version": 1, "is_accepted": true,
                "accepting_block_hash": block,
                "accepting_block_blue_score": 900 + case_index * 10 + index,
                "accepting_block_time": 1790000070000u64 + (case_index * 10 + index) as u64,
                "inputs": [{"previous_outpoint_hash": format!("{:064x}", 9800 + case_index * 10 + index),
                    "previous_outpoint_index": "0",
                    "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
                    "signature_script": ""}],
                "outputs": [{"index": 0,
                    "amount": input["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
                    "script_public_key": input["scriptPublicKeyHex"],
                    "covenant_authorizing_input": 0,
                    "covenant_id": if index == 0 {graph} else {token}}]
            }));
            writer.persist_tx(&source).await.unwrap();
            sources.push(txid);
        }
        let spend_txid = case["localTransactionId"].as_str().unwrap();
        let block = format!("{:064x}", 8802 + case_index * 10);
        let inputs = case["inputs"].as_array().unwrap().iter().enumerate()
            .map(|(index, input)| json!({
                "previous_outpoint_hash": if index < 2 {sources[index].clone()} else {
                    input["transactionId"].as_str().unwrap().to_owned()},
                "previous_outpoint_index": if index < 2 {"0".to_owned()} else {
                    input["index"].to_string()},
                "previous_outpoint_script": input["scriptPublicKeyHex"],
                "signature_script": if index == 0 {push_reveal(tag, &vault_reveal)}
                    else if index == 1 {recovery_token_signature(case, &token_reveal)}
                    else {String::new()},
            })).collect::<Vec<_>>();
        let outputs = case["outputs"].as_array().unwrap().iter().map(|output| json!({
            "index": output["index"],
            "amount": output["amountSompi"].as_str().unwrap().parse::<u64>().unwrap(),
            "script_public_key": output["scriptPublicKeyHex"],
            "covenant_id": output["covenantId"],
            "covenant_authorizing_input": output["authorizingInput"],
        })).collect::<Vec<_>>();
        let spend = transaction(json!({
            "transaction_id": spend_txid, "version": 1, "is_accepted": true,
            "accepting_block_hash": block,
            "accepting_block_blue_score": 902 + case_index * 10,
            "accepting_block_time": 1790000072000u64 + case_index as u64,
            "inputs": inputs, "outputs": outputs,
        }));
        let mut forged = spend.clone();
        forged.transaction_id = format!("{:064x}", 7803 + case_index * 10);
        forged.outputs[0].script_public_key.replace_range(8..10, "ff");
        assert!(format!("{:#}", writer.persist_tx(&forged).await.unwrap_err())
            .contains("forged recovered vault script"));
        writer.persist_tx(&spend).await.unwrap();
        let state: Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
        ).bind(&graph_bytes).bind(hex::decode(spend_txid).unwrap())
            .fetch_one(&pool).await.unwrap();
        assert_eq!(state["modeName"], "KCOMVault");
        assert_eq!(state["recovered"], true);
        assert_eq!(state["liability_raw"], case["vaultState"]["liability_raw"]);
        let token_states: Vec<Value> = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 ORDER BY vout",
        ).bind(hex::decode(token).unwrap()).bind(hex::decode(spend_txid).unwrap())
            .fetch_all(&pool).await.unwrap();
        assert_eq!(token_states.len(), if action == "recover_partial" { 2 } else { 1 });
        assert_eq!(token_states[0]["amount"], case["surplusRaw"]);
        if action == "recover_partial" {
            assert_eq!(token_states[1]["amount"], case["remainingLiabilityRaw"]);
        }
        writer.persist_tx(&spend).await.unwrap();
        writer.revert_block(&hex::decode(&block).unwrap()).await.unwrap();
        let remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2",
        ).bind(&graph_bytes).bind(hex::decode(spend_txid).unwrap())
            .fetch_one(&pool).await.unwrap();
        assert_eq!(remaining, 0);
        let token_remaining: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2",
        ).bind(hex::decode(token).unwrap()).bind(hex::decode(spend_txid).unwrap())
            .fetch_one(&pool).await.unwrap();
        assert_eq!(token_remaining, 0);
        writer.persist_tx(&spend).await.unwrap();
        let restored: Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
        ).bind(&graph_bytes).bind(hex::decode(spend_txid).unwrap())
            .fetch_one(&pool).await.unwrap();
        assert_eq!(restored["recovered"], true);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn closed_shard_collection_infers_collector_before_reveal(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let collection = &vector["collection"];
    let graph = vector["graphId"].as_str().unwrap();
    let graph_bytes = hex::decode(graph).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut sources = Vec::new();
    for (index, field) in [(0, "collectorSourceScript"), (1, "shardSourceScript")] {
        let reveal = hex::decode(collection[field].as_str().unwrap()).unwrap();
        let script = format!("aa20{}87", hex::encode(blake2b_256(&reveal)));
        let txid = format!("{:064x}", 7600 + index);
        let source = transaction(json!({
            "transaction_id": txid,
            "version": 1,
            "is_accepted": true,
            "accepting_block_hash": format!("{:064x}", 8600 + index),
            "accepting_block_blue_score": 700 + index,
            "accepting_block_time": 1790000050000u64 + index as u64,
            "inputs": [{
                "previous_outpoint_hash": format!("{:064x}", 9600 + index),
                "previous_outpoint_index": "0",
                "previous_outpoint_script": format!("20{}ac", "11".repeat(32)),
                "signature_script": ""
            }],
            "outputs": [{
                "index": 0,
                "amount": 100000000,
                "script_public_key": script,
                "covenant_authorizing_input": 0,
                "covenant_id": graph
            }]
        }));
        writer.persist_tx(&source).await.unwrap();
        sources.push((txid, script));
    }
    let spend_txid = format!("{:064x}", 7602);
    let block = format!("{:064x}", 8602);
    let spend = transaction(json!({
        "transaction_id": spend_txid,
        "version": 1,
        "is_accepted": true,
        "accepting_block_hash": block,
        "accepting_block_blue_score": 702,
        "accepting_block_time": 1790000052000u64,
        "inputs": [
            {"previous_outpoint_hash":sources[0].0,"previous_outpoint_index":"0",
                "previous_outpoint_script":sources[0].1,
                "signature_script":collection["leaderWitness"]},
            {"previous_outpoint_hash":sources[1].0,"previous_outpoint_index":"0",
                "previous_outpoint_script":sources[1].1,
                "signature_script":collection["shardWitness"]}
        ],
        "outputs": [{
            "index":0,"amount":200000000,"script_public_key":collection["outputScript"],
            "covenant_authorizing_input":0,"covenant_id":graph
        }]
    }));
    let mut forged = spend.clone();
    forged.transaction_id = format!("{:064x}", 7603);
    forged.outputs[0]
        .script_public_key
        .replace_range(8..10, "ff");
    let error = writer.persist_tx(&forged).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("forged collected settlement script"),
        "unexpected rejection: {error:#}"
    );
    writer.persist_tx(&spend).await.unwrap();
    let state: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state["modeName"], "KCOMSettlement");
    assert_eq!(state["next_shard"], "1");
    assert_eq!(state["selected_count"], "1");
    assert_eq!(state["all_weight"], "27");
    assert_eq!(state["collection_complete"], true);
    writer.persist_tx(&spend).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND entrypoint='collect'",
    ).bind(&graph_bytes).bind(hex::decode(&spend_txid).unwrap())
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);
    writer
        .revert_block(&hex::decode(&block).unwrap())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&spend_txid).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    writer.persist_tx(&spend).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=0",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored["selected_count"], "1");
}

#[sqlx::test(migrations = "./migrations")]
async fn settled_claim_infers_beneficiary_entitlement_before_reveal(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let step = &vector["settlementStep"];
    let graph = vector["graphId"].as_str().unwrap();
    let graph_bytes = hex::decode(graph).unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let mut sources = Vec::new();
    for (index, field) in [(0, "collectorSourceScript"), (1, "commitmentSourceScript")] {
        let reveal = hex::decode(step[field].as_str().unwrap()).unwrap();
        let script = format!("aa20{}87", hex::encode(blake2b_256(&reveal)));
        let txid = format!("{:064x}", 7700 + index);
        let source = transaction(json!({
            "transaction_id": txid,"version":1,"is_accepted":true,
            "accepting_block_hash":format!("{:064x}",8700+index),
            "accepting_block_blue_score":800+index,
            "accepting_block_time":1790000060000u64+index as u64,
            "inputs":[{"previous_outpoint_hash":format!("{:064x}",9700+index),
                "previous_outpoint_index":"0",
                "previous_outpoint_script":format!("20{}ac","11".repeat(32)),
                "signature_script":""}],
            "outputs":[{"index":0,"amount":100000000,"script_public_key":script,
                "covenant_authorizing_input":0,"covenant_id":graph}]
        }));
        writer.persist_tx(&source).await.unwrap();
        sources.push((txid, script));
    }
    let spend_txid = format!("{:064x}", 7702);
    let block = format!("{:064x}", 8702);
    let spend = transaction(json!({
        "transaction_id":spend_txid,"version":1,"is_accepted":true,
        "accepting_block_hash":block,"accepting_block_blue_score":802,
        "accepting_block_time":1790000062000u64,
        "inputs":[
            {"previous_outpoint_hash":sources[0].0,"previous_outpoint_index":"0",
                "previous_outpoint_script":sources[0].1,"signature_script":step["leaderWitness"]},
            {"previous_outpoint_hash":sources[1].0,"previous_outpoint_index":"0",
                "previous_outpoint_script":sources[1].1,"signature_script":step["delegateWitness"]}
        ],
        "outputs":step["outputScripts"].as_array().unwrap().iter().enumerate()
            .map(|(index,script)|json!({"index":index,"amount":100000000,
                "script_public_key":script,"covenant_authorizing_input":0,"covenant_id":graph}))
            .collect::<Vec<_>>()
    }));
    let mut forged = spend.clone();
    forged.transaction_id = format!("{:064x}", 7703);
    forged.outputs[1]
        .script_public_key
        .replace_range(8..10, "ff");
    let error = writer.persist_tx(&forged).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("forged settlement successor script"),
        "unexpected rejection: {error:#}"
    );
    writer.persist_tx(&spend).await.unwrap();
    let states: Vec<Value> = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 ORDER BY vout",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[0]["modeName"], "KCOMSettlement");
    assert_eq!(
        states[0]["liability_raw"],
        step["nextState"]["liability_raw"]
    );
    assert_eq!(states[1]["modeName"], "KCOMEntitlement");
    assert_eq!(states[1]["total"], step["step"]["totalRaw"]);
    assert_eq!(
        states[1]["beneficiary"],
        step["entitlementState"]["beneficiary"]
    );
    writer.persist_tx(&spend).await.unwrap();
    let count:i64=sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND txid=$2 AND entrypoint='settle'",
    ).bind(&graph_bytes).bind(hex::decode(&spend_txid).unwrap())
        .fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);
    writer
        .revert_block(&hex::decode(&block).unwrap())
        .await
        .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2")
            .bind(&graph_bytes)
            .bind(hex::decode(&spend_txid).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    writer.persist_tx(&spend).await.unwrap();
    let restored: Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE covenant_id=$1 AND txid=$2 AND vout=1",
    )
    .bind(&graph_bytes)
    .bind(hex::decode(&spend_txid).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored["total"], step["step"]["totalRaw"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn activation_infers_unrevealed_vesting_position_and_reorgs(pool: PgPool) {
    let vector: Value = serde_json::from_str(FACTORY_VECTOR).unwrap();
    let activation = &vector["activationVectors"];
    let graph = activation["graphId"].as_str().unwrap();
    let token = activation["tokenId"].as_str().unwrap();
    let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    for (fixture_number, name) in ["first", "last"].into_iter().enumerate() {
        let step = &activation[name];
        let inputs = step["inputs"].as_array().unwrap();
        let source_fields = [
            "vaultSourceScript",
            "entitlementSourceScript",
            "tokenSourceScript",
        ];
        let mut source_scripts = Vec::new();
        for field in source_fields {
            let reveal = hex::decode(step[field].as_str().unwrap()).unwrap();
            source_scripts.push(format!("aa20{}87", hex::encode(blake2b_256(&reveal))));
        }
        let mut grouped = std::collections::BTreeMap::<String, Vec<Value>>::new();
        for index in 0..3 {
            let txid = inputs[index]["transactionId"].as_str().unwrap();
            grouped.entry(txid.to_string()).or_default().push(json!({
                "index": inputs[index]["index"],
                "amount": if index == 0 {600_000_000} else if index == 1 {100_000_000} else if name == "first" {200_000_000} else {100_000_000},
                "script_public_key": source_scripts[index],
                "covenant_authorizing_input": 0,
                "covenant_id": if index == 2 {token} else {graph},
            }));
        }
        for (source_number, (txid, outputs)) in grouped.into_iter().enumerate() {
            let source = transaction(json!({
                "transaction_id":txid,"version":1,"is_accepted":true,
                "accepting_block_hash":format!("{:064x}", 30_000 + fixture_number * 10 + source_number),
                "accepting_block_blue_score":1_000 + fixture_number * 10 + source_number,
                "accepting_block_time":1790000000000u64,
                "inputs":[{"previous_outpoint_hash":format!("{:064x}",40_000+fixture_number*10+source_number),
                    "previous_outpoint_index":"0","previous_outpoint_script":format!("20{}ac", "aa".repeat(32)),
                    "signature_script":""}],
                "outputs":outputs,
            }));
            writer.persist_tx(&source).await.unwrap();
        }
        let position_id = hex::decode(step["positionId"].as_str().unwrap()).unwrap();
        let source_classification: String =
            sqlx::query_scalar("SELECT classification_status FROM covenants WHERE covenant_id=$1")
                .bind(&position_id)
                .fetch_optional(&pool)
                .await
                .unwrap()
                .unwrap_or_default();
        assert!(
            source_classification.is_empty(),
            "position must not preexist"
        );
        let txid = format!("{:064x}", 50_000 + fixture_number);
        let block = format!("{:064x}", 60_000 + fixture_number);
        let spend = transaction(json!({
            "transaction_id":txid,"version":1,"is_accepted":true,
            "accepting_block_hash":block,"accepting_block_blue_score":2_000+fixture_number,
            "accepting_block_time":1790000001000u64,
            "inputs":inputs.iter().enumerate().map(|(index, input)|json!({
                "previous_outpoint_hash":input["transactionId"],
                "previous_outpoint_index":input["index"],
                "previous_outpoint_script":if index < 3 {Value::String(source_scripts[index].clone())} else {Value::Null},
                "signature_script":if index == 0 {step["vaultWitness"].clone()} else if index == 1 {step["entitlementWitness"].clone()} else if index == 2 {step["tokenWitness"].clone()} else {json!("")},
            })).collect::<Vec<_>>(),
            "outputs":step["outputs"].as_array().unwrap().iter().enumerate().map(|(index, output)|json!({
                "index":index,"amount":output["valueSompi"].as_str().unwrap().parse::<u64>().unwrap(),
                "script_public_key":output["scriptPublicKeyHex"],
                "covenant_authorizing_input":if index < 2 {0} else {2},
                "covenant_id":output["covenantId"],
            })).collect::<Vec<_>>(),
        }));
        let mut forged = spend.clone();
        forged.transaction_id = format!("{:064x}", 70_000 + fixture_number);
        forged.outputs[1]
            .script_public_key
            .replace_range(8..10, "ff");
        let error = writer.persist_tx(&forged).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("activation position lineage differs"),
            "unexpected rejection: {error:#}"
        );
        writer.persist_tx(&spend).await.unwrap();
        let state: Value = sqlx::query_scalar(
            "SELECT state FROM covenant_utxos WHERE txid=$1 AND vout=1 AND covenant_id=$2",
        )
        .bind(hex::decode(&txid).unwrap())
        .bind(&position_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state["released"], "0");
        assert_eq!(state["total"], step["allocationRaw"]);
        let classified: (String, String) = sqlx::query_as(
            "SELECT template_name, classification_status FROM covenants WHERE covenant_id=$1",
        )
        .bind(&position_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(classified, ("KCOMVesting".into(), "matched".into()));
        writer.persist_tx(&spend).await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE txid=$1 AND covenant_id=$2",
        )
        .bind(hex::decode(&txid).unwrap())
        .bind(&position_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        writer
            .revert_block(&hex::decode(&block).unwrap())
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_utxos WHERE txid=$1 AND covenant_id=$2",
        )
        .bind(hex::decode(&txid).unwrap())
        .bind(&position_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
        let classified: i64 =
            sqlx::query_scalar("SELECT count(*) FROM covenants WHERE covenant_id=$1")
                .bind(&position_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            classified, 0,
            "reorg must remove genesis position classification"
        );
        writer.persist_tx(&spend).await.unwrap();
    }
}
