//! Integration tests for the read-side `repo::*` functions.
//!
//! Uses `#[sqlx::test]` to spin up a fresh database per test (sqlx creates a
//! random schema, runs every migration under `migrations/`, then hands us a
//! pool). Migrations include the dedupe-actions migration that adds the
//! `(covenant_id, txid, action)` UNIQUE INDEX — tests exercise that too.
//!
//! Running locally:
//!
//! ```bash
//! sudo -u postgres createuser --pwprompt tn12_test   # one-time
//! DATABASE_URL=postgres://tn12_test:PASS@127.0.0.1:5432/postgres \
//!     cargo test -p tn12-indexer-db
//! ```
//!
//! sqlx::test reads `DATABASE_URL`, connects to the named DB only long enough
//! to `CREATE DATABASE _sqlx_test_<random>`, then runs against that fresh DB.
//! Each test is therefore fully isolated and concurrent runs are safe.
//!
//! CI integration with a `postgres` service is a follow-up — see the
//! audit task list.

use serde_json::json;
use sqlx::{postgres::PgListener, PgPool, Row};
use std::time::Duration;
use tn12_indexer_core::{
    blake2b_256, compute_genesis_covenant_id_for_output, RestCovenantBinding, RestTransaction,
    RestTxInput, RestTxOutput,
};
use tn12_indexer_db::{claim, migrate, repo, Persister, PgPersister};
use tn12_indexer_decoder::kcc20_v2;

#[test]
fn standard_native_cutover_clears_legacy_rows_before_adding_constraints() {
    let migration = include_str!("../migrations/20260822190000_kcc20_standard_native_cutover.sql");
    let truncate = migration.find("TRUNCATE TABLE").unwrap();
    let constraints = migration
        .find("ADD CONSTRAINT kcc20_token_summaries_mint_policy_check")
        .unwrap();

    assert!(truncate < constraints);
    assert!(migration[..truncate].contains("UPDATE covenant_utxos\nSET state = NULL"));
    assert!(migration[..truncate].contains("claimed_template = NULL"));
    assert!(migration[..truncate].contains("claimed_args = NULL"));
    assert_eq!(
        migration[..truncate].matches("        'KCC20',").count(),
        2,
        "the one-time cutover must clear retired KCC20 rows and their UTXO state",
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_claim_projection_replays_dedupes_and_rolls_back(pool: PgPool) {
    let genesis_block = insert_block(&pool, 0x91, 100).await;
    let first_block = insert_block(&pool, 0x92, 200).await;
    let final_block = insert_block(&pool, 0x93, 300).await;
    let controller = insert_covenant(
        &pool,
        0x94,
        "kaspatest:snapshot-controller",
        Some("KCC20SnapshotController"),
        &genesis_block,
        100,
    )
    .await;
    sqlx::query("UPDATE covenants SET claim_verified = TRUE WHERE covenant_id = $1")
        .bind(&controller)
        .execute(&pool)
        .await
        .unwrap();
    let common = json!({
        "projectionSchema": "kcc20-snapshot-claim/v1",
        "tokenId": "11".repeat(32),
        "manifestCommitment": "22".repeat(32),
        "snapshotContext": "33".repeat(32),
        "shardIndex": "0",
        "ownerScheme": "0",
        "owner": "44".repeat(32),
        "holderExtensionCommitment": "aa".repeat(32),
        "recipient": "44".repeat(32),
        "recipientOwnerScheme": "0",
        "holderCount": "2"
    });
    insert_active_utxo_with_state(
        &pool,
        &controller,
        "kaspatest:snapshot-controller-genesis",
        50_000_000,
        json!({
            "tokenId": "11".repeat(32),
            "holderExtensionCommitment": "aa".repeat(32),
            "manifestCommitment": "22".repeat(32),
            "snapshotContext": "33".repeat(32),
            "kcc20TemplateHash": "bb".repeat(32),
            "claimNotBeforeDaaScore": "500",
            "shardIndex": "0",
            "globalIndexStart": "0",
            "holderCount": "2",
            "treeDepth": "1",
            "kcc20TemplatePrefixLen": "100",
            "kcc20TemplateSuffixLen": "200",
            "controllerCellKas": "50000000",
            "reserveCellKas": "50000000",
            "recipientMinCellKas": "50000000",
            "remainingRoot": "55".repeat(32),
            "remainingAmount": "300",
            "claimsProcessed": "0"
        }),
        &genesis_block,
        0x94,
    )
    .await;
    let zero_claim: (String, String, i64, bool, bool, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT allocation_total::TEXT, remaining_amount::TEXT, claims_processed, exhausted, state_verified, active_txid FROM kcc20_snapshot_shards WHERE controller_id = $1",
    ).bind(&controller).fetch_one(&pool).await.unwrap();
    assert_eq!(
        zero_claim,
        (
            "300".into(),
            "300".into(),
            0,
            false,
            true,
            Some(vec![0x94_u8; 32])
        )
    );

    insert_active_utxo_with_state(
        &pool,
        &controller,
        "kaspatest:snapshot-controller-ambiguous",
        50_000_000,
        json!({
            "tokenId": "11".repeat(32), "manifestCommitment": "22".repeat(32),
            "snapshotContext": "33".repeat(32), "shardIndex": "0",
            "holderCount": "2", "remainingRoot": "55".repeat(32),
            "remainingAmount": "300", "claimsProcessed": "0"
        }),
        &genesis_block,
        0x9a,
    )
    .await;
    let ambiguous: (bool, i64, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT state_verified, active_outpoint_count, active_txid FROM kcc20_snapshot_shards WHERE controller_id = $1",
    ).bind(&controller).fetch_one(&pool).await.unwrap();
    assert_eq!(ambiguous, (false, 2, None));
    sqlx::query("DELETE FROM covenant_utxos WHERE txid = $1")
        .bind(vec![0x9a_u8; 32])
        .execute(&pool)
        .await
        .unwrap();

    let drifted_controller = insert_covenant(
        &pool,
        0xa1,
        "kaspatest:snapshot-controller-drifted-history",
        Some("KCC20SnapshotController"),
        &genesis_block,
        100,
    )
    .await;
    sqlx::query("UPDATE covenants SET claim_verified = TRUE WHERE covenant_id = $1")
        .bind(&drifted_controller)
        .execute(&pool)
        .await
        .unwrap();
    insert_active_utxo_with_state(
        &pool,
        &drifted_controller,
        "kaspatest:snapshot-controller-drifted-history",
        50_000_000,
        json!({
            "tokenId": "81".repeat(32),
            "holderExtensionCommitment": "aa".repeat(32),
            "manifestCommitment": "82".repeat(32),
            "snapshotContext": "83".repeat(32),
            "kcc20TemplateHash": "bb".repeat(32),
            "claimNotBeforeDaaScore": "500",
            "shardIndex": "0",
            "globalIndexStart": "0",
            "holderCount": "2",
            "treeDepth": "1",
            "kcc20TemplatePrefixLen": "100",
            "kcc20TemplateSuffixLen": "200",
            "controllerCellKas": "50000000",
            "reserveCellKas": "50000000",
            "recipientMinCellKas": "50000000",
            "remainingRoot": "84".repeat(32),
            "remainingAmount": "300",
            "claimsProcessed": "0"
        }),
        &genesis_block,
        0xa1,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &drifted_controller,
        0xa2,
        &first_block,
        200,
        "spend",
        Some("claim"),
        None,
        Some(json!({
            "projectionSchema": "kcc20-snapshot-claim/v1",
            "tokenId": "81".repeat(32),
            "manifestCommitment": "82".repeat(32),
            "snapshotContext": "83".repeat(32),
            "shardIndex": "0",
            "globalIndex": "0",
            "shardLeafIndex": "0",
            "ownerScheme": "0",
            "owner": "85".repeat(32),
            "claimAmount": "100",
            "holderExtensionCommitment": "aa".repeat(32),
            "recipientAmount": "99",
            "recipient": "85".repeat(32),
            "recipientOwnerScheme": "0",
            "successorReserveAmount": "200",
            "previousRoot": "84".repeat(32),
            "nextRoot": "86".repeat(32),
            "remainingBefore": "300",
            "remainingAfter": "200",
            "claimsProcessedBefore": "0",
            "claimsProcessedAfter": "1",
            "holderCount": "2",
            "terminal": false
        })),
    )
    .await;
    let drifted_verified: bool = sqlx::query_scalar(
        "SELECT state_verified FROM kcc20_snapshot_shards WHERE controller_id = $1",
    )
    .bind(&drifted_controller)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!drifted_verified, "drifted claim history must fail closed");

    sqlx::query(
        "UPDATE covenant_utxos SET status = 'spent', spent_block = $1, spent_by_txid = $2 WHERE txid = $3",
    )
    .bind(&first_block)
    .bind(vec![0x95_u8; 32])
    .bind(vec![0x94_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let mut first = common.clone();
    first.as_object_mut().unwrap().extend(
        json!({
            "globalIndex": "0", "shardLeafIndex": "0", "claimAmount": "100",
            "recipientAmount": "100", "successorReserveAmount": "200",
            "previousRoot": "55".repeat(32), "nextRoot": "66".repeat(32),
            "remainingBefore": "300", "remainingAfter": "200",
            "claimsProcessedBefore": "0", "claimsProcessedAfter": "1", "terminal": false
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    insert_action_with_outputs_and_args(
        &pool,
        &controller,
        0x95,
        &first_block,
        200,
        "spend",
        Some("claim"),
        None,
        Some(first.clone()),
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &controller,
        "kaspatest:snapshot-controller-next",
        50_000_000,
        json!({"remainingRoot": "66".repeat(32), "remainingAmount": "200", "claimsProcessed": "1"}),
        &first_block,
        0x95,
    )
    .await;

    let initial: (String, String, i64, bool) = sqlx::query_as(
        "SELECT allocation_total::TEXT, remaining_amount::TEXT, claims_processed, exhausted FROM kcc20_snapshot_shards WHERE controller_id = $1",
    ).bind(&controller).fetch_one(&pool).await.unwrap();
    assert_eq!(initial, ("300".into(), "200".into(), 1, false));

    let duplicate = sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, decoded_args)
           VALUES ($1, $2, $3, 201, 'spend', 'claim', $4)"#,
    )
    .bind(&controller)
    .bind(vec![0x96_u8; 32])
    .bind(&first_block)
    .bind(&first)
    .execute(&pool)
    .await;
    assert!(duplicate.is_err(), "global claim index must dedupe");

    let unrelated_claim = json!({
        "tokenId": "11".repeat(32),
        "manifestCommitment": "22".repeat(32),
        "globalIndex": "0"
    });
    let unrelated = sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, decoded_args)
           VALUES ($1, $2, $3, 201, 'spend', 'claim', $4)"#,
    )
    .bind(&controller)
    .bind(vec![0x9b_u8; 32])
    .bind(&first_block)
    .bind(unrelated_claim)
    .execute(&pool)
    .await;
    assert!(
        unrelated.is_ok(),
        "unrelated claim schemas must not collide"
    );

    let other_controller = insert_covenant(
        &pool,
        0x98,
        "kaspatest:snapshot-controller-duplicate",
        Some("KCC20SnapshotController"),
        &genesis_block,
        100,
    )
    .await;
    let cross_controller_duplicate = sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, decoded_args)
           VALUES ($1, $2, $3, 202, 'spend', 'claim', $4)"#,
    )
    .bind(&other_controller)
    .bind(vec![0x99_u8; 32])
    .bind(&first_block)
    .bind(&first)
    .execute(&pool)
    .await;
    assert!(
        cross_controller_duplicate.is_err(),
        "token + manifest + global index must dedupe across controllers"
    );

    sqlx::query(
        "UPDATE covenant_utxos SET status = 'spent', spent_block = $1, spent_by_txid = $2 WHERE txid = $3",
    )
    .bind(&final_block)
    .bind(vec![0x97_u8; 32])
    .bind(vec![0x95_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let mut final_claim = common;
    final_claim.as_object_mut().unwrap().extend(
        json!({
            "globalIndex": "1", "shardLeafIndex": "1", "claimAmount": "200",
            "recipientAmount": "200", "successorReserveAmount": "0",
            "previousRoot": "66".repeat(32), "nextRoot": "77".repeat(32),
            "remainingBefore": "200", "remainingAfter": "0",
            "claimsProcessedBefore": "1", "claimsProcessedAfter": "2", "terminal": true
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    insert_action_with_outputs_and_args(
        &pool,
        &controller,
        0x97,
        &final_block,
        300,
        "spend",
        Some("claim"),
        None,
        Some(final_claim),
    )
    .await;
    let exhausted: (String, i64, bool, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT remaining_amount::TEXT, claims_processed, exhausted, active_txid FROM kcc20_snapshot_shards WHERE controller_id = $1",
    ).bind(&controller).fetch_one(&pool).await.unwrap();
    assert_eq!(exhausted, ("0".into(), 2, true, None));

    PgPersister::new(pool.clone())
        .revert_block(&final_block)
        .await
        .unwrap();
    let restored: (String, i64, bool, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT remaining_amount::TEXT, claims_processed, exhausted, active_txid FROM kcc20_snapshot_shards WHERE controller_id = $1",
    ).bind(&controller).fetch_one(&pool).await.unwrap();
    assert_eq!(restored, ("200".into(), 1, false, Some(vec![0x95_u8; 32])));

    let totals: (String, String, i64) = sqlx::query_as(
        "SELECT claimed_total::TEXT, remaining_total::TEXT, claims_processed FROM kcc20_snapshot_global_totals",
    ).fetch_one(&pool).await.unwrap();
    assert_eq!(totals, ("100".into(), "200".into(), 1));
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_claim_actions_join_exactly_one_reserve_input(pool: PgPool) {
    let block = insert_block(&pool, 0x31, 100).await;
    let controller = insert_covenant(
        &pool,
        0x32,
        "kaspatest:snapshot-controller-query",
        Some("KCC20SnapshotController"),
        &block,
        100,
    )
    .await;
    let token = insert_covenant(
        &pool,
        0x33,
        "kaspatest:snapshot-token-query",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    let controller_input = json!({
        "previousOutpoint": { "hash": "41".repeat(32), "index": 0 }
    });
    let reserve_input = json!({
        "previousOutpoint": { "hash": "42".repeat(32), "index": 1 }
    });
    insert_action_full(
        &pool,
        &controller,
        0x43,
        &block,
        200,
        "spend",
        Some("claim"),
        Some(controller_input.clone()),
        None,
        Some(json!({
            "projectionSchema": "kcc20-snapshot-claim/v1",
            "tokenId": hex::encode(&token),
            "manifestCommitment": "44".repeat(32),
            "globalIndex": "0"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &controller,
        0x44,
        &block,
        199,
        "spend",
        Some("claim"),
        Some(controller_input.clone()),
        None,
        Some(json!({
            "projectionSchema": "kcc20-snapshot-claim/v1",
            "tokenId": "99".repeat(32),
            "manifestCommitment": "44".repeat(32),
            "globalIndex": "0"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &token,
        0x43,
        &block,
        200,
        "spend",
        Some("transfer"),
        Some(reserve_input.clone()),
        None,
        None,
    )
    .await;

    let page = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.epoch.len(), 64);
    assert!(page.epoch.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(page.content_commitment.len(), 64);
    assert!(page
        .content_commitment
        .chars()
        .all(|c| c.is_ascii_hexdigit()));
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].txid_hex, "43".repeat(32));
    assert_eq!(page.items[0].inputs, Some(controller_input));
    assert_eq!(page.items[0].token_action_count, 1);
    assert_eq!(page.items[0].token_inputs, Some(reserve_input));
    assert_eq!(
        page.items[0].controller_template_name.as_deref(),
        Some("KCC20SnapshotController")
    );
    assert_eq!(page.items[0].token_template_name.as_deref(), Some("KCC20"));
    assert_eq!(
        page.items[0].token_classification_kind.as_deref(),
        Some("covenant")
    );

    sqlx::query(
        "UPDATE covenant_actions SET canonical_token_id = $1 WHERE covenant_id = $2 AND txid = $3",
    )
    .bind(vec![0x98_u8; 32])
    .bind(&token)
    .bind(vec![0x43_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let conflicting_identity = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert_eq!(conflicting_identity.items[0].token_action_count, 0);

    sqlx::query("UPDATE covenants SET template_name = 'IgnoredKCC20' WHERE covenant_id = $1")
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();
    let after_conflicting_identity_reclassification = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        after_conflicting_identity_reclassification.revision, conflicting_identity.revision,
        "a transfer with a conflicting canonical token ID must not invalidate claim replay"
    );
    assert_eq!(
        after_conflicting_identity_reclassification.epoch,
        conflicting_identity.epoch
    );
    assert_eq!(
        after_conflicting_identity_reclassification.items[0].token_action_count,
        0
    );
    sqlx::query("UPDATE covenants SET template_name = 'KCC20' WHERE covenant_id = $1")
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "UPDATE covenant_actions SET canonical_token_id = NULL WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&token)
    .bind(vec![0x43_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE covenant_actions SET entrypoint = 'unrelated' WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&token)
    .bind(vec![0x43_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let detached = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert!(detached.revision > page.revision);
    assert_ne!(detached.epoch, page.epoch);
    assert_eq!(detached.items[0].token_action_count, 0);

    sqlx::query(
        "UPDATE covenant_actions SET entrypoint = 'transfer' WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&token)
    .bind(vec![0x43_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let restored = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert!(restored.revision > detached.revision);
    assert_eq!(restored.items[0].token_action_count, 1);

    let other_token = insert_covenant(
        &pool,
        0x36,
        "kaspatest:nonmatching-snapshot-token-query",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    insert_action_full(
        &pool,
        &other_token,
        0x43,
        &block,
        200,
        "spend",
        Some("transfer"),
        Some(json!({
            "previousOutpoint": { "hash": "46".repeat(32), "index": 1 }
        })),
        None,
        None,
    )
    .await;
    let with_nonmatching_transfer = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert_eq!(with_nonmatching_transfer.items[0].token_action_count, 1);

    sqlx::query("UPDATE covenants SET template_name = 'OtherKCC20Changed' WHERE covenant_id = $1")
        .bind(&other_token)
        .execute(&pool)
        .await
        .unwrap();
    let after_nonmatching_transfer_reclassification = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        after_nonmatching_transfer_reclassification.revision, with_nonmatching_transfer.revision,
        "a same-transaction transfer from another token must not invalidate claim replay"
    );
    assert_eq!(
        after_nonmatching_transfer_reclassification.epoch,
        with_nonmatching_transfer.epoch
    );
    assert_eq!(
        after_nonmatching_transfer_reclassification.items[0].token_action_count,
        1
    );

    let unrelated = insert_covenant(
        &pool,
        0x35,
        "kaspatest:unrelated-covenant-query",
        Some("UnrelatedContract"),
        &block,
        100,
    )
    .await;
    sqlx::query(
        "UPDATE covenants SET template_name = 'UnrelatedContractChanged' WHERE covenant_id = $1",
    )
    .bind(&unrelated)
    .execute(&pool)
    .await
    .unwrap();
    let after_unrelated_reclassification = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        after_unrelated_reclassification.revision,
        after_nonmatching_transfer_reclassification.revision,
        "unrelated covenant maintenance must not invalidate claim replay"
    );
    assert_eq!(
        after_unrelated_reclassification.epoch,
        after_nonmatching_transfer_reclassification.epoch
    );

    sqlx::query("UPDATE covenants SET template_name = 'KCC20Changed' WHERE covenant_id = $1")
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();
    let reclassified = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert!(reclassified.revision > after_unrelated_reclassification.revision);
    assert_ne!(reclassified.epoch, after_unrelated_reclassification.epoch);
    assert_eq!(
        reclassified.items[0].token_template_name.as_deref(),
        Some("KCC20Changed")
    );

    sqlx::query("UPDATE covenants SET template_name = 'KCC20' WHERE covenant_id = $1")
        .bind(&token)
        .execute(&pool)
        .await
        .unwrap();

    let alias = insert_covenant(
        &pool,
        0x34,
        "kaspatest:snapshot-token-alias-query",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    insert_action_full(
        &pool,
        &alias,
        0x43,
        &block,
        200,
        "spend",
        Some("transfer"),
        Some(json!({
            "previousOutpoint": { "hash": "45".repeat(32), "index": 1 }
        })),
        None,
        None,
    )
    .await;
    sqlx::query("UPDATE covenant_actions SET canonical_token_id = $1 WHERE covenant_id = $2")
        .bind(&token)
        .bind(&alias)
        .execute(&pool)
        .await
        .unwrap();
    let ambiguous = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        200,
        0,
    )
    .await
    .unwrap();
    assert!(ambiguous.revision > reclassified.revision);
    assert_ne!(ambiguous.epoch, reclassified.epoch);
    assert_eq!(ambiguous.epoch.len(), 64);
    assert!(ambiguous.epoch.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(ambiguous.items[0].token_action_count, 2);
    assert!(ambiguous.items[0].token_inputs.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_claim_content_commitment_changes_for_only_an_interior_row(pool: PgPool) {
    let block = insert_block(&pool, 0x71, 100).await;
    let controller = insert_covenant(
        &pool,
        0x72,
        "kaspatest:snapshot-controller-commitment",
        Some("KCC20SnapshotController"),
        &block,
        100,
    )
    .await;
    let token = insert_covenant(
        &pool,
        0x73,
        "kaspatest:snapshot-token-commitment",
        Some("KCC20"),
        &block,
        100,
    )
    .await;

    for (position, tx_byte) in [(0_i64, 0x74_u8), (1, 0x75), (2, 0x76)] {
        insert_action_full(
            &pool,
            &controller,
            tx_byte,
            &block,
            200 + position,
            "spend",
            Some("claim"),
            Some(json!({
                "previousOutpoint": {
                    "hash": format!("{:02x}", 0x80 + position).repeat(32),
                    "index": 0
                }
            })),
            None,
            Some(json!({
                "projectionSchema": "kcc20-snapshot-claim/v1",
                "tokenId": hex::encode(&token),
                "manifestCommitment": "77".repeat(32),
                "globalIndex": position.to_string(),
                "claimsProcessedBefore": position.to_string(),
                "claimsProcessedAfter": (position + 1).to_string()
            })),
        )
        .await;
        insert_action_full(
            &pool,
            &token,
            tx_byte,
            &block,
            200 + position,
            "spend",
            Some("transfer"),
            Some(json!({
                "previousOutpoint": {
                    "hash": format!("{:02x}", 0x90 + position).repeat(32),
                    "index": 1
                }
            })),
            None,
            None,
        )
        .await;
    }

    let before = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(before.total, 3);
    assert_eq!(before.items.len(), 3);
    let boundary_txids = [
        before.items.first().unwrap().txid_hex.clone(),
        before.items.last().unwrap().txid_hex.clone(),
    ];

    sqlx::query(
        r#"
        UPDATE covenant_actions
        SET inputs = jsonb_set(inputs, '{previousOutpoint,hash}', to_jsonb($1::TEXT))
        WHERE covenant_id = $2
          AND txid = $3
          AND action = 'spend'
          AND entrypoint = 'claim'
        "#,
    )
    .bind("a5".repeat(32))
    .bind(&controller)
    .bind(vec![0x75_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let after = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(after.total, before.total);
    assert_eq!(after.items.len(), before.items.len());
    assert_eq!(
        [
            after.items.first().unwrap().txid_hex.clone(),
            after.items.last().unwrap().txid_hex.clone(),
        ],
        boundary_txids
    );
    assert_ne!(after.content_commitment, before.content_commitment);
}

#[sqlx::test(migrations = "./migrations")]
async fn snapshot_claim_actions_truncate_clears_materialized_history(pool: PgPool) {
    let block = insert_block(&pool, 0x81, 100).await;
    let controller = insert_covenant(
        &pool,
        0x82,
        "kaspatest:snapshot-controller-truncate",
        Some("KCC20SnapshotController"),
        &block,
        100,
    )
    .await;
    let token = insert_covenant(
        &pool,
        0x83,
        "kaspatest:snapshot-token-truncate",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    insert_action_full(
        &pool,
        &controller,
        0x84,
        &block,
        200,
        "spend",
        Some("claim"),
        Some(json!({
            "previousOutpoint": { "hash": "85".repeat(32), "index": 0 }
        })),
        None,
        Some(json!({
            "projectionSchema": "kcc20-snapshot-claim/v1",
            "tokenId": hex::encode(&token),
            "manifestCommitment": "86".repeat(32),
            "globalIndex": "0"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &token,
        0x84,
        &block,
        200,
        "spend",
        Some("transfer"),
        Some(json!({
            "previousOutpoint": { "hash": "87".repeat(32), "index": 1 }
        })),
        None,
        None,
    )
    .await;

    let seeded = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(seeded.total, 1);
    assert_eq!(seeded.items.len(), 1);

    let empty_commitment: String =
        sqlx::query_scalar("SELECT encode(snapshot_claim_history_empty_commitment($1, $2), 'hex')")
            .bind(&controller)
            .bind(&token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_ne!(seeded.content_commitment, empty_commitment);

    sqlx::query("TRUNCATE covenant_actions CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let materialized_scope_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM snapshot_claim_history_commitments WHERE controller_id = $1 AND token_id = $2",
    )
    .bind(&controller)
    .bind(&token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(materialized_scope_count, 0);

    let truncated = repo::snapshot_claim_actions(
        &pool,
        &hex::encode(&controller),
        &hex::encode(&token),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(truncated.total, 0);
    assert!(truncated.items.is_empty());
    assert_eq!(truncated.content_commitment, empty_commitment);
}

#[sqlx::test(migrations = "./migrations")]
async fn public_mint_summary_defaults_missing_indexed_flag_to_paused(pool: PgPool) {
    let block = insert_block(&pool, 0x2e, 200).await;
    let token = insert_covenant(
        &pool,
        0x2e,
        "kaspatest:missing-public-mint-flag",
        Some("KCC20"),
        &block,
        200,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES ($1, $2, 0, 1, 1, FALSE, 1000)"#,
    )
    .bind(&token)
    .bind(vec![0x11_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:public-minter",
        50_000_000,
        json!({
            "owner": "22".repeat(32),
            "isMintAuthority": true,
            "mintPolicy": 2,
            "remainingSupply": "999"
        }),
        &block,
        0x2d,
    )
    .await;

    repo::refresh_kcc20_token_summaries(&pool).await.unwrap();
    let summary = repo::kcc20_token_summary(&pool, &hex::encode(token))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(summary.active_mint_policy_value, Some(2));
    assert_eq!(summary.public_mint_active, Some(false));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_active_mint_policy_query_uses_partial_index(pool: PgPool) {
    let block = insert_block(&pool, 0x2f, 201).await;
    let token = insert_covenant(
        &pool,
        0x2f,
        "kaspatest:mint-policy-query-plan",
        Some("KCC20"),
        &block,
        201,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:mint-policy-query-plan",
        50_000_000,
        json!({
            "owner": "33".repeat(32),
            "isMintAuthority": true,
            "mintPolicy": 2,
            "remainingSupply": "999"
        }),
        &block,
        0x2f,
    )
    .await;

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        r#"
        EXPLAIN (COSTS OFF)
        SELECT
            active.covenant_id,
            MIN((active.state->>'mintPolicy')::SMALLINT)
        FROM covenant_utxos active
        WHERE active.covenant_id = $1
          AND active.status = 'active'
          AND active.state->>'isMintAuthority' = 'true'
          AND active.state->>'mintPolicy' ~ '^[12]$'
        GROUP BY active.covenant_id
        "#,
    )
    .bind(&token)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();

    assert!(
        plan.join("\n")
            .contains("covenant_utxos_kcc20_active_mint_policy_idx"),
        "query plan did not use the active mint-policy partial index: {plan:#?}",
    );

    let (valid, ready): (bool, bool) = sqlx::query_as(
        r#"
        SELECT i.indisvalid, i.indisready
        FROM pg_class c
        JOIN pg_index i ON i.indexrelid = c.oid
        WHERE c.relname = 'covenant_utxos_kcc20_active_mint_policy_idx'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid && ready);
}

#[sqlx::test(migrations = "./migrations")]
async fn migrate_repairs_interrupted_concurrent_indexes(pool: PgPool) {
    let block = insert_block(&pool, 0x71, 1).await;
    let covenant = insert_covenant(
        &pool,
        0x71,
        "kaspatest:prepair",
        Some("RepairFixture"),
        &block,
        1,
    )
    .await;
    let duplicate_genesis = insert_covenant(
        &pool,
        0x72,
        "kaspatest:prepair-duplicate",
        Some("RepairFixture"),
        &block,
        2,
    )
    .await;
    sqlx::query("UPDATE covenants SET genesis_txid = $1 WHERE covenant_id IN ($2, $3)")
        .bind(vec![0xee_u8; 32])
        .bind(&covenant)
        .bind(&duplicate_genesis)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET script_hash = $1 WHERE covenant_id = $2")
        .bind(&covenant)
        .bind(&duplicate_genesis)
        .execute(&pool)
        .await
        .unwrap();
    insert_action_with_inputs(&pool, &covenant, 0x72, &block, 1, "deploy", json!([])).await;
    insert_action_with_inputs(&pool, &covenant, 0x73, &block, 2, "spend", json!([])).await;
    insert_active_utxo(&pool, &covenant, "kaspatest:prepair", 1, &block, 0x74).await;
    insert_active_utxo(&pool, &covenant, "kaspatest:prepair", 2, &block, 0x75).await;
    sqlx::query("UPDATE covenant_utxos SET status = 'spent', spent_block = $1, spent_by_txid = $2")
        .bind(&block)
        .bind(vec![0xef_u8; 32])
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("DROP INDEX CONCURRENTLY covenant_actions_revert_block_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_actions_revert_block_idx \
             ON covenant_actions (block_hash)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_spent_block_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_spent_block_idx \
             ON covenant_utxos (spent_block) WHERE spent_block IS NOT NULL",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_created_block_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_created_block_idx \
             ON covenant_utxos (created_block)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenants_genesis_block_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenants_genesis_block_idx \
             ON covenants (genesis_block)",
    )
    .execute(&pool)
    .await
    .is_err());

    let removed_migration_records = sqlx::query(
        "DELETE FROM _sqlx_migrations \
         WHERE version BETWEEN 20260829223000 AND 20260829223300",
    )
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(removed_migration_records, 4);

    sqlx::query("DROP INDEX CONCURRENTLY covenant_actions_covenant_time_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_actions_covenant_time_id_idx \
             ON covenant_actions (covenant_id)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenant_actions_covenant_id_id_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_actions_covenant_id_id_idx \
             ON covenant_actions (covenant_id)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_active_covenant_amount_outpoint_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_active_covenant_amount_outpoint_idx \
             ON covenant_utxos (covenant_id)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_active_address_amount_outpoint_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_active_address_amount_outpoint_idx \
             ON covenant_utxos (address)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenants_genesis_txid_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenants_genesis_txid_idx \
             ON covenants (genesis_txid)",
    )
    .execute(&pool)
    .await
    .is_err());
    sqlx::query("DROP INDEX CONCURRENTLY covenants_script_hash_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenants_script_hash_idx \
             ON covenants (script_hash)",
    )
    .execute(&pool)
    .await
    .is_err());

    let invalid_indexes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname IN (
             'covenant_actions_revert_block_idx',
             'covenant_utxos_spent_block_idx',
             'covenant_utxos_created_block_idx',
             'covenants_genesis_block_idx',
             'covenant_actions_covenant_time_id_idx',
             'covenant_actions_covenant_id_id_idx',
             'covenant_utxos_active_covenant_amount_outpoint_idx',
             'covenant_utxos_active_address_amount_outpoint_idx',
             'covenants_genesis_txid_idx',
             'covenants_script_hash_idx'
         )
           AND NOT i.indisvalid",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(invalid_indexes, 10);

    migrate(&pool).await.unwrap();

    let repaired_reorg_indexes: Vec<(String, bool, String)> = sqlx::query_as(
        "SELECT c.relname, i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname IN ( \
             'covenant_actions_revert_block_idx', \
             'covenant_utxos_spent_block_idx', \
             'covenant_utxos_created_block_idx', \
             'covenants_genesis_block_idx' \
         ) \
         ORDER BY c.relname",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(repaired_reorg_indexes.len(), 4);
    assert!(repaired_reorg_indexes.iter().all(|(_, valid, _)| *valid));
    assert!(repaired_reorg_indexes.iter().any(|(name, _, definition)| {
        name == "covenant_actions_revert_block_idx"
            && definition.contains("USING btree (block_hash)")
            && definition.contains("INCLUDE (action, covenant_id)")
    }));
    assert!(repaired_reorg_indexes.iter().any(|(name, _, definition)| {
        name == "covenant_utxos_spent_block_idx"
            && definition.contains("USING btree (spent_block)")
            && definition.contains("INCLUDE (covenant_id)")
            && definition.contains("WHERE (spent_block IS NOT NULL)")
    }));
    assert!(repaired_reorg_indexes.iter().any(|(name, _, definition)| {
        name == "covenant_utxos_created_block_idx"
            && definition.contains("USING btree (created_block)")
    }));
    assert!(repaired_reorg_indexes.iter().any(|(name, _, definition)| {
        name == "covenants_genesis_block_idx" && definition.contains("USING btree (genesis_block)")
    }));

    let (valid, definition): (bool, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname = 'covenant_actions_covenant_time_id_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid);
    assert!(definition.contains("block_time_ms DESC"));
    assert!(definition.contains("id DESC"));

    let (valid, definition): (bool, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname = 'covenant_actions_covenant_id_id_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid);
    assert!(definition.contains("USING btree (covenant_id, id)"));

    let (valid, definition): (bool, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname = 'covenants_script_hash_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid);
    assert!(definition.contains("USING btree (script_hash)"));

    let (valid, definition): (bool, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname = 'covenant_utxos_active_covenant_amount_outpoint_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid);
    assert!(definition.contains("amount_sompi DESC"));
    assert!(definition.contains("WHERE (status = 'active'::text)"));

    let (valid, definition): (bool, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname = 'covenant_utxos_active_address_amount_outpoint_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid);
    assert!(definition.contains("address"));
    assert!(definition.contains("amount_sompi DESC"));
    assert!(definition.contains("INCLUDE (covenant_id)"));
    assert!(definition.contains("WHERE (status = 'active'::text)"));

    let (valid, definition): (bool, String) = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_class c \
         JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE c.relname = 'covenants_genesis_txid_idx'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(valid);
    assert!(definition.contains("genesis_txid"));
    assert!(definition.contains("WHERE (genesis_txid IS NOT NULL)"));
}

#[sqlx::test(migrations = "./migrations")]
async fn template_summary_reconciliation_preserves_concurrent_first_delta(pool: PgPool) {
    let block = insert_block(&pool, 0x73, 1).await;
    insert_covenant(
        &pool,
        0x73,
        "kaspatest:preconcile-race",
        Some("ReconcileRace"),
        &block,
        1,
    )
    .await;
    sqlx::query("DELETE FROM covenant_template_summaries WHERE template = 'ReconcileRace'")
        .execute(&pool)
        .await
        .unwrap();

    let mut concurrent_tx = pool.begin().await.unwrap();
    sqlx::query(
        r#"INSERT INTO covenant_template_summaries
           (template, covenant_count, latest_created_at_ms)
           VALUES ('ReconcileRace', 1, 1778654400002)"#,
    )
    .execute(&mut *concurrent_tx)
    .await
    .unwrap();

    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *concurrent_tx)
        .await
        .unwrap();
    let mut reconcile_conn = pool.acquire().await.unwrap();
    let reconcile_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *reconcile_conn)
        .await
        .unwrap();
    let reconcile_task = tokio::spawn(async move {
        // Exercise a start delayed beyond the old 50 ms sleep-based barrier.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let migration = include_str!(
            "../migrations/20260830105100_reconcile_template_summaries_from_compact_state.sql"
        );
        let reconcile = migration
            .split("\n\nDELETE FROM covenant_template_summaries")
            .next()
            .unwrap();
        sqlx::query(reconcile).execute(&mut *reconcile_conn).await
    });
    // A pending task may still be waiting for CPU or a pool connection. Wait
    // until PostgreSQL proves the reconciliation snapshot precedes commit.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                .bind(writer_pid)
                .bind(reconcile_pid)
                .fetch_one(&pool)
                .await
                .unwrap();
            if blocked {
                break;
            }
            assert!(
                !reconcile_task.is_finished(),
                "reconciliation finished before blocking on the writer"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconciliation never reached the concurrent writer's lock");
    concurrent_tx.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), reconcile_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let (covenant_count, latest_created_at_ms): (i64, Option<i64>) = sqlx::query_as(
        r#"SELECT covenant_count, latest_created_at_ms
           FROM covenant_template_summaries
           WHERE template = 'ReconcileRace'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(covenant_count, 2);
    assert_eq!(latest_created_at_ms, Some(1778654400002));
}

#[sqlx::test(migrations = "./migrations")]
async fn template_summary_latest_action_lookup_uses_latest_index(pool: PgPool) {
    let definitions: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT p.proname, pg_get_functiondef(p.oid)
        FROM pg_proc p
        WHERE p.proname IN (
            'refresh_covenant_template_summary_from_action_delete_statement',
            'apply_covenant_template_summary_covenant_delete'
        )
        ORDER BY p.proname
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(definitions.len(), 2);
    assert!(definitions.iter().all(|(_, definition)| definition
        .contains("ORDER BY action_summary.latest_action_time_ms DESC NULLS LAST")));

    let block = insert_block(&pool, 0x74, 2).await;
    let covenant = insert_covenant(
        &pool,
        0x74,
        "kaspatest:latest-action-query-plan",
        None,
        &block,
        2,
    )
    .await;
    insert_action_with_inputs(&pool, &covenant, 0x75, &block, 2, "spend", json!([])).await;

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SET LOCAL enable_sort = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        r#"
        EXPLAIN (COSTS OFF)
        SELECT action_summary.latest_action_time_ms
        FROM covenant_action_summaries action_summary
        JOIN covenants covenant
          ON covenant.covenant_id = action_summary.covenant_id
        WHERE COALESCE(
                  covenant.template_name,
                  covenant.claimed_template,
                  'Unknown'
              ) = 'Unknown'
          AND action_summary.latest_action_time_ms IS NOT NULL
        ORDER BY action_summary.latest_action_time_ms DESC NULLS LAST
        LIMIT 1
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();

    let plan_text = plan.join("\n");
    assert!(
        plan_text.contains("covenant_action_summaries_latest_idx"),
        "latest-action lookup did not use its ordering index: {plan:#?}",
    );
    assert!(!plan_text.contains("Sort"), "unexpected sort: {plan:#?}");
}

// ---------- fixture helpers -----------------------------------------------

/// Insert a `blocks` row. Returns the 32-byte hash so callers can use it as
/// an FK in `covenants` / `covenant_utxos` / `covenant_actions`.
async fn insert_block(pool: &PgPool, tag: u8, blue_score: i64) -> Vec<u8> {
    let hash = vec![tag; 32];
    sqlx::query(
        r#"INSERT INTO blocks
           (hash, blue_score, daa_score, parent_hashes, timestamp_ms, is_chain_block, indexed_at_ms)
           VALUES ($1, $2, $2, ARRAY[]::bytea[], $3, TRUE, $3)"#,
    )
    .bind(&hash)
    .bind(blue_score)
    .bind(1778654400000_i64 + blue_score)
    .execute(pool)
    .await
    .unwrap();
    hash
}

async fn insert_market_summary(
    pool: &PgPool,
    tag: u8,
    total_volume_sompi: &str,
    total_trades: i64,
    last_trade_time_ms: Option<i64>,
) -> Vec<u8> {
    let token_id = vec![tag; 32];
    let last_trade_txid = last_trade_time_ms.map(|_| vec![0x40 | tag; 32]);
    sqlx::query(
        r#"INSERT INTO kcc20_market_summaries
           (token_id, best_ask_unit_price_sompi, best_bid_unit_price_sompi,
            spread_sompi, open_ask_count, open_bid_count, total_volume_sompi,
            total_trades, last_trade_txid, last_trade_time_ms, refreshed_at_ms,
            source_blue_score)
           VALUES ($1, $2::NUMERIC, $3::NUMERIC, $4::NUMERIC, $5, $6,
                   $7::NUMERIC, $8, $9, $10, $11, $12)"#,
    )
    .bind(&token_id)
    .bind((1000 + tag as i64).to_string())
    .bind((900 + tag as i64).to_string())
    .bind("100")
    .bind(tag as i64)
    .bind((tag as i64) + 1)
    .bind(total_volume_sompi)
    .bind(total_trades)
    .bind(&last_trade_txid)
    .bind(last_trade_time_ms)
    .bind(1778654500000_i64 + tag as i64)
    .bind(10_000_i64 + tag as i64)
    .execute(pool)
    .await
    .unwrap();
    token_id
}

fn kcc20_v2_placeholder_script() -> Vec<u8> {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-v2/KCC20V2.placeholder.json"
    ))
    .unwrap();
    artifact_script_array(&artifact)
}

fn kcc20_wrapper_placeholder_script() -> Vec<u8> {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-wrapper/KCC20Wrapper.placeholder.json"
    ))
    .unwrap();
    artifact_script_array(&artifact)
}

fn artifact_script_array(artifact: &serde_json::Value) -> Vec<u8> {
    artifact
        .get("bytecode")
        .or_else(|| artifact.get("script"))
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .expect("placeholder artifact has script or bytecode array")
}

fn kcc20_fee_ticket_placeholder_script() -> Vec<u8> {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-fee-ticket/KCC20FeeTicket.placeholder.json"
    ))
    .unwrap();
    serde_json::from_value(artifact["bytecode"].clone()).unwrap()
}

fn kcc20_fee_ticket_transfer_signature_script(recipient: [u8; 32], reveal_script: &[u8]) -> String {
    let mut sig = Vec::new();
    push_data(&mut sig, &[0x41; 65]);
    push_data(&mut sig, &recipient);
    sig.extend([1, 0]);
    push_i64(&mut sig, 0);
    push_data(&mut sig, &[0x1e, 0xae, 0x2a, 0xda]);
    push_data(&mut sig, reveal_script);
    hex::encode(sig)
}

fn kcc20_wrapper_action_signature_script(tag: [u8; 4], reveal_script: &[u8]) -> String {
    let mut sig = Vec::new();
    for _ in 0..6 {
        push_i64(&mut sig, 0);
    }
    push_i64(&mut sig, 1);
    push_i64(&mut sig, 2);
    push_i64(&mut sig, 3);
    push_i64(&mut sig, 4);
    push_data(&mut sig, &[0x77; 32]);
    push_i64(&mut sig, 0);
    push_i64(&mut sig, 5);
    push_data(&mut sig, &tag);
    push_data(&mut sig, reveal_script);
    hex::encode(sig)
}

fn kcc20_v2_public_mint_signature_script(
    recipient_owner: [u8; 32],
    token_amount: i64,
    token_output_index: i64,
    minter_output_index: i64,
    reveal_script: &[u8],
) -> String {
    let mut sig = Vec::new();
    sig.push(32);
    sig.extend(recipient_owner);
    push_i64(&mut sig, 0);
    push_i64(&mut sig, token_amount);
    push_i64(&mut sig, token_output_index);
    push_i64(&mut sig, minter_output_index);
    sig.push(0x53);
    push_data(&mut sig, reveal_script);
    hex::encode(sig)
}

fn kcc20_v2_public_mint_availability_signature_script(
    active: bool,
    minter_output_index: i64,
    reveal_script: &[u8],
) -> String {
    let mut sig = Vec::new();
    push_data(&mut sig, &[0x11; 65]);
    push_i64(&mut sig, i64::from(active));
    push_i64(&mut sig, minter_output_index);
    sig.push(0x57);
    push_data(&mut sig, reveal_script);
    hex::encode(sig)
}

fn kcc20_v2_holder_script(owner: [u8; 32], amount: i64) -> Vec<u8> {
    let mut script = kcc20_v2_placeholder_script();
    script[2..34].copy_from_slice(&owner);
    script[35..43].copy_from_slice(&0_i64.to_le_bytes());
    script[44..52].copy_from_slice(&amount.to_le_bytes());
    script[53..61].copy_from_slice(&0_i64.to_le_bytes());
    script
}

fn holder_merge_signature_script(
    primary_input_index: Option<i64>,
    merged_amount: Option<i64>,
    selector: u8,
    reveal_script: &[u8],
) -> String {
    let mut sig = Vec::new();
    push_data(&mut sig, &[0x11; 65]);
    if let Some(primary_input_index) = primary_input_index {
        push_i64(&mut sig, primary_input_index);
    }
    if let Some(merged_amount) = merged_amount {
        push_i64(&mut sig, merged_amount);
    }
    match selector {
        0x5a => push_data(&mut sig, &[0x80, 0xc5, 0x48, 0x6d]),
        0x5b => push_data(&mut sig, &[0x4b, 0xa1, 0xee, 0xf2]),
        _ => sig.push(selector),
    }
    push_data(&mut sig, reveal_script);
    hex::encode(sig)
}

async fn update_market_summary_windows(
    pool: &PgPool,
    token_id: &[u8],
    volume_24h_sompi: &str,
    volume_7d_sompi: &str,
    trade_count_24h: i64,
    trade_count_7d: i64,
) {
    sqlx::query(
        r#"UPDATE kcc20_market_summaries
           SET volume_24h_sompi = $2::NUMERIC,
               volume_7d_sompi = $3::NUMERIC,
               trade_count_24h = $4,
               trade_count_7d = $5
           WHERE token_id = $1"#,
    )
    .bind(token_id)
    .bind(volume_24h_sompi)
    .bind(volume_7d_sompi)
    .bind(trade_count_24h)
    .bind(trade_count_7d)
    .execute(pool)
    .await
    .unwrap();
}

/// Insert a legacy `covenants` row. `script_hash` doubles as `covenant_id`.
async fn insert_covenant(
    pool: &PgPool,
    tag: u8,
    address: &str,
    template: Option<&str>,
    block_hash: &[u8],
    blue_score: i64,
) -> Vec<u8> {
    let cov_id: Vec<u8> = vec![tag; 32];
    let txid: Vec<u8> = vec![0x80u8 | tag; 32];
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
            classification_kind, classification_status)
           VALUES ($1, $2, 0, $1, $3, $4, 0, $5, $6, NULL, $7, $8)"#,
    )
    .bind(&cov_id)
    .bind(address)
    .bind(template)
    .bind(&txid)
    .bind(block_hash)
    .bind(1778654400000_i64 + blue_score)
    .bind(if template.is_some() {
        "covenant"
    } else {
        "unknown"
    })
    .bind(if template.is_some() {
        "matched"
    } else {
        "unrevealed"
    })
    .execute(pool)
    .await
    .unwrap();
    cov_id
}

async fn insert_active_utxo(
    pool: &PgPool,
    covenant_id: &[u8],
    address: &str,
    amount: i64,
    block_hash: &[u8],
    txid_seed: u8,
) {
    // (txid, vout) is the utxos pk; caller picks a seed per call to keep
    // multi-utxo tests from colliding.
    let txid: Vec<u8> = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, $3, $4, $5, NULL, $6, NULL, NULL, 'active')"#,
    )
    .bind(&txid)
    .bind(covenant_id)
    .bind(address)
    .bind(amount)
    .bind(vec![0u8; 35])
    .bind(block_hash)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test]
async fn persister_batches_exact_covenant_outpoint_lookups(pool: PgPool) {
    let block = insert_block(&pool, 0x31, 100).await;
    let covenant = insert_covenant(
        &pool,
        0x32,
        "kaspatest:pbatched",
        Some("TimeLockVault"),
        &block,
        100,
    )
    .await;
    insert_active_utxo(
        &pool,
        &covenant,
        "kaspatest:pbatched",
        50_000_000,
        &block,
        0x33,
    )
    .await;
    let persister = PgPersister::new(pool);

    let existing = persister
        .existing_utxos(&[
            (hex::encode([0x33_u8; 32]), 0),
            (hex::encode([0x33_u8; 32]), 1),
            (hex::encode([0x34_u8; 32]), 0),
        ])
        .await
        .unwrap();

    assert_eq!(existing.len(), 1);
    assert!(existing.contains(&(hex::encode([0x33_u8; 32]), 0)));
}

async fn insert_active_utxo_with_state(
    pool: &PgPool,
    covenant_id: &[u8],
    address: &str,
    amount: i64,
    state: serde_json::Value,
    block_hash: &[u8],
    txid_seed: u8,
) {
    let txid: Vec<u8> = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, $3, $4, $5, $6, $7, NULL, NULL, 'active')"#,
    )
    .bind(&txid)
    .bind(covenant_id)
    .bind(address)
    .bind(amount)
    .bind(vec![0u8; 35])
    .bind(state)
    .bind(block_hash)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_utxo_with_state_at_vout(
    pool: &PgPool,
    covenant_id: &[u8],
    txid_seed: u8,
    vout: i32,
    block_hash: &[u8],
    state: serde_json::Value,
) {
    let txid: Vec<u8> = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, $2, $3, $4, 50000000, $5, $6, $7, NULL, NULL, 'active')"#,
    )
    .bind(&txid)
    .bind(vout)
    .bind(covenant_id)
    .bind(format!("kaspatest:fee-ticket-vout-{txid_seed:02x}-{vout}"))
    .bind(vec![0u8; 35])
    .bind(state)
    .bind(block_hash)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_active_utxo_with_script_hash(
    pool: &PgPool,
    covenant_id: &[u8],
    address: &str,
    amount: i64,
    script_hash: &[u8],
    block_hash: &[u8],
    txid_seed: u8,
) {
    let txid: Vec<u8> = vec![txid_seed; 32];
    let mut script_pubkey = Vec::with_capacity(35);
    script_pubkey.extend_from_slice(&[0xaa, 0x20]);
    script_pubkey.extend_from_slice(script_hash);
    script_pubkey.push(0x87);
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, $3, $4, $5, NULL, $6, NULL, NULL, 'active')"#,
    )
    .bind(&txid)
    .bind(covenant_id)
    .bind(address)
    .bind(amount)
    .bind(script_pubkey)
    .bind(block_hash)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test]
async fn kcc20_projection_dirty_watermark_tracks_only_new_dirty_rows(pool: PgPool) {
    let initial_dirty_id =
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_market_projection_name())
            .await
            .unwrap()
            .expect("migration should force one initial projection refresh");

    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_market_projection_name(),
        initial_dirty_id,
    )
    .await
    .unwrap();
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_market_projection_name())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_token_page_projection_name())
            .await
            .unwrap(),
        Some(initial_dirty_id)
    );
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        Some(initial_dirty_id)
    );
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_token_page_projection_name(),
        initial_dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        initial_dirty_id,
    )
    .await
    .unwrap();
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(
            &pool,
            repo::kcc20_owner_portfolio_assets_projection_name()
        )
        .await
        .unwrap(),
        Some(initial_dirty_id)
    );

    let txid = [0x42_u8; 32];
    let mut tx = pool.begin().await.unwrap();
    repo::mark_kcc20_projection_dirty_tx(&mut tx, "test_kcc20_write", Some(&txid))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let next_dirty_id =
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_market_projection_name())
            .await
            .unwrap()
            .expect("new KCC20 write should dirty projections");
    assert!(next_dirty_id > initial_dirty_id);
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_token_page_projection_name())
            .await
            .unwrap(),
        Some(next_dirty_id)
    );
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        Some(next_dirty_id)
    );

    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_market_projection_name(),
        next_dirty_id,
    )
    .await
    .unwrap();
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_market_projection_name())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_token_page_projection_name())
            .await
            .unwrap(),
        Some(next_dirty_id)
    );

    let freshness = repo::kcc20_projection_freshness(&pool).await.unwrap();
    assert!(!freshness.market.pending);
    assert!(freshness.token_page.pending);
    assert!(freshness.activity_feed.pending);
    assert!(freshness.owner_portfolio_assets.pending);
    assert_eq!(freshness.latest_dirty_id, next_dirty_id);
}

#[sqlx::test]
async fn kcc20_projection_pass_watermark_does_not_absorb_later_writes(pool: PgPool) {
    let pass_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_projection_dirty (reason, created_at_ms)
           VALUES ('write_after_pass_started', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let later_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    assert!(later_dirty_id > pass_dirty_id);

    let target = repo::kcc20_projection_dirty_target_for_through(
        &pool,
        repo::kcc20_owner_portfolio_assets_projection_name(),
        pass_dirty_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(target, pass_dirty_id);
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_portfolio_assets_projection_name(),
        target,
    )
    .await
    .unwrap();
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(
            &pool,
            repo::kcc20_owner_portfolio_assets_projection_name()
        )
        .await
        .unwrap(),
        Some(later_dirty_id)
    );
}

#[sqlx::test]
async fn kcc20_projection_pass_watermark_waits_for_earlier_sequence_commits(pool: PgPool) {
    let txid_a = vec![0x4a_u8; 32];
    let txid_b = vec![0x4b_u8; 32];
    let mut tx_a = pool.begin().await.unwrap();
    repo::mark_kcc20_projection_dirty_tx(&mut tx_a, "commit_order_a", Some(&txid_a))
        .await
        .unwrap();

    let mut tx_b = pool.begin().await.unwrap();
    repo::mark_kcc20_projection_dirty_tx(&mut tx_b, "commit_order_b", Some(&txid_b))
        .await
        .unwrap();
    tx_b.commit().await.unwrap();

    let barrier_pool = pool.clone();
    let barrier_task = tokio::spawn(async move {
        let mut conn = barrier_pool.acquire().await.unwrap();
        repo::capture_kcc20_projection_pass_dirty_id(&mut conn)
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !barrier_task.is_finished(),
        "pass boundary must wait for the lower uncommitted sequence value"
    );

    tx_a.commit().await.unwrap();
    let pass_dirty_id = tokio::time::timeout(Duration::from_secs(2), barrier_task)
        .await
        .unwrap()
        .unwrap();
    let committed_ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM kcc20_projection_dirty WHERE reason IN ('commit_order_a', 'commit_order_b') ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(committed_ids.len(), 2);
    assert!(committed_ids[0] < committed_ids[1]);
    assert_eq!(pass_dirty_id, committed_ids[1]);
}

#[sqlx::test]
async fn kcc20_activity_projection_target_bounds_distinct_txids_in_id_order(pool: PgPool) {
    let initial_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        initial_dirty_id,
    )
    .await
    .unwrap();

    let txid_a = vec![0x51_u8; 32];
    let txid_b = vec![0x52_u8; 32];
    let txid_c = vec![0x53_u8; 32];
    for (reason, txid) in [
        ("activity_a_first", Some(txid_a.as_slice())),
        ("activity_a_duplicate", Some(txid_a.as_slice())),
        ("block_revert_legacy_repair", None),
        ("activity_b_first", Some(txid_b.as_slice())),
        ("activity_b_duplicate", Some(txid_b.as_slice())),
        ("activity_c_overflow", Some(txid_c.as_slice())),
    ] {
        repo::mark_kcc20_projection_dirty(&pool, reason, txid)
            .await
            .unwrap();
    }
    let pass_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    let first_target =
        repo::kcc20_activity_projection_dirty_target_for_through(&pool, pass_dirty_id, 2)
            .await
            .unwrap()
            .unwrap();
    let expected_first_target: i64 = sqlx::query_scalar(
        "SELECT id FROM kcc20_projection_dirty WHERE reason = 'activity_b_duplicate'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(first_target, expected_first_target);

    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        first_target,
    )
    .await
    .unwrap();
    assert_eq!(
        repo::kcc20_activity_projection_dirty_target_for_through(&pool, pass_dirty_id, 2)
            .await
            .unwrap(),
        Some(pass_dirty_id)
    );
}

#[sqlx::test]
async fn kcc20_projection_dirty_notification_is_delivered_only_after_commit(pool: PgPool) {
    let mut listener = PgListener::connect_with(&pool).await.unwrap();
    listener
        .listen(repo::KCC20_PROJECTION_DIRTY_CHANNEL)
        .await
        .unwrap();

    let mut tx = pool.begin().await.unwrap();
    repo::mark_kcc20_projection_dirty_tx(&mut tx, "notification_test", None)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.recv())
            .await
            .is_err()
    );

    tx.commit().await.unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(1), listener.recv())
        .await
        .expect("notification timeout")
        .unwrap();
    assert_eq!(notification.channel(), repo::KCC20_PROJECTION_DIRTY_CHANNEL);
    assert!(notification.payload().parse::<i64>().unwrap() > 0);
}

#[sqlx::test]
async fn kcc20_projection_pruning_waits_for_every_projection(pool: PgPool) {
    let first_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    for projection in [
        repo::kcc20_market_projection_name(),
        repo::kcc20_token_page_projection_name(),
        repo::kcc20_activity_feed_projection_name(),
        repo::kcc20_owner_orders_projection_name(),
        repo::kcc20_owner_portfolio_assets_projection_name(),
        repo::kcc20_owner_action_history_projection_name(),
    ] {
        repo::mark_kcc20_projection_refreshed_for(&pool, projection, first_dirty_id)
            .await
            .unwrap();
    }
    for reason in ["coalesced_one", "coalesced_two", "coalesced_three"] {
        repo::mark_kcc20_projection_dirty(&pool, reason, None)
            .await
            .unwrap();
    }
    let pass_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();

    for projection in [
        repo::kcc20_market_projection_name(),
        repo::kcc20_token_page_projection_name(),
        repo::kcc20_activity_feed_projection_name(),
    ] {
        repo::mark_kcc20_projection_refreshed_for(&pool, projection, pass_dirty_id)
            .await
            .unwrap();
    }
    repo::prune_kcc20_projection_dirty(&pool, 100)
        .await
        .unwrap();
    let pending_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM kcc20_projection_dirty WHERE id > $1 AND id <= $2",
    )
    .bind(first_dirty_id)
    .bind(pass_dirty_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending_rows, 3);

    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_orders_projection_name(),
        pass_dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_portfolio_assets_projection_name(),
        pass_dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_action_history_projection_name(),
        pass_dirty_id,
    )
    .await
    .unwrap();
    assert!(
        repo::prune_kcc20_projection_dirty(&pool, 100)
            .await
            .unwrap()
            >= 3
    );
    let remaining_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM kcc20_projection_dirty WHERE id <= $1")
            .bind(pass_dirty_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining_rows, 0);
}

#[sqlx::test]
async fn kcc20_projection_dirty_txid_batch_deduplicates_input(pool: PgPool) {
    let txid = vec![0x44_u8; 32];
    let mut tx = pool.begin().await.unwrap();
    repo::mark_kcc20_projection_dirty_txids_tx(
        &mut tx,
        "dedupe_batch",
        &[txid.clone(), txid.clone(), txid.clone()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM kcc20_projection_dirty WHERE reason = 'dedupe_batch'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rows, 1);
}

#[sqlx::test]
async fn kcc20_activity_refresh_disables_jit_only_in_its_transaction(pool: PgPool) {
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    sqlx::query("SET jit = on").execute(&single).await.unwrap();
    let block = insert_block(&single, 0x32, 300).await;
    let token = insert_covenant(
        &single,
        0x32,
        "kaspatest:activity-jit",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    insert_v3_trade_action(
        &single,
        &token,
        0x61,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xa1,
    )
    .await;
    sqlx::raw_sql(
        r#"
        CREATE FUNCTION assert_activity_refresh_jit_off() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF current_setting('jit') <> 'off' THEN
                RAISE EXCEPTION 'activity refresh must disable JIT locally';
            END IF;
            RETURN NULL;
        END;
        $$;
        CREATE TRIGGER assert_activity_refresh_jit_off
        BEFORE INSERT ON kcc20_activity_feed
        FOR EACH STATEMENT EXECUTE FUNCTION assert_activity_refresh_jit_off();
        "#,
    )
    .execute(&single)
    .await
    .unwrap();

    // Exercise both the initial rebuild and the scoped dirty-transaction path.
    repo::refresh_kcc20_activity_feed(&single).await.unwrap();
    let clean = repo::kcc20_projection_latest_dirty_id(&single)
        .await
        .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &single,
        repo::kcc20_activity_feed_projection_name(),
        clean,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_dirty(&single, "jit_regression", Some(&vec![0x61_u8; 32]))
        .await
        .unwrap();
    let target = repo::kcc20_projection_latest_dirty_id(&single)
        .await
        .unwrap();
    let stats = repo::refresh_kcc20_activity_feed_with_config(
        &single,
        repo::Kcc20ActivityFeedRefreshConfig::projector(target, false, "10s".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(stats.mode, repo::Kcc20ActivityFeedRefreshMode::ScopedTxids);
    assert_eq!(stats.rows_inserted, 1);
    let amount: String = sqlx::query_scalar("SELECT token_amount FROM kcc20_activity_feed")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(amount, "10");
    let restored: String = sqlx::query_scalar("SHOW jit")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(
        restored, "on",
        "refresh must preserve the caller's JIT setting"
    );

    sqlx::raw_sql(
        r#"
        CREATE OR REPLACE FUNCTION assert_activity_refresh_jit_off() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF current_setting('jit') <> 'off' THEN
                RAISE EXCEPTION 'activity refresh must disable JIT locally';
            END IF;
            RAISE EXCEPTION 'injected activity refresh failure';
        END;
        $$;
        "#,
    )
    .execute(&single)
    .await
    .unwrap();
    repo::mark_kcc20_projection_dirty(&single, "jit_regression_failure", Some(&vec![0x61_u8; 32]))
        .await
        .unwrap();
    let error = repo::refresh_kcc20_activity_feed(&single)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("injected activity refresh failure"));
    let restored: String = sqlx::query_scalar("SHOW jit")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(
        restored, "on",
        "rollback must restore JIT on the same connection"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_activity_feed")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(rows, 1, "failed refresh must preserve the committed feed");
    single.close().await;
}

#[sqlx::test]
async fn kcc20_market_refresh_disables_jit_only_in_its_transaction(pool: PgPool) {
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    sqlx::query("SET jit = on").execute(&single).await.unwrap();
    sqlx::raw_sql(
        r#"
        CREATE FUNCTION assert_market_refresh_jit_off() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF current_setting('jit') <> 'off' THEN
                RAISE EXCEPTION 'market refresh must disable JIT locally';
            END IF;
            RETURN NULL;
        END;
        $$;
        CREATE TRIGGER assert_market_refresh_jit_off
        BEFORE INSERT ON kcc20_market_summaries
        FOR EACH STATEMENT EXECUTE FUNCTION assert_market_refresh_jit_off();
        "#,
    )
    .execute(&single)
    .await
    .unwrap();

    repo::refresh_kcc20_owner_orders(&single).await.unwrap();
    repo::refresh_kcc20_market_summaries(&single).await.unwrap();
    let restored: String = sqlx::query_scalar("SHOW jit")
        .fetch_one(&single)
        .await
        .unwrap();
    assert_eq!(
        restored, "on",
        "refresh must preserve the caller's JIT setting"
    );
    single.close().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_market_refresh_reuses_open_owner_order_prices(pool: PgPool) {
    let token = vec![0x27_u8; 32];
    sqlx::query(
        "INSERT INTO kcc20_owner_orders \
         (order_id, side, status, token_id, owner, remaining_token_amount, \
          unit_price_sompi, address, created_at_ms, refreshed_at_ms) VALUES \
         ('ask', 'ask', 'open', $1, $2, '3', '120', 'kaspatest:ask', 100, 100), \
         ('bid', 'bid', 'open', $1, $2, '4', '90', 'kaspatest:bid', 100, 100)",
    )
    .bind(&token)
    .bind("21".repeat(32))
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();
    let row: (i64, i64, String, String) = sqlx::query_as(
        "SELECT open_ask_count, open_bid_count, \
         best_ask_unit_price_sompi::TEXT, best_bid_unit_price_sompi::TEXT \
         FROM kcc20_market_summaries WHERE token_id=$1",
    )
    .bind(&token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (1, 1, "120".to_string(), "90".to_string()));

    sqlx::query("UPDATE kcc20_owner_orders SET status='cancelled' WHERE order_id='ask'")
        .execute(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();
    let row: (i64, i64, Option<String>, String) = sqlx::query_as(
        "SELECT open_ask_count, open_bid_count, \
         best_ask_unit_price_sompi::TEXT, best_bid_unit_price_sompi::TEXT \
         FROM kcc20_market_summaries WHERE token_id=$1",
    )
    .bind(&token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (0, 1, None, "90".to_string()));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_market_refresh_preserves_legacy_order_unit_prices(pool: PgPool) {
    let token = vec![0x28_u8; 32];
    sqlx::query(
        "INSERT INTO kcc20_owner_orders \
         (order_id, side, status, token_id, owner, token_amount, \
          remaining_token_amount, price_sompi, template_name, address, \
          created_at_ms, refreshed_at_ms) VALUES \
         ('legacy-ask', 'ask', 'open', $1, $2, '10', '8', '1000', \
          'KCC20SaleV2', 'kaspatest:legacy-ask', 100, 100), \
         ('legacy-bid', 'bid', 'open', $1, $2, '20', '20', '2200', \
          'KCC20BuyOrder', 'kaspatest:legacy-bid', 100, 100)",
    )
    .bind(&token)
    .bind("22".repeat(32))
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();
    let row: (i64, i64, String, String) = sqlx::query_as(
        "SELECT open_ask_count, open_bid_count, \
         best_ask_unit_price_sompi::TEXT, best_bid_unit_price_sompi::TEXT \
         FROM kcc20_market_summaries WHERE token_id=$1",
    )
    .bind(&token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (1, 1, "100".to_string(), "110".to_string()));
}

#[sqlx::test]
async fn kcc20_market_refresh_reports_lock_contention_instead_of_succeeding(pool: PgPool) {
    let mut lock_connection = pool.acquire().await.unwrap();
    sqlx::query(
        "SELECT pg_advisory_lock(hashtextextended('tn12:kcc20_market_summaries_refresh', 0))",
    )
    .execute(&mut *lock_connection)
    .await
    .unwrap();

    let error = repo::refresh_kcc20_market_summaries(&pool)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("lock timeout"));

    let unlocked: bool = sqlx::query_scalar(
        "SELECT pg_advisory_unlock(hashtextextended('tn12:kcc20_market_summaries_refresh', 0))",
    )
    .fetch_one(&mut *lock_connection)
    .await
    .unwrap();
    assert!(unlocked);
}

#[sqlx::test]
async fn kcc20_activity_request_refresh_skips_lock_contention(pool: PgPool) {
    let mut lock_connection = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock(hashtextextended('tn12:kcc20_activity_feed_refresh', 0))")
        .execute(&mut *lock_connection)
        .await
        .unwrap();

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();

    let unlocked: bool = sqlx::query_scalar(
        "SELECT pg_advisory_unlock(hashtextextended('tn12:kcc20_activity_feed_refresh', 0))",
    )
    .fetch_one(&mut *lock_connection)
    .await
    .unwrap();
    assert!(unlocked);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_read_leaves_pending_refresh_to_projector(pool: PgPool) {
    let block = insert_block(&pool, 0x31, 300).await;
    let token = insert_covenant(
        &pool,
        0x31,
        "kaspatest:activity",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    let txid = vec![0x52_u8; 32];
    let owner = hex::encode(vec![0xa1; 32]);

    insert_v3_trade_action(
        &pool,
        &token,
        0x52,
        &block,
        400,
        "fillAskPartial",
        "25",
        "100",
        0xa1,
    )
    .await;
    let other_token = insert_covenant(
        &pool,
        0x3f,
        "kaspatest:activity-other",
        Some("KCC20"),
        &block,
        301,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed (
               token_id, txid, block_time_ms, kind, side, owner_identifier,
               owner_identifier_type, owner_identifier_type_version, token_amount
           )
           VALUES ($1, $2, 300, 'trade', 'bid', $3, NULL, 0, '100')"#,
    )
    .bind(&other_token)
    .bind(vec![0x51_u8; 32])
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();

    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "kcc20_persist", Some(&txid))
        .await
        .unwrap();

    let activity = repo::kcc20_activity_filtered(
        &pool,
        &hex::encode(&token),
        &repo::Kcc20ActivityFilter {
            scope: Some("trading".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert!(activity.is_empty());

    let feed_row_count_before_projector: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_activity_feed WHERE token_id = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(feed_row_count_before_projector, 0);
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        Some(clean_dirty_id + 1)
    );

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let feed_row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_activity_feed WHERE token_id = $1")
            .bind(&token)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(feed_row_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_projector_removes_obsolete_projected_rows(pool: PgPool) {
    let block = insert_block(&pool, 0x32, 300).await;
    let token = insert_covenant(
        &pool,
        0x32,
        "kaspatest:activity-dirty-overlay",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    let txid = vec![0x53_u8; 32];
    let stale_owner = hex::encode(vec![0xa2; 32]);

    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed (
               token_id, txid, block_time_ms, kind, side, owner_identifier,
               owner_identifier_type, owner_identifier_type_version, token_amount
           )
           VALUES ($1, $2, 400, 'trade', 'ask', $3, 0, 1, '25')"#,
    )
    .bind(&token)
    .bind(&txid)
    .bind(&stale_owner)
    .execute(&pool)
    .await
    .unwrap();
    insert_v3_trade_action(
        &pool,
        &token,
        0x53,
        &block,
        400,
        "fillAskPartial",
        "25",
        "100",
        0xa3,
    )
    .await;

    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "kcc20_reclassification", Some(&txid))
        .await
        .unwrap();

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();

    let activity = repo::kcc20_activity_filtered(
        &pool,
        &hex::encode(&token),
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            owner: Some(stale_owner.to_ascii_uppercase()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert!(activity.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_projects_standard_native_actions_and_excludes_retired_v2(pool: PgPool) {
    let block = insert_block(&pool, 0x30, 300).await;
    let token = insert_covenant(
        &pool,
        0x30,
        "kaspatest:standard-native",
        Some("KCC20"),
        &block,
        300,
    )
    .await;
    let retired = insert_covenant(
        &pool,
        0x2f,
        "kaspatest:retired-native",
        Some("KCC20V2"),
        &block,
        299,
    )
    .await;
    let owner = "ab".repeat(32);

    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x40,
        &block,
        400,
        "spend",
        Some("mint_public"),
        None,
        Some(json!({"tokenOutputIndex": "0", "minterOutputIndex": "1"})),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x40,
        &block,
        400,
        "continuation",
        None,
        Some(json!({
            "vout": "0",
            "state": {"owner": owner, "ownerScheme": 3, "amount": "25"}
        })),
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x40,
        &block,
        400,
        "continuation",
        None,
        Some(json!({
            "vout": "1",
            "state": {
                "owner": "cd".repeat(32),
                "ownerScheme": 0,
                "amount": "0",
                "isMintAuthority": true
            }
        })),
        None,
    )
    .await;

    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x41,
        &block,
        401,
        "spend",
        Some("set_public_mint_active"),
        None,
        Some(json!({"minterOutputIndex": "0", "active": true})),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x41,
        &block,
        401,
        "continuation",
        None,
        Some(json!({
            "vout": "0",
            "state": {
                "owner": "cd".repeat(32),
                "ownerScheme": 0,
                "amount": "0",
                "isMintAuthority": true,
                "publicMintActive": true
            }
        })),
        None,
    )
    .await;

    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x42,
        &block,
        402,
        "spend",
        Some("transfer"),
        None,
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x42,
        &block,
        402,
        "continuation",
        None,
        Some(json!({
            "vout": "0",
            "state": {"owner": owner, "ownerScheme": 3, "amount": "20"}
        })),
        None,
    )
    .await;

    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x43,
        &block,
        403,
        "spend",
        Some("burn"),
        None,
        Some(json!({"burnAmount": "5"})),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x43,
        &block,
        403,
        "continuation",
        None,
        Some(json!({
            "vout": "0",
            "state": {"owner": owner, "ownerScheme": 3, "amount": "15"}
        })),
        None,
    )
    .await;

    insert_action_with_outputs_and_args(
        &pool,
        &retired,
        0x44,
        &block,
        404,
        "continuation",
        Some("mintByAuthoritySig"),
        Some(json!({
            "vout": "0",
            "state": {"ownerIdentifier": owner, "identifierType": 0, "amount": "999"}
        })),
        None,
    )
    .await;

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &hex::encode(&token), 20, 0)
        .await
        .unwrap();

    assert_eq!(activity.iter().filter(|row| row.kind == "mint").count(), 1);
    assert!(activity.iter().any(|row| {
        row.kind == "mint"
            && row.entrypoint.as_deref() == Some("mint_public")
            && row.owner.as_deref() == Some(owner.as_str())
            && row.owner_identifier_type == Some(3)
            && row.token_amount.as_deref() == Some("25")
    }));
    assert!(activity.iter().any(|row| {
        row.kind == "mintConfig" && row.entrypoint.as_deref() == Some("set_public_mint_active")
    }));
    assert!(activity.iter().any(|row| {
        row.kind == "transfer"
            && row.entrypoint.as_deref() == Some("transfer")
            && row.token_amount.as_deref() == Some("20")
    }));
    assert!(activity.iter().any(|row| {
        row.kind == "burn"
            && row.entrypoint.as_deref() == Some("burn")
            && row.token_amount.as_deref() == Some("5")
    }));
    assert_eq!(activity.iter().filter(|row| row.kind == "burn").count(), 1);

    let retired_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_activity_feed WHERE token_id = $1")
            .bind(&retired)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retired_rows, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_refresh_replays_pending_dirty_txid_without_old_range_rebuild(pool: PgPool) {
    let block = insert_block(&pool, 0x32, 300).await;
    let token = insert_covenant(
        &pool,
        0x32,
        "kaspatest:activity-dirty-window",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    let token_hex = hex::encode(&token);

    insert_v3_trade_action(
        &pool,
        &token,
        0x61,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xa1,
    )
    .await;
    insert_v3_trade_action(
        &pool,
        &token,
        0x62,
        &block,
        5_000_000,
        "fillAskPartial",
        "20",
        "100",
        0xa2,
    )
    .await;
    insert_v3_trade_action(
        &pool,
        &token,
        0x67,
        &block,
        10_000_000,
        "fillAskPartial",
        "40",
        "100",
        0xa7,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kcc20_activity_feed SET token_amount = 'stale' WHERE txid = $1")
        .bind(vec![0x62_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "activity_feed_dirty_txid_backfill", None)
        .await
        .unwrap();

    insert_v3_trade_action(
        &pool,
        &token,
        0x63,
        &block,
        2_000,
        "fillAskPartial",
        "30",
        "100",
        0xa3,
    )
    .await;
    repo::mark_kcc20_projection_dirty(&pool, "late_kcc20_persist", Some(&vec![0x63_u8; 32]))
        .await
        .unwrap();

    let stats = repo::refresh_kcc20_activity_feed_with_config(
        &pool,
        repo::Kcc20ActivityFeedRefreshConfig::request_path(),
    )
    .await
    .unwrap();
    assert_eq!(stats.mode, repo::Kcc20ActivityFeedRefreshMode::ScopedTxids);
    assert_eq!(stats.dirty_rows, 2);
    assert_eq!(stats.scoped_dirty_txids, 1);
    let activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        activity
            .iter()
            .map(|row| row.token_amount.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["40", "stale", "30", "10"]
    );
    assert!(activity
        .iter()
        .any(|row| row.txid_hex == hex::encode(vec![0x63_u8; 32])));
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        None
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_refresh_dedupes_duplicate_dirty_txids(pool: PgPool) {
    let block = insert_block(&pool, 0x34, 300).await;
    let token = insert_covenant(
        &pool,
        0x34,
        "kaspatest:activity-duplicate-dirty",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;

    insert_v3_trade_action(
        &pool,
        &token,
        0x70,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xb0,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();

    let txid = vec![0x71_u8; 32];
    insert_v3_trade_action(
        &pool,
        &token,
        0x71,
        &block,
        2_000,
        "fillAskPartial",
        "20",
        "100",
        0xb1,
    )
    .await;
    repo::mark_kcc20_projection_dirty(&pool, "late_kcc20_persist", Some(&txid))
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "late_kcc20_persist", Some(&txid))
        .await
        .unwrap();

    let stats = repo::refresh_kcc20_activity_feed_with_config(
        &pool,
        repo::Kcc20ActivityFeedRefreshConfig::request_path(),
    )
    .await
    .unwrap();
    assert_eq!(stats.mode, repo::Kcc20ActivityFeedRefreshMode::ScopedTxids);
    assert_eq!(stats.dirty_rows, 2);
    assert_eq!(stats.scoped_dirty_txids, 1);

    let feed_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM kcc20_activity_feed WHERE txid = $1")
            .bind(txid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(feed_rows, 1);
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        None
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_legacy_revert_reconciles_existing_feed_without_full_scan(pool: PgPool) {
    let block = insert_block(&pool, 0x36, 300).await;
    let token = insert_covenant(
        &pool,
        0x36,
        "kaspatest:activity-legacy-revert",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    let txid = vec![0x74_u8; 32];

    insert_v3_trade_action(
        &pool,
        &token,
        0x74,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xb4,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();

    sqlx::query("DELETE FROM covenant_actions WHERE txid = $1")
        .bind(&txid)
        .execute(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "block_revert_legacy_repair", None)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "activity_feed_dirty_txid_backfill", Some(&txid))
        .await
        .unwrap();
    let target_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();

    let stats = repo::refresh_kcc20_activity_feed_with_config(
        &pool,
        repo::Kcc20ActivityFeedRefreshConfig::projector(target_dirty_id, false, "10s".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(stats.mode, repo::Kcc20ActivityFeedRefreshMode::ScopedTxids);
    assert_eq!(stats.scoped_dirty_txids, 1);
    let feed_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM kcc20_activity_feed WHERE txid = $1")
            .bind(txid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(feed_rows, 0);
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        None
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn legacy_activity_revert_migration_scopes_every_existing_feed_txid(pool: PgPool) {
    let block = insert_block(&pool, 0x37, 300).await;
    let token = insert_covenant(
        &pool,
        0x37,
        "kaspatest:activity-legacy-migration",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    insert_v3_trade_action(
        &pool,
        &token,
        0x75,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xb5,
    )
    .await;
    insert_v3_trade_action(
        &pool,
        &token,
        0x77,
        &block,
        1_100,
        "fillAskPartial",
        "11",
        "101",
        0xb6,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();
    let scoped_duplicate_txid = vec![0x76_u8; 32];
    for txid in [
        vec![0x75_u8; 32],
        vec![0x75_u8; 32],
        scoped_duplicate_txid.clone(),
        scoped_duplicate_txid.clone(),
    ] {
        repo::mark_kcc20_projection_dirty(&pool, "duplicate_pending", Some(&txid))
            .await
            .unwrap();
    }
    repo::mark_kcc20_projection_dirty(&pool, "block_revert", None)
        .await
        .unwrap();

    sqlx::raw_sql(include_str!(
        "../migrations/20260830130000_recover_legacy_activity_reverts.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let legacy_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM kcc20_projection_dirty WHERE reason = 'block_revert_legacy_repair' AND txid IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(legacy_rows, 1);
    let scoped_txids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT txid FROM kcc20_projection_dirty WHERE reason = 'activity_feed_dirty_txid_backfill' AND txid IS NOT NULL",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        scoped_txids,
        vec![vec![0x77_u8; 32]],
        "only feed txids without a pending scoped marker need backfill"
    );
    let pending_counts: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        r#"SELECT txid, COUNT(*)::BIGINT
           FROM kcc20_projection_dirty
           WHERE id > $1 AND txid IS NOT NULL
           GROUP BY txid
           ORDER BY txid"#,
    )
    .bind(clean_dirty_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        pending_counts,
        vec![
            (vec![0x75_u8; 32], 1),
            (scoped_duplicate_txid, 1),
            (vec![0x77_u8; 32], 1),
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_disabled_full_refresh_does_not_pin_later_scoped_dirty(pool: PgPool) {
    let block = insert_block(&pool, 0x35, 300).await;
    let token = insert_covenant(
        &pool,
        0x35,
        "kaspatest:activity-periodic-repair",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    let token_hex = hex::encode(&token);

    insert_v3_trade_action(
        &pool,
        &token,
        0x72,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xb2,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();

    repo::mark_kcc20_projection_dirty(&pool, "periodic_projection_repair", None)
        .await
        .unwrap();
    insert_v3_trade_action(
        &pool,
        &token,
        0x73,
        &block,
        2_000,
        "fillAskPartial",
        "20",
        "100",
        0xb3,
    )
    .await;
    repo::mark_kcc20_projection_dirty(&pool, "kcc20_persist", Some(&vec![0x73_u8; 32]))
        .await
        .unwrap();
    let target_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();

    let stats = repo::refresh_kcc20_activity_feed_with_config(
        &pool,
        repo::Kcc20ActivityFeedRefreshConfig::projector(target_dirty_id, false, "10s".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(stats.mode, repo::Kcc20ActivityFeedRefreshMode::ScopedTxids);
    assert_eq!(stats.dirty_rows, 2);
    assert_eq!(stats.activity_dirty_rows, 1);
    assert_eq!(stats.scoped_dirty_txids, 1);

    let activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert!(activity
        .iter()
        .any(|row| row.txid_hex == hex::encode(vec![0x73_u8; 32])));
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        None
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_activity_refresh_rebuilds_for_unscoped_dirty_backfill(pool: PgPool) {
    let block = insert_block(&pool, 0x33, 300).await;
    let token = insert_covenant(
        &pool,
        0x33,
        "kaspatest:activity-unscoped-backfill",
        Some("KCC20Orderbook"),
        &block,
        300,
    )
    .await;
    let token_hex = hex::encode(&token);

    insert_v3_trade_action(
        &pool,
        &token,
        0x64,
        &block,
        1_000,
        "fillAskPartial",
        "10",
        "100",
        0xa4,
    )
    .await;
    insert_v3_trade_action(
        &pool,
        &token,
        0x65,
        &block,
        10_000_000,
        "fillAskPartial",
        "20",
        "100",
        0xa5,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let clean_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        clean_dirty_id,
    )
    .await
    .unwrap();

    insert_v3_trade_action(
        &pool,
        &token,
        0x66,
        &block,
        2_000,
        "fillAskPartial",
        "30",
        "100",
        0xa6,
    )
    .await;
    repo::mark_kcc20_projection_dirty(&pool, "activity_feed_backfill", None)
        .await
        .unwrap();

    let stats = repo::refresh_kcc20_activity_feed_with_config(
        &pool,
        repo::Kcc20ActivityFeedRefreshConfig::request_path(),
    )
    .await
    .unwrap();
    assert_eq!(stats.mode, repo::Kcc20ActivityFeedRefreshMode::Full);
    assert_eq!(stats.dirty_rows, 1);
    let activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        activity
            .iter()
            .map(|row| row.token_amount.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["20", "30", "10"]
    );
    assert!(activity
        .iter()
        .any(|row| row.txid_hex == hex::encode(vec![0x66_u8; 32])));
    assert_eq!(
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_activity_feed_projection_name())
            .await
            .unwrap(),
        None
    );
}

#[sqlx::test]
async fn kcc20_activity_refresh_excludes_retired_sale_trades(pool: PgPool) {
    let block = insert_block(&pool, 0x68, 300).await;
    let token = insert_covenant(
        &pool,
        0x68,
        "kaspatest:legacy-sale-token",
        Some("KCC20"),
        &block,
        300,
    )
    .await;
    let token_hex = hex::encode(&token);
    let sale = insert_covenant(
        &pool,
        0x69,
        "kaspatest:legacy-sale",
        Some("KCC20Sale"),
        &block,
        301,
    )
    .await;
    let seller = "ab".repeat(32);

    insert_action_with_outputs_and_args(
        &pool,
        &sale,
        0x6a,
        &block,
        1_000,
        "spend",
        Some("buy"),
        None,
        Some(json!({
            "seller": seller,
            "tokenId": token_hex,
            "tokenAmount": "10",
            "priceSompi": "5000000"
        })),
    )
    .await;

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();

    assert!(activity.is_empty());
}

#[sqlx::test]
async fn kcc20_fast_freshness_requires_a_recent_realtime_cursor_and_clean_projections(
    pool: PgPool,
) {
    insert_block(&pool, 1, 100).await;
    sqlx::query(
        r#"INSERT INTO indexer_state (key, value, updated_at_ms)
           VALUES (
             'chain_realtime_tip_cursor',
             $1,
             EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
           )"#,
    )
    .bind(json!({
        "blue_score": 99,
        "rest_database_blue_score": 100,
        "rest_database_observed_at_ms": chrono::Utc::now().timestamp_millis()
    }))
    .execute(&pool)
    .await
    .unwrap();

    let dirty_id =
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_market_projection_name())
            .await
            .unwrap()
            .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_market_projection_name(),
        dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_token_page_projection_name(),
        dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_activity_feed_projection_name(),
        dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_orders_projection_name(),
        dirty_id,
    )
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_portfolio_assets_projection_name(),
        dirty_id,
    )
    .await
    .unwrap();

    let fresh = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert!(fresh.ok);
    assert!(!fresh.stale);
    assert_eq!(
        fresh.scanner.cursor_key.as_deref(),
        Some("chain_realtime_tip_cursor")
    );

    sqlx::query(
        "INSERT INTO indexer_state (key, value, updated_at_ms) \
         VALUES ('chain_live_near_tip_repair_cursor', \
                 '{\"blue_score\":99,\"rest_database_blue_score\":100}', \
                 EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let near_tip = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert_eq!(
        near_tip.scanner.cursor_key.as_deref(),
        Some("chain_live_near_tip_repair_cursor")
    );
    sqlx::query("DELETE FROM indexer_state WHERE key = 'chain_live_near_tip_repair_cursor'")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO indexer_state (key, value, updated_at_ms) \
         VALUES ('chain_wrpc_acceptance_heartbeat', '{\"blue_score\":99}', \
                 EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let live = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert!(live.scanner.live_acceptance_fresh);
    assert!(live.ok);
    sqlx::query(
        "UPDATE indexer_state SET value = '{\"blue_score\":6500100}' \
         WHERE key = 'chain_wrpc_acceptance_heartbeat'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let stale_rest = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert_eq!(
        stale_rest.scanner.live_acceptance_blue_score,
        Some(6_500_100)
    );
    assert_eq!(stale_rest.scanner.rest_db_lag_blocks, Some(6_500_000));
    assert!(!stale_rest.ok);
    assert!(stale_rest.stale);
    sqlx::query(
        "UPDATE indexer_state SET value = '{\"blue_score\":99}' \
         WHERE key = 'chain_wrpc_acceptance_heartbeat'",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE indexer_state SET updated_at_ms = \
         EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - 61000 \
         WHERE key = 'chain_wrpc_acceptance_heartbeat'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let missed_live = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert!(!missed_live.scanner.live_acceptance_fresh);
    assert!(!missed_live.ok);
    assert!(missed_live.stale);
    sqlx::query(
        "UPDATE indexer_state SET updated_at_ms = \
         EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 \
         WHERE key = 'chain_wrpc_acceptance_heartbeat'",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"UPDATE indexer_state
           SET value = value || $1
           WHERE key = 'chain_realtime_tip_cursor'"#,
    )
    .bind(json!({"rest_database_blue_score": 250}))
    .execute(&pool)
    .await
    .unwrap();
    let rest_tip_lagged = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert!(!rest_tip_lagged.ok);
    assert!(rest_tip_lagged.stale);
    assert_eq!(rest_tip_lagged.scanner.rest_database_blue_score, Some(250));
    assert_eq!(rest_tip_lagged.scanner.db_cursor_lag_blocks, Some(151));

    sqlx::query(
        r#"UPDATE indexer_state
           SET value = value - 'rest_database_blue_score'
           WHERE key = 'chain_realtime_tip_cursor'"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO kcc20_projection_dirty (reason, created_at_ms)
           VALUES ('portfolio_pending', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let portfolio_pending_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    for projection in [
        repo::kcc20_market_projection_name(),
        repo::kcc20_token_page_projection_name(),
        repo::kcc20_activity_feed_projection_name(),
        repo::kcc20_owner_orders_projection_name(),
    ] {
        repo::mark_kcc20_projection_refreshed_for(&pool, projection, portfolio_pending_id)
            .await
            .unwrap();
    }
    let portfolio_pending = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert!(!portfolio_pending.ok);

    sqlx::query(
        r#"UPDATE indexer_state
           SET updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - 61000
           WHERE key = 'chain_realtime_tip_cursor'"#,
    )
    .execute(&pool)
    .await
    .unwrap();
    let stale = repo::kcc20_fast_freshness(&pool).await.unwrap();
    assert!(!stale.ok);
    assert!(stale.stale);
}

#[sqlx::test]
async fn kcc20_projection_freshness_ages_oldest_unprocessed_write(pool: PgPool) {
    let initial_dirty_id =
        repo::kcc20_projection_dirty_target_for(&pool, repo::kcc20_market_projection_name())
            .await
            .unwrap()
            .unwrap();
    for projection in [
        repo::kcc20_market_projection_name(),
        repo::kcc20_token_page_projection_name(),
        repo::kcc20_activity_feed_projection_name(),
        repo::kcc20_owner_orders_projection_name(),
        repo::kcc20_owner_portfolio_assets_projection_name(),
    ] {
        repo::mark_kcc20_projection_refreshed_for(&pool, projection, initial_dirty_id)
            .await
            .unwrap();
    }
    sqlx::query(
        r#"INSERT INTO kcc20_projection_dirty (reason, created_at_ms)
           VALUES
             ('old_unprocessed_write', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 - 120000),
             ('recent_unprocessed_write', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let freshness = repo::kcc20_projection_freshness(&pool).await.unwrap();
    assert!(freshness.market.pending);
    assert!(freshness.token_page.pending);
    assert!(freshness.activity_feed.pending);
    assert!(freshness.owner_orders.pending);
    assert!(freshness.owner_portfolio_assets.pending);
    assert!(freshness
        .market
        .pending_age_ms
        .is_some_and(|age| age >= 120_000));
    assert!(freshness
        .token_page
        .pending_age_ms
        .is_some_and(|age| age >= 120_000));
    assert!(freshness
        .activity_feed
        .pending_age_ms
        .is_some_and(|age| age >= 120_000));
    assert!(freshness
        .owner_orders
        .pending_age_ms
        .is_some_and(|age| age >= 120_000));
    assert!(freshness
        .owner_portfolio_assets
        .pending_age_ms
        .is_some_and(|age| age >= 120_000));
}

#[sqlx::test]
async fn kcc20_wrapper_deploy_seeds_wrapped_root_state(pool: PgPool) {
    let token_id = "45".repeat(32);
    let wrapper_id = "91".repeat(32);
    let owner = "ce".repeat(32);
    let txid = "50".repeat(32);

    let tx = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654401000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("51".repeat(32)),
        accepting_block_blue_score: Some(101),
        payload: Some(hex::encode(
            json!({
                "tn10": {
                    "v": 1,
                    "tmpl": "KCC20Wrapper",
                    "args": [
                        {"name": "canonicalTokenId", "type": "byte[32]", "value": token_id},
                        {"name": "feeTicketId", "type": "byte[32]", "value": "00".repeat(32)},
                        {"name": "wrappedRootAmount", "type": "u64", "value": "0"},
                        {"name": "priceScale", "type": "u64", "value": "100000000"}
                    ]
                }
            })
            .to_string(),
        )),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: "40".repeat(32),
            previous_outpoint_index: "1".into(),
            previous_outpoint_script: None,
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 0,
                amount: 100_000_000,
                script_public_key: format!("aa20{}87", "a3".repeat(32)),
                script_public_key_address: Some("kaspatest:wrapper".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: Some(wrapper_id.clone()),
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 1,
                amount: 100_000_000,
                script_public_key: format!("aa20{}87", "e9".repeat(32)),
                script_public_key_address: Some("kaspatest:wrapped-root".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: Some(wrapper_id.clone()),
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 2,
                amount: 100_000_000,
                script_public_key: format!("20{owner}ac"),
                script_public_key_address: Some("kaspatest:change".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let row = sqlx::query(
        "SELECT encode(covenant_id, 'hex') AS covenant_id, state FROM covenant_utxos WHERE txid = decode($1, 'hex') AND vout = 1",
    )
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    let state: serde_json::Value = row.get("state");

    assert_eq!(row.get::<String, _>("covenant_id"), wrapper_id);
    assert_eq!(state["canonicalTokenId"], token_id);
    assert_eq!(state["ownerIdentifier"], owner);
    assert_eq!(state["amount"], "0");
    assert_eq!(state["mode"], 1);
    assert_eq!(state["modeName"], "root");
}

async fn insert_action(
    pool: &PgPool,
    covenant_id: &[u8],
    txid_seed: u8,
    block_hash: &[u8],
    block_time_ms: i64,
    action: &str,
    entrypoint: Option<&str>,
) {
    let txid = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, NULL)"#,
    )
    .bind(covenant_id)
    .bind(&txid)
    .bind(block_hash)
    .bind(block_time_ms)
    .bind(action)
    .bind(entrypoint)
    .bind(json!({"placeholder": true}))
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_action_with_inputs(
    pool: &PgPool,
    covenant_id: &[u8],
    txid_seed: u8,
    block_hash: &[u8],
    block_time_ms: i64,
    action: &str,
    inputs: serde_json::Value,
) {
    let txid = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, $4, $5, NULL, $6, NULL, NULL)"#,
    )
    .bind(covenant_id)
    .bind(&txid)
    .bind(block_hash)
    .bind(block_time_ms)
    .bind(action)
    .bind(inputs)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_action_with_outputs_and_args(
    pool: &PgPool,
    covenant_id: &[u8],
    txid_seed: u8,
    block_hash: &[u8],
    block_time_ms: i64,
    action: &str,
    entrypoint: Option<&str>,
    outputs: Option<serde_json::Value>,
    decoded_args: Option<serde_json::Value>,
) {
    let txid = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8)"#,
    )
    .bind(covenant_id)
    .bind(&txid)
    .bind(block_hash)
    .bind(block_time_ms)
    .bind(action)
    .bind(entrypoint)
    .bind(outputs)
    .bind(decoded_args)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_v3_trade_action(
    pool: &PgPool,
    covenant_id: &[u8],
    txid_seed: u8,
    block_hash: &[u8],
    block_time_ms: i64,
    entrypoint: &str,
    fill_amount: &str,
    unit_price_sompi: &str,
    owner_seed: u8,
) {
    let owner = hex::encode(vec![owner_seed; 32]);
    insert_action_with_outputs_and_args(
        pool,
        covenant_id,
        txid_seed,
        block_hash,
        block_time_ms,
        "spend",
        Some(entrypoint),
        None,
        Some(json!({
            "buyerOutputIndex": "0",
            "fillAmount": fill_amount,
            "ownerIdentifier": owner,
            "identifierType": "0",
            "unitPriceSompi": unit_price_sompi
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        pool,
        covenant_id,
        txid_seed,
        block_hash,
        block_time_ms,
        "continuation",
        None,
        Some(json!({
            "vout": "0",
            "state": {
                "ownerIdentifier": owner,
                "identifierType": "0",
                "amount": fill_amount,
                "mode": "0",
                "modeName": "holder"
            }
        })),
        None,
    )
    .await;
}

async fn insert_action_full(
    pool: &PgPool,
    covenant_id: &[u8],
    txid_seed: u8,
    block_hash: &[u8],
    block_time_ms: i64,
    action: &str,
    entrypoint: Option<&str>,
    inputs: Option<serde_json::Value>,
    outputs: Option<serde_json::Value>,
    decoded_args: Option<serde_json::Value>,
) {
    let txid = vec![txid_seed; 32];
    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(covenant_id)
    .bind(&txid)
    .bind(block_hash)
    .bind(block_time_ms)
    .bind(action)
    .bind(entrypoint)
    .bind(inputs)
    .bind(outputs)
    .bind(decoded_args)
    .execute(pool)
    .await
    .unwrap();
}

async fn mark_utxo_spent(pool: &PgPool, txid_seed: u8, spent_block: &[u8], spent_by_seed: u8) {
    sqlx::query(
        r#"UPDATE covenant_utxos
           SET status = 'spent', spent_block = $1, spent_by_txid = $2
           WHERE txid = $3 AND vout = 0"#,
    )
    .bind(spent_block)
    .bind(vec![spent_by_seed; 32])
    .bind(vec![txid_seed; 32])
    .execute(pool)
    .await
    .unwrap();
}

fn kcc20_v3_script(owner: [u8; 32], amount: i64, mode: i64, unit_price: i64) -> Vec<u8> {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-v3/KCC20V3.placeholder.json"
    ))
    .unwrap();
    let mut script: Vec<u8> = artifact["bytecode"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    script[2..34].copy_from_slice(&owner);
    script[35..43].copy_from_slice(&amount.to_le_bytes());
    script[44..52].copy_from_slice(&mode.to_le_bytes());
    script[53..61].copy_from_slice(&unit_price.to_le_bytes());
    script
}

fn kcc20_orderbook_script(
    canonical_token_id: &[u8],
    owner: [u8; 32],
    amount: i64,
    mode: i64,
    unit_price: i64,
) -> Vec<u8> {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-orderbook/KCC20Orderbook.placeholder.json"
    ))
    .unwrap();
    let mut script: Vec<u8> = artifact["bytecode"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();
    script[2..34].copy_from_slice(canonical_token_id);
    script[35..67].copy_from_slice(&owner);
    script[68] = 0;
    script[70..78].copy_from_slice(&amount.to_le_bytes());
    script[79..87].copy_from_slice(&mode.to_le_bytes());
    script[88..96].copy_from_slice(&unit_price.to_le_bytes());
    script[130..138].copy_from_slice(&100_000_000_i64.to_le_bytes());
    script
}

fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0..=75 => script.push(data.len() as u8),
        76..=255 => {
            script.push(0x4c);
            script.push(data.len() as u8);
        }
        256..=65535 => {
            script.push(0x4d);
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        _ => panic!("push too large"),
    }
    script.extend_from_slice(data);
}

fn push_i64(script: &mut Vec<u8>, value: i64) {
    match value {
        0 => script.push(0x00),
        -1 => script.push(0x4f),
        1..=16 => script.push(0x50 + value as u8),
        _ => {
            let mut bytes = value.to_le_bytes().to_vec();
            if value > 0 {
                while bytes.len() > 1 && bytes.last() == Some(&0) {
                    bytes.pop();
                }
                if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
                    bytes.push(0);
                }
            } else {
                while bytes.len() > 1
                    && bytes.last() == Some(&0xff)
                    && bytes[bytes.len() - 2] & 0x80 != 0
                {
                    bytes.pop();
                }
            }
            push_data(script, &bytes);
        }
    }
}

fn v3_partial_ask_fill_tx(owner: [u8; 32], buyer: [u8; 32]) -> RestTransaction {
    let reveal = kcc20_v3_script(owner, 150, 2, 1_000_000);
    let mut signature_script = Vec::new();
    push_data(&mut signature_script, &buyer);
    push_i64(&mut signature_script, 25);
    push_i64(&mut signature_script, 0);
    push_i64(&mut signature_script, 1);
    push_i64(&mut signature_script, 2);
    push_i64(&mut signature_script, 3);
    push_data(&mut signature_script, &reveal);

    let txid = "cc".repeat(32);
    RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400200,
        is_accepted: true,
        accepting_block_hash: Some("55".repeat(32)),
        accepting_block_blue_score: Some(200),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: "aa".repeat(32),
            previous_outpoint_index: "0".into(),
            signature_script: hex::encode(signature_script),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 0,
                amount: 200_000_000,
                script_public_key: format!("aa20{}87", "11".repeat(32)),
                script_public_key_address: Some("kaspatest:holder".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 1,
                amount: 200_000_000,
                script_public_key: format!("aa20{}87", "22".repeat(32)),
                script_public_key_address: Some("kaspatest:ask-continuation".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid,
                index: 2,
                amount: 25_000_000,
                script_public_key: format!("20{}ac", hex::encode(owner)),
                script_public_key_address: Some("kaspatest:seller".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    }
}

fn orderbook_sweep_ask_fill_tx(token: &[u8], owner: [u8; 32], buyer: [u8; 32]) -> RestTransaction {
    let full_reveal = kcc20_orderbook_script(token, owner, 100_000_000, 2, 1_000_000);
    let mut full_sig = Vec::new();
    push_data(&mut full_sig, &buyer);
    push_i64(&mut full_sig, 100_000_000);
    push_i64(&mut full_sig, 0);
    push_i64(&mut full_sig, 2);
    push_i64(&mut full_sig, 1);
    push_data(&mut full_sig, &[0xcb, 0x10, 0x63, 0xeb]);
    push_data(&mut full_sig, &full_reveal);

    let partial_reveal = kcc20_orderbook_script(token, owner, 150_000_000, 2, 2_000_000);
    let mut partial_sig = Vec::new();
    push_data(&mut partial_sig, &buyer);
    push_i64(&mut partial_sig, 25_000_000);
    push_i64(&mut partial_sig, 3);
    push_i64(&mut partial_sig, 4);
    push_i64(&mut partial_sig, 5);
    push_data(&mut partial_sig, &[0xcb, 0x10, 0x63, 0xeb]);
    push_data(&mut partial_sig, &partial_reveal);

    let txid = "dd".repeat(32);
    RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400300,
        is_accepted: true,
        accepting_block_hash: Some("56".repeat(32)),
        accepting_block_blue_score: Some(201),
        inputs: vec![
            RestTxInput {
                previous_outpoint_hash: "aa".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: hex::encode(full_sig),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash: "bb".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: hex::encode(partial_sig),
                ..Default::default()
            },
        ],
        outputs: vec![
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 0,
                amount: 50_000_000,
                script_public_key: format!("aa20{}87", "31".repeat(32)),
                script_public_key_address: Some("kaspatest:holder-one".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 1,
                amount: 100_000_000,
                script_public_key: format!("20{}ac", hex::encode(owner)),
                script_public_key_address: Some("kaspatest:seller-one".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 2,
                amount: 2_000_000,
                script_public_key: format!("20{}ac", "ce".repeat(32)),
                script_public_key_address: Some("kaspatest:fee-one".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 3,
                amount: 50_000_000,
                script_public_key: format!("aa20{}87", "32".repeat(32)),
                script_public_key_address: Some("kaspatest:holder-two".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 4,
                amount: 50_000_000,
                script_public_key: format!("aa20{}87", "33".repeat(32)),
                script_public_key_address: Some("kaspatest:ask-continuation-two".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.clone(),
                index: 5,
                amount: 50_000_000,
                script_public_key: format!("20{}ac", hex::encode(owner)),
                script_public_key_address: Some("kaspatest:seller-two".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid,
                index: 6,
                amount: 50_000_000,
                script_public_key: format!("20{}ac", "ce".repeat(32)),
                script_public_key_address: Some("kaspatest:fee-two".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    }
}

#[derive(Clone, Copy)]
struct WrappedSweepAskFillSpec {
    previous_txid_seed: u8,
    available_amount: i64,
    fill_amount: i64,
    unit_price_sompi: i64,
}

fn repeated_seed_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn orderbook_sweep_ask_fill_tx_from_specs(
    token: &[u8],
    owner: [u8; 32],
    buyer: [u8; 32],
    txid_seed: u8,
    specs: &[WrappedSweepAskFillSpec],
) -> RestTransaction {
    let txid = repeated_seed_hex(txid_seed);
    let mut inputs = Vec::with_capacity(specs.len());
    let mut outputs = Vec::new();

    for (fill_index, spec) in specs.iter().enumerate() {
        let reveal = kcc20_orderbook_script(
            token,
            owner,
            spec.available_amount,
            2,
            spec.unit_price_sompi,
        );
        let buyer_output_index = outputs.len() as i64;
        let remaining_amount = spec.available_amount - spec.fill_amount;
        let ask_output_index = if remaining_amount > 0 {
            buyer_output_index + 1
        } else {
            -1
        };
        let seller_output_index = if remaining_amount > 0 {
            buyer_output_index + 2
        } else {
            buyer_output_index + 1
        };

        let mut signature_script = Vec::new();
        push_data(&mut signature_script, &buyer);
        push_i64(&mut signature_script, spec.fill_amount);
        push_i64(&mut signature_script, buyer_output_index);
        push_i64(&mut signature_script, ask_output_index);
        push_i64(&mut signature_script, seller_output_index);
        push_data(&mut signature_script, &[0xcb, 0x10, 0x63, 0xeb]);
        push_data(&mut signature_script, &reveal);

        inputs.push(RestTxInput {
            previous_outpoint_hash: repeated_seed_hex(spec.previous_txid_seed),
            previous_outpoint_index: "0".into(),
            signature_script: hex::encode(signature_script),
            ..Default::default()
        });

        outputs.push(RestTxOutput {
            transaction_id: txid.clone(),
            index: buyer_output_index as u64,
            amount: 50_000_000,
            script_public_key: format!("aa20{}87", repeated_seed_hex(0x40 + fill_index as u8)),
            script_public_key_address: Some(format!("kaspatest:sweep-holder-{fill_index}")),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        });

        if remaining_amount > 0 {
            outputs.push(RestTxOutput {
                transaction_id: txid.clone(),
                index: ask_output_index as u64,
                amount: 50_000_000,
                script_public_key: format!("aa20{}87", repeated_seed_hex(0x60 + fill_index as u8)),
                script_public_key_address: Some(format!(
                    "kaspatest:sweep-ask-continuation-{fill_index}"
                )),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            });
        }

        outputs.push(RestTxOutput {
            transaction_id: txid.clone(),
            index: seller_output_index as u64,
            amount: 50_000_000,
            script_public_key: format!("20{}ac", hex::encode(owner)),
            script_public_key_address: Some(format!("kaspatest:sweep-seller-{fill_index}")),
            script_public_key_type: Some("pubkey".into()),
            covenant_id: None,
            covenant: None,
        });

        outputs.push(RestTxOutput {
            transaction_id: txid.clone(),
            index: seller_output_index as u64 + 1,
            amount: 50_000_000,
            script_public_key: format!("20{}ac", repeated_seed_hex(0xce)),
            script_public_key_address: Some(format!("kaspatest:sweep-fee-{fill_index}")),
            script_public_key_type: Some("pubkey".into()),
            covenant_id: None,
            covenant: None,
        });
    }

    RestTransaction {
        transaction_id: txid,
        block_time: 1_778_654_400_400 + u64::from(txid_seed),
        is_accepted: true,
        accepting_block_hash: Some(repeated_seed_hex(0x57)),
        accepting_block_blue_score: Some(202 + u64::from(txid_seed)),
        inputs,
        outputs,
        ..Default::default()
    }
}

// ---------- repo::list_covenant_summaries ---------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_empty(pool: PgPool) {
    let rows = repo::list_covenant_summaries(&pool, None, false, None, None, None, None)
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_aggregates_active_utxos(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(
        &pool,
        2,
        "kaspatest:pone",
        Some("TimeLockVault"),
        &block,
        100,
    )
    .await;
    insert_active_utxo(&pool, &cov, "kaspatest:pone", 100_000_000, &block, 0xa1).await;
    insert_active_utxo(&pool, &cov, "kaspatest:pone", 50_000_000, &block, 0xa2).await;

    let rows = repo::list_covenant_summaries(&pool, None, false, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(r.template.as_deref(), Some("TimeLockVault"));
    assert_eq!(r.address, "kaspatest:pone");
    assert_eq!(r.active_utxos, 2);
    assert_eq!(r.total_amount_sompi, 150_000_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_marks_canonical_identity_source(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let canonical_id = vec![0x22u8; 32];
    let script_hash = vec![0x11u8; 32];
    let txid = vec![0x33u8; 32];
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
            classification_kind, classification_status)
           VALUES ($1, 'kaspatest:pcanonical', 0, $2, 'TimeLockVault',
                   $3, 0, $4, 1778654400100, NULL, 'covenant', 'matched')"#,
    )
    .bind(&canonical_id)
    .bind(&script_hash)
    .bind(&txid)
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::list_covenant_summaries(&pool, None, false, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].covenant_id_hex, "22".repeat(32));
    assert_eq!(rows[0].script_hash_hex, "11".repeat(32));
    assert!(rows[0].canonical_covenant_id_known);
    assert_eq!(rows[0].identity_source, "canonical");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_marks_script_hash_fallback_identity_source(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    insert_covenant(
        &pool,
        2,
        "kaspatest:pfallback",
        Some("TimeLockVault"),
        &block,
        100,
    )
    .await;

    let rows = repo::list_covenant_summaries(&pool, None, false, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].covenant_id_hex, rows[0].script_hash_hex);
    assert!(!rows[0].canonical_covenant_id_known);
    assert_eq!(rows[0].identity_source, "scriptHashFallback");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_orders_newest_first(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let _older = insert_covenant(&pool, 2, "kaspatest:pold", None, &block, 100).await;
    let _newer = insert_covenant(&pool, 3, "kaspatest:pnew", None, &block, 500).await;

    let rows = repo::list_covenant_summaries(&pool, None, false, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].address, "kaspatest:pnew");
    assert_eq!(rows[1].address, "kaspatest:pold");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_template_filter_matches_claimed_or_verified(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    // One verified MultiSigVault (template_name set).
    let _verified = insert_covenant(
        &pool,
        1,
        "kaspatest:pver",
        Some("MultiSigVault"),
        &block,
        100,
    )
    .await;
    // One claimed-only MultiSigVault (template_name NULL, claimed_template set).
    let claimed = insert_covenant(&pool, 2, "kaspatest:pclm", None, &block, 200).await;
    sqlx::query(
        "UPDATE covenants SET claimed_template = $1, claimed_args = $2, claim_source = 'payload' WHERE covenant_id = $3",
    )
    .bind("MultiSigVault")
    .bind(json!({"tmpl": "MultiSigVault", "args": []}))
    .bind(&claimed)
    .execute(&pool)
    .await
    .unwrap();
    // One unrelated covenant that shouldn't match the filter.
    let _other = insert_covenant(&pool, 3, "kaspatest:poth", Some("Escrow"), &block, 300).await;

    // Default: matches claimed OR verified, both should appear.
    let mixed =
        repo::list_covenant_summaries(&pool, Some("MultiSigVault"), false, None, None, None, None)
            .await
            .unwrap();
    assert_eq!(mixed.len(), 2);
    let addrs: Vec<&str> = mixed.iter().map(|r| r.address.as_str()).collect();
    assert!(addrs.contains(&"kaspatest:pver"));
    assert!(addrs.contains(&"kaspatest:pclm"));

    // verified_only: only the verified row.
    let strict =
        repo::list_covenant_summaries(&pool, Some("MultiSigVault"), true, None, None, None, None)
            .await
            .unwrap();
    assert_eq!(strict.len(), 1);
    assert_eq!(strict[0].address, "kaspatest:pver");

    // No filter: all three rows.
    let all = repo::list_covenant_summaries(&pool, None, false, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(all.len(), 3);

    // verified_only without a template should still hide claim-only rows.
    let verified_all = repo::list_covenant_summaries(&pool, None, true, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(verified_all.len(), 2);
    let verified_addrs: Vec<&str> = verified_all.iter().map(|r| r.address.as_str()).collect();
    assert!(verified_addrs.contains(&"kaspatest:pver"));
    assert!(verified_addrs.contains(&"kaspatest:poth"));
    assert!(!verified_addrs.contains(&"kaspatest:pclm"));
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_filters_by_claimed_arg(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let alice = insert_covenant(&pool, 2, "kaspatest:palice", None, &block, 100).await;
    let bob = insert_covenant(&pool, 3, "kaspatest:pbob", None, &block, 200).await;

    sqlx::query(
        "UPDATE covenants SET claimed_template = $1, claimed_args = $2, claim_source = 'payload' WHERE covenant_id = $3",
    )
    .bind("Escrow")
    .bind(json!({
        "tmpl": "Escrow",
        "args": [
            {"name": "buyer", "type": "address", "value": "kaspatest:qalice"},
            {"name": "amountSompi", "type": "u64", "value": "100000000"}
        ]
    }))
    .bind(&alice)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE covenants SET claimed_template = $1, claimed_args = $2, claim_source = 'payload' WHERE covenant_id = $3",
    )
    .bind("Escrow")
    .bind(json!({
        "tmpl": "Escrow",
        "args": [{"name": "buyer", "type": "address", "value": "kaspatest:qbob"}]
    }))
    .bind(&bob)
    .execute(&pool)
    .await
    .unwrap();

    let any_buyer = repo::list_covenant_summaries(
        &pool,
        Some("Escrow"),
        false,
        None,
        None,
        Some("buyer"),
        None,
    )
    .await
    .unwrap();
    assert_eq!(any_buyer.len(), 2);

    let alice_only = repo::list_covenant_summaries(
        &pool,
        Some("Escrow"),
        false,
        None,
        None,
        Some("buyer"),
        Some("kaspatest:qalice"),
    )
    .await
    .unwrap();
    assert_eq!(alice_only.len(), 1);
    assert_eq!(alice_only[0].address, "kaspatest:palice");
}

#[sqlx::test(migrations = "./migrations")]
async fn list_summaries_filters_by_classification(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let inscription =
        insert_covenant(&pool, 2, "kaspatest:pins", Some("KRC-20-mint"), &block, 100).await;
    let unknown = insert_covenant(&pool, 3, "kaspatest:punk", None, &block, 200).await;

    sqlx::query(
        "UPDATE covenants SET classification_kind = 'inscription', classification_status = 'matched' WHERE covenant_id = $1",
    )
    .bind(&inscription)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE covenants SET classification_kind = 'unknown', classification_status = 'unmatched' WHERE covenant_id = $1",
    )
    .bind(&unknown)
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::list_covenant_summaries(
        &pool,
        None,
        false,
        Some("inscription"),
        Some("matched"),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].classification_kind, "inscription");
    assert_eq!(rows[0].classification_status, "matched");
    assert_eq!(rows[0].template.as_deref(), Some("KRC-20-mint"));
    assert_eq!(rows[0].inscription_protocol.as_deref(), Some("KRC-20"));
}

// ---------- repo::covenant_by_script_hash --------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn covenant_by_script_hash_roundtrip(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 0x42, "kaspatest:pq", Some("Escrow"), &block, 100).await;
    let hex = hex::encode(&cov);

    let row = repo::covenant_by_script_hash(&pool, &hex)
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(row.template.as_deref(), Some("Escrow"));
    assert_eq!(row.address, "kaspatest:pq");
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_summaries_use_latest_active_continuation_address(pool: PgPool) {
    let old_block = insert_block(&pool, 1, 100).await;
    let new_block = insert_block(&pool, 2, 101).await;
    let cov = insert_covenant(
        &pool,
        0x44,
        "kaspatest:pgenesis",
        Some("DeadManSwitch"),
        &old_block,
        100,
    )
    .await;

    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:pcurrent",
        700_000_000,
        &new_block,
        0xc1,
    )
    .await;

    let hex = hex::encode(&cov);
    let detail = repo::covenant_by_script_hash(&pool, &hex)
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(detail.address, "kaspatest:pcurrent");

    let (rows, total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&hex),
        None,
        None,
        None,
        Some(20),
        Some(0),
    )
    .await
    .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].address, "kaspatest:pcurrent");

    let by_address = repo::covenants_by_address(&pool, "kaspatest:pcurrent")
        .await
        .unwrap();
    assert_eq!(by_address.len(), 1);
    assert_eq!(by_address[0].covenant_id_hex, hex);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_summaries_track_spend_and_reactivation(pool: PgPool) {
    let genesis_block = insert_block(&pool, 1, 100).await;
    let continuation_block = insert_block(&pool, 2, 101).await;
    let spent_block = insert_block(&pool, 3, 102).await;
    let cov = insert_covenant(
        &pool,
        0x45,
        "kaspatest:pgenesis",
        Some("DeadManSwitch"),
        &genesis_block,
        100,
    )
    .await;
    let hex = hex::encode(&cov);

    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:polder",
        500_000_000,
        &genesis_block,
        0xd1,
    )
    .await;
    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:pnewer",
        700_000_000,
        &continuation_block,
        0xd2,
    )
    .await;

    let summary = repo::covenant_by_script_hash(&pool, &hex)
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(summary.address, "kaspatest:pnewer");
    assert_eq!(summary.active_utxos, 2);
    assert_eq!(summary.total_amount_sompi, 1_200_000_000);

    mark_utxo_spent(&pool, 0xd2, &spent_block, 0xe2).await;
    let summary = repo::covenant_by_script_hash(&pool, &hex)
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(summary.address, "kaspatest:polder");
    assert_eq!(summary.active_utxos, 1);
    assert_eq!(summary.total_amount_sompi, 500_000_000);

    mark_utxo_spent(&pool, 0xd1, &spent_block, 0xe1).await;
    let summary = repo::covenant_by_script_hash(&pool, &hex)
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(summary.address, "kaspatest:pgenesis");
    assert_eq!(summary.active_utxos, 0);
    assert_eq!(summary.total_amount_sompi, 0);

    sqlx::query(
        r#"UPDATE covenant_utxos
           SET status = 'active', spent_block = NULL, spent_by_txid = NULL
           WHERE txid = $1 AND vout = 0"#,
    )
    .bind(vec![0xd2u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let summary = repo::covenant_by_script_hash(&pool, &hex)
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(summary.address, "kaspatest:pnewer");
    assert_eq!(summary.active_utxos, 1);
    assert_eq!(summary.total_amount_sompi, 700_000_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_summary_ignores_state_only_utxo_updates(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(
        &pool,
        0x46,
        "kaspatest:pgenesis",
        Some("DeadManSwitch"),
        &block,
        100,
    )
    .await;
    insert_active_utxo(&pool, &cov, "kaspatest:pcurrent", 500_000_000, &block, 0xd3).await;

    let before: i64 = sqlx::query_scalar(
        "SELECT xmin::TEXT::BIGINT FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query("UPDATE covenant_utxos SET state = $1 WHERE txid = $2 AND vout = 0")
        .bind(serde_json::json!({ "ownerIdentifier": "11".repeat(32) }))
        .bind(vec![0xd3u8; 32])
        .execute(&pool)
        .await
        .unwrap();

    let after: i64 = sqlx::query_scalar(
        "SELECT xmin::TEXT::BIGINT FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after, before);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_summary_refresh_bounds_latest_lookup_and_preserves_reorg_fallback(pool: PgPool) {
    let genesis = insert_block(&pool, 1, 1).await;
    let cov = insert_covenant(&pool, 0x47, "kaspatest:genesis", None, &genesis, 1).await;
    sqlx::query(
        "INSERT INTO covenant_utxos \
         (txid, vout, covenant_id, address, amount_sompi, script_pubkey, created_block, status) \
         SELECT decode(lpad(to_hex(10000 + n), 64, '0'), 'hex'), 0, $1, \
                'kaspatest:old', 1, decode('51','hex'), $2, 'active' \
         FROM generate_series(1, 2000) n",
    )
    .bind(&cov)
    .bind(&genesis)
    .execute(&pool)
    .await
    .unwrap();
    // More than 64 blocks share the newest score. All ties must remain eligible.
    let mut tied_blocks = Vec::new();
    for tag in 0x80_u8..0xd0 {
        tied_blocks.push(insert_block(&pool, tag, 1000).await);
    }
    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:tie-first",
        10,
        &tied_blocks[0],
        0xfd,
    )
    .await;
    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:tie-last",
        20,
        &tied_blocks[79],
        0xfe,
    )
    .await;
    sqlx::query("SELECT refresh_covenant_summary($1)")
        .bind(&cov)
        .execute(&pool)
        .await
        .unwrap();
    let summary: (i64, i64, String, Vec<u8>) = sqlx::query_as(
        "SELECT active_utxos, total_amount_sompi, current_address, latest_active_txid \
         FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        summary,
        (2002, 2030, "kaspatest:tie-last".into(), vec![0xfe; 32])
    );

    // Explain the SELECT from the installed production function. The SQL is
    // trusted migration code from this isolated test DB; the covenant stays bound.
    let function: String = sqlx::query_scalar(
        "SELECT prosrc FROM pg_proc WHERE oid = 'refresh_covenant_summary(bytea)'::regprocedure",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let select = function
        .split_once("    INSERT INTO covenant_summaries (")
        .unwrap()
        .1
        .split_once("    )\n")
        .unwrap()
        .1
        .split_once("    ON CONFLICT")
        .unwrap()
        .0
        .replace("target_covenant_id", "$1");
    let explain = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {select}");
    let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(explain))
        .bind(&cov)
        .fetch_one(&pool)
        .await
        .unwrap();

    let writer = PgPersister::new(pool.clone());
    writer.revert_block(&tied_blocks[79]).await.unwrap();
    let after_tie: (i64, i64, String) = sqlx::query_as(
        "SELECT active_utxos, total_amount_sompi, current_address \
         FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_tie, (2001, 2010, "kaspatest:tie-first".into()));
    writer.revert_block(&tied_blocks[0]).await.unwrap();
    // The remaining active output is older than the entire recent-block window.
    let fallback: (i64, i64, String, Vec<u8>) = sqlx::query_as(
        "SELECT active_utxos, total_amount_sompi, current_address, latest_active_txid \
         FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        fallback,
        (
            2000,
            2000,
            "kaspatest:old".into(),
            hex::decode(format!("{:064x}", 12000)).unwrap()
        )
    );
    sqlx::query("DELETE FROM covenant_utxos WHERE covenant_id = $1")
        .bind(&cov)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("SELECT refresh_covenant_summary($1)")
        .bind(&cov)
        .execute(&pool)
        .await
        .unwrap();
    let empty: (i64, i64, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT active_utxos, total_amount_sompi, current_address, latest_active_txid \
         FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(empty, (0, 0, "kaspatest:genesis".into(), None));

    fn cte_execution(node: &serde_json::Value, name: &str, found: &mut Vec<(u64, u64)>) {
        if node["Subplan Name"].as_str() == Some(name) {
            found.push((
                node["Actual Loops"].as_u64().unwrap(),
                node["Actual Rows"].as_u64().unwrap(),
            ));
        }
        for child in node["Plans"].as_array().into_iter().flatten() {
            cte_execution(child, name, found);
        }
    }
    let mut recent_blocks = Vec::new();
    let mut recent_active = Vec::new();
    cte_execution(&plan[0]["Plan"], "CTE recent_blocks", &mut recent_blocks);
    cte_execution(&plan[0]["Plan"], "CTE recent_active", &mut recent_active);
    assert_eq!(
        recent_blocks,
        vec![(1, 80)],
        "latest lookup must bound blocks while preserving score ties"
    );
    assert_eq!(
        recent_active,
        vec![(1, 1)],
        "latest lookup must reuse one recent candidate"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn reorg_summary_counts_surviving_outputs_when_latest_deleted_first(pool: PgPool) {
    let genesis = insert_block(&pool, 1, 1).await;
    let removed = insert_block(&pool, 2, 2).await;
    let cov = insert_covenant(&pool, 0x48, "kaspatest:genesis", None, &genesis, 1).await;
    insert_active_utxo(&pool, &cov, "kaspatest:survivor", 5, &genesis, 0x10).await;
    // Heap order deletes the highest txid before another output in the same block.
    insert_active_utxo(&pool, &cov, "kaspatest:latest", 20, &removed, 0xfe).await;
    insert_active_utxo(&pool, &cov, "kaspatest:other", 10, &removed, 0xfd).await;
    PgPersister::new(pool.clone())
        .revert_block(&removed)
        .await
        .unwrap();
    let actual: (i64, i64, String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT active_utxos, total_amount_sompi, current_address, latest_active_txid \
         FROM covenant_summaries WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        actual,
        (1, 5, "kaspatest:survivor".into(), Some(vec![0x10; 32]))
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn deferred_summary_repair_uses_new_continuation_without_full_refresh(pool: PgPool) {
    let genesis_block = insert_block(&pool, 1, 100).await;
    let current_block = insert_block(&pool, 2, 101).await;
    let next_block = insert_block(&pool, 3, 102).await;
    let cov = insert_covenant(
        &pool,
        0x47,
        "kaspatest:pgenesis",
        Some("DeadManSwitch"),
        &genesis_block,
        100,
    )
    .await;
    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:polder",
        500_000_000,
        &genesis_block,
        0xd4,
    )
    .await;
    insert_active_utxo(
        &pool,
        &cov,
        "kaspatest:pcurrent",
        700_000_000,
        &current_block,
        0xd5,
    )
    .await;

    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION refresh_covenant_summary(target_covenant_id BYTEA)
           RETURNS VOID
           LANGUAGE plpgsql
           AS $$
           BEGIN
               RAISE EXCEPTION 'unexpected full covenant summary refresh';
           END;
           $$"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('tn12.defer_covenant_summary_repair', 'on', TRUE)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        r#"UPDATE covenant_utxos
           SET status = 'spent', spent_block = $1, spent_by_txid = $2
           WHERE txid = $3 AND vout = 0"#,
    )
    .bind(&next_block)
    .bind(vec![0xe5u8; 32])
    .bind(vec![0xd5u8; 32])
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, 'kaspatest:pnext', 900000000, decode('51', 'hex'),
                   NULL, $3, NULL, NULL, 'active')"#,
    )
    .bind(vec![0xd6u8; 32])
    .bind(&cov)
    .bind(&next_block)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("SELECT finalize_deferred_covenant_summary($1)")
        .bind(&cov)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let summary = repo::covenant_by_script_hash(&pool, &hex::encode(&cov))
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(summary.address, "kaspatest:pnext");
    assert_eq!(summary.active_utxos, 2);
    assert_eq!(summary.total_amount_sompi, 1_400_000_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_by_script_hash_missing(pool: PgPool) {
    let missing = "ff".repeat(32);
    let row = repo::covenant_by_script_hash(&pool, &missing)
        .await
        .unwrap();
    assert!(row.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_script_hash_lookup_index_is_valid(pool: PgPool) {
    let index: Option<(bool, String)> = sqlx::query_as(
        "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) \
         FROM pg_index i \
         WHERE i.indexrelid = to_regclass('covenants_script_hash_idx')",
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

    let (is_valid, definition) = index.expect("script hash lookup index should exist");
    assert!(is_valid, "script hash lookup index should be valid");
    assert!(
        definition.contains("USING btree (script_hash)"),
        "unexpected script hash lookup index definition: {definition}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn tip_follower_persister_waits_for_current_writer(pool: PgPool) {
    const PERSIST_WRITER_LOCK_KEY: i64 = 6_074_847_039_450_202_930;
    let mut repair_connection = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PERSIST_WRITER_LOCK_KEY)
        .execute(&mut *repair_connection)
        .await
        .unwrap();

    let txid = "31".repeat(32);
    let tx = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("32".repeat(32)),
        accepting_block_blue_score: Some(100),
        outputs: vec![RestTxOutput {
            transaction_id: txid,
            index: 0,
            amount: 100,
            script_public_key: format!("aa20{}87", "33".repeat(32)),
            script_public_key_address: Some("kaspatest:prealtime".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some("34".repeat(32)),
            covenant: None,
        }],
        ..Default::default()
    };
    let tip_follower = PgPersister::for_tip_follow(pool.clone()).unwrap();
    let persist = tokio::spawn(async move { tip_follower.persist_tx(&tx).await });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !persist.is_finished(),
        "tip follower should wait while another writer owns the lock"
    );
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PERSIST_WRITER_LOCK_KEY)
        .execute(&mut *repair_connection)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), persist)
        .await
        .expect("tip follower should resume after the writer yields")
        .unwrap()
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_persister_remains_fail_fast_when_realtime_writer_is_active(pool: PgPool) {
    const PERSIST_WRITER_LOCK_KEY: i64 = 6_074_847_039_450_202_930;
    let mut realtime_connection = pool.acquire().await.unwrap();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(PERSIST_WRITER_LOCK_KEY)
        .execute(&mut *realtime_connection)
        .await
        .unwrap();

    let tx = RestTransaction {
        transaction_id: "35".repeat(32),
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("36".repeat(32)),
        accepting_block_blue_score: Some(100),
        ..Default::default()
    };
    let error = PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .expect_err("repair writer must yield instead of waiting behind realtime");

    assert!(error.to_string().contains("WriterLockBusy"));
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(PERSIST_WRITER_LOCK_KEY)
        .execute(&mut *realtime_connection)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_prefers_canonical_covenant_id_when_output_exposes_it(pool: PgPool) {
    let script_hash_hex = "11".repeat(32);
    let covenant_id_hex = "22".repeat(32);
    let txid = "33".repeat(32);
    let tx = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("44".repeat(32)),
        accepting_block_blue_score: Some(100),
        outputs: vec![RestTxOutput {
            transaction_id: txid,
            index: 0,
            amount: 100,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:p".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(covenant_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let row: (String, String) = sqlx::query_as(
        "SELECT encode(covenant_id, 'hex'), encode(script_hash, 'hex') FROM covenants",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, covenant_id_hex);
    assert_eq!(row.1, script_hash_hex);

    let summary = repo::covenant_by_script_hash(&pool, &covenant_id_hex)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.covenant_id_hex, covenant_id_hex);
    assert_eq!(summary.script_hash_hex, script_hash_hex);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_rekeys_existing_fallback_utxo_when_canonical_id_arrives(pool: PgPool) {
    let script_hash_hex = "12".repeat(32);
    let fallback_id_hex = script_hash_hex.clone();
    let canonical_id_hex = "34".repeat(32);
    let txid = "56".repeat(32);
    let block_hash = insert_block(&pool, 0x78, 100).await;
    let script_pubkey = format!("aa20{script_hash_hex}87");

    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args)
           VALUES (decode($1, 'hex'), 'kaspatest:pfallback', 0, decode($2, 'hex'), NULL,
                   decode($3, 'hex'), 0, $4, 1778654400000, NULL)"#,
    )
    .bind(&fallback_id_hex)
    .bind(&script_hash_hex)
    .bind(&txid)
    .bind(&block_hash)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES (decode($1, 'hex'), 0, decode($2, 'hex'), 'kaspatest:pfallback',
                   100, decode($3, 'hex'), NULL, $4, NULL, NULL, 'active')"#,
    )
    .bind(&txid)
    .bind(&fallback_id_hex)
    .bind(&script_pubkey)
    .bind(&block_hash)
    .execute(&pool)
    .await
    .unwrap();

    let tx = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654401000,
        version: 1,
        is_accepted: true,
        // Identity enrichment does not move this transaction to another block.
        accepting_block_hash: Some(hex::encode(&block_hash)),
        accepting_block_blue_score: Some(100),
        accepting_block_time: Some(1778654400100),
        outputs: vec![RestTxOutput {
            transaction_id: txid.clone(),
            index: 0,
            amount: 100,
            script_public_key: script_pubkey,
            script_public_key_address: Some("kaspatest:pcanonical".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(canonical_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let row: (String, String) = sqlx::query_as(
        r#"SELECT encode(u.covenant_id, 'hex'), encode(c.script_hash, 'hex')
           FROM covenant_utxos u
           JOIN covenants c ON c.covenant_id = u.covenant_id
           WHERE u.txid = decode($1, 'hex') AND u.vout = 0"#,
    )
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, canonical_id_hex);
    assert_eq!(row.1, script_hash_hex);

    let fallback_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM covenants WHERE covenant_id = decode($1, 'hex'))",
    )
    .bind(&fallback_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!fallback_exists);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "old KCC20V2 artifact is not registered after the standard-native cutover"]
async fn persist_tx_projects_kcc20_v2_public_mint_output_states(pool: PgPool) {
    let reveal_script = kcc20_v2_placeholder_script();
    let token_id_hex = "aa".repeat(32);
    let deploy_txid = "ab".repeat(32);
    let mint_txid = "ac".repeat(32);
    let second_mint_txid = "b3".repeat(32);
    let pause_txid = "b5".repeat(32);
    let deploy_script_hash_hex = "ad".repeat(32);
    let holder_script_hash_hex = "ae".repeat(32);
    let minter_script_hash_hex = "af".repeat(32);
    let second_holder_script_hash_hex = "c1".repeat(32);
    let second_minter_script_hash_hex = "c2".repeat(32);
    let recipient_owner = [0x42_u8; 32];
    let second_recipient_owner = [0x43_u8; 32];
    let claim_blob = json!({
        "tmpl": "KCC20V2",
        "args": [
            {"name": "stateOwner", "type": "byte[32]", "value": "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"},
            {"name": "stateOwnerType", "type": "u64", "value": "0"},
            {"name": "maxSupply", "type": "u64", "value": "1000000"},
            {"name": "premintSupply", "type": "u64", "value": "0"},
            {"name": "mintMode", "type": "u64", "value": "2"},
            {"name": "mintPricePerTokenSompi", "type": "u64", "value": "100000000"},
            {"name": "treasuryRecipient", "type": "byte[32]", "value": "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"},
            {"name": "protocolFeeRecipient", "type": "byte[32]", "value": "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01"},
            {"name": "protocolFeeBps", "type": "u64", "value": "200"},
            {"name": "ticker", "type": "string", "value": "KCOM"},
            {"name": "tokenName", "type": "string", "value": "KaspaCom Utility"}
        ]
    });

    let deploy = RestTransaction {
        transaction_id: deploy_txid.clone(),
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("b0".repeat(32)),
        accepting_block_blue_score: Some(100),
        outputs: vec![RestTxOutput {
            transaction_id: deploy_txid.clone(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{deploy_script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:deploy".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(token_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };
    let mint = RestTransaction {
        transaction_id: mint_txid.clone(),
        block_time: 1778654401000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("b1".repeat(32)),
        accepting_block_blue_score: Some(101),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: deploy_txid.clone(),
            previous_outpoint_index: "0".into(),
            signature_script: kcc20_v2_public_mint_signature_script(
                recipient_owner,
                100,
                0,
                1,
                &reveal_script,
            ),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: mint_txid.clone(),
                index: 0,
                amount: 50_000_000,
                script_public_key: format!("aa20{holder_script_hash_hex}87"),
                script_public_key_address: Some("kaspatest:holder".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: mint_txid.clone(),
                index: 1,
                amount: 40_000_000,
                script_public_key: format!("aa20{minter_script_hash_hex}87"),
                script_public_key_address: Some("kaspatest:minter".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    };

    let persister = PgPersister::new(pool.clone());
    persister.persist_tx(&deploy).await.unwrap();
    sqlx::query(
        "UPDATE covenants SET claimed_template = 'KCC20V2', claimed_args = $1 WHERE covenant_id = decode($2, 'hex')",
    )
    .bind(&claim_blob)
    .bind(&token_id_hex)
    .execute(&pool)
    .await
    .unwrap();
    persister.persist_tx(&mint).await.unwrap();

    let output_states: Vec<(i32, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT vout, state
        FROM covenant_utxos
        WHERE txid = decode($1, 'hex')
        ORDER BY vout
        "#,
    )
    .bind(&mint_txid)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(output_states.len(), 2);
    assert_eq!(output_states[0].0, 0);
    assert_eq!(
        output_states[0].1["ownerIdentifier"],
        hex::encode(recipient_owner)
    );
    assert_eq!(output_states[0].1["amount"], "100");
    assert_eq!(output_states[0].1["isMinter"], false);
    assert_eq!(output_states[0].1["minterMode"], 0);
    assert_eq!(output_states[0].1["mintPriceSompi"], "100000000");
    assert_eq!(
        output_states[0].1["treasury"],
        "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5"
    );
    assert_eq!(
        output_states[0].1["feeRecipient"],
        "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01"
    );
    assert_eq!(output_states[0].1["feeBps"], 200);
    assert_eq!(output_states[0].1["ticker"], "KCOM");
    assert_eq!(output_states[0].1["tokenName"], "KaspaCom Utility");
    assert_eq!(output_states[1].0, 1);
    assert_eq!(output_states[1].1["amount"], "999900");
    assert_eq!(output_states[1].1["isMinter"], true);
    assert_eq!(output_states[1].1["minterMode"], 2);
    assert_eq!(output_states[1].1["mintPricePerTokenSompi"], "100000000");
    assert_eq!(output_states[1].1["protocolFeeBps"], 200);
    assert_eq!(output_states[1].1["ticker"], "KCOM");

    let balances = repo::kcc20_balances_for_owner(&pool, &hex::encode(recipient_owner))
        .await
        .unwrap();
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].token_id_hex, token_id_hex);
    assert_eq!(balances[0].amount, "100");
    assert!(!balances[0].is_minter);

    let holders = repo::kcc20_holders(&pool, &token_id_hex, 200, 0)
        .await
        .unwrap();
    assert_eq!(holders.len(), 1);
    assert!(!holders[0].is_minter);
    let remaining_supply: String = sqlx::query_scalar(
        "SELECT amount_total::TEXT FROM kcc20_holders WHERE covenant_id = decode($1, 'hex') AND is_minter = TRUE",
    )
    .bind(&token_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining_supply, "999900");

    repo::refresh_kcc20_token_page_projections(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let projected_activity_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_activity_feed WHERE token_id = decode($1, 'hex')",
    )
    .bind(&token_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(projected_activity_rows > 0);
    let summary = repo::kcc20_token_summary(&pool, &token_id_hex)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.holder_supply, "100");
    assert_eq!(summary.remaining_supply, "999900");
    assert_eq!(summary.active_mint_policy_value, Some(2));
    assert_eq!(summary.public_mint_active, Some(true));
    assert_eq!(summary.holder_count, 1);
    let top_holders = summary.top_holders.as_array().unwrap();
    assert_eq!(top_holders.len(), 1);
    assert_eq!(top_holders[0]["amount"], "100");

    let legacy_block = insert_block(&pool, 0xb2, 102).await;
    let legacy = insert_covenant(
        &pool,
        0x9a,
        "kaspatest:legacy-continuation",
        Some("KCC20V2"),
        &legacy_block,
        102,
    )
    .await;
    sqlx::query(
        "UPDATE covenant_utxos SET covenant_id = $1 WHERE txid = decode($2, 'hex') AND vout = 1",
    )
    .bind(&legacy)
    .bind(&mint_txid)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES ($1, $2, 0, '999900'::NUMERIC, 1, FALSE, 1000)"#,
    )
    .bind(&legacy)
    .bind(vec![0x99_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let second_mint = RestTransaction {
        transaction_id: second_mint_txid.clone(),
        block_time: 1778654402000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("b4".repeat(32)),
        accepting_block_blue_score: Some(103),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: mint_txid.clone(),
            previous_outpoint_index: "1".into(),
            signature_script: kcc20_v2_public_mint_signature_script(
                second_recipient_owner,
                50,
                0,
                1,
                &reveal_script,
            ),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: second_mint_txid.clone(),
                index: 0,
                amount: 50_000_000,
                script_public_key: format!("aa20{second_holder_script_hash_hex}87"),
                script_public_key_address: Some("kaspatest:holder2".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: second_mint_txid.clone(),
                index: 1,
                amount: 40_000_000,
                script_public_key: format!("aa20{second_minter_script_hash_hex}87"),
                script_public_key_address: Some("kaspatest:minter2".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    };
    persister.persist_tx(&second_mint).await.unwrap();

    let spent_minter_covenant: String = sqlx::query_scalar(
        "SELECT encode(covenant_id, 'hex') FROM covenant_utxos WHERE txid = decode($1, 'hex') AND vout = 1",
    )
    .bind(&mint_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(spent_minter_covenant, token_id_hex);

    let second_output_covenants: Vec<String> = sqlx::query_scalar(
        "SELECT encode(covenant_id, 'hex') FROM covenant_utxos WHERE txid = decode($1, 'hex') ORDER BY vout",
    )
    .bind(&second_mint_txid)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        second_output_covenants,
        vec![token_id_hex.clone(), token_id_hex.clone()]
    );

    let second_actions = repo::actions_by_txid(&pool, &second_mint_txid)
        .await
        .unwrap();
    assert!(second_actions.iter().any(|row| {
        row.action == "continuation"
            && row.canonical_token_id_hex.as_deref() == Some(token_id_hex.as_str())
    }));
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let second_activity = repo::kcc20_activity(&pool, &token_id_hex, 10, 0)
        .await
        .unwrap();
    assert!(second_activity.iter().any(|row| {
        row.txid_hex == second_mint_txid
            && row.kind == "mint"
            && row.token_amount.as_deref() == Some("50")
    }));
    assert!(!second_activity.iter().any(|row| {
        row.txid_hex == second_mint_txid
            && row.kind == "mint"
            && row.token_amount.as_deref() == Some("999850")
    }));

    let second_balances =
        repo::kcc20_balances_for_owner(&pool, &hex::encode(second_recipient_owner))
            .await
            .unwrap();
    assert_eq!(second_balances.len(), 1);
    assert_eq!(second_balances[0].token_id_hex, token_id_hex);
    assert_eq!(second_balances[0].amount, "50");
    let stale_legacy_holders: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_holders WHERE covenant_id = $1")
            .bind(&legacy)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stale_legacy_holders, 0);

    let pause = RestTransaction {
        transaction_id: pause_txid.clone(),
        block_time: 1778654403000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("b6".repeat(32)),
        accepting_block_blue_score: Some(104),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: second_mint_txid.clone(),
            previous_outpoint_index: "1".into(),
            signature_script: kcc20_v2_public_mint_availability_signature_script(
                false,
                0,
                &reveal_script,
            ),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: pause_txid.clone(),
            index: 0,
            amount: 40_000_000,
            script_public_key: format!("aa20{}87", "c3".repeat(32)),
            script_public_key_address: Some("kaspatest:paused-minter".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };
    persister.persist_tx(&pause).await.unwrap();

    let paused_state: serde_json::Value = sqlx::query_scalar(
        "SELECT state FROM covenant_utxos WHERE txid = decode($1, 'hex') AND vout = 0",
    )
    .bind(&pause_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(paused_state["minterMode"], 3);
    assert_eq!(paused_state["publicMintActive"], false);

    repo::refresh_kcc20_token_summaries(&pool).await.unwrap();
    let paused_summary = repo::kcc20_token_summary(&pool, &token_id_hex)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paused_summary.active_mint_policy_value, Some(3));
    assert_eq!(paused_summary.public_mint_active, Some(false));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "old KCC20V2 artifact is not registered after the standard-native cutover"]
async fn persist_tx_ignores_kcc20_v2_payload_token_id_for_ambiguous_metadata(pool: PgPool) {
    let reveal_script = kcc20_v2_placeholder_script();
    let block = insert_block(&pool, 0xd0, 100).await;
    let first = insert_covenant(&pool, 0xd1, "kaspatest:first", Some("KCC20V2"), &block, 100).await;
    let second = insert_covenant(
        &pool,
        0xd2,
        "kaspatest:second",
        Some("KCC20V2"),
        &block,
        101,
    )
    .await;
    let legacy = insert_covenant(
        &pool,
        0xd3,
        "kaspatest:legacy-continuation",
        Some("KCC20V2"),
        &block,
        102,
    )
    .await;
    let owner = "d739de4b3b61a894f01988b6cfd0963d43d1b40a787413666122a4f12e0b60d5";
    let claim_blob = json!({
        "tmpl": "KCC20V2",
        "args": [
            {"name": "stateOwner", "type": "byte[32]", "value": owner},
            {"name": "stateOwnerType", "type": "u64", "value": "0"},
            {"name": "maxSupply", "type": "u64", "value": "1000000"},
            {"name": "premintSupply", "type": "u64", "value": "0"},
            {"name": "mintMode", "type": "u64", "value": "2"},
            {"name": "mintPricePerTokenSompi", "type": "u64", "value": "100000000"},
            {"name": "treasuryRecipient", "type": "byte[32]", "value": owner},
            {"name": "protocolFeeRecipient", "type": "byte[32]", "value": "ce2100e68197c8e695bd781d07e2bd5de7ed77f5a97668884190531bdc632c01"},
            {"name": "protocolFeeBps", "type": "u64", "value": "200"},
            {"name": "ticker", "type": "string", "value": "KCOM"},
            {"name": "tokenName", "type": "string", "value": "KaspaCom Utility"}
        ]
    });
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20V2',
               claimed_args = $1,
               template_name = 'KCC20V2',
               classification_status = 'matched'
           WHERE covenant_id IN ($2, $3)"#,
    )
    .bind(&claim_blob)
    .bind(&first)
    .bind(&second)
    .execute(&pool)
    .await
    .unwrap();

    let previous_txid = "d4".repeat(32);
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES (decode($1, 'hex'), 0, $2, 'kaspatest:legacy-minter',
                   50_000_000, decode($3, 'hex'), NULL, $4, NULL, NULL, 'active')"#,
    )
    .bind(&previous_txid)
    .bind(&legacy)
    .bind(format!("aa20{}87", "d5".repeat(32)))
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let recipient_owner = [0x42_u8; 32];
    let mint_txid = "d6".repeat(32);
    let tx = RestTransaction {
        transaction_id: mint_txid.clone(),
        block_time: 1778654401000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("d7".repeat(32)),
        accepting_block_blue_score: Some(101),
        payload: Some(hex::encode(
            json!({
                "tn10": {
                    "v": 1,
                    "tmpl": "KCC20V2",
                    "op": "mintPublic",
                    "args": [
                        {"name": "covenantId", "type": "byte[32]", "value": hex::encode(&first)}
                    ]
                }
            })
            .to_string(),
        )),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: previous_txid.clone(),
            previous_outpoint_index: "0".into(),
            signature_script: kcc20_v2_public_mint_signature_script(
                recipient_owner,
                100,
                0,
                1,
                &reveal_script,
            ),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: mint_txid.clone(),
                index: 0,
                amount: 50_000_000,
                script_public_key: format!("aa20{}87", "d8".repeat(32)),
                script_public_key_address: Some("kaspatest:holder".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: mint_txid.clone(),
                index: 1,
                amount: 40_000_000,
                script_public_key: format!("aa20{}87", "d9".repeat(32)),
                script_public_key_address: Some("kaspatest:minter".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let output_covenants: Vec<String> = sqlx::query_scalar(
        "SELECT encode(covenant_id, 'hex') FROM covenant_utxos WHERE txid = decode($1, 'hex') ORDER BY vout",
    )
    .bind(&mint_txid)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        output_covenants,
        vec![hex::encode(&legacy), hex::encode(&legacy)]
    );
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "old KCC20V2 artifact is not registered after the standard-native cutover"]
async fn persist_tx_projects_kcc20_v2_deploy_premint_holder_output(pool: PgPool) {
    let deploy_txid = "5c".repeat(32);
    let owner = "11".repeat(32);
    let premint_owner = "22".repeat(32);
    let treasury = "33".repeat(32);
    let claim_blob = json!({
        "tmpl": "KCC20V2",
        "args": [
            {"name": "stateOwner", "type": "byte[32]", "value": owner},
            {"name": "stateOwnerType", "type": "u64", "value": "0"},
            {"name": "maxSupply", "type": "u64", "value": "1000000"},
            {"name": "premintSupply", "type": "u64", "value": "500000"},
            {"name": "premintRecipient", "type": "byte[32]", "value": premint_owner},
            {"name": "premintRecipientType", "type": "u64", "value": "0"},
            {"name": "mintMode", "type": "u64", "value": "2"},
            {"name": "mintPricePerTokenSompi", "type": "u64", "value": "500000000"},
            {"name": "treasuryRecipient", "type": "byte[32]", "value": treasury},
            {"name": "protocolFeeBps", "type": "u64", "value": "200"},
            {"name": "ticker", "type": "string", "value": "TESTV9"},
            {"name": "tokenName", "type": "string", "value": "Test V9"}
        ]
    });
    let deploy_states = kcc20_v2::deploy_output_states_from_claimed_args(&claim_blob).unwrap();
    let minter_script_hash_hex = hex::encode(deploy_states[0].script_hash);
    let premint_script_hash_hex = hex::encode(deploy_states[1].script_hash);
    let payload = hex::encode(
        json!({
            "tn10": {
                "v": 1,
                "tmpl": "KCC20V2",
                "args": claim_blob["args"].clone()
            }
        })
        .to_string(),
    );

    let deploy = RestTransaction {
        transaction_id: deploy_txid.clone(),
        block_time: 1778654400000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("b0".repeat(32)),
        accepting_block_blue_score: Some(100),
        payload: Some(payload),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: "4b".repeat(32),
            previous_outpoint_index: "4".into(),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: deploy_txid.clone(),
                index: 0,
                amount: 100_000_000,
                script_public_key: format!("aa20{minter_script_hash_hex}87"),
                script_public_key_address: Some("kaspatest:minter".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: Some("66".repeat(32)),
                covenant: None,
            },
            RestTxOutput {
                transaction_id: deploy_txid.clone(),
                index: 1,
                amount: 50_000_000,
                script_public_key: format!("20{}ac", "44".repeat(32)),
                script_public_key_address: Some("kaspatest:change".into()),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: deploy_txid.clone(),
                index: 2,
                amount: 100_000_000,
                script_public_key: format!("aa20{premint_script_hash_hex}87"),
                script_public_key_address: Some("kaspatest:premint".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: Some("77".repeat(32)),
                covenant: None,
            },
        ],
        ..Default::default()
    };
    PgPersister::new(pool.clone())
        .persist_tx(&deploy)
        .await
        .unwrap();

    let output_states: Vec<(i32, String, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT vout, encode(covenant_id, 'hex'), state
        FROM covenant_utxos
        WHERE txid = decode($1, 'hex')
        ORDER BY vout
        "#,
    )
    .bind(&deploy_txid)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(output_states.len(), 2);
    assert_eq!(output_states[0].0, 0);
    assert_eq!(output_states[1].0, 2);
    assert_eq!(output_states[0].1, "66".repeat(32));
    assert_eq!(output_states[0].1, output_states[1].1);
    assert_ne!(output_states[0].1, minter_script_hash_hex);
    assert_ne!(output_states[1].1, "77".repeat(32));
    assert_eq!(output_states[0].2["ownerIdentifier"], owner);
    assert_eq!(output_states[0].2["amount"], "500000");
    assert_eq!(output_states[0].2["isMinter"], true);
    assert_eq!(output_states[1].2["ownerIdentifier"], premint_owner);
    assert_eq!(output_states[1].2["amount"], "500000");
    assert_eq!(output_states[1].2["isMinter"], false);

    let owner_balances = repo::kcc20_balances_for_owner(&pool, &owner).await.unwrap();
    assert!(owner_balances.is_empty());

    let premint_balances = repo::kcc20_balances_for_owner(&pool, &premint_owner)
        .await
        .unwrap();
    assert_eq!(premint_balances.len(), 1);
    assert_eq!(premint_balances[0].token_id_hex, "66".repeat(32));
    assert_eq!(premint_balances[0].amount, "500000");
    assert!(!premint_balances[0].is_minter);

    let holders = repo::kcc20_holders(&pool, &"66".repeat(32), 200, 0)
        .await
        .unwrap();
    assert_eq!(holders.len(), 1);
    assert!(!holders[0].is_minter);
    let internal_minter_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_holders WHERE covenant_id = decode($1, 'hex') AND is_minter = TRUE",
    )
    .bind("66".repeat(32))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(internal_minter_rows, 1);

    repo::refresh_kcc20_token_page_projections(&pool)
        .await
        .unwrap();
    let summary = repo::kcc20_token_summary(&pool, &"66".repeat(32))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.holder_supply, "500000");
    assert_eq!(summary.remaining_supply, "500000");
    assert_eq!(summary.holder_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_non_kcc20_tx_preserves_market_summaries(pool: PgPool) {
    let token_id = insert_market_summary(&pool, 0x6a, "12345", 7, Some(1778654500000)).await;
    let script_hash_hex = "ab".repeat(32);
    let txid = "6b".repeat(32);
    let tx = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("6c".repeat(32)),
        accepting_block_blue_score: Some(101),
        outputs: vec![RestTxOutput {
            transaction_id: txid,
            index: 0,
            amount: 100,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:non-kcc20".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let row: (String, i64) = sqlx::query_as(
        r#"SELECT total_volume_sompi::TEXT, total_trades
           FROM kcc20_market_summaries
           WHERE token_id = $1"#,
    )
    .bind(&token_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("12345".to_string(), 7));
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_batch_preserves_ordered_deploy_and_continuation(pool: PgPool) {
    let covenant_id_hex = "72".repeat(32);
    let deploy_txid = "73".repeat(32);
    let spend_txid = "74".repeat(32);
    let deploy_script_hash_hex = "75".repeat(32);
    let continuation_script_hash_hex = "76".repeat(32);

    let deploy = RestTransaction {
        transaction_id: deploy_txid.clone(),
        block_time: 1778654400000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("77".repeat(32)),
        accepting_block_blue_score: Some(100),
        outputs: vec![RestTxOutput {
            transaction_id: deploy_txid.clone(),
            index: 0,
            amount: 100,
            script_public_key: format!("aa20{deploy_script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:pdeploy".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(covenant_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };

    let continuation = RestTransaction {
        transaction_id: spend_txid.clone(),
        block_time: 1778654401000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("78".repeat(32)),
        accepting_block_blue_score: Some(101),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: deploy_txid,
            previous_outpoint_index: "0".into(),
            previous_outpoint_amount: Some(100),
            previous_outpoint_script: Some(format!("aa20{deploy_script_hash_hex}87")),
            signature_script: String::new(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: spend_txid,
            index: 0,
            amount: 90,
            script_public_key: format!("aa20{continuation_script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:pcontinue".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    let replay_txids = [
        deploy.transaction_id.clone(),
        continuation.transaction_id.clone(),
    ];
    let persister = PgPersister::new(pool.clone());
    let stats = persister
        .persist_batch(&[deploy.clone(), continuation.clone()])
        .await
        .unwrap();

    assert_eq!(stats.blocks_inserted, 2);
    assert_eq!(stats.covenants_inserted, 1);
    assert_eq!(stats.utxos_inserted, 2);
    assert_eq!(stats.utxos_spent, 1);
    assert_eq!(stats.actions_inserted, 3);

    let actions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT action FROM covenant_actions
        WHERE covenant_id = decode($1, 'hex')
        ORDER BY block_time_ms, id
        "#,
    )
    .bind(&covenant_id_hex)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(actions, vec!["deploy", "spend", "continuation"]);

    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM covenant_utxos WHERE covenant_id = decode($1, 'hex') AND status = 'active'",
    )
    .bind(&covenant_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 1);

    let versions_before_replay: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT encode(txid, 'hex'), xmin::TEXT
        FROM covenant_utxos
        WHERE txid IN (decode($1, 'hex'), decode($2, 'hex'))
        ORDER BY txid
        "#,
    )
    .bind(&replay_txids[0])
    .bind(&replay_txids[1])
    .fetch_all(&pool)
    .await
    .unwrap();

    let replay_stats = persister
        .persist_batch(&[deploy, continuation])
        .await
        .unwrap();
    let versions_after_replay: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT encode(txid, 'hex'), xmin::TEXT
        FROM covenant_utxos
        WHERE txid IN (decode($1, 'hex'), decode($2, 'hex'))
        ORDER BY txid
        "#,
    )
    .bind(&replay_txids[0])
    .bind(&replay_txids[1])
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(replay_stats.utxos_inserted, 0);
    assert_eq!(versions_after_replay, versions_before_replay);
}

#[sqlx::test(migrations = "./migrations")]
async fn generic_bulk_matches_serial_spends_outputs_and_reorg(pool: PgPool) {
    let mut baseline = None;
    for (base, bulk) in [(0x01_u8, false), (0x41_u8, true)] {
        let ids = |offset: u8| {
            (0..32_u8)
                .map(|index| format!("{:02x}", base + offset + index).repeat(32))
                .collect::<Vec<_>>()
        };
        let script_ids = ids(0);
        let output_script_ids = (0..32_u8)
            .map(|index| format!("{:02x}", base + 160 + index / 2).repeat(32))
            .collect::<Vec<_>>();
        let script_id_bytes = script_ids
            .iter()
            .chain(&output_script_ids)
            .map(|id| hex::decode(id).unwrap())
            .collect::<Vec<_>>();
        let source_ids = ids(32);
        let spend_ids = ids(64);
        let source_blocks = ids(96);
        let spend_blocks = ids(128);
        let persister = PgPersister::new(pool.clone());
        let mut spends = Vec::new();
        for index in 0..32 {
            let script = format!("aa20{}87", script_ids[index]);
            let output_script = format!("aa20{}87", output_script_ids[index]);
            let address = format!("kaspatest:generic-{index}");
            let source = RestTransaction {
                transaction_id: source_ids[index].clone(),
                block_time: 1000 + index as u64,
                version: 0,
                is_accepted: true,
                accepting_block_hash: Some(source_blocks[index].clone()),
                accepting_block_blue_score: Some(100 + index as u64),
                outputs: vec![RestTxOutput {
                    transaction_id: source_ids[index].clone(),
                    index: 0,
                    amount: 100 * (index as u64 + 1),
                    script_public_key: script.clone(),
                    script_public_key_address: Some(address.clone()),
                    ..Default::default()
                }],
                ..Default::default()
            };
            persister.persist_tx(&source).await.unwrap();
            spends.push(RestTransaction {
                transaction_id: spend_ids[index].clone(),
                block_time: 2000 + index as u64,
                version: 0,
                is_accepted: true,
                accepting_block_hash: Some(spend_blocks[index].clone()),
                accepting_block_blue_score: Some(200 + index as u64),
                inputs: vec![RestTxInput {
                    previous_outpoint_hash: source_ids[index].clone(),
                    previous_outpoint_index: "0".into(),
                    previous_outpoint_amount: Some(100 * (index as u64 + 1)),
                    previous_outpoint_script: Some(script.clone()),
                    signature_script: if index % 2 == 0 {
                        "0151".into()
                    } else {
                        "0704940c00007551".into()
                    },
                    ..Default::default()
                }],
                outputs: vec![RestTxOutput {
                    transaction_id: spend_ids[index].clone(),
                    index: 0,
                    amount: 90 * (index as u64 + 1),
                    script_public_key: output_script,
                    script_public_key_address: Some(address),
                    ..Default::default()
                }],
                ..Default::default()
            });
        }
        let writer = PgPersister::new(pool.clone()).with_generic_bulk_persist(bulk);
        let stats = writer.persist_batch(&spends).await.unwrap();
        let counts = (
            stats.blocks_inserted,
            stats.covenants_inserted,
            stats.utxos_inserted,
            stats.utxos_spent,
            stats.actions_inserted,
        );
        let actions: Vec<(String, i64)> = sqlx::query_as(
            "SELECT action, COUNT(*) FROM covenant_actions WHERE covenant_id = ANY($1::bytea[]) GROUP BY action ORDER BY action",
        )
        .bind(&script_id_bytes)
        .fetch_all(&pool)
        .await
        .unwrap();
        let utxos: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status, amount_sompi FROM covenant_utxos WHERE covenant_id = ANY($1::bytea[]) ORDER BY amount_sompi, status",
        )
        .bind(&script_id_bytes)
        .fetch_all(&pool)
        .await
        .unwrap();
        let summaries: Vec<(i64, String, Option<String>, Option<i64>)> = sqlx::query_as(
            "SELECT active_utxos, total_amount_sompi::TEXT, current_address, latest_active_blue_score FROM covenant_summaries WHERE covenant_id = ANY($1::bytea[]) ORDER BY active_utxos, total_amount_sompi, current_address",
        )
        .bind(&script_id_bytes)
        .fetch_all(&pool)
        .await
        .unwrap();
        let snapshot = (counts, actions, utxos, summaries);
        if let Some(expected) = baseline.as_ref() {
            assert_eq!(&snapshot, expected);
        } else {
            baseline = Some(snapshot);
        }
        let replay = writer.persist_batch(&spends).await.unwrap();
        assert_eq!(replay.blocks_inserted, 0);
        assert_eq!(replay.covenants_inserted, 0);
        assert_eq!(replay.utxos_inserted, 0);
        assert_eq!(replay.utxos_spent, 0);
        assert_eq!(replay.actions_inserted, 0);
        writer
            .revert_block(&hex::decode(&spend_blocks[0]).unwrap())
            .await
            .unwrap();
        let restored: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM covenant_utxos WHERE txid = decode($1, 'hex') AND status = 'active'",
        )
        .bind(&source_ids[0])
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(restored, 1);
    }
}

async fn replay_real_tn10_dense_window_shape(
    pool: PgPool,
    bulk: bool,
    max_txs: Option<usize>,
    dependencies: bool,
    contention: bool,
) {
    let fixture: Vec<RestTransaction> =
        serde_json::from_str(include_str!("fixtures/tn10-dense-generic-32.json")).unwrap();
    assert_eq!(fixture.len(), 32);
    let repeat = if max_txs.is_some() {
        5
    } else {
        std::env::var("TN10_DENSE_REPLAY_REPEAT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 20)
    };
    let namespace_hash = |value: &str, round: usize| {
        if round == 0 {
            return value.to_string();
        }
        let mut bytes = hex::decode(value).unwrap();
        bytes[0] ^= round as u8;
        hex::encode(bytes)
    };
    let mut txs = Vec::with_capacity(32 * repeat);
    for round in 0..repeat {
        for mut tx in fixture.iter().cloned() {
            tx.transaction_id = namespace_hash(&tx.transaction_id, round);
            tx.accepting_block_hash = tx
                .accepting_block_hash
                .as_ref()
                .map(|hash| namespace_hash(hash, round));
            tx.accepting_block_blue_score = tx
                .accepting_block_blue_score
                .map(|score| score + round as u64);
            tx.accepting_block_time = tx.accepting_block_time.map(|time| time + round as u64);
            tx.block_time += round as u64;
            for input in &mut tx.inputs {
                input.previous_outpoint_hash = namespace_hash(&input.previous_outpoint_hash, round);
            }
            for output in &mut tx.outputs {
                if !output.transaction_id.is_empty() {
                    output.transaction_id = namespace_hash(&output.transaction_id, round);
                }
            }
            txs.push(tx);
        }
    }
    if dependencies {
        for index in [63, 128] {
            let parent = txs[index - 1].clone();
            let input = &mut txs[index].inputs[0];
            input.previous_outpoint_hash = parent.transaction_id;
            input.previous_outpoint_index = parent.outputs[0].index.to_string();
            input.previous_outpoint_amount = Some(parent.outputs[0].amount);
            input.previous_outpoint_script = Some(parent.outputs[0].script_public_key.clone());
            input.previous_outpoint_address = parent.outputs[0].script_public_key_address.clone();
        }
    }
    let batch_ids: std::collections::HashSet<_> =
        txs.iter().map(|tx| tx.transaction_id.clone()).collect();
    let mut writer = PgPersister::new(pool.clone())
        .with_bounded_writer_lock_wait()
        .with_generic_bulk_persist(bulk);
    if let Some(max_txs) = max_txs {
        writer = writer.with_generic_bulk_max_txs(max_txs);
    }
    for tx in &txs {
        for input in &tx.inputs {
            if batch_ids.contains(&input.previous_outpoint_hash) {
                continue;
            }
            let source_txid = input.previous_outpoint_hash.clone();
            let source = RestTransaction {
                transaction_id: source_txid.clone(),
                block_time: tx.block_time - 1,
                version: 0,
                is_accepted: true,
                accepting_block_hash: Some(source_txid.clone()),
                accepting_block_blue_score: Some(tx.accepting_block_blue_score.unwrap() - 1),
                outputs: vec![RestTxOutput {
                    transaction_id: source_txid,
                    index: input.previous_outpoint_index.parse().unwrap(),
                    amount: input.previous_outpoint_amount.unwrap(),
                    script_public_key: input.previous_outpoint_script.clone().unwrap(),
                    script_public_key_address: input.previous_outpoint_address.clone(),
                    ..Default::default()
                }],
                ..Default::default()
            };
            writer.persist_tx(&source).await.unwrap();
        }
    }
    if max_txs.is_some() && bulk && !dependencies && !contention {
        // Fail the second chunk after the first committed, then replay the whole window.
        sqlx::raw_sql("CREATE TABLE rejected_batch_txid (txid BYTEA PRIMARY KEY);
            CREATE FUNCTION reject_second_chunk() RETURNS TRIGGER LANGUAGE plpgsql AS $$
            BEGIN IF EXISTS (SELECT 1 FROM rejected_batch_txid WHERE txid = NEW.txid) THEN RAISE EXCEPTION 'injected second chunk failure'; END IF;
            RETURN NEW; END $$;
            CREATE TRIGGER reject_second_chunk BEFORE INSERT ON covenant_actions
            FOR EACH ROW EXECUTE FUNCTION reject_second_chunk();")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO rejected_batch_txid VALUES ($1)")
            .bind(hex::decode(&txs[128].transaction_id).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        let error = writer.persist_batch(&txs).await.unwrap_err();
        assert!(format!("{error:#}").contains("injected second chunk failure"));
        let ids: Vec<Vec<u8>> = txs
            .iter()
            .map(|tx| hex::decode(&tx.transaction_id).unwrap())
            .collect();
        let committed: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM covenant_actions WHERE txid = ANY($1)")
                .bind(&ids)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(committed, 256);
        sqlx::query("DROP TRIGGER reject_second_chunk ON covenant_actions")
            .execute(&pool)
            .await
            .unwrap();
        let resumed = writer.persist_batch(&txs).await.unwrap();
        assert_eq!(resumed.actions_inserted, 64);
        assert_eq!(resumed.utxos_inserted, 32);
        assert_eq!(resumed.utxos_spent, 32);
        let replay = writer.persist_batch(&txs).await.unwrap();
        assert_eq!(replay.actions_inserted, 0);
        let mut seen = std::collections::HashSet::new();
        for tx in txs.iter().rev() {
            let hash = hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap();
            if seen.insert(hash.clone()) {
                writer.revert_block(&hash).await.unwrap();
            }
        }
    }
    if max_txs.is_some() && bulk {
        sqlx::raw_sql(
            "CREATE TABLE observed_generic_batches (transaction_id BIGINT PRIMARY KEY, actions BIGINT NOT NULL);
             CREATE FUNCTION observe_generic_batch() RETURNS TRIGGER LANGUAGE plpgsql AS $$
             BEGIN
                 INSERT INTO observed_generic_batches VALUES (txid_current(), 1)
                 ON CONFLICT (transaction_id) DO UPDATE SET actions = observed_generic_batches.actions + 1;
                 RETURN NEW;
             END $$;
             CREATE TRIGGER observe_generic_batch AFTER INSERT ON covenant_actions
             FOR EACH ROW EXECUTE FUNCTION observe_generic_batch();"
        ).execute(&pool).await.unwrap();
    }
    if contention {
        sqlx::raw_sql(
            "CREATE FUNCTION slow_bulk_actions() RETURNS TRIGGER LANGUAGE plpgsql AS $$
            BEGIN PERFORM pg_sleep(0.001); RETURN NEW; END $$;
            CREATE TRIGGER slow_bulk_actions BEFORE INSERT ON covenant_actions
            FOR EACH ROW EXECUTE FUNCTION slow_bulk_actions();",
        )
        .execute(&pool)
        .await
        .unwrap();
    }
    let started = std::time::Instant::now();
    let stats = if contention {
        let batch = txs.clone();
        let replay = tokio::spawn(async move {
            let stats = writer.persist_batch(&batch).await.unwrap();
            (writer, stats)
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let sleeping: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'PgSleep')")
                    .fetch_one(&pool).await.unwrap();
                if sleeping { break; }
                assert!(!replay.is_finished(), "bulk writer completed before contention barrier");
                tokio::task::yield_now().await;
            }
        }).await.expect("bulk writer must reach trigger while holding writer lock");
        let live_writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
        let mut live = txs[0].clone();
        // An idempotent live replay still acquires the shared writer lock.
        live.transaction_id = txs[0].inputs[0].previous_outpoint_hash.clone();
        live.accepting_block_hash = Some(live.transaction_id.clone());
        live.accepting_block_blue_score = Some(txs[0].accepting_block_blue_score.unwrap() - 1);
        live.accepting_block_time = Some(txs[0].block_time - 1);
        live.inputs.clear();
        live.outputs.clear();
        let live_started = std::time::Instant::now();
        let live_result = live_writer.persist_tx(&live).await;
        eprintln!(
            "concurrent live writer elapsed_ms={}",
            live_started.elapsed().as_millis()
        );
        live_result.expect("128-transaction chunk must release lock within live writer timeout");
        let (returned_writer, stats) = replay.await.unwrap();
        writer = returned_writer;
        sqlx::query("DROP TRIGGER slow_bulk_actions ON covenant_actions")
            .execute(&pool)
            .await
            .unwrap();
        stats
    } else {
        writer.persist_batch(&txs).await.unwrap()
    };
    eprintln!(
        "dense fixture {} tx bulk={bulk} elapsed_ms={}",
        txs.len(),
        started.elapsed().as_millis()
    );
    assert_eq!(stats.blocks_inserted, repeat as u64);
    assert_eq!(stats.utxos_spent, (32 * repeat) as u64);
    assert_eq!(stats.utxos_inserted, (32 * repeat) as u64);
    assert_eq!(stats.actions_inserted, (64 * repeat) as u64);
    if max_txs.is_some() && bulk {
        let batch_actions: Vec<i64> = sqlx::query_scalar(
            "SELECT actions FROM observed_generic_batches ORDER BY actions DESC",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            batch_actions,
            if dependencies {
                vec![130, 126, 64]
            } else {
                vec![256, 64]
            }
        );
    }
    let replay = writer.persist_batch(&txs).await.unwrap();
    assert_eq!(replay.blocks_inserted, 0);
    assert_eq!(replay.utxos_spent, 0);
    assert_eq!(replay.utxos_inserted, 0);
    assert_eq!(replay.actions_inserted, 0);
    if dependencies {
        let mut seen = std::collections::HashSet::new();
        for tx in txs.iter().rev() {
            let block_hash = hex::decode(tx.accepting_block_hash.as_ref().unwrap()).unwrap();
            if seen.insert(block_hash.clone()) {
                writer.revert_block(&block_hash).await.unwrap();
            }
        }
        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM covenant_utxos WHERE status = 'active'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 158);
        let replay = writer.persist_batch(&txs).await.unwrap();
        assert_eq!(replay.actions_inserted, 320);
        assert_eq!(replay.utxos_spent, 160);
        return;
    }
    let block_hash = hex::decode(txs[0].accepting_block_hash.as_ref().unwrap()).unwrap();
    let reverted = writer.revert_block(&block_hash).await.unwrap();
    assert_eq!(reverted.utxos_reactivated, 32);
    assert_eq!(reverted.utxos_created_removed, 32);
}

#[sqlx::test(migrations = "./migrations")]
async fn generic_bulk_replays_real_tn10_dense_window_shape(pool: PgPool) {
    replay_real_tn10_dense_window_shape(pool, true, None, false, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn serial_replays_real_tn10_dense_window_shape(pool: PgPool) {
    replay_real_tn10_dense_window_shape(pool, false, None, false, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn generic_bulk_128_preserves_replay_and_reorg(pool: PgPool) {
    replay_real_tn10_dense_window_shape(pool, true, Some(128), false, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn generic_bulk_128_splits_dependencies_and_preserves_reorg(pool: PgPool) {
    replay_real_tn10_dense_window_shape(pool, true, Some(128), true, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn serial_matches_bulk_128_dependency_fixture(pool: PgPool) {
    replay_real_tn10_dense_window_shape(pool, false, Some(128), true, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn generic_bulk_128_allows_concurrent_bounded_live_writer(pool: PgPool) {
    replay_real_tn10_dense_window_shape(pool, true, Some(128), false, true).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn action_addresses_use_current_contract_address(pool: PgPool) {
    let covenant_id_hex = "81".repeat(32);
    let deploy_txid = "82".repeat(32);
    let first_spend_txid = "83".repeat(32);
    let second_spend_txid = "84".repeat(32);
    let deploy_script_hash_hex = "85".repeat(32);
    let first_script_hash_hex = "86".repeat(32);
    let second_script_hash_hex = "87".repeat(32);
    let deploy_address = "kaspatest:pdeploy-address";
    let first_address = "kaspatest:pfirst-continuation";
    let second_address = "kaspatest:psecond-continuation";

    let deploy = RestTransaction {
        transaction_id: deploy_txid.clone(),
        block_time: 1778654400000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("88".repeat(32)),
        accepting_block_blue_score: Some(100),
        outputs: vec![RestTxOutput {
            transaction_id: deploy_txid.clone(),
            index: 0,
            amount: 100,
            script_public_key: format!("aa20{deploy_script_hash_hex}87"),
            script_public_key_address: Some(deploy_address.into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(covenant_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };
    let first_continuation = RestTransaction {
        transaction_id: first_spend_txid.clone(),
        block_time: 1778654401000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("89".repeat(32)),
        accepting_block_blue_score: Some(101),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: deploy_txid,
            previous_outpoint_index: "0".into(),
            previous_outpoint_amount: Some(100),
            previous_outpoint_script: Some(format!("aa20{deploy_script_hash_hex}87")),
            signature_script: String::new(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: first_spend_txid.clone(),
            index: 0,
            amount: 90,
            script_public_key: format!("aa20{first_script_hash_hex}87"),
            script_public_key_address: Some(first_address.into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };
    let second_continuation = RestTransaction {
        transaction_id: second_spend_txid.clone(),
        block_time: 1778654402000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("8a".repeat(32)),
        accepting_block_blue_score: Some(102),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: first_spend_txid,
            previous_outpoint_index: "0".into(),
            previous_outpoint_amount: Some(90),
            previous_outpoint_script: Some(format!("aa20{first_script_hash_hex}87")),
            signature_script: String::new(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: second_spend_txid.clone(),
            index: 0,
            amount: 80,
            script_public_key: format!("aa20{second_script_hash_hex}87"),
            script_public_key_address: Some(second_address.into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_batch(&[deploy, first_continuation, second_continuation])
        .await
        .unwrap();

    let actions = repo::actions_for_covenant(&pool, &covenant_id_hex, 200, 0, false, None, &[])
        .await
        .unwrap();
    assert_eq!(
        actions
            .iter()
            .map(|row| (row.action.as_str(), row.address.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("deploy", second_address),
            ("spend", second_address),
            ("continuation", second_address),
            ("spend", second_address),
            ("continuation", second_address),
        ]
    );
    assert_eq!(
        actions[3]
            .inputs
            .as_ref()
            .and_then(|inputs| inputs.get("address"))
            .and_then(|value| value.as_str()),
        Some(second_address)
    );
    assert_eq!(
        actions[0]
            .outputs
            .as_ref()
            .and_then(|outputs| outputs.get("address"))
            .and_then(|value| value.as_str()),
        Some(second_address)
    );
    let stored_addresses: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"
        SELECT action,
               inputs->>'address' AS input_address,
               outputs->>'address' AS output_address
        FROM covenant_actions
        WHERE covenant_id = decode($1, 'hex')
        ORDER BY block_time_ms, id
        "#,
    )
    .bind(&covenant_id_hex)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored_addresses,
        vec![
            ("deploy".to_string(), None, Some(deploy_address.to_string())),
            ("spend".to_string(), Some(deploy_address.to_string()), None),
            (
                "continuation".to_string(),
                None,
                Some(first_address.to_string())
            ),
            ("spend".to_string(), Some(first_address.to_string()), None),
            (
                "continuation".to_string(),
                None,
                Some(second_address.to_string())
            ),
        ]
    );

    sqlx::query(
        r#"UPDATE covenant_actions
           SET inputs = inputs - 'address'
           WHERE txid = decode($1, 'hex') AND action = 'spend'"#,
    )
    .bind(&second_spend_txid)
    .execute(&pool)
    .await
    .unwrap();

    let historical_actions =
        repo::actions_for_covenant(&pool, &covenant_id_hex, 200, 0, false, None, &[])
            .await
            .unwrap();
    assert_eq!(historical_actions[3].address, second_address);

    let first_address_actions = repo::actions_by_address(&pool, first_address, 10)
        .await
        .unwrap();
    assert!(first_address_actions.is_empty());

    let current_address_actions = repo::actions_by_address(&pool, second_address, 10)
        .await
        .unwrap();
    assert_eq!(
        current_address_actions
            .iter()
            .map(|row| (row.action.as_str(), row.address.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("continuation", second_address),
            ("spend", second_address),
            ("continuation", second_address),
            ("spend", second_address),
            ("deploy", second_address),
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_keeps_historical_action_address_repair_off_hot_path(pool: PgPool) {
    let block = insert_block(&pool, 0x91, 120).await;
    let next_block = insert_block(&pool, 0x92, 121).await;
    let covenant_id_hex = "93".repeat(32);
    let script_hash_hex = "94".repeat(32);
    let old_address = "kaspatest:pold-batched-normalize";
    let historic_address = "kaspatest:phistorical-batched-normalize";
    let new_address = "kaspatest:pnew-batched-normalize";
    let covenant = insert_covenant(
        &pool,
        0x93,
        "kaspatest:pgenesis-batched-normalize",
        Some("BatchNormalizeFixture"),
        &block,
        120,
    )
    .await;
    insert_active_utxo_with_script_hash(
        &pool,
        &covenant,
        old_address,
        100,
        &hex::decode(&script_hash_hex).unwrap(),
        &block,
        0xd1,
    )
    .await;

    sqlx::query(
        r#"
        INSERT INTO covenant_actions
            (covenant_id, txid, block_hash, block_time_ms, action, entrypoint,
             inputs, outputs, decoded_args)
        SELECT $1,
               decode(lpad(to_hex(100000 + g), 64, '0'), 'hex'),
               $2,
               1778654400000 + g,
               'continuation',
               NULL,
               NULL,
               jsonb_build_object('address', $3::TEXT, 'vout', g),
               NULL
        FROM generate_series(1, 1005) AS g
        "#,
    )
    .bind(&covenant)
    .bind(&block)
    .bind(historic_address)
    .execute(&pool)
    .await
    .unwrap();

    let spend_txid = "95".repeat(32);
    let continuation = RestTransaction {
        transaction_id: spend_txid.clone(),
        block_time: 1778655500000,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some(hex::encode(&next_block)),
        accepting_block_blue_score: Some(121),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: hex::encode(vec![0xd1_u8; 32]),
            previous_outpoint_index: "0".into(),
            previous_outpoint_amount: Some(100),
            previous_outpoint_script: Some(format!("aa20{script_hash_hex}87")),
            signature_script: String::new(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: spend_txid,
            index: 0,
            amount: 90,
            script_public_key: format!("aa20{}87", "96".repeat(32)),
            script_public_key_address: Some(new_address.into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(covenant_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_batch(&[continuation])
        .await
        .unwrap();

    let stale_rows: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM covenant_actions
        WHERE covenant_id = decode($1, 'hex')
          AND outputs->>'address' = $2
        "#,
    )
    .bind(&covenant_id_hex)
    .bind(historic_address)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale_rows, 1005);

    let normalized_rows: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM covenant_actions
        WHERE covenant_id = decode($1, 'hex')
          AND outputs->>'address' = $2
        "#,
    )
    .bind(&covenant_id_hex)
    .bind(new_address)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(normalized_rows, 1);

    let actions = repo::actions_for_covenant(&pool, &covenant_id_hex, 20, 0, false, None, &[])
        .await
        .unwrap();
    assert!(actions.iter().all(|action| action.address == new_address));
    assert!(actions.iter().all(|action| {
        action
            .outputs
            .as_ref()
            .and_then(|outputs| outputs.get("address"))
            .and_then(|value| value.as_str())
            .is_none_or(|address| address == new_address)
    }));

    // Reverting the continuation restores the previous active address. The
    // read path must reflect that address without rewriting 1005 historical rows in
    // the live writer's reorg transaction.
    PgPersister::new(pool.clone())
        .revert_block(&next_block)
        .await
        .unwrap();
    let restored = repo::actions_for_covenant(&pool, &covenant_id_hex, 20, 0, false, None, &[])
        .await
        .unwrap();
    assert!(restored.iter().all(|action| action.address == old_address));
    assert!(restored.iter().all(|action| {
        action.outputs.as_ref().and_then(|value| value.get("address"))
            .and_then(|value| value.as_str()).is_none_or(|address| address == old_address)
    }));
    let by_address = repo::actions_by_address(&pool, old_address, 10).await.unwrap();
    assert!(!by_address.is_empty());
    assert!(by_address.iter().all(|action| action.address == old_address));
    let untouched_historical_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_actions WHERE covenant_id=$1 AND outputs->>'address'=$2",
    )
    .bind(&covenant)
    .bind(historic_address)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(untouched_historical_rows, 1005);
}

#[sqlx::test(migrations = "./migrations")]
async fn multi_active_covenant_actions_keep_their_own_contract_addresses(pool: PgPool) {
    let block = insert_block(&pool, 0x8b, 110).await;
    let covenant_id_hex = "8c".repeat(32);
    let genesis_address = "kaspatest:pmulti-genesis";
    let first_address = "kaspatest:pmulti-first";
    let second_address = "kaspatest:pmulti-second";
    let covenant = insert_covenant(
        &pool,
        0x8c,
        genesis_address,
        Some("MultiActiveFixture"),
        &block,
        110,
    )
    .await;
    insert_active_utxo(&pool, &covenant, first_address, 100, &block, 0x8d).await;
    insert_active_utxo(&pool, &covenant, second_address, 200, &block, 0x8e).await;
    insert_action_with_outputs_and_args(
        &pool,
        &covenant,
        0x8f,
        &block,
        1778654401100,
        "continuation",
        None,
        Some(json!({"address": first_address, "vout": 0})),
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &covenant,
        0x90,
        &block,
        1778654401200,
        "continuation",
        None,
        Some(json!({"address": second_address, "vout": 1})),
        None,
    )
    .await;

    let active_utxos: i64 = sqlx::query_scalar(
        "SELECT active_utxos FROM covenant_summaries WHERE covenant_id = decode($1, 'hex')",
    )
    .bind(&covenant_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_utxos, 2);

    let actions = repo::actions_for_covenant(&pool, &covenant_id_hex, 200, 0, false, None, &[])
        .await
        .unwrap();
    assert_eq!(
        actions
            .iter()
            .map(|row| {
                (
                    row.address.as_str(),
                    row.outputs
                        .as_ref()
                        .and_then(|outputs| outputs.get("address"))
                        .and_then(|value| value.as_str()),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (first_address, Some(first_address)),
            (second_address, Some(second_address)),
        ]
    );

    let current_address: String = sqlx::query_scalar(
        "SELECT current_address FROM covenant_summaries WHERE covenant_id = decode($1, 'hex')",
    )
    .bind(&covenant_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(actions.iter().any(|row| row.address != current_address));
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_computes_genesis_covenant_id_from_v1_deploy_payload(pool: PgPool) {
    let script_hash_hex = "b808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d";
    let covenant_id_hex = "884c13695a8bef0023ab743ed43102a4832bdaaceb8a27a48589bef0906b25f5";
    let txid = "536d2b5459bbd9a742ffcee2e3b2d422830e94b7bbe45098b554e46bde6d2e8b";
    let tx = RestTransaction {
        transaction_id: txid.into(),
        version: 1,
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("44".repeat(32)),
        accepting_block_blue_score: Some(100),
        payload: Some(hex::encode(br#"{"tn10":{"v":1,"tmpl":"KCC20","args":[]}}"#)),
        inputs: vec![RestTxInput {
            previous_outpoint_hash:
                "40c367458fd0790267e3a90098ffbb4fba7800f64a53134a33d9315a9789ed1f".into(),
            previous_outpoint_index: "1".into(),
            // Synthetic funding evidence for this fixture; unknown inputs must fail.
            previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: txid.into(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:p".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    let persister = PgPersister::new(pool.clone());
    persister.persist_tx(&tx).await.unwrap();

    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT encode(covenant_id, 'hex'), encode(script_hash, 'hex'), claimed_template FROM covenants",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, covenant_id_hex);
    assert_eq!(row.1, script_hash_hex);
    assert_eq!(row.2.as_deref(), Some("KCC20"));

    let dirty_rows_before_replay: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_projection_dirty")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(dirty_rows_before_replay > 0);

    let replay_stats = persister.persist_tx(&tx).await.unwrap();
    let dirty_rows_after_replay: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_projection_dirty")
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(replay_stats.utxos_inserted, 0);
    assert_eq!(replay_stats.actions_inserted, 0);
    assert_eq!(dirty_rows_after_replay, dirty_rows_before_replay);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_stores_deploy_payload_claim_before_optional_update_path(pool: PgPool) {
    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION test_slow_claim_update()
        RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.claimed_template IS NOT NULL AND OLD.claimed_template IS NULL THEN
                PERFORM pg_sleep(2);
            END IF;
            RETURN NEW;
        END;
        $$;
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        CREATE TRIGGER test_slow_claim_update
        BEFORE UPDATE OF claimed_template ON covenants
        FOR EACH ROW
        EXECUTE FUNCTION test_slow_claim_update();
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let script_hash_hex = "b808c1364721429a386ed5b0089b0679928dbb0bde113c0408077990bd98bc0d";
    let txid = "536d2b5459bbd9a742ffcee2e3b2d422830e94b7bbe45098b554e46bde6d2e8c";
    let tx = RestTransaction {
        transaction_id: txid.into(),
        version: 1,
        block_time: 1778654400000,
        is_accepted: true,
        accepting_block_hash: Some("45".repeat(32)),
        accepting_block_blue_score: Some(101),
        payload: Some(hex::encode(br#"{"tn10":{"v":1,"tmpl":"KCC20","args":[]}}"#)),
        inputs: vec![RestTxInput {
            previous_outpoint_hash:
                "40c367458fd0790267e3a90098ffbb4fba7800f64a53134a33d9315a9789ed1f".into(),
            previous_outpoint_index: "2".into(),
            // Synthetic funding evidence for this fixture; unknown inputs must fail.
            previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: txid.into(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:p".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    let started = std::time::Instant::now();
    let stats = PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "deploy payload claim should not wait for the optional update timeout path"
    );

    assert_eq!(stats.utxos_inserted, 1);
    assert_eq!(stats.actions_inserted, 1);

    let row: (String, Option<String>, i64, i64) = sqlx::query_as(
        r#"
        SELECT encode(c.covenant_id, 'hex'),
               c.claimed_template,
               (SELECT COUNT(*) FROM covenant_utxos WHERE covenant_id = c.covenant_id),
               (SELECT COUNT(*) FROM covenant_actions WHERE covenant_id = c.covenant_id)
        FROM covenants c
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_ne!(row.0, script_hash_hex);
    assert_eq!(row.1.as_deref(), Some("KCC20"));
    assert_eq!(row.2, 1);
    assert_eq!(row.3, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_computes_deadman_switch_genesis_covenant_id_without_payload(pool: PgPool) {
    let covenant_id_hex = "f43ab9b0ffda99a204ecebc3bc9df7d7bf7e8949e2358643ae02bcebf828a5f6";
    let script_hash_hex = "08aa9aa589f35fc5127483e82a36efd6ae77b142fe52203b41c8b766ff011227";
    let txid = "57775955da444980bc320b977937a6db350e438d435f701938a7b1679cc6633b";
    let tx = RestTransaction {
        transaction_id: txid.into(),
        version: 1,
        block_time: 1780447338944,
        is_accepted: true,
        accepting_block_hash: Some(
            "8d010127721488eef10386478ec5c9f6df904607cd170e0350e48612d61f3f14".into(),
        ),
        accepting_block_blue_score: Some(470165089),
        payload: None,
        inputs: vec![
            RestTxInput {
                previous_outpoint_hash:
                    "5d9aad8116dcbf6077632061d6fba7a5815346425208542240e268d03fbb1d87".into(),
                previous_outpoint_index: "0".into(),
                // Synthetic funding evidence for this fixture; unknown inputs must fail.
                previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash:
                    "cec37073c805ef7d65c6fcf93888c110904726eba91fb384c2e588884054aa79".into(),
                previous_outpoint_index: "1".into(),
                // Synthetic funding evidence for this fixture; unknown inputs must fail.
                previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
                ..Default::default()
            },
        ],
        outputs: vec![RestTxOutput {
            transaction_id: txid.into(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some(
                "kaspatest:pqy24x4938e4l3gjwjp7s23kalt2uaa3gtl9ygpmg8ytwehlqyfzw3n6dhrdv".into(),
            ),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let row: (String, String) = sqlx::query_as(
        "SELECT encode(covenant_id, 'hex'), encode(script_hash, 'hex') FROM covenants",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, covenant_id_hex);
    assert_eq!(row.1, script_hash_hex);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_propagates_spent_covenant_id_for_deadman_switch_keepalive(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant_id =
        hex::decode("f43ab9b0ffda99a204ecebc3bc9df7d7bf7e8949e2358643ae02bcebf828a5f6").unwrap();
    let creation_txid =
        hex::decode("57775955da444980bc320b977937a6db350e438d435f701938a7b1679cc6633b").unwrap();
    let genesis_script_hash =
        hex::decode("08aa9aa589f35fc5127483e82a36efd6ae77b142fe52203b41c8b766ff011227").unwrap();
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
            classification_kind, classification_status)
           VALUES ($1, $2, 0, $3, 'DeadManSwitch',
                   $4, 0, $5, 1780447338944, NULL, 'covenant', 'matched')"#,
    )
    .bind(&covenant_id)
    .bind("kaspatest:pqy24x4938e4l3gjwjp7s23kalt2uaa3gtl9ygpmg8ytwehlqyfzw3n6dhrdv")
    .bind(&genesis_script_hash)
    .bind(&creation_txid)
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();
    let genesis_claim = json!({
        "tmpl": "DeadManSwitch",
        "args": [
            {"name": "owner", "type": "address", "value": "kaspatest:qowner"},
            {"name": "heir", "type": "address", "value": "kaspatest:qheir"},
            {"name": "checkInDeadline", "type": "blueScore", "value": "988693200001"}
        ]
    });
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'DeadManSwitch',
               claimed_args = $2,
               claim_source = 'payload'
           WHERE covenant_id = $1"#,
    )
    .bind(&covenant_id)
    .bind(&genesis_claim)
    .execute(&pool)
    .await
    .unwrap();
    let mut genesis_spk = Vec::with_capacity(35);
    genesis_spk.extend_from_slice(&[0xaa, 0x20]);
    genesis_spk.extend_from_slice(&genesis_script_hash);
    genesis_spk.push(0x87);
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, $3, 100000000, $4, NULL, $5, NULL, NULL, 'active')"#,
    )
    .bind(&creation_txid)
    .bind(&covenant_id)
    .bind("kaspatest:pqy24x4938e4l3gjwjp7s23kalt2uaa3gtl9ygpmg8ytwehlqyfzw3n6dhrdv")
    .bind(&genesis_spk)
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let keepalive_script_hash = "1d7f46505938b24a70f57217a6fa483a577a0ba08f69952d901fbaeb2bae8b2f";
    let keepalive_txid = "942ea404fadf44f8ca5a0731d7341f6daf767780c3c30e0097a722c3b48b3fb2";
    let keepalive_payload = json!({
        "tn10": {
            "v": 1,
            "tmpl": "DeadManSwitch",
            "args": [
                {"name": "owner", "type": "address", "value": "kaspatest:qowner"},
                {"name": "heir", "type": "address", "value": "kaspatest:qheir"},
                {"name": "checkInDeadline", "type": "blueScore", "value": "988693200002"}
            ]
        }
    });
    let tx = RestTransaction {
        transaction_id: keepalive_txid.into(),
        version: 1,
        block_time: 1780447339944,
        is_accepted: true,
        accepting_block_hash: Some("55".repeat(32)),
        accepting_block_blue_score: Some(470165100),
        payload: Some(hex::encode(keepalive_payload.to_string())),
        inputs: vec![RestTxInput {
            previous_outpoint_hash:
                "57775955da444980bc320b977937a6db350e438d435f701938a7b1679cc6633b".into(),
            previous_outpoint_index: "0".into(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: keepalive_txid.into(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{keepalive_script_hash}87"),
            script_public_key_address: Some(
                "kaspatest:pqwh73jstyutyjns74ep0fh6fqa9w7st5z8kn9fdjq0m46et469j7hwgmk98k".into(),
            ),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let active: (String, String, String) = sqlx::query_as(
        r#"SELECT encode(covenant_id, 'hex'), address, encode(script_pubkey, 'hex')
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND vout = 0"#,
    )
    .bind(keepalive_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        active.0,
        "f43ab9b0ffda99a204ecebc3bc9df7d7bf7e8949e2358643ae02bcebf828a5f6"
    );
    assert_eq!(
        active.1,
        "kaspatest:pqwh73jstyutyjns74ep0fh6fqa9w7st5z8kn9fdjq0m46et469j7hwgmk98k"
    );
    assert_eq!(active.2, format!("aa20{keepalive_script_hash}87"));

    let summary = repo::covenant_by_script_hash(&pool, &hex::encode(&covenant_id))
        .await
        .unwrap()
        .expect("covenant should exist");
    assert_eq!(summary.address, active.1);
    assert_eq!(summary.active_utxos, 1);
    assert_eq!(summary.total_amount_sompi, 100_000_000);

    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM covenant_actions ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(actions, vec!["spend", "continuation"]);

    let claim: serde_json::Value =
        sqlx::query_scalar("SELECT claimed_args FROM covenants WHERE covenant_id = $1")
            .bind(&covenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim["args"][2]["value"], "988693200002");

    let summary = repo::covenant_by_script_hash(
        &pool,
        "f43ab9b0ffda99a204ecebc3bc9df7d7bf7e8949e2358643ae02bcebf828a5f6",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        summary.address,
        "kaspatest:pqwh73jstyutyjns74ep0fh6fqa9w7st5z8kn9fdjq0m46et469j7hwgmk98k"
    );
    assert_eq!(
        summary.claimed_args.unwrap()["args"][2]["value"],
        "988693200002"
    );

    let newer_keepalive_script_hash =
        "0a1a63b3b5eaebc891e4d04725f08a2a30af4cb06e2643f80002a974a973cf6a";
    let newer_keepalive_txid = "114d7a45da30086e442d5bed8b1015764ac4f39e1abb9f64e54e8c492b34a31d";
    let newer_keepalive_payload = json!({
        "tn10": {
            "v": 1,
            "tmpl": "DeadManSwitch",
            "args": [
                {"name": "owner", "type": "address", "value": "kaspatest:qowner"},
                {"name": "heir", "type": "address", "value": "kaspatest:qheir"},
                {"name": "checkInDeadline", "type": "blueScore", "value": "988693200003"}
            ]
        }
    });
    let newer_tx = RestTransaction {
        transaction_id: newer_keepalive_txid.into(),
        version: 1,
        block_time: 1780447340944,
        is_accepted: true,
        accepting_block_hash: Some("66".repeat(32)),
        accepting_block_blue_score: Some(470165101),
        payload: Some(hex::encode(newer_keepalive_payload.to_string())),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: keepalive_txid.into(),
            previous_outpoint_index: "0".into(),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: newer_keepalive_txid.into(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{newer_keepalive_script_hash}87"),
            script_public_key_address: Some(
                "kaspatest:pq9p5cankh4whjy3ungywf0s3g4rpt6vkphzvslcqqp2ja9fw08k5ve9muzuf".into(),
            ),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&newer_tx)
        .await
        .unwrap();
    let claim_after_newer: serde_json::Value =
        sqlx::query_scalar("SELECT claimed_args FROM covenants WHERE covenant_id = $1")
            .bind(&covenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim_after_newer["args"][2]["value"], "988693200003");

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();
    let claim_after_old_replay: serde_json::Value =
        sqlx::query_scalar("SELECT claimed_args FROM covenants WHERE covenant_id = $1")
            .bind(&covenant_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim_after_old_replay["args"][2]["value"], "988693200003");
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_does_not_propagate_generic_parent_to_ambiguous_multi_p2sh_outputs(
    pool: PgPool,
) {
    let block = insert_block(&pool, 1, 100).await;
    let parent = insert_covenant(
        &pool,
        0x44,
        "kaspatest:pparent",
        Some("DeadManSwitch"),
        &block,
        100,
    )
    .await;
    let parent_txid = vec![0x91u8; 32];
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, 'kaspatest:pparent', 100000000, $3, NULL, $4, NULL, NULL, 'active')"#,
    )
    .bind(&parent_txid)
    .bind(&parent)
    .bind(vec![0u8; 35])
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let tx = RestTransaction {
        transaction_id: txid.into(),
        version: 1,
        block_time: 1780447340000,
        is_accepted: true,
        accepting_block_hash: Some("66".repeat(32)),
        accepting_block_blue_score: Some(470165101),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: hex::encode(&parent_txid),
            previous_outpoint_index: "0".into(),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: txid.into(),
                index: 0,
                amount: 100_000_000,
                script_public_key: format!("aa20{}87", "21".repeat(32)),
                script_public_key_address: Some("kaspatest:pambiguous1".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.into(),
                index: 1,
                amount: 100_000_000,
                script_public_key: format!("aa20{}87", "22".repeat(32)),
                script_public_key_address: Some("kaspatest:pambiguous2".into()),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let propagated: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND covenant_id = $2"#,
    )
    .bind(txid)
    .bind(&parent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(propagated, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_propagates_single_generic_parent_even_when_not_input_zero(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let parent = insert_covenant(
        &pool,
        0x45,
        "kaspatest:pparent-nonzero",
        Some("DeadManSwitch"),
        &block,
        100,
    )
    .await;
    let parent_txid = vec![0x92u8; 32];
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, 'kaspatest:pparent-nonzero', 100000000, $3, NULL, $4, NULL, NULL, 'active')"#,
    )
    .bind(&parent_txid)
    .bind(&parent)
    .bind(vec![0u8; 35])
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let txid = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let tx = RestTransaction {
        transaction_id: txid.into(),
        version: 1,
        block_time: 1780447340000,
        is_accepted: true,
        accepting_block_hash: Some("67".repeat(32)),
        accepting_block_blue_score: Some(470165102),
        inputs: vec![
            RestTxInput {
                previous_outpoint_hash: "11".repeat(32),
                previous_outpoint_index: "0".into(),
                // Synthetic funding evidence for this fixture; unknown inputs must fail.
                previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash: hex::encode(&parent_txid),
                previous_outpoint_index: "0".into(),
                ..Default::default()
            },
        ],
        outputs: vec![RestTxOutput {
            transaction_id: txid.into(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{}87", "23".repeat(32)),
            script_public_key_address: Some("kaspatest:pnonzero-parent".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let propagated: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND covenant_id = $2"#,
    )
    .bind(txid)
    .bind(&parent)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(propagated, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_api_payment_channel_settlement_lifecycle(pool: PgPool) {
    let artifact: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/api-payment-channel/ApiPaymentChannel.placeholder.json"
    ))
    .unwrap();
    let reveal = artifact_script_array(&artifact);
    let script_hash_hex = hex::encode(blake2b_256(&reveal));
    let channel_id_hex = "44".repeat(32);
    let open_txid = "11".repeat(32);

    let deploy = RestTransaction {
        transaction_id: open_txid.clone(),
        version: 1,
        block_time: 1_780_000_100_000,
        is_accepted: true,
        accepting_block_hash: Some("aa".repeat(32)),
        accepting_block_blue_score: Some(100),
        outputs: vec![RestTxOutput {
            transaction_id: open_txid.clone(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:papi".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(channel_id_hex.clone()),
            covenant: None,
        }],
        ..Default::default()
    };

    PgPersister::with_network_id(pool.clone(), "testnet-10")
        .persist_tx(&deploy)
        .await
        .unwrap();

    let mut signature_script = Vec::new();
    push_data(&mut signature_script, &[0x41; 65]);
    push_data(&mut signature_script, &[0x42; 65]);
    push_data(&mut signature_script, &[0x44; 32]);
    push_i64(&mut signature_script, 50_000_000);
    push_i64(&mut signature_script, 4_000_000);
    push_i64(&mut signature_script, 0);
    push_i64(&mut signature_script, 1);
    push_i64(&mut signature_script, 0);
    push_data(&mut signature_script, &reveal);

    let settle_txid = "22".repeat(32);
    let settle = RestTransaction {
        transaction_id: settle_txid.clone(),
        version: 1,
        block_time: 1_780_000_200_000,
        is_accepted: true,
        accepting_block_hash: Some("bb".repeat(32)),
        accepting_block_blue_score: Some(101),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: open_txid,
            previous_outpoint_index: "0".into(),
            previous_outpoint_amount: Some(100_000_000),
            signature_script: hex::encode(signature_script),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: settle_txid.clone(),
                index: 0,
                amount: 50_000_000,
                script_public_key: format!("20{}ac", "55".repeat(32)),
                script_public_key_address: Some("kaspatest:qprovider".into()),
                script_public_key_type: Some("pubkey".into()),
                ..Default::default()
            },
            RestTxOutput {
                transaction_id: settle_txid.clone(),
                index: 1,
                amount: 46_000_000,
                script_public_key: format!("20{}ac", "66".repeat(32)),
                script_public_key_address: Some("kaspatest:qpayer".into()),
                script_public_key_type: Some("pubkey".into()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    PgPersister::with_network_id(pool.clone(), "testnet-10")
        .persist_tx(&settle)
        .await
        .unwrap();

    let generic = sqlx::query(
        r#"
        SELECT c.template_name, a.entrypoint, a.decoded_args->>'payerPubkey' AS payer_pubkey
        FROM covenants c
        JOIN covenant_actions a ON a.covenant_id = c.covenant_id
        WHERE c.covenant_id = decode($1, 'hex') AND a.action = 'spend'
        "#,
    )
    .bind(&channel_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        generic.get::<Option<String>, _>("template_name").as_deref(),
        Some("ApiPaymentChannel")
    );
    assert_eq!(
        generic.get::<Option<String>, _>("entrypoint").as_deref(),
        Some("settle")
    );
    assert_eq!(
        generic.get::<Option<String>, _>("payer_pubkey").as_deref(),
        Some("1111111111111111111111111111111111111111111111111111111111111111")
    );

    let channel = sqlx::query(
        r#"
        SELECT status, spent_sompi, deposit_sompi, reserve_sompi,
               encode(open_txid, 'hex') AS open_txid,
               encode(settlement_txid, 'hex') AS settlement_txid,
               provider_payout_pubkey, encode(voucher_domain_hash, 'hex') AS voucher_domain_hash,
               refund_after_ms, max_spend_sompi
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind(&channel_id_hex)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(channel.get::<String, _>("status"), "settled");
    assert_eq!(channel.get::<i64, _>("spent_sompi"), 50_000_000);
    assert_eq!(channel.get::<i64, _>("deposit_sompi"), 100_000_000);
    assert_eq!(channel.get::<i64, _>("reserve_sompi"), 1_000);
    assert_eq!(channel.get::<String, _>("open_txid"), "11".repeat(32));
    assert_eq!(channel.get::<String, _>("settlement_txid"), "22".repeat(32));
    assert_eq!(
        channel
            .get::<Option<String>, _>("provider_payout_pubkey")
            .as_deref(),
        Some("3333333333333333333333333333333333333333333333333333333333333333")
    );
    assert_eq!(
        channel.get::<String, _>("voucher_domain_hash"),
        "44".repeat(32)
    );
    assert_eq!(channel.get::<i64, _>("refund_after_ms"), 500_000_000_001);
    assert_eq!(channel.get::<i64, _>("max_spend_sompi"), 999_999_000);

    let settlement = sqlx::query(
        r#"
        SELECT settled_total_sompi, provider_amount_sompi, payer_refund_sompi, indexer_status
        FROM api_payment_settlements
        WHERE txid = decode($1, 'hex')
        "#,
    )
    .bind("22".repeat(32))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(settlement.get::<i64, _>("settled_total_sompi"), 50_000_000);
    assert_eq!(
        settlement.get::<i64, _>("provider_amount_sompi"),
        50_000_000
    );
    assert_eq!(settlement.get::<i64, _>("payer_refund_sompi"), 46_000_000);
    assert_eq!(settlement.get::<String, _>("indexer_status"), "indexed");
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_api_payment_channel_open_from_payload(pool: PgPool) {
    let payer_pubkey = "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4";
    let provider_pubkey = "5b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4";
    let provider_payout_pubkey = "6b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4";
    let voucher_domain_hash = "44".repeat(32);
    let payload = json!({
        "kaspaApiPayment": {
            "v": 1,
            "action": "channel_open",
            "contract": "ApiPaymentChannel",
            "payerPubkey": payer_pubkey,
            "providerPubkey": provider_pubkey,
            "providerPayoutPubkey": provider_payout_pubkey,
            "voucherDomainHash": voucher_domain_hash,
            "refundAfterMs": "1780580237087",
            "reserveSompi": "50000000",
            "maxSpendSompi": "50000000"
        }
    });
    let payload_hex = hex::encode(serde_json::to_vec(&payload).unwrap());
    let open_txid = "bb".repeat(32);
    let script_hash_hex = "81".repeat(32);
    let tx = RestTransaction {
        transaction_id: open_txid.clone(),
        version: 1,
        payload: Some(payload_hex),
        block_time: 1_780_580_000_000,
        is_accepted: true,
        accepting_block_hash: Some("cc".repeat(32)),
        accepting_block_blue_score: Some(300),
        inputs: vec![RestTxInput {
            previous_outpoint_hash: "aa".repeat(32),
            previous_outpoint_index: "0".into(),
            // Synthetic funding evidence for this fixture; unknown inputs must fail.
            previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
            previous_outpoint_amount: Some(200_000_000),
            ..Default::default()
        }],
        outputs: vec![RestTxOutput {
            transaction_id: open_txid.clone(),
            index: 0,
            amount: 100_000_000,
            script_public_key: format!("aa20{script_hash_hex}87"),
            script_public_key_address: Some("kaspatest:papiopen".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: None,
            covenant: None,
        }],
        ..Default::default()
    };
    let channel_id = compute_genesis_covenant_id_for_output(&tx, 0).unwrap();

    PgPersister::with_network_id(pool.clone(), "testnet-10")
        .persist_tx(&tx)
        .await
        .unwrap();
    sqlx::query(
        r#"
        UPDATE covenants
        SET template_name = NULL,
            constructor_args = NULL,
            classification_kind = 'unknown',
            classification_status = 'unrevealed'
        WHERE covenant_id = decode($1, 'hex')
        "#,
    )
    .bind(&channel_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        UPDATE covenant_actions
        SET decoded_args = NULL
        WHERE covenant_id = decode($1, 'hex')
          AND action = 'deploy'
        "#,
    )
    .bind(&channel_id)
    .execute(&pool)
    .await
    .unwrap();
    PgPersister::with_network_id(pool.clone(), "testnet-10")
        .persist_tx(&tx)
        .await
        .unwrap();

    let channel = sqlx::query(
        r#"
        SELECT status, network_id, payer_pubkey, provider_pubkey,
               provider_payout_pubkey, encode(voucher_domain_hash, 'hex') AS voucher_domain_hash,
               deposit_sompi, reserve_sompi, max_spend_sompi, refund_after_ms,
               encode(open_txid, 'hex') AS open_txid
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind(&channel_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(channel.get::<String, _>("status"), "usable");
    assert_eq!(channel.get::<String, _>("network_id"), "testnet-10");
    assert_eq!(channel.get::<String, _>("payer_pubkey"), payer_pubkey);
    assert_eq!(channel.get::<String, _>("provider_pubkey"), provider_pubkey);
    assert_eq!(
        channel
            .get::<Option<String>, _>("provider_payout_pubkey")
            .as_deref(),
        Some(provider_payout_pubkey)
    );
    assert_eq!(
        channel.get::<String, _>("voucher_domain_hash"),
        voucher_domain_hash
    );
    assert_eq!(channel.get::<i64, _>("deposit_sompi"), 100_000_000);
    assert_eq!(channel.get::<i64, _>("reserve_sompi"), 50_000_000);
    assert_eq!(channel.get::<i64, _>("max_spend_sompi"), 50_000_000);
    assert_eq!(channel.get::<i64, _>("refund_after_ms"), 1_780_580_237_087);
    assert_eq!(channel.get::<String, _>("open_txid"), open_txid);

    let generic = sqlx::query(
        r#"
        SELECT c.template_name,
               c.constructor_args->>'payerPubkey' AS constructor_payer_pubkey,
               a.decoded_args->>'providerPubkey' AS action_provider_pubkey
        FROM covenants c
        JOIN covenant_actions a ON a.covenant_id = c.covenant_id
        WHERE c.covenant_id = decode($1, 'hex')
          AND a.action = 'deploy'
        "#,
    )
    .bind(&channel_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        generic.get::<Option<String>, _>("template_name").as_deref(),
        Some("ApiPaymentChannel")
    );
    assert_eq!(
        generic
            .get::<Option<String>, _>("constructor_payer_pubkey")
            .as_deref(),
        Some(payer_pubkey)
    );
    assert_eq!(
        generic
            .get::<Option<String>, _>("action_provider_pubkey")
            .as_deref(),
        Some(provider_pubkey)
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_live_tn10_api_payment_channel_open_from_payload(pool: PgPool) {
    let txid = "bb2b53558b8815d1404913228cd3e62b8930f5c7202053e9d6355366415ec7e2";
    let tx = RestTransaction {
        transaction_id: txid.to_string(),
        version: 1,
        payload: Some("7b226b617370614170695061796d656e74223a7b2276223a312c22616374696f6e223a226368616e6e656c5f6f70656e222c22636f6e7472616374223a224170695061796d656e744368616e6e656c222c2270617965725075626b6579223a2234623166613965363232326565316238303139383534383666656131663537346536393363376565356433393333643536663339393563373738353033326434222c2270726f76696465725075626b6579223a2234623166613965363232326565316238303139383534383666656131663537346536393363376565356433393333643536663339393563373738353033326434222c2270726f76696465725061796f75745075626b6579223a2234623166613965363232326565316238303139383534383666656131663537346536393363376565356433393333643536663339393563373738353033326434222c22766f7563686572446f6d61696e48617368223a2234343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434343434222c226465706f736974536f6d7069223a22313030303030303030222c2272657365727665536f6d7069223a223530303030303030222c226d61785370656e64536f6d7069223a223530303030303030222c22726566756e6441667465724d73223a2231373830353830323337303837227d7d".to_string()),
        block_time: 1_780_576_773_268,
        is_accepted: true,
        accepting_block_hash: Some(
            "4e116c2fe5be5093f3b3f9ed243bfdc551f672df627d2af29840f961968370e0".into(),
        ),
        accepting_block_blue_score: Some(471_454_176),
        inputs: vec![RestTxInput {
            previous_outpoint_hash:
                "0895377c3ef2339a4dac404e33c32735ce9a158909ae176119e30028dfe2c2b7"
                    .into(),
            previous_outpoint_index: "1".into(),
            // Synthetic funding evidence for this fixture; unknown inputs must fail.
            previous_outpoint_script: Some(format!("20{}ac", "01".repeat(32))),
            previous_outpoint_amount: Some(114_865_661_930),
            ..Default::default()
        }],
        outputs: vec![
            RestTxOutput {
                transaction_id: txid.to_string(),
                index: 0,
                amount: 100_000_000,
                script_public_key:
                    "aa208157c111a231fdfc89e79ee97fa5ce5128eaa4d6ae2b1a49a26e9ff2da7ee17b87"
                        .into(),
                script_public_key_address: Some(
                    "kaspatest:pzq40sg35gclmlyfu70wjla9eegj364y66hzkxjf5fhfluk60mshkt2swjdzk"
                        .into(),
                ),
                script_public_key_type: Some("scripthash".into()),
                covenant_id: None,
                covenant: None,
            },
            RestTxOutput {
                transaction_id: txid.to_string(),
                index: 1,
                amount: 114_761_651_930,
                script_public_key:
                    "204b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4ac"
                        .into(),
                script_public_key_address: Some(
                    "kaspatest:qp93l20xyghwrwqpnp2gdl4p746wdy78aewnjv74duuet3mc2qedgfvgz42s2"
                        .into(),
                ),
                script_public_key_type: Some("pubkey".into()),
                covenant_id: None,
                covenant: None,
            },
        ],
        ..Default::default()
    };

    let channel_id = compute_genesis_covenant_id_for_output(&tx, 0).unwrap();
    assert_eq!(
        channel_id,
        "c91bcba8a237bbef58a3bdfbc2f6d33790e81ae2ec5700371955bdad8174dd07"
    );

    PgPersister::with_network_id(pool.clone(), "testnet-10")
        .persist_tx(&tx)
        .await
        .unwrap();

    let channel = sqlx::query(
        r#"
        SELECT status, network_id, payer_pubkey, provider_pubkey,
               provider_payout_pubkey, deposit_sompi, reserve_sompi,
               max_spend_sompi, refund_after_ms, encode(open_txid, 'hex') AS open_txid
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind(&channel_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(channel.get::<String, _>("status"), "usable");
    assert_eq!(channel.get::<String, _>("network_id"), "testnet-10");
    assert_eq!(
        channel.get::<String, _>("payer_pubkey"),
        "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
    );
    assert_eq!(
        channel.get::<String, _>("provider_pubkey"),
        "4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4"
    );
    assert_eq!(
        channel
            .get::<Option<String>, _>("provider_payout_pubkey")
            .as_deref(),
        Some("4b1fa9e6222ee1b801985486fea1f574e693c7ee5d3933d56f3995c7785032d4")
    );
    assert_eq!(channel.get::<i64, _>("deposit_sompi"), 100_000_000);
    assert_eq!(channel.get::<i64, _>("reserve_sompi"), 50_000_000);
    assert_eq!(channel.get::<i64, _>("max_spend_sompi"), 50_000_000);
    assert_eq!(channel.get::<i64, _>("refund_after_ms"), 1_780_580_237_087);
    assert_eq!(channel.get::<String, _>("open_txid"), txid);
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_replays_live_tn10_api_payment_channel_fixtures(pool: PgPool) {
    let fixtures = [
        include_str!("../../../fixtures/api-payment-channel-tn10/01-settlement-open.json"),
        include_str!("../../../fixtures/api-payment-channel-tn10/02-settlement-settle.json"),
        include_str!("../../../fixtures/api-payment-channel-tn10/03-refund-open.json"),
        include_str!("../../../fixtures/api-payment-channel-tn10/04-refund.json"),
    ];

    let persister = PgPersister::with_network_id(pool.clone(), "testnet-10");
    for raw in fixtures {
        let tx: RestTransaction = serde_json::from_str(raw).unwrap();
        persister.persist_tx(&tx).await.unwrap();
    }

    let actions = sqlx::query(
        r#"
        SELECT a.txid, a.entrypoint
        FROM covenant_actions a
        JOIN covenants c ON c.covenant_id = a.covenant_id
        WHERE c.template_name = 'ApiPaymentChannel'
          AND a.action = 'spend'
        ORDER BY a.block_time_ms
        "#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(
        hex::encode(actions[0].get::<Vec<u8>, _>("txid")),
        "6597a6741183031147b082f144685515366c024e88326aa8e567e668371922ad"
    );
    assert_eq!(
        actions[0].get::<Option<String>, _>("entrypoint").as_deref(),
        Some("refund")
    );
    assert_eq!(
        hex::encode(actions[1].get::<Vec<u8>, _>("txid")),
        "718ab78ecf3b25907d146b1fac35b1cf80efe3ecbc0d572a472ed54072909f72"
    );
    assert_eq!(
        actions[1].get::<Option<String>, _>("entrypoint").as_deref(),
        Some("settle")
    );

    let settled_channel = sqlx::query(
        r#"
        SELECT status, spent_sompi, deposit_sompi, reserve_sompi,
               encode(open_txid, 'hex') AS open_txid,
               encode(settlement_txid, 'hex') AS settlement_txid,
               encode(refund_txid, 'hex') AS refund_txid,
               refund_after_ms, max_spend_sompi
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind("af3c1065efa87396d1cefe1bf41a877370e5ce04878e3c18ef1cddcc8ba571c0")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(settled_channel.get::<String, _>("status"), "settled");
    assert_eq!(settled_channel.get::<i64, _>("spent_sompi"), 50_000_000);
    assert_eq!(settled_channel.get::<i64, _>("deposit_sompi"), 100_000_000);
    assert_eq!(settled_channel.get::<i64, _>("reserve_sompi"), 50_000_000);
    assert_eq!(
        settled_channel.get::<String, _>("open_txid"),
        "e63060ee7608086f4d7ccdb550e43832204b34257c7c83e4052069275cf1e9c0"
    );
    assert_eq!(
        settled_channel.get::<String, _>("settlement_txid"),
        "718ab78ecf3b25907d146b1fac35b1cf80efe3ecbc0d572a472ed54072909f72"
    );
    assert_eq!(
        settled_channel.get::<Option<String>, _>("refund_txid"),
        None
    );
    assert_eq!(
        settled_channel.get::<i64, _>("refund_after_ms"),
        1_780_510_711_398
    );
    assert_eq!(settled_channel.get::<i64, _>("max_spend_sompi"), 50_000_000);

    let settlement = sqlx::query(
        r#"
        SELECT channel_id, settled_total_sompi, provider_amount_sompi,
               payer_refund_sompi, indexer_status
        FROM api_payment_settlements
        WHERE txid = decode($1, 'hex')
        "#,
    )
    .bind("718ab78ecf3b25907d146b1fac35b1cf80efe3ecbc0d572a472ed54072909f72")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        settlement.get::<String, _>("channel_id"),
        "af3c1065efa87396d1cefe1bf41a877370e5ce04878e3c18ef1cddcc8ba571c0"
    );
    assert_eq!(settlement.get::<i64, _>("settled_total_sompi"), 50_000_000);
    assert_eq!(
        settlement.get::<i64, _>("provider_amount_sompi"),
        50_000_000
    );
    assert_eq!(settlement.get::<i64, _>("payer_refund_sompi"), 46_000_000);
    assert_eq!(settlement.get::<String, _>("indexer_status"), "indexed");

    let refunded_channel = sqlx::query(
        r#"
        SELECT status, spent_sompi, deposit_sompi, reserve_sompi,
               encode(open_txid, 'hex') AS open_txid,
               encode(settlement_txid, 'hex') AS settlement_txid,
               encode(refund_txid, 'hex') AS refund_txid,
               refund_after_ms, max_spend_sompi
        FROM api_payment_channels
        WHERE channel_id = $1
        "#,
    )
    .bind("0186b94fdc847765759c189719d9bab8aa8fca36f9cfa7b16d9ef04e03058170")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(refunded_channel.get::<String, _>("status"), "refunded");
    assert_eq!(refunded_channel.get::<i64, _>("spent_sompi"), 0);
    assert_eq!(refunded_channel.get::<i64, _>("deposit_sompi"), 100_000_000);
    assert_eq!(refunded_channel.get::<i64, _>("reserve_sompi"), 50_000_000);
    assert_eq!(
        refunded_channel.get::<String, _>("open_txid"),
        "969c3d893f1d2885432abb985df771ff479f3d451bcce9dabcc828524df0f93c"
    );
    assert_eq!(
        refunded_channel.get::<Option<String>, _>("settlement_txid"),
        None
    );
    assert_eq!(
        refunded_channel.get::<String, _>("refund_txid"),
        "6597a6741183031147b082f144685515366c024e88326aa8e567e668371922ad"
    );
    assert_eq!(
        refunded_channel.get::<i64, _>("refund_after_ms"),
        500_000_000_001
    );
    assert_eq!(
        refunded_channel.get::<i64, _>("max_spend_sompi"),
        50_000_000
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_id_repair_candidates_returns_script_hash_fallback_rows(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let fallback = insert_covenant(
        &pool,
        0x11,
        "kaspatest:pfallback",
        Some("DeadManSwitch"),
        &block,
        100,
    )
    .await;
    let canonical_id = vec![0x22u8; 32];
    let canonical_script_hash = vec![0x33u8; 32];
    let canonical_txid = vec![0x44u8; 32];
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
            classification_kind, classification_status)
           VALUES ($1, 'kaspatest:pcanonical', 0, $2, 'DeadManSwitch',
                   $3, 0, $4, 1778654400200, NULL, 'covenant', 'matched')"#,
    )
    .bind(&canonical_id)
    .bind(&canonical_script_hash)
    .bind(&canonical_txid)
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let stale_continuation_id = vec![0x55u8; 32];
    let stale_script_hash = vec![0x56u8; 32];
    let stale_txid = vec![0x66u8; 32];
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
            classification_kind, classification_status)
           VALUES ($1, 'kaspatest:pstale', 0, $2, 'DeadManSwitch',
                   $3, 0, $4, 1778654400300, NULL, 'covenant', 'matched')"#,
    )
    .bind(&stale_continuation_id)
    .bind(&stale_script_hash)
    .bind(&stale_txid)
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(
        &pool,
        &stale_continuation_id,
        0x66,
        &block,
        300,
        "deploy",
        None,
    )
    .await;
    insert_action_with_inputs(
        &pool,
        &canonical_id,
        0x66,
        &block,
        300,
        "spend",
        json!({"previousOutpoint": {"hash": "44".repeat(32), "index": 0}}),
    )
    .await;

    let rows = repo::covenant_id_repair_candidates(&pool, 10)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].covenant_id, fallback);
    assert_eq!(rows[0].covenant_id_hex, "11".repeat(32));
    assert_eq!(rows[1].covenant_id, stale_continuation_id);
    assert_eq!(rows[1].covenant_id_hex, "55".repeat(32));
}

#[sqlx::test(migrations = "./migrations")]
async fn rekey_covenant_id_moves_legacy_children_to_canonical_id(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let legacy = insert_covenant(&pool, 0x11, "kaspatest:legacy", Some("KCC20"), &block, 100).await;
    let canonical = vec![0x22; 32];
    insert_active_utxo(&pool, &legacy, "kaspatest:legacy", 100, &block, 0xa1).await;
    insert_action(&pool, &legacy, 0xb1, &block, 100, "deploy", None).await;
    sqlx::query("UPDATE covenant_actions SET canonical_token_id = $1 WHERE covenant_id = $1")
        .bind(&legacy)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES ($1, $2, 0, '100'::NUMERIC, 1, FALSE, 1000)"#,
    )
    .bind(&legacy)
    .bind(vec![0x33_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed
           (token_id, txid, block_time_ms, kind)
           VALUES ($1, $2, 1000, 'deploy')"#,
    )
    .bind(&legacy)
    .bind(vec![0xd1_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_market_summaries
           (token_id, open_ask_count, open_bid_count, total_volume_sompi,
            total_trades, refreshed_at_ms)
           VALUES ($1, 0, 0, '0'::NUMERIC, 0, 1000)"#,
    )
    .bind(&legacy)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_token_summaries
           (token_id, holder_count, holder_supply, remaining_supply,
            wrapper_reserve_supply, orderbook_tradeable_supply, top_holders,
            wrapper_id, refreshed_at_ms)
           VALUES ($1, 1, '100'::NUMERIC, '0'::NUMERIC, '0'::NUMERIC,
                   '0'::NUMERIC, '[]'::jsonb, $1, 1000)"#,
    )
    .bind(&legacy)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_wrapper_summaries
           (wrapper_id, canonical_token_id, address, active_utxos,
            pending_reveal, enabled, refreshed_at_ms)
           VALUES ($1, $1, 'kaspatest:legacy-wrapper', 1, FALSE, TRUE, 1000)"#,
    )
    .bind(&legacy)
    .execute(&pool)
    .await
    .unwrap();
    let legacy_channel_id = hex::encode(&legacy);
    let canonical_channel_id = hex::encode(&canonical);
    sqlx::query(
        r#"INSERT INTO api_payment_channels
           (channel_id, network_id, payer_identifier, payer_pubkey, provider_pubkey,
            deposit_sompi, reserve_sompi, status, open_txid, indexed_at_ms,
            created_at_ms, updated_at_ms)
           VALUES ($1, 'testnet-10', $2, $2, $2, 100000000, 50000000,
                   'usable', $3, 1000, 1000, 1000)"#,
    )
    .bind(&legacy_channel_id)
    .bind("aa".repeat(32))
    .bind(vec![0xb2_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO api_payment_vouchers
           (channel_id, sequence, total_spent_sompi, incremental_amount_sompi,
            pricing_id, request_hash, route, credential_hash, signature, accepted_at_ms)
           VALUES ($1, 1, 50000000, 50000000, 'kcc20.discovery.v1',
                   $2, 'GET /kcc20/discovery', $3, 'sig', 1001)"#,
    )
    .bind(&legacy_channel_id)
    .bind(vec![0xc1_u8; 32])
    .bind(vec![0xc2_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO api_payment_usage_events
           (request_id, channel_id, route, pricing_id, amount_sompi,
            voucher_sequence, created_at_ms)
           VALUES ('req-rekey', $1, 'GET /kcc20/discovery',
                   'kcc20.discovery.v1', 50000000, 1, 1002)"#,
    )
    .bind(&legacy_channel_id)
    .execute(&pool)
    .await
    .unwrap();

    assert!(repo::rekey_covenant_id(&pool, &legacy, &canonical)
        .await
        .unwrap());

    let old_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM covenants WHERE covenant_id = $1)")
            .bind(&legacy)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!old_exists);
    let child_count: i64 = sqlx::query_scalar(
        r#"
        SELECT
          (SELECT COUNT(*) FROM covenant_utxos WHERE covenant_id = $1) +
          (SELECT COUNT(*) FROM covenant_actions WHERE covenant_id = $1) +
          (SELECT COUNT(*) FROM kcc20_holders WHERE covenant_id = $1)
        "#,
    )
    .bind(&canonical)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(child_count, 3);
    let projection_count: i64 = sqlx::query_scalar(
        r#"
        SELECT
          (SELECT COUNT(*) FROM covenant_actions WHERE canonical_token_id = $1) +
          (SELECT COUNT(*) FROM kcc20_activity_feed WHERE token_id = $1) +
          (SELECT COUNT(*) FROM kcc20_market_summaries WHERE token_id = $1) +
          (SELECT COUNT(*) FROM kcc20_token_summaries WHERE token_id = $1 OR wrapper_id = $1) +
          (SELECT COUNT(*) FROM kcc20_wrapper_summaries WHERE wrapper_id = $1 OR canonical_token_id = $1)
        "#,
    )
    .bind(&canonical)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(projection_count, 5);
    let stale_projection_count: i64 = sqlx::query_scalar(
        r#"
        SELECT
          (SELECT COUNT(*) FROM covenant_actions WHERE canonical_token_id = $1) +
          (SELECT COUNT(*) FROM kcc20_activity_feed WHERE token_id = $1) +
          (SELECT COUNT(*) FROM kcc20_market_summaries WHERE token_id = $1) +
          (SELECT COUNT(*) FROM kcc20_token_summaries WHERE token_id = $1 OR wrapper_id = $1) +
          (SELECT COUNT(*) FROM kcc20_wrapper_summaries WHERE wrapper_id = $1 OR canonical_token_id = $1)
        "#,
    )
    .bind(&legacy)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale_projection_count, 0);
    let payment_channel_id: String =
        sqlx::query_scalar("SELECT channel_id FROM api_payment_channels")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(payment_channel_id, canonical_channel_id);
    let voucher_channel_id: String =
        sqlx::query_scalar("SELECT channel_id FROM api_payment_vouchers")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(voucher_channel_id, canonical_channel_id);
    let usage_channel_id: String =
        sqlx::query_scalar("SELECT channel_id FROM api_payment_usage_events")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(usage_channel_id, canonical_channel_id);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_misclassified_continuation_deploy_actions_removes_stale_deploy(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(
        &pool,
        0x22,
        "kaspatest:continuation",
        Some("DeadManSwitch"),
        &block,
        100,
    )
    .await;

    insert_action_with_inputs(
        &pool,
        &cov,
        0xee,
        &block,
        200,
        "spend",
        json!({"previousOutpoint": {"hash": "11".repeat(32), "index": 0}}),
    )
    .await;
    insert_action(&pool, &cov, 0xee, &block, 200, "deploy", None).await;
    insert_action_with_outputs_and_args(
        &pool,
        &cov,
        0xee,
        &block,
        200,
        "continuation",
        None,
        Some(json!({"vout": 0})),
        None,
    )
    .await;

    let deleted = repo::delete_misclassified_continuation_deploy_actions(&pool)
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM covenant_actions WHERE covenant_id = $1 ORDER BY action",
    )
    .bind(&cov)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(actions, vec!["continuation", "spend"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_kcc20_holders_maps_output_states_and_rebuilds_holders(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 0x22, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let legacy = insert_covenant(&pool, 0x33, "kaspatest:legacy", Some("KCC20"), &block, 101).await;
    let output_script_hash = vec![0x44_u8; 32];
    let owner_identifier = vec![0x55_u8; 32];
    insert_active_utxo_with_script_hash(
        &pool,
        &legacy,
        "kaspatest:out",
        50_000,
        &output_script_hash,
        &block,
        0xa4,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES ($1, $2, 0, '1'::NUMERIC, 1, FALSE, 1000)"#,
    )
    .bind(&legacy)
    .bind(vec![0x66_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let result = repo::repair_kcc20_holders(
        &pool,
        &token,
        std::slice::from_ref(&output_script_hash),
        &[repo::Kcc20RepairStateSpec {
            script_hash: output_script_hash.clone(),
            owner_identifier: owner_identifier.clone(),
            identifier_type: 4,
            amount: "250000".to_string(),
            is_minter: false,
        }],
        1234,
        false,
        false,
    )
    .await
    .unwrap();

    assert!(!result.dry_run);
    assert_eq!(result.canonicalized_utxos, 1);
    assert_eq!(result.state_updates, 1);
    assert_eq!(result.source_holders_deleted, 1);
    assert_eq!(result.holders_inserted, 1);

    let row: (Vec<u8>, serde_json::Value) =
        sqlx::query_as("SELECT covenant_id, state FROM covenant_utxos WHERE script_pubkey = $1")
            .bind({
                let mut script = Vec::with_capacity(35);
                script.extend_from_slice(&[0xaa, 0x20]);
                script.extend_from_slice(&output_script_hash);
                script.push(0x87);
                script
            })
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row.0, token);
    assert_eq!(row.1["owner"], hex::encode(&owner_identifier));
    assert_eq!(row.1["ownerScheme"], 4);
    assert_eq!(row.1["ownerSchemeName"], "covenant-id/v1");
    assert_eq!(row.1["amount"], "250000");

    let holders = repo::kcc20_holders(&pool, &hex::encode(&token), 200, 0)
        .await
        .unwrap();
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0].owner_identifier, hex::encode(owner_identifier));
    assert_eq!(holders[0].identifier_type, 4);
    assert_eq!(holders[0].amount, "250000");
    assert_eq!(holders[0].utxo_count, 1);
    assert_eq!(holders[0].last_change_ms, 1234);

    let stale_holder_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_holders WHERE covenant_id = $1")
            .bind(&legacy)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stale_holder_count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_kcc20_holders_keeps_same_owner_holder_and_minter_rows(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 0x45, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let owner_identifier = vec![0xce_u8; 32];

    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:holder",
        50_000,
        json!({
            "owner": hex::encode(&owner_identifier),
            "ownerScheme": 0,
            "amount": "500",
            "isMintAuthority": false,
        }),
        &block,
        0xa1,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:minter",
        50_000,
        json!({
            "owner": hex::encode(&owner_identifier),
            "ownerScheme": 0,
            "amount": "9500",
            "isMintAuthority": true,
        }),
        &block,
        0xa2,
    )
    .await;

    let result = repo::repair_kcc20_holders(&pool, &token, &[], &[], 1234, false, false)
        .await
        .unwrap();
    assert_eq!(result.holders_inserted, 2);

    let public_holders = repo::kcc20_holders(&pool, &hex::encode(&token), 200, 0)
        .await
        .unwrap();
    assert_eq!(public_holders.len(), 1);
    assert_eq!(
        public_holders[0].owner_identifier,
        hex::encode(&owner_identifier)
    );
    assert_eq!(public_holders[0].amount, "500");
    assert!(!public_holders[0].is_minter);

    let internal_rows: Vec<(bool, String)> = sqlx::query_as(
        r#"
        SELECT is_minter, amount_total::TEXT
        FROM kcc20_holders
        WHERE covenant_id = $1
        ORDER BY is_minter
        "#,
    )
    .bind(&token)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        internal_rows,
        vec![(false, "500".to_string()), (true, "9500".to_string())]
    );

    repo::refresh_kcc20_token_page_projections(&pool)
        .await
        .unwrap();
    let summary = repo::kcc20_token_summary(&pool, &hex::encode(&token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.holder_supply, "500");
    assert_eq!(summary.remaining_supply, "0");
    assert_eq!(summary.holder_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn repair_kcc20_holders_counts_only_spendable_holder_states(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 0x46, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let owner_identifier = vec![0xab_u8; 32];

    for (index, address, amount, is_mint_authority, mode) in [
        (0, "kaspatest:holder-a", "100", false, None),
        (1, "kaspatest:holder-b", "200", false, Some(0)),
        (2, "kaspatest:minter", "300", true, None),
        (3, "kaspatest:wrapped-root", "400", false, Some(1)),
        (4, "kaspatest:wrapped-ask", "500", false, Some(2)),
        (5, "kaspatest:wrapped-bid", "600", false, Some(3)),
    ] {
        let mut state = json!({
            "owner": hex::encode(&owner_identifier),
            "ownerScheme": 0,
            "amount": amount,
            "isMintAuthority": is_mint_authority,
        });
        if let Some(mode) = mode {
            state["mode"] = json!(mode);
        }
        insert_active_utxo_with_state(&pool, &token, address, 50_000, state, &block, index).await;
    }

    let result = repo::repair_kcc20_holders(&pool, &token, &[], &[], 1234, false, false)
        .await
        .unwrap();
    assert_eq!(result.holders_inserted, 2);

    let balances = repo::kcc20_balances_for_owner(&pool, &hex::encode(&owner_identifier))
        .await
        .unwrap();
    assert_eq!(balances.len(), 1);
    assert_eq!(balances[0].token_id_hex, hex::encode(&token));
    assert_eq!(balances[0].amount, "300");
    assert_eq!(balances[0].utxo_count, 2);

    let internal_rows: Vec<(bool, String, i32)> = sqlx::query_as(
        r#"
        SELECT is_minter, amount_total::TEXT, utxo_count
        FROM kcc20_holders
        WHERE covenant_id = $1
        ORDER BY is_minter
        "#,
    )
    .bind(&token)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        internal_rows,
        vec![(false, "300".to_string(), 2), (true, "300".to_string(), 1),]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_balances_for_owner_pages_and_counts(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let first = insert_covenant(&pool, 0x71, "kaspatest:first", Some("KCC20V2"), &block, 100).await;
    let second = insert_covenant(
        &pool,
        0x72,
        "kaspatest:second",
        Some("KCC20V2"),
        &block,
        101,
    )
    .await;
    let owner = vec![0x73_u8; 32];
    for (token, amount) in [(&first, "200"), (&second, "100")] {
        sqlx::query(
            r#"
            INSERT INTO kcc20_holders
                (covenant_id, owner_identifier, identifier_type, amount_total,
                 utxo_count, is_minter, last_change_ms)
            VALUES ($1, $2, 0, $3::NUMERIC, 1, FALSE, 1000)
            "#,
        )
        .bind(token)
        .bind(&owner)
        .bind(amount)
        .execute(&pool)
        .await
        .unwrap();
    }

    let page = repo::kcc20_balances_for_owner_paged(&pool, &hex::encode(&owner), 1, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].amount, "100");
    assert_eq!(
        repo::kcc20_balances_for_owner_count(&pool, &hex::encode(&owner))
            .await
            .unwrap(),
        2
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn actions_for_covenant_orders_oldest_first(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;

    insert_action(&pool, &cov, 0xa1, &block, 200, "deploy", None).await;
    insert_action(&pool, &cov, 0xa2, &block, 100, "spend", Some("recover")).await; // earlier
    insert_action(&pool, &cov, 0xa3, &block, 300, "continuation", None).await;

    let rows = repo::actions_for_covenant(&pool, &hex::encode(&cov), 200, 0, false, None, &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    // Oldest first (100, 200, 300 ms)
    assert_eq!(rows[0].action, "spend");
    assert_eq!(rows[0].entrypoint.as_deref(), Some("recover"));
    assert_eq!(rows[1].action, "deploy");
    assert_eq!(rows[2].action, "continuation");

    let newest = repo::actions_for_covenant(&pool, &hex::encode(&cov), 1, 0, true, None, &[])
        .await
        .unwrap();
    assert_eq!(newest[0].action, "continuation");

    let filtered = repo::actions_for_covenant(
        &pool,
        &hex::encode(&cov),
        10,
        0,
        true,
        Some("spend"),
        &["recover".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(
        repo::actions_for_covenant_count(
            &pool,
            &hex::encode(&cov),
            Some("spend"),
            &["recover".to_string()],
        )
        .await
        .unwrap(),
        1
    );
}

// ---------- repo::actions_by_txid ----------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn actions_by_txid_returns_matches(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;
    insert_action(&pool, &cov, 0xbe, &block, 200, "spend", Some("release")).await;
    insert_action(&pool, &cov, 0xff, &block, 200, "deploy", None).await;

    let txid_hex = hex::encode(vec![0xbe_u8; 32]);
    let rows = repo::actions_by_txid(&pool, &txid_hex).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "spend");
    assert_eq!(rows[0].entrypoint.as_deref(), Some("release"));
}

#[sqlx::test(migrations = "./migrations")]
async fn covenants_and_actions_by_address_return_address_scope(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let first = insert_covenant(
        &pool,
        2,
        "kaspatest:pfirst",
        Some("TimeLockVault"),
        &block,
        100,
    )
    .await;
    let second = insert_covenant(&pool, 3, "kaspatest:psecond", Some("Escrow"), &block, 200).await;
    insert_action_with_outputs_and_args(
        &pool,
        &first,
        0xa1,
        &block,
        200,
        "deploy",
        None,
        Some(json!({ "address": "kaspatest:pfirst" })),
        None,
    )
    .await;
    insert_action(&pool, &first, 0xa2, &block, 300, "spend", Some("release")).await;
    insert_action_with_outputs_and_args(
        &pool,
        &second,
        0xa3,
        &block,
        400,
        "deploy",
        None,
        Some(json!({ "address": "kaspatest:pfirst" })),
        None,
    )
    .await;

    let covenants = repo::covenants_by_address(&pool, "kaspatest:pfirst")
        .await
        .unwrap();
    assert_eq!(covenants.len(), 1);
    assert_eq!(covenants[0].template.as_deref(), Some("TimeLockVault"));

    insert_covenant(&pool, 4, "kaspatest:pfirst", Some("Escrow"), &block, 500).await;
    let covenant_page =
        repo::covenants_by_address_with_aliases(&pool, "kaspatest:pfirst", &[], 1, 1)
            .await
            .unwrap();
    assert_eq!(covenant_page.len(), 1);
    assert_eq!(
        repo::covenants_by_address_count(&pool, "kaspatest:pfirst", &[])
            .await
            .unwrap(),
        2
    );

    let actions = repo::actions_by_address(&pool, "kaspatest:pfirst", 10)
        .await
        .unwrap();
    assert_eq!(actions.len(), 3);
    assert_eq!(actions[0].covenant_id_hex, hex::encode(&second));
    assert_eq!(actions[1].entrypoint.as_deref(), Some("release"));
    assert_eq!(actions[2].action, "deploy");
}

#[sqlx::test(migrations = "./migrations")]
async fn active_utxos_by_address_returns_address_scope(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let first = insert_covenant(&pool, 2, "kaspatest:pfirst", Some("Escrow"), &block, 100).await;
    let second = insert_covenant(&pool, 3, "kaspatest:psecond", Some("Escrow"), &block, 200).await;
    insert_active_utxo(&pool, &first, "kaspatest:pfirst", 10_000, &block, 0xa1).await;
    insert_active_utxo(&pool, &first, "kaspatest:pfirst", 5_000, &block, 0xa3).await;
    insert_active_utxo(&pool, &second, "kaspatest:psecond", 20_000, &block, 0xa2).await;

    let rows = repo::active_utxos_by_address(&pool, "kaspatest:pfirst", 1, 1)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].address, "kaspatest:pfirst");
    assert_eq!(rows[0].amount_sompi, 5_000);
    assert_eq!(
        repo::active_utxos_by_address_count(&pool, "kaspatest:pfirst")
            .await
            .unwrap(),
        2
    );
}

// ---------- repo::recent_actions ------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn recent_actions_newest_first_and_limit(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;
    for (i, t) in [100i64, 200, 300, 400, 500].iter().enumerate() {
        insert_action(&pool, &cov, 0x10 + i as u8, &block, *t, "deploy", None).await;
    }

    let rows = repo::recent_actions(&pool, 3, None, None).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].block_time_ms, 500);
    assert_eq!(rows[1].block_time_ms, 400);
    assert_eq!(rows[2].block_time_ms, 300);
}

#[sqlx::test(migrations = "./migrations")]
async fn recent_actions_filters_by_classification(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let inscription = insert_covenant(
        &pool,
        2,
        "kaspatest:pins",
        Some("KRC-721-mint"),
        &block,
        100,
    )
    .await;
    let covenant = insert_covenant(
        &pool,
        3,
        "kaspatest:pcov",
        Some("TimeLockVault"),
        &block,
        200,
    )
    .await;
    sqlx::query(
        "UPDATE covenants SET classification_kind = 'inscription', classification_status = 'matched' WHERE covenant_id = $1",
    )
    .bind(&inscription)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE covenants SET classification_kind = 'covenant', classification_status = 'matched' WHERE covenant_id = $1",
    )
    .bind(&covenant)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(
        &pool,
        &inscription,
        0xa1,
        &block,
        100,
        "spend",
        Some("mint"),
    )
    .await;
    insert_action(
        &pool,
        &covenant,
        0xa2,
        &block,
        200,
        "spend",
        Some("withdraw"),
    )
    .await;

    let rows = repo::recent_actions(&pool, 20, Some("inscription"), Some("matched"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].classification_kind, "inscription");
    assert_eq!(rows[0].entrypoint.as_deref(), Some("mint"));
    assert_eq!(rows[0].inscription_protocol.as_deref(), Some("KRC-721"));
}

// ---------- repo::list_active_utxos --------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn list_active_utxos_skips_spent(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;
    insert_active_utxo(&pool, &cov, "kaspatest:p", 10_000, &block, 0xa1).await;

    // Insert a spent utxo too — should not appear.
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, spent_block, spent_by_txid, status)
           VALUES ($1, 0, $2, $3, 99999, $4, NULL, $5, $5, $1, 'spent')"#,
    )
    .bind(vec![0xbb_u8; 32])
    .bind(&cov)
    .bind("kaspatest:p")
    .bind(vec![0u8; 35])
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::list_active_utxos(&pool, 100, 0).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount_sompi, 10_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_active_utxos_paginates(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let first = insert_covenant(&pool, 2, "kaspatest:pfirst", None, &block, 100).await;
    let second = insert_covenant(&pool, 3, "kaspatest:psecond", None, &block, 200).await;
    insert_active_utxo(&pool, &first, "kaspatest:pfirst", 10_000, &block, 0xa1).await;
    insert_active_utxo(&pool, &second, "kaspatest:psecond", 20_000, &block, 0xa2).await;

    let rows = repo::list_active_utxos(&pool, 1, 1).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount_sompi, 10_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_active_utxos_accepts_covenant_id_or_script_hash(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:pactive", Some("Escrow"), &block, 100).await;
    let canonical = vec![0x77_u8; 32];
    sqlx::query(
        r#"UPDATE covenants SET covenant_id = $1, script_hash = $2 WHERE covenant_id = $2"#,
    )
    .bind(&canonical)
    .bind(&cov)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(&pool, &canonical, "kaspatest:pactive", 12_345, &block, 0xc1).await;

    let by_covenant_id = repo::covenant_active_utxos(
        &pool,
        &hex::encode(&canonical),
        200,
        0,
        None,
        None,
        None,
        false,
    )
    .await
    .unwrap();
    let by_script_hash =
        repo::covenant_active_utxos(&pool, &hex::encode(&cov), 200, 0, None, None, None, false)
            .await
            .unwrap();
    assert_eq!(by_covenant_id.len(), 1);
    assert_eq!(by_script_hash.len(), 1);
    assert_eq!(by_covenant_id[0].amount_sompi, 12_345);
    assert_eq!(by_script_hash[0].amount_sompi, 12_345);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_active_utxos_pages_and_filters_before_materializing(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:pactive", Some("KCC20V2"), &block, 100).await;
    insert_active_utxo(&pool, &cov, "kaspatest:first", 20_000, &block, 0xc1).await;
    insert_active_utxo(&pool, &cov, "kaspatest:second", 10_000, &block, 0xc2).await;
    sqlx::query(
        r#"
        UPDATE covenant_utxos
        SET state = '{"ownerIdentifier":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mode":2}'::jsonb
        WHERE txid = $1
        "#,
    )
    .bind(vec![0xc1_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let owner_rows = repo::covenant_active_utxos(
        &pool,
        &hex::encode(&cov),
        1,
        0,
        None,
        Some(owner),
        Some(2),
        false,
    )
    .await
    .unwrap();
    assert_eq!(owner_rows.len(), 1);
    assert_eq!(owner_rows[0].address, "kaspatest:first");
    assert_eq!(
        repo::covenant_active_utxos_count(
            &pool,
            &hex::encode(&cov),
            None,
            Some(owner),
            Some(2),
            false,
        )
        .await
        .unwrap(),
        1
    );

    let null_state_rows =
        repo::covenant_active_utxos(&pool, &hex::encode(&cov), 1, 0, None, None, None, true)
            .await
            .unwrap();
    assert_eq!(null_state_rows.len(), 1);
    assert_eq!(null_state_rows[0].address, "kaspatest:second");
}

#[sqlx::test(migrations = "./migrations")]
async fn fomo_rounds_return_active_state_and_settled_status(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let active = insert_covenant(
        &pool,
        2,
        "kaspatest:pfomoactive",
        Some("KaspaFomoRound"),
        &block,
        100,
    )
    .await;
    let settled = insert_covenant(
        &pool,
        3,
        "kaspatest:pfomosettled",
        Some("KaspaFomoRound"),
        &block,
        200,
    )
    .await;

    insert_active_utxo_with_state(
        &pool,
        &active,
        "kaspatest:pfomoactive",
        2_600_000_000,
        json!({
            "lastBuyer": "ab".repeat(32),
            "endTimeMs": "1780870388002",
            "ticketCount": "2",
            "modeName": "activeRound"
        }),
        &block,
        0xa1,
    )
    .await;
    insert_action(&pool, &active, 0xb1, &block, 300, "spend", Some("buy")).await;
    insert_action(&pool, &active, 0xb2, &block, 400, "spend", Some("buy")).await;
    insert_action(&pool, &settled, 0xc1, &block, 500, "spend", Some("settle")).await;

    let rounds = repo::fomo_rounds(&pool, false, 10, 0).await.unwrap();
    assert_eq!(rounds.len(), 2);
    assert_eq!(repo::fomo_rounds_count(&pool, false).await.unwrap(), 2);
    assert_eq!(repo::fomo_rounds_count(&pool, true).await.unwrap(), 1);
    let active_round = rounds
        .iter()
        .find(|round| round.covenant_id_hex == hex::encode(&active))
        .unwrap();
    assert_eq!(active_round.status, "active");
    assert_eq!(active_round.pot_sompi.as_deref(), Some("2600000000"));
    assert_eq!(active_round.last_buyer.as_deref().unwrap(), "ab".repeat(32));
    assert_eq!(active_round.end_time_ms.as_deref(), Some("1780870388002"));
    assert_eq!(active_round.ticket_count.as_deref(), Some("2"));
    assert_eq!(active_round.buy_count, 2);

    let settled_round = rounds
        .iter()
        .find(|round| round.covenant_id_hex == hex::encode(&settled))
        .unwrap();
    assert_eq!(settled_round.status, "settled");
    assert!(settled_round.settled_txid_hex.is_some());

    let active_only = repo::fomo_rounds(&pool, true, 10, 0).await.unwrap();
    assert_eq!(active_only.len(), 1);
    assert_eq!(active_only[0].covenant_id_hex, hex::encode(&active));

    let detail = repo::fomo_round_by_id(&pool, &hex::encode(&active))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.status, "active");
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_template_summaries_roll_up_verified_claimed_and_actions(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let verified =
        insert_covenant(&pool, 2, "kaspatest:pverified", Some("Escrow"), &block, 100).await;
    let claimed_only = insert_covenant(&pool, 3, "kaspatest:pclaimed", None, &block, 200).await;
    sqlx::query("UPDATE covenants SET claimed_template = 'Escrow' WHERE covenant_id = $1")
        .bind(&claimed_only)
        .execute(&pool)
        .await
        .unwrap();
    insert_active_utxo(&pool, &verified, "kaspatest:pverified", 10, &block, 0xd1).await;
    insert_active_utxo(&pool, &claimed_only, "kaspatest:pclaimed", 20, &block, 0xd2).await;
    insert_action(&pool, &verified, 0xe1, &block, 300, "deploy", None).await;
    insert_action(&pool, &claimed_only, 0xe2, &block, 400, "deploy", None).await;

    let rows = repo::covenant_template_summaries(&pool).await.unwrap();
    let escrow = rows
        .iter()
        .find(|row| row.template == "Escrow")
        .expect("escrow row");
    assert_eq!(escrow.covenant_count, 2);
    assert_eq!(escrow.verified_count, 1);
    assert_eq!(escrow.claimed_only_count, 1);
    assert_eq!(escrow.active_covenants, 2);
    assert_eq!(escrow.active_utxos, 2);
    assert_eq!(escrow.total_amount_sompi, "30");
    assert_eq!(escrow.action_count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_template_summary_template_move_uses_single_covenant_delta(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant = insert_covenant(&pool, 2, "kaspatest:pmove", None, &block, 100).await;
    insert_active_utxo(&pool, &covenant, "kaspatest:pmove", 25, &block, 0xd1).await;
    insert_action(&pool, &covenant, 0xe1, &block, 300, "deploy", None).await;

    sqlx::query(
        r#"UPDATE covenants
           SET template_name = 'Escrow',
               classification_kind = 'covenant',
               classification_status = 'matched'
           WHERE covenant_id = $1"#,
    )
    .bind(&covenant)
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::covenant_template_summaries(&pool).await.unwrap();
    assert!(rows.iter().all(|row| row.template != "Unknown"));

    let escrow = rows
        .iter()
        .find(|row| row.template == "Escrow")
        .expect("escrow row");
    assert_eq!(escrow.covenant_count, 1);
    assert_eq!(escrow.verified_count, 1);
    assert_eq!(escrow.active_covenants, 1);
    assert_eq!(escrow.active_utxos, 1);
    assert_eq!(escrow.total_amount_sompi, "25");
    assert_eq!(escrow.action_count, 1);
    assert_eq!(escrow.matched_count, 1);
    assert_eq!(escrow.unrevealed_count, 0);
    assert_eq!(escrow.latest_action_time_ms, Some(300));
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_action_summary_inserts_do_not_rebuild_action_history(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant = insert_covenant(
        &pool,
        2,
        "kaspatest:pactionsummary",
        Some("Escrow"),
        &block,
        100,
    )
    .await;

    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION refresh_covenant_action_summary(target_covenant_id BYTEA)
           RETURNS VOID
           LANGUAGE plpgsql
           AS $function$
           BEGIN
               RAISE EXCEPTION 'full action summary rebuild called';
           END;
           $function$"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    insert_action(&pool, &covenant, 0xe1, &block, 100, "spend", Some("first")).await;
    insert_action(&pool, &covenant, 0xe2, &block, 300, "spend", Some("second")).await;

    let (count, latest, summary_xmin): (i64, Option<i64>, i64) = sqlx::query_as(
        r#"SELECT action_count, latest_action_time_ms, xmin::TEXT::BIGINT
           FROM covenant_action_summaries
           WHERE covenant_id = $1"#,
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
    assert_eq!(latest, Some(300));

    sqlx::query(
        r#"UPDATE covenant_actions
           SET outputs = jsonb_build_object('updated', TRUE)
           WHERE covenant_id = $1 AND txid = $2"#,
    )
    .bind(&covenant)
    .bind(vec![0xe1u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let state_only_xmin: i64 = sqlx::query_scalar(
        r#"SELECT xmin::TEXT::BIGINT
           FROM covenant_action_summaries
           WHERE covenant_id = $1"#,
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state_only_xmin, summary_xmin);
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_action_summary_tracks_latest_time_updates_and_deletes(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant = insert_covenant(
        &pool,
        2,
        "kaspatest:pactionsummarychanges",
        Some("Escrow"),
        &block,
        100,
    )
    .await;
    insert_action(&pool, &covenant, 0xe1, &block, 100, "spend", Some("first")).await;
    insert_action(&pool, &covenant, 0xe2, &block, 300, "spend", Some("second")).await;
    insert_action(&pool, &covenant, 0xe3, &block, 300, "spend", Some("third")).await;

    sqlx::query(
        "UPDATE covenant_actions SET block_time_ms = 400 WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&covenant)
    .bind(vec![0xe1u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let (count, latest): (i64, Option<i64>) = sqlx::query_as(
        "SELECT action_count, latest_action_time_ms FROM covenant_action_summaries WHERE covenant_id = $1",
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((count, latest), (3, Some(400)));

    sqlx::query(
        "UPDATE covenant_actions SET block_time_ms = 250 WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&covenant)
    .bind(vec![0xe1u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM covenant_actions WHERE covenant_id = $1 AND txid = $2")
        .bind(&covenant)
        .bind(vec![0xe2u8; 32])
        .execute(&pool)
        .await
        .unwrap();

    let (count, latest): (i64, Option<i64>) = sqlx::query_as(
        "SELECT action_count, latest_action_time_ms FROM covenant_action_summaries WHERE covenant_id = $1",
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((count, latest), (2, Some(300)));

    sqlx::query("DELETE FROM covenant_actions WHERE covenant_id = $1 AND txid = $2")
        .bind(&covenant)
        .bind(vec![0xe3u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    let (count, latest): (i64, Option<i64>) = sqlx::query_as(
        "SELECT action_count, latest_action_time_ms FROM covenant_action_summaries WHERE covenant_id = $1",
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((count, latest), (1, Some(250)));

    sqlx::query("DELETE FROM covenant_actions WHERE covenant_id = $1")
        .bind(&covenant)
        .execute(&pool)
        .await
        .unwrap();
    let (count, latest): (i64, Option<i64>) = sqlx::query_as(
        "SELECT action_count, latest_action_time_ms FROM covenant_action_summaries WHERE covenant_id = $1",
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((count, latest), (0, None));
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_template_action_reorg_delete_is_incremental_and_exact(pool: PgPool) {
    let base_block = insert_block(&pool, 1, 100).await;
    let reverted_block = insert_block(&pool, 2, 200).await;
    let first = insert_covenant(
        &pool,
        3,
        "kaspatest:preorgfirst",
        Some("Escrow"),
        &base_block,
        100,
    )
    .await;
    let second = insert_covenant(
        &pool,
        4,
        "kaspatest:preorgsecond",
        Some("Escrow"),
        &base_block,
        100,
    )
    .await;
    let lottery = insert_covenant(
        &pool,
        5,
        "kaspatest:preorglottery",
        Some("Lottery"),
        &base_block,
        100,
    )
    .await;
    let auction = insert_covenant(
        &pool,
        6,
        "kaspatest:preorgauction",
        Some("Auction"),
        &base_block,
        100,
    )
    .await;
    let concurrent = insert_covenant(
        &pool,
        7,
        "kaspatest:preorgconcurrent",
        Some("Escrow"),
        &base_block,
        100,
    )
    .await;

    insert_action(
        &pool,
        &first,
        0xe1,
        &base_block,
        100,
        "spend",
        Some("first"),
    )
    .await;
    insert_action(
        &pool,
        &second,
        0xe2,
        &base_block,
        250,
        "spend",
        Some("second"),
    )
    .await;
    insert_action(
        &pool,
        &first,
        0xe3,
        &reverted_block,
        300,
        "spend",
        Some("reverted-first"),
    )
    .await;
    insert_action(
        &pool,
        &second,
        0xe4,
        &reverted_block,
        300,
        "spend",
        Some("reverted-second"),
    )
    .await;
    insert_action(
        &pool,
        &lottery,
        0xe5,
        &reverted_block,
        300,
        "spend",
        Some("reverted-lottery"),
    )
    .await;
    insert_action(
        &pool,
        &auction,
        0xe6,
        &base_block,
        400,
        "spend",
        Some("newer-auction"),
    )
    .await;
    insert_action(
        &pool,
        &auction,
        0xe7,
        &reverted_block,
        300,
        "spend",
        Some("reverted-auction"),
    )
    .await;

    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION refresh_covenant_template_summary(target_template TEXT)
           RETURNS VOID
           LANGUAGE plpgsql
           AS $function$
           BEGIN
               RAISE EXCEPTION 'full template summary rebuild called';
           END;
           $function$"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let mut insert_tx = pool.begin().await.unwrap();
    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, 350, 'spend', 'concurrent', NULL, NULL, NULL)"#,
    )
    .bind(&concurrent)
    .bind(vec![0xe8_u8; 32])
    .bind(&base_block)
    .execute(&mut *insert_tx)
    .await
    .unwrap();

    let delete_pool = pool.clone();
    let delete_block = reverted_block.clone();
    let delete_task = tokio::spawn(async move {
        sqlx::query("DELETE FROM covenant_actions WHERE block_hash = $1")
            .bind(delete_block)
            .execute(&delete_pool)
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!delete_task.is_finished());
    insert_tx.commit().await.unwrap();

    let deleted = tokio::time::timeout(Duration::from_secs(2), delete_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(deleted.rows_affected(), 4);

    let (action_count, latest_action_time_ms): (i64, Option<i64>) = sqlx::query_as(
        "SELECT action_count, latest_action_time_ms FROM covenant_template_summaries WHERE template = 'Escrow'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((action_count, latest_action_time_ms), (3, Some(350)));

    let template_states: Vec<(String, i64, Option<i64>)> = sqlx::query_as(
        r#"SELECT template, action_count, latest_action_time_ms
           FROM covenant_template_summaries
           WHERE template IN ('Auction', 'Lottery')
           ORDER BY template"#,
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        template_states,
        vec![
            ("Auction".to_string(), 1, Some(400)),
            ("Lottery".to_string(), 0, None),
        ]
    );

    let mut action_delete_tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM covenant_actions WHERE covenant_id = $1")
        .bind(&concurrent)
        .execute(&mut *action_delete_tx)
        .await
        .unwrap();

    let parent_delete_pool = pool.clone();
    let parent_delete_covenant = concurrent.clone();
    let parent_delete_task = tokio::spawn(async move {
        sqlx::query("DELETE FROM covenants WHERE covenant_id = $1")
            .bind(parent_delete_covenant)
            .execute(&parent_delete_pool)
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!parent_delete_task.is_finished());
    action_delete_tx.commit().await.unwrap();
    let parent_deleted = tokio::time::timeout(Duration::from_secs(2), parent_delete_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(parent_deleted.rows_affected(), 1);

    let escrow_after_parent_delete: (i64, i64, Option<i64>) = sqlx::query_as(
        r#"SELECT covenant_count, action_count, latest_action_time_ms
           FROM covenant_template_summaries
           WHERE template = 'Escrow'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(escrow_after_parent_delete, (2, 2, Some(250)));

    let trigger_definition: String = sqlx::query_scalar(
        r#"SELECT pg_get_triggerdef(oid)
           FROM pg_trigger
           WHERE tgrelid = 'covenant_actions'::regclass
             AND tgname = 'covenant_actions_refresh_template_summary_delete'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(trigger_definition.contains("REFERENCING OLD TABLE AS deleted_actions"));
    assert!(trigger_definition.contains("FOR EACH STATEMENT"));

    let row_trigger_definition: String = sqlx::query_scalar(
        r#"SELECT pg_get_triggerdef(oid)
           FROM pg_trigger
           WHERE tgrelid = 'covenant_actions'::regclass
             AND tgname = 'covenant_actions_refresh_template_summary'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!row_trigger_definition.contains("DELETE"));

    let function_definition: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('refresh_covenant_template_summary_from_action_delete_statement()'::regprocedure)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(function_definition.contains("FOR UPDATE OF summary"));
}

#[sqlx::test(migrations = "./migrations")]
async fn explorer_search_resolves_core_indexer_targets(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant =
        insert_covenant(&pool, 2, "kaspatest:psearch", Some("Escrow"), &block, 100).await;
    let utxo_address = "kaspatest:psearch-current";
    insert_active_utxo(&pool, &covenant, utxo_address, 10, &block, 0xd1).await;
    insert_action(&pool, &covenant, 0xe1, &block, 300, "deploy", None).await;

    let token_id = vec![0x44; 32];
    let wrapper_id = vec![0x45; 32];
    sqlx::query(
        r#"INSERT INTO kcc20_token_summaries
           (token_id, holder_count, holder_supply, remaining_supply, wrapper_reserve_supply,
            orderbook_tradeable_supply, top_holders, wrapper_id, refreshed_at_ms, source_blue_score)
           VALUES ($1, 2, '100'::NUMERIC, '0'::NUMERIC, '0'::NUMERIC,
                   '1'::NUMERIC, '[]'::jsonb, $2, 1778654400300, 100)"#,
    )
    .bind(&token_id)
    .bind(&wrapper_id)
    .execute(&pool)
    .await
    .unwrap();

    let by_covenant = repo::explorer_search(&pool, &hex::encode(&covenant), 10)
        .await
        .unwrap();
    assert!(by_covenant.iter().any(|row| row.kind == "covenant"
        && row.path == format!("/covenants/{}", hex::encode(&covenant))));

    let by_tx = repo::explorer_search(&pool, &hex::encode(vec![0xe1; 32]), 10)
        .await
        .unwrap();
    assert!(by_tx.iter().any(|row| row.kind == "transaction"
        && row.path == format!("/tx/{}", hex::encode(vec![0xe1; 32]))));

    let by_address = repo::explorer_search(&pool, "kaspatest:psearch", 10)
        .await
        .unwrap();
    assert!(by_address.iter().any(|row| row.kind == "covenant"
        && row.path == format!("/covenants/{}", hex::encode(&covenant))));

    let by_utxo_address = repo::explorer_search(&pool, utxo_address, 10)
        .await
        .unwrap();
    assert!(by_utxo_address
        .iter()
        .any(|row| row.kind == "address" && row.path == format!("/addresses/{utxo_address}")));
    let (utxo_address_rows, utxo_address_total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(utxo_address),
        None,
        Some("recent"),
        Some(10),
        None,
    )
    .await
    .unwrap();
    assert_eq!(utxo_address_total, 1);
    assert_eq!(utxo_address_rows[0].covenant_id_hex, hex::encode(&covenant));
    let address_utxos = repo::active_utxos_by_address(&pool, utxo_address, 10, 0)
        .await
        .unwrap();
    assert_eq!(address_utxos[0].amount_sompi_exact, "10");
    assert_eq!(
        repo::active_utxos_by_address_count(&pool, utxo_address)
            .await
            .unwrap(),
        1
    );

    let participant = "kaspatest:qparticipant";
    let mut newest_participant_covenant = Vec::new();
    let mut oldest_participant_covenant = Vec::new();
    for i in 0..12 {
        let participant_covenant = insert_covenant(
            &pool,
            20 + i,
            &format!("kaspatest:participant-vault-{i}"),
            Some("WalletVault"),
            &block,
            1_000 + i as i64,
        )
        .await;
        sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
            .bind(&participant_covenant)
            .bind(json!({
                "args": [
                    { "name": "signer", "type": "address", "value": participant }
                ]
            }))
            .execute(&pool)
            .await
            .unwrap();
        if i == 0 {
            oldest_participant_covenant = participant_covenant.clone();
        }
        if i == 11 {
            newest_participant_covenant = participant_covenant;
        }
    }

    let by_participant = repo::explorer_search(&pool, participant, 10).await.unwrap();
    assert!(by_participant.iter().any(|row| row.kind == "covenant"
        && row.path == format!("/covenants/{}", hex::encode(&newest_participant_covenant))));
    assert!(!by_participant.iter().any(|row| row.kind == "covenant"
        && row.path == format!("/covenants/{}", hex::encode(&oldest_participant_covenant))));

    let by_template = repo::explorer_search(&pool, "Escrow", 10).await.unwrap();
    assert!(by_template
        .iter()
        .any(|row| row.kind == "template" && row.path == "/covenants?template=Escrow"));

    let by_wrapper = repo::explorer_search(&pool, &hex::encode(&wrapper_id), 10)
        .await
        .unwrap();
    assert!(
        by_wrapper
            .iter()
            .any(|row| row.kind == "kcc20"
                && row.path == format!("/kcc20/{}", hex::encode(&token_id)))
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn address_utxo_page_preserves_exact_amounts_and_total(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let address = "kaspatest:pexact-address-summary";
    let first = insert_covenant(&pool, 2, "kaspatest:pfirst", Some("Escrow"), &block, 100).await;
    let second = insert_covenant(&pool, 3, "kaspatest:psecond", Some("Escrow"), &block, 200).await;
    insert_active_utxo(&pool, &first, address, 9_007_199_254_740_993, &block, 0xd2).await;
    insert_active_utxo(&pool, &second, address, 7, &block, 0xd3).await;

    let (rows, total) = repo::active_utxos_by_address_page(&pool, address, 1, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].amount_sompi_exact, "9007199254740993");
    assert_eq!(total, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_holders_orders_by_token_amount(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:kcc20", Some("KCC20"), &block, 100).await;
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES ($1, $2, 0, '100'::NUMERIC, 1, FALSE, 1000),
                  ($1, $3, 2, '900'::NUMERIC, 2, FALSE, 2000)"#,
    )
    .bind(&cov)
    .bind(vec![0x11_u8; 32])
    .bind(vec![0x22_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::kcc20_holders(&pool, &hex::encode(&cov), 200, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].owner_identifier, "22".repeat(32));
    assert_eq!(rows[0].identifier_type_name, "p2pkh-ecdsa/v1");
    assert_eq!(rows[0].amount, "900");
    assert_eq!(rows[0].utxo_count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_active_utxos_report_each_output_script_hash(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let output_script_hash = vec![0x44_u8; 32];
    insert_active_utxo_with_script_hash(
        &pool,
        &token,
        "kaspatest:out",
        50_000_000,
        &output_script_hash,
        &block,
        0xa4,
    )
    .await;

    let rows =
        repo::kcc20_active_utxos(&pool, &hex::encode(&token), 200, 0, None, None, None, false)
            .await
            .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].covenant_id_hex, hex::encode(&token));
    assert_eq!(rows[0].script_hash_hex, hex::encode(&output_script_hash));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_market_discovery_reads_summary_with_db_pagination_and_token_filter(pool: PgPool) {
    let low_volume = insert_market_summary(&pool, 0x01, "500", 1, Some(1000)).await;
    let high_volume = insert_market_summary(&pool, 0x02, "1000000", 2, Some(2000)).await;
    for tag in 0x03..=0x0c {
        insert_market_summary(
            &pool,
            tag,
            &(10_000_i64 - tag as i64).to_string(),
            tag as i64,
            Some(3000 + tag as i64),
        )
        .await;
    }

    let page = repo::kcc20_market_discovery(&pool, None, "totalVolumeSompi", "desc", 5, 0, true)
        .await
        .unwrap();

    assert_eq!(page.items.len(), 5);
    assert_eq!(page.total, Some(12));
    assert_eq!(page.freshness.row_count, 12);
    assert_eq!(page.items[0].token_id_hex, hex::encode(&high_volume));
    assert!(!page
        .items
        .iter()
        .any(|row| row.token_id_hex == hex::encode(&low_volume)));

    let filtered = repo::kcc20_market_discovery(
        &pool,
        Some(&hex::encode(&low_volume)),
        "totalVolumeSompi",
        "desc",
        5,
        0,
        true,
    )
    .await
    .unwrap();
    assert_eq!(filtered.items.len(), 1);
    assert_eq!(filtered.total, Some(1));
    assert_eq!(filtered.items[0].token_id_hex, hex::encode(&low_volume));

    let missing = repo::kcc20_market_discovery(
        &pool,
        Some(&"ff".repeat(32)),
        "totalVolumeSompi",
        "desc",
        5,
        0,
        true,
    )
    .await
    .unwrap();
    assert!(missing.items.is_empty());
    assert_eq!(missing.total, Some(0));

    let no_total =
        repo::kcc20_market_discovery(&pool, None, "totalVolumeSompi", "desc", 5, 0, false)
            .await
            .unwrap();
    assert_eq!(no_total.total, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn token_summary_computes_wrapper_supply_once_for_many_tokens(pool: PgPool) {
    let block = insert_block(&pool, 0x01, 100).await;
    let owner = vec![0xf0_u8; 32];
    let mut tokens = Vec::new();
    for tag in 0x10_u8..0x30 {
        let token = insert_covenant(
            &pool,
            tag,
            &format!("kaspatest:summary-plan-{tag}"),
            Some("KCC20V2"),
            &block,
            100,
        )
        .await;
        sqlx::query(
            "INSERT INTO kcc20_holders \
             (covenant_id, owner_identifier, identifier_type, amount_total, \
              utxo_count, is_minter, last_change_ms) \
             VALUES ($1, $2, 0, 1000, 1, FALSE, 1000)",
        )
        .bind(&token)
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
        tokens.push(token);
    }
    for (tag, reserve, tradeable) in [(0x80_u8, 30_i64, 100_i64), (0x81, 40, 200), (0x82, 50, 200)]
    {
        let wrapper = insert_covenant(
            &pool,
            tag,
            &format!("kaspatest:wrapper-plan-{tag}"),
            Some("KCC20Wrapper"),
            &block,
            100,
        )
        .await;
        sqlx::query(
            "INSERT INTO kcc20_wrapper_summaries \
             (wrapper_id, canonical_token_id, refreshed_at_ms) VALUES ($1, $2, 1000)",
        )
        .bind(&wrapper)
        .bind(&tokens[0])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO kcc20_holders \
             (covenant_id, owner_identifier, identifier_type, amount_total, \
              utxo_count, is_minter, last_change_ms) VALUES \
             ($1, $2, 4, $3, 1, FALSE, 1000), \
             ($2, $4, 0, $5, 1, FALSE, 1000)",
        )
        .bind(&tokens[0])
        .bind(&wrapper)
        .bind(reserve)
        .bind(&owner)
        .bind(tradeable)
        .execute(&pool)
        .await
        .unwrap();
    }

    repo::refresh_kcc20_token_summaries(&pool).await.unwrap();
    let summary = repo::kcc20_token_summary(&pool, &hex::encode(&tokens[0]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.holder_supply, "1120");
    assert_eq!(summary.wrapper_reserve_supply, "0");
    assert_eq!(summary.orderbook_tradeable_supply, "0");
    assert!(summary.wrapper_id_hex.is_none(), "competing markets must not select an arbitrary winner");
    let unwrapped = repo::kcc20_token_summary(&pool, &hex::encode(&tokens[1]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unwrapped.wrapper_reserve_supply, "0");
    assert_eq!(unwrapped.orderbook_tradeable_supply, "0");
    assert!(unwrapped.wrapper_id_hex.is_none());

    // Explain the same INSERT used by the public refresh function, rather
    // than a simplified query that could miss per-token recomputation.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL jit = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let explain = concat!(
        "EXPLAIN (ANALYZE, FORMAT JSON) ",
        include_str!("../src/queries/kcc20_token_summaries.sql")
    );
    let plan: serde_json::Value = sqlx::query_scalar(explain)
        .bind(serde_json::json!([]))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    fn wrapper_supply_loops(node: &serde_json::Value, loops: &mut Vec<u64>) {
        if node["Subplan Name"].as_str() == Some("CTE wrapper_supply") {
            loops.push(node["Actual Loops"].as_u64().unwrap());
        }
        for child in node["Plans"].as_array().into_iter().flatten() {
            wrapper_supply_loops(child, loops);
        }
    }
    let mut loops = Vec::new();
    wrapper_supply_loops(&plan[0]["Plan"], &mut loops);
    assert_eq!(
        loops,
        vec![1],
        "wrapper supply must be computed once per refresh"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_token_page_projections_materialize_wrapper_supply_and_activity(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        0x31,
        "kaspatest:ptoken",
        Some("KCC20V2"),
        &block,
        100,
    )
    .await;
    let decoded_wrong_token = vec![0x39; 32];
    let wrapper = insert_covenant(
        &pool,
        0x32,
        "kaspatest:pwrapper",
        Some("KCC20Wrapper"),
        &block,
        101,
    )
    .await;
    let native_wrapper = vec![0x35; 32];
    let owner = vec![0x77; 32];
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "canonicalTokenId": hex::encode(&decoded_wrong_token),
        "feeTicketId": "00".repeat(32),
        "wrappedRootAmount": "1",
        "initEnabled": true
    }))
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(
        &pool,
        &wrapper,
        "kaspatest:pwrapper",
        100_000_000,
        &block,
        0x33,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:pwrapped-holder",
        50_000_000,
        json!({
            "canonicalTokenId": hex::encode(&token),
            "ownerIdentifier": hex::encode(&owner),
            "identifierType": 0,
            "amount": "7",
            "mode": 0,
            "wrapperCovenantId": hex::encode(&native_wrapper),
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &block,
        0x35,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES
           ($1, $2, 0, 500::NUMERIC, 1, FALSE, 1000),
           ($1, $3, 4, 3::NUMERIC, 1, FALSE, 1001),
           ($4, $2, 0, 7::NUMERIC, 1, FALSE, 1002)"#,
    )
    .bind(&token)
    .bind(&owner)
    .bind(&native_wrapper)
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();
    insert_action_with_outputs_and_args(
        &pool,
        &wrapper,
        0x34,
        &block,
        2000,
        "spend",
        Some("wrap"),
        Some(json!({
            "state": {
                "ownerIdentifier": hex::encode(&owner),
                "amount": "7",
                "canonicalTokenId": hex::encode(&decoded_wrong_token)
            }
        })),
        Some(json!({
            "canonicalTokenId": hex::encode(&decoded_wrong_token),
            "tokenAmount": "7"
        })),
    )
    .await;
    sqlx::query(
        r#"UPDATE covenant_actions
           SET canonical_token_id = $1
           WHERE covenant_id = $2"#,
    )
    .bind(&decoded_wrong_token)
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();
    repo::refresh_kcc20_token_page_projections(&pool)
        .await
        .unwrap();

    let wrappers =
        repo::kcc20_wrapper_summaries_by_canonical(&pool, &hex::encode(&token), true, 200, 0)
            .await
            .unwrap();
    assert_eq!(wrappers.len(), 1);
    assert_eq!(wrappers[0].wrapper_id_hex, hex::encode(&wrapper));

    let wrong_wrappers = repo::kcc20_wrapper_summaries_by_canonical(
        &pool,
        &hex::encode(&decoded_wrong_token),
        true,
        200,
        0,
    )
    .await
    .unwrap();
    assert!(wrong_wrappers.is_empty());

    let summary = repo::kcc20_token_summary(&pool, &hex::encode(&token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(summary.holder_supply, "503");
    assert_eq!(summary.wrapper_reserve_supply, "3");
    assert_eq!(summary.orderbook_tradeable_supply, "7");
    assert_eq!(summary.holder_count, 2);

    let repaired_action_token: String = sqlx::query_scalar(
        "SELECT encode(canonical_token_id, 'hex') FROM covenant_actions WHERE covenant_id = $1",
    )
    .bind(&wrapper)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(repaired_action_token, hex::encode(&token));

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &hex::encode(&token), 10, 0)
        .await
        .unwrap();
    assert!(activity
        .iter()
        .any(|row| row.kind == "wrap" && row.token_amount.as_deref() == Some("7")));
    let wrapper_activity = repo::kcc20_activity(&pool, &hex::encode(&wrapper), 10, 0)
        .await
        .unwrap();
    assert!(wrapper_activity.iter().any(|row| {
        row.token_id_hex == hex::encode(&token)
            && row.kind == "wrap"
            && row.token_amount.as_deref() == Some("7")
    }));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_wrapper_summaries_page_and_count_before_materializing(pool: PgPool) {
    let canonical = vec![0x81_u8; 32];
    for (tag, active_utxos, pending_reveal) in [
        (0x82_u8, 30_i64, false),
        (0x83_u8, 20_i64, false),
        (0x84_u8, 10_i64, true),
    ] {
        sqlx::query(
            r#"
            INSERT INTO kcc20_wrapper_summaries
                (wrapper_id, canonical_token_id, active_utxos, pending_reveal, refreshed_at_ms)
            VALUES ($1, $2, $3, $4, 1000)
            "#,
        )
        .bind(vec![tag; 32])
        .bind(&canonical)
        .bind(active_utxos)
        .bind(pending_reveal)
        .execute(&pool)
        .await
        .unwrap();
    }

    let rows = repo::kcc20_wrapper_summaries(&pool, true, 1, 1)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].active_utxos, 20);
    assert_eq!(
        repo::kcc20_wrapper_summaries_count(&pool, true)
            .await
            .unwrap(),
        3
    );

    let canonical_rows =
        repo::kcc20_wrapper_summaries_by_canonical(&pool, &hex::encode(&canonical), false, 1, 1)
            .await
            .unwrap();
    assert_eq!(canonical_rows.len(), 1);
    assert_eq!(canonical_rows[0].active_utxos, 20);
    assert_eq!(
        repo::kcc20_wrapper_summaries_by_canonical_count(&pool, &hex::encode(&canonical), false,)
            .await
            .unwrap(),
        2
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_wrapper_lifecycle_activity_dedupes_internal_native_continuations(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        0x71,
        "kaspatest:pdedupe-token",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    let wrapper = insert_covenant(
        &pool,
        0x72,
        "kaspatest:pdedupe-wrapper",
        Some("KCC20Wrapper"),
        &block,
        101,
    )
    .await;
    let token_hex = hex::encode(&token);
    let wrapper_hex = hex::encode(&wrapper);
    let owner = "73".repeat(32);

    for (txid_seed, entrypoint, amount) in [(0x74, "wrap", "40"), (0x75, "unwrap", "15")] {
        let wrapper_args = if entrypoint == "wrap" {
            json!({
                "canonicalTokenId": token_hex.clone(),
                "ownerIdentifier": owner.clone(),
                "tokenAmount": amount,
                "tokenInputIndex": "1",
                "tokenLockedOutputIndex": "2",
                "orderbookHolderOutputIndex": "4",
                "wrapperOutputIndex": "6"
            })
        } else {
            json!({
                "canonicalTokenId": token_hex.clone(),
                "ownerIdentifier": owner.clone(),
                "tokenAmount": amount,
                "wrappedInputIndex": "1",
                "tokenReserveInputIndex": "2",
                "tokenRecipientOutputIndex": "2",
                "tokenReserveChangeOutputIndex": "3",
                "wrappedChangeOutputIndex": "4",
                "wrapperOutputIndex": "6"
            })
        };
        if entrypoint == "unwrap" {
            insert_action_full(
                &pool,
                // Wrapper and wrapped-holder states share one covenant family
                // in production, so the covenants row is classified as the
                // wrapper even though this input runs a wrapped entrypoint.
                &wrapper,
                txid_seed,
                &block,
                1778654400100 + i64::from(txid_seed),
                "spend",
                Some("unwrapByOwnerSig"),
                None,
                None,
                Some(json!({
                    "canonicalTokenId": token_hex.clone(),
                    "ownerIdentifier": owner.clone(),
                    // Partial unwrap: 25 input - 15 unwrapped = 10 change.
                    "amount": "25",
                    "tokenAmount": amount,
                    "inputIndex": "1"
                })),
            )
            .await;
        }
        insert_action_full(
            &pool,
            &wrapper,
            txid_seed,
            &block,
            1778654400100 + i64::from(txid_seed),
            "spend",
            Some(entrypoint),
            Some(json!({
                "previousOutpoint": {
                    "hash": repeated_seed_hex(txid_seed - 1),
                    "index": "0"
                }
            })),
            None,
            Some(wrapper_args),
        )
        .await;
        insert_action_full(
            &pool,
            &token,
            txid_seed,
            &block,
            1778654400100 + i64::from(txid_seed),
            "spend",
            Some("transfer"),
            None,
            None,
            Some(json!({
                "inputIndex": if entrypoint == "wrap" { "1" } else { "2" },
                "tokenAmount": amount,
                "tokenOutputIndex": "2",
                "changeOutputIndex": "3"
            })),
        )
        .await;
        insert_action_with_outputs_and_args(
            &pool,
            &token,
            txid_seed,
            &block,
            1778654400100 + i64::from(txid_seed),
            "continuation",
            None,
            Some(json!({
                "vout": 2,
                "state": {
                    "owner": if entrypoint == "wrap" { wrapper_hex.clone() } else { owner.clone() },
                    "ownerScheme": if entrypoint == "wrap" { 4 } else { 0 },
                    "amount": amount
                }
            })),
            None,
        )
        .await;
        insert_action_with_outputs_and_args(
            &pool,
            &token,
            txid_seed,
            &block,
            1778654400100 + i64::from(txid_seed),
            "continuation",
            None,
            Some(json!({
                "vout": 3,
                "state": {
                    "owner": if entrypoint == "wrap" { owner.clone() } else { wrapper_hex.clone() },
                    "ownerScheme": if entrypoint == "wrap" { 0 } else { 4 },
                    "amount": if entrypoint == "wrap" { "60" } else { "85" }
                }
            })),
            None,
        )
        .await;
        insert_action_with_outputs_and_args(
            &pool,
            &wrapper,
            txid_seed,
            &block,
            1778654400100 + i64::from(txid_seed),
            "continuation",
            None,
            Some(json!({
                "vout": 4,
                "state": {
                    "canonicalTokenId": token_hex.clone(),
                    "ownerIdentifier": owner.clone(),
                    "amount": if entrypoint == "wrap" { amount } else { "10" },
                    "mode": 0,
                    "modeName": "holder",
                    "unitPriceSompi": "0"
                }
            })),
            None,
        )
        .await;
        if entrypoint == "wrap" {
            insert_action_with_outputs_and_args(
                &pool,
                &wrapper,
                txid_seed,
                &block,
                1778654400100 + i64::from(txid_seed),
                "continuation",
                None,
                Some(json!({
                    "vout": 0,
                    "state": {
                        "canonicalTokenId": token_hex.clone(),
                        "ownerIdentifier": owner.clone(),
                        "amount": amount,
                        "mode": 0
                    }
                })),
                None,
            )
            .await;
        }
    }

    // A transaction may batch an unrelated transfer of the same canonical
    // token. The wrapper-validated output index is internal; the other output
    // must remain visible as a transfer.
    let batched_txid_seed = 0x78;
    insert_action_full(
        &pool,
        &wrapper,
        batched_txid_seed,
        &block,
        1778654400250,
        "spend",
        Some("wrap"),
        None,
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": owner.clone(),
            "tokenAmount": "40",
            "tokenInputIndex": "1",
            "tokenLockedOutputIndex": "2"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &token,
        batched_txid_seed,
        &block,
        1778654400250,
        "spend",
        Some("transfer"),
        None,
        None,
        Some(json!({"inputIndex": "1", "tokenOutputIndex": "2"})),
    )
    .await;
    insert_action_full(
        &pool,
        &token,
        batched_txid_seed,
        &block,
        1778654400250,
        "spend",
        Some("mint_public"),
        None,
        None,
        Some(json!({"inputIndex": "4", "tokenOutputIndex": "9"})),
    )
    .await;
    for (vout, output_owner, amount) in [(2, wrapper_hex.clone(), "40"), (9, owner.clone(), "7")] {
        insert_action_with_outputs_and_args(
            &pool,
            &token,
            batched_txid_seed,
            &block,
            1778654400250,
            "continuation",
            None,
            Some(json!({
                "vout": vout,
                "state": {
                    "owner": output_owner,
                    "ownerScheme": 0,
                    "amount": amount
                }
            })),
            None,
        )
        .await;
    }

    // Only the wrapped input named by the wrapper is an internal leg. A
    // second same-token unwrapByOwnerSig spend in the transaction remains a
    // visible (even if economically unusual) burn/unwrap event.
    let batched_unwrap_txid_seed = 0x79;
    insert_action_full(
        &pool,
        &wrapper,
        batched_unwrap_txid_seed,
        &block,
        1778654400275,
        "spend",
        Some("unwrap"),
        None,
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": owner.clone(),
            "tokenAmount": "10",
            "wrappedInputIndex": "1",
            "tokenReserveInputIndex": "2",
            "tokenRecipientOutputIndex": "2",
            "tokenReserveChangeOutputIndex": "3"
        })),
    )
    .await;
    for input_index in ["1", "4"] {
        let unrelated = input_index == "4";
        insert_action_full(
            &pool,
            &wrapper,
            batched_unwrap_txid_seed,
            &block,
            1778654400275,
            "spend",
            Some("unwrapByOwnerSig"),
            None,
            None,
            Some(json!({
                "canonicalTokenId": token_hex.clone(),
                "ownerIdentifier": owner.clone(),
                "amount": if unrelated { "11" } else { "10" },
                "tokenAmount": if unrelated { "11" } else { "10" },
                "inputIndex": input_index
            })),
        )
        .await;
    }
    insert_action_full(
        &pool,
        &token,
        batched_unwrap_txid_seed,
        &block,
        1778654400275,
        "spend",
        Some("transfer_delegator"),
        None,
        None,
        Some(json!({
            "inputIndex": "2",
            "tokenAmount": "10",
            "tokenOutputIndex": "2",
            "changeOutputIndex": "3"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        batched_unwrap_txid_seed,
        &block,
        1778654400275,
        "continuation",
        None,
        Some(json!({
            "vout": 2,
            "state": {"owner": owner.clone(), "ownerScheme": 0, "amount": "10"}
        })),
        None,
    )
    .await;

    let transfer_txid_seed = 0x76;
    insert_action_full(
        &pool,
        &token,
        transfer_txid_seed,
        &block,
        1778654400300,
        "spend",
        Some("transfer"),
        None,
        None,
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        transfer_txid_seed,
        &block,
        1778654400300,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "owner": owner.clone(),
                "ownerScheme": 0,
                "amount": "9"
            }
        })),
        None,
    )
    .await;
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    for (txid_seed, kind, amount) in [
        (0x74, "wrap", "40"),
        (0x75, "unwrap", "15"),
        (transfer_txid_seed, "transfer", "9"),
    ] {
        let activity = repo::kcc20_activity_filtered(
            &pool,
            &token_hex,
            &repo::Kcc20ActivityFilter {
                txid: Some(repeated_seed_hex(txid_seed)),
                ..Default::default()
            },
            10,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            activity.len(),
            1,
            "projected {kind} activity must be unique"
        );
        assert_eq!(activity[0].kind, kind);
        assert_eq!(activity[0].token_amount.as_deref(), Some(amount));
        if kind == "wrap" || kind == "unwrap" {
            assert_eq!(activity[0].entrypoint.as_deref(), Some(kind));
            assert_eq!(activity[0].owner.as_deref(), Some(owner.as_str()));
        }
    }

    let batched_activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            txid: Some(repeated_seed_hex(batched_txid_seed)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(batched_activity.len(), 2);
    assert!(batched_activity.iter().any(|row| row.kind == "wrap"));
    assert!(batched_activity
        .iter()
        .any(|row| row.kind == "mint" && row.token_amount.as_deref() == Some("7")));

    let batched_unwrap_activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            txid: Some(repeated_seed_hex(batched_unwrap_txid_seed)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(batched_unwrap_activity.len(), 2);
    assert!(batched_unwrap_activity
        .iter()
        .all(|row| row.kind == "unwrap"));
    assert_eq!(
        batched_unwrap_activity
            .iter()
            .filter(|row| row.entrypoint.as_deref() == Some("unwrapByOwnerSig"))
            .count(),
        1
    );
    assert!(batched_unwrap_activity.iter().any(|row| {
        row.entrypoint.as_deref() == Some("unwrapByOwnerSig")
            && row.token_amount.as_deref() == Some("11")
    }));

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();

    for (txid_seed, kind, amount) in [
        (0x74, "wrap", "40"),
        (0x75, "unwrap", "15"),
        (transfer_txid_seed, "transfer", "9"),
    ] {
        let activity = repo::kcc20_activity_filtered(
            &pool,
            &token_hex,
            &repo::Kcc20ActivityFilter {
                txid: Some(repeated_seed_hex(txid_seed)),
                ..Default::default()
            },
            10,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            activity.len(),
            1,
            "materialized {kind} activity must be unique"
        );
        assert_eq!(activity[0].kind, kind);
        assert_eq!(activity[0].token_amount.as_deref(), Some(amount));
    }

    let batched_activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            txid: Some(repeated_seed_hex(batched_txid_seed)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(batched_activity.len(), 2);
    assert!(batched_activity.iter().any(|row| row.kind == "wrap"));
    assert!(batched_activity
        .iter()
        .any(|row| row.kind == "mint" && row.token_amount.as_deref() == Some("7")));

    let batched_unwrap_activity = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            txid: Some(repeated_seed_hex(batched_unwrap_txid_seed)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(batched_unwrap_activity.len(), 2);
    assert_eq!(
        batched_unwrap_activity
            .iter()
            .filter(|row| row.entrypoint.as_deref() == Some("unwrapByOwnerSig"))
            .count(),
        1
    );
    assert!(batched_unwrap_activity.iter().any(|row| {
        row.entrypoint.as_deref() == Some("unwrapByOwnerSig")
            && row.token_amount.as_deref() == Some("11")
    }));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_wrapper_lifecycle_activity_handles_batched_owners_and_source_duplicates(
    pool: PgPool,
) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        0x81,
        "kaspatest:plifecycle-token",
        Some("KCC20V2"),
        &block,
        100,
    )
    .await;
    let wrapper = insert_covenant(
        &pool,
        0x82,
        "kaspatest:plifecycle-wrapper",
        Some("KCC20Wrapper"),
        &block,
        101,
    )
    .await;
    let duplicate_wrapper = insert_covenant(
        &pool,
        0x83,
        "kaspatest:plifecycle-wrapper-duplicate",
        Some("KCC20Wrapper"),
        &block,
        102,
    )
    .await;
    let other_wrapper = insert_covenant(
        &pool,
        0x84,
        "kaspatest:plifecycle-wrapper-other",
        Some("KCC20Wrapper"),
        &block,
        103,
    )
    .await;
    let token_hex = hex::encode(&token);
    let recipient = "85".repeat(32);
    let stale_owner = "86".repeat(32);
    let unrelated_holder = "87".repeat(32);

    let wrap_txid_seed = 0x88;
    let wrap_input = json!({
        "previousOutpoint": {
            "hash": repeated_seed_hex(0x89),
            "index": "0"
        }
    });
    for lifecycle_wrapper in [&wrapper, &duplicate_wrapper] {
        insert_action_full(
            &pool,
            lifecycle_wrapper,
            wrap_txid_seed,
            &block,
            1778654400400,
            "spend",
            Some("wrap"),
            Some(wrap_input.clone()),
            None,
            Some(json!({
                "canonicalTokenId": token_hex.clone(),
                "ownerIdentifier": stale_owner.clone(),
                "wrappedRecipient": recipient.clone(),
                "tokenAmount": "5",
                "tokenInputIndex": "1",
                "tokenLockedOutputIndex": "2",
                "orderbookHolderOutputIndex": "9",
                "wrapperOutputIndex": "10"
            })),
        )
        .await;
    }
    insert_action_with_outputs_and_args(
        &pool,
        &wrapper,
        wrap_txid_seed,
        &block,
        1778654400400,
        "continuation",
        None,
        Some(json!({
            "vout": 9,
            "state": {
                "canonicalTokenId": token_hex.clone(),
                "ownerIdentifier": unrelated_holder.clone(),
                "amount": "999",
                "mode": 0
            }
        })),
        None,
    )
    .await;

    let unwrap_txid_seed = 0x8a;
    insert_action_full(
        &pool,
        &wrapper,
        unwrap_txid_seed,
        &block,
        1778654400500,
        "spend",
        Some("unwrap"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0x8b),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": stale_owner.clone(),
            "tokenRecipient": recipient.clone(),
            "tokenAmount": "4",
            "wrappedInputIndex": "1",
            "tokenReserveInputIndex": "2",
            "tokenRecipientOutputIndex": "0",
            "tokenReserveChangeOutputIndex": "1",
            "wrappedChangeOutputIndex": "9",
            "wrapperOutputIndex": "10"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        unwrap_txid_seed,
        &block,
        1778654400500,
        "spend",
        Some("unwrapByOwnerSig"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0x8c),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": unrelated_holder.clone(),
            "tokenAmount": "4",
            "inputIndex": "1"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &wrapper,
        unwrap_txid_seed,
        &block,
        1778654400500,
        "continuation",
        None,
        Some(json!({
            "vout": 9,
            "state": {
                "canonicalTokenId": token_hex.clone(),
                "ownerIdentifier": unrelated_holder.clone(),
                "amount": "995",
                "mode": 0
            }
        })),
        None,
    )
    .await;

    // A legacy wrapper action with no wrappedInputIndex must not consume an
    // unwrap authorization from another wrapper family merely because the
    // canonical token and transaction match.
    let cross_family_txid_seed = 0x8d;
    insert_action_full(
        &pool,
        &wrapper,
        cross_family_txid_seed,
        &block,
        1778654400600,
        "spend",
        Some("unwrap"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0x8e),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": recipient.clone(),
            "tokenAmount": "3"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &other_wrapper,
        cross_family_txid_seed,
        &block,
        1778654400600,
        "spend",
        Some("unwrapByOwnerSig"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0x8f),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": recipient.clone(),
            "tokenAmount": "3",
            "inputIndex": "1"
        })),
    )
    .await;

    // The same legacy fallback remains valid inside one wrapper family when
    // there is exactly one authorization input.
    let same_family_txid_seed = 0x90;
    insert_action_full(
        &pool,
        &wrapper,
        same_family_txid_seed,
        &block,
        1778654400700,
        "spend",
        Some("unwrap"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0x91),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": stale_owner.clone(),
            "tokenAmount": "2",
            "tokenRecipientOutputIndex": "0"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        same_family_txid_seed,
        &block,
        1778654400700,
        "spend",
        Some("unwrapByOwnerSig"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0x92),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": recipient.clone(),
            "tokenAmount": "2",
            "inputIndex": "1"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        same_family_txid_seed,
        &block,
        1778654400700,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "ownerIdentifier": recipient.clone(),
                "amount": "2"
            }
        })),
        None,
    )
    .await;

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    for (txid_seed, kind, amount) in [
        (wrap_txid_seed, "wrap", "5"),
        (unwrap_txid_seed, "unwrap", "4"),
        (same_family_txid_seed, "unwrap", "2"),
    ] {
        let rows = repo::kcc20_activity_filtered(
            &pool,
            &token_hex,
            &repo::Kcc20ActivityFilter {
                txid: Some(repeated_seed_hex(txid_seed)),
                ..Default::default()
            },
            10,
            0,
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1, "{kind} must remain unique");
        assert_eq!(rows[0].kind, kind);
        assert_eq!(rows[0].token_amount.as_deref(), Some(amount));
        assert_eq!(rows[0].owner.as_deref(), Some(recipient.as_str()));
    }

    let cross_family = repo::kcc20_activity_filtered(
        &pool,
        &token_hex,
        &repo::Kcc20ActivityFilter {
            txid: Some(repeated_seed_hex(cross_family_txid_seed)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        cross_family.len(),
        2,
        "an unrelated wrapper family's authorization must remain visible"
    );
    assert!(cross_family
        .iter()
        .any(|row| row.entrypoint.as_deref() == Some("unwrap")));
    assert!(cross_family
        .iter()
        .any(|row| row.entrypoint.as_deref() == Some("unwrapByOwnerSig")));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_wrapper_lifecycle_migration_is_fail_safe_without_source_wrapper(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        0x93,
        "kaspatest:pmigration-token",
        Some("KCC20V2"),
        &block,
        100,
    )
    .await;
    let owner = "94".repeat(32);
    let fake_lifecycle_txid = vec![0x95_u8; 32];

    insert_action_full(
        &pool,
        &token,
        0x95,
        &block,
        1778654400800,
        "spend",
        Some("transferByOwnerSig"),
        None,
        None,
        Some(json!({
            "tokenAmount": "5",
            "tokenOutputIndex": "0",
            "changeOutputIndex": "1"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0x95,
        &block,
        1778654400800,
        "continuation",
        None,
        Some(json!({
            "vout": 1,
            "state": {"ownerIdentifier": owner.clone(), "amount": "5"}
        })),
        None,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed
           (token_id, txid, block_time_ms, entrypoint, kind, order_id,
            owner_identifier, token_amount)
           VALUES
           ($1, $2, 1778654400800, 'wrap', 'wrap', 'fake:0', $3, '5'),
           ($1, $2, 1778654400800, NULL, 'wrap', NULL, $3, '5')"#,
    )
    .bind(&token)
    .bind(&fake_lifecycle_txid)
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();

    let duplicate_txid = vec![0x96_u8; 32];
    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed
           (token_id, txid, block_time_ms, entrypoint, kind, order_id,
            owner_identifier, token_amount)
           VALUES
           ($1, $2, 1778654400900, 'wrap', 'wrap', 'same-outpoint:0', NULL, NULL),
           ($1, $2, 1778654400900, 'wrap', 'wrap', 'same-outpoint:0', $3, '7')"#,
    )
    .bind(&token)
    .bind(&duplicate_txid)
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::raw_sql(include_str!(
        "../migrations/20260717090000_kcc20_wrapper_lifecycle_activity_hardening.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let fake_rows: Vec<String> =
        sqlx::query_scalar("SELECT kind FROM kcc20_activity_feed WHERE txid = $1 ORDER BY id")
            .bind(&fake_lifecycle_txid)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        fake_rows,
        vec!["wrap".to_string(), "wrap".to_string()],
        "a feed-only lifecycle marker cannot authorize destructive cleanup"
    );

    let richer_duplicate: (i64, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT, MAX(owner_identifier), MAX(token_amount)
         FROM kcc20_activity_feed WHERE txid = $1",
    )
    .bind(&duplicate_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(richer_duplicate.0, 1);
    assert_eq!(richer_duplicate.1.as_deref(), Some(owner.as_str()));
    assert_eq!(richer_duplicate.2.as_deref(), Some("7"));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_wrapper_summary_prefers_claim_over_bad_constructor_without_reserve(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        0x41,
        "kaspatest:claim-token",
        Some("KCC20V2"),
        &block,
        100,
    )
    .await;
    let decoded_wrong_token = vec![0x49; 32];
    let wrapper = insert_covenant(
        &pool,
        0x42,
        "kaspatest:claim-wrapper",
        Some("KCC20Wrapper"),
        &block,
        101,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1,
               claimed_args = $2,
               claim_source = 'payload'
           WHERE covenant_id = $3"#,
    )
    .bind(json!({
        "canonicalTokenId": hex::encode(&decoded_wrong_token),
        "feeTicketId": "00".repeat(32),
        "wrappedRootAmount": "1",
        "initEnabled": true
    }))
    .bind(json!({
        "args": [
            {"name": "canonicalTokenId", "value": hex::encode(&token)},
            {"name": "feeTicketId", "value": "00".repeat(32)},
            {"name": "wrappedRootAmount", "value": "1"},
            {"name": "initEnabled", "value": true}
        ]
    }))
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(
        &pool,
        &wrapper,
        "kaspatest:claim-wrapper",
        100_000_000,
        &block,
        0x43,
    )
    .await;

    repo::refresh_kcc20_wrapper_summaries(&pool).await.unwrap();

    let wrappers =
        repo::kcc20_wrapper_summaries_by_canonical(&pool, &hex::encode(&token), true, 200, 0)
            .await
            .unwrap();
    assert_eq!(wrappers.len(), 1);
    assert_eq!(wrappers[0].wrapper_id_hex, hex::encode(&wrapper));

    let wrong_wrappers = repo::kcc20_wrapper_summaries_by_canonical(
        &pool,
        &hex::encode(&decoded_wrong_token),
        true,
        200,
        0,
    )
    .await
    .unwrap();
    assert!(wrong_wrappers.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_shared_family_keeps_wrapper_projection_after_wrapped_classification(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token =
        hex::decode("f6d63104971ad2721641f870ac54dc80ac98ac960db1cf57be7d681973d4f6e3").unwrap();
    let wrapper =
        hex::decode("bcf7ddba096e1c6e8c4e55f048025cfafb5f2d1006bbe9746e03cc60b884a8e4").unwrap();
    let decoded_wrong_token =
        hex::decode("5b0d747910bff259c85d53591d42373da0e0995c297bfdacb9de508a898c6e4e").unwrap();
    let owner = vec![0x77; 32];

    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms, constructor_args,
            classification_kind, classification_status)
           VALUES
           ($1, 'kaspatest:test43-token', 0, $1, 'KCC20V2', $2, 0, $3, 1000, NULL, 'covenant', 'matched'),
           ($4, 'kaspatest:test43-wrapper', 0, $4, 'KCC20Orderbook', $5, 0, $3, 1001, $6, 'covenant', 'matched')"#,
    )
    .bind(&token)
    .bind(vec![0x91_u8; 32])
    .bind(&block)
    .bind(&wrapper)
    .bind(vec![0x92_u8; 32])
    .bind(json!({
        "canonicalTokenId": hex::encode(&decoded_wrong_token),
        "feeTicketId": "00".repeat(32),
        "wrappedRootAmount": "1",
        "initEnabled": true
    }))
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20Wrapper',
               claimed_args = $1,
               claim_source = 'payload',
               claim_verified = FALSE
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20Wrapper",
        "args": [
            {"name": "canonicalTokenId", "type": "bytes", "value": hex::encode(&token)}
        ]
    }))
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES
           ($1, $2, 0, 100000000::NUMERIC, 1, FALSE, 1000),
           ($1, $3, 4, 100000000::NUMERIC, 1, FALSE, 1001),
           ($3, $2, 0, 100000000::NUMERIC, 1, FALSE, 1002)"#,
    )
    .bind(&token)
    .bind(&owner)
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();

    let wrap_txid =
        hex::decode("b1d3d9d1d6d202e1852d85ddebefed2fdff5f30fc65a682312a6bb236c00121c").unwrap();
    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint,
            inputs, outputs, decoded_args, canonical_token_id)
           VALUES ($1, $2, $3, 2000, 'spend', 'wrap', NULL, $4, $5, $6)"#,
    )
    .bind(&wrapper)
    .bind(&wrap_txid)
    .bind(&block)
    .bind(json!({
        "state": {
            "ownerIdentifier": hex::encode(&owner),
            "amount": "100000000",
            "canonicalTokenId": hex::encode(&decoded_wrong_token)
        }
    }))
    .bind(json!({
        "canonicalTokenId": hex::encode(&decoded_wrong_token),
        "tokenAmount": "100000000"
    }))
    .bind(&decoded_wrong_token)
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_token_page_projections(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "kcc20_persist", Some(&wrap_txid))
        .await
        .unwrap();
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();

    let wrappers =
        repo::kcc20_wrapper_summaries_by_canonical(&pool, &hex::encode(&token), true, 200, 0)
            .await
            .unwrap();
    assert_eq!(wrappers.len(), 1);
    assert_eq!(wrappers[0].wrapper_id_hex, hex::encode(&wrapper));

    let wrong_wrappers = repo::kcc20_wrapper_summaries_by_canonical(
        &pool,
        &hex::encode(&decoded_wrong_token),
        true,
        200,
        0,
    )
    .await
    .unwrap();
    assert!(wrong_wrappers.is_empty());

    let summary = repo::kcc20_token_summary(&pool, &hex::encode(&token))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        summary.wrapper_id_hex.as_deref(),
        Some(hex::encode(&wrapper).as_str())
    );
    assert_eq!(summary.wrapper_reserve_supply, "100000000");
    assert_eq!(summary.orderbook_tradeable_supply, "100000000");

    let repaired_action_token: String = sqlx::query_scalar(
        "SELECT encode(canonical_token_id, 'hex') FROM covenant_actions WHERE covenant_id = $1",
    )
    .bind(&wrapper)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(repaired_action_token, hex::encode(&token));

    let claim_verified: bool =
        sqlx::query_scalar("SELECT claim_verified FROM covenants WHERE covenant_id = $1")
            .bind(&wrapper)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(claim_verified);

    let activity = repo::kcc20_activity(&pool, &hex::encode(&token), 10, 0)
        .await
        .unwrap();
    assert!(activity
        .iter()
        .any(|row| row.kind == "wrap" && row.token_amount.as_deref() == Some("100000000")));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_market_discovery_query_plan_uses_summary_table_only(pool: PgPool) {
    for tag in 0x20..=0x2a {
        insert_market_summary(
            &pool,
            tag,
            &(1_000_000_i64 + tag as i64).to_string(),
            tag as i64,
            Some(5000 + tag as i64),
        )
        .await;
    }

    let plan: Vec<String> = sqlx::query_scalar(
        r#"
        EXPLAIN
        SELECT
            encode(m.token_id, 'hex') AS token_id_hex,
            m.total_volume_sompi::TEXT AS total_volume_sompi
        FROM kcc20_market_summaries m
        WHERE ($1::BYTEA IS NULL OR m.token_id = $1)
        ORDER BY m.total_volume_sompi DESC NULLS LAST, m.token_id ASC
        LIMIT 5 OFFSET 0
        "#,
    )
    .bind(Option::<Vec<u8>>::None)
    .fetch_all(&pool)
    .await
    .unwrap();
    let plan_text = plan.join("\n");

    assert!(plan_text.contains("kcc20_market_summaries"));
    assert!(!plan_text.contains("covenant_actions"));
    assert!(!plan_text.contains("covenant_utxos"));
    assert!(!plan_text.contains("covenants"));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_market_discovery_sorts_numeric_fields_and_nulls_last(pool: PgPool) {
    let null_trade = insert_market_summary(&pool, 0x11, "900", 1, None).await;
    let active_trade = insert_market_summary(&pool, 0x12, "1000", 2, Some(5000)).await;
    let older_trade = insert_market_summary(&pool, 0x13, "800", 3, Some(1000)).await;

    let page = repo::kcc20_market_discovery(&pool, None, "lastTradeTimeMs", "desc", 10, 0, true)
        .await
        .unwrap();

    assert_eq!(page.items.len(), 3);
    assert_eq!(page.items[0].token_id_hex, hex::encode(&active_trade));
    assert_eq!(page.items[1].token_id_hex, hex::encode(&older_trade));
    assert_eq!(page.items[2].token_id_hex, hex::encode(&null_trade));

    let numeric = repo::kcc20_market_discovery(&pool, None, "totalVolumeSompi", "asc", 10, 0, true)
        .await
        .unwrap();
    assert_eq!(numeric.items[0].total_volume_sompi, "800");
    assert_eq!(numeric.items[1].total_volume_sompi, "900");
    assert_eq!(numeric.items[2].total_volume_sompi, "1000");
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_market_discovery_exposes_and_sorts_window_fields(pool: PgPool) {
    let low_24h = insert_market_summary(&pool, 0x14, "5000", 5, Some(1000)).await;
    let high_24h = insert_market_summary(&pool, 0x15, "1000", 1, Some(2000)).await;
    update_market_summary_windows(&pool, &low_24h, "100", "10000", 2, 9).await;
    update_market_summary_windows(&pool, &high_24h, "900", "2000", 7, 8).await;

    let by_volume =
        repo::kcc20_market_discovery(&pool, None, "volume24hSompi", "desc", 10, 0, true)
            .await
            .unwrap();
    assert_eq!(by_volume.items[0].token_id_hex, hex::encode(&high_24h));
    assert_eq!(by_volume.items[0].volume_24h_sompi, "900");
    assert_eq!(by_volume.items[0].volume_7d_sompi, "2000");
    assert_eq!(by_volume.items[0].trade_count_24h, 7);
    assert_eq!(by_volume.items[0].trade_count_7d, 8);

    let by_7d_trades =
        repo::kcc20_market_discovery(&pool, None, "tradeCount7d", "desc", 10, 0, true)
            .await
            .unwrap();
    assert_eq!(by_7d_trades.items[0].token_id_hex, hex::encode(&low_24h));
    assert_eq!(by_7d_trades.items[0].trade_count_7d, 9);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "fixed-lot sale market summaries are retired after the standard-native cutover"]
async fn refresh_kcc20_market_summaries_populates_window_fields(pool: PgPool) {
    let anchor_block = insert_block(&pool, 7, 604_800_000).await;
    let anchor_ms = 1778654400000_i64 + 604_800_000;
    let token_id = vec![0x16; 32];
    let token_hex = hex::encode(&token_id);
    let sale = insert_covenant(
        &pool,
        0x16,
        "kaspatest:window-sale",
        Some("KCC20Sale"),
        &anchor_block,
        100,
    )
    .await;
    let malformed_sale = insert_covenant(
        &pool,
        0x17,
        "kaspatest:malformed-window-sale",
        None,
        &anchor_block,
        101,
    )
    .await;
    let malformed_bid = insert_covenant(
        &pool,
        0x18,
        "kaspatest:malformed-window-bid",
        None,
        &anchor_block,
        102,
    )
    .await;

    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20Sale',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20Sale",
        "args": { "name": "tokenId", "type": "byte[32]", "value": token_hex }
    }))
    .bind(&malformed_sale)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20BuyOrder',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20BuyOrder",
        "args": { "name": "tokenId", "type": "byte[32]", "value": token_hex }
    }))
    .bind(&malformed_bid)
    .execute(&pool)
    .await
    .unwrap();

    insert_action_with_outputs_and_args(
        &pool,
        &sale,
        0xd1,
        &anchor_block,
        anchor_ms - 60_000,
        "spend",
        Some("buy"),
        None,
        Some(json!({
            "tokenId": token_hex,
            "tokenAmount": "10",
            "priceSompi": "1000"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &sale,
        0xd2,
        &anchor_block,
        anchor_ms - 2 * 86_400_000,
        "spend",
        Some("buy"),
        None,
        Some(json!({
            "tokenId": token_hex,
            "tokenAmount": "20",
            "priceSompi": "2000"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &sale,
        0xd3,
        &anchor_block,
        anchor_ms - 8 * 86_400_000,
        "spend",
        Some("buy"),
        None,
        Some(json!({
            "tokenId": token_hex,
            "tokenAmount": "40",
            "priceSompi": "4000"
        })),
    )
    .await;

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();
    let page = repo::kcc20_market_discovery(
        &pool,
        Some(&token_hex),
        "volume7dSompi",
        "desc",
        10,
        0,
        true,
    )
    .await
    .unwrap();

    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].total_volume_sompi, "7000");
    assert_eq!(page.items[0].total_trades, 3);
    assert_eq!(page.items[0].volume_24h_sompi, "1000");
    assert_eq!(page.items[0].trade_count_24h, 1);
    assert_eq!(page.items[0].volume_7d_sompi, "3000");
    assert_eq!(page.items[0].trade_count_7d, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn refresh_kcc20_market_summaries_excludes_retired_sales(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 0xab, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let token_hex = hex::encode(&token);
    let sale = insert_covenant(
        &pool,
        0x0c,
        "kaspatest:sale",
        Some("KCC20Sale"),
        &block,
        101,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tokenId": token_hex.to_ascii_uppercase(),
        "tokenAmount": "10",
        "priceSompi": "1000"
    }))
    .bind(&sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(&pool, &sale, "kaspatest:sale", 50_000_000, &block, 0xb1).await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:locked",
        50_000_000,
        json!({
            "ownerIdentifier": hex::encode(&sale),
            "identifierType": 2,
            "amount": "10"
        }),
        &block,
        0xb2,
    )
    .await;

    let wrapped = insert_covenant(
        &pool,
        0xad,
        "kaspatest:orderbook-ask",
        Some("KCC20Orderbook"),
        &block,
        102,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &wrapped,
        "kaspatest:orderbook-ask",
        50_000_000,
        json!({
            "canonicalTokenId": token_hex,
            "ownerIdentifier": "11".repeat(32),
            "identifierType": 0,
            "amount": "10",
            "mode": "2",
            "unitPriceSompi": "90"
        }),
        &block,
        0xb3,
    )
    .await;

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();

    let row = sqlx::query(
        r#"SELECT encode(token_id, 'hex') AS token_id_hex,
                  open_ask_count,
                  best_ask_unit_price_sompi::TEXT AS best_ask
           FROM kcc20_market_summaries"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("token_id_hex"), token_hex);
    assert_eq!(row.get::<i64, _>("open_ask_count"), 1);
    assert_eq!(row.get::<String, _>("best_ask"), "90");
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_listings_exclude_retired_sale_for_current_token(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let sale = insert_covenant(&pool, 3, "kaspatest:sale", Some("KCC20Sale"), &block, 101).await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "seller": "11".repeat(32),
        "tokenId": hex::encode(&token),
        "tokenAmount": "250",
        "priceSompi": "100000000"
    }))
    .bind(&sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(&pool, &sale, "kaspatest:sale", 50_000_000, &block, 0xa1).await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:locked",
        50_000_000,
        json!({
            "ownerIdentifier": hex::encode(&sale),
            "identifierType": 2,
            "identifierTypeName": "covenantId",
            "amount": "250",
            "isMinter": false
        }),
        &block,
        0xa2,
    )
    .await;

    let rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is retired after the standard-native cutover"]
async fn kcc20_listings_exposes_v3_ask_state(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V3"), &block, 100).await;
    let seller = "11".repeat(32);
    let fee_ticket_id = "44".repeat(32);
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-ask",
        50_000_000,
        json!({
            "ownerIdentifier": seller.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "250",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "minFillAmount": "25",
            "feeTicketId": fee_ticket_id.clone(),
            "feeBps": 200
        }),
        &block,
        0xa5,
    )
    .await;

    let rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template_name.as_deref(), Some("KCC20V3"));
    assert_eq!(rows[0].order_id, format!("{}:0", "a5".repeat(32)));
    assert_eq!(rows[0].txid_hex.as_deref().unwrap(), "a5".repeat(32));
    assert_eq!(rows[0].vout, Some(0));
    assert_eq!(rows[0].market_side, "ask");
    assert_eq!(rows[0].token_id_hex, hex::encode(&token));
    assert_eq!(rows[0].seller.as_deref(), Some(seller.as_str()));
    assert_eq!(rows[0].token_amount.as_deref(), Some("250"));
    assert_eq!(rows[0].price_sompi.as_deref(), Some("250000000"));
    assert_eq!(rows[0].unit_price_sompi.as_deref(), Some("1000000"));
    assert_eq!(rows[0].min_fill_amount.as_deref(), Some("25"));
    assert_eq!(
        rows[0].fee_ticket_id.as_deref(),
        Some(fee_ticket_id.as_str())
    );
    assert_eq!(rows[0].status, "open");
    assert_eq!(rows[0].locked_token_amount.as_deref(), Some("250"));

    let seller_rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), Some(&seller))
        .await
        .unwrap();
    let other_seller_rows =
        repo::kcc20_listings(&pool, Some(&hex::encode(&token)), Some(&"22".repeat(32)))
            .await
            .unwrap();
    assert_eq!(seller_rows.len(), 1);
    assert!(other_seller_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_holder_authority_backfill_preserves_standard_balances(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let market = insert_covenant(&pool, 2, "kaspatest:fee-balance", Some("KCC20OrderbookFeeRootV1"), &block, 100).await;
    let legacy = insert_covenant(&pool, 3, "kaspatest:standard-balance", Some("KCC20"), &block, 100).await;
    let owner = "11".repeat(32);
    for (mode, amount, seed) in [(0, "3", 0xa1), (0, "4", 0xa2), (2, "9", 0xa3), (3, "12", 0xa4)] {
        insert_active_utxo_with_state(&pool, &market, "kaspatest:fee-holder", 50_000_000,
            json!({"owner": owner, "owner_scheme": 1, "amount": amount, "mode": mode.to_string(),
                "feePolicyVersion": 1, "feePolicy": "ab".repeat(361)}), &block, seed).await;
    }
    sqlx::query("INSERT INTO kcc20_holders(covenant_id,owner_identifier,identifier_type,amount_total,utxo_count,is_minter,last_change_ms) VALUES($1,decode($2,'hex'),0,17,1,FALSE,100)")
        .bind(&legacy).bind(&owner).execute(&pool).await.unwrap();
    for _ in 0..2 {
        sqlx::raw_sql(include_str!("../migrations/20261102214500_fee_market_holder_authority.sql"))
            .execute(&pool).await.unwrap();
        let balances = repo::kcc20_balances_for_owner(&pool, &owner).await.unwrap();
        assert_eq!(balances.len(), 2);
        let fee = balances.iter().find(|row| row.token_id_hex == hex::encode(&market)).unwrap();
        assert_eq!(fee.amount, "7");
        assert_eq!(fee.utxo_count, 2);
        assert_eq!(fee.identifier_type, 1);
        assert_eq!(balances.iter().find(|row| row.token_id_hex == hex::encode(&legacy)).unwrap().amount, "17");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_market_cross_persists_partial_successors_idempotently(pool: PgPool) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-fee-escrow-v1/signed-cross-3-2.json")).unwrap();
    let block = insert_block(&pool, 1, 100).await;
    let market = insert_covenant(&pool, 2, "kaspatest:fee-cross", Some("KCC20OrderbookFeeRootV1"), &block, 100).await;
    assert_eq!(hex::encode(&market), fixture["marketId"].as_str().unwrap());
    let accepted_block = insert_block(&pool, 3, 200).await;
    let mut tx: RestTransaction = serde_json::from_value(fixture["transaction"].clone()).unwrap();
    tx.is_accepted = true;
    tx.version = 1;
    tx.block_hash = vec![hex::encode(&accepted_block)];
    tx.accepting_block_hash = Some(hex::encode(&accepted_block));
    tx.accepting_block_blue_score = Some(200);
    tx.block_time = 1778654400200;
    tx.accepting_block_time = Some(tx.block_time);
    let decoders = tn12_indexer_decoder::default_registry();
    for (index, role, seed) in [(0, "ask", 0x0a), (1, "bid", 0x0b)] {
        // Seed the same authenticated state that preceding order creation stores,
        // including decoder-derived policy metadata absent from builder inputs.
        let signature = hex::decode(&tx.inputs[index].signature_script).unwrap();
        let reveal = tn12_indexer_db::persist::extract_last_push(&signature).unwrap();
        let state = decoders.find_for_reveal(&reveal).unwrap()
            .decode_constructor(&reveal).unwrap();
        assert_eq!(state["owner"], fixture[role]["owner"]);
        assert_eq!(state["amount"], fixture[role]["amount"]);
        insert_active_utxo_with_state(&pool, &market, "kaspatest:fee-cross-order",
            tx.inputs[index].previous_outpoint_amount.unwrap() as i64,
            state, &block, seed).await;
        sqlx::query("UPDATE covenant_utxos SET script_pubkey=$1 WHERE txid=decode($2,'hex') AND vout=0")
            .bind(hex::decode(tx.inputs[index].previous_outpoint_script.as_ref().unwrap()).unwrap())
            .bind(&tx.inputs[index].previous_outpoint_hash).execute(&pool).await.unwrap();
    }
    // REST may omit parent values; persistence must hydrate the authenticated UTXOs.
    tx.inputs[0].previous_outpoint_amount = None;
    tx.inputs[1].previous_outpoint_amount = None;
    let persister = PgPersister::new(pool.clone());
    for _ in 0..2 {
        persister.persist_tx(&tx).await.unwrap();
        let rows = sqlx::query("SELECT vout, state, amount_sompi FROM covenant_utxos WHERE txid=decode($1,'hex') AND covenant_id=$2 ORDER BY vout")
            .bind(&tx.transaction_id).bind(&market).fetch_all(&pool).await.unwrap();
        assert_eq!(rows.len(), 3);
        let holder: serde_json::Value = rows[0].get("state");
        let ask: serde_json::Value = rows[1].get("state");
        assert_eq!(holder["mode"], "0");
        assert_eq!(holder["amount"], "2");
        assert_eq!(holder["owner"], fixture["bid"]["owner"]);
        assert_eq!(ask["mode"], "2");
        assert_eq!(ask["amount"], "1");
        assert_eq!(rows[0].get::<i64,_>("amount_sompi"), 100_000_000);
        assert_eq!(rows[1].get::<i64,_>("amount_sompi"), 200_000_000);
        let balances = repo::kcc20_balances_for_owner(&pool, fixture["bid"]["owner"].as_str().unwrap()).await.unwrap();
        let held = balances.iter().find(|row| row.token_id_hex == hex::encode(&market)).unwrap();
        assert_eq!(held.amount, "2");
        assert_eq!(held.identifier_type, 0);
        let receipt: serde_json::Value = rows[2].get("state");
        assert_eq!(receipt["roleName"], "receipt");
        assert_eq!(receipt["protocol_amount"], "50000000");
        assert_eq!(receipt["creator_amount"], "50000000");
        let trades = repo::kcc20_trades(&pool, Some(&"01".repeat(32)), None, None, None, None, 50, 0).await.unwrap();
        assert_eq!(trades.len(), 1);
        assert_eq!(trades[0].entrypoint.as_deref(), Some("crossWithBid"));
        assert_eq!(trades[0].token_amount.as_deref(), Some("2"));
        assert_eq!(trades[0].price_sompi.as_deref(), Some("600000000"));
        for (role, direction) in [("ask", "out"), ("bid", "in")] {
            let owner = fixture[role]["owner"].as_str().unwrap();
            let raw = repo::kcc20_actions_for_owner(&pool,owner,Some(&"01".repeat(32)),Some("trade"),50,0).await.unwrap();
            let projected = repo::kcc20_actions_for_owner_materialized(&pool,owner,Some(&"01".repeat(32)),Some("trade"),50,0).await.unwrap();
            for rows in [raw,projected] {
                assert_eq!(rows.len(),1);
                assert_eq!(rows[0].amount.as_deref(),Some("2"));
                assert_eq!(rows[0].direction.as_deref(),Some(direction));
                assert_eq!(rows[0].wrapped_token_id.as_deref(),Some(fixture["marketId"].as_str().unwrap()));
            }
        }

        let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
        let summary = summaries.iter().find(|s| s.token_id_hex == "01".repeat(32)).unwrap();
        assert_eq!(summary.total_trades, 1);
        assert_eq!(summary.total_volume_sompi, "600000000");
        let stats = repo::kcc20_token_stats(&pool, &"01".repeat(32), 86_400_000).await.unwrap();
        assert_eq!(stats.trade_count, 1);
        assert_eq!(stats.volume_sompi, "600000000");
        let filter = repo::Kcc20ActivityFilter { kind: Some("trade".into()), ..Default::default() };
        // This API deliberately serves only the projection when its table exists.
        // Refresh before asserting; an empty projection is not a raw-query fallback.
        repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
        let feed = repo::kcc20_activity_filtered(&pool, &"01".repeat(32), &filter, 50, 0).await.unwrap();
        assert_eq!(feed.len(), 1);
        assert_eq!(feed[0].price_sompi.as_deref(), Some("600000000"));
        assert_eq!(feed[0].owner.as_deref(), fixture["bid"]["owner"].as_str());
        assert_eq!(rows[2].get::<i64,_>("amount_sompi"), 100_000_000);
    }
    persister.revert_block(&accepted_block).await.unwrap();
    let owner_count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_fee_owner_trades").fetch_one(&pool).await.unwrap();
    assert_eq!(owner_count,0);
    assert!(repo::kcc20_trades(&pool, Some(&"01".repeat(32)), None, None, None, None, 50, 0).await.unwrap().is_empty());
    let active: Vec<Vec<u8>> = sqlx::query_scalar("SELECT txid FROM covenant_utxos WHERE covenant_id=$1 AND status='active' ORDER BY txid")
        .bind(&market).fetch_all(&pool).await.unwrap();
    assert_eq!(active, vec![vec![0x0a_u8; 32], vec![0x0b_u8; 32]]);
    persister.persist_tx(&tx).await.unwrap();
    let active_amounts: Vec<i64> = sqlx::query_scalar("SELECT amount_sompi FROM covenant_utxos WHERE txid=decode($1,'hex') AND covenant_id=$2 AND status='active' ORDER BY vout")
        .bind(&tx.transaction_id).bind(&market).fetch_all(&pool).await.unwrap();
    assert_eq!(active_amounts, vec![100_000_000, 200_000_000, 100_000_000]);

}

#[sqlx::test(migrations = "./migrations")]
async fn owner_order_candidate_index_excludes_holder_modes(pool: PgPool) {
    let block = insert_block(&pool, 0xa0, 100).await;
    let market = insert_covenant(
        &pool,
        0xa1,
        "kaspatest:owner-order-candidates",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let canonical = hex::encode(&market);
    let owner = "11".repeat(32);

    for tx in 0x10..0x50 {
        insert_active_utxo_with_state(
            &pool,
            &market,
            "kaspatest:owner-order-holder",
            50_000_000,
            json!({
                "canonicalTokenId": canonical,
                "ownerIdentifier": owner,
                "amount": "1",
                "mode": 0
            }),
            &block,
            tx,
        )
        .await;
    }
    for (mode, tx) in [(2, 0xa2), (3, 0xa3)] {
        insert_active_utxo_with_state(
            &pool,
            &market,
            "kaspatest:owner-order",
            50_000_000,
            json!({
                "canonicalTokenId": canonical,
                "ownerIdentifier": owner,
                "amount": "3",
                "mode": mode,
                "unitPriceSompi": "100000000",
                "supplyBacking": "kcc20WrapperReserve"
            }),
            &block,
            tx,
        )
        .await;
    }

    let candidate_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM covenant_utxos \
         WHERE status='active' AND state ? 'ownerIdentifier' \
           AND state ? 'mode' AND state->>'mode' IN ('2','3')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(candidate_count, 2, "holders must not enter order candidates");

    let predicate: String = sqlx::query_scalar(
        "SELECT pg_get_expr(indpred, indrelid) FROM pg_index \
         WHERE indexrelid='covenant_utxos_kcc20_owner_order_state_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(predicate.contains("ownerIdentifier"));
    assert!(predicate.contains("'2'"));
    assert!(predicate.contains("'3'"));

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (COSTS OFF) SELECT covenant_id FROM covenant_utxos \
         WHERE status='active' AND state ? 'ownerIdentifier' \
           AND state ? 'mode' AND state->>'mode' IN ('2','3')",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        plan.join("\n")
            .contains("covenant_utxos_kcc20_owner_order_state_idx"),
        "order candidates did not use the order-only partial index: {plan:#?}"
    );

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    let orders: Vec<(String, String)> = sqlx::query_as(
        "SELECT order_id, side FROM kcc20_owner_orders WHERE owner=$1 ORDER BY order_id",
    )
    .bind(&owner)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        orders,
        vec![
            (format!("{}:0", "a2".repeat(32)), "ask".into()),
            (format!("{}:0", "a3".repeat(32)), "bid".into()),
        ]
    );

    // An interrupted concurrent build can leave an invalid index. The
    // guarded migrator must drop and recreate it on the next attempt.
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_kcc20_owner_order_state_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_kcc20_owner_order_state_idx \
         ON covenant_utxos ((state->>'ownerIdentifier'))",
    )
    .execute(&pool)
    .await
    .is_err());
    let invalid: bool = sqlx::query_scalar(
        "SELECT NOT indisvalid FROM pg_index \
         WHERE indexrelid='covenant_utxos_kcc20_owner_order_state_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(invalid);
    migrate(&pool).await.unwrap();
    let repaired: (bool, String) = sqlx::query_as(
        "SELECT indisvalid, pg_get_expr(indpred, indrelid) FROM pg_index \
         WHERE indexrelid='covenant_utxos_kcc20_owner_order_state_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(repaired.0);
    assert!(repaired.1.contains("'2'") && repaired.1.contains("'3'"));

    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_kcc20_fee_order_state_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query(
        "CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_kcc20_fee_order_state_idx \
         ON covenant_utxos (status)",
    )
    .execute(&pool)
    .await
    .is_err());
    migrate(&pool).await.unwrap();
    let fee_repaired: (bool, String) = sqlx::query_as(
        "SELECT indisvalid, pg_get_expr(indpred, indrelid) FROM pg_index \
         WHERE indexrelid='covenant_utxos_kcc20_fee_order_state_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(fee_repaired.0);
    assert!(fee_repaired.1.contains("'2'") && fee_repaired.1.contains("'3'"));
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_market_orders_expose_scaled_prices_and_owner_filters(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let market = insert_covenant(&pool, 2, "kaspatest:fee-market", Some("KCC20OrderbookFeeRootV1"), &block, 100).await;
    let canonical_id = insert_covenant(&pool, 0x33, "kaspatest:canonical", Some("KCC20"), &block, 100).await;
    let canonical = hex::encode(&canonical_id);
    sqlx::query("UPDATE covenants SET constructor_args=$2 WHERE covenant_id=$1")
        .bind(&canonical_id).bind(json!({"decimals": "8"})).execute(&pool).await.unwrap();
    let owner = "11".repeat(32);
    for (mode, tx) in [(2, 0xa1), (3, 0xa2), (0, 0xa3)] {
        let mut state =
            json!({"canonicalTokenId": canonical, "owner": owner, "mode": mode,
                "amount": "3", "unitPrice": "30000000000000000", "priceScale": "100000000",
                "feePolicyVersion": 1, "feePolicy": "ab".repeat(361), "feeTicketId": "00".repeat(32)});
        if mode == 3 {
            state["ownerIdentifier"] = json!(owner);
        }
        insert_active_utxo_with_state(&pool, &market, "kaspatest:fee-order", 950_000_000,
            state, &block, tx).await;
    }
    let fee_candidates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM covenant_utxos \
         WHERE status='active' AND NOT (state ? 'ownerIdentifier') \
           AND state->>'feePolicyVersion'='1' AND state ? 'feePolicy' \
           AND state ? 'owner' AND state ? 'mode' \
           AND state->>'mode' IN ('2','3')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(fee_candidates, 1, "fee holder and dual-owner bid are excluded");
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *tx)
        .await
        .unwrap();
    let fee_plan: Vec<String> = sqlx::query_scalar(
        "EXPLAIN (COSTS OFF) SELECT covenant_id FROM covenant_utxos \
         WHERE status='active' AND NOT (state ? 'ownerIdentifier') \
           AND state->>'feePolicyVersion'='1' AND state ? 'feePolicy' \
           AND state ? 'owner' AND state ? 'mode' \
           AND state->>'mode' IN ('2','3')",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        fee_plan.join("\n").contains("covenant_utxos_kcc20_fee_order_state_idx"),
        "fee order candidates did not use the order-only index: {fee_plan:#?}"
    );
    for filter in [canonical.clone(), hex::encode(&market)] {
        let asks = repo::kcc20_listings(&pool, Some(&filter), Some(&owner)).await.unwrap();
        let bids = repo::kcc20_bids(&pool, Some(&filter), Some(&owner)).await.unwrap();
        assert_eq!(asks.len(), 1);
        assert_eq!(bids.len(), 1);
        assert_eq!(asks[0].template_name.as_deref(), Some("KCC20OrderbookFeeAskV1"));
        assert_eq!(bids[0].template_name.as_deref(), Some("KCC20OrderbookFeeBidV1"));
        assert_eq!(asks[0].seller.as_deref(), Some(owner.as_str()));
        assert_eq!(bids[0].buyer.as_deref(), Some(owner.as_str()));
        assert_eq!(asks[0].price_sompi.as_deref(), Some("900000000"));
        assert_eq!(bids[0].price_sompi.as_deref(), Some("900000000"));
        assert_eq!(bids[0].bid_value_sompi.as_deref(), Some("950000000"));
        assert_eq!(asks[0].token_id_hex, canonical);
        assert_eq!(bids[0].token_id_hex, canonical);
    }
    assert!(repo::kcc20_listings(&pool, Some(&canonical), Some(&"22".repeat(32))).await.unwrap().is_empty());
    assert!(repo::kcc20_bids(&pool, Some(&canonical), Some(&"22".repeat(32))).await.unwrap().is_empty());
    assert!(repo::kcc20_listings(&pool, Some(&"44".repeat(32)), None).await.unwrap().is_empty());
    assert!(repo::kcc20_bids(&pool, Some(&"44".repeat(32)), None).await.unwrap().is_empty());
    // A version hint without the authenticated policy must not enter any read model.
    insert_active_utxo_with_state(&pool, &market, "kaspatest:incomplete-fee-state", 950_000_000,
        json!({"canonicalTokenId": canonical, "owner": owner, "mode": 2,
            "amount": "1000", "unitPrice": "1", "priceScale": "100000000",
            "feePolicyVersion": 1}), &block, 0xa4).await;
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    let orders = sqlx::query("SELECT side, price_sompi::TEXT AS price, unit_price_sompi::TEXT AS unit_price, template_name FROM kcc20_owner_orders WHERE owner=$1 ORDER BY side")
        .bind(&owner).fetch_all(&pool).await.unwrap();
    assert_eq!(orders.len(), 2);
    assert_eq!(orders[0].get::<String,_>("side"), "ask");
    assert_eq!(orders[1].get::<String,_>("side"), "bid");
    // Unit prices are sompi per display token; raw token amounts use priceScale.
    for row in &orders {
        assert_eq!(row.get::<String,_>("price"), "900000000");
        assert_eq!(row.get::<String,_>("unit_price"), "30000000000000000");
    }
    assert_eq!(orders[0].get::<String,_>("template_name"), "KCC20OrderbookFeeAskV1");
    assert_eq!(orders[1].get::<String,_>("template_name"), "KCC20OrderbookFeeBidV1");
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_market_summaries(&pool).await.unwrap();
    let summary = sqlx::query("SELECT open_ask_count, open_bid_count, best_ask_unit_price_sompi::TEXT AS ask, best_bid_unit_price_sompi::TEXT AS bid FROM kcc20_market_summaries WHERE token_id=decode($1,'hex')")
        .bind(&canonical).fetch_one(&pool).await.unwrap();
    assert_eq!(summary.get::<i64,_>("open_ask_count"), 1);
    assert_eq!(summary.get::<i64,_>("open_bid_count"), 1);
    assert_eq!(summary.get::<String,_>("ask"), "30000000000000000");
    assert_eq!(summary.get::<String,_>("bid"), "30000000000000000");
    sqlx::query("INSERT INTO kcc20_holders (covenant_id,owner_identifier,identifier_type,amount_total,utxo_count,is_minter,last_change_ms) VALUES ($1,decode($2,'hex'),0,3,1,FALSE,1000)")
        .bind(&market).bind(&owner).execute(&pool).await.unwrap();
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool).await.unwrap();
    let asset = sqlx::query("SELECT open_ask_amount::TEXT AS ask, open_bid_amount::TEXT AS bid, open_order_count, value_sompi::TEXT AS value FROM kcc20_owner_portfolio_assets WHERE owner_identifier=decode($1,'hex') AND canonical_token_id=decode($2,'hex')")
        .bind(&owner).bind(&canonical).fetch_one(&pool).await.unwrap();
    assert_eq!(asset.get::<String,_>("ask"), "3");
    assert_eq!(asset.get::<String,_>("bid"), "3");
    assert_eq!(asset.get::<i64,_>("open_order_count"), 2);
    // Three held base units at 3 KAS each. Dividing the display unit price
    // by priceScale again would understate this value by 100,000,000.
    assert_eq!(asset.get::<String,_>("value"), "900000000");

}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_listings_exposes_orderbook_ask_state(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-token",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let canonical = [0x33u8; 32];
    let canonical_hex = hex::encode(canonical);
    let seller = "11".repeat(32);
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:wrapped-orderbook-ask",
        50_000_000,
        json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": seller.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "250",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "supplyBacking": "kcc20WrapperReserve",
            "feeBps": 200
        }),
        &block,
        0xa9,
    )
    .await;

    let rows = repo::kcc20_listings(&pool, Some(&canonical_hex), None)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template_name.as_deref(), Some("KCC20Orderbook"));
    assert_eq!(rows[0].market_side, "ask");
    assert_eq!(rows[0].token_id_hex, canonical_hex);
    assert_eq!(rows[0].seller.as_deref(), Some(seller.as_str()));
    assert_eq!(rows[0].token_amount.as_deref(), Some("250"));
    assert_eq!(rows[0].price_sompi.as_deref(), Some("250000000"));
    assert_eq!(rows[0].status, "open");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is retired after the standard-native cutover"]
async fn kcc20_listings_v3_filters_spent_non_ask_and_other_tokens(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let spent_block = insert_block(&pool, 2, 200).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V3"), &block, 100).await;
    let other_token = insert_covenant(
        &pool,
        3,
        "kaspatest:other-token",
        Some("KCC20V3"),
        &block,
        100,
    )
    .await;
    let seller = "11".repeat(32);
    let ask_state = json!({
        "ownerIdentifier": seller.clone(),
        "identifierType": 0,
        "identifierTypeName": "pubkey",
        "amount": "250",
        "mode": 2,
        "modeName": "ask",
        "unitPriceSompi": "1000000",
        "minFillAmount": "25"
    });
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-ask-open",
        50_000_000,
        ask_state.clone(),
        &block,
        0xa5,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-ask-spent",
        50_000_000,
        ask_state.clone(),
        &block,
        0xa6,
    )
    .await;
    mark_utxo_spent(&pool, 0xa6, &spent_block, 0xf6).await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-holder",
        50_000_000,
        json!({
            "ownerIdentifier": seller.clone(),
            "identifierType": 0,
            "amount": "250",
            "mode": 0,
            "modeName": "holder",
            "unitPriceSompi": "0",
            "minFillAmount": "0"
        }),
        &block,
        0xa7,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &other_token,
        "kaspatest:orderbook-other-ask",
        50_000_000,
        ask_state,
        &block,
        0xa8,
    )
    .await;

    let rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sale_address, "kaspatest:orderbook-ask-open");
    assert_eq!(rows[0].token_amount.as_deref(), Some("250"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is not registered in the current wrapped-orderbook runtime"]
async fn persist_tx_keeps_v3_partial_ask_continuation_open(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V3"), &block, 100).await;
    let owner = [0x4b_u8; 32];
    let buyer = [0x55_u8; 32];
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-ask",
        200_000_000,
        json!({
            "ownerIdentifier": hex::encode(owner),
            "identifierType": 0,
            "amount": "150",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "minFillAmount": "25"
        }),
        &block,
        0xaa,
    )
    .await;

    let tx = v3_partial_ask_fill_tx(owner, buyer);

    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let listings = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert_eq!(listings.len(), 1);
    assert_eq!(listings[0].status, "open");
    assert_eq!(listings[0].sale_address, "kaspatest:ask-continuation");
    assert_eq!(listings[0].token_amount.as_deref(), Some("125"));

    let actions = repo::actions_by_txid(&pool, &"cc".repeat(32))
        .await
        .unwrap();
    let continuations = actions
        .iter()
        .filter(|action| action.action == "continuation")
        .count();
    assert_eq!(continuations, 2);

    sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, 1778654400200, 'continuation', NULL, NULL, $4, NULL)"#,
    )
    .bind(&token)
    .bind(vec![0xcc_u8; 32])
    .bind(vec![0x55_u8; 32])
    .bind(json!({
        "state": {
            "ownerIdentifier": hex::encode(buyer),
            "identifierType": 0,
            "amount": "99",
            "mode": 0,
            "modeName": "holder"
        }
    }))
    .execute(&pool)
    .await
    .unwrap();

    let trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&token)),
        None,
        None,
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(trades.len(), 1);
    assert_eq!(trades[0].entrypoint.as_deref(), Some("fillAskPartial"));
    assert_eq!(trades[0].side, "buy");
    assert_eq!(trades[0].token_amount.as_deref(), Some("25"));
    assert_eq!(trades[0].price_sompi.as_deref(), Some("25000000"));

    let ranged_trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&token)),
        None,
        None,
        Some(1778654400200),
        Some(1778654400201),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(ranged_trades.len(), 1);
    let excluded_trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&token)),
        None,
        None,
        Some(1778654400201),
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert!(excluded_trades.is_empty());

    let buyer_trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&token)),
        Some(&hex::encode(buyer)),
        None,
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(buyer_trades.len(), 1);

    let sell_trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&token)),
        None,
        Some("sell"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert!(sell_trades.is_empty());

    let paged_trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&token)),
        None,
        None,
        None,
        None,
        10,
        1,
    )
    .await
    .unwrap();
    assert!(paged_trades.is_empty());

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == hex::encode(&token))
        .unwrap();
    assert_eq!(summary.total_trades, 1);
    assert_eq!(summary.total_volume_sompi, "25000000");
    assert_eq!(
        summary.last_trade_txid_hex.as_deref().unwrap(),
        "cc".repeat(32)
    );

    let stats = repo::kcc20_token_stats(&pool, &hex::encode(&token), 86_400_000)
        .await
        .unwrap();
    assert_eq!(stats.trade_count, 1);
    assert_eq!(stats.volume_sompi, "25000000");
    assert_eq!(stats.token_volume, "25");
    assert_eq!(stats.open_unit_price_sompi.as_deref(), Some("1000000"));
    assert_eq!(stats.close_unit_price_sompi.as_deref(), Some("1000000"));
    assert_eq!(stats.price_change_sompi.as_deref(), Some("0"));

    let candles = repo::kcc20_candles(&pool, &hex::encode(&token), 3_600_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(candles.len(), 1);
    assert_eq!(candles[0].trade_count, 1);
    assert_eq!(candles[0].volume_sompi, "25000000");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &hex::encode(&token), 10, 0)
        .await
        .unwrap();
    assert_eq!(
        activity
            .iter()
            .filter(|row| {
                row.kind == "trade" && row.entrypoint.as_deref() == Some("fillAskPartial")
            })
            .count(),
        1
    );
    let fill_activity = activity
        .iter()
        .find(|row| row.kind == "trade" && row.entrypoint.as_deref() == Some("fillAskPartial"))
        .unwrap();
    assert_eq!(fill_activity.token_amount.as_deref(), Some("25"));
    assert_eq!(fill_activity.price_sompi.as_deref(), Some("25000000"));

    let buyer_balances = repo::kcc20_balances_for_owner(&pool, &hex::encode(buyer))
        .await
        .unwrap();
    assert!(buyer_balances
        .iter()
        .any(|row| row.token_id_hex == hex::encode(&token) && row.amount == "25"));

    let seller_balances = repo::kcc20_balances_for_owner(&pool, &hex::encode(owner))
        .await
        .unwrap();
    assert!(
        seller_balances
            .iter()
            .all(|row| row.token_id_hex != hex::encode(&token)),
        "remaining ask continuation must not count as spendable holder balance"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_cross_ask_feeds_trade_activity(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-token",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let canonical = [0x55u8; 32];
    let canonical_hex = hex::encode(canonical);
    let seller = "11".repeat(32);
    let buyer = "22".repeat(32);

    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xcd,
        &block,
        1778654400200,
        "spend",
        Some("crossAskSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": seller,
            "amount": "150",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "240000000",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xcd,
        &block,
        1778654400200,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": buyer,
                "amount": "20",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0"
            }
        })),
        None,
    )
    .await;

    let trades = repo::kcc20_trades(&pool, Some(&canonical_hex), None, None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(trades.len(), 1);
    assert_eq!(trades[0].entrypoint.as_deref(), Some("crossAskSide"));
    assert_eq!(trades[0].side, "cross");
    assert_eq!(trades[0].token_amount.as_deref(), Some("20"));
    assert_eq!(trades[0].unit_price_sompi.as_deref(), Some("240000000"));
    assert_eq!(trades[0].price_sompi.as_deref(), Some("4800000000"));

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == canonical_hex.as_str())
        .unwrap();
    assert_eq!(summary.total_trades, 1);
    assert_eq!(summary.total_volume_sompi, "4800000000");

    let stats = repo::kcc20_token_stats(&pool, &canonical_hex, 86_400_000)
        .await
        .unwrap();
    assert_eq!(stats.trade_count, 1);
    assert_eq!(stats.volume_sompi, "4800000000");
    assert_eq!(stats.token_volume, "20");

    let candles = repo::kcc20_candles(&pool, &canonical_hex, 3_600_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(candles.len(), 1);
    assert_eq!(candles[0].trade_count, 1);
    assert_eq!(candles[0].volume_sompi, "4800000000");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &canonical_hex, 10, 0)
        .await
        .unwrap();
    assert_eq!(
        activity
            .iter()
            .filter(|row| {
                row.kind == "trade" && row.entrypoint.as_deref() == Some("crossAskSide")
            })
            .count(),
        1
    );
    let trade_activity = activity
        .iter()
        .find(|row| row.kind == "trade" && row.entrypoint.as_deref() == Some("crossAskSide"))
        .unwrap();
    assert_eq!(trade_activity.side.as_deref(), Some("ask"));
    assert_eq!(trade_activity.token_amount.as_deref(), Some("20"));
    assert_eq!(trade_activity.price_sompi.as_deref(), Some("4800000000"));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_token_stats_cancels_blocked_reads(pool: PgPool) {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE covenant_actions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let token = "01".repeat(32);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        repo::kcc20_token_stats(&pool, &token, 86_400_000),
    )
    .await;
    blocker.rollback().await.unwrap();
    let error = result
        .expect("the database must cancel the stats read before the caller gives up")
        .expect_err("an exclusive table lock must stop this read");
    let sql_error = error.downcast_ref::<sqlx::Error>().unwrap();
    assert_eq!(
        sql_error.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    let empty = repo::kcc20_token_stats(&pool, &token, 86_400_000)
        .await
        .unwrap();
    assert_eq!(empty.trade_count, 0);
    assert_eq!(empty.volume_sompi, "0");
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_candles_from_to_narrows_result_set(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        3,
        "kaspatest:candles-time-range",
        Some("KCC20V3"),
        &block,
        100,
    )
    .await;
    let canonical = [0x5cu8; 32];
    let canonical_hex = hex::encode(canonical);

    for (txid_seed, block_time_ms) in [(0xa1u8, 1_000_000i64), (0xa2, 2_000_000), (0xa3, 3_000_000)]
    {
        insert_action_with_outputs_and_args(
            &pool,
            &token,
            txid_seed,
            &block,
            block_time_ms,
            "spend",
            Some("fillAskPartial"),
            None,
            Some(json!({
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": "88".repeat(32),
                "fillAmount": "10",
                "unitPriceSompi": "100000000"
            })),
        )
        .await;
    }

    let unbounded = repo::kcc20_candles(&pool, &canonical_hex, 1_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(
        unbounded.len(),
        3,
        "omitting from/to must preserve today's newest-N behavior"
    );

    let from_only = repo::kcc20_candles(
        &pool,
        &canonical_hex,
        1_000,
        Some(10),
        Some(1_500_000),
        None,
    )
    .await
    .unwrap();
    assert_eq!(from_only.len(), 2);
    assert!(from_only.iter().all(|c| c.bucket_time_ms >= 1_500_000));

    let to_only = repo::kcc20_candles(
        &pool,
        &canonical_hex,
        1_000,
        Some(10),
        None,
        Some(2_500_000),
    )
    .await
    .unwrap();
    assert_eq!(to_only.len(), 2, "to must be exclusive of the upper bound");
    assert!(to_only.iter().all(|c| c.bucket_time_ms < 2_500_000));

    let both = repo::kcc20_candles(
        &pool,
        &canonical_hex,
        1_000,
        Some(10),
        Some(1_500_000),
        Some(2_500_000),
    )
    .await
    .unwrap();
    assert_eq!(both.len(), 1);
    assert_eq!(both[0].bucket_time_ms, 2_000_000);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_candles_from_to_bound_on_bucket_not_raw_trade_time(pool: PgPool) {
    // Two trades sharing ONE 1,000,000ms bucket: an unaligned from/to that
    // lands strictly between them must not silently drop one trade out of
    // the bucket's OHLCV -- the whole bucket is included or excluded, never
    // computed from a partial trade set.
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        4,
        "kaspatest:candles-bucket-boundary",
        Some("KCC20V3"),
        &block,
        100,
    )
    .await;
    let canonical = [0x5du8; 32];
    let canonical_hex = hex::encode(canonical);

    for (txid_seed, block_time_ms, price) in [
        (0xb1u8, 2_000_000i64, "100000000"),
        (0xb2, 2_900_000, "200000000"),
    ] {
        insert_action_with_outputs_and_args(
            &pool,
            &token,
            txid_seed,
            &block,
            block_time_ms,
            "spend",
            Some("fillAskPartial"),
            None,
            Some(json!({
                "canonicalTokenId": canonical_hex.clone(),
                "fillAmount": "10",
                "unitPriceSompi": price
            })),
        )
        .await;
    }

    let baseline = repo::kcc20_candles(&pool, &canonical_hex, 1_000_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(baseline.len(), 1);
    assert_eq!(baseline[0].bucket_time_ms, 2_000_000);
    assert_eq!(
        baseline[0].open_unit_price_sompi.as_deref(),
        Some("100000000")
    );
    assert_eq!(
        baseline[0].close_unit_price_sompi.as_deref(),
        Some("200000000")
    );
    assert_eq!(baseline[0].trade_count, 2);

    // from lands strictly between the two trades, inside the bucket. If the
    // filter bound raw trade time, this would return a corrupted 1-trade
    // candle (open=close=200000000). Bounding on the bucket boundary instead
    // must drop the WHOLE bucket, since its start (2_000_000) is before the
    // unaligned from (2_500_000).
    let unaligned_from = repo::kcc20_candles(
        &pool,
        &canonical_hex,
        1_000_000,
        Some(10),
        Some(2_500_000),
        None,
    )
    .await
    .unwrap();
    assert!(
        unaligned_from.is_empty(),
        "an unaligned from strictly inside the only bucket must exclude it whole, not return a partial-trade candle: {unaligned_from:?}"
    );

    // from exactly on the bucket boundary must include the bucket WHOLE
    // (both trades), not just trades at or after the raw from timestamp.
    let aligned_from = repo::kcc20_candles(
        &pool,
        &canonical_hex,
        1_000_000,
        Some(10),
        Some(2_000_000),
        None,
    )
    .await
    .unwrap();
    assert_eq!(aligned_from.len(), 1);
    assert_eq!(aligned_from[0].trade_count, 2);
    assert_eq!(
        aligned_from[0].open_unit_price_sompi.as_deref(),
        Some("100000000")
    );

    // to lands strictly between the two trades, inside the bucket. Bounding
    // on the bucket boundary must include the WHOLE bucket (both trades)
    // since its start (2_000_000) is still before the unaligned to
    // (2_500_000) -- not a corrupted 1-trade candle (open=close=100000000).
    let unaligned_to = repo::kcc20_candles(
        &pool,
        &canonical_hex,
        1_000_000,
        Some(10),
        None,
        Some(2_500_000),
    )
    .await
    .unwrap();
    assert_eq!(unaligned_to.len(), 1);
    assert_eq!(
        unaligned_to[0].trade_count,
        2,
        "an unaligned to strictly inside the only bucket must include it whole, not return a partial-trade candle: {unaligned_to:?}"
    );
    assert_eq!(
        unaligned_to[0].close_unit_price_sompi.as_deref(),
        Some("200000000")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_bid_side_fills_feed_trade_surfaces(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-token",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let canonical = [0x56u8; 32];
    let canonical_hex = hex::encode(canonical);
    let seller = "33".repeat(32);
    let buyer = "44".repeat(32);

    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xce,
        &block,
        1778654400300,
        "spend",
        Some("sellIntoBidByOwnerSig"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": seller,
            "amount": "90",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "200000000",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xce,
        &block,
        1778654400300,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": buyer,
                "amount": "30",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0"
            }
        })),
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xcf,
        &block,
        1778654400400,
        "spend",
        Some("crossBidSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": seller,
            "amount": "120",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "150000000",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xcf,
        &block,
        1778654400400,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": buyer,
                "amount": "40",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0"
            }
        })),
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xd0,
        &block,
        1778654400350,
        "spend",
        Some("fillBidPartial"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": seller,
            "amount": "75",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "100000000",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        0xd0,
        &block,
        1778654400350,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": buyer,
                "amount": "35",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0"
            }
        })),
        None,
    )
    .await;

    let trades = repo::kcc20_trades(&pool, Some(&canonical_hex), None, None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(trades.len(), 3);
    assert_eq!(trades[0].entrypoint.as_deref(), Some("crossBidSide"));
    assert_eq!(trades[0].side, "cross");
    assert_eq!(trades[0].token_amount.as_deref(), Some("40"));
    assert_eq!(trades[0].price_sompi.as_deref(), Some("6000000000"));
    assert_eq!(trades[1].entrypoint.as_deref(), Some("fillBidPartial"));
    assert_eq!(trades[1].side, "sell");
    assert_eq!(trades[1].token_amount.as_deref(), Some("35"));
    assert_eq!(trades[1].price_sompi.as_deref(), Some("3500000000"));
    assert_eq!(
        trades[2].entrypoint.as_deref(),
        Some("sellIntoBidByOwnerSig")
    );
    assert_eq!(trades[2].side, "sell");
    assert_eq!(trades[2].token_amount.as_deref(), Some("30"));
    assert_eq!(trades[2].price_sompi.as_deref(), Some("6000000000"));

    let sell_trades = repo::kcc20_trades(
        &pool,
        Some(&canonical_hex),
        None,
        Some("sell"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(sell_trades.len(), 2);
    assert_eq!(sell_trades[0].entrypoint.as_deref(), Some("fillBidPartial"));
    assert_eq!(
        sell_trades[1].entrypoint.as_deref(),
        Some("sellIntoBidByOwnerSig")
    );
    let cross_trades = repo::kcc20_trades(
        &pool,
        Some(&canonical_hex),
        None,
        Some("cross"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(cross_trades.len(), 1);
    assert_eq!(cross_trades[0].entrypoint.as_deref(), Some("crossBidSide"));
    let all_trade_alias_rows = repo::kcc20_trades(
        &pool,
        Some(&canonical_hex),
        None,
        Some("trade"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(all_trade_alias_rows.len(), 3);

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == canonical_hex.as_str())
        .unwrap();
    assert_eq!(summary.total_trades, 3);
    assert_eq!(summary.total_volume_sompi, "15500000000");

    let stats = repo::kcc20_token_stats(&pool, &canonical_hex, 86_400_000)
        .await
        .unwrap();
    assert_eq!(stats.trade_count, 3);
    assert_eq!(stats.volume_sompi, "15500000000");
    assert_eq!(stats.token_volume, "105");
    assert_eq!(stats.open_unit_price_sompi.as_deref(), Some("200000000"));
    assert_eq!(stats.close_unit_price_sompi.as_deref(), Some("150000000"));
    assert_eq!(stats.price_change_sompi.as_deref(), Some("-50000000"));

    let candles = repo::kcc20_candles(&pool, &canonical_hex, 3_600_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(candles.len(), 1);
    assert_eq!(candles[0].trade_count, 3);
    assert_eq!(candles[0].volume_sompi, "15500000000");
    assert_eq!(candles[0].token_volume, "105");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &canonical_hex, 10, 0)
        .await
        .unwrap();
    let bid_trade_entries: Vec<_> = activity
        .iter()
        .filter(|row| {
            row.kind == "trade"
                && row.side.as_deref() == Some("bid")
                && matches!(
                    row.entrypoint.as_deref(),
                    Some("fillBidPartial" | "sellIntoBidByOwnerSig" | "crossBidSide")
                )
        })
        .collect();
    assert_eq!(bid_trade_entries.len(), 3);
    assert!(bid_trade_entries.iter().any(|row| {
        row.entrypoint.as_deref() == Some("fillBidPartial")
            && row.token_amount.as_deref() == Some("35")
            && row.price_sompi.as_deref() == Some("3500000000")
    }));
    assert!(bid_trade_entries.iter().any(|row| {
        row.entrypoint.as_deref() == Some("sellIntoBidByOwnerSig")
            && row.token_amount.as_deref() == Some("30")
            && row.price_sompi.as_deref() == Some("6000000000")
    }));
    assert!(bid_trade_entries.iter().any(|row| {
        row.entrypoint.as_deref() == Some("crossBidSide")
            && row.token_amount.as_deref() == Some("40")
            && row.price_sompi.as_deref() == Some("6000000000")
    }));

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let materialized_trading_scope = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            scope: Some("trading".to_string()),
            side: Some("bid".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(materialized_trading_scope.len(), 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_cross_match_counts_as_one_trade(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        2,
        "kaspatest:cross-match-dedupe",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let canonical = [0x5eu8; 32];
    let canonical_hex = hex::encode(canonical);
    let ask_owner = "66".repeat(32);
    let bid_owner = "77".repeat(32);
    let txid_seed = 0x5f;

    // One atomic crossed match spends an ask input and a bid input in the
    // SAME transaction, decoded into two covenant_actions rows. The
    // inputIndex/askInputIndex/bidInputIndex correlation mirrors what
    // persist-time enrichment produces in production.
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        txid_seed,
        &block,
        1778654400900,
        "spend",
        Some("crossAskSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": ask_owner,
            "inputIndex": "0",
            "bidInputIndex": "1",
            "fillAmount": "60",
            "unitPriceSompi": "300000000",
            "buyerOutputIndex": "0",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        txid_seed,
        &block,
        1778654400900,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": bid_owner,
                "amount": "60",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0"
            }
        })),
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        txid_seed,
        &block,
        1778654400900,
        "spend",
        Some("crossBidSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": bid_owner,
            "inputIndex": "1",
            "askInputIndex": "0",
            "fillAmount": "60",
            "unitPriceSompi": "300000000",
            "buyerOutputIndex": "0",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;

    let trades = repo::kcc20_trades(&pool, Some(&canonical_hex), None, None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(
        trades.len(),
        1,
        "a crossed match spends two covenant_actions rows for one economic trade"
    );
    assert_eq!(trades[0].entrypoint.as_deref(), Some("crossAskSide"));
    assert_eq!(trades[0].token_amount.as_deref(), Some("60"));
    assert_eq!(trades[0].maker.as_deref(), Some(ask_owner.as_str()));
    assert_eq!(trades[0].taker.as_deref(), Some(bid_owner.as_str()));

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == canonical_hex.as_str())
        .unwrap();
    assert_eq!(summary.total_trades, 1);

    let stats = repo::kcc20_token_stats(&pool, &canonical_hex, 86_400_000)
        .await
        .unwrap();
    assert_eq!(stats.trade_count, 1);
    assert_eq!(stats.token_volume, "60");

    let candles = repo::kcc20_candles(&pool, &canonical_hex, 3_600_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(candles.len(), 1);
    assert_eq!(candles[0].trade_count, 1);
    assert_eq!(candles[0].token_volume, "60");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &canonical_hex, 10, 0)
        .await
        .unwrap();
    assert_eq!(
        activity.iter().filter(|row| row.kind == "trade").count(),
        1,
        "projected activity feed must also collapse the crossed pair to one row"
    );
    let materialized = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        materialized.len(),
        1,
        "materialized activity feed must also collapse the crossed pair to one row"
    );
}

/// The `inputIndex`/`askInputIndex`/`bidInputIndex` enrichment the PRIMARY
/// correlation path depends on was only added at persist time by commit
/// `8d9693579` (2026-07-17). `crossAskSide`/`crossBidSide` themselves shipped
/// earlier (commit `77aecfb`, 2026-05-26), so every crossed match persisted
/// in that ~7-week window relies ENTIRELY on the FALLBACK correlation
/// (`buyerOutputIndex` + `fillAmount` equality, no inputIndex fields at all)
/// -- there is no migration backfilling inputIndex into that historical
/// data. Six of the seven guarded functions recompute directly off
/// `covenant_actions` on every call (not just once via a migration), so this
/// exact fixture shape is exercised on every live request against a token
/// with pre-2026-07-17 crossed-match history, not just historically.
#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_cross_match_counts_as_one_trade_fallback_correlation_only(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        3,
        "kaspatest:cross-match-dedupe-fallback",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let canonical = [0x5fu8; 32];
    let canonical_hex = hex::encode(canonical);
    let ask_owner = "88".repeat(32);
    let bid_owner = "99".repeat(32);
    let txid_seed = 0x6f;

    // No inputIndex/askInputIndex/bidInputIndex anywhere -- pre-enrichment
    // shape. Only buyerOutputIndex + fillAmount correlate the pair.
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        txid_seed,
        &block,
        1778654401200,
        "spend",
        Some("crossAskSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": ask_owner,
            "fillAmount": "45",
            "unitPriceSompi": "150000000",
            "buyerOutputIndex": "0",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        txid_seed,
        &block,
        1778654401200,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": bid_owner,
                "amount": "45",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0"
            }
        })),
        None,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &token,
        txid_seed,
        &block,
        1778654401200,
        "spend",
        Some("crossBidSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": bid_owner,
            "fillAmount": "45",
            "unitPriceSompi": "150000000",
            "buyerOutputIndex": "0",
            "supplyBacking": "kcc20WrapperReserve"
        })),
    )
    .await;

    let trades = repo::kcc20_trades(&pool, Some(&canonical_hex), None, None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(
        trades.len(),
        1,
        "fallback-only correlation (no inputIndex fields) must still collapse the pair"
    );
    assert_eq!(trades[0].entrypoint.as_deref(), Some("crossAskSide"));
    assert_eq!(trades[0].maker.as_deref(), Some(ask_owner.as_str()));
    assert_eq!(trades[0].taker.as_deref(), Some(bid_owner.as_str()));

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == canonical_hex.as_str())
        .unwrap();
    assert_eq!(summary.total_trades, 1);

    let stats = repo::kcc20_token_stats(&pool, &canonical_hex, 86_400_000)
        .await
        .unwrap();
    assert_eq!(stats.trade_count, 1);
    assert_eq!(stats.token_volume, "45");

    let candles = repo::kcc20_candles(&pool, &canonical_hex, 3_600_000, Some(10), None, None)
        .await
        .unwrap();
    assert_eq!(candles.len(), 1);
    assert_eq!(candles[0].trade_count, 1);
    assert_eq!(candles[0].token_volume, "45");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &canonical_hex, 10, 0)
        .await
        .unwrap();
    assert_eq!(
        activity.iter().filter(|row| row.kind == "trade").count(),
        1,
        "projected activity feed must also collapse the fallback-only pair to one row"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_cross_match_migration_dedupes_historical_activity_feed(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapped = insert_covenant(
        &pool,
        0x5a,
        "kaspatest:cross-match-migration",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let canonical = [0x5eu8; 32];
    let canonical_hex = hex::encode(canonical);

    // Paired txid: a real crossAskSide + crossBidSide sharing one txid via
    // the inputIndex correlation, with historical (pre-fix) feed rows for
    // BOTH legs -- exactly the duplicated shape the live-query guard now
    // prevents going forward, which this migration must retroactively clean.
    let paired_txid_seed = 0x5f;
    insert_action_with_outputs_and_args(
        &pool,
        &wrapped,
        paired_txid_seed,
        &block,
        1778654400900,
        "spend",
        Some("crossAskSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "inputIndex": "0",
            "bidInputIndex": "1",
            "fillAmount": "60",
            "buyerOutputIndex": "0"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &wrapped,
        paired_txid_seed,
        &block,
        1778654400900,
        "spend",
        Some("crossBidSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "inputIndex": "1",
            "askInputIndex": "0",
            "fillAmount": "60",
            "buyerOutputIndex": "0"
        })),
    )
    .await;

    // Unpaired txid: a lone crossBidSide with no crossAskSide anywhere in the
    // same transaction -- must survive the cleanup untouched.
    let unpaired_txid_seed = 0x60;
    insert_action_with_outputs_and_args(
        &pool,
        &wrapped,
        unpaired_txid_seed,
        &block,
        1778654401000,
        "spend",
        Some("crossBidSide"),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "inputIndex": "3",
            "askInputIndex": "2",
            "fillAmount": "15",
            "buyerOutputIndex": "0"
        })),
    )
    .await;

    // Ambiguous txid: two crossAskSide candidates both matching one
    // crossBidSide via the buyerOutputIndex/fillAmount fallback (same
    // fallback fields, no inputIndex set) -- the pairing is not exact, so
    // the migration's safety net must preserve the row rather than guess.
    let ambiguous_txid_seed = 0x61;
    for (entrypoint, extra) in [
        ("crossAskSide", json!({})),
        ("crossAskSide", json!({})),
        ("crossBidSide", json!({})),
    ] {
        let mut args = json!({
            "canonicalTokenId": canonical_hex.clone(),
            "fillAmount": "25",
            "buyerOutputIndex": "0"
        });
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().cloned().unwrap_or_default().into_iter());
        insert_action_with_outputs_and_args(
            &pool,
            &wrapped,
            ambiguous_txid_seed,
            &block,
            1778654401100,
            "spend",
            Some(entrypoint),
            None,
            Some(args),
        )
        .await;
    }

    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed
           (token_id, txid, block_time_ms, entrypoint, kind, side)
           VALUES
           ($1, $2, 1778654400900, 'crossAskSide', 'trade', 'ask'),
           ($1, $2, 1778654400900, 'crossBidSide', 'trade', 'bid'),
           ($1, $3, 1778654401000, 'crossBidSide', 'trade', 'bid'),
           ($1, $4, 1778654401100, 'crossBidSide', 'trade', 'bid')"#,
    )
    .bind(&canonical)
    .bind(vec![paired_txid_seed; 32])
    .bind(vec![unpaired_txid_seed; 32])
    .bind(vec![ambiguous_txid_seed; 32])
    .execute(&pool)
    .await
    .unwrap();

    sqlx::raw_sql(include_str!(
        "../migrations/20260804120000_kcc20_cross_match_trade_dedupe.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let remaining: Vec<(Vec<u8>, String)> = sqlx::query(
        "SELECT txid, entrypoint FROM kcc20_activity_feed WHERE token_id = $1 ORDER BY txid, entrypoint",
    )
    .bind(&canonical)
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| (row.get::<Vec<u8>, _>("txid"), row.get::<String, _>("entrypoint")))
    .collect();

    assert!(
        remaining.contains(&(vec![paired_txid_seed; 32], "crossAskSide".to_string())),
        "the canonical ask leg of a cleanly paired cross match must survive"
    );
    assert!(
        !remaining.contains(&(vec![paired_txid_seed; 32], "crossBidSide".to_string())),
        "the duplicate bid leg of a cleanly paired cross match must be removed"
    );
    assert!(
        remaining.contains(&(vec![unpaired_txid_seed; 32], "crossBidSide".to_string())),
        "an unpaired crossBidSide with no matching crossAskSide must be preserved"
    );
    assert!(
        remaining.contains(&(vec![ambiguous_txid_seed; 32], "crossBidSide".to_string())),
        "an ambiguously-paired crossBidSide (2+ candidate asks) must be preserved, not guessed at"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_paired_bid_fills_emit_one_priced_trade_per_fill(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapped = insert_covenant(
        &pool,
        0x5a,
        "kaspatest:paired-bid-fills",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let canonical = [0x5bu8; 32];
    let canonical_hex = hex::encode(canonical);
    let txid_seed = 0x5c;

    for (buyer_output_index, fill_amount, unit_price, previous_seed) in [
        ("0", "150000000000", "290000000", 0x61),
        ("4", "5000000000", "190000000", 0x62),
    ] {
        insert_action_full(
            &pool,
            &wrapped,
            txid_seed,
            &block,
            1778654400700,
            "spend",
            Some("fillBidPartial"),
            Some(json!({
                "previousOutpoint": {"hash": repeated_seed_hex(previous_seed), "index": 0}
            })),
            None,
            Some(json!({
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": "44".repeat(32),
                "fillAmount": fill_amount,
                "unitPriceSompi": unit_price,
                "priceScale": "100000000",
                "buyerOutputIndex": buyer_output_index
            })),
        )
        .await;
        insert_action_full(
            &pool,
            &wrapped,
            txid_seed,
            &block,
            1778654400700,
            "spend",
            Some("sellIntoBidByOwnerSig"),
            None,
            None,
            Some(json!({
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": "55".repeat(32),
                "fillAmount": fill_amount,
                "unitPriceSompi": "0",
                "priceScale": "100000000",
                "buyerOutputIndex": buyer_output_index
            })),
        )
        .await;
    }

    let filters = repo::Kcc20ActivityFilter {
        txid: Some(repeated_seed_hex(txid_seed)),
        kind: Some("trade".to_string()),
        ..Default::default()
    };
    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let raw_activity = repo::kcc20_activity_filtered(&pool, &canonical_hex, &filters, 10, 0)
        .await
        .unwrap();
    assert_eq!(raw_activity.len(), 2);
    assert!(raw_activity
        .iter()
        .all(|row| row.entrypoint.as_deref() == Some("fillBidPartial")));
    assert!(raw_activity.iter().all(|row| {
        row.unit_price_sompi
            .as_deref()
            .is_some_and(|price| price != "0")
    }));

    let trades = repo::kcc20_trades(&pool, Some(&canonical_hex), None, None, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(trades.len(), 2);
    assert!(trades
        .iter()
        .all(|row| row.entrypoint.as_deref() == Some("fillBidPartial")));

    let materialized_activity =
        repo::kcc20_activity_filtered(&pool, &canonical_hex, &filters, 10, 0)
            .await
            .unwrap();
    assert_eq!(materialized_activity.len(), 2);

    let ranged_activity = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            from_ms: Some(1778654400700),
            to_ms: Some(1778654400701),
            ..filters.clone()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(ranged_activity.len(), 2);
    let excluded_activity = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            to_ms: Some(1778654400700),
            ..filters.clone()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert!(excluded_activity.is_empty());

    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed
           (token_id, txid, block_time_ms, entrypoint, kind, side)
           VALUES
           ($1, $2, 1778654400700, 'sellIntoBidByOwnerSig', 'trade', 'bid'),
           ($1, $2, 1778654400700, 'sellIntoBidByOwnerSig', 'trade', 'bid')"#,
    )
    .bind(&canonical)
    .bind(vec![txid_seed; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/20260716223000_kcc20_paired_bid_trade_dedupe.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let historical_rows: Vec<String> = sqlx::query_scalar(
        "SELECT entrypoint FROM kcc20_activity_feed WHERE txid = $1 ORDER BY id",
    )
    .bind(vec![txid_seed; 32])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(historical_rows, vec!["fillBidPartial", "fillBidPartial"]);

    let ambiguous_txid_seed = 0x5d;
    for (entrypoint, buyer_output_index, fill_amount) in [
        ("fillBidPartial", "0", "10"),
        ("sellIntoBidByOwnerSig", "0", "10"),
        ("sellIntoBidByOwnerSig", "4", "20"),
    ] {
        insert_action_full(
            &pool,
            &wrapped,
            ambiguous_txid_seed,
            &block,
            1778654400800,
            "spend",
            Some(entrypoint),
            None,
            None,
            Some(json!({
                "canonicalTokenId": canonical_hex.clone(),
                "fillAmount": fill_amount,
                "buyerOutputIndex": buyer_output_index
            })),
        )
        .await;
    }
    sqlx::query(
        r#"INSERT INTO kcc20_activity_feed
           (token_id, txid, block_time_ms, entrypoint, kind, side)
           VALUES
           ($1, $2, 1778654400800, 'sellIntoBidByOwnerSig', 'trade', 'bid'),
           ($1, $2, 1778654400800, 'sellIntoBidByOwnerSig', 'trade', 'bid')"#,
    )
    .bind(&canonical)
    .bind(vec![ambiguous_txid_seed; 32])
    .execute(&pool)
    .await
    .unwrap();
    let ambiguous_rows_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_activity_feed WHERE txid = $1 AND entrypoint = 'sellIntoBidByOwnerSig'",
    )
    .bind(vec![ambiguous_txid_seed; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(include_str!(
        "../migrations/20260716223000_kcc20_paired_bid_trade_dedupe.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let ambiguous_rows_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_activity_feed WHERE txid = $1 AND entrypoint = 'sellIntoBidByOwnerSig'",
    )
    .bind(vec![ambiguous_txid_seed; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        ambiguous_rows_after, ambiguous_rows_before,
        "historical cleanup must preserve ambiguous unpaired seller activity"
    );
    assert!(ambiguous_rows_after >= 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_sweep_bid_fills_feed_trade_surfaces(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapper = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-sweep-bid",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let canonical = [0x57u8; 32];
    let canonical_hex = hex::encode(canonical);
    let external_buyer = "44".repeat(32);
    let seller = "55".repeat(32);
    let specs = [
        (
            0xa1_u8,
            "100000000",
            "200000000",
            0_i64,
            external_buyer.clone(),
        ),
        (
            0xa2_u8,
            "250000000",
            "250000000",
            1_i64,
            external_buyer.clone(),
        ),
        (0xa3_u8, "400000000", "300000000", 2_i64, seller.clone()),
    ];

    insert_action_full(
        &pool,
        &wrapper,
        0xda,
        &block,
        1778654400499,
        "spend",
        Some("sellIntoBids10ByOwnerSig"),
        None,
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": seller.clone(),
            "identifierType": 0,
            "inputIndex": "7",
            "mode": 0,
            "modeName": "holder"
        })),
    )
    .await;

    for (previous_seed, fill_amount, unit_price, index, buyer) in specs {
        insert_action_full(
            &pool,
            &wrapper,
            0xda,
            &block,
            1778654400500 + index,
            "spend",
            Some("fillBidFromSellerSweep"),
            Some(json!({
                "previousOutpoint": {
                    "hash": repeated_seed_hex(previous_seed),
                    "index": "0"
                }
            })),
            None,
            Some(json!({
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": buyer.clone(),
                "sellerInputIndex": "7",
                "fillAmount": fill_amount,
                "unitPriceSompi": unit_price,
                "buyerOutputIndex": index.to_string(),
                "bidOutputIndex": (index + 10).to_string(),
                "sellerOutputIndex": (index + 20).to_string()
            })),
        )
        .await;
        insert_action_with_outputs_and_args(
            &pool,
            &wrapper,
            0xda,
            &block,
            1778654400500 + index,
            "continuation",
            None,
            Some(json!({
                "vout": index,
                "state": {
                    "canonicalTokenId": canonical_hex.clone(),
                    "ownerIdentifier": buyer.clone(),
                    "amount": fill_amount,
                    "mode": 0,
                    "modeName": "holder",
                    "unitPriceSompi": "0",
                    "priceScale": "100000000"
                }
            })),
            None,
        )
        .await;
    }

    let trades = repo::kcc20_trades(
        &pool,
        Some(&canonical_hex),
        None,
        Some("sell"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(trades.len(), 3);
    assert!(trades.iter().all(|row| {
        row.entrypoint.as_deref() == Some("fillBidFromSellerSweep") && row.side == "sell"
    }));
    assert!(trades
        .iter()
        .all(|row| row.taker.as_deref() == Some(seller.as_str())));
    assert!(trades.iter().any(|row| {
        row.maker.as_deref() == Some(seller.as_str())
            && row.taker.as_deref() == Some(seller.as_str())
    }));
    assert!(trades.iter().any(|row| {
        row.token_amount.as_deref() == Some("250000000")
            && row.unit_price_sompi.as_deref() == Some("250000000")
            && row.price_sompi.as_deref() == Some("625000000")
    }));

    let seller_trades = repo::kcc20_trades(
        &pool,
        Some(&canonical_hex),
        Some(seller.as_str()),
        Some("sell"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(seller_trades.len(), 3);

    let external_buyer_trades = repo::kcc20_trades(
        &pool,
        Some(&canonical_hex),
        Some(external_buyer.as_str()),
        Some("sell"),
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(external_buyer_trades.len(), 2);
    assert!(external_buyer_trades
        .iter()
        .all(|row| row.maker.as_deref() == Some(external_buyer.as_str())));

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == canonical_hex)
        .unwrap();
    assert_eq!(summary.total_trades, 3);
    assert_eq!(summary.total_volume_sompi, "2025000000");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let raw_seller_activity = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            side: Some("bid".to_string()),
            txid: Some(repeated_seed_hex(0xda)),
            owner: Some(seller.clone()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(raw_seller_activity.len(), 3);
    assert!(raw_seller_activity.iter().all(|row| {
        row.owner.as_deref() == Some(seller.as_str()) && row.owner_identifier_type == Some(0)
    }));

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            side: Some("bid".to_string()),
            txid: Some(repeated_seed_hex(0xda)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(activity.len(), 3);
    assert!(activity.iter().all(|row| {
        row.owner.as_deref() == Some(seller.as_str()) && row.owner_identifier_type == Some(0)
    }));
    assert!(activity.iter().any(|row| {
        row.order_id.as_deref() == Some(&format!("{}:0", repeated_seed_hex(0xa2)))
            && row.entrypoint.as_deref() == Some("fillBidFromSellerSweep")
            && row.token_amount.as_deref() == Some("250000000")
            && row.price_sompi.as_deref() == Some("625000000")
    }));
    let materialized_seller_activity = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            side: Some("bid".to_string()),
            txid: Some(repeated_seed_hex(0xda)),
            owner: Some(seller.clone()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(materialized_seller_activity.len(), 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_holder_merge_surfaces_consolidation_activity(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapper = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-merge",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let canonical = [0x58u8; 32];
    let canonical_hex = hex::encode(canonical);
    let owner = "66".repeat(32);

    insert_action_full(
        &pool,
        &wrapper,
        0xdb,
        &block,
        1778654400600,
        "spend",
        Some("mergeByOwnerSig"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0xb1),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "peerInputIndex": "1",
            "mergedOutputIndex": "0"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        0xdb,
        &block,
        1778654400600,
        "spend",
        Some("mergePeerByOwnerSig"),
        Some(json!({
            "previousOutpoint": {
                "hash": repeated_seed_hex(0xb2),
                "index": "0"
            }
        })),
        None,
        Some(json!({
            "primaryInputIndex": "0",
            "mergedOutputIndex": "0"
        })),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &wrapper,
        0xdb,
        &block,
        1778654400600,
        "continuation",
        None,
        Some(json!({
            "vout": 0,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": owner.clone(),
                "amount": "900000000",
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0",
                "priceScale": "100000000"
            }
        })),
        None,
    )
    .await;

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("consolidate".to_string()),
            txid: Some(repeated_seed_hex(0xdb)),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(activity.len(), 1);
    assert_eq!(activity[0].entrypoint.as_deref(), Some("mergeByOwnerSig"));
    assert_eq!(activity[0].token_amount.as_deref(), Some("900000000"));
    assert_eq!(activity[0].owner.as_deref(), Some(owner.as_str()));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_actions_for_owner_cancels_blocked_reads(pool: PgPool) {
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE covenant_actions IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await
        .unwrap();
    let owner = "01".repeat(32);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        repo::kcc20_actions_for_owner(&pool, &owner, None, None, 20, 0),
    )
    .await;
    blocker.rollback().await.unwrap();
    let error = result
        .expect("the database must cancel the read before the caller gives up")
        .expect_err("an exclusive table lock must stop this read");
    let sql_error = error.downcast_ref::<sqlx::Error>().unwrap();
    assert_eq!(
        sql_error.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    // The transaction-local budget must not poison subsequent reads in the pool.
    assert!(
        repo::kcc20_actions_for_owner(&pool, &owner, None, None, 20, 0)
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_actions_for_owner_classifies_wrap_unwrap_lifecycle(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapper = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-token",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let wrapper_hex = hex::encode(&wrapper);
    let canonical = [0x55u8; 32];
    let canonical_hex = hex::encode(canonical);
    let owner = "11".repeat(32);

    insert_action_full(
        &pool,
        &wrapper,
        0xd1,
        &block,
        1778654400100,
        "spend",
        Some("wrap"),
        Some(json!({
            "previousOutpoint": {
                "txidHex": "aa".repeat(32),
                "vout": 1
            }
        })),
        None,
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": owner.clone(),
            "amount": "40"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        0xd2,
        &block,
        1778654400200,
        "spend",
        Some("unwrap"),
        Some(json!({
            "previousOutpoint": {
                "txidHex": "bb".repeat(32),
                "vout": 0
            }
        })),
        Some(json!({
            "vout": 2,
            "state": {
                "canonicalTokenId": canonical_hex.clone(),
                "ownerIdentifier": owner.clone(),
                "amount": "10",
                "mode": 0,
                "modeName": "holder"
            }
        })),
        Some(json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": owner.clone(),
            "amount": "10"
        })),
    )
    .await;

    let rows = repo::kcc20_actions_for_owner(&pool, &owner, Some(&canonical_hex), None, 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].action, "unwrap");
    assert_eq!(rows[0].owner.as_deref(), Some(owner.as_str()));
    assert_eq!(
        rows[0].canonical_token_id.as_deref(),
        Some(canonical_hex.as_str())
    );
    assert_eq!(
        rows[0].wrapped_token_id.as_deref(),
        Some(wrapper_hex.as_str())
    );
    assert_eq!(
        rows[0].wrapper_covenant_id.as_deref(),
        Some(wrapper_hex.as_str())
    );
    assert_eq!(rows[0].amount.as_deref(), Some("10"));
    assert_eq!(rows[0].direction.as_deref(), Some("in"));
    assert_eq!(
        rows[0].output_outpoints,
        json!([{ "txidHex": "d2".repeat(32), "vout": 2 }])
    );
    assert_eq!(rows[1].action, "wrap");
    assert_eq!(rows[1].amount.as_deref(), Some("40"));
    assert_eq!(rows[1].direction.as_deref(), Some("out"));
    assert_eq!(
        rows[1].input_outpoints,
        json!([{ "txidHex": "aa".repeat(32), "vout": 1 }])
    );

    let address_rows = repo::kcc20_actions_for_owner(
        &pool,
        "kaspatest:wrapped-token",
        Some(&canonical_hex),
        Some("wrap"),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(address_rows.len(), 1);
    assert_eq!(address_rows[0].txid_hex, "d1".repeat(32));

    let second_page = repo::kcc20_actions_for_owner(&pool, &owner, None, None, 1, 1)
        .await
        .unwrap();
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].txid_hex, rows[1].txid_hex);
    assert!(
        repo::kcc20_actions_for_owner(&pool, &"ff".repeat(32), None, None, 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo::kcc20_actions_for_owner(&pool, &owner, Some(&"ff".repeat(32)), None, 10, 0)
            .await
            .unwrap()
            .is_empty()
    );

    // A claimed template retains the same owner/address behavior until classification.
    sqlx::query("UPDATE covenants SET claimed_template = template_name, template_name = NULL WHERE covenant_id = $1")
        .bind(&wrapper).execute(&pool).await.unwrap();
    let claimed_rows = repo::kcc20_actions_for_owner(&pool, &owner, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(claimed_rows.len(), 2);
    // A different classified template takes precedence over the claim.
    sqlx::query("UPDATE covenants SET template_name = 'UnrelatedContract' WHERE covenant_id = $1")
        .bind(&wrapper)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        repo::kcc20_actions_for_owner(&pool, &owner, None, None, 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_actions_for_owner_indexes_fee_ticket_owner_fields(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let ticket = insert_covenant(
        &pool,
        3,
        "kaspatest:fee-ticket",
        Some("KCC20FeeTicket"),
        &block,
        100,
    )
    .await;
    let utility_token = "55".repeat(32);
    let owner = "22".repeat(32);
    let recipient = "33".repeat(32);

    insert_action_full(
        &pool,
        &ticket,
        0xe1,
        &block,
        1778654400100,
        "spend",
        Some("createFromUtilityBurn"),
        None,
        None,
        Some(json!({
            "ticketOwner": owner.clone(),
            "utilityTokenId": utility_token.clone(),
            "denomination": "100"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &ticket,
        0xe2,
        &block,
        1778654400200,
        "spend",
        Some("transferByOwnerSig"),
        None,
        None,
        Some(json!({
            "toOwner": recipient.clone(),
            "utilityTokenId": utility_token.clone(),
            "denomination": "100"
        })),
    )
    .await;
    insert_action_full(
        &pool,
        &ticket,
        0xe3,
        &block,
        1778654400300,
        "spend",
        Some("burnByOwnerSig"),
        None,
        None,
        Some(json!({
            "ownerIdentifier": recipient.clone(),
            "utilityTokenId": utility_token.clone(),
            "denomination": "100"
        })),
    )
    .await;

    let creates = repo::kcc20_actions_for_owner(
        &pool,
        &owner,
        Some(&utility_token),
        Some("feeTicketCreate"),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0].amount.as_deref(), Some("100"));
    assert_eq!(
        creates[0].canonical_token_id.as_deref(),
        Some(utility_token.as_str())
    );

    let recipient_rows =
        repo::kcc20_actions_for_owner(&pool, &recipient, Some(&utility_token), None, 10, 0)
            .await
            .unwrap();
    assert_eq!(recipient_rows.len(), 2);
    assert_eq!(recipient_rows[0].action, "feeTicketBurn");
    assert_eq!(recipient_rows[1].action, "feeTicketUse");
}

async fn assert_owner_action_history_parity(
    pool: &PgPool,
    owner_or_address: &str,
    token_id: Option<&str>,
    action: Option<&str>,
    limit: i64,
    offset: i64,
) {
    let original =
        repo::kcc20_actions_for_owner(pool, owner_or_address, token_id, action, limit, offset)
            .await
            .unwrap();
    let materialized = repo::kcc20_actions_for_owner_materialized(
        pool,
        owner_or_address,
        token_id,
        action,
        limit,
        offset,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(materialized).unwrap(),
        serde_json::to_value(original).unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_action_history_watermark_survives_empty_queue(pool: PgPool) {
    let first_txid = vec![0x41; 32];
    repo::mark_kcc20_projection_dirty(&pool, "owner_action_first", Some(&first_txid))
        .await
        .unwrap();
    let first_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO kcc20_projection_state (name, last_dirty_id, refreshed_at_ms) \
         VALUES ('owner_action_history', 0, 0)",
    )
    .execute(&pool)
    .await
    .unwrap();

    repo::initialize_kcc20_owner_action_backfill(&pool)
        .await
        .unwrap();
    let saved: i64 = sqlx::query_scalar(
        "SELECT last_dirty_id FROM kcc20_projection_state WHERE name = 'owner_action_history'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(saved, first_id);

    sqlx::query("UPDATE kcc20_owner_action_backfill SET complete = TRUE WHERE singleton")
        .execute(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, first_id, 10)
        .await
        .unwrap();
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());

    sqlx::query("DELETE FROM kcc20_projection_dirty")
        .execute(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, 0, 10)
        .await
        .unwrap();
    let saved: i64 = sqlx::query_scalar(
        "SELECT last_dirty_id FROM kcc20_projection_state WHERE name = 'owner_action_history'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(saved, first_id);

    let second_txid = vec![0x42; 32];
    repo::mark_kcc20_projection_dirty(&pool, "owner_action_second", Some(&second_txid))
        .await
        .unwrap();
    let second_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, second_id, 10)
        .await
        .unwrap();
    let saved: i64 = sqlx::query_scalar(
        "SELECT last_dirty_id FROM kcc20_projection_state WHERE name = 'owner_action_history'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(saved, second_id);
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_action_history_backfill_filters_reorg_and_rebuild(pool: PgPool) {
    let block = insert_block(&pool, 0x91, 100).await;
    let token = insert_covenant(
        &pool,
        0x92,
        "kaspatest:token-history",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    let wrapper = insert_covenant(
        &pool,
        0x93,
        "kaspatest:wrapper-history",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let ticket = insert_covenant(
        &pool,
        0x94,
        "kaspatest:ticket-history",
        Some("KCC20FeeTicket"),
        &block,
        100,
    )
    .await;
    let orderbook = insert_covenant(
        &pool,
        0x95,
        "kaspatest:orderbook-history",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let late_classified = insert_covenant(
        &pool,
        0x96,
        "kaspatest:late-classified-history",
        None,
        &block,
        100,
    )
    .await;
    let owner = "11".repeat(32);
    let canonical = hex::encode(&token);
    insert_action_full(
        &pool,
        &token,
        0xa1,
        &block,
        1778654400100,
        "deploy",
        None,
        None,
        Some(json!({"state": {"ownerIdentifier": owner.clone(), "amount": "100"}, "vout": 0})),
        None,
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        0xa2,
        &block,
        1778654400200,
        "spend",
        Some("wrap"),
        None,
        None,
        Some(json!({"ownerIdentifier": owner.clone(), "canonicalTokenId": canonical.clone(), "amount": "20"})),
    )
    .await;
    insert_action_full(
        &pool,
        &ticket,
        0xa3,
        &block,
        1778654400300,
        "spend",
        Some("createFromUtilityBurn"),
        None,
        None,
        Some(json!({"ticketOwner": owner.clone(), "utilityTokenId": canonical.clone(), "denomination": "5"})),
    )
    .await;
    insert_action_full(
        &pool,
        &orderbook,
        0xa5,
        &block,
        1778654400250,
        "spend",
        Some("createAskByOwnerSig"),
        None,
        None,
        Some(json!({"ownerIdentifier": owner.clone(), "canonicalTokenId": canonical.clone(), "amount": "12"})),
    )
    .await;
    insert_action_full(
        &pool,
        &late_classified,
        0xa8,
        &block,
        1778654400150,
        "deploy",
        None,
        None,
        Some(json!({"state": {"ownerIdentifier": owner.clone()}, "vout": 0})),
        None,
    )
    .await;
    insert_action_full(
        &pool,
        &orderbook,
        0xa6,
        &block,
        1778654400350,
        "spend",
        Some("fillAskPartial"),
        None,
        None,
        Some(json!({"ownerIdentifier": owner.clone(), "canonicalTokenId": canonical.clone(), "amount": "4"})),
    )
    .await;

    repo::initialize_kcc20_owner_action_backfill(&pool)
        .await
        .unwrap();
    assert!(!repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    assert!(
        repo::kcc20_actions_for_owner_materialized_if_ready(&pool, &owner, None, None, 10, 0)
            .await
            .unwrap()
            .is_none()
    );
    for _ in 0..20 {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
            .await
            .unwrap()
        {
            break;
        }
    }
    let complete: bool =
        sqlx::query_scalar("SELECT complete FROM kcc20_owner_action_backfill WHERE singleton")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(complete);
    assert!(repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
        .await
        .unwrap());
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    assert_eq!(
        repo::kcc20_actions_for_owner_materialized_if_ready(&pool, &owner, None, None, 10, 0)
            .await
            .unwrap()
            .unwrap()
            .len(),
        5
    );
    let baseline = repo::kcc20_actions_for_owner(&pool, &owner, None, None, 10, 0)
        .await
        .unwrap();
    assert_eq!(baseline.len(), 5);
    assert_owner_action_history_parity(&pool, &owner, None, None, 10, 0).await;
    assert_owner_action_history_parity(&pool, &owner, Some(&canonical), None, 10, 0).await;
    assert_owner_action_history_parity(&pool, &owner, None, Some("wrap"), 10, 0).await;
    assert_owner_action_history_parity(&pool, &owner, None, Some("orderCreate"), 10, 0).await;
    assert_owner_action_history_parity(&pool, &owner, None, Some("trade"), 10, 0).await;
    assert_owner_action_history_parity(&pool, &owner, None, None, 1, 1).await;
    assert_owner_action_history_parity(&pool, "kaspatest:wrapper-history", None, None, 10, 0).await;
    assert_owner_action_history_parity(&pool, &"ff".repeat(32), None, None, 10, 0).await;

    sqlx::query(
        "UPDATE covenants SET address = 'kaspatest:wrapper-history-new' WHERE covenant_id = $1",
    )
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();
    let wrap_txid = vec![0xa2; 32];
    repo::mark_kcc20_projection_dirty(&pool, "owner_action_address_test", Some(&wrap_txid))
        .await
        .unwrap();
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(!repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    for _ in 0..10 {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
            .await
            .unwrap()
        {
            break;
        }
    }
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert_owner_action_history_parity(&pool, "kaspatest:wrapper-history", None, None, 10, 0).await;
    assert_owner_action_history_parity(&pool, "kaspatest:wrapper-history-new", None, None, 10, 0)
        .await;

    insert_action_full(
        &pool,
        &wrapper,
        0xa4,
        &block,
        1778654400400,
        "spend",
        Some("unwrap"),
        None,
        None,
        Some(json!({"ownerIdentifier": owner.clone(), "canonicalTokenId": canonical.clone(), "amount": "2"})),
    )
    .await;
    let added_txid = vec![0xa4; 32];
    repo::mark_kcc20_projection_dirty(&pool, "owner_action_test", Some(&added_txid))
        .await
        .unwrap();
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert_owner_action_history_parity(&pool, &owner, None, None, 10, 0).await;

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM covenant_actions WHERE txid = $1")
        .bind(&added_txid)
        .execute(&mut *tx)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty_tx(&mut tx, "owner_action_reorg_test", Some(&added_txid))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_owner_action_history WHERE txid = $1")
            .bind(&added_txid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert_owner_action_history_parity(&pool, &owner, None, None, 10, 0).await;

    sqlx::query("UPDATE covenants SET template_name = 'KCC20' WHERE covenant_id = $1")
        .bind(&late_classified)
        .execute(&pool)
        .await
        .unwrap();
    insert_action_full(
        &pool,
        &late_classified,
        0xa7,
        &block,
        1778654400500,
        "spend",
        Some("transferByOwnerSig"),
        None,
        None,
        Some(json!({"ownerIdentifier": owner.clone(), "amount": "1"})),
    )
    .await;
    let classified_txid = vec![0xa7; 32];
    repo::mark_kcc20_projection_dirty(
        &pool,
        "owner_action_classification_test",
        Some(&classified_txid),
    )
    .await
    .unwrap();
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(!repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    for _ in 0..10 {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
            .await
            .unwrap()
        {
            break;
        }
    }
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    assert_owner_action_history_parity(
        &pool,
        "kaspatest:late-classified-history",
        None,
        None,
        10,
        0,
    )
    .await;
    let late_rows = repo::kcc20_actions_for_owner_materialized(
        &pool,
        "kaspatest:late-classified-history",
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(late_rows.len(), 2);

    sqlx::query("UPDATE covenants SET template_name = NULL WHERE covenant_id = $1")
        .bind(&late_classified)
        .execute(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(
        &pool,
        "owner_action_interleaved_unclass",
        Some(&classified_txid),
    )
    .await
    .unwrap();
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(!repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
        .await
        .unwrap());
    sqlx::query("UPDATE covenants SET template_name = 'KCC20' WHERE covenant_id = $1")
        .bind(&late_classified)
        .execute(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(
        &pool,
        "owner_action_interleaved_reclass",
        Some(&classified_txid),
    )
    .await
    .unwrap();
    for _ in 0..10 {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
            .await
            .unwrap()
        {
            break;
        }
    }
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    assert_owner_action_history_parity(
        &pool,
        "kaspatest:late-classified-history",
        None,
        None,
        10,
        0,
    )
    .await;

    sqlx::query("UPDATE covenants SET template_name = NULL WHERE covenant_id = $1")
        .bind(&late_classified)
        .execute(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(
        &pool,
        "owner_action_unclassification_test",
        Some(&classified_txid),
    )
    .await
    .unwrap();
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(!repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    for _ in 0..10 {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
            .await
            .unwrap()
        {
            break;
        }
    }
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    assert_owner_action_history_parity(
        &pool,
        "kaspatest:late-classified-history",
        None,
        None,
        10,
        0,
    )
    .await;
    let late_rows = repo::kcc20_actions_for_owner_materialized(
        &pool,
        "kaspatest:late-classified-history",
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert!(late_rows.is_empty());

    sqlx::query("UPDATE covenants SET template_name = NULL WHERE covenant_id = $1")
        .bind(&ticket)
        .execute(&pool)
        .await
        .unwrap();
    repo::mark_kcc20_projection_dirty(&pool, "owner_action_global_test", None)
        .await
        .unwrap();
    let dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(!repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    for _ in 0..20 {
        if repo::backfill_kcc20_owner_action_history_batch(&pool, 1)
            .await
            .unwrap()
        {
            break;
        }
    }
    repo::refresh_kcc20_owner_action_history(&pool, dirty_id, 10)
        .await
        .unwrap();
    assert!(repo::kcc20_owner_action_history_ready(&pool).await.unwrap());
    assert_owner_action_history_parity(&pool, &owner, None, None, 10, 0).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_orderbook_sweep_ask_activity_per_fill(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapper = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let owner = [0x4b_u8; 32];
    let buyer = [0x55_u8; 32];

    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:orderbook-ask-full",
        50_000_000,
        json!({
            "canonicalTokenId": hex::encode(&wrapper),
            "ownerIdentifier": hex::encode(owner),
            "identifierType": 0,
            "amount": "100000000",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "priceScale": "100000000"
        }),
        &block,
        0xaa,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:orderbook-ask-partial",
        50_000_000,
        json!({
            "canonicalTokenId": hex::encode(&wrapper),
            "ownerIdentifier": hex::encode(owner),
            "identifierType": 0,
            "amount": "150000000",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "2000000",
            "priceScale": "100000000"
        }),
        &block,
        0xbb,
    )
    .await;

    let tx = orderbook_sweep_ask_fill_tx(&wrapper, owner, buyer);
    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let actions = repo::actions_by_txid(&pool, &"dd".repeat(32))
        .await
        .unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|action| {
                action.action == "spend" && action.entrypoint.as_deref() == Some("fillAskPartial")
            })
            .count(),
        2
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.action == "continuation")
            .count(),
        3
    );

    let listings = repo::kcc20_listings(&pool, Some(&hex::encode(&wrapper)), None)
        .await
        .unwrap();
    assert_eq!(listings.len(), 1);
    assert_eq!(listings[0].sale_address, "kaspatest:ask-continuation-two");
    assert_eq!(listings[0].token_amount.as_deref(), Some("125000000"));

    let trades = repo::kcc20_trades(
        &pool,
        Some(&hex::encode(&wrapper)),
        None,
        None,
        None,
        None,
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(trades.len(), 2);
    assert!(trades.iter().any(|row| {
        row.token_amount.as_deref() == Some("25000000")
            && row.unit_price_sompi.as_deref() == Some("2000000")
            && row.price_sompi.as_deref() == Some("500000")
    }));
    assert!(trades.iter().any(|row| {
        row.token_amount.as_deref() == Some("100000000")
            && row.unit_price_sompi.as_deref() == Some("1000000")
            && row.price_sompi.as_deref() == Some("1000000")
    }));

    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == hex::encode(&wrapper))
        .unwrap();
    assert_eq!(summary.total_trades, 2);
    assert_eq!(summary.total_volume_sompi, "1500000");

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &hex::encode(&wrapper), 10, 0)
        .await
        .unwrap();
    let trade_rows = activity
        .iter()
        .filter(|row| row.kind == "trade" && row.entrypoint.as_deref() == Some("fillAskPartial"))
        .collect::<Vec<_>>();
    assert_eq!(trade_rows.len(), 2);
    let full_order_id = format!("{}:0", "aa".repeat(32));
    let partial_order_id = format!("{}:0", "bb".repeat(32));
    assert!(trade_rows.iter().any(|row| {
        row.order_id.as_deref() == Some(full_order_id.as_str())
            && row.token_amount.as_deref() == Some("100000000")
            && row.price_sompi.as_deref() == Some("1000000")
    }));
    assert!(trade_rows.iter().any(|row| {
        row.order_id.as_deref() == Some(partial_order_id.as_str())
            && row.token_amount.as_deref() == Some("25000000")
            && row.price_sompi.as_deref() == Some("500000")
    }));
}

async fn assert_orderbook_sweep_ask_activity_for_specs(
    pool: PgPool,
    txid_seed: u8,
    specs: Vec<WrappedSweepAskFillSpec>,
) {
    let block = insert_block(&pool, txid_seed, 100 + i64::from(txid_seed)).await;
    let wrapper = insert_covenant(
        &pool,
        txid_seed + 1,
        "kaspatest:wrapped-sweep",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let owner = [0x4b_u8; 32];
    let buyer = [0x55_u8; 32];
    let wrapper_hex = hex::encode(&wrapper);
    let txid_hex = repeated_seed_hex(txid_seed);

    for (index, spec) in specs.iter().enumerate() {
        insert_active_utxo_with_state(
            &pool,
            &wrapper,
            &format!("kaspatest:sweep-source-{index}"),
            50_000_000,
            json!({
                "canonicalTokenId": wrapper_hex,
                "ownerIdentifier": hex::encode(owner),
                "identifierType": 0,
                "amount": spec.available_amount.to_string(),
                "mode": 2,
                "modeName": "ask",
                "unitPriceSompi": spec.unit_price_sompi.to_string(),
                "priceScale": "100000000"
            }),
            &block,
            spec.previous_txid_seed,
        )
        .await;
    }

    let tx = orderbook_sweep_ask_fill_tx_from_specs(&wrapper, owner, buyer, txid_seed, &specs);
    PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();

    let actions = repo::actions_by_txid(&pool, &txid_hex).await.unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|action| {
                action.action == "spend" && action.entrypoint.as_deref() == Some("fillAskPartial")
            })
            .count(),
        specs.len()
    );

    let partial_specs = specs
        .iter()
        .filter(|spec| spec.available_amount > spec.fill_amount)
        .count();
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.action == "continuation")
            .count(),
        specs.len() + partial_specs
    );

    let listings = repo::kcc20_listings(&pool, Some(&wrapper_hex), None)
        .await
        .unwrap();
    assert_eq!(listings.len(), partial_specs);
    for spec in specs
        .iter()
        .filter(|spec| spec.available_amount > spec.fill_amount)
    {
        let remaining_amount = (spec.available_amount - spec.fill_amount).to_string();
        assert!(listings.iter().any(|row| {
            row.token_amount.as_deref() == Some(remaining_amount.as_str())
                && row.unit_price_sompi.as_deref() == Some(&spec.unit_price_sompi.to_string())
        }));
    }

    let trades = repo::kcc20_trades(&pool, Some(&wrapper_hex), None, None, None, None, 100, 0)
        .await
        .unwrap();
    assert_eq!(trades.len(), specs.len());
    for spec in &specs {
        let price_sompi = (i128::from(spec.fill_amount) * i128::from(spec.unit_price_sompi)
            / 100_000_000)
            .to_string();
        let token_amount = spec.fill_amount.to_string();
        let unit_price_sompi = spec.unit_price_sompi.to_string();
        assert!(
            trades.iter().any(|row| {
                row.token_amount.as_deref() == Some(token_amount.as_str())
                    && row.unit_price_sompi.as_deref() == Some(unit_price_sompi.as_str())
                    && row.price_sompi.as_deref() == Some(price_sompi.as_str())
            }),
            "missing trade fill amount={token_amount} unit={unit_price_sompi} price={price_sompi}; trades={trades:?}"
        );
    }

    let expected_volume: i128 = specs
        .iter()
        .map(|spec| i128::from(spec.fill_amount) * i128::from(spec.unit_price_sompi) / 100_000_000)
        .sum();
    let summaries = repo::kcc20_trade_summaries(&pool).await.unwrap();
    let summary = summaries
        .iter()
        .find(|row| row.token_id_hex == wrapper_hex)
        .unwrap();
    assert_eq!(summary.total_trades, specs.len() as i64);
    assert_eq!(summary.total_volume_sompi, expected_volume.to_string());

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity_filtered(
        &pool,
        &wrapper_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("trade".to_string()),
            side: Some("ask".to_string()),
            txid: Some(txid_hex.clone()),
            ..Default::default()
        },
        100,
        0,
    )
    .await
    .unwrap();
    assert_eq!(activity.len(), specs.len());
    for spec in &specs {
        let order_id = format!("{}:0", repeated_seed_hex(spec.previous_txid_seed));
        let price_sompi = (i128::from(spec.fill_amount) * i128::from(spec.unit_price_sompi)
            / 100_000_000)
            .to_string();
        assert!(activity.iter().any(|row| {
            row.order_id.as_deref() == Some(order_id.as_str())
                && row.token_amount.as_deref() == Some(&spec.fill_amount.to_string())
                && row.unit_price_sompi.as_deref() == Some(&spec.unit_price_sompi.to_string())
                && row.price_sompi.as_deref() == Some(price_sompi.as_str())
                && row.entrypoint.as_deref() == Some("fillAskPartial")
        }));
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_orderbook_sweep_ask_activity_for_three_full_fills(pool: PgPool) {
    assert_orderbook_sweep_ask_activity_for_specs(
        pool,
        0xe1,
        vec![
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xa1,
                available_amount: 100_000_000,
                fill_amount: 100_000_000,
                unit_price_sompi: 100_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xa2,
                available_amount: 200_000_000,
                fill_amount: 200_000_000,
                unit_price_sompi: 150_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xa3,
                available_amount: 300_000_000,
                fill_amount: 300_000_000,
                unit_price_sompi: 175_000_000,
            },
        ],
    )
    .await;
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_orderbook_sweep_ask_activity_for_four_mixed_fills(pool: PgPool) {
    assert_orderbook_sweep_ask_activity_for_specs(
        pool,
        0xe2,
        vec![
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xb1,
                available_amount: 3_317_000_000,
                fill_amount: 3_317_000_000,
                unit_price_sompi: 350_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xb2,
                available_amount: 500_000_000,
                fill_amount: 500_000_000,
                unit_price_sompi: 369_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xb3,
                available_amount: 3_000_000_000,
                fill_amount: 3_000_000_000,
                unit_price_sompi: 500_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xb4,
                available_amount: 200_000_000,
                fill_amount: 183_000_000,
                unit_price_sompi: 1_500_000_000,
            },
        ],
    )
    .await;
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_orderbook_sweep_ask_activity_has_no_small_count_limit(pool: PgPool) {
    assert_orderbook_sweep_ask_activity_for_specs(
        pool,
        0xe3,
        vec![
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc1,
                available_amount: 100_000_000,
                fill_amount: 100_000_000,
                unit_price_sompi: 110_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc2,
                available_amount: 200_000_000,
                fill_amount: 125_000_000,
                unit_price_sompi: 120_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc3,
                available_amount: 300_000_000,
                fill_amount: 300_000_000,
                unit_price_sompi: 130_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc4,
                available_amount: 400_000_000,
                fill_amount: 250_000_000,
                unit_price_sompi: 140_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc5,
                available_amount: 500_000_000,
                fill_amount: 500_000_000,
                unit_price_sompi: 150_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc6,
                available_amount: 600_000_000,
                fill_amount: 600_000_000,
                unit_price_sompi: 160_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc7,
                available_amount: 700_000_000,
                fill_amount: 550_000_000,
                unit_price_sompi: 170_000_000,
            },
            WrappedSweepAskFillSpec {
                previous_txid_seed: 0xc8,
                available_amount: 800_000_000,
                fill_amount: 800_000_000,
                unit_price_sompi: 180_000_000,
            },
        ],
    )
    .await;
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "old KCC20V2 artifact is not registered after the standard-native cutover"]
async fn persist_tx_projects_v2_holder_merge_and_replays_idempotently(pool: PgPool) {
    let source_block = insert_block(&pool, 0xd0, 100).await;
    let token = insert_covenant(
        &pool,
        0xd1,
        "kaspatest:native-token",
        Some("KCC20V2"),
        &source_block,
        100,
    )
    .await;
    let owner = [0x4b_u8; 32];
    for (txid_seed, amount) in [(0xd2, 1_000_i64), (0xd3, 500_i64), (0xd6, 250_i64)] {
        insert_active_utxo_with_state(
            &pool,
            &token,
            "kaspatest:native-holder",
            50_000_000,
            json!({
                "ownerIdentifier": hex::encode(owner),
                "identifierType": 0,
                "amount": amount.to_string(),
                "isMinter": false,
                "minterMode": 0
            }),
            &source_block,
            txid_seed,
        )
        .await;
    }

    let primary_reveal = kcc20_v2_holder_script(owner, 1_000);
    let peer_reveal = kcc20_v2_holder_script(owner, 500);
    let second_peer_reveal = kcc20_v2_holder_script(owner, 250);
    let merged_reveal = kcc20_v2_holder_script(owner, 1_750);
    let txid = "d4".repeat(32);
    let token_id_hex = hex::encode(&token);
    let merge = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400400,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("d5".repeat(32)),
        accepting_block_blue_score: Some(200),
        inputs: vec![
            RestTxInput {
                previous_outpoint_hash: "d2".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: holder_merge_signature_script(None, None, 0x55, &primary_reveal),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash: "d3".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: holder_merge_signature_script(
                    Some(0),
                    Some(1_750),
                    0x56,
                    &peer_reveal,
                ),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash: "d6".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: holder_merge_signature_script(
                    Some(0),
                    Some(1_750),
                    0x56,
                    &second_peer_reveal,
                ),
                ..Default::default()
            },
        ],
        outputs: vec![RestTxOutput {
            transaction_id: txid.clone(),
            index: 0,
            amount: 50_000_000,
            script_public_key: format!("aa20{}87", hex::encode(blake2b_256(&merged_reveal))),
            script_public_key_address: Some("kaspatest:native-merged".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(token_id_hex.clone()),
            covenant: Some(RestCovenantBinding {
                covenant_id: Some(token_id_hex),
                authorizing_input: Some(0),
            }),
        }],
        ..Default::default()
    };

    let persister = PgPersister::new(pool.clone());
    let mut invalid_merge = merge.clone();
    invalid_merge.outputs[0].script_public_key = format!("aa20{}87", "d6".repeat(32));
    assert!(persister.persist_tx(&invalid_merge).await.is_err());
    let active_after_rejection: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM covenant_utxos
           WHERE txid IN (decode($1, 'hex'), decode($2, 'hex'), decode($3, 'hex'))
             AND status = 'active'"#,
    )
    .bind("d2".repeat(32))
    .bind("d3".repeat(32))
    .bind("d6".repeat(32))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_after_rejection, 3);

    persister.persist_tx(&merge).await.unwrap();
    persister.persist_tx(&merge).await.unwrap();

    let row: (String, String, String) = sqlx::query_as(
        r#"SELECT state->>'amount', state->>'ownerIdentifier', status
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND vout = 0"#,
    )
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "1750");
    assert_eq!(row.1, hex::encode(owner));
    assert_eq!(row.2, "active");
    let holders = repo::kcc20_holders(&pool, &hex::encode(&token), 200, 0)
        .await
        .unwrap();
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0].owner_identifier, hex::encode(owner));
    assert_eq!(holders[0].amount, "1750");
    assert_eq!(holders[0].utxo_count, 1);
    let balances = repo::kcc20_balances_for_owner(&pool, &hex::encode(owner))
        .await
        .unwrap();
    let merged_balance = balances
        .iter()
        .find(|balance| balance.token_id_hex == hex::encode(&token))
        .unwrap();
    assert_eq!(merged_balance.amount, "1750");
    assert_eq!(merged_balance.utxo_count, 1);
    let spent_sources: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM covenant_utxos
           WHERE txid IN (decode($1, 'hex'), decode($2, 'hex'), decode($3, 'hex'))
             AND status = 'spent'"#,
    )
    .bind("d2".repeat(32))
    .bind("d3".repeat(32))
    .bind("d6".repeat(32))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(spent_sources, 3);

    mark_utxo_spent(&pool, 0xd4, &source_block, 0xf4).await;
    persister.persist_tx(&merge).await.unwrap();
    let replayed_spent_row: (String, String, String) = sqlx::query_as(
        r#"SELECT state->>'amount', status, encode(spent_by_txid, 'hex')
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND vout = 0"#,
    )
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replayed_spent_row.0, "1750");
    assert_eq!(replayed_spent_row.1, "spent");
    assert_eq!(replayed_spent_row.2, "f4".repeat(32));
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_tx_projects_orderbook_holder_merge(pool: PgPool) {
    let source_block = insert_block(&pool, 0xe0, 100).await;
    let wrapper = insert_covenant(
        &pool,
        0xe1,
        "kaspatest:orderbook-wrapper",
        Some("KCC20Orderbook"),
        &source_block,
        100,
    )
    .await;
    let canonical_token = vec![0x44_u8; 32];
    let owner = [0x5b_u8; 32];
    for (txid_seed, amount) in [(0xe2, 2_000_i64), (0xe3, 750_i64), (0xe6, 250_i64)] {
        insert_active_utxo_with_state(
            &pool,
            &wrapper,
            "kaspatest:orderbook-holder",
            50_000_000,
            json!({
                "canonicalTokenId": hex::encode(&canonical_token),
                "ownerIdentifier": hex::encode(owner),
                "amount": amount.to_string(),
                "mode": 0,
                "modeName": "holder",
                "unitPriceSompi": "0",
                "priceScale": "100000000"
            }),
            &source_block,
            txid_seed,
        )
        .await;
    }

    let primary_reveal = kcc20_orderbook_script(&canonical_token, owner, 2_000, 0, 0);
    let peer_reveal = kcc20_orderbook_script(&canonical_token, owner, 750, 0, 0);
    let second_peer_reveal = kcc20_orderbook_script(&canonical_token, owner, 250, 0, 0);
    let merged_reveal = kcc20_orderbook_script(&canonical_token, owner, 3_000, 0, 0);
    let txid = "e4".repeat(32);
    let wrapper_id_hex = hex::encode(&wrapper);
    let merge = RestTransaction {
        transaction_id: txid.clone(),
        block_time: 1778654400500,
        version: 1,
        is_accepted: true,
        accepting_block_hash: Some("e5".repeat(32)),
        accepting_block_blue_score: Some(201),
        inputs: vec![
            RestTxInput {
                previous_outpoint_hash: "e2".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: holder_merge_signature_script(None, None, 0x5a, &primary_reveal),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash: "e3".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: holder_merge_signature_script(
                    Some(0),
                    Some(3_000),
                    0x5b,
                    &peer_reveal,
                ),
                ..Default::default()
            },
            RestTxInput {
                previous_outpoint_hash: "e6".repeat(32),
                previous_outpoint_index: "0".into(),
                signature_script: holder_merge_signature_script(
                    Some(0),
                    Some(3_000),
                    0x5b,
                    &second_peer_reveal,
                ),
                ..Default::default()
            },
        ],
        outputs: vec![RestTxOutput {
            transaction_id: txid.clone(),
            index: 0,
            amount: 50_000_000,
            script_public_key: format!("aa20{}87", hex::encode(blake2b_256(&merged_reveal))),
            script_public_key_address: Some("kaspatest:orderbook-merged".into()),
            script_public_key_type: Some("scripthash".into()),
            covenant_id: Some(wrapper_id_hex.clone()),
            covenant: Some(RestCovenantBinding {
                covenant_id: Some(wrapper_id_hex),
                authorizing_input: Some(0),
            }),
        }],
        ..Default::default()
    };

    let persister = PgPersister::new(pool.clone());
    let mut invalid_merge = merge.clone();
    invalid_merge.outputs[0].script_public_key = format!("aa20{}87", "e6".repeat(32));
    assert!(persister.persist_tx(&invalid_merge).await.is_err());
    let active_after_rejection: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM covenant_utxos
           WHERE txid IN (decode($1, 'hex'), decode($2, 'hex'), decode($3, 'hex'))
             AND status = 'active'"#,
    )
    .bind("e2".repeat(32))
    .bind("e3".repeat(32))
    .bind("e6".repeat(32))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_after_rejection, 3);

    persister.persist_tx(&merge).await.unwrap();
    persister.persist_tx(&merge).await.unwrap();

    let row: (String, String, i64, String) = sqlx::query_as(
        r#"SELECT state->>'amount', state->>'ownerIdentifier',
                  (state->>'mode')::BIGINT, state->>'canonicalTokenId'
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND vout = 0"#,
    )
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "3000");
    assert_eq!(row.1, hex::encode(owner));
    assert_eq!(row.2, 0);
    assert_eq!(row.3, hex::encode(canonical_token));
    let holders = repo::kcc20_holders(&pool, &hex::encode(&wrapper), 200, 0)
        .await
        .unwrap();
    assert_eq!(holders.len(), 1);
    assert_eq!(holders[0].owner_identifier, hex::encode(owner));
    assert_eq!(holders[0].amount, "3000");
    assert_eq!(holders[0].utxo_count, 1);
    let balances = repo::kcc20_balances_for_owner(&pool, &hex::encode(owner))
        .await
        .unwrap();
    let merged_balance = balances
        .iter()
        .find(|balance| balance.token_id_hex == hex::encode(&wrapper))
        .unwrap();
    assert_eq!(merged_balance.amount, "3000");
    assert_eq!(merged_balance.utxo_count, 1);

    mark_utxo_spent(&pool, 0xe4, &source_block, 0xf5).await;
    persister.persist_tx(&merge).await.unwrap();
    let replayed_spent_row: (String, String, String) = sqlx::query_as(
        r#"SELECT state->>'amount', status, encode(spent_by_txid, 'hex')
           FROM covenant_utxos
           WHERE txid = decode($1, 'hex') AND vout = 0"#,
    )
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replayed_spent_row.0, "3000");
    assert_eq!(replayed_spent_row.1, "spent");
    assert_eq!(replayed_spent_row.2, "f5".repeat(32));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is not registered in the current wrapped-orderbook runtime"]
async fn persist_tx_reprocesses_v3_spent_input_for_missing_outputs(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V3"), &block, 100).await;
    let owner = [0x4b_u8; 32];
    let buyer = [0x55_u8; 32];
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-ask",
        200_000_000,
        json!({
            "ownerIdentifier": hex::encode(owner),
            "identifierType": 0,
            "amount": "150",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "minFillAmount": "25"
        }),
        &block,
        0xaa,
    )
    .await;
    mark_utxo_spent(&pool, 0xaa, &block, 0xcc).await;

    let tx = v3_partial_ask_fill_tx(owner, buyer);
    let stats = PgPersister::new(pool.clone())
        .persist_tx(&tx)
        .await
        .unwrap();
    assert_eq!(stats.utxos_spent, 0);

    let listings = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert_eq!(listings.len(), 1);
    assert_eq!(listings[0].status, "open");
    assert_eq!(listings[0].sale_address, "kaspatest:ask-continuation");
    assert_eq!(listings[0].token_amount.as_deref(), Some("125"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "KCC20Sale is retired after the standard-native cutover"]
async fn kcc20_listings_exposes_terminal_sale_status(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20"), &block, 100).await;
    let sale = insert_covenant(&pool, 3, "kaspatest:sale", Some("KCC20Sale"), &block, 101).await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "seller": "11".repeat(32),
        "tokenId": hex::encode(&token),
        "tokenAmount": "250",
        "priceSompi": "100000000"
    }))
    .bind(&sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(&pool, &sale, 0xfe, &block, 200, "spend", Some("buy")).await;

    let rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    let close_txid = "fe".repeat(32);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "filled");
    assert_eq!(rows[0].close_txid_hex.as_deref(), Some(close_txid.as_str()));
    assert_eq!(rows[0].close_entrypoint.as_deref(), Some("buy"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "KCC20SaleV2 is retired after the standard-native cutover"]
async fn kcc20_listings_exposes_v2_terminal_sale_status(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V2"), &block, 100).await;
    let sale = insert_covenant(&pool, 3, "kaspatest:sale", None, &block, 101).await;
    let malformed_sale =
        insert_covenant(&pool, 4, "kaspatest:malformed-sale", None, &block, 102).await;
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20SaleV2',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20SaleV2",
        "args": [
            { "name": "listingSeller", "type": "pubkey", "value": "11".repeat(32) },
            { "name": "tokenId", "type": "byte[32]", "value": hex::encode(&token) },
            { "name": "tokenAmount", "type": "u64", "value": "250" },
            { "name": "listingPriceSompi", "type": "u64", "value": "100000000" }
        ]
    }))
    .bind(&sale)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20SaleV2',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20SaleV2",
        "args": { "name": "tokenId", "type": "byte[32]", "value": hex::encode(&token) }
    }))
    .bind(&malformed_sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(&pool, &sale, 0xfe, &block, 200, "spend", Some("buyListing")).await;

    let rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    let close_txid = "fe".repeat(32);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "filled");
    assert_eq!(rows[0].close_txid_hex.as_deref(), Some(close_txid.as_str()));
    assert_eq!(rows[0].close_entrypoint.as_deref(), Some("buyListing"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "KCC20SaleV2 is retired after the standard-native cutover"]
async fn kcc20_listings_follows_v2_sale_continuation_status(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V2"), &block, 100).await;
    let sale = insert_covenant(&pool, 3, "kaspatest:sale", None, &block, 101).await;
    let activated_sale = insert_covenant(
        &pool,
        4,
        "kaspatest:activated-sale",
        Some("KCC20SaleV2"),
        &block,
        102,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20SaleV2',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20SaleV2",
        "args": [
            { "name": "listingSeller", "type": "pubkey", "value": "11".repeat(32) },
            { "name": "tokenId", "type": "byte[32]", "value": hex::encode(&token) },
            { "name": "tokenAmount", "type": "u64", "value": "250" },
            { "name": "listingPriceSompi", "type": "u64", "value": "100000000" }
        ]
    }))
    .bind(&sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(
        &pool,
        &sale,
        0xee,
        &block,
        200,
        "spend",
        Some("activateListing"),
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET genesis_txid = $1
           WHERE covenant_id = $2"#,
    )
    .bind(vec![0xee_u8; 32])
    .bind(&activated_sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(
        &pool,
        &activated_sale,
        0xfe,
        &block,
        300,
        "spend",
        Some("buyListing"),
    )
    .await;

    let rows = repo::kcc20_listings(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    let close_txid = "fe".repeat(32);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sale_covenant_id_hex, hex::encode(&sale));
    assert_eq!(rows[0].status, "filled");
    assert_eq!(rows[0].close_txid_hex.as_deref(), Some(close_txid.as_str()));
    assert_eq!(rows[0].close_entrypoint.as_deref(), Some("buyListing"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "KCC20BuyOrder is retired after the standard-native cutover"]
async fn kcc20_bids_exposes_buy_order_as_orderbook_bid(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V2"), &block, 100).await;
    let bid = insert_covenant(
        &pool,
        3,
        "kaspatest:bid",
        Some("KCC20BuyOrder"),
        &block,
        101,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "orderBuyer": "22".repeat(32),
        "orderedTokenId": hex::encode(&token),
        "orderedTokenAmount": "500",
        "offerPriceSompi": "1000000000"
    }))
    .bind(&bid)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(&pool, &bid, "kaspatest:bid", 1_000_000_000, &block, 0xb1).await;

    let rows = repo::kcc20_bids(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template_name.as_deref(), Some("KCC20BuyOrder"));
    assert_eq!(rows[0].market_side, "bid");
    assert_eq!(rows[0].status, "open");
    assert_eq!(rows[0].token_amount.as_deref(), Some("500"));
    assert_eq!(rows[0].price_sompi.as_deref(), Some("1000000000"));
    assert_eq!(rows[0].unit_price_sompi, None);
    assert_eq!(rows[0].min_fill_amount, None);
    assert_eq!(rows[0].bid_value_sompi.as_deref(), Some("1000000000"));
    assert_eq!(rows[0].close_entrypoint, None);

    let buyer_rows = repo::kcc20_bids(&pool, Some(&hex::encode(&token)), Some(&"22".repeat(32)))
        .await
        .unwrap();
    let other_buyer_rows =
        repo::kcc20_bids(&pool, Some(&hex::encode(&token)), Some(&"11".repeat(32)))
            .await
            .unwrap();
    assert_eq!(buyer_rows.len(), 1);
    assert!(other_buyer_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is retired after the standard-native cutover"]
async fn kcc20_bids_exposes_v3_bid_state(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V3"), &block, 100).await;
    let buyer = "22".repeat(32);
    let fee_ticket_id = "55".repeat(32);
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-bid",
        500_000_000,
        json!({
            "ownerIdentifier": buyer.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "500",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "1000000",
            "minFillAmount": "50",
            "feeTicketId": fee_ticket_id.clone(),
            "feeBps": 200
        }),
        &block,
        0xb5,
    )
    .await;

    let rows = repo::kcc20_bids(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template_name.as_deref(), Some("KCC20V3"));
    assert_eq!(rows[0].order_id, format!("{}:0", "b5".repeat(32)));
    assert_eq!(rows[0].txid_hex.as_deref().unwrap(), "b5".repeat(32));
    assert_eq!(rows[0].vout, Some(0));
    assert_eq!(rows[0].market_side, "bid");
    assert_eq!(rows[0].token_id_hex, hex::encode(&token));
    assert_eq!(rows[0].buyer.as_deref(), Some(buyer.as_str()));
    assert_eq!(rows[0].token_amount.as_deref(), Some("500"));
    assert_eq!(rows[0].price_sompi.as_deref(), Some("500000000"));
    assert_eq!(rows[0].unit_price_sompi.as_deref(), Some("1000000"));
    assert_eq!(rows[0].min_fill_amount.as_deref(), Some("50"));
    assert_eq!(
        rows[0].fee_ticket_id.as_deref(),
        Some(fee_ticket_id.as_str())
    );
    assert_eq!(rows[0].bid_value_sompi.as_deref(), Some("500000000"));
    assert_eq!(rows[0].status, "open");

    let buyer_rows = repo::kcc20_bids(&pool, Some(&hex::encode(&token)), Some(&buyer))
        .await
        .unwrap();
    let other_buyer_rows =
        repo::kcc20_bids(&pool, Some(&hex::encode(&token)), Some(&"11".repeat(32)))
            .await
            .unwrap();
    assert_eq!(buyer_rows.len(), 1);
    assert!(other_buyer_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is retired after the standard-native cutover"]
async fn kcc20_owner_orders_filters_open_orderbook_orders_by_owner_and_pages(pool: PgPool) {
    let token_block = insert_block(&pool, 1, 100).await;
    let ask_block = insert_block(&pool, 2, 200).await;
    let bid_block = insert_block(&pool, 3, 300).await;
    let token = insert_covenant(
        &pool,
        4,
        "kaspatest:token",
        Some("KCC20V3"),
        &token_block,
        100,
    )
    .await;
    let token_hex = hex::encode(&token);
    let owner = "22".repeat(32);
    let other_owner = "33".repeat(32);

    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-ask",
        50_000_000,
        json!({
            "ownerIdentifier": owner.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "250",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "minFillAmount": "25"
        }),
        &ask_block,
        0xc1,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-bid",
        500_000_000,
        json!({
            "ownerIdentifier": owner.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "500",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "1000000",
            "minFillAmount": "50"
        }),
        &bid_block,
        0xc2,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:other-orderbook-ask",
        50_000_000,
        json!({
            "ownerIdentifier": other_owner.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "900",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000"
        }),
        &bid_block,
        0xc3,
    )
    .await;

    let rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].side, "bid");
    assert_eq!(rows[0].order_id, format!("{}:0", "c2".repeat(32)));
    assert_eq!(rows[0].owner.as_deref(), Some(owner.as_str()));
    assert_eq!(rows[0].remaining_token_amount.as_deref(), Some("500"));
    assert_eq!(rows[1].side, "ask");
    assert_eq!(rows[1].order_id, format!("{}:0", "c1".repeat(32)));

    let open_range_ignored = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        Some(1),
        Some(2),
    )
    .await
    .unwrap();
    assert_eq!(open_range_ignored.len(), 2);

    let second_page = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        1,
        1,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].order_id, format!("{}:0", "c1".repeat(32)));

    let other_rows = repo::kcc20_owner_orders(
        &pool,
        &other_owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(other_rows.len(), 1);
    assert_eq!(other_rows[0].token_amount.as_deref(), Some("900"));

    let filled_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("filled"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(filled_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_orders_projection_matches_raw_sources_and_filters(pool: PgPool) {
    let token_block = insert_block(&pool, 0xd1, 100).await;
    let legacy_ask_block = insert_block(&pool, 0xd2, 200).await;
    let legacy_bid_block = insert_block(&pool, 0xd3, 300).await;
    let orderbook_ask_block = insert_block(&pool, 0xd4, 400).await;
    let orderbook_bid_block = insert_block(&pool, 0xd5, 500).await;
    let token = insert_covenant(
        &pool,
        0xd1,
        "kaspatest:owner-orders-token",
        Some("KCC20Wrapper"),
        &token_block,
        100,
    )
    .await;
    let token_hex = hex::encode(&token);
    let owner = "22".repeat(32);
    let other_owner = "33".repeat(32);

    let legacy_ask = insert_covenant(
        &pool,
        0xd6,
        "kaspatest:owner-orders-legacy-ask",
        Some("KCC20Sale"),
        &legacy_ask_block,
        200,
    )
    .await;
    let legacy_bid = insert_covenant(
        &pool,
        0xd7,
        "kaspatest:owner-orders-legacy-bid",
        Some("KCC20BuyOrder"),
        &legacy_bid_block,
        300,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET claim_verified = TRUE,
               claim_verified_at_ms = created_at_ms,
               constructor_args = CASE
                   WHEN covenant_id = $1 THEN $3
                   WHEN covenant_id = $2 THEN $4
                   ELSE constructor_args
               END
           WHERE covenant_id IN ($1, $2)"#,
    )
    .bind(&legacy_ask)
    .bind(&legacy_bid)
    .bind(json!({
        "seller": owner.clone(),
        "tokenId": token_hex.clone(),
        "tokenAmount": "250",
        "priceSompi": "100000000"
    }))
    .bind(json!({
        "buyer": owner.clone(),
        "tokenId": token_hex.clone(),
        "tokenAmount": "500",
        "priceSompi": "200000000"
    }))
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(
        &pool,
        &legacy_ask,
        "kaspatest:owner-orders-legacy-ask",
        50_000_000,
        &legacy_ask_block,
        0xd8,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:owner-orders-sale-token",
        50_000_000,
        json!({
            "stateOwner": hex::encode(&legacy_ask),
            "stateOwnerType": 2,
            "stateAmount": "250"
        }),
        &legacy_ask_block,
        0xd9,
    )
    .await;
    insert_active_utxo(
        &pool,
        &legacy_bid,
        "kaspatest:owner-orders-legacy-bid",
        200_000_000,
        &legacy_bid_block,
        0xda,
    )
    .await;

    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:owner-orders-standard-ask",
        50_000_000,
        json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": owner.clone(),
            "identifierType": 0,
            "amount": "125",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "minFillAmount": "25",
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &orderbook_ask_block,
        0xdb,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:owner-orders-standard-bid",
        75_000_000,
        json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": owner.clone(),
            "identifierType": 0,
            "amount": "300",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "2000000",
            "minFillAmount": "30",
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &orderbook_bid_block,
        0xdc,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:owner-orders-other-owner",
        50_000_000,
        json!({
            "canonicalTokenId": token_hex.clone(),
            "ownerIdentifier": other_owner.clone(),
            "identifierType": 0,
            "amount": "900",
            "mode": 2,
            "modeName": "ask",
            "unitPriceSompi": "1000000",
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &orderbook_bid_block,
        0xdd,
    )
    .await;

    let raw_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(raw_rows.len(), 4);

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    let initial_dirty_id: i64 = sqlx::query_scalar(
        "SELECT MAX(id) FROM kcc20_projection_dirty WHERE reason = 'owner_orders_projection_added'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_orders_projection_name(),
        initial_dirty_id,
    )
    .await
    .unwrap();

    let projected_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        Some(1),
        Some(2),
    )
    .await
    .unwrap();
    assert_eq!(projected_rows.len(), 4);
    assert_eq!(
        projected_rows
            .iter()
            .map(|row| (
                row.order_id.as_str(),
                row.side.as_str(),
                row.status.as_str(),
                row.token_amount.as_deref(),
                row.remaining_token_amount.as_deref(),
            ))
            .collect::<Vec<_>>(),
        raw_rows
            .iter()
            .map(|row| (
                row.order_id.as_str(),
                row.side.as_str(),
                row.status.as_str(),
                row.token_amount.as_deref(),
                row.remaining_token_amount.as_deref(),
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(projected_rows[0].order_id, format!("{}:0", "dc".repeat(32)));
    assert_eq!(projected_rows[0].side, "bid");
    assert_eq!(
        projected_rows[0].unit_price_sompi.as_deref(),
        Some("2000000")
    );
    assert_eq!(projected_rows[1].order_id, format!("{}:0", "db".repeat(32)));
    assert_eq!(projected_rows[1].side, "ask");
    assert_eq!(projected_rows[2].order_id, hex::encode(&legacy_bid));
    assert_eq!(projected_rows[2].side, "bid");
    assert_eq!(projected_rows[3].order_id, hex::encode(&legacy_ask));
    assert_eq!(projected_rows[3].side, "ask");

    let second_page = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        2,
        2,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(second_page.len(), 2);
    assert_eq!(second_page[0].order_id, hex::encode(&legacy_bid));
    assert_eq!(second_page[1].order_id, hex::encode(&legacy_ask));

    let filled_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("filled"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(filled_rows.is_empty());

    let other_rows = repo::kcc20_owner_orders(
        &pool,
        &other_owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(other_rows.len(), 1);
    assert_eq!(other_rows[0].order_id, format!("{}:0", "dd".repeat(32)));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "fixed-lot orders are retired after the standard-native cutover"]
async fn kcc20_owner_orders_filters_legacy_terminal_statuses(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V2"), &block, 100).await;
    let sale = insert_covenant(&pool, 3, "kaspatest:sale", Some("KCC20Sale"), &block, 101).await;
    let owner = "11".repeat(32);
    let token_hex = hex::encode(&token);
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "seller": owner.clone(),
        "tokenId": token_hex.clone(),
        "tokenAmount": "250",
        "priceSompi": "100000000"
    }))
    .bind(&sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_action(&pool, &sale, 0xfe, &block, 200, "spend", Some("buy")).await;

    let rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("filled"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].side, "ask");
    assert_eq!(rows[0].status, "filled");
    let close_txid = "fe".repeat(32);
    assert_eq!(rows[0].close_txid_hex.as_deref(), Some(close_txid.as_str()));
    assert_eq!(rows[0].close_entrypoint.as_deref(), Some("buy"));
    let created_at_ms = rows[0].created_at_ms;

    let ranged_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("filled"),
        10,
        0,
        Some(created_at_ms),
        Some(created_at_ms + 1),
    )
    .await
    .unwrap();
    assert_eq!(ranged_rows.len(), 1);
    let excluded_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("filled"),
        10,
        0,
        Some(created_at_ms + 1),
        None,
    )
    .await
    .unwrap();
    assert!(excluded_rows.is_empty());

    let open_rows = repo::kcc20_owner_orders(
        &pool,
        &owner,
        Some(&token_hex),
        Some("open"),
        10,
        0,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(open_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_bids_exposes_orderbook_bid_state(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-token",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let canonical = [0x44u8; 32];
    let canonical_hex = hex::encode(canonical);
    let buyer = "22".repeat(32);
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:wrapped-orderbook-bid",
        500_000_000,
        json!({
            "canonicalTokenId": canonical_hex.clone(),
            "ownerIdentifier": buyer.clone(),
            "identifierType": 0,
            "identifierTypeName": "pubkey",
            "amount": "500",
            "mode": 3,
            "modeName": "bid",
            "unitPriceSompi": "1000000",
            "supplyBacking": "kcc20WrapperReserve",
            "feeBps": 200
        }),
        &block,
        0xb9,
    )
    .await;

    let rows = repo::kcc20_bids(&pool, Some(&canonical_hex), None)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template_name.as_deref(), Some("KCC20Orderbook"));
    assert_eq!(rows[0].market_side, "bid");
    assert_eq!(rows[0].token_id_hex, canonical_hex);
    assert_eq!(rows[0].buyer.as_deref(), Some(buyer.as_str()));
    assert_eq!(rows[0].token_amount.as_deref(), Some("500"));
    assert_eq!(rows[0].price_sompi.as_deref(), Some("500000000"));
    assert_eq!(rows[0].bid_value_sompi.as_deref(), Some("500000000"));
    assert_eq!(rows[0].status, "open");
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "standalone KCC20V3 is retired after the standard-native cutover"]
async fn kcc20_bids_v3_filters_spent_non_bid_and_other_tokens(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let spent_block = insert_block(&pool, 2, 200).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V3"), &block, 100).await;
    let other_token = insert_covenant(
        &pool,
        3,
        "kaspatest:other-token",
        Some("KCC20V3"),
        &block,
        100,
    )
    .await;
    let buyer = "22".repeat(32);
    let bid_state = json!({
        "ownerIdentifier": buyer.clone(),
        "identifierType": 0,
        "identifierTypeName": "pubkey",
        "amount": "500",
        "mode": 3,
        "modeName": "bid",
        "unitPriceSompi": "1000000",
        "minFillAmount": "50"
    });
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-bid-open",
        500_000_000,
        bid_state.clone(),
        &block,
        0xb5,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-bid-spent",
        500_000_000,
        bid_state.clone(),
        &block,
        0xb6,
    )
    .await;
    mark_utxo_spent(&pool, 0xb6, &spent_block, 0xf7).await;
    insert_active_utxo_with_state(
        &pool,
        &token,
        "kaspatest:orderbook-root",
        500_000_000,
        json!({
            "ownerIdentifier": buyer.clone(),
            "identifierType": 0,
            "amount": "500",
            "mode": 1,
            "modeName": "root",
            "unitPriceSompi": "0",
            "minFillAmount": "0"
        }),
        &block,
        0xb7,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &other_token,
        "kaspatest:orderbook-other-bid",
        500_000_000,
        bid_state,
        &block,
        0xb8,
    )
    .await;

    let rows = repo::kcc20_bids(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].bid_address, "kaspatest:orderbook-bid-open");
    assert_eq!(rows[0].token_amount.as_deref(), Some("500"));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_orderbook_cancel_actions_close_orders_and_feed_activity(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let spent_block = insert_block(&pool, 2, 200).await;
    let wrapper = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapped-token",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let canonical = [0x44u8; 32];
    let canonical_hex = hex::encode(canonical);
    let seller = "11".repeat(32);
    let buyer = "22".repeat(32);
    let full_ask_state = json!({
        "canonicalTokenId": canonical_hex.clone(),
        "ownerIdentifier": seller.clone(),
        "identifierType": 0,
        "identifierTypeName": "pubkey",
        "amount": "250",
        "mode": 2,
        "modeName": "ask",
        "unitPriceSompi": "1000000",
        "supplyBacking": "kcc20WrapperReserve",
        "feeBps": 200
    });
    let remaining_ask_state = json!({
        "canonicalTokenId": canonical_hex.clone(),
        "ownerIdentifier": seller.clone(),
        "identifierType": 0,
        "identifierTypeName": "pubkey",
        "amount": "125",
        "mode": 2,
        "modeName": "ask",
        "unitPriceSompi": "1000000",
        "supplyBacking": "kcc20WrapperReserve",
        "feeBps": 200
    });
    let bid_state = json!({
        "canonicalTokenId": canonical_hex.clone(),
        "ownerIdentifier": buyer.clone(),
        "identifierType": 0,
        "identifierTypeName": "pubkey",
        "amount": "500",
        "mode": 3,
        "modeName": "bid",
        "unitPriceSompi": "1000000",
        "supplyBacking": "kcc20WrapperReserve",
        "feeBps": 200
    });
    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:wrapped-full-ask",
        50_000_000,
        full_ask_state.clone(),
        &block,
        0xa1,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:wrapped-remaining-ask",
        50_000_000,
        remaining_ask_state.clone(),
        &block,
        0xa2,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:wrapped-bid",
        500_000_000,
        bid_state.clone(),
        &block,
        0xb1,
    )
    .await;

    mark_utxo_spent(&pool, 0xa1, &spent_block, 0xc1).await;
    mark_utxo_spent(&pool, 0xa2, &spent_block, 0xc2).await;
    mark_utxo_spent(&pool, 0xb1, &spent_block, 0xc3).await;
    insert_action_full(
        &pool,
        &wrapper,
        0xc1,
        &spent_block,
        1778654400200,
        "spend",
        Some("cancelAskByOwnerSig"),
        Some(json!({"previousOutpoint": {"hash": "a1".repeat(32), "index": 0}})),
        None,
        Some(full_ask_state),
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        0xc2,
        &spent_block,
        1778654400300,
        "spend",
        Some("cancelAskByOwnerSig"),
        Some(json!({"previousOutpoint": {"hash": "a2".repeat(32), "index": 0}})),
        None,
        Some(remaining_ask_state),
    )
    .await;
    insert_action_full(
        &pool,
        &wrapper,
        0xc3,
        &spent_block,
        1778654400400,
        "spend",
        Some("cancelBidByOwnerSig"),
        Some(json!({"previousOutpoint": {"hash": "b1".repeat(32), "index": 0}})),
        None,
        Some(bid_state.clone()),
    )
    .await;

    let listings = repo::kcc20_listings(&pool, Some(&canonical_hex), None)
        .await
        .unwrap();
    assert!(listings.is_empty());
    let bids = repo::kcc20_bids(&pool, Some(&canonical_hex), None)
        .await
        .unwrap();
    assert!(bids.is_empty());

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let activity = repo::kcc20_activity(&pool, &canonical_hex, 10, 0)
        .await
        .unwrap();
    let ask_cancels: Vec<_> = activity
        .iter()
        .filter(|row| {
            row.kind == "orderCancelled"
                && row.side.as_deref() == Some("ask")
                && row.entrypoint.as_deref() == Some("cancelAskByOwnerSig")
        })
        .collect();
    assert_eq!(ask_cancels.len(), 2);
    let full_ask_order_id = format!("{}:0", "a1".repeat(32));
    let remaining_ask_order_id = format!("{}:0", "a2".repeat(32));
    assert!(ask_cancels.iter().any(|row| {
        row.order_id.as_deref() == Some(full_ask_order_id.as_str())
            && row.token_amount.as_deref() == Some("250")
    }));
    assert!(ask_cancels.iter().any(|row| {
        row.order_id.as_deref() == Some(remaining_ask_order_id.as_str())
            && row.token_amount.as_deref() == Some("125")
    }));
    let bid_cancel = activity
        .iter()
        .find(|row| {
            row.kind == "orderCancelled"
                && row.side.as_deref() == Some("bid")
                && row.entrypoint.as_deref() == Some("cancelBidByOwnerSig")
        })
        .unwrap();
    let bid_order_id = format!("{}:0", "b1".repeat(32));
    assert_eq!(bid_cancel.order_id.as_deref(), Some(bid_order_id.as_str()));
    assert_eq!(bid_cancel.owner.as_deref(), Some(buyer.as_str()));
    assert_eq!(bid_cancel.token_amount.as_deref(), Some("500"));
    assert_eq!(bid_cancel.price_sompi.as_deref(), Some("500000000"));

    let filtered_ask_cancels = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("orderCancelled".to_string()),
            side: Some("ask".to_string()),
            entrypoint: Some("cancelAskByOwnerSig".to_string()),
            owner: Some(seller.clone()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(filtered_ask_cancels.len(), 2);
    assert!(filtered_ask_cancels
        .iter()
        .all(|row| row.kind == "orderCancelled"
            && row.side.as_deref() == Some("ask")
            && row.entrypoint.as_deref() == Some("cancelAskByOwnerSig")
            && row.owner.as_deref() == Some(seller.as_str())));

    let filtered_bid_cancel = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            txid: Some("c3".repeat(32).to_ascii_uppercase()),
            order_id: Some(bid_order_id.to_ascii_uppercase()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(filtered_bid_cancel.len(), 1);
    assert_eq!(
        filtered_bid_cancel[0].entrypoint.as_deref(),
        Some("cancelBidByOwnerSig")
    );

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let materialized_bid_cancel = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("orderCancelled".to_string()),
            side: Some("bid".to_string()),
            owner: Some(buyer.to_ascii_uppercase()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(materialized_bid_cancel.len(), 1);
    assert_eq!(
        materialized_bid_cancel[0].order_id.as_deref(),
        Some(bid_order_id.as_str())
    );
    let materialized_trading_scope = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            scope: Some("trading".to_string()),
            side: Some("bid".to_string()),
            owner: Some(buyer.to_ascii_uppercase()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(materialized_trading_scope.len(), 1);
    assert_eq!(
        materialized_trading_scope[0].order_id.as_deref(),
        Some(bid_order_id.as_str())
    );
    let conflicting_token_scope = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            scope: Some("token".to_string()),
            kind: Some("orderCancelled".to_string()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert!(conflicting_token_scope.is_empty());

    let owner_actions = repo::kcc20_actions_for_owner(
        &pool,
        &seller,
        Some(&canonical_hex),
        Some("orderCancel"),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(owner_actions.len(), 2);
    assert!(owner_actions.iter().all(|row| {
        row.action == "orderCancel" && row.entrypoint.as_deref() == Some("cancelAskByOwnerSig")
    }));

    let buyer_actions = repo::kcc20_actions_for_owner(
        &pool,
        &buyer,
        Some(&canonical_hex),
        Some("orderCancel"),
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(buyer_actions.len(), 1);
    assert_eq!(
        buyer_actions[0].entrypoint.as_deref(),
        Some("cancelBidByOwnerSig")
    );

    insert_action_full(
        &pool,
        &wrapper,
        0xc4,
        &spent_block,
        1778654400500,
        "spend",
        Some("cancelBidByOwnerSig"),
        Some(json!({"previousOutpoint": {"hash": "b2".repeat(32), "index": 0}})),
        None,
        Some(bid_state),
    )
    .await;
    repo::mark_kcc20_projection_dirty(&pool, "kcc20_persist", Some(&vec![0xc4; 32]))
        .await
        .unwrap();
    let projected_bid_cancel_before_refresh = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("orderCancelled".to_string()),
            side: Some("bid".to_string()),
            owner: Some(buyer.to_ascii_uppercase()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(projected_bid_cancel_before_refresh.len(), 1);
    let second_bid_order_id = format!("{}:0", "b2".repeat(32));
    assert!(projected_bid_cancel_before_refresh
        .iter()
        .any(|row| row.order_id.as_deref() == Some(bid_order_id.as_str())));
    assert!(!projected_bid_cancel_before_refresh
        .iter()
        .any(|row| row.order_id.as_deref() == Some(second_bid_order_id.as_str())));

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let refreshed_bid_cancels = repo::kcc20_activity_filtered(
        &pool,
        &canonical_hex,
        &repo::Kcc20ActivityFilter {
            kind: Some("orderCancelled".to_string()),
            side: Some("bid".to_string()),
            owner: Some(buyer.to_ascii_uppercase()),
            ..Default::default()
        },
        10,
        0,
    )
    .await
    .unwrap();
    assert_eq!(refreshed_bid_cancels.len(), 2);
    assert!(refreshed_bid_cancels
        .iter()
        .any(|row| row.order_id.as_deref() == Some(bid_order_id.as_str())));
    assert!(refreshed_bid_cancels
        .iter()
        .any(|row| row.order_id.as_deref() == Some(second_bid_order_id.as_str())));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "KCC20BuyOrder is retired after the standard-native cutover"]
async fn kcc20_bids_falls_back_to_claimed_args_when_constructor_args_is_json_null(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let token = insert_covenant(&pool, 2, "kaspatest:token", Some("KCC20V2"), &block, 100).await;
    let bid = insert_covenant(&pool, 3, "kaspatest:bid", None, &block, 101).await;
    let malformed_bid =
        insert_covenant(&pool, 4, "kaspatest:malformed-bid", None, &block, 102).await;
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20BuyOrder',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20BuyOrder",
        "args": [
            { "name": "orderBuyer", "type": "pubkey", "value": "22".repeat(32) },
            { "name": "tokenId", "type": "byte[32]", "value": hex::encode(&token) },
            { "name": "tokenAmount", "type": "u64", "value": "500" },
            { "name": "offerPriceSompi", "type": "u64", "value": "1000000000" }
        ]
    }))
    .bind(&bid)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'KCC20BuyOrder',
               constructor_args = 'null'::jsonb,
               claimed_args = $1
           WHERE covenant_id = $2"#,
    )
    .bind(json!({
        "tmpl": "KCC20BuyOrder",
        "args": { "name": "tokenId", "type": "byte[32]", "value": hex::encode(&token) }
    }))
    .bind(&malformed_bid)
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::kcc20_bids(&pool, Some(&hex::encode(&token)), None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template_name.as_deref(), Some("KCC20BuyOrder"));
    assert_eq!(rows[0].token_id_hex, hex::encode(&token));
    assert_eq!(rows[0].token_amount.as_deref(), Some("500"));
}

// ---------- repo::counts ---------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn counts_sums_each_table(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov1 = insert_covenant(&pool, 2, "kaspatest:p1", None, &block, 100).await;
    let cov2 = insert_covenant(&pool, 3, "kaspatest:p2", None, &block, 200).await;
    insert_active_utxo(&pool, &cov1, "kaspatest:p1", 100, &block, 0xa1).await;
    insert_active_utxo(&pool, &cov2, "kaspatest:p2", 200, &block, 0xa2).await;
    insert_action(&pool, &cov1, 0x11, &block, 100, "deploy", None).await;
    insert_action(&pool, &cov2, 0x12, &block, 200, "deploy", None).await;
    insert_action(&pool, &cov2, 0x13, &block, 300, "spend", Some("release")).await;

    let c = repo::counts(&pool).await.unwrap();
    assert_eq!(c.covenants, 2);
    assert_eq!(c.active_utxos, 2);
    assert_eq!(c.actions, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn health_snapshot_includes_scanner_and_classification_counts(pool: PgPool) {
    let older_block = insert_block(&pool, 1, 95).await;
    let latest_block = insert_block(&pool, 2, 100).await;
    let unknown_unrevealed =
        insert_covenant(&pool, 3, "kaspatest:punrevealed", None, &older_block, 95).await;
    let unknown_unmatched =
        insert_covenant(&pool, 4, "kaspatest:punmatched", None, &latest_block, 100).await;
    let covenant_matched = insert_covenant(
        &pool,
        5,
        "kaspatest:pmatched",
        Some("Escrow"),
        &latest_block,
        100,
    )
    .await;

    sqlx::query("UPDATE covenants SET classification_status = 'unmatched' WHERE covenant_id = $1")
        .bind(&unknown_unmatched)
        .execute(&pool)
        .await
        .unwrap();
    insert_action(
        &pool,
        &covenant_matched,
        0x21,
        &latest_block,
        1778654400999,
        "spend",
        Some("release"),
    )
    .await;
    insert_active_utxo(
        &pool,
        &unknown_unrevealed,
        "kaspatest:punrevealed",
        100,
        &older_block,
        0xa1,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO indexer_state (key, value, updated_at_ms)
           VALUES ('chain_scan_cursor', $1, 1778654412345)"#,
    )
    .bind(json!({
        "blue_score": 98,
        "rest_database_blue_score": 140
    }))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ANALYZE covenant_utxos")
        .execute(&pool)
        .await
        .unwrap();

    let h = repo::health_snapshot(&pool).await.unwrap();
    assert_eq!(h.counts.covenants, 3);
    assert_eq!(h.counts.active_utxos, 1);
    assert_eq!(h.counts.actions, 1);
    assert_eq!(h.scanner.cursor_key.as_deref(), Some("chain_scan_cursor"));
    assert_eq!(h.scanner.cursor_blue_score, Some(98));
    assert_eq!(h.scanner.rest_database_blue_score, Some(140));
    assert_eq!(h.scanner.cursor_updated_at_ms, Some(1778654412345));
    assert!(h.scanner.cursor_age_ms.is_some_and(|age| age > 0));
    assert!(!h.scanner.rest_observation_fresh);
    assert!(h.scanner.live_acceptance_observed_at_ms.is_none());
    assert!(!h.scanner.live_acceptance_fresh);
    assert_eq!(h.scanner.latest_block_blue_score, Some(100));
    assert_eq!(h.scanner.latest_block_time_ms, Some(1778654400100));
    assert_eq!(h.scanner.latest_action_time_ms, Some(1778654400999));
    assert_eq!(h.scanner.db_cursor_lag_blocks, None);
    assert_eq!(h.unknown.total, 2);
    assert_eq!(h.unknown.unrevealed, 1);
    assert_eq!(h.unknown.unmatched, 1);

    let mut buckets: Vec<_> = h
        .classifications
        .iter()
        .map(|b| {
            (
                b.classification_kind.as_str(),
                b.classification_status.as_str(),
                b.count,
            )
        })
        .collect();
    buckets.sort();
    assert_eq!(
        buckets,
        vec![
            ("covenant", "matched", 1),
            ("unknown", "unmatched", 1),
            ("unknown", "unrevealed", 1),
        ]
    );

    let scanner = repo::scanner_health(&pool).await.unwrap();
    assert_eq!(scanner.cursor_key.as_deref(), Some("chain_scan_cursor"));
    assert_eq!(scanner.cursor_blue_score, Some(98));
    assert_eq!(scanner.rest_database_blue_score, Some(140));
    assert_eq!(scanner.cursor_updated_at_ms, Some(1778654412345));
    assert_eq!(scanner.latest_block_blue_score, Some(100));
    assert_eq!(scanner.latest_block_time_ms, Some(1778654400100));
    assert_eq!(scanner.latest_action_time_ms, Some(1778654400999));
    assert!(!scanner.rest_observation_fresh);
    assert_eq!(scanner.db_cursor_lag_blocks, None);
}

#[sqlx::test(migrations = "./migrations")]
async fn scanner_health_prefers_realtime_then_live_then_historical(pool: PgPool) {
    insert_block(&pool, 1, 100).await;
    sqlx::query(
        r#"INSERT INTO indexer_state (key, value, updated_at_ms)
           VALUES
             ('chain_scan_cursor', $1, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
             ('chain_live_scan_cursor', $2, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
             ('chain_realtime_tip_cursor', $3, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)"#,
    )
    .bind(json!({"blue_score": 25, "rest_database_blue_score": 100}))
    .bind(json!({"blue_score": 99, "rest_database_blue_score": 100}))
    .bind(json!({"blue_score": 100, "rest_database_blue_score": 100}))
    .execute(&pool)
    .await
    .unwrap();

    let realtime = repo::scanner_health(&pool).await.unwrap();
    assert_eq!(
        realtime.cursor_key.as_deref(),
        Some("chain_realtime_tip_cursor")
    );
    assert_eq!(realtime.cursor_blue_score, Some(100));
    assert_eq!(realtime.db_cursor_lag_blocks, Some(0));
    assert!(realtime.cursor_age_ms.is_some_and(|age| age < 5_000));

    sqlx::query(
        "INSERT INTO indexer_state (key, value, updated_at_ms) VALUES \
         ('chain_live_repair_cursor', '{\"blue_score\":60,\"rest_database_blue_score\":100}', \
          EXTRACT(EPOCH FROM NOW())::BIGINT * 1000), \
         ('chain_live_near_tip_repair_cursor', \
          '{\"blue_score\":98,\"rest_database_blue_score\":100}', \
          EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let near_tip = repo::scanner_health(&pool).await.unwrap();
    assert_eq!(
        near_tip.cursor_key.as_deref(),
        Some("chain_live_near_tip_repair_cursor")
    );
    assert_eq!(near_tip.cursor_blue_score, Some(98));
    assert_eq!(near_tip.db_cursor_lag_blocks, Some(2));
    sqlx::query(
        "DELETE FROM indexer_state WHERE key IN \
         ('chain_live_near_tip_repair_cursor', 'chain_live_repair_cursor')",
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query("DELETE FROM indexer_state WHERE key = 'chain_realtime_tip_cursor'")
        .execute(&pool)
        .await
        .unwrap();
    let live = repo::scanner_health(&pool).await.unwrap();
    assert_eq!(live.cursor_key.as_deref(), Some("chain_live_scan_cursor"));
    assert_eq!(live.cursor_blue_score, Some(99));
    assert_eq!(live.db_cursor_lag_blocks, Some(1));

    sqlx::query("DELETE FROM indexer_state WHERE key = 'chain_live_scan_cursor'")
        .execute(&pool)
        .await
        .unwrap();
    let fallback = repo::scanner_health(&pool).await.unwrap();
    assert_eq!(fallback.cursor_key.as_deref(), Some("chain_scan_cursor"));
    assert_eq!(fallback.cursor_blue_score, Some(25));
    assert_eq!(fallback.db_cursor_lag_blocks, Some(75));
}

// ---------- persist::revert_block -----------------------------------------

async fn revert_waits_for_uncommitted_writer(pool: PgPool, batch: bool) {
    let mut writer = pool.begin().await.unwrap();
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x544e31324b434332_i64)
        .execute(&mut *writer)
        .await
        .unwrap();
    let block_hash = vec![0x91_u8; 32];
    sqlx::query("INSERT INTO blocks(hash, blue_score, daa_score, parent_hashes, timestamp_ms, indexed_at_ms) VALUES ($1, 100, 100, ARRAY[]::bytea[], 1000, 1000)")
        .bind(&block_hash)
        .execute(&mut *writer)
        .await
        .unwrap();

    let persister = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
    let removed_hash = block_hash.clone();
    let removal = tokio::spawn(async move {
        if batch {
            persister.revert_blocks(&[removed_hash]).await.unwrap()[0]
        } else {
            persister.revert_block(&removed_hash).await.unwrap()
        }
    });
    // Observe an actual waiter, or the old implementation returning too soon.
    // A sleep cannot establish that the removal reached its visibility check.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if removal.is_finished() {
                break;
            }
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                 WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid)))",
            )
            .bind(writer_pid)
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("removal must execute or wait behind the writer");
    writer.commit().await.unwrap();
    let reverted = removal.await.unwrap();
    assert_eq!(
        reverted.blocks_removed, 1,
        "reorg must see the writer's committed block"
    );
    let remains: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM blocks WHERE hash = $1)")
        .bind(block_hash)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!remains);
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_block_waits_for_uncommitted_writer(pool: PgPool) {
    revert_waits_for_uncommitted_writer(pool, false).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_blocks_waits_before_filtering_uncommitted_blocks(pool: PgPool) {
    revert_waits_for_uncommitted_writer(pool, true).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_blocks_batches_known_and_unknown_block_lookup(pool: PgPool) {
    let known_block = insert_block(&pool, 0x91, 100).await;
    let persister = PgPersister::new(pool);

    let results = persister
        .revert_blocks(&[known_block.clone(), vec![0x92; 32], known_block])
        .await
        .unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].blocks_removed, 1);
    assert_eq!(results[1], tn12_indexer_db::RevertStats::default());
    assert_eq!(results[2], tn12_indexer_db::RevertStats::default());
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_blocks_failure_rolls_back_the_whole_removal_event(pool: PgPool) {
    let first = insert_block(&pool, 0x91, 100).await;
    let second = insert_block(&pool, 0x92, 101).await;
    sqlx::raw_sql(
        "CREATE FUNCTION reject_second_removal() RETURNS TRIGGER LANGUAGE plpgsql AS $$
         BEGIN
             IF OLD.blue_score = 101 THEN RAISE EXCEPTION 'fixture removal failure'; END IF;
             RETURN OLD;
         END $$;
         CREATE TRIGGER reject_second_removal BEFORE DELETE ON blocks
         FOR EACH ROW EXECUTE FUNCTION reject_second_removal();",
    )
    .execute(&pool)
    .await
    .unwrap();
    let persister = PgPersister::new(pool.clone());
    assert!(persister
        .revert_blocks(&[first.clone(), second.clone()])
        .await
        .is_err());
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM blocks WHERE hash = ANY($1::bytea[])")
            .bind(vec![first, second])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_block_reactivates_spent_utxo_and_removes_reverted_outputs(pool: PgPool) {
    let created_block = insert_block(&pool, 1, 100).await;
    let reverted_block = insert_block(&pool, 2, 101).await;
    let cov = insert_covenant(&pool, 3, "kaspatest:p", Some("KCC20"), &created_block, 100).await;
    insert_action(
        &pool,
        &cov,
        0xa0,
        &created_block,
        1778654400100,
        "deploy",
        None,
    )
    .await;

    insert_active_utxo(&pool, &cov, "kaspatest:p", 10_000, &created_block, 0xa1).await;
    mark_utxo_spent(&pool, 0xa1, &reverted_block, 0xb1).await;
    insert_active_utxo(&pool, &cov, "kaspatest:p", 9_000, &reverted_block, 0xb2).await;
    insert_action(
        &pool,
        &cov,
        0xb1,
        &reverted_block,
        1778654400101,
        "spend",
        Some("recover"),
    )
    .await;
    insert_action(
        &pool,
        &cov,
        0xb2,
        &reverted_block,
        1778654400101,
        "continuation",
        None,
    )
    .await;

    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = '{"decoded": true}'::jsonb,
               claim_verified = TRUE,
               claim_verified_at_ms = 1778654400101
           WHERE covenant_id = $1"#,
    )
    .bind(&cov)
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_activity_feed(&pool).await.unwrap();
    let projected_deploys: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM kcc20_activity_feed WHERE txid = $1")
            .bind(vec![0xa0_u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(projected_deploys, 1);

    let stats = PgPersister::new(pool.clone())
        .revert_block(&reverted_block)
        .await
        .unwrap();

    assert_eq!(stats.reverted_blue_score, Some(101));
    assert_eq!(stats.blocks_removed, 1);
    assert_eq!(stats.covenants_removed, 0);
    assert_eq!(stats.utxos_created_removed, 1);
    assert_eq!(stats.utxos_reactivated, 1);
    assert_eq!(stats.actions_removed, 2);
    assert_eq!(stats.covenants_unclassified, 1);

    let original: (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT status, spent_block FROM covenant_utxos WHERE txid = $1 AND vout = 0",
    )
    .bind(vec![0xa1_u8; 32])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(original.0, "active");
    assert!(original.1.is_none());

    let reverted_utxo_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM covenant_utxos WHERE txid = $1)")
            .bind(vec![0xb2_u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!reverted_utxo_exists);

    let covenant: (
        Option<String>,
        Option<serde_json::Value>,
        String,
        String,
        bool,
    ) = sqlx::query_as(
        r#"SELECT template_name, constructor_args, classification_kind,
                      classification_status, claim_verified
               FROM covenants WHERE covenant_id = $1"#,
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(covenant.0.is_none());
    assert!(covenant.1.is_none());
    assert_eq!(covenant.2, "unknown");
    assert_eq!(covenant.3, "unrevealed");
    assert!(!covenant.4);

    let dirty_txids: Vec<Option<Vec<u8>>> = sqlx::query_scalar(
        "SELECT txid FROM kcc20_projection_dirty WHERE reason = 'block_revert' ORDER BY txid",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        dirty_txids,
        vec![
            Some(vec![0xa0_u8; 32]),
            Some(vec![0xb1_u8; 32]),
            Some(vec![0xb2_u8; 32]),
        ]
    );

    let target_dirty_id = repo::kcc20_projection_latest_dirty_id(&pool).await.unwrap();
    let refresh = repo::refresh_kcc20_activity_feed_with_config(
        &pool,
        repo::Kcc20ActivityFeedRefreshConfig::projector(target_dirty_id, false, "10s".to_string()),
    )
    .await
    .unwrap();
    assert_eq!(
        refresh.mode,
        repo::Kcc20ActivityFeedRefreshMode::ScopedTxids
    );
    assert_eq!(refresh.scoped_dirty_txids, 3);

    let remaining_deploys: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM kcc20_activity_feed WHERE txid = $1")
            .bind(vec![0xa0_u8; 32])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining_deploys, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_block_skips_history_for_already_unrevealed_covenant(pool: PgPool) {
    let created_block = insert_block(&pool, 0x21, 100).await;
    let reverted_block = insert_block(&pool, 0x22, 101).await;
    let covenant = insert_covenant(
        &pool,
        0x23,
        "kaspatest:unrevealed-reorg",
        None,
        &created_block,
        100,
    )
    .await;
    insert_action(
        &pool,
        &covenant,
        0xa0,
        &created_block,
        1_000,
        "deploy",
        None,
    )
    .await;
    insert_action(
        &pool,
        &covenant,
        0xb1,
        &reverted_block,
        2_000,
        "spend",
        None,
    )
    .await;

    let stats = PgPersister::new(pool.clone())
        .revert_block(&reverted_block)
        .await
        .unwrap();
    assert_eq!(stats.actions_removed, 1);
    assert_eq!(stats.covenants_unclassified, 0);

    let dirty_txids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT txid FROM kcc20_projection_dirty WHERE reason = 'block_revert' ORDER BY txid",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(dirty_txids, vec![vec![0xb1_u8; 32]]);
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_block_does_not_expand_history_when_classification_survives(pool: PgPool) {
    let created_block = insert_block(&pool, 0x11, 100).await;
    let prior_spend_block = insert_block(&pool, 0x12, 101).await;
    let reverted_block = insert_block(&pool, 0x13, 102).await;
    let covenant = insert_covenant(
        &pool,
        0x14,
        "kaspatest:revert-history-scope",
        Some("KCC20"),
        &created_block,
        100,
    )
    .await;
    insert_action(
        &pool,
        &covenant,
        0xa0,
        &created_block,
        1_000,
        "deploy",
        None,
    )
    .await;
    insert_action(
        &pool,
        &covenant,
        0xa5,
        &prior_spend_block,
        2_000,
        "spend",
        Some("transfer"),
    )
    .await;
    insert_action(
        &pool,
        &covenant,
        0xb1,
        &reverted_block,
        3_000,
        "spend",
        Some("transfer"),
    )
    .await;

    let stats = PgPersister::new(pool.clone())
        .revert_block(&reverted_block)
        .await
        .unwrap();
    assert_eq!(stats.actions_removed, 1);
    assert_eq!(stats.covenants_unclassified, 0);

    let dirty_txids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT txid FROM kcc20_projection_dirty WHERE reason = 'block_revert' ORDER BY txid",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(dirty_txids, vec![vec![0xb1_u8; 32]]);
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_classification_batches_preserve_surviving_spends_and_dirty_scope(pool: PgPool) {
    let created = insert_block(&pool, 0x31, 100).await;
    let prior = insert_block(&pool, 0x32, 101).await;
    let reverted = insert_block(&pool, 0x33, 102).await;
    // Cross the 256-covenant SQL chunk boundary, including an unchanged
    // classification and a surviving spend in the affected set.
    sqlx::query(
        r#"INSERT INTO covenants
           (covenant_id, address, script_version, script_hash, template_name,
            genesis_txid, genesis_vout, genesis_block, created_at_ms,
            classification_kind, classification_status)
           SELECT decode(lpad(to_hex(i),64,'0'),'hex'), 'kaspatest:batch-' || i,
                  0, decode(lpad(to_hex(i),64,'0'),'hex'),
                  CASE WHEN i = 257 THEN NULL ELSE 'KCC20' END,
                  decode(lpad(to_hex(i + 1000),64,'0'),'hex'), 0, $1, 1000,
                  CASE WHEN i = 257 THEN 'unknown' ELSE 'covenant' END,
                  CASE WHEN i = 257 THEN 'unrevealed' ELSE 'matched' END
           FROM generate_series(1,258) i"#,
    )
    .bind(&created)
    .execute(&pool)
    .await
    .unwrap();
    for (block, action, offset) in [(&created, "deploy", 1000_i64), (&reverted, "spend", 2000)] {
        sqlx::query(
            r#"INSERT INTO covenant_actions
               (covenant_id,txid,block_hash,block_time_ms,action)
               SELECT decode(lpad(to_hex(i),64,'0'),'hex'),
                      decode(lpad(to_hex(i + $3),64,'0'),'hex'), $1, 2000, $2
               FROM generate_series(1,258) i"#,
        )
        .bind(block)
        .bind(action)
        .bind(offset)
        .execute(&pool)
        .await
        .unwrap();
    }
    let survivor = hex::decode(format!("{:064x}", 258)).unwrap();
    insert_action(&pool, &survivor, 0xfa, &prior, 1500, "spend", None).await;
    let stats = PgPersister::new(pool.clone())
        .revert_block(&reverted)
        .await
        .unwrap();
    assert_eq!(stats.actions_removed, 258);
    assert_eq!(stats.covenants_unclassified, 256);
    let still_classified: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT covenant_id FROM covenants WHERE template_name IS NOT NULL")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(still_classified, vec![survivor]);
    let dirty: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT txid FROM kcc20_projection_dirty WHERE reason = 'block_revert' ORDER BY txid",
    ).fetch_all(&pool).await.unwrap();
    let mut expected: Vec<Vec<u8>> = (1001..=1256)
        .chain(2001..=2258)
        .map(|i| hex::decode(format!("{i:064x}")).unwrap())
        .collect();
    expected.sort();
    assert_eq!(dirty, expected);
    let replay = PgPersister::new(pool)
        .revert_block(&reverted)
        .await
        .unwrap();
    assert_eq!(replay.actions_removed, 0);
    assert_eq!(replay.covenants_unclassified, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn revert_block_deletes_covenants_created_by_reverted_block(pool: PgPool) {
    let base_block = insert_block(&pool, 1, 100).await;
    let reverted_block = insert_block(&pool, 2, 101).await;
    let survivor = insert_covenant(
        &pool,
        4,
        "kaspatest:survivor",
        Some("TimeLockVault"),
        &base_block,
        100,
    )
    .await;
    insert_active_utxo(
        &pool,
        &survivor,
        "kaspatest:survivor",
        20_000,
        &base_block,
        0xa0,
    )
    .await;
    insert_action(
        &pool,
        &survivor,
        0xa0,
        &base_block,
        1778654400100,
        "deploy",
        None,
    )
    .await;
    let cov = insert_covenant(
        &pool,
        3,
        "kaspatest:p",
        Some("TimeLockVault"),
        &reverted_block,
        101,
    )
    .await;
    insert_active_utxo(&pool, &cov, "kaspatest:p", 10_000, &reverted_block, 0xa1).await;
    insert_action(
        &pool,
        &cov,
        0xa1,
        &reverted_block,
        1778654400101,
        "deploy",
        None,
    )
    .await;

    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION refresh_covenant_template_summary(target_template TEXT)
           RETURNS VOID
           LANGUAGE plpgsql
           AS $function$
           BEGIN
               RAISE EXCEPTION 'full template summary rebuild called';
           END;
           $function$"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let stats = PgPersister::new(pool.clone())
        .revert_block(&reverted_block)
        .await
        .unwrap();

    assert_eq!(stats.reverted_blue_score, Some(101));
    assert_eq!(stats.blocks_removed, 1);
    assert_eq!(stats.covenants_removed, 1);
    assert_eq!(stats.utxos_created_removed, 1);
    assert_eq!(stats.actions_removed, 1);

    let covenants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM covenants")
        .fetch_one(&pool)
        .await
        .unwrap();
    let utxos: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM covenant_utxos")
        .fetch_one(&pool)
        .await
        .unwrap();
    let actions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM covenant_actions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let blocks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocks")
        .fetch_one(&pool)
        .await
        .unwrap();
    let template_summaries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM covenant_template_summaries")
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(covenants, 1);
    assert_eq!(utxos, 1);
    assert_eq!(actions, 1);
    assert_eq!(blocks, 1);
    assert_eq!(template_summaries, 1);

    let template_state: (i64, i64, i64, String, i64, Option<i64>, Option<i64>) = sqlx::query_as(
        r#"SELECT covenant_count, active_covenants, active_utxos,
                      total_amount_sompi::TEXT, action_count,
                      latest_created_at_ms, latest_action_time_ms
               FROM covenant_template_summaries
               WHERE template = 'TimeLockVault'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(template_state.0, 1);
    assert_eq!(template_state.1, 1);
    assert_eq!(template_state.2, 1);
    assert_eq!(template_state.3, "20000");
    assert_eq!(template_state.4, 1);
    assert_eq!(template_state.5, Some(1778654400100));
    assert_eq!(template_state.6, Some(1778654400100));
}

// ---------- auto-discover helpers -----------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn unclassified_covenant_addresses_only_returns_unrevealed_rows(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let unrevealed = insert_covenant(&pool, 2, "kaspatest:unrevealed", None, &block, 100).await;
    let unmatched = insert_covenant(&pool, 3, "kaspatest:unmatched", None, &block, 200).await;
    insert_covenant(
        &pool,
        4,
        "kaspatest:classified",
        Some("TimeLockVault"),
        &block,
        300,
    )
    .await;

    sqlx::query("UPDATE covenants SET classification_status = 'unmatched' WHERE covenant_id = $1")
        .bind(&unmatched)
        .execute(&pool)
        .await
        .unwrap();

    let rows = repo::unclassified_covenant_addresses(&pool, 20)
        .await
        .unwrap();

    assert_eq!(rows, vec![(unrevealed, "kaspatest:unrevealed".to_string())]);
}

#[sqlx::test(migrations = "./migrations")]
async fn unclassified_covenants_with_spends_returns_spent_outpoint(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:unclassified", None, &block, 100).await;
    let classified = insert_covenant(
        &pool,
        3,
        "kaspatest:classified",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let spent_hash = "11".repeat(32);

    insert_action_with_inputs(
        &pool,
        &cov,
        0xaa,
        &block,
        200,
        "spend",
        json!({
            "previousOutpoint": {
                "hash": spent_hash,
                "index": 3
            }
        }),
    )
    .await;
    insert_action_with_inputs(
        &pool,
        &cov,
        0xab,
        &block,
        300,
        "spend",
        json!({
            "previousOutpoint": {
                "hash": "22".repeat(32),
                "index": 4
            }
        }),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &classified,
        0xac,
        &block,
        400,
        "spend",
        None,
        None,
        Some(json!({"templateOnly": true})),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &classified,
        0xad,
        &block,
        500,
        "spend",
        Some("cancelBidByOwnerSig"),
        None,
        Some(json!({"alreadyDecoded": true})),
    )
    .await;

    let rows = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap();

    assert_eq!(rows.len(), 3);
    assert!(rows[0].action_id > 0);
    assert_eq!(rows[0].covenant_id, classified);
    assert_eq!(rows[0].spend_txid_hex, "ac".repeat(32));
    assert_eq!(rows[1].covenant_id, cov);
    assert_eq!(rows[1].spend_txid_hex, "ab".repeat(32));
    assert_eq!(rows[2].covenant_id, cov);
    assert_eq!(rows[2].spend_txid_hex, "aa".repeat(32));
    assert_eq!(
        rows[2].spent_outpoint_hash.as_deref(),
        Some(spent_hash.as_str())
    );
    assert_eq!(rows[2].spent_outpoint_index.as_deref(), Some("3"));

    let limited = repo::unclassified_covenants_with_spends(&pool, 2)
        .await
        .unwrap();
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].spend_txid_hex, "ac".repeat(32));
    assert_eq!(limited[1].spend_txid_hex, "ab".repeat(32));
}

#[sqlx::test(migrations = "./migrations")]
async fn unclassified_covenants_with_spends_repairs_stale_wrapper_args(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let wrapper = insert_covenant(
        &pool,
        2,
        "kaspatest:wrapper",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;

    for (tx_byte, entrypoint, decoded_args) in [
        (0xa1, "wrap", json!({"canonicalTokenId": "11".repeat(32)})),
        (0xa2, "wrap", json!({"tokenInputIndex": "1"})),
        (0xa3, "unwrap", json!({"canonicalTokenId": "11".repeat(32)})),
        (0xa4, "unwrap", json!({"wrappedInputIndex": "1"})),
    ] {
        insert_action_with_outputs_and_args(
            &pool,
            &wrapper,
            tx_byte,
            &block,
            i64::from(tx_byte),
            "spend",
            Some(entrypoint),
            None,
            Some(decoded_args),
        )
        .await;
    }

    let rows = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.spend_txid_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["a3".repeat(32), "a1".repeat(32)]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unclassified_covenants_with_spends_repairs_stale_fee_ticket_args(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let fee_ticket = insert_covenant(
        &pool,
        2,
        "kaspatest:fee-ticket",
        Some("KCC20FeeTicket"),
        &block,
        100,
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &fee_ticket,
        0xf1,
        &block,
        200,
        "spend",
        Some("transferByOwnerSig"),
        None,
        Some(json!({"ownerIdentifier": "11".repeat(32)})),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &fee_ticket,
        0xf2,
        &block,
        300,
        "spend",
        Some("burnByOwnerSig"),
        None,
        Some(json!({"ownerIdentifier": "22".repeat(32)})),
    )
    .await;

    let rows = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].covenant_id, fee_ticket);
    assert_eq!(rows[0].spend_txid_hex, "f1".repeat(32));
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_ticket_indexed_arg_backfill_repairs_create_batch_and_transfer(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let fee_ticket = insert_covenant(
        &pool,
        2,
        "kaspatest:fee-ticket-indexed-backfill",
        Some("KCC20FeeTicket"),
        &block,
        100,
    )
    .await;
    let ticket_owner = "aa".repeat(32);
    let batch_owner = "bb".repeat(32);
    let transfer_owner = "cc".repeat(32);

    insert_action_with_outputs_and_args(
        &pool,
        &fee_ticket,
        0xc1,
        &block,
        200,
        "spend",
        Some("createFromUtilityBurn"),
        None,
        Some(json!({"ownerIdentifier": "11".repeat(32)})),
    )
    .await;
    insert_utxo_with_state_at_vout(
        &pool,
        &fee_ticket,
        0xc1,
        0,
        &block,
        json!({"mode": 2, "ownerIdentifier": ticket_owner, "ownerScheme": 4}),
    )
    .await;
    insert_utxo_with_state_at_vout(
        &pool,
        &fee_ticket,
        0xc1,
        1,
        &block,
        json!({"mode": 1, "ownerIdentifier": "11".repeat(32), "ownerScheme": 0}),
    )
    .await;

    insert_action_with_outputs_and_args(
        &pool,
        &fee_ticket,
        0xc2,
        &block,
        300,
        "spend",
        Some("createBatchFromUtilityBurn"),
        None,
        Some(json!({"ownerIdentifier": "11".repeat(32)})),
    )
    .await;
    for vout in [2, 3] {
        insert_utxo_with_state_at_vout(
            &pool,
            &fee_ticket,
            0xc2,
            vout,
            &block,
            json!({"mode": 2, "ownerIdentifier": batch_owner, "ownerScheme": 3}),
        )
        .await;
    }
    insert_utxo_with_state_at_vout(
        &pool,
        &fee_ticket,
        0xc2,
        4,
        &block,
        json!({"mode": 1, "ownerIdentifier": "11".repeat(32), "ownerScheme": 0}),
    )
    .await;

    insert_action_with_outputs_and_args(
        &pool,
        &fee_ticket,
        0xc3,
        &block,
        400,
        "spend",
        Some("transferByOwnerSig"),
        None,
        Some(json!({"ownerIdentifier": "11".repeat(32)})),
    )
    .await;
    insert_utxo_with_state_at_vout(
        &pool,
        &fee_ticket,
        0xc3,
        5,
        &block,
        json!({"mode": 2, "ownerIdentifier": transfer_owner, "ownerScheme": 1}),
    )
    .await;

    sqlx::query(include_str!(
        "../migrations/20260823153000_kcc20_fee_ticket_indexed_arg_backfill.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT entrypoint, decoded_args FROM covenant_actions WHERE covenant_id = $1 ORDER BY txid",
    )
    .bind(&fee_ticket)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows[0].0, "createFromUtilityBurn");
    assert_eq!(rows[0].1["ticketOwner"], ticket_owner);
    assert_eq!(rows[0].1["ticketOwnerScheme"], "4");
    assert_eq!(rows[0].1["ticketOutputIndex"], "0");
    assert_eq!(rows[0].1["rootOutputIndex"], "1");
    assert_eq!(rows[0].1["quantity"], 1);

    assert_eq!(rows[1].0, "createBatchFromUtilityBurn");
    assert_eq!(rows[1].1["ticketOwner"], batch_owner);
    assert_eq!(rows[1].1["ticketOwnerScheme"], "3");
    assert_eq!(rows[1].1["firstTicketOutputIndex"], "2");
    assert_eq!(rows[1].1["rootOutputIndex"], "4");
    assert_eq!(rows[1].1["quantity"], 2);

    assert_eq!(rows[2].0, "transferByOwnerSig");
    assert_eq!(rows[2].1["recipientOwner"], transfer_owner);
    assert_eq!(rows[2].1["toOwner"], transfer_owner);
    assert_eq!(rows[2].1["recipientOwnerScheme"], "1");
    assert_eq!(rows[2].1["toOwnerScheme"], "1");
    assert_eq!(rows[2].1["ticketOutputIndex"], "5");

    let dirty_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_projection_dirty WHERE reason = 'kcc20_fee_ticket_indexed_arg_backfill'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dirty_count, 3);
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_ticket_multi_transfer_owner_backfill_repairs_unambiguous_owner(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let fee_ticket = insert_covenant(
        &pool,
        2,
        "kaspatest:fee-ticket-multi-transfer-backfill",
        Some("KCC20FeeTicket"),
        &block,
        100,
    )
    .await;
    let transfer_owner = "dd".repeat(32);

    for block_time in [200, 201, 202] {
        insert_action_with_outputs_and_args(
            &pool,
            &fee_ticket,
            0xd1,
            &block,
            block_time,
            "spend",
            Some("transferByOwnerSig"),
            None,
            Some(json!({"ownerIdentifier": "11".repeat(32)})),
        )
        .await;
    }
    for vout in [0, 1, 2] {
        insert_utxo_with_state_at_vout(
            &pool,
            &fee_ticket,
            0xd1,
            vout,
            &block,
            json!({"mode": 2, "ownerIdentifier": transfer_owner, "ownerScheme": 2}),
        )
        .await;
    }

    sqlx::query(include_str!(
        "../migrations/20260823161000_kcc20_fee_ticket_multi_transfer_owner_backfill.sql"
    ))
    .execute(&pool)
    .await
    .unwrap();

    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT decoded_args FROM covenant_actions WHERE covenant_id = $1 ORDER BY id",
    )
    .bind(&fee_ticket)
    .fetch_all(&pool)
    .await
    .unwrap();

    assert_eq!(rows.len(), 3);
    for args in rows {
        assert_eq!(args["recipientOwner"], transfer_owner);
        assert_eq!(args["toOwner"], transfer_owner);
        assert_eq!(args["recipientOwnerScheme"], "2");
        assert_eq!(args["toOwnerScheme"], "2");
        assert!(args.get("ticketOutputIndex").is_none());
    }

    let dirty_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_projection_dirty WHERE reason = 'kcc20_fee_ticket_multi_transfer_owner_backfill'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dirty_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn unclassified_covenants_with_spends_repairs_stale_orderbook_ticket_args(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let orderbook = insert_covenant(
        &pool,
        2,
        "kaspatest:orderbook",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;

    for (tx_byte, entrypoint, decoded_args) in [
        (0xe1, "fillAskPartial", json!({"fillAmount": "1"})),
        (0xe2, "fillBidPartial", json!({"fillAmount": "1"})),
        (0xe3, "fillBidFromSellerSweep", json!({"fillAmount": "1"})),
        (
            0xe4,
            "fillAskPartial",
            json!({"fillAmount": "1", "ticketInputIndex": "-1"}),
        ),
    ] {
        insert_action_with_outputs_and_args(
            &pool,
            &orderbook,
            tx_byte,
            &block,
            i64::from(tx_byte),
            "spend",
            Some(entrypoint),
            None,
            Some(decoded_args),
        )
        .await;
    }

    let rows = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.spend_txid_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["e3".repeat(32), "e2".repeat(32), "e1".repeat(32)]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unclassified_covenants_with_spends_prioritizes_known_kcc20_repairs(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let unknown = insert_covenant(&pool, 2, "kaspatest:unknown", None, &block, 100).await;
    let fee_ticket = insert_covenant(
        &pool,
        3,
        "kaspatest:fee-ticket-priority",
        Some("KCC20FeeTicket"),
        &block,
        100,
    )
    .await;
    let orderbook = insert_covenant(
        &pool,
        4,
        "kaspatest:orderbook-priority",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;

    for tx_byte in 0x10..0x18 {
        insert_action_with_inputs(
            &pool,
            &unknown,
            tx_byte,
            &block,
            1_000 + i64::from(tx_byte),
            "spend",
            json!({
                "previousOutpoint": {
                    "hash": "11".repeat(32),
                    "index": tx_byte
                }
            }),
        )
        .await;
    }
    insert_action_with_outputs_and_args(
        &pool,
        &fee_ticket,
        0xf1,
        &block,
        200,
        "spend",
        Some("transferByOwnerSig"),
        None,
        Some(json!({"ownerIdentifier": "22".repeat(32)})),
    )
    .await;
    insert_action_with_outputs_and_args(
        &pool,
        &orderbook,
        0xe1,
        &block,
        300,
        "spend",
        Some("fillAskPartial"),
        None,
        Some(json!({"fillAmount": "1"})),
    )
    .await;

    let rows = repo::unclassified_covenants_with_spends(&pool, 2)
        .await
        .unwrap();

    assert_eq!(
        rows.iter()
            .map(|row| row.spend_txid_hex.as_str())
            .collect::<Vec<_>>(),
        vec!["e1".repeat(32), "f1".repeat(32)]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn reclassify_covenant_updates_only_the_selected_spend_action(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:wrapper", None, &block, 100).await;
    let spend_txid = vec![0xee; 32];
    let first_hash = "11".repeat(32);
    let second_hash = "22".repeat(32);

    for hash in [&first_hash, &second_hash] {
        insert_action_with_inputs(
            &pool,
            &cov,
            0xee,
            &block,
            200,
            "spend",
            json!({
                "previousOutpoint": {
                    "hash": hash,
                    "index": 0
                }
            }),
        )
        .await;
    }

    let rows = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap();
    let selected = rows
        .iter()
        .find(|row| row.spent_outpoint_hash.as_deref() == Some(first_hash.as_str()))
        .unwrap();
    let reveal = kcc20_wrapper_placeholder_script();
    let signature_script = kcc20_wrapper_action_signature_script([0x45, 0xf3, 0x39, 0x9f], &reveal);
    let persister = PgPersister::new(pool.clone());

    let matched = persister
        .reclassify_covenant(selected.action_id, &cov, &spend_txid, &signature_script)
        .await
        .unwrap();

    assert_eq!(matched.as_deref(), Some("KCC20Wrapper"));
    let actions: Vec<(i64, Option<String>, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT id, entrypoint, decoded_args FROM covenant_actions WHERE covenant_id = $1 AND txid = $2 ORDER BY id",
    )
    .bind(&cov)
    .bind(&spend_txid)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(
        actions
            .iter()
            .find(|row| row.0 == selected.action_id)
            .unwrap()
            .1
            .as_deref(),
        Some("wrap")
    );
    assert_eq!(
        actions
            .iter()
            .find(|row| row.0 == selected.action_id)
            .unwrap()
            .2
            .as_ref()
            .unwrap()["tokenInputIndex"],
        "1"
    );
    assert!(actions
        .iter()
        .find(|row| row.0 != selected.action_id)
        .unwrap()
        .1
        .is_none());

    let dirty_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kcc20_projection_dirty WHERE reason = 'kcc20_reclassification' AND txid = $1",
    )
    .bind(&spend_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dirty_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn reclassify_covenant_preserves_shared_wrapper_family_template(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant = insert_covenant(
        &pool,
        2,
        "kaspatest:shared-wrapper-family",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let original_constructor = json!({"canonicalTokenId": "11".repeat(32)});
    sqlx::query("UPDATE covenants SET constructor_args = $1 WHERE covenant_id = $2")
        .bind(&original_constructor)
        .bind(&covenant)
        .execute(&pool)
        .await
        .unwrap();
    insert_action_with_inputs(
        &pool,
        &covenant,
        0xef,
        &block,
        200,
        "spend",
        json!({
            "previousOutpoint": {
                "hash": "22".repeat(32),
                "index": 0
            }
        }),
    )
    .await;

    let candidate = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap()
        .remove(0);
    let reveal = kcc20_wrapper_placeholder_script();
    let signature_script = kcc20_wrapper_action_signature_script([0x45, 0xf3, 0x39, 0x9f], &reveal);
    let matched = PgPersister::new(pool.clone())
        .reclassify_covenant(
            candidate.action_id,
            &covenant,
            &candidate.spend_txid,
            &signature_script,
        )
        .await
        .unwrap();

    assert_eq!(matched.as_deref(), Some("KCC20Wrapper"));
    let stored_covenant: (Option<String>, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT template_name, constructor_args FROM covenants WHERE covenant_id = $1",
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_covenant.0.as_deref(), Some("KCC20Orderbook"));
    assert_eq!(stored_covenant.1, Some(original_constructor));

    let stored_action: (Option<String>, Option<serde_json::Value>) =
        sqlx::query_as("SELECT entrypoint, decoded_args FROM covenant_actions WHERE id = $1")
            .bind(candidate.action_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_action.0.as_deref(), Some("wrap"));
    assert_eq!(stored_action.1.as_ref().unwrap()["tokenInputIndex"], "1");
}

#[sqlx::test(migrations = "./migrations")]
async fn reclassify_fee_ticket_restores_transfer_recipient_args(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant = insert_covenant(&pool, 2, "kaspatest:fee-ticket", None, &block, 100).await;
    insert_action_with_inputs(
        &pool,
        &covenant,
        0xfa,
        &block,
        200,
        "spend",
        json!({
            "previousOutpoint": {
                "hash": "22".repeat(32),
                "index": 0
            }
        }),
    )
    .await;

    let candidate = repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap()
        .remove(0);
    let recipient = [0x33; 32];
    let signature_script = kcc20_fee_ticket_transfer_signature_script(
        recipient,
        &kcc20_fee_ticket_placeholder_script(),
    );
    let matched = PgPersister::new(pool.clone())
        .reclassify_covenant(
            candidate.action_id,
            &covenant,
            &candidate.spend_txid,
            &signature_script,
        )
        .await
        .unwrap();

    assert_eq!(matched.as_deref(), Some("KCC20FeeTicket"));
    let stored_action: (Option<String>, Option<serde_json::Value>) =
        sqlx::query_as("SELECT entrypoint, decoded_args FROM covenant_actions WHERE id = $1")
            .bind(candidate.action_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_action.0.as_deref(), Some("transferByOwnerSig"));
    assert_eq!(
        stored_action.1.as_ref().unwrap()["recipientOwner"],
        hex::encode(recipient)
    );
    assert_eq!(stored_action.1.as_ref().unwrap()["ticketOutputIndex"], "0");
}

#[sqlx::test(migrations = "./migrations")]
async fn reclassify_covenant_rejects_retired_kcc20_sale_reveal(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:unclassified", None, &block, 100).await;
    let spend_txid = vec![0xdd; 32];
    let signature_script = concat!(
        "419462d15cb1f4f256a1b6c86376c8885da4dfd63d64f4b50aa2e2809a1ef96d47e780",
        "32024d903a695d1ba79c366a8757e2a371cb076e5e0ce9f23107bfc7299f015151",
        "4cc66b6c76009c637576cf2019f02af56c89ee13fd6320a4f30ee867bc723d92e957ee",
        "5695a340ed6e2d8e118769016400a06900c203a08601a26900c3203a45f49d274878",
        "c84aec501cdb8dca6699bf6495eb31ccc0e349ec567f4be732030000207c7e01ac7",
        "e876975516776519c637578203a45f49d274878c84aec501cdb8dca6699bf6495eb",
        "31ccc0e349ec567f4be732ac6976cf2019f02af56c89ee13fd6320a4f30ee867bc",
        "723d92e957ee5695a340ed6e2d8e118769016400a069757551677500696868"
    );
    insert_action_with_inputs(
        &pool,
        &cov,
        0xdd,
        &block,
        200,
        "spend",
        json!({
            "previousOutpoint": {
                "hash": "7a1f2d436a79931da7449688446578914f4e2d824c871219eca71a887b250095",
                "index": 0
            }
        }),
    )
    .await;
    let persister = PgPersister::new(pool.clone());

    let matched = persister
        .reclassify_covenant(
            sqlx::query_scalar(
                "SELECT id FROM covenant_actions WHERE covenant_id = $1 AND txid = $2",
            )
            .bind(&cov)
            .bind(&spend_txid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            &cov,
            &spend_txid,
            signature_script,
        )
        .await
        .unwrap();

    assert!(matched.is_none());
    let row: (Option<String>, Option<serde_json::Value>, String) = sqlx::query_as(
        "SELECT template_name, constructor_args, classification_status FROM covenants WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.0.is_none());
    assert!(row.1.is_none());
    assert_eq!(row.2, "unmatched");

    let action: (Option<String>, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT entrypoint, decoded_args FROM covenant_actions WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&cov)
    .bind(&spend_txid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(action.0.is_none());
    assert!(action.1.is_none());
}

// ---------- payload claim repair helpers ----------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn payload_claim_repair_candidates_include_legacy_claimed_rows(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let missing = insert_covenant(&pool, 2, "kaspatest:p1", None, &block, 100).await;
    let claimed = insert_covenant(&pool, 3, "kaspatest:p2", None, &block, 200).await;

    sqlx::query(
        "UPDATE covenants SET claimed_template = 'TimeLockVault', claimed_args = '{}'::jsonb, claim_source = 'payload' WHERE covenant_id = $1",
    )
    .bind(&claimed)
    .execute(&pool)
    .await
    .unwrap();

    let rows = repo::covenants_payload_claim_repair_candidates(&pool, 20)
        .await
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .any(|row| { row.covenant_id == missing && row.covenant_id_hex == hex::encode(&missing) }));
    assert!(rows
        .iter()
        .any(|row| { row.covenant_id == claimed && row.covenant_id_hex == hex::encode(&claimed) }));
}

#[sqlx::test(migrations = "./migrations")]
async fn store_payload_claim_for_covenant_is_idempotent(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;
    let claim = claim::ClaimedDeployment {
        v: 1,
        tmpl: "MultiSigVault".to_string(),
        args: vec![claim::ClaimedArg {
            name: "signer1".to_string(),
            arg_type: "address".to_string(),
            value: json!("kaspatest:qexample"),
        }],
        meta: None,
    };

    let changed = repo::store_payload_claim_for_covenant(&pool, &cov, &claim)
        .await
        .unwrap();
    assert_eq!(changed, 1);

    let changed_again = repo::store_payload_claim_for_covenant(&pool, &cov, &claim)
        .await
        .unwrap();
    assert_eq!(changed_again, 0);

    let row: (Option<String>, Option<serde_json::Value>, Option<String>) = sqlx::query_as(
        "SELECT claimed_template, claimed_args, claim_source FROM covenants WHERE covenant_id = $1",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0.as_deref(), Some("MultiSigVault"));
    assert_eq!(row.1.unwrap()["args"][0]["name"], "signer1");
    assert_eq!(row.2.as_deref(), Some("payload"));
}

// ---------- dedupe migration regression ----------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn unique_index_blocks_duplicate_deploy_output_vouts(pool: PgPool) {
    // Deploy actions are keyed by their output identity so one transaction can
    // deploy several reserve outputs without allowing the same output twice.
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;
    insert_action_with_outputs_and_args(
        &pool,
        &cov,
        0xee,
        &block,
        100,
        "deploy",
        None,
        Some(json!({ "vout": 0 })),
        None,
    )
    .await;

    let txid_dup = vec![0xee_u8; 32];
    let err = sqlx::query(
        r#"INSERT INTO covenant_actions
           (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
           VALUES ($1, $2, $3, 100, 'deploy', NULL, NULL, $4, NULL)"#,
    )
    .bind(&cov)
    .bind(&txid_dup)
    .bind(&block)
    .bind(json!({ "vout": 0 }))
    .execute(&pool)
    .await
    .expect_err("expected unique violation");

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("unique") || msg.contains("duplicate"),
        "expected unique-violation error, got: {msg}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn continuation_actions_allow_multiple_vouts_per_tx(pool: PgPool) {
    // V3 partial fills can create a buyer holder output plus an ask/bid
    // continuation in the same token covenant and transaction.
    let block = insert_block(&pool, 1, 100).await;
    let cov = insert_covenant(&pool, 2, "kaspatest:p", None, &block, 100).await;
    let txid = vec![0xee_u8; 32];

    for vout in [0, 1] {
        sqlx::query(
            r#"INSERT INTO covenant_actions
               (covenant_id, txid, block_hash, block_time_ms, action, entrypoint, inputs, outputs, decoded_args)
               VALUES ($1, $2, $3, 100, 'continuation', NULL, NULL, $4, NULL)"#,
        )
        .bind(&cov)
        .bind(&txid)
        .bind(&block)
        .bind(json!({ "vout": vout, "state": { "mode": vout } }))
        .execute(&pool)
        .await
        .unwrap();
    }

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM covenant_actions WHERE covenant_id = $1 AND txid = $2",
    )
    .bind(&cov)
    .bind(&txid)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_covenant_summaries_paged_limit_offset_total_search(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    // Three covenants with distinct templates; blue_score drives created_at_ms.
    let a = insert_covenant(&pool, 2, "kaspatest:a", Some("AlphaVault"), &block, 100).await;
    insert_covenant(&pool, 3, "kaspatest:b", Some("BetaVault"), &block, 200).await;
    insert_covenant(&pool, 4, "kaspatest:c", Some("GammaVault"), &block, 300).await;
    // Only covenant `a` has an active UTXO.
    insert_active_utxo(&pool, &a, "kaspatest:a", 1000, &block, 0x40).await;

    // Page 1 of 2, newest first; total ignores the LIMIT window.
    let (rows, total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(2),
        Some(0),
    )
    .await
    .unwrap();
    assert_eq!(total, 3);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].template.as_deref(), Some("GammaVault"));
    assert_eq!(rows[1].template.as_deref(), Some("BetaVault"));

    // Page 2: the remaining row, total still 3.
    let (rows2, total2) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(2),
        Some(2),
    )
    .await
    .unwrap();
    assert_eq!(total2, 3);
    assert_eq!(rows2.len(), 1);
    assert_eq!(rows2[0].template.as_deref(), Some("AlphaVault"));

    // Empty pages and count-only requests still return the exact total.
    let (empty, empty_total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(2),
        Some(10),
    )
    .await
    .unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty_total, 3);

    let (count_only, count_only_total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(0),
        Some(0),
    )
    .await
    .unwrap();
    assert!(count_only.is_empty());
    assert_eq!(count_only_total, 3);

    // Free-text search.
    let (hit, hit_total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("beta"),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hit_total, 1);
    assert_eq!(hit[0].template.as_deref(), Some("BetaVault"));

    // Active-only filter.
    let (act, act_total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(true),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(act_total, 1);
    assert_eq!(act[0].template.as_deref(), Some("AlphaVault"));

    // Sort by template A-Z.
    let (sorted, _) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("template"),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(sorted[0].template.as_deref(), Some("AlphaVault"));
    assert_eq!(sorted[2].template.as_deref(), Some("GammaVault"));
}

#[sqlx::test(migrations = "./migrations")]
async fn list_covenant_summaries_paged_breaks_sort_ties_by_covenant_id(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let first = insert_covenant(&pool, 2, "kaspatest:first", Some("SameVault"), &block, 100).await;
    let second =
        insert_covenant(&pool, 3, "kaspatest:second", Some("SameVault"), &block, 100).await;
    let mut expected = vec![hex::encode(first), hex::encode(second)];
    expected.sort();

    let (page_one, total_one) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("recent"),
        Some(1),
        Some(0),
    )
    .await
    .unwrap();
    let (page_two, total_two) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("recent"),
        Some(1),
        Some(1),
    )
    .await
    .unwrap();

    assert_eq!(total_one, 2);
    assert_eq!(total_two, 2);
    assert_eq!(page_one[0].covenant_id_hex, expected[0]);
    assert_eq!(page_two[0].covenant_id_hex, expected[1]);
}

#[sqlx::test(migrations = "./migrations")]
async fn list_covenant_summaries_paged_covenant_id_exact_filter(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let target = insert_covenant(
        &pool,
        2,
        "kaspatest:target",
        Some("TargetVault"),
        &block,
        100,
    )
    .await;
    insert_covenant(&pool, 3, "kaspatest:other", Some("OtherVault"), &block, 200).await;
    let target_hex = hex::encode(target);

    let (rows, total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&target_hex),
        None,
        None,
        None,
        Some(5),
        Some(0),
    )
    .await
    .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].template.as_deref(), Some("TargetVault"));

    let (invalid_rows, invalid_total) = repo::list_covenant_summaries_paged(
        &pool,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        Some("not-a-covenant-id"),
        None,
        None,
        None,
        Some(5),
        Some(0),
    )
    .await
    .unwrap();
    assert_eq!(invalid_total, 0);
    assert!(invalid_rows.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn list_covenant_summaries_paged_wallet_filter_matches_claims_and_constructor_args(
    pool: PgPool,
) {
    let block = insert_block(&pool, 1, 100).await;
    let wallet = "kaspatest:qwalletowner";
    let owner_vault = insert_covenant(
        &pool,
        2,
        "kaspatest:owner-vault",
        Some("WalletVault"),
        &block,
        100,
    )
    .await;
    let seller_vault = insert_covenant(
        &pool,
        3,
        "kaspatest:seller-vault",
        Some("WalletVault"),
        &block,
        300,
    )
    .await;
    let state_owner_vault = insert_covenant(
        &pool,
        5,
        "kaspatest:state-owner-vault",
        Some("WalletVault"),
        &block,
        250,
    )
    .await;
    let signer_vault = insert_covenant(
        &pool,
        6,
        "kaspatest:signer-vault",
        Some("WalletVault"),
        &block,
        350,
    )
    .await;
    let recovery_vault = insert_covenant(
        &pool,
        7,
        "kaspatest:recovery-vault",
        Some("WalletVault"),
        &block,
        360,
    )
    .await;
    let heir_vault = insert_covenant(
        &pool,
        8,
        "kaspatest:heir-vault",
        Some("WalletVault"),
        &block,
        370,
    )
    .await;
    let arbiter_vault = insert_covenant(
        &pool,
        9,
        "kaspatest:arbiter-vault",
        Some("WalletVault"),
        &block,
        380,
    )
    .await;
    let multisig_vault = insert_covenant(
        &pool,
        10,
        "kaspatest:multisig-vault",
        Some("WalletVault"),
        &block,
        390,
    )
    .await;
    let object_claim_vault = insert_covenant(
        &pool,
        11,
        "kaspatest:object-claim-vault",
        Some("WalletVault"),
        &block,
        395,
    )
    .await;
    let other_vault = insert_covenant(
        &pool,
        4,
        "kaspatest:other-vault",
        Some("WalletVault"),
        &block,
        200,
    )
    .await;

    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&owner_vault)
        .bind(json!({
            "args": [
                { "name": "owner", "type": "address", "value": wallet }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET constructor_args = $2 WHERE covenant_id = $1")
        .bind(&seller_vault)
        .bind(json!({ "seller": wallet, "assetId": "beta-sword" }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&state_owner_vault)
        .bind(json!({
            "args": [
                { "name": "stateOwner", "type": "byte[32]", "value": wallet }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&signer_vault)
        .bind(json!({
            "args": [
                { "name": "signer", "type": "address", "value": wallet }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&recovery_vault)
        .bind(json!({
            "args": [
                { "name": "recoveryKey", "type": "address", "value": wallet }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&heir_vault)
        .bind(json!({
            "args": [
                { "name": "heir", "type": "address", "value": wallet }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET constructor_args = $2 WHERE covenant_id = $1")
        .bind(&arbiter_vault)
        .bind(json!({ "arbiter": wallet }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&multisig_vault)
        .bind(json!({
            "args": [
                { "name": "signer1", "type": "address", "value": wallet }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&object_claim_vault)
        .bind(json!({
            "payer": wallet,
            "invoiceId": "top-level-claim-shape"
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&other_vault)
        .bind(json!({
            "args": { "name": "owner", "type": "address", "value": "kaspatest:qother" }
        }))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET constructor_args = $2 WHERE covenant_id = $1")
        .bind(&other_vault)
        .bind(json!(["legacy", "array", "shape"]))
        .execute(&pool)
        .await
        .unwrap();

    let participant_rows: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT source, name, value_normalized
           FROM covenant_participants
           WHERE covenant_id IN ($1, $2, $3)
           ORDER BY source, name, value_normalized"#,
    )
    .bind(&owner_vault)
    .bind(&seller_vault)
    .bind(&object_claim_vault)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        participant_rows,
        vec![
            (
                "claimed_args".to_string(),
                "invoiceid".to_string(),
                "top-level-claim-shape".to_string()
            ),
            (
                "claimed_args".to_string(),
                "owner".to_string(),
                wallet.to_string()
            ),
            (
                "claimed_args".to_string(),
                "payer".to_string(),
                wallet.to_string()
            ),
            (
                "constructor_args".to_string(),
                "assetid".to_string(),
                "beta-sword".to_string()
            ),
            (
                "constructor_args".to_string(),
                "seller".to_string(),
                wallet.to_string()
            )
        ]
    );

    let (all_wallet_rows, all_wallet_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        None,
        None,
        Some(wallet),
        None,
        None,
        None,
        None,
        Some("recent"),
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(all_wallet_total, 9);
    assert_eq!(
        all_wallet_rows
            .iter()
            .map(|r| r.address.as_str())
            .collect::<Vec<_>>(),
        vec![
            "kaspatest:object-claim-vault",
            "kaspatest:multisig-vault",
            "kaspatest:arbiter-vault",
            "kaspatest:heir-vault",
            "kaspatest:recovery-vault",
            "kaspatest:signer-vault",
            "kaspatest:seller-vault",
            "kaspatest:state-owner-vault",
            "kaspatest:owner-vault"
        ]
    );

    let (owner_only, owner_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        None,
        None,
        Some(wallet),
        Some("owner"),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(owner_total, 1);
    assert_eq!(owner_only[0].address, "kaspatest:owner-vault");

    let (recovery_only, recovery_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        None,
        None,
        Some(wallet),
        Some("recoveryKey"),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(recovery_total, 1);
    assert_eq!(recovery_only[0].address, "kaspatest:recovery-vault");

    let pubkey_hex = "f952cc2af7b2c1e1a7ded898eeff5a9a8ed710f3c8e11ffea5353cd8a3f8d32f";
    let wallet_aliases = vec![wallet.to_string()];
    let (pubkey_wallet_rows, pubkey_wallet_total) =
        repo::list_covenant_summaries_paged_with_aliases(
            &pool,
            Some("WalletVault"),
            false,
            None,
            None,
            None,
            None,
            Some(pubkey_hex),
            &wallet_aliases,
            None,
            None,
            None,
            &[],
            None,
            Some("recent"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(pubkey_wallet_total, 9);
    assert_eq!(
        pubkey_wallet_rows
            .iter()
            .map(|r| r.address.as_str())
            .collect::<Vec<_>>(),
        vec![
            "kaspatest:object-claim-vault",
            "kaspatest:multisig-vault",
            "kaspatest:arbiter-vault",
            "kaspatest:heir-vault",
            "kaspatest:recovery-vault",
            "kaspatest:signer-vault",
            "kaspatest:seller-vault",
            "kaspatest:state-owner-vault",
            "kaspatest:owner-vault"
        ]
    );

    let (claim_arg_rows, claim_arg_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        Some("owner"),
        Some(wallet),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(claim_arg_total, 1);
    assert_eq!(claim_arg_rows[0].address, "kaspatest:owner-vault");

    let (address_search_rows, address_search_total) =
        repo::list_covenant_summaries_paged_with_aliases(
            &pool,
            Some("WalletVault"),
            false,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            Some(wallet),
            &[],
            None,
            Some("recent"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(address_search_total, 9);
    assert_eq!(
        address_search_rows[0].address,
        "kaspatest:object-claim-vault"
    );

    let (pubkey_search_rows, pubkey_search_total) =
        repo::list_covenant_summaries_paged_with_aliases(
            &pool,
            Some("WalletVault"),
            false,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            Some(pubkey_hex),
            &wallet_aliases,
            None,
            Some("recent"),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(pubkey_search_total, 9);
    assert_eq!(
        pubkey_search_rows[0].address,
        "kaspatest:object-claim-vault"
    );

    let explorer_address = repo::explorer_search_with_aliases(&pool, wallet, &[], 20)
        .await
        .unwrap();
    assert!(explorer_address
        .iter()
        .any(|result| result.id.as_deref() == Some(&hex::encode(&signer_vault))));

    let explorer_pubkey =
        repo::explorer_search_with_aliases(&pool, pubkey_hex, &wallet_aliases, 20)
            .await
            .unwrap();
    assert!(explorer_pubkey
        .iter()
        .any(|result| result.id.as_deref() == Some(&hex::encode(&signer_vault))));

    let explorer_object_claim = repo::explorer_search_with_aliases(&pool, wallet, &[], 20)
        .await
        .unwrap();
    assert!(explorer_object_claim
        .iter()
        .any(|result| result.id.as_deref() == Some(&hex::encode(&object_claim_vault))));

    let (payer_only, payer_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        None,
        None,
        Some(wallet),
        Some("payer"),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(payer_total, 1);
    assert_eq!(payer_only[0].address, "kaspatest:object-claim-vault");

    let (payer_claim_arg, payer_claim_arg_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        Some("payer"),
        Some(wallet),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(payer_claim_arg_total, 1);
    assert_eq!(payer_claim_arg[0].address, "kaspatest:object-claim-vault");

    let (seller_search, seller_search_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("WalletVault"),
        false,
        None,
        None,
        None,
        None,
        Some(wallet),
        Some("seller"),
        None,
        Some("seller-vault"),
        None,
        Some("template"),
        Some(10),
        Some(0),
    )
    .await
    .unwrap();
    assert_eq!(seller_search_total, 1);
    assert_eq!(seller_search[0].address, "kaspatest:seller-vault");
}

#[sqlx::test(migrations = "./migrations")]
async fn covenant_participants_accept_large_values_without_index_tuple_failure(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let covenant = insert_covenant(
        &pool,
        2,
        "kaspatest:large-participant",
        Some("LargeVault"),
        &block,
        100,
    )
    .await;
    let large_value = "x".repeat(6000);

    sqlx::query("UPDATE covenants SET claimed_args = $2 WHERE covenant_id = $1")
        .bind(&covenant)
        .bind(json!({
            "args": [
                { "name": "memo", "type": "string", "value": large_value }
            ]
        }))
        .execute(&pool)
        .await
        .unwrap();

    let participant: (String, String) = sqlx::query_as(
        r#"SELECT value_normalized, value_hash
           FROM covenant_participants
           WHERE covenant_id = $1 AND name = 'memo'"#,
    )
    .bind(&covenant)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(participant.0, large_value);
    assert_eq!(participant.1.len(), 32);
}

#[sqlx::test(migrations = "./migrations")]
async fn wallet_filter_matches_self_custody_vault_claimed_address_args(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let vault = insert_covenant(&pool, 2, "kaspatest:vault-covenant", None, &block, 100).await;
    let hot_key = "kaspatest:qpdzgy8gvav58tgjwlxr7sj8fd6888r8l93tvqnkkwk3mhy8phgd5uq3yrpc2";
    let cold_key = "kaspatest:qru49np277evrcd8mmvf3mhlt2dga4cs70ywz8l7556nek9rlrfj7w043aq6v";
    let whitelisted_destination =
        "kaspatest:qzqs6uypp8h2wx8jhc366s6p2puvzg295v6h46sgj69vumflx7lyuqf5wmjwf";
    let future_address = "kaspatest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqm6a7l";

    sqlx::query(
        r#"UPDATE covenants
           SET claimed_template = 'SelfCustodyVault',
               claimed_args = $2,
               claim_source = 'payload'
           WHERE covenant_id = $1"#,
    )
    .bind(&vault)
    .bind(json!({
        "args": [
            { "name": "hotKey", "type": "pubkey", "value": hot_key },
            { "name": "coldKey", "type": "pubkey", "value": cold_key },
            {
                "name": "whitelistedDestinations",
                "type": "pubkey[]",
                "value": [whitelisted_destination]
            },
            { "name": "futureVaultAddress", "type": "address", "value": future_address },
            { "name": "memo", "type": "string", "value": "not a wallet relationship" }
        ]
    }))
    .execute(&pool)
    .await
    .unwrap();

    let participants: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"SELECT name, value_normalized, type
           FROM covenant_participants
           WHERE covenant_id = $1
           ORDER BY name, value_normalized"#,
    )
    .bind(&vault)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        participants,
        vec![
            (
                "coldkey".to_string(),
                cold_key.to_string(),
                Some("pubkey".to_string())
            ),
            (
                "futurevaultaddress".to_string(),
                future_address.to_string(),
                Some("address".to_string())
            ),
            (
                "hotkey".to_string(),
                hot_key.to_string(),
                Some("pubkey".to_string())
            ),
            (
                "memo".to_string(),
                "not a wallet relationship".to_string(),
                Some("string".to_string())
            ),
            (
                "whitelisteddestinations".to_string(),
                whitelisted_destination.to_string(),
                Some("pubkey[]".to_string())
            ),
        ]
    );

    for wallet in [hot_key, cold_key, whitelisted_destination, future_address] {
        let (rows, total) = repo::list_covenant_summaries_paged(
            &pool,
            Some("SelfCustodyVault"),
            false,
            None,
            None,
            None,
            None,
            Some(wallet),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(total, 1, "wallet filter should match {wallet}");
        assert_eq!(rows[0].address, "kaspatest:vault-covenant");
        assert_eq!(rows[0].claim_verified, false);

        let address_rows = repo::covenants_by_address(&pool, wallet).await.unwrap();
        assert_eq!(address_rows.len(), 1, "address route should match {wallet}");
        assert_eq!(address_rows[0].address, "kaspatest:vault-covenant");
    }

    let (memo_rows, memo_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("SelfCustodyVault"),
        false,
        None,
        None,
        None,
        None,
        Some("not a wallet relationship"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(memo_total, 0);
    assert!(memo_rows.is_empty());

    let (cold_role_rows, cold_role_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("SelfCustodyVault"),
        false,
        None,
        None,
        None,
        None,
        Some(cold_key),
        Some("coldKey"),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(cold_role_total, 1);
    assert_eq!(cold_role_rows[0].address, "kaspatest:vault-covenant");

    let explorer_results = repo::explorer_search_with_aliases(&pool, hot_key, &[], 10)
        .await
        .unwrap();
    let vault_result = explorer_results
        .iter()
        .find(|result| result.id.as_deref() == Some(&hex::encode(&vault)))
        .expect("global explorer search should include the vault");
    assert!(vault_result
        .description
        .as_deref()
        .unwrap_or_default()
        .contains("claimed/unverified hotkey"));

    sqlx::query(
        r#"UPDATE covenants
           SET claim_verified = TRUE,
               claim_verified_at_ms = 1778654400101
           WHERE covenant_id = $1"#,
    )
    .bind(&vault)
    .execute(&pool)
    .await
    .unwrap();

    let verified_explorer_results = repo::explorer_search_with_aliases(&pool, hot_key, &[], 10)
        .await
        .unwrap();
    let verified_vault_result = verified_explorer_results
        .iter()
        .find(|result| result.id.as_deref() == Some(&hex::encode(&vault)))
        .expect("global explorer search should include the verified vault");
    let verified_description = verified_vault_result
        .description
        .as_deref()
        .unwrap_or_default();
    assert!(verified_description.contains("claimed/verified hotkey"));
    assert!(!verified_description.contains("claimed/unverified hotkey"));
}

#[sqlx::test(migrations = "./migrations")]
async fn list_covenant_summaries_paged_unknown_template_matches_nulls(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    insert_covenant(&pool, 2, "kaspatest:named", Some("AlphaVault"), &block, 100).await;
    insert_covenant(&pool, 3, "kaspatest:null1", None, &block, 200).await;
    insert_covenant(&pool, 4, "kaspatest:null2", None, &block, 300).await;

    // /covenant-templates labels null-template covenants "Unknown"; filtering by
    // "Unknown" must return exactly those (regression: it returned 0 before).
    let (rows, total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("Unknown"),
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(total, 2);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.template.is_none()));

    // A named template still resolves to just that template.
    let (named, named_total) = repo::list_covenant_summaries_paged(
        &pool,
        Some("AlphaVault"),
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(named_total, 1);
    assert_eq!(named[0].template.as_deref(), Some("AlphaVault"));
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "old KCC20V2 portfolio defaults are removed by the standard-native cutover"]
async fn kcc20_portfolio_defaults_to_canonical_v2_rows(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let owner = vec![0x11_u8; 32];
    let canonical = vec![0xa1_u8; 32];
    let second_canonical = vec![0xa2_u8; 32];
    let wrapper = insert_covenant(
        &pool,
        0xb1,
        "kaspatest:wrapper",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let native_wrapper = vec![0xb2_u8; 32];

    sqlx::query(
        r#"INSERT INTO kcc20_wrapper_summaries
           (wrapper_id, canonical_token_id, address, genesis_txid, active_utxos,
            pending_reveal, enabled, refreshed_at_ms, source_blue_score)
           VALUES ($1, $2, 'kaspatest:wrapper', $3, 1, FALSE, TRUE, 1000, 1)"#,
    )
    .bind(&wrapper)
    .bind(&canonical)
    .bind(vec![0xc1_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:wrapped-holder",
        50_000_000,
        json!({
            "canonicalTokenId": hex::encode(&canonical),
            "ownerIdentifier": hex::encode(&owner),
            "identifierType": 0,
            "amount": "5",
            "mode": 0,
            "wrapperCovenantId": hex::encode(&native_wrapper),
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &block,
        0xc2,
    )
    .await;

    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES
           ($1, $2, 0, 100::NUMERIC, 2, FALSE, 1100),
           ($3, $2, 0, 20::NUMERIC, 1, FALSE, 1200),
           ($4, $2, 0, 5::NUMERIC, 1, FALSE, 1300),
           ($1, $5, 2, 5::NUMERIC, 1, FALSE, 1400)"#,
    )
    .bind(&canonical)
    .bind(&owner)
    .bind(&second_canonical)
    .bind(&wrapper)
    .bind(&native_wrapper)
    .execute(&pool)
    .await
    .unwrap();

    let (rows, total) = repo::kcc20_portfolio_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioOptions {
            limit: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(total, 2);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].canonical_token_id_hex, hex::encode(&canonical));
    assert_eq!(rows[0].native_balance, "100");
    assert_eq!(rows[0].utxo_count, 2);
    assert_eq!(rows[0].last_change_ms, 1100);
    assert!(rows[0].orderbook_balance.is_none());
    assert!(rows[0].total_balance.is_none());
    assert!(rows[0].wrapped_markets.is_none());
    assert!(rows[0].reserve_rows.is_none());

    let (rows, total) = repo::kcc20_portfolio_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioOptions {
            offset: 10,
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(total, 2);
    assert!(rows.is_empty());

    let (rows, total) = repo::kcc20_portfolio_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioOptions {
            include_wrapped: true,
            include_reserves: true,
            include_totals: true,
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(total, 2);
    let canonical_row = rows
        .iter()
        .find(|row| row.canonical_token_id_hex == hex::encode(&canonical))
        .unwrap();
    assert_eq!(canonical_row.native_balance, "100");
    assert_eq!(canonical_row.orderbook_balance.as_deref(), Some("5"));
    assert_eq!(canonical_row.total_balance.as_deref(), Some("105"));
    assert_eq!(canonical_row.utxo_count, 3);
    assert_eq!(canonical_row.last_change_ms, 1300);

    let wrapped_markets = canonical_row
        .wrapped_markets
        .as_ref()
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(wrapped_markets.len(), 1);
    assert_eq!(
        wrapped_markets[0]["wrapperCovenantIdHex"],
        hex::encode(&wrapper)
    );
    assert_eq!(wrapped_markets[0]["orderbookBalance"], "5");

    let reserve_rows = canonical_row
        .reserve_rows
        .as_ref()
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(reserve_rows.len(), 1);
    assert_eq!(
        reserve_rows[0]["ownerIdentifier"],
        hex::encode(&native_wrapper)
    );
    assert_eq!(reserve_rows[0]["identifierType"], 2);
    assert_eq!(reserve_rows[0]["amount"], "5");
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_reuses_open_owner_order_projection(pool: PgPool) {
    let owner = "21".repeat(32);
    let token = vec![0x31_u8; 32];
    sqlx::query(
        "INSERT INTO kcc20_owner_orders (order_id, side, status, token_id, owner, \
         remaining_token_amount, address, created_at_ms, refreshed_at_ms) \
         VALUES ('test-order', 'ask', 'open', $1, $2, '5', 'kaspatest:test-order', 100, 100)",
    )
    .bind(&token)
    .bind(&owner)
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let row: (String, i64) = sqlx::query_as(
        "SELECT open_ask_amount::TEXT, open_order_count \
         FROM kcc20_owner_portfolio_assets \
         WHERE owner_identifier=decode($1,'hex') AND canonical_token_id=$2",
    )
    .bind(&owner)
    .bind(&token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("5".to_string(), 1));

    sqlx::query("UPDATE kcc20_owner_orders SET status='cancelled' WHERE order_id='test-order'")
        .execute(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kcc20_owner_portfolio_assets \
         WHERE owner_identifier=decode($1,'hex') AND canonical_token_id=$2",
    )
    .bind(&owner)
    .bind(&token)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_requires_a_completed_initial_projection(pool: PgPool) {
    assert!(!repo::kcc20_owner_portfolio_assets_initialized(&pool)
        .await
        .unwrap());
    let initial_dirty_id: i64 = sqlx::query_scalar(
        "SELECT MAX(id) FROM kcc20_projection_dirty WHERE reason = 'kcc20_standard_native_cutover'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_portfolio_assets_projection_name(),
        initial_dirty_id.saturating_sub(1),
    )
    .await
    .unwrap();
    assert!(!repo::kcc20_owner_portfolio_assets_initialized(&pool)
        .await
        .unwrap());
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    assert!(!repo::kcc20_owner_portfolio_assets_initialized(&pool)
        .await
        .unwrap());
    repo::mark_kcc20_projection_refreshed_for(
        &pool,
        repo::kcc20_owner_portfolio_assets_projection_name(),
        initial_dirty_id,
    )
    .await
    .unwrap();
    assert!(repo::kcc20_owner_portfolio_assets_initialized(&pool)
        .await
        .unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_missing_table_cannot_report_refresh_success(pool: PgPool) {
    sqlx::query("DROP TABLE kcc20_owner_portfolio_assets")
        .execute(&pool)
        .await
        .unwrap();

    let error = repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("kcc20_owner_portfolio_assets migration is required"));
    assert!(!repo::kcc20_owner_portfolio_assets_initialized(&pool)
        .await
        .unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_refreshes_balances_orders_prices_and_metadata(pool: PgPool) {
    let block = insert_block(&pool, 0x31, 100).await;
    let owner = vec![0x11_u8; 32];
    let canonical = insert_covenant(
        &pool,
        0x41,
        "kaspatest:canonical",
        Some("KCC20"),
        &block,
        100,
    )
    .await;
    let wrapper = insert_covenant(
        &pool,
        0x42,
        "kaspatest:wrapper",
        Some("KCC20Wrapper"),
        &block,
        101,
    )
    .await;
    let superseded_wrapper = insert_covenant(
        &pool,
        0x47,
        "kaspatest:superseded-wrapper",
        Some("KCC20Wrapper"),
        &block,
        99,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $2,
               claimed_args = $3
           WHERE covenant_id = $1"#,
    )
    .bind(&canonical)
    .bind(json!({
        "tokenName": "Alpha Token"
    }))
    .bind(json!({
        "args": [
            "ignored scalar",
            null,
            {"name": null, "value": "ignored"},
            {"name": "", "value": "ignored"},
            {"name": "ticker", "value": "ALPHA"},
            {"name": "tokenName", "value": "Claimed Name"},
            {"name": "decimals", "value": "6"}
        ]
    }))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_wrapper_summaries
           (wrapper_id, canonical_token_id, address, genesis_txid, active_utxos,
            pending_reveal, enabled, fee_ticket_id, refreshed_at_ms, source_blue_score)
           VALUES
           ($1, $2, 'kaspatest:wrapper', $4, 2, FALSE, TRUE, $5, 1000, 100),
           ($3, $2, 'kaspatest:superseded-wrapper', $6, 0, FALSE, TRUE, NULL, 1000, 100)"#,
    )
    .bind(&wrapper)
    .bind(&canonical)
    .bind(&superseded_wrapper)
    .bind(vec![0x51_u8; 32])
    .bind(vec![0x52_u8; 32])
    .bind(vec![0x53_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES
           ($1, $3, 0, 100000000::NUMERIC, 2, FALSE, 1100),
           ($2, $3, 0, 50000000::NUMERIC, 1, FALSE, 1200),
           ($4, $3, 0, 777::NUMERIC, 1, FALSE, 900)"#,
    )
    .bind(&canonical)
    .bind(&wrapper)
    .bind(&owner)
    .bind(&superseded_wrapper)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_market_summaries
           (token_id, best_ask_unit_price_sompi, best_bid_unit_price_sompi,
            spread_sompi, open_ask_count, open_bid_count, total_volume_sompi,
            total_trades, refreshed_at_ms, source_blue_score)
           VALUES ($1, 1000000001, 1000000000, 1, 1, 0, 0, 0, 1000, 100)"#,
    )
    .bind(&wrapper)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo_with_state(
        &pool,
        &wrapper,
        "kaspatest:wrapper",
        50_000_000,
        json!({
            "ownerIdentifier": hex::encode(&owner),
            "amount": "7000000",
            "unitPriceSompi": "1161",
            "mode": 2,
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &block,
        0x61,
    )
    .await;

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(page.total, 1);
    let row = &page.items[0];
    assert_eq!(row.canonical_token_id_hex, hex::encode(&canonical));
    assert_eq!(
        row.wrapper_id_hex.as_deref(),
        Some(hex::encode(&wrapper).as_str())
    );
    assert_eq!(row.wrapped_market_id_hex, row.wrapper_id_hex);
    assert_eq!(row.native_balance, "100000000");
    assert_eq!(row.orderbook_balance, "50000000");
    assert_eq!(row.total_balance, "150000000");
    assert_eq!(row.asset_utxo_count, 3);
    assert_eq!(row.open_ask_amount, "7000000");
    assert_eq!(row.open_bid_amount, "0");
    assert_eq!(row.open_order_count, 1);
    assert_eq!(row.best_ask_unit_price_sompi.as_deref(), Some("1000000001"));
    assert_eq!(row.best_bid_unit_price_sompi.as_deref(), Some("1000000000"));
    assert_eq!(row.value_sompi.as_deref(), Some("150000000150"));
    assert!(row.fee_ticket_supported);
    assert_eq!(row.ticker.as_deref(), Some("ALPHA"));
    assert_eq!(row.token_name.as_deref(), Some("Alpha Token"));
    assert_eq!(row.decimals, 6);
    assert!(row.actions.wrap.enabled);
    assert!(row.actions.unwrap.enabled);
    assert!(row.actions.trade.enabled);
    assert!(row.actions.wrap.reason.is_none());
    assert!(row.actions.unwrap.reason.is_none());
    assert!(row.actions.trade.reason.is_none());

    sqlx::query("UPDATE kcc20_wrapper_summaries SET fee_ticket_id = $2 WHERE wrapper_id = $1")
        .bind(&wrapper)
        .bind(vec![0_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let zero_ticket_page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();
    assert!(!zero_ticket_page.items[0].fee_ticket_supported);
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_uses_standard_display_scale(pool: PgPool) {
    let block = insert_block(&pool, 0x36, 500).await;
    let owner = vec![0x18_u8; 32];
    for (index, decimals, extension_only) in [
        (0_u8, 0_u32, false),
        (1, 2, false),
        (2, 8, false),
        (3, 8, true),
    ] {
        let token = insert_covenant(
            &pool,
            0x60 + index,
            "kaspatest:display-scale",
            Some("KCC20"),
            &block,
            500,
        )
        .await;
        let scale = 10_u64.pow(decimals);
        let claim = if extension_only {
            json!({"args": []})
        } else {
            json!({"args": [{"name": "displayScale", "value": scale.to_string()}, {"name": "ticker", "value": "SCALE"}]})
        };
        sqlx::query(
            "UPDATE covenants SET claimed_args=$2, constructor_args=$3 WHERE covenant_id=$1",
        )
        .bind(&token)
        .bind(claim)
        .bind(json!({"decimals": null}))
        .execute(&pool)
        .await
        .unwrap();
        if extension_only {
            insert_active_utxo_with_state(&pool, &token, "kaspatest:scale-extension", 1,
                json!({"extension": {"displayScale": scale.to_string(), "ticker": "SCALE", "name": "Scale token"}}),
                &block, 0x70 + index).await;
        }
        // 991 whole tokens, represented in base units, priced at one KAS.
        sqlx::query("INSERT INTO kcc20_holders (covenant_id,owner_identifier,identifier_type,amount_total,utxo_count,is_minter,last_change_ms) VALUES ($1,$2,0,$3::NUMERIC,1,FALSE,1000)")
            .bind(&token).bind(&owner).bind((991_u64 * scale).to_string()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO kcc20_market_summaries (token_id,best_ask_unit_price_sompi,refreshed_at_ms) VALUES ($1,100000000,1000)")
            .bind(&token).execute(&pool).await.unwrap();
    }
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(page.items.len(), 4);
    for row in &page.items {
        let index = hex::decode(&row.canonical_token_id_hex).unwrap()[0] - 0x60;
        assert_eq!(row.decimals, [0, 2, 8, 8][index as usize]);
        assert_eq!(row.value_sompi.as_deref(), Some("99100000000"));
    }
    // Repricing still uses the same scale at read time, without rebuilding holdings.
    sqlx::query("UPDATE kcc20_market_summaries SET best_ask_unit_price_sompi=200000000")
        .execute(&pool)
        .await
        .unwrap();
    let repriced = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();
    assert!(repriced
        .items
        .iter()
        .all(|row| row.value_sompi.as_deref() == Some("198200000000")));
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_handles_wide_totals_and_sibling_wrapper_market(pool: PgPool) {
    let block = insert_block(&pool, 0x35, 500).await;
    let owner = vec![0x17_u8; 32];
    let canonical = insert_covenant(
        &pool,
        0x55,
        "kaspatest:wide-canonical",
        Some("KCC20V2"),
        &block,
        500,
    )
    .await;
    let selected_wrapper = insert_covenant(
        &pool,
        0x56,
        "kaspatest:selected-wrapper",
        Some("KCC20Wrapper"),
        &block,
        501,
    )
    .await;
    let priced_wrapper = insert_covenant(
        &pool,
        0x57,
        "kaspatest:priced-wrapper",
        Some("KCC20Wrapper"),
        &block,
        502,
    )
    .await;
    sqlx::query("UPDATE covenants SET constructor_args = $2 WHERE covenant_id = $1")
        .bind(&canonical)
        .bind(json!({"ticker": "WIDE", "decimals": "0"}))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_wrapper_summaries
           (wrapper_id, canonical_token_id, address, genesis_txid, active_utxos,
            pending_reveal, enabled, refreshed_at_ms, source_blue_score)
           VALUES
           ($1, $3, 'kaspatest:selected-wrapper', $4, 2, FALSE, TRUE, 1000, 500),
           ($2, $3, 'kaspatest:priced-wrapper', $5, 1, TRUE, TRUE, 1000, 500)"#,
    )
    .bind(&selected_wrapper)
    .bind(&priced_wrapper)
    .bind(&canonical)
    .bind(vec![0x58_u8; 32])
    .bind(vec![0x59_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let max_numeric_78 = "9".repeat(78);
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES
           ($1, $4, 0, $5::NUMERIC, 1, FALSE, 1000),
           ($2, $4, 0, $5::NUMERIC, 1, FALSE, 1001),
           ($3, $4, 0, 1, 1, FALSE, 1002)"#,
    )
    .bind(&canonical)
    .bind(&selected_wrapper)
    .bind(&priced_wrapper)
    .bind(&owner)
    .bind(&max_numeric_78)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO kcc20_market_summaries
           (token_id, best_ask_unit_price_sompi, best_bid_unit_price_sompi,
            spread_sompi, open_ask_count, open_bid_count, total_volume_sompi,
            total_trades, refreshed_at_ms, source_blue_score)
           VALUES ($1, $2::NUMERIC, 1, 0, 1, 1, 0, 0, 1000, 500)"#,
    )
    .bind(&priced_wrapper)
    .bind(&max_numeric_78)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo_with_state(
        &pool,
        &priced_wrapper,
        "kaspatest:priced-wrapper-order",
        1,
        json!({
            "ownerIdentifier": hex::encode(&owner),
            "canonicalTokenId": hex::encode(&canonical),
            "amount": "3",
            "mode": 3,
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &block,
        0x5a,
    )
    .await;

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(page.total, 1);
    let row = &page.items[0];
    assert_eq!(
        row.wrapper_id_hex.as_deref(),
        Some(hex::encode(&selected_wrapper).as_str())
    );
    assert_eq!(
        row.best_ask_unit_price_sompi.as_deref(),
        Some(max_numeric_78.as_str())
    );
    assert_eq!(row.orderbook_balance, format!("1{}", "0".repeat(78)));
    assert_eq!(row.open_bid_amount, "3");
    assert_eq!(row.open_order_count, 1);
    assert_eq!(row.total_balance.len(), 79);
    assert_eq!(row.value_sompi.as_ref().unwrap().len(), 157);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "legacy order-only portfolio rows are not migrated at the standard-native cutover"]
async fn kcc20_owner_portfolio_assets_refreshes_legacy_order_only_assets(pool: PgPool) {
    let block = insert_block(&pool, 0x32, 200).await;
    let owner = vec![0x12_u8; 32];
    let script_owner = vec![0x22_u8; 32];
    let canonical = insert_covenant(
        &pool,
        0x43,
        "kaspatest:canonical",
        Some("KCC20V2"),
        &block,
        200,
    )
    .await;
    let sale = insert_covenant(
        &pool,
        0x44,
        "kaspatest:sale",
        Some("KCC20SaleV2"),
        &block,
        201,
    )
    .await;
    let bid = insert_covenant(
        &pool,
        0x45,
        "kaspatest:bid",
        Some("KCC20BuyOrder"),
        &block,
        202,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $2,
               claimed_args = $3
           WHERE covenant_id = $1"#,
    )
    .bind(&sale)
    .bind(json!({
        "tokenAmount": "12"
    }))
    .bind(json!({
        "args": [
            "ignored scalar",
            null,
            {"name": null, "value": "ignored"},
            {"name": "", "value": "ignored"},
            {"name": "seller", "value": hex::encode(&owner)},
            {"name": "tokenId", "value": hex::encode(&canonical)},
            {"value": "ignored"}
        ]
    }))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $2,
               claimed_args = $3
           WHERE covenant_id = $1"#,
    )
    .bind(&bid)
    .bind(json!({
        "tokenAmount": "9"
    }))
    .bind(json!({
        "args": null,
        "buyer": hex::encode(&owner),
        "tokenId": hex::encode(&canonical)
    }))
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(&pool, &sale, "kaspatest:sale", 1, &block, 0x62).await;
    insert_active_utxo_with_state(
        &pool,
        &canonical,
        "kaspatest:canonical",
        1,
        json!({
            "stateOwner": hex::encode(&sale).to_uppercase(),
            "stateOwnerType": 2,
            "stateAmount": "12"
        }),
        &block,
        0x63,
    )
    .await;
    insert_active_utxo(&pool, &bid, "kaspatest:bid", 1, &block, 0x64).await;
    let zero_bid = insert_covenant(
        &pool,
        0x46,
        "kaspatest:zero-bid",
        Some("KCC20BuyOrder"),
        &block,
        203,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $2
           WHERE covenant_id = $1"#,
    )
    .bind(&zero_bid)
    .bind(json!({
        "buyer": hex::encode(&owner),
        "tokenId": hex::encode(&canonical),
        "tokenAmount": "0"
    }))
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(&pool, &zero_bid, "kaspatest:zero-bid", 1, &block, 0x65).await;
    let oversized_bid = insert_covenant(
        &pool,
        0x47,
        "kaspatest:oversized-bid",
        Some("KCC20BuyOrder"),
        &block,
        204,
    )
    .await;
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $2
           WHERE covenant_id = $1"#,
    )
    .bind(&oversized_bid)
    .bind(json!({
        "buyer": hex::encode(&owner),
        "tokenId": hex::encode(&canonical),
        "tokenAmount": "9".repeat(100)
    }))
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(
        &pool,
        &oversized_bid,
        "kaspatest:oversized-bid",
        1,
        &block,
        0x67,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &canonical,
        "kaspatest:zero-orderbook-order",
        1,
        json!({
            "ownerIdentifier": hex::encode(&owner),
            "amount": "0",
            "mode": 2,
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &block,
        0x66,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &canonical,
        "kaspatest:oversized-orderbook-order",
        2,
        json!({
            "ownerIdentifier": hex::encode(&owner),
            "amount": "9".repeat(100),
            "mode": 2,
            "supplyBacking": "kcc20WrapperReserve"
        }),
        &block,
        0x68,
    )
    .await;
    sqlx::query(
        r#"INSERT INTO kcc20_holders
           (covenant_id, owner_identifier, identifier_type, amount_total,
            utxo_count, is_minter, last_change_ms)
           VALUES
           ($1, $2, 2, 12, 1, FALSE, 203),
           ($1, $3, 1, 5, 1, FALSE, 204)"#,
    )
    .bind(&canonical)
    .bind(&sale)
    .bind(&script_owner)
    .execute(&pool)
    .await
    .unwrap();

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            has_open_orders: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(page.total, 1);
    let row = &page.items[0];
    assert_eq!(row.canonical_token_id_hex, hex::encode(&canonical));
    assert_eq!(row.native_balance, "0");
    assert_eq!(row.orderbook_balance, "0");
    assert_eq!(row.open_ask_amount, "12");
    assert_eq!(row.open_bid_amount, "9");
    assert_eq!(row.open_order_count, 2);
    assert!(!row.actions.wrap.enabled);
    assert!(!row.actions.unwrap.enabled);
    assert!(!row.actions.trade.enabled);
    assert_eq!(
        row.actions.trade.reason.as_deref(),
        Some("wrapper is not available")
    );

    let escrow = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&sale),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(escrow.total, 0);

    let script_hash = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&script_owner),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(script_hash.total, 1);
    assert_eq!(script_hash.items[0].native_balance, "5");
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_follows_sale_continuation_escrow(pool: PgPool) {
    let block = insert_block(&pool, 0x33, 300).await;
    let owner = vec![0x14_u8; 32];
    let canonical = insert_covenant(
        &pool,
        0x48,
        "kaspatest:continuation-token",
        Some("KCC20V2"),
        &block,
        300,
    )
    .await;
    let sale_root = insert_covenant(
        &pool,
        0x49,
        "kaspatest:sale-root",
        Some("KCC20SaleV2"),
        &block,
        301,
    )
    .await;
    let sale_child = insert_covenant(
        &pool,
        0x4a,
        "kaspatest:sale-child",
        Some("KCC20SaleV2"),
        &block,
        302,
    )
    .await;
    let unrelated_child = insert_covenant(
        &pool,
        0x4b,
        "kaspatest:unrelated-sale-child",
        Some("KCC20SaleV2"),
        &block,
        302,
    )
    .await;
    sqlx::query(
        "UPDATE covenants SET claim_verified = TRUE WHERE covenant_id IN ($1, $2, $3)",
    )
    .bind(&sale_root)
    .bind(&sale_child)
    .bind(&unrelated_child)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        r#"UPDATE covenants
           SET constructor_args = $2
           WHERE covenant_id = $1"#,
    )
    .bind(&sale_root)
    .bind(json!({
        "seller": hex::encode(&owner),
        "tokenId": hex::encode(&canonical),
        "tokenAmount": "12"
    }))
    .execute(&pool)
    .await
    .unwrap();
    insert_action(
        &pool,
        &sale_root,
        0x75,
        &block,
        303,
        "spend",
        Some("activateListing"),
    )
    .await;
    sqlx::query(
        "UPDATE covenant_actions SET decoded_args = $1 \
         WHERE covenant_id = $2 AND txid = $3 AND action = 'spend'",
    )
    .bind(json!({"listingOutputIndex": "1"}))
    .bind(&sale_root)
    .bind(vec![0x75_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE covenants SET genesis_txid = $2, genesis_vout = 1 WHERE covenant_id = $1")
        .bind(&sale_child)
        .bind(vec![0x75_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE covenants SET genesis_txid = $2, genesis_vout = 2 WHERE covenant_id = $1")
        .bind(&unrelated_child)
        .bind(vec![0x75_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    insert_active_utxo(&pool, &sale_child, "kaspatest:sale-child", 1, &block, 0x76).await;
    insert_active_utxo(&pool, &unrelated_child, "kaspatest:unrelated-sale-child", 1, &block, 0x78).await;
    insert_active_utxo_with_state(
        &pool,
        &canonical,
        "kaspatest:continuation-token",
        1,
        json!({
            "stateOwner": hex::encode(&sale_child),
            "stateOwnerType": 2,
            "stateAmount": "12"
        }),
        &block,
        0x77,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &canonical,
        "kaspatest:unrelated-token-lock",
        1,
        json!({
            "stateOwner": hex::encode(&unrelated_child),
            "stateOwnerType": 2,
            "stateAmount": "7"
        }),
        &block,
        0x79,
    )
    .await;

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            has_open_orders: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].canonical_token_id_hex, hex::encode(canonical));
    assert_eq!(page.items[0].open_ask_amount, "12");
    assert_eq!(page.items[0].open_order_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
#[ignore = "fixed-lot sale escrow is retired after the standard-native cutover"]
async fn kcc20_owner_portfolio_assets_does_not_link_unrelated_batched_sale(pool: PgPool) {
    let block = insert_block(&pool, 0x34, 400).await;
    let alice = vec![0x15_u8; 32];
    let bob = vec![0x16_u8; 32];
    let alice_token = insert_covenant(
        &pool,
        0x4b,
        "kaspatest:alice-token",
        Some("KCC20V2"),
        &block,
        400,
    )
    .await;
    let bob_token = insert_covenant(
        &pool,
        0x4c,
        "kaspatest:bob-token",
        Some("KCC20V2"),
        &block,
        401,
    )
    .await;
    let alice_root = insert_covenant(
        &pool,
        0x4d,
        "kaspatest:alice-sale-root",
        Some("KCC20SaleV2"),
        &block,
        402,
    )
    .await;
    let alice_child = insert_covenant(
        &pool,
        0x4e,
        "kaspatest:alice-sale-child",
        Some("KCC20SaleV2"),
        &block,
        403,
    )
    .await;
    let bob_sale = insert_covenant(
        &pool,
        0x4f,
        "kaspatest:bob-sale",
        Some("KCC20SaleV2"),
        &block,
        404,
    )
    .await;
    for (sale, owner, token, amount) in [
        (&alice_root, &alice, &alice_token, "12"),
        (&bob_sale, &bob, &bob_token, "7"),
    ] {
        sqlx::query("UPDATE covenants SET constructor_args = $2 WHERE covenant_id = $1")
            .bind(sale)
            .bind(json!({
                "seller": hex::encode(owner),
                "tokenId": hex::encode(token),
                "tokenAmount": amount
            }))
            .execute(&pool)
            .await
            .unwrap();
    }
    insert_action(
        &pool,
        &alice_root,
        0x78,
        &block,
        405,
        "spend",
        Some("activateListing"),
    )
    .await;
    sqlx::query(
        "UPDATE covenant_actions SET decoded_args = $1 \
         WHERE covenant_id = $2 AND txid = $3 AND action = 'spend'",
    )
    .bind(json!({"listingOutputIndex": "1"}))
    .bind(&alice_root)
    .bind(vec![0x78_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE covenants SET genesis_txid = $1, genesis_vout = CASE \
         WHEN covenant_id = $2 THEN 1 ELSE 2 END WHERE covenant_id IN ($2, $3)",
    )
    .bind(vec![0x78_u8; 32])
    .bind(&alice_child)
    .bind(&bob_sale)
    .execute(&pool)
    .await
    .unwrap();
    insert_active_utxo(
        &pool,
        &alice_child,
        "kaspatest:alice-sale-child",
        1,
        &block,
        0x79,
    )
    .await;
    insert_active_utxo(&pool, &bob_sale, "kaspatest:bob-sale", 1, &block, 0x7a).await;
    insert_active_utxo_with_state(
        &pool,
        &alice_token,
        "kaspatest:alice-token",
        1,
        json!({
            "stateOwner": hex::encode(&alice_child),
            "stateOwnerType": 2,
            "stateAmount": "12"
        }),
        &block,
        0x7b,
    )
    .await;
    insert_active_utxo_with_state(
        &pool,
        &bob_token,
        "kaspatest:bob-token",
        1,
        json!({
            "stateOwner": hex::encode(&bob_sale),
            "stateOwnerType": 2,
            "stateAmount": "7"
        }),
        &block,
        0x7c,
    )
    .await;

    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool)
        .await
        .unwrap();
    let alice_page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&alice),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();
    let bob_page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&bob),
        repo::Kcc20PortfolioAssetOptions::default(),
    )
    .await
    .unwrap();

    assert_eq!(alice_page.total, 1);
    assert_eq!(
        alice_page.items[0].canonical_token_id_hex,
        hex::encode(alice_token)
    );
    assert_eq!(alice_page.items[0].open_ask_amount, "12");
    assert_eq!(bob_page.total, 1);
    assert_eq!(
        bob_page.items[0].canonical_token_id_hex,
        hex::encode(bob_token)
    );
    assert_eq!(bob_page.items[0].open_ask_amount, "7");
}

#[sqlx::test(migrations = "./migrations")]
async fn kcc20_owner_portfolio_assets_filters_sorts_and_counts_before_paging(pool: PgPool) {
    let owner = vec![0x13_u8; 32];
    for (tag, value, ticker, orderbook, orders) in [
        (0x51_u8, Some("300"), "THREE", "0", 0_i64),
        (0x52_u8, None, "50% TOKEN", "10", 2_i64),
        (0x53_u8, Some("100"), "ONE", "0", 1_i64),
    ] {
        sqlx::query(
            r#"INSERT INTO kcc20_owner_portfolio_assets
               (owner_identifier, canonical_token_id, native_balance, orderbook_balance,
                total_balance, asset_utxo_count, open_ask_amount, open_bid_amount,
                open_order_count, best_ask_unit_price_sompi, value_sompi,
                fee_ticket_supported, last_change_ms, ticker, decimals,
                refreshed_at_ms)
               VALUES ($1, $2, 1, $4::NUMERIC, 1 + $4::NUMERIC, 1, 0, 0,
                       $5, $3::NUMERIC, $3::NUMERIC, FALSE, $6, $7, 0, 1000)"#,
        )
        .bind(&owner)
        .bind(vec![tag; 32])
        .bind(value)
        .bind(orderbook)
        .bind(orders)
        .bind(i64::from(tag))
        .bind(ticker)
        .execute(&pool)
        .await
        .unwrap();
        if let Some(price) = value {
            sqlx::query(
                "INSERT INTO kcc20_market_summaries (token_id,best_ask_unit_price_sompi,refreshed_at_ms) VALUES ($1,$2::NUMERIC,1000)",
            )
            .bind(vec![tag; 32])
            .bind(price)
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    sqlx::query(
        "UPDATE kcc20_owner_portfolio_assets SET token_name = 'Éclair Named Asset' WHERE canonical_token_id = $1",
    )
    .bind(vec![0x53_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    let page = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            sort_by: "valueSompi".into(),
            sort_direction: "desc".into(),
            limit: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].canonical_token_id_hex,
        hex::encode(vec![0x51; 32])
    );

    let nulls_last = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            sort_by: "valueSompi".into(),
            sort_direction: "desc".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(nulls_last.items.len(), 3);
    assert_eq!(
        nulls_last.items[2].canonical_token_id_hex,
        hex::encode(vec![0x52; 32])
    );

    // Market-only writes must change the displayed value and value sort
    // without rebuilding any owner's holding row.
    sqlx::query(
        "UPDATE kcc20_market_summaries SET best_ask_unit_price_sompi=20 WHERE token_id=$1",
    )
    .bind(vec![0x51_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let repriced = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            sort_by: "valueSompi".into(),
            sort_direction: "desc".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(repriced.items[0].canonical_token_id_hex, hex::encode(vec![0x53; 32]));
    assert_eq!(repriced.items[1].best_ask_unit_price_sompi.as_deref(), Some("20"));
    assert_eq!(repriced.items[1].value_sompi.as_deref(), Some("20"));

    sqlx::query("UPDATE kcc20_owner_portfolio_assets SET wrapped_market_id=$2 WHERE canonical_token_id=$1")
        .bind(vec![0x53_u8; 32])
        .bind(vec![0x54_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO kcc20_market_summaries (token_id,best_ask_unit_price_sompi,best_bid_unit_price_sompi,refreshed_at_ms) VALUES ($1,10,500,1000)",
    )
    .bind(vec![0x54_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let wrapped_market = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            token_id_hex: Some(hex::encode(vec![0x53; 32])),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(wrapped_market.items[0].best_ask_unit_price_sompi.as_deref(), Some("10"));
    assert_eq!(wrapped_market.items[0].best_bid_unit_price_sompi.as_deref(), Some("500"));
    assert_eq!(wrapped_market.items[0].value_sompi.as_deref(), Some("10"));

    let descending_ties = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            sort_by: "nativeBalance".into(),
            sort_direction: "desc".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        descending_ties
            .items
            .iter()
            .map(|row| row.canonical_token_id_hex.as_str())
            .collect::<Vec<_>>(),
        vec![
            hex::encode(vec![0x53; 32]),
            hex::encode(vec![0x52; 32]),
            hex::encode(vec![0x51; 32]),
        ]
    );

    let out_of_range = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            offset: 99,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(out_of_range.total, 3);
    assert!(out_of_range.items.is_empty());

    let search = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            search: Some("%".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(search.total, 1);
    assert_eq!(search.items[0].ticker.as_deref(), Some("50% TOKEN"));

    for (query, expected) in [
        (
            repo::Kcc20PortfolioAssetOptions {
                token_id_hex: Some(hex::encode(vec![0x53; 32])),
                ..Default::default()
            },
            0x53_u8,
        ),
        (
            repo::Kcc20PortfolioAssetOptions {
                search: Some("named".into()),
                ..Default::default()
            },
            0x53_u8,
        ),
        (
            repo::Kcc20PortfolioAssetOptions {
                search: Some("éCLAIR".into()),
                ..Default::default()
            },
            0x53_u8,
        ),
        (
            repo::Kcc20PortfolioAssetOptions {
                search: Some("5252".into()),
                ..Default::default()
            },
            0x52_u8,
        ),
    ] {
        let exact = repo::kcc20_portfolio_assets_for_owner(&pool, &hex::encode(&owner), query)
            .await
            .unwrap();
        assert_eq!(exact.total, 1);
        assert_eq!(
            exact.items[0].canonical_token_id_hex,
            hex::encode(vec![expected; 32])
        );
    }

    let filtered = repo::kcc20_portfolio_assets_for_owner(
        &pool,
        &hex::encode(&owner),
        repo::Kcc20PortfolioAssetOptions {
            has_orderbook_balance: true,
            has_open_orders: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(filtered.total, 1);
    assert_eq!(
        filtered.items[0].canonical_token_id_hex,
        hex::encode(vec![0x52; 32])
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn accepted_child_before_parent_preserves_spend_for_serial_and_bulk(pool: PgPool) {
    // REST sorts txids within one accepting block: a child can precede its parent.
    for (case, bulk, max_txs) in [(1, false, 32), (2, true, 32), (3, true, 128)] {
        let id = |n| format!("{n:064x}");
        let parent_id = id(case * 10 + 9);
        let child_id = id(case * 10 + 1);
        let block = id(case * 10 + 5);
        let parent_script = format!("aa20{}87", id(case * 10 + 6));
        let parent = RestTransaction {
            transaction_id: parent_id.clone(),
            is_accepted: true,
            accepting_block_hash: Some(block.clone()),
            accepting_block_blue_score: Some(100),
            block_time: 1000,
            outputs: vec![RestTxOutput {
                index: 0,
                amount: 1000,
                script_public_key: parent_script.clone(),
                script_public_key_address: Some(format!("kaspatest:pparent{case}")),
                ..Default::default()
            }],
            ..Default::default()
        };
        let child = RestTransaction {
            transaction_id: child_id.clone(),
            inputs: vec![RestTxInput {
                previous_outpoint_hash: parent_id.clone(),
                previous_outpoint_index: "0".into(),
                previous_outpoint_script: Some(parent_script),
                previous_outpoint_amount: Some(1000),
                ..Default::default()
            }],
            outputs: vec![RestTxOutput {
                index: 0,
                amount: 900,
                script_public_key: format!("aa20{}87", id(case * 10 + 7)),
                script_public_key_address: Some(format!("kaspatest:pchild{case}")),
                ..Default::default()
            }],
            ..parent.clone()
        };
        let writer = PgPersister::new(pool.clone())
            .with_bounded_writer_lock_wait()
            .with_generic_bulk_persist(bulk)
            .with_generic_bulk_max_txs(max_txs);
        let mut unaccepted_parent = parent.clone();
        unaccepted_parent.is_accepted = false;
        let invalid = writer
            .persist_batch(&[child.clone(), unaccepted_parent])
            .await;
        assert!(invalid
            .unwrap_err()
            .to_string()
            .contains("in-batch P2SH source output missing"));
        let txs = vec![child, parent];
        for replay in 0..2 {
            writer.persist_batch(&txs).await.unwrap();
            let spent: Option<String> = sqlx::query_scalar(
                "SELECT encode(spent_by_txid, 'hex') FROM covenant_utxos WHERE txid=decode($1,'hex') AND vout=0")
                .bind(&parent_id).fetch_one(&pool).await.unwrap();
            assert_eq!(
                spent.as_deref(),
                Some(child_id.as_str()),
                "bulk={bulk} max={max_txs} replay={replay}"
            );
        }
        writer
            .revert_block(&hex::decode(&block).unwrap())
            .await
            .unwrap();
        writer.persist_batch(&txs).await.unwrap();
        let spent: Option<String> = sqlx::query_scalar(
            "SELECT encode(spent_by_txid, 'hex') FROM covenant_utxos WHERE txid=decode($1,'hex') AND vout=0")
            .bind(&parent_id).fetch_one(&pool).await.unwrap();
        assert_eq!(spent.as_deref(), Some(child_id.as_str()));
        // Reproduce already committed old state, then repair through normal replay.
        writer
            .revert_block(&hex::decode(&block).unwrap())
            .await
            .unwrap();
        writer.persist_tx(&txs[0]).await.unwrap();
        writer.persist_tx(&txs[1]).await.unwrap();
        writer.persist_batch(&txs).await.unwrap();
        let repaired: (String, String) = sqlx::query_as(
            "SELECT encode(spent_by_txid,'hex'), encode(spent_block,'hex') FROM covenant_utxos WHERE txid=decode($1,'hex') AND vout=0")
            .bind(&parent_id).fetch_one(&pool).await.unwrap();
        assert_eq!(repaired, (child_id.clone(), block.clone()));
        let spends: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM covenant_actions WHERE txid=decode($1,'hex') AND action='spend'",
        )
        .bind(&child_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(spends, 1);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn reclassify_kcc20_authenticates_balances_and_rejects_reorged_actions(pool: PgPool) {
    use tn12_indexer_decoder::kcc20_standard;
    let block = insert_block(&pool, 0xa1, 100).await;
    let cov = insert_covenant(&pool, 0xa2, "kaspatest:external", None, &block, 100).await;
    let state = json!({"amount":"100", "owner":"11".repeat(32), "ownerScheme":0,
        "borrowScheme":0, "borrowGuard":"00".repeat(32), "extensionCommitment":"22".repeat(32)});
    let mut next = state.clone();
    next["owner"] = json!("33".repeat(32));
    let reveal = kcc20_standard::script_for_state_value(&state).unwrap();
    let successor = kcc20_standard::script_for_state_value(&next).unwrap();
    insert_active_utxo_with_script_hash(
        &pool,
        &cov,
        "input",
        10000,
        &blake2b_256(&reveal),
        &block,
        0xa3,
    )
    .await;
    // Start with a mismatched output. Reclassification must roll back all writes.
    insert_active_utxo_with_script_hash(&pool, &cov, "output", 10000, &[0; 32], &block, 0xa4).await;
    insert_action_with_inputs(
        &pool,
        &cov,
        0xa4,
        &block,
        200,
        "spend",
        json!({"previousOutpoint":{"hash":"a3".repeat(32),"index":0}}),
    )
    .await;
    let action_id: i64 =
        sqlx::query_scalar("SELECT id FROM covenant_actions WHERE covenant_id = $1")
            .bind(&cov)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut sig = Vec::new();
    push_data(&mut sig, &100i64.to_le_bytes());
    push_data(&mut sig, &[0x33; 32]);
    push_data(&mut sig, &[0]);
    push_data(&mut sig, &[0]);
    push_data(&mut sig, &[0; 32]);
    push_data(&mut sig, &[0x22; 32]);
    push_data(&mut sig, &kcc20_standard::TRANSFER_TAG);
    push_data(&mut sig, &reveal);
    let sig = hex::encode(sig);
    let persister = PgPersister::new(pool.clone());
    let spend = vec![0xa4; 32];
    assert!(persister
        .reclassify_covenant(action_id, &cov, &spend, &sig)
        .await
        .is_err());
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM covenant_utxos WHERE covenant_id = $1 AND state IS NOT NULL",
    )
    .bind(&cov)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 0);
    let mut spk = vec![0xaa, 0x20];
    spk.extend(blake2b_256(&successor));
    spk.push(0x87);
    sqlx::query("UPDATE covenant_utxos SET script_pubkey = $1 WHERE txid = $2")
        .bind(spk)
        .bind(&spend)
        .execute(&pool)
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            persister
                .reclassify_covenant(action_id, &cov, &spend, &sig)
                .await
                .unwrap()
                .as_deref(),
            Some("KCC20")
        );
    }
    let states: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE covenant_id = $1 ORDER BY txid")
            .bind(&cov)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(states.len(), 2);
    assert_eq!(states[0]["amount"], "100");
    assert_eq!(states[1]["owner"], "33".repeat(32));
    assert!(repo::unclassified_covenants_with_spends(&pool, 0)
        .await
        .unwrap()
        .is_empty());
    // Reorg persistence removes the action. A delayed repair must not recreate it.
    sqlx::query("DELETE FROM covenant_actions WHERE id = $1")
        .bind(action_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(persister
        .reclassify_covenant(action_id, &cov, &spend, &sig)
        .await
        .is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_recipient_continuation_survives_duplicate_and_reorg(pool: PgPool) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-fee-escrow-v1/recipient-rotation-back.json")).unwrap();
    let block = insert_block(&pool, 1, 100).await;
    let account = insert_covenant(&pool, 5, "kaspatest:fee-account", Some("KCC20FeeEscrowV1"), &block, 100).await;
    let recipient = insert_covenant(&pool, 6, "kaspatest:fee-recipient", Some("KCC20FeeRecipientV1"), &block, 100).await;
    let accepted_block = insert_block(&pool, 3, 200).await;
    let mut tx: RestTransaction = serde_json::from_value(fixture["transaction"].clone()).unwrap();
    tx.is_accepted = true;
    tx.version = 1;
    tx.block_hash = vec![hex::encode(&accepted_block)];
    tx.accepting_block_hash = Some(hex::encode(&accepted_block));
    tx.accepting_block_blue_score = Some(200);
    tx.block_time = 1778654400200;
    tx.accepting_block_time = Some(tx.block_time);
    let decoders = tn12_indexer_decoder::default_registry();
    for (index, id, seed) in [(0, &account, 20), (1, &recipient, 21)] {
        let witness = hex::decode(&tx.inputs[index].signature_script).unwrap();
        let reveal = tn12_indexer_db::persist::extract_last_push(&witness).unwrap();
        let state = decoders.find_for_reveal(&reveal).unwrap().decode_constructor(&reveal).unwrap();
        insert_active_utxo_with_state(&pool, id, "kaspatest:fee-source",
            tx.inputs[index].previous_outpoint_amount.unwrap() as i64,state,&block,seed).await;
        sqlx::query("UPDATE covenant_utxos SET script_pubkey=$1 WHERE txid=decode($2,'hex') AND vout=0")
            .bind(hex::decode(tx.inputs[index].previous_outpoint_script.as_ref().unwrap()).unwrap())
            .bind(&tx.inputs[index].previous_outpoint_hash).execute(&pool).await.unwrap();
    }
    tx.inputs[1].previous_outpoint_amount = None;
    let persister = PgPersister::new(pool.clone());
    for _ in 0..2 {
        persister.persist_tx(&tx).await.unwrap();
        let row = sqlx::query("SELECT state,amount_sompi FROM covenant_utxos WHERE txid=decode($1,'hex') AND covenant_id=$2 AND status='active'")
            .bind(&tx.transaction_id).bind(&recipient).fetch_one(&pool).await.unwrap();
        let state: serde_json::Value = row.get("state");
        assert_eq!(state["roleName"], "recipient");
        assert_ne!(state["action_hash"], "00".repeat(32));
        assert_eq!(row.get::<i64,_>("amount_sompi"),70_000_000);
    }
    persister.revert_block(&accepted_block).await.unwrap();
    let old: Vec<u8> = sqlx::query_scalar("SELECT txid FROM covenant_utxos WHERE covenant_id=$1 AND status='active'")
        .bind(&recipient).fetch_one(&pool).await.unwrap();
    assert_eq!(old,vec![21_u8;32]);
    persister.persist_tx(&tx).await.unwrap();
    let recovered: serde_json::Value = sqlx::query_scalar("SELECT state FROM covenant_utxos WHERE txid=decode($1,'hex') AND covenant_id=$2 AND status='active'")
        .bind(&tx.transaction_id).bind(&recipient).fetch_one(&pool).await.unwrap();
    assert_eq!(recovered["roleName"], "recipient");
}

#[sqlx::test(migrations = "./migrations")]
async fn fee_market_portfolio_groups_wrapped_holdings_under_canonical_token(pool: PgPool) {
    let block = insert_block(&pool, 0x91, 100).await;
    let token = insert_covenant(&pool, 1, "kaspatest:fee-token", Some("KCC20"), &block, 100).await;
    let market = insert_covenant(&pool, 2, "kaspatest:fee-market", Some("KCC20OrderbookFeeRootV1"), &block, 100).await;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tn12-indexer-decoder/fixtures/kcc20-fee-escrow-v1/signed-cross-3-2.json")).unwrap();
    let owner = hex::decode(fixture["ask"]["owner"].as_str().unwrap()).unwrap();
    let mut state = fixture["ask"].clone();
    state["feePolicyVersion"] = json!(1);
    state["ownerScheme"] = json!(0);
    state["mode"] = json!("0");
    state["unitPrice"] = json!("0");
    state["amount"] = json!("7");
    insert_active_utxo_with_state(&pool, &market, "kaspatest:fee-holder", 50_000_000, state, &block, 0xa1).await;
    sqlx::query("INSERT INTO kcc20_holders (covenant_id, owner_identifier, identifier_type, amount_total, utxo_count, is_minter, last_change_ms) VALUES ($1,$3,0,5,1,FALSE,1000),($2,$3,0,7,1,FALSE,1000)")
        .bind(&token).bind(&market).bind(&owner).execute(&pool).await.unwrap();
    let (rows, total) = repo::kcc20_portfolio_for_owner(&pool, &hex::encode(&owner), repo::Kcc20PortfolioOptions {
        include_wrapped: true, include_totals: true, ..Default::default()
    }).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].canonical_token_id_hex, hex::encode(&token));
    assert_eq!(rows[0].native_balance, "5");
    assert_eq!(rows[0].orderbook_balance.as_deref(), Some("7"));
    assert_eq!(rows[0].total_balance.as_deref(), Some("12"));
    let (native, _) = repo::kcc20_portfolio_for_owner(&pool, &hex::encode(&owner), repo::Kcc20PortfolioOptions::default()).await.unwrap();
    assert_eq!(native.len(), 1);
    assert_eq!(native[0].canonical_token_id_hex, hex::encode(&token));
    assert_eq!(native[0].native_balance, "5");
    repo::refresh_kcc20_owner_orders(&pool).await.unwrap();
    repo::refresh_kcc20_owner_portfolio_assets(&pool).await.unwrap();
    let row = sqlx::query("SELECT canonical_token_id, native_balance::TEXT AS native, orderbook_balance::TEXT AS wrapped, total_balance::TEXT AS total, wrapped_market_id FROM kcc20_owner_portfolio_assets WHERE owner_identifier=$1")
        .bind(&owner).fetch_one(&pool).await.unwrap();
    assert_eq!(row.get::<Vec<u8>, _>("canonical_token_id"), token);
    assert_eq!(row.get::<Vec<u8>, _>("wrapped_market_id"), market);
    assert_eq!(row.get::<String, _>("native"), "5");
    assert_eq!(row.get::<String, _>("wrapped"), "7");
    assert_eq!(row.get::<String, _>("total"), "12");
    let registered: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kcc20_wrapper_summaries WHERE wrapper_id=$1")
        .bind(&market).fetch_one(&pool).await.unwrap();
    assert_eq!(registered, 0, "read-side identity must not create a legacy market registration");
}


#[sqlx::test(migrations = "./migrations")]
async fn public_market_reads_keep_fee_fallbacks_and_use_order_indexes(pool: PgPool) {
    let block = insert_block(&pool, 1, 100).await;
    let native = insert_covenant(
        &pool,
        2,
        "kaspatest:native",
        Some("KCC20Orderbook"),
        &block,
        100,
    )
    .await;
    let fee = insert_covenant(
        &pool,
        3,
        "kaspatest:fee",
        Some("KCC20OrderbookFeeRootV1"),
        &block,
        100,
    )
    .await;
    let wrapper = insert_covenant(
        &pool,
        4,
        "kaspatest:wrapper",
        Some("KCC20Wrapper"),
        &block,
        100,
    )
    .await;
    let token = "33".repeat(32);
    let owner = "11".repeat(32);
    let other = "22".repeat(32);
    let mut id = 10_u8;
    for mode in [2, 3] {
        // Standard, fee fallback without a policy, normal fee, dual-owner fee,
        // and a wrapper-backed fee without a policy must each survive once.
        for kind in 0..5 {
            let mut state = json!({"canonicalTokenId": token, "mode": mode,
                "amount": "3", "unitPriceSompi": "100", "unitPrice": "100",
                "priceScale": "1", "minFillAmount": "1"});
            if kind == 0 {
                state["ownerIdentifier"] = json!(owner);
            } else {
                state["owner"] = json!(owner);
                state["feePolicyVersion"] = json!(1);
                if kind == 2 || kind == 3 {
                    state["feePolicy"] = json!("ab".repeat(361));
                }
                if kind == 3 {
                    state["ownerIdentifier"] = json!(owner);
                    state["owner"] = json!(other);
                }
                if kind == 4 {
                    state["supplyBacking"] = json!("kcc20WrapperReserve");
                }
            }
            let covenant = if kind < 2 {
                &native
            } else if kind == 4 {
                &wrapper
            } else {
                &fee
            };
            insert_active_utxo_with_state(
                &pool,
                covenant,
                "kaspatest:order",
                1000,
                state,
                &block,
                id,
            )
            .await;
            id += 1;
        }
    }
    // Holder cells and an unqualified fee-looking state cannot become orders.
    for (mode, covenant) in [(0, &native), (2, &fee), (3, &fee)] {
        insert_active_utxo_with_state(
            &pool,
            covenant,
            "kaspatest:not-order",
            1000,
            json!({"canonicalTokenId": token, "mode": mode, "amount": "3",
                "owner": owner, "feePolicyVersion": 1, "unitPrice": "100", "priceScale": "1"}),
            &block,
            id,
        )
        .await;
        id += 1;
    }
    let asks = repo::kcc20_listings(&pool, Some(&token), Some(&owner))
        .await
        .unwrap();
    let bids = repo::kcc20_bids(&pool, Some(&token), Some(&owner))
        .await
        .unwrap();
    assert_eq!(asks.len(), 5);
    assert_eq!(bids.len(), 5);
    assert!(asks.iter().all(|r| r.price_sompi.as_deref() == Some("300")));
    assert!(bids.iter().all(|r| r.price_sompi.as_deref() == Some("300")));
    assert!(repo::kcc20_listings(&pool, None, Some(&other))
        .await
        .unwrap()
        .is_empty());
    assert!(repo::kcc20_bids(&pool, None, Some(&other))
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        repo::kcc20_listings(&pool, Some(&hex::encode(&native)), None)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        repo::kcc20_bids(&pool, Some(&hex::encode(&native)), None)
            .await
            .unwrap()
            .len(),
        2
    );
    sqlx::query("UPDATE covenant_utxos SET status='spent' WHERE txid=$1")
        .bind(vec![10_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        repo::kcc20_listings(&pool, Some(&token), None)
            .await
            .unwrap()
            .len(),
        4
    );

    // Holder cells dominate the live table. Give the planner that distribution
    // and fresh statistics instead of forcing a plan on a tiny fixture.
    sqlx::query(
        r#"INSERT INTO covenant_utxos
           (txid, vout, covenant_id, address, amount_sompi, script_pubkey,
            state, created_block, status)
           SELECT decode(lpad(to_hex(n),64,'0'),'hex'), 0, $1,
                  'kaspatest:holder', 1, decode('00','hex'),
                  jsonb_build_object('mode',0,'ownerIdentifier',repeat('11',32)),
                  $2, 'active'
           FROM generate_series(1000000,1009999) n"#,
    )
    .bind(&native)
    .bind(&block)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ANALYZE covenant_utxos")
        .execute(&pool)
        .await
        .unwrap();

    // Explain the exact production SQL with normal planner settings.
    let mut tx = pool.begin().await.unwrap();
    for query in [
        concat!(
            "EXPLAIN (COSTS OFF) ",
            include_str!("../src/repo/kcc20_listings.sql")
        ),
        concat!(
            "EXPLAIN (COSTS OFF) ",
            include_str!("../src/repo/kcc20_bids.sql")
        ),
    ] {
        let plan: Vec<String> = sqlx::query_scalar(query)
            .bind(None::<Vec<u8>>)
            .bind(None::<String>)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        let text = plan.join("\n");
        assert!(
            text.contains("covenant_utxos_kcc20_owner_order_state_idx"),
            "{text}"
        );
        assert!(
            text.contains("covenant_utxos_kcc20_public_fee_order_idx"),
            "{text}"
        );
    }
    tx.rollback().await.unwrap();

    // A completed build can survive a crash before its migration is recorded.
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version=20261112010000")
        .execute(&pool)
        .await
        .unwrap();
    migrate(&pool).await.unwrap();
    assert_eq!(
        repo::kcc20_bids(&pool, Some(&token), None)
            .await
            .unwrap()
            .len(),
        5
    );

    // A failed concurrent build must be repairable without dropping valid data.
    sqlx::query("DROP INDEX CONCURRENTLY covenant_utxos_kcc20_public_fee_order_idx")
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlx::query("CREATE UNIQUE INDEX CONCURRENTLY covenant_utxos_kcc20_public_fee_order_idx ON covenant_utxos (status)")
        .execute(&pool).await.is_err());
    migrate(&pool).await.unwrap();
    let valid: bool = sqlx::query_scalar("SELECT indisvalid FROM pg_index WHERE indexrelid='covenant_utxos_kcc20_public_fee_order_idx'::regclass")
        .fetch_one(&pool).await.unwrap();
    assert!(valid);
    assert_eq!(
        repo::kcc20_bids(&pool, Some(&token), None)
            .await
            .unwrap()
            .len(),
        5
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn portfolio_price_sort_discovers_market_identities_once(pool: PgPool) {
    let owner = vec![0x19_u8; 32];
    for tag in 1..=50_u8 {
        sqlx::query("INSERT INTO kcc20_owner_portfolio_assets (owner_identifier,canonical_token_id,native_balance,orderbook_balance,total_balance,refreshed_at_ms,decimals) VALUES ($1,$2,1,0,1,1000,0)")
            .bind(&owner).bind(vec![tag; 32]).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO kcc20_market_summaries(token_id,best_ask_unit_price_sompi,refreshed_at_ms) VALUES($1,$2,1000)")
            .bind(vec![tag; 32]).bind(i64::from(tag)).execute(&pool).await.unwrap();
    }
    // Exercise the same SQL included by the repository, including ordering before
    // LIMIT. Assert work count rather than a machine-dependent time threshold.
    let query = format!(
        include_str!("../src/repo/kcc20_portfolio_assets.sql"),
        order_by = "valuation.value_sompi DESC NULLS LAST, a.canonical_token_id DESC"
    );
    let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, FORMAT JSON) {query}"
    )))
    .bind(&owner)
    .bind(None::<Vec<u8>>)
    .bind(None::<String>)
    .bind(false)
    .bind(false)
    .bind(false)
    .bind(2_i64)
    .bind(0_i64)
    .fetch_one(&pool)
    .await
    .unwrap();
    fn scans(node: &serde_json::Value, loops: &mut Vec<u64>) {
        if node["Relation Name"] == "covenant_utxos" {
            loops.push(node["Actual Loops"].as_u64().unwrap());
        }
        if let Some(children) = node["Plans"].as_array() {
            for child in children {
                scans(child, loops);
            }
        }
    }
    let mut loops = Vec::new();
    scans(&plan[0]["Plan"], &mut loops);
    assert!(
        !loops.is_empty(),
        "plan must exercise fee identity discovery"
    );
    assert!(
        loops.iter().all(|&count| count <= 1),
        "fee UTXOs must not be scanned for every holding: {loops:?}"
    );
    for offset in [0_i64, 2, 48] {
        let page = repo::kcc20_portfolio_assets_for_owner(
            &pool,
            &hex::encode(&owner),
            repo::Kcc20PortfolioAssetOptions {
                sort_by: "valueSompi".into(),
                sort_direction: "desc".into(),
                limit: 2,
                offset,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(page.total, 50);
        assert_eq!(
            page.items[0].value_sompi.as_deref(),
            Some((50 - offset).to_string().as_str())
        );
        assert_eq!(
            page.items[1].value_sompi.as_deref(),
            Some((49 - offset).to_string().as_str())
        );
    }
}
