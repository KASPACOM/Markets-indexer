//! Locked classification of an already recorded historical acceptance map.
use super::acceptance_map_apply::remaining_budget;
use super::{AcceptanceReconciliationStats, HistoricalAcceptanceMapProof};
use anyhow::{ensure, Result};
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use std::collections::BTreeMap;
use tokio::time::Instant;

/// Caller must hold the shared writer lock. Absence is not authorization to
/// write: the transition must still compare the complete original cohort.
pub(super) async fn classify_applied(
    conn: &mut Transaction<'_, Postgres>,
    proof: &HistoricalAcceptanceMapProof,
    deadline: impl Into<Option<Instant>>,
) -> Result<Option<AcceptanceReconciliationStats>> {
    let deadline = deadline.into();
    macro_rules! query {
        ($q:expr) => {{
            remaining_budget(conn, deadline).await?;
            $q.await?
        }};
    }
    let record:Option<(Vec<u8>,String,Vec<u8>,Vec<u8>)>=query!(sqlx::query_as("SELECT proof_hash,status,cohort_digest,window_digest FROM historical_acceptance_maps WHERE proof_hash=$1")
        .bind(proof.proof_hash().as_slice()).fetch_optional(&mut **conn));
    let Some((hash, status, cohort_digest, window_digest)) = record else {
        return Ok(None);
    };
    ensure!(
        status == "applied",
        "historical acceptance map lost a canonical target"
    );
    ensure!(
        hash == proof.proof_hash()
            && cohort_digest == proof.cohort.digest()
            && window_digest == proof.source.window_digest(),
        "historical acceptance ledger digest mismatch"
    );
    let entries:Vec<(Vec<u8>,Vec<u8>,Vec<u8>,i64,i64)>=query!(sqlx::query_as("SELECT old_hash,txid,target_hash,target_score,target_time_ms FROM historical_acceptance_map_entries WHERE proof_hash=$1 ORDER BY txid")
        .bind(proof.proof_hash().as_slice()).fetch_all(&mut **conn));
    let expected: Vec<_> = proof
        .source
        .targets()
        .iter()
        .map(|t| {
            (
                t.old_hash.clone(),
                t.transaction_id.clone(),
                t.target_hash.clone(),
                t.target_score as i64,
                t.target_time_ms as i64,
            )
        })
        .collect();
    ensure!(
        entries == expected,
        "historical acceptance ledger has incomplete or different targets"
    );
    let sources:Vec<Vec<u8>>=query!(sqlx::query_scalar("SELECT old_hash FROM historical_acceptance_map_sources WHERE proof_hash=$1 ORDER BY old_hash")
        .bind(proof.proof_hash().as_slice()).fetch_all(&mut **conn));
    ensure!(
        sources == proof.cohort.old_hashes(),
        "historical acceptance ledger source set differs"
    );
    let roots: Vec<_> = proof
        .source
        .targets()
        .iter()
        .map(|t| t.target_hash.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let terminals:Vec<(Vec<u8>,Vec<u8>,i32,bool,bool,Option<i64>,Option<i64>,Option<bool>)>=query!(sqlx::query_as(r#"
        WITH RECURSIVE paths(root,hash,path,cycle) AS (
            SELECT h,h,ARRAY[h]::bytea[],FALSE FROM unnest($1::bytea[]) h
            UNION ALL
            SELECT p.root,r.new_hash,p.path || r.new_hash,r.new_hash=ANY(p.path)
            FROM paths p JOIN canonical_block_replacements r ON r.old_hash=p.hash
            WHERE NOT p.cycle AND cardinality(p.path)<33
        ) SELECT p.root,p.hash,cardinality(p.path),p.cycle,r.old_hash IS NOT NULL,b.blue_score,b.timestamp_ms,b.is_chain_block
        FROM paths p LEFT JOIN canonical_block_replacements r ON r.old_hash=p.hash LEFT JOIN blocks b ON b.hash=p.hash
        WHERE p.cycle OR cardinality(p.path)=33 OR r.old_hash IS NULL
    "#).bind(&roots).fetch_all(&mut **conn));
    ensure!(
        terminals.len() == roots.len(),
        "historical acceptance target lineage is incomplete"
    );
    let mut resolved = BTreeMap::new();
    for (root, hash, depth, cycle, has_next, score, time, canonical) in terminals {
        ensure!(
            !cycle && !has_next && depth <= 33 && canonical == Some(true),
            "historical acceptance target lineage is cyclic, too deep, missing or noncanonical"
        );
        let score = score.ok_or_else(|| anyhow::anyhow!("canonical target score missing"))?;
        let time = time.ok_or_else(|| anyhow::anyhow!("canonical target timestamp missing"))?;
        let original = proof
            .source
            .targets()
            .iter()
            .find(|t| t.target_hash == root)
            .expect("requested target");
        ensure!(
            score == original.target_score as i64
                && (hash != root || time == original.target_time_ms as i64),
            "canonical successor metadata differs from equivalent acceptance evidence"
        );
        ensure!(
            resolved.insert(root, (hash, score, time)).is_none(),
            "duplicate canonical target lineage"
        );
    }
    let by_tx: BTreeMap<_, _> = proof
        .source
        .targets()
        .iter()
        .map(|t| {
            (
                t.transaction_id.clone(),
                resolved.get(&t.target_hash).expect("resolved target"),
            )
        })
        .collect();
    let requested = Value::Array(
        proof
            .cohort
            .references
            .iter()
            .enumerate()
            .map(|(index, r)| serde_json::json!({"ordinal":index,"kind":r.kind,"data":r.row}))
            .collect(),
    );
    let rows:Vec<(i32,Value)>=query!(sqlx::query_as(r#"
        WITH wanted AS MATERIALIZED (SELECT * FROM jsonb_to_recordset($1::jsonb) r(ordinal int,kind text,data jsonb))
        SELECT w.ordinal,to_jsonb(u) FROM wanted w JOIN covenant_utxos u ON u.txid=(w.data->>'txid')::bytea AND u.vout=(w.data->>'vout')::int WHERE w.kind IN ('created','spent')
        UNION ALL SELECT w.ordinal,to_jsonb(a) FROM wanted w JOIN covenant_actions a ON a.id=(w.data->>'id')::bigint WHERE w.kind='action'
        UNION ALL SELECT w.ordinal,to_jsonb(c) FROM wanted w JOIN covenants c ON c.covenant_id=(w.data->>'covenant_id')::bytea WHERE w.kind='genesis'
        ORDER BY 1
    "#).bind(requested).fetch_all(&mut **conn));
    ensure!(
        rows.len() == proof.cohort.reference_count(),
        "recorded historical acceptance map has missing references"
    );
    let mut current = proof.cohort.clone();
    for (index, (ordinal, row)) in rows.into_iter().enumerate() {
        ensure!(
            ordinal as usize == index,
            "recorded historical acceptance reference is duplicated"
        );
        let reference = &mut current.references[index];
        let (target, _, time) = by_tx
            .get(&reference.transaction_id)
            .expect("mapped transaction");
        let block = Value::String(format!("\\x{}", hex::encode(target)));
        let original = &reference.row;
        let valid = match reference.kind.as_str() {
            "created" => {
                row["created_block"] == block
                    && row["txid"] == original["txid"]
                    && row["vout"] == original["vout"]
                    && row["covenant_id"] == original["covenant_id"]
            }
            "spent" => {
                row["spent_block"] == block
                    && row["spent_by_txid"] == original["spent_by_txid"]
                    && row["status"] == "spent"
                    && row["txid"] == original["txid"]
                    && row["vout"] == original["vout"]
            }
            "action" => {
                row["block_hash"] == block
                    && row["block_time_ms"] == Value::from(*time)
                    && row["txid"] == original["txid"]
                    && row["covenant_id"] == original["covenant_id"]
                    && row["action"] == original["action"]
            }
            "genesis" => {
                row["genesis_block"] == block
                    && row["created_at_ms"] == Value::from(*time)
                    && row["genesis_txid"] == original["genesis_txid"]
                    && row["genesis_vout"] == original["genesis_vout"]
            }
            _ => false,
        };
        ensure!(
            valid,
            "recorded historical acceptance map has stale or conflicting references"
        );
        reference.row = row;
    }
    super::acceptance_map_proof::validate_content(&current, &proof.source)?;
    let mapping=Value::Array(by_tx.iter().map(|(txid,(target,_,_))|serde_json::json!({"txid":hex::encode(txid),"target":hex::encode(target)})).collect());
    let wrong:bool=query!(sqlx::query_scalar(r#"WITH m AS (SELECT decode(txid,'hex') txid,decode(target,'hex') target FROM jsonb_to_recordset($1::jsonb) m(txid text,target text))
        SELECT EXISTS(SELECT 1 FROM m JOIN covenant_utxos u ON u.txid=m.txid WHERE u.created_block<>m.target)
        OR EXISTS(SELECT 1 FROM m JOIN covenant_actions a ON a.txid=m.txid WHERE a.block_hash<>m.target)
        OR EXISTS(SELECT 1 FROM m JOIN covenants c ON c.genesis_txid=m.txid WHERE c.genesis_block<>m.target)"#).bind(mapping).fetch_one(&mut **conn));
    ensure!(
        !wrong,
        "recorded historical acceptance transaction has contradictory additional references"
    );
    let stale: bool = query!(sqlx::query_scalar(
        r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos WHERE created_block=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM covenant_utxos WHERE spent_block=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM covenant_actions WHERE block_hash=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM covenants WHERE genesis_block=ANY($1::bytea[]))
        OR EXISTS(SELECT 1 FROM blocks WHERE hash=ANY($1::bytea[]) AND is_chain_block)"#
    )
    .bind(proof.cohort.old_hashes())
    .fetch_one(&mut **conn));
    ensure!(
        !stale,
        "recorded historical acceptance source retains references or canonical status"
    );
    Ok(Some(AcceptanceReconciliationStats {
        already_reconciled: true,
        ..Default::default()
    }))
}
