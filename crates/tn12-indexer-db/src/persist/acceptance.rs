//! Accepting-block conflicts must be resolved from canonical chain evidence.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::collections::HashSet;

use super::PgPersister;

#[derive(Debug, Clone, thiserror::Error)]
#[error("accepting block conflict: persisted {persisted_hash}, incoming {incoming_hash}")]
pub struct AcceptanceConflict {
    pub transaction_id: String,
    pub persisted_hash: String,
    pub incoming_hash: String,
}

#[derive(Debug, thiserror::Error)]
#[error("persisted output content conflicts with incoming transaction evidence")]
pub struct AcceptanceEvidenceConflict;

impl AcceptanceConflict {
    pub(super) fn new(txid: &[u8], persisted_hash: &[u8], incoming_hash: &[u8]) -> Self {
        Self {
            transaction_id: hex::encode(txid),
            persisted_hash: hex::encode(persisted_hash),
            incoming_hash: hex::encode(incoming_hash),
        }
    }
}

/// Distinguishes a valid, settled canonical acceptance change from an
/// equivalent block replacement. Only a separate complete map proof may repair it.
#[derive(Debug, thiserror::Error)]
#[error("accepting blocks do not have equivalent chain evidence")]
pub struct NonEquivalentBlockEvidence;

/// Facts fetched from the configured node-backed REST block endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptingBlockEvidence {
    pub hash: Vec<u8>,
    pub is_chain_block: bool,
    pub blue_score: u64,
    pub timestamp: u64,
    pub selected_parent: Vec<u8>,
    pub parents: Vec<Vec<Vec<u8>>>,
    pub accepted_id_merkle_root: Vec<u8>,
    pub utxo_commitment: Vec<u8>,
}

/// A narrow replacement: identical acceptance and UTXO commitments at the
/// same chain position. General reorganizations still require rollback.
#[derive(Debug, Clone, Serialize)]
pub struct CanonicalBlockReplacement {
    old: AcceptingBlockEvidence,
    new: AcceptingBlockEvidence,
    source_tip: u64,
    accepted_txids: Vec<Vec<u8>>,
    accepted_inputs: Vec<AcceptedInputEvidence>,
    accepted_outputs: Vec<AcceptedOutputEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptedInputEvidence {
    pub transaction_id: Vec<u8>,
    pub previous_txid: Vec<u8>,
    pub previous_vout: i32,
    pub previous_amount: Option<u64>,
    pub previous_script: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptedOutputEvidence {
    pub transaction_id: Vec<u8>,
    pub vout: i32,
    pub amount: u64,
    pub script: Vec<u8>,
}

pub(super) fn validate_accepting_block_evidence(block: &AcceptingBlockEvidence) -> Result<()> {
    anyhow::ensure!(
        [
            &block.hash,
            &block.selected_parent,
            &block.accepted_id_merkle_root,
            &block.utxo_commitment
        ]
        .iter()
        .all(|hash| hash.len() == 32)
            && !block.parents.is_empty()
            && block
                .parents
                .iter()
                .all(|level| !level.is_empty() && level.iter().all(|hash| hash.len() == 32))
            && block.parents[0].contains(&block.selected_parent),
        "incomplete accepting block evidence"
    );
    anyhow::ensure!(
        block.blue_score <= i64::MAX as u64 && block.timestamp <= i64::MAX as u64,
        "accepting block metadata exceeds database range"
    );
    Ok(())
}

pub(super) fn validate_acceptance_membership(
    accepted_txids: &[Vec<u8>],
    accepted_inputs: &[AcceptedInputEvidence],
    accepted_outputs: &[AcceptedOutputEvidence],
) -> Result<()> {
    anyhow::ensure!(
        !accepted_txids.is_empty()
            && accepted_txids.len() <= 50_000
            && accepted_txids.iter().all(|txid| txid.len() == 32)
            && accepted_txids.iter().collect::<HashSet<_>>().len() == accepted_txids.len(),
        "invalid or oversized canonical acceptance membership"
    );
    let members: HashSet<_> = accepted_txids.iter().collect();
    anyhow::ensure!(
        accepted_inputs.len() <= 200_000
            && accepted_inputs
                .iter()
                .all(|input| members.contains(&input.transaction_id)
                    && input.previous_txid.len() == 32
                    && input.previous_vout >= 0
                    && input
                        .previous_amount
                        .is_some_and(|amount| amount <= i64::MAX as u64)
                    && input
                        .previous_script
                        .as_ref()
                        .is_some_and(|script| !script.is_empty())),
        "invalid or oversized canonical input evidence"
    );
    anyhow::ensure!(
        accepted_inputs
            .iter()
            .map(|input| (
                &input.transaction_id,
                &input.previous_txid,
                input.previous_vout
            ))
            .collect::<HashSet<_>>()
            .len()
            == accepted_inputs.len(),
        "duplicate canonical input evidence"
    );
    anyhow::ensure!(
        accepted_outputs.len() <= 200_000
            && accepted_outputs
                .iter()
                .all(|output| members.contains(&output.transaction_id)
                    && output.vout >= 0
                    && output.amount <= i64::MAX as u64
                    && !output.script.is_empty()),
        "invalid or oversized canonical output evidence"
    );
    anyhow::ensure!(
        accepted_outputs
            .iter()
            .map(|output| (&output.transaction_id, output.vout))
            .collect::<HashSet<_>>()
            .len()
            == accepted_outputs.len(),
        "duplicate canonical output evidence"
    );
    Ok(())
}

impl CanonicalBlockReplacement {
    pub fn target_block(&self) -> &AcceptingBlockEvidence { &self.new }
    pub fn verify(
        old: AcceptingBlockEvidence,
        new: AcceptingBlockEvidence,
        source_tip: u64,
        accepted_txids: Vec<Vec<u8>>,
        accepted_inputs: Vec<AcceptedInputEvidence>,
        accepted_outputs: Vec<AcceptedOutputEvidence>,
    ) -> Result<Self> {
        Self::verify_at_depth(
            old,
            new,
            source_tip,
            accepted_txids,
            accepted_inputs,
            accepted_outputs,
            1_000,
        )
    }

    /// Live cursors can reconcile after two complete ten-score REST windows.
    /// The proof still requires removed/canonical block facts, equivalent
    /// commitments, and complete acceptance membership from one source.
    pub fn verify_recent(
        old: AcceptingBlockEvidence,
        new: AcceptingBlockEvidence,
        source_tip: u64,
        accepted_txids: Vec<Vec<u8>>,
        accepted_inputs: Vec<AcceptedInputEvidence>,
        accepted_outputs: Vec<AcceptedOutputEvidence>,
    ) -> Result<Self> {
        Self::verify_at_depth(
            old,
            new,
            source_tip,
            accepted_txids,
            accepted_inputs,
            accepted_outputs,
            20,
        )
    }

    fn verify_at_depth(
        old: AcceptingBlockEvidence,
        new: AcceptingBlockEvidence,
        source_tip: u64,
        accepted_txids: Vec<Vec<u8>>,
        accepted_inputs: Vec<AcceptedInputEvidence>,
        accepted_outputs: Vec<AcceptedOutputEvidence>,
        minimum_depth: u64,
    ) -> Result<Self> {
        validate_accepting_block_evidence(&old)?;
        validate_accepting_block_evidence(&new)?;
        anyhow::ensure!(
            old.hash != new.hash && !old.is_chain_block && new.is_chain_block,
            "replacement requires a removed block and a canonical replacement"
        );

        anyhow::ensure!(
            source_tip <= i64::MAX as u64,
            "source tip exceeds database range"
        );
        validate_acceptance_membership(&accepted_txids, &accepted_inputs, &accepted_outputs)?;
        let required_tip = new.blue_score.checked_add(minimum_depth)
            .context("acceptance maturity overflow")?;
        if source_tip < required_tip {
            return Err(super::AcceptanceWindowPending { source_tip, required_tip }.into());
        }
        // A distinct recovery path may inspect a valid settled change, but
        // malformed/stale membership must never be classified as that case.
        anyhow::ensure!(
            old.blue_score == new.blue_score
                && old.selected_parent == new.selected_parent
                && old.parents == new.parents
                && old.accepted_id_merkle_root == new.accepted_id_merkle_root
                && old.utxo_commitment == new.utxo_commitment,
            NonEquivalentBlockEvidence
        );
        Ok(Self {
            old,
            new,
            source_tip,
            accepted_txids,
            accepted_inputs,
            accepted_outputs,
        })
    }

    fn audit_evidence(&self) -> serde_json::Value {
        let mut members = self.accepted_txids.clone();
        members.sort();
        serde_json::json!({
            "old": self.old, "new": self.new,
            "accepted_count": members.len(),
            "accepted_ids_digest": hex::encode(tn12_indexer_core::blake2b_256(&members.concat())),
            "input_count": self.accepted_inputs.len(),
            "input_digest": hex::encode(tn12_indexer_core::blake2b_256(&serde_json::to_vec(&self.accepted_inputs).expect("serializable input evidence"))),
            "output_count": self.accepted_outputs.len(),
            "output_digest": hex::encode(tn12_indexer_core::blake2b_256(&serde_json::to_vec(&self.accepted_outputs).expect("serializable output evidence"))),
        })
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct AcceptanceReconciliationStats {
    pub created_outputs: u64,
    pub spent_inputs: u64,
    pub actions: u64,
    pub covenants: u64,
    pub already_reconciled: bool,
}

impl PgPersister {
    pub(super) async fn check_conflicting_output_content(
        conn: &mut Transaction<'_, Postgres>,
        tx: &tn12_indexer_core::RestTransaction,
    ) -> Result<()> {
        let rows: Vec<_> = tx.outputs.iter().map(|output| serde_json::json!({
            "vout": output.index, "amount": output.amount, "script": output.script_public_key,
        })).collect();
        let conflicting: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM jsonb_to_recordset($2::jsonb) o(vout bigint, amount numeric, script text)
                JOIN covenant_utxos u ON u.txid=decode($1,'hex') AND u.vout=o.vout
                WHERE u.amount_sompi IS DISTINCT FROM o.amount OR u.script_pubkey IS DISTINCT FROM decode(o.script,'hex'))"#,
        ).bind(&tx.transaction_id).bind(serde_json::json!(rows)).fetch_one(&mut **conn).await?;
        if conflicting {
            return Err(AcceptanceEvidenceConflict.into());
        }
        Ok(())
    }

    pub(super) async fn retire_removed_acceptance_replacements(
        conn: &mut Transaction<'_, Postgres>,
        removed: &[Vec<u8>],
    ) -> Result<()> {
        // Reverting a replacement target invalidates its proof and any older
        // replacement chain. Reverting only an old hash leaves its guard intact.
        let aliases: Vec<Vec<u8>> = sqlx::query_scalar(
            r#"
            WITH RECURSIVE ancestors(old_hash) AS (
                SELECT r.old_hash FROM canonical_block_replacements r WHERE r.new_hash = ANY($1::bytea[])
                    AND NOT EXISTS (SELECT 1 FROM canonical_block_replacements later WHERE later.old_hash = r.new_hash)
                UNION
                SELECT r.old_hash FROM canonical_block_replacements r JOIN ancestors a ON r.new_hash = a.old_hash
            ) SELECT old_hash FROM ancestors LIMIT 4097
            "#,
        ).bind(removed).fetch_all(&mut **conn).await?;
        anyhow::ensure!(
            aliases.len() <= 4_096,
            "removed acceptance replacement chain exceeds bound"
        );
        if aliases.is_empty() {
            return Ok(());
        }
        let has_refs: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos WHERE created_block = ANY($1::bytea[]))
                OR EXISTS(SELECT 1 FROM covenant_utxos WHERE spent_block = ANY($1::bytea[]))
                OR EXISTS(SELECT 1 FROM covenant_actions WHERE block_hash = ANY($1::bytea[]))
                OR EXISTS(SELECT 1 FROM covenants WHERE genesis_block = ANY($1::bytea[]))"#,
        )
        .bind(&aliases)
        .fetch_one(&mut **conn)
        .await?;
        anyhow::ensure!(
            !has_refs,
            "removed acceptance replacement has unexpected old references"
        );
        Self::record_rest_removals(conn, &aliases).await?;
        sqlx::query("DELETE FROM blocks WHERE hash = ANY($1::bytea[]) AND is_chain_block = FALSE")
            .bind(&aliases)
            .execute(&mut **conn)
            .await?;
        sqlx::query("DELETE FROM canonical_block_replacements WHERE old_hash = ANY($1::bytea[])")
            .bind(&aliases)
            .execute(&mut **conn)
            .await?;
        Ok(())
    }

    pub(super) async fn check_transaction_acceptance(
        conn: &mut Transaction<'_, Postgres>,
        txid: &[u8],
        incoming_hash: &[u8],
    ) -> Result<()> {
        Self::check_transactions_acceptance(conn, &[txid.to_vec()], &[incoming_hash.to_vec()]).await
    }

    pub(super) async fn check_transactions_acceptance(
        conn: &mut Transaction<'_, Postgres>,
        txids: &[Vec<u8>],
        incoming_hashes: &[Vec<u8>],
    ) -> Result<()> {
        anyhow::ensure!(
            txids.len() == incoming_hashes.len(),
            "transaction acceptance arrays differ in length"
        );
        Self::check_historical_acceptance_map_guards(conn, txids, incoming_hashes).await?;
        // All branches use transaction identity indexes. Do not scan spent_by_txid:
        // input acceptance is checked by outpoint in the serial/bulk input lookup.
        let conflicting: Option<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> = sqlx::query_as(
            r#"
            SELECT w.txid, w.incoming_hash, e.hashes
            FROM unnest($1::bytea[], $2::bytea[]) w(txid, incoming_hash)
            CROSS JOIN LATERAL (SELECT ARRAY(
            WITH RECURSIVE replacements(hash, depth) AS (
                SELECT new_hash, 1 FROM canonical_block_replacements WHERE old_hash = w.incoming_hash
                UNION ALL
                SELECT r.new_hash, p.depth + 1 FROM canonical_block_replacements r
                JOIN replacements p ON r.old_hash = p.hash WHERE p.depth < 32
            )
            SELECT DISTINCT block_hash FROM (
                (SELECT hash AS block_hash FROM replacements ORDER BY depth DESC LIMIT 1)
                UNION ALL
                SELECT created_block AS block_hash FROM covenant_utxos WHERE txid = w.txid
                UNION ALL
                SELECT block_hash FROM covenant_actions WHERE txid = w.txid
                UNION ALL
                SELECT genesis_block AS block_hash FROM covenants WHERE genesis_txid = w.txid
            ) evidence WHERE block_hash <> w.incoming_hash ORDER BY block_hash LIMIT 2
            ) AS hashes) e WHERE cardinality(e.hashes) > 0 ORDER BY w.txid LIMIT 1
            "#,
        )
        .bind(txids)
        .bind(incoming_hashes)
        .fetch_optional(&mut **conn)
        .await
        .context("check persisted transaction acceptance")?;
        if let Some((txid, incoming_hash, old)) = conflicting {
            anyhow::ensure!(
                old.len() == 1,
                "transaction has multiple conflicting accepting blocks"
            );
            return Err(AcceptanceConflict::new(&txid, &old[0], &incoming_hash).into());
        }
        Ok(())
    }

    /// Reassociate accepting-block references and times; later spends and decoded state survive.
    pub async fn reconcile_accepting_block(
        &self,
        proof: &CanonicalBlockReplacement,
    ) -> Result<AcceptanceReconciliationStats> {
        self.reconcile_accepting_block_inner(proof, true).await
    }

    pub async fn preview_accepting_block_reconciliation(
        &self,
        proof: &CanonicalBlockReplacement,
    ) -> Result<AcceptanceReconciliationStats> {
        self.reconcile_accepting_block_inner(proof, false).await
    }

    async fn reconcile_accepting_block_inner(
        &self,
        proof: &CanonicalBlockReplacement,
        apply: bool,
    ) -> Result<AcceptanceReconciliationStats> {
        self.require_rest_guard_hashes([proof.new.hash.as_slice()])?;
        const MAX_REFERENCES: i64 = 8_192;
        let mut conn = self
            .pool
            .begin()
            .await
            .context("begin acceptance reconciliation")?;
        Self::set_persist_query_limits(&mut conn).await?;
        self.acquire_persist_writer_lock(&mut conn).await?;
        let old = &proof.old.hash;
        let new = &proof.new.hash;
        Self::check_historical_acceptance_map_guards(
            &mut conn,
            &proof.accepted_txids,
            &[old.clone(), new.clone()],
        )
        .await?;
        let existing: Option<(Vec<u8>, serde_json::Value)> = sqlx::query_as(
            "SELECT new_hash, evidence FROM canonical_block_replacements WHERE old_hash = $1",
        )
        .bind(old)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some((target, stored_evidence)) = &existing {
            anyhow::ensure!(
                target == new && stored_evidence == &proof.audit_evidence(),
                "accepting block has different recorded replacement evidence"
            );
        }
        let replacement_is_removed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM canonical_block_replacements WHERE old_hash = $1)",
        )
        .bind(new)
        .fetch_one(&mut *conn)
        .await?;
        anyhow::ensure!(
            !replacement_is_removed,
            "replacement block was itself removed"
        );
        let blocks: Vec<(Vec<u8>, i64, i64, bool)> = sqlx::query_as(
            "SELECT hash, blue_score, timestamp_ms, is_chain_block FROM blocks \
             WHERE hash = ANY($1::bytea[]) ORDER BY hash FOR UPDATE",
        )
        .bind(vec![old.clone(), new.clone()])
        .fetch_all(&mut *conn)
        .await?;
        anyhow::ensure!(
            existing.is_some() || blocks.iter().any(|row| &row.0 == old),
            "removed accepting block is not indexed"
        );
        anyhow::ensure!(
            existing.is_none() || blocks.iter().any(|row| &row.0 == new && row.3),
            "recorded canonical replacement block is missing"
        );
        anyhow::ensure!(
            blocks.iter().all(|row| {
                let evidence = if &row.0 == old {
                    &proof.old
                } else {
                    &proof.new
                };
                row.1 == evidence.blue_score as i64
                    && row.2 == evidence.timestamp as i64
                    && (&row.0 != new || row.3)
            }),
            "stored accepting block metadata conflicts with verified evidence"
        );

        // Bounded, indexed reads by each FK. Every event, including spends of
        // older outputs, must belong to the replacement's accepted transaction set.
        let pair = vec![old.clone(), new.clone()];
        let references: Vec<(String, Option<Vec<u8>>, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT kind, txid, block_hash FROM (
                (SELECT 'created'::text AS kind, txid, created_block AS block_hash FROM covenant_utxos WHERE created_block = ANY($1::bytea[]) LIMIT 8193)
                UNION ALL
                (SELECT 'spent'::text AS kind, spent_by_txid AS txid, spent_block AS block_hash FROM covenant_utxos WHERE spent_block = ANY($1::bytea[]) LIMIT 8193)
                UNION ALL
                (SELECT 'action'::text AS kind, txid, block_hash FROM covenant_actions WHERE block_hash = ANY($1::bytea[]) LIMIT 8193)
                UNION ALL
                (SELECT 'genesis'::text AS kind, genesis_txid AS txid, genesis_block AS block_hash FROM covenants WHERE genesis_block = ANY($1::bytea[]) LIMIT 8193)
            ) refs LIMIT 8193
            "#,
        ).bind(&pair).fetch_all(&mut *conn).await?;
        anyhow::ensure!(
            references.len() as i64 <= MAX_REFERENCES,
            "accepting block repair exceeds reference bound"
        );
        let accepted: HashSet<_> = proof.accepted_txids.iter().collect();
        anyhow::ensure!(
            references
                .iter()
                .all(|(_, txid, _)| txid.as_ref().is_some_and(|id| accepted.contains(id))),
            "stored accepting block references are outside canonical acceptance membership"
        );
        let involved: Vec<Vec<u8>> = references
            .iter()
            .filter_map(|row| row.1.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let unrelated: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos WHERE txid = ANY($1::bytea[]) AND NOT created_block = ANY($2::bytea[]))
                OR EXISTS(SELECT 1 FROM covenant_actions WHERE txid = ANY($1::bytea[]) AND NOT block_hash = ANY($2::bytea[]))
                OR EXISTS(SELECT 1 FROM covenants WHERE genesis_txid = ANY($1::bytea[]) AND NOT genesis_block = ANY($2::bytea[]))"#,
        ).bind(&involved).bind(&pair).fetch_one(&mut *conn).await?;
        anyhow::ensure!(
            !unrelated,
            "canonical acceptance event has references to a third block"
        );
        let wanted: HashSet<_> = involved.iter().collect();
        let inputs: Vec<_> = proof.accepted_inputs.iter().filter(|input| wanted.contains(&input.transaction_id))
            .map(|input| serde_json::json!({"txid":hex::encode(&input.transaction_id),
                "prev_txid":hex::encode(&input.previous_txid),"vout":input.previous_vout,
                "amount":input.previous_amount,"script":input.previous_script.as_ref().map(hex::encode)})).collect();
        let input_evidence = serde_json::json!(inputs);
        // Check every persisted spend in the pair, including rows that an
        // incomplete source input list would otherwise omit from a source-led join.
        let missing_spend_evidence: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos u
                LEFT JOIN jsonb_to_recordset($1::jsonb) i(txid text, prev_txid text, vout int, amount numeric, script text)
                    ON u.txid=decode(i.prev_txid,'hex') AND u.vout=i.vout AND u.spent_by_txid=decode(i.txid,'hex')
                WHERE u.spent_block = ANY($2::bytea[]) AND (i.txid IS NULL OR u.status <> 'spent'
                    OR u.amount_sompi IS DISTINCT FROM i.amount OR u.script_pubkey IS DISTINCT FROM decode(i.script,'hex')))"#,
        ).bind(&input_evidence).bind(&pair).fetch_one(&mut *conn).await?;
        anyhow::ensure!(
            !missing_spend_evidence,
            "stored spend is absent from canonical input evidence"
        );
        // Every indexed covenant spend has a spend action. Use its transaction
        // index and the referenced UTXO PK; spent_by_txid has no global index.
        let conflicting_spend_action: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM covenant_actions a
                LEFT JOIN jsonb_to_recordset($1::jsonb) i(txid text, prev_txid text, vout int, amount numeric, script text)
                    ON a.txid=decode(i.txid,'hex')
                    AND lower(a.inputs#>>'{previousOutpoint,hash}')=i.prev_txid
                    AND a.inputs#>>'{previousOutpoint,index}'=i.vout::text
                LEFT JOIN covenant_utxos u ON u.txid=decode(i.prev_txid,'hex') AND u.vout=i.vout
                WHERE a.txid = ANY($2::bytea[]) AND a.action='spend' AND (i.txid IS NULL OR u.txid IS NULL
                    OR u.status <> 'spent' OR u.spent_by_txid IS DISTINCT FROM a.txid
                    OR u.spent_block IS NULL OR NOT u.spent_block = ANY($3::bytea[])
                    OR u.amount_sompi IS DISTINCT FROM i.amount OR u.script_pubkey IS DISTINCT FROM decode(i.script,'hex')))"#,
        ).bind(&input_evidence).bind(&involved).bind(&pair).fetch_one(&mut *conn).await?;
        anyhow::ensure!(
            !conflicting_spend_action,
            "stored spend action conflicts with canonical input evidence"
        );
        // Live ingestion can precede parent history. A matching, wholly unspent
        // input is incomplete replay, not a contradictory spend. Leave it active
        // here; the scanner retries the batch through normal spend persistence.
        // The inverse action check above still requires every stored spend action
        // to have a matching spent UTXO. Reject hybrid states and other spenders.
        let conflicting_spend: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) i(txid text, prev_txid text, vout int, amount numeric, script text)
                JOIN covenant_utxos u ON u.txid=decode(i.prev_txid,'hex') AND u.vout=i.vout
                WHERE u.amount_sompi IS DISTINCT FROM i.amount OR u.script_pubkey IS DISTINCT FROM decode(i.script,'hex')
                    OR ((u.status = 'active' AND u.spent_by_txid IS NULL AND u.spent_block IS NULL)
                        OR (u.status = 'spent' AND u.spent_by_txid = decode(i.txid,'hex')
                            AND u.spent_block = ANY($2::bytea[]))) IS NOT TRUE)"#,
        ).bind(&input_evidence).bind(&pair).fetch_one(&mut *conn).await?;
        anyhow::ensure!(
            !conflicting_spend,
            "canonical input has conflicting spend evidence"
        );
        let outputs: Vec<_> = proof
            .accepted_outputs
            .iter()
            .filter(|output| wanted.contains(&output.transaction_id))
            .map(|output| {
                serde_json::json!({"txid":hex::encode(&output.transaction_id),
                "vout":output.vout,"amount":output.amount,"script":hex::encode(&output.script)})
            })
            .collect();
        let conflicting_output: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos u
                LEFT JOIN jsonb_to_recordset($1::jsonb) o(txid text, vout int, amount numeric, script text)
                    ON u.txid=decode(o.txid,'hex') AND u.vout=o.vout
                WHERE u.created_block = ANY($2::bytea[]) AND (o.txid IS NULL
                    OR u.amount_sompi IS DISTINCT FROM o.amount OR u.script_pubkey IS DISTINCT FROM decode(o.script,'hex')))"#,
        ).bind(serde_json::json!(outputs)).bind(&pair).fetch_one(&mut *conn).await?;
        anyhow::ensure!(
            !conflicting_output,
            "canonical output has conflicting content evidence"
        );
        if existing.is_some() {
            anyhow::ensure!(
                references.iter().all(|row| &row.2 == new),
                "recorded accepting block replacement has stale references"
            );
            anyhow::ensure!(
                blocks.iter().all(|row| &row.0 != old || !row.3),
                "recorded removed accepting block is marked canonical"
            );
            conn.rollback().await?;
            return Ok(AcceptanceReconciliationStats {
                already_reconciled: true,
                ..Default::default()
            });
        }
        if !apply {
            let count = |kind: &str| {
                references
                    .iter()
                    .filter(|row| row.0 == kind && &row.2 == old)
                    .count() as u64
            };
            let stats = AcceptanceReconciliationStats {
                created_outputs: count("created"),
                spent_inputs: count("spent"),
                actions: count("action"),
                covenants: count("genesis"),
                already_reconciled: false,
            };
            conn.rollback().await?;
            return Ok(stats);
        }
        sqlx::query(
            "INSERT INTO blocks (hash, blue_score, daa_score, parent_hashes, timestamp_ms, is_chain_block, indexed_at_ms) \
             VALUES ($1, $2, 0, ARRAY[]::bytea[], $3, TRUE, EXTRACT(EPOCH FROM NOW())::bigint * 1000) \
             ON CONFLICT (hash) DO NOTHING",
        ).bind(new).bind(proof.new.blue_score as i64).bind(proof.new.timestamp as i64).execute(&mut *conn).await?;
        let mut stats = AcceptanceReconciliationStats::default();
        stats.created_outputs =
            sqlx::query("UPDATE covenant_utxos SET created_block = $2 WHERE created_block = $1")
                .bind(old)
                .bind(new)
                .execute(&mut *conn)
                .await?
                .rows_affected();
        stats.spent_inputs =
            sqlx::query("UPDATE covenant_utxos SET spent_block = $2 WHERE spent_block = $1")
                .bind(old)
                .bind(new)
                .execute(&mut *conn)
                .await?
                .rows_affected();
        stats.actions = sqlx::query(
            "UPDATE covenant_actions SET block_hash = $2, block_time_ms = $3 WHERE block_hash = $1",
        )
        .bind(old)
        .bind(new)
        .bind(proof.new.timestamp as i64)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        stats.covenants = sqlx::query(
            "UPDATE covenants SET genesis_block = $2, created_at_ms = $3 WHERE genesis_block = $1",
        )
        .bind(old)
        .bind(new)
        .bind(proof.new.timestamp as i64)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        for (kind, count) in [
            ("created", stats.created_outputs),
            ("spent", stats.spent_inputs),
            ("action", stats.actions),
            ("genesis", stats.covenants),
        ] {
            anyhow::ensure!(
                count
                    == references
                        .iter()
                        .filter(|row| row.0 == kind && &row.2 == old)
                        .count() as u64,
                "accepting block reference count changed during reconciliation"
            );
        }
        Self::record_rest_removals(&mut conn, std::slice::from_ref(old)).await?;
        sqlx::query("UPDATE blocks SET is_chain_block = FALSE WHERE hash = $1")
            .bind(old)
            .execute(&mut *conn)
            .await?;
        let stale: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(SELECT 1 FROM covenant_utxos WHERE created_block = $1)
                OR EXISTS(SELECT 1 FROM covenant_utxos WHERE spent_block = $1)
                OR EXISTS(SELECT 1 FROM covenant_actions WHERE block_hash = $1)
                OR EXISTS(SELECT 1 FROM covenants WHERE genesis_block = $1)"#,
        )
        .bind(old)
        .fetch_one(&mut *conn)
        .await?;
        anyhow::ensure!(
            !stale,
            "old accepting block references remain after reconciliation"
        );
        if proof.new.timestamp < proof.old.timestamp {
            // The normal covenant trigger only increases this maximum. Repair
            // affected maxima once after all canonical timestamps have moved.
            sqlx::query(r#"
                UPDATE covenant_template_summaries summary
                SET latest_created_at_ms = (
                    SELECT c.created_at_ms FROM covenants c
                    WHERE COALESCE(c.template_name, c.claimed_template, 'Unknown') = summary.template
                    ORDER BY c.created_at_ms DESC, c.covenant_id DESC LIMIT 1
                ), updated_at_ms = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
                WHERE summary.latest_created_at_ms = $2
                  AND summary.template IN (
                    SELECT COALESCE(c.template_name, c.claimed_template, 'Unknown')
                    FROM covenants c WHERE c.genesis_block = $1
                  )
            "#).bind(new).bind(proof.old.timestamp as i64).execute(&mut *conn).await?;
        }
        if proof.old.timestamp != proof.new.timestamp {
            crate::repo::mark_kcc20_projection_dirty_txids_tx(
                &mut conn,
                "acceptance_reconciliation",
                &involved,
            )
            .await
            .context("mark projections dirty after acceptance timestamp correction")?;
        }
        sqlx::query("INSERT INTO canonical_block_replacements (old_hash, new_hash, evidence, source_tip) VALUES ($1, $2, $3, $4)")
            .bind(old).bind(new).bind(proof.audit_evidence()).bind(i64::try_from(proof.source_tip)?).execute(&mut *conn).await?;
        conn.commit()
            .await
            .context("commit canonical acceptance reconciliation")?;
        Ok(stats)
    }
}

#[cfg(test)]
mod historical_map_error_tests {
    use super::*;

    fn blocks() -> (AcceptingBlockEvidence, AcceptingBlockEvidence) {
        let old = AcceptingBlockEvidence {
            hash: vec![1; 32],
            is_chain_block: false,
            blue_score: 100,
            timestamp: 1000,
            selected_parent: vec![3; 32],
            parents: vec![vec![vec![3; 32]]],
            accepted_id_merkle_root: vec![4; 32],
            utxo_commitment: vec![5; 32],
        };
        let mut new = old.clone();
        new.hash = vec![2; 32];
        new.is_chain_block = true;
        new.blue_score = 101;
        (old, new)
    }

    #[test]
    fn historical_map_error_is_typed_only_after_common_evidence_validation() {
        let (old, new) = blocks();
        let error =
            CanonicalBlockReplacement::verify(old, new, 2000, vec![vec![9; 32]], vec![], vec![])
                .unwrap_err();
        assert!(
            error.is::<NonEquivalentBlockEvidence>(),
            "valid non-equivalent source must have a distinct classification: {error:#}"
        );
    }

    #[test]
    fn historical_map_error_does_not_classify_unsettled_or_bad_membership() {
        for (tip, members) in [(102, vec![vec![9; 32]]), (2000, vec![])] {
            let (old, new) = blocks();
            let error = CanonicalBlockReplacement::verify(old, new, tip, members, vec![], vec![])
                .unwrap_err();
            assert!(!error.is::<NonEquivalentBlockEvidence>());
        }
    }

    #[test]
    fn historical_map_error_does_not_classify_noncanonical_or_malformed_blocks() {
        for malformed in [false, true] {
            let (old, mut new) = blocks();
            if malformed {
                new.hash.clear();
            } else {
                new.is_chain_block = false;
            }
            let error = CanonicalBlockReplacement::verify(
                old,
                new,
                2000,
                vec![vec![9; 32]],
                vec![],
                vec![],
            )
            .unwrap_err();
            assert!(!error.is::<NonEquivalentBlockEvidence>());
        }
    }
}
