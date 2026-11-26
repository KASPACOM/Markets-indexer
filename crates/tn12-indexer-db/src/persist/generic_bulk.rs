//! Bounded set-based persistence for version-0 P2SH transactions whose spends
//! and outputs have only the generic behavior of the serial writer. An opt-in
//! path also handles unmatched native genesis with the scalar identity rules.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sqlx::Acquire;
use tn12_indexer_core::{is_p2sh_script_pubkey, p2sh_script_hash, RestTransaction};
use tn12_indexer_decoder::registry::DecoderRegistry;

use super::{extract_last_push, PersistStats, PgPersister};

#[path = "generic_probe.rs"]
mod generic_probe;
pub use generic_probe::{GenericProbeAttempt, GenericProbeOutcome, ProbeReason};

// Preserve the earliest matching output action during replay. Evaluate performance
// across lookup and insertion together: insertion needs the same index pages.
const EXISTING_OUTPUT_ACTIONS_SQL: &str = r#"
    SELECT s.tx_ord, a.action
    FROM jsonb_to_recordset($1::jsonb)
         AS s(tx_ord INT, txid TEXT, covenant_id TEXT, vout INT)
    JOIN LATERAL (
        SELECT action FROM covenant_actions
        WHERE covenant_id = decode(s.covenant_id, 'hex')
          AND txid = decode(s.txid, 'hex')
          AND action IN ('deploy', 'continuation')
          AND outputs->>'vout' = s.vout::TEXT
        ORDER BY id ASC LIMIT 1
    ) a ON TRUE
"#;

const BUDGET_STATEMENT_TIMEOUT_SQL: &str = "SELECT set_config('statement_timeout', LEAST(NULLIF(setting::bigint, 0), 75)::text || 'ms', true), (setting::bigint = 0 OR setting::bigint >= 75) FROM pg_settings WHERE name='statement_timeout'";

fn is_budget_statement_timeout(error: &anyhow::Error, cap_applied: bool) -> bool {
    cap_applied
        && error.chain().any(|cause| {
            cause
                .downcast_ref::<sqlx::Error>()
                .and_then(sqlx::Error::as_database_error)
                .is_some_and(|db| {
                    db.code().as_deref() == Some("57014")
                        && db.message() == "canceling statement due to statement timeout"
                })
        })
}

pub(super) const DEFAULT_TXS: usize = 32;
pub(super) const MAX_TXS: usize = 1024;
const MAX_INPUTS: usize = 16;
const MAX_CONSOLIDATION_INPUTS: usize = 128;
const MAX_OUTPUTS: usize = 64;
const MAX_TX_BYTES: usize = 64 * 1024;
const MAX_BATCH_ACTIONS: usize = 512;
const MAX_SIMPLE_BATCH_ACTIONS: usize = 2048;

pub(super) struct GenericBatchStats {
    pub stats: PersistStats,
    pub lock_wait_us: u128,
    pub lock_held_us: u128,
}

// This internal marker is never exposed as a retryable error until rollback
// has been acknowledged by PostgreSQL.
#[derive(Debug, thiserror::Error)]
#[error("generic writer body deadline elapsed")]
struct WriterBodyDeadline;

#[derive(Debug, thiserror::Error)]
#[error("generic writer rollback acknowledged")]
struct GenericRollbackAcknowledged;

// A cancelled owner cannot return an uncertain transaction to the pool.
// Only an acknowledged rollback or commit makes a writer lease reusable.
struct GenericConnection {
    connection: sqlx::pool::PoolConnection<sqlx::Postgres>,
    reusable: bool,
}
impl Drop for GenericConnection {
    fn drop(&mut self) {
        if !self.reusable {
            self.connection.close_on_drop();
        }
    }
}

// Bound serialization before cloning or staging SQL JSON, including extension fields.
struct SizeLimit(usize);
impl std::io::Write for SizeLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.0 {
            return Err(std::io::Error::other(
                "generic transaction exceeds size limit",
            ));
        }
        self.0 -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct GenericInput {
    prev_txid: Vec<u8>,
    vout: i32,
    is_p2sh: Option<bool>,
    prev_script: Option<Vec<u8>>,
    prev_amount: Option<i64>,
    source_hash: String,
}

struct GenericTx {
    tx: RestTransaction,
    txid: Vec<u8>,
    block_hash: Vec<u8>,
    block_time: i64,
    blue_score: i64,
    output: Option<GenericOutput>,
    inputs: Vec<GenericInput>,
}

struct GenericOutput {
    covenant_id: Vec<u8>,
    script_hash: Vec<u8>,
    script_pubkey: Vec<u8>,
    vout: i32,
    amount: i64,
    address: String,
}

fn hash32(hex_text: &str) -> Option<Vec<u8>> {
    let bytes = hex::decode(hex_text).ok()?;
    (bytes.len() == 32).then_some(bytes)
}

fn prepare(tx: &RestTransaction, decoders: &DecoderRegistry) -> Option<GenericTx> {
    prepare_with_evidence_policy(tx, decoders, true)
}

fn prepare_with_evidence_policy(
    tx: &RestTransaction,
    decoders: &DecoderRegistry,
    require_complete_prevouts: bool,
) -> Option<GenericTx> {
    if !tx.is_accepted || tx.version != 0 || tx.payload.as_deref().is_some_and(|p| !p.is_empty()) {
        return None;
    }
    if tx.inputs.len() > MAX_CONSOLIDATION_INPUTS
        || tx.outputs.len() > MAX_OUTPUTS
        || serde_json::to_writer(SizeLimit(MAX_TX_BYTES), tx).is_err()
    {
        return None;
    }
    let tx = tx.with_normalized_missing_output_indexes();
    let txid = hash32(&tx.transaction_id)?;
    let block_hash = hash32(tx.accepting_block_hash.as_deref()?)?;
    let blue_score = i64::try_from(tx.accepting_block_blue_score?).ok()?;
    let block_time = i64::try_from(tx.accepting_block_time.unwrap_or(tx.block_time)).ok()?;
    let mut p2sh_output = None;
    for output in &tx.outputs {
        let script = hex::decode(&output.script_public_key).ok()?;
        if output.canonical_covenant_id().is_some() || output.covenant_authorizing_input().is_some()
        {
            return None;
        }
        if !is_p2sh_script_pubkey(&script) {
            continue;
        }
        if p2sh_output.is_some() {
            return None;
        }
        let script_hash = p2sh_script_hash(&script)?.to_vec();
        p2sh_output = Some((output.clone(), script, script_hash));
    }
    if p2sh_output.is_some() && tx.inputs.len() > MAX_INPUTS {
        return None;
    }
    let output = match p2sh_output {
        Some((output, script_pubkey, script_hash)) => Some(GenericOutput {
            covenant_id: script_hash.clone(),
            script_hash,
            script_pubkey,
            vout: i32::try_from(output.index).ok()?,
            amount: i64::try_from(output.amount).ok()?,
            address: output.script_public_key_address.unwrap_or_default(),
        }),
        None => None,
    };
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    if tx.inputs.is_empty() {
        return None;
    }
    for input in &tx.inputs {
        let prev_txid = hash32(&input.previous_outpoint_hash)?;
        let vout = input.previous_outpoint_index.parse::<i32>().ok()?;
        let prev_script = input
            .previous_outpoint_script
            .as_deref()
            .map(hex::decode)
            .transpose()
            .ok()?;
        let is_p2sh = prev_script.as_deref().map(is_p2sh_script_pubkey);
        let prev_amount = input
            .previous_outpoint_amount
            .map(i64::try_from)
            .transpose()
            .ok()?;
        if require_complete_prevouts
            && (prev_script.is_none() || (is_p2sh == Some(true) && prev_amount.is_none()))
        {
            return None;
        }
        let signature_script = hex::decode(&input.signature_script).ok()?;
        if let Some(reveal) = extract_last_push(&signature_script) {
            if decoders.find_for_reveal(&reveal).is_some()
                || tn12_indexer_decoder::detect_inscription_from_reveal(&reveal).is_some() {
                return None;
            }
        }
        inputs.push(GenericInput {
            prev_txid,
            vout,
            is_p2sh,
            prev_script,
            prev_amount,
            source_hash: input.previous_outpoint_hash.clone(),
        });
    }
    if output.is_none() && !inputs.iter().any(|input| input.is_p2sh == Some(true)) {
        return None;
    }
    Some(GenericTx {
        tx,
        txid,
        block_hash,
        output,
        block_time,
        blue_score,
        inputs,
    })
}

// Preserve the scalar native genesis identity. Eligibility is deliberately
// narrow; database input/rekey checks below can still require scalar fallback.
fn prepare_for_writer(tx: &RestTransaction, decoders: &DecoderRegistry, strict: bool, native: bool) -> Option<GenericTx> {
    if super::deferred_decode::unsupported_reason(tx,decoders).is_some() { return None; }

    if let Some(prepared) = prepare_with_evidence_policy(tx, decoders, strict) {
        return Some(prepared);
    }
    if !native || tx.version != 1 || serde_json::to_writer(SizeLimit(MAX_TX_BYTES), tx).is_err()
        || tx.payload.as_deref().and_then(super::claim::parse_payload_envelope).is_some()
        || tx.payload.as_deref().and_then(super::parse_api_payment_channel_open_payload).is_some() {
        return None;
    }
    let mut legacy = tx.clone();
    legacy.version = 0;
    legacy.payload = None;
    let mut prepared = prepare_with_evidence_policy(&legacy, decoders, strict)?;
    if prepared.inputs.iter().any(|i| i.is_p2sh == Some(true)) || tx.inputs.iter().any(|i| tx.needs_input_identity(i)) { return None; }
    let output = prepared.output.as_mut()?;
    let normalized = tx.with_normalized_missing_output_indexes();
    let source_output = normalized.outputs.iter().find(|o| o.index == output.vout as u64)?;
    let script_hash: [u8;32] = output.script_hash.as_slice().try_into().ok()?;
    output.covenant_id = super::covenant_identity_for_output(&normalized, source_output, &script_hash, None, false);
    // Native identity derivation failure must never silently use the legacy ID.
    if output.covenant_id == output.script_hash { return None; }
    prepared.tx = normalized;
    Some(prepared)
}

pub(super) fn is_writer_candidate(tx: &RestTransaction, decoders: &DecoderRegistry, native: bool) -> bool {
    prepare_for_writer(tx, decoders, false, native).is_some()
}

#[cfg(test)]
pub(super) fn is_candidate(tx: &RestTransaction, decoders: &DecoderRegistry) -> bool {
    prepare_with_evidence_policy(tx, decoders, false).is_some()
}

// One consolidation already contains enough independent input writes to
// benefit from SQL batching. Ordinary single-input transactions keep the
// scalar path when they cannot share a batch with another transaction.
pub(super) fn minimum_batch_len(tx: &RestTransaction) -> usize {
    if tx.inputs.len() > MAX_INPUTS {
        1
    } else {
        2
    }
}

pub(super) fn independent_prefix_len(txs: &[RestTransaction], decoders: &DecoderRegistry) -> usize {
    writer_prefix_len(txs, decoders, false)
}

pub(super) fn writer_prefix_len(txs: &[RestTransaction], decoders: &DecoderRegistry, native: bool) -> usize {
    let mut txids = HashSet::new();
    let mut previous_txids = HashSet::new();
    let mut outpoints = HashSet::new();
    let mut blocks = HashMap::new();
    let mut staged_actions = 0;
    let mut has_multi_input = false;
    for (index, tx) in txs.iter().enumerate() {
        let Some(prepared) = prepare_for_writer(tx, decoders, false, native) else {
            return index;
        };
        let actions = prepared.inputs.len() + usize::from(prepared.output.is_some());
        let multi_input = has_multi_input || prepared.inputs.len() > 1;
        let action_limit = if multi_input {
            MAX_BATCH_ACTIONS
        } else {
            MAX_SIMPLE_BATCH_ACTIONS
        };
        if staged_actions + actions > action_limit {
            return index;
        }
        staged_actions += actions;
        has_multi_input = multi_input;
        if txids.contains(&prepared.txid) || previous_txids.contains(&prepared.txid) {
            return index;
        }
        let block_info = (prepared.blue_score, prepared.block_time);
        if blocks
            .get(&prepared.block_hash)
            .is_some_and(|old| *old != block_info)
        {
            return index;
        }
        let mut local_outpoints = HashSet::new();
        for input in &prepared.inputs {
            let outpoint = (input.prev_txid.clone(), input.vout);
            if txids.contains(&input.prev_txid)
                || input.prev_txid == prepared.txid
                || outpoints.contains(&outpoint)
                || !local_outpoints.insert(outpoint)
            {
                return index;
            }
        }
        txids.insert(prepared.txid);
        blocks.insert(prepared.block_hash, block_info);
        previous_txids.extend(prepared.inputs.into_iter().map(|input| input.prev_txid));
        outpoints.extend(local_outpoints);
    }
    txs.len()
}

impl PgPersister {
    /// `None` means a source or database dependency needs the serial writer.
    /// Both eligibility and writes run under the same advisory writer lock.
    pub(super) async fn try_persist_generic_batch(
        &self,
        txs: &[RestTransaction],
    ) -> Result<Option<GenericBatchStats>> {
        self.try_persist_generic_batch_inner(txs, self.generic_writer_budget)
            .await
    }

    // Optional historical budget. Only the TIP runtime constructor reads its
    // opt-in flag; ordinary writers keep the budget disabled.
    async fn try_persist_generic_batch_inner(
        &self,
        txs: &[RestTransaction],
        budget_enabled: bool,
    ) -> Result<Option<GenericBatchStats>> {
        self.try_persist_generic_batch_with_fence(txs, budget_enabled, false)
            .await
    }

    // Only the finite probe requires a newly written batch. Keep ordinary
    // historical/live replay idempotent and avoid extra queries for those callers.
    async fn try_persist_generic_batch_with_fence(
        &self,
        txs: &[RestTransaction],
        budget_enabled: bool,
        require_unwritten: bool,
    ) -> Result<Option<GenericBatchStats>> {
        if txs.len() > MAX_TXS {
            return Ok(None);
        }
        let Some(prepared) = txs
            .iter()
            .map(|tx| prepare_for_writer(tx, &self.decoders, require_unwritten, self.native_genesis_bulk))
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(None);
        };
        // Enforce the work bound here as well as in prefix selection so a
        // future internal caller cannot bypass it before staging SQL JSON.
        let action_limit = if prepared.iter().any(|tx| tx.inputs.len() > 1) {
            MAX_BATCH_ACTIONS
        } else {
            MAX_SIMPLE_BATCH_ACTIONS
        };
        if prepared
            .iter()
            .map(|tx| tx.inputs.len() + usize::from(tx.output.is_some()))
            .sum::<usize>()
            > action_limit
        {
            return Ok(None);
        }
        let mut txids = HashSet::new();
        let mut input_outpoints = HashSet::new();
        let mut blocks = HashMap::new();
        for tx in &prepared {
            if !txids.insert(tx.txid.clone()) {
                return Ok(None);
            }
            if let Some(old) = blocks.insert(tx.block_hash.clone(), (tx.blue_score, tx.block_time))
            {
                if old != (tx.blue_score, tx.block_time) {
                    return Ok(None);
                }
            }
            for input in &tx.inputs {
                if !input_outpoints.insert((input.prev_txid.clone(), input.vout)) {
                    return Ok(None);
                }
            }
        }
        if prepared
            .iter()
            .flat_map(|tx| &tx.inputs)
            .any(|input| txids.contains(&input.prev_txid))
        {
            return Ok(None);
        }

        let input_rows = Value::Array(
            prepared
                .iter()
                .enumerate()
                .flat_map(|(tx_ord, tx)| {
                    tx.inputs.iter().enumerate().map(move |(input_ord, input)| {
                        json!({
                            "tx_ord": tx_ord, "input_ord": input_ord,
                            "prev_txid": hex::encode(&input.prev_txid), "vout": input.vout,
                        })
                    })
                })
                .collect(),
        );
        // Accepting blocks belong to every transaction, including spends without
        // a covenant output. Keep them independent of the output-only rows.
        let transaction_rows = Value::Array(
            prepared
                .iter()
                .enumerate()
                .map(|(tx_ord, tx)| {
                    json!({
                        "tx_ord": tx_ord, "txid": hex::encode(&tx.txid),
                        "block_hash": hex::encode(&tx.block_hash),
                        "blue_score": tx.blue_score, "block_time": tx.block_time,
                    })
                })
                .collect(),
        );
        let output_rows_by_tx = prepared.iter().enumerate().map(|(tx_ord, tx)| {
            tx.output.as_ref().map(|output| json!({
                "tx_ord": tx_ord,
                "txid": hex::encode(&tx.txid),
                "block_hash": hex::encode(&tx.block_hash),
                "blue_score": tx.blue_score, "block_time": tx.block_time,
                "covenant_id": hex::encode(&output.covenant_id),
                "script_hash": hex::encode(&output.script_hash),
                "native": tx.tx.version == 1,
                "vout": output.vout, "address": output.address,
                "amount": output.amount, "script_pubkey": hex::encode(&output.script_pubkey),
                "outputs": {
                    "vout": output.vout, "amountSompi": output.amount,
                    "address": output.address,
                    "scriptPubKeyHex": tx.tx.outputs.iter().find(|out| out.index == output.vout as u64)
                        .map(|out| out.script_public_key.as_str()).unwrap_or_default(),
                    "state": null,
                },
            }))
        }).collect::<Vec<_>>();
        let output_rows = Value::Array(output_rows_by_tx.iter().flatten().cloned().collect());

        let mut lease = GenericConnection {
            connection: self
                .pool
                .acquire()
                .await
                .context("acquire generic bulk connection")?,
            reusable: false,
        };
        let mut conn = lease
            .connection
            .begin()
            .await
            .context("begin generic bulk persist")?;
        Self::set_persist_query_limits(&mut conn).await?;
        let wait_started = std::time::Instant::now();
        self.acquire_persist_writer_lock(&mut conn).await?;
        let lock_wait_us = wait_started.elapsed().as_micros();
        let held_started = std::time::Instant::now();
        let mut budget_statement_cap_applied = false;
        let work = async {
            if budget_enabled {
                // pg_settings reports the normalized value in milliseconds. Zero
                // means unlimited. Keep stricter configured limits unchanged.
                let (_, cap_applied): (String, bool) = sqlx::query_as(BUDGET_STATEMENT_TIMEOUT_SQL)
                    .fetch_one(&mut *conn)
                    .await
                    .context("cap experimental generic statement timeout")?;
                budget_statement_cap_applied = cap_applied;
            }
            if super::deferred_decode::pending_dependency(&mut conn,txs,&[],None).await? {
                return Ok(None);
            }
            if require_unwritten {
                // This runs after acquiring the writer lock, in the write's
                // transaction and budget, including every post-rollback retry.
                // Use transaction identity indexes; never scan spent_by_txid.
                // Required input spend state is checked by outpoint below.
                let represented: bool = sqlx::query_scalar(
                    r#"
                    SELECT EXISTS (SELECT 1 FROM covenant_utxos WHERE txid=ANY($1::bytea[]))
                        OR EXISTS (SELECT 1 FROM covenant_actions WHERE txid=ANY($1::bytea[]))
                        OR EXISTS (SELECT 1 FROM covenants WHERE genesis_txid=ANY($1::bytea[]))
                    "#,
                )
                .bind(txids.iter().cloned().collect::<Vec<_>>())
                .fetch_one(&mut *conn)
                .await
                .context("check probe transaction freshness")?;
                if represented {
                    return Ok(None);
                }
            }
            sqlx::query("SELECT set_config('tn12.defer_covenant_summary_repair', 'on', TRUE)")
                .execute(&mut *conn)
                .await
                .context("defer generic bulk summary repair")?;

            let existing: Vec<(
                i32,
                i32,
                Vec<u8>,
                String,
                String,
                Option<Vec<u8>>,
                Vec<u8>,
                i64,
                Option<String>,
                Option<String>,
                String,
                Option<Vec<u8>>,
            )> = sqlx::query_as(
                r#"
                SELECT i.tx_ord, i.input_ord, u.covenant_id, u.address, u.status,
                       u.spent_by_txid, u.script_pubkey, u.amount_sompi,
                       c.template_name, c.claimed_template, c.classification_status, u.spent_block
                FROM jsonb_to_recordset($1::jsonb)
                     AS i(tx_ord INT, input_ord INT, prev_txid TEXT, vout INT)
                JOIN covenant_utxos u ON u.txid = decode(i.prev_txid, 'hex') AND u.vout = i.vout
                JOIN covenants c ON c.covenant_id = u.covenant_id
            "#,
            )
            .bind(&input_rows)
            .fetch_all(&mut *conn)
            .await
            .context("check generic bulk inputs")?;
            let mut found_inputs = HashMap::new();
            let mut classified = HashSet::new();
            for (
                tx_ord,
                input_ord,
                cid,
                address,
                status,
                spent_by,
                script,
                amount,
                template,
                claimed,
                classification,
                spent_block,
            ) in existing
            {
                if template.is_some() || claimed.is_some() || classification == "matched" {
                    return Ok(None);
                }
                let tx = &prepared[tx_ord as usize];
                // Native continuations require the scalar identity inference.
                if tx.tx.version == 1 { return Ok(None); }
                let input = &tx.inputs[input_ord as usize];
                // Missing metadata can be resolved by this immutable DB row.
                // Supplied metadata must still agree with it exactly.
                if input
                    .prev_script
                    .as_ref()
                    .is_some_and(|source| *source != script)
                    || input.prev_amount.is_some_and(|source| source != amount)
                {
                    return Err(anyhow::Error::new(super::AcceptanceEvidenceConflict)
                        .context("generic bulk input conflicts with source prevout evidence"));
                }
                if require_unwritten
                    && (status != "active" || spent_by.is_some() || spent_block.is_some())
                {
                    return Ok(None);
                }
                if status == "spent" && spent_by.as_deref() != Some(tx.txid.as_slice()) {
                    return Err(anyhow::Error::new(super::AcceptanceEvidenceConflict)
                        .context("generic bulk input was spent by a different transaction"));
                }
                if status == "spent" {
                    let old = spent_block
                        .as_ref()
                        .context("spent input has no accepting block")?;
                    if old != &tx.block_hash {
                        return Err(
                            super::AcceptanceConflict::new(&tx.txid, old, &tx.block_hash).into(),
                        );
                    }
                }
                classified.insert(cid.clone());
                found_inputs.insert((tx_ord as usize, input_ord as usize), (cid, address));
            }
            for (tx_ord, tx) in prepared.iter().enumerate() {
                for (input_ord, input) in tx.inputs.iter().enumerate() {
                    let found = found_inputs.contains_key(&(tx_ord, input_ord));
                    if require_unwritten && input.is_p2sh != Some(found) {
                        return Ok(None);
                    }
                    if !found && tx.tx.needs_input_identity(&tx.tx.inputs[input_ord]) {
                        return Err(super::identity::MissingIdentityDependency {
                            txid: input.source_hash.clone(), vout: input.vout,
                        }.into());
                    }
                    // The scalar writer ignores absent DB inputs. Preserve
                    // that behavior without inventing their script or amount;
                    // historical replay remains responsible for coverage.
                    if found && input.is_p2sh == Some(false) {
                        return Err(super::AcceptanceEvidenceConflict.into());
                    }
                }
            }
            let recognized_output: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM jsonb_to_recordset($1::jsonb)
                        AS s(covenant_id TEXT, script_hash TEXT, txid TEXT, vout INT, native BOOLEAN)
                    JOIN covenants c ON c.covenant_id=decode(s.covenant_id,'hex')
                    WHERE c.template_name IS NOT NULL OR c.claimed_template IS NOT NULL
                       OR c.classification_status='matched' OR c.script_hash<>decode(s.script_hash,'hex')
                ) OR EXISTS (
                    SELECT 1 FROM jsonb_to_recordset($1::jsonb)
                        AS s(covenant_id TEXT, script_hash TEXT, txid TEXT, vout INT, native BOOLEAN)
                    JOIN covenants c ON c.covenant_id=decode(s.script_hash,'hex')
                    WHERE s.native AND c.script_hash=c.covenant_id
                      AND c.genesis_txid=decode(s.txid,'hex') AND c.genesis_vout=s.vout
                )
                "#,
            ).bind(&output_rows).fetch_one(&mut *conn).await
             .context("check generic bulk output identities and native fallback rekey")?;
            if recognized_output {
                return Ok(None);
            }
            let conflicting_output: bool = sqlx::query_scalar(
                r#"
            SELECT EXISTS (
                SELECT 1 FROM jsonb_to_recordset($1::jsonb)
                    AS s(txid TEXT, vout INT, covenant_id TEXT, amount BIGINT,
                         script_pubkey TEXT, block_hash TEXT)
                JOIN covenant_utxos u ON u.txid = decode(s.txid, 'hex') AND u.vout = s.vout
                WHERE u.covenant_id <> decode(s.covenant_id, 'hex')
                   OR u.amount_sompi <> s.amount
                   OR u.script_pubkey <> decode(s.script_pubkey, 'hex')
            )
        "#,
            )
            .bind(&output_rows)
            .fetch_one(&mut *conn)
            .await
            .context("check generic bulk output conflicts")?;
            if conflicting_output {
                return Err(super::AcceptanceEvidenceConflict.into());
            }
            Self::check_transactions_acceptance(
                &mut conn,
                &prepared
                    .iter()
                    .map(|tx| tx.txid.clone())
                    .collect::<Vec<_>>(),
                &prepared
                    .iter()
                    .map(|tx| tx.block_hash.clone())
                    .collect::<Vec<_>>(),
            )
            .await
            .context("check generic batch acceptance")?;
            let conflicting_block: bool = sqlx::query_scalar(
                r#"
            SELECT EXISTS (
                SELECT 1 FROM jsonb_to_recordset($1::jsonb)
                    AS s(block_hash TEXT, blue_score BIGINT, block_time BIGINT)
                LEFT JOIN blocks b ON b.hash = decode(s.block_hash, 'hex')
                LEFT JOIN canonical_block_replacements r ON r.old_hash = decode(s.block_hash, 'hex')
                WHERE b.blue_score <> s.blue_score OR b.timestamp_ms <> s.block_time
                   OR r.old_hash IS NOT NULL
            )
        "#,
            )
            .bind(&transaction_rows)
            .fetch_one(&mut *conn)
            .await
            .context("check generic bulk accepting blocks")?;
            if conflicting_block {
                for tx in &prepared {
                    Self::check_transaction_acceptance(&mut conn, &tx.txid, &tx.block_hash).await?;
                }
                anyhow::bail!(
                    "generic bulk accepting block conflicts with persisted chain evidence"
                );
            }
            let prior: Vec<(i32, bool)> = sqlx::query_as(
                r#"
            SELECT s.tx_ord, EXISTS (
                SELECT 1 FROM covenant_utxos u
                WHERE u.covenant_id = decode(s.covenant_id, 'hex')
                  AND u.txid <> decode(s.txid, 'hex')
            )
            FROM jsonb_to_recordset($1::jsonb)
                 AS s(tx_ord INT, txid TEXT, covenant_id TEXT)
        "#,
            )
            .bind(&output_rows)
            .fetch_all(&mut *conn)
            .await
            .context("classify generic bulk outputs")?;
            let prior = prior.into_iter().collect::<HashMap<_, _>>();
            let existing_actions: Vec<(i32, String)> = sqlx::query_as(EXISTING_OUTPUT_ACTIONS_SQL)
                .bind(&output_rows)
                .fetch_all(&mut *conn)
                .await
                .context("reuse generic bulk output action kinds")?;
            let existing_actions = existing_actions.into_iter().collect::<HashMap<_, _>>();

            let mut stats = PersistStats::default();
            stats.blocks_inserted = sqlx::query(
                r#"
            INSERT INTO blocks (hash, blue_score, daa_score, parent_hashes, timestamp_ms,
                                is_chain_block, indexed_at_ms)
            SELECT decode(s.block_hash, 'hex'), s.blue_score, 0, ARRAY[]::bytea[],
                   s.block_time, TRUE, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
            FROM (SELECT DISTINCT ON (block_hash) block_hash, blue_score, block_time
                  FROM jsonb_to_recordset($1::jsonb)
                       AS r(block_hash TEXT, blue_score BIGINT, block_time BIGINT, tx_ord INT)
                  ORDER BY block_hash, tx_ord) s
            ON CONFLICT (hash) DO NOTHING
        "#,
            )
            .bind(&transaction_rows)
            .execute(&mut *conn)
            .await
            .context("insert generic bulk blocks")?
            .rows_affected();
            stats.covenants_inserted = sqlx::query(
                r#"
            INSERT INTO covenants (covenant_id, address, script_version, script_hash,
                                   template_name, genesis_txid, genesis_vout, genesis_block,
                                   created_at_ms, constructor_args)
            SELECT decode(s.covenant_id, 'hex'), s.address, 0,
                   decode(s.script_hash, 'hex'), NULL, decode(s.txid, 'hex'), s.vout,
                   decode(s.block_hash, 'hex'), s.block_time, NULL
            FROM (SELECT DISTINCT ON (covenant_id) covenant_id, script_hash, address, txid, vout,
                           block_hash, block_time
                  FROM jsonb_to_recordset($1::jsonb)
                       AS r(covenant_id TEXT, script_hash TEXT, address TEXT, txid TEXT, vout INT,
                            block_hash TEXT, block_time BIGINT, tx_ord INT)
                  ORDER BY covenant_id, tx_ord) s
            ON CONFLICT (covenant_id) DO NOTHING
        "#,
            )
            .bind(&output_rows)
            .execute(&mut *conn)
            .await
            .context("insert generic bulk covenants")?
            .rows_affected();

            // Only actual row changes contribute deltas. Retries and duplicate
            // outputs must never increment summary counters a second time.
            // Compilation overhead can exceed this bounded write's execution time
            // on a large database. Keep the setting local to this transaction.
            sqlx::query("SELECT set_config('tn12.defer_bulk_utxo_summaries', 'on', TRUE), set_config('jit', 'off', TRUE)")
                .execute(&mut *conn)
                .await
                .context("defer bulk UTXO summaries")?;
            let spent_rows: Vec<(Vec<u8>, i64)> = sqlx::query_as(
                r#"
            UPDATE covenant_utxos u
               SET status = 'spent', spent_block = decode(s.block_hash, 'hex'),
                   spent_by_txid = decode(s.txid, 'hex')
              FROM jsonb_to_recordset($1::jsonb)
                   AS s(prev_txid TEXT, vout INT, block_hash TEXT, txid TEXT)
             WHERE u.txid = decode(s.prev_txid, 'hex') AND u.vout = s.vout
               AND u.status = 'active'
            RETURNING u.covenant_id, u.amount_sompi
        "#,
            )
            .bind(&Value::Array(
                prepared
                    .iter()
                    .flat_map(|tx| {
                        tx.inputs.iter().map(|input| json!({
            "prev_txid": hex::encode(&input.prev_txid), "vout": input.vout,
            "block_hash": hex::encode(&tx.block_hash), "txid": hex::encode(&tx.txid),
        }))
                    })
                    .collect(),
            ))
            .fetch_all(&mut *conn)
            .await
            .context("spend generic bulk inputs")?;
            stats.utxos_spent = spent_rows.len() as u64;

            if !classified.is_empty() {
                let classified = classified.into_iter().collect::<Vec<_>>();
                sqlx::query(
                    r#"
                UPDATE covenants SET classification_kind = 'unknown',
                    classification_status = 'unmatched'
                WHERE covenant_id = ANY($1::bytea[])
                  AND classification_status <> 'matched'
                  AND (classification_kind IS DISTINCT FROM 'unknown'
                       OR classification_status IS DISTINCT FROM 'unmatched')
            "#,
                )
                .bind(&classified)
                .execute(&mut *conn)
                .await
                .context("classify generic bulk spends")?;
            }

            let inserted_rows: Vec<(Vec<u8>, i64, Vec<u8>, i32, String, Vec<u8>)> = sqlx::query_as(
                r#"
            INSERT INTO covenant_utxos (txid, vout, covenant_id, address, amount_sompi,
                                        script_pubkey, state, created_block, spent_block,
                                        spent_by_txid, status)
            SELECT decode(s.txid, 'hex'), s.vout, decode(s.covenant_id, 'hex'), s.address,
                   s.amount, decode(s.script_pubkey, 'hex'), NULL,
                   decode(s.block_hash, 'hex'), NULL, NULL, 'active'
            FROM jsonb_to_recordset($1::jsonb)
                 AS s(tx_ord INT, txid TEXT, vout INT, covenant_id TEXT, address TEXT,
                      amount BIGINT, script_pubkey TEXT, block_hash TEXT)
            ORDER BY s.tx_ord
            ON CONFLICT (txid, vout) DO NOTHING
            RETURNING covenant_id, amount_sompi, txid, vout, address, created_block
        "#,
            )
            .bind(&output_rows)
            .fetch_all(&mut *conn)
            .await
            .context("insert generic bulk outputs")?;
            stats.utxos_inserted = inserted_rows.len() as u64;
            sqlx::query("SELECT set_config('tn12.defer_bulk_utxo_summaries', 'off', TRUE)")
                .execute(&mut *conn)
                .await
                .context("restore bulk UTXO summaries")?;
            let mut summary_changes = spent_rows
                .iter()
                .map(|(cid, amount)| {
                    json!({
                        "cid": hex::encode(cid), "count_delta": -1, "amount_delta": -amount,
                    })
                })
                .collect::<Vec<_>>();
            summary_changes.extend(inserted_rows.iter().map(|(cid, amount, txid, vout, address, block)| json!({
                "cid": hex::encode(cid), "count_delta": 1, "amount_delta": amount,
                "txid": hex::encode(txid), "vout": vout, "address": address, "block": hex::encode(block),
            })));
            if !summary_changes.is_empty() {
                let expected = spent_rows
                    .iter()
                    .map(|r| &r.0)
                    .chain(inserted_rows.iter().map(|r| &r.0))
                    .collect::<HashSet<_>>()
                    .len();
                let updated = sqlx::query(include_str!("finalize_bulk_summary_deltas.sql"))
                    .bind(Value::Array(summary_changes))
                    .execute(&mut *conn)
                    .await
                    .context("apply generic bulk summary deltas")?
                    .rows_affected();
                anyhow::ensure!(
                    updated as usize == expected,
                    "bulk summary missing or invalid; transaction rolled back"
                );
            }

            let mut actions = Vec::new();
            let mut seen = HashSet::new();
            for (tx_ord, tx) in prepared.iter().enumerate() {
                for (input_ord, input) in tx.inputs.iter().enumerate() {
                    if let Some((cid, address)) = found_inputs.get(&(tx_ord, input_ord)) {
                        actions.push(json!({
                        "tx_ord": tx_ord, "action_ord": input_ord,
                        "action": "spend",
                        "covenant_id": hex::encode(cid), "txid": hex::encode(&tx.txid),
                        "block_hash": hex::encode(&tx.block_hash), "block_time": tx.block_time,
                        "inputs": {"previousOutpoint": {"hash": input.source_hash, "index": input.vout},
                                   "address": address},
                        "outputs": null,
                    }));
                    }
                }
                let Some(output) = &tx.output else {
                    continue;
                };
                let was_seen = !seen.insert(output.covenant_id.clone());
                let action = existing_actions
                    .get(&(tx_ord as i32))
                    .map(String::as_str)
                    .unwrap_or(
                        if was_seen || prior.get(&(tx_ord as i32)).copied().unwrap_or(false) {
                            "continuation"
                        } else {
                            "deploy"
                        },
                    );
                let mut row = output_rows_by_tx[tx_ord]
                    .clone()
                    .expect("prepared output row");
                row["action"] = Value::String(action.to_string());
                row["action_ord"] = json!(tx.inputs.len());
                row["inputs"] = Value::Null;
                actions.push(row);
            }
            stats.actions_inserted = sqlx::query(
                r#"
            INSERT INTO covenant_actions (covenant_id, txid, block_hash, block_time_ms,
                                          action, entrypoint, inputs, outputs, decoded_args)
            SELECT decode(s.covenant_id, 'hex'), decode(s.txid, 'hex'),
                   decode(s.block_hash, 'hex'), s.block_time, s.action, NULL,
                   s.inputs, s.outputs, NULL
            FROM jsonb_to_recordset($1::jsonb)
                 AS s(tx_ord INT, action_ord INT, covenant_id TEXT, txid TEXT,
                      block_hash TEXT, block_time BIGINT, action TEXT,
                      inputs JSONB, outputs JSONB)
            ORDER BY s.tx_ord, s.action_ord
            ON CONFLICT DO NOTHING
        "#,
            )
            .bind(&Value::Array(actions))
            .execute(&mut *conn)
            .await
            .context("insert generic bulk actions")?
            .rows_affected();

            Ok::<_, anyhow::Error>(Some(stats))
        };
        let result = if budget_enabled {
            match tokio::time::timeout(std::time::Duration::from_millis(200), work).await {
                Ok(result) => result,
                Err(_) => Err(WriterBodyDeadline.into()),
            }
        } else {
            work.await
        };
        let stats = match result {
            Ok(Some(stats)) => stats,
            Ok(None) => {
                conn.rollback()
                    .await
                    .map_err(|error| super::GenericWriteOutcomeUnknown {
                        phase: "rollback",
                        detail: error.to_string(),
                    })?;
                lease.reusable = true;
                return Ok(None);
            }
            Err(error) => {
                // Drains any in-flight query before rollback. Do not report a
                // retryable outcome or reuse this connection before completion.
                conn.rollback()
                    .await
                    .map_err(|error| super::GenericWriteOutcomeUnknown {
                        phase: "rollback",
                        detail: error.to_string(),
                    })?;
                lease.reusable = true;
                if error.downcast_ref::<WriterBodyDeadline>().is_some()
                    || is_budget_statement_timeout(&error, budget_statement_cap_applied)
                {
                    return Err(super::TransientPersistError::writer_budget_exceeded().into());
                }
                return Err(error.context(GenericRollbackAcknowledged));
            }
        };
        // Never cancel a commit future. An unknown acknowledgement requires
        // fresh source validation and whole-window reconciliation.
        conn.commit()
            .await
            .map_err(|error| super::GenericWriteOutcomeUnknown {
                phase: "commit",
                detail: error.to_string(),
            })?;
        lease.reusable = true;
        Ok(Some(GenericBatchStats {
            stats,
            lock_wait_us,
            lock_held_us: held_started.elapsed().as_micros(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use tn12_indexer_core::{RestTxInput, RestTxOutput};

    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn captured_sparse_child_bulk_matches_scalar_without_parent(pool: sqlx::PgPool) {
        captured_sparse_parity(pool, false).await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn captured_sparse_child_bulk_matches_scalar_with_parent(pool: sqlx::PgPool) {
        captured_sparse_parity(pool, true).await;
    }

    async fn captured_sparse_parity(pool: sqlx::PgPool, seed_parent: bool) {
        use crate::Persister;
        let child: RestTransaction = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-cold-parent-child.json"
        ))
        .unwrap();
        let parent: RestTransaction =
            serde_json::from_str(include_str!("../../tests/fixtures/tn10-cold-parent.json"))
                .unwrap();
        let writer = PgPersister::new(pool.clone());
        if seed_parent {
            writer.persist_tx(&parent).await.unwrap();
        }
        let snapshot = r#"SELECT jsonb_build_object(
          'covenants',(SELECT jsonb_agg(to_jsonb(t) ORDER BY covenant_id) FROM covenants t),
          'utxos',(SELECT jsonb_agg(to_jsonb(t) ORDER BY txid,vout) FROM covenant_utxos t),
          'actions',(SELECT jsonb_agg(to_jsonb(t)-'id' ORDER BY txid,covenant_id,action) FROM covenant_actions t),
          'summaries',(SELECT jsonb_agg(to_jsonb(t)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_summaries t)
        )"#;
        writer.persist_tx(&child).await.unwrap();
        let scalar: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        writer
            .revert_block(&hex::decode(child.accepting_block_hash.as_deref().unwrap()).unwrap())
            .await
            .unwrap();
        let scalar_reverted: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        sqlx::query("TRUNCATE covenants,blocks RESTART IDENTITY CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        if seed_parent {
            writer.persist_tx(&parent).await.unwrap();
        }
        let result = writer
            .try_persist_generic_batch(std::slice::from_ref(&child))
            .await
            .unwrap();
        assert!(
            result.is_some(),
            "captured sparse child must not require scalar fallback"
        );
        let bulk: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        assert_eq!(bulk, scalar);
        // Replay must preserve all semantic rows without duplicate actions.
        assert!(writer
            .try_persist_generic_batch(std::slice::from_ref(&child))
            .await
            .unwrap()
            .is_some());
        let replay: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        assert_eq!(replay, scalar);
        writer
            .revert_block(&hex::decode(child.accepting_block_hash.as_deref().unwrap()).unwrap())
            .await
            .unwrap();
        let bulk_reverted: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        assert_eq!(bulk_reverted, scalar_reverted);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn captured_sparse_child_keeps_conflict_and_classification_guards(pool: sqlx::PgPool) {
        use crate::Persister;
        let child: RestTransaction = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-cold-parent-child.json"
        ))
        .unwrap();
        let parent: RestTransaction =
            serde_json::from_str(include_str!("../../tests/fixtures/tn10-cold-parent.json"))
                .unwrap();
        let writer = PgPersister::new(pool.clone());
        writer.persist_tx(&parent).await.unwrap();
        let mut bad = child.clone();
        bad.inputs[0].previous_outpoint_amount = Some(parent.outputs[0].amount + 1);
        let error = writer
            .try_persist_generic_batch(&[bad])
            .await
            .err()
            .unwrap();
        assert!(error
            .downcast_ref::<super::super::AcceptanceEvidenceConflict>()
            .is_some());
        let probe = PgPersister::new(pool.clone())
            .persist_guarded_generic_probe(std::slice::from_ref(&child))
            .await;
        assert!(matches!(probe.reason, ProbeReason::InvalidInput));
        sqlx::query("UPDATE covenants SET template_name='guarded-template'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(writer
            .try_persist_generic_batch(std::slice::from_ref(&child))
            .await
            .unwrap()
            .is_none());
        let states: Vec<String> = sqlx::query_scalar("SELECT status FROM covenant_utxos")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(states, vec!["active"]);
    }

    // Captured accepted TN10 child and parent on 2026-10-01. The parent
    // predates the sampled watcher connection and was absent from its DB.
    #[sqlx::test(migrations = "./migrations")]
    async fn captured_cold_parent_preserves_strict_probe_evidence_gates(pool: sqlx::PgPool) {
        use crate::Persister;
        let child: RestTransaction = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-cold-parent-child.json"
        ))
        .unwrap();
        let parent: RestTransaction =
            serde_json::from_str(include_str!("../../tests/fixtures/tn10-cold-parent.json"))
                .unwrap();
        let writer = PgPersister::new(pool.clone());
        assert_eq!(
            child.inputs[0].previous_outpoint_hash,
            parent.transaction_id
        );
        assert!(child.inputs[0].previous_outpoint_script.is_none());
        assert!(prepare(&child, &writer.decoders).is_none());
        assert!(writer
            .try_persist_generic_batch_with_fence(std::slice::from_ref(&child), false, true)
            .await
            .unwrap()
            .is_none());

        // Canonical parent metadata fixes eligibility, but cannot supply the
        // missing database row. Hydration alone is therefore insufficient.
        let mut hydrated = child.clone();
        let output = &parent.outputs[0];
        hydrated.inputs[0].previous_outpoint_script = Some(output.script_public_key.clone());
        hydrated.inputs[0].previous_outpoint_amount = Some(output.amount);
        assert!(is_candidate(&hydrated, &writer.decoders));
        assert!(writer
            .try_persist_generic_batch_with_fence(std::slice::from_ref(&hydrated), false, true)
            .await
            .unwrap()
            .is_none());
        let untouched: i64 = sqlx::query_scalar("SELECT count(*) FROM covenant_utxos")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(untouched, 0, "fallback must not partially write");

        writer.persist_tx(&parent).await.unwrap();
        assert!(
            writer
                .try_persist_generic_batch_with_fence(std::slice::from_ref(&hydrated), false, true)
                .await
                .unwrap()
                .is_some(),
            "canonical parent persistence enables batching"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM covenant_utxos WHERE txid=$1 AND vout=0")
                .bind(hex::decode(&parent.transaction_id).unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "spent");
    }

    #[sqlx::test(migrations = false)]
    async fn existing_output_actions_preserve_filters_and_cached_results(pool: sqlx::PgPool) {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::raw_sql(r#"
CREATE TEMP TABLE covenant_actions (id BIGINT PRIMARY KEY, txid BYTEA NOT NULL,covenant_id BYTEA NOT NULL,action TEXT NOT NULL,outputs JSONB);
CREATE INDEX ON covenant_actions(txid);
CREATE INDEX ON covenant_actions(txid,covenant_id,action,id);
INSERT INTO covenant_actions VALUES
(1,decode('01','hex'),decode('aa','hex'),'deploy','{"vout":0}'),
(2,decode('01','hex'),decode('aa','hex'),'continuation','{"vout":0}'),
(3,decode('01','hex'),decode('bb','hex'),'continuation','{"vout":0}'),
(4,decode('02','hex'),decode('aa','hex'),'spend','{"vout":0}'),
(5,decode('02','hex'),decode('aa','hex'),'continuation','{"vout":1}'),
(6,decode('03','hex'),decode('aa','hex'),'continuation','{"vout":"0"}'),
(7,decode('04','hex'),decode('aa','hex'),'continuation','{}'),
(8,decode('05','hex'),decode('aa','hex'),'deploy',NULL),
(9,decode('06','hex'),decode('aa','hex'),'continuation','{"vout":null}'),
(10,decode('07','hex'),decode('aa','hex'),'continuation','{"vout":"00"}'),
(11,decode('08','hex'),decode('aa','hex'),'continuation','{"vout":-1}');
CREATE TEMP TABLE inputs AS SELECT jsonb_build_array(
jsonb_build_object('tx_ord',0,'txid','ff','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',1,'txid','01','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',2,'txid','01','covenant_id','bb','vout',0),
jsonb_build_object('tx_ord',3,'txid','01','covenant_id','cc','vout',0),
jsonb_build_object('tx_ord',4,'txid','02','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',5,'txid','02','covenant_id','aa','vout',1),
jsonb_build_object('tx_ord',6,'txid','03','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',7,'txid','04','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',8,'txid','05','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',9,'txid','06','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',10,'txid','07','covenant_id','aa','vout',0),
jsonb_build_object('tx_ord',11,'txid','08','covenant_id','aa','vout',-1)) AS payload;
CREATE TEMP TABLE expected(tx_ord INT,action TEXT);
INSERT INTO expected VALUES (1,'deploy'),(2,'continuation'),(5,'continuation'),(6,'continuation'),(11,'continuation');
"#).execute(&mut *conn).await.unwrap();
        // A transaction may also have spends. They must not change output kind selection.
        sqlx::query("INSERT INTO covenant_actions SELECT 100 + n,decode('01','hex'),decode('aa','hex'),'spend',jsonb_build_object('vout',0) FROM generate_series(1,1000) n")
            .execute(&mut *conn).await.unwrap();
        let input: Value = sqlx::query_scalar("SELECT payload FROM inputs")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        let expected: Vec<(i32, String)> = sqlx::query_as("SELECT * FROM expected ORDER BY tx_ord")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        for plan in ["force_custom_plan", "force_generic_plan"] {
            sqlx::query("SELECT set_config('plan_cache_mode', $1, false)")
                .bind(plan)
                .execute(&mut *conn)
                .await
                .unwrap();
            for _ in 0..7 {
                let mut actual: Vec<(i32, String)> = sqlx::query_as(EXISTING_OUTPUT_ACTIONS_SQL)
                    .bind(&input)
                    .fetch_all(&mut *conn)
                    .await
                    .unwrap();
                actual.sort();
                assert_eq!(actual, expected, "{plan}");
            }
            let empty: Vec<(i32, String)> = sqlx::query_as(EXISTING_OUTPUT_ACTIONS_SQL)
                .bind(json!([]))
                .fetch_all(&mut *conn)
                .await
                .unwrap();
            assert!(empty.is_empty());
        }
    }

    fn generic_tx() -> RestTransaction {
        RestTransaction {
            transaction_id: "11".repeat(32),
            is_accepted: true,
            accepting_block_hash: Some("22".repeat(32)),
            accepting_block_blue_score: Some(100),
            accepting_block_time: Some(1_000),
            inputs: vec![RestTxInput {
                previous_outpoint_hash: "33".repeat(32),
                previous_outpoint_index: "0".into(),
                previous_outpoint_amount: Some(100),
                previous_outpoint_script: Some(format!("aa20{}87", "44".repeat(32))),
                signature_script: "0151".into(),
                ..Default::default()
            }],
            outputs: vec![RestTxOutput {
                amount: 90,
                script_public_key: format!("aa20{}87", "55".repeat(32)),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn ordinary_history_batches_can_reach_1024_transactions() {
        let registry = tn12_indexer_decoder::default_registry();
        let mut transactions = Vec::new();
        for n in 0..1025 {
            let mut transaction = generic_tx();
            transaction.transaction_id = format!("{:064x}", 10_000 + n);
            transaction.inputs[0].previous_outpoint_hash = format!("{:064x}", 20_000 + n);
            transactions.push(transaction);
        }
        assert_eq!(independent_prefix_len(&transactions, &registry), 1024);
        assert_eq!(MAX_TXS, 1024);

        let mut mixed = transactions[..300].to_vec();
        let consolidation: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-consolidation-2.json"
        ))
        .unwrap();
        mixed.push(consolidation[0].clone());
        assert_eq!(independent_prefix_len(&mixed, &registry), 300);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn batch_of_1024_matches_four_ordered_batches_of_256(pool: sqlx::PgPool) {
        let transactions = (0..1024)
            .map(|n| {
                let mut transaction = generic_tx();
                transaction.transaction_id = format!("{:064x}", 10_000 + n);
                transaction.inputs[0].previous_outpoint_hash = format!("{:064x}", 20_000 + n);
                transaction
            })
            .collect::<Vec<_>>();
        let writer = PgPersister::new(pool.clone());
        let snapshot = r#"SELECT jsonb_build_object(
          'covenants',(SELECT jsonb_agg(to_jsonb(t) ORDER BY covenant_id) FROM covenants t),
          'utxos',(SELECT jsonb_agg(to_jsonb(t) ORDER BY txid,vout) FROM covenant_utxos t),
          'actions',(SELECT jsonb_agg(to_jsonb(t)-'id' ORDER BY txid,covenant_id,action) FROM covenant_actions t),
          'summaries',(SELECT jsonb_agg(to_jsonb(t)-'updated_at_ms' ORDER BY covenant_id) FROM covenant_summaries t)
        )"#;

        assert!(writer
            .try_persist_generic_batch(&transactions)
            .await
            .unwrap()
            .is_some());
        let combined: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        sqlx::query("TRUNCATE covenants,blocks RESTART IDENTITY CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        for half in transactions.chunks(256) {
            assert!(writer
                .try_persist_generic_batch(half)
                .await
                .unwrap()
                .is_some());
        }
        let ordered: Value = sqlx::query_scalar(snapshot).fetch_one(&pool).await.unwrap();
        assert_eq!(combined, ordered);
    }

    #[test]
    fn captured_consolidations_use_bounded_bulk_prefix() {
        let registry = tn12_indexer_decoder::default_registry();
        let txs: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-consolidation-2.json"
        ))
        .unwrap();
        assert_eq!(txs.len(), 2);
        assert!(txs.iter().all(|tx| tx.inputs.len() == 84));
        assert!(
            txs.iter().all(|tx| is_candidate(tx, &registry)),
            "captured generic consolidation spends must avoid the per-input writer"
        );
        assert_eq!(independent_prefix_len(&txs, &registry), 2);
    }

    #[tokio::test]
    async fn consolidation_writer_rejects_excess_work_before_database_access() {
        let fixture: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-consolidation-2.json"
        ))
        .unwrap();
        let mut txs = Vec::new();
        for n in 0..7 {
            let mut tx = fixture[0].clone();
            tx.transaction_id = format!("{:064x}", 10_000 + n);
            for (i, input) in tx.inputs.iter_mut().enumerate() {
                input.previous_outpoint_hash = format!("{:064x}", 20_000 + n * 100 + i);
            }
            txs.push(tx);
        }
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(30))
            .connect_lazy("postgresql://127.0.0.1:1/unused")
            .unwrap();
        let writer = PgPersister::new(pool);
        // All seven transactions are individually eligible and independent,
        // but 588 input actions exceed the bound before any SQL may run.
        assert!(writer
            .try_persist_generic_batch(&txs)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn consolidations_keep_work_limits_and_dependency_checks() {
        let registry = tn12_indexer_decoder::default_registry();
        let txs: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-consolidation-2.json"
        ))
        .unwrap();
        assert_eq!(minimum_batch_len(&txs[0]), 1);
        assert_eq!(minimum_batch_len(&generic_tx()), 2);
        let mut many = Vec::new();
        for n in 0..7 {
            let mut tx = txs[0].clone();
            tx.transaction_id = format!("{:064x}", 10_000 + n);
            for (i, input) in tx.inputs.iter_mut().enumerate() {
                input.previous_outpoint_hash = format!("{:064x}", 20_000 + n * 100 + i);
            }
            many.push(tx);
        }
        assert_eq!(independent_prefix_len(&many, &registry), 6); // 504 input actions
        let mut conflict = txs.clone();
        conflict[1].inputs[0] = conflict[0].inputs[0].clone();
        assert_eq!(independent_prefix_len(&conflict, &registry), 1);
        conflict[1].inputs[0].previous_outpoint_hash = conflict[0].transaction_id.clone();
        assert_eq!(independent_prefix_len(&conflict, &registry), 1);
        let mut oversized = txs[0].clone();
        oversized.inputs.resize(129, oversized.inputs[0].clone());
        assert!(!is_candidate(&oversized, &registry));
        let mut payload = txs[0].clone();
        payload.payload = Some("00".into());
        assert!(!is_candidate(&payload, &registry));
        let mut native = txs[0].clone();
        native.version = 1;
        assert!(!is_candidate(&native, &registry));
        let mut output = txs[0].clone();
        output.outputs = generic_tx().outputs;
        assert!(!is_candidate(&output, &registry)); // Existing output-producing cap stays 16.
    }

    #[test]
    fn bulk_prefix_stops_at_dependencies_and_conflicts() {
        let registry = tn12_indexer_decoder::default_registry();
        let first = generic_tx();
        let mut second = first.clone();
        second.transaction_id = "66".repeat(32);
        second.inputs[0].previous_outpoint_hash = "77".repeat(32);
        assert_eq!(
            independent_prefix_len(&[first.clone(), second.clone()], &registry),
            2
        );
        second.inputs[0].previous_outpoint_hash = first.transaction_id.clone();
        assert_eq!(
            independent_prefix_len(&[first.clone(), second.clone()], &registry),
            1
        );
        second.inputs[0].previous_outpoint_hash = first.inputs[0].previous_outpoint_hash.clone();
        assert_eq!(
            independent_prefix_len(&[first.clone(), second.clone()], &registry),
            1
        );
        second.inputs[0].previous_outpoint_hash = "77".repeat(32);
        second.transaction_id = first.transaction_id.clone();
        assert_eq!(
            independent_prefix_len(&[first.clone(), second.clone()], &registry),
            1
        );
        second.transaction_id = first.inputs[0].previous_outpoint_hash.clone();
        assert_eq!(independent_prefix_len(&[first, second], &registry), 1);
    }

    #[test]
    fn bulk_candidate_bounds_staged_data() {
        let registry = tn12_indexer_decoder::default_registry();
        let mut tx = generic_tx();
        tx.inputs = vec![tx.inputs[0].clone(); 17];
        assert!(!is_candidate(&tx, &registry));
        let mut tx = generic_tx();
        tx.outputs.extend(vec![RestTxOutput::default(); 64]);
        assert!(!is_candidate(&tx, &registry));
        let mut tx = generic_tx();
        tx.inputs[0].signature_script = "00".repeat(65536);
        assert!(!is_candidate(&tx, &registry));
    }

    #[test]
    fn bulk_prefix_caps_total_actions_for_many_input_transactions() {
        let registry = tn12_indexer_decoder::default_registry();
        let txs: Vec<_> = (0..31u8)
            .map(|index| {
                let mut tx = generic_tx();
                tx.transaction_id = format!("{:02x}", index + 1).repeat(32);
                tx.inputs = (0..16u8)
                    .map(|input_index| {
                        let mut input = tx.inputs[0].clone();
                        input.previous_outpoint_hash = format!("{:02x}", index + 32).repeat(32);
                        input.previous_outpoint_index = input_index.to_string();
                        input
                    })
                    .collect();
                tx
            })
            .collect();
        assert_eq!(independent_prefix_len(&txs, &registry), 30);
    }

    fn push_data(data: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        match data.len() {
            0..=75 => script.push(data.len() as u8),
            76..=255 => script.extend([0x4c, data.len() as u8]),
            256..=65535 => {
                script.push(0x4d);
                script.extend_from_slice(&(data.len() as u16).to_le_bytes());
            }
            _ => panic!("fixture reveal is too large"),
        }
        script.extend_from_slice(data);
        script
    }

    #[test]
    fn generic_bulk_excludes_kcc20_and_incomplete_source_evidence() {
        let registry = tn12_indexer_decoder::default_registry();
        let base = generic_tx();
        assert!(is_candidate(&base, &registry));

        let mut claimed = base.clone();
        claimed.payload = Some("01".into());
        assert!(!is_candidate(&claimed, &registry));

        let mut bound = base.clone();
        bound.outputs[0].covenant_id = Some("66".repeat(32));
        assert!(!is_candidate(&bound, &registry));

        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tn12-indexer-decoder/fixtures/kcc20/KCC20.placeholder.json"
        ))
        .unwrap();
        let reveal: Vec<u8> = serde_json::from_value(artifact["bytecode"].clone()).unwrap();
        let mut recognized = base.clone();
        recognized.inputs[0].signature_script = hex::encode(push_data(&reveal));
        assert!(super::super::classify_reveal(
            &registry,
            &hex::decode(&recognized.inputs[0].signature_script).unwrap(),
            &reveal
        )
        .is_some());
        assert!(!is_candidate(&recognized, &registry));

        let mut missing_script = base.clone();
        missing_script.inputs[0].previous_outpoint_script = None;
        assert!(prepare(&missing_script, &registry).is_none());

        let mut missing_amount = base;
        missing_amount.inputs[0].previous_outpoint_amount = None;
        assert!(prepare(&missing_amount, &registry).is_none());
    }
}

#[cfg(test)]
mod budget_regression {
    use super::*;
    use crate::Persister;
    use tn12_indexer_core::RestTxOutput;
    const BUDGET_SNAPSHOT: &str = "SELECT jsonb_build_object('blocks',(SELECT jsonb_agg(to_jsonb(t) ORDER BY hash) FROM blocks t),'covenants',(SELECT jsonb_agg(to_jsonb(t) ORDER BY covenant_id) FROM covenants t),'utxos',(SELECT jsonb_agg(to_jsonb(t) ORDER BY txid,vout) FROM covenant_utxos t),'actions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM covenant_actions t),'summaries',(SELECT jsonb_agg(to_jsonb(t) ORDER BY covenant_id) FROM covenant_action_summaries t))";

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_slow_statement_rolls_back(pool: sqlx::PgPool) {
        check_budget_rollback(pool, 0.09, false, false).await;
    }

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_aggregate_hold_stays_within_400ms(pool: sqlx::PgPool) {
        check_budget_rollback(pool, 0.05, true, false).await;
    }

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_caller_cancellation_releases_lock(pool: sqlx::PgPool) {
        check_budget_rollback(pool, 0.05, false, true).await;
    }

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = false)]
    async fn generic_budget_keeps_stricter_configured_timeout(pool: sqlx::PgPool) {
        for (configured, expected, owned) in [
            ("0", 75_i64, true),
            ("20ms", 20, false),
            ("75ms", 75, true),
            ("1s", 75, true),
            ("1min", 75, true),
        ] {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SELECT set_config('statement_timeout', $1, true)")
                .bind(configured)
                .execute(&mut *tx)
                .await
                .unwrap();
            let (_, cap_applied): (String, bool) = sqlx::query_as(BUDGET_STATEMENT_TIMEOUT_SQL)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(cap_applied, owned, "configured {configured}");
            let actual: i64 = sqlx::query_scalar(
                "SELECT setting::bigint FROM pg_settings WHERE name='statement_timeout'",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(actual, expected, "configured {configured}");
            tx.rollback().await.unwrap();
        }
    }

    async fn seed_budget_fixture(pool: sqlx::PgPool) -> (PgPersister, Vec<RestTransaction>) {
        let fixture: Vec<RestTransaction> = serde_json::from_str(include_str!(
            "../../tests/fixtures/tn10-dense-generic-32.json"
        ))
        .unwrap();
        let txs = &fixture[..16];
        let writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
        for tx in txs {
            for input in &tx.inputs {
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
        (writer, txs.to_vec())
    }

    async fn check_budget_rollback(pool: sqlx::PgPool, delay: f64, aggregate: bool, cancel: bool) {
        let (writer, txs) = seed_budget_fixture(pool.clone()).await;
        let txs = &txs;
        // Aggregate case: each 50ms statement fits the 75ms server cap, but
        // five statements exceed the 200ms whole-body budget.
        sqlx::query("CREATE TABLE test_generic_delay_config(seconds double precision NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO test_generic_delay_config VALUES ($1)")
            .bind(delay)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(r#"
CREATE SEQUENCE test_generic_delay_calls;
CREATE FUNCTION test_generic_delay() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM nextval('test_generic_delay_calls'); PERFORM pg_sleep(seconds) FROM test_generic_delay_config; RETURN NULL; END $$;
CREATE TRIGGER test_delay AFTER INSERT ON blocks FOR EACH STATEMENT EXECUTE FUNCTION test_generic_delay();
CREATE TRIGGER test_delay AFTER INSERT ON covenants FOR EACH STATEMENT EXECUTE FUNCTION test_generic_delay();
CREATE TRIGGER test_delay_insert AFTER INSERT ON covenant_utxos FOR EACH STATEMENT EXECUTE FUNCTION test_generic_delay();
CREATE TRIGGER test_delay_update AFTER UPDATE ON covenant_utxos FOR EACH STATEMENT EXECUTE FUNCTION test_generic_delay();
CREATE TRIGGER test_delay AFTER INSERT ON covenant_actions FOR EACH STATEMENT EXECUTE FUNCTION test_generic_delay();
"#).execute(&pool).await.unwrap();
        let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let writer_work = async {
            if cancel {
                tokio::select! {
                    result = writer.try_persist_generic_batch_inner(txs, true) => result,
                    _ = cancel_rx => Err(anyhow::anyhow!("injected caller cancellation")),
                }
            } else {
                writer.try_persist_generic_batch_inner(txs, true).await
            }
        };
        let observer_work = async {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    let reached: bool =
                        sqlx::query_scalar("SELECT is_called FROM test_generic_delay_calls")
                            .fetch_one(&pool)
                            .await
                            .unwrap();
                    if reached {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                if cancel {
                    cancel_tx.send(()).unwrap();
                }
                let mut observer = pool.begin().await.unwrap();
                sqlx::query("SET LOCAL statement_timeout='1s'")
                    .execute(&mut *observer)
                    .await
                    .unwrap();
                sqlx::query("SELECT pg_advisory_xact_lock(6074847039450202930::bigint)")
                    .execute(&mut *observer)
                    .await
                    .unwrap();
                let acquired_at = started.elapsed();
                observer.rollback().await.unwrap();
                acquired_at
            })
            .await
            .expect("waiting writer must acquire after budget rollback")
        };
        let (result, observer_acquired_at) = tokio::join!(writer_work, observer_work);
        let elapsed = started.elapsed();
        assert!(
            observer_acquired_at.as_millis() <= 400,
            "concurrent writer acquired at {observer_acquired_at:?}"
        );
        let calls: i64 = sqlx::query_scalar("SELECT last_value FROM test_generic_delay_calls")
            .fetch_one(&pool)
            .await
            .unwrap();
        if aggregate {
            assert!(
                (3..=5).contains(&calls),
                "aggregate path reached {calls} delayed statements"
            );
        } else {
            assert_eq!(calls, 1);
        }
        match result {
            Ok(Some(stats)) => {
                eprintln!("actual generic writer hold: {}us", stats.lock_held_us);
                panic!(
                    "expected budget rollback, batch committed after {}us",
                    stats.lock_held_us
                );
            }
            Ok(None) => panic!("fixture must exercise the generic writer"),
            Err(error) => {
                let message = format!("{error:#}");
                if cancel {
                    assert!(message.contains("injected caller cancellation"));
                } else {
                    assert_eq!(
                        error
                            .downcast_ref::<super::super::TransientPersistError>()
                            .unwrap()
                            .kind,
                        super::super::PersistTransientKind::WriterBudgetExceeded
                    );
                    assert!(
                        message.contains("body budget exceeded"),
                        "acknowledged budget rollback must enable splitting: {message}"
                    );
                }
                if !cancel {
                    assert!(
                        super::super::is_transient_persist_error(&error),
                        "confirmed rollback must prevent caller serial fallback"
                    );
                }
                assert!(elapsed.as_millis() <= 400, "rollback took {elapsed:?}");
                let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
                assert_eq!(
                    before, after,
                    "cancelled batch must leave stored state unchanged"
                );
                let mut observer = pool.begin().await.unwrap();
                let free: bool = sqlx::query_scalar(
                    "SELECT pg_try_advisory_xact_lock(6074847039450202930::bigint)",
                )
                .fetch_one(&mut *observer)
                .await
                .unwrap();
                assert!(
                    free,
                    "writer lock must be released before returning failure"
                );
                observer.rollback().await.unwrap();
                eprintln!("budget rollback completed in {elapsed:?}; five tables unchanged and writer lock free");
            }
        }
    }
    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_replay_after_lost_commit_ack_matches_stored_state(pool: sqlx::PgPool) {
        check_lost_transaction_ack(pool, true, false, false).await;
    }

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_normal_lost_commit_ack_matches_stored_state(pool: sqlx::PgPool) {
        check_lost_transaction_ack(pool, false, false, false).await;
    }

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_lost_rollback_ack_is_not_retryable(pool: sqlx::PgPool) {
        check_lost_transaction_ack(pool, true, true, false).await;
    }

    async fn check_lost_transaction_ack(
        pool: sqlx::PgPool,
        budget_enabled: bool,
        rollback: bool,
        strict_probe: bool,
    ) {
        use sqlx::postgres::{PgPoolOptions, PgSslMode};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let (_seed_writer, txs) = seed_budget_fixture(pool.clone()).await;
        let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        if rollback {
            sqlx::raw_sql(r#"
CREATE FUNCTION test_force_rollback() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'injected body failure'; END $$;
CREATE TRIGGER test_force_rollback BEFORE INSERT ON covenant_actions FOR EACH STATEMENT EXECUTE FUNCTION test_force_rollback();
"#).execute(&pool).await.unwrap();
        }
        let options = (*pool.connect_options()).clone();
        assert_eq!(options.get_host(), "127.0.0.1", "fault proxy is local-only");
        assert_eq!(
            options.get_port(),
            55439,
            "fault proxy only uses owned test DB"
        );
        let upstream_port = options.get_port();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let backend_pid = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0));
        let proxy_pid = backend_pid.clone();
        let proxy = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(10), async move {
                let (client, _) = listener.accept().await.unwrap();
                let server = TcpStream::connect(("127.0.0.1", upstream_port)).await.unwrap();
                client.set_nodelay(true).unwrap();
                server.set_nodelay(true).unwrap();
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                let forward = async { tokio::io::copy(&mut client_read, &mut server_write).await };
                let intercept = async {
                    loop {
                        let tag = server_read.read_u8().await.unwrap();
                        let length = server_read.read_u32().await.unwrap();
                        assert!((4..=16_777_216).contains(&length));
                        let mut body = vec![0; (length - 4) as usize];
                        server_read.read_exact(&mut body).await.unwrap();
                        if tag == b'K' {
                            proxy_pid.store(i32::from_be_bytes(body[..4].try_into().unwrap()), std::sync::atomic::Ordering::SeqCst);
                        }
                        // PostgreSQL has completed COMMIT. Deliberately suppress
                        // its acknowledgement so the real writer observes EOF.
                        if tag == b'C' && body == if rollback { b"ROLLBACK\0".as_slice() } else { b"COMMIT\0".as_slice() } {
                            client_write.shutdown().await.unwrap();
                            return;
                        }
                        let mut frame = Vec::with_capacity(length as usize + 1);
                        frame.push(tag);
                        frame.extend_from_slice(&length.to_be_bytes());
                        frame.extend_from_slice(&body);
                        client_write.write_all(&frame).await.unwrap();
                    }
                };
                tokio::select! {
                    result = forward => panic!("client closed before committed acknowledgement: {result:?}"),
                    _ = intercept => (),
                }
            }).await.expect("commit acknowledgement proxy deadline");
        });
        let faulty = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(
                options
                    .host("127.0.0.1")
                    .port(proxy_port)
                    .ssl_mode(PgSslMode::Disable),
            )
            .await
            .unwrap();
        let writer = PgPersister::new(faulty.clone()).with_bounded_writer_lock_wait();
        if strict_probe {
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                writer.persist_guarded_generic_probe(&txs),
            )
            .await
            .unwrap();
            assert_eq!(outcome.reason, ProbeReason::UnknownOutcome);
            assert!(outcome.confirmed_txids.is_empty());
            assert_eq!(
                outcome.uncertain_txids,
                txs.iter()
                    .map(|tx| tx.transaction_id.clone())
                    .collect::<Vec<_>>()
            );
            assert_eq!(outcome.remaining_txids, outcome.uncertain_txids);
            assert_eq!(
                outcome.attempts.len(),
                1,
                "unknown acknowledgement cannot retry"
            );
            assert!(outcome.attempts[0].hold_upper_bound_us.is_none());
        } else {
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                writer.try_persist_generic_batch_inner(&txs, budget_enabled),
            )
            .await
            .unwrap()
            .err()
            .expect("lost acknowledgement must be visible to caller");
            assert_eq!(
                error
                    .downcast_ref::<super::super::GenericWriteOutcomeUnknown>()
                    .unwrap()
                    .phase,
                if rollback { "rollback" } else { "commit" }
            );
            assert!(!super::super::is_transient_persist_error(&error));
        }
        proxy.await.unwrap();
        let pid = backend_pid.load(std::sync::atomic::Ordering::SeqCst);
        assert!(pid > 0, "proxy must observe the actual backend PID");
        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            loop {
                let alive: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                )
                .bind(pid)
                .fetch_one(&pool)
                .await
                .unwrap();
                if !alive {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("lost transaction acknowledgement backend must disappear");
        if rollback {
            let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(
                before, after,
                "failed rollback acknowledgement must preserve canonical state"
            );
            faulty.close().await;
            return;
        }
        let committed: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        let ids: Vec<Vec<u8>> = txs
            .iter()
            .map(|tx| hex::decode(&tx.transaction_id).unwrap())
            .collect();
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT txid) FROM covenant_actions WHERE txid=ANY($1::bytea[])",
        )
        .bind(&ids)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            stored,
            txs.len() as i64,
            "server must have committed the complete batch"
        );
        let revision_before: i64 =
            sqlx::query_scalar("SELECT revision FROM snapshot_claim_history_revision")
                .fetch_one(&pool)
                .await
                .unwrap();
        let sequence_before: i64 =
            sqlx::query_scalar("SELECT last_value FROM covenant_actions_id_seq")
                .fetch_one(&pool)
                .await
                .unwrap();
        let fresh_writer = PgPersister::new(pool.clone()).with_bounded_writer_lock_wait();
        let replay = fresh_writer
            .try_persist_generic_batch_inner(&txs, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay.stats.actions_inserted, 0);
        let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            committed, after,
            "replaying an acknowledged-lost commit must preserve all captured rows"
        );
        let revision_after: i64 =
            sqlx::query_scalar("SELECT revision FROM snapshot_claim_history_revision")
                .fetch_one(&pool)
                .await
                .unwrap();
        let sequence_after: i64 =
            sqlx::query_scalar("SELECT last_value FROM covenant_actions_id_seq")
                .fetch_one(&pool)
                .await
                .unwrap();
        eprintln!(
            "replay auxiliary deltas: snapshot revision={}, action sequence={}",
            revision_after - revision_before,
            sequence_after - sequence_before
        );
        for scenario in 0..6 {
            let mut changed = txs.clone();
            match scenario {
                0 => changed[0].accepting_block_hash = Some("ff".repeat(32)),
                1 => {
                    changed[0].inputs[0].previous_outpoint_amount =
                        changed[0].inputs[0].previous_outpoint_amount.map(|n| n + 1)
                }
                2 => {
                    changed[0].inputs[0].previous_outpoint_script =
                        Some(format!("aa20{}87", "ee".repeat(32)))
                }
                3 => changed[0].outputs[0].amount += 1,
                4 => changed[0].outputs[0].script_public_key = format!("aa20{}87", "ee".repeat(32)),
                5 => changed[0].transaction_id = "fa".repeat(32),
                _ => unreachable!(),
            }
            let error = fresh_writer
                .try_persist_generic_batch_inner(&changed, true)
                .await
                .err()
                .expect("changed replay evidence must fail");
            assert!(
                error
                    .downcast_ref::<super::super::AcceptanceConflict>()
                    .is_some()
                    || error
                        .downcast_ref::<super::super::AcceptanceEvidenceConflict>()
                        .is_some(),
                "changed scenario {scenario} must fence scanner fallback: {error:#}"
            );
            let unchanged: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(committed, unchanged, "changed replay scenario {scenario}");
        }
        faulty.close().await;
        eprintln!("server COMMIT observed, acknowledgement dropped, real writer errored, fresh replay preserved five tables");
    }
    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_budget_splits_and_finishes_window(pool: sqlx::PgPool) {
        let (writer, txs) = seed_budget_fixture(pool.clone()).await;
        sqlx::raw_sql(include_str!(
            "../../tests/fixtures/generic-writer-budget-delays.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        let writer = writer
            .with_generic_bulk_persist(true)
            .with_generic_bulk_max_txs(16)
            .with_generic_writer_budget(true);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            writer.persist_batch(&txs),
        )
        .await
        .expect("bounded split must terminate")
        .expect("smaller prefixes must make progress");
        assert_eq!(result.actions_inserted, 32);
        let attempts: i64 = sqlx::query_scalar("SELECT last_value FROM test_budget_attempts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            attempts, 3,
            "one timed out 16-row batch and two successful 8-row batches"
        );
        let ids: Vec<Vec<u8>> = txs
            .iter()
            .map(|tx| hex::decode(&tx.transaction_id).unwrap())
            .collect();
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT txid) FROM covenant_actions WHERE txid=ANY($1::bytea[])",
        )
        .bind(&ids)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, 16);
    }

    #[ignore = "run serially against isolated local PostgreSQL; exercised by the writer recovery CI step"]
    #[sqlx::test(migrations = "./migrations")]
    async fn generic_writer_normal_commit_failure_quarantines_connection(pool: sqlx::PgPool) {
        let (writer, txs) = seed_budget_fixture(pool.clone()).await;
        let before: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(r#"
CREATE SEQUENCE test_failed_commit_pid;
CREATE FUNCTION test_fail_deferred_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM setval('test_failed_commit_pid',pg_backend_pid()); RAISE EXCEPTION 'injected deferred commit failure'; END $$;
CREATE CONSTRAINT TRIGGER test_deferred_failure AFTER INSERT ON covenant_actions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION test_fail_deferred_commit();
"#).execute(&pool).await.unwrap();
        let error = writer
            .try_persist_generic_batch_inner(&txs, false)
            .await
            .err()
            .expect("deferred commit must fail");
        assert_eq!(
            error
                .downcast_ref::<super::super::GenericWriteOutcomeUnknown>()
                .unwrap()
                .phase,
            "commit"
        );
        assert!(!super::super::is_transient_persist_error(&error));
        let pid: i64 = sqlx::query_scalar("SELECT last_value FROM test_failed_commit_pid")
            .fetch_one(&pool)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            loop {
                let alive: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
                )
                .bind(pid as i32)
                .fetch_one(&pool)
                .await
                .unwrap();
                if !alive {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("uncertain commit connection must close, not return to pool");
        let after: serde_json::Value = sqlx::query_scalar(BUDGET_SNAPSHOT)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(before, after);
        eprintln!("normal runtime commit failure: backend removed, canonical state unchanged, non-transient outcome");
    }
    mod progress {
        include!("generic_budget_progress_tests.rs");
    }
    mod strict_probe {
        include!("generic_probe_sql_tests.rs");
    }
}

#[cfg(test)]
#[path = "native_genesis_tests.rs"]
mod native_genesis_tests;
